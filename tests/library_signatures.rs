//! Default library names against the symbol tables of the unstripped builds.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use flate2::read::GzDecoder;
use object::{Object, ObjectSymbol};
use serde_json::json;
use velk::service::{Binary, SignatureOptions};
use velk::sigs::Certainty;

fn fixture(name: &str, directory: &str) -> PathBuf {
    let checked_in = Path::new("tests/library_signatures").join(format!("{name}.gz"));
    let source = if checked_in.is_file() {
        checked_in
    } else {
        Path::new("target/library-signatures/fixtures").join(format!("{name}.gz"))
    };
    let compressed = fs::read(&source).expect("the compressed fixture is checked in or generated");
    let mut bytes = Vec::new();
    GzDecoder::new(compressed.as_slice())
        .read_to_end(&mut bytes)
        .expect("the fixture is valid gzip");
    let directory = Path::new("target").join(directory);
    fs::create_dir_all(&directory).expect("the test output directory is writable");
    let path = directory.join(name);
    fs::write(&path, bytes).expect("the extracted fixture can be written");
    path
}

#[test]
fn default_sets_agree_with_all_library_symbols() {
    let mut measurements = Vec::new();
    for arch in ["x86_64", "aarch64", "i386", "arm32"] {
        for level in ["O0", "O1", "O2", "O3", "Os"] {
            for library in ["zlib", "xxhash"] {
                let stem = format!("{library}.{arch}.{level}");
                let reference = fixture(&format!("{stem}.elf"), "library-measurement");
                let target = fixture(&format!("{stem}.stripped.elf"), "library-measurement");
                let bytes = fs::read(reference).unwrap();
                let object = object::File::parse(bytes.as_slice()).unwrap();
                let mut symbols: BTreeMap<u64, Vec<&str>> = BTreeMap::new();
                for symbol in object.symbols() {
                    if symbol.kind() == object::SymbolKind::Text && !symbol.is_undefined() {
                        symbols
                            .entry(symbol.address())
                            .or_default()
                            .push(symbol.name().unwrap());
                    }
                }
                let library_functions = symbols
                    .values()
                    .filter(|names| {
                        names
                            .iter()
                            .any(|name| name.starts_with("adler32") || name.starts_with("XXH"))
                    })
                    .count();
                let binary = Binary::open(&target).unwrap();
                let mut correct = 0;
                let mut wrong = Vec::new();
                for function in binary.functions() {
                    let Some(evidence) = &function.library else {
                        continue;
                    };
                    if evidence.certainty != Certainty::Exact {
                        continue;
                    }
                    let name = function.name.as_deref().unwrap();
                    if symbols
                        .get(&function.addr)
                        .is_some_and(|names| names.contains(&name))
                    {
                        correct += 1;
                    } else {
                        wrong.push((function.addr, name.to_owned()));
                    }
                }
                assert!(wrong.is_empty(), "{stem}: {wrong:?}");
                assert!(library_functions > 0, "{stem} has no ground truth");
                measurements.push(json!({"library":library, "arch":arch, "optimization":level,
                    "correct":correct, "wrong":wrong.len(), "missed":library_functions-correct}));
            }
        }
    }
    for (library, expected) in [("zlib", 26), ("xxhash", 114)] {
        let mut correct = 0;
        for row in &measurements {
            if row["library"] == library {
                correct += row["correct"].as_u64().unwrap();
            }
        }
        assert_eq!(correct, expected, "{library} recovered-name count changed");
    }
    let path = Path::new("target/library-signatures/measurements.json");
    let actual = format!("{}\n", serde_json::to_string_pretty(&measurements).unwrap());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, actual).unwrap();
}

#[test]
#[ignore = "Generate with docker compose run --rm signatures; run with --include-ignored."]
fn library_sets_agree_with_stripped_library_symbols() {
    assert!(
        Path::new("target/library-signatures/fixtures").is_dir(),
        "Generate the library fixtures with docker compose run --rm signatures."
    );
    let only_arch = std::env::var("SIGNATURE_MEASUREMENT_ARCH").ok();
    let only_embedded = std::env::var("SIGNATURE_MEASUREMENT_MODE")
        .is_ok_and(|mode| mode == "embedded")
        || !Path::new("target/library-signatures/libraries.json.gz").is_file();
    let mut measurements = Vec::new();
    let mut full_measurements = Vec::new();
    let mut coverage: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for library in ["musl", "mbedtls", "libsodium", "openssl", "rust"] {
        for arch in ["x86_64", "aarch64", "i386", "arm32"] {
            if only_arch.as_deref().is_some_and(|only| only != arch) {
                continue;
            }
            for level in ["O0", "O1", "O2", "O3", "Os"] {
                let stem = format!("{library}.{arch}.{level}");
                let reference = fixture(&format!("{stem}.elf"), "library-symbol-measurement");
                let target = fixture(
                    &format!("{stem}.stripped.elf"),
                    "library-symbol-measurement",
                );
                let truth_path =
                    fixture(&format!("{stem}.truth.json"), "library-symbol-measurement");
                let raw_truth: BTreeMap<u64, Vec<String>> =
                    serde_json::from_slice(&fs::read(truth_path).unwrap()).unwrap();
                let normalize_name = |name: &str| format!("{:#}", rustc_demangle::demangle(name));
                let mut truth = BTreeMap::new();
                for (address, names) in raw_truth {
                    let names: Vec<String> =
                        names.iter().map(|name| normalize_name(name)).collect();
                    truth.insert(address, names);
                }
                let bytes = fs::read(reference).unwrap();
                let object = object::File::parse(bytes.as_slice()).unwrap();
                let mut symbols: BTreeMap<u64, Vec<String>> = BTreeMap::new();
                for symbol in object.symbols() {
                    if symbol.kind() == object::SymbolKind::Text && !symbol.is_undefined() {
                        let address = if arch == "arm32" {
                            symbol.address() & !1
                        } else {
                            symbol.address()
                        };
                        symbols
                            .entry(address)
                            .or_default()
                            .push(normalize_name(symbol.name().unwrap()));
                    }
                }
                if arch == "x86_64" && cfg!(all(target_os = "linux", target_arch = "x86_64")) {
                    use std::os::unix::fs::PermissionsExt as _;
                    fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
                    let output = Command::new(&target).output().unwrap();
                    assert!(output.status.success(), "{stem}: {output:?}");
                }
                for full in [false, true] {
                    if full && only_embedded {
                        continue;
                    }
                    let options = SignatureOptions {
                        defaults: !full,
                        files: if full {
                            vec![PathBuf::from("target/library-signatures/libraries.json.gz")]
                        } else {
                            Vec::new()
                        },
                    };
                    let binary =
                        Binary::open_with_signatures(&target, None, None, &options).unwrap();
                    let mut correct = 0;
                    let mut wrong = Vec::new();
                    for function in binary.functions() {
                        let Some(evidence) = &function.library else {
                            continue;
                        };
                        if evidence.certainty != Certainty::Exact {
                            continue;
                        }
                        let name = function.name.as_ref().unwrap();
                        if !symbols
                            .get(&function.addr)
                            .is_some_and(|names| names.contains(name))
                        {
                            wrong.push((function.addr, name.clone()));
                        } else if truth.contains_key(&function.addr) {
                            correct += 1;
                            if full {
                                for candidate in &evidence.candidates {
                                    coverage
                                        .entry(candidate.set.clone())
                                        .or_default()
                                        .push(format!("{stem}:0x{:x}", function.addr));
                                }
                            }
                        }
                    }
                    assert!(wrong.is_empty(), "{stem}: {wrong:?}");
                    assert!(!truth.is_empty(), "{stem} has no library ground truth");
                    let rows = if full {
                        &mut full_measurements
                    } else {
                        &mut measurements
                    };
                    rows.push(json!({"library":library,"arch":arch,"optimization":level,
                    "correct":correct,"wrong":wrong.len(),"missed":truth.len()-correct}));
                }
            }
        }
    }
    for (path, measurements) in [
        (
            "target/library-signatures/library-measurements.json",
            &measurements,
        ),
        (
            "target/library-signatures/full-measurements.json",
            &full_measurements,
        ),
    ] {
        if measurements.is_empty() {
            continue;
        }
        let path = Path::new(path);
        let mut measured = measurements.clone();
        if let Some(only) = only_arch.as_ref().filter(|_| path.is_file()) {
            let mut previous: Vec<serde_json::Value> =
                serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            previous.retain(|row| row["arch"] != only.as_str());
            previous.append(&mut measured);
            measured = previous;
        }
        let actual = format!("{}\n", serde_json::to_string_pretty(&measured).unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, actual).unwrap();
    }
    if !only_embedded {
        if let Some(only) = only_arch
            .as_ref()
            .filter(|_| Path::new("target/library-signatures/set-coverage.json").is_file())
        {
            let previous: BTreeMap<String, Vec<String>> = serde_json::from_slice(
                &fs::read("target/library-signatures/set-coverage.json").unwrap(),
            )
            .unwrap();
            for (set, matches) in previous {
                if set.split('.').nth(1) != Some(only.as_str()) {
                    coverage.insert(set, matches);
                }
            }
        }
        fs::write(
            "target/library-signatures/set-coverage.json",
            format!("{}\n", serde_json::to_string_pretty(&coverage).unwrap()),
        )
        .unwrap();
    }
}

#[test]
fn existing_stripped_rust_fixture_names_agree_with_symbols() {
    let bytes = fs::read("tests/fixtures/rust_probe").unwrap();
    let object = object::File::parse(bytes.as_slice()).unwrap();
    let mut symbols: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for symbol in object.symbols() {
        if symbol.kind() == object::SymbolKind::Text && !symbol.is_undefined() {
            let name = format!("{:#}", rustc_demangle::demangle(symbol.name().unwrap()));
            symbols.entry(symbol.address()).or_default().push(name);
        }
    }
    let reference = Binary::open(Path::new("tests/fixtures/rust_probe")).unwrap();
    for function in reference.functions() {
        if let Some(name) = function.name {
            symbols.entry(function.addr).or_default().push(name);
        }
    }
    for full in [false, true] {
        if full && !Path::new("target/library-signatures/libraries.json.gz").is_file() {
            continue;
        }
        let options = SignatureOptions {
            defaults: !full,
            files: if full {
                vec![PathBuf::from("target/library-signatures/libraries.json.gz")]
            } else {
                Vec::new()
            },
        };
        let binary = Binary::open_with_signatures(
            Path::new("tests/fixtures/rust_probe_stripped"),
            None,
            None,
            &options,
        )
        .unwrap();
        let functions = binary.functions();
        let mut correct = 0;
        let mut wrong = Vec::new();
        for function in &functions {
            let Some(name) = &function.name else { continue };
            if symbols
                .get(&function.addr)
                .is_some_and(|names| names.contains(name))
            {
                correct += 1;
            } else {
                wrong.push((function.addr, name.clone()));
            }
        }
        assert!(wrong.is_empty(), "{wrong:?}");
        assert_eq!(
            correct, 3,
            "the Rust fixture must retain its recovered names"
        );
        assert_eq!(functions.len(), 545);
        let measurement = json!({"correct":correct,"wrong":wrong.len(),
        "missed":functions.len()-correct,"discovered":functions.len()});
        let path = Path::new(if full {
            "target/library-signatures/full-rust-measurement.json"
        } else {
            "target/library-signatures/rust-measurement.json"
        });
        let actual = format!("{}\n", serde_json::to_string_pretty(&measurement).unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, actual).unwrap();
    }
}

#[test]
fn default_names_compile_and_compute_the_library_result() {
    let path = fixture("zlib.x86_64.Os.stripped.elf", "library-c-test");
    let mut binary = Binary::open(&path).unwrap();
    let address = binary.find("adler32_combine_").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    assert!(
        code.contains("/* identified: adler32_combine_; zlib-1.3.2-x86_64-Os-clang21; exact */")
    );
    assert!(code.contains("adler32_combine_("));
    let directory = path.parent().unwrap();
    let source = directory.join("combine.c");
    fs::write(
        &source,
        format!(
            r#"{code}
extern unsigned long adler32_combine(unsigned long, unsigned long, long);
int main(void) {{
    for (unsigned i=0; i<10000; ++i) {{
        uint32_t a=i*2654435761u, b=i*1640531527u;
        if ((uint32_t)adler32_combine_(a,b,i) != (uint32_t)adler32_combine(a,b,i)) return 1;
    }}
    return (uint32_t)adler32_combine_(1,2,-1) != (uint32_t)adler32_combine(1,2,-1);
}}
"#
        ),
    )
    .unwrap();
    let executable = directory.join("combine");
    let output = Command::new("clang")
        .args(["-std=c11", "-Werror", "-O2", "-DZ_SOLO"])
        .arg(source)
        .arg("-lz")
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(Command::new(executable).status().unwrap().success());
}

#[test]
#[ignore = "Generate with docker compose run --rm signatures; run with --include-ignored."]
fn recovered_musl_name_compiles_and_computes_the_source_result() {
    assert!(
        Path::new("target/library-signatures/fixtures").is_dir(),
        "Generate the library fixtures with docker compose run --rm signatures."
    );
    let path = fixture("musl.x86_64.O0.stripped.elf", "musl-c-test");
    let mut binary = Binary::open(&path).unwrap();
    let address = binary.find("memcmp").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    assert!(code.contains("/* identified: memcmp; musl.x86_64.O0.0; exact */"));
    assert!(code.contains("int32_t memcmp("));
    let code = code.replacen("int32_t memcmp(", "int32_t recovered_memcmp(", 1);
    let source = path.parent().unwrap().join("memcmp.c");
    fs::write(
        &source,
        format!(
            r#"{code}
#include <stddef.h>
#include <string.h>
int main(void) {{
    unsigned char first[64], second[64];
    uint32_t random = 1;
    for (unsigned i = 0; i < 10000; ++i) {{
        for (unsigned j = 0; j < 64; ++j) {{
            random = random * 1664525u + 1013904223u;
            first[j] = (unsigned char)(random >> 24);
            second[j] = first[j];
        }}
        if (i % 3) second[i % 64] ^= (unsigned char)i;
        size_t length = i % 65;
        int actual = recovered_memcmp((intptr_t)first, (intptr_t)second, (int64_t)length);
        if (actual != memcmp(first, second, length)) return 1;
    }}
    return recovered_memcmp(0, 0, 0);
}}
"#
        ),
    )
    .unwrap();
    let executable = source.with_extension("exe");
    let output = Command::new("clang")
        .args(["-std=c11", "-Werror", "-O2", "-Dmemcmp=reference_memcmp"])
        .arg(&source)
        .arg("target/library-signatures/sources/references/memcmp.c")
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(Command::new(executable).status().unwrap().success());
}

#[test]
fn disabled_defaults_and_user_aliases_do_not_leave_stale_names() {
    let path = fixture("xxhash.x86_64.O2.stripped.elf", "library-options-test");
    let mut binary = Binary::open(&path).unwrap();
    let address = binary.find("XXH32").unwrap().addr;
    let _ = binary.decompile(address, None, None).unwrap();
    let mut aliases = velk::sigs::bundled().clone();
    for entry in &mut aliases.entries {
        entry.name = format!("alias_{}", entry.name);
    }
    let result = binary.identify(&aliases, None).unwrap();
    assert!(!result.candidates.is_empty());
    assert!(binary.image().functions[&address].name.is_none());
    assert!(
        !binary
            .decompile(address, None, None)
            .unwrap()
            .contains("XXH32(")
    );
    let options = SignatureOptions {
        defaults: false,
        files: Vec::new(),
    };
    let binary = Binary::open_with_signatures(&path, None, None, &options).unwrap();
    assert!(
        binary
            .functions()
            .iter()
            .all(|function| function.library.is_none())
    );
    assert!(binary.find("XXH32").is_err());
    let named_path = fixture("xxhash.x86_64.O2.elf", "library-options-test");
    let mut named = Binary::open(&named_path).unwrap();
    named
        .identify(&velk::sigs::Database::new(Vec::new()), None)
        .unwrap();
    assert_eq!(
        named
            .find("XXH32")
            .unwrap()
            .library
            .as_ref()
            .unwrap()
            .certainty,
        Certainty::Exact
    );
}

#[test]
fn cli_javascript_and_mcp_show_the_same_evidence_and_options() {
    let path = fixture("xxhash.x86_64.O2.stripped.elf", "library-api-test");
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("-f")
        .arg(&path)
        .args(["--json", "--limit", "100"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let listing: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        listing["functions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|function| {
                function["name"] == "XXH32" && function["library"]["certainty"] == "exact"
            })
    );
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("-f")
        .arg(&path)
        .args(["--json", "--no-default-signatures"])
        .output()
        .unwrap();
    let disabled: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(output.status.success());
    assert!(
        disabled["functions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|function| function.get("library").is_none())
    );
    let directory = path.parent().unwrap();
    let empty_path = directory.join("empty.json.gz");
    use std::io::Write as _;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(&serde_json::to_vec(&velk::sigs::Database::new(Vec::new())).unwrap())
        .unwrap();
    fs::write(&empty_path, encoder.finish().unwrap()).unwrap();
    let named_path = fixture("xxhash.x86_64.O2.elf", "library-api-test");
    let options = SignatureOptions {
        defaults: true,
        files: vec![empty_path.clone()],
    };
    let named = Binary::open_with_signatures(&named_path, None, None, &options).unwrap();
    let function = named.find("XXH32").unwrap();
    assert_eq!(
        function.library.as_ref().unwrap().certainty,
        Certainty::Exact
    );
    let mut aliases = velk::sigs::bundled().clone();
    for entry in &mut aliases.entries {
        entry.name = format!("alias_{}", entry.name);
    }
    let alias_path = directory.join("aliases.json");
    fs::write(&alias_path, serde_json::to_vec(&aliases).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("-f")
        .arg(&path)
        .args(["--json", "--signatures"])
        .arg(&empty_path)
        .arg("--signatures")
        .arg(&alias_path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let ambiguous: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        ambiguous["functions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|function| function["name"].is_null()
                && function["library"]["certainty"] == "ambiguous")
    );
    let code = format!(
        r#"
const b = velk.open({path});
const named = b.getFunction("XXH32");
if (named.library.certainty !== "exact") throw Error("missing evidence");
if (!named.decompile().includes("XXH32(")) throw Error("missing C name");
const disabled = velk.open({path}, {{defaultSignatures:false}});
if (disabled.functions().some(f=>f.library)) throw Error("disabled defaults");
const unnamed = disabled.getFunction(named.addr);
if (unnamed.decompile().includes("XXH32(")) throw Error("disabled decompile defaults");
if (!b.decompile([named])[0].code.includes("XXH32(")) throw Error("missing batch C name");
if (disabled.decompile([unnamed])[0].code.includes("XXH32(")) throw Error("disabled batch defaults");
if (b.getFunction("XXH32").library.certainty !== "exact") throw Error("cache options collide");
const extra = velk.open({path}, {{signatures:[{empty}, {aliases}]}});
if (!extra.functions().some(f=>f.library?.certainty === "ambiguous")) throw Error("user sets missing");
console.log("library evidence checked");
"#,
        path = serde_json::to_string(&path).unwrap(),
        empty = serde_json::to_string(&empty_path).unwrap(),
        aliases = serde_json::to_string(&alias_path).unwrap(),
    );
    let script = path.parent().unwrap().join("check.js");
    fs::write(&script, &code).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("-r")
        .arg(script)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("library evidence checked"));
    let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{"name":"velk_run_script","arguments":{"code":code}}});
    // Exercise the actual newline-delimited MCP transport.
    let mut child = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--mcp")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{request}").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_ne!(response["result"]["isError"], true, "{response}");
    assert!(
        response.to_string().contains("library evidence checked"),
        "{response}"
    );
}

#[test]
fn invalid_compressed_databases_report_the_file_and_cause() {
    let directory = Path::new("target/signature-file-errors");
    fs::create_dir_all(directory).unwrap();
    for (name, bytes) in [
        ("invalid.json.gz", &[0x1f, 0x8b, 0][..]),
        ("invalid.json", b"{invalid".as_slice()),
    ] {
        let path = directory.join(name);
        fs::write(&path, bytes).unwrap();
        let error = velk::sigs::Database::load(&path).unwrap_err().to_string();
        assert!(error.contains(name), "{error}");
    }
}

#[test]
fn scratch_register_match_names_printed_c_and_preserves_reference_results() {
    let directory = Path::new("target/signature-register-c");
    fs::create_dir_all(directory).unwrap();
    let assembly = |name: &str, register: &str| {
        format!(
            ".text\n.globl {name}\n.type {name},@function\n{name}:\nmov %rdi,%{register}\n.rept 12\nadd $1,%{register}\n.endr\nmov %{register},%rax\nret\n.size {name},.-{name}\n.section .note.GNU-stack,\"\",@progbits\n"
        )
    };
    let reference_source = directory.join("reference.s");
    let target_source = directory.join("target.s");
    fs::write(&reference_source, assembly("library_sum", "r10")).unwrap();
    fs::write(&target_source, assembly("anonymous", "r11")).unwrap();
    let reference = directory.join("reference.o");
    let target = directory.join("target.elf");
    for arguments in [
        vec![
            "-c".into(),
            reference_source,
            "-o".into(),
            reference.clone(),
        ],
        vec![
            "-fuse-ld=lld".into(),
            "-nostdlib".into(),
            "-static".into(),
            "-Wl,--build-id=none,-e,anonymous".into(),
            "-s".into(),
            target_source,
            "-o".into(),
            target.clone(),
        ],
    ] {
        let output = Command::new("clang")
            .args(["--target=x86_64-unknown-linux-gnu"])
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let database = velk::sigs::build(&reference, None).unwrap();
    let database_path = directory.join("signatures.json");
    fs::write(&database_path, serde_json::to_vec(&database).unwrap()).unwrap();
    let options = SignatureOptions {
        defaults: false,
        files: vec![database_path],
    };
    let mut binary = Binary::open_with_signatures(&target, None, None, &options).unwrap();
    let address = binary.find("library_sum").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    assert!(code.contains("library_sum("), "{code}");
    let source = directory.join("check.c");
    let native_source = directory.join("native.s");
    let native_x86 = cfg!(all(target_os = "linux", target_arch = "x86_64"));
    let reference = if native_x86 {
        fs::write(&native_source, assembly("reference_sum", "r10")).unwrap();
        "extern int64_t reference_sum(int64_t);"
    } else {
        "int64_t reference_sum(int64_t value) { return value + 12; }"
    };
    fs::write(&source, format!("{code}\n{reference}\nint main(void) {{ for (int64_t i=-5000;i<5000;i++) if (library_sum(i)!=reference_sum(i)) return 1; return 0; }}\n")).unwrap();
    let executable = directory.join("check");
    let mut compiler = Command::new("clang");
    compiler.args(["-std=c11", "-Werror", "-O2"]).arg(source);
    if native_x86 {
        compiler.arg(native_source);
    }
    let output = compiler.arg("-o").arg(&executable).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(Command::new(executable).status().unwrap().success());
}

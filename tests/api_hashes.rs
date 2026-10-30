//! Export hash comparisons checked against source execution.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use serde_json::{Value, json};
use velk::service::Binary;

fn fixtures() -> &'static Path {
    static DIRECTORY: OnceLock<PathBuf> = OnceLock::new();
    DIRECTORY.get_or_init(|| {
        let directory =
            common::root().join(format!("target/api-hash-tests-{}", std::process::id()));
        let output = Command::new("sh")
            .arg(common::root().join("tests/make_api_hash_fixtures.sh"))
            .arg(&directory)
            .output()
            .expect("building API hash fixtures");
        assert!(output.status.success(), "{output:?}");
        directory
    })
}

fn assert_decompiled_code_compiles(binary: &mut Binary, address: u64, label: &str) {
    let code = binary
        .decompile(address, None, None)
        .unwrap_or_else(|error| panic!("{label}: {error}"));
    let output = common::compiler::run(
        Command::new("clang").args([
            "-x",
            "c",
            "-fsyntax-only",
            "-Werror=implicit-function-declaration",
            "-",
        ]),
        Some(&code),
    );
    assert!(output.status.success(), "{label}: {output:?}\n{code}");
}

#[test]
fn hash_comparisons_reach_indirect_calls() {
    for architecture in ["x86_64", "i386", "aarch64"] {
        for optimization in ["O0", "O2"] {
            let mut resolved = 0;
            let mut unresolved = 0;
            let mut binary =
                Binary::open(&fixtures().join(format!("{architecture}.{optimization}.elf")))
                    .unwrap();
            for routine in [
                "ror13", "djb2", "fnv1a", "seeded", "wide", "crc32", "custom", "pe", "elf",
            ] {
                let name = format!("case_{routine}");
                let address = binary.find(&name).unwrap().addr;
                let summary = binary.summary(address, None).unwrap();
                let hashes = summary["apiHashes"].as_array().unwrap();
                if hashes.is_empty() {
                    unresolved += 1;
                    eprintln!("{architecture} {optimization} {name}: unresolved");
                    continue;
                }
                assert_eq!(hashes.len(), 1, "{summary}");
                assert_eq!(hashes[0]["candidates"], json!(["puts"]), "{summary}");
                assert_eq!(hashes[0]["complete"], true, "{summary}");
                let call = summary["calls"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|call| {
                        call["block"] == hashes[0]["block"]
                            && call["statement"] == hashes[0]["statement"]
                    })
                    .unwrap();
                assert_eq!(call["indirect"], hashes[0]["indirectCall"]);
                let code = binary.decompile(address, None, None).unwrap();
                assert!(code.contains("candidates puts"), "{code}");
                resolved += 1;
            }
            eprintln!(
                "{architecture} {optimization}: resolved={resolved} unresolved={unresolved} wrong=0"
            );
            assert!(
                resolved >= 5,
                "{architecture} {optimization}: resolved={resolved}"
            );
        }
    }
}

#[test]
fn collisions_and_unknown_names_remain_explicit() {
    for architecture in ["x86_64", "i386", "aarch64"] {
        for optimization in ["O0", "O2"] {
            let mut binary =
                Binary::open(&fixtures().join(format!("{architecture}.{optimization}.elf")))
                    .unwrap();
            let address = binary.find("case_unknown").unwrap().addr;
            let summary = binary.summary(address, None).unwrap();
            assert_eq!(
                summary["apiHashes"].as_array().unwrap().len(),
                1,
                "{summary}"
            );
            assert_eq!(
                summary["apiHashes"][0]["candidates"],
                json!([]),
                "{summary}"
            );
            assert_eq!(summary["apiHashes"][0]["complete"], true);
            let address = binary.find("case_collision").unwrap().addr;
            let summary = binary.summary(address, None).unwrap();
            let hashes = summary["apiHashes"].as_array().unwrap();
            if optimization == "O2" {
                assert!(
                    hashes.is_empty(),
                    "{architecture} {optimization}: {summary}"
                );
                continue;
            }
            assert_eq!(hashes.len(), 1, "{architecture} {optimization}: {summary}");
            let candidates = hashes[0]["candidates"].as_array().unwrap();
            assert!(candidates.contains(&json!("puts")), "{summary}");
            assert!(candidates.contains(&json!("malloc")), "{summary}");
            assert_eq!(hashes[0]["complete"], true, "{summary}");
        }
    }
}

#[test]
fn inlined_and_dynamic_symbol_resolvers_are_emulated() {
    let reference = Command::new(fixtures().join("resolvers-reference"))
        .status()
        .expect("running the native resolver reference");
    assert!(
        reference.success(),
        "native resolver reference failed: {reference}"
    );
    for architecture in ["x86_64", "i386", "aarch64"] {
        for optimization in ["O0", "O2"] {
            let path = fixtures().join(format!("resolvers.{architecture}.{optimization}.elf"));
            let mut binary = Binary::open(&path).unwrap();
            for (name, candidate, complete) in [
                ("case_inline", json!(["puts"]), false),
                ("case_dynamic", json!(["puts"]), false),
                ("case_dynamic_unknown", json!([]), true),
            ] {
                let address = binary.find(name).unwrap().addr;
                let summary = binary.summary(address, None).unwrap();
                let hashes = summary["apiHashes"].as_array().unwrap();
                assert_eq!(
                    hashes.len(),
                    1,
                    "{architecture} {optimization} {name}: {summary}"
                );
                assert_eq!(hashes[0]["candidates"], candidate);
                assert_eq!(hashes[0]["complete"], complete);
                let code = binary.decompile(address, None, None).unwrap();
                if name != "case_dynamic_unknown" {
                    assert!(code.contains("candidates puts"), "{code}");
                }
            }
        }
    }
}

#[test]
fn peb_resolver_uses_synthetic_windows_exports() {
    for architecture in ["win64", "win32"] {
        let path = fixtures().join(format!("windows.{architecture}.dll"));
        let mut binary = Binary::open(&path).unwrap();
        let address = binary.find("case_pe").unwrap().addr;
        let summary = binary.summary(address, None).unwrap();
        let hashes = summary["apiHashes"].as_array().unwrap();
        assert_eq!(hashes.len(), 1, "{architecture}: {summary}");
        assert_eq!(hashes[0]["candidates"], json!(["GetCurrentProcessId"]));
        assert_eq!(hashes[0]["complete"], false);
        let code = binary.decompile(address, None, None).unwrap();
        assert!(code.contains("candidates GetCurrentProcessId"), "{code}");
    }
}

#[test]
fn long_hash_stops_consistently() {
    for architecture in ["x86_64", "i386", "aarch64"] {
        let path = fixtures().join(format!("{architecture}.O0.elf"));
        let mut previous = None;
        for _ in 0..2 {
            let mut binary = Binary::open(&path).unwrap();
            let address = binary.find("case_long_hash").unwrap().addr;
            let summary = binary.summary(address, None).unwrap();
            let hashes = &summary["apiHashes"];
            assert_eq!(hashes.as_array().unwrap().len(), 1, "{summary}");
            assert_eq!(hashes[0]["complete"], false, "{summary}");
            let code = binary.decompile(address, None, None).unwrap();
            let result = (hashes.clone(), code);
            if let Some(previous) = &previous {
                assert_eq!(&result, previous);
            }
            previous = Some(result);
        }
    }
}

#[test]
fn public_interfaces_and_documentation_return_the_same_candidates() {
    use std::io::Write as _;
    use std::process::Stdio;

    let path = fixtures().join("x86_64.O2.elf");
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .args(["--summary", path.to_str().unwrap(), "case_ror13"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    let expected = summary["apiHashes"].clone();
    assert_eq!(expected[0]["candidates"], json!(["puts"]));
    let resolver_path = fixtures().join("resolvers.x86_64.O2.elf");
    let mut resolver_binary = Binary::open(&resolver_path).unwrap();
    let resolver_address = resolver_binary.find("case_inline").unwrap().addr;
    let resolver_summary = resolver_binary.summary(resolver_address, None).unwrap();
    let resolver_expected = resolver_summary["apiHashes"].clone();
    assert_eq!(resolver_expected[0]["candidates"], json!(["puts"]));
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .args(["--summary", resolver_path.to_str().unwrap(), "case_inline"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let cli_summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cli_summary["apiHashes"], resolver_expected);
    let interface_expected = json!([expected, resolver_expected]);
    let code = format!(
        "[velk.open({path:?}).getFunction('case_ror13').summary().apiHashes, \
         velk.open({resolver_path:?}).getFunction('case_inline').summary().apiHashes]"
    );
    let outcome = velk::script::Engine::new().unwrap().run(&code, None);
    assert!(outcome.error.is_none(), "{:?}", outcome.error);
    assert_eq!(
        serde_json::from_str::<Value>(&outcome.output).unwrap(),
        interface_expected
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let request = json!({"jsonrpc":"2.0", "id":1,"method":"tools/call",
        "params":{"name":"velk_run_script", "arguments":{"code":code}}});
    writeln!(child.stdin.take().unwrap(), "{request}").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["result"]["isError"], false, "{response}");
    let text = response["result"]["content"][0]["text"].as_str().unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(text).unwrap(),
        interface_expected
    );

    let serve_script =
        format!("velk.open({resolver_path:?}).getFunction('case_inline').summary().apiHashes");
    let mut child = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("serve process");
    writeln!(
        child.stdin.take().unwrap(),
        "{}",
        json!({"id": 1, "code": serve_script})
    )
    .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["result"], resolver_expected);

    for document in ["docs/API_HASHES.md", "docs/API_HASHES.ja.md"] {
        let text = std::fs::read_to_string(common::root().join(document)).unwrap();
        let code = text
            .split("```js\n")
            .nth(1)
            .unwrap()
            .split("```")
            .next()
            .unwrap();
        let code = code.replace(
            "target/api-hash-fixtures/x86_64.O2.elf",
            path.to_str().unwrap(),
        );
        let outcome = velk::script::Engine::new().unwrap().run(&code, None);
        assert!(outcome.error.is_none(), "{:?}", outcome.error);
        assert_eq!(
            serde_json::from_str::<Value>(&outcome.output).unwrap(),
            expected
        );
    }
}

#[test]
fn printed_calls_execute_with_matching_and_missing_exports() {
    for architecture in ["x86_64", "i386", "aarch64"] {
        for optimization in ["O0", "O2"] {
            let mut binary =
                Binary::open(&fixtures().join(format!("{architecture}.{optimization}.elf")))
                    .unwrap();
            for (routine, hash) in [
                ("ror13", "0xe3a01db3"),
                ("djb2", "0x7c9c7b11"),
                ("fnv1a", "0x9c67d227"),
                ("seeded", "0x89112f9d"),
                ("wide", "0x9c67d227"),
                ("crc32", "0x9a1e494f"),
                ("custom", "0x7661fdcd"),
            ] {
                let name = format!("case_{routine}");
                let address = binary.find(&name).unwrap().addr;
                let mut code = binary.decompile(address, None, None).unwrap();
                code.push_str(&format!(
                    r#"
static int missing;
static uint64_t callback(uint32_t value) {{ return (value * 33u) ^ 0xa5a5a5a5u; }}
uint64_t resolve_{routine}(uint32_t hash) {{
    if (hash != {hash} || missing) return 0;
    return {};
}}
int main(void) {{
    uint32_t values[] = {{0, 1, 255, 65535, 0x7fffffff, 0x80000000, 0xffffffff}};
    for (missing = 0; missing <= 1; ++missing) {{
        for (unsigned i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {{
            uint32_t actual = (uint32_t){};
            uint32_t expected = {};
            if (actual != expected) return 1;
        }}
    }}
    return 0;
}}
"#,
                    if architecture == "i386" {
                        "0x12345678"
                    } else {
                        "(uintptr_t)callback"
                    },
                    if architecture == "i386" {
                        format!("{name}()")
                    } else {
                        format!("{name}((int32_t)values[i])")
                    },
                    if architecture == "i386" {
                        "missing ? 0 : 0x12345678"
                    } else {
                        "missing ? 0xffffffff : (uint32_t)callback(values[i])"
                    },
                ));
                let executable =
                    fixtures().join(format!("{architecture}.{optimization}.{routine}"));
                let output = common::compiler::run(
                    Command::new("clang")
                        .args(["-O0", "-x", "c", "-o"])
                        .arg(&executable)
                        .arg("-"),
                    Some(&code),
                );
                assert!(output.status.success(), "{output:?}\n{code}");
                let output = Command::new(&executable).output().unwrap();
                assert!(
                    output.status.success(),
                    "{architecture} {optimization} {routine}: {output:?}\n{code}"
                );
            }
        }
    }
}

#[test]
fn every_fixture_function_compiles_as_c() {
    for architecture in ["x86_64", "i386", "aarch64"] {
        for optimization in ["O0", "O2"] {
            let mut binary =
                Binary::open(&fixtures().join(format!("{architecture}.{optimization}.elf")))
                    .unwrap();
            for function in binary.functions() {
                let code = binary
                    .decompile(function.addr, None, None)
                    .unwrap_or_else(|error| {
                        panic!("{architecture} {optimization} {:?}: {error}", function.name)
                    });
                let output = common::compiler::run(
                    Command::new("clang").args([
                        "-x",
                        "c",
                        "-fsyntax-only",
                        "-Werror=implicit-function-declaration",
                        "-",
                    ]),
                    Some(&code),
                );
                assert!(
                    output.status.success(),
                    "{architecture} {optimization} {:?}: {output:?}\n{code}",
                    function.name
                );
            }
        }
    }
    for architecture in ["x86_64", "i386", "aarch64"] {
        for optimization in ["O0", "O2"] {
            let path = fixtures().join(format!("resolvers.{architecture}.{optimization}.elf"));
            let mut binary = Binary::open(&path).unwrap();
            for name in ["case_inline", "case_dynamic", "case_dynamic_unknown"] {
                let address = binary.find(name).unwrap().addr;
                assert_decompiled_code_compiles(
                    &mut binary,
                    address,
                    &format!("{architecture} {optimization} {name}"),
                );
            }
        }
    }
    for architecture in ["win64", "win32"] {
        let path = fixtures().join(format!("windows.{architecture}.dll"));
        let mut binary = Binary::open(&path).unwrap();
        let address = binary.find("case_pe").unwrap().addr;
        assert_decompiled_code_compiles(&mut binary, address, architecture);
    }
}

#[test]
fn emulated_hash_routines_match_native_execution() {
    let mut names: Vec<String> = ["", "a", "puts", "VirtualAlloc", "GetProcAddress", "\u{ff}"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    for length in [2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 127] {
        let mut name = String::new();
        for index in 0..length {
            name.push((33 + (index * 29 % 93)) as u8 as char);
        }
        names.push(name);
    }
    for architecture in ["x86_64", "i386", "aarch64"] {
        for optimization in ["O0", "O2"] {
            let binary =
                Binary::open(&fixtures().join(format!("{architecture}.{optimization}.elf")))
                    .unwrap();
            for (index, routine) in ["ror13", "djb2", "fnv1a", "crc32", "custom"]
                .iter()
                .enumerate()
            {
                for name in &names {
                    let native = Command::new(fixtures().join("reference"))
                        .args([index.to_string().as_str(), name.as_str()])
                        .output()
                        .unwrap();
                    assert!(native.status.success());
                    let expected: u64 = String::from_utf8(native.stdout)
                        .unwrap()
                        .trim()
                        .parse()
                        .unwrap();
                    let mut bytes = name.as_bytes().to_vec();
                    bytes.push(0);
                    let options = serde_json::from_value(json!({
                        "arguments": ["0x10000000"],
                        "memory": [{"address":"0x10000000", "bytes":bytes}],
                    }))
                    .unwrap();
                    let report = velk::emulation::run(&binary, routine, &options, None).unwrap();
                    assert_eq!(
                        report.reason, "return",
                        "{architecture} {optimization} {routine}: {report:?}"
                    );
                    assert_eq!(
                        velk::addr::parse(&report.return_value).unwrap() & 0xffff_ffff,
                        expected
                    );
                }
            }
        }
    }
}

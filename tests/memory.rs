//! Memory queries agree across the CLI, JavaScript API and MCP transport.
mod common;

use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use velk::script::Engine;
use velk::service::Binary;

const ARCHITECTURES: &[&str] = &["x86_64", "i386", "aarch64", "arm", "thumb", "aarch64_be"];

fn cli(path: &Path, args: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg(args[0])
        .arg(path)
        .args(&args[1..])
        .output()
        .expect("the CLI runs");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("a JSON response")
}

fn script(code: &str) -> Value {
    let result = Engine::new()
        .expect("the script engine starts")
        .run(code, None);
    assert!(result.error.is_none(), "{:?}", result.error);
    serde_json::from_str(&result.output).expect("a JSON script result")
}

fn mcp(code: &str) -> Value {
    let child = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("the MCP server starts");
    let request = json!({"jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{"name":"velk_run_script", "arguments":{"code":code,"max_output_chars":20000}}});
    let output = common::mcp_request(child, &request);
    assert!(output.status.success());
    let response: Value = serde_json::from_slice(&output.stdout).expect("a JSON response");
    assert_eq!(response["result"]["isError"], false, "{response}");
    serde_json::from_str(
        response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content"),
    )
    .expect("a JSON result")
}

#[test]
fn every_interface_searches_reads_and_detects_on_each_architecture() {
    for arch in ARCHITECTURES {
        let path = common::root().join(format!("tests/data/byte_search/{arch}.elf"));
        let prefix = format!("const b=velk.open({path:?}); ");
        let query = "b.search('48 8b ?? 24')";
        let expected = cli(&path, &["--search", "48 8b ?? 24"]);
        assert_eq!(expected["matches"].as_array().unwrap().len(), 1, "{arch}");
        assert_eq!(script(&format!("{prefix}{query}")), expected, "{arch}");
        assert_eq!(mcp(&format!("{prefix}{query}")), expected, "{arch}");
        let zeros = cli(
            &path,
            &[
                "--read-memory",
                "zero_values",
                "--type",
                "u32",
                "--count",
                "4",
            ],
        );
        assert_eq!(zeros["values"], json!([0, 0, 0, 0]));
        assert_eq!(
            cli(&path, &["--search", "00 00", "--section", ".bss"])["matches"]
                .as_array()
                .unwrap()
                .len(),
            15
        );
        let binary = Binary::open(&path).unwrap();
        let address = binary.find_address("large_integer").unwrap();
        let address_text = velk::addr::format(address);
        let expected = cli(&path, &["--read-memory", &address_text, "--type", "u64"]);
        assert_eq!(expected["values"], json!(["0xfedcba9876543210"]), "{arch}");
        let query = "b.readMemory('large_integer','u64')";
        assert_eq!(script(&format!("{prefix}{query}")), expected, "{arch}");
        assert_eq!(mcp(&format!("{prefix}{query}")), expected, "{arch}");
        let expected = cli(&path, &["--detect-constants"]);
        let query = "b.detectConstants()";
        assert_eq!(script(&format!("{prefix}{query}")), expected, "{arch}");
        assert_eq!(mcp(&format!("{prefix}{query}")), expected, "{arch}");
        let matches = expected["matches"].as_array().unwrap();
        for name in [
            "aes_sbox",
            "sha256_round_constants",
            "crc32_table",
            "base64_alphabet",
            "deflate_length_bases",
        ] {
            let matched = matches
                .iter()
                .find(|value| value["name"] == name && value["kind"] == "data")
                .unwrap();
            assert_eq!(
                matched["byteOrder"],
                if matches!(name, "aes_sbox" | "base64_alphabet") {
                    "bytes"
                } else if *arch == "aarch64_be" {
                    "big"
                } else {
                    "little"
                }
            );
            if *arch != "aarch64_be" {
                assert!(
                    !matched["functions"].as_array().unwrap().is_empty(),
                    "{arch}: {matched}"
                );
            }
        }
        if matches!(*arch, "x86_64" | "i386") {
            assert!(
                matches
                    .iter()
                    .any(|value| value["name"] == "tea_delta" && value["kind"] == "immediates"),
                "{arch}: {expected}"
            );
        }
    }
}

#[test]
fn text_integers_structs_arrays_and_global_names_are_visible() {
    for arch in ARCHITECTURES {
        let path = common::root().join(format!("tests/data/byte_search/{arch}.elf"));
        let prefix = format!("const b=velk.open({path:?}); ");
        let result = script(&format!(
            "{prefix} ({{ascii:b.search('byte search example',{{encoding:'ascii'}}), wide:b.search('byte😀',{{encoding:'utf16'}}), integer:b.search('0xfedcba9876543210',{{encoding:'integer',width:8}}), text:b.readMemory('greeting','cstring'), wideText:b.readMemory('wide_greeting','utf16'), floats:[b.readMemory('single_value','f32').values[0],b.readMemory('double_value','f64').values[0]], pointer:b.readMemory('text_pointer','pointer')}})"
        ));
        for key in ["ascii", "wide", "integer"] {
            assert_eq!(
                result[key]["matches"].as_array().unwrap().len(),
                1,
                "{arch}: {result}"
            );
        }
        assert_eq!(result["text"]["values"], json!(["byte search example"]));
        assert_eq!(result["wideText"]["values"], json!(["byte😀"]));
        assert_eq!(result["floats"], json!([1.5, -2.5]));
        assert_eq!(
            result["pointer"]["bytes"],
            if matches!(*arch, "i386" | "arm" | "thumb") {
                4
            } else {
                8
            }
        );
        if *arch == "aarch64_be" {
            continue;
        } // Debug type loading currently supports little-endian images.
        let result = script(&format!("{prefix} b.readMemory('record','struct sample')"));
        assert_eq!(
            result["values"],
            json!([{"tag":7,"value":-1234,"words":[0x12345678,9,10]}]),
            "{arch}"
        );
        let mut binary = Binary::open(&path).unwrap();
        let address = binary.find("table_byte").unwrap().addr;
        let code = binary.decompile(address, None, None).unwrap();
        assert!(code.contains("aes_sbox"), "{arch}: {code}");
        assert!(!code.contains("substitution"), "{arch}: {code}");
    }
}

#[test]
fn ranges_and_failures_are_consistent_and_mcp_recovers() {
    let path = common::root().join("tests/data/byte_search/x86_64.elf");
    let binary = Binary::open(&path).unwrap();
    let address = binary.find_address("wildcard_bytes").unwrap();
    let start = velk::addr::format(address);
    let end = velk::addr::format(address + 4);
    let section = binary.image().section_at(address).unwrap().name.clone();
    let expected = cli(
        &path,
        &[
            "--search",
            "48 8b ?? 24",
            "--start",
            &start,
            "--end",
            &end,
            "--section",
            &section,
        ],
    );
    assert_eq!(expected["matches"].as_array().unwrap().len(), 1);
    let prefix = format!("const b=velk.open({path:?}); ");
    assert_eq!(
        mcp(&format!(
            "{prefix} b.search('48 8b ?? 24',{{start:{start:?},end:{end:?},section:{section:?}}})"
        )),
        expected
    );
    let code = format!(
        "{prefix} const errors=[]; for(const run of [()=>b.search('xx'),()=>b.search('256',{{encoding:'integer',width:1}}),()=>b.readMemory('0xffffffffffffffff','u64'),()=>b.readMemory('record','missing'),()=>b.readMemory('record','u64',{{count:100000}})]) {{try{{run()}}catch(e){{errors.push(e.message)}}}} ({{errors,ok:b.readMemory('large_integer','u64').values}})"
    );
    let result = mcp(&code);
    assert_eq!(result["errors"].as_array().unwrap().len(), 5);
    assert_eq!(result["ok"], json!(["0xfedcba9876543210"]));
    for args in [
        vec!["--search", "xx"],
        vec!["--read-memory", "0xffffffffffffffff", "--type", "u64"],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_velk"))
            .arg(args[0])
            .arg(&path)
            .args(&args[1..])
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("memory query:"));
    }
}

#[test]
fn detected_names_compile_and_preserve_every_table_element() {
    let path = common::root().join("tests/data/byte_search/aarch64.elf");
    let mut binary = Binary::open(&path).unwrap();
    let address = binary.find("table_byte").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    let data_address = binary.find_address("substitution").unwrap();
    let values = binary.image().read_vaddr(data_address, 256).unwrap();
    let values = values
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let directory = common::root().join("target/memory-recompile");
    std::fs::create_dir_all(&directory).unwrap();
    let original = directory.join("original.o");
    let compiled = common::compiler::run(
        Command::new("clang")
            .args(["-O1", "-Dtable_byte=original_table_byte", "-c"])
            .arg(common::root().join("tests/cases/memory/values.c"))
            .arg("-o")
            .arg(&original),
        None,
    );
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let source = format!(
        "#include <stdint.h>\nuint8_t aes_sbox[] = {{{values}}};\n{code}\nunsigned original_table_byte(unsigned);\nint main(void) {{ for(unsigned i=0;i<1024;i++) if(table_byte(i)!=original_table_byte(i)) return 1; return 0; }}\n"
    );
    let executable = directory.join("check");
    let mut command = Command::new("clang");
    command
        .args([
            "-std=c11",
            "-Werror=implicit-function-declaration",
            "-x",
            "c",
            "-",
        ])
        .arg("-x")
        .arg("none")
        .arg(&original)
        .arg("-o")
        .arg(&executable);
    let compiled = common::compiler::run(&mut command, Some(&source));
    assert!(
        compiled.status.success(),
        "{}\n{source}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    assert!(Command::new(executable).status().unwrap().success());
}

#[test]
fn fixture_corpus_constant_matches_are_recorded() {
    let mut output = String::new();
    for fixture in common::fixtures() {
        let path = common::fixtures_dir().join(&fixture);
        let Ok(mut binary) = Binary::open(&path) else {
            continue;
        };
        let result = velk::xrefs::query::run(
            &mut binary,
            velk::xrefs::query::Query::DetectConstants,
            None,
        )
        .unwrap();
        for matched in result["matches"].as_array().unwrap() {
            use std::fmt::Write as _;
            writeln!(
                output,
                "{}: {} {} {} {}",
                fixture.display(),
                matched["name"].as_str().unwrap(),
                matched["addr"].as_str().unwrap(),
                matched["kind"].as_str().unwrap(),
                matched["functions"]
            )
            .unwrap();
        }
    }
    let expected = common::root().join("tests/data/byte_search/corpus_matches.txt");
    if let Some(difference) = common::check_expected(&expected, &output) {
        panic!("{difference}");
    }
}

#[test]
fn architecture_selection_is_available_to_memory_queries() {
    let path = common::root().join("tests/universal/universal.o");
    for arch in ["arm64", "x86_64"] {
        let expected = cli(&path, &["--search", "??", "--arch", arch]);
        assert!(!expected["matches"].as_array().unwrap().is_empty());
        let code = format!("velk.open({path:?},{{arch:{arch:?}}}).search('??')");
        assert_eq!(script(&code), expected);
    }
}

#[test]
fn global_annotations_override_detected_table_names() {
    let path = common::root().join("tests/data/byte_search/aarch64.elf");
    let project = common::root()
        .join("target")
        .join(format!("memory-project-{}.json", std::process::id()));
    if project.exists() {
        std::fs::remove_file(&project).unwrap();
    }
    let code = format!(
        "const b=velk.open({path:?},{{project:{project:?}}}); const address=b.search('63 7c 77 7b').matches[0].addr; b.projectSet({{target:{{kind:'global',address}},name:'lookup_bytes'}}); b.getFunction('table_byte').decompile()"
    );
    let outcome = Engine::new().unwrap().run(&code, None);
    assert!(outcome.error.is_none(), "{:?}", outcome.error);
    assert!(
        outcome.output.contains("lookup_bytes"),
        "{}",
        outcome.output
    );
    assert!(!outcome.output.contains("aes_sbox"), "{}", outcome.output);
    std::fs::remove_file(project).unwrap();
}

#[test]
fn pe_virtual_tails_are_zero_without_reading_the_next_file_region() {
    use object::{Object as _, ObjectSection as _};
    let path = common::root().join("tests/data/byte_search/section_tail.dll");
    let bytes = std::fs::read(&path).unwrap();
    let file = object::File::parse(bytes.as_slice()).unwrap();
    let section = file.section_by_name(".data").unwrap();
    let (file_offset, file_size) = section.file_range().unwrap();
    assert!(section.size() > file_size + 16);
    let next = usize::try_from(file_offset + file_size).unwrap();
    assert_eq!(
        bytes[next], 0xa5,
        "the next file region contains different initialized data"
    );
    let start = velk::addr::format(section.address() + file_size - 2);
    let end = velk::addr::format(section.address() + file_size + 2);
    let tail = velk::addr::format(section.address() + file_size);
    let read = cli(
        &path,
        &["--read-memory", &tail, "--type", "u32", "--count", "4"],
    );
    assert_eq!(read["values"], json!([0, 0, 0, 0]));
    let pattern = cli(
        &path,
        &["--search", "00 00 00 00", "--start", &start, "--end", &end],
    );
    assert_eq!(pattern["matches"].as_array().unwrap().len(), 1);
    let code = format!(
        "const b=velk.open({path:?}); ({{read:b.readMemory({tail:?},'u32',{{count:4}}),pattern:b.search('00 00 00 00',{{start:{start:?},end:{end:?}}})}})"
    );
    assert_eq!(script(&code), json!({"read":read,"pattern":pattern}));
    assert_eq!(mcp(&code), json!({"read":read,"pattern":pattern}));
}

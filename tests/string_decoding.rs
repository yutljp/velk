//! Source-grounded checks of automatic recovery and its public interfaces.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use serde_json::{Value, json};
use velk::service::Binary;

fn fixtures() -> &'static Path {
    static DIRECTORY: OnceLock<PathBuf> = OnceLock::new();
    DIRECTORY.get_or_init(|| {
        let directory = common::root().join(format!(
            "target/string-decoding-tests-{}",
            std::process::id()
        ));
        let output = Command::new("sh")
            .arg(common::root().join("tests/make_string_decoding_fixtures.sh"))
            .arg(&directory)
            .output()
            .expect("compiling string fixtures");
        assert!(output.status.success(), "{output:?}");
        directory
    })
}

const CASES: &[(&str, &[&str])] = &[
    ("case_xor", &["xor sample text"]),
    ("case_rolling", &["rolling sample text"]),
    ("case_rc4", &["rc4 sample text"]),
    ("case_base64", &["base64 sample text"]),
    ("case_many", &["first sample text", "second sample text"]),
    ("case_inline", &["inline stack"]),
    ("case_stack", &["stack bytes"]),
    ("case_utf8", &["café sample"]),
    ("case_wide", &["wide sample"]),
    ("case_global_inline", &["global inline"]),
    ("case_known_terminator", &["xor sample text"]),
];

#[test]
fn source_text_matches_native_execution() {
    let output = Command::new(fixtures().join("reference"))
        .output()
        .expect("running source reference");
    assert!(output.status.success(), "{output:?}");
    let mut expected = String::from(
        "xor sample text\nrolling sample text\nrc4 sample text\nbase64 sample text\nfirst sample text\nsecond sample text\n12 11\n",
    );
    for index in 0..32 {
        expected.push_str(&format!("message number {index:02}\n"));
    }
    expected.push_str("café sample\nwide sample\nglobal inline\nxor sample text\n");
    assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
}

#[test]
fn an_expired_scan_does_not_cache_a_miss() {
    let mut binary = Binary::open(&fixtures().join("x86_64.O0.elf")).unwrap();
    let address = binary.find("case_xor").unwrap().addr;
    assert!(
        binary
            .decoded_strings_at(address, Some(std::time::Instant::now()))
            .is_empty()
    );
    assert_eq!(
        binary.decoded_strings_at(address, None)[0].text,
        "xor sample text"
    );
}

#[test]
fn architecture_and_optimization_matrix() {
    for architecture in ["x86_64", "aarch64", "i386", "arm32", "thumb32"] {
        for optimization in ["O0", "O2"] {
            let path = fixtures().join(format!("{architecture}.{optimization}.elf"));
            let mut binary = Binary::open(&path).unwrap();
            for &(name, expected) in CASES {
                let address = binary.find(name).unwrap().addr;
                let strings = binary.decoded_strings_at(address, None);
                let found: Vec<_> = strings.iter().map(|s| s.text.as_str()).collect();
                let wrong = found.iter().filter(|text| !expected.contains(text)).count();
                let missed = expected.iter().filter(|text| !found.contains(text)).count();
                eprintln!(
                    "{architecture} {optimization} {name}: found={} wrong={wrong} missed={missed}",
                    found.len()
                );
                assert_eq!(wrong, 0, "{strings:?}");
                assert_eq!(
                    missed, 0,
                    "{architecture} {optimization} {name}: {strings:?}"
                );
                let code = binary.decompile(address, None, None).unwrap();
                if missed == 0 {
                    for text in expected {
                        assert!(code.contains(text), "{code}");
                    }
                }
                binary.set_string_decoding(false);
                let plain = binary.decompile(address, None, None).unwrap();
                assert!(!plain.contains("/* decoded at"), "{plain}");
                let mut uncommented = String::new();
                for line in code.lines() {
                    let mut remaining = line;
                    while let Some(start) = remaining.find(" /* decoded at") {
                        uncommented.push_str(&remaining[..start]);
                        let end = remaining[start..].find(" */").unwrap() + start + 3;
                        remaining = &remaining[end..];
                    }
                    if remaining.starts_with("/* decoded at") {
                        continue;
                    }
                    uncommented.push_str(remaining);
                    uncommented.push('\n');
                }
                assert_eq!(uncommented, plain, "recovery must only add comments");
                binary.set_string_decoding(true);
            }
            for name in [
                "unknown_key",
                "unknown_buffer",
                "unknown_stack",
                "plain_copy",
                "never_finishes",
                "unexpected_write",
                "stops_on_trap",
                "unchanged_text",
                "unchanged_terminated_text",
                "unexpected_nearby_write",
            ] {
                let address = binary.find(name).unwrap().addr;
                assert!(
                    binary.decoded_strings_at(address, None).is_empty(),
                    "{architecture} {optimization} {name}"
                );
            }
            if architecture == "x86_64" || architecture == "i386" {
                let address = binary.find("changed_return").unwrap().addr;
                assert!(binary.decoded_strings_at(address, None).is_empty());
            }
            let address = binary.find("case_bulk").unwrap().addr;
            let strings = binary.decoded_strings_at(address, None);
            assert_eq!(
                strings.len(),
                32,
                "{architecture} {optimization}: {strings:?}"
            );
            for (index, string) in strings.iter().enumerate() {
                assert_eq!(string.text, format!("message number {index:02}"));
            }
            let code = binary.decompile(address, None, None).unwrap();
            for index in 0..32 {
                assert!(
                    code.contains(&format!("message number {index:02}")),
                    "{code}"
                );
            }
            eprintln!("{architecture} {optimization} repeated calls: found=32 wrong=0 missed=0");
            let shared = fixtures().join(format!("{architecture}.{optimization}.shared.elf"));
            let mut binary = Binary::open(&shared).unwrap();
            let address = binary.find("case_unknown_call").unwrap().addr;
            assert!(binary.decoded_strings_at(address, None).is_empty());
            let report = velk::emulation::run(
                &binary,
                "case_unknown_call",
                &velk::emulation::Options::default(),
                None,
            )
            .unwrap();
            assert_eq!(report.reason, "error");
            assert!(report.error.unwrap().contains("external_event"));
            let address = binary.find("case_heap").unwrap().addr;
            let strings = binary.decoded_strings_at(address, None);
            assert_eq!(
                strings.len(),
                1,
                "{architecture} {optimization}: {strings:?}"
            );
            assert_eq!(strings[0].text, "xor sample text");
            assert!(
                !strings[0].stack,
                "heap buffers must not be labeled as stack buffers"
            );
            eprintln!("{architecture} {optimization} heap XOR: found=1 wrong=0 missed=0");
        }
    }
}

#[test]
fn batch_comments_match_single_requests() {
    let path = fixtures().join("x86_64.O0.elf");
    let mut binary = Binary::open(&path).unwrap();
    let addresses: Vec<_> = ["case_xor", "case_rolling"]
        .iter()
        .map(|name| binary.find(name).unwrap().addr)
        .collect();
    for enabled in [true, false] {
        binary.set_string_decoding(enabled);
        let batch = binary.decompile_many(&addresses, None, None).unwrap();
        for (&address, result) in addresses.iter().zip(batch) {
            let code = result.unwrap();
            assert_eq!(code.contains("/* decoded at"), enabled);
            assert_eq!(code, binary.decompile(address, None, None).unwrap());
        }
        let mut command = Command::new(env!("CARGO_BIN_EXE_velk"));
        command
            .arg("-D")
            .arg(&path)
            .args(["case_xor", "case_rolling"]);
        if !enabled {
            command.arg("--no-string-decoding");
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{output:?}");
        let code = String::from_utf8(output.stdout).unwrap();
        assert_eq!(code.contains("xor sample text"), enabled);
        assert_eq!(code.contains("rolling sample text"), enabled);
    }
    let engine = velk::script::Engine::new().unwrap();
    let output = engine.run(
        &format!(
            "const b = velk.open({}); const f = b.getFunction('case_xor'); \
             f.decompile({{decodeStrings:false}}); \
             b.decompile([f, b.getFunction('case_rolling')])",
            json!(path)
        ),
        None,
    );
    assert!(output.error.is_none(), "{:?}", output.error);
    let results: Value = serde_json::from_str(&output.output).unwrap();
    for (index, text) in ["xor sample text", "rolling sample text"]
        .iter()
        .enumerate()
    {
        assert_eq!(results[index]["error"], Value::Null);
        assert!(results[index]["code"].as_str().unwrap().contains(text));
    }
}

#[test]
fn documentation_examples() {
    let path = fixtures().join("x86_64.O0.elf");
    for document in ["docs/STRING_DECODING.md", "docs/STRING_DECODING.ja.md"] {
        let text = fs::read_to_string(common::root().join(document)).unwrap();
        let mut language = "";
        let mut script = String::new();
        for line in text.lines() {
            if let Some(next) = line.strip_prefix("```") {
                if language == "js" {
                    let engine = velk::script::Engine::new().unwrap();
                    let output = engine.run(
                        &script.replace("\"app.elf\"", &json!(path).to_string()),
                        None,
                    );
                    assert!(output.error.is_none(), "{document}: {:?}", output.error);
                    if script.contains("decode: false") {
                        assert_eq!(output.output, "[]");
                    }
                    if script.contains("decodeStrings: false") {
                        assert!(!output.output.contains("/* decoded at"));
                    }
                    script.clear();
                }
                language = next;
                continue;
            }
            if language == "sh" && line.starts_with("velk ") {
                let mut command = Command::new(env!("CARGO_BIN_EXE_velk"));
                for word in line.split_whitespace().skip(1) {
                    if word == "app.elf" {
                        command.arg(&path);
                    } else {
                        command.arg(word);
                    }
                }
                let output = command.output().unwrap();
                assert!(output.status.success(), "{document}: {line}: {output:?}");
            } else if language == "js" {
                script.push_str(line);
                script.push('\n');
            }
        }
    }
}

#[test]
fn recovered_call_comments_compile_and_execute() {
    let path = fixtures().join("x86_64.O0.elf");
    let mut binary = Binary::open(&path).unwrap();
    let object = fixtures().join("routines.o");
    let mut compiler = Command::new("clang");
    compiler.args(["-O0", "-fno-builtin", "-c"]);
    for &(name, _) in CASES {
        compiler.arg(format!("-D{name}=source_{name}"));
    }
    compiler.arg("-Dcase_comment=source_case_comment");
    let output = compiler
        .arg(common::root().join("tests/string_decoding/fixtures.c"))
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let mut cases = CASES[..5].to_vec();
    cases.push(("case_comment", &["comment */ text\\\nend"]));
    for (name, expected) in cases {
        let address = binary.find(name).unwrap().addr;
        let mut code = binary.decompile(address, None, None).unwrap();
        let globals: &[&str] = match name {
            "case_xor" => &["xor_data"],
            "case_rolling" => &["rolling_data"],
            "case_rc4" => &["rc4_data"],
            "case_base64" => &["base64_data"],
            "case_comment" => &["comment_data"],
            _ => &["many_a_data", "many_b_data"],
        };
        code.push_str(&format!(
            "\n#include <stdio.h>\nint main(void) {{ (void){name}();\n"
        ));
        for global in globals {
            code.push_str(&format!("puts((const char *)&{global});\n"));
        }
        code.push_str("return 0; }\n");
        let source = fixtures().join(format!("{name}.c"));
        let executable = fixtures().join(format!("{name}.native"));
        fs::write(&source, code).unwrap();
        let output = Command::new("clang")
            .args([
                "-O2",
                "-fno-builtin",
                "-Werror=implicit-function-declaration",
            ])
            .arg(&source)
            .arg(&object)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(output.status.success(), "{name}: {output:?}");
        let output = Command::new(executable).output().unwrap();
        assert!(output.status.success(), "{name}: {output:?}");
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("{}\n", expected.join("\n"))
        );
    }
}

fn strings_cli(path: &Path, disabled: bool) -> Value {
    let mut command = Command::new(env!("CARGO_BIN_EXE_velk"));
    command
        .arg("--strings")
        .arg(path)
        .args(["--contains", "sample"]);
    if disabled {
        command.arg("--no-string-decoding");
    }
    let output = command.output().expect("listing strings");
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).expect("valid strings JSON")
}

#[test]
fn cli_javascript_mcp_and_disable_option() {
    use std::io::Write as _;
    let path = fixtures().join("x86_64.O0.elf");
    let cli = strings_cli(&path, false);
    assert!(
        cli["decodedStrings"].as_array().unwrap().len() >= 6,
        "{cli}"
    );
    assert_eq!(strings_cli(&path, true)["decodedStrings"], json!([]));
    let code = format!(
        "const b = velk.open({}); b.strings({{contains:'sample'}})",
        json!(path)
    );
    let engine = velk::script::Engine::new().unwrap();
    let output = engine.run(&code, None);
    assert!(output.error.is_none(), "{:?}", output.error);
    assert_eq!(serde_json::from_str::<Value>(&output.output).unwrap(), cli);
    let disabled = engine.run(
        &format!(
            "velk.open({}).strings({{decode:false}}).decodedStrings",
            json!(path)
        ),
        None,
    );
    assert_eq!(disabled.output, "[]");
    let output = engine.run(
        &format!(
            "velk.open({}).getFunction('case_xor').strings()",
            json!(path)
        ),
        None,
    );
    assert!(output.error.is_none(), "{:?}", output.error);
    assert!(
        output.output.contains("xor sample text"),
        "{}",
        output.output
    );
    let output = engine.run(
        &format!(
            "velk.open({}).getFunction('case_xor').strings({{decode:false}})",
            json!(path)
        ),
        None,
    );
    assert!(output.error.is_none(), "{:?}", output.error);
    assert!(
        !output.output.contains("xor sample text"),
        "{}",
        output.output
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"velk_run_script","arguments":{"code":code,"max_output_chars":20000}}});
    writeln!(child.stdin.take().unwrap(), "{request}").unwrap();
    let output = child.wait_with_output().unwrap();
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["result"]["isError"], false, "{response}");
    let result: Value =
        serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(result, cli);
    for disabled in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_velk"));
        command.arg("-D").arg(&path).arg("case_xor");
        if disabled {
            command.arg("--no-string-decoding");
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("/* decoded at"),
            !disabled
        );
        let script = format!(
            "velk.open({}).getFunction('case_xor').decompile({{decodeStrings:{}}})",
            json!(path),
            !disabled
        );
        let output = engine.run(&script, None);
        assert!(output.error.is_none(), "{:?}", output.error);
        assert_eq!(output.output.contains("/* decoded at"), !disabled);
    }
}

#[test]
fn existing_fixture_findings_are_reviewable() {
    let mut paths = Vec::new();
    fn collect(directory: &Path, paths: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect(&path, paths);
            } else {
                paths.push(path);
            }
        }
    }
    collect(&common::fixtures_dir(), &mut paths);
    paths.sort();
    let mut findings = Vec::new();
    for path in paths {
        let Ok(mut binary) = Binary::open(&path) else {
            continue;
        };
        for string in binary.decoded_strings(None) {
            findings.push(format!(
                "{} {:#x} {:#x} {:?}",
                path.strip_prefix(common::fixtures_dir()).unwrap().display(),
                string.function,
                string.site,
                string.text
            ));
        }
    }
    let actual = findings.join("\n");
    eprintln!("Existing fixture findings:\n{actual}");
    assert!(
        findings.is_empty(),
        "Review each recovered string against the fixture source:\n{actual}"
    );
}

#[test]
fn whole_binary_scan_reaches_functions_after_first_thousand() {
    let directory = fixtures();
    let source = directory.join("many-functions.c");
    let binary_path = directory.join("many-functions.elf");
    let mut code = String::new();
    for index in 0..1001 {
        code.push_str(&format!("void dummy_{index}(void) {{}}\n"));
    }
    code.push_str(&format!(
        "#include \"{}\"\n",
        common::root()
            .join("tests/string_decoding/fixtures.c")
            .display()
    ));
    fs::write(&source, code).unwrap();
    let output = Command::new("clang")
        .args([
            "--target=x86_64-linux-gnu",
            "-O0",
            "-fno-builtin",
            "-fno-stack-protector",
            "-fno-pie",
            "-nostdlib",
            "-static",
            "-fuse-ld=lld",
            "-Wl,-e,case_xor",
            "-Wl,--build-id=none",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&binary_path)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let mut binary = Binary::open(&binary_path).unwrap();
    let address = binary.find("case_xor").unwrap().addr;
    assert!(
        binary
            .functions()
            .iter()
            .filter(|function| function.addr < address)
            .count()
            > 1000
    );
    assert!(
        binary
            .decoded_strings(None)
            .iter()
            .any(|string| { string.function == address && string.text == "xor sample text" })
    );
}

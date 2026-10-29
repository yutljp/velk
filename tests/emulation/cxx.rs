//! Standard C++ streams compared with the compiled program.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use serde_json::{Value, json};
use velk::service::Binary;
use velk::symbolic;

use super::matrix::Interfaces;
use crate::common;

fn fixtures() -> &'static [PathBuf] {
    static FIXTURES: OnceLock<Vec<PathBuf>> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        let directory = common::root().join(format!("target/cxx-streams-{}", std::process::id()));
        if directory.exists() {
            fs::remove_dir_all(&directory).expect("remove stale C++ fixtures");
        }
        let output = Command::new("bash")
            .arg(common::root().join("tools/make_cxx_stream_fixtures.sh"))
            .arg(&directory)
            .output()
            .expect("C++ fixture builder");
        assert!(output.status.success(), "{output:?}");
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        let mut paths = Vec::new();
        for entry in fs::read_dir(directory).expect("C++ fixture directory") {
            let path = entry.expect("C++ fixture entry").path();
            if path
                .file_name()
                .expect("file name")
                .to_string_lossy()
                .contains("-O")
                && path.extension().is_none()
            {
                paths.push(path);
            }
        }
        paths.sort();
        paths
    })
}

fn native(path: &Path, function: &str, input: &[u8]) -> std::process::Output {
    let mut command = Command::new(path);
    if path
        .file_name()
        .expect("fixture name")
        .to_string_lossy()
        .starts_with("aarch64-")
    {
        command = Command::new("qemu-aarch64");
        command.args(["-L", "/usr/aarch64-linux-gnu"]).arg(path);
    }
    let mut child = command
        .arg(if function == "integer_echo" {
            "echo"
        } else if function == "integer_status" {
            "j"
        } else if function == "character_input" {
            "h"
        } else if function == "cstring_input" {
            "p"
        } else if function == "raw_character_input" {
            "q"
        } else if function == "locale_characters" {
            "types"
        } else if function == "locale_input" {
            "facet"
        } else {
            function
        })
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("native C++ program");
    child
        .stdin
        .take()
        .expect("native stdin")
        .write_all(input)
        .expect("input bytes");
    child.wait_with_output().expect("native result")
}

#[test]
fn standard_streams_match_native() {
    let mut interfaces = Interfaces::new();
    for path in fixtures() {
        let binary = Binary::open(path).expect("C++ binary");
        for function in [
            "word",
            "line",
            "integer",
            "integer_echo",
            "numbers",
            "unsigned_numbers",
            "constants",
            "string_operations",
            "guarded_string",
        ] {
            let inputs: &[&[u8]] = match function {
                "word" => &[
                    b"key\n",
                    b"wrong next",
                    b"  \tkey\n",
                    b"a\0b",
                    b"abcdefghijklmno",
                    b"abcdefghijklmnop",
                    b"abcdefghijklmnopqrstuv",
                    b"abcdefghijklmnopqrstuvw",
                    b"abcdefghijklmnopqrstuvwxyz\n",
                ],
                "line" => &[
                    b"a key\n",
                    b"\n",
                    b"wrong\n",
                    b"a\0b\n",
                    b"abcdefghijklmnopqrstuvw\n",
                    b"unterminated",
                ],
                "constants" | "guarded_string" => &[b""],
                "string_operations" => &[b"key", b"alpha", b"a", b"abcdefghijklmno"],
                "numbers" => &[
                    b"-123",
                    b"0",
                    b"9223372036854775807",
                    b"-9223372036854775808",
                ],
                "unsigned_numbers" => &[
                    b"0",
                    b"18446744073709551615",
                    b"-1",
                    b"-18446744073709551615",
                    b"-18446744073709551616",
                ],
                _ => &[
                    b"-123\n",
                    b"0",
                    b"+17x",
                    b"-2147483648\n",
                    b"2147483647\n",
                    b" \t42\n",
                ],
            };
            for input in inputs {
                let reference = native(path, function, input);
                let report =
                    interfaces.check(path, &binary, function, json!({"stdin":{"hex":hex(input)}}));
                assert_eq!(
                    report["reason"],
                    "return",
                    "{} {function} {input:?}: {report}",
                    path.display()
                );
                assert_eq!(
                    report["stdout"],
                    String::from_utf8_lossy(&reference.stdout).as_ref(),
                    "{} {function} {input:?}",
                    path.display()
                );
                assert_eq!(
                    super::matrix::value(&report),
                    reference.status.code().expect("native exit") as u32
                );
            }
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
#[cfg(target_os = "macos")]
fn locale_characters_match_native() {
    let mut interfaces = Interfaces::new();
    for path in fixtures() {
        let binary = Binary::open(path).expect("C++ binary");
        let reference = native(path, "locale_characters", b"");
        assert!(reference.status.success(), "{reference:?}");
        let report = interfaces.check(
            path,
            &binary,
            "locale_characters",
            json!({"stepLimit":1000000,"timeLimitMs":30000}),
        );
        assert_eq!(report["reason"], "return", "{}: {report}", path.display());
        assert_eq!(
            report["stdout"],
            String::from_utf8_lossy(&reference.stdout).as_ref()
        );
        assert_eq!(super::matrix::value(&report), 0);
    }
}

#[test]
fn explored_inputs_replay_natively() {
    if !Command::new("z3")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
    {
        eprintln!("SKIP C++ exploration: z3 unavailable");
        return;
    }
    let engine = velk::script::Engine::new().expect("JavaScript engine");
    for path in fixtures() {
        let binary = Binary::open(path).expect("C++ binary");
        let mut cases = vec![
            ("word", 3),
            ("line", 5),
            ("integer", 4),
            ("string_operations", 3),
        ];
        if cfg!(target_os = "macos") {
            cases.push(("locale_input", 1));
        }
        for (function, count) in cases {
            let options = json!({"stdin":count,"find":[format!("0x{:x}", binary.find("accepted").expect("accepted function").addr)],"pathLimit":4096,"stepLimit":100000});
            eprintln!("explore {} {function}", path.display());
            let report = symbolic::explore(
                &binary,
                function,
                &serde_json::from_value(options.clone()).expect("exploration options"),
            )
            .expect("C++ exploration");
            assert!(report.found, "{} {function}: {report:?}", path.display());
            let inputs = report.inputs.expect("found input");
            let replay = native(path, function, &inputs.stdin);
            assert!(
                replay.status.success(),
                "{} {function} {:?}: {replay:?}",
                path.display(),
                inputs.stdin
            );
            assert_eq!(replay.stdout, inputs.stdout);
            let cli = Command::new(env!("CARGO_BIN_EXE_velk"))
                .arg("--explore")
                .arg(function)
                .args([
                    "--find",
                    options["find"][0].as_str().expect("find address"),
                    "--json",
                    "--symbolic-options",
                    &options.to_string(),
                ])
                .arg(path)
                .output()
                .expect("explore CLI");
            assert!(cli.status.success(), "{cli:?}");
            let cli: Value = serde_json::from_slice(&cli.stdout).expect("CLI report");
            replay_json(path, function, &cli);
            let script = engine.run(
                &format!(
                    "velk.open({}).explore({}, {})",
                    json!(path),
                    json!(function),
                    options
                ),
                None,
            );
            assert!(script.error.is_none(), "{:?}", script.error);
            let script: Value = serde_json::from_str(&script.output).expect("JavaScript report");
            replay_json(path, function, &script);
            let child = Command::new(env!("CARGO_BIN_EXE_velk"))
                .arg("--mcp")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .expect("MCP server");
            let output = common::mcp_request(
                child,
                &json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"velk_explore","arguments":{"path":path,"start":function,"options":options}}}),
            );
            let response: Value = serde_json::from_slice(&output.stdout).expect("MCP JSON");
            assert_eq!(response["result"]["isError"], false, "{response}");
            let report: Value = serde_json::from_str(
                response["result"]["content"][0]["text"]
                    .as_str()
                    .expect("MCP text"),
            )
            .expect("MCP report");
            replay_json(path, function, &report);
        }
    }
}

#[test]
fn stream_abi_layouts_on_both_instruction_sets() {
    let mut interfaces = Interfaces::new();
    let directory = fixtures()
        .first()
        .expect("C++ fixture")
        .parent()
        .expect("fixture directory");
    for (arch, format) in [
        ("x86_64", "so"),
        ("aarch64", "so"),
        ("x86_64", "dylib"),
        ("arm64", "dylib"),
    ] {
        for opt in [0, 2] {
            let path = directory.join(format!("{arch}-abi-O{opt}.{format}"));
            if !path.exists() {
                continue;
            }
            let binary = Binary::open(&path).expect("C++ ABI fixture");
            if format == "dylib" {
                let report = interfaces.check(
                    &path,
                    &binary,
                    "abi_llvm_locale",
                    json!({"stepLimit":100000}),
                );
                assert_eq!(report["reason"], "return", "{arch} O{opt}: {report}");
                assert_eq!(super::matrix::value(&report), 0, "{report}");
                let report = interfaces.check(&path, &binary, "abi_bad_llvm_facet", json!({}));
                assert_eq!(report["reason"], "error", "{report}");
                assert!(
                    report["error"]
                        .as_str()
                        .expect("error")
                        .contains("unsupported C++ locale facet"),
                    "{report}"
                );
            }
            for function in ["abi_gnu_word", "abi_llvm_word", "abi_llvm_line"] {
                for input in [
                    "key",
                    "a key",
                    "abcdefghijklmno",
                    "abcdefghijklmnop",
                    "abcdefghijklmnopqrstuv",
                    "abcdefghijklmnopqrstuvw",
                    "abcdefghijklmnopqrstuvwxyz",
                ] {
                    let report =
                        interfaces.check(&path, &binary, function, json!({"stdin":{"text":input}}));
                    assert_eq!(
                        report["reason"], "return",
                        "{arch} O{opt} {format} {function} {input}: {report}"
                    );
                    assert_eq!(
                        report["stdout"],
                        if function.ends_with("line") {
                            input
                        } else {
                            input.split_whitespace().next().expect("nonempty input")
                        }
                    );
                }
            }
            for input in [
                "key",
                "a",
                "abcdefghijklmno",
                "abcdefghijklmnop",
                "abcdefghijklmnopqrstuvwxyz",
            ] {
                let reference = native(
                    fixtures().first().expect("native C++ fixture"),
                    "access",
                    input.as_bytes(),
                );
                let report = interfaces.check(
                    &path,
                    &binary,
                    "abi_gnu_access",
                    json!({"stdin":{"text":input}}),
                );
                assert_eq!(
                    report["reason"], "return",
                    "{arch} O{opt} {format}: {report}"
                );
                assert_eq!(
                    super::matrix::value(&report),
                    reference.status.code().expect("native exit") as u32,
                    "{report}"
                );
                assert_eq!(
                    report["stdout"],
                    String::from_utf8_lossy(&reference.stdout).as_ref()
                );
            }
            for function in ["abi_gnu_integer", "abi_llvm_integer"] {
                for input in ["-123", "0", "9223372036854775807", "-9223372036854775808"] {
                    let report =
                        interfaces.check(&path, &binary, function, json!({"stdin":{"text":input}}));
                    assert_eq!(
                        report["reason"], "return",
                        "{arch} O{opt} {format} {function}: {report}"
                    );
                    assert_eq!(report["stdout"], input);
                }
            }
            for (input, expected) in [("xke", 0), ("xk", -1), ("xkf", 1)] {
                let report = interfaces.check(
                    &path,
                    &binary,
                    "abi_llvm_compare_range",
                    json!({"stdin":{"text":input}}),
                );
                assert_eq!(report["reason"], "return", "{report}");
                assert_eq!(super::matrix::value(&report), expected as u32, "{report}");
            }
            let startup = interfaces.check(&path, &binary, "abi_startup", json!({}));
            assert_eq!(super::matrix::value(&startup), 0);
            for function in [
                "abi_bad_gnu_size",
                if format == "dylib" {
                    "abi_bad_llvm_alternate_size"
                } else {
                    "abi_bad_llvm_size"
                },
            ] {
                let report = interfaces.check(&path, &binary, function, json!({}));
                assert_eq!(report["reason"], "error", "{report}");
                assert!(
                    report["error"].as_str().expect("error").contains(
                        if function == "abi_bad_gnu_size" {
                            "exceeds model bound"
                        } else {
                            "invalid libc++ short string size"
                        }
                    ),
                    "{report}"
                );
            }
        }
    }
}

#[test]
fn unsupported_stream_operations_stop() {
    let mut interfaces = Interfaces::new();
    for path in fixtures() {
        let binary = Binary::open(path).expect("C++ binary");
        for (function, input) in [("formatted", ""), ("unsupported", "")] {
            let report = interfaces.check(path, &binary, function, json!({"stdin":{"text":input}}));
            assert_eq!(
                report["reason"],
                "error",
                "{} {function}: {report}",
                path.display()
            );
            assert!(
                report["error"]
                    .as_str()
                    .expect("diagnostic")
                    .contains("unsupported C++"),
                "{report}"
            );
        }
    }
}

#[test]
fn stream_extraction_failures_match_native() {
    let mut interfaces = Interfaces::new();
    for path in fixtures() {
        let binary = Binary::open(path).expect("C++ binary");
        for (function, inputs) in [
            (
                "integer_status",
                &[
                    b"42".as_slice(),
                    b"x",
                    b"",
                    b"   ",
                    b"+x",
                    b"2147483648",
                    b"-2147483649",
                    b"2147483647",
                    b"-2147483648",
                    b"4x",
                ][..],
            ),
            (
                "character_input",
                &[b"a".as_slice(), b" a", b" \t", b"", b"\xff"][..],
            ),
            (
                "raw_character_input",
                &[b"a".as_slice(), b" a", b"\n", b"", b"\xff"][..],
            ),
            (
                "cstring_input",
                &[b"word rest".as_slice(), b" word", b"\t\n", b"", b"word"][..],
            ),
        ] {
            for input in inputs {
                let reference = native(path, function, input);
                let report =
                    interfaces.check(path, &binary, function, json!({"stdin":{"hex":hex(input)}}));
                assert_eq!(
                    report["reason"],
                    "return",
                    "{} {function} {input:?}: {report}",
                    path.display()
                );
                assert_eq!(
                    report["stdout"],
                    String::from_utf8_lossy(&reference.stdout).as_ref(),
                    "{} {function} {input:?}",
                    path.display()
                );
                assert_eq!(
                    super::matrix::value(&report),
                    reference.status.code().expect("native exit") as u32
                );
            }
        }
    }
}

fn replay_json(path: &Path, function: &str, report: &Value) {
    assert_eq!(report["found"], true, "{report}");
    let bytes: Vec<u8> =
        serde_json::from_value(report["inputs"]["stdin"].clone()).expect("found stdin");
    let expected: Vec<u8> =
        serde_json::from_value(report["inputs"]["stdout"].clone()).expect("found stdout");
    let output = native(path, function, &bytes);
    assert!(
        output.status.success(),
        "{} {function} {bytes:?}: {output:?}",
        path.display()
    );
    assert_eq!(output.stdout, expected);
}

#[test]
fn symbolic_stream_abi_inputs_replay() {
    if !Command::new("z3")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
    {
        return;
    }
    let reference = fixtures().first().expect("native C++ fixture");
    let directory = reference.parent().expect("fixture directory");
    for arch in ["x86_64", "aarch64"] {
        for opt in [0, 2] {
            let path = directory.join(format!("{arch}-abi-O{opt}.so"));
            let binary = Binary::open(&path).expect("C++ ABI fixture");
            for function in [
                "abi_gnu_word",
                "abi_gnu_access",
                "abi_llvm_word",
                "abi_llvm_line",
            ] {
                let line = function.ends_with("line");
                let options = serde_json::from_value(json!({"stdin":if line {5} else {3},"find":[format!("0x{:x}",binary.find("abi_accepted").expect("target").addr)],"pathLimit":512})).expect("ABI exploration options");
                let report =
                    symbolic::explore(&binary, function, &options).expect("ABI exploration");
                assert!(report.found, "{arch} O{opt} {function}: {report:?}");
                let input = report.inputs.expect("found ABI input");
                let native_function = if line {
                    "line"
                } else if function == "abi_gnu_access" {
                    "access"
                } else {
                    "word"
                };
                let replay = native(reference, native_function, &input.stdin);
                assert!(replay.status.success(), "{replay:?}");
                if function == "abi_gnu_access" {
                    assert_eq!(replay.stdout, input.stdout);
                }
            }
        }
    }
}

#[test]
fn symbolic_unsupported_calls_report_the_import() {
    if !Command::new("z3")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
    {
        return;
    }
    let path = fixtures().first().expect("native C++ fixture");
    let binary = Binary::open(path).expect("native C++ binary");
    for function in ["unsupported", "formatted"] {
        let options = serde_json::from_value(
            json!({"find":[format!("0x{:x}", binary.find("accepted").expect("target").addr)]}),
        )
        .expect("exploration options");
        let report =
            symbolic::explore(&binary, function, &options).expect("unsupported exploration");
        assert!(!report.found, "{report:?}");
        assert!(
            report
                .diagnostics
                .iter()
                .any(|text| text.contains("unsupported C++") && text.contains("_Z")),
            "{report:?}"
        );
    }
}

#[test]
fn string_input_uses_the_existing_memory_bound() {
    let mut interfaces = Interfaces::new();
    let input = "a".repeat(100000);
    for path in fixtures() {
        let binary = Binary::open(path).expect("C++ binary");
        let report = interfaces.check(
            path,
            &binary,
            "word",
            json!({"stdin":{"text":input},"stepLimit":1000000,"timeLimitMs":10000}),
        );
        assert_eq!(report["reason"], "return", "{report}");
        assert_eq!(report["stdout"], format!("failure:{input}\n"));
        let reference = native(path, "word", input.as_bytes());
        assert_eq!(
            reference.stdout,
            report["stdout"].as_str().expect("captured text").as_bytes()
        );
    }
}

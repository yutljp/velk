//! Explicit file inputs across the execution interfaces and native libc.

use super::matrix;
use crate::common;

use std::fs;
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use velk::emulation;
use velk::service::Binary;
use velk::symbolic;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn file_streams_match_native_through_all_interfaces() {
    let mut interfaces = matrix::Interfaces::new();
    let directory = matrix::fixtures().join("native-streams");
    fs::create_dir_all(&directory).expect("native file directory");
    for architecture in matrix::ARCHITECTURES {
        for optimization in ["O0", "O2"] {
            let path =
                matrix::fixtures().join(format!("{architecture}.{optimization}.streams.elf"));
            let binary = Binary::open(&path).expect("stream fixture");
            for input in [
                b"".as_slice(),
                b"A",
                b"ab\n",
                b"OK\n",
                b"abc\r\nXYZ",
                b"OK\n\0\xff",
                b"abcdefghijk",
                b"\0\xff\x80\n",
            ] {
                for name in [
                    "descriptor_after_append",
                    "read_descriptor",
                    "read_file",
                    "write_file",
                    "update_file",
                    "solve_file",
                    "append_existing",
                ] {
                    let native = Command::new(matrix::fixtures().join("host.streams.native"))
                        .current_dir(&directory)
                        .args([name, &hex(input)])
                        .output()
                        .expect("native streams");
                    assert!(native.status.success(), "{native:?}");
                    let text = String::from_utf8(native.stdout).expect("ASCII reference");
                    let mut lines = text.lines();
                    let expected: u32 = lines
                        .next()
                        .expect("return value")
                        .parse()
                        .expect("unsigned return");
                    let report = interfaces.check(
                        &path,
                        &binary,
                        name,
                        json!({"files":{"input":input,"output":[]}}),
                    );
                    assert_eq!(
                        matrix::value(&report),
                        expected,
                        "{architecture} {optimization} {name} {input:?}: {report}"
                    );
                    for file in ["input", "output"] {
                        let bytes: Vec<u8> = serde_json::from_value(report["files"][file].clone())
                            .expect("file bytes");
                        assert_eq!(
                            hex(&bytes),
                            lines.next().expect("file bytes"),
                            "{architecture} {name} {file}"
                        );
                    }
                }
            }
            let report =
                interfaces.check(&path, &binary, "exit_file", json!({"files":{"output":[]}}));
            assert_eq!(report["reason"], "exit", "{architecture} {report}");
            assert_eq!(report["files"]["output"], json!([81]));
            let report = interfaces.check(
                &path,
                &binary,
                "caller_buffer",
                json!({"files":{"output":[]}}),
            );
            assert_eq!(report["reason"], "error", "{architecture} {report}");
            let report = interfaces.check(
                &path,
                &binary,
                "stream_boundaries",
                json!({"files":{"input":[],"output":[]}}),
            );
            assert_eq!(matrix::value(&report), 14);
            let report = interfaces.check(
                &path,
                &binary,
                "file_errors",
                json!({"files":{"input":[],"output":[]}}),
            );
            assert_eq!(matrix::value(&report), 58);
            let report = interfaces.check(
                &path,
                &binary,
                "unflushed_file",
                json!({"files":{"output":[1,2]}}),
            );
            assert_eq!(matrix::value(&report), 7);
            assert_eq!(report["files"]["output"], json!([]));
            for (name, diagnostic) in [
                ("invalid_file", "0x1234"),
                ("closed_file", "FILE pointer"),
                ("unknown_file", "missing"),
                ("unsupported_mode", "w+"),
            ] {
                let report = interfaces.check(&path, &binary, name, json!({"files":{"input":[]}}));
                assert_eq!(report["reason"], "error", "{report}");
                assert!(
                    report["error"]
                        .as_str()
                        .expect("diagnostic")
                        .contains(diagnostic),
                    "{report}"
                );
            }
        }
    }
}

#[test]
fn symbolic_file_solution_replays_across_interfaces() {
    if !Command::new("z3")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
    {
        return;
    }
    let engine = velk::script::Engine::new().expect("script engine");
    for architecture in ["x86_64", "i386", "aarch64"] {
        for optimization in ["O0", "O2"] {
            let path =
                matrix::fixtures().join(format!("{architecture}.{optimization}.streams.elf"));
            let binary = Binary::open(&path).expect("stream fixture");
            let options =
                serde_json::from_value(json!({"files":{"output":[]},"returns":{"eq":99}}))
                    .expect("exit options");
            let report = symbolic::solve(&binary, "exit_file", &options).expect("exit search");
            assert!(!report.found, "{report:?}");
            assert!(
                report.diagnostics.iter().any(|message| message == "exit"),
                "{report:?}"
            );
            let options = serde_json::from_value(json!({"files":{"output":[]},"returns":{"eq":1}}))
                .expect("symbolic options");
            let report =
                symbolic::solve(&binary, "caller_buffer", &options).expect("buffer search");
            assert!(!report.found, "{report:?}");
            assert!(
                report
                    .diagnostics
                    .iter()
                    .any(|message| message.contains("caller-owned buffer")),
                "{report:?}"
            );
            for (name, bytes, result) in [
                ("solve_file", vec![0; 5], 1u32),
                ("combined_inputs", vec![0; 1], 1),
                ("output_assignment", vec![], 1),
                ("write_file", vec![], 8),
                ("stream_boundaries", vec![], 14),
                ("append_existing", vec![0; 2], 2),
                ("file_errors", vec![], 58),
            ] {
                let options = json!({"files":{"input":bytes,"output":[]},"returns":{"eq":result},"stdin":if matches!(name, "combined_inputs" | "output_assignment") {1} else {0},"pathLimit":4096});
                let parsed = serde_json::from_value(options.clone()).expect("symbolic options");
                let report = symbolic::solve(&binary, name, &parsed).expect("solve file");
                assert!(
                    report.found,
                    "{architecture} {optimization} {name}: {report:?}"
                );
                let expected = serde_json::to_value(&report).expect("report");
                let cli = Command::new(env!("CARGO_BIN_EXE_velk"))
                    .args([
                        "--solve",
                        name,
                        "--returns",
                        &format!("eq:{result}"),
                        "--json",
                        "--symbolic-options",
                        &options.to_string(),
                    ])
                    .arg(&path)
                    .output()
                    .expect("CLI solve");
                assert!(cli.status.success(), "{cli:?}");
                assert_eq!(
                    serde_json::from_slice::<Value>(&cli.stdout).expect("CLI JSON"),
                    expected
                );
                let script = engine.run(
                    &format!(
                        "velk.open({}).solve({}, {})",
                        json!(path),
                        json!(name),
                        options
                    ),
                    None,
                );
                assert!(script.error.is_none(), "{:?}", script.error);
                assert_eq!(
                    serde_json::from_str::<Value>(&script.output).expect("JS report"),
                    expected
                );
                let child = Command::new(env!("CARGO_BIN_EXE_velk"))
                    .arg("--mcp")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()
                    .expect("MCP server");
                let output = common::mcp_request(
                    child,
                    &json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"velk_solve","arguments":{"path":path,"start":name,"options":options}}}),
                );
                let response: Value = serde_json::from_slice(&output.stdout).expect("MCP JSON");
                assert_eq!(response["result"]["isError"], false, "{response}");
                assert_eq!(
                    serde_json::from_str::<Value>(
                        response["result"]["content"][0]["text"]
                            .as_str()
                            .expect("MCP text")
                    )
                    .expect("MCP report"),
                    expected
                );
                let inputs = report.inputs.expect("solved file inputs");
                if name == "solve_file" {
                    assert_eq!(inputs.files["input"], b"OK\n\0\xff");
                }
                if name == "combined_inputs" {
                    assert_eq!(inputs.files["input"], b"Q");
                    assert_eq!(inputs.stdin, b"R");
                    assert_eq!(inputs.file_outputs["output"], b"Q");
                }
                if name == "output_assignment" {
                    assert_eq!(inputs.stdin, [0]);
                    assert_eq!(inputs.file_outputs["output"], [255]);
                }
                let replay = emulation::run(
                    &binary,
                    name,
                    &serde_json::from_value(
                        json!({"files":inputs.files,"stdin":{"hex":hex(&inputs.stdin)}}),
                    )
                    .expect("replay options"),
                    None,
                )
                .expect("replay");
                assert_eq!(replay.reason, "return", "{replay:?}");
                assert_eq!(
                    velk::addr::parse(&replay.return_value),
                    Some(u64::from(result))
                );
                assert_eq!(replay.files, inputs.file_outputs);
            }
        }
    }
}

#[test]
fn versioned_standard_streams_work_through_all_interfaces() {
    use std::io::Write as _;

    let mut native = Command::new(matrix::fixtures().join("host.versioned_streams.native"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("native stream reference");
    native
        .stdin
        .take()
        .expect("native stdin")
        .write_all(b"Q")
        .expect("reference input");
    let native = native.wait_with_output().expect("reference output");
    assert!(native.status.success(), "{native:?}");
    let mut interfaces = matrix::Interfaces::new();
    for architecture in matrix::ARCHITECTURES {
        let path = matrix::fixtures().join(format!("{architecture}.versioned_streams.elf"));
        let mut bytes = fs::read(&path).expect("stream fixture bytes");
        for name in ["stdin", "stdout", "stderr"] {
            let original = format!("{name}_symbol_version");
            let versioned = format!("{name}@@STREAM_1");
            for offset in 0..bytes.len().saturating_sub(original.len()) {
                if bytes[offset..].starts_with(original.as_bytes()) {
                    bytes[offset..offset + original.len()].fill(0);
                    bytes[offset..offset + versioned.len()].copy_from_slice(versioned.as_bytes());
                }
            }
        }
        fs::write(&path, bytes).expect("versioned stream symbols");
        let binary = Binary::open(&path).expect("versioned stream fixture");
        assert!(
            binary
                .image()
                .data_symbols
                .values()
                .any(|name| name == "stdin@@STREAM_1")
        );
        let report = interfaces.check(
            &path,
            &binary,
            "versioned_streams",
            json!({"stdin":{"text":"Q"}}),
        );
        assert_eq!(report["reason"], "return", "{architecture}: {report}");
        assert_eq!(matrix::value(&report), u32::from(b'Q'));
        assert_eq!(
            report["stdout"],
            String::from_utf8(native.stdout.clone()).expect("native text")
        );
        if matches!(architecture, "x86_64" | "aarch64" | "i386") {
            let options = serde_json::from_value(json!({"stdin":1,"returns":{"eq":81}}))
                .expect("search options");
            let report =
                symbolic::solve(&binary, "versioned_streams", &options).expect("stream search");
            assert!(report.found, "{architecture}: {report:?}");
        }
    }
}

#[test]
fn descriptor_limits_and_symbolic_inputs() {
    let mut interfaces = matrix::Interfaces::new();
    for architecture in matrix::ARCHITECTURES {
        for optimization in ["O0", "O2"] {
            let path =
                matrix::fixtures().join(format!("{architecture}.{optimization}.streams.elf"));
            let binary = Binary::open(&path).expect("descriptor fixture");
            let pending = interfaces.check(
                &path,
                &binary,
                "descriptor_close_preserves_pending_output",
                json!({"files":{"input":[65]}}),
            );
            assert_eq!(pending["reason"], "return", "{pending}");
            assert_eq!(pending["files"]["input"], json!([65]), "{pending}");
            let large_file = if matches!(architecture, "arm32" | "thumb32") {
                0x20000
            } else {
                0x8000
            };
            for flags in [0, large_file, 0x80000, large_file | 0x80000] {
                let report = interfaces.check(
                    &path,
                    &binary,
                    "open_flags",
                    json!({"arguments":[flags],"files":{"input":[]}}),
                );
                assert_eq!(matrix::value(&report), 3, "{architecture}: {report}");
            }
            for flags in [1, 2, 64, 512, 1024, u32::MAX] {
                let report = interfaces.check(
                    &path,
                    &binary,
                    "open_flags",
                    json!({"arguments":[flags],"files":{"input":[]}}),
                );
                assert!(
                    report["error"]
                        .as_str()
                        .expect("flags error")
                        .contains("unsupported flags"),
                    "{report}"
                );
            }
            let report = interfaces.check(
                &path,
                &binary,
                "descriptor_from_stream",
                json!({"files":{"input":[81]}}),
            );
            assert_eq!(report["reason"], "error", "{report}");
            let report = interfaces.check(
                &path,
                &binary,
                "closed_descriptor",
                json!({"files":{"input":[81]}}),
            );
            assert_eq!(report["reason"], "error", "{report}");
            if matches!(architecture, "x86_64" | "aarch64" | "i386") {
                let pending_options =
                    serde_json::from_value(json!({"files":{"input":[0]},"returns":{"eq":1}}))
                        .expect("pending file search options");
                let pending = symbolic::solve(
                    &binary,
                    "descriptor_close_preserves_pending_output",
                    &pending_options,
                )
                .expect("pending file search");
                assert!(pending.found, "{pending:?}");
                let inputs = pending.inputs.expect("pending file inputs");
                assert_eq!(inputs.file_outputs["input"], inputs.files["input"]);
                let options = serde_json::from_value(json!({"files":{"input":[0]},"returns":{"eq":(1u32 + 7)*33u32.pow(4)+81*33u32.pow(3)+1}})).expect("descriptor search options");
                let report = symbolic::solve(&binary, "read_descriptor", &options)
                    .expect("descriptor search");
                assert!(report.found, "{architecture}: {report:?}");
                let inputs = report.inputs.expect("descriptor inputs");
                let replay =
                    serde_json::from_value(json!({"files":inputs.files})).expect("replay options");
                let report = emulation::run(&binary, "read_descriptor", &replay, None)
                    .expect("descriptor replay");
                assert_eq!(report.reason, "return", "{report:?}");
            }
        }
    }
}

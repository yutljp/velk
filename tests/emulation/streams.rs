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

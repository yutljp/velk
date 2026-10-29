//! Deterministic libc state across execution and search interfaces.

use std::process::Command;

use serde_json::{Value, json};
use velk::service::Binary;
use velk::symbolic;

use super::matrix::{self, Interfaces};

#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "rand reference requires glibc")]
fn random_sequence_matches_native() {
    let mut interfaces = Interfaces::new();
    for architecture in matrix::ARCHITECTURES {
        for optimization in ["O0", "O2"] {
            let path =
                matrix::fixtures().join(format!("{architecture}.{optimization}.runtime.elf"));
            let binary = Binary::open(&path).expect("runtime fixture");
            for seed in [0u32, 1, 42, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
                for count in [1, 2, 31, 64, 127] {
                    let native = Command::new(matrix::fixtures().join("host.runtime.native"))
                        .args([seed.to_string(), count.to_string()])
                        .output()
                        .expect("native random reference");
                    assert!(native.status.success(), "{native:?}");
                    let expected: u32 = String::from_utf8(native.stdout)
                        .expect("reference text")
                        .parse()
                        .expect("reference integer");
                    let report = interfaces.check(
                        &path,
                        &binary,
                        "random_values",
                        json!({"arguments":[seed, count]}),
                    );
                    assert_eq!(
                        matrix::value(&report),
                        expected,
                        "{architecture} {seed} {count}"
                    );
                }
            }
            let report = interfaces.check(&path, &binary, "random_default", json!({}));
            assert_eq!(matrix::value(&report), 1804289383);
        }
    }
}

#[test]
fn clock_and_process_state() {
    let mut interfaces = Interfaces::new();
    for architecture in matrix::ARCHITECTURES {
        for optimization in ["O0", "O2"] {
            let path =
                matrix::fixtures().join(format!("{architecture}.{optimization}.runtime.elf"));
            let binary = Binary::open(&path).expect("runtime fixture");
            for value in [0, 42, u32::MAX as u64, 0x1234_5678_9abc_def0] {
                let report = interfaces.check(
                    &path,
                    &binary,
                    "clock_value",
                    json!({"time":format!("0x{value:x}")}),
                );
                assert_eq!(matrix::value(&report), value as u32);
            }
            for (name, expected) in [("signal_values", 7), ("alarm_values", 7)] {
                let report = interfaces.check(&path, &binary, name, json!({}));
                assert_eq!(matrix::value(&report), expected);
            }
            for number in [0, 9, 19, 32, 33, 65, u32::MAX] {
                let report = interfaces.check(
                    &path,
                    &binary,
                    "signal_number",
                    json!({"arguments":[number]}),
                );
                assert_eq!(report["reason"], "error");
            }
            let report = interfaces.check(&path, &binary, "signal_error_handler", json!({}));
            assert_eq!(report["reason"], "error");
            let report =
                interfaces.check(&path, &binary, "clock_pointer", json!({"arguments":[1]}));
            assert_eq!(report["reason"], "error");
        }
    }
}

#[test]
fn anti_analysis_defaults_and_overrides() {
    let mut interfaces = Interfaces::new();
    for architecture in matrix::ARCHITECTURES {
        for optimization in ["O0", "O2"] {
            let path =
                matrix::fixtures().join(format!("{architecture}.{optimization}.runtime.elf"));
            let binary = Binary::open(&path).expect("runtime fixture");
            let once = interfaces.check(&path, &binary, "ptrace_once", json!({}));
            assert_eq!(matrix::value(&once), 1);
            let twice = interfaces.check(&path, &binary, "ptrace_twice", json!({}));
            assert_eq!(matrix::value(&twice), 3);
            assert!(
                twice["antiAnalysis"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("ptrace(PTRACE_TRACEME)"))
            );
            if matches!(architecture, "x86_64" | "i386" | "aarch64") {
                let raw = interfaces.check(&path, &binary, "raw_ptrace_twice", json!({}));
                assert_eq!(matrix::value(&raw), 3);
            }
            let parent = interfaces.check(&path, &binary, "parent_process", json!({}));
            assert_eq!(matrix::value(&parent), 1);
            let traced = interfaces.check(
                &path,
                &binary,
                "ptrace_once",
                json!({"antiAnalysis":{"ptraceTracemeSucceeds":false}}),
            );
            assert_eq!(matrix::value(&traced), 0);
            let preload = interfaces.check(
                &path,
                &binary,
                "preload_unset",
                json!({"antiAnalysis":{"preload":"/lib/example.so"}}),
            );
            assert_eq!(matrix::value(&preload), 0);
            let debugger = interfaces.check(&path, &binary, "debugger_apis_clear", json!({}));
            assert_eq!(matrix::value(&debugger), 1);
            let debugger = interfaces.check(
                &path,
                &binary,
                "debugger_apis_clear",
                json!({"antiAnalysis":{"debuggerPresent":true}}),
            );
            assert_eq!(matrix::value(&debugger), 0);
            let status = interfaces.check(&path, &binary, "status_tracer_clear", json!({}));
            assert_eq!(matrix::value(&status), 1);
            let status = interfaces.check(
                &path,
                &binary,
                "status_tracer_clear",
                json!({"antiAnalysis":{"debuggerPresent":true}}),
            );
            assert_eq!(matrix::value(&status), 0);
            let clock = interfaces.check(&path, &binary, "clock_advances", json!({}));
            assert_eq!(matrix::value(&clock), 1);
            assert!(
                clock["antiAnalysis"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("clock_gettime"))
            );
        }
    }
    let path = matrix::fixtures().join("x86_64.O2.runtime.elf");
    let binary = Binary::open(&path).expect("runtime fixture");
    let trap = interfaces.check(&path, &binary, "sigtrap_handler", json!({}));
    assert_eq!(matrix::value(&trap), 1);
}

#[test]
fn symbolic_runtime_state() {
    if !Command::new("z3")
        .arg("-version")
        .output()
        .is_ok_and(|output| output.status.success())
    {
        return;
    }
    for architecture in ["i386", "x86_64", "aarch64"] {
        for optimization in ["O0", "O2"] {
            let path =
                matrix::fixtures().join(format!("{architecture}.{optimization}.runtime.elf"));
            let binary = Binary::open(&path).expect("runtime fixture");
            for (name, options) in [
                (
                    "random_values",
                    json!({"argumentValues":[1,1],"returns":{"eq":1804289383}}),
                ),
                ("random_repeat", json!({"arguments":[0],"returns":{"eq":1}})),
                ("random_branch", json!({"arguments":[0],"returns":{"eq":1}})),
                ("clock_value", json!({"time":42,"returns":{"eq":42}})),
                ("signal_values", json!({"returns":{"eq":7}})),
                ("alarm_values", json!({"returns":{"eq":7}})),
                ("ptrace_twice", json!({"returns":{"eq":3}})),
                ("parent_process", json!({"returns":{"eq":1}})),
                (
                    "ptrace_once",
                    json!({"antiAnalysis":{"ptraceTracemeSucceeds":false},"returns":{"eq":0}}),
                ),
            ] {
                let parsed: symbolic::Options =
                    serde_json::from_value(options.clone()).expect("search options");
                let report = symbolic::solve(&binary, name, &parsed).expect("runtime solve");
                assert!(report.found, "{architecture} {name}: {report:?}");
                if !matches!(name, "random_repeat" | "random_branch") {
                    check_search_interfaces(
                        &path,
                        name,
                        &options,
                        &serde_json::to_value(&report).expect("search JSON"),
                    );
                }
                let inputs = report.inputs.expect("satisfying inputs");
                let arguments = if parsed.arguments.is_empty() {
                    parsed.argument_values.clone()
                } else {
                    vec![velk::emulation::Word::Text(inputs.arguments[&0].clone())]
                };
                let replay = velk::emulation::Options {
                    arguments,
                    time: parsed.time,
                    anti_analysis: parsed.anti_analysis.clone(),
                    ..Default::default()
                };
                let actual =
                    velk::emulation::run(&binary, name, &replay, None).expect("runtime replay");
                let actual: Value = serde_json::to_value(actual).expect("replay JSON");
                let expected = options["returns"]["eq"].as_u64().expect("expected return") as u32;
                assert_eq!(matrix::value(&actual), expected, "{name} {inputs:?}");
            }
        }
    }
}

fn check_search_interfaces(path: &std::path::Path, name: &str, options: &Value, expected: &Value) {
    use std::process::Stdio;

    let cli = Command::new(env!("CARGO_BIN_EXE_velk"))
        .args([
            "--solve",
            name,
            "--returns",
            &format!("eq:{}", options["returns"]["eq"]),
            "--json",
            "--symbolic-options",
            &options.to_string(),
        ])
        .arg(path)
        .output()
        .expect("runtime CLI solve");
    assert!(cli.status.success(), "{cli:?}");
    assert_eq!(
        serde_json::from_slice::<Value>(&cli.stdout).expect("CLI JSON"),
        *expected
    );
    let engine = velk::script::Engine::new().expect("script engine");
    let script = format!(
        "velk.open({}).solve({},{options})",
        json!(path),
        json!(name)
    );
    let result = engine.run(&script, None);
    assert!(result.error.is_none(), "{:?}", result.error);
    assert_eq!(
        serde_json::from_str::<Value>(&result.output).expect("script JSON"),
        *expected
    );
    let child = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("MCP server");
    let output = crate::common::mcp_request(
        child,
        &json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"velk_solve","arguments":{"path":path,"start":name,"options":options}}}),
    );
    let response: Value = serde_json::from_slice(&output.stdout).expect("MCP JSON");
    assert_eq!(response["result"]["isError"], false, "{response}");
    let actual: Value = serde_json::from_str(
        response["result"]["content"][0]["text"]
            .as_str()
            .expect("MCP text"),
    )
    .expect("MCP report");
    assert_eq!(actual, *expected);
}

#[test]
fn unavailable_process_and_network_state_has_a_clear_diagnostic() {
    let mut interfaces = Interfaces::new();
    for architecture in matrix::ARCHITECTURES {
        for optimization in ["O0", "O2"] {
            let path =
                matrix::fixtures().join(format!("{architecture}.{optimization}.runtime.elf"));
            let binary = Binary::open(&path).expect("runtime fixture");
            for (name, message) in [
                ("network_socket", "network connections are not modeled"),
                ("process_control", "unsupported prctl operation 38"),
            ] {
                let report = interfaces.check(&path, &binary, name, json!({}));
                assert_eq!(report["reason"], "error", "{report}");
                assert!(
                    report["error"]
                        .as_str()
                        .expect("diagnostic")
                        .contains(message),
                    "{report}"
                );
                let skipped = interfaces.check(&path, &binary, name, json!({"skipCalls":true}));
                assert_eq!(skipped["reason"], "return", "{skipped}");
                assert_eq!(matrix::value(&skipped), 0);
                let imported = if name == "network_socket" {
                    "socket"
                } else {
                    "prctl"
                };
                let overridden =
                    interfaces.check(&path, &binary, name, json!({"callReturns":{(imported):7}}));
                assert_eq!(matrix::value(&overridden), 7, "{overridden}");
                if matches!(architecture, "i386" | "x86_64" | "aarch64") {
                    let options = serde_json::from_value(json!({"returns":{"eq":0}}))
                        .expect("search options");
                    let report =
                        symbolic::solve(&binary, name, &options).expect("unsupported state search");
                    assert!(format!("{report:?}").contains(message), "{report:?}");
                }
            }
        }
    }
}

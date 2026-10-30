//! Regression coverage for constant-table loads and optimized byte sums.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use serde_json::{Value, json};
use velk::ir::{BinOp, Cond, Expr};
use velk::service::Binary;
use velk::symbolic::{self, Options, State, Term};

fn fixtures() -> &'static Path {
    static DIRECTORY: OnceLock<PathBuf> = OnceLock::new();
    DIRECTORY.get_or_init(|| {
        let directory = common::root()
            .join("target/crackme-fixtures")
            .join(std::process::id().to_string());
        let output = Command::new("bash")
            .arg(common::root().join("tests/scripts/make_crackme_fixtures.sh"))
            .arg(&directory)
            .output()
            .expect("run crackme fixture builder");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        directory
    })
}

fn solver_available() -> bool {
    Command::new("z3")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

#[test]
fn tables_and_vector_sums_reach_success_and_return_one() {
    if !solver_available() {
        return;
    }
    for arch in ["x86_64", "aarch64"] {
        for opt in [0, 2] {
            for name in ["table", "sum"] {
                let binary = Binary::open(&fixtures().join(format!("{arch}-O{opt}-{name}.elf")))
                    .expect("open crackme");
                let explore_options: Options = serde_json::from_value(json!({
                    "stdin":4,
                    "find":[binary.find("success").expect("success target").addr],
                    "avoid":[binary.find("failure").expect("failure target").addr]
                }))
                .expect("explore options");
                let solve_options: Options = serde_json::from_value(json!({
                    "argumentValues":["0x10000000"],
                    "memory":[{"address":"0x10000000","size":4}],
                    "returns":{"eq":1}
                }))
                .expect("solve options");
                let reports = [
                    symbolic::explore(&binary, "main", &explore_options).expect("explore crackme"),
                    symbolic::solve(&binary, "check", &solve_options).expect("solve crackme"),
                ];
                for (mode, report) in reports.into_iter().enumerate() {
                    assert!(report.found, "{arch} O{opt} {name}: {report:?}");
                    let inputs = report.inputs.expect("satisfying inputs");
                    let bytes = if mode == 0 {
                        inputs.stdin
                    } else {
                        inputs.memory.values().copied().collect()
                    };
                    assert_eq!(bytes.len(), 4);
                    if name == "sum" {
                        assert_eq!(bytes.iter().map(|byte| u32::from(*byte)).sum::<u32>(), 282);
                    } else {
                        let table = [9, 2, 14, 7, 1, 12, 3, 11, 5, 0, 15, 6, 10, 8, 4, 13];
                        let actual: Vec<u8> = bytes
                            .iter()
                            .map(|byte| table[usize::from(byte & 15)])
                            .collect();
                        assert_eq!(actual, [3, 10, 2, 11]);
                    }
                }
            }
        }
    }
}

#[test]
fn table_loads_preserve_width_sign_and_memory_bounds() {
    if !solver_available() {
        return;
    }
    let values = [
        0u64,
        1,
        127,
        128,
        255,
        256,
        32767,
        32768,
        65535,
        65536,
        0x7fffffff,
        0x80000000,
        0xffffffff,
        0x8000000000000000,
        0xffffffffffffff80,
        u64::MAX,
    ];
    for arch in ["x86_64", "aarch64"] {
        let binary = Binary::open(&fixtures().join(format!("{arch}-O0-table.elf")))
            .expect("open table fixture");
        let base = binary.find_address("table_words").expect("constant table");
        let options = Options {
            arguments: vec![0],
            ..Options::default()
        };
        let mut state = State::new(&binary, "check", &options).expect("table state");
        let register = if arch == "x86_64" { 7 } else { 0 };
        let index = state.read_register(register).expect("symbolic index");
        state
            .constrain(Cond::Ls, &index, &Term::constant(15), 64)
            .expect("bounded index");
        for width in 1..=8 {
            for signed in [false, true] {
                let expression = Expr::Load {
                    addr: Box::new(Expr::bin(
                        BinOp::Add,
                        Expr::Const(base),
                        Expr::bin(BinOp::Mul, Expr::reg(register, 64), Expr::Const(8)),
                    )),
                    width,
                    signed,
                };
                let loaded = state
                    .expression(&binary, &expression)
                    .expect("table load without forks");
                for (position, value) in values.iter().enumerate() {
                    let mut selected = state.clone();
                    selected
                        .constrain(Cond::Eq, &index, &Term::constant(position as u64), 64)
                        .expect("select table entry");
                    let shift = 64 - u32::from(width) * 8;
                    let expected = if signed {
                        ((*value << shift) as i64 >> shift) as u64
                    } else {
                        *value << shift >> shift
                    };
                    selected
                        .constrain(Cond::Ne, &loaded, &Term::constant(expected), 64)
                        .expect("compare loaded value");
                    assert!(
                        !selected.satisfiable().expect("table equality"),
                        "{arch} width {width} signed {signed} index {position}"
                    );
                }
            }
        }
        let section = binary.image().section_at(base).expect("table section");
        for (base, stride, width) in [
            (0x10000000, 1, 1),                       // Writable memory keeps address forks.
            (base, 256, 1), // A large address span keeps the enumeration bound.
            (section.vaddr + section.size - 1, 1, 8), // A load must fit the section.
        ] {
            let expression = Expr::Load {
                addr: Box::new(Expr::bin(
                    BinOp::Add,
                    Expr::Const(base),
                    Expr::bin(BinOp::Mul, Expr::reg(register, 64), Expr::Const(stride)),
                )),
                width,
                signed: false,
            };
            let error = state
                .expression(&binary, &expression)
                .err()
                .expect("requires address forks");
            assert!(error.to_string().contains("requires a fork"), "{error}");
        }
    }
}

#[test]
fn cli_javascript_and_mcp_agree_on_table_and_vector_searches() {
    if !solver_available() {
        return;
    }
    let engine = velk::script::Engine::new().expect("script engine");
    for fixture in [
        "x86_64-O0-table-protected.elf",
        "aarch64-O2-sum-protected-tpidr.elf",
    ] {
        let path = fixtures().join(fixture);
        let binary = Binary::open(&path).expect("open interface fixture");
        for action in ["emulate", "explore", "solve"] {
            let start = if action == "solve" { "check" } else { "main" };
            let mut options = if action == "emulate" {
                if fixture.starts_with("x86_64") {
                    json!({"stdin":{"hex":"060c0107"}})
                } else {
                    json!({"stdin":{"hex":"46464648"}})
                }
            } else if action == "explore" {
                json!({"stdin":4,
                    "find":[binary.find("success").expect("success target").addr],
                    "avoid":[binary.find("failure").expect("failure target").addr]})
            } else {
                json!({"argumentValues":["0x10000000"],"returns":{"eq":1},
                    "memory":[{"address":"0x10000000","size":4}]})
            };
            options["tlsBase"] = json!("0x31000000");
            options["canary"] = json!("0xfedcba9876543200");
            let mut command = Command::new(env!("CARGO_BIN_EXE_velk"));
            let option_flag = if action == "emulate" {
                "--emulation-options"
            } else {
                "--symbolic-options"
            };
            command.arg(format!("--{action}"));
            if action != "emulate" {
                command.arg(start);
            }
            command.args(["--json", option_flag, &options.to_string()]);
            if action == "explore" {
                command.args([
                    "--find",
                    &format!(
                        "0x{:x}",
                        binary.find("success").expect("success target").addr
                    ),
                ]);
            } else if action == "solve" {
                command.args(["--returns", "eq:1"]);
            }
            command.arg(&path);
            if action == "emulate" {
                command.arg(start);
            }
            let output = command.output().expect("CLI execution");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let cli: Value = serde_json::from_slice(&output.stdout).expect("CLI report");
            if action == "emulate" {
                assert_eq!(cli["reason"], "return", "{cli}");
                assert_eq!(cli["stdout"], "success\n");
            } else {
                assert_eq!(cli["found"], true);
                let bytes: Vec<u8> = if action == "explore" {
                    serde_json::from_value(cli["inputs"]["stdin"].clone()).expect("solved stdin")
                } else {
                    let memory: std::collections::BTreeMap<String, u8> =
                        serde_json::from_value(cli["inputs"]["memory"].clone())
                            .expect("solved memory");
                    memory.values().copied().collect()
                };
                let (opt, name) = if fixture.starts_with("x86_64") {
                    (0, "table")
                } else {
                    (2, "sum")
                };
                replay_protected(opt, name, &bytes);
            }
            let outcome = engine.run(
                &format!(
                    "velk.open({}).{action}({},{options})",
                    json!(path),
                    json!(start)
                ),
                None,
            );
            assert!(outcome.error.is_none(), "{:?}", outcome.error);
            assert_eq!(
                serde_json::from_str::<Value>(&outcome.output).expect("JS report"),
                cli
            );
            let child = Command::new(env!("CARGO_BIN_EXE_velk"))
                .arg("--mcp")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .expect("MCP process");
            let output = common::mcp_request(
                child,
                &json!({
                    "jsonrpc":"2.0","id":1,"method":"tools/call",
                    "params":{"name":format!("velk_{action}"),
                        "arguments":{"path":path,"start":start,"options":options}}
                }),
            );
            let response: Value = serde_json::from_slice(&output.stdout).expect("MCP response");
            assert_eq!(response["result"]["isError"], false, "{response}");
            let report = response["result"]["content"][0]["text"]
                .as_str()
                .expect("MCP report text");
            assert_eq!(
                serde_json::from_str::<Value>(report).expect("MCP report"),
                cli
            );
        }
    }
}

fn replay_protected(opt: u8, name: &str, bytes: &[u8]) {
    use std::io::Write;
    let mut child = Command::new(fixtures().join(format!("native-O{opt}-{name}-protected")))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("native protected executable");
    child
        .stdin
        .take()
        .expect("native stdin")
        .write_all(bytes)
        .expect("write solved input");
    let output = child.wait_with_output().expect("native replay");
    assert!(output.status.success(), "{opt} {name}: {output:?}");
    assert_eq!(output.stdout, b"success\n");
}

#[test]
fn protected_crackmes_emulate_explore_and_replay() {
    let has_solver = solver_available();
    for arch in ["x86_64", "aarch64", "i386"] {
        let guards: &[&str] = if arch == "aarch64" {
            &["protected", "protected-tpidr"]
        } else {
            &["protected"]
        };
        for opt in [0, 2] {
            let names: &[&str] = if arch == "i386" {
                &["sum"]
            } else {
                &["sum", "table"]
            };
            for &name in names {
                for guard in guards {
                    let path = fixtures().join(format!("{arch}-O{opt}-{name}-{guard}.elf"));
                    let binary = Binary::open(&path).expect("protected crackme");
                    let success = binary.find("success").expect("success target").addr;
                    let failure = binary.find("failure").expect("failure target").addr;
                    for overrides in [
                        json!({}),
                        json!({"tlsBase":"0x31000000", "canary":"0xfedcba9876543200"}),
                        json!({"tlsBase":"0x31000000", "canary":0}),
                        json!({"tlsBase":"0x31000000", "canary":"0xffffffffffffffff"}),
                    ] {
                        let input = if arch == "i386" || !has_solver {
                            if name == "sum" {
                                vec![70, 70, 70, 72]
                            } else {
                                vec![6, 12, 1, 7]
                            }
                        } else {
                            let mut options = overrides.clone();
                            options["stdin"] = json!(4);
                            // Reaching the outer return exercises the epilogue's guard check.
                            options["returns"] = json!({"eq":0});
                            options["avoid"] = json!([failure]);
                            let report = symbolic::explore(
                                &binary,
                                "main",
                                &serde_json::from_value(options).expect("protected search options"),
                            )
                            .expect("protected exploration");
                            assert!(report.found, "{path:?}: {report:?}");
                            report.inputs.expect("solved input").stdin
                        };
                        replay_protected(opt, name, &input);
                        let mut options = overrides.clone();
                        options["stdin"] = json!({"hex": input.iter().map(|b| format!("{b:02x}")).collect::<String>()});
                        options["trace"] = json!(true);
                        let base = u64::from_str_radix(
                            overrides["tlsBase"]
                                .as_str()
                                .unwrap_or("0x20000000")
                                .trim_start_matches("0x"),
                            16,
                        )
                        .expect("TLS base");
                        let offset = if arch == "i386" { 0x14 } else { 0x28 };
                        let width = if arch == "i386" { 4 } else { 8 };
                        options["reads"] = json!([{"address":format!("0x{:x}", base + offset),"length":width,"format":"bytes"}]);
                        let guard = match &overrides["canary"] {
                            Value::String(text) => {
                                u64::from_str_radix(text.trim_start_matches("0x"), 16)
                                    .expect("guard")
                            }
                            Value::Number(number) => number.as_u64().expect("guard"),
                            _ => 0x6a09e667bb67ae00,
                        };
                        let report = velk::emulation::run(
                            &binary,
                            "main",
                            &serde_json::from_value(options).expect("protected emulation options"),
                            None,
                        )
                        .expect("protected emulation");
                        assert_eq!(report.reason, "return", "{path:?}: {report:?}");
                        assert_eq!(report.return_value, "0x0", "{path:?}: {report:?}");
                        assert_eq!(report.stdout, "success\n");
                        assert_eq!(report.reads[0].bytes, guard.to_le_bytes()[..width]);
                        assert!(report.trace.contains(&format!("0x{success:x}")));
                        let register = match arch {
                            "x86_64" => "fs_base",
                            "i386" => "gs_base",
                            _ => "tpidr_el0",
                        };
                        let base = overrides["tlsBase"].as_str().unwrap_or("0x20000000");
                        assert_eq!(report.registers[register], base);
                    }
                    let report = velk::emulation::run(
                        &binary,
                        "corrupt_guard",
                        &velk::emulation::Options::default(),
                        None,
                    )
                    .expect("corrupted guard execution");
                    assert_eq!(report.reason, "stack check failed", "{path:?}: {report:?}");
                    if arch != "i386" && has_solver {
                        let options = serde_json::from_value(json!({"returns":{"eq":7}}))
                            .expect("corrupted guard search options");
                        let report = symbolic::explore(&binary, "corrupt_guard", &options)
                            .expect("corrupted guard search");
                        assert!(!report.found, "{path:?}: {report:?}");
                        assert!(
                            report
                                .diagnostics
                                .iter()
                                .any(|d| d.contains("stack check failed")),
                            "{path:?}: {report:?}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn symbolic_thread_local_and_global_guards_use_the_requested_value() {
    if !solver_available() {
        return;
    }
    for arch in ["x86_64", "aarch64"] {
        let binary = Binary::open(&fixtures().join(format!("{arch}-O0-sum-protected.elf")))
            .expect("guard fixture");
        let global = binary
            .find_address("__stack_chk_guard")
            .expect("global guard");
        for canary in [0, 1, 0x6a09e667bb67ae00, u64::MAX] {
            let options = serde_json::from_value(json!({
                "tlsBase":"0x31000000", "canary":format!("0x{canary:x}")
            }))
            .expect("guard options");
            let state = State::new(&binary, "main", &options).expect("initial guard state");
            let register = if arch == "x86_64" { 16 } else { 96 };
            assert_eq!(
                state
                    .evaluate(&state.read_register(register).expect("thread pointer"), 1)
                    .expect("thread pointer value"),
                [0x31000000]
            );
            for address in [0x31000028, global] {
                let bytes = state.read_memory(&binary, address, 8).expect("guard bytes");
                for (byte, expected) in bytes.iter().zip(canary.to_le_bytes()) {
                    assert_eq!(
                        state.evaluate(byte, 1).expect("guard byte"),
                        [u64::from(expected)]
                    );
                }
            }
        }
    }
}

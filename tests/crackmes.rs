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
            .arg(common::root().join("tests/make_crackme_fixtures.sh"))
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
    for fixture in ["x86_64-O0-table.elf", "aarch64-O2-sum.elf"] {
        let path = fixtures().join(fixture);
        let binary = Binary::open(&path).expect("open interface fixture");
        for action in ["explore", "solve"] {
            let start = if action == "explore" { "main" } else { "check" };
            let options = if action == "explore" {
                json!({"stdin":4,
                    "find":[binary.find("success").expect("success target").addr],
                    "avoid":[binary.find("failure").expect("failure target").addr]})
            } else {
                json!({"argumentValues":["0x10000000"],"returns":{"eq":1},
                    "memory":[{"address":"0x10000000","size":4}]})
            };
            let mut command = Command::new(env!("CARGO_BIN_EXE_velk"));
            command.args([
                &format!("--{action}"),
                start,
                "--json",
                "--symbolic-options",
                &options.to_string(),
            ]);
            if action == "explore" {
                command.args([
                    "--find",
                    &format!(
                        "0x{:x}",
                        binary.find("success").expect("success target").addr
                    ),
                ]);
            } else {
                command.args(["--returns", "eq:1"]);
            }
            let output = command.arg(&path).output().expect("CLI search");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let cli: Value = serde_json::from_slice(&output.stdout).expect("CLI report");
            assert_eq!(cli["found"], true);
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

//! Symbolic inputs checked by executing the resulting concrete IR paths.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Instant;

use serde_json::json;
use velk::emulation::{self, Word};
use velk::ir::Cond;
use velk::service::Binary;
use velk::symbolic::{self, Options, State, Step, Term};

fn solver_available() -> bool {
    let available = ["z3", "bitwuzla"].iter().any(|program| {
        Command::new(program)
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    });
    if !available {
        eprintln!("SKIP symbolic execution: no SMT solver on PATH");
    }
    available
}

fn fixtures() -> &'static Path {
    static DIRECTORY: OnceLock<PathBuf> = OnceLock::new();
    DIRECTORY.get_or_init(|| {
        let out = common::root().join("target/symbolic-fixtures");
        let result = Command::new("bash")
            .arg(common::root().join("tools/make_symbolic_fixtures.sh"))
            .arg(&out)
            .output()
            .expect("symbolic fixture operation succeeds");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        out
    })
}

fn binary(arch: &str, opt: u8) -> Binary {
    Binary::open(&fixtures().join(format!("{arch}-O{opt}.elf")))
        .expect("symbolic fixture operation succeeds")
}

fn options(binary: &Binary, name: &str) -> Options {
    let mut options: Options = serde_json::from_value(json!({
        "find": [format!("0x{:x}", binary.find("success").expect("symbolic fixture operation succeeds").addr)],
        "avoid": [format!("0x{:x}", binary.find("failure").expect("symbolic fixture operation succeeds").addr)],
        "memory": [{"address": "0x10000000", "size": 4}],
        "argumentValues": ["0x10000000"], "pathLimit": 512
    }))
    .expect("symbolic fixture operation succeeds");
    if name == "arguments" {
        options.argv = vec![1, 3];
        options.argument_values.clear();
        options.memory.clear();
    }
    if matches!(name, "getchar_password" | "read_checksum") {
        options.stdin = 4;
        options.argument_values.clear();
        options.memory.clear();
    }
    options
}

#[test]
fn crackme_paths_match_concrete_execution() {
    if !solver_available() {
        return;
    }
    for arch in ["x86_64", "aarch64"] {
        for opt in [0, 2] {
            let binary = binary(arch, opt);
            for name in [
                "password",
                "checksum",
                "arguments",
                "counted",
                "avoided",
                "indirect",
                "getchar_password",
                "read_checksum",
                "nested",
            ] {
                let options = options(&binary, name);
                let start = Instant::now();
                let report = symbolic::explore(&binary, name, &options)
                    .expect("symbolic fixture operation succeeds");
                eprintln!(
                    "{arch} O{opt} {name}: {:?}, {} states",
                    start.elapsed(),
                    report.paths
                );
                assert!(
                    report.found,
                    "{arch} O{opt} {name}: {} {:?}",
                    report.reason, report.diagnostics
                );
                let inputs = report.inputs.expect("symbolic fixture operation succeeds");
                let mut setup = json!({
                    "arguments": options.argument_values.iter().map(|value| match value {Word::Text(text) => text.clone(), Word::Integer(value) => value.to_string()}).collect::<Vec<_>>(),
                    "end": options.find.iter().map(|value| match value {Word::Text(text) => text.clone(), Word::Integer(value) => value.to_string()}).collect::<Vec<_>>(),
                    "stdin": {"hex": inputs.stdin.iter().map(|byte| format!("{byte:02x}")).collect::<String>()},
                    "memory": inputs.memory.iter().map(|(address, byte)| json!({"address": address, "bytes": [byte]})).collect::<Vec<_>>()
                });
                if name == "arguments" {
                    setup
                        .as_object_mut()
                        .expect("symbolic fixture operation succeeds")
                        .remove("arguments");
                    setup["argv"] = json!(
                        inputs
                            .argv
                            .into_iter()
                            .map(|bytes| String::from_utf8(bytes)
                                .expect("symbolic fixture operation succeeds"))
                            .collect::<Vec<_>>()
                    );
                }
                let setup =
                    serde_json::from_value(setup).expect("symbolic fixture operation succeeds");
                let concrete = emulation::run(&binary, name, &setup, None)
                    .expect("symbolic fixture operation succeeds");
                assert_eq!(
                    concrete.reason, "end address",
                    "{arch} O{opt} {name}: {:?}",
                    concrete.error
                );
            }
        }
    }
}

#[test]
fn state_constraints_forks_values_and_memory() {
    if !solver_available() {
        return;
    }
    let binary = binary("x86_64", 0);
    let mut state = State::new(&binary, "password", &Options::default())
        .expect("symbolic fixture operation succeeds");
    let x = state
        .symbolic()
        .expect("symbolic fixture operation succeeds");
    state
        .constrain(Cond::Cs, &x, &Term::constant(10), 64)
        .expect("symbolic fixture operation succeeds");
    state
        .constrain(Cond::Ls, &x, &Term::constant(12), 64)
        .expect("symbolic fixture operation succeeds");
    assert_eq!(
        state
            .evaluate(&x, 4)
            .expect("symbolic fixture operation succeeds"),
        [10, 11, 12]
    );
    assert_eq!(
        state
            .bounds(&x)
            .expect("symbolic fixture operation succeeds"),
        Some((10, 12))
    );
    let mut fork = state.clone();
    fork.constrain(Cond::Eq, &x, &Term::constant(11), 64)
        .expect("symbolic fixture operation succeeds");
    assert_eq!(
        fork.evaluate(&x, 4)
            .expect("symbolic fixture operation succeeds"),
        [11]
    );
    assert_eq!(
        state
            .evaluate(&x, 4)
            .expect("symbolic fixture operation succeeds"),
        [10, 11, 12]
    );
    fork.write_register(7, x.clone())
        .expect("symbolic fixture operation succeeds");
    assert_eq!(
        fork.evaluate(
            &fork
                .read_register(7)
                .expect("symbolic fixture operation succeeds"),
            1
        )
        .expect("symbolic fixture operation succeeds"),
        [11]
    );
    fork.write_memory(&binary, 0x10000000, std::slice::from_ref(&x))
        .expect("symbolic fixture operation succeeds");
    assert_eq!(
        fork.evaluate(
            &fork
                .read_memory(&binary, 0x10000000, 1)
                .expect("symbolic fixture operation succeeds")[0],
            1
        )
        .expect("symbolic fixture operation succeeds"),
        [11]
    );
    fork.constrain(Cond::Eq, &x, &Term::constant(99), 64)
        .expect("symbolic fixture operation succeeds");
    assert!(
        !fork
            .satisfiable()
            .expect("symbolic fixture operation succeeds")
    );
    assert!(
        fork.evaluate(&x, 1)
            .expect("symbolic fixture operation succeeds")
            .is_empty()
    );
    assert!(state.read_memory(&binary, u64::MAX, 2).is_err());
    assert!(
        state
            .write_memory(
                &binary,
                binary
                    .find("password")
                    .expect("symbolic fixture operation succeeds")
                    .addr,
                &[Term::constant(0)]
            )
            .is_err()
    );
    let other = State::new(&binary, "password", &Options::default())
        .expect("symbolic fixture operation succeeds");
    assert!(other.evaluate(&x, 1).is_err());
}

#[test]
fn deterministic_search_and_budgets() {
    if !solver_available() {
        return;
    }
    let binary = binary("aarch64", 2);
    let options = options(&binary, "password");
    let first = symbolic::explore(&binary, "password", &options)
        .expect("symbolic fixture operation succeeds");
    assert_eq!(
        first,
        symbolic::explore(&binary, "password", &options)
            .expect("symbolic fixture operation succeeds")
    );
    let short = Options {
        step_limit: 1,
        ..options.clone()
    };
    assert_eq!(
        symbolic::explore(&binary, "password", &short)
            .expect("symbolic fixture operation succeeds")
            .reason,
        "step budget"
    );
    let short = Options {
        path_limit: 1,
        ..options.clone()
    };
    assert_eq!(
        symbolic::explore(&binary, "password", &short)
            .expect("symbolic fixture operation succeeds")
            .reason,
        "path budget"
    );
    let avoided = Options {
        avoid: options.find.clone(),
        ..options.clone()
    };
    assert!(
        !symbolic::explore(&binary, "password", &avoided)
            .expect("symbolic fixture operation succeeds")
            .found
    );
    let mut state =
        State::new(&binary, "password", &options).expect("symbolic fixture operation succeeds");
    assert!(matches!(
        state
            .step(&binary, &[state.address()])
            .expect("symbolic fixture operation succeeds"),
        Step::Reached
    ));
    let mut options = options;
    options.arguments = vec![0];
    options.argument_values.clear();
    options.memory.clear();
    assert!(
        symbolic::explore(&binary, "recurse", &options)
            .expect("symbolic fixture operation succeeds")
            .found
    );
}

#[test]
fn cli_javascript_mcp_and_documentation() {
    if !solver_available() {
        return;
    }
    use serde_json::Value;
    use std::process::Stdio;
    let path = fixtures().join("x86_64-O0.elf");
    let binary = Binary::open(&path).expect("symbolic fixture operation succeeds");
    let find = format!(
        "0x{:x}",
        binary
            .find("success")
            .expect("symbolic fixture operation succeeds")
            .addr
    );
    let avoid = format!(
        "0x{:x}",
        binary
            .find("failure")
            .expect("symbolic fixture operation succeeds")
            .addr
    );
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .args([
            "--explore",
            "getchar_password",
            "--find",
            &find,
            "--avoid",
            &avoid,
            "--stdin",
            "4",
            "--json",
        ])
        .arg(&path)
        .output()
        .expect("symbolic fixture operation succeeds");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cli: Value =
        serde_json::from_slice(&output.stdout).expect("symbolic fixture operation succeeds");
    assert_eq!(cli["inputs"]["stdin"], json!([118, 101, 108, 107]));
    for extra in [
        vec!["--limit", "1"],
        vec!["ignored-function"],
        vec!["--emulate"],
    ] {
        let invalid = Command::new(env!("CARGO_BIN_EXE_velk"))
            .args(["--explore", "getchar_password", "--find", &find])
            .arg(&path)
            .args(extra)
            .output()
            .expect("invalid CLI invocation completes");
        assert_eq!(invalid.status.code(), Some(2), "{invalid:?}");
    }
    let options = json!({"find": [find], "avoid": [avoid], "stdin": 4});
    let engine = velk::script::Engine::new().expect("symbolic fixture operation succeeds");
    let outcome = engine.run(
        &format!(
            "velk.open({}).explore('getchar_password', {options})",
            json!(path)
        ),
        None,
    );
    assert!(outcome.error.is_none(), "{:?}", outcome.error);
    assert_eq!(
        serde_json::from_str::<Value>(&outcome.output)
            .expect("symbolic fixture operation succeeds"),
        cli
    );
    let child = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("symbolic fixture operation succeeds");
    let request = json!({"jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{"name":"velk_explore", "arguments":{"path":path, "start":"getchar_password", "options":options}}});
    let output = common::mcp_request(child, &request);
    let response: Value =
        serde_json::from_slice(&output.stdout).expect("symbolic fixture operation succeeds");
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert_eq!(
        serde_json::from_str::<Value>(
            response["result"]["content"][0]["text"]
                .as_str()
                .expect("symbolic fixture operation succeeds")
        )
        .expect("symbolic fixture operation succeeds"),
        cli
    );
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .args(["--api-docs", "symbolic"])
        .output()
        .expect("symbolic fixture operation succeeds");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("interface Symbolic"));
    for file in ["docs/SYMBOLIC.md", "docs/SYMBOLIC.ja.md"] {
        let text = std::fs::read_to_string(common::root().join(file))
            .expect("symbolic fixture operation succeeds");
        let example = text
            .split("```js\n")
            .nth(1)
            .expect("symbolic fixture operation succeeds")
            .split("```")
            .next()
            .expect("symbolic fixture operation succeeds");
        let code = example
            .replace("\"app.elf\"", &json!(path).to_string())
            .replace("\"check\"", "\"password\"");
        let outcome = engine.run(&code, None);
        assert!(outcome.error.is_none(), "{file}: {:?}", outcome.error);
        assert_eq!(
            serde_json::from_str::<Value>(&outcome.output)
                .expect("symbolic fixture operation succeeds"),
            json!(["0x2a"])
        );
    }
    let code = format!(
        r#"
const b = velk.open({});
const s = b.symbolic('password', {{arguments:[0]}});
const x = s.readRegister(7);
const c = s.constant(42);
s.constrain(x, 'eq', c);
const f = s.fork();
f.writeRegister(0, c);
f.writeMemory('0x10000000', [x]);
const bytes = f.readMemory('0x10000000', 1);
const result = [s.evaluate(x), s.bounds(x), f.evaluate(f.readRegister(0)), f.evaluate(bytes[0]), s.satisfiable(), s.step([s.address()]).reason];
f.constrain(x, 'ne', c);
result.push(f.satisfiable());
f.dispose(); s.dispose();
result;
"#,
        json!(path)
    );
    let outcome = engine.run(&code, None);
    assert!(outcome.error.is_none(), "{:?}", outcome.error);
    assert_eq!(
        serde_json::from_str::<Value>(&outcome.output)
            .expect("symbolic fixture operation succeeds"),
        json!([
            ["0x2a"],
            ["0x2a", "0x2a"],
            ["0x2a"],
            ["0x2a"],
            true,
            "address",
            false
        ])
    );
}

#[test]
fn missing_solver_only_affects_symbolic_operations() {
    let path = fixtures().join("x86_64-O0.elf");
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .env("VELK_SOLVER", "velk-missing-smt-solver")
        .args(["--explore", "password", "--find", "0x1"])
        .arg(&path)
        .output()
        .expect("symbolic fixture operation succeeds");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot start solver"));
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .env("VELK_SOLVER", "velk-missing-smt-solver")
        .args(["--functions"])
        .arg(path)
        .output()
        .expect("symbolic fixture operation succeeds");
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn nested_expressions_preserve_intermediate_values_and_widths() {
    if !solver_available() {
        return;
    }
    use velk::ir::{BinOp, Expr};
    for arch in ["x86_64", "aarch64"] {
        let binary = binary(arch, 0);
        let mut state = State::new(&binary, "password", &Options::default())
            .expect("symbolic fixture operation succeeds");
        let x = state
            .symbolic()
            .expect("symbolic fixture operation succeeds");
        state
            .constrain(Cond::Eq, &x, &Term::constant(0xffff_ffff), 64)
            .expect("symbolic fixture operation succeeds");
        state
            .write_register(0, x)
            .expect("symbolic fixture operation succeeds");
        let sum = Expr::Bin {
            op: BinOp::Add,
            lhs: Box::new(Expr::reg(0, 32)),
            rhs: Box::new(Expr::Const(1)),
        };
        let expression = Expr::Bin {
            op: BinOp::Shr,
            lhs: Box::new(sum),
            rhs: Box::new(Expr::Const(32)),
        };
        let result = state
            .expression(&binary, &expression)
            .expect("symbolic fixture operation succeeds");
        assert_eq!(
            state
                .evaluate(&result, 1)
                .expect("symbolic fixture operation succeeds"),
            [1]
        );
        state
            .write_register(0, Term::constant(0xffff_ffff))
            .expect("symbolic fixture operation succeeds");
        let result = state
            .expression(&binary, &expression)
            .expect("symbolic fixture operation succeeds");
        assert_eq!(
            state
                .evaluate(&result, 1)
                .expect("symbolic fixture operation succeeds"),
            [1]
        );
        let select = Expr::Select {
            cond: Cond::Eq,
            lhs: Box::new(Expr::Const(1)),
            rhs: Box::new(Expr::Const(1)),
            then: Box::new(Expr::Const(7)),
            els: Box::new(Expr::Load {
                addr: Box::new(Expr::Const(0)),
                width: 8,
                signed: false,
            }),
        };
        let result = state
            .expression(&binary, &select)
            .expect("symbolic fixture operation succeeds");
        assert_eq!(
            state
                .evaluate(&result, 1)
                .expect("symbolic fixture operation succeeds"),
            [7]
        );
    }
}

#[test]
fn address_enumeration_reports_incomplete_search() {
    if !solver_available() {
        return;
    }
    let binary = binary("x86_64", 0);
    let mut options = options(&binary, "indirect");
    options.address_limit = 1;
    let report = symbolic::explore(&binary, "indirect", &options)
        .expect("symbolic fixture operation succeeds");
    assert!(
        !report.found,
        "first array element does not satisfy the check"
    );
    assert_eq!(
        report.reason, "address enumeration bound reached",
        "{report:?}"
    );
    options.address_limit = 4;
    assert!(
        symbolic::explore(&binary, "indirect", &options)
            .expect("symbolic fixture operation succeeds")
            .found
    );
}

#[test]
fn branch_parent_and_terminal_states_cannot_skip_execution() {
    if !solver_available() {
        return;
    }
    let binary = binary("x86_64", 0);
    let options = options(&binary, "password");
    let mut state =
        State::new(&binary, "password", &options).expect("symbolic fixture operation succeeds");
    let Step::Branch(successors) = state
        .step(&binary, &[])
        .expect("symbolic fixture operation succeeds")
    else {
        panic!("password comparison must branch");
    };
    assert_eq!(successors.len(), 2);
    assert!(
        matches!(state.step(&binary, &[]).expect("symbolic fixture operation succeeds"), Step::Stopped(reason) if reason.contains("forked"))
    );
    let mut concrete = State::new(&binary, "success", &Options::default())
        .expect("symbolic fixture operation succeeds");
    assert!(
        matches!(concrete.step(&binary, &[]).expect("symbolic fixture operation succeeds"), Step::Stopped(reason) if reason == "return")
    );
    assert!(
        matches!(concrete.step(&binary, &[]).expect("symbolic fixture operation succeeds"), Step::Stopped(reason) if reason == "return")
    );
}

#[test]
fn scalar_terms_match_the_ir_evaluator_on_edge_inputs() {
    if !solver_available() {
        return;
    }
    use velk::ir::eval::{self, Convention, Outcome, Setup};
    use velk::ir::{BinOp, Block, Expr, Stmt};
    let values = [
        0,
        1,
        0x7f,
        0x80,
        0xff,
        0x7fff,
        0x8000,
        0xffff,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_ffff,
        1 << 63,
        u64::MAX,
    ];
    let operations = [
        BinOp::Add,
        BinOp::Sub,
        BinOp::Mul,
        BinOp::MulHigh,
        BinOp::MulHighS,
        BinOp::And,
        BinOp::Or,
        BinOp::Xor,
        BinOp::Shl,
        BinOp::Shr,
        BinOp::Sar,
        BinOp::DivU,
        BinOp::DivS,
        BinOp::ModU,
        BinOp::ModS,
    ];
    for arch in ["x86_64", "aarch64"] {
        let mut binary = binary(arch, 0);
        let address = binary
            .find("success")
            .expect("symbolic fixture operation succeeds")
            .addr;
        let mut ir = binary
            .analysis(address, None)
            .expect("symbolic fixture operation succeeds")
            .ir
            .clone();
        ir.params.clear();
        let mut state = State::new(&binary, "password", &Options::default())
            .expect("symbolic fixture operation succeeds");
        let x = state
            .symbolic()
            .expect("symbolic fixture operation succeeds");
        let y = state
            .symbolic()
            .expect("symbolic fixture operation succeeds");
        state
            .write_register(0, x.clone())
            .expect("symbolic fixture operation succeeds");
        state
            .write_register(1, y.clone())
            .expect("symbolic fixture operation succeeds");
        for width in [8, 16, 32, 64] {
            for (index, &a) in values.iter().enumerate() {
                let b = values[(index * 5 + 3) % values.len()];
                let mut sample = state.clone();
                sample
                    .constrain(Cond::Eq, &x, &Term::constant(a), 64)
                    .expect("symbolic fixture operation succeeds");
                sample
                    .constrain(Cond::Eq, &y, &Term::constant(b), 64)
                    .expect("symbolic fixture operation succeeds");
                for op in operations {
                    let expression = Expr::Bin {
                        op,
                        lhs: Box::new(Expr::reg(0, width)),
                        rhs: Box::new(Expr::reg(1, width)),
                    };
                    ir.blocks = vec![Block {
                        start: 0,
                        stmts: vec![Stmt::Ret {
                            value: expression.clone(),
                        }],
                    }];
                    let registers = [(0, a), (1, b)];
                    let setup = Setup {
                        seed: 0,
                        convention: Convention {
                            arguments: &[],
                            clobbered: &[],
                        },
                        registers: &registers,
                        memory: &[],
                        step_limit: 10,
                    };
                    let reference = eval::run(&ir, &setup);
                    let term = sample.expression(&binary, &expression);
                    match reference {
                        Outcome::Return { value, .. } => {
                            let term = term.expect("symbolic fixture operation succeeds");
                            let mut mismatch = sample.clone();
                            mismatch
                                .constrain(Cond::Ne, &term, &Term::constant(value), 64)
                                .expect("symbolic fixture operation succeeds");
                            assert!(
                                !mismatch
                                    .satisfiable()
                                    .expect("symbolic fixture operation succeeds"),
                                "{arch} {width} {op:?} {a:x} {b:x}"
                            );
                        }
                        Outcome::Unknown(_) => assert!(term.is_err()),
                        Outcome::Trap { .. } => panic!("scalar expression cannot trap"),
                    }
                }
            }
        }
    }
}

#[test]
fn initial_state_writes_are_in_the_concrete_inputs() {
    if !solver_available() {
        return;
    }
    for arch in ["x86_64", "aarch64"] {
        let binary = binary(arch, 0);
        let options = options(&binary, "avoided");
        let mut state = State::new(&binary, "avoided", &options).expect("symbolic fixture state");
        state
            .write_memory(&binary, 0x10000000, &[Term::constant(42)])
            .expect("writable input byte");
        let report = state.explore(&binary, &options).expect("valid search");
        assert!(report.found, "{report:?}");
        let inputs = report.inputs.expect("found input");
        assert_eq!(inputs.memory["0x10000000"], 42);
        let replay: emulation::Options = serde_json::from_value(json!({
            "arguments": ["0x10000000"],
            "end": [binary.find("success").expect("success function").addr],
            "memory": inputs.memory.iter().map(|(address, byte)| json!({"address": address, "bytes": [byte]})).collect::<Vec<_>>()
        })).expect("concrete input writes");
        let concrete = emulation::run(&binary, "avoided", &replay, None).expect("concrete replay");
        assert_eq!(concrete.reason, "end address", "{:?}", concrete.error);
        let mut options = options;
        options.memory.clear();
        options.argument_values.clear();
        options.arguments = vec![0];
        let mut state = State::new(&binary, "recurse", &options).expect("symbolic argument state");
        let register = binary
            .image()
            .convention_of(binary.find("recurse").expect("recursive function").addr)
            .arguments()[0];
        state
            .write_register(register, Term::constant(3))
            .expect("initial physical argument");
        let report = state
            .explore(&binary, &options)
            .expect("valid recursive search");
        assert!(report.found, "{report:?}");
        assert_eq!(report.inputs.expect("found input").arguments[&0], "0x3");
        let replay: emulation::Options = serde_json::from_value(json!({
            "arguments": [3], "end": [binary.find("success").expect("success function").addr]
        }))
        .expect("concrete recursive argument");
        let concrete =
            emulation::run(&binary, "recurse", &replay, None).expect("concrete recursion replay");
        assert_eq!(concrete.reason, "end address", "{:?}", concrete.error);
    }
}

#[test]
fn imported_stop_addresses_are_rejected_instead_of_ignored() {
    if !solver_available() {
        return;
    }
    let binary = binary("x86_64", 0);
    let mut options = options(&binary, "getchar_password");
    let slot = *binary
        .image()
        .imports
        .keys()
        .next()
        .expect("imported stream hook");
    options.avoid = vec![Word::Text(format!("0x{slot:x}"))];
    let error = symbolic::explore(&binary, "getchar_password", &options)
        .expect_err("imported stop is unsupported");
    assert!(error.to_string().contains("imported address"));
}

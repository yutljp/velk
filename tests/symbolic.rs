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
        let out = common::root()
            .join("target/symbolic-fixtures")
            .join(std::process::id().to_string());
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
    for arch in ["i386", "x86_64", "aarch64"] {
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

#[test]
fn libc_return_solutions_replay() {
    if !solver_available() {
        return;
    }
    for arch in ["i386", "x86_64", "aarch64"] {
        for opt in [0, 2] {
            let binary = binary(arch, opt);
            for (name, length) in [
                ("scan_stream", 3),
                ("scan_stack", 9),
                ("scan_decimal", 2),
                ("scan_unsigned", 2),
                ("scan_hex", 2),
                ("scan_text", 3),
                ("scan_characters", 3),
                ("scan_string", 2),
                ("line_compare", 3),
                ("allocated_line", 3),
                ("integer_check", 2),
                ("integer_hex", 2),
                ("copy_check", 3),
                ("output_check", 1),
                ("bound_descriptor", 1),
            ] {
                let options: Options = serde_json::from_value(json!({"stdin": length, "returns": {"eq": 1}, "pathLimit": 4096, "stdinDescriptors": [7]})).expect("return options");
                let report = symbolic::solve(&binary, name, &options).expect("return search");
                assert!(report.found, "{arch} O{opt} {name}: {report:?}");
                let inputs = report.inputs.expect("satisfying input");
                #[cfg(target_os = "linux")]
                {
                    use std::io::Write as _;
                    use std::process::Stdio;
                    let mut child = Command::new(fixtures().join("native-libc"))
                        .arg(name)
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .spawn()
                        .expect("native checker");
                    child
                        .stdin
                        .take()
                        .expect("native input pipe")
                        .write_all(&inputs.stdin)
                        .expect("native input");
                    let native = child.wait_with_output().expect("native result");
                    assert!(
                        native.status.success(),
                        "{arch} O{opt} {name}: {:?}",
                        inputs.stdin
                    );
                    assert_eq!(native.stdout, inputs.stdout, "native {arch} O{opt} {name}");
                }
                let options = serde_json::from_value(json!({"stdin": {"hex": inputs.stdin.iter().map(|b|format!("{b:02x}")).collect::<String>()}, "stdinDescriptors": [7]})).expect("replay options");
                let concrete =
                    emulation::run(&binary, name, &options, None).expect("concrete replay");
                assert_eq!(
                    concrete.return_value, "0x1",
                    "{arch} O{opt} {name}: {concrete:?}"
                );
                assert_eq!(
                    concrete.stdout.as_bytes(),
                    inputs.stdout,
                    "{arch} O{opt} {name}"
                );
            }
        }
    }
}

#[test]
fn stack_switch_and_branch_proofs() {
    if !solver_available() {
        return;
    }
    for arch in ["x86_64", "aarch64"] {
        for opt in [0, 2] {
            let binary = binary(arch, opt);
            for (name, options) in [
                (
                    "stack_check",
                    json!({"arguments":[9], "argumentValues":[1,2,3,4,5,6,7,8,9,0], "returns":{"eq":1}}),
                ),
                (
                    "switch_check",
                    json!({"arguments":[0],"returns":{"eq":1},"addressLimit":16}),
                ),
            ] {
                let options = serde_json::from_value(options).expect("search options");
                let report =
                    symbolic::solve(&binary, name, &options).expect("scalar return search");
                assert!(report.found, "{arch} O{opt} {name}: {report:?}");
                let inputs = report.inputs.expect("scalar inputs");
                let count = inputs.arguments.keys().max().copied().unwrap_or(0) + 1;
                let values: Vec<String> = (0..count)
                    .map(|index| {
                        inputs
                            .arguments
                            .get(&index)
                            .cloned()
                            .unwrap_or_else(|| "0x0".into())
                    })
                    .collect();
                let options =
                    serde_json::from_value(json!({"arguments":values})).expect("scalar replay");
                let concrete =
                    emulation::run(&binary, name, &options, None).expect("scalar concrete replay");
                assert_eq!(concrete.return_value, "0x1", "{concrete:?}");
            }
            for name in [
                "even_predicate",
                "square_predicate",
                "normal_predicate",
                "repeated_branch",
            ] {
                let options: Options =
                    serde_json::from_value(json!({"arguments":[0,1]})).expect("branch options");
                let report =
                    symbolic::branch_feasibility(&binary, name, &options).expect("branch proof");
                assert!(report.complete, "{arch} O{opt} {name}: {report:?}");
                assert!(report.branches.iter().all(|b| b.status == "unsat"));
                if opt == 0 && matches!(name, "even_predicate" | "square_predicate") {
                    assert!(!report.branches.is_empty(), "{arch} {name}");
                }
                if matches!(name, "normal_predicate" | "repeated_branch") {
                    assert!(report.branches.is_empty(), "{report:?}");
                }
            }
        }
    }
}

#[test]
fn return_and_feasibility_interfaces_agree() {
    use serde_json::Value;
    use std::process::Stdio;
    if !solver_available() {
        return;
    }
    let path = fixtures().join("x86_64-O0.elf");
    let engine = velk::script::Engine::new().expect("script engine");
    for (name, action, tool, flags, options) in [
        (
            "scan_decimal",
            "solve",
            "velk_solve",
            vec![
                "--solve",
                "scan_decimal",
                "--returns",
                "eq:1",
                "--stdin",
                "2",
            ],
            json!({"stdin":2,"returns":{"eq":1}}),
        ),
        (
            "even_predicate",
            "branchFeasibility",
            "velk_branch_feasibility",
            vec![
                "--opaque",
                "even_predicate",
                "--symbolic-options",
                "{\"arguments\":[0]}",
            ],
            json!({"arguments":[0]}),
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_velk"))
            .args(flags)
            .arg("--json")
            .arg(&path)
            .output()
            .expect("CLI run");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let cli: Value = serde_json::from_slice(&output.stdout).expect("CLI JSON");
        let code = match action {
            "solve" => format!(
                "velk.open({}).solve({},{options})",
                json!(path),
                json!(name)
            ),
            _ => format!(
                "velk.open({}).branchFeasibility({},{options})",
                json!(path),
                json!(name)
            ),
        };
        let outcome = engine.run(&code, None);
        assert!(outcome.error.is_none(), "{:?}", outcome.error);
        assert_eq!(
            serde_json::from_str::<Value>(&outcome.output).expect("JS JSON"),
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
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":tool,"arguments":{"path":path,"start":name,"options":options}}}),
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
            cli
        );
    }
}

#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "compares ASCII C locale and strtol behavior with Linux libc"
)]
fn integer_and_case_models_match_native_edges() {
    if !solver_available() {
        return;
    }
    let cases = [
        "",
        "0",
        "+",
        "-",
        "  -42rest",
        "+42",
        "0x",
        "0x2a",
        "0XFF!",
        "-8000000000000000",
        "9223372036854775807",
        "9223372036854775808",
        "-9223372036854775809",
        "18446744073709551615",
        "9999999999999999999999999999999999999999",
    ];
    for arch in ["x86_64", "aarch64"] {
        let binary = binary(arch, 2);
        for base in [10, 16] {
            for text in cases {
                for name in ["integer_value", "integer_end"] {
                    let reference = Command::new(fixtures().join("native-libc"))
                        .args([name, text, &base.to_string()])
                        .output()
                        .expect("native conversion");
                    assert!(reference.status.success());
                    let expected =
                        String::from_utf8(reference.stdout).expect("native ASCII result");
                    let options: Options = serde_json::from_value(
                        json!({"argumentValues":["0x10000000",base],"returns":{"eq":expected}}),
                    )
                    .expect("integer options");
                    let mut state = State::new(&binary, name, &options).expect("integer state");
                    let bytes: Vec<Term> = text
                        .bytes()
                        .chain([0])
                        .map(|byte| Term::constant(u64::from(byte)))
                        .collect();
                    state
                        .write_memory(&binary, 0x10000000, &bytes)
                        .expect("conversion input");
                    let report = state.explore(&binary, &options).expect("integer solve");
                    assert!(report.found, "{arch} {name} {base} {text:?}: {report:?}");
                    let setup = serde_json::from_value(json!({"arguments":["0x10000000",base],"memory":[{"address":"0x10000000","bytes":text.bytes().chain([0]).collect::<Vec<_>>()}]})).expect("integer replay options");
                    let concrete =
                        emulation::run(&binary, name, &setup, None).expect("integer replay");
                    assert_eq!(
                        concrete.return_value, expected,
                        "{arch} {name} {base} {text:?}"
                    );
                }
            }
        }
        for c in [0, 1, 32, 64, 65, 90, 91, 96, 97, 122, 123, 127, 128, 255] {
            let reference = Command::new(fixtures().join("native-libc"))
                .args(["case_value", &c.to_string(), "0"])
                .output()
                .expect("native case conversion");
            let expected = String::from_utf8(reference.stdout).expect("case result");
            let options: Options =
                serde_json::from_value(json!({"argumentValues":[c],"returns":{"eq":expected}}))
                    .expect("case options");
            let report = symbolic::solve(&binary, "case_value", &options).expect("case solve");
            assert!(report.found, "{arch} {c}: {report:?}");
            let setup =
                serde_json::from_value(json!({"arguments":[c]})).expect("case replay options");
            let concrete =
                emulation::run(&binary, "case_value", &setup, None).expect("case replay");
            assert_eq!(concrete.return_value, expected);
        }
    }
}

#[test]
fn incomplete_branch_search_does_not_claim_unsat() {
    if !solver_available() {
        return;
    }
    let binary = binary("x86_64", 0);
    let options: Options =
        serde_json::from_value(json!({"arguments":[0],"pathLimit":1})).expect("bounded options");
    let report =
        symbolic::branch_feasibility(&binary, "even_predicate", &options).expect("bounded proof");
    assert!(!report.complete, "{report:?}");
    assert!(!report.branches.is_empty());
    assert!(report.branches.iter().all(|b| {
        b.status == "unknown"
            && b.reason
                .as_deref()
                .is_some_and(|s| s.contains("path budget"))
    }));
    for condition in [
        json!({"eq":1}),
        json!({"ne":0}),
        json!({"lt":2}),
        json!({"gt":0}),
    ] {
        let options: Options = serde_json::from_value(json!({"arguments":[0],"returns":condition}))
            .expect("return condition");
        let report =
            symbolic::solve(&binary, "normal_predicate", &options).expect("comparison solve");
        assert!(report.found, "{report:?}");
        let inputs = report.inputs.expect("comparison inputs");
        let setup = serde_json::from_value(json!({"arguments":[inputs.arguments[&0]]}))
            .expect("comparison replay options");
        let concrete =
            emulation::run(&binary, "normal_predicate", &setup, None).expect("comparison replay");
        let value = u64::from_str_radix(concrete.return_value.trim_start_matches("0x"), 16)
            .expect("returned integer");
        assert!(match condition
            .as_object()
            .expect("condition")
            .keys()
            .next()
            .expect("operator")
            .as_str()
        {
            "eq" => value == 1,
            "ne" => value != 0,
            "lt" => (value as i64) < 2,
            "gt" => (value as i64) > 0,
            _ => false,
        });
    }
}

#[test]
fn signed_return_constants_accept_numbers_and_strings() {
    if !solver_available() {
        return;
    }
    for arch in ["x86_64", "aarch64"] {
        let binary = binary(arch, 2);
        for condition in [
            json!({"eq":-1}),
            json!({"ne":"-1"}),
            json!({"lt":-1}),
            json!({"gt":"-2"}),
        ] {
            let options: Options =
                serde_json::from_value(json!({"arguments":[0],"returns":condition}))
                    .expect("signed condition");
            let report =
                symbolic::solve(&binary, "signed_identity", &options).expect("signed solve");
            assert!(report.found, "{report:?}");
            let inputs = report.inputs.expect("signed inputs");
            let setup = serde_json::from_value(json!({"arguments":[inputs.arguments[&0]]}))
                .expect("signed replay options");
            let concrete =
                emulation::run(&binary, "signed_identity", &setup, None).expect("signed replay");
            let value = u64::from_str_radix(concrete.return_value.trim_start_matches("0x"), 16)
                .expect("return bits") as i64;
            let op = condition
                .as_object()
                .expect("condition")
                .keys()
                .next()
                .expect("operator");
            assert!(match op.as_str() {
                "eq" => value == -1,
                "ne" => value != -1,
                "lt" => value < -1,
                "gt" => value > -2,
                _ => false,
            });
        }
    }
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .args([
            "--solve",
            "signed_identity",
            "--returns",
            "lt:-1",
            "--symbolic-options",
            "{\"arguments\":[0]}",
            "--json",
        ])
        .arg(fixtures().join("x86_64-O2.elf"))
        .output()
        .expect("signed CLI");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("signed CLI report");
    let setup = serde_json::from_value(json!({"arguments":[report["inputs"]["arguments"]["0"]]}))
        .expect("signed CLI replay");
    let concrete = emulation::run(&binary("x86_64", 2), "signed_identity", &setup, None)
        .expect("signed CLI concrete replay");
    let value = u64::from_str_radix(concrete.return_value.trim_start_matches("0x"), 16)
        .expect("signed CLI return") as i64;
    assert!(value < -1);
}

#[test]
fn solve_rejects_address_goals_in_options() {
    if solver_available() {
        let binary = binary("x86_64", 0);
        let options: Options =
            serde_json::from_value(json!({"find":[1],"returns":{"eq":1}})).expect("mixed goals");
        let state = State::new(&binary, "normal_predicate", &options).expect("mixed goal state");
        let error = state
            .explore(&binary, &options)
            .expect_err("mixed goals must be rejected");
        assert!(error.to_string().contains("mutually exclusive"));
    }

    let path = fixtures().join("x86_64-O0.elf");
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .args([
            "--solve",
            "normal_predicate",
            "--returns",
            "eq:1",
            "--symbolic-options",
            "{\"find\":[1]}",
        ])
        .arg(path)
        .output()
        .expect("invalid goal CLI");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("solve requires returns and no find addresses"),
        "{output:?}"
    );
}

#[test]
fn unreachable_conditional_instructions_are_reported() {
    if !solver_available() {
        return;
    }
    for arch in ["x86_64", "aarch64"] {
        let binary = binary(arch, 0);
        let options =
            serde_json::from_value(json!({"arguments":[0]})).expect("unreachable options");
        let report = symbolic::branch_feasibility(&binary, "unreachable_branches", &options)
            .expect("unreachable proof");
        assert!(report.complete, "{report:?}");
        assert!(report.branches.iter().all(|b| b.status == "unsat"));
        let unreachable: Vec<_> = report
            .branches
            .iter()
            .filter(|b| {
                b.reason
                    .as_deref()
                    .is_some_and(|s| s.contains("instruction is unreachable"))
            })
            .collect();
        assert_eq!(unreachable.len(), 2, "{arch}: {report:?}");
        assert_eq!(unreachable[0].address, unreachable[1].address);
        assert_ne!(unreachable[0].taken, unreachable[1].taken);
    }
}

#[test]
fn tail_calls_preserve_returns_and_require_exact_library_evidence() {
    use velk::service::SignatureOptions;
    use velk::sigs::{self, Database};

    if !solver_available() {
        return;
    }
    for arch in ["x86_64", "aarch64"] {
        let path = fixtures().join(format!("{arch}-O0.elf"));
        let mut database = sigs::build(&path, None).expect("build instruction signatures");
        database
            .entries
            .retain(|entry| entry.name == "local_length");
        assert_eq!(database.entries.len(), 1);
        database.entries[0].name = "_strlen".into();
        for ambiguous in [false, true] {
            let mut entries = database.entries.clone();
            if ambiguous {
                let mut alias = entries[0].clone();
                alias.name = "other_length".into();
                entries.push(alias);
            }
            let database_path = fixtures().join(format!(
                "{arch}-{ambiguous}-budget-unsupported-address enumeration bound.json"
            ));
            std::fs::write(
                &database_path,
                serde_json::to_vec(&Database::new(entries)).expect("serialize signatures"),
            )
            .expect("write signatures");
            let signatures = SignatureOptions {
                defaults: false,
                files: vec![database_path],
            };
            let mut binary = Binary::open_with_signatures(&path, None, None, &signatures)
                .expect("open with signatures");
            let target = binary
                .find_address("local_length")
                .expect("local length entry");
            let stop_options: Options =
                serde_json::from_value(json!({"find":[target], "argumentValues":["0x10000000"]}))
                    .expect("static entry stop options");
            for name in ["tail_length", "nested_tail"] {
                let report =
                    symbolic::explore(&binary, name, &stop_options).expect("stop at static entry");
                assert!(report.found, "{arch} {name}: {report:?}");
                assert_eq!(report.path.last(), Some(&format!("0x{target:x}")));
                assert!(
                    report
                        .diagnostics
                        .iter()
                        .all(|message| !message.contains("exact signature"))
                );
            }
            for (name, expected) in [("tail_length", 3), ("tail_import", 3), ("nested_tail", 10)] {
                let options: Options = serde_json::from_value(json!({
                    "argumentValues":["0x10000000"],
                    "memory":[{"address":"0x10000000","size":4}],
                    "returns":{"eq":expected}
                }))
                .expect("tail options");
                let report = symbolic::solve(&binary, name, &options).expect("solve tail call");
                assert!(report.found, "{arch} {ambiguous} {name}: {report:?}");
                let modeled = report
                    .diagnostics
                    .iter()
                    .any(|message| message.contains("exact signature"));
                assert_eq!(modeled, !ambiguous && name != "tail_import", "{report:?}");
                assert!(
                    report
                        .diagnostics
                        .iter()
                        .filter(|message| message.starts_with("libc model at "))
                        .count()
                        <= 1,
                    "{report:?}"
                );
                if !ambiguous && name == "nested_tail" {
                    use serde_json::Value;
                    use std::process::Stdio;
                    let expected = json!(&report);
                    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
                        .args(["--solve", name, "--returns", "eq:10", "--json", "--no-default-signatures", "--signatures"])
                        .arg(&signatures.files[0])
                        .args(["--symbolic-options", &serde_json::to_string(&json!({"argumentValues":["0x10000000"],"memory":[{"address":"0x10000000","size":4}]})).expect("CLI options")])
                        .arg(&path).output().expect("static model CLI");
                    assert!(output.status.success(), "{output:?}");
                    assert_eq!(
                        serde_json::from_slice::<Value>(&output.stdout).expect("CLI JSON"),
                        expected
                    );
                    let code = format!(
                        "velk.open({}, {{defaultSignatures:false, signatures:{}, cache:false}}).solve('nested_tail', {})",
                        json!(path),
                        json!(signatures.files),
                        json!({"argumentValues":["0x10000000"],"memory":[{"address":"0x10000000","size":4}],"returns":{"eq":10}})
                    );
                    let engine = velk::script::Engine::new().expect("script engine");
                    let outcome = engine.run(&code, None);
                    assert!(outcome.error.is_none(), "{:?}", outcome.error);
                    assert_eq!(
                        serde_json::from_str::<Value>(&outcome.output).expect("script JSON"),
                        expected
                    );
                    let child = Command::new(env!("CARGO_BIN_EXE_velk"))
                        .arg("--mcp")
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .spawn()
                        .expect("MCP process");
                    let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"velk_run_script","arguments":{"code":code}}});
                    let output = common::mcp_request(child, &request);
                    let response: Value =
                        serde_json::from_slice(&output.stdout).expect("MCP response");
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
                }
                let inputs = report.inputs.expect("tail inputs");
                let bytes: Vec<_> = inputs.memory.values().copied().collect();
                assert!(bytes[..3].iter().all(|byte| *byte != 0));
                assert_eq!(bytes[3], 0);
                #[cfg(target_os = "linux")]
                {
                    use std::io::Write as _;
                    use std::process::Stdio;
                    let mut child = Command::new(fixtures().join("native-calls"))
                        .stdin(Stdio::piped())
                        .spawn()
                        .expect("native tail calls");
                    child
                        .stdin
                        .take()
                        .expect("native stdin")
                        .write_all(&bytes)
                        .expect("native input");
                    assert!(child.wait().expect("native result").success());
                }
            }
            if !ambiguous {
                let options: Options = serde_json::from_value(json!({
                    "argumentValues":["0x10000000"],
                    "memory":[{"address":"0x10000000","size":4}],
                    "returns":{"eq":"0xffffffffffffffff"}
                }))
                .expect("impossible return options");
                let report = symbolic::solve(&binary, "tail_length", &options)
                    .expect("search with identified model");
                assert!(!report.found, "{arch}: {report:?}");
                assert_eq!(report.reason, "paths exhausted", "{arch}: {report:?}");
                assert!(report.diagnostics.iter().any(|message| {
                    message.starts_with("libc model at ") && message.contains("budget-unsupported")
                }));

                let options: Options = serde_json::from_value(json!({
                    "argumentValues":["0x10000000"],
                    "memory":[{"address":"0x10000000","size":4}],
                    "returns":{"eq":3}
                }))
                .expect("return options");
                let state = State::new(&binary, "tail_length", &options).expect("symbolic state");
                let mut priming = state.clone();
                assert!(matches!(
                    priming.step(&binary, &[]).expect("prime identification"),
                    Step::Branch(_)
                ));
                let disabled = Binary::open_with_signatures(
                    &path,
                    None,
                    None,
                    &SignatureOptions {
                        defaults: false,
                        files: Vec::new(),
                    },
                )
                .expect("open without signatures");
                let report = state
                    .clone()
                    .explore(&disabled, &options)
                    .expect("search without signatures");
                assert!(report.found, "{arch}: {report:?}");
                assert!(
                    report
                        .diagnostics
                        .iter()
                        .all(|message| !message.starts_with("libc model at ")),
                    "{arch}: {report:?}"
                );

                let mut alias = database.entries[0].clone();
                alias.name = "other_length".into();
                binary
                    .identify(&Database::new(vec![alias]), None)
                    .expect("add ambiguous signature");
                assert_eq!(
                    binary.image().functions[&target]
                        .library
                        .as_ref()
                        .expect("library evidence")
                        .certainty,
                    velk::sigs::Certainty::Ambiguous
                );
                let report = state
                    .explore(&binary, &options)
                    .expect("search with ambiguous signatures");
                assert!(report.found, "{arch}: {report:?}");
                assert!(
                    report
                        .diagnostics
                        .iter()
                        .all(|message| !message.starts_with("libc model at ")),
                    "{arch}: {report:?}"
                );
            }
        }
    }
}

#[test]
fn text_reports_show_bytes_and_bounded_path_summaries() {
    if !solver_available() {
        return;
    }
    let path = fixtures().join("x86_64-O0.elf");
    for (operation, name, options) in [
        (
            "--solve",
            "tail_length",
            json!({"argumentValues":["0x10000000"], "memory":[{"address":"0x10000000","size":4}], "returns":{"eq":3}}),
        ),
        (
            "--explore",
            "getchar_password",
            json!({"stdin":4,"find":[binary("x86_64",0).find("success").expect("success").addr]}),
        ),
        (
            "--explore",
            "arguments",
            json!({"argv":[1,3],"find":[binary("x86_64",0).find("success").expect("success").addr]}),
        ),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_velk"));
        if operation == "--solve" {
            command.args(["--returns", "eq:3"]);
        } else {
            command.args([
                "--find",
                &format!("0x{:x}", options["find"][0].as_u64().expect("find address")),
            ]);
        }
        let output = command
            .args([operation, name, "--symbolic-options", &options.to_string()])
            .arg(&path)
            .output()
            .expect("text report");
        assert!(output.status.success(), "{:?}", output);
        let text = String::from_utf8(output.stdout).expect("UTF-8 text report");
        let expected = match name {
            "tail_length" => "memory[0x10000000]:",
            "arguments" => "argv[1]: \"yes\" (hex: 79 65 73)",
            _ => "stdin: \"velk\" (hex: 76 65 6c 6b)",
        };
        assert!(text.contains(expected), "{text}");
        if name == "tail_length" {
            assert!(text.contains("\\x00\" (hex:"), "{text}");
        }
        let path_line = text
            .lines()
            .find(|line| line.starts_with("Path:"))
            .expect("path summary");
        assert!(path_line.contains(" addresses (0x"), "{path_line}");
        assert_eq!(path_line.matches(" -> ").count(), 1);
    }
}

#[test]
fn symbolic_narrow_pack_and_leading_zeros_match_scalar_values() {
    use velk::ir::{Expr, Operation};

    if !solver_available() {
        return;
    }
    let values = [0, 1, u64::MAX, 0x8000_7fff_0080_007f, 0xffff_0100_00ff_0000];
    for arch in ["x86_64", "aarch64"] {
        let binary = binary(arch, 0);
        let mut state =
            State::new(&binary, "password", &Options::default()).expect("expression state");
        let a = state.symbolic().expect("first input");
        let b = state.symbolic().expect("second input");
        state.write_register(0, a.clone()).expect("first register");
        state.write_register(1, b.clone()).expect("second register");
        for bits in [16u8, 32, 64] {
            for (index, &first) in values.iter().enumerate() {
                let second = values[(index + 2) % values.len()];
                let mut sample = state.clone();
                sample
                    .constrain(Cond::Eq, &a, &Term::constant(first), 64)
                    .expect("first value");
                sample
                    .constrain(Cond::Eq, &b, &Term::constant(second), 64)
                    .expect("second value");
                for op in [
                    Operation::Narrow(bits),
                    Operation::Pack {
                        from: bits,
                        unsigned: false,
                    },
                    Operation::Pack {
                        from: bits,
                        unsigned: true,
                    },
                    Operation::CountLeadingZeros(bits),
                ] {
                    let mut args = vec![Expr::reg(0, 64), Expr::reg(1, 64)];
                    args.truncate(op.arity());
                    let expression = Expr::Apply { op, args };
                    let term = sample
                        .expression(&binary, &expression)
                        .expect("symbolic operation");
                    let mut expected = 0;
                    if matches!(op, Operation::CountLeadingZeros(_)) {
                        let value = first & (u64::MAX >> (64 - bits));
                        expected = u64::from(value.leading_zeros() - (64 - u32::from(bits)));
                    } else {
                        for lane in 0..128 / u32::from(bits) {
                            let half = if lane < 64 / u32::from(bits) {
                                first
                            } else {
                                second
                            };
                            let shift = (lane % (64 / u32::from(bits))) * u32::from(bits);
                            let value = ((half >> shift) << (64 - bits)) as i64 >> (64 - bits);
                            let narrow = bits / 2;
                            let value = match op {
                                Operation::Pack { unsigned: true, .. } => {
                                    value.clamp(0, (1i64 << narrow) - 1)
                                }
                                Operation::Pack {
                                    unsigned: false, ..
                                } => {
                                    value.clamp(-(1i64 << (narrow - 1)), (1i64 << (narrow - 1)) - 1)
                                }
                                _ => value,
                            };
                            expected |= (value as u64 & ((1u64 << narrow) - 1))
                                << (lane * u32::from(narrow));
                        }
                    }
                    let mut mismatch = sample.clone();
                    mismatch
                        .constrain(Cond::Ne, &term, &Term::constant(expected), 64)
                        .expect("operation comparison");
                    assert!(
                        !mismatch.satisfiable().expect("operation equality"),
                        "{arch} {op:?} {first:x} {second:x}"
                    );
                }
            }
        }
    }
}

#[test]
fn tail_libc_models_read_stack_arguments_at_function_entry_offsets() {
    if !solver_available() {
        return;
    }
    for arch in ["x86_64", "aarch64"] {
        let binary = binary(arch, 0);
        let mut arguments = vec![
            json!("0x10000000"),
            json!(
                binary
                    .image()
                    .data_symbols
                    .iter()
                    .find(|(_, name)| name.as_str() == "scan_format")
                    .map(|(address, _)| *address)
                    .expect("scan format")
            ),
        ];
        for index in 0..7 {
            arguments.push(json!(0x10000020u64 + index));
        }
        let options: Options = serde_json::from_value(json!({
            "argumentValues":arguments,
            "memory":[{"address":"0x10000000","size":7}],
            "returns":{"eq":7}
        }))
        .expect("stack scan options");
        let report = symbolic::solve(&binary, "tail_scan", &options).expect("tail scan");
        assert!(report.found, "{arch}: {report:?}");
        let inputs = report.inputs.expect("scan inputs");
        let bytes: Vec<_> = inputs.memory.values().copied().collect();
        assert!(bytes.iter().all(|byte| *byte != 0));
        #[cfg(target_os = "linux")]
        {
            use std::io::Write as _;
            use std::process::Stdio;
            let mut child = Command::new(fixtures().join("native-calls"))
                .stdin(Stdio::piped())
                .spawn()
                .expect("native stack arguments");
            child
                .stdin
                .take()
                .expect("native stdin")
                .write_all(&bytes)
                .expect("native input");
            assert!(child.wait().expect("native result").success());
        }
    }
}

#[test]
fn i386_argv_and_library_interfaces_replay() {
    use serde_json::Value;
    use std::io::Write as _;
    use std::process::Stdio;

    if !solver_available() {
        return;
    }
    let engine = velk::script::Engine::new().expect("script engine");
    for opt in [0, 2] {
        let path = fixtures().join(format!("i386-O{opt}.elf"));
        let binary = Binary::open(&path).expect("i386 fixture");
        for (name, input) in [
            ("argv_one", json!({"argv":[1]})),
            ("argv_two", json!({"argv":[0,3]})),
            ("argv_three", json!({"argv":[1,0,3]})),
            ("scan_stream", json!({"stdin":3})),
            ("scan_stack", json!({"stdin":9})),
            ("scan_decimal", json!({"stdin":2})),
            ("scan_unsigned", json!({"stdin":2})),
            ("scan_hex", json!({"stdin":2})),
            ("scan_text", json!({"stdin":3})),
            ("scan_characters", json!({"stdin":3})),
            ("scan_string", json!({"stdin":2})),
            ("line_compare", json!({"stdin":3})),
            ("allocated_line", json!({"stdin":3})),
            ("integer_check", json!({"stdin":2})),
            ("integer_hex", json!({"stdin":2})),
            ("copy_check", json!({"stdin":3})),
            ("output_check", json!({"stdin":1})),
            (
                "bound_descriptor",
                json!({"stdin":1,"stdinDescriptors":[7]}),
            ),
        ] {
            let mut options = input;
            options["returns"] = json!({"eq":1});
            options["pathLimit"] = json!(4096);
            let output = Command::new(env!("CARGO_BIN_EXE_velk"))
                .args([
                    "--solve",
                    name,
                    "--returns",
                    "eq:1",
                    "--json",
                    "--symbolic-options",
                ])
                .arg(options.to_string())
                .arg(&path)
                .output()
                .expect("CLI solve");
            assert!(
                output.status.success(),
                "{name}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let cli: Value = serde_json::from_slice(&output.stdout).expect("CLI JSON");
            assert_eq!(cli["found"], true, "O{opt} {name}: {cli}");
            if name != "argv_one" {
                assert!(
                    cli["diagnostics"]
                        .as_array()
                        .expect("diagnostics")
                        .iter()
                        .any(|message| message
                            .as_str()
                            .is_some_and(|message| message.contains("import symbol"))),
                    "{name}: {cli}"
                );
            }
            let outcome = engine.run(
                &format!(
                    "velk.open({}).solve({},{options})",
                    json!(path),
                    json!(name)
                ),
                None,
            );
            assert!(outcome.error.is_none(), "{name}: {:?}", outcome.error);
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
                &json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"velk_solve","arguments":{"path":path,"start":name,"options":options}}}),
            );
            let response: Value = serde_json::from_slice(&output.stdout).expect("MCP JSON");
            assert_eq!(response["result"]["isError"], false, "{response}");
            let mcp: Value = serde_json::from_str(
                response["result"]["content"][0]["text"]
                    .as_str()
                    .expect("MCP text"),
            )
            .expect("MCP report");
            assert_eq!(mcp, cli);
            let search = serde_json::from_value(options).expect("search options");
            let report = symbolic::solve(&binary, name, &search).expect("API solve");
            assert_eq!(serde_json::to_value(&report).expect("API report"), cli);
            let inputs = report.inputs.expect("solved input");
            let argv: Vec<String> = inputs
                .argv
                .iter()
                .map(|bytes| {
                    assert!(!bytes.contains(&0));
                    String::from_utf8(bytes.clone()).expect("ASCII fixture argv")
                })
                .collect();
            let mut native = Command::new(fixtures().join("native-libc"))
                .arg(name)
                .args(&argv)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .expect("C reference");
            native
                .stdin
                .take()
                .expect("reference input")
                .write_all(&inputs.stdin)
                .expect("write reference input");
            let reference = native.wait_with_output().expect("C reference result");
            assert!(reference.status.success(), "O{opt} {name}: {inputs:?}");
            assert_eq!(reference.stdout, inputs.stdout, "O{opt} {name}");
            let mut replay = json!({"stdin":{"hex":inputs.stdin.iter().map(|byte| format!("{byte:02x}")).collect::<String>()},"stdinDescriptors":[7]});
            if name.starts_with("argv_") {
                replay["argv"] = json!(argv);
            }
            let replay = serde_json::from_value(replay).expect("replay options");
            let concrete = emulation::run(&binary, name, &replay, None).expect("concrete replay");
            assert!(concrete.error.is_none(), "O{opt} {name}: {concrete:?}");
            assert_eq!(concrete.return_value, "0x1", "O{opt} {name}: {concrete:?}");
            assert_eq!(concrete.stdout.as_bytes(), inputs.stdout);
        }
    }
}

#[test]
fn i386_strtol_limits_and_end_pointers_replay() {
    if !solver_available() {
        return;
    }
    for opt in [0, 2] {
        let binary = binary("i386", opt);
        for (text, base, value, end) in [
            ("", 10, 0u64, 0u64),
            ("+", 10, 0, 0),
            ("  -42rest", 10, 0xffffffd6, 5),
            ("2147483647", 10, 0x7fffffff, 10),
            ("2147483648", 10, 0x7fffffff, 10),
            ("-2147483648", 10, 0x80000000, 11),
            ("-2147483649", 10, 0x80000000, 11),
            ("99999999999999999999", 10, 0x7fffffff, 20),
            ("0x", 16, 0, 1),
            ("0x2arest", 16, 42, 4),
            ("7fffffff", 16, 0x7fffffff, 8),
            ("80000000", 16, 0x7fffffff, 8),
            ("-80000000", 16, 0x80000000, 9),
            ("-80000001", 16, 0x80000000, 9),
        ] {
            for (name, expected) in [("integer_value", value), ("integer_end", end)] {
                let options: Options = serde_json::from_value(json!({
                    "argumentValues":["0x10000000",base], "returns":{"eq":expected}
                }))
                .expect("conversion options");
                let mut state = State::new(&binary, name, &options).expect("conversion state");
                let bytes: Vec<Term> = text
                    .bytes()
                    .chain([0])
                    .map(|byte| Term::constant(u64::from(byte)))
                    .collect();
                state
                    .write_memory(&binary, 0x10000000, &bytes)
                    .expect("conversion text");
                let report = state.explore(&binary, &options).expect("conversion solve");
                assert!(report.found, "O{opt} {name} {text:?}: {report:?}");
                let setup = serde_json::from_value(json!({"arguments":["0x10000000",base],"memory":[{"address":"0x10000000","bytes":text.bytes().chain([0]).collect::<Vec<_>>()}]})).expect("conversion replay");
                let concrete =
                    emulation::run(&binary, name, &setup, None).expect("conversion replay");
                assert!(concrete.error.is_none(), "{concrete:?}");
                assert_eq!(
                    concrete.return_value,
                    format!("0x{expected:x}"),
                    "O{opt} {name} {text:?}"
                );
            }
        }
    }
}

#[test]
fn i386_tail_library_returns_use_eax() {
    if !solver_available() {
        return;
    }
    for opt in [0, 2] {
        let binary = binary("i386", opt);
        let options: Options =
            serde_json::from_value(json!({"returns":{"eq":"0xffffffff"}})).expect("EOF options");
        let report = symbolic::solve(&binary, "tail_getchar", &options).expect("tail input model");
        assert!(report.found, "O{opt}: {report:?}");
        let replay = emulation::run(
            &binary,
            "tail_getchar",
            &emulation::Options::default(),
            None,
        )
        .expect("tail EOF replay");
        assert_eq!(replay.return_value, "0xffffffff");
        let native = Command::new(fixtures().join("native-libc"))
            .arg("tail_getchar")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("native EOF reference");
        assert!(native.status.success(), "O{opt}: {native:?}");
    }
}

#[test]
fn import_diagnostics_preserve_all_paths_avoided() {
    if !solver_available() {
        return;
    }
    for arch in ["i386", "x86_64", "aarch64"] {
        let binary = binary(arch, 0);
        let options: Options = serde_json::from_value(json!({
            "stdin":4,
            "find":[binary.find("password").expect("unreached target").addr],
            "avoid":[binary.find("success").expect("success").addr, binary.find("failure").expect("failure").addr]
        })).expect("avoided paths options");
        let report =
            symbolic::explore(&binary, "getchar_password", &options).expect("avoid search");
        assert!(!report.found, "{arch}: {report:?}");
        assert_eq!(report.reason, "all paths avoided", "{arch}: {report:?}");
        assert!(
            report
                .diagnostics
                .iter()
                .any(|message| message.contains("import symbol")),
            "{arch}: {report:?}"
        );
    }
}

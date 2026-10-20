//! The printed pseudo-C must mean what the IR means. Every fixture function
//! whose optimized IR only computes on integer registers (no memory, calls
//! or globals) is printed, compiled with the system C compiler, and run on
//! the inputs the semantics test uses; its results are compared with the
//! interpreter's. Results are kept in tests/golden/recompile.txt: a new
//! mismatch or compile failure fails, and an improvement is blessed with
//! `VELK_BLESS=1 cargo test --release --test recompile`.

mod common;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use velk::ir::eval::{self, Outcome};
use velk::ir::{CType, Expr, FunctionIr, Operation, Stmt, trials};
use velk::loader::Image;
use velk::service::Binary;

const COMPILER: &str = "clang";
const FLAGS: [&str; 3] = ["-fwrapv", "-fno-strict-aliasing", "-w"];
const LEVELS: [&str; 2] = ["-O1", "-O0"];
/// A second seed for the values of registers the setup leaves unset: a run
/// whose result changes with it reads a register that is not a parameter.
const OTHER_SEED: u64 = 0x5eed_0000;
/// Rounds of dropping the functions the compiler rejects before giving up.
const COMPILE_ROUNDS: usize = 8;

/// What the pseudo-C uses beyond its own text: fixed-width integers, `bool`,
/// the high half of a product, and the integer type names debug info gives.
const HEADER: &str = r#"#include <inttypes.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>

static inline uint64_t __umulh(uint64_t a, uint64_t b) {
    return (uint64_t)(((unsigned __int128)a * b) >> 64);
}
static inline int64_t __smulh(int64_t a, int64_t b) {
    return (int64_t)(((__int128)a * b) >> 64);
}
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;
typedef uintptr_t usize;
typedef intptr_t isize;
"#;

/// Reads `c|r <function> <count> <arguments in hex>...` lines. `c` prints the
/// arguments as the parameters' types hold them, sign- or zero-extended to
/// 64 bits; `r` calls the function and prints its result, a trap, another
/// signal, or a timeout.
const DRIVER: &str = r#"
static sigjmp_buf velk_jump;
static void velk_signal(int sig) { siglongjmp(velk_jump, sig); }
static void velk_timer(long usec) {
    struct itimerval timer = {{0, 0}, {0, usec}};
    setitimer(ITIMER_REAL, &timer, 0);
}
int main(void) {
    int signals[] = {SIGILL, SIGTRAP, SIGFPE, SIGSEGV, SIGBUS, SIGALRM};
    for (unsigned i = 0; i < sizeof signals / sizeof *signals; i++) {
        struct sigaction action = {0};
        action.sa_handler = velk_signal;
        sigaction(signals[i], &action, 0);
    }
    char mode;
    int k, n;
    while (scanf(" %c %d %d", &mode, &k, &n) == 3) {
        uint64_t a[16] = {0}, c[16] = {0};
        for (int i = 0; i < n && i < 16; i++) {
            scanf("%" SCNx64, &a[i]);
        }
        if (mode == 'c') {
            velk_canonical(k, a, c);
            for (int i = 0; i < n; i++) {
                printf("%s%" PRIx64, i ? " " : "", c[i]);
            }
            printf("\n");
            continue;
        }
        int sig = sigsetjmp(velk_jump, 1);
        if (sig == 0) {
            velk_timer(200000);
            uint64_t r = velk_call(k, a);
            velk_timer(0);
            printf("v %" PRIx64 "\n", r);
        } else {
            velk_timer(0);
            if (sig == SIGILL || sig == SIGTRAP) {
                printf("trap\n");
            } else if (sig == SIGALRM) {
                printf("timeout\n");
            } else {
                printf("signal %d\n", sig);
            }
        }
        fflush(stdout);
    }
    return 0;
}
"#;

#[test]
fn printed_code_computes_what_the_ir_does() {
    if Command::new(COMPILER).arg("--version").output().is_err() {
        eprintln!("skipping: no `{COMPILER}` to compile the pseudo-C with");
        return;
    }
    let fixtures = common::fixtures();
    let prepared = common::in_parallel(&fixtures, |fixture| prepare(fixture));
    let scratch = scratch_dir();
    let results = check(&prepared, &scratch);
    std::fs::remove_dir_all(&scratch).ok();

    let mut excluded: BTreeMap<&str, usize> = BTreeMap::new();
    let mut skipped: BTreeMap<&str, usize> = BTreeMap::new();
    let mut header = String::new();
    let mut lines = Vec::new();
    for (fixture, result) in prepared.iter().zip(&results) {
        for (reason, count) in &fixture.excluded {
            *excluded.entry(reason).or_default() += count;
        }
        for (reason, count) in &result.skipped {
            *skipped.entry(reason).or_default() += count;
        }
        if fixture.candidates.is_empty() {
            continue;
        }
        writeln!(
            header,
            "# {}: {} functions, {} qualify, {} compile, {} do not, {} compared ({} runs), {} differ",
            fixture.name.display(),
            fixture.functions,
            fixture.candidates.len(),
            result.compiled,
            result.failed,
            result.compared,
            result.runs,
            result.differing
        )
        .expect("writing to a String");
        lines.extend(result.lines.iter().cloned());
    }
    let mut actual = String::from("# functions left out:\n");
    for (reason, count) in &excluded {
        writeln!(actual, "#   {reason}: {count}").expect("writing to a String");
    }
    actual.push_str("# runs left out:\n");
    for (reason, count) in &skipped {
        writeln!(actual, "#   {reason}: {count}").expect("writing to a String");
    }
    actual.push_str(&header);
    for line in lines {
        actual.push_str(&line);
        actual.push('\n');
    }
    let path = common::root().join("tests/golden/recompile.txt");
    if let Some(difference) = common::check_expected(&path, &actual) {
        panic!(
            "the recompiled pseudo-C behaves differently from before; fix a new \
             difference, or bless an improvement with VELK_BLESS=1:\n{difference}"
        );
    }
}

/// A fixture's functions that qualify, printed, with their inputs.
struct Fixture {
    name: PathBuf,
    binary: Binary,
    functions: usize,
    excluded: BTreeMap<&'static str, usize>,
    candidates: Vec<Candidate>,
}

struct Candidate {
    label: String,
    ir: FunctionIr,
    code: String,
    params: Vec<String>,
    /// Each trial's argument values, in parameter order.
    inputs: Vec<Vec<u64>>,
}

fn prepare(fixture: &Path) -> Fixture {
    let path = common::fixtures_dir().join(fixture);
    let mut binary = Binary::open(&path).unwrap_or_else(|error| panic!("{error}"));
    let functions: Vec<_> = binary.image().functions.values().cloned().collect();
    let mut excluded: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut candidates = Vec::new();
    for function in &functions {
        if calls(binary.image(), function) {
            *excluded.entry("calls").or_default() += 1;
            continue;
        }
        let Ok(analysis) = binary.analysis(function.addr) else {
            *excluded.entry("does not lift").or_default() += 1;
            continue;
        };
        if let Err(reason) = qualifies(&analysis.ir, analysis.references.is_empty()) {
            *excluded.entry(reason).or_default() += 1;
            continue;
        }
        let ir = analysis.ir.clone();
        let code = binary
            .decompile(function.addr, None)
            .unwrap_or_else(|error| panic!("{error}"));
        let image = binary.image();
        let inputs = (0..trials::TRIALS)
            .map(|trial| {
                let registers = trials::registers(image, trial);
                ir.params
                    .iter()
                    .map(|param| {
                        registers
                            .iter()
                            .find(|(register, _)| *register == param.index)
                            .map_or_else(|| eval::hash(trial, u64::from(param.index)), |r| r.1)
                    })
                    .collect()
            })
            .collect();
        candidates.push(Candidate {
            label: format!(
                "{} {} {}",
                fixture.display(),
                velk::addr::format(function.addr),
                function.name.as_deref().unwrap_or("-")
            ),
            params: ir.params.iter().map(|param| param.ty.to_string()).collect(),
            ir,
            code,
            inputs,
        });
    }
    Fixture {
        name: fixture.to_owned(),
        binary,
        functions: functions.len(),
        excluded,
        candidates,
    }
}

/// Whether the function's code calls another function, which analysis
/// keeps as a call: a quick test that spares analyzing most runtime code.
/// Go's call to grow the stack is not counted, as analysis drops it.
fn calls(image: &Image, function: &velk::loader::Function) -> bool {
    let size = function.size.unwrap_or(velk::analysis::UNKNOWN_SIZE);
    let Ok(blocks) = velk::lift::lift(image, function.addr, size, &Default::default()) else {
        return false;
    };
    blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .any(|stmt| match stmt {
            Stmt::Call { target, .. } => !target.is_some_and(|target| {
                image
                    .functions
                    .get(&target)
                    .and_then(|callee| callee.name.as_deref())
                    .is_some_and(|name| name.starts_with("runtime.morestack"))
            }),
            _ => false,
        })
}

/// Why a function is outside what this test compares, if it is.
fn qualifies(ir: &FunctionIr, no_references: bool) -> Result<(), &'static str> {
    if !integer(&ir.ret_type) {
        return Err(if ir.ret_type == CType::Void {
            "returns nothing"
        } else {
            "returns no integer"
        });
    }
    if !ir.stack_params.is_empty() || ir.variadic {
        return Err("takes arguments on the stack");
    }
    if !ir.params.iter().all(|param| integer(&param.ty)) {
        return Err("takes an argument that is no integer");
    }
    if ir.params.len() > 16 {
        return Err("takes more than 16 arguments");
    }
    if !no_references {
        return Err("refers to data");
    }
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        match stmt {
            Stmt::Store { .. } => return Err("accesses memory"),
            Stmt::Call { .. } => return Err("calls"),
            Stmt::BrIndirect { .. } => return Err("jumps indirectly"),
            Stmt::Unsupported { .. } => return Err("has an unsupported instruction"),
            Stmt::BrifFlags { .. } => return Err("branches on flags"),
            Stmt::Assign { .. }
            | Stmt::Brif { .. }
            | Stmt::Br { .. }
            | Stmt::Switch { .. }
            | Stmt::Ret { .. }
            | Stmt::Trap => {}
        }
        for operand in stmt.operands() {
            pure(operand)?;
        }
    }
    Ok(())
}

fn pure(expr: &Expr) -> Result<(), &'static str> {
    match expr {
        Expr::Reg { .. } | Expr::Const(_) => Ok(()),
        Expr::Load { .. } => Err("accesses memory"),
        Expr::Bin { lhs, rhs, .. } => pure(lhs).and(pure(rhs)),
        Expr::SignExtend { value, .. } => pure(value),
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => pure(lhs).and(pure(rhs)).and(pure(then)).and(pure(els)),
        Expr::Apply { op, args } => match op {
            Operation::CountLeadingZeros(_)
            | Operation::CountTrailingZeros(_)
            | Operation::PopCount(_)
            | Operation::ReverseBits(_)
            | Operation::WideDivide { .. } => args.iter().try_for_each(pure),
            _ => Err("computes on floats or vectors"),
        },
    }
}

fn integer(ty: &CType) -> bool {
    match ty {
        CType::Int { .. } => true,
        CType::Named(name) => {
            !name.contains(['*', '[', '(']) && {
                let words: Vec<&str> = name.split_whitespace().collect();
                !["float", "double", "struct", "union", "class"]
                    .iter()
                    .any(|word| words.contains(word))
            }
        }
        CType::Void | CType::Pointer(_) | CType::Array(_) => false,
    }
}

/// One fixture's counts and the lines it adds to the golden file.
#[derive(Default)]
struct Findings {
    compiled: usize,
    failed: usize,
    compared: usize,
    runs: usize,
    differing: usize,
    skipped: BTreeMap<&'static str, usize>,
    lines: Vec<String>,
}

/// What a run of the compiled code printed.
#[derive(Clone, PartialEq)]
enum Ran {
    Value(u64),
    Other(String),
}

/// A run the interpreter finished: the function, the trial, the
/// arguments as the parameters hold them, and the outcome.
struct Expected {
    function: usize,
    trial: u64,
    arguments: Vec<u64>,
    outcome: Outcome,
}

/// Compiles every fixture's functions into one program per optimization
/// level, which keeps the compiler runs few, and compares their runs with
/// the interpreter's.
fn check(fixtures: &[Fixture], scratch: &Path) -> Vec<Findings> {
    let mut results: Vec<Findings> = fixtures.iter().map(|_| Findings::default()).collect();
    let all: Vec<(usize, &Candidate)> = fixtures
        .iter()
        .enumerate()
        .flat_map(|(index, fixture)| fixture.candidates.iter().map(move |c| (index, c)))
        .collect();
    let candidates: Vec<&Candidate> = all.iter().map(|(_, candidate)| *candidate).collect();
    let (alive, failures) = compiles(&candidates, &scratch.join("check.c"));
    for (index, message) in &failures {
        let (fixture, candidate) = all[*index];
        results[fixture].failed += 1;
        results[fixture]
            .lines
            .push(format!("{}: does not compile: {message}", candidate.label));
    }
    for &index in &alive {
        results[all[index].0].compiled += 1;
    }
    if alive.is_empty() {
        return results;
    }
    let source = program(&candidates, &alive);
    let programs: Vec<PathBuf> = std::thread::scope(|scope| {
        let handles: Vec<_> = LEVELS
            .iter()
            .map(|level| {
                let source = &source;
                scope.spawn(move || build(source, scratch, level))
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("a compiler run"))
            .collect()
    });

    // The arguments as the parameters' types hold them.
    let mut requests = String::new();
    for &index in &alive {
        for input in &candidates[index].inputs {
            requests.push_str(&request('c', index, input));
        }
    }
    let printed = run(&programs[0], &requests);
    let mut canonical = printed.lines().map(|line| {
        line.split_whitespace()
            .map(|word| u64::from_str_radix(word, 16).expect("a hex value"))
            .collect::<Vec<u64>>()
    });
    let mut expected = Vec::new();
    for &index in &alive {
        let (fixture, candidate) = all[index];
        let image = fixtures[fixture].binary.image();
        for trial in 0..trials::TRIALS {
            let arguments = canonical.next().unwrap_or_default();
            // Another function's address differs between the binary and
            // the compiled program.
            if !declared_functions(&candidate.code).is_empty() {
                *results[fixture]
                    .skipped
                    .entry("takes a function's address")
                    .or_default() += 1;
                continue;
            }
            match interpret(image, candidate, trial, &arguments) {
                Ok(outcome) => expected.push(Expected {
                    function: index,
                    trial,
                    arguments,
                    outcome,
                }),
                Err(reason) => *results[fixture].skipped.entry(reason).or_default() += 1,
            }
        }
    }

    let mut requests = String::new();
    for run in &expected {
        requests.push_str(&request('r', run.function, &run.arguments));
    }
    let outputs: Vec<Vec<Ran>> = std::thread::scope(|scope| {
        let handles: Vec<_> = programs
            .iter()
            .map(|program| {
                let (requests, count) = (&requests, expected.len());
                scope.spawn(move || {
                    let mut ran: Vec<Ran> = run(program, requests).lines().map(parse_ran).collect();
                    ran.resize(count, Ran::Other("the program stopped".to_owned()));
                    ran
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("a run"))
            .collect()
    });

    let mut agreeing: BTreeMap<usize, bool> = BTreeMap::new();
    for (position, run) in expected.iter().enumerate() {
        let (fixture, candidate) = all[run.function];
        results[fixture].runs += 1;
        let differing: Vec<(&str, &Ran)> = LEVELS
            .iter()
            .zip(&outputs)
            .map(|(level, ran)| (*level, &ran[position]))
            .filter(|(_, ran)| !agrees(ran, &run.outcome, candidate))
            .collect();
        let same = agreeing.entry(run.function).or_insert(true);
        if differing.is_empty() || !std::mem::replace(same, false) {
            continue;
        }
        let shown: Vec<String> = run
            .arguments
            .iter()
            .map(|value| format!("0x{value:x}"))
            .collect();
        let printed: Vec<String> = differing
            .iter()
            .map(|(level, ran)| format!("{} at {level}", describe(ran, mask(candidate))))
            .collect();
        let wanted = match run.outcome {
            Outcome::Return { value, .. } => format!("0x{:x}", value & mask(candidate)),
            _ => "a trap".to_owned(),
        };
        results[fixture].lines.push(format!(
            "{}: trial {} ({}): pseudo-C gives {}, IR gives {wanted} ({})",
            candidate.label,
            run.trial,
            shown.join(", "),
            printed.join(", "),
            candidate.ir.ret_type
        ));
    }
    for (function, same) in agreeing {
        let fixture = &mut results[all[function].0];
        fixture.compared += 1;
        fixture.differing += usize::from(!same);
    }
    results
}

/// The interpreter's outcome of one trial, or why it cannot tell one.
fn interpret(
    image: &Image,
    candidate: &Candidate,
    trial: u64,
    arguments: &[u64],
) -> Result<Outcome, &'static str> {
    if arguments.len() != candidate.params.len() {
        return Err("the driver gave no arguments");
    }
    let mut registers: Vec<(u16, u64)> = candidate
        .ir
        .params
        .iter()
        .map(|param| param.index)
        .zip(arguments.iter().copied())
        .collect();
    registers.extend(trials::entry_state(image));
    let memory = trials::initial_memory(image);
    let setup = trials::setup(image, trial, &registers, &memory);
    let outcome = eval::run(&candidate.ir, &setup);
    if let Outcome::Unknown(reason) = outcome {
        return Err(reason);
    }
    let reseeded = eval::Setup {
        seed: OTHER_SEED + trial,
        ..trials::setup(image, trial, &registers, &memory)
    };
    if !same_outcome(&outcome, &eval::run(&candidate.ir, &reseeded), candidate) {
        return Err("reads a register that is not a parameter");
    }
    Ok(outcome)
}

fn mask(candidate: &Candidate) -> u64 {
    match trials::return_bits(&candidate.ir.ret_type) {
        Some(bits) if bits < 64 => (1 << bits) - 1,
        _ => u64::MAX,
    }
}

fn same_outcome(a: &Outcome, b: &Outcome, candidate: &Candidate) -> bool {
    match (a, b) {
        (Outcome::Return { value: x, .. }, Outcome::Return { value: y, .. }) => {
            x & mask(candidate) == y & mask(candidate)
        }
        (Outcome::Trap { .. }, Outcome::Trap { .. }) => true,
        _ => false,
    }
}

fn agrees(ran: &Ran, outcome: &Outcome, candidate: &Candidate) -> bool {
    match (ran, outcome) {
        (Ran::Value(value), Outcome::Return { value: wanted, .. }) => {
            value & mask(candidate) == wanted & mask(candidate)
        }
        (Ran::Other(text), Outcome::Trap { .. }) => text == "trap",
        _ => false,
    }
}

fn describe(ran: &Ran, mask: u64) -> String {
    match ran {
        Ran::Value(value) => format!("0x{:x}", value & mask),
        Ran::Other(text) => text.clone(),
    }
}

fn parse_ran(line: &str) -> Ran {
    match line.strip_prefix("v ") {
        Some(hex) => Ran::Value(u64::from_str_radix(hex, 16).expect("a hex value")),
        None => Ran::Other(line.to_owned()),
    }
}

fn request(mode: char, index: usize, arguments: &[u64]) -> String {
    let mut line = format!("{mode} {index} {}", arguments.len());
    for value in arguments {
        write!(line, " {value:x}").expect("writing to a String");
    }
    line.push('\n');
    line
}

/// The functions that compile, and those the compiler rejects with their
/// first error: checking the syntax, dropping the rejected functions, and
/// checking again until the rest pass.
fn compiles(candidates: &[&Candidate], source: &Path) -> (Vec<usize>, BTreeMap<usize, String>) {
    let mut alive: Vec<usize> = (0..candidates.len()).collect();
    let mut failures = BTreeMap::new();
    for _ in 0..COMPILE_ROUNDS {
        let text = program(candidates, &alive);
        std::fs::write(source, &text.text).unwrap_or_else(|error| panic!("{error}"));
        let checked = Command::new(COMPILER)
            .args(FLAGS)
            .args(["-fsyntax-only", "-ferror-limit=0"])
            .arg(source)
            .output()
            .unwrap_or_else(|error| panic!("{COMPILER}: {error}"));
        if checked.status.success() {
            return (alive, failures);
        }
        let errors = String::from_utf8_lossy(&checked.stderr);
        let prefix = format!("{}:", source.display());
        let mut rejected = false;
        for line in errors.lines() {
            let Some(rest) = line.strip_prefix(&prefix) else {
                continue;
            };
            let mut parts = rest.splitn(3, ':');
            let (Some(number), Some(_), Some(message)) = (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            let (Ok(number), Some(message)) = (
                number.parse::<usize>(),
                message.trim().strip_prefix("error: "),
            ) else {
                continue;
            };
            if let Some((index, _)) = text
                .ranges
                .iter()
                .find(|(_, range)| range.contains(&number))
            {
                failures.entry(*index).or_insert_with(|| message.to_owned());
                rejected = true;
            }
        }
        assert!(
            rejected,
            "{COMPILER} rejects the test's own code in {}:\n{errors}",
            source.display()
        );
        alive.retain(|index| !failures.contains_key(index));
    }
    panic!(
        "{COMPILER} still rejects {} after {COMPILE_ROUNDS} rounds",
        source.display()
    );
}

/// The program compiled at `level`.
fn build(source: &Program, scratch: &Path, level: &str) -> PathBuf {
    let path = scratch.join(format!("check{level}.c"));
    let output = scratch.join(format!("check{level}"));
    std::fs::write(&path, &source.text).unwrap_or_else(|error| panic!("{error}"));
    let compiled = Command::new(COMPILER)
        .arg(level)
        .args(FLAGS)
        .arg("-o")
        .arg(&output)
        .arg(&path)
        .output()
        .unwrap_or_else(|error| panic!("{COMPILER}: {error}"));
    assert!(
        compiled.status.success(),
        "{COMPILER} {level} fails on {} after its syntax passed:\n{}",
        path.display(),
        String::from_utf8_lossy(&compiled.stderr)
    );
    output
}

/// A C program's text and the lines each function in it spans.
struct Program {
    text: String,
    ranges: Vec<(usize, std::ops::RangeInclusive<usize>)>,
}

/// The C program holding the functions in `alive`.
fn program(candidates: &[&Candidate], alive: &[usize]) -> Program {
    let mut text = String::from(HEADER);
    let mut ranges = Vec::new();
    let mut line = text.lines().count() + 1;
    for &index in alive {
        let code = renamed(&candidates[index].code, index);
        let lines = code.lines().count();
        ranges.push((index, line..=line + lines - 1));
        line += lines;
        text.push_str(&code);
    }
    // The functions whose address the printed ones take, defined so the
    // program links.
    let declared: std::collections::BTreeSet<&str> = alive
        .iter()
        .flat_map(|&index| declared_functions(&candidates[index].code))
        .collect();
    for name in declared {
        writeln!(text, "void {name}(void) {{}}").expect("writing to a String");
    }
    text.push_str("static uint64_t velk_call(int k, const uint64_t *a) {\n    switch (k) {\n");
    for &index in alive {
        let arguments: Vec<String> = (0..candidates[index].params.len())
            .map(|position| format!("a[{position}]"))
            .collect();
        writeln!(
            text,
            "    case {index}: return (uint64_t)velk_f{index}({});",
            arguments.join(", ")
        )
        .expect("writing to a String");
    }
    text.push_str("    }\n    return 0;\n}\n");
    text.push_str(
        "static void velk_canonical(int k, const uint64_t *a, uint64_t *c) {\n    switch (k) {\n",
    );
    for &index in alive {
        write!(text, "    case {index}:").expect("writing to a String");
        for (position, ty) in candidates[index].params.iter().enumerate() {
            write!(
                text,
                " c[{position}] = (uint64_t)(int64_t)({ty})a[{position}];"
            )
            .expect("writing to a String");
        }
        text.push_str(" break;\n");
    }
    text.push_str("    }\n}\n");
    text.push_str(DRIVER);
    Program { text, ranges }
}

/// The functions the printed code declares ahead of itself, whose address
/// it takes.
fn declared_functions(code: &str) -> Vec<&str> {
    code.lines()
        .filter_map(|line| line.strip_prefix("void ")?.strip_suffix("(void);"))
        .collect()
}

/// The printed function under the name `velk_f<index>`, so names cannot
/// clash with each other or with the C library.
fn renamed(code: &str, index: usize) -> String {
    let mut out = String::new();
    let mut done = false;
    for line in code.lines() {
        if !done
            && !line.starts_with([' ', '/'])
            && line.trim_end().ends_with('{')
            && let Some(open) = line.find('(')
        {
            let start = line[..open]
                .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .map_or(0, |at| at + 1);
            out.push_str(&line[..start]);
            write!(out, "velk_f{index}").expect("writing to a String");
            out.push_str(&line[open..]);
            done = true;
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

/// The program's output for `input`.
fn run(program: &Path, input: &str) -> String {
    let mut child = Command::new(program)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("{}: {error}", program.display()));
    let mut stdin = child.stdin.take().expect("a pipe");
    let input = input.to_owned();
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()).ok());
    let output = child
        .wait_with_output()
        .unwrap_or_else(|error| panic!("{}: {error}", program.display()));
    writer.join().ok();
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn scratch_dir() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("recompile-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap_or_else(|error| panic!("{}: {error}", dir.display()));
    dir
}

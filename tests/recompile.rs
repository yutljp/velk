//! The printed pseudo-C must mean what the IR means. Every fixture function
//! whose optimized IR only computes on integer registers (no memory, calls
//! or globals) is printed, compiled with the system C compiler, and run on
//! the inputs the semantics test uses; its results are compared with the
//! interpreter's. Results are kept in tests/golden/recompile.txt: a new
//! mismatch or compile failure fails, and an improvement is blessed with
//! `VELK_BLESS=1 cargo test --release --test recompile`.
//!
//! A second pass takes the functions that also read and write memory but
//! call nothing. Their pointer arguments point into a region at a fixed
//! address holding the bytes the interpreter's memory holds, and any other
//! page the compiled code touches is mapped and filled the same way when
//! it first faults; the region's bytes after the run are compared too, in
//! tests/golden/recompile_memory.txt.

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
/// The region pointer arguments point into, and its size.
const REGION: u64 = 0x3000_0000_0000;
const REGION_SIZE: u64 = 0x1_0000;

/// Which functions a pass compares: those computing on registers alone, or
/// those reading and writing memory too.
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Registers,
    Memory,
}

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

/// The memory pass's driver: the same requests, `r` taking the trial's
/// seed after the count. Before each run the region holds the bytes the
/// interpreter's memory holds for the seed, and a page the code faults on
/// is mapped and filled the same way; after it, the run prints its result
/// and a checksum of the region.
const MEMORY_DRIVER: &str = r#"
#include <sys/mman.h>
#include <unistd.h>
static sigjmp_buf velk_jump;
static uint64_t velk_seed;
static volatile int velk_unreachable;
static uintptr_t velk_pages[4096];
static int velk_page_count;
static long velk_page;
static uint64_t velk_hash(uint64_t seed, uint64_t key) {
    uint64_t value = seed ^ (key * 0x9e3779b97f4a7c15ULL);
    value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
    value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
    return value ^ (value >> 31);
}
static void velk_fill(uintptr_t start, uint64_t size) {
    for (uint64_t i = 0; i < size; i++) {
        ((volatile uint8_t *)start)[i] = (uint8_t)velk_hash(velk_seed, start + i);
    }
}
static void velk_signal(int sig) { siglongjmp(velk_jump, sig); }
static void velk_fault(int sig, siginfo_t *info, void *context) {
    (void)context;
    uintptr_t page = (uintptr_t)info->si_addr & ~(uintptr_t)(velk_page - 1);
    if (velk_page_count < 4096 && page >= 0x100000) {
        void *mapped = mmap((void *)page, velk_page, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANON, -1, 0);
        if (mapped == (void *)page) {
            velk_pages[velk_page_count++] = page;
            velk_fill(page, velk_page);
            return;
        }
        if (mapped != MAP_FAILED) {
            munmap(mapped, velk_page);
        }
    }
    velk_unreachable = 1;
    siglongjmp(velk_jump, sig);
}
static void velk_timer(long usec) {
    struct itimerval timer = {{0, 0}, {0, usec}};
    setitimer(ITIMER_REAL, &timer, 0);
}
int main(void) {
    velk_page = getpagesize();
    void *region = mmap((void *)REGION_START, REGION_BYTES, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANON, -1, 0);
    if (region != (void *)REGION_START) {
        return 2;
    }
    int signals[] = {SIGILL, SIGTRAP, SIGFPE, SIGALRM};
    for (unsigned i = 0; i < sizeof signals / sizeof *signals; i++) {
        struct sigaction action = {0};
        action.sa_handler = velk_signal;
        sigaction(signals[i], &action, 0);
    }
    int faults[] = {SIGSEGV, SIGBUS};
    for (unsigned i = 0; i < sizeof faults / sizeof *faults; i++) {
        struct sigaction action = {0};
        action.sa_sigaction = velk_fault;
        action.sa_flags = SA_SIGINFO | SA_NODEFER;
        sigaction(faults[i], &action, 0);
    }
    char mode;
    int k, n;
    while (scanf(" %c %d %d", &mode, &k, &n) == 3) {
        uint64_t a[16] = {0}, c[16] = {0};
        if (mode == 'r') {
            scanf("%" SCNx64, &velk_seed);
        }
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
        while (velk_page_count > 0) {
            munmap((void *)velk_pages[--velk_page_count], velk_page);
        }
        velk_fill(REGION_START, REGION_BYTES);
        velk_unreachable = 0;
        int sig = sigsetjmp(velk_jump, 1);
        if (sig == 0) {
            velk_timer(200000);
            uint64_t r = velk_call(k, a);
            velk_timer(0);
            uint64_t sum = 0xcbf29ce484222325ULL;
            for (uint64_t i = 0; i < REGION_BYTES; i++) {
                sum = (sum ^ ((volatile uint8_t *)REGION_START)[i]) * 0x100000001b3ULL;
            }
            printf("v %" PRIx64 " %" PRIx64 "\n", r, sum);
        } else {
            velk_timer(0);
            if (velk_unreachable) {
                printf("unreachable\n");
            } else if (sig == SIGILL || sig == SIGTRAP) {
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
    compare(Mode::Registers, "tests/golden/recompile.txt");
}

#[test]
fn printed_code_reads_and_writes_memory_as_the_ir_does() {
    compare(Mode::Memory, "tests/golden/recompile_memory.txt");
}

fn compare(mode: Mode, golden: &str) {
    if Command::new(COMPILER).arg("--version").output().is_err() {
        eprintln!("skipping: no `{COMPILER}` to compile the pseudo-C with");
        return;
    }
    let fixtures = common::fixtures();
    let prepared = common::in_parallel(&fixtures, |fixture| prepare(fixture, mode));
    let scratch = scratch_dir(mode);
    let results = check(&prepared, &scratch, mode);
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
    let path = common::root().join(golden);
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
    /// It returns nothing, so only its effects compare.
    void: bool,
}

fn prepare(fixture: &Path, mode: Mode) -> Fixture {
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
        if let Err(reason) = qualifies(&analysis.ir, analysis.references.is_empty(), mode) {
            *excluded.entry(reason).or_default() += 1;
            continue;
        }
        let ir = analysis.ir.clone();
        let code = binary
            .decompile(function.addr, None)
            .unwrap_or_else(|error| panic!("{error}"));
        // The printed code reads such a register uninitialized, which C
        // leaves undefined.
        if code.lines().any(|line| {
            line.strip_prefix("    uint64_t ")
                .and_then(|rest| rest.strip_suffix(';'))
                .is_some_and(machine_register)
        }) {
            *excluded
                .entry("reads a register that is not a parameter")
                .or_default() += 1;
            continue;
        }
        let image = binary.image();
        let inputs = (0..trials::TRIALS)
            .map(|trial| {
                let registers = trials::registers(image, trial);
                ir.params
                    .iter()
                    .enumerate()
                    .map(|(position, param)| {
                        // A pointer points into the region, each its own part.
                        if param.ty.is_pointer() {
                            return REGION + 0x2000 + 0x2000 * (position as u64 % 6);
                        }
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
            void: ir.ret_type == CType::Void,
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
fn qualifies(ir: &FunctionIr, no_references: bool, mode: Mode) -> Result<(), &'static str> {
    let memory = mode == Mode::Memory;
    let value = |ty: &CType| integer(ty) || (memory && ty.is_pointer());
    if !value(&ir.ret_type) && !(memory && ir.ret_type == CType::Void) {
        return Err(if ir.ret_type == CType::Void {
            "returns nothing"
        } else {
            "returns no integer"
        });
    }
    if !ir.stack_params.is_empty() || ir.variadic {
        return Err("takes arguments on the stack");
    }
    if !ir.params.iter().all(|param| value(&param.ty)) {
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
            Stmt::Store { .. } if !memory => return Err("accesses memory"),
            Stmt::Store { .. } => {}
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
            pure(operand, memory)?;
        }
    }
    // The other pass takes what this one leaves to memory.
    if memory
        && !ir
            .blocks
            .iter()
            .flat_map(|block| &block.stmts)
            .any(touches_memory)
    {
        return Err("computes on registers alone");
    }
    Ok(())
}

fn touches_memory(stmt: &Stmt) -> bool {
    fn loads(expr: &Expr) -> bool {
        match expr {
            Expr::Load { .. } => true,
            Expr::Reg { .. } | Expr::Const(_) => false,
            Expr::Bin { lhs, rhs, .. } => loads(lhs) || loads(rhs),
            Expr::SignExtend { value, .. } => loads(value),
            Expr::Select {
                lhs,
                rhs,
                then,
                els,
                ..
            } => loads(lhs) || loads(rhs) || loads(then) || loads(els),
            Expr::Apply { args, .. } => args.iter().any(loads),
        }
    }
    matches!(stmt, Stmt::Store { .. }) || stmt.operands().into_iter().any(loads)
}

fn pure(expr: &Expr, memory: bool) -> Result<(), &'static str> {
    match expr {
        Expr::Reg { .. } | Expr::Const(_) => Ok(()),
        Expr::Load { addr, .. } if memory => pure(addr, memory),
        Expr::Load { .. } => Err("accesses memory"),
        Expr::Bin { lhs, rhs, .. } => pure(lhs, memory).and(pure(rhs, memory)),
        Expr::SignExtend { value, .. } => pure(value, memory),
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => pure(lhs, memory)
            .and(pure(rhs, memory))
            .and(pure(then, memory))
            .and(pure(els, memory)),
        Expr::Apply { op, args } => match op {
            Operation::CountLeadingZeros(_)
            | Operation::CountTrailingZeros(_)
            | Operation::PopCount(_)
            | Operation::ReverseBits(_)
            | Operation::WideDivide { .. } => args.iter().try_for_each(|arg| pure(arg, memory)),
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
    /// The result, and the region's checksum after the run in the memory
    /// pass.
    Value(u64, Option<u64>),
    Other(String),
}

/// A run the interpreter finished: the function, the trial, the
/// arguments as the parameters hold them, and the outcome.
struct Expected {
    function: usize,
    trial: u64,
    arguments: Vec<u64>,
    outcome: Outcome,
    /// The region's checksum after the run, in the memory pass.
    checksum: Option<u64>,
}

/// Compiles every fixture's functions into one program per optimization
/// level, which keeps the compiler runs few, and compares their runs with
/// the interpreter's.
fn check(fixtures: &[Fixture], scratch: &Path, mode: Mode) -> Vec<Findings> {
    let mut results: Vec<Findings> = fixtures.iter().map(|_| Findings::default()).collect();
    let all: Vec<(usize, &Candidate)> = fixtures
        .iter()
        .enumerate()
        .flat_map(|(index, fixture)| fixture.candidates.iter().map(move |c| (index, c)))
        .collect();
    let candidates: Vec<&Candidate> = all.iter().map(|(_, candidate)| *candidate).collect();
    let (alive, failures) = compiles(&candidates, &scratch.join("check.c"), mode);
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
    let source = program(&candidates, &alive, mode);
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
            match interpret(image, candidate, trial, &arguments, mode) {
                Ok(outcome) => expected.push(Expected {
                    function: index,
                    trial,
                    arguments,
                    checksum: (mode == Mode::Memory).then(|| region_checksum(&outcome, trial)),
                    outcome,
                }),
                Err(reason) => *results[fixture].skipped.entry(reason).or_default() += 1,
            }
        }
    }

    let mut requests = String::new();
    for run in &expected {
        let seed = (mode == Mode::Memory).then_some(run.trial);
        requests.push_str(&request_run(run.function, seed, &run.arguments));
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
        // An address no page can be mapped at, as one past the 48 bits of
        // addresses, leaves the compiled code nothing to read there.
        if outputs
            .iter()
            .any(|ran| ran[position] == Ran::Other("unreachable".to_owned()))
        {
            *results[fixture]
                .skipped
                .entry("reaches memory no page can map")
                .or_default() += 1;
            continue;
        }
        results[fixture].runs += 1;
        let differing: Vec<(&str, &Ran)> = LEVELS
            .iter()
            .zip(&outputs)
            .map(|(level, ran)| (*level, &ran[position]))
            .filter(|(_, ran)| !agrees(ran, run, candidate))
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
        let wanted = match (&run.outcome, run.checksum) {
            (Outcome::Return { value, .. }, None) => format!("0x{:x}", value & mask(candidate)),
            (Outcome::Return { value, .. }, Some(sum)) => {
                format!("0x{:x} and memory {sum:x}", value & mask(candidate))
            }
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
    mode: Mode,
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
    let mut memory = trials::initial_memory(image);
    // The region holds what the trial's seed hashes, whatever seed reads
    // the rest, so a second seed tells registers apart and not memory.
    if mode == Mode::Memory {
        memory.extend((REGION..REGION + REGION_SIZE).step_by(8).map(|addr| {
            let word = (0..8).fold(0, |word, byte| {
                word | (eval::hash(trial, addr + byte) & 0xff) << (8 * byte)
            });
            (addr, word)
        }));
    }
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

fn agrees(ran: &Ran, run: &Expected, candidate: &Candidate) -> bool {
    match (ran, &run.outcome) {
        (Ran::Value(value, sum), Outcome::Return { value: wanted, .. }) => {
            (candidate.void || value & mask(candidate) == wanted & mask(candidate))
                && *sum == run.checksum
        }
        (Ran::Other(text), Outcome::Trap { .. }) => text == "trap",
        _ => false,
    }
}

fn describe(ran: &Ran, mask: u64) -> String {
    match ran {
        Ran::Value(value, None) => format!("0x{:x}", value & mask),
        Ran::Value(value, Some(sum)) => format!("0x{:x} and memory {sum:x}", value & mask),
        Ran::Other(text) => text.clone(),
    }
}

fn parse_ran(line: &str) -> Ran {
    match line.strip_prefix("v ") {
        Some(words) => {
            let mut words = words
                .split_whitespace()
                .map(|word| u64::from_str_radix(word, 16).expect("a hex value"));
            let value = words.next().expect("a value");
            Ran::Value(value, words.next())
        }
        None => Ran::Other(line.to_owned()),
    }
}

/// The checksum the driver prints of the region after a run: FNV-1a over
/// its bytes, as the run leaves them.
fn region_checksum(outcome: &Outcome, trial: u64) -> u64 {
    let memory = match outcome {
        Outcome::Return { memory, .. } | Outcome::Trap { memory, .. } => memory,
        Outcome::Unknown(_) => return 0,
    };
    (REGION..REGION + REGION_SIZE).fold(0xcbf2_9ce4_8422_2325, |sum, addr| {
        let byte = memory
            .get(&addr)
            .copied()
            .unwrap_or(eval::hash(trial, addr) as u8);
        (sum ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3)
    })
}

/// A run request, with the trial's seed in the memory pass.
fn request_run(index: usize, seed: Option<u64>, arguments: &[u64]) -> String {
    let mut line = format!("r {index} {}", arguments.len());
    if let Some(seed) = seed {
        write!(line, " {seed:x}").expect("writing to a String");
    }
    for value in arguments {
        write!(line, " {value:x}").expect("writing to a String");
    }
    line.push('\n');
    line
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
fn compiles(
    candidates: &[&Candidate],
    source: &Path,
    mode: Mode,
) -> (Vec<usize>, BTreeMap<usize, String>) {
    let mut alive: Vec<usize> = (0..candidates.len()).collect();
    let mut failures = BTreeMap::new();
    for _ in 0..COMPILE_ROUNDS {
        let text = program(candidates, &alive, mode);
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
fn program(candidates: &[&Candidate], alive: &[usize], mode: Mode) -> Program {
    let mut text = String::from(HEADER);
    if mode == Mode::Memory {
        writeln!(
            text,
            "#define REGION_START 0x{REGION:x}ULL\n#define REGION_BYTES 0x{REGION_SIZE:x}ULL"
        )
        .expect("writing to a String");
    }
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
        let candidate = candidates[index];
        // The memory pass passes pointers, converted to their types.
        let arguments: Vec<String> = candidate
            .params
            .iter()
            .enumerate()
            .map(|(position, ty)| match mode {
                Mode::Registers => format!("a[{position}]"),
                Mode::Memory => format!("({ty})a[{position}]"),
            })
            .collect();
        let call = format!("velk_f{index}({})", arguments.join(", "));
        if candidate.void {
            writeln!(text, "    case {index}: {call}; return 0;")
        } else {
            writeln!(text, "    case {index}: return (uint64_t){call};")
        }
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
    text.push_str(match mode {
        Mode::Registers => DRIVER,
        Mode::Memory => MEMORY_DRIVER,
    });
    Program { text, ranges }
}

/// Whether `name` is a machine register's, as the printed code names one
/// it reads on entry.
fn machine_register(name: &str) -> bool {
    matches!(
        name,
        "g" | "rax" | "rbx" | "rcx" | "rdx" | "rsi" | "rdi" | "rbp"
    ) || name
        .strip_prefix(['r', 'x', 'w'])
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
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
    // Each function's own structures are its own, whatever another names
    // the same.
    let mut code = code.to_owned();
    let defined: Vec<String> = code
        .lines()
        .filter_map(|line| {
            let tag = line.strip_prefix("struct ")?.split_once(" {")?.0;
            Some(tag.to_owned())
        })
        .collect();
    for tag in defined {
        let from = format!("struct {tag}");
        let mut out = String::new();
        let mut rest = code.as_str();
        while let Some(at) = rest.find(&from) {
            let after = &rest[at + from.len()..];
            out.push_str(&rest[..at]);
            out.push_str(&from);
            if !after.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
                write!(out, "_k{index}").expect("writing to a String");
            }
            rest = after;
        }
        out.push_str(rest);
        code = out;
    }
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

fn scratch_dir(mode: Mode) -> PathBuf {
    let pass = match mode {
        Mode::Registers => "registers",
        Mode::Memory => "memory",
    };
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("recompile-{}-{pass}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap_or_else(|error| panic!("{}: {error}", dir.display()));
    dir
}

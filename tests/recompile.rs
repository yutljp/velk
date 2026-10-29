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
//! `tests/golden/recompile_memory.txt`, or `recompile_memory_x86_64_linux.txt`
//! on x86-64 Linux, to keep the exact run counts for each host.
//!
//! Compiler and driver results for batches of at most 32 functions are cached
//! under target/recompile-cache; IR expectations share the cache. Comparisons are recomputed.
//! Batches run in parallel, with results collected in fixture and batch order.
//! Set `VELK_RECOMPILE_NO_CACHE=1` to compile and run every batch again.

#[path = "recompile/arm64_results.rs"]
mod arm64_results;
#[path = "recompile/atomic_layouts.rs"]
mod atomic_layouts;
#[path = "recompile/atomic_spelling.rs"]
mod atomic_spelling;
#[path = "recompile/atomic_values.rs"]
mod atomic_values;
#[path = "recompile/body_types.rs"]
mod body_types;
#[path = "recompile/cache.rs"]
mod cache;
#[path = "recompile/call_arithmetic.rs"]
mod call_arithmetic;
#[path = "recompile/compile_fail.rs"]
mod compile_fail;

#[path = "recompile/constant_spills.rs"]
mod constant_spills;
#[path = "recompile/constants.rs"]
mod constants;
#[path = "recompile/counted_loops.rs"]
mod counted_loops;

#[path = "recompile/casts.rs"]
mod casts;
mod common;
#[path = "recompile/debug_locals.rs"]
mod debug_locals;
#[path = "recompile/division.rs"]
mod division;
#[path = "recompile/forward_exits.rs"]
mod forward_exits;
#[path = "recompile/forwarding.rs"]
mod forwarding;
#[path = "recompile/frame_arrays.rs"]
mod frame_arrays;
#[path = "recompile/frame_values.rs"]
mod frame_values;
#[path = "recompile/go_locals.rs"]
mod go_locals;
#[path = "recompile/go_runtime.rs"]
mod go_runtime;
#[path = "recompile/go_stack.rs"]
mod go_stack;
#[path = "recompile/go_values.rs"]
mod go_values;
#[path = "recompile/identical_exits.rs"]
mod identical_exits;
#[path = "recompile/ignored_result.rs"]
mod ignored_result;
#[path = "recompile/initializers.rs"]
mod initializers;
#[path = "recompile/integer_storage.rs"]
mod integer_storage;
#[path = "recompile/local_expressions.rs"]
mod local_expressions;
#[path = "recompile/long_branches.rs"]
mod long_branches;
#[path = "recompile/memory_driver.rs"]
mod memory_driver;

#[path = "recompile/bit_counts.rs"]
mod bit_counts;
#[path = "recompile/com.rs"]
mod com;
#[path = "recompile/crackmes.rs"]
mod crackmes;
#[path = "recompile/main_signatures.rs"]
mod main_signatures;
#[path = "recompile/pe.rs"]
mod pe;
#[path = "recompile/physical_stack.rs"]
#[allow(
    clippy::unwrap_used,
    reason = "Test bodies are called by root test entry points to preserve their names."
)]
mod physical_stack;
#[path = "recompile/pointer_assignments.rs"]
mod pointer_assignments;
#[path = "recompile/prelude.rs"]
mod prelude;
#[path = "recompile/record_transfers.rs"]
mod record_transfers;
#[path = "recompile/register_locals.rs"]
mod register_locals;
#[path = "recompile/saved_registers.rs"]
mod saved_registers;
#[path = "recompile/scaled_registers.rs"]
mod scaled_registers;
#[path = "recompile/short_circuit.rs"]
#[allow(
    clippy::unwrap_used,
    reason = "Test bodies are called by root test entry points to preserve their names."
)]
mod short_circuit;
#[path = "recompile/stack_arrays.rs"]
mod stack_arrays;
#[path = "recompile/switches.rs"]
mod switches;
#[path = "recompile/syntax.rs"]
mod syntax;
#[path = "recompile/type_library.rs"]
mod type_library;
#[path = "recompile/unsupported.rs"]
mod unsupported;
#[path = "recompile/vector_values.rs"]
mod vector_values;
#[path = "recompile/virtual_calls.rs"]
mod virtual_calls;
#[path = "recompile/x64_flags.rs"]
mod x64_flags;
#[path = "recompile/x64_half_moves.rs"]
mod x64_half_moves;
#[path = "recompile/x64_inputs.rs"]
mod x64_inputs;

use physical_stack::{incoming_stack_word, physical_stack_call, physical_stack_signature};
use short_circuit::{SC_COUNTER, SC_RIGHT, sc_ir, sc_load, sc_store};

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

use velk::ir::eval::{self, Outcome};
use velk::ir::{
    AbiLocation, AbiPiece, AbiProfile, Access, BinOp, Block, CType, Cond, Convention,
    DeclaredSignature, Definition, Expr, FunctionIr, Member, Operation, Param, Passing, Precision,
    RegisterClass, SignatureAbi, Stmt, ValueAbi, trials,
};
use velk::loader::{Image, Isa};
use velk::render::{SegmentBase, SegmentBaseRead};
use velk::service::Binary;

thread_local! {
    static COMPILATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn compiler() -> PathBuf {
    std::env::var_os("VELK_TEST_CC")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("clang"))
}
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
const FRAME_BASE: u64 = 0x3100_0000_0000;

fn region_start(isa: Isa) -> u64 {
    if velk::arch::pointer_bytes(isa) == 4 {
        0x3000_0000
    } else {
        REGION
    }
}

fn frame_base(isa: Isa) -> u64 {
    if velk::arch::pointer_bytes(isa) == 4 {
        0x3100_0000
    } else {
        FRAME_BASE
    }
}

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
#include <math.h>
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
static long velk_page_size;
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
    // Page allocation and initialization are harness work, not execution.
    struct itimerval stopped = {0}, remaining;
    setitimer(ITIMER_VIRTUAL, &stopped, &remaining);
    uintptr_t page = (uintptr_t)info->si_addr & ~(uintptr_t)(velk_page_size - 1);
    if (velk_page_count < 4096 && page >= 0x100000) {
        void *mapped = mmap((void *)page, velk_page_size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANON, -1, 0);
        if (mapped == (void *)page) {
            velk_pages[velk_page_count++] = page;
            velk_fill(page, velk_page_size);
            velk_fixture_overlay(page, velk_page_size);
            setitimer(ITIMER_VIRTUAL, &remaining, 0);
            return;
        }
        if (mapped != MAP_FAILED) {
            munmap(mapped, velk_page_size);
        }
    }
    velk_unreachable = 1;
    siglongjmp(velk_jump, sig);
}
static void velk_timer(long usec) {
    struct itimerval timer = {{0, 0}, {0, usec}};
    setitimer(ITIMER_VIRTUAL, &timer, 0);
}
int main(void) {
    velk_page_size = getpagesize();
    void *region = mmap((void *)REGION_START, REGION_BYTES, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANON, -1, 0);
    if (region != (void *)REGION_START) {
        return 2;
    }
    int signals[] = {SIGILL, SIGTRAP, SIGFPE, SIGVTALRM};
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
        sigaddset(&action.sa_mask, SIGVTALRM);
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
            munmap((void *)velk_pages[--velk_page_count], velk_page_size);
        }
        velk_fill(REGION_START, REGION_BYTES);
        velk_unreachable = 0;
        int sig = sigsetjmp(velk_jump, 1);
        if (sig == 0) {
            velk_prepare(k, velk_seed);
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
            } else if (sig == SIGVTALRM) {
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
    let golden = if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "tests/golden/recompile_memory_x86_64_linux.txt"
    } else {
        "tests/golden/recompile_memory.txt"
    };
    compare(Mode::Memory, golden);
}

#[test]
fn printed_global_views_preserve_addresses_and_memory() {
    assert!(
        Command::new(compiler())
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success()),
        "{} is required to check global memory accesses",
        compiler().display()
    );
    let address = REGION + 0x1000;
    let load = |addr, width, signed| Expr::Load {
        addr: Box::new(addr),
        width,
        signed,
    };
    let store = |addr, width, value| Stmt::Store {
        addr,
        width,
        value,
        at: None,
    };
    let mut cases = vec![
        (
            "unsigned_read".to_owned(),
            Vec::new(),
            vec![Stmt::Ret {
                value: load(Expr::Const(address), 8, false),
                at: None,
            }],
            CType::U64,
        ),
        (
            "shared_symbol".to_owned(),
            Vec::new(),
            vec![
                store(Expr::Const(address), 8, Expr::Const(0x1234)),
                Stmt::Ret {
                    value: load(Expr::Const(address), 8, false),
                    at: None,
                },
            ],
            CType::U64,
        ),
    ];
    for width in [1, 2, 4, 8] {
        cases.push((
            format!("signed_{}", width * 8),
            Vec::new(),
            vec![
                store(
                    Expr::Const(address),
                    width,
                    Expr::Const((1 << (width * 8 - 1)) | 5),
                ),
                Stmt::Ret {
                    value: load(Expr::Const(address), width, true),
                    at: None,
                },
            ],
            CType::U64,
        ));
    }
    for (name, op, read_width, signed, write_width, rhs) in [
        ("sar_unsigned_byte", BinOp::Sar, 1, false, 1, 1),
        ("sar_signed_word", BinOp::Sar, 4, true, 4, 1),
        ("shr_signed_word", BinOp::Shr, 4, true, 4, 1),
        ("widening_add", BinOp::Add, 1, false, 8, 1),
        ("narrowing_shift", BinOp::Shr, 8, false, 1, 8),
    ] {
        cases.push((
            name.to_owned(),
            Vec::new(),
            vec![
                store(Expr::Const(address), 8, Expr::Const(0xfedc_ba98_8765_4385)),
                store(
                    Expr::Const(address),
                    write_width,
                    Expr::bin(
                        op,
                        load(Expr::Const(address), read_width, signed),
                        Expr::Const(rhs),
                    ),
                ),
                Stmt::Ret {
                    value: load(Expr::Const(address), 8, false),
                    at: None,
                },
            ],
            CType::U64,
        ));
    }
    for (name, precision, width, store_width, initial, increment) in [
        (
            "float32_bits",
            Precision::Single,
            4,
            4,
            u64::from(1.25_f32.to_bits()),
            u64::from(2.5_f32.to_bits()),
        ),
        (
            "float64_bits",
            Precision::Double,
            8,
            8,
            1.25_f64.to_bits(),
            2.5_f64.to_bits(),
        ),
        (
            "float32_wide_store",
            Precision::Single,
            4,
            8,
            u64::from(1.25_f32.to_bits()),
            u64::from(2.5_f32.to_bits()),
        ),
        (
            "float64_narrow_store",
            Precision::Double,
            8,
            4,
            1.25_f64.to_bits(),
            2.5_f64.to_bits(),
        ),
    ] {
        cases.push((
            name.to_owned(),
            Vec::new(),
            vec![
                store(Expr::Const(address), width, Expr::Const(initial)),
                store(
                    Expr::Const(address),
                    store_width,
                    Expr::apply(
                        Operation::FloatAdd(precision),
                        vec![
                            load(Expr::Const(address), width, false),
                            Expr::Const(increment),
                        ],
                    ),
                ),
                Stmt::Ret {
                    value: load(Expr::Const(address), 8, false),
                    at: None,
                },
            ],
            CType::U64,
        ));
    }
    let parameter = |name: &str| Param {
        index: 7,
        name: name.to_owned(),
        ty: CType::U64,
    };
    let indexed = Expr::bin(
        BinOp::Add,
        Expr::Const(address),
        Expr::bin(BinOp::Shl, Expr::reg(7, 64), Expr::Const(2)),
    );
    cases.extend([
        (
            "table_read".to_owned(),
            vec![parameter("index")],
            vec![Stmt::Ret {
                value: load(indexed.clone(), 4, false),
                at: None,
            }],
            CType::U64,
        ),
        (
            "table_write".to_owned(),
            vec![parameter("index")],
            vec![
                store(indexed.clone(), 4, Expr::Const(0x8123_4567)),
                Stmt::Ret {
                    value: load(indexed, 4, false),
                    at: None,
                },
            ],
            CType::U64,
        ),
        (
            "overlapping_views".to_owned(),
            Vec::new(),
            vec![
                store(Expr::Const(address), 8, Expr::Const(0x0123_4567_89ab_cdef)),
                store(Expr::Const(address), 1, Expr::Const(0x80)),
                store(Expr::Const(address + 2), 2, Expr::Const(0xdead)),
                Stmt::Ret {
                    value: load(Expr::Const(address), 8, false),
                    at: None,
                },
            ],
            CType::U64,
        ),
        (
            "parameter_collision".to_owned(),
            vec![parameter("counter")],
            vec![Stmt::Ret {
                value: Expr::bin(
                    BinOp::Xor,
                    load(Expr::Const(address), 8, false),
                    Expr::reg(7, 64),
                ),
                at: None,
            }],
            CType::U64,
        ),
        (
            "integer_address".to_owned(),
            Vec::new(),
            vec![Stmt::Ret {
                value: Expr::Const(address),
                at: None,
            }],
            CType::U64,
        ),
        (
            "pointer_address".to_owned(),
            Vec::new(),
            vec![Stmt::Ret {
                value: Expr::Const(address),
                at: None,
            }],
            CType::Pointer(Box::new(CType::Int {
                bytes: 1,
                signed: false,
            })),
        ),
        (
            "word_pointer_address".to_owned(),
            Vec::new(),
            vec![Stmt::Ret {
                value: Expr::Const(address),
                at: None,
            }],
            CType::Pointer(Box::new(CType::Int {
                bytes: 4,
                signed: false,
            })),
        ),
        (
            "pointer_slot".to_owned(),
            Vec::new(),
            vec![
                store(Expr::Const(address), 8, Expr::Const(address + 0x100)),
                store(Expr::Const(address + 0x100), 1, Expr::Const(0xa5)),
                Stmt::Ret {
                    value: load(load(Expr::Const(address), 8, false), 1, false),
                    at: None,
                },
            ],
            CType::U64,
        ),
    ]);
    let symbols = velk::render::Symbols {
        data: [(address, "counter".to_owned())].into(),
        ..Default::default()
    };
    let candidates = cases
        .into_iter()
        .map(|(name, params, stmts, ret_type)| {
            let ir = synthetic_ir(&name, params, ret_type, stmts);
            Candidate {
                marshalling: None,
                label: name,
                segment_bases: Vec::new(),
                states: Vec::new(),
                code: velk::render::render(&ir, &[], &symbols, &[(REGION, REGION_SIZE)]),
                params: ir.params.iter().map(|param| param.ty.to_string()).collect(),
                inputs: (0..trials::TRIALS)
                    .map(|trial| ir.params.iter().map(|_| trial).collect())
                    .collect(),
                void: false,
                ir,
            }
        })
        .collect::<Vec<_>>();
    check_candidates("globals", candidates, Mode::Memory, &[]);
}

#[test]
fn printed_members_preserve_declared_types_and_access_widths() {
    let address = |offset| Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(offset));
    let load = |offset, width, signed| Expr::Load {
        addr: Box::new(address(offset)),
        width,
        signed,
    };
    let store = |offset, width, value| Stmt::Store {
        addr: address(offset),
        width,
        value,
        at: None,
    };
    let mut cases = Vec::new();
    let mut case = |name: &str, mut stmts: Vec<Stmt>, value: Expr| {
        stmts.push(Stmt::Ret { value, at: None });
        cases.push((name.to_owned(), stmts));
    };
    case("adjacent_fields", Vec::new(), load(0, 8, false));
    for (name, offset, width) in [("partial_byte", 8, 1), ("partial_word", 10, 2)] {
        case(
            name,
            vec![
                store(8, 8, Expr::Const(0x0123_4567_89ab_cdef)),
                store(offset, width, Expr::Const(0xbeef)),
            ],
            load(8, 8, false),
        );
    }
    for (name, offset, signed) in [
        ("unsigned_from_signed", 16, false),
        ("signed_from_signed", 16, true),
        ("signed_from_unsigned", 20, true),
    ] {
        case(
            name,
            vec![store(offset, 4, Expr::Const(0x8123_4567))],
            load(offset, 4, signed),
        );
    }
    case(
        "pointer_integer_bits",
        vec![store(24, 8, Expr::Const(REGION + 0x4000))],
        Expr::bin(BinOp::Xor, load(24, 8, false), Expr::Const(0x55)),
    );
    case(
        "pointer_byte_arithmetic",
        vec![store(24, 8, Expr::Const(REGION + 0x4000))],
        Expr::bin(BinOp::Add, load(24, 8, false), Expr::Const(1)),
    );
    for (name, value) in [
        ("pointer_integer_store", Expr::Const(0x8123_4567)),
        ("pointer_null_store", Expr::Const(0)),
        ("pointer_value_store", Expr::reg(6, 64)),
    ] {
        case(name, vec![store(24, 8, value)], load(24, 8, false));
    }
    case(
        "pointer_partial_store",
        vec![
            store(24, 8, Expr::Const(REGION + 0x4000)),
            store(25, 1, Expr::Const(0x80)),
        ],
        load(24, 8, false),
    );
    case(
        "pointer_partial_read",
        vec![store(24, 8, Expr::Const(REGION + 0x4234))],
        load(24, 4, false),
    );
    case(
        "float_integer_read",
        vec![store(32, 4, Expr::Const(u64::from(1.25_f32.to_bits())))],
        load(32, 4, false),
    );
    case(
        "float_integer_write",
        vec![store(32, 4, Expr::reg(0, 32))],
        load(32, 4, false),
    );
    case(
        "float_add_store",
        vec![
            store(32, 4, Expr::Const(u64::from(1.25_f32.to_bits()))),
            store(
                32,
                4,
                Expr::apply(
                    Operation::FloatAdd(Precision::Single),
                    vec![
                        load(32, 4, false),
                        Expr::Const(u64::from(2.5_f32.to_bits())),
                    ],
                ),
            ),
        ],
        load(32, 4, false),
    );
    for (name, offset, width, precision) in [
        ("wide_float32_bits", 8, 8, Precision::Single),
        ("wide_float64_bits", 8, 8, Precision::Double),
        ("float_narrow_double_bits", 32, 4, Precision::Double),
        ("unknown_float32_bits", 56, 8, Precision::Single),
    ] {
        let (first, second) = match precision {
            Precision::Single => (u64::from(1.25_f32.to_bits()), u64::from(2.5_f32.to_bits())),
            Precision::Double => (1.1_f64.to_bits(), 2.2_f64.to_bits()),
        };
        case(
            name,
            vec![store(
                offset,
                width,
                Expr::apply(
                    Operation::FloatAdd(precision),
                    vec![Expr::Const(first), Expr::Const(second)],
                ),
            )],
            load(offset, width, false),
        );
    }
    case(
        "boolean_raw_byte",
        vec![store(36, 1, Expr::Const(2))],
        load(36, 1, false),
    );
    for (name, offset) in [
        ("array_raw_storage", 40),
        ("aggregate_raw_storage", 48),
        ("unknown_raw_storage", 56),
    ] {
        case(
            name,
            vec![store(offset, 8, Expr::Const(0x8123_4567_89ab_cdef))],
            load(offset, 8, false),
        );
    }
    let fields = vec![
        (0, "lo", CType::U32, 4),
        (4, "hi", CType::U32, 4),
        (8, "wide", CType::U64, 8),
        (16, "signed_value", CType::I32, 4),
        (20, "unsigned_value", CType::U32, 4),
        (24, "pointer", CType::pointer_to(CType::U32), 8),
        (32, "sample", CType::Named("float".to_owned()), 4),
        (36, "flag", CType::Named("bool".to_owned()), 1),
        (40, "array", CType::Array(Box::new(CType::U32)), 8),
        (48, "aggregate", CType::Named("struct pair".to_owned()), 8),
        (56, "unknown", CType::Void, 8),
    ];
    let candidates = cases
        .into_iter()
        .map(|(name, stmts)| {
            let mut ir = synthetic_ir(
                &name,
                vec![
                    Param {
                        index: 7,
                        name: "record".to_owned(),
                        ty: CType::pointer_to(CType::Named("struct record".to_owned())),
                    },
                    Param {
                        index: 6,
                        name: "target".to_owned(),
                        ty: CType::pointer_to(CType::int(1, false)),
                    },
                    Param {
                        index: 0,
                        name: "bits".to_owned(),
                        ty: CType::U32,
                    },
                ],
                CType::U64,
                stmts,
            );
            ir.members = fields
                .iter()
                .map(|(offset, name, ty, width)| Member {
                    structure: "record".to_owned(),
                    offset: *offset,
                    name: (*name).to_owned(),
                    ty: ty.clone(),
                    width: *width,
                })
                .collect();
            ir.accesses = vec![Access {
                register: 7,
                fields: fields
                    .iter()
                    .map(|(offset, _, _, width)| {
                        let width = if *offset == 0 { 8 } else { *width };
                        (*offset as u64, CType::int(width as u8, false))
                    })
                    .collect(),
            }];
            ir.definitions = vec![
                Definition {
                    name: "struct pair".to_owned(),
                    members: vec!["uint32_t lo;".to_owned(), "uint32_t hi;".to_owned()],
                    fields: vec!["lo".to_owned(), "hi".to_owned()],
                    contains: Vec::new(),
                    size: 8,
                    alignment: Some(4),
                    compatible_profiles: vec![
                        AbiProfile::SysV,
                        AbiProfile::Aapcs64,
                        AbiProfile::Win64,
                    ],
                },
                Definition {
                    name: "struct record".to_owned(),
                    members: [
                        "uint32_t lo;",
                        "uint32_t hi;",
                        "uint64_t wide;",
                        "int32_t signed_value;",
                        "uint32_t unsigned_value;",
                        "uint32_t *pointer;",
                        "float sample;",
                        "bool flag;",
                        "uint8_t padding[3];",
                        "uint32_t array[2];",
                        "struct pair aggregate;",
                        "uint64_t unknown;",
                    ]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                    fields: fields
                        .iter()
                        .map(|(_, name, _, _)| (*name).to_owned())
                        .collect(),
                    contains: vec!["struct pair".to_owned()],
                    size: 64,
                    alignment: Some(8),
                    compatible_profiles: vec![
                        AbiProfile::SysV,
                        AbiProfile::Aapcs64,
                        AbiProfile::Win64,
                    ],
                },
            ];
            let code = velk::render::render(&ir, &[], &Default::default(), &[]);
            let named_return = match name.as_str() {
                "unsigned_from_signed" | "signed_from_signed" => Some("->signed_value"),
                "signed_from_unsigned" => Some("->unsigned_value"),
                "wide_float32_bits" | "wide_float64_bits" => Some("->wide"),
                "pointer_integer_bits"
                | "pointer_byte_arithmetic"
                | "pointer_integer_store"
                | "pointer_null_store"
                | "pointer_value_store" => Some("->pointer"),
                _ => None,
            };
            if let Some(field) = named_return {
                assert!(
                    code.lines().any(|line| {
                        line.trim_start().starts_with("return ") && line.contains(field)
                    }),
                    "{name}: {code}"
                );
            }
            if name == "float_add_store" {
                assert!(code.contains("->sample"), "{name}: {code}");
            }
            for field in ["array", "aggregate", "unknown", "flag"] {
                assert!(!code.contains(&format!("->{}", field)), "{name}: {code}");
            }
            Candidate {
                marshalling: None,
                label: name,
                segment_bases: Vec::new(),
                states: Vec::new(),
                params: ir.params.iter().map(|param| param.ty.to_string()).collect(),
                inputs: (0..trials::TRIALS)
                    .map(|trial| vec![REGION + 0x2000, REGION + 0x4000, eval::hash(trial, 0)])
                    .collect(),
                void: false,
                ir,
                code,
            }
        })
        .collect();
    check_candidates("members", candidates, Mode::Memory, &[]);
}

#[test]
fn printed_shifts_preserve_counts_widths_and_updates() {
    let counts = [0, 1, 7, 8, 16, 31, 32, 40, 63, 64, 65, u64::MAX];
    let constants = [0, 1, 31, 32, 40, 63, 64, 65, u64::MAX];
    assert_eq!(counts.len(), trials::TRIALS as usize);
    let mut scalar = Vec::new();
    let mut updates = Vec::new();
    for bytes in [1u8, 2, 4] {
        for signed in [false, true] {
            let ty = CType::int(bytes, signed);
            let raw = (1u64 << (bytes * 8 - 1)) | 5;
            let source = Expr::reg(7, bytes * 8);
            let source = if signed {
                Expr::SignExtend {
                    value: Box::new(source),
                    width: bytes,
                }
            } else {
                source
            };
            for (operation, op) in [
                ("shl", BinOp::Shl),
                ("shr", BinOp::Shr),
                ("sar", BinOp::Sar),
            ] {
                let prefix = format!(
                    "{operation}_{}{}",
                    if signed { 'i' } else { 'u' },
                    bytes * 8
                );
                for count in constants.into_iter().map(Some).chain(std::iter::once(None)) {
                    let mut params = vec![Param {
                        index: 7,
                        name: "value".to_owned(),
                        ty: ty.clone(),
                    }];
                    if count.is_none() {
                        params.push(Param {
                            index: 6,
                            name: "count".to_owned(),
                            ty: CType::int(1, false),
                        });
                    }
                    let suffix =
                        count.map_or_else(|| "variable8".to_owned(), |count| count.to_string());
                    let ir = synthetic_ir(
                        &format!("{prefix}_{suffix}"),
                        params,
                        CType::U64,
                        vec![Stmt::Ret {
                            value: Expr::Bin {
                                op,
                                lhs: Box::new(source.clone()),
                                rhs: Box::new(count.map_or_else(|| Expr::reg(6, 8), Expr::Const)),
                            },
                            at: None,
                        }],
                    );
                    let inputs = counts
                        .iter()
                        .map(|amount| {
                            if count.is_some() {
                                vec![raw]
                            } else {
                                vec![raw, *amount]
                            }
                        })
                        .collect();
                    scalar.push(printed_candidate(ir, inputs));
                }
                if !signed && op == BinOp::Sar {
                    let ir = synthetic_ir(
                        &format!("{prefix}_variable64"),
                        vec![
                            Param {
                                index: 7,
                                name: "value".to_owned(),
                                ty: ty.clone(),
                            },
                            Param {
                                index: 6,
                                name: "count".to_owned(),
                                ty: CType::U64,
                            },
                        ],
                        CType::U64,
                        vec![Stmt::Ret {
                            value: Expr::Bin {
                                op,
                                lhs: Box::new(source.clone()),
                                rhs: Box::new(Expr::reg(6, 64)),
                            },
                            at: None,
                        }],
                    );
                    scalar.push(printed_candidate(
                        ir,
                        counts.iter().map(|amount| vec![raw, *amount]).collect(),
                    ));
                }
                let address = Expr::reg(7, 64);
                let ir = synthetic_ir(
                    &format!("{prefix}_update"),
                    vec![
                        Param {
                            index: 7,
                            name: "value".to_owned(),
                            ty: CType::pointer_to(ty.clone()),
                        },
                        Param {
                            index: 6,
                            name: "count".to_owned(),
                            ty: CType::int(1, false),
                        },
                    ],
                    CType::U64,
                    vec![
                        Stmt::Store {
                            addr: address.clone(),
                            width: 8,
                            value: Expr::Const(0x0123_4567_89ab_cdef),
                            at: None,
                        },
                        Stmt::Store {
                            addr: address.clone(),
                            width: bytes,
                            value: Expr::Const(raw),
                            at: None,
                        },
                        Stmt::Store {
                            addr: address.clone(),
                            width: bytes,
                            value: Expr::Bin {
                                op,
                                lhs: Box::new(Expr::Load {
                                    addr: Box::new(address.clone()),
                                    width: bytes,
                                    signed,
                                }),
                                rhs: Box::new(Expr::reg(6, 8)),
                            },
                            at: None,
                        },
                        Stmt::Ret {
                            value: Expr::Load {
                                addr: Box::new(address),
                                width: 8,
                                signed: false,
                            },
                            at: None,
                        },
                    ],
                );
                let candidate = printed_candidate(
                    ir,
                    counts
                        .iter()
                        .map(|amount| vec![REGION + 0x2000, *amount])
                        .collect(),
                );
                assert!(!candidate.code.contains("<<="), "{}", candidate.code);
                assert!(!candidate.code.contains(">>="), "{}", candidate.code);
                updates.push(candidate);
            }
        }
    }
    for mask in [0xff, 0xffff, 0xffff_ffff] {
        for count in [0, 1, 31, 64, 65, u64::MAX] {
            let ir = synthetic_ir(
                &format!("shr_mask_{mask:x}_{count}"),
                vec![Param {
                    index: 7,
                    name: "value".to_owned(),
                    ty: CType::U64,
                }],
                CType::U64,
                vec![Stmt::Ret {
                    value: Expr::bin(
                        BinOp::And,
                        Expr::bin(BinOp::Shr, Expr::reg(7, 64), Expr::Const(count)),
                        Expr::Const(mask),
                    ),
                    at: None,
                }],
            );
            scalar.push(printed_candidate(
                ir,
                (0..trials::TRIALS)
                    .map(|_| vec![0xfedc_ba98_8765_4385])
                    .collect(),
            ));
        }
    }
    for (name, ret_type) in [
        ("shl_reg32_return32", CType::U32),
        ("shl_reg32_return64", CType::U64),
    ] {
        let ir = synthetic_ir(
            name,
            vec![Param {
                index: 7,
                name: "value".to_owned(),
                ty: CType::U64,
            }],
            ret_type,
            vec![Stmt::Ret {
                value: Expr::bin(BinOp::Shl, Expr::reg(7, 32), Expr::Const(1)),
                at: None,
            }],
        );
        scalar.push(printed_candidate(
            ir,
            (0..trials::TRIALS)
                .map(|trial| {
                    vec![match trial {
                        0 => 0,
                        1 => 1,
                        2 => u64::MAX,
                        _ => 0xfedc_ba98_8000_0005,
                    }]
                })
                .collect(),
        ));
    }
    assert_eq!(scalar.len(), 203);
    assert_eq!(updates.len(), 18);
    for (name, op, input, amount) in [
        ("flat_index_shl", BinOp::Shl, 0x8000_0005u64, 3u64),
        ("flat_index_add", BinOp::Add, 0xffff_fffe, 5),
        ("flat_index_sub", BinOp::Sub, 3, 5),
        ("flat_index_mul", BinOp::Mul, 0x4000_0005, 4),
    ] {
        let offset = match op {
            BinOp::Shl => input.wrapping_shl(amount as u32),
            BinOp::Add => input.wrapping_add(amount),
            BinOp::Sub => input.wrapping_sub(amount),
            BinOp::Mul => input.wrapping_mul(amount),
            _ => unreachable!(),
        } & 0xffff_ffff;
        let base = REGION + 0x2000 - offset;
        let address = Expr::bin(
            BinOp::Add,
            Expr::bin(
                BinOp::Add,
                Expr::Const(base),
                Expr::bin(
                    BinOp::And,
                    Expr::bin(op, Expr::reg(7, 64), Expr::Const(amount)),
                    Expr::Const(0xffff_ffff),
                ),
            ),
            Expr::bin(BinOp::Mul, Expr::reg(6, 64), Expr::Const(8)),
        );
        let ir = synthetic_ir(
            name,
            vec![
                Param {
                    index: 7,
                    name: "value".to_owned(),
                    ty: CType::U32,
                },
                Param {
                    index: 6,
                    name: "index".to_owned(),
                    ty: CType::U64,
                },
            ],
            CType::U64,
            vec![
                Stmt::Store {
                    addr: address,
                    width: 1,
                    value: Expr::Const(0x5a),
                    at: None,
                },
                Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(Expr::Const(REGION + 0x2000)),
                        width: 8,
                        signed: false,
                    },
                    at: None,
                },
            ],
        );
        let code = velk::render::render(&ir, &[], &Default::default(), &[(base, 0x1_0001_0000)]);
        updates.push(Candidate {
            marshalling: None,
            label: name.to_owned(),
            segment_bases: Vec::new(),
            states: Vec::new(),
            params: ir.params.iter().map(|param| param.ty.to_string()).collect(),
            inputs: (0..trials::TRIALS).map(|_| vec![input, 0]).collect(),
            void: false,
            ir,
            code,
        });
    }
    assert_eq!(updates.len(), 22);
    let sanitizer = [
        "-fno-wrapv",
        "-fsanitize=shift",
        "-fno-sanitize-recover=shift",
    ];
    check_candidates("shifts", scalar, Mode::Registers, &sanitizer);
    check_candidates("shift-memory", updates, Mode::Memory, &sanitizer);
}

#[test]
fn printed_masked_float_operands_preserve_result_bits() {
    let mut candidates = Vec::new();
    for (name, precision, mask, fused) in [
        ("masked_single_lerp", Precision::Single, 0xffff_ffff, false),
        ("masked_single_superset", Precision::Single, u64::MAX, false),
        ("masked_double_lerp", Precision::Double, u64::MAX, false),
        ("masked_single_fma", Precision::Single, 0xffff_ffff, true),
        ("masked_double_fma", Precision::Double, u64::MAX, true),
    ] {
        let bits = |value: f64| match precision {
            Precision::Single => u64::from((value as f32).to_bits()),
            Precision::Double => value.to_bits(),
        };
        let (p, m, negative_m) = match precision {
            Precision::Single => (0x3f80_0001, 0x3f7f_fffe, 0xbf7f_fffe),
            Precision::Double => (
                0x3ff0_0000_0000_0001,
                0x3fef_ffff_ffff_fffe,
                0xbfef_ffff_ffff_fffe,
            ),
        };
        let rows = if fused {
            [
                [p, m, bits(-1.0)],
                [bits(1.0), bits(1.0), bits(-1.0)],
                [bits(1.25), bits(2.5), bits(-0.125)],
                [bits(-1.25), bits(2.5), bits(0.125)],
                [bits(-0.0), bits(1.0), bits(0.0)],
                [bits(0.0), bits(-1.0), bits(-0.0)],
                [bits(-0.0), bits(-1.0), bits(-0.0)],
                [bits(0.0), bits(1.0), bits(0.0)],
                [bits(2.0), bits(0.5), bits(1.0)],
                [bits(-2.0), bits(0.5), bits(-1.0)],
                [p, m, bits(1.0)],
                [p, negative_m, bits(1.0)],
            ]
        } else {
            [
                [bits(0.0), bits(1.0), bits(0.0)],
                [bits(0.0), bits(1.0), bits(1.0)],
                [bits(0.0), bits(1.0), bits(0.5)],
                [bits(1.0), bits(2.0), bits(0.5)],
                [bits(-1.0), bits(1.0), bits(0.5)],
                [bits(2.0), bits(-2.0), bits(0.25)],
                [bits(-0.0), bits(0.0), bits(1.0)],
                [bits(0.0), bits(-0.0), bits(1.0)],
                [bits(-0.0), bits(-0.0), bits(0.5)],
                [p, m, bits(0.5)],
                [bits(16.0), bits(17.0), bits(0.5)],
                [bits(-16.0), bits(-17.0), bits(0.5)],
            ]
        };
        assert_eq!(rows.len(), trials::TRIALS as usize);
        for row in &rows {
            for &raw in row {
                assert!(match precision {
                    Precision::Single => {
                        assert_eq!(raw >> 32, 0);
                        f32::from_bits(raw as u32).is_finite()
                    }
                    Precision::Double => f64::from_bits(raw).is_finite(),
                });
            }
        }
        let width = precision.bits() / 8;
        let inputs = (0..3)
            .map(|index| Expr::Load {
                addr: Box::new(Expr::Const(REGION + 0x8000 + index * 8)),
                width,
                signed: false,
            })
            .collect::<Vec<_>>();
        let [a, b, c]: [Expr; 3] = inputs.try_into().expect("three floating inputs");
        let value = if fused {
            Expr::apply(
                Operation::FloatNegate(precision),
                vec![Expr::bin(
                    BinOp::And,
                    Expr::apply(Operation::FloatMulAdd(precision), vec![a, b, c]),
                    Expr::Const(mask),
                )],
            )
        } else {
            Expr::apply(
                Operation::FloatAdd(precision),
                vec![
                    a.clone(),
                    Expr::bin(
                        BinOp::And,
                        Expr::apply(
                            Operation::FloatMul(precision),
                            vec![Expr::apply(Operation::FloatSub(precision), vec![b, a]), c],
                        ),
                        Expr::Const(mask),
                    ),
                ],
            )
        };
        let registers = [7, 6, 2];
        let params = registers
            .iter()
            .zip(["a_bits", "b_bits", "c_bits"])
            .map(|(&index, name)| Param {
                index,
                name: name.to_owned(),
                ty: CType::U64,
            })
            .collect();
        let mut stmts = registers
            .iter()
            .enumerate()
            .map(|(index, &register)| Stmt::Store {
                addr: Expr::Const(REGION + 0x8000 + index as u64 * 8),
                width,
                value: Expr::reg(register, 64),
                at: None,
            })
            .collect::<Vec<_>>();
        let result = REGION + 0x8040;
        stmts.push(Stmt::Store {
            addr: Expr::Const(result),
            width,
            value,
            at: None,
        });
        stmts.push(Stmt::Ret {
            value: Expr::Load {
                addr: Box::new(Expr::Const(result)),
                width,
                signed: false,
            },
            at: None,
        });
        let ir = synthetic_ir(name, params, CType::U64, stmts);
        if fused {
            let registers = registers.into_iter().zip(rows[0]).collect::<Vec<_>>();
            let outcome = eval::run(
                &ir,
                &eval::Setup {
                    seed: 0,
                    convention: eval::Convention {
                        arguments: Convention::SysV.arguments(),
                        clobbered: &[],
                    },
                    registers: &registers,
                    memory: &[],
                    step_limit: trials::STEP_LIMIT,
                },
            );
            let Outcome::Return { value, calls, .. } = outcome else {
                panic!("the fused discriminator must return: {outcome:?}");
            };
            assert!(calls.is_empty());
            assert_eq!(
                value,
                match precision {
                    Precision::Single => 0x2880_0000,
                    Precision::Double => 0x3970_0000_0000_0000,
                }
            );
        }
        candidates.push(printed_candidate(
            ir,
            rows.into_iter().map(|row| row.to_vec()).collect(),
        ));
    }
    assert_eq!(candidates.len(), 5);
    check_candidates(
        "float-masks",
        candidates,
        Mode::Memory,
        &[
            "-ffp-contract=off",
            // Preserve the FMA result before the separate negation.
            "-fno-builtin-fma",
            "-fno-builtin-fmaf",
            "-lm",
        ],
    );
}

#[test]
fn printed_segment_bases_preserve_controlled_state() {
    let offset = |index, amount: i64| {
        Expr::bin(BinOp::Add, Expr::reg(index, 64), Expr::Const(amount as u64))
    };
    let load = |addr| Expr::Load {
        addr: Box::new(addr),
        width: 8,
        signed: false,
    };
    let value_bits = |trial| 0xfedc_ba98_7654_3210 ^ trial;
    let mut candidates = Vec::new();
    for (case, name) in [
        "segment_fs_zero",
        "segment_fs_positive",
        "segment_fs_negative",
        "segment_gs_zero",
        "segment_distinct",
        "segment_store_alias",
        "segment_partial_store",
        "segment_nested",
        "segment_narrow_base",
        "segment_parameter_collision",
        "velk_x86_fs_base",
        "segment_reserved_names",
    ]
    .into_iter()
    .enumerate()
    {
        let mut params = Vec::new();
        let mut stmts = Vec::new();
        let value = match case {
            0 => load(Expr::reg(16, 64)),
            1 | 10 => load(offset(16, 8)),
            2 => load(offset(16, -8)),
            3 => load(Expr::reg(17, 64)),
            4 => Expr::bin(BinOp::Xor, load(offset(16, 8)), load(offset(17, 8))),
            5 => {
                params.extend([
                    Param {
                        index: 7,
                        name: "alias".to_owned(),
                        ty: CType::pointer_to(CType::U64),
                    },
                    Param {
                        index: 6,
                        name: "value".to_owned(),
                        ty: CType::U64,
                    },
                ]);
                stmts.push(Stmt::Store {
                    addr: offset(16, -8),
                    width: 8,
                    value: Expr::reg(6, 64),
                    at: None,
                });
                load(Expr::reg(7, 64))
            }
            6 => {
                params.push(Param {
                    index: 7,
                    name: "value".to_owned(),
                    ty: CType::U64,
                });
                stmts.push(Stmt::Store {
                    addr: offset(17, -6),
                    width: 2,
                    value: Expr::reg(7, 64),
                    at: None,
                });
                load(offset(17, -8))
            }
            7 => Expr::Select {
                cond: Cond::Eq,
                lhs: Box::new(load(Expr::bin(
                    BinOp::Sub,
                    load(Expr::reg(16, 64)),
                    Expr::Const(0x20),
                ))),
                rhs: Box::new(Expr::Const(0)),
                then: Box::new(Expr::Const(1)),
                els: Box::new(Expr::Const(0)),
            },
            8 => Expr::bin(BinOp::Add, Expr::reg(16, 32), Expr::Const(1)),
            9 => {
                params.push(Param {
                    index: 7,
                    name: "fs_base".to_owned(),
                    ty: CType::U64,
                });
                Expr::bin(BinOp::Xor, Expr::reg(7, 64), load(offset(16, 8)))
            }
            11 => {
                params.push(Param {
                    index: 16,
                    name: "target_base".to_owned(),
                    ty: CType::U64,
                });
                Expr::bin(BinOp::Xor, Expr::reg(16, 64), load(offset(17, 8)))
            }
            _ => unreachable!(),
        };
        stmts.push(Stmt::Ret { value, at: None });
        let ir = synthetic_ir(name, params, CType::U64, stmts);
        let inputs = (0..trials::TRIALS)
            .map(|trial| match case {
                5 => vec![
                    REGION + 0x1000 + (trial % 2) * 0x1000 - 8,
                    value_bits(trial),
                ],
                6 | 9 => vec![value_bits(trial)],
                11 => vec![REGION + 0x9000 + trial],
                _ => Vec::new(),
            })
            .collect();
        let mut candidate = printed_candidate(ir, inputs);
        if case == 11 {
            let symbols = velk::render::Symbols {
                functions: [
                    (0x1110, "velk_x86_fs_base".to_owned()),
                    (0x1120, "velk_x86_gs_base".to_owned()),
                ]
                .into(),
                ..Default::default()
            };
            let rendered =
                velk::render::render_with_dependencies(&candidate.ir, &[], &symbols, &[]);
            candidate.code = rendered.code;
            candidate.segment_bases = rendered.segment_bases;
        }
        assert!(!candidate.segment_bases.is_empty(), "{name}");
        assert!(
            declared_functions(&candidate.code).is_empty(),
            "{}",
            candidate.code
        );
        if case == 4 {
            assert_eq!(candidate.segment_bases.len(), 2);
        }
        if case == 10 {
            assert!(
                candidate
                    .segment_bases
                    .iter()
                    .all(|read| read.provider != name)
            );
        }
        if case == 11 {
            assert_eq!(candidate.segment_bases.len(), 1);
            assert_eq!(candidate.segment_bases[0].segment, SegmentBase::Gs);
            assert_ne!(candidate.segment_bases[0].provider, "velk_x86_gs_base");
        }
        candidates.push(candidate);
    }
    let fixture = Fixture {
        name: "segments".into(),
        convention: eval::Convention {
            arguments: Convention::SysV.arguments(),
            clobbered: &[],
        },
        entry_registers: Vec::new(),
        initial_memory: vec![(REGION + 0x1008, 0x11), (REGION + 0x2008, 0x22)],
        functions: candidates.len(),
        excluded: BTreeMap::new(),
        candidates,
    };
    assert_eq!(fixture.candidates.len(), 12);
    for (case, candidate) in fixture.candidates.iter().enumerate() {
        for trial in 0..trials::TRIALS {
            let context = trial % 2;
            let fs = REGION + 0x1000 + context * 0x1000;
            let expected = match case {
                0 => REGION + 0x6000 + context * 0x1000,
                1 | 10 => segment_word(trial, context, 2),
                2 => segment_word(trial, context, 1),
                3 => segment_word(trial, context, 3),
                4 => segment_word(trial, context, 2) ^ segment_word(trial, context, 5),
                5 => value_bits(trial),
                6 => {
                    (segment_word(trial, context, 4) & !(0xffff << 16))
                        | ((value_bits(trial) & 0xffff) << 16)
                }
                7 => u64::from(context == 0),
                8 => (fs & 0xffff_ffff) + 1,
                9 => value_bits(trial) ^ segment_word(trial, context, 2),
                11 => (REGION + 0x9000 + trial) ^ segment_word(trial, context, 5),
                _ => unreachable!(),
            };
            let outcome = interpret(
                &fixture,
                candidate,
                trial,
                &candidate.inputs[trial as usize],
                Mode::Memory,
            )
            .expect("a controlled return");
            let Outcome::Return { value, calls, .. } = outcome else {
                panic!("{outcome:?}")
            };
            assert_eq!(value, expected, "{} trial {trial}", candidate.label);
            assert!(calls.is_empty());
        }
    }
    let scratch = scratch_dir("segments");
    let results = check(&[fixture], &scratch, Mode::Memory, &[]);
    std::fs::remove_dir_all(&scratch).ok();
    assert_comparisons(&results[0], 12);
}

#[test]
fn printed_real_segment_functions_use_controlled_state() {
    let mut fixtures = Vec::new();
    for (name, address) in [
        ("go_probe", 0x460e80),
        ("go_stripped", 0x460e80),
        ("rust_demo", 0x3b8e0),
        ("rust_probe", 0x3b8e0),
        ("rust_probe_stripped", 0x3b8e0),
    ] {
        let mut fixture = prepare(Path::new(name), Mode::Memory);
        fixture
            .candidates
            .retain(|candidate| candidate.ir.addr == address);
        assert_eq!(
            fixture.candidates.len(),
            1,
            "{name}: expected the segment-dependent function"
        );
        assert_eq!(fixture.candidates[0].segment_bases.len(), 1);
        assert_eq!(
            fixture.candidates[0].segment_bases[0].segment,
            SegmentBase::Fs
        );
        assert_eq!(fixture.candidates[0].void, name != "rust_probe_stripped");
        fixtures.push(fixture);
    }
    let scratch = scratch_dir("real-segments");
    let results = check(&fixtures, &scratch, Mode::Memory, &[]);
    std::fs::remove_dir_all(&scratch).ok();
    assert_eq!(results.len(), 5);
    for result in &results {
        assert_comparisons(result, 1);
    }
}

#[test]
fn segment_dependencies_reject_missing_state() {
    let mut candidate = printed_candidate(
        synthetic_ir(
            "missing_segment",
            Vec::new(),
            CType::U64,
            vec![Stmt::Ret {
                value: Expr::reg(16, 64),
                at: None,
            }],
        ),
        (0..trials::TRIALS).map(|_| Vec::new()).collect(),
    );
    assert_eq!(candidate.segment_bases.len(), 1);
    candidate.states.clear();
    assert!(segment_state(&candidate, 0).is_err());
    candidate.states = segment_states();
    candidate.states[0].fs = None;
    assert!(segment_state(&candidate, 0).is_err());
}

#[test]
fn segment_fixture_overlays_preserve_region_boundaries() {
    let address = REGION + REGION_SIZE - 4;
    let load = |addr, width| Expr::Load {
        addr: Box::new(Expr::Const(addr)),
        width,
        signed: false,
    };
    let value = Expr::bin(
        BinOp::Xor,
        Expr::bin(
            BinOp::Or,
            load(address, 4),
            Expr::bin(BinOp::Shl, load(address + 4, 4), Expr::Const(32)),
        ),
        Expr::bin(
            BinOp::Or,
            load(address - 1, 1),
            Expr::bin(BinOp::Shl, load(address + 10, 1), Expr::Const(8)),
        ),
    );
    let candidate = printed_candidate(
        synthetic_ir(
            "fixture_boundary",
            Vec::new(),
            CType::U64,
            vec![Stmt::Ret { value, at: None }],
        ),
        (0..trials::TRIALS).map(|_| Vec::new()).collect(),
    );
    assert!(candidate.segment_bases.is_empty());
    let fixture = Fixture {
        name: "segment-fixture-boundary".into(),
        convention: eval::Convention {
            arguments: Convention::SysV.arguments(),
            clobbered: &[],
        },
        entry_registers: Vec::new(),
        initial_memory: vec![
            (address, 0x0123_4567_89ab_cdef),
            (address + 2, 0xfedc_ba98_7654_3210),
            (address + 10, 0x1122_3344_5566_775a),
        ],
        functions: 1,
        excluded: BTreeMap::new(),
        candidates: vec![candidate],
    };
    for trial in 0..trials::TRIALS {
        let outcome = interpret(&fixture, &fixture.candidates[0], trial, &[], Mode::Memory)
            .expect("defined fixture bytes");
        let Outcome::Return { value, .. } = outcome else {
            panic!("{outcome:?}")
        };
        assert_eq!(
            value,
            0xba98_7654_3210_cdef ^ (eval::hash(trial, address - 1) & 0xff) ^ 0x5a00
        );
    }
    let scratch = scratch_dir("segment-fixture-boundary");
    let results = check(&[fixture], &scratch, Mode::Memory, &[]);
    std::fs::remove_dir_all(&scratch).ok();
    assert_comparisons(&results[0], 1);
}

#[test]
fn segment_state_checks_ignore_void_returns_but_preserve_effects() {
    let address = REGION + 0x1230;
    let memory = [(address, 0)];
    let run = |ir: &FunctionIr, seed| {
        eval::run(
            ir,
            &eval::Setup {
                seed,
                convention: eval::Convention {
                    arguments: Convention::SysV.arguments(),
                    clobbered: &[],
                },
                registers: &[],
                memory: &memory,
                step_limit: trials::STEP_LIMIT,
            },
        )
    };
    let candidate = |value, returned| {
        printed_candidate(
            synthetic_ir(
                "void_effects",
                Vec::new(),
                CType::Void,
                vec![
                    Stmt::Store {
                        addr: Expr::Const(address),
                        width: 8,
                        value,
                        at: None,
                    },
                    Stmt::Ret {
                        value: returned,
                        at: None,
                    },
                ],
            ),
            (0..trials::TRIALS).map(|_| Vec::new()).collect(),
        )
    };
    let mut defined_store = candidate(Expr::Const(5), Expr::reg(0, 64));
    let (first, second) = (run(&defined_store.ir, 1), run(&defined_store.ir, 2));
    let (
        Outcome::Return {
            value: a,
            memory: am,
            ..
        },
        Outcome::Return {
            value: b,
            memory: bm,
            ..
        },
    ) = (&first, &second)
    else {
        panic!("expected returns")
    };
    assert_ne!(a, b);
    assert_eq!(am, bm);
    assert!(same_outcome(&first, &second, &defined_store));
    defined_store.void = false;
    defined_store.ir.ret_type = CType::U64;
    assert!(!same_outcome(&first, &second, &defined_store));

    let undefined_store = candidate(Expr::reg(3, 64), Expr::Const(0));
    let (first, second) = (run(&undefined_store.ir, 1), run(&undefined_store.ir, 2));
    let (
        Outcome::Return {
            value: a,
            memory: am,
            ..
        },
        Outcome::Return {
            value: b,
            memory: bm,
            ..
        },
    ) = (&first, &second)
    else {
        panic!("expected returns")
    };
    assert_eq!(a, b);
    assert_ne!(am, bm);
    assert!(!same_outcome(&first, &second, &undefined_store));
}

#[test]
fn generic_comparisons_keep_declared_objects_on_the_focused_path() {
    let ir = integer_object_ir(4, false);
    for mode in [Mode::Registers, Mode::Memory] {
        assert_eq!(
            qualifies(&ir, true, mode),
            Err("takes an argument that is no integer")
        );
    }
    let (inputs, upper) = aggregate_inputs(&[4, 8], 1);
    let candidates = aggregate_candidates(ir.clone(), inputs, upper);
    assert_eq!(candidates.len(), 1);
    let call = candidates[0]
        .marshalling
        .as_ref()
        .expect("the focused object path");
    assert!(call.signature.abi.as_ref().unwrap().arguments[0].aggregate);
    assert_eq!(candidates[0].inputs.len(), 3);
    assert!(candidates[0].code.contains("struct bytes value"));

    for ty in [
        CType::Named("struct missing".into()),
        CType::Named("union missing".into()),
        CType::Named("double".into()),
    ] {
        let mut unsupported = ir.clone();
        let signature = unsupported.declared_signature.as_mut().unwrap();
        signature.params[0].1 = ty.clone();
        signature.abi = Err(velk::ir::AbiIssue::UnsupportedType);
        for mode in [Mode::Registers, Mode::Memory] {
            assert_eq!(
                qualifies(&unsupported, true, mode),
                Err("takes an argument that is no integer")
            );
        }
        unsupported.declared_signature.as_mut().unwrap().ret = ty;
        for mode in [Mode::Registers, Mode::Memory] {
            assert_eq!(
                qualifies(&unsupported, true, mode),
                Err("returns no integer")
            );
        }
    }

    let mut scalar = ir;
    let signature = scalar.declared_signature.as_mut().unwrap();
    signature.params[0].1 = CType::U64;
    signature.abi = Err(velk::ir::AbiIssue::UnsupportedType);
    assert_eq!(qualifies(&scalar, true, Mode::Registers), Ok(()));

    let pointer = CType::pointer_to(CType::U64);
    let mut memory = synthetic_ir(
        "declared_pointer_store",
        vec![Param {
            index: 7,
            name: "output".into(),
            ty: pointer.clone(),
        }],
        CType::Void,
        vec![
            Stmt::Store {
                addr: Expr::reg(7, 64),
                value: Expr::Const(1),
                width: 8,
                at: None,
            },
            Stmt::Ret {
                value: Expr::Const(0),
                at: None,
            },
        ],
    );
    memory.declared_signature = Some(DeclaredSignature {
        params: vec![("output".into(), pointer)],
        ret: CType::Void,
        variadic: false,
        abi: Err(velk::ir::AbiIssue::UnsupportedType),
    });
    assert_eq!(qualifies(&memory, true, Mode::Memory), Ok(()));
    assert_eq!(
        qualifies(&memory, true, Mode::Registers),
        Err("returns nothing")
    );
}

#[test]
fn aggregate_object_view_rejects_observed_non_object_bits() {
    let mut ir = integer_object_ir(4, false);
    ir.blocks[0].stmts = vec![Stmt::Ret {
        value: Expr::reg(7, 64),
        at: None,
    }];
    let mut observed = BTreeSet::new();
    for upper in [0, u64::MAX, 0xa55a_3cc3_9669_f00f] {
        let input = 0x8123_4567 | (upper & !0xffff_ffff);
        let outcome = eval::run(
            &ir,
            &eval::Setup {
                seed: 0,
                convention: eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &[(7, input), (6, 0)],
                memory: &[],
                step_limit: trials::STEP_LIMIT,
            },
        );
        let Outcome::Return { value, .. } = outcome else {
            panic!("{outcome:?}")
        };
        assert_eq!(value, input);
        observed.insert(value);
    }
    assert_eq!(observed.len(), 3);
    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
    let signature = code
        .lines()
        .find(|line| line.starts_with("uint64_t aggregate_bytes_4_scalar("))
        .expect("the physical function remains renderable");
    assert!(signature.contains("uint64_t piece0"), "{signature}");
    assert!(!signature.contains("struct bytes"), "{signature}");
}

#[test]
fn printed_aggregate_integer_objects_preserve_bounded_pieces() {
    let mut candidates = Vec::new();
    for size in 1..=16 {
        for aggregate_return in [false, true] {
            let ir = integer_object_ir(size, aggregate_return);
            let (inputs, upper) = aggregate_inputs(&[size, 8], 12);
            let batch = aggregate_candidates(ir, inputs, upper);
            assert_aggregate_oracle(&batch, |input, slice| {
                let words = size.div_ceil(8) as usize;
                let tail = input[words];
                if aggregate_return {
                    let at = slice.offset as usize / 8;
                    (input[at] ^ tail) & byte_mask(slice.bytes)
                } else {
                    input[..words]
                        .iter()
                        .enumerate()
                        .fold(tail, |value, (part, word)| {
                            value ^ (word & byte_mask((size - part as u64 * 8).min(8) as u8))
                        })
                }
            });
            candidates.extend(batch);
        }
    }
    check_candidates(
        "aggregate-integer-objects",
        candidates,
        Mode::Registers,
        &[],
    );
}

#[test]
fn printed_aggregate_capture_tracks_narrow_register_writes() {
    let mut candidates = Vec::new();
    for written in [0x1_0000_0001, 0x1_8000_0000, 0x1_ffff_ffff] {
        let mut ir = integer_object_ir(8, false);
        ir.name = Some(format!("aggregate_narrow_write_{written:x}"));
        ir.blocks[0].stmts = vec![
            Stmt::Assign {
                dest: velk::ir::RegRef {
                    index: velk::ir::VARIABLE_BASE,
                    width: 64,
                },
                value: Expr::reg(7, 64),
                at: None,
            },
            Stmt::Assign {
                dest: velk::ir::RegRef {
                    index: 7,
                    width: 32,
                },
                value: Expr::Const(written),
                at: None,
            },
            Stmt::Ret {
                value: Expr::bin(
                    BinOp::Xor,
                    Expr::reg(velk::ir::VARIABLE_BASE, 64),
                    Expr::reg(7, 64),
                ),
                at: None,
            },
        ];
        let (inputs, upper) = aggregate_inputs(&[8, 8], 12);
        let batch = aggregate_candidates(ir, inputs, upper);
        assert_aggregate_oracle(&batch, |input, _| input[0] ^ (written & 0xffff_ffff));
        candidates.extend(batch);
    }
    let mut ir = integer_object_ir(4, false);
    ir.name = Some("aggregate_capture_wide_write".into());
    let written = 0xfedc_ba98_8123_4567;
    ir.blocks[0].stmts = vec![
        Stmt::Assign {
            dest: velk::ir::RegRef {
                index: velk::ir::VARIABLE_BASE,
                width: 64,
            },
            value: Expr::reg(7, 32),
            at: None,
        },
        Stmt::Assign {
            dest: velk::ir::RegRef {
                index: 7,
                width: 64,
            },
            value: Expr::Const(written),
            at: None,
        },
        Stmt::Ret {
            value: Expr::bin(
                BinOp::Xor,
                Expr::reg(velk::ir::VARIABLE_BASE, 64),
                Expr::reg(7, 64),
            ),
            at: None,
        },
    ];
    let (inputs, upper) = aggregate_inputs(&[4, 8], 12);
    let batch = aggregate_candidates(ir, inputs, upper);
    assert_aggregate_oracle(&batch, |input, _| (input[0] & 0xffff_ffff) ^ written);
    candidates.extend(batch);
    check_candidates("aggregate-narrow-write", candidates, Mode::Registers, &[]);
}

#[test]
fn printed_scalar_stack_parameter_views_preserve_loaded_values() {
    let mut candidates = Vec::new();
    for kind in ["u8", "u16", "u32", "i32", "f32", "f64"] {
        let (offset, width) = match kind {
            "u8" => (7, 1),
            "u16" => (1, 2),
            "u32" => (3, 4),
            "i32" | "f32" => (1, 4),
            "f64" => (0, 8),
            _ => unreachable!(),
        };
        let load = Expr::Load {
            addr: Box::new(Expr::bin(
                BinOp::Add,
                Expr::reg(4, 64),
                Expr::Const(24 + offset),
            )),
            width,
            signed: kind == "i32",
        };
        let value = match kind {
            "f32" => Expr::Apply {
                op: Operation::FloatLess(Precision::Single),
                args: vec![load, Expr::Const(u64::from(0.5f32.to_bits()))],
            },
            "f64" => Expr::Apply {
                op: Operation::FloatLess(Precision::Double),
                args: vec![load, Expr::Const(0.5f64.to_bits())],
            },
            _ => load,
        };
        let ir = scalar_stack_ir(
            &format!("scalar_stack_read_{kind}"),
            3,
            vec![Stmt::Ret { value, at: None }],
        );
        assert_scalar_stack_render_control(&ir);
        let (mut inputs, upper) = aggregate_inputs(&[8; 9], 12);
        for (trial, input) in inputs.iter_mut().enumerate() {
            let row = trial / 3;
            let raw = match kind {
                "f32" => u64::from([0.0f32, -0.0, 1.25, -2.5, 3.75, -4.0][row % 6].to_bits()),
                "f64" => [0.0f64, -0.0, 1.25, -2.5, 3.75, -4.0][row % 6].to_bits(),
                _ => {
                    let sign = 1u64 << (width * 8 - 1);
                    [0, 1, sign - 1, sign, byte_mask(width)][row % 5]
                }
            };
            let mask = byte_mask(width) << (8 * offset);
            input[8] = (input[8] & !mask) | ((raw << (8 * offset)) & mask);
        }
        let batch = aggregate_candidates(ir, inputs, upper);
        assert_aggregate_oracle(&batch, |input, _| {
            let raw = (input[8] >> (8 * offset)) & byte_mask(width);
            match kind {
                "i32" => (raw as i32) as i64 as u64,
                "f32" => u64::from(f32::from_bits(raw as u32) < 0.5),
                "f64" => u64::from(f64::from_bits(raw) < 0.5),
                _ => raw,
            }
        });
        candidates.extend(batch);
    }
    assert_eq!(candidates.len(), 6);
    check_candidates(
        "scalar-stack-parameter-views",
        candidates,
        Mode::Registers,
        &["-fsanitize=alignment", "-fno-sanitize-recover=alignment"],
    );
}

#[test]
fn printed_scalar_stack_parameter_stores_preserve_surrounding_bytes() {
    let address = |offset| Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const(offset));
    let load = |offset, width| Expr::Load {
        addr: Box::new(address(offset)),
        width,
        signed: false,
    };
    let mut candidates = Vec::new();
    for width in [1u8, 2, 4] {
        let mut stmts = vec![Stmt::Store {
            addr: address(25),
            value: load(24, width),
            width,
            at: None,
        }];
        for (part, offset) in [16, 24, 32].into_iter().enumerate() {
            stmts.push(Stmt::Store {
                addr: Expr::Const(REGION + 0x1800 + part as u64 * 8),
                value: load(offset, 8),
                width: 8,
                at: None,
            });
        }
        stmts.push(Stmt::Ret {
            value: load(24, 8),
            at: None,
        });
        let ir = scalar_stack_ir(&format!("scalar_stack_store_{width}"), 4, stmts);
        assert_scalar_stack_render_control(&ir);
        let (mut inputs, upper) = aggregate_inputs(&[8; 10], 12);
        for (trial, input) in inputs.iter_mut().enumerate() {
            input[8] =
                0xfedc_ba98_7654_3210 ^ (trial as u64 / 3).wrapping_mul(0x0101_0101_0101_0101);
        }
        let batch = aggregate_candidates(ir, inputs, upper);
        let fixture = Fixture {
            name: "scalar stack store oracle".into(),
            convention: eval::Convention {
                arguments: &[],
                clobbered: &[],
            },
            entry_registers: Vec::new(),
            initial_memory: Vec::new(),
            functions: batch.len(),
            excluded: BTreeMap::new(),
            candidates: Vec::new(),
        };
        for candidate in &batch {
            for (trial, input) in candidate.inputs.iter().enumerate() {
                let before = input[8].to_le_bytes();
                let mut after = before;
                after[1..1 + usize::from(width)].copy_from_slice(&before[..usize::from(width)]);
                let changed = u64::from_le_bytes(after);
                let memory = [input[7], changed, input[9]]
                    .into_iter()
                    .enumerate()
                    .flat_map(|(part, word)| {
                        word.to_le_bytes()
                            .into_iter()
                            .enumerate()
                            .map(move |(byte, value)| {
                                (REGION + 0x1800 + part as u64 * 8 + byte as u64, value)
                            })
                    })
                    .collect();
                let outcome =
                    interpret(&fixture, candidate, trial as u64, input, Mode::Registers).unwrap();
                assert_eq!(
                    outcome,
                    Outcome::Return {
                        value: changed,
                        calls: Vec::new(),
                        memory
                    }
                );
            }
        }
        candidates.extend(batch);
    }
    assert_eq!(candidates.len(), 3);
    check_candidates(
        "scalar-stack-parameter-stores",
        candidates,
        Mode::Memory,
        &["-fsanitize=alignment", "-fno-sanitize-recover=alignment"],
    );
}

fn scalar_stack_ir(name: &str, count: usize, stmts: Vec<Stmt>) -> FunctionIr {
    let registers = [7, 6, 2, 1, 8, 9];
    let mut ir = synthetic_ir(
        name,
        registers
            .into_iter()
            .enumerate()
            .map(|(position, index)| Param {
                index,
                name: format!("physical{position}"),
                ty: CType::U64,
            })
            .collect(),
        CType::U64,
        stmts,
    );
    ir.stack_params = (0..count)
        .map(|slot| velk::ir::StackParam {
            offset: (slot as i64 + 1) * 8,
            size: 8,
            name: format!("stack{slot}"),
            ty: CType::U64,
            position: 6 + slot,
        })
        .collect();
    let scalar = |location| ValueAbi {
        aggregate: false,
        size: 8,
        alignment: 8,
        defined_bits: vec![(0, 64)],
        passing: Passing::Direct(vec![AbiPiece {
            location,
            object_offset: 0,
            bytes: 8,
            class: if matches!(location, AbiLocation::Register(_)) {
                Some(RegisterClass::Integer)
            } else {
                None
            },
        }]),
    };
    ir.declared_signature = Some(DeclaredSignature {
        params: (0..6 + count)
            .map(|position| (format!("logical{position}"), CType::U64))
            .collect(),
        ret: CType::U64,
        variadic: false,
        abi: Ok(SignatureAbi {
            profile: AbiProfile::SysV,
            arguments: registers
                .into_iter()
                .map(AbiLocation::Register)
                .chain((0..count).map(|slot| AbiLocation::Stack((slot as i64 + 1) * 8)))
                .map(scalar)
                .collect(),
            result: Some(scalar(AbiLocation::Register(0))),
        }),
    });
    ir
}

fn assert_scalar_stack_render_control(ir: &FunctionIr) {
    let abi = ir
        .declared_signature
        .as_ref()
        .expect("the scalar stack test requires a declared signature")
        .abi
        .as_ref()
        .expect("the scalar stack test requires a valid ABI");
    assert!(
        abi.arguments
            .iter()
            .chain(&abi.result)
            .all(|value| !value.aggregate)
    );
    let actual = velk::render::render_with_dependencies(ir, &[], &Default::default(), &[]);
    let mut physical = ir.clone();
    physical.declared_signature = None;
    let expected = velk::render::render_with_dependencies(&physical, &[], &Default::default(), &[]);
    assert_eq!(actual, expected);
}

#[test]
fn printed_aggregate_unaligned_object_accesses_preserve_bits() {
    let mut candidates = Vec::new();
    for offset in [0u64, 1] {
        for kind in ["u64", "i8", "i16", "i32", "f32", "f64"] {
            let width = match kind {
                "i8" => 1,
                "i16" => 2,
                "i32" | "f32" => 4,
                _ => 8,
            };
            let source = if kind == "u64" { 1 - offset } else { offset };
            let target = if kind == "u64" {
                offset
            } else {
                24 - u64::from(if kind.starts_with('i') { 8 } else { width }) - offset
            };
            let address = |at| Expr::bin(BinOp::Add, Expr::reg(0, 64), Expr::Const(at));
            let load = |at, bytes, signed| Expr::Load {
                addr: Box::new(address(at)),
                width: bytes,
                signed,
            };
            let value = match kind {
                "f32" => Expr::Apply {
                    op: Operation::FloatAdd(Precision::Single),
                    args: vec![
                        load(source, 4, false),
                        Expr::Const(u64::from(0.5f32.to_bits())),
                    ],
                },
                "f64" => Expr::Apply {
                    op: Operation::FloatAdd(Precision::Double),
                    args: vec![load(source, 8, false), Expr::Const((-0.25f64).to_bits())],
                },
                _ => load(source, width, kind.starts_with('i')),
            };
            let stored = if kind.starts_with('i') { 8 } else { width };
            let ir = indirect_byte_object_ir(
                &format!("aggregate_unaligned_{kind}_{offset}"),
                vec![
                    Stmt::Store {
                        addr: address(target),
                        width: stored,
                        value,
                        at: None,
                    },
                    Stmt::Ret {
                        value: load(target, stored, false),
                        at: None,
                    },
                ],
            );
            let (mut inputs, upper) = aggregate_inputs(&[24, 8], 12);
            for (trial, input) in inputs.iter_mut().enumerate() {
                let row = trial / 3;
                let raw = match kind {
                    "f32" => u64::from([0.0f32, -0.0, 1.25, -2.5, 3.75, -4.0][row % 6].to_bits()),
                    "f64" => [0.0f64, -0.0, 1.25, -2.5, 3.75, -4.0][row % 6].to_bits(),
                    "i8" | "i16" | "i32" => {
                        let sign = 1u64 << (width * 8 - 1);
                        [0, 1, sign - 1, sign, byte_mask(width)][row % 5]
                    }
                    _ => continue,
                };
                for byte in 0..u64::from(width) {
                    let at = source + byte;
                    let shift = (at % 8) * 8;
                    input[at as usize / 8] = (input[at as usize / 8] & !(0xff << shift))
                        | ((raw >> (byte * 8)) & 0xff) << shift;
                }
            }
            let batch = aggregate_candidates(ir, inputs, upper);
            assert_aggregate_oracle(&batch, |input, _| {
                let bytes: Vec<_> = input[..3]
                    .iter()
                    .flat_map(|word| word.to_le_bytes())
                    .collect();
                let raw = (0..u64::from(width)).fold(0u64, |word, byte| {
                    word | u64::from(bytes[(source + byte) as usize]) << (8 * byte)
                });
                match kind {
                    "i8" => (raw as i8) as i64 as u64,
                    "i16" => (raw as i16) as i64 as u64,
                    "i32" => (raw as i32) as i64 as u64,
                    "f32" => u64::from((f32::from_bits(raw as u32) + 0.5).to_bits()),
                    "f64" => (f64::from_bits(raw) - 0.25).to_bits(),
                    _ => raw,
                }
            });
            candidates.extend(batch);
        }
    }
    check_candidates(
        "aggregate-unaligned-objects",
        candidates,
        Mode::Registers,
        &["-fsanitize=alignment", "-fno-sanitize-recover=alignment"],
    );
}

fn indirect_byte_object_ir(name: &str, stmts: Vec<Stmt>) -> FunctionIr {
    let mut ir = synthetic_ir(
        name,
        vec![
            Param {
                index: 0,
                name: "address".into(),
                ty: CType::pointer_to(CType::int(1, false)),
            },
            Param {
                index: 1,
                name: "tail".into(),
                ty: CType::U64,
            },
        ],
        CType::U64,
        stmts,
    );
    ir.isa = Isa::AArch64;
    ir.convention = Convention::Aapcs64;
    ir.definitions.push(Definition {
        name: "struct byte_object".into(),
        members: vec!["unsigned char bytes[24];".into()],
        fields: vec!["bytes".into()],
        contains: Vec::new(),
        size: 24,
        alignment: Some(1),
        compatible_profiles: vec![AbiProfile::Aapcs64],
    });
    let scalar = |index| ValueAbi {
        aggregate: false,
        size: 8,
        alignment: 8,
        defined_bits: vec![(0, 64)],
        passing: Passing::Direct(vec![AbiPiece {
            location: AbiLocation::Register(index),
            object_offset: 0,
            bytes: 8,
            class: Some(RegisterClass::Integer),
        }]),
    };
    ir.declared_signature = Some(DeclaredSignature {
        params: vec![
            ("value".into(), CType::Named("struct byte_object".into())),
            ("tail".into(), CType::U64),
        ],
        ret: CType::U64,
        variadic: false,
        abi: Ok(SignatureAbi {
            profile: AbiProfile::Aapcs64,
            arguments: vec![
                ValueAbi {
                    aggregate: true,
                    size: 24,
                    alignment: 1,
                    defined_bits: vec![(0, 192)],
                    passing: Passing::Indirect {
                        pointer: AbiLocation::Register(0),
                        returned_pointer: None,
                    },
                },
                scalar(1),
            ],
            result: Some(scalar(0)),
        }),
    });
    ir
}

#[test]
fn printed_aggregate_arguments_preserve_scalar_128_bit_results() {
    let mut candidates = Vec::new();
    for ty in ["unsigned __int128", "__int128"] {
        let mut ir = integer_object_ir(16, true);
        ir.name = Some(
            if ty.starts_with("unsigned") {
                "aggregate_unsigned_wide_result"
            } else {
                "aggregate_signed_wide_result"
            }
            .into(),
        );
        ir.ret_type = CType::Named(ty.into());
        let signature = ir.declared_signature.as_mut().unwrap();
        signature.ret = ir.ret_type.clone();
        let result = signature.abi.as_mut().unwrap().result.as_mut().unwrap();
        result.aggregate = false;
        result.alignment = 16;
        ir.blocks[0].stmts = vec![Stmt::Ret {
            value: Expr::Apply {
                op: Operation::Results,
                args: vec![
                    Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::reg(2, 64)),
                    Expr::bin(BinOp::Xor, Expr::reg(6, 64), Expr::reg(2, 64)),
                ],
            },
            at: None,
        }];
        let (mut inputs, upper) = aggregate_inputs(&[16, 8], 12);
        let boundaries = [
            0,
            1,
            u64::MAX,
            0x8000_0000_0000_0000,
            0x7fff_ffff_ffff_ffff,
            0x8123_4567_89ab_cdef,
        ];
        for (trial, input) in inputs.iter_mut().enumerate() {
            let row = trial / 3;
            input[0] = boundaries[row % boundaries.len()];
            input[1] = boundaries[(row + 3) % boundaries.len()];
            input[2] = boundaries[(row + 1) % boundaries.len()];
        }
        let batch = aggregate_candidates(ir, inputs, upper);
        assert_eq!(batch.len(), 2);
        assert_aggregate_oracle(&batch, |input, slice| {
            if slice.offset == 0 {
                input[0].wrapping_add(input[2])
            } else {
                input[1] ^ input[2]
            }
        });
        let high = batch
            .iter()
            .find(|candidate| candidate.marshalling.as_ref().unwrap().result.offset == 8)
            .unwrap();
        assert_ne!(
            high.inputs[0][1] ^ high.inputs[0][2],
            high.inputs[3][1] ^ high.inputs[3][2]
        );
        candidates.extend(batch);
    }
    check_candidates(
        "aggregate-scalar-wide-results",
        candidates,
        Mode::Registers,
        &[],
    );
}

#[test]
fn printed_aggregate_parameter_names_preserve_execution() {
    let mut candidates = Vec::new();
    for case in [
        "stack",
        "typedef",
        "duplicates",
        "free",
        "builtin",
        "true",
        "nullptr",
        "constexpr",
    ] {
        let mut ir = integer_object_ir(8, false);
        ir.name = Some(format!("aggregate_name_{case}"));
        let signature = ir.declared_signature.as_mut().unwrap();
        signature.params[0].0 = match case {
            "stack" => "local_0",
            "typedef" => "uint64_t",
            "builtin" => "__builtin_memcpy",
            "duplicates" => "value.x",
            "free" => "bytes",
            _ => case,
        }
        .into();
        if case == "duplicates" {
            signature.params[1].0 = "value-x".into();
        }
        match case {
            "stack" => {
                let address = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const((-8i64) as u64));
                ir.blocks[0].stmts = vec![
                    Stmt::Store {
                        addr: address.clone(),
                        width: 8,
                        value: Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(1)),
                        at: None,
                    },
                    Stmt::Ret {
                        value: Expr::bin(
                            BinOp::Xor,
                            Expr::Load {
                                addr: Box::new(address),
                                width: 8,
                                signed: false,
                            },
                            Expr::reg(6, 64),
                        ),
                        at: None,
                    },
                ];
            }
            "typedef" => {
                ir.blocks[0].stmts = vec![
                    Stmt::Assign {
                        dest: velk::ir::RegRef {
                            index: 7,
                            width: 32,
                        },
                        value: Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(1)),
                        at: None,
                    },
                    Stmt::Ret {
                        value: Expr::bin(BinOp::Xor, Expr::reg(7, 64), Expr::reg(6, 64)),
                        at: None,
                    },
                ];
            }
            _ => {}
        }
        let (inputs, upper) = aggregate_inputs(&[8, 8], 12);
        let batch = aggregate_candidates(ir, inputs, upper);
        assert_aggregate_oracle(&batch, |input, _| {
            let first = match case {
                "stack" => input[0].wrapping_add(1),
                "typedef" => input[0].wrapping_add(1) & 0xffff_ffff,
                _ => input[0],
            };
            first ^ input[1]
        });
        if case == "free" {
            assert!(
                batch[0].code.contains("struct bytes bytes"),
                "{}",
                batch[0].code
            );
        } else if case == "stack" {
            assert!(
                batch[0].code.contains("uint64_t local_0"),
                "{}",
                batch[0].code
            );
        } else if matches!(case, "true" | "nullptr" | "constexpr") {
            assert!(
                batch[0].code.contains(&format!("struct bytes {case}_2")),
                "{}",
                batch[0].code
            );
        }
        candidates.extend(batch);
    }
    check_candidates(
        "aggregate-parameter-names",
        candidates,
        Mode::Registers,
        &[],
    );
}

#[test]
fn printed_indirect_aggregate_copy_keeps_external_stores_observable() {
    let pointer = CType::pointer_to(CType::int(1, false));
    let address = |index, offset| Expr::bin(BinOp::Add, Expr::reg(index, 64), Expr::Const(offset));
    let load = |offset| Expr::Load {
        addr: Box::new(address(0, offset)),
        width: 8,
        signed: false,
    };
    let written = 0xdead_beef_8123_4567;
    let mut ir = synthetic_ir(
        "aggregate_private_copy",
        vec![
            Param {
                index: 0,
                name: "copy".into(),
                ty: pointer.clone(),
            },
            Param {
                index: 1,
                name: "output".into(),
                ty: pointer.clone(),
            },
        ],
        CType::U64,
        vec![
            Stmt::Store {
                addr: address(0, 8),
                value: Expr::Const(written),
                width: 8,
                at: None,
            },
            Stmt::Store {
                addr: Expr::reg(1, 64),
                value: Expr::bin(BinOp::Xor, load(0), load(16)),
                width: 8,
                at: None,
            },
            Stmt::Ret {
                value: load(8),
                at: None,
            },
        ],
    );
    ir.isa = Isa::AArch64;
    ir.convention = Convention::Aapcs64;
    ir.definitions.push(Definition {
        name: "struct private_bytes".into(),
        members: vec!["unsigned char bytes[24];".into()],
        fields: vec!["bytes".into()],
        contains: Vec::new(),
        size: 24,
        alignment: Some(1),
        compatible_profiles: vec![AbiProfile::Aapcs64],
    });
    let scalar = |index| ValueAbi {
        aggregate: false,
        size: 8,
        alignment: 8,
        defined_bits: vec![(0, 64)],
        passing: Passing::Direct(vec![AbiPiece {
            location: AbiLocation::Register(index),
            object_offset: 0,
            bytes: 8,
            class: Some(RegisterClass::Integer),
        }]),
    };
    ir.declared_signature = Some(DeclaredSignature {
        params: vec![
            ("value".into(), CType::Named("struct private_bytes".into())),
            ("output".into(), pointer),
        ],
        ret: CType::U64,
        variadic: false,
        abi: Ok(SignatureAbi {
            profile: AbiProfile::Aapcs64,
            arguments: vec![
                ValueAbi {
                    aggregate: true,
                    size: 24,
                    alignment: 1,
                    defined_bits: vec![(0, 192)],
                    passing: Passing::Indirect {
                        pointer: AbiLocation::Register(0),
                        returned_pointer: None,
                    },
                },
                scalar(1),
            ],
            result: Some(scalar(0)),
        }),
    });
    let (mut inputs, upper) = aggregate_inputs(&[24, 8], 12);
    for input in &mut inputs {
        input[3] = REGION + 0x1800;
    }
    let mut candidates = Vec::new();
    for name in ["value", "uint64_t"] {
        let mut variant = ir.clone();
        variant.name = Some(format!("aggregate_private_copy_{name}"));
        variant.declared_signature.as_mut().unwrap().params[0].0 = name.into();
        candidates.extend(aggregate_candidates(variant, inputs.clone(), upper.clone()));
    }
    let fixture = Fixture {
        name: "aggregate private copy oracle".into(),
        convention: eval::Convention {
            arguments: &[],
            clobbered: &[],
        },
        entry_registers: Vec::new(),
        initial_memory: Vec::new(),
        functions: candidates.len(),
        excluded: BTreeMap::new(),
        candidates: Vec::new(),
    };
    for candidate in &candidates {
        for (trial, input) in candidate.inputs.iter().enumerate() {
            let outcome =
                interpret(&fixture, candidate, trial as u64, input, Mode::Registers).unwrap();
            let expected = (input[0] ^ input[2])
                .to_le_bytes()
                .into_iter()
                .enumerate()
                .map(|(offset, byte)| (input[3] + offset as u64, byte))
                .collect();
            assert_eq!(
                outcome,
                Outcome::Return {
                    value: written,
                    calls: Vec::new(),
                    memory: expected
                }
            );
        }
    }
    check_candidates("aggregate-private-copy", candidates, Mode::Memory, &[]);
}

#[test]
fn printed_aggregate_struct_fixtures_match_independent_oracles() {
    let mut candidates = Vec::new();
    for isa in ["x86_64", "aarch64"] {
        for optimization in ["O0", "O2"] {
            let path = common::fixtures_dir()
                .join(format!("metrics/structs.{isa}.{optimization}.debug.elf"));
            let mut binary = Binary::open(&path).unwrap();
            for name in ["flags_level", "word_low_byte", "point_add", "big_sum"] {
                let address = binary.find(name).unwrap().addr;
                let mut ir = binary.analysis(address, None).unwrap().ir.clone();
                let signature = ir
                    .declared_signature
                    .as_ref()
                    .expect("the source signature");
                let abi = signature.abi.as_ref().expect("the source ABI layout");
                assert_eq!(
                    abi.profile,
                    if isa == "x86_64" {
                        AbiProfile::SysV
                    } else {
                        AbiProfile::Aapcs64
                    }
                );
                assert_struct_fixture_placement(name, abi);
                let sizes: Vec<_> = abi.arguments.iter().map(|argument| argument.size).collect();
                let rows = if matches!(name, "flags_level" | "word_low_byte") {
                    256
                } else {
                    12
                };
                let (mut inputs, mut upper) = aggregate_inputs(&sizes, rows);
                if name == "point_add" {
                    for (a, b) in [
                        (0, 0),
                        (u64::MAX, u64::MAX),
                        (0x7fff_ffff_7fff_ffff, 0x0000_0001_0000_0001),
                        (0x8000_0000_8000_0000, u64::MAX),
                        (0xffff_ffff_0000_0000, 0x0000_0001_ffff_ffff),
                    ] {
                        inputs.push(vec![a, b]);
                        upper.push(0);
                    }
                    if optimization == "O0" {
                        let code = velk::render::render(&ir, &[], &Default::default(), &[]);
                        for field in ["a.x", "a.y", "b.x", "b.y", "result.x", "result.y"] {
                            assert!(code.contains(field), "{isa}: {code}");
                        }
                        assert!(!code.contains("__builtin_memcpy"), "{code}");
                        assert!(!code.contains("*(uint32_t *)"), "{code}");
                        assert!(!code.contains("(uint32_t)"), "{code}");
                        assert!(!code.contains("local_"), "{code}");
                    }
                    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
                    assert!(!code.contains("__builtin_memcpy"), "{code}");
                }
                if name == "big_sum" {
                    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
                    for field in ["value.a", "value.b", "value.c", "value.d"] {
                        assert!(code.contains(field), "{isa}: {code}");
                    }
                    assert!(!code.contains("__builtin_memcpy"), "{code}");
                    assert!(!code.contains("(uint8_t *)"), "{code}");
                }
                ir.name = Some(name.into());
                let mut batch = aggregate_candidates(ir, inputs, upper);
                assert_aggregate_oracle(&batch, |input, _| match name {
                    "flags_level" => {
                        let byte = input[0] as u8;
                        u64::from(if byte & 1 != 0 {
                            byte >> 4
                        } else {
                            (byte >> 1) & 7
                        })
                    }
                    "word_low_byte" => input[0] & 0xff,
                    "point_add" => {
                        let x = (input[0] as u32).wrapping_add(input[1] as u32);
                        let y = ((input[0] >> 32) as u32).wrapping_add((input[1] >> 32) as u32);
                        u64::from(x) | u64::from(y) << 32
                    }
                    "big_sum" => input
                        .iter()
                        .fold(0u64, |sum, value| sum.wrapping_add(*value)),
                    _ => unreachable!(),
                });
                for candidate in &mut batch {
                    candidate.label = format!("{isa} {optimization} {}", candidate.label);
                }
                candidates.extend(batch);
            }
        }
    }
    check_candidates(
        "aggregate-struct-fixtures",
        candidates,
        Mode::Registers,
        &[],
    );
}

fn assert_struct_fixture_placement(name: &str, abi: &SignatureAbi) {
    let x86 = abi.profile == AbiProfile::SysV;
    let direct = |index, bytes| {
        Passing::Direct(vec![AbiPiece {
            location: AbiLocation::Register(index),
            object_offset: 0,
            bytes,
            class: Some(RegisterClass::Integer),
        }])
    };
    let arguments = &abi.arguments;
    let result = abi.result.as_ref().expect("a return layout");
    let first = if x86 { 7 } else { 0 };
    match name {
        "flags_level" | "word_low_byte" => {
            assert_eq!(arguments.len(), 1);
            assert!(arguments[0].aggregate);
            assert_eq!(arguments[0].size, 4);
            assert_eq!(arguments[0].passing, direct(first, 4));
            assert_eq!(
                result.passing,
                direct(0, if name == "flags_level" { 4 } else { 1 })
            );
        }
        "point_add" => {
            assert_eq!(arguments.len(), 2);
            for (argument, index) in arguments.iter().zip(if x86 { [7, 6] } else { [0, 1] }) {
                assert!(argument.aggregate);
                assert_eq!(argument.size, 8);
                assert_eq!(argument.passing, direct(index, 8));
            }
            assert!(result.aggregate);
            assert_eq!(result.size, 8);
            assert_eq!(result.passing, direct(0, 8));
        }
        "big_sum" => {
            assert_eq!(arguments.len(), 1);
            assert!(arguments[0].aggregate);
            assert_eq!(arguments[0].size, 32);
            assert_eq!(
                arguments[0].passing,
                if x86 {
                    Passing::Direct(vec![AbiPiece {
                        location: AbiLocation::Stack(8),
                        object_offset: 0,
                        bytes: 32,
                        class: None,
                    }])
                } else {
                    Passing::Indirect {
                        pointer: AbiLocation::Register(0),
                        returned_pointer: None,
                    }
                }
            );
            assert_eq!(result.passing, direct(0, 8));
        }
        _ => unreachable!(),
    }
}

#[test]
fn sysv_unresolved_alignment_uses_whole_function_fallback() {
    let mut checked = 0;
    let (isa, name) = ("x86_64", "abi_exhaust_seven");
    for optimization in ["O0", "O2"] {
        let path = common::fixtures_dir().join(format!(
            "metrics/aggregate_abi.{isa}.{optimization}.debug.elf"
        ));
        let mut binary = Binary::open(&path).unwrap();
        let address = binary.find(name).unwrap().addr;
        let ir = binary.analysis(address, None).unwrap().ir.clone();
        let signature = ir
            .declared_signature
            .as_ref()
            .expect("the source signature");
        assert_eq!(
            signature.abi,
            Err(velk::ir::AbiIssue::UnknownLayout),
            "{isa} {optimization} {name}"
        );
        let actual = velk::render::render_with_dependencies(&ir, &[], &Default::default(), &[]);
        let mut physical = ir;
        physical.declared_signature = None;
        let expected =
            velk::render::render_with_dependencies(&physical, &[], &Default::default(), &[]);
        assert_eq!(actual, expected, "{isa} {optimization} {name}");
        checked += 1;
    }
    assert_eq!(checked, 2);
}

#[test]
fn printed_aggregate_abi_fixtures_observe_every_result_piece() {
    let mut candidates = Vec::new();
    let mut ordinary = 0;
    let mut aligned = 0;
    for isa in ["x86_64", "aarch64"] {
        for optimization in ["O0", "O2"] {
            let path = common::fixtures_dir().join(format!(
                "metrics/aggregate_abi.{isa}.{optimization}.debug.elf"
            ));
            let mut binary = Binary::open(&path).unwrap();
            for name in [
                "abi_pair_adjust",
                "abi_mixed_adjust",
                "abi_hfa1_adjust",
                "abi_hfa2_adjust",
                "abi_hfa3_adjust",
                "abi_hfa4_adjust",
                "abi_exhaust_five",
                "abi_exhaust_seven",
                "abi_indirect_make",
                "abi_exhaust_five_aligned",
                "abi_exhaust_seven_aligned",
            ] {
                if (isa, name) == ("x86_64", "abi_exhaust_seven") {
                    continue;
                }
                let address = binary.find(name).unwrap().addr;
                let mut ir = binary.analysis(address, None).unwrap().ir.clone();
                let signature = ir
                    .declared_signature
                    .as_ref()
                    .expect("the source signature");
                let abi = signature.abi.as_ref().expect("the source ABI layout");
                assert_eq!(
                    abi.profile,
                    if isa == "x86_64" {
                        AbiProfile::SysV
                    } else {
                        AbiProfile::Aapcs64
                    }
                );
                assert_abi_fixture_placement(name, abi);
                let sizes: Vec<_> = abi.arguments.iter().map(|argument| argument.size).collect();
                let (mut inputs, mut upper) = aggregate_inputs(&sizes, 12);
                if name.starts_with("abi_hfa") {
                    let lanes = sizes[0] as usize / 8;
                    for (trial, input) in inputs.iter_mut().enumerate() {
                        for (lane, value) in
                            [1.25f64, -2.5, 3.75, -4.0].iter().take(lanes).enumerate()
                        {
                            input[lane] = value.to_bits();
                        }
                        input[lanes] = if (trial / 3) % 2 == 0 {
                            0.5f64
                        } else {
                            -0.25f64
                        }
                        .to_bits();
                    }
                } else if name == "abi_mixed_adjust" {
                    for (trial, input) in inputs.iter_mut().enumerate() {
                        input[0] = (-2.5f64).to_bits();
                        input[3] = if (trial / 3) % 2 == 0 {
                            0.5f64
                        } else {
                            -0.25f64
                        }
                        .to_bits();
                    }
                }
                if name == "abi_hfa2_adjust" {
                    for bits in [
                        0,
                        1 << 63,
                        0x7ff0_0000_0000_0000,
                        0x7ff0_0000_0000_0001,
                        0x7ff8_0000_0000_1234,
                    ] {
                        let mut input = inputs[0].clone();
                        input[0] = bits;
                        inputs.push(input);
                        upper.push(0);
                    }
                }
                ir.name = Some(name.into());
                let mut batch = aggregate_candidates(ir, inputs, upper);
                if matches!(name, "abi_hfa1_adjust" | "abi_hfa2_adjust") {
                    for candidate in &batch {
                        assert!(candidate.code.contains("result.a ="), "{}", candidate.code);
                        assert!(
                            !candidate
                                .code
                                .contains("__builtin_memcpy((unsigned char *)&result"),
                            "{}",
                            candidate.code
                        );
                    }
                }
                assert_aggregate_oracle(&batch, |input, slice| {
                    abi_fixture_oracle(name, input, slice)
                });
                if name.starts_with("abi_hfa") {
                    let last_offset = sizes[0] - 8;
                    let last = batch
                        .iter()
                        .find(|candidate| {
                            candidate.marshalling.as_ref().unwrap().result.offset == last_offset
                        })
                        .expect("the last HFA result is observed");
                    let slice = last.marshalling.as_ref().unwrap().result;
                    assert_ne!(
                        abi_fixture_oracle(name, &last.inputs[0], slice),
                        abi_fixture_oracle(name, &last.inputs[3], slice)
                    );
                }
                for candidate in &mut batch {
                    candidate.label = format!("{isa} {optimization} {}", candidate.label);
                }
                if name.ends_with("_aligned") {
                    aligned += 1;
                } else {
                    ordinary += 1;
                }
                candidates.extend(batch);
            }
        }
    }
    assert_eq!(ordinary, 34);
    assert_eq!(aligned, 8);
    assert_eq!(candidates.len(), 82);
    check_candidates("aggregate-abi-fixtures", candidates, Mode::Registers, &[]);
}

fn abi_fixture_oracle(name: &str, input: &[u64], slice: ObjectSlice) -> u64 {
    let name = name.strip_suffix("_aligned").unwrap_or(name);
    let piece = slice.offset as usize / 8;
    match name {
        "abi_pair_adjust" => [input[0].wrapping_add(input[2]), input[1] ^ input[2]][piece],
        "abi_mixed_adjust" => [
            (f64::from_bits(input[0]) + f64::from_bits(input[3])).to_bits(),
            input[1] ^ input[2],
        ][piece],
        "abi_indirect_make" => [
            input[0].wrapping_add(input[2]),
            input[1] ^ input[2],
            input[0].wrapping_sub(input[1]),
        ][piece],
        "abi_exhaust_five" => [1u64, 3, 5, 7, 11, 13, 17, 19]
            .iter()
            .zip(input)
            .fold(0u64, |sum, (coefficient, value)| {
                sum.wrapping_add(coefficient.wrapping_mul(*value))
            }),
        "abi_exhaust_seven" => [1u64, 3, 5, 7, 11, 13, 17, 19, 23, 29]
            .iter()
            .zip(input)
            .fold(0u64, |sum, (coefficient, value)| {
                sum.wrapping_add(coefficient.wrapping_mul(*value))
            }),
        name if name.starts_with("abi_hfa") => {
            let lanes = input.len() - 1;
            if piece + 1 == lanes {
                (f64::from_bits(input[piece]) + f64::from_bits(input[lanes])).to_bits()
            } else {
                input[piece]
            }
        }
        _ => unreachable!(),
    }
}

fn assert_abi_fixture_placement(name: &str, abi: &SignatureAbi) {
    let name = name.strip_suffix("_aligned").unwrap_or(name);
    let x86 = abi.profile == AbiProfile::SysV;
    let integer_registers: &[u16] = if x86 {
        &[7, 6, 2, 1, 8, 9]
    } else {
        &[0, 1, 2, 3, 4, 5, 6, 7]
    };
    let simd = if x86 { 18 } else { 32 };
    let reg = |index, offset, class| AbiPiece {
        location: AbiLocation::Register(index),
        object_offset: offset,
        bytes: 8,
        class: Some(class),
    };
    let integer = |index| Passing::Direct(vec![reg(index, 0, RegisterClass::Integer)]);
    let float = |index| Passing::Direct(vec![reg(index, 0, RegisterClass::Simd)]);
    let pair = |first, second| {
        Passing::Direct(vec![
            reg(first, 0, RegisterClass::Integer),
            reg(second, 8, RegisterClass::Integer),
        ])
    };
    let stack = |offset, bytes| {
        Passing::Direct(vec![AbiPiece {
            location: AbiLocation::Stack(offset),
            object_offset: 0,
            bytes,
            class: None,
        }])
    };
    let hidden = || Passing::Indirect {
        pointer: AbiLocation::Register(if x86 { 7 } else { 8 }),
        returned_pointer: if x86 { Some(0) } else { None },
    };
    let (arguments, result) = match name {
        "abi_pair_adjust" => (
            vec![
                pair(integer_registers[0], integer_registers[1]),
                integer(integer_registers[2]),
            ],
            pair(0, if x86 { 2 } else { 1 }),
        ),
        "abi_mixed_adjust" if x86 => (
            vec![
                Passing::Direct(vec![
                    reg(18, 0, RegisterClass::Simd),
                    reg(7, 8, RegisterClass::Integer),
                ]),
                integer(6),
                float(20),
            ],
            Passing::Direct(vec![
                reg(18, 0, RegisterClass::Simd),
                reg(0, 8, RegisterClass::Integer),
            ]),
        ),
        "abi_mixed_adjust" => (vec![pair(0, 1), integer(2), float(32)], pair(0, 1)),
        "abi_indirect_make" => (
            vec![
                pair(
                    integer_registers[usize::from(x86)],
                    integer_registers[usize::from(x86) + 1],
                ),
                integer(integer_registers[usize::from(x86) + 2]),
            ],
            hidden(),
        ),
        "abi_exhaust_five" => {
            let mut arguments: Vec<_> = integer_registers[..5]
                .iter()
                .copied()
                .map(integer)
                .collect();
            arguments.push(if x86 { stack(8, 16) } else { pair(5, 6) });
            arguments.push(integer(if x86 { 9 } else { 7 }));
            (arguments, integer(0))
        }
        "abi_exhaust_seven" => {
            let mut arguments: Vec<_> = integer_registers
                .iter()
                .take(7)
                .copied()
                .map(integer)
                .collect();
            if x86 {
                arguments.push(stack(8, 8));
            }
            arguments.push(stack(if x86 { 16 } else { 0 }, 16));
            arguments.push(stack(if x86 { 32 } else { 16 }, 8));
            (arguments, integer(0))
        }
        name if name.starts_with("abi_hfa") => {
            let lanes = name.as_bytes()[7] - b'0';
            let hfa = Passing::Direct(
                (0..lanes)
                    .map(|lane| {
                        reg(
                            simd + u16::from(lane) * 2,
                            u64::from(lane) * 8,
                            RegisterClass::Simd,
                        )
                    })
                    .collect(),
            );
            if x86 && lanes > 2 {
                (vec![stack(8, u64::from(lanes) * 8), float(simd)], hidden())
            } else {
                (vec![hfa.clone(), float(simd + u16::from(lanes) * 2)], hfa)
            }
        }
        _ => unreachable!(),
    };
    assert_eq!(abi.arguments.len(), arguments.len(), "{name}");
    for (actual, expected) in abi.arguments.iter().zip(arguments) {
        assert_eq!(actual.passing, expected, "{name}");
    }
    assert_eq!(
        abi.result.as_ref().expect("a result layout").passing,
        result,
        "{name}"
    );
}

fn byte_mask(bytes: u8) -> u64 {
    assert!((1..=8).contains(&bytes));
    u64::MAX >> (64 - u32::from(bytes) * 8)
}

fn aggregate_inputs(sizes: &[u64], rows: u64) -> (Vec<Vec<u64>>, Vec<u64>) {
    let upper_patterns = [0, u64::MAX, 0xa55a_3cc3_9669_f00f];
    let mut inputs = Vec::new();
    let mut upper = Vec::new();
    for row in 0..rows {
        let mut input = Vec::new();
        for (argument, &size) in sizes.iter().enumerate() {
            for part in 0..size.div_ceil(8) {
                let word = eval::hash(row + 0x1020, argument as u64 * 16 + part);
                input.push(if part == 0 {
                    (word & !0xff) | (row & 0xff)
                } else {
                    word
                });
            }
        }
        for pattern in upper_patterns {
            inputs.push(input.clone());
            upper.push(pattern);
        }
    }
    (inputs, upper)
}

fn integer_object_ir(size: u64, aggregate_return: bool) -> FunctionIr {
    let ty = CType::Named("struct bytes".into());
    let pieces: Vec<_> = (0..size)
        .step_by(8)
        .enumerate()
        .map(|(part, offset)| AbiPiece {
            location: AbiLocation::Register([7, 6][part]),
            object_offset: offset,
            bytes: (size - offset).min(8),
            class: Some(RegisterClass::Integer),
        })
        .collect();
    let tail = [6, 2][pieces.len() - 1];
    let mut params: Vec<_> = pieces
        .iter()
        .enumerate()
        .map(|(part, piece)| Param {
            index: match piece.location {
                AbiLocation::Register(index) => index,
                _ => unreachable!(),
            },
            name: format!("piece{part}"),
            ty: CType::U64,
        })
        .collect();
    params.push(Param {
        index: tail,
        name: "tail".into(),
        ty: CType::U64,
    });
    let values: Vec<_> = pieces
        .iter()
        .map(|piece| {
            let AbiLocation::Register(index) = piece.location else {
                unreachable!()
            };
            Expr::bin(
                BinOp::And,
                Expr::reg(index, 64),
                Expr::Const(byte_mask(piece.bytes as u8)),
            )
        })
        .collect();
    let results: Vec<_> = values
        .iter()
        .zip(&pieces)
        .map(|(value, piece)| {
            Expr::bin(
                BinOp::And,
                Expr::bin(BinOp::Xor, value.clone(), Expr::reg(tail, 64)),
                Expr::Const(byte_mask(piece.bytes as u8)),
            )
        })
        .collect();
    let return_type = if aggregate_return {
        ty.clone()
    } else {
        CType::U64
    };
    let expression = if aggregate_return {
        Expr::Apply {
            op: Operation::Results,
            args: results,
        }
    } else {
        values
            .into_iter()
            .fold(Expr::reg(tail, 64), |value, piece| {
                Expr::bin(BinOp::Xor, value, piece)
            })
    };
    let mut ir = synthetic_ir(
        &format!(
            "aggregate_bytes_{size}_{}",
            if aggregate_return { "object" } else { "scalar" }
        ),
        params,
        return_type.clone(),
        vec![Stmt::Ret {
            value: expression,
            at: None,
        }],
    );
    ir.definitions.push(Definition {
        name: ty.to_string(),
        members: vec![format!("unsigned char bytes[{size}];")],
        fields: vec!["bytes".into()],
        contains: Vec::new(),
        size,
        alignment: Some(1),
        compatible_profiles: vec![AbiProfile::SysV],
    });
    let scalar = |index| ValueAbi {
        aggregate: false,
        size: 8,
        alignment: 8,
        defined_bits: vec![(0, 64)],
        passing: Passing::Direct(vec![AbiPiece {
            location: AbiLocation::Register(index),
            object_offset: 0,
            bytes: 8,
            class: Some(RegisterClass::Integer),
        }]),
    };
    let argument = ValueAbi {
        aggregate: true,
        size,
        alignment: 1,
        defined_bits: vec![(0, size * 8)],
        passing: Passing::Direct(pieces.clone()),
    };
    let result = if aggregate_return {
        ValueAbi {
            passing: Passing::Direct(
                pieces
                    .into_iter()
                    .enumerate()
                    .map(|(part, mut piece)| {
                        piece.location = AbiLocation::Register([0, 2][part]);
                        piece
                    })
                    .collect(),
            ),
            ..argument.clone()
        }
    } else {
        scalar(0)
    };
    ir.declared_signature = Some(DeclaredSignature {
        params: vec![("value".into(), ty), ("tail".into(), CType::U64)],
        ret: return_type,
        variadic: false,
        abi: Ok(SignatureAbi {
            profile: AbiProfile::SysV,
            arguments: vec![argument, scalar(tail)],
            result: Some(result),
        }),
    });
    ir
}

#[test]
fn aggregate_result_projection_observes_each_piece() {
    let values = vec![
        Expr::bin(BinOp::Xor, Expr::reg(u16::MAX, 64), Expr::Const(0x1234)),
        Expr::bin(BinOp::Add, Expr::reg(u16::MAX - 1, 64), Expr::Const(1)),
    ];
    let ir = synthetic_ir(
        "aggregate_projection",
        Vec::new(),
        CType::Named("struct result".to_owned()),
        vec![
            Stmt::Store {
                addr: Expr::Const(REGION + 0x100),
                value: Expr::Const(0x5a),
                width: 1,
                at: None,
            },
            Stmt::Ret {
                value: Expr::Apply {
                    op: Operation::Results,
                    args: values.clone(),
                },
                at: None,
            },
        ],
    );
    for selected in 0..2 {
        let projected = project_result(&ir, 2, selected, 8).expect("a complete result");
        assert_eq!(projected.ret_type, CType::U64);
        assert_eq!(projected.blocks[0].stmts.len(), 4);
        let mut temporaries = BTreeSet::new();
        for (index, expected) in values.iter().enumerate() {
            let Stmt::Assign { dest, value, .. } = &projected.blocks[0].stmts[index + 1] else {
                panic!("each result must be evaluated in order")
            };
            assert_eq!(value, expected);
            assert_eq!(dest.width, 64);
            assert!(![u16::MAX, u16::MAX - 1].contains(&dest.index));
            assert!(temporaries.insert(dest.index));
        }
        let Stmt::Assign { dest, .. } = &projected.blocks[0].stmts[selected + 1] else {
            unreachable!()
        };
        let Stmt::Ret { value, .. } = &projected.blocks[0].stmts[3] else {
            panic!("the projection must return its saved result")
        };
        assert_eq!(value, &Expr::reg(dest.index, 64));
        for second in [0xfedc_ba98_7654_3210, 0x8000_0000_0000_0000] {
            let registers = [(u16::MAX, 0x1122_3344_5566_7788), (u16::MAX - 1, second)];
            let run = |source| {
                eval::run(
                    source,
                    &eval::Setup {
                        seed: 1,
                        convention: eval::Convention {
                            arguments: &[],
                            clobbered: &[],
                        },
                        registers: &registers,
                        memory: &[],
                        step_limit: trials::STEP_LIMIT,
                    },
                )
            };
            let Outcome::Return {
                value: original,
                memory: original_memory,
                calls: original_calls,
            } = run(&ir)
            else {
                panic!("the source must return")
            };
            let Outcome::Return {
                value,
                memory,
                calls,
            } = run(&projected)
            else {
                panic!("the projection must return")
            };
            assert_eq!(original, 0x1122_3344_5566_65bc);
            assert_eq!(
                value,
                [0x1122_3344_5566_65bc, second.wrapping_add(1)][selected]
            );
            assert_eq!(memory, original_memory);
            assert_eq!(memory.get(&(REGION + 0x100)), Some(&0x5a));
            assert_eq!(calls, original_calls);
        }
    }
    assert_eq!(ir.blocks[0].stmts.len(), 2);
}

#[test]
fn aggregate_result_projection_keeps_unknown_loads_and_faults() {
    let load = |addr| Expr::Load {
        addr: Box::new(addr),
        width: 8,
        signed: false,
    };
    let source = |second| {
        synthetic_ir(
            "aggregate_projection_load",
            Vec::new(),
            CType::U64,
            vec![Stmt::Ret {
                value: Expr::Apply {
                    op: Operation::Results,
                    args: vec![Expr::Const(7), second],
                },
                at: None,
            }],
        )
    };
    let run = |ir: &FunctionIr, seed| {
        eval::run(
            ir,
            &eval::Setup {
                seed,
                convention: eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &[],
                memory: &[],
                step_limit: trials::STEP_LIMIT,
            },
        )
    };
    let address = REGION + 0x780;
    let unknown = source(load(Expr::Const(address)));
    let mut observed = Vec::new();
    for selected in 0..2 {
        let projected = project_result(&unknown, 2, selected, 8).unwrap();
        let Stmt::Assign { value, .. } = &projected.blocks[0].stmts[1] else {
            panic!("the later load must still be evaluated")
        };
        assert_eq!(value, &load(Expr::Const(address)));
        for seed in [11, 12] {
            let Outcome::Return { value, .. } = run(&projected, seed) else {
                panic!("a hashed load still returns")
            };
            let expected = if selected == 0 {
                7
            } else {
                (0..8).fold(0, |value, byte| {
                    value | (eval::hash(seed, address + byte) & 0xff) << (8 * byte)
                })
            };
            assert_eq!(value, expected);
            if selected == 1 {
                observed.push(value);
            }
        }
    }
    assert_ne!(observed[0], observed[1]);

    let fault = source(load(Expr::bin(BinOp::DivU, Expr::Const(1), Expr::Const(0))));
    assert_eq!(run(&fault, 1), Outcome::Unknown("division by zero"));
    for selected in 0..2 {
        let projected = project_result(&fault, 2, selected, 8).unwrap();
        assert_eq!(run(&projected, 1), Outcome::Unknown("division by zero"));
    }
}

#[test]
fn aggregate_result_projection_validates_returns_and_tail_width() {
    let mut ir = synthetic_ir(
        "aggregate_projection_tail",
        Vec::new(),
        CType::U64,
        vec![Stmt::Ret {
            value: Expr::Const(0xfedc_ba98_7654_3210),
            at: None,
        }],
    );
    for bytes in [1, 2, 3, 4, 5, 6, 7, 8] {
        let projected = project_result(&ir, 1, 0, bytes).unwrap();
        let outcome = eval::run(
            &projected,
            &eval::Setup {
                seed: 0,
                convention: eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &[],
                memory: &[],
                step_limit: trials::STEP_LIMIT,
            },
        );
        let Outcome::Return { value, .. } = outcome else {
            panic!("{outcome:?}")
        };
        let mask = u64::MAX >> (64 - u32::from(bytes) * 8);
        assert_eq!(value, 0xfedc_ba98_7654_3210 & mask);
    }
    for (count, selected, bytes) in [(0, 0, 8), (1, 1, 8), (1, 0, 0), (1, 0, 9)] {
        assert!(project_result(&ir, count, selected, bytes).is_err());
    }
    assert!(project_result(&ir, 2, 0, 8).is_err());
    ir.blocks.push(Block {
        start: 4,
        stmts: vec![Stmt::Ret {
            value: Expr::Apply {
                op: Operation::Results,
                args: vec![Expr::Const(1), Expr::Const(2)],
            },
            at: None,
        }],
    });
    assert!(project_result(&ir, 1, 0, 8).is_err());
    ir.blocks.clear();
    assert!(project_result(&ir, 1, 0, 8).is_err());
}

#[test]
fn segment_provider_rebinding_preserves_other_c_tokens() {
    let code = "provider(); provider_more(); /* provider */\n// provider\n\"provider\\\"\" '\\'';";
    let expected =
        "rebound(); provider_more(); /* provider */\n// provider\n\"provider\\\"\" '\\'';";
    assert_eq!(replace_c_identifier(code, "provider", "rebound"), expected);
}

#[test]
fn segment_providers_need_an_adapter_and_do_not_replace_function_addresses() {
    let state = printed_candidate(
        synthetic_ir(
            "segment_binding",
            Vec::new(),
            CType::U64,
            vec![Stmt::Ret {
                value: Expr::reg(16, 64),
                at: None,
            }],
        ),
        (0..trials::TRIALS).map(|_| Vec::new()).collect(),
    );
    assert_eq!(state.segment_bases.len(), 1);
    assert!(declared_functions(&state.code).is_empty());
    let provider = &state.segment_bases[0].provider;
    let scratch = scratch_dir("segment-binding");
    let unbound = scratch.join("unbound.c");
    std::fs::write(
        &unbound,
        format!(
            "{HEADER}{}\nint main(void) {{ return (int)segment_binding(); }}\n",
            state.code
        ),
    )
    .expect("saved source");
    let syntax = Command::new(compiler())
        .args(FLAGS)
        .arg("-fsyntax-only")
        .arg(&unbound)
        .output()
        .expect("a C compiler");
    assert!(
        syntax.status.success(),
        "{}",
        String::from_utf8_lossy(&syntax.stderr)
    );
    let linked = Command::new(compiler())
        .args(FLAGS)
        .arg(&unbound)
        .arg("-o")
        .arg(scratch.join("unbound"))
        .output()
        .expect("a C compiler");
    assert!(
        !linked.status.success(),
        "a missing state adapter must not link"
    );
    assert!(
        String::from_utf8_lossy(&linked.stderr).contains(provider),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );

    let mut address = printed_candidate(
        synthetic_ir(
            "address_binding",
            Vec::new(),
            CType::U64,
            vec![Stmt::Ret {
                value: Expr::Const(0),
                at: None,
            }],
        ),
        (0..trials::TRIALS).map(|_| Vec::new()).collect(),
    );
    // This address value is checked for compilation and binding, not execution.
    address.code = format!(
        "void {provider}(void);\nuint64_t address_binding(void) {{\n    return (uint64_t)(uintptr_t)&{provider};\n}}\n"
    );
    assert_eq!(declared_functions(&address.code), vec![provider.as_str()]);
    let source = program(&[&state, &address], &[&[], &[]], &[0, 1], Mode::Memory);
    assert!(source.text.contains(&format!("void {provider}(void) {{}}")));
    assert!(!source.text.contains(&format!("uint64_t {provider}(void)")));
    let executable = build(&source, &scratch, "-O0", &[]);
    assert!(executable.is_file());
    std::fs::remove_dir_all(&scratch).ok();
}

#[test]
fn printed_debug_structure_arrays_preserve_indices_and_widths() {
    let mut candidates = Vec::new();
    for case in 0..16 {
        let name = format!("debug_array_{case}");
        let index = if matches!(case, 2 | 14) {
            Expr::SignExtend {
                value: Box::new(Expr::reg(6, 32)),
                width: 4,
            }
        } else {
            Expr::reg(6, 64)
        };
        let stride = if case == 3 { 12 } else { 8 };
        let product = Expr::bin(BinOp::Mul, index, Expr::Const(stride));
        let product = if case == 2 {
            Expr::SignExtend {
                value: Box::new(Expr::bin(BinOp::And, product, Expr::Const(0xffff_ffff))),
                width: 4,
            }
        } else {
            product
        };
        let addr = Expr::bin(
            BinOp::Add,
            Expr::reg(7, 64),
            Expr::bin(
                BinOp::Add,
                product,
                Expr::Const(if case == 5 { 3 } else { 4 }),
            ),
        );
        let mut ir = synthetic_ir(
            &name,
            vec![
                Param {
                    index: 7,
                    name: "items".into(),
                    ty: CType::pointer_to(CType::Named("struct item".into())),
                },
                Param {
                    index: 6,
                    name: "i".into(),
                    ty: match case {
                        1 => CType::I64,
                        14 => CType::I32,
                        _ => CType::U64,
                    },
                },
            ],
            CType::U64,
            vec![Stmt::Ret {
                value: Expr::Load {
                    addr: Box::new(addr),
                    width: if case == 4 { 1 } else { 2 },
                    signed: true,
                },
                at: None,
            }],
        );
        ir.definitions = vec![Definition {
            name: "struct item".into(),
            members: vec![
                "int32_t count;".into(),
                "int16_t kind;".into(),
                "uint8_t gap_0x6[0x2];".into(),
            ],
            fields: vec!["count".into(), "kind".into()],
            contains: vec![],
            size: 8,
            alignment: Some(4),
            compatible_profiles: vec![AbiProfile::SysV],
        }];
        ir.members = vec![
            Member {
                structure: "item".into(),
                offset: 0,
                name: "count".into(),
                ty: CType::I32,
                width: 4,
            },
            Member {
                structure: "item".into(),
                offset: 4,
                name: "kind".into(),
                ty: CType::int(2, true),
                width: 2,
            },
        ];
        match case {
            6 => ir.definitions[0].size = 0,
            7 => ir.definitions[0].alignment = Some(1),
            8 => ir.definitions[0].compatible_profiles.clear(),
            9 => ir.members[1].offset = 3,
            10 => ir.members[1].width = 1,
            11 => ir.definitions.push(ir.definitions[0].clone()),
            12 => ir.definitions[0].members[1] = "int16_t kind : 8;".into(),
            13 => {
                ir.definitions[0].name = "union choice".into();
                ir.params[0].ty = CType::pointer_to(CType::Named("union choice".into()));
            }
            _ => {}
        }
        let code = velk::render::render(&ir, &[], &Default::default(), &[]);
        if !(2..14).contains(&case) {
            assert!(code.contains("struct item {"), "{code}");
        }
        assert_eq!(
            code.contains("].kind"),
            !(2..14).contains(&case),
            "{name}: {code}"
        );
        ir.params.push(Param {
            index: 2,
            name: "value".into(),
            ty: CType::U64,
        });
        let Stmt::Ret {
            value: Expr::Load { addr, .. },
            ..
        } = &ir.blocks[0].stmts[0]
        else {
            unreachable!()
        };
        let addr = *addr.clone();
        ir.blocks[0].stmts.insert(
            0,
            Stmt::Store {
                addr,
                value: Expr::reg(2, 64),
                width: 2,
                at: None,
            },
        );
        if case == 15 {
            ir.params.push(Param {
                index: 1,
                name: "count".into(),
                ty: CType::I32,
            });
            let count_addr = Expr::bin(
                BinOp::Add,
                Expr::reg(7, 64),
                Expr::bin(BinOp::Mul, Expr::reg(6, 64), Expr::Const(8)),
            );
            ir.blocks[0].stmts.insert(
                0,
                Stmt::Store {
                    addr: count_addr.clone(),
                    value: Expr::reg(1, 32),
                    width: 4,
                    at: None,
                },
            );
            let Some(Stmt::Ret { value, .. }) = ir.blocks[0].stmts.last_mut() else {
                unreachable!()
            };
            *value = Expr::bin(
                BinOp::And,
                Expr::bin(
                    BinOp::Mul,
                    value.clone(),
                    Expr::Load {
                        addr: Box::new(count_addr),
                        width: 4,
                        signed: false,
                    },
                ),
                Expr::Const(0xffff_ffff),
            );
        }
        let mut inputs = Vec::new();
        for index in [0u64, 1, 2, u64::MAX, u64::MAX - 1] {
            let index = if case == 2 {
                index & 0xffff_ffff
            } else {
                index
            };
            for short in [0u64, 0x7fff, 0x8000, 0xffff] {
                if case == 15 {
                    for count in [0x7fff_ffff, 0x8000_0000, 0xffff_ffff] {
                        inputs.push(vec![REGION + 0x8000, index, short, count]);
                    }
                } else {
                    inputs.push(vec![REGION + 0x8000, index, short]);
                }
            }
        }
        if case == 2 {
            inputs.push(vec![REGION + 0x8000, 0x2000_0001, 0x8000]);
        }
        if case < 2 {
            for index in [0x1_0000_0001u64, 0xffff_fffe_ffff_ffff] {
                inputs.push(vec![
                    (REGION + 0x8000).wrapping_sub(index.wrapping_mul(8)),
                    index,
                    0x8000,
                ]);
            }
        }
        if case == 0 {
            let mut address_ir = ir.clone();
            address_ir.name = Some("debug_array_address".into());
            address_ir.blocks[0].stmts = vec![Stmt::Ret {
                value: Expr::bin(
                    BinOp::Add,
                    Expr::reg(7, 64),
                    Expr::bin(BinOp::Mul, Expr::reg(6, 64), Expr::Const(8)),
                ),
                at: None,
            }];
            let candidate = printed_candidate(address_ir, inputs.clone());
            assert!(
                candidate.code.contains("struct item {"),
                "{}",
                candidate.code
            );
            assert!(candidate.code.contains("items + i"), "{}", candidate.code);
            candidates.push(candidate);
        }
        let mut candidate = printed_candidate(ir, inputs);
        if !(2..14).contains(&case) {
            candidate.code.push_str("\n_Static_assert(sizeof(struct item) == 8, \"size\");\n_Static_assert(offsetof(struct item, kind) == 4, \"offset\");\n");
        }
        candidates.push(candidate);
    }
    check_candidates("debug_arrays", candidates, Mode::Memory, &[]);
}

fn synthetic_ir(name: &str, params: Vec<Param>, ret_type: CType, stmts: Vec<Stmt>) -> FunctionIr {
    FunctionIr {
        isa: Isa::X86_64,
        convention: Convention::SysV,
        declared_signature: None,
        params,
        stack_params: Vec::new(),
        stack_spills: None,
        debug_locals: Vec::new(),
        debug_registers: Vec::new(),
        debug_globals: Vec::new(),
        variadic: false,
        ret_type,
        accesses: Vec::new(),
        members: Vec::new(),
        definitions: Vec::new(),
        structures: Vec::new(),
        signed_params: Default::default(),
        landing_pads: Vec::new(),
        pointer_values: Vec::new(),
        saved_slots: Vec::new(),
        frame_bottom: 0,
        callee_signatures: Default::default(),
        value_types: Default::default(),
        variable_registers: Default::default(),
        addr: 0,
        name: Some(name.to_owned()),
        size: 0,
        blocks: vec![Block { start: 0, stmts }],
    }
}

fn printed_candidate(ir: FunctionIr, inputs: Vec<Vec<u64>>) -> Candidate {
    let rendered = velk::render::render_with_dependencies(&ir, &[], &Default::default(), &[]);
    let states = if rendered.segment_bases.is_empty() {
        Vec::new()
    } else {
        segment_states()
    };
    Candidate {
        marshalling: None,
        label: ir.name.clone().expect("a named synthetic function"),
        code: rendered.code,
        segment_bases: rendered.segment_bases,
        states,
        params: ir.params.iter().map(|param| param.ty.to_string()).collect(),
        inputs,
        void: ir.ret_type == CType::Void,
        ir,
    }
}

#[test]
fn printed_signed_division_skips_an_unrelated_shift() {
    check_signed_select_search(false);
}

#[test]
fn printed_signed_remainder_skips_an_unresolved_select_arm() {
    check_signed_select_search(true);
}

fn check_signed_select_search(remainder: bool) {
    let assign = |index, value| Stmt::Assign {
        dest: velk::ir::RegRef { index, width: 64 },
        value,
        at: None,
    };
    let select = |adjusted| Expr::Select {
        cond: Cond::Ge,
        lhs: Box::new(Expr::reg(7, 64)),
        rhs: Box::new(Expr::Const(0)),
        then: Box::new(Expr::reg(7, 64)),
        els: Box::new(Expr::reg(adjusted, 64)),
    };
    let name = if remainder {
        "remainder_after_unresolved_arm"
    } else {
        "division_after_unrelated_shift"
    };
    let mut candidates = Vec::new();
    for blocked in [false, true] {
        let mut stmts = if !blocked {
            Vec::new()
        } else if remainder {
            vec![
                assign(40, select(6)),
                assign(
                    41,
                    Expr::bin(BinOp::And, Expr::reg(40, 64), Expr::Const(!7)),
                ),
                assign(
                    42,
                    Expr::bin(BinOp::Sub, Expr::reg(7, 64), Expr::reg(41, 64)),
                ),
            ]
        } else {
            vec![assign(
                42,
                Expr::bin(BinOp::Sar, Expr::reg(6, 64), Expr::Const(1)),
            )]
        };
        stmts.extend([
            assign(43, Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(7))),
            assign(44, select(43)),
        ]);
        if remainder {
            stmts.extend([
                assign(
                    45,
                    Expr::bin(BinOp::And, Expr::reg(44, 64), Expr::Const(!7)),
                ),
                assign(
                    46,
                    Expr::bin(BinOp::Sub, Expr::reg(7, 64), Expr::reg(45, 64)),
                ),
            ]);
        } else {
            stmts.push(assign(
                46,
                Expr::bin(BinOp::Sar, Expr::reg(44, 64), Expr::Const(3)),
            ));
        }
        stmts.push(Stmt::Ret {
            value: if blocked {
                Expr::bin(BinOp::Xor, Expr::reg(42, 64), Expr::reg(46, 64))
            } else {
                Expr::reg(46, 64)
            },
            at: None,
        });
        let original = synthetic_ir(
            &format!("{name}_{blocked}"),
            vec![
                Param {
                    index: 7,
                    name: "x".into(),
                    ty: CType::I64,
                },
                Param {
                    index: 6,
                    name: "y".into(),
                    ty: CType::I64,
                },
            ],
            CType::I64,
            stmts,
        );
        let mut ir = original.clone();
        velk::passes::division::recover_divisions(&mut ir);
        velk::passes::dce::dce(&mut ir);
        let values = [
            i64::MIN,
            i64::MIN + 7,
            -17,
            -9,
            -8,
            -7,
            -1,
            0,
            1,
            7,
            8,
            9,
            17,
            i64::MAX,
        ];
        let inputs = values
            .iter()
            .flat_map(|x| values.iter().map(move |y| vec![*x as u64, *y as u64]))
            .collect();
        let mut candidate = printed_candidate(ir, inputs);
        let operator = if remainder { "x % 8" } else { "x / 8" };
        assert!(candidate.code.contains(operator), "{}", candidate.code);
        candidate.ir = original;
        candidates.push(candidate);
    }
    check_candidates(name, candidates, Mode::Registers, &[]);
}

#[test]
fn printed_void_calls_keep_existing_values_in_both_output_paths() {
    use velk::ir::{CallOutput, RegRef, Registers, VARIABLE_BASE};

    let mut text = String::from(HEADER);
    text.push_str("static unsigned void_calls;\nstatic void void_callee(void) { ++void_calls; }\n");
    let symbols = velk::render::Symbols {
        functions: [(0x1000, "void_callee".to_owned())].into(),
        function_returns: [(0x1000, CType::Void)].into(),
        ..Default::default()
    };
    for (name, dest) in [("void_direct", VARIABLE_BASE), ("void_snapshot", 2)] {
        let ir = synthetic_ir(
            name,
            vec![Param {
                index: 7,
                name: "value".to_owned(),
                ty: CType::U64,
            }],
            CType::U64,
            vec![
                Stmt::Call {
                    abi: None,
                    kind: velk::ir::CallKind::Invoke,
                    target: Some(0x1000),
                    through: None,
                    convention: Convention::SysV,
                    args: Some(vec![]),
                    floats_named: true,
                    outputs: vec![
                        CallOutput {
                            register: 7,
                            dest: RegRef {
                                index: 7,
                                width: 64,
                            },
                        },
                        CallOutput {
                            register: 0,
                            dest: RegRef {
                                index: dest,
                                width: 64,
                            },
                        },
                    ],
                    clobbers: Some(Registers((1 << 7) | 1)),
                    via: None,
                    at: None,
                },
                Stmt::Ret {
                    value: Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::reg(dest, 64)),
                    at: None,
                },
            ],
        );
        let printed = velk::render::render(&ir, &[], &symbols, &[]);
        assert!(!printed.contains("also returned by the call"), "{printed}");
        assert_eq!(printed.contains("call_values"), dest == 2, "{printed}");
        text.push_str(&printed);
    }
    text.push_str("int main(void) { if (void_direct(UINT64_C(0x100000005)) != UINT64_C(0x100000005)) return 1; if (void_snapshot(17) != 17) return 2; return void_calls != 2; }\n");
    let source = Program {
        text,
        ranges: Vec::new(),
    };
    let scratch = scratch_dir("void-call-outputs");
    for level in LEVELS {
        let program = build(&source, &scratch, level, &["-Werror=int-conversion"]);
        assert_eq!(run(&program, ""), "");
    }
    std::fs::remove_dir_all(&scratch).ok();
}

#[test]
fn printed_call_outputs_preserve_dependencies_and_run_once() {
    use velk::ir::{CallOutput, RegRef, Registers, VARIABLE_BASE};

    let (first, second) = (VARIABLE_BASE, VARIABLE_BASE + 1);
    let output = |register, index, width| CallOutput {
        register,
        dest: RegRef { index, width },
    };
    let mut text = String::from(HEADER);
    text.push_str(
        r#"
static uint64_t output_calls, output_argument;
static uint64_t output_callee(uint64_t value) {
    ++output_calls;
    output_argument = value;
    return value ^ UINT64_C(0x8123456789abcdef);
}
"#,
    );
    let symbols = velk::render::Symbols {
        functions: [(0x1000, "output_callee".to_owned())].into(),
        function_returns: [(0x1000, CType::U64)].into(),
        ..Default::default()
    };
    for (name, outputs, argument, direct) in [
        (
            "independent_outputs",
            vec![output(2, second, 32), output(0, first, 64)],
            Expr::reg(7, 64),
            true,
        ),
        (
            "swapped_outputs",
            vec![output(7, 6, 64), output(6, 7, 64)],
            Expr::reg(7, 64),
            false,
        ),
        (
            "later_source",
            vec![output(0, 7, 64), output(7, second, 64)],
            Expr::reg(6, 64),
            false,
        ),
        (
            "destination_argument",
            vec![output(0, first, 64), output(6, second, 32)],
            Expr::bin(BinOp::Add, Expr::reg(first, 64), Expr::Const(1)),
            false,
        ),
    ] {
        let (returned_first, returned_second) = match name {
            "swapped_outputs" => (7, 6),
            "later_source" => (7, second),
            _ => (first, second),
        };
        let ir = synthetic_ir(
            name,
            vec![
                Param {
                    index: 7,
                    name: "left".to_owned(),
                    ty: CType::U64,
                },
                Param {
                    index: 6,
                    name: "right".to_owned(),
                    ty: CType::U64,
                },
            ],
            CType::U64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: first,
                        width: 64,
                    },
                    value: Expr::reg(7, 64),
                    at: None,
                },
                Stmt::Assign {
                    dest: RegRef {
                        index: second,
                        width: 64,
                    },
                    value: Expr::reg(6, 64),
                    at: None,
                },
                Stmt::Assign {
                    dest: RegRef {
                        index: 2,
                        width: 64,
                    },
                    value: Expr::reg(6, 64),
                    at: None,
                },
                Stmt::Call {
                    kind: velk::ir::CallKind::Invoke,
                    target: Some(0x1000),
                    through: None,
                    convention: Convention::SysV,
                    args: Some(vec![argument]),
                    floats_named: true,
                    abi: None,
                    outputs,
                    clobbers: Some(Registers(if direct { 5 } else { 1 })),
                    via: None,
                    at: None,
                },
                Stmt::Ret {
                    value: Expr::bin(
                        if name == "swapped_outputs" {
                            BinOp::Sub
                        } else {
                            BinOp::Xor
                        },
                        Expr::reg(returned_first, 64),
                        Expr::reg(returned_second, 64),
                    ),
                    at: None,
                },
            ],
        );
        let printed = velk::render::render(&ir, &[], &symbols, &[]);
        assert_eq!(!printed.contains("call_values"), direct, "{printed}");
        let body = velk::render::Prelude::default().extract(&printed);
        assert_eq!(body.matches("output_callee(").count(), 1, "{printed}");
        if direct {
            assert!(printed.contains("v1 = output_callee(left);"), "{printed}");
            assert!(
                printed.contains("v2 = (uint32_t)(v3); /* also returned by the call */"),
                "{printed}"
            );
        }
        text.push_str(&printed);
    }
    text.push_str(
        r#"
int main(void) {
    uint64_t left, right;
    while (scanf("%" SCNx64 " %" SCNx64, &left, &right) == 2) {
        uint64_t expected[] = {
            (left ^ UINT64_C(0x8123456789abcdef)) ^ (uint32_t)right,
            right - left,
            (right ^ UINT64_C(0x8123456789abcdef)) ^ left,
            ((left + 1) ^ UINT64_C(0x8123456789abcdef)) ^ (uint32_t)right
        };
        uint64_t arguments[] = {left, left, right, left + 1};
        uint64_t (*functions[])(uint64_t, uint64_t) = {
            independent_outputs, swapped_outputs, later_source, destination_argument
        };
        for (unsigned i = 0; i < 4; ++i) {
            output_calls = 0;
            uint64_t actual = functions[i](left, right);
            if (actual != expected[i] || output_calls != 1 || output_argument != arguments[i]) return 1;
        }
    }
    puts("ok");
    return 0;
}
"#,
    );
    let source = Program {
        text,
        ranges: Vec::new(),
    };
    let scratch = scratch_dir("call-outputs");
    for level in LEVELS {
        let program = build(&source, &scratch, level, &["-Werror=int-conversion"]);
        assert_eq!(
            run(
                &program,
                "0 100000005\nffffffffffffffff 8123456789abcdef\n31 17\n"
            ),
            "ok\n"
        );
    }
    std::fs::remove_dir_all(&scratch).ok();
}

#[test]
fn printed_calls_share_snapshots_across_control_flow_and_recursion() {
    use velk::ir::{CallOutput, RegRef, Registers};

    let output = |register, index, width| CallOutput {
        register,
        dest: RegRef { index, width },
    };
    let call = |target, wide| Stmt::Call {
        kind: velk::ir::CallKind::Invoke,
        target: Some(target),
        through: None,
        convention: Convention::SysV,
        args: Some(vec![Expr::reg(7, 64), Expr::reg(6, 64), Expr::reg(2, 64)]),
        floats_named: true,
        abi: None,
        outputs: if wide {
            vec![output(7, 6, 64), output(6, 7, 32), output(0, 2, 64)]
        } else {
            vec![output(7, 6, 64), output(6, 7, 64)]
        },
        clobbers: Some(Registers(1)),
        via: None,
        at: None,
    };
    let returned = Stmt::Ret {
        value: Expr::bin(BinOp::Xor, Expr::reg(7, 64), Expr::reg(6, 64)),
        at: None,
    };
    let mut text = String::from(HEADER);
    text.push_str("static uint64_t recurse(uint64_t, uint64_t, uint64_t);\n");
    text.push_str("static uint64_t helper(uint64_t a, uint64_t b, uint64_t depth) { return depth ? recurse(a, b, depth - 1) : a + b; }\n");
    for name in ["sequential", "branches", "loops", "recurse"] {
        let mut ir = synthetic_ir(
            name,
            [(7, "left"), (6, "right"), (2, "depth")]
                .into_iter()
                .map(|(index, name)| Param {
                    index,
                    name: name.into(),
                    ty: CType::U64,
                })
                .collect(),
            CType::U64,
            vec![call(0x1000, false), call(0x1000, true), returned.clone()],
        );
        if name == "branches" {
            ir.blocks[0].stmts = vec![Stmt::Brif {
                cond: Cond::Eq,
                lhs: Expr::reg(2, 64),
                rhs: Expr::Const(0),
                target: 0x20,
                at: None,
            }];
            ir.blocks.extend([
                Block {
                    start: 0x10,
                    stmts: vec![call(0x1000, false), returned.clone()],
                },
                Block {
                    start: 0x20,
                    stmts: vec![call(0x1000, true), returned.clone()],
                },
            ]);
        } else if name == "loops" {
            let counter = velk::ir::VARIABLE_BASE;
            ir.blocks[0].stmts = vec![
                call(0x1000, false),
                Stmt::Assign {
                    dest: RegRef {
                        index: counter,
                        width: 64,
                    },
                    value: Expr::Const(2),
                    at: None,
                },
            ];
            ir.blocks.extend([
                Block {
                    start: 0x10,
                    stmts: vec![
                        call(0x1000, true),
                        Stmt::Assign {
                            dest: RegRef {
                                index: counter,
                                width: 64,
                            },
                            value: Expr::bin(BinOp::Sub, Expr::reg(counter, 64), Expr::Const(1)),
                            at: None,
                        },
                        Stmt::Brif {
                            cond: Cond::Ne,
                            lhs: Expr::reg(counter, 64),
                            rhs: Expr::Const(0),
                            target: 0x10,
                            at: None,
                        },
                    ],
                },
                Block {
                    start: 0x20,
                    stmts: vec![returned.clone()],
                },
            ]);
        }
        // Keep the scalar result live so the larger block needs all three slots.
        for block in &mut ir.blocks {
            if matches!(block.stmts.last(), Some(Stmt::Ret { .. })) {
                block.stmts.pop();
                block.stmts.push(Stmt::Ret {
                    value: Expr::bin(
                        BinOp::Xor,
                        Expr::bin(BinOp::Xor, Expr::reg(7, 64), Expr::reg(6, 64)),
                        Expr::reg(2, 64),
                    ),
                    at: None,
                });
            }
        }
        let symbols = velk::render::Symbols {
            functions: [(0x1000, "helper".to_owned())].into(),
            function_returns: [(0x1000, CType::U64)].into(),
            ..Default::default()
        };
        let printed = velk::render::render(&ir, &[], &symbols, &[]);
        assert_eq!(
            printed.matches("uint64_t call_values[").count(),
            1,
            "{printed}"
        );
        assert!(printed.contains("uint64_t call_values[3];"), "{printed}");
        text.push_str(&printed);
    }
    text.push_str(
        r#"
static uint64_t expected(uint64_t a, uint64_t b, uint64_t d) {
    uint64_t value = d ? expected(b, a, d - 1) : b + a;
    return b ^ (uint32_t)a ^ value;
}
int main(void) {
    uint64_t values[] = {0, 1, UINT64_C(0x8123456789abcdef), UINT64_MAX};
    for (unsigned i = 0; i < 4; ++i) for (unsigned j = 0; j < 4; ++j) {
        uint64_t a = values[i], b = values[j];
        for (uint64_t d = 0; d < 4; ++d) {
            uint64_t want = expected(a, b, d);
            if (sequential(a, b, d) != want || recurse(a, b, d) != want) return 1;
        }
        if (branches(a, b, 0) != (a ^ (uint32_t)b ^ (a + b))) return 2;
        if (branches(a, b, 1) != (a ^ b ^ 1)) return 3;
    }
    if (loops(0, 0, 0) != 0) return 4;
    if (loops(UINT64_MAX, 1, 0) != UINT64_C(0x1fffffffe)) return 5;
    puts("ok");
    return 0;
}
"#,
    );
    let source = Program {
        text,
        ranges: Vec::new(),
    };
    let scratch = scratch_dir("shared-call-results");
    for level in LEVELS {
        let program = build(&source, &scratch, level, &[]);
        assert_eq!(run(&program, ""), "ok\n");
    }
    std::fs::remove_dir_all(&scratch).ok();
}

#[test]
fn printed_address_literals_preserve_all_bits() {
    let mut text = String::from(
        "typedef __UINT64_TYPE__ uint64_t;\ntypedef __UINTPTR_TYPE__ uintptr_t;\n_Static_assert(sizeof(uint64_t) == 8 && sizeof(uintptr_t) == 8, \"64-bit addresses\");\nint main(void) {\n",
    );
    for address in [
        0,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_ffff,
        0x1_0000_0000,
        0x8000_0000_0000_0000,
        u64::MAX - 1,
    ] {
        let ir = synthetic_ir(
            "address_literal",
            Vec::new(),
            CType::U64,
            vec![Stmt::Ret {
                value: Expr::Load {
                    addr: Box::new(Expr::Const(address)),
                    width: 8,
                    signed: false,
                },
                at: None,
            }],
        );
        let printed = velk::render::render(&ir, &[], &Default::default(), &[(address, 1)]);
        let declaration = printed
            .lines()
            .find(|line| line.starts_with("extern "))
            .unwrap_or_else(|| panic!("{printed}"));
        assert!(
            declaration.contains(&format!("/* address: 0x{address:x} */")),
            "{printed}"
        );
        let name = declaration
            .strip_prefix("extern uint64_t ")
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let check = bound_globals(&format!(
            "{declaration}\nif ((uint64_t)(uintptr_t)&{name} != 0x{address:x}ULL || &{name} != (uint64_t *)(uintptr_t)0x{address:x}) return 1;"
        ));
        writeln!(text, "{{\n{check}\n}}").unwrap();
    }
    text.push_str("return 0;\n}\n");
    let source = Program {
        text,
        ranges: Vec::new(),
    };
    let scratch = scratch_dir("address-literals");
    for level in LEVELS {
        let program = build(&source, &scratch, level, &["-Wall", "-Wextra", "-Werror"]);
        assert_eq!(run(&program, ""), "");
        let cross = Command::new(compiler())
            .args([
                "-target",
                "aarch64-none-elf",
                "-ffreestanding",
                "-Wall",
                "-Wextra",
                "-Werror",
                level,
                "-c",
            ])
            .arg(scratch.join(format!("check{level}.c")))
            .arg("-o")
            .arg(scratch.join(format!("address{level}.o")))
            .output()
            .expect("a C compiler");
        assert!(
            cross.status.success(),
            "{}",
            String::from_utf8_lossy(&cross.stderr)
        );
    }
    std::fs::remove_dir_all(&scratch).ok();
}

#[test]
fn printed_call_address_conversions_preserve_types_and_widths() {
    use velk::ir::{CallOutput, RegRef, Registers, VARIABLE_BASE};

    let dest = VARIABLE_BASE;
    let pointer = CType::pointer_to(CType::U64);
    let mut text = String::from(HEADER);
    text.push_str(
        r#"
static uint64_t address_calls, address_object = UINT64_C(0x123456789abcdef);
static uint64_t address_integer(uint64_t value) { ++address_calls; return value; }
static uint64_t *address_pointer(uint64_t value) { ++address_calls; return (uint64_t *)value; }
static uint64_t *address_allocate(uint64_t value) { ++address_calls; (void)value; return &address_object; }
static uint32_t address_unsigned(uint64_t value) { ++address_calls; return (uint32_t)value; }
static int32_t address_signed(uint64_t value) { ++address_calls; return (int32_t)value; }
"#,
    );
    let symbols = velk::render::Symbols {
        functions: [
            (0x1000, "address_integer".to_owned()),
            (0x2000, "address_pointer".to_owned()),
            (0x3000, "address_allocate".to_owned()),
            (0x4000, "address_unsigned".to_owned()),
            (0x5000, "address_signed".to_owned()),
        ]
        .into(),
        function_returns: [
            (0x1000, CType::U64),
            (0x2000, pointer.clone()),
            (0x3000, pointer.clone()),
            (0x4000, CType::U32),
            (0x5000, CType::I32),
        ]
        .into(),
        ..Default::default()
    };
    for (name, target, width, stored, returned) in [
        (
            "integer_to_pointer",
            0x1000,
            64,
            pointer.clone(),
            pointer.clone(),
        ),
        (
            "pointer_to_pointer",
            0x2000,
            64,
            pointer.clone(),
            pointer.clone(),
        ),
        ("pointer_to_integer", 0x2000, 64, CType::U64, CType::U64),
        ("narrow_pointer", 0x2000, 32, CType::U64, CType::U64),
        ("unsigned_integer", 0x4000, 32, CType::U32, CType::U32),
        ("signed_integer", 0x5000, 32, CType::I32, CType::I32),
        (
            "allocated_pointer",
            0x3000,
            64,
            pointer.clone(),
            pointer.clone(),
        ),
    ] {
        for mode in ["scalar", "direct", "snapshot"] {
            let second = if mode == "snapshot" { 2 } else { dest + 1 };
            let mut outputs = vec![CallOutput {
                register: 0,
                dest: RegRef { index: dest, width },
            }];
            if mode != "scalar" {
                outputs.push(CallOutput {
                    register: 2,
                    dest: RegRef {
                        index: second,
                        width: 32,
                    },
                });
            }
            let mut stmts = vec![Stmt::Call {
                kind: velk::ir::CallKind::Invoke,
                target: Some(target),
                through: None,
                convention: Convention::SysV,
                args: Some(vec![Expr::reg(7, 64)]),
                floats_named: true,
                abi: None,
                outputs,
                clobbers: Some(Registers(1)),
                via: None,
                at: None,
            }];
            if mode != "scalar" {
                stmts.push(Stmt::Store {
                    addr: Expr::reg(6, 64),
                    value: Expr::reg(second, 64),
                    width: 8,
                    at: None,
                });
            }
            stmts.push(Stmt::Ret {
                value: Expr::reg(dest, width),
                at: None,
            });
            let mut ir = synthetic_ir(
                &format!("{name}_{mode}"),
                vec![
                    Param {
                        index: 7,
                        name: "value".to_owned(),
                        ty: CType::U64,
                    },
                    Param {
                        index: 2,
                        name: "saved".to_owned(),
                        ty: CType::U64,
                    },
                    Param {
                        index: 6,
                        name: "sink".to_owned(),
                        ty: pointer.clone(),
                    },
                ],
                returned.clone(),
                stmts,
            );
            ir.value_types.insert(dest, stored.clone());
            let printed = velk::render::render(&ir, &[], &symbols, &[]);
            assert!(!printed.contains("uintptr_t"), "{printed}");
            assert_eq!(
                printed.contains("call_values"),
                mode == "snapshot",
                "{printed}"
            );
            if matches!(name, "pointer_to_pointer" | "allocated_pointer") && mode != "snapshot" {
                let callee = &symbols.functions[&target];
                let assignment = if mode == "scalar" { "return" } else { "v1 =" };
                assert!(
                    printed.contains(&format!("{assignment} {callee}(value);")),
                    "{printed}"
                );
            }
            if matches!(name, "unsigned_integer" | "signed_integer") && mode == "direct" {
                assert!(
                    printed.contains(&format!("v1 = {}(value);", symbols.functions[&target])),
                    "{printed}"
                );
            }
            text.push_str(&printed);
        }
    }
    text.push_str(
        r#"
int main(void) {
    uint64_t value;
    while (scanf("%" SCNx64, &value) == 1) {
"#,
    );
    for mode in ["scalar", "direct", "snapshot"] {
        writeln!(text, r#"{{
        uint64_t sink = 0;
        address_calls = 0;
        if ((uint64_t)integer_to_pointer_{mode}(value, value, &sink) != value) return 1;
        if ((uint64_t)pointer_to_pointer_{mode}(value, value, &sink) != value) return 2;
        if (pointer_to_integer_{mode}(value, value, &sink) != value) return 3;
        if (narrow_pointer_{mode}(value, value, &sink) != (uint32_t)value) return 4;
        if (unsigned_integer_{mode}(value, value, &sink) != (uint32_t)value) return 7;
        if ((uint32_t)signed_integer_{mode}(value, value, &sink) != (uint32_t)value) return 8;
        uint64_t *allocated = allocated_pointer_{mode}(value, value, &sink);
        if (allocated != &address_object || *allocated != address_object || address_calls != 7) return 5;
        if (sink != {}) return 6;
        }}"#, if mode == "scalar" { "0" } else { "(uint32_t)value" }).unwrap();
    }
    text.push_str("}\nputs(\"ok\");\nreturn 0;\n}\n");
    let source = Program {
        text,
        ranges: Vec::new(),
    };
    let scratch = scratch_dir("call-addresses");
    for level in LEVELS {
        let program = build(
            &source,
            &scratch,
            level,
            &[
                "-Werror=int-conversion",
                "-Werror=incompatible-pointer-types",
            ],
        );
        assert_eq!(
            run(
                &program,
                "0\n7fffffff\n80000000\nffffffff\n100000000\n8123456789abcdef\nffffffffffffffff\n"
            ),
            "ok\n"
        );
    }
    std::fs::remove_dir_all(&scratch).ok();
}

#[test]
fn printed_physical_call_arguments_preserve_zero_extended_values() {
    let mut text = String::from(HEADER);
    text.push_str(
        r#"
#include <string.h>
static uint64_t width_argument, width_calls;
static __attribute__((noinline)) uint64_t width_callee(uint64_t value) {
    width_argument = value;
    ++width_calls;
    return value ^ UINT64_C(0x8123456789abcdef);
}
"#,
    );
    let mut symbols = velk::render::Symbols::default();
    symbols.functions.insert(0x1000, "width_callee".to_owned());
    symbols.function_returns.insert(0x1000, CType::U64);
    for (name, ty) in [
        ("width_input_i32", CType::I32),
        ("width_input_i64", CType::I64),
    ] {
        let mut ir = synthetic_ir(
            name,
            vec![Param {
                index: 7,
                name: "input".to_owned(),
                ty,
            }],
            CType::U64,
            vec![
                Stmt::Call {
                    kind: velk::ir::CallKind::Invoke,
                    target: Some(0x1000),
                    through: None,
                    convention: Convention::SysV,
                    args: Some(vec![Expr::bin(
                        BinOp::And,
                        Expr::reg(7, 64),
                        Expr::Const(0xffff_ffff),
                    )]),
                    floats_named: true,
                    abi: None,
                    outputs: velk::ir::fallback_call_outputs(Convention::SysV, None),
                    clobbers: None,
                    via: None,
                    at: None,
                },
                Stmt::Assign {
                    dest: velk::ir::RegRef {
                        index: velk::ir::VARIABLE_BASE,
                        width: 64,
                    },
                    value: Expr::reg(0, 64),
                    at: None,
                },
                Stmt::Ret {
                    value: Expr::reg(velk::ir::VARIABLE_BASE, 64),
                    at: None,
                },
            ],
        );
        velk::ssa::take_results_directly(&mut ir);
        text.push_str(&velk::render::render(&ir, &[], &symbols, &[]));
    }
    text.push_str(
        r#"
int main(void) {
    unsigned which;
    uint64_t raw;
    while (scanf("%u %" SCNx64, &which, &raw) == 2) {
        uint32_t low = (uint32_t)raw;
        int32_t input32;
        int64_t input64;
        memcpy(&input32, &low, sizeof input32);
        memcpy(&input64, &raw, sizeof input64);
        width_argument = width_calls = 0;
        uint64_t result = which == 0 ? width_input_i32(input32) : width_input_i64(input64);
        printf("%" PRIx64 " %" PRIx64 " %" PRIx64 "\n", result, width_argument, width_calls);
    }
    return 0;
}
"#,
    );
    let inputs = [
        0,
        1,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_ffff,
        0x1122_3344_0000_0000,
        0x8123_4567_89ab_cdef,
        u64::MAX,
    ];
    let mut rows = Vec::new();
    let mut requests = String::new();
    let mut changed = [false; 2];
    for (which, differs) in changed.iter_mut().enumerate() {
        for raw in inputs {
            let entry = if which == 0 {
                (raw as u32 as i32 as i64) as u64
            } else {
                raw
            };
            let projected = u64::from(raw as u32);
            *differs |= entry != projected;
            rows.push((which, raw, projected ^ 0x8123_4567_89ab_cdef, projected));
            writeln!(requests, "{which} {raw:x}").unwrap();
        }
    }
    assert_eq!(changed, [true, true]);
    assert_eq!(rows.len(), 16);
    let source = Program {
        text,
        ranges: Vec::new(),
    };
    let scratch = scratch_dir("call-argument-width");
    for level in LEVELS {
        let program = build(&source, &scratch, level, &[]);
        let output = run(&program, &requests);
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(lines.len(), rows.len(), "{level}: {output}");
        for ((which, raw, result, argument), line) in rows.iter().zip(lines) {
            let actual: Vec<_> = line
                .split_whitespace()
                .map(|word| u64::from_str_radix(word, 16).expect("a hexadecimal result"))
                .collect();
            assert_eq!(
                actual,
                vec![*result, *argument, 1],
                "{level} input{which}({raw:#x}): {line}"
            );
        }
    }
    std::fs::remove_dir_all(&scratch).ok();
}

#[test]
fn single_use_structure_addresses_preserve_printed_memory_reads() {
    let variable = velk::ir::VARIABLE_BASE;
    let address = Expr::bin(
        BinOp::Add,
        Expr::reg(7, 64),
        Expr::bin(BinOp::Mul, Expr::reg(6, 64), Expr::Const(24)),
    );
    let mut candidates = Vec::new();
    for case in 0..6 {
        let value = match case {
            1 => Expr::Load {
                addr: Box::new(address.clone()),
                width: 8,
                signed: false,
            },
            2 => Expr::bin(BinOp::DivU, address.clone(), Expr::reg(6, 64)),
            _ => address.clone(),
        };
        let read = Expr::Load {
            addr: Box::new(Expr::bin(
                BinOp::Add,
                Expr::reg(variable, 64),
                Expr::Const(8),
            )),
            width: 8,
            signed: false,
        };
        let mut stmts = vec![Stmt::Assign {
            dest: velk::ir::RegRef {
                index: variable,
                width: 64,
            },
            value,
            at: None,
        }];
        if case == 4 {
            stmts.push(Stmt::Assign {
                dest: velk::ir::RegRef {
                    index: 6,
                    width: 64,
                },
                value: Expr::Const(2),
                at: None,
            });
        }
        stmts.push(Stmt::Ret {
            value: if case == 3 {
                Expr::bin(BinOp::Add, read.clone(), read)
            } else {
                read
            },
            at: None,
        });
        let mut ir = synthetic_ir(
            &format!("record_value_{case}"),
            vec![
                Param {
                    index: 7,
                    name: "items".into(),
                    ty: CType::pointer_to(CType::Named("struct record".into())),
                },
                Param {
                    index: 6,
                    name: "index".into(),
                    ty: CType::U64,
                },
            ],
            CType::U64,
            stmts,
        );
        ir.structures.push(velk::ir::Structure {
            name: "record".into(),
            fields: vec![(0, CType::U64), (8, CType::U64), (16, CType::U64)],
            size: Some(24),
            elements: vec![variable],
        });
        ir.value_types.insert(
            variable,
            CType::pointer_to(CType::Named("struct record".into())),
        );
        if case == 5 {
            let reader = ir.blocks[0].stmts.pop().expect("the return");
            ir.blocks[0].stmts.push(Stmt::Brif {
                cond: Cond::Eq,
                lhs: Expr::reg(6, 64),
                rhs: Expr::Const(0),
                target: 0x20,
                at: None,
            });
            ir.blocks.extend([
                Block {
                    start: 0x10,
                    stmts: vec![reader],
                },
                Block {
                    start: 0x20,
                    stmts: vec![Stmt::Ret {
                        value: Expr::Const(0),
                        at: None,
                    }],
                },
            ]);
        }
        let original = ir.clone();
        velk::passes::read_once::fold_values_read_once(&mut ir);
        let render = |ir: &FunctionIr| {
            velk::render::render_with_dependencies(ir, &[], &Default::default(), &[]).code
        };
        let code = render(&ir);
        if case == 0 {
            assert!(!code.contains("*v1;"), "{code}");
            assert!(code.contains("struct record {"), "{code}");
            assert!(code.contains("items[index].f_8"), "{code}");
        } else {
            assert_eq!(code, render(&original));
        }
        if case == 0 || case >= 3 {
            let mut candidate = printed_candidate(
                ir,
                vec![vec![0x3000_0000_0000, 0], vec![0x3000_0000_0000, 1]],
            );
            candidate.ir = original;
            candidates.push(candidate);
        }
    }
    check_candidates("structure-addresses", candidates, Mode::Memory, &[]);
}

fn check_candidates(name: &str, candidates: Vec<Candidate>, mode: Mode, compiler_args: &[&str]) {
    let count = candidates.len();
    let runs = candidates
        .iter()
        .map(|candidate| candidate.inputs.len())
        .sum();
    let fixture = Fixture {
        name: name.into(),
        convention: eval::Convention {
            arguments: Convention::SysV.arguments(),
            clobbered: &[],
        },
        entry_registers: Vec::new(),
        initial_memory: Vec::new(),
        functions: count,
        excluded: BTreeMap::new(),
        candidates,
    };
    let scratch = scratch_dir(name);
    let results = check(&[fixture], &scratch, mode, compiler_args);
    assert_comparison_runs(&results[0], count, runs);
    std::fs::remove_dir_all(&scratch).ok();
}

fn assert_comparisons(result: &Findings, count: usize) {
    assert_comparison_runs(result, count, count * trials::TRIALS as usize);
}

fn assert_comparison_runs(result: &Findings, count: usize, runs: usize) {
    assert!(result.lines.is_empty(), "{}", result.lines.join("\n"));
    assert!(result.skipped.is_empty(), "{:?}", result.skipped);
    assert_eq!(result.compiled, count);
    assert_eq!(result.failed, 0);
    assert_eq!(result.compared, count);
    assert_eq!(result.runs, runs);
    assert_eq!(result.differing, 0);
}

fn compare(mode: Mode, golden: &str) {
    if Command::new(compiler()).arg("--version").output().is_err() {
        eprintln!(
            "skipping: no `{}` to compile the pseudo-C with",
            compiler().display()
        );
        return;
    }
    let started = std::time::Instant::now();
    let fixtures = common::fixtures();
    let prepared = common::in_parallel(&fixtures, |fixture| prepare(fixture, mode));
    eprintln!(
        "recompile prepare {golden}: {:.3}s",
        started.elapsed().as_secs_f64()
    );
    let scratch = scratch_dir(match mode {
        Mode::Registers => "registers",
        Mode::Memory => "memory",
    });
    let results = check_parallel(&prepared, &scratch, mode);
    std::fs::remove_dir_all(&scratch).ok();

    let mut excluded: BTreeMap<&str, usize> = BTreeMap::new();
    let mut skipped: BTreeMap<&str, usize> = BTreeMap::new();
    let mut header = String::new();
    let mut lines = Vec::new();
    for (fixture, result) in prepared.iter().zip(&results) {
        if fixture.name.to_string_lossy().contains(".win64.") {
            assert_eq!(
                result.failed,
                0,
                "{}: {:?}",
                fixture.name.display(),
                result.lines
            );
        }
        assert_eq!(
            result.differing,
            0,
            "{}: {:?}",
            fixture.name.display(),
            result.lines
        );
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
    convention: eval::Convention<'static>,
    entry_registers: Vec<(u16, u64)>,
    initial_memory: Vec<(u64, u64)>,
    functions: usize,
    excluded: BTreeMap<&'static str, usize>,
    candidates: Vec<Candidate>,
}

struct Candidate {
    label: String,
    ir: FunctionIr,
    code: String,
    segment_bases: Vec<SegmentBaseRead>,
    states: Vec<SegmentState>,
    marshalling: Option<AggregateCall>,
    params: Vec<String>,
    /// Each trial's argument values, in parameter order.
    inputs: Vec<Vec<u64>>,
    /// It returns nothing, so only its effects compare.
    void: bool,
}

#[derive(Debug, Clone)]
struct AggregateCall {
    signature: DeclaredSignature,
    result: ObjectSlice,
    upper_bits: Vec<u64>,
}

#[derive(Debug, Clone, Copy)]
struct ObjectSlice {
    offset: u64,
    bytes: u8,
    mask: u64,
}

const AGGREGATE_STORAGE: u64 = eval::STACK_TOP - 0x10_0000;
const AGGREGATE_RESULT: u64 = AGGREGATE_STORAGE + 0x2_0000;

#[derive(Debug, Clone)]
struct SegmentState {
    fs: Option<u64>,
    gs: Option<u64>,
    memory: Vec<(u64, u64)>,
}

impl SegmentState {
    fn base(&self, segment: SegmentBase) -> Option<u64> {
        match segment {
            SegmentBase::Fs => self.fs,
            SegmentBase::Gs => self.gs,
        }
    }
}

fn segment_word(trial: u64, context: u64, slot: u64) -> u64 {
    0x8123_4567_89ab_cdef ^ (trial << 32) ^ (context << 16) ^ slot
}

fn segment_states() -> Vec<SegmentState> {
    (0..trials::TRIALS)
        .map(|trial| {
            let mut memory = Vec::new();
            for context in 0..2 {
                let fs = REGION + 0x1000 + context * 0x1000;
                let gs = REGION + 0x3000 + context * 0x1000;
                let target = REGION + 0x6000 + context * 0x1000;
                let nested = if context == 0 {
                    0
                } else {
                    0x8000_0000_0000_0001
                };
                memory.extend([
                    (fs, target),
                    (fs - 8, segment_word(trial, context, 1)),
                    (fs + 8, segment_word(trial, context, 2)),
                    (gs, segment_word(trial, context, 3)),
                    (gs - 8, segment_word(trial, context, 4)),
                    (gs + 8, segment_word(trial, context, 5)),
                    (target - 0x20, nested),
                    (fs - 0x20, u64::from(nested == 0)),
                ]);
            }
            SegmentState {
                fs: Some(REGION + 0x1000 + (trial % 2) * 0x1000),
                gs: Some(REGION + 0x3000 + (trial % 2) * 0x1000),
                memory,
            }
        })
        .collect()
}

fn segment_state(candidate: &Candidate, trial: u64) -> Result<Option<&SegmentState>, &'static str> {
    if candidate.segment_bases.is_empty() && candidate.states.is_empty() {
        return Ok(None);
    }
    if candidate.states.len() != trials::TRIALS as usize {
        return Err("segment state is required for every trial");
    }
    let state = &candidate.states[trial as usize];
    for dependency in &candidate.segment_bases {
        let Some(base) = state.base(dependency.segment) else {
            return Err("a required segment base is missing");
        };
        if !(REGION..REGION + REGION_SIZE).contains(&base) {
            return Err("the controlled segment base is outside the region");
        }
    }
    if state.memory.iter().any(|(addr, _)| {
        *addr < REGION
            || addr
                .checked_add(8)
                .is_none_or(|end| end > REGION + REGION_SIZE)
    }) {
        return Err("segment memory is outside the region");
    }
    Ok(Some(state))
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
        let Ok(analysis) = binary.analysis(function.addr, None) else {
            *excluded.entry("does not lift").or_default() += 1;
            continue;
        };
        if let Err(reason) = qualifies(&analysis.ir, analysis.references.is_empty(), mode) {
            *excluded.entry(reason).or_default() += 1;
            continue;
        }
        let ir = analysis.ir.clone();
        let rendered = binary
            .decompile_with_dependencies(function.addr, None, None)
            .unwrap_or_else(|error| panic!("{error}"));
        if mode == Mode::Registers && !rendered.segment_bases.is_empty() {
            *excluded.entry("requires segment state").or_default() += 1;
            continue;
        }
        let code = rendered.code;
        // Register inputs outside the signature have no defined C value.
        // Inspect the IR so the exclusion does not depend on local names.
        if ir.blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
            if matches!(stmt, Stmt::Ret { .. }) && ir.ret_type == CType::Void {
                return false;
            }
            velk::ir::visit::statement_reads(stmt)
                .into_iter()
                .any(|index| {
                    index < velk::ir::TEMP_BASE
                        && index != velk::arch::stack_pointer(ir.isa)
                        && !ir.params.iter().any(|param| param.index == index)
                        && machine_register(&velk::ir::reg_name(ir.isa, index, 64))
                })
        }) {
            *excluded
                .entry("reads a register that is not a parameter")
                .or_default() += 1;
            continue;
        }
        let image = binary.image();
        let mut inputs: Vec<Vec<u64>> = (0..trials::TRIALS)
            .map(|trial| {
                let registers = trials::registers(image, trial);
                ir.params
                    .iter()
                    .enumerate()
                    .map(|(position, param)| {
                        // A pointer points into the region, each its own part.
                        if param.ty.is_pointer() {
                            return region_start(image.isa)
                                + 0x2000
                                + 0x2000 * (position as u64 % 6);
                        }
                        if let Some(register) = trials::register_pair(&ir, param) {
                            return trials::pair_input(register, &registers, trial);
                        }
                        registers
                            .iter()
                            .find(|(register, _)| *register == param.index)
                            .map_or_else(|| eval::hash(trial, u64::from(param.index)), |r| r.1)
                    })
                    .collect()
            })
            .collect();
        let marshalling = physical_stack_call(&ir, inputs.len());
        if marshalling.is_some() {
            for (trial, input) in inputs.iter_mut().enumerate() {
                input.extend(
                    ir.stack_params
                        .iter()
                        .map(|param| incoming_stack_word(trial as u64, param.offset)),
                );
            }
        }
        let params = if let Some(call) = &marshalling {
            call.signature
                .params
                .iter()
                .map(|(_, ty)| ty.to_string())
                .collect()
        } else {
            ir.params.iter().map(|param| param.ty.to_string()).collect()
        };
        candidates.push(Candidate {
            marshalling,
            label: format!(
                "{} {} {}",
                fixture.display(),
                velk::addr::format(function.addr),
                function.name.as_deref().unwrap_or("-")
            ),
            params,
            void: ir.ret_type == CType::Void,
            states: if rendered.segment_bases.is_empty() {
                Vec::new()
            } else {
                segment_states()
            },
            segment_bases: rendered.segment_bases,
            ir,
            code,
            inputs,
        });
    }
    Fixture {
        name: fixture.to_owned(),
        convention: trials::convention(binary.image()),
        entry_registers: trials::entry_state(binary.image()),
        initial_memory: trials::initial_memory(binary.image()),
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
    if let Some(ret) = std::iter::once(&ir.ret_type)
        .chain(ir.declared_signature.iter().map(|signature| &signature.ret))
        .find(|ty| !value(ty) && !(memory && **ty == CType::Void))
    {
        return Err(if *ret == CType::Void {
            "returns nothing"
        } else {
            "returns no integer"
        });
    }
    if ir.variadic || (!ir.stack_params.is_empty() && physical_stack_signature(ir).is_none()) {
        return Err("takes arguments on the stack");
    }
    if !ir
        .params
        .iter()
        .map(|param| &param.ty)
        .chain(
            ir.declared_signature
                .iter()
                .flat_map(|signature| signature.params.iter().map(|(_, ty)| ty)),
        )
        .all(value)
    {
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
            Stmt::Machine {
                instruction: velk::ir::MachineInstruction::Atomic { .. },
                ..
            } if !memory => return Err("accesses memory"),
            Stmt::Machine {
                instruction: velk::ir::MachineInstruction::Atomic { .. },
                ..
            } => {}
            Stmt::Machine { .. } => return Err("requires an external machine-state source"),
            Stmt::Unsupported { .. } => return Err("has an unsupported instruction"),
            Stmt::BrifFlags { .. } => return Err("branches on flags"),
            Stmt::Assign { .. }
            | Stmt::Brif { .. }
            | Stmt::Br { .. }
            | Stmt::Switch { .. }
            | Stmt::Ret { .. }
            | Stmt::Trap { .. } => {}
        }
        for operand in stmt.operands() {
            if let Err(reason) = pure(operand, memory) {
                return Err(reason);
            }
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
    matches!(stmt, Stmt::Store { .. })
        || matches!(
            stmt,
            Stmt::Machine {
                instruction: velk::ir::MachineInstruction::Atomic { .. },
                ..
            }
        )
        || stmt.operands().into_iter().any(loads)
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
                !name
                    .split_whitespace()
                    .any(|word| ["float", "double", "struct", "union", "class"].contains(&word))
            }
        }
        CType::Void | CType::Pointer(_) | CType::Array(_) | CType::Function { .. } => false,
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
    skipped: BTreeMap<String, usize>,
    lines: Vec<String>,
}

/// What a run of the compiled code printed.
#[derive(Clone, PartialEq)]
enum ExecutionOutcome {
    /// The result, and the region's checksum after the run in the memory
    /// pass.
    Value(u64, Option<u64>),
    Other(String),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
enum ExpectedOutcome {
    Return { value: u64 },
    Trap,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Interpretation {
    outcome: ExpectedOutcome,
    checksum: Option<u64>,
}

/// A run the interpreter finished: the function, the trial, the
/// arguments as the parameters hold them, and the outcome.
struct Expected {
    function: usize,
    trial: u64,
    arguments: Vec<u64>,
    outcome: ExpectedOutcome,
    /// The region's checksum after the run, in the memory pass.
    checksum: Option<u64>,
}

/// Compiles each group at both optimization levels and compares every run.
fn check(
    fixtures: &[Fixture],
    scratch: &Path,
    mode: Mode,
    compiler_args: &[&str],
) -> Vec<Findings> {
    fixtures
        .iter()
        .map(|fixture| check_fixture(fixture, scratch, mode, compiler_args))
        .collect()
}

fn check_parallel(fixtures: &[Fixture], scratch: &Path, mode: Mode) -> Vec<Findings> {
    let mut batches = Vec::new();
    for (index, fixture) in fixtures.iter().enumerate() {
        for candidates in fixture.candidates.chunks(32) {
            batches.push((index, candidates));
        }
    }
    let indexed: Vec<_> = batches.iter().enumerate().collect();
    let checked = common::in_parallel(&indexed, |(index, (fixture, candidates))| {
        let directory = scratch.join(index.to_string());
        std::fs::create_dir_all(&directory)
            .unwrap_or_else(|error| panic!("{}: {error}", directory.display()));
        let candidates: Vec<&Candidate> = candidates.iter().collect();
        check_batch(&fixtures[*fixture], &candidates, &directory, mode, &[])
    });
    let mut results: Vec<Findings> = fixtures.iter().map(|_| Findings::default()).collect();
    for ((index, _), batch) in batches.iter().zip(checked) {
        let result = &mut results[*index];
        result.compiled += batch.compiled;
        result.failed += batch.failed;
        result.compared += batch.compared;
        result.runs += batch.runs;
        result.differing += batch.differing;
        for (reason, count) in batch.skipped {
            *result.skipped.entry(reason).or_default() += count;
        }
        result.lines.extend(batch.lines);
    }
    results
}

fn check_fixture(
    fixture: &Fixture,
    scratch: &Path,
    mode: Mode,
    compiler_args: &[&str],
) -> Findings {
    let candidates: Vec<&Candidate> = fixture.candidates.iter().collect();
    check_batch(fixture, &candidates, scratch, mode, compiler_args)
}

fn check_batch(
    fixture: &Fixture,
    candidates: &[&Candidate],
    scratch: &Path,
    mode: Mode,
    compiler_args: &[&str],
) -> Findings {
    let mut arguments = compiler_args.to_vec();
    if cfg!(target_os = "macos")
        && candidates
            .first()
            .is_some_and(|candidate| velk::arch::pointer_bytes(candidate.ir.isa) == 4)
    {
        arguments.extend(["-arch", "x86_64", "-Wl,-pagezero_size,0x1000"]);
    }
    let compiler_args = arguments.as_slice();
    let started = std::time::Instant::now();
    let mut result = Findings::default();
    let initial_memory = vec![fixture.initial_memory.as_slice(); candidates.len()];
    for candidate in candidates {
        for trial in 0..candidate.inputs.len() as u64 {
            segment_state(candidate, trial)
                .unwrap_or_else(|reason| panic!("{}: {reason}", candidate.label));
        }
    }
    if candidates.is_empty() {
        return result;
    }
    let source = program(
        candidates,
        &initial_memory,
        &(0..candidates.len()).collect::<Vec<_>>(),
        mode,
    );
    let inputs: Vec<_> = candidates
        .iter()
        .map(|candidate| &candidate.inputs)
        .collect();
    let cache = cache::Cache::new(&source.text, &inputs, compiler_args);
    let syntax_started = std::time::Instant::now();
    let (alive, failures) = cache.get_or_compute("syntax", &(), || {
        compiles(candidates, &initial_memory, &scratch.join("check.c"), mode)
    });
    let syntax_seconds = syntax_started.elapsed().as_secs_f64();
    for (index, message) in &failures {
        let candidate = candidates[*index];
        result.failed += 1;
        result
            .lines
            .push(format!("{}: does not compile: {message}", candidate.label));
    }
    result.compiled = alive.len();
    if alive.is_empty() {
        return result;
    }
    let source = program(candidates, &initial_memory, &alive, mode);
    let build_seconds = std::cell::Cell::new(0.0);
    let mut programs = None;
    let mut build_programs = || {
        programs
            .get_or_insert_with(|| {
                let start = std::time::Instant::now();
                let built = LEVELS
                    .iter()
                    .map(|level| build(&source, scratch, level, compiler_args))
                    .collect::<Vec<_>>();
                build_seconds.set(build_seconds.get() + start.elapsed().as_secs_f64());
                built
            })
            .clone()
    };

    // The arguments as the parameters' types hold them.
    let mut requests = String::new();
    for &index in &alive {
        for input in &candidates[index].inputs {
            requests.push_str(&request('c', index, input));
        }
    }
    let canonical_started = std::time::Instant::now();
    let printed = cache.get_or_compute_if(
        "canonical",
        &(&source.text, &requests),
        || run(&build_programs()[0], &requests),
        |output| can_cache_run(output),
    );
    let canonical_seconds = canonical_started.elapsed().as_secs_f64();
    let interpretation_started = std::time::Instant::now();
    let mut canonical = printed.lines().map(|line| {
        line.split_whitespace()
            .map(|word| u64::from_str_radix(word, 16).expect("a hex value"))
            .collect::<Vec<u64>>()
    });
    let mut expected = Vec::new();
    for &index in &alive {
        let candidate = candidates[index];
        let mut arguments = Vec::new();
        for _ in &candidate.inputs {
            arguments.push(canonical.next().unwrap_or_default());
        }
        if arguments.is_empty() {
            continue;
        }
        // Another function's address differs between the binary and
        // the compiled program.
        if !declared_functions(&candidate.code).is_empty() {
            *result
                .skipped
                .entry("takes a function's address".to_owned())
                .or_default() += arguments.len();
            continue;
        }
        let interpreted = interpretations(fixture, candidate, &arguments, mode);
        let trials = arguments.into_iter().zip(interpreted).enumerate();
        for (trial, (arguments, interpreted)) in trials {
            match interpreted {
                Ok(interpreted) => expected.push(Expected {
                    function: index,
                    trial: trial as u64,
                    arguments,
                    checksum: interpreted.checksum,
                    outcome: interpreted.outcome,
                }),
                Err(reason) => *result.skipped.entry(reason).or_default() += 1,
            }
        }
    }

    let interpretation_seconds = interpretation_started.elapsed().as_secs_f64();
    let execution_started = std::time::Instant::now();
    let mut requests = String::new();
    for run in &expected {
        let seed = (mode == Mode::Memory).then_some(run.trial);
        requests.push_str(&request_run(run.function, seed, &run.arguments));
    }
    let expectations: Vec<_> = expected
        .iter()
        .map(|run| match &run.outcome {
            ExpectedOutcome::Return { value } => format!("value {value:x} {:?}", run.checksum),
            ExpectedOutcome::Trap => "trap".to_owned(),
        })
        .collect();
    let printed: Vec<String> = cache.get_or_compute_if(
        "execute",
        &(&source.text, &requests, expectations),
        || {
            build_programs()
                .iter()
                .map(|program| run(program, &requests))
                .collect()
        },
        |outputs: &Vec<String>| outputs.iter().all(|output| can_cache_run(output)),
    );
    let execution_seconds = execution_started.elapsed().as_secs_f64();
    let comparison_started = std::time::Instant::now();
    let outputs: Vec<Vec<ExecutionOutcome>> = printed
        .iter()
        .map(|output| {
            let mut ran: Vec<ExecutionOutcome> =
                output.lines().map(parse_execution_outcome).collect();
            ran.resize(
                expected.len(),
                ExecutionOutcome::Other("the program stopped".to_owned()),
            );
            ran
        })
        .collect();

    let mut agreeing: BTreeMap<usize, bool> = BTreeMap::new();
    for (position, run) in expected.iter().enumerate() {
        let candidate = candidates[run.function];
        // An address no page can be mapped at, as one past the 48 bits of
        // addresses, leaves the compiled code nothing to read there.
        if outputs
            .iter()
            .any(|ran| ran[position] == ExecutionOutcome::Other("unreachable".to_owned()))
        {
            *result
                .skipped
                .entry("reaches memory no page can map".to_owned())
                .or_default() += 1;
            continue;
        }
        result.runs += 1;
        let differing: Vec<(&str, &ExecutionOutcome)> = LEVELS
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
            (ExpectedOutcome::Return { value }, None) => format!("0x{:x}", value & mask(candidate)),
            (ExpectedOutcome::Return { value }, Some(sum)) => {
                format!("0x{:x} and memory {sum:x}", value & mask(candidate))
            }
            _ => "a trap".to_owned(),
        };
        result.lines.push(format!(
            "{}: trial {} ({}): pseudo-C gives {}, IR gives {wanted} ({})",
            candidate.label,
            run.trial,
            shown.join(", "),
            printed.join(", "),
            candidate.ir.ret_type
        ));
    }
    for same in agreeing.into_values() {
        result.compared += 1;
        result.differing += usize::from(!same);
    }
    eprintln!(
        "recompile phase {}: total={:.3} syntax={syntax_seconds:.3} canonical={canonical_seconds:.3} interpret={interpretation_seconds:.3} execute={execution_seconds:.3} build={:.3} compare={:.3}",
        fixture.name.display(),
        started.elapsed().as_secs_f64(),
        build_seconds.get(),
        comparison_started.elapsed().as_secs_f64()
    );
    result
}

fn project_result(
    ir: &FunctionIr,
    count: usize,
    selected: usize,
    bytes: u8,
) -> Result<FunctionIr, &'static str> {
    if count == 0 || selected >= count || !(1..=8).contains(&bytes) {
        return Err("invalid result projection");
    }
    let mut used: std::collections::HashSet<u16> =
        ir.params.iter().map(|param| param.index).collect();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        used.extend(velk::ir::visit::statement_reads(stmt));
        used.extend(stmt.call_clobbers());
        match stmt {
            Stmt::Assign { dest, .. } => {
                used.insert(dest.index);
            }
            Stmt::Call { outputs, .. } => {
                used.extend(outputs.iter().map(|output| output.dest.index));
            }
            Stmt::Unsupported { .. } => return Err("cannot project an unsupported statement"),
            _ => {}
        }
    }
    let temporaries: Vec<u16> = (0..=u16::MAX)
        .rev()
        .filter(|index| !used.contains(index))
        .take(count)
        .collect();
    if temporaries.len() != count {
        return Err("no registers remain for the result projection");
    }
    let mut projected = ir.clone();
    projected.ret_type = CType::U64;
    projected.declared_signature = None;
    let mut returns = 0;
    for block in &mut projected.blocks {
        let mut statements = Vec::new();
        for stmt in std::mem::take(&mut block.stmts) {
            let Stmt::Ret { value, .. } = stmt else {
                statements.push(stmt);
                continue;
            };
            let values = match value {
                Expr::Apply {
                    op: Operation::Results,
                    args,
                } => args,
                value if count == 1 => vec![value],
                _ => return Err("return does not hold all result pieces"),
            };
            if values.len() != count {
                return Err("return has a different result piece count");
            }
            // Keep every operand evaluation, including faults in another piece.
            for (index, value) in values.into_iter().enumerate() {
                statements.push(Stmt::Assign {
                    dest: velk::ir::RegRef {
                        index: temporaries[index],
                        width: 64,
                    },
                    value,
                    at: None,
                });
            }
            let value = Expr::reg(temporaries[selected], 64);
            statements.push(Stmt::Ret {
                value: if bytes == 8 {
                    value
                } else {
                    Expr::bin(BinOp::And, value, Expr::Const((1u64 << (8 * bytes)) - 1))
                },
                at: None,
            });
            returns += 1;
        }
        block.stmts = statements;
    }
    if returns == 0 {
        return Err("result projection needs a return");
    }
    Ok(projected)
}

fn object_mask(value: &ValueAbi, offset: u64, bytes: u8) -> u64 {
    (0..u64::from(bytes) * 8).fold(0, |mask, bit| {
        let position = offset * 8 + bit;
        if value
            .defined_bits
            .iter()
            .any(|&(start, count)| (start..start + count).contains(&position))
        {
            mask | (1 << bit)
        } else {
            mask
        }
    })
}

fn aggregate_candidates(
    ir: FunctionIr,
    inputs: Vec<Vec<u64>>,
    upper_bits: Vec<u64>,
) -> Vec<Candidate> {
    let signature = ir.declared_signature.as_ref().expect("a logical signature");
    let abi = signature.abi.as_ref().expect("a supported ABI");
    assert_eq!(signature.params.len(), abi.arguments.len());
    assert!(!signature.variadic);
    assert_eq!(inputs.len(), upper_bits.len());
    let words: usize = abi
        .arguments
        .iter()
        .map(|arg| arg.size.div_ceil(8) as usize)
        .sum();
    assert!(words <= 16);
    assert!(inputs.iter().all(|input| input.len() == words));
    for value in abi.arguments.iter().chain(abi.result.iter()) {
        value.validate().expect("a valid object ABI");
    }
    for ((_, ty), value) in signature.params.iter().zip(&abi.arguments) {
        assert_aggregate_definition(&ir, ty, value, abi.profile);
    }
    if let Some(result) = &abi.result {
        assert_aggregate_definition(&ir, &signature.ret, result, abi.profile);
    }
    let result = abi.result.as_ref().expect("an observable returned object");
    let direct = match &result.passing {
        Passing::Direct(pieces) => Some(pieces),
        Passing::Indirect { .. } => None,
    };
    let slices: Vec<ObjectSlice> = match direct {
        Some(pieces) => pieces
            .iter()
            .map(|piece| {
                assert!(matches!(piece.location, AbiLocation::Register(_)));
                ObjectSlice {
                    offset: piece.object_offset,
                    bytes: u8::try_from(piece.bytes).expect("a register word"),
                    mask: object_mask(result, piece.object_offset, piece.bytes as u8),
                }
            })
            .collect(),
        None => (0..result.size)
            .step_by(8)
            .map(|offset| {
                let bytes = (result.size - offset).min(8) as u8;
                ObjectSlice {
                    offset,
                    bytes,
                    mask: object_mask(result, offset, bytes),
                }
            })
            .collect(),
    };
    for &(start, count) in &result.defined_bits {
        for bit in start..start + count {
            assert!(slices.iter().any(|slice| {
                (slice.offset * 8..slice.offset * 8 + u64::from(slice.bytes) * 8).contains(&bit)
            }));
        }
    }
    let rendered = velk::render::render_with_dependencies(&ir, &[], &Default::default(), &[]);
    assert!(rendered.segment_bases.is_empty());
    let count = match direct {
        Some(pieces) => pieces.len(),
        None => ir
            .blocks
            .iter()
            .flat_map(|block| &block.stmts)
            .find_map(|stmt| {
                let Stmt::Ret { value, .. } = stmt else {
                    return None;
                };
                Some(match value {
                    Expr::Apply {
                        op: Operation::Results,
                        args,
                    } => args.len(),
                    _ => 1,
                })
            })
            .expect("a return"),
    };
    let mut candidates = Vec::new();
    for (selected, slice) in slices.into_iter().enumerate() {
        if slice.mask == 0 {
            continue;
        }
        let mut projected = project_result(
            &ir,
            count,
            if direct.is_some() { selected } else { 0 },
            slice.bytes,
        )
        .expect("all return expressions retained");
        for stmt in projected
            .blocks
            .iter_mut()
            .flat_map(|block| &mut block.stmts)
        {
            if let Stmt::Ret { value, .. } = stmt {
                if direct.is_none() {
                    *value = Expr::Load {
                        addr: Box::new(Expr::Const(AGGREGATE_RESULT + slice.offset)),
                        width: slice.bytes,
                        signed: false,
                    };
                }
                *value = Expr::bin(BinOp::And, value.clone(), Expr::Const(slice.mask));
            }
        }
        candidates.push(Candidate {
            label: format!(
                "{} result {selected}",
                ir.name.as_deref().expect("a named function")
            ),
            ir: projected,
            code: rendered.code.clone(),
            segment_bases: Vec::new(),
            states: Vec::new(),
            marshalling: Some(AggregateCall {
                signature: signature.clone(),
                result: slice,
                upper_bits: upper_bits.clone(),
            }),
            params: vec!["uint64_t".to_owned(); words],
            inputs: inputs.clone(),
            void: false,
        });
    }
    assert!(!candidates.is_empty(), "the result needs defined bits");
    candidates
}

fn assert_aggregate_definition(ir: &FunctionIr, ty: &CType, value: &ValueAbi, profile: AbiProfile) {
    if !value.aggregate {
        return;
    }
    let name = ty.to_string();
    let definition = ir
        .definitions
        .iter()
        .find(|definition| definition.name == name)
        .unwrap_or_else(|| panic!("missing definition for {name}"));
    assert_eq!(definition.size, value.size, "{name}");
    assert_eq!(definition.alignment, Some(value.alignment), "{name}");
    let mut names = vec![name];
    let mut seen = BTreeSet::new();
    while let Some(name) = names.pop() {
        if !seen.insert(name.clone()) {
            continue;
        }
        let definition = ir
            .definitions
            .iter()
            .find(|definition| definition.name == name)
            .unwrap_or_else(|| panic!("missing nested definition for {name}"));
        assert!(
            definition.compatible_profiles.contains(&profile),
            "{name}: {profile:?}"
        );
        names.extend(definition.contains.iter().cloned());
    }
}

fn assert_aggregate_oracle(candidates: &[Candidate], oracle: impl Fn(&[u64], ObjectSlice) -> u64) {
    let fixture = Fixture {
        name: "aggregate oracle".into(),
        convention: eval::Convention {
            arguments: &[],
            clobbered: &[],
        },
        entry_registers: Vec::new(),
        initial_memory: Vec::new(),
        functions: candidates.len(),
        excluded: BTreeMap::new(),
        candidates: Vec::new(),
    };
    for candidate in candidates {
        let call = candidate.marshalling.as_ref().expect("an object call");
        for (trial, input) in candidate.inputs.iter().enumerate() {
            let outcome = interpret(&fixture, candidate, trial as u64, input, Mode::Registers)
                .unwrap_or_else(|reason| panic!("{} trial {trial}: {reason}", candidate.label));
            let Outcome::Return {
                value,
                calls,
                memory,
            } = outcome
            else {
                panic!("{} trial {trial}: {outcome:?}", candidate.label)
            };
            assert_eq!(
                value,
                oracle(input, call.result) & call.result.mask,
                "{} trial {trial}",
                candidate.label
            );
            assert!(calls.is_empty(), "{} trial {trial}", candidate.label);
            assert!(memory.is_empty(), "{} trial {trial}", candidate.label);
        }
    }
}

type EntryState = (Vec<(u16, u64)>, Vec<(u64, u64)>);

fn aggregate_state(call: &AggregateCall, arguments: &[u64], trial: u64) -> EntryState {
    let abi = call.signature.abi.as_ref().expect("a supported ABI");
    let upper = call.upper_bits[trial as usize];
    let mut registers = Vec::new();
    let mut memory = BTreeMap::new();
    let mut cursor = 0;
    let mut bind = |location, value, bytes| match location {
        AbiLocation::Register(index) => registers.push((index, value)),
        AbiLocation::Stack(offset) => {
            let address = eval::STACK_TOP.wrapping_add_signed(offset);
            for byte in 0..bytes {
                memory.insert(address + byte, (value >> (8 * byte)) as u8);
            }
        }
    };
    let mut objects = BTreeMap::new();
    for (position, value) in abi.arguments.iter().enumerate() {
        let words = value.size.div_ceil(8) as usize;
        let source = &arguments[cursor..cursor + words];
        cursor += words;
        let bytes: Vec<u8> = (0..value.size)
            .map(|byte| (source[byte as usize / 8] >> (8 * (byte % 8))) as u8)
            .collect();
        let word = |offset: u64, size: u64| {
            let count = size.min(8);
            let mask = if count == 8 {
                u64::MAX
            } else {
                (1 << (8 * count)) - 1
            };
            (0..count).fold(upper & !mask, |word, byte| {
                word | u64::from(bytes[(offset + byte) as usize]) << (8 * byte)
            })
        };
        match &value.passing {
            Passing::Direct(pieces) => {
                for piece in pieces {
                    for part in (0..piece.bytes).step_by(8) {
                        let location = match piece.location {
                            AbiLocation::Register(index) => {
                                assert_eq!(part, 0);
                                AbiLocation::Register(index)
                            }
                            AbiLocation::Stack(offset) => AbiLocation::Stack(offset + part as i64),
                        };
                        let bytes = (piece.bytes - part).min(8);
                        bind(location, word(piece.object_offset + part, bytes), bytes);
                    }
                }
            }
            Passing::Indirect { pointer, .. } => {
                assert!(value.size <= 0x1000 && value.alignment <= 0x1000);
                let address = AGGREGATE_STORAGE + position as u64 * 0x1000;
                assert_eq!(address % value.alignment, 0);
                bind(*pointer, address, 8);
                for (offset, byte) in bytes.into_iter().enumerate() {
                    objects.insert(address + offset as u64, byte);
                }
            }
        }
    }
    assert_eq!(cursor, arguments.len());
    if let Some(result) = &abi.result
        && let Passing::Indirect { pointer, .. } = &result.passing
    {
        assert!(result.size <= 0x1000 && result.alignment <= 0x1000);
        assert_eq!(AGGREGATE_RESULT % result.alignment, 0);
        bind(*pointer, AGGREGATE_RESULT, 8);
        objects.extend((0..result.size).map(|offset| {
            (
                AGGREGATE_RESULT + offset,
                (upper >> (8 * (offset % 8))) as u8,
            )
        }));
    }
    memory.extend(objects);
    let mut words = BTreeMap::new();
    for (address, byte) in memory {
        let base = address & !7;
        let word = words.entry(base).or_insert_with(|| {
            (0..8).fold(0, |word, offset| {
                word | (eval::hash(trial, base + offset) & 0xff) << (8 * offset)
            })
        });
        let shift = 8 * (address - base);
        *word = (*word & !(0xff << shift)) | u64::from(byte) << shift;
    }
    (registers, words.into_iter().collect())
}

/// The values, traps, and memory checksums observed for a function's trials.
fn interpretations(
    fixture: &Fixture,
    candidate: &Candidate,
    arguments: &[Vec<u64>],
    mode: Mode,
) -> Vec<Result<Interpretation, String>> {
    let input = (
        format!("{:?}", candidate.ir),
        arguments,
        mode == Mode::Memory,
        fixture.convention.arguments,
        fixture.convention.clobbered,
        &fixture.entry_registers,
        &fixture.initial_memory,
        format!("{:?}", candidate.marshalling),
        format!("{:?}", candidate.segment_bases),
        format!("{:?}", candidate.states),
        (
            candidate
                .code
                .contains("/* target frame's return-address slot */"),
            candidate.code.contains("/* target entry stack pointer */"),
        ),
        candidate.params.len(),
        candidate.void,
    );
    cache::Cache::expectations().get_or_compute("interpret", &input, || {
        let mut interpreted = Vec::new();
        let trials = arguments.iter().enumerate();
        for (trial, arguments) in trials {
            let trial = trial as u64;
            let outcome = match interpret(fixture, candidate, trial, arguments, mode) {
                Ok(outcome) => outcome,
                Err(reason) => {
                    interpreted.push(Err(reason.to_owned()));
                    continue;
                }
            };
            let checksum =
                (mode == Mode::Memory).then(|| region_checksum(&outcome, trial, candidate.ir.isa));
            let outcome = match outcome {
                Outcome::Return { value, .. } => ExpectedOutcome::Return { value },
                Outcome::Trap { .. } => ExpectedOutcome::Trap,
                Outcome::Unknown(reason) => {
                    interpreted.push(Err(reason.to_owned()));
                    continue;
                }
            };
            interpreted.push(Ok(Interpretation { outcome, checksum }));
        }
        interpreted
    })
}

fn interpret(
    fixture: &Fixture,
    candidate: &Candidate,
    trial: u64,
    arguments: &[u64],
    mode: Mode,
) -> Result<Outcome, &'static str> {
    if arguments.len() != candidate.params.len() {
        return Err("the driver gave no arguments");
    }
    let (mut registers, mut aggregate_memory): EntryState =
        if let Some(call) = &candidate.marshalling {
            aggregate_state(call, arguments, trial)
        } else {
            (
                candidate
                    .ir
                    .params
                    .iter()
                    .map(|param| param.index)
                    .zip(arguments.iter().copied())
                    .collect(),
                Vec::new(),
            )
        };
    if velk::arch::pointer_bytes(candidate.ir.isa) == 4 {
        for (address, _) in &mut aggregate_memory {
            *address = address
                .wrapping_sub(eval::STACK_TOP)
                .wrapping_add(eval::stack_top(candidate.ir.isa));
        }
    }
    registers.extend_from_slice(&fixture.entry_registers);
    let mut memory = Vec::new();
    // The region holds what the trial's seed hashes, whatever seed reads
    // the rest, so a second seed tells registers apart and not memory.
    if mode == Mode::Memory {
        let region = region_start(candidate.ir.isa);
        memory.extend((region..region + REGION_SIZE).step_by(8).map(|addr| {
            let word = (0..8).fold(0, |word, byte| {
                word | (eval::hash(trial, addr + byte) & 0xff) << (8 * byte)
            });
            (addr, word)
        }));
    }
    memory.extend_from_slice(&fixture.initial_memory);
    memory.extend(aggregate_memory);
    if let Some(state) = segment_state(candidate, trial)
        .unwrap_or_else(|reason| panic!("{}: {reason}", candidate.label))
    {
        for dependency in &candidate.segment_bases {
            let index = match dependency.segment {
                SegmentBase::Fs => 16,
                SegmentBase::Gs => 17,
            };
            registers.push((
                index,
                state.base(dependency.segment).expect("configured segment"),
            ));
        }
        memory.extend_from_slice(&state.memory);
    }
    let setup = eval::Setup {
        seed: trial,
        convention: eval::Convention {
            arguments: fixture.convention.arguments,
            clobbered: fixture.convention.clobbered,
        },
        registers: &registers,
        memory: &memory,
        step_limit: trials::STEP_LIMIT,
    };
    let mut relocated = None;
    if candidate
        .code
        .contains("/* target frame's return-address slot */")
        || candidate.code.contains("/* target entry stack pointer */")
        || candidate.code.contains("/* entry stack offset: ")
    {
        let sp = velk::arch::stack_pointer(candidate.ir.isa);
        if candidate.marshalling.is_some()
            || candidate
                .ir
                .blocks
                .iter()
                .flat_map(|block| &block.stmts)
                .any(|stmt| matches!(stmt, Stmt::Assign { dest, .. } if dest.index == sp))
        {
            return Err("requires an unnormalized target frame");
        }
        // Use a frame address the host can map for both C and IR execution.
        let mut ir = candidate.ir.clone();
        for stmt in ir.blocks.iter_mut().flat_map(|block| &mut block.stmts) {
            for value in stmt.operands_mut() {
                *value = velk::ir::visit::substitute_values(
                    value.clone(),
                    &[(sp, Expr::Const(frame_base(candidate.ir.isa)))],
                );
            }
        }
        relocated = Some(ir);
    }
    let ir = relocated.as_ref().unwrap_or(&candidate.ir);
    let outcome = eval::run(ir, &setup);
    if let Outcome::Unknown(reason) = outcome {
        return Err(reason);
    }
    let reseeded = eval::Setup {
        seed: OTHER_SEED + trial,
        ..setup
    };
    if !same_outcome(&outcome, &eval::run(ir, &reseeded), candidate) {
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
        (
            Outcome::Return {
                value: x,
                calls: xc,
                memory: xm,
            },
            Outcome::Return {
                value: y,
                calls: yc,
                memory: ym,
            },
        ) => (candidate.void || x & mask(candidate) == y & mask(candidate)) && xc == yc && xm == ym,
        (
            Outcome::Trap {
                calls: xc,
                memory: xm,
            },
            Outcome::Trap {
                calls: yc,
                memory: ym,
            },
        ) => xc == yc && xm == ym,
        _ => false,
    }
}

fn agrees(ran: &ExecutionOutcome, run: &Expected, candidate: &Candidate) -> bool {
    match (ran, &run.outcome) {
        (ExecutionOutcome::Value(value, sum), ExpectedOutcome::Return { value: wanted }) => {
            (candidate.void || value & mask(candidate) == wanted & mask(candidate))
                && *sum == run.checksum
        }
        (ExecutionOutcome::Other(text), ExpectedOutcome::Trap) => text == "trap",
        _ => false,
    }
}

fn describe(ran: &ExecutionOutcome, mask: u64) -> String {
    match ran {
        ExecutionOutcome::Value(value, None) => format!("0x{:x}", value & mask),
        ExecutionOutcome::Value(value, Some(sum)) => {
            format!("0x{:x} and memory {sum:x}", value & mask)
        }
        ExecutionOutcome::Other(text) => text.clone(),
    }
}

fn parse_execution_outcome(line: &str) -> ExecutionOutcome {
    match line.strip_prefix("v ") {
        Some(words) => {
            let mut words = words
                .split_whitespace()
                .map(|word| u64::from_str_radix(word, 16).expect("a hex value"));
            let value = words.next().expect("a value");
            ExecutionOutcome::Value(value, words.next())
        }
        None => ExecutionOutcome::Other(line.to_owned()),
    }
}

/// The checksum the driver prints of the region after a run: FNV-1a over
/// its bytes, as the run leaves them.
fn region_checksum(outcome: &Outcome, trial: u64, isa: Isa) -> u64 {
    let region = region_start(isa);
    let memory = match outcome {
        Outcome::Return { memory, .. } | Outcome::Trap { memory, .. } => memory,
        Outcome::Unknown(_) => return 0,
    };
    (region..region + REGION_SIZE).fold(0xcbf2_9ce4_8422_2325, |sum, addr| {
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
    initial_memory: &[&[(u64, u64)]],
    source: &Path,
    mode: Mode,
) -> (Vec<usize>, BTreeMap<usize, String>) {
    let mut alive: Vec<usize> = (0..candidates.len()).collect();
    let mut failures = BTreeMap::new();
    for _ in 0..COMPILE_ROUNDS {
        let text = program(candidates, initial_memory, &alive, mode);
        std::fs::write(source, &text.text).unwrap_or_else(|error| panic!("{error}"));
        COMPILATIONS.set(COMPILATIONS.get() + 1);
        let checked = Command::new(compiler())
            .args(FLAGS)
            .args(["-fsyntax-only", "-ferror-limit=0"])
            .arg(source)
            .output()
            .unwrap_or_else(|error| panic!("{}: {error}", compiler().display()));
        if checked.status.success() {
            return (alive, failures);
        }
        assert!(
            checked.status.code().is_some(),
            "compiler was killed: {}",
            checked.status
        );
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
            "{} rejects the test's own code in {}:\n{errors}",
            compiler().display(),
            source.display()
        );
        alive.retain(|index| !failures.contains_key(index));
    }
    panic!(
        "{} still rejects {} after {COMPILE_ROUNDS} rounds",
        compiler().display(),
        source.display()
    );
}

/// The program compiled at `level`.
fn build(source: &Program, scratch: &Path, level: &str, compiler_args: &[&str]) -> PathBuf {
    let path = scratch.join(format!("check{level}.c"));
    let output = scratch.join(format!("check{level}"));
    std::fs::write(&path, &source.text).unwrap_or_else(|error| panic!("{error}"));
    COMPILATIONS.set(COMPILATIONS.get() + 1);
    let compiled = Command::new(compiler())
        .arg(level)
        .args(FLAGS)
        .arg("-o")
        .arg(&output)
        .arg(&path)
        .args(compiler_args)
        .output()
        .unwrap_or_else(|error| panic!("{}: {error}", compiler().display()));
    assert!(
        compiled.status.success(),
        "{} {level} fails on {}:\n{}",
        compiler().display(),
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

fn fresh_name(reserved: &mut BTreeSet<String>, preferred: &str) -> String {
    let mut name = preferred.to_owned();
    let mut suffix = 0;
    while !reserved.insert(name.clone()) {
        suffix += 1;
        name = format!("{preferred}_{suffix}");
    }
    name
}

fn replace_c_identifier(code: &str, from: &str, to: &str) -> String {
    let mut out = String::new();
    let mut index = 0;
    let mut member = false;
    let mut record_type = false;
    let mut record_tag = false;
    let mut record_braces = 0usize;
    while index < code.len() {
        let rest = &code[index..];
        if (record_type || record_tag) && rest.starts_with("__attribute__(") {
            let mut length = "__attribute__(".len();
            let mut depth = 1usize;
            while length < rest.len() && depth != 0 {
                if rest.as_bytes()[length] == b'(' {
                    depth += 1;
                }
                if rest.as_bytes()[length] == b')' {
                    depth -= 1;
                }
                length += 1;
            }
            out.push_str(&rest[..length]);
            index += length;
            continue;
        }
        let first = rest.chars().next().expect("remaining C");
        let length = if rest.starts_with("/*") {
            rest.find("*/").map_or(rest.len(), |end| end + 2)
        } else if rest.starts_with("//") {
            rest.find('\n').unwrap_or(rest.len())
        } else if matches!(first, '\'' | '"') {
            let mut escaped = false;
            let mut length = rest.len();
            for (at, ch) in rest.char_indices().skip(1) {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == first {
                    length = at + ch.len_utf8();
                    break;
                }
            }
            length
        } else if first.is_ascii_alphabetic() || first == '_' {
            rest.find(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
                .unwrap_or(rest.len())
        } else if rest.starts_with("->") {
            2
        } else {
            first.len_utf8()
        };
        let token = &rest[..length];
        let identifier = first.is_ascii_alphabetic() || first == '_';
        let replace = token == from && !member && !record_type && record_braces == 0;
        out.push_str(if replace { to } else { token });
        if token == "{" && (record_type || record_tag || record_braces != 0) {
            record_braces += 1;
            record_type = false;
            record_tag = false;
        } else if token == "}" && record_braces != 0 {
            record_braces -= 1;
        } else if identifier {
            record_tag = record_type;
            record_type = matches!(token, "struct" | "union");
            member = false;
        } else if !first.is_whitespace() && !rest.starts_with("/*") && !rest.starts_with("//") {
            member = matches!(token, "." | "->");
            record_tag = false;
        }
        index += length;
    }
    out
}

fn bound_candidate(
    candidate: &Candidate,
    index: usize,
    reserved: &mut BTreeSet<String>,
) -> (String, Vec<(String, SegmentBase)>) {
    let mut code = bound_globals(&renamed(&candidate.code, index));
    let mut seen = BTreeMap::new();
    let mut providers = Vec::new();
    for dependency in &candidate.segment_bases {
        if let Some(previous) = seen.insert(&dependency.provider, dependency.segment) {
            assert_eq!(previous, dependency.segment, "conflicting segment binding");
            continue;
        }
        let kind = match dependency.segment {
            SegmentBase::Fs => "fs",
            SegmentBase::Gs => "gs",
        };
        let name = fresh_name(reserved, &format!("velk_segment_{index}_{kind}"));
        code = replace_c_identifier(&code, &dependency.provider, &name);
        providers.push((name, dependency.segment));
    }
    (code, providers)
}

fn bound_globals(code: &str) -> String {
    let mut bindings = Vec::new();
    let mut output = String::new();
    for line in code.lines() {
        let Some((declaration, address)) = line.split_once("; /* address: 0x") else {
            writeln!(output, "{line}").expect("writing to a String");
            continue;
        };
        let Some(declaration) = declaration.strip_prefix("extern ") else {
            panic!("invalid global declaration: {line}");
        };
        let Some(address) = address.strip_suffix(" */") else {
            panic!("invalid global address: {line}");
        };
        let Some((ty, name)) = declaration.rsplit_once(' ') else {
            panic!("invalid global type: {line}");
        };
        let (name, value) = if let Some(name) = name.strip_suffix("[]") {
            (name, format!("(({ty} *)(uintptr_t)0x{address}ULL)"))
        } else {
            (name, format!("(*({ty} *)(uintptr_t)0x{address}ULL)"))
        };
        bindings.push((name, value));
    }
    for (name, value) in bindings {
        output = replace_c_identifier(&output, name, &value);
    }
    output
}

fn write_memory_words(text: &mut String, words: &[(u64, u64)]) {
    for (addr, value) in words {
        writeln!(text, "        for (unsigned byte = 0; byte < 8; byte++) ((volatile uint8_t *)(uintptr_t)0x{addr:x}ULL)[byte] = (uint8_t)(0x{value:x}ULL >> (8 * byte));")
            .expect("writing to a String");
    }
}

fn segment_support(
    candidates: &[&Candidate],
    initial_memory: &[&[(u64, u64)]],
    alive: &[usize],
    providers: &[(String, SegmentBase)],
    reserved: &mut BTreeSet<String>,
) -> (String, String, String) {
    let prepare = fresh_name(reserved, "velk_prepare");
    let overlay = fresh_name(reserved, "velk_fixture_overlay");
    let active = fresh_name(reserved, "velk_active_candidate");
    let values = [
        fresh_name(reserved, "velk_fs_value"),
        fresh_name(reserved, "velk_gs_value"),
    ];
    let valid = [
        fresh_name(reserved, "velk_fs_valid"),
        fresh_name(reserved, "velk_gs_valid"),
    ];
    let mut text = format!(
        "static uint64_t {}, {};\nstatic bool {}, {};\nstatic volatile sig_atomic_t {active} = -1;\n",
        values[0], values[1], valid[0], valid[1]
    );
    writeln!(
        text,
        "static void {overlay}(uintptr_t start, uint64_t size) {{\n    switch ({active}) {{"
    )
    .expect("writing to a String");
    for &index in alive {
        if initial_memory[index].is_empty() {
            continue;
        }
        writeln!(text, "    case {index}:").expect("writing to a String");
        for (addr, value) in initial_memory[index] {
            writeln!(text, "        for (unsigned byte = 0; byte < 8; byte++) {{\n            uintptr_t addr = (uintptr_t)0x{addr:x}ULL + byte;\n            if (addr >= start && addr - start < size) *(volatile uint8_t *)addr = (uint8_t)(0x{value:x}ULL >> (8 * byte));\n        }}").expect("writing to a String");
        }
        text.push_str("        break;\n");
    }
    text.push_str("    }\n}\n");
    for (provider, segment) in providers {
        let slot = match segment {
            SegmentBase::Fs => 0,
            SegmentBase::Gs => 1,
        };
        writeln!(
            text,
            "uint64_t {provider}(void) {{ if (!{}) __builtin_trap(); return {}; }}",
            valid[slot], values[slot]
        )
        .expect("writing to a String");
    }
    writeln!(text, "static void {prepare}(int k, uint64_t trial) {{\n    {active} = k;\n    {} = false; {} = false;\n    {overlay}(REGION_START, REGION_BYTES);\n    switch (k) {{", valid[0], valid[1]).expect("writing to a String");
    for &index in alive {
        let candidate = candidates[index];
        if candidate.states.is_empty() {
            continue;
        }
        writeln!(text, "    case {index}:").expect("writing to a String");
        text.push_str("        switch (trial) {\n");
        for trial in 0..trials::TRIALS {
            let state = segment_state(candidate, trial)
                .expect("configured segment state")
                .expect("a trial state");
            writeln!(text, "        case {trial}:").expect("writing to a String");
            write_memory_words(&mut text, &state.memory);
            for (slot, segment) in [SegmentBase::Fs, SegmentBase::Gs].into_iter().enumerate() {
                if let Some(base) = state.base(segment) {
                    writeln!(
                        text,
                        "            {} = 0x{base:x}ULL; {} = true;",
                        values[slot], valid[slot]
                    )
                    .expect("writing to a String");
                }
            }
            text.push_str("            break;\n");
        }
        text.push_str("        default: __builtin_trap();\n        }\n");
        text.push_str("        break;\n");
    }
    text.push_str("    }\n}\n");
    (text, prepare, overlay)
}

/// The C program holding the functions in `alive`.
fn aggregate_call(text: &mut String, candidate: &Candidate, index: usize, call: &AggregateCall) {
    let abi = call.signature.abi.as_ref().expect("a supported ABI");
    writeln!(text, "    case {index}: {{").expect("formatting into a String cannot fail");
    let mut cursor = 0;
    let mut arguments = Vec::new();
    for (position, ((_, ty), value)) in call.signature.params.iter().zip(&abi.arguments).enumerate()
    {
        let ty = scoped_type(&ty.to_string(), &candidate.code, index);
        let local = format!("velk_arg{position}");
        writeln!(text, "        {ty} {local};").expect("formatting into a String cannot fail");
        writeln!(
            text,
            "        _Static_assert(sizeof({local}) == {}, \"argument size\");",
            value.size
        )
        .expect("formatting into a String cannot fail");
        writeln!(
            text,
            "        _Static_assert(_Alignof({ty}) == {}, \"argument alignment\");",
            value.alignment
        )
        .expect("formatting into a String cannot fail");
        writeln!(text, "        for (unsigned byte = 0; byte < {}; byte++) ((unsigned char *)&{local})[byte] = (unsigned char)(a[{cursor} + byte / 8] >> (8 * (byte % 8)));", value.size).expect("formatting into a String cannot fail");
        cursor += value.size.div_ceil(8) as usize;
        arguments.push(local);
    }
    let result = abi.result.as_ref().expect("an observed result");
    let ty = scoped_type(&call.signature.ret.to_string(), &candidate.code, index);
    writeln!(
        text,
        "        {ty} velk_result = velk_f{index}({});",
        arguments.join(", ")
    )
    .expect("formatting into a String cannot fail");
    writeln!(
        text,
        "        _Static_assert(sizeof(velk_result) == {}, \"result size\");",
        result.size
    )
    .expect("formatting into a String cannot fail");
    writeln!(
        text,
        "        _Static_assert(_Alignof({ty}) == {}, \"result alignment\");",
        result.alignment
    )
    .expect("formatting into a String cannot fail");
    writeln!(text, "        uint64_t velk_word = 0;")
        .expect("formatting into a String cannot fail");
    writeln!(text, "        for (unsigned byte = 0; byte < {}; byte++) velk_word |= (uint64_t)((const unsigned char *)&velk_result)[{} + byte] << (8 * byte);", call.result.bytes, call.result.offset).expect("formatting into a String cannot fail");
    writeln!(
        text,
        "        return velk_word & 0x{:x}ULL;\n    }}",
        call.result.mask
    )
    .expect("formatting into a String cannot fail");
}

/// The C program holding the functions in `alive`.
fn program(
    candidates: &[&Candidate],
    initial_memory: &[&[(u64, u64)]],
    alive: &[usize],
    mode: Mode,
) -> Program {
    assert_eq!(candidates.len(), initial_memory.len());
    let isa = candidates
        .first()
        .map_or(Isa::Unsupported, |candidate| candidate.ir.isa);
    let region = region_start(isa);
    let frame = frame_base(isa);
    let mut text = String::from(HEADER);
    let frame_providers: BTreeSet<_> = alive
        .iter()
        .flat_map(|&index| {
            candidates[index].code.lines().filter_map(|line| {
                line.strip_prefix("uint64_t *").and_then(|line| {
                    line.strip_suffix("(void); /* target frame's return-address slot */")
                })
            })
        })
        .collect();
    for provider in frame_providers {
        writeln!(
            text,
            "uint64_t *{provider}(void) {{ return (uint64_t *)(uintptr_t)0x{:x}ULL; }}",
            frame
        )
        .expect("formatting into a String cannot fail");
    }
    let stack_providers: BTreeSet<_> = alive
        .iter()
        .flat_map(|&index| {
            candidates[index].code.lines().filter_map(|line| {
                line.strip_prefix("uint64_t ")
                    .and_then(|line| line.strip_suffix("(void); /* target entry stack pointer */"))
            })
        })
        .collect();
    for provider in stack_providers {
        writeln!(
            text,
            "uint64_t {provider}(void) {{ return 0x{frame:x}ULL; }}"
        )
        .expect("formatting into a String cannot fail");
    }
    let mut argument_providers = BTreeSet::new();
    for &index in alive {
        for line in candidates[index].code.lines() {
            let Some(line) = line.strip_prefix("extern uint8_t *") else {
                continue;
            };
            let Some((provider, offset)) = line.split_once("; /* entry stack offset: 0x") else {
                continue;
            };
            let Some(offset) = offset.strip_suffix(" */") else {
                continue;
            };
            let offset = u64::from_str_radix(offset, 16).expect("a rendered stack offset");
            argument_providers.insert((provider, offset));
        }
    }
    for (provider, offset) in argument_providers {
        writeln!(
            text,
            "uint8_t *{provider} = (uint8_t *)(uintptr_t)0x{:x}ULL;",
            frame
                .checked_add(offset)
                .expect("a bounded test frame offset")
        )
        .expect("writing to a String");
    }
    if mode == Mode::Memory {
        writeln!(
            text,
            "#define REGION_START 0x{region:x}ULL\n#define REGION_BYTES 0x{REGION_SIZE:x}ULL"
        )
        .expect("writing to a String");
    }
    let mut ranges = Vec::new();
    let mut reserved: BTreeSet<String> = candidates
        .iter()
        .map(|candidate| candidate.code.as_str())
        .chain([HEADER, DRIVER, MEMORY_DRIVER])
        .flat_map(|code| code.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_'))
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
        .collect();
    reserved.extend((0..candidates.len()).map(|index| format!("velk_f{index}")));
    let mut providers = Vec::new();
    let mut line = text.lines().count() + 1;
    for &index in alive {
        let (code, bindings) = bound_candidate(candidates[index], index, &mut reserved);
        providers.extend(bindings);
        let lines = code.lines().count();
        ranges.push((index, line..=line + lines - 1));
        line += lines;
        text.push_str(&code);
    }
    // The functions whose address the printed ones take, defined so the
    // program links.
    let declared: BTreeMap<&str, FunctionAddressDeclaration<'_>> = alive
        .iter()
        .flat_map(|&index| function_address_declarations(&candidates[index].code))
        .map(|declaration| (declaration.name, declaration))
        .collect();
    for declaration in declared.values() {
        let body = if declaration.returns_void {
            ""
        } else {
            " __builtin_trap(); "
        };
        writeln!(text, "{} {{{body}}}", declaration.signature).expect("writing to a String");
    }
    text.push_str("static uint64_t velk_call(int k, const uint64_t *a) {\n    switch (k) {\n");
    for &index in alive {
        let candidate = candidates[index];
        if let Some(call) = &candidate.marshalling {
            aggregate_call(&mut text, candidate, index, call);
            continue;
        }
        // The memory pass passes pointers, converted to their types.
        let arguments: Vec<String> = candidate
            .params
            .iter()
            .enumerate()
            .map(|(position, ty)| match mode {
                Mode::Registers => format!("a[{position}]"),
                Mode::Memory if ty.trim_end().ends_with('*') => {
                    format!("(void *)(uintptr_t)a[{position}]")
                }
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
        if candidates[index].marshalling.is_some() {
            for position in 0..candidates[index].params.len() {
                write!(text, " c[{position}] = a[{position}];")
                    .expect("formatting into a String cannot fail");
            }
            text.push_str(" break;\n");
            continue;
        }
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
    if mode == Mode::Memory {
        let (support, prepare, overlay) =
            segment_support(candidates, initial_memory, alive, &providers, &mut reserved);
        text.push_str(&support);
        text.push_str(
            &MEMORY_DRIVER
                .replace(
                    "velk_prepare(k, velk_seed)",
                    &format!("{prepare}(k, velk_seed)"),
                )
                .replace(
                    "velk_fixture_overlay(page, velk_page_size)",
                    &format!("{overlay}(page, velk_page_size)"),
                ),
        );
    } else {
        assert!(
            providers.is_empty(),
            "register comparisons need explicit segment state"
        );
        text.push_str(DRIVER);
    }
    Program { text, ranges }
}

/// Whether `name` is a general machine register or the Go runtime pointer.
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
    function_address_declarations(code)
        .into_iter()
        .map(|declaration| declaration.name)
        .collect()
}

struct FunctionAddressDeclaration<'a> {
    name: &'a str,
    signature: &'a str,
    returns_void: bool,
}

fn function_address_declarations(code: &str) -> Vec<FunctionAddressDeclaration<'_>> {
    let mut reserved: BTreeSet<String> = code
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .map(str::to_owned)
        .collect();
    let marker = format!(" {} ", fresh_name(&mut reserved, "velk_function_address"));
    let mut declarations = Vec::new();
    for line in code.lines() {
        if line.starts_with(char::is_whitespace) {
            continue;
        }
        let Some(declaration) = line
            .strip_suffix("();")
            .or_else(|| line.strip_suffix("(void);"))
        else {
            continue;
        };
        let Some((ty, name)) = declaration.rsplit_once(' ') else {
            continue;
        };
        if ty.trim().is_empty()
            || !ty.chars().all(|ch| {
                ch.is_ascii_alphanumeric() || ch.is_ascii_whitespace() || matches!(ch, '_' | '*')
            })
        {
            continue;
        }
        let returns_void = ty.trim() == "void" && !name.starts_with('*');
        let name = name.trim_start_matches('*');
        let body = code
            .lines()
            .filter(|other| *other != line)
            .collect::<Vec<_>>()
            .join("\n");
        let body = replace_c_identifier(&body, name, &marker);
        let mut taken = false;
        for (at, _) in body.match_indices(&marker) {
            if !body[at + marker.len()..].trim_start().starts_with('(') {
                taken = true;
                break;
            }
        }
        if taken {
            declarations.push(FunctionAddressDeclaration {
                name,
                signature: line.strip_suffix(';').expect("a function declaration"),
                returns_void,
            });
        }
    }
    declarations
}

#[test]
fn function_address_declarations_include_unspecified_parameters() {
    assert_eq!(
        declared_functions(
            "void callback();\nuint64_t other();\nvoid old_callback(void);\nuint64_t stack_provider(void);\nuint64_t callee();\n    callback();\n    return callee();\n    value = (uintptr_t)callback ^ (uintptr_t)other ^ (uintptr_t)old_callback;\n"
        ),
        vec!["callback", "other", "old_callback"]
    );
}

/// Structure and union definitions whose tags need a distinct name per function.
fn defined_types(code: &str) -> Vec<String> {
    code.lines()
        .filter_map(|line| {
            let Some((declaration, _)) = line.split_once(" {") else {
                return None;
            };
            let Some(name) = declaration
                .strip_prefix("struct ")
                .or_else(|| declaration.strip_prefix("union "))
            else {
                return None;
            };
            (!name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'))
            .then(|| declaration.to_owned())
        })
        .collect()
}

fn scoped_type(ty: &str, source: &str, index: usize) -> String {
    let mut code = ty.to_owned();
    for from in defined_types(source) {
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
    code
}

fn renamed(code: &str, index: usize) -> String {
    let code = scoped_type(code, code, index);
    let mut out = String::new();
    let mut done = false;
    for line in code.lines() {
        if !done
            && !line.starts_with([' ', '/'])
            && !line.starts_with("static inline ")
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

fn timed_out(output: &str) -> bool {
    output.lines().any(|line| line == "timeout")
}

fn can_cache_run(output: &str) -> bool {
    !timed_out(output) && !output.lines().any(|line| line == "unreachable")
}

/// The program's output for `input`, retrying one timed-out run.
fn run(program: &Path, input: &str) -> String {
    let output = run_once(program, input);
    if timed_out(&output) {
        return run_once(program, input);
    }
    output
}

fn run_once(program: &Path, input: &str) -> String {
    let mut child = Command::new(program)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("{}: {error}", program.display()));
    let mut stdin = child.stdin.take().expect("a pipe");
    let input = input.to_owned();
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()).ok());
    let output = child
        .wait_with_output()
        .unwrap_or_else(|error| panic!("{}: {error}", program.display()));
    writer.join().ok();
    assert!(
        output.status.success(),
        "{} failed with {}:\n{}",
        program.display(),
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn scratch_dir(pass: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("recompile-{}-{pass}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap_or_else(|error| panic!("{}: {error}", dir.display()));
    dir
}

#[test]
fn printed_short_circuit_conditions_keep_order_and_effects() {
    short_circuit::printed_short_circuit_conditions_keep_order_and_effects();
}

#[test]
fn printed_real_short_circuit_guards_preserve_memory_and_results() {
    short_circuit::printed_real_short_circuit_guards_preserve_memory_and_results();
}

#[test]
fn physical_scalar_stack_calls_require_complete_bounded_slots() {
    physical_stack::physical_scalar_stack_calls_require_complete_bounded_slots();
}

#[test]
fn printed_stripped_stack_fixtures_preserve_all_physical_inputs() {
    physical_stack::printed_stripped_stack_fixtures_preserve_all_physical_inputs();
}

#[test]
fn printed_stack_bytes_preserve_read_write_order_and_slot_boundaries() {
    physical_stack::printed_stack_bytes_preserve_read_write_order_and_slot_boundaries();
}

#[test]
fn printed_stack_cross_slot_scalar_views_preserve_bits_and_frame_locations() {
    physical_stack::printed_stack_cross_slot_scalar_views_preserve_bits_and_frame_locations();
}

#[test]
fn printed_stripped_x86_stack_fixtures_preserve_held_alias_inputs() {
    physical_stack::printed_stripped_x86_stack_fixtures_preserve_held_alias_inputs();
}

#[test]
fn printed_switch_ranges_preserve_cases_across_negative_one_and_zero() {
    let mut candidates = Vec::new();
    for signed in [false, true] {
        for chained in [false, true] {
            let name = format!("switch_zero_{}_{}", u8::from(signed), u8::from(chained));
            let mut blocks = Vec::new();
            if chained {
                for (position, value) in [u64::MAX, 0, 1, 17].into_iter().enumerate() {
                    blocks.push(Block {
                        start: position as u64 * 0x10,
                        stmts: vec![Stmt::Brif {
                            cond: Cond::Eq,
                            lhs: Expr::reg(7, 64),
                            rhs: Expr::Const(value),
                            target: if value == 17 { 0x120 } else { 0x100 },
                            at: None,
                        }],
                    });
                }
            } else {
                blocks.push(Block {
                    start: 0,
                    stmts: vec![Stmt::Switch {
                        index: Expr::reg(7, 64),
                        cases: vec![(-1, 0x100), (0, 0x100), (1, 0x100), (17, 0x120)],
                        default: Some(0x40),
                        at: None,
                    }],
                });
            }
            blocks.extend([
                Block {
                    start: 0x40,
                    stmts: vec![Stmt::Ret {
                        value: Expr::Const(99),
                        at: None,
                    }],
                },
                Block {
                    start: 0x100,
                    stmts: vec![Stmt::Ret {
                        value: Expr::Const(11),
                        at: None,
                    }],
                },
                Block {
                    start: 0x120,
                    stmts: vec![Stmt::Ret {
                        value: Expr::Const(12),
                        at: None,
                    }],
                },
            ]);
            let ir = sc_ir(
                &name,
                vec![if signed { CType::I64 } else { CType::U64 }],
                blocks,
            );
            let rows = [
                u64::MAX - 1,
                u64::MAX,
                0,
                1,
                2,
                17,
                18,
                1 << 63,
                (1 << 63) - 1,
            ];
            let candidate =
                printed_candidate(ir, rows.into_iter().map(|value| vec![value]).collect());
            assert!(candidate.code.contains("switch ("), "{}", candidate.code);
            if signed {
                assert!(
                    candidate.code.contains("case -1 ... 1:"),
                    "{}",
                    candidate.code
                );
            } else {
                assert!(
                    !candidate.code.contains("case -1 ... 1:"),
                    "{}",
                    candidate.code
                );
                for value in [-1, 0, 1] {
                    assert!(
                        candidate.code.contains(&format!("case {value}:")),
                        "{}",
                        candidate.code
                    );
                }
            }
            candidates.push(candidate);
        }
    }
    check_candidates("switch-zero-ranges", candidates, Mode::Registers, &[]);
}

#[test]
fn printed_sparse_equality_dispatch_preserves_cases_and_effects() {
    let mut candidates = Vec::new();
    for (name, width, mixed, effect) in [
        ("sparse_eq32", 32, false, false),
        ("sparse_ne64", 64, true, false),
        ("sparse_effect64", 64, false, true),
        ("sparse_high64", 64, true, false),
    ] {
        let high = name == "sparse_high64";
        let values = if high {
            [1, 1 << 63, u64::MAX]
        } else {
            [1, 1000, 10000]
        };
        let rows = if high {
            [
                0,
                1,
                2,
                (1 << 63) - 1,
                1 << 63,
                (1 << 63) + 1,
                u64::MAX - 1,
                u64::MAX,
                0x1_0000_0001,
                1000,
                10000,
                0x1234,
            ]
        } else {
            [
                0,
                1,
                2,
                999,
                1000,
                1001,
                9999,
                10000,
                10001,
                u64::MAX,
                0x1234_5678_0000_03e8,
                0x8000_0000,
            ]
        };
        let body = |position: usize| Block {
            start: 0x100 + position as u64 * 0x20,
            stmts: vec![
                sc_store(SC_COUNTER, Expr::Const(position as u64 + 11)),
                Stmt::Ret {
                    value: Expr::Const(position as u64 + 11),
                    at: None,
                },
            ],
        };
        let mut blocks = Vec::new();
        let mut later = Vec::new();
        for (position, value) in values.iter().enumerate() {
            let inverse = mixed && position == 1;
            let next = if position == 2 {
                0x80
            } else {
                (position as u64 + 1) * 0x20
            };
            let mut stmts = Vec::new();
            if position == 0 && effect {
                stmts.push(sc_store(
                    SC_RIGHT,
                    Expr::bin(BinOp::Add, sc_load(SC_RIGHT), Expr::Const(1)),
                ));
            }
            stmts.push(Stmt::Brif {
                cond: if inverse { Cond::Ne } else { Cond::Eq },
                lhs: Expr::reg(7, width),
                rhs: Expr::Const(*value),
                target: if inverse { next } else { body(position).start },
                at: None,
            });
            blocks.push(Block {
                start: position as u64 * 0x20,
                stmts,
            });
            if inverse {
                blocks.push(body(position));
            } else {
                later.push(body(position));
            }
        }
        blocks.push(Block {
            start: 0x80,
            stmts: vec![
                sc_store(SC_COUNTER, Expr::Const(99)),
                Stmt::Ret {
                    value: Expr::Const(99),
                    at: None,
                },
            ],
        });
        blocks.extend(later);
        let mut ir = sc_ir(
            name,
            vec![if width == 32 { CType::U32 } else { CType::U64 }],
            blocks,
        );
        ir.ret_type = CType::U64;
        let inputs = rows.into_iter().map(|value| vec![value]).collect();
        let candidate = printed_candidate(ir, inputs);
        for value in values {
            assert!(
                candidate.code.contains(&format!("case {}:", value as i64)),
                "{}",
                candidate.code
            );
        }
        let fixture = Fixture {
            name: "sparse dispatch oracle".into(),
            convention: eval::Convention {
                arguments: Convention::SysV.arguments(),
                clobbered: &[],
            },
            entry_registers: Vec::new(),
            initial_memory: Vec::new(),
            functions: 1,
            excluded: BTreeMap::new(),
            candidates: Vec::new(),
        };
        for (trial, input) in candidate.inputs.iter().enumerate() {
            let discriminant = if width == 32 {
                input[0] & 0xffff_ffff
            } else {
                input[0]
            };
            let wanted = if high {
                match discriminant {
                    1 => 11,
                    0x8000_0000_0000_0000 => 12,
                    u64::MAX => 13,
                    _ => 99,
                }
            } else {
                match discriminant {
                    1 => 11,
                    1000 => 12,
                    10000 => 13,
                    _ => 99,
                }
            };
            let mut expected: BTreeMap<u64, u8> = (REGION..REGION + REGION_SIZE)
                .map(|address| (address, eval::hash(trial as u64, address) as u8))
                .collect();
            let mut updates = vec![(SC_COUNTER, wanted)];
            if effect {
                let original = u64::from_le_bytes(std::array::from_fn(|offset| {
                    expected[&(SC_RIGHT + offset as u64)]
                }));
                updates.push((SC_RIGHT, original.wrapping_add(1)));
            }
            for (address, value) in updates {
                for (offset, byte) in value.to_le_bytes().into_iter().enumerate() {
                    expected.insert(address + offset as u64, byte);
                }
            }
            let outcome = interpret(&fixture, &candidate, trial as u64, input, Mode::Memory)
                .unwrap_or_else(|reason| panic!("{} trial {trial}: {reason}", candidate.label));
            assert_eq!(
                outcome,
                Outcome::Return {
                    value: wanted,
                    calls: Vec::new(),
                    memory: expected
                },
                "{} trial {trial}",
                candidate.label
            );
        }
        candidates.push(candidate);
    }
    assert_eq!(candidates.len(), 4);
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.inputs.len())
            .sum::<usize>(),
        48
    );
    check_candidates("sparse-equality-dispatch", candidates, Mode::Memory, &[]);
}

#[test]
fn printed_scalar_half_immediate_wrappers_preserve_raw_patterns() {
    let mut source = String::from(
        "#include <stdint.h>\n#include <inttypes.h>\n#include <stdio.h>\n#include <stdbool.h>\n",
    );
    let native = cfg!(all(target_arch = "aarch64", target_os = "macos"));
    let mut body = String::from("int main(void) {\n");
    let scratch = scratch_dir("half-immediate");
    for immediate in 0u32..256 {
        let word = 0x1ee0_1000 | immediate << 13;
        let words = [word, 0x0e02_3c00, 0xd65f_03c0];
        let code: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let size = code.len() as u64;
        let mut object = object::write::Object::new(
            object::BinaryFormat::Elf,
            object::Architecture::Aarch64,
            object::Endianness::Little,
        );
        let text = object.add_section(Vec::new(), b".text".to_vec(), object::SectionKind::Text);
        object.append_section_data(text, &code, 4);
        object.add_symbol(object::write::Symbol {
            name: b"half_wrapper".to_vec(),
            value: 0,
            size,
            kind: object::SymbolKind::Text,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: object::write::SymbolSection::Section(text),
            flags: object::SymbolFlags::None,
        });
        let wrapper = scratch.join("half-wrapper.o");
        std::fs::write(&wrapper, object.write().expect("a tiny ELF object")).unwrap();
        let image = velk::loader::load(&wrapper).expect("the original wrapper object");
        assert_eq!(image.isa, Isa::AArch64);
        assert_eq!(image.format, velk::loader::Format::Elf);
        let function = image
            .functions
            .values()
            .find(|function| function.name.as_deref() == Some("half_wrapper"))
            .expect("the original wrapper symbol");
        assert_eq!(function.size, Some(size));
        assert_eq!(image.read_vaddr(function.addr, size), Some(code.as_slice()));
        let mut ir = synthetic_ir("half_raw", Vec::new(), CType::U64, Vec::new());
        ir.isa = Isa::AArch64;
        ir.convention = Convention::Aapcs64;
        ir.addr = function.addr;
        ir.size = size;
        ir.blocks = velk::lift::lift(&image, function.addr, size, &Default::default())
            .expect("original wrapper lift");
        for optimized in [false, true] {
            if optimized {
                velk::passes::optimize(&mut ir, false);
            }
            assert!(
                !ir.blocks
                    .iter()
                    .flat_map(|block| &block.stmts)
                    .any(|stmt| matches!(
                        stmt,
                        Stmt::Unsupported { .. } | Stmt::Call { .. } | Stmt::Store { .. }
                    )),
                "immediate {immediate}, optimized={optimized}: {}",
                ir.render()
            );
            let bit = u64::from(immediate >> 6 & 1);
            let expected = u64::from(immediate >> 7) << 15
                | (bit ^ 1) << 14
                | (bit * 3) << 12
                | u64::from(immediate & 63) << 6;
            let setup = eval::Setup {
                seed: 0x5eed,
                convention: eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &[],
                memory: &[],
                step_limit: 100,
            };
            assert_eq!(
                eval::run(&ir, &setup),
                Outcome::Return {
                    value: expected,
                    calls: Vec::new(),
                    memory: BTreeMap::new(),
                }
            );
            let suffix = if optimized { "optimized" } else { "raw" };
            ir.name = Some(format!("half_{suffix}_{immediate}"));
            source.push_str(&velk::render::render(&ir, &[], &Default::default(), &[]));
            source.push('\n');
        }
        if native {
            writeln!(source, "extern uint64_t half_original_{immediate}(void);").unwrap();
            writeln!(source, "__asm__(\".text\\n.p2align 2\\n.globl _half_original_{immediate}\\n_half_original_{immediate}:\\n.long {word:#010x}\\n.long 0x0e023c00\\n.long 0xd65f03c0\\n\");").unwrap();
            writeln!(body, "printf(\"{immediate} %\" PRIx64 \" %\" PRIx64 \" %\" PRIx64 \"\\n\", half_raw_{immediate}(), half_optimized_{immediate}(), half_original_{immediate}());").unwrap();
        } else {
            writeln!(body, "printf(\"{immediate} %\" PRIx64 \" %\" PRIx64 \"\\n\", half_raw_{immediate}(), half_optimized_{immediate}());").unwrap();
        }
    }
    body.push_str("return 0;\n}\n");
    source.push_str(&body);
    let input = scratch.join("half.c");
    std::fs::write(&input, source).unwrap();
    let mut compared = 0;
    let mut original_calls = 0;
    for level in LEVELS {
        let executable = scratch.join(format!("half{level}"));
        let compiled = Command::new(compiler())
            .arg("-std=c11")
            .arg(level)
            .args([
                "-fwrapv",
                "-fno-strict-aliasing",
                "-Werror=implicit-function-declaration",
                "-Werror=return-type",
            ])
            .arg(&input)
            .arg("-o")
            .arg(&executable)
            .output()
            .expect("a C compiler");
        assert!(
            compiled.status.success(),
            "{level}: {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let output = run(&executable, "");
        let rows: Vec<_> = output.lines().collect();
        assert_eq!(rows.len(), 256, "{level}: {output}");
        for (immediate, row) in rows.iter().enumerate() {
            let mut words = row.split_whitespace();
            assert_eq!(words.next().unwrap().parse::<usize>().unwrap(), immediate);
            let bit = (immediate as u64 >> 6) & 1;
            let expected = (immediate as u64 >> 7) << 15
                | (bit ^ 1) << 14
                | (bit * 3) << 12
                | (immediate as u64 & 63) << 6;
            let values: Vec<_> = words
                .map(|value| u64::from_str_radix(value, 16).unwrap())
                .collect();
            assert_eq!(values.len(), if native { 3 } else { 2 });
            for actual in values {
                assert_eq!(actual, expected, "{level}, immediate {immediate}");
            }
            compared += 2;
            original_calls += usize::from(native);
        }
    }
    assert_eq!(compared, 1024);
    assert_eq!(original_calls, if native { 512 } else { 0 });
    eprintln!(
        "{compared} generated-C calls and {original_calls} original-machine calls agree with exact immediate patterns"
    );
    std::fs::remove_dir_all(scratch).ok();
}

#[test]
fn printed_physical_vector_slots_preserve_integer_bits_and_float_views() {
    let mut candidates = Vec::new();
    for isa in [Isa::AArch64, Isa::X86_64] {
        let low = match isa {
            Isa::AArch64 => velk::arch::aarch64::V0,
            _ => velk::arch::x86::XMM0,
        };
        let set = |index, width, value| Stmt::Assign {
            dest: velk::ir::RegRef { index, width },
            value,
            at: None,
        };
        let full = 0xfedc_ba98_7654_3210;
        let mut cases = Vec::new();
        for (width, expected) in [(16, 0x3210), (32, 0x7654_3210), (64, full)] {
            cases.push((
                format!("read{width}"),
                vec![
                    set(low, 64, Expr::Const(full)),
                    Stmt::Ret {
                        value: Expr::reg(low, width),
                        at: None,
                    },
                ],
                expected,
            ));
        }
        for (width, expected) in [(16, 0x3210), (32, 0x7654_3210)] {
            cases.push((
                format!("write{width}"),
                vec![
                    set(low, 64, Expr::Const(u64::MAX)),
                    set(low, width, Expr::Const(full)),
                    Stmt::Ret {
                        value: Expr::reg(low, 64),
                        at: None,
                    },
                ],
                expected,
            ));
        }
        cases.push((
            "upper_zero".to_owned(),
            vec![
                set(low + 1, 64, Expr::Const(u64::MAX)),
                set(low, 64, Expr::Const(0xbc00)),
                set(low + 1, 64, Expr::Const(0)),
                Stmt::Ret {
                    value: Expr::bin(BinOp::Xor, Expr::reg(low, 64), Expr::reg(low + 1, 64)),
                    at: None,
                },
            ],
            0xbc00,
        ));
        for (precision, first, second, expected) in [
            (Precision::Single, 0x3fc0_0000, 0x4010_0000, 0x4070_0000),
            (
                Precision::Double,
                0x3ff8_0000_0000_0000,
                0x4002_0000_0000_0000,
                0x400e_0000_0000_0000,
            ),
        ] {
            let sum = Expr::Apply {
                op: Operation::FloatAdd(precision),
                args: vec![Expr::reg(low, 64), Expr::reg(low + 2, 64)],
            };
            let sum = if precision == Precision::Single {
                Expr::bin(BinOp::And, sum, Expr::Const(0xffff_ffff))
            } else {
                sum
            };
            cases.push((
                format!("float{}", precision.bits()),
                vec![
                    set(low, 64, Expr::Const(first)),
                    set(low + 2, 64, Expr::Const(second)),
                    set(low + 4, 64, sum),
                    Stmt::Ret {
                        value: Expr::reg(low + 4, 64),
                        at: None,
                    },
                ],
                expected,
            ));
        }
        cases.push((
            "typed_float".to_owned(),
            vec![
                set(low, 64, Expr::Const(0x3fc0_0000)),
                set(low + 2, 64, Expr::Const(0x4010_0000)),
                set(
                    velk::ir::VARIABLE_BASE,
                    64,
                    Expr::Apply {
                        op: Operation::FloatAdd(Precision::Single),
                        args: vec![Expr::reg(low, 64), Expr::reg(low + 2, 64)],
                    },
                ),
                set(low + 4, 64, Expr::reg(velk::ir::VARIABLE_BASE, 64)),
                Stmt::Ret {
                    value: Expr::reg(low + 4, 64),
                    at: None,
                },
            ],
            0x4070_0000,
        ));
        cases.push((
            "vector_lanes".to_owned(),
            vec![
                set(low, 64, Expr::Const(u64::MAX)),
                set(low + 1, 64, Expr::Const(0x8123_4567_89ab_cdef)),
                set(
                    low + 2,
                    64,
                    Expr::Apply {
                        op: Operation::Lanes(velk::ir::LaneOp::Add, 64),
                        args: vec![Expr::reg(low, 64), Expr::Const(2)],
                    },
                ),
                Stmt::Ret {
                    value: Expr::bin(BinOp::Xor, Expr::reg(low + 2, 64), Expr::reg(low + 1, 64)),
                    at: None,
                },
            ],
            0x8123_4567_89ab_cdee,
        ));
        for (case, stmts, expected) in cases {
            let mut ir = synthetic_ir(
                &format!("physical_{isa:?}_{case}"),
                Vec::new(),
                CType::U64,
                stmts,
            );
            ir.isa = isa;
            ir.convention = if isa == Isa::AArch64 {
                Convention::Aapcs64
            } else {
                Convention::SysV
            };
            let setup = eval::Setup {
                seed: 0x5eed,
                convention: eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &[],
                memory: &[],
                step_limit: 100,
            };
            assert_eq!(
                eval::run(&ir, &setup),
                Outcome::Return {
                    value: expected,
                    calls: Vec::new(),
                    memory: BTreeMap::new()
                },
                "{isa:?}, {case}"
            );
            candidates.push(printed_candidate(ir, vec![Vec::new()]));
        }
    }
    assert_eq!(candidates.len(), 20);
    check_candidates("physical-vector-storage", candidates, Mode::Registers, &[]);
}

#[test]
fn printed_typed_float_parameters_interoperate_with_raw_vector_storage() {
    let mut source = String::from(HEADER);
    let mut body = String::from("int main(void) {\n");
    for isa in [Isa::AArch64, Isa::X86_64] {
        let low = match isa {
            Isa::AArch64 => velk::arch::aarch64::V0,
            _ => velk::arch::x86::XMM0,
        };
        for (precision, first, second, expected, ty, literal) in [
            (
                Precision::Single,
                0x3fc0_0000,
                0x4010_0000,
                0x4070_0000,
                "float",
                "1.5f",
            ),
            (
                Precision::Double,
                0x3ff8_0000_0000_0000,
                0x4002_0000_0000_0000,
                0x400e_0000_0000_0000,
                "double",
                "1.5",
            ),
        ] {
            let name = format!("typed_{isa:?}_{}", precision.bits());
            let mut ir = synthetic_ir(
                &name,
                vec![Param {
                    index: low,
                    name: "input".to_owned(),
                    ty: CType::Named(ty.to_owned()),
                }],
                CType::U64,
                vec![
                    Stmt::Assign {
                        dest: velk::ir::RegRef {
                            index: low + 2,
                            width: 64,
                        },
                        value: Expr::Const(second),
                        at: None,
                    },
                    Stmt::Assign {
                        dest: velk::ir::RegRef {
                            index: low + 4,
                            width: 64,
                        },
                        value: Expr::Apply {
                            op: Operation::FloatAdd(precision),
                            args: vec![Expr::reg(low, 64), Expr::reg(low + 2, 64)],
                        },
                        at: None,
                    },
                    Stmt::Ret {
                        value: Expr::reg(low + 4, 64),
                        at: None,
                    },
                ],
            );
            ir.isa = isa;
            ir.convention = if isa == Isa::AArch64 {
                Convention::Aapcs64
            } else {
                Convention::SysV
            };
            let registers = [(low, first)];
            let setup = eval::Setup {
                seed: 0x5eed,
                convention: eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &registers,
                memory: &[],
                step_limit: 100,
            };
            assert_eq!(
                eval::run(&ir, &setup),
                Outcome::Return {
                    value: expected,
                    calls: Vec::new(),
                    memory: BTreeMap::new()
                },
                "{name}"
            );
            source.push_str(&velk::render::render(&ir, &[], &Default::default(), &[]));
            writeln!(
                body,
                "if ({name}({literal}) != UINT64_C({expected})) return 1;"
            )
            .unwrap();
        }
    }
    body.push_str("puts(\"4 typed float parameter cases passed\");\nreturn 0;\n}\n");
    source.push_str(&body);
    let source = Program {
        text: source,
        ranges: Vec::new(),
    };
    let scratch = scratch_dir("typed-float-vector-storage");
    for level in LEVELS {
        let executable = build(&source, &scratch, level, &[]);
        assert_eq!(
            run(&executable, ""),
            "4 typed float parameter cases passed\n"
        );
    }
    std::fs::remove_dir_all(scratch).ok();
}

#[test]
fn printed_vector_entry_bits_and_numeric_patterns_do_not_acquire_new_meanings() {
    let mut source = String::from(HEADER);
    source.push_str("static uint64_t input_calls;\nstatic uint64_t raw_input(void) { ++input_calls; return UINT64_C(0x123456783fc00000); }\nvoid raw_symbol(void) {}\n");
    let mut body = String::from("int main(void) {\n");
    let mut cases = 0;
    for isa in [Isa::AArch64, Isa::X86_64] {
        let low = match isa {
            Isa::AArch64 => velk::arch::aarch64::V0,
            _ => velk::arch::x86::XMM0,
        };
        for (case, width, copied, expected) in [
            ("full", 64, false, 0x1234_5678_3fc0_0000),
            ("copied", 64, true, 0x1234_5678_3fc0_0000),
            ("low", 32, false, 0x3fc0_0000),
            ("overwritten", 64, false, 0x1234_5678_3fc0_0000),
            ("read_then_overwritten", 64, false, 0x1234_5678_0000_0000),
        ] {
            let name = format!("entry_{isa:?}_{case}");
            let mut stmts = vec![Stmt::Assign {
                dest: velk::ir::RegRef {
                    index: low + 2,
                    width: 64,
                },
                value: Expr::Const(0),
                at: None,
            }];
            let returned = if copied {
                stmts.push(Stmt::Assign {
                    dest: velk::ir::RegRef {
                        index: velk::ir::VARIABLE_BASE,
                        width: 64,
                    },
                    value: Expr::reg(low, 64),
                    at: None,
                });
                velk::ir::VARIABLE_BASE
            } else {
                low
            };
            if case == "read_then_overwritten" {
                stmts.push(Stmt::Assign {
                    dest: velk::ir::RegRef {
                        index: velk::ir::VARIABLE_BASE,
                        width: 64,
                    },
                    value: Expr::reg(low, 32),
                    at: None,
                });
            }
            if matches!(case, "overwritten" | "read_then_overwritten") {
                stmts.push(Stmt::Assign {
                    dest: velk::ir::RegRef {
                        index: low,
                        width: 64,
                    },
                    value: Expr::Const(0x1234_5678_3fc0_0000),
                    at: None,
                });
            }
            let value = if case == "read_then_overwritten" {
                Expr::bin(
                    BinOp::Xor,
                    Expr::reg(low, 64),
                    Expr::reg(velk::ir::VARIABLE_BASE, 32),
                )
            } else {
                Expr::reg(returned, width)
            };
            stmts.push(Stmt::Ret { value, at: None });
            let mut ir = synthetic_ir(
                &name,
                vec![Param {
                    index: low,
                    name: "input".to_owned(),
                    ty: CType::Named("float".to_owned()),
                }],
                CType::U64,
                stmts,
            );
            ir.isa = isa;
            ir.convention = if isa == Isa::AArch64 {
                Convention::Aapcs64
            } else {
                Convention::SysV
            };
            let registers = [(low, 0x1234_5678_3fc0_0000)];
            let setup = eval::Setup {
                seed: 0x5eed,
                convention: eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &registers,
                memory: &[],
                step_limit: 100,
            };
            assert_eq!(
                eval::run(&ir, &setup),
                Outcome::Return {
                    value: expected,
                    calls: Vec::new(),
                    memory: BTreeMap::new()
                },
                "{name}"
            );
            let code = velk::render::render(&ir, &[], &Default::default(), &[]);
            let physical = width == 64 && !matches!(case, "overwritten" | "read_then_overwritten");
            let (ty, argument) = if physical {
                ("uint64_t", "raw_input()")
            } else {
                ("float", "1.5f")
            };
            assert!(code.contains(&format!("{name}({ty} input)")), "{code}");
            source.push_str(&code);
            writeln!(
                body,
                "if ({name}({argument}) != UINT64_C({expected})) return 1;"
            )
            .unwrap();
            cases += 1;
        }
        let name = format!("numeric_{isa:?}");
        let mut ir = synthetic_ir(
            &name,
            Vec::new(),
            CType::U64,
            vec![
                Stmt::Assign {
                    dest: velk::ir::RegRef {
                        index: low,
                        width: 64,
                    },
                    value: Expr::Const(0x1000),
                    at: None,
                },
                Stmt::Ret {
                    value: Expr::reg(low, 64),
                    at: None,
                },
            ],
        );
        ir.isa = isa;
        ir.convention = if isa == Isa::AArch64 {
            Convention::Aapcs64
        } else {
            Convention::SysV
        };
        let setup = eval::Setup {
            seed: 0x5eed,
            convention: eval::Convention {
                arguments: &[],
                clobbered: &[],
            },
            registers: &[],
            memory: &[],
            step_limit: 100,
        };
        assert_eq!(
            eval::run(&ir, &setup),
            Outcome::Return {
                value: 0x1000,
                calls: Vec::new(),
                memory: BTreeMap::new()
            }
        );
        let mut symbols = velk::render::Symbols::default();
        symbols.functions.insert(0x1000, "raw_symbol".to_owned());
        source.push_str(&velk::render::render(&ir, &[], &symbols, &[]));
        writeln!(body, "if ({name}() != UINT64_C(0x1000)) return 1;").unwrap();
        cases += 1;
    }
    assert_eq!(cases, 12);
    body.push_str("if (input_calls != 4) return 2;\nputs(\"12 vector entry and numeric cases passed\");\nreturn 0;\n}\n");
    source.push_str(&body);
    let source = Program {
        text: source,
        ranges: Vec::new(),
    };
    let scratch = scratch_dir("vector-entry-and-numeric");
    for level in LEVELS {
        let executable = build(&source, &scratch, level, &[]);
        assert_eq!(
            run(&executable, ""),
            "12 vector entry and numeric cases passed\n"
        );
    }
    std::fs::remove_dir_all(scratch).ok();
}

#[test]
fn printed_floating_returns_read_the_mutable_raw_vector_slot() {
    let mut source = String::from(HEADER);
    source.push_str("#include <string.h>\n");
    let mut body = String::from("int main(void) {\n");
    for isa in [Isa::AArch64, Isa::X86_64] {
        let low = match isa {
            Isa::AArch64 => velk::arch::aarch64::V0,
            _ => velk::arch::x86::XMM0,
        };
        for (width, bits, ty, input, expected, storage) in [
            (32, 0x4070_0000, "float", "1.5f", 0x4070_0000, "uint32_t"),
            (
                64,
                0x400e_0000_0000_0000,
                "double",
                "1.5",
                0x400e_0000_0000_0000,
                "uint64_t",
            ),
        ] {
            let name = format!("return_{isa:?}_{width}");
            let mut ir = synthetic_ir(
                &name,
                vec![Param {
                    index: low,
                    name: "input".to_owned(),
                    ty: CType::Named(ty.to_owned()),
                }],
                CType::Named(ty.to_owned()),
                vec![
                    Stmt::Assign {
                        dest: velk::ir::RegRef {
                            index: low,
                            width: 64,
                        },
                        value: Expr::Const(bits),
                        at: None,
                    },
                    Stmt::Ret {
                        value: Expr::reg(low, width),
                        at: None,
                    },
                ],
            );
            ir.isa = isa;
            ir.convention = if isa == Isa::AArch64 {
                Convention::Aapcs64
            } else {
                Convention::SysV
            };
            let setup = eval::Setup {
                seed: 0x5eed,
                convention: eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &[],
                memory: &[],
                step_limit: 100,
            };
            assert_eq!(
                eval::run(&ir, &setup),
                Outcome::Return {
                    value: expected,
                    calls: Vec::new(),
                    memory: BTreeMap::new()
                },
                "{name}"
            );
            let code = velk::render::render(&ir, &[], &Default::default(), &[]);
            assert!(code.contains(&format!("{name}({ty} input)")), "{code}");
            source.push_str(&code);
            writeln!(body, "{{ {ty} result = {name}({input}); {storage} bits; memcpy(&bits, &result, sizeof(bits)); if (bits != UINT64_C({expected})) return 1; }}").unwrap();
        }
    }
    body.push_str("puts(\"4 floating return cases passed\");\nreturn 0;\n}\n");
    source.push_str(&body);
    let source = Program {
        text: source,
        ranges: Vec::new(),
    };
    let scratch = scratch_dir("floating-return-vector-storage");
    for level in LEVELS {
        let executable = build(&source, &scratch, level, &[]);
        assert_eq!(run(&executable, ""), "4 floating return cases passed\n");
    }
    std::fs::remove_dir_all(scratch).ok();
}

#[test]
fn printed_nested_physical_floating_operations_preserve_grouping() {
    let mut source = String::from(HEADER);
    source.push_str("#include <string.h>\n");
    let mut body = String::from("int main(void) {\n");
    let mut checked = 0;
    for isa in [Isa::AArch64, Isa::X86_64] {
        let low = match isa {
            Isa::AArch64 => velk::arch::aarch64::V0,
            _ => velk::arch::x86::XMM0,
        };
        for precision in [Precision::Single, Precision::Double] {
            let ty = if precision == Precision::Single {
                "float"
            } else {
                "double"
            };
            let storage = if precision == Precision::Single {
                "uint32_t"
            } else {
                "uint64_t"
            };
            let apply = |op, lhs, rhs| Expr::apply(op, vec![lhs, rhs]);
            let a = Expr::reg(low, 64);
            let b = Expr::reg(low + 2, 64);
            let t = Expr::reg(low + 4, 64);
            let add = Operation::FloatAdd(precision);
            let sub = Operation::FloatSub(precision);
            let mul = Operation::FloatMul(precision);
            let div = Operation::FloatDiv(precision);
            let large = if precision == Precision::Single {
                16_777_216.0
            } else {
                9_007_199_254_740_992.0
            };
            let other = if precision == Precision::Single {
                Precision::Double
            } else {
                Precision::Single
            };
            let cases: Vec<(&str, Expr, [f64; 3], f64)> = vec![
                (
                    "lerp",
                    apply(
                        add,
                        a.clone(),
                        apply(mul, apply(sub, b.clone(), a.clone()), t.clone()),
                    ),
                    [1.0, 3.0, 2.0],
                    5.0,
                ),
                (
                    "left_product",
                    apply(mul, apply(sub, a.clone(), b.clone()), t.clone()),
                    [16.0, 8.0, 2.0],
                    16.0,
                ),
                (
                    "subtract_sum",
                    apply(sub, a.clone(), apply(add, b.clone(), t.clone())),
                    [16.0, 8.0, 2.0],
                    6.0,
                ),
                (
                    "subtract_difference",
                    apply(sub, a.clone(), apply(sub, b.clone(), t.clone())),
                    [16.0, 8.0, 2.0],
                    10.0,
                ),
                (
                    "divide_quotient",
                    apply(div, a.clone(), apply(div, b.clone(), t.clone())),
                    [16.0, 8.0, 2.0],
                    4.0,
                ),
                (
                    "divide_product",
                    apply(div, a.clone(), apply(mul, b.clone(), t.clone())),
                    [16.0, 8.0, 2.0],
                    1.0,
                ),
                (
                    "negate_difference",
                    Expr::apply(
                        Operation::FloatNegate(precision),
                        vec![apply(sub, a.clone(), b.clone())],
                    ),
                    [16.0, 8.0, 2.0],
                    -8.0,
                ),
                (
                    "rounded_right_sum",
                    apply(add, a.clone(), apply(add, b.clone(), t.clone())),
                    [large, -large, -1.0],
                    0.0,
                ),
                (
                    "converted_difference",
                    Expr::apply(
                        Operation::FloatConvert {
                            from: other,
                            to: precision,
                        },
                        vec![Expr::apply(
                            Operation::FloatConvert {
                                from: precision,
                                to: other,
                            },
                            vec![apply(sub, a.clone(), b.clone())],
                        )],
                    ),
                    [16.0, 8.0, 2.0],
                    8.0,
                ),
            ];
            for (case, value, inputs, expected) in cases {
                let name = format!("group_{isa:?}_{}_{case}", precision.bits());
                let params = [(low, "a"), (low + 2, "b"), (low + 4, "t")]
                    .into_iter()
                    .map(|(index, name)| Param {
                        index,
                        name: name.to_owned(),
                        ty: CType::Named(ty.to_owned()),
                    })
                    .collect();
                let mut ir = synthetic_ir(
                    &name,
                    params,
                    CType::Named(ty.to_owned()),
                    vec![Stmt::Ret { value, at: None }],
                );
                ir.isa = isa;
                ir.convention = if isa == Isa::AArch64 {
                    Convention::Aapcs64
                } else {
                    Convention::SysV
                };
                let bits = |value: f64| {
                    if precision == Precision::Single {
                        u64::from((value as f32).to_bits())
                    } else {
                        value.to_bits()
                    }
                };
                let registers: Vec<_> = [low, low + 2, low + 4]
                    .into_iter()
                    .zip(inputs.map(bits))
                    .collect();
                let expected = bits(expected);
                let setup = eval::Setup {
                    seed: 0x5eed,
                    convention: eval::Convention {
                        arguments: &[],
                        clobbered: &[],
                    },
                    registers: &registers,
                    memory: &[],
                    step_limit: 100,
                };
                assert_eq!(
                    eval::run(&ir, &setup),
                    Outcome::Return {
                        value: expected,
                        calls: Vec::new(),
                        memory: BTreeMap::new()
                    },
                    "{name}"
                );
                let text = velk::render::render(&ir, &[], &Default::default(), &[]);
                assert!(
                    text.contains(&format!("{name}({ty} a, {ty} b, {ty} t)")),
                    "{text}"
                );
                source.push_str(&text);
                let arguments = inputs
                    .map(|value| {
                        if precision == Precision::Single {
                            format!("{value:.1}f")
                        } else {
                            format!("{value:.1}")
                        }
                    })
                    .join(", ");
                writeln!(body, "{{ {ty} result = {name}({arguments}); {storage} bits; memcpy(&bits, &result, sizeof(bits)); if (bits != UINT64_C({expected})) {{ fprintf(stderr, \"{name}: %\" PRIu64 \"\\n\", (uint64_t)bits); return 1; }} }}").unwrap();
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 36);
    body.push_str("puts(\"36 nested physical floating cases passed\");\nreturn 0;\n}\n");
    source.push_str(&body);
    let source = Program {
        text: source,
        ranges: Vec::new(),
    };
    let scratch = scratch_dir("nested-physical-float-grouping");
    for level in LEVELS {
        let executable = build(&source, &scratch, level, &[]);
        assert_eq!(
            run(&executable, ""),
            "36 nested physical floating cases passed\n"
        );
    }
    std::fs::remove_dir_all(scratch).ok();
}

fn check_printed_unary_floating_negation(constants: bool) {
    let mut source = String::from(HEADER);
    source.push_str("#include <string.h>\n");
    let mut body = String::from("int main(void) {\n");
    let mut checked = 0;
    for isa in [Isa::AArch64, Isa::X86_64] {
        let low = match isa {
            Isa::AArch64 => velk::arch::aarch64::V0,
            _ => velk::arch::x86::XMM0,
        };
        for precision in [Precision::Single, Precision::Double] {
            let (ty, storage, positive, negative, sign) = match precision {
                Precision::Single => (
                    "float",
                    "uint32_t",
                    0x3fa0_0000u64,
                    0xbfa0_0000u64,
                    0x8000_0000u64,
                ),
                Precision::Double => (
                    "double",
                    "uint64_t",
                    0x3ff4_0000_0000_0000u64,
                    0xbff4_0000_0000_0000u64,
                    0x8000_0000_0000_0000u64,
                ),
            };
            let negate = |value| Expr::apply(Operation::FloatNegate(precision), vec![value]);
            let parameter = Expr::reg(low, 64);
            let cases = if constants {
                vec![
                    (
                        "negative_constant",
                        negate(Expr::Const(negative)),
                        positive,
                        positive,
                    ),
                    (
                        "double_negative_constant",
                        negate(negate(Expr::Const(negative))),
                        positive,
                        negative,
                    ),
                    (
                        "positive_zero_constant",
                        negate(Expr::Const(0)),
                        positive,
                        sign,
                    ),
                    (
                        "negative_zero_constant",
                        negate(Expr::Const(sign)),
                        positive,
                        0,
                    ),
                    (
                        "double_positive_zero_constant",
                        negate(negate(Expr::Const(0))),
                        positive,
                        0,
                    ),
                    (
                        "double_negative_zero_constant",
                        negate(negate(Expr::Const(sign))),
                        positive,
                        sign,
                    ),
                ]
            } else {
                vec![
                    (
                        "positive_parameter",
                        negate(negate(parameter.clone())),
                        positive,
                        positive,
                    ),
                    (
                        "negative_parameter",
                        negate(negate(parameter.clone())),
                        negative,
                        negative,
                    ),
                    (
                        "positive_zero_parameter",
                        negate(negate(parameter.clone())),
                        0,
                        0,
                    ),
                    (
                        "negative_zero_parameter",
                        negate(negate(parameter)),
                        sign,
                        sign,
                    ),
                ]
            };
            for (case, value, input, expected) in cases {
                let name = format!("unary_{isa:?}_{}_{case}", precision.bits());
                let mut ir = synthetic_ir(
                    &name,
                    vec![Param {
                        index: low,
                        name: "input".to_owned(),
                        ty: CType::Named(ty.to_owned()),
                    }],
                    CType::Named(ty.to_owned()),
                    vec![Stmt::Ret { value, at: None }],
                );
                ir.isa = isa;
                ir.convention = if isa == Isa::AArch64 {
                    Convention::Aapcs64
                } else {
                    Convention::SysV
                };
                let registers = [(low, input)];
                let setup = eval::Setup {
                    seed: 0x5eed,
                    convention: eval::Convention {
                        arguments: &[],
                        clobbered: &[],
                    },
                    registers: &registers,
                    memory: &[],
                    step_limit: 100,
                };
                assert_eq!(
                    eval::run(&ir, &setup),
                    Outcome::Return {
                        value: expected,
                        calls: Vec::new(),
                        memory: BTreeMap::new()
                    },
                    "{name}",
                );
                let text = velk::render::render(&ir, &[], &Default::default(), &[]);
                assert!(text.contains(&format!("{name}({ty} input)")), "{text}");
                source.push_str(&text);
                writeln!(body, "{{ {storage} raw = UINT64_C({input}); {ty} input; memcpy(&input, &raw, sizeof(input)); {ty} result = {name}(input); {storage} bits; memcpy(&bits, &result, sizeof(bits)); if (bits != UINT64_C({expected})) {{ fprintf(stderr, \"{name}: %\" PRIu64 \"\\n\", (uint64_t)bits); return 1; }} }}").expect("formatting into a String cannot fail");
                checked += 1;
            }
        }
    }
    let expected_count = if constants { 24 } else { 16 };
    assert_eq!(checked, expected_count);
    println!("unary floating original IR cases: {checked}");
    writeln!(
        body,
        "puts(\"{expected_count} unary floating cases passed\");\nreturn 0;\n}}"
    )
    .expect("formatting into a String cannot fail");
    source.push_str(&body);
    let source = Program {
        text: source,
        ranges: Vec::new(),
    };
    let pass = if constants {
        "unary-floating-constants"
    } else {
        "unary-floating-parameters"
    };
    let scratch = scratch_dir(pass);
    for level in LEVELS {
        let executable = build(&source, &scratch, level, &[]);
        assert_eq!(
            run(&executable, ""),
            format!("{expected_count} unary floating cases passed\n")
        );
    }
    std::fs::remove_dir_all(scratch).ok();
}

#[test]
fn printed_unary_floating_negation_parameters_preserve_literal_bits() {
    check_printed_unary_floating_negation(false);
}

#[test]
fn printed_unary_floating_negation_constants_preserve_literal_bits() {
    check_printed_unary_floating_negation(true);
}

#[test]
fn printed_readonly_floating_views_preserve_raw_reads_and_overwrites() {
    let mut source = String::from(HEADER);
    source.push_str("#include <string.h>\nstatic double hetero_input(void) { uint64_t bits = UINT64_C(0x3ff000003fc00000); double value; memcpy(&value, &bits, sizeof(value)); return value; }\n");
    let mut body = String::from("int main(void) {\n");
    let mut checked = 0;
    for isa in [Isa::AArch64, Isa::X86_64] {
        let low = if isa == Isa::AArch64 {
            velk::arch::aarch64::V0
        } else {
            velk::arch::x86::XMM0
        };
        for (precision, first, second, written, sum, mixed, overwritten, ty, storage, a, b) in [
            (
                Precision::Single,
                0x3fc0_0000,
                0x4010_0000,
                0x40f0_0000,
                0x4070_0000,
                0x7fb0_0000,
                0x4134_0000,
                "float",
                "uint32_t",
                "1.5f",
                "2.25f",
            ),
            (
                Precision::Double,
                0x3ff8_0000_0000_0000,
                0x4002_0000_0000_0000,
                0x401e_0000_0000_0000,
                0x400e_0000_0000_0000,
                0x7ff6_0000_0000_0000,
                0x4026_8000_0000_0000,
                "double",
                "uint64_t",
                "1.5",
                "2.25",
            ),
        ] {
            for (case, expected) in [
                ("readonly", sum),
                ("mixed_raw", mixed),
                ("overwritten", overwritten),
            ] {
                let name = format!("view_{isa:?}_{}_{case}", precision.bits());
                let sum = Expr::apply(
                    Operation::FloatAdd(precision),
                    vec![Expr::reg(low, 64), Expr::reg(low + 2, 64)],
                );
                let mut stmts = Vec::new();
                let value = match case {
                    "mixed_raw" => Expr::bin(BinOp::Xor, sum, Expr::reg(low, precision.bits())),
                    "overwritten" => {
                        stmts.push(Stmt::Assign {
                            dest: velk::ir::RegRef {
                                index: velk::ir::VARIABLE_BASE,
                                width: 64,
                            },
                            value: sum,
                            at: None,
                        });
                        stmts.push(Stmt::Assign {
                            dest: velk::ir::RegRef {
                                index: low,
                                width: 64,
                            },
                            value: Expr::Const(written),
                            at: None,
                        });
                        Expr::apply(
                            Operation::FloatAdd(precision),
                            vec![Expr::reg(low, 64), Expr::reg(velk::ir::VARIABLE_BASE, 64)],
                        )
                    }
                    _ => sum,
                };
                stmts.push(Stmt::Ret { value, at: None });
                let params = [(low, "a"), (low + 2, "b")]
                    .into_iter()
                    .map(|(index, name)| Param {
                        index,
                        name: name.to_owned(),
                        ty: CType::Named(ty.to_owned()),
                    })
                    .collect();
                let mut ir = synthetic_ir(
                    &name,
                    params,
                    if case == "mixed_raw" {
                        CType::U64
                    } else {
                        CType::Named(ty.to_owned())
                    },
                    stmts,
                );
                ir.isa = isa;
                ir.convention = if isa == Isa::AArch64 {
                    Convention::Aapcs64
                } else {
                    Convention::SysV
                };
                let registers = [(low, first), (low + 2, second)];
                let setup = eval::Setup {
                    seed: 0x5eed,
                    convention: eval::Convention {
                        arguments: &[],
                        clobbered: &[],
                    },
                    registers: &registers,
                    memory: &[],
                    step_limit: 100,
                };
                assert_eq!(
                    eval::run(&ir, &setup),
                    Outcome::Return {
                        value: expected,
                        calls: Vec::new(),
                        memory: BTreeMap::new()
                    },
                    "{name}"
                );
                let text = velk::render::render(&ir, &[], &Default::default(), &[]);
                if case != "readonly" {
                    let slot = if case == "overwritten" { "v2" } else { "v1" };
                    assert!(text.contains(&format!("uint64_t {slot} =")), "{text}");
                }
                source.push_str(&text);
                if case == "mixed_raw" {
                    writeln!(
                        body,
                        "if ({name}({a}, {b}) != UINT64_C({expected})) return 1;"
                    )
                    .unwrap();
                } else {
                    writeln!(body, "{{ {ty} result = {name}({a}, {b}); {storage} bits; memcpy(&bits, &result, sizeof(bits)); if (bits != UINT64_C({expected})) return 1; }}").unwrap();
                }
                checked += 1;
            }
        }
        let name = format!("view_{isa:?}_heterogeneous_precision");
        let mut ir = synthetic_ir(
            &name,
            vec![Param {
                index: low,
                name: "a".to_owned(),
                ty: CType::Named("double".to_owned()),
            }],
            CType::Named("float".to_owned()),
            vec![Stmt::Ret {
                value: Expr::apply(
                    Operation::FloatAdd(Precision::Single),
                    vec![Expr::reg(low, 32), Expr::Const(0x4000_0000)],
                ),
                at: None,
            }],
        );
        ir.isa = isa;
        ir.convention = if isa == Isa::AArch64 {
            Convention::Aapcs64
        } else {
            Convention::SysV
        };
        let registers = [(low, 0x3ff0_0000_3fc0_0000)];
        let setup = eval::Setup {
            seed: 0x5eed,
            convention: eval::Convention {
                arguments: &[],
                clobbered: &[],
            },
            registers: &registers,
            memory: &[],
            step_limit: 100,
        };
        assert_eq!(
            eval::run(&ir, &setup),
            Outcome::Return {
                value: 0x4060_0000,
                calls: Vec::new(),
                memory: BTreeMap::new()
            },
            "{name}"
        );
        let text = velk::render::render(&ir, &[], &Default::default(), &[]);
        assert!(!text.contains("return a +"), "{text}");
        source.push_str(&text);
        writeln!(body, "{{ float result = {name}(hetero_input()); uint32_t bits; memcpy(&bits, &result, sizeof(bits)); if (bits != UINT64_C(0x40600000)) return 1; }}").unwrap();
        checked += 1;
    }
    assert_eq!(checked, 14);
    body.push_str("puts(\"14 readonly floating view cases passed\");\nreturn 0;\n}\n");
    source.push_str(&body);
    let source = Program {
        text: source,
        ranges: Vec::new(),
    };
    let scratch = scratch_dir("readonly-floating-views");
    for level in LEVELS {
        let executable = build(&source, &scratch, level, &[]);
        assert_eq!(
            run(&executable, ""),
            "14 readonly floating view cases passed\n"
        );
    }
    std::fs::remove_dir_all(scratch).ok();
}

#[test]
fn printed_readonly_floating_views_keep_narrow_same_precision_reads_raw() {
    let mut source = String::from(HEADER);
    source.push_str("#include <string.h>\nstatic double narrow_double_input(void) { uint64_t bits = UINT64_C(0x3ff000003fc00000); double value; memcpy(&value, &bits, sizeof(value)); return value; }\n");
    let mut body = String::from("int main(void) {\n");
    let mut checked = 0;
    for isa in [Isa::AArch64, Isa::X86_64] {
        let low = if isa == Isa::AArch64 {
            velk::arch::aarch64::V0
        } else {
            velk::arch::x86::XMM0
        };
        for (width, initial, expected, ty, storage, argument) in [
            (16, 0x3fc0_0000, 0, "float", "uint32_t", "1.5f"),
            (
                32,
                0x3ff0_0000_3fc0_0000,
                0x3fc0_0000,
                "double",
                "uint64_t",
                "narrow_double_input()",
            ),
        ] {
            let name = format!("narrow_view_{isa:?}_{width}");
            let mut ir = synthetic_ir(
                &name,
                vec![Param {
                    index: low,
                    name: "a".to_owned(),
                    ty: CType::Named(ty.to_owned()),
                }],
                CType::Named(ty.to_owned()),
                vec![Stmt::Ret {
                    value: Expr::reg(low, width),
                    at: None,
                }],
            );
            ir.isa = isa;
            ir.convention = if isa == Isa::AArch64 {
                Convention::Aapcs64
            } else {
                Convention::SysV
            };
            let registers = [(low, initial)];
            let setup = eval::Setup {
                seed: 0x5eed,
                convention: eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &registers,
                memory: &[],
                step_limit: 100,
            };
            assert_eq!(
                eval::run(&ir, &setup),
                Outcome::Return {
                    value: expected,
                    calls: Vec::new(),
                    memory: BTreeMap::new()
                },
                "{name}"
            );
            let text = velk::render::render(&ir, &[], &Default::default(), &[]);
            assert!(text.contains(&format!("{name}({ty} a)")), "{text}");
            let slot = "v1";
            assert!(text.contains(&format!("uint64_t {slot} =")), "{text}");
            assert!(!text.contains("return a;"), "{text}");
            source.push_str(&text);
            writeln!(body, "{{ {ty} result = {name}({argument}); {storage} bits; memcpy(&bits, &result, sizeof(bits)); if (bits != UINT64_C({expected})) return 1; }}").unwrap();
            checked += 1;
        }
    }
    assert_eq!(checked, 4);
    body.push_str("puts(\"4 narrow floating read cases passed\");\nreturn 0;\n}\n");
    source.push_str(&body);
    let source = Program {
        text: source,
        ranges: Vec::new(),
    };
    let scratch = scratch_dir("narrow-floating-views");
    for level in LEVELS {
        let executable = build(&source, &scratch, level, &[]);
        assert_eq!(
            run(&executable, ""),
            "4 narrow floating read cases passed\n"
        );
    }
    std::fs::remove_dir_all(scratch).ok();
}

#[test]
fn aggregate_field_projection_rejects_unverified_objects() {
    let path = common::fixtures_dir().join("metrics/structs.x86_64.O0.debug.elf");
    let mut binary = Binary::open(&path).unwrap();
    let address = binary.find("point_add").unwrap().addr;
    let original = binary.analysis(address, None).unwrap().ir.clone();
    for case in 0..23 {
        let mut ir = original.clone();
        match case {
            0 => ir
                .members
                .iter_mut()
                .filter(|m| m.structure == "point")
                .for_each(|m| m.width = 2),
            1 => ir
                .members
                .iter_mut()
                .filter(|m| m.structure == "point")
                .for_each(|m| m.offset = 0),
            2 | 3 => ir
                .definitions
                .iter_mut()
                .filter(|d| d.name == "struct point")
                .for_each(|d| d.alignment = Some(if case == 2 { 1 } else { 16 })),
            4 => {
                ir.declared_signature.as_mut().unwrap().params[0].1 =
                    CType::Named("struct other".into());
                let mut other = ir
                    .definitions
                    .iter()
                    .find(|d| d.name == "struct point")
                    .unwrap()
                    .clone();
                other.name = "struct other".into();
                ir.definitions.push(other);
            }
            5 => {
                if let Stmt::Store { width, .. } = &mut ir.blocks[0].stmts[0] {
                    *width = 4;
                }
            }
            6 => {
                let addr = match &ir.blocks[0].stmts[0] {
                    Stmt::Store { addr, .. } => addr.clone(),
                    _ => panic!(),
                };
                if let Stmt::Store { addr: target, .. } = &mut ir.blocks[0].stmts[1] {
                    *target = addr;
                }
            }
            7..=9 => {
                let abi = ir
                    .declared_signature
                    .as_mut()
                    .unwrap()
                    .abi
                    .as_mut()
                    .unwrap();
                if case == 7 {
                    abi.arguments[0].defined_bits = vec![(0, 32)];
                }
                if case == 8 {
                    abi.arguments[0].size = u64::MAX;
                }
                if case == 9 {
                    abi.arguments[0].size = 0;
                }
            }
            10 => {
                let signature = ir.declared_signature.as_mut().unwrap();
                signature.ret = CType::Named("union point".into());
                for (_, ty) in &mut signature.params {
                    *ty = CType::Named("union point".into());
                }
                for definition in &mut ir.definitions {
                    if definition.name == "struct point" {
                        definition.name = "union point".into();
                    }
                }
            }
            11 => {
                if let Stmt::Store { width, .. } = &mut ir.blocks[0].stmts[2] {
                    *width = 2;
                }
            }
            12 => {
                let addr = match &ir.blocks[0].stmts[2] {
                    Stmt::Store { addr, .. } => addr.clone(),
                    _ => panic!(),
                };
                if let Stmt::Store { addr: target, .. } = &mut ir.blocks[0].stmts[3] {
                    *target = addr;
                }
            }
            13 => {
                let abi = ir
                    .declared_signature
                    .as_mut()
                    .unwrap()
                    .abi
                    .as_mut()
                    .unwrap();
                if let Passing::Direct(pieces) = &mut abi.arguments[0].passing {
                    pieces[0].class = Some(RegisterClass::Simd);
                }
            }
            14 | 15 | 19 => {
                let sp = if let Stmt::Store { addr, .. } = &ir.blocks[0].stmts[0] {
                    match addr {
                        Expr::Bin { lhs, .. } => lhs.as_ref().clone(),
                        _ => panic!("expected frame address"),
                    }
                } else {
                    panic!("expected aggregate copy");
                };
                if let Stmt::Store { addr, .. } = &mut ir.blocks[0].stmts[0] {
                    *addr = Expr::bin(
                        BinOp::Add,
                        sp,
                        Expr::Const(match case {
                            14 => 8,
                            15 => i64::MAX as u64,
                            _ => i64::MIN as u64,
                        }),
                    );
                }
            }
            16 => {
                let address = match &ir.blocks[0].stmts[0] {
                    Stmt::Store { addr, .. } => addr.clone(),
                    _ => panic!("expected aggregate copy"),
                };
                if let Stmt::Store { value, .. } = &mut ir.blocks[0].stmts[2] {
                    *value = address;
                }
            }
            17 => {
                let extra = ir.blocks[0].stmts[0].clone();
                ir.blocks[0].stmts.insert(2, extra);
            }
            18 => {
                for definition in &mut ir.definitions {
                    if definition.name == "struct point" {
                        definition.size = u64::MAX;
                    }
                }
            }
            20 => {
                if let Stmt::Store { value, .. } = &mut ir.blocks[0].stmts[2] {
                    *value = Expr::Load {
                        addr: Box::new(Expr::reg(7, 64)),
                        width: 2,
                        signed: false,
                    };
                }
            }
            21 => {
                if let Stmt::Store { addr, .. } = &mut ir.blocks[0].stmts[3] {
                    *addr = Expr::reg(7, 64);
                }
            }
            22 => {
                let signature = ir.declared_signature.as_mut().unwrap();
                signature
                    .abi
                    .as_mut()
                    .unwrap()
                    .result
                    .as_mut()
                    .unwrap()
                    .defined_bits = vec![(0, 32)];
            }
            _ => unreachable!(),
        }
        let code = velk::render::render(&ir, &[], &Default::default(), &[]);
        assert!(!code.contains("uint32_t a_x = a.x;"), "case {case}: {code}");
    }
}

#[test]
fn aggregate_field_names_preserve_c_type_names() {
    let path = common::fixtures_dir().join("metrics/structs.x86_64.O0.debug.elf");
    let mut binary = Binary::open(&path).unwrap();
    let address = binary.find("point_add").unwrap().addr;
    let mut ir = binary.analysis(address, None).unwrap().ir.clone();
    ir.declared_signature.as_mut().unwrap().params[0].0 = "uint64".into();
    for member in &mut ir.members {
        if member.structure == "point" && member.name == "x" {
            member.name = "t".into();
        }
    }
    let definition = ir
        .definitions
        .iter_mut()
        .find(|d| d.name == "struct point")
        .unwrap();
    definition.fields[0] = "t".into();
    definition.members[0] = definition.members[0].replace(" x;", " t;");
    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
    assert!(code.contains("uint32_t uint64_t_2 = uint64.t;"), "{code}");
    let (inputs, upper) = aggregate_inputs(&[8, 8], 12);
    let candidates = aggregate_candidates(ir, inputs, upper);
    check_candidates("aggregate-field-names", candidates, Mode::Registers, &[]);
}

#[test]
fn printed_point_fields_match_original_machine_code() {
    let isa = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else {
        return;
    };
    let prefix = if cfg!(target_os = "macos") { "_" } else { "" };
    let scratch = scratch_dir("point-fields-machine");
    let mut architectures = vec![isa];
    if cfg!(all(target_os = "macos", target_arch = "aarch64"))
        && Command::new("arch")
            .args(["-x86_64", "true"])
            .output()
            .is_ok_and(|output| output.status.success())
    {
        architectures.push("x86_64");
    }
    for isa in architectures {
        for optimization in ["O0", "O2"] {
            let path = common::fixtures_dir()
                .join(format!("metrics/structs.{isa}.{optimization}.debug.elf"));
            let mut binary = Binary::open(&path).unwrap();
            let function = binary.find("point_add").unwrap().clone();
            let mut ir = binary.analysis(function.addr, None).unwrap().ir.clone();
            ir.name = Some("projected_point".into());
            let bytes = binary
                .image()
                .read_vaddr(function.addr, function.size.expect("fixture function size"))
                .unwrap();
            let encoded = bytes
                .iter()
                .map(|byte| byte.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let mut source = String::from("#include <stdint.h>\n#include <stdbool.h>\n");
            source.push_str(&velk::render::render(&ir, &[], &Default::default(), &[]));
            writeln!(
                source,
                "extern struct point original_point(struct point, struct point);"
            )
            .unwrap();
            writeln!(source, "__asm__(\".text\\n.p2align 2\\n.globl {prefix}original_point\\n{prefix}original_point:\\n.byte {encoded}\\n\");").unwrap();
            source.push_str(
            "int main(void) {\nuint32_t values[] = {0, 1, 0x7fffffff, 0x80000000, 0xffffffff};\n",
        );
            source.push_str("for (unsigned a = 0; a < 5; ++a) for (unsigned b = 0; b < 5; ++b) for (unsigned c = 0; c < 5; ++c) for (unsigned d = 0; d < 5; ++d) {\n");
            source.push_str("struct point x = {(int32_t)values[a], (int32_t)values[b]}, y = {(int32_t)values[c], (int32_t)values[d]};\nstruct point expected = original_point(x, y), actual = projected_point(x, y);\nif (actual.x != expected.x || actual.y != expected.y) return 1;\n}\nreturn 0;\n}\n");
            let input = scratch.join(format!("point-{isa}-{optimization}.c"));
            std::fs::write(&input, source).unwrap();
            for level in LEVELS {
                let executable = scratch.join(format!("point-{isa}-{optimization}-{level}"));
                let mut compiler = Command::new(compiler());
                if cfg!(target_os = "macos") {
                    compiler.args(["-arch", if isa == "aarch64" { "arm64" } else { "x86_64" }]);
                }
                let compiled = compiler
                    .args(["-std=c11", level])
                    .args(FLAGS)
                    .arg(&input)
                    .arg("-o")
                    .arg(&executable)
                    .output()
                    .unwrap();
                assert!(
                    compiled.status.success(),
                    "{}",
                    String::from_utf8_lossy(&compiled.stderr)
                );
                let output = Command::new(&executable).output().unwrap();
                assert!(
                    output.status.success(),
                    "{isa} {optimization} {level}: {output:?}"
                );
            }
        }
    }
    std::fs::remove_dir_all(scratch).ok();
}

#[path = "recompile/comparison_inputs.rs"]
mod comparison_inputs;
#[path = "recompile/vector_elements.rs"]
mod vector_elements;
#[path = "recompile/vector_extensions.rs"]
mod vector_extensions;

#[path = "recompile/i386.rs"]
mod i386;

#[path = "recompile/word_pairs.rs"]
mod word_pairs;

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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use velk::ir::eval::{self, Outcome};
use velk::ir::{
    Access, BinOp, Block, CType, Cond, Convention, Definition, Expr, FunctionIr, Member, Operation,
    Param, Precision, Stmt, trials,
};
use velk::loader::{Image, Isa};
use velk::render::{SegmentBase, SegmentBaseRead};
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
            velk_fixture_overlay(page, velk_page);
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
            velk_prepare(k, velk_seed);
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

#[test]
fn printed_global_views_preserve_addresses_and_memory() {
    assert!(
        Command::new(COMPILER)
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success()),
        "{COMPILER} is required to check global memory accesses"
    );
    let address = REGION + 0x1000;
    let load = |addr, width, signed| Expr::Load {
        addr: Box::new(addr),
        width,
        signed,
    };
    let store = |addr, width, value| Stmt::Store { addr, width, value };
    let mut cases = vec![
        (
            "unsigned_read".to_owned(),
            Vec::new(),
            vec![Stmt::Ret {
                value: load(Expr::Const(address), 8, false),
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
            }],
            CType::U64,
        ),
        (
            "integer_address".to_owned(),
            Vec::new(),
            vec![Stmt::Ret {
                value: Expr::Const(address),
            }],
            CType::U64,
        ),
        (
            "pointer_address".to_owned(),
            Vec::new(),
            vec![Stmt::Ret {
                value: Expr::Const(address),
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
    };
    let mut cases = Vec::new();
    let mut case = |name: &str, mut stmts: Vec<Stmt>, value: Expr| {
        stmts.push(Stmt::Ret { value });
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
                        },
                        Stmt::Store {
                            addr: address.clone(),
                            width: bytes,
                            value: Expr::Const(raw),
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
                        },
                        Stmt::Ret {
                            value: Expr::Load {
                                addr: Box::new(address),
                                width: 8,
                                signed: false,
                            },
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
                },
                Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(Expr::Const(REGION + 0x2000)),
                        width: 8,
                        signed: false,
                    },
                },
            ],
        );
        let code = velk::render::render(&ir, &[], &Default::default(), &[(base, 0x1_0001_0000)]);
        updates.push(Candidate {
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
            })
            .collect::<Vec<_>>();
        let result = REGION + 0x8040;
        stmts.push(Stmt::Store {
            addr: Expr::Const(result),
            width,
            value,
        });
        stmts.push(Stmt::Ret {
            value: Expr::Load {
                addr: Box::new(Expr::Const(result)),
                width,
                signed: false,
            },
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
        stmts.push(Stmt::Ret { value });
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
            vec![Stmt::Ret { value }],
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
                    },
                    Stmt::Ret { value: returned },
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
    let syntax = Command::new(COMPILER)
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
    let linked = Command::new(COMPILER)
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

fn synthetic_ir(name: &str, params: Vec<Param>, ret_type: CType, stmts: Vec<Stmt>) -> FunctionIr {
    FunctionIr {
        isa: Isa::X86_64,
        convention: Convention::SysV,
        params,
        stack_params: Vec::new(),
        variadic: false,
        ret_type,
        accesses: Vec::new(),
        members: Vec::new(),
        definitions: Vec::new(),
        structures: Vec::new(),
        signed_params: Default::default(),
        landing_pads: Vec::new(),
        pointer_values: Vec::new(),
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

fn check_candidates(name: &str, candidates: Vec<Candidate>, mode: Mode, compiler_args: &[&str]) {
    let count = candidates.len();
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
    std::fs::remove_dir_all(&scratch).ok();
    assert_comparisons(&results[0], count);
}

fn assert_comparisons(result: &Findings, count: usize) {
    assert!(result.lines.is_empty(), "{}", result.lines.join("\n"));
    assert!(result.skipped.is_empty(), "{:?}", result.skipped);
    assert_eq!(result.compiled, count);
    assert_eq!(result.failed, 0);
    assert_eq!(result.compared, count);
    assert_eq!(result.runs, count * trials::TRIALS as usize);
    assert_eq!(result.differing, 0);
}

fn compare(mode: Mode, golden: &str) {
    if Command::new(COMPILER).arg("--version").output().is_err() {
        eprintln!("skipping: no `{COMPILER}` to compile the pseudo-C with");
        return;
    }
    let fixtures = common::fixtures();
    let prepared = common::in_parallel(&fixtures, |fixture| prepare(fixture, mode));
    let scratch = scratch_dir(match mode {
        Mode::Registers => "registers",
        Mode::Memory => "memory",
    });
    let results = check(&prepared, &scratch, mode, &[]);
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
    params: Vec<String>,
    /// Each trial's argument values, in parameter order.
    inputs: Vec<Vec<u64>>,
    /// It returns nothing, so only its effects compare.
    void: bool,
}

#[derive(Clone)]
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
        let Ok(analysis) = binary.analysis(function.addr) else {
            *excluded.entry("does not lift").or_default() += 1;
            continue;
        };
        if let Err(reason) = qualifies(&analysis.ir, analysis.references.is_empty(), mode) {
            *excluded.entry(reason).or_default() += 1;
            continue;
        }
        let ir = analysis.ir.clone();
        let rendered = binary
            .decompile_with_dependencies(function.addr, None)
            .unwrap_or_else(|error| panic!("{error}"));
        if mode == Mode::Registers && !rendered.segment_bases.is_empty() {
            *excluded.entry("requires segment state").or_default() += 1;
            continue;
        }
        let code = rendered.code;
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
fn check(
    fixtures: &[Fixture],
    scratch: &Path,
    mode: Mode,
    compiler_args: &[&str],
) -> Vec<Findings> {
    let mut results: Vec<Findings> = fixtures.iter().map(|_| Findings::default()).collect();
    let all: Vec<(usize, &Candidate)> = fixtures
        .iter()
        .enumerate()
        .flat_map(|(index, fixture)| fixture.candidates.iter().map(move |c| (index, c)))
        .collect();
    let candidates: Vec<&Candidate> = all.iter().map(|(_, candidate)| *candidate).collect();
    let initial_memory: Vec<&[(u64, u64)]> = all
        .iter()
        .map(|(fixture, _)| fixtures[*fixture].initial_memory.as_slice())
        .collect();
    for candidate in &candidates {
        for trial in 0..trials::TRIALS {
            segment_state(candidate, trial)
                .unwrap_or_else(|reason| panic!("{}: {reason}", candidate.label));
        }
    }
    let (alive, failures) = compiles(&candidates, &initial_memory, &scratch.join("check.c"), mode);
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
    let source = program(&candidates, &initial_memory, &alive, mode);
    let programs: Vec<PathBuf> = std::thread::scope(|scope| {
        let handles: Vec<_> = LEVELS
            .iter()
            .map(|level| {
                let source = &source;
                scope.spawn(move || build(source, scratch, level, compiler_args))
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
            match interpret(&fixtures[fixture], candidate, trial, &arguments, mode) {
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
    fixture: &Fixture,
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
    registers.extend_from_slice(&fixture.entry_registers);
    let mut memory = Vec::new();
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
    memory.extend_from_slice(&fixture.initial_memory);
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
    let outcome = eval::run(&candidate.ir, &setup);
    if let Outcome::Unknown(reason) = outcome {
        return Err(reason);
    }
    let reseeded = eval::Setup {
        seed: OTHER_SEED + trial,
        ..setup
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
    initial_memory: &[&[(u64, u64)]],
    source: &Path,
    mode: Mode,
) -> (Vec<usize>, BTreeMap<usize, String>) {
    let mut alive: Vec<usize> = (0..candidates.len()).collect();
    let mut failures = BTreeMap::new();
    for _ in 0..COMPILE_ROUNDS {
        let text = program(candidates, initial_memory, &alive, mode);
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
fn build(source: &Program, scratch: &Path, level: &str, compiler_args: &[&str]) -> PathBuf {
    let path = scratch.join(format!("check{level}.c"));
    let output = scratch.join(format!("check{level}"));
    std::fs::write(&path, &source.text).unwrap_or_else(|error| panic!("{error}"));
    let compiled = Command::new(COMPILER)
        .arg(level)
        .args(FLAGS)
        .arg("-o")
        .arg(&output)
        .arg(&path)
        .args(compiler_args)
        .output()
        .unwrap_or_else(|error| panic!("{COMPILER}: {error}"));
    assert!(
        compiled.status.success(),
        "{COMPILER} {level} fails on {}:\n{}",
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
    while index < code.len() {
        let rest = &code[index..];
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
        } else {
            first.len_utf8()
        };
        let token = &rest[..length];
        out.push_str(if token == from { to } else { token });
        index += length;
    }
    out
}

fn bound_candidate(
    candidate: &Candidate,
    index: usize,
    reserved: &mut BTreeSet<String>,
) -> (String, Vec<(String, SegmentBase)>) {
    let mut code = renamed(&candidate.code, index);
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
fn program(
    candidates: &[&Candidate],
    initial_memory: &[&[(u64, u64)]],
    alive: &[usize],
    mode: Mode,
) -> Program {
    assert_eq!(candidates.len(), initial_memory.len());
    let mut text = String::from(HEADER);
    if mode == Mode::Memory {
        writeln!(
            text,
            "#define REGION_START 0x{REGION:x}ULL\n#define REGION_BYTES 0x{REGION_SIZE:x}ULL"
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
                    "velk_fixture_overlay(page, velk_page)",
                    &format!("{overlay}(page, velk_page)"),
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

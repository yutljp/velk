//! The optimization passes must not change what a function does: every fixture
//! function runs through the interpreter before and after them, on the same inputs.
//! Current mismatches are listed in tests/golden/semantics.txt; a new one fails,
//! and a fixed one must be removed with `VELK_BLESS=1 cargo test semantics`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use super::{lift_function, optimize};
use crate::ir::CType;
use crate::ir::eval::{self, Convention, Outcome, Setup, hash};
use crate::loader::{self, Format, Function, Image, Isa};

const TRIALS: u64 = 12;
const STEP_LIMIT: usize = 20_000;
const INTERESTING: [u64; 10] = [
    0,
    1,
    2,
    7,
    u64::MAX,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_ffff,
    0x8000_0000_0000_0000,
    0x7fff_ffff_ffff_ffff,
];

#[test]
fn passes_preserve_behavior() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut fixtures = Vec::new();
    collect(&root.join("tests/fixtures"), Path::new(""), &mut fixtures);
    fixtures.sort();
    let images: Vec<Image> = fixtures
        .iter()
        .map(|fixture| open(&root.join("tests/fixtures").join(fixture)))
        .collect();
    let work: Vec<(usize, &Function)> = images
        .iter()
        .enumerate()
        .flat_map(|(index, image)| {
            image
                .functions
                .values()
                .map(move |function| (index, function))
        })
        .collect();

    let next = AtomicUsize::new(0);
    let workers = std::thread::available_parallelism().map_or(4, |count| count.get());
    let checks: Vec<Check> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                scope.spawn(|| {
                    let mut done = Vec::new();
                    while let Some((index, function)) =
                        work.get(next.fetch_add(1, Ordering::Relaxed))
                    {
                        done.push(check(&fixtures[*index], &images[*index], function));
                    }
                    done
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| {
                handle
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            })
            .collect()
    });

    let (mut checked, mut runs) = (0, 0);
    let mut unknown: BTreeMap<String, usize> = BTreeMap::new();
    let mut mismatches: Vec<String> = Vec::new();
    for result in checks {
        checked += usize::from(result.lifted);
        runs += result.runs;
        for reason in result.unknown {
            *unknown.entry(reason).or_default() += 1;
        }
        mismatches.extend(result.mismatch);
    }
    mismatches.sort();
    let mut actual =
        format!("# {checked} functions, {runs} compared runs\n# runs left unfinished:\n");
    for (reason, count) in &unknown {
        writeln!(actual, "#   {reason}: {count}").expect("writing to a String");
    }
    for line in mismatches {
        actual.push_str(&line);
        actual.push('\n');
    }

    let path = root.join("tests/golden/semantics.txt");
    if std::env::var_os("VELK_BLESS").is_some_and(|value| value == "1") {
        std::fs::write(&path, &actual)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_default();
    if expected != actual {
        panic!(
            "behavior changes differ from {}:\n{}",
            path.display(),
            changes(&expected, &actual)
        );
    }
}

/// The functions that newly differ and the ones no longer listed.
fn changes(expected: &str, actual: &str) -> String {
    let functions = |text: &str| -> BTreeMap<String, String> {
        text.lines()
            .filter(|line| !line.starts_with('#'))
            .map(|line| {
                (
                    line.split_whitespace()
                        .take(2)
                        .collect::<Vec<_>>()
                        .join(" "),
                    line.to_owned(),
                )
            })
            .collect()
    };
    let (before, after) = (functions(expected), functions(actual));
    let mut out = String::new();
    for (key, line) in &after {
        if !before.contains_key(key) {
            writeln!(out, "  new: {line}").expect("writing to a String");
        }
    }
    for (key, line) in &before {
        if !after.contains_key(key) {
            writeln!(out, "  no longer differs: {line}").expect("writing to a String");
        }
    }
    if out.is_empty() {
        out.push_str("  the same functions differ; the counts or descriptions changed\n");
    }
    out
}

/// Go and Rust executables are mostly their runtimes, so they are counted apart.
fn group(fixture: &Path) -> &'static str {
    let name = fixture.to_string_lossy();
    if name.starts_with("go_") {
        "Go"
    } else if name.starts_with("rust_") {
        "Rust"
    } else {
        "C and C++"
    }
}

struct Check {
    lifted: bool,
    runs: usize,
    unknown: Vec<String>,
    mismatch: Option<String>,
}

fn check(fixture: &Path, image: &Image, function: &Function) -> Check {
    let mut result = Check {
        lifted: false,
        runs: 0,
        unknown: Vec::new(),
        mismatch: None,
    };
    let Ok(lifted) = lift_function(image, function) else {
        return result;
    };
    result.lifted = true;
    let before = lifted.ir.clone();
    let after = optimize(image, lifted).ir;
    let memory = initial_memory(image);
    for trial in 0..TRIALS {
        let registers = registers(image, trial);
        let setup = setup(image, trial, &registers, &memory);
        let old = eval::run(&before, &setup);
        let new = eval::run(&after, &setup);
        if let (Outcome::Unknown(reason), _) | (_, Outcome::Unknown(reason)) = (&old, &new) {
            result
                .unknown
                .push(format!("{reason} ({})", group(fixture)));
            continue;
        }
        result.runs += 1;
        if !same(&old, &new, &after.ret_type) {
            result.mismatch = Some(format!(
                "{} {} {}: trial {trial}: {}",
                fixture.display(),
                crate::addr::format(function.addr),
                function.name.as_deref().unwrap_or("-"),
                describe(&old, &new, &after.ret_type)
            ));
            break;
        }
    }
    result
}

fn collect(dir: &Path, relative: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|error| panic!("{}: {error}", dir.display()))
    {
        let path = entry.unwrap_or_else(|error| panic!("{error}")).path();
        let name = relative.join(path.file_name().expect("a directory entry has a name"));
        if path.is_dir() {
            collect(&path, &name, found);
        } else if path.extension().is_none_or(|extension| extension != "txt") {
            found.push(name);
        }
    }
}

/// Go keeps the current goroutine in r14, and every function first compares
/// the stack pointer with the goroutine's stack guard; a zero guard always passes.
const GO_G: u64 = 0x5000_0000;
const GO_STACK_GUARD: u64 = 0x10;
const R14: u16 = 14;

fn initial_memory(image: &Image) -> Vec<(u64, u64)> {
    if image.go {
        vec![(GO_G + GO_STACK_GUARD, 0)]
    } else {
        Vec::new()
    }
}

/// The calling convention of the image's code.
/// An image as the service opens it, with jump table cases folded back.
fn open(path: &std::path::Path) -> Image {
    let mut image = loader::load(path).unwrap_or_else(|error| panic!("{error}"));
    super::absorb_jump_table_cases(&mut image);
    image
}

fn convention(image: &Image) -> Convention<'static> {
    match image.isa {
        Isa::AArch64 => Convention {
            arguments: &[0, 1, 2, 3, 4, 5, 6, 7],
            clobbered: &[
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
            ],
        },
        // Go's internal ABI: everything but rsp, rbp, r14 (the goroutine) and r15.
        Isa::X86_64 if image.go => Convention {
            arguments: &[0, 3, 1, 7, 6, 8, 9, 10, 11],
            clobbered: &[0, 1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13],
        },
        Isa::X86_64 if matches!(image.format, Format::Pe | Format::Coff) => Convention {
            arguments: &[1, 2, 8, 9],
            clobbered: &[0, 1, 2, 8, 9, 10, 11],
        },
        Isa::X86_64 => Convention {
            arguments: &[7, 6, 2, 1, 8, 9],
            clobbered: &[0, 1, 2, 6, 7, 8, 9, 10, 11],
        },
        Isa::Unsupported => Convention {
            arguments: &[],
            clobbered: &[],
        },
    }
}

fn setup<'a>(
    image: &Image,
    trial: u64,
    registers: &'a [(u16, u64)],
    memory: &'a [(u64, u64)],
) -> Setup<'a> {
    Setup {
        seed: trial,
        convention: convention(image),
        registers,
        memory,
        step_limit: STEP_LIMIT,
    }
}

/// Argument registers for one trial. A third of the trials use small values,
/// so loops over a count finish; the rest use boundary values or hashed ones.
fn registers(image: &Image, trial: u64) -> Vec<(u16, u64)> {
    let goroutine = image.go.then_some((R14, GO_G));
    convention(image)
        .arguments
        .iter()
        .enumerate()
        .map(|(position, register)| {
            let pick = hash(trial, position as u64);
            let value = match trial % 3 {
                0 => pick % 16,
                1 => INTERESTING[pick as usize % INTERESTING.len()],
                _ => pick,
            };
            (*register, value)
        })
        .chain(goroutine)
        .collect()
}

fn return_bits(ret: &CType) -> Option<u32> {
    match ret {
        CType::Void => None,
        CType::Int { bytes, .. } => Some(u32::from(*bytes) * 8),
        CType::Named(name) => Some(named_bits(name)),
        CType::Pointer(_) | CType::Array(_) => Some(64),
    }
}

/// The width of a C type the debug info names, as on LP64 targets.
fn named_bits(name: &str) -> u32 {
    let words: Vec<&str> = name.split_whitespace().collect();
    if words.contains(&"char") || words.contains(&"_Bool") || words.contains(&"bool") {
        8
    } else if words.contains(&"short") {
        16
    } else if words.contains(&"long") {
        64
    } else if words.contains(&"int") || words.contains(&"unsigned") || words.contains(&"signed") {
        32
    } else {
        64
    }
}

/// Prints both versions of one function and their runs:
/// `VELK_FIXTURE=arm64.o VELK_FUNCTION=0x0 cargo test --release explain_function -- --ignored --nocapture`
#[test]
#[ignore]
fn explain_function() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture = std::env::var("VELK_FIXTURE").expect("set VELK_FIXTURE");
    let addr = std::env::var("VELK_FUNCTION").expect("set VELK_FUNCTION");
    let addr = crate::addr::parse(&addr).expect("VELK_FUNCTION is an address");
    let image = open(&root.join("tests/fixtures").join(fixture));
    let function = image
        .functions
        .get(&addr)
        .expect("a function at that address");
    let lifted = lift_function(&image, function).unwrap_or_else(|error| panic!("{error}"));
    let before = lifted.ir.clone();
    let after = optimize(&image, lifted).ir;
    println!(
        "== before\n{}\n== after\n{}",
        before.render(),
        after.render()
    );
    let memory = initial_memory(&image);
    for trial in 0..TRIALS {
        let registers = registers(&image, trial);
        let setup = setup(&image, trial, &registers, &memory);
        let old = eval::run(&before, &setup);
        let new = eval::run(&after, &setup);
        let verdict = if matches!(old, Outcome::Unknown(_)) || matches!(new, Outcome::Unknown(_)) {
            "skipped"
        } else if same(&old, &new, &after.ret_type) {
            "same"
        } else {
            "DIFFERENT"
        };
        println!(
            "trial {trial} {verdict} registers {registers:x?}\n  before {old:x?}\n  after  {new:x?}"
        );
    }
}

fn same(old: &Outcome, new: &Outcome, ret: &CType) -> bool {
    match (old, new) {
        (
            Outcome::Return {
                value: a,
                calls: ca,
                memory: ma,
            },
            Outcome::Return {
                value: b,
                calls: cb,
                memory: mb,
            },
        ) => {
            let values_match = return_bits(ret).is_none_or(|bits| {
                let mask = if bits >= 64 {
                    u64::MAX
                } else {
                    (1 << bits) - 1
                };
                a & mask == b & mask
            });
            values_match && ca == cb && ma == mb
        }
        (
            Outcome::Trap {
                calls: ca,
                memory: ma,
            },
            Outcome::Trap {
                calls: cb,
                memory: mb,
            },
        ) => ca == cb && ma == mb,
        _ => false,
    }
}

fn describe(old: &Outcome, new: &Outcome, ret: &CType) -> String {
    match (old, new) {
        (
            Outcome::Return {
                value: a,
                calls: ca,
                memory: ma,
            },
            Outcome::Return {
                value: b,
                calls: cb,
                memory: mb,
            },
        ) => {
            if ca != cb {
                format!("calls differ ({} before, {} after)", ca.len(), cb.len())
            } else if ma != mb {
                "memory differs".to_owned()
            } else {
                format!("returns 0x{b:x} instead of 0x{a:x} ({ret})")
            }
        }
        (Outcome::Trap { .. }, Outcome::Trap { .. }) => {
            "memory or calls differ before the trap".to_owned()
        }
        _ => "one run returns and the other traps".to_owned(),
    }
}

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
use crate::ir::eval::{self, Outcome};
use crate::ir::trials::{TRIALS, initial_memory, registers, return_bits, setup};
use crate::loader::{self, Function, Image};

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

/// The lifted function with each switch a jump table became turned back
/// into the indirect jump it was, as a switch on the address itself over
/// every block, or `None` without tables.
fn indirect_jumps(
    image: &Image,
    function: &Function,
    lifted: &crate::ir::FunctionIr,
) -> Option<(crate::ir::FunctionIr, Vec<(u64, u64)>)> {
    use crate::ir::Stmt;
    if !lifted
        .blocks
        .iter()
        .any(|block| matches!(block.stmts.last(), Some(Stmt::Switch { .. })))
    {
        return None;
    }
    let size = function.size.unwrap_or(super::UNKNOWN_SIZE);
    let targets: std::collections::HashSet<u64> =
        lifted.blocks.iter().map(|block| block.start).collect();
    let Ok(raw) = crate::lift::lift(image, function.addr, size, &targets) else {
        return None;
    };
    let extent = function.addr..function.addr.saturating_add(size);
    let tables = super::jump_table::recover(&raw, image, extent)
        .into_iter()
        .map(|table| table.table)
        .collect();
    let mut indirect = lifted.clone();
    for block in &mut indirect.blocks {
        if !matches!(block.stmts.last(), Some(Stmt::Switch { .. })) {
            continue;
        }
        let Some(original) = raw.iter().find(|other| other.start == block.start) else {
            return None;
        };
        let Some(Stmt::BrIndirect { target, .. }) = original.stmts.last() else {
            return None;
        };
        let mut stmts = original.stmts.clone();
        *stmts.last_mut().expect("a jump") = Stmt::Switch {
            index: target.clone(),
            cases: targets
                .iter()
                .map(|start| (*start as i64, *start))
                .collect(),
            default: None,
            at: None,
        };
        block.stmts = stmts;
    }
    Some((indirect, tables))
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
    let after = optimize(image, lifted, None).unwrap().ir;
    // Both versions go into SSA form and back unchanged.
    for ir in [&before, &after] {
        let Some(ssa) = crate::ssa::build(ir) else {
            continue;
        };
        let broken = crate::ssa::verify(&ssa).err().or_else(|| {
            (crate::ssa::lower(&ssa).render() != ir.render())
                .then(|| "lowering changes the function".to_owned())
        });
        if let Some(reason) = broken {
            result.mismatch = Some(format!("ssa: {reason}"));
            return result;
        }
    }
    let memory = initial_memory(image);
    // A switch a jump table became goes where the indirect jump went, with
    // the tables' bytes as the image holds them.
    let indirect = indirect_jumps(image, function, &before);
    if let Some((indirect, tables)) = &indirect {
        let mut seeded = memory.clone();
        for (start, length) in tables {
            for word in (0..length.div_ceil(8)).map(|word| start + word * 8) {
                if let Some(bytes) = image.read_vaddr(word, 8) {
                    seeded.push((word, u64::from_le_bytes(bytes.try_into().expect("8 bytes"))));
                }
            }
        }
        for trial in 0..TRIALS {
            let registers = registers(image, trial);
            let setup = setup(image, trial, &registers, &seeded);
            let jumped = eval::run(indirect, &setup);
            let switched = eval::run(&before, &setup);
            if !matches!(jumped, Outcome::Unknown(_))
                && !matches!(switched, Outcome::Unknown(_))
                && !same(&jumped, &switched, &before.ret_type)
            {
                result.mismatch = Some(format!(
                    "{} {} {}: trial {trial}: jump table: {}",
                    fixture.display(),
                    crate::addr::format(function.addr),
                    function.name.as_deref().unwrap_or("-"),
                    describe(&jumped, &switched, &before.ret_type)
                ));
                return result;
            }
        }
    }
    // The structured code, as blocks again, behaves as the optimized IR does.
    let structured = crate::render::structure::lower::lower(
        &after,
        &crate::render::structure::structure_best(&after),
    );
    for trial in 0..TRIALS {
        let registers = registers(image, trial);
        let setup = setup(image, trial, &registers, &memory);
        let old = eval::run(&before, &setup);
        let new = eval::run(&after, &setup);
        let shaped = eval::run(&structured, &setup);
        if !matches!(new, Outcome::Unknown(_))
            && !matches!(shaped, Outcome::Unknown(_))
            && !same(&new, &shaped, &after.ret_type)
        {
            result.mismatch = Some(format!(
                "{} {} {}: trial {trial}: structuring: {}",
                fixture.display(),
                crate::addr::format(function.addr),
                function.name.as_deref().unwrap_or("-"),
                describe(&new, &shaped, &after.ret_type)
            ));
            break;
        }
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
        } else if path.extension().is_none_or(|extension| {
            !matches!(
                extension.to_str(),
                Some("txt" | "pdb" | "velk-cache" | "tmp")
            )
        }) {
            found.push(name);
        }
    }
}

/// An image as the service opens it, with jump table cases folded back.
fn open(path: &std::path::Path) -> Image {
    let mut image = loader::load(path).unwrap_or_else(|error| panic!("{error}"));
    super::absorb_jump_table_cases(&mut image);
    image
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
    let after = optimize(&image, lifted, None).unwrap().ir;
    let structured = crate::render::structure::lower::lower(
        &after,
        &crate::render::structure::structure_best(&after),
    );
    println!(
        "== before\n{}\n== after\n{}\n== structured\n{}",
        before.render(),
        after.render(),
        structured.render()
    );
    let memory = initial_memory(&image);
    for trial in 0..TRIALS {
        let registers = registers(&image, trial);
        let setup = setup(&image, trial, &registers, &memory);
        let old = eval::run(&before, &setup);
        let new = eval::run(&after, &setup);
        println!("  structured {:x?}", eval::run(&structured, &setup));
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

/// The same calls in the same order, passing the same arguments as far as
/// both name them: a call whose callee's arity is unknown passes every
/// argument register, and one the analysis counted passes just those.
fn calls_match(old: &[eval::Call], new: &[eval::Call]) -> bool {
    old.len() == new.len()
        && old.iter().zip(new).all(|(a, b)| {
            a.target == b.target && a.arguments.iter().zip(&b.arguments).all(|(x, y)| x == y)
        })
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
            values_match && calls_match(ca, cb) && ma == mb
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
        ) => calls_match(ca, cb) && ma == mb,
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
            if !calls_match(ca, cb) {
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

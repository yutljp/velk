//! Checks the lifters against processors: random instructions run once on
//! the processor and once as lifted code in the interpreter, from the same
//! registers, and must leave the same registers and satisfy the same
//! conditions.
//!
//! Each random instruction follows a flag-setting compare, so one that reads
//! the flags reads ones the lifter knows.

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
mod aarch64;
mod arm32;
mod i386;
#[cfg(any(
    all(target_arch = "aarch64", target_os = "macos"),
    all(target_arch = "x86_64", unix)
))]
mod x86_64;

use std::collections::{BTreeMap, HashSet};

use super::lift;
use crate::ir::eval::{self, hash};
use crate::ir::{FunctionIr, Stmt};
use crate::loader::{Image, Isa};

/// Register values that reach the edges of the arithmetic often.
fn value(seed: u64, key: u64) -> u64 {
    const EDGES: [u64; 9] = [
        0,
        1,
        u64::MAX,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_ffff,
        0x7fff_ffff_ffff_ffff,
        0x8000_0000_0000_0000,
        0x1_0000_0000,
    ];
    let pick = hash(seed, key);
    match pick % 4 {
        0 => EDGES[(pick >> 8) as usize % EDGES.len()],
        1 => (pick >> 8) % 64,
        2 => (pick >> 8) as u32 as u64,
        _ => hash(seed, key ^ 0x55),
    }
}

/// Bits of a float that reach the edges of the arithmetic often: zeros,
/// infinities, NaNs, subnormals, integers and ordinary values, as a double
/// or as a single in the low half.
fn float_bits(seed: u64, key: u64) -> u64 {
    const DOUBLES: [u64; 10] = [
        0,
        1 << 63,
        0x3ff0_0000_0000_0000,
        0xbff8_0000_0000_0000,
        0x7ff0_0000_0000_0000,
        0xfff0_0000_0000_0000,
        0x7ff8_0000_0000_0000,
        0x0000_0000_0000_0001,
        0x4340_0000_0000_0000,
        0x41e0_0000_0000_0000,
    ];
    const SINGLES: [u32; 9] = [
        0,
        0x8000_0000,
        0x3f80_0000,
        0xbfc0_0000,
        0x7f80_0000,
        0xff80_0000,
        0x7fc0_0000,
        1,
        0x4f00_0000,
    ];
    let pick = hash(seed, key);
    let random = hash(seed, key ^ 0xf1);
    let ordinary = |value: f64| value.to_bits();
    match pick % 6 {
        0 => DOUBLES[(pick >> 8) as usize % DOUBLES.len()],
        1 => (random & !0xffff_ffff) | u64::from(SINGLES[(pick >> 8) as usize % SINGLES.len()]),
        2 => ordinary(((pick >> 8) % 2000) as f64 / 8.0 - 125.0),
        3 => {
            (random & !0xffff_ffff)
                | u64::from((((pick >> 8) % 2000) as f32 / 8.0 - 125.0).to_bits())
        }
        _ => random,
    }
}

/// Whether two values of a vector register's half are the same, counting
/// any two NaNs, as a double or as a single in the low half, alike: their
/// bits come from the processor either way.
fn same_float_bits(a: u64, b: u64) -> bool {
    let nan = |value: u64| f64::from_bits(value).is_nan();
    let single_nan = |value: u64| f32::from_bits(value as u32).is_nan();
    a == b || (nan(a) && nan(b)) || (single_nan(a) && single_nan(b) && a >> 32 == b >> 32)
}

fn lifted(isa: Isa, code: Vec<u8>) -> Option<FunctionIr> {
    let len = code.len() as u64;
    let image = Image::from_code(isa, 0, code);
    let mut ir = FunctionIr::single_block(isa, Vec::new());
    ir.blocks = match lift(&image, 0, len, &HashSet::new()) {
        Ok(blocks) => blocks,
        Err(_) => return None,
    };
    Some(ir)
}

fn setup<'a>(registers: &'a [(u16, u64)]) -> eval::Setup<'a> {
    eval::Setup {
        seed: 0,
        convention: eval::Convention {
            arguments: &[],
            clobbered: &[],
        },
        registers,
        memory: &[],
        step_limit: 100,
    }
}

/// The first instruction the lifter left unsupported, by its name.
fn unsupported(ir: &FunctionIr) -> Option<String> {
    ir.blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .find_map(|stmt| match stmt {
            Stmt::Unsupported { text, .. } => {
                Some(text.split(' ').next().unwrap_or(text).to_owned())
            }
            _ => None,
        })
}

/// Whether the lifted code leaves the flags to an unknown branch.
fn branches_on_unknown_flags(ir: &FunctionIr) -> bool {
    ir.blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .any(|stmt| matches!(stmt, Stmt::BrifFlags { .. }))
}

/// How the lifted code's registers differ from the processor's: None when
/// they agree or the run divides by zero, which C and the IR leave
/// undefined.
fn register_differences(
    ir: &FunctionIr,
    registers: &[(u16, u64)],
    processor: impl Fn(u16) -> u64,
    name: impl Fn(u16) -> String,
    same: impl Fn(u16, u64, u64) -> bool,
) -> Option<String> {
    match eval::registers_after(ir, &setup(registers)) {
        Ok(after) => {
            let differ: Vec<String> = registers
                .iter()
                .filter_map(|(index, start)| {
                    let lifted = after.get(index).copied().unwrap_or(*start);
                    let real = processor(*index);
                    (!same(*index, lifted, real)).then(|| {
                        format!("{}: lifted {lifted:#x}, processor {real:#x}", name(*index))
                    })
                })
                .collect();
            (!differ.is_empty()).then(|| differ.join("\n  "))
        }
        Err("division by zero") => None,
        Err(reason) => Some(reason.to_owned()),
    }
}

/// Whether lifted code that returns one when a condition holds and zero
/// otherwise agrees with the processor's `expected`.
fn condition_differs(ir: &FunctionIr, registers: &[(u16, u64)], expected: bool) -> Option<String> {
    match eval::run(ir, &setup(registers)) {
        eval::Outcome::Return { value, .. } if (value == 1) == expected => None,
        eval::Outcome::Unknown("division by zero") => None,
        outcome => Some(format!("processor {expected}, lifted {outcome:?}")),
    }
}

#[derive(Default)]
struct Findings {
    unsupported: BTreeMap<String, usize>,
    /// Disagreements by kind, each with how often it occurred and one example.
    registers: BTreeMap<String, (usize, String)>,
    conditions: BTreeMap<String, (usize, String)>,
    tried: usize,
    /// Encodings the decoder accepts but the processor does not run.
    undefined: usize,
}

impl Findings {
    fn note(
        kinds: &mut BTreeMap<String, (usize, String)>,
        kind: String,
        example: impl FnOnce() -> String,
    ) {
        kinds.entry(kind).or_insert_with(|| (0, example())).0 += 1;
    }

    /// Fails with every kind of disagreement and one example of each.
    fn assert_agreement(&self) {
        let shown = |kinds: &BTreeMap<String, (usize, String)>| {
            kinds
                .iter()
                .map(|(kind, (count, example))| format!("{kind}: {count} cases, as in\n{example}"))
                .collect::<Vec<_>>()
                .join("\n\n")
        };
        assert!(
            self.registers.is_empty() && self.conditions.is_empty(),
            "of {} cases, {} kinds leave different registers and {} decide a condition differently\n\n{}\n\n{}\n\nunsupported: {:?}",
            self.tried,
            self.registers.len(),
            self.conditions.len(),
            shown(&self.registers),
            shown(&self.conditions),
            self.unsupported,
        );
        eprintln!(
            "{} cases agree, {} not run; unsupported: {:?}",
            self.tried, self.undefined, self.unsupported
        );
    }
}

fn docker_available(platform: &str, image: &str, architecture: &str) -> bool {
    let result = std::process::Command::new("docker")
        .args(["run", "--rm", "--platform", platform, image, "uname", "-m"])
        .output();
    match result {
        Ok(output)
            if output.status.success() && output.stdout.starts_with(architecture.as_bytes()) =>
        {
            true
        }
        other => {
            eprintln!("skipping {platform} hardware check: Docker unavailable: {other:?}");
            false
        }
    }
}

fn docker_run(
    platform: &str,
    image: &str,
    directory: &std::path::Path,
    executable: &str,
) -> std::process::Output {
    std::process::Command::new("docker")
        .args(["run", "--rm", "--platform", platform, "-v"])
        .arg(format!("{}:/check:ro", directory.display()))
        .args([image, &format!("/check/{executable}")])
        .output()
        .expect("Docker was available during the platform check")
}

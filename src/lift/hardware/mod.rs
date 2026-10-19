//! Checks the lifters against processors: random instructions run once on
//! the processor and once as lifted code in the interpreter, from the same
//! registers, and must leave the same registers and satisfy the same
//! conditions.
//!
//! Each case follows a flag-setting compare, so an instruction that reads
//! the flags reads ones the lifter knows.

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
mod aarch64;
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

fn lifted(isa: Isa, code: Vec<u8>) -> Option<FunctionIr> {
    let len = code.len() as u64;
    let image = Image::from_code(isa, 0, code);
    let mut ir = FunctionIr::single_block(isa, Vec::new());
    ir.blocks = lift(&image, 0, len, &HashSet::new()).ok()?;
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
            Stmt::Unsupported { text } => Some(text.split(' ').next().unwrap_or(text).to_owned()),
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
) -> Option<String> {
    match eval::registers_after(ir, &setup(registers)) {
        Ok(after) => {
            let differ: Vec<String> = registers
                .iter()
                .filter_map(|(index, start)| {
                    let lifted = after.get(index).copied().unwrap_or(*start);
                    let real = processor(*index);
                    (lifted != real).then(|| {
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

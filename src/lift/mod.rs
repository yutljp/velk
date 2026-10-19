mod aarch64;
mod x86_64;

use std::collections::HashSet;

use crate::error::LiftError;
use crate::ir::{Block, Stmt};
use crate::loader::{Image, Isa};

const MAX_INSTRUCTIONS: usize = 8192;

struct Decoded<I> {
    pc: u64,
    next: u64,
    instruction: I,
}

trait Machine {
    type Instruction;

    fn branch_target(&self, instruction: &Self::Instruction, pc: u64) -> Option<u64>;
    /// Appends the instruction's statements and reports whether it ends the block.
    fn step(&mut self, instruction: &Self::Instruction, pc: u64) -> bool;
    fn take_statements(&mut self) -> Vec<Stmt>;
    /// The previous instruction ended its block.
    fn block_ended(&mut self);
    /// A branch target splits the block; the fall-through path continues into it.
    fn block_split(&mut self);
}

/// Splits the function at `addr` into basic blocks; `extra_targets` adds
/// block starts the branches alone do not show, such as jump-table cases.
pub fn lift(
    image: &Image,
    addr: u64,
    size: u64,
    extra_targets: &HashSet<u64>,
) -> Result<Vec<Block>, LiftError> {
    let bytes = image.read_vaddr(addr, size).ok_or(LiftError::Unreadable)?;
    match image.isa {
        Isa::AArch64 => {
            let (decoded, stop) = aarch64::decode(bytes, addr);
            build(
                aarch64::Lifter::new(image, addr),
                addr,
                &decoded,
                stop,
                extra_targets,
            )
        }
        Isa::X86_64 => {
            let (decoded, stop) = x86_64::decode(bytes, addr);
            build(
                x86_64::Lifter::new(image, addr),
                addr,
                &decoded,
                stop,
                extra_targets,
            )
        }
        Isa::Unsupported => Err(LiftError::UnsupportedIsa),
    }
}

fn build<M: Machine>(
    mut machine: M,
    start: u64,
    decoded: &[Decoded<M::Instruction>],
    stop: Option<String>,
    extra_targets: &HashSet<u64>,
) -> Result<Vec<Block>, LiftError> {
    if decoded.is_empty() {
        return Err(LiftError::NoInstructions);
    }
    let mut targets: HashSet<u64> = decoded
        .iter()
        .filter_map(|d| machine.branch_target(&d.instruction, d.pc))
        .collect();
    targets.extend(extra_targets);

    let mut blocks = Vec::new();
    let mut block_start = start;
    let mut pending = Vec::new();
    for d in decoded {
        if d.pc != block_start && targets.contains(&d.pc) {
            pending.extend(machine.take_statements());
            if !pending.is_empty() {
                blocks.push(Block {
                    start: block_start,
                    stmts: std::mem::take(&mut pending),
                });
                block_start = d.pc;
                machine.block_split();
            }
        }
        if machine.step(&d.instruction, d.pc) {
            pending.extend(machine.take_statements());
            blocks.push(Block {
                start: block_start,
                stmts: std::mem::take(&mut pending),
            });
            block_start = d.next;
            machine.block_ended();
        }
    }
    pending.extend(machine.take_statements());
    if let Some(text) = stop {
        pending.push(Stmt::Unsupported { text });
    }
    if !pending.is_empty() {
        blocks.push(Block {
            start: block_start,
            stmts: pending,
        });
    }
    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::analysis::analyze;
    use crate::ir::eval::hash;
    use crate::loader::{Function, Image, Isa};

    /// Random bytes may decode to anything; analysis and rendering must still finish.
    #[test]
    fn random_code_never_panics() {
        for isa in [Isa::AArch64, Isa::X86_64] {
            for seed in 0..300u64 {
                let len = 4 + (hash(seed, 0) % 508) as usize;
                let code: Vec<u8> = (0..len as u64)
                    .map(|offset| hash(seed, offset + 1) as u8)
                    .collect();
                let function = Function {
                    addr: 0,
                    size: Some(len as u64),
                    size_estimated: false,
                    name: None,
                    aliases: Vec::new(),
                    sources: Vec::new(),
                };
                let image = Image::from_code(isa, 0, code);
                if let Ok(analysis) = analyze(&image, &function) {
                    crate::render::render(&analysis.ir, &analysis.references, &HashMap::new(), &[]);
                }
            }
        }
    }
}

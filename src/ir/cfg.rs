use std::collections::HashSet;

use crate::ir::visit::statement_registers;
use crate::ir::{Block, Expr, FunctionIr, Stmt};

pub(crate) fn successors(ir: &FunctionIr, index: usize) -> Vec<usize> {
    block_successors(&ir.blocks, index)
}

pub(crate) fn block_successors(blocks: &[Block], index: usize) -> Vec<usize> {
    let find = |address: u64| blocks.iter().position(|block| block.start == address);
    let fallthrough = (index + 1 < blocks.len()).then_some(index + 1);
    let mut out = Vec::new();
    match blocks[index].stmts.last() {
        Some(Stmt::Br {
            target: Some(target),
        }) => out.extend(find(*target)),
        Some(Stmt::Brif { target, .. }) | Some(Stmt::BrifFlags { target, .. }) => {
            out.extend(find(*target));
            out.extend(fallthrough);
        }
        Some(Stmt::Switch { cases, default, .. }) => {
            for (_, target) in cases {
                out.extend(find(*target));
            }
            if let Some(target) = default {
                out.extend(find(*target));
            }
        }
        Some(Stmt::Ret { .. }) | Some(Stmt::BrIndirect { .. }) | Some(Stmt::Trap) => {}
        _ => out.extend(fallthrough),
    }
    out
}

/// The blocks that can reach themselves: the bodies of the loops.
pub(crate) fn cyclic_blocks(ir: &FunctionIr) -> std::collections::HashSet<usize> {
    let index: std::collections::HashMap<u64, usize> = ir
        .blocks
        .iter()
        .enumerate()
        .map(|(position, block)| (block.start, position))
        .collect();
    let successors: Vec<Vec<usize>> = ir
        .blocks
        .iter()
        .map(|block| {
            let mut next = Vec::new();
            match block.stmts.last() {
                Some(Stmt::Brif { target, .. }) | Some(Stmt::BrifFlags { target, .. }) => {
                    if let Some(target) = index.get(target) {
                        next.push(*target);
                    }
                    next.push(
                        index
                            .get(&block.start)
                            .map(|position| position + 1)
                            .unwrap_or_default(),
                    );
                }
                Some(Stmt::Br {
                    target: Some(target),
                }) => {
                    if let Some(target) = index.get(target) {
                        next.push(*target);
                    }
                }
                Some(Stmt::Switch { cases, default, .. }) => {
                    for (_, target) in cases {
                        if let Some(target) = index.get(target) {
                            next.push(*target);
                        }
                    }
                    if let Some(target) = default
                        && let Some(target) = index.get(target)
                    {
                        next.push(*target);
                    }
                }
                Some(Stmt::Ret { .. }) | Some(Stmt::BrIndirect { .. }) | Some(Stmt::Trap) => {}
                _ => {
                    if let Some(position) = index.get(&block.start) {
                        next.push(position + 1);
                    }
                }
            }
            next.retain(|position| *position < ir.blocks.len());
            next
        })
        .collect();
    let mut cyclic = std::collections::HashSet::new();
    for start in 0..ir.blocks.len() {
        let mut seen = std::collections::HashSet::new();
        let mut stack = successors[start].clone();
        while let Some(next) = stack.pop() {
            if next == start {
                cyclic.insert(start);
                break;
            }
            if seen.insert(next) {
                stack.extend(successors[next].iter().copied());
            }
        }
    }
    cyclic
}

/// An unmodeled instruction or an indirect jump may read anything, so a block
/// holding one keeps every definition and reads everything.
pub(crate) fn opaque(block: &Block) -> bool {
    block.stmts.iter().any(|stmt| {
        matches!(
            stmt,
            Stmt::Unsupported { .. } | Stmt::BrIndirect { .. } | Stmt::Br { target: None }
        )
    })
}

/// The registers live on entry to each block. Computed over dense bit sets
/// of the registers the function names, from each block's upward-exposed
/// reads and its writes; a block with an unmodeled effect may read any of
/// them.
pub(crate) fn live_in(ir: &FunctionIr) -> Vec<HashSet<u16>> {
    let count = ir.blocks.len();
    let registers = universe(ir);
    let dense: std::collections::HashMap<u16, usize> = registers
        .iter()
        .enumerate()
        .map(|(position, register)| (*register, position))
        .collect();
    let words = registers.len().div_ceil(64);
    let set = |bits: &mut [u64], register: u16| {
        let at = dense[&register];
        bits[at / 64] |= 1 << (at % 64);
    };
    let clear = |bits: &mut [u64], register: u16| {
        let at = dense[&register];
        bits[at / 64] &= !(1 << (at % 64));
    };
    // What each block reads before writing it, and what it writes.
    let mut uses = vec![vec![0u64; words]; count];
    let mut defs = vec![vec![0u64; words]; count];
    for (index, block) in ir.blocks.iter().enumerate() {
        for stmt in block.stmts.iter().rev() {
            let (writes, reads) = statement_registers(stmt);
            for written in writes {
                clear(&mut uses[index], written);
                set(&mut defs[index], written);
            }
            for read in reads {
                set(&mut uses[index], read);
            }
        }
        if opaque(block) {
            uses[index].iter_mut().for_each(|word| *word = u64::MAX);
        }
    }
    let successors: Vec<Vec<usize>> = (0..count).map(|index| successors(ir, index)).collect();
    let mut live = vec![vec![0u64; words]; count];
    // The sets only grow, so this reaches a fixpoint.
    loop {
        let mut changed = false;
        for index in (0..count).rev() {
            let mut next = uses[index].clone();
            for successor in &successors[index] {
                for word in 0..words {
                    next[word] |= live[*successor][word] & !defs[index][word];
                }
            }
            if next != live[index] {
                live[index] = next;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    live.iter()
        .map(|bits| {
            registers
                .iter()
                .enumerate()
                .filter(|(position, _)| bits[position / 64] >> (position % 64) & 1 == 1)
                .map(|(_, register)| *register)
                .collect()
        })
        .collect()
}

/// The registers live on leaving block `index`, given `live_in`.
pub(crate) fn live_out(ir: &FunctionIr, live_in: &[HashSet<u16>], index: usize) -> HashSet<u16> {
    if opaque(&ir.blocks[index]) {
        return universe(ir).into_iter().collect();
    }
    live_out_of(live_in, &successors(ir, index))
}

/// Every register the function's statements name, and the machine registers
/// of either architecture, which an unmodeled effect may read.
fn universe(ir: &FunctionIr) -> Vec<u16> {
    let mut registers: std::collections::BTreeSet<u16> = crate::arch::machine_registers()
        .chain(crate::ir::FLAG_OPERANDS)
        .chain([crate::ir::EXCHANGE])
        .collect();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        let (writes, reads) = statement_registers(stmt);
        registers.extend(writes);
        registers.extend(reads);
    }
    registers.into_iter().collect()
}

fn live_out_of(live_in: &[HashSet<u16>], successors: &[usize]) -> HashSet<u16> {
    successors
        .iter()
        .flat_map(|next| live_in[*next].iter().copied())
        .collect()
}

/// The value of the last return that is not a tail call, which returns
/// whatever its callee does.
pub(crate) fn own_return(blocks: &[Block]) -> Option<&Expr> {
    blocks
        .iter()
        .rev()
        .find_map(|block| match block.stmts.as_slice() {
            [.., Stmt::Call { .. }, Stmt::Ret { .. }] => None,
            [.., Stmt::Ret { value }] => Some(value),
            _ => None,
        })
}

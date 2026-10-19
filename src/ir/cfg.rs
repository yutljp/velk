use std::collections::HashSet;

use crate::ir::visit::statement_registers;
use crate::ir::{Block, Expr, FunctionIr, Stmt};

pub(crate) fn successors(ir: &FunctionIr, index: usize) -> Vec<usize> {
    let find = |address: u64| ir.blocks.iter().position(|block| block.start == address);
    let fallthrough = (index + 1 < ir.blocks.len()).then_some(index + 1);
    let mut out = Vec::new();
    match ir.blocks[index].stmts.last() {
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

/// The registers live on entry to each block.
pub(crate) fn live_in(ir: &FunctionIr) -> Vec<HashSet<u16>> {
    let count = ir.blocks.len();
    let successors: Vec<Vec<usize>> = (0..count).map(|index| successors(ir, index)).collect();
    let mut live_in: Vec<HashSet<u16>> = vec![HashSet::new(); count];
    // The sets only grow, so this reaches a fixpoint.
    loop {
        let mut changed = false;
        for index in (0..count).rev() {
            let mut live = live_out_of(&live_in, &successors[index]);
            for stmt in ir.blocks[index].stmts.iter().rev() {
                let (writes, reads) = statement_registers(stmt);
                for written in &writes {
                    live.remove(written);
                }
                live.extend(reads);
            }
            if opaque(&ir.blocks[index]) {
                live.extend(universe());
            }
            if live != live_in[index] {
                live_in[index] = live;
                changed = true;
            }
        }
        if !changed {
            return live_in;
        }
    }
}

/// The registers live on leaving block `index`, given `live_in`.
pub(crate) fn live_out(ir: &FunctionIr, live_in: &[HashSet<u16>], index: usize) -> HashSet<u16> {
    if opaque(&ir.blocks[index]) {
        return universe().collect();
    }
    live_out_of(live_in, &successors(ir, index))
}

/// Every register any statement could name.
fn universe() -> impl Iterator<Item = u16> {
    // The general registers of either architecture, then the xmm halves.
    (0..crate::arch::x86::XMM0 + 32)
        .chain(crate::ir::TEMP_BASE..crate::ir::TEMP_BASE + 64)
        .chain(crate::ir::FLAG_OPERANDS)
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

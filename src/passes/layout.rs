use crate::ir::{FunctionIr, Stmt};

/// Reorders blocks depth-first, preferring the fall-through edge, and repairs
/// the fall-through edges the new order broke.
///
/// The structurer treats fall-through as "the next block", so a loop latch
/// placed before its header would leave a label it cannot fold.
pub fn normalize_layout(ir: &mut FunctionIr) {
    if ir.blocks.len() < 2 {
        return;
    }
    let position: std::collections::HashMap<u64, usize> = ir
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start, index))
        .collect();
    let fallthrough: std::collections::HashMap<u64, Option<u64>> = ir
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start, ir.blocks.get(index + 1).map(|next| next.start)))
        .collect();

    let mut order: Vec<usize> = Vec::new();
    let mut seen = vec![false; ir.blocks.len()];
    let mut stack = vec![0usize];
    while let Some(index) = stack.pop() {
        if seen[index] {
            continue;
        }
        seen[index] = true;
        order.push(index);
        let mut next: Vec<usize> = Vec::new();
        let following = (index + 1 < ir.blocks.len()).then_some(index + 1);
        match ir.blocks[index].stmts.last() {
            Some(Stmt::Br {
                target: Some(target),
            }) => next.extend(position.get(target).copied()),
            Some(Stmt::Brif { target, .. }) | Some(Stmt::BrifFlags { target, .. }) => {
                next.extend(following);
                next.extend(position.get(target).copied());
            }
            Some(Stmt::Switch { cases, default, .. }) => {
                next.extend(following);
                for (_, target) in cases {
                    next.extend(position.get(target).copied());
                }
                next.extend(default.and_then(|target| position.get(&target).copied()));
            }
            Some(Stmt::Ret { .. }) | Some(Stmt::BrIndirect { .. }) | Some(Stmt::Trap) => {}
            _ => next.extend(following),
        }
        next.dedup();
        for successor in next.into_iter().rev() {
            if !seen[successor] {
                stack.push(successor);
            }
        }
    }
    order.extend(
        seen.iter()
            .enumerate()
            .filter(|(_, seen)| !**seen)
            .map(|(index, _)| index),
    );
    let mut blocks: Vec<crate::ir::Block> = Vec::with_capacity(ir.blocks.len());
    for index in order {
        blocks.push(ir.blocks[index].clone());
    }
    ir.blocks = blocks;

    for index in 0..ir.blocks.len() {
        let next = ir.blocks.get(index + 1).map(|block| block.start);
        let last = ir.blocks[index].stmts.last().cloned();
        let last_index = ir.blocks[index].stmts.len();
        match last {
            Some(Stmt::Br {
                target: Some(target),
            }) if Some(target) == next => {
                ir.blocks[index].stmts.remove(last_index - 1);
            }
            Some(Stmt::Br { .. }) => {}
            Some(Stmt::Brif { .. }) | Some(Stmt::BrifFlags { .. }) | Some(Stmt::Switch { .. }) => {
                let original = fallthrough.get(&ir.blocks[index].start).copied().flatten();
                if let (Some(original), Some(next)) = (original, next)
                    && original != next
                {
                    ir.blocks[index].stmts.push(Stmt::Br {
                        target: Some(original),
                    });
                }
            }
            Some(Stmt::Ret { .. }) | Some(Stmt::BrIndirect { .. }) | Some(Stmt::Trap) => {}
            _ => {
                if let Some(next) = next {
                    ir.blocks[index].stmts.push(Stmt::Br { target: Some(next) });
                }
            }
        }
    }
}

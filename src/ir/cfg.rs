use crate::ir::{FunctionIr, Stmt};

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

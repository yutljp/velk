use crate::ir::{FunctionIr, Stmt};

/// The first address given to a copied block: no code lies this high, so
/// the copies' starts never meet a real one.
const COPIES: u64 = 0xc000_0000_0000_0000;

/// The function with each short block that several branches enter, and
/// that only assigns before going on, copied into each of them. A branch
/// that skipped such a block to reach the code after it, as `switch` arms
/// that leave past the code the default runs, then meets the others there,
/// where structuring needs no `goto`.
pub(super) fn tail_duplicated(ir: &FunctionIr) -> Option<FunctionIr> {
    let mut ir = ir.clone();
    let mut next_copy = COPIES;
    let mut changed = false;
    let mut candidate = 1;
    while candidate < ir.blocks.len() {
        let block = &ir.blocks[candidate];
        let short = block.stmts.len() <= 3
            && block.start < COPIES
            && block.stmts.iter().enumerate().all(|(position, stmt)| {
                matches!(stmt, Stmt::Assign { .. })
                    || (position + 1 == block.stmts.len()
                        && matches!(stmt, Stmt::Br { target: Some(_) }))
            });
        // Where the block goes on to.
        let follow = match block.stmts.last() {
            Some(Stmt::Br {
                target: Some(target),
            }) => Some(*target),
            _ => ir.blocks.get(candidate + 1).map(|next| next.start),
        };
        let entered: Vec<usize> = (0..ir.blocks.len())
            .filter(|from| {
                crate::render::structure::compare_chain::successors(&ir, *from).contains(&candidate)
            })
            .collect();
        let (true, Some(follow)) = (short, follow) else {
            candidate += 1;
            continue;
        };
        if entered.len() < 2 || entered.contains(&candidate) {
            candidate += 1;
            continue;
        }
        let start = ir.blocks[candidate].start;
        let body: Vec<Stmt> = ir.blocks[candidate]
            .stmts
            .iter()
            .filter(|stmt| matches!(stmt, Stmt::Assign { .. }))
            .cloned()
            .chain(std::iter::once(Stmt::Br {
                target: Some(follow),
            }))
            .collect();
        // Each branch to the block goes to a copy of its own; one falling
        // into it falls into a copy placed after it.
        let mut copies = Vec::new();
        for from in &entered {
            let copy = next_copy;
            next_copy += 1;
            let falls = *from + 1 == candidate
                && !matches!(
                    ir.blocks[*from].stmts.last(),
                    Some(Stmt::Br { .. } | Stmt::Switch { .. })
                );
            if let Some(last) = ir.blocks[*from].stmts.last_mut() {
                retarget(last, start, copy);
            }
            copies.push((*from, copy, falls));
        }
        // Copies a block falls into go right after it; the others at the end.
        let mut fallthrough = None;
        for (from, copy, falls) in copies {
            let block = crate::ir::Block {
                start: copy,
                stmts: body.clone(),
            };
            if falls {
                fallthrough = Some((from, block));
            } else {
                ir.blocks.push(block);
            }
        }
        ir.blocks.remove(candidate);
        if let Some((from, block)) = fallthrough {
            ir.blocks.insert(from + 1, block);
        }
        changed = true;
    }
    changed.then_some(ir)
}

/// Sends a branch to `from` to `to` instead.
fn retarget(stmt: &mut Stmt, from: u64, to: u64) {
    let replace = |target: &mut u64| {
        if *target == from {
            *target = to;
        }
    };
    match stmt {
        Stmt::Br {
            target: Some(target),
        }
        | Stmt::Brif { target, .. } => replace(target),
        Stmt::Switch { cases, default, .. } => {
            for (_, target) in cases {
                replace(target);
            }
            if let Some(target) = default {
                replace(target);
            }
        }
        _ => {}
    }
}

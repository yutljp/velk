use crate::ir::{FunctionIr, Stmt};

/// The first address given to a copied block: no code lies this high, so
/// the copies' starts never meet a real one.
const COPY_ADDRESS_BASE: u64 = 0xc000_0000_0000_0000;

/// The function with each short block that several branches enter, and
/// that only assigns, stores or calls before going on, copied into each of
/// them. A branch
/// that skipped such a block to reach the code after it, as `switch` arms
/// that leave past the code the default runs, then meets the others there,
/// where structuring needs no `goto`.
pub(super) fn tail_duplicated(ir: &FunctionIr) -> Option<FunctionIr> {
    let mut ir = ir.clone();
    let mut next_copy = COPY_ADDRESS_BASE;
    let mut changed = false;
    let mut candidate = 1;
    let mut incoming = None;
    while candidate < ir.blocks.len() {
        let block = &ir.blocks[candidate];
        let short = block.stmts.len() <= 3
            && block.start < COPY_ADDRESS_BASE
            // Keep shared constant setup together instead of repeating it in each arm.
            && !(block.stmts.iter().filter(|stmt| matches!(stmt, Stmt::Assign { .. })).count() >= 2
                && block.stmts.iter().all(|stmt| {
                    matches!(stmt, Stmt::Assign { value: crate::ir::Expr::Const(_), .. }
                        | Stmt::Br { target: Some(_), .. })
                }))
            && block.stmts.iter().enumerate().all(|(position, stmt)| {
                is_straight_line_statement(stmt)
                    || (position + 1 == block.stmts.len()
                        && matches!(stmt, Stmt::Br { target: Some(_), .. }))
            });
        // Where the block goes on to.
        let follow = match block.stmts.last() {
            Some(Stmt::Br {
                target: Some(target),
                ..
            }) => Some(*target),
            _ => ir.blocks.get(candidate + 1).map(|next| next.start),
        };
        let (true, Some(follow)) = (short, follow) else {
            candidate += 1;
            continue;
        };
        let predecessors = incoming.get_or_insert_with(|| {
            let mut incoming = vec![Vec::new(); ir.blocks.len()];
            for from in 0..ir.blocks.len() {
                let mut next = crate::render::structure::compare_chain::successors(&ir, from);
                next.sort_unstable();
                next.dedup();
                for to in next {
                    incoming[to].push(from);
                }
            }
            incoming
        });
        let entered = &predecessors[candidate];
        if entered.len() < 2 || entered.contains(&candidate) {
            candidate += 1;
            continue;
        }
        let start = ir.blocks[candidate].start;
        let body: Vec<Stmt> = ir.blocks[candidate]
            .stmts
            .iter()
            .filter(|stmt| is_straight_line_statement(stmt))
            .cloned()
            .chain(std::iter::once(Stmt::Br {
                target: Some(follow),
                at: ir.blocks[candidate]
                    .stmts
                    .last()
                    .filter(|stmt| matches!(stmt, Stmt::Br { .. }))
                    .and_then(Stmt::origin),
            }))
            .collect();
        // Each branch to the block goes to a copy of its own; one falling
        // into it falls into a copy placed after it.
        let mut copies = Vec::new();
        for from in entered {
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
        // Removing and inserting blocks changes both indices and edges.
        incoming = None;
    }
    changed.then_some(ir)
}

/// A statement that goes on to the next.
fn is_straight_line_statement(stmt: &Stmt) -> bool {
    matches!(
        stmt,
        Stmt::Assign { .. } | Stmt::Store { .. } | Stmt::Call { .. }
    )
}

/// The function with the same test, ending several blocks and choosing
/// between the same two places, made once in a block of its own that they
/// all jump to: the check a compiler copied into each branch before the
/// code they share.
pub(super) fn merged_checks(ir: &FunctionIr) -> Option<FunctionIr> {
    use crate::ir::{Cond, Expr};
    let original = ir;
    let starts: std::collections::HashMap<u64, usize> = ir
        .blocks
        .iter()
        .enumerate()
        .map(|(position, block)| (block.start, position))
        .collect();
    let settle = |target| super::short_circuit::follow_branches(ir, &starts, target);
    // Each conditional exit as (cond, lhs, rhs, taken, otherwise), the
    // condition put the way that compares smaller first.
    type Exit = (Cond, Expr, Expr, u64, u64);
    let mut exits: Vec<(usize, Exit)> = Vec::new();
    for (position, block) in ir.blocks.iter().enumerate() {
        let Some(Stmt::Brif {
            cond,
            lhs,
            rhs,
            target,
            ..
        }) = block.stmts.last()
        else {
            continue;
        };
        let Some(next) = ir.blocks.get(position + 1) else {
            continue;
        };
        let (taken, otherwise) = (settle(*target), settle(next.start));
        let exit = if taken <= otherwise {
            (*cond, lhs.clone(), rhs.clone(), taken, otherwise)
        } else {
            (cond.invert(), lhs.clone(), rhs.clone(), otherwise, taken)
        };
        exits.push((position, exit));
    }
    let mut ir = ir.clone();
    let mut next_copy = COPY_ADDRESS_BASE + 0x1000_0000;
    let mut changed = false;
    let mut done = vec![false; exits.len()];
    for first in 0..exits.len() {
        if done[first] {
            continue;
        }
        let same: Vec<usize> = (first..exits.len())
            .filter(|other| !done[*other] && exits[*other].1 == exits[first].1)
            .collect();
        if same.len() < 2 {
            continue;
        }
        let (cond, lhs, rhs, taken, otherwise) = exits[first].1.clone();
        let check = next_copy;
        next_copy += 2;
        for member in &same {
            done[*member] = true;
            let block = &mut ir.blocks[exits[*member].0];
            block.stmts.pop();
            block.stmts.push(Stmt::Br {
                target: Some(check),
                at: None,
            });
        }
        // The test falls into a jump to the other place.
        ir.blocks.push(crate::ir::Block {
            start: check,
            stmts: vec![Stmt::Brif {
                cond,
                lhs,
                rhs,
                target: taken,
                at: None,
            }],
        });
        ir.blocks.push(crate::ir::Block {
            start: check + 1,
            stmts: vec![Stmt::Br {
                target: Some(otherwise),
                at: None,
            }],
        });
        changed = true;
    }
    if !changed {
        return None;
    }
    // A block only the old tests fell into is left behind.
    let before = reached(original);
    let after = reached(&ir);
    let mut position = 0;
    ir.blocks.retain(|_| {
        position += 1;
        after[position - 1] || !before.get(position - 1).copied().unwrap_or(false)
    });
    Some(ir)
}

/// Which blocks a path from the entry reaches.
fn reached(ir: &FunctionIr) -> Vec<bool> {
    let mut seen = vec![false; ir.blocks.len()];
    let mut pending = vec![0];
    while let Some(at) = pending.pop() {
        if at >= seen.len() || std::mem::replace(&mut seen[at], true) {
            continue;
        }
        pending.extend(crate::render::structure::compare_chain::successors(ir, at));
    }
    seen
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
            ..
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

/// The function with each branch to a block that only jumps on sent to
/// where the jumps end, and such blocks nothing reaches any more dropped.
pub(super) fn threaded(ir: &FunctionIr) -> Option<FunctionIr> {
    let only_jump = |stmts: &[Stmt]| match stmts {
        [
            Stmt::Br {
                target: Some(target),
                ..
            },
        ] => Some(*target),
        _ => None,
    };
    let jumps: std::collections::HashMap<u64, u64> = ir
        .blocks
        .iter()
        .skip(1)
        .filter_map(|block| {
            let Some(jump) = only_jump(&block.stmts) else {
                return None;
            };
            Some((block.start, jump))
        })
        .collect();
    if jumps.is_empty() {
        return None;
    }
    let end = |mut target: u64| {
        for _ in 0..8 {
            match jumps.get(&target) {
                Some(next) if *next != target => target = *next,
                _ => break,
            }
        }
        target
    };
    let mut ir = ir.clone();
    let mut changed = false;
    for block in &mut ir.blocks {
        let Some(last) = block.stmts.last_mut() else {
            continue;
        };
        let mut redirect = |target: &mut u64| {
            let threaded = end(*target);
            if threaded != *target {
                *target = threaded;
                changed = true;
            }
        };
        match last {
            Stmt::Br {
                target: Some(target),
                ..
            }
            | Stmt::Brif { target, .. } => redirect(target),
            Stmt::Switch { cases, default, .. } => {
                for (_, target) in cases {
                    redirect(target);
                }
                if let Some(target) = default {
                    redirect(target);
                }
            }
            _ => {}
        }
    }
    if !changed {
        return None;
    }
    // A jump-only block stays while anything still falls or branches to it.
    let reached: std::collections::HashSet<usize> = (0..ir.blocks.len())
        .flat_map(|from| crate::render::structure::compare_chain::successors(&ir, from))
        .collect();
    let mut position = 0;
    ir.blocks.retain(|block| {
        position += 1;
        position == 1 || reached.contains(&(position - 1)) || only_jump(&block.stmts).is_none()
    });
    Some(ir)
}

/// The function with each branch that went past a test whose outcome its
/// own test decided sent through that test again. A compiler that knows,
/// say, that `i == n` where a loop ends sends the loop's exit straight to
/// where a later `if (i != n)` would go; the later test is then a join of
/// its own, which the structure can only reach with a goto. Through the
/// test again, the exit meets the other paths before it.
pub(super) fn unthreaded(ir: &FunctionIr) -> Option<FunctionIr> {
    use crate::ir::{Block, Cond, Expr};
    // The blocks that only test, as (position, cond, lhs, rhs, taken, otherwise).
    type Test<'a> = (usize, Cond, &'a Expr, &'a Expr, u64, u64);
    let tests: Vec<Test> = ir
        .blocks
        .iter()
        .enumerate()
        .filter_map(|(position, block)| match block.stmts.as_slice() {
            [
                Stmt::Brif {
                    cond,
                    lhs,
                    rhs,
                    target,
                    ..
                },
            ] => {
                let Some(next) = ir.blocks.get(position + 1) else {
                    return None;
                };
                let next = next.start;
                Some((position, *cond, lhs, rhs, *target, next))
            }
            _ => None,
        })
        .collect();
    if tests.is_empty() {
        return None;
    }
    let starts: std::collections::HashMap<u64, usize> = ir
        .blocks
        .iter()
        .enumerate()
        .map(|(position, block)| (block.start, position))
        .collect();
    let settle = |target| super::short_circuit::follow_branches(ir, &starts, target);
    let original = ir;
    let mut ir = ir.clone();
    let mut next_copy = COPY_ADDRESS_BASE + 0x2000_0000;
    // Jumps to add after a block that falls into its branch's new place.
    let mut jumps: Vec<(usize, u64)> = Vec::new();
    let mut changed = false;
    for position in 0..ir.blocks.len() {
        // A test sent on to another would go back and forth with it.
        if tests.iter().any(|(test, ..)| *test == position) {
            continue;
        }
        let Some(Stmt::Brif {
            cond,
            lhs,
            rhs,
            target,
            ..
        }) = ir.blocks[position].stmts.last()
        else {
            continue;
        };
        let Some(fallthrough) = ir.blocks.get(position + 1).map(|block| block.start) else {
            continue;
        };
        let (cond, lhs, rhs, target) = (*cond, lhs.clone(), rhs.clone(), *target);
        for (edge, holds) in [(target, true), (fallthrough, false)] {
            let again = tests
                .iter()
                .find(|(test, other, left, right, taken, otherwise)| {
                    *test != position
                        && settle(original.blocks[*test].start) != settle(edge)
                        && implied((cond, &lhs, &rhs, holds), (*other, left, right)).is_some_and(
                            |outcome| {
                                settle(edge) == settle(if outcome { *taken } else { *otherwise })
                            },
                        )
                });
            let Some((test, ..)) = again else {
                continue;
            };
            let start = ir.blocks[*test].start;
            if holds {
                if let Some(Stmt::Brif { target, .. }) = ir.blocks[position].stmts.last_mut() {
                    *target = start;
                }
            } else {
                jumps.push((position, start));
            }
            changed = true;
        }
    }
    if !changed {
        return None;
    }
    // Later positions first, so the earlier ones stay where they were.
    for (position, start) in jumps.into_iter().rev() {
        ir.blocks.insert(
            position + 1,
            Block {
                start: next_copy,
                stmts: vec![Stmt::Br {
                    target: Some(start),
                    at: None,
                }],
            },
        );
        next_copy += 1;
    }
    // A block only the old branches went to is left behind.
    let before: std::collections::HashMap<u64, bool> = original
        .blocks
        .iter()
        .zip(reached(original))
        .map(|(block, reached)| (block.start, reached))
        .collect();
    let after = reached(&ir);
    let mut position = 0;
    ir.blocks.retain(|block| {
        position += 1;
        after[position - 1] || !before.get(&block.start).copied().unwrap_or(false)
    });
    Some(ir)
}

/// What a test `(cond, lhs, rhs)` comes to where `fact` is known to hold
/// or not, when the two compare the same values.
fn implied(
    fact: (crate::ir::Cond, &crate::ir::Expr, &crate::ir::Expr, bool),
    test: (crate::ir::Cond, &crate::ir::Expr, &crate::ir::Expr),
) -> Option<bool> {
    use crate::ir::Cond;
    let (known, left, right, holds) = fact;
    let (cond, lhs, rhs) = test;
    let flags = |cond: Cond| matches!(cond, Cond::Mi | Cond::Pl | Cond::Vs | Cond::Vc);
    if flags(known) || flags(cond) {
        return None;
    }
    let cond = if (lhs, rhs) == (left, right) {
        cond
    } else if (lhs, rhs) == (right, left) {
        // `a < b` is `b > a`.
        match cond {
            Cond::Lt => Cond::Gt,
            Cond::Gt => Cond::Lt,
            Cond::Le => Cond::Ge,
            Cond::Ge => Cond::Le,
            Cond::Cc => Cond::Hi,
            Cond::Hi => Cond::Cc,
            Cond::Cs => Cond::Ls,
            Cond::Ls => Cond::Cs,
            other => other,
        }
    } else {
        return None;
    };
    if cond == known {
        Some(holds)
    } else if cond == known.invert() {
        Some(!holds)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::COPY_ADDRESS_BASE;
    use crate::ir::{Block, Cond, Expr, FunctionIr, Stmt};
    use crate::loader::Isa;

    #[test]
    fn tail_copies_keep_source_order_and_refresh_edges_after_removal() {
        let branch = |target| Stmt::Br {
            target: Some(target),
            at: None,
        };
        let store = |value| Stmt::Store {
            addr: Expr::reg(7, 64),
            value: Expr::Const(value),
            width: 8,
            at: None,
        };
        let switch = |first, second| Stmt::Switch {
            index: Expr::reg(0, 64),
            cases: vec![(0, first), (1, first), (2, second)],
            default: Some(8),
            at: None,
        };
        let conditional = |target| Stmt::Brif {
            cond: Cond::Eq,
            lhs: Expr::reg(0, 64),
            rhs: Expr::Const(0),
            target,
            at: None,
        };
        let ret = Stmt::Ret {
            value: Expr::Const(0),
            at: None,
        };
        let mut ir = FunctionIr::single_block(Isa::X86_64, Vec::new());
        ir.blocks = vec![
            Block {
                start: 0,
                stmts: vec![switch(16, 32)],
            },
            Block {
                start: 8,
                stmts: vec![branch(16)],
            },
            Block {
                start: 16,
                stmts: vec![store(1), branch(24)],
            },
            Block {
                start: 24,
                stmts: vec![conditional(32)],
            },
            Block {
                start: 32,
                stmts: vec![store(2), branch(40)],
            },
            Block {
                start: 40,
                stmts: vec![ret.clone()],
            },
        ];
        let copied = super::tail_duplicated(&ir).expect("both stores have two incoming blocks");
        let base = COPY_ADDRESS_BASE;
        let expected = vec![
            Block {
                start: 0,
                stmts: vec![switch(base, base + 2)],
            },
            Block {
                start: 8,
                stmts: vec![branch(base + 1)],
            },
            Block {
                start: 24,
                stmts: vec![conditional(base + 3)],
            },
            Block {
                start: base + 3,
                stmts: vec![store(2), branch(40)],
            },
            Block {
                start: 40,
                stmts: vec![ret],
            },
            Block {
                start: base,
                stmts: vec![store(1), branch(24)],
            },
            Block {
                start: base + 1,
                stmts: vec![store(1), branch(24)],
            },
            Block {
                start: base + 2,
                stmts: vec![store(2), branch(40)],
            },
        ];
        assert_eq!(format!("{:?}", copied.blocks), format!("{expected:?}"));
    }
}

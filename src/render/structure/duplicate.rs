use crate::ir::{FunctionIr, Stmt};

/// The first address given to a copied block: no code lies this high, so
/// the copies' starts never meet a real one.
const COPIES: u64 = 0xc000_0000_0000_0000;

/// The function with each short block that several branches enter, and
/// that only assigns, stores or calls before going on, copied into each of
/// them. A branch
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
                straight(stmt)
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
            .filter(|stmt| straight(stmt))
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

/// A statement that goes on to the next.
fn straight(stmt: &Stmt) -> bool {
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
    // Where control goes from a block start, past blocks that only jump.
    let settle = |mut target: u64| {
        for _ in 0..8 {
            match starts
                .get(&target)
                .map(|position| ir.blocks[*position].stmts.as_slice())
            {
                Some([Stmt::Br { target: Some(next) }]) if *next != target => target = *next,
                _ => break,
            }
        }
        target
    };
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
    let mut next_copy = COPIES + 0x1000_0000;
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
            }],
        });
        ir.blocks.push(crate::ir::Block {
            start: check + 1,
            stmts: vec![Stmt::Br {
                target: Some(otherwise),
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
            },
        ] => Some(*target),
        _ => None,
    };
    let jumps: std::collections::HashMap<u64, u64> = ir
        .blocks
        .iter()
        .skip(1)
        .filter_map(|block| Some((block.start, only_jump(&block.stmts)?)))
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
                },
            ] => {
                let next = ir.blocks.get(position + 1)?.start;
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
    // Where control goes from a block start, past blocks that only jump.
    let settle = |mut target: u64| {
        for _ in 0..8 {
            match starts
                .get(&target)
                .map(|position| ir.blocks[*position].stmts.as_slice())
            {
                Some([Stmt::Br { target: Some(next) }]) if *next != target => target = *next,
                _ => break,
            }
        }
        target
    };
    let original = ir;
    let mut ir = ir.clone();
    let mut next_copy = COPIES + 0x2000_0000;
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

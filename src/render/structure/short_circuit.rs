//! Tests that only complete another one, joined with it as `&&` or `||`.
//! A compiler lowers `if (a && b)` to two branches that share where the
//! test fails, so the block after the whole condition has two entries and
//! structuring it as nested tests needs a goto. Joined, the condition is
//! one test again, a choice of truth values that reads as `&&` and `||`
//! and, like C's operators, evaluates its second test only when needed.

use std::collections::HashMap;

use crate::ir::{Cond, Expr, FunctionIr, Stmt};

/// The most tests one joined condition holds.
const MAX_TESTS: usize = 4;

/// The function with each block that only tests, entered from one test
/// alone and going where that test goes on one side, joined into it.
pub(super) fn short_circuited(ir: &FunctionIr) -> Option<FunctionIr> {
    if ir
        .blocks
        .iter()
        .any(|block| matches!(block.stmts.last(), Some(Stmt::BrIndirect { .. })))
    {
        return None;
    }
    let mut ir = ir.clone();
    let mut changed = false;
    let mut block = 0;
    let mut entries = entry_counts(&ir);
    let mut index = positions(&ir);
    while block < ir.blocks.len() {
        match join(&ir, &entries, &index, block) {
            Some((stmt, removed)) => {
                *ir.blocks[block].stmts.last_mut().expect("a test") = stmt;
                ir.blocks.remove(removed);
                entries = entry_counts(&ir);
                index = positions(&ir);
                changed = true;
                // The joined test may complete the one before it in turn.
                block = block.saturating_sub(1);
            }
            None => block += 1,
        }
    }
    changed.then_some(ir)
}

fn positions(ir: &FunctionIr) -> HashMap<u64, usize> {
    ir.blocks
        .iter()
        .enumerate()
        .map(|(position, block)| (block.start, position))
        .collect()
}

/// How many edges enter each block, by its start.
fn entry_counts(ir: &FunctionIr) -> HashMap<u64, usize> {
    let mut counts: HashMap<u64, usize> = HashMap::new();
    for (position, block) in ir.blocks.iter().enumerate() {
        let next = ir.blocks.get(position + 1).map(|next| next.start);
        let mut enter = |target: u64| *counts.entry(target).or_default() += 1;
        match block.stmts.last() {
            Some(Stmt::Br {
                target: Some(target),
            }) => enter(*target),
            Some(Stmt::Brif { target, .. } | Stmt::BrifFlags { target, .. }) => {
                enter(*target);
                next.into_iter().for_each(&mut enter);
            }
            Some(Stmt::Switch { cases, default, .. }) => {
                cases.iter().for_each(|(_, target)| enter(*target));
                default.iter().for_each(|target| enter(*target));
            }
            Some(
                Stmt::Ret { .. } | Stmt::Trap | Stmt::BrIndirect { .. } | Stmt::Br { target: None },
            ) => {}
            _ => next.into_iter().for_each(&mut enter),
        }
    }
    counts
}

/// A test the condition can join: a comparison of values, not of flags.
fn test(stmt: Option<&Stmt>) -> Option<(Cond, &Expr, &Expr, u64)> {
    match stmt {
        Some(Stmt::Brif {
            cond,
            lhs,
            rhs,
            target,
        }) if !matches!(cond, Cond::Mi | Cond::Pl | Cond::Vs | Cond::Vc) => {
            Some((*cond, lhs, rhs, *target))
        }
        _ => None,
    }
}

/// The test ending `block` joined with the block after it, or the one it
/// branches to, when that one only tests and nothing else enters it: the
/// new test and the position of the block it takes in.
fn join(
    ir: &FunctionIr,
    entries: &HashMap<u64, usize>,
    index: &HashMap<u64, usize>,
    block: usize,
) -> Option<(Stmt, usize)> {
    let (first, lhs, rhs, taken) = test(ir.blocks[block].stmts.last())?;
    let starts = |position: usize| ir.blocks.get(position).map(|block| block.start);
    let fallthrough = starts(block + 1)?;
    let position = |start: u64| index.get(&start).copied();
    let same = |one: u64, other: u64| same_place(ir, index, one, other);
    let first_test = || (first, lhs.clone(), rhs.clone());
    for second in [block + 1, position(taken)?] {
        let candidate = &ir.blocks[second];
        if second == 0
            || second == block
            || entries.get(&candidate.start) != Some(&1)
            || candidate.stmts.len() != 1
        {
            continue;
        }
        let Some((cond, other_lhs, other_rhs, other)) = test(candidate.stmts.last()) else {
            continue;
        };
        let Some(after) = starts(second + 1) else {
            continue;
        };
        if [other, after].contains(&candidate.start) {
            continue;
        }
        let holds = truth(cond, other_lhs, other_rhs);
        let fails = truth(cond.invert(), other_lhs, other_rhs);
        let (test, then, els, target) = if second == block + 1 {
            if same(other, taken) {
                // a || b goes where both go; otherwise on.
                (first_test(), Expr::Const(1), holds, taken)
            } else if same(after, taken) {
                // !a && b goes where b goes; otherwise where both go.
                (
                    (first.invert(), lhs.clone(), rhs.clone()),
                    holds,
                    Expr::Const(0),
                    other,
                )
            } else {
                continue;
            }
        } else if same(other, fallthrough) {
            // a && !b goes where b falls; otherwise on.
            (first_test(), fails, Expr::Const(0), after)
        } else if same(after, fallthrough) {
            // a && b goes where b goes; otherwise on.
            (first_test(), holds, Expr::Const(0), other)
        } else {
            continue;
        };
        let (cond, lhs, rhs) = test;
        let joined = Expr::Select {
            cond,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
            then: Box::new(then),
            els: Box::new(els),
        };
        if tests(&joined) > MAX_TESTS {
            continue;
        }
        let stmt = Stmt::Brif {
            cond: Cond::Ne,
            lhs: joined,
            rhs: Expr::Const(0),
            target,
        };
        return Some((stmt, second));
    }
    None
}

/// Whether going to `one` does what going to `other` does: they lead to
/// the same block, or to blocks that only return the same value.
fn same_place(ir: &FunctionIr, index: &HashMap<u64, usize>, one: u64, other: u64) -> bool {
    let (one, other) = (settle(ir, index, one), settle(ir, index, other));
    if one == other {
        return true;
    }
    let stmts = |start: u64| {
        index
            .get(&start)
            .map(|position| ir.blocks[*position].stmts.as_slice())
    };
    match (stmts(one), stmts(other)) {
        (Some([Stmt::Ret { value: a }]), Some([Stmt::Ret { value: b }])) => a == b,
        (Some([Stmt::Trap]), Some([Stmt::Trap])) => true,
        _ => false,
    }
}

/// Where control goes from a block start, past blocks that only jump.
fn settle(ir: &FunctionIr, index: &HashMap<u64, usize>, mut target: u64) -> u64 {
    for _ in 0..8 {
        match index
            .get(&target)
            .map(|position| ir.blocks[*position].stmts.as_slice())
        {
            Some([Stmt::Br { target: Some(next) }]) if *next != target => target = *next,
            _ => break,
        }
    }
    target
}

/// A test as a truth value, one when it holds; a joined test already is one.
fn truth(cond: Cond, lhs: &Expr, rhs: &Expr) -> Expr {
    if cond == Cond::Ne && matches!(rhs, Expr::Const(0)) && is_truth(lhs) {
        return lhs.clone();
    }
    Expr::Select {
        cond,
        lhs: Box::new(lhs.clone()),
        rhs: Box::new(rhs.clone()),
        then: Box::new(Expr::Const(1)),
        els: Box::new(Expr::Const(0)),
    }
}

/// A choice whose every outcome is zero or one.
fn is_truth(expr: &Expr) -> bool {
    match expr {
        Expr::Select { then, els, .. } => [then, els]
            .into_iter()
            .all(|value| matches!(value.as_ref(), Expr::Const(0 | 1)) || is_truth(value)),
        _ => false,
    }
}

/// How many comparisons a truth value makes.
fn tests(expr: &Expr) -> usize {
    match expr {
        Expr::Select { lhs, then, els, .. } => {
            let own = if is_truth(lhs) { tests(lhs) } else { 1 };
            own + [then, els]
                .into_iter()
                .map(|value| if is_truth(value) { tests(value) } else { 0 })
                .sum::<usize>()
        }
        _ => 0,
    }
}

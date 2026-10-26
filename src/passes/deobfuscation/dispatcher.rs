//! Bypass decision blocks only when every incoming state is constant.

use std::collections::{HashMap, HashSet};

use crate::ir::{Block, Expr, FunctionIr, Stmt};

pub(super) fn remove(ir: &mut FunctionIr) -> usize {
    crate::timing::scope!("deobfuscation::dispatcher");
    if !ir
        .blocks
        .iter()
        .skip(1)
        .any(|block| state_register(block).is_some())
    {
        return 0;
    }
    if !ir.landing_pads.is_empty() || ir.blocks.iter().any(crate::ir::cfg::opaque) {
        return 0;
    }
    let starts: HashSet<u64> = ir.blocks.iter().map(|block| block.start).collect();
    for block in &ir.blocks {
        let valid = match block.stmts.last() {
            Some(
                Stmt::Br {
                    target: Some(target),
                }
                | Stmt::Brif { target, .. },
            ) => starts.contains(target),
            Some(Stmt::Switch { cases, default, .. }) => {
                default.is_some_and(|target| starts.contains(&target))
                    && cases.iter().all(|(_, target)| starts.contains(target))
            }
            Some(Stmt::BrifFlags { .. }) => false,
            _ => true,
        };
        if !valid {
            return 0;
        }
    }
    let mut removed = 0;
    // Each success deletes at least one decision block.
    loop {
        let mut changed = false;
        for header in 1..ir.blocks.len() {
            let Some(state) = state_register(&ir.blocks[header]) else {
                continue;
            };
            if let Some(count) = rewrite(ir, header, state) {
                removed += count;
                changed = true;
                break;
            }
        }
        if !changed {
            return removed;
        }
    }
}

fn state_register(block: &Block) -> Option<u16> {
    if block.stmts.len() != 1 {
        return None;
    }
    let mut reads = HashSet::new();
    match &block.stmts[0] {
        Stmt::Brif { lhs, rhs, .. } => {
            if !super::total(lhs) || !super::total(rhs) {
                return None;
            }
            crate::ir::visit::collect_reads(lhs, &mut reads);
            crate::ir::visit::collect_reads(rhs, &mut reads);
        }
        Stmt::Switch { index, .. } if super::total(index) => {
            crate::ir::visit::collect_reads(index, &mut reads);
        }
        _ => return None,
    }
    if reads.len() != 1 {
        return None;
    }
    reads
        .into_iter()
        .next()
        .filter(|register| *register >= crate::ir::VARIABLE_BASE)
}

fn pure(block: &Block, state: u16) -> bool {
    block.stmts.is_empty()
        || matches!(block.stmts.as_slice(), [Stmt::Br { target: Some(_) }])
        || state_register(block) == Some(state)
}

fn resolve(
    ir: &FunctionIr,
    region: &HashSet<usize>,
    header: usize,
    state: u16,
    value: u64,
) -> Option<u64> {
    let mut at = header;
    let mut seen = HashSet::new();
    while region.contains(&at) {
        if !seen.insert(at) {
            return None;
        }
        let next = match ir.blocks[at].stmts.last() {
            Some(Stmt::Brif {
                cond,
                lhs,
                rhs,
                target,
            }) => {
                let register = |index| (index == state).then_some(value);
                let (Some(a), Some(b)) = (
                    crate::ir::semantics::evaluate(lhs, &register),
                    crate::ir::semantics::evaluate(rhs, &register),
                ) else {
                    return None;
                };
                if crate::ir::semantics::holds(
                    *cond,
                    a,
                    b,
                    crate::ir::semantics::operand_width(lhs, rhs),
                ) {
                    *target
                } else {
                    match ir.blocks.get(at + 1) {
                        Some(block) => block.start,
                        None => return None,
                    }
                }
            }
            Some(Stmt::Switch {
                index,
                cases,
                default,
            }) => {
                let Some(value) = crate::ir::semantics::evaluate(index, &|index| {
                    (index == state).then_some(value)
                }) else {
                    return None;
                };
                match cases.iter().find(|(case, _)| *case as u64 == value) {
                    Some((_, target)) => *target,
                    None => match default {
                        Some(target) => *target,
                        None => return None,
                    },
                }
            }
            Some(Stmt::Br {
                target: Some(target),
            }) => *target,
            None => match ir.blocks.get(at + 1) {
                Some(block) => block.start,
                None => return None,
            },
            _ => return None,
        };
        let Some(index) = ir.blocks.iter().position(|block| block.start == next) else {
            return None;
        };
        at = index;
    }
    Some(ir.blocks[at].start)
}

fn constants(expr: &Expr) -> Option<Vec<u64>> {
    match expr {
        Expr::Const(value) => Some(vec![*value]),
        Expr::Select {
            then,
            els,
            lhs,
            rhs,
            ..
        } if super::total(lhs) && super::total(rhs) => match (then.as_ref(), els.as_ref()) {
            (Expr::Const(a), Expr::Const(b)) => Some(vec![*a, *b]),
            _ => None,
        },
        _ => None,
    }
}

struct Transition {
    value: Expr,
    targets: HashMap<u64, Vec<u64>>,
}

struct Transitions {
    edits: HashMap<usize, Transition>,
    state_count: usize,
}

fn region(ir: &FunctionIr, header: usize, state: u16) -> HashSet<usize> {
    let mut region = HashSet::new();
    let mut pending = vec![header];
    while let Some(at) = pending.pop() {
        if pure(&ir.blocks[at], state) && region.insert(at) {
            pending.extend(crate::ir::cfg::successors(ir, at));
        }
    }
    // Empty return-to-dispatcher blocks are shared by the case bodies.
    loop {
        let mut added = false;
        for at in 1..ir.blocks.len() {
            if region.contains(&at)
                || !matches!(
                    ir.blocks[at].stmts.as_slice(),
                    [Stmt::Br { target: Some(_) }]
                )
            {
                continue;
            }
            let next = crate::ir::cfg::successors(ir, at);
            if next.len() == 1 && region.contains(&next[0]) {
                region.insert(at);
                added = true;
            }
        }
        if !added {
            break;
        }
    }
    region
}

fn prove_transitions(ir: &FunctionIr, region: &HashSet<usize>, state: u16) -> Option<Transitions> {
    // Unknown state definitions anywhere in the function require the original CFG.
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        let (written, _) = crate::ir::visit::statement_registers(stmt);
        if !written.contains(&state) {
            continue;
        }
        match stmt {
            Stmt::Assign { dest, value } if dest.width == 32 || dest.width == 64 => {
                if constants(value).is_none() {
                    return None;
                }
            }
            _ => return None,
        }
    }
    let counts = crate::render::structure::compare_chain::predecessors(ir);
    let mut predecessors = vec![Vec::new(); ir.blocks.len()];
    for at in 0..ir.blocks.len() {
        for next in crate::ir::cfg::successors(ir, at) {
            predecessors[next].push(at);
        }
    }
    let mut edits = HashMap::new();
    let mut states = HashSet::new();
    for at in 0..ir.blocks.len() {
        if region.contains(&at) {
            continue;
        }
        let next = crate::ir::cfg::successors(ir, at);
        let entries: Vec<usize> = next
            .iter()
            .copied()
            .filter(|next| region.contains(next))
            .collect();
        if entries.is_empty() {
            continue;
        }
        // The state must be fixed before this edge; do not speculate through joins.
        let mut from = at;
        let mut seen = HashSet::new();
        let value = loop {
            if !seen.insert(from) {
                return None;
            }
            if let Some((position, dest, value)) = ir.blocks[from]
                .stmts
                .iter()
                .enumerate()
                .rev()
                .find_map(|(position, stmt)| match stmt {
                    Stmt::Assign { dest, value } if dest.index == state => {
                        Some((position, dest, value))
                    }
                    _ => None,
                })
            {
                let mut value = value.clone();
                let mask = crate::ir::semantics::mask(u32::from(dest.width));
                match &mut value {
                    Expr::Const(value) => *value &= mask,
                    Expr::Select {
                        then,
                        els,
                        lhs,
                        rhs,
                        ..
                    } => {
                        // Reusing the condition is valid only while its operands
                        // still have the values read by the state assignment.
                        let mut reads = HashSet::new();
                        crate::ir::visit::collect_reads(lhs, &mut reads);
                        crate::ir::visit::collect_reads(rhs, &mut reads);
                        if reads.contains(&state)
                            || from != at
                            || !matches!(
                                ir.blocks[from].stmts.get(position + 1..),
                                Some([] | [Stmt::Br { target: Some(_) }])
                            )
                        {
                            return None;
                        }
                        for arm in [then, els] {
                            let Expr::Const(value) = arm.as_mut() else {
                                return None;
                            };
                            *value &= mask;
                        }
                    }
                    _ => return None,
                }
                break value;
            }
            if counts.get(&ir.blocks[from].start).copied() != Some(1) {
                return None;
            }
            let [previous] = predecessors[from].as_slice() else {
                return None;
            };
            if region.contains(previous) {
                return None;
            }
            from = *previous;
        };
        let Some(values) = constants(&value) else {
            return None;
        };
        states.extend(values.iter().copied());
        let mut targets = HashMap::new();
        for entry in entries {
            let mut resolved = Vec::new();
            for value in &values {
                let Some(target) = resolve(ir, region, entry, state, *value) else {
                    return None;
                };
                resolved.push(target);
            }
            targets.insert(ir.blocks[entry].start, resolved);
        }
        if values.len() == 2 && next.len() != 1 {
            return None;
        }
        edits.insert(at, Transition { value, targets });
    }
    if edits.is_empty() || states.len() < 2 {
        return None;
    }
    Some(Transitions {
        edits,
        state_count: states.len(),
    })
}

fn edit_blocks(ir: &FunctionIr, edits: &HashMap<usize, Transition>) -> Option<FunctionIr> {
    let mut blocks = Vec::new();
    // Branches use addresses for identity only; reserve an unused address for a
    // conditional transition's explicit false edge.
    let mut address = ir.blocks.iter().map(|block| block.start).max().unwrap_or(0);
    for (at, original) in ir.blocks.iter().enumerate() {
        let mut block = original.clone();
        if let Some(Transition { value, targets }) = edits.get(&at) {
            if let Expr::Select { cond, lhs, rhs, .. } = value {
                let Some(resolved) = targets.values().next() else {
                    return None;
                };
                if matches!(block.stmts.last(), Some(Stmt::Br { .. })) {
                    block.stmts.pop();
                }
                block.stmts.push(Stmt::Brif {
                    cond: *cond,
                    lhs: lhs.as_ref().clone(),
                    rhs: rhs.as_ref().clone(),
                    target: resolved[0],
                });
                blocks.push(block);
                address = match address.checked_add(1) {
                    Some(address) => address,
                    None => return None,
                };
                blocks.push(Block {
                    start: address,
                    stmts: vec![Stmt::Br {
                        target: Some(resolved[1]),
                    }],
                });
                continue;
            }
            match block.stmts.last_mut() {
                Some(Stmt::Br {
                    target: Some(target),
                })
                | Some(Stmt::Brif { target, .. }) => {
                    if let Some(resolved) = targets.get(target) {
                        *target = resolved[0];
                    }
                }
                Some(Stmt::Switch { .. }) => return None,
                _ => {}
            }
            let fallthrough = ir
                .blocks
                .get(at + 1)
                .and_then(|next| targets.get(&next.start));
            if let Some(resolved) = fallthrough {
                if matches!(block.stmts.last(), Some(Stmt::Brif { .. })) {
                    blocks.push(block);
                    address = match address.checked_add(1) {
                        Some(address) => address,
                        None => return None,
                    };
                    blocks.push(Block {
                        start: address,
                        stmts: vec![Stmt::Br {
                            target: Some(resolved[0]),
                        }],
                    });
                    continue;
                }
                if !matches!(block.stmts.last(), Some(Stmt::Br { .. })) {
                    block.stmts.push(Stmt::Br {
                        target: Some(resolved[0]),
                    });
                }
            }
        }
        blocks.push(block);
    }
    let mut rewritten = ir.clone();
    rewritten.blocks = blocks;
    Some(rewritten)
}

fn rewrite(ir: &mut FunctionIr, header: usize, state: u16) -> Option<usize> {
    let region = region(ir, header, state);
    if region.contains(&0) {
        return None;
    }
    let decisions = region
        .iter()
        .filter(|at| state_register(&ir.blocks[**at]) == Some(state))
        .count();
    if decisions < 2 && !matches!(ir.blocks[header].stmts.last(), Some(Stmt::Switch { .. })) {
        return None;
    }
    let Some(transitions) = prove_transitions(ir, &region, state) else {
        return None;
    };
    let Some(mut rewritten) = edit_blocks(ir, &transitions.edits) else {
        return None;
    };
    let reached = crate::ir::cfg::reached(&rewritten);
    if region
        .iter()
        .any(|at| reached.contains(&ir.blocks[*at].start))
    {
        return None;
    }
    rewritten
        .blocks
        .retain(|block| reached.contains(&block.start));
    *ir = rewritten;
    Some(transitions.state_count)
}

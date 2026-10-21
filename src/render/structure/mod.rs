mod build;
#[cfg(test)]
mod classify;
mod cleanup;
pub mod compare_chain;
mod dominance;
mod duplicate;
#[cfg(test)]
pub(crate) mod lower;
mod short_circuit;

use std::borrow::Cow;
use std::collections::HashMap;

use crate::ir::{Cond, Expr, FunctionIr, Stmt};
use crate::render::structure::build::{Structurer, branch_targets};
use crate::render::structure::cleanup::collect_targets;
use crate::render::structure::cleanup::flatten_early_returns;
use crate::render::structure::cleanup::prune_labels;
use crate::render::structure::cleanup::prune_unreachable;

#[derive(Debug, Clone)]
pub enum Node {
    Stmt(Stmt),
    Label(u64),
    If {
        cond: Cond,
        lhs: Expr,
        rhs: Expr,
        then: Vec<Node>,
        els: Vec<Node>,
    },
    DoWhile {
        cond: Cond,
        lhs: Expr,
        rhs: Expr,
        body: Vec<Node>,
    },
    /// `for (;;)`: a loop whose only exits are `break`, `return` or `goto`.
    Forever {
        body: Vec<Node>,
    },
    Break,
    Continue,
    /// A dispatch with the case bodies inlined.
    Switch {
        index: Expr,
        arms: Vec<(Vec<i64>, Vec<Node>)>,
        default: Option<Vec<Node>>,
    },
    While {
        prefix: Vec<Node>,
        cond: Cond,
        lhs: Expr,
        rhs: Expr,
        body: Vec<Node>,
    },
}

/// Structures the function by its dominator tree, also with compare chains
/// rebuilt as switches, keeping the result with the fewest labels, and of
/// those the fewest gotos. A function
/// that tree cannot cover, such as one with code only an indirect jump
/// reaches, is structured in address order instead.
pub fn structure_best(ir: &FunctionIr) -> Vec<Node> {
    best_structure(ir).0
}

/// The same, with the function as the chosen structure reads it: the
/// variant whose blocks were structured.
pub(crate) fn best_structure(ir: &FunctionIr) -> (Vec<Node>, Cow<'_, FunctionIr>) {
    let mut best = structure_variants(Cow::Borrowed(ir));
    if label_count(&best.0) == 0 {
        return best;
    }
    // A branch to a block that only jumps on can go where the jump does.
    if let Some(threaded) = duplicate::threaded(ir) {
        let candidate = structure_variants(Cow::Owned(threaded));
        if cost(&candidate.0) < cost(&best.0) {
            best = candidate;
        }
    }
    if label_count(&best.0) == 0 {
        return best;
    }
    // A test copied into several branches can be made once where they meet.
    if let Some(merged) = duplicate::merged_checks(ir) {
        let merged = duplicate::threaded(&merged).unwrap_or(merged);
        let candidate = structure_variants(Cow::Owned(merged));
        if cost(&candidate.0) < cost(&best.0) {
            best = candidate;
        }
    }
    if label_count(&best.0) == 0 {
        return best;
    }
    // A branch sent past a test it decided can go through the test again.
    if let Some(unthreaded) = duplicate::unthreaded(&best.1) {
        let candidate = structure_variants(Cow::Owned(unthreaded));
        if cost(&candidate.0) < cost(&best.0) {
            best = candidate;
        }
    }
    if label_count(&best.0) == 0 {
        return best;
    }
    // Tests that only complete another one can join it as `&&` or `||`.
    if let Some(joined) = short_circuit::short_circuited(&best.1) {
        let candidate = structure_variants(Cow::Owned(joined));
        if cost(&candidate.0) < cost(&best.0) {
            best = candidate;
        }
    }
    best
}

fn structure_variants(ir: Cow<'_, FunctionIr>) -> (Vec<Node>, Cow<'_, FunctionIr>) {
    let best = structure_chosen(ir.clone());
    if label_count(&best.0) == 0 {
        return best;
    }
    // Copying short shared blocks into the branches that enter them can
    // leave fewer labels.
    if let Some(duplicated) = duplicate::tail_duplicated(&ir) {
        let candidate = structure_chosen(Cow::Owned(duplicated));
        if cost(&candidate.0) < cost(&best.0) {
            return candidate;
        }
    }
    best
}

fn structure_chosen(ir: Cow<'_, FunctionIr>) -> (Vec<Node>, Cow<'_, FunctionIr>) {
    let Some(primary) = by_dominance(&ir) else {
        return (by_layout(&ir), ir);
    };
    // A compare tree over one value reads as a switch, unless that leaves
    // more labels.
    let chains = crate::render::structure::compare_chain::recover_chains(&ir);
    if !chains.is_empty() {
        let mut chained = ir.clone().into_owned();
        crate::render::structure::compare_chain::apply_chains(&mut chained, &chains);
        if let Some(candidate) = by_dominance(&chained)
            && cost(&candidate) <= cost(&primary)
            && labels_resolve(&ir, &candidate)
        {
            return (candidate, Cow::Owned(chained));
        }
    }
    (primary, ir)
}

/// Drops labels nothing jumps to but the `kept` ones, code after a jump,
/// and jumps to where the code goes next anyway; hoisting an `else` after
/// a branch that leaves can bring a jump right before its label.
fn tidy(nodes: &mut Vec<Node>, kept: std::collections::HashSet<u64>) {
    let prune = |nodes: &mut Vec<Node>| {
        let mut used = kept.clone();
        collect_targets(nodes, &mut used);
        prune_labels(nodes, &used);
    };
    cleanup::drop_jumps_to_next(nodes, None);
    cleanup::inline_return_tails(nodes);
    prune(nodes);
    prune_unreachable(nodes);
    cleanup::shape_forever_loops(nodes);
    cleanup::fold_trailing_continues(nodes);
    flatten_early_returns(nodes);
    cleanup::drop_jumps_to_next(nodes, None);
    prune(nodes);
    cleanup::undo_loop_inversion(nodes);
    cleanup::return_known_constants(nodes);
}

fn by_dominance(ir: &FunctionIr) -> Option<Vec<Node>> {
    let mut nodes = dominance::structure(ir)?;
    // Code the entry does not reach keeps its label, which names where it starts.
    let entries: std::collections::HashSet<u64> = dominance::entries(ir).into_iter().collect();
    tidy(&mut nodes, entries.clone());
    if label_count(&nodes) == 0 {
        return Some(nodes);
    }
    // A loop's exits that one branch alone enters can sit where it leaves
    // to them, when that leaves fewer labels.
    let mut best = nodes;
    for absorb in [dominance::Absorb::Private, dominance::Absorb::Every] {
        if let Some(mut absorbing) = dominance::structure_absorbing(ir, absorb) {
            tidy(&mut absorbing, entries.clone());
            if cost(&absorbing) < cost(&best) && labels_resolve(ir, &absorbing) {
                best = absorbing;
            }
        }
        if label_count(&best) == 0 {
            break;
        }
    }
    Some(best)
}

/// The address-order structuring and its variants, keeping the one with the
/// fewest labels.
fn by_layout(ir: &FunctionIr) -> Vec<Node> {
    let primary = structure(ir);
    if label_count(&primary) == 0 {
        return primary;
    }
    let mut candidates = Vec::new();
    let mut alternative = ir.clone();
    crate::passes::layout::normalize_layout(&mut alternative);
    candidates.push(structure_with(&alternative, true));
    let mut chained = ir.clone();
    let chains = crate::render::structure::compare_chain::recover_chains(&chained);
    if !chains.is_empty() {
        crate::render::structure::compare_chain::apply_chains(&mut chained, &chains);
        candidates.push(structure(&chained));
    }
    // A variant wins only with fewer labels and every goto into the function
    // reaching exactly one of them.
    let mut best = primary;
    for candidate in candidates {
        if cost(&candidate) < cost(&best) && labels_resolve(ir, &candidate) {
            best = candidate;
        }
    }
    best
}

/// True when every jump to a block of the function has exactly one label.
fn labels_resolve(ir: &FunctionIr, nodes: &[Node]) -> bool {
    fn labels(nodes: &[Node], found: &mut Vec<u64>) {
        for node in nodes {
            match node {
                Node::Label(address) => found.push(*address),
                Node::If { then, els, .. } => {
                    labels(then, found);
                    labels(els, found);
                }
                Node::DoWhile { body, .. } | Node::Forever { body } => labels(body, found),
                Node::While { prefix, body, .. } => {
                    labels(prefix, found);
                    labels(body, found);
                }
                Node::Switch { arms, default, .. } => {
                    for (_, body) in arms {
                        labels(body, found);
                    }
                    if let Some(body) = default {
                        labels(body, found);
                    }
                }
                Node::Stmt(_) | Node::Break | Node::Continue => {}
            }
        }
    }
    let mut found = Vec::new();
    labels(nodes, &mut found);
    let mut targets = std::collections::HashSet::new();
    collect_targets(nodes, &mut targets);
    targets
        .iter()
        .filter(|target| ir.blocks.iter().any(|block| block.start == **target))
        .all(|target| found.iter().filter(|label| *label == target).count() == 1)
}

/// What a structure leaves to read as jumps: its labels, then its gotos.
fn cost(nodes: &[Node]) -> (usize, usize) {
    fn gotos(nodes: &[Node]) -> usize {
        nodes
            .iter()
            .map(|node| match node {
                Node::Stmt(Stmt::Br { target: Some(_) }) => 1,
                Node::If { then, els, .. } => gotos(then) + gotos(els),
                Node::DoWhile { body, .. } | Node::Forever { body } => gotos(body),
                Node::While { prefix, body, .. } => gotos(prefix) + gotos(body),
                Node::Switch { arms, default, .. } => {
                    arms.iter().map(|(_, body)| gotos(body)).sum::<usize>()
                        + default.as_ref().map_or(0, |body| gotos(body))
                }
                _ => 0,
            })
            .sum()
    }
    (label_count(nodes), gotos(nodes))
}

fn label_count(nodes: &[Node]) -> usize {
    nodes
        .iter()
        .map(|node| match node {
            Node::Label(_) => 1,
            Node::If { then, els, .. } => label_count(then) + label_count(els),
            Node::DoWhile { body, .. } | Node::Forever { body } | Node::While { body, .. } => {
                label_count(body)
            }
            Node::Switch { arms, default, .. } => {
                arms.iter()
                    .map(|(_, body)| label_count(body))
                    .sum::<usize>()
                    + default.as_ref().map_or(0, |body| label_count(body))
            }
            _ => 0,
        })
        .sum()
}

pub fn structure(ir: &FunctionIr) -> Vec<Node> {
    structure_with(ir, false)
}

/// The blocks only an indirect jump can enter: nothing branches or falls
/// through into them, so they keep a label instead of being pruned. Padding
/// that only traps is left out.
fn indirect_entries(ir: &FunctionIr) -> std::collections::HashSet<u64> {
    let indirect = ir
        .blocks
        .iter()
        .any(|block| matches!(block.stmts.last(), Some(Stmt::BrIndirect { .. })));
    if !indirect {
        return std::collections::HashSet::new();
    }
    let mut seen = vec![false; ir.blocks.len()];
    let mut pending = vec![0];
    while let Some(index) = pending.pop() {
        if index >= seen.len() || seen[index] {
            continue;
        }
        seen[index] = true;
        pending.extend(compare_chain::successors(ir, index));
    }
    ir.blocks
        .iter()
        .zip(seen)
        .filter(|(block, seen)| !seen && !block.stmts.iter().all(|stmt| matches!(stmt, Stmt::Trap)))
        .map(|(block, _)| block.start)
        .collect()
}

fn structure_with(ir: &FunctionIr, reordered: bool) -> Vec<Node> {
    let index: HashMap<u64, usize> = ir
        .blocks
        .iter()
        .enumerate()
        .map(|(position, block)| (block.start, position))
        .collect();
    let entries = indirect_entries(ir);
    let mut structurer = Structurer {
        blocks: &ir.blocks,
        index,
        targeted: ir
            .blocks
            .iter()
            .flat_map(branch_targets)
            .chain(entries.iter().copied())
            .collect(),
        reordered,
    };
    let mut nodes = structurer.emit(0, ir.blocks.len());
    tidy(&mut nodes, entries);
    nodes
}

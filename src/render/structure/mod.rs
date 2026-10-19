mod build;
mod cleanup;
pub mod compare_chain;

use std::collections::HashMap;

use crate::ir::{Cond, Expr, FunctionIr, Stmt};
use crate::render::structure::build::Structurer;
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

/// Structures the function in address order and, when labels remain, also
/// with a reordered layout and with compare chains rebuilt as switches,
/// keeping the result with the fewest labels.
///
/// Reordering folds loops whose latch precedes the header but can make other
/// shapes worse; every variant describes the same graph.
pub fn structure_best(ir: &FunctionIr) -> Vec<Node> {
    let primary = structure(ir);
    if label_count(&primary) == 0 {
        return primary;
    }
    let mut alternative = ir.clone();
    crate::passes::layout::normalize_layout(&mut alternative);
    let reordered = structure_with(&alternative, true);
    let reordered_count = label_count(&reordered);
    let primary_count = label_count(&primary);
    let mut best = if reordered_count < primary_count {
        reordered
    } else {
        primary
    };
    let mut best_count = label_count(&best);
    // A compare tree over one value, rebuilt as a switch, lays out its case
    // bodies without a label each.
    let mut chained = ir.clone();
    let chains = crate::render::structure::compare_chain::recover_chains(&chained);
    if !chains.is_empty() {
        crate::render::structure::compare_chain::apply_chains(&mut chained, &chains);
        let rebuilt = structure(&chained);
        let count = label_count(&rebuilt);
        if count < best_count {
            best = rebuilt;
            best_count = count;
        }
    }
    let _ = best_count;
    best
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

fn structure_with(ir: &FunctionIr, reordered: bool) -> Vec<Node> {
    let index: HashMap<u64, usize> = ir
        .blocks
        .iter()
        .enumerate()
        .map(|(position, block)| (block.start, position))
        .collect();
    let mut targeted = std::collections::HashSet::new();
    for block in &ir.blocks {
        if let Some(Stmt::Brif { target, .. }) | Some(Stmt::BrifFlags { target, .. }) =
            block.stmts.last()
        {
            targeted.insert(*target);
        }
        if let Some(Stmt::Br {
            target: Some(target),
        }) = block.stmts.last()
        {
            targeted.insert(*target);
        }
        if let Some(Stmt::Switch { cases, default, .. }) = block.stmts.last() {
            for (_, target) in cases {
                targeted.insert(*target);
            }
            if let Some(target) = default {
                targeted.insert(*target);
            }
        }
    }
    let mut structurer = Structurer {
        blocks: &ir.blocks,
        index,
        targeted,
        reordered,
    };
    let mut nodes = structurer.emit(0, ir.blocks.len());
    let mut used = std::collections::HashSet::new();
    collect_targets(&nodes, &mut used);
    prune_labels(&mut nodes, &used);
    prune_unreachable(&mut nodes);
    flatten_early_returns(&mut nodes);
    nodes
}

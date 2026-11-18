//! Analysis dependencies for call declarations.

use std::collections::BTreeSet;

use crate::analysis::Analysis;
use crate::ir::{Expr, Stmt};
use crate::loader::Image;

pub(crate) fn dependencies(image: &Image, root: &Analysis) -> BTreeSet<u64> {
    if image.go {
        return BTreeSet::new();
    }
    let mut targets = BTreeSet::from([root.ir.addr]);
    let mut operands: Vec<_> = root
        .ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .flat_map(Stmt::operands)
        .collect();
    while let Some(value) = operands.pop() {
        operands.extend(crate::ir::visit::children(value));
        if let Expr::Const(address) = value
            && image.functions.contains_key(address)
        {
            targets.insert(*address);
        }
    }
    let mut callees = BTreeSet::new();
    for stmt in root.ir.blocks.iter().flat_map(|block| &block.stmts) {
        if let Stmt::Call {
            target: Some(target),
            through: None,
            ..
        } = stmt
        {
            targets.insert(*target);
            callees.insert(*target);
        }
    }
    let mut addresses = BTreeSet::new();
    for target in targets {
        if crate::analysis::declarations::unknown_import(image, target) {
            addresses.extend(few_callers(image, target));
            continue;
        }
        if target != root.ir.addr
            && callees.contains(&target)
            && crate::analysis::summary::needs_parameter_analysis(image, target)
        {
            addresses.insert(target);
        }
        let summary = crate::analysis::summary::summary(image, target);
        if summary.arity.is_some_and(|count| count != 0)
            || summary.floats.is_some_and(|count| count != 0)
            || summary.stack != 0
            || !image.functions.contains_key(&target)
            || image.functions[&target]
                .sources
                .contains(&crate::loader::NameSource::Plt)
        {
            continue;
        }
        addresses.insert(target);
        addresses.extend(few_callers(image, target));
    }
    addresses
}

/// The callers of `target` when they are few enough to analyse for one
/// request, and none otherwise.
///
/// A declaration is recovered only from all the callers of a function, so
/// some of them would be no use; and a function that much of a large binary
/// calls has thousands, each of which would be analysed whole.
fn few_callers(image: &Image, target: u64) -> Vec<u64> {
    const MOST: usize = 16;
    let callers = crate::analysis::results::callers(image, target);
    if callers.len() > MOST {
        return Vec::new();
    }
    callers
}

#[cfg(test)]
mod tests;

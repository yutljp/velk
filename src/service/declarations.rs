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
            addresses.extend(crate::analysis::results::callers(image, target));
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
        addresses.extend(crate::analysis::results::callers(image, target));
    }
    addresses
}

#[cfg(test)]
mod tests;

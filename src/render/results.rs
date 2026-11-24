//! Functions that return several values at once, as Go's do: each returns
//! a structure with one member for every value.

use crate::ir::{CType, Expr, FunctionIr, Operation, Stmt};

/// How many values the function returns in a structure: what every return
/// of it holds, when each holds the same number and more than one. Only
/// for Go's register convention, whose callers take the values from the
/// call; those of its assembly one read them from their own frame.
pub(super) fn count(ir: &FunctionIr) -> usize {
    if !ir.convention.several_results()
        || ir.ret_type == CType::Void
        || ir.ret_type.precision().is_some()
        || ir.declared_signature.is_some()
    {
        return 0;
    }
    let mut count = None;
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        let Stmt::Ret { value, .. } = stmt else {
            continue;
        };
        let held = match value {
            Expr::Apply {
                op: Operation::Results,
                args,
            } => args.len(),
            _ => 1,
        };
        if held < 2 || count.replace(held).is_some_and(|previous| previous != held) {
            return 0;
        }
    }
    count.unwrap_or(0)
}

pub(super) fn type_name(count: usize) -> String {
    format!("struct velk_results{count}")
}

fn definition(count: usize) -> String {
    let members: String = (0..count)
        .map(|member| format!(" int64_t r{member};"))
        .collect();
    format!("{} {{{members} }};\n\n", type_name(count))
}

/// The definitions of the structures of `own` values, when that is any,
/// of what the callees among `called` return, and of the `others`.
pub(super) fn definitions(
    ir: &FunctionIr,
    own: usize,
    called: impl Fn(u64) -> bool,
    others: impl Iterator<Item = usize>,
) -> String {
    let mut counts: std::collections::BTreeSet<usize> = ir
        .callee_results
        .iter()
        .filter(|(address, _)| called(**address))
        .map(|(_, count)| *count)
        .chain(others)
        .collect();
    if own > 0 {
        counts.insert(own);
    }
    counts.into_iter().map(definition).collect()
}

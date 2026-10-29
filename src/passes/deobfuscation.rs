//! Proven integer predicates and constant dispatcher transitions.

use serde::Serialize;

use crate::ir::{BinOp, Expr, FunctionIr, Stmt};

mod dispatcher;
#[cfg(test)]
mod tests;

/// Expression and control-flow simplifications proved by the analysis.
#[derive(Debug, Default, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Simplification {
    /// Whether an expression, predicate or dispatcher was simplified.
    pub simplified: bool,
    /// Conditional branches proved constant.
    pub predicates_removed: usize,
    /// Distinct constant states whose dispatcher tests were bypassed.
    pub dispatcher_states_removed: usize,
    /// Mixed bitwise/arithmetic expression trees replaced by shorter equivalents.
    pub mba_expressions_simplified: usize,
}

impl Simplification {
    pub(crate) fn add(&mut self, other: Self) {
        self.predicates_removed += other.predicates_removed;
        self.dispatcher_states_removed += other.dispatcher_states_removed;
        self.mba_expressions_simplified += other.mba_expressions_simplified;
        self.simplified = self.predicates_removed != 0
            || self.dispatcher_states_removed != 0
            || self.mba_expressions_simplified != 0;
    }
}

pub(crate) fn simplify(ir: &mut FunctionIr) -> Simplification {
    crate::timing::scope!("deobfuscation::simplify");
    let mba = super::mba::simplify(ir);
    if !ir.blocks.iter().any(|block| {
        matches!(
            block.stmts.last(),
            Some(Stmt::Brif { .. } | Stmt::Switch { .. })
        )
    }) {
        return Simplification {
            simplified: mba != 0,
            mba_expressions_simplified: mba,
            ..Default::default()
        };
    }
    let original = ir.clone();
    let mut changes = predicates(ir);
    changes.mba_expressions_simplified = mba;
    changes.dispatcher_states_removed = dispatcher::remove(ir);
    changes.simplified =
        changes.predicates_removed != 0 || changes.dispatcher_states_removed != 0 || mba != 0;
    if changes.simplified {
        super::copies::copy_propagate_guarded(ir);
        super::simplify::simplify(ir);
        super::dce::dce(ir);
    } else {
        *ir = original;
    }
    changes
}

pub(super) fn branches(ir: &FunctionIr) -> usize {
    ir.blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .filter(|stmt| matches!(stmt, Stmt::Brif { .. }))
        .count()
}

pub(super) fn predicates(ir: &mut FunctionIr) -> Simplification {
    crate::timing::scope!("deobfuscation::predicates");
    let before = branches(ir);
    for at in 0..ir.blocks.len() {
        let next = ir.blocks.get(at + 1).map(|block| block.start);
        let Some(Stmt::Brif {
            cond,
            lhs,
            rhs,
            target,
            ..
        }) = ir.blocks[at].stmts.last()
        else {
            continue;
        };
        let value = |expr: &Expr| match expr {
            Expr::Const(value) => Some(*value),
            _ if known_zero(expr) => Some(0),
            _ => None,
        };
        let (Some(a), Some(b)) = (value(lhs), value(rhs)) else {
            continue;
        };
        let taken =
            crate::ir::semantics::holds(*cond, a, b, crate::ir::semantics::operand_width(lhs, rhs));
        let target = if taken { Some(*target) } else { next };
        if let Some(target) = target {
            let origin = ir.blocks[at].stmts.pop().and_then(|stmt| stmt.origin());
            if Some(target) != next {
                ir.blocks[at].stmts.push(Stmt::Br {
                    target: Some(target),
                    at: origin,
                });
            }
        }
    }
    {
        crate::timing::scope!("deobfuscation::constants");
        crate::ssa::propagate_constants(ir);
    }
    {
        crate::timing::scope!("deobfuscation::ranges");
        crate::ssa::ranges::simplify(ir);
    }
    let removed = before.saturating_sub(branches(ir));
    Simplification {
        simplified: removed != 0,
        predicates_removed: removed,
        dispatcher_states_removed: 0,
        mba_expressions_simplified: 0,
    }
}

// Only total register arithmetic can disappear: a memory access or a division
// could fault even when its value cancels from the result.
fn total(expr: &Expr) -> bool {
    match expr {
        Expr::Const(_) | Expr::Reg { width: 1..=64, .. } => true,
        Expr::Bin {
            op: BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::And | BinOp::Or | BinOp::Xor,
            lhs,
            rhs,
        } => total(lhs) && total(rhs),
        _ => false,
    }
}

fn differs_by_odd_constant(lhs: &Expr, rhs: &Expr) -> bool {
    let Expr::Bin {
        op,
        lhs: base,
        rhs: offset,
    } = rhs
    else {
        return false;
    };
    matches!(op, BinOp::Add | BinOp::Sub)
        && base.as_ref() == lhs
        && matches!(offset.as_ref(), Expr::Const(value) if value & 1 != 0)
}

fn product_with_odd_difference(expr: &Expr) -> bool {
    matches!(expr, Expr::Bin { op: BinOp::Mul, lhs, rhs }
        if total(lhs) && total(rhs) && (differs_by_odd_constant(lhs, rhs) || differs_by_odd_constant(rhs, lhs)))
}

fn known_zero(expr: &Expr) -> bool {
    let Expr::Bin { op, lhs, rhs } = expr else {
        return matches!(expr, Expr::Const(0));
    };
    match op {
        BinOp::And if matches!(rhs.as_ref(), Expr::Const(1)) => {
            product_with_odd_difference(lhs) || (known_zero(lhs) && total(rhs))
        }
        BinOp::ModU if matches!(rhs.as_ref(), Expr::Const(2)) => product_with_odd_difference(lhs),
        BinOp::Xor | BinOp::Sub => lhs == rhs && total(lhs),
        BinOp::Or => known_zero(lhs) && known_zero(rhs),
        BinOp::And => {
            let complement = |a: &Expr, b: &Expr| {
                matches!(b, Expr::Bin { op: BinOp::Xor, lhs, rhs }
                    if lhs.as_ref() == a && matches!(rhs.as_ref(), Expr::Const(u64::MAX)))
            };
            total(lhs)
                && total(rhs)
                && (complement(lhs, rhs)
                    || complement(rhs, lhs)
                    || known_zero(lhs)
                    || known_zero(rhs))
        }
        _ => false,
    }
}

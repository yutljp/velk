use crate::ir::{Expr, Stmt};

pub(crate) fn children(expr: &Expr) -> Vec<&Expr> {
    match expr {
        Expr::Bin { lhs, rhs, .. } => vec![lhs.as_ref(), rhs.as_ref()],
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => vec![lhs.as_ref(), rhs.as_ref(), then.as_ref(), els.as_ref()],
        Expr::Load { addr, .. } => vec![addr.as_ref()],
        Expr::SignExtend { value, .. } => vec![value.as_ref()],
        _ => Vec::new(),
    }
}

/// The width an expression computes at. `None` for a constant, a sign
/// extension or mixed operand widths.
pub(crate) fn expr_width(expr: &Expr) -> Option<u8> {
    match expr {
        Expr::Reg { width, .. } => Some(*width),
        Expr::Const(_) => None,
        Expr::SignExtend { .. } => None,
        Expr::Load { width, .. } => Some(width.saturating_mul(8)),
        Expr::Bin {
            op: crate::ir::BinOp::And,
            rhs,
            ..
        } if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) => Some(32),
        Expr::Bin { lhs, rhs, .. } => match (expr_width(lhs), expr_width(rhs)) {
            (Some(left), Some(right)) if left == right => Some(left),
            (Some(width), None) | (None, Some(width)) => Some(width),
            _ => None,
        },
        Expr::Select { then, els, .. } => match (expr_width(then), expr_width(els)) {
            (Some(left), Some(right)) if left == right => Some(left),
            (Some(width), None) | (None, Some(width)) => Some(width),
            _ => None,
        },
    }
}

pub fn collect_reads(expr: &Expr, out: &mut std::collections::HashSet<u16>) {
    match expr {
        Expr::Reg { index, .. } => {
            out.insert(*index);
        }
        Expr::Const(_) => {}
        Expr::Bin { lhs, rhs, .. } => {
            collect_reads(lhs, out);
            collect_reads(rhs, out);
        }
        Expr::Load { addr, .. } => collect_reads(addr, out),
        Expr::SignExtend { value, .. } => collect_reads(value, out),
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => {
            collect_reads(lhs, out);
            collect_reads(rhs, out);
            collect_reads(then, out);
            collect_reads(els, out);
        }
    }
}

/// Substitutes register reads with values, for folding a loop header into
/// the condition that consumes it.
/// Replaces the reads of each register in a statement with its value.
pub(crate) fn replace_reads(stmt: &mut Stmt, values: &[(u16, Expr)]) {
    let replace = |expr: &mut Expr| *expr = substitute_values(expr.clone(), values);
    match stmt {
        Stmt::Assign { value, .. } | Stmt::Ret { value } => replace(value),
        Stmt::Store { addr, value, .. } => {
            replace(addr);
            replace(value);
        }
        Stmt::Brif { lhs, rhs, .. } => {
            replace(lhs);
            replace(rhs);
        }
        Stmt::BrIndirect { target } => replace(target),
        Stmt::Switch { index, .. } => replace(index),
        Stmt::Call {
            through: Some(through),
            ..
        } => replace(through),
        _ => {}
    }
}

pub fn substitute_values(expr: Expr, values: &[(u16, Expr)]) -> Expr {
    match expr {
        Expr::Reg { index, width } => match values.iter().find(|(reg, _)| *reg == index) {
            Some((_, value)) => value.clone(),
            None => Expr::Reg { index, width },
        },
        Expr::Const(value) => Expr::Const(value),
        Expr::Bin { op, lhs, rhs } => Expr::bin(
            op,
            substitute_values(*lhs, values),
            substitute_values(*rhs, values),
        ),
        Expr::Load {
            addr,
            width,
            signed,
        } => Expr::Load {
            addr: Box::new(substitute_values(*addr, values)),
            width,
            signed,
        },
        Expr::SignExtend { value, width } => Expr::SignExtend {
            value: Box::new(substitute_values(*value, values)),
            width,
        },
        Expr::Select {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => Expr::Select {
            cond,
            lhs: Box::new(substitute_values(*lhs, values)),
            rhs: Box::new(substitute_values(*rhs, values)),
            then: Box::new(substitute_values(*then, values)),
            els: Box::new(substitute_values(*els, values)),
        },
    }
}

pub fn statement_reads(stmt: &Stmt) -> std::collections::HashSet<u16> {
    statement_registers(stmt).1
}

pub(crate) fn statement_registers(
    stmt: &Stmt,
) -> (
    std::collections::HashSet<u16>,
    std::collections::HashSet<u16>,
) {
    let mut writes = std::collections::HashSet::new();
    let mut reads = std::collections::HashSet::new();
    match stmt {
        Stmt::Assign { dest, value } => {
            writes.insert(dest.index);
            expr_reads(value, &mut reads);
        }
        Stmt::Store { addr, value, .. } => {
            expr_reads(addr, &mut reads);
            expr_reads(value, &mut reads);
        }
        Stmt::Brif { lhs, rhs, .. } => {
            expr_reads(lhs, &mut reads);
            expr_reads(rhs, &mut reads);
        }
        Stmt::Ret { value } => expr_reads(value, &mut reads),
        Stmt::BrIndirect { target } => expr_reads(target, &mut reads),
        Stmt::Call {
            through,
            convention,
            ..
        } => {
            if let Some(through) = through {
                expr_reads(through, &mut reads);
            }
            reads.extend(convention.call_reads());
            writes.extend(convention.clobbered());
        }
        _ => {}
    }
    (writes, reads)
}

pub(crate) fn expr_reads(expr: &Expr, reads: &mut std::collections::HashSet<u16>) {
    match expr {
        Expr::Reg { index, .. } => {
            reads.insert(*index);
        }
        Expr::Const(_) => {}
        _ => {
            for child in children(expr) {
                expr_reads(child, reads);
            }
        }
    }
}

pub(crate) fn assignment_at(
    statements: &[Stmt],
    position: usize,
) -> Option<(crate::ir::RegRef, &Expr)> {
    statements.get(position).and_then(assign_of)
}

pub(crate) fn assign_of(stmt: &Stmt) -> Option<(crate::ir::RegRef, &Expr)> {
    match stmt {
        Stmt::Assign { dest, value } => Some((*dest, value)),
        _ => None,
    }
}

use std::collections::HashMap;

use crate::ir::visit::children;
use crate::ir::visit::unused_temporaries;
use crate::ir::{BinOp, Expr, FunctionIr, Stmt};

#[cfg(test)]
mod tests;

/// Common-subexpression elimination within each statement: a pure subtree
/// repeated in one statement is bound once to a `t<n>` temporary.
pub fn cse(ir: &mut FunctionIr) {
    // Indices no statement or annotation names, so a binding never takes
    // a temporary that is live elsewhere or has a fixed role.
    let temporaries = unused_temporaries(ir);
    for block in &mut ir.blocks {
        for mut stmt in std::mem::take(&mut block.stmts) {
            let mut counts: HashMap<Expr, usize> = HashMap::new();
            count_stmt(&stmt, &mut counts);
            if counts.values().all(|count| *count <= 1) {
                block.stmts.push(stmt);
                continue;
            }

            let mut bound: HashMap<Expr, u16> = HashMap::new();
            let mut available = temporaries.iter().copied();
            let mut pending: Vec<Stmt> = Vec::new();
            let mut share = |value: &mut Expr| {
                let expr = std::mem::replace(value, Expr::Const(0));
                *value = bind(
                    expr,
                    &counts,
                    &mut bound,
                    &mut pending,
                    &mut available,
                    false,
                    0,
                );
            };
            match &mut stmt {
                Stmt::Assign { value, .. } | Stmt::Ret { value, .. } => share(value),
                Stmt::Store { addr, value, .. } => {
                    share(addr);
                    share(value);
                }
                Stmt::Brif { lhs, rhs, .. } => {
                    share(lhs);
                    share(rhs);
                }
                Stmt::BrIndirect { target, .. } | Stmt::Switch { index: target, .. } => {
                    share(target);
                }
                _ => {}
            }
            block.stmts.extend(pending);
            block.stmts.push(stmt);
        }
    }
}

/// Works bottom-up; only subtrees that contain an operator are bound.
/// `conditional` holds inside an arm of a select, which runs only when
/// chosen; `outer` is how often the subtree being bound around `expr`
/// occurs.
fn bind(
    expr: Expr,
    counts: &HashMap<Expr, usize>,
    bound: &mut HashMap<Expr, u16>,
    pending: &mut Vec<Stmt>,
    available: &mut impl Iterator<Item = u16>,
    conditional: bool,
    outer: usize,
) -> Expr {
    let count = counts.get(&expr).copied().unwrap_or(0);
    // A part repeated only as often as the subtree around it is shared
    // through that subtree's temporary.
    let width = if count > 1 && count > outer {
        binding_width(&expr)
    } else {
        None
    };
    // A binding runs before the statement, whichever arm a select chooses.
    let binds = width.is_some() && (!conditional || safe_to_speculate(&expr));
    let enclosing = if binds { count } else { outer };
    let mut inner = |expr: Box<Expr>, conditional| {
        Box::new(bind(
            *expr,
            counts,
            bound,
            pending,
            available,
            conditional,
            enclosing,
        ))
    };
    let rewritten = match expr {
        Expr::Bin { op, lhs, rhs } => Expr::Bin {
            op,
            lhs: inner(lhs, conditional),
            rhs: inner(rhs, conditional),
        },
        Expr::Load {
            addr,
            width,
            signed,
        } => Expr::Load {
            addr: inner(addr, conditional),
            width,
            signed,
        },
        Expr::SignExtend { value, width } => Expr::SignExtend {
            value: inner(value, conditional),
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
            lhs: inner(lhs, conditional),
            rhs: inner(rhs, conditional),
            then: inner(then, true),
            els: inner(els, true),
        },
        Expr::Apply { op, args } => Expr::Apply {
            op,
            args: args
                .into_iter()
                .map(|arg| *inner(Box::new(arg), conditional))
                .collect(),
        },
        other => other,
    };
    let Some(width) = width else {
        return rewritten;
    };
    if let Some(index) = bound.get(&rewritten).copied() {
        return Expr::Reg { index, width };
    }
    if !binds {
        return rewritten;
    }
    let Some(index) = available.next() else {
        return rewritten;
    };
    bound.insert(rewritten.clone(), index);
    pending.push(Stmt::Assign {
        dest: crate::ir::RegRef { index, width },
        value: rewritten,
        at: None,
    });
    Expr::Reg { index, width }
}

/// The width of a temporary for `expr`, when one is worth having: `expr`
/// has an operator, is not a read of a register's low part, which is as
/// cheap as the register, and its value fits the width it is meaningful at.
fn binding_width(expr: &Expr) -> Option<u8> {
    match expr {
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if matches!(lhs.as_ref(), Expr::Reg { .. })
            && matches!(rhs.as_ref(), Expr::Const(0xff | 0xffff | 0xffff_ffff)) =>
        {
            return None;
        }
        Expr::Bin { .. } | Expr::Select { .. } | Expr::SignExtend { .. } | Expr::Apply { .. } => {}
        _ => return None,
    }
    // A constant expression has no width of its own.
    let bits = crate::ir::semantics::width(expr);
    if !(1..=64).contains(&bits) {
        return None;
    }
    // A narrow temporary keeps only its low bits.
    if bits < 64 && crate::ssa::ranges::of(expr).hi > crate::ir::semantics::mask(bits) {
        return None;
    }
    u8::try_from(bits).ok()
}

/// Whether `expr` can be computed where its select does not choose it:
/// integer arithmetic that cannot fault.
fn safe_to_speculate(expr: &Expr) -> bool {
    match expr {
        Expr::Reg { width: 1..=64, .. } | Expr::Const(_) => true,
        Expr::SignExtend {
            width: 1..=8,
            value,
        } => safe_to_speculate(value),
        Expr::Bin {
            op:
                BinOp::Add
                | BinOp::Sub
                | BinOp::Mul
                | BinOp::MulHigh
                | BinOp::MulHighS
                | BinOp::And
                | BinOp::Or
                | BinOp::Xor
                | BinOp::Shl
                | BinOp::Shr
                | BinOp::Sar,
            lhs,
            rhs,
        } => safe_to_speculate(lhs) && safe_to_speculate(rhs),
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => [lhs, rhs, then, els]
            .into_iter()
            .all(|value| safe_to_speculate(value)),
        _ => false,
    }
}

fn count_stmt(stmt: &Stmt, counts: &mut std::collections::HashMap<Expr, usize>) {
    match stmt {
        Stmt::Assign { value, .. } => count_nodes(value, counts),
        Stmt::Store { addr, value, .. } => {
            count_nodes(addr, counts);
            count_nodes(value, counts);
        }
        Stmt::Brif { lhs, rhs, .. } => {
            count_nodes(lhs, counts);
            count_nodes(rhs, counts);
        }
        Stmt::Ret { value, .. } => count_nodes(value, counts),
        Stmt::BrIndirect { target, .. } => count_nodes(target, counts),
        Stmt::Switch { index, .. } => count_nodes(index, counts),
        _ => {}
    }
}

fn count_nodes(expr: &Expr, counts: &mut std::collections::HashMap<Expr, usize>) {
    if load_free(expr) {
        *counts.entry(expr.clone()).or_insert(0) += 1;
    }
    for child in children(expr) {
        count_nodes(child, counts);
    }
}

/// Loads may be volatile, so a subtree that contains one is never shared.
fn load_free(expr: &Expr) -> bool {
    !super::copies::reads_memory(expr)
}

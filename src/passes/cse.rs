use std::collections::HashMap;

use crate::ir::visit::children;
use crate::ir::visit::expr_width;
use crate::ir::{Expr, FunctionIr, Stmt};

/// Common-subexpression elimination within each statement: a pure subtree
/// repeated in one statement is bound once to a `t<n>` temporary.
pub fn cse(ir: &mut FunctionIr) {
    for block in &mut ir.blocks {
        for stmt_index in 0..block.stmts.len() {
            let mut counts: HashMap<Expr, usize> = HashMap::new();
            let snapshot = block.stmts[stmt_index].clone();
            count_stmt(&snapshot, &mut counts);
            if counts.values().all(|count| *count <= 1) {
                continue;
            }

            let mut bound: HashMap<Expr, u16> = HashMap::new();
            let mut next_id = crate::ir::TEMP_BASE;
            let mut pending: Vec<Stmt> = Vec::new();
            let stmt = std::mem::replace(
                &mut block.stmts[stmt_index],
                Stmt::Unsupported {
                    text: String::new(),
                },
            );
            let rewritten = match stmt {
                Stmt::Assign { dest, value } => Stmt::Assign {
                    dest,
                    value: bind(value, &counts, &mut bound, &mut pending, &mut next_id),
                },
                Stmt::Store { addr, value, width } => {
                    let addr = bind(addr, &counts, &mut bound, &mut pending, &mut next_id);
                    let value = bind(value, &counts, &mut bound, &mut pending, &mut next_id);
                    Stmt::Store { addr, value, width }
                }
                Stmt::Brif {
                    cond,
                    lhs,
                    rhs,
                    target,
                } => Stmt::Brif {
                    cond,
                    lhs: bind(lhs, &counts, &mut bound, &mut pending, &mut next_id),
                    rhs: bind(rhs, &counts, &mut bound, &mut pending, &mut next_id),
                    target,
                },
                Stmt::Ret { value } => Stmt::Ret {
                    value: bind(value, &counts, &mut bound, &mut pending, &mut next_id),
                },
                Stmt::BrIndirect { target } => Stmt::BrIndirect {
                    target: bind(target, &counts, &mut bound, &mut pending, &mut next_id),
                },
                Stmt::Switch {
                    index,
                    cases,
                    default,
                } => Stmt::Switch {
                    index: bind(index, &counts, &mut bound, &mut pending, &mut next_id),
                    cases,
                    default,
                },
                other => other,
            };
            block.stmts[stmt_index] = rewritten;
            for (insert_position, definition) in pending.into_iter().enumerate() {
                block.stmts.insert(stmt_index + insert_position, definition);
            }
        }
    }
}

/// Works bottom-up; only subtrees that contain an operator are bound.
fn bind(
    expr: Expr,
    counts: &HashMap<Expr, usize>,
    bound: &mut HashMap<Expr, u16>,
    pending: &mut Vec<Stmt>,
    next_id: &mut u16,
) -> Expr {
    let rewritten = match expr {
        Expr::Bin { op, lhs, rhs } => Expr::Bin {
            op,
            lhs: Box::new(bind(*lhs, counts, bound, pending, next_id)),
            rhs: Box::new(bind(*rhs, counts, bound, pending, next_id)),
        },
        Expr::Load {
            addr,
            width,
            signed,
        } => Expr::Load {
            addr: Box::new(bind(*addr, counts, bound, pending, next_id)),
            width,
            signed,
        },
        Expr::SignExtend { value, width } => Expr::SignExtend {
            value: Box::new(bind(*value, counts, bound, pending, next_id)),
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
            lhs: Box::new(bind(*lhs, counts, bound, pending, next_id)),
            rhs: Box::new(bind(*rhs, counts, bound, pending, next_id)),
            then: Box::new(bind(*then, counts, bound, pending, next_id)),
            els: Box::new(bind(*els, counts, bound, pending, next_id)),
        },
        Expr::Apply { op, args } => Expr::Apply {
            op,
            args: args
                .into_iter()
                .map(|arg| bind(arg, counts, bound, pending, next_id))
                .collect(),
        },
        other => other,
    };

    let operator = matches!(
        rewritten,
        Expr::Bin { .. } | Expr::Select { .. } | Expr::SignExtend { .. } | Expr::Apply { .. }
    );
    // A 32-bit read of a register is as cheap as the register.
    let narrow_read = matches!(
        &rewritten,
        Expr::Bin { op: crate::ir::BinOp::And, lhs, rhs }
            if matches!(lhs.as_ref(), Expr::Reg { .. }) && matches!(rhs.as_ref(), Expr::Const(0xffff_ffff))
    );
    if !operator || narrow_read {
        return rewritten;
    }
    if !load_free(&rewritten) || counts.get(&rewritten).copied().unwrap_or(0) <= 1 {
        return rewritten;
    }
    // The temporary takes its value's width so a 32-bit value stays 32-bit.
    let width = expr_width(&rewritten).unwrap_or(64);
    if let Some(index) = bound.get(&rewritten).copied() {
        return Expr::Reg { index, width };
    }
    let index = *next_id;
    *next_id += 1;
    bound.insert(rewritten.clone(), index);
    pending.push(Stmt::Assign {
        dest: crate::ir::RegRef { index, width },
        value: rewritten,
    });
    Expr::Reg { index, width }
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
        Stmt::Ret { value } => count_nodes(value, counts),
        Stmt::BrIndirect { target } => count_nodes(target, counts),
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
    match expr {
        Expr::Load { .. } => false,
        Expr::Reg { .. } | Expr::Const(_) => true,
        _ => children(expr).into_iter().all(load_free),
    }
}

use std::collections::HashMap;

use crate::ir::{Expr, FunctionIr, Stmt};

/// Propagates constants within a basic block and simplifies expressions.
pub fn simplify(ir: &mut FunctionIr) {
    for block in &mut ir.blocks {
        let mut constants: HashMap<u16, u64> = HashMap::new();
        for stmt in &mut block.stmts {
            simplify_stmt(stmt, &mut constants);
        }
    }
}

fn simplify_stmt(stmt: &mut Stmt, constants: &mut HashMap<u16, u64>) {
    match stmt {
        Stmt::Assign { dest, value } => {
            let simplified = simplify_expr(value.clone(), constants);
            if let Expr::Const(value) = simplified {
                constants.insert(dest.index, value);
            } else {
                constants.remove(&dest.index);
            }
            *value = simplified;
        }
        Stmt::Store { addr, value, .. } => {
            *addr = simplify_expr(addr.clone(), constants);
            *value = simplify_expr(value.clone(), constants);
        }
        Stmt::Brif { lhs, rhs, .. } => {
            *lhs = simplify_expr(lhs.clone(), constants);
            *rhs = simplify_expr(rhs.clone(), constants);
        }
        Stmt::BrIndirect { target } => {
            *target = simplify_expr(target.clone(), constants);
        }
        Stmt::Switch { index, .. } => {
            *index = simplify_expr(index.clone(), constants);
        }
        Stmt::Ret { value } => {
            *value = simplify_expr(value.clone(), constants);
        }
        Stmt::Call { .. } | Stmt::Unsupported { .. } => {
            // Unknown effects may clobber registers.
            constants.clear();
        }
        Stmt::Br { .. } | Stmt::BrifFlags { .. } | Stmt::Trap => {}
    }
}

fn simplify_expr(expr: Expr, constants: &HashMap<u16, u64>) -> Expr {
    match expr {
        Expr::Reg { index, width } => match constants.get(&index) {
            Some(value) => Expr::constant(*value),
            None => Expr::Reg { index, width },
        },
        Expr::Const(_) => expr,
        Expr::Bin { op, lhs, rhs } => fold_offsets(algebraic(Expr::bin(
            op,
            simplify_expr(*lhs, constants),
            simplify_expr(*rhs, constants),
        ))),
        Expr::Load {
            addr,
            width,
            signed,
        } => Expr::Load {
            addr: Box::new(simplify_expr(*addr, constants)),
            width,
            signed,
        },
        Expr::SignExtend { value, width } => {
            let value = simplify_expr(*value, constants);
            // In `(int8_t)(x & 0xff)` the mask repeats the extension's truncation.
            let value = match value {
                Expr::Bin {
                    op: crate::ir::BinOp::And,
                    lhs,
                    rhs,
                } => match rhs.as_ref() {
                    Expr::Const(mask)
                        if *mask == (1u64 << (width.min(8) as u32 * 8)).wrapping_sub(1) =>
                    {
                        lhs.as_ref().clone()
                    }
                    _ => Expr::Bin {
                        op: crate::ir::BinOp::And,
                        lhs,
                        rhs,
                    },
                },
                other => other,
            };
            Expr::SignExtend {
                value: Box::new(value),
                width,
            }
        }
        Expr::Select {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => Expr::Select {
            cond,
            lhs: Box::new(simplify_expr(*lhs, constants)),
            rhs: Box::new(simplify_expr(*rhs, constants)),
            then: Box::new(simplify_expr(*then, constants)),
            els: Box::new(simplify_expr(*els, constants)),
        },
    }
}

/// Removes a double negation and the addition or subtraction of zero.
pub(crate) fn algebraic(expr: Expr) -> Expr {
    let Expr::Bin { op, lhs, rhs } = &expr else {
        return expr;
    };
    let zero = |value: &Expr| matches!(value, Expr::Const(0));
    match op {
        // `0 - (0 - x)`, left behind by the absolute-value and negate shapes.
        crate::ir::BinOp::Sub if zero(lhs) => {
            if let Expr::Bin {
                op: crate::ir::BinOp::Sub,
                lhs: inner,
                rhs: inner_rhs,
            } = rhs.as_ref()
                && zero(inner)
            {
                return inner_rhs.as_ref().clone();
            }
            expr
        }
        crate::ir::BinOp::Sub if zero(rhs) => lhs.as_ref().clone(),
        crate::ir::BinOp::Add if zero(rhs) => lhs.as_ref().clone(),
        _ => expr,
    }
}

/// Reassociates constant offsets so an address reads as one base plus one
/// displacement (`(sp - 0x20) + 8` becomes `sp - 0x18`).
fn fold_offsets(expr: Expr) -> Expr {
    let Expr::Bin { op, lhs, rhs } = expr else {
        return expr;
    };
    let Expr::Const(delta) = rhs.as_ref() else {
        return Expr::Bin { op, lhs, rhs };
    };
    let Expr::Bin {
        op: inner_op,
        lhs: base,
        rhs: inner,
    } = lhs.as_ref()
    else {
        return Expr::Bin { op, lhs, rhs };
    };
    let Expr::Const(offset) = inner.as_ref() else {
        return Expr::Bin { op, lhs, rhs };
    };
    let outer = match op {
        crate::ir::BinOp::Add => *delta,
        crate::ir::BinOp::Sub => delta.wrapping_neg(),
        _ => return Expr::Bin { op, lhs, rhs },
    };
    let total = match inner_op {
        crate::ir::BinOp::Add => offset.wrapping_add(outer),
        crate::ir::BinOp::Sub => offset.wrapping_sub(outer),
        _ => return Expr::Bin { op, lhs, rhs },
    };
    Expr::bin(
        crate::ir::BinOp::Add,
        base.as_ref().clone(),
        Expr::constant(total),
    )
}

#[cfg(test)]
mod tests {
    use super::simplify;
    use crate::ir::{BinOp, Expr, FunctionIr, RegRef, Stmt};
    use crate::loader::Isa;

    #[test]
    fn folds_constant_register_uses() {
        let x10 = RegRef {
            index: 10,
            width: 64,
        };
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                Stmt::Assign {
                    dest: x10,
                    value: Expr::Const(0x5556),
                },
                Stmt::Assign {
                    dest: x10,
                    value: Expr::bin(
                        BinOp::Or,
                        Expr::bin(BinOp::And, Expr::reg(10, 64), Expr::Const(0xffff_ffff)),
                        Expr::Const(0x5555_0000),
                    ),
                },
                Stmt::Ret {
                    value: Expr::reg(10, 64),
                },
            ],
        );

        simplify(&mut ir);

        let rendered = ir.render();
        assert!(rendered.contains("ret #0x55555556"), "{rendered}");
    }
}

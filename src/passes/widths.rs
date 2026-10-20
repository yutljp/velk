use crate::ir::{Expr, FunctionIr, Stmt};

/// Registers read and written only as 32-bit values become 32-bit variables
/// without the lifter's zero-extension masks; returns those registers.
pub fn specialize_widths(ir: &mut FunctionIr) -> std::collections::HashSet<u16> {
    use crate::ir::BinOp;
    use std::collections::{HashMap, HashSet};

    // A write is 32-bit when the lifter wrapped the value in a zero-extension
    // mask; anything else, a call's result included, writes all 64 bits.
    let mut writes: HashMap<u16, Vec<u8>> = HashMap::new();
    for block in &ir.blocks {
        for stmt in &block.stmts {
            if let Stmt::Assign { dest, value } = stmt {
                let width = match value {
                    Expr::Bin {
                        op: BinOp::And,
                        rhs,
                        ..
                    } if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) => 32,
                    _ => 64,
                };
                writes.entry(dest.index).or_default().push(width);
            } else {
                for written in crate::ir::visit::statement_registers(stmt).0 {
                    writes.entry(written).or_default().push(64);
                }
            }
        }
    }

    // A returned register that is only ever written at 32 bits returns its
    // 32-bit view.
    for block in &mut ir.blocks {
        for stmt in &mut block.stmts {
            let Stmt::Ret { value } = stmt else {
                continue;
            };
            let Expr::Reg { index, width: 64 } = value else {
                continue;
            };
            let only_32 = writes.get(index).is_some_and(|widths| {
                !widths.is_empty() && widths.iter().all(|width| *width == 32)
            });
            if only_32 {
                *value = Expr::Reg {
                    index: *index,
                    width: 32,
                };
            }
        }
    }

    // A register under a `& 0xffffffff` mask is a 32-bit read; any other
    // reference reads at its own width.
    let mut reads: HashMap<u16, Vec<u8>> = HashMap::new();
    for block in &mut ir.blocks {
        for stmt in &mut block.stmts {
            map_stmt(stmt, &mut |expr| {
                let expr = expr.clone();
                fn visit(expr: &Expr, reads: &mut HashMap<u16, Vec<u8>>) {
                    match expr {
                        Expr::Const(_) => {}
                        Expr::Reg { index, width } => {
                            reads.entry(*index).or_default().push(*width);
                        }
                        Expr::Bin {
                            op: BinOp::And,
                            lhs,
                            rhs,
                            ..
                        } if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) => match lhs.as_ref()
                        {
                            Expr::Reg { index, .. } => {
                                reads.entry(*index).or_default().push(32);
                            }
                            other => visit(other, reads),
                        },
                        Expr::Bin { lhs, rhs, .. } => {
                            visit(lhs, reads);
                            visit(rhs, reads);
                        }
                        Expr::Load { addr, .. } => visit(addr, reads),
                        Expr::SignExtend { value, .. } => visit(value, reads),
                        Expr::Select {
                            lhs,
                            rhs,
                            then,
                            els,
                            ..
                        } => {
                            visit(lhs, reads);
                            visit(rhs, reads);
                            visit(then, reads);
                            visit(els, reads);
                        }
                        Expr::Apply { args, .. } => {
                            for arg in args {
                                visit(arg, reads);
                            }
                        }
                    }
                }
                visit(&expr, &mut reads);
                expr
            });
        }
    }

    let uniform: HashSet<u16> = (0..u16::MAX)
        .filter(|index| {
            let read_all_32 = reads
                .get(index)
                .is_none_or(|widths| widths.iter().all(|width| *width == 32));
            let write_all_32 = writes
                .get(index)
                .is_none_or(|widths| widths.iter().all(|width| *width == 32));
            (reads.contains_key(index) || writes.contains_key(index)) && read_all_32 && write_all_32
        })
        .collect();

    for block in &mut ir.blocks {
        for stmt in &mut block.stmts {
            map_stmt(stmt, &mut |expr| rewrite_read_masks(expr, &uniform));
            if let Stmt::Assign { dest, value } = stmt
                && uniform.contains(&dest.index)
            {
                dest.width = 32;
                if let Expr::Bin {
                    op: BinOp::And,
                    lhs,
                    rhs,
                } = value
                    && matches!(rhs.as_ref(), Expr::Const(0xffff_ffff))
                {
                    *value = (**lhs).clone();
                }
            }
        }
    }

    uniform
}

fn rewrite_read_masks(expr: &Expr, uniform: &std::collections::HashSet<u16>) -> Expr {
    use crate::ir::BinOp;

    if let Expr::Bin {
        op: BinOp::And,
        lhs,
        rhs,
    } = expr
        && matches!(rhs.as_ref(), Expr::Const(0xffff_ffff))
        && let Expr::Reg { index, .. } = lhs.as_ref()
        && uniform.contains(index)
    {
        return Expr::Reg {
            index: *index,
            width: 32,
        };
    }
    match expr {
        Expr::Bin { op, lhs, rhs } => Expr::bin(
            *op,
            rewrite_read_masks(lhs, uniform),
            rewrite_read_masks(rhs, uniform),
        ),
        Expr::Load {
            addr,
            width,
            signed,
        } => Expr::Load {
            addr: Box::new(rewrite_read_masks(addr, uniform)),
            width: *width,
            signed: *signed,
        },
        Expr::SignExtend { value, width } => Expr::SignExtend {
            value: Box::new(rewrite_read_masks(value, uniform)),
            width: *width,
        },
        Expr::Select {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => Expr::Select {
            cond: *cond,
            lhs: Box::new(rewrite_read_masks(lhs, uniform)),
            rhs: Box::new(rewrite_read_masks(rhs, uniform)),
            then: Box::new(rewrite_read_masks(then, uniform)),
            els: Box::new(rewrite_read_masks(els, uniform)),
        },
        Expr::Apply { op, args } => Expr::Apply {
            op: *op,
            args: args
                .iter()
                .map(|arg| rewrite_read_masks(arg, uniform))
                .collect(),
        },
        other => other.clone(),
    }
}

fn map_stmt(stmt: &mut Stmt, map: &mut dyn FnMut(&Expr) -> Expr) {
    match stmt {
        Stmt::Assign { value, .. } => *value = map(&*value),
        Stmt::Store { addr, value, .. } => {
            *addr = map(&*addr);
            *value = map(&*value);
        }
        Stmt::Brif { lhs, rhs, .. } => {
            *lhs = map(&*lhs);
            *rhs = map(&*rhs);
        }
        Stmt::Ret { value } => *value = map(&*value),
        Stmt::BrIndirect { target } => *target = map(&*target),
        Stmt::Switch { index, .. } => *index = map(&*index),
        Stmt::Call { through, args, .. } => {
            for value in through.iter_mut().chain(args.iter_mut().flatten()) {
                *value = map(&*value);
            }
        }
        _ => {}
    }
}

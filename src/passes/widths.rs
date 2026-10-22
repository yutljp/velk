use std::collections::HashMap;

use crate::ir::{Block, Expr, FunctionIr, Stmt};

/// Whether the function at an address returns only 32-bit values.
pub type NarrowReturn<'a> = &'a dyn Fn(u64) -> bool;

/// The widths each register is written at. A write is 32-bit when the
/// lifter wrapped the value in a zero-extension mask, or when it is the
/// result of a call to a function returning 32 bits; a constant that fits
/// in 32 bits is width 0, as wide as whatever else the register holds;
/// anything else writes all 64 bits.
fn register_writes(blocks: &[Block], narrow_return: NarrowReturn<'_>) -> HashMap<u16, Vec<u8>> {
    use crate::ir::BinOp;

    let mut writes: HashMap<u16, Vec<u8>> = HashMap::new();
    for block in blocks {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Assign { dest, value } => {
                    let width = match value {
                        Expr::Bin {
                            op: BinOp::And,
                            rhs,
                            ..
                        } if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) => 32,
                        Expr::Const(value) if *value <= 0xffff_ffff => 0,
                        _ => 64,
                    };
                    writes.entry(dest.index).or_default().push(width);
                }
                Stmt::Call { target, .. } => {
                    let narrow = target.is_some_and(narrow_return);
                    let returned = stmt.primary_call_output().map(|output| output.dest.index);
                    for written in crate::ir::visit::statement_registers(stmt).0 {
                        let width = if narrow && Some(written) == returned {
                            32
                        } else {
                            64
                        };
                        writes.entry(written).or_default().push(width);
                    }
                }
                _ => {
                    for written in crate::ir::visit::statement_registers(stmt).0 {
                        writes.entry(written).or_default().push(64);
                    }
                }
            }
        }
    }
    writes
}

fn only_32(writes: &HashMap<u16, Vec<u8>>, register: u16) -> bool {
    writes
        .get(&register)
        .is_some_and(|widths| !widths.is_empty() && widths.iter().all(|width| *width == 32))
}

/// Whether every return of the lifted `blocks` returns a register written
/// at 32 bits, and otherwise only with constants that fit, so the function
/// returns 32-bit values.
pub fn returns_32(blocks: &[Block], narrow_return: NarrowReturn<'_>) -> bool {
    let writes = register_writes(blocks, narrow_return);
    let mut returns = blocks
        .iter()
        .filter_map(|block| match block.stmts.last() {
            Some(Stmt::Ret { value }) => Some(value),
            _ => None,
        })
        .peekable();
    returns.peek().is_some()
        && returns.all(|value| {
            let Expr::Reg { index, width: 64 } = value else {
                return false;
            };
            writes.get(index).is_some_and(|widths| {
                widths.contains(&32) && widths.iter().all(|width| *width <= 32)
            })
        })
}

/// Registers read and written only as 32-bit values become 32-bit variables
/// without the lifter's zero-extension masks; returns those registers.
pub fn specialize_widths(
    ir: &mut FunctionIr,
    narrow_return: NarrowReturn<'_>,
) -> std::collections::HashSet<u16> {
    use crate::ir::BinOp;
    use std::collections::HashSet;

    let writes = register_writes(&ir.blocks, narrow_return);

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
            if only_32(&writes, *index) {
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
            for dest in crate::ir::visit::statement_destinations_mut(stmt) {
                if uniform.contains(&dest.index) {
                    dest.width = 32;
                }
            }
            if let Stmt::Assign { dest, value } = stmt
                && uniform.contains(&dest.index)
                && let Expr::Bin {
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

#[cfg(test)]
mod tests {
    use super::{register_writes, returns_32, specialize_widths};
    use crate::ir::{Block, Convention, Expr, FunctionIr, Operation, Stmt, VARIABLE_BASE};
    use crate::loader::Isa;

    fn two_outputs() -> Stmt {
        let mut outputs = crate::ir::fallback_call_outputs(
            Convention::Aapcs64,
            Some([0, 1].into_iter().collect()),
        );
        for (index, output) in outputs.iter_mut().enumerate() {
            output.dest.index = VARIABLE_BASE + index as u16;
        }
        outputs.reverse();
        Stmt::Call {
            target: Some(0x1000),
            through: None,
            convention: Convention::Aapcs64,
            args: Some(Vec::new()),
            floats_named: true,
            clobbers: Some([0, 1].into_iter().collect()),
            outputs,
            via: None,
        }
    }

    #[test]
    fn narrow_call_return_applies_only_to_primary_provenance() {
        let blocks = vec![Block {
            start: 0,
            stmts: vec![two_outputs()],
        }];
        let writes = register_writes(&blocks, &|_| true);
        assert_eq!(writes[&VARIABLE_BASE], [32]);
        assert_eq!(writes[&(VARIABLE_BASE + 1)], [64]);
        assert!(!writes.contains_key(&0));
        assert!(!writes.contains_key(&1));
    }

    #[test]
    fn a_secondary_only_call_is_not_a_narrow_primary() {
        let mut call = two_outputs();
        if let Stmt::Call { outputs, .. } = &mut call {
            outputs.retain(|output| output.register == 1);
        }
        let blocks = vec![Block {
            start: 0,
            stmts: vec![
                call,
                Stmt::Ret {
                    value: Expr::reg(VARIABLE_BASE + 1, 64),
                },
            ],
        }];
        assert!(!returns_32(&blocks, &|_| true));
    }

    #[test]
    fn specializing_a_primary_keeps_secondary_bits_and_provenance() {
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                two_outputs(),
                Stmt::Ret {
                    value: Expr::Apply {
                        op: Operation::Results,
                        args: vec![
                            Expr::bin(
                                crate::ir::BinOp::And,
                                Expr::reg(VARIABLE_BASE, 64),
                                Expr::Const(0xffff_ffff),
                            ),
                            Expr::reg(VARIABLE_BASE + 1, 64),
                        ],
                    },
                },
            ],
        );
        let uniform = specialize_widths(&mut ir, &|_| true);
        assert!(uniform.contains(&VARIABLE_BASE));
        assert!(!uniform.contains(&(VARIABLE_BASE + 1)));
        let outputs = ir.blocks[0].stmts[0].call_outputs();
        assert_eq!(
            outputs
                .iter()
                .map(|output| (output.register, output.dest.index, output.dest.width))
                .collect::<Vec<_>>(),
            [(1, VARIABLE_BASE + 1, 64), (0, VARIABLE_BASE, 32),]
        );
    }
}

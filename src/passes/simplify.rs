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
        Stmt::Brif { cond, lhs, rhs, .. } => {
            *lhs = simplify_expr(lhs.clone(), constants);
            *rhs = simplify_expr(rhs.clone(), constants);
            if let Some(width) =
                crate::ir::visit::expr_width(lhs).or_else(|| crate::ir::visit::expr_width(rhs))
            {
                cancel_round_trip(lhs, width);
                cancel_round_trip(rhs, width);
            }
            if matches!(cond, crate::ir::Cond::Eq | crate::ir::Cond::Ne) {
                move_offset_across(lhs, rhs);
            }
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

/// `other` when `kept` is `r & keep` and `keep` shares no bit with `mask`.
fn outside_mask<'e>(kept: &Expr, other: &'e Expr, mask: u64) -> Option<&'e Expr> {
    match kept {
        Expr::Bin {
            op: crate::ir::BinOp::And,
            rhs,
            ..
        } if matches!(rhs.as_ref(), Expr::Const(keep) if keep & mask == 0) => Some(other),
        _ => None,
    }
}

/// In a compare at `width` bits, `(a - b) + b` and `(a + b) - b` are `a`; a
/// 32-bit mask on the inner result changes nothing at 32 bits.
fn cancel_round_trip(expr: &mut Expr, width: u8) {
    use crate::ir::BinOp;
    let Expr::Bin { op, lhs, rhs } = &*expr else {
        return;
    };
    let inverse = match op {
        BinOp::Add => BinOp::Sub,
        BinOp::Sub => BinOp::Add,
        _ => return,
    };
    let mut inner = lhs.as_ref();
    if width <= 32
        && let Expr::Bin {
            op: BinOp::And,
            lhs: masked,
            rhs: mask,
        } = inner
        && matches!(mask.as_ref(), Expr::Const(0xffff_ffff))
    {
        inner = masked;
    }
    if let Expr::Bin {
        op: inner_op,
        lhs: original,
        rhs: offset,
    } = inner
        && *inner_op == inverse
        && offset == rhs
    {
        *expr = original.as_ref().clone();
    }
}

/// `x + c == k` is `x == k - c` at the width of `x`, as is `x - c == k`
/// with `k + c`.
fn move_offset_across(lhs: &mut Expr, rhs: &mut Expr) {
    let (
        Expr::Bin {
            op,
            lhs: inner,
            rhs: offset,
        },
        Expr::Const(k),
    ) = (&*lhs, &*rhs)
    else {
        return;
    };
    let Expr::Const(c) = offset.as_ref() else {
        return;
    };
    let moved = match op {
        crate::ir::BinOp::Add => k.wrapping_sub(*c),
        crate::ir::BinOp::Sub => k.wrapping_add(*c),
        _ => return,
    };
    let Some(width) = crate::ir::visit::expr_width(inner) else {
        return;
    };
    let mask = if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    };
    *rhs = Expr::Const(moved & mask);
    *lhs = inner.as_ref().clone();
}

fn simplify_expr(expr: Expr, constants: &HashMap<u16, u64>) -> Expr {
    match expr {
        Expr::Reg { index, width } => match constants.get(&index) {
            Some(value) if width >= 64 => Expr::constant(*value),
            Some(value) => Expr::constant(*value & ((1u64 << width) - 1)),
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
        // `((r & keep) | v) & mask` with `keep & mask == 0` is `v & mask`:
        // the kept bits of a partial register write fall outside the mask.
        crate::ir::BinOp::And
            if let Expr::Const(mask) = rhs.as_ref()
                && let Expr::Bin {
                    op: crate::ir::BinOp::Or,
                    lhs: a,
                    rhs: b,
                } = lhs.as_ref()
                && let Some(value) =
                    outside_mask(a, b, *mask).or_else(|| outside_mask(b, a, *mask)) =>
        {
            Expr::bin(crate::ir::BinOp::And, value.clone(), Expr::Const(*mask))
        }
        // The low 32 bits of a sum, difference, product or bitwise operation
        // depend only on the low 32 bits of its operands.
        crate::ir::BinOp::And if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) => {
            let Expr::Bin {
                op: inner,
                lhs: a,
                rhs: b,
            } = lhs.as_ref()
            else {
                return expr;
            };
            use crate::ir::BinOp;
            if !matches!(
                inner,
                BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::And | BinOp::Or | BinOp::Xor
            ) {
                return expr;
            }
            // A masked register stays: it reads as the 32-bit register.
            let low = |operand: &Expr| match operand {
                Expr::Bin {
                    op: BinOp::And,
                    lhs,
                    rhs,
                } if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff))
                    && !matches!(lhs.as_ref(), Expr::Reg { .. }) =>
                {
                    lhs.as_ref().clone()
                }
                other => other.clone(),
            };
            Expr::bin(
                BinOp::And,
                Expr::bin(*inner, low(a), low(b)),
                Expr::Const(0xffff_ffff),
            )
        }
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
        crate::ir::BinOp::Sub => outer.wrapping_sub(*offset),
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
    fn a_mask_drops_the_bits_a_partial_write_kept() {
        // ((rcx & ~0xff) | v) & 0xff is v & 0xff.
        let value = Expr::bin(BinOp::And, Expr::reg(7, 64), Expr::Const(0xff));
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![Stmt::Ret {
                value: Expr::bin(
                    BinOp::And,
                    Expr::bin(
                        BinOp::Or,
                        Expr::bin(BinOp::And, Expr::reg(1, 64), Expr::Const(!0xff)),
                        value.clone(),
                    ),
                    Expr::Const(0xff),
                ),
            }],
        );

        simplify(&mut ir);

        let Stmt::Ret { value: simplified } = &ir.blocks[0].stmts[0] else {
            panic!("the return stays");
        };
        let mut reads = std::collections::HashSet::new();
        crate::ir::visit::collect_reads(simplified, &mut reads);
        assert!(!reads.contains(&1), "{}", ir.render());
    }

    #[test]
    fn folds_an_offset_from_a_subtracted_base() {
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![Stmt::Ret {
                value: Expr::bin(
                    BinOp::Add,
                    Expr::bin(BinOp::Sub, Expr::reg(31, 64), Expr::Const(0x20)),
                    Expr::Const(8),
                ),
            }],
        );

        simplify(&mut ir);

        let Stmt::Ret { value } = &ir.blocks[0].stmts[0] else {
            panic!("the return stays");
        };
        let expected = Expr::bin(
            BinOp::Add,
            Expr::reg(31, 64),
            Expr::Const(0x18u64.wrapping_neg()),
        );
        assert_eq!(*value, expected, "{}", ir.render());
    }

    #[test]
    fn a_narrow_read_of_a_constant_keeps_its_low_bits() {
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: 8,
                        width: 64,
                    },
                    value: Expr::Const(0x1_0000_0001),
                },
                Stmt::Ret {
                    value: Expr::reg(8, 32),
                },
            ],
        );

        simplify(&mut ir);

        assert!(
            matches!(
                ir.blocks[0].stmts[1],
                Stmt::Ret {
                    value: Expr::Const(1)
                }
            ),
            "{}",
            ir.render()
        );
    }

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

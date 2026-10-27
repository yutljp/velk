use crate::ir::Expr;
use crate::ir::visit::assignment;
use crate::passes::division::divisor::magic_divisor_signed64;
use crate::passes::division::leaf_domain;
use crate::passes::memory::strip_mask;

/// A constant the widening multiply may have sign-extended.
fn signed_const(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Const(value) => Some(*value),
        Expr::SignExtend { value, width: 4 } => match value.as_ref() {
            Expr::Const(value) => Some(*value & 0xffff_ffff),
            _ => None,
        },
        _ => None,
    }
}

fn definition_before(stmts: &[crate::ir::Stmt], before: usize, reg: u16) -> Option<usize> {
    (0..before).rev().find(|index| {
        matches!(
            &stmts[*index],
            crate::ir::Stmt::Assign { dest, .. } if dest.index == reg
        )
    })
}

/// The register a masked read looks at.
fn view_base(expr: &Expr) -> Option<u16> {
    match strip_mask(expr) {
        Expr::Reg { index, .. } => Some(*index),
        _ => None,
    }
}

/// `reg >> k` (logical or arithmetic, possibly masked) as `(reg, k)`.
fn inline_shift(expr: &Expr) -> Option<(u16, u64)> {
    let Expr::Bin { op, lhs, rhs } = strip_mask(expr) else {
        return None;
    };
    if !matches!(op, crate::ir::BinOp::Shr | crate::ir::BinOp::Sar) {
        return None;
    }
    let Expr::Const(amount) = rhs.as_ref() else {
        return None;
    };
    Some((view_base(lhs)?, *amount))
}

/// The `(statement, dividend, divisor)` of the widened signed division, if the
/// block holds one.
pub(crate) fn widened_signed_site(stmts: &[crate::ir::Stmt]) -> Option<(usize, Expr, u64)> {
    for probe in 0..stmts.len() {
        let crate::ir::Stmt::Assign { value, .. } = &stmts[probe] else {
            continue;
        };
        let Expr::Bin {
            op: crate::ir::BinOp::Add,
            lhs,
            rhs,
        } = value
        else {
            continue;
        };
        // Each side is `x >> k`, inline or through a register defined by a
        // shift statement.
        let term = |expr: &Expr| -> Option<(u16, u64)> {
            if let Some(found) = inline_shift(expr) {
                return Some(found);
            }
            let reg = view_base(expr)?;
            let at = definition_before(stmts, probe, reg)?;
            shift_statement(&stmts[at])
        };
        let (left, right) = (term(lhs), term(rhs));
        // Case A: the high half and the sign term of one product.
        if let (Some((left_source, left_amount)), Some((right_source, right_amount))) =
            (left, right)
            && left_source == right_source
            && (left_amount == 63 || right_amount == 63)
            && left_amount != right_amount
        {
            let high = if left_amount == 63 {
                right_amount
            } else {
                left_amount
            };
            if high >= 32
                && let Some(found) = widened_product(stmts, probe, left_source, high)
                && super::proof::equivalent(
                    stmts,
                    probe,
                    &super::division(found.0.clone(), found.1),
                )
            {
                return Some((probe, found.0, found.1));
            }
        }
        // Case B: `v + (v >> 31)`, the sign of the truncated high half.
        let narrow = |plain: &Expr, shifted: &Expr| -> Option<(u16, u64, usize)> {
            let (shifted_reg, amount) = inline_shift(shifted)?;
            if amount != 31 || view_base(plain)? != shifted_reg {
                return None;
            }
            let view_at = definition_before(stmts, probe, shifted_reg)?;
            let (_, view) = assignment(&stmts[view_at])?;
            let base = view_base(view).unwrap_or(shifted_reg);
            let high_at = definition_before(stmts, view_at, base)?;
            let (source, high) = shift_statement(&stmts[high_at])?;
            (high >= 32).then_some((source, high, high_at))
        };
        let narrow_hit = narrow(lhs, rhs).or_else(|| narrow(rhs, lhs));
        if let Some((source, high, high_at)) = narrow_hit
            && let Some(found) = widened_product(stmts, high_at, source, high)
            && super::proof::equivalent(stmts, probe, &super::division(found.0.clone(), found.1))
        {
            return Some((probe, found.0, found.1));
        }
    }
    None
}

/// The dividend and divisor of the product the shifts read.
fn widened_product(
    stmts: &[crate::ir::Stmt],
    before: usize,
    source: u16,
    shift: u64,
) -> Option<(Expr, u64)> {
    let product_at = definition_before(stmts, before, source)?;
    let (_, product) = assignment(&stmts[product_at])?;
    let (leaf, magic, _) = magic_product(strip_mask(product))?;
    let divisor = magic_divisor_signed64(magic, shift, 32)?;
    Some((leaf, divisor))
}

fn shift_statement(stmt: &crate::ir::Stmt) -> Option<(u16, u64)> {
    let crate::ir::Stmt::Assign { value, .. } = stmt else {
        return None;
    };
    let Expr::Bin { op, lhs, rhs } = value else {
        return None;
    };
    if !matches!(op, crate::ir::BinOp::Shr | crate::ir::BinOp::Sar) {
        return None;
    }
    let Expr::Const(amount) = rhs.as_ref() else {
        return None;
    };
    Some((view_base(lhs)?, *amount))
}

pub(crate) fn magic_product(value: &Expr) -> Option<(Expr, u64, u64)> {
    let Expr::Bin {
        op: product_op,
        lhs,
        rhs,
    } = value
    else {
        return None;
    };
    if !matches!(
        product_op,
        crate::ir::BinOp::Mul | crate::ir::BinOp::MulHigh | crate::ir::BinOp::MulHighS
    ) {
        return None;
    }
    // The compiler may emit either operand order, and a widening multiply
    // sign-extends the constant it multiplies by.
    let (leaf, magic_operand) = if signed_const(rhs).is_some() {
        (lhs.as_ref(), rhs.as_ref())
    } else if signed_const(lhs).is_some() {
        (rhs.as_ref(), lhs.as_ref())
    } else {
        return None;
    };
    let Some(magic) = signed_const(magic_operand) else {
        return None;
    };
    let high_part = matches!(
        product_op,
        crate::ir::BinOp::MulHigh | crate::ir::BinOp::MulHighS
    );
    let magic_cap = if high_part { u64::MAX } else { 0xffff_ffff };
    if magic == 0 || magic > magic_cap {
        return None;
    }
    let Some(domain_bits) = leaf_domain(leaf) else {
        return None;
    };
    let Some(operand) = leaf_operand(leaf) else {
        return None;
    };
    Some((operand, magic, domain_bits))
}

/// The dividend expression: a masked or sign-extended 64-bit register becomes
/// its 32-bit register so the division renders without the extension.
fn leaf_operand(expr: &Expr) -> Option<Expr> {
    match expr {
        Expr::Reg { width, .. } if *width == 32 || *width == 64 => Some(expr.clone()),
        Expr::SignExtend { width: 4, value } => match value.as_ref() {
            Expr::Reg { index, .. } => Some(Expr::Reg {
                index: *index,
                width: 32,
            }),
            other => leaf_operand(other),
        },
        Expr::SignExtend { .. } => Some(expr.clone()),
        Expr::Bin {
            op: crate::ir::BinOp::And,
            lhs,
            rhs,
        } => {
            let Expr::Const(0xffff_ffff) = rhs.as_ref() else {
                return None;
            };
            match &**lhs {
                Expr::Reg { index, .. } => Some(Expr::Reg {
                    index: *index,
                    width: 32,
                }),
                _ => None,
            }
        }
        _ => None,
    }
}

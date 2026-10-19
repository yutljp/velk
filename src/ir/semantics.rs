//! The meaning of the IR's operations where it depends on width: an
//! operand's width comes from its expression, and signed operations and
//! comparisons act at the wider of their operands' widths, as the
//! instruction they came from did.

use super::{BinOp, Cond, Expr};

pub(crate) fn mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

pub(crate) fn sign_extend(value: u64, bits: u32) -> i64 {
    if bits >= 64 {
        value as i64
    } else {
        let shift = 64 - bits;
        ((value << shift) as i64) >> shift
    }
}

/// The width, in bits, at which an expression's value is meaningful; 0 for a constant.
pub(crate) fn width(expr: &Expr) -> u32 {
    match expr {
        Expr::Reg { width, .. } => u32::from(*width),
        Expr::Const(_) => 0,
        Expr::Load { width, signed, .. } => {
            if *signed {
                64
            } else {
                u32::from(*width) * 8
            }
        }
        Expr::SignExtend { .. } => 64,
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } => match rhs.as_ref() {
            // A mask the width of a register reads that register's low part;
            // any other mask leaves the operation as wide as its operand, so
            // `x & 7` is not a 3-bit value whose top bit is a sign.
            Expr::Const(value @ (0xff | 0xffff | 0xffff_ffff)) => value.count_ones(),
            _ => width(lhs).max(width(rhs)),
        },
        Expr::Bin { lhs, rhs, .. } => width(lhs).max(width(rhs)),
        Expr::Select { then, els, .. } => width(then).max(width(els)),
    }
}

pub(crate) fn operand_width(lhs: &Expr, rhs: &Expr) -> u32 {
    match width(lhs).max(width(rhs)) {
        0 => 64,
        bits => bits,
    }
}

pub(crate) fn holds(cond: Cond, a: u64, b: u64, bits: u32) -> bool {
    let (a, b) = (a & mask(bits), b & mask(bits));
    let (sa, sb) = (sign_extend(a, bits), sign_extend(b, bits));
    let difference = a.wrapping_sub(b) & mask(bits);
    let negative = sign_extend(difference, bits) < 0;
    let overflow = ((a ^ b) & (a ^ difference)) >> (bits - 1) & 1 == 1;
    match cond {
        Cond::Eq => a == b,
        Cond::Ne => a != b,
        Cond::Cs => a >= b,
        Cond::Cc => a < b,
        Cond::Hi => a > b,
        Cond::Ls => a <= b,
        Cond::Ge => sa >= sb,
        Cond::Lt => sa < sb,
        Cond::Gt => sa > sb,
        Cond::Le => sa <= sb,
        Cond::Mi => negative,
        Cond::Pl => !negative,
        Cond::Vs => overflow,
        Cond::Vc => !overflow,
    }
}

/// The value of an expression whose registers `register` gives, or None
/// when it reads memory, an unknown register, or divides by zero.
pub(crate) fn evaluate(expr: &Expr, register: &dyn Fn(u16) -> Option<u64>) -> Option<u64> {
    Some(match expr {
        Expr::Reg { index, width } => register(*index)? & mask(u32::from(*width)),
        Expr::Const(value) => *value,
        Expr::Load { .. } => return None,
        Expr::SignExtend { value, width } => {
            sign_extend(evaluate(value, register)?, u32::from(*width) * 8) as u64
        }
        Expr::Select {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => {
            let bits = operand_width(lhs, rhs);
            if holds(
                *cond,
                evaluate(lhs, register)?,
                evaluate(rhs, register)?,
                bits,
            ) {
                evaluate(then, register)?
            } else {
                evaluate(els, register)?
            }
        }
        Expr::Bin { op, lhs, rhs } => {
            let (a, b) = (evaluate(lhs, register)?, evaluate(rhs, register)?);
            let bits = operand_width(lhs, rhs);
            match op {
                BinOp::Add => a.wrapping_add(b),
                BinOp::Sub => a.wrapping_sub(b),
                BinOp::Mul => a.wrapping_mul(b),
                BinOp::MulHigh => ((u128::from(a) * u128::from(b)) >> 64) as u64,
                BinOp::MulHighS => ((i128::from(a as i64) * i128::from(b as i64)) >> 64) as u64,
                BinOp::And => a & b,
                BinOp::Or => a | b,
                BinOp::Xor => a ^ b,
                BinOp::Shl => a.wrapping_shl(b as u32),
                BinOp::Shr => a.wrapping_shr(b as u32),
                BinOp::Sar => (sign_extend(a, bits).wrapping_shr(b as u32) as u64) & mask(bits),
                BinOp::DivU | BinOp::ModU if b == 0 => return None,
                BinOp::DivU => a / b,
                BinOp::ModU => a % b,
                BinOp::DivS | BinOp::ModS => {
                    let (sa, sb) = (sign_extend(a, bits), sign_extend(b, bits));
                    if sb == 0 {
                        return None;
                    }
                    let result = if *op == BinOp::DivS {
                        sa.wrapping_div(sb)
                    } else {
                        sa.wrapping_rem(sb)
                    };
                    result as u64 & mask(bits)
                }
            }
        }
    })
}

//! The meaning of the IR's operations where it depends on width: an
//! operand's width comes from its expression, and signed operations and
//! comparisons act at the wider of their operands' widths, as the
//! instruction they came from did.

use super::{BinOp, Cond, Expr, Operation, Precision};

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
        Expr::Apply { op, args } => match op {
            _ if let Some(precision) = op.result_precision() => u32::from(precision.bits()),
            Operation::FloatToInt { bits, .. } => u32::from(*bits),
            Operation::ReverseBits(bits) => u32::from(*bits),
            // A truth value or a count is small and never negative.
            _ => args.first().map_or(64, width).max(1),
        },
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
        Expr::Apply { op, args } => {
            let values = args
                .iter()
                .map(|arg| evaluate(arg, register))
                .collect::<Option<Vec<u64>>>()?;
            apply(*op, &values)
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

/// `op` on constant arguments, unless the result is a NaN, whose bit pattern
/// the processor running velk would choose.
pub(crate) fn fold(op: Operation, args: &[u64]) -> Option<u64> {
    let value = apply(op, args);
    let nan = match op {
        Operation::FloatAdd(p)
        | Operation::FloatSub(p)
        | Operation::FloatMul(p)
        | Operation::FloatDiv(p)
        | Operation::FloatSqrt(p)
        | Operation::FloatMulAdd(p)
        | Operation::FloatConvert { to: p, .. } => match p {
            Precision::Double => f64::from_bits(value).is_nan(),
            Precision::Single => f32::from_bits(value as u32).is_nan(),
        },
        _ => false,
    };
    (!nan).then_some(value)
}

/// How many low bits of each argument `op` reads.
pub(crate) fn argument_bits(op: Operation) -> u32 {
    u32::from(match op {
        Operation::FloatAdd(p)
        | Operation::FloatSub(p)
        | Operation::FloatMul(p)
        | Operation::FloatDiv(p)
        | Operation::FloatSqrt(p)
        | Operation::FloatNegate(p)
        | Operation::FloatAbs(p)
        | Operation::FloatMulAdd(p)
        | Operation::FloatEqual(p)
        | Operation::FloatLess(p)
        | Operation::FloatLessEqual(p)
        | Operation::FloatUnordered(p)
        | Operation::FloatToInt { from: p, .. }
        | Operation::FloatConvert { from: p, .. } => p.bits(),
        Operation::IntToFloat { bits, .. }
        | Operation::CountLeadingZeros(bits)
        | Operation::CountTrailingZeros(bits)
        | Operation::PopCount(bits)
        | Operation::ReverseBits(bits) => bits,
    })
}

/// The value of `op` on `args`, which hold floats as bit patterns.
pub(crate) fn apply(op: Operation, args: &[u64]) -> u64 {
    let single = |bits: u64| f32::from_bits(bits as u32);
    let double = f64::from_bits;
    let arithmetic =
        |precision: Precision, f: fn(f64, f64) -> f64, g: fn(f32, f32) -> f32| match precision {
            Precision::Double => f(double(args[0]), double(args[1])).to_bits(),
            Precision::Single => u64::from(g(single(args[0]), single(args[1])).to_bits()),
        };
    let compare = |precision: Precision, f: fn(f64, f64) -> bool| {
        // Widening a single is exact, so comparing as doubles decides the same.
        let (a, b) = match precision {
            Precision::Double => (double(args[0]), double(args[1])),
            Precision::Single => (f64::from(single(args[0])), f64::from(single(args[1]))),
        };
        u64::from(f(a, b))
    };
    let float = |precision: Precision, value: u64| match precision {
        Precision::Double => double(value),
        Precision::Single => f64::from(single(value)),
    };
    match op {
        Operation::FloatAdd(p) => arithmetic(p, |a, b| a + b, |a, b| a + b),
        Operation::FloatSub(p) => arithmetic(p, |a, b| a - b, |a, b| a - b),
        Operation::FloatMul(p) => arithmetic(p, |a, b| a * b, |a, b| a * b),
        Operation::FloatDiv(p) => arithmetic(p, |a, b| a / b, |a, b| a / b),
        Operation::FloatNegate(Precision::Double) => args[0] ^ (1 << 63),
        Operation::FloatNegate(Precision::Single) => (args[0] ^ (1 << 31)) & mask(32),
        Operation::FloatAbs(Precision::Double) => args[0] & !(1 << 63),
        Operation::FloatAbs(Precision::Single) => args[0] & mask(31),
        Operation::FloatSqrt(Precision::Double) => double(args[0]).sqrt().to_bits(),
        Operation::FloatSqrt(Precision::Single) => u64::from(single(args[0]).sqrt().to_bits()),
        Operation::FloatMulAdd(Precision::Double) => double(args[0])
            .mul_add(double(args[1]), double(args[2]))
            .to_bits(),
        Operation::FloatMulAdd(Precision::Single) => u64::from(
            single(args[0])
                .mul_add(single(args[1]), single(args[2]))
                .to_bits(),
        ),
        Operation::FloatEqual(p) => compare(p, |a, b| a == b),
        Operation::FloatLess(p) => compare(p, |a, b| a < b),
        Operation::FloatLessEqual(p) => compare(p, |a, b| a <= b),
        Operation::FloatUnordered(p) => compare(p, |a, b| a.is_nan() || b.is_nan()),
        Operation::IntToFloat { signed, bits, to } => {
            let value = args[0] & mask(u32::from(bits));
            match (signed, to) {
                (true, Precision::Double) => (sign_extend(value, u32::from(bits)) as f64).to_bits(),
                (false, Precision::Double) => (value as f64).to_bits(),
                (true, Precision::Single) => {
                    u64::from((sign_extend(value, u32::from(bits)) as f32).to_bits())
                }
                (false, Precision::Single) => u64::from((value as f32).to_bits()),
            }
        }
        Operation::FloatToInt {
            signed,
            bits,
            from,
            saturating,
        } => {
            let value = float(from, args[0]);
            let bits = u32::from(bits);
            let (low, high) = if signed {
                (-(2f64.powi(bits as i32 - 1)), 2f64.powi(bits as i32 - 1))
            } else {
                (0.0, 2f64.powi(bits as i32))
            };
            let truncated = value.trunc();
            let result = if value.is_nan() {
                if saturating { 0 } else { 1u64 << (bits - 1) }
            } else if truncated < low || truncated >= high {
                match (saturating, truncated < low) {
                    (false, _) => 1u64 << (bits - 1),
                    (true, true) if signed => 1u64 << (bits - 1),
                    (true, true) => 0,
                    (true, false) if signed => mask(bits - 1),
                    (true, false) => mask(bits),
                }
            } else if signed {
                truncated as i64 as u64
            } else {
                truncated as u64
            };
            result & mask(bits)
        }
        Operation::FloatConvert { from, to } => {
            let value = float(from, args[0]);
            match to {
                Precision::Double => value.to_bits(),
                Precision::Single => u64::from((value as f32).to_bits()),
            }
        }
        Operation::CountLeadingZeros(bits) => {
            let value = args[0] & mask(u32::from(bits));
            u64::from(value.leading_zeros()) - (64 - u64::from(bits))
        }
        Operation::CountTrailingZeros(bits) => {
            let value = args[0] & mask(u32::from(bits));
            u64::from(value.trailing_zeros().min(u32::from(bits)))
        }
        Operation::PopCount(bits) => u64::from((args[0] & mask(u32::from(bits))).count_ones()),
        Operation::ReverseBits(bits) => {
            (args[0] & mask(u32::from(bits))).reverse_bits() >> (64 - u32::from(bits))
        }
    }
}

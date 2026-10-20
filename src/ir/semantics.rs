//! The meaning of the IR's operations where it depends on width: an
//! operand's width comes from its expression, and signed operations and
//! comparisons act at the wider of their operands' widths, as the
//! instruction they came from did.

use super::{BinOp, Cond, Expr, LaneOp, Operation, Precision, Rounding};

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
            Operation::Lanes(..)
            | Operation::InterleaveLow(_)
            | Operation::InterleaveHigh(_)
            | Operation::Widen { .. }
            | Operation::Narrow(_)
            | Operation::Aes { .. }
            | Operation::Pack { .. }
            | Operation::MultiplyAddPairs
            | Operation::SumAbsoluteDifferences
            | Operation::Results => 64,
            Operation::SumLanesLong { bits, .. } => 2 * u32::from(*bits),
            Operation::Crc32 { .. } => 32,
            Operation::WideDivide { bits, .. } => u32::from(*bits),
            Operation::SignBits(bits) => 64 / u32::from(*bits),
            // A count of up to 64 bits, with no sign.
            Operation::CountLeadingZeros(_)
            | Operation::CountTrailingZeros(_)
            | Operation::PopCount(_) => 8,
            Operation::SumLanes(bits) => u32::from(*bits),
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
    if faults(op, args) {
        return None;
    }
    let value = apply(op, args);
    let nan = match op {
        Operation::FloatAdd(p)
        | Operation::FloatSub(p)
        | Operation::FloatMul(p)
        | Operation::FloatDiv(p)
        | Operation::FloatSqrt(p)
        | Operation::FloatRound(p, _)
        | Operation::FloatMulAdd(p)
        | Operation::FloatConvert { to: p, .. } => match p {
            Precision::Double => f64::from_bits(value).is_nan(),
            Precision::Single => f32::from_bits(value as u32).is_nan(),
        },
        _ => false,
    };
    (!nan).then_some(value)
}

/// `op` on each pair of lanes of `bits` in `a` and `b`.
fn lanes(op: LaneOp, bits: u32, a: u64, b: u64) -> u64 {
    let ones = mask(bits);
    (0..64 / bits).fold(0, |out, index| {
        let shift = index * bits;
        let (x, y) = ((a >> shift) & ones, (b >> shift) & ones);
        let (sx, sy) = (sign_extend(x, bits), sign_extend(y, bits));
        let truth = |holds: bool| if holds { ones } else { 0 };
        let lane = match op {
            LaneOp::Add => x.wrapping_add(y),
            LaneOp::Sub => x.wrapping_sub(y),
            LaneOp::Mul => x.wrapping_mul(y),
            LaneOp::Equal => truth(x == y),
            LaneOp::GreaterSigned => truth(sx > sy),
            LaneOp::GreaterUnsigned => truth(x > y),
            LaneOp::GreaterEqualSigned => truth(sx >= sy),
            LaneOp::GreaterEqualUnsigned => truth(x >= y),
            LaneOp::MinSigned => {
                if sx <= sy {
                    x
                } else {
                    y
                }
            }
            LaneOp::MinUnsigned => x.min(y),
            LaneOp::MaxSigned => {
                if sx >= sy {
                    x
                } else {
                    y
                }
            }
            LaneOp::MaxUnsigned => x.max(y),
            // The count is the second argument itself, not a lane of it.
            LaneOp::ShiftLeft if b < u64::from(bits) => x << b,
            LaneOp::ShiftRight if b < u64::from(bits) => x >> b,
            LaneOp::ShiftLeft | LaneOp::ShiftRight => 0,
            LaneOp::ShiftRightSigned => (sx >> b.min(u64::from(bits) - 1)) as u64,
            LaneOp::AddSaturatingSigned => clamp_signed(sx.saturating_add(sy), bits),
            LaneOp::SubSaturatingSigned => clamp_signed(sx.saturating_sub(sy), bits),
            LaneOp::AddSaturatingUnsigned => x.saturating_add(y).min(ones),
            LaneOp::SubSaturatingUnsigned => x.saturating_sub(y),
            LaneOp::Average => (x + y + 1) >> 1,
            LaneOp::MulHighSigned => ((sx * sy) >> bits) as u64,
            LaneOp::MulHighUnsigned => (x * y) >> bits,
            LaneOp::PopCount => u64::from(x.count_ones()),
            LaneOp::CountLeadingZeros => u64::from(x.leading_zeros() - (64 - bits)),
        };
        out | (lane & ones) << shift
    })
}

/// `value` held within a signed lane of `bits`.
fn clamp_signed(value: i64, bits: u32) -> u64 {
    if bits >= 64 {
        return value as u64;
    }
    let limit = 1i64 << (bits - 1);
    value.clamp(-limit, limit - 1) as u64
}

/// The signed lanes of `from` bits in `low` then `high`, narrowed.
fn pack(from: u32, unsigned: bool, low: u64, high: u64) -> u64 {
    let narrow = from / 2;
    let per_half = 64 / from;
    (0..2 * per_half).fold(0, |out, index| {
        let half = if index < per_half { low } else { high };
        let lane = sign_extend((half >> ((index % per_half) * from)) & mask(from), from);
        let held = if unsigned {
            lane.clamp(0, mask(narrow) as i64) as u64
        } else {
            clamp_signed(lane, narrow) & mask(narrow)
        };
        out | held << (index * narrow)
    })
}

fn round(value: f64, rounding: Rounding) -> f64 {
    match rounding {
        Rounding::TowardZero => value.trunc(),
        Rounding::NearestEven => value.round_ties_even(),
        Rounding::NearestAway => value.round(),
        Rounding::Down => value.floor(),
        Rounding::Up => value.ceil(),
    }
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
        | Operation::FloatRound(p, _)
        | Operation::FloatMulAdd(p)
        | Operation::FloatEqual(p)
        | Operation::FloatLess(p)
        | Operation::FloatLessEqual(p)
        | Operation::FloatUnordered(p)
        | Operation::FloatToInt { from: p, .. }
        | Operation::FloatConvert { from: p, .. } => p.bits(),
        Operation::Lanes(..)
        | Operation::InterleaveLow(_)
        | Operation::InterleaveHigh(_)
        | Operation::Widen { .. }
        | Operation::Narrow(_)
        | Operation::SignBits(_)
        | Operation::SumLanes(_)
        | Operation::Aes { .. }
        | Operation::Pack { .. }
        | Operation::MultiplyAddPairs
        | Operation::SumAbsoluteDifferences
        | Operation::SumLanesLong { .. }
        | Operation::Crc32 { .. }
        | Operation::Results => 64,
        Operation::WideDivide { bits, .. } => bits,
        Operation::IntToFloat { bits, .. }
        | Operation::CountLeadingZeros(bits)
        | Operation::CountTrailingZeros(bits)
        | Operation::PopCount(bits)
        | Operation::ReverseBits(bits) => bits,
    })
}

/// Whether `op` on `args` faults instead of giving a value: a wide division
/// by zero, or one whose quotient does not fit.
pub(crate) fn faults(op: Operation, args: &[u64]) -> bool {
    let Operation::WideDivide { signed, bits, .. } = op else {
        return false;
    };
    wide_division(signed, u32::from(bits), args).is_none()
}

/// The quotient and remainder of a wide division, each in `bits`, or None
/// when it faults.
fn wide_division(signed: bool, bits: u32, args: &[u64]) -> Option<(u64, u64)> {
    let part = |value: u64| u128::from(value & mask(bits));
    let dividend = (part(args[0]) << bits) | part(args[1]);
    let divisor = part(args[2]);
    if divisor == 0 {
        return None;
    }
    if signed {
        let extend = |value: u128, width: u32| ((value << (128 - width)) as i128) >> (128 - width);
        let dividend = extend(dividend, 2 * bits);
        let divisor = extend(divisor, bits);
        let quotient = dividend.checked_div(divisor)?;
        let limit = 1i128 << (bits - 1);
        if quotient < -limit || quotient >= limit {
            return None;
        }
        let remainder = dividend % divisor;
        Some((quotient as u64 & mask(bits), remainder as u64 & mask(bits)))
    } else {
        let quotient = dividend / divisor;
        if quotient >> bits != 0 {
            return None;
        }
        Some((quotient as u64, (dividend % divisor) as u64))
    }
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
        Operation::FloatRound(precision, rounding) => match precision {
            Precision::Double => round(double(args[0]), rounding).to_bits(),
            // Rounding a single as a double gives the same integral value.
            Precision::Single => {
                u64::from((round(f64::from(single(args[0])), rounding) as f32).to_bits())
            }
        },
        Operation::FloatToInt {
            signed,
            bits,
            from,
            saturating,
            rounding,
        } => {
            let value = float(from, args[0]);
            let bits = u32::from(bits);
            let (low, high) = if signed {
                (-(2f64.powi(bits as i32 - 1)), 2f64.powi(bits as i32 - 1))
            } else {
                (0.0, 2f64.powi(bits as i32))
            };
            let truncated = round(value, rounding);
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
        Operation::Lanes(op, bits) => lanes(op, u32::from(bits), args[0], args[1]),
        Operation::InterleaveLow(bits) | Operation::InterleaveHigh(bits) => {
            let bits = u32::from(bits);
            let start = if matches!(op, Operation::InterleaveLow(_)) {
                0
            } else {
                32
            };
            let lane = mask(bits);
            (0..32 / bits).fold(0, |out, index| {
                let take = |value: u64| (value >> (start + index * bits)) & lane;
                out | take(args[0]) << (2 * index * bits)
                    | take(args[1]) << ((2 * index + 1) * bits)
            })
        }
        Operation::Widen { bits, signed, high } => {
            let bits = u32::from(bits);
            let start = if high { 32 } else { 0 };
            (0..32 / bits).fold(0, |out, index| {
                let lane = (args[0] >> (start + index * bits)) & mask(bits);
                let wide = if signed {
                    sign_extend(lane, bits) as u64 & mask(2 * bits)
                } else {
                    lane
                };
                out | wide << (2 * index * bits)
            })
        }
        Operation::Narrow(from) => {
            let from = u32::from(from);
            let per_half = 64 / from;
            (0..2 * per_half).fold(0, |out, index| {
                let half = if index < per_half { args[0] } else { args[1] };
                let lane = (half >> ((index % per_half) * from)) & mask(from / 2);
                out | lane << (index * from / 2)
            })
        }
        Operation::SignBits(bits) => {
            let bits = u32::from(bits);
            (0..64 / bits).fold(0, |out, index| {
                out | ((args[0] >> ((index + 1) * bits - 1)) & 1) << index
            })
        }
        Operation::SumLanes(bits) => {
            let bits = u32::from(bits);
            let sum = |value: u64| {
                (0..64 / bits).fold(0u64, |sum, index| {
                    sum.wrapping_add((value >> (index * bits)) & mask(bits))
                })
            };
            sum(args[0]).wrapping_add(sum(args[1])) & mask(bits)
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
        Operation::Pack { from, unsigned } => pack(u32::from(from), unsigned, args[0], args[1]),
        Operation::MultiplyAddPairs => (0..2).fold(0, |out, pair| {
            let lane = |value: u64, index: u32| sign_extend((value >> (16 * index)) & 0xffff, 16);
            let sum = lane(args[0], 2 * pair) * lane(args[1], 2 * pair)
                + lane(args[0], 2 * pair + 1) * lane(args[1], 2 * pair + 1);
            out | (sum as u64 & 0xffff_ffff) << (32 * pair)
        }),
        Operation::SumLanesLong { bits, signed } => {
            let bits = u32::from(bits);
            let sum = [args[0], args[1]].iter().fold(0i64, |sum, half| {
                (0..64 / bits).fold(sum, |sum, index| {
                    let lane = (half >> (index * bits)) & mask(bits);
                    sum + if signed {
                        sign_extend(lane, bits)
                    } else {
                        lane as i64
                    }
                })
            });
            sum as u64 & mask(2 * bits)
        }
        Operation::Results => args.first().copied().unwrap_or(0),
        Operation::Crc32 { castagnoli, bits } => {
            let polynomial: u32 = if castagnoli { 0x82f6_3b78 } else { 0xedb8_8320 };
            let mut crc = args[0] as u32;
            let data = args[1] & mask(u32::from(bits));
            for index in 0..u32::from(bits) {
                let bit = ((data >> index) as u32 ^ crc) & 1;
                crc = (crc >> 1) ^ if bit != 0 { polynomial } else { 0 };
            }
            u64::from(crc)
        }
        Operation::SumAbsoluteDifferences => (0..8).fold(0, |sum, index| {
            let byte = |value: u64| (value >> (8 * index)) & 0xff;
            sum + byte(args[0]).abs_diff(byte(args[1]))
        }),
        Operation::WideDivide {
            signed,
            remainder,
            bits,
        } => match wide_division(signed, u32::from(bits), args) {
            Some((_, rest)) if remainder => rest,
            Some((quotient, _)) => quotient,
            None => 0,
        },
        Operation::Aes { round, high } => {
            let state = u128::from(args[0]) | (u128::from(args[1]) << 64);
            let key = u128::from(args[2]) | (u128::from(args[3]) << 64);
            let result = aes_round(round, state) ^ key;
            if high {
                (result >> 64) as u64
            } else {
                result as u64
            }
        }
    }
}

/// The AES S-box, or its inverse: each byte's multiplicative inverse in
/// GF(2^8), then the affine map.
fn aes_sbox(inverse: bool) -> &'static [u8; 256] {
    static FORWARD: std::sync::OnceLock<[u8; 256]> = std::sync::OnceLock::new();
    static BACKWARD: std::sync::OnceLock<[u8; 256]> = std::sync::OnceLock::new();
    let forward = FORWARD.get_or_init(|| {
        let mut table = [0u8; 256];
        for (value, entry) in table.iter_mut().enumerate() {
            let inverse = (1..=255u8)
                .find(|candidate| gf_multiply(value as u8, *candidate) == 1)
                .unwrap_or(0);
            let mut out = inverse;
            for shift in 1..5 {
                out ^= inverse.rotate_left(shift);
            }
            *entry = out ^ 0x63;
        }
        table
    });
    if !inverse {
        return forward;
    }
    BACKWARD.get_or_init(|| {
        let mut table = [0u8; 256];
        for (value, image) in forward.iter().enumerate() {
            table[usize::from(*image)] = value as u8;
        }
        table
    })
}

/// The product in GF(2^8) under AES's polynomial.
fn gf_multiply(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        a = (a << 1) ^ if a & 0x80 != 0 { 0x1b } else { 0 };
        b >>= 1;
    }
    product
}

/// One AES round before its key: the state's bytes in column order, the
/// rows shifted, the bytes substituted and, but in the last round, each
/// column mixed.
fn aes_round(round: crate::ir::AesRound, state: u128) -> u128 {
    use crate::ir::AesRound;
    let bytes = state.to_le_bytes();
    let decrypt = matches!(round, AesRound::Decrypt | AesRound::DecryptLast);
    let sbox = aes_sbox(decrypt);
    let mut shifted = [0u8; 16];
    for column in 0..4 {
        for row in 0..4 {
            let from = if decrypt {
                (column + 4 - row) % 4
            } else {
                (column + row) % 4
            };
            shifted[row + 4 * column] = sbox[usize::from(bytes[row + 4 * from])];
        }
    }
    if matches!(round, AesRound::EncryptLast | AesRound::DecryptLast) {
        return u128::from_le_bytes(shifted);
    }
    let matrix: [[u8; 4]; 4] = if decrypt {
        [
            [14, 11, 13, 9],
            [9, 14, 11, 13],
            [13, 9, 14, 11],
            [11, 13, 9, 14],
        ]
    } else {
        [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
    };
    let mut mixed = [0u8; 16];
    for column in 0..4 {
        for row in 0..4 {
            mixed[row + 4 * column] = (0..4).fold(0, |sum, term| {
                sum ^ gf_multiply(matrix[row][term], shifted[term + 4 * column])
            });
        }
    }
    u128::from_le_bytes(mixed)
}

#[cfg(test)]
mod tests {
    use super::apply;
    use crate::ir::{AesRound, Operation};

    #[test]
    fn crc32_steps_give_the_check_values() {
        // The checksums of "123456789", from an all-ones start, inverted.
        for (castagnoli, check) in [(false, 0xcbf4_3926), (true, 0xe306_9283)] {
            let crc = b"123456789".iter().fold(0xffff_ffff, |crc, byte| {
                apply(
                    Operation::Crc32 {
                        castagnoli,
                        bits: 8,
                    },
                    &[crc, u64::from(*byte)],
                )
            });
            assert_eq!(crc ^ 0xffff_ffff, check);
        }
    }

    #[test]
    fn aes_rounds_match_the_published_example() {
        // The state 0x7b5b5465_73745665_63746f72_5d53475d and the round key
        // 0x48692853_68617929_5b477565_726f6e5d, round by round.
        let args = [
            0x6374_6f72_5d53_475d,
            0x7b5b_5465_7374_5665,
            0x5b47_7565_726f_6e5d,
            0x4869_2853_6861_7929,
        ];
        let round = |round, high| apply(Operation::Aes { round, high }, &args);
        let whole = |kind| (u128::from(round(kind, true)) << 64) | u128::from(round(kind, false));
        assert_eq!(
            whole(AesRound::Encrypt),
            0xa831_1c2f_9fdb_a3c5_8b10_4b58_ded7_e595
        );
        assert_eq!(
            whole(AesRound::EncryptLast),
            0xc7fb_881e_938c_5964_177e_c425_53fd_c611
        );
        assert_eq!(
            whole(AesRound::Decrypt),
            0x138a_c342_faea_2787_b58e_b95e_b730_392a
        );
        assert_eq!(
            whole(AesRound::DecryptLast),
            0xc5a3_91ef_6b31_7f95_d410_637b_72a5_93d0
        );
    }
}

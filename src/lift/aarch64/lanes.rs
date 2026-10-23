use super::{BinOp, Expr, LaneOp, Lifter, Operand, Operation, RegRef, a64, mask_bits};

/// A vector register used whole or as a scalar: its low slot and its width
/// in bits.
pub(super) fn simd(operand: Operand) -> Option<(u16, u16)> {
    let Operand::SIMDRegister(size, number) = operand else {
        return None;
    };
    let bits = match size {
        a64::SIMDSizeCode::B => 8,
        a64::SIMDSizeCode::H => 16,
        a64::SIMDSizeCode::S => 32,
        a64::SIMDSizeCode::D => 64,
        a64::SIMDSizeCode::Q => 128,
    };
    Some((crate::arch::aarch64::V0 + 2 * number, bits))
}

/// A lane of a vector register: its slot, the bit it starts at there, and
/// its width.
pub(super) fn lane(operand: Operand) -> Option<(u16, u64, u64)> {
    let Operand::SIMDRegisterElementsLane(_, number, size, index) = operand else {
        return None;
    };
    let bits: u64 = match size {
        a64::SIMDSizeCode::B => 8,
        a64::SIMDSizeCode::H => 16,
        a64::SIMDSizeCode::S => 32,
        a64::SIMDSizeCode::D => 64,
        a64::SIMDSizeCode::Q => return None,
    };
    let start = u64::from(index) * bits;
    let slot = crate::arch::aarch64::V0 + 2 * number + (start / 64) as u16;
    Some((slot, start % 64, bits))
}

pub(super) fn lane_value((slot, shift, bits): (u16, u64, u64)) -> Expr {
    let value = Expr::bin(BinOp::Shr, Expr::reg(slot, 64), Expr::constant(shift));
    if bits == 64 {
        value
    } else {
        Expr::bin(BinOp::And, value, Expr::constant((1 << bits) - 1))
    }
}

/// A vector register with an arrangement: its low slot, whether it fills
/// all 128 bits, and its lane width. A 64-bit scalar is one 64-bit lane.
pub(super) fn vector(operand: Operand) -> Option<(u16, bool, u8)> {
    let (size, number, element) = match operand {
        Operand::SIMDRegisterElements(size, number, element) => (size, number, element),
        Operand::SIMDRegister(a64::SIMDSizeCode::D, number) => {
            (a64::SIMDSizeCode::D, number, a64::SIMDSizeCode::D)
        }
        _ => return None,
    };
    let bits = match element {
        a64::SIMDSizeCode::B => 8,
        a64::SIMDSizeCode::H => 16,
        a64::SIMDSizeCode::S => 32,
        a64::SIMDSizeCode::D => 64,
        a64::SIMDSizeCode::Q => return None,
    };
    Some((
        crate::arch::aarch64::V0 + 2 * number,
        size == a64::SIMDSizeCode::Q,
        bits,
    ))
}

/// A vector's halves; a 64-bit one has no high half.
pub(super) fn halves((slot, full, _): (u16, bool, u8)) -> (Expr, Expr) {
    let high = if full {
        Expr::reg(slot + 1, 64)
    } else {
        Expr::constant(0)
    };
    (Expr::reg(slot, 64), high)
}

/// The lane a vector immediate gives: shifted left, filling with zeros or,
/// for `msl`, ones, and complemented for `mvni`.
pub(super) fn immediate_lane(operand: Operand, complement: bool, bits: u8) -> Option<u64> {
    let lane = match operand {
        Operand::ImmShift(value, shift) => u64::from(value) << shift,
        Operand::ImmShiftMSL(value, shift) => (u64::from(value) << shift) | ((1 << shift) - 1),
        _ => return None,
    };
    let lane = if complement { !lane } else { lane };
    Some(if bits == 64 {
        lane
    } else {
        lane & ((1u64 << bits) - 1)
    })
}

/// A constant lane in every lane of `bits` of a half.
pub(super) fn replicated(lane: u64, bits: u8) -> u64 {
    (0..64 / u32::from(bits)).fold(0, |out, index| out | lane << (index * u32::from(bits)))
}

/// `value` in every lane of `bits` of a half.
pub(super) fn replicate(value: Expr, bits: u8) -> Expr {
    if bits == 64 {
        return value;
    }
    let lane = (1u64 << bits) - 1;
    let ones =
        (0..64 / u32::from(bits)).fold(0u64, |out, index| out | 1 << (index * u32::from(bits)));
    Expr::bin(
        BinOp::Mul,
        Expr::bin(BinOp::And, value, Expr::constant(lane)),
        Expr::constant(ones),
    )
}

/// 64 bits of `parts` (halves, lowest first) starting at bit `start`.
pub(super) fn window(parts: &[Expr], start: u64) -> Expr {
    let (index, offset) = ((start / 64) as usize, start % 64);
    let low = Expr::bin(BinOp::Shr, parts[index].clone(), Expr::constant(offset));
    match parts.get(index + 1) {
        Some(next) if offset > 0 => Expr::bin(
            BinOp::Or,
            low,
            Expr::bin(BinOp::Shl, next.clone(), Expr::constant(64 - offset)),
        ),
        _ => low,
    }
}

/// The count of a shift by an immediate, or a fixed-point conversion's
/// fraction bits.
pub(super) fn shift_count(operand: Operand) -> Option<u64> {
    match operand {
        Operand::Immediate(count) => Some(u64::from(count)),
        Operand::Imm16(count) => Some(u64::from(count)),
        _ => None,
    }
}

/// A vector source's halves: a register, zero for a compare with zero, or
/// one lane of a register, as `mul v0.2s, v1.2s, v2.s[1]` takes, copied
/// into every lane.
pub(super) fn source_halves(operand: Operand) -> Option<(Expr, Expr)> {
    match operand {
        Operand::Immediate(0) | Operand::Imm64(0) | Operand::ImmediateDouble(0.0) => {
            Some((Expr::constant(0), Expr::constant(0)))
        }
        Operand::SIMDRegisterElementsLane(_, number, element, lane) => {
            let bits = match element {
                a64::SIMDSizeCode::H => 16u64,
                a64::SIMDSizeCode::S => 32,
                a64::SIMDSizeCode::D => 64,
                _ => return None,
            };
            let at = u64::from(lane) * bits;
            let half = Expr::reg(crate::arch::aarch64::V0 + 2 * number + (at / 64) as u16, 64);
            let within = at % 64;
            let value = if bits == 64 {
                half
            } else {
                Expr::bin(
                    BinOp::And,
                    Expr::bin(BinOp::Shr, half, Expr::constant(within)),
                    Expr::constant((1u64 << bits) - 1),
                )
            };
            let copied = Expr::bin(BinOp::Mul, value, Expr::constant(replicated(1, bits as u8)));
            Some((copied.clone(), copied))
        }
        operand => Some(halves(vector(operand)?)),
    }
}

pub(super) fn lanewise(op: LaneOp, bits: u8, a: Expr, b: Expr) -> Expr {
    Expr::apply(Operation::Lanes(op, bits), vec![a, b])
}

/// Each lane of `bits` of `value` shifted by `count`; a plain shift where
/// the lane is the whole half and the count below 64.
pub(super) fn lane_shift(op: LaneOp, bits: u8, value: Expr, count: u64) -> Expr {
    match op {
        LaneOp::ShiftLeft if bits == 64 && count < 64 => {
            Expr::bin(BinOp::Shl, value, Expr::constant(count))
        }
        LaneOp::ShiftRight if bits == 64 && count < 64 => {
            Expr::bin(BinOp::Shr, value, Expr::constant(count))
        }
        _ => lanewise(op, bits, value, Expr::constant(count)),
    }
}

/// `f` on each half of `a` with the same half of `b`.
pub(super) fn by_halves(
    (a0, a1): (Expr, Expr),
    (b0, b1): (Expr, Expr),
    f: impl Fn(Expr, Expr) -> Expr,
) -> (Expr, Expr) {
    (f(a0, b0), f(a1, b1))
}

/// The lanes of `bits` in one half of a vector, the high one for the
/// second-half forms, each extended to twice `bits`, as two halves.
pub(super) fn widened(
    (low, high): (Expr, Expr),
    upper: bool,
    bits: u8,
    signed: bool,
) -> (Expr, Expr) {
    let half = if upper { high } else { low };
    let widen = |high| Expr::apply(Operation::Widen { bits, signed, high }, vec![half.clone()]);
    (widen(false), widen(true))
}

pub(super) fn narrowed((low, high): (Expr, Expr), from: u8) -> Expr {
    Expr::apply(Operation::Narrow(from), vec![low, high])
}

pub(super) fn doubling_mul_high(a: Expr, b: Expr, bits: u8) -> Expr {
    let wide = bits * 2;
    let a = widened((a, Expr::constant(0)), false, bits, true);
    let b = widened((b, Expr::constant(0)), false, bits, true);
    let limit = Expr::constant(replicated((1u64 << (bits - 1)) - 1, wide));
    let product = |a, b| {
        let multiplied = lanewise(LaneOp::Mul, wide, a, b);
        // Shifting the undoubled product avoids a 64-bit overflow at MIN * MIN.
        let high = lane_shift(
            LaneOp::ShiftRightSigned,
            wide,
            multiplied,
            u64::from(bits - 1),
        );
        lanewise(LaneOp::MinSigned, wide, high, limit.clone())
    };
    narrowed((product(a.0, b.0), product(a.1, b.1)), wide)
}

/// The even (or odd) lanes of `bits` of two vectors taken as one, the
/// first's first.
pub(super) fn unzip(
    a: (Expr, Expr),
    b: (Expr, Expr),
    bits: u8,
    full: bool,
    odd: bool,
) -> (Expr, Expr) {
    if bits == 64 {
        return if odd { (a.1, b.1) } else { (a.0, b.0) };
    }
    let wide = 2 * bits;
    let pick = |half: Expr| {
        if odd {
            lane_shift(LaneOp::ShiftRight, wide, half, u64::from(bits))
        } else {
            half
        }
    };
    let narrow = |x: Expr, y: Expr| narrowed((pick(x), pick(y)), wide);
    if full {
        (narrow(a.0, a.1), narrow(b.0, b.1))
    } else {
        (narrow(a.0, b.0), Expr::constant(0))
    }
}

/// Each lane rounded to nearest after a right shift by `count`: the shifted
/// lane plus the last bit shifted out.
pub(super) fn rounding_shift(bits: u8, value: Expr, count: u64, signed: bool) -> Expr {
    let op = if signed {
        LaneOp::ShiftRightSigned
    } else {
        LaneOp::ShiftRight
    };
    let shifted = lane_shift(op, bits, value.clone(), count);
    let last = Expr::bin(
        BinOp::And,
        lane_shift(LaneOp::ShiftRight, bits, value, count - 1),
        Expr::constant(replicated(1, bits)),
    );
    lanewise(LaneOp::Add, bits, shifted, last)
}

/// The absolute difference of each pair of lanes.
pub(super) fn absolute_difference(bits: u8, signed: bool, a: Expr, b: Expr) -> Expr {
    let (max, min) = if signed {
        (LaneOp::MaxSigned, LaneOp::MinSigned)
    } else {
        (LaneOp::MaxUnsigned, LaneOp::MinUnsigned)
    };
    lanewise(
        LaneOp::Sub,
        bits,
        lanewise(max, bits, a.clone(), b.clone()),
        lanewise(min, bits, a, b),
    )
}

pub(super) fn complement(value: Expr) -> Expr {
    Expr::bin(BinOp::Xor, value, Expr::constant(u64::MAX))
}

/// A narrowed half written to the low half of a vector, clearing the high
/// one, or for the second-half forms to the high half, keeping the low one.
pub(super) fn write_narrow(
    lifter: &mut Lifter,
    (slot, _, _): (u16, bool, u8),
    upper: bool,
    value: Expr,
) {
    if upper {
        lifter.assign(
            RegRef {
                index: slot + 1,
                width: 64,
            },
            value,
        );
    } else {
        lifter.write_simd(slot, 128, (value, Expr::constant(0)));
    }
}

/// The lanes of `bits` of a half in reverse order within each part of
/// `part` bits.
pub(super) fn reverse_lanes(half: Expr, bits: u8, part: u8) -> Expr {
    let (bits, per_part) = (u64::from(bits), u64::from(part / bits));
    (0..64 / bits)
        .map(|index| {
            let target = index - index % per_part + (per_part - 1 - index % per_part);
            let lane = Expr::bin(
                BinOp::And,
                Expr::bin(BinOp::Shr, half.clone(), Expr::constant(bits * index)),
                Expr::constant(mask_bits(bits)),
            );
            Expr::bin(BinOp::Shl, lane, Expr::constant(bits * target))
        })
        .reduce(|all, lane| Expr::bin(BinOp::Or, all, lane))
        .unwrap_or(half)
}

use super::{
    BinOp, Expr, Instruction, LaneOp, Lifter, Operand, Operation, a64, absolute_difference,
    by_halves, complement, doubling_mul_high, halves, immediate_lane, immediates, lane, lane_shift,
    lane_value, lanewise, mask_bits, narrowed, replicate, replicated, reverse_lanes,
    rounding_shift, shift_count, simd, source_halves, unzip, vector, widened, window, write_narrow,
};

/// What a widening instruction does with the lanes it extends.
#[derive(Clone, Copy)]
enum Widening {
    Add,
    Sub,
    /// The first source already wide.
    AddWide,
    SubWide,
    Mul,
    /// The product added to the destination, or taken from it.
    MulAdd,
    MulSub,
    AbsoluteDifference,
    AbsoluteDifferenceAdd,
}

/// A widening instruction's operation, whether it extends with the sign,
/// and whether it takes the sources' high halves.
fn widening(opcode: a64::Opcode) -> Option<(Widening, bool, bool)> {
    use Widening as W;
    use a64::Opcode as O;
    Some(match opcode {
        O::SADDL => (W::Add, true, false),
        O::SADDL2 => (W::Add, true, true),
        O::UADDL => (W::Add, false, false),
        O::UADDL2 => (W::Add, false, true),
        O::SSUBL => (W::Sub, true, false),
        O::SSUBL2 => (W::Sub, true, true),
        O::USUBL => (W::Sub, false, false),
        O::USUBL2 => (W::Sub, false, true),
        O::SADDW => (W::AddWide, true, false),
        O::SADDW2 => (W::AddWide, true, true),
        O::UADDW => (W::AddWide, false, false),
        O::UADDW2 => (W::AddWide, false, true),
        O::SSUBW => (W::SubWide, true, false),
        O::SSUBW2 => (W::SubWide, true, true),
        O::USUBW => (W::SubWide, false, false),
        O::USUBW2 => (W::SubWide, false, true),
        O::SMULL => (W::Mul, true, false),
        O::SMULL2 => (W::Mul, true, true),
        O::UMULL => (W::Mul, false, false),
        O::UMULL2 => (W::Mul, false, true),
        O::SMLAL => (W::MulAdd, true, false),
        O::SMLAL2 => (W::MulAdd, true, true),
        O::UMLAL => (W::MulAdd, false, false),
        O::UMLAL2 => (W::MulAdd, false, true),
        O::SMLSL => (W::MulSub, true, false),
        O::SMLSL2 => (W::MulSub, true, true),
        O::UMLSL => (W::MulSub, false, false),
        O::UMLSL2 => (W::MulSub, false, true),
        O::SABDL => (W::AbsoluteDifference, true, false),
        O::SABDL2 => (W::AbsoluteDifference, true, true),
        O::UABDL => (W::AbsoluteDifference, false, false),
        O::UABDL2 => (W::AbsoluteDifference, false, true),
        O::SABAL => (W::AbsoluteDifferenceAdd, true, false),
        O::SABAL2 => (W::AbsoluteDifferenceAdd, true, true),
        O::UABAL => (W::AbsoluteDifferenceAdd, false, false),
        O::UABAL2 => (W::AbsoluteDifferenceAdd, false, true),
        _ => return None,
    })
}

/// How a narrowing instruction cuts its lanes.
#[derive(Clone, Copy)]
enum Narrowing {
    /// As they are.
    Cut,
    /// Signed lanes held at the narrow lane's limits, signed or unsigned.
    Held { unsigned: bool },
    /// Unsigned lanes held at the narrow lane's limit.
    HeldUnsigned,
    /// Shifted right first, rounding to nearest when `rounded` is set.
    Shift { rounded: bool },
    /// The high half of a sum or difference.
    High { op: LaneOp, rounded: bool },
}

/// A narrowing instruction's form, and whether it writes the destination's
/// high half.
fn narrowing(opcode: a64::Opcode) -> Option<(Narrowing, bool)> {
    use Narrowing as N;
    use a64::Opcode as O;
    let high = |op, rounded| N::High { op, rounded };
    Some(match opcode {
        O::XTN => (N::Cut, false),
        O::XTN2 => (N::Cut, true),
        O::SQXTN => (N::Held { unsigned: false }, false),
        O::SQXTN2 => (N::Held { unsigned: false }, true),
        O::SQXTUN => (N::Held { unsigned: true }, false),
        O::SQXTUN2 => (N::Held { unsigned: true }, true),
        O::UQXTN => (N::HeldUnsigned, false),
        O::UQXTN2 => (N::HeldUnsigned, true),
        O::SHRN => (N::Shift { rounded: false }, false),
        O::SHRN2 => (N::Shift { rounded: false }, true),
        O::RSHRN => (N::Shift { rounded: true }, false),
        O::RSHRN2 => (N::Shift { rounded: true }, true),
        O::ADDHN => (high(LaneOp::Add, false), false),
        O::ADDHN2 => (high(LaneOp::Add, false), true),
        O::RADDHN => (high(LaneOp::Add, true), false),
        O::RADDHN2 => (high(LaneOp::Add, true), true),
        O::SUBHN => (high(LaneOp::Sub, false), false),
        O::SUBHN2 => (high(LaneOp::Sub, false), true),
        O::RSUBHN => (high(LaneOp::Sub, true), false),
        O::RSUBHN2 => (high(LaneOp::Sub, true), true),
        _ => return None,
    })
}

/// The integer vector instructions, lane by lane on each half.
pub(super) fn lift_vector(lifter: &mut Lifter, ins: &Instruction) -> Option<()> {
    use a64::Opcode as O;
    let ops = ins.operands;
    let lanes = |op, bits, a: Expr, b: Expr| Expr::apply(Operation::Lanes(op, bits), vec![a, b]);
    match ins.opcode {
        O::SQDMULH => {
            let dest = vector(ops[0])?;
            let a = vector(ops[1])?;
            let b = vector(ops[2])?;
            if !matches!(dest.2, 16 | 32)
                || (a.1, a.2) != (dest.1, dest.2)
                || (b.1, b.2) != (dest.1, dest.2)
            {
                return None;
            }
            let (low, high) =
                by_halves(halves(a), halves(b), |a, b| doubling_mul_high(a, b, dest.2));
            lifter.write_vector(dest, low, high);
        }
        O::ADD
        | O::SUB
        | O::MUL
        | O::CMEQ
        | O::CMGT
        | O::CMHI
        | O::CMGE
        | O::CMHS
        | O::SMIN
        | O::SMAX
        | O::UMIN
        | O::UMAX
        | O::SQADD
        | O::UQADD
        | O::SQSUB
        | O::UQSUB
        | O::URHADD
            if vector(ops[0]).is_some() =>
        {
            let dest = vector(ops[0])?;
            let bits = dest.2;
            let (a, b) = (halves(vector(ops[1])?), source_halves(ops[2])?);
            let op = match ins.opcode {
                O::ADD => LaneOp::Add,
                O::SUB => LaneOp::Sub,
                O::MUL => LaneOp::Mul,
                O::CMEQ => LaneOp::Equal,
                O::CMGT => LaneOp::GreaterSigned,
                O::CMHI => LaneOp::GreaterUnsigned,
                O::CMGE => LaneOp::GreaterEqualSigned,
                O::CMHS => LaneOp::GreaterEqualUnsigned,
                O::SMIN => LaneOp::MinSigned,
                O::SMAX => LaneOp::MaxSigned,
                O::UMIN => LaneOp::MinUnsigned,
                O::SQADD => LaneOp::AddSaturatingSigned,
                O::UQADD => LaneOp::AddSaturatingUnsigned,
                O::SQSUB => LaneOp::SubSaturatingSigned,
                O::UQSUB => LaneOp::SubSaturatingUnsigned,
                O::URHADD => LaneOp::Average,
                _ => LaneOp::MaxUnsigned,
            };
            let low = lanes(op, bits, a.0, b.0);
            let high = lanes(op, bits, a.1, b.1);
            lifter.write_vector(dest, low, high);
        }
        // A shifted immediate set (orr) or cleared (bic) in every lane.
        O::ORR | O::BIC
            if vector(ops[0]).is_some()
                && matches!(ops[1], Operand::ImmShift(..) | Operand::ImmShiftMSL(..)) =>
        {
            let dest = vector(ops[0])?;
            let lane = immediate_lane(ops[1], false, dest.2)?;
            let bits = Expr::constant(replicated(lane, dest.2));
            let (low, high) = halves(dest);
            let combine = |half: Expr| match ins.opcode {
                O::ORR => Expr::bin(BinOp::Or, half, bits.clone()),
                _ => Expr::bin(
                    BinOp::And,
                    half,
                    Expr::bin(BinOp::Xor, bits.clone(), Expr::constant(u64::MAX)),
                ),
            };
            lifter.write_vector(dest, combine(low), combine(high));
        }
        // The set bits of each byte.
        O::CNT => {
            let dest = vector(ops[0])?;
            let (low, high) = halves(vector(ops[1])?);
            lifter.write_vector(
                dest,
                lanes(LaneOp::PopCount, 8, low, Expr::constant(0)),
                lanes(LaneOp::PopCount, 8, high, Expr::constant(0)),
            );
        }
        // The sum of every lane, each extended, into a scalar twice as wide.
        O::UADDLV | O::SADDLV => {
            let (slot, bits) = simd(ops[0])?;
            let source = vector(ops[1])?;
            let (low, high) = halves(source);
            let sum = Expr::apply(
                Operation::SumLanesLong {
                    bits: source.2,
                    signed: ins.opcode == O::SADDLV,
                },
                vec![low, high],
            );
            lifter.write_simd(slot, bits, (sum, Expr::constant(0)));
        }
        O::AND | O::ORR | O::EOR | O::BIC | O::ORN if vector(ops[0]).is_some() => {
            let dest = vector(ops[0])?;
            let (a, b) = (halves(vector(ops[1])?), halves(vector(ops[2])?));
            let combine = |x: Expr, y: Expr| match ins.opcode {
                O::AND => Expr::bin(BinOp::And, x, y),
                O::ORR => Expr::bin(BinOp::Or, x, y),
                O::EOR => Expr::bin(BinOp::Xor, x, y),
                O::BIC => Expr::bin(
                    BinOp::And,
                    x,
                    Expr::bin(BinOp::Xor, y, Expr::constant(u64::MAX)),
                ),
                _ => Expr::bin(
                    BinOp::Or,
                    x,
                    Expr::bin(BinOp::Xor, y, Expr::constant(u64::MAX)),
                ),
            };
            let (low, high) = (combine(a.0, b.0), combine(a.1, b.1));
            lifter.write_vector(dest, low, high);
        }
        // The sum of every lane, into a scalar.
        O::ADDV => {
            let (slot, bits) = simd(ops[0])?;
            let source = vector(ops[1])?;
            let (low, high) = halves(source);
            let sum = Expr::apply(Operation::SumLanes(source.2), vec![low, high]);
            lifter.write_simd(slot, bits, (sum, Expr::constant(0)));
        }
        // The two 64-bit lanes added, into a scalar.
        O::ADDP if simd(ops[0]).is_some() => {
            let (slot, bits) = simd(ops[0])?;
            let (low, high) = halves(vector(ops[1])?);
            lifter.write_simd(
                slot,
                bits,
                (Expr::bin(BinOp::Add, low, high), Expr::constant(0)),
            );
        }
        // A general register or one lane, in every lane.
        O::DUP if vector(ops[0]).is_some() => {
            let dest = vector(ops[0])?;
            let value = match lane(ops[1]) {
                Some(source) => lane_value(source),
                None => lifter.operand(ops[1], dest.2.max(32))?,
            };
            let half = replicate(value, dest.2);
            lifter.write_vector(dest, half.clone(), half);
        }
        O::SHL | O::USHR | O::SSHR if vector(ops[0]).is_some() => {
            let dest = vector(ops[0])?;
            let source = halves(vector(ops[1])?);
            let count = shift_count(ops[2])?;
            let op = match ins.opcode {
                O::SHL => LaneOp::ShiftLeft,
                O::USHR => LaneOp::ShiftRight,
                _ => LaneOp::ShiftRightSigned,
            };
            let count = Expr::constant(count);
            let (low, high) = (
                lanes(op, dest.2, source.0, count.clone()),
                lanes(op, dest.2, source.1, count),
            );
            lifter.write_vector(dest, low, high);
        }
        // Bytes from the pair of sources taken as one, the first lowest.
        O::EXT => {
            let dest = vector(ops[0])?;
            let (n, m) = (halves(vector(ops[1])?), halves(vector(ops[2])?));
            let start = match ops[3] {
                Operand::Imm64(value) => value,
                other => immediates(other)?,
            };
            let parts = if dest.1 {
                vec![n.0, n.1, m.0, m.1]
            } else {
                vec![n.0, m.0]
            };
            let start = 8 * start;
            let low = window(&parts, start);
            let high = if dest.1 {
                window(&parts, start + 64)
            } else {
                Expr::constant(0)
            };
            lifter.write_vector(dest, low, high);
        }
        // Below zero, or at most zero.
        O::CMLT | O::CMLE if vector(ops[0]).is_some() => {
            let dest = vector(ops[0])?;
            let op = if ins.opcode == O::CMLT {
                LaneOp::GreaterSigned
            } else {
                LaneOp::GreaterEqualSigned
            };
            let (low, high) = by_halves(
                (Expr::constant(0), Expr::constant(0)),
                halves(vector(ops[1])?),
                |zero, x| lanewise(op, dest.2, zero, x),
            );
            lifter.write_vector(dest, low, high);
        }
        // All ones where the lanes share a set bit.
        O::CMTST => {
            let dest = vector(ops[0])?;
            let (low, high) =
                by_halves(halves(vector(ops[1])?), halves(vector(ops[2])?), |x, y| {
                    complement(lanewise(
                        LaneOp::Equal,
                        dest.2,
                        Expr::bin(BinOp::And, x, y),
                        Expr::constant(0),
                    ))
                });
            lifter.write_vector(dest, low, high);
        }
        O::MLA | O::MLS => {
            let dest = vector(ops[0])?;
            let bits = dest.2;
            let product = by_halves(halves(vector(ops[1])?), source_halves(ops[2])?, |x, y| {
                lanewise(LaneOp::Mul, bits, x, y)
            });
            let op = if ins.opcode == O::MLA {
                LaneOp::Add
            } else {
                LaneOp::Sub
            };
            let (low, high) = by_halves(halves(dest), product, |acc, p| lanewise(op, bits, acc, p));
            lifter.write_vector(dest, low, high);
        }
        O::SABD | O::UABD | O::SABA | O::UABA => {
            let dest = vector(ops[0])?;
            let bits = dest.2;
            let signed = matches!(ins.opcode, O::SABD | O::SABA);
            let difference = by_halves(halves(vector(ops[1])?), halves(vector(ops[2])?), |x, y| {
                absolute_difference(bits, signed, x, y)
            });
            let (low, high) = if matches!(ins.opcode, O::SABA | O::UABA) {
                by_halves(halves(dest), difference, |acc, d| {
                    lanewise(LaneOp::Add, bits, acc, d)
                })
            } else {
                difference
            };
            lifter.write_vector(dest, low, high);
        }
        // Halving sums and differences, which never overflow the lane: a
        // sum is the common bits plus half the differing ones, a rounded
        // one either's bits less half the differing ones, and a difference
        // the halves' difference less a borrow from the low bits.
        O::SHADD | O::UHADD | O::SRHADD | O::SHSUB | O::UHSUB => {
            let dest = vector(ops[0])?;
            let bits = dest.2;
            let signed = matches!(ins.opcode, O::SHADD | O::SRHADD | O::SHSUB);
            let half = |value: Expr| {
                let op = if signed {
                    LaneOp::ShiftRightSigned
                } else {
                    LaneOp::ShiftRight
                };
                lane_shift(op, bits, value, 1)
            };
            let (low, high) = by_halves(
                halves(vector(ops[1])?),
                halves(vector(ops[2])?),
                |x, y| match ins.opcode {
                    O::SHADD | O::UHADD => lanewise(
                        LaneOp::Add,
                        bits,
                        Expr::bin(BinOp::And, x.clone(), y.clone()),
                        half(Expr::bin(BinOp::Xor, x, y)),
                    ),
                    O::SRHADD => lanewise(
                        LaneOp::Sub,
                        bits,
                        Expr::bin(BinOp::Or, x.clone(), y.clone()),
                        half(Expr::bin(BinOp::Xor, x, y)),
                    ),
                    _ => lanewise(
                        LaneOp::Sub,
                        bits,
                        lanewise(LaneOp::Sub, bits, half(x.clone()), half(y.clone())),
                        Expr::bin(
                            BinOp::And,
                            Expr::bin(BinOp::And, complement(x), y),
                            Expr::constant(replicated(1, bits)),
                        ),
                    ),
                },
            );
            lifter.write_vector(dest, low, high);
        }
        // Pairs of neighbouring lanes of the two sources taken as one.
        O::ADDP | O::SMAXP | O::UMAXP | O::SMINP | O::UMINP if vector(ops[0]).is_some() => {
            let dest = vector(ops[0])?;
            let bits = dest.2;
            let (a, b) = (halves(vector(ops[1])?), halves(vector(ops[2])?));
            let even = unzip(a.clone(), b.clone(), bits, dest.1, false);
            let odd = unzip(a, b, bits, dest.1, true);
            let op = match ins.opcode {
                O::ADDP => LaneOp::Add,
                O::SMAXP => LaneOp::MaxSigned,
                O::UMAXP => LaneOp::MaxUnsigned,
                O::SMINP => LaneOp::MinSigned,
                _ => LaneOp::MinUnsigned,
            };
            let (low, high) = if bits == 64 {
                by_halves(even, odd, |x, y| Expr::bin(BinOp::Add, x, y))
            } else {
                by_halves(even, odd, |x, y| lanewise(op, bits, x, y))
            };
            lifter.write_vector(dest, low, high);
        }
        O::NOT | O::NEG | O::ABS | O::SQNEG | O::SQABS | O::CLZ | O::CLS
            if vector(ops[0]).is_some() =>
        {
            let dest = vector(ops[0])?;
            let bits = dest.2;
            let negate = |x: Expr| lanewise(LaneOp::Sub, bits, Expr::constant(0), x);
            let held = |x: Expr| lanewise(LaneOp::SubSaturatingSigned, bits, Expr::constant(0), x);
            let each = |x: Expr| match ins.opcode {
                O::NOT => complement(x),
                O::NEG => negate(x),
                O::ABS => lanewise(LaneOp::MaxSigned, bits, x.clone(), negate(x)),
                O::SQNEG => held(x),
                O::SQABS => lanewise(LaneOp::MaxSigned, bits, x.clone(), held(x)),
                O::CLZ => lanewise(LaneOp::CountLeadingZeros, bits, x, Expr::constant(0)),
                // The bits below the top one that match it are the leading
                // zeros, less one, of the lane with each bit compared to
                // the one above it.
                _ => {
                    let neighbours = Expr::bin(
                        BinOp::Xor,
                        x.clone(),
                        lane_shift(LaneOp::ShiftRightSigned, bits, x, 1),
                    );
                    lanewise(
                        LaneOp::Sub,
                        bits,
                        lanewise(
                            LaneOp::CountLeadingZeros,
                            bits,
                            neighbours,
                            Expr::constant(0),
                        ),
                        Expr::constant(replicated(1, bits)),
                    )
                }
            };
            let (low, high) = halves(vector(ops[1])?);
            lifter.write_vector(dest, each(low), each(high));
        }
        // Bitwise selects: bsl picks from the first source where the
        // destination is set, bit inserts the first source where the second
        // is set, and bif where it is clear.
        O::BSL | O::BIT | O::BIF => {
            let dest = vector(ops[0])?;
            let select = |mask: Expr, set: Expr, clear: Expr| {
                Expr::bin(
                    BinOp::Or,
                    Expr::bin(BinOp::And, set, mask.clone()),
                    Expr::bin(BinOp::And, clear, complement(mask)),
                )
            };
            let (d, n, m) = (
                halves(dest),
                halves(vector(ops[1])?),
                halves(vector(ops[2])?),
            );
            let each = |d: Expr, n: Expr, m: Expr| match ins.opcode {
                O::BSL => select(d, n, m),
                O::BIT => select(m, n, d),
                _ => select(m, d, n),
            };
            let (low, high) = (each(d.0, n.0, m.0), each(d.1, n.1, m.1));
            lifter.write_vector(dest, low, high);
        }
        // Shifts right whose result is added to the destination, rounded,
        // or both.
        O::USRA | O::SSRA | O::URSHR | O::SRSHR | O::URSRA | O::SRSRA
            if vector(ops[0]).is_some() =>
        {
            let dest = vector(ops[0])?;
            let bits = dest.2;
            let count = shift_count(ops[2])?;
            let signed = matches!(ins.opcode, O::SSRA | O::SRSHR | O::SRSRA);
            let rounded = matches!(ins.opcode, O::URSHR | O::SRSHR | O::URSRA | O::SRSRA);
            let shift = |x: Expr| {
                if rounded {
                    rounding_shift(bits, x, count, signed)
                } else if signed {
                    lane_shift(LaneOp::ShiftRightSigned, bits, x, count)
                } else {
                    lane_shift(LaneOp::ShiftRight, bits, x, count)
                }
            };
            let (x, y) = halves(vector(ops[1])?);
            let shifted = (shift(x), shift(y));
            let (low, high) = if matches!(ins.opcode, O::URSHR | O::SRSHR) {
                shifted
            } else {
                by_halves(halves(dest), shifted, |acc, s| {
                    lanewise(LaneOp::Add, bits, acc, s)
                })
            };
            lifter.write_vector(dest, low, high);
        }
        // Shifts that insert the source's bits and keep the destination's
        // the shift leaves empty.
        O::SLI | O::SRI if vector(ops[0]).is_some() => {
            let dest = vector(ops[0])?;
            let bits = dest.2;
            let count = shift_count(ops[2])?;
            let lane = mask_bits(u64::from(bits));
            let (op, inserted) = if ins.opcode == O::SLI {
                (LaneOp::ShiftLeft, (lane << count) & lane)
            } else {
                (
                    LaneOp::ShiftRight,
                    lane.checked_shr(count as u32).unwrap_or(0),
                )
            };
            let kept = Expr::constant(!replicated(inserted, bits));
            let (low, high) = by_halves(halves(dest), halves(vector(ops[1])?), |d, x| {
                Expr::bin(
                    BinOp::Or,
                    Expr::bin(BinOp::And, d, kept.clone()),
                    lane_shift(op, bits, x, count),
                )
            });
            lifter.write_vector(dest, low, high);
        }
        O::ZIP1 | O::ZIP2 => {
            let dest = vector(ops[0])?;
            let bits = dest.2;
            let (a, b) = (halves(vector(ops[1])?), halves(vector(ops[2])?));
            let second = ins.opcode == O::ZIP2;
            let interleave = |op: fn(u8) -> Operation, x: &Expr, y: &Expr| {
                Expr::apply(op(bits), vec![x.clone(), y.clone()])
            };
            let (low, high) = if bits == 64 {
                if second { (a.1, b.1) } else { (a.0, b.0) }
            } else if dest.1 {
                let (x, y) = if second { (a.1, b.1) } else { (a.0, b.0) };
                (
                    interleave(Operation::InterleaveLow, &x, &y),
                    interleave(Operation::InterleaveHigh, &x, &y),
                )
            } else if second {
                (
                    interleave(Operation::InterleaveHigh, &a.0, &b.0),
                    Expr::constant(0),
                )
            } else {
                (
                    interleave(Operation::InterleaveLow, &a.0, &b.0),
                    Expr::constant(0),
                )
            };
            lifter.write_vector(dest, low, high);
        }
        O::UZP1 | O::UZP2 => {
            let dest = vector(ops[0])?;
            let (a, b) = (halves(vector(ops[1])?), halves(vector(ops[2])?));
            let (low, high) = unzip(a, b, dest.2, dest.1, ins.opcode == O::UZP2);
            lifter.write_vector(dest, low, high);
        }
        // The even (or odd) lanes of each pair, the first source's in the
        // even lanes and the second's in the odd ones.
        O::TRN1 | O::TRN2 => {
            let dest = vector(ops[0])?;
            let bits = dest.2;
            let (a, b) = (halves(vector(ops[1])?), halves(vector(ops[2])?));
            let (low, high) = if bits == 64 {
                if ins.opcode == O::TRN1 {
                    (a.0, b.0)
                } else {
                    (a.1, b.1)
                }
            } else {
                let even = replicated(mask_bits(u64::from(bits)), 2 * bits);
                let count = Expr::constant(u64::from(bits));
                by_halves(a, b, |x, y| {
                    if ins.opcode == O::TRN1 {
                        Expr::bin(
                            BinOp::Or,
                            Expr::bin(BinOp::And, x, Expr::constant(even)),
                            Expr::bin(
                                BinOp::Shl,
                                Expr::bin(BinOp::And, y, Expr::constant(even)),
                                count.clone(),
                            ),
                        )
                    } else {
                        Expr::bin(
                            BinOp::Or,
                            Expr::bin(
                                BinOp::And,
                                Expr::bin(BinOp::Shr, x, count.clone()),
                                Expr::constant(even),
                            ),
                            Expr::bin(BinOp::And, y, Expr::constant(!even)),
                        )
                    }
                })
            };
            lifter.write_vector(dest, low, high);
        }
        // Each lane extended to twice its width and shifted left.
        O::SSHLL | O::SSHLL2 | O::USHLL | O::USHLL2 | O::SHLL | O::SHLL2 => {
            let dest = vector(ops[0])?;
            let bits = dest.2 / 2;
            let count = shift_count(ops[2]).unwrap_or(u64::from(bits));
            let upper = matches!(ins.opcode, O::SSHLL2 | O::USHLL2 | O::SHLL2);
            let signed = matches!(ins.opcode, O::SSHLL | O::SSHLL2);
            let (low, high) = widened(halves(vector(ops[1])?), upper, bits, signed);
            let shift = |x: Expr| {
                if count == 0 {
                    x
                } else {
                    lane_shift(LaneOp::ShiftLeft, dest.2, x, count)
                }
            };
            lifter.write_vector(dest, shift(low), shift(high));
        }
        // Lanes of twice the width from lanes of the sources, each extended:
        // both sources, or for the wide forms only the second.
        _ if let Some((form, signed, upper)) = widening(ins.opcode)
            && vector(ops[0]).is_some() =>
        {
            let dest = vector(ops[0])?;
            let wide = dest.2;
            let extend = |operand: (Expr, Expr)| widened(operand, upper, wide / 2, signed);
            let first = halves(vector(ops[1])?);
            let first = if matches!(form, Widening::AddWide | Widening::SubWide) {
                first
            } else {
                extend(first)
            };
            let second = extend(source_halves(ops[2])?);
            let (low, high) = by_halves(first, second, |x, y| match form {
                Widening::Add | Widening::AddWide => lanewise(LaneOp::Add, wide, x, y),
                Widening::Sub | Widening::SubWide => lanewise(LaneOp::Sub, wide, x, y),
                Widening::AbsoluteDifference | Widening::AbsoluteDifferenceAdd => {
                    absolute_difference(wide, signed, x, y)
                }
                Widening::Mul | Widening::MulAdd | Widening::MulSub => {
                    lanewise(LaneOp::Mul, wide, x, y)
                }
            });
            let accumulate = match form {
                Widening::MulAdd | Widening::AbsoluteDifferenceAdd => Some(LaneOp::Add),
                Widening::MulSub => Some(LaneOp::Sub),
                _ => None,
            };
            let (low, high) = match accumulate {
                Some(op) => by_halves(halves(dest), (low, high), |acc, x| {
                    lanewise(op, wide, acc, x)
                }),
                None => (low, high),
            };
            lifter.write_vector(dest, low, high);
        }
        // Lanes cut to half their width, into the low half or, for the
        // second-half forms, the high one.
        _ if let Some((form, upper)) = narrowing(ins.opcode)
            && vector(ops[0]).is_some() =>
        {
            let dest = vector(ops[0])?;
            let wide = vector(ops[1])?.2;
            let narrow = u64::from(wide / 2);
            let source = halves(vector(ops[1])?);
            let value = match form {
                Narrowing::Cut => narrowed(source, wide),
                Narrowing::Held { unsigned } => Expr::apply(
                    Operation::Pack {
                        from: wide,
                        unsigned,
                    },
                    vec![source.0, source.1],
                ),
                Narrowing::HeldUnsigned => {
                    let limit = Expr::constant(replicated(mask_bits(narrow), wide));
                    narrowed(
                        by_halves(source, (limit.clone(), limit), |x, l| {
                            lanewise(LaneOp::MinUnsigned, wide, x, l)
                        }),
                        wide,
                    )
                }
                Narrowing::Shift { rounded } => {
                    let count = shift_count(ops[2])?;
                    let shift = |x: Expr| {
                        let x = if rounded {
                            let round = Expr::constant(replicated(1 << (count - 1), wide));
                            lanewise(LaneOp::Add, wide, x, round)
                        } else {
                            x
                        };
                        lane_shift(LaneOp::ShiftRight, wide, x, count)
                    };
                    narrowed((shift(source.0), shift(source.1)), wide)
                }
                Narrowing::High { op, rounded } => {
                    let round = Expr::constant(replicated(1 << (narrow - 1), wide));
                    let each = by_halves(source, halves(vector(ops[2])?), |x, y| {
                        let value = lanewise(op, wide, x, y);
                        let value = if rounded {
                            lanewise(LaneOp::Add, wide, value, round.clone())
                        } else {
                            value
                        };
                        lane_shift(LaneOp::ShiftRight, wide, value, narrow)
                    });
                    narrowed(each, wide)
                }
            };
            write_narrow(lifter, dest, upper, value);
        }
        // The sums of neighbouring lanes, each extended, in lanes of twice
        // the width, added to the destination for the accumulating forms.
        O::SADDLP | O::UADDLP | O::SADALP | O::UADALP => {
            let dest = vector(ops[0])?;
            let wide = dest.2;
            let bits = u64::from(wide / 2);
            let signed = matches!(ins.opcode, O::SADDLP | O::SADALP);
            let pairs = |x: Expr| {
                let (even, odd) = if signed {
                    (
                        lane_shift(
                            LaneOp::ShiftRightSigned,
                            wide,
                            lane_shift(LaneOp::ShiftLeft, wide, x.clone(), bits),
                            bits,
                        ),
                        lane_shift(LaneOp::ShiftRightSigned, wide, x, bits),
                    )
                } else {
                    (
                        Expr::bin(
                            BinOp::And,
                            x.clone(),
                            Expr::constant(replicated(mask_bits(bits), wide)),
                        ),
                        lane_shift(LaneOp::ShiftRight, wide, x, bits),
                    )
                };
                lanewise(LaneOp::Add, wide, even, odd)
            };
            let (x, y) = halves(vector(ops[1])?);
            let sums = (pairs(x), pairs(y));
            let (low, high) = if matches!(ins.opcode, O::SADALP | O::UADALP) {
                by_halves(halves(dest), sums, |acc, s| {
                    lanewise(LaneOp::Add, wide, acc, s)
                })
            } else {
                sums
            };
            lifter.write_vector(dest, low, high);
        }
        // The lanes in reverse order within each 16-, 32- or 64-bit part,
        // or the bits of each byte.
        O::REV16 | O::REV32 | O::REV64 | O::RBIT if vector(ops[0]).is_some() => {
            let dest = vector(ops[0])?;
            let each = |half: Expr| match ins.opcode {
                O::REV16 => reverse_lanes(half, dest.2, 16),
                O::REV32 => reverse_lanes(half, dest.2, 32),
                O::REV64 => reverse_lanes(half, dest.2, 64),
                _ => Expr::apply(Operation::ReverseBits(64), vec![reverse_lanes(half, 8, 64)]),
            };
            let (low, high) = halves(vector(ops[1])?);
            lifter.write_vector(dest, each(low), each(high));
        }
        _ => return None,
    }
    Some(())
}

use super::{
    BinOp, Cond, Expr, Instruction, LaneOp, Lifter, Mnemonic, OpKind, Operation, Precision,
    Rounding, gpr, hold, load_at, memory_address, operand, xmm,
};

/// 64 bits of `parts` (halves, lowest first) starting at bit `start`, with
/// zeros past the end.
fn window(parts: &[Expr], start: u64) -> Expr {
    let (index, offset) = ((start / 64) as usize, start % 64);
    let Some(first) = parts.get(index) else {
        return Expr::constant(0);
    };
    super::super::windows::window(first, parts.get(index + 1), offset)
}

/// Lane `index` of `bits` from a vector's halves, at the bottom.
fn lane_of((low, high): &(Expr, Expr), index: u64, bits: u64) -> Expr {
    let per_half = 64 / bits;
    let half = if index < per_half { low } else { high };
    let shifted = Expr::bin(
        BinOp::Shr,
        half.clone(),
        Expr::constant((index % per_half) * bits),
    );
    Expr::bin(BinOp::And, shifted, Expr::constant((1 << bits) - 1))
}

/// Lanes placed from the bottom of a half.
fn pack(lanes: Vec<Expr>, bits: u64) -> Expr {
    lanes
        .into_iter()
        .enumerate()
        .map(|(index, lane)| Expr::bin(BinOp::Shl, lane, Expr::constant(index as u64 * bits)))
        .reduce(|out, lane| Expr::bin(BinOp::Or, out, lane))
        .unwrap_or_else(|| Expr::constant(0))
}

pub(super) fn lift_extend(lifter: &mut Lifter, ins: &Instruction) -> Option<()> {
    use Mnemonic::*;
    let (source_bits, destination_bits, signed) = match ins.mnemonic() {
        Pmovzxbw => (8, 16, false),
        Pmovzxbd => (8, 32, false),
        Pmovzxbq => (8, 64, false),
        Pmovzxwd => (16, 32, false),
        Pmovzxwq => (16, 64, false),
        Pmovzxdq => (32, 64, false),
        Pmovsxbw => (8, 16, true),
        Pmovsxbd => (8, 32, true),
        Pmovsxbq => (8, 64, true),
        Pmovsxwd => (16, 32, true),
        Pmovsxwq => (16, 64, true),
        Pmovsxdq => (32, 64, true),
        _ => return None,
    };
    let Some(destination) = xmm(ins.op0_register()) else {
        return None;
    };
    let source = match ins.op1_kind() {
        OpKind::Register => {
            let Some(slot) = xmm(ins.op1_register()) else {
                return None;
            };
            Expr::reg(slot, 64)
        }
        OpKind::Memory => {
            let Some(address) = memory_address(ins) else {
                return None;
            };
            load_at(address, (128 / destination_bits * source_bits / 8) as u8)
        }
        _ => return None,
    };
    let half = |high: bool| {
        pack(
            (0..64 / destination_bits)
                .map(|lane| {
                    let index = lane + u64::from(high) * (64 / destination_bits);
                    let value = lane_of(&(source.clone(), Expr::Const(0)), index, source_bits);
                    let value = if signed {
                        Expr::SignExtend {
                            value: Box::new(value),
                            width: (source_bits / 8) as u8,
                        }
                    } else {
                        value
                    };
                    Expr::bin(
                        BinOp::And,
                        value,
                        Expr::Const(u64::MAX >> (64 - destination_bits)),
                    )
                })
                .collect(),
            destination_bits,
        )
    };
    let high = hold(lifter, half(true));
    lifter.assign(destination, 64, half(false));
    lifter.assign(destination + 1, 64, high);
    Some(())
}

fn lane_operation(mnemonic: Mnemonic) -> Option<(LaneOp, u8)> {
    use Mnemonic::*;
    match mnemonic {
        Paddb => Some((LaneOp::Add, 8)),
        Paddw => Some((LaneOp::Add, 16)),
        Paddd => Some((LaneOp::Add, 32)),
        Psubb => Some((LaneOp::Sub, 8)),
        Psubw => Some((LaneOp::Sub, 16)),
        Psubd => Some((LaneOp::Sub, 32)),
        Pmullw => Some((LaneOp::Mul, 16)),
        Pcmpeqb => Some((LaneOp::Equal, 8)),
        Pcmpeqw => Some((LaneOp::Equal, 16)),
        Pcmpeqd => Some((LaneOp::Equal, 32)),
        Pcmpeqq => Some((LaneOp::Equal, 64)),
        Pcmpgtb => Some((LaneOp::GreaterSigned, 8)),
        Pcmpgtw => Some((LaneOp::GreaterSigned, 16)),
        Pcmpgtd => Some((LaneOp::GreaterSigned, 32)),
        Pminub => Some((LaneOp::MinUnsigned, 8)),
        Pminuw => Some((LaneOp::MinUnsigned, 16)),
        Pminud => Some((LaneOp::MinUnsigned, 32)),
        Pmaxub => Some((LaneOp::MaxUnsigned, 8)),
        Pmaxuw => Some((LaneOp::MaxUnsigned, 16)),
        Pmaxud => Some((LaneOp::MaxUnsigned, 32)),
        Pminsb => Some((LaneOp::MinSigned, 8)),
        Pminsw => Some((LaneOp::MinSigned, 16)),
        Pminsd => Some((LaneOp::MinSigned, 32)),
        Pmaxsb => Some((LaneOp::MaxSigned, 8)),
        Pmaxsw => Some((LaneOp::MaxSigned, 16)),
        Pmaxsd => Some((LaneOp::MaxSigned, 32)),
        Paddsb => Some((LaneOp::AddSaturatingSigned, 8)),
        Paddsw => Some((LaneOp::AddSaturatingSigned, 16)),
        Paddusb => Some((LaneOp::AddSaturatingUnsigned, 8)),
        Paddusw => Some((LaneOp::AddSaturatingUnsigned, 16)),
        Psubsb => Some((LaneOp::SubSaturatingSigned, 8)),
        Psubsw => Some((LaneOp::SubSaturatingSigned, 16)),
        Psubusb => Some((LaneOp::SubSaturatingUnsigned, 8)),
        Psubusw => Some((LaneOp::SubSaturatingUnsigned, 16)),
        Pavgb => Some((LaneOp::Average, 8)),
        Pavgw => Some((LaneOp::Average, 16)),
        Pmulhw => Some((LaneOp::MulHighSigned, 16)),
        Pmulhuw => Some((LaneOp::MulHighUnsigned, 16)),
        _ => None,
    }
}

fn lane_shift(mnemonic: Mnemonic) -> Option<(LaneOp, u8)> {
    use Mnemonic::*;
    match mnemonic {
        Psllw => Some((LaneOp::ShiftLeft, 16)),
        Pslld => Some((LaneOp::ShiftLeft, 32)),
        Psllq => Some((LaneOp::ShiftLeft, 64)),
        Psrlw => Some((LaneOp::ShiftRight, 16)),
        Psrld => Some((LaneOp::ShiftRight, 32)),
        Psrlq => Some((LaneOp::ShiftRight, 64)),
        Psraw => Some((LaneOp::ShiftRightSigned, 16)),
        Psrad => Some((LaneOp::ShiftRightSigned, 32)),
        _ => None,
    }
}

fn interleave_properties(mnemonic: Mnemonic) -> Option<(u8, bool)> {
    use Mnemonic::*;
    match mnemonic {
        Punpcklbw => Some((8, false)),
        Punpcklwd => Some((16, false)),
        Punpckldq => Some((32, false)),
        Punpckhbw => Some((8, true)),
        Punpckhwd => Some((16, true)),
        Punpckhdq => Some((32, true)),
        Unpcklps => Some((32, false)),
        Unpckhps => Some((32, true)),
        _ => None,
    }
}

/// The packed SSE instructions, on each 64-bit half: integer lanes, packed
/// doubles and singles, shuffles, and sign masks.
pub(super) fn lift_packed(lifter: &mut Lifter, ins: &Instruction) -> Option<()> {
    use Mnemonic::*;
    let destination = xmm(ins.op0_register());
    // The halves of an xmm operand or of the 16 bytes at a memory one.
    let halves = |index: u32| -> Option<(Expr, Expr)> {
        match ins.op_kind(index) {
            OpKind::Register => {
                let Some(slot) = xmm(ins.op_register(index)) else {
                    return None;
                };
                Some((Expr::reg(slot, 64), Expr::reg(slot + 1, 64)))
            }
            OpKind::Memory => {
                let Some(addr) = memory_address(ins) else {
                    return None;
                };
                let high = Expr::bin(BinOp::Add, addr.clone(), Expr::constant(8));
                Some((load_at(addr, 8), load_at(high, 8)))
            }
            _ => None,
        }
    };
    // Comparing or subtracting a register with itself, as `pcmpeqd x, x`
    // does to set every bit, reads nothing of it.
    let lanes = |op, bits, a: Expr, b: Expr| match op {
        LaneOp::Equal | LaneOp::GreaterEqualSigned | LaneOp::GreaterEqualUnsigned if a == b => {
            Expr::constant(u64::MAX)
        }
        LaneOp::Sub | LaneOp::GreaterSigned | LaneOp::GreaterUnsigned if a == b => {
            Expr::constant(0)
        }
        _ => Expr::apply(Operation::Lanes(op, bits), vec![a, b]),
    };
    let write = |lifter: &mut Lifter, (low, high): (Expr, Expr)| -> Option<()> {
        let Some(slot) = destination else {
            return None;
        };
        // The high half may read the low one it replaces.
        let high = hold(lifter, high);
        lifter.assign(slot, 64, low);
        lifter.assign(slot + 1, 64, high);
        Some(())
    };
    let lane_op = lane_operation(ins.mnemonic());
    match ins.mnemonic() {
        Pshufb => {
            let Some(source) = halves(0) else {
                return None;
            };
            let Some(control) = halves(1) else {
                return None;
            };
            let shuffle = |mask: Expr| {
                let bytes = (0..8)
                    .map(|index| {
                        let byte = Expr::bin(BinOp::Shr, mask.clone(), Expr::constant(index * 8));
                        let shift = Expr::bin(
                            BinOp::Mul,
                            Expr::bin(BinOp::And, byte.clone(), Expr::constant(7)),
                            Expr::constant(8),
                        );
                        let half = Expr::Select {
                            cond: Cond::Eq,
                            lhs: Box::new(Expr::bin(BinOp::And, byte.clone(), Expr::constant(8))),
                            rhs: Box::new(Expr::constant(0)),
                            then: Box::new(source.0.clone()),
                            els: Box::new(source.1.clone()),
                        };
                        Expr::Select {
                            cond: Cond::Eq,
                            lhs: Box::new(Expr::bin(BinOp::And, byte, Expr::constant(128))),
                            rhs: Box::new(Expr::constant(0)),
                            then: Box::new(Expr::bin(
                                BinOp::And,
                                Expr::bin(BinOp::Shr, half, shift),
                                Expr::constant(255),
                            )),
                            els: Box::new(Expr::constant(0)),
                        }
                    })
                    .collect();
                pack(bytes, 8)
            };
            return write(lifter, (shuffle(control.0), shuffle(control.1)));
        }
        Pinsrb | Pinsrd => {
            let Some(slot) = destination else {
                return None;
            };
            let Some(value) = operand(lifter, ins, 1) else {
                return None;
            };
            let bits = if ins.mnemonic() == Pinsrb { 8 } else { 32 };
            let per_half = 64 / bits;
            let lane = u64::from(ins.immediate8()) & (128 / bits - 1);
            let slot = slot + (lane / per_half) as u16;
            let shift = (lane % per_half) * bits;
            let mask = (1u64 << bits) - 1;
            let value = Expr::bin(BinOp::And, value, Expr::constant(mask));
            lifter.assign(
                slot,
                64,
                Expr::bin(
                    BinOp::Or,
                    Expr::bin(
                        BinOp::And,
                        Expr::reg(slot, 64),
                        Expr::constant(!(mask << shift)),
                    ),
                    Expr::bin(BinOp::Shl, value, Expr::constant(shift)),
                ),
            );
            return Some(());
        }
        _ if lane_op.is_some() => {
            let Some((op, bits)) = lane_op else {
                return None;
            };
            let Some(a) = halves(0) else {
                return None;
            };
            let Some(b) = halves(1) else {
                return None;
            };
            if write(
                lifter,
                (lanes(op, bits, a.0, b.0), lanes(op, bits, a.1, b.1)),
            )
            .is_none()
            {
                return None;
            }
        }
        // An AES round reads the whole state and key for each half.
        Aesenc | Aesenclast | Aesdec | Aesdeclast => {
            let round = match ins.mnemonic() {
                Aesenc => crate::ir::AesRound::Encrypt,
                Aesenclast => crate::ir::AesRound::EncryptLast,
                Aesdec => crate::ir::AesRound::Decrypt,
                _ => crate::ir::AesRound::DecryptLast,
            };
            let Some(state) = halves(0) else {
                return None;
            };
            let Some(key) = halves(1) else {
                return None;
            };
            let half = |high| {
                Expr::apply(
                    Operation::Aes { round, high },
                    vec![
                        state.0.clone(),
                        state.1.clone(),
                        key.0.clone(),
                        key.1.clone(),
                    ],
                )
            };
            if write(lifter, (half(false), half(true))).is_none() {
                return None;
            }
        }
        // Narrowing two sources' lanes into one register, the first's low.
        Packsswb | Packuswb | Packssdw | Packusdw => {
            let (from, unsigned) = match ins.mnemonic() {
                Packsswb => (16, false),
                Packuswb => (16, true),
                Packusdw => (32, true),
                _ => (32, false),
            };
            let Some(a) = halves(0) else {
                return None;
            };
            let Some(b) = halves(1) else {
                return None;
            };
            let pack = |(low, high): (Expr, Expr)| {
                Expr::apply(Operation::Pack { from, unsigned }, vec![low, high])
            };
            if write(lifter, (pack(a), pack(b))).is_none() {
                return None;
            }
        }
        Pmaddwd | Psadbw => {
            let op = if ins.mnemonic() == Pmaddwd {
                Operation::MultiplyAddPairs
            } else {
                Operation::SumAbsoluteDifferences
            };
            let Some(a) = halves(0) else {
                return None;
            };
            let Some(b) = halves(1) else {
                return None;
            };
            if write(
                lifter,
                (
                    Expr::apply(op, vec![a.0, b.0]),
                    Expr::apply(op, vec![a.1, b.1]),
                ),
            )
            .is_none()
            {
                return None;
            }
        }
        Paddq | Psubq | Pmuludq | Pandn => {
            let Some(a) = halves(0) else {
                return None;
            };
            let Some(b) = halves(1) else {
                return None;
            };
            let combine = |x: Expr, y: Expr| match ins.mnemonic() {
                Paddq => Expr::bin(BinOp::Add, x, y),
                Psubq => Expr::bin(BinOp::Sub, x, y),
                // The low 32 bits of each 64-bit lane, multiplied whole.
                Pmuludq => Expr::bin(
                    BinOp::Mul,
                    Expr::bin(BinOp::And, x, Expr::constant(0xffff_ffff)),
                    Expr::bin(BinOp::And, y, Expr::constant(0xffff_ffff)),
                ),
                _ => Expr::bin(
                    BinOp::And,
                    Expr::bin(BinOp::Xor, x, Expr::constant(u64::MAX)),
                    y,
                ),
            };
            if write(lifter, (combine(a.0, b.0), combine(a.1, b.1))).is_none() {
                return None;
            }
        }
        // Shifts of each lane by an immediate or by the low 64 bits of a
        // register.
        Psllw | Pslld | Psllq | Psrlw | Psrld | Psrlq | Psraw | Psrad => {
            let Some((op, bits)) = lane_shift(ins.mnemonic()) else {
                return None;
            };
            let Some(a) = halves(0) else {
                return None;
            };
            let count = match ins.op1_kind() {
                OpKind::Immediate8 => Expr::constant(u64::from(ins.immediate8())),
                _ => {
                    let Some(second_halves) = halves(1) else {
                        return None;
                    };
                    second_halves.0
                }
            };
            let shifted = |half: Expr| lanes(op, bits, half, count.clone());
            if write(lifter, (shifted(a.0), shifted(a.1))).is_none() {
                return None;
            }
        }
        // Whole-register byte shifts.
        Pslldq | Psrldq => {
            let Some((low, high)) = halves(0) else {
                return None;
            };
            let shift_bits = u64::from(ins.immediate8()).min(16) * 8;
            let result = if ins.mnemonic() == Psrldq {
                let parts = [low, high];
                (window(&parts, shift_bits), window(&parts, shift_bits + 64))
            } else {
                let parts = [Expr::constant(0), Expr::constant(0), low, high];
                (
                    window(&parts, 128 - shift_bits),
                    window(&parts, 192 - shift_bits),
                )
            };
            if write(lifter, result).is_none() {
                return None;
            }
        }
        Pshufd => {
            let Some(source) = halves(1) else {
                return None;
            };
            let order = u64::from(ins.immediate8());
            let pick = |index: u64| lane_of(&source, (order >> (2 * index)) & 3, 32);
            if write(
                lifter,
                (
                    pack(vec![pick(0), pick(1)], 32),
                    pack(vec![pick(2), pick(3)], 32),
                ),
            )
            .is_none()
            {
                return None;
            }
        }
        Pshuflw | Pshufhw => {
            let Some(source) = halves(1) else {
                return None;
            };
            let order = u64::from(ins.immediate8());
            let high_half = ins.mnemonic() == Pshufhw;
            let words = if high_half { &source.1 } else { &source.0 };
            let words = (words.clone(), Expr::constant(0));
            let shuffled = pack(
                (0..4)
                    .map(|index| lane_of(&words, (order >> (2 * index)) & 3, 16))
                    .collect(),
                16,
            );
            let result = if high_half {
                (source.0, shuffled)
            } else {
                (shuffled, source.1)
            };
            if write(lifter, result).is_none() {
                return None;
            }
        }
        Punpcklbw | Punpcklwd | Punpckldq | Punpckhbw | Punpckhwd | Punpckhdq | Unpcklps
        | Unpckhps => {
            let Some(a) = halves(0) else {
                return None;
            };
            let Some(b) = halves(1) else {
                return None;
            };
            let Some((bits, high)) = interleave_properties(ins.mnemonic()) else {
                return None;
            };
            let (x, y) = if high { (a.1, b.1) } else { (a.0, b.0) };
            let interleave = |op| Expr::apply(op, vec![x.clone(), y.clone()]);
            if write(
                lifter,
                (
                    interleave(Operation::InterleaveLow(bits)),
                    interleave(Operation::InterleaveHigh(bits)),
                ),
            )
            .is_none()
            {
                return None;
            }
        }
        Punpcklqdq | Unpcklpd | Movlhps => {
            let Some(a) = halves(0) else {
                return None;
            };
            let Some(b) = halves(1) else {
                return None;
            };
            if write(lifter, (a.0, b.0)).is_none() {
                return None;
            }
        }
        Punpckhqdq | Unpckhpd => {
            let Some(a) = halves(0) else {
                return None;
            };
            let Some(b) = halves(1) else {
                return None;
            };
            if write(lifter, (a.1, b.1)).is_none() {
                return None;
            }
        }
        Movhlps => {
            let Some(a) = halves(0) else {
                return None;
            };
            let Some(b) = halves(1) else {
                return None;
            };
            if write(lifter, (b.1, a.1)).is_none() {
                return None;
            }
        }
        // The VEX forms on an xmm register write a general one, as these do.
        Pmovmskb | Movmskpd | Movmskps | Vpmovmskb | Vmovmskpd | Vmovmskps => {
            let Some(source) = halves(1) else {
                return None;
            };
            let bits = match ins.mnemonic() {
                Pmovmskb | Vpmovmskb => 8,
                Movmskps | Vmovmskps => 32,
                _ => 64,
            };
            let signs = |half| Expr::apply(Operation::SignBits(bits), vec![half]);
            let mask = Expr::bin(
                BinOp::Or,
                signs(source.0),
                Expr::bin(
                    BinOp::Shl,
                    signs(source.1),
                    Expr::constant(u64::from(64 / bits)),
                ),
            );
            let Some((index, width)) = gpr(ins.op0_register()) else {
                return None;
            };
            lifter.assign(index, width, mask);
        }
        // The first unless the comparison prefers the second, which a NaN
        // on either side makes it.
        Maxpd | Minpd | Maxps | Minps => {
            let single = matches!(ins.mnemonic(), Maxps | Minps);
            let precision = if single {
                Precision::Single
            } else {
                Precision::Double
            };
            let minimum = matches!(ins.mnemonic(), Minpd | Minps);
            let choose = |x: Expr, y: Expr| {
                let (smaller, larger) = if minimum {
                    (x.clone(), y.clone())
                } else {
                    (y.clone(), x.clone())
                };
                Expr::Select {
                    cond: Cond::Ne,
                    lhs: Box::new(Expr::apply(
                        Operation::FloatLess(precision),
                        vec![smaller, larger],
                    )),
                    rhs: Box::new(Expr::constant(0)),
                    then: Box::new(x),
                    els: Box::new(y),
                }
            };
            let each = |x: &Expr, y: &Expr| {
                if single {
                    let lane =
                        |half: &Expr, index| lane_of(&(half.clone(), Expr::constant(0)), index, 32);
                    pack(
                        (0..2)
                            .map(|index| choose(lane(x, index), lane(y, index)))
                            .collect(),
                        32,
                    )
                } else {
                    choose(x.clone(), y.clone())
                }
            };
            let Some(a) = halves(0) else {
                return None;
            };
            let Some(b) = halves(1) else {
                return None;
            };
            if write(lifter, (each(&a.0, &b.0), each(&a.1, &b.1))).is_none() {
                return None;
            }
        }
        Andnpd | Andnps => {
            let Some(a) = halves(0) else {
                return None;
            };
            let Some(b) = halves(1) else {
                return None;
            };
            let andn = |x: Expr, y: Expr| {
                Expr::bin(
                    BinOp::And,
                    Expr::bin(BinOp::Xor, x, Expr::constant(u64::MAX)),
                    y,
                )
            };
            if write(lifter, (andn(a.0, b.0), andn(a.1, b.1))).is_none() {
                return None;
            }
        }
        // Each source's two doubles summed (or subtracted) into one.
        Haddpd | Hsubpd => {
            let op = if ins.mnemonic() == Haddpd {
                Operation::FloatAdd(Precision::Double)
            } else {
                Operation::FloatSub(Precision::Double)
            };
            let Some(a) = halves(0) else {
                return None;
            };
            let Some(b) = halves(1) else {
                return None;
            };
            if write(
                lifter,
                (
                    Expr::apply(op, vec![a.0, a.1]),
                    Expr::apply(op, vec![b.0, b.1]),
                ),
            )
            .is_none()
            {
                return None;
            }
        }
        Addsubpd => {
            let Some(a) = halves(0) else {
                return None;
            };
            let Some(b) = halves(1) else {
                return None;
            };
            if write(
                lifter,
                (
                    Expr::apply(Operation::FloatSub(Precision::Double), vec![a.0, b.0]),
                    Expr::apply(Operation::FloatAdd(Precision::Double), vec![a.1, b.1]),
                ),
            )
            .is_none()
            {
                return None;
            }
        }
        // Conversions lane by lane, widening from the low half or narrowing
        // into it.
        Cvtdq2pd | Cvtps2pd => {
            let Some(source) = halves(1) else {
                return None;
            };
            let convert = |index| {
                let lane = lane_of(&source, index, 32);
                if ins.mnemonic() == Cvtdq2pd {
                    Expr::apply(
                        Operation::IntToFloat {
                            signed: true,
                            bits: 32,
                            to: Precision::Double,
                        },
                        vec![lane],
                    )
                } else {
                    Expr::apply(
                        Operation::FloatConvert {
                            from: Precision::Single,
                            to: Precision::Double,
                        },
                        vec![lane],
                    )
                }
            };
            if write(lifter, (convert(0), convert(1))).is_none() {
                return None;
            }
        }
        Cvtpd2ps | Cvtpd2dq | Cvttpd2dq => {
            let Some(source) = halves(1) else {
                return None;
            };
            let convert = |half: Expr| match ins.mnemonic() {
                Cvtpd2ps => Expr::apply(
                    Operation::FloatConvert {
                        from: Precision::Double,
                        to: Precision::Single,
                    },
                    vec![half],
                ),
                mnemonic => Expr::apply(
                    Operation::FloatToInt {
                        signed: true,
                        bits: 32,
                        from: Precision::Double,
                        saturating: false,
                        rounding: if mnemonic == Cvttpd2dq {
                            Rounding::TowardZero
                        } else {
                            Rounding::NearestEven
                        },
                    },
                    vec![half],
                ),
            };
            if write(
                lifter,
                (
                    pack(vec![convert(source.0), convert(source.1)], 32),
                    Expr::constant(0),
                ),
            )
            .is_none()
            {
                return None;
            }
        }
        Cvtdq2ps | Cvtps2dq | Cvttps2dq => {
            let Some(source) = halves(1) else {
                return None;
            };
            let convert = |lane: Expr| match ins.mnemonic() {
                Cvtdq2ps => Expr::apply(
                    Operation::IntToFloat {
                        signed: true,
                        bits: 32,
                        to: Precision::Single,
                    },
                    vec![lane],
                ),
                mnemonic => Expr::apply(
                    Operation::FloatToInt {
                        signed: true,
                        bits: 32,
                        from: Precision::Single,
                        saturating: false,
                        rounding: if mnemonic == Cvttps2dq {
                            Rounding::TowardZero
                        } else {
                            Rounding::NearestEven
                        },
                    },
                    vec![lane],
                ),
            };
            let half = |index: u64| {
                pack(
                    vec![
                        convert(lane_of(&source, index, 32)),
                        convert(lane_of(&source, index + 1, 32)),
                    ],
                    32,
                )
            };
            if write(lifter, (half(0), half(2))).is_none() {
                return None;
            }
        }
        Addpd | Subpd | Mulpd | Divpd | Addps | Subps | Mulps | Divps | Sqrtpd | Sqrtps => {
            let single = matches!(ins.mnemonic(), Addps | Subps | Mulps | Divps | Sqrtps);
            let precision = if single {
                Precision::Single
            } else {
                Precision::Double
            };
            let op = match ins.mnemonic() {
                Addpd | Addps => Operation::FloatAdd(precision),
                Subpd | Subps => Operation::FloatSub(precision),
                Mulpd | Mulps => Operation::FloatMul(precision),
                Divpd | Divps => Operation::FloatDiv(precision),
                _ => Operation::FloatSqrt(precision),
            };
            let unary = matches!(ins.mnemonic(), Sqrtpd | Sqrtps);
            let Some(b) = halves(1) else {
                return None;
            };
            let a = if unary {
                b.clone()
            } else {
                match halves(0) {
                    Some(value) => value,
                    None => return None,
                }
            };
            // A double fills a half; singles take its two 32-bit lanes.
            let each = |x: &Expr, y: &Expr| {
                let args = |x: Expr, y: Expr| if unary { vec![y] } else { vec![x, y] };
                if single {
                    let lane =
                        |half: &Expr, index| lane_of(&(half.clone(), Expr::constant(0)), index, 32);
                    pack(
                        (0..2)
                            .map(|index| Expr::apply(op, args(lane(x, index), lane(y, index))))
                            .collect(),
                        32,
                    )
                } else {
                    Expr::apply(op, args(x.clone(), y.clone()))
                }
            };
            if write(lifter, (each(&a.0, &b.0), each(&a.1, &b.1))).is_none() {
                return None;
            }
        }
        _ => return None,
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_match_adjacent_half_expressions() {
        let parts = [Expr::reg(0, 64), Expr::reg(1, 64), Expr::reg(2, 64)];
        for count in 1..=parts.len() {
            for start in 0..(count as u64 * 64) {
                let (index, offset) = ((start / 64) as usize, start % 64);
                let low = Expr::bin(BinOp::Shr, parts[index].clone(), Expr::Const(offset));
                let expected = match parts[..count].get(index + 1) {
                    Some(next) if offset > 0 => Expr::bin(
                        BinOp::Or,
                        low,
                        Expr::bin(BinOp::Shl, next.clone(), Expr::Const(64 - offset)),
                    ),
                    _ => low,
                };
                assert_eq!(window(&parts[..count], start), expected);
            }
        }
    }

    #[test]
    fn windows_zero_fill_past_the_last_half() {
        for parts in [vec![], vec![Expr::reg(0, 64)]] {
            for start in [parts.len() as u64 * 64, 128, u64::MAX] {
                assert_eq!(window(&parts, start), Expr::Const(0));
            }
        }
    }

    #[test]
    fn packed_properties_match_all_mnemonics() {
        use Mnemonic::*;
        for mnemonic in Mnemonic::values() {
            let name = format!("{mnemonic:?}");
            let bits = match name.chars().last() {
                Some('b') => 8,
                Some('w') => 16,
                Some('d') => 32,
                _ => 64,
            };
            let operation = match mnemonic {
                Paddb | Paddw | Paddd => Some(LaneOp::Add),
                Psubb | Psubw | Psubd => Some(LaneOp::Sub),
                Pmullw => Some(LaneOp::Mul),
                Pcmpeqb | Pcmpeqw | Pcmpeqd | Pcmpeqq => Some(LaneOp::Equal),
                Pcmpgtb | Pcmpgtw | Pcmpgtd => Some(LaneOp::GreaterSigned),
                Pminub | Pminuw | Pminud => Some(LaneOp::MinUnsigned),
                Pmaxub | Pmaxuw | Pmaxud => Some(LaneOp::MaxUnsigned),
                Pminsb | Pminsw | Pminsd => Some(LaneOp::MinSigned),
                Pmaxsb | Pmaxsw | Pmaxsd => Some(LaneOp::MaxSigned),
                Paddsb | Paddsw => Some(LaneOp::AddSaturatingSigned),
                Paddusb | Paddusw => Some(LaneOp::AddSaturatingUnsigned),
                Psubsb | Psubsw => Some(LaneOp::SubSaturatingSigned),
                Psubusb | Psubusw => Some(LaneOp::SubSaturatingUnsigned),
                Pavgb | Pavgw => Some(LaneOp::Average),
                Pmulhw => Some(LaneOp::MulHighSigned),
                Pmulhuw => Some(LaneOp::MulHighUnsigned),
                _ => None,
            };
            assert_eq!(
                lane_operation(mnemonic),
                operation.map(|op| (op, bits)),
                "{mnemonic:?}"
            );
            let shift = match mnemonic {
                Psllw | Pslld | Psllq => Some(LaneOp::ShiftLeft),
                Psrlw | Psrld | Psrlq => Some(LaneOp::ShiftRight),
                Psraw | Psrad => Some(LaneOp::ShiftRightSigned),
                _ => None,
            };
            assert_eq!(
                lane_shift(mnemonic),
                shift.map(|op| (op, bits)),
                "{mnemonic:?}"
            );
            let interleave = match mnemonic {
                Punpcklbw | Punpcklwd | Punpckldq | Punpckhbw | Punpckhwd | Punpckhdq
                | Unpcklps | Unpckhps => {
                    let bits = match &name[name.len() - 2..] {
                        "bw" => 8,
                        "wd" => 16,
                        _ => 32,
                    };
                    Some((bits, name.starts_with("Punpckh") || name == "Unpckhps"))
                }
                _ => None,
            };
            assert_eq!(interleave_properties(mnemonic), interleave, "{mnemonic:?}");
        }
    }
}

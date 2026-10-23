use super::{
    BinOp, Cond, Expr, Instruction, LaneOp, Lifter, Mnemonic, OpKind, Operation, Precision,
    Rounding, gpr, hold, load_at, memory_address, xmm,
};

/// 64 bits of `parts` (halves, lowest first) starting at bit `start`, with
/// zeros past the end.
fn window(parts: &[Expr], start: u64) -> Expr {
    let (index, offset) = ((start / 64) as usize, start % 64);
    let Some(first) = parts.get(index) else {
        return Expr::constant(0);
    };
    let low = Expr::bin(BinOp::Shr, first.clone(), Expr::constant(offset));
    match parts.get(index + 1) {
        Some(next) if offset > 0 => Expr::bin(
            BinOp::Or,
            low,
            Expr::bin(BinOp::Shl, next.clone(), Expr::constant(64 - offset)),
        ),
        _ => low,
    }
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

/// The packed SSE instructions, on each 64-bit half: integer lanes, packed
/// doubles and singles, shuffles, and sign masks.
pub(super) fn lift_packed(lifter: &mut Lifter, ins: &Instruction) -> Option<()> {
    use Mnemonic::*;
    let destination = xmm(ins.op0_register());
    // The halves of an xmm operand or of the 16 bytes at a memory one.
    let halves = |index: u32| -> Option<(Expr, Expr)> {
        match ins.op_kind(index) {
            OpKind::Register => {
                let slot = xmm(ins.op_register(index))?;
                Some((Expr::reg(slot, 64), Expr::reg(slot + 1, 64)))
            }
            OpKind::Memory => {
                let addr = memory_address(ins)?;
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
        let slot = destination?;
        // The high half may read the low one it replaces.
        let high = hold(lifter, high);
        lifter.assign(slot, 64, low);
        lifter.assign(slot + 1, 64, high);
        Some(())
    };
    let lane_op = match ins.mnemonic() {
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
    let lane_bits = |mnemonic: Mnemonic| -> u8 {
        let name = format!("{mnemonic:?}");
        match name.chars().last() {
            Some('b') => 8,
            Some('w') => 16,
            Some('d') => 32,
            _ => 64,
        }
    };
    match ins.mnemonic() {
        _ if lane_op.is_some() => {
            let op = lane_op?;
            let bits = lane_bits(ins.mnemonic());
            let (a, b) = (halves(0)?, halves(1)?);
            write(
                lifter,
                (lanes(op, bits, a.0, b.0), lanes(op, bits, a.1, b.1)),
            )?;
        }
        // An AES round reads the whole state and key for each half.
        Aesenc | Aesenclast | Aesdec | Aesdeclast => {
            let round = match ins.mnemonic() {
                Aesenc => crate::ir::AesRound::Encrypt,
                Aesenclast => crate::ir::AesRound::EncryptLast,
                Aesdec => crate::ir::AesRound::Decrypt,
                _ => crate::ir::AesRound::DecryptLast,
            };
            let (state, key) = (halves(0)?, halves(1)?);
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
            write(lifter, (half(false), half(true)))?;
        }
        // Narrowing two sources' lanes into one register, the first's low.
        Packsswb | Packuswb | Packssdw => {
            let (from, unsigned) = match ins.mnemonic() {
                Packsswb => (16, false),
                Packuswb => (16, true),
                _ => (32, false),
            };
            let (a, b) = (halves(0)?, halves(1)?);
            let pack = |(low, high): (Expr, Expr)| {
                Expr::apply(Operation::Pack { from, unsigned }, vec![low, high])
            };
            write(lifter, (pack(a), pack(b)))?;
        }
        Pmaddwd | Psadbw => {
            let op = if ins.mnemonic() == Pmaddwd {
                Operation::MultiplyAddPairs
            } else {
                Operation::SumAbsoluteDifferences
            };
            let (a, b) = (halves(0)?, halves(1)?);
            write(
                lifter,
                (
                    Expr::apply(op, vec![a.0, b.0]),
                    Expr::apply(op, vec![a.1, b.1]),
                ),
            )?;
        }
        Paddq | Psubq | Pmuludq | Pandn => {
            let (a, b) = (halves(0)?, halves(1)?);
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
            write(lifter, (combine(a.0, b.0), combine(a.1, b.1)))?;
        }
        // Shifts of each lane by an immediate or by the low 64 bits of a
        // register.
        Psllw | Pslld | Psllq | Psrlw | Psrld | Psrlq | Psraw | Psrad => {
            let bits = lane_bits(ins.mnemonic());
            let a = halves(0)?;
            let count = match ins.op1_kind() {
                OpKind::Immediate8 => Expr::constant(u64::from(ins.immediate8())),
                _ => halves(1)?.0,
            };
            let op = match ins.mnemonic() {
                Psllw | Pslld | Psllq => LaneOp::ShiftLeft,
                Psrlw | Psrld | Psrlq => LaneOp::ShiftRight,
                _ => LaneOp::ShiftRightSigned,
            };
            let shifted = |half: Expr| {
                if bits == 64 && op != LaneOp::ShiftRightSigned {
                    lanes(op, 64, half, count.clone())
                } else {
                    lanes(op, bits, half, count.clone())
                }
            };
            write(lifter, (shifted(a.0), shifted(a.1)))?;
        }
        // Whole-register byte shifts.
        Pslldq | Psrldq => {
            let (low, high) = halves(0)?;
            let bytes = u64::from(ins.immediate8()).min(16) * 8;
            let result = if ins.mnemonic() == Psrldq {
                let parts = [low, high];
                (window(&parts, bytes), window(&parts, bytes + 64))
            } else {
                let parts = [Expr::constant(0), Expr::constant(0), low, high];
                (window(&parts, 128 - bytes), window(&parts, 192 - bytes))
            };
            write(lifter, result)?;
        }
        Pshufd => {
            let source = halves(1)?;
            let order = u64::from(ins.immediate8());
            let pick = |index: u64| lane_of(&source, (order >> (2 * index)) & 3, 32);
            write(
                lifter,
                (
                    pack(vec![pick(0), pick(1)], 32),
                    pack(vec![pick(2), pick(3)], 32),
                ),
            )?;
        }
        Pshuflw | Pshufhw => {
            let source = halves(1)?;
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
            write(lifter, result)?;
        }
        Punpcklbw | Punpcklwd | Punpckldq | Punpckhbw | Punpckhwd | Punpckhdq | Unpcklps
        | Unpckhps => {
            let (a, b) = (halves(0)?, halves(1)?);
            let name = format!("{:?}", ins.mnemonic());
            let bits = match &name[name.len() - 2..] {
                "bw" => 8,
                "wd" => 16,
                _ => 32,
            };
            let (x, y) = if name.starts_with("Punpckh") || name == "Unpckhps" {
                (a.1, b.1)
            } else {
                (a.0, b.0)
            };
            let interleave = |op| Expr::apply(op, vec![x.clone(), y.clone()]);
            write(
                lifter,
                (
                    interleave(Operation::InterleaveLow(bits)),
                    interleave(Operation::InterleaveHigh(bits)),
                ),
            )?;
        }
        Punpcklqdq | Unpcklpd | Movlhps => {
            let (a, b) = (halves(0)?, halves(1)?);
            write(lifter, (a.0, b.0))?;
        }
        Punpckhqdq | Unpckhpd => {
            let (a, b) = (halves(0)?, halves(1)?);
            write(lifter, (a.1, b.1))?;
        }
        Movhlps => {
            let (a, b) = (halves(0)?, halves(1)?);
            write(lifter, (b.1, a.1))?;
        }
        // The VEX forms on an xmm register write a general one, as these do.
        Pmovmskb | Movmskpd | Movmskps | Vpmovmskb | Vmovmskpd | Vmovmskps => {
            let source = halves(1)?;
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
            let (index, width) = gpr(ins.op0_register())?;
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
            let (a, b) = (halves(0)?, halves(1)?);
            write(lifter, (each(&a.0, &b.0), each(&a.1, &b.1)))?;
        }
        Andnpd | Andnps => {
            let (a, b) = (halves(0)?, halves(1)?);
            let andn = |x: Expr, y: Expr| {
                Expr::bin(
                    BinOp::And,
                    Expr::bin(BinOp::Xor, x, Expr::constant(u64::MAX)),
                    y,
                )
            };
            write(lifter, (andn(a.0, b.0), andn(a.1, b.1)))?;
        }
        // Each source's two doubles summed (or subtracted) into one.
        Haddpd | Hsubpd => {
            let op = if ins.mnemonic() == Haddpd {
                Operation::FloatAdd(Precision::Double)
            } else {
                Operation::FloatSub(Precision::Double)
            };
            let (a, b) = (halves(0)?, halves(1)?);
            write(
                lifter,
                (
                    Expr::apply(op, vec![a.0, a.1]),
                    Expr::apply(op, vec![b.0, b.1]),
                ),
            )?;
        }
        Addsubpd => {
            let (a, b) = (halves(0)?, halves(1)?);
            write(
                lifter,
                (
                    Expr::apply(Operation::FloatSub(Precision::Double), vec![a.0, b.0]),
                    Expr::apply(Operation::FloatAdd(Precision::Double), vec![a.1, b.1]),
                ),
            )?;
        }
        // Conversions lane by lane, widening from the low half or narrowing
        // into it.
        Cvtdq2pd | Cvtps2pd => {
            let source = halves(1)?;
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
            write(lifter, (convert(0), convert(1)))?;
        }
        Cvtpd2ps | Cvtpd2dq | Cvttpd2dq => {
            let source = halves(1)?;
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
            write(
                lifter,
                (
                    pack(vec![convert(source.0), convert(source.1)], 32),
                    Expr::constant(0),
                ),
            )?;
        }
        Cvtdq2ps | Cvtps2dq | Cvttps2dq => {
            let source = halves(1)?;
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
            write(lifter, (half(0), half(2)))?;
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
            let b = halves(1)?;
            let a = if unary { b.clone() } else { halves(0)? };
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
            write(lifter, (each(&a.0, &b.0), each(&a.1, &b.1)))?;
        }
        _ => return None,
    }
    Some(())
}

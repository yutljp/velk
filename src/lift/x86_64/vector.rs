use super::{
    BinOp, EncodingKind, Expr, Instruction, LaneOp, Lifter, Mnemonic, OpKind, Operation, Register,
    Stmt, Write, gpr, hold, load_at, memory_address, operand, preserve_compare, xmm,
};

/// The vector moves and bitwise operations: on the halves of an xmm
/// register, or the quarters of a ymm one. A VEX instruction that writes an
/// xmm register clears the bits above it. None, with nothing lifted, for
/// any other instruction.
pub(super) fn lift_vector(lifter: &mut Lifter, ins: &Instruction) -> Option<()> {
    use crate::arch::x86::upper;
    let clear_upper = |lifter: &mut Lifter, slot: u16| {
        lifter.assign(upper(slot), 64, Expr::constant(0));
        lifter.assign(upper(slot) + 1, 64, Expr::constant(0));
    };
    match ins.mnemonic() {
        Mnemonic::Vzeroupper => {
            for register in 0..16 {
                clear_upper(lifter, crate::arch::x86::XMM0 + 2 * register);
            }
            return Some(());
        }
        Mnemonic::Vzeroall => {
            for register in 0..16 {
                let slot = crate::arch::x86::XMM0 + 2 * register;
                lifter.assign(slot, 64, Expr::constant(0));
                lifter.assign(slot + 1, 64, Expr::constant(0));
                clear_upper(lifter, slot);
            }
            return Some(());
        }
        _ => {}
    }
    if (0..ins.op_count()).any(|index| {
        ins.op_kind(index) == OpKind::Register
            && (ins.op_register(index).is_ymm() || ins.op_register(index).is_zmm())
    }) {
        return lift_ymm(lifter, ins);
    }
    lift_xmm(lifter, ins)?;
    if ins.encoding() != EncodingKind::Legacy
        && ins.mnemonic() != Mnemonic::Vptest
        && ins.op0_kind() == OpKind::Register
        && let Some(slot) = xmm(ins.op0_register())
    {
        clear_upper(lifter, slot);
    }
    Some(())
}

/// The ymm register's slots, lowest quarter first.
fn ymm(reg: Register) -> Option<[u16; 4]> {
    (reg.is_ymm() && reg.number() < 16).then(|| {
        let low = crate::arch::x86::XMM0 + 2 * reg.number() as u16;
        let high = crate::arch::x86::upper(low);
        [low, low + 1, high, high + 1]
    })
}

/// The 256-bit moves, bitwise operations and byte compares, each quarter
/// from the same quarter of the sources.
fn lift_ymm(lifter: &mut Lifter, ins: &Instruction) -> Option<()> {
    use Mnemonic::*;
    // The quarters of a ymm operand or of the 32 bytes at a memory one.
    let quarters = |index: u32| -> Option<[Expr; 4]> {
        match ins.op_kind(index) {
            OpKind::Register => {
                Some(ymm(ins.op_register(index))?.map(|slot| Lifter::read_reg(slot, 64)))
            }
            OpKind::Memory => {
                let addr = memory_address(ins)?;
                Some(std::array::from_fn(|quarter| {
                    load_at(
                        Expr::bin(BinOp::Add, addr.clone(), Expr::constant(8 * quarter as u64)),
                        8,
                    )
                }))
            }
            _ => None,
        }
    };
    let write = |lifter: &mut Lifter, values: [Expr; 4]| -> Option<()> {
        let slots = ymm(ins.op0_register())?;
        for (slot, value) in slots.into_iter().zip(values) {
            lifter.assign(slot, 64, value);
        }
        Some(())
    };
    match ins.mnemonic() {
        Vptest => {
            let Some(a) = quarters(0) else {
                return None;
            };
            let Some(b) = quarters(1) else {
                return None;
            };
            test_bits(lifter, &a, &b);
        }
        Vmovdqu | Vmovdqu8 | Vmovdqu16 | Vmovdqu32 | Vmovdqu64 | Vmovdqa | Vmovdqa32
        | Vmovdqa64 | Vmovntdq | Vmovups | Vmovaps | Vmovupd | Vmovapd | Vmovntps | Vmovntpd
        | Vlddqu => match ins.op0_kind() {
            OpKind::Memory => {
                let addr = memory_address(ins)?;
                let values = quarters(1)?;
                preserve_compare(&mut lifter.last_compare, Write::Memory, &mut lifter.stmts);
                for (quarter, value) in values.into_iter().enumerate() {
                    lifter.stmts.push(Stmt::Store {
                        addr: Expr::bin(
                            BinOp::Add,
                            addr.clone(),
                            Expr::constant(8 * quarter as u64),
                        ),
                        value,
                        width: 8,
                    });
                }
            }
            _ => write(lifter, quarters(1)?)?,
        },
        Vpxor | Vpand | Vpor | Vpandn | Vxorps | Vxorpd | Vandps | Vandpd | Vorps | Vorpd
        | Vpcmpeqb | Vpcmpeqw | Vpcmpeqd | Vpcmpeqq | Vpaddb | Vpaddw | Vpaddd | Vpaddq
        | Vpsubb | Vpsubw | Vpsubd | Vpsubq | Vpminub | Vpmaxub
            if ins.op_count() == 3 =>
        {
            let (a, b) = (quarters(1)?, quarters(2)?);
            let mnemonic = ins.mnemonic();
            let combine = |x: Expr, y: Expr| match mnemonic {
                Vpxor | Vxorps | Vxorpd => Expr::bin(BinOp::Xor, x, y),
                Vpand | Vandps | Vandpd => Expr::bin(BinOp::And, x, y),
                Vpandn => Expr::bin(
                    BinOp::And,
                    Expr::bin(BinOp::Xor, x, Expr::constant(u64::MAX)),
                    y,
                ),
                Vpor | Vorps | Vorpd => Expr::bin(BinOp::Or, x, y),
                Vpaddq => Expr::bin(BinOp::Add, x, y),
                Vpsubq => Expr::bin(BinOp::Sub, x, y),
                other => {
                    let (op, bits) = match other {
                        Vpcmpeqb => (LaneOp::Equal, 8),
                        Vpcmpeqw => (LaneOp::Equal, 16),
                        Vpcmpeqd => (LaneOp::Equal, 32),
                        Vpcmpeqq => (LaneOp::Equal, 64),
                        Vpaddb => (LaneOp::Add, 8),
                        Vpaddw => (LaneOp::Add, 16),
                        Vpaddd => (LaneOp::Add, 32),
                        Vpsubb => (LaneOp::Sub, 8),
                        Vpsubw => (LaneOp::Sub, 16),
                        Vpsubd => (LaneOp::Sub, 32),
                        Vpminub => (LaneOp::MinUnsigned, 8),
                        _ => (LaneOp::MaxUnsigned, 8),
                    };
                    Expr::apply(Operation::Lanes(op, bits), vec![x, y])
                }
            };
            let [a0, a1, a2, a3] = a;
            let [b0, b1, b2, b3] = b;
            write(
                lifter,
                [
                    combine(a0, b0),
                    combine(a1, b1),
                    combine(a2, b2),
                    combine(a3, b3),
                ],
            )?;
        }
        // The top bit of each byte, lowest byte first.
        Vpmovmskb => {
            let (index, width) = gpr(ins.op0_register())?;
            let [q0, q1, q2, q3] = quarters(1)?;
            let mask = |quarter: Expr, shift: u64| {
                Expr::bin(
                    BinOp::Shl,
                    Expr::apply(Operation::SignBits(8), vec![quarter]),
                    Expr::constant(shift),
                )
            };
            let value = [mask(q1, 8), mask(q2, 16), mask(q3, 24)].into_iter().fold(
                Expr::apply(Operation::SignBits(8), vec![q0]),
                |sum, part| Expr::bin(BinOp::Or, sum, part),
            );
            lifter.assign(index, width, value);
        }
        // The low byte of the source in every byte.
        Vpbroadcastb => {
            let byte = match ins.op1_kind() {
                OpKind::Register => Lifter::read_reg(xmm(ins.op1_register())?, 64),
                OpKind::Memory => load_at(memory_address(ins)?, 1),
                _ => return None,
            };
            let spread = Expr::bin(
                BinOp::Mul,
                Expr::bin(BinOp::And, byte, Expr::constant(0xff)),
                Expr::constant(0x0101_0101_0101_0101),
            );
            write(lifter, std::array::from_fn(|_| spread.clone()))?;
        }
        _ => return None,
    }
    Some(())
}

fn test_bits(lifter: &mut Lifter, a: &[Expr], b: &[Expr]) {
    let test = |invert| {
        let value = a
            .iter()
            .zip(b)
            .map(|(a, b)| {
                let a = if invert {
                    Expr::bin(BinOp::Xor, a.clone(), Expr::constant(u64::MAX))
                } else {
                    a.clone()
                };
                Expr::bin(BinOp::And, a, b.clone())
            })
            .reduce(|a, b| Expr::bin(BinOp::Or, a, b))
            .unwrap_or(Expr::constant(0));
        Expr::Select {
            cond: super::Cond::Eq,
            lhs: Box::new(value),
            rhs: Box::new(Expr::constant(0)),
            then: Box::new(Expr::constant(1)),
            els: Box::new(Expr::constant(0)),
        }
    };
    let byte = Expr::bin(
        BinOp::Or,
        test(true),
        Expr::bin(BinOp::Shl, test(false), Expr::constant(6)),
    );
    lifter.set_flags(super::Flags::stored(byte, Some(Expr::constant(0))));
}

/// The SSE moves and bitwise operations, on the 64-bit halves of each xmm
/// register. None, with nothing lifted, for any other instruction.
fn lift_xmm(lifter: &mut Lifter, ins: &Instruction) -> Option<()> {
    use Mnemonic::*;
    let destination = xmm(ins.op0_register());
    let source = xmm(ins.op1_register());
    let address = || memory_address(ins);
    let offset = |addr: Expr| Expr::bin(BinOp::Add, addr, Expr::constant(8));
    let low = |slot: u16| Lifter::read_reg(slot, 64);
    if matches!(ins.mnemonic(), Ptest | Vptest) {
        let Some(a) = destination else {
            return None;
        };
        let b = match ins.op1_kind() {
            OpKind::Register => {
                let Some(b) = source else {
                    return None;
                };
                [low(b), low(b + 1)]
            }
            OpKind::Memory => {
                let Some(addr) = address() else {
                    return None;
                };
                [load_at(addr.clone(), 8), load_at(offset(addr), 8)]
            }
            _ => return None,
        };
        test_bits(lifter, &[low(a), low(a + 1)], &b);
        return Some(());
    }
    let store = |lifter: &mut Lifter, addr: Expr, value: Expr, width: u8| {
        preserve_compare(&mut lifter.last_compare, Write::Memory, &mut lifter.stmts);
        lifter.stmts.push(Stmt::Store { addr, value, width });
    };
    // A VEX move of a 128-bit register, or a non-temporal one, moves as the
    // plain one does; the IR keeps no bits above 128.
    let narrow = (0..ins.op_count()).all(|index| {
        ins.op_kind(index) != OpKind::Register
            || !ins.op_register(index).is_ymm() && !ins.op_register(index).is_zmm()
    });
    let mnemonic = match ins.mnemonic() {
        Vmovdqu | Vmovdqu8 | Vmovdqu16 | Vmovdqu32 | Vmovdqu64 if narrow => Movdqu,
        Vmovdqa | Vmovdqa32 | Vmovdqa64 | Vmovntdq | Movntdq if narrow => Movdqa,
        Vmovups if narrow => Movups,
        Vmovaps | Vmovntps | Movntps if narrow => Movaps,
        Vmovupd if narrow => Movupd,
        Vmovapd | Vmovntpd | Movntpd if narrow => Movapd,
        other => other,
    };
    match (mnemonic, ins.op0_kind(), ins.op1_kind()) {
        // A VEX bitwise operation names two sources apart from its destination.
        (
            Vpxor | Vpand | Vpor | Vpandn | Vxorps | Vxorpd | Vandps | Vandpd | Vorps | Vorpd,
            OpKind::Register,
            OpKind::Register,
        ) if narrow && ins.op_count() == 3 => {
            let (to, first) = (destination?, source?);
            let (second_low, second_high) = match ins.op2_kind() {
                OpKind::Register => {
                    let slot = xmm(ins.op2_register())?;
                    (low(slot), low(slot + 1))
                }
                OpKind::Memory => {
                    let addr = address()?;
                    (load_at(addr.clone(), 8), load_at(offset(addr), 8))
                }
                _ => return None,
            };
            let combine = |a: Expr, b: Expr| match mnemonic {
                Vpxor | Vxorps | Vxorpd => Expr::bin(BinOp::Xor, a, b),
                Vpand | Vandps | Vandpd => Expr::bin(BinOp::And, a, b),
                Vpandn => Expr::bin(
                    BinOp::And,
                    Expr::bin(BinOp::Xor, a, Expr::constant(u64::MAX)),
                    b,
                ),
                _ => Expr::bin(BinOp::Or, a, b),
            };
            let low_half = combine(low(first), second_low);
            let high_half = hold(lifter, combine(low(first + 1), second_high));
            lifter.assign(to, 64, low_half);
            lifter.assign(to + 1, 64, high_half);
        }
        // One 16-bit lane written from a general register or memory, or read
        // out to a general register.
        (Pinsrw | Vpinsrw, OpKind::Register, _) if narrow => {
            let to = destination?;
            let value_index = if mnemonic == Vpinsrw { 2 } else { 1 };
            let value = match ins.op_kind(value_index) {
                OpKind::Memory => load_at(address()?, 2),
                _ => operand(lifter, ins, value_index)?,
            };
            let lane = u64::from(ins.immediate8()) & 7;
            let (slot, shift) = (to + (lane / 4) as u16, (lane % 4) * 16);
            let base = if mnemonic == Vpinsrw {
                low(source? + (lane / 4) as u16)
            } else {
                low(slot)
            };
            let merged = Expr::bin(
                BinOp::Or,
                Expr::bin(BinOp::And, base, Expr::constant(!(0xffff << shift))),
                Expr::bin(
                    BinOp::Shl,
                    Expr::bin(BinOp::And, value, Expr::constant(0xffff)),
                    Expr::constant(shift),
                ),
            );
            if mnemonic == Vpinsrw {
                let from = source?;
                let other = hold(lifter, low(from + 1 - (lane / 4) as u16));
                lifter.assign(slot, 64, merged);
                lifter.assign(to + 1 - (lane / 4) as u16, 64, other);
            } else {
                lifter.assign(slot, 64, merged);
            }
        }
        (Pextrw | Vpextrw, OpKind::Register, OpKind::Register) if narrow && source.is_some() => {
            let from = source?;
            let lane = u64::from(ins.immediate8()) & 7;
            let value = Expr::bin(
                BinOp::And,
                Expr::bin(
                    BinOp::Shr,
                    low(from + (lane / 4) as u16),
                    Expr::constant((lane % 4) * 16),
                ),
                Expr::constant(0xffff),
            );
            let (index, width) = gpr(ins.op0_register())?;
            lifter.assign(index, width, value);
        }
        (
            Movups | Movaps | Movupd | Movapd | Movdqu | Movdqa,
            OpKind::Register,
            OpKind::Register,
        ) => {
            let (to, from) = (destination?, source?);
            lifter.assign(to, 64, low(from));
            lifter.assign(to + 1, 64, low(from + 1));
        }
        (Movups | Movaps | Movupd | Movapd | Movdqu | Movdqa, OpKind::Register, OpKind::Memory) => {
            let (to, addr) = (destination?, address()?);
            lifter.assign(to, 64, load_at(addr.clone(), 8));
            lifter.assign(to + 1, 64, load_at(offset(addr), 8));
        }
        (Movups | Movaps | Movupd | Movapd | Movdqu | Movdqa, OpKind::Memory, OpKind::Register) => {
            let (from, addr) = (source?, address()?);
            store(lifter, addr.clone(), low(from), 8);
            store(lifter, offset(addr), low(from + 1), 8);
        }
        (Xorps | Xorpd | Pxor | Andps | Andpd | Pand | Orps | Orpd | Por, OpKind::Register, _) => {
            let to = destination?;
            let op = match ins.mnemonic() {
                Xorps | Xorpd | Pxor => BinOp::Xor,
                Andps | Andpd | Pand => BinOp::And,
                _ => BinOp::Or,
            };
            let (first, second) = match ins.op1_kind() {
                OpKind::Register => {
                    let from = source?;
                    (low(from), low(from + 1))
                }
                OpKind::Memory => {
                    let addr = address()?;
                    (load_at(addr.clone(), 8), load_at(offset(addr), 8))
                }
                _ => return None,
            };
            let cleared =
                op == BinOp::Xor && ins.op1_kind() == OpKind::Register && source == destination;
            let combine = |slot: u16, value: Expr| {
                if cleared {
                    Expr::constant(0)
                } else {
                    Expr::bin(op, low(slot), value)
                }
            };
            let (first, second) = (combine(to, first), combine(to + 1, second));
            lifter.assign(to, 64, first);
            lifter.assign(to + 1, 64, second);
        }
        // A scalar load clears the rest of the register; a move between
        // registers keeps it.
        (Movq | Movd | Movsd | Movss, OpKind::Register, OpKind::Register | OpKind::Memory)
            if destination.is_some() =>
        {
            let to = destination?;
            let width = match ins.mnemonic() {
                Movd | Movss => 4,
                _ => 8,
            };
            let value = match (ins.op1_kind(), source) {
                (OpKind::Memory, _) => load_at(address()?, width),
                (_, Some(from)) => Lifter::read_reg(from, width * 8),
                (_, None) => operand(lifter, ins, 1)?,
            };
            let keeps = source.is_some() && matches!(ins.mnemonic(), Movsd | Movss);
            let value = if keeps && width == 4 {
                Expr::bin(
                    BinOp::Or,
                    Expr::bin(BinOp::And, low(to), Expr::constant(!0xffff_ffff)),
                    value,
                )
            } else {
                value
            };
            lifter.assign(to, 64, value);
            if !keeps {
                lifter.assign(to + 1, 64, Expr::constant(0));
            }
        }
        (Movq | Movd | Movsd | Movss, OpKind::Register | OpKind::Memory, OpKind::Register)
            if source.is_some() =>
        {
            let from = source?;
            let width = match ins.mnemonic() {
                Movd | Movss => 4,
                _ => 8,
            };
            let value = Lifter::read_reg(from, width * 8);
            match ins.op0_kind() {
                OpKind::Memory => store(lifter, address()?, value, width),
                _ => {
                    let (index, register_width) = gpr(ins.op0_register())?;
                    lifter.assign(index, register_width, value);
                }
            }
        }
        _ => return None,
    }
    Some(())
}

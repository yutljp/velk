use super::{
    BinOp, Cond, ConditionCode, EXCHANGE, Expr, Flags, Instruction, Lifter, Mnemonic, OpKind,
    Operation, RAX, RDX, RSP, RegRef, Stmt, Write, gpr, operand, operand_width, preserve_compare,
    write_destination, write_operand,
};

/// A division of the dividend in rdx:rax (or ah:al for bytes) by `divisor`
/// of `width` bits: the quotient into rax (al) and the remainder into rdx
/// (ah).
pub(super) fn wide_divide(lifter: &mut Lifter, signed: bool, width: u8, divisor: Expr) {
    let divide = |remainder, high: Expr, low: Expr| {
        Expr::apply(
            Operation::WideDivide {
                signed,
                remainder,
                bits: width,
            },
            vec![high, low, divisor.clone()],
        )
    };
    if width == 8 {
        let ax = Lifter::read_reg(RAX, 16);
        let high = Expr::bin(BinOp::Shr, ax.clone(), Expr::constant(8));
        let low = Expr::bin(BinOp::And, ax, Expr::constant(0xff));
        let quotient = divide(false, high.clone(), low.clone());
        let remainder = divide(true, high, low);
        // ax takes the remainder above the quotient.
        let joined = Expr::bin(
            BinOp::Or,
            Expr::bin(BinOp::Shl, remainder, Expr::constant(8)),
            quotient,
        );
        lifter.assign(RAX, 16, joined);
        return;
    }
    let (high, low) = (Lifter::read_reg(RDX, width), Lifter::read_reg(RAX, width));
    let quotient = divide(false, high.clone(), low.clone());
    // Both read the dividend, so the quotient waits while rdx changes.
    let quotient = hold(lifter, quotient);
    lifter.assign(RDX, width, divide(true, high, low));
    lifter.assign(RAX, width, quotient);
}

pub(super) fn hold(lifter: &mut Lifter, value: Expr) -> Expr {
    preserve_compare(
        &mut lifter.last_compare,
        Write::Register(EXCHANGE, None),
        &mut lifter.stmts,
    );
    lifter.stmts.push(Stmt::Assign {
        dest: RegRef {
            index: EXCHANGE,
            width: 64,
        },
        value,
    });
    Expr::reg(EXCHANGE, 64)
}

/// `xchg`, `xadd` and `cmpxchg`, whose destination is the first operand
/// (the memory one, if any) and whose source register receives the old value.
pub(super) fn lift_exchange(lifter: &mut Lifter, ins: &Instruction) {
    let (Some(current), Some(source), Some(width)) = (
        operand(lifter, ins, 0),
        operand(lifter, ins, 1),
        operand_width(ins, 0),
    ) else {
        lifter.stmts.push(Stmt::unsupported(format!(
            "{:?} at 0x{:x}",
            ins.mnemonic(),
            ins.ip()
        )));
        return;
    };
    let same_register = ins.op0_kind() == OpKind::Register
        && ins.op1_kind() == OpKind::Register
        && ins.op0_register() == ins.op1_register();
    match ins.mnemonic() {
        Mnemonic::Xchg if same_register => {}
        Mnemonic::Xchg => {
            let old = hold(lifter, current);
            write_operand(lifter, ins, 0, source);
            write_operand(lifter, ins, 1, old);
        }
        Mnemonic::Xadd if same_register => {
            lifter.set_flags(Flags::sum(current.clone(), source.clone()));
            let sum = Expr::bin(BinOp::Add, current, source);
            write_destination(lifter, ins, sum);
        }
        Mnemonic::Xadd => {
            let old = hold(lifter, current);
            lifter.set_flags(Flags::sum(old.clone(), source.clone()));
            let sum = Expr::bin(BinOp::Add, old.clone(), source);
            write_destination(lifter, ins, sum);
            write_operand(lifter, ins, 1, old);
        }
        // The destination receives the source if it held the accumulator,
        // and the accumulator receives the destination if it did not.
        _ => {
            let expected = Lifter::read_reg(RAX, width);
            let old = hold(lifter, current);
            let select = |then: Expr, els: Expr| Expr::Select {
                cond: Cond::Eq,
                lhs: Box::new(old.clone()),
                rhs: Box::new(expected.clone()),
                then: Box::new(then),
                els: Box::new(els),
            };
            write_destination(lifter, ins, select(source, old.clone()));
            // The flags compare the accumulator with the old value.
            lifter.set_flags(Flags::difference(expected.clone(), old.clone()));
            let mismatch = if width >= 32 {
                old.clone()
            } else {
                let mask = (1u64 << width) - 1;
                Expr::bin(
                    BinOp::Or,
                    Expr::bin(BinOp::And, Expr::reg(RAX, 64), Expr::constant(!mask)),
                    old.clone(),
                )
            };
            lifter.assign(RAX, 64, select(Expr::reg(RAX, 64), mismatch));
        }
    }
}

/// `rol`, `ror`, `rcl`, `rcr`, `shld`, `shrd`, `bswap` and `bt`.
pub(super) fn lift_bits(lifter: &mut Lifter, ins: &Instruction) {
    let (Some(value), Some(width)) = (operand(lifter, ins, 0), operand_width(ins, 0)) else {
        lifter.stmts.push(Stmt::unsupported(format!(
            "{:?} at 0x{:x}",
            ins.mnemonic(),
            ins.ip()
        )));
        return;
    };
    let bits = u64::from(width);
    match ins.mnemonic() {
        // The result of swapping a 16-bit register is undefined.
        Mnemonic::Bswap if width == 16 => lifter.stmts.push(Stmt::unsupported(format!(
            "bswap of a 16-bit register at 0x{:x}",
            ins.ip()
        ))),
        Mnemonic::Bswap => {
            let swapped = super::reverse_bytes(value, width, width / 8);
            write_destination(lifter, ins, swapped);
        }
        // A rotate through the carry, with the carry known: the operand and
        // the carry rotate together as one value a bit wider.
        Mnemonic::Rcl | Mnemonic::Rcr if lifter.carry().is_some() => {
            let Some(amount) = operand(lifter, ins, 1) else {
                return;
            };
            let carry = lifter.carry().expect("a known carry");
            // The carry may read registers that keep the earlier flags'
            // operands, which keeping the new flags' operands overwrites.
            let carry = hold(lifter, carry);
            let count = match shift_count(amount, width) {
                Expr::Const(count) if width < 32 => Expr::constant(count % (bits + 1)),
                count if width < 32 => Expr::bin(BinOp::ModU, count, Expr::constant(bits + 1)),
                count => count,
            };
            let shifted = |op, value: Expr, by: Expr| Expr::bin(op, value, by);
            let sub =
                |a: u64, count: &Expr| Expr::bin(BinOp::Sub, Expr::constant(a), count.clone());
            let one = || Expr::constant(1);
            let (towards, from) = if ins.mnemonic() == Mnemonic::Rcl {
                (BinOp::Shl, BinOp::Shr)
            } else {
                (BinOp::Shr, BinOp::Shl)
            };
            // For a count from one to the width: the operand shifted by the
            // count, the carry beside it and the bits that wrap past it.
            let carry_at = if towards == BinOp::Shl {
                Expr::bin(BinOp::Sub, count.clone(), one())
            } else {
                sub(bits, &count)
            };
            let wrapped = shifted(from, shifted(from, value.clone(), sub(bits, &count)), one());
            let rotated = Expr::bin(
                BinOp::Or,
                Expr::bin(
                    BinOp::Or,
                    shifted(towards, value.clone(), count.clone()),
                    shifted(BinOp::Shl, carry.clone(), carry_at),
                ),
                wrapped,
            );
            let rotated = if bits == 64 {
                rotated
            } else {
                Expr::bin(BinOp::And, rotated, Expr::constant((1u64 << bits) - 1))
            };
            let out_at = if towards == BinOp::Shl {
                sub(bits, &count)
            } else {
                Expr::bin(BinOp::Sub, count.clone(), one())
            };
            let out = Expr::bin(
                BinOp::And,
                shifted(BinOp::Shr, value.clone(), out_at),
                one(),
            );
            let (rotated, out) = match count {
                Expr::Const(0) => (value, carry),
                Expr::Const(_) => (rotated, out),
                count => {
                    let unless_zero = |then: Expr, els: Expr| Expr::Select {
                        cond: Cond::Eq,
                        lhs: Box::new(count.clone()),
                        rhs: Box::new(Expr::constant(0)),
                        then: Box::new(then),
                        els: Box::new(els),
                    };
                    (unless_zero(value, rotated), unless_zero(carry, out))
                }
            };
            lifter.set_flags(Flags::carry(out));
            write_destination(lifter, ins, rotated);
        }
        Mnemonic::Rcl | Mnemonic::Rcr => lifter.stmts.push(Stmt::unsupported(format!(
            "{:?} on a carry not modelled at 0x{:x}",
            ins.mnemonic(),
            ins.ip()
        ))),
        Mnemonic::Rol | Mnemonic::Ror => {
            let Some(amount) = operand(lifter, ins, 1) else {
                return;
            };
            let amount = shift_count(amount, width);
            let right = ins.mnemonic() == Mnemonic::Ror;
            write_destination(lifter, ins, super::rotate(value, amount, width, right));
        }
        // A bit string in memory may lie past the addressed operand.
        Mnemonic::Bt | Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc
            if ins.op0_kind() == OpKind::Memory && ins.op1_kind() == OpKind::Register =>
        {
            lifter
                .stmts
                .push(Stmt::unsupported(format!("bt at 0x{:x}", ins.ip())));
        }
        // The carry holds the bit; zero is left as it was. bts, btr and btc
        // then set, clear or flip it.
        Mnemonic::Bt | Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc => {
            let Some(bit) = operand(lifter, ins, 1) else {
                return;
            };
            let bit = Expr::bin(BinOp::And, bit, Expr::constant(bits - 1));
            let flag = Expr::bin(
                BinOp::And,
                Expr::bin(BinOp::Shr, value.clone(), bit.clone()),
                Expr::constant(1),
            );
            lifter.set_flags(Flags::carry(flag));
            let single = Expr::bin(BinOp::Shl, Expr::constant(1), bit);
            let changed = match ins.mnemonic() {
                Mnemonic::Bts => Expr::bin(BinOp::Or, value, single),
                Mnemonic::Btr => Expr::bin(
                    BinOp::And,
                    value,
                    Expr::bin(BinOp::Xor, single, Expr::constant(u64::MAX)),
                ),
                Mnemonic::Btc => Expr::bin(BinOp::Xor, value, single),
                _ => return,
            };
            write_destination(lifter, ins, changed);
        }
        _ => {
            let (Some(source), Some(count)) = (operand(lifter, ins, 1), operand(lifter, ins, 2))
            else {
                return;
            };
            if width < 32 {
                lifter.stmts.push(Stmt::unsupported(format!(
                    "{:?} at 0x{:x}",
                    ins.mnemonic(),
                    ins.ip()
                )));
                return;
            }
            let (towards, from) = match ins.mnemonic() {
                Mnemonic::Shld => (BinOp::Shl, BinOp::Shr),
                _ => (BinOp::Shr, BinOp::Shl),
            };
            let shifted = |amount: Expr, back: Expr| {
                Expr::bin(
                    BinOp::Or,
                    Expr::bin(towards, value.clone(), amount),
                    Expr::bin(from, source.clone(), back),
                )
            };
            lifter.last_compare = None;
            let value = match count {
                Expr::Const(count) => match count & (bits - 1) {
                    0 => return,
                    count => shifted(Expr::constant(count), Expr::constant(bits - count)),
                },
                count => {
                    let count = Expr::bin(BinOp::And, count, Expr::constant(bits - 1));
                    Expr::Select {
                        cond: Cond::Eq,
                        lhs: Box::new(count.clone()),
                        rhs: Box::new(Expr::constant(0)),
                        then: Box::new(value.clone()),
                        els: Box::new(shifted(
                            count.clone(),
                            Expr::bin(BinOp::Sub, Expr::constant(bits), count),
                        )),
                    }
                }
            };
            write_destination(lifter, ins, value);
        }
    }
}

/// One-operand `mul` and `imul`: the accumulator times the operand, with
/// the product's low half in the accumulator and its high half in rdx (edx,
/// dx), or the whole product in ax for bytes.
pub(super) fn lift_mul_high(lifter: &mut Lifter, ins: &Instruction, signed: bool) {
    let (Some(source), Some(width)) = (operand(lifter, ins, 0), operand_width(ins, 0)) else {
        lifter.incomplete = true;
        return;
    };
    let multiplicand = Lifter::read_reg(RAX, width);
    if width == 64 {
        // The operand may be rdx, which the high half overwrites first.
        let source = hold(lifter, source);
        let high_op = if signed {
            BinOp::MulHighS
        } else {
            BinOp::MulHigh
        };
        lifter.assign(
            RDX,
            64,
            Expr::bin(high_op, multiplicand.clone(), source.clone()),
        );
        lifter.assign(RAX, 64, Expr::bin(BinOp::Mul, multiplicand, source));
        lifter.set_flags(Flags::carry_overflow(lost_high(RDX, RAX, 64, signed)));
        return;
    }
    let widen = |value: Expr| {
        if signed {
            Expr::SignExtend {
                value: Box::new(value),
                width: width / 8,
            }
        } else {
            value
        }
    };
    let product = Expr::bin(BinOp::Mul, widen(multiplicand), widen(source));
    if width == 8 {
        lifter.assign(RAX, 16, product);
        // ah against what al's sign (or zero) would put there.
        let ax = Lifter::read_reg(RAX, 16);
        let low = Expr::bin(BinOp::And, ax.clone(), Expr::constant(0xff));
        let expected = if signed {
            Expr::SignExtend {
                value: Box::new(low),
                width: 1,
            }
        } else {
            low
        };
        let lost = Expr::bin(
            BinOp::And,
            Expr::bin(BinOp::Xor, ax, expected),
            Expr::constant(0xffff),
        );
        lifter.set_flags(Flags::carry_overflow(lost));
        return;
    }
    let product = hold(lifter, product);
    lifter.assign(
        RDX,
        width,
        Expr::bin(
            BinOp::Shr,
            product.clone(),
            Expr::constant(u64::from(width)),
        ),
    );
    lifter.assign(RAX, width, product);
    lifter.set_flags(Flags::carry_overflow(lost_high(RDX, RAX, width, signed)));
}

/// Nonzero when the signed product of `a` and `b` does not fit in `width`
/// bits: the full product against its truncation, sign-extended.
pub(super) fn signed_product_lost(a: &Expr, b: &Expr, width: u8) -> Expr {
    if width == 64 {
        let product = Expr::bin(BinOp::Mul, a.clone(), b.clone());
        return Expr::bin(
            BinOp::Xor,
            Expr::bin(BinOp::MulHighS, a.clone(), b.clone()),
            Expr::bin(BinOp::Sar, product, Expr::constant(63)),
        );
    }
    let extend = |value: Expr, bytes: u8| Expr::SignExtend {
        value: Box::new(value),
        width: bytes,
    };
    let bytes = width / 8;
    let full = Expr::bin(
        BinOp::Mul,
        extend(a.clone(), bytes),
        extend(b.clone(), bytes),
    );
    let truncated = Expr::bin(
        BinOp::And,
        full.clone(),
        Expr::constant((1u64 << width) - 1),
    );
    Expr::bin(BinOp::Xor, full, extend(truncated, bytes))
}

/// What a multiply's high half `high` holds beyond what its low half
/// `low` implies, zero or its sign: nonzero when the product did not fit.
fn lost_high(high: u16, low: u16, width: u8, signed: bool) -> Expr {
    let high = Lifter::read_reg(high, width);
    let expected = if signed {
        Expr::bin(
            BinOp::Sar,
            Lifter::read_reg(low, width),
            Expr::constant(u64::from(width) - 1),
        )
    } else {
        Expr::constant(0)
    };
    let lost = Expr::bin(BinOp::Xor, high, expected);
    if width == 64 {
        lost
    } else {
        Expr::bin(BinOp::And, lost, Expr::constant((1u64 << width) - 1))
    }
}

pub(super) fn binary(lifter: &mut Lifter, ins: &Instruction, op: BinOp) {
    let (Some(lhs), Some(rhs)) = (operand(lifter, ins, 0), operand(lifter, ins, 1)) else {
        return;
    };
    // `xor r, r` and `sub r, r` clear the register without depending on its value.
    let value = if matches!(op, BinOp::Xor | BinOp::Sub) && lhs == rhs {
        Expr::constant(0)
    } else {
        Expr::bin(op, lhs.clone(), rhs.clone())
    };
    let width = operand_width(ins, 0).map_or(64, u32::from);
    lifter.set_flags(match op {
        BinOp::Sub => Flags::difference(lhs, rhs),
        BinOp::Add => Flags::sum(lhs, rhs),
        _ => Flags::logic_at(value.clone(), width),
    });
    write_destination(lifter, ins, value);
}

pub(super) fn select(
    lifter: &mut Lifter,
    ins: &Instruction,
    then: Expr,
    els: Expr,
) -> Option<Expr> {
    lifter
        .condition_test(ins.condition_code())
        .select(then, els)
}

pub(super) fn shift(lifter: &mut Lifter, ins: &Instruction, op: BinOp) {
    let (Some(value), Some(amount), Some(width)) = (
        operand(lifter, ins, 0),
        operand(lifter, ins, 1),
        operand_width(ins, 0),
    ) else {
        return;
    };
    let amount = shift_count(amount, width);
    let shifted = Expr::bin(op, value.clone(), amount.clone());
    // A shift by zero leaves the flags as they were. The carry holds the
    // last bit shifted out, which a count of the width or more leaves
    // undefined.
    match amount {
        Expr::Const(count) if count != 0 && count < u64::from(width) => {
            let out = if op == BinOp::Shl {
                u64::from(width) - count
            } else {
                count - 1
            };
            let carry = Expr::bin(
                BinOp::And,
                Expr::bin(BinOp::Shr, value, Expr::constant(out)),
                Expr::constant(1),
            );
            lifter.set_flags(Flags::shift(shifted.clone(), carry));
        }
        Expr::Const(count) if count != 0 => lifter.set_flags(Flags::result(shifted.clone())),
        Expr::Const(_) => {
            if let Some(flags) = lifter.last_compare.clone() {
                lifter.set_flags(flags);
            }
        }
        amount => {
            if let Some(old) = lifter
                .test(Cond::Eq)
                .select(Expr::constant(1), Expr::constant(0))
            {
                let result = if width < 64 {
                    Expr::bin(
                        BinOp::And,
                        shifted.clone(),
                        Expr::constant((1u64 << width) - 1),
                    )
                } else {
                    shifted.clone()
                };
                let zero = Expr::Select {
                    cond: Cond::Eq,
                    lhs: Box::new(result),
                    rhs: Box::new(Expr::constant(0)),
                    then: Box::new(Expr::constant(1)),
                    els: Box::new(Expr::constant(0)),
                };
                lifter.set_flags(Flags::zero(Expr::Select {
                    cond: Cond::Eq,
                    lhs: Box::new(amount),
                    rhs: Box::new(Expr::constant(0)),
                    then: Box::new(old),
                    els: Box::new(zero),
                }));
            }
        }
    }
    write_destination(lifter, ins, shifted);
}

/// `tzcnt`, `lzcnt`, `popcnt`, and `bsf` and `bsr`, which leave the
/// destination as it was for a zero source (as processors do, though Intel
/// leaves it undefined), all 64 bits of it even for a 32-bit operand, and
/// set the zero flag for it.
pub(super) fn lift_count(lifter: &mut Lifter, ins: &Instruction) {
    let (Some(source), Some(width)) = (operand(lifter, ins, 1), operand_width(ins, 1)) else {
        return;
    };
    let count = |op| Expr::apply(op, vec![source.clone()]);
    let zero = || Expr::constant(0);
    // One when the source is zero.
    let empty = Expr::Select {
        cond: Cond::Eq,
        lhs: Box::new(source.clone()),
        rhs: Box::new(zero()),
        then: Box::new(Expr::constant(1)),
        els: Box::new(zero()),
    };
    let (value, flags) = match ins.mnemonic() {
        Mnemonic::Tzcnt => (
            count(Operation::CountTrailingZeros(width)),
            Flags::carry(empty),
        ),
        Mnemonic::Lzcnt => (
            count(Operation::CountLeadingZeros(width)),
            Flags::carry(empty),
        ),
        // Zero follows the source; carry, sign and overflow are clear, as
        // after comparing the small count with zero, and so are parity and
        // adjust.
        Mnemonic::Popcnt => {
            let value = count(Operation::PopCount(width));
            (
                value.clone(),
                Flags::difference(value, zero()).clearing_low(),
            )
        }
        _ => {
            let Some(old) = operand(lifter, ins, 0) else {
                return;
            };
            // A 32-bit destination left as it was keeps its high half too.
            let whole = match (width, gpr(ins.op0_register())) {
                (32, Some((index, _))) if ins.op0_kind() == OpKind::Register => Some(index),
                _ => None,
            };
            let old = whole.map_or(old, |index| Lifter::read_reg(index, 64));
            let found = if ins.mnemonic() == Mnemonic::Bsf {
                count(Operation::CountTrailingZeros(width))
            } else {
                Expr::bin(
                    BinOp::Sub,
                    Expr::constant(u64::from(width) - 1),
                    count(Operation::CountLeadingZeros(width)),
                )
            };
            let value = Expr::Select {
                cond: Cond::Eq,
                lhs: Box::new(source.clone()),
                rhs: Box::new(zero()),
                then: Box::new(old),
                els: Box::new(found),
            };
            lifter.set_flags(Flags::result(source.clone()));
            match whole {
                Some(index) => lifter.assign(index, 64, value),
                None => write_destination(lifter, ins, value),
            }
            return;
        }
    };
    lifter.set_flags(flags);
    write_destination(lifter, ins, value);
}

/// `adc` and `sbb`: a sum with the carry, or a difference less it. The
/// flags include the carry out and the truncated result.
pub(super) fn with_carry(lifter: &mut Lifter, ins: &Instruction, subtract: bool) {
    let (Some(a), Some(b), Some(width)) = (
        operand(lifter, ins, 0),
        operand(lifter, ins, 1),
        operand_width(ins, 0),
    ) else {
        return;
    };
    let Some(carry) = lifter.carry() else {
        lifter.stmts.push(Stmt::unsupported(format!(
            "{:?} on a carry not modelled at 0x{:x}",
            ins.mnemonic(),
            ins.ip()
        )));
        return;
    };
    // The carry may read registers that keep the earlier flags' operands,
    // which keeping the new flags' operands overwrites.
    let carry = hold(lifter, carry);
    let (out, value) = if subtract {
        (
            super::flags::borrow_out(&a, &b, carry.clone()),
            Expr::bin(
                BinOp::Sub,
                Expr::bin(BinOp::Sub, a.clone(), b.clone()),
                carry,
            ),
        )
    } else {
        (
            super::flags::carry_out(&a, &b, carry.clone(), u32::from(width)),
            Expr::bin(
                BinOp::Add,
                Expr::bin(BinOp::Add, a.clone(), b.clone()),
                carry,
            ),
        )
    };
    let result = Expr::bin(
        BinOp::And,
        value.clone(),
        Expr::constant(crate::ir::semantics::mask(u32::from(width))),
    );
    let bit = |value, shift| Expr::bin(BinOp::Shl, value, Expr::constant(shift));
    let truth = |cond, lhs, rhs| Expr::Select {
        cond,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
        then: Box::new(Expr::constant(1)),
        els: Box::new(Expr::constant(0)),
    };
    let sign = |value| {
        Expr::bin(
            BinOp::And,
            Expr::bin(BinOp::Shr, value, Expr::constant(u64::from(width - 1))),
            Expr::constant(1),
        )
    };
    let zero = truth(Cond::Eq, result.clone(), Expr::constant(0));
    let adjust = Expr::bin(
        BinOp::And,
        Expr::bin(
            BinOp::Xor,
            Expr::bin(BinOp::Xor, a.clone(), b.clone()),
            result.clone(),
        ),
        Expr::constant(0x10),
    );
    let parity = Flags::logic(result.clone())
        .parity(true)
        .select(Expr::constant(4), Expr::constant(0))
        .expect("logical results define parity");
    let different = Expr::bin(BinOp::Xor, a.clone(), b);
    let overflow = sign(Expr::bin(
        BinOp::And,
        if subtract {
            different
        } else {
            Expr::bin(BinOp::Xor, different, Expr::constant(u64::MAX))
        },
        Expr::bin(BinOp::Xor, a, result.clone()),
    ));
    let byte = [bit(sign(result), 7), bit(zero, 6), adjust, parity]
        .into_iter()
        .fold(out, |byte, part| Expr::bin(BinOp::Or, byte, part));
    lifter.set_flags(Flags::stored(byte, Some(overflow)));
    write_destination(lifter, ins, value);
}

/// `lahf`: sign, zero, adjust, parity and carry into bits 7, 6, 4, 2 and 0
/// of `ah`, with bit 1 set; unsupported when the flags here leave one open.
pub(super) fn lift_lahf(lifter: &mut Lifter, ins: &Instruction) {
    let bits = lifter.last_compare.as_ref().and_then(|flags| {
        [
            (lifter.test(Cond::Mi), 7),
            (lifter.test(Cond::Eq), 6),
            (flags.adjust(), 4),
            (flags.parity(true), 2),
            (lifter.test(Cond::Cc), 0),
        ]
        .into_iter()
        .try_fold(Expr::constant(2), |byte, (test, bit)| {
            let value = test.select(Expr::constant(1 << bit), Expr::constant(0))?;
            Some(Expr::bin(BinOp::Or, byte, value))
        })
    });
    let Some(byte) = bits else {
        lifter.stmts.push(Stmt::unsupported(format!(
            "lahf on flags not modelled at 0x{:x}",
            ins.ip()
        )));
        return;
    };
    // The byte may read registers that keep the flags' operands, which
    // writing `rax` may move there.
    let byte = hold(lifter, byte);
    let kept = Expr::bin(BinOp::And, Expr::reg(RAX, 64), Expr::constant(!0xff00));
    let placed = Expr::bin(BinOp::Shl, byte, Expr::constant(8));
    lifter.assign(RAX, 64, Expr::bin(BinOp::Or, kept, placed));
}

/// The count a shift or rotate uses: its low six bits for a 64-bit operand,
/// its low five bits otherwise.
fn shift_count(amount: Expr, width: u8) -> Expr {
    let mask = if width == 64 { 63 } else { 31 };
    match amount {
        Expr::Const(count) => Expr::constant(count & mask),
        amount => Expr::bin(BinOp::And, amount, Expr::constant(mask)),
    }
}

pub(super) fn condition(code: ConditionCode) -> Option<Cond> {
    use ConditionCode::*;
    Some(match code {
        e => Cond::Eq,
        ne => Cond::Ne,
        l => Cond::Lt,
        le => Cond::Le,
        g => Cond::Gt,
        ge => Cond::Ge,
        b => Cond::Cc,
        be => Cond::Ls,
        a => Cond::Hi,
        ae => Cond::Cs,
        s => Cond::Mi,
        ns => Cond::Pl,
        o => Cond::Vs,
        no => Cond::Vc,
        _ => return Option::None,
    })
}

/// The value with each read of the stack pointer offset by `delta`, for a
/// value read before the stack pointer moves down by `delta`.
pub(super) fn stack_reads_before(value: Expr, delta: u64) -> Expr {
    match value {
        Expr::Reg {
            index: RSP,
            width: 64,
        } => Expr::bin(BinOp::Add, Lifter::read_reg(RSP, 64), Expr::constant(delta)),
        Expr::Bin { op, lhs, rhs } => Expr::bin(
            op,
            stack_reads_before(*lhs, delta),
            stack_reads_before(*rhs, delta),
        ),
        Expr::Load {
            addr,
            width,
            signed,
        } => Expr::Load {
            addr: Box::new(stack_reads_before(*addr, delta)),
            width,
            signed,
        },
        other => other,
    }
}

pub(super) fn stack_adjust(lifter: &mut Lifter, delta: i64) {
    let current = Lifter::read_reg(RSP, 64);
    let value = Expr::bin(BinOp::Add, current, Expr::constant(delta as u64));
    lifter.assign(RSP, lifter.word_bits(), value);
}

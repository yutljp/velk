use super::{
    BinOp, Cond, Expr, Flags, Lifter, Operand, Operation, RegRef, SizeCode, Stmt, Test, a64,
};

fn shift_expr(style: a64::ShiftStyle, amount: u64, value: Expr) -> Option<Expr> {
    let op = match style {
        a64::ShiftStyle::LSL => BinOp::Shl,
        a64::ShiftStyle::LSR => BinOp::Shr,
        a64::ShiftStyle::ASR => BinOp::Sar,
        _ => return None,
    };
    Some(Expr::bin(op, value, Expr::constant(amount)))
}

pub(super) fn extend_shift(
    style: a64::ShiftStyle,
    amount: u64,
    value: Expr,
    size: SizeCode,
) -> Option<Expr> {
    let width = if size == SizeCode::X { 64 } else { 32 };
    let mask = match (style, width) {
        (a64::ShiftStyle::UXTB, _) => Some(0xff),
        (a64::ShiftStyle::UXTH, _) => Some(0xffff),
        (a64::ShiftStyle::UXTW, _) | (a64::ShiftStyle::UXTX, _) => Some(0xffff_ffff),
        _ => None,
    };
    if let Some(mask) = mask {
        let masked = Expr::bin(BinOp::And, value, Expr::constant(mask));
        return Some(Expr::bin(BinOp::Shl, masked, Expr::constant(amount)));
    }
    let signed_width = match style {
        a64::ShiftStyle::SXTB => Some(1),
        a64::ShiftStyle::SXTH => Some(2),
        a64::ShiftStyle::SXTW => Some(4),
        a64::ShiftStyle::SXTX => Some(8),
        _ => None,
    };
    if style == a64::ShiftStyle::ROR {
        let rotated = super::rotate(value, Expr::constant(amount), width, true);
        return Some(if width == 32 {
            Expr::bin(BinOp::And, rotated, Expr::constant(0xffff_ffff))
        } else {
            rotated
        });
    }
    if let Some(bytes) = signed_width {
        let widened = Expr::SignExtend {
            value: Box::new(value),
            width: bytes,
        };
        return Some(Expr::bin(BinOp::Shl, widened, Expr::constant(amount)));
    }
    shift_expr(style, amount, value)
}

/// The width in bits of a general register operand, the zero register included.
pub(super) fn register_width(operand: Operand) -> Option<u8> {
    match operand {
        Operand::Register(size, _) | Operand::RegisterOrSP(size, _) => {
            Some(if size == SizeCode::X { 64 } else { 32 })
        }
        _ => None,
    }
}

pub(super) fn destination(operand: Operand) -> Option<RegRef> {
    match operand {
        Operand::Register(_, 31) => None,
        Operand::Register(size, index) => Some(RegRef {
            index,
            width: if size == SizeCode::X { 64 } else { 32 },
        }),
        Operand::RegisterOrSP(size, index) => Some(RegRef {
            index,
            width: if size == SizeCode::X { 64 } else { 32 },
        }),
        _ => None,
    }
}

pub(super) fn lift_alu(lifter: &mut Lifter, ops: [Operand; 4], op: BinOp, flags: bool) {
    if flags {
        lifter.last_compare = None;
    }
    let dest = destination(ops[0]);
    // The operand size decides the width even when the destination is the
    // zero register (`cmp w0, #0` is a 32-bit comparison).
    let width = match ops[0] {
        Operand::Register(size, _) | Operand::RegisterOrSP(size, _) => {
            if size == SizeCode::X {
                64
            } else {
                32
            }
        }
        _ => dest.map(|d| d.width).unwrap_or(64),
    };
    let (Some(lhs), Some(rhs)) = (lifter.operand(ops[1], width), lifter.operand(ops[2], width))
    else {
        return;
    };
    let value = Expr::bin(op, lhs.clone(), rhs.clone());
    if flags {
        lifter.last_compare = Some(match op {
            BinOp::Add => Flags::sum(lhs, rhs),
            BinOp::And => Flags::logic_at(value.clone(), u32::from(width)),
            _ => Flags::difference(lhs, rhs),
        });
    }
    if let Some(dest) = dest {
        lifter.assign(dest, value)
    }
}

pub(super) fn lift_mul_high(lifter: &mut Lifter, ops: [Operand; 4], signed: bool) {
    let Some(dest) = destination(ops[0]) else {
        return;
    };
    let (Some(a), Some(b)) = (lifter.operand(ops[1], 64), lifter.operand(ops[2], 64)) else {
        return;
    };
    let op = if signed {
        BinOp::MulHighS
    } else {
        BinOp::MulHigh
    };
    lifter.assign(dest, Expr::bin(op, a, b));
}

pub(super) fn lift_madd(lifter: &mut Lifter, ops: [Operand; 4], accumulate: bool) {
    let Some(dest) = destination(ops[0]) else {
        return;
    };
    let (Some(a), Some(b)) = (
        lifter.operand(ops[1], dest.width),
        lifter.operand(ops[2], dest.width),
    ) else {
        return;
    };
    let product = Expr::bin(BinOp::Mul, a, b);
    let value = if accumulate {
        match lifter.operand(ops[3], dest.width) {
            Some(offset) => Expr::bin(BinOp::Add, product, offset),
            None => product,
        }
    } else {
        product
    };
    lifter.assign(dest, value);
}

/// `bic Rd, Rn, Rm` computes `Rn & ~Rm`.
/// `orn` and `eon`: the operation with the second operand inverted.
pub(super) fn lift_inverted(lifter: &mut Lifter, ops: [Operand; 4], op: BinOp) {
    let (Some(dest), Some(width)) = (destination(ops[0]), register_width(ops[0])) else {
        return;
    };
    let (Some(base), Some(mask)) = (lifter.operand(ops[1], width), lifter.operand(ops[2], width))
    else {
        lifter.stmts.push(Stmt::unsupported(format!("{op:?} not")));
        return;
    };
    let inverted = Expr::bin(BinOp::Xor, mask, Expr::constant(u64::MAX));
    lifter.assign(dest, Expr::bin(op, base, inverted));
}

/// `extr`: the register pair `rn:rm` shifted right by `lsb`, which with
/// `rn` equal to `rm` is `ror`.
pub(super) fn lift_extract(lifter: &mut Lifter, ops: [Operand; 4]) {
    let Some(dest) = destination(ops[0]) else {
        return;
    };
    let (Some(high), Some(low), Operand::Immediate(lsb)) = (
        lifter.operand(ops[1], dest.width),
        lifter.operand(ops[2], dest.width),
        ops[3],
    ) else {
        return;
    };
    let lsb = u64::from(lsb) % u64::from(dest.width);
    let value = if lsb == 0 {
        low
    } else {
        Expr::bin(
            BinOp::Or,
            Expr::bin(BinOp::Shr, low, Expr::constant(lsb)),
            Expr::bin(
                BinOp::Shl,
                high,
                Expr::constant(u64::from(dest.width) - lsb),
            ),
        )
    };
    lifter.assign(dest, value);
}

/// `rev`, `rev16` and `rev32`: the bytes reversed within each `chunk` bytes.
pub(super) fn lift_reverse(lifter: &mut Lifter, ops: [Operand; 4], chunk: Option<u8>) {
    let Some(dest) = destination(ops[0]) else {
        return;
    };
    let Some(value) = lifter.operand(ops[1], dest.width) else {
        return;
    };
    let chunk = chunk.unwrap_or(dest.width / 8);
    lifter.assign(dest, super::reverse_bytes(value, dest.width, chunk));
}

/// `clz`, `cls` and `rbit`. Leading sign bits are the leading zeros of the
/// value with each bit compared to the one above it, less the sign itself.
pub(super) fn lift_count(lifter: &mut Lifter, ops: [Operand; 4], opcode: a64::Opcode) {
    let Some(dest) = destination(ops[0]) else {
        return;
    };
    let Some(value) = lifter.operand(ops[1], dest.width) else {
        return;
    };
    let bits = dest.width;
    let count = |op, value| Expr::apply(op, vec![value]);
    let result = match opcode {
        a64::Opcode::CLZ => count(Operation::CountLeadingZeros(bits), value),
        a64::Opcode::RBIT => count(Operation::ReverseBits(bits), value),
        _ => {
            let neighbours = Expr::bin(
                BinOp::Xor,
                value.clone(),
                Expr::bin(BinOp::Sar, value, Expr::constant(1)),
            );
            Expr::bin(
                BinOp::Sub,
                count(Operation::CountLeadingZeros(bits), neighbours),
                Expr::constant(1),
            )
        }
    };
    lifter.assign(dest, result);
}

pub(super) fn lift_bic(lifter: &mut Lifter, ops: [Operand; 4], flags: bool) {
    if flags {
        lifter.last_compare = None;
    }
    let width = match ops[0] {
        Operand::Register(size, _) | Operand::RegisterOrSP(size, _) => {
            if size == SizeCode::X {
                64
            } else {
                32
            }
        }
        _ => 64,
    };
    let (Some(base), Some(mask)) = (lifter.operand(ops[1], width), lifter.operand(ops[2], width))
    else {
        lifter.stmts.push(Stmt::unsupported("bic".to_owned()));
        return;
    };
    let inverted = Expr::bin(BinOp::Xor, mask, Expr::constant(u64::MAX));
    let value = Expr::bin(BinOp::And, base, inverted);
    if flags {
        lifter.last_compare = Some(Flags::logic_at(value.clone(), u32::from(width)));
    }
    // `bics` into the zero register only sets the flags.
    if let Some(dest) = destination(ops[0]) {
        lifter.assign(dest, value);
    }
}

/// `msub Rd, Rn, Rm, Ra` computes `Ra - Rn * Rm`.
pub(super) fn lift_msub(lifter: &mut Lifter, ops: [Operand; 4]) {
    let Some(dest) = destination(ops[0]) else {
        return;
    };
    let (Some(product_base), Some(product_operand)) = (
        lifter.operand(ops[1], dest.width),
        lifter.operand(ops[2], dest.width),
    ) else {
        // Unreadable product operands: keep only the accumulate value.
        if let Some(base) = lifter.operand(ops[3], dest.width) {
            lifter.assign(dest, base);
        }
        return;
    };
    let product = Expr::bin(BinOp::Mul, product_base, product_operand);
    let value = match lifter.operand(ops[3], dest.width) {
        Some(base) => Expr::bin(BinOp::Sub, base, product),
        None => product,
    };
    lifter.assign(dest, value);
}

/// `umaddl`, `smaddl`, `umsubl` and `smsubl`: a 64-bit product of 32-bit
/// operands added to or subtracted from the fourth operand.
pub(super) fn lift_long_multiply(
    lifter: &mut Lifter,
    ops: [Operand; 4],
    signed: bool,
    subtract: bool,
) {
    let Some(dest) = destination(ops[0]) else {
        return;
    };
    let (Some(a), Some(b)) = (lifter.operand(ops[1], 32), lifter.operand(ops[2], 32)) else {
        return;
    };
    // `smaddl` sign-extends its 32-bit operands before multiplying.
    let widen = |expr: Expr| -> Expr {
        if signed {
            Expr::SignExtend {
                value: Box::new(expr),
                width: 4,
            }
        } else {
            expr
        }
    };
    let product = Expr::bin(BinOp::Mul, widen(a), widen(b));
    let value = match (lifter.operand(ops[3], 64), subtract) {
        (Some(base), false) => Expr::bin(BinOp::Add, product, base),
        (Some(base), true) => Expr::bin(BinOp::Sub, base, product),
        (None, false) => product,
        (None, true) => Expr::bin(BinOp::Sub, Expr::constant(0), product),
    };
    lifter.assign(dest, value);
}

/// `ccmp` and `ccmn`: compare (or add, for `ccmn`) when the condition holds,
/// and otherwise set the flags to the immediate.
pub(super) fn lift_conditional_compare(lifter: &mut Lifter, ops: [Operand; 4], sum: bool) {
    let earlier = match ops[3] {
        Operand::ConditionCode(code) => lifter.test_code(code),
        _ => Test::Unknown,
    };
    lifter.last_compare = None;
    let Some(width) = register_width(ops[0]) else {
        return;
    };
    let (Some(a), Some(b), Some(nzcv)) = (
        lifter.operand(ops[0], width),
        lifter.operand(ops[1], width),
        immediates(ops[2]),
    ) else {
        return;
    };
    let compare = if sum {
        Flags::sum(a, b)
    } else {
        Flags::difference(a, b)
    };
    lifter.last_compare = compare.chosen_by(earlier, nzcv as u8);
}

/// `adc`, `sbc` and their flag-setting forms: a sum with the carry, or a
/// difference less its complement. The flag-setting forms keep only the
/// carry they produce.
pub(super) fn lift_with_carry(lifter: &mut Lifter, ops: [Operand; 4], subtract: bool, flags: bool) {
    let carry = lifter
        .test(Cond::Cs)
        .select(Expr::constant(1), Expr::constant(0));
    lifter.last_compare = None;
    let Some(dest) = destination(ops[0]) else {
        return;
    };
    let (Some(a), Some(b), Some(carry)) = (
        lifter.operand(ops[1], dest.width),
        lifter.operand(ops[2], dest.width),
        carry,
    ) else {
        lifter
            .stmts
            .push(Stmt::unsupported("carry not modelled here".to_owned()));
        return;
    };
    // The carry may read registers that keep the earlier flags' operands,
    // which keeping the new flags' operands overwrites.
    let carry = lifter.hold(carry);
    // `sbc` adds the complement of its second operand and the carry.
    let all = if dest.width == 64 {
        u64::MAX
    } else {
        0xffff_ffff
    };
    let addend = if subtract {
        Expr::bin(BinOp::Xor, b.clone(), Expr::constant(all))
    } else {
        b.clone()
    };
    if flags {
        let out = super::flags::carry_out(&a, &addend, carry.clone(), u32::from(dest.width));
        lifter.last_compare = Some(Flags::carry(out));
    }
    let value = if subtract {
        let borrow = Expr::bin(BinOp::Xor, carry, Expr::constant(1));
        Expr::bin(BinOp::Sub, Expr::bin(BinOp::Sub, a, b), borrow)
    } else {
        Expr::bin(BinOp::Add, Expr::bin(BinOp::Add, a, b), carry)
    };
    lifter.assign(dest, value);
}

/// `bfm`: bits of the source replace a field of the destination, which
/// keeps its other bits (`bfi`, `bfxil`).
pub(super) fn lift_bitfield_insert(lifter: &mut Lifter, ops: [Operand; 4]) {
    let Some(dest) = destination(ops[0]) else {
        return;
    };
    let (Some(old), Some(source), Some(immr), Some(imms)) = (
        lifter.operand(ops[0], dest.width),
        lifter.operand(ops[1], dest.width),
        immediates(ops[2]),
        immediates(ops[3]),
    ) else {
        return;
    };
    let width = u64::from(dest.width);
    let (immr, imms) = (immr & (width - 1), imms & (width - 1));
    // `imms >= immr` moves bits immr..=imms to the bottom; otherwise the low
    // imms + 1 bits move up to width - immr.
    let (field, from, to) = if imms >= immr {
        (imms - immr + 1, immr, 0)
    } else {
        (imms + 1, 0, width - immr)
    };
    let ones = mask_bits(field);
    let moved = Expr::bin(
        BinOp::Shl,
        Expr::bin(
            BinOp::And,
            Expr::bin(BinOp::Shr, source, Expr::constant(from)),
            Expr::constant(ones),
        ),
        Expr::constant(to),
    );
    let kept = Expr::bin(
        BinOp::And,
        old,
        Expr::constant(!(ones << to) & mask_bits(width)),
    );
    lifter.assign(dest, Expr::bin(BinOp::Or, kept, moved));
}

pub(super) fn mask_bits(bits: u64) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1 << bits) - 1
    }
}

pub(super) fn immediates(operand: Operand) -> Option<u64> {
    match operand {
        Operand::Immediate(value) => Some(value as u64),
        Operand::Imm16(value) => Some(value as u64),
        Operand::ImmShift(value, shift) => Some((value as u64) << shift),
        _ => None,
    }
}

pub(super) fn lift_mov(lifter: &mut Lifter, ops: [Operand; 4], invert: bool) {
    let Some(dest) = destination(ops[0]) else {
        return;
    };
    let Some(immediate) = immediates(ops[1]) else {
        return;
    };
    let value = if invert {
        let mask = if dest.width == 32 {
            0xffff_ffff
        } else {
            u64::MAX
        };
        Expr::constant(!immediate & mask)
    } else {
        Expr::constant(immediate)
    };
    lifter.assign(dest, value);
}

pub(super) fn lift_movk(lifter: &mut Lifter, ops: [Operand; 4]) {
    let Some(dest) = destination(ops[0]) else {
        return;
    };
    let (value, shift) = match ops[1] {
        Operand::ImmShift(value, shift) => (value as u64, shift as u64),
        Operand::Immediate(value) => (value as u64, 0),
        _ => return,
    };
    let width_mask: u64 = if dest.width == 32 {
        0xffff_ffff
    } else {
        u64::MAX
    };
    let current = Lifter::read_reg(dest.index, dest.width);
    let keep = Expr::bin(
        BinOp::And,
        current,
        Expr::constant(!(0xffffu64 << shift) & width_mask),
    );
    let inserted = Expr::constant(value << shift);
    lifter.assign(dest, Expr::bin(BinOp::Or, keep, inserted));
}

pub(super) fn lift_bitfield(lifter: &mut Lifter, ops: [Operand; 4], signed: bool) {
    let Some(dest) = destination(ops[0]) else {
        return;
    };
    let (Some(source), Some(immr), Some(imms)) = (
        lifter.operand(ops[1], dest.width),
        immediates(ops[2]),
        immediates(ops[3]),
    ) else {
        return;
    };
    let imms = imms & 0x3f;
    let immr = immr & 0x3f;
    let full = (dest.width - 1) as u64;
    if imms == full {
        let value = shift_expr(
            if signed {
                a64::ShiftStyle::ASR
            } else {
                a64::ShiftStyle::LSR
            },
            immr,
            source,
        );
        match value {
            Some(value) => lifter.assign(dest, value),
            None => lifter
                .stmts
                .push(Stmt::unsupported("bitfield shift".to_owned())),
        }
    } else if imms + 1 == immr {
        match shift_expr(a64::ShiftStyle::LSL, dest.width as u64 - immr, source) {
            Some(value) => lifter.assign(dest, value),
            None => lifter
                .stmts
                .push(Stmt::unsupported("bitfield shift".to_owned())),
        }
    } else {
        match bitfield_move(source, immr, imms, dest.width, signed) {
            Some(value) => lifter.assign(dest, value),
            None => lifter.stmts.push(Stmt::unsupported(format!(
                "bitfield immr={immr} imms={imms}"
            ))),
        }
    }
}

/// The general bitfield move: with `imms >= immr` it extracts bits
/// `immr..=imms` to the bottom (ubfx, sbfx, sxtw), otherwise it places the low
/// `imms + 1` bits at `width - immr` (ubfiz, sbfiz). A signed field extends
/// only when it is 8, 16 or 32 bits wide.
fn bitfield_move(source: Expr, immr: u64, imms: u64, width: u8, signed: bool) -> Option<Expr> {
    let (field, shifted_left) = if imms >= immr {
        (imms - immr + 1, false)
    } else {
        (imms + 1, true)
    };
    let mask = Expr::constant(if field >= 64 {
        u64::MAX
    } else {
        (1u64 << field) - 1
    });
    let low = if shifted_left {
        source
    } else {
        Expr::bin(BinOp::Shr, source, Expr::constant(immr))
    };
    let extracted = if signed {
        match field {
            8 | 16 | 32 => Expr::SignExtend {
                value: Box::new(low),
                width: (field / 8) as u8,
            },
            // Any other field moves to the top and back down with its sign.
            _ => {
                let up = Expr::constant(u64::from(width) - field);
                Expr::bin(BinOp::Sar, Expr::bin(BinOp::Shl, low, up.clone()), up)
            }
        }
    } else {
        Expr::bin(BinOp::And, low, mask)
    };
    Some(if shifted_left {
        Expr::bin(
            BinOp::Shl,
            extracted,
            Expr::constant(u64::from(width) - immr),
        )
    } else {
        extracted
    })
}

pub(super) fn lift_variable_shift(lifter: &mut Lifter, ops: [Operand; 4], shift: a64::ShiftStyle) {
    let Some(dest) = destination(ops[0]) else {
        return;
    };
    let (Some(value), Some(amount)) = (
        lifter.operand(ops[1], dest.width),
        lifter.operand(ops[2], dest.width),
    ) else {
        return;
    };
    // The amount counts modulo the width.
    let amount = Expr::bin(
        BinOp::And,
        amount,
        Expr::constant(u64::from(dest.width) - 1),
    );
    let op = match shift {
        a64::ShiftStyle::LSL => BinOp::Shl,
        a64::ShiftStyle::LSR => BinOp::Shr,
        a64::ShiftStyle::ASR => BinOp::Sar,
        a64::ShiftStyle::ROR => {
            lifter.assign(dest, super::rotate(value, amount, dest.width, true));
            return;
        }
        _ => {
            lifter
                .stmts
                .push(Stmt::unsupported("rotate/extend".to_owned()));
            return;
        }
    };
    lifter.assign(dest, Expr::bin(op, value, amount));
}

/// `csinc/csinv/csneg Rd, Rn, Rm, cond`: Rd = cond ? Rn : f(Rm), where f adds
/// one, inverts every bit, or negates.
pub(super) fn lift_cs_family(lifter: &mut Lifter, ops: [Operand; 4], opcode: a64::Opcode) {
    let Some(dest) = destination(ops[0]) else {
        return;
    };
    let Operand::ConditionCode(code) = ops[3] else {
        return;
    };
    let (Some(a), Some(b)) = (
        lifter.operand(ops[1], dest.width),
        lifter.operand(ops[2], dest.width),
    ) else {
        return;
    };
    // `cset`/`csetm` are aliases of `csinc`/`csinv` with zero-register sources.
    let decorate = |expr: Expr| -> Expr {
        match opcode {
            a64::Opcode::CSINC => Expr::bin(BinOp::Add, expr, Expr::constant(1)),
            a64::Opcode::CSINV => {
                // Invert only the destination width.
                let ones = if dest.width >= 64 {
                    u64::MAX
                } else {
                    (1u64 << dest.width) - 1
                };
                Expr::bin(BinOp::Xor, expr, Expr::constant(ones))
            }
            _ => Expr::bin(BinOp::Sub, Expr::constant(0), expr),
        }
    };
    let mut then_value = a.clone();
    let mut els_value = decorate(b.clone());
    let mut test = lifter.test_code(code);
    // `cset` encodes the inverted condition with zero as the true value;
    // swap back so the condition matches the comparison.
    if matches!(then_value, Expr::Const(0)) && !matches!(els_value, Expr::Const(0)) {
        std::mem::swap(&mut then_value, &mut els_value);
        test = test.invert();
    }
    // `last_compare` is kept: a following conditional select reads the same flags.
    lifter.select(dest, test, then_value, els_value);
}

pub(super) fn lift_csel(lifter: &mut Lifter, ops: [Operand; 4]) {
    let Some(dest) = destination(ops[0]) else {
        return;
    };
    let Operand::ConditionCode(code) = ops[3] else {
        return;
    };
    let Some(then_value) = lifter.operand(ops[1], dest.width) else {
        return;
    };
    let Some(els_value) = lifter.operand(ops[2], dest.width) else {
        return;
    };
    let test = lifter.test_code(code);
    lifter.select(dest, test, then_value, els_value);
}

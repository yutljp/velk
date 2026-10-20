use yaxpeax_arch::{Decoder, ReaderBuilder};
use yaxpeax_arm::armv8::a64::{self, Instruction, Operand, SizeCode};

use super::flags::{Flags, Test};
use super::{
    Decoded, MAX_INSTRUCTIONS, Machine, Write, call, call_through, preserve_compare, tail_call,
};
use crate::ir::{BinOp, Cond, Expr, LaneOp, Operation, Precision, RegRef, Rounding, Stmt};

pub(super) struct Lifter<'a> {
    stmts: Vec<Stmt>,
    /// Whether an operand of the instruction being lifted was one the
    /// lifter cannot express, so that its effect would be lost.
    incomplete: std::cell::Cell<bool>,
    /// Whether an instruction of the current block may have changed the flags.
    flags_touched: bool,
    last_compare: Option<Flags>,
    image: &'a crate::loader::Image,
    summaries: super::Summaries<'a>,
    function: u64,
}

impl<'a> Lifter<'a> {
    pub(super) fn new(
        image: &'a crate::loader::Image,
        function: u64,
        summaries: super::Summaries<'a>,
    ) -> Self {
        Self {
            stmts: Vec::new(),
            incomplete: Default::default(),
            flags_touched: false,
            last_compare: None,
            image,
            summaries,
            function,
        }
    }

    /// A pending relocation overrides the encoded branch offset.
    fn target_of(&self, operand: Operand, pc: u64) -> Option<u64> {
        if let Some(target) = self.image.relocations.get(&pc) {
            return Some(*target);
        }
        relative_target(operand, pc)
    }

    /// A branch to another known function is a tail call.
    fn is_tail_call(&self, target: u64) -> bool {
        target != self.function && self.image.functions.contains_key(&target)
    }

    /// `cond` under the flags; flags set in another block are unknown.
    fn test(&self, cond: Cond) -> Test {
        self.last_compare.as_ref().map_or(Test::Unknown, |flags| {
            flags.test(cond, crate::loader::Isa::AArch64)
        })
    }

    /// Copies `value` into a register of its own and reads it from there.
    fn hold(&mut self, value: Expr) -> Expr {
        preserve_compare(
            &mut self.last_compare,
            Write::Register(crate::ir::EXCHANGE, None),
            &mut self.stmts,
        );
        self.stmts.push(Stmt::Assign {
            dest: RegRef {
                index: crate::ir::EXCHANGE,
                width: 64,
            },
            value,
        });
        Expr::reg(crate::ir::EXCHANGE, 64)
    }

    /// The low `bits` of a vector register.
    fn read_simd(&self, slot: u16, bits: u16) -> Expr {
        let register = Expr::reg(slot, 64);
        if bits >= 64 {
            register
        } else {
            Expr::bin(BinOp::And, register, Expr::constant((1 << bits) - 1))
        }
    }

    /// A write of `bits` to a vector register, given as its low and high
    /// halves: below 128 bits the high half is zero, and a scalar clears
    /// the bits above it.
    fn write_simd(&mut self, slot: u16, bits: u16, (low, high): (Expr, Expr)) {
        let low = if bits < 64 {
            Expr::bin(BinOp::And, low, Expr::constant((1 << bits) - 1))
        } else {
            low
        };
        self.assign(
            RegRef {
                index: slot,
                width: 64,
            },
            low,
        );
        self.assign(
            RegRef {
                index: slot + 1,
                width: 64,
            },
            high,
        );
    }

    /// A write of a vector's halves; a 64-bit vector clears the high half.
    /// The high half is held first when it reads the low one it replaces.
    fn write_vector(&mut self, (slot, full, _): (u16, bool, u8), low: Expr, high: Expr) {
        let high = if full {
            let mut read = std::collections::HashSet::new();
            crate::ir::visit::collect_reads(&high, &mut read);
            if read.contains(&slot) {
                self.hold(high)
            } else {
                high
            }
        } else {
            Expr::constant(0)
        };
        self.write_simd(slot, 128, (low, high));
    }

    fn simd_store(&mut self, slot: u16, bits: u16, address: &Expr) {
        preserve_compare(&mut self.last_compare, Write::Memory, &mut self.stmts);
        if bits == 128 {
            let high = Expr::bin(BinOp::Add, address.clone(), Expr::constant(8));
            self.stmts.push(Stmt::Store {
                addr: address.clone(),
                value: Expr::reg(slot, 64),
                width: 8,
            });
            self.stmts.push(Stmt::Store {
                addr: high,
                value: Expr::reg(slot + 1, 64),
                width: 8,
            });
        } else {
            self.stmts.push(Stmt::Store {
                addr: address.clone(),
                value: self.read_simd(slot, bits),
                width: (bits / 8) as u8,
            });
        }
    }

    /// The condition encoded as `code`; `al` and `nv` both always hold.
    fn test_code(&self, code: u8) -> Test {
        match Cond::from_code(code) {
            Some(cond) => self.test(cond),
            None => Test::Always,
        }
    }

    /// Writes `then` or `els` to `dest` as `test` decides.
    fn select(&mut self, dest: RegRef, test: Test, then: Expr, els: Expr) {
        match test.select(then, els) {
            Some(value) => self.assign(dest, value),
            None => self.stmts.push(Stmt::unsupported(
                "conditional select on flags not modelled here".to_owned(),
            )),
        }
    }

    fn read_reg(index: u16, width: u8) -> Expr {
        if index == 31 && width == 32 {
            return Expr::constant(0);
        }
        let slot = Expr::reg(index, 64);
        if width == 32 {
            Expr::bin(BinOp::And, slot, Expr::constant(0xffff_ffff))
        } else {
            slot
        }
    }

    fn assign(&mut self, dest: RegRef, value: Expr) {
        preserve_compare(
            &mut self.last_compare,
            Write::Register(dest.index, Some(&value)),
            &mut self.stmts,
        );
        let value = if dest.width == 32 {
            Expr::bin(BinOp::And, value, Expr::constant(0xffff_ffff))
        } else {
            value
        };
        self.stmts.push(Stmt::Assign {
            dest: RegRef {
                index: dest.index,
                width: 64,
            },
            value,
        });
    }

    fn operand(&self, operand: Operand, width: u8) -> Option<Expr> {
        match operand {
            Operand::Register(_, 31) => Some(Expr::constant(0)),
            Operand::Register(_, index) => Some(Self::read_reg(index, width)),
            Operand::RegisterOrSP(_, 31) => Some(Expr::reg(31, 64)),
            // A 32-bit operand reads only the register's low half.
            Operand::RegisterOrSP(size, index) => {
                if size == SizeCode::X {
                    Some(Expr::reg(index, 64))
                } else {
                    Some(Self::read_reg(index, 32))
                }
            }
            Operand::Immediate(value) => Some(Expr::constant(value as u64)),
            Operand::Imm16(value) => Some(Expr::constant(value as u64)),
            Operand::Imm64(value) => Some(Expr::constant(value)),
            Operand::ImmShift(value, shift) => Some(Expr::constant((value as u64) << shift)),
            Operand::RegShift(style, amount, size, index) => {
                let source = if size == SizeCode::X { 64 } else { 32 };
                let value = if index == 31 {
                    Expr::constant(0)
                } else {
                    Self::read_reg(index, source)
                };
                let extended = extend_shift(style, amount as u64, value, size)?;
                // A sign-extended source of a 32-bit operation keeps its low half.
                let signed = matches!(
                    style,
                    a64::ShiftStyle::SXTB
                        | a64::ShiftStyle::SXTH
                        | a64::ShiftStyle::SXTW
                        | a64::ShiftStyle::SXTX
                );
                Some(if width == 32 && signed {
                    Expr::bin(BinOp::And, extended, Expr::constant(0xffff_ffff))
                } else {
                    extended
                })
            }
            Operand::PCOffset(offset) => Some(Expr::constant(offset as u64)),
            Operand::Nothing => None,
            // A vector operand, which the scalar handlers cannot express.
            _ => {
                self.incomplete.set(true);
                None
            }
        }
    }
}

fn shift_expr(style: a64::ShiftStyle, amount: u64, value: Expr) -> Option<Expr> {
    let op = match style {
        a64::ShiftStyle::LSL => BinOp::Shl,
        a64::ShiftStyle::LSR => BinOp::Shr,
        a64::ShiftStyle::ASR => BinOp::Sar,
        _ => return None,
    };
    Some(Expr::bin(op, value, Expr::constant(amount)))
}

fn extend_shift(style: a64::ShiftStyle, amount: u64, value: Expr, size: SizeCode) -> Option<Expr> {
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
fn register_width(operand: Operand) -> Option<u8> {
    match operand {
        Operand::Register(size, _) | Operand::RegisterOrSP(size, _) => {
            Some(if size == SizeCode::X { 64 } else { 32 })
        }
        _ => None,
    }
}

fn destination(operand: Operand) -> Option<RegRef> {
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

fn lift_alu(lifter: &mut Lifter, ops: [Operand; 4], op: BinOp, flags: bool) {
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
            BinOp::And => Flags::logic(value.clone()),
            _ => Flags::difference(lhs, rhs),
        });
    }
    if let Some(dest) = dest {
        lifter.assign(dest, value)
    }
}

fn lift_mul_high(lifter: &mut Lifter, ops: [Operand; 4], signed: bool) {
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

fn lift_madd(lifter: &mut Lifter, ops: [Operand; 4], accumulate: bool) {
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
fn lift_inverted(lifter: &mut Lifter, ops: [Operand; 4], op: BinOp) {
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
fn lift_extract(lifter: &mut Lifter, ops: [Operand; 4]) {
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
fn lift_reverse(lifter: &mut Lifter, ops: [Operand; 4], chunk: Option<u8>) {
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
fn lift_count(lifter: &mut Lifter, ops: [Operand; 4], opcode: a64::Opcode) {
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

fn lift_bic(lifter: &mut Lifter, ops: [Operand; 4], flags: bool) {
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
        lifter.last_compare = Some(Flags::logic(value.clone()));
    }
    // `bics` into the zero register only sets the flags.
    if let Some(dest) = destination(ops[0]) {
        lifter.assign(dest, value);
    }
}

/// `msub Rd, Rn, Rm, Ra` computes `Ra - Rn * Rm`.
fn lift_msub(lifter: &mut Lifter, ops: [Operand; 4]) {
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
fn lift_long_multiply(lifter: &mut Lifter, ops: [Operand; 4], signed: bool, subtract: bool) {
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
fn lift_conditional_compare(lifter: &mut Lifter, ops: [Operand; 4], sum: bool) {
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
fn lift_with_carry(lifter: &mut Lifter, ops: [Operand; 4], subtract: bool, flags: bool) {
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
fn lift_bitfield_insert(lifter: &mut Lifter, ops: [Operand; 4]) {
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

fn mask_bits(bits: u64) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1 << bits) - 1
    }
}

fn immediates(operand: Operand) -> Option<u64> {
    match operand {
        Operand::Immediate(value) => Some(value as u64),
        Operand::Imm16(value) => Some(value as u64),
        Operand::ImmShift(value, shift) => Some((value as u64) << shift),
        _ => None,
    }
}

fn lift_mov(lifter: &mut Lifter, ops: [Operand; 4], invert: bool) {
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

fn lift_movk(lifter: &mut Lifter, ops: [Operand; 4]) {
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

fn lift_bitfield(lifter: &mut Lifter, ops: [Operand; 4], signed: bool) {
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

fn lift_variable_shift(lifter: &mut Lifter, ops: [Operand; 4], shift: a64::ShiftStyle) {
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

struct Memory {
    address: Expr,
    writeback: Option<(RegRef, Expr)>,
}

fn read_base(operand: u16) -> Expr {
    if operand == 31 {
        Expr::reg(31, 64)
    } else {
        Expr::reg(operand, 64)
    }
}

fn memory(_lifter: &mut Lifter, operand: Operand, width: u8) -> Option<Memory> {
    match operand {
        Operand::RegPreIndex(reg, offset, writeback) => {
            let base = read_base(reg);
            let address = if offset == 0 {
                base
            } else {
                Expr::bin(BinOp::Add, base, Expr::constant(offset as i64 as u64))
            };
            let dest = RegRef {
                index: reg,
                width: 64,
            };
            Some(Memory {
                address: address.clone(),
                writeback: writeback.then_some((dest, address)),
            })
        }
        Operand::RegPostIndex(reg, offset) => {
            let base = read_base(reg);
            let updated = if offset == 0 {
                base.clone()
            } else {
                Expr::bin(
                    BinOp::Add,
                    base.clone(),
                    Expr::constant(offset as i64 as u64),
                )
            };
            Some(Memory {
                address: base,
                writeback: Some((
                    RegRef {
                        index: reg,
                        width: 64,
                    },
                    updated,
                )),
            })
        }
        Operand::RegRegOffset(base_reg, index_reg, size, style, amount) => {
            let base = read_base(base_reg);
            let index_width = if size == SizeCode::X { 64 } else { 32 };
            let index = Lifter::read_reg(index_reg, index_width);
            let index = extend_shift(style, amount as u64, index, size)?;
            Some(Memory {
                address: Expr::bin(BinOp::Add, base, index),
                writeback: None,
            })
        }
        Operand::RegisterOrSP(_, 31) => Some(Memory {
            address: Expr::reg(31, 64),
            writeback: None,
        }),
        Operand::Register(_, index) => Some(Memory {
            address: Lifter::read_reg(index, width),
            writeback: None,
        }),
        _ => None,
    }
}

fn write_back(lifter: &mut Lifter, writeback: Option<(RegRef, Expr)>) {
    if let Some((dest, value)) = writeback {
        lifter.assign(dest, value);
    }
}

fn lift_load(lifter: &mut Lifter, ops: [Operand; 4], opcode: a64::Opcode) {
    if let Some((slot, bits)) = simd(ops[0]) {
        let Some(mem) = memory(lifter, ops[1], (bits / 8) as u8) else {
            lifter
                .stmts
                .push(Stmt::unsupported("load address".to_owned()));
            return;
        };
        let halves = simd_load(&mem.address, bits);
        lifter.write_simd(slot, bits, halves);
        write_back(lifter, mem.writeback);
        return;
    }
    // A load into the zero register discards the value but still writes
    // back its base.
    let Some(dest) = destination(ops[0]) else {
        let bytes = register_width(ops[0]).map_or(8, |bits| bits / 8);
        if let Some(mem) = memory(lifter, ops[1], bytes) {
            write_back(lifter, mem.writeback);
        }
        return;
    };
    let (load_width, signed) = match opcode {
        a64::Opcode::LDR => (if dest.width == 64 { 8 } else { 4 }, false),
        a64::Opcode::LDRB => (1, false),
        a64::Opcode::LDRH => (2, false),
        a64::Opcode::LDRSB => (1, true),
        a64::Opcode::LDRSH => (2, true),
        a64::Opcode::LDRSW => (4, true),
        _ => (4, false),
    };
    let Some(mem) = memory(lifter, ops[1], dest.width / 8) else {
        lifter
            .stmts
            .push(Stmt::unsupported("load address".to_owned()));
        return;
    };
    let value = Expr::Load {
        addr: Box::new(mem.address),
        width: load_width,
        signed,
    };
    lifter.assign(dest, value);
    write_back(lifter, mem.writeback);
}

fn lift_store(lifter: &mut Lifter, ops: [Operand; 4], opcode: a64::Opcode) {
    if let Some((slot, bits)) = simd(ops[0]) {
        let Some(mem) = memory(lifter, ops[1], (bits / 8) as u8) else {
            lifter
                .stmts
                .push(Stmt::unsupported("store address".to_owned()));
            return;
        };
        lifter.simd_store(slot, bits, &mem.address);
        write_back(lifter, mem.writeback);
        return;
    }
    let width = match opcode {
        a64::Opcode::STRB => 1,
        a64::Opcode::STRH => 2,
        _ => match register_width(ops[0]) {
            Some(bits) => bits / 8,
            None => {
                lifter
                    .stmts
                    .push(Stmt::unsupported("SIMD store".to_owned()));
                return;
            }
        },
    };
    let value_width = if width == 8 { 64 } else { 32 };
    let Some(value) = lifter.operand(ops[0], value_width) else {
        return;
    };
    let Some(mem) = memory(lifter, ops[1], width) else {
        lifter
            .stmts
            .push(Stmt::unsupported("store address".to_owned()));
        return;
    };
    lifter.stmts.push(Stmt::Store {
        addr: mem.address,
        value,
        width,
    });
    write_back(lifter, mem.writeback);
}

fn lift_pair(lifter: &mut Lifter, ops: [Operand; 4], store: bool, signed: bool) {
    if let (Some((first, bits)), Some((second, _))) = (simd(ops[0]), simd(ops[1])) {
        let Some(mem) = memory(lifter, ops[2], (bits / 8) as u8) else {
            return;
        };
        let second_addr = Expr::bin(
            BinOp::Add,
            mem.address.clone(),
            Expr::constant(u64::from(bits / 8)),
        );
        if store {
            lifter.simd_store(first, bits, &mem.address);
            lifter.simd_store(second, bits, &second_addr);
        } else {
            // Both loads read memory as it was before either write.
            let (a, b) = (simd_load(&mem.address, bits), simd_load(&second_addr, bits));
            lifter.write_simd(first, bits, a);
            lifter.write_simd(second, bits, b);
        }
        write_back(lifter, mem.writeback);
        return;
    }
    let (Some(first_bits), Some(second_bits)) = (register_width(ops[0]), register_width(ops[1]))
    else {
        // A vector pair touches registers the scalar IR does not model.
        lifter.stmts.push(Stmt::unsupported(if store {
            "SIMD vector pair store".to_owned()
        } else {
            "SIMD vector pair load".to_owned()
        }));
        return;
    };
    let Some(mem) = memory(lifter, ops[2], 8) else {
        return;
    };
    // ldpsw's elements are 32 bits, sign-extended into 64-bit registers.
    let width = if signed { 4 } else { first_bits / 8 };
    let second_addr = Expr::bin(
        BinOp::Add,
        mem.address.clone(),
        Expr::constant(width as u64),
    );
    if store {
        let (Some(a), Some(b)) = (
            lifter.operand(ops[0], first_bits),
            lifter.operand(ops[1], second_bits),
        ) else {
            return;
        };
        lifter.stmts.push(Stmt::Store {
            addr: mem.address,
            value: a,
            width,
        });
        lifter.stmts.push(Stmt::Store {
            addr: second_addr,
            value: b,
            width,
        });
    } else {
        let load = |addr: Expr| Expr::Load {
            addr: Box::new(addr),
            width,
            signed,
        };
        let (a, b) = (load(mem.address), load(second_addr));
        // The second address may read the register the first load writes.
        let b = match destination(ops[0]) {
            Some(first)
                if {
                    let mut read = std::collections::HashSet::new();
                    crate::ir::visit::collect_reads(&b, &mut read);
                    read.contains(&first.index)
                } =>
            {
                lifter.hold(b)
            }
            _ => b,
        };
        // A load into the zero register is discarded.
        if let Some(first) = destination(ops[0]) {
            lifter.assign(first, a);
        }
        if let Some(second) = destination(ops[1]) {
            lifter.assign(second, b);
        }
    }
    write_back(lifter, mem.writeback);
}

/// Whether an instruction writes NZCV; `msr` stands for the writes to PSTATE
/// (`cfinv`, `axflag`) the decoder shows as one.
fn sets_flags(opcode: a64::Opcode) -> bool {
    use a64::Opcode as O;
    matches!(
        opcode,
        O::ADDS
            | O::SUBS
            | O::ANDS
            | O::BICS
            | O::ADCS
            | O::SBCS
            | O::CCMP
            | O::CCMN
            | O::FCMP
            | O::FCMPE
            | O::FCCMP
            | O::FCCMPE
            | O::MSR
            | O::RMIF
            | O::SETF8
            | O::SETF16
            | O::SUBPS
    )
}

/// The registers, as the IR numbers them, an instruction may write: every
/// register it names, and a base it writes back.
fn written_registers(ins: &Instruction) -> Vec<u16> {
    let vector = |number: u16| {
        let slot = crate::arch::aarch64::V0 + 2 * number;
        [slot, slot + 1]
    };
    let mut out = Vec::new();
    for operand in ins.operands {
        match operand {
            Operand::Register(_, 31) => {}
            Operand::Register(_, index) | Operand::RegisterOrSP(_, index) => out.push(index),
            Operand::SIMDRegister(_, number)
            | Operand::SIMDRegisterElements(_, number, _)
            | Operand::SIMDRegisterElementsLane(_, number, ..)
            | Operand::SIMDRegisterElementsMultipleLane(_, number, ..) => {
                out.extend(vector(number))
            }
            Operand::SIMDRegisterGroup(_, number, _, count)
            | Operand::SIMDRegisterGroupLane(number, _, count, _) => {
                for offset in 0..u16::from(count) {
                    out.extend(vector((number + offset) % 32));
                }
            }
            Operand::RegPreIndex(base, _, true)
            | Operand::RegPostIndex(base, _)
            | Operand::RegPostIndexReg(base, _) => out.push(base),
            _ => {}
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// A vector register used whole or as a scalar: its low slot and its width
/// in bits.
fn simd(operand: Operand) -> Option<(u16, u16)> {
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

/// `2^exponent` as a float of `precision`.
fn power_of_two(exponent: u32, precision: Precision) -> Expr {
    let value = 2f64.powi(exponent as i32);
    Expr::constant(match precision {
        Precision::Double => value.to_bits(),
        Precision::Single => u64::from((value as f32).to_bits()),
    })
}

fn precision(bits: u16) -> Option<Precision> {
    match bits {
        32 => Some(Precision::Single),
        64 => Some(Precision::Double),
        _ => None,
    }
}

/// The low and high halves `bits` of memory at `address` fill.
fn simd_load(address: &Expr, bits: u16) -> (Expr, Expr) {
    let load = |addr: Expr, width: u8| Expr::Load {
        addr: Box::new(addr),
        width,
        signed: false,
    };
    if bits == 128 {
        let high = Expr::bin(BinOp::Add, address.clone(), Expr::constant(8));
        (load(address.clone(), 8), load(high, 8))
    } else {
        (load(address.clone(), (bits / 8) as u8), Expr::constant(0))
    }
}

/// A lane of a vector register: its slot, the bit it starts at there, and
/// its width.
fn lane(operand: Operand) -> Option<(u16, u64, u64)> {
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

fn lane_value((slot, shift, bits): (u16, u64, u64)) -> Expr {
    let value = Expr::bin(BinOp::Shr, Expr::reg(slot, 64), Expr::constant(shift));
    if bits == 64 {
        value
    } else {
        Expr::bin(BinOp::And, value, Expr::constant((1 << bits) - 1))
    }
}

/// A vector register with an arrangement: its low slot, whether it fills
/// all 128 bits, and its lane width.
fn vector(operand: Operand) -> Option<(u16, bool, u8)> {
    let Operand::SIMDRegisterElements(size, number, element) = operand else {
        return None;
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
fn halves((slot, full, _): (u16, bool, u8)) -> (Expr, Expr) {
    let high = if full {
        Expr::reg(slot + 1, 64)
    } else {
        Expr::constant(0)
    };
    (Expr::reg(slot, 64), high)
}

/// `value` in every lane of `bits` of a half.
fn replicate(value: Expr, bits: u8) -> Expr {
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
fn window(parts: &[Expr], start: u64) -> Expr {
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

/// The integer vector instructions, lane by lane on each half.
fn lift_vector(lifter: &mut Lifter, ins: &Instruction) -> Option<()> {
    use a64::Opcode as O;
    let ops = ins.operands;
    let lanes = |op, bits, a: Expr, b: Expr| Expr::apply(Operation::Lanes(op, bits), vec![a, b]);
    match ins.opcode {
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
            if vector(ops[0]).is_some() =>
        {
            let dest = vector(ops[0])?;
            let bits = dest.2;
            let (a, b) = (
                halves(vector(ops[1])?),
                match ops[2] {
                    // A compare with zero.
                    Operand::Immediate(0) | Operand::Imm64(0) => {
                        (Expr::constant(0), Expr::constant(0))
                    }
                    operand => halves(vector(operand)?),
                },
            );
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
                _ => LaneOp::MaxUnsigned,
            };
            let low = lanes(op, bits, a.0, b.0);
            let high = lanes(op, bits, a.1, b.1);
            lifter.write_vector(dest, low, high);
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
            let Operand::Immediate(count) = ops[2] else {
                return None;
            };
            let op = match ins.opcode {
                O::SHL => LaneOp::ShiftLeft,
                O::USHR => LaneOp::ShiftRight,
                _ => LaneOp::ShiftRightSigned,
            };
            let count = Expr::constant(u64::from(count));
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
            let Operand::Immediate(start) = ops[3] else {
                return None;
            };
            let parts = if dest.1 {
                vec![n.0, n.1, m.0, m.1]
            } else {
                vec![n.0, m.0]
            };
            let start = 8 * u64::from(start);
            let low = window(&parts, start);
            let high = if dest.1 {
                window(&parts, start + 64)
            } else {
                Expr::constant(0)
            };
            lifter.write_vector(dest, low, high);
        }
        _ => return None,
    }
    Some(())
}

/// The scalar instructions on floating-point registers.
fn lift_float(lifter: &mut Lifter, ins: &Instruction) -> Option<()> {
    use a64::Opcode as O;
    let ops = ins.operands;
    let read = |lifter: &Lifter, operand: Operand| -> Option<(Expr, Precision)> {
        let (slot, bits) = simd(operand)?;
        Some((lifter.read_simd(slot, bits), precision(bits)?))
    };
    let float = |op: Operation, args: Vec<Expr>| Expr::apply(op, args);
    match ins.opcode {
        O::FADD | O::FSUB | O::FMUL | O::FDIV | O::FNMUL => {
            let (slot, bits) = simd(ops[0])?;
            let ((a, p), (b, _)) = (read(lifter, ops[1])?, read(lifter, ops[2])?);
            let value = match ins.opcode {
                O::FADD => float(Operation::FloatAdd(p), vec![a, b]),
                O::FSUB => float(Operation::FloatSub(p), vec![a, b]),
                O::FMUL => float(Operation::FloatMul(p), vec![a, b]),
                O::FDIV => float(Operation::FloatDiv(p), vec![a, b]),
                _ => float(
                    Operation::FloatNegate(p),
                    vec![float(Operation::FloatMul(p), vec![a, b])],
                ),
            };
            lifter.write_simd(slot, bits, (value, Expr::constant(0)));
        }
        O::FSQRT
        | O::FNEG
        | O::FABS
        | O::FRINTN
        | O::FRINTA
        | O::FRINTM
        | O::FRINTP
        | O::FRINTZ
        | O::FRINTX
        | O::FRINTI => {
            let (slot, bits) = simd(ops[0])?;
            let (a, p) = read(lifter, ops[1])?;
            let op = match ins.opcode {
                O::FSQRT => Operation::FloatSqrt(p),
                O::FNEG => Operation::FloatNegate(p),
                O::FABS => Operation::FloatAbs(p),
                O::FRINTA => Operation::FloatRound(p, Rounding::NearestAway),
                O::FRINTM => Operation::FloatRound(p, Rounding::Down),
                O::FRINTP => Operation::FloatRound(p, Rounding::Up),
                O::FRINTZ => Operation::FloatRound(p, Rounding::TowardZero),
                // frintx and frinti round as the current mode does.
                _ => Operation::FloatRound(p, Rounding::NearestEven),
            };
            lifter.write_simd(slot, bits, (float(op, vec![a]), Expr::constant(0)));
        }
        // fmadd d, n, m, a is a + n * m; fmsub negates the product, fnmadd
        // both the product and the addend, and fnmsub the addend.
        O::FMADD | O::FMSUB | O::FNMADD | O::FNMSUB => {
            let (slot, bits) = simd(ops[0])?;
            let ((n, p), (m, _), (a, _)) = (
                read(lifter, ops[1])?,
                read(lifter, ops[2])?,
                read(lifter, ops[3])?,
            );
            let negate = |value| float(Operation::FloatNegate(p), vec![value]);
            let fused = |n, a| float(Operation::FloatMulAdd(p), vec![n, m.clone(), a]);
            let value = match ins.opcode {
                O::FMADD => fused(n, a),
                O::FMSUB => fused(negate(n), a),
                O::FNMADD => fused(negate(n), negate(a)),
                _ => fused(n, negate(a)),
            };
            lifter.write_simd(slot, bits, (value, Expr::constant(0)));
        }
        O::FCMP | O::FCMPE => {
            let (a, p) = read(lifter, ops[0])?;
            let b = match ops[1] {
                Operand::ImmediateDouble(_) => Expr::constant(0),
                operand => read(lifter, operand)?.0,
            };
            lifter.last_compare = Some(Flags::float_compare(a, b, p));
        }
        // Compare when the condition holds, and otherwise set the flags to the
        // immediate, as ccmp does.
        O::FCCMP | O::FCCMPE => {
            let earlier = match ops[3] {
                Operand::ConditionCode(code) => lifter.test_code(code),
                _ => return None,
            };
            let ((a, p), (b, _), Operand::Immediate(nzcv)) =
                (read(lifter, ops[0])?, read(lifter, ops[1])?, ops[2])
            else {
                return None;
            };
            lifter.last_compare = Flags::float_compare(a, b, p).chosen_by(earlier, nzcv as u8);
        }
        O::FCSEL => {
            let (slot, bits) = simd(ops[0])?;
            let ((a, _), (b, _)) = (read(lifter, ops[1])?, read(lifter, ops[2])?);
            let Operand::ConditionCode(code) = ops[3] else {
                return None;
            };
            match lifter.test_code(code).select(a, b) {
                Some(value) => lifter.write_simd(slot, bits, (value, Expr::constant(0))),
                None => lifter.stmts.push(Stmt::unsupported(
                    "conditional select on flags not modelled here".to_owned(),
                )),
            }
        }
        O::FCVT => {
            let (slot, bits) = simd(ops[0])?;
            let (a, from) = read(lifter, ops[1])?;
            let to = precision(bits)?;
            let value = float(Operation::FloatConvert { from, to }, vec![a]);
            lifter.write_simd(slot, bits, (value, Expr::constant(0)));
        }
        O::SCVTF | O::UCVTF => {
            let (slot, bits) = simd(ops[0])?;
            let to = precision(bits)?;
            let source = register_width(ops[1])?;
            let value = lifter.operand(ops[1], source)?;
            let converted = float(
                Operation::IntToFloat {
                    signed: ins.opcode == O::SCVTF,
                    bits: source,
                    to,
                },
                vec![value],
            );
            // A fixed-point source has that many fraction bits; dividing by
            // a power of two adds no rounding.
            let converted = match ops[2] {
                Operand::Immediate(fraction) if fraction > 0 => float(
                    Operation::FloatDiv(to),
                    vec![converted, power_of_two(fraction, to)],
                ),
                _ => converted,
            };
            lifter.write_simd(slot, bits, (converted, Expr::constant(0)));
        }
        O::FCVTZS
        | O::FCVTZU
        | O::FCVTNS
        | O::FCVTNU
        | O::FCVTAS
        | O::FCVTAU
        | O::FCVTMS
        | O::FCVTMU
        | O::FCVTPS
        | O::FCVTPU => {
            let (a, from) = read(lifter, ops[1])?;
            let (signed, rounding) = match ins.opcode {
                O::FCVTZS => (true, Rounding::TowardZero),
                O::FCVTZU => (false, Rounding::TowardZero),
                O::FCVTNS => (true, Rounding::NearestEven),
                O::FCVTNU => (false, Rounding::NearestEven),
                O::FCVTAS => (true, Rounding::NearestAway),
                O::FCVTAU => (false, Rounding::NearestAway),
                O::FCVTMS => (true, Rounding::Down),
                O::FCVTMU => (false, Rounding::Down),
                O::FCVTPS => (true, Rounding::Up),
                _ => (false, Rounding::Up),
            };
            // A fixed-point result keeps that many fraction bits.
            let a = match ops[2] {
                Operand::Immediate(fraction) if fraction > 0 => float(
                    Operation::FloatMul(from),
                    vec![a, power_of_two(fraction, from)],
                ),
                _ => a,
            };
            let converted = float(
                Operation::FloatToInt {
                    signed,
                    bits: register_width(ops[0])?,
                    from,
                    saturating: true,
                    rounding,
                },
                vec![a],
            );
            if let Some(dest) = destination(ops[0]) {
                lifter.assign(dest, converted);
            }
        }
        O::FMOV => match (ops[0], ops[1]) {
            (Operand::SIMDRegister(..), Operand::SIMDRegister(..)) => {
                let ((slot, bits), (from, _)) = (simd(ops[0])?, simd(ops[1])?);
                let value = lifter.read_simd(from, bits);
                lifter.write_simd(slot, bits, (value, Expr::constant(0)));
            }
            (Operand::SIMDRegister(..), Operand::Register(..)) => {
                let (slot, bits) = simd(ops[0])?;
                let value = lifter.operand(ops[1], bits as u8)?;
                lifter.write_simd(slot, bits, (value, Expr::constant(0)));
            }
            (Operand::Register(..), Operand::SIMDRegister(..)) => {
                let (from, bits) = simd(ops[1])?;
                let value = lifter.read_simd(from, bits);
                if let Some(dest) = destination(ops[0]) {
                    lifter.assign(dest, value);
                }
            }
            (Operand::SIMDRegister(..), Operand::ImmediateDouble(value)) => {
                let (slot, bits) = simd(ops[0])?;
                let pattern = match precision(bits)? {
                    Precision::Double => value.to_bits(),
                    Precision::Single => u64::from((value as f32).to_bits()),
                };
                lifter.write_simd(slot, bits, (Expr::constant(pattern), Expr::constant(0)));
            }
            // The upper half of a 128-bit register, which the rest keeps.
            (Operand::SIMDRegisterElementsLane(_, number, a64::SIMDSizeCode::D, 1), source) => {
                let value = lifter.operand(source, 64)?;
                let slot = crate::arch::aarch64::V0 + 2 * number + 1;
                lifter.assign(
                    RegRef {
                        index: slot,
                        width: 64,
                    },
                    value,
                );
            }
            (dest, Operand::SIMDRegisterElementsLane(_, number, a64::SIMDSizeCode::D, 1)) => {
                let value = Expr::reg(crate::arch::aarch64::V0 + 2 * number + 1, 64);
                if let Some(dest) = destination(dest) {
                    lifter.assign(dest, value);
                }
            }
            _ => return None,
        },
        // A lane read out to a scalar or general register.
        O::DUP | O::UMOV | O::SMOV if lane(ops[1]).is_some() && vector(ops[0]).is_none() => {
            let source = lane(ops[1])?;
            let value = lane_value(source);
            match simd(ops[0]) {
                Some((slot, bits)) if u64::from(bits) == source.2 => {
                    lifter.write_simd(slot, bits, (value, Expr::constant(0)))
                }
                Some(_) => return None,
                None => {
                    let value = if ins.opcode == O::SMOV {
                        Expr::SignExtend {
                            value: Box::new(value),
                            width: (source.2 / 8) as u8,
                        }
                    } else {
                        value
                    };
                    if let Some(dest) = destination(ops[0]) {
                        lifter.assign(dest, value);
                    }
                }
            }
        }
        // A lane written from a general register or another lane; the rest
        // of the register stays.
        O::INS => {
            let (slot, shift, bits) = lane(ops[0])?;
            let value = match lane(ops[1]) {
                Some(source) => lane_value(source),
                None => lifter.operand(ops[1], bits as u8)?,
            };
            let ones = if bits == 64 {
                u64::MAX
            } else {
                (1 << bits) - 1
            };
            let merged = if bits == 64 {
                value
            } else {
                Expr::bin(
                    BinOp::Or,
                    Expr::bin(
                        BinOp::And,
                        Expr::reg(slot, 64),
                        Expr::constant(!(ones << shift)),
                    ),
                    Expr::bin(
                        BinOp::Shl,
                        Expr::bin(BinOp::And, value, Expr::constant(ones)),
                        Expr::constant(shift),
                    ),
                )
            };
            lifter.assign(
                RegRef {
                    index: slot,
                    width: 64,
                },
                merged,
            );
        }
        // Zero, or a 64-bit pattern in each half.
        O::MOVI => {
            let Operand::Imm64(value) = ops[1] else {
                return None;
            };
            match ops[0] {
                Operand::SIMDRegister(a64::SIMDSizeCode::D, number) => lifter.write_simd(
                    crate::arch::aarch64::V0 + 2 * number,
                    64,
                    (Expr::constant(value), Expr::constant(0)),
                ),
                Operand::SIMDRegisterElements(size, number, a64::SIMDSizeCode::D)
                    if value == 0 || size == a64::SIMDSizeCode::Q =>
                {
                    let high = if size == a64::SIMDSizeCode::Q {
                        value
                    } else {
                        0
                    };
                    lifter.write_simd(
                        crate::arch::aarch64::V0 + 2 * number,
                        128,
                        (Expr::constant(value), Expr::constant(high)),
                    )
                }
                Operand::SIMDRegisterElements(size, number, _) if value == 0 => lifter.write_simd(
                    crate::arch::aarch64::V0 + 2 * number,
                    if size == a64::SIMDSizeCode::Q {
                        128
                    } else {
                        64
                    },
                    (Expr::constant(0), Expr::constant(0)),
                ),
                _ => return None,
            }
        }
        _ => return None,
    }
    Some(())
}

fn relative_target(operand: Operand, pc: u64) -> Option<u64> {
    match operand {
        Operand::PCOffset(offset) => Some(pc.wrapping_add(offset as u64)),
        _ => None,
    }
}

fn lift_cond_branch(lifter: &mut Lifter, ops: [Operand; 4], code: u8, pc: u64) -> bool {
    let Some(target) = lifter.target_of(ops[0], pc) else {
        lifter
            .stmts
            .push(Stmt::unsupported("branch target".to_owned()));
        return true;
    };
    let test = lifter.test_code(code);
    // Only a condition the flags here leave open names itself in the branch.
    let cond = Cond::from_code(code).unwrap_or(Cond::Eq);
    lifter.stmts.extend(test.branch(cond, target));
    true
}

fn lift_compare_branch(lifter: &mut Lifter, ops: [Operand; 4], pc: u64, non_zero: bool) -> bool {
    // `cbz w0` tests only the low half.
    let width = destination(ops[0]).map_or(64, |register| register.width);
    let Some(value) = lifter.operand(ops[0], width) else {
        return true;
    };
    let Some(target) = relative_target(ops[1], pc) else {
        return true;
    };
    lifter.stmts.push(Stmt::Brif {
        cond: if non_zero { Cond::Ne } else { Cond::Eq },
        lhs: value,
        rhs: Expr::constant(0),
        target,
    });
    true
}

fn lift_test_branch(lifter: &mut Lifter, ops: [Operand; 4], pc: u64, non_zero: bool) -> bool {
    let Some(value) = lifter.operand(ops[0], 64) else {
        return true;
    };
    let Some(bit) = immediates(ops[1]) else {
        return true;
    };
    let Some(target) = relative_target(ops[2], pc) else {
        return true;
    };
    let masked = Expr::bin(BinOp::And, value, Expr::constant(1u64 << (bit & 63)));
    lifter.stmts.push(Stmt::Brif {
        cond: if non_zero { Cond::Ne } else { Cond::Eq },
        lhs: masked,
        rhs: Expr::constant(0),
        target,
    });
    true
}

/// `csinc/csinv/csneg Rd, Rn, Rm, cond`: Rd = cond ? Rn : f(Rm), where f adds
/// one, inverts every bit, or negates.
fn lift_cs_family(lifter: &mut Lifter, ops: [Operand; 4], opcode: a64::Opcode) {
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

fn lift_csel(lifter: &mut Lifter, ops: [Operand; 4]) {
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

fn lift_instruction(lifter: &mut Lifter, ins: &Instruction, pc: u64) -> bool {
    use a64::Opcode as O;
    let ops = ins.operands;
    if lift_float(lifter, ins).is_some() || lift_vector(lifter, ins).is_some() {
        return false;
    }
    // Only loads and stores handle vector operands past this point.
    let vector_operand = ins.operands.iter().any(|operand| {
        matches!(
            operand,
            Operand::SIMDRegister(..)
                | Operand::SIMDRegisterElements(..)
                | Operand::SIMDRegisterElementsLane(..)
                | Operand::SIMDRegisterElementsMultipleLane(..)
                | Operand::SIMDRegisterGroup(..)
                | Operand::SIMDRegisterGroupLane(..)
        )
    });
    if vector_operand
        && !matches!(
            ins.opcode,
            O::LDR | O::LDUR | O::STR | O::STUR | O::LDP | O::STP | O::LDNP | O::STNP
        )
    {
        lifter
            .stmts
            .push(Stmt::unsupported(format!("{:?} at 0x{pc:x}", ins.opcode)));
        return false;
    }

    match ins.opcode {
        O::ADD => lift_alu(lifter, ops, BinOp::Add, false),
        O::ADDS => lift_alu(lifter, ops, BinOp::Add, true),
        O::SUB => lift_alu(lifter, ops, BinOp::Sub, false),
        O::SUBS => lift_alu(lifter, ops, BinOp::Sub, true),
        O::AND => lift_alu(lifter, ops, BinOp::And, false),
        O::ANDS => lift_alu(lifter, ops, BinOp::And, true),
        O::ORR => lift_alu(lifter, ops, BinOp::Or, false),
        O::EOR => lift_alu(lifter, ops, BinOp::Xor, false),
        O::BIC => lift_bic(lifter, ops, false),
        O::BICS => lift_bic(lifter, ops, true),
        O::MUL => lift_madd(lifter, ops, false),
        O::UMULH => lift_mul_high(lifter, ops, false),
        O::SMULH => lift_mul_high(lifter, ops, true),
        O::MADD => lift_madd(lifter, ops, true),
        O::CSEL => lift_csel(lifter, ops),
        O::CSINC | O::CSINV | O::CSNEG => lift_cs_family(lifter, ops, ins.opcode),
        O::MSUB => lift_msub(lifter, ops),
        O::UMADDL => lift_long_multiply(lifter, ops, false, false),
        O::SMADDL => lift_long_multiply(lifter, ops, true, false),
        O::UMSUBL => lift_long_multiply(lifter, ops, false, true),
        O::SMSUBL => lift_long_multiply(lifter, ops, true, true),
        O::CCMP => lift_conditional_compare(lifter, ops, false),
        O::CCMN => lift_conditional_compare(lifter, ops, true),
        O::ADC => lift_with_carry(lifter, ops, false, false),
        O::ADCS => lift_with_carry(lifter, ops, false, true),
        O::SBC => lift_with_carry(lifter, ops, true, false),
        O::SBCS => lift_with_carry(lifter, ops, true, true),
        O::BFM => lift_bitfield_insert(lifter, ops),
        O::MOVZ => lift_mov(lifter, ops, false),
        O::MOVN => lift_mov(lifter, ops, true),
        O::MOVK => lift_movk(lifter, ops),
        O::UBFM => lift_bitfield(lifter, ops, false),
        O::SBFM => lift_bitfield(lifter, ops, true),
        O::LSLV => lift_variable_shift(lifter, ops, a64::ShiftStyle::LSL),
        O::LSRV => lift_variable_shift(lifter, ops, a64::ShiftStyle::LSR),
        O::ASRV => lift_variable_shift(lifter, ops, a64::ShiftStyle::ASR),
        O::RORV => lift_variable_shift(lifter, ops, a64::ShiftStyle::ROR),
        O::EXTR => lift_extract(lifter, ops),
        O::ORN => lift_inverted(lifter, ops, BinOp::Or),
        O::EON => lift_inverted(lifter, ops, BinOp::Xor),
        O::REV => lift_reverse(lifter, ops, None),
        O::CLZ | O::CLS | O::RBIT => lift_count(lifter, ops, ins.opcode),
        O::REV16 => lift_reverse(lifter, ops, Some(2)),
        O::REV32 => lift_reverse(lifter, ops, Some(4)),
        O::LDR => lift_load(lifter, ops, O::LDR),
        O::LDRB => lift_load(lifter, ops, O::LDRB),
        O::LDRH => lift_load(lifter, ops, O::LDRH),
        O::LDRSB => lift_load(lifter, ops, O::LDRSB),
        O::LDRSH => lift_load(lifter, ops, O::LDRSH),
        O::LDRSW => lift_load(lifter, ops, O::LDRSW),
        O::STR => lift_store(lifter, ops, O::STR),
        O::STRB => lift_store(lifter, ops, O::STRB),
        O::STRH => lift_store(lifter, ops, O::STRH),
        // The unscaled forms differ only in how the offset is encoded.
        O::LDUR => lift_load(lifter, ops, O::LDR),
        O::LDURB => lift_load(lifter, ops, O::LDRB),
        O::LDURH => lift_load(lifter, ops, O::LDRH),
        O::LDURSB => lift_load(lifter, ops, O::LDRSB),
        O::LDURSH => lift_load(lifter, ops, O::LDRSH),
        O::LDURSW => lift_load(lifter, ops, O::LDRSW),
        O::STUR => lift_store(lifter, ops, O::STR),
        O::STURB => lift_store(lifter, ops, O::STRB),
        O::STURH => lift_store(lifter, ops, O::STRH),
        O::SDIV => lift_alu(lifter, ops, BinOp::DivS, false),
        O::UDIV => lift_alu(lifter, ops, BinOp::DivU, false),
        O::LDP | O::LDNP => lift_pair(lifter, ops, false, false),
        O::LDPSW => lift_pair(lifter, ops, false, true),
        O::STP | O::STNP => lift_pair(lifter, ops, true, false),
        O::B => {
            let target = lifter.target_of(ops[0], pc);
            // A branch to itself is an unresolved reference to another
            // function; lift it as a tail call.
            if target == Some(pc) {
                lifter
                    .stmts
                    .extend(tail_call(lifter.image, lifter.summaries, None));
                return true;
            }
            if let Some(target) = target
                && lifter.is_tail_call(target)
            {
                lifter
                    .stmts
                    .extend(tail_call(lifter.image, lifter.summaries, Some(target)));
                return true;
            }
            lifter.stmts.push(Stmt::Br { target });
            return true;
        }
        O::Bcc(code) => return lift_cond_branch(lifter, ops, code, pc),
        O::CBZ => return lift_compare_branch(lifter, ops, pc, false),
        O::CBNZ => return lift_compare_branch(lifter, ops, pc, true),
        O::TBZ => return lift_test_branch(lifter, ops, pc, false),
        O::TBNZ => return lift_test_branch(lifter, ops, pc, true),
        O::BR => {
            if let Some(target) = lifter.operand(ops[0], 64) {
                lifter.stmts.push(Stmt::BrIndirect { target });
            }
            return true;
        }
        O::BLR => {
            if let Some(through) = lifter.operand(ops[0], 64) {
                lifter.stmts.push(call_through(lifter.image, through));
            }
        }
        O::BL => {
            let target = lifter.target_of(ops[0], pc);
            let made = call(lifter.image, lifter.summaries, target);
            lifter.stmts.push(made);
            if target.is_some_and(|target| (lifter.summaries)(target).noreturn) {
                lifter.stmts.push(Stmt::Trap);
                return true;
            }
        }
        O::RET => {
            let value = Lifter::read_reg(0, 64);
            lifter.stmts.push(Stmt::Ret { value });
            return true;
        }
        O::ADRP => {
            if let (Some(dest), Operand::PCOffset(offset)) = (destination(ops[0]), ops[1]) {
                let page = pc & !0xfff;
                let value = Expr::constant(page.wrapping_add(offset as u64));
                lifter.assign(dest, value);
            }
        }
        O::ADR => {
            if let (Some(dest), Operand::PCOffset(offset)) = (destination(ops[0]), ops[1]) {
                let value = Expr::constant(pc.wrapping_add(offset as u64));
                lifter.assign(dest, value);
            }
        }
        O::HINT => {}
        // The kernel's call: its number and arguments in registers.
        O::SVC => lifter.stmts.push(Stmt::Call {
            target: None,
            through: None,
            convention: crate::ir::Convention::SyscallArm,
            args: None,
            result: None,
        }),
        other => {
            lifter
                .stmts
                .push(Stmt::unsupported(format!("{other:?} at 0x{pc:x}")));
        }
    }
    false
}

fn branch_target(ins: &Instruction, pc: u64) -> Option<u64> {
    use a64::Opcode as O;
    match ins.opcode {
        O::B | O::Bcc(_) | O::BL => relative_target(ins.operands[0], pc),
        O::CBZ | O::CBNZ => relative_target(ins.operands[1], pc),
        O::TBZ | O::TBNZ => relative_target(ins.operands[2], pc),
        _ => None,
    }
}

pub(super) fn decode(bytes: &[u8], addr: u64) -> (Vec<Decoded<Instruction>>, Option<String>) {
    let mut reader = ReaderBuilder::<u64, u8>::read_at(bytes, 0);
    let decoder = a64::InstDecoder::default();
    let count = bytes.len() / 4;
    let mut decoded = Vec::new();
    for index in 0..count.min(MAX_INSTRUCTIONS) {
        let pc = addr + 4 * index as u64;
        match decoder.decode(&mut reader) {
            Ok(instruction) => decoded.push(Decoded {
                pc,
                next: pc + 4,
                instruction,
            }),
            Err(error) => {
                return (
                    decoded,
                    Some(format!("undecodable instruction at 0x{pc:x}: {error}")),
                );
            }
        }
    }
    let stop = (count > MAX_INSTRUCTIONS)
        .then(|| format!("stopped after {MAX_INSTRUCTIONS} instructions"));
    (decoded, stop)
}

impl Machine for Lifter<'_> {
    type Instruction = Instruction;

    fn branch_target(&self, instruction: &Instruction, pc: u64) -> Option<u64> {
        branch_target(instruction, pc)
    }

    fn step(&mut self, instruction: &Instruction, pc: u64) -> bool {
        self.incomplete.set(false);
        let first = self.stmts.len();
        let ended = lift_instruction(self, instruction, pc);
        if self.incomplete.get() {
            self.stmts.push(Stmt::unsupported(format!(
                "{:?} operands at 0x{pc:x}",
                instruction.opcode
            )));
        }
        let changed = written_registers(instruction);
        let mut unsupported = false;
        for stmt in &mut self.stmts[first..] {
            if let Stmt::Unsupported { writes, .. } = stmt {
                unsupported = true;
                if writes.is_none() {
                    *writes = Some(changed.clone());
                }
            }
        }
        self.flags_touched |= unsupported || sets_flags(instruction.opcode);
        ended
    }

    fn take_statements(&mut self) -> Vec<Stmt> {
        std::mem::take(&mut self.stmts)
    }

    fn block_ended(&mut self) {
        self.last_compare = None;
    }

    /// Other paths may enter a branch target with other flags; flags carry
    /// into it only where every block before it leaves the same kind.
    fn block_split(&mut self) {
        self.last_compare = None;
    }

    fn exit_flags(&self) -> Option<Flags> {
        self.last_compare.clone()
    }

    fn enter_block(&mut self, flags: Option<Flags>) {
        self.last_compare = flags;
        self.flags_touched = false;
    }

    fn flags_touched(&self) -> bool {
        self.flags_touched
    }
}

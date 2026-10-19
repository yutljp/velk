use yaxpeax_arch::{Decoder, ReaderBuilder};
use yaxpeax_arm::armv8::a64::{self, Instruction, Operand, SizeCode};

use super::{Decoded, MAX_INSTRUCTIONS, Machine, Write, call, preserve_compare, tail_call};
use crate::ir::{BinOp, Cond, Expr, RegRef, Stmt};

pub(super) struct Lifter<'a> {
    stmts: Vec<Stmt>,
    last_compare: Option<(Expr, Expr)>,
    image: &'a crate::loader::Image,
    function: u64,
}

impl<'a> Lifter<'a> {
    pub(super) fn new(image: &'a crate::loader::Image, function: u64) -> Self {
        Self {
            stmts: Vec::new(),
            last_compare: None,
            image,
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
                let width = if size == SizeCode::X { 64 } else { 32 };
                let value = if index == 31 {
                    Expr::constant(0)
                } else {
                    Self::read_reg(index, width)
                };
                extend_shift(style, amount as u64, value, size)
            }
            Operand::PCOffset(offset) => Some(Expr::constant(offset as u64)),
            _ => None,
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
    if flags {
        lifter.last_compare = Some((lhs.clone(), rhs.clone()));
    }
    let value = Expr::bin(op, lhs, rhs);
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
fn lift_bic(lifter: &mut Lifter, ops: [Operand; 4]) {
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
    let (Some(dest), Some(base), Some(mask)) = (
        destination(ops[0]),
        lifter.operand(ops[1], width),
        lifter.operand(ops[2], width),
    ) else {
        lifter.stmts.push(Stmt::Unsupported {
            text: "bic".to_owned(),
        });
        return;
    };
    let inverted = Expr::bin(BinOp::Xor, mask, Expr::constant(u64::MAX));
    lifter.assign(dest, Expr::bin(BinOp::And, base, inverted));
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

fn lift_umaddl(lifter: &mut Lifter, ops: [Operand; 4], signed: bool) {
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
    let value = match lifter.operand(ops[3], 64) {
        Some(base) => Expr::bin(BinOp::Add, product, base),
        None => product,
    };
    lifter.assign(dest, value);
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
            None => lifter.stmts.push(Stmt::Unsupported {
                text: "bitfield shift".to_owned(),
            }),
        }
    } else if imms + 1 == immr {
        match shift_expr(a64::ShiftStyle::LSL, dest.width as u64 - immr, source) {
            Some(value) => lifter.assign(dest, value),
            None => lifter.stmts.push(Stmt::Unsupported {
                text: "bitfield shift".to_owned(),
            }),
        }
    } else {
        lifter.stmts.push(Stmt::Unsupported {
            text: format!("bitfield immr={immr} imms={imms}"),
        });
    }
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
    let op = match shift {
        a64::ShiftStyle::LSL => BinOp::Shl,
        a64::ShiftStyle::LSR => BinOp::Shr,
        a64::ShiftStyle::ASR => BinOp::Sar,
        _ => {
            lifter.stmts.push(Stmt::Unsupported {
                text: "rotate/extend".to_owned(),
            });
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
    let Some(dest) = destination(ops[0]) else {
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
        lifter.stmts.push(Stmt::Unsupported {
            text: "load address".to_owned(),
        });
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
    let width = match opcode {
        a64::Opcode::STRB => 1,
        a64::Opcode::STRH => 2,
        _ => match register_width(ops[0]) {
            Some(bits) => bits / 8,
            None => {
                lifter.stmts.push(Stmt::Unsupported {
                    text: "SIMD store".to_owned(),
                });
                return;
            }
        },
    };
    let value_width = if width == 8 { 64 } else { 32 };
    let Some(value) = lifter.operand(ops[0], value_width) else {
        return;
    };
    let Some(mem) = memory(lifter, ops[1], width) else {
        lifter.stmts.push(Stmt::Unsupported {
            text: "store address".to_owned(),
        });
        return;
    };
    lifter.stmts.push(Stmt::Store {
        addr: mem.address,
        value,
        width,
    });
    write_back(lifter, mem.writeback);
}

fn lift_pair(lifter: &mut Lifter, ops: [Operand; 4], store: bool) {
    let (Some(first_bits), Some(second_bits)) = (register_width(ops[0]), register_width(ops[1]))
    else {
        // A vector pair touches registers the scalar IR does not model.
        lifter.stmts.push(Stmt::Unsupported {
            text: if store {
                "SIMD vector pair store".to_owned()
            } else {
                "SIMD vector pair load".to_owned()
            },
        });
        return;
    };
    let Some(mem) = memory(lifter, ops[2], 8) else {
        return;
    };
    let width = first_bits / 8;
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
        // A load into the zero register is discarded.
        if let Some(first) = destination(ops[0]) {
            let a = Expr::Load {
                addr: Box::new(mem.address),
                width,
                signed: false,
            };
            lifter.assign(first, a);
        }
        if let Some(second) = destination(ops[1]) {
            let b = Expr::Load {
                addr: Box::new(second_addr),
                width,
                signed: false,
            };
            lifter.assign(second, b);
        }
    }
    write_back(lifter, mem.writeback);
}

fn relative_target(operand: Operand, pc: u64) -> Option<u64> {
    match operand {
        Operand::PCOffset(offset) => Some(pc.wrapping_add(offset as u64)),
        _ => None,
    }
}

fn lift_cond_branch(lifter: &mut Lifter, ops: [Operand; 4], code: u8, pc: u64) -> bool {
    let Some(target) = lifter.target_of(ops[0], pc) else {
        lifter.stmts.push(Stmt::Unsupported {
            text: "branch target".to_owned(),
        });
        return true;
    };
    let Some(cond) = Cond::from_code(code) else {
        lifter.stmts.push(Stmt::Unsupported {
            text: format!("condition {code}"),
        });
        return true;
    };
    match lifter.last_compare.take() {
        Some((lhs, rhs)) => lifter.stmts.push(Stmt::Brif {
            cond,
            lhs,
            rhs,
            target,
        }),
        None => lifter.stmts.push(Stmt::BrifFlags { cond, target }),
    }
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
    let Some(cond) = Cond::from_code(code) else {
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
    let (lhs, rhs) = lifter
        .last_compare
        .clone()
        .unwrap_or_else(|| (a.clone(), Expr::constant(0)));
    let mut then_value = a.clone();
    let mut els_value = decorate(b.clone());
    let mut cond = sign_condition(cond, &rhs);
    // `cset` encodes the inverted condition with zero as the true value;
    // swap back so the condition matches the comparison.
    if matches!(then_value, Expr::Const(0)) && !matches!(els_value, Expr::Const(0)) {
        std::mem::swap(&mut then_value, &mut els_value);
        cond = cond.invert();
    }
    let value = Expr::Select {
        cond,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
        then: Box::new(then_value),
        els: Box::new(els_value),
    };
    lifter.assign(dest, value);
    // `last_compare` is kept: a following conditional select reads the same flags.
}

/// After a compare with zero, `mi`/`pl` equal signed `<`/`>=`: subtracting
/// zero cannot overflow, so N alone decides `lt`.
fn sign_condition(cond: Cond, rhs: &Expr) -> Cond {
    if !matches!(rhs, Expr::Const(0)) {
        return cond;
    }
    match cond {
        Cond::Mi => Cond::Lt,
        Cond::Pl => Cond::Ge,
        other => other,
    }
}

fn lift_csel(lifter: &mut Lifter, ops: [Operand; 4]) {
    let Some(dest) = destination(ops[0]) else {
        return;
    };
    let Operand::ConditionCode(code) = ops[3] else {
        return;
    };
    let Some(cond) = Cond::from_code(code) else {
        return;
    };
    let Some(then_value) = lifter.operand(ops[1], dest.width) else {
        return;
    };
    let Some(els_value) = lifter.operand(ops[2], dest.width) else {
        return;
    };
    let (lhs, rhs) = lifter
        .last_compare
        .clone()
        .unwrap_or_else(|| (then_value.clone(), Expr::constant(0)));
    let cond = sign_condition(cond, &rhs);
    let value = Expr::Select {
        cond,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
        then: Box::new(then_value),
        els: Box::new(els_value),
    };
    lifter.assign(dest, value);
}

fn lift_instruction(lifter: &mut Lifter, ins: &Instruction, pc: u64) -> bool {
    use a64::Opcode as O;
    let ops = ins.operands;

    match ins.opcode {
        O::ADD => lift_alu(lifter, ops, BinOp::Add, false),
        O::ADDS => lift_alu(lifter, ops, BinOp::Add, true),
        O::SUB => lift_alu(lifter, ops, BinOp::Sub, false),
        O::SUBS => lift_alu(lifter, ops, BinOp::Sub, true),
        O::AND => lift_alu(lifter, ops, BinOp::And, false),
        O::ANDS => lift_alu(lifter, ops, BinOp::And, true),
        O::ORR => lift_alu(lifter, ops, BinOp::Or, false),
        O::EOR => lift_alu(lifter, ops, BinOp::Xor, false),
        O::BIC | O::BICS => lift_bic(lifter, ops),
        O::MUL => lift_madd(lifter, ops, false),
        O::UMULH => lift_mul_high(lifter, ops, false),
        O::SMULH => lift_mul_high(lifter, ops, true),
        O::MADD => lift_madd(lifter, ops, true),
        O::CSEL => lift_csel(lifter, ops),
        O::CSINC | O::CSINV | O::CSNEG => lift_cs_family(lifter, ops, ins.opcode),
        O::MSUB => lift_msub(lifter, ops),
        O::UMADDL => lift_umaddl(lifter, ops, false),
        O::SMADDL => lift_umaddl(lifter, ops, true),
        O::MOVZ => lift_mov(lifter, ops, false),
        O::MOVN => lift_mov(lifter, ops, true),
        O::MOVK => lift_movk(lifter, ops),
        O::UBFM => lift_bitfield(lifter, ops, false),
        O::SBFM => lift_bitfield(lifter, ops, true),
        O::LSLV => lift_variable_shift(lifter, ops, a64::ShiftStyle::LSL),
        O::LSRV => lift_variable_shift(lifter, ops, a64::ShiftStyle::LSR),
        O::ASRV => lift_variable_shift(lifter, ops, a64::ShiftStyle::ASR),
        O::LDR => lift_load(lifter, ops, O::LDR),
        O::LDRB => lift_load(lifter, ops, O::LDRB),
        O::LDRH => lift_load(lifter, ops, O::LDRH),
        O::LDRSB => lift_load(lifter, ops, O::LDRSB),
        O::LDRSH => lift_load(lifter, ops, O::LDRSH),
        O::LDRSW => lift_load(lifter, ops, O::LDRSW),
        O::STR => lift_store(lifter, ops, O::STR),
        O::STRB => lift_store(lifter, ops, O::STRB),
        O::STRH => lift_store(lifter, ops, O::STRH),
        O::LDP => lift_pair(lifter, ops, false),
        O::STP => lift_pair(lifter, ops, true),
        O::B => {
            let target = lifter.target_of(ops[0], pc);
            // A branch to itself is an unresolved reference to another
            // function; lift it as a tail call.
            if target == Some(pc) {
                lifter.stmts.extend(tail_call(lifter.image, None));
                return true;
            }
            if let Some(target) = target
                && lifter.is_tail_call(target)
            {
                lifter.stmts.extend(tail_call(lifter.image, Some(target)));
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
        O::BL => {
            lifter
                .stmts
                .push(call(lifter.image, lifter.target_of(ops[0], pc)));
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
        other => {
            lifter.stmts.push(Stmt::Unsupported {
                text: format!("{other:?} at 0x{pc:x}"),
            });
        }
    }
    false
}

fn branch_target(ins: &Instruction, pc: u64) -> Option<u64> {
    use a64::Opcode as O;
    match ins.opcode {
        O::B | O::Bcc(_) | O::BL | O::CBZ | O::CBNZ => relative_target(ins.operands[0], pc),
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
        lift_instruction(self, instruction, pc)
    }

    fn take_statements(&mut self) -> Vec<Stmt> {
        std::mem::take(&mut self.stmts)
    }

    fn block_ended(&mut self) {
        self.last_compare = None;
    }

    /// Keeps the compare: the flags a conditional select reads after the
    /// split come from it on the fall-through path.
    fn block_split(&mut self) {}
}

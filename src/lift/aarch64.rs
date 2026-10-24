mod atomic;
mod float;
mod integer;
mod lanes;
mod memory;
mod vector;

pub(super) use atomic::recover_atomic_loops;
#[cfg(test)]
use float::half_immediate;
use float::{lift_float, lift_vector_float};
use integer::{
    destination, extend_shift, immediates, lift_alu, lift_bic, lift_bitfield, lift_bitfield_insert,
    lift_conditional_compare, lift_count, lift_cs_family, lift_csel, lift_extract, lift_inverted,
    lift_long_multiply, lift_madd, lift_mov, lift_movk, lift_msub, lift_mul_high, lift_reverse,
    lift_variable_shift, lift_with_carry, mask_bits, register_width,
};
use lanes::{
    absolute_difference, by_halves, complement, doubling_mul_high, halves, immediate_lane, lane,
    lane_shift, lane_value, lanewise, narrowed, replicate, replicated, reverse_lanes,
    rounding_shift, shift_count, simd, source_halves, unzip, vector, widened, window, write_narrow,
};
use memory::{lift_load, lift_pair, lift_store};
use vector::lift_vector;

use yaxpeax_arch::{Decoder, ReaderBuilder};
use yaxpeax_arm::armv8::a64::{self, Instruction, Operand, SizeCode};

use super::flags::{Flags, Test};
use super::{
    Decoded, Machine, Write, call, call_through, flags, preserve_compare, reverse_bytes, rotate,
    tail_call,
};
use crate::arch::aarch64::LR;
use crate::ir::{
    BinOp, CallKind, Cond, Expr, LaneOp, Operation, Precision, RegRef, Rounding, Stmt,
};

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
}

impl<'a> Lifter<'a> {
    pub(super) fn new(image: &'a crate::loader::Image, summaries: super::Summaries<'a>) -> Self {
        Self {
            stmts: Vec::new(),
            incomplete: Default::default(),
            flags_touched: false,
            last_compare: None,
            image,
            summaries,
        }
    }

    /// A pending relocation overrides the encoded branch offset.
    fn target_of(&self, operand: Operand, pc: u64) -> Option<u64> {
        if let Some(target) = self.image.relocations.get(&pc) {
            return Some(*target);
        }
        relative_target(operand, pc)
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

/// A call's write of the address after it, at `pc`, to the link register.
fn link(lifter: &mut Lifter, pc: u64) {
    let dest = RegRef {
        index: LR,
        width: 64,
    };
    lifter.assign(dest, Expr::constant(pc.wrapping_add(4)));
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

fn lift_instruction(lifter: &mut Lifter, ins: &Instruction, pc: u64) -> bool {
    if atomic::lift(lifter, ins) {
        return false;
    }
    use a64::Opcode as O;
    let ops = ins.operands;
    if lift_float(lifter, ins).is_some()
        || lift_vector(lifter, ins).is_some()
        || lift_vector_float(lifter, ins).is_some()
    {
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
            // In an object a branch to itself is an unresolved reference to
            // another function; lift it as a tail call. In a linked image it
            // is an endless loop.
            if target == Some(pc) && lifter.image.relocatable {
                lifter
                    .stmts
                    .extend(tail_call(lifter.image, lifter.summaries, None));
                return true;
            }
            // Whether a branch out of the function is a tail call is
            // decided once its blocks are known.
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
            // A call leaves the flags undefined.
            lifter.last_compare = None;
            if let Some(through) = lifter.operand(ops[0], 64) {
                // `blr x30` jumps to the address x30 held before the link.
                let through = if matches!(through, Expr::Reg { index: LR, .. }) {
                    lifter.hold(through)
                } else {
                    through
                };
                link(lifter, pc);
                lifter
                    .stmts
                    .push(call_through(CallKind::Invoke, lifter.image, through));
            }
        }
        O::BL => {
            lifter.last_compare = None;
            let target = lifter.target_of(ops[0], pc);
            link(lifter, pc);
            let made = call(CallKind::Invoke, lifter.image, lifter.summaries, target);
            lifter.stmts.push(made);
            if target.is_some_and(|target| (lifter.summaries)(target).noreturn) {
                lifter.stmts.push(Stmt::Trap);
                return true;
            }
        }
        O::BRK | O::UDF => {
            lifter.stmts.push(Stmt::Trap);
            return true;
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
        O::CRC32B
        | O::CRC32H
        | O::CRC32W
        | O::CRC32X
        | O::CRC32CB
        | O::CRC32CH
        | O::CRC32CW
        | O::CRC32CX => {
            let (castagnoli, bits) = match ins.opcode {
                O::CRC32B => (false, 8),
                O::CRC32H => (false, 16),
                O::CRC32W => (false, 32),
                O::CRC32X => (false, 64),
                O::CRC32CB => (true, 8),
                O::CRC32CH => (true, 16),
                O::CRC32CW => (true, 32),
                _ => (true, 64),
            };
            if let (Some(dest), Some(crc), Some(data)) = (
                destination(ops[0]),
                lifter.operand(ops[1], 32),
                lifter.operand(ops[2], bits.max(32)),
            ) {
                let value = Expr::apply(Operation::Crc32 { castagnoli, bits }, vec![crc, data]);
                lifter.assign(dest, value);
            }
        }
        // The kernel's call: its number and arguments in registers.
        O::SVC => lifter.stmts.push(Stmt::Call {
            kind: CallKind::Syscall,
            target: None,
            through: None,
            convention: crate::ir::Convention::SyscallArm,
            args: None,
            // The kernel reads no floating-point register.
            floats_named: true,
            abi: None,
            clobbers: None,
            outputs: crate::ir::fallback_call_outputs(crate::ir::Convention::SyscallArm, None),
            via: None,
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
    let mut pc = addr;
    for _ in 0..count {
        let Some(next) = pc.checked_add(4) else {
            return (
                decoded,
                Some(format!("instruction address overflows at 0x{pc:x}")),
            );
        };
        match decoder.decode(&mut reader) {
            Ok(instruction) => decoded.push(Decoded {
                pc,
                next,
                instruction,
            }),
            Err(error) => {
                return (
                    decoded,
                    Some(format!("undecodable instruction at 0x{pc:x}: {error}")),
                );
            }
        }
        pc = next;
    }
    (decoded, None)
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::arch::aarch64::V0;
    use crate::ir::eval::{self, Convention, Outcome, Setup};
    use crate::ir::{FunctionIr, Stmt};
    use crate::loader::{Image, Isa};

    const RET: u32 = 0xd65f_03c0;

    fn lifted(words: &[u32]) -> FunctionIr {
        let code: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let size = code.len() as u64;
        let image = Image::from_code(Isa::AArch64, 0, code);
        let mut ir = FunctionIr::single_block(Isa::AArch64, Vec::new());
        ir.blocks = crate::lift::lift(&image, 0, size, &HashSet::new()).expect("decoded lift");
        ir
    }

    fn setup(registers: &[(u16, u64)]) -> Setup<'_> {
        Setup {
            seed: 0,
            convention: Convention {
                arguments: &[],
                clobbered: &[],
            },
            registers,
            memory: &[],
            step_limit: 100,
        }
    }

    fn edge(bits: u8, index: usize) -> u64 {
        let limit = 1i64 << (bits - 1);
        let values = [
            -limit,
            -limit + 1,
            -limit / 2,
            -1,
            0,
            1,
            limit / 2,
            limit - 2,
            limit - 1,
        ];
        values[index % values.len()] as u64 & ((1u64 << bits) - 1)
    }

    fn fill(
        registers: &mut [(u16, u64)],
        number: u16,
        bits: u8,
        full: bool,
        row: usize,
        second: bool,
    ) {
        for half in 0..if full { 2 } else { 1 } {
            let mut value = 0;
            for lane in 0..64 / usize::from(bits) {
                let position = half * (64 / usize::from(bits)) + lane;
                let index = if second {
                    row / 9 + position * 3
                } else {
                    row % 9 + position
                };
                value |= edge(bits, index) << (lane * usize::from(bits));
            }
            let slot = V0 + 2 * number + half as u16;
            registers
                .iter_mut()
                .find(|(index, _)| *index == slot)
                .expect("vector slot")
                .1 = value;
        }
    }

    fn product_reference(a: u64, b: u64, bits: u8) -> u64 {
        let mask = (1u64 << bits) - 1;
        let limit = 1i128 << (bits - 1);
        let signed = |value: u64| {
            let value = i128::from(value & mask);
            if value >= limit {
                value - 2 * limit
            } else {
                value
            }
        };
        (0..64 / u32::from(bits)).fold(0, |out, lane| {
            let shift = lane * u32::from(bits);
            let product = 2 * signed(a >> shift) * signed(b >> shift);
            let result = product.div_euclid(1i128 << bits).clamp(-limit, limit - 1);
            out | (result as u64 & mask) << shift
        })
    }

    #[test]
    fn sqdmulh_vectors_match_signed_saturating_products() {
        let mut checked = 0;
        for (bits, full, base) in [
            (16, false, 0x0e60_b400),
            (16, true, 0x4e60_b400),
            (32, false, 0x0ea0_b400),
            (32, true, 0x4ea0_b400),
        ] {
            for (d, n, m) in [
                (0u16, 1u16, 2u16),
                (1, 1, 2),
                (2, 1, 2),
                (0, 1, 1),
                (1, 1, 1),
            ] {
                let word = base | u32::from(m) << 16 | u32::from(n) << 5 | u32::from(d);
                let decoded = super::decode(&word.to_le_bytes(), 0);
                assert!(decoded.1.is_none() && decoded.0.len() == 1, "{word:#010x}");
                assert_eq!(
                    decoded.0[0].instruction.opcode,
                    yaxpeax_arm::armv8::a64::Opcode::SQDMULH
                );
                let ir = lifted(&[word, RET]);
                assert!(
                    !ir.blocks
                        .iter()
                        .flat_map(|block| &block.stmts)
                        .any(|stmt| matches!(stmt, Stmt::Unsupported { .. })),
                    "{}",
                    ir.render()
                );
                for row in 0..if n == m { 9 } else { 81 } {
                    let mut registers: Vec<_> = (0..8u16)
                        .chain(V0..V0 + 64)
                        .map(|index| (index, 0x8877_6655_4433_2211 ^ (u64::from(index) << 32)))
                        .collect();
                    fill(&mut registers, n, bits, full, row, false);
                    if n != m {
                        fill(&mut registers, m, bits, full, row, true);
                    }
                    let before = |index| {
                        registers
                            .iter()
                            .find(|(slot, _)| *slot == index)
                            .expect("initial slot")
                            .1
                    };
                    let low = product_reference(before(V0 + 2 * n), before(V0 + 2 * m), bits);
                    let high = if full {
                        product_reference(before(V0 + 2 * n + 1), before(V0 + 2 * m + 1), bits)
                    } else {
                        0
                    };
                    let (after, memory) =
                        eval::state_after(&ir, &setup(&registers)).expect("modeled vector result");
                    assert!(memory.is_empty());
                    for &(index, initial) in &registers {
                        let expected = if index == V0 + 2 * d {
                            low
                        } else if index == V0 + 2 * d + 1 {
                            high
                        } else {
                            initial
                        };
                        assert_eq!(
                            after.get(&index).copied().unwrap_or(initial),
                            expected,
                            "word {word:#010x}, row {row}, register {index}"
                        );
                    }
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 1044);
    }

    #[test]
    fn sqdmulh_status_accesses_stay_unsupported_after_optimization() {
        const SQDMULH: u32 = 0x4ea2_b420;
        const MRS: u32 = 0xd53b_4420;
        const MSR: u32 = 0xd51b_4420;
        for words in [
            vec![0xd280_0aa0, SQDMULH, MRS, RET],
            vec![MSR, SQDMULH, MRS, RET],
            vec![SQDMULH, 0x1400_0002, 0xd503_201f, MRS, RET],
        ] {
            let mut ir = lifted(&words);
            for optimized in [false, true] {
                if optimized {
                    crate::passes::optimize(&mut ir, false);
                }
                let statements: Vec<_> = ir.blocks.iter().flat_map(|block| &block.stmts).collect();
                assert!(
                    statements.iter().any(|stmt| matches!(stmt,
                    Stmt::Unsupported { text, writes: Some(writes) }
                    if text.starts_with("MRS") && writes.contains(&0))),
                    "{}",
                    ir.render()
                );
                if words.contains(&MSR) {
                    assert!(statements.iter().any(|stmt| matches!(stmt,
                        Stmt::Unsupported { text, .. } if text.starts_with("MSR"))));
                }
                assert!(statements.iter().any(|stmt| matches!(stmt,
                    Stmt::Assign { dest, .. } if dest.index == V0)));
                assert_eq!(
                    eval::run(&ir, &setup(&[(0, 0x55)])),
                    Outcome::Unknown("unsupported instruction")
                );
                assert!(crate::ssa::entry_demands(&ir, &[]).is_none());
                let rendered =
                    crate::render::render(&ir, &[], &crate::render::Symbols::default(), &[]);
                assert!(rendered.contains("unsupported: MRS"), "{rendered}");
            }
        }
    }

    #[test]
    fn sqdmulh_scalar_and_indexed_forms_stay_unsupported() {
        for word in [0x5e62_b420, 0x5ea2_b420, 0x0f42_c020, 0x4fa2_c820] {
            let ir = lifted(&[word, RET]);
            assert!(
                ir.blocks
                    .iter()
                    .flat_map(|block| &block.stmts)
                    .any(|stmt| matches!(stmt,
                Stmt::Unsupported { text, .. } if text.starts_with("SQDMULH"))),
                "{}",
                ir.render()
            );
            assert_eq!(
                eval::run(&ir, &setup(&[])),
                Outcome::Unknown("unsupported instruction")
            );
        }
    }

    #[test]
    fn sqdmulh_preserves_a_retained_integer_comparison() {
        for value in [0, 1, u64::MAX] {
            // cmp x0, #0; sqdmulh v0.4s, v1.4s, v2.4s; b.eq true; return 0/1.
            let ir = lifted(&[
                0xf100_001f,
                0x4ea2_b420,
                0x5400_0060,
                0xd280_0000,
                RET,
                0xd280_0020,
                RET,
            ]);
            assert!(
                !ir.blocks
                    .iter()
                    .flat_map(|block| &block.stmts)
                    .any(|stmt| matches!(stmt, Stmt::Unsupported { .. } | Stmt::BrifFlags { .. }))
            );
            let Outcome::Return {
                value: returned, ..
            } = eval::run(&ir, &setup(&[(0, value)]))
            else {
                panic!("modeled comparison");
            };
            assert_eq!(returned, u64::from(value == 0));
        }
    }
    #[test]
    fn scalar_half_immediates_preserve_exact_bits_and_other_registers() {
        let registers: Vec<_> = (0u16..96)
            .map(|index| {
                let value = if index == crate::arch::stack_pointer(Isa::AArch64) {
                    eval::STACK_TOP
                } else {
                    eval::hash(0x5eed, u64::from(index))
                };
                (index, value)
            })
            .collect();
        let mut checked = 0;
        for immediate in 0u32..256 {
            let bit = u64::from(immediate >> 6 & 1);
            let expected = u64::from(immediate >> 7) << 15
                | (bit ^ 1) << 14
                | (bit * 3) << 12
                | u64::from(immediate & 63) << 6;
            for destination in 0u16..32 {
                let word = 0x1ee0_1000 | immediate << 13 | u32::from(destination);
                let ir = lifted(&[word, RET]);
                assert!(
                    !ir.blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
                        matches!(
                            stmt,
                            Stmt::Unsupported { .. } | Stmt::Call { .. } | Stmt::Store { .. }
                        )
                    }),
                    "{word:#010x}: {}",
                    ir.render()
                );
                let (after, memory) = eval::state_after(&ir, &setup(&registers))
                    .expect("a scalar immediate move has complete integer semantics");
                assert!(memory.is_empty());
                let slot = V0 + 2 * destination;
                for &(index, initial) in &registers {
                    let wanted = if index == slot {
                        expected
                    } else if index == slot + 1 {
                        0
                    } else {
                        initial
                    };
                    assert_eq!(
                        after.get(&index).copied().unwrap_or(initial),
                        wanted,
                        "{word:#010x}, register {index}"
                    );
                }
                checked += 1;
            }
        }
        assert_eq!(checked, 8192);
    }
    #[test]
    fn scalar_half_immediate_rejects_nonencodable_decoded_values() {
        for value in [
            0.0,
            -0.0,
            0.0625,
            32.0,
            1.03125,
            1.1,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::NAN,
            f64::from_bits(1),
        ] {
            assert!(super::half_immediate(value).is_none(), "{value:?}");
        }
        for (value, bits) in [
            (0.125, 0x3000),
            (-0.125, 0xb000),
            (1.0, 0x3c00),
            (-1.0, 0xbc00),
            (1.0625, 0x3c40),
            (31.0, 0x4fc0),
        ] {
            assert_eq!(super::half_immediate(value), Some(bits), "{value:?}");
        }
    }

    #[test]
    fn scalar_half_immediate_does_not_enable_other_half_operations() {
        use yaxpeax_arm::armv8::a64::Opcode;

        for (word, opcode) in [
            (0x1ee2_2820u32, Opcode::FADD),
            (0x1ee2_4020, Opcode::FCVT),
            (0x0f03_fe00, Opcode::FMOV),
        ] {
            let (decoded, issue) = super::decode(&word.to_le_bytes(), 0);
            assert!(issue.is_none(), "{word:#010x}: {issue:?}");
            assert_eq!(decoded.len(), 1);
            assert_eq!(decoded[0].instruction.opcode, opcode, "{word:#010x}");
            let mut ir = lifted(&[word, RET]);
            for optimized in [false, true] {
                if optimized {
                    crate::passes::optimize(&mut ir, false);
                }
                assert!(
                    ir.blocks
                        .iter()
                        .flat_map(|block| &block.stmts)
                        .any(|stmt| matches!(stmt, Stmt::Unsupported { .. })),
                    "{word:#010x}, optimized={optimized}: {}",
                    ir.render()
                );
                assert!(matches!(eval::run(&ir, &setup(&[])), Outcome::Unknown(_)));
            }
        }
    }

    mod half_immediate_decoder {
        use yaxpeax_arch::{Decoder, ReaderBuilder};
        use yaxpeax_arm::armv8::a64::{InstDecoder, Opcode, Operand, SIMDSizeCode};

        #[test]
        fn scalar_half_immediate_decodes_every_constant_and_destination() {
            let mut checked = 0;
            for immediate in 0u32..256 {
                let exponent = if immediate & 0x40 == 0 { 0x400 } else { 0x3fc }
                    | u64::from(immediate >> 4 & 3);
                let expected = u64::from(immediate >> 7) << 63
                    | exponent << 52
                    | u64::from(immediate & 15) << 48;
                for destination in 0u16..32 {
                    let word = 0x1ee0_1000 | immediate << 13 | u32::from(destination);
                    let bytes = word.to_le_bytes();
                    let mut reader = ReaderBuilder::<u64, u8>::read_from(&bytes[..]);
                    let decoded = InstDecoder::default()
                        .decode(&mut reader)
                        .unwrap_or_else(|error| panic!("{word:#010x}: {error}"));
                    assert_eq!(decoded.opcode, Opcode::FMOV, "{word:#010x}");
                    assert!(
                        matches!(decoded.operands[0], Operand::SIMDRegister(SIMDSizeCode::H, number) if number == destination)
                    );
                    let Operand::ImmediateDouble(value) = decoded.operands[1] else {
                        panic!("{word:#010x}: {:?}", decoded.operands);
                    };
                    assert_eq!(value.to_bits(), expected, "{word:#010x}");
                    assert!(
                        decoded.operands[2..]
                            .iter()
                            .all(|operand| matches!(operand, Operand::Nothing))
                    );
                    checked += 1;
                }
            }
            assert_eq!(checked, 8192);
        }
    }

    fn precise_calls(ir: &mut FunctionIr, changed: &[u16]) {
        let mut registers = crate::ir::Registers::default();
        for register in changed {
            registers.insert(*register);
        }
        for stmt in ir.blocks.iter_mut().flat_map(|block| &mut block.stmts) {
            if let Stmt::Call { clobbers, .. } = stmt {
                *clobbers = Some(registers);
            }
        }
    }

    #[test]
    fn decoded_bl_defines_original_next_pc_before_a_preserving_leaf() {
        let mut ir = lifted(&[0x9400_0008, 0xaa1e_03e0, RET]);
        precise_calls(&mut ir, &[]);
        let statements = &ir.blocks[0].stmts;
        let call = statements
            .iter()
            .position(|stmt| matches!(stmt, Stmt::Call { .. }))
            .unwrap();
        assert!(matches!(
            statements[call - 1],
            Stmt::Assign {
                dest: crate::ir::RegRef {
                    index: 30,
                    width: 64
                },
                value: crate::ir::Expr::Const(4)
            }
        ));
        assert!(matches!(
            statements[call],
            Stmt::Call {
                kind: crate::ir::CallKind::Invoke,
                target: Some(32),
                ..
            }
        ));
        assert!(!statements[call].call_clobbers().contains(&30));
        let Outcome::Return { value, calls, .. } = eval::run(&ir, &setup(&[(30, 0x9876)])) else {
            panic!("modeled BL");
        };
        assert_eq!(value, 4);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].target, Some(32));
    }

    #[test]
    fn decoded_blr_x30_captures_old_target_before_link_definition_once() {
        let mut ir = lifted(&[0xd63f_03c0, 0xaa1e_03e0, RET]);
        precise_calls(&mut ir, &[]);
        let statements = &ir.blocks[0].stmts;
        let call = statements
            .iter()
            .position(|stmt| matches!(stmt, Stmt::Call { .. }))
            .unwrap();
        assert!(matches!(
            statements[call - 2],
            Stmt::Assign {
                dest: crate::ir::RegRef {
                    index: crate::ir::EXCHANGE,
                    width: 64
                },
                value: crate::ir::Expr::Reg {
                    index: 30,
                    width: 64
                }
            }
        ));
        assert!(matches!(
            statements[call - 1],
            Stmt::Assign {
                dest: crate::ir::RegRef {
                    index: 30,
                    width: 64
                },
                value: crate::ir::Expr::Const(4)
            }
        ));
        assert!(matches!(
            statements[call],
            Stmt::Call {
                through: Some(crate::ir::Expr::Reg {
                    index: crate::ir::EXCHANGE,
                    width: 64
                }),
                ..
            }
        ));
        let Outcome::Return { value, calls, .. } = eval::run(&ir, &setup(&[(30, 0x8765)])) else {
            panic!("modeled BLR");
        };
        assert_eq!(value, 4);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].target, Some(0x8765));
    }

    #[test]
    fn decoded_blr_other_register_defines_link_without_an_unneeded_snapshot() {
        let mut ir = lifted(&[0xd63f_0000, 0xaa1e_03e0, RET]);
        precise_calls(&mut ir, &[]);
        assert!(!ir.blocks.iter().flat_map(|block| &block.stmts).any(
            |stmt| matches!(stmt, Stmt::Assign { dest, .. } if dest.index == crate::ir::EXCHANGE)
        ));
        let Outcome::Return { value, calls, .. } =
            eval::run(&ir, &setup(&[(0, 0x7654), (30, 0x9999)]))
        else {
            panic!("modeled BLR");
        };
        assert_eq!(value, 4);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].target, Some(0x7654));
    }

    #[test]
    fn callee_link_clobbers_are_separate_from_the_decoded_link_definition() {
        for precise in [false, true] {
            let mut ir = lifted(&[0x9400_0008, 0xaa1e_03e0, RET]);
            if precise {
                precise_calls(&mut ir, &[30]);
            }
            let call = ir
                .blocks
                .iter()
                .flat_map(|block| &block.stmts)
                .find(|stmt| matches!(stmt, Stmt::Call { .. }))
                .unwrap();
            assert!(call.call_clobbers().contains(&30));
            assert!(crate::ir::visit::statement_registers(call).0.contains(&30));
            assert!(
                !call
                    .preserved_output_sources()
                    .iter()
                    .any(|(_, register)| *register == 30)
            );
            let Outcome::Return { value, .. } = eval::run(&ir, &setup(&[(30, 0x9876)])) else {
                panic!("modeled BL");
            };
            assert_eq!(value, 0);
        }
    }

    #[test]
    fn branches_and_system_calls_write_no_link_value() {
        for words in [&[0xd61f_03c0][..], &[0xd400_0001, RET][..]] {
            let ir = lifted(words);
            assert!(
                !ir.blocks
                    .iter()
                    .flat_map(|block| &block.stmts)
                    .any(|stmt| matches!(stmt, Stmt::Assign { dest, .. } if dest.index == 30))
            );
        }
    }
}

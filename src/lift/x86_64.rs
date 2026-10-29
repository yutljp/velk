mod atomic;
mod float;
mod integer;
mod machine;
mod operands;
mod packed;
pub(super) mod string;
mod vector;

use float::lift_float;
use integer::{
    binary, condition, hold, lift_bits, lift_count, lift_exchange, lift_lahf, lift_mul_high,
    select, shift, signed_product_lost, stack_adjust, stack_reads_before, wide_divide, with_carry,
};
use operands::{
    gpr, load_at, memory_address, memory_width, operand, operand_width, write_destination,
    write_operand, xmm,
};
use packed::lift_packed;
use string::{lift_string, string_size};
use vector::lift_vector;

use crate::arch::x86::{RAX, RDX, RSP};
use iced_x86::{
    ConditionCode, Decoder, DecoderOptions, EncodingKind, FlowControl, Instruction, Mnemonic,
    OpKind, Register, RflagsBits,
};

use super::flags::{Flags, Test};
use super::{
    Decoded, Machine, Write, call, call_through, flags, preserve_compare, reverse_bytes, rotate,
    tail_call,
};
use crate::ir::{
    BinOp, Block, CallKind, Cond, EXCHANGE, Expr, LaneOp, Operation, Precision, RegRef, Rounding,
    Stmt,
};
use crate::loader::Image;

/// The flags conditions read; the direction flag is none of them.
const CONDITION_FLAGS: u32 = RflagsBits::CF
    | RflagsBits::PF
    | RflagsBits::AF
    | RflagsBits::ZF
    | RflagsBits::SF
    | RflagsBits::OF;

pub(super) const DIRECTION: u16 = crate::ir::TEMP_BASE + 0x4d;

pub(super) struct Lifter<'a> {
    stmts: Vec<Stmt>,
    last_compare: Option<Flags>,
    /// Whether the instruction being lifted set `last_compare`.
    flags_written: bool,
    /// Whether an operand of the instruction being lifted was one the lifter
    /// cannot express, so that its effect would be lost.
    incomplete: bool,
    /// What each instruction reads and writes, for the registers an
    /// unsupported one may change.
    info: iced_x86::InstructionInfoFactory,
    /// Whether an instruction of the current block may have changed the flags.
    flags_touched: bool,
    /// The body of a `rep` string instruction's loop, after its test.
    extra: Vec<(Block, Option<Flags>)>,
    extended_dividend: Option<u8>,
    /// The width of the high half of an unsigned dividend the previous
    /// instruction cleared (`xor edx, edx`).
    zeroed_dividend: Option<u8>,
    image: &'a Image,
    summaries: super::Summaries<'a>,
}

impl<'a> Lifter<'a> {
    pub(super) fn new(image: &'a Image, summaries: super::Summaries<'a>) -> Self {
        Self {
            stmts: Vec::new(),
            last_compare: None,
            flags_written: false,
            incomplete: false,
            info: iced_x86::InstructionInfoFactory::new(),
            flags_touched: false,
            extra: Vec::new(),
            extended_dividend: None,
            zeroed_dividend: None,
            image,
            summaries,
        }
    }

    fn word_bits(&self) -> u8 {
        if self.image.isa == crate::loader::Isa::I386 {
            32
        } else {
            64
        }
    }

    fn set_flags(&mut self, flags: Flags) {
        self.last_compare = Some(flags);
        self.flags_written = true;
    }

    /// `cond` under the flags; flags set in another block are unknown.
    fn test(&self, cond: Cond) -> Test {
        self.last_compare.as_ref().map_or(Test::Unknown, |flags| {
            flags.test(cond, crate::loader::Isa::X86_64)
        })
    }

    /// The condition code `code` under the flags.
    fn condition_test(&self, code: ConditionCode) -> Test {
        let parity = |even| {
            self.last_compare
                .as_ref()
                .map_or(Test::Unknown, |flags| flags.parity(even))
        };
        match code {
            ConditionCode::p => parity(true),
            ConditionCode::np => parity(false),
            code => condition(code).map_or(Test::Unknown, |cond| self.test(cond)),
        }
    }

    /// The carry flag as one or zero, when the flags here decide it.
    fn carry(&self) -> Option<Expr> {
        self.test(Cond::Cc)
            .select(Expr::constant(1), Expr::constant(0))
    }

    fn read_reg(index: u16, width: u8) -> Expr {
        let slot = Expr::reg(index, 64);
        match width {
            32 => Expr::bin(BinOp::And, slot, Expr::constant(0xffff_ffff)),
            16 => Expr::bin(BinOp::And, slot, Expr::constant(0xffff)),
            8 => Expr::bin(BinOp::And, slot, Expr::constant(0xff)),
            _ => slot,
        }
    }

    fn assign(&mut self, index: u16, width: u8, value: Expr) {
        preserve_compare(
            &mut self.last_compare,
            // A partial write keeps the register's other bits.
            Write::Register(index, matches!(width, 32 | 64).then_some(&value)),
            &mut self.stmts,
        );
        let value = match width {
            32 => Expr::bin(BinOp::And, value, Expr::constant(0xffff_ffff)),
            16 | 8 => {
                let bits = if width == 16 { 16 } else { 8 };
                let mask = (1u64 << bits) - 1;
                let keep = Expr::bin(BinOp::And, Expr::reg(index, 64), Expr::constant(!mask));
                let inserted = Expr::bin(BinOp::And, value, Expr::constant(mask));
                Expr::bin(BinOp::Or, keep, inserted)
            }
            _ => value,
        };
        self.stmts.push(Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
            at: None,
        });
    }
}

/// The registers, as the IR numbers them, an instruction may write.
fn written_registers(
    instruction_info_factory: &mut iced_x86::InstructionInfoFactory,
    instruction: &Instruction,
) -> Vec<u16> {
    use iced_x86::OpAccess;
    let mut out = Vec::new();
    for used in instruction_info_factory.info(instruction).used_registers() {
        if !matches!(
            used.access(),
            OpAccess::Write | OpAccess::ReadWrite | OpAccess::CondWrite | OpAccess::ReadCondWrite
        ) {
            continue;
        }
        let register = used.register();
        if let Some((index, _)) = gpr(register.full_register()) {
            out.push(index);
        } else if (register.is_xmm() || register.is_ymm() || register.is_zmm())
            && register.number() < 16
        {
            let slot = crate::arch::x86::XMM0 + 2 * register.number() as u16;
            out.extend([slot, slot + 1]);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn is_cmov(mnemonic: Mnemonic) -> bool {
    use Mnemonic::*;
    matches!(
        mnemonic,
        Cmovo
            | Cmovno
            | Cmovb
            | Cmovae
            | Cmove
            | Cmovne
            | Cmovbe
            | Cmova
            | Cmovs
            | Cmovns
            | Cmovp
            | Cmovnp
            | Cmovl
            | Cmovge
            | Cmovle
            | Cmovg
    )
}

fn is_setcc(mnemonic: Mnemonic) -> bool {
    use Mnemonic::*;
    matches!(
        mnemonic,
        Seto | Setno
            | Setb
            | Setae
            | Sete
            | Setne
            | Setbe
            | Seta
            | Sets
            | Setns
            | Setp
            | Setnp
            | Setl
            | Setge
            | Setle
            | Setg
    )
}

fn resolved_target(instruction: &Instruction, relocation_target: Option<u64>) -> u64 {
    relocation_target.unwrap_or_else(|| instruction.near_branch_target())
}

fn return_address_register(image: &Image, target: u64) -> Option<u16> {
    let Some(end) = target.checked_add(4) else {
        return None;
    };
    if !image.sections.iter().any(|section| {
        section.executable
            && section.vaddr <= target
            && section
                .vaddr
                .checked_add(section.size)
                .is_some_and(|limit| end <= limit)
    }) {
        return None;
    }
    let Some([0x8b, modrm, 0x24, 0xc3]) = image.read_vaddr(target, 4) else {
        return None;
    };
    if modrm & 0xc7 != 0x04 {
        return None;
    }
    let register = u16::from((modrm >> 3) & 7);
    if register == RSP {
        return None;
    }
    Some(register)
}

fn complete_call(lifter: &mut Lifter, target: u64) -> bool {
    if (lifter.summaries)(target).noreturn {
        lifter.stmts.push(Stmt::Trap { at: None });
        return true;
    }
    if let Some(bytes) = lifter.image.callee_cleanup(target)
        && bytes != 0
    {
        stack_adjust(lifter, i64::from(bytes));
    }
    lifter
        .stmts
        .extend(super::stack_results(lifter.image, lifter.summaries, target));
    false
}

fn lift_instruction(
    lifter: &mut Lifter,
    ins: &Instruction,
    relocation_target: Option<u64>,
) -> bool {
    let was_extended = lifter.extended_dividend.take();
    let was_zeroed = lifter.zeroed_dividend.take();
    if atomic::lift(lifter, ins) {
        return false;
    }
    if is_cmov(ins.mnemonic()) {
        let Some(source) = operand(lifter, ins, 1) else {
            return false;
        };
        let Some(current) = operand(lifter, ins, 0) else {
            return false;
        };
        match select(lifter, ins, source, current) {
            Some(value) => write_destination(lifter, ins, value),
            None => lifter.stmts.push(Stmt::unsupported(format!(
                "cmov without compare at 0x{:x}",
                ins.ip()
            ))),
        }
        return false;
    }
    if is_setcc(ins.mnemonic()) {
        let width = match ins.op0_kind() {
            OpKind::Memory => memory_width(ins).unwrap_or(1),
            _ => 1,
        };
        let bits = width * 8;
        // Flags from another block are unknown here.
        let Some(value) = lifter
            .condition_test(ins.condition_code())
            .select(Expr::constant(1), Expr::constant(0))
        else {
            lifter.stmts.push(Stmt::unsupported(format!(
                "setcc without compare at 0x{:x}",
                ins.ip()
            )));
            return false;
        };
        let value = Expr::bin(BinOp::And, value, Expr::constant((1u64 << bits) - 1));
        write_destination(lifter, ins, value);
        return false;
    }

    if lift_vector(lifter, ins).is_some()
        || lift_float(lifter, ins).is_some()
        || packed::lift_extend(lifter, ins).is_some()
        || lift_packed(lifter, ins).is_some()
    {
        return false;
    }

    match ins.mnemonic() {
        Mnemonic::Mov => {
            if let Some(value) = operand(lifter, ins, 1) {
                write_destination(lifter, ins, value);
            }
        }
        Mnemonic::Lea => {
            if let (OpKind::Register, Some(addr)) = (ins.op0_kind(), memory_address(ins))
                && let Some((index, width)) = gpr(ins.op0_register())
            {
                lifter.assign(index, width, addr);
            }
        }
        Mnemonic::Mul => lift_mul_high(lifter, ins, false),
        Mnemonic::Add => binary(lifter, ins, BinOp::Add),
        Mnemonic::Sub => binary(lifter, ins, BinOp::Sub),
        Mnemonic::And => binary(lifter, ins, BinOp::And),
        Mnemonic::Or => binary(lifter, ins, BinOp::Or),
        Mnemonic::Xor => {
            if ins.op0_kind() == OpKind::Register
                && ins.op1_kind() == OpKind::Register
                && ins.op0_register() == ins.op1_register()
                && let Some((RDX, 32 | 64)) = gpr(ins.op0_register())
            {
                // `xor edx, edx` clears all of rdx.
                lifter.zeroed_dividend = Some(64);
            }
            binary(lifter, ins, BinOp::Xor)
        }
        Mnemonic::Imul => match ins.op_count() {
            1 => lift_mul_high(lifter, ins, true),
            2 | 3 => {
                let first = ins.op_count() - 2;
                if let (Some(a), Some(b), Some(width)) = (
                    operand(lifter, ins, first),
                    operand(lifter, ins, first + 1),
                    operand_width(ins, 0),
                ) {
                    lifter.set_flags(Flags::carry_overflow(signed_product_lost(&a, &b, width)));
                    let value = Expr::bin(BinOp::Mul, a, b);
                    write_destination(lifter, ins, value);
                }
            }
            _ => lifter
                .stmts
                .push(Stmt::unsupported(format!("imul at 0x{:x}", ins.ip()))),
        },
        Mnemonic::Cmp => {
            if let (Some(a), Some(b)) = (operand(lifter, ins, 0), operand(lifter, ins, 1)) {
                lifter.set_flags(Flags::difference(a, b));
            }
        }
        Mnemonic::Test => {
            if let (Some(a), Some(b)) = (operand(lifter, ins, 0), operand(lifter, ins, 1)) {
                let masked = Expr::bin(BinOp::And, a, b);
                let width = operand_width(ins, 0).map_or(64, u32::from);
                lifter.set_flags(Flags::logic_at(masked, width));
            }
        }
        Mnemonic::Shl | Mnemonic::Sal => shift(lifter, ins, BinOp::Shl),
        Mnemonic::Shr => shift(lifter, ins, BinOp::Shr),
        Mnemonic::Sar => shift(lifter, ins, BinOp::Sar),
        Mnemonic::Movsx | Mnemonic::Movsxd => {
            if let Some(value) = operand(lifter, ins, 1) {
                let source_width = operand_width(ins, 1).unwrap_or(32) / 8;
                let value = Expr::SignExtend {
                    value: Box::new(value),
                    width: source_width,
                };
                write_destination(lifter, ins, value);
            }
        }
        Mnemonic::Cdqe => {
            let value = Expr::SignExtend {
                value: Box::new(Lifter::read_reg(RAX, 32)),
                width: 4,
            };
            lifter.assign(RAX, 64, value);
        }
        Mnemonic::Cwde => {
            let value = Expr::SignExtend {
                value: Box::new(Lifter::read_reg(RAX, 16)),
                width: 2,
            };
            lifter.assign(RAX, 32, value);
        }
        Mnemonic::Cbw => {
            let value = Expr::SignExtend {
                value: Box::new(Lifter::read_reg(RAX, 8)),
                width: 1,
            };
            lifter.assign(RAX, 16, value);
        }
        Mnemonic::Neg => {
            let Some(value) = operand(lifter, ins, 0) else {
                return false;
            };
            lifter.set_flags(Flags::difference(Expr::constant(0), value.clone()));
            let negated = Expr::bin(BinOp::Sub, Expr::constant(0), value);
            write_destination(lifter, ins, negated);
        }
        Mnemonic::Not => {
            let Some(value) = operand(lifter, ins, 0) else {
                return false;
            };
            let width = match ins.op0_kind() {
                OpKind::Memory => memory_width(ins).unwrap_or(8),
                OpKind::Register => gpr(ins.op0_register()).map(|(_, w)| w).unwrap_or(64) / 8,
                _ => 8,
            };
            let mask = if width >= 8 {
                u64::MAX
            } else {
                (1u64 << (width * 8)) - 1
            };
            let inverted = Expr::bin(BinOp::Xor, value, Expr::constant(mask));
            write_destination(lifter, ins, inverted);
        }
        Mnemonic::Inc | Mnemonic::Dec => {
            let Some(value) = operand(lifter, ins, 0) else {
                return false;
            };
            // Both leave the carry as it was.
            let (op, flags) = if ins.mnemonic() == Mnemonic::Inc {
                (BinOp::Add, Flags::sum(value.clone(), Expr::constant(1)))
            } else {
                (
                    BinOp::Sub,
                    Flags::difference(value.clone(), Expr::constant(1)),
                )
            };
            lifter.set_flags(flags.keeping_carry());
            let updated = Expr::bin(op, value, Expr::constant(1));
            write_destination(lifter, ins, updated);
        }
        // rdx (edx, dx) receives copies of the accumulator's sign bit.
        Mnemonic::Cwd | Mnemonic::Cdq | Mnemonic::Cqo => {
            let width = match ins.mnemonic() {
                Mnemonic::Cwd => 16,
                Mnemonic::Cdq => 32,
                _ => 64,
            };
            let sign = Expr::bin(
                BinOp::Sar,
                Lifter::read_reg(RAX, width),
                Expr::constant(u64::from(width) - 1),
            );
            lifter.assign(RDX, width, sign);
            lifter.extended_dividend = Some(width);
        }
        Mnemonic::Idiv => {
            let Some(divisor) = operand(lifter, ins, 0) else {
                return false;
            };
            let width = operand_width(ins, 0).unwrap_or(64);
            if was_extended != Some(width) || width == 8 {
                wide_divide(lifter, true, width, divisor);
                return false;
            }
            let dividend = Lifter::read_reg(RAX, width);
            // Both results read the dividend and the divisor, which may be
            // rdx, so the quotient waits while rdx takes the remainder.
            let quotient = hold(
                lifter,
                Expr::bin(BinOp::DivS, dividend.clone(), divisor.clone()),
            );
            lifter.assign(RDX, width, Expr::bin(BinOp::ModS, dividend, divisor));
            lifter.assign(RAX, width, quotient);
        }
        // An unsigned division whose high half rdx was just cleared divides
        // rax alone.
        Mnemonic::Div => {
            let Some(divisor) = operand(lifter, ins, 0) else {
                return false;
            };
            let width = operand_width(ins, 0).unwrap_or(64);
            if was_zeroed.is_none() || !matches!(width, 32 | 64) {
                wide_divide(lifter, false, width, divisor);
                return false;
            }
            let dividend = Lifter::read_reg(RAX, width);
            let quotient = hold(
                lifter,
                Expr::bin(BinOp::DivU, dividend.clone(), divisor.clone()),
            );
            lifter.assign(RDX, width, Expr::bin(BinOp::ModU, dividend, divisor));
            lifter.assign(RAX, width, quotient);
        }
        Mnemonic::Leave => {
            let bits = lifter.word_bits();
            let bytes = bits / 8;
            let base = Lifter::read_reg(5, bits);
            lifter.assign(RSP, bits, base.clone());
            let value = Expr::Load {
                addr: Box::new(base),
                width: bytes,
                signed: false,
            };
            lifter.assign(5, bits, value);
            stack_adjust(lifter, i64::from(bytes));
        }
        Mnemonic::Movzx => {
            if let Some(value) = operand(lifter, ins, 1) {
                let width = operand_width(ins, 1).unwrap_or(8);
                let mask = crate::ir::semantics::mask(u32::from(width));
                let value = Expr::bin(BinOp::And, value, Expr::constant(mask));
                write_destination(lifter, ins, value);
            }
        }
        Mnemonic::Call => {
            if lifter.image.isa == crate::loader::Isa::I386
                && ins.op0_kind() == OpKind::NearBranch32
            {
                let target = resolved_target(ins, relocation_target);
                let return_register = return_address_register(lifter.image, target);
                if target == ins.next_ip() || return_register.is_some() {
                    stack_adjust(lifter, -4);
                    preserve_compare(&mut lifter.last_compare, Write::Memory, &mut lifter.stmts);
                    lifter.stmts.push(Stmt::Store {
                        addr: Lifter::read_reg(RSP, 32),
                        value: Expr::constant(ins.next_ip()),
                        width: 4,
                        at: None,
                    });
                    if let Some(register) = return_register {
                        lifter.assign(register, 32, Expr::constant(ins.next_ip()));
                        stack_adjust(lifter, 4);
                    }
                    return false;
                }
            }
            // A call leaves the flags undefined: none of the compare before
            // it is read after it.
            lifter.last_compare = None;
            if matches!(
                ins.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            ) {
                let target = resolved_target(ins, relocation_target);
                let made = call(
                    CallKind::Invoke,
                    lifter.image,
                    lifter.summaries,
                    Some(target),
                );
                lifter.stmts.push(made);
                if complete_call(lifter, target) {
                    return true;
                }
            } else if let Some(through) = operand(lifter, ins, 0) {
                // A pointer the image fills itself is a call to its function.
                if let Some(target) = super::pointer_target(lifter.image, &through) {
                    lifter.stmts.push(call(
                        CallKind::Invoke,
                        lifter.image,
                        lifter.summaries,
                        Some(target),
                    ));
                    if complete_call(lifter, target) {
                        return true;
                    }
                } else {
                    let noreturn = super::import_called(lifter.image, &through)
                        .is_some_and(|summary| summary.noreturn);
                    let cleanup = super::import_name(lifter.image, &through)
                        .and_then(|name| {
                            crate::analysis::prototypes::i386_import(lifter.image, name)
                        })
                        .map_or(0, |properties| properties.1);
                    lifter
                        .stmts
                        .push(call_through(CallKind::Invoke, lifter.image, through));
                    if cleanup != 0 {
                        stack_adjust(lifter, i64::from(cleanup));
                    }
                    if noreturn {
                        lifter.stmts.push(Stmt::Trap { at: None });
                        return true;
                    }
                }
            } else {
                let made = call(CallKind::Invoke, lifter.image, lifter.summaries, None);
                lifter.stmts.push(made);
            }
            lifter.assign(DIRECTION, 64, Expr::constant(0));
        }
        Mnemonic::Jmp => {
            if relocation_target.is_some()
                || matches!(
                    ins.op0_kind(),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                )
            {
                // Whether a jump out of the function is a tail call is
                // decided once its blocks are known.
                lifter.stmts.push(Stmt::Br {
                    target: Some(resolved_target(ins, relocation_target)),
                    at: None,
                });
            } else if let Some(target) = operand(lifter, ins, 0) {
                match super::pointer_target(lifter.image, &target) {
                    Some(target) => lifter.stmts.extend(self::tail_call(
                        lifter.image,
                        lifter.summaries,
                        Some(target),
                    )),
                    // A jump through an import's slot calls it for the result.
                    None if let Some(summary) = super::import_called(lifter.image, &target) => {
                        lifter
                            .stmts
                            .push(call_through(CallKind::Tail, lifter.image, target));
                        lifter.stmts.push(if summary.noreturn {
                            Stmt::Trap { at: None }
                        } else {
                            Stmt::Ret {
                                value: Lifter::read_reg(RAX, lifter.word_bits()),
                                at: None,
                            }
                        });
                    }
                    None => lifter.stmts.push(Stmt::BrIndirect { target, at: None }),
                }
            }
            return true;
        }
        Mnemonic::Ret => {
            lifter.stmts.push(Stmt::Ret {
                value: Lifter::read_reg(RAX, lifter.word_bits()),
                at: None,
            });
            return true;
        }
        Mnemonic::Cpuid
        | Mnemonic::Xgetbv
        | Mnemonic::Rdtsc
        | Mnemonic::Rdtscp
        | Mnemonic::Pushf
        | Mnemonic::Pushfd
        | Mnemonic::Popf
        | Mnemonic::Popfd
        | Mnemonic::Pushfq
        | Mnemonic::Popfq => machine::lift(lifter, ins.mnemonic()),
        Mnemonic::Push => {
            let bytes = match ins.stack_pointer_increment() {
                -2 => 2,
                -4 => 4,
                -8 => 8,
                _ => return false,
            };
            let Some(value) = operand(lifter, ins, 0) else {
                return false;
            };
            // The value is read before the stack pointer moves.
            let value = stack_reads_before(value, u64::from(bytes));
            stack_adjust(lifter, -i64::from(bytes));
            let address = Lifter::read_reg(RSP, 64);
            preserve_compare(&mut lifter.last_compare, Write::Memory, &mut lifter.stmts);
            lifter.stmts.push(Stmt::Store {
                addr: address,
                value,
                width: bytes,
                at: None,
            });
        }
        Mnemonic::Pop => {
            let bytes = operand_width(ins, 0).unwrap_or(lifter.word_bits()) / 8;
            let address = Lifter::read_reg(RSP, 64);
            let value = Expr::Load {
                addr: Box::new(address),
                width: bytes,
                signed: false,
            };
            match gpr(ins.op0_register()) {
                // `pop rsp` leaves the loaded value in place of the increment.
                Some((RSP, width)) if ins.op0_kind() == OpKind::Register => {
                    let value = hold(lifter, value);
                    stack_adjust(lifter, i64::from(bytes));
                    lifter.assign(RSP, width, value);
                }
                Some((index, width)) if ins.op0_kind() == OpKind::Register => {
                    lifter.assign(index, width, value);
                    stack_adjust(lifter, i64::from(bytes));
                }
                _ => {
                    let value = hold(lifter, value);
                    stack_adjust(lifter, i64::from(bytes));
                    write_destination(lifter, ins, value);
                }
            }
        }
        Mnemonic::Xchg | Mnemonic::Xadd | Mnemonic::Cmpxchg => lift_exchange(lifter, ins),
        Mnemonic::Rol
        | Mnemonic::Ror
        | Mnemonic::Rcl
        | Mnemonic::Rcr
        | Mnemonic::Shld
        | Mnemonic::Shrd
        | Mnemonic::Bswap
        | Mnemonic::Bt
        | Mnemonic::Bts
        | Mnemonic::Btr
        | Mnemonic::Btc => lift_bits(lifter, ins),
        Mnemonic::Movsb
        | Mnemonic::Movsw
        | Mnemonic::Movsd
        | Mnemonic::Movsq
        | Mnemonic::Stosb
        | Mnemonic::Stosw
        | Mnemonic::Stosd
        | Mnemonic::Stosq
        | Mnemonic::Lodsb
        | Mnemonic::Lodsw
        | Mnemonic::Lodsd
        | Mnemonic::Lodsq
        | Mnemonic::Cmpsb
        | Mnemonic::Cmpsw
        | Mnemonic::Cmpsd
        | Mnemonic::Cmpsq
        | Mnemonic::Scasb
        | Mnemonic::Scasw
        | Mnemonic::Scasd
        | Mnemonic::Scasq
            if string_size(ins).is_some() =>
        {
            return lift_string(lifter, ins);
        }
        Mnemonic::Tzcnt | Mnemonic::Lzcnt | Mnemonic::Popcnt | Mnemonic::Bsf | Mnemonic::Bsr => {
            lift_count(lifter, ins)
        }
        // The Castagnoli checksum, updated with the source's bytes.
        Mnemonic::Crc32 => {
            if let (Some(crc), Some(data), Some(bits)) = (
                operand(lifter, ins, 0),
                operand(lifter, ins, 1),
                operand_width(ins, 1),
            ) {
                let crc = Expr::bin(BinOp::And, crc, Expr::constant(0xffff_ffff));
                let value = Expr::apply(
                    Operation::Crc32 {
                        castagnoli: true,
                        bits,
                    },
                    vec![crc, data],
                );
                write_destination(lifter, ins, value);
            }
        }
        // Hints and fences change nothing a single thread sees.
        Mnemonic::Nop
        | Mnemonic::Endbr64
        | Mnemonic::Reservednop
        | Mnemonic::Pause
        | Mnemonic::Wait
        | Mnemonic::Prefetchnta
        | Mnemonic::Prefetcht0
        | Mnemonic::Prefetcht1
        | Mnemonic::Prefetcht2
        | Mnemonic::Prefetchw
        | Mnemonic::Sfence
        | Mnemonic::Lfence
        | Mnemonic::Mfence => {}
        Mnemonic::Std | Mnemonic::Cld => {
            lifter.assign(
                DIRECTION,
                64,
                Expr::constant(u64::from(ins.mnemonic() == Mnemonic::Std)),
            );
        }
        Mnemonic::Adc => with_carry(lifter, ins, false),
        Mnemonic::Sbb => with_carry(lifter, ins, true),
        Mnemonic::Lahf => lift_lahf(lifter, ins),
        // Overflow, which `ah` does not hold, stays as it was.
        Mnemonic::Sahf => {
            let overflow = lifter
                .test(Cond::Vs)
                .select(Expr::constant(1), Expr::constant(0));
            let ah = Expr::bin(
                BinOp::And,
                Expr::bin(BinOp::Shr, Expr::reg(RAX, 64), Expr::constant(8)),
                Expr::constant(0xff),
            );
            lifter.set_flags(Flags::stored(ah, overflow));
        }
        Mnemonic::Clc => lifter.set_flags(Flags::carry(Expr::constant(0))),
        Mnemonic::Stc => lifter.set_flags(Flags::carry(Expr::constant(1))),
        Mnemonic::Cmc => {
            if let Some(carry) = lifter.carry() {
                let flipped = Expr::bin(BinOp::Xor, carry, Expr::constant(1));
                lifter.set_flags(Flags::carry(flipped));
            }
        }
        // The kernel's call: its number and arguments in registers.
        Mnemonic::Syscall | Mnemonic::Int
            if ins.mnemonic() == Mnemonic::Syscall
                || (ins.immediate8() == 0x80 && lifter.image.isa == crate::loader::Isa::I386) =>
        {
            lifter.stmts.push(Stmt::Call {
                kind: CallKind::Syscall,
                target: None,
                through: None,
                convention: if ins.mnemonic() == Mnemonic::Int {
                    crate::ir::Convention::SyscallI386
                } else {
                    crate::ir::Convention::SyscallX86
                },
                args: if ins.mnemonic() == Mnemonic::Int {
                    Some(
                        crate::ir::Convention::SyscallI386
                            .arguments()
                            .iter()
                            .map(|register| Lifter::read_reg(*register, 32))
                            .collect(),
                    )
                } else {
                    None
                },
                // The kernel reads no floating-point register.
                floats_named: true,
                abi: None,
                clobbers: None,
                outputs: crate::ir::fallback_call_outputs(
                    if ins.mnemonic() == Mnemonic::Int {
                        crate::ir::Convention::SyscallI386
                    } else {
                        crate::ir::Convention::SyscallX86
                    },
                    None,
                ),
                via: None,
                at: None,
            })
        }
        Mnemonic::Int if ins.immediate8() == 3 => {
            lifter.stmts.push(Stmt::Trap { at: None });
            return true;
        }
        Mnemonic::Int3 | Mnemonic::Ud2 | Mnemonic::Hlt => {
            lifter.stmts.push(Stmt::Trap { at: None });
            return true;
        }
        other => {
            if ins.flow_control() == FlowControl::ConditionalBranch {
                // Only a condition the flags here leave open names itself in the branch.
                let cond = condition(ins.condition_code()).unwrap_or(Cond::Eq);
                let target = resolved_target(ins, relocation_target);
                let test = lifter.condition_test(ins.condition_code());
                lifter.stmts.extend(test.branch(cond, target));
                return true;
            }
            // Instructions that report on the processor write only the
            // registers they fill.
            let writes = match other {
                Mnemonic::Cpuid => Some(vec![0, 1, 2, 3]),
                Mnemonic::Rdtsc | Mnemonic::Xgetbv | Mnemonic::Rdpmc => Some(vec![0, 2]),
                Mnemonic::Rdtscp => Some(vec![0, 1, 2]),
                // The direction flag is no register the analysis follows.
                Mnemonic::Std | Mnemonic::Cld => Some(Vec::new()),
                _ => None,
            };
            lifter.stmts.push(Stmt::Unsupported {
                at: None,
                text: format!("{other:?} at 0x{:x}", ins.ip()),
                writes,
            });
        }
    }
    false
}

fn branch_target(instruction: &Instruction, relocation_target: Option<u64>) -> Option<u64> {
    match instruction.flow_control() {
        FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
            Some(resolved_target(instruction, relocation_target))
        }
        FlowControl::IndirectBranch => relocation_target,
        _ => None,
    }
}

pub(super) fn decode(bytes: &[u8], addr: u64) -> (Vec<Decoded<Instruction>>, Option<String>) {
    decode_mode(bytes, addr, 64)
}

pub(super) fn decode32(bytes: &[u8], addr: u64) -> (Vec<Decoded<Instruction>>, Option<String>) {
    decode_mode(bytes, addr, 32)
}

pub(super) fn decode_mode(
    bytes: &[u8],
    addr: u64,
    bitness: u32,
) -> (Vec<Decoded<Instruction>>, Option<String>) {
    let mut decoder = Decoder::with_ip(bitness, bytes, addr, DecoderOptions::NONE);
    let mut decoded = Vec::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        decoded.push(Decoded {
            pc: instruction.ip(),
            next: instruction.next_ip(),
            instruction,
        });
    }
    (decoded, None)
}

impl Machine for Lifter<'_> {
    type Instruction = Instruction;

    fn branch_target(&self, instruction: &Instruction, pc: u64) -> Option<u64> {
        branch_target(instruction, self.image.relocations.get(&pc).copied())
    }

    fn step(&mut self, instruction: &Instruction, pc: u64) -> bool {
        let relocation_target = self.image.relocations.get(&pc).copied();
        self.flags_written = false;
        self.incomplete = false;
        let first = self.stmts.len();
        let ended = lift_instruction(self, instruction, relocation_target);
        if self.incomplete {
            self.stmts.push(Stmt::unsupported(format!(
                "{:?} operands at 0x{:x}",
                instruction.mnemonic(),
                instruction.ip()
            )));
        }
        if self.stmts[first..]
            .iter()
            .any(|stmt| matches!(stmt, Stmt::Unsupported { writes: None, .. }))
        {
            let changed = written_registers(&mut self.info, instruction);
            for stmt in &mut self.stmts[first..] {
                if let Stmt::Unsupported { writes, .. } = stmt
                    && writes.is_none()
                {
                    *writes = Some(changed.clone());
                }
            }
        }
        // Flags the instruction sets in a way not modelled are unknown.
        let modified = instruction.rflags_modified() & CONDITION_FLAGS != 0;
        if modified && !self.flags_written {
            self.last_compare = None;
        }
        self.flags_touched |= modified
            || self.flags_written
            || self.stmts[first..]
                .iter()
                .any(|stmt| matches!(stmt, Stmt::Unsupported { .. }));
        for stmt in &mut self.stmts[first..] {
            if !matches!(stmt, Stmt::Assign { dest, .. } if crate::ir::is_temp(dest.index)) {
                stmt.set_origin(Some(pc));
            }
        }
        ended
    }

    fn take_statements(&mut self) -> Vec<Stmt> {
        std::mem::take(&mut self.stmts)
    }

    fn block_ended(&mut self) {
        self.last_compare = None;
    }

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

    fn take_extra_blocks(&mut self) -> Vec<(Block, Option<Flags>)> {
        std::mem::take(&mut self.extra)
    }
}

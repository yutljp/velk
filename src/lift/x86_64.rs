use crate::arch::x86::{RAX, RDX, RSP};
use iced_x86::{
    ConditionCode, Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register,
};

use super::{
    Decoded, MAX_INSTRUCTIONS, Machine, Write, call, call_through, preserve_compare, tail_call,
};
use crate::ir::{BinOp, Cond, Expr, RegRef, Stmt};
use crate::loader::Image;

pub(super) struct Lifter<'a> {
    stmts: Vec<Stmt>,
    last_compare: Option<(Expr, Expr)>,
    extended_dividend: Option<u8>,
    /// The width of the high half of an unsigned dividend the previous
    /// instruction cleared (`xor edx, edx`).
    zeroed_dividend: Option<u8>,
    image: &'a Image,
    function: u64,
}

impl<'a> Lifter<'a> {
    pub(super) fn new(image: &'a Image, function: u64) -> Self {
        Self {
            stmts: Vec::new(),
            last_compare: None,
            extended_dividend: None,
            zeroed_dividend: None,
            image,
            function,
        }
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
        });
    }
}

fn gpr(reg: Register) -> Option<(u16, u8)> {
    use Register::*;
    let pair = match reg {
        RAX => (0, 64),
        EAX => (0, 32),
        AX => (0, 16),
        AL => (0, 8),
        RCX => (1, 64),
        ECX => (1, 32),
        CX => (1, 16),
        CL => (1, 8),
        RDX => (2, 64),
        EDX => (2, 32),
        DX => (2, 16),
        DL => (2, 8),
        RBX => (3, 64),
        EBX => (3, 32),
        BX => (3, 16),
        BL => (3, 8),
        RSP => (4, 64),
        ESP => (4, 32),
        SP => (4, 16),
        SPL => (4, 8),
        RBP => (5, 64),
        EBP => (5, 32),
        BP => (5, 16),
        BPL => (5, 8),
        RSI => (6, 64),
        ESI => (6, 32),
        SI => (6, 16),
        SIL => (6, 8),
        RDI => (7, 64),
        EDI => (7, 32),
        DI => (7, 16),
        DIL => (7, 8),
        R8 => (8, 64),
        R8D => (8, 32),
        R8W => (8, 16),
        R8L => (8, 8),
        R9 => (9, 64),
        R9D => (9, 32),
        R9W => (9, 16),
        R9L => (9, 8),
        R10 => (10, 64),
        R10D => (10, 32),
        R10W => (10, 16),
        R10L => (10, 8),
        R11 => (11, 64),
        R11D => (11, 32),
        R11W => (11, 16),
        R11L => (11, 8),
        R12 => (12, 64),
        R12D => (12, 32),
        R12W => (12, 16),
        R12L => (12, 8),
        R13 => (13, 64),
        R13D => (13, 32),
        R13W => (13, 16),
        R13L => (13, 8),
        R14 => (14, 64),
        R14D => (14, 32),
        R14W => (14, 16),
        R14L => (14, 8),
        R15 => (15, 64),
        R15D => (15, 32),
        R15W => (15, 16),
        R15L => (15, 8),
        _ => return Option::None,
    };
    Option::Some(pair)
}

fn memory_width(ins: &Instruction) -> Option<u8> {
    Some(match ins.memory_size().size() {
        1 => 1,
        2 => 2,
        4 => 4,
        8 => 8,
        _ => return None,
    })
}

fn memory_address(ins: &Instruction) -> Option<Expr> {
    if ins.memory_base() == Register::RIP {
        return Some(Expr::constant(ins.ip_rel_memory_address()));
    }
    let mut address: Option<Expr> = None;
    if let Some((index, _)) = gpr(ins.memory_base()) {
        address = Some(Expr::reg(index, 64));
    }
    if let Some((index, _)) = gpr(ins.memory_index()) {
        let mut value = Expr::reg(index, 64);
        let scale = ins.memory_index_scale();
        if scale > 1 {
            value = Expr::bin(BinOp::Mul, value, Expr::constant(scale as u64));
        }
        address = Some(match address {
            Some(base) => Expr::bin(BinOp::Add, base, value),
            None => value,
        });
    }
    let displacement = ins.memory_displacement64();
    if displacement != 0 {
        address = Some(match address {
            Some(base) => Expr::bin(BinOp::Add, base, Expr::constant(displacement)),
            None => Expr::constant(displacement),
        });
    }
    address
}

fn load(ins: &Instruction) -> Option<Expr> {
    Some(Expr::Load {
        addr: Box::new(memory_address(ins)?),
        width: memory_width(ins)?,
        signed: false,
    })
}

fn immediate(ins: &Instruction, index: u32) -> Option<Expr> {
    let value = match ins.op_kind(index) {
        OpKind::Immediate8 => ins.immediate8() as u64,
        OpKind::Immediate8to32 => ins.immediate8to32() as i64 as u64,
        OpKind::Immediate8to64 => ins.immediate8to64() as u64,
        OpKind::Immediate16 => ins.immediate16() as u64,
        OpKind::Immediate32 => ins.immediate32() as u64,
        OpKind::Immediate32to64 => ins.immediate32to64() as u64,
        OpKind::Immediate64 => ins.immediate64(),
        OpKind::NearBranch64 => ins.near_branch_target(),
        _ => return None,
    };
    Some(Expr::constant(value))
}

fn operand(_lifter: &mut Lifter, ins: &Instruction, index: u32) -> Option<Expr> {
    match ins.op_kind(index) {
        OpKind::Register => {
            let (register, width) = gpr(ins.op_register(index))?;
            Some(Lifter::read_reg(register, width))
        }
        OpKind::Memory => load(ins),
        _ => immediate(ins, index),
    }
}

fn write_destination(lifter: &mut Lifter, ins: &Instruction, value: Expr) {
    match ins.op0_kind() {
        OpKind::Register => {
            if let Some((index, width)) = gpr(ins.op0_register()) {
                lifter.assign(index, width, value);
            }
        }
        OpKind::Memory => {
            if let (Some(addr), Some(width)) = (memory_address(ins), memory_width(ins)) {
                preserve_compare(&mut lifter.last_compare, Write::Memory, &mut lifter.stmts);
                lifter.stmts.push(Stmt::Store { addr, value, width });
            }
        }
        _ => {}
    }
}

/// `mul rm` computes rdx:rax = rax * rm; rdx is written first so the high
/// product still reads the original rax.
fn lift_mul_high(lifter: &mut Lifter, ins: &Instruction, signed: bool) {
    let Some((_, width)) = gpr(ins.op0_register()) else {
        return;
    };
    if width != 64 {
        return;
    }
    let Some(op_value) = operand(lifter, ins, 0) else {
        return;
    };
    let multiplicand = Lifter::read_reg(RAX, 64);
    let high_op = if signed {
        BinOp::MulHighS
    } else {
        BinOp::MulHigh
    };
    lifter.assign(
        RDX,
        64,
        Expr::bin(high_op, multiplicand.clone(), op_value.clone()),
    );
    lifter.assign(RAX, 64, Expr::bin(BinOp::Mul, multiplicand, op_value));
}

fn binary(lifter: &mut Lifter, ins: &Instruction, op: BinOp) {
    let (Some(lhs), Some(rhs)) = (operand(lifter, ins, 0), operand(lifter, ins, 1)) else {
        return;
    };
    // `xor r, r` and `sub r, r` clear the register without depending on its value.
    let value = if matches!(op, BinOp::Xor | BinOp::Sub) && lhs == rhs {
        Expr::constant(0)
    } else {
        Expr::bin(op, lhs.clone(), rhs.clone())
    };
    // `sub` sets the flags `cmp` would: carry and overflow compare its
    // operands, which a test of the result against zero cannot show.
    lifter.last_compare = Some(match op {
        BinOp::Sub => (lhs, rhs),
        _ => (value.clone(), Expr::constant(0)),
    });
    write_destination(lifter, ins, value);
}

fn select(lifter: &mut Lifter, ins: &Instruction, then: Expr, els: Expr) -> Option<Expr> {
    let cond = condition(ins.condition_code())?;
    let (lhs, rhs) = lifter.last_compare.take()?;
    Some(Expr::Select {
        cond,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
        then: Box::new(then),
        els: Box::new(els),
    })
}

fn shift(lifter: &mut Lifter, ins: &Instruction, op: BinOp) {
    let (Some(value), Some(amount)) = (operand(lifter, ins, 0), operand(lifter, ins, 1)) else {
        return;
    };
    let value = Expr::bin(op, value, amount);
    lifter.last_compare = Some((value.clone(), Expr::constant(0)));
    write_destination(lifter, ins, value);
}

fn condition(code: ConditionCode) -> Option<Cond> {
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
        s => Cond::Lt,
        ns => Cond::Ge,
        _ => return Option::None,
    })
}

/// The value with each read of the stack pointer offset by `delta`, for a
/// value read before the stack pointer moves down by `delta`.
fn stack_reads_before(value: Expr, delta: u64) -> Expr {
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

fn stack_adjust(lifter: &mut Lifter, delta: i64) {
    let current = Lifter::read_reg(RSP, 64);
    let value = Expr::bin(BinOp::Add, current, Expr::constant(delta as u64));
    lifter.assign(RSP, 64, value);
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

fn resolved_target(ins: &Instruction, relocation_target: Option<u64>) -> u64 {
    relocation_target.unwrap_or_else(|| ins.near_branch_target())
}

fn lift_instruction(
    lifter: &mut Lifter,
    ins: &Instruction,
    relocation_target: Option<u64>,
    tail_call: bool,
) -> bool {
    let was_extended = lifter.extended_dividend.take();
    let was_zeroed = lifter.zeroed_dividend.take();
    if is_cmov(ins.mnemonic()) {
        let Some(source) = operand(lifter, ins, 1) else {
            return false;
        };
        let Some(current) = operand(lifter, ins, 0) else {
            return false;
        };
        match select(lifter, ins, source, current) {
            Some(value) => write_destination(lifter, ins, value),
            None => lifter.stmts.push(Stmt::Unsupported {
                text: format!("cmov without compare at 0x{:x}", ins.ip()),
            }),
        }
        return false;
    }
    if is_setcc(ins.mnemonic()) {
        let width = match ins.op0_kind() {
            OpKind::Memory => memory_width(ins).unwrap_or(1),
            _ => 1,
        };
        let bits = width * 8;
        let (Some(cond), Some((lhs, rhs))) =
            (condition(ins.condition_code()), lifter.last_compare.clone())
        else {
            return false;
        };
        let value = Expr::Select {
            cond,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
            then: Box::new(Expr::constant(1)),
            els: Box::new(Expr::constant(0)),
        };
        let value = Expr::bin(BinOp::And, value, Expr::constant((1u64 << bits) - 1));
        write_destination(lifter, ins, value);
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
                && let Some((2, _)) = gpr(ins.op0_register())
            {
                // `xor edx, edx` clears all of rdx.
                lifter.zeroed_dividend = Some(64);
            }
            binary(lifter, ins, BinOp::Xor)
        }
        Mnemonic::Imul => match ins.op_count() {
            1 => lift_mul_high(lifter, ins, true),
            2 => {
                if let (Some(a), Some(b)) = (operand(lifter, ins, 0), operand(lifter, ins, 1)) {
                    let value = Expr::bin(BinOp::Mul, a, b);
                    write_destination(lifter, ins, value);
                }
            }
            3 => {
                if let (Some(a), Some(b)) = (operand(lifter, ins, 1), operand(lifter, ins, 2)) {
                    let value = Expr::bin(BinOp::Mul, a, b);
                    write_destination(lifter, ins, value);
                }
            }
            _ => lifter.stmts.push(Stmt::Unsupported {
                text: format!("imul at 0x{:x}", ins.ip()),
            }),
        },
        Mnemonic::Cmp => {
            if let (Some(a), Some(b)) = (operand(lifter, ins, 0), operand(lifter, ins, 1)) {
                lifter.last_compare = Some((a, b));
            }
        }
        Mnemonic::Test => {
            if let (Some(a), Some(b)) = (operand(lifter, ins, 0), operand(lifter, ins, 1)) {
                let masked = Expr::bin(BinOp::And, a, b);
                lifter.last_compare = Some((masked, Expr::constant(0)));
            }
        }
        Mnemonic::Shl | Mnemonic::Sal => shift(lifter, ins, BinOp::Shl),
        Mnemonic::Shr => shift(lifter, ins, BinOp::Shr),
        Mnemonic::Sar => shift(lifter, ins, BinOp::Sar),
        Mnemonic::Movsx | Mnemonic::Movsxd => {
            if let Some(value) = operand(lifter, ins, 1) {
                let source_width = match ins.op1_kind() {
                    OpKind::Memory => memory_width(ins).unwrap_or(4),
                    OpKind::Register => gpr(ins.op1_register()).map(|(_, w)| w).unwrap_or(32) / 8,
                    _ => 4,
                };
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
            let negated = Expr::bin(BinOp::Sub, Expr::constant(0), value);
            lifter.last_compare = Some((negated.clone(), Expr::constant(0)));
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
            lifter.last_compare = Some((inverted.clone(), Expr::constant(0)));
            write_destination(lifter, ins, inverted);
        }
        Mnemonic::Inc | Mnemonic::Dec => {
            let Some(value) = operand(lifter, ins, 0) else {
                return false;
            };
            let delta = if ins.mnemonic() == Mnemonic::Inc {
                1
            } else {
                u64::MAX
            };
            let updated = Expr::bin(BinOp::Add, value, Expr::constant(delta));
            lifter.last_compare = Some((updated.clone(), Expr::constant(0)));
            write_destination(lifter, ins, updated);
        }
        Mnemonic::Cdq | Mnemonic::Cqo => {
            let width = if ins.mnemonic() == Mnemonic::Cdq {
                32
            } else {
                64
            };
            lifter.extended_dividend = Some(width);
        }
        Mnemonic::Idiv => {
            let Some(divisor) = operand(lifter, ins, 0) else {
                return false;
            };
            let width = match ins.op0_kind() {
                OpKind::Memory => memory_width(ins).unwrap_or(8) * 8,
                OpKind::Register => gpr(ins.op0_register()).map(|(_, w)| w).unwrap_or(64),
                _ => 64,
            };
            if was_extended != Some(width.min(64)) && was_extended.is_none() {
                lifter.stmts.push(Stmt::Unsupported {
                    text: format!("idiv without cdq/cqo at 0x{:x}", ins.ip()),
                });
                return false;
            }
            let dividend = Lifter::read_reg(RAX, width);
            let quotient = Expr::bin(BinOp::DivS, dividend.clone(), divisor.clone());
            let remainder = Expr::bin(BinOp::ModS, dividend, divisor);
            // Both results read the original rax, so rdx (the remainder) is
            // written before rax (the quotient).
            lifter.assign(2, width, remainder);
            lifter.assign(RAX, width, quotient);
        }
        // An unsigned division whose high half rdx was just cleared divides
        // rax alone; otherwise the 128-bit dividend is not modeled.
        Mnemonic::Div => {
            let Some(divisor) = operand(lifter, ins, 0) else {
                return false;
            };
            let width = match ins.op0_kind() {
                OpKind::Memory => memory_width(ins).unwrap_or(8) * 8,
                OpKind::Register => gpr(ins.op0_register()).map(|(_, w)| w).unwrap_or(64),
                _ => 64,
            };
            if was_zeroed.is_none() || !matches!(width, 32 | 64) {
                lifter.stmts.push(Stmt::Unsupported {
                    text: format!("div at 0x{:x}", ins.ip()),
                });
                return false;
            }
            let dividend = Lifter::read_reg(RAX, width);
            let quotient = Expr::bin(BinOp::DivU, dividend.clone(), divisor.clone());
            let remainder = Expr::bin(BinOp::ModU, dividend, divisor);
            lifter.assign(2, width, remainder);
            lifter.assign(RAX, width, quotient);
        }
        Mnemonic::Leave => {
            let base = Lifter::read_reg(5, 64);
            lifter.assign(RSP, 64, base.clone());
            let value = Expr::Load {
                addr: Box::new(base),
                width: 8,
                signed: false,
            };
            lifter.assign(5, 64, value);
            stack_adjust(lifter, 8);
        }
        Mnemonic::Movzx => {
            if let Some(value) = operand(lifter, ins, 1) {
                let width = match ins.op1_kind() {
                    OpKind::Memory => memory_width(ins).unwrap_or(1),
                    OpKind::Register => gpr(ins.op1_register()).map(|(_, w)| w).unwrap_or(4) / 8,
                    _ => 1,
                };
                let mask = if width >= 8 {
                    u64::MAX
                } else {
                    (1u64 << (width * 8)) - 1
                };
                let value = Expr::bin(BinOp::And, value, Expr::constant(mask));
                write_destination(lifter, ins, value);
            }
        }
        Mnemonic::Call => {
            if matches!(
                ins.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            ) {
                lifter.stmts.push(call(
                    lifter.image,
                    Some(resolved_target(ins, relocation_target)),
                ));
            } else if let Some(through) = operand(lifter, ins, 0) {
                lifter.stmts.push(call_through(lifter.image, through));
            } else {
                lifter.stmts.push(call(lifter.image, None));
            }
        }
        Mnemonic::Jmp => {
            if ins.op0_kind() == OpKind::NearBranch64 {
                let target = resolved_target(ins, relocation_target);
                if tail_call {
                    lifter
                        .stmts
                        .extend(self::tail_call(lifter.image, Some(target)));
                } else {
                    lifter.stmts.push(Stmt::Br {
                        target: Some(target),
                    });
                }
            } else if let Some(target) = operand(lifter, ins, 0) {
                lifter.stmts.push(Stmt::BrIndirect { target });
            }
            return true;
        }
        Mnemonic::Ret => {
            lifter.stmts.push(Stmt::Ret {
                value: Lifter::read_reg(RAX, 64),
            });
            return true;
        }
        Mnemonic::Push => {
            let Some(value) = operand(lifter, ins, 0) else {
                return false;
            };
            // The value is read before the stack pointer moves.
            let value = stack_reads_before(value, 8);
            stack_adjust(lifter, -8);
            let address = Lifter::read_reg(RSP, 64);
            preserve_compare(&mut lifter.last_compare, Write::Memory, &mut lifter.stmts);
            lifter.stmts.push(Stmt::Store {
                addr: address,
                value,
                width: 8,
            });
        }
        Mnemonic::Pop => {
            let address = Lifter::read_reg(RSP, 64);
            let value = Expr::Load {
                addr: Box::new(address),
                width: 8,
                signed: false,
            };
            match gpr(ins.op0_register()) {
                // `pop rsp` leaves the loaded value in place of the increment.
                Some((RSP, width)) if ins.op0_kind() == OpKind::Register => {
                    lifter.assign(RSP, width, value)
                }
                Some((index, width)) if ins.op0_kind() == OpKind::Register => {
                    lifter.assign(index, width, value);
                    stack_adjust(lifter, 8);
                }
                _ => stack_adjust(lifter, 8),
            }
        }
        Mnemonic::Nop | Mnemonic::Endbr64 => {}
        Mnemonic::Int3 | Mnemonic::Ud2 | Mnemonic::Hlt => {
            lifter.stmts.push(Stmt::Trap);
            return true;
        }
        other => {
            if ins.flow_control() == FlowControl::ConditionalBranch {
                let Some(cond) = condition(ins.condition_code()) else {
                    lifter.stmts.push(Stmt::BrifFlags {
                        cond: Cond::Eq,
                        target: resolved_target(ins, relocation_target),
                    });
                    return true;
                };
                let target = resolved_target(ins, relocation_target);
                match lifter.last_compare.take() {
                    Some((lhs, rhs)) => lifter.stmts.push(Stmt::Brif {
                        cond,
                        lhs,
                        rhs,
                        target,
                    }),
                    None => lifter.stmts.push(Stmt::BrifFlags { cond, target }),
                }
                return true;
            }
            lifter.stmts.push(Stmt::Unsupported {
                text: format!("{other:?} at 0x{:x}", ins.ip()),
            });
        }
    }
    false
}

fn branch_target(ins: &Instruction, relocation_target: Option<u64>) -> Option<u64> {
    match ins.flow_control() {
        FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
            Some(resolved_target(ins, relocation_target))
        }
        _ => None,
    }
}

pub(super) fn decode(bytes: &[u8], addr: u64) -> (Vec<Decoded<Instruction>>, Option<String>) {
    let mut decoder = Decoder::with_ip(64, bytes, addr, DecoderOptions::NONE);
    let mut decoded = Vec::new();
    while decoder.can_decode() {
        if decoded.len() == MAX_INSTRUCTIONS {
            return (
                decoded,
                Some(format!("stopped after {MAX_INSTRUCTIONS} instructions")),
            );
        }
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
        let tail_call = instruction.mnemonic() == Mnemonic::Jmp
            && instruction.op0_kind() == OpKind::NearBranch64
            && {
                let target = resolved_target(instruction, relocation_target);
                target != self.function && self.image.functions.contains_key(&target)
            };
        lift_instruction(self, instruction, relocation_target, tail_call)
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
}

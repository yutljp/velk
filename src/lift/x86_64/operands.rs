use super::{BinOp, Expr, Instruction, Lifter, OpKind, Register, Stmt, Write, preserve_compare};

pub(super) fn gpr(reg: Register) -> Option<(u16, u8)> {
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

/// The register whose second byte `reg` names (`ah`, `ch`, `dh`, `bh`).
fn high_byte(reg: Register) -> Option<u16> {
    match reg {
        Register::AH => Some(0),
        Register::CH => Some(1),
        Register::DH => Some(2),
        Register::BH => Some(3),
        _ => None,
    }
}

pub(super) fn memory_width(ins: &Instruction) -> Option<u8> {
    Some(match ins.memory_size().size() {
        1 => 1,
        2 => 2,
        4 => 4,
        8 => 8,
        _ => return None,
    })
}

pub(super) fn memory_address(ins: &Instruction) -> Option<Expr> {
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
    let segment = match ins.memory_segment() {
        Register::FS => Some(crate::arch::x86::FS_BASE),
        Register::GS => Some(crate::arch::x86::GS_BASE),
        _ => None,
    };
    match (segment, address) {
        (Some(segment), Some(address)) => {
            Some(Expr::bin(BinOp::Add, Expr::reg(segment, 64), address))
        }
        (Some(segment), None) => Some(Expr::reg(segment, 64)),
        // No base, index or displacement addresses zero.
        (None, None) => Some(Expr::constant(0)),
        (None, address) => address,
    }
}

/// The slot holding the low half of an xmm register.
pub(super) fn xmm(reg: Register) -> Option<u16> {
    (reg.is_xmm() && reg.number() < 16).then(|| crate::arch::x86::XMM0 + 2 * reg.number() as u16)
}

pub(super) fn load_at(addr: Expr, width: u8) -> Expr {
    Expr::Load {
        addr: Box::new(addr),
        width,
        signed: false,
    }
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
        OpKind::Immediate8_2nd => ins.immediate8_2nd() as u64,
        OpKind::Immediate8to16 => ins.immediate8to16() as u16 as u64,
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

pub(super) fn operand(lifter: &mut Lifter, ins: &Instruction, index: u32) -> Option<Expr> {
    let value = match ins.op_kind(index) {
        OpKind::Register => {
            let register = ins.op_register(index);
            if register == Register::None {
                return None;
            }
            match (gpr(register), high_byte(register)) {
                (Some((register, width)), _) => Some(Lifter::read_reg(register, width)),
                (None, Some(register)) => Some(Expr::bin(
                    BinOp::And,
                    Expr::bin(BinOp::Shr, Expr::reg(register, 64), Expr::constant(8)),
                    Expr::constant(0xff),
                )),
                _ => None,
            }
        }
        OpKind::Memory => load(ins),
        _ if index >= ins.op_count() => return None,
        _ => immediate(ins, index),
    };
    if value.is_none() {
        lifter.incomplete = true;
    }
    value
}

pub(super) fn write_destination(lifter: &mut Lifter, ins: &Instruction, value: Expr) {
    write_operand(lifter, ins, 0, value);
}

pub(super) fn write_operand(lifter: &mut Lifter, ins: &Instruction, index: u32, value: Expr) {
    match ins.op_kind(index) {
        OpKind::Register => {
            let register = ins.op_register(index);
            match (gpr(register), high_byte(register)) {
                (Some((index, width)), _) => lifter.assign(index, width, value),
                // The second byte replaces bits 8..16 and keeps the rest.
                (None, Some(index)) => {
                    let kept = Expr::bin(BinOp::And, Expr::reg(index, 64), Expr::constant(!0xff00));
                    let placed = Expr::bin(
                        BinOp::Shl,
                        Expr::bin(BinOp::And, value, Expr::constant(0xff)),
                        Expr::constant(8),
                    );
                    lifter.assign(index, 64, Expr::bin(BinOp::Or, kept, placed));
                }
                _ => lifter.incomplete = true,
            }
        }
        OpKind::Memory => {
            if let (Some(addr), Some(width)) = (memory_address(ins), memory_width(ins)) {
                preserve_compare(&mut lifter.last_compare, Write::Memory, &mut lifter.stmts);
                lifter.stmts.push(Stmt::Store { addr, value, width });
            } else {
                lifter.incomplete = true;
            }
        }
        _ => lifter.incomplete = true,
    }
}

/// The width in bits of a general register or memory operand.
pub(super) fn operand_width(ins: &Instruction, index: u32) -> Option<u8> {
    match ins.op_kind(index) {
        OpKind::Register if high_byte(ins.op_register(index)).is_some() => Some(8),
        OpKind::Register => gpr(ins.op_register(index)).map(|(_, width)| width),
        OpKind::Memory => memory_width(ins).map(|bytes| bytes * 8),
        _ => None,
    }
}

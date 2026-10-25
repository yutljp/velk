use super::{
    BinOp, Cond, Expr, Flags, Instruction, Lifter, Mnemonic, OpKind, RAX, RDX, RegRef, Stmt, Write,
    memory_address, memory_width, operand, preserve_compare, write_operand,
};
use crate::ir::{AtomicOp, MachineInstruction, Ordering};

const OUTPUT: u16 = crate::ir::TEMP_BASE + 0x60;

pub(super) fn lift(lifter: &mut Lifter, ins: &Instruction) -> bool {
    if !ins.has_lock_prefix()
        && !(ins.mnemonic() == Mnemonic::Xchg
            && (ins.op0_kind() == OpKind::Memory || ins.op1_kind() == OpKind::Memory))
    {
        return false;
    }
    let width = if ins.mnemonic() == Mnemonic::Cmpxchg16b {
        Some(16)
    } else {
        memory_width(ins)
    };
    let (Some(mut addr), Some(width)) = (memory_address(ins), width) else {
        lifter.stmts.push(Stmt::unsupported(format!(
            "atomic operand at 0x{:x}",
            ins.ip()
        )));
        return true;
    };
    let op = match ins.mnemonic() {
        Mnemonic::Add | Mnemonic::Inc | Mnemonic::Xadd => AtomicOp::Add,
        Mnemonic::Sub | Mnemonic::Dec => AtomicOp::Sub,
        Mnemonic::And | Mnemonic::Btr => AtomicOp::And,
        Mnemonic::Or | Mnemonic::Bts => AtomicOp::Or,
        Mnemonic::Xor | Mnemonic::Btc => AtomicOp::Xor,
        Mnemonic::Xchg => AtomicOp::Exchange,
        Mnemonic::Cmpxchg | Mnemonic::Cmpxchg8b | Mnemonic::Cmpxchg16b => AtomicOp::CompareExchange,
        _ => {
            lifter.stmts.push(Stmt::unsupported(format!(
                "atomic {:?} at 0x{:x}",
                ins.mnemonic(),
                ins.ip()
            )));
            return true;
        }
    };
    let bits = width * 8;
    if matches!(ins.mnemonic(), Mnemonic::Cmpxchg8b | Mnemonic::Cmpxchg16b) {
        wide_compare_exchange(lifter, addr, width);
        return true;
    }
    let source_index = if ins.op0_kind() == OpKind::Memory {
        1
    } else {
        0
    };
    let source = match ins.mnemonic() {
        Mnemonic::Inc | Mnemonic::Dec => Expr::constant(1),
        _ => match operand(lifter, ins, source_index) {
            Some(source) => source,
            None => {
                lifter.stmts.push(Stmt::unsupported("atomic source"));
                return true;
            }
        },
    };
    let bit_op = matches!(
        ins.mnemonic(),
        Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc
    );
    let bit = Expr::bin(
        BinOp::And,
        source.clone(),
        Expr::constant(u64::from(bits - 1)),
    );
    if bit_op && ins.op1_kind() == OpKind::Register {
        let signed = Expr::SignExtend {
            value: Box::new(source.clone()),
            width,
        };
        let offset = Expr::bin(
            BinOp::Mul,
            Expr::bin(
                BinOp::Sar,
                signed,
                Expr::constant(u64::from(bits.trailing_zeros())),
            ),
            Expr::constant(u64::from(width)),
        );
        addr = Expr::bin(BinOp::Add, addr, offset);
    }
    let argument = if bit_op {
        let mask = Expr::bin(BinOp::Shl, Expr::constant(1), bit.clone());
        if op == AtomicOp::And {
            Expr::bin(BinOp::Xor, mask, Expr::constant(u64::MAX))
        } else {
            mask
        }
    } else {
        source.clone()
    };
    let expected = Lifter::read_reg(RAX, bits);
    preserve_compare(&mut lifter.last_compare, Write::Memory, &mut lifter.stmts);
    preserve_compare(
        &mut lifter.last_compare,
        Write::Register(OUTPUT, None),
        &mut lifter.stmts,
    );
    let mut inputs = vec![addr, argument];
    if op == AtomicOp::CompareExchange {
        inputs.push(expected.clone());
    }
    lifter.stmts.push(Stmt::Machine {
        instruction: MachineInstruction::Atomic {
            op,
            width,
            ordering: Ordering::SeqCst,
        },
        inputs,
        outputs: vec![RegRef {
            index: OUTPUT,
            width: bits,
        }],
    });
    let old = Expr::reg(OUTPUT, bits);
    if bit_op {
        lifter.set_flags(Flags::carry(Expr::bin(
            BinOp::And,
            Expr::bin(BinOp::Shr, old, bit),
            Expr::constant(1),
        )));
    } else if op == AtomicOp::CompareExchange {
        lifter.set_flags(Flags::difference(expected, old.clone()));
        // EAX is zero-extended even when a 32-bit comparison succeeds.
        lifter.assign(RAX, bits, old);
    } else if op == AtomicOp::Exchange {
        write_operand(lifter, ins, source_index, old);
    } else {
        let binary = match op {
            AtomicOp::Add => BinOp::Add,
            AtomicOp::Sub => BinOp::Sub,
            AtomicOp::And => BinOp::And,
            AtomicOp::Or => BinOp::Or,
            _ => BinOp::Xor,
        };
        let flags = match op {
            AtomicOp::Add => Flags::sum(old.clone(), source),
            AtomicOp::Sub => Flags::difference(old.clone(), source),
            _ => Flags::logic_at(Expr::bin(binary, old.clone(), source), u32::from(bits)),
        };
        lifter.set_flags(if matches!(ins.mnemonic(), Mnemonic::Inc | Mnemonic::Dec) {
            flags.keeping_carry()
        } else {
            flags
        });
        if ins.mnemonic() == Mnemonic::Xadd {
            write_operand(lifter, ins, 1, old);
        }
    }
    true
}

fn wide_compare_exchange(lifter: &mut Lifter, addr: Expr, width: u8) {
    let half = width * 4;
    preserve_compare(&mut lifter.last_compare, Write::Memory, &mut lifter.stmts);
    for index in [OUTPUT, OUTPUT + 1] {
        preserve_compare(
            &mut lifter.last_compare,
            Write::Register(index, None),
            &mut lifter.stmts,
        );
    }
    let low_expected = Lifter::read_reg(RAX, half);
    let high_expected = Lifter::read_reg(RDX, half);
    lifter.stmts.push(Stmt::Machine {
        instruction: MachineInstruction::Atomic {
            op: AtomicOp::CompareExchange,
            width,
            ordering: Ordering::SeqCst,
        },
        inputs: vec![
            addr,
            Lifter::read_reg(3, half),
            low_expected.clone(),
            Lifter::read_reg(1, half),
            high_expected.clone(),
        ],
        outputs: vec![
            RegRef {
                index: OUTPUT,
                width: half,
            },
            RegRef {
                index: OUTPUT + 1,
                width: half,
            },
        ],
    });
    let low = Expr::reg(OUTPUT, half);
    let high = Expr::reg(OUTPUT + 1, half);
    let difference = Expr::bin(
        BinOp::Or,
        Expr::bin(BinOp::Xor, low.clone(), low_expected),
        Expr::bin(BinOp::Xor, high.clone(), high_expected),
    );
    // Only ZF is defined; preserve the full registers on a successful comparison.
    lifter.set_flags(Flags::difference(difference.clone(), Expr::constant(0)));
    for (register, value) in [(RAX, low), (RDX, high)] {
        let value = Expr::Select {
            cond: Cond::Eq,
            lhs: Box::new(difference.clone()),
            rhs: Box::new(Expr::constant(0)),
            then: Box::new(Expr::reg(register, 64)),
            els: Box::new(value),
        };
        // Save both decisions before modifying either expected register.
        lifter.stmts.push(Stmt::Assign {
            dest: RegRef {
                index: OUTPUT + 2 + register,
                width: 64,
            },
            value,
        });
    }
    lifter.assign(RAX, 64, Expr::reg(OUTPUT + 2 + RAX, 64));
    lifter.assign(RDX, 64, Expr::reg(OUTPUT + 2 + RDX, 64));
}

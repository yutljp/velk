use super::{DIRECTION, Lifter, stack_adjust};
use crate::arch::x86::{RAX, RDX, RSP};
use crate::ir::{BinOp, Cond, Expr, MachineInstruction, RegRef, Stmt, TEMP_BASE};
use crate::lift::flags::Flags;
use iced_x86::Mnemonic;

const OUTPUT: u16 = TEMP_BASE + 0x50;

pub(super) fn lift(lifter: &mut Lifter<'_>, mnemonic: Mnemonic) {
    let (instruction, inputs, count) = match mnemonic {
        Mnemonic::Cpuid => (
            MachineInstruction::Cpuid,
            vec![Lifter::read_reg(RAX, 32), Lifter::read_reg(1, 32)],
            4,
        ),
        Mnemonic::Xgetbv => (MachineInstruction::Xgetbv, vec![Lifter::read_reg(1, 32)], 1),
        Mnemonic::Rdtsc => (MachineInstruction::Rdtsc, vec![], 1),
        Mnemonic::Rdtscp => (MachineInstruction::Rdtscp, vec![], 2),
        Mnemonic::Pushfq => {
            let mut mask = 1 << 10;
            let mut bits = Expr::bin(BinOp::Shl, Expr::reg(DIRECTION, 64), Expr::constant(10));
            if let Some(flags) = &lifter.last_compare {
                for (test, bit) in [
                    (lifter.test(Cond::Cc), 0),
                    (flags.parity(true), 2),
                    (flags.adjust(), 4),
                    (lifter.test(Cond::Eq), 6),
                    (lifter.test(Cond::Mi), 7),
                    (lifter.test(Cond::Vs), 11),
                ] {
                    if let Some(value) = test.select(Expr::constant(1 << bit), Expr::constant(0)) {
                        mask |= 1 << bit;
                        bits = Expr::bin(BinOp::Or, bits, value);
                    }
                }
            }
            (
                MachineInstruction::ReadFlags,
                vec![Expr::constant(mask), bits],
                1,
            )
        }
        Mnemonic::Popfq => (
            MachineInstruction::WriteFlags,
            vec![Expr::Load {
                addr: Box::new(Lifter::read_reg(RSP, 64)),
                width: 8,
                signed: false,
            }],
            1,
        ),
        _ => return,
    };
    for offset in 0..count {
        crate::lift::preserve_compare(
            &mut lifter.last_compare,
            crate::lift::Write::Register(OUTPUT + offset, None),
            &mut lifter.stmts,
        );
    }
    lifter.stmts.push(Stmt::Machine {
        instruction,
        inputs,
        outputs: (0..count)
            .map(|offset| RegRef {
                index: OUTPUT + offset,
                width: 64,
            })
            .collect(),
    });
    let output = |offset| Expr::reg(OUTPUT + offset, 64);
    match instruction {
        MachineInstruction::Atomic { .. }
        | MachineInstruction::ArmSystem { .. }
        | MachineInstruction::ArmBarrier { .. }
        | MachineInstruction::ArmLoadAcquire { .. }
        | MachineInstruction::ArmExclusive { .. }
        | MachineInstruction::ArmCacheZero => unreachable!(),
        MachineInstruction::Cpuid => {
            for (offset, register) in [RAX, 3, 1, RDX].into_iter().enumerate() {
                lifter.assign(register, 32, output(offset as u16));
            }
        }
        MachineInstruction::Xgetbv | MachineInstruction::Rdtsc | MachineInstruction::Rdtscp => {
            lifter.assign(RAX, 32, output(0));
            lifter.assign(
                RDX,
                32,
                Expr::bin(BinOp::Shr, output(0), Expr::constant(32)),
            );
            if instruction == MachineInstruction::Rdtscp {
                lifter.assign(1, 32, output(1));
            }
        }
        MachineInstruction::ReadFlags => {
            stack_adjust(lifter, -8);
            crate::lift::preserve_compare(
                &mut lifter.last_compare,
                crate::lift::Write::Memory,
                &mut lifter.stmts,
            );
            lifter.stmts.push(Stmt::Store {
                addr: Lifter::read_reg(RSP, 64),
                value: output(0),
                width: 8,
            });
        }
        MachineInstruction::WriteFlags => {
            stack_adjust(lifter, 8);
            let overflow = Expr::bin(
                BinOp::And,
                Expr::bin(BinOp::Shr, output(0), Expr::constant(11)),
                Expr::constant(1),
            );
            lifter.set_flags(Flags::stored(output(0), Some(overflow)));
            lifter.assign(
                DIRECTION,
                64,
                Expr::bin(
                    BinOp::And,
                    Expr::bin(BinOp::Shr, output(0), Expr::constant(10)),
                    Expr::constant(1),
                ),
            );
        }
    }
}

#[cfg(test)]
mod tests;

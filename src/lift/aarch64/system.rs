//! Operations whose effects depend on processor state outside the registers.

use super::{
    Expr, Instruction, Lifter, Operand, RegRef, Stmt, Write, a64, destination, memory,
    preserve_compare, register_width,
};
use crate::ir::MachineInstruction;

pub(super) fn lift(lifter: &mut Lifter, ins: &Instruction) -> bool {
    use a64::Opcode as O;
    let mut inputs = Vec::new();
    let mut dest = None;
    let instruction = match ins.opcode {
        O::PRFM | O::PRFUM => return true,
        O::DMB(option) => MachineInstruction::ArmBarrier { kind: 0, option },
        O::DSB(option) => MachineInstruction::ArmBarrier { kind: 1, option },
        O::ISB => {
            let Operand::Imm16(option) = ins.operands[0] else {
                return false;
            };
            MachineInstruction::ArmBarrier {
                kind: 2,
                option: option as u8,
            }
        }
        O::LDAPR | O::LDAPRB | O::LDAPRH | O::LDAPUR | O::LDAPURB | O::LDAPURH => {
            let Some(register_bits) = register_width(ins.operands[0]) else {
                return false;
            };
            let width = match ins.opcode {
                O::LDAPRB | O::LDAPURB => 1,
                O::LDAPRH | O::LDAPURH => 2,
                _ => register_bits / 8,
            };
            let Some(mem) = memory::memory(ins.operands[1], 64) else {
                return false;
            };
            inputs.push(mem.address);
            dest = destination(ins.operands[0]);
            MachineInstruction::ArmLoadAcquire { width }
        }
        O::MRS | O::MSR => {
            let write = ins.opcode == O::MSR;
            let Operand::SystemReg(register) = ins.operands[usize::from(!write)] else {
                return false;
            };
            // Arithmetic and floating-point operations do not materialize these
            // registers, so their reads and writes must remain unsupported.
            if matches!(register, 0x5a10 | 0x5a20 | 0x5a21) {
                return false;
            }
            if write {
                let Some(value) = lifter.operand(ins.operands[1], 64) else {
                    return false;
                };
                inputs.push(value);
            } else {
                dest = destination(ins.operands[0]);
            }
            MachineInstruction::ArmSystem { register, write }
        }
        O::SYS(ops)
            if ops.op1() == 3
                && ops.op2() == 1
                && ins.operands[1] == Operand::ControlReg(7)
                && ins.operands[2] == Operand::ControlReg(4) =>
        {
            let Some(address) = lifter.operand(ins.operands[0], 64) else {
                return false;
            };
            inputs.push(address);
            MachineInstruction::ArmCacheZero
        }
        _ => return false,
    };
    let output = RegRef {
        index: crate::ir::TEMP_BASE + 0x50,
        width: 64,
    };
    preserve_compare(&mut lifter.last_compare, Write::Memory, &mut lifter.stmts);
    preserve_compare(
        &mut lifter.last_compare,
        Write::Register(output.index, None),
        &mut lifter.stmts,
    );
    lifter.stmts.push(Stmt::Machine {
        at: None,
        instruction,
        inputs,
        outputs: if matches!(
            instruction,
            MachineInstruction::ArmSystem { write: false, .. }
                | MachineInstruction::ArmLoadAcquire { .. }
        ) {
            vec![output]
        } else {
            vec![]
        },
    });
    if let Some(dest) = dest {
        lifter.assign(dest, Expr::reg(output.index, 64));
    }
    true
}

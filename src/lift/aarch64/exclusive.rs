//! Accesses whose success depends on the processor's exclusive monitor.

use super::{
    Expr, Instruction, Lifter, Operand, RegRef, Stmt, Write, a64, destination, memory,
    preserve_compare, register_width,
};
use crate::ir::MachineInstruction;

pub(super) fn lift(lifter: &mut Lifter, ins: &Instruction) -> bool {
    use a64::Opcode as O;
    let (load, bytes, pair, ordered) = match ins.opcode {
        O::LDXR => (true, 0, false, false),
        O::LDAXR => (true, 0, false, true),
        O::LDXRB => (true, 1, false, false),
        O::LDAXRB => (true, 1, false, true),
        O::LDXRH => (true, 2, false, false),
        O::LDAXRH => (true, 2, false, true),
        O::LDXP => (true, 0, true, false),
        O::LDAXP => (true, 0, true, true),
        O::STXR => (false, 0, false, false),
        O::STLXR => (false, 0, false, true),
        O::STXRB => (false, 1, false, false),
        O::STLXRB => (false, 1, false, true),
        O::STXRH => (false, 2, false, false),
        O::STLXRH => (false, 2, false, true),
        O::STXP => (false, 0, true, false),
        O::STLXP => (false, 0, true, true),
        _ => return false,
    };
    let first = usize::from(!load);
    if load && pair && ins.operands[0] == ins.operands[1] {
        lifter.incomplete.set(true);
        return true;
    }
    let Some(bits) = register_width(ins.operands[first]) else {
        lifter.incomplete.set(true);
        return true;
    };
    let width = if bytes == 0 { bits / 8 } else { bytes };
    let address_operand = first + 1 + usize::from(pair);
    if !load && let Some(status) = destination(ins.operands[0]) {
        let aliases_value = ins.operands[first..address_operand].iter().any(
            |operand| matches!(operand, Operand::Register(_, index) if *index == status.index),
        );
        let aliases_base = matches!(ins.operands[address_operand],
            Operand::RegPreIndex(index, _, _) if index != 31 && index == status.index);
        if aliases_value || aliases_base {
            lifter.incomplete.set(true);
            return true;
        }
    }
    let Some(mem) = memory::memory(ins.operands[address_operand], 64) else {
        lifter.incomplete.set(true);
        return true;
    };
    let mut inputs = vec![mem.address];
    if !load {
        for operand in &ins.operands[first..address_operand] {
            let Some(value) = lifter.operand(*operand, bits) else {
                lifter.incomplete.set(true);
                return true;
            };
            inputs.push(value);
        }
    }
    let count = if load && pair { 2 } else { 1 };
    let outputs: Vec<_> = (0..count)
        .map(|offset| RegRef {
            index: crate::ir::TEMP_BASE + 0x50 + offset,
            width: 64,
        })
        .collect();
    preserve_compare(&mut lifter.last_compare, Write::Memory, &mut lifter.stmts);
    for output in &outputs {
        preserve_compare(
            &mut lifter.last_compare,
            Write::Register(output.index, None),
            &mut lifter.stmts,
        );
    }
    lifter.stmts.push(Stmt::Machine {
        at: None,
        instruction: MachineInstruction::ArmExclusive {
            load,
            width,
            pair,
            ordered,
        },
        inputs,
        outputs: outputs.clone(),
    });
    for (offset, output) in outputs.iter().enumerate() {
        if let Some(dest) = destination(ins.operands[if load { offset } else { 0 }]) {
            lifter.assign(dest, Expr::reg(output.index, 64));
        }
    }
    true
}

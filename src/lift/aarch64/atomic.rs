use super::{
    BinOp, Expr, Instruction, Lifter, Operand, RegRef, SizeCode, Stmt, Write, a64, destination,
    lift_alu, memory, preserve_compare, relative_target,
};
use crate::ir::{AtomicOp, MachineInstruction, Ordering};

/// A retry loop containing only a load, pure update, exclusive store and
/// retry has the same observable memory effect as one atomic update.
/// Other exclusive sequences retain their monitor operations.
pub(in crate::lift) fn recover_atomic_loops(
    image: &crate::loader::Image,
    summaries: super::super::Summaries<'_>,
    blocks: &mut [crate::ir::Block],
) {
    use a64::Opcode as O;
    let starts: std::collections::HashSet<_> = blocks.iter().map(|block| block.start).collect();
    for block in blocks {
        if !matches!(
            block.stmts.first(),
            Some(Stmt::Machine {
                instruction: MachineInstruction::ArmExclusive { load: true, .. },
                ..
            })
        ) {
            continue;
        }
        let Some(next) = block.start.checked_add(16) else {
            continue;
        };
        if (1..4).any(|offset| starts.contains(&(block.start + offset * 4))) {
            continue;
        }
        let Some(bytes) = image.read_vaddr(block.start, 16) else {
            continue;
        };
        let (decoded, error) = super::decode(bytes, block.start);
        if error.is_some() || decoded.len() != 4 {
            continue;
        }
        let load = &decoded[0].instruction;
        let update = &decoded[1].instruction;
        let store = &decoded[2].instruction;
        let retry = &decoded[3].instruction;
        let (width, acquire) = match load.opcode {
            O::LDXR => (0, false),
            O::LDAXR => (0, true),
            O::LDXRB => (1, false),
            O::LDAXRB => (1, true),
            O::LDXRH => (2, false),
            O::LDAXRH => (2, true),
            _ => continue,
        };
        let (store_width, release) = match store.opcode {
            O::STXR => (0, false),
            O::STLXR => (0, true),
            O::STXRB => (1, false),
            O::STLXRB => (1, true),
            O::STXRH => (2, false),
            O::STLXRH => (2, true),
            _ => continue,
        };
        if width != store_width
            || load.operands[1] != store.operands[2]
            || retry.opcode != O::CBNZ
            || destination(retry.operands[0]).is_none_or(|retry| {
                destination(store.operands[0])
                    .is_none_or(|status| retry.index != status.index || retry.width < status.width)
            })
            || relative_target(retry.operands[1], decoded[3].pc) != Some(block.start)
            || !matches!(block.stmts.last(), Some(Stmt::Brif { target, .. }) if *target == block.start)
        {
            continue;
        }
        let (Some(old), Some(new), Some(status)) = (
            destination(load.operands[0]),
            destination(update.operands[0]),
            destination(store.operands[0]),
        ) else {
            continue;
        };
        if update.operands[1] != load.operands[0]
            || update.operands[0] != store.operands[1]
            || old.width != new.width
            || status.index == old.index
            || status.index == new.index
        {
            continue;
        }
        let (op, binary) = match update.opcode {
            O::ADD => (AtomicOp::Add, BinOp::Add),
            O::SUB => (AtomicOp::Sub, BinOp::Sub),
            O::AND => (AtomicOp::And, BinOp::And),
            O::ORR => (AtomicOp::Or, BinOp::Or),
            O::EOR => (AtomicOp::Xor, BinOp::Xor),
            _ => continue,
        };
        if update.operands[3] != Operand::Nothing {
            continue;
        }
        let mut lifter = Lifter::new(image, summaries);
        let Some(mem) = memory::memory(load.operands[1], 64) else {
            continue;
        };
        let Some(argument) = lifter.operand(update.operands[2], new.width) else {
            continue;
        };
        let changed = [old.index, new.index, status.index];
        let mut reads = std::collections::HashSet::new();
        crate::ir::visit::collect_reads(&mem.address, &mut reads);
        crate::ir::visit::collect_reads(&argument, &mut reads);
        if changed.iter().any(|reg| reads.contains(reg)) {
            continue;
        }
        let width = if width == 0 { old.width / 8 } else { width };
        let ordering = match (acquire, release) {
            (false, false) => Ordering::Relaxed,
            (true, false) => Ordering::Acquire,
            (false, true) => Ordering::Release,
            (true, true) => Ordering::AcqRel,
        };
        let output = RegRef {
            index: crate::ir::TEMP_BASE + 0x60,
            width: width * 8,
        };
        lifter.stmts.push(Stmt::Machine {
            instruction: MachineInstruction::Atomic {
                op,
                width,
                ordering,
            },
            inputs: vec![mem.address, argument],
            outputs: vec![output],
        });
        lifter.assign(old, Expr::reg(output.index, output.width));
        lift_alu(&mut lifter, update.operands, binary, false);
        lifter.assign(status, Expr::constant(0));
        lifter.stmts.push(Stmt::Br { target: Some(next) });
        block.stmts = lifter.stmts;
    }
}

pub(super) fn lift(lifter: &mut Lifter, ins: &Instruction) -> bool {
    use a64::Opcode as O;
    let (op, bytes, acquire_release) = match ins.opcode {
        O::LDADD(acquire_release) => (AtomicOp::Add, 0, acquire_release),
        O::LDADDB(acquire_release) => (AtomicOp::Add, 1, acquire_release),
        O::LDADDH(acquire_release) => (AtomicOp::Add, 2, acquire_release),
        O::LDCLR(acquire_release) => (AtomicOp::And, 0, acquire_release),
        O::LDCLRB(acquire_release) => (AtomicOp::And, 1, acquire_release),
        O::LDCLRH(acquire_release) => (AtomicOp::And, 2, acquire_release),
        O::LDSET(acquire_release) => (AtomicOp::Or, 0, acquire_release),
        O::LDSETB(acquire_release) => (AtomicOp::Or, 1, acquire_release),
        O::LDSETH(acquire_release) => (AtomicOp::Or, 2, acquire_release),
        O::LDEOR(acquire_release) => (AtomicOp::Xor, 0, acquire_release),
        O::LDEORB(acquire_release) => (AtomicOp::Xor, 1, acquire_release),
        O::LDEORH(acquire_release) => (AtomicOp::Xor, 2, acquire_release),
        O::SWP(acquire_release) => (AtomicOp::Exchange, 0, acquire_release),
        O::SWPB(acquire_release) => (AtomicOp::Exchange, 1, acquire_release),
        O::SWPH(acquire_release) => (AtomicOp::Exchange, 2, acquire_release),
        O::CAS(acquire_release) => (AtomicOp::CompareExchange, 0, acquire_release),
        O::CASB(acquire_release) => (AtomicOp::CompareExchange, 1, acquire_release),
        O::CASH(acquire_release) => (AtomicOp::CompareExchange, 2, acquire_release),
        O::LDAR => (AtomicOp::Load, 0, 2),
        O::LDARB => (AtomicOp::Load, 1, 2),
        O::LDARH => (AtomicOp::Load, 2, 2),
        O::STLR | O::STLUR => (AtomicOp::Store, 0, 1),
        O::STLRB | O::STLURB => (AtomicOp::Store, 1, 1),
        O::STLRH | O::STLURH => (AtomicOp::Store, 2, 1),
        _ => return false,
    };
    let ops = ins.operands;
    let Operand::Register(size, index) = ops[0] else {
        lifter.stmts.push(Stmt::unsupported("atomic register"));
        return true;
    };
    let first = RegRef {
        index,
        width: if size == SizeCode::X { 64 } else { 32 },
    };
    let width = if bytes == 0 { first.width / 8 } else { bytes };
    let simple = matches!(op, AtomicOp::Load | AtomicOp::Store);
    let Some(mem) = memory::memory(ops[if simple { 1 } else { 2 }], width * 8) else {
        lifter.stmts.push(Stmt::unsupported("atomic address"));
        return true;
    };
    let Some(mut source) = lifter.operand(ops[0], width * 8) else {
        lifter.stmts.push(Stmt::unsupported("atomic source"));
        return true;
    };
    let result = if simple || op == AtomicOp::CompareExchange {
        destination(ops[0])
    } else {
        destination(ops[1])
    };
    let mut acquire = acquire_release & 2 != 0;
    // The acquire bit is ignored when the RMW result is discarded.
    if !simple && op != AtomicOp::CompareExchange && matches!(ops[1], Operand::Register(_, 31)) {
        acquire = false;
    }
    let ordering = match (acquire, acquire_release & 1 != 0) {
        (false, false) => Ordering::Relaxed,
        (true, false) => Ordering::Acquire,
        (false, true) => Ordering::Release,
        (true, true) => Ordering::AcqRel,
    };
    if op == AtomicOp::And {
        source = Expr::bin(BinOp::Xor, source, Expr::constant(u64::MAX));
    }
    let mut inputs = vec![mem.address];
    if op == AtomicOp::CompareExchange {
        let Some(desired) = lifter.operand(ops[1], width * 8) else {
            lifter.stmts.push(Stmt::unsupported("atomic replacement"));
            return true;
        };
        inputs.extend([desired, source]);
    } else if op != AtomicOp::Load {
        inputs.push(source);
    }
    let output = RegRef {
        index: crate::ir::TEMP_BASE + 0x60,
        width: width * 8,
    };
    preserve_compare(&mut lifter.last_compare, Write::Memory, &mut lifter.stmts);
    preserve_compare(
        &mut lifter.last_compare,
        Write::Register(output.index, None),
        &mut lifter.stmts,
    );
    lifter.stmts.push(Stmt::Machine {
        instruction: MachineInstruction::Atomic {
            op,
            width,
            ordering,
        },
        inputs,
        outputs: if op == AtomicOp::Store {
            vec![]
        } else {
            vec![output]
        },
    });
    if op != AtomicOp::Store
        && let Some(dest) = result
    {
        lifter.assign(dest, Expr::reg(output.index, output.width));
    }
    true
}

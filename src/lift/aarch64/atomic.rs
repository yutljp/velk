use super::*;
use crate::ir::{AtomicOp, MachineInstruction, Ordering};

/// A retry loop containing only a load, pure update, exclusive store and
/// retry has the same observable memory effect as one atomic update.
/// Other exclusive sequences retain their unsupported instructions.
pub(in crate::lift) fn recover_atomic_loops(
    image: &crate::loader::Image,
    summaries: super::super::Summaries<'_>,
    blocks: &mut [crate::ir::Block],
) {
    use a64::Opcode as O;
    let starts: std::collections::HashSet<_> = blocks.iter().map(|block| block.start).collect();
    for block in blocks {
        if !matches!(block.stmts.first(), Some(Stmt::Unsupported { text, .. }) if text.starts_with("LDXR") || text.starts_with("LDAXR"))
        {
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
            || retry.operands[0] != store.operands[0]
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
        let Some(mem) = memory::memory(&mut lifter, load.operands[1], 64) else {
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
    let (op, bytes, ar) = match ins.opcode {
        O::LDADD(ar) => (AtomicOp::Add, 0, ar),
        O::LDADDB(ar) => (AtomicOp::Add, 1, ar),
        O::LDADDH(ar) => (AtomicOp::Add, 2, ar),
        O::LDCLR(ar) => (AtomicOp::And, 0, ar),
        O::LDCLRB(ar) => (AtomicOp::And, 1, ar),
        O::LDCLRH(ar) => (AtomicOp::And, 2, ar),
        O::LDSET(ar) => (AtomicOp::Or, 0, ar),
        O::LDSETB(ar) => (AtomicOp::Or, 1, ar),
        O::LDSETH(ar) => (AtomicOp::Or, 2, ar),
        O::LDEOR(ar) => (AtomicOp::Xor, 0, ar),
        O::LDEORB(ar) => (AtomicOp::Xor, 1, ar),
        O::LDEORH(ar) => (AtomicOp::Xor, 2, ar),
        O::SWP(ar) => (AtomicOp::Exchange, 0, ar),
        O::SWPB(ar) => (AtomicOp::Exchange, 1, ar),
        O::SWPH(ar) => (AtomicOp::Exchange, 2, ar),
        O::CAS(ar) => (AtomicOp::CompareExchange, 0, ar),
        O::CASB(ar) => (AtomicOp::CompareExchange, 1, ar),
        O::CASH(ar) => (AtomicOp::CompareExchange, 2, ar),
        O::LDAR => (AtomicOp::Load, 0, 2),
        O::LDARB => (AtomicOp::Load, 1, 2),
        O::LDARH => (AtomicOp::Load, 2, 2),
        O::STLR => (AtomicOp::Store, 0, 1),
        O::STLRB => (AtomicOp::Store, 1, 1),
        O::STLRH => (AtomicOp::Store, 2, 1),
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
    let Some(mem) = memory::memory(lifter, ops[if simple { 1 } else { 2 }], width * 8) else {
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
    let mut acquire = ar & 2 != 0;
    // The acquire bit is ignored when the RMW result is discarded.
    if !simple && op != AtomicOp::CompareExchange && matches!(ops[1], Operand::Register(_, 31)) {
        acquire = false;
    }
    let ordering = match (acquire, ar & 1 != 0) {
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

use std::collections::{BTreeMap, HashSet};

use super::FrameAccess;
use crate::ir::{BinOp, Expr, FunctionIr, Stmt};
use crate::passes::frame_slots::frame_slot;

/// A pointer advanced in a loop can also address slots below its initial
/// value. Those slots must share its C object even at different access widths.
pub(super) fn extend(
    ir: &FunctionIr,
    sp: u16,
    frames: &[Option<i64>],
    accesses: &mut Vec<FrameAccess>,
) {
    let mut starts = BTreeMap::new();
    let mut advanced = HashSet::new();
    let mut invalid = HashSet::new();
    for (block, frame) in ir.blocks.iter().zip(frames) {
        let mut frame = *frame;
        for stmt in &block.stmts {
            let before = frame;
            frame = super::frame_after(stmt, frame, sp);
            let Stmt::Assign { dest, value } = stmt else {
                invalid.extend(crate::ir::visit::statement_registers(stmt).0);
                continue;
            };
            if dest.width != 64 || dest.index == sp {
                invalid.insert(dest.index);
                continue;
            }
            if let Some(slot) = before.and_then(|frame| frame_slot(value, frame, sp))
                && slot < 0
            {
                if starts
                    .insert(dest.index, slot)
                    .is_some_and(|old| old != slot)
                {
                    invalid.insert(dest.index);
                }
            } else if let Expr::Bin {
                op: BinOp::Add,
                lhs,
                rhs,
            } = value
                && matches!(lhs.as_ref(), Expr::Reg { index, width: 64 } if *index == dest.index)
                && matches!(rhs.as_ref(), Expr::Const(_))
            {
                advanced.insert(dest.index);
            } else {
                invalid.insert(dest.index);
            }
        }
    }
    starts.retain(|index, _| advanced.contains(index) && !invalid.contains(index));
    for (index, start) in starts {
        let mut lowest = start;
        let mut inspect = |addr: &Expr| {
            if let Some(delta) = frame_slot(addr, 0, index)
                && let Some(slot) = start.checked_add(delta)
            {
                lowest = lowest.min(slot);
            }
        };
        for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
            if let Stmt::Store { addr, .. } = stmt {
                inspect(addr);
            }
            for operand in stmt.operands() {
                let mut pending = vec![operand];
                while let Some(expr) = pending.pop() {
                    if let Expr::Load { addr, .. } = expr {
                        inspect(addr);
                    }
                    pending.extend(crate::ir::visit::children(expr));
                }
            }
        }
        if lowest < start {
            for slot in [lowest, start] {
                accesses.push((
                    Some(slot),
                    Expr::bin(BinOp::Add, Expr::reg(sp, 64), Expr::Const(slot as u64)),
                    0,
                    Some(false),
                ));
            }
        }
    }
}

use std::collections::{BTreeMap, HashMap, HashSet};

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

pub(super) fn extents(ir: &FunctionIr, sp: u16) -> HashMap<i64, i64> {
    let mut extents = HashMap::new();
    let mut indexed = false;
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        if let Stmt::Store { addr, .. } = stmt {
            indexed |= super::offset_local(addr, sp).is_some();
        }
        let mut pending = stmt.operands();
        while let Some(value) = pending.pop() {
            if let Expr::Load { addr, .. } = value {
                indexed |= super::offset_local(addr, sp).is_some();
            }
            pending.extend(crate::ir::visit::children(value));
        }
    }
    if !indexed
        || ir
            .blocks
            .iter()
            .flat_map(|block| &block.stmts)
            .any(|stmt| crate::ir::visit::statement_registers(stmt).0.contains(&sp))
    {
        return extents;
    }
    let Some(ssa) = crate::ssa::build(ir) else {
        return extents;
    };
    let Some(&renamed_sp) = ssa.entry.get(&sp) else {
        return extents;
    };
    let Some(ranges) = crate::ssa::ranges::Ranges::solve(&ssa) else {
        return extents;
    };
    let frames = crate::passes::frame_slots::block_frames(ir, sp);
    for (index, (block, renamed)) in ir.blocks.iter().zip(&ssa.ir.blocks).enumerate() {
        let Some(mut frame) = frames[index] else {
            continue;
        };
        for (stmt, renamed) in block.stmts.iter().zip(&renamed.stmts) {
            let inspect =
                |addr: &Expr, renamed: &Expr, width: u8, extents: &mut HashMap<i64, i64>| {
                    let Some((base, _)) = super::offset_local(addr, sp) else {
                        return;
                    };
                    let Some(slot) = frame_slot(&base, frame, sp).filter(|slot| *slot < 0) else {
                        return;
                    };
                    let Some((_, terms)) = super::offset_local(renamed, renamed_sp) else {
                        return;
                    };
                    let mut high = 0u64;
                    for term in terms {
                        let Some(fact) = ranges.eval(&term, index, 32) else {
                            return;
                        };
                        let Some(sum) = high.checked_add(fact.hi) else {
                            return;
                        };
                        high = sum;
                    }
                    let Some(end) = i64::try_from(high)
                        .ok()
                        .and_then(|high| slot.checked_add(high))
                        .and_then(|end| end.checked_add(i64::from(width)))
                    else {
                        return;
                    };
                    if end <= 0 && end > slot {
                        extents
                            .entry(slot)
                            .and_modify(|known| *known = (*known).max(end))
                            .or_insert(end);
                    }
                };
            if let (Stmt::Store { addr, width, .. }, Stmt::Store { addr: renamed, .. }) =
                (stmt, renamed)
            {
                inspect(addr, renamed, *width, &mut extents);
            }
            let mut pending: Vec<_> = stmt
                .operands()
                .into_iter()
                .zip(renamed.operands())
                .collect();
            while let Some((value, renamed)) = pending.pop() {
                if let (Expr::Load { addr, width, .. }, Expr::Load { addr: renamed, .. }) =
                    (value, renamed)
                {
                    inspect(addr, renamed, *width, &mut extents);
                }
                pending.extend(
                    crate::ir::visit::children(value)
                        .into_iter()
                        .zip(crate::ir::visit::children(renamed)),
                );
            }
            frame = match super::frame_after(stmt, Some(frame), sp) {
                Some(frame) => frame,
                None => break,
            };
        }
    }
    extents
}

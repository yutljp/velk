use crate::arch::stack_pointer;
use std::collections::HashMap;

use crate::ir::{BinOp, Expr, FunctionIr, Stmt};
use crate::passes::{copies, frame};

/// Rewrites every stack access against the entry frame and drops the
/// adjustments, when the stack pointer is only ever a frame base.
pub fn settle(ir: &mut FunctionIr) {
    let frames = block_frames(ir, stack_pointer(ir.isa));
    if !canonical_frame(ir, &frames) {
        return;
    }
    rewrite_frame(ir, &frames);
    frame::drop_dead_frame_stores(ir);
    copies::inline_local_copies(ir);
}

/// True when every block has a known frame and the stack pointer is used only
/// as a frame-slot address and written only by adjustments.
pub(crate) fn canonical_frame(ir: &FunctionIr, frames: &[Option<i64>]) -> bool {
    let sp = stack_pointer(ir.isa);
    for (position, block) in ir.blocks.iter().enumerate() {
        let Some(frame) = frames[position] else {
            return false;
        };
        for stmt in &block.stmts {
            match stmt {
                Stmt::Store { addr, value, .. } => {
                    if frame_slot(addr, frame, sp).is_none() || !frame_only(value, frame, sp) {
                        return false;
                    }
                }
                Stmt::Assign { dest, value } => {
                    if dest.index == sp {
                        if !is_adjustment(value, sp) {
                            return false;
                        }
                        continue;
                    }
                    if !frame_only(value, frame, sp) {
                        return false;
                    }
                }
                Stmt::Brif { lhs, rhs, .. } => {
                    if !frame_only(lhs, frame, sp) || !frame_only(rhs, frame, sp) {
                        return false;
                    }
                }
                Stmt::Switch { index, .. } => {
                    if !frame_only(index, frame, sp) {
                        return false;
                    }
                }
                Stmt::BrIndirect { target } => {
                    if !frame_only(target, frame, sp) {
                        return false;
                    }
                }
                Stmt::Ret { value } if !frame_only(value, frame, sp) => {
                    return false;
                }
                Stmt::Call {
                    through: Some(through),
                    ..
                } if !frame_only(through, frame, sp) => {
                    return false;
                }
                _ => {}
            }
        }
    }
    true
}

/// True when the stack pointer appears in the value only as the address of a
/// frame-slot load.
fn frame_only(expr: &Expr, frame: i64, sp: u16) -> bool {
    match expr {
        Expr::Reg { index, .. } => *index != sp,
        Expr::Const(_) => true,
        Expr::Bin { lhs, rhs, .. } => frame_only(lhs, frame, sp) && frame_only(rhs, frame, sp),
        Expr::Load { addr, .. } => match frame_slot(addr, frame, sp) {
            Some(_) => true,
            None => frame_only(addr, frame, sp),
        },
        Expr::SignExtend { value, .. } => frame_only(value, frame, sp),
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => {
            frame_only(lhs, frame, sp)
                && frame_only(rhs, frame, sp)
                && frame_only(then, frame, sp)
                && frame_only(els, frame, sp)
        }
    }
}

fn is_adjustment(value: &Expr, sp: u16) -> bool {
    matches!(
        value,
        Expr::Bin { lhs, .. } if matches!(lhs.as_ref(), Expr::Reg { index, .. } if *index == sp)
    )
}

/// Rewrites frame-relative addresses against the entry frame and drops the
/// adjustments, so each slot has one address everywhere.
pub(crate) fn rewrite_frame(ir: &mut FunctionIr, frames: &[Option<i64>]) {
    let sp = stack_pointer(ir.isa);
    for (position, block) in ir.blocks.iter_mut().enumerate() {
        let Some(mut frame) = frames[position] else {
            continue;
        };
        for stmt in &mut block.stmts {
            match stmt {
                Stmt::Store { addr, value, .. } => {
                    if let Some(slot) = frame_slot(addr, frame, sp) {
                        *addr = frame_address(sp, slot);
                    }
                    rewrite_expr_frame(value, frame, sp);
                }
                Stmt::Assign { dest, value } => {
                    if dest.index == sp {
                        if let Expr::Bin { op, rhs, .. } = value
                            && let Expr::Const(delta) = rhs.as_ref()
                        {
                            frame = match op {
                                BinOp::Add => frame.wrapping_add(*delta as i64),
                                BinOp::Sub => frame.wrapping_sub(*delta as i64),
                                _ => frame,
                            };
                        }
                        continue;
                    }
                    rewrite_expr_frame(value, frame, sp);
                }
                Stmt::Brif { lhs, rhs, .. } => {
                    rewrite_expr_frame(lhs, frame, sp);
                    rewrite_expr_frame(rhs, frame, sp);
                }
                Stmt::Switch { index: value, .. }
                | Stmt::BrIndirect { target: value }
                | Stmt::Ret { value }
                | Stmt::Call {
                    through: Some(value),
                    ..
                } => rewrite_expr_frame(value, frame, sp),
                _ => {}
            }
        }
        // Drop the adjustments now that every access names its slot.
        block
            .stmts
            .retain(|stmt| !matches!(stmt, Stmt::Assign { dest, value } if dest.index == sp && is_adjustment(value, sp)));
    }
}

fn rewrite_expr_frame(expr: &mut Expr, frame: i64, sp: u16) {
    match expr {
        Expr::Load { addr, .. } => {
            if let Some(slot) = frame_slot(addr, frame, sp) {
                **addr = frame_address(sp, slot);
            } else {
                rewrite_expr_frame(addr, frame, sp);
            }
        }
        Expr::Bin { lhs, rhs, .. } => {
            rewrite_expr_frame(lhs, frame, sp);
            rewrite_expr_frame(rhs, frame, sp);
        }
        Expr::SignExtend { value, .. } => rewrite_expr_frame(value, frame, sp),
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => {
            rewrite_expr_frame(lhs, frame, sp);
            rewrite_expr_frame(rhs, frame, sp);
            rewrite_expr_frame(then, frame, sp);
            rewrite_expr_frame(els, frame, sp);
        }
        _ => {}
    }
}

fn frame_address(sp: u16, slot: i64) -> Expr {
    Expr::bin(
        BinOp::Add,
        Expr::Reg {
            index: sp,
            width: 64,
        },
        Expr::Const(slot as u64),
    )
}

/// The entry-frame offset of an address that is exactly `sp + k`, given the
/// frame displacement at that point.
pub(crate) fn frame_slot(expr: &Expr, frame: i64, sp: u16) -> Option<i64> {
    match expr {
        Expr::Reg { index, .. } if *index == sp => Some(frame),
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Reg { index, .. }, Expr::Const(delta)) if *index == sp => {
                Some(frame.wrapping_add(*delta as i64))
            }
            (Expr::Const(delta), Expr::Reg { index, .. }) if *index == sp => {
                Some(frame.wrapping_add(*delta as i64))
            }
            _ => None,
        },
        _ => None,
    }
}

/// The frame displacement on entry to each block, propagated over the control
/// flow; `None` when unreachable or when paths disagree.
pub(crate) fn block_frames(ir: &FunctionIr, sp: u16) -> Vec<Option<i64>> {
    let index: HashMap<u64, usize> = ir
        .blocks
        .iter()
        .enumerate()
        .map(|(position, block)| (block.start, position))
        .collect();
    let mut frames: Vec<Option<i64>> = vec![None; ir.blocks.len()];
    if frames.is_empty() {
        return frames;
    }
    frames[0] = Some(0);
    for _ in 0..ir.blocks.len().max(1) * 4 {
        let mut changed = false;
        for position in 0..ir.blocks.len() {
            let Some(entry) = frames[position] else {
                continue;
            };
            let block = &ir.blocks[position];
            let mut exit = entry;
            for stmt in &block.stmts {
                if let Stmt::Assign { dest, value } = stmt
                    && dest.index == sp
                    && let Expr::Bin { op, rhs, .. } = value
                    && let Expr::Const(delta) = rhs.as_ref()
                {
                    exit = match op {
                        BinOp::Add => exit.wrapping_add(*delta as i64),
                        BinOp::Sub => exit.wrapping_sub(*delta as i64),
                        _ => exit,
                    };
                }
            }
            let mut successors: Vec<usize> = Vec::new();
            match block.stmts.last() {
                Some(Stmt::Brif { target, .. }) | Some(Stmt::BrifFlags { target, .. }) => {
                    if let Some(target) = index.get(target) {
                        successors.push(*target);
                    }
                    if position + 1 < ir.blocks.len() {
                        successors.push(position + 1);
                    }
                }
                Some(Stmt::Switch { cases, default, .. }) => {
                    for (_, target) in cases {
                        if let Some(target) = index.get(target) {
                            successors.push(*target);
                        }
                    }
                    if let Some(target) = default
                        && let Some(target) = index.get(target)
                    {
                        successors.push(*target);
                    }
                }
                Some(Stmt::Br {
                    target: Some(target),
                }) => {
                    if let Some(target) = index.get(target) {
                        successors.push(*target);
                    }
                }
                Some(Stmt::Ret { .. }) | Some(Stmt::BrIndirect { .. }) => {}
                _ => {
                    if position + 1 < ir.blocks.len() {
                        successors.push(position + 1);
                    }
                }
            }
            for successor in successors {
                match frames[successor] {
                    None => {
                        frames[successor] = Some(exit);
                        changed = true;
                    }
                    Some(existing) if existing != exit => {
                        // Paths disagree; `i64::MIN` marks the frame unknown.
                        frames[successor] = Some(i64::MIN);
                    }
                    Some(_) => {}
                }
            }
        }
        if !changed {
            break;
        }
    }
    frames
        .into_iter()
        .map(|frame| (frame != Some(i64::MIN)).then_some(frame).flatten())
        .collect()
}

//! Constant frame values kept across calls that cannot write the caller's memory.

use std::collections::HashMap;

use crate::ir::{Block, Expr, FunctionIr, Stmt};
use crate::loader::Image;
use crate::passes::frame_slots::frame_slot;

struct Stored {
    offset: i64,
    width: u8,
    value: u64,
    first_call: usize,
}

pub(super) fn forward(ir: &mut FunctionIr, image: &Image) {
    if !ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .any(|stmt| matches!(stmt, Stmt::Call { .. }))
    {
        return;
    }
    if !ir.blocks.iter().any(|block| {
        block.stmts.iter().any(|stmt| {
            matches!(
                stmt,
                Stmt::Store {
                    value: Expr::Const(_),
                    width: 8,
                    ..
                }
            )
        })
    }) {
        return;
    }
    let sp = crate::arch::stack_pointer(ir.isa);
    let frames = crate::passes::frame_slots::block_frames(ir, sp);
    let mut call_frames = Vec::new();
    for (block, mut frame) in ir.blocks.iter().zip(frames) {
        let mut calls = Vec::new();
        for stmt in &block.stmts {
            if matches!(stmt, Stmt::Call { .. }) {
                calls.push(frame);
            }
            if let Stmt::Assign { dest, value } = stmt
                && dest.index == sp
            {
                frame = frame.and_then(|frame| frame_slot(value, frame, sp));
            }
        }
        call_frames.push(calls);
    }
    let mut normalized = ir.clone();
    crate::passes::frame_slots::settle(&mut normalized);
    // Settling must have removed every stack adjustment. Otherwise a remembered
    // address could mean different storage at its later read.
    if normalized
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .any(|stmt| crate::ir::visit::statement_registers(stmt).0.contains(&sp))
    {
        return;
    }
    let mut callees = HashMap::new();
    let mut changed = false;
    for (block, frames) in normalized.blocks.iter_mut().zip(call_frames) {
        let mut frames = frames.into_iter();
        let mut pending: Vec<Stored> = Vec::new();
        let mut calls = Vec::new();
        for stmt in &mut block.stmts {
            for operand in stmt.operands_mut() {
                changed |= replace(operand, sp, &mut pending, &mut |first_call| {
                    let preserved = calls[first_call..].iter().all(|target| {
                        *callees
                            .entry(*target)
                            .or_insert_with(|| writes_only_frame(image, *target))
                    });
                    preserved.then_some(calls.len())
                });
            }
            if matches!(stmt, Stmt::Call { .. }) {
                let frame = frames.next().flatten();
                pending.retain(|stored| frame.is_some_and(|frame| stored.offset >= frame));
            }
            match stmt {
                Stmt::Store { addr, value, width } => {
                    let Some(offset) = frame_slot(addr, 0, sp) else {
                        pending.clear();
                        continue;
                    };
                    let Some(end) = offset.checked_add(i64::from(*width)) else {
                        pending.clear();
                        continue;
                    };
                    pending.retain(|stored| {
                        stored.offset >= end
                            || stored
                                .offset
                                .checked_add(i64::from(stored.width))
                                .is_some_and(|end| end <= offset)
                    });
                    if matches!(width, 1 | 2 | 4 | 8)
                        && let Expr::Const(value) = value
                    {
                        pending.push(Stored {
                            offset,
                            width: *width,
                            value: *value,
                            first_call: calls.len(),
                        });
                    }
                }
                Stmt::Call {
                    target: Some(target),
                    kind: crate::ir::CallKind::Invoke,
                    ..
                } => {
                    // Prove preservation only if a later load needs a stored value.
                    if !pending.is_empty() {
                        calls.push(*target);
                    }
                }
                Stmt::Assign { .. }
                | Stmt::Brif { .. }
                | Stmt::Br { .. }
                | Stmt::Ret { .. }
                | Stmt::Switch { .. } => {}
                _ => pending.clear(),
            }
        }
    }
    if changed {
        crate::passes::simplify::simplify(&mut normalized);
        *ir = normalized;
    }
}

fn replace(
    expr: &mut Expr,
    sp: u16,
    pending: &mut Vec<Stored>,
    preserved: &mut impl FnMut(usize) -> Option<usize>,
) -> bool {
    let mut changed = false;
    for child in crate::ir::visit::children_mut(expr) {
        changed |= replace(child, sp, pending, preserved);
    }
    if let Expr::Load {
        addr,
        width,
        signed,
    } = expr
        && let Some(offset) = frame_slot(addr, 0, sp)
        && let Some(position) = pending
            .iter()
            .position(|stored| stored.offset == offset && stored.width == *width)
    {
        let Some(first_call) = preserved(pending[position].first_call) else {
            pending.remove(position);
            return changed;
        };
        let stored = &mut pending[position];
        stored.first_call = first_call;
        let bits = u32::from(*width).saturating_mul(8);
        let value = stored.value & crate::ir::semantics::mask(bits);
        *expr = Expr::Const(if *signed {
            crate::ir::semantics::sign_extend(value, bits) as u64
        } else {
            value
        });
        return true;
    }
    changed
}

fn writes_only_frame(image: &Image, address: u64) -> bool {
    let Some(function) = image.functions.get(&address) else {
        return false;
    };
    if function.size.is_none() {
        return false;
    }
    let mut ir = match super::lift_function(image, function) {
        Ok(lifted) => lifted.ir,
        Err(_) => return false,
    };
    let sp = crate::arch::stack_pointer(image.isa);
    crate::passes::frame_slots::settle(&mut ir);
    if !closed(&ir.blocks) {
        return false;
    }
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        match stmt {
            Stmt::Store { addr, width, .. } => {
                if frame_slot(addr, 0, sp).is_none_or(|offset| {
                    offset
                        .checked_add(i64::from(*width))
                        .is_none_or(|end| end > 0)
                }) {
                    return false;
                }
            }
            Stmt::Assign { dest, .. } if dest.index != sp => {}
            Stmt::Brif { .. } | Stmt::Br { target: Some(_) } | Stmt::Ret { .. } => {}
            _ => return false,
        }
    }
    true
}

fn closed(blocks: &[Block]) -> bool {
    if blocks.is_empty() {
        return false;
    }
    for (index, block) in blocks.iter().enumerate() {
        let target_exists = |target| blocks.iter().any(|block| block.start == target);
        let closed = match block.stmts.last() {
            Some(Stmt::Ret { .. }) => true,
            Some(
                Stmt::Br { target: None }
                | Stmt::BrIndirect { .. }
                | Stmt::Switch { .. }
                | Stmt::BrifFlags { .. },
            ) => false,
            Some(Stmt::Br {
                target: Some(target),
            }) => target_exists(*target),
            Some(Stmt::Brif { target, .. }) => target_exists(*target) && index + 1 < blocks.len(),
            _ => index + 1 < blocks.len(),
        };
        if !closed {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_only_callees_require_closed_control_flow() {
        let mut blocks = vec![Block {
            start: 16,
            stmts: Vec::new(),
        }];
        assert!(!closed(&blocks));
        blocks[0].stmts.push(Stmt::Br { target: Some(32) });
        assert!(!closed(&blocks));
        blocks.push(Block {
            start: 32,
            stmts: vec![Stmt::Ret {
                value: Expr::Const(0),
            }],
        });
        assert!(closed(&blocks));
        blocks[1].stmts = vec![Stmt::Brif {
            cond: crate::ir::Cond::Eq,
            lhs: Expr::Const(0),
            rhs: Expr::Const(0),
            target: 16,
        }];
        assert!(!closed(&blocks));
    }
}

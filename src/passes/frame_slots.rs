use crate::arch::stack_pointer;
use std::collections::HashMap;

use crate::ir::{BinOp, Expr, FunctionIr, Stmt};
use crate::passes::{copies, frame};

/// Rewrites every stack access against the entry frame and drops the
/// adjustments, when the stack pointer is only ever a frame base.
pub fn settle(ir: &mut FunctionIr) {
    let frames = block_frames(ir, stack_pointer(ir.isa));
    if substitute_frame_pointer(ir, &frames) {
        crate::passes::simplify::simplify(ir);
        frame::elide_callee_saves(ir);
    }
    let frames = block_frames(ir, stack_pointer(ir.isa));
    if !canonical_frame(ir, &frames) {
        return;
    }
    let escapes = address_escapes(ir, &frames);
    rewrite_frame(ir, &frames);
    // Code that has a slot's address may read or write it unseen.
    if !escapes {
        frame::drop_dead_frame_stores(ir);
        copies::inline_local_copies(ir);
    }
    crate::passes::simplify::simplify(ir);
}

/// Whether a frame slot's address is used as a value, beyond the address of
/// a load or store, so the code may reach the slot through a pointer.
fn address_escapes(ir: &FunctionIr, frames: &[Option<i64>]) -> bool {
    let sp = stack_pointer(ir.isa);
    fn escapes(expr: &Expr, frame: i64, sp: u16) -> bool {
        if frame_slot(expr, frame, sp).is_some() {
            return true;
        }
        match expr {
            Expr::Load { addr, .. } if frame_slot(addr, frame, sp).is_some() => false,
            _ => crate::ir::visit::children(expr)
                .into_iter()
                .any(|child| escapes(child, frame, sp)),
        }
    }
    for (position, block) in ir.blocks.iter().enumerate() {
        let Some(mut frame) = frames[position] else {
            continue;
        };
        for stmt in &block.stmts {
            if let Stmt::Assign { dest, value } = stmt
                && dest.index == sp
            {
                frame = adjusted(frame, value, sp);
                continue;
            }
            let operands: Vec<&Expr> = match stmt {
                // The address a store writes is no escape; what it stores may be.
                Stmt::Store { addr, value, .. } => {
                    if frame_slot(addr, frame, sp).is_some() {
                        vec![value]
                    } else {
                        vec![addr, value]
                    }
                }
                other => other.operands(),
            };
            if operands.into_iter().any(|expr| escapes(expr, frame, sp)) {
                return true;
            }
        }
    }
    false
}

/// Rewrites the reads of a frame pointer that the entry block sets once from
/// the stack pointer as the stack addresses they are, so the frame settles
/// like one addressed through the stack pointer. Other writes may only
/// restore the caller's value on the way out. Returns whether it rewrote.
fn substitute_frame_pointer(ir: &mut FunctionIr, frames: &[Option<i64>]) -> bool {
    let sp = stack_pointer(ir.isa);
    let fp = crate::arch::frame_pointer(ir.isa);
    // The setup, its block, and the entry-frame offset it gives the frame
    // pointer: in the entry block, or later where the prologue waits past
    // an early return.
    let mut setup = None;
    'find: for (index, block) in ir.blocks.iter().enumerate() {
        let Some(mut frame) = frames[index] else {
            continue;
        };
        for (position, stmt) in block.stmts.iter().enumerate() {
            match stmt {
                Stmt::Assign { dest, value } if dest.index == fp => {
                    if let Some(base) = frame_slot(value, frame, sp) {
                        setup = Some((index, position, base));
                        break 'find;
                    }
                }
                Stmt::Assign { dest, value } if dest.index == sp => {
                    frame = adjusted(frame, value, sp);
                }
                _ => {}
            }
        }
    }
    let Some((setup_block, setup_at, base)) = setup else {
        return false;
    };
    // The frame pointer means the frame only in the blocks the setup
    // dominates; elsewhere it still holds the caller's.
    let successors: Vec<Vec<usize>> = (0..ir.blocks.len())
        .map(|index| crate::ir::cfg::block_successors(&ir.blocks, index))
        .collect();
    let idom = crate::ssa::dom::dominators(&successors).idom;
    // A landing pad holds the frame pointer of the call that unwinds into
    // it, which the unwinder restores as it does every register the callee
    // saves: it is the frame where that call's block is.
    let starts: HashMap<u64, usize> = ir
        .blocks
        .iter()
        .enumerate()
        .map(|(position, block)| (block.start, position))
        .collect();
    let caller_of: HashMap<usize, usize> = ir
        .landing_pads
        .iter()
        .filter_map(|(pad, sites)| {
            let (site, _) = sites.first()?;
            let holder = ir
                .blocks
                .iter()
                .enumerate()
                .filter(|(_, block)| block.start <= *site)
                .max_by_key(|(_, block)| block.start)?
                .0;
            Some((*starts.get(pad)?, holder))
        })
        .collect();
    let count = ir.blocks.len();
    let dominated = |mut block: usize| {
        for _ in 0..=count {
            if block == setup_block {
                return true;
            }
            match idom[block] {
                Some(parent) if parent != block => block = parent,
                _ => match caller_of.get(&block) {
                    Some(caller) if *caller != block => block = *caller,
                    _ => return false,
                },
            }
        }
        false
    };
    // Any other write restores the caller's frame pointer before a return.
    for (index, block) in ir.blocks.iter().enumerate() {
        for (position, stmt) in block.stmts.iter().enumerate() {
            if (index, position) == (setup_block, setup_at)
                || !crate::ir::visit::statement_registers(stmt).0.contains(&fp)
            {
                continue;
            }
            let restores = matches!(
                stmt,
                Stmt::Assign {
                    value: Expr::Load { .. },
                    ..
                }
            ) && matches!(block.stmts.last(), Some(Stmt::Ret { .. }))
                && block.stmts[position + 1..]
                    .iter()
                    .all(|later| !crate::ir::visit::statement_reads(later).contains(&fp));
            if !restores {
                return false;
            }
        }
    }
    if (0..ir.blocks.len()).any(|index| dominated(index) && frames[index].is_none()) {
        return false;
    }
    for (index, block) in ir.blocks.iter_mut().enumerate() {
        if !dominated(index) {
            continue;
        }
        let Some(mut frame) = frames[index] else {
            return false;
        };
        for (position, stmt) in block.stmts.iter_mut().enumerate() {
            // The save before the setup reads the caller's frame pointer.
            if index != setup_block || position > setup_at {
                let address = Expr::bin(
                    BinOp::Add,
                    Expr::reg(sp, 64),
                    Expr::Const(base.wrapping_sub(frame) as u64),
                );
                crate::ir::visit::replace_reads(stmt, &[(fp, address)]);
            }
            if let Stmt::Assign { dest, value } = stmt
                && dest.index == sp
            {
                frame = adjusted(frame, value, sp);
            }
        }
    }
    ir.blocks[setup_block].stmts.remove(setup_at);
    true
}

/// The frame displacement after `sp = value`.
fn adjusted(frame: i64, value: &Expr, sp: u16) -> i64 {
    match value {
        Expr::Bin { op, lhs, rhs } if matches!(lhs.as_ref(), Expr::Reg { index, .. } if *index == sp) => {
            match (op, rhs.as_ref()) {
                (BinOp::Add, Expr::Const(delta)) => frame.wrapping_add(*delta as i64),
                (BinOp::Sub, Expr::Const(delta)) => frame.wrapping_sub(*delta as i64),
                _ => frame,
            }
        }
        _ => frame,
    }
}

/// True when every block has a known frame and the stack pointer is used only
/// as a frame-slot address and written only by adjustments.
pub(crate) fn canonical_frame(ir: &FunctionIr, frames: &[Option<i64>]) -> bool {
    let sp = stack_pointer(ir.isa);
    for (position, block) in ir.blocks.iter().enumerate() {
        let Some(frame) = frames[position] else {
            // Code no path reaches, such as padding, may stay as it is
            // unless it uses the stack pointer.
            let uses_sp = block.stmts.iter().any(|stmt| {
                let (writes, reads) = crate::ir::visit::statement_registers(stmt);
                writes.contains(&sp) || reads.contains(&sp)
            });
            if uses_sp {
                return false;
            }
            continue;
        };
        for stmt in &block.stmts {
            match stmt {
                // A store through any other pointer leaves the frame alone.
                Stmt::Store { addr, value, .. } => {
                    if !frame_only(addr, frame, sp) || !frame_only(value, frame, sp) {
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
                Stmt::Call { through, args, .. }
                    if through
                        .iter()
                        .chain(args.iter().flatten())
                        .any(|expr| !frame_only(expr, frame, sp)) =>
                {
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
    // A slot's address, such as a local array's, settles like its loads.
    if frame_slot(expr, frame, sp).is_some() {
        return true;
    }
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
        Expr::Apply { args, .. } => args.iter().all(|arg| frame_only(arg, frame, sp)),
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
                    // Either a slot, or an address whose parts read slots.
                    rewrite_expr_frame(addr, frame, sp);
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
                | Stmt::Ret { value } => rewrite_expr_frame(value, frame, sp),
                Stmt::Call { through, args, .. } => {
                    for value in through.iter_mut().chain(args.iter_mut().flatten()) {
                        rewrite_expr_frame(value, frame, sp);
                    }
                }
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
    if !matches!(expr, Expr::Load { .. })
        && let Some(slot) = frame_slot(expr, frame, sp)
    {
        *expr = frame_address(sp, slot);
        return;
    }
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
        Expr::Apply { args, .. } => {
            for arg in args {
                rewrite_expr_frame(arg, frame, sp);
            }
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
        Expr::Bin {
            op: BinOp::Sub,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Reg { index, .. }, Expr::Const(delta)) if *index == sp => {
                Some(frame.wrapping_sub(*delta as i64))
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
    // A landing pad starts in the frame of the calls that unwind into it:
    // that of the block holding the first of them.
    let pads: Vec<(usize, usize)> = ir
        .landing_pads
        .iter()
        .filter_map(|(pad, sites)| {
            let pad = *index.get(pad)?;
            let (site, _) = sites.first()?;
            let holder = ir
                .blocks
                .iter()
                .enumerate()
                .filter(|(_, block)| block.start <= *site)
                .max_by_key(|(_, block)| block.start)?
                .0;
            Some((pad, holder))
        })
        .collect();
    for _ in 0..ir.blocks.len().max(1) * 4 {
        let mut changed = false;
        for (pad, holder) in &pads {
            if frames[*pad].is_none()
                && let Some(frame) = frames[*holder]
            {
                frames[*pad] = Some(frame);
                changed = true;
            }
        }
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
                Some(Stmt::Ret { .. }) | Some(Stmt::BrIndirect { .. }) | Some(Stmt::Trap) => {}
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

#[cfg(test)]
mod tests {
    use super::settle;
    use crate::ir::{BinOp, Expr, FunctionIr, RegRef, Stmt};
    use crate::loader::Isa;

    #[test]
    fn a_frame_with_stores_through_pointers_settles() {
        const RSP: u16 = 4;
        let at =
            |offset: i64| Expr::bin(BinOp::Add, Expr::reg(RSP, 64), Expr::Const(offset as u64));
        let load = |offset: i64| Expr::Load {
            addr: Box::new(at(offset)),
            width: 8,
            signed: false,
        };
        // rsp -= 0x10; [rsp] = rdi; *(uint8_t *)[rsp] = 1; rsp += 0x10; ret
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: RSP,
                        width: 64,
                    },
                    value: at(-0x10),
                },
                Stmt::Store {
                    addr: at(0),
                    value: Expr::reg(7, 64),
                    width: 8,
                },
                Stmt::Store {
                    addr: load(0),
                    value: Expr::Const(1),
                    width: 1,
                },
                Stmt::Assign {
                    dest: RegRef {
                        index: RSP,
                        width: 64,
                    },
                    value: at(0x10),
                },
                Stmt::Ret {
                    value: Expr::reg(0, 64),
                },
            ],
        );
        settle(&mut ir);
        let stmts = &ir.blocks[0].stmts;
        assert!(
            !stmts
                .iter()
                .any(|stmt| matches!(stmt, Stmt::Assign { dest, .. } if dest.index == RSP)),
            "the adjustments go:\n{}",
            ir.render()
        );
        // The pointer's slot reads at its entry-frame offset, where it was stored.
        assert!(
            stmts.iter().any(
                |stmt| matches!(stmt, Stmt::Store { addr: Expr::Load { addr, .. }, .. }
                if **addr == at(-0x10))
            ),
            "{}",
            ir.render()
        );
    }

    #[test]
    fn locals_addressed_through_the_frame_pointer_settle() {
        const RSP: u16 = 4;
        const RBP: u16 = 5;
        let at = |base: u16, offset: i64| {
            Expr::bin(BinOp::Add, Expr::reg(base, 64), Expr::Const(offset as u64))
        };
        let assign = |index, value| Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
        };
        let slot = |offset| Expr::Load {
            addr: Box::new(at(RBP, offset)),
            width: 4,
            signed: false,
        };
        // push rbp; mov rbp, rsp; [rbp-4] = edi; eax = [rbp-4]; pop rbp; ret
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                assign(RSP, at(RSP, -8)),
                Stmt::Store {
                    addr: Expr::reg(RSP, 64),
                    value: Expr::reg(RBP, 64),
                    width: 8,
                },
                assign(RBP, Expr::reg(RSP, 64)),
                Stmt::Store {
                    addr: at(RBP, -4),
                    value: Expr::reg(7, 32),
                    width: 4,
                },
                assign(0, slot(-4)),
                assign(
                    RBP,
                    Expr::Load {
                        addr: Box::new(Expr::reg(RSP, 64)),
                        width: 8,
                        signed: false,
                    },
                ),
                assign(RSP, at(RSP, 8)),
                Stmt::Ret {
                    value: Expr::reg(0, 64),
                },
            ],
        );

        settle(&mut ir);

        let reads_rbp = ir.blocks[0]
            .stmts
            .iter()
            .any(|stmt| crate::ir::visit::statement_registers(stmt).1.contains(&RBP));
        assert!(!reads_rbp, "{}", ir.render());
    }

    #[test]
    fn a_landing_pad_reads_its_call_sites_frame_through_the_frame_pointer() {
        const RSP: u16 = 4;
        const RBP: u16 = 5;
        let at = |base: u16, offset: i64| {
            Expr::bin(BinOp::Add, Expr::reg(base, 64), Expr::Const(offset as u64))
        };
        let assign = |index, value| Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
        };
        let call = Stmt::Call {
            target: Some(0x1000),
            through: None,
            convention: crate::ir::Convention::SysV,
            args: Some(Vec::new()),
            floats_named: false,
            result: None,
            clobbers: None,
            via: None,
        };
        // push rbp; mov rbp, rsp; [rbp-8] = edi; call f; ... ret, and a pad
        // at 0x40 for the call that reads [rbp-8].
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                assign(RSP, at(RSP, -8)),
                Stmt::Store {
                    addr: Expr::reg(RSP, 64),
                    value: Expr::reg(RBP, 64),
                    width: 8,
                },
                assign(RBP, Expr::reg(RSP, 64)),
                assign(RSP, at(RSP, -0x10)),
                Stmt::Store {
                    addr: at(RBP, -8),
                    value: Expr::reg(7, 64),
                    width: 8,
                },
                call,
                assign(RSP, at(RSP, 0x10)),
                assign(
                    RBP,
                    Expr::Load {
                        addr: Box::new(Expr::reg(RSP, 64)),
                        width: 8,
                        signed: false,
                    },
                ),
                assign(RSP, at(RSP, 8)),
                Stmt::Ret {
                    value: Expr::Const(0),
                },
            ],
        );
        ir.blocks.push(crate::ir::Block {
            start: 0x40,
            stmts: vec![Stmt::Ret {
                value: Expr::Load {
                    addr: Box::new(at(RBP, -8)),
                    width: 8,
                    signed: false,
                },
            }],
        });
        ir.landing_pads = vec![(0x40, vec![(0x0, 0x10)])];

        settle(&mut ir);

        let reads_rbp = ir.blocks[1]
            .stmts
            .iter()
            .any(|stmt| crate::ir::visit::statement_registers(stmt).1.contains(&RBP));
        assert!(!reads_rbp, "{}", ir.render());
    }
}

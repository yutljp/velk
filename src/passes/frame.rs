use crate::arch::{aarch64, stack_pointer, x86};
use std::collections::HashMap;

use crate::ir::visit::statement_registers;
use crate::ir::{Expr, FunctionIr, Stmt};

/// Removes stores to frame slots that nothing reads. Does nothing when any
/// frame address escapes.
pub fn drop_dead_frame_stores(ir: &mut FunctionIr) {
    let sp = stack_pointer(ir.isa);
    // Every frame-slot address the body names, and whether one escapes.
    let mut read: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut escaped = false;
    let mut stores: Vec<(usize, usize, u64)> = Vec::new();
    for (position, block) in ir.blocks.iter().enumerate() {
        for (index, stmt) in block.stmts.iter().enumerate() {
            match stmt {
                Stmt::Store { addr, value, .. } => {
                    if let Some(slot) = frame_slot_of(addr, sp) {
                        stores.push((position, index, slot));
                    } else if address_uses_frame(addr, sp) {
                        escaped = true;
                    }
                    collect_frame_reads(value, sp, &mut read);
                    if address_uses_frame(value, sp) {
                        escaped = true;
                    }
                }
                Stmt::Assign { dest, value } => {
                    // Adjusting the stack pointer does not make a frame address escape.
                    if dest.index == sp {
                        continue;
                    }
                    collect_frame_reads(value, sp, &mut read);
                    if let Expr::Load { addr, .. } = value {
                        if frame_slot_of(addr, sp).is_none() && address_uses_frame(addr, sp) {
                            escaped = true;
                        }
                    } else if address_uses_frame(value, sp) {
                        escaped = true;
                    }
                }
                Stmt::Ret { value } => {
                    collect_frame_reads(value, sp, &mut read);
                    if address_uses_frame(value, sp) {
                        escaped = true;
                    }
                }
                Stmt::Brif { lhs, rhs, .. } => {
                    collect_frame_reads(lhs, sp, &mut read);
                    collect_frame_reads(rhs, sp, &mut read);
                    if address_uses_frame(lhs, sp) || address_uses_frame(rhs, sp) {
                        escaped = true;
                    }
                }
                _ => {}
            }
        }
    }
    // An escaped frame address may be read through elsewhere, e.g. by a callee.
    if escaped {
        return;
    }
    let dead: std::collections::HashSet<(usize, usize)> = stores
        .into_iter()
        .filter(|(_, _, slot)| !read.contains(slot))
        .map(|(position, index, _)| (position, index))
        .collect();
    if dead.is_empty() {
        return;
    }
    for (position, block) in ir.blocks.iter_mut().enumerate() {
        let mut index = 0;
        block.stmts.retain(|_| {
            let keep = !dead.contains(&(position, index));
            index += 1;
            keep
        });
    }
}

/// The offset `k` of an address that is exactly `sp + k`.
fn frame_slot_of(addr: &Expr, sp: u16) -> Option<u64> {
    match addr {
        Expr::Reg { index, .. } if *index == sp => Some(0),
        Expr::Bin {
            op: crate::ir::BinOp::Add,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Reg { index, .. }, Expr::Const(delta)) if *index == sp => Some(*delta),
            (Expr::Const(delta), Expr::Reg { index, .. }) if *index == sp => Some(*delta),
            _ => None,
        },
        _ => None,
    }
}

fn collect_frame_reads(expr: &Expr, sp: u16, read: &mut std::collections::HashSet<u64>) {
    match expr {
        Expr::Load { addr, .. } => match frame_slot_of(addr, sp) {
            Some(slot) => {
                read.insert(slot);
            }
            None => collect_frame_reads(addr, sp, read),
        },
        Expr::Bin { lhs, rhs, .. } => {
            collect_frame_reads(lhs, sp, read);
            collect_frame_reads(rhs, sp, read);
        }
        Expr::SignExtend { value, .. } => collect_frame_reads(value, sp, read),
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => {
            collect_frame_reads(lhs, sp, read);
            collect_frame_reads(rhs, sp, read);
            collect_frame_reads(then, sp, read);
            collect_frame_reads(els, sp, read);
        }
        Expr::Reg { .. } | Expr::Const(_) => {}
    }
}

/// True when the expression computes a stack address other than a plain slot
/// access; such a value may reach a callee.
fn address_uses_frame(expr: &Expr, sp: u16) -> bool {
    match expr {
        Expr::Reg { index, .. } => *index == sp,
        // A load through a slot is a local read; any other load still carries
        // the address it computed.
        Expr::Load { addr, .. } => {
            frame_slot_of(addr, sp).is_none() && address_uses_frame(addr, sp)
        }
        Expr::Bin { lhs, rhs, .. } => address_uses_frame(lhs, sp) || address_uses_frame(rhs, sp),
        Expr::SignExtend { value, .. } => address_uses_frame(value, sp),
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => {
            address_uses_frame(lhs, sp)
                || address_uses_frame(rhs, sp)
                || address_uses_frame(then, sp)
                || address_uses_frame(els, sp)
        }
        Expr::Const(_) => false,
    }
}

/// Removes callee-saved register spills (a register stored to a slot and
/// reloaded from it, untouched in between), plus the stack adjustments when
/// the stack has no other use.
///
/// The frame displacement is tracked in layout order so the save and the
/// restore resolve to the same slot across blocks and stack adjustments.
pub fn elide_callee_saves(ir: &mut FunctionIr) {
    let sp = stack_pointer(ir.isa);
    struct Access {
        block: usize,
        position: usize,
        slot: i64,
        store: bool,
        reg: u16,
    }
    let mut accesses: Vec<Access> = Vec::new();
    let mut frame: i64 = 0;
    for (block_index, block) in ir.blocks.iter().enumerate() {
        for (position, stmt) in block.stmts.iter().enumerate() {
            match stmt {
                Stmt::Store { addr, value, .. } => {
                    let slot = stack_slot(addr, frame, sp);
                    if let (Some(slot), Expr::Reg { index, .. }) = (slot, value) {
                        accesses.push(Access {
                            block: block_index,
                            position,
                            slot,
                            store: true,
                            reg: *index,
                        });
                    }
                }
                Stmt::Assign { dest, value } => {
                    if let Expr::Load { addr, .. } = value
                        && let Some(slot) = stack_slot(addr, frame, sp)
                    {
                        accesses.push(Access {
                            block: block_index,
                            position,
                            slot,
                            store: false,
                            reg: dest.index,
                        });
                    }
                    if dest.index == sp
                        && let Some(delta) = stack_delta(value, sp)
                    {
                        frame = frame.wrapping_add(delta);
                    }
                }
                _ => {}
            }
        }
        // A conditional exit may reach a block whose frame differs.
        if matches!(block.stmts.last(), Some(Stmt::Brif { .. })) {
            frame = 0;
        }
    }
    // Each slot must be written once and read once, round-tripping the same
    // register, with that register untouched in between.
    let mut by_slot: HashMap<i64, Vec<usize>> = HashMap::new();
    for (index, access) in accesses.iter().enumerate() {
        by_slot.entry(access.slot).or_default().push(index);
    }
    let mut drop: std::collections::HashSet<(usize, usize)> = std::collections::HashSet::new();
    for list in by_slot.values() {
        if list.len() != 2 {
            continue;
        }
        let (first, second) = (&accesses[list[0]], &accesses[list[1]]);
        if !first.store || second.store || first.reg != second.reg || first.reg == sp {
            continue;
        }
        let mut borrowed = false;
        let mut frame_setup: Option<(usize, usize)> = None;
        'scan: for block_index in first.block..=second.block {
            let block = &ir.blocks[block_index];
            let start = if block_index == first.block {
                first.position + 1
            } else {
                0
            };
            let end = if block_index == second.block {
                second.position
            } else {
                block.stmts.len()
            };
            for position in start..end {
                let (writes, reads) = statement_registers(&block.stmts[position]);
                if reads.contains(&first.reg) {
                    borrowed = true;
                    break 'scan;
                }
                if writes.contains(&first.reg) {
                    // `mov fp, sp` is the frame setup, not a use of the
                    // register the prologue saved.
                    if is_frame_setup(&block.stmts[position], sp) {
                        frame_setup = Some((block_index, position));
                        continue;
                    }
                    borrowed = true;
                    break 'scan;
                }
            }
        }
        if borrowed {
            continue;
        }
        drop.insert((first.block, first.position));
        drop.insert((second.block, second.position));
        if let Some(position) = frame_setup {
            drop.insert(position);
        }
    }
    if drop.is_empty() {
        return;
    }
    // A frame that only held the spills can go too.
    let stack_still_used = ir.blocks.iter().enumerate().any(|(block_index, block)| {
        block.stmts.iter().enumerate().any(|(position, stmt)| {
            if drop.contains(&(block_index, position)) {
                return false;
            }
            let (writes, reads) = statement_registers(stmt);
            let touched = reads.contains(&sp) || writes.contains(&sp);
            if !touched {
                return false;
            }
            !matches!(
                stmt,
                Stmt::Assign { dest, value } if dest.index == sp && stack_delta(value, sp).is_some()
            )
        })
    });
    if !stack_still_used {
        for (block_index, block) in ir.blocks.iter().enumerate() {
            for (position, stmt) in block.stmts.iter().enumerate() {
                if let Stmt::Assign { dest, value } = stmt
                    && dest.index == sp
                    && stack_delta(value, sp).is_some()
                {
                    drop.insert((block_index, position));
                }
            }
        }
    }
    for (block_index, block) in ir.blocks.iter_mut().enumerate() {
        let mut keep = vec![true; block.stmts.len()];
        for (position, slot) in keep.iter_mut().enumerate() {
            if drop.contains(&(block_index, position)) {
                *slot = false;
            }
        }
        let kept: Vec<Stmt> = block
            .stmts
            .drain(..)
            .zip(keep)
            .filter_map(|(stmt, keep)| keep.then_some(stmt))
            .collect();
        block.stmts = kept;
    }
}

/// `fp = sp` or `fp = sp + k`: the frame pointer setup in a frame-pointer
/// prologue.
fn is_frame_setup(stmt: &Stmt, sp: u16) -> bool {
    let Stmt::Assign { value, .. } = stmt else {
        return false;
    };
    match value {
        Expr::Reg { index, .. } => *index == sp,
        _ => stack_slot(value, 0, sp).is_some(),
    }
}

/// Removes an x86 `push rbp; mov rbp, rsp` prologue and `pop rbp` epilogue
/// in the same block when nothing between them reads the frame pointer or
/// the stack pointer.
pub fn elide_frame_pointer(ir: &mut FunctionIr) {
    for block in &mut ir.blocks {
        elide_frame_pointer_block(block);
    }
}

fn elide_frame_pointer_block(block: &mut crate::ir::Block) {
    let Some((prologue, frame)) = frame_prologue(&block.stmts) else {
        return;
    };
    let Some(epilogue) = frame_epilogue(&block.stmts, frame) else {
        return;
    };
    for position in prologue.end..epilogue.start {
        let (writes, reads) = statement_registers(&block.stmts[position]);
        let _ = writes;
        if reads.contains(&frame) || reads.contains(&x86::RSP) {
            return;
        }
    }
    // Remove the epilogue first so the prologue's indices stay valid.
    block.stmts.drain(epilogue.start..epilogue.end);
    block.stmts.drain(prologue.start..prologue.end);
}

/// The slot of an exact `sp + k` or `sp - k` address, offset by the current
/// frame displacement.
fn stack_slot(expr: &Expr, frame: i64, sp: u16) -> Option<i64> {
    let add = |offset: i64| Some(frame.wrapping_add(offset));
    match expr {
        Expr::Reg { index, .. } if *index == sp => Some(frame),
        Expr::Bin {
            op: crate::ir::BinOp::Add,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Reg { index, .. }, Expr::Const(delta)) if *index == sp => add(*delta as i64),
            (Expr::Const(delta), Expr::Reg { index, .. }) if *index == sp => add(*delta as i64),
            _ => None,
        },
        Expr::Bin {
            op: crate::ir::BinOp::Sub,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Reg { index, .. }, Expr::Const(delta)) if *index == sp => add(-(*delta as i64)),
            _ => None,
        },
        _ => None,
    }
}

/// Reads `sp + k` / `sp - k` as a signed stack delta.
fn stack_delta(value: &Expr, sp: u16) -> Option<i64> {
    let Expr::Bin { op, lhs, rhs } = value else {
        return None;
    };
    if !matches!(lhs.as_ref(), Expr::Reg { index, .. } if *index == sp) {
        return None;
    }
    let Expr::Const(delta) = rhs.as_ref() else {
        return None;
    };
    let delta = *delta as i64;
    match op {
        crate::ir::BinOp::Add => Some(delta),
        crate::ir::BinOp::Sub => Some(-delta),
        _ => None,
    }
}

/// Matches `rsp -= 8; *(u64 *)rsp = rbp; rbp = rsp` at the block's head and
/// returns its range and the frame pointer register.
fn frame_prologue(stmts: &[Stmt]) -> Option<(std::ops::Range<usize>, u16)> {
    let Stmt::Assign { dest: sp, value } = stmts.first()? else {
        return None;
    };
    if sp.index != x86::RSP {
        return None;
    }
    if stack_delta(value, x86::RSP)? != -(8i64) {
        return None;
    }
    let Stmt::Store {
        addr, value: saved, ..
    } = stmts.get(1)?
    else {
        return None;
    };
    if !matches!(addr, Expr::Reg { index, .. } if *index == x86::RSP) {
        return None;
    }
    let Expr::Reg { index: frame, .. } = saved else {
        return None;
    };
    let Stmt::Assign {
        dest: next,
        value: source,
    } = stmts.get(2)?
    else {
        return None;
    };
    if next.index != *frame || !matches!(source, Expr::Reg { index, .. } if *index == x86::RSP) {
        return None;
    }
    Some((0..3, *frame))
}

/// Matches `rsp += 8; rbp = *(u64 *)rsp` at the block's tail, restoring the
/// same frame pointer register, and returns its range.
fn frame_epilogue(stmts: &[Stmt], frame: u16) -> Option<std::ops::Range<usize>> {
    // The pair may sit just before a trailing `Ret`.
    let mut len = stmts.len();
    if matches!(stmts.get(len.saturating_sub(1)), Some(Stmt::Ret { .. })) {
        len -= 1;
    }
    if len < 2 {
        return None;
    }
    let Stmt::Assign { dest: sp, value } = &stmts[len - 2] else {
        return None;
    };
    if sp.index != x86::RSP {
        return None;
    }
    if stack_delta(value, x86::RSP)? != 8 {
        return None;
    }
    let Stmt::Assign {
        dest: restored,
        value,
    } = &stmts[len - 1]
    else {
        return None;
    };
    if restored.index != frame {
        return None;
    }
    let Expr::Load { addr, .. } = value else {
        return None;
    };
    if !matches!(addr.as_ref(), Expr::Reg { index, .. } if *index == x86::RSP) {
        return None;
    }
    Some(len - 2..len)
}

/// True when the expression loads through a non-stack address, which may be
/// volatile; stack accesses are ordinary locals.
pub(crate) fn reads_outside_frame(expr: &Expr) -> bool {
    match expr {
        Expr::Load { addr, .. } => !address_uses_stack(addr) || reads_outside_frame(addr),
        Expr::Bin { lhs, rhs, .. } => reads_outside_frame(lhs) || reads_outside_frame(rhs),
        Expr::SignExtend { value, .. } => reads_outside_frame(value),
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => {
            reads_outside_frame(lhs)
                || reads_outside_frame(rhs)
                || reads_outside_frame(then)
                || reads_outside_frame(els)
        }
        _ => false,
    }
}

fn address_uses_stack(expr: &Expr) -> bool {
    match expr {
        Expr::Reg { index, .. } => *index == x86::RSP || *index == aarch64::SP,
        Expr::Bin { lhs, rhs, .. } => address_uses_stack(lhs) || address_uses_stack(rhs),
        Expr::SignExtend { value, .. } => address_uses_stack(value),
        _ => false,
    }
}

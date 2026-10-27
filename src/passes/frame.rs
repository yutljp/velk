use crate::arch::{aarch64, stack_pointer, x86};
use std::collections::HashMap;

use crate::ir::visit::statement_registers;
use crate::ir::{Expr, FunctionIr, Stmt};

/// Removes stores to frame slots that nothing reads. Does nothing when any
/// frame address escapes.
pub fn drop_dead_frame_stores(ir: &mut FunctionIr) {
    let sp = stack_pointer(ir.isa);
    // Every frame-slot range the body reads, and whether a frame address escapes.
    let mut read: Vec<(u64, u8)> = Vec::new();
    let mut escaped = false;
    let mut stores: Vec<(usize, usize, u64, u8)> = Vec::new();
    for (position, block) in ir.blocks.iter().enumerate() {
        for (index, stmt) in block.stmts.iter().enumerate() {
            // A declared call may read any frame slot through memory.
            if stmt.has_deferred_call_memory() {
                return;
            }
            match stmt {
                Stmt::Store { addr, value, width } => {
                    if let Some(slot) = frame_slot_of(addr, sp) {
                        stores.push((position, index, slot, *width));
                    } else {
                        // The address may be computed from slots it loads.
                        collect_frame_reads(addr, sp, &mut read);
                        if address_uses_frame(addr, sp) {
                            escaped = true;
                        }
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
                Stmt::Ret { value: read_value }
                | Stmt::Switch {
                    index: read_value, ..
                }
                | Stmt::BrIndirect { target: read_value } => {
                    collect_frame_reads(read_value, sp, &mut read);
                    if address_uses_frame(read_value, sp) {
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
                // A callee whose arguments are known reads its stack ones
                // through the loads among them; any other may read the
                // frame anywhere.
                Stmt::Call {
                    through,
                    args: Some(args),
                    ..
                } => {
                    for value in through.iter().chain(args) {
                        collect_frame_reads(value, sp, &mut read);
                        if address_uses_frame(value, sp) {
                            escaped = true;
                        }
                    }
                }
                Stmt::Machine { inputs, .. } => {
                    for value in inputs {
                        collect_frame_reads(value, sp, &mut read);
                        if address_uses_frame(value, sp) {
                            escaped = true;
                        }
                    }
                }
                Stmt::Call { .. } => escaped = true,
                _ => {}
            }
        }
    }
    // An escaped frame address may be read through elsewhere, e.g. by a callee.
    if escaped {
        return;
    }
    let overlaps = |slot: u64, width: u8| {
        let (start, end) = (slot as i64, slot as i64 + i64::from(width));
        read.iter().any(|(other, other_width)| {
            let (other_start, other_end) = (*other as i64, *other as i64 + i64::from(*other_width));
            start < other_end && other_start < end
        })
    };
    let dead: std::collections::HashSet<(usize, usize)> = stores
        .into_iter()
        .filter(|(position, index, slot, width)| {
            !overlaps(*slot, *width)
                || overwritten(&ir.blocks[*position].stmts, *index, *slot, *width, sp)
        })
        .map(|(position, index, _, _)| (position, index))
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

/// True when later stores in the block cover every byte of the store at
/// `index` before anything reads them.
fn overwritten(stmts: &[Stmt], index: usize, slot: u64, width: u8, sp: u16) -> bool {
    let start = slot as i64;
    let end = start + i64::from(width);
    let mut covered = vec![false; usize::from(width)];
    for stmt in &stmts[index + 1..] {
        let mut read = Vec::new();
        match stmt {
            Stmt::Store { addr, value, width } => {
                collect_frame_reads(addr, sp, &mut read);
                collect_frame_reads(value, sp, &mut read);
                if read.iter().any(|(other, other_width)| {
                    let other = *other as i64;
                    other < end && start < other + i64::from(*other_width)
                }) {
                    return false;
                }
                if let Some(other) = frame_slot_of(addr, sp) {
                    let other = other as i64;
                    for byte in other.max(start)..(other + i64::from(*width)).min(end) {
                        covered[(byte - start) as usize] = true;
                    }
                    if covered.iter().all(|byte| *byte) {
                        return true;
                    }
                }
            }
            Stmt::Assign { dest, value } => {
                if dest.index == sp {
                    return false;
                }
                collect_frame_reads(value, sp, &mut read);
                if read.iter().any(|(other, other_width)| {
                    let other = *other as i64;
                    other < end && start < other + i64::from(*other_width)
                }) {
                    return false;
                }
            }
            _ => return false,
        }
    }
    false
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
        Expr::Bin {
            op: crate::ir::BinOp::Sub,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Reg { index, .. }, Expr::Const(delta)) if *index == sp => {
                Some(delta.wrapping_neg())
            }
            _ => None,
        },
        _ => None,
    }
}

fn collect_frame_reads(expr: &Expr, sp: u16, read: &mut Vec<(u64, u8)>) {
    match expr {
        Expr::Load { addr, width, .. } => match frame_slot_of(addr, sp) {
            Some(slot) => read.push((slot, *width)),
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
        Expr::Apply { args, .. } => {
            for arg in args {
                collect_frame_reads(arg, sp, read);
            }
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
        Expr::Apply { args, .. } => args.iter().any(|arg| address_uses_frame(arg, sp)),
        Expr::Const(_) => false,
    }
}

/// Removes callee-saved register spills (a register stored to a slot and
/// reloaded from it, untouched in between), plus the stack adjustments when
/// the stack has no other use.
///
/// The frame displacement on entry to each block follows the control flow,
/// so the save and the restores resolve to the same slot across blocks and
/// stack adjustments.
pub fn elide_callee_saves(ir: &mut FunctionIr) {
    if ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .any(Stmt::has_deferred_call_memory)
    {
        return;
    }
    let sp = stack_pointer(ir.isa);
    let mut accesses: Vec<Access> = Vec::new();
    let frames = crate::passes::frame_slots::block_entry_frame_offsets(ir, sp);
    for (block_index, block) in ir.blocks.iter().enumerate() {
        // A block whose frame the paths into it disagree on names no slot.
        let Some(mut frame) = frames[block_index] else {
            continue;
        };
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
                            register: *index,
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
                            register: dest.index,
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
    }
    // Each slot must be written once and only read back into the same
    // register, once per return path, with that register untouched between
    // the save and each restore.
    let mut by_slot: HashMap<i64, Vec<usize>> = HashMap::new();
    for (index, access) in accesses.iter().enumerate() {
        by_slot.entry(access.slot).or_default().push(index);
    }
    let mut drop: std::collections::HashSet<(usize, usize)> = std::collections::HashSet::new();
    let mut saved: Vec<i64> = Vec::new();
    for list in by_slot.values() {
        let [save, restores @ ..] = list.as_slice() else {
            continue;
        };
        let first = &accesses[*save];
        if restores.is_empty()
            || !first.store
            || first.register == sp
            || restores.iter().any(|index| {
                let restore = &accesses[*index];
                restore.store || restore.register != first.register
            })
        {
            continue;
        }
        // Nothing else in the function may touch the register, whatever the
        // path: the save and its restores are the register's only uses, apart
        // from a frame pointer setup that nothing reads through.
        let round_trip: Vec<(usize, usize)> = list
            .iter()
            .map(|index| (accesses[*index].block, accesses[*index].position))
            .collect();
        let mut register_used_elsewhere = false;
        let mut frame_setup: Option<(usize, usize)> = None;
        'scan: for (block_index, block) in ir.blocks.iter().enumerate() {
            for (position, stmt) in block.stmts.iter().enumerate() {
                if round_trip.contains(&(block_index, position)) {
                    continue;
                }
                let (writes, reads) = statement_registers(stmt);
                if reads.contains(&first.register) {
                    register_used_elsewhere = true;
                    break 'scan;
                }
                if writes.contains(&first.register) {
                    if frame_setup.is_none() && is_frame_setup(stmt, sp) {
                        frame_setup = Some((block_index, position));
                        continue;
                    }
                    register_used_elsewhere = true;
                    break 'scan;
                }
            }
        }
        if register_used_elsewhere {
            // A callee-saved register the body uses is still only preserved
            // for the caller when the entry saves it and each return restores
            // it: the round trip says nothing about the function itself,
            // unless the body reads the saved value through the frame pointer.
            if callee_saved(ir, first.register, sp)
                && !reads_through_stack_pointer_copy(ir, sp)
                && saves_entry_value(ir, first)
                && restores
                    .iter()
                    .all(|index| restores_on_return(ir, &accesses[*index]))
            {
                drop.insert((first.block, first.position));
                saved.push(first.slot);
                for restore in restores.iter().map(|index| &accesses[*index]) {
                    drop.insert((restore.block, restore.position));
                }
            }
            continue;
        }
        drop.insert((first.block, first.position));
        saved.push(first.slot);
        for restore in restores.iter().map(|index| &accesses[*index]) {
            drop.insert((restore.block, restore.position));
        }
        if let Some(position) = frame_setup {
            drop.insert(position);
        }
    }
    for slot in saved {
        if !ir.saved_slots.contains(&slot) {
            ir.saved_slots.push(slot);
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
        let mut position = 0;
        block.stmts.retain(|_| {
            let keep = !drop.contains(&(block_index, position));
            position += 1;
            keep
        });
    }
}

struct Access {
    block: usize,
    position: usize,
    slot: i64,
    store: bool,
    register: u16,
}

/// Drops the pushes of a scratch register the entry block makes before
/// writing it, as `push rax` does to align the stack: the register holds no
/// argument there, and no load reads the slot.
pub fn drop_alignment_pushes(ir: &mut FunctionIr) {
    use crate::ir::Convention;
    if ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .any(Stmt::has_deferred_call_memory)
    {
        return;
    }
    if !matches!(ir.convention, Convention::SysV | Convention::Win64) {
        return;
    }
    let sp = stack_pointer(ir.isa);
    let arguments = ir.convention.arguments();
    let loads_from_frame = ir.blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
        let mut read = Vec::new();
        for operand in stmt.operands() {
            collect_frame_reads(operand, sp, &mut read);
        }
        !read.is_empty()
    });
    if loads_from_frame {
        return;
    }
    let Some(entry) = ir.blocks.first_mut() else {
        return;
    };
    let mut written = std::collections::HashSet::new();
    let mut keep = Vec::with_capacity(entry.stmts.len());
    for stmt in entry.stmts.drain(..) {
        let pushed = matches!(&stmt, Stmt::Store {
                addr,
                value: Expr::Reg { index, width: 64 },
                width: 8,
            } if frame_slot_of(addr, sp).is_some()
                && *index != sp
                && !arguments.contains(index)
                && ir.convention.clobbered().contains(index)
                && !written.contains(index));
        written.extend(crate::ir::visit::statement_registers(&stmt).0);
        if !pushed {
            keep.push(stmt);
        }
    }
    entry.stmts = keep;
}

fn callee_saved(ir: &FunctionIr, reg: u16, sp: u16) -> bool {
    reg != sp && reg < 32 && !ir.convention.clobbered().contains(&reg)
}

/// The save stores the register's value on entry: nothing writes it before
/// the save in its block, nor in any block a path from the entry passes
/// on the way there, as when the prologue waits past an early return.
fn saves_entry_value(ir: &FunctionIr, save: &Access) -> bool {
    let writes = |stmts: &[Stmt]| {
        stmts
            .iter()
            .any(|stmt| statement_registers(stmt).0.contains(&save.register))
    };
    if writes(&ir.blocks[save.block].stmts[..save.position]) {
        return false;
    }
    if save.block == 0 {
        return true;
    }
    // The blocks from which the save's block can be reached.
    let successors: Vec<Vec<usize>> = (0..ir.blocks.len())
        .map(|index| crate::ir::cfg::block_successors(&ir.blocks, index))
        .collect();
    let mut before = std::collections::HashSet::new();
    let mut work = vec![save.block];
    while let Some(block) = work.pop() {
        for (from, next) in successors.iter().enumerate() {
            if next.contains(&block) && before.insert(from) {
                work.push(from);
            }
        }
    }
    !before.contains(&save.block)
        && before.contains(&0)
        && before.iter().all(|block| !writes(&ir.blocks[*block].stmts))
}

/// The restore is the register's last use on the way out of a return.
fn restores_on_return(ir: &FunctionIr, restore: &Access) -> bool {
    let stmts = &ir.blocks[restore.block].stmts;
    matches!(stmts.last(), Some(Stmt::Ret { .. }))
        && stmts[restore.position + 1..].iter().all(|stmt| {
            let (writes, reads) = statement_registers(stmt);
            !writes.contains(&restore.register) && !reads.contains(&restore.register)
        })
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

/// Matches `rbp = *(u64 *)rsp; rsp += 8` at the block's tail, restoring the
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
    let Stmt::Assign { dest: sp, value } = &stmts[len - 1] else {
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
    } = &stmts[len - 2]
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
        Expr::Apply { args, .. } => args.iter().any(reads_outside_frame),
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

/// Whether a register set to the stack pointer is read through as an
/// address: right after a push it addresses the value pushed.
fn reads_through_stack_pointer_copy(ir: &FunctionIr, sp: u16) -> bool {
    let pointers: std::collections::HashSet<u16> = ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .filter_map(|stmt| match stmt {
            Stmt::Assign { dest, value } if dest.index != sp && *value == Expr::reg(sp, 64) => {
                Some(dest.index)
            }
            _ => None,
        })
        .collect();
    fn loads_at(expr: &Expr, pointers: &std::collections::HashSet<u16>) -> bool {
        match expr {
            Expr::Load { addr, .. } if matches!(addr.as_ref(), Expr::Reg { index, .. } if pointers.contains(index)) => {
                true
            }
            _ => crate::ir::visit::children(expr)
                .into_iter()
                .any(|child| loads_at(child, pointers)),
        }
    }
    ir.blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .any(|stmt| match stmt {
            Stmt::Assign { value, .. } | Stmt::Ret { value } => loads_at(value, &pointers),
            Stmt::Store { addr, value, .. } => {
                loads_at(addr, &pointers) || loads_at(value, &pointers)
            }
            Stmt::Brif { lhs, rhs, .. } => loads_at(lhs, &pointers) || loads_at(rhs, &pointers),
            _ => false,
        })
}

#[cfg(test)]
mod tests {
    use super::{drop_dead_frame_stores, elide_callee_saves};
    use crate::ir::{BinOp, Block, Cond, Convention, Expr, FunctionIr, RegRef, Stmt};
    use crate::loader::Isa;

    const RSP: u16 = 4;
    const RBP: u16 = 5;

    fn assign(index: u16, value: Expr) -> Stmt {
        Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
        }
    }

    fn adjust(delta: i64) -> Stmt {
        assign(
            RSP,
            Expr::bin(BinOp::Add, Expr::reg(RSP, 64), Expr::Const(delta as u64)),
        )
    }

    fn restore() -> Vec<Stmt> {
        vec![
            assign(
                RBP,
                Expr::Load {
                    addr: Box::new(Expr::reg(RSP, 64)),
                    width: 8,
                    signed: false,
                },
            ),
            adjust(8),
            Stmt::Ret {
                value: Expr::reg(0, 64),
            },
        ]
    }

    /// `push rbp; mov rbp, rsp; if (rdi == 0) goto other;` returning through
    /// a restore, with `other` at 0x20.
    fn frame_pointer_function(other: Vec<Stmt>) -> FunctionIr {
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                adjust(-8),
                Stmt::Store {
                    addr: Expr::reg(RSP, 64),
                    value: Expr::reg(RBP, 64),
                    width: 8,
                },
                assign(RBP, Expr::reg(RSP, 64)),
                Stmt::Brif {
                    cond: Cond::Eq,
                    lhs: Expr::reg(7, 64),
                    rhs: Expr::Const(0),
                    target: 0x20,
                },
            ],
        );
        ir.blocks.push(Block {
            start: 0x10,
            stmts: restore(),
        });
        ir.blocks.push(Block {
            start: 0x20,
            stmts: other,
        });
        ir
    }

    #[test]
    fn keeps_a_save_the_body_reads_through_the_frame_pointer() {
        // The body reads the pushed rbp back through rbp, then uses rbp.
        let mut ir = frame_pointer_function(vec![
            assign(
                3,
                Expr::Load {
                    addr: Box::new(Expr::reg(RBP, 64)),
                    width: 8,
                    signed: false,
                },
            ),
            assign(RBP, Expr::reg(3, 64)),
            Stmt::Store {
                addr: Expr::Const(0x1000),
                value: Expr::reg(RBP, 64),
                width: 8,
            },
        ]);
        ir.blocks[2].stmts.extend(restore());
        let before = ir.render();
        elide_callee_saves(&mut ir);
        assert_eq!(ir.render(), before);
    }

    #[test]
    fn elides_a_save_restored_on_every_return_path() {
        let mut ir = frame_pointer_function(restore());
        elide_callee_saves(&mut ir);
        let left = ir.blocks.iter().flat_map(|block| &block.stmts).count();
        assert_eq!(
            left,
            3,
            "only the branch and the returns stay:\n{}",
            ir.render()
        );
    }

    #[test]
    fn elides_a_callee_saved_register_the_body_uses() {
        // push rbx; rbx = rdi; call; rax = rbx; pop rbx; return rax;
        const RBX: u16 = 3;
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                adjust(-8),
                Stmt::Store {
                    addr: Expr::reg(RSP, 64),
                    value: Expr::reg(RBX, 64),
                    width: 8,
                },
                assign(RBX, Expr::reg(7, 64)),
                Stmt::Call {
                    kind: crate::ir::CallKind::Invoke,
                    target: Some(0x100),
                    through: None,
                    convention: Convention::SysV,
                    args: None,
                    floats_named: false,
                    abi: None,
                    clobbers: None,
                    outputs: crate::ir::fallback_call_outputs(Convention::SysV, None),
                    via: None,
                },
                assign(0, Expr::reg(RBX, 64)),
                assign(
                    RBX,
                    Expr::Load {
                        addr: Box::new(Expr::reg(RSP, 64)),
                        width: 8,
                        signed: false,
                    },
                ),
                adjust(8),
                Stmt::Ret {
                    value: Expr::reg(0, 64),
                },
            ],
        );

        elide_callee_saves(&mut ir);

        let touches_stack = ir.blocks[0].stmts.iter().any(|stmt| {
            matches!(stmt, Stmt::Store { .. })
                || matches!(
                    stmt,
                    Stmt::Assign {
                        value: Expr::Load { .. },
                        ..
                    }
                )
        });
        assert!(!touches_stack, "{}", ir.render());
    }

    #[test]
    fn keeps_a_spill_a_later_path_clobbers() {
        // *slot = rax; loop: rax = *slot; if (rdi == 0) return; call; goto loop;
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Store {
                    addr: Expr::reg(RSP, 64),
                    value: Expr::reg(0, 64),
                    width: 8,
                },
                Stmt::Br { target: Some(0x10) },
            ],
        );
        ir.blocks.push(Block {
            start: 0x10,
            stmts: vec![
                assign(
                    0,
                    Expr::Load {
                        addr: Box::new(Expr::reg(RSP, 64)),
                        width: 8,
                        signed: false,
                    },
                ),
                Stmt::Brif {
                    cond: Cond::Eq,
                    lhs: Expr::reg(7, 64),
                    rhs: Expr::Const(0),
                    target: 0x30,
                },
            ],
        });
        ir.blocks.push(Block {
            start: 0x18,
            stmts: vec![
                Stmt::Call {
                    kind: crate::ir::CallKind::Invoke,
                    target: Some(0x100),
                    through: None,
                    convention: Convention::SysV,
                    args: None,
                    floats_named: false,
                    abi: None,
                    clobbers: None,
                    outputs: crate::ir::fallback_call_outputs(Convention::SysV, None),
                    via: None,
                },
                Stmt::Br { target: Some(0x10) },
            ],
        });
        ir.blocks.push(Block {
            start: 0x30,
            stmts: vec![Stmt::Ret {
                value: Expr::reg(0, 64),
            }],
        });

        elide_callee_saves(&mut ir);

        assert!(
            matches!(ir.blocks[1].stmts.first(), Some(Stmt::Assign { dest, .. }) if dest.index == 0),
            "the reload after the call stays:\n{}",
            ir.render()
        );
    }

    #[test]
    fn keeps_a_frame_pointer_another_path_reads() {
        // The other path passes a frame address to a call that never returns.
        let mut ir = frame_pointer_function(vec![
            assign(7, Expr::reg(RBP, 64)),
            Stmt::Call {
                kind: crate::ir::CallKind::Invoke,
                target: Some(0x100),
                through: None,
                convention: Convention::SysV,
                args: None,
                floats_named: false,
                abi: None,
                clobbers: None,
                outputs: crate::ir::fallback_call_outputs(Convention::SysV, None),
                via: None,
            },
            Stmt::Trap,
        ]);
        elide_callee_saves(&mut ir);
        assert!(
            ir.blocks[0]
                .stmts
                .iter()
                .any(|stmt| matches!(stmt, Stmt::Assign { dest, .. } if dest.index == RBP)),
            "{}",
            ir.render()
        );
    }

    fn slot(offset: i64) -> Expr {
        Expr::bin(BinOp::Add, Expr::reg(31, 64), Expr::Const(offset as u64))
    }

    fn store(offset: i64, value: Expr, width: u8) -> Stmt {
        Stmt::Store {
            addr: slot(offset),
            value,
            width,
        }
    }

    fn load(offset: i64, width: u8) -> Expr {
        Expr::Load {
            addr: Box::new(slot(offset)),
            width,
            signed: false,
        }
    }

    #[test]
    fn keeps_a_store_a_wider_load_reads() {
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                store(-4, Expr::Const(5), 4),
                Stmt::Ret { value: load(-8, 8) },
            ],
        );
        drop_dead_frame_stores(&mut ir);
        assert_eq!(ir.blocks[0].stmts.len(), 2, "{}", ir.render());
    }

    #[test]
    fn drops_a_store_later_stores_cover() {
        // An 8-byte store both halves of which are written before the read.
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                store(-8, Expr::reg(0, 64), 8),
                store(-8, Expr::Const(1), 4),
                store(-4, Expr::Const(2), 4),
                Stmt::Ret { value: load(-8, 8) },
            ],
        );
        drop_dead_frame_stores(&mut ir);
        assert_eq!(ir.blocks[0].stmts.len(), 3, "{}", ir.render());
    }

    #[test]
    fn keeps_a_store_an_address_reads_back() {
        // [sp-8] = rdi; *(uint8_t *)[sp-8] = 1: the pointer comes from the slot.
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                store(-8, Expr::reg(0, 64), 8),
                Stmt::Store {
                    addr: load(-8, 8),
                    value: Expr::Const(1),
                    width: 1,
                },
                Stmt::Ret {
                    value: Expr::reg(0, 64),
                },
            ],
        );
        drop_dead_frame_stores(&mut ir);
        assert_eq!(ir.blocks[0].stmts.len(), 3, "{}", ir.render());
    }

    #[test]
    fn keeps_a_store_a_callee_may_read() {
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                store(0, Expr::Const(9), 8),
                Stmt::Call {
                    kind: crate::ir::CallKind::Invoke,
                    target: Some(0x100),
                    through: None,
                    convention: Convention::Aapcs64,
                    args: None,
                    floats_named: false,
                    abi: None,
                    clobbers: None,
                    outputs: crate::ir::fallback_call_outputs(Convention::Aapcs64, None),
                    via: None,
                },
                Stmt::Ret {
                    value: Expr::reg(0, 64),
                },
            ],
        );
        drop_dead_frame_stores(&mut ir);
        assert_eq!(ir.blocks[0].stmts.len(), 3, "{}", ir.render());
    }
    #[test]
    fn declared_register_calls_preserve_stack_height_after_save_elimination() {
        for declared in [false, true] {
            let mut ir = FunctionIr::single_block(
                Isa::X86_64,
                vec![
                    adjust(-16),
                    Stmt::Store {
                        addr: Expr::reg(RSP, 64),
                        value: Expr::reg(3, 64),
                        width: 8,
                    },
                    Stmt::Call {
                        kind: crate::ir::CallKind::Invoke,
                        target: Some(0x1000),
                        through: None,
                        convention: Convention::SysV,
                        args: Some(Vec::new()),
                        floats_named: true,
                        clobbers: Some(Default::default()),
                        outputs: Vec::new(),
                        abi: declared.then(|| crate::ir::calls::test_call_abi(vec![RSP], false)),
                        via: None,
                    },
                    assign(
                        3,
                        Expr::Load {
                            addr: Box::new(Expr::reg(RSP, 64)),
                            width: 8,
                            signed: false,
                        },
                    ),
                    adjust(16),
                    Stmt::Ret {
                        value: Expr::Const(0),
                    },
                ],
            );
            elide_callee_saves(&mut ir);
            assert!(!ir.blocks[0].stmts.iter().any(|stmt| matches!(
                stmt,
                Stmt::Store { .. }
                    | Stmt::Assign {
                        dest: RegRef { index: 3, .. },
                        ..
                    }
            )));
            assert_eq!(
                ir.blocks[0]
                    .stmts
                    .iter()
                    .filter(|stmt| matches!(stmt,
                Stmt::Assign { dest, .. } if dest.index == RSP))
                    .count(),
                if declared { 2 } else { 0 }
            );
        }
    }

    #[test]
    fn deferred_call_memory_keeps_an_otherwise_dead_frame_store() {
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                store(0, Expr::Const(9), 8),
                Stmt::Call {
                    kind: crate::ir::CallKind::Invoke,
                    target: Some(0x1000),
                    through: None,
                    convention: Convention::Aapcs64,
                    args: Some(Vec::new()),
                    floats_named: true,
                    clobbers: Some(Default::default()),
                    outputs: Vec::new(),
                    abi: Some(crate::ir::calls::test_call_abi(vec![31], true)),
                    via: None,
                },
                Stmt::Ret {
                    value: Expr::Const(0),
                },
            ],
        );
        let original = ir.blocks[0].stmts.clone();
        drop_dead_frame_stores(&mut ir);
        assert_eq!(format!("{:?}", ir.blocks[0].stmts), format!("{original:?}"));
        if let Stmt::Call { abi, .. } = &mut ir.blocks[0].stmts[1] {
            *abi = None;
        }
        drop_dead_frame_stores(&mut ir);
        assert_eq!(ir.blocks[0].stmts.len(), 2);
        assert!(matches!(ir.blocks[0].stmts[0], Stmt::Call { .. }));
    }
}

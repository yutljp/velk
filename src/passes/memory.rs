use crate::arch::stack_pointer;

use crate::ir::visit::statement_registers;
use crate::ir::{Expr, FunctionIr, Stmt};

mod frame_values;

pub fn promote_frame_slots(ir: &mut FunctionIr) {
    frame_values::promote(ir);
}

/// Replaces a load with the value stored to the same address earlier in the
/// block: `*(u32 *)&local_3 = w8; x8 = *(u32 *)&local_3;` leaves `x8 = w8;`.
///
/// # Panics
///
/// Panics if a call has no write definitions after they were computed for the block.
pub fn forward_stored_values(ir: &mut FunctionIr) {
    frame_values::forward(ir);
    let sp = stack_pointer(ir.isa);
    // A callee can reach the caller's frame only through an address the
    // code hands out, and the outgoing arguments it may write: Go's callee
    // spills its register arguments to the bottom of the caller's frame.
    let private_frame = !frame_address_escapes(ir, sp);
    let atomic_private_frame = fixed_private_frame(ir, sp);
    let spills = ir.convention == crate::ir::Convention::GoAmd64;
    for block in &mut ir.blocks {
        let mut pending: Vec<(u8, Expr, Expr)> = Vec::new();
        for stmt in &mut block.stmts {
            // A declared call reads memory its declaration names, which
            // no earlier store can be forwarded past.
            if stmt.has_deferred_call_memory() {
                pending.clear();
                continue;
            }
            let call_writes =
                matches!(stmt, Stmt::Call { .. }).then(|| statement_registers(stmt).0);
            match stmt {
                Stmt::Store {
                    addr, value, width, ..
                } => {
                    // A newer store replaces every older one it may overlap,
                    // and every remembered value that loads what it overwrites.
                    pending.retain(|(stored_width, stored, remembered)| {
                        disjoint(stored, *stored_width, addr, *width)
                            && loads_avoid(remembered, addr, *width)
                    });
                    if loads_avoid(value, addr, *width) {
                        pending.push((*width, addr.clone(), value.clone()));
                    }
                }
                // A call reads its arguments before it may change memory,
                // which leaves a private frame alone past the arguments it
                // passes on the stack.
                Stmt::Call {
                    through,
                    args,
                    convention,
                    ..
                } => {
                    let clobbered = call_writes.as_ref().expect("call definitions");
                    let mut passed = 0;
                    if let Some(through) = through {
                        forward_expr(through, &pending);
                    }
                    // Arguments past the registers are the ones the stack
                    // carries; a register argument loaded from a slot only
                    // reads it.
                    let in_registers = convention.arguments().len();
                    for value in args.iter_mut().flatten().take(in_registers) {
                        forward_expr(value, &pending);
                    }
                    for value in args.iter_mut().flatten().skip(in_registers) {
                        forward_expr(value, &pending);
                        if let Expr::Load { addr, width, .. } = value {
                            let (base, offset) = split_offset(addr);
                            if matches!(base, Expr::Reg { index, .. } if *index == sp) {
                                passed = passed.max(offset + i64::from(*width));
                            }
                        }
                    }
                    // A callee of Go's register convention spills its
                    // arguments to the area at the bottom of the frame that
                    // is its own, which the caller stores nothing to: a slot
                    // the caller stored to keeps its value. Only a call of
                    // unknown arguments, or of another convention, may write
                    // more.
                    let spilled = match args {
                        Some(_) if spills && *convention == crate::ir::Convention::GoAmd64 => 0,
                        Some(args) if spills => 8 * args.len() as i64,
                        None if spills => i64::MAX,
                        _ => 0,
                    };
                    let reserved = passed.max(spilled);
                    pending.retain(|(_, addr, stored)| {
                        let (base, offset) = split_offset(addr);
                        let mut reads = std::collections::HashSet::new();
                        crate::ir::visit::collect_reads(stored, &mut reads);
                        private_frame
                            && matches!(base, Expr::Reg { index, .. } if *index == sp)
                            && offset >= reserved
                            && !reads.iter().any(|register| clobbered.contains(register))
                    });
                }
                Stmt::Unsupported { .. } => pending.clear(),
                Stmt::Assign { dest, value } => {
                    // Moving the stack pointer by a constant moves every
                    // remembered `sp`-relative address the other way; any
                    // other move leaves them unknown.
                    if dest.index == sp {
                        let delta = match value {
                            Expr::Bin {
                                op: crate::ir::BinOp::Add,
                                lhs,
                                rhs,
                            } if matches!(lhs.as_ref(), Expr::Reg { index, .. } if *index == sp) => {
                                match rhs.as_ref() {
                                    Expr::Const(delta) => Some(*delta),
                                    _ => None,
                                }
                            }
                            Expr::Bin {
                                op: crate::ir::BinOp::Sub,
                                lhs,
                                rhs,
                            } if matches!(lhs.as_ref(), Expr::Reg { index, .. } if *index == sp) => {
                                match rhs.as_ref() {
                                    Expr::Const(delta) => Some(delta.wrapping_neg()),
                                    _ => None,
                                }
                            }
                            _ => None,
                        };
                        let Some(delta) = delta else {
                            pending.clear();
                            continue;
                        };
                        pending = pending
                            .drain(..)
                            .filter_map(|(width, addr, stored)| {
                                let mut reads = std::collections::HashSet::new();
                                crate::ir::visit::collect_reads(&stored, &mut reads);
                                if reads.contains(&sp) {
                                    return None;
                                }
                                let (base, offset) = split_offset(&addr);
                                if !matches!(base, Expr::Reg { index, .. } if *index == sp) {
                                    reads.clear();
                                    crate::ir::visit::collect_reads(&addr, &mut reads);
                                    return (!reads.contains(&sp)).then_some((width, addr, stored));
                                }
                                let moved = (offset as u64).wrapping_sub(delta);
                                let base = base.clone();
                                let addr = if moved == 0 {
                                    base
                                } else {
                                    Expr::bin(crate::ir::BinOp::Add, base, Expr::Const(moved))
                                };
                                Some((width, addr, stored))
                            })
                            .collect();
                        continue;
                    }
                    forward_expr(value, &pending);
                    // A remembered store that reads the register now describes
                    // its old value.
                    pending.retain(|(_, addr, stored)| {
                        let mut reads = std::collections::HashSet::new();
                        crate::ir::visit::collect_reads(addr, &mut reads);
                        crate::ir::visit::collect_reads(stored, &mut reads);
                        !reads.contains(&dest.index)
                    });
                }
                Stmt::Brif { cond, lhs, rhs, .. } => {
                    forward_comparison(*cond, lhs, rhs, &pending);
                }
                Stmt::Machine {
                    instruction,
                    inputs,
                    outputs,
                } => {
                    if matches!(
                        instruction,
                        crate::ir::MachineInstruction::ArmSystem { .. }
                            | crate::ir::MachineInstruction::ArmBarrier { .. }
                            | crate::ir::MachineInstruction::ArmLoadAcquire { .. }
                            | crate::ir::MachineInstruction::ArmExclusive { .. }
                            | crate::ir::MachineInstruction::ArmCacheZero
                    ) {
                        pending.clear();
                    } else if matches!(instruction, crate::ir::MachineInstruction::Atomic { .. }) {
                        pending.retain(|(width, addr, stored)| {
                            atomic_private_frame
                                && private_address(addr, *width, sp)
                                && private_loads(stored, sp)
                        });
                    }
                    for input in inputs {
                        forward_expr(input, &pending);
                    }
                    pending.retain(|(_, addr, stored)| {
                        let mut reads = std::collections::HashSet::new();
                        crate::ir::visit::collect_reads(addr, &mut reads);
                        crate::ir::visit::collect_reads(stored, &mut reads);
                        !outputs.iter().any(|output| reads.contains(&output.index))
                    });
                }
                Stmt::Ret { value } => forward_expr(value, &pending),
                _ => {}
            }
        }
    }
}

pub(crate) fn atomic(stmt: &Stmt) -> bool {
    matches!(
        stmt,
        Stmt::Machine {
            instruction: crate::ir::MachineInstruction::Atomic { .. }
                | crate::ir::MachineInstruction::ArmSystem { .. }
                | crate::ir::MachineInstruction::ArmBarrier { .. }
                | crate::ir::MachineInstruction::ArmLoadAcquire { .. }
                | crate::ir::MachineInstruction::ArmExclusive { .. }
                | crate::ir::MachineInstruction::ArmCacheZero,
            ..
        }
    )
}

pub(crate) fn fixed_private_frame(ir: &FunctionIr, sp: u16) -> bool {
    !frame_address_escapes(ir, sp)
        && !ir.blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
            matches!(
                stmt,
                Stmt::Machine {
                    instruction: crate::ir::MachineInstruction::ArmCacheZero
                        | crate::ir::MachineInstruction::ArmExclusive { .. },
                    ..
                }
            )
        })
        && !ir
            .blocks
            .iter()
            .flat_map(|block| &block.stmts)
            .any(|stmt| statement_registers(stmt).0.contains(&sp))
}

pub(crate) fn private_address(addr: &Expr, width: u8, sp: u16) -> bool {
    if !frame_values::full_frame_register(addr, sp) {
        return false;
    }
    crate::passes::frame_slots::frame_slot(addr, 0, sp)
        .and_then(|offset| offset.checked_add(i64::from(width)))
        .is_some_and(|end| end <= 0)
}

fn private_loads(value: &Expr, sp: u16) -> bool {
    match value {
        Expr::Load { addr, width, .. } => {
            private_address(addr, *width, sp) && private_loads(addr, sp)
        }
        _ => crate::ir::visit::children(value)
            .into_iter()
            .all(|child| private_loads(child, sp)),
    }
}

/// Atomics order potentially shared memory, even when its address is disjoint.
/// Only register expressions and loads from an unescaped frame may cross one.
/// A frame address used as an atomic operand counts as escaping, so these
/// retained slots cannot overlap the atomic access, for any memory ordering.
/// Incoming stack arguments remain potentially shared with the caller.
pub(crate) fn crosses_atomic(value: &Expr, sp: u16, private_frame: bool) -> bool {
    !crate::passes::copies::reads_memory(value) || (private_frame && private_loads(value, sp))
}

/// Whether an address in the frame is used as a value: stored, passed, or
/// computed with, rather than only loaded and stored through.
pub(crate) fn frame_address_escapes(ir: &FunctionIr, sp: u16) -> bool {
    frame_addresses_escape(&ir.blocks, sp)
}

pub(crate) fn frame_addresses_escape(blocks: &[crate::ir::Block], sp: u16) -> bool {
    fn escapes(expr: &Expr, sp: u16) -> bool {
        match expr {
            Expr::Reg { index, .. } => *index == sp,
            Expr::Load { addr, .. } => {
                let (base, _) = split_offset(addr);
                if matches!(base, Expr::Reg { index, .. } if *index == sp) {
                    false
                } else {
                    escapes(addr, sp)
                }
            }
            other => crate::ir::visit::children(other)
                .into_iter()
                .any(|child| escapes(child, sp)),
        }
    }
    blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .any(|stmt| match stmt {
            Stmt::Assign { dest, .. } if dest.index == sp => false,
            Stmt::Store { addr, value, .. } => {
                let (base, _) = split_offset(addr);
                escapes(value, sp)
                    || (!matches!(base, Expr::Reg { index, .. } if *index == sp)
                        && escapes(addr, sp))
            }
            other => other.operands().into_iter().any(|value| escapes(value, sp)),
        })
}

/// True when the two accesses provably touch different bytes: the same base
/// at constant offsets whose ranges do not meet.
fn disjoint(a: &Expr, a_width: u8, b: &Expr, b_width: u8) -> bool {
    let (a_base, a_offset) = split_offset(a);
    let (b_base, b_offset) = split_offset(b);
    if a_base != b_base {
        return false;
    }
    let a_end = a_offset.wrapping_add(i64::from(a_width));
    let b_end = b_offset.wrapping_add(i64::from(b_width));
    a_end <= b_offset || b_end <= a_offset
}

/// True when every load in the value provably reads other bytes than the
/// `width` bytes at `addr`.
pub(super) fn loads_avoid(value: &Expr, addr: &Expr, width: u8) -> bool {
    match value {
        Expr::Load {
            addr: read,
            width: read_width,
            ..
        } => disjoint(read, *read_width, addr, width) && loads_avoid(read, addr, width),
        _ => crate::ir::visit::children(value)
            .into_iter()
            .all(|child| loads_avoid(child, addr, width)),
    }
}

/// An address as a base and a constant byte offset.
pub(crate) fn split_offset(addr: &Expr) -> (&Expr, i64) {
    match addr {
        Expr::Bin {
            op: crate::ir::BinOp::Add,
            lhs,
            rhs,
        } => match rhs.as_ref() {
            Expr::Const(offset) => (lhs, *offset as i64),
            _ => (addr, 0),
        },
        _ => (addr, 0),
    }
}

fn forward_comparison(
    cond: crate::ir::Cond,
    lhs: &mut Expr,
    rhs: &mut Expr,
    pending: &[(u8, Expr, Expr)],
) {
    let bits = crate::ir::semantics::operand_width(lhs, rhs);
    let original = (lhs.clone(), rhs.clone());
    forward_expr(lhs, pending);
    forward_expr(rhs, pending);
    if !super::copies::comparison_preserved(cond, bits, lhs, rhs) {
        (*lhs, *rhs) = original;
    }
}

fn forward_expr(expr: &mut Expr, pending: &[(u8, Expr, Expr)]) {
    match expr {
        Expr::Load {
            addr,
            width,
            signed,
        } => {
            if let Some((_, _, value)) = pending.iter().find(|(stored_width, stored, _)| {
                *stored_width == *width && stored == addr.as_ref()
            }) {
                // The load reads back only the stored bytes, extended its own way.
                *expr = match (*width, *signed) {
                    (8, _) => value.clone(),
                    (width, true) => Expr::SignExtend {
                        value: Box::new(value.clone()),
                        width,
                    },
                    (width, false) => {
                        let bits = width.saturating_mul(8);
                        if crate::ir::semantics::width(value) == u32::from(bits) {
                            crate::passes::copies::truncated(value, bits)
                        } else {
                            Expr::bin(
                                crate::ir::BinOp::And,
                                value.clone(),
                                Expr::Const(crate::ir::semantics::mask(u32::from(bits))),
                            )
                        }
                    }
                };
                return;
            }
            forward_expr(addr, pending);
        }
        Expr::Bin { lhs, rhs, .. } => {
            forward_expr(lhs, pending);
            forward_expr(rhs, pending);
        }
        Expr::SignExtend { value, .. } => forward_expr(value, pending),
        Expr::Select {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => {
            forward_comparison(*cond, lhs, rhs, pending);
            forward_expr(then, pending);
            forward_expr(els, pending);
        }
        Expr::Apply { args, .. } => {
            for arg in args {
                forward_expr(arg, pending);
            }
        }
        _ => {}
    }
}

/// Fuses `t = *p; t = op(t, x); *p = t` into `*p = op(*p, x)` when the
/// temporary is read nowhere else in the block.
pub fn fuse_load_op_store(ir: &mut FunctionIr) {
    let live_in = crate::ir::cfg::live_in(ir);
    let live_out: Vec<_> = (0..ir.blocks.len())
        .map(|index| crate::ir::cfg::live_out(ir, &live_in, index))
        .collect();
    let sp = stack_pointer(ir.isa);
    let private_frame = fixed_private_frame(ir, sp);
    for (block, live_out) in ir.blocks.iter_mut().zip(&live_out) {
        fuse_block(block, live_out, sp, private_frame);
    }
}

/// True when something after `from` reads the temporary before redefining
/// it, in this block or, through the block's exit, in a later one.
fn read_later(
    stmts: &[Stmt],
    from: usize,
    dest: u16,
    live_out: &std::collections::HashSet<u16>,
) -> bool {
    for stmt in &stmts[from..] {
        let (writes, reads) = statement_registers(stmt);
        if reads.contains(&dest) {
            return true;
        }
        if writes.contains(&dest) {
            return false;
        }
    }
    live_out.contains(&dest)
}

fn fuse_block(
    block: &mut crate::ir::Block,
    live_out: &std::collections::HashSet<u16>,
    sp: u16,
    private_frame: bool,
) {
    let mut fused: Vec<usize> = Vec::new();
    let mut index = 0;
    while index < block.stmts.len() {
        if fused.contains(&index) {
            index += 1;
            continue;
        }
        // The update may already carry its load: `t = op(*p, x); *p = t`.
        if let Some((dest, address, update)) = inline_update(&block.stmts[index])
            && let Some(store_at) = store_back(
                &block.stmts,
                index,
                dest,
                &address,
                live_out,
                crosses_atomic(&update, sp, private_frame),
            )
        {
            if let Stmt::Store { value, .. } = &mut block.stmts[store_at] {
                *value = update;
            }
            fused.push(index);
            index = store_at + 1;
            continue;
        }
        let Some((dest, address, load)) = temporary_load(&block.stmts[index]) else {
            index += 1;
            continue;
        };
        // The next statement to touch the temporary, within a short window,
        // must be the update that rewrites it.
        let mut op_at = None;
        let mut clean = true;
        for probe in index + 1..block.stmts.len().min(index + 8) {
            if block.stmts[probe].has_deferred_call_memory()
                || atomic(&block.stmts[probe])
                    && (!crosses_atomic(&load, sp, private_frame)
                        || !statement_registers(&block.stmts[probe]).0.is_empty())
            {
                clean = false;
                break;
            }
            let (writes, reads) = statement_registers(&block.stmts[probe]);
            if writes.contains(&dest) {
                op_at = Some(probe);
                break;
            }
            if reads.contains(&dest) {
                clean = false;
                break;
            }
        }
        let Some(op_at) = op_at else {
            index += 1;
            continue;
        };
        if !clean {
            index += 1;
            continue;
        }
        let Some((op, rhs)) = update_of(&block.stmts[op_at], dest) else {
            index += 1;
            continue;
        };
        // Then the temporary must be stored back to the same address.
        let mut store_at = None;
        let mut blocked = false;
        for probe in op_at + 1..block.stmts.len().min(op_at + 8) {
            if block.stmts[probe].has_deferred_call_memory()
                || atomic(&block.stmts[probe])
                    && (!crosses_atomic(&load, sp, private_frame)
                        || !crosses_atomic(&rhs, sp, private_frame)
                        || !statement_registers(&block.stmts[probe]).0.is_empty())
            {
                blocked = true;
                break;
            }
            let (writes, reads) = statement_registers(&block.stmts[probe]);
            if let Some((addr, value)) = store_pair(&block.stmts[probe])
                && addr == &address
                && reads_temporary(value, dest) == Some(true)
            {
                store_at = Some(probe);
                break;
            }
            if reads.contains(&dest) || writes.contains(&dest) {
                blocked = true;
                break;
            }
        }
        let Some(store_at) = store_at else {
            index += 1;
            continue;
        };
        if blocked {
            index += 1;
            continue;
        }
        // Nothing may read the temporary after the store either.
        if read_later(&block.stmts, store_at + 1, dest, live_out) {
            index += 1;
            continue;
        }
        if let Stmt::Store { addr, value, .. } = &mut block.stmts[store_at] {
            *value = Expr::bin(op, load.clone(), rhs);
            let _ = addr;
        }
        fused.push(index);
        fused.push(op_at);
        index = store_at + 1;
    }
    if fused.is_empty() {
        return;
    }
    let kept: Vec<Stmt> = block
        .stmts
        .drain(..)
        .enumerate()
        .filter_map(|(position, stmt)| (!fused.contains(&position)).then_some(stmt))
        .collect();
    block.stmts = kept;
}

/// `t = *p` (optionally masked to the load's width).
fn temporary_load(stmt: &Stmt) -> Option<(u16, Expr, Expr)> {
    let Stmt::Assign { dest, value } = stmt else {
        return None;
    };
    let inner = strip_mask(value);
    let Expr::Load { addr, .. } = inner else {
        return None;
    };
    Some((dest.index, addr.as_ref().clone(), inner.clone()))
}

/// `t = op(t, rhs)` as the operator and its other operand.
fn update_of(stmt: &Stmt, dest: u16) -> Option<(crate::ir::BinOp, Expr)> {
    let Stmt::Assign {
        dest: written,
        value,
    } = stmt
    else {
        return None;
    };
    if written.index != dest {
        return None;
    }
    let Expr::Bin { op, lhs, rhs } = strip_mask(value) else {
        return None;
    };
    let Expr::Reg { index, .. } = strip_mask(lhs) else {
        return None;
    };
    if *index != dest {
        return None;
    }
    Some((*op, rhs.as_ref().clone()))
}

/// `t = op(*p, x)` as the temporary, the address it updated and the new
/// value of the location.
fn inline_update(stmt: &Stmt) -> Option<(u16, Expr, Expr)> {
    let Stmt::Assign { dest, value } = stmt else {
        return None;
    };
    let Expr::Bin { op, lhs, rhs } = strip_mask(value) else {
        return None;
    };
    let read = strip_mask(lhs);
    let Expr::Load { addr, .. } = read else {
        return None;
    };
    // Same shape as the three-statement fusion produces.
    Some((
        dest.index,
        addr.as_ref().clone(),
        Expr::bin(*op, read.clone(), rhs.as_ref().clone()),
    ))
}

/// The statement storing the temporary back to the address it read,
/// provided nothing observes the temporary in between or after.
fn store_back(
    stmts: &[Stmt],
    index: usize,
    dest: u16,
    address: &Expr,
    live_out: &std::collections::HashSet<u16>,
    crosses: bool,
) -> Option<usize> {
    let mut store_at = None;
    for (probe, stmt) in stmts.iter().enumerate().take(index + 8).skip(index + 1) {
        if stmt.has_deferred_call_memory()
            || atomic(stmt) && (!crosses || !statement_registers(stmt).0.is_empty())
        {
            return None;
        }
        let (writes, reads) = statement_registers(stmt);
        if let Some((addr, value)) = store_pair(stmt)
            && addr == address
            && reads_temporary(value, dest) == Some(true)
        {
            store_at = Some(probe);
            break;
        }
        if reads.contains(&dest) || writes.contains(&dest) {
            return None;
        }
    }
    let Some(store_at) = store_at else {
        return None;
    };
    (!read_later(stmts, store_at + 1, dest, live_out)).then_some(store_at)
}

fn store_pair(stmt: &Stmt) -> Option<(&Expr, &Expr)> {
    match stmt {
        Stmt::Store { addr, value, .. } => Some((addr, value)),
        _ => None,
    }
}

/// True when the expression is a read of the register, possibly masked.
fn reads_temporary(value: &Expr, dest: u16) -> Option<bool> {
    let Expr::Reg { index, .. } = strip_mask(value) else {
        return Some(false);
    };
    Some(*index == dest)
}

/// Peels a `& mask` off the expression when the mask only truncates.
pub(crate) fn strip_mask(expr: &Expr) -> &Expr {
    match expr {
        Expr::Bin {
            op: crate::ir::BinOp::And,
            lhs,
            rhs,
        } => match rhs.as_ref() {
            Expr::Const(0xff)
            | Expr::Const(0xffff)
            | Expr::Const(0xffff_ffff)
            | Expr::Const(u64::MAX) => strip_mask(lhs),
            _ => expr,
        },
        _ => expr,
    }
}

/// Reads a frame slot as the variable it holds where the function stores
/// that variable there once and only reads it back: a value kept across
/// calls in the frame, `local_0 = v1; ... f(local_0)`, reads `f(v1)`, and
/// the store goes. The slot must be private to the frame and touched only
/// whole, stored once by a variable defined once, before the store and
/// outside any loop unless in the store's block, and read only where that
/// store has run; no call may take it as an argument on the stack, and no
/// Go call of unknown arguments may run after the store. Slots are told
/// apart by their offset from the stack pointer on entry, which tracks the
/// stack pointer's moves.
pub fn forward_spilled_variables(ir: &mut FunctionIr) {
    use std::collections::HashMap;
    let sp = stack_pointer(ir.isa);
    let go = ir.convention == crate::ir::Convention::GoAmd64;
    if frame_address_escapes(ir, sp)
        || ir
            .blocks
            .iter()
            .flat_map(|block| &block.stmts)
            .any(|stmt| matches!(stmt, Stmt::Unsupported { .. }) || stmt.has_deferred_call_memory())
    {
        return;
    }
    // Slots by their offset from the stack pointer on entry, through the
    // frame each block starts in and the moves of the stack pointer in it.
    let frames = crate::passes::frame_slots::block_frames(ir, sp);
    let slot = |addr: &Expr, frame: i64| -> Option<i64> {
        let (base, offset) = split_offset(addr);
        matches!(base, Expr::Reg { index, .. } if *index == sp)
            .then_some(frame.wrapping_add(offset))
    };
    // Every access of each slot: (block, position, width, is store).
    let mut accesses: HashMap<i64, Vec<(usize, usize, u8, bool)>> = HashMap::new();
    let mut overlapping: Vec<(i64, u8)> = Vec::new();
    // The slots a call passes on the stack.
    let mut passed: std::collections::HashSet<i64> = std::collections::HashSet::new();
    // The Go calls of unknown arguments, which may spill over any slot.
    let mut unknown: Vec<(usize, usize)> = Vec::new();
    // How many times each variable is given a value, and where.
    let mut definitions: HashMap<u16, Vec<(usize, usize)>> = HashMap::new();
    for (block, stmts) in ir.blocks.iter().enumerate() {
        let Some(mut frame) = frames[block] else {
            // A block of unknown frame may touch any slot.
            if stmts
                .stmts
                .iter()
                .any(|stmt| statement_registers(stmt).1.contains(&sp))
            {
                return;
            }
            continue;
        };
        for (position, stmt) in stmts.stmts.iter().enumerate() {
            let mut loads = Vec::new();
            for operand in stmt.operands() {
                collect_loads(operand, &mut loads);
            }
            for (addr, width) in loads {
                if let Some(offset) = slot(addr, frame) {
                    accesses
                        .entry(offset)
                        .or_default()
                        .push((block, position, width, false));
                    overlapping.push((offset, width));
                }
            }
            match stmt {
                Stmt::Store { addr, width, .. } => {
                    if let Some(offset) = slot(addr, frame) {
                        accesses
                            .entry(offset)
                            .or_default()
                            .push((block, position, *width, true));
                        overlapping.push((offset, *width));
                    }
                }
                Stmt::Assign { dest, value } => {
                    if dest.index == sp {
                        match moved(value, sp) {
                            Some(delta) => frame = frame.wrapping_add(delta),
                            None => return,
                        }
                    }
                    definitions
                        .entry(dest.index)
                        .or_default()
                        .push((block, position));
                }
                Stmt::Machine { outputs, .. } => {
                    for output in outputs {
                        definitions
                            .entry(output.index)
                            .or_default()
                            .push((block, position));
                    }
                }
                Stmt::Call {
                    args, convention, ..
                } => {
                    if go && args.is_none() {
                        unknown.push((block, position));
                    }
                    for written in statement_registers(stmt).0 {
                        definitions
                            .entry(written)
                            .or_default()
                            .push((block, position));
                    }
                    for arg in args.iter().flatten().skip(convention.arguments().len()) {
                        if let Expr::Load { addr, .. } = arg
                            && let Some(offset) = slot(addr, frame)
                        {
                            passed.insert(offset);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    let successors: Vec<Vec<usize>> = (0..ir.blocks.len())
        .map(|index| crate::ir::cfg::successors(ir, index))
        .collect();
    let idom = crate::ssa::dom::dominators(&successors).idom;
    let dominates = |above: usize, mut block: usize| loop {
        if block == above {
            return true;
        }
        match idom[block] {
            Some(parent) if parent != block => block = parent,
            _ => return false,
        }
    };
    let cyclic = crate::ir::cfg::cyclic_blocks(ir);
    let atomics = ir.blocks.iter().flat_map(|block| &block.stmts).any(atomic);
    let mut forwarded: Vec<(i64, u8, u16)> = Vec::new();
    let mut dropped: Vec<(usize, usize)> = Vec::new();
    for (offset, uses) in &accesses {
        let stores: Vec<(usize, usize, u8, bool)> =
            uses.iter().copied().filter(|(.., store)| *store).collect();
        let [(store_block, store_at, width, _)] = stores.as_slice() else {
            continue;
        };
        let (store_block, store_at, width) = (*store_block, *store_at, *width);
        if !matches!(width, 4 | 8)
            || (atomics && offset.checked_add(i64::from(width)).is_none_or(|end| end > 0))
            || passed.contains(offset)
            || uses.iter().any(|(.., used, _)| *used != width)
            // Another access reaching into the slot from elsewhere.
            || overlapping.iter().any(|(other, other_width)| {
                other != offset
                    && *other < offset + i64::from(width)
                    && *offset < other + i64::from(*other_width)
            })
        {
            continue;
        }
        let Stmt::Store {
            value:
                Expr::Reg {
                    index: variable,
                    width: 64,
                },
            ..
        } = &ir.blocks[store_block].stmts[store_at]
        else {
            continue;
        };
        let variable = *variable;
        // The variable holds one value from its definition on: given earlier
        // in the store's block, or in a block that runs once and comes
        // before it on every path.
        let defined_before = match definitions.get(&variable).map(Vec::as_slice) {
            Some([(block, at)]) if *block == store_block => *at < store_at,
            Some([(block, _)]) => !cyclic.contains(block) && dominates(*block, store_block),
            _ => false,
        };
        let read_after = uses
            .iter()
            .filter(|(.., store)| !*store)
            .all(|(block, at, ..)| {
                if *block == store_block {
                    *at > store_at
                } else {
                    dominates(store_block, *block)
                }
            });
        // A call between the store and a read runs after the store: one the
        // store does not come before on every path would leave a read the
        // store does not come before either.
        let overwritten = unknown.iter().any(|(block, at)| {
            if *block == store_block {
                *at > store_at
            } else {
                dominates(store_block, *block)
            }
        });
        if variable < crate::ir::VARIABLE_BASE || !defined_before || !read_after || overwritten {
            continue;
        }
        forwarded.push((*offset, width, variable));
        dropped.push((store_block, store_at));
    }
    if forwarded.is_empty() {
        return;
    }
    fn replace(expr: &mut Expr, sp: u16, frame: i64, forwarded: &[(i64, u8, u16)]) {
        if let Expr::Load {
            addr,
            width,
            signed,
        } = expr
        {
            let (base, offset) = split_offset(addr);
            if matches!(base, Expr::Reg { index, .. } if *index == sp)
                && let Some((_, _, variable)) = forwarded.iter().find(|(slot, slot_width, _)| {
                    *slot == frame.wrapping_add(offset) && slot_width == width
                })
            {
                *expr = match (*width, *signed) {
                    (8, _) => Expr::reg(*variable, 64),
                    (_, false) => Expr::reg(*variable, 32),
                    (width, true) => Expr::SignExtend {
                        value: Box::new(Expr::reg(*variable, 32)),
                        width,
                    },
                };
                return;
            }
        }
        for child in crate::ir::visit::children_mut(expr) {
            replace(child, sp, frame, forwarded);
        }
    }
    for (block, stmts) in ir.blocks.iter_mut().enumerate() {
        let mut position = 0;
        stmts.stmts.retain(|_| {
            position += 1;
            !dropped.contains(&(block, position - 1))
        });
        let Some(mut frame) = frames[block] else {
            continue;
        };
        for stmt in &mut stmts.stmts {
            for operand in stmt.operands_mut() {
                replace(operand, sp, frame, &forwarded);
            }
            if let Stmt::Assign { dest, value } = stmt
                && dest.index == sp
            {
                frame = frame.wrapping_add(moved(value, sp).unwrap_or(0));
            }
        }
    }
}

/// How far `sp = value` moves the stack pointer, when by a constant.
fn moved(value: &Expr, sp: u16) -> Option<i64> {
    let Expr::Bin { op, lhs, rhs } = value else {
        return None;
    };
    if !matches!(lhs.as_ref(), Expr::Reg { index, .. } if *index == sp) {
        return None;
    }
    match (op, rhs.as_ref()) {
        (crate::ir::BinOp::Add, Expr::Const(delta)) => Some(*delta as i64),
        (crate::ir::BinOp::Sub, Expr::Const(delta)) => Some((*delta as i64).wrapping_neg()),
        _ => None,
    }
}

/// The address and width of every load in `expr`.
fn collect_loads<'e>(expr: &'e Expr, out: &mut Vec<(&'e Expr, u8)>) {
    if let Expr::Load { addr, width, .. } = expr {
        out.push((addr, *width));
    }
    for child in crate::ir::visit::children(expr) {
        collect_loads(child, out);
    }
}

#[cfg(test)]
mod tests {
    use super::{forward_stored_values, fuse_load_op_store};
    use crate::ir::{BinOp, Expr, FunctionIr, RegRef, Stmt};
    use crate::loader::Isa;

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
    fn an_update_read_again_after_its_store_is_not_fused() {
        let assign = |value| Stmt::Assign {
            dest: RegRef {
                index: 0,
                width: 64,
            },
            value,
        };
        // t = *p; t = t + 1; *p = t; t = t & 0xff; return t;
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                assign(load(-8, 8)),
                assign(Expr::bin(BinOp::Add, Expr::reg(0, 64), Expr::Const(1))),
                store(-8, Expr::reg(0, 64), 8),
                assign(Expr::bin(BinOp::And, Expr::reg(0, 64), Expr::Const(0xff))),
                Stmt::Ret {
                    value: Expr::reg(0, 64),
                },
            ],
        );

        fuse_load_op_store(&mut ir);

        assert_eq!(ir.blocks[0].stmts.len(), 5, "{}", ir.render());
    }

    #[test]
    fn a_value_that_loads_its_own_slot_is_not_forwarded() {
        // c = c + 1; return c;
        let increment = Expr::bin(BinOp::Add, load(-8, 8), Expr::Const(1));
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![store(-8, increment, 8), Stmt::Ret { value: load(-8, 8) }],
        );

        forward_stored_values(&mut ir);

        assert!(
            matches!(&ir.blocks[0].stmts[1], Stmt::Ret { value } if *value == load(-8, 8)),
            "{}",
            ir.render()
        );
    }

    #[test]
    fn a_forwarded_byte_is_extended_like_the_load() {
        let byte = |signed| Expr::Load {
            addr: Box::new(slot(-1)),
            width: 1,
            signed,
        };
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                store(-1, Expr::reg(0, 64), 1),
                Stmt::Ret {
                    value: Expr::bin(BinOp::Add, byte(true), byte(false)),
                },
            ],
        );

        forward_stored_values(&mut ir);

        let expected = Expr::bin(
            BinOp::Add,
            Expr::SignExtend {
                value: Box::new(Expr::reg(0, 64)),
                width: 1,
            },
            Expr::bin(BinOp::And, Expr::reg(0, 64), Expr::Const(0xff)),
        );
        assert!(
            matches!(&ir.blocks[0].stmts[1], Stmt::Ret { value } if *value == expected),
            "{}",
            ir.render()
        );
    }

    #[test]
    fn a_value_whose_register_changes_is_not_forwarded() {
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                store(-8, Expr::reg(0, 64), 8),
                Stmt::Assign {
                    dest: RegRef {
                        index: 0,
                        width: 64,
                    },
                    value: Expr::Const(1),
                },
                Stmt::Ret { value: load(-8, 8) },
            ],
        );

        forward_stored_values(&mut ir);

        assert!(
            matches!(&ir.blocks[0].stmts[2], Stmt::Ret { value } if *value == load(-8, 8)),
            "{}",
            ir.render()
        );
    }

    #[test]
    fn a_store_over_part_of_a_slot_stops_forwarding_it() {
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                store(-8, Expr::reg(0, 64), 8),
                store(-4, Expr::Const(5), 4),
                Stmt::Ret { value: load(-8, 8) },
            ],
        );

        forward_stored_values(&mut ir);

        assert!(
            matches!(&ir.blocks[0].stmts[2], Stmt::Ret { value } if *value == load(-8, 8)),
            "{}",
            ir.render()
        );
    }

    #[test]
    fn a_variable_kept_in_a_slot_across_blocks_reads_as_itself() {
        // v1 = *x0; *(sp - 8) = v1; f(); if (x2 != 0) { return *(sp - 8) }.
        let v1 = crate::ir::VARIABLE_BASE;
        let call = Stmt::Call {
            kind: crate::ir::CallKind::Invoke,
            target: Some(0x1000),
            through: None,
            convention: crate::ir::Convention::Aapcs64,
            args: Some(Vec::new()),
            floats_named: false,
            abi: None,
            outputs: crate::ir::fallback_call_outputs(crate::ir::Convention::Aapcs64, None),
            clobbers: None,
            via: None,
        };
        let build = |second_store: bool| {
            let mut first = vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: v1,
                        width: 64,
                    },
                    value: Expr::Load {
                        addr: Box::new(Expr::reg(0, 64)),
                        width: 8,
                        signed: false,
                    },
                },
                store(-8, Expr::reg(v1, 64), 8),
                call.clone(),
            ];
            if second_store {
                first.push(store(-8, Expr::Const(0), 8));
            }
            first.push(Stmt::Brif {
                cond: crate::ir::Cond::Eq,
                lhs: Expr::reg(2, 64),
                rhs: Expr::Const(0),
                target: 0x20,
            });
            let mut ir = FunctionIr::single_block(Isa::AArch64, first);
            ir.blocks.push(crate::ir::Block {
                start: 0x10,
                stmts: vec![Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(slot(-8)),
                        width: 8,
                        signed: false,
                    },
                }],
            });
            ir.blocks.push(crate::ir::Block {
                start: 0x20,
                stmts: vec![Stmt::Ret {
                    value: Expr::Const(0),
                }],
            });
            ir
        };
        let mut ir = build(false);
        super::forward_spilled_variables(&mut ir);
        assert!(
            matches!(&ir.blocks[1].stmts[0], Stmt::Ret { value: Expr::Reg { index, .. } } if *index == v1),
            "{}",
            ir.render()
        );
        assert!(
            !ir.blocks[0]
                .stmts
                .iter()
                .any(|stmt| matches!(stmt, Stmt::Store { .. })),
            "{}",
            ir.render()
        );
        // A slot stored twice holds what the later store left.
        let mut ir = build(true);
        super::forward_spilled_variables(&mut ir);
        assert!(
            matches!(
                &ir.blocks[1].stmts[0],
                Stmt::Ret {
                    value: Expr::Load { .. }
                }
            ),
            "{}",
            ir.render()
        );
    }
    #[test]
    fn call_forwarding_uses_all_semantic_outputs_not_renamed_physical_output_registers() {
        let variable = crate::ir::VARIABLE_BASE;
        let mut outputs = crate::ir::fallback_call_outputs(
            crate::ir::Convention::Aapcs64,
            Some([1].into_iter().collect()),
        );
        outputs[0].dest.index = variable;
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                store(16, Expr::reg(variable, 64), 8),
                store(24, Expr::reg(1, 64), 8),
                Stmt::Call {
                    kind: crate::ir::CallKind::Invoke,
                    target: Some(0x1000),
                    through: None,
                    convention: crate::ir::Convention::Aapcs64,
                    args: Some(Vec::new()),
                    floats_named: true,
                    abi: None,
                    clobbers: Some([1].into_iter().collect()),
                    outputs,
                    via: None,
                },
                Stmt::Ret {
                    value: Expr::bin(crate::ir::BinOp::Xor, load(16, 8), load(24, 8)),
                },
            ],
        );
        forward_stored_values(&mut ir);
        assert!(
            matches!(ir.blocks[0].stmts.last(), Some(Stmt::Ret { value }) if *value == Expr::bin(crate::ir::BinOp::Xor, load(16, 8), Expr::reg(1, 64))),
            "{}",
            ir.render()
        );
    }
    fn deferred_call(args: Vec<Expr>) -> Stmt {
        Stmt::Call {
            kind: crate::ir::CallKind::Invoke,
            target: Some(0x1000),
            through: None,
            convention: crate::ir::Convention::Aapcs64,
            args: Some(args),
            floats_named: true,
            clobbers: Some(Default::default()),
            outputs: Vec::new(),
            abi: Some(crate::ir::calls::test_call_abi(vec![31], true)),
            via: None,
        }
    }

    #[test]
    fn deferred_call_memory_blocks_forwarding_and_keeps_fallback_loads() {
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                store(16, Expr::Const(9), 8),
                deferred_call(vec![load(16, 8)]),
                Stmt::Ret { value: load(16, 8) },
            ],
        );
        let original = ir.blocks[0].stmts.clone();
        forward_stored_values(&mut ir);
        assert_eq!(format!("{:?}", ir.blocks[0].stmts), format!("{original:?}"));

        if let Stmt::Call { abi, .. } = &mut ir.blocks[0].stmts[1] {
            *abi = None;
        }
        forward_stored_values(&mut ir);
        assert!(
            matches!(&ir.blocks[0].stmts[1], Stmt::Call { args: Some(args), .. } if args == &[Expr::Const(9)])
        );
        assert!(matches!(
            ir.blocks[0].stmts[2],
            Stmt::Ret {
                value: Expr::Const(9)
            }
        ));
    }

    #[test]
    fn deferred_call_memory_keeps_a_spilled_variable_store() {
        let variable = crate::ir::VARIABLE_BASE;
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: variable,
                        width: 64,
                    },
                    value: Expr::Const(9),
                },
                store(16, Expr::reg(variable, 64), 8),
                deferred_call(Vec::new()),
                Stmt::Ret { value: load(16, 8) },
            ],
        );
        let original = ir.blocks[0].stmts.clone();
        super::forward_spilled_variables(&mut ir);
        assert_eq!(format!("{:?}", ir.blocks[0].stmts), format!("{original:?}"));
    }

    #[test]
    fn deferred_call_memory_blocks_a_load_update_store_fusion() {
        let temporary = crate::ir::VARIABLE_BASE;
        let assign = |value| Stmt::Assign {
            dest: RegRef {
                index: temporary,
                width: 64,
            },
            value,
        };
        let update = || {
            assign(Expr::bin(
                BinOp::Add,
                Expr::reg(temporary, 64),
                Expr::Const(1),
            ))
        };
        let write = || store(16, Expr::reg(temporary, 64), 8);
        let call = || deferred_call(Vec::new());
        for mut stmts in [
            vec![assign(load(16, 8)), call(), update(), write()],
            vec![assign(load(16, 8)), update(), call(), write()],
            vec![
                assign(Expr::bin(BinOp::Add, load(16, 8), Expr::Const(1))),
                call(),
                write(),
            ],
        ] {
            stmts.push(Stmt::Ret {
                value: Expr::Const(0),
            });
            let original = format!("{stmts:?}");
            let mut ir = FunctionIr::single_block(Isa::AArch64, stmts);
            fuse_load_op_store(&mut ir);
            assert_eq!(format!("{:?}", ir.blocks[0].stmts), original);
        }
    }
}

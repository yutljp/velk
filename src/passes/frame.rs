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
            match stmt {
                Stmt::Store { addr, value, width } => {
                    if let Some(slot) = frame_slot_of(addr, sp) {
                        stores.push((position, index, slot, *width));
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
                // A callee may read its stack arguments from the frame.
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
        .filter(|(_, _, slot, width)| !overlaps(*slot, *width))
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
/// The frame displacement on entry to each block follows the control flow,
/// so the save and the restores resolve to the same slot across blocks and
/// stack adjustments.
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
    let frames = crate::passes::frame_slots::block_frames(ir, sp);
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
    }
    // Each slot must be written once and only read back into the same
    // register, once per return path, with that register untouched between
    // the save and each restore.
    let mut by_slot: HashMap<i64, Vec<usize>> = HashMap::new();
    for (index, access) in accesses.iter().enumerate() {
        by_slot.entry(access.slot).or_default().push(index);
    }
    let mut drop: std::collections::HashSet<(usize, usize)> = std::collections::HashSet::new();
    for list in by_slot.values() {
        let [save, restores @ ..] = list.as_slice() else {
            continue;
        };
        let first = &accesses[*save];
        if restores.is_empty()
            || !first.store
            || first.reg == sp
            || restores.iter().any(|index| {
                let restore = &accesses[*index];
                restore.store || restore.reg != first.reg
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
        let mut borrowed = false;
        let mut frame_setup: Option<(usize, usize)> = None;
        'scan: for (block_index, block) in ir.blocks.iter().enumerate() {
            for (position, stmt) in block.stmts.iter().enumerate() {
                if round_trip.contains(&(block_index, position)) {
                    continue;
                }
                let (writes, reads) = statement_registers(stmt);
                if reads.contains(&first.reg) {
                    borrowed = true;
                    break 'scan;
                }
                if writes.contains(&first.reg) {
                    if frame_setup.is_none() && is_frame_setup(stmt, sp) {
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
        for restore in restores.iter().map(|index| &accesses[*index]) {
            drop.insert((restore.block, restore.position));
        }
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
                    target: Some(0x100),
                    convention: Convention::SysV,
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
                target: Some(0x100),
                convention: Convention::SysV,
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
    fn keeps_a_store_a_callee_may_read() {
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                store(0, Expr::Const(9), 8),
                Stmt::Call {
                    target: Some(0x100),
                    convention: Convention::Aapcs64,
                },
                Stmt::Ret {
                    value: Expr::reg(0, 64),
                },
            ],
        );
        drop_dead_frame_stores(&mut ir);
        assert_eq!(ir.blocks[0].stmts.len(), 3, "{}", ir.render());
    }
}

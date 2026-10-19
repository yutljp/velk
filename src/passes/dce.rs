use crate::ir::cfg::successors;

use crate::ir::cfg::cyclic_blocks;
use crate::ir::visit::statement_registers;
use crate::ir::{FunctionIr, Stmt};
use crate::passes::frame::reads_outside_frame;

/// Dead-store elimination over the control flow graph: removes a definition
/// that no path reads before overwriting it.
pub fn dce_flow(ir: &mut FunctionIr) {
    let count = ir.blocks.len();
    if count == 0 {
        return;
    }
    // An unmodeled instruction or an indirect jump may read anything, so
    // the blocks holding one keep every definition and read everything.
    let opaque: Vec<bool> = ir
        .blocks
        .iter()
        .map(|block| {
            block.stmts.iter().any(|stmt| {
                matches!(
                    stmt,
                    Stmt::Unsupported { .. } | Stmt::BrIndirect { .. } | Stmt::Br { target: None }
                )
            })
        })
        .collect();
    // Every register any statement could name, for the opaque blocks.
    let universe: std::collections::HashSet<u16> = (0..=31u16)
        .chain(crate::ir::TEMP_BASE..crate::ir::TEMP_BASE + 64)
        .collect();
    // A call may read any register this function writes, so those stay live
    // across it.
    let mut clobbered: std::collections::HashSet<u16> = std::collections::HashSet::new();
    for block in &ir.blocks {
        for stmt in &block.stmts {
            clobbered.extend(statement_registers(stmt).0);
        }
    }
    let successors: Vec<Vec<usize>> = (0..count).map(|index| successors(ir, index)).collect();
    let mut live_in: Vec<std::collections::HashSet<u16>> = vec![Default::default(); count];
    // Backward liveness to a fixpoint, with an iteration cap.
    for _ in 0..count.max(4) * 2 {
        let mut changed = false;
        for index in (0..count).rev() {
            let mut live: std::collections::HashSet<u16> = successors[index]
                .iter()
                .flat_map(|next| live_in[*next].iter().copied())
                .collect();
            for stmt in ir.blocks[index].stmts.iter().rev() {
                if matches!(stmt, Stmt::Call { .. }) {
                    live.extend(clobbered.iter().copied());
                }
                let (writes, reads) = statement_registers(stmt);
                for written in &writes {
                    live.remove(written);
                }
                live.extend(reads);
            }
            if opaque[index] {
                live.extend(universe.iter().copied());
            }
            if live != live_in[index] {
                live_in[index] = live;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    for index in 0..count {
        if opaque[index] {
            continue;
        }
        let mut live: std::collections::HashSet<u16> = successors[index]
            .iter()
            .flat_map(|next| live_in[*next].iter().copied())
            .collect();
        let mut keep: Vec<bool> = vec![true; ir.blocks[index].stmts.len()];
        for (position, stmt) in ir.blocks[index].stmts.iter().enumerate().rev() {
            if matches!(stmt, Stmt::Call { .. }) {
                live.extend(clobbered.iter().copied());
            }
            let (writes, reads) = statement_registers(stmt);
            let pure = match stmt {
                Stmt::Assign { value, .. } => !reads_outside_frame(value),
                _ => true,
            };
            if let Stmt::Assign { dest, value } = stmt {
                let mut own = std::collections::HashSet::new();
                crate::ir::visit::collect_reads(value, &mut own);
                if pure && !live.contains(&dest.index) && !own.contains(&dest.index) {
                    keep[position] = false;
                    continue;
                }
            }
            for written in &writes {
                live.remove(written);
            }
            live.extend(reads);
        }
        let kept: Vec<Stmt> = ir.blocks[index]
            .stmts
            .drain(..)
            .zip(keep)
            .filter_map(|(stmt, keep)| keep.then_some(stmt))
            .collect();
        ir.blocks[index].stmts = kept;
    }
}

/// Per-block dead-store removal: drops an assignment whose destination no
/// other block reads and that is overwritten or never read later in its block.
pub fn dce(ir: &mut FunctionIr) {
    // A register read in another block is live at this block's boundary.
    let reads: Vec<std::collections::HashSet<u16>> = ir
        .blocks
        .iter()
        .map(|block| {
            block
                .stmts
                .iter()
                .flat_map(|stmt| statement_registers(stmt).1)
                .collect()
        })
        .collect();
    // A block inside a cycle reads its own live-outs again on the next
    // iteration, so its own reads are live at its boundary too.
    let cyclic = cyclic_blocks(ir);
    for (index, block) in ir.blocks.iter_mut().enumerate() {
        let mut outer: std::collections::HashSet<u16> = reads
            .iter()
            .enumerate()
            .filter(|(other, _)| *other != index)
            .flat_map(|(_, set)| set.iter().copied())
            .collect();
        if cyclic.contains(&index) {
            outer.extend(reads[index].iter().copied());
        }
        // A removed statement can strand the one feeding it, so sweep until
        // nothing changes.
        loop {
            let before = block.stmts.len();
            drop_dead_constants(block, &outer);
            if block.stmts.len() == before {
                break;
            }
        }
    }
}

fn drop_dead_constants(block: &mut crate::ir::Block, outer_reads: &std::collections::HashSet<u16>) {
    let mut keep: Vec<bool> = vec![true; block.stmts.len()];
    for (index, stmt) in block.stmts.iter().enumerate() {
        let Stmt::Assign { dest, value } = stmt else {
            continue;
        };
        // A read of memory outside the frame may be volatile, so it stays;
        // dead arithmetic, even a division, is removed.
        if reads_outside_frame(value) {
            continue;
        }
        if outer_reads.contains(&dest.index) {
            continue;
        }
        let mut dead = true;
        for later in block.stmts.iter().skip(index + 1) {
            let (writes, reads) = statement_registers(later);
            if reads.contains(&dest.index) {
                dead = false;
                break;
            }
            if writes.contains(&dest.index) {
                break;
            }
        }
        keep[index] = !dead;
    }
    let kept: Vec<Stmt> = block
        .stmts
        .drain(..)
        .zip(keep)
        .filter_map(|(stmt, keep)| keep.then_some(stmt))
        .collect();
    block.stmts = kept;
}

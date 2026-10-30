use crate::ir::cfg::{cyclic_blocks, live_in, live_out, opaque};
use crate::ir::visit::statement_registers;
use crate::ir::{FunctionIr, Stmt};
use crate::passes::frame::reads_outside_frame;

/// Dead-store elimination over the control flow graph: removes a definition
/// that no path reads before overwriting it.
pub fn dce_flow(ir: &mut FunctionIr) {
    let live_in = live_in(ir);
    for index in 0..ir.blocks.len() {
        if opaque(&ir.blocks[index]) {
            continue;
        }
        let mut live = live_out(ir, &live_in, index);
        let mut keep: Vec<bool> = vec![true; ir.blocks[index].stmts.len()];
        let reversed_statements = ir.blocks[index].stmts.iter().enumerate().rev();
        for (position, stmt) in reversed_statements {
            let (writes, reads) = statement_registers(stmt);
            let pure = match stmt {
                Stmt::Assign { value, .. } => !reads_outside_frame(value),
                _ => true,
            };
            if let Stmt::Assign { dest, value, .. } = stmt {
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
    // A copy of a register into itself, as a restore after a call that
    // left the register alone becomes, does nothing.
    for block in &mut ir.blocks {
        block.stmts.retain(|stmt| {
            !matches!(stmt, Stmt::Assign {
                dest,
                value: crate::ir::Expr::Reg { index, width: 64 },
                ..
            } if dest.width == 64 && *index == dest.index)
        });
    }
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
    // A register live on leaving the block, such as one a tail call through
    // an indirect jump reads, is kept too.
    let live_in = live_in(ir);
    let live_out: Vec<_> = (0..ir.blocks.len())
        .map(|index| live_out(ir, &live_in, index))
        .collect();
    for (index, block) in ir.blocks.iter_mut().enumerate() {
        if opaque(block) {
            continue;
        }
        let mut outer: std::collections::HashSet<u16> = reads
            .iter()
            .enumerate()
            .filter(|(other, _)| *other != index)
            .flat_map(|(_, set)| set.iter().copied())
            .collect();
        if cyclic.contains(&index) {
            outer.extend(reads[index].iter().copied());
        }
        outer.extend(live_out[index].iter().copied());
        // A removed statement can strand the one feeding it, so sweep until
        // nothing changes.
        loop {
            let before = block.stmts.len();
            drop_dead_assignments(block, &outer);
            if block.stmts.len() == before {
                break;
            }
        }
    }
}

fn drop_dead_assignments(
    block: &mut crate::ir::Block,
    outer_reads: &std::collections::HashSet<u16>,
) {
    let mut keep: Vec<bool> = vec![true; block.stmts.len()];
    for (index, stmt) in block.stmts.iter().enumerate() {
        let Stmt::Assign { dest, value, .. } = stmt else {
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

#[cfg(test)]
mod tests {
    use super::{dce, dce_flow};
    use crate::ir::{Convention, Expr, FunctionIr, RegRef, Stmt};
    use crate::loader::Isa;

    #[test]
    fn keeps_the_arguments_a_call_reads() {
        let stmts = vec![
            Stmt::Assign {
                dest: RegRef {
                    index: 0,
                    width: 64,
                },
                value: Expr::Const(5),
                at: None,
            },
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
                at: None,
            },
            Stmt::Ret {
                value: Expr::reg(0, 64),
                at: None,
            },
        ];
        for pass in [dce, dce_flow] {
            let mut ir = FunctionIr::single_block(Isa::AArch64, stmts.clone());
            pass(&mut ir);
            assert_eq!(ir.blocks[0].stmts.len(), 3, "{}", ir.render());
        }
    }

    #[test]
    fn keeps_the_index_a_switch_reads() {
        let stmts = vec![
            Stmt::Assign {
                dest: RegRef {
                    index: 8,
                    width: 64,
                },
                value: Expr::Const(1),
                at: None,
            },
            Stmt::Switch {
                index: Expr::reg(8, 64),
                cases: vec![(0, 0x100), (1, 0x200)],
                default: None,
                at: None,
            },
        ];
        for pass in [dce, dce_flow] {
            let mut ir = FunctionIr::single_block(Isa::AArch64, stmts.clone());
            pass(&mut ir);
            assert_eq!(ir.blocks[0].stmts.len(), 2, "{}", ir.render());
        }
    }
}

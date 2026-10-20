use crate::ir::cfg::{cyclic_blocks, live_in, live_out, opaque};
use crate::ir::visit::assign_of;
use crate::ir::visit::children;
use crate::ir::visit::expr_reads;
use crate::ir::visit::expr_width;
use crate::ir::visit::statement_reads;
use crate::ir::visit::statement_registers;
use crate::ir::{Expr, FunctionIr, Stmt};
use crate::passes::frame::reads_outside_frame;

/// Folds a definition read exactly once before its register is written again
/// into that reader, so `x8 = w8; if (x8 & 0x80000000) ...` keeps no temporary.
/// A definition a later block, or the next pass of a loop, may read stays.
pub fn inline_local_copies(ir: &mut FunctionIr) {
    let live_in = live_in(ir);
    let live_out: Vec<_> = (0..ir.blocks.len())
        .map(|index| live_out(ir, &live_in, index))
        .collect();
    for (position, block) in ir.blocks.iter_mut().enumerate() {
        let mut index = 0;
        while index < block.stmts.len() {
            let Some((dest, value)) = (match &block.stmts[index] {
                Stmt::Assign { dest, value } => Some((dest.index, truncated(value, dest.width))),
                _ => None,
            }) else {
                index += 1;
                continue;
            };
            // The value's width must be known to check it against the read.
            if expr_width(&value).is_none() {
                index += 1;
                continue;
            }
            // The registers the value reads must not change before the use,
            // nor the memory it loads.
            let mut sources = std::collections::HashSet::new();
            crate::ir::visit::collect_reads(&value, &mut sources);
            let loads = reads_memory(&value);
            let mut reads = 0usize;
            let mut use_at = None;
            let mut clobbered = false;
            let mut redefined = false;
            for position in index + 1..block.stmts.len() {
                let stmt = &block.stmts[position];
                if use_at.is_none()
                    && loads
                    && matches!(
                        stmt,
                        Stmt::Store { .. } | Stmt::Call { .. } | Stmt::Unsupported { .. }
                    )
                    && !statement_reads(stmt).contains(&dest)
                {
                    clobbered = true;
                    break;
                }
                let used = statement_reads(stmt);
                if used.contains(&dest) {
                    // Folding into two reads would duplicate the value.
                    reads += count_reg(stmt, dest);
                    use_at = Some(position);
                }
                let written = statement_registers(stmt).0;
                if written.contains(&dest) {
                    redefined = true;
                    break;
                }
                if written.intersection(&sources).next().is_some() {
                    clobbered = true;
                    break;
                }
            }
            // A later block may read the definition this block leaves behind.
            if !redefined && live_out[position].contains(&dest) {
                index += 1;
                continue;
            }
            let Some(use_at) = use_at else {
                index += 1;
                continue;
            };
            if reads != 1 || clobbered {
                index += 1;
                continue;
            }
            // Skip a reader that overwrites a register the value reads.
            if let Stmt::Assign { dest: reader, .. } = &block.stmts[use_at] {
                let mut reader_sources = std::collections::HashSet::new();
                crate::ir::visit::collect_reads(&value, &mut reader_sources);
                if reader_sources.contains(&reader.index) {
                    index += 1;
                    continue;
                }
            }
            let mut ok = true;
            substitute_in_statement(&mut block.stmts[use_at], dest, &value, &mut ok);
            if !ok {
                index += 1;
                continue;
            }
            block.stmts.remove(index);
        }
    }
}

/// The value a register of `width` bits holds once it is assigned `value`:
/// a narrow destination drops the high bits a sum or product may carry.
fn truncated(value: &Expr, width: u8) -> Expr {
    if width >= 64 || fits(value, width) {
        return value.clone();
    }
    Expr::bin(
        crate::ir::BinOp::And,
        value.clone(),
        Expr::Const((1u64 << width) - 1),
    )
}

/// True when the value provably has no bits at or above `width`.
fn fits(value: &Expr, width: u8) -> bool {
    match value {
        Expr::Reg { width: read, .. } => *read <= width,
        Expr::Const(constant) => constant >> width == 0,
        Expr::Load { width: bytes, .. } => u32::from(*bytes) * 8 <= u32::from(width),
        Expr::Bin {
            op: crate::ir::BinOp::And,
            lhs,
            rhs,
        } => fits(lhs, width) || fits(rhs, width),
        Expr::Bin {
            op: crate::ir::BinOp::Shr,
            lhs,
            ..
        } => fits(lhs, width),
        _ => false,
    }
}

fn reads_memory(expr: &Expr) -> bool {
    matches!(expr, Expr::Load { .. }) || children(expr).into_iter().any(reads_memory)
}

/// Replaces every read of `dest` in one statement with the value; clears `ok`
/// when a read's width does not fit the value's.
fn substitute_in_statement(stmt: &mut Stmt, dest: u16, value: &Expr, ok: &mut bool) {
    let width = expr_width(value).unwrap_or(64);
    match stmt {
        Stmt::Assign { value: target, .. } => substitute_reg_inner(target, dest, width, value, ok),
        Stmt::Store {
            addr,
            value: stored,
            ..
        } => {
            substitute_reg_inner(addr, dest, width, value, ok);
            substitute_reg_inner(stored, dest, width, value, ok);
        }
        Stmt::Brif { lhs, rhs, .. } => {
            substitute_reg_inner(lhs, dest, width, value, ok);
            substitute_reg_inner(rhs, dest, width, value, ok);
        }
        Stmt::Ret { value: returned } => substitute_reg_inner(returned, dest, width, value, ok),
        Stmt::Switch { index, .. } => substitute_reg_inner(index, dest, width, value, ok),
        Stmt::BrIndirect { target } => substitute_reg_inner(target, dest, width, value, ok),
        _ => *ok = false,
    }
}

/// Copy propagation: folds a single-use assignment (a register copy, a sign
/// extension or a small expression) into its only consumer when the widths
/// match, so no value is extended or truncated by accident.
pub fn copy_propagate(ir: &mut FunctionIr) {
    copy_propagate_with(ir, false);
}

/// Copy propagation for use after CSE: does not duplicate a compound value
/// into several reads of one consumer.
pub fn copy_propagate_guarded(ir: &mut FunctionIr) {
    copy_propagate_with(ir, true);
}

/// The registers each block reads.
fn block_reads(ir: &FunctionIr) -> Vec<std::collections::HashSet<u16>> {
    ir.blocks
        .iter()
        .map(|block| {
            block
                .stmts
                .iter()
                .flat_map(|stmt| statement_registers(stmt).1)
                .collect()
        })
        .collect()
}

/// The registers some block other than `index` reads.
fn reads_elsewhere(
    reads: &[std::collections::HashSet<u16>],
    index: usize,
) -> std::collections::HashSet<u16> {
    reads
        .iter()
        .enumerate()
        .filter(|(other, _)| *other != index)
        .flat_map(|(_, set)| set.iter().copied())
        .collect()
}

fn copy_propagate_with(ir: &mut FunctionIr, avoid_duplication: bool) {
    let reads = block_reads(ir);
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
        let mut outer = reads_elsewhere(&reads, index);
        if cyclic.contains(&index) {
            outer.extend(reads[index].iter().copied());
        }
        outer.extend(live_out[index].iter().copied());
        copy_propagate_block(block, &outer, avoid_duplication);
    }
}

fn copy_propagate_block(
    block: &mut crate::ir::Block,
    outer_reads: &std::collections::HashSet<u16>,
    avoid_duplication: bool,
) {
    let mut index = 0;
    while index < block.stmts.len() {
        let copy = match &block.stmts[index] {
            Stmt::Assign { dest, value } => {
                // A value of unknown width, such as a sign extension, takes
                // the destination's width.
                let fold_width = expr_width(value).unwrap_or(dest.width);
                let foldable = match value {
                    Expr::Reg { index: src, .. } => *src != dest.index,
                    Expr::SignExtend { .. } => true,
                    // A read outside the frame may be volatile, and a large
                    // expression hurts readability once inlined.
                    _ => !reads_outside_frame(value) && expr_size(value) <= 8,
                };
                foldable.then(|| (dest.index, fold_width, truncated(value, dest.width)))
            }
            _ => None,
        };
        let Some((dest, width, template)) = copy else {
            index += 1;
            continue;
        };
        // A read in another block keeps the temporary alive, unless this block
        // redefines it later so other blocks see that value instead.
        let redefined = block
            .stmts
            .iter()
            .skip(index + 1)
            .any(|stmt| statement_registers(stmt).0.contains(&dest));
        if outer_reads.contains(&dest) && !redefined {
            index += 1;
            continue;
        }
        // A value that reads its own destination cannot move.
        let mut sources: std::collections::HashSet<u16> = std::collections::HashSet::new();
        expr_reads(&template, &mut sources);
        if sources.contains(&dest) {
            index += 1;
            continue;
        }
        // Exactly one consumer, and no redefinition of the sources before it.
        let mut consumer = None;
        let mut foldable = true;
        for later in index + 1..block.stmts.len() {
            let (writes, reads) = statement_registers(&block.stmts[later]);
            let reads_dest = reads.contains(&dest);
            // The consumer may rewrite a source: it reads before it writes.
            if writes.iter().any(|written| sources.contains(written)) && !reads_dest {
                foldable = false;
                break;
            }
            if reads_dest {
                if consumer.is_some() {
                    foldable = false;
                    break;
                }
                consumer = Some(later);
            }
            if writes.contains(&dest) {
                break;
            }
        }
        let Some(consumer) = consumer else {
            index += 1;
            continue;
        };
        if !foldable {
            index += 1;
            continue;
        }
        // Removing the copy is safe when the consumer redefines the register
        // or nothing else reads it before its next definition.
        let rewrites_dest = match assign_of(&block.stmts[consumer]) {
            Some((dest_ref, _)) => dest_ref.index == dest,
            None => false,
        };
        let mut other_reads = block.stmts.iter().enumerate().any(|(position, stmt)| {
            position != consumer && position != index && statement_registers(stmt).1.contains(&dest)
        });
        if other_reads && !rewrites_dest {
            let mut escapes = false;
            for later in consumer + 1..block.stmts.len() {
                let (writes, reads) = statement_registers(&block.stmts[later]);
                if writes.contains(&dest) {
                    break;
                }
                if reads.contains(&dest) {
                    escapes = true;
                    break;
                }
            }
            other_reads = escapes;
        }
        if !rewrites_dest && other_reads {
            index += 1;
            continue;
        }
        // Inlining a compound value into two reads would undo CSE, and a
        // choice repeated reads as two.
        let reads_in_consumer = count_reg(&block.stmts[consumer], dest);
        if reads_in_consumer > 1
            && ((avoid_duplication && expr_size(&template) > 1) || contains_select(&template))
        {
            index += 1;
            continue;
        }
        if !substitute_stmt(&mut block.stmts[consumer], dest, width, &template) {
            index += 1;
            continue;
        }
        block.stmts.remove(index);
        // `index` now names the statement after the removed copy.
    }
}

fn contains_select(expr: &Expr) -> bool {
    matches!(expr, Expr::Select { .. })
        || crate::ir::visit::children(expr)
            .into_iter()
            .any(contains_select)
}

/// How many times a statement reads one register.
fn count_reg(stmt: &Stmt, reg: u16) -> usize {
    fn count(expr: &Expr, reg: u16) -> usize {
        match expr {
            Expr::Reg { index, .. } if *index == reg => 1,
            _ => children(expr)
                .into_iter()
                .map(|child| count(child, reg))
                .sum(),
        }
    }
    let mut total = 0;
    match stmt {
        Stmt::Assign { value, .. } => total += count(value, reg),
        Stmt::Store { addr, value, .. } => {
            total += count(addr, reg) + count(value, reg);
        }
        Stmt::Brif { lhs, rhs, .. } => total += count(lhs, reg) + count(rhs, reg),
        Stmt::Ret { value } => total += count(value, reg),
        Stmt::BrIndirect { target } => total += count(target, reg),
        Stmt::Call {
            convention,
            through,
            args,
            floats_named,
            ..
        } => {
            total += through.iter().map(|expr| count(expr, reg)).sum::<usize>();
            total += match args {
                Some(args) => args.iter().map(|arg| count(arg, reg)).sum::<usize>(),
                None => usize::from(
                    convention
                        .call_reads_through(through.as_ref(), *floats_named)
                        .contains(&reg),
                ),
            };
        }
        _ => {}
    }
    total
}

/// Number of expression nodes, used to keep inlining from exploding.
fn expr_size(expr: &Expr) -> usize {
    1 + children(expr).into_iter().map(expr_size).sum::<usize>()
}

fn substitute_stmt(stmt: &mut Stmt, dest: u16, width: u8, template: &Expr) -> bool {
    let mut ok = true;
    match stmt {
        Stmt::Assign { value, .. } => substitute_reg_inner(value, dest, width, template, &mut ok),
        Stmt::Store { addr, value, .. } => {
            substitute_reg_inner(addr, dest, width, template, &mut ok);
            substitute_reg_inner(value, dest, width, template, &mut ok);
        }
        Stmt::Brif { lhs, rhs, .. } => {
            substitute_reg_inner(lhs, dest, width, template, &mut ok);
            substitute_reg_inner(rhs, dest, width, template, &mut ok);
        }
        Stmt::Ret { value } => substitute_reg_inner(value, dest, width, template, &mut ok),
        Stmt::BrIndirect { target } => substitute_reg_inner(target, dest, width, template, &mut ok),
        // A call naming its arguments reads nothing else of them.
        Stmt::Call {
            through,
            args: Some(args),
            convention,
            floats_named,
            ..
        } if !convention.unnamed_reads(*floats_named).contains(&dest) => {
            for expr in through.iter_mut().chain(args.iter_mut()) {
                substitute_reg_inner(expr, dest, width, template, &mut ok);
            }
        }
        _ => ok = false,
    }
    ok
}

fn substitute_reg_inner(expr: &mut Expr, dest: u16, width: u8, template: &Expr, ok: &mut bool) {
    if !*ok {
        return;
    }
    if let Expr::Reg { index, width: read } = expr {
        if *index == dest {
            // A 32-bit value has a zero high half, so a wider read of the
            // register can take it too.
            let narrow_value = matches!(expr_width(template), Some(32));
            if *read != width && !(narrow_value && *read > 32 && width <= 32) {
                *ok = false;
                return;
            }
            *expr = template.clone();
        }
        return;
    }
    // A mask within 32 bits needs only the low bits, so a 32-bit value may
    // replace the masked register whatever the read's width.
    if let Expr::Bin {
        op: crate::ir::BinOp::And,
        lhs,
        rhs,
    } = expr
    {
        let mask = match rhs.as_ref() {
            Expr::Const(mask) => Some(*mask),
            _ => None,
        };
        if let Some(mask) = mask
            && mask <= 0xffff_ffff
            && matches!(lhs.as_ref(), Expr::Reg { index, .. } if *index == dest)
            && matches!(expr_width(template), Some(32))
        {
            let kept_mask = mask;
            *expr = Expr::bin(
                crate::ir::BinOp::And,
                template.clone(),
                Expr::constant(kept_mask),
            );
            return;
        }
    }
    match expr {
        Expr::Bin { lhs, rhs, .. } => {
            substitute_reg_inner(lhs, dest, width, template, ok);
            substitute_reg_inner(rhs, dest, width, template, ok);
        }
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => {
            substitute_reg_inner(lhs, dest, width, template, ok);
            substitute_reg_inner(rhs, dest, width, template, ok);
            substitute_reg_inner(then, dest, width, template, ok);
            substitute_reg_inner(els, dest, width, template, ok);
        }
        Expr::Load { addr, .. } => substitute_reg_inner(addr, dest, width, template, ok),
        Expr::SignExtend { value, .. } => substitute_reg_inner(value, dest, width, template, ok),
        Expr::Apply { args, .. } => {
            for arg in args {
                substitute_reg_inner(arg, dest, width, template, ok);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::{copy_propagate, inline_local_copies};
    use crate::ir::{BinOp, Block, Cond, Expr, FunctionIr, RegRef, Stmt};
    use crate::loader::Isa;

    #[test]
    fn a_folded_narrow_sum_keeps_its_truncation() {
        // eax = ecx + edx; return eax;
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: 0,
                        width: 32,
                    },
                    value: Expr::bin(BinOp::Add, Expr::reg(1, 32), Expr::reg(2, 32)),
                },
                Stmt::Ret {
                    value: Expr::reg(0, 32),
                },
            ],
        );

        copy_propagate(&mut ir);

        let sum = Expr::bin(BinOp::Add, Expr::reg(1, 32), Expr::reg(2, 32));
        let truncated = Expr::bin(BinOp::And, sum, Expr::Const(0xffff_ffff));
        assert!(
            matches!(ir.blocks[0].stmts.as_slice(), [Stmt::Ret { value }] if *value == truncated),
            "{}",
            ir.render()
        );
    }

    #[test]
    fn a_load_does_not_move_past_a_store() {
        let load = |index| Expr::Load {
            addr: Box::new(Expr::reg(index, 64)),
            width: 4,
            signed: false,
        };
        let assign = |index, value| Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
        };
        let store = |value, addr| Stmt::Store {
            addr: Expr::reg(addr, 64),
            value: Expr::reg(value, 64),
            width: 4,
        };
        // t = *a; *a = *b; *b = t;
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                assign(8, load(1)),
                assign(9, load(0)),
                store(8, 0),
                store(9, 1),
                Stmt::Ret {
                    value: Expr::Const(0),
                },
            ],
        );

        inline_local_copies(&mut ir);

        let stmts = &ir.blocks[0].stmts;
        let saved = stmts
            .iter()
            .position(|stmt| matches!(stmt, Stmt::Assign { dest, .. } if dest.index == 9));
        let overwritten = stmts
            .iter()
            .position(|stmt| matches!(stmt, Stmt::Store { addr, .. } if *addr == Expr::reg(0, 64)));
        assert!(
            saved.is_some_and(|saved| Some(saved) < overwritten),
            "the load of *a stays before the store to *a:\n{}",
            ir.render()
        );
    }

    #[test]
    fn keeps_a_definition_a_later_block_reads() {
        let load = Expr::Load {
            addr: Box::new(Expr::reg(1, 64)),
            width: 8,
            signed: false,
        };
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: 8,
                        width: 64,
                    },
                    value: load,
                },
                Stmt::Brif {
                    cond: Cond::Eq,
                    lhs: Expr::reg(8, 64),
                    rhs: Expr::Const(0),
                    target: 0x10,
                },
            ],
        );
        ir.blocks.push(Block {
            start: 0x8,
            stmts: vec![Stmt::Ret {
                value: Expr::reg(8, 64),
            }],
        });
        ir.blocks.push(Block {
            start: 0x10,
            stmts: vec![Stmt::Ret {
                value: Expr::Const(0),
            }],
        });

        inline_local_copies(&mut ir);

        assert!(
            matches!(ir.blocks[0].stmts[0], Stmt::Assign { dest, .. } if dest.index == 8),
            "{}",
            ir.render()
        );
    }

    #[test]
    fn inlines_a_masked_temporary() {
        let masked = |index| Expr::bin(BinOp::And, Expr::reg(index, 64), Expr::Const(0xffff_ffff));
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: 0,
                        width: 64,
                    },
                    value: masked(1),
                },
                Stmt::Assign {
                    dest: RegRef {
                        index: 2,
                        width: 64,
                    },
                    value: Expr::bin(BinOp::ModS, masked(0), masked(2)),
                },
                Stmt::Ret { value: masked(2) },
            ],
        );

        copy_propagate(&mut ir);

        assert!(
            !matches!(ir.blocks[0].stmts.first(), Some(Stmt::Assign { dest, .. }) if dest.index == 0),
            "the masked copy should inline: {:?}",
            ir.blocks[0].stmts
        );
    }
}

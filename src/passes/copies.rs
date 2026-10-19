use crate::ir::cfg::cyclic_blocks;
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
pub fn inline_local_copies(ir: &mut FunctionIr) {
    // In a loop the definition also feeds the next iteration, so folding it
    // would drop the update; only blocks outside every cycle are rewritten.
    let cyclic = cyclic_blocks(ir);
    for (position, block) in ir.blocks.iter_mut().enumerate() {
        if cyclic.contains(&position) {
            continue;
        }
        let mut index = 0;
        while index < block.stmts.len() {
            let Some((dest, value)) = (match &block.stmts[index] {
                Stmt::Assign { dest, value } => Some((dest.index, value.clone())),
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
            // The registers the value reads must not change before the use.
            let mut sources = std::collections::HashSet::new();
            crate::ir::visit::collect_reads(&value, &mut sources);
            let mut reads = 0usize;
            let mut use_at = None;
            let mut clobbered = false;
            for position in index + 1..block.stmts.len() {
                let stmt = &block.stmts[position];
                let used = statement_reads(stmt);
                if used.contains(&dest) {
                    // Folding into two reads would duplicate the value.
                    reads += count_reg(stmt, dest);
                    use_at = Some(position);
                }
                let written = statement_registers(stmt).0;
                if written.contains(&dest) {
                    break;
                }
                if written.intersection(&sources).next().is_some() {
                    clobbered = true;
                    break;
                }
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
        _ => {}
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

fn copy_propagate_with(ir: &mut FunctionIr, avoid_duplication: bool) {
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
                foldable.then(|| (dest.index, fold_width, value.clone()))
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
        // Inlining a compound value into two reads would undo CSE.
        let reads_in_consumer = count_reg(&block.stmts[consumer], dest);
        if avoid_duplication && reads_in_consumer > 1 && expr_size(&template) > 1 {
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
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::copy_propagate;
    use crate::ir::{BinOp, Expr, FunctionIr, RegRef, Stmt};
    use crate::loader::Isa;

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

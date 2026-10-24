use std::collections::HashSet;

use crate::ir::{Expr, FunctionIr, Stmt};
use crate::passes::frame_slots::{block_frames, frame_slot};

type Values = Vec<(i64, u8, Expr)>;

/// Forwards only exact scalar slots whose incoming values agree on every path.
pub(super) fn forward(ir: &mut FunctionIr) {
    let sp = crate::arch::stack_pointer(ir.isa);
    if ir.blocks.is_empty() || super::frame_address_escapes(ir, sp) {
        return;
    }
    let reached = crate::ir::cfg::reached(ir);
    let frames = block_frames(ir, sp);
    let counts = crate::render::structure::compare_chain::predecessors(ir);
    let mut incoming = vec![Vec::new(); ir.blocks.len()];
    let mut positions = vec![Vec::new(); ir.blocks.len()];
    let mut accesses = Vec::new();
    for (index, block) in ir.blocks.iter().enumerate() {
        let edges =
            crate::ir::cfg::block_successors_with_exceptions(&ir.blocks, index, &ir.landing_pads);
        if edges.unknown_normal || edges.unknown_exceptional || !edges.exceptional.is_empty() {
            return;
        }
        let exists = |target| ir.blocks.iter().any(|block| block.start == target);
        let unresolved = match block.stmts.last() {
            Some(
                Stmt::Br {
                    target: Some(target),
                }
                | Stmt::Brif { target, .. }
                | Stmt::BrifFlags { target, .. },
            ) => !exists(*target),
            Some(Stmt::Switch { cases, default, .. }) => {
                default.is_none_or(|target| !exists(target))
                    || cases.iter().any(|(_, target)| !exists(*target))
            }
            _ => false,
        };
        if unresolved {
            return;
        }
        for next in edges.normal {
            incoming[next].push(index);
        }
    }
    for (index, block) in ir.blocks.iter().enumerate() {
        if incoming[index].len() != counts.get(&block.start).copied().unwrap_or(0) {
            return;
        }
        incoming[index].retain(|from| reached.contains(&ir.blocks[*from].start));
    }
    for (index, block) in ir.blocks.iter().enumerate() {
        if !reached.contains(&block.start) {
            continue;
        }
        let edges =
            crate::ir::cfg::block_successors_with_exceptions(&ir.blocks, index, &ir.landing_pads);
        let Some(mut frame) = frames[index] else {
            return;
        };
        for stmt in &block.stmts {
            positions[index].push(frame);
            let mut loads = Vec::new();
            for operand in stmt.operands() {
                super::collect_loads(operand, &mut loads);
            }
            if let Stmt::Store { addr, width, .. } = stmt {
                loads.push((addr, *width));
            }
            for (addr, width) in loads {
                if let Some(offset) = frame_slot(addr, 0, sp) {
                    if !full_frame_register(addr, sp) {
                        return;
                    }
                    let Some(offset) = frame.checked_add(offset) else {
                        return;
                    };
                    let Some(end) = offset.checked_add(i64::from(width)) else {
                        return;
                    };
                    accesses.push((offset, end, width));
                }
            }
            if crate::ir::visit::statement_registers(stmt).0.contains(&sp) {
                let Stmt::Assign { dest, value } = stmt else {
                    return;
                };
                if dest.width != 64 || !full_frame_register(value, sp) {
                    return;
                }
                let Some(delta) = super::moved(value, sp) else {
                    return;
                };
                let Some(next) = frame.checked_add(delta) else {
                    return;
                };
                frame = next;
            }
        }
        for next in edges.normal {
            if frames[next] != Some(frame) || (next == 0 && frame != 0) {
                return;
            }
        }
    }
    accesses.sort_unstable();
    accesses.dedup();
    let slots: HashSet<_> = accesses
        .iter()
        .filter(|(offset, end, width)| {
            matches!(width, 1 | 2 | 4 | 8)
                && !accesses.iter().any(|(other, other_end, other_width)| {
                    (other != offset || other_width != width) && other < end && offset < other_end
                })
        })
        .map(|(offset, _, width)| (*offset, *width))
        .collect();
    if slots.is_empty() {
        return;
    }
    // None is the as-yet unconstrained state. The empty entry state forces
    // every retained value, including a loop invariant, to be initialized.
    let mut exits: Vec<Option<Values>> = vec![None; ir.blocks.len()];
    let entry_values = |index: usize, exits: &[Option<Values>]| {
        if index == 0 {
            return Some(Vec::new());
        }
        let mut known = incoming[index]
            .iter()
            .filter_map(|from| exits[*from].as_ref());
        let Some(first) = known.next() else {
            return None;
        };
        let mut values = first.clone();
        for other in known {
            values.retain(|value| other.contains(value));
        }
        Some(values)
    };
    loop {
        let mut changed = false;
        for (index, block) in ir.blocks.iter().enumerate() {
            if !reached.contains(&block.start) {
                continue;
            }
            let Some(mut values) = entry_values(index, &exits) else {
                continue;
            };
            for (stmt, frame) in block.stmts.iter().zip(&positions[index]) {
                transfer(stmt, *frame, sp, &slots, &mut values);
            }
            if exits[index].as_ref() != Some(&values) {
                exits[index] = Some(values);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    for (index, block) in ir.blocks.iter_mut().enumerate() {
        if !reached.contains(&block.start) {
            continue;
        }
        let Some(mut values) = entry_values(index, &exits) else {
            continue;
        };
        for (stmt, frame) in block.stmts.iter_mut().zip(&positions[index]) {
            let mut loads = Vec::new();
            for operand in stmt.operands() {
                super::collect_loads(operand, &mut loads);
            }
            let pending: Vec<_> = loads
                .iter()
                .filter_map(|(addr, width)| {
                    let offset = match frame_slot(addr, *frame, sp) {
                        Some(offset) => offset,
                        None => return None,
                    };
                    let Some((_, _, value)) = values.iter().find(|(stored, stored_width, _)| {
                        *stored == offset && stored_width == width
                    }) else {
                        return None;
                    };
                    let bits = width.saturating_mul(8);
                    let value = match value {
                        Expr::Reg { index, width } if *width >= bits => Expr::reg(*index, bits),
                        _ => value.clone(),
                    };
                    Some((*width, (*addr).clone(), value))
                })
                .collect();
            let comparison = match stmt {
                Stmt::Brif { cond, lhs, rhs, .. } => Some((
                    *cond,
                    crate::ir::semantics::operand_width(lhs, rhs),
                    lhs.clone(),
                    rhs.clone(),
                )),
                _ => None,
            };
            for operand in stmt.operands_mut() {
                forward_value(operand, &pending);
            }
            if let Some((cond, width, before_lhs, before_rhs)) = comparison
                && let Stmt::Brif { lhs, rhs, .. } = stmt
                && !crate::passes::copies::comparison_preserved(cond, width, lhs, rhs)
            {
                *lhs = before_lhs;
                *rhs = before_rhs;
            }
            invalidate(stmt, *frame, sp, &mut values);
        }
    }
}

fn forward_value(expr: &mut Expr, pending: &[(u8, Expr, Expr)]) {
    if let Expr::Load { addr, width, .. } = expr
        && pending
            .iter()
            .any(|(stored_width, stored, _)| stored_width == width && stored == addr.as_ref())
    {
        super::forward_expr(expr, pending);
        return;
    }
    let original = matches!(
        expr,
        Expr::Bin {
            op: crate::ir::BinOp::Sar | crate::ir::BinOp::DivS | crate::ir::BinOp::ModS,
            ..
        } | Expr::Select { .. }
    )
    .then(|| expr.clone());
    for child in crate::ir::visit::children_mut(expr) {
        forward_value(child, pending);
    }
    let Some(original) = original else { return };
    let preserved = match (&original, &*expr) {
        (
            Expr::Bin { lhs, rhs, .. },
            Expr::Bin {
                lhs: after_lhs,
                rhs: after_rhs,
                ..
            },
        ) => {
            crate::ir::semantics::operand_width(lhs, rhs)
                == crate::ir::semantics::operand_width(after_lhs, after_rhs)
        }
        (
            Expr::Select { cond, lhs, rhs, .. },
            Expr::Select {
                lhs: after_lhs,
                rhs: after_rhs,
                ..
            },
        ) => crate::passes::copies::comparison_preserved(
            *cond,
            crate::ir::semantics::operand_width(lhs, rhs),
            after_lhs,
            after_rhs,
        ),
        _ => true,
    };
    if !preserved {
        *expr = original;
    }
}

fn full_frame_register(expr: &Expr, sp: u16) -> bool {
    match expr {
        Expr::Reg { index, width } if *index == sp => *width == 64,
        _ => crate::ir::visit::children(expr)
            .into_iter()
            .all(|child| full_frame_register(child, sp)),
    }
}

fn transfer(stmt: &Stmt, frame: i64, sp: u16, slots: &HashSet<(i64, u8)>, values: &mut Values) {
    invalidate(stmt, frame, sp, values);
    let Stmt::Store { addr, value, width } = stmt else {
        return;
    };
    let Some(offset) = frame_slot(addr, frame, sp) else {
        return;
    };
    let mut reads = HashSet::new();
    crate::ir::visit::collect_reads(value, &mut reads);
    if slots.contains(&(offset, *width))
        && !crate::passes::copies::reads_memory(value)
        && !reads.contains(&sp)
    {
        values.push((offset, *width, value.clone()));
        values.sort_by_key(|(offset, width, _)| (*offset, *width));
    }
}

fn invalidate(stmt: &Stmt, frame: i64, sp: u16, values: &mut Values) {
    match stmt {
        Stmt::Call { .. } | Stmt::Unsupported { .. } => values.clear(),
        Stmt::Store { addr, .. } => {
            let Some(offset) = frame_slot(addr, frame, sp) else {
                values.clear();
                return;
            };
            values.retain(|(stored, _, _)| *stored != offset);
        }
        _ => {
            let writes = crate::ir::visit::statement_registers(stmt).0;
            values.retain(|(_, _, value)| {
                let mut reads = HashSet::new();
                crate::ir::visit::collect_reads(value, &mut reads);
                reads.is_disjoint(&writes)
            });
        }
    }
}

use std::collections::HashSet;

use crate::ir::{Expr, FunctionIr, Stmt};
use crate::passes::frame_slots::{block_entry_frame_offsets, frame_slot};

type Values = Vec<(i64, u8, Expr)>;

/// Forwards only exact scalar slots whose incoming values agree on every path.
pub(super) fn forward(ir: &mut FunctionIr) {
    forward_or_promote_frame_values(ir, false, &mut false, &[]);
}

pub(super) fn promote(ir: &mut FunctionIr) {
    let sp = crate::arch::stack_pointer(ir.isa);
    if ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .any(|stmt| {
            matches!(stmt, Stmt::Trap { .. })
                || matches!(stmt, Stmt::Assign { dest, value, .. } if dest.index == sp
                    && (dest.width != 64 || !full_frame_register(value, sp) || super::stack_pointer_delta(value, sp).is_none()))
        })
    {
        return;
    }
    // Settling removes stack adjustments, so retain each call's actual frame.
    let frames = block_entry_frame_offsets(ir, sp);
    let call_frames: Vec<Vec<Option<i64>>> = ir
        .blocks
        .iter()
        .zip(frames)
        .map(|(block, mut frame)| {
            let mut calls = Vec::new();
            for stmt in &block.stmts {
                if matches!(stmt, Stmt::Call { .. }) {
                    calls.push(frame);
                }
                if let Stmt::Assign { dest, value, .. } = stmt
                    && dest.index == sp
                {
                    frame = match (frame, super::stack_pointer_delta(value, sp)) {
                        (Some(frame), Some(delta)) => frame.checked_add(delta),
                        _ => None,
                    };
                }
            }
            calls
        })
        .collect();
    let mut normalized = ir.clone();
    crate::passes::frame_slots::settle(&mut normalized);
    let mut promoted = false;
    forward_or_promote_frame_values(&mut normalized, true, &mut promoted, &call_frames);
    if promoted {
        *ir = normalized;
    }
}

struct FrameAccesses {
    sp: u16,
    reached: HashSet<u64>,
    incoming: Vec<Vec<usize>>,
    positions: Vec<Vec<i64>>,
    slots: HashSet<(i64, u8)>,
}

fn validated_accesses(ir: &FunctionIr) -> Option<FrameAccesses> {
    let sp = crate::arch::stack_pointer(ir.isa);
    if ir.blocks.is_empty() || super::frame_address_escapes(ir, sp) {
        return None;
    }
    let reached = crate::ir::cfg::reached(ir);
    let frames = block_entry_frame_offsets(ir, sp);
    let counts = crate::render::structure::compare_chain::predecessor_counts(ir);
    let mut incoming = vec![Vec::new(); ir.blocks.len()];
    let mut positions = vec![Vec::new(); ir.blocks.len()];
    let mut accesses = Vec::new();
    for (index, block) in ir.blocks.iter().enumerate() {
        let edges =
            crate::ir::cfg::block_successors_with_exceptions(&ir.blocks, index, &ir.landing_pads);
        if edges.unknown_normal || edges.unknown_exceptional || !edges.exceptional.is_empty() {
            return None;
        }
        let exists = |target| ir.blocks.iter().any(|block| block.start == target);
        let unresolved = match block.stmts.last() {
            Some(
                Stmt::Br {
                    target: Some(target),
                    ..
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
            return None;
        }
        for next in edges.normal {
            incoming[next].push(index);
        }
    }
    for (index, block) in ir.blocks.iter().enumerate() {
        if incoming[index].len() != counts.get(&block.start).copied().unwrap_or(0) {
            return None;
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
            return None;
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
                        return None;
                    }
                    let Some(offset) = frame.checked_add(offset) else {
                        return None;
                    };
                    let Some(end) = offset.checked_add(i64::from(width)) else {
                        return None;
                    };
                    accesses.push((offset, end, width));
                }
            }
            if crate::ir::visit::statement_registers(stmt).0.contains(&sp) {
                let Stmt::Assign { dest, value, .. } = stmt else {
                    return None;
                };
                if dest.width != 64 || !full_frame_register(value, sp) {
                    return None;
                }
                let Some(delta) = super::stack_pointer_delta(value, sp) else {
                    return None;
                };
                let Some(next) = frame.checked_add(delta) else {
                    return None;
                };
                frame = next;
            }
        }
        for next in edges.normal {
            if frames[next] != Some(frame) || (next == 0 && frame != 0) {
                return None;
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
        return None;
    }
    Some(FrameAccesses {
        sp,
        reached,
        incoming,
        positions,
        slots,
    })
}

fn forward_or_promote_frame_values(
    ir: &mut FunctionIr,
    promotion: bool,
    promoted: &mut bool,
    call_frames: &[Vec<Option<i64>>],
) {
    let Some(FrameAccesses {
        sp,
        reached,
        incoming,
        positions,
        slots,
    }) = validated_accesses(ir)
    else {
        return;
    };
    if promotion {
        *promoted = promote_slots(ir, &positions, &incoming, &reached, &slots, call_frames);
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
                    let Some(offset) = frame_slot(addr, *frame, sp) else {
                        return None;
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

fn promote_slots(
    ir: &mut FunctionIr,
    positions: &[Vec<i64>],
    incoming: &[Vec<usize>],
    reached: &HashSet<u64>,
    slots: &HashSet<(i64, u8)>,
    call_frames: &[Vec<Option<i64>>],
) -> bool {
    let sp = crate::arch::stack_pointer(ir.isa);
    // Unknown writes may reach the frame through an address we cannot resolve.
    if ir.blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
        let mut loads = Vec::new();
        for operand in stmt.operands() {
            super::collect_loads(operand, &mut loads);
        }
        matches!(stmt, Stmt::Unsupported { .. })
            || matches!(stmt, Stmt::Store { addr, .. } if frame_slot(addr, 0, sp).is_none())
            || loads
                .iter()
                .any(|(addr, _)| frame_slot(addr, 0, sp).is_none())
    }) {
        return false;
    }
    let mut used = HashSet::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        let (writes, reads) = crate::ir::visit::statement_registers(stmt);
        used.extend(writes);
        used.extend(reads);
    }
    let mut free =
        (crate::ir::TEMP_BASE..crate::ir::VARIABLE_BASE).filter(|index| !used.contains(index));
    let mut selected = Vec::new();
    let mut ordered: Vec<_> = slots.iter().copied().collect();
    ordered.sort_unstable();
    for (offset, width) in ordered {
        if !super::private_slot(offset, width, super::spill_range(ir)) {
            continue;
        }
        if ir.blocks.iter().enumerate().any(|(index, block)| {
            block
                .stmts
                .iter()
                .filter(|stmt| matches!(stmt, Stmt::Call { .. }))
                .zip(&call_frames[index])
                .any(|(stmt, frame)| {
                    frame.is_none_or(|frame| !call_preserves_slot(ir, stmt, frame, offset, sp))
                })
        }) {
            continue;
        }
        let mut initialized = vec![true; ir.blocks.len()];
        loop {
            let mut changed = false;
            for (index, block) in ir.blocks.iter().enumerate() {
                if !reached.contains(&block.start) {
                    continue;
                }
                let entry = index != 0
                    && !incoming[index].is_empty()
                    && incoming[index].iter().all(|from| initialized[*from]);
                let stored = block
                    .stmts
                    .iter()
                    .zip(&positions[index])
                    .any(|(stmt, frame)| {
                        matches!(stmt, Stmt::Store { addr, width: bytes, .. }
                        if *bytes == width && frame_slot(addr, *frame, sp) == Some(offset))
                    });
                let exit = entry || stored;
                changed |= initialized[index] != exit;
                initialized[index] = exit;
            }
            if !changed {
                break;
            }
        }
        let safe = ir.blocks.iter().enumerate().all(|(index, block)| {
            if !reached.contains(&block.start) {
                return true;
            }
            let mut defined = index != 0
                && !incoming[index].is_empty()
                && incoming[index].iter().all(|from| initialized[*from]);
            for (stmt, frame) in block.stmts.iter().zip(&positions[index]) {
                let mut loads = Vec::new();
                for operand in stmt.operands() {
                    super::collect_loads(operand, &mut loads);
                }
                if !defined
                    && loads.iter().any(|(addr, bytes)| {
                        *bytes == width && frame_slot(addr, *frame, sp) == Some(offset)
                    })
                {
                    return false;
                }
                if matches!(stmt, Stmt::Store { addr, width: bytes, .. }
                    if *bytes == width && frame_slot(addr, *frame, sp) == Some(offset))
                {
                    defined = true;
                }
            }
            true
        });
        if safe {
            let Some(register) = free.next() else {
                break;
            };
            selected.push((offset, width, register));
        }
    }
    if selected.is_empty() {
        return false;
    }
    for (index, block) in ir.blocks.iter_mut().enumerate() {
        for (stmt, frame) in block.stmts.iter_mut().zip(&positions[index]) {
            let mut loads = Vec::new();
            for operand in stmt.operands() {
                super::collect_loads(operand, &mut loads);
            }
            let pending: Vec<_> = loads
                .iter()
                .filter_map(|(addr, width)| {
                    let Some(offset) = frame_slot(addr, *frame, sp) else {
                        return None;
                    };
                    selected
                        .iter()
                        .find(|(slot, bytes, _)| *slot == offset && bytes == width)
                        .map(|(_, _, register)| {
                            (
                                *width,
                                (*addr).clone(),
                                Expr::reg(*register, width.saturating_mul(8)),
                            )
                        })
                })
                .collect();
            for operand in stmt.operands_mut() {
                super::forward_expr(operand, &pending);
            }
            if let Stmt::Store {
                addr,
                value,
                width,
                at,
            } = stmt
                && let Some((_, _, register)) = selected.iter().find(|(offset, bytes, _)| {
                    bytes == width && frame_slot(addr, *frame, sp) == Some(*offset)
                })
            {
                *stmt = Stmt::Assign {
                    dest: crate::ir::RegRef {
                        index: *register,
                        width: width.saturating_mul(8),
                    },
                    value: crate::passes::copies::truncated(value, width.saturating_mul(8)),
                    at: *at,
                };
            }
        }
    }
    let registers: Vec<_> = selected.iter().map(|(_, _, register)| *register).collect();
    crate::ssa::split_variables(ir, &registers);
    if call_frames.iter().any(|calls| !calls.is_empty()) {
        for (variable, source) in &ir.variable_registers {
            if let Some((_, width, _)) = selected.iter().find(|(_, _, register)| register == source)
            {
                ir.value_types.insert(
                    *variable,
                    crate::ir::CType::Int {
                        bytes: *width,
                        signed: false,
                    },
                );
            }
        }
    }
    true
}

fn call_preserves_slot(ir: &FunctionIr, stmt: &Stmt, frame: i64, offset: i64, sp: u16) -> bool {
    use crate::ir::{CallKind, Convention};
    let Stmt::Call {
        kind,
        convention,
        args,
        ..
    } = stmt
    else {
        return true;
    };
    if kind.push_bytes(ir.isa, *convention).is_none() {
        return false;
    }
    if *kind == CallKind::Syscall {
        return true;
    }
    // The call and callee may overwrite memory below the caller's stack
    // pointer, including this function's red zone.
    let Some(relative) = offset.checked_sub(frame) else {
        return false;
    };
    if relative < 0 {
        return false;
    }
    let Some(args) = args else {
        return false;
    };
    let start = match convention {
        Convention::SysV | Convention::Aapcs64 | Convention::Win64 => convention.stack_arguments(),
        _ => return false,
    };
    let Some(mut reserved) = start.and_then(|start| kind.stack_offset(ir.isa, *convention, start))
    else {
        return false;
    };
    for argument in args.iter().skip(convention.arguments().len()) {
        let Expr::Load { addr, width, .. } = argument else {
            return false;
        };
        if !matches!(width, 1 | 2 | 4 | 8) {
            return false;
        }
        let Some(start) = frame_slot(addr, 0, sp) else {
            return false;
        };
        let Some(end) = start.checked_add(8).and_then(|end| end.checked_sub(frame)) else {
            return false;
        };
        reserved = reserved.max(end);
    }
    relative >= reserved
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

pub(super) fn full_frame_register(expr: &Expr, sp: u16) -> bool {
    match expr {
        Expr::Reg { index, width } if *index == sp => *width == 64,
        _ => crate::ir::visit::children(expr)
            .into_iter()
            .all(|child| full_frame_register(child, sp)),
    }
}

fn transfer(stmt: &Stmt, frame: i64, sp: u16, slots: &HashSet<(i64, u8)>, values: &mut Values) {
    invalidate(stmt, frame, sp, values);
    let Stmt::Store {
        addr, value, width, ..
    } = stmt
    else {
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
        Stmt::Machine {
            instruction:
                crate::ir::MachineInstruction::ArmCacheZero
                | crate::ir::MachineInstruction::ArmExclusive { .. },
            ..
        } => values.clear(),
        Stmt::Call { .. } | Stmt::Unsupported { .. } => values.clear(),
        Stmt::Store { addr, .. } => {
            let Some(offset) = frame_slot(addr, frame, sp) else {
                values.clear();
                return;
            };
            values.retain(|(stored, _, _)| *stored != offset);
        }
        _ => {
            if super::memory_ordering_barrier(stmt) {
                values.retain(|(offset, width, _)| {
                    offset
                        .checked_add(i64::from(*width))
                        .is_some_and(|end| end <= 0)
                });
            }
            let writes = crate::ir::visit::statement_registers(stmt).0;
            values.retain(|(_, _, value)| {
                let mut reads = HashSet::new();
                crate::ir::visit::collect_reads(value, &mut reads);
                writes.iter().all(|register| !reads.contains(register))
            });
        }
    }
}

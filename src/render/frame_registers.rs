//! Addresses of locals a register carries, written as the stack pointer
//! plus an offset. Code that keeps the address of a local in a register and reaches
//! the local's bytes through it at offsets reads, once printed, as an access
//! through a pointer to that local; the slots it reaches are then not seen
//! as part of the local, and the printed object is too small for them.
//! Unoptimized code with a large frame also keeps such an address in a
//! frame slot of its own and loads it back before each use.

use std::collections::HashSet;

use super::stack_bytes::{Origins, origin, origins, transfer};
use crate::ir::{BinOp, Convention, Expr, FunctionIr, Stmt};

/// Rewrites each value that a register holding the address of a local, plus
/// or minus constants, computes into the stack pointer plus an offset.
/// A variadic function's register save area is left alone: its end, which
/// the argument list points at, names the area and not the slot above it.
/// Only the C conventions are taken: a callee under another may write its
/// results into the caller's frame.
pub(super) fn rebase(ir: &mut FunctionIr) {
    if ir.blocks.is_empty()
        || ir.variadic
        || !matches!(
            ir.convention,
            Convention::SysV | Convention::Win64 | Convention::Aapcs64
        )
    {
        return;
    }
    let sp = crate::arch::stack_pointer(ir.isa);
    unspill(ir, sp);
    let Some(entries) = origins(ir, &Origins::from([(sp, Some(0))])) else {
        return;
    };
    for (block, entry) in ir.blocks.iter_mut().zip(entries) {
        let Some(mut state) = entry else {
            continue;
        };
        for stmt in &mut block.stmts {
            let original = stmt.clone();
            let moves_sp = matches!(stmt, Stmt::Assign { dest, .. } if dest.index == sp);
            if !moves_sp && let Some(Some(frame)) = state.get(&sp).copied() {
                for value in stmt.operands_mut() {
                    rebase_value(value, &state, sp, frame, true);
                }
            }
            transfer(&original, &mut state);
        }
    }
    drop_unread_frame_addresses(ir, sp);
}

pub(super) fn drop_unused_adjustments(body: &mut String, name: &str) {
    let search = super::variables::WordSearch::new(name);
    let adjustment = |line: &str| {
        let words: Vec<_> = line.split_whitespace().collect();
        let [dest, "=", source, "+" | "-", delta] = words.as_slice() else {
            return false;
        };
        let Some(delta) = delta.strip_suffix(';') else {
            return false;
        };
        let constant = match delta.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16).is_ok(),
            None => delta.parse::<u64>().is_ok(),
        };
        *dest == name && *source == name && constant
    };
    if body
        .lines()
        .any(|line| search.contains(line) && !adjustment(line))
    {
        return;
    }
    let mut retained = String::new();
    for line in body.lines() {
        if !adjustment(line) {
            retained.push_str(line);
            retained.push('\n');
        }
    }
    *body = retained;
}

/// Drops the assignments of local addresses to variables nothing reads
/// once their uses are rewritten: such an address goes nowhere, and kept,
/// it would count as one taken.
fn drop_unread_frame_addresses(ir: &mut FunctionIr, sp: u16) {
    let statements = || ir.blocks.iter().flat_map(|block| &block.stmts);
    if statements().any(|stmt| matches!(stmt, Stmt::Unsupported { .. })) {
        return;
    }
    let read: HashSet<u16> = statements()
        .flat_map(|stmt| crate::ir::visit::statement_registers(stmt).1)
        .collect();
    let unread = |register: u16| {
        crate::ir::is_temp(register)
            && !read.contains(&register)
            && !ir
                .variable_registers
                .get(&register)
                .is_some_and(|physical| read.contains(physical))
    };
    let dropped: HashSet<u16> = statements()
        .filter_map(|stmt| match stmt {
            Stmt::Assign { dest, value }
                if dest.width == 64 && base_register(value) == Some(sp) && unread(dest.index) =>
            {
                Some(dest.index)
            }
            _ => None,
        })
        .collect();
    for block in &mut ir.blocks {
        block.stmts.retain(|stmt| {
            !matches!(stmt, Stmt::Assign { dest, value }
                if dropped.contains(&dest.index) && base_register(value) == Some(sp))
        });
    }
}

/// Only where the value is used as an address: a whole operand, a load or
/// store address, or the base of a constant offset from one. Elsewhere, as under a
/// mask, the stack pointer could not be named as a local.
fn rebase_value(expr: &mut Expr, state: &Origins, sp: u16, frame: i64, pointer: bool) {
    let stack_pointer_expression = match expr {
        Expr::Reg { index, width: 64 } => *index == sp,
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => matches!(
            (lhs.as_ref(), rhs.as_ref()),
            (Expr::Reg { index, width: 64 }, Expr::Const(_)) if *index == sp
        ),
        _ => false,
    };
    if pointer
        && !stack_pointer_expression
        && base_register(expr).is_some()
        && let Some(Some(offset)) = origin(expr, state)
        && offset < 0
        && let Some(delta) = offset.checked_sub(frame)
    {
        *expr = frame_address(sp, delta);
        return;
    }
    match expr {
        Expr::Load { addr, .. } => rebase_value(addr, state, sp, frame, true),
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => {
            rebase_value(lhs, state, sp, frame, pointer);
            rebase_value(rhs, state, sp, frame, pointer);
        }
        other => {
            for child in crate::ir::visit::children_mut(other) {
                rebase_value(child, state, sp, frame, false);
            }
        }
    }
}

fn frame_address(sp: u16, delta: i64) -> Expr {
    if delta == 0 {
        Expr::reg(sp, 64)
    } else {
        Expr::bin(BinOp::Add, Expr::reg(sp, 64), Expr::Const(delta as u64))
    }
}

/// Replaces each load of a local slot that only ever holds one local's
/// address, stored there whole and read back whole, by that address. The
/// stores stay, as a callee may read the slot as an argument. Nothing takes
/// the slot's address, so only a store at an unknown place in the frame
/// could change it, and none may be present.
fn unspill(ir: &mut FunctionIr, sp: u16) {
    let Some(entries) = origins(ir, &Origins::from([(sp, Some(0))])) else {
        return;
    };
    // Every access at a known frame offset, with its width and, for a
    // store, the frame address it stores.
    let mut accesses: Vec<(i64, u8, Option<Option<i64>>)> = Vec::new();
    let mut taken: HashSet<i64> = HashSet::new();
    for (block, entry) in ir.blocks.iter().zip(&entries) {
        let Some(mut state) = entry.clone() else {
            continue;
        };
        for stmt in &block.stmts {
            match stmt {
                Stmt::Store { addr, value, width } => match origin(addr, &state) {
                    Some(Some(offset)) => {
                        accesses.push((offset, *width, Some(origin(value, &state).flatten())));
                    }
                    Some(None) => return,
                    None => {}
                },
                Stmt::Unsupported { .. } => return,
                _ => {}
            }
            for value in stmt.operands() {
                let address = matches!(stmt, Stmt::Store { addr, .. } if std::ptr::eq(value, addr));
                frame_uses(
                    value,
                    &state,
                    if address {
                        OperandUse::Address
                    } else {
                        OperandUse::Value
                    },
                    /* pointer */ true,
                    &mut accesses,
                    &mut taken,
                );
            }
            transfer(stmt, &mut state);
        }
    }
    let mut spills: std::collections::HashMap<i64, i64> = std::collections::HashMap::new();
    for (offset, width, stored) in &accesses {
        let Some(Some(target)) = stored else {
            continue;
        };
        if *width != 8 || *offset >= 0 || *target >= 0 || taken.contains(offset) {
            continue;
        }
        let has_exclusive_access = accesses.iter().all(|(other, other_width, other_stored)| {
            let overlaps =
                *other < offset + 8 && other.saturating_add(i64::from(*other_width)) > *offset;
            !overlaps
                || (*other == *offset
                    && *other_width == 8
                    && other_stored.is_none_or(|value| value == Some(*target)))
        });
        if has_exclusive_access {
            spills.insert(*offset, *target);
        }
    }
    if spills.is_empty() {
        return;
    }
    for (block, entry) in ir.blocks.iter_mut().zip(entries) {
        let Some(mut state) = entry else {
            continue;
        };
        for stmt in &mut block.stmts {
            let original = stmt.clone();
            if let Some(Some(frame)) = state.get(&sp).copied() {
                for value in stmt.operands_mut() {
                    reload(value, &state, &spills, sp, frame, true);
                }
            }
            transfer(&original, &mut state);
        }
    }
}

#[derive(Clone, Copy)]
enum OperandUse {
    Address,
    Value,
}

/// Notes the frame offsets an operand loads from, and those whose address
/// it takes as a value rather than to load through. A slot loaded where
/// its value could not be rewritten as an address, as under a mask, counts
/// as taken: it stays as it is.
fn frame_uses(
    expr: &Expr,
    state: &Origins,
    address: OperandUse,
    pointer: bool,
    accesses: &mut Vec<(i64, u8, Option<Option<i64>>)>,
    taken: &mut HashSet<i64>,
) {
    let address = matches!(address, OperandUse::Address);
    if let Expr::Load { addr, width, .. } = expr {
        if let Some(Some(offset)) = origin(addr, state) {
            accesses.push((offset, *width, None));
            if !pointer {
                taken.insert(offset);
            }
            return;
        }
        frame_uses(
            addr,
            state,
            OperandUse::Address,
            /* pointer */ true,
            accesses,
            taken,
        );
        return;
    }
    if !address && let Some(Some(offset)) = origin(expr, state) {
        taken.insert(offset);
        return;
    }
    let constant_offset = matches!(expr, Expr::Bin { op: BinOp::Add, lhs, rhs }
        if matches!(lhs.as_ref(), Expr::Const(_)) || matches!(rhs.as_ref(), Expr::Const(_)));
    for child in crate::ir::visit::children(expr) {
        frame_uses(
            child,
            state,
            OperandUse::Value,
            pointer && constant_offset,
            accesses,
            taken,
        );
    }
}

fn reload(
    expr: &mut Expr,
    state: &Origins,
    spills: &std::collections::HashMap<i64, i64>,
    sp: u16,
    frame: i64,
    pointer: bool,
) {
    if pointer
        && let Expr::Load { addr, width: 8, .. } = expr
        && let Some(Some(offset)) = origin(addr, state)
        && let Some(target) = spills.get(&offset)
        && let Some(delta) = target.checked_sub(frame)
    {
        *expr = frame_address(sp, delta);
        return;
    }
    let pointer = match expr {
        Expr::Load { .. } => true,
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => {
            pointer
                && (matches!(lhs.as_ref(), Expr::Const(_))
                    || matches!(rhs.as_ref(), Expr::Const(_)))
        }
        _ => false,
    };
    for child in crate::ir::visit::children_mut(expr) {
        reload(child, state, spills, sp, frame, pointer);
    }
}

/// The register a sum or difference of one register and constants starts
/// from.
fn base_register(expr: &Expr) -> Option<u16> {
    match expr {
        Expr::Reg { index, width: 64 } => Some(*index),
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (value, Expr::Const(_)) | (Expr::Const(_), value) => base_register(value),
            _ => None,
        },
        Expr::Bin {
            op: BinOp::Sub,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(_)) => base_register(lhs),
        _ => None,
    }
}

//! Stack result storage and use under the Go assembly ABI.

use std::collections::HashSet;

use super::Summaries;
use crate::ir::{Block, Convention, Expr, Stmt};
use crate::loader::Image;

/// What a call to `target` under Go's assembly ABI leaves past its stack
/// arguments: its results, stored from the registers the convention moves
/// them through, so the caller's loads of them read the call's results.
pub(crate) fn stack_results(image: &Image, summaries: Summaries<'_>, target: u64) -> Vec<Stmt> {
    let convention = image.convention_of(target);
    if convention != Convention::GoAbi0 {
        return Vec::new();
    }
    let sp = crate::arch::stack_pointer(image.isa);
    summaries(target)
        .stack_results
        .iter()
        .take_while(|(_, width)| *width != 0)
        .zip(convention.results())
        .map(|((offset, width), register)| Stmt::Store {
            // Addressed as the caller's own loads of it are.
            addr: match offset {
                0 => Expr::reg(sp, 64),
                _ => Expr::bin(
                    crate::ir::BinOp::Add,
                    Expr::reg(sp, 64),
                    Expr::Const(u64::from(*offset)),
                ),
            },
            value: Expr::reg(*register, 64),
            width: *width,
        })
        .collect()
}

/// The offset from the stack pointer an address is, in the forms the lifter
/// writes: `sp` and `sp + k`.
fn stack_offset(addr: &Expr, sp: u16) -> Option<u64> {
    match addr {
        Expr::Reg { index, width: 64 } if *index == sp => Some(0),
        Expr::Bin {
            op: crate::ir::BinOp::Add,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Reg { index, width: 64 }, Expr::Const(offset)) if *index == sp => Some(*offset),
            _ => None,
        },
        _ => None,
    }
}

/// A caller of Go's assembly ABI reads the results right after the call.
/// Each such read of a whole result in the call's block takes the register
/// `stack_results` stored it from, while that still holds it. The store
/// goes when no later read may see it, on any path from the call.
pub(super) fn take_stack_results(blocks: &mut [Block], image: &Image, summaries: Summaries<'_>) {
    let sp = crate::arch::stack_pointer(image.isa);
    for index in 0..blocks.len() {
        let mut at = 0;
        while at < blocks[index].stmts.len() {
            let stmts = &mut blocks[index].stmts;
            let Stmt::Call {
                target: Some(target),
                convention: Convention::GoAbi0,
                ..
            } = stmts[at]
            else {
                at += 1;
                continue;
            };
            let stored = stack_results(image, summaries, target).len();
            // Offset, width and register of each result.
            let fields: Vec<(u64, u8, u16)> = stmts
                .get(at + 1..at + 1 + stored)
                .unwrap_or_default()
                .iter()
                .filter_map(|stmt| match stmt {
                    Stmt::Store {
                        addr,
                        value: Expr::Reg { index, .. },
                        width,
                    } => Some((stack_offset(addr, sp)?, *width, *index)),
                    _ => None,
                })
                .collect();
            if fields.len() != stored {
                at += 1;
                continue;
            }
            // Whether the register still holds each result, and whether
            // the slot does, so that a later read may see it.
            let mut held = vec![true; stored];
            let mut open = vec![true; stored];
            let mut needed = vec![false; stored];
            // How far the stack pointer has moved since the call.
            let mut moved = Some(0u64);
            for stmt in &mut stmts[at + 1 + stored..] {
                let Some(delta) = moved else {
                    break;
                };
                for operand in stmt.operands_mut() {
                    take_result_reads(operand, sp, delta, &fields, &held, &open, &mut needed);
                }
                let written = crate::ir::visit::statement_registers(stmt).0;
                moved = stack_moved(stmt, sp, delta);
                for (position, field) in fields.iter().enumerate() {
                    if written.contains(&field.2) {
                        held[position] = false;
                    }
                    if let Some(covers) = stored_over(stmt, sp, delta, *field)
                        && open[position]
                    {
                        // Overwritten in part, the rest may still be read.
                        needed[position] |= !covers;
                        open[position] = false;
                    }
                }
            }
            for (position, field) in fields.iter().enumerate() {
                if open[position] && !needed[position] {
                    // Past an unknown move of the stack pointer, the slot is
                    // out of sight.
                    needed[position] = match moved {
                        None => true,
                        Some(delta) => {
                            ends_unknown(blocks, index)
                                || read_later(
                                    blocks,
                                    &crate::ir::cfg::block_successors(blocks, index),
                                    sp,
                                    delta,
                                    *field,
                                )
                        }
                    };
                }
            }
            let mut position = 0;
            blocks[index].stmts.retain(|_| {
                let index = position;
                position += 1;
                !(at < index && index <= at + stored) || needed[index - at - 1]
            });
            at += 1;
        }
    }
}

/// Replaces the loads of a whole result whose register still holds it with
/// that register, and notes the results other loads may read.
fn take_result_reads(
    expr: &mut Expr,
    sp: u16,
    delta: u64,
    fields: &[(u64, u8, u16)],
    held: &[bool],
    open: &[bool],
    needed: &mut [bool],
) {
    if let Expr::Load {
        addr,
        width,
        signed,
    } = expr
        && let Some(offset) = stack_offset(addr, sp)
    {
        let offset = offset.wrapping_add(delta);
        let (width, signed) = (*width, *signed);
        for (position, field) in fields.iter().enumerate() {
            if !open[position] || !overlaps((offset, width), *field) {
                continue;
            }
            if held[position] && (offset, width) == (field.0, field.1) {
                let register = Expr::reg(field.2, 8 * width);
                *expr = match signed {
                    true => Expr::SignExtend {
                        value: Box::new(register),
                        width,
                    },
                    false => register,
                };
                return;
            }
            needed[position] = true;
        }
    }
    for child in crate::ir::visit::children_mut(expr) {
        take_result_reads(child, sp, delta, fields, held, open, needed);
    }
}

fn overlaps((offset, width): (u64, u8), field: (u64, u8, u16)) -> bool {
    offset < field.0 + u64::from(field.1) && field.0 < offset + u64::from(width)
}

/// Whether the statement stores over the field, and then whether it covers
/// all of it.
fn stored_over(stmt: &Stmt, sp: u16, delta: u64, field: (u64, u8, u16)) -> Option<bool> {
    let Stmt::Store { addr, width, .. } = stmt else {
        return None;
    };
    let offset = stack_offset(addr, sp)?.wrapping_add(delta);
    overlaps((offset, *width), field)
        .then(|| offset <= field.0 && field.0 + u64::from(field.1) <= offset + u64::from(*width))
}

/// How far the stack pointer has moved after the statement, from `delta`
/// before it; `None` once that is unknown.
fn stack_moved(stmt: &Stmt, sp: u16, delta: u64) -> Option<u64> {
    if let Stmt::Assign { dest, value } = stmt
        && dest.index == sp
    {
        return match value {
            Expr::Bin { op, lhs, rhs } if stack_offset(lhs, sp) == Some(0) => {
                match (op, rhs.as_ref()) {
                    (crate::ir::BinOp::Add, Expr::Const(by)) => Some(delta.wrapping_add(*by)),
                    (crate::ir::BinOp::Sub, Expr::Const(by)) => Some(delta.wrapping_sub(*by)),
                    _ => None,
                }
            }
            _ => None,
        };
    }
    (!crate::ir::visit::statement_registers(stmt).0.contains(&sp)).then_some(delta)
}

/// Whether the block may go on to code not lifted with it.
fn ends_unknown(blocks: &[Block], index: usize) -> bool {
    let known = |target: &u64| blocks.iter().any(|block| block.start == *target);
    match blocks[index].stmts.last() {
        Some(Stmt::Br { target: None } | Stmt::BrIndirect { .. }) => true,
        Some(Stmt::Br {
            target: Some(target),
        }) => !known(target),
        Some(Stmt::Brif { target, .. } | Stmt::BrifFlags { target, .. }) => {
            !known(target) || index + 1 == blocks.len()
        }
        Some(Stmt::Ret { .. } | Stmt::Trap | Stmt::Switch { .. }) => false,
        _ => index + 1 == blocks.len(),
    }
}

/// Whether some path through the blocks from `starts` may load the field
/// before storing over all of it or returning, with the stack pointer
/// `delta` past where the call left it and moved only by constants.
fn read_later(
    blocks: &[Block],
    starts: &[usize],
    sp: u16,
    delta: u64,
    field: (u64, u8, u16),
) -> bool {
    fn reads(expr: &Expr, sp: u16, delta: u64, field: (u64, u8, u16)) -> bool {
        if let Expr::Load { addr, width, .. } = expr
            && stack_offset(addr, sp)
                .is_some_and(|offset| overlaps((offset.wrapping_add(delta), *width), field))
        {
            return true;
        }
        crate::ir::visit::children(expr)
            .into_iter()
            .any(|child| reads(child, sp, delta, field))
    }
    let mut seen = HashSet::new();
    let mut work: Vec<(usize, u64)> = starts.iter().map(|index| (*index, delta)).collect();
    'blocks: while let Some((index, mut delta)) = work.pop() {
        if !seen.insert((index, delta)) {
            continue;
        }
        // A loop that moves the stack pointer each time round never settles.
        if seen.len() > 4 * blocks.len() {
            return true;
        }
        for stmt in &blocks[index].stmts {
            if stmt
                .operands()
                .into_iter()
                .any(|operand| reads(operand, sp, delta, field))
            {
                return true;
            }
            if stored_over(stmt, sp, delta, field) == Some(true) {
                continue 'blocks;
            }
            let Some(moved) = stack_moved(stmt, sp, delta) else {
                return true;
            };
            delta = moved;
        }
        if ends_unknown(blocks, index) {
            return true;
        }
        work.extend(
            crate::ir::cfg::block_successors(blocks, index)
                .into_iter()
                .map(|next| (next, delta)),
        );
    }
    false
}

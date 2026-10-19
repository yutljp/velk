use crate::arch::stack_pointer;

use crate::ir::visit::statement_registers;
use crate::ir::{Expr, FunctionIr, Stmt};

/// Replaces a load with the value stored to the same address earlier in the
/// block: `*(u32 *)&local_3 = w8; x8 = *(u32 *)&local_3;` leaves `x8 = w8;`.
pub fn forward_stored_values(ir: &mut FunctionIr) {
    let sp = stack_pointer(ir.isa);
    for block in &mut ir.blocks {
        let mut pending: Vec<(u8, Expr, Expr)> = Vec::new();
        for stmt in &mut block.stmts {
            match stmt {
                Stmt::Store {
                    addr, value, width, ..
                } => {
                    // A newer store replaces every older one it may overlap.
                    pending.retain(|(stored_width, stored, _)| {
                        disjoint(stored, *stored_width, addr, *width)
                    });
                    pending.push((*width, addr.clone(), value.clone()));
                }
                Stmt::Call { .. } | Stmt::Unsupported { .. } => pending.clear(),
                Stmt::Assign { dest, value } => {
                    // Moving the stack pointer changes what every remembered
                    // `sp`-relative address refers to.
                    if dest.index == sp {
                        pending.clear();
                        continue;
                    }
                    forward_expr(value, &pending);
                }
                Stmt::Brif { lhs, rhs, .. } => {
                    forward_expr(lhs, &pending);
                    forward_expr(rhs, &pending);
                }
                Stmt::Ret { value } => forward_expr(value, &pending),
                _ => {}
            }
        }
    }
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

/// An address as a base and a constant byte offset.
fn split_offset(addr: &Expr) -> (&Expr, i64) {
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

fn forward_expr(expr: &mut Expr, pending: &[(u8, Expr, Expr)]) {
    match expr {
        Expr::Load { addr, width, .. } => {
            if let Some((_, _, value)) = pending.iter().find(|(stored_width, stored, _)| {
                *stored_width == *width && stored == addr.as_ref()
            }) {
                *expr = value.clone();
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
            lhs,
            rhs,
            then,
            els,
            ..
        } => {
            forward_expr(lhs, pending);
            forward_expr(rhs, pending);
            forward_expr(then, pending);
            forward_expr(els, pending);
        }
        _ => {}
    }
}

/// Fuses `t = *p; t = op(t, x); *p = t` into `*p = op(*p, x)` when the
/// temporary is read nowhere else in the block.
pub fn fuse_load_op_store(ir: &mut FunctionIr) {
    for block in &mut ir.blocks {
        fuse_block(block);
    }
}

fn fuse_block(block: &mut crate::ir::Block) {
    let mut fused: Vec<usize> = Vec::new();
    let mut index = 0;
    while index < block.stmts.len() {
        if fused.contains(&index) {
            index += 1;
            continue;
        }
        // The update may already carry its load: `t = op(*p, x); *p = t`.
        if let Some((dest, address, update)) = inline_update(&block.stmts[index])
            && let Some(store_at) = store_back(&block.stmts, index, dest, &address)
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
        let mut escapes = false;
        for later in store_at + 1..block.stmts.len() {
            let (writes, reads) = statement_registers(&block.stmts[later]);
            if writes.contains(&dest) {
                break;
            }
            if reads.contains(&dest) {
                escapes = true;
                break;
            }
        }
        if escapes {
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
fn store_back(stmts: &[Stmt], index: usize, dest: u16, address: &Expr) -> Option<usize> {
    let mut store_at = None;
    for (probe, stmt) in stmts.iter().enumerate().take(index + 8).skip(index + 1) {
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
    let store_at = store_at?;
    for stmt in &stmts[store_at + 1..] {
        let (writes, reads) = statement_registers(stmt);
        if writes.contains(&dest) {
            break;
        }
        if reads.contains(&dest) {
            return None;
        }
    }
    Some(store_at)
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

#[cfg(test)]
mod tests {
    use super::forward_stored_values;
    use crate::ir::{BinOp, Expr, FunctionIr, Stmt};
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
}

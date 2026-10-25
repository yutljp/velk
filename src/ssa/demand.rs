use super::{Ssa, build, lower};
use crate::ir::{Expr, FunctionIr, Stmt};
use std::collections::{HashMap, HashSet};

/// The bits of each value its reads look at, given the bits each use needs:
/// a store needs its width, a mask its bits, and the low bits of a sum, a
/// product or a bitwise operation need only the operands' bits up to the
/// highest one needed. Anything else needs every bit.
pub(super) fn demanded_bits(
    ssa: &Ssa,
    returns: Option<&[u64]>,
    stores: &HashMap<(usize, usize), u64>,
) -> HashMap<u16, u64> {
    use crate::ir::BinOp;
    use crate::ir::semantics::mask;
    fn up_to_highest(bits: u64) -> u64 {
        if bits == 0 {
            0
        } else {
            mask(64 - bits.leading_zeros())
        }
    }
    fn walk(expr: &Expr, needed: u64, demand: &mut HashMap<u16, u64>, precise: bool) {
        match expr {
            Expr::Reg { index, width } => {
                *demand.entry(*index).or_insert(0) |= needed & mask(u32::from(*width));
            }
            Expr::Const(_) => {}
            Expr::Bin { op, lhs, rhs } => match op {
                BinOp::And => {
                    let (left, right) = match (lhs.as_ref(), rhs.as_ref()) {
                        (_, Expr::Const(m)) => (needed & m, 0),
                        (Expr::Const(m), _) => (0, needed & m),
                        _ => (needed, needed),
                    };
                    walk(lhs, left, demand, precise);
                    walk(rhs, right, demand, precise);
                }
                BinOp::Or | BinOp::Xor => {
                    walk(lhs, needed, demand, precise);
                    walk(rhs, needed, demand, precise);
                }
                BinOp::Shr if precise && matches!(rhs.as_ref(), Expr::Const(_)) => {
                    let Expr::Const(count) = rhs.as_ref() else {
                        unreachable!()
                    };
                    walk(lhs, needed << (count & 63), demand, precise);
                }
                BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Shl => {
                    let low = up_to_highest(needed);
                    walk(lhs, low, demand, precise);
                    // A shift amount is needed whole.
                    walk(
                        rhs,
                        if *op == BinOp::Shl { u64::MAX } else { low },
                        demand,
                        precise,
                    );
                }
                _ => {
                    walk(lhs, u64::MAX, demand, precise);
                    walk(rhs, u64::MAX, demand, precise);
                }
            },
            Expr::SignExtend { value, width } => {
                walk(value, mask(u32::from(*width) * 8), demand, precise);
            }
            Expr::Select {
                lhs,
                rhs,
                then,
                els,
                ..
            } if precise => {
                walk(lhs, u64::MAX, demand, precise);
                walk(rhs, u64::MAX, demand, precise);
                walk(then, needed, demand, precise);
                walk(els, needed, demand, precise);
            }
            Expr::Apply { op, args } if precise && op.argument_precision().is_some() => {
                let bits = op.argument_precision().expect("a floating operand").bits();
                for arg in args {
                    walk(arg, mask(u32::from(bits)), demand, precise);
                }
            }
            _ => {
                for child in crate::ir::visit::children(expr) {
                    walk(child, u64::MAX, demand, precise);
                }
            }
        }
    }
    // What an assignment or a φ needs of its operands is what its own uses
    // need of it, so the needs flow back from the uses until they settle.
    let precise = returns.is_some();
    let mut demand: HashMap<u16, u64> = HashMap::new();
    loop {
        let mut next: HashMap<u16, u64> = HashMap::new();
        for (position, stmt) in ssa.ir.blocks.iter().enumerate().flat_map(|(block, body)| {
            body.stmts
                .iter()
                .enumerate()
                .map(move |(at, stmt)| ((block, at), stmt))
        }) {
            match stmt {
                Stmt::Store { addr, value, width } => {
                    walk(addr, u64::MAX, &mut next, precise);
                    let needed = stores
                        .get(&position)
                        .copied()
                        .unwrap_or_else(|| mask(u32::from(*width) * 8));
                    walk(value, needed, &mut next, precise);
                }
                Stmt::Assign { dest, value } => {
                    let needed = demand.get(&dest.index).copied().unwrap_or(0);
                    walk(
                        value,
                        needed & mask(u32::from(dest.width)),
                        &mut next,
                        precise,
                    );
                }
                Stmt::Ret { value } if returns.is_some_and(|masks| !masks.is_empty()) => {
                    let values = match value {
                        Expr::Apply {
                            op: crate::ir::Operation::Results,
                            args,
                        } => args.as_slice(),
                        value => std::slice::from_ref(value),
                    };
                    for (value, needed) in values.iter().zip(returns.expect("return masks")) {
                        walk(value, *needed, &mut next, precise);
                    }
                }
                other => {
                    for expr in other.operands() {
                        walk(expr, u64::MAX, &mut next, precise);
                    }
                }
            }
        }
        for phi in ssa.phis.iter().flatten() {
            let needed = demand.get(&phi.value).copied().unwrap_or(0);
            for arg in &phi.args {
                *next.entry(*arg).or_insert(0) |= needed;
            }
        }
        for (&(block, position), reads) in &ssa.implicit_reads {
            let stmt = &ssa.ir.blocks[block].stmts[position];
            let abi = stmt.unnamed_call_reads();
            let sources = stmt.preserved_output_sources();
            for (register, value) in reads {
                let needed = if !matches!(stmt, Stmt::Call { .. })
                    || abi.contains(register)
                    || stmt.declared_call_reads().contains(register)
                {
                    u64::MAX
                } else {
                    sources
                        .iter()
                        .filter(|(_, source)| source == register)
                        .fold(0, |needed, (index, _)| {
                            needed
                                | (demand
                                    .get(&stmt.call_outputs()[*index].dest.index)
                                    .copied()
                                    .unwrap_or(0)
                                    & mask(u32::from(stmt.call_outputs()[*index].dest.width)))
                        })
                };
                *next.entry(*value).or_insert(0) |= needed;
            }
        }
        if next == demand {
            return demand;
        }
        demand = next;
    }
}

fn private_store_demands(ir: &FunctionIr) -> Option<HashMap<(usize, usize), u64>> {
    use crate::ir::BinOp;
    let sp = crate::arch::stack_pointer(ir.isa);
    if crate::passes::memory::frame_address_escapes(ir, sp)
        || ir
            .blocks
            .iter()
            .flat_map(|block| &block.stmts)
            .any(|stmt| matches!(stmt, Stmt::Call { .. } | Stmt::Unsupported { .. }))
    {
        return None;
    }
    fn slot(addr: &Expr, frame: i64, sp: u16) -> Option<i64> {
        let register = |expr: &Expr| matches!(expr, Expr::Reg { index, width: 64 } if *index == sp);
        let delta = match addr {
            value if register(value) => 0,
            Expr::Bin {
                op: BinOp::Add,
                lhs,
                rhs,
            } => match (lhs.as_ref(), rhs.as_ref()) {
                (base, Expr::Const(delta)) | (Expr::Const(delta), base) if register(base) => {
                    i128::from(*delta as i64)
                }
                _ => return None,
            },
            Expr::Bin {
                op: BinOp::Sub,
                lhs,
                rhs,
            } if register(lhs) => {
                let Expr::Const(delta) = rhs.as_ref() else {
                    return None;
                };
                -i128::from(*delta as i64)
            }
            _ => return None,
        };
        i64::try_from(i128::from(frame) + delta).ok()
    }
    fn range(addr: &Expr, width: u8, frame: i64, sp: u16) -> Option<(i64, i64)> {
        if !(1..=8).contains(&width) {
            return None;
        }
        let start = slot(addr, frame, sp)?;
        Some((start, start.checked_add(i64::from(width))?))
    }
    fn loads(expr: &Expr, frame: i64, sp: u16, read: &mut Vec<(i64, i64)>) -> Option<()> {
        if let Expr::Load { addr, width, .. } = expr {
            let Some(range) = range(addr, *width, frame, sp) else {
                return None;
            };
            read.push(range);
        }
        for child in crate::ir::visit::children(expr) {
            let Some(()) = loads(child, frame, sp, read) else {
                return None;
            };
        }
        Some(())
    }
    let frames = crate::passes::frame_slots::block_frames(ir, sp);
    let mut read = Vec::new();
    let mut stores = Vec::new();
    for (block, body) in ir.blocks.iter().enumerate() {
        let Some(mut frame) = frames[block] else {
            return None;
        };
        for (at, stmt) in body.stmts.iter().enumerate() {
            if let Stmt::Assign { dest, value } = stmt
                && dest.index == sp
            {
                if dest.width != 64 {
                    return None;
                }
                let Some(next) = slot(value, frame, sp) else {
                    return None;
                };
                frame = next;
                continue;
            }
            if let Stmt::Store { addr, width, .. } = stmt {
                let Some((start, end)) = range(addr, *width, frame, sp) else {
                    return None;
                };
                if start >= -(crate::ir::eval::STACK_SPAN as i64) && end <= 0 {
                    stores.push(((block, at), start, end));
                }
            }
            for operand in stmt.operands() {
                let Some(()) = loads(operand, frame, sp, &mut read) else {
                    return None;
                };
            }
        }
        for successor in crate::ir::cfg::block_successors(&ir.blocks, block) {
            if frames[successor] != Some(frame) {
                return None;
            }
        }
    }
    Some(
        stores
            .into_iter()
            .map(|(position, start, end)| {
                let mut bits = 0;
                for byte in start..end {
                    if read.iter().any(|(from, to)| *from <= byte && byte < *to) {
                        bits |= 0xffu64 << ((byte - start) * 8);
                    }
                }
                (position, bits)
            })
            .collect(),
    )
}

/// The entry-register bits observed by effects and the requested result pieces.
/// An empty result mask list keeps every returned bit observable.
pub(crate) fn entry_demands(ir: &FunctionIr, returns: &[u64]) -> Option<HashMap<u16, u64>> {
    if ir.blocks.is_empty() {
        return None;
    }
    let starts: HashSet<_> = ir.blocks.iter().map(|block| block.start).collect();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        match stmt {
            Stmt::Unsupported { .. }
            | Stmt::BrIndirect { .. }
            | Stmt::BrifFlags { .. }
            | Stmt::Br { target: None } => return None,
            Stmt::Br {
                target: Some(target),
            }
            | Stmt::Brif { target, .. }
                if !starts.contains(target) =>
            {
                return None;
            }
            Stmt::Switch { cases, default, .. }
                if default.is_none()
                    || cases.iter().any(|(_, target)| !starts.contains(target))
                    || default.is_some_and(|target| !starts.contains(&target)) =>
            {
                return None;
            }
            Stmt::Ret { value } if !returns.is_empty() => {
                let count = match value {
                    Expr::Apply {
                        op: crate::ir::Operation::Results,
                        args,
                    } => args.len(),
                    _ => 1,
                };
                if count != returns.len() {
                    return None;
                }
            }
            _ => {}
        }
    }
    let stores = private_store_demands(ir).unwrap_or_default();
    let Some(ssa) = build(ir) else {
        return None;
    };
    let demand = demanded_bits(&ssa, Some(returns), &stores);
    Some(
        ssa.entry
            .iter()
            .map(|(register, value)| (*register, demand.get(value).copied().unwrap_or(0)))
            .collect(),
    )
}

/// A partial write keeps the register's other bits: `v = (r & ~m) | x`.
/// When no read of `v` looks at the kept bits, they never matter and the
/// write is just `v = x`.
pub fn narrow_partial_writes(ir: &mut FunctionIr) {
    // An unmodeled instruction or an unknown jump may read any bit.
    if ir.blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
        matches!(
            stmt,
            Stmt::Unsupported { .. } | Stmt::BrIndirect { .. } | Stmt::Br { target: None }
        )
    }) {
        return;
    }
    let Some(mut ssa) = build(ir) else {
        return;
    };
    let demand = demanded_bits(&ssa, None, &HashMap::new());
    let mut changed = false;
    for stmt in ssa.ir.blocks.iter_mut().flat_map(|block| &mut block.stmts) {
        let Stmt::Assign { dest, value } = stmt else {
            continue;
        };
        let Expr::Bin {
            op: crate::ir::BinOp::Or,
            lhs,
            rhs,
        } = value
        else {
            continue;
        };
        let kept = |expr: &Expr| match expr {
            Expr::Const(keep) => Some(*keep),
            Expr::Bin {
                op: crate::ir::BinOp::And,
                lhs,
                rhs,
            } if matches!(lhs.as_ref(), Expr::Reg { .. }) => match rhs.as_ref() {
                Expr::Const(keep) => Some(*keep),
                _ => None,
            },
            _ => None,
        };
        let (keep, written) = match (kept(lhs), kept(rhs)) {
            (Some(keep), _) => (keep, rhs.as_ref().clone()),
            (None, Some(keep)) => (keep, lhs.as_ref().clone()),
            _ => continue,
        };
        if demand.get(&dest.index).copied().unwrap_or(0) & keep == 0 {
            *value = written;
            changed = true;
        }
    }
    if changed {
        *ir = lower(&ssa);
    }
}

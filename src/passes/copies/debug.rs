use crate::ir::visit::{expr_reads, statement_registers};
use crate::ir::{Expr, FunctionIr, Stmt, VARIABLE_BASE};

/// Uses an integer stack variable in place of the register copied into it,
/// only when every read sees the same complete value in the slot.
pub(crate) fn fold_debug_locals(ir: &mut FunctionIr) -> bool {
    let sp = crate::arch::stack_pointer(ir.isa);
    if !crate::passes::memory::fixed_private_frame(ir, sp) {
        return false;
    }
    let types = crate::render::variable_types(ir);
    let mut predecessors = vec![Vec::new(); ir.blocks.len()];
    for (index, block) in ir.blocks.iter().enumerate() {
        let edges =
            crate::ir::cfg::block_successors_with_exceptions(&ir.blocks, index, &ir.landing_pads);
        if crate::ir::cfg::opaque(block)
            || edges.unknown_normal
            || edges.unknown_exceptional
            || !edges.exceptional.is_empty()
        {
            return false;
        }
        for next in edges.normal {
            predecessors[next].push(index);
        }
    }
    let mut definitions = std::collections::HashMap::<u16, usize>::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        for register in statement_registers(stmt).0 {
            let count = definitions.entry(register).or_default();
            *count = count.saturating_add(1);
        }
    }
    let mut changed = false;
    for block in 0..ir.blocks.len() {
        let mut index = 0;
        while index + 1 < ir.blocks[block].stmts.len() {
            let Stmt::Assign { dest, value } = &ir.blocks[block].stmts[index] else {
                index += 1;
                continue;
            };
            let dest = *dest;
            let value = value.clone();
            let Stmt::Store {
                addr,
                value: stored,
                width,
            } = &ir.blocks[block].stmts[index + 1]
            else {
                index += 1;
                continue;
            };
            let (addr, width) = (addr.clone(), *width);
            let slot = crate::passes::frame_slots::frame_slot(&addr, 0, sp);
            let integer = (ir.debug_locals.is_empty()
                && matches!(types.get(&dest.index), Some(crate::ir::CType::Int { .. }))
                && !crate::passes::read_once::floats(&value))
                || ir.debug_locals.iter().any(|local| {
                Some(local.slot) == slot
                    && local.size == u64::from(width)
                    && local
                        .ty
                        .integer()
                        .is_some_and(|(bits, _)| bits == u32::from(width) * 8)
                    && !matches!(&local.ty, crate::ir::CType::Named(name)
                        if name.split_whitespace().any(|word| matches!(word, "bool" | "_Bool" | "volatile")))
                    && !ir.debug_locals.iter().any(|other| {
                        !std::ptr::eq(local, other)
                            && i128::from(other.slot)
                                < i128::from(local.slot) + i128::from(local.size)
                            && i128::from(local.slot)
                                < i128::from(other.slot) + i128::from(other.size)
                    })
            });
            let mut sources = Default::default();
            expr_reads(&value, &mut sources);
            if !integer
                || !matches!(width, 1 | 2 | 4 | 8)
                || dest.index < VARIABLE_BASE
                || u32::from(width) * 8 > u32::from(dest.width)
                || crate::ssa::ranges::of(&super::truncated(&value, dest.width)).hi
                    > crate::ir::semantics::mask(u32::from(width) * 8)
                || !matches!(stored, Expr::Reg { index, width: read } if *index == dest.index && u32::from(*read) >= u32::from(width) * 8)
                || sources.contains(&dest.index)
                || definitions.get(&dest.index) != Some(&1)
                || !crate::passes::memory::private_address(&addr, width, sp)
            {
                index += 1;
                continue;
            }
            let load = Expr::Load {
                addr: Box::new(addr.clone()),
                width,
                signed: false,
            };
            let store_at = (block, index + 1);
            let transfer = |block: usize, mut valid: bool| {
                for (position, stmt) in ir.blocks[block].stmts.iter().enumerate() {
                    if (block, position) == store_at {
                        valid = true;
                    } else if invalidates(stmt, dest.index, &load) {
                        valid = false;
                    }
                }
                valid
            };
            let incoming = |block: usize, outgoing: &[bool]| {
                block != 0
                    && !predecessors[block].is_empty()
                    && predecessors[block].iter().all(|from| outgoing[*from])
            };
            let mut outgoing = vec![false; ir.blocks.len()];
            loop {
                let mut progress = false;
                for block in 0..ir.blocks.len() {
                    let next = transfer(block, incoming(block, &outgoing));
                    progress |= outgoing[block] != next;
                    outgoing[block] = next;
                }
                if !progress {
                    break;
                }
            }
            let mut replacements = Vec::new();
            let mut safe = true;
            for (block, body) in ir.blocks.iter().enumerate() {
                let mut valid = incoming(block, &outgoing);
                for (position, stmt) in body.stmts.iter().enumerate() {
                    if (block, position) == store_at {
                        valid = true;
                        continue;
                    }
                    if statement_registers(stmt).1.contains(&dest.index) {
                        let mut replacement = stmt.clone();
                        if !valid
                            || !crate::passes::read_once::substitute(&mut replacement, dest, &load)
                        {
                            safe = false;
                            break;
                        }
                        replacements.push((block, position, replacement));
                    }
                    if invalidates(stmt, dest.index, &load) {
                        valid = false;
                    }
                }
                if !safe {
                    break;
                }
            }
            if !safe {
                index += 1;
                continue;
            }
            for (block, position, replacement) in replacements {
                ir.blocks[block].stmts[position] = replacement;
            }
            ir.blocks[block].stmts[index] = Stmt::Store {
                addr,
                value: super::truncated(&value, dest.width),
                width,
            };
            ir.blocks[block].stmts.remove(index + 1);
            changed = true;
            index += 1;
        }
    }
    changed
}

fn invalidates(stmt: &Stmt, register: u16, load: &Expr) -> bool {
    statement_registers(stmt).0.contains(&register)
        || match stmt {
            Stmt::Store { addr, width, .. } => {
                crate::passes::memory::split_offset(addr)
                    .1
                    .checked_add(i64::from(*width))
                    .is_none()
                    || !crate::passes::memory::loads_avoid(load, addr, *width)
            }
            Stmt::Call { .. } | Stmt::Machine { .. } | Stmt::Unsupported { .. } => true,
            _ => false,
        }
}

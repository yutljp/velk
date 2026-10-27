use std::collections::HashMap;

use crate::ir::{BinOp, Expr, FunctionIr, Stmt, VARIABLE_BASE};

pub(in crate::render) fn register_scales(ir: &FunctionIr) -> HashMap<u16, u64> {
    let mut scales = HashMap::new();
    let mut writes = HashMap::<u16, usize>::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        for register in crate::ir::visit::statement_registers(stmt).0 {
            *writes.entry(register).or_default() += 1;
        }
        let Stmt::Assign { dest, value } = stmt else {
            continue;
        };
        if dest.index < VARIABLE_BASE || dest.width != 64 {
            continue;
        }
        let (index, scale) = match value {
            Expr::Bin {
                op: BinOp::Mul,
                lhs,
                rhs,
            } => match (lhs.as_ref(), rhs.as_ref()) {
                (index, Expr::Const(scale)) | (Expr::Const(scale), index) => (index, *scale),
                _ => continue,
            },
            Expr::Bin {
                op: BinOp::Shl,
                lhs,
                rhs,
            } => match rhs.as_ref() {
                Expr::Const(shift) if *shift < 31 => (lhs.as_ref(), 1u64 << shift),
                _ => continue,
            },
            _ => continue,
        };
        // A 32-bit index times this scale cannot wrap a signed 64-bit offset.
        if !(2..=i32::MAX as u64).contains(&scale) {
            continue;
        }
        let bounded = match index {
            Expr::Reg { width, .. } => matches!(width, 8 | 16 | 32),
            Expr::Load { width, .. } | Expr::SignExtend { width, .. } => matches!(width, 1 | 2 | 4),
            _ => false,
        };
        if bounded {
            scales.insert(dest.index, scale);
        }
    }
    scales.retain(|register, _| {
        writes.get(register) == Some(&1) && !ir.params.iter().any(|param| param.index == *register)
    });
    if scales.is_empty() {
        return scales;
    }
    let Some(demanded) = crate::ssa::entry_demands(ir, &[u64::MAX]) else {
        return HashMap::new();
    };
    scales.retain(|register, _| demanded.get(register).copied().unwrap_or(0) == 0);
    scales
}

pub(in crate::render) fn address_register_scales(ir: &FunctionIr) -> HashMap<u16, u64> {
    let mut scales = register_scales(ir);
    if !ir.landing_pads.is_empty() {
        return scales;
    }
    let Some(demanded) = crate::ssa::entry_demands(ir, &[u64::MAX]) else {
        return scales;
    };
    for (register, scale) in aligned_registers(ir, &demanded) {
        scales.entry(register).or_insert(scale);
    }
    scales
}

fn aligned_registers(ir: &FunctionIr, demanded: &HashMap<u16, u64>) -> HashMap<u16, u64> {
    let mut zeros = HashMap::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        for register in crate::ir::visit::statement_registers(stmt).0 {
            if register >= VARIABLE_BASE {
                zeros.entry(register).or_insert(64u32);
            }
        }
    }
    for (register, bits) in &mut zeros {
        if demanded.get(register).copied().unwrap_or(0) != 0
            || ir.params.iter().any(|param| param.index == *register)
        {
            *bits = 0;
        }
    }
    // Start with all low bits clear, then discard every bit any definition
    // can set. This also proves alignment for initialized loop counters.
    for _ in 0..=64 {
        let mut changed = false;
        for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
            let read = |register, _| {
                let bits = zeros.get(&register).copied().unwrap_or(0);
                crate::ssa::ranges::Fact::bits(crate::ir::semantics::mask(bits), 0)
            };
            let bits = match stmt {
                Stmt::Assign { dest, value } if dest.width == 64 => {
                    crate::ssa::ranges::expression(value, &read)
                        .map_or(0, |fact| fact.zeros.trailing_ones())
                }
                _ => 0,
            };
            for register in crate::ir::visit::statement_registers(stmt).0 {
                if let Some(known) = zeros.get_mut(&register) {
                    let next = (*known).min(bits);
                    changed |= next != *known;
                    *known = next;
                }
            }
        }
        if !changed {
            zeros.retain(|_, bits| *bits > 0);
            return zeros
                .into_iter()
                .map(|(register, bits)| (register, 1u64 << bits.min(31)))
                .collect();
        }
    }
    HashMap::new()
}

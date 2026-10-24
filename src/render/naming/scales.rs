use std::collections::HashMap;

use crate::ir::{BinOp, Expr, FunctionIr, Stmt, VARIABLE_BASE};

pub(in crate::render) fn registers(ir: &FunctionIr) -> HashMap<u16, u64> {
    let mut scales = HashMap::new();
    let mut writes = HashMap::<u16, usize>::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        for register in crate::ir::visit::statement_registers(stmt).0 {
            *writes.entry(register).or_default() += 1;
        }
        let Stmt::Assign {
            dest,
            value:
                Expr::Bin {
                    op: BinOp::Mul,
                    lhs,
                    rhs,
                },
        } = stmt
        else {
            continue;
        };
        if dest.index < VARIABLE_BASE || dest.width != 64 {
            continue;
        }
        let (index, scale) = match (lhs.as_ref(), rhs.as_ref()) {
            (index, Expr::Const(scale)) | (Expr::Const(scale), index) => (index, *scale),
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

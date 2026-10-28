//! Express an adjusted pointer as a pointer to its original base.

use crate::ir::{BinOp, Expr, FunctionIr, Stmt, VARIABLE_BASE};

#[cfg(test)]
mod tests;

fn whole(value: &Expr, register: u16) -> bool {
    if let Expr::Reg { index, width } = value
        && *index == register
    {
        return *width == 64;
    }
    crate::ir::visit::children(value)
        .into_iter()
        .all(|child| whole(child, register))
}

fn replace(value: &mut Expr, phases: &[(u16, u64)]) {
    if let Expr::Reg { index, width: 64 } = value
        && let Some((_, phase)) = phases.iter().find(|(register, _)| register == index)
    {
        *value = Expr::bin(BinOp::Add, value.clone(), Expr::Const(*phase));
        return;
    }
    for child in crate::ir::visit::children_mut(value) {
        replace(child, phases);
    }
}

pub(super) fn normalize(ir: &mut FunctionIr, phases: &[(u16, u64)]) -> Vec<u16> {
    if phases.is_empty() {
        return Vec::new();
    }
    let Some(demanded) = crate::ssa::entry_demands(ir, &[]) else {
        return Vec::new();
    };
    let phases: Vec<_> = phases
        .iter()
        .copied()
        .filter(|(register, _)| {
            *register >= VARIABLE_BASE
                && demanded.get(register).copied().unwrap_or(0) == 0
                && !ir.params.iter().any(|param| param.index == *register)
                && ir.blocks.iter().flat_map(|block| &block.stmts).all(|stmt| {
                    let writes = crate::ir::visit::statement_registers(stmt).0;
                    (!writes.contains(register)
                        || matches!(stmt, Stmt::Assign { dest, .. } if dest.index == *register && dest.width == 64))
                        && stmt.operands().into_iter().all(|value| whole(value, *register))
                })
        })
        .collect();
    if phases.is_empty() {
        return Vec::new();
    }
    for stmt in ir.blocks.iter_mut().flat_map(|block| &mut block.stmts) {
        for value in stmt.operands_mut() {
            replace(value, &phases);
        }
        if let Stmt::Assign { dest, value } = stmt
            && let Some((_, phase)) = phases.iter().find(|(register, _)| *register == dest.index)
        {
            *value = Expr::bin(BinOp::Sub, value.clone(), Expr::Const(*phase));
        }
    }
    crate::passes::simplify::simplify(ir);
    phases.into_iter().map(|(register, _)| register).collect()
}

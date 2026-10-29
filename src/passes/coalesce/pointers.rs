use std::collections::{BTreeMap, HashMap, HashSet};

use crate::ir::cfg::opaque;
use crate::ir::visit::{children, statement_registers};
use crate::ir::{BinOp, CType, Expr, FunctionIr, Stmt, VARIABLE_BASE};

use super::{Groups, interference, rename};

/// Reuses same-origin pointer locals once their printed types and layouts
/// are known. No definition or memory access moves.
pub(crate) fn reuse_pointers(ir: &mut FunctionIr) {
    // A protected call can leave before later definitions in its block.
    if !ir.landing_pads.is_empty() || ir.blocks.iter().any(opaque) {
        return;
    }
    let types = crate::render::variable_types(ir);
    let mut excluded = HashSet::new();
    let mut defined = HashSet::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        match stmt {
            Stmt::Assign { dest, value, .. } => {
                defined.insert(dest.index);
                // Partial register writes also appear as full-width masks
                // and merges, even when a declared type remains a pointer.
                if dest.width != 64
                    || matches!(
                        value,
                        Expr::Bin {
                            op: BinOp::And | BinOp::Or | BinOp::Xor,
                            ..
                        }
                    )
                {
                    excluded.insert(dest.index);
                }
            }
            Stmt::Call { .. } => {
                let (writes, reads) = statement_registers(stmt);
                excluded.extend(writes.iter().chain(&reads).copied());
                // Implicit machine-register arguments are not renamed.
                excluded.extend(
                    ir.variable_registers
                        .iter()
                        .filter_map(|(variable, origin)| {
                            reads.contains(origin).then_some(*variable)
                        }),
                );
            }
            _ => {}
        }
        for operand in stmt.operands() {
            narrow_reads(operand, &mut excluded);
        }
    }
    let mut origins: BTreeMap<u16, Vec<u16>> = BTreeMap::new();
    for (&variable, &origin) in &ir.variable_registers {
        if variable >= VARIABLE_BASE
            && defined.contains(&variable)
            && !excluded.contains(&variable)
            && types.get(&variable).is_some_and(|ty| known_layout(ir, ty))
        {
            origins.entry(origin).or_default().push(variable);
        }
    }
    if !origins.values().any(|variables| variables.len() > 1) {
        return;
    }
    let (interferes, _, entry) = interference(ir, &|_| None);
    let mut groups = Groups::default();
    for variables in origins.values() {
        for (at, variable) in variables.iter().enumerate() {
            for earlier in &variables[..at] {
                if types[earlier] == types[variable]
                    && groups.join(*earlier, *variable, &interferes, &entry)
                {
                    break;
                }
            }
        }
    }
    if groups.leader.is_empty() {
        return;
    }
    let renamed: HashMap<u16, u16> = groups
        .leader
        .keys()
        .map(|variable| (*variable, groups.find(*variable)))
        .collect();
    let class = |variable: u16| renamed.get(&variable).copied().unwrap_or(variable);
    let mut candidate = ir.clone();
    for stmt in candidate
        .blocks
        .iter_mut()
        .flat_map(|block| &mut block.stmts)
    {
        rename(stmt, &renamed);
    }
    candidate
        .variable_registers
        .retain(|variable, _| !renamed.contains_key(variable));
    candidate
        .value_types
        .retain(|variable, _| !renamed.contains_key(variable));
    for variable in renamed.values() {
        candidate
            .value_types
            .insert(*variable, types[variable].clone());
    }
    for variable in &mut candidate.pointer_values {
        *variable = class(*variable);
    }
    candidate.pointer_values.sort_unstable();
    candidate.pointer_values.dedup();
    for access in &mut candidate.accesses {
        access.register = class(access.register);
    }
    for structure in &mut candidate.structures {
        for variable in &mut structure.elements {
            *variable = class(*variable);
        }
        structure.elements.sort_unstable();
        structure.elements.dedup();
    }
    // Combining uses must not change inference, including types of other
    // variables whose loaded element types depend on these pointers.
    let after = crate::render::variable_types(&candidate);
    if types
        .iter()
        .all(|(variable, ty)| after.get(&class(*variable)) == Some(ty))
    {
        *ir = candidate;
    }
}

fn narrow_reads(expr: &Expr, excluded: &mut HashSet<u16>) {
    if let Expr::Reg { index, width } = expr
        && *width != 64
    {
        excluded.insert(*index);
    }
    for child in children(expr) {
        narrow_reads(child, excluded);
    }
}

fn known_layout(ir: &FunctionIr, ty: &CType) -> bool {
    if let Some(size) = ty.pointee_size() {
        return size != 0;
    }
    let Some(name) = ty.pointee_struct() else {
        return false;
    };
    ir.structures.iter().any(|structure| structure.name == name)
        || ir
            .definitions
            .iter()
            .any(|definition| definition.name == format!("struct {name}"))
}

#[cfg(test)]
mod tests;

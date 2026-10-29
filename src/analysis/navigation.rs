//! Lifts used for navigation, before rendering passes discard machine accesses.

use std::collections::HashSet;

use crate::error::LiftError;
use crate::ir::{Block, Expr};
use crate::loader::{Function, Image, Summary};
use std::collections::HashMap;

pub(crate) fn blocks(image: &Image, function: &Function) -> Result<Vec<Block>, LiftError> {
    let size = function.size.unwrap_or(super::UNKNOWN_SIZE);
    let extent = function.addr..function.addr.saturating_add(size);
    let pads = super::landing_pads(image, extent.clone());
    let mut targets = super::exception_starts(&pads, extent.clone());
    // Navigation needs no inferred argument or return types from other functions.
    let summaries = |_| Summary::default();
    let mut blocks = match crate::lift::lift_shared_with_targets(
        image,
        function.addr,
        size,
        &targets,
        &summaries,
    ) {
        Ok(blocks) => (*blocks).clone(),
        Err(error) => return Err(error),
    };
    let mut tables = super::jump_table::recover(&blocks, image, extent.clone());
    for _ in 0..4 {
        let found: HashSet<_> = tables
            .iter()
            .flat_map(super::jump_table::Recovered::targets)
            .collect();
        if found.is_subset(&targets) {
            break;
        }
        targets.extend(found);
        blocks = match crate::lift::lift_shared_with_targets(
            image,
            function.addr,
            size,
            &targets,
            &summaries,
        ) {
            Ok(blocks) => (*blocks).clone(),
            Err(error) => return Err(error),
        };
        tables = super::jump_table::recover(&blocks, image, extent.clone());
    }
    let switched = tables.iter().map(|table| table.block_start).collect();
    super::tail_calls_through_pointers(&mut blocks, &switched, image);
    super::indirect::resolve(&mut blocks, &pads, image);
    super::jump_table::apply(&mut blocks, &tables);
    Ok(blocks)
}

pub(crate) fn resolve(expr: &Expr, values: &std::collections::HashMap<u16, Expr>) -> Expr {
    if let Expr::Reg { index, width } = expr {
        if let Some(Expr::Const(value)) = values.get(index) {
            return Expr::Const(if *width >= 64 {
                *value
            } else {
                *value & ((1u64 << width) - 1)
            });
        }
        return expr.clone();
    }
    let mut resolved = expr.clone();
    for child in crate::ir::visit::children_mut(&mut resolved) {
        *child = resolve(child, values);
    }
    if let Expr::Bin { op, lhs, rhs } = resolved {
        return Expr::bin(op, *lhs, *rhs);
    }
    resolved
}

pub(crate) fn advance(stmt: &crate::ir::Stmt, values: &mut HashMap<u16, Expr>) {
    let assigned = match stmt {
        crate::ir::Stmt::Assign { dest, value, .. } if dest.width >= 32 => {
            let mut value = resolve(value, values);
            if dest.width == 32 {
                value = Expr::bin(crate::ir::BinOp::And, value, Expr::Const(u32::MAX as u64));
            }
            Some((dest.index, value))
        }
        _ => None,
    };
    for register in crate::ir::visit::statement_registers(stmt).0 {
        values.remove(&register);
    }
    // Propagating a load could invent another read, or reuse stale memory.
    if let Some((register, value @ Expr::Const(_))) = assigned {
        values.insert(register, value);
    }
}

/// Only constants that agree on every incoming path reach a block. Exception
/// entries receive unknown registers, independently of their normal predecessors.
pub(crate) fn constants(blocks: &[Block], image: &Image) -> Vec<HashMap<u16, Expr>> {
    let mut entry = vec![None::<HashMap<u16, Expr>>; blocks.len()];
    let mut pending = Vec::new();
    for (at, block) in blocks.iter().enumerate() {
        if at == 0 || image.landing_pads.contains_key(&block.start) {
            entry[at] = Some(HashMap::new());
            pending.push(at);
        }
    }
    while let Some(at) = pending.pop() {
        let Some(mut values) = entry[at].clone() else {
            continue;
        };
        for stmt in &blocks[at].stmts {
            advance(stmt, &mut values);
        }
        if matches!(
            blocks[at].stmts.last(),
            Some(crate::ir::Stmt::Call {
                kind: crate::ir::CallKind::Tail,
                ..
            })
        ) {
            continue;
        }
        for next in crate::ir::cfg::block_successors(blocks, at) {
            let merged = match &entry[next] {
                None => values.clone(),
                Some(old) => old
                    .iter()
                    .filter(|(register, value)| values.get(register) == Some(value))
                    .map(|(register, value)| (*register, value.clone()))
                    .collect(),
            };
            if entry[next].as_ref() != Some(&merged) {
                entry[next] = Some(merged);
                pending.push(next);
            }
        }
    }
    entry.into_iter().map(Option::unwrap_or_default).collect()
}

//! Definite writes on paths distinguished by constant boolean registers.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use crate::ir::{Block, Expr, Stmt};

type Writes = Vec<Vec<Option<HashSet<u16>>>>;
type Entries = BTreeMap<Vec<(u16, u64)>, HashSet<u16>>;

/// Keeps boolean assignments separate at joins so a guarded read does not
/// require an entry value when every path enabling it first writes it.
/// Exceeding the state budget leaves the ordinary analysis in use.
pub(super) fn definite_writes(
    blocks: &[Block],
    writes: &[Vec<rustc_hash::FxHashSet<u16>>],
) -> Option<Writes> {
    let mut guards = HashSet::new();
    for stmt in blocks.iter().flat_map(|block| &block.stmts) {
        if let Stmt::Assign {
            dest,
            value: Expr::Const(0 | 1),
            ..
        } = stmt
        {
            guards.insert(dest.index);
        }
    }
    if guards.is_empty() || guards.len() > 6 || blocks.is_empty() {
        return None;
    }
    let starts: HashMap<_, _> = blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start, index))
        .collect();
    let mut entering: Vec<Entries> = vec![BTreeMap::new(); blocks.len()];
    entering[0].insert(Vec::new(), HashSet::new());
    let mut pending = VecDeque::from([(0, Vec::new())]);
    let mut result: Writes = blocks
        .iter()
        .map(|block| vec![None; block.stmts.len()])
        .collect();
    let mut visits = 0usize;
    while let Some((index, key)) = pending.pop_front() {
        visits = visits.saturating_add(1);
        if visits > blocks.len().saturating_mul(64) {
            return None;
        }
        let mut written = entering[index][&key].clone();
        let mut constants: HashMap<u16, u64> = key.into_iter().collect();
        let mut branch = None;
        for (position, stmt) in blocks[index].stmts.iter().enumerate() {
            match &mut result[index][position] {
                Some(before) => before.retain(|register| written.contains(register)),
                before @ None => *before = Some(written.clone()),
            }
            let assigned = match stmt {
                Stmt::Assign { dest, value, .. } => {
                    crate::ir::semantics::evaluate(value, &|register| {
                        constants.get(&register).copied()
                    })
                    .map(|value| {
                        (
                            dest.index,
                            value & crate::ir::semantics::mask(u32::from(dest.width)),
                        )
                    })
                }
                _ => None,
            };
            for register in &writes[index][position] {
                constants.remove(register);
                written.insert(*register);
            }
            if let Some((register, value)) = assigned {
                constants.insert(register, value);
            }
            if let Stmt::Brif { cond, lhs, rhs, .. } = stmt {
                let value = |expr| {
                    crate::ir::semantics::evaluate(expr, &|register| {
                        constants.get(&register).copied()
                    })
                };
                if let (Some(a), Some(b)) = (value(lhs), value(rhs)) {
                    branch = Some(crate::ir::semantics::holds(
                        *cond,
                        a,
                        b,
                        crate::ir::semantics::operand_width(lhs, rhs),
                    ));
                }
            }
        }
        let mut key: Vec<_> = constants
            .into_iter()
            .filter(|(register, _)| guards.contains(register))
            .collect();
        key.sort_unstable();
        let mut successors = crate::ir::cfg::block_successors(blocks, index);
        if let Some(Stmt::Brif { target, .. }) = blocks[index].stmts.last()
            && let Some(taken) = branch
        {
            let target = starts.get(target).copied();
            successors.retain(|next| {
                if taken {
                    Some(*next) == target
                } else {
                    *next == index + 1
                }
            });
        }
        for next in successors {
            let changed = match entering[next].get_mut(&key) {
                Some(before) => {
                    let count = before.len();
                    before.retain(|register| written.contains(register));
                    count != before.len()
                }
                None => {
                    if entering[next].len() >= 16 {
                        return None;
                    }
                    entering[next].insert(key.clone(), written.clone());
                    true
                }
            };
            if changed {
                pending.push_back((next, key.clone()));
            }
        }
    }
    Some(result)
}

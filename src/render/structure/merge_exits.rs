use std::collections::HashMap;

use crate::ir::{Block, Expr, FunctionIr, RegRef, Stmt};

#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) enum Statement {
    Assign(RegRef, Expr),
    Store(Expr, Expr, u8),
    Return(Expr),
    Branch(u64),
}

pub(super) fn comparable_statement(stmt: &Stmt) -> Option<Statement> {
    match stmt {
        Stmt::Assign { dest, value, .. } => Some(Statement::Assign(*dest, value.clone())),
        Stmt::Store {
            addr, value, width, ..
        } => Some(Statement::Store(addr.clone(), value.clone(), *width)),
        Stmt::Ret { value, .. } => Some(Statement::Return(value.clone())),
        Stmt::Br {
            target: Some(target),
            ..
        } => Some(Statement::Branch(*target)),
        _ => None,
    }
}

/// Share exact suffixes, including their explicit successor. Calls and
/// exception regions stay at their original addresses.
pub(in crate::render) fn merged(ir: &FunctionIr) -> Option<FunctionIr> {
    if !ir.landing_pads.is_empty()
        || ir.blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
            matches!(
                stmt,
                Stmt::BrIndirect { .. } | Stmt::Br { target: None, .. }
            )
        })
        || !matches!(
            ir.blocks.last().and_then(|block| block.stmts.last()),
            Some(Stmt::Ret { .. } | Stmt::Br { .. } | Stmt::Trap { .. } | Stmt::Switch { .. })
        )
    {
        return None;
    }
    let shared = super::motion::share_assignments(ir);
    let ir = shared.as_ref().unwrap_or(ir);
    // Intern suffixes from the end, so each statement is visited once.
    let mut suffixes = HashMap::new();
    let mut occurrences: Vec<Vec<(usize, usize)>> = Vec::new();
    for (block_index, block) in ir.blocks.iter().enumerate() {
        if !matches!(
            block.stmts.last(),
            Some(
                Stmt::Ret { .. }
                    | Stmt::Br {
                        target: Some(_),
                        ..
                    }
            )
        ) {
            continue;
        }
        let mut suffix = 0;
        for (position, stmt) in block.stmts.iter().enumerate().rev() {
            let Some(key) = comparable_statement(stmt) else {
                break;
            };
            // Only the final statement may transfer control.
            if position + 1 < block.stmts.len()
                && matches!(stmt, Stmt::Ret { .. } | Stmt::Br { .. })
            {
                break;
            }
            let next = suffixes.len() + 1;
            suffix = *suffixes.entry((key, suffix)).or_insert(next);
            if occurrences.len() < suffix {
                occurrences.push(Vec::new());
            }
            occurrences[suffix - 1].push((block_index, position));
        }
    }
    let mut groups: Vec<_> = occurrences
        .into_iter()
        .filter(|group| group.len() > 1 && ir.blocks[group[0].0].stmts.len() - group[0].1 > 1)
        .collect();
    groups.sort_by_key(|group| {
        std::cmp::Reverse(
            (ir.blocks[group[0].0].stmts.len() - group[0].1 - 1).saturating_mul(group.len() - 1),
        )
    });
    if groups.is_empty() {
        return shared;
    }
    let mut merged = ir.clone();
    let mut used = vec![false; ir.blocks.len()];
    // Unresolved direct targets must not become edges to a new block.
    let mut next = ir.blocks.iter().map(|block| block.start).max().unwrap_or(0);
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        match stmt {
            Stmt::Br {
                target: Some(target),
                ..
            }
            | Stmt::Brif { target, .. }
            | Stmt::BrifFlags { target, .. } => next = next.max(*target),
            Stmt::Switch { cases, default, .. } => {
                for (_, target) in cases {
                    next = next.max(*target);
                }
                if let Some(target) = default {
                    next = next.max(*target);
                }
            }
            _ => {}
        }
    }
    let mut changed = false;
    for group in groups {
        let members: Vec<_> = group
            .into_iter()
            .filter(|(block, _)| !used[*block])
            .collect();
        if members.len() < 2 {
            continue;
        }
        let Some(address) = next.checked_add(1) else {
            break;
        };
        next = address;
        let (first, position) = members[0];
        let mut stmts = ir.blocks[first].stmts[position..].to_vec();
        for (offset, stmt) in stmts.iter_mut().enumerate() {
            if members.iter().any(|(block, position)| {
                ir.blocks[*block].stmts[*position + offset].origin() != stmt.origin()
            }) {
                stmt.set_origin(None);
            }
        }
        for (block, position) in members {
            used[block] = true;
            merged.blocks[block].stmts.truncate(position);
            merged.blocks[block].stmts.push(Stmt::Br {
                target: Some(address),
                at: None,
            });
        }
        merged.blocks.push(Block {
            start: address,
            stmts,
        });
        changed = true;
    }
    if !changed {
        return shared;
    }
    Some(super::duplicate::threaded(&merged).unwrap_or(merged))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::Isa;

    fn exits() -> FunctionIr {
        let mut ir = FunctionIr::single_block(Isa::X86_64, Vec::new());
        ir.blocks = vec![10, 20]
            .into_iter()
            .map(|start| Block {
                start,
                stmts: vec![
                    Stmt::Assign {
                        dest: RegRef {
                            index: 0,
                            width: 64,
                        },
                        value: Expr::Const(19),
                        at: None,
                    },
                    Stmt::Ret {
                        value: Expr::reg(0, 64),
                        at: None,
                    },
                ],
            })
            .collect();
        ir
    }

    #[test]
    fn constants_and_successors_must_match() {
        let mut ir = exits();
        assert!(merged(&ir).is_some());
        ir.blocks[1].stmts[0] = Stmt::Assign {
            dest: RegRef {
                index: 0,
                width: 64,
            },
            value: Expr::Const(20),
            at: None,
        };
        assert!(merged(&ir).is_none());
        ir.blocks[1].stmts[0] = ir.blocks[0].stmts[0].clone();
        ir.blocks[0].stmts[1] = Stmt::Br {
            target: Some(100),
            at: None,
        };
        ir.blocks[1].stmts[1] = Stmt::Br {
            target: Some(200),
            at: None,
        };
        assert!(merged(&ir).is_none());
    }

    #[test]
    fn excludes_exception_regions_and_address_overflow() {
        let mut ir = exits();
        ir.landing_pads.push((20, vec![(10, 20)]));
        assert!(merged(&ir).is_none());
        ir.landing_pads.clear();
        ir.blocks[1].start = u64::MAX;
        assert!(merged(&ir).is_none());
    }

    #[test]
    fn new_blocks_do_not_capture_external_branches() {
        let mut ir = exits();
        for block in &mut ir.blocks {
            block.stmts[1] = Stmt::Br {
                target: Some(21),
                at: None,
            };
        }
        let merged = merged(&ir).unwrap();
        assert!(merged.blocks.iter().all(|block| block.start != 21));
        assert!(matches!(
            merged.blocks.last().unwrap().stmts.last(),
            Some(Stmt::Br {
                target: Some(21),
                ..
            })
        ));
    }
}

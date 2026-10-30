use crate::ir::visit::statement_registers;
use crate::ir::{Expr, FunctionIr, Stmt};

fn same_assignment(left: &Stmt, right: &Stmt) -> bool {
    match (left, right) {
        (
            Stmt::Assign {
                dest: a, value: x, ..
            },
            Stmt::Assign {
                dest: b, value: y, ..
            },
        ) => a == b && x == y,
        _ => false,
    }
}

// Keep memory reads and potentially trapping operations in place.
fn safe_to_move_expression(expr: &Expr) -> bool {
    match expr {
        Expr::Const(_) | Expr::Reg { .. } => true,
        Expr::SignExtend { value, .. } => safe_to_move_expression(value),
        Expr::Bin {
            op:
                crate::ir::BinOp::Add
                | crate::ir::BinOp::Sub
                | crate::ir::BinOp::And
                | crate::ir::BinOp::Or
                | crate::ir::BinOp::Xor,
            lhs,
            rhs,
        } => safe_to_move_expression(lhs) && safe_to_move_expression(rhs),
        _ => false,
    }
}

fn movable(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Assign { value, .. } => safe_to_move_expression(value),
        _ => false,
    }
}

fn independent(left: &Stmt, right: &Stmt) -> bool {
    if !matches!(right, Stmt::Assign { value, .. } if safe_to_move_expression(value)) {
        return false;
    }
    let (left_writes, left_reads) = statement_registers(left);
    let (right_writes, right_reads) = statement_registers(right);
    left_writes.is_disjoint(&right_writes)
        && left_writes.is_disjoint(&right_reads)
        && right_writes.is_disjoint(&left_reads)
}

fn body_end(stmts: &[Stmt]) -> usize {
    if matches!(
        stmts.last(),
        Some(Stmt::Br {
            target: Some(_),
            ..
        })
    ) {
        stmts.len() - 1
    } else {
        stmts.len()
    }
}

/// Move identical setup to joins, and identical branch prefixes before the test.
/// Only independent register assignments may be crossed; memory order is unchanged.
pub(super) fn share_assignments(ir: &FunctionIr) -> Option<FunctionIr> {
    if !ir.landing_pads.is_empty()
        || ir.blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
            matches!(
                stmt,
                Stmt::BrIndirect { .. } | Stmt::Br { target: None, .. }
            )
        })
    {
        return None;
    }
    let mut out = ir.clone();
    let mut changed = false;
    let edges: Vec<Vec<usize>> = (0..ir.blocks.len())
        .map(|index| {
            let mut edges = crate::ir::cfg::successors(ir, index);
            edges.sort_unstable();
            edges.dedup();
            edges
        })
        .collect();
    let mut incoming = vec![Vec::new(); ir.blocks.len()];
    for (from, successors) in edges.iter().enumerate() {
        for to in successors {
            incoming[*to].push(from);
        }
    }
    let later_incoming = incoming.iter().enumerate().skip(1);
    for (join, predecessors) in later_incoming {
        if predecessors.len() < 2
            || predecessors.contains(&join)
            || !predecessors.iter().all(|from| edges[*from] == [join])
        {
            continue;
        }
        let mut moved = Vec::new();
        loop {
            let first = &out.blocks[predecessors[0]].stmts;
            let end = body_end(first);
            let candidate = (0..end).rev().find_map(|at| {
                let stmt = &first[at];
                if !movable(stmt)
                    || !first[at + 1..end]
                        .iter()
                        .all(|other| independent(stmt, other))
                {
                    return None;
                }
                let mut positions = vec![at];
                for from in &predecessors[1..] {
                    let body = &out.blocks[*from].stmts;
                    let end = body_end(body);
                    let Some(position) = (0..end).rev().find(|position| {
                        same_assignment(&body[*position], stmt)
                            && body[*position + 1..end]
                                .iter()
                                .all(|other| independent(stmt, other))
                    }) else {
                        return None;
                    };
                    positions.push(position);
                }
                Some((stmt.clone(), positions))
            });
            let Some((mut stmt, positions)) = candidate else {
                break;
            };
            for (from, position) in predecessors.iter().zip(positions) {
                let other = out.blocks[*from].stmts.remove(position);
                if stmt.origin() != other.origin() {
                    stmt.set_origin(None);
                }
            }
            moved.push(stmt);
            changed = true;
        }
        moved.reverse();
        out.blocks[join].stmts.splice(0..0, moved);
    }
    for (from, successors) in edges.iter().enumerate() {
        if successors.len() < 2
            || successors.contains(&from)
            || !successors
                .iter()
                .all(|to| *to != 0 && incoming[*to] == [from])
        {
            continue;
        }
        while let Some(mut stmt) = out.blocks[successors[0]].stmts.first().cloned() {
            if !movable(&stmt)
                || !successors.iter().all(|to| {
                    out.blocks[*to]
                        .stmts
                        .first()
                        .is_some_and(|other| same_assignment(other, &stmt))
                })
            {
                break;
            }
            let Some(test) = out.blocks[from].stmts.last() else {
                break;
            };
            let resolved = |target: &u64| ir.blocks.iter().any(|block| block.start == *target);
            let complete = match test {
                Stmt::Brif {
                    target, lhs, rhs, ..
                } => {
                    resolved(target)
                        && from + 1 < ir.blocks.len()
                        && safe_to_move_expression(lhs)
                        && safe_to_move_expression(rhs)
                }
                Stmt::Switch {
                    index,
                    cases,
                    default: Some(default),
                    ..
                } => {
                    safe_to_move_expression(index)
                        && resolved(default)
                        && cases.iter().all(|(_, target)| resolved(target))
                }
                _ => false,
            };
            if !complete {
                break;
            }
            let (writes, _) = statement_registers(&stmt);
            let (_, reads) = statement_registers(test);
            if !writes.is_disjoint(&reads) {
                break;
            }
            for to in successors {
                let other = out.blocks[*to].stmts.remove(0);
                if stmt.origin() != other.origin() {
                    stmt.set_origin(None);
                }
            }
            let end = out.blocks[from].stmts.len() - 1;
            out.blocks[from].stmts.insert(end, stmt);
            changed = true;
        }
    }
    changed.then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Block, Cond, RegRef};
    use crate::loader::Isa;

    fn assign(index: u16, value: Expr) -> Stmt {
        Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
            at: None,
        }
    }

    fn diamond() -> FunctionIr {
        let mut ir = FunctionIr::single_block(Isa::X86_64, Vec::new());
        ir.blocks = vec![
            Block {
                start: 0,
                stmts: vec![Stmt::Brif {
                    cond: Cond::Eq,
                    lhs: Expr::reg(0, 64),
                    rhs: Expr::Const(0),
                    target: 20,
                    at: None,
                }],
            },
            Block {
                start: 10,
                stmts: vec![
                    assign(1, Expr::Const(19)),
                    assign(2, Expr::Const(1)),
                    Stmt::Br {
                        target: Some(30),
                        at: None,
                    },
                ],
            },
            Block {
                start: 20,
                stmts: vec![
                    assign(1, Expr::Const(19)),
                    assign(2, Expr::Const(8)),
                    Stmt::Br {
                        target: Some(30),
                        at: None,
                    },
                ],
            },
            Block {
                start: 30,
                stmts: vec![Stmt::Ret {
                    value: Expr::reg(1, 64),
                    at: None,
                }],
            },
        ];
        ir
    }

    #[test]
    fn sinks_interleaved_constants_but_preserves_observers() {
        let ir = diamond();
        let shared = share_assignments(&ir).unwrap();
        assert!(same_assignment(
            &shared.blocks[3].stmts[0],
            &ir.blocks[1].stmts[0]
        ));
        for observer in [
            assign(2, Expr::reg(1, 64)),
            Stmt::Store {
                addr: Expr::reg(3, 64),
                value: Expr::reg(1, 64),
                width: 8,
                at: None,
            },
            Stmt::Trap { at: None },
            Stmt::unsupported("unknown instruction"),
            assign(
                2,
                Expr::Bin {
                    op: crate::ir::BinOp::DivU,
                    lhs: Box::new(Expr::Const(1)),
                    rhs: Box::new(Expr::reg(3, 64)),
                },
            ),
            assign(
                2,
                Expr::Load {
                    addr: Box::new(Expr::reg(3, 64)),
                    width: 8,
                    signed: false,
                },
            ),
            assign(1, Expr::Const(20)),
        ] {
            let mut ir = diamond();
            ir.blocks[1].stmts[1] = observer;
            // Prevent prefix hoisting so this assertion isolates sinking.
            ir.blocks[0].stmts[0] = Stmt::Brif {
                cond: Cond::Eq,
                lhs: Expr::reg(1, 64),
                rhs: Expr::Const(0),
                target: 20,
                at: None,
            };
            assert!(super::share_assignments(&ir).is_none());
        }
    }

    #[test]
    fn hoists_only_when_the_test_and_all_incoming_edges_allow_it() {
        let mut ir = diamond();
        ir.blocks[2].stmts.pop();
        ir.blocks[2].stmts.push(Stmt::Ret {
            value: Expr::reg(1, 64),
            at: None,
        });
        let result = share_assignments(&ir).unwrap();
        assert!(same_assignment(
            &result.blocks[0].stmts[0],
            &ir.blocks[1].stmts[0]
        ));
        ir.blocks[0].stmts[0] = Stmt::Brif {
            cond: Cond::Eq,
            lhs: Expr::reg(1, 64),
            rhs: Expr::Const(0),
            target: 20,
            at: None,
        };
        assert!(share_assignments(&ir).is_none());
        ir.blocks[0].stmts[0] = Stmt::Brif {
            cond: Cond::Eq,
            lhs: Expr::reg(0, 64),
            rhs: Expr::Const(0),
            target: 20,
            at: None,
        };
        ir.blocks[3].stmts = vec![Stmt::Br {
            target: Some(20),
            at: None,
        }];
        assert!(share_assignments(&ir).is_none());
    }

    #[test]
    fn excludes_unknown_edges_and_exception_entries() {
        let mut ir = diamond();
        ir.landing_pads.push((30, vec![(10, 20)]));
        assert!(share_assignments(&ir).is_none());
        ir.landing_pads.clear();
        ir.blocks[3].stmts = vec![Stmt::BrIndirect {
            target: Expr::reg(0, 64),
            at: None,
        }];
        assert!(share_assignments(&ir).is_none());
    }

    #[test]
    fn sinks_a_sequence_from_explicit_and_fallthrough_edges() {
        let mut ir = diamond();
        for at in [1, 2] {
            ir.blocks[at].stmts.insert(1, assign(3, Expr::reg(1, 64)));
        }
        ir.blocks[2].stmts.pop();
        let result = share_assignments(&ir).unwrap();
        assert!(same_assignment(
            &result.blocks[3].stmts[0],
            &ir.blocks[1].stmts[0]
        ));
        assert!(same_assignment(
            &result.blocks[3].stmts[1],
            &ir.blocks[1].stmts[1]
        ));
        assert_eq!(result.blocks[1].stmts.len(), 2);
        assert_eq!(result.blocks[2].stmts.len(), 1);
    }

    #[test]
    fn switch_requires_every_target_and_counts_repeated_targets_once() {
        let mut ir = diamond();
        ir.blocks[2].stmts.pop();
        ir.blocks[2].stmts.push(Stmt::Ret {
            value: Expr::reg(1, 64),
            at: None,
        });
        ir.blocks[0].stmts = vec![Stmt::Switch {
            index: Expr::reg(0, 64),
            cases: vec![(0, 10), (1, 10), (2, 20)],
            default: Some(20),
            at: None,
        }];
        let result = share_assignments(&ir).unwrap();
        assert!(same_assignment(
            &result.blocks[0].stmts[0],
            &ir.blocks[1].stmts[0]
        ));
        if let Stmt::Switch { cases, .. } = &mut ir.blocks[0].stmts[0] {
            cases.push((3, 999));
        }
        assert!(share_assignments(&ir).is_none());
    }

    #[test]
    fn partial_writes_and_source_changes_block_sinking() {
        for width in [8, 16, 32, 64] {
            let mut ir = diamond();
            ir.blocks[0].stmts = vec![Stmt::Brif {
                cond: Cond::Eq,
                lhs: Expr::reg(1, 64),
                rhs: Expr::Const(0),
                target: 20,
                at: None,
            }];
            ir.blocks[1].stmts[1] = Stmt::Assign {
                dest: RegRef { index: 1, width },
                value: Expr::Const(20),
                at: None,
            };
            assert!(share_assignments(&ir).is_none());
        }
        let mut ir = diamond();
        for at in [1, 2] {
            ir.blocks[at].stmts[0] = assign(1, Expr::reg(2, 64));
        }
        ir.blocks[0].stmts = vec![Stmt::Brif {
            cond: Cond::Eq,
            lhs: Expr::reg(1, 64),
            rhs: Expr::Const(0),
            target: 20,
            at: None,
        }];
        assert!(share_assignments(&ir).is_none());
    }
}

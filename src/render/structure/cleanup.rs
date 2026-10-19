use crate::ir::{Expr, Stmt};
use crate::render::structure::Node;

/// A conditional branch to the block right after the loop reads as `break`.
pub(crate) fn fold_exit_branches(nodes: &mut [Node], exit: Option<u64>) {
    let Some(exit) = exit else {
        return;
    };
    for node in nodes.iter_mut() {
        match node {
            Node::Stmt(Stmt::Brif {
                cond,
                lhs,
                rhs,
                target,
            }) if *target == exit => {
                *node = Node::If {
                    cond: *cond,
                    lhs: lhs.clone(),
                    rhs: rhs.clone(),
                    then: vec![Node::Break],
                    els: Vec::new(),
                };
            }
            Node::If { then, els, .. } => {
                fold_exit_branches(then, Some(exit));
                fold_exit_branches(els, Some(exit));
            }
            Node::DoWhile { body, .. } | Node::Forever { body } | Node::While { body, .. } => {
                fold_exit_branches(body, Some(exit));
            }
            Node::Switch { arms, default, .. } => {
                for (_, body) in arms.iter_mut() {
                    fold_exit_branches(body, Some(exit));
                }
                if let Some(body) = default {
                    fold_exit_branches(body, Some(exit));
                }
            }
            _ => {}
        }
    }
}

/// `if (c) goto L; ...; L:` inside one body is `if (!c) { ... } L:`. The label
/// stays for other jumps to it; unused labels are pruned later.
pub(crate) fn fold_label_branches(nodes: &mut Vec<Node>) {
    let mut label_at = 0;
    while label_at < nodes.len() {
        let Node::Label(target) = nodes[label_at] else {
            label_at += 1;
            continue;
        };
        let branch_at = (0..label_at).rev().find(|position| {
            matches!(
                &nodes[*position],
                Node::Stmt(Stmt::Brif { target: inner, .. }) if *inner == target
            )
        });
        if let Some(branch_at) = branch_at
            && let Node::Stmt(Stmt::Brif { cond, lhs, rhs, .. }) = nodes[branch_at].clone()
        {
            let body: Vec<Node> = nodes
                .splice(branch_at + 1..label_at, std::iter::empty())
                .collect();
            nodes[branch_at] = Node::If {
                cond: cond.invert(),
                lhs,
                rhs,
                then: body,
                els: Vec::new(),
            };
            label_at = branch_at + 1;
        }
        label_at += 1;
    }
}

fn terminates(nodes: &[Node]) -> bool {
    matches!(
        nodes.last(),
        Some(Node::Stmt(
            Stmt::Ret { .. } | Stmt::Br { .. } | Stmt::BrIndirect { .. } | Stmt::Switch { .. }
        ))
    )
}

/// Folds a loop header's temporary reads into the exit test, so
/// `x8 = local_0; if (x8 == 0) break;` reads as `while (local_0 != 0)`.
/// Only values that merely move a register or read memory fold, and only
/// when the body cannot observe the temporary first.
pub(crate) fn fold_header(
    prefix: Vec<Node>,
    lhs: &Expr,
    rhs: &Expr,
    body: &[Node],
) -> (Vec<Node>, Expr, Expr) {
    if prefix.is_empty() {
        return (prefix, lhs.clone(), rhs.clone());
    }
    let mut values: Vec<(u16, Expr)> = Vec::new();
    for node in &prefix {
        let Node::Stmt(Stmt::Assign { dest, value }) = node else {
            return (prefix, lhs.clone(), rhs.clone());
        };
        if !moves_value(value) {
            return (prefix, lhs.clone(), rhs.clone());
        }
        let mut reads = std::collections::HashSet::new();
        crate::ir::visit::collect_reads(value, &mut reads);
        if reads.contains(&dest.index) {
            return (prefix, lhs.clone(), rhs.clone());
        }
        let value = crate::ir::visit::substitute_values(value.clone(), &values);
        values.retain(|(register, _)| *register != dest.index);
        values.push((dest.index, value));
    }
    // The body must not read a temporary before it overwrites it.
    let mut reads = std::collections::HashSet::new();
    collect_node_reads(body, &mut reads);
    let killed: Option<u16> = body.first().and_then(|node| match node {
        Node::Stmt(Stmt::Assign { dest, value }) => {
            let mut own = std::collections::HashSet::new();
            crate::ir::visit::collect_reads(value, &mut own);
            (!own.contains(&dest.index)).then_some(dest.index)
        }
        _ => None,
    });
    if values
        .iter()
        .any(|(register, _)| reads.contains(register) && killed != Some(*register))
    {
        return (prefix, lhs.clone(), rhs.clone());
    }
    let lhs = crate::ir::visit::substitute_values(lhs.clone(), &values);
    let rhs = crate::ir::visit::substitute_values(rhs.clone(), &values);
    (Vec::new(), lhs, rhs)
}

/// A plain register or memory read, optionally masked with `&`.
fn moves_value(value: &Expr) -> bool {
    match value {
        Expr::Reg { .. } | Expr::Load { .. } => true,
        Expr::Bin { op, lhs, .. } => {
            matches!(op, crate::ir::BinOp::And)
                && matches!(lhs.as_ref(), Expr::Reg { .. } | Expr::Load { .. })
        }
        _ => false,
    }
}

fn collect_node_reads(nodes: &[Node], reads: &mut std::collections::HashSet<u16>) {
    for node in nodes {
        match node {
            Node::Stmt(stmt) => {
                reads.extend(crate::ir::visit::statement_reads(stmt));
            }
            Node::If {
                lhs,
                rhs,
                then,
                els,
                ..
            } => {
                crate::ir::visit::collect_reads(lhs, reads);
                crate::ir::visit::collect_reads(rhs, reads);
                collect_node_reads(then, reads);
                collect_node_reads(els, reads);
            }
            Node::While {
                prefix,
                lhs,
                rhs,
                body,
                ..
            } => {
                collect_node_reads(prefix, reads);
                crate::ir::visit::collect_reads(lhs, reads);
                crate::ir::visit::collect_reads(rhs, reads);
                collect_node_reads(body, reads);
            }
            Node::DoWhile { lhs, rhs, body, .. } => {
                crate::ir::visit::collect_reads(lhs, reads);
                crate::ir::visit::collect_reads(rhs, reads);
                collect_node_reads(body, reads);
            }
            Node::Forever { body } => collect_node_reads(body, reads),
            Node::Switch { arms, default, .. } => {
                for (_, body) in arms {
                    collect_node_reads(body, reads);
                }
                if let Some(body) = default {
                    collect_node_reads(body, reads);
                }
            }
            Node::Break | Node::Continue | Node::Label(_) => {}
        }
    }
}

/// A branch to the loop's exit is a `break`, and a branch back to its
/// header is a `continue`. Nested loops keep their own exits, so their
/// bodies are left alone.
pub(crate) fn rewrite_loop_exits(nodes: &mut [Node], exit: Option<u64>, header: Option<u64>) {
    for node in nodes.iter_mut() {
        match node {
            Node::Stmt(Stmt::Br {
                target: Some(target),
            }) => {
                if Some(*target) == exit {
                    *node = Node::Break;
                } else if Some(*target) == header {
                    *node = Node::Continue;
                }
            }
            Node::Stmt(Stmt::Brif {
                cond,
                lhs,
                rhs,
                target,
            }) => {
                if Some(*target) == exit {
                    *node = Node::If {
                        cond: *cond,
                        lhs: lhs.clone(),
                        rhs: rhs.clone(),
                        then: vec![Node::Break],
                        els: Vec::new(),
                    };
                } else if Some(*target) == header {
                    *node = Node::If {
                        cond: *cond,
                        lhs: lhs.clone(),
                        rhs: rhs.clone(),
                        then: vec![Node::Continue],
                        els: Vec::new(),
                    };
                }
            }
            Node::If { then, els, .. } => {
                rewrite_loop_exits(then, exit, header);
                rewrite_loop_exits(els, exit, header);
            }
            Node::Switch { arms, default, .. } => {
                for (_, body) in arms {
                    rewrite_loop_exits(body, exit, header);
                }
                if let Some(body) = default {
                    rewrite_loop_exits(body, exit, header);
                }
            }
            _ => {}
        }
    }
}

pub(crate) fn flatten_early_returns(nodes: &mut Vec<Node>) {
    for node in nodes.iter_mut() {
        match node {
            Node::If { then, els, .. } => {
                flatten_early_returns(then);
                flatten_early_returns(els);
            }
            Node::DoWhile { body, .. } | Node::Forever { body } => flatten_early_returns(body),
            Node::While { prefix, body, .. } => {
                flatten_early_returns(prefix);
                flatten_early_returns(body);
            }
            Node::Switch { arms, default, .. } => {
                for (_, body) in arms {
                    flatten_early_returns(body);
                }
                if let Some(body) = default {
                    flatten_early_returns(body);
                }
            }
            Node::Break | Node::Continue | Node::Label(_) | Node::Stmt(_) => {}
        }
    }

    let mut flattened = Vec::with_capacity(nodes.len());
    for node in nodes.drain(..) {
        match node {
            Node::If {
                cond,
                lhs,
                rhs,
                then,
                els,
            } if !els.is_empty() && terminates(&then) => {
                flattened.push(Node::If {
                    cond,
                    lhs,
                    rhs,
                    then,
                    els: Vec::new(),
                });
                flattened.extend(els);
            }
            other => flattened.push(other),
        }
    }
    *nodes = flattened;
}

pub(crate) fn prune_unreachable(nodes: &mut Vec<Node>) {
    let mut reachable = true;
    nodes.retain(|node| match node {
        Node::Stmt(stmt) => {
            if !reachable {
                return false;
            }
            if matches!(
                stmt,
                Stmt::Br { .. }
                    | Stmt::BrIndirect { .. }
                    | Stmt::Switch { .. }
                    | Stmt::Ret { .. }
                    | Stmt::Trap
            ) {
                reachable = false;
            }
            true
        }
        Node::Label(_) => {
            reachable = true;
            true
        }
        Node::Break | Node::Continue => {
            reachable = false;
            true
        }
        Node::If { .. }
        | Node::DoWhile { .. }
        | Node::Forever { .. }
        | Node::While { .. }
        | Node::Switch { .. } => {
            reachable = true;
            true
        }
    });
    for node in nodes.iter_mut() {
        match node {
            Node::If { then, els, .. } => {
                prune_unreachable(then);
                prune_unreachable(els);
            }
            Node::DoWhile { body, .. } | Node::Forever { body } => prune_unreachable(body),
            Node::Switch { arms, default, .. } => {
                for (_, body) in arms {
                    prune_unreachable(body);
                }
                if let Some(body) = default {
                    prune_unreachable(body);
                }
            }
            Node::While { prefix, body, .. } => {
                prune_unreachable(prefix);
                prune_unreachable(body);
            }
            _ => {}
        }
    }
}

pub(crate) fn collect_targets(nodes: &[Node], used: &mut std::collections::HashSet<u64>) {
    for node in nodes {
        match node {
            Node::Stmt(Stmt::Brif { target, .. }) | Node::Stmt(Stmt::BrifFlags { target, .. }) => {
                used.insert(*target);
            }
            Node::Stmt(Stmt::Br {
                target: Some(target),
            }) => {
                used.insert(*target);
            }
            Node::Stmt(Stmt::Switch { cases, default, .. }) => {
                for (_, target) in cases {
                    used.insert(*target);
                }
                if let Some(target) = default {
                    used.insert(*target);
                }
            }
            Node::If { then, els, .. } => {
                collect_targets(then, used);
                collect_targets(els, used);
            }
            Node::DoWhile { body, .. } | Node::Forever { body } => collect_targets(body, used),
            Node::Switch { arms, default, .. } => {
                for (_, body) in arms {
                    collect_targets(body, used);
                }
                if let Some(body) = default {
                    collect_targets(body, used);
                }
            }
            Node::While { prefix, body, .. } => {
                collect_targets(prefix, used);
                collect_targets(body, used);
            }
            _ => {}
        }
    }
}

pub(crate) fn prune_labels(nodes: &mut Vec<Node>, used: &std::collections::HashSet<u64>) {
    nodes.retain(|node| match node {
        Node::Label(address) => used.contains(address),
        _ => true,
    });
    for node in nodes.iter_mut() {
        match node {
            Node::If { then, els, .. } => {
                prune_labels(then, used);
                prune_labels(els, used);
            }
            Node::DoWhile { body, .. } | Node::Forever { body } => prune_labels(body, used),
            Node::Switch { arms, default, .. } => {
                for (_, body) in arms {
                    prune_labels(body, used);
                }
                if let Some(body) = default {
                    prune_labels(body, used);
                }
            }
            Node::While { prefix, body, .. } => {
                prune_labels(prefix, used);
                prune_labels(body, used);
            }
            _ => {}
        }
    }
}

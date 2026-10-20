use crate::ir::{Expr, Stmt};
use crate::render::structure::Node;
use std::collections::HashMap;

/// A conditional branch to the block right after the loop reads as `break`.
/// Inside a nested loop or a switch a `break` would leave that instead, so
/// branches there stay.
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
/// Only values that merely move a register or read memory fold, only when
/// the body cannot observe the temporary first, and only when no other block,
/// such as the code after the loop, in `elsewhere` reads it.
pub(crate) fn fold_header(
    prefix: Vec<Node>,
    lhs: &Expr,
    rhs: &Expr,
    body: &[Node],
    elsewhere: &std::collections::HashSet<u16>,
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
    if values.iter().any(|(register, _)| {
        (reads.contains(register) && killed != Some(*register)) || elsewhere.contains(register)
    }) {
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
        // Nothing after an `if` or a `switch` runs when every way through
        // it leaves.
        Node::If { .. } | Node::Switch { .. } => {
            if !reachable {
                return false;
            }
            reachable = !ends(std::slice::from_ref(node), true);
            true
        }
        Node::DoWhile { .. } | Node::Forever { .. } | Node::While { .. } => {
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

/// Whether control never runs off the end of `nodes`: they end in a return,
/// a jump or a trap, or in an `if` or a `switch` with a default all of whose
/// ways end so. A `break` leaves too where `break_leaves` says, as it does
/// out of a loop, but not out of a `switch`, after which it carries on.
fn ends(nodes: &[Node], break_leaves: bool) -> bool {
    match nodes.last() {
        Some(Node::Stmt(stmt)) => matches!(
            stmt,
            Stmt::Ret { .. }
                | Stmt::Br { .. }
                | Stmt::BrIndirect { .. }
                | Stmt::Switch { .. }
                | Stmt::Trap
        ),
        Some(Node::Continue) => true,
        Some(Node::Break) => break_leaves,
        Some(Node::If { then, els, .. }) => ends(then, break_leaves) && ends(els, break_leaves),
        Some(Node::Switch {
            arms,
            default: Some(default),
            ..
        }) => arms.iter().all(|(_, body)| ends(body, false)) && ends(default, false),
        _ => false,
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

/// The node lists directly inside a node.
fn children(node: &Node) -> Vec<&Vec<Node>> {
    match node {
        Node::If { then, els, .. } => vec![then, els],
        Node::DoWhile { body, .. } | Node::Forever { body } => vec![body],
        Node::While { prefix, body, .. } => vec![prefix, body],
        Node::Switch { arms, default, .. } => arms
            .iter()
            .map(|(_, body)| body)
            .chain(default.iter())
            .collect(),
        Node::Stmt(_) | Node::Label(_) | Node::Break | Node::Continue => Vec::new(),
    }
}

/// The same, to change.
fn children_mut(node: &mut Node) -> Vec<&mut Vec<Node>> {
    match node {
        Node::If { then, els, .. } => vec![then, els],
        Node::DoWhile { body, .. } | Node::Forever { body } => vec![body],
        Node::While { prefix, body, .. } => vec![prefix, body],
        Node::Switch { arms, default, .. } => arms
            .iter_mut()
            .map(|(_, body)| body)
            .chain(default.iter_mut())
            .collect(),
        Node::Stmt(_) | Node::Label(_) | Node::Break | Node::Continue => Vec::new(),
    }
}

/// Replaces each jump to a label that only runs a few statements before
/// returning, or before trapping after a call that does not return, with
/// those statements, while that copies no more than a few in all.
pub(crate) fn inline_return_tails(nodes: &mut Vec<Node>) {
    fn jumps(nodes: &[Node], counts: &mut HashMap<u64, usize>) {
        for node in nodes {
            if let Node::Stmt(Stmt::Br {
                target: Some(target),
            }) = node
            {
                *counts.entry(*target).or_default() += 1;
            }
            for child in children(node) {
                jumps(child, counts);
            }
        }
    }
    fn collect(nodes: &mut [Node], tails: &mut HashMap<u64, Vec<Node>>) {
        for index in 0..nodes.len() {
            if let Node::Label(label) = nodes[index] {
                let mut tail = Vec::new();
                for next in &nodes[index + 1..] {
                    match next {
                        Node::Label(_) => {}
                        Node::Stmt(
                            stmt @ (Stmt::Assign { .. } | Stmt::Store { .. } | Stmt::Call { .. }),
                        ) if tail.len() < 3 => tail.push(Node::Stmt(stmt.clone())),
                        Node::Stmt(stmt @ (Stmt::Ret { .. } | Stmt::Trap)) => {
                            tail.push(Node::Stmt(stmt.clone()));
                            tails.insert(label, tail);
                            break;
                        }
                        _ => break,
                    }
                }
            }
            for child in children_mut(&mut nodes[index]) {
                collect(child, tails);
            }
        }
    }
    fn replace(nodes: &mut Vec<Node>, tails: &HashMap<u64, Vec<Node>>) {
        let mut index = 0;
        while index < nodes.len() {
            if let Node::Stmt(Stmt::Br {
                target: Some(target),
            }) = &nodes[index]
                && let Some(tail) = tails.get(target)
            {
                let tail = tail.clone();
                let length = tail.len();
                nodes.splice(index..=index, tail);
                index += length;
                continue;
            }
            for child in children_mut(&mut nodes[index]) {
                replace(child, tails);
            }
            index += 1;
        }
    }
    let mut tails = HashMap::new();
    collect(nodes, &mut tails);
    let mut counts = HashMap::new();
    jumps(nodes, &mut counts);
    tails.retain(|label, tail| (tail.len() - 1) * counts.get(label).copied().unwrap_or(0) <= 4);
    if !tails.is_empty() {
        replace(nodes, &tails);
    }
}

/// Returns the constant a variable holds on each path to a return, where
/// the path set it last, and drops assignments nothing reads any more.
pub(crate) fn return_known_constants(nodes: &mut Vec<Node>) {
    use crate::ir::Expr;
    type Known = std::collections::HashMap<u16, u64>;
    fn walk(nodes: &mut [Node], known: &mut Known) {
        for node in nodes.iter_mut() {
            match node {
                Node::Stmt(Stmt::Ret { value }) => {
                    let replaced = match value {
                        Expr::Reg { index, .. } => known.get(index).map(|c| Expr::Const(*c)),
                        Expr::Bin {
                            op: crate::ir::BinOp::And,
                            lhs,
                            rhs,
                        } => match (lhs.as_ref(), rhs.as_ref()) {
                            (Expr::Reg { index, .. }, Expr::Const(mask)) => {
                                known.get(index).map(|c| Expr::Const(c & mask))
                            }
                            _ => None,
                        },
                        _ => None,
                    };
                    if let Some(replaced) = replaced {
                        *value = replaced;
                    }
                }
                Node::Stmt(stmt) => {
                    for written in crate::ir::visit::statement_registers(stmt).0 {
                        known.remove(&written);
                    }
                    if let Stmt::Assign {
                        dest,
                        value: Expr::Const(c),
                    } = stmt
                        && dest.index >= crate::ir::VARIABLE_BASE
                        && dest.width == 64
                    {
                        known.insert(dest.index, *c);
                    }
                }
                Node::If { then, els, .. } => {
                    let mut written = std::collections::HashSet::new();
                    writes_in(then, &mut written);
                    writes_in(els, &mut written);
                    walk(then, &mut known.clone());
                    walk(els, &mut known.clone());
                    known.retain(|variable, _| !written.contains(variable));
                }
                // A loop's body may run after its own later writes; a
                // label may be entered from anywhere.
                other => {
                    let mut written = std::collections::HashSet::new();
                    writes_in(std::slice::from_ref(other), &mut written);
                    for child in children_mut(other) {
                        walk(child, &mut Known::new());
                    }
                    if matches!(other, Node::Label(_)) {
                        known.clear();
                    }
                    known.retain(|variable, _| !written.contains(variable));
                }
            }
        }
    }
    walk(nodes, &mut Known::new());
    // Assignments to variables nothing reads now go.
    let mut read = std::collections::HashSet::new();
    reads_in(nodes, &mut read);
    drop_unread(nodes, &read);
}

/// The registers the nodes read, at any depth.
fn reads_in(nodes: &[Node], out: &mut std::collections::HashSet<u16>) {
    for node in nodes {
        match node {
            Node::Stmt(stmt) => out.extend(crate::ir::visit::statement_registers(stmt).1),
            Node::If {
                lhs,
                rhs,
                then,
                els,
                ..
            } => {
                crate::ir::visit::collect_reads(lhs, out);
                crate::ir::visit::collect_reads(rhs, out);
                reads_in(then, out);
                reads_in(els, out);
            }
            Node::DoWhile { lhs, rhs, body, .. } => {
                crate::ir::visit::collect_reads(lhs, out);
                crate::ir::visit::collect_reads(rhs, out);
                reads_in(body, out);
            }
            Node::While {
                prefix,
                lhs,
                rhs,
                body,
                ..
            } => {
                crate::ir::visit::collect_reads(lhs, out);
                crate::ir::visit::collect_reads(rhs, out);
                reads_in(prefix, out);
                reads_in(body, out);
            }
            Node::Forever { body } => reads_in(body, out),
            Node::Switch {
                index,
                arms,
                default,
            } => {
                crate::ir::visit::collect_reads(index, out);
                for (_, body) in arms {
                    reads_in(body, out);
                }
                if let Some(body) = default {
                    reads_in(body, out);
                }
            }
            Node::Label(_) | Node::Break | Node::Continue => {}
        }
    }
}

/// Drops the assignments of constants to variables `read` does not hold,
/// and those right before a return that does not read them.
fn drop_unread(nodes: &mut Vec<Node>, read: &std::collections::HashSet<u16>) {
    nodes.retain(|node| {
        !matches!(node, Node::Stmt(Stmt::Assign { dest, value: crate::ir::Expr::Const(_) })
            if dest.index >= crate::ir::VARIABLE_BASE && !read.contains(&dest.index))
    });
    let mut index = 0;
    while index + 1 < nodes.len() {
        if let (
            Node::Stmt(Stmt::Assign {
                dest,
                value: crate::ir::Expr::Const(_),
            }),
            Node::Stmt(ret @ Stmt::Ret { .. }),
        ) = (&nodes[index], &nodes[index + 1])
            && dest.index >= crate::ir::VARIABLE_BASE
            && !crate::ir::visit::statement_registers(ret)
                .1
                .contains(&dest.index)
        {
            nodes.remove(index);
            continue;
        }
        index += 1;
    }
    for node in nodes.iter_mut() {
        for child in children_mut(node) {
            drop_unread(child, read);
        }
    }
}

/// Undoes the inversion compilers make of a counting loop: after a test
/// that leaves unless `n >= 1`, `i = 0; do { ...; i += 1; } while (i != n);`
/// runs as `while (i < n)`, which reads as the `for` loop it was. The body
/// may change neither `i` nor `n` but at its last step.
pub(crate) fn undo_loop_inversion(nodes: &mut Vec<Node>) {
    invert_loops(nodes, &std::collections::HashSet::new());
}

/// The same, with `known` the registers an enclosing test leaves at least
/// one.
fn invert_loops(nodes: &mut Vec<Node>, known: &std::collections::HashSet<u16>) {
    use crate::ir::{BinOp, Cond, Expr};
    let register = |expr: &Expr| match expr {
        Expr::Reg { index, .. } => Some(*index),
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) => match lhs.as_ref() {
            Expr::Reg { index, .. } => Some(*index),
            _ => None,
        },
        _ => None,
    };
    let below_one = |cond: &Cond, lhs: &Expr, rhs: &Expr| match (cond, register(lhs), rhs) {
        (Cond::Lt, Some(n), Expr::Const(1)) | (Cond::Le, Some(n), Expr::Const(0)) => Some(n),
        _ => None,
    };
    let mut known = known.clone();
    let mut index = 0;
    while index < nodes.len() {
        // What a test that leaves here guarantees holds for what follows.
        if let Node::If {
            cond,
            lhs,
            rhs,
            then,
            els,
        } = &nodes[index]
            && els.is_empty()
            && ends(then, false)
            && let Some(limit) = below_one(cond, lhs, rhs)
        {
            known.insert(limit);
        }
        for child in children_mut(&mut nodes[index]) {
            let mut written = std::collections::HashSet::new();
            writes_in(child, &mut written);
            let inner: std::collections::HashSet<u16> =
                known.difference(&written).copied().collect();
            invert_loops(child, &inner);
        }
        if let Node::Stmt(stmt) = &nodes[index] {
            for written in crate::ir::visit::statement_registers(stmt).0 {
                known.remove(&written);
            }
        }
        let Node::DoWhile {
            cond: Cond::Ne,
            lhs,
            rhs,
            body,
        } = &nodes[index]
        else {
            index += 1;
            continue;
        };
        // The counter steps by one at the end of the body.
        let Some((Node::Stmt(Stmt::Assign { dest, value }), rest)) = body.split_last() else {
            index += 1;
            continue;
        };
        let counter = dest.index;
        let steps = matches!(value, Expr::Bin { op: BinOp::Add, lhs: base, rhs: one }
            if register(base) == Some(counter) && matches!(one.as_ref(), Expr::Const(1)))
            || matches!(value, Expr::Bin { op: BinOp::And, lhs: inner, rhs: mask }
                if matches!(mask.as_ref(), Expr::Const(0xffff_ffff))
                    && matches!(inner.as_ref(), Expr::Bin { op: BinOp::Add, lhs: base, rhs: one }
                        if register(base) == Some(counter) && matches!(one.as_ref(), Expr::Const(1))));
        let limit = match (register(lhs), register(rhs)) {
            (Some(a), Some(b)) if a == counter => b,
            (Some(a), Some(b)) if b == counter => a,
            _ => u16::MAX,
        };
        let mut written = std::collections::HashSet::new();
        writes_in(rest, &mut written);
        if !steps
            || limit == u16::MAX
            || written.contains(&counter)
            || written.contains(&limit)
            || !known.contains(&limit)
        {
            index += 1;
            continue;
        }
        // The counter set to zero before the loop, with what comes between
        // leaving it alone.
        let mut start = None;
        for (at, before) in nodes[..index].iter().enumerate().rev() {
            match before {
                Node::Stmt(Stmt::Assign { dest, value }) if dest.index == counter => {
                    if matches!(value, Expr::Const(0)) {
                        start = Some(at);
                    }
                    break;
                }
                Node::Stmt(stmt @ (Stmt::Assign { .. } | Stmt::Store { .. })) => {
                    let (writes, reads) = crate::ir::visit::statement_registers(stmt);
                    if writes.contains(&counter) || reads.contains(&counter) {
                        break;
                    }
                }
                _ => break,
            }
        }
        let Some(start) = start else {
            index += 1;
            continue;
        };
        let Node::DoWhile { lhs, rhs, body, .. } = nodes[index].clone() else {
            index += 1;
            continue;
        };
        let (lhs, rhs) = if register(&lhs) == Some(counter) {
            (lhs, rhs)
        } else {
            (rhs, lhs)
        };
        nodes[index] = Node::While {
            prefix: Vec::new(),
            cond: Cond::Lt,
            lhs,
            rhs,
            body,
        };
        // The counter's start goes right before the loop, as a `for` has it.
        let init = nodes.remove(start);
        nodes.insert(index - 1, init);
        index += 1;
    }
}

/// The registers the nodes write, at any depth.
fn writes_in(nodes: &[Node], out: &mut std::collections::HashSet<u16>) {
    for node in nodes {
        match node {
            Node::Stmt(stmt) => out.extend(crate::ir::visit::statement_registers(stmt).0),
            Node::If { then, els, .. } => {
                writes_in(then, out);
                writes_in(els, out);
            }
            Node::DoWhile { body, .. } | Node::Forever { body } => writes_in(body, out),
            Node::While { prefix, body, .. } => {
                writes_in(prefix, out);
                writes_in(body, out);
            }
            Node::Switch { arms, default, .. } => {
                for (_, body) in arms {
                    writes_in(body, out);
                }
                if let Some(body) = default {
                    writes_in(body, out);
                }
            }
            Node::Label(_) | Node::Break | Node::Continue => {}
        }
    }
}

/// Drops a jump to the label that comes next anyway: at the end of a
/// sequence, or of an `if` branch, that the label follows.
pub(crate) fn drop_jumps_to_next(nodes: &mut Vec<Node>, follow: Option<u64>) {
    let mut index = 0;
    while index < nodes.len() {
        let next = match nodes.get(index + 1) {
            Some(Node::Label(label)) => Some(*label),
            Some(_) => None,
            None => follow,
        };
        match &mut nodes[index] {
            Node::Stmt(Stmt::Br {
                target: Some(target),
            }) if Some(*target) == next => {
                nodes.remove(index);
                continue;
            }
            Node::If { then, els, .. } => {
                drop_jumps_to_next(then, next);
                drop_jumps_to_next(els, next);
            }
            Node::DoWhile { body, .. } | Node::Forever { body } => drop_jumps_to_next(body, None),
            Node::While { prefix, body, .. } => {
                drop_jumps_to_next(prefix, None);
                drop_jumps_to_next(body, None);
            }
            Node::Switch { arms, default, .. } => {
                for (_, body) in arms {
                    drop_jumps_to_next(body, None);
                }
                if let Some(body) = default {
                    drop_jumps_to_next(body, None);
                }
            }
            _ => {}
        }
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::fold_exit_branches;
    use crate::ir::{Cond, Expr, Stmt};
    use crate::render::structure::Node;

    fn branch(target: u64) -> Node {
        Node::Stmt(Stmt::Brif {
            cond: Cond::Eq,
            lhs: Expr::reg(0, 64),
            rhs: Expr::constant(0),
            target,
        })
    }

    #[test]
    fn an_exit_from_a_nested_loop_stays_a_branch() {
        // A `break` inside the inner loop or the switch would leave that
        // instead of the loop whose exit is 0x40.
        let mut nodes = vec![
            branch(0x40),
            Node::Forever {
                body: vec![branch(0x40)],
            },
            Node::Switch {
                index: Expr::reg(1, 64),
                arms: vec![(vec![0], vec![branch(0x40)])],
                default: None,
            },
        ];
        fold_exit_branches(&mut nodes, Some(0x40));
        assert!(
            matches!(&nodes[0], Node::If { then, .. } if matches!(then.as_slice(), [Node::Break]))
        );
        assert!(
            matches!(&nodes[1], Node::Forever { body } if matches!(body.as_slice(), [Node::Stmt(Stmt::Brif { .. })]))
        );
        assert!(
            matches!(&nodes[2], Node::Switch { arms, .. } if matches!(arms[0].1.as_slice(), [Node::Stmt(Stmt::Brif { .. })]))
        );
    }
}

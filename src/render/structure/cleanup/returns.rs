use super::{children, children_mut, terminates, writes_in};
use crate::ir::Stmt;
use crate::render::structure::Node;
use std::collections::HashMap;

/// The most statements a copied return tail runs before it returns.
const TAIL_STATEMENTS: usize = 6;

/// The most lines the copies of one return tail may add in all.
const TAIL_LINES: usize = 8;

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

/// Replaces each jump to a label that only runs a few statements before
/// returning, or before trapping after a call that does not return, with
/// those statements, while that adds no more than a few lines in all. A
/// tail that reads as one line, as `return f(x);` does, is copied to every
/// jump: the copy takes no more room than the goto.
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
                            stmt @ (Stmt::Assign { .. }
                            | Stmt::Store { .. }
                            | Stmt::Call { .. }
                            | Stmt::Unsupported { .. }),
                        ) if tail.len() < TAIL_STATEMENTS => tail.push(Node::Stmt(stmt.clone())),
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
    tails.retain(|label, tail| {
        let added = added_lines(tail);
        added == 0 || added * counts.get(label).copied().unwrap_or(0) <= TAIL_LINES
    });
    if !tails.is_empty() {
        replace(nodes, &tails);
    }
}

/// How many more lines a copy of `tail` takes than the goto it replaces:
/// one per statement before the last, but a return of what a call just
/// returned prints with the call.
fn added_lines(tail: &[Node]) -> usize {
    let fused = matches!(
        tail,
        [
            ..,
            Node::Stmt(Stmt::Call { .. }),
            Node::Stmt(Stmt::Ret { .. })
        ]
    );
    tail.len() - 1 - usize::from(fused)
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

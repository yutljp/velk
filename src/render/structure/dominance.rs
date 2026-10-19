//! Structuring by the dominator tree. Every block is emitted once, inside the
//! block that dominates it: a block a single forward edge reaches is inlined
//! where the branch is, and one several forward edges reach (a join) follows
//! the code of the block dominating it. A back edge to a block that dominates
//! its source makes that block a loop header; the blocks the loop leaves to
//! follow the loop. Every branch first becomes a jump, which then reads as
//! falling through, `break` or `continue` where the shape allows, and as a
//! goto only where the graph has none.

use std::collections::HashMap;

use super::Node;
use crate::ir::{Block, FunctionIr, Stmt};

/// Deeper dominator trees fall back to the other structurer.
const MAX_DEPTH: usize = 1500;

struct Graph<'a> {
    blocks: &'a [Block],
    successors: Vec<Vec<usize>>,
    /// Reverse-postorder number of each block; `usize::MAX` if unreachable.
    order: Vec<usize>,
    idom: Vec<Option<usize>>,
    /// Dominator-tree children, in reverse postorder.
    children: Vec<Vec<usize>>,
    /// Reached by more than one forward edge.
    merge: Vec<bool>,
    /// The blocks of the loop each header heads, by header.
    loops: HashMap<usize, Vec<bool>>,
    /// Where each loop's own tests, at its header and latches, leave it to.
    tests: HashMap<usize, Vec<usize>>,
    index: HashMap<u64, usize>,
}

fn successors(blocks: &[Block], index: &HashMap<u64, usize>, block: usize) -> Vec<usize> {
    let fallthrough = (block + 1 < blocks.len()).then_some(block + 1);
    let find = |address: &u64| index.get(address).copied();
    let mut out = Vec::new();
    match blocks[block].stmts.last() {
        Some(Stmt::Br {
            target: Some(target),
        }) => out.extend(find(target)),
        Some(Stmt::Brif { target, .. }) | Some(Stmt::BrifFlags { target, .. }) => {
            out.extend(find(target));
            out.extend(fallthrough);
        }
        Some(Stmt::Switch { cases, default, .. }) => {
            out.extend(cases.iter().filter_map(|(_, target)| find(target)));
            out.extend(default.as_ref().and_then(find));
        }
        Some(
            Stmt::Ret { .. } | Stmt::BrIndirect { .. } | Stmt::Trap | Stmt::Br { target: None },
        ) => {}
        _ => out.extend(fallthrough),
    }
    out
}

impl<'a> Graph<'a> {
    fn new(ir: &'a FunctionIr) -> Graph<'a> {
        let blocks = &ir.blocks;
        let count = blocks.len();
        let index: HashMap<u64, usize> = blocks
            .iter()
            .enumerate()
            .map(|(position, block)| (block.start, position))
            .collect();
        let successors: Vec<Vec<usize>> = (0..count)
            .map(|block| successors(blocks, &index, block))
            .collect();
        // Reverse postorder by an explicit stack.
        let mut order = vec![usize::MAX; count];
        let mut postorder = Vec::new();
        let mut visited = vec![false; count];
        let mut stack = vec![(0usize, 0usize)];
        visited[0] = true;
        while let Some((block, next)) = stack.last_mut() {
            if let Some(successor) = successors[*block].get(*next).copied() {
                *next += 1;
                if !visited[successor] {
                    visited[successor] = true;
                    stack.push((successor, 0));
                }
            } else {
                postorder.push(*block);
                stack.pop();
            }
        }
        for (number, block) in postorder.iter().rev().enumerate() {
            order[*block] = number;
        }
        let idom = crate::ssa::dom::dominators(&successors).idom;
        let mut children = vec![Vec::new(); count];
        for (block, parent) in idom.iter().enumerate() {
            if let Some(parent) = parent {
                children[*parent].push(block);
            }
        }
        for list in &mut children {
            list.sort_by_key(|block| order[*block]);
        }
        let dominates = |upper: usize, mut lower: usize| loop {
            if upper == lower {
                return true;
            }
            match idom[lower] {
                Some(up) => lower = up,
                None => return false,
            }
        };
        let mut forward = vec![0usize; count];
        let mut latches: HashMap<usize, Vec<usize>> = HashMap::new();
        for (block, next) in successors.iter().enumerate() {
            if order[block] == usize::MAX {
                continue;
            }
            for successor in next {
                if order[*successor] > order[block] {
                    forward[*successor] += 1;
                } else if dominates(*successor, block) {
                    latches.entry(*successor).or_default().push(block);
                }
            }
        }
        let mut merge: Vec<bool> = forward.iter().map(|count| *count > 1).collect();
        // A branch on flags keeps its goto, so its target needs a place of its own.
        for block in blocks {
            if let Some(Stmt::BrifFlags { target, .. }) = block.stmts.last()
                && let Some(target) = index.get(target)
            {
                merge[*target] = true;
            }
        }
        // Each loop's blocks: those reaching a latch without passing the header.
        let mut predecessors = vec![Vec::new(); count];
        for (block, next) in successors.iter().enumerate() {
            for successor in next {
                predecessors[*successor].push(block);
            }
        }
        let mut loops = HashMap::new();
        let mut tests: HashMap<usize, Vec<usize>> = HashMap::new();
        for (header, sources) in &latches {
            let mut body = vec![false; count];
            body[*header] = true;
            let mut work: Vec<usize> = sources.clone();
            while let Some(block) = work.pop() {
                if std::mem::replace(&mut body[block], true) {
                    continue;
                }
                work.extend(predecessors[block].iter().copied());
            }
            let exits: Vec<usize> = sources
                .iter()
                .chain(std::iter::once(header))
                .flat_map(|test| successors[*test].iter().copied())
                .filter(|exit| !body[*exit])
                .collect();
            tests.insert(*header, exits);
            loops.insert(*header, body);
        }
        Graph {
            blocks,
            successors,
            order,
            idom,
            children,
            merge,
            loops,
            tests,
            index,
        }
    }

    fn in_loop(&self, header: usize, block: usize) -> bool {
        self.loops.get(&header).is_some_and(|body| body[block])
    }

    /// The loop headers containing `block`, innermost first.
    fn enclosing(&self, block: usize) -> Vec<usize> {
        let mut headers: Vec<usize> = self
            .loops
            .iter()
            .filter(|(_, body)| body[block])
            .map(|(header, _)| *header)
            .collect();
        headers.sort_by_key(|header| self.loops[header].iter().filter(|inside| **inside).count());
        headers
    }

    /// Where a child the code of `parent` reaches goes: `None` inside
    /// `parent`'s own code, or the header of the outermost loop containing
    /// `parent` but not the child, which the child then follows.
    fn hoisted(&self, parent: usize, child: usize) -> Option<usize> {
        self.enclosing(parent)
            .into_iter()
            .rfind(|header| !self.in_loop(*header, child))
    }

    /// The code of the subtree `block` heads, starting with its label.
    fn tree(&self, block: usize, depth: usize) -> Option<Vec<Node>> {
        if depth > MAX_DEPTH {
            return None;
        }
        let start = self.blocks[block].start;
        let header = self.loops.contains_key(&block);
        // Children the branches inline stay out of these lists.
        let mut inside = Vec::new();
        let mut after = Vec::new();
        for child in &self.children[block] {
            match self.hoisted(block, *child) {
                // Leaving a loop this block heads: the child follows the loop.
                Some(outer) if outer == block => after.push(*child),
                // Leaving an enclosing loop: that loop's header places it.
                Some(_) => {}
                None if header && !self.in_loop(block, *child) => after.push(*child),
                // A child no branch of this block inlines needs a place of
                // its own: a join, or one entered through an irreducible edge.
                None if !self.successors[block].contains(child)
                    || !self.inlinable(block, *child) =>
                {
                    inside.push(*child)
                }
                None => {}
            }
        }
        let mut out = vec![Node::Label(start)];
        let mut code = self.code(block, depth)?;
        for child in inside {
            code.extend(self.tree(child, depth + 1)?);
        }
        if header {
            // Falling off the end of the body leaves the loop.
            code.push(Node::Break);
            out.push(Node::Forever { body: code });
        } else {
            out.extend(code);
        }
        for child in after {
            out.extend(self.tree(child, depth + 1)?);
        }
        // Blocks deeper in the tree that leave this loop follow it too.
        if header {
            let mut leaving: Vec<usize> = (0..self.blocks.len())
                .filter(|other| {
                    let Some(parent) = self.idom[*other] else {
                        return false;
                    };
                    parent != block && self.hoisted(parent, *other) == Some(block)
                })
                .collect();
            leaving.sort_by_key(|other| self.order[*other]);
            for other in leaving {
                out.extend(self.tree(other, depth + 1)?);
            }
        }
        Some(out)
    }

    /// The block's statements, its branches resolved into the code they reach.
    fn code(&self, block: usize, depth: usize) -> Option<Vec<Node>> {
        let stmts = &self.blocks[block].stmts;
        let (last, rest) = match stmts.split_last() {
            Some((last, rest)) => (Some(last), rest),
            None => (None, &[][..]),
        };
        let mut out: Vec<Node> = rest.iter().cloned().map(Node::Stmt).collect();
        let fallthrough = (block + 1 < self.blocks.len()).then_some(block + 1);
        match last {
            Some(Stmt::Brif {
                cond,
                lhs,
                rhs,
                target,
            }) => {
                let then = self.branch(block, self.index.get(target).copied(), *target, depth)?;
                let els = match fallthrough {
                    Some(next) => self.branch(block, Some(next), self.blocks[next].start, depth)?,
                    None => Vec::new(),
                };
                out.push(Node::If {
                    cond: *cond,
                    lhs: lhs.clone(),
                    rhs: rhs.clone(),
                    then,
                    els,
                });
            }
            Some(Stmt::Br {
                target: Some(target),
            }) => {
                out.extend(self.branch(block, self.index.get(target).copied(), *target, depth)?)
            }
            Some(Stmt::Switch {
                index,
                cases,
                default,
            }) => {
                // One arm per target, with every value that reaches it.
                let mut arms: Vec<(Vec<i64>, u64)> = Vec::new();
                for (value, target) in cases {
                    if Some(*target) == *default {
                        continue;
                    }
                    match arms.iter_mut().find(|(_, existing)| existing == target) {
                        Some((values, _)) => values.push(*value),
                        None => arms.push((vec![*value], *target)),
                    }
                }
                let mut nodes = Vec::new();
                for (values, target) in arms {
                    let mut body =
                        self.branch(block, self.index.get(&target).copied(), target, depth)?;
                    // A case never falls into the next.
                    body.push(Node::Break);
                    nodes.push((values, body));
                }
                let default = match default {
                    Some(target) => {
                        let mut body =
                            self.branch(block, self.index.get(target).copied(), *target, depth)?;
                        body.push(Node::Break);
                        Some(body)
                    }
                    None => None,
                };
                out.push(Node::Switch {
                    index: index.clone(),
                    arms: nodes,
                    default,
                });
            }
            Some(
                stmt @ (Stmt::Ret { .. }
                | Stmt::Trap
                | Stmt::BrIndirect { .. }
                | Stmt::Br { target: None }),
            ) => out.push(Node::Stmt(stmt.clone())),
            Some(stmt @ Stmt::BrifFlags { .. }) => {
                // Flags the lifter could not tie to a compare keep their jump.
                out.push(Node::Stmt(stmt.clone()));
                if let Some(next) = fallthrough {
                    out.extend(self.branch(block, Some(next), self.blocks[next].start, depth)?);
                }
            }
            other => {
                out.extend(other.cloned().map(Node::Stmt));
                if let Some(next) = fallthrough {
                    out.extend(self.branch(block, Some(next), self.blocks[next].start, depth)?);
                }
            }
        }
        Some(out)
    }

    /// Whether a branch from `from` to `target` stays in the same loops, or
    /// leaves them other than where their tests do, so the target's code can
    /// sit at the branch without splitting a loop's shape.
    fn leaves_aside(&self, from: usize, target: usize) -> bool {
        self.enclosing(from)
            .into_iter()
            .filter(|header| !self.in_loop(*header, target))
            .all(|header| !self.tests[&header].contains(&target))
    }

    /// The block a chain of blocks that only jump on ends at.
    fn through_jumps(&self, mut block: usize) -> Option<usize> {
        for _ in 0..8 {
            match self.blocks[block].stmts.as_slice() {
                [
                    Stmt::Br {
                        target: Some(target),
                    },
                ] => block = *self.index.get(target)?,
                _ => return Some(block),
            }
        }
        None
    }

    /// A block short enough to copy that only returns.
    fn returns_only(&self, block: usize) -> bool {
        let stmts = &self.blocks[block].stmts;
        stmts.len() <= 4
            && matches!(stmts.last(), Some(Stmt::Ret { .. }))
            && stmts[..stmts.len() - 1]
                .iter()
                .all(|stmt| matches!(stmt, Stmt::Assign { .. }))
    }

    /// Whether a branch from `from` brings in `target`'s code: it dominates
    /// the target, which no other forward edge enters, in the same loops.
    fn inlinable(&self, from: usize, target: usize) -> bool {
        self.idom[target] == Some(from)
            && !self.merge[target]
            && self.order[target] > self.order[from]
            && self.hoisted(from, target).is_none()
            && !(self.loops.contains_key(&from) && !self.in_loop(from, target))
    }

    /// A branch from `from` to `target`: the target's code, when this branch
    /// alone enters it and it stays in the same loops, else a jump.
    fn branch(
        &self,
        from: usize,
        target: Option<usize>,
        address: u64,
        depth: usize,
    ) -> Option<Vec<Node>> {
        let jump = vec![Node::Stmt(Stmt::Br {
            target: Some(address),
        })];
        let Some(target) = target else {
            return Some(jump);
        };
        if self.inlinable(from, target) {
            self.tree(target, depth + 1)
        } else if let Some(end) = self.through_jumps(target)
            && self.returns_only(end)
            && self.order[target] > self.order[from]
            && self.leaves_aside(from, target)
        {
            // A shared return, as compilers merge them, reads in place.
            self.code(end, depth + 1)
        } else {
            Some(jump)
        }
    }
}

/// What falling off the end of a sequence reaches.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Next {
    Label(u64),
    /// The end of a loop body: the header again.
    Repeat(u64),
    Unknown,
}

/// The constructs a `break` or `continue` may leave.
#[derive(Clone, Copy)]
enum Enclosing {
    Loop { header: u64, follow: Next },
    Switch { follow: Next },
}

/// Rewrites each jump as falling through, `break`, `continue` or a goto.
fn resolve(nodes: &mut Vec<Node>, next: Next, enclosing: &mut Vec<Enclosing>) {
    let mut position = 0;
    while position < nodes.len() {
        // What runs once this node completes.
        let after = match nodes.get(position + 1) {
            Some(Node::Label(label)) => Next::Label(*label),
            Some(_) => Next::Unknown,
            None => next,
        };
        let header = match position.checked_sub(1).map(|before| &nodes[before]) {
            Some(Node::Label(label)) => Some(*label),
            _ => None,
        };
        match &mut nodes[position] {
            Node::Stmt(Stmt::Br {
                target: Some(target),
            }) => match jump(*target, after, enclosing) {
                Some(node) => nodes[position] = node,
                None => {
                    nodes.remove(position);
                    continue;
                }
            },
            Node::If { then, els, .. } => {
                resolve(then, after, enclosing);
                resolve(els, after, enclosing);
            }
            Node::Forever { body } => {
                let header = header.unwrap_or(u64::MAX);
                enclosing.push(Enclosing::Loop {
                    header,
                    follow: after,
                });
                resolve(body, Next::Repeat(header), enclosing);
                enclosing.pop();
            }
            Node::Switch { arms, default, .. } => {
                enclosing.push(Enclosing::Switch { follow: after });
                for (_, body) in arms.iter_mut() {
                    resolve(body, Next::Unknown, enclosing);
                }
                if let Some(body) = default {
                    resolve(body, Next::Unknown, enclosing);
                }
                enclosing.pop();
            }
            _ => {}
        }
        position += 1;
    }
}

/// A jump to `target` given what the code reaches next; None when falling
/// through already gets there.
fn jump(target: u64, after: Next, enclosing: &[Enclosing]) -> Option<Node> {
    if after == Next::Label(target) || after == Next::Repeat(target) {
        return None;
    }
    match enclosing.last() {
        Some(Enclosing::Loop { header, .. }) if *header == target => Some(Node::Continue),
        Some(Enclosing::Loop { follow, .. }) | Some(Enclosing::Switch { follow })
            if *follow == Next::Label(target) =>
        {
            Some(Node::Break)
        }
        _ => Some(Node::Stmt(Stmt::Br {
            target: Some(target),
        })),
    }
}

/// Whether control never leaves the end of the sequence.
fn ends(nodes: &[Node]) -> bool {
    match nodes.last() {
        Some(Node::Stmt(
            Stmt::Ret { .. } | Stmt::Br { .. } | Stmt::BrIndirect { .. } | Stmt::Trap,
        ))
        | Some(Node::Break)
        | Some(Node::Continue) => true,
        Some(Node::If { then, els, .. }) => ends(then) && ends(els),
        Some(Node::Forever { body }) => !mentions_break(body),
        _ => false,
    }
}

/// Whether a `break` or `continue` in the sequence binds to the loop the
/// sequence is the body of, rather than to a loop or switch inside it.
fn binds(nodes: &[Node], kind: fn(&Node) -> bool, in_switch: bool) -> bool {
    nodes.iter().any(|node| match node {
        Node::Break if in_switch => false,
        Node::Break | Node::Continue => kind(node),
        Node::If { then, els, .. } => binds(then, kind, in_switch) || binds(els, kind, in_switch),
        // `continue` inside a switch still binds to the loop.
        Node::Switch { arms, default, .. } => arms
            .iter()
            .map(|(_, body)| body)
            .chain(default.iter())
            .any(|body| binds(body, kind, true)),
        _ => false,
    })
}

fn mentions_break(nodes: &[Node]) -> bool {
    binds(nodes, |node| matches!(node, Node::Break), false)
}

fn mentions_continue(nodes: &[Node]) -> bool {
    binds(nodes, |node| matches!(node, Node::Continue), false)
}

/// Drops what follows code that never falls through, up to the next label.
fn prune_dead(nodes: &mut Vec<Node>) {
    let mut kept = Vec::with_capacity(nodes.len());
    let mut dead = false;
    for node in nodes.drain(..) {
        if matches!(node, Node::Label(_)) {
            dead = false;
        }
        if dead {
            continue;
        }
        dead = ends(std::slice::from_ref(&node));
        kept.push(node);
    }
    *nodes = kept;
}

/// `if (c) { leave } else { rest }` as `if (c) leave; rest`, and the same
/// with the sides swapped, so the code that goes on stays at the top level.
fn flatten_exits(nodes: &mut Vec<Node>) {
    let mut flat = Vec::with_capacity(nodes.len());
    for node in nodes.drain(..) {
        match node {
            Node::If {
                cond,
                lhs,
                rhs,
                then,
                els,
            } if !then.is_empty() && !els.is_empty() && (ends(&then) || ends(&els)) => {
                let (cond, leave, rest) = if ends(&then) {
                    (cond, then, els)
                } else {
                    (cond.invert(), els, then)
                };
                flat.push(Node::If {
                    cond,
                    lhs,
                    rhs,
                    then: leave,
                    els: Vec::new(),
                });
                flat.extend(rest);
            }
            other => flat.push(other),
        }
    }
    // `if (c) { long; leave } short; leave` reads better as
    // `if (!c) { short; leave } long; leave`.
    for position in 0..flat.len() {
        let Node::If { then, els, .. } = &flat[position] else {
            continue;
        };
        let rest = &flat[position + 1..];
        if !els.is_empty()
            || !ends(then)
            || !ends(rest)
            || rest.iter().any(|node| matches!(node, Node::Label(_)))
            || size(rest) >= size(then)
        {
            continue;
        }
        let rest: Vec<Node> = flat.drain(position + 1..).collect();
        let Node::If {
            cond, then, els, ..
        } = &mut flat[position]
        else {
            continue;
        };
        *cond = cond.invert();
        let long = std::mem::replace(then, rest);
        els.clear();
        flat.extend(long);
        break;
    }
    *nodes = flat;
}

/// How many nodes the sequence holds, counting nested ones.
fn size(nodes: &[Node]) -> usize {
    nodes
        .iter()
        .map(|node| {
            1 + match node {
                Node::If { then, els, .. } => size(then) + size(els),
                Node::Forever { body } | Node::DoWhile { body, .. } => size(body),
                Node::While { prefix, body, .. } => size(prefix) + size(body),
                Node::Switch { arms, default, .. } => {
                    arms.iter().map(|(_, body)| size(body)).sum::<usize>()
                        + default.as_ref().map_or(0, |body| size(body))
                }
                _ => 0,
            }
        })
        .sum()
}

/// Turns `for (;;)` loops into `while` and `do while` where their tests sit
/// at the top or the bottom, and empty `then` branches into inverted tests.
fn shape(nodes: &mut Vec<Node>) {
    for node in nodes.iter_mut() {
        match node {
            Node::If { then, els, .. } => {
                shape(then);
                shape(els);
            }
            Node::Forever { body } => shape(body),
            Node::Switch { arms, default, .. } => {
                for (_, body) in arms.iter_mut() {
                    shape(body);
                }
                if let Some(body) = default {
                    shape(body);
                }
            }
            _ => {}
        }
    }
    prune_dead(nodes);
    flatten_exits(nodes);
    for node in nodes.iter_mut() {
        if let Node::If {
            cond, then, els, ..
        } = node
            && then.is_empty()
            && !els.is_empty()
        {
            *cond = cond.invert();
            std::mem::swap(then, els);
        }
        let Node::Forever { body } = node else {
            continue;
        };
        // Coming back to the top is what the end of the body does anyway.
        while matches!(body.last(), Some(Node::Continue)) {
            body.pop();
        }
        if let Some(shaped) = do_while(body).or_else(|| while_loop(body)) {
            *node = shaped;
        }
    }
}

/// `do { body } while (c)`: the body ends in `if (c) continue;`, and nothing
/// else in it continues, which would skip the test.
fn do_while(body: &[Node]) -> Option<Node> {
    let (prefix, test) = match body {
        [prefix @ .., test @ Node::If { els, .. }] if matches!(els.as_slice(), [Node::Break]) => {
            (prefix, test)
        }
        [prefix @ .., test @ Node::If { els, .. }, Node::Break] if els.is_empty() => (prefix, test),
        _ => return None,
    };
    let Node::If {
        cond,
        lhs,
        rhs,
        then,
        ..
    } = test
    else {
        return None;
    };
    if !matches!(then.as_slice(), [Node::Continue]) || mentions_continue(prefix) {
        return None;
    }
    Some(Node::DoWhile {
        cond: *cond,
        lhs: lhs.clone(),
        rhs: rhs.clone(),
        body: prefix.to_vec(),
    })
}

/// `while (c) { body }`: after statements that only compute, the body tests
/// once whether to leave.
fn while_loop(body: &[Node]) -> Option<Node> {
    let start = body
        .iter()
        .position(|node| !matches!(node, Node::Stmt(Stmt::Assign { .. } | Stmt::Store { .. })))?;
    let (prefix, rest) = body.split_at(start);
    let (test, rest) = rest.split_first()?;
    let Node::If {
        cond,
        lhs,
        rhs,
        then,
        els,
    } = test
    else {
        return None;
    };
    // The test leaves on one side; the other side, and what follows, loops.
    let (cond, mut stays) = if matches!(then.as_slice(), [Node::Break]) {
        let mut stays = els.clone();
        stays.extend(rest.iter().cloned());
        (cond.invert(), stays)
    } else if matches!(els.as_slice(), [Node::Break]) && rest.is_empty() {
        (*cond, then.clone())
    } else {
        return None;
    };
    while matches!(stays.last(), Some(Node::Continue)) {
        stays.pop();
    }
    Some(Node::While {
        prefix: prefix.to_vec(),
        cond,
        lhs: lhs.clone(),
        rhs: rhs.clone(),
        body: stays,
    })
}

/// The function structured by its dominator tree, or None when the tree is
/// too deep to walk or code outside it, such as an indirect jump's target,
/// would be lost.
pub(super) fn structure(ir: &FunctionIr) -> Option<Vec<Node>> {
    if ir.blocks.is_empty() {
        return Some(Vec::new());
    }
    let graph = Graph::new(ir);
    let lost = ir.blocks.iter().enumerate().any(|(index, block)| {
        graph.order[index] == usize::MAX
            && !block.stmts.iter().all(|stmt| matches!(stmt, Stmt::Trap))
    });
    if lost {
        return None;
    }
    let mut nodes = graph.tree(0, 0)?;
    resolve(&mut nodes, Next::Unknown, &mut Vec::new());
    shape(&mut nodes);
    Some(nodes)
}

#[cfg(test)]
mod tests {
    use super::structure;
    use crate::ir::{BinOp, Block, Cond, Expr, FunctionIr, RegRef, Stmt};
    use crate::loader::Isa;
    use crate::render::structure::Node;

    fn function(blocks: Vec<(u64, Vec<Stmt>)>) -> FunctionIr {
        let mut ir = FunctionIr::single_block(Isa::X86_64, Vec::new());
        ir.blocks = blocks
            .into_iter()
            .map(|(start, stmts)| Block { start, stmts })
            .collect();
        ir
    }

    fn assign(index: u16, value: Expr) -> Stmt {
        Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
        }
    }

    fn brif(target: u64) -> Stmt {
        Stmt::Brif {
            cond: Cond::Ne,
            lhs: Expr::reg(1, 64),
            rhs: Expr::reg(6, 64),
            target,
        }
    }

    fn ret() -> Stmt {
        Stmt::Ret {
            value: Expr::reg(0, 64),
        }
    }

    fn count(nodes: &[Node], matches: &dyn Fn(&Node) -> bool) -> usize {
        nodes
            .iter()
            .map(|node| {
                usize::from(matches(node))
                    + match node {
                        Node::If { then, els, .. } => count(then, matches) + count(els, matches),
                        Node::Forever { body } | Node::DoWhile { body, .. } => count(body, matches),
                        Node::While { prefix, body, .. } => {
                            count(prefix, matches) + count(body, matches)
                        }
                        Node::Switch { arms, default, .. } => {
                            arms.iter()
                                .map(|(_, body)| count(body, matches))
                                .sum::<usize>()
                                + default.as_ref().map_or(0, |body| count(body, matches))
                        }
                        _ => 0,
                    }
            })
            .sum()
    }

    fn gotos(nodes: &[Node]) -> usize {
        count(nodes, &|node| matches!(node, Node::Stmt(Stmt::Br { .. })))
    }

    #[test]
    fn a_loop_entered_at_its_test_is_a_while() {
        // rcx = 0; goto test; body: rcx += 1; test: if (rcx != rsi) goto body; return
        let ir = function(vec![
            (
                0x0,
                vec![assign(1, Expr::Const(0)), Stmt::Br { target: Some(0x20) }],
            ),
            (
                0x10,
                vec![assign(
                    1,
                    Expr::bin(BinOp::Add, Expr::reg(1, 64), Expr::Const(1)),
                )],
            ),
            (0x20, vec![brif(0x10)]),
            (0x30, vec![ret()]),
        ]);
        let nodes = structure(&ir).expect("structures");
        assert_eq!(
            count(&nodes, &|node| matches!(node, Node::While { .. })),
            1,
            "{nodes:#?}"
        );
        assert_eq!(gotos(&nodes), 0, "{nodes:#?}");
    }

    #[test]
    fn a_block_entered_past_its_dominator_keeps_its_code() {
        // A loop entered both at its body (from 0x20) and at its test (from
        // 0x40): the test's one forward edge comes from 0x40, which does not
        // dominate it, so no branch inlines it.
        let ir = function(vec![
            (0x0, vec![brif(0x40)]),
            (0x20, vec![Stmt::Br { target: Some(0x60) }]),
            (
                0x40,
                vec![assign(0, Expr::Const(2)), Stmt::Br { target: Some(0x70) }],
            ),
            (0x60, vec![assign(0, Expr::Const(1))]),
            (0x70, vec![brif(0x60)]),
            (0x80, vec![ret()]),
        ]);
        let nodes = structure(&ir).expect("structures");
        assert_eq!(
            count(&nodes, &|node| matches!(node, Node::Stmt(Stmt::Ret { .. }))),
            1,
            "the return stays:\n{nodes:#?}"
        );
    }

    #[test]
    fn a_shared_return_reads_in_place() {
        // if (..) goto out; r0 = 1; out: return r0
        let ir = function(vec![
            (0x0, vec![brif(0x20)]),
            (0x10, vec![assign(0, Expr::Const(1))]),
            (0x20, vec![ret()]),
        ]);
        let nodes = structure(&ir).expect("structures");
        assert_eq!(gotos(&nodes), 0, "{nodes:#?}");
    }
}

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

pub(super) struct Graph<'a> {
    blocks: &'a [Block],
    successors: Vec<Vec<usize>>,
    /// Reverse-postorder number of each block; `usize::MAX` if unreachable.
    order: Vec<usize>,
    /// Blocks reached without entering through a separate handler root.
    entry_reached: Vec<bool>,
    immediate_dominators: Vec<Option<usize>>,
    /// Dominator-tree children, in reverse postorder.
    children: Vec<Vec<usize>>,
    /// Reached by more than one forward edge.
    merge: Vec<bool>,
    /// The blocks of the loop each header heads, by header.
    loops: HashMap<usize, Vec<bool>>,
    /// The loop headers containing each block, innermost first.
    enclosing: Vec<Vec<usize>>,
    /// Where each loop's own tests, at its header and latches, leave it to.
    loop_test_exits: HashMap<usize, Vec<usize>>,
    index: HashMap<u64, usize>,
    /// Loop exits whose code sits where the loop leaves to them, ahead of a
    /// `break`, rather than after the loop.
    absorbed: std::collections::HashSet<usize>,
    absorb: Absorb,
    switch_cases: bool,
}

fn successors(blocks: &[Block], index: &HashMap<u64, usize>, block: usize) -> Vec<usize> {
    crate::ir::cfg::normal_successors(
        blocks[block].stmts.last(),
        (block + 1 < blocks.len()).then_some(block + 1),
        |address| index.get(&address).copied(),
        crate::ir::cfg::UnknownBranch::Stop,
    )
}

fn forest_order(successors: &[Vec<usize>]) -> (Vec<usize>, Vec<usize>) {
    let count = successors.len();
    // Reverse postorder by an explicit stack, from the entry and then
    // from each block it does not reach.
    let mut order = vec![usize::MAX; count];
    let mut postorder = Vec::new();
    let mut visited = vec![false; count];
    let mut roots = Vec::new();
    for root in 0..count {
        if visited[root] {
            continue;
        }
        roots.push(root);
        let mut stack = vec![(root, 0usize)];
        visited[root] = true;
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
    }
    let reversed_postorder = postorder.iter().rev().enumerate();
    for (number, block) in reversed_postorder {
        order[*block] = number;
    }
    (order, roots)
}

impl<'a> Graph<'a> {
    pub(super) fn new(ir: &'a FunctionIr) -> Graph<'a> {
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
        let (order, roots) = forest_order(&successors);
        let mut entry_reached = vec![false; count];
        let mut pending = vec![0];
        while let Some(block) = pending.pop() {
            if block < count && !std::mem::replace(&mut entry_reached[block], true) {
                pending.extend(successors[block].iter().copied());
            }
        }
        let immediate_dominators = forest_dominators(&successors, &roots);
        let mut children = vec![Vec::new(); count];
        for (block, parent) in immediate_dominators.iter().enumerate() {
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
            match immediate_dominators[lower] {
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
            // Several edges from one block, as switch values sharing a
            // case, enter its target once.
            let mut seen = std::collections::HashSet::new();
            for successor in next {
                if !seen.insert(*successor) {
                    continue;
                }
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
        let mut loop_test_exits: HashMap<usize, Vec<usize>> = HashMap::new();
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
            loop_test_exits.insert(*header, exits);
            loops.insert(*header, body);
        }
        let mut enclosing = vec![Vec::new(); count];
        let mut headers: Vec<(usize, usize)> = loops
            .iter()
            .map(|(header, body)| (*header, body.iter().filter(|inside| **inside).count()))
            .collect();
        headers.sort_by_key(|(_, size)| *size);
        for (header, _) in headers {
            for (block, inside) in loops[&header].iter().enumerate() {
                if *inside {
                    enclosing[block].push(header);
                }
            }
        }
        Graph {
            blocks,
            successors,
            order,
            entry_reached,
            immediate_dominators,
            children,
            merge,
            loops,
            enclosing,
            loop_test_exits,
            index,
            absorbed: std::collections::HashSet::new(),
            absorb: Absorb::Nothing,
            switch_cases: false,
        }
    }

    /// The exits of each loop with several that are entered by one branch
    /// alone and are not where the loop's own tests leave: their code can
    /// stay inside the loop, so the others follow it. One of them stays
    /// after the loop when nothing else does, the one heading the most code.
    /// With `Absorb::Every`, the exits the loop's own tests leave to stay
    /// inside too, and none need stay after it: exits that all go on to the
    /// same code then meet it right after the loop. A short return is then
    /// copied to a test of the loop too, so another exit can follow it.
    fn absorbed_exits(&self, absorb: Absorb) -> std::collections::HashSet<usize> {
        let mut absorbed = std::collections::HashSet::new();
        for header in self.loops.keys() {
            let exits: Vec<usize> = (0..self.blocks.len())
                .filter(|exit| {
                    self.immediate_dominators[*exit]
                        .is_some_and(|parent| self.hoisted(parent, *exit) == Some(*header))
                })
                .collect();
            if exits.len() < 2 {
                continue;
            }
            // A short return already reads in place at each branch to it.
            let private = |exit: &usize| {
                let parent = self.immediate_dominators[*exit].expect("an exit has a parent");
                !self.merge[*exit]
                    && (absorb == Absorb::Every || !self.loop_test_exits[header].contains(exit))
                    && self.successors[parent].contains(exit)
                    && !self
                        .through_jumps(*exit)
                        .is_some_and(|end| self.returns_only(end))
            };
            let mut candidates: Vec<usize> = exits.iter().copied().filter(private).collect();
            if candidates.len() == exits.len() && absorb == Absorb::Private {
                let largest = candidates
                    .iter()
                    .copied()
                    .max_by_key(|exit| (self.subtree_size(*exit), std::cmp::Reverse(*exit)))
                    .expect("several exits");
                candidates.retain(|exit| *exit != largest);
            }
            absorbed.extend(candidates);
        }
        absorbed
    }

    /// How many blocks the subtree `block` heads holds.
    fn subtree_size(&self, block: usize) -> usize {
        let mut count = 0;
        let mut pending = vec![block];
        while let Some(next) = pending.pop() {
            count += 1;
            pending.extend(self.children[next].iter().copied());
        }
        count
    }

    /// A block nothing reaches that only traps, as the filler between
    /// functions does.
    fn padding(&self, block: usize) -> bool {
        !self.successors.iter().any(|next| next.contains(&block))
            && self.blocks[block]
                .stmts
                .iter()
                .all(|stmt| matches!(stmt, Stmt::Trap { .. }))
    }

    fn in_loop(&self, header: usize, block: usize) -> bool {
        self.loops.get(&header).is_some_and(|body| body[block])
    }

    /// The loop headers containing `block`, innermost first.
    fn enclosing(&self, block: usize) -> &[usize] {
        &self.enclosing[block]
    }

    /// Where a child the code of `parent` reaches goes: `None` inside
    /// `parent`'s own code, or the header of the outermost loop containing
    /// `parent` but not the child, which the child then follows.
    fn hoisted(&self, parent: usize, child: usize) -> Option<usize> {
        self.enclosing(parent)
            .iter()
            .copied()
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
            if self.absorbed.contains(child) {
                continue;
            }
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
        let Some(mut code) = self.code(block, depth) else {
            return None;
        };
        for child in inside {
            code.extend(match self.tree(child, depth + 1) {
                Some(value) => value,
                None => return None,
            });
        }
        if header {
            // Falling off the end of the body leaves the loop.
            code.push(Node::Break { at: None });
            out.push(Node::Forever { body: code });
        } else {
            out.extend(code);
        }
        for child in after {
            out.extend(match self.tree(child, depth + 1) {
                Some(value) => value,
                None => return None,
            });
        }
        // Blocks deeper in the tree that leave this loop follow it too.
        if header {
            let mut leaving: Vec<usize> = (0..self.blocks.len())
                .filter(|other| {
                    let Some(parent) = self.immediate_dominators[*other] else {
                        return false;
                    };
                    parent != block
                        && !self.absorbed.contains(other)
                        && self.hoisted(parent, *other) == Some(block)
                })
                .collect();
            leaving.sort_by_key(|other| self.order[*other]);
            for other in leaving {
                out.extend(match self.tree(other, depth + 1) {
                    Some(value) => value,
                    None => return None,
                });
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
                at,
            }) => {
                let Some(then) =
                    self.branch(block, self.index.get(target).copied(), *target, depth, *at)
                else {
                    return None;
                };
                let els = match fallthrough {
                    Some(next) => {
                        match self.branch(block, Some(next), self.blocks[next].start, depth, None) {
                            Some(value) => value,
                            None => return None,
                        }
                    }
                    None => Vec::new(),
                };
                out.push(Node::If {
                    cond: *cond,
                    lhs: lhs.clone(),
                    rhs: rhs.clone(),
                    then,
                    els,
                    at: *at,
                });
            }
            Some(Stmt::Br {
                target: Some(target),
                at,
            }) => out.extend(
                match self.branch(block, self.index.get(target).copied(), *target, depth, *at) {
                    Some(value) => value,
                    None => return None,
                },
            ),
            Some(Stmt::Switch {
                index,
                cases,
                default,
                at,
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
                    let Some(mut body) =
                        self.branch(block, self.index.get(&target).copied(), target, depth, None)
                    else {
                        return None;
                    };
                    // A case never falls into the next.
                    body.push(Node::Break { at: None });
                    nodes.push((values, body));
                }
                let default = match default {
                    Some(target) => {
                        let Some(mut body) = self.branch(
                            block,
                            self.index.get(target).copied(),
                            *target,
                            depth,
                            None,
                        ) else {
                            return None;
                        };
                        body.push(Node::Break { at: None });
                        Some(body)
                    }
                    None => None,
                };
                out.push(Node::Switch {
                    index: index.clone(),
                    arms: nodes,
                    default,
                    at: *at,
                });
            }
            Some(
                stmt @ (Stmt::Ret { .. }
                | Stmt::Trap { .. }
                | Stmt::BrIndirect { .. }
                | Stmt::Br { target: None, .. }),
            ) => out.push(Node::Stmt(stmt.clone())),
            Some(stmt @ Stmt::BrifFlags { .. }) => {
                // Flags the lifter could not tie to a compare keep their jump.
                out.push(Node::Stmt(stmt.clone()));
                if let Some(next) = fallthrough {
                    out.extend(
                        match self.branch(block, Some(next), self.blocks[next].start, depth, None) {
                            Some(value) => value,
                            None => return None,
                        },
                    );
                }
            }
            other => {
                out.extend(other.cloned().map(Node::Stmt));
                if let Some(next) = fallthrough {
                    out.extend(
                        match self.branch(block, Some(next), self.blocks[next].start, depth, None) {
                            Some(value) => value,
                            None => return None,
                        },
                    );
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
            .iter()
            .copied()
            .filter(|header| !self.in_loop(*header, target))
            .all(|header| !self.loop_test_exits[&header].contains(&target))
    }

    /// The block a chain of blocks that only jump on ends at.
    fn through_jumps(&self, mut block: usize) -> Option<usize> {
        for _ in 0..8 {
            match self.blocks[block].stmts.as_slice() {
                [
                    Stmt::Br {
                        target: Some(target),
                        ..
                    },
                ] => {
                    block = *(match self.index.get(target) {
                        Some(value) => value,
                        None => return None,
                    })
                }
                _ => return Some(block),
            }
        }
        None
    }

    /// A block short enough to copy that only returns, or calls a function
    /// that never returns, as a panic does.
    fn returns_only(&self, block: usize) -> bool {
        let stmts = &self.blocks[block].stmts;
        match stmts.last() {
            Some(Stmt::Ret { .. }) => {
                stmts.len() <= 4
                    && stmts[..stmts.len() - 1]
                        .iter()
                        .all(|stmt| matches!(stmt, Stmt::Assign { .. }))
            }
            Some(Stmt::Trap { .. }) => {
                stmts.len() <= 6
                    && matches!(stmts.iter().rev().nth(1), Some(Stmt::Call { .. }))
                    && stmts[..stmts.len() - 2]
                        .iter()
                        .all(|stmt| matches!(stmt, Stmt::Assign { .. }))
            }
            _ => false,
        }
    }

    /// Whether a branch from `from` brings in `target`'s code: it dominates
    /// the target in the same loops. A switch emits each target once even
    /// when another case enters it; that edge still has its label.
    fn inlinable(&self, from: usize, target: usize) -> bool {
        self.immediate_dominators[target] == Some(from)
            && (!self.merge[target]
                || (self.switch_cases
                    && matches!(self.blocks[from].stmts.last(), Some(Stmt::Switch { .. }))))
            && self.order[target] > self.order[from]
            && (self.absorbed.contains(&target)
                || (self.hoisted(from, target).is_none()
                    && !(self.loops.contains_key(&from) && !self.in_loop(from, target))))
    }

    /// A branch from `from` to `target`: the target's code, when this branch
    /// alone enters it and it stays in the same loops, else a jump.
    fn branch(
        &self,
        from: usize,
        target: Option<usize>,
        address: u64,
        depth: usize,
        at: Option<u64>,
    ) -> Option<Vec<Node>> {
        let jump = || {
            vec![Node::Stmt(Stmt::Br {
                target: Some(address),
                at,
            })]
        };
        let Some(target) = target else {
            return Some(jump());
        };
        if self.inlinable(from, target) {
            self.tree(target, depth + 1)
        } else if let Some(end) = self.through_jumps(target)
            && self.returns_only(end)
            && self.order[target] > self.order[from]
            && (self.absorb == Absorb::Every || self.leaves_aside(from, target))
        {
            // A shared return, as compilers merge them, reads in place.
            self.code(end, depth + 1)
        } else {
            Some(jump())
        }
    }
}

/// Which exits of a loop with several keep their code inside it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Absorb {
    Nothing,
    Private,
    Every,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum RootOrder {
    Address,
    Flow,
}

/// What falling off the end of a sequence reaches: the labels that stand
/// there before any code, or where a jump there leads, and at the end of a
/// loop body its header again.
#[derive(Clone, Default)]
struct Next {
    labels: Vec<u64>,
    repeat: Option<u64>,
}

impl Next {
    fn reaches(&self, target: u64) -> bool {
        self.labels.contains(&target) || self.repeat == Some(target)
    }
}

/// What runs once the node at `position` completes, `next` being what the
/// end of the sequence reaches.
fn next_after_node(nodes: &[Node], position: usize, next: &Next) -> Next {
    let mut labels = Vec::new();
    for node in &nodes[position + 1..] {
        match node {
            Node::Label(label) => labels.push(*label),
            Node::Stmt(Stmt::Br {
                target: Some(target),
                ..
            }) => {
                labels.push(*target);
                return Next {
                    labels,
                    repeat: None,
                };
            }
            _ => {
                return Next {
                    labels,
                    repeat: None,
                };
            }
        }
    }
    labels.extend(next.labels.iter().copied());
    Next {
        labels,
        repeat: next.repeat,
    }
}

/// The constructs a `break` or `continue` may leave.
#[derive(Clone)]
enum Enclosing {
    Loop { header: u64, follow: Next },
    Switch { follow: Next },
}

/// The immediate dominator of each block under a root that precedes every
/// block in `roots`; None for the blocks only that root dominates.
fn forest_dominators(successors: &[Vec<usize>], roots: &[usize]) -> Vec<Option<usize>> {
    // The shared root comes first, and every block moves up by one.
    let shifted: Vec<Vec<usize>> = std::iter::once(roots.iter().map(|root| root + 1).collect())
        .chain(
            successors
                .iter()
                .map(|next| next.iter().map(|block| block + 1).collect()),
        )
        .collect();
    crate::ssa::dom::dominators(&shifted).idom[1..]
        .iter()
        .map(|parent| parent.and_then(|parent| parent.checked_sub(1)))
        .collect()
}

/// The blocks the entry does not reach, which start code of their own
/// (an exception handler, or the target of a jump not followed).
impl Graph<'_> {
    pub(super) fn entries(&self) -> Vec<u64> {
        (1..self.blocks.len())
            .filter(|block| self.immediate_dominators[*block].is_none() && !self.padding(*block))
            .map(|block| self.blocks[block].start)
            .collect()
    }
}

/// Rewrites each jump as falling through, `break`, `continue` or a goto.
fn resolve(nodes: &mut Vec<Node>, next: &Next, enclosing: &mut Vec<Enclosing>) {
    let mut position = 0;
    while position < nodes.len() {
        let after = next_after_node(nodes, position, next);
        let header = match position.checked_sub(1).map(|before| &nodes[before]) {
            Some(Node::Label(label)) => Some(*label),
            _ => None,
        };
        match &mut nodes[position] {
            Node::Stmt(Stmt::Br {
                target: Some(target),
                at,
            }) => match jump(*target, &after, enclosing, *at) {
                Some(node) => nodes[position] = node,
                None => {
                    nodes.remove(position);
                    continue;
                }
            },
            Node::If { then, els, .. } => {
                resolve(then, &after, enclosing);
                resolve(els, &after, enclosing);
            }
            Node::Forever { body } => {
                let header = header.unwrap_or(u64::MAX);
                enclosing.push(Enclosing::Loop {
                    header,
                    follow: after.clone(),
                });
                let repeat = Next {
                    labels: Vec::new(),
                    repeat: Some(header),
                };
                resolve(body, &repeat, enclosing);
                enclosing.pop();
                prune_dead(body);
                let leaving = (!mentions_break(body))
                    .then(|| leave_by_break(&mut [body], &after, enclosing))
                    .flatten();
                if let Some(node) = leaving {
                    nodes.insert(position + 1, node);
                }
            }
            Node::Switch { arms, default, .. } => {
                enclosing.push(Enclosing::Switch {
                    follow: after.clone(),
                });
                for (_, body) in arms.iter_mut() {
                    resolve(body, &Next::default(), enclosing);
                }
                if let Some(body) = default.as_mut() {
                    resolve(body, &Next::default(), enclosing);
                }
                enclosing.pop();
                let closed = default.is_some();
                let mut bodies: Vec<&mut Vec<Node>> = arms
                    .iter_mut()
                    .map(|(_, body)| body)
                    .chain(default.as_mut())
                    .collect();
                for body in bodies.iter_mut() {
                    prune_dead(body);
                }
                let leaving = (closed && bodies.iter().all(|body| !mentions_break(body)))
                    .then(|| leave_by_break(&mut bodies, &after, enclosing))
                    .flatten();
                if let Some(node) = leaving {
                    nodes.insert(position + 1, node);
                }
            }
            _ => {}
        }
        position += 1;
    }
}

/// For a loop or a switch control never leaves at its end, the goto its
/// `bodies` make most often becomes `break`, and that jump follows the
/// construct instead: returned as it resolves there, unless it falls
/// through. Exits a compiler sent from deep inside to one place then read
/// as one `break` each, and the jump after them often as nothing at all.
fn leave_by_break(
    bodies: &mut [&mut Vec<Node>],
    after: &Next,
    enclosing: &[Enclosing],
) -> Option<Node> {
    fn count(nodes: &[Node], counts: &mut HashMap<u64, usize>) {
        for node in nodes {
            match node {
                Node::Stmt(Stmt::Br {
                    target: Some(target),
                    ..
                }) => *counts.entry(*target).or_default() += 1,
                Node::If { then, els, .. } => {
                    count(then, counts);
                    count(els, counts);
                }
                _ => {}
            }
        }
    }
    fn replace(nodes: &mut [Node], target: u64) {
        for node in nodes {
            match node {
                Node::Stmt(Stmt::Br {
                    target: Some(jump),
                    at,
                }) if *jump == target => *node = Node::Break { at: *at },
                Node::If { then, els, .. } => {
                    replace(then, target);
                    replace(els, target);
                }
                _ => {}
            }
        }
    }
    let mut counts = HashMap::new();
    let mut inside = Vec::new();
    for body in bodies.iter() {
        count(body, &mut counts);
        labels_in(body, &mut inside);
    }
    // A jump to code inside the construct stays where it is.
    counts.retain(|target, _| !inside.contains(target));
    let Some((target, _)) = counts
        .into_iter()
        .max_by_key(|(target, count)| (*count, std::cmp::Reverse(*target)))
    else {
        return None;
    };
    for body in bodies.iter_mut() {
        replace(body, target);
    }
    jump(target, after, enclosing, None)
}

/// A jump to `target` given what the code reaches next; None when falling
/// through already gets there.
fn jump(target: u64, after: &Next, enclosing: &[Enclosing], at: Option<u64>) -> Option<Node> {
    if after.reaches(target) {
        return None;
    }
    // `continue` inside a switch still goes on with the loop around it.
    let innermost_loop = enclosing
        .iter()
        .rev()
        .find_map(|construct| match construct {
            Enclosing::Loop { header, .. } => Some(*header),
            Enclosing::Switch { .. } => None,
        });
    match enclosing.last() {
        Some(Enclosing::Loop { header, .. }) if *header == target => Some(Node::Continue { at }),
        Some(Enclosing::Loop { follow, .. }) | Some(Enclosing::Switch { follow })
            if follow.reaches(target) =>
        {
            Some(Node::Break { at })
        }
        _ if innermost_loop == Some(target) => Some(Node::Continue { at }),
        _ => Some(Node::Stmt(Stmt::Br {
            target: Some(target),
            at,
        })),
    }
}

/// The labels the sequence holds, at any depth.
fn labels_in(nodes: &[Node], found: &mut Vec<u64>) {
    for node in nodes {
        match node {
            Node::Label(label) => found.push(*label),
            Node::If { then, els, .. } => {
                labels_in(then, found);
                labels_in(els, found);
            }
            Node::Forever { body } | Node::DoWhile { body, .. } => labels_in(body, found),
            Node::While { prefix, body, .. } => {
                labels_in(prefix, found);
                labels_in(body, found);
            }
            Node::Switch { arms, default, .. } => {
                let arm_bodies = arms.iter().map(|(_, body)| body).chain(default.iter());
                for body in arm_bodies {
                    labels_in(body, found);
                }
            }
            Node::Stmt(_) | Node::Break { .. } | Node::Continue { .. } => {}
        }
    }
}

/// Whether control never leaves the end of the sequence.
fn ends(nodes: &[Node]) -> bool {
    match nodes.last() {
        Some(Node::Stmt(
            Stmt::Ret { .. } | Stmt::Br { .. } | Stmt::BrIndirect { .. } | Stmt::Trap { .. },
        ))
        | Some(Node::Break { .. })
        | Some(Node::Continue { .. }) => true,
        Some(Node::If { then, els, .. }) => ends(then) && ends(els),
        Some(Node::Forever { body }) => !mentions_break(body),
        _ => false,
    }
}

/// Whether a `break` or `continue` in the sequence binds to the loop the
/// sequence is the body of, rather than to a loop or switch inside it.
fn binds(nodes: &[Node], kind: fn(&Node) -> bool, in_switch: bool) -> bool {
    nodes.iter().any(|node| match node {
        Node::Break { .. } if in_switch => false,
        Node::Break { .. } | Node::Continue { .. } => kind(node),
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
    binds(nodes, |node| matches!(node, Node::Break { .. }), false)
}

fn mentions_continue(nodes: &[Node]) -> bool {
    binds(nodes, |node| matches!(node, Node::Continue { .. }), false)
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
                at,
                cond,
                lhs,
                rhs,
                then,
                els,
                ..
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
                    at,
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
        while matches!(body.last(), Some(Node::Continue { .. })) {
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
    // A body that leaves at its end when a test holds, and otherwise falls
    // back to its start.
    if let [
        prefix @ ..,
        Node::If {
            at,
            cond,
            lhs,
            rhs,
            then,
            els,
            ..
        },
    ] = body
        && matches!(then.as_slice(), [Node::Break { .. }])
        && els.is_empty()
        && !mentions_continue(prefix)
    {
        return Some(Node::DoWhile {
            cond: cond.invert(),
            lhs: lhs.clone(),
            rhs: rhs.clone(),
            body: prefix.to_vec(),
            at: *at,
        });
    }
    let (prefix, test) = match body {
        [prefix @ .., test @ Node::If { els, .. }]
            if matches!(els.as_slice(), [Node::Break { .. }]) =>
        {
            (prefix, test)
        }
        [prefix @ .., test @ Node::If { els, .. }, Node::Break { .. }] if els.is_empty() => {
            (prefix, test)
        }
        _ => return None,
    };
    let Node::If {
        at,
        cond,
        lhs,
        rhs,
        then,
        ..
    } = test
    else {
        return None;
    };
    if !matches!(then.as_slice(), [Node::Continue { .. }]) || mentions_continue(prefix) {
        return None;
    }
    Some(Node::DoWhile {
        cond: *cond,
        lhs: lhs.clone(),
        rhs: rhs.clone(),
        body: prefix.to_vec(),
        at: *at,
    })
}

/// `while (c) { body }`: after statements that only compute, the body tests
/// once whether to leave.
fn while_loop(body: &[Node]) -> Option<Node> {
    let Some(start) = body
        .iter()
        .position(|node| !matches!(node, Node::Stmt(Stmt::Assign { .. } | Stmt::Store { .. })))
    else {
        return None;
    };
    let (prefix, rest) = body.split_at(start);
    let Some((test, rest)) = rest.split_first() else {
        return None;
    };
    let Node::If {
        at,
        cond,
        lhs,
        rhs,
        then,
        els,
        ..
    } = test
    else {
        return None;
    };
    // The test leaves on one side; the other side, and what follows, loops.
    let (cond, mut stays) = if matches!(then.as_slice(), [Node::Break { .. }]) {
        let mut stays = els.clone();
        stays.extend(rest.iter().cloned());
        (cond.invert(), stays)
    } else if matches!(els.as_slice(), [Node::Break { .. }]) && rest.is_empty() {
        (*cond, then.clone())
    } else {
        return None;
    };
    while matches!(stays.last(), Some(Node::Continue { .. })) {
        stays.pop();
    }
    Some(Node::While {
        prefix: prefix.to_vec(),
        cond,
        lhs: lhs.clone(),
        rhs: rhs.clone(),
        body: stays,
        at: *at,
    })
}

/// The function structured by its dominator tree, or None when the tree is
/// too deep to walk.
#[cfg(test)]
pub(super) fn structure(ir: &FunctionIr) -> Option<Vec<Node>> {
    Graph::new(ir).structure(
        Absorb::Nothing,
        /* switch_cases */ false,
        RootOrder::Flow,
    )
}

impl Graph<'_> {
    pub(super) fn structure(
        &mut self,
        absorb: Absorb,
        switch_cases: bool,
        root_order: RootOrder,
    ) -> Option<Vec<Node>> {
        if self.blocks.is_empty() {
            return Some(Vec::new());
        }
        self.absorb = absorb;
        self.absorbed = if absorb == Absorb::Nothing {
            std::collections::HashSet::new()
        } else {
            self.absorbed_exits(absorb)
        };
        self.switch_cases = switch_cases;
        let Some(mut nodes) = self.tree(0, 0) else {
            return None;
        };
        // Normal joins precede handlers so the normal path can fall through
        // to its cleanup. Use reverse postorder within each group.
        let mut roots: Vec<usize> = (1..self.blocks.len())
            .filter(|block| self.immediate_dominators[*block].is_none() && !self.padding(*block))
            .collect();
        if root_order == RootOrder::Flow {
            roots.sort_by_key(|block| (!self.entry_reached[*block], self.order[*block]));
        }
        for block in roots {
            let Some(body) = self.tree(block, 0) else {
                return None;
            };
            nodes.extend(body);
        }
        resolve(&mut nodes, &Next::default(), &mut Vec::new());
        shape(&mut nodes);
        Some(nodes)
    }
}

#[cfg(test)]
mod tests {
    use super::structure;
    use crate::ir::{BinOp, Block, Cond, Expr, FunctionIr, RegRef, Stmt};
    use crate::loader::Isa;
    use crate::render::structure::Node;

    fn cleanup_joins() -> FunctionIr {
        let branch = |target| Stmt::Br {
            target: Some(target),
            at: None,
        };
        let cleanup = |value| {
            let mut statements: Vec<Stmt> = (0..8)
                .map(|offset| Stmt::Store {
                    addr: Expr::bin(BinOp::Add, Expr::reg(1, 64), Expr::Const(offset * 8)),
                    value: Expr::Const(value + offset),
                    width: 8,
                    at: None,
                })
                .collect();
            statements.push(branch(60));
            statements
        };
        function(vec![
            (0, vec![brif(40)]),
            (10, vec![branch(60)]),
            (20, vec![branch(40)]),
            (30, vec![branch(60)]),
            (40, cleanup(100)),
            (60, vec![ret()]),
        ])
    }

    #[test]
    fn normal_cleanup_precedes_handlers_and_shared_tails_follow_predecessors() {
        let ir = cleanup_joins();
        let nodes = structure(&ir).unwrap();
        let labels: Vec<u64> = nodes
            .iter()
            .filter_map(|node| match node {
                Node::Label(address) => Some(*address),
                _ => None,
            })
            .collect();
        assert_eq!(labels, [0, 40, 60, 30, 20]);
        assert_eq!(gotos(&nodes), 1, "{nodes:#?}");
    }

    #[test]
    fn cleanup_layout_preserves_each_entry_and_memory_smt() {
        use crate::ir::smt::Proofs;
        use crate::render::structure::lower;

        if !Proofs::available() {
            return;
        }
        let mut proofs = Proofs::default();
        for isa in [Isa::I386, Isa::X86_64, Isa::AArch64, Isa::Arm32] {
            let mut ir = cleanup_joins();
            ir.isa = isa;
            let nodes = structure(&ir).unwrap();
            let lowered = lower::lower(&ir, &nodes);
            for entry in [0, 20, 30, 40, 60] {
                let start = Block {
                    start: 1000,
                    stmts: vec![Stmt::Br {
                        target: Some(entry),
                        at: None,
                    }],
                };
                let mut before = ir.clone();
                before.blocks.insert(0, start.clone());
                let mut after = lowered.clone();
                after.blocks.insert(0, start);
                proofs.function(
                    format!("cleanup layout {isa:?} entry {entry}"),
                    &before,
                    &after,
                );
            }
        }
        proofs.check();
    }

    #[test]
    fn structure_variants_reset_options_when_reusing_the_graph() {
        let ir = function(vec![
            (0, vec![brif(40)]),
            (
                8,
                vec![Stmt::Switch {
                    index: Expr::reg(0, 64),
                    cases: vec![(0, 16), (1, 24)],
                    default: Some(32),
                    at: None,
                }],
            ),
            (
                16,
                vec![
                    assign(0, Expr::Const(1)),
                    Stmt::Br {
                        target: Some(0),
                        at: None,
                    },
                ],
            ),
            (
                24,
                vec![
                    assign(0, Expr::Const(2)),
                    Stmt::Br {
                        target: Some(48),
                        at: None,
                    },
                ],
            ),
            (32, vec![ret()]),
            (
                40,
                vec![
                    assign(0, Expr::Const(3)),
                    Stmt::Br {
                        target: Some(48),
                        at: None,
                    },
                ],
            ),
            (48, vec![ret()]),
            (56, vec![Stmt::Trap { at: None }]),
            (64, vec![ret()]),
        ]);
        let mut reused = super::Graph::new(&ir);
        assert_eq!(reused.entries(), vec![64]);
        for _ in 0..2 {
            for absorb in [
                super::Absorb::Every,
                super::Absorb::Nothing,
                super::Absorb::Private,
            ] {
                for switch_cases in [true, false] {
                    for order in [super::RootOrder::Address, super::RootOrder::Flow] {
                        let expected =
                            super::Graph::new(&ir).structure(absorb, switch_cases, order);
                        let actual = reused.structure(absorb, switch_cases, order);
                        assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
                        assert_eq!(reused.entries(), vec![64]);
                    }
                }
            }
        }
    }

    #[test]
    fn enclosing_headers_keep_loop_size_and_iteration_order() {
        for targets in [[0, 0, 8, 8], [24, 0, 8, 0], [8, 16, 0, 8], [0, 8, 16, 24]] {
            let ir = function(vec![
                (0, vec![brif(targets[0])]),
                (8, vec![brif(targets[1])]),
                (16, vec![brif(targets[2])]),
                (24, vec![brif(targets[3])]),
                (32, vec![ret()]),
            ]);
            let graph = super::Graph::new(&ir);
            for block in 0..ir.blocks.len() {
                let mut expected: Vec<usize> = graph
                    .loops
                    .iter()
                    .filter(|(_, body)| body[block])
                    .map(|(header, _)| *header)
                    .collect();
                expected.sort_by_key(|header| {
                    graph.loops[header].iter().filter(|inside| **inside).count()
                });
                assert_eq!(graph.enclosing(block), expected);
            }
        }
    }

    #[test]
    fn indexed_edges_preserve_duplicates_and_stop_unknown_branches() {
        let ir = function(vec![
            (
                0,
                vec![Stmt::Switch {
                    index: Expr::reg(0, 64),
                    cases: vec![(0, 16), (1, 8), (2, 16), (3, 99)],
                    default: Some(8),
                    at: None,
                }],
            ),
            (
                8,
                vec![Stmt::Br {
                    target: None,
                    at: None,
                }],
            ),
            (16, vec![ret()]),
        ]);
        let index = ir
            .blocks
            .iter()
            .enumerate()
            .map(|(position, block)| (block.start, position))
            .collect();
        assert_eq!(super::successors(&ir.blocks, &index, 0), vec![2, 1, 2, 1]);
        assert!(super::successors(&ir.blocks, &index, 1).is_empty());
        assert_eq!(
            crate::render::structure::compare_chain::successors(&ir, 0),
            vec![2, 1, 2, 1]
        );
        assert_eq!(
            crate::render::structure::compare_chain::successors(&ir, 1),
            vec![2]
        );
    }

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
            at: None,
        }
    }

    fn brif(target: u64) -> Stmt {
        Stmt::Brif {
            cond: Cond::Ne,
            lhs: Expr::reg(1, 64),
            rhs: Expr::reg(6, 64),
            target,
            at: None,
        }
    }

    fn ret() -> Stmt {
        Stmt::Ret {
            value: Expr::reg(0, 64),
            at: None,
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
                vec![
                    assign(1, Expr::Const(0)),
                    Stmt::Br {
                        target: Some(0x20),
                        at: None,
                    },
                ],
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
            (
                0x20,
                vec![Stmt::Br {
                    target: Some(0x60),
                    at: None,
                }],
            ),
            (
                0x40,
                vec![
                    assign(0, Expr::Const(2)),
                    Stmt::Br {
                        target: Some(0x70),
                        at: None,
                    },
                ],
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

    #[test]
    fn switch_values_sharing_a_case_enter_it_once() {
        // switch (r1) { case 0, 1: r0 = 1; } return r0
        let ir = function(vec![
            (
                0x0,
                vec![Stmt::Switch {
                    index: Expr::reg(1, 64),
                    cases: vec![(0, 0x10), (1, 0x10)],
                    default: Some(0x20),
                    at: None,
                }],
            ),
            (
                0x10,
                vec![
                    assign(0, Expr::Const(1)),
                    Stmt::Br {
                        target: Some(0x20),
                        at: None,
                    },
                ],
            ),
            (0x20, vec![ret()]),
        ]);
        let nodes = structure(&ir).expect("structures");
        assert_eq!(gotos(&nodes), 0, "{nodes:#?}");
    }

    #[test]
    fn an_inner_loop_ending_its_outer_body_leaves_to_it_by_break() {
        // for (;;) { if (r1 == r6) return; for (;;) { r2 += 1;
        //   if (r2 == r6) continue outer; if (r1 != r6) return; } }
        let ir = function(vec![
            (0x0, vec![assign(1, Expr::Const(0))]),
            (
                0x10,
                vec![Stmt::Brif {
                    cond: Cond::Eq,
                    lhs: Expr::reg(1, 64),
                    rhs: Expr::reg(6, 64),
                    target: 0x60,
                    at: None,
                }],
            ),
            (
                0x20,
                vec![
                    assign(2, Expr::bin(BinOp::Add, Expr::reg(2, 64), Expr::Const(1))),
                    Stmt::Brif {
                        cond: Cond::Ne,
                        lhs: Expr::reg(2, 64),
                        rhs: Expr::reg(6, 64),
                        target: 0x40,
                        at: None,
                    },
                ],
            ),
            (
                0x30,
                vec![Stmt::Br {
                    target: Some(0x10),
                    at: None,
                }],
            ),
            (0x40, vec![brif(0x20)]),
            (0x50, vec![ret()]),
            (0x60, vec![ret()]),
        ]);
        let nodes = crate::render::structure::structure_best(&ir);
        assert_eq!(gotos(&nodes), 0, "{nodes:#?}");
    }

    #[test]
    fn a_switch_whose_arms_all_leave_its_loop_breaks_twice() {
        // for (;;) { r2 += 1; if (r2 == r6) continue;
        //   switch (r1) { case 0: r0 = 1; goto out; case 1: r0 = 2; goto out;
        //   case 2: continue; default: return; } }
        // out: a tail too long to copy.
        let tail: Vec<Stmt> = (0..8)
            .map(|offset| Stmt::Store {
                addr: Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(offset * 8)),
                value: Expr::reg(0, 64),
                width: 8,
                at: None,
            })
            .chain(std::iter::once(ret()))
            .collect();
        let ir = function(vec![
            (0x0, vec![assign(2, Expr::Const(0))]),
            (
                0x10,
                vec![
                    assign(2, Expr::bin(BinOp::Add, Expr::reg(2, 64), Expr::Const(1))),
                    Stmt::Brif {
                        cond: Cond::Eq,
                        lhs: Expr::reg(2, 64),
                        rhs: Expr::reg(6, 64),
                        target: 0x10,
                        at: None,
                    },
                ],
            ),
            (
                0x20,
                vec![Stmt::Switch {
                    index: Expr::reg(1, 64),
                    cases: vec![(0, 0x30), (1, 0x40), (2, 0x10)],
                    default: Some(0x50),
                    at: None,
                }],
            ),
            (
                0x30,
                vec![
                    assign(0, Expr::Const(1)),
                    Stmt::Br {
                        target: Some(0x60),
                        at: None,
                    },
                ],
            ),
            (
                0x40,
                vec![
                    assign(0, Expr::Const(2)),
                    Stmt::Br {
                        target: Some(0x60),
                        at: None,
                    },
                ],
            ),
            (0x50, vec![ret()]),
            (0x60, tail),
        ]);
        let nodes = crate::render::structure::structure_best(&ir);
        assert_eq!(gotos(&nodes), 0, "{nodes:#?}");
    }

    #[test]
    fn a_loop_exit_sent_past_a_test_it_decided_meets_the_others_there() {
        // r4 = 0; if (r5 != r6) do { r4 += 1; if (r7 == r6) break; } while (r1 != r4);
        // if (r4 != r1) { ...; return; } then a tail too long to copy, which
        // the loop's end jumps to straight, knowing r4 == r1.
        let tail = |count: u64| -> Vec<Stmt> {
            (0..count)
                .map(|offset| Stmt::Store {
                    addr: Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(offset * 8)),
                    value: Expr::reg(0, 64),
                    width: 8,
                    at: None,
                })
                .chain(std::iter::once(ret()))
                .collect()
        };
        let test = |cond: Cond, lhs: u16, rhs: u16, target: u64| Stmt::Brif {
            cond,
            lhs: Expr::reg(lhs, 64),
            rhs: Expr::reg(rhs, 64),
            target,
            at: None,
        };
        let ir = function(vec![
            (
                0x0,
                vec![assign(4, Expr::Const(0)), test(Cond::Eq, 5, 6, 0x50)],
            ),
            (
                0x10,
                vec![
                    assign(4, Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const(1))),
                    test(Cond::Eq, 7, 6, 0x50),
                ],
            ),
            (
                0x18,
                vec![assign(8, Expr::reg(4, 64)), test(Cond::Ne, 1, 4, 0x10)],
            ),
            (
                0x20,
                vec![Stmt::Br {
                    target: Some(0x60),
                    at: None,
                }],
            ),
            (0x50, vec![test(Cond::Eq, 4, 1, 0x60)]),
            (0x58, tail(7)),
            (0x60, tail(8)),
        ]);
        let nodes = crate::render::structure::structure_best(&ir);
        assert_eq!(gotos(&nodes), 0, "{nodes:#?}");
    }

    #[test]
    fn a_test_that_completes_another_joins_it() {
        // if (r1 != r6 && r2 != r6) r0 = 1; else { r2 = ... = r6 = 2; }
        // then a tail too long to copy.
        let stores: Vec<Stmt> = (0..8)
            .map(|offset| Stmt::Store {
                addr: Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(offset * 8)),
                value: Expr::reg(0, 64),
                width: 8,
                at: None,
            })
            .chain(std::iter::once(ret()))
            .collect();
        let fails = |lhs: u16| Stmt::Brif {
            cond: Cond::Eq,
            lhs: Expr::reg(lhs, 64),
            rhs: Expr::reg(6, 64),
            target: 0x30,
            at: None,
        };
        let ir = function(vec![
            (0x0, vec![fails(1)]),
            (0x10, vec![fails(2)]),
            (
                0x20,
                vec![
                    assign(0, Expr::Const(1)),
                    Stmt::Br {
                        target: Some(0x40),
                        at: None,
                    },
                ],
            ),
            (
                0x30,
                (2..7).map(|index| assign(index, Expr::Const(2))).collect(),
            ),
            (0x40, stores),
        ]);
        let nodes = crate::render::structure::structure_best(&ir);
        assert_eq!(gotos(&nodes), 0, "{nodes:#?}");
    }
}

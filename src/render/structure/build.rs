use std::collections::HashMap;

use crate::ir::{Cond, Expr, Stmt};
use crate::render::structure::Node;
use crate::render::structure::cleanup::fold_exit_branches;
use crate::render::structure::cleanup::fold_header;
use crate::render::structure::cleanup::fold_label_branches;
use crate::render::structure::cleanup::rewrite_loop_exits;

pub(crate) struct Structurer<'a> {
    pub(super) blocks: &'a [crate::ir::Block],
    pub(super) index: HashMap<u64, usize>,
    pub(super) targeted: std::collections::HashSet<u64>,
    /// Enables the shapes only the reordered layout produces, such as a
    /// latch that closes with an unconditional branch.
    pub(super) reordered: bool,
}

impl Structurer<'_> {
    fn target(&self, address: u64) -> Option<usize> {
        self.index.get(&address).copied()
    }

    /// A bottom-tested loop from this block to the first later block that
    /// branches back to it conditionally; nothing outside may jump inside.
    fn bottom_latch(&self, index: usize, to: usize) -> Option<(usize, Cond, Expr, Expr)> {
        let mut latch: Option<(usize, Cond, Expr, Expr)> = None;
        for position in index + 1..to {
            let block = self.blocks.get(position)?;
            match block.stmts.last() {
                Some(Stmt::Brif {
                    cond,
                    lhs,
                    rhs,
                    target,
                }) if self.target(*target) == Some(index) => {
                    latch = Some((position, *cond, lhs.clone(), rhs.clone()));
                    break;
                }
                _ => {}
            }
            if matches!(block.stmts.last(), Some(Stmt::Ret { .. })) {
                return None;
            }
        }
        let (position, cond, lhs, rhs) = latch?;
        let region = index..=position;
        for (other, block) in self.blocks.iter().enumerate() {
            if region.contains(&other) {
                continue;
            }
            if branch_targets(block)
                .any(|target| self.target(target).is_some_and(|at| region.contains(&at)))
            {
                return None;
            }
        }
        Some((position, cond, lhs, rhs))
    }

    /// The first later block that closes a loop with an unconditional branch
    /// back to this block.
    fn back_edge_latch(&self, index: usize, to: usize) -> Option<usize> {
        let header = self.blocks.get(index)?.start;
        for position in index + 1..to {
            let block = self.blocks.get(position)?;
            if let Some(Stmt::Br {
                target: Some(target),
            }) = block.stmts.last()
                && self.target(*target) == Some(index)
            {
                return Some(position);
            }
            if matches!(
                block.stmts.last(),
                Some(Stmt::Ret { .. }) | Some(Stmt::Trap)
            ) {
                return None;
            }
        }
        let _ = header;
        None
    }

    fn latch(&self, from: usize, to: usize, header: u64) -> Option<usize> {
        let mut latch = None;
        for position in from..to {
            let block = self.blocks.get(position)?;
            for stmt in &block.stmts {
                if let Stmt::Brif { target, .. } | Stmt::BrifFlags { target, .. } = stmt
                    && *target != header
                {
                    return None;
                }
            }
            match block.stmts.last() {
                Some(Stmt::Br {
                    target: Some(target),
                }) if *target == header => {
                    if latch.is_some() {
                        return None;
                    }
                    latch = Some(position);
                }
                Some(Stmt::Br {
                    target: Some(target),
                }) => {
                    if self.target(*target)? >= to {
                        return None;
                    }
                }
                Some(Stmt::Ret { .. }) => return None,
                _ => {}
            }
        }
        latch
    }

    /// The statements of a block that returns, following one branch or
    /// fallthrough into the epilogue, so a jump there can be inlined as an
    /// early return instead of a `goto`.
    fn return_block(&self, index: usize) -> Option<Vec<Stmt>> {
        let block = self.blocks.get(index)?;
        if block.stmts.is_empty() {
            return None;
        }
        if block.stmts.iter().any(|stmt| {
            matches!(
                stmt,
                Stmt::Brif { .. } | Stmt::BrifFlags { .. } | Stmt::Br { .. }
            )
        }) {
            // A single trailing branch may lead to the epilogue.
            let mut stmts: Vec<Stmt> = block.stmts.clone();
            let Some(Stmt::Br {
                target: Some(target),
            }) = stmts.pop()
            else {
                return None;
            };
            let rest = self.blocks.get(self.target(target)?)?;
            if !matches!(rest.stmts.last(), Some(Stmt::Ret { .. })) {
                return None;
            }
            if rest
                .stmts
                .iter()
                .any(|stmt| matches!(stmt, Stmt::Br { .. } | Stmt::Switch { .. }))
            {
                return None;
            }
            stmts.extend(rest.stmts.clone());
            return Some(stmts);
        }
        if matches!(block.stmts.last(), Some(Stmt::Ret { .. })) {
            return Some(block.stmts.clone());
        }
        // Falling through into the epilogue counts too.
        let next = self.blocks.get(index + 1)?;
        if !matches!(next.stmts.last(), Some(Stmt::Ret { .. })) {
            return None;
        }
        if next
            .stmts
            .iter()
            .any(|stmt| matches!(stmt, Stmt::Br { .. } | Stmt::Switch { .. }))
        {
            return None;
        }
        let mut stmts = block.stmts.clone();
        stmts.extend(next.stmts.clone());
        Some(stmts)
    }

    fn terminal_edge(&self, from: usize, limit: usize) -> Option<usize> {
        let block = self.blocks.get(from)?;
        match block.stmts.last() {
            Some(Stmt::Br {
                target: Some(target),
            }) => {
                let target = self.target(*target)?;
                (target > from && target <= limit).then_some(target)
            }
            _ => None,
        }
    }

    /// True when the blocks in `[from, to)` fall through to `to` in order.
    fn region_falls_into(&self, from: usize, to: usize) -> bool {
        if from >= to {
            return false;
        }
        for index in from..to {
            let next = if index + 1 < to {
                Some(self.blocks[index + 1].start)
            } else {
                Some(self.blocks[to].start)
            };
            match self.blocks[index].stmts.last() {
                Some(Stmt::Br {
                    target: Some(target),
                }) => {
                    if Some(*target) != next {
                        return false;
                    }
                }
                Some(
                    Stmt::Brif { .. }
                    | Stmt::BrifFlags { .. }
                    | Stmt::BrIndirect { .. }
                    | Stmt::Switch { .. }
                    | Stmt::Ret { .. }
                    | Stmt::Trap,
                ) => return false,
                _ => {}
            }
        }
        true
    }

    pub(super) fn emit(&mut self, from: usize, to: usize) -> Vec<Node> {
        let mut out = Vec::new();
        let mut index = from;

        while index < to {
            let block = &self.blocks[index];
            let Some(last) = block.stmts.last() else {
                if self.targeted.contains(&block.start) {
                    out.push(Node::Label(block.start));
                }
                index += 1;
                continue;
            };
            // A loop whose latch closes with an unconditional branch back to
            // this block: only the reordered layout produces it.
            if self.reordered
                && let Some(latch) = self.back_edge_latch(index, to)
            {
                let exit = self.blocks.get(latch + 1).map(|next| next.start);
                let mut body = self.emit(index, latch);
                // When the back edge is the header label's only jumper, the
                // loop replaces it.
                let jumpers = self
                    .blocks
                    .iter()
                    .filter(|other| branch_targets(other).any(|target| target == block.start))
                    .count();
                if jumpers == 1
                    && matches!(body.first(), Some(Node::Label(label)) if *label == block.start)
                {
                    body.remove(0);
                }
                body.extend(self.inlined(latch));
                rewrite_loop_exits(&mut body, exit, Some(block.start));
                fold_exit_branches(&mut body, exit);
                fold_label_branches(&mut body);
                out.push(Node::Forever { body });
                index = latch + 1;
                continue;
            }

            // A bottom-tested loop starts here and ends at its latch.
            if let Some((latch, cond, lhs, rhs)) = self.bottom_latch(index, to) {
                let mut body = self.plain(&block.stmts);
                body.extend(self.emit(index + 1, latch));
                // The latch's own statements run at the end of each pass.
                body.extend(self.inlined(latch));
                let exit = self.blocks.get(latch + 1).map(|next| next.start);
                rewrite_loop_exits(&mut body, exit, Some(block.start));
                out.push(Node::DoWhile {
                    cond,
                    lhs,
                    rhs,
                    body,
                });
                index = latch + 1;
                continue;
            }

            let labeled = self.targeted.contains(&block.start);
            if labeled {
                out.push(Node::Label(block.start));
            }

            match last {
                Stmt::Brif {
                    cond,
                    lhs,
                    rhs,
                    target,
                } => {
                    let destination = self.target(*target);
                    let fallthrough = index + 1;

                    if let Some(destination) = destination {
                        // do-while: conditional branch back to this block.
                        if destination == index {
                            let mut body = self.plain(&block.stmts[..block.stmts.len() - 1]);
                            let exit = self.blocks.get(index + 1).map(|block| block.start);
                            rewrite_loop_exits(&mut body, exit, Some(block.start));
                            out.push(Node::DoWhile {
                                cond: *cond,
                                lhs: lhs.clone(),
                                rhs: rhs.clone(),
                                body,
                            });
                            index += 1;
                            continue;
                        }

                        if destination > index && destination < to && fallthrough < to {
                            // while: header branch exits forward, body loops back
                            // from the block just before the exit.
                            if let Some(latch) = self.latch(fallthrough, destination, block.start)
                                && latch + 1 == destination
                            {
                                let mut body = self.emit(fallthrough, latch);
                                body.extend(self.inlined(latch));
                                let prefix = self.plain(&block.stmts[..block.stmts.len() - 1]);
                                // `Node::While` carries the continue predicate,
                                // the inverse of the header's exit test.
                                let (prefix, lhs, rhs) = fold_header(prefix, lhs, rhs, &body);
                                rewrite_loop_exits(
                                    &mut body,
                                    self.blocks.get(destination).map(|block| block.start),
                                    Some(block.start),
                                );
                                out.push(Node::While {
                                    prefix,
                                    cond: cond.invert(),
                                    lhs,
                                    rhs,
                                    body,
                                });
                                index = destination;
                                continue;
                            }

                            // if-then: the branch skips a straight-line
                            // region that falls into the target.
                            if destination > fallthrough
                                && self.region_falls_into(fallthrough, destination)
                            {
                                out.extend(self.plain(&block.stmts[..block.stmts.len() - 1]));
                                let then = self.emit(fallthrough, destination);
                                out.push(Node::If {
                                    cond: cond.invert(),
                                    lhs: lhs.clone(),
                                    rhs: rhs.clone(),
                                    then,
                                    els: Vec::new(),
                                });
                                index = destination;
                                continue;
                            }

                            // if/else: the fallthrough block jumps past the
                            // target region to the join. Only blocks that just
                            // return, inlined where they are reached, may lie
                            // between.
                            if let Some(join) = self.terminal_edge(fallthrough, to)
                                && join > destination
                                && destination > fallthrough
                                && (fallthrough + 1..destination)
                                    .all(|between| self.only_returns(between))
                            {
                                let cond = cond.invert();
                                out.extend(self.plain(&block.stmts[..block.stmts.len() - 1]));
                                let then = self.inlined(fallthrough);
                                let els = self.emit(destination, join);
                                out.push(Node::If {
                                    cond,
                                    lhs: lhs.clone(),
                                    rhs: rhs.clone(),
                                    then,
                                    els,
                                });
                                index = join;
                                continue;
                            }

                            // if/else: both arms converge on the same forward join.
                            let join_fallthrough = self.terminal_edge(fallthrough, to);
                            let join_target = self.terminal_edge(destination, to);
                            if let (Some(a), Some(b)) = (join_fallthrough, join_target)
                                && a == b
                                && a == destination + 1
                                && destination == fallthrough + 1
                            {
                                out.extend(self.plain(&block.stmts[..block.stmts.len() - 1]));
                                let then = self.emit(destination, a);
                                let els = self.emit(fallthrough, destination);
                                out.push(Node::If {
                                    cond: *cond,
                                    lhs: lhs.clone(),
                                    rhs: rhs.clone(),
                                    then,
                                    els,
                                });
                                index = a;
                                continue;
                            }

                            // A loop no other shape covered, closed by an
                            // unconditional back edge: labels inside are kept
                            // so the remaining `goto`s still resolve.
                            if let Some(latch) = self.back_edge_latch(index, to) {
                                let mut body = self.emit(index, latch);
                                body.extend(self.inlined(latch));
                                out.push(Node::Forever { body });
                                index = latch + 1;
                                continue;
                            }

                            // if/else where both arms terminate and the target is the last block.
                            if destination + 1 == to
                                && join_fallthrough.is_none()
                                && join_target.is_none()
                                && self.ends(destination - 1)
                            {
                                out.extend(self.plain(&block.stmts[..block.stmts.len() - 1]));
                                let then = self.emit(destination, to);
                                let els = self.emit(fallthrough, destination);
                                out.push(Node::If {
                                    cond: *cond,
                                    lhs: lhs.clone(),
                                    rhs: rhs.clone(),
                                    then,
                                    els,
                                });
                                index = to;
                                continue;
                            }
                        }

                        // early return: branch straight into a returning block.
                        if let Some(stmts) = self.return_block(destination)
                            && destination != index
                        {
                            out.extend(self.plain(&block.stmts[..block.stmts.len() - 1]));
                            out.push(Node::If {
                                cond: *cond,
                                lhs: lhs.clone(),
                                rhs: rhs.clone(),
                                then: self.plain(&stmts),
                                els: Vec::new(),
                            });
                            index += 1;
                            continue;
                        }
                    }

                    out.extend(self.plain(&block.stmts));
                    index += 1;
                }
                Stmt::Br {
                    target: Some(target),
                } => {
                    let destination = self.target(*target);
                    // A branch straight back to this block never exits.
                    if destination == Some(index) {
                        let body = self.plain(&block.stmts[..block.stmts.len() - 1]);
                        out.push(Node::Forever { body });
                        index += 1;
                        continue;
                    }
                    if let Some(stmts) = destination.and_then(|index| self.return_block(index)) {
                        out.extend(self.plain(&block.stmts[..block.stmts.len() - 1]));
                        out.extend(self.plain(&stmts));
                        index += 1;
                        continue;
                    }
                    if destination == Some(index + 1) {
                        out.extend(self.plain(&block.stmts[..block.stmts.len() - 1]));
                    } else {
                        out.extend(self.plain(&block.stmts));
                    }
                    index += 1;
                }
                Stmt::Switch {
                    index: value,
                    cases,
                    default,
                } => {
                    // Cases sharing a target share a body, and each body
                    // ends where the next one starts.
                    let mut arms: Vec<(Vec<i64>, usize)> = Vec::new();
                    let mut jumps: Vec<(i64, Vec<Node>)> = Vec::new();
                    for (case_value, address) in cases {
                        match self.target(*address) {
                            Some(target) if target > index && target < to => {
                                match arms.iter_mut().find(|(_, at)| *at == target) {
                                    Some((values, _)) => values.push(*case_value),
                                    None => arms.push((vec![*case_value], target)),
                                }
                            }
                            // The case body sits outside this range: inline it
                            // when it is an epilogue arm, otherwise jump.
                            _ => {
                                let body = match self
                                    .target(*address)
                                    .and_then(|at| self.return_block(at))
                                {
                                    Some(stmts) => self.plain(&stmts),
                                    None => self.plain(&[Stmt::Br {
                                        target: Some(*address),
                                    }]),
                                };
                                jumps.push((*case_value, body));
                            }
                        }
                    }
                    arms.sort_by_key(|(_, target)| *target);
                    let default_index = default.and_then(|address| self.target(address));
                    let mut bounds: Vec<usize> = arms.iter().map(|(_, target)| *target).collect();
                    if let Some(target) = default_index {
                        bounds.push(target);
                    }
                    bounds.sort_unstable();
                    if arms.is_empty() || bounds.first().copied() != Some(index + 1) {
                        out.extend(self.plain(&block.stmts));
                        index += 1;
                        continue;
                    }
                    let end_of = |start: usize| -> usize {
                        bounds
                            .iter()
                            .copied()
                            .find(|bound| *bound > start)
                            .unwrap_or(to)
                    };
                    out.extend(self.plain(&block.stmts[..block.stmts.len() - 1]));
                    // The cases print in value order, not in the order their
                    // bodies fall into each other, so a body that runs into
                    // the next one says so with a `goto`; only the last falls
                    // out of the switch.
                    let last = bounds.last().copied().unwrap_or(to);
                    let after = end_of(last).max(last);
                    let falls_into = |start: usize, structurer: &Self| {
                        let end = end_of(start);
                        (end < after && !structurer.ends(end - 1)).then_some(end)
                    };
                    for start in &bounds {
                        if let Some(next) = falls_into(*start, self) {
                            self.targeted.insert(self.blocks[next].start);
                        }
                    }
                    let body_of = |start: usize, structurer: &mut Self| {
                        let mut body = structurer.emit(start, end_of(start));
                        if let Some(next) = falls_into(start, structurer) {
                            match structurer.return_block(next) {
                                Some(stmts) => body.extend(structurer.plain(&stmts)),
                                None => body.push(Node::Stmt(Stmt::Br {
                                    target: Some(structurer.blocks[next].start),
                                })),
                            }
                        }
                        body
                    };
                    let mut rendered: Vec<(Vec<i64>, Vec<Node>)> = Vec::new();
                    for (values, target) in &arms {
                        rendered.push((values.clone(), body_of(*target, self)));
                    }
                    for (case_value, body) in jumps {
                        rendered.push((vec![case_value], body));
                    }
                    let default_body = match default {
                        Some(address) => match self.target(*address) {
                            Some(target) if target > index && target < to => {
                                Some(body_of(target, self))
                            }
                            _ => Some(
                                match self.target(*address).and_then(|at| self.return_block(at)) {
                                    Some(stmts) => self.plain(&stmts),
                                    None => self.plain(&[Stmt::Br {
                                        target: Some(*address),
                                    }]),
                                },
                            ),
                        },
                        None => None,
                    };
                    rendered.sort_by_key(|(values, _)| values.first().copied().unwrap_or(0));
                    out.push(Node::Switch {
                        index: value.clone(),
                        arms: rendered,
                        default: default_body,
                    });
                    index = end_of(last).max(last);
                }
                _ => {
                    out.extend(self.plain(&block.stmts));
                    index += 1;
                }
            }
        }

        out
    }

    /// A block that never falls through into the next one.
    fn ends(&self, index: usize) -> bool {
        matches!(
            self.blocks[index].stmts.last(),
            Some(
                Stmt::Ret { .. }
                    | Stmt::Trap
                    | Stmt::Br { .. }
                    | Stmt::BrIndirect { .. }
                    | Stmt::Switch { .. }
            )
        )
    }

    /// A block that ends in a return and branches nowhere.
    fn only_returns(&self, index: usize) -> bool {
        let stmts = &self.blocks[index].stmts;
        matches!(stmts.last(), Some(Stmt::Ret { .. }))
            && !stmts.iter().any(|stmt| {
                matches!(
                    stmt,
                    Stmt::Br { .. }
                        | Stmt::Brif { .. }
                        | Stmt::BrifFlags { .. }
                        | Stmt::Switch { .. }
                )
            })
    }

    /// A block folded into an enclosing shape, without its closing branch;
    /// its label stays when something else jumps to it.
    fn inlined(&self, index: usize) -> Vec<Node> {
        let block = &self.blocks[index];
        let mut nodes = Vec::new();
        if self.targeted.contains(&block.start) {
            nodes.push(Node::Label(block.start));
        }
        nodes.extend(self.plain(&block.stmts[..block.stmts.len().saturating_sub(1)]));
        nodes
    }

    fn plain(&self, stmts: &[Stmt]) -> Vec<Node> {
        stmts.iter().cloned().map(Node::Stmt).collect()
    }
}

/// The direct branch targets of a block's statements.
pub(super) fn branch_targets(block: &crate::ir::Block) -> impl Iterator<Item = u64> + '_ {
    block.stmts.iter().flat_map(|stmt| match stmt {
        Stmt::Br {
            target: Some(target),
        }
        | Stmt::Brif { target, .. }
        | Stmt::BrifFlags { target, .. } => vec![*target],
        Stmt::Switch { cases, default, .. } => cases
            .iter()
            .map(|(_, target)| *target)
            .chain(*default)
            .collect(),
        _ => Vec::new(),
    })
}

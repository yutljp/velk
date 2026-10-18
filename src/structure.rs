//! Lightweight control-flow structuring: if/else, do-while, and labeled fallback.

use std::collections::HashMap;

use crate::ir::{Cond, Expr, FunctionIr, Stmt};

#[derive(Debug, Clone)]
pub enum Out {
    Stmt(Stmt),
    Label(u64),
    If {
        cond: Cond,
        lhs: Expr,
        rhs: Expr,
        then: Vec<Out>,
        els: Vec<Out>,
    },
    DoWhile {
        cond: Cond,
        lhs: Expr,
        rhs: Expr,
        body: Vec<Out>,
    },
    /// A loop with no exit (`while (true)` with nothing that leaves it).
    Forever { body: Vec<Out> },
    /// Leaves the enclosing loop: a branch to its exit block.
    Break,
    /// Starts the next iteration: a branch back to the loop header.
    Continue,
    /// A dispatch with the case bodies inlined.
    Switch {
        index: Expr,
        arms: Vec<(Vec<i64>, Vec<Out>)>,
        default: Option<Vec<Out>>,
    },
    While {
        prefix: Vec<Out>,
        cond: Cond,
        lhs: Expr,
        rhs: Expr,
        body: Vec<Out>,
    },
}

struct Structurer<'a> {
    blocks: &'a [crate::ir::Block],
    index: HashMap<u64, usize>,
    targeted: std::collections::HashSet<u64>,
}

pub fn structure(ir: &FunctionIr) -> Vec<Out> {
    let index: HashMap<u64, usize> = ir
        .blocks
        .iter()
        .enumerate()
        .map(|(position, block)| (block.start, position))
        .collect();
    let mut targeted = std::collections::HashSet::new();
    for block in &ir.blocks {
        if let Some(Stmt::Brif { target, .. }) | Some(Stmt::BrifFlags { target, .. }) =
            block.stmts.last()
        {
            targeted.insert(*target);
        }
        if let Some(Stmt::Br {
            target: Some(target),
        }) = block.stmts.last()
        {
            targeted.insert(*target);
        }
        if let Some(Stmt::Switch { cases, default, .. }) = block.stmts.last() {
            for (_, target) in cases {
                targeted.insert(*target);
            }
            if let Some(target) = default {
                targeted.insert(*target);
            }
        }
    }
    let mut structurer = Structurer {
        blocks: &ir.blocks,
        index,
        targeted,
    };
    let mut nodes = structurer.emit(0, ir.blocks.len());
    let mut used = std::collections::HashSet::new();
    collect_targets(&nodes, &mut used);
    prune_labels(&mut nodes, &used);
    prune_unreachable(&mut nodes);
    flatten_early_returns(&mut nodes);
    nodes
}

fn terminates(nodes: &[Out]) -> bool {
    matches!(
        nodes.last(),
        Some(Out::Stmt(
            Stmt::Ret { .. }
                | Stmt::Br { .. }
                | Stmt::BrIndirect { .. }
                | Stmt::Switch { .. }
        ))
    )
}

/// Folds a loop header's temporary reads into the exit test, so
/// `x8 = local_0; if (x8 == 0) break;` reads as `while (local_0 != 0)`.
/// Only values that merely move a register or read memory fold, and only
/// when the body cannot observe the temporary first.
fn fold_header(
    prefix: Vec<Out>,
    lhs: &Expr,
    rhs: &Expr,
    body: &[Out],
) -> (Vec<Out>, Expr, Expr) {
    if prefix.is_empty() {
        return (prefix, lhs.clone(), rhs.clone());
    }
    let mut values: Vec<(u16, Expr)> = Vec::new();
    for node in &prefix {
        let Out::Stmt(Stmt::Assign { dest, value }) = node else {
            return (prefix, lhs.clone(), rhs.clone());
        };
        if !moves_value(value) {
            return (prefix, lhs.clone(), rhs.clone());
        }
        let mut reads = std::collections::HashSet::new();
        crate::pass::collect_reads(value, &mut reads);
        if reads.contains(&dest.index) {
            return (prefix, lhs.clone(), rhs.clone());
        }
        let value = crate::pass::substitute_values(value.clone(), &values);
        values.retain(|(register, _)| *register != dest.index);
        values.push((dest.index, value));
    }
    // The body must not read a temporary before it overwrites it.
    let mut reads = std::collections::HashSet::new();
    collect_node_reads(body, &mut reads);
    let killed: Option<u16> = body.first().and_then(|node| match node {
        Out::Stmt(Stmt::Assign { dest, value }) => {
            let mut own = std::collections::HashSet::new();
            crate::pass::collect_reads(value, &mut own);
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
    let lhs = crate::pass::substitute_values(lhs.clone(), &values);
    let rhs = crate::pass::substitute_values(rhs.clone(), &values);
    (Vec::new(), lhs, rhs)
}

/// A value a loop header only moves: a register, a memory read, or that
/// read masked to its own width.
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

fn collect_node_reads(nodes: &[Out], reads: &mut std::collections::HashSet<u16>) {
    for node in nodes {
        match node {
            Out::Stmt(stmt) => {
                reads.extend(crate::pass::statement_reads(stmt));
            }
            Out::If {
                lhs,
                rhs,
                then,
                els,
                ..
            } => {
                crate::pass::collect_reads(lhs, reads);
                crate::pass::collect_reads(rhs, reads);
                collect_node_reads(then, reads);
                collect_node_reads(els, reads);
            }
            Out::While {
                prefix,
                lhs,
                rhs,
                body,
                ..
            } => {
                collect_node_reads(prefix, reads);
                crate::pass::collect_reads(lhs, reads);
                crate::pass::collect_reads(rhs, reads);
                collect_node_reads(body, reads);
            }
            Out::DoWhile { lhs, rhs, body, .. } => {
                crate::pass::collect_reads(lhs, reads);
                crate::pass::collect_reads(rhs, reads);
                collect_node_reads(body, reads);
            }
            Out::Forever { body } => collect_node_reads(body, reads),
            Out::Switch { arms, default, .. } => {
                for (_, body) in arms {
                    collect_node_reads(body, reads);
                }
                if let Some(body) = default {
                    collect_node_reads(body, reads);
                }
            }
            Out::Break | Out::Continue | Out::Label(_) => {}
        }
    }
}

/// A branch to the loop's exit is a `break`, and a branch back to its
/// header is a `continue`. Nested loops keep their own exits, so their
/// bodies are left alone.
fn rewrite_loop_exits(nodes: &mut Vec<Out>, exit: Option<u64>, header: Option<u64>) {
    for node in nodes.iter_mut() {
        match node {
            Out::Stmt(Stmt::Br { target: Some(target) }) => {
                if Some(*target) == exit {
                    *node = Out::Break;
                } else if Some(*target) == header {
                    *node = Out::Continue;
                }
            }
            // A conditional branch out of the loop is a guarded `break`.
            Out::Stmt(Stmt::Brif {
                cond,
                lhs,
                rhs,
                target,
            }) => {
                if Some(*target) == exit {
                    *node = Out::If {
                        cond: *cond,
                        lhs: lhs.clone(),
                        rhs: rhs.clone(),
                        then: vec![Out::Break],
                        els: Vec::new(),
                    };
                } else if Some(*target) == header {
                    *node = Out::If {
                        cond: *cond,
                        lhs: lhs.clone(),
                        rhs: rhs.clone(),
                        then: vec![Out::Continue],
                        els: Vec::new(),
                    };
                }
            }
            Out::If { then, els, .. } => {
                rewrite_loop_exits(then, exit, header);
                rewrite_loop_exits(els, exit, header);
            }
            Out::Switch { arms, default, .. } => {
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

fn flatten_early_returns(nodes: &mut Vec<Out>) {
    for node in nodes.iter_mut() {
        match node {
            Out::If { then, els, .. } => {
                flatten_early_returns(then);
                flatten_early_returns(els);
            }
            Out::DoWhile { body, .. } | Out::Forever { body } => flatten_early_returns(body),
            Out::While { prefix, body, .. } => {
                flatten_early_returns(prefix);
                flatten_early_returns(body);
            }
            Out::Switch { arms, default, .. } => {
                for (_, body) in arms {
                    flatten_early_returns(body);
                }
                if let Some(body) = default {
                    flatten_early_returns(body);
                }
            }
            Out::Break | Out::Continue | Out::Label(_) | Out::Stmt(_) => {}
        }
    }

    let mut flattened = Vec::with_capacity(nodes.len());
    for node in nodes.drain(..) {
        match node {
            Out::If {
                cond,
                lhs,
                rhs,
                then,
                els,
            } if !els.is_empty() && terminates(&then) => {
                flattened.push(Out::If {
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

fn prune_unreachable(nodes: &mut Vec<Out>) {
    let mut reachable = true;
    nodes.retain(|node| match node {
        Out::Stmt(stmt) => {
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
        Out::Label(_) => {
            reachable = true;
            true
        }
        Out::Break | Out::Continue => {
            reachable = false;
            true
        }
        Out::If { .. }
        | Out::DoWhile { .. }
        | Out::Forever { .. }
        | Out::While { .. }
        | Out::Switch { .. } => {
            reachable = true;
            true
        }
    });
    for node in nodes.iter_mut() {
        match node {
            Out::If { then, els, .. } => {
                prune_unreachable(then);
                prune_unreachable(els);
            }
            Out::DoWhile { body, .. } | Out::Forever { body } => prune_unreachable(body),
            Out::Switch { arms, default, .. } => {
                for (_, body) in arms {
                    prune_unreachable(body);
                }
                if let Some(body) = default {
                    prune_unreachable(body);
                }
            }
            Out::While { prefix, body, .. } => {
                prune_unreachable(prefix);
                prune_unreachable(body);
            }
            _ => {}
        }
    }
}

fn collect_targets(nodes: &[Out], used: &mut std::collections::HashSet<u64>) {
    for node in nodes {
        match node {
            Out::Stmt(Stmt::Brif { target, .. }) | Out::Stmt(Stmt::BrifFlags { target, .. }) => {
                used.insert(*target);
            }
            Out::Stmt(Stmt::Br {
                target: Some(target),
            }) => {
                used.insert(*target);
            }
            Out::Stmt(Stmt::Switch { cases, default, .. }) => {
                for (_, target) in cases {
                    used.insert(*target);
                }
                if let Some(target) = default {
                    used.insert(*target);
                }
            }
            Out::If { then, els, .. } => {
                collect_targets(then, used);
                collect_targets(els, used);
            }
            Out::DoWhile { body, .. } | Out::Forever { body } => collect_targets(body, used),
            Out::Switch { arms, default, .. } => {
                for (_, body) in arms {
                    collect_targets(body, used);
                }
                if let Some(body) = default {
                    collect_targets(body, used);
                }
            }
            Out::While { prefix, body, .. } => {
                collect_targets(prefix, used);
                collect_targets(body, used);
            }
            _ => {}
        }
    }
}

fn prune_labels(nodes: &mut Vec<Out>, used: &std::collections::HashSet<u64>) {
    nodes.retain(|node| match node {
        Out::Label(address) => used.contains(address),
        _ => true,
    });
    for node in nodes.iter_mut() {
        match node {
            Out::If { then, els, .. } => {
                prune_labels(then, used);
                prune_labels(els, used);
            }
            Out::DoWhile { body, .. } | Out::Forever { body } => prune_labels(body, used),
            Out::Switch { arms, default, .. } => {
                for (_, body) in arms {
                    prune_labels(body, used);
                }
                if let Some(body) = default {
                    prune_labels(body, used);
                }
            }
            Out::While { prefix, body, .. } => {
                prune_labels(prefix, used);
                prune_labels(body, used);
            }
            _ => {}
        }
    }
}

impl Structurer<'_> {
    fn target(&self, address: u64) -> Option<usize> {
        self.index.get(&address).copied()
    }

    /// A bottom-tested loop: this block starts it and a later block ends it
    /// with a conditional branch back to this block. The region is exactly
    /// the blocks up to that latch, and nothing outside may jump inside.
    fn bottom_latch(&self, index: usize, to: usize) -> Option<(usize, Cond, Expr, Expr)> {
        let header = self.blocks.get(index)?.start;
        // The first block that branches back to the header closes the loop.
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
            // A block that leaves the function before the latch means this
            // is not a simple bottom-tested loop.
            if matches!(block.stmts.last(), Some(Stmt::Ret { .. })) {
                return None;
            }
        }
        let (position, cond, lhs, rhs) = latch?;
        let region_end = match self.blocks.get(position + 1) {
            Some(next) => next.start.saturating_sub(1),
            None => u64::MAX,
        };
        let region = header..=region_end;
        // Nothing outside the loop may enter it part way.
        for (other, block) in self.blocks.iter().enumerate() {
            if other >= index && other <= position {
                continue;
            }
            for stmt in &block.stmts {
                let target = match stmt {
                    Stmt::Br { target: Some(target) } => *target,
                    Stmt::Brif { target, .. } | Stmt::BrifFlags { target, .. } => *target,
                    _ => continue,
                };
                if region.contains(&target) {
                    return None;
                }
            }
        }
        Some((position, cond, lhs, rhs))
    }

    /// An unconditional back edge to this block closes a loop whose body
    /// keeps every label, so the `goto`s inside it still land as they did.
    fn back_edge_latch(&self, index: usize, to: usize) -> Option<usize> {
        let header = self.blocks.get(index)?.start;
        for position in index + 1..to {
            let block = self.blocks.get(position)?;
            if let Some(Stmt::Br {
                target: Some(target),
            }) = block.stmts.last()
            {
                if self.target(*target) == Some(index) {
                    return Some(position);
                }
            }
            if matches!(block.stmts.last(), Some(Stmt::Ret { .. }) | Some(Stmt::Trap)) {
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
                if let Stmt::Brif { target, .. } | Stmt::BrifFlags { target, .. } = stmt {
                    if *target != header {
                        return None;
                    }
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

    /// The statements of a block that returns, following one unconditional
    /// branch: a case body usually falls into the epilogue instead of
    /// repeating `return` itself, and inlining that epilogue turns the case
    /// into an early return instead of a `goto`.
    fn return_block(&self, index: usize) -> Option<Vec<Stmt>> {
        let block = self.blocks.get(index)?;
        if block.stmts.len() < 1 {
            return None;
        }
        if block
            .stmts
            .iter()
            .any(|stmt| matches!(stmt, Stmt::Brif { .. } | Stmt::BrifFlags { .. } | Stmt::Br { .. }))
        {
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
        if !matches!(block.stmts.last(), Some(Stmt::Ret { .. })) {
            return None;
        }
        Some(block.stmts.clone())
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

    fn emit(&mut self, from: usize, to: usize) -> Vec<Out> {
        let mut out = Vec::new();
        let mut index = from;

        while index < to {
            let block = &self.blocks[index];
            let Some(last) = block.stmts.last() else {
                index += 1;
                continue;
            };
            // A bottom-tested loop starts here and ends at its latch.
            if let Some((latch, cond, lhs, rhs)) = self.bottom_latch(index, to) {
                let mut body = self.plain(&block.stmts);
                body.extend(self.emit(index + 1, latch));
                // The latch's own statements run at the end of each pass.
                body.extend(
                    self.plain(&self.blocks[latch].stmts[..self.blocks[latch].stmts.len() - 1]),
                );
                let exit = self.blocks.get(latch + 1).map(|next| next.start);
                rewrite_loop_exits(&mut body, exit, Some(block.start));
                out.push(Out::DoWhile {
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
                out.push(Out::Label(block.start));
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
                            // The loop leaves through the block after it.
                            let exit = self.blocks.get(index + 1).map(|block| block.start);
                            rewrite_loop_exits(&mut body, exit, Some(block.start));
                            out.push(Out::DoWhile {
                                cond: *cond,
                                lhs: lhs.clone(),
                                rhs: rhs.clone(),
                                body,
                            });
                            index += 1;
                            continue;
                        }

                        if destination > index && destination < to && fallthrough < to {
                            // while: header branch exits forward, body loops back.
                            if let Some(latch) = self.latch(fallthrough, destination, block.start) {
                                let mut body = self.emit(fallthrough, latch);
                                body.extend(self.plain(
                                    &self.blocks[latch].stmts[..self.blocks[latch].stmts.len() - 1],
                                ));
                                let prefix = self.plain(&block.stmts[..block.stmts.len() - 1]);
                                // `Out::While` carries the *continue*
                                // predicate: the loop keeps running while
                                // the exit test is false.
                                let (prefix, lhs, rhs) =
                                    fold_header(prefix, lhs, rhs, &body);
                                let mut body = body;
                                rewrite_loop_exits(
                                    &mut body,
                                    self.blocks.get(destination).map(|block| block.start),
                                    Some(block.start),
                                );
                                out.push(Out::While {
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
                            // region that falls into its own target, which
                            // is `if (!cond) { region }` with the target
                            // following. Reordering leaves this shape at the
                            // end of a loop body, where the region is the body
                            // and the target is the latch.
                            if destination > fallthrough
                                && self.region_falls_into(fallthrough, destination)
                            {
                                out.extend(
                                    self.plain(&block.stmts[..block.stmts.len() - 1]),
                                );
                                let then = self.emit(fallthrough, destination);
                                out.push(Out::If {
                                    cond: cond.invert(),
                                    lhs: lhs.clone(),
                                    rhs: rhs.clone(),
                                    then,
                                    els: Vec::new(),
                                });
                                index = destination;
                                continue;
                            }

                            // if/else across a skipped block: the branch
                            // jumps to one arm while the fallthrough arm
                            // jumps forward to the same join, so the two
                            // arms can be written as one if/else.
                            if let Some(join) = self.terminal_edge(fallthrough, to) {
                                if join > destination && destination > fallthrough {
                                    let cond = cond.invert();
                                    // The current block's own statements run
                                    // before either arm.
                                    out.extend(self.plain(
                                        &block.stmts[..block.stmts.len() - 1],
                                    ));
                                    let then = self.plain(
                                        &self.blocks[fallthrough].stmts
                                            [..self.blocks[fallthrough].stmts.len() - 1],
                                    );
                                    let els = self.emit(destination, join);
                                    out.push(Out::If {
                                        cond,
                                        lhs: lhs.clone(),
                                        rhs: rhs.clone(),
                                        then,
                                        els,
                                    });
                                    index = join;
                                    continue;
                                }
                            }

                            // if/else: both arms converge on the same forward join.
                            let join_fallthrough = self.terminal_edge(fallthrough, to);
                            let join_target = self.terminal_edge(destination, to);
                            if let (Some(a), Some(b)) = (join_fallthrough, join_target) {
                                if a == b && a > destination {
                                    out.extend(self.plain(
                                        &block.stmts[..block.stmts.len() - 1],
                                    ));
                                    let then = self.emit(destination, a);
                                    let els = self.emit(fallthrough, a);
                                    out.push(Out::If {
                                        cond: *cond,
                                        lhs: lhs.clone(),
                                        rhs: rhs.clone(),
                                        then,
                                        els,
                                    });
                                    index = a;
                                    continue;
                                }
                            }

                            // A loop that no `while` or `do { } while`
                            // shape covered still closes through an
                            // unconditional branch back to its head:
                            // structure it and keep every label, so the
                            // jumps inside it land where they did.
                            if let Some(latch) = self.back_edge_latch(index, to) {
                                let mut body = self.emit(index, latch);
                                if self.targeted.contains(&self.blocks[latch].start) {
                                    body.push(Out::Label(self.blocks[latch].start));
                                }
                                body.extend(self.plain(
                                    &self.blocks[latch].stmts
                                        [..self.blocks[latch].stmts.len() - 1],
                                ));
                                out.push(Out::Forever { body });
                                index = latch + 1;
                                continue;
                            }

                            // if/else where both arms terminate and the target is the last block.
                            if destination + 1 == to
                                && join_fallthrough.is_none()
                                && join_target.is_none()
                            {
                                out.extend(self.plain(
                                    &block.stmts[..block.stmts.len() - 1],
                                ));
                                let then = self.emit(destination, to);
                                let els = self.emit(fallthrough, destination);
                                out.push(Out::If {
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
                        if let Some(stmts) = self.return_block(destination) {
                            if destination != index {
                                out.push(Out::If {
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
                        out.push(Out::Forever { body });
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
                    let mut jumps: Vec<(i64, u64)> = Vec::new();
                    for (case_value, address) in cases {
                        match self.target(*address) {
                            Some(target) if target > index && target < to => {
                                match arms.iter_mut().find(|(_, at)| *at == target) {
                                    Some((values, _)) => values.push(*case_value),
                                    None => arms.push((vec![*case_value], target)),
                                }
                            }
                            // The case leaves this range through a jump.
                            _ => jumps.push((*case_value, *address)),
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
                    let mut rendered: Vec<(Vec<i64>, Vec<Out>)> = arms
                        .iter()
                        .map(|(values, target)| {
                            (values.clone(), self.emit(*target, end_of(*target)))
                        })
                        .collect();
                    for (case_value, address) in jumps {
                        rendered.push((
                            vec![case_value],
                            self.plain(&[Stmt::Br {
                                target: Some(address),
                            }]),
                        ));
                    }
                    let default_body = match default {
                        Some(address) => match self.target(*address) {
                            Some(target) if target > index && target < to => {
                                Some(self.emit(target, end_of(target)))
                            }
                            _ => Some(self.plain(&[Stmt::Br {
                                target: Some(*address),
                            }])),
                        },
                        None => None,
                    };
                    // Cases read best in value order.
                    rendered.sort_by_key(|(values, _)| values.first().copied().unwrap_or(0));
                    let last = bounds.last().copied().unwrap_or(to);
                    out.push(Out::Switch {
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

    fn plain(&self, stmts: &[Stmt]) -> Vec<Out> {
        stmts.iter().cloned().map(Out::Stmt).collect()
    }
}

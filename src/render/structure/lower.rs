//! Structured code as blocks for value analysis and behavior checks.
//! Labels keep their addresses;
//! the joins and exits the structure implies take addresses of their own.

use super::Node;
use crate::ir::{Block, Cond, Expr, FunctionIr, Stmt};

#[cfg(test)]
mod tests;

/// Addresses for the blocks structure implies, far from any code.
const SYNTHETIC: u64 = 0xf000_0000_0000_0000;

struct Lowering {
    blocks: Vec<Block>,
    next: u64,
    locations: Vec<(usize, usize)>,
    used: std::collections::HashSet<u64>,
}

impl Lowering {
    fn fresh(&mut self) -> u64 {
        loop {
            self.next = self.next.checked_add(1).unwrap_or(0);
            if self.used.insert(self.next) {
                return self.next;
            }
        }
    }

    fn push(&mut self, stmt: Stmt) {
        self.blocks.last_mut().expect("a block").stmts.push(stmt);
    }

    fn note(&mut self) {
        let block = self.blocks.len() - 1;
        self.locations.push((block, self.blocks[block].stmts.len()));
    }

    /// Ends the current block, falling through to a new one at `start`.
    fn begin(&mut self, start: u64) {
        self.push(Stmt::Br {
            target: Some(start),
        });
        self.blocks.push(Block {
            start,
            stmts: Vec::new(),
        });
    }

    fn branch(&mut self, cond: Cond, lhs: &Expr, rhs: &Expr, target: u64) {
        self.note();
        self.push(Stmt::Brif {
            cond,
            lhs: lhs.clone(),
            rhs: rhs.clone(),
            target,
        });
        let next = self.fresh();
        self.blocks.push(Block {
            start: next,
            stmts: Vec::new(),
        });
    }

    /// Ends the block with `stmt`, which leaves it, and starts an unreachable one.
    fn leave(&mut self, stmt: Stmt) {
        self.push(stmt);
        let next = self.fresh();
        self.blocks.push(Block {
            start: next,
            stmts: Vec::new(),
        });
    }

    fn nodes(&mut self, nodes: &[Node], exit: Option<u64>, repeat: Option<u64>) {
        for node in nodes {
            self.node(node, exit, repeat);
        }
    }

    fn node(&mut self, node: &Node, exit: Option<u64>, repeat: Option<u64>) {
        match node {
            Node::Stmt(stmt) => {
                self.note();
                match stmt {
                    Stmt::Call { .. }
                    | Stmt::Br { .. }
                    | Stmt::Ret { .. }
                    | Stmt::Trap
                    | Stmt::BrIndirect { .. }
                    | Stmt::Switch { .. } => self.leave(stmt.clone()),
                    Stmt::Brif { .. } | Stmt::BrifFlags { .. } => {
                        self.push(stmt.clone());
                        let next = self.fresh();
                        self.blocks.push(Block {
                            start: next,
                            stmts: Vec::new(),
                        });
                    }
                    _ => self.push(stmt.clone()),
                }
            }
            Node::Label(address) => self.begin(*address),
            Node::Break => self.leave(Stmt::Br { target: exit }),
            Node::Continue => self.leave(Stmt::Br { target: repeat }),
            Node::If {
                cond,
                lhs,
                rhs,
                then,
                els,
            } => {
                let (taken, join) = (self.fresh(), self.fresh());
                self.branch(*cond, lhs, rhs, taken);
                self.nodes(els, exit, repeat);
                self.leave(Stmt::Br { target: Some(join) });
                self.begin(taken);
                self.nodes(then, exit, repeat);
                self.begin(join);
            }
            Node::Forever { body } => {
                let (header, after) = (self.fresh(), self.fresh());
                self.begin(header);
                self.nodes(body, Some(after), Some(header));
                self.leave(Stmt::Br {
                    target: Some(header),
                });
                self.begin(after);
            }
            Node::While {
                prefix,
                cond,
                lhs,
                rhs,
                body,
            } => {
                let (header, after) = (self.fresh(), self.fresh());
                self.begin(header);
                self.nodes(prefix, Some(after), Some(header));
                self.branch(cond.invert(), lhs, rhs, after);
                self.nodes(body, Some(after), Some(header));
                self.leave(Stmt::Br {
                    target: Some(header),
                });
                self.begin(after);
            }
            Node::DoWhile {
                cond,
                lhs,
                rhs,
                body,
            } => {
                let (header, test, after) = (self.fresh(), self.fresh(), self.fresh());
                self.begin(header);
                self.nodes(body, Some(after), Some(test));
                self.begin(test);
                self.branch(*cond, lhs, rhs, header);
                self.begin(after);
            }
            Node::Switch {
                index,
                arms,
                default,
            } => {
                let after = self.fresh();
                let labels: Vec<u64> = arms.iter().map(|_| self.fresh()).collect();
                let fallback = default.as_ref().map(|_| self.fresh());
                let cases = arms
                    .iter()
                    .zip(&labels)
                    .flat_map(|((values, _), label)| {
                        values.iter().map(move |value| (*value, *label))
                    })
                    .collect();
                self.note();
                self.leave(Stmt::Switch {
                    index: index.clone(),
                    cases,
                    default: Some(fallback.unwrap_or(after)),
                });
                // An arm that does not leave falls into the next one, as in C.
                for ((_, body), label) in arms.iter().zip(&labels) {
                    self.begin(*label);
                    self.nodes(body, Some(after), repeat);
                }
                if let (Some(body), Some(label)) = (default, fallback) {
                    self.begin(label);
                    self.nodes(body, Some(after), repeat);
                }
                self.begin(after);
            }
        }
    }
}

/// `ir` with its blocks replaced by the structured code `nodes`.
#[cfg(test)]
pub(crate) fn lower(ir: &FunctionIr, nodes: &[Node]) -> FunctionIr {
    lowered(ir, nodes).0
}

fn lowered(ir: &FunctionIr, nodes: &[Node]) -> (FunctionIr, Vec<(usize, usize)>) {
    // Execution starts in an empty block that falls into the code.
    let mut lowering = Lowering {
        blocks: Vec::new(),
        next: SYNTHETIC,
        locations: Vec::new(),
        used: ir.blocks.iter().map(|block| block.start).collect(),
    };
    let start = lowering.fresh();
    lowering.blocks.push(Block {
        start,
        stmts: Vec::new(),
    });
    lowering.nodes(nodes, None, None);
    lowering.push(Stmt::Trap);
    let mut lowered = ir.clone();
    lowered.blocks = lowering.blocks;
    (lowered, lowering.locations)
}

/// Splits independent values after all control-flow transformations have finished.
pub(crate) fn split_variables(ir: &FunctionIr, nodes: &mut [Node]) -> FunctionIr {
    if ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .any(|stmt| matches!(stmt, Stmt::BrIndirect { .. } | Stmt::Br { target: None }))
    {
        return ir.clone();
    }
    let (mut lowered, mut locations) = lowered(ir, nodes);
    exception_edges(ir, &mut lowered);
    drop_empty_paths(&mut lowered, &mut locations);
    let fixed: std::collections::HashSet<u16> = lowered
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .flat_map(Stmt::call_outputs)
        .map(|output| output.register)
        .collect();
    let general = match ir.isa {
        crate::loader::Isa::AArch64 => 0..31,
        crate::loader::Isa::X86_64 => 0..16,
        crate::loader::Isa::I386 => 0..8,
        crate::loader::Isa::Arm32 => 0..13,
        crate::loader::Isa::Unsupported => 0..0,
    };
    let general: Vec<u16> = general
        .filter(|register| {
            ir.declared_signature.is_none()
                && *register != crate::arch::stack_pointer(ir.isa)
                && *register != crate::arch::frame_pointer(ir.isa)
                && !fixed.contains(register)
        })
        .collect();
    let registers: Vec<u16> = lowered
        .variable_registers
        .keys()
        .copied()
        .chain(general.iter().copied())
        .collect();
    crate::ssa::split_render_variables(&mut lowered, &registers);
    let mut statements = locations
        .into_iter()
        .map(|(block, position)| lowered.blocks[block].stmts[position].clone());
    rewrite(nodes, &mut statements);
    lowered
}

fn drop_empty_paths(ir: &mut FunctionIr, locations: &mut [(usize, usize)]) {
    let mut kept = vec![false; ir.blocks.len()];
    let mut pending: Vec<usize> = locations.iter().map(|(block, _)| *block).collect();
    pending.push(0);
    for (address, _) in &ir.landing_pads {
        if let Some(block) = ir.blocks.iter().position(|block| block.start == *address) {
            pending.push(block);
        }
    }
    while let Some(block) = pending.pop() {
        if kept[block] {
            continue;
        }
        kept[block] = true;
        pending.extend(crate::ir::cfg::successors(ir, block));
    }
    let mut positions = vec![0; kept.len()];
    let mut next = 0;
    for (block, keep) in kept.iter().enumerate() {
        if *keep {
            positions[block] = next;
            next += 1;
        }
    }
    for (block, _) in locations {
        *block = positions[*block];
    }
    let mut position = 0;
    ir.blocks.retain(|_| {
        let keep = kept[position];
        position += 1;
        keep
    });
}

fn rewrite(nodes: &mut [Node], statements: &mut impl Iterator<Item = Stmt>) {
    for node in nodes {
        match node {
            Node::Stmt(stmt) => {
                let mut renamed = statements.next().expect("recorded statement");
                for (operand, value) in stmt.operands_mut().into_iter().zip(renamed.operands()) {
                    *operand = value.clone();
                }
                for (dest, renamed) in crate::ir::visit::statement_destinations_mut(stmt)
                    .into_iter()
                    .zip(crate::ir::visit::statement_destinations_mut(&mut renamed))
                {
                    dest.index = renamed.index;
                }
            }
            Node::If {
                lhs,
                rhs,
                then,
                els,
                ..
            } => {
                rewrite_test(lhs, rhs, statements);
                rewrite(els, statements);
                rewrite(then, statements);
            }
            Node::While {
                prefix,
                lhs,
                rhs,
                body,
                ..
            } => {
                rewrite(prefix, statements);
                rewrite_test(lhs, rhs, statements);
                rewrite(body, statements);
            }
            Node::DoWhile { lhs, rhs, body, .. } => {
                rewrite(body, statements);
                rewrite_test(lhs, rhs, statements);
            }
            Node::Forever { body } => rewrite(body, statements),
            Node::Switch {
                index,
                arms,
                default,
            } => {
                let Some(Stmt::Switch { index: renamed, .. }) = statements.next() else {
                    unreachable!("recorded switch");
                };
                *index = renamed;
                for (_, body) in arms {
                    rewrite(body, statements);
                }
                if let Some(body) = default {
                    rewrite(body, statements);
                }
            }
            Node::Label(_) | Node::Break | Node::Continue => {}
        }
    }
}

fn matches_exception_site(lowered: &[Stmt], original: &[String]) -> bool {
    lowered.iter().any(|stmt| {
        matches!(stmt, Stmt::Call { .. } | Stmt::Unsupported { .. })
            && original.contains(&format!("{stmt:?}"))
    })
}

fn exception_edges(original: &FunctionIr, lowered: &mut FunctionIr) {
    if original.landing_pads.is_empty() {
        return;
    }
    // Structured order is not address order. Give the analysis blocks ordered
    // addresses and translate the protected calls along with their handlers.
    let addresses: std::collections::HashMap<u64, u64> = lowered
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start, index as u64))
        .collect();
    let mut sites: std::collections::BTreeMap<u64, Vec<(u64, u64)>> =
        std::collections::BTreeMap::new();
    for (index, block) in original.blocks.iter().enumerate() {
        let edges = crate::ir::cfg::block_successors_with_exceptions(
            &original.blocks,
            index,
            &original.landing_pads,
        );
        let statements: Vec<String> = block.stmts.iter().map(|stmt| format!("{stmt:?}")).collect();
        for handler in edges.exceptional {
            let Some(pad) = addresses.get(&original.blocks[handler].start) else {
                continue;
            };
            for (position, block) in lowered.blocks.iter().enumerate() {
                if matches_exception_site(&block.stmts, &statements) {
                    sites
                        .entry(*pad)
                        .or_default()
                        .push((position as u64, position.saturating_add(1) as u64));
                }
            }
        }
    }
    for block in &mut lowered.blocks {
        block.start = addresses[&block.start];
        for stmt in &mut block.stmts {
            match stmt {
                Stmt::Br {
                    target: Some(target),
                }
                | Stmt::Brif { target, .. }
                | Stmt::BrifFlags { target, .. } => {
                    if let Some(address) = addresses.get(target) {
                        *target = *address;
                    }
                }
                Stmt::Switch { cases, default, .. } => {
                    for (_, target) in cases {
                        if let Some(address) = addresses.get(target) {
                            *target = *address;
                        }
                    }
                    if let Some(target) = default
                        && let Some(address) = addresses.get(target)
                    {
                        *target = *address;
                    }
                }
                _ => {}
            }
        }
    }
    lowered.landing_pads = sites.into_iter().collect();
}

fn rewrite_test(lhs: &mut Expr, rhs: &mut Expr, statements: &mut impl Iterator<Item = Stmt>) {
    let Some(Stmt::Brif { lhs: a, rhs: b, .. }) = statements.next() else {
        unreachable!("recorded condition");
    };
    *lhs = a;
    *rhs = b;
}

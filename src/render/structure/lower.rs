//! Structured code back as blocks, so the interpreter can check that
//! structuring kept the function's behavior. Labels keep their addresses;
//! the joins and exits the structure implies take addresses of their own.

use super::Node;
use crate::ir::{Block, Cond, Expr, FunctionIr, Stmt};

/// Addresses for the blocks structure implies, far from any code.
const SYNTHETIC: u64 = 0xf000_0000_0000_0000;

struct Lowering {
    blocks: Vec<Block>,
    next: u64,
}

impl Lowering {
    fn fresh(&mut self) -> u64 {
        self.next += 1;
        SYNTHETIC + self.next
    }

    fn push(&mut self, stmt: Stmt) {
        self.blocks.last_mut().expect("a block").stmts.push(stmt);
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
            Node::Stmt(stmt) => match stmt {
                Stmt::Br { .. }
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
            },
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
pub(crate) fn lower(ir: &FunctionIr, nodes: &[Node]) -> FunctionIr {
    // Execution starts in an empty block that falls into the code.
    let mut lowering = Lowering {
        blocks: vec![Block {
            start: SYNTHETIC,
            stmts: Vec::new(),
        }],
        next: 0,
    };
    lowering.nodes(nodes, None, None);
    lowering.push(Stmt::Trap);
    let mut lowered = ir.clone();
    lowered.blocks = lowering.blocks;
    lowered
}

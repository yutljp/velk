//! Conditional constant propagation: values are computed over the paths that
//! can run, so a branch a constant decides keeps its other side, and what
//! flows only from there, out of the joins.

use std::collections::{HashMap, HashSet};

use super::Ssa;
use crate::ir::semantics::{evaluate, holds, mask, operand_width};
use crate::ir::{BinOp, Expr, FunctionIr, Operation, Stmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lattice {
    /// No path that runs has defined it yet.
    Unknown,
    Constant(u64),
    Varying,
}

impl Lattice {
    fn meet(self, other: Lattice) -> Lattice {
        match (self, other) {
            (Lattice::Unknown, other) | (other, Lattice::Unknown) => other,
            (Lattice::Constant(a), Lattice::Constant(b)) if a == b => self,
            _ => Lattice::Varying,
        }
    }
}

struct Solver<'a> {
    ssa: &'a Ssa,
    values: HashMap<u16, Lattice>,
    executable: Vec<bool>,
    /// Edges that can run, as (predecessor, successor).
    edges: HashSet<(usize, usize)>,
    starts: HashMap<u64, usize>,
}

impl Solver<'_> {
    fn of(&self, value: u16) -> Lattice {
        self.values.get(&value).copied().unwrap_or(Lattice::Unknown)
    }

    /// The expression's lattice value from the values it reads.
    fn expression(&self, expr: &Expr) -> Lattice {
        if matches!(
            expr,
            Expr::Apply {
                op: Operation::Results,
                ..
            }
        ) {
            return Lattice::Varying;
        }
        let mut reads = HashSet::new();
        crate::ir::visit::expr_reads(expr, &mut reads);
        if reads
            .iter()
            .any(|value| self.of(*value) == Lattice::Unknown)
        {
            return Lattice::Unknown;
        }
        let constant = |value: u16| match self.of(value) {
            Lattice::Constant(constant) => Some(constant),
            _ => None,
        };
        match evaluate(expr, &constant) {
            Some(value) => Lattice::Constant(value),
            None => Lattice::Varying,
        }
    }

    fn set(&mut self, value: u16, lattice: Lattice) -> bool {
        let old = self.of(value);
        let new = old.meet(lattice);
        if new != old {
            self.values.insert(value, new);
            return true;
        }
        false
    }

    fn mark(&mut self, from: usize, to: Option<usize>) -> bool {
        let Some(to) = to else {
            return false;
        };
        let mut changed = self.edges.insert((from, to));
        if !self.executable[to] {
            self.executable[to] = true;
            changed = true;
        }
        changed
    }

    fn target(&self, address: u64) -> Option<usize> {
        self.starts.get(&address).copied()
    }

    /// One pass over the blocks that can run; true when anything changed.
    fn sweep(&mut self) -> bool {
        let ssa = self.ssa;
        let mut changed = false;
        for block in 0..ssa.ir.blocks.len() {
            if !self.executable[block] {
                continue;
            }
            for phi in &ssa.phis[block] {
                let mut lattice = Lattice::Unknown;
                for (predecessor, arg) in ssa.predecessors[block].iter().zip(&phi.args) {
                    if self.edges.contains(&(*predecessor, block)) {
                        lattice = lattice.meet(self.of(*arg));
                    }
                }
                changed |= self.set(phi.value, lattice);
            }
            let stmts = &ssa.ir.blocks[block].stmts;
            for (position, stmt) in stmts.iter().enumerate() {
                if let Stmt::Assign { dest, value, .. } = stmt {
                    let lattice = match self.expression(value) {
                        Lattice::Constant(value) => {
                            Lattice::Constant(value & mask(u32::from(dest.width)))
                        }
                        lattice => lattice,
                    };
                    if lattice != Lattice::Unknown {
                        changed |= self.set(dest.index, lattice);
                    }
                }
                if let Stmt::Machine { outputs, .. } = stmt {
                    for output in outputs {
                        changed |= self.set(output.index, Lattice::Varying);
                    }
                }
                for output in stmt.call_outputs() {
                    changed |= self.set(output.dest.index, Lattice::Varying);
                }
                for (_, value) in ssa
                    .implicit_writes
                    .get(&(block, position))
                    .into_iter()
                    .flatten()
                {
                    changed |= self.set(*value, Lattice::Varying);
                }
            }
            let fallthrough = (block + 1 < ssa.ir.blocks.len()).then_some(block + 1);
            match stmts.last() {
                Some(Stmt::Brif {
                    cond,
                    lhs,
                    rhs,
                    target,
                    ..
                }) => match (self.expression(lhs), self.expression(rhs)) {
                    (Lattice::Constant(a), Lattice::Constant(b)) => {
                        let taken = holds(*cond, a, b, operand_width(lhs, rhs));
                        let next = if taken {
                            self.target(*target)
                        } else {
                            fallthrough
                        };
                        changed |= self.mark(block, next);
                    }
                    (Lattice::Unknown, _) | (_, Lattice::Unknown) => {}
                    _ => {
                        changed |= self.mark(block, self.target(*target));
                        changed |= self.mark(block, fallthrough);
                    }
                },
                Some(Stmt::Switch {
                    index,
                    cases,
                    default,
                    ..
                }) => match self.expression(index) {
                    Lattice::Constant(value) => {
                        let target = cases
                            .iter()
                            .find(|(case, _)| *case as u64 == value)
                            .map(|(_, target)| *target)
                            .or(*default);
                        changed |= self.mark(block, target.and_then(|target| self.target(target)));
                    }
                    Lattice::Unknown => {}
                    Lattice::Varying => {
                        for next in &ssa.successors[block] {
                            changed |= self.mark(block, Some(*next));
                        }
                    }
                },
                _ => {
                    for next in &ssa.successors[block] {
                        changed |= self.mark(block, Some(*next));
                    }
                }
            }
        }
        changed
    }
}

/// Replaces each read of a constant value with the constant, where the
/// replacement keeps the width every enclosing operation sees: under a
/// comparison or a signed operation, a register's width decides the
/// operation's, and a constant has none.
fn substitute(expr: &mut Expr, constants: &HashMap<u16, u64>, sensitive: bool) {
    match expr {
        Expr::Reg { index, width } => {
            if !sensitive && let Some(value) = constants.get(index) {
                *expr = Expr::Const(value & mask(u32::from(*width)));
            }
        }
        Expr::Const(_) => {}
        Expr::Load { addr, .. } => substitute(addr, constants, false),
        Expr::SignExtend { value, .. } => substitute(value, constants, false),
        Expr::Bin { op, lhs, rhs } => {
            let signed = matches!(op, BinOp::Sar | BinOp::DivS | BinOp::ModS);
            // A low-bits mask sets the width whatever it masks.
            let masked = *op == BinOp::And
                && matches!(rhs.as_ref(), Expr::Const(value) if value.wrapping_add(1).is_power_of_two());
            substitute(lhs, constants, signed || (sensitive && !masked));
            substitute(rhs, constants, signed || sensitive);
            // Two constants fold at full width, as they evaluate; only where
            // no enclosing operation takes its width from this one.
            if !sensitive && let (Expr::Const(_), Expr::Const(_)) = (lhs.as_ref(), rhs.as_ref()) {
                *expr = Expr::bin(*op, (**lhs).clone(), (**rhs).clone());
            }
        }
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => {
            substitute(lhs, constants, true);
            substitute(rhs, constants, true);
            substitute(then, constants, sensitive);
            substitute(els, constants, sensitive);
        }
        // An operation reads the low bits it names, whatever the width.
        Expr::Apply { args, .. } => {
            for arg in args {
                substitute(arg, constants, false);
            }
        }
    }
}

/// Replaces a whole expression whose value is constant with the constant,
/// or else the constant reads inside it.
fn replace(expr: &mut Expr, constants: &HashMap<u16, u64>) {
    if let Expr::Apply {
        op: Operation::Results,
        args,
    } = expr
    {
        for arg in args {
            replace(arg, constants);
        }
        return;
    }
    if matches!(expr, Expr::Const(_)) {
        return;
    }
    match evaluate(expr, &|value| constants.get(&value).copied()) {
        Some(value) => *expr = Expr::Const(value),
        None => substitute(expr, constants, false),
    }
}

fn solve(ssa: &Ssa) -> Solver<'_> {
    let mut solver = Solver {
        ssa,
        values: HashMap::new(),
        executable: vec![false; ssa.ir.blocks.len()],
        edges: HashSet::new(),
        starts: ssa
            .ir
            .blocks
            .iter()
            .enumerate()
            .map(|(index, block)| (block.start, index))
            .collect(),
    };
    solver.executable[0] = true;
    solver.edges.insert((super::ENTRY, 0));
    for value in ssa.entry.values() {
        solver.values.insert(*value, Lattice::Varying);
    }
    while solver.sweep() {}
    solver
}

fn constant_values(solver: &Solver<'_>) -> HashMap<u16, u64> {
    solver
        .values
        .iter()
        .filter_map(|(value, lattice)| match lattice {
            Lattice::Constant(constant) => Some((*value, *constant)),
            _ => None,
        })
        .collect()
}

/// The constant each value holds on every path that can run.
#[must_use]
pub fn constants(ssa: &Ssa) -> HashMap<u16, u64> {
    if ssa.ir.blocks.is_empty() {
        return HashMap::new();
    }
    let solver = solve(ssa);
    constant_values(&solver)
}

pub fn propagate(ssa: &mut Ssa) -> bool {
    let count = ssa.ir.blocks.len();
    if count == 0 {
        return false;
    }
    let solver = solve(ssa);
    let constants = constant_values(&solver);
    let executable = solver.executable;
    let decided: HashMap<usize, Option<u64>> = (0..count)
        .filter(|block| executable[*block])
        .filter_map(|block| {
            let edges = &ssa.successors[block];
            let live: Vec<usize> = edges
                .iter()
                .copied()
                .filter(|next| solver.edges.contains(&(block, *next)))
                .collect();
            (live.len() == 1 && edges.len() > 1)
                .then(|| (block, Some(ssa.ir.blocks[live[0]].start)))
        })
        .collect();

    let mut changed = false;
    let fallthrough_start =
        |block: usize, ir: &FunctionIr| ir.blocks.get(block + 1).map(|next| next.start);
    for (block, runs) in executable.iter().enumerate() {
        if !runs {
            continue;
        }
        let next = fallthrough_start(block, &ssa.ir);
        let stmts = &mut ssa.ir.blocks[block].stmts;
        for stmt in stmts.iter_mut() {
            let before = format!("{stmt:?}");
            match stmt {
                Stmt::Assign { dest, value, .. } => match constants.get(&dest.index) {
                    Some(constant) if !matches!(value, Expr::Const(_)) => {
                        *value = Expr::Const(*constant);
                    }
                    _ => substitute(value, &constants, false),
                },
                Stmt::Store { addr, value, .. } => {
                    replace(addr, &constants);
                    replace(value, &constants);
                }
                Stmt::Ret { value, .. } => replace(value, &constants),
                Stmt::Call { through, args, .. } => {
                    for value in through.iter_mut().chain(args.iter_mut().flatten()) {
                        replace(value, &constants);
                    }
                }
                Stmt::Brif { lhs, rhs, .. } => {
                    substitute(lhs, &constants, true);
                    substitute(rhs, &constants, true);
                }
                _ => {}
            }
            changed |= format!("{stmt:?}") != before;
        }
        // A branch only one side of which can run becomes a jump, or falls through.
        if let Some(Some(target)) = decided.get(&block) {
            match stmts.last() {
                Some(Stmt::Brif { .. }) | Some(Stmt::Switch { .. }) => {
                    let at = stmts.pop().and_then(|stmt| stmt.origin());
                    if Some(*target) != next {
                        stmts.push(Stmt::Br {
                            target: Some(*target),
                            at,
                        });
                    }
                    changed = true;
                }
                _ => {}
            }
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    use crate::ir::{BinOp, Block, Cond, Expr, FunctionIr, Operation, RegRef, Stmt};
    use crate::loader::Isa;
    use crate::ssa::propagate_constants;

    fn assign(index: u16, value: Expr) -> Stmt {
        Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
            at: None,
        }
    }

    fn function(blocks: Vec<Vec<Stmt>>) -> FunctionIr {
        let mut ir = FunctionIr::single_block(Isa::AArch64, Vec::new());
        ir.blocks = blocks
            .into_iter()
            .enumerate()
            .map(|(index, stmts)| Block {
                start: 0x10 * index as u64,
                stmts,
            })
            .collect();
        ir
    }

    #[test]
    fn result_groups_preserve_later_pieces_and_propagate_each_constant() {
        for last in [2, 3] {
            let mut ir = function(vec![vec![
                assign(0, Expr::Const(7)),
                assign(1, Expr::Const(last)),
                Stmt::Ret {
                    value: Expr::apply(
                        Operation::Results,
                        vec![Expr::reg(0, 64), Expr::reg(1, 64)],
                    ),
                    at: None,
                },
            ]]);
            propagate_constants(&mut ir);
            assert!(
                matches!(
                    ir.blocks[0].stmts.last(),
                    Some(Stmt::Ret { value: Expr::Apply { op: Operation::Results, args }, .. })
                        if *args == vec![Expr::Const(7), Expr::Const(last)]
                ),
                "{}",
                ir.render()
            );
        }
    }

    #[test]
    fn a_faulting_later_result_remains_observable() {
        let mut ir = function(vec![vec![
            assign(0, Expr::Const(7)),
            assign(1, Expr::Const(0)),
            Stmt::Ret {
                value: Expr::apply(
                    Operation::Results,
                    vec![
                        Expr::reg(0, 64),
                        Expr::bin(BinOp::DivU, Expr::Const(1), Expr::reg(1, 64)),
                    ],
                ),
                at: None,
            },
        ]]);
        let run = |ir: &FunctionIr| {
            crate::ir::eval::run(
                ir,
                &crate::ir::eval::Setup {
                    seed: 0,
                    convention: crate::ir::eval::Convention {
                        arguments: &[],
                        clobbered: &[],
                    },
                    registers: &[],
                    memory: &[],
                    step_limit: 100,
                },
            )
        };
        assert!(matches!(
            run(&ir),
            crate::ir::eval::Outcome::Unknown("division by zero")
        ));
        propagate_constants(&mut ir);
        crate::passes::simplify::simplify(&mut ir);
        assert!(
            matches!(
                ir.blocks[0].stmts.last(),
                Some(Stmt::Ret { value: Expr::Apply { op: Operation::Results, args }, .. }) if args.len() == 2
            ),
            "{}",
            ir.render()
        );
        assert!(matches!(
            run(&ir),
            crate::ir::eval::Outcome::Unknown("division by zero")
        ));
    }

    #[test]
    fn a_constant_set_before_a_loop_reaches_the_loop() {
        let mut ir = function(vec![
            vec![assign(9, Expr::Const(0x100))],
            vec![
                Stmt::Store {
                    addr: Expr::bin(BinOp::Add, Expr::reg(9, 64), Expr::Const(4)),
                    value: Expr::reg(8, 64),
                    width: 4,
                    at: None,
                },
                Stmt::Brif {
                    cond: Cond::Ne,
                    lhs: Expr::reg(8, 64),
                    rhs: Expr::Const(0),
                    target: 0x10,
                    at: None,
                },
            ],
            vec![Stmt::Ret {
                value: Expr::reg(0, 64),
                at: None,
            }],
        ]);
        propagate_constants(&mut ir);
        assert!(
            matches!(
                &ir.blocks[1].stmts[0],
                Stmt::Store {
                    addr: Expr::Const(0x104),
                    ..
                }
            ),
            "{}",
            ir.render()
        );
    }

    #[test]
    fn a_branch_a_constant_decides_keeps_one_side_out_of_the_join() {
        // x = 1; if (x == 1) goto set; x = rdi (never runs); set: return x
        let mut ir = function(vec![
            vec![
                assign(0, Expr::Const(1)),
                Stmt::Brif {
                    cond: Cond::Eq,
                    lhs: Expr::reg(0, 64),
                    rhs: Expr::Const(1),
                    target: 0x20,
                    at: None,
                },
            ],
            vec![assign(0, Expr::reg(7, 64))],
            vec![Stmt::Ret {
                value: Expr::reg(0, 64),
                at: None,
            }],
        ]);
        propagate_constants(&mut ir);
        assert!(
            matches!(
                &ir.blocks[2].stmts[0],
                Stmt::Ret {
                    value: Expr::Const(1),
                    ..
                }
            ),
            "{}",
            ir.render()
        );
    }

    #[test]
    fn a_constant_under_a_comparison_keeps_the_comparison_width() {
        // x = 0x80000000; return (int32_t)x < 0 ? rdi : 0. As a constant, x
        // would make the comparison 64 bits wide and false.
        let select = Expr::Select {
            cond: Cond::Lt,
            lhs: Box::new(Expr::reg(0, 32)),
            rhs: Box::new(Expr::Const(0)),
            then: Box::new(Expr::reg(7, 64)),
            els: Box::new(Expr::Const(0)),
        };
        let mut ir = function(vec![vec![
            assign(0, Expr::Const(0x8000_0000)),
            Stmt::Ret {
                value: select,
                at: None,
            },
        ]]);
        propagate_constants(&mut ir);
        let Stmt::Ret {
            value: Expr::Select { lhs, .. },
            ..
        } = &ir.blocks[0].stmts[1]
        else {
            panic!("{}", ir.render());
        };
        assert!(
            matches!(lhs.as_ref(), Expr::Reg { width: 32, .. }),
            "{}",
            ir.render()
        );
    }

    #[test]
    fn assignment_width_is_kept_by_wide_consumers_and_constant_branches() {
        use crate::ir::eval::{self, Convention, Outcome, Setup};
        for width in [8, 16, 32, 64] {
            for raw in [0, 1, 0x100, 0x1_0000, 0x1_0000_0000, 1 << 63, u64::MAX] {
                let ir = function(vec![
                    vec![
                        Stmt::Assign {
                            dest: RegRef { index: 0, width },
                            value: Expr::Const(raw),
                            at: None,
                        },
                        Stmt::Store {
                            addr: Expr::Const(0x4000),
                            value: Expr::reg(0, 64),
                            width: 8,
                            at: None,
                        },
                        assign(
                            1,
                            Expr::apply(Operation::PopCount(64), vec![Expr::reg(0, 64)]),
                        ),
                        Stmt::Store {
                            addr: Expr::Const(0x4008),
                            value: Expr::reg(1, 64),
                            width: 8,
                            at: None,
                        },
                        Stmt::Brif {
                            cond: Cond::Eq,
                            lhs: Expr::reg(1, 64),
                            rhs: Expr::Const(1),
                            target: 0x20,
                            at: None,
                        },
                    ],
                    vec![
                        assign(2, Expr::Const(3)),
                        Stmt::Br {
                            target: Some(0x30),
                            at: None,
                        },
                    ],
                    vec![
                        assign(2, Expr::Const(0)),
                        Stmt::Br {
                            target: Some(0x30),
                            at: None,
                        },
                    ],
                    vec![Stmt::Ret {
                        value: Expr::reg(2, 64),
                        at: None,
                    }],
                ]);
                let truncated = (u128::from(raw) % (1u128 << width)) as u64;
                let population = u64::from(truncated.count_ones());
                let returned = if population == 1 { 0 } else { 3 };
                let memory = [(0x4000, truncated), (0x4008, population)]
                    .into_iter()
                    .flat_map(|(address, value)| {
                        value
                            .to_le_bytes()
                            .into_iter()
                            .enumerate()
                            .map(move |(offset, byte)| (address + offset as u64, byte))
                    })
                    .collect();
                let expected = Outcome::Return {
                    value: returned,
                    calls: Vec::new(),
                    memory,
                };
                let setup = Setup {
                    seed: 0,
                    convention: Convention {
                        arguments: &[],
                        clobbered: &[],
                    },
                    registers: &[],
                    memory: &[],
                    step_limit: 40,
                };
                let ssa = crate::ssa::build(&ir).unwrap();
                let constants = super::constants(&ssa);
                for (statement, expected_value) in [(0, truncated), (2, population)] {
                    let Stmt::Assign { dest, .. } = &ssa.ir.blocks[0].stmts[statement] else {
                        unreachable!()
                    };
                    assert_eq!(
                        constants.get(&dest.index),
                        Some(&expected_value),
                        "width {width}, raw {raw:#x}, statement {statement}"
                    );
                }
                let lowered = crate::ssa::lower(&ssa);
                let mut folded = ir.clone();
                propagate_constants(&mut folded);
                for candidate in [&ir, &lowered, &folded] {
                    assert_eq!(
                        eval::run(candidate, &setup),
                        expected,
                        "width {width}, raw {raw:#x}"
                    );
                }
            }
        }
    }
}

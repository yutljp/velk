//! The SSA layer. Every definition of a register becomes a value of its own,
//! a register index from `VALUE_BASE` up, so the expression types, the
//! interpreter and the simplifier work on it unchanged. Where control flow
//! joins different definitions, a φ at the block's start picks the one the
//! path came by. Reads and writes a statement makes without naming them,
//! such as a call's arguments and the registers it clobbers, are kept beside
//! the statements.

mod dom;
pub mod sccp;

use std::collections::{HashMap, HashSet};

use crate::ir::cfg::{live_in, successors};
use crate::ir::visit::statement_registers;
use crate::ir::{Expr, FunctionIr, Stmt, VALUE_BASE};

/// The value a block starts with for one register, chosen by the
/// predecessor the path came from.
#[derive(Debug, Clone)]
pub struct Phi {
    pub value: u16,
    /// One value per predecessor, in the order of `Ssa::predecessors`.
    pub args: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct Ssa {
    /// The function with every register read and write renamed to its value.
    pub ir: FunctionIr,
    pub predecessors: Vec<Vec<usize>>,
    pub successors: Vec<Vec<usize>>,
    pub phis: Vec<Vec<Phi>>,
    /// The register each value stands for, by `value - VALUE_BASE`.
    pub origin: Vec<u16>,
    /// The value each register holds on entry.
    pub entry: HashMap<u16, u16>,
    /// The `(register, value)` pairs each statement reads without naming them.
    pub implicit_reads: HashMap<(usize, usize), Vec<(u16, u16)>>,
    /// The `(register, value)` pairs each statement defines without naming them.
    pub implicit_writes: HashMap<(usize, usize), Vec<(u16, u16)>>,
}

impl Ssa {
    pub fn register_of(&self, value: u16) -> u16 {
        self.origin[usize::from(value - VALUE_BASE)]
    }

    pub fn is_value(index: u16) -> bool {
        index >= VALUE_BASE
    }
}

/// The registers an expression names.
fn named(expr: &Expr, out: &mut HashSet<u16>) {
    crate::ir::visit::expr_reads(expr, out);
}

fn explicit_reads(stmt: &Stmt) -> HashSet<u16> {
    let mut out = HashSet::new();
    match stmt {
        Stmt::Assign { value, .. } | Stmt::Ret { value } => named(value, &mut out),
        Stmt::Store { addr, value, .. } => {
            named(addr, &mut out);
            named(value, &mut out);
        }
        Stmt::Brif { lhs, rhs, .. } => {
            named(lhs, &mut out);
            named(rhs, &mut out);
        }
        Stmt::BrIndirect { target } => named(target, &mut out),
        Stmt::Switch { index, .. } => named(index, &mut out),
        Stmt::Call {
            through: Some(through),
            ..
        } => named(through, &mut out),
        _ => {}
    }
    out
}

/// Renames each register an expression reads by `rename`, keeping widths.
fn rename_expr(expr: &mut Expr, rename: &mut dyn FnMut(u16) -> u16) {
    match expr {
        Expr::Reg { index, .. } => *index = rename(*index),
        Expr::Const(_) => {}
        Expr::Bin { lhs, rhs, .. } => {
            rename_expr(lhs, rename);
            rename_expr(rhs, rename);
        }
        Expr::Load { addr, .. } => rename_expr(addr, rename),
        Expr::SignExtend { value, .. } => rename_expr(value, rename),
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => {
            for expr in [lhs, rhs, then, els] {
                rename_expr(expr, rename);
            }
        }
    }
}

/// Renames the registers a statement reads, not the one it assigns.
fn rename_reads(stmt: &mut Stmt, rename: &mut dyn FnMut(u16) -> u16) {
    match stmt {
        Stmt::Assign { value, .. } | Stmt::Ret { value } => rename_expr(value, rename),
        Stmt::Store { addr, value, .. } => {
            rename_expr(addr, rename);
            rename_expr(value, rename);
        }
        Stmt::Brif { lhs, rhs, .. } => {
            rename_expr(lhs, rename);
            rename_expr(rhs, rename);
        }
        Stmt::BrIndirect { target } => rename_expr(target, rename),
        Stmt::Switch { index, .. } => rename_expr(index, rename),
        Stmt::Call {
            through: Some(through),
            ..
        } => rename_expr(through, rename),
        _ => {}
    }
}

struct Builder {
    origin: Vec<u16>,
    entry: HashMap<u16, u16>,
    stacks: HashMap<u16, Vec<u16>>,
}

impl Builder {
    fn fresh(&mut self, register: u16) -> u16 {
        let value = VALUE_BASE + self.origin.len() as u16;
        self.origin.push(register);
        value
    }

    fn current(&mut self, register: u16) -> u16 {
        if let Some(value) = self.stacks.get(&register).and_then(|stack| stack.last()) {
            return *value;
        }
        if let Some(value) = self.entry.get(&register) {
            return *value;
        }
        let value = self.fresh(register);
        self.entry.insert(register, value);
        value
    }
}

/// Puts the function into SSA form, or None when it has more definitions
/// than value indices.
pub fn build(ir: &FunctionIr) -> Option<Ssa> {
    let count = ir.blocks.len();
    let successors: Vec<Vec<usize>> = (0..count).map(|index| successors(ir, index)).collect();
    let mut predecessors = vec![Vec::new(); count];
    for (block, next) in successors.iter().enumerate() {
        for successor in next {
            predecessors[*successor].push(block);
        }
    }
    let dominators = dom::dominators(&successors);
    let frontier = dom::frontiers(&successors, &dominators);
    let live = live_in(ir);

    // The blocks defining each register.
    let mut defining: HashMap<u16, HashSet<usize>> = HashMap::new();
    for (block, contents) in ir.blocks.iter().enumerate() {
        for stmt in &contents.stmts {
            for register in statement_registers(stmt).0 {
                defining.entry(register).or_default().insert(block);
            }
        }
    }
    // A φ wherever two definitions meet and the register is still live.
    let mut builder = Builder {
        origin: Vec::new(),
        entry: HashMap::new(),
        stacks: HashMap::new(),
    };
    let mut phi_registers: Vec<Vec<u16>> = vec![Vec::new(); count];
    let mut registers: Vec<u16> = defining.keys().copied().collect();
    registers.sort_unstable();
    for register in &registers {
        let mut work: Vec<usize> = defining[register].iter().copied().collect();
        let mut placed: HashSet<usize> = HashSet::new();
        while let Some(block) = work.pop() {
            for join in &frontier[block] {
                if live[*join].contains(register) && placed.insert(*join) {
                    phi_registers[*join].push(*register);
                    work.push(*join);
                }
            }
        }
    }
    let mut phis: Vec<Vec<Phi>> = phi_registers
        .iter()
        .enumerate()
        .map(|(block, list)| {
            list.iter()
                .map(|register| Phi {
                    value: builder.fresh(*register),
                    args: vec![0; predecessors[block].len()],
                })
                .collect()
        })
        .collect();

    let mut renamed = ir.clone();
    let mut implicit_reads = HashMap::new();
    let mut implicit_writes = HashMap::new();
    let mut children = vec![Vec::new(); count];
    for (block, parent) in dominators.idom.iter().enumerate() {
        if let Some(parent) = parent {
            children[*parent].push(block);
        }
    }
    // Reachable blocks in dominator-tree order, then each unreachable one on
    // its own, starting from the entry values.
    let mut roots = vec![0];
    roots.extend((1..count).filter(|block| dominators.idom[*block].is_none()));
    enum Step {
        Enter(usize),
        Leave(Vec<u16>),
    }
    for root in roots {
        if count == 0 {
            break;
        }
        let mut steps = vec![Step::Enter(root)];
        while let Some(step) = steps.pop() {
            let block = match step {
                Step::Enter(block) => block,
                Step::Leave(pushed) => {
                    for register in pushed {
                        builder.stacks.get_mut(&register).expect("pushed").pop();
                    }
                    continue;
                }
            };
            let mut pushed = Vec::new();
            for (phi, register) in phis[block].iter().zip(&phi_registers[block]) {
                builder.stacks.entry(*register).or_default().push(phi.value);
                pushed.push(*register);
            }
            for position in 0..renamed.blocks[block].stmts.len() {
                let stmt = &mut renamed.blocks[block].stmts[position];
                let (writes, reads) = statement_registers(stmt);
                let explicit = explicit_reads(stmt);
                let mut implicit: Vec<(u16, u16)> = reads
                    .difference(&explicit)
                    .map(|register| (*register, builder.current(*register)))
                    .collect();
                if !implicit.is_empty() {
                    implicit.sort_unstable();
                    implicit_reads.insert((block, position), implicit);
                }
                rename_reads(stmt, &mut |register| builder.current(register));
                let mut defined = Vec::new();
                for register in writes {
                    let value = builder.fresh(register);
                    builder.stacks.entry(register).or_default().push(value);
                    pushed.push(register);
                    match stmt {
                        Stmt::Assign { dest, .. } if dest.index == register => dest.index = value,
                        _ => defined.push((register, value)),
                    }
                }
                if !defined.is_empty() {
                    defined.sort_unstable();
                    implicit_writes.insert((block, position), defined);
                }
            }
            for successor in &successors[block] {
                for (slot, from) in predecessors[*successor].iter().enumerate() {
                    if *from != block {
                        continue;
                    }
                    for (phi, register) in
                        phis[*successor].iter_mut().zip(&phi_registers[*successor])
                    {
                        phi.args[slot] = builder.current(*register);
                    }
                }
            }
            steps.push(Step::Leave(pushed));
            for child in children[block].iter().rev() {
                steps.push(Step::Enter(*child));
            }
        }
    }
    if builder.origin.len() > usize::from(u16::MAX - VALUE_BASE) {
        return None;
    }
    // φ arguments from unreachable predecessors read the entry values.
    for (block, list) in phis.iter_mut().enumerate() {
        for (phi, register) in list.iter_mut().zip(&phi_registers[block]) {
            for arg in &mut phi.args {
                if *arg == 0 {
                    *arg = builder.current(*register);
                }
            }
        }
    }
    Some(Ssa {
        ir: renamed,
        predecessors,
        successors,
        phis,
        origin: builder.origin,
        entry: builder.entry,
        implicit_reads,
        implicit_writes,
    })
}

/// Propagates constants across the function through its SSA form.
pub fn propagate_constants(ir: &mut FunctionIr) {
    let Some(mut ssa) = build(ir) else {
        return;
    };
    if sccp::propagate(&mut ssa) {
        *ir = lower(&ssa);
    }
}

/// Leaves SSA form by giving every value its register back. Correct as long
/// as each value's register still holds it wherever it is read, as it does
/// after transformations that only rewrite reads into equal expressions.
pub fn lower(ssa: &Ssa) -> FunctionIr {
    let mut ir = ssa.ir.clone();
    let mut back = |index: u16| {
        if Ssa::is_value(index) {
            ssa.register_of(index)
        } else {
            index
        }
    };
    for block in &mut ir.blocks {
        for stmt in &mut block.stmts {
            rename_reads(stmt, &mut back);
            if let Stmt::Assign { dest, .. } = stmt {
                dest.index = back(dest.index);
            }
        }
    }
    ir
}

/// Checks the SSA properties: every value defined once, every read and φ
/// argument a defined value whose definition comes first on every path, and
/// one φ argument per predecessor. Returns the first violation.
pub fn verify(ssa: &Ssa) -> Result<(), String> {
    // Where each value is defined: block, and position (-1 for φ and entry).
    let mut defined: HashMap<u16, (usize, isize)> = HashMap::new();
    let mut define = |value: u16, at: (usize, isize)| {
        if defined.insert(value, at).is_some() {
            return Err(format!("s{} is defined twice", value - VALUE_BASE));
        }
        Ok(())
    };
    for value in ssa.entry.values() {
        define(*value, (0, -2))?;
    }
    for (block, list) in ssa.phis.iter().enumerate() {
        for phi in list {
            if phi.args.len() != ssa.predecessors[block].len() {
                return Err(format!(
                    "a φ in block {block} has the wrong number of arguments"
                ));
            }
            define(phi.value, (block, -1))?;
        }
    }
    for (block, contents) in ssa.ir.blocks.iter().enumerate() {
        for (position, stmt) in contents.stmts.iter().enumerate() {
            if let Stmt::Assign { dest, .. } = stmt {
                if !Ssa::is_value(dest.index) {
                    return Err(format!("block {block} assigns a register, not a value"));
                }
                define(dest.index, (block, position as isize))?;
            }
            for (_, value) in ssa
                .implicit_writes
                .get(&(block, position))
                .into_iter()
                .flatten()
            {
                define(*value, (block, position as isize))?;
            }
        }
    }
    let dominators = dom::dominators(&ssa.successors);
    let dominates = |upper: usize, mut lower: usize| loop {
        if upper == lower {
            return true;
        }
        match dominators.idom[lower] {
            Some(up) => lower = up,
            None => return false,
        }
    };
    let reachable = |block: usize| block == 0 || dominators.idom[block].is_some();
    let check =
        |value: u16, block: usize, position: isize, inclusive: bool| -> Result<(), String> {
            let Some((at, place)) = defined.get(&value).copied() else {
                return Err(format!("s{} is read but never defined", value - VALUE_BASE));
            };
            // Entry values hold everywhere, and unreachable code is unordered.
            if place == -2 || !reachable(block) {
                return Ok(());
            }
            let before = if at == block {
                place < position || (inclusive && place == position)
            } else {
                dominates(at, block)
            };
            if before {
                Ok(())
            } else {
                Err(format!(
                    "s{} is read where its definition does not reach",
                    value - VALUE_BASE
                ))
            }
        };
    for (block, contents) in ssa.ir.blocks.iter().enumerate() {
        for (position, stmt) in contents.stmts.iter().enumerate() {
            for register in explicit_reads(stmt) {
                if !Ssa::is_value(register) {
                    return Err(format!("block {block} reads a register, not a value"));
                }
                check(register, block, position as isize, false)?;
            }
            for (_, value) in ssa
                .implicit_reads
                .get(&(block, position))
                .into_iter()
                .flatten()
            {
                check(*value, block, position as isize, false)?;
            }
        }
    }
    for (block, list) in ssa.phis.iter().enumerate() {
        for phi in list {
            for (predecessor, arg) in ssa.predecessors[block].iter().zip(&phi.args) {
                let end = ssa.ir.blocks[*predecessor].stmts.len() as isize;
                check(*arg, *predecessor, end, true)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{build, lower, verify};
    use crate::ir::{BinOp, Block, Cond, Expr, FunctionIr, RegRef, Stmt};
    use crate::loader::Isa;

    fn assign(index: u16, value: Expr) -> Stmt {
        Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
        }
    }

    /// x = 0; loop: x = x + 1; if x != n goto loop; return x
    fn counting_loop() -> FunctionIr {
        let x = Expr::reg(0, 64);
        let mut ir = FunctionIr::single_block(Isa::X86_64, vec![assign(0, Expr::Const(0))]);
        ir.blocks.push(Block {
            start: 0x10,
            stmts: vec![
                assign(0, Expr::bin(BinOp::Add, x.clone(), Expr::Const(1))),
                Stmt::Brif {
                    cond: Cond::Ne,
                    lhs: x.clone(),
                    rhs: Expr::reg(7, 64),
                    target: 0x10,
                },
            ],
        });
        ir.blocks.push(Block {
            start: 0x20,
            stmts: vec![Stmt::Ret { value: x }],
        });
        ir
    }

    #[test]
    fn a_loop_counter_joins_at_the_loop_header() {
        let ir = counting_loop();
        let ssa = build(&ir).expect("builds");
        assert_eq!(ssa.phis[1].len(), 1, "one φ for the counter");
        let phi = &ssa.phis[1][0];
        assert_eq!(ssa.register_of(phi.value), 0);
        // From the entry, the constant's value; from the back edge, the sum's.
        let defined = |block: usize| match &ssa.ir.blocks[block].stmts[0] {
            Stmt::Assign { dest, .. } => dest.index,
            other => panic!("{other:?}"),
        };
        assert_eq!(phi.args, vec![defined(0), defined(1)]);
        // The parameter n is read at its entry value.
        assert!(ssa.entry.contains_key(&7));
        verify(&ssa).expect("well formed");
    }

    #[test]
    fn lowering_gives_every_value_its_register_back() {
        let ir = counting_loop();
        let ssa = build(&ir).expect("builds");
        assert_ne!(ssa.ir.render(), ir.render());
        assert_eq!(lower(&ssa).render(), ir.render());
    }
}

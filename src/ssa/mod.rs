//! The SSA layer. Every definition of a register becomes a value of its own,
//! a register index from `VALUE_BASE` up, so the expression types, the
//! interpreter and the simplifier work on it unchanged. Where control flow
//! joins different definitions, a φ at the block's start picks the one the
//! path came by. Reads and writes a statement makes without naming them,
//! such as a call's arguments and the registers it clobbers, are kept beside
//! the statements.

mod demand;
mod split;

#[cfg(test)]
use demand::demanded_bits;
pub(crate) use demand::entry_demands;
pub use demand::narrow_partial_writes;
pub use split::split_variables;

pub(crate) mod dom;
pub mod ranges;
pub mod sccp;

use std::collections::{HashMap, HashSet};

use crate::ir::cfg::{live_in, successors};
use crate::ir::visit::statement_registers;
use crate::ir::{Expr, FunctionIr, Stmt, VALUE_BASE};

/// The predecessor standing for the call into the function.
pub const ENTRY: usize = usize::MAX;

/// The value a block starts with for one register, chosen by the
/// predecessor the path came from.
#[derive(Debug, Clone)]
pub struct Phi {
    pub value: u16,
    /// One value per predecessor, in the order of `Ssa::predecessors`; the
    /// entry block's first is the value the function was called with.
    pub args: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct Ssa {
    /// The function with every register read and write renamed to its value.
    pub ir: FunctionIr,
    /// The blocks each block is entered from; the entry block's list starts
    /// with `ENTRY`, the call into the function.
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
        Stmt::Call { through, args, .. } => {
            for value in through.iter().chain(args.iter().flatten()) {
                named(value, &mut out);
            }
        }
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
        Expr::Apply { args, .. } => {
            for arg in args {
                rename_expr(arg, rename);
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
        Stmt::Call { through, args, .. } => {
            for value in through.iter_mut().chain(args.iter_mut().flatten()) {
                rename_expr(value, rename);
            }
        }
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
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        let mut destinations = HashSet::new();
        let mut output_registers = HashSet::new();
        for output in stmt.call_outputs() {
            if !destinations.insert(output.dest.index) || !output_registers.insert(output.register)
            {
                return None;
            }
        }
    }
    let count = ir.blocks.len();
    let successors: Vec<Vec<usize>> = (0..count).map(|index| successors(ir, index)).collect();
    let mut predecessors = vec![Vec::new(); count];
    if count > 0 {
        predecessors[0].push(ENTRY);
    }
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
                // A call reads its argument registers whether or not it also
                // names one, as the address it calls through.
                let unnamed: Vec<u16> = match stmt {
                    Stmt::Call { .. } => {
                        let mut sources = stmt.unnamed_call_reads();
                        sources.extend(
                            stmt.preserved_output_sources()
                                .into_iter()
                                .map(|(_, register)| register),
                        );
                        sources.sort_unstable();
                        sources.dedup();
                        sources
                    }
                    _ => reads.difference(&explicit_reads(stmt)).copied().collect(),
                };
                let mut implicit: Vec<(u16, u16)> = unnamed
                    .into_iter()
                    .map(|register| (register, builder.current(register)))
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
                    if let Some(dest) = crate::ir::visit::statement_destinations_mut(stmt)
                        .into_iter()
                        .find(|dest| dest.index == register)
                    {
                        dest.index = value;
                    } else {
                        defined.push((register, value));
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

/// Makes each read of what a call leaves in a register it changes, but
/// returns nothing in, read the undefined value: the register's earlier
/// value is gone, and the code cannot rely on what is there instead. A
/// value a φ joins with others is left as it is.
pub fn undefine_clobbered_reads(ir: &mut FunctionIr) {
    if !ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .any(|stmt| matches!(stmt, Stmt::Call { .. }))
    {
        return;
    }
    let Some(ssa) = build(ir) else {
        return;
    };
    let mut undefined: HashSet<u16> = HashSet::new();
    for (&(block, position), defined) in &ssa.implicit_writes {
        let stmt = &ssa.ir.blocks[block].stmts[position];
        let Stmt::Call { .. } = stmt else {
            continue;
        };
        let results: Vec<u16> = stmt
            .call_outputs()
            .iter()
            .map(|output| output.register)
            .collect();
        undefined.extend(
            defined
                .iter()
                .filter(|(register, _)| {
                    crate::arch::machine_registers().contains(register)
                        && !results.contains(register)
                })
                .map(|(_, value)| *value),
        );
    }
    if undefined.is_empty() {
        return;
    }
    fn undefine(original: &mut Expr, renamed: &Expr, undefined: &HashSet<u16>) {
        if let Expr::Reg { index, .. } = renamed
            && undefined.contains(index)
        {
            *original = Expr::apply(crate::ir::Operation::Undefined, Vec::new());
            return;
        }
        let children = crate::ir::visit::children(renamed);
        for (original, renamed) in crate::ir::visit::children_mut(original)
            .into_iter()
            .zip(children)
        {
            undefine(original, renamed, undefined);
        }
    }
    for (contents, renamed) in ir.blocks.iter_mut().zip(&ssa.ir.blocks) {
        for (stmt, renamed) in contents.stmts.iter_mut().zip(&renamed.stmts) {
            for (original, renamed) in stmt.operands_mut().into_iter().zip(renamed.operands()) {
                undefine(original, renamed, &undefined);
            }
        }
    }
}

/// Gives each call to a variadic library function the arguments its format
/// string's conversions take, where a constant format reaches the call.
pub fn count_variadic_arguments(ir: &mut FunctionIr, image: &crate::loader::Image) {
    let variadic = |target: u64| {
        let name = image.functions.get(&target)?.name.as_deref()?;
        let prototype =
            crate::analysis::prototypes::of(name, image.format == crate::loader::Format::MachO)?;
        Some((prototype.fixed(), prototype.format?, prototype.scans))
    };
    let pending = ir.blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
        matches!(stmt, Stmt::Call { target: Some(target), args: None, .. } if variadic(*target).is_some())
    });
    if !pending {
        return;
    }
    let Some(ssa) = build(ir) else {
        return;
    };
    let constants = sccp::constants(&ssa);
    for (block, contents) in ir.blocks.iter_mut().enumerate() {
        for (position, stmt) in contents.stmts.iter_mut().enumerate() {
            let Stmt::Call {
                target: Some(target),
                args: args @ None,
                convention,
                ..
            } = stmt
            else {
                continue;
            };
            let Some((fixed, format, scans)) = variadic(*target) else {
                continue;
            };
            let registers = convention.arguments();
            let Some(register) = registers.get(format) else {
                continue;
            };
            // The format's address, as the value the call reads it in.
            let Some(address) = ssa
                .implicit_reads
                .get(&(block, position))
                .and_then(|reads| reads.iter().find(|(read, _)| read == register))
                .and_then(|(_, value)| constants.get(value))
            else {
                continue;
            };
            let Some(format) = c_string(image, *address) else {
                continue;
            };
            let count = fixed + crate::analysis::prototypes::conversion_types(&format, scans).len();
            // The rest are read from the stack, where the call finds them.
            *args = crate::lift::arguments(
                *convention,
                ir.isa,
                Some(count),
                count.saturating_sub(registers.len()),
            );
        }
    }
}

/// The NUL-terminated text at `address`, within its section.
pub(crate) fn c_string(image: &crate::loader::Image, address: u64) -> Option<String> {
    let section = image.section_at(address)?;
    let available = (section.vaddr + section.size)
        .saturating_sub(address)
        .min(256);
    let bytes = image.read_vaddr(address, available)?;
    let text: Vec<u8> = bytes
        .iter()
        .copied()
        .take_while(|byte| *byte != 0)
        .collect();
    String::from_utf8(text).ok()
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
    lower_with(ssa, &HashMap::new())
}

/// A call's result that only moves on into another variable right after the
/// call goes there directly: `v1 = f(); v2 = v1;` becomes `v2 = f();`, and
/// every other output retains its own destination.
pub fn take_results_directly(ir: &mut FunctionIr) {
    let mut reads: HashMap<u16, usize> = HashMap::new();
    let mut definitions: HashMap<u16, usize> = HashMap::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        let (written, read) = statement_registers(stmt);
        for register in read {
            *reads.entry(register).or_default() += 1;
        }
        for register in written {
            *definitions.entry(register).or_default() += 1;
        }
    }
    let variable = |index: u16| index >= crate::ir::VARIABLE_BASE;
    for block in &mut ir.blocks {
        let mut position = 0;
        while position < block.stmts.len() {
            position += 1;
            if !matches!(block.stmts[position - 1], Stmt::Call { .. }) {
                continue;
            }
            let position = position - 1;
            let mut next = position + 1;
            while let Some(Stmt::Assign {
                dest,
                value: Expr::Reg { index, width: 64 },
            }) = block.stmts.get(next)
            {
                let (dest, taken) = (*dest, *index);
                let written = |stmt: &Stmt| statement_registers(stmt).0;
                if !(variable(dest.index)
                    && dest.width == 64
                    && reads.get(&taken) == Some(&1)
                    && definitions.get(&taken) == Some(&1)
                    && !block.stmts[position..next]
                        .iter()
                        .any(|stmt| written(stmt).contains(&dest.index))
                    && !block.stmts[position + 1..next]
                        .iter()
                        .any(|stmt| statement_registers(stmt).1.contains(&dest.index)))
                {
                    next += 1;
                    continue;
                }
                let Some(definition) = block.stmts[position..next].iter_mut().find_map(|stmt| {
                    crate::ir::visit::statement_destinations_mut(stmt)
                        .into_iter()
                        .find(|dest| dest.index == taken && dest.width == 64)
                }) else {
                    next += 1;
                    continue;
                };
                *definition = dest;
                block.stmts.remove(next);
            }
        }
    }
}

/// Leaves SSA form, giving each value its name in `renames` or else its register.
fn lower_with(ssa: &Ssa, renames: &HashMap<u16, u16>) -> FunctionIr {
    let mut ir = ssa.ir.clone();
    let mut back = |index: u16| {
        if let Some(name) = renames.get(&index) {
            *name
        } else if Ssa::is_value(index) {
            ssa.register_of(index)
        } else {
            index
        }
    };
    for block in &mut ir.blocks {
        for stmt in &mut block.stmts {
            rename_reads(stmt, &mut back);
            for dest in crate::ir::visit::statement_destinations_mut(stmt) {
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
            let mut destinations = stmt.clone();
            for dest in crate::ir::visit::statement_destinations_mut(&mut destinations) {
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
                if *predecessor == ENTRY {
                    if !ssa.entry.values().any(|value| value == arg) {
                        return Err(
                            "the entry block's φ does not start from an entry value".to_owned()
                        );
                    }
                    continue;
                }
                let end = ssa.ir.blocks[*predecessor].stmts.len() as isize;
                check(*arg, *predecessor, end, true)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{build, entry_demands, lower, verify};
    use crate::ir::{BinOp, Block, Cond, Expr, FunctionIr, Operation, Precision, RegRef, Stmt};
    use crate::loader::Isa;

    fn assign(index: u16, value: Expr) -> Stmt {
        Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
        }
    }

    fn output_call(output_registers: &[u16], changed: &[u16]) -> Stmt {
        Stmt::Call {
            target: Some(0x1000),
            through: None,
            convention: crate::ir::Convention::Aapcs64,
            args: Some(Vec::new()),
            floats_named: true,
            outputs: output_registers
                .iter()
                .map(|register| crate::ir::CallOutput {
                    register: *register,
                    dest: RegRef {
                        index: *register,
                        width: 64,
                    },
                })
                .collect(),
            clobbers: Some(changed.iter().copied().collect()),
            via: None,
        }
    }

    #[test]
    fn all_call_outputs_keep_provenance_through_ssa_and_splitting() {
        use crate::ir::eval::{self, Setup};
        for output_registers in [&[32, 34, 36, 38][..], &[0, 32], &[0, 1]] {
            let sum = output_registers.iter().enumerate().fold(
                Expr::Const(0),
                |value, (at, register)| {
                    Expr::bin(
                        BinOp::Add,
                        value,
                        Expr::bin(
                            BinOp::Mul,
                            Expr::reg(*register, 64),
                            Expr::Const(at as u64 + 1),
                        ),
                    )
                },
            );
            let mut ir = FunctionIr::single_block(
                Isa::AArch64,
                vec![
                    output_call(output_registers, output_registers),
                    Stmt::Ret { value: sum },
                ],
            );
            ir.convention = crate::ir::Convention::Aapcs64;
            for seed in [0, 1, u64::MAX] {
                let setup = Setup {
                    seed,
                    convention: eval::Convention {
                        arguments: &[],
                        clobbered: &[],
                    },
                    registers: &[],
                    memory: &[],
                    step_limit: 100,
                };
                let expected =
                    output_registers
                        .iter()
                        .enumerate()
                        .fold(0_u64, |sum, (at, register)| {
                            sum.wrapping_add(
                                eval::hash(seed ^ 1, 0x2_0000 + u64::from(*register))
                                    .wrapping_mul(at as u64 + 1),
                            )
                        });
                let before = eval::run(&ir, &setup);
                assert!(matches!(before, eval::Outcome::Return { value, .. } if value == expected));
                let mut defined = ir.clone();
                super::undefine_clobbered_reads(&mut defined);
                assert_eq!(eval::run(&defined, &setup), before);
                let mut ssa = build(&ir).unwrap();
                verify(&ssa).unwrap();
                let constants = super::sccp::constants(&ssa);
                let ranges = super::ranges::Ranges::solve(&ssa).unwrap();
                for (output, register) in ssa.ir.blocks[0].stmts[0]
                    .call_outputs()
                    .iter()
                    .zip(output_registers)
                {
                    assert_eq!(output.register, *register);
                    assert!(!constants.contains_key(&output.dest.index));
                    assert_eq!(
                        ranges.read(output.dest.index, 64, 0, 0),
                        Some(super::ranges::Fact::TOP)
                    );
                    assert!(
                        !ssa.implicit_writes
                            .get(&(0, 0))
                            .into_iter()
                            .flatten()
                            .any(|(physical, _)| physical == register)
                    );
                }
                super::sccp::propagate(&mut ssa);
                verify(&ssa).unwrap();
                assert_eq!(eval::run(&lower(&ssa), &setup), before);
                let mut renamed = ir.clone();
                super::split_variables(&mut renamed, &(0..64).collect::<Vec<_>>());
                assert_eq!(eval::run(&renamed, &setup), before);
                let rebuilt = build(&renamed).unwrap();
                verify(&rebuilt).unwrap();
                for (output, register) in renamed.blocks[0].stmts[0]
                    .call_outputs()
                    .iter()
                    .zip(output_registers)
                {
                    assert_eq!(output.register, *register);
                    assert!(output.dest.index >= crate::ir::VARIABLE_BASE);
                    assert!(
                        !rebuilt
                            .implicit_writes
                            .get(&(0, 0))
                            .into_iter()
                            .flatten()
                            .any(|(physical, _)| physical == register)
                    );
                }
                assert_eq!(eval::run(&lower(&rebuilt), &setup), before);
                crate::passes::dce::dce_flow(&mut renamed);
                assert_eq!(eval::run(&renamed, &setup), before);
            }
        }
    }

    #[test]
    fn canonical_call_aliases_preserve_both_readers_and_unnamed_inputs() {
        use crate::ir::eval::{self, Setup};
        let named = crate::ir::VARIABLE_BASE + 100;
        let observe = 0x4000_0080_0000;
        for changed in [false, true] {
            for unnamed in [false, true] {
                for seed in [0, 1, 0x1234_5678] {
                    for initial in [0, 0x8123_4567_ffff_0011, u64::MAX] {
                        let mut ir = FunctionIr::single_block(
                            Isa::AArch64,
                            vec![
                                assign(0, Expr::Const(initial)),
                                output_call(
                                    if changed { &[0] } else { &[] },
                                    if changed { &[0] } else { &[] },
                                ),
                                assign(named, Expr::reg(0, 64)),
                            ],
                        );
                        ir.convention = crate::ir::Convention::Aapcs64;
                        if unnamed {
                            let mut call = output_call(&[], &[]);
                            let Stmt::Call {
                                args,
                                floats_named,
                                target,
                                ..
                            } = &mut call
                            else {
                                unreachable!()
                            };
                            *args = None;
                            *floats_named = false;
                            *target = Some(0x2000);
                            ir.blocks[0].stmts.push(call);
                        }
                        ir.blocks[0].stmts.extend([
                            Stmt::Store {
                                addr: Expr::Const(observe),
                                value: Expr::reg(0, 64),
                                width: 8,
                            },
                            Stmt::Store {
                                addr: Expr::Const(observe + 8),
                                value: Expr::reg(named, 64),
                                width: 8,
                            },
                            Stmt::Ret {
                                value: Expr::bin(
                                    BinOp::Add,
                                    Expr::bin(BinOp::Mul, Expr::reg(0, 64), Expr::Const(3)),
                                    Expr::bin(BinOp::Mul, Expr::reg(named, 64), Expr::Const(5)),
                                ),
                            },
                        ]);
                        let setup = Setup {
                            seed,
                            convention: eval::Convention {
                                arguments: &[],
                                clobbered: &[],
                            },
                            registers: &[],
                            memory: &[],
                            step_limit: 100,
                        };
                        let expected = if changed {
                            eval::hash(seed ^ 1, 0x2_0000)
                        } else {
                            initial
                        };
                        let before = eval::run(&ir, &setup);
                        let eval::Outcome::Return {
                            value,
                            calls,
                            memory,
                        } = &before
                        else {
                            panic!("{before:?}")
                        };
                        assert_eq!(*value, expected.wrapping_mul(8));
                        assert_eq!(calls.len(), if unnamed { 2 } else { 1 });
                        if unnamed {
                            assert_eq!(calls[1].arguments[0], expected);
                        }
                        for address in [observe, observe + 8] {
                            let word = u64::from_le_bytes(std::array::from_fn(|byte| {
                                memory[&(address + byte as u64)]
                            }));
                            assert_eq!(word, expected);
                        }
                        let ssa = build(&ir).unwrap();
                        verify(&ssa).unwrap();
                        let Stmt::Assign { dest: input, .. } = &ssa.ir.blocks[0].stmts[0] else {
                            unreachable!()
                        };
                        let source = if changed {
                            ssa.ir.blocks[0].stmts[1].call_outputs()[0].dest.index
                        } else {
                            input.index
                        };
                        let Stmt::Assign { dest: alias, value } = &ssa.ir.blocks[0].stmts[2] else {
                            unreachable!()
                        };
                        assert_eq!(*value, Expr::reg(source, 64));
                        assert_ne!(alias.index, source);
                        assert_eq!(eval::run(&lower(&ssa), &setup), before);
                        super::split_variables(&mut ir, &(0..31).collect::<Vec<_>>());
                        super::take_results_directly(&mut ir);
                        assert_eq!(eval::run(&ir, &setup), before);
                        let rebuilt = build(&ir).unwrap();
                        verify(&rebuilt).unwrap();
                        let first = ir.blocks[0]
                            .stmts
                            .iter()
                            .position(|stmt| {
                                matches!(
                                    stmt,
                                    Stmt::Call {
                                        target: Some(0x1000),
                                        ..
                                    }
                                )
                            })
                            .unwrap();
                        if changed && unnamed {
                            assert_eq!(ir.blocks[0].stmts[first].call_outputs()[0].dest.index, 0);
                            let physical = rebuilt.ir.blocks[0].stmts[first].call_outputs()[0]
                                .dest
                                .index;
                            let next = ir.blocks[0]
                                .stmts
                                .iter()
                                .position(|stmt| {
                                    matches!(
                                        stmt,
                                        Stmt::Call {
                                            target: Some(0x2000),
                                            ..
                                        }
                                    )
                                })
                                .unwrap();
                            assert!(rebuilt.implicit_reads[&(0, next)].contains(&(0, physical)));
                        }
                        assert_eq!(eval::run(&lower(&rebuilt), &setup), before);
                        crate::passes::dce::dce_flow(&mut ir);
                        assert_eq!(eval::run(&ir, &setup), before);
                    }
                }
            }
        }
    }

    #[test]
    fn preserved_call_outputs_transfer_only_demanded_bits_to_the_prevalue() {
        for width in [32, 64] {
            let mut call = output_call(&[32, 38], &[]);
            for output in call.call_outputs_mut() {
                output.dest.index = crate::ir::VARIABLE_BASE + output.register;
            }
            let needed = if width == 32 { 0xffff_ffff } else { u64::MAX };
            let mut ir = FunctionIr::single_block(
                Isa::AArch64,
                vec![
                    call,
                    Stmt::Ret {
                        value: Expr::reg(crate::ir::VARIABLE_BASE + 38, width),
                    },
                ],
            );
            ir.convention = crate::ir::Convention::Aapcs64;
            let demand = entry_demands(&ir, &[u64::MAX]).unwrap();
            assert_eq!(demand[&38], needed);
            assert_eq!(demand[&32], 0);
            let ssa = build(&ir).unwrap();
            verify(&ssa).unwrap();
            assert!(ssa.implicit_reads[&(0, 0)].contains(&(38, ssa.entry[&38])));
            let Stmt::Call {
                args, floats_named, ..
            } = &mut ir.blocks[0].stmts[0]
            else {
                unreachable!()
            };
            *args = None;
            *floats_named = false;
            assert_eq!(entry_demands(&ir, &[needed]).unwrap()[&38], u64::MAX);
        }
        let mut call = output_call(&[38], &[]);
        call.call_outputs_mut()[0].dest = RegRef {
            index: crate::ir::VARIABLE_BASE,
            width: 32,
        };
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                call,
                Stmt::Ret {
                    value: Expr::reg(crate::ir::VARIABLE_BASE, 64),
                },
            ],
        );
        ir.convention = crate::ir::Convention::Aapcs64;
        assert_eq!(entry_demands(&ir, &[u64::MAX]).unwrap()[&38], 0xffff_ffff);
    }

    #[test]
    fn preserved_call_output_keeps_its_producer_and_snapshots_crossed_destinations() {
        use crate::ir::eval::{self, Setup};
        let mut call = output_call(&[0, 1], &[]);
        call.call_outputs_mut()[0].dest.index = 1;
        call.call_outputs_mut()[1].dest.index = 0;
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                assign(0, Expr::Const(0x1234)),
                assign(1, Expr::Const(0xabcd)),
                call,
                Stmt::Ret {
                    value: Expr::bin(BinOp::Sub, Expr::reg(0, 64), Expr::reg(1, 64)),
                },
            ],
        );
        ir.convention = crate::ir::Convention::Aapcs64;
        let setup = Setup {
            seed: 1,
            convention: eval::Convention {
                arguments: &[],
                clobbered: &[],
            },
            registers: &[],
            memory: &[],
            step_limit: 100,
        };
        let before = eval::run(&ir, &setup);
        assert!(matches!(before, eval::Outcome::Return { value, .. } if value == 0xabcd - 0x1234));
        let ssa = build(&ir).unwrap();
        verify(&ssa).unwrap();
        assert_eq!(eval::run(&lower(&ssa), &setup), before);
        super::split_variables(&mut ir, &[0, 1]);
        assert_eq!(eval::run(&ir, &setup), before);
        crate::passes::dce::dce_flow(&mut ir);
        assert_eq!(eval::run(&ir, &setup), before);
    }

    #[test]
    fn forwarding_one_output_cannot_overwrite_an_intervening_old_value_read() {
        let named = crate::ir::VARIABLE_BASE;
        let saved = named + 1;
        let ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                output_call(&[0], &[0]),
                assign(saved, Expr::reg(named, 64)),
                assign(named, Expr::reg(0, 64)),
                Stmt::Ret {
                    value: Expr::bin(BinOp::Add, Expr::reg(named, 64), Expr::reg(saved, 64)),
                },
            ],
        );
        let mut forwarded = ir.clone();
        super::take_results_directly(&mut forwarded);
        assert_eq!(forwarded.blocks[0].stmts[0].call_outputs()[0].dest.index, 0);
        assert_eq!(forwarded.blocks[0].stmts.len(), 4);
    }

    #[test]
    fn forwarding_a_call_output_cannot_widen_its_definition() {
        use crate::ir::eval::{self, Setup};
        let first = crate::ir::VARIABLE_BASE;
        let second = first + 1;
        let mut call = output_call(&[0], &[0]);
        call.call_outputs_mut()[0].dest = RegRef {
            index: first,
            width: 32,
        };
        let ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                call,
                assign(second, Expr::reg(first, 64)),
                Stmt::Ret {
                    value: Expr::reg(second, 64),
                },
            ],
        );
        let mut forwarded = ir.clone();
        super::take_results_directly(&mut forwarded);
        assert_eq!(forwarded.blocks[0].stmts.len(), 3);
        assert_eq!(
            forwarded.blocks[0].stmts[0].call_outputs()[0].dest.width,
            32
        );
        for seed in [0, 1, 0x1234_5678] {
            let setup = Setup {
                seed,
                convention: eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &[],
                memory: &[],
                step_limit: 100,
            };
            let before = eval::run(&ir, &setup);
            assert!(matches!(before, eval::Outcome::Return { value, .. }
                if value == eval::hash(seed ^ 1, 0x2_0000) & 0xffff_ffff));
            assert_eq!(eval::run(&forwarded, &setup), before);
        }
    }

    #[test]
    fn entry_demands_distinguish_each_result_piece_and_read_width() {
        let ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![Stmt::Ret {
                value: Expr::apply(Operation::Results, vec![Expr::reg(0, 64), Expr::reg(1, 16)]),
            }],
        );
        let demand = entry_demands(&ir, &[0xffff_ffff, 0xff]).unwrap();
        assert_eq!(demand[&0], 0xffff_ffff);
        assert_eq!(demand[&1], 0xff);
        let unknown = entry_demands(&ir, &[]).unwrap();
        assert_eq!(unknown[&0], u64::MAX);
        assert_eq!(unknown[&1], 0xffff);
        assert!(entry_demands(&ir, &[u64::MAX]).is_none());
        let scalar = FunctionIr::single_block(
            Isa::X86_64,
            vec![Stmt::Ret {
                value: Expr::reg(0, 64),
            }],
        );
        assert!(entry_demands(&scalar, &[1, 1]).is_none());
    }

    #[test]
    fn entry_demands_use_floating_operand_precision_without_changing_partial_writes() {
        for (precision, expected) in [
            (Precision::Single, 0xffff_ffff),
            (Precision::Double, u64::MAX),
        ] {
            let ir = FunctionIr::single_block(
                Isa::X86_64,
                vec![Stmt::Ret {
                    value: Expr::apply(Operation::FloatNegate(precision), vec![Expr::reg(0, 64)]),
                }],
            );
            assert_eq!(entry_demands(&ir, &[u64::MAX]).unwrap()[&0], expected);
            let ssa = build(&ir).unwrap();
            assert_eq!(
                super::demanded_bits(&ssa, None, &Default::default())[&ssa.entry[&0]],
                u64::MAX
            );
        }
    }

    #[test]
    fn entry_demands_keep_raw_float_bits_and_sign_extension_distinct() {
        let ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Store {
                    addr: Expr::Const(0x1000),
                    value: Expr::reg(0, 64),
                    width: 8,
                },
                Stmt::Ret {
                    value: Expr::SignExtend {
                        value: Box::new(Expr::reg(1, 64)),
                        width: 2,
                    },
                },
            ],
        );
        let demand = entry_demands(&ir, &[u64::MAX]).unwrap();
        assert_eq!(demand[&0], u64::MAX);
        assert_eq!(demand[&1], 0xffff);
    }

    #[test]
    fn entry_demands_follow_values_across_a_narrow_overwrite() {
        let ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Store {
                    addr: Expr::Const(0x1000),
                    value: Expr::reg(0, 64),
                    width: 1,
                },
                Stmt::Assign {
                    dest: RegRef {
                        index: 0,
                        width: 32,
                    },
                    value: Expr::Const(0x1_0000_0005),
                },
                Stmt::Ret {
                    value: Expr::reg(0, 64),
                },
            ],
        );
        assert_eq!(entry_demands(&ir, &[u64::MAX]).unwrap()[&0], 0xff);
        let run = |value| {
            crate::ir::eval::run(
                &ir,
                &crate::ir::eval::Setup {
                    seed: 0,
                    convention: crate::ir::eval::Convention {
                        arguments: &[],
                        clobbered: &[],
                    },
                    registers: &[(0, value)],
                    memory: &[],
                    step_limit: 10,
                },
            )
        };
        let original = run(0x12);
        let crate::ir::eval::Outcome::Return {
            value,
            calls,
            memory,
        } = &original
        else {
            panic!("a return");
        };
        assert_eq!(*value, 5);
        assert!(calls.is_empty());
        assert_eq!(memory.get(&0x1000), Some(&0x12));
        assert_eq!(original, run(0xffff_ffff_ffff_ff12));
    }

    #[test]
    fn entry_demands_reject_unknown_effects_and_missing_jump_targets() {
        for stmt in [
            Stmt::Unsupported {
                text: "unknown".to_owned(),
                writes: Some(Vec::new()),
            },
            Stmt::Br { target: None },
            Stmt::Br {
                target: Some(0x1234),
            },
            Stmt::BrIndirect {
                target: Expr::reg(0, 64),
            },
            Stmt::BrifFlags {
                cond: Cond::Eq,
                target: 0,
            },
            Stmt::Switch {
                index: Expr::reg(0, 64),
                cases: Vec::new(),
                default: None,
            },
        ] {
            assert!(
                entry_demands(&FunctionIr::single_block(Isa::X86_64, vec![stmt]), &[]).is_none()
            );
        }
    }

    #[test]
    fn entry_demands_follow_loop_phis_without_requiring_unused_upper_bits() {
        let mut ir = FunctionIr::single_block(Isa::X86_64, vec![Stmt::Br { target: Some(0x10) }]);
        ir.blocks.push(Block {
            start: 0x10,
            stmts: vec![
                assign(0, Expr::bin(BinOp::Add, Expr::reg(0, 64), Expr::Const(1))),
                Stmt::Brif {
                    cond: Cond::Ne,
                    lhs: Expr::reg(0, 8),
                    rhs: Expr::reg(1, 8),
                    target: 0x10,
                },
            ],
        });
        ir.blocks.push(Block {
            start: 0x20,
            stmts: vec![Stmt::Ret {
                value: Expr::reg(0, 64),
            }],
        });
        let demand = entry_demands(&ir, &[0xff]).unwrap();
        assert_eq!(demand[&0], 0xff);
        assert_eq!(demand[&1], 0xff);
    }

    #[test]
    fn entry_demands_map_constant_right_shifts_and_select_arms() {
        for count in [0, 1, 63, 64, 65, 127] {
            let ir = FunctionIr::single_block(
                Isa::X86_64,
                vec![Stmt::Ret {
                    value: Expr::Select {
                        cond: Cond::Eq,
                        lhs: Box::new(Expr::reg(1, 8)),
                        rhs: Box::new(Expr::Const(0)),
                        then: Box::new(Expr::bin(BinOp::Shr, Expr::reg(0, 64), Expr::Const(count))),
                        els: Box::new(Expr::reg(2, 64)),
                    },
                }],
            );
            let demand = entry_demands(&ir, &[0xf]).unwrap();
            assert_eq!(demand[&0], 0xfu64 << (count & 63));
            assert_eq!(demand[&1], 0xff);
            assert_eq!(demand[&2], 0xf);
            let ssa = build(&ir).unwrap();
            assert_eq!(
                super::demanded_bits(&ssa, None, &Default::default())[&ssa.entry[&0]],
                u64::MAX
            );
        }
    }

    fn stack_at(offset: i64) -> Expr {
        Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const(offset as u64))
    }

    fn stack_load(offset: i64, width: u8) -> Expr {
        Expr::Load {
            addr: Box::new(stack_at(offset)),
            width,
            signed: false,
        }
    }

    fn spill_then(value: Expr) -> FunctionIr {
        FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Store {
                    addr: stack_at(-8),
                    value: Expr::reg(7, 64),
                    width: 4,
                },
                Stmt::Ret { value },
            ],
        )
    }

    #[test]
    fn entry_demands_limit_private_spills_to_read_bytes() {
        for (value, expected) in [
            (stack_load(-8, 1), 0xff),
            (stack_load(-6, 2), 0xffff_0000),
            (
                Expr::bin(BinOp::Xor, stack_load(-9, 2), stack_load(-5, 2)),
                0xff00_00ff,
            ),
            (Expr::Const(0), 0),
        ] {
            let ir = spill_then(value);
            assert_eq!(entry_demands(&ir, &[u64::MAX]).unwrap()[&7], expected);
            let ssa = build(&ir).unwrap();
            assert_eq!(
                super::demanded_bits(&ssa, None, &Default::default())[&ssa.entry[&7]],
                0xffff_ffff
            );
        }
        let mut incoming = spill_then(stack_load(8, 1));
        if let Stmt::Store { addr, .. } = &mut incoming.blocks[0].stmts[0] {
            *addr = stack_at(8);
        }
        assert_eq!(
            entry_demands(&incoming, &[u64::MAX]).unwrap()[&7],
            0xffff_ffff
        );
    }

    #[test]
    fn entry_demands_match_spill_positions_across_frames_and_blocks() {
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                assign(4, stack_at(-16)),
                Stmt::Store {
                    addr: stack_at(8),
                    value: Expr::reg(7, 64),
                    width: 4,
                },
                Stmt::Store {
                    addr: stack_at(12),
                    value: Expr::reg(6, 64),
                    width: 4,
                },
                Stmt::Br { target: Some(0x10) },
            ],
        );
        ir.blocks.push(Block {
            start: 0x10,
            stmts: vec![
                assign(4, stack_at(16)),
                Stmt::Ret {
                    value: Expr::bin(BinOp::Or, stack_load(-7, 1), stack_load(-2, 1)),
                },
            ],
        });
        let ssa = build(&ir).unwrap();
        for (original, renamed) in ir.blocks.iter().zip(&ssa.ir.blocks) {
            assert_eq!(original.stmts.len(), renamed.stmts.len());
            for (original, renamed) in original.stmts.iter().zip(&renamed.stmts) {
                assert_eq!(
                    std::mem::discriminant(original),
                    std::mem::discriminant(renamed)
                );
            }
        }
        let demand = entry_demands(&ir, &[u64::MAX]).unwrap();
        assert_eq!(demand[&7], 0xff00);
        assert_eq!(demand[&6], 0xff_0000);
    }

    #[test]
    fn entry_demands_keep_spills_whole_when_stack_addresses_are_unproven() {
        let load = |addr| Expr::Load {
            addr: Box::new(addr),
            width: 1,
            signed: false,
        };
        for value in [
            load(Expr::reg(8, 64)),
            load(Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::reg(8, 64))),
            load(Expr::bin(
                BinOp::Add,
                Expr::reg(4, 32),
                Expr::Const((-8i64) as u64),
            )),
            stack_load(i64::MAX, 1),
        ] {
            let ir = spill_then(value);
            assert_eq!(entry_demands(&ir, &[u64::MAX]).unwrap()[&7], 0xffff_ffff);
        }
        let mut escaped = spill_then(stack_load(-8, 1));
        escaped.blocks[0].stmts.insert(1, assign(8, stack_at(-8)));
        assert_eq!(
            entry_demands(&escaped, &[u64::MAX]).unwrap()[&7],
            0xffff_ffff
        );
        for value in [
            Expr::bin(BinOp::Sub, Expr::reg(4, 64), Expr::Const(i64::MIN as u64)),
            Expr::reg(8, 64),
        ] {
            let mut ir = spill_then(stack_load(-8, 1));
            ir.blocks[0].stmts.insert(0, assign(4, value));
            assert_eq!(entry_demands(&ir, &[u64::MAX]).unwrap()[&7], 0xffff_ffff);
        }
    }

    #[test]
    fn entry_demands_keep_external_stores_and_unknown_frames_whole() {
        let mut external = spill_then(stack_load(-8, 1));
        external.blocks[0].stmts.insert(
            1,
            Stmt::Store {
                addr: Expr::reg(8, 64),
                value: Expr::reg(6, 64),
                width: 8,
            },
        );
        let demand = entry_demands(&external, &[u64::MAX]).unwrap();
        assert_eq!(demand[&7], 0xffff_ffff);
        assert_eq!(demand[&6], u64::MAX);
        let mut ir = spill_then(stack_load(-8, 1));
        ir.blocks[0].stmts[1] = Stmt::Brif {
            cond: Cond::Eq,
            lhs: Expr::reg(8, 64),
            rhs: Expr::Const(0),
            target: 0x20,
        };
        ir.blocks.push(Block {
            start: 0x10,
            stmts: vec![assign(4, stack_at(-16)), Stmt::Br { target: Some(0x20) }],
        });
        ir.blocks.push(Block {
            start: 0x20,
            stmts: vec![Stmt::Ret {
                value: stack_load(-8, 1),
            }],
        });
        assert_eq!(entry_demands(&ir, &[u64::MAX]).unwrap()[&7], 0xffff_ffff);
    }

    #[test]
    fn entry_demands_keep_load_addresses_observable_in_unread_private_stores() {
        let mut ir = spill_then(Expr::Const(0));
        if let Stmt::Store { value, .. } = &mut ir.blocks[0].stmts[0] {
            *value = stack_load(-16, 1);
        }
        assert_eq!(entry_demands(&ir, &[u64::MAX]).unwrap()[&4], u64::MAX);
    }

    #[test]
    fn entry_demands_keep_stores_outside_private_stack_memory_observable() {
        let span = crate::ir::eval::STACK_SPAN as i64;
        for (offset, width, expected) in [
            (-span, 4, 0xff),
            (-span - 4, 4, 0xffff_ffff),
            (-span - 2, 4, 0xffff_ffff),
            (-4, 8, u64::MAX),
        ] {
            let ir = FunctionIr::single_block(
                Isa::X86_64,
                vec![
                    Stmt::Store {
                        addr: stack_at(offset),
                        value: Expr::reg(7, 64),
                        width,
                    },
                    Stmt::Ret {
                        value: stack_load(offset, 1),
                    },
                ],
            );
            assert_eq!(entry_demands(&ir, &[0xff]).unwrap()[&7], expected);
        }
        let ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Store {
                    addr: stack_at(-2 * span),
                    value: Expr::reg(7, 64),
                    width: 8,
                },
                Stmt::Ret {
                    value: Expr::reg(7, 8),
                },
            ],
        );
        assert_eq!(entry_demands(&ir, &[0xff]).unwrap()[&7], u64::MAX);
        let run = |value| {
            crate::ir::eval::run(
                &ir,
                &crate::ir::eval::Setup {
                    seed: 0,
                    convention: crate::ir::eval::Convention {
                        arguments: &[],
                        clobbered: &[],
                    },
                    registers: &[(7, value)],
                    memory: &[],
                    step_limit: 10,
                },
            )
        };
        let first = run(0x12);
        let second = run(0xffff_ffff_ffff_ff12);
        let (
            crate::ir::eval::Outcome::Return {
                value: left,
                memory: before,
                ..
            },
            crate::ir::eval::Outcome::Return {
                value: right,
                memory: after,
                ..
            },
        ) = (&first, &second)
        else {
            panic!("two returns")
        };
        assert_eq!(left, right);
        assert_ne!(before, after);
    }

    #[test]
    fn entry_demands_keep_private_spills_whole_across_calls() {
        let mut ir = spill_then(stack_load(-8, 1));
        ir.blocks[0].stmts.insert(
            1,
            Stmt::Call {
                target: Some(1),
                through: None,
                convention: crate::ir::Convention::SysV,
                args: Some(Vec::new()),
                floats_named: true,
                outputs: crate::ir::fallback_call_outputs(crate::ir::Convention::SysV, None),
                clobbers: None,
                via: None,
            },
        );
        assert_eq!(entry_demands(&ir, &[u64::MAX]).unwrap()[&7], 0xffff_ffff);
    }

    /// `call; mov cl, 1; mov eax, ecx; ret` with the callee changing what
    /// `clobbers` says.
    fn byte_after_call(clobbers: Option<crate::ir::Registers>) -> FunctionIr {
        const RCX: u16 = 1;
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Call {
                    target: Some(0x2000),
                    through: None,
                    convention: crate::ir::Convention::SysV,
                    args: Some(Vec::new()),
                    floats_named: false,
                    outputs: crate::ir::fallback_call_outputs(
                        crate::ir::Convention::SysV,
                        clobbers,
                    ),
                    clobbers,
                    via: None,
                },
                assign(
                    RCX,
                    Expr::bin(
                        BinOp::Or,
                        Expr::bin(BinOp::And, Expr::reg(RCX, 64), Expr::Const(!0xff)),
                        Expr::Const(1),
                    ),
                ),
                Stmt::Ret {
                    value: Expr::reg(RCX, 64),
                },
            ],
        );
        super::undefine_clobbered_reads(&mut ir);
        crate::passes::simplify::simplify(&mut ir);
        ir
    }

    #[test]
    fn a_partial_write_over_a_register_a_call_destroyed_is_the_new_bits() {
        let ir = byte_after_call(None);
        assert!(matches!(
            &ir.blocks[0].stmts[1],
            Stmt::Assign {
                value: Expr::Const(1),
                ..
            }
        ));
    }

    #[test]
    fn a_register_the_callee_keeps_holds_its_earlier_value() {
        let ir = byte_after_call(Some(crate::ir::Registers::default()));
        let Stmt::Assign { value, .. } = &ir.blocks[0].stmts[1] else {
            panic!("an assignment");
        };
        let mut read = std::collections::HashSet::new();
        crate::ir::visit::collect_reads(value, &mut read);
        assert!(read.contains(&1));
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
    fn a_result_only_moved_on_goes_to_its_variable() {
        let (first, second) = (crate::ir::VARIABLE_BASE, crate::ir::VARIABLE_BASE + 1);
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Call {
                    target: Some(0x1000),
                    through: None,
                    convention: crate::ir::Convention::GoAbi0,
                    args: Some(Vec::new()),
                    floats_named: false,
                    clobbers: None,
                    outputs: crate::ir::fallback_call_outputs(crate::ir::Convention::GoAbi0, None),
                    via: None,
                },
                assign(first, Expr::reg(0, 64)),
                assign(second, Expr::reg(first, 64)),
                Stmt::Ret {
                    value: Expr::reg(second, 64),
                },
            ],
        );
        super::take_results_directly(&mut ir);
        assert_eq!(ir.blocks[0].stmts.len(), 2);
        assert_eq!(
            ir.blocks[0].stmts[0]
                .primary_call_output()
                .unwrap()
                .dest
                .index,
            second
        );
    }

    #[test]
    fn further_results_moved_on_go_to_their_variables() {
        // v1 = f(); v3 = rbx; v2 = v1; v4 = v3; return v2 + v4;
        let [first, second, third, fourth] =
            [0, 1, 2, 3].map(|offset| crate::ir::VARIABLE_BASE + offset);
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Call {
                    target: Some(0x1000),
                    through: None,
                    convention: crate::ir::Convention::GoAmd64,
                    args: Some(Vec::new()),
                    floats_named: false,
                    clobbers: None,
                    outputs: crate::ir::fallback_call_outputs(crate::ir::Convention::GoAmd64, None),
                    via: None,
                },
                assign(first, Expr::reg(0, 64)),
                assign(third, Expr::reg(3, 64)),
                assign(second, Expr::reg(first, 64)),
                assign(fourth, Expr::reg(third, 64)),
                Stmt::Ret {
                    value: Expr::bin(BinOp::Add, Expr::reg(second, 64), Expr::reg(fourth, 64)),
                },
            ],
        );
        super::take_results_directly(&mut ir);
        let stmts = &ir.blocks[0].stmts;
        assert_eq!(stmts.len(), 2, "{}", ir.render());
        assert_eq!(stmts[0].primary_call_output().unwrap().dest.index, second);
        assert_eq!(
            stmts[0]
                .call_outputs()
                .iter()
                .find(|output| output.register == 3)
                .unwrap()
                .dest
                .index,
            fourth
        );
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
    fn a_loop_back_to_the_entry_joins_the_entry_value() {
        // 0: if (rdi == 0) return rax; 1: rax = rax + 1; goto 0
        let rax = Expr::reg(0, 64);
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![Stmt::Brif {
                cond: Cond::Eq,
                lhs: Expr::reg(7, 64),
                rhs: Expr::Const(0),
                target: 0x20,
            }],
        );
        ir.blocks.push(Block {
            start: 0x10,
            stmts: vec![
                assign(0, Expr::bin(BinOp::Add, rax.clone(), Expr::Const(1))),
                Stmt::Br { target: Some(0) },
            ],
        });
        ir.blocks.push(Block {
            start: 0x20,
            stmts: vec![Stmt::Ret { value: rax }],
        });
        let ssa = build(&ir).expect("builds");
        verify(&ssa).expect("well formed");
        let phi = ssa.phis[0].first().expect("a φ at the entry");
        assert_eq!(
            phi.args[0], ssa.entry[&0],
            "the call brings the entry value"
        );
    }

    #[test]
    fn a_partial_write_only_its_low_byte_is_read_of_drops_the_rest() {
        // r11b = 4; store8(r11): the bits r11 kept are never read.
        let keep = Expr::bin(BinOp::And, Expr::reg(11, 64), Expr::Const(!0xff));
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                assign(11, Expr::bin(BinOp::Or, keep.clone(), Expr::Const(4))),
                Stmt::Store {
                    addr: Expr::reg(7, 64),
                    value: Expr::reg(11, 64),
                    width: 1,
                },
                Stmt::Ret {
                    value: Expr::reg(0, 64),
                },
            ],
        );
        super::narrow_partial_writes(&mut ir);
        assert!(
            matches!(
                &ir.blocks[0].stmts[0],
                Stmt::Assign {
                    value: Expr::Const(4),
                    ..
                }
            ),
            "{}",
            ir.render()
        );
        // Returned whole, the kept bits stay.
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                assign(
                    0,
                    Expr::bin(
                        BinOp::Or,
                        Expr::bin(BinOp::And, Expr::reg(0, 64), Expr::Const(!0xff)),
                        Expr::Const(4),
                    ),
                ),
                Stmt::Ret {
                    value: Expr::reg(0, 64),
                },
            ],
        );
        super::narrow_partial_writes(&mut ir);
        assert!(
            !matches!(
                &ir.blocks[0].stmts[0],
                Stmt::Assign {
                    value: Expr::Const(4),
                    ..
                }
            ),
            "{}",
            ir.render()
        );
    }

    #[test]
    fn lowering_gives_every_value_its_register_back() {
        let ir = counting_loop();
        let ssa = build(&ir).expect("builds");
        assert_ne!(ssa.ir.render(), ir.render());
        assert_eq!(lower(&ssa).render(), ir.render());
    }
}

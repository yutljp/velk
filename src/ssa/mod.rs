//! The SSA layer. Every definition of a register becomes a value of its own,
//! a register index from `VALUE_BASE` up, so the expression types, the
//! interpreter and the simplifier work on it unchanged. Where control flow
//! joins different definitions, a φ at the block's start picks the one the
//! path came by. Reads and writes a statement makes without naming them,
//! such as a call's arguments and the registers it clobbers, are kept beside
//! the statements.

mod demand;
mod split;
mod variadic;

#[cfg(test)]
use demand::demanded_bits;
pub(crate) use demand::entry_demands;
pub use demand::narrow_partial_writes;
pub(crate) use split::split_render_variables;
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
    #[must_use]
    pub fn register_of(&self, value: u16) -> u16 {
        self.origin[usize::from(value - VALUE_BASE)]
    }

    #[must_use]
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
    for operand in stmt.operands() {
        named(operand, &mut out);
    }
    out
}

/// Renames each register an expression reads by `rename`, keeping widths.
fn rename_expr(expr: &mut Expr, rename: &mut dyn FnMut(u16) -> u16) {
    if let Expr::Reg { index, .. } = expr {
        *index = rename(*index);
    } else {
        for child in crate::ir::visit::children_mut(expr) {
            rename_expr(child, rename);
        }
    }
}

/// Renames the registers a statement reads, not the one it assigns.
fn rename_reads(stmt: &mut Stmt, rename: &mut dyn FnMut(u16) -> u16) {
    for operand in stmt.operands_mut() {
        rename_expr(operand, rename);
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
///
/// # Panics
///
/// Panics if a renamed definition has no register stack to unwind.
#[must_use]
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
    let mut predecessors = dom::predecessors(&successors);
    if count > 0 {
        predecessors[0].insert(0, ENTRY);
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
                        sources.extend_from_slice(stmt.declared_call_reads());
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
    if ir.isa == crate::loader::Isa::I386 {
        variadic::count_i386(ir, image);
        return;
    }
    let variadic = |target: u64| {
        let Some(name) = image
            .functions
            .get(&target)
            .and_then(|function| function.name.as_deref())
        else {
            return None;
        };
        let Some(prototype) = crate::analysis::prototypes::for_image(name, image) else {
            return None;
        };
        if prototype.format.is_none() {
            return None;
        }
        Some(prototype)
    };
    let pending = ir.blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
        !stmt.has_declared_call()
            && matches!(stmt, Stmt::Call { target: Some(target), args: None, .. } if variadic(*target).is_some())
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
            if stmt.has_declared_call() {
                continue;
            }
            let Stmt::Call {
                kind,
                target: Some(target),
                args: args @ None,
                convention,
                ..
            } = stmt
            else {
                continue;
            };
            let Some(prototype) = variadic(*target) else {
                continue;
            };
            let fixed = prototype.fixed();
            let Some(format) = prototype.format else {
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
            if image.isa == crate::loader::Isa::AArch64
                && image.format == crate::loader::Format::MachO
            {
                // Apple places unnamed arguments in eight-byte stack slots, even
                // when unused integer argument registers remain.
                let conversions =
                    crate::analysis::prototypes::all_conversion_types(&format, prototype.scans);
                if prototype.floats() != 0
                    || fixed > registers.len()
                    || conversions.iter().any(|ty| {
                        !ty.is_pointer() && ty.integer().is_none_or(|(bits, _)| bits > 64)
                    })
                {
                    continue;
                }
                *args = crate::lift::arguments(
                    *kind,
                    *convention,
                    ir.isa,
                    Some(fixed),
                    conversions.len(),
                );
                if let Some(args) = args {
                    for (value, ty) in args.iter_mut().skip(fixed).zip(&conversions) {
                        if let Expr::Load { width, signed, .. } = value
                            && let Some((bits, is_signed)) = ty.integer()
                        {
                            *width = (bits / 8) as u8;
                            *signed = is_signed;
                        }
                    }
                }
                continue;
            }
            let count = fixed.saturating_add(
                crate::analysis::prototypes::conversion_types(&format, prototype.scans).len(),
            );
            // The rest are read from the stack, where the call finds them.
            *args = crate::lift::arguments(
                *kind,
                *convention,
                ir.isa,
                Some(count),
                count.saturating_sub(registers.len()),
            );
        }
    }
}

/// The text at `address`, up to a NUL byte or 256 bytes within its section.
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
#[must_use]
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
mod tests;

//! The SSA layer. Every definition of a register becomes a value of its own,
//! a register index from `VALUE_BASE` up, so the expression types, the
//! interpreter and the simplifier work on it unchanged. Where control flow
//! joins different definitions, a φ at the block's start picks the one the
//! path came by. Reads and writes a statement makes without naming them,
//! such as a call's arguments and the registers it clobbers, are kept beside
//! the statements.

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
                    Stmt::Call { .. } => stmt.unnamed_call_reads(),
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
                    match stmt {
                        Stmt::Assign { dest, .. } if dest.index == register => dest.index = value,
                        Stmt::Call {
                            result: Some(dest), ..
                        } if dest.index == register => dest.index = value,
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
        let Stmt::Call { convention, .. } = &ssa.ir.blocks[block].stmts[position] else {
            continue;
        };
        let results = convention.results();
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

/// The bits of each value its reads look at, given the bits each use needs:
/// a store needs its width, a mask its bits, and the low bits of a sum, a
/// product or a bitwise operation need only the operands' bits up to the
/// highest one needed. Anything else needs every bit.
fn demanded_bits(
    ssa: &Ssa,
    returns: Option<&[u64]>,
    stores: &HashMap<(usize, usize), u64>,
) -> HashMap<u16, u64> {
    use crate::ir::BinOp;
    use crate::ir::semantics::mask;
    fn up_to_highest(bits: u64) -> u64 {
        if bits == 0 {
            0
        } else {
            mask(64 - bits.leading_zeros())
        }
    }
    fn walk(expr: &Expr, needed: u64, demand: &mut HashMap<u16, u64>, precise: bool) {
        match expr {
            Expr::Reg { index, width } => {
                *demand.entry(*index).or_insert(0) |= needed & mask(u32::from(*width));
            }
            Expr::Const(_) => {}
            Expr::Bin { op, lhs, rhs } => match op {
                BinOp::And => {
                    let (left, right) = match (lhs.as_ref(), rhs.as_ref()) {
                        (_, Expr::Const(m)) => (needed & m, 0),
                        (Expr::Const(m), _) => (0, needed & m),
                        _ => (needed, needed),
                    };
                    walk(lhs, left, demand, precise);
                    walk(rhs, right, demand, precise);
                }
                BinOp::Or | BinOp::Xor => {
                    walk(lhs, needed, demand, precise);
                    walk(rhs, needed, demand, precise);
                }
                BinOp::Shr if precise && matches!(rhs.as_ref(), Expr::Const(_)) => {
                    let Expr::Const(count) = rhs.as_ref() else {
                        unreachable!()
                    };
                    walk(lhs, needed << (count & 63), demand, precise);
                }
                BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Shl => {
                    let low = up_to_highest(needed);
                    walk(lhs, low, demand, precise);
                    // A shift amount is needed whole.
                    walk(
                        rhs,
                        if *op == BinOp::Shl { u64::MAX } else { low },
                        demand,
                        precise,
                    );
                }
                _ => {
                    walk(lhs, u64::MAX, demand, precise);
                    walk(rhs, u64::MAX, demand, precise);
                }
            },
            Expr::SignExtend { value, width } if precise => {
                walk(value, mask(u32::from(*width) * 8), demand, precise);
            }
            Expr::Select {
                lhs,
                rhs,
                then,
                els,
                ..
            } if precise => {
                walk(lhs, u64::MAX, demand, precise);
                walk(rhs, u64::MAX, demand, precise);
                walk(then, needed, demand, precise);
                walk(els, needed, demand, precise);
            }
            Expr::Apply { op, args } if precise && op.argument_precision().is_some() => {
                let bits = op.argument_precision().expect("a floating operand").bits();
                for arg in args {
                    walk(arg, mask(u32::from(bits)), demand, precise);
                }
            }
            _ => {
                for child in crate::ir::visit::children(expr) {
                    walk(child, u64::MAX, demand, precise);
                }
            }
        }
    }
    // What an assignment or a φ needs of its operands is what its own uses
    // need of it, so the needs flow back from the uses until they settle.
    let precise = returns.is_some();
    let mut demand: HashMap<u16, u64> = HashMap::new();
    loop {
        let mut next: HashMap<u16, u64> = HashMap::new();
        for (position, stmt) in ssa.ir.blocks.iter().enumerate().flat_map(|(block, body)| {
            body.stmts
                .iter()
                .enumerate()
                .map(move |(at, stmt)| ((block, at), stmt))
        }) {
            match stmt {
                Stmt::Store { addr, value, width } => {
                    walk(addr, u64::MAX, &mut next, precise);
                    let needed = stores
                        .get(&position)
                        .copied()
                        .unwrap_or_else(|| mask(u32::from(*width) * 8));
                    walk(value, needed, &mut next, precise);
                }
                Stmt::Assign { dest, value } => {
                    let needed = demand.get(&dest.index).copied().unwrap_or(0);
                    walk(
                        value,
                        needed & mask(u32::from(dest.width)),
                        &mut next,
                        precise,
                    );
                }
                Stmt::Ret { value } if returns.is_some_and(|masks| !masks.is_empty()) => {
                    let values = match value {
                        Expr::Apply {
                            op: crate::ir::Operation::Results,
                            args,
                        } => args.as_slice(),
                        value => std::slice::from_ref(value),
                    };
                    for (value, needed) in values.iter().zip(returns.expect("return masks")) {
                        walk(value, *needed, &mut next, precise);
                    }
                }
                other => {
                    for expr in other.operands() {
                        walk(expr, u64::MAX, &mut next, precise);
                    }
                }
            }
        }
        for phi in ssa.phis.iter().flatten() {
            let needed = demand.get(&phi.value).copied().unwrap_or(0);
            for arg in &phi.args {
                *next.entry(*arg).or_insert(0) |= needed;
            }
        }
        for (_, value) in ssa.implicit_reads.values().flatten() {
            next.insert(*value, u64::MAX);
        }
        if next == demand {
            return demand;
        }
        demand = next;
    }
}

fn private_store_demands(ir: &FunctionIr) -> Option<HashMap<(usize, usize), u64>> {
    use crate::ir::BinOp;
    let sp = crate::arch::stack_pointer(ir.isa);
    if crate::passes::memory::frame_address_escapes(ir, sp)
        || ir
            .blocks
            .iter()
            .flat_map(|block| &block.stmts)
            .any(|stmt| matches!(stmt, Stmt::Call { .. } | Stmt::Unsupported { .. }))
    {
        return None;
    }
    fn slot(addr: &Expr, frame: i64, sp: u16) -> Option<i64> {
        let register = |expr: &Expr| matches!(expr, Expr::Reg { index, width: 64 } if *index == sp);
        let delta = match addr {
            value if register(value) => 0,
            Expr::Bin {
                op: BinOp::Add,
                lhs,
                rhs,
            } => match (lhs.as_ref(), rhs.as_ref()) {
                (base, Expr::Const(delta)) | (Expr::Const(delta), base) if register(base) => {
                    i128::from(*delta as i64)
                }
                _ => return None,
            },
            Expr::Bin {
                op: BinOp::Sub,
                lhs,
                rhs,
            } if register(lhs) => {
                let Expr::Const(delta) = rhs.as_ref() else {
                    return None;
                };
                -i128::from(*delta as i64)
            }
            _ => return None,
        };
        i64::try_from(i128::from(frame) + delta).ok()
    }
    fn range(addr: &Expr, width: u8, frame: i64, sp: u16) -> Option<(i64, i64)> {
        if !(1..=8).contains(&width) {
            return None;
        }
        let start = slot(addr, frame, sp)?;
        Some((start, start.checked_add(i64::from(width))?))
    }
    fn loads(expr: &Expr, frame: i64, sp: u16, read: &mut Vec<(i64, i64)>) -> Option<()> {
        if let Expr::Load { addr, width, .. } = expr {
            read.push(range(addr, *width, frame, sp)?);
        }
        for child in crate::ir::visit::children(expr) {
            loads(child, frame, sp, read)?;
        }
        Some(())
    }
    let frames = crate::passes::frame_slots::block_frames(ir, sp);
    let mut read = Vec::new();
    let mut stores = Vec::new();
    for (block, body) in ir.blocks.iter().enumerate() {
        let mut frame = frames[block]?;
        for (at, stmt) in body.stmts.iter().enumerate() {
            if let Stmt::Assign { dest, value } = stmt
                && dest.index == sp
            {
                if dest.width != 64 {
                    return None;
                }
                frame = slot(value, frame, sp)?;
                continue;
            }
            if let Stmt::Store { addr, width, .. } = stmt {
                let (start, end) = range(addr, *width, frame, sp)?;
                if start >= -(crate::ir::eval::STACK_SPAN as i64) && end <= 0 {
                    stores.push(((block, at), start, end));
                }
            }
            for operand in stmt.operands() {
                loads(operand, frame, sp, &mut read)?;
            }
        }
        for successor in crate::ir::cfg::block_successors(&ir.blocks, block) {
            if frames[successor] != Some(frame) {
                return None;
            }
        }
    }
    Some(
        stores
            .into_iter()
            .map(|(position, start, end)| {
                let mut bits = 0;
                for byte in start..end {
                    if read.iter().any(|(from, to)| *from <= byte && byte < *to) {
                        bits |= 0xffu64 << ((byte - start) * 8);
                    }
                }
                (position, bits)
            })
            .collect(),
    )
}

/// The entry-register bits observed by effects and the requested result pieces.
/// An empty result mask list keeps every returned bit observable.
pub(crate) fn entry_demands(ir: &FunctionIr, returns: &[u64]) -> Option<HashMap<u16, u64>> {
    if ir.blocks.is_empty() {
        return None;
    }
    let starts: HashSet<_> = ir.blocks.iter().map(|block| block.start).collect();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        match stmt {
            Stmt::Unsupported { .. }
            | Stmt::BrIndirect { .. }
            | Stmt::BrifFlags { .. }
            | Stmt::Br { target: None } => return None,
            Stmt::Br {
                target: Some(target),
            }
            | Stmt::Brif { target, .. }
                if !starts.contains(target) =>
            {
                return None;
            }
            Stmt::Switch { cases, default, .. }
                if default.is_none()
                    || cases.iter().any(|(_, target)| !starts.contains(target))
                    || default.is_some_and(|target| !starts.contains(&target)) =>
            {
                return None;
            }
            Stmt::Ret { value } if !returns.is_empty() => {
                let count = match value {
                    Expr::Apply {
                        op: crate::ir::Operation::Results,
                        args,
                    } => args.len(),
                    _ => 1,
                };
                if count != returns.len() {
                    return None;
                }
            }
            _ => {}
        }
    }
    let stores = private_store_demands(ir).unwrap_or_default();
    let ssa = build(ir)?;
    let demand = demanded_bits(&ssa, Some(returns), &stores);
    Some(
        ssa.entry
            .iter()
            .map(|(register, value)| (*register, demand.get(value).copied().unwrap_or(0)))
            .collect(),
    )
}

/// A partial write keeps the register's other bits: `v = (r & ~m) | x`.
/// When no read of `v` looks at the kept bits, they never matter and the
/// write is just `v = x`.
pub fn narrow_partial_writes(ir: &mut FunctionIr) {
    // An unmodeled instruction or an unknown jump may read any bit.
    if ir.blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
        matches!(
            stmt,
            Stmt::Unsupported { .. } | Stmt::BrIndirect { .. } | Stmt::Br { target: None }
        )
    }) {
        return;
    }
    let Some(mut ssa) = build(ir) else {
        return;
    };
    let demand = demanded_bits(&ssa, None, &HashMap::new());
    let mut changed = false;
    for stmt in ssa.ir.blocks.iter_mut().flat_map(|block| &mut block.stmts) {
        let Stmt::Assign { dest, value } = stmt else {
            continue;
        };
        let Expr::Bin {
            op: crate::ir::BinOp::Or,
            lhs,
            rhs,
        } = value
        else {
            continue;
        };
        let kept = |expr: &Expr| match expr {
            Expr::Bin {
                op: crate::ir::BinOp::And,
                lhs,
                rhs,
            } if matches!(lhs.as_ref(), Expr::Reg { .. }) => match rhs.as_ref() {
                Expr::Const(keep) => Some(*keep),
                _ => None,
            },
            _ => None,
        };
        let (keep, written) = match (kept(lhs), kept(rhs)) {
            (Some(keep), _) => (keep, rhs.as_ref().clone()),
            (None, Some(keep)) => (keep, lhs.as_ref().clone()),
            _ => continue,
        };
        if demand.get(&dest.index).copied().unwrap_or(0) & keep == 0 {
            *value = written;
            changed = true;
        }
    }
    if changed {
        *ir = lower(&ssa);
    }
}

/// Leaves SSA form by giving every value its register back. Correct as long
/// as each value's register still holds it wherever it is read, as it does
/// after transformations that only rewrite reads into equal expressions.
pub fn lower(ssa: &Ssa) -> FunctionIr {
    lower_with(ssa, &HashMap::new())
}

/// The values joined through φs: each set is one variable of the program.
/// A φ whose value nothing in `needed` reads joins nothing.
fn congruence_classes(ssa: &Ssa, needed: &HashSet<u16>) -> Vec<usize> {
    let mut parent: Vec<usize> = (0..ssa.origin.len()).collect();
    fn find(parent: &mut [usize], mut index: usize) -> usize {
        while parent[index] != index {
            parent[index] = parent[parent[index]];
            index = parent[index];
        }
        index
    }
    for phi in ssa.phis.iter().flatten() {
        if !needed.contains(&phi.value) {
            continue;
        }
        let value = usize::from(phi.value - VALUE_BASE);
        for arg in &phi.args {
            let (a, b) = (
                find(&mut parent, value),
                find(&mut parent, usize::from(arg - VALUE_BASE)),
            );
            parent[a] = b;
        }
    }
    (0..parent.len())
        .map(|index| find(&mut parent, index))
        .collect()
}

/// The values of vector register halves that hold vector data rather than
/// a scalar float: a half loaded together with the other one from the next
/// eight bytes, one an integer lane operation reads or gives, an integer
/// sum or product, and one computed from those without floating-point
/// arithmetic.
fn vector_values(ssa: &Ssa) -> HashSet<u16> {
    let isa = ssa.ir.isa;
    let half = |value: u16| {
        Ssa::is_value(value) && crate::arch::vector_half(isa, ssa.register_of(value)).is_some()
    };
    let mut vectors = HashSet::new();
    let mut derived: Vec<(u16, HashSet<u16>)> = Vec::new();
    for block in &ssa.ir.blocks {
        for (position, stmt) in block.stmts.iter().enumerate() {
            if let Stmt::Assign { dest, value } = stmt
                && half(dest.index)
            {
                let mut lanes = false;
                let mut float = false;
                lane_operands(value, &mut lanes, &mut float, &mut vectors, &half);
                // Integer sums and products of halves are lane arithmetic too.
                if let Expr::Bin {
                    op: crate::ir::BinOp::Add | crate::ir::BinOp::Sub | crate::ir::BinOp::Mul,
                    lhs,
                    rhs,
                } = value
                {
                    lanes = true;
                    for operand in [lhs, rhs] {
                        if let Expr::Reg { index, .. } = operand.as_ref()
                            && half(*index)
                        {
                            vectors.insert(*index);
                        }
                    }
                }
                if lanes && !float {
                    vectors.insert(dest.index);
                }
                let expected = match crate::arch::vector_half(isa, ssa.register_of(dest.index)) {
                    Some(true) => -8,
                    _ => 8,
                };
                if let Expr::Load { addr, width: 8, .. } = value
                    && let Some(other) = [position.checked_sub(1), Some(position + 1)]
                        .into_iter()
                        .flatten()
                        .find_map(|at| match block.stmts.get(at) {
                            Some(Stmt::Assign {
                                dest: other,
                                value:
                                    Expr::Load {
                                        addr: other_addr,
                                        width: 8,
                                        ..
                                    },
                            }) if half(other.index)
                                && ssa.register_of(other.index) ^ 1
                                    == ssa.register_of(dest.index)
                                && apart(addr, other_addr) == Some(expected) =>
                            {
                                Some(other.index)
                            }
                            _ => None,
                        })
                {
                    vectors.insert(dest.index);
                    vectors.insert(other);
                }
                if !float {
                    let mut reads = HashSet::new();
                    named(value, &mut reads);
                    derived.push((dest.index, reads));
                }
            }
        }
    }
    let phis: Vec<&Phi> = ssa.phis.iter().flatten().collect();
    loop {
        let before = vectors.len();
        for (value, reads) in &derived {
            if reads.iter().any(|read| vectors.contains(read)) {
                vectors.insert(*value);
            }
        }
        for phi in &phis {
            if half(phi.value) && phi.args.iter().any(|arg| vectors.contains(arg)) {
                vectors.insert(phi.value);
            }
        }
        if vectors.len() == before {
            return vectors;
        }
    }
}

/// Notes whether `expr` holds an integer lane operation or floating-point
/// arithmetic, adding the vector halves a lane operation reads to `vectors`.
fn lane_operands(
    expr: &Expr,
    lanes: &mut bool,
    float: &mut bool,
    vectors: &mut HashSet<u16>,
    half: &dyn Fn(u16) -> bool,
) {
    use crate::ir::Operation;
    if let Expr::Apply { op, args } = expr {
        match op {
            Operation::Lanes(..)
            | Operation::InterleaveLow(_)
            | Operation::InterleaveHigh(_)
            | Operation::SignBits(_)
            | Operation::SumLanes(_)
            | Operation::Pack { .. }
            | Operation::MultiplyAddPairs
            | Operation::SumAbsoluteDifferences
            | Operation::SumLanesLong { .. } => {
                *lanes = true;
                for arg in args {
                    if let Expr::Reg { index, .. } = arg
                        && half(*index)
                    {
                        vectors.insert(*index);
                    }
                }
            }
            Operation::FloatAdd(_)
            | Operation::FloatSub(_)
            | Operation::FloatMul(_)
            | Operation::FloatDiv(_)
            | Operation::FloatSqrt(_)
            | Operation::FloatNegate(_)
            | Operation::FloatAbs(_)
            | Operation::FloatMulAdd(_)
            | Operation::FloatEqual(_)
            | Operation::FloatLess(_)
            | Operation::FloatLessEqual(_)
            | Operation::FloatUnordered(_)
            | Operation::IntToFloat { .. }
            | Operation::FloatToInt { .. }
            | Operation::FloatRound(..)
            | Operation::FloatConvert { .. } => *float = true,
            _ => {}
        }
    }
    for child in crate::ir::visit::children(expr) {
        lane_operands(child, lanes, float, vectors, half);
    }
}

/// How many bytes `high` lies past `low`, when both are the same base plus
/// constants.
fn apart(low: &Expr, high: &Expr) -> Option<i64> {
    fn split(addr: &Expr) -> (Option<&Expr>, i64) {
        match addr {
            Expr::Const(offset) => (None, *offset as i64),
            Expr::Bin {
                op: crate::ir::BinOp::Add,
                lhs,
                rhs,
            } => match rhs.as_ref() {
                Expr::Const(offset) => (Some(lhs), *offset as i64),
                _ => (Some(addr), 0),
            },
            _ => (Some(addr), 0),
        }
    }
    let (low_base, low_offset) = split(low);
    let (high_base, high_offset) = split(high);
    (low_base == high_base).then(|| high_offset.wrapping_sub(low_offset))
}

/// Gives each variable a register of `registers` holds once the value it
/// held on entry is dead a name of its own, from `VARIABLE_BASE` up. The
/// variable holding the entry value keeps the register, and so does one a
/// call reads or writes without naming it.
pub fn split_variables(ir: &mut FunctionIr, registers: &[u16]) {
    // An unknown successor could read any register.
    if ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .any(|stmt| matches!(stmt, Stmt::BrIndirect { .. } | Stmt::Br { target: None }))
    {
        return;
    }
    let Some(ssa) = build(ir) else {
        return;
    };
    let mut needed: HashSet<u16> = HashSet::new();
    for stmt in ssa.ir.blocks.iter().flat_map(|block| &block.stmts) {
        needed.extend(explicit_reads(stmt));
    }
    // A value a statement reads without naming it must be in its register,
    // but for vector data a call of unknown floating-point arguments could
    // only take as a scalar one, and for a value the code computes with in
    // a register a call reads unnamed besides its arguments, AArch64's
    // indirect result register or SysV's vector count: that is scratch the
    // call passes by.
    let vectors = vector_values(&ssa);
    let mut implicit: HashSet<u16> = HashSet::new();
    for (&(block, position), reads) in &ssa.implicit_reads {
        let (floats, extra) = match &ssa.ir.blocks[block].stmts[position] {
            Stmt::Call { convention, .. } => {
                (convention.float_arguments(), convention.call_extra())
            }
            _ => (&[][..], &[][..]),
        };
        implicit.extend(
            reads
                .iter()
                .filter(|(register, value)| {
                    !(floats.contains(register) && vectors.contains(value))
                        && !(extra.contains(register) && needed.contains(value))
                })
                .map(|(_, value)| *value),
        );
    }
    needed.extend(&implicit);
    // A φ only such a call reads joins nothing, so the vector data and what
    // the register held before it can be variables apart.
    let mut pending: Vec<u16> = needed.iter().copied().collect();
    let phi_of: HashMap<u16, &Phi> = ssa
        .phis
        .iter()
        .flatten()
        .map(|phi| (phi.value, phi))
        .collect();
    while let Some(value) = pending.pop() {
        for arg in phi_of
            .get(&value)
            .map(|phi| &phi.args)
            .into_iter()
            .flatten()
        {
            if needed.insert(*arg) {
                pending.push(*arg);
            }
        }
    }
    let class = congruence_classes(&ssa, &needed);
    let mut kept: HashSet<usize> = ssa
        .entry
        .values()
        .chain(&implicit)
        .chain(phi_of.keys().filter(|value| !needed.contains(value)))
        .map(|value| class[usize::from(value - VALUE_BASE)])
        .collect();
    // One a call defines, such as its result, moves into its variable
    // right after the call, when anything reads it.
    let mut read: HashSet<usize> = HashSet::new();
    for stmt in ssa.ir.blocks.iter().flat_map(|block| &block.stmts) {
        for value in explicit_reads(stmt) {
            if Ssa::is_value(value) {
                read.insert(class[usize::from(value - VALUE_BASE)]);
            }
        }
    }
    for arg in ssa.phis.iter().flatten().flat_map(|phi| &phi.args) {
        read.insert(class[usize::from(arg - VALUE_BASE)]);
    }
    // Further results, as a second half in rdx or a Go function's later
    // ones, move into their variables too.
    for ((block, position), defined) in &ssa.implicit_writes {
        let returns = match &ssa.ir.blocks[*block].stmts[*position] {
            Stmt::Call { convention, .. } => convention.results(),
            _ => &[crate::arch::RETURN],
        };
        for (register, value) in defined {
            let root = class[usize::from(value - VALUE_BASE)];
            if !read.contains(&root) || !returns.contains(register) {
                kept.insert(root);
            }
        }
    }
    // Code no path reaches keeps its registers.
    let dominators = dom::dominators(&ssa.successors);
    for (block, contents) in ssa.ir.blocks.iter().enumerate() {
        if block == 0 || dominators.idom[block].is_some() {
            continue;
        }
        for stmt in &contents.stmts {
            if let Stmt::Assign { dest, .. } = stmt {
                kept.insert(class[usize::from(dest.index - VALUE_BASE)]);
            }
        }
    }
    // Number the new variables in the order their first definitions appear
    // in the code, a φ before the statements of its block and a call's
    // results in the order the convention returns them.
    let mut first: HashMap<usize, (usize, usize, u16)> = HashMap::new();
    let mut note = |value: u16, at: (usize, usize, u16)| {
        let root = class[usize::from(value - VALUE_BASE)];
        let entry = first.entry(root).or_insert(at);
        *entry = (*entry).min(at);
    };
    for (block, list) in ssa.phis.iter().enumerate() {
        for phi in list {
            note(phi.value, (block, 0, 0));
        }
    }
    for (block, contents) in ssa.ir.blocks.iter().enumerate() {
        for (position, stmt) in contents.stmts.iter().enumerate() {
            if let Stmt::Assign { dest, .. } = stmt {
                note(dest.index, (block, position + 1, 0));
            }
            let returns = match stmt {
                Stmt::Call { convention, .. } => convention.results(),
                _ => &[],
            };
            for (register, value) in ssa
                .implicit_writes
                .get(&(block, position))
                .into_iter()
                .flatten()
            {
                let rank = returns
                    .iter()
                    .position(|result| result == register)
                    .map_or(*register, |rank| rank as u16);
                note(*value, (block, position + 1, rank));
            }
        }
    }
    let mut order: Vec<(usize, (usize, usize, u16))> = first
        .into_iter()
        .filter(|(root, _)| registers.contains(&ssa.origin[*root]) && !kept.contains(root))
        .collect();
    order.sort_by_key(|(root, at)| (*at, *root));
    let names: HashMap<usize, u16> = order
        .into_iter()
        .enumerate()
        .map(|(index, (root, _))| (root, crate::ir::VARIABLE_BASE + index as u16))
        .collect();
    if names.is_empty() {
        return;
    }
    let origins: Vec<(u16, u16)> = names
        .iter()
        .map(|(root, name)| (*name, ssa.origin[*root]))
        .collect();
    let renames: HashMap<u16, u16> = (0..ssa.origin.len())
        .filter_map(|index| {
            names
                .get(&class[index])
                .map(|name| (VALUE_BASE + index as u16, *name))
        })
        .collect();
    let mut lowered = lower_with(&ssa, &renames);
    // A renamed value a call returns goes straight into its variable; one
    // in another result register is copied out of it right after the call.
    // (block, position, variable, register, the register's place among the
    // call's results)
    let mut copies: Vec<(usize, usize, u16, u16, usize)> = Vec::new();
    for ((block, position), defined) in &ssa.implicit_writes {
        for (register, value) in defined {
            let Some(name) = renames.get(value) else {
                continue;
            };
            match &mut lowered.blocks[*block].stmts[*position] {
                Stmt::Call {
                    result, convention, ..
                } if convention.results().first() == Some(register) => {
                    *result = Some(crate::ir::RegRef {
                        index: *name,
                        width: 64,
                    });
                }
                Stmt::Call { convention, .. } => {
                    let rank = convention
                        .results()
                        .iter()
                        .position(|result| result == register)
                        .unwrap_or(usize::MAX);
                    copies.push((*block, *position, *name, *register, rank));
                }
                _ => {}
            }
        }
    }
    // Each goes right after the call, so the last inserted comes first: the
    // results end up in the order the convention returns them.
    copies.sort_by_key(|copy| std::cmp::Reverse((copy.0, copy.1, copy.4, copy.3)));
    for (block, position, name, register, _) in copies {
        lowered.blocks[block].stmts.insert(
            position + 1,
            Stmt::Assign {
                dest: crate::ir::RegRef {
                    index: name,
                    width: 64,
                },
                value: Expr::reg(register, 64),
            },
        );
    }
    // Code no path reaches, as a landing pad the unwinder enters, finds a
    // callee-saved register holding what it held across the calls: the
    // variable the register holds at every call, when that is one.
    let clobbered = ir.convention.clobbered();
    for register in registers.iter().filter(|register| {
        crate::arch::machine_registers().contains(register) && !clobbered.contains(register)
    }) {
        let held: HashSet<u16> = names
            .iter()
            .filter(|(root, _)| ssa.origin[**root] == *register)
            .map(|(_, name)| *name)
            .collect();
        let Some(variable) = held_across_calls(&lowered, &held, &dominators) else {
            continue;
        };
        for (block, contents) in lowered.blocks.iter_mut().enumerate() {
            if block == 0 || dominators.idom[block].is_some() {
                continue;
            }
            for stmt in &mut contents.stmts {
                rename_reads(stmt, &mut |index| {
                    if index == *register { variable } else { index }
                });
                if crate::ir::visit::statement_registers(stmt)
                    .0
                    .contains(register)
                {
                    break;
                }
            }
        }
    }
    *ir = lowered;
    ir.variable_registers.extend(origins);
}

/// A call's result that only moves on into another variable right after the
/// call goes there directly: `v1 = f(); v2 = v1;` becomes `v2 = f();`, and
/// `v1 = f(); v3 = rbx; v2 = v1; v4 = v3;` becomes `v2 = f(); v4 = rbx;`.
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
    // So do the further results copied out of their registers right after it.
    let further = |stmt: &Stmt| {
        matches!(stmt, Stmt::Assign {
            dest,
            value: Expr::Reg { index, .. },
        } if variable(dest.index) && !variable(*index))
    };
    for block in &mut ir.blocks {
        let mut position = 0;
        while position < block.stmts.len() {
            position += 1;
            if !matches!(block.stmts[position - 1], Stmt::Call { .. }) {
                continue;
            }
            let position = position - 1;
            let mut next = position + 1;
            while block.stmts.get(next).is_some_and(further) {
                next += 1;
            }
            while let Some(Stmt::Assign {
                dest,
                value: Expr::Reg { index, width: 64 },
            }) = block.stmts.get(next)
            {
                let (dest, taken) = (*dest, *index);
                let written = |stmt: &Stmt| statement_registers(stmt).0;
                if !(variable(taken)
                    && variable(dest.index)
                    && dest.width == 64
                    && reads.get(&taken) == Some(&1)
                    && definitions.get(&taken) == Some(&1)
                    && !block.stmts[position..next]
                        .iter()
                        .any(|stmt| written(stmt).contains(&dest.index)))
                {
                    break;
                }
                let Some(definition) =
                    block.stmts[position..next]
                        .iter_mut()
                        .find_map(|stmt| match stmt {
                            Stmt::Call {
                                result: Some(result),
                                ..
                            }
                            | Stmt::Assign { dest: result, .. }
                                if result.index == taken =>
                            {
                                Some(result)
                            }
                            _ => None,
                        })
                else {
                    break;
                };
                *definition = dest;
                block.stmts.remove(next);
            }
        }
    }
}

/// The one variable of `held` that every call the entry reaches finds in
/// the register they share, following the writes of them forward. A tail
/// call has left the frame, so no landing pad of it can be entered.
fn held_across_calls(
    ir: &FunctionIr,
    held: &HashSet<u16>,
    dominators: &dom::Dominators,
) -> Option<u16> {
    if held.is_empty() {
        return None;
    }
    // Per block on entry: the variable in the register, `Some(None)` when
    // paths disagree or none was written.
    let mut entry: Vec<Option<Option<u16>>> = vec![None; ir.blocks.len()];
    entry[0] = Some(None);
    let mut work = vec![0];
    let mut seen: Option<Option<u16>> = None;
    while let Some(index) = work.pop() {
        let mut current = entry[index].expect("visited");
        let stmts = &ir.blocks[index].stmts;
        for (position, stmt) in stmts.iter().enumerate() {
            match stmt {
                Stmt::Assign { dest, .. } if held.contains(&dest.index) => {
                    current = Some(dest.index);
                }
                Stmt::Call { .. } if matches!(stmts.get(position + 1), Some(Stmt::Ret { .. })) => {}
                Stmt::Call { .. } => {
                    seen = Some(match seen {
                        None => current,
                        Some(before) if before == current => current,
                        Some(_) => None,
                    });
                }
                _ => {}
            }
        }
        for next in crate::ir::cfg::block_successors(&ir.blocks, index) {
            if dominators.idom[next].is_none() && next != 0 {
                continue;
            }
            let merged = match entry[next] {
                None => current,
                Some(old) if old == current => current,
                Some(_) => None,
            };
            if entry[next] != Some(merged) {
                entry[next] = Some(merged);
                work.push(next);
            }
        }
    }
    seen.flatten()
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
            match stmt {
                Stmt::Assign { dest, .. }
                | Stmt::Call {
                    result: Some(dest), ..
                } => dest.index = back(dest.index),
                _ => {}
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
            if let Stmt::Assign { dest, .. }
            | Stmt::Call {
                result: Some(dest), ..
            } = stmt
            {
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
                result: None,
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
                    result: None,
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
                    result: Some(RegRef {
                        index: first,
                        width: 64,
                    }),
                    via: None,
                },
                assign(second, Expr::reg(first, 64)),
                Stmt::Ret {
                    value: Expr::reg(second, 64),
                },
            ],
        );
        super::take_results_directly(&mut ir);
        assert_eq!(ir.blocks[0].stmts.len(), 2);
        assert!(matches!(
            ir.blocks[0].stmts[0],
            Stmt::Call { result: Some(RegRef { index, .. }), .. } if index == second
        ));
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
                    result: Some(RegRef {
                        index: first,
                        width: 64,
                    }),
                    via: None,
                },
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
        assert_eq!(stmts.len(), 3, "{}", ir.render());
        assert!(matches!(
            stmts[0],
            Stmt::Call { result: Some(RegRef { index, .. }), .. } if index == second
        ));
        assert!(matches!(
            &stmts[1],
            Stmt::Assign { dest, value: Expr::Reg { index: 3, .. } } if dest.index == fourth
        ));
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

#[cfg(test)]
mod split_tests {
    use super::split_variables;
    use crate::ir::VARIABLE_BASE;
    use crate::ir::{BinOp, Block, CType, Cond, Expr, FunctionIr, Param, RegRef, Stmt};
    use crate::loader::Isa;

    const RSI: u16 = 6;

    fn function(blocks: Vec<Vec<Stmt>>) -> FunctionIr {
        let mut ir = FunctionIr::single_block(Isa::X86_64, Vec::new());
        ir.blocks = blocks
            .into_iter()
            .enumerate()
            .map(|(index, stmts)| Block {
                start: 0x10 * index as u64,
                stmts,
            })
            .collect();
        ir.params = vec![Param {
            index: RSI,
            name: "n".to_owned(),
            ty: CType::U64,
        }];
        ir
    }

    fn assign(index: u16, value: Expr) -> Stmt {
        Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
        }
    }

    fn counting_loop(start: Stmt) -> FunctionIr {
        let rsi = Expr::reg(RSI, 64);
        function(vec![
            vec![assign(0, rsi.clone()), start],
            vec![
                assign(RSI, Expr::bin(BinOp::Add, rsi.clone(), Expr::Const(1))),
                Stmt::Brif {
                    cond: Cond::Ne,
                    lhs: rsi.clone(),
                    rhs: Expr::reg(0, 64),
                    target: 0x10,
                },
            ],
            vec![Stmt::Ret { value: rsi }],
        ])
    }

    #[test]
    fn a_counter_reusing_a_dead_parameter_is_a_variable_of_its_own() {
        let mut ir = counting_loop(assign(RSI, Expr::Const(0)));
        split_variables(&mut ir, &[RSI]);
        let variable = Expr::reg(VARIABLE_BASE, 64);
        assert!(
            matches!(&ir.blocks[0].stmts[0], Stmt::Assign { value, .. } if *value == Expr::reg(RSI, 64))
        );
        assert!(
            matches!(&ir.blocks[0].stmts[1], Stmt::Assign { dest, .. } if dest.index == VARIABLE_BASE)
        );
        assert!(
            matches!(&ir.blocks[2].stmts[0], Stmt::Ret { value } if *value == variable),
            "{}",
            ir.render()
        );
    }

    #[test]
    fn a_parameter_the_loop_updates_keeps_its_register() {
        // The loop starts from the parameter itself.
        let mut ir = counting_loop(assign(1, Expr::Const(0)));
        let before = ir.render();
        split_variables(&mut ir, &[RSI]);
        assert_eq!(ir.render(), before);
    }

    /// Copies eight or sixteen bytes from rdi to rsi through xmm0, then calls
    /// through rax, which may take floating-point arguments.
    fn copy_through_xmm0(both_halves: bool) -> FunctionIr {
        const XMM0: u16 = 18;
        let at = |base: u16, offset: u64| {
            Expr::bin(BinOp::Add, Expr::reg(base, 64), Expr::Const(offset))
        };
        let load = |addr: Expr| Expr::Load {
            addr: Box::new(addr),
            width: 8,
            signed: false,
        };
        let store = |value: Expr, addr: Expr| Stmt::Store {
            addr,
            value,
            width: 8,
        };
        let mut stmts = vec![assign(XMM0, load(Expr::reg(7, 64)))];
        if both_halves {
            stmts.push(assign(XMM0 + 1, load(at(7, 8))));
        }
        stmts.push(store(Expr::reg(XMM0, 64), Expr::reg(RSI, 64)));
        if both_halves {
            stmts.push(store(Expr::reg(XMM0 + 1, 64), at(RSI, 8)));
        }
        stmts.push(Stmt::Call {
            target: None,
            through: Some(Expr::reg(0, 64)),
            convention: crate::ir::Convention::SysV,
            args: None,
            floats_named: false,
            clobbers: None,
            result: None,
            via: None,
        });
        stmts.push(Stmt::Ret {
            value: Expr::Const(0),
        });
        let mut ir = function(vec![stmts]);
        split_variables(&mut ir, &[XMM0, XMM0 + 1]);
        ir
    }

    #[test]
    fn sixteen_bytes_copied_through_a_vector_register_are_no_float_argument() {
        let ir = copy_through_xmm0(true);
        assert!(
            matches!(&ir.blocks[0].stmts[0], Stmt::Assign { dest, .. } if dest.index >= VARIABLE_BASE),
            "{}",
            ir.render()
        );
    }

    #[test]
    fn a_scalar_loaded_into_a_float_argument_register_stays_there() {
        let ir = copy_through_xmm0(false);
        assert!(
            matches!(&ir.blocks[0].stmts[0], Stmt::Assign { dest, .. } if dest.index == 18),
            "{}",
            ir.render()
        );
    }
}

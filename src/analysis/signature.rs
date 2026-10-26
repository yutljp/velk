//! Heuristic calling-convention and parameter recovery from lifted IR.

use std::collections::{HashMap, HashSet};

use crate::analysis::prototypes::{Prototype, preferred};
use crate::ir::{Access, Block, CType, Convention, Expr, Operation, Param, Stmt};
use crate::loader::Isa;

mod stack;

use stack::{StackFrame, stack_arguments};

#[derive(Debug, Clone)]
pub struct Signature {
    pub params: Vec<Param>,
    pub inputs: Option<crate::ir::Registers>,
    /// Argument registers actually read, excluding unchanged implicit results.
    pub(super) arguments: crate::ir::Registers,
    pub ret: CType,
    pub accesses: Vec<Access>,
    /// Argument registers a signed comparison reads: the parameter is signed.
    pub signed: HashSet<u16>,
    /// The 8-byte arguments past the registers, by offset from the stack
    /// pointer on entry.
    pub stack: Vec<i64>,
    /// How many bytes of each stack argument the body reads.
    pub stack_widths: Vec<u8>,
    /// The results past the stack arguments that a function of Go's
    /// assembly ABI writes in its caller's frame: offset from the stack
    /// pointer on entry, and width.
    pub stack_results: Vec<(i64, u8)>,
    /// The body reads `AArch64`'s indirect result register before writing it.
    pub indirect_result: bool,
    /// The stack arguments come while argument registers are left free:
    /// they are one structure passed by value.
    pub aggregate: bool,
}

fn reads(expr: &Expr, into: &mut HashSet<u16>) {
    match expr {
        Expr::Reg { index, .. } => {
            into.insert(*index);
        }
        Expr::Bin { lhs, rhs, .. } => {
            reads(lhs, into);
            reads(rhs, into);
        }
        Expr::Load { addr, .. } => reads(addr, into),
        Expr::SignExtend { value, .. } => reads(value, into),
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => {
            reads(lhs, into);
            reads(rhs, into);
            reads(then, into);
            reads(els, into);
        }
        Expr::Apply { args, .. } => {
            for arg in args {
                reads(arg, into);
            }
        }
        Expr::Const(_) => {}
    }
}

/// The new bits of `r = (r & keep) | value`, a write of part of a register
/// that keeps the rest: the kept bits are no input.
fn partial_write_source(value: &Expr, dest: u16) -> &Expr {
    if let Expr::Bin {
        op: crate::ir::BinOp::Or,
        lhs,
        rhs,
    } = value
        && let Expr::Bin {
            op: crate::ir::BinOp::And,
            lhs: kept,
            rhs: mask,
        } = lhs.as_ref()
        && matches!(kept.as_ref(), Expr::Reg { index, .. } if *index == dest)
        && matches!(mask.as_ref(), Expr::Const(_))
    {
        return rhs;
    }
    value
}

/// The condition kinds only a signed comparison produces.
fn signed_cond(cond: crate::ir::Cond) -> bool {
    matches!(
        cond,
        crate::ir::Cond::Lt | crate::ir::Cond::Gt | crate::ir::Cond::Le | crate::ir::Cond::Ge
    )
}

fn note_signed_cond(cond: crate::ir::Cond, operands: &[&Expr], signed: &mut HashSet<u16>) {
    if !signed_cond(cond) {
        return;
    }
    for expr in operands {
        reads(expr, signed);
    }
}

/// Walks an expression for the operands of signed operations: selects whose
/// condition is signed, signed division and remainder, and arithmetic shifts.
fn signed_in_expr(expr: &Expr, signed: &mut HashSet<u16>) {
    match expr {
        Expr::Bin { op, lhs, rhs } => {
            match op {
                crate::ir::BinOp::DivS | crate::ir::BinOp::ModS => {
                    reads(lhs, signed);
                    reads(rhs, signed);
                }
                crate::ir::BinOp::Sar => reads(lhs, signed),
                _ => {}
            }
            signed_in_expr(lhs, signed);
            signed_in_expr(rhs, signed);
        }
        Expr::Load { addr, .. } => signed_in_expr(addr, signed),
        Expr::SignExtend { value, .. } => signed_in_expr(value, signed),
        Expr::Select {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => {
            note_signed_cond(*cond, &[lhs, rhs], signed);
            signed_in_expr(lhs, signed);
            signed_in_expr(rhs, signed);
            signed_in_expr(then, signed);
            signed_in_expr(els, signed);
        }
        Expr::Apply { op, args } => {
            // Converting a signed integer to a float reads it as signed.
            if let crate::ir::Operation::IntToFloat { signed: true, .. } = op {
                for arg in args {
                    reads(arg, signed);
                }
            }
            for arg in args {
                signed_in_expr(arg, signed);
            }
        }
        Expr::Reg { .. } | Expr::Const(_) => {}
    }
}

/// The register Go's x86-64 ABI passes a closure's context in.
const GO_CLOSURE: u16 = 2;

/// The prototype of the library function a call reaches, when known.
pub type Callees<'a> = &'a dyn Fn(&Stmt) -> Option<&'static Prototype>;

fn inputs_known(blocks: &[Block], landing_pads: &[(u64, Vec<(u64, u64)>)]) -> bool {
    let starts: HashSet<_> = blocks.iter().map(|block| block.start).collect();
    landing_pads.is_empty()
        && blocks
            .iter()
            .flat_map(|block| &block.stmts)
            .all(|stmt| match stmt {
                Stmt::Unsupported { .. }
                | Stmt::BrIndirect { .. }
                | Stmt::BrifFlags { .. }
                | Stmt::Br { target: None } => false,
                Stmt::Br {
                    target: Some(target),
                }
                | Stmt::Brif { target, .. } => starts.contains(target),
                Stmt::Switch { cases, default, .. } => {
                    default.is_some_and(|target| starts.contains(&target))
                        && cases.iter().all(|(_, target)| starts.contains(target))
                }
                _ => true,
            })
}

/// Assignments whose values can reach an observable use. Unresolved control
/// flow, exception entries and vector values stay conservative: undeclared
/// aggregate results can use further vector registers.
fn needed_assignments(
    blocks: &[Block],
    registers: &[Vec<(HashSet<u16>, HashSet<u16>)>],
    isa: Isa,
    convention: Convention,
) -> Vec<Vec<bool>> {
    let mut needed: Vec<Vec<bool>> = blocks
        .iter()
        .map(|block| vec![true; block.stmts.len()])
        .collect();
    if registers.is_empty()
        || !matches!(
            convention,
            Convention::SysV | Convention::Win64 | Convention::Aapcs64
        )
    {
        return needed;
    }
    let successors: Vec<_> = (0..blocks.len())
        .map(|index| crate::ir::cfg::block_successors(blocks, index))
        .collect();
    let mut incoming = vec![HashSet::new(); blocks.len()];
    loop {
        let mut changed = false;
        for index in (0..blocks.len()).rev() {
            let mut live: HashSet<_> = successors[index]
                .iter()
                .flat_map(|next| incoming[*next].iter().copied())
                .collect();
            for (position, stmt) in blocks[index].stmts.iter().enumerate().rev() {
                let (writes, reads) = &registers[index][position];
                // The raw return may name only the first integer result.
                if matches!(stmt, Stmt::Ret { .. }) {
                    live.extend(convention.results());
                }
                if let Stmt::Assign { dest, value } = stmt
                    && !live.contains(&dest.index)
                    && !crate::passes::frame::reads_outside_frame(value)
                    && !writes
                        .iter()
                        .chain(reads)
                        .any(|register| crate::arch::vector_half(isa, *register).is_some())
                {
                    needed[index][position] = false;
                    continue;
                }
                needed[index][position] = true;
                live.retain(|register| !writes.contains(register));
                live.extend(reads.iter().copied());
            }
            if live != incoming[index] {
                incoming[index] = live;
                changed = true;
            }
        }
        if !changed {
            return needed;
        }
    }
}

#[cfg(test)]
fn recover(blocks: &[Block], isa: Isa, convention: Convention, go: bool) -> Signature {
    recover_with(blocks, &[], isa, convention, go, &|_| None)
}

/// The signature, with each argument passed unchanged to a library function
/// of the type that function's prototype gives it.
pub fn recover_with(
    blocks: &[Block],
    landing_pads: &[(u64, Vec<(u64, u64)>)],
    isa: Isa,
    convention: Convention,
    go: bool,
    callees: Callees<'_>,
) -> Signature {
    let (arguments, float_arguments) = match isa {
        Isa::Unsupported => (&[][..], &[][..]),
        _ => (convention.arguments(), convention.float_arguments()),
    };
    // AArch64's indirect result register is no argument, but whether the
    // body reads it says whether the function returns through memory.
    let indirect = match isa {
        Isa::AArch64 => Some(8),
        // Go passes a closure's context in rdx.
        Isa::X86_64 if go => Some(GO_CLOSURE),
        _ => None,
    };
    let universe: HashSet<u16> = arguments
        .iter()
        .chain(float_arguments)
        .copied()
        .chain(indirect)
        .collect();

    // Registers written on every path to each block; a register read before
    // it is written is an argument.
    let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); blocks.len()];
    for (index, block) in blocks.iter().enumerate() {
        let Some(last) = block.stmts.last() else {
            continue;
        };
        let mut targets = Vec::new();
        let falls_through = match last {
            Stmt::Brif { target, .. } | Stmt::BrifFlags { target, .. } => {
                targets.push(*target);
                true
            }
            Stmt::Br {
                target: Some(target),
            } => {
                targets.push(*target);
                false
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, target) in cases {
                    targets.push(*target);
                }
                if let Some(target) = default {
                    targets.push(*target);
                }
                false
            }
            Stmt::Ret { .. } | Stmt::BrIndirect { .. } => false,
            _ => true,
        };
        if falls_through && index + 1 < blocks.len() {
            predecessors[index + 1].push(index);
        }
        for target in targets {
            if let Some(destination) = blocks.iter().position(|block| block.start == target) {
                predecessors[destination].push(index);
            }
        }
    }

    // Code compiled to the convention takes no argument past a call in a
    // register the convention lets the call change, whatever the callee
    // really leaves there: a read of one is no argument either.
    let call_writes = |stmt: &Stmt| match stmt {
        Stmt::Call { convention, .. } => {
            let mut written: Vec<_> = crate::ir::visit::statement_registers(stmt)
                .0
                .into_iter()
                .collect();
            written.extend(convention.clobbered().iter().copied().filter(|register| {
                !stmt
                    .call_outputs()
                    .iter()
                    .any(|output| output.register == *register)
            }));
            for (output, source) in stmt.preserved_output_sources() {
                let dest = stmt.call_outputs()[output].dest;
                if dest.index == source && dest.width == 64 {
                    written.retain(|register| *register != source);
                }
            }
            written
        }
        _ => Vec::new(),
    };
    let writes: Vec<HashSet<u16>> = blocks
        .iter()
        .map(|block| {
            block
                .stmts
                .iter()
                .flat_map(|stmt| match stmt {
                    Stmt::Assign { dest, .. } => vec![dest.index],
                    Stmt::Machine { outputs, .. } => {
                        outputs.iter().map(|output| output.index).collect()
                    }
                    Stmt::Call { .. } => call_writes(stmt),
                    // Unsupported instructions are mostly vector ones, which
                    // may write any floating-point register.
                    Stmt::Unsupported { .. } => float_arguments.to_vec(),
                    _ => Vec::new(),
                })
                .collect()
        })
        .collect();
    let mut entry: Vec<HashSet<u16>> = vec![universe; blocks.len()];
    if !entry.is_empty() {
        entry[0] = HashSet::new();
    }
    loop {
        let mut changed = false;
        for index in 0..blocks.len() {
            if index == 0 {
                continue;
            }
            let preds = &predecessors[index];
            if preds.is_empty() {
                continue;
            }
            let mut merged: Option<HashSet<u16>> = None;
            for pred in preds {
                let exit: HashSet<u16> = entry[*pred].union(&writes[*pred]).copied().collect();
                merged = Some(match merged {
                    None => exit,
                    Some(current) => current.intersection(&exit).copied().collect(),
                });
            }
            let merged = merged.unwrap_or_default();
            if merged != entry[index] {
                entry[index] = merged;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let returns_argument = !matches!(convention, Convention::Aapcs64 | Convention::Aapcs32)
        && arguments.contains(&crate::arch::RETURN);
    let effects = blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
        matches!(stmt, Stmt::Store { .. } | Stmt::Call { .. })
            || matches!(
                stmt,
                Stmt::Machine {
                    instruction: crate::ir::MachineInstruction::Atomic { .. },
                    ..
                }
            )
    });
    let mut inputs: HashSet<u16> = HashSet::new();
    let mut incoming = crate::ir::Registers::default();
    // Inputs some read takes more than the low 32 bits of.
    let mut wide_inputs: HashSet<u16> = HashSet::new();
    // Go runtime entry points can use registers beyond the source ABI.
    let known_inputs = !go && inputs_known(blocks, landing_pads);
    let registers: Vec<Vec<_>> = if known_inputs {
        blocks
            .iter()
            .map(|block| {
                block
                    .stmts
                    .iter()
                    .map(crate::ir::visit::statement_registers)
                    .collect()
            })
            .collect()
    } else {
        Vec::new()
    };
    let needed = needed_assignments(blocks, &registers, isa, convention);
    for (index, block) in blocks.iter().enumerate() {
        let mut written = entry[index].clone();
        for (position, stmt) in block.stmts.iter().enumerate() {
            // Results can pass incoming values through without an explicit read.
            if known_inputs && matches!(stmt, Stmt::Ret { .. }) {
                for register in convention.results() {
                    if !written.contains(register) {
                        incoming.insert(*register);
                    }
                }
            }
            if known_inputs && needed[index][position] {
                for register in &registers[index][position].1 {
                    if !written.contains(register) {
                        incoming.insert(*register);
                    }
                }
            }
            let mut used = HashSet::new();
            match stmt {
                Stmt::Machine { inputs, .. } => {
                    for input in inputs {
                        reads(input, &mut used);
                    }
                }
                Stmt::Assign { dest, value } => {
                    if needed[index][position] {
                        reads(partial_write_source(value, dest.index), &mut used);
                    }
                }
                Stmt::Store { addr, value, .. } => {
                    reads(addr, &mut used);
                    reads(value, &mut used);
                }
                Stmt::Brif { lhs, rhs, .. } => {
                    reads(lhs, &mut used);
                    reads(rhs, &mut used);
                }
                // AAPCS64 can return an unchanged first argument even when
                // the function has effects. Other conventions keep the
                // void-return heuristic for such functions.
                Stmt::Ret { value }
                    if convention == Convention::Aapcs64 || !(returns_argument && effects) =>
                {
                    reads(value, &mut used)
                }
                Stmt::Ret { .. } => {}
                Stmt::BrIndirect { target } => reads(target, &mut used),
                Stmt::Switch { index, .. } => reads(index, &mut used),
                // What a call passes on is read here too.
                Stmt::Call { through, args, .. } => {
                    for value in through.iter().chain(args.iter().flatten()) {
                        reads(value, &mut used);
                    }
                    for &source in stmt.declared_call_reads() {
                        used.insert(source);
                        if !written.contains(&source) {
                            wide_inputs.insert(source);
                        }
                    }
                    for (output, source) in stmt.preserved_output_sources() {
                        let dest = stmt.call_outputs()[output].dest;
                        if dest.index == source && dest.width == 64 {
                            continue;
                        }
                        used.insert(source);
                        if !written.contains(&source) && dest.width > 32 {
                            wide_inputs.insert(source);
                        }
                    }
                }
                _ => {}
            }
            for register in used {
                if !written.contains(&register) {
                    inputs.insert(register);
                    // A write of the low bits keeps the rest without reading it.
                    let operands = match stmt {
                        Stmt::Assign { dest, value } => {
                            vec![partial_write_source(value, dest.index)]
                        }
                        _ => stmt.operands(),
                    };
                    let (mut narrow, mut seen) = (true, false);
                    for value in operands {
                        crate::analysis::typing::scan_reads(
                            value,
                            register,
                            false,
                            &mut narrow,
                            &mut seen,
                        );
                    }
                    if !narrow {
                        wide_inputs.insert(register);
                    }
                }
            }
            match stmt {
                Stmt::Assign { dest, .. } => {
                    written.insert(dest.index);
                }
                Stmt::Machine { outputs, .. } => {
                    written.extend(outputs.iter().map(|output| output.index))
                }
                Stmt::Call { .. } => written.extend(call_writes(stmt)),
                Stmt::Unsupported { .. } => written.extend(float_arguments),
                _ => {}
            }
        }
    }

    // Arguments are passed in order, so every register before the last one
    // the body reads is a parameter too, even one only passed on.
    let count = arguments
        .iter()
        .rposition(|register| inputs.contains(register))
        .map_or(0, |last| last + 1);
    let mut params: Vec<Param> = arguments[..count]
        .iter()
        .enumerate()
        .map(|(position, register)| Param {
            index: *register,
            name: format!("a{position}"),
            ty: CType::U64,
        })
        .collect();
    // The floating-point arguments follow, a float where only the low 32
    // bits are read.
    let float_count = float_arguments
        .iter()
        .rposition(|register| inputs.contains(register))
        .map_or(0, |last| last + 1);
    // A variadic function saves every floating-point argument register to
    // its register save area and reads them nowhere else.
    let saved_only = |register: u16| {
        blocks.iter().flat_map(|block| &block.stmts).all(|stmt| {
            let operands = match stmt {
                Stmt::Store {
                    addr,
                    value: Expr::Reg { index, .. },
                    ..
                } if *index == register => vec![addr],
                _ => stmt.operands(),
            };
            operands.into_iter().all(|value| {
                let mut read = HashSet::new();
                reads(value, &mut read);
                !read.contains(&register)
            })
        })
    };
    let float_count = if float_count == float_arguments.len()
        && float_arguments.iter().all(|register| saved_only(*register))
    {
        0
    } else {
        float_count
    };
    if convention == Convention::Win64 {
        for (position, register) in arguments.iter().enumerate().take(float_count).skip(count) {
            params.push(Param {
                index: *register,
                name: format!("a{position}"),
                ty: CType::U64,
            });
        }
    }
    for (position, register) in float_arguments[..float_count].iter().enumerate() {
        if convention == Convention::Win64 && !inputs.contains(register) {
            continue;
        }
        let narrow = !wide_inputs.contains(register);
        let shared = convention == Convention::Win64 && !inputs.contains(&arguments[position]);
        let param = Param {
            index: *register,
            name: format!("a{}", if shared { position } else { params.len() }),
            ty: CType::Named(if narrow { "float" } else { "double" }.to_owned()),
        };
        if shared {
            params[position] = param;
        } else {
            params.push(param);
        }
    }
    // A Go function value's code reads its closure's context.
    if go && isa == Isa::X86_64 && inputs.contains(&GO_CLOSURE) {
        params.push(Param {
            index: GO_CLOSURE,
            name: "closure".to_owned(),
            ty: CType::pointer_to(CType::Void),
        });
    }

    // Which argument each register is derived from through copies and
    // base-preserving arithmetic, so loads through it type that argument.
    // A stack slot every store fills from one argument passes it on too, as
    // unoptimized code keeps each argument in its slot. A register written
    // once has one origin everywhere; one written more often, only from its
    // write to the end of the block.
    let mut definitions: HashMap<u16, usize> = HashMap::new();
    for stmt in blocks.iter().flat_map(|block| &block.stmts) {
        match stmt {
            Stmt::Assign { dest, .. } => *definitions.entry(dest.index).or_default() += 1,
            Stmt::Call { .. } | Stmt::Machine { .. } => {
                for register in crate::ir::visit::statement_registers(stmt).0 {
                    *definitions.entry(register).or_default() += 2;
                }
            }
            _ => {}
        }
    }
    let entry_origins: HashMap<u16, u16> = params
        .iter()
        .map(|param| (param.index, param.index))
        .collect();
    let settle = |exact: bool| {
        let mut origins = Origins {
            entry: entry_origins.clone(),
            global: entry_origins
                .iter()
                .filter(|(register, _)| !definitions.contains_key(register))
                .map(|(register, param)| (*register, *param))
                .collect(),
            slots: HashMap::new(),
            definitions: definitions.clone(),
            sp: crate::arch::stack_pointer(isa),
            exact,
        };
        loop {
            let (global, slots) = origins.walk(blocks, &mut |_, _| {});
            if global == origins.global && slots == origins.slots {
                break;
            }
            origins.global = global;
            origins.slots = slots;
        }
        origins
    };
    let origins = settle(false);

    // What a vector register holds, from the operations that read it: the
    // floats of a float operation, or the lanes of an integer one.
    let mut vector_reads: HashMap<u16, Option<u8>> = HashMap::new();
    for stmt in blocks.iter().flat_map(|block| &block.stmts) {
        for value in stmt.operands() {
            vector_operands(value, &mut vector_reads);
        }
    }
    // What each pointer argument points to: the first general-register
    // access through it, or else the first vector one whose value an
    // operation reads as floats or lanes. The high half of a vector says
    // nothing about the element.
    let mut pointer_elements: HashMap<u16, (bool, CType)> = HashMap::new();
    let note = |addr: &Expr,
                width: u8,
                register: Option<u16>,
                read_as: Option<Option<u8>>,
                origin: &HashMap<u16, u16>,
                elements: &mut HashMap<u16, (bool, CType)>| {
        let Some(param) = base_register(addr).and_then(|base| origin.get(&base)) else {
            return;
        };
        let held = read_as.or_else(|| register.and_then(|index| vector_reads.get(&index).copied()));
        let (float, element) = match register.and_then(|index| crate::arch::vector_half(isa, index))
        {
            Some(true) => return,
            Some(false) => match held {
                Some(None) if matches!(width, 4 | 8) => (
                    true,
                    CType::Named(if width == 4 { "float" } else { "double" }.to_owned()),
                ),
                Some(Some(lane)) => (true, CType::int(lane, false)),
                _ => return,
            },
            None => (false, CType::int(width, false)),
        };
        match elements.get(param) {
            Some((false, _)) => {}
            Some((true, _)) if float => {}
            _ => {
                elements.insert(*param, (float, element));
            }
        }
    };
    let mut code_pointers: HashSet<u16> = HashSet::new();
    origins.walk(blocks, &mut |stmt, origin| match stmt {
        Stmt::Assign { dest, value } => {
            if let Some((addr, width)) = load_of(value) {
                note(
                    addr,
                    width,
                    Some(dest.index),
                    None,
                    origin,
                    &mut pointer_elements,
                );
            } else {
                // Memory an integer operation reads holds integers.
                let mut nested = Vec::new();
                integer_loads(value, &mut nested);
                for (addr, width) in nested {
                    note(addr, width, None, None, origin, &mut pointer_elements);
                }
            }
            // A float operation reading memory reads a float there, and a
            // lane operation lanes.
            if let Expr::Apply { op, args } = partial_write_source(value, dest.index) {
                let read_as = vector_reading(*op);
                for arg in args {
                    if let Expr::Load { addr, width, .. } = arg
                        && (read_as != Some(None)
                            || op.argument_precision().map(|p| u32::from(p.bits()))
                                == Some(u32::from(*width) * 8))
                    {
                        note(
                            addr,
                            *width,
                            Some(dest.index),
                            read_as,
                            origin,
                            &mut pointer_elements,
                        );
                    }
                }
            }
        }
        Stmt::Machine {
            instruction: crate::ir::MachineInstruction::Atomic { width, .. },
            inputs,
            ..
        } => {
            if let Some(addr) = inputs.first() {
                note(addr, *width, None, None, origin, &mut pointer_elements);
            }
        }
        Stmt::Store { addr, width, value } => {
            let register = match value {
                Expr::Reg { index, .. } => Some(*index),
                Expr::Bin { lhs, .. } => match lhs.as_ref() {
                    Expr::Reg { index, .. } => Some(*index),
                    _ => None,
                },
                _ => None,
            };
            note(addr, *width, register, None, origin, &mut pointer_elements);
        }
        // Memory a compare or a return reads holds integers too.
        Stmt::Brif { lhs, rhs, .. } => {
            for value in [lhs, rhs] {
                let mut nested = Vec::new();
                integer_loads(value, &mut nested);
                for (addr, width) in nested {
                    note(addr, width, None, None, origin, &mut pointer_elements);
                }
            }
        }
        Stmt::Ret { value } => {
            let mut nested = Vec::new();
            integer_loads(value, &mut nested);
            for (addr, width) in nested {
                note(addr, width, None, None, origin, &mut pointer_elements);
            }
        }
        // An argument the code calls or jumps through points at code.
        Stmt::Call {
            through: Some(Expr::Reg { index, .. }),
            ..
        }
        | Stmt::BrIndirect {
            target: Expr::Reg { index, .. },
        } => {
            if let Some(param) = origin.get(index) {
                code_pointers.insert(*param);
            }
        }
        _ => {}
    });
    for param in &mut params {
        if let Some((_, element)) = pointer_elements.get(&param.index) {
            param.ty = CType::pointer_to(element.clone());
        } else if code_pointers.contains(&param.index) {
            param.ty = CType::pointer_to(CType::Void);
        }
    }
    let offered = prototype_types(blocks, &settle(true), callees);
    for param in &mut params {
        if let Some(ty) = offered.get(&param.index) {
            crate::analysis::typing::settle_param(param, ty);
        }
    }

    // Signedness is visible only in comparison conditions.
    let mut signed_args: HashSet<u16> = HashSet::new();
    origins.walk(blocks, &mut |stmt, origin| {
        let mut signed: HashSet<u16> = HashSet::new();
        match stmt {
            Stmt::Brif { cond, lhs, rhs, .. } => {
                note_signed_cond(*cond, &[lhs, rhs], &mut signed);
            }
            Stmt::Assign { value, .. } => signed_in_expr(value, &mut signed),
            Stmt::Store { addr, value, .. } => {
                signed_in_expr(addr, &mut signed);
                signed_in_expr(value, &mut signed);
            }
            Stmt::Ret { value } => signed_in_expr(value, &mut signed),
            Stmt::Switch { index, .. } => signed_in_expr(index, &mut signed),
            Stmt::Call { .. } => {
                for value in stmt.operands() {
                    signed_in_expr(value, &mut signed);
                }
            }
            _ => {}
        }
        signed_args.extend(
            signed
                .iter()
                .filter_map(|register| origin.get(register).copied()),
        );
    });

    let ret = crate::ir::cfg::own_return(blocks).map_or(CType::U64, expression_type);

    // Field offsets count from the argument itself: a register only copied
    // from it, never one advanced from it.
    let mut copies: HashMap<u16, u16> = params
        .iter()
        .map(|param| (param.index, param.index))
        .collect();
    loop {
        let mut changed = false;
        for stmt in blocks.iter().flat_map(|block| &block.stmts) {
            if let Stmt::Assign {
                dest,
                value: Expr::Reg { index, .. },
            } = stmt
                && !copies.contains_key(&dest.index)
                && let Some(param) = copies.get(index).copied()
            {
                copies.insert(dest.index, param);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    // A register advanced from the argument it copies counts from elsewhere.
    let redefined: HashSet<u16> = blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .filter_map(|stmt| match stmt {
            Stmt::Assign { dest, value } if !matches!(value, Expr::Reg { .. }) => {
                let Some(param) = copies.get(&dest.index) else {
                    return None;
                };
                let mut read = HashSet::new();
                reads(value, &mut read);
                read.iter()
                    .any(|register| copies.get(register) == Some(param))
                    .then_some(dest.index)
            }
            _ => None,
        })
        .collect();
    let mut offsets: HashMap<u16, std::collections::BTreeMap<u64, u8>> = HashMap::new();
    for block in blocks {
        for stmt in &block.stmts {
            let (addr, width) = match stmt {
                Stmt::Assign { value, .. } => match load_of(value) {
                    Some((addr, width)) => (addr, width),
                    None => continue,
                },
                Stmt::Store { addr, width, .. } => (addr, *width),
                _ => continue,
            };
            let Some((base, offset)) = split_address(addr) else {
                continue;
            };
            let Some(param) = copies.get(&base).filter(|_| !redefined.contains(&base)) else {
                continue;
            };
            offsets
                .entry(*param)
                .or_default()
                .entry(offset)
                .or_insert(width);
        }
    }
    let accesses = params
        .iter()
        .filter_map(|param| {
            let Some(fields) = offsets.get(&param.index) else {
                return None;
            };
            Some(Access {
                register: param.index,
                fields: fields
                    .iter()
                    .map(|(offset, width)| (*offset, CType::int(*width, false)))
                    .collect(),
            })
        })
        .collect();

    let registers_full = arguments
        .iter()
        .all(|register| params.iter().any(|param| param.index == *register));
    let frame = match (registers_full, isa) {
        (_, Isa::AArch64 | Isa::Arm32)
            if matches!(convention, Convention::Aapcs64 | Convention::Aapcs32) =>
        {
            stack_arguments(blocks, landing_pads, isa, convention)
        }
        (_, Isa::I386) => stack_arguments(blocks, landing_pads, isa, convention),
        (true, Isa::X86_64) => stack_arguments(blocks, landing_pads, isa, convention),
        (false, Isa::X86_64) if matches!(convention, Convention::SysV | Convention::GoAmd64) => {
            stack_arguments(blocks, landing_pads, isa, convention)
        }
        _ => StackFrame::default(),
    };
    let stack = frame.offsets;
    let aggregate = convention == Convention::SysV && !registers_full && !stack.is_empty();

    Signature {
        params,
        inputs: known_inputs.then_some(incoming),
        arguments: arguments
            .iter()
            .chain(float_arguments)
            .copied()
            .filter(|register| inputs.contains(register))
            .collect(),
        ret,
        accesses,
        signed: signed_args,
        stack,
        stack_widths: frame.widths,
        stack_results: frame.results,
        indirect_result: isa == Isa::AArch64 && inputs.contains(&8),
        aggregate,
    }
}

/// The types library functions give the arguments the body passes them
/// unchanged, by argument register.
fn prototype_types(
    blocks: &[Block],
    origins: &Origins,
    callees: Callees<'_>,
) -> HashMap<u16, CType> {
    let mut offered: HashMap<u16, CType> = HashMap::new();
    origins.walk(blocks, &mut |stmt, origin| {
        // A declared call's parameters are typed by its declaration, not
        // by their position.
        if stmt.has_declared_call() {
            return;
        }
        let Stmt::Call {
            args, convention, ..
        } = stmt
        else {
            return;
        };
        let Some(prototype) = callees(stmt) else {
            return;
        };
        // A variadic call's arguments are counted later; its fixed ones are
        // in the first argument registers.
        let registers: Vec<u16> = match args {
            Some(args) => args
                .iter()
                .map(|arg| match arg {
                    Expr::Reg { index, .. } => *index,
                    _ => u16::MAX,
                })
                .collect(),
            None => convention.arguments().to_vec(),
        };
        for (register, ty) in registers.iter().zip(prototype.integer_params()) {
            let Some(param) = origin.get(register) else {
                continue;
            };
            let ty = match offered.remove(param) {
                Some(first) => preferred(first, ty),
                None => ty.clone(),
            };
            offered.insert(*param, ty);
        }
    });
    offered
}

fn expression_type(expr: &Expr) -> CType {
    match expr {
        Expr::SignExtend { width, .. } => CType::int(*width, true),
        Expr::Load { width, signed, .. } => CType::int(*width, *signed),
        Expr::Bin {
            op: crate::ir::BinOp::And,
            lhs,
            ..
        } => expression_type(lhs),
        Expr::Select { then, .. } => expression_type(then),
        _ => CType::U64,
    }
}

fn split_address(expr: &Expr) -> Option<(u16, u64)> {
    match expr {
        Expr::Reg { index, .. } => Some((*index, 0)),
        Expr::Const(_) => None,
        Expr::Bin {
            op: crate::ir::BinOp::Add,
            lhs,
            rhs,
        } => match (split_address(lhs), split_address(rhs)) {
            (Some((base, offset)), None) => {
                let constant = match rhs.as_ref() {
                    Expr::Const(value) => *value,
                    _ => return None,
                };
                Some((base, offset.wrapping_add(constant)))
            }
            (None, Some((base, offset))) => {
                let constant = match lhs.as_ref() {
                    Expr::Const(value) => *value,
                    _ => return None,
                };
                Some((base, offset.wrapping_add(constant)))
            }
            _ => None,
        },
        _ => None,
    }
}

/// The origins of registers written once, and of stack slots by address.
type Found = (HashMap<u16, u16>, HashMap<String, Option<u16>>);

/// The arguments registers and stack slots hold, as `recover` follows them.
struct Origins {
    sp: u16,
    /// The argument registers on entry.
    entry: HashMap<u16, u16>,
    /// Registers written at most once, with the argument they hold.
    global: HashMap<u16, u16>,
    /// Stack slots, by address, that every store fills from one argument.
    slots: HashMap<String, Option<u16>>,
    /// How often each register is written; a call counts twice.
    definitions: HashMap<u16, usize>,
    /// Only copies of an argument hold it, not values offset from it.
    exact: bool,
}

impl Origins {
    /// Walks every statement with the arguments the registers hold just
    /// before it, on every path that reaches it, and returns the origins
    /// this walk finds for registers written once and for stack slots.
    fn walk(&self, blocks: &[Block], visit: &mut dyn FnMut(&Stmt, &HashMap<u16, u16>)) -> Found {
        let mut entry: Vec<Option<HashMap<u16, u16>>> = vec![None; blocks.len()];
        if blocks.is_empty() {
            return (self.global.clone(), HashMap::new());
        }
        let mut start = self.global.clone();
        start.extend(
            self.entry
                .iter()
                .map(|(register, param)| (*register, *param)),
        );
        entry[0] = Some(start);
        let mut work = vec![0];
        while let Some(index) = work.pop() {
            let mut origin = entry[index].clone().expect("visited");
            for stmt in &blocks[index].stmts {
                self.step(stmt, &mut origin, None);
            }
            for next in crate::ir::cfg::block_successors(blocks, index) {
                let merged = match &entry[next] {
                    None => origin.clone(),
                    Some(old) => old
                        .iter()
                        .filter(|(register, param)| origin.get(register) == Some(param))
                        .map(|(register, param)| (*register, *param))
                        .collect(),
                };
                if entry[next].as_ref() != Some(&merged) {
                    entry[next] = Some(merged);
                    work.push(next);
                }
            }
        }
        let mut found = (self.global.clone(), HashMap::new());
        for (index, block) in blocks.iter().enumerate() {
            let Some(mut origin) = entry[index].clone() else {
                continue;
            };
            for stmt in &block.stmts {
                visit(stmt, &origin);
                self.step(stmt, &mut origin, Some(&mut found));
            }
        }
        if blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
            matches!(
                stmt,
                Stmt::Machine {
                    instruction: crate::ir::MachineInstruction::Atomic { .. },
                    ..
                }
            )
        }) {
            if crate::passes::memory::frame_addresses_escape(blocks, self.sp)
                || blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
                    crate::ir::visit::statement_registers(stmt)
                        .0
                        .contains(&self.sp)
                })
            {
                found.1.clear();
            } else {
                let private: HashSet<_> = blocks
                    .iter()
                    .flat_map(|block| &block.stmts)
                    .filter_map(|stmt| match stmt {
                        Stmt::Store { addr, .. }
                            if crate::passes::memory::private_address(addr, 8, self.sp) =>
                        {
                            Some(format!("{addr:?}"))
                        }
                        _ => None,
                    })
                    .collect();
                found.1.retain(|slot, _| private.contains(slot));
            }
        }
        found
    }

    /// What `stmt` does to the arguments the registers hold, noting in
    /// `found` the slots it fills and the registers written once it sets.
    fn step(&self, stmt: &Stmt, origin: &mut HashMap<u16, u16>, found: Option<&mut Found>) {
        match stmt {
            Stmt::Store {
                addr,
                value,
                width: 8,
            } => {
                if let Some((_, slots)) = found {
                    let from = match value {
                        Expr::Reg { index, .. } => origin.get(index).copied(),
                        _ => None,
                    };
                    let slot = slots.entry(format!("{addr:?}")).or_insert(from);
                    if *slot != from {
                        *slot = None;
                    }
                }
            }
            Stmt::Assign { dest, value } => {
                let source = match value {
                    Expr::Load { addr, width: 8, .. } => {
                        self.slots.get(&format!("{addr:?}")).copied().flatten()
                    }
                    _ if self.exact => copy_origin(value, origin),
                    _ => base_origin(value, origin),
                };
                match source {
                    Some(source) => {
                        origin.insert(dest.index, source);
                        if let Some((global, _)) = found
                            && self.definitions.get(&dest.index) == Some(&1)
                        {
                            global.insert(dest.index, source);
                        }
                    }
                    None => {
                        origin.remove(&dest.index);
                    }
                }
            }
            Stmt::Machine { outputs, .. } => {
                for output in outputs {
                    origin.remove(&output.index);
                }
            }
            Stmt::Call { .. } => {
                let preserved: Vec<_> = stmt
                    .preserved_output_sources()
                    .into_iter()
                    .filter_map(|(output, source)| {
                        let dest = stmt.call_outputs()[output].dest;
                        if dest.width != 64 {
                            return None;
                        }
                        origin.get(&source).map(|source| (dest.index, *source))
                    })
                    .collect();
                for register in crate::ir::visit::statement_registers(stmt).0 {
                    origin.remove(&register);
                }
                origin.extend(preserved);
            }
            _ => {}
        }
    }
}

/// The loads integer arithmetic reads, outside any float or vector operation.
fn integer_loads<'e>(expr: &'e Expr, out: &mut Vec<(&'e Expr, u8)>) {
    match expr {
        Expr::Load { addr, width, .. } => out.push((addr.as_ref(), *width)),
        Expr::Apply { .. } => {}
        other => {
            for child in crate::ir::visit::children(other) {
                integer_loads(child, out);
            }
        }
    }
}

/// The argument a register, or its low half, holds.
fn copy_origin(expr: &Expr, origin: &HashMap<u16, u16>) -> Option<u16> {
    match expr {
        Expr::Reg { index, .. } => origin.get(index).copied(),
        Expr::Bin {
            op: crate::ir::BinOp::And,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) => copy_origin(lhs, origin),
        _ => None,
    }
}

fn base_origin(expr: &Expr, origin: &HashMap<u16, u16>) -> Option<u16> {
    match expr {
        Expr::Reg { index, .. } => origin.get(index).copied(),
        Expr::Bin {
            op: crate::ir::BinOp::Add | crate::ir::BinOp::Sub,
            lhs,
            ..
        } => base_origin(lhs, origin),
        _ => None,
    }
}

/// How an operation reads its arguments: as floats (`None`), or as lanes
/// of some bytes.
fn vector_reading(op: Operation) -> Option<Option<u8>> {
    match op {
        Operation::Lanes(_, bits)
        | Operation::InterleaveLow(bits)
        | Operation::InterleaveHigh(bits)
        | Operation::Widen { bits, .. }
        | Operation::Narrow(bits)
        | Operation::SignBits(bits)
        | Operation::SumLanes(bits) => Some(Some(bits / 8)),
        _ if op.argument_precision().is_some() => Some(None),
        _ => None,
    }
}

/// The registers operations read as floats or as lanes, as
/// `vector_reading` tells them.
fn vector_operands(expr: &Expr, out: &mut HashMap<u16, Option<u8>>) {
    if let Expr::Apply { op, args } = expr
        && let Some(held) = vector_reading(*op)
    {
        for arg in args {
            let register = match arg {
                Expr::Reg { index, .. } => Some(*index),
                Expr::Bin {
                    op: crate::ir::BinOp::And,
                    lhs,
                    ..
                } => match lhs.as_ref() {
                    Expr::Reg { index, .. } => Some(*index),
                    _ => None,
                },
                _ => None,
            };
            if let Some(register) = register {
                out.entry(register).or_insert(held);
            }
        }
    }
    for child in crate::ir::visit::children(expr) {
        vector_operands(child, out);
    }
}

fn base_register(expr: &Expr) -> Option<u16> {
    match expr {
        Expr::Reg { index, .. } => Some(*index),
        Expr::Bin {
            op: crate::ir::BinOp::Add | crate::ir::BinOp::Sub,
            lhs,
            ..
        } => base_register(lhs),
        _ => None,
    }
}

fn load_of(expr: &Expr) -> Option<(&Expr, u8)> {
    match expr {
        Expr::Load { addr, width, .. } => Some((addr.as_ref(), *width)),
        Expr::SignExtend { value, .. } => load_of(value),
        Expr::Bin {
            op: crate::ir::BinOp::And,
            lhs,
            ..
        } => load_of(lhs),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::recover;
    use crate::ir::{BinOp, Block, Convention, Expr, RegRef, Stmt};
    use crate::loader::{Format, Isa};

    #[test]
    fn a_register_written_in_an_earlier_block_is_not_an_argument() {
        let blocks = vec![
            Block {
                start: 0,
                stmts: vec![Stmt::Assign {
                    dest: RegRef {
                        index: 1,
                        width: 64,
                    },
                    value: Expr::Const(7),
                }],
            },
            Block {
                start: 4,
                stmts: vec![Stmt::Ret {
                    value: Expr::bin(crate::ir::BinOp::Add, Expr::reg(0, 64), Expr::reg(1, 64)),
                }],
            },
        ];

        let signature = recover(
            &blocks,
            Isa::AArch64,
            Convention::of(Isa::AArch64, Format::Elf, false),
            false,
        );

        let params: Vec<u16> = signature.params.iter().map(|param| param.index).collect();
        assert_eq!(params, vec![0]);
    }

    #[test]
    fn an_argument_kept_in_a_stack_slot_is_typed_by_its_loads() {
        // `str x0, [sp, #8]`, then x8 holds a count before it holds the
        // argument again and a load goes through it.
        let slot = Expr::bin(crate::ir::BinOp::Add, Expr::reg(31, 64), Expr::Const(8));
        let assign = |index, value| Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
        };
        let load = |addr: Expr, width| Expr::Load {
            addr: Box::new(addr),
            width,
            signed: false,
        };
        let blocks = vec![Block {
            start: 0,
            stmts: vec![
                Stmt::Store {
                    addr: slot.clone(),
                    value: Expr::reg(0, 64),
                    width: 8,
                },
                assign(8, Expr::reg(1, 64)),
                assign(
                    9,
                    Expr::bin(crate::ir::BinOp::Add, Expr::reg(8, 64), Expr::Const(1)),
                ),
                assign(8, load(slot, 8)),
                assign(10, load(Expr::reg(8, 64), 4)),
                Stmt::Ret {
                    value: Expr::bin(crate::ir::BinOp::Add, Expr::reg(9, 64), Expr::reg(10, 64)),
                },
            ],
        }];
        let signature = recover(
            &blocks,
            Isa::AArch64,
            Convention::of(Isa::AArch64, Format::Elf, false),
            false,
        );
        let types: Vec<String> = signature
            .params
            .iter()
            .map(|param| param.ty.to_string())
            .collect();
        assert_eq!(types, vec!["uint32_t *", "uint64_t"]);
    }

    #[test]
    fn arguments_past_the_registers_are_read_from_the_callers_frame() {
        // Every integer register is read, then `push rbp; mov rbp, rsp`
        // and a load of the second stack argument through rbp.
        let sum = [7u16, 6, 2, 1, 8, 9]
            .into_iter()
            .map(|register| Expr::reg(register, 64))
            .reduce(|a, b| Expr::bin(crate::ir::BinOp::Add, a, b))
            .expect("registers");
        let assign = |index, value| Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
        };
        let blocks = vec![Block {
            start: 0,
            stmts: vec![
                assign(
                    4,
                    Expr::bin(crate::ir::BinOp::Sub, Expr::reg(4, 64), Expr::Const(8)),
                ),
                assign(5, Expr::reg(4, 64)),
                assign(
                    0,
                    Expr::Load {
                        addr: Box::new(Expr::bin(
                            crate::ir::BinOp::Add,
                            Expr::reg(5, 64),
                            Expr::Const(0x18),
                        )),
                        width: 8,
                        signed: false,
                    },
                ),
                Stmt::Ret {
                    value: Expr::bin(crate::ir::BinOp::Add, sum, Expr::reg(0, 64)),
                },
            ],
        }];
        let signature = recover(
            &blocks,
            Isa::X86_64,
            Convention::of(Isa::X86_64, Format::Elf, false),
            false,
        );
        assert_eq!(signature.params.len(), 6);
        assert_eq!(signature.stack, vec![8, 16]);
    }

    #[test]
    fn go_assembly_results_follow_the_arguments_read() {
        // The stack pointer kept in r12 across a move to another stack, two
        // arguments read through it, the second a byte, then a result
        // stored and the address of the next handed to a call.
        let load = |base: u16, offset: u64, width: u8| Expr::Load {
            addr: Box::new(Expr::bin(
                crate::ir::BinOp::Add,
                Expr::reg(base, 64),
                Expr::Const(offset),
            )),
            width,
            signed: false,
        };
        let assign = |index, value| Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
        };
        let blocks = vec![Block {
            start: 0,
            stmts: vec![
                assign(12, Expr::reg(4, 64)),
                assign(4, load(0, 0x38, 8)),
                assign(0, load(12, 8, 8)),
                assign(3, load(12, 0x10, 1)),
                assign(4, Expr::reg(12, 64)),
                Stmt::Store {
                    addr: Expr::bin(crate::ir::BinOp::Add, Expr::reg(4, 64), Expr::Const(0x18)),
                    value: Expr::reg(0, 64),
                    width: 4,
                },
                assign(
                    8,
                    Expr::bin(crate::ir::BinOp::Add, Expr::reg(4, 64), Expr::Const(0x20)),
                ),
                Stmt::Call {
                    kind: crate::ir::CallKind::Invoke,
                    target: Some(0x2000),
                    through: None,
                    convention: Convention::GoAmd64,
                    args: Some(vec![Expr::reg(3, 64), Expr::reg(8, 64)]),
                    floats_named: false,
                    abi: None,
                    clobbers: None,
                    outputs: crate::ir::fallback_call_outputs(Convention::GoAmd64, None),
                    via: None,
                },
                Stmt::Ret {
                    value: Expr::reg(0, 64),
                },
            ],
        }];
        let signature = recover(&blocks, Isa::X86_64, Convention::GoAbi0, true);
        assert_eq!(signature.stack, vec![8, 0x10]);
        assert_eq!(signature.stack_widths, vec![8, 1]);
        assert_eq!(signature.stack_results, vec![(0x18, 4), (0x20, 8)]);
    }

    fn params_of(stmts: Vec<Stmt>, isa: Isa) -> Vec<u16> {
        let blocks = vec![Block { start: 0, stmts }];
        recover(&blocks, isa, Convention::of(isa, Format::Elf, false), false)
            .params
            .iter()
            .map(|param| param.index)
            .collect()
    }

    #[test]
    fn registers_before_the_last_argument_read_are_parameters() {
        // `if (x2 == 0) return; tail call`, passing x0 and x1 on unchanged.
        let stmts = vec![
            Stmt::Brif {
                cond: crate::ir::Cond::Eq,
                lhs: Expr::reg(2, 64),
                rhs: Expr::Const(0),
                target: 0x10,
            },
            Stmt::Ret {
                value: Expr::Const(0),
            },
        ];
        assert_eq!(params_of(stmts, Isa::AArch64), vec![0, 1, 2]);
    }

    #[test]
    fn incoming_reads_follow_live_values_across_blocks() {
        let blocks = vec![
            Block {
                start: 0,
                stmts: vec![
                    stack_assign(10, Expr::reg(7, 64)),
                    stack_assign(11, Expr::reg(1, 64)),
                    Stmt::Br { target: Some(16) },
                ],
            },
            Block {
                start: 16,
                stmts: vec![Stmt::Ret {
                    value: Expr::reg(10, 64),
                }],
            },
        ];
        let signature = recover(&blocks, Isa::X86_64, Convention::SysV, false);
        assert_eq!(
            signature
                .params
                .iter()
                .map(|param| param.index)
                .collect::<Vec<_>>(),
            vec![7]
        );
        let mut expected: crate::ir::Registers =
            Convention::SysV.results().iter().copied().collect();
        expected.insert(7);
        assert_eq!(signature.inputs, Some(expected));
        let mut unknown = blocks;
        unknown[1].stmts = vec![Stmt::BrIndirect {
            target: Expr::reg(10, 64),
        }];
        assert!(
            recover(&unknown, Isa::X86_64, Convention::SysV, false)
                .inputs
                .is_none()
        );
        unknown[1].stmts = vec![Stmt::Br { target: Some(32) }];
        assert!(
            recover(&unknown, Isa::X86_64, Convention::SysV, false)
                .inputs
                .is_none()
        );
    }

    #[test]
    fn floating_results_and_unchanged_secondary_results_keep_their_inputs() {
        for (isa, convention, dest, source) in [
            (Isa::X86_64, Convention::SysV, 18, 20),
            (Isa::X86_64, Convention::SysV, 10, 20),
            (Isa::AArch64, Convention::Aapcs64, 36, 38),
            (Isa::AArch64, Convention::Aapcs64, 38, 40),
        ] {
            let signature = recover(
                &[Block {
                    start: 0,
                    stmts: vec![
                        stack_assign(dest, Expr::reg(source, 64)),
                        Stmt::Ret {
                            value: Expr::reg(0, 64),
                        },
                    ],
                }],
                isa,
                convention,
                false,
            );
            assert!(signature.params.iter().any(|param| param.index == source));
            let inputs = signature.inputs.unwrap();
            assert!(inputs.contains(source));
            assert!(inputs.contains(if isa == Isa::X86_64 { 2 } else { 1 }));
        }
    }

    #[test]
    fn go_runtime_result_registers_keep_input_reads() {
        let signature = recover(
            &[Block {
                start: 0,
                stmts: vec![
                    stack_assign(2, Expr::reg(3, 64)),
                    Stmt::Ret {
                        value: Expr::reg(0, 64),
                    },
                ],
            }],
            Isa::AArch64,
            Convention::Aapcs64,
            true,
        );
        assert!(signature.params.iter().any(|param| param.index == 3));
        assert!(signature.inputs.is_none());
    }

    #[test]
    fn preserved_tail_call_outputs_are_inputs_only_when_read() {
        use crate::ir::{CallKind, CallOutput, Registers};
        for read in [None, Some(3)] {
            let mut stmts = vec![
                Stmt::Call {
                    abi: None,
                    kind: if read.is_some() {
                        CallKind::Invoke
                    } else {
                        CallKind::Tail
                    },
                    target: Some(0x1000),
                    through: None,
                    convention: Convention::Aapcs64,
                    args: Some(vec![Expr::reg(0, 64)]),
                    floats_named: true,
                    clobbers: Some(Registers(1)),
                    outputs: (0..4)
                        .map(|index| CallOutput {
                            register: index,
                            dest: RegRef { index, width: 64 },
                        })
                        .collect(),
                    via: None,
                },
                Stmt::Ret {
                    value: Expr::Const(0),
                },
            ];
            if let Some(index) = read {
                stmts.insert(
                    1,
                    Stmt::Store {
                        addr: Expr::Const(0x2000),
                        value: Expr::reg(index, 64),
                        width: 8,
                    },
                );
            }
            assert_eq!(
                params_of(stmts, Isa::AArch64),
                if read.is_some() {
                    vec![0, 1, 2, 3]
                } else {
                    vec![0]
                }
            );
        }
    }

    #[test]
    fn the_kept_bits_of_a_partial_write_are_no_argument() {
        // cl = dil: rcx keeps its upper bits, which the body never uses.
        let stmts = vec![
            Stmt::Assign {
                dest: RegRef {
                    index: 1,
                    width: 64,
                },
                value: Expr::bin(
                    crate::ir::BinOp::Or,
                    Expr::bin(crate::ir::BinOp::And, Expr::reg(1, 64), Expr::Const(!0xff)),
                    Expr::bin(crate::ir::BinOp::And, Expr::reg(7, 64), Expr::Const(0xff)),
                ),
            },
            Stmt::Ret {
                value: Expr::bin(crate::ir::BinOp::And, Expr::reg(1, 64), Expr::Const(0xff)),
            },
        ];
        assert_eq!(params_of(stmts, Isa::X86_64), vec![7]);
    }

    fn stack_address(base: u16, offset: i64) -> Expr {
        Expr::bin(BinOp::Add, Expr::reg(base, 64), Expr::Const(offset as u64))
    }

    fn stack_load(base: u16, offset: i64, width: u8) -> Expr {
        Expr::Load {
            addr: Box::new(stack_address(base, offset)),
            width,
            signed: false,
        }
    }

    fn stack_assign(index: u16, value: Expr) -> Stmt {
        Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
        }
    }

    fn stack_store(base: u16, offset: i64, width: u8) -> Stmt {
        Stmt::Store {
            addr: stack_address(base, offset),
            value: Expr::Const(7),
            width,
        }
    }

    fn recover_aapcs_stack(stmts: Vec<Stmt>) -> super::Signature {
        recover(
            &[Block { start: 0, stmts }],
            Isa::AArch64,
            Convention::Aapcs64,
            false,
        )
    }

    #[test]
    fn go_stack_arguments_exclude_register_spills() {
        let signature = recover(
            &[Block {
                start: 0,
                stmts: vec![
                    stack_store(4, 16, 8),
                    stack_assign(
                        12,
                        Expr::bin(
                            BinOp::Add,
                            Expr::reg(0, 64),
                            Expr::bin(BinOp::Add, stack_load(4, 8, 8), stack_load(4, 16, 8)),
                        ),
                    ),
                    Stmt::Ret {
                        value: Expr::reg(12, 64),
                    },
                ],
            }],
            Isa::X86_64,
            Convention::GoAmd64,
            true,
        );
        assert_eq!(signature.stack, vec![8]);
        assert!(signature.stack_results.is_empty());
        assert!(signature.params.iter().any(|param| param.index == 0));
    }

    #[test]
    fn incoming_stack_arguments_do_not_require_every_integer_register() {
        let registers = (0..7)
            .map(|index| Expr::reg(index, 64))
            .reduce(|lhs, rhs| Expr::bin(BinOp::Add, lhs, rhs))
            .unwrap();
        for framed in [false, true] {
            let mut stmts = Vec::new();
            let (base, displacement) = if framed {
                stmts.extend([
                    stack_assign(
                        31,
                        Expr::bin(BinOp::Sub, Expr::reg(31, 64), Expr::Const(48)),
                    ),
                    stack_store(31, 0, 8),
                    stack_store(31, 8, 8),
                    stack_assign(29, Expr::reg(31, 64)),
                ]);
                (29, 48)
            } else {
                (31, 0)
            };
            let value = [0, 8, 16]
                .into_iter()
                .fold(registers.clone(), |sum, offset| {
                    Expr::bin(BinOp::Add, sum, stack_load(base, displacement + offset, 8))
                });
            stmts.push(stack_assign(12, value));
            stmts.push(Stmt::Ret {
                value: Expr::reg(12, 64),
            });
            let signature = recover_aapcs_stack(stmts);
            assert_eq!(
                signature
                    .params
                    .iter()
                    .map(|param| param.index)
                    .collect::<Vec<_>>(),
                vec![0, 1, 2, 3, 4, 5, 6]
            );
            assert_eq!(signature.stack, vec![0, 8, 16]);
            assert_eq!(signature.stack_widths, vec![8, 8, 8]);
            assert!(!signature.aggregate);
        }
    }

    #[test]
    fn private_spills_saved_registers_and_return_addresses_are_not_arguments() {
        let signature = recover_aapcs_stack(vec![
            stack_assign(
                31,
                Expr::bin(BinOp::Sub, Expr::reg(31, 64), Expr::Const(32)),
            ),
            Stmt::Store {
                addr: stack_address(31, 0),
                value: Expr::reg(29, 64),
                width: 8,
            },
            Stmt::Store {
                addr: stack_address(31, 8),
                value: Expr::reg(30, 64),
                width: 8,
            },
            Stmt::Store {
                addr: stack_address(31, 16),
                value: Expr::reg(0, 64),
                width: 8,
            },
            Stmt::Ret {
                value: Expr::bin(
                    BinOp::Add,
                    Expr::bin(BinOp::Add, stack_load(31, 0, 8), stack_load(31, 8, 8)),
                    stack_load(31, 16, 8),
                ),
            },
        ]);
        assert!(signature.stack.is_empty());
        assert_eq!(
            signature
                .params
                .iter()
                .map(|param| param.index)
                .collect::<Vec<_>>(),
            vec![0]
        );
        let signature = recover(
            &[Block {
                start: 0,
                stmts: vec![Stmt::Ret {
                    value: stack_load(4, 0, 8),
                }],
            }],
            Isa::X86_64,
            Convention::SysV,
            false,
        );
        assert!(signature.stack.is_empty());
    }

    #[test]
    fn incoming_stack_bytes_written_before_their_first_read_are_not_inputs() {
        for width in [1, 4, 8] {
            let signature = recover_aapcs_stack(vec![
                stack_store(31, 0, width),
                Stmt::Ret {
                    value: stack_load(31, 0, 8),
                },
            ]);
            if width == 8 {
                assert!(signature.stack.is_empty());
            } else {
                assert_eq!(signature.stack, vec![0]);
            }
            let signature = recover_aapcs_stack(vec![
                stack_store(31, 0, width),
                Stmt::Ret {
                    value: stack_load(31, 0, width),
                },
            ]);
            assert!(signature.stack.is_empty());
        }
        let signature = recover_aapcs_stack(vec![
            stack_assign(9, stack_load(31, 0, 8)),
            stack_store(31, 0, 8),
            Stmt::Ret {
                value: Expr::reg(9, 64),
            },
        ]);
        assert_eq!(signature.stack, vec![0]);
        let signature = recover_aapcs_stack(vec![
            Stmt::Store {
                addr: stack_address(31, 0),
                value: stack_load(31, 0, 8),
                width: 8,
            },
            Stmt::Ret {
                value: Expr::Const(0),
            },
        ]);
        assert_eq!(signature.stack, vec![0]);
    }

    #[test]
    fn a_stack_write_must_cover_every_predecessor_to_remove_an_input() {
        for both in [false, true] {
            let mut left = Vec::new();
            if both {
                left.push(stack_store(31, 0, 8));
            }
            left.push(Stmt::Br { target: Some(24) });
            let blocks = vec![
                Block {
                    start: 0,
                    stmts: vec![Stmt::Brif {
                        cond: crate::ir::Cond::Eq,
                        lhs: Expr::reg(0, 64),
                        rhs: Expr::Const(0),
                        target: 16,
                    }],
                },
                Block {
                    start: 8,
                    stmts: left,
                },
                Block {
                    start: 16,
                    stmts: vec![stack_store(31, 0, 8), Stmt::Br { target: Some(24) }],
                },
                Block {
                    start: 24,
                    stmts: vec![Stmt::Ret {
                        value: stack_load(31, 0, 8),
                    }],
                },
            ];
            let signature = recover(&blocks, Isa::AArch64, Convention::Aapcs64, false);
            assert_eq!(signature.stack, if both { vec![] } else { vec![0] });
            assert!(!signature.aggregate);
        }
    }

    #[test]
    fn unknown_stack_adjustments_preserve_only_a_stable_frame_pointer() {
        let dynamic = || {
            stack_assign(
                31,
                Expr::bin(BinOp::Sub, Expr::reg(31, 64), Expr::reg(0, 64)),
            )
        };
        let signature = recover_aapcs_stack(vec![
            dynamic(),
            Stmt::Ret {
                value: stack_load(31, 16, 8),
            },
        ]);
        assert!(signature.stack.is_empty());
        let signature = recover_aapcs_stack(vec![
            stack_assign(
                31,
                Expr::bin(BinOp::Sub, Expr::reg(31, 64), Expr::Const(32)),
            ),
            stack_assign(29, Expr::reg(31, 64)),
            dynamic(),
            Stmt::Ret {
                value: stack_load(29, 32, 8),
            },
        ]);
        assert_eq!(signature.stack, vec![0]);
        let signature = recover_aapcs_stack(vec![Stmt::Ret {
            value: Expr::Load {
                addr: Box::new(Expr::bin(BinOp::Add, Expr::reg(31, 64), Expr::reg(1, 64))),
                width: 8,
                signed: false,
            },
        }]);
        assert!(signature.stack.is_empty());
    }

    #[test]
    fn only_surviving_stack_address_aliases_are_followed_across_calls() {
        for index in [9, 19] {
            let signature = recover_aapcs_stack(vec![
                stack_assign(index, stack_address(31, 0)),
                Stmt::Call {
                    kind: crate::ir::CallKind::Invoke,
                    target: Some(0x2000),
                    through: None,
                    convention: Convention::Aapcs64,
                    args: Some(vec![]),
                    floats_named: false,
                    abi: None,
                    clobbers: None,
                    outputs: crate::ir::fallback_call_outputs(Convention::Aapcs64, None),
                    via: None,
                },
                Stmt::Ret {
                    value: stack_load(index, 0, 8),
                },
            ]);
            assert_eq!(signature.stack, if index == 19 { vec![0] } else { vec![] });
        }
    }

    #[test]
    fn incoming_stack_recovery_keeps_its_frame_bound() {
        for offset in [-8, 512] {
            let signature = recover_aapcs_stack(vec![Stmt::Ret {
                value: stack_load(31, offset, 8),
            }]);
            assert!(signature.stack.is_empty());
        }
        let signature = recover_aapcs_stack(vec![Stmt::Ret {
            value: stack_load(31, 504, 8),
        }]);
        assert_eq!(signature.stack.len(), 64);
        assert_eq!(signature.stack.last(), Some(&504));
    }

    #[test]
    fn incoming_stack_write_proofs_include_switch_and_flag_edges() {
        for branch in [
            Stmt::Switch {
                index: Expr::reg(0, 64),
                cases: vec![(0, 8)],
                default: Some(16),
            },
            Stmt::BrifFlags {
                cond: crate::ir::Cond::Eq,
                target: 16,
            },
        ] {
            let blocks = vec![
                Block {
                    start: 0,
                    stmts: vec![branch],
                },
                Block {
                    start: 8,
                    stmts: vec![stack_store(31, 0, 8), Stmt::Br { target: Some(24) }],
                },
                Block {
                    start: 16,
                    stmts: vec![Stmt::Br { target: Some(24) }],
                },
                Block {
                    start: 24,
                    stmts: vec![Stmt::Ret {
                        value: stack_load(31, 0, 8),
                    }],
                },
            ];
            let signature = recover(&blocks, Isa::AArch64, Convention::Aapcs64, false);
            assert_eq!(signature.stack, vec![0]);
        }
        let blocks = vec![
            Block {
                start: 0,
                stmts: vec![Stmt::Br { target: None }],
            },
            Block {
                start: 8,
                stmts: vec![Stmt::Ret {
                    value: stack_load(31, 0, 8),
                }],
            },
        ];
        assert_eq!(
            recover(&blocks, Isa::AArch64, Convention::Aapcs64, false).stack,
            vec![0]
        );
    }

    #[test]
    fn truncated_frame_addresses_and_overrunning_loads_remain_unknown() {
        let signature = recover_aapcs_stack(vec![
            Stmt::Assign {
                dest: RegRef {
                    index: 29,
                    width: 32,
                },
                value: Expr::reg(31, 64),
            },
            Stmt::Ret {
                value: stack_load(29, 0, 8),
            },
        ]);
        assert!(signature.stack.is_empty());
        for (offset, width) in [(511, 2), (504, 16), (0, 0)] {
            let signature = recover_aapcs_stack(vec![Stmt::Ret {
                value: stack_load(31, offset, width),
            }]);
            assert!(signature.stack.is_empty());
        }
    }

    #[test]
    fn unsupported_stack_widths_do_not_establish_input_or_overwrite_proofs() {
        let signature = recover_aapcs_stack(vec![Stmt::Ret {
            value: stack_load(31, 0, 3),
        }]);
        assert!(signature.stack.is_empty());
        let signature = recover_aapcs_stack(vec![
            stack_store(31, 0, 3),
            Stmt::Ret {
                value: stack_load(31, 0, 2),
            },
        ]);
        assert_eq!(signature.stack, vec![0]);
    }

    fn cfg_call() -> Stmt {
        Stmt::Call {
            kind: crate::ir::CallKind::Invoke,
            target: Some(0x1000),
            through: None,
            convention: Convention::Aapcs64,
            args: Some(Vec::new()),
            floats_named: true,
            abi: None,
            outputs: crate::ir::fallback_call_outputs(Convention::Aapcs64, None),
            clobbers: None,
            via: None,
        }
    }

    fn cfg_stack(blocks: &[Block], pads: &[(u64, Vec<(u64, u64)>)]) -> Vec<i64> {
        super::stack_arguments(blocks, pads, Isa::AArch64, Convention::Aapcs64).offsets
    }

    #[test]
    fn preserved_output_addresses_keep_their_pre_call_origin() {
        let destination = crate::ir::VARIABLE_BASE;
        for preserved in [false, true] {
            let mut call = cfg_call();
            let Stmt::Call {
                outputs, clobbers, ..
            } = &mut call
            else {
                unreachable!()
            };
            *clobbers = Some(if preserved {
                Default::default()
            } else {
                [0].into_iter().collect()
            });
            *outputs = vec![crate::ir::CallOutput {
                register: 0,
                dest: RegRef {
                    index: destination,
                    width: 64,
                },
            }];
            let signature = recover_aapcs_stack(vec![
                stack_assign(0, stack_address(31, 0)),
                call,
                Stmt::Ret {
                    value: stack_load(destination, 0, 8),
                },
            ]);
            assert_eq!(signature.stack, if preserved { vec![0] } else { vec![] });
        }
    }

    #[test]
    fn first_entry_reads_survive_unknown_backedges_without_adding_results() {
        for (isa, convention, sp, start) in [
            (Isa::AArch64, Convention::Aapcs64, 31, 0),
            (Isa::X86_64, Convention::GoAbi0, 4, 8),
        ] {
            for width in [1, 8] {
                let blocks = vec![
                    Block {
                        start: 0,
                        stmts: vec![
                            stack_assign(sp, stack_address(sp, -16)),
                            stack_assign(12, stack_load(sp, start + 16, width)),
                            stack_store(sp, start + 16, 8),
                            stack_store(sp, start + 24, 8),
                            Stmt::Br { target: Some(8) },
                        ],
                    },
                    Block {
                        start: 8,
                        stmts: vec![
                            stack_assign(sp, Expr::reg(0, 64)),
                            Stmt::BrIndirect {
                                target: Expr::reg(1, 64),
                            },
                        ],
                    },
                ];
                let frame = super::stack_arguments(&blocks, &[], isa, convention);
                assert_eq!(frame.offsets, vec![start]);
                assert_eq!(
                    frame.widths,
                    vec![if convention == Convention::GoAbi0 {
                        width
                    } else {
                        8
                    }]
                );
                assert!(frame.results.is_empty());
            }
        }
    }

    #[test]
    fn first_entry_overwrites_keep_their_byte_coverage() {
        for (stored, loaded, needed) in [(8, 8, false), (4, 8, true), (1, 8, true), (8, 4, false)] {
            let blocks = vec![
                Block {
                    start: 0,
                    stmts: vec![
                        stack_store(31, 0, stored),
                        stack_assign(12, stack_load(31, 0, loaded)),
                        Stmt::Br { target: Some(8) },
                    ],
                },
                Block {
                    start: 8,
                    stmts: vec![
                        stack_assign(31, Expr::reg(0, 64)),
                        Stmt::BrIndirect {
                            target: Expr::reg(1, 64),
                        },
                    ],
                },
            ];
            assert_eq!(
                cfg_stack(&blocks, &[]),
                if needed { vec![0] } else { vec![] }
            );
        }
    }

    #[test]
    fn first_entry_scan_keeps_reads_before_an_opaque_frame_change_only() {
        for early in [false, true] {
            let mut first = Vec::new();
            if early {
                first.push(stack_assign(12, stack_load(31, 0, 8)));
            }
            first.extend([
                Stmt::Unsupported {
                    text: "opaque frame change".to_owned(),
                    writes: Some(vec![31]),
                },
                stack_assign(13, stack_load(31, 16, 8)),
                Stmt::Br { target: Some(8) },
            ]);
            let blocks = vec![
                Block {
                    start: 0,
                    stmts: first,
                },
                Block {
                    start: 8,
                    stmts: vec![Stmt::BrIndirect {
                        target: Expr::reg(1, 64),
                    }],
                },
            ];
            assert_eq!(
                cfg_stack(&blocks, &[]),
                if early { vec![0] } else { vec![] }
            );
        }
    }

    #[test]
    fn unknown_predecessors_meet_frame_and_written_facts() {
        for indirect in [false, true] {
            for changed_sp in [false, true] {
                let mut unknown = Vec::new();
                if changed_sp {
                    unknown.push(stack_assign(31, stack_address(31, 16)));
                }
                unknown.push(if indirect {
                    Stmt::BrIndirect {
                        target: Expr::reg(1, 64),
                    }
                } else {
                    Stmt::Br { target: None }
                });
                let blocks = vec![
                    Block {
                        start: 0,
                        stmts: vec![Stmt::Brif {
                            cond: crate::ir::Cond::Eq,
                            lhs: Expr::reg(0, 64),
                            rhs: Expr::Const(0),
                            target: 16,
                        }],
                    },
                    Block {
                        start: 8,
                        stmts: vec![stack_store(31, 0, 8), Stmt::Br { target: Some(24) }],
                    },
                    Block {
                        start: 16,
                        stmts: unknown,
                    },
                    Block {
                        start: 24,
                        stmts: vec![Stmt::Ret {
                            value: stack_load(31, 0, 8),
                        }],
                    },
                ];
                assert_eq!(
                    cfg_stack(&blocks, &[]),
                    if changed_sp { vec![] } else { vec![0] }
                );
            }
        }
        for before in [false, true] {
            let mut first = Vec::new();
            if before {
                first.push(stack_store(31, 0, 8));
            }
            first.push(Stmt::BrIndirect {
                target: Expr::reg(1, 64),
            });
            let blocks = vec![
                Block {
                    start: 0,
                    stmts: first,
                },
                Block {
                    start: 8,
                    stmts: vec![Stmt::Ret {
                        value: stack_load(31, 0, 8),
                    }],
                },
            ];
            assert_eq!(
                cfg_stack(&blocks, &[]),
                if before { vec![] } else { vec![0] }
            );
        }
    }

    #[test]
    fn normal_and_exception_predecessors_must_both_overwrite() {
        for both in [false, true] {
            let mut pad = Vec::new();
            if both {
                pad.push(stack_store(31, 0, 8));
            }
            pad.push(Stmt::Br { target: Some(12) });
            let blocks = vec![
                Block {
                    start: 0,
                    stmts: vec![cfg_call()],
                },
                Block {
                    start: 4,
                    stmts: vec![stack_store(31, 0, 8), Stmt::Br { target: Some(12) }],
                },
                Block {
                    start: 8,
                    stmts: pad,
                },
                Block {
                    start: 12,
                    stmts: vec![Stmt::Ret {
                        value: stack_load(31, 0, 8),
                    }],
                },
            ];
            assert_eq!(
                cfg_stack(&blocks, &[(8, vec![(0, 4)])]),
                if both { vec![] } else { vec![0] }
            );
        }
    }

    #[test]
    fn exception_states_meet_call_prefixes_instead_of_the_block_exit() {
        for before in [false, true] {
            for second_call in [false, true] {
                let mut first = Vec::new();
                if before {
                    first.push(stack_store(31, 0, 8));
                }
                first.extend([cfg_call(), stack_store(31, 0, 8)]);
                if second_call {
                    first.push(cfg_call());
                }
                first.push(Stmt::Br { target: Some(16) });
                let blocks = vec![
                    Block {
                        start: 0,
                        stmts: first,
                    },
                    Block {
                        start: 8,
                        stmts: vec![Stmt::Br { target: Some(16) }],
                    },
                    Block {
                        start: 16,
                        stmts: vec![Stmt::Ret {
                            value: stack_load(31, 0, 8),
                        }],
                    },
                ];
                assert_eq!(
                    cfg_stack(&blocks, &[(8, vec![(0, 8)])]),
                    if before { vec![] } else { vec![0] }
                );
            }
        }
    }

    #[test]
    fn exception_frame_origins_use_the_call_point() {
        for second_call in [false, true] {
            let mut first = vec![cfg_call(), stack_assign(31, stack_address(31, 16))];
            if second_call {
                first.push(cfg_call());
            }
            let blocks = vec![
                Block {
                    start: 0,
                    stmts: first,
                },
                Block {
                    start: 8,
                    stmts: vec![
                        stack_assign(31, stack_address(31, -16)),
                        Stmt::Br { target: Some(24) },
                    ],
                },
                Block {
                    start: 16,
                    stmts: vec![Stmt::Br { target: Some(24) }],
                },
                Block {
                    start: 24,
                    stmts: vec![Stmt::Ret {
                        value: stack_load(31, 0, 8),
                    }],
                },
            ];
            assert_eq!(
                cfg_stack(&blocks, &[(16, vec![(0, 8)])]),
                if second_call { vec![] } else { vec![0] }
            );
        }
    }

    #[test]
    fn missing_exception_targets_cannot_certify_the_normal_store() {
        let blocks = vec![
            Block {
                start: 0,
                stmts: vec![cfg_call(), stack_store(31, 0, 8)],
            },
            Block {
                start: 8,
                stmts: vec![Stmt::Ret {
                    value: stack_load(31, 0, 8),
                }],
            },
        ];
        assert_eq!(cfg_stack(&blocks, &[(0x100, vec![(0, 8)])]), vec![0]);
    }

    #[test]
    fn loop_backedges_do_not_replace_the_initial_unwritten_state() {
        for before in [false, true] {
            let mut first = Vec::new();
            if before {
                first.push(stack_store(31, 0, 8));
            }
            first.push(Stmt::Br { target: Some(8) });
            let blocks = vec![
                Block {
                    start: 0,
                    stmts: first,
                },
                Block {
                    start: 8,
                    stmts: vec![
                        stack_assign(9, stack_load(31, 0, 8)),
                        stack_store(31, 0, 8),
                        Stmt::Brif {
                            cond: crate::ir::Cond::Ne,
                            lhs: Expr::reg(0, 64),
                            rhs: Expr::Const(0),
                            target: 8,
                        },
                    ],
                },
                Block {
                    start: 16,
                    stmts: vec![Stmt::Ret {
                        value: Expr::reg(9, 64),
                    }],
                },
            ];
            assert_eq!(
                cfg_stack(&blocks, &[]),
                if before { vec![] } else { vec![0] }
            );
        }
    }

    #[test]
    fn an_exception_range_spanning_call_blocks_keeps_the_earlier_call() {
        for before in [false, true] {
            let mut first = Vec::new();
            if before {
                first.push(stack_store(31, 0, 8));
            }
            first.push(cfg_call());
            let blocks = vec![
                Block {
                    start: 0,
                    stmts: first,
                },
                Block {
                    start: 8,
                    stmts: vec![stack_store(31, 0, 8)],
                },
                Block {
                    start: 16,
                    stmts: vec![cfg_call(), Stmt::Br { target: Some(32) }],
                },
                Block {
                    start: 24,
                    stmts: vec![Stmt::Br { target: Some(32) }],
                },
                Block {
                    start: 32,
                    stmts: vec![Stmt::Ret {
                        value: stack_load(31, 0, 8),
                    }],
                },
            ];
            assert_eq!(
                cfg_stack(&blocks, &[(24, vec![(0, 24)])]),
                if before { vec![] } else { vec![0] }
            );
        }
    }

    #[test]
    fn an_entry_backedge_keeps_the_external_unwritten_root() {
        let blocks = vec![
            Block {
                start: 0,
                stmts: vec![
                    stack_assign(9, stack_load(31, 0, 8)),
                    stack_store(31, 0, 8),
                    Stmt::Brif {
                        cond: crate::ir::Cond::Ne,
                        lhs: Expr::reg(0, 64),
                        rhs: Expr::Const(0),
                        target: 0,
                    },
                ],
            },
            Block {
                start: 8,
                stmts: vec![Stmt::Ret {
                    value: Expr::reg(9, 64),
                }],
            },
        ];
        assert_eq!(cfg_stack(&blocks, &[]), vec![0]);
    }

    #[test]
    fn opaque_exception_effects_remove_the_call_prefix_origin() {
        for opaque in [false, true] {
            let mut first = vec![cfg_call()];
            if opaque {
                first.push(Stmt::Unsupported {
                    text: "opaque".to_owned(),
                    writes: Some(Vec::new()),
                });
            }
            first.extend([stack_store(31, 0, 8), Stmt::Br { target: Some(16) }]);
            let blocks = vec![
                Block {
                    start: 0,
                    stmts: first,
                },
                Block {
                    start: 8,
                    stmts: vec![Stmt::Ret {
                        value: stack_load(31, 0, 8),
                    }],
                },
                Block {
                    start: 16,
                    stmts: vec![Stmt::Ret {
                        value: stack_load(31, 0, 8),
                    }],
                },
            ];
            assert_eq!(
                cfg_stack(&blocks, &[(8, vec![(0, 8)])]),
                if opaque { vec![] } else { vec![0] }
            );
        }
    }
    #[test]
    fn declared_calls_do_not_offer_positional_parameter_types() {
        let image = crate::loader::Image::from_code(Isa::AArch64, 0, Vec::new());
        for attached in [false, true] {
            let mut call = crate::lift::call(
                crate::ir::CallKind::Invoke,
                &image,
                &|_| Default::default(),
                Some(0x1000),
            );
            let Stmt::Call {
                args,
                floats_named,
                abi,
                ..
            } = &mut call
            else {
                unreachable!()
            };
            *args = Some(vec![Expr::reg(0, 64)]);
            *floats_named = true;
            *abi = attached.then(|| crate::ir::calls::test_call_abi(vec![0], false));
            let signature = super::recover_with(
                &[Block {
                    start: 0,
                    stmts: vec![call],
                }],
                &[],
                Isa::AArch64,
                Convention::Aapcs64,
                false,
                &|_| crate::analysis::prototypes::of("free", false),
            );
            let param = signature
                .params
                .iter()
                .find(|param| param.index == 0)
                .expect("forwarded parameter");
            assert_eq!(param.ty.is_pointer(), !attached);
        }
    }
}

//! Heuristic calling-convention and parameter recovery from lifted IR.

use std::collections::{HashMap, HashSet};

use crate::analysis::prototypes::{Prototype, preferred};
use crate::ir::{Access, Block, CType, Convention, Expr, Operation, Param, Stmt};
use crate::loader::Isa;

mod paths;
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
const GO_CLOSURE_REGISTER: u16 = 2;

/// The prototype of the library function a call reaches, when known.
pub type CalleePrototypeLookup<'a> = &'a dyn Fn(&Stmt) -> Option<&'static Prototype>;

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
    callees: CalleePrototypeLookup<'_>,
) -> Signature {
    let (arguments, float_arguments) = match isa {
        Isa::Unsupported => (&[][..], &[][..]),
        _ => (convention.arguments(), convention.float_arguments()),
    };
    let RegisterInputs {
        inputs,
        incoming,
        wide_inputs,
        known_inputs,
    } = register_inputs(
        blocks,
        landing_pads,
        isa,
        convention,
        go,
        arguments,
        float_arguments,
    );

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
    if go && isa == Isa::X86_64 && inputs.contains(&GO_CLOSURE_REGISTER) {
        params.push(Param {
            index: GO_CLOSURE_REGISTER,
            name: "closure".to_owned(),
            ty: CType::pointer_to(CType::Void),
        });
    }

    let signed_args = parameter_types(blocks, isa, callees, &mut params);

    let ret = crate::ir::cfg::own_return(blocks).map_or(CType::U64, expression_type);

    let accesses = parameter_accesses(blocks, &params);

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

fn parameter_types(
    blocks: &[Block],
    isa: Isa,
    callees: CalleePrototypeLookup<'_>,
    params: &mut [Param],
) -> HashSet<u16> {
    if params.is_empty() {
        return HashSet::new();
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
                for register in crate::ir::visit::statement_writes(stmt) {
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
    let note_integer_loads =
        |value: &Expr, origin: &HashMap<u16, u16>, elements: &mut HashMap<u16, (bool, CType)>| {
            let mut nested = Vec::new();
            integer_loads(value, &mut nested);
            for (addr, width) in nested {
                note(addr, width, None, None, origin, elements);
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
                note_integer_loads(value, origin, &mut pointer_elements);
            }
            // A float operation reading memory reads a float there, and a
            // lane operation lanes.
            if let Expr::Apply { op, args } = partial_write_source(value, dest.index) {
                let read_as = vector_operand_type(*op);
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
                note_integer_loads(value, origin, &mut pointer_elements);
            }
        }
        Stmt::Ret { value } => {
            note_integer_loads(value, origin, &mut pointer_elements);
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
    for param in params.iter_mut() {
        if let Some((_, element)) = pointer_elements.get(&param.index) {
            param.ty = CType::pointer_to(element.clone());
        } else if code_pointers.contains(&param.index) {
            param.ty = CType::pointer_to(CType::Void);
        }
    }
    let offered = prototype_types(blocks, &settle(true), callees);
    for param in params.iter_mut() {
        if let Some(ty) = offered.get(&param.index) {
            crate::analysis::typing::settle_param(param, ty);
        }
    }

    signed_parameters(blocks, &origins)
}

fn signed_parameters(blocks: &[Block], origins: &Origins) -> HashSet<u16> {
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

    signed_args
}

fn parameter_accesses(blocks: &[Block], params: &[Param]) -> Vec<Access> {
    if params.is_empty() {
        return Vec::new();
    }
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
    params
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
        .collect()
}

struct RegisterInputs {
    inputs: HashSet<u16>,
    incoming: crate::ir::Registers,
    wide_inputs: HashSet<u16>,
    known_inputs: bool,
}

fn register_inputs(
    blocks: &[Block],
    landing_pads: &[(u64, Vec<(u64, u64)>)],
    isa: Isa,
    convention: Convention,
    go: bool,
    arguments: &[u16],
    float_arguments: &[u16],
) -> RegisterInputs {
    // AArch64's indirect result register is no argument, but whether the
    // body reads it says whether the function returns through memory.
    let indirect = match isa {
        Isa::AArch64 => Some(8),
        // Go passes a closure's context in rdx.
        Isa::X86_64 if go => Some(GO_CLOSURE_REGISTER),
        _ => None,
    };
    let universe: HashSet<u16> = arguments
        .iter()
        .chain(float_arguments)
        .copied()
        .chain(indirect)
        .collect();

    let predecessors = register_predecessors(blocks);

    // Internal calls can preserve argument registers the ABI permits them
    // to change. Their summaries determine which entry values survive.
    let call_writes = |stmt: &Stmt| match stmt {
        Stmt::Call { convention, .. } => {
            let mut written: Vec<_> = crate::ir::visit::statement_writes(stmt)
                .into_iter()
                .collect();
            if go || *convention == Convention::Aapcs64 {
                // Save/restore reads can otherwise introduce extra arguments.
                written.extend(convention.clobbered().iter().copied().filter(|register| {
                    !stmt
                        .call_outputs()
                        .iter()
                        .any(|output| output.register == *register)
                }));
            }
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
    let path_writes = if known_inputs {
        let writes: Vec<Vec<_>> = blocks
            .iter()
            .map(|block| {
                block
                    .stmts
                    .iter()
                    .map(|stmt| match stmt {
                        Stmt::Call { .. } => call_writes(stmt).into_iter().collect(),
                        Stmt::Unsupported { .. } => float_arguments.iter().copied().collect(),
                        _ => crate::ir::visit::statement_writes(stmt),
                    })
                    .collect()
            })
            .collect();
        paths::definite_writes(blocks, &writes)
    } else {
        None
    };
    for (index, block) in blocks.iter().enumerate() {
        let mut written = entry[index].clone();
        for (position, stmt) in block.stmts.iter().enumerate() {
            if let Some(paths) = &path_writes {
                let Some(before) = &paths[index][position] else {
                    continue;
                };
                written.clone_from(before);
            }
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

    RegisterInputs {
        inputs,
        incoming,
        wide_inputs,
        known_inputs,
    }
}

fn register_predecessors(blocks: &[Block]) -> Vec<Vec<usize>> {
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

    predecessors
}

/// The types library functions give the arguments the body passes them
/// unchanged, by argument register.
fn prototype_types(
    blocks: &[Block],
    origins: &Origins,
    callees: CalleePrototypeLookup<'_>,
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
type FoundOrigins = (HashMap<u16, u16>, HashMap<String, Option<u16>>);

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
    fn walk(
        &self,
        blocks: &[Block],
        visit: &mut dyn FnMut(&Stmt, &HashMap<u16, u16>),
    ) -> FoundOrigins {
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
                || blocks
                    .iter()
                    .flat_map(|block| &block.stmts)
                    .any(|stmt| crate::ir::visit::statement_writes(stmt).contains(&self.sp))
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
    fn step(&self, stmt: &Stmt, origin: &mut HashMap<u16, u16>, found: Option<&mut FoundOrigins>) {
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
                for register in crate::ir::visit::statement_writes(stmt) {
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
    base_register(expr).and_then(|index| origin.get(&index).copied())
}

/// How an operation reads its arguments: as floats (`None`), or as lanes
/// of some bytes.
fn vector_operand_type(op: Operation) -> Option<Option<u8>> {
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
/// `vector_operand_type` tells them.
fn vector_operands(expr: &Expr, out: &mut HashMap<u16, Option<u8>>) {
    if let Expr::Apply { op, args } = expr
        && let Some(held) = vector_operand_type(*op)
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
mod tests;

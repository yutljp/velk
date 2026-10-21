//! Heuristic calling-convention and parameter recovery from lifted IR.

use std::collections::{HashMap, HashSet};

use crate::ir::{Access, Block, CType, Convention, Expr, Operation, Param, Stmt};
use crate::loader::Isa;

#[derive(Debug, Clone)]
pub struct Signature {
    pub params: Vec<Param>,
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
    /// The body reads AArch64's indirect result register before writing it.
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

pub fn recover(blocks: &[Block], isa: Isa, convention: Convention, go: bool) -> Signature {
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
            let mut written = stmt.call_clobbers();
            written.extend(convention.clobbered());
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
                    Stmt::Call { .. } => call_writes(stmt),
                    // Unsupported instructions are mostly vector ones, which
                    // may write any floating-point register.
                    Stmt::Unsupported { .. } => float_arguments.to_vec(),
                    _ => Vec::new(),
                })
                .collect()
        })
        .collect();
    let mut entry: Vec<HashSet<u16>> = vec![universe.clone(); blocks.len()];
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

    let returns_argument = arguments.contains(&crate::arch::RETURN);
    let effects = blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .any(|stmt| matches!(stmt, Stmt::Store { .. } | Stmt::Call { .. }));
    let mut inputs: HashSet<u16> = HashSet::new();
    // Inputs some read takes more than the low 32 bits of.
    let mut wide_inputs: HashSet<u16> = HashSet::new();
    for (index, block) in blocks.iter().enumerate() {
        let mut written = entry[index].clone();
        for stmt in &block.stmts {
            let mut used = HashSet::new();
            match stmt {
                Stmt::Assign { dest, value } => {
                    reads(partial_write_source(value, dest.index), &mut used)
                }
                Stmt::Store { addr, value, .. } => {
                    reads(addr, &mut used);
                    reads(value, &mut used);
                }
                Stmt::Brif { lhs, rhs, .. } => {
                    reads(lhs, &mut used);
                    reads(rhs, &mut used);
                }
                // Where the return register also carries the first argument,
                // returning it unwritten makes it one only in a function with
                // no effect, as `return x;` is; one with effects returns
                // nothing there.
                Stmt::Ret { value } if !(returns_argument && effects) => reads(value, &mut used),
                Stmt::Ret { .. } => {}
                Stmt::BrIndirect { target } => reads(target, &mut used),
                Stmt::Switch { index, .. } => reads(index, &mut used),
                // What a call passes on is read here too.
                Stmt::Call { through, args, .. } => {
                    for value in through.iter().chain(args.iter().flatten()) {
                        reads(value, &mut used);
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
    for register in &float_arguments[..float_count] {
        let narrow = !wide_inputs.contains(register);
        params.push(Param {
            index: *register,
            name: format!("a{}", params.len()),
            ty: CType::Named(if narrow { "float" } else { "double" }.to_owned()),
        });
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
            Stmt::Call { .. } => {
                for register in stmt.call_clobbers() {
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
    let mut origins = Origins {
        entry: entry_origins.clone(),
        global: entry_origins
            .into_iter()
            .filter(|(register, _)| !definitions.contains_key(register))
            .collect(),
        slots: HashMap::new(),
        definitions,
    };
    loop {
        let (global, slots) = origins.walk(blocks, &mut |_, _| {});
        if global == origins.global && slots == origins.slots {
            break;
        }
        origins.global = global;
        origins.slots = slots;
    }

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
                let param = copies.get(&dest.index)?;
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
            let fields = offsets.get(&param.index)?;
            Some(Access {
                register: param.index,
                fields: fields
                    .iter()
                    .map(|(offset, width)| (*offset, CType::int(*width, false)))
                    .collect(),
            })
        })
        .collect();

    // Arguments go on the stack only once the integer registers run out.
    let registers_full = arguments
        .iter()
        .all(|register| params.iter().any(|param| param.index == *register));
    // SysV passes a structure too large for registers in the caller's frame
    // even while argument registers are free.
    let frame = match (registers_full, isa) {
        (true, Isa::X86_64 | Isa::AArch64) => stack_arguments(blocks, isa, convention),
        (false, Isa::X86_64) if convention == Convention::SysV => {
            stack_arguments(blocks, isa, convention)
        }
        _ => StackFrame::default(),
    };
    let stack = frame.offsets;
    let aggregate = !registers_full && !stack.is_empty();

    Signature {
        params,
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

/// What the body uses of the caller's frame past the register arguments.
#[derive(Default)]
struct StackFrame {
    /// The offsets of the 8-byte arguments.
    offsets: Vec<i64>,
    /// How many bytes of each argument the body reads, under Go's assembly
    /// ABI; eight elsewhere.
    widths: Vec<u8>,
    /// The results the body writes past the arguments, under Go's assembly
    /// ABI: offset and width.
    results: Vec<(i64, u8)>,
}

/// The offsets of the arguments past the registers the body reads: loads
/// from the caller's frame, through the stack pointer or a frame pointer
/// set from it, up to the last one read. And under Go's assembly ABI, the
/// results that follow them: what the body writes past the last argument
/// read, or the slot whose address it hands to a call. The arguments then
/// run up to the first result.
fn stack_arguments(blocks: &[Block], isa: Isa, convention: Convention) -> StackFrame {
    let Some(start) = convention.stack_arguments() else {
        return StackFrame::default();
    };
    let sp = crate::arch::stack_pointer(isa);
    let fp = crate::arch::frame_pointer(isa);
    let results = convention == Convention::GoAbi0;
    // The registers holding a known offset from the stack pointer on entry,
    // as each block starts: the stack pointer and the frame pointer, and
    // under Go's assembly ABI, whose code may keep the stack pointer in
    // another register while it moves to another stack, any register.
    type Frame = std::collections::BTreeMap<u16, i64>;
    let tracked = |register: u16| register == sp || register == fp || results;
    let mut entry: Vec<Option<Frame>> = vec![None; blocks.len()];
    if blocks.is_empty() {
        return StackFrame::default();
    }
    entry[0] = Some(Frame::from([(sp, 0)]));
    // A register plus constants, nested as the upper half of a vector load
    // adds its eight bytes.
    fn based(expr: &Expr) -> Option<(u16, i64)> {
        match expr {
            Expr::Reg { index, .. } => Some((*index, 0)),
            Expr::Bin {
                op: crate::ir::BinOp::Add,
                lhs,
                rhs,
            } => match rhs.as_ref() {
                Expr::Const(delta) => {
                    based(lhs).map(|(base, inner)| (base, inner.wrapping_add(*delta as i64)))
                }
                _ => None,
            },
            _ => None,
        }
    }
    let offset_of = |expr: &Expr, frame: &Frame| -> Option<i64> {
        let (base, delta) = match expr {
            Expr::Reg { .. }
            | Expr::Bin {
                op: crate::ir::BinOp::Add,
                ..
            } => based(expr)?,
            Expr::Bin {
                op: crate::ir::BinOp::Sub,
                lhs,
                rhs,
            } => match (lhs.as_ref(), rhs.as_ref()) {
                (Expr::Reg { index, .. }, Expr::Const(delta)) => {
                    (*index, (*delta as i64).wrapping_neg())
                }
                _ => return None,
            },
            _ => return None,
        };
        if !tracked(base) {
            return None;
        }
        Some(frame.get(&base)?.wrapping_add(delta))
    };
    let step = |stmt: &Stmt, frame: &mut Frame| {
        if let Stmt::Assign { dest, value } = stmt
            && tracked(dest.index)
        {
            match offset_of(value, frame) {
                Some(at) => frame.insert(dest.index, at),
                None => frame.remove(&dest.index),
            };
        } else if results {
            for register in crate::ir::visit::statement_registers(stmt).0 {
                frame.remove(&register);
            }
        }
    };
    let mut work = vec![0];
    while let Some(index) = work.pop() {
        let mut frame = entry[index].clone().expect("visited");
        for stmt in &blocks[index].stmts {
            step(stmt, &mut frame);
        }
        let mut targets = Vec::new();
        if let Some(last) = blocks[index].stmts.last() {
            match last {
                Stmt::Br {
                    target: Some(target),
                } => targets.push(*target),
                Stmt::Brif { target, .. } => targets.push(*target),
                _ => {}
            }
        }
        let mut next: Vec<usize> = targets
            .iter()
            .filter_map(|target| blocks.iter().position(|block| block.start == *target))
            .collect();
        if !matches!(
            blocks[index].stmts.last(),
            Some(Stmt::Br { .. } | Stmt::Ret { .. } | Stmt::BrIndirect { .. } | Stmt::Trap)
        ) && index + 1 < blocks.len()
        {
            next.push(index + 1);
        }
        for next in next {
            let merged = match &entry[next] {
                None => frame.clone(),
                Some(old) => old
                    .iter()
                    .filter(|(register, at)| frame.get(register) == Some(at))
                    .map(|(register, at)| (*register, *at))
                    .collect(),
            };
            if entry[next].as_ref() != Some(&merged) {
                entry[next] = Some(merged);
                work.push(next);
            }
        }
    }
    let mut last = None;
    // Under Go's assembly ABI: how far into each slot of the caller's frame
    // the body reads, the bytes it writes there, and the addresses in it
    // that it passes to a call.
    let mut extent: HashMap<i64, i64> = HashMap::new();
    let (mut written, mut handed): (Vec<(i64, i64)>, Vec<i64>) = (Vec::new(), Vec::new());
    let slot = |at: i64| at - (at - start).rem_euclid(8);
    for (index, block) in blocks.iter().enumerate() {
        let Some(mut frame) = entry[index].clone() else {
            continue;
        };
        // Registers the block sets to an address in the caller's frame, as
        // an argument structure's address the body reads it through.
        let mut held: HashMap<u16, i64> = HashMap::new();
        for stmt in &block.stmts {
            // Every load, the ones vector operations make included.
            fn all_loads<'a>(expr: &'a Expr, out: &mut Vec<(&'a Expr, u8)>) {
                if let Expr::Load { addr, width, .. } = expr {
                    out.push((addr, *width));
                }
                for child in crate::ir::visit::children(expr) {
                    all_loads(child, out);
                }
            }
            let mut loads = Vec::new();
            for value in stmt.operands() {
                all_loads(value, &mut loads);
            }
            let located = |addr: &Expr, frame: &Frame, held: &HashMap<u16, i64>| {
                let through = based(addr)
                    .and_then(|(base, delta)| Some(held.get(&base)?.wrapping_add(delta)));
                offset_of(addr, frame)
                    .or(through)
                    .filter(|at| *at >= start && at - start < 8 * 64)
            };
            for (addr, width) in loads {
                let Some(at) = located(addr, &frame, &held) else {
                    continue;
                };
                if (at - start) % 8 == 0 {
                    last = last.max(Some(at));
                }
                if results {
                    let reach = extent.entry(slot(at)).or_default();
                    *reach = (*reach).max(at - slot(at) + i64::from(width));
                }
            }
            match stmt {
                Stmt::Store { addr, width, .. } if results => {
                    if let Some(at) = located(addr, &frame, &held) {
                        written.push((at, i64::from(*width)));
                    }
                }
                Stmt::Call { .. } if results => {
                    handed.extend(
                        crate::ir::visit::statement_registers(stmt)
                            .1
                            .iter()
                            .filter_map(|register| frame.get(register))
                            .filter(|at| **at >= start)
                            .map(|at| slot(*at)),
                    );
                }
                _ => {}
            }
            if let Stmt::Assign { dest, value } = stmt {
                match offset_of(value, &frame).filter(|at| *at >= start) {
                    Some(at) if dest.index != sp && dest.index != fp => {
                        held.insert(dest.index, at);
                    }
                    _ => {
                        held.remove(&dest.index);
                    }
                }
            }
            step(stmt, &mut frame);
        }
    }
    // A result follows every argument read. An address handed on may be
    // that of the arguments, unless some argument is read before it.
    let past = |at: i64| last.is_none_or(|last| at > last);
    let first = written
        .iter()
        .map(|(at, _)| slot(*at))
        .filter(|at| past(*at))
        .chain(
            handed
                .iter()
                .copied()
                .filter(|at| last.is_some() && past(*at)),
        )
        .min();
    let offsets: Vec<i64> = match (first, last) {
        (Some(first), _) => (start..first).step_by(8).collect(),
        (None, Some(last)) => (start..=last).step_by(8).collect(),
        (None, None) => Vec::new(),
    };
    let widths = offsets
        .iter()
        .map(|at| match extent.get(at) {
            Some(reach) => (*reach as u64).next_power_of_two().min(8) as u8,
            None => 8,
        })
        .collect();
    let results = first.map_or_else(Vec::new, |first| {
        // A result handed on is written whole.
        let mut fields: Vec<(i64, i64)> = written
            .iter()
            .copied()
            .chain(handed.iter().map(|at| (*at, 8)))
            .filter(|(at, _)| *at >= first)
            .map(|(at, width)| (at, at + width))
            .collect();
        fields.sort_unstable();
        let mut merged: Vec<(i64, i64)> = Vec::new();
        for (from, to) in fields {
            match merged.last_mut() {
                Some(last) if from < last.1 => last.1 = last.1.max(to),
                _ => merged.push((from, to)),
            }
        }
        // Each must be a value a register holds, aligned to its size.
        if merged.iter().any(|(from, to)| {
            let width = to - from;
            !matches!(width, 1 | 2 | 4 | 8) || from % width != 0
        }) {
            return Vec::new();
        }
        merged
            .into_iter()
            .take(convention.results().len())
            .map(|(from, to)| (from, (to - from) as u8))
            .collect()
    });
    StackFrame {
        offsets,
        widths,
        results,
    }
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
    /// The argument registers on entry.
    entry: HashMap<u16, u16>,
    /// Registers written at most once, with the argument they hold.
    global: HashMap<u16, u16>,
    /// Stack slots, by address, that every store fills from one argument.
    slots: HashMap<String, Option<u16>>,
    /// How often each register is written; a call counts twice.
    definitions: HashMap<u16, usize>,
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
            Stmt::Call { .. } => {
                for register in stmt.call_clobbers() {
                    origin.remove(&register);
                }
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
    use crate::ir::{Block, Convention, Expr, RegRef, Stmt};
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
                    target: Some(0x2000),
                    through: None,
                    convention: Convention::GoAmd64,
                    args: Some(vec![Expr::reg(3, 64), Expr::reg(8, 64)]),
                    floats_named: false,
                    clobbers: None,
                    result: None,
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
}

pub(crate) mod abi;
pub(crate) mod calls;
mod clobbers;
mod com;
mod constant_spills;
pub(crate) mod declarations;
pub(crate) mod go_types;
mod indirect;
pub(crate) use indirect::constant_branch_targets;
mod jump_table;
pub(crate) mod navigation;
mod optimization;
mod pairs32;
pub mod prototypes;
pub mod refs;
pub(crate) mod results;
#[cfg(test)]
mod semantics_tests;
pub(crate) mod shared_structures;
pub(crate) mod signature;
mod structures;
pub(crate) mod summary;
pub(crate) mod typing;
pub(crate) mod variadic;

use std::collections::HashSet;
use std::time::Instant;

use crate::deadline::passed;
use crate::error::{Error, LiftError};
use crate::ir::{CType, FunctionIr, Stmt};
use crate::lift;
use crate::loader::{Function, Image};
use optimization::optimize;
use refs::Reference;
pub use summary::summary;

/// Bytes lifted for a function whose extent neither symbols nor scanning give.
pub const UNKNOWN_SIZE: u64 = 256;

#[derive(Debug, Clone)]
pub struct Analysis {
    /// Value-preserving parameter types recovered for direct calls to imports.
    pub import_parameters: std::collections::BTreeMap<u64, Vec<CType>>,
    /// Parameters unused by a callee's body, merged from its direct callers.
    pub unused_parameters: std::collections::BTreeMap<u64, prototypes::Prototype>,
    /// Recovered callee parameters that require a prototype under default promotions.
    pub callee_parameters: std::collections::BTreeMap<u64, Vec<CType>>,
    /// Predicate and dispatcher removals proved during analysis.
    pub simplification: crate::passes::deobfuscation::Simplification,
    pub ir: FunctionIr,
    pub references: Vec<Reference>,
}

impl Analysis {
    #[must_use]
    pub fn strings(&self) -> Vec<String> {
        self.references
            .iter()
            .filter_map(|r| r.text.clone())
            .collect()
    }
}

pub fn analyze(
    image: &Image,
    function: &Function,
    deadline: Option<Instant>,
) -> Result<Analysis, Error> {
    passed(deadline)?;
    let lifted = lift_function(image, function);
    passed(deadline)?;
    let lifted = match lifted {
        Ok(lifted) => lifted,
        Err(source) => {
            return Err(Error::Lift {
                addr: function.addr,
                source,
            });
        }
    };
    optimize(image, lifted, deadline)
}

fn float_return_slot(isa: crate::loader::Isa) -> Option<u16> {
    match isa {
        crate::loader::Isa::X86_64 => Some(crate::arch::x86::XMM0),
        crate::loader::Isa::AArch64 => Some(crate::arch::aarch64::V0),
        crate::loader::Isa::Arm32 | crate::loader::Isa::I386 | crate::loader::Isa::Unsupported => {
            None
        }
    }
}

/// Whether, without debug info, the function returns a float, and which:
/// every path to a return writes the float return register, and either
/// some path leaves the integer one as it came in, or every path writes it
/// before the float one. On x86-64 an untouched integer register means
/// nothing, and on `AArch64` it is the first argument, which a function
/// returning a float does not return. A float is a single when the last
/// write on every path that says computes or loads one.
fn float_result(blocks: &[crate::ir::Block], image: &Image) -> Option<crate::ir::Precision> {
    use crate::ir::{Precision, Stmt};
    let Some(slot) = float_return_slot(image.isa) else {
        return None;
    };
    if blocks.is_empty() {
        return None;
    }
    // Per block on entry: whether every path wrote the float register and
    // the integer one (a call writes both), whether every path wrote the
    // float one last, and the precision the last write to the float
    // register shows, when the paths agree.
    #[derive(Clone, Copy, PartialEq)]
    struct State {
        float: bool,
        int: bool,
        float_last: bool,
        precision: Option<Precision>,
    }
    let mut entry: Vec<Option<State>> = vec![None; blocks.len()];
    entry[0] = Some(State {
        float: false,
        int: false,
        float_last: false,
        precision: None,
    });
    let mut work = vec![0];
    let mut returns = Vec::new();
    while let Some(index) = work.pop() {
        let mut state = entry[index].expect("visited");
        for stmt in &blocks[index].stmts {
            match stmt {
                Stmt::Assign { dest, .. } if dest.index == crate::arch::RETURN => {
                    state.int = true;
                    state.float_last = false;
                }
                Stmt::Assign { dest, value } if dest.index == slot => {
                    state.float = true;
                    state.float_last = true;
                    state.precision = written_precision(value, slot);
                }
                Stmt::Call { .. } => {
                    let written = crate::ir::visit::statement_registers(stmt).0;
                    if written.contains(&slot) {
                        state.float = false;
                        state.float_last = false;
                        state.precision = None;
                    }
                    if written.contains(&crate::arch::RETURN) {
                        state.int = true;
                        state.float_last = false;
                    }
                    if written.contains(&slot)
                        && let Some(prototype) = prototypes::called(image, stmt)
                        && prototype.ret.is_sse_float()
                    {
                        state.float = true;
                        state.float_last = true;
                        state.precision = Some(if prototype.ret.to_string() == "float" {
                            Precision::Single
                        } else {
                            Precision::Double
                        });
                    }
                }
                Stmt::Ret { .. } => returns.push(state),
                _ => {}
            }
        }
        for next in crate::ir::cfg::block_successors(blocks, index) {
            let merged = match entry[next] {
                Some(old) => State {
                    float: old.float && state.float,
                    int: old.int && state.int,
                    float_last: old.float_last && state.float_last,
                    precision: if old.precision == state.precision {
                        old.precision
                    } else {
                        None
                    },
                },
                None => state,
            };
            if entry[next] != Some(merged) {
                entry[next] = Some(merged);
                work.push(next);
            }
        }
    }
    let floats = !returns.is_empty() && returns.iter().all(|state| state.float);
    let integer_unwritten_or_float_last =
        returns.iter().all(|state| !state.int || state.float_last);
    let single = returns
        .iter()
        .any(|state| state.precision == Some(Precision::Single))
        && returns
            .iter()
            .all(|state| state.precision != Some(Precision::Double));
    (floats && integer_unwritten_or_float_last).then_some(if single {
        Precision::Single
    } else {
        Precision::Double
    })
}

/// The precision of the float a write to the vector register `slot` puts
/// in its low half: what an operation computes or a load reads. x86 merges
/// a single into the register's other bits, and `AArch64` clears them.
fn written_precision(value: &crate::ir::Expr, slot: u16) -> Option<crate::ir::Precision> {
    use crate::ir::{BinOp, Expr, Precision};
    match value {
        Expr::Apply { op, .. } => op.result_precision(),
        Expr::Load { width: 4, .. } => Some(Precision::Single),
        Expr::Load { width: 8, .. } => Some(Precision::Double),
        Expr::Bin {
            op: BinOp::And | BinOp::Or,
            lhs,
            rhs,
        } => {
            let kept = |side: &Expr| match side {
                Expr::Const(_) => true,
                Expr::Bin { lhs, rhs, .. } => {
                    matches!(lhs.as_ref(), Expr::Reg { index, .. } if *index == slot)
                        && matches!(rhs.as_ref(), Expr::Const(_))
                }
                _ => false,
            };
            match (kept(lhs), kept(rhs)) {
                (true, false) => written_precision(rhs, slot),
                (false, true) => written_precision(lhs, slot),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Takes a jump through a pointer read from memory, or through a register
/// the block never sets, as a call that ends the function: a tail call, as
/// through a table of functions. A jump to an address the block computes
/// otherwise, as an unrecovered jump table's, stays a jump, as does one
/// made with the stack away from its height on entry.
fn tail_calls_through_pointers(
    blocks: &mut [crate::ir::Block],
    switched: &HashSet<u64>,
    image: &Image,
) {
    use crate::ir::Expr;
    let heights = crate::lift::stack_heights(blocks, image.isa);
    for (block, height) in blocks.iter_mut().zip(heights) {
        if switched.contains(&block.start) || height.is_some_and(|height| height != 0) {
            continue;
        }
        let Some(Stmt::BrIndirect { target }) = block.stmts.last() else {
            continue;
        };
        // A copy of such a register is one too, as an argument moved aside
        // for the arguments the callee takes.
        let mut pointer = matches!(target, Expr::Load { .. });
        let mut copied = target;
        let mut earlier = block.stmts.iter().rev().skip(1);
        loop {
            if image.isa == crate::loader::Isa::Arm32
                && let Expr::Bin {
                    op: crate::ir::BinOp::And,
                    lhs,
                    rhs,
                } = copied
                && matches!(rhs.as_ref(), Expr::Const(0xffff_ffff | 0xffff_fffe))
            {
                copied = lhs;
                continue;
            }
            let Expr::Reg { index, .. } = copied else {
                break;
            };
            match earlier.find_map(|stmt| match stmt {
                Stmt::Assign { dest, value } if dest.index == *index => Some(value),
                _ => None,
            }) {
                None | Some(Expr::Load { .. }) => {
                    pointer = true;
                    break;
                }
                Some(value) => copied = value,
            }
        }
        if !pointer {
            continue;
        }
        let through = target.clone();
        block.stmts.pop();
        block.stmts.push(Stmt::Call {
            kind: crate::ir::CallKind::Tail,
            target: None,
            through: Some(through),
            convention: crate::ir::Convention::of(image.isa, image.format, image.go),
            args: None,
            floats_named: false,
            abi: None,
            clobbers: None,
            outputs: crate::ir::fallback_call_outputs(
                crate::ir::Convention::of(image.isa, image.format, image.go),
                None,
            ),
            via: None,
        });
        block.stmts.push(Stmt::Ret {
            value: Expr::reg(crate::arch::RETURN, 64),
        });
    }
}

/// A landing pad receives the exception in the return register and the
/// handler selector in the next: its reads of them before writing them read
/// those.
fn receive_exceptions(
    blocks: &mut [crate::ir::Block],
    pads: &HashSet<u64>,
    isa: crate::loader::Isa,
) {
    let (exception, selector) = match isa {
        crate::loader::Isa::I386 | crate::loader::Isa::X86_64 => (0, 2),
        crate::loader::Isa::AArch64 => (0, 1),
        crate::loader::Isa::Arm32 | crate::loader::Isa::Unsupported => return,
    };
    for block in blocks
        .iter_mut()
        .filter(|block| pads.contains(&block.start))
    {
        let mut received = vec![
            (exception, crate::ir::Expr::reg(crate::ir::EXCEPTION, 64)),
            (selector, crate::ir::Expr::reg(crate::ir::SELECTOR, 64)),
        ];
        for stmt in &mut block.stmts {
            crate::ir::visit::replace_reads(stmt, &received);
            let written = crate::ir::visit::statement_registers(stmt).0;
            received.retain(|(register, _)| !written.contains(register));
            if received.is_empty() {
                break;
            }
        }
    }
}

/// Drops the blocks no path from the entry reaches, unless an indirect jump
/// may reach any of them.
fn drop_unreached(blocks: &mut Vec<crate::ir::Block>) {
    use crate::ir::Stmt;
    if blocks.iter().any(|block| {
        matches!(
            block.stmts.last(),
            Some(Stmt::BrIndirect { .. } | Stmt::Br { target: None })
        )
    }) {
        return;
    }
    let index: std::collections::HashMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(position, block)| (block.start, position))
        .collect();
    let mut seen = vec![false; blocks.len()];
    let mut pending = vec![0];
    while let Some(at) = pending.pop() {
        if at >= blocks.len() || std::mem::replace(&mut seen[at], true) {
            continue;
        }
        pending.extend(crate::ir::cfg::normal_successors(
            blocks[at].stmts.last(),
            (at + 1 < blocks.len()).then_some(at + 1),
            |address| index.get(&address).copied(),
            crate::ir::cfg::UnknownBranch::Fallthrough,
        ));
    }
    let mut position = 0;
    blocks.retain(|_| {
        position += 1;
        seen[position - 1]
    });
}

/// Drops the blocks of `reached`, those a path reached before optimizing,
/// that none does now: a branch folded to one way leaves the other dead.
/// Code no path reached to begin with, as a landing pad's the unwind
/// tables do not lead to, stays.
fn drop_folded_away(ir: &mut FunctionIr, reached: &HashSet<u64>) {
    if ir
        .blocks
        .iter()
        .any(|block| matches!(block.stmts.last(), Some(Stmt::BrIndirect { .. })))
    {
        return;
    }
    let now = crate::ir::cfg::reached(ir);
    ir.blocks
        .retain(|block| now.contains(&block.start) || !reached.contains(&block.start));
}

/// Go code on x86-64 keeps xmm15 zero: it holds zero as a function starts
/// and after every call. It keeps the goroutine in r14 too, and reloading it
/// from thread-local storage after a call changes nothing.
fn initialize_go_registers(blocks: &mut [crate::ir::Block], isa: crate::loader::Isa) {
    if isa != crate::loader::Isa::X86_64 {
        return;
    }
    for block in blocks.iter_mut() {
        block.stmts.retain(|stmt| {
            !matches!(stmt, crate::ir::Stmt::Assign {
                dest: crate::ir::RegRef { index: 14, width: 64 },
                value: crate::ir::Expr::Load { addr, width: 8, .. },
            } if matches!(addr.as_ref(), crate::ir::Expr::Bin {
                    op: crate::ir::BinOp::Add,
                    lhs,
                    rhs,
                } if matches!(lhs.as_ref(), crate::ir::Expr::Reg { index: crate::arch::x86::FS_BASE, .. })
                    && matches!(rhs.as_ref(), crate::ir::Expr::Const(0xffff_ffff_ffff_fff8))))
        });
    }
    let Some(first) = blocks.first_mut() else {
        return;
    };
    for half in [crate::arch::x86::XMM0 + 30, crate::arch::x86::XMM0 + 31] {
        first.stmts.insert(
            0,
            crate::ir::Stmt::Assign {
                dest: crate::ir::RegRef {
                    index: half,
                    width: 64,
                },
                value: crate::ir::Expr::constant(0),
            },
        );
    }
}

/// Drops the check a Go function starts with, which compares the stack
/// pointer with the goroutine's stack limit and, when it runs low, calls the
/// runtime to grow the stack and starts the function again. It is no part
/// of what the function does. The blocks that grow the stack and restart
/// go too.
fn drop_stack_growth_check(blocks: &mut Vec<crate::ir::Block>, image: &Image) {
    let grows = |target: u64| {
        image
            .functions
            .get(&target)
            .and_then(|function| function.name.as_deref())
            .is_some_and(|name| name.starts_with("runtime.morestack"))
    };
    let Some(entry) = blocks.first().map(|block| block.start) else {
        return;
    };
    let mut dropped = HashSet::new();
    for index in 0..blocks.len() {
        let Some(Stmt::Brif { target, .. }) = blocks[index].stmts.last() else {
            continue;
        };
        let target = *target;
        let Some(growth) = blocks.iter().position(|block| block.start == target) else {
            continue;
        };
        let calls_growth = blocks[growth]
            .stmts
            .iter()
            .any(|stmt| matches!(stmt, Stmt::Call { target: Some(callee), .. } if grows(*callee)));
        let Some(next) = blocks.get(index + 1).map(|block| block.start) else {
            continue;
        };
        if !calls_growth {
            continue;
        }
        // The check falls through into the body.
        *blocks[index].stmts.last_mut().expect("a branch") = Stmt::Br { target: Some(next) };
        dropped.insert(growth);
        // The restart: arguments reloaded, then back to the entry.
        if let Some(next) = blocks.get(growth + 1)
            && matches!(next.stmts.last(), Some(Stmt::Br { target: Some(start) }) if *start == entry)
        {
            dropped.insert(growth + 1);
        }
    }
    let mut index = 0;
    blocks.retain(|_| {
        index += 1;
        !dropped.contains(&(index - 1))
    });
}

/// A function that only ever returns what the functions it calls return
/// returns as wide a value as they do, or nothing when they return nothing;
/// a library function's result, or one a constant moves, is of the type
/// its prototype gives it.
fn apply_call_return(ir: &mut FunctionIr, image: &Image) {
    use crate::ir::{BinOp, CType, Expr};
    if ir.ret_type == CType::Void || crate::ir::cfg::own_return(&ir.blocks).is_some() {
        return;
    }
    let mut width = None;
    for block in &ir.blocks {
        let [.., call @ Stmt::Call { target, .. }, Stmt::Ret { value }] = block.stmts.as_slice()
        else {
            if matches!(block.stmts.last(), Some(Stmt::Ret { .. })) {
                return;
            }
            continue;
        };
        let prototype = prototypes::called(image, call);
        let returned = match value {
            Expr::Reg { index, .. } => *index,
            Expr::Bin {
                op: BinOp::Add | BinOp::Sub,
                lhs,
                rhs,
            } if matches!(rhs.as_ref(), Expr::Const(_))
                && prototype.is_some_and(|prototype| prototype.ret.integer().is_some()) =>
            {
                match lhs.as_ref() {
                    Expr::Reg { index, .. } => *index,
                    _ => return,
                }
            }
            _ => return,
        };
        let returned_type = match (prototype, target) {
            (Some(prototype), _) => prototype.ret.clone(),
            (None, Some(target)) => match returned_type(image, *target) {
                Some(returned_type) => returned_type,
                None => return,
            },
            (None, None) => return,
        };
        let output = if returned_type == CType::Void {
            call.primary_call_output()
        } else {
            prototypes::scalar_call_output(call, &returned_type)
        };
        let Some(carried) = output.map(|output| output.dest.index) else {
            return;
        };
        if returned != carried || width.as_ref().is_some_and(|width| *width != returned_type) {
            return;
        }
        width = Some(returned_type);
    }
    match (width, &ir.ret_type) {
        // The calls' results go nowhere.
        (Some(CType::Void), _) => {
            ir.ret_type = CType::Void;
            for block in &mut ir.blocks {
                if let [.., Stmt::Call { .. }, Stmt::Ret { value }] = block.stmts.as_mut_slice() {
                    *value = Expr::constant(0);
                }
            }
        }
        (Some(CType::Int { bytes, .. }), CType::Int { signed, .. }) => {
            ir.ret_type = CType::int(bytes, *signed);
        }
        (Some(CType::Int { .. }) | None, _) => {}
        (Some(given), _) => ir.ret_type = given,
    }
}

/// What the function at `addr` returns, as its own analysis decides: an
/// integer, or nothing; `None` for anything else, or for a function already
/// being analysed further up, as mutual tail calls are.
fn returned_type(image: &Image, addr: u64) -> Option<crate::ir::CType> {
    thread_local! {
        static UNDER_WAY: std::cell::RefCell<HashSet<u64>> = Default::default();
    }
    let function = image.functions.get(&addr)?;
    if !UNDER_WAY.with(|under_way| under_way.borrow_mut().insert(addr)) {
        return None;
    }
    let analysis = analyze(image, function, None);
    UNDER_WAY.with(|under_way| under_way.borrow_mut().remove(&addr));
    let Ok(analysis) = analysis else {
        return None;
    };
    match analysis.ir.ret_type {
        crate::ir::CType::Int { bytes, .. } => Some(crate::ir::CType::int(bytes, false)),
        crate::ir::CType::Void => Some(crate::ir::CType::Void),
        _ => None,
    }
}

/// Gives a call whose callee's arguments are unknown, such as one through a
/// pointer, the argument registers the code sets up for it: up to the last
/// one written since the block's previous call and not used again before
/// the call, as a register holding scratch is. Loading through a register,
/// as a virtual call loads its table through the object, is no such use.
fn set_up_arguments(ir: &mut FunctionIr, types: Option<&crate::loader::dwarf::FunctionTypes>) {
    // The registers an expression reads other than as the base of a load.
    fn used(expr: &crate::ir::Expr, out: &mut HashSet<u16>) {
        use crate::ir::{BinOp, Expr};
        match expr {
            Expr::Load { addr, .. } => match addr.as_ref() {
                Expr::Reg { .. } => {}
                Expr::Bin {
                    op: BinOp::Add,
                    lhs,
                    rhs,
                } if matches!(lhs.as_ref(), Expr::Reg { .. })
                    && matches!(rhs.as_ref(), Expr::Const(_)) => {}
                other => used(other, out),
            },
            Expr::Reg { index, .. } => {
                out.insert(*index);
            }
            other => {
                for child in crate::ir::visit::children(other) {
                    used(child, out);
                }
            }
        }
    }
    let mut incoming: HashSet<u16> = ir.params.iter().map(|param| param.index).collect();
    if ir.convention == crate::ir::Convention::Win64
        && let Some(types) = types.filter(|types| !abi::has_aggregate(types))
    {
        for (register, layout) in ir.convention.arguments().iter().zip(&types.param_layouts) {
            if layout.as_ref().is_ok_and(|layout| {
                matches!(layout.size, 1 | 2 | 4 | 8)
                    && matches!(
                        layout.kind,
                        crate::ir::abi::LayoutKind::Integer
                            | crate::ir::abi::LayoutKind::Boolean
                            | crate::ir::abi::LayoutKind::Pointer
                    )
            }) {
                incoming.insert(*register);
            }
        }
    }
    for (position, block) in ir.blocks.iter_mut().enumerate() {
        let mut written = if position == 0 && ir.convention == crate::ir::Convention::Win64 {
            incoming.clone()
        } else {
            HashSet::new()
        };
        for stmt in &mut block.stmts {
            // A declared call names what it reads; it keeps no argument
            // guessed from the writes before it.
            if stmt.has_declared_call() {
                written.clear();
                continue;
            }
            let Stmt::Call {
                convention,
                args,
                through,
                ..
            } = stmt
            else {
                let mut reads = HashSet::new();
                for operand in stmt.operands() {
                    used(operand, &mut reads);
                }
                for read in reads {
                    written.remove(&read);
                }
                written.extend(crate::ir::visit::statement_registers(stmt).0);
                continue;
            };
            // The register holding the callee's address is no argument.
            if let Some(through) = through {
                let mut read = HashSet::new();
                crate::ir::visit::collect_reads(through, &mut read);
                written.retain(|register| !read.contains(register));
            }
            let registers = convention.arguments();
            if args.is_none()
                && let Some(last) = registers
                    .iter()
                    .rposition(|register| written.contains(register))
            {
                *args = Some(
                    registers[..=last]
                        .iter()
                        .map(|register| {
                            crate::ir::Expr::reg(
                                *register,
                                if *convention == crate::ir::Convention::Aapcs32 {
                                    32
                                } else {
                                    64
                                },
                            )
                        })
                        .collect(),
                );
            }
            written.clear();
        }
    }
}

/// Drops the stack protector: the guard value copied into the frame on
/// entry, and the test before each return that calls the runtime to abort
/// when the copy no longer matches. Neither is part of what the function
/// does. The blocks only that test reached go too.
fn drop_stack_protector(ir: &mut FunctionIr, image: &Image) {
    use crate::ir::Expr;
    let fails = |block: &crate::ir::Block| {
        block.stmts.iter().any(|stmt| {
            matches!(stmt, Stmt::Call { target: Some(target), .. }
                if image.functions.get(target).and_then(|function| function.name.as_deref())
                    .is_some_and(|name| name.trim_start_matches('_') == "stack_chk_fail"))
        })
    };
    let failing: HashSet<u64> = ir
        .blocks
        .iter()
        .filter(|block| fails(block))
        .map(|block| block.start)
        .collect();
    if failing.is_empty() {
        return;
    }
    let sp = crate::arch::stack_pointer(ir.isa);
    let in_frame = |expr: &Expr| match expr {
        Expr::Load { addr, .. } => {
            let mut read = HashSet::new();
            crate::ir::visit::collect_reads(addr, &mut read);
            read.contains(&sp)
        }
        _ => false,
    };
    // The frame copy and the guard each test compares it with.
    let mut guarded: Vec<(Expr, Expr)> = Vec::new();
    for index in 0..ir.blocks.len() {
        let next = ir.blocks.get(index + 1).map(|block| block.start);
        let Some(Stmt::Brif {
            cond,
            lhs,
            rhs,
            target,
        }) = ir.blocks[index].stmts.last()
        else {
            continue;
        };
        let (copy, guard) = match (in_frame(lhs), in_frame(rhs)) {
            (true, false) => (lhs.clone(), rhs.clone()),
            (false, true) => (rhs.clone(), lhs.clone()),
            _ => continue,
        };
        let continues = match cond {
            crate::ir::Cond::Ne if failing.contains(target) => next,
            crate::ir::Cond::Eq if next.is_some_and(|next| failing.contains(&next)) => {
                Some(*target)
            }
            _ => continue,
        };
        let Some(continues) = continues else {
            continue;
        };
        *ir.blocks[index].stmts.last_mut().expect("a branch") = Stmt::Br {
            target: Some(continues),
        };
        guarded.push((copy, guard));
    }
    if guarded.is_empty() {
        return;
    }
    for block in &mut ir.blocks {
        block.stmts.retain(|stmt| {
            !matches!(stmt, Stmt::Store { addr, value, .. }
            if guarded.iter().any(|(copy, guard)| {
                matches!(copy, Expr::Load { addr: slot, .. } if slot.as_ref() == addr)
                    && guard == value
            }))
        });
    }
    // The failing blocks nothing reaches any more.
    loop {
        let reached: HashSet<usize> = (0..ir.blocks.len())
            .flat_map(|from| crate::render::structure::compare_chain::successors(ir, from))
            .collect();
        let before = ir.blocks.len();
        let mut position = 0;
        ir.blocks.retain(|block| {
            position += 1;
            position == 1 || reached.contains(&(position - 1)) || !failing.contains(&block.start)
        });
        if ir.blocks.len() == before {
            break;
        }
    }
}

/// Drops a value nothing reads that loads only from memory the program
/// cannot change, such as the jump table entry a switch no longer needs:
/// code, or constant data, at addresses that may take an index read from
/// the function's own frame. Other loads may touch a device and stay.
fn drop_dead_constant_reads(ir: &mut FunctionIr, image: &Image) {
    use crate::ir::Expr;
    let constant = |address: u64| {
        image.section_at(address).is_some_and(|section| {
            section.executable
                || section.read_only
                || section.name.contains("rodata")
                || section.name.contains("rel.ro")
                || section.name.contains("__const")
        })
    };
    // Every load reads at a constant base inside such memory, plus offsets,
    // or in the function's own frame, as an index spilled there.
    let sp = crate::arch::stack_pointer(ir.isa);
    fn constant_loads(expr: &Expr, constant: &dyn Fn(u64) -> bool, sp: u16) -> bool {
        match expr {
            Expr::Load { addr, .. } => {
                let mut base = None;
                let mut frame = false;
                let mut indexed = false;
                let mut terms = vec![addr.as_ref()];
                while let Some(term) = terms.pop() {
                    match term {
                        Expr::Bin {
                            op: crate::ir::BinOp::Add,
                            lhs,
                            rhs,
                        } => terms.extend([lhs.as_ref(), rhs.as_ref()]),
                        Expr::Const(value) => base = Some(*value),
                        Expr::Reg { index, .. } if *index == sp => frame = true,
                        other if !constant_loads(other, constant, sp) => return false,
                        _ => indexed = true,
                    }
                }
                match (frame, base) {
                    (true, offset) => {
                        !indexed && offset.is_none_or(|offset| (offset as i64).abs() < 0x1_0000)
                    }
                    (false, base) => base.is_some_and(constant),
                }
            }
            other => crate::ir::visit::children(other)
                .into_iter()
                .all(|child| constant_loads(child, constant, sp)),
        }
    }
    let live_in = crate::ir::cfg::live_in(ir);
    for index in 0..ir.blocks.len() {
        let mut live = crate::ir::cfg::live_out(ir, &live_in, index);
        let mut keep = vec![true; ir.blocks[index].stmts.len()];
        for (position, stmt) in ir.blocks[index].stmts.iter().enumerate().rev() {
            let (writes, reads) = crate::ir::visit::statement_registers(stmt);
            if let Stmt::Assign { dest, value } = stmt
                && !live.contains(&dest.index)
                && constant_loads(value, &constant, sp)
            {
                keep[position] = false;
                continue;
            }
            for written in &writes {
                live.remove(written);
            }
            live.extend(reads);
        }
        let mut position = 0;
        ir.blocks[index].stmts.retain(|_| {
            position += 1;
            keep[position - 1]
        });
    }
}

/// A function returning a structure too large for registers writes it
/// through a pointer its caller passes first and returns that pointer: the
/// first parameter is the result, no parameter of the source.
fn name_indirect_result(ir: &mut FunctionIr) {
    use crate::ir::{Convention, Expr};
    if ir.declared_signature.is_some() {
        return;
    }
    if !matches!(ir.convention, Convention::SysV | Convention::Win64) {
        return;
    }
    let first = ir.convention.arguments()[0];
    let Some(param) = ir.params.iter().position(|param| param.index == first) else {
        return;
    };
    let based = |addr: &Expr| match addr {
        Expr::Reg { index, .. } => *index == first,
        Expr::Bin { lhs, rhs, .. } => {
            matches!(lhs.as_ref(), Expr::Reg { index, .. } if *index == first)
                && matches!(rhs.as_ref(), Expr::Const(_))
        }
        _ => false,
    };
    let stmts = || ir.blocks.iter().flat_map(|block| &block.stmts);
    let returns_it = stmts()
        .filter_map(|stmt| match stmt {
            Stmt::Ret { value } => Some(value),
            _ => None,
        })
        .all(|value| matches!(value, Expr::Reg { index, width: 64 } if *index == first));
    let writes_through =
        stmts().any(|stmt| matches!(stmt, Stmt::Store { addr, .. } if based(addr)));
    let returns = stmts().any(|stmt| matches!(stmt, Stmt::Ret { .. }));
    if returns && returns_it && writes_through {
        ir.params[param].name = "result".to_owned();
    }
}

/// Drops each value `AArch64` code leaves in x8, its indirect result
/// register, that no path reads before the register changes: a call reads
/// it unnamed only when its callee may return through memory, so a
/// compiler's scratch there, as a jump table's computed target, is dead
/// before calls of callees known to take no result address.
fn drop_unread_indirect_result(ir: &mut FunctionIr, image: &Image) {
    const INDIRECT: u16 = 8;
    if ir.isa != crate::loader::Isa::AArch64 {
        return;
    }
    let reads = |expr: &crate::ir::Expr| {
        let mut read = HashSet::new();
        crate::ir::visit::collect_reads(expr, &mut read);
        read.contains(&INDIRECT)
    };
    // Whether x8's value is needed before the statement, given whether it
    // is after it. A call whose callee's summary takes no result address
    // reads it only where its expressions name it.
    let before = |stmt: &Stmt, after: bool| match stmt {
        _ if stmt.operands().into_iter().any(reads) => true,
        // A declared call reads x8 only for the result its declaration
        // returns through memory.
        Stmt::Call { abi: Some(_), .. } if !stmt.declared_call_reads().contains(&INDIRECT) => {
            after && !stmt.call_clobbers().contains(&INDIRECT)
        }
        Stmt::Call {
            target: Some(target),
            args: Some(_),
            abi: None,
            ..
        } if !summary::summary(image, *target).indirect_result => {
            after && !stmt.call_clobbers().contains(&INDIRECT)
        }
        _ => {
            let (writes, read) = crate::ir::visit::statement_registers(stmt);
            read.contains(&INDIRECT) || (after && !writes.contains(&INDIRECT))
        }
    };
    let count = ir.blocks.len();
    let successors: Vec<Vec<usize>> = (0..count)
        .map(|index| crate::ir::cfg::successors(ir, index))
        .collect();
    let out = |live: &[bool], index: usize| {
        crate::ir::cfg::opaque(&ir.blocks[index])
            || successors[index].iter().any(|next| live[*next])
    };
    let mut live = vec![false; count];
    loop {
        let mut changed = false;
        for index in (0..count).rev() {
            let entry = ir.blocks[index]
                .stmts
                .iter()
                .rev()
                .fold(out(&live, index), |after, stmt| before(stmt, after));
            if entry && !live[index] {
                live[index] = true;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let outs: Vec<bool> = (0..count).map(|index| out(&live, index)).collect();
    for (block, mut after) in ir.blocks.iter_mut().zip(outs) {
        let mut dead = Vec::new();
        for (position, stmt) in block.stmts.iter().enumerate().rev() {
            if matches!(stmt, Stmt::Assign { dest, .. } if dest.index == INDIRECT) && !after {
                dead.push(position);
            }
            after = before(stmt, after);
        }
        for position in dead {
            block.stmts.remove(position);
        }
    }
}

/// The function's IR before any optimization pass, with its recovered signature.
struct Lifted {
    ir: FunctionIr,
    has_jump_tables: bool,
    types: Option<crate::loader::dwarf::FunctionTypes>,
}

/// Folds the cases of jump tables back into their functions where the
/// prologue scan took a case, which follows a return like a new function
/// would, for a function start. Each pass widens the functions it merges,
/// which may expose further tables.
pub fn absorb_jump_table_cases(image: &mut Image) {
    for _ in 0..4 {
        let functions: Vec<_> = image
            .functions
            .values()
            .filter(|function| {
                function
                    .sources
                    .contains(&crate::loader::NameSource::Prologue)
            })
            .collect();
        let found = crate::parallel::map(&functions, |function| {
            let mut cases = HashSet::new();
            let size = function.size.unwrap_or(UNKNOWN_SIZE);
            // Function extents are still settling, so no callee is summarized yet.
            let Ok(blocks) = lift::lift_with(image, function.addr, size, &HashSet::new(), &|_| {
                crate::loader::Summary::default()
            }) else {
                return cases;
            };
            let reach = function.addr..function.addr.saturating_add(0x1_0000);
            for table in jump_table::recover(&blocks, image, reach) {
                cases.extend(
                    table
                        .targets()
                        .into_iter()
                        .filter(|target| *target != function.addr),
                );
            }
            cases
        });
        let mut cases = HashSet::new();
        for found in found {
            cases.extend(found);
        }
        if !image.drop_scanned_starts(&cases) {
            return;
        }
    }
}

/// The results the function at `addr` returns past its stack arguments,
/// under Go's assembly ABI, as it finds them when it returns.
fn stack_results(image: &Image, addr: u64) -> Vec<crate::ir::Expr> {
    let convention = image.convention_of(addr);
    let Some(start) = convention.stack_arguments() else {
        return Vec::new();
    };
    let sp = crate::arch::stack_pointer(image.isa);
    summary::summary(image, addr)
        .stack_results
        .iter()
        .take_while(|(_, width)| *width != 0)
        .map(|(offset, width)| crate::ir::Expr::Load {
            addr: Box::new(crate::ir::Expr::bin(
                crate::ir::BinOp::Add,
                crate::ir::Expr::reg(sp, 64),
                crate::ir::Expr::Const(start as u64 + u64::from(*offset)),
            )),
            width: *width,
            signed: false,
        })
        .collect()
}

fn landing_pads(image: &Image, extent: std::ops::Range<u64>) -> Vec<(u64, Vec<(u64, u64)>)> {
    image
        .landing_pads
        .iter()
        .filter(|(pad, sites)| {
            extent.contains(*pad)
                || sites
                    .iter()
                    .any(|(from, to)| from < to && extent.start < *to && *from < extent.end)
        })
        .map(|(&pad, sites)| (pad, sites.clone()))
        .collect()
}

fn exception_starts(
    landing_pads: &[(u64, Vec<(u64, u64)>)],
    extent: std::ops::Range<u64>,
) -> HashSet<u64> {
    landing_pads
        .iter()
        .flat_map(|(_, sites)| sites.iter().map(|(_, end)| *end))
        .chain(landing_pads.iter().map(|(pad, _)| *pad))
        .filter(|address| extent.contains(address))
        .collect()
}

fn lift_function(image: &Image, function: &Function) -> Result<Lifted, LiftError> {
    let size = function.size.unwrap_or(UNKNOWN_SIZE);
    let extent = function.addr..function.addr.saturating_add(size);
    let landing_pads = landing_pads(image, extent.clone());
    let pads: HashSet<u64> = landing_pads.iter().map(|(pad, _)| *pad).collect();
    let starts = exception_starts(&landing_pads, extent.clone());
    let mut blocks = match lift::lift(image, function.addr, size, &starts) {
        Ok(blocks) => blocks,
        Err(error) => return Err(error),
    };
    let mut tables = jump_table::recover(&blocks, image, extent.clone());
    // Cases start blocks of their own, which may hold further tables.
    let mut targets: HashSet<u64> = starts;
    for _ in 0..4 {
        let found: HashSet<u64> = tables
            .iter()
            .flat_map(jump_table::Recovered::targets)
            .collect();
        if found.is_subset(&targets) {
            break;
        }
        targets.extend(found);
        blocks = match lift::lift(image, function.addr, size, &targets) {
            Ok(blocks) => blocks,
            Err(error) => return Err(error),
        };
        tables = jump_table::recover(&blocks, image, extent.clone());
    }
    if image.go {
        drop_stack_growth_check(&mut blocks, image);
        initialize_go_registers(&mut blocks, image.isa);
    }
    receive_exceptions(&mut blocks, &pads, image.isa);
    let switched: HashSet<u64> = tables.iter().map(|table| table.block_start).collect();
    tail_calls_through_pointers(&mut blocks, &switched, image);
    indirect::resolve(&mut blocks, &landing_pads, image);
    let types = crate::loader::dwarf::function_types(image, function.addr);
    let declared_signature = types.as_ref().and_then(abi::declaration);
    // A function returning a float returns it in xmm0 or v0.
    let inferred = if types.is_none() {
        crate::lift::pairs32::definition_types(image, function.addr)
    } else {
        None
    };
    let runtime = go_types::runtime(image, function.addr);
    let declared = types
        .as_ref()
        .and_then(|types| types.ret.as_ref())
        .or_else(|| inferred.as_ref().map(|(_, ret)| ret))
        .or_else(|| runtime.map(|prototype| &prototype.ret));
    if matches!(
        image.isa,
        crate::loader::Isa::I386 | crate::loader::Isa::Arm32
    ) && declared.is_some_and(crate::lift::pairs32::wide)
    {
        let high = if image.isa == crate::loader::Isa::I386 {
            2
        } else {
            1
        };
        for stmt in blocks.iter_mut().flat_map(|block| &mut block.stmts) {
            if let Stmt::Ret { value } = stmt {
                *value = crate::lift::pairs32::join(
                    crate::ir::Expr::reg(0, 32),
                    crate::ir::Expr::reg(high, 32),
                );
            }
        }
    }
    // A function of Go's assembly ABI returns what it writes past its
    // arguments.
    let stack_results = stack_results(image, function.addr);
    let float_return = match declared {
        Some(ret) if ret.is_sse_float() => Some(if ret.to_string().contains("double") {
            crate::ir::Precision::Double
        } else {
            crate::ir::Precision::Single
        }),
        Some(_) => None,
        None if !stack_results.is_empty() => None,
        None => float_result(&blocks, image),
    };
    // Without debug info, a function whose callers all ignore what is left
    // in the return register returns nothing either. A linkage stub returns
    // what the library function does, whatever these callers make of it.
    // So does one that returns on some path with the register unset.
    let ignored = declared.is_none()
        && float_return.is_none()
        && stack_results.is_empty()
        && !function.sources.contains(&crate::loader::NameSource::Plt)
        && (results::ignored_by_callers(image, function.addr)
            || results::returns_unset(&blocks, image.convention_of(function.addr)));
    // A function the debug info says returns nothing returns no register.
    if declared == Some(&crate::ir::CType::Void) || ignored {
        for stmt in blocks.iter_mut().flat_map(|block| &mut block.stmts) {
            if let crate::ir::Stmt::Ret { value } = stmt {
                *value = crate::ir::Expr::constant(0);
            }
        }
    }
    if let (Some(precision), Some(slot)) = (float_return, float_return_slot(image.isa)) {
        for stmt in blocks.iter_mut().flat_map(|block| &mut block.stmts) {
            if let crate::ir::Stmt::Ret { value } = stmt {
                *value = crate::ir::Expr::reg(slot, precision.bits());
            }
        }
    }
    // A Go function returns as many values as its callers read.
    let further = if image.go && float_return.is_none() && !ignored && stack_results.is_empty() {
        results::further_results(image, function.addr)
    } else {
        0
    };
    if further > 0 {
        let convention = crate::ir::Convention::of(image.isa, image.format, image.go);
        let returned: Vec<crate::ir::Expr> = convention.results()[..=further]
            .iter()
            .map(|register| crate::ir::Expr::reg(*register, 64))
            .collect();
        for stmt in blocks.iter_mut().flat_map(|block| &mut block.stmts) {
            if let crate::ir::Stmt::Ret { value } = stmt
                && matches!(value, crate::ir::Expr::Reg { .. })
            {
                *value = crate::ir::Expr::Apply {
                    op: crate::ir::Operation::Results,
                    args: returned.clone(),
                };
            }
        }
    }
    if let Some(Ok(binding)) = declared_signature.as_ref().map(|signature| &signature.abi) {
        let returned = match binding.result.as_ref().map(|value| &value.passing) {
            Some(crate::ir::Passing::Direct(pieces)) => {
                let values: Option<Vec<_>> = pieces
                    .iter()
                    .map(|piece| match piece.location {
                        crate::ir::AbiLocation::Register(register) => {
                            Some(crate::ir::Expr::reg(register, 64))
                        }
                        crate::ir::AbiLocation::Stack(_) => None,
                    })
                    .collect();
                values.map(|args| crate::ir::Expr::Apply {
                    op: crate::ir::Operation::Results,
                    args,
                })
            }
            Some(crate::ir::Passing::Indirect {
                returned_pointer, ..
            }) => Some(returned_pointer.map_or_else(
                || crate::ir::Expr::constant(0),
                |register| crate::ir::Expr::reg(register, 64),
            )),
            None => Some(crate::ir::Expr::constant(0)),
        };
        if let Some(returned) = returned {
            for stmt in blocks.iter_mut().flat_map(|block| &mut block.stmts) {
                if let crate::ir::Stmt::Ret { value } = stmt {
                    *value = returned.clone();
                }
            }
        }
    }
    // The signature reads the returns as they now are, and the cases
    // through the switches.
    jump_table::apply(&mut blocks, &tables);
    jump_table::drop_data(&mut blocks, &tables, &landing_pads);
    // Without landing pads, code no path reaches is dead; so is a linkage
    // stub's code for binding its import on first use.
    if image.go
        || (landing_pads.is_empty() && image.exception_handlers.is_empty())
        || function.sources.contains(&crate::loader::NameSource::Plt)
    {
        drop_unreached(&mut blocks);
    }
    let mut signature = signature::recover_with(
        &blocks,
        &landing_pads,
        image.isa,
        image.convention_of(function.addr),
        image.go,
        &|stmt| prototypes::called(image, stmt),
    );
    if function.sources.contains(&crate::loader::NameSource::Call)
        || (image.isa == crate::loader::Isa::I386
            && signature.params.is_empty()
            && signature.stack.is_empty())
    {
        signature::add_register_parameters(
            &mut signature,
            &blocks,
            &landing_pads,
            image.isa,
            image.convention_of(function.addr),
        );
    }
    // Read only now, the results are no arguments to the signature.
    if let Some(first) = stack_results.first() {
        let returned = match stack_results.as_slice() {
            [only] => only.clone(),
            all => crate::ir::Expr::Apply {
                op: crate::ir::Operation::Results,
                args: all.to_vec(),
            },
        };
        for stmt in blocks.iter_mut().flat_map(|block| &mut block.stmts) {
            if let crate::ir::Stmt::Ret { value } = stmt {
                *value = returned.clone();
            }
        }
        // Go's wider results are mostly `int` and `int32`, a byte one a `bool`.
        if let crate::ir::Expr::Load { width, .. } = first {
            signature.ret = crate::ir::CType::int(*width, *width > 1);
        }
    }
    // The arguments past the registers follow the register ones; with
    // registers left free, they are one structure.
    let mut structures = Vec::new();
    let stack_params = match (signature.aggregate, signature.stack.first()) {
        (true, Some(first)) => {
            let position = signature.params.len();
            let name = format!(
                "{}_a{position}",
                crate::render::structure_prefix(function.name.as_deref(), function.addr)
            );
            structures.push(crate::ir::Structure {
                name: name.clone(),
                fields: signature
                    .stack
                    .iter()
                    .map(|offset| ((offset - first) as u64, crate::ir::CType::I64))
                    .collect(),
                size: None,
                elements: Vec::new(),
            });
            vec![crate::ir::StackParam {
                offset: *first,
                size: 8 * signature.stack.len() as u64,
                name: format!("a{position}"),
                ty: crate::ir::CType::Named(format!("struct {name}")),
                position,
            }]
        }
        _ => signature
            .stack
            .iter()
            .enumerate()
            .map(|(slot, offset)| {
                let position = signature.params.len() + slot;
                // Only the low bytes of a packed argument are read, as they are.
                let ty = match signature.stack_widths.get(slot) {
                    Some(width) if *width < 8 => crate::ir::CType::int(*width, false),
                    _ => crate::ir::CType::I64,
                };
                crate::ir::StackParam {
                    offset: *offset,
                    size: u64::from(crate::arch::pointer_bytes(image.isa)),
                    name: format!("a{position}"),
                    ty,
                    position,
                }
            })
            .collect(),
    };
    let mut ir = FunctionIr {
        isa: image.isa,
        convention: image.convention_of(function.addr),
        params: signature.params,
        declared_signature,
        stack_params,
        stack_spills: crate::loader::go::stack_spills(image, function.addr),
        debug_globals: types
            .as_ref()
            .map(|types| types.globals.clone())
            .unwrap_or_default(),
        debug_registers: types
            .as_ref()
            .map(|types| types.registers.clone())
            .unwrap_or_default(),
        debug_locals: types
            .as_ref()
            .map(|types| types.locals.clone())
            .unwrap_or_default(),
        variadic: false,
        ret_type: match float_return {
            _ if ignored => crate::ir::CType::Void,
            Some(precision) => crate::ir::CType::Named(
                match precision {
                    crate::ir::Precision::Single => "float",
                    crate::ir::Precision::Double => "double",
                }
                .to_owned(),
            ),
            None => inferred.map_or(signature.ret, |(_, ret)| ret),
        },
        accesses: signature.accesses,
        members: Vec::new(),
        definitions: Vec::new(),
        structures,
        signed_params: signature.signed,
        landing_pads,
        pointer_values: Vec::new(),
        saved_slots: Vec::new(),
        frame_bottom: 0,
        callee_signatures: Default::default(),
        value_types: std::collections::BTreeMap::new(),
        variable_registers: std::collections::BTreeMap::new(),
        addr: function.addr,
        name: function.name.clone(),
        size,
        blocks,
    };
    if let Some(Ok(binding)) = ir
        .declared_signature
        .as_ref()
        .map(|signature| &signature.abi)
        && let Some(crate::ir::ValueAbi {
            passing:
                crate::ir::Passing::Indirect {
                    pointer: crate::ir::AbiLocation::Register(register),
                    returned_pointer,
                },
            ..
        }) = &binding.result
    {
        if !ir.params.iter().any(|param| param.index == *register) {
            let mut position = ir.params.len();
            while ir
                .params
                .iter()
                .any(|param| param.name == format!("a{position}"))
            {
                position += 1;
            }
            ir.params.push(crate::ir::Param {
                index: *register,
                name: format!("a{position}"),
                ty: crate::ir::CType::U64,
            });
        }
        if returned_pointer.is_none() {
            ir.ret_type = crate::ir::CType::Void;
        }
    }
    go_types::apply_runtime_signature(&mut ir, image);
    Ok(Lifted {
        ir,
        has_jump_tables: !tables.is_empty(),
        types,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::ir::Stmt;
    use crate::loader::{Image, Isa};

    #[test]
    fn explicit_scalar_return_types_take_precedence_over_pointer_producer_inference() {
        use crate::ir::{
            AbiProfile, CType, CallOutput, Convention, Expr, FunctionIr, Param, RegRef,
            VARIABLE_BASE,
        };
        for ret in [Some(CType::U64), None] {
            let mut image = Image::from_code(Isa::AArch64, 0, Vec::new());
            image.imports.insert(0x1000, "memcpy".to_owned());
            let mut ir = FunctionIr::single_block(
                Isa::AArch64,
                vec![
                    Stmt::Call {
                        kind: crate::ir::CallKind::Invoke,
                        target: None,
                        through: Some(Expr::Load {
                            addr: Box::new(Expr::Const(0x1000)),
                            width: 8,
                            signed: false,
                        }),
                        convention: Convention::Aapcs64,
                        args: Some(vec![Expr::reg(0, 64), Expr::reg(1, 64), Expr::reg(2, 64)]),
                        floats_named: true,
                        abi: None,
                        outputs: vec![CallOutput {
                            register: 0,
                            dest: RegRef {
                                index: VARIABLE_BASE,
                                width: 64,
                            },
                        }],
                        clobbers: Some([0].into_iter().collect()),
                        via: None,
                    },
                    Stmt::Store {
                        addr: Expr::reg(3, 64),
                        value: Expr::reg(2, 64),
                        width: 8,
                    },
                    Stmt::Ret {
                        value: Expr::reg(VARIABLE_BASE, 64),
                    },
                ],
            );
            ir.name = Some("copy_and_note".to_owned());
            ir.ret_type = CType::I64;
            ir.params = vec![
                Param {
                    index: 0,
                    name: "dst".to_owned(),
                    ty: CType::pointer_to(CType::Void),
                },
                Param {
                    index: 1,
                    name: "src".to_owned(),
                    ty: CType::pointer_to(CType::Void),
                },
                Param {
                    index: 2,
                    name: "n".to_owned(),
                    ty: CType::U64,
                },
                Param {
                    index: 3,
                    name: "count".to_owned(),
                    ty: CType::pointer_to(CType::U64),
                },
            ];
            let types = crate::loader::dwarf::FunctionTypes {
                globals: Vec::new(),
                params: Vec::new(),
                ret: ret.clone(),
                ret_aggregate_size: None,
                param_aggregate_sizes: Vec::new(),
                variadic: false,
                members: Vec::new(),
                definitions: Vec::new(),
                locals: Vec::new(),
                registers: Vec::new(),
                param_layouts: Vec::new(),
                ret_layout: Ok(None),
                abi_profile: Ok(AbiProfile::Aapcs64),
                source: crate::ir::calls::FunctionSource {
                    function: crate::ir::calls::TypeSource { unit: 0, die: 0 },
                    parameters: Vec::new(),
                    result: None,
                },
            };
            assert!(super::abi::declaration(&types).is_none());
            let analyzed = super::optimize(
                &image,
                super::Lifted {
                    ir,
                    has_jump_tables: false,
                    types: Some(types),
                },
                None,
            )
            .unwrap();
            let expected = ret.unwrap_or_else(|| CType::pointer_to(CType::Void));
            assert_eq!(analyzed.ir.ret_type, expected);
            let mut symbols = crate::render::Symbols::default();
            symbols.import_slots.insert(0x1000, "memcpy".to_owned());
            symbols
                .import_returns
                .insert(0x1000, CType::pointer_to(CType::Void));
            let rendered = crate::render::render(&analyzed.ir, &analyzed.references, &symbols, &[]);
            let declaration = if expected.is_pointer() {
                "void *copy_and_note("
            } else {
                "uint64_t copy_and_note("
            };
            assert!(rendered.contains(declaration), "{rendered}");
        }
    }

    fn ends_through_pointer(code: Vec<u8>) -> Option<Stmt> {
        let size = code.len() as u64;
        let image = Image::from_code(Isa::X86_64, 0, code);
        let mut blocks = crate::lift::lift(&image, 0, size, &HashSet::new()).expect("lifts");
        super::tail_calls_through_pointers(&mut blocks, &HashSet::new(), &image);
        blocks[0].stmts.iter().rev().nth(1).cloned()
    }

    #[test]
    fn a_jump_through_a_register_is_a_tail_call_only_with_the_stack_as_on_entry() {
        // jmp rax
        assert!(matches!(
            ends_through_pointer(vec![0xff, 0xe0]),
            Some(Stmt::Call { .. })
        ));
        // mov rax, rdi; jmp rax
        assert!(matches!(
            ends_through_pointer(vec![0x48, 0x89, 0xf8, 0xff, 0xe0]),
            Some(Stmt::Call { .. })
        ));
        // lea rax, [rdi + 8]; jmp rax
        assert!(!matches!(
            ends_through_pointer(vec![0x48, 0x8d, 0x47, 0x08, 0xff, 0xe0]),
            Some(Stmt::Call { .. })
        ));
        // push rbx; jmp rax
        assert!(!matches!(
            ends_through_pointer(vec![0x53, 0xff, 0xe0]),
            Some(Stmt::Call { .. })
        ));
    }

    #[test]
    fn scalar_void_return_preserves_output_register_definitions() {
        use crate::ir::{CType, Convention, Expr, FunctionIr};
        let mut image = Image::from_code(Isa::X86_64, 0, Vec::new());
        image.imports.insert(0x1000, "free".to_owned());
        let mut outputs = crate::ir::fallback_call_outputs(Convention::SysV, None);
        outputs.swap(0, 1);
        let expected = outputs.clone();
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Call {
                    kind: crate::ir::CallKind::Invoke,
                    target: None,
                    through: Some(Expr::Load {
                        addr: Box::new(Expr::Const(0x1000)),
                        width: 8,
                        signed: false,
                    }),
                    convention: Convention::SysV,
                    args: Some(Vec::new()),
                    floats_named: true,
                    abi: None,
                    outputs,
                    clobbers: None,
                    via: None,
                },
                Stmt::Ret {
                    value: Expr::reg(0, 64),
                },
            ],
        );
        ir.ret_type = CType::U64;
        super::apply_call_return(&mut ir, &image);
        assert_eq!(ir.ret_type, CType::Void);
        assert_eq!(ir.blocks[0].stmts[0].call_outputs(), expected.as_slice());
        assert!(matches!(
            ir.blocks[0].stmts[1],
            Stmt::Ret {
                value: Expr::Const(0)
            }
        ));
    }

    #[test]
    fn floating_return_evidence_survives_only_preserving_calls() {
        use crate::ir::{Convention, Expr, Precision, RegRef};
        for (isa, convention, slot) in [
            (Isa::X86_64, Convention::SysV, crate::arch::x86::XMM0),
            (Isa::AArch64, Convention::Aapcs64, crate::arch::aarch64::V0),
        ] {
            for changed in [false, true] {
                let clobbers = Some(if changed {
                    [slot].into_iter().collect()
                } else {
                    Default::default()
                });
                let blocks = [crate::ir::Block {
                    start: 0,
                    stmts: vec![
                        Stmt::Assign {
                            dest: RegRef {
                                index: slot,
                                width: 64,
                            },
                            value: Expr::Load {
                                addr: Box::new(Expr::Const(0x1000)),
                                width: 4,
                                signed: false,
                            },
                        },
                        Stmt::Call {
                            kind: crate::ir::CallKind::Invoke,
                            target: Some(0x2000),
                            through: None,
                            convention,
                            args: Some(Vec::new()),
                            floats_named: true,
                            abi: None,
                            outputs: crate::ir::fallback_call_outputs(convention, clobbers),
                            clobbers,
                            via: None,
                        },
                        Stmt::Ret {
                            value: Expr::reg(slot, 32),
                        },
                    ],
                }];
                assert_eq!(
                    super::float_result(&blocks, &Image::from_code(isa, 0, Vec::new())),
                    (!changed).then_some(Precision::Single)
                );
            }
        }
    }

    #[test]
    fn known_float_forwarding_requires_the_fp_output_register() {
        use crate::ir::{CType, Convention, Expr, FunctionIr, VARIABLE_BASE};
        for present in [false, true] {
            let mut image = Image::from_code(Isa::X86_64, 0, Vec::new());
            image.imports.insert(0x1000, "strtod".to_owned());
            let mut outputs = crate::ir::fallback_call_outputs(Convention::SysV, None);
            outputs.retain(|output| present || output.register != crate::arch::x86::XMM0);
            outputs.reverse();
            for output in &mut outputs {
                output.dest.index = VARIABLE_BASE + output.register;
            }
            let returned = VARIABLE_BASE + if present { crate::arch::x86::XMM0 } else { 0 };
            let mut ir = FunctionIr::single_block(
                Isa::X86_64,
                vec![
                    Stmt::Call {
                        kind: crate::ir::CallKind::Invoke,
                        target: None,
                        through: Some(Expr::Load {
                            addr: Box::new(Expr::Const(0x1000)),
                            width: 8,
                            signed: false,
                        }),
                        convention: Convention::SysV,
                        args: Some(Vec::new()),
                        floats_named: true,
                        abi: None,
                        outputs,
                        clobbers: None,
                        via: None,
                    },
                    Stmt::Ret {
                        value: Expr::reg(returned, 64),
                    },
                ],
            );
            ir.ret_type = CType::U64;
            super::apply_call_return(&mut ir, &image);
            assert_eq!(
                ir.ret_type,
                if present {
                    CType::Named("double".to_owned())
                } else {
                    CType::U64
                }
            );
        }
    }
}

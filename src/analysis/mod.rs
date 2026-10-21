mod clobbers;
mod indirect;
mod jump_table;
pub mod prototypes;
pub mod refs;
mod results;
#[cfg(test)]
mod semantics_tests;
mod signature;
mod structures;
pub(crate) mod summary;
pub(crate) mod typing;
pub(crate) mod variadic;

use std::collections::HashSet;

use crate::error::LiftError;
use crate::ir::{FunctionIr, Stmt};
use crate::loader::{Function, Image};
use crate::{lift, passes};
use refs::Reference;
pub use summary::summary;

/// Bytes lifted for a function whose extent neither symbols nor scanning give.
pub const UNKNOWN_SIZE: u64 = 256;

#[derive(Debug, Clone)]
pub struct Analysis {
    pub ir: FunctionIr,
    pub references: Vec<Reference>,
}

impl Analysis {
    pub fn strings(&self) -> Vec<String> {
        self.references
            .iter()
            .filter_map(|r| r.text.clone())
            .collect()
    }
}

pub fn analyze(image: &Image, function: &Function) -> Result<Analysis, LiftError> {
    let lifted = lift_function(image, function)?;
    Ok(optimize(image, lifted))
}

fn float_return_slot(isa: crate::loader::Isa) -> Option<u16> {
    match isa {
        crate::loader::Isa::X86_64 => Some(crate::arch::x86::XMM0),
        crate::loader::Isa::AArch64 => Some(crate::arch::aarch64::V0),
        crate::loader::Isa::Unsupported => None,
    }
}

/// Whether, without debug info, the function returns a float, and which:
/// every path to a return writes the float return register, and either
/// some path leaves the integer one as it came in, or every path writes it
/// before the float one. On x86-64 an untouched integer register means
/// nothing, and on AArch64 it is the first argument, which a function
/// returning a float does not return. A float is a single when the last
/// write on every path that says computes or loads one.
fn float_result(
    blocks: &[crate::ir::Block],
    isa: crate::loader::Isa,
) -> Option<crate::ir::Precision> {
    use crate::ir::{Precision, Stmt};
    let slot = float_return_slot(isa)?;
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
                    state = State {
                        float: true,
                        int: true,
                        float_last: false,
                        precision: None,
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
    let int_first = returns.iter().all(|state| !state.int || state.float_last);
    let single = returns
        .iter()
        .any(|state| state.precision == Some(Precision::Single))
        && returns
            .iter()
            .all(|state| state.precision != Some(Precision::Double));
    (floats && int_first).then_some(if single {
        Precision::Single
    } else {
        Precision::Double
    })
}

/// The precision of the float a write to the vector register `slot` puts
/// in its low half: what an operation computes or a load reads. x86 merges
/// a single into the register's other bits, and AArch64 clears them.
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
        while let Expr::Reg { index, .. } = copied {
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
            target: None,
            through: Some(through),
            convention: crate::ir::Convention::of(image.isa, image.format, image.go),
            args: None,
            floats_named: false,
            clobbers: None,
            result: None,
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
        crate::loader::Isa::X86_64 => (0, 2),
        crate::loader::Isa::AArch64 => (0, 1),
        crate::loader::Isa::Unsupported => return,
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
        let falls = at + 1;
        match blocks[at].stmts.last() {
            Some(Stmt::Br {
                target: Some(target),
            }) => pending.extend(index.get(target)),
            Some(Stmt::Brif { target, .. } | Stmt::BrifFlags { target, .. }) => {
                pending.extend(index.get(target));
                pending.push(falls);
            }
            Some(Stmt::Switch { cases, default, .. }) => {
                pending.extend(cases.iter().filter_map(|(_, target)| index.get(target)));
                pending.extend(default.iter().filter_map(|target| index.get(target)));
            }
            Some(Stmt::Ret { .. } | Stmt::Trap) => {}
            _ => pending.push(falls),
        }
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
fn zero_fixed_register(blocks: &mut [crate::ir::Block], isa: crate::loader::Isa) {
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
        let [
            ..,
            call @ Stmt::Call { target, result, .. },
            Stmt::Ret { value },
        ] = block.stmts.as_slice()
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
        let carried = result.map_or(crate::arch::RETURN, |result| result.index);
        let returned_type = match (prototype, target) {
            (Some(prototype), _) => prototype.ret.clone(),
            (None, Some(target)) => match returned_type(image, *target) {
                Some(returned_type) => returned_type,
                None => return,
            },
            (None, None) => return,
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
                if let [.., Stmt::Call { result, .. }, Stmt::Ret { value }] =
                    block.stmts.as_mut_slice()
                {
                    *result = None;
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
    let analysis = analyze(image, function);
    UNDER_WAY.with(|under_way| under_way.borrow_mut().remove(&addr));
    match analysis.ok()?.ir.ret_type {
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
fn set_up_arguments(ir: &mut FunctionIr) {
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
    for block in &mut ir.blocks {
        let mut written: HashSet<u16> = HashSet::new();
        for stmt in &mut block.stmts {
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
                        .map(|register| crate::ir::Expr::reg(*register, 64))
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
/// code, or constant data. Other loads may touch a device and stay.
fn drop_dead_constant_reads(ir: &mut FunctionIr, image: &Image) {
    use crate::ir::Expr;
    let constant = |address: u64| {
        image.section_at(address).is_some_and(|section| {
            section.executable
                || section.name.contains("rodata")
                || section.name.contains("rel.ro")
                || section.name.contains("__const")
        })
    };
    // Every load reads at a constant base inside such memory, plus offsets.
    fn constant_loads(expr: &Expr, constant: &dyn Fn(u64) -> bool) -> bool {
        match expr {
            Expr::Load { addr, .. } => {
                let mut base = None;
                let mut terms = vec![addr.as_ref()];
                while let Some(term) = terms.pop() {
                    match term {
                        Expr::Bin {
                            op: crate::ir::BinOp::Add,
                            lhs,
                            rhs,
                        } => terms.extend([lhs.as_ref(), rhs.as_ref()]),
                        Expr::Const(value) => base = Some(*value),
                        other if !constant_loads(other, constant) => return false,
                        _ => {}
                    }
                }
                base.is_some_and(constant)
            }
            other => crate::ir::visit::children(other)
                .into_iter()
                .all(|child| constant_loads(child, constant)),
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
                && constant_loads(value, &constant)
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

/// Drops a write of AArch64's indirect result register that only a call
/// reads, implicitly, when the callee does not return through memory: the
/// compiler used it as a scratch register for the call's arguments.
/// A function returning a structure too large for registers writes it
/// through a pointer its caller passes first and returns that pointer: the
/// first parameter is the result, no parameter of the source.
fn name_indirect_result(ir: &mut FunctionIr) {
    use crate::ir::{Convention, Expr};
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
    for block in &mut ir.blocks {
        let mut dead = Vec::new();
        for (position, stmt) in block.stmts.iter().enumerate() {
            let Stmt::Assign { dest, .. } = stmt else {
                continue;
            };
            if dest.index != INDIRECT {
                continue;
            }
            for later in &block.stmts[position + 1..] {
                match later {
                    Stmt::Call {
                        target: Some(target),
                        args: Some(_),
                        ..
                    } if !later.operands().into_iter().any(reads)
                        && !summary::summary(image, *target).indirect_result =>
                    {
                        dead.push(position);
                        break;
                    }
                    _ => {
                        let (writes, read) = crate::ir::visit::statement_registers(later);
                        if read.contains(&INDIRECT) || writes.contains(&INDIRECT) {
                            break;
                        }
                    }
                }
            }
        }
        for position in dead.into_iter().rev() {
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
        let mut cases = HashSet::new();
        for function in image.functions.values() {
            if !function
                .sources
                .contains(&crate::loader::NameSource::Prologue)
            {
                continue;
            }
            let size = function.size.unwrap_or(UNKNOWN_SIZE);
            // Function extents are still settling, so no callee is summarized yet.
            let Ok(blocks) = lift::lift_with(image, function.addr, size, &HashSet::new(), &|_| {
                crate::loader::Summary::default()
            }) else {
                continue;
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

fn lift_function(image: &Image, function: &Function) -> Result<Lifted, LiftError> {
    let size = function.size.unwrap_or(UNKNOWN_SIZE);
    let extent = function.addr..function.addr.saturating_add(size);
    // Landing pads start blocks of their own, which exceptions enter.
    let landing_pads: Vec<(u64, Vec<(u64, u64)>)> = image
        .landing_pads
        .range(extent.clone())
        .map(|(pad, sites)| (*pad, sites.clone()))
        .collect();
    let pads: HashSet<u64> = landing_pads.iter().map(|(pad, _)| *pad).collect();
    // A block ends where the calls that unwind into a pad do, so the state
    // after them is what the pad receives.
    let starts: HashSet<u64> = landing_pads
        .iter()
        .flat_map(|(_, sites)| sites.iter().map(|(_, end)| *end))
        .filter(|end| extent.contains(end))
        .chain(pads.iter().copied())
        .collect();
    let mut blocks = lift::lift(image, function.addr, size, &starts)?;
    let mut tables = jump_table::recover(&blocks, image, extent.clone());
    // Cases start blocks of their own, which may hold further tables.
    let mut targets: HashSet<u64> = starts.clone();
    for _ in 0..4 {
        let found: HashSet<u64> = tables
            .iter()
            .flat_map(jump_table::Recovered::targets)
            .collect();
        if found.is_subset(&targets) {
            break;
        }
        targets.extend(found);
        blocks = lift::lift(image, function.addr, size, &targets)?;
        tables = jump_table::recover(&blocks, image, extent.clone());
    }
    if image.go {
        drop_stack_growth_check(&mut blocks, image);
        zero_fixed_register(&mut blocks, image.isa);
    }
    receive_exceptions(&mut blocks, &pads, image.isa);
    let switched: HashSet<u64> = tables.iter().map(|table| table.block_start).collect();
    tail_calls_through_pointers(&mut blocks, &switched, image);
    indirect::resolve(&mut blocks, &landing_pads, image);
    let types = crate::loader::dwarf::function_types(image, function.addr);
    // A function returning a float returns it in xmm0 or v0.
    let declared = types.as_ref().and_then(|types| types.ret.as_ref());
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
        None => float_result(&blocks, image.isa),
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
    // The signature reads the returns as they now are, and the cases
    // through the switches.
    jump_table::apply(&mut blocks, &tables);
    // Go has no landing pads an unwinder enters, so code no path reaches,
    // as the epilogue after a call that does not return, is dead; so is a
    // linkage stub's code for binding its import on first use.
    if image.go || function.sources.contains(&crate::loader::NameSource::Plt) {
        drop_unreached(&mut blocks);
    }
    let mut signature = signature::recover_with(
        &blocks,
        image.isa,
        image.convention_of(function.addr),
        image.go,
        &|stmt| prototypes::called(image, stmt),
    );
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
                    size: 8,
                    name: format!("a{position}"),
                    ty,
                    position,
                }
            })
            .collect(),
    };
    let ir = FunctionIr {
        isa: image.isa,
        convention: image.convention_of(function.addr),
        params: signature.params,
        stack_params,
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
            None => signature.ret,
        },
        accesses: signature.accesses,
        members: Vec::new(),
        structures,
        signed_params: signature.signed,
        landing_pads,
        pointer_values: Vec::new(),
        value_types: std::collections::BTreeMap::new(),
        variable_registers: std::collections::BTreeMap::new(),
        addr: function.addr,
        name: function.name.clone(),
        size,
        blocks,
    };
    Ok(Lifted {
        ir,
        has_jump_tables: !tables.is_empty(),
        types,
    })
}

fn optimize(image: &Image, lifted: Lifted) -> Analysis {
    let Lifted {
        mut ir,
        has_jump_tables,
        types,
    } = lifted;
    let uniform_32 = passes::widths::specialize_widths(&mut ir, &|target| {
        summary::summary(image, target).narrow_return
    });
    // Before the stack adjustments a call reads unseen, such as the push
    // of an argument, are dropped as dead.
    crate::ssa::count_variadic_arguments(&mut ir, image);
    crate::ssa::undefine_clobbered_reads(&mut ir);
    let reached = crate::ir::cfg::reached(&ir);
    passes::optimize(&mut ir, has_jump_tables);
    drop_folded_away(&mut ir, &reached);
    set_up_arguments(&mut ir);
    passes::dce::dce(&mut ir);
    // Every general register becomes the variables it holds, apart from the
    // stack pointer, and the frame pointer while it addresses the frame.
    // So do the vector registers, each half on its own, and the registers
    // the lifter keeps flag operands and exchanged values in.
    let sp = crate::arch::stack_pointer(ir.isa);
    let fp = crate::arch::frame_pointer(ir.isa);
    let addresses_frame = ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .any(|stmt| match stmt {
            Stmt::Assign { dest, value } if dest.index == fp => {
                let mut read = HashSet::new();
                crate::ir::visit::collect_reads(value, &mut read);
                read.contains(&sp)
            }
            _ => false,
        });
    let general: Vec<u16> = match ir.isa {
        crate::loader::Isa::AArch64 => (0..=30).collect::<Vec<u16>>(),
        _ => (0..16).collect(),
    }
    .into_iter()
    .filter(|register| *register != sp && (*register != fp || !addresses_frame))
    .chain(
        crate::arch::machine_registers()
            .filter(|register| crate::arch::vector_half(ir.isa, *register).is_some()),
    )
    .chain(crate::ir::FLAG_OPERANDS)
    .chain(crate::ir::FLAG_CARRIED)
    .chain([crate::ir::EXCHANGE, crate::ir::SWITCH_INDEX])
    .collect();
    // Bits no read looks at go first, so the variables they tied split apart;
    // a narrow return reads fewer of them.
    typing::apply_partial_return(&mut ir);
    crate::ssa::narrow_partial_writes(&mut ir);
    crate::ssa::split_variables(&mut ir, &general);
    // The new variables leave copies between them to fold away, and values
    // spilled across calls that now survive them in their variables.
    passes::copies::copy_propagate_guarded(&mut ir);
    if !has_jump_tables {
        passes::memory::forward_stored_values(&mut ir);
    }
    passes::dce::dce(&mut ir);
    typing::apply_width_types(&mut ir, &uniform_32);
    typing::apply_void_return(&mut ir);
    typing::apply_partial_return(&mut ir);
    apply_call_return(&mut ir, image);
    typing::apply_dwarf_types(types, &mut ir);
    // A narrower return reads fewer bits, which may leave more of a
    // partial write unread.
    crate::ssa::narrow_partial_writes(&mut ir);
    passes::copies::copy_propagate_guarded(&mut ir);
    passes::simplify::simplify(&mut ir);
    // With the variables split, what they hold narrows again.
    crate::ssa::ranges::simplify(&mut ir);
    // Simplifying can fold a variable's value into its readers.
    passes::dce::dce(&mut ir);
    passes::coalesce::coalesce_copies(&mut ir);
    drop_unread_indirect_result(&mut ir, image);
    name_indirect_result(&mut ir);
    structures::recover(&mut ir);
    // It returns the pointer it wrote the result through.
    if let Some(result) = ir.params.iter().find(|param| param.name == "result") {
        ir.ret_type = result.ty.clone();
    }
    let references = refs::collect(&ir, image);
    passes::frame_slots::settle(&mut ir);
    drop_stack_protector(&mut ir, image);
    // Settling simplifies again, which can leave a table read unused.
    drop_dead_constant_reads(&mut ir, image);
    crate::ssa::take_results_directly(&mut ir);
    // A variable passed where a callee takes a pointer holds one.
    let mut pointer_values = Vec::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        if let Stmt::Call {
            target: Some(target),
            args: Some(args),
            ..
        } = stmt
        {
            let pointers = summary::summary(image, *target).pointers;
            for (position, arg) in args.iter().enumerate().take(32) {
                if pointers & 1 << position != 0
                    && let crate::ir::Expr::Reg { index, width: 64 } = arg
                    && *index >= crate::ir::VARIABLE_BASE
                {
                    pointer_values.push(*index);
                }
            }
        }
    }
    ir.pointer_values = pointer_values;
    typing::apply_prototypes(&mut ir, image);
    variadic::mark_variadic(&mut ir);
    Analysis { ir, references }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::ir::Stmt;
    use crate::loader::{Image, Isa};

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
}

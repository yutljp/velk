mod aarch64;
mod exits;
mod flags;
#[cfg(test)]
mod hardware;
mod x86_64;

pub(crate) use exits::stack_heights;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::error::LiftError;
use crate::ir::visit::{children, expr_reads};
use crate::ir::{Block, Convention, Expr, FLAG_OPERANDS, RegRef, Stmt};
use crate::loader::{Image, Isa, Summary};

const MAX_INSTRUCTIONS: usize = 8192;

struct Decoded<I> {
    pc: u64,
    next: u64,
    instruction: I,
}

trait Machine {
    type Instruction;

    fn branch_target(&self, instruction: &Self::Instruction, pc: u64) -> Option<u64>;
    /// Appends the instruction's statements and reports whether it ends the block.
    fn step(&mut self, instruction: &Self::Instruction, pc: u64) -> bool;
    fn take_statements(&mut self) -> Vec<Stmt>;
    /// The previous instruction ended its block.
    fn block_ended(&mut self);
    /// A branch target splits the block; the fall-through path continues into it.
    fn block_split(&mut self);
    /// The flags as the code so far leaves them.
    fn exit_flags(&self) -> Option<flags::Flags>;
    /// Whether an instruction since the block began may have changed the
    /// flags.
    fn flags_touched(&self) -> bool;
    /// The flags a new block starts from.
    fn enter_block(&mut self, flags: Option<flags::Flags>);
    /// Blocks an instruction that loops by itself adds after the one it ends
    /// (an x86 `rep` string instruction's body).
    fn take_extra_blocks(&mut self) -> Vec<Block> {
        Vec::new()
    }
}

/// How a block leaves the flags: as its own code set them, if it changed
/// them, or else as they came in.
#[derive(Clone)]
struct Exit {
    flags: Option<flags::Flags>,
    touched: bool,
}

/// The flags each block that reads them unknown should start from, and the
/// blocks before them that pass their flags on.
#[derive(Default)]
struct CarriedFlags {
    entry: HashMap<u64, flags::Flags>,
    exporters: HashSet<u64>,
}

/// What lifting needs to know of the functions a body calls.
pub type Summaries<'a> = &'a dyn Fn(u64) -> Summary;

/// Splits the function at `addr` into basic blocks; `extra_targets` adds
/// block starts the branches alone do not show, such as jump-table cases.
/// What each callee takes and whether it returns comes from its summary.
pub fn lift(
    image: &Image,
    addr: u64,
    size: u64,
    extra_targets: &HashSet<u64>,
) -> Result<Vec<Block>, LiftError> {
    let summaries = |target| crate::analysis::summary(image, target);
    if extra_targets.is_empty() {
        return lift_shared(image, addr, size, &summaries).map(Arc::unwrap_or_clone);
    }
    lift_with(image, addr, size, extra_targets, &summaries)
}

/// The lifts made so far, by function start, size and extra block starts,
/// each with what it asked of its callees. Lifting reads nothing else that
/// changes, so a lift whose callees all still answer the same is the lift
/// made again.
#[derive(Debug, Default)]
pub struct Lifts(Mutex<HashMap<LiftKey, Kept>>);

type LiftKey = (u64, u64, Vec<u64>);

/// The lifts kept of one function, oldest first.
type Kept = Vec<Arc<Recorded>>;

#[derive(Debug)]
struct Recorded {
    answers: Vec<(u64, Summary)>,
    blocks: Result<Arc<Vec<Block>>, LiftError>,
}

/// The lifts kept of one function: knowing no callee, as the call graph is
/// found, and knowing them all.
const KEPT_LIFTS: usize = 2;

/// `lift_with` and no extra block starts, sharing the lift with every other
/// caller that gets the same summaries.
pub fn lift_shared(
    image: &Image,
    addr: u64,
    size: u64,
    summaries: Summaries<'_>,
) -> Result<Arc<Vec<Block>>, LiftError> {
    lift_shared_with_targets(image, addr, size, &HashSet::new(), summaries)
}

pub(crate) fn lift_shared_with_targets(
    image: &Image,
    addr: u64,
    size: u64,
    extra_targets: &HashSet<u64>,
    summaries: Summaries<'_>,
) -> Result<Arc<Vec<Block>>, LiftError> {
    let mut targets: Vec<_> = extra_targets.iter().copied().collect();
    targets.sort_unstable();
    let key = (addr, size, targets);
    let kept = image
        .lifts
        .0
        .lock()
        .expect("lifts lock")
        .get(&key)
        .cloned()
        .unwrap_or_default();
    // Asked outside the lock: a summary may lift other functions.
    if let Some(found) = kept.iter().find(|recorded| {
        recorded
            .answers
            .iter()
            .all(|(target, summary)| calling(summaries(*target)) == *summary)
    }) {
        return found.blocks.clone();
    }
    let answers = std::cell::RefCell::new(Vec::new());
    let blocks = lift_with(image, addr, size, extra_targets, &|target| {
        let summary = summaries(target);
        answers.borrow_mut().push((target, calling(summary)));
        summary
    })
    .map(Arc::new);
    let mut answers = answers.into_inner();
    answers.sort_unstable_by_key(|(target, _)| *target);
    answers.dedup_by_key(|(target, _)| *target);
    let mut lifts = image.lifts.0.lock().expect("lifts lock");
    let kept = lifts.entry(key).or_default();
    if kept.len() == KEPT_LIFTS {
        kept.remove(0);
    }
    kept.push(Arc::new(Recorded {
        answers,
        blocks: blocks.clone(),
    }));
    blocks
}

/// What a call needs of its callee's summary. Lifting reads nothing else,
/// so lifts that differ only in the rest are the same lift.
pub(crate) fn calling(summary: Summary) -> Summary {
    Summary {
        pointers: 0,
        indirect_result: false,
        narrow_return: false,
        ..summary
    }
}

/// `lift`, knowing of callees only what `summaries` says.
pub fn lift_with(
    image: &Image,
    addr: u64,
    size: u64,
    extra_targets: &HashSet<u64>,
    summaries: Summaries<'_>,
) -> Result<Vec<Block>, LiftError> {
    let summaries: Summaries<'_> = &|target| calling(summaries(target));
    let bytes = image.read_vaddr(addr, size).ok_or(LiftError::Unreadable)?;
    match image.isa {
        Isa::AArch64 => lift_continuing(
            image,
            summaries,
            || aarch64::Lifter::new(image, summaries),
            addr,
            bytes,
            aarch64::decode,
            extra_targets,
        ),
        Isa::X86_64 => {
            let mut blocks = lift_continuing(
                image,
                summaries,
                || x86_64::Lifter::new(image, summaries),
                addr,
                bytes,
                x86_64::decode,
                extra_targets,
            )?;
            if image.go {
                take_stack_results(&mut blocks, image, summaries);
            }
            Ok(blocks)
        }
        Isa::Unsupported => Err(LiftError::UnsupportedIsa),
    }
}

/// `value`, `width` bits wide, rotated by `amount`, which wraps at the width,
/// towards the low bits or the high ones. Bits above the width are left for
/// the write to clear.
fn rotate(value: Expr, amount: Expr, width: u8, right: bool) -> Expr {
    use crate::ir::BinOp;
    let bits = u64::from(width);
    let (amount, back) = match amount {
        Expr::Const(amount) => match amount % bits {
            0 => return value,
            amount => (Expr::constant(amount), Expr::constant(bits - amount)),
        },
        amount => {
            let amount = Expr::bin(BinOp::And, amount, Expr::constant(bits - 1));
            // A rotation by zero shifts back by zero too, not by the width.
            let back = Expr::bin(
                BinOp::And,
                Expr::bin(BinOp::Sub, Expr::constant(bits), amount.clone()),
                Expr::constant(bits - 1),
            );
            (amount, back)
        }
    };
    let (towards, from) = if right {
        (BinOp::Shr, BinOp::Shl)
    } else {
        (BinOp::Shl, BinOp::Shr)
    };
    Expr::bin(
        BinOp::Or,
        Expr::bin(towards, value.clone(), amount),
        Expr::bin(from, value, back),
    )
}

/// `value`, `width` bits wide, with the order of the bytes reversed within
/// each `chunk` bytes.
fn reverse_bytes(value: Expr, width: u8, chunk: u8) -> Expr {
    use crate::ir::BinOp;
    let bytes = width / 8;
    (0..bytes)
        .map(|byte| {
            let start = byte - byte % chunk;
            let target = start + (chunk - 1 - byte % chunk);
            let field = Expr::bin(
                BinOp::And,
                Expr::bin(
                    BinOp::Shr,
                    value.clone(),
                    Expr::constant(8 * u64::from(byte)),
                ),
                Expr::constant(0xff),
            );
            Expr::bin(BinOp::Shl, field, Expr::constant(8 * u64::from(target)))
        })
        .reduce(|all, field| Expr::bin(BinOp::Or, all, field))
        .unwrap_or(value)
}

type Decoder<I> = fn(&[u8], u64) -> (Vec<Decoded<I>>, Option<String>);

/// The function's blocks, lifted again with the code its branches out
/// continue in, which is no tail call, until no more such code turns up.
fn lift_continuing<M: Machine>(
    image: &Image,
    summaries: Summaries<'_>,
    machine: impl Fn() -> M,
    addr: u64,
    bytes: &[u8],
    decode: Decoder<M::Instruction>,
    extra_targets: &HashSet<u64>,
) -> Result<Vec<Block>, LiftError> {
    let mut pulled = exits::Pulled::new();
    let mut rounds = 0;
    loop {
        rounds += 1;
        let (decoded, stop) =
            decode_with_fragments(image, &machine(), addr, bytes, decode, &pulled);
        let (blocks, more) = build_carrying(
            image,
            summaries,
            &machine,
            addr,
            &decoded,
            stop,
            extra_targets,
        )?;
        let known = pulled.len();
        pulled.extend(more);
        if pulled.len() == known || rounds == 4 {
            return Ok(blocks);
        }
    }
}

/// The function's instructions, followed by those of the code `pulled`
/// names and of every fragment split off it, such as a cold part, that its
/// branches reach.
fn decode_with_fragments<M: Machine>(
    image: &Image,
    machine: &M,
    addr: u64,
    bytes: &[u8],
    decode: Decoder<M::Instruction>,
    pulled: &exits::Pulled,
) -> (Vec<Decoded<M::Instruction>>, Option<String>) {
    let (mut decoded, stop) = decode(bytes, addr);
    for (start, size) in pulled {
        if let Some(bytes) = image.read_vaddr(*start, *size) {
            decoded.extend(decode(bytes, *start).0);
        }
    }
    let mut included = HashSet::new();
    let mut scanned = 0;
    while scanned < decoded.len() {
        let reached: Vec<(u64, u64)> = decoded[scanned..]
            .iter()
            .filter_map(|d| machine.branch_target(&d.instruction, d.pc))
            .filter(|target| !image.functions.contains_key(target))
            .filter_map(|target| image.fragment_at(target))
            .filter(|(start, _)| included.insert(*start))
            .collect();
        scanned = decoded.len();
        for (start, size) in reached {
            if let Some(bytes) = image.read_vaddr(start, size) {
                decoded.extend(decode(bytes, start).0);
            }
        }
    }
    (decoded, stop)
}

/// What an instruction is about to overwrite.
enum Write<'a> {
    /// A register and, when the register then holds exactly it, the value it receives.
    Register(u16, Option<&'a Expr>),
    Memory,
}

/// Before a write, keeps the pending compare testing the values its flags
/// were set from: an operand equal to the value written reads the register
/// afterwards, the operand of a written sum or difference is recovered from
/// the register, and any other operand reading what is overwritten moves into
/// a register of its own.
fn preserve_compare(compare: &mut Option<flags::Flags>, write: Write<'_>, stmts: &mut Vec<Stmt>) {
    let Some(flags) = compare else {
        return;
    };
    let clobbered = |expr: &Expr| match write {
        Write::Register(index, _) => {
            let mut reads = HashSet::new();
            expr_reads(expr, &mut reads);
            reads.contains(&index)
        }
        Write::Memory => reads_memory(expr),
    };
    for (slot, operand) in FLAG_OPERANDS.into_iter().zip(flags.operands_mut()) {
        if !clobbered(operand) {
            continue;
        }
        let width = match crate::ir::semantics::width(operand) {
            0 => 64,
            bits => bits as u8,
        };
        if let Write::Register(index, Some(value)) = write {
            if operand == value {
                *operand = Expr::reg(index, width);
                continue;
            }
            if let Some(recovered) = recover_operand(operand, value, index, width) {
                *operand = recovered;
                continue;
            }
        }
        stmts.push(Stmt::Assign {
            dest: RegRef {
                index: slot,
                width: 64,
            },
            value: operand.clone(),
        });
        *operand = Expr::reg(slot, width);
    }
}

/// `a` from the register that receives `a - b`, `a + b` or `0 - a`, when
/// `b` does not read that register.
fn recover_operand(operand: &Expr, value: &Expr, index: u16, width: u8) -> Option<Expr> {
    let Expr::Bin { op, lhs, rhs } = value else {
        return None;
    };
    // A negation is undone by negating the register.
    if *op == crate::ir::BinOp::Sub && matches!(lhs.as_ref(), Expr::Const(0)) && **rhs == *operand {
        return Some(Expr::bin(
            crate::ir::BinOp::Sub,
            Expr::constant(0),
            Expr::reg(index, width),
        ));
    }
    let inverse = match op {
        crate::ir::BinOp::Sub => crate::ir::BinOp::Add,
        crate::ir::BinOp::Add => crate::ir::BinOp::Sub,
        _ => return None,
    };
    let mut reads = HashSet::new();
    expr_reads(rhs, &mut reads);
    (**lhs == *operand && !reads.contains(&index))
        .then(|| Expr::bin(inverse, Expr::reg(index, width), rhs.as_ref().clone()))
}

fn reads_memory(expr: &Expr) -> bool {
    matches!(expr, Expr::Load { .. }) || children(expr).into_iter().any(reads_memory)
}

/// The argument registers a call to `target` passes, when the number the
/// callee takes is known.
/// The arguments of a call reading `count` registers and `stack` slots
/// past them, as they stand at the call.
pub(crate) fn arguments(
    convention: Convention,
    isa: crate::loader::Isa,
    count: Option<usize>,
    stack: usize,
) -> Option<Vec<Expr>> {
    let count = count?;
    let mut args: Vec<Expr> = convention.arguments()[..count.min(convention.arguments().len())]
        .iter()
        .map(|register| Expr::reg(*register, 64))
        .collect();
    if let Some(start) = convention.stack_arguments() {
        let sp = crate::arch::stack_pointer(isa);
        for slot in 0..stack {
            let offset = start - convention.pushed_by_call() + 8 * slot as i64;
            args.push(Expr::Load {
                addr: Box::new(Expr::bin(
                    crate::ir::BinOp::Add,
                    Expr::reg(sp, 64),
                    Expr::Const(offset as u64),
                )),
                width: 8,
                signed: false,
            });
        }
    }
    Some(args)
}

/// A call to `target`. A variadic library function's arguments are left to
/// the analysis, which counts them from its format string.
pub(crate) fn call(image: &Image, summaries: Summaries<'_>, target: Option<u64>) -> Stmt {
    let name = target
        .and_then(|target| image.functions.get(&target))
        .and_then(|function| function.name.as_deref());
    if image.go && name.is_some_and(|name| name.starts_with("runtime.gcWriteBarrier")) {
        return Stmt::Call {
            target,
            through: None,
            convention: Convention::GoWriteBarrier,
            args: Some(Vec::new()),
            floats_named: false,
            clobbers: None,
            result: None,
            via: None,
        };
    }
    let convention = match target {
        Some(target) => image.convention_of(target),
        None => Convention::of(image.isa, image.format, image.go),
    };
    let variadic = target.is_some_and(|target| {
        image
            .functions
            .get(&target)
            .and_then(|function| function.name.as_deref())
            .and_then(|name| {
                crate::analysis::prototypes::of(name, image.format == crate::loader::Format::MachO)
            })
            .is_some_and(|prototype| prototype.format.is_some())
    });
    let summary = target.filter(|_| !variadic).map(summaries);
    let arity = summary.and_then(|summary| summary.arity);
    let stack = summary.map_or(0, |summary| summary.stack);
    let mut args = arguments(convention, image.isa, arity, stack);
    // Go's assembly ABI packs its arguments: the callee may read only the
    // low bytes of a slot.
    if let (Convention::GoAbi0, Some(args), Some(summary)) = (convention, &mut args, summary) {
        for (arg, read) in args.iter_mut().zip(summary.stack_widths) {
            if let Expr::Load { width, .. } = arg
                && read != 0
            {
                *width = read;
            }
        }
    }
    // The floating-point arguments follow the integer ones.
    let floats = summary
        .and_then(|summary| summary.floats)
        .filter(|_| args.is_some());
    if let (Some(args), Some(floats)) = (&mut args, floats) {
        args.extend(
            convention.float_arguments()[..floats.min(convention.float_arguments().len())]
                .iter()
                .map(|register| Expr::reg(*register, 64)),
        );
    }
    Stmt::Call {
        target,
        through: None,
        convention,
        args,
        floats_named: floats.is_some(),
        result: None,
        clobbers: summary.and_then(|summary| summary.clobbers),
        via: None,
    }
}

/// What a call to `target` under Go's assembly ABI leaves past its stack
/// arguments: its results, stored from the registers the convention moves
/// them through, so the caller's loads of them read the call's results.
pub(crate) fn stack_results(image: &Image, summaries: Summaries<'_>, target: u64) -> Vec<Stmt> {
    let convention = image.convention_of(target);
    if convention != Convention::GoAbi0 {
        return Vec::new();
    }
    let sp = crate::arch::stack_pointer(image.isa);
    summaries(target)
        .stack_results
        .iter()
        .take_while(|(_, width)| *width != 0)
        .zip(convention.results())
        .map(|((offset, width), register)| Stmt::Store {
            // Addressed as the caller's own loads of it are.
            addr: match offset {
                0 => Expr::reg(sp, 64),
                _ => Expr::bin(
                    crate::ir::BinOp::Add,
                    Expr::reg(sp, 64),
                    Expr::Const(u64::from(*offset)),
                ),
            },
            value: Expr::reg(*register, 64),
            width: *width,
        })
        .collect()
}

/// The offset from the stack pointer an address is, in the forms the lifter
/// writes: `sp` and `sp + k`.
fn stack_offset(addr: &Expr, sp: u16) -> Option<u64> {
    match addr {
        Expr::Reg { index, width: 64 } if *index == sp => Some(0),
        Expr::Bin {
            op: crate::ir::BinOp::Add,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Reg { index, width: 64 }, Expr::Const(offset)) if *index == sp => Some(*offset),
            _ => None,
        },
        _ => None,
    }
}

/// A caller of Go's assembly ABI reads the results right after the call.
/// Each such read of a whole result in the call's block takes the register
/// `stack_results` stored it from, while that still holds it. The store
/// goes when no later read may see it, on any path from the call.
fn take_stack_results(blocks: &mut [Block], image: &Image, summaries: Summaries<'_>) {
    let sp = crate::arch::stack_pointer(image.isa);
    for index in 0..blocks.len() {
        let mut at = 0;
        while at < blocks[index].stmts.len() {
            let stmts = &mut blocks[index].stmts;
            let Stmt::Call {
                target: Some(target),
                convention: Convention::GoAbi0,
                ..
            } = stmts[at]
            else {
                at += 1;
                continue;
            };
            let stored = stack_results(image, summaries, target).len();
            // Offset, width and register of each result.
            let fields: Vec<(u64, u8, u16)> = stmts
                .get(at + 1..at + 1 + stored)
                .unwrap_or_default()
                .iter()
                .filter_map(|stmt| match stmt {
                    Stmt::Store {
                        addr,
                        value: Expr::Reg { index, .. },
                        width,
                    } => Some((stack_offset(addr, sp)?, *width, *index)),
                    _ => None,
                })
                .collect();
            if fields.len() != stored {
                at += 1;
                continue;
            }
            // Whether the register still holds each result, and whether
            // the slot does, so that a later read may see it.
            let mut held = vec![true; stored];
            let mut open = vec![true; stored];
            let mut needed = vec![false; stored];
            // How far the stack pointer has moved since the call.
            let mut moved = Some(0u64);
            for stmt in &mut stmts[at + 1 + stored..] {
                let Some(delta) = moved else {
                    break;
                };
                for operand in stmt.operands_mut() {
                    take_result_reads(operand, sp, delta, &fields, &held, &open, &mut needed);
                }
                let written = crate::ir::visit::statement_registers(stmt).0;
                moved = stack_moved(stmt, sp, delta);
                for (position, field) in fields.iter().enumerate() {
                    if written.contains(&field.2) {
                        held[position] = false;
                    }
                    if let Some(covers) = stored_over(stmt, sp, delta, *field)
                        && open[position]
                    {
                        // Overwritten in part, the rest may still be read.
                        needed[position] |= !covers;
                        open[position] = false;
                    }
                }
            }
            for (position, field) in fields.iter().enumerate() {
                if open[position] && !needed[position] {
                    // Past an unknown move of the stack pointer, the slot is
                    // out of sight.
                    needed[position] = match moved {
                        None => true,
                        Some(delta) => {
                            ends_unknown(blocks, index)
                                || read_later(
                                    blocks,
                                    &crate::ir::cfg::block_successors(blocks, index),
                                    sp,
                                    delta,
                                    *field,
                                )
                        }
                    };
                }
            }
            let mut position = 0;
            blocks[index].stmts.retain(|_| {
                let index = position;
                position += 1;
                !(at < index && index <= at + stored) || needed[index - at - 1]
            });
            at += 1;
        }
    }
}

/// Replaces the loads of a whole result whose register still holds it with
/// that register, and notes the results other loads may read.
fn take_result_reads(
    expr: &mut Expr,
    sp: u16,
    delta: u64,
    fields: &[(u64, u8, u16)],
    held: &[bool],
    open: &[bool],
    needed: &mut [bool],
) {
    if let Expr::Load {
        addr,
        width,
        signed,
    } = expr
        && let Some(offset) = stack_offset(addr, sp)
    {
        let offset = offset.wrapping_add(delta);
        let (width, signed) = (*width, *signed);
        for (position, field) in fields.iter().enumerate() {
            if !open[position] || !overlaps((offset, width), *field) {
                continue;
            }
            if held[position] && (offset, width) == (field.0, field.1) {
                let register = Expr::reg(field.2, 8 * width);
                *expr = match signed {
                    true => Expr::SignExtend {
                        value: Box::new(register),
                        width,
                    },
                    false => register,
                };
                return;
            }
            needed[position] = true;
        }
    }
    for child in crate::ir::visit::children_mut(expr) {
        take_result_reads(child, sp, delta, fields, held, open, needed);
    }
}

fn overlaps((offset, width): (u64, u8), field: (u64, u8, u16)) -> bool {
    offset < field.0 + u64::from(field.1) && field.0 < offset + u64::from(width)
}

/// Whether the statement stores over the field, and then whether it covers
/// all of it.
fn stored_over(stmt: &Stmt, sp: u16, delta: u64, field: (u64, u8, u16)) -> Option<bool> {
    let Stmt::Store { addr, width, .. } = stmt else {
        return None;
    };
    let offset = stack_offset(addr, sp)?.wrapping_add(delta);
    overlaps((offset, *width), field)
        .then(|| offset <= field.0 && field.0 + u64::from(field.1) <= offset + u64::from(*width))
}

/// How far the stack pointer has moved after the statement, from `delta`
/// before it; `None` once that is unknown.
fn stack_moved(stmt: &Stmt, sp: u16, delta: u64) -> Option<u64> {
    if let Stmt::Assign { dest, value } = stmt
        && dest.index == sp
    {
        return match value {
            Expr::Bin { op, lhs, rhs } if stack_offset(lhs, sp) == Some(0) => {
                match (op, rhs.as_ref()) {
                    (crate::ir::BinOp::Add, Expr::Const(by)) => Some(delta.wrapping_add(*by)),
                    (crate::ir::BinOp::Sub, Expr::Const(by)) => Some(delta.wrapping_sub(*by)),
                    _ => None,
                }
            }
            _ => None,
        };
    }
    (!crate::ir::visit::statement_registers(stmt).0.contains(&sp)).then_some(delta)
}

/// Whether the block may go on to code not lifted with it.
fn ends_unknown(blocks: &[Block], index: usize) -> bool {
    let known = |target: &u64| blocks.iter().any(|block| block.start == *target);
    match blocks[index].stmts.last() {
        Some(Stmt::Br { target: None } | Stmt::BrIndirect { .. }) => true,
        Some(Stmt::Br {
            target: Some(target),
        }) => !known(target),
        Some(Stmt::Brif { target, .. } | Stmt::BrifFlags { target, .. }) => {
            !known(target) || index + 1 == blocks.len()
        }
        Some(Stmt::Ret { .. } | Stmt::Trap | Stmt::Switch { .. }) => false,
        _ => index + 1 == blocks.len(),
    }
}

/// Whether some path through the blocks from `starts` may load the field
/// before storing over all of it or returning, with the stack pointer
/// `delta` past where the call left it and moved only by constants.
fn read_later(
    blocks: &[Block],
    starts: &[usize],
    sp: u16,
    delta: u64,
    field: (u64, u8, u16),
) -> bool {
    fn reads(expr: &Expr, sp: u16, delta: u64, field: (u64, u8, u16)) -> bool {
        if let Expr::Load { addr, width, .. } = expr
            && stack_offset(addr, sp)
                .is_some_and(|offset| overlaps((offset.wrapping_add(delta), *width), field))
        {
            return true;
        }
        crate::ir::visit::children(expr)
            .into_iter()
            .any(|child| reads(child, sp, delta, field))
    }
    let mut seen = HashSet::new();
    let mut work: Vec<(usize, u64)> = starts.iter().map(|index| (*index, delta)).collect();
    'blocks: while let Some((index, mut delta)) = work.pop() {
        if !seen.insert((index, delta)) {
            continue;
        }
        // A loop that moves the stack pointer each time round never settles.
        if seen.len() > 4 * blocks.len() {
            return true;
        }
        for stmt in &blocks[index].stmts {
            if stmt
                .operands()
                .into_iter()
                .any(|operand| reads(operand, sp, delta, field))
            {
                return true;
            }
            if stored_over(stmt, sp, delta, field) == Some(true) {
                continue 'blocks;
            }
            let Some(moved) = stack_moved(stmt, sp, delta) else {
                return true;
            };
            delta = moved;
        }
        if ends_unknown(blocks, index) {
            return true;
        }
        work.extend(
            crate::ir::cfg::block_successors(blocks, index)
                .into_iter()
                .map(|next| (next, delta)),
        );
    }
    false
}

/// The function a pointer in data names, for a call or jump through it:
/// `call [slot]`, where the slot holds a known function's address and the
/// program cannot write another there.
pub(crate) fn pointer_target(image: &Image, through: &Expr) -> Option<u64> {
    let Expr::Load { addr, width: 8, .. } = through else {
        return None;
    };
    let Expr::Const(slot) = addr.as_ref() else {
        return None;
    };
    let section = image.section_at(*slot)?;
    if section.executable || !section.read_only {
        return None;
    }
    let bytes = image.read_vaddr(*slot, 8)?;
    let target = u64::from_le_bytes(bytes.try_into().ok()?);
    image.functions.contains_key(&target).then_some(target)
}

/// The name of the import whose slot `through` loads.
pub(crate) fn import_name<'a>(image: &'a Image, through: &Expr) -> Option<&'a str> {
    let Expr::Load { addr, width: 8, .. } = through else {
        return None;
    };
    let Expr::Const(slot) = addr.as_ref() else {
        return None;
    };
    image.imports.get(slot).map(String::as_str)
}

/// The import a call through `through` reaches, when it loads a slot the
/// dynamic linker fills, and what its name says of it.
pub(crate) fn import_called(image: &Image, through: &Expr) -> Option<crate::loader::Summary> {
    import_name(image, through).map(|name| crate::analysis::summary::import(image, name))
}

/// A call to the address `through` computes. One through an import's slot
/// passes the arguments its prototype takes.
pub(crate) fn call_through(image: &Image, through: Expr) -> Stmt {
    let convention = Convention::of(image.isa, image.format, image.go);
    let variadic = crate::lift::import_name(image, &through)
        .and_then(|name| {
            crate::analysis::prototypes::of(name, image.format == crate::loader::Format::MachO)
        })
        .is_some_and(|prototype| prototype.format.is_some());
    let arity = import_called(image, &through)
        .filter(|_| !variadic)
        .and_then(|summary| summary.arity);
    Stmt::Call {
        target: None,
        through: Some(through),
        convention,
        args: arguments(convention, image.isa, arity, 0),
        floats_named: false,
        clobbers: None,
        result: None,
        via: None,
    }
}

/// A jump out of the function: the callee's result is this function's,
/// unless the callee never returns.
fn tail_call(image: &Image, summaries: Summaries<'_>, target: Option<u64>) -> [Stmt; 2] {
    if target.is_some_and(|target| summaries(target).noreturn) {
        return [call(image, summaries, target), Stmt::Trap];
    }
    [
        call(image, summaries, target),
        Stmt::Ret {
            value: Expr::reg(crate::arch::RETURN, 64),
        },
    ]
}

/// The blocks, lifted once to find the blocks that read flags they do not
/// know and the flags each block ends with, and again where every block
/// before such a block ends with flags of one shape, which then carry over.
/// Also returns the code the branches out of it continue in.
fn build_carrying<M: Machine>(
    image: &Image,
    summaries: Summaries<'_>,
    machine: impl Fn() -> M,
    start: u64,
    decoded: &[Decoded<M::Instruction>],
    stop: Option<String>,
    extra_targets: &HashSet<u64>,
) -> Result<(Vec<Block>, exits::Pulled), LiftError> {
    let none = CarriedFlags::default();
    let (blocks, exits, pulled) = build(
        image,
        summaries,
        machine(),
        start,
        decoded,
        stop.clone(),
        extra_targets,
        &none,
    )?;
    let carried = carry_flags(&blocks, &exits, extra_targets);
    if carried.entry.is_empty() {
        return Ok((blocks, pulled));
    }
    let (blocks, _, pulled) = build(
        image,
        summaries,
        machine(),
        start,
        decoded,
        stop,
        extra_targets,
        &carried,
    )?;
    Ok((blocks, pulled))
}

/// Whether a block reads flags its own code did not set: a branch on them,
/// or a select, setcc or carry left unsupported for want of them.
fn reads_unknown_flags(block: &Block) -> bool {
    block.stmts.iter().any(|stmt| match stmt {
        Stmt::BrifFlags { .. } => true,
        Stmt::Unsupported { text, .. } => {
            text.contains("without compare") || text.contains("not modelled")
        }
        _ => false,
    })
}

/// The flags each block starts from, by a forward pass over the blocks: a
/// block that leaves the flags alone passes on what came in, one that sets
/// them passes on its own, and a join keeps flags only of one shape from
/// every block before it. Blocks that read flags they do not know start
/// from those; the blocks that set them pass their operands on. A
/// jump-table case may be entered by a jump the blocks do not show, so it
/// never takes flags.
fn carry_flags(
    blocks: &[Block],
    exits: &HashMap<u64, Exit>,
    extra_targets: &HashSet<u64>,
) -> CarriedFlags {
    let mut carried = CarriedFlags::default();
    let count = blocks.len();
    let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); count];
    for index in 0..count {
        for next in crate::ir::cfg::block_successors(blocks, index) {
            predecessors[next].push(index);
        }
    }
    let exit = |index: usize| exits.get(&blocks[index].start);
    // The shape of the flags on entry to each block: None for unknown.
    let mut entry: Vec<Option<flags::Flags>> = vec![None; count];
    let opaque = |index: usize| index == 0 || extra_targets.contains(&blocks[index].start);
    let out = |index: usize, entry: &[Option<flags::Flags>]| match exit(index) {
        Some(Exit {
            touched: true,
            flags,
        }) => flags.as_ref().map(|flags| flags.carried().0),
        Some(Exit { touched: false, .. }) => entry[index].clone(),
        None => None,
    };
    loop {
        let mut changed = false;
        for index in 0..count {
            if opaque(index) || predecessors[index].is_empty() {
                continue;
            }
            let shapes: Vec<Option<flags::Flags>> = predecessors[index]
                .iter()
                .map(|pred| out(*pred, &entry))
                .collect();
            let merged = match shapes.first() {
                Some(Some(first)) if shapes.iter().all(|shape| shape.as_ref() == Some(first)) => {
                    Some(first.clone())
                }
                _ => None,
            };
            if merged != entry[index] {
                entry[index] = merged;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    // The blocks that set the flags a reading block takes, through blocks
    // that pass them along.
    let exporters = |index: usize, exporters: &mut HashSet<u64>| {
        let mut work = predecessors[index].clone();
        let mut seen = HashSet::new();
        while let Some(pred) = work.pop() {
            if !seen.insert(pred) {
                continue;
            }
            match exit(pred) {
                Some(Exit { touched: true, .. }) => {
                    exporters.insert(blocks[pred].start);
                }
                _ => work.extend(predecessors[pred].iter().copied()),
            }
        }
    };
    for (index, block) in blocks.iter().enumerate() {
        if let Some(shape) = &entry[index]
            && reads_unknown_flags(block)
        {
            carried.entry.insert(block.start, shape.clone());
            exporters(index, &mut carried.exporters);
        }
    }
    carried
}

/// Ends a block: a block whose flags carry on passes their operands, before
/// the branch that leaves it.
fn finish_block<M: Machine>(
    machine: &M,
    start: u64,
    mut stmts: Vec<Stmt>,
    carried: &CarriedFlags,
    exits: &mut HashMap<u64, Exit>,
) -> Block {
    let exit = machine.exit_flags();
    if carried.exporters.contains(&start)
        && machine.flags_touched()
        && let Some(flags) = &exit
    {
        let (_, values) = flags.carried();
        let at = match stmts.last() {
            Some(
                Stmt::Br { .. }
                | Stmt::Brif { .. }
                | Stmt::BrifFlags { .. }
                | Stmt::Switch { .. }
                | Stmt::BrIndirect { .. },
            ) => stmts.len() - 1,
            _ => stmts.len(),
        };
        let passes = crate::ir::FLAG_CARRIED
            .into_iter()
            .zip(values)
            .map(|(slot, value)| Stmt::Assign {
                dest: RegRef {
                    index: slot,
                    width: 64,
                },
                value,
            });
        stmts.splice(at..at, passes);
    }
    exits.insert(
        start,
        Exit {
            flags: exit,
            touched: machine.flags_touched(),
        },
    );
    Block { start, stmts }
}

/// The blocks, the flags each leaves, and the code its branches out continue
/// in.
type Built = (Vec<Block>, HashMap<u64, Exit>, exits::Pulled);

#[allow(clippy::too_many_arguments)]
fn build<M: Machine>(
    image: &Image,
    summaries: Summaries<'_>,
    mut machine: M,
    start: u64,
    decoded: &[Decoded<M::Instruction>],
    stop: Option<String>,
    extra_targets: &HashSet<u64>,
    carried: &CarriedFlags,
) -> Result<Built, LiftError> {
    let mut exits = HashMap::new();
    // The address of the instruction ending each block that a branch ends.
    let mut ends = HashMap::new();
    // Where the code goes on past each start that left no block.
    let mut passed: HashMap<u64, u64> = HashMap::new();
    if decoded.is_empty() {
        return Err(LiftError::NoInstructions);
    }
    let mut targets: HashSet<u64> = decoded
        .iter()
        .filter_map(|d| machine.branch_target(&d.instruction, d.pc))
        .collect();
    targets.extend(extra_targets);

    let mut blocks = Vec::new();
    let mut block_start = start;
    let mut pending = Vec::new();
    let mut expected = start;
    let entry = |address: u64| carried.entry.get(&address).cloned();
    machine.enter_block(entry(start));
    for d in decoded {
        // A fragment follows the code before it in the list, not in memory:
        // code running off the end goes on at the next address.
        if d.pc != expected {
            pending.extend(machine.take_statements());
            if block_start != expected || !pending.is_empty() {
                pending.push(Stmt::Br {
                    target: Some(expected),
                });
                let stmts = std::mem::take(&mut pending);
                blocks.push(finish_block(
                    &machine,
                    block_start,
                    stmts,
                    carried,
                    &mut exits,
                ));
                machine.block_ended();
            }
            block_start = d.pc;
            machine.enter_block(entry(block_start));
        }
        expected = d.next;
        if d.pc != block_start && targets.contains(&d.pc) {
            pending.extend(machine.take_statements());
            // Instructions without statements, such as padding, leave no
            // block, unless they set flags a later block may read or a
            // jump table lands on them. The branches to them go on to the
            // next block instead.
            if pending.is_empty()
                && !machine.flags_touched()
                && !extra_targets.contains(&block_start)
            {
                passed.insert(block_start, d.pc);
            } else {
                let stmts = std::mem::take(&mut pending);
                blocks.push(finish_block(
                    &machine,
                    block_start,
                    stmts,
                    carried,
                    &mut exits,
                ));
            }
            block_start = d.pc;
            machine.block_split();
            machine.enter_block(entry(block_start));
        }
        if machine.step(&d.instruction, d.pc) {
            pending.extend(machine.take_statements());
            ends.insert(block_start, d.pc);
            let stmts = std::mem::take(&mut pending);
            blocks.push(finish_block(
                &machine,
                block_start,
                stmts,
                carried,
                &mut exits,
            ));
            // A loop's body leaves the flags as they came in.
            for extra in machine.take_extra_blocks() {
                exits.insert(
                    extra.start,
                    Exit {
                        flags: None,
                        touched: false,
                    },
                );
                blocks.push(extra);
            }
            block_start = d.next;
            machine.block_ended();
            machine.enter_block(entry(block_start));
        }
    }
    pending.extend(machine.take_statements());
    if let Some(text) = stop {
        pending.push(Stmt::unsupported(text));
    }
    if !pending.is_empty() {
        blocks.push(Block {
            start: block_start,
            stmts: pending,
        });
    }
    // Code that ends in a call, with nothing after it, never returns from it.
    if let Some(last) = blocks.last_mut()
        && matches!(last.stmts.last(), Some(Stmt::Call { .. }))
    {
        last.stmts.push(Stmt::Trap);
    }
    for stmt in blocks.iter_mut().flat_map(|block| &mut block.stmts) {
        if let Stmt::Br {
            target: Some(target),
        }
        | Stmt::Brif { target, .. }
        | Stmt::BrifFlags { target, .. } = stmt
        {
            while let Some(next) = passed.get(target) {
                *target = *next;
            }
        }
    }
    let pulled = exits::resolve_exits(image, summaries, start, &mut blocks, &ends);
    drop_unread_compare_operands(&mut blocks);
    Ok((blocks, exits, pulled))
}

/// Removes the copies of compare operands no branch went on to read: most
/// instructions set flags that nothing tests.
fn drop_unread_compare_operands(blocks: &mut [Block]) {
    let mut read = HashSet::new();
    for stmt in blocks.iter().flat_map(|block| &block.stmts) {
        read.extend(
            crate::ir::visit::statement_registers(stmt)
                .1
                .into_iter()
                .filter(|register| FLAG_OPERANDS.contains(register)),
        );
    }
    for block in blocks {
        block.stmts.retain(|stmt| {
            !matches!(stmt, Stmt::Assign { dest, .. }
                if FLAG_OPERANDS.contains(&dest.index) && !read.contains(&dest.index))
        });
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::lift;
    use crate::analysis::analyze;
    use crate::ir::eval::{self, hash};
    use crate::ir::visit::expr_width;
    use crate::ir::{Expr, FunctionIr, Stmt};
    use crate::loader::{Function, Image, Isa};

    /// Runs the lifted code with the given registers and returns its result.
    fn returns(isa: Isa, code: Vec<u8>, registers: &[(u16, u64)]) -> u64 {
        returns_with(isa, code, registers, &[])
    }

    fn returns_with(
        isa: Isa,
        code: Vec<u8>,
        registers: &[(u16, u64)],
        memory: &[(u64, u64)],
    ) -> u64 {
        let len = code.len() as u64;
        let image = Image::from_code(isa, 0, code);
        let mut ir = FunctionIr::single_block(isa, Vec::new());
        ir.blocks = lift(&image, 0, len, &HashSet::new()).expect("lifts");
        let setup = eval::Setup {
            seed: 0,
            convention: eval::Convention {
                arguments: &[],
                clobbered: &[],
            },
            registers,
            memory,
            step_limit: 100,
        };
        match eval::run(&ir, &setup) {
            eval::Outcome::Return { value, .. } => value,
            other => panic!("{other:?}\n{}", ir.render()),
        }
    }

    fn words(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    #[test]
    fn a_branch_tests_the_operands_a_flag_setting_write_replaced() {
        // subs w8, w8, w9; b.gt +12; mov w0, #0; ret; mov w0, #1; ret
        let code = words(&[
            0x6b090108, 0x5400006c, 0x52800000, 0xd65f03c0, 0x52800020, 0xd65f03c0,
        ]);
        assert_eq!(returns(Isa::AArch64, code, &[(8, 5), (9, 3)]), 1);
        // dec ecx; jne +6; mov eax, 0; ret; mov eax, 1; ret
        let code = vec![
            0xff, 0xc9, 0x75, 0x06, 0xb8, 0, 0, 0, 0, 0xc3, 0xb8, 1, 0, 0, 0, 0xc3,
        ];
        assert_eq!(returns(Isa::X86_64, code, &[(1, 1)]), 0);
    }

    #[test]
    fn flags_carry_into_a_block_every_path_reaches_with_them() {
        // cmp edi, esi; jne +5; mov eax, 5; setl al; movzx eax, al; ret
        let x86 = vec![
            0x39, 0xf7, 0x75, 0x05, 0xb8, 5, 0, 0, 0, 0x0f, 0x9c, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3,
        ];
        // cmp w0, w1; b.ne +8; mov w2, #1; cset w0, lt; ret
        let a64 = words(&[
            0x6b01_001f,
            0x5400_0041,
            0x5280_0022,
            0x1a9f_a7e0,
            0xd65f_03c0,
        ]);
        for (a, b) in [(1u64, 2u64), (2, 1), (0xffff_ffff, 1), (3, 3)] {
            let less = u64::from((a as u32 as i32) < (b as u32 as i32));
            assert_eq!(returns(Isa::X86_64, x86.clone(), &[(7, a), (6, b)]), less);
            assert_eq!(returns(Isa::AArch64, a64.clone(), &[(0, a), (1, b)]), less);
        }
    }

    /// The bytes a run of `code` leaves in memory.
    fn memory_after(
        code: Vec<u8>,
        registers: &[(u16, u64)],
        memory: &[(u64, u64)],
    ) -> std::collections::BTreeMap<u64, u8> {
        let len = code.len() as u64;
        let image = Image::from_code(Isa::X86_64, 0, code);
        let mut ir = FunctionIr::single_block(Isa::X86_64, Vec::new());
        ir.blocks = lift(&image, 0, len, &HashSet::new()).expect("lifts");
        let setup = eval::Setup {
            seed: 0,
            convention: eval::Convention {
                arguments: &[],
                clobbered: &[],
            },
            registers,
            memory,
            step_limit: 1000,
        };
        match eval::run(&ir, &setup) {
            eval::Outcome::Return { memory, .. } => memory,
            other => panic!("{other:?}\n{}", ir.render()),
        }
    }

    #[test]
    fn a_repeated_string_move_copies_as_many_elements_as_the_count() {
        let source = [(0x1000, 0x0807_0605_0403_0201)];
        // rep movsb; ret
        let moved = memory_after(
            vec![0xf3, 0xa4, 0xc3],
            &[(6, 0x1000), (7, 0x2000), (1, 3)],
            &source,
        );
        let copied: Vec<u8> = (0x2000..0x2004)
            .filter_map(|addr| moved.get(&addr).copied())
            .collect();
        assert_eq!(copied, vec![1, 2, 3]);
        let none = memory_after(
            vec![0xf3, 0xa4, 0xc3],
            &[(6, 0x1000), (7, 0x2000), (1, 0)],
            &source,
        );
        assert!(!none.keys().any(|addr| (0x2000..0x2010).contains(addr)));
        // rep stosq; ret: two quadwords of rax.
        let stored = memory_after(
            vec![0xf3, 0x48, 0xab, 0xc3],
            &[(0, 0x1122_3344_5566_7788), (7, 0x3000), (1, 2)],
            &[],
        );
        assert_eq!(
            stored
                .keys()
                .filter(|addr| (0x3000..0x3018).contains(*addr))
                .count(),
            16
        );
        assert_eq!(stored.get(&0x3008), Some(&0x88));
    }

    #[test]
    fn flags_of_different_kinds_do_not_carry_into_a_join() {
        // test edi, edi; je +2; cmp edi, esi; setl al; ret
        let code = vec![0x85, 0xff, 0x74, 0x02, 0x39, 0xf7, 0x0f, 0x9c, 0xc0, 0xc3];
        let len = code.len() as u64;
        let image = Image::from_code(Isa::X86_64, 0, code);
        let blocks = lift(&image, 0, len, &HashSet::new()).expect("lifts");
        assert!(
            blocks
                .iter()
                .flat_map(|block| &block.stmts)
                .any(|stmt| matches!(stmt, Stmt::Unsupported { .. })),
            "{blocks:?}"
        );
    }

    #[test]
    fn flags_of_tst_and_cmn_test_the_result() {
        // tst w0, w1; b.eq +12; mov w0, #0; ret; mov w0, #1; ret
        let tst = words(&[
            0x6a01_001f,
            0x5400_0060,
            0x5280_0000,
            0xd65f_03c0,
            0x5280_0020,
            0xd65f_03c0,
        ]);
        // 6 & 9 is zero although 6 != 9.
        assert_eq!(returns(Isa::AArch64, tst, &[(0, 6), (1, 9)]), 1);
        // cmn w0, #8; b.le +12; ...: -8 + 8 <= 0.
        let cmn = words(&[
            0x3100_201f,
            0x5400_006d,
            0x5280_0000,
            0xd65f_03c0,
            0x5280_0020,
            0xd65f_03c0,
        ]);
        assert_eq!(returns(Isa::AArch64, cmn, &[(0, 0xffff_fff8)]), 1);
    }

    #[test]
    fn an_unsigned_test_after_sub_compares_the_operands() {
        // sub edi, 9; ja +6; mov eax, 0; ret; mov eax, 1; ret
        let code = vec![
            0x83, 0xef, 0x09, 0x77, 0x06, 0xb8, 0, 0, 0, 0, 0xc3, 0xb8, 1, 0, 0, 0, 0xc3,
        ];
        // 5 - 9 is nonzero, but 5 is not above 9.
        assert_eq!(returns(Isa::X86_64, code, &[(7, 5)]), 0);
    }

    #[test]
    fn a_call_through_a_register_keeps_its_target() {
        // call rax; ret
        let image = Image::from_code(Isa::X86_64, 0, vec![0xff, 0xd0, 0xc3]);
        let blocks = lift(&image, 0, 3, &HashSet::new()).expect("lifts");
        assert!(
            matches!(
                blocks[0].stmts.first(),
                Some(Stmt::Call {
                    target: None,
                    through: Some(Expr::Reg { index: 0, .. }),
                    ..
                })
            ),
            "{blocks:?}"
        );
    }

    #[test]
    fn bitfield_moves_extract_and_insert() {
        let ret = 0xd65f_03c0;
        // ubfx w0, w1, #4, #4
        let ubfx = words(&[0x5304_1c20, ret]);
        assert_eq!(returns(Isa::AArch64, ubfx, &[(1, 0xab)]), 0xa);
        // sxtw x0, w1
        let sxtw = words(&[0x9340_7c20, ret]);
        assert_eq!(returns(Isa::AArch64, sxtw, &[(1, 0xffff_ffff)]), u64::MAX);
        // ubfiz w0, w1, #1, #3
        let ubfiz = words(&[0x531f_0820, ret]);
        assert_eq!(returns(Isa::AArch64, ubfiz, &[(1, 0xff)]), 0xe);
    }

    #[test]
    fn integer_division_and_unscaled_loads_lift() {
        // sdiv w0, w0, w1; ret: -7 / 2 is -3.
        let sdiv = words(&[0x1ac1_0c00, 0xd65f_03c0]);
        let quotient = returns(Isa::AArch64, sdiv, &[(0, (-7i32) as u32 as u64), (1, 2)]);
        assert_eq!(quotient as u32, (-3i32) as u32);
        // ldur w0, [x1, #-4]; ret
        let ldur = words(&[0xb85f_c020, 0xd65f_03c0]);
        assert_eq!(
            returns_with(Isa::AArch64, ldur, &[(1, 0x1004)], &[(0x1000, 0x2a)]),
            0x2a
        );
        // mov eax, edi; xor edx, edx; div esi; ret
        let div = vec![0x89, 0xf8, 0x31, 0xd2, 0xf7, 0xf6, 0xc3];
        assert_eq!(returns(Isa::X86_64, div, &[(7, 7), (6, 2)]), 3);
    }

    #[test]
    fn moves_after_one_compare_all_test_it() {
        // mov ecx, 9; cmp edi, esi; cmovl eax, ecx; cmovl eax, edx; ret
        let code = vec![
            0xb9, 0x09, 0x00, 0x00, 0x00, 0x39, 0xf7, 0x0f, 0x4c, 0xc1, 0x0f, 0x4c, 0xc2, 0xc3,
        ];
        assert_eq!(returns(Isa::X86_64, code, &[(7, 1), (6, 2), (2, 4)]), 4);
    }

    #[test]
    fn vector_moves_copy_both_halves() {
        // movups xmm0, [rdi]; movups [rsi], xmm0; mov rax, [rsi + 8]; ret
        let code = vec![
            0x0f, 0x10, 0x07, 0x0f, 0x11, 0x06, 0x48, 0x8b, 0x46, 0x08, 0xc3,
        ];
        let registers = [(7, 0x100), (6, 0x200)];
        assert_eq!(
            returns_with(Isa::X86_64, code, &registers, &[(0x108, 0x55)]),
            0x55
        );
        // xorps xmm0, xmm0; movq rax, xmm0; ret
        let code = vec![0x0f, 0x57, 0xc0, 0x66, 0x48, 0x0f, 0x7e, 0xc0, 0xc3];
        assert_eq!(returns(Isa::X86_64, code, &[(18, 5)]), 0);
    }

    #[test]
    fn rotations_and_byte_reversals_lift() {
        let x = 0x1122_3344_5566_7788;
        // mov rax, rdi; rol rax, 8; ret
        let rol = vec![0x48, 0x89, 0xf8, 0x48, 0xc1, 0xc0, 0x08, 0xc3];
        assert_eq!(returns(Isa::X86_64, rol, &[(7, x)]), 0x2233_4455_6677_8811);
        // mov eax, edi; ror eax, cl; ret
        let ror = vec![0x89, 0xf8, 0xd3, 0xc8, 0xc3];
        let rotated = |count| returns(Isa::X86_64, ror.clone(), &[(7, 0x1234_5678), (1, count)]);
        assert_eq!(rotated(4), 0x8123_4567);
        assert_eq!(rotated(0), 0x1234_5678);
        // mov rax, rdi; bswap rax; ret
        let bswap = vec![0x48, 0x89, 0xf8, 0x48, 0x0f, 0xc8, 0xc3];
        assert_eq!(
            returns(Isa::X86_64, bswap, &[(7, x)]),
            0x8877_6655_4433_2211
        );
        // mov rax, rdi; shrd rax, rsi, 8; ret
        let shrd = vec![0x48, 0x89, 0xf8, 0x48, 0x0f, 0xac, 0xf0, 0x08, 0xc3];
        assert_eq!(
            returns(Isa::X86_64, shrd, &[(7, x), (6, 0xaabb)]),
            0xbb11_2233_4455_6677
        );
        let ret = 0xd65f_03c0;
        let a64 = |word: u32, registers: &[(u16, u64)]| {
            returns(Isa::AArch64, words(&[word, ret]), registers)
        };
        // ror x0, x1, #8
        assert_eq!(a64(0x93c1_2020, &[(1, x)]), 0x8811_2233_4455_6677);
        // orr x0, xzr, x1, ror #8
        assert_eq!(a64(0xaac1_23e0, &[(1, x)]), 0x8811_2233_4455_6677);
        // rorv w0, w1, w2
        assert_eq!(a64(0x1ac2_2c20, &[(1, 0x1234_5678), (2, 36)]), 0x8123_4567);
        // rev x0, x1; rev16 w0, w1
        assert_eq!(a64(0xdac0_0c20, &[(1, x)]), 0x8877_6655_4433_2211);
        assert_eq!(a64(0x5ac0_0420, &[(1, 0x1122_3344)]), 0x2211_4433);
        // orn x0, x1, x2
        assert_eq!(a64(0xaa22_0020, &[(1, 0xf0), (2, !0x0f)]), 0xff);
    }

    #[test]
    fn exchanges_return_the_old_value() {
        // mov eax, 5; xchg rax, rdi; ret
        let xchg = vec![0xb8, 0x05, 0x00, 0x00, 0x00, 0x48, 0x97, 0xc3];
        assert_eq!(returns(Isa::X86_64, xchg, &[(7, 9)]), 9);
        // mov eax, 3; lock xadd [rdi], rax; ret
        let xadd = vec![
            0xb8, 0x03, 0x00, 0x00, 0x00, 0xf0, 0x48, 0x0f, 0xc1, 0x07, 0xc3,
        ];
        assert_eq!(
            returns_with(Isa::X86_64, xadd, &[(7, 0x100)], &[(0x100, 10)]),
            10
        );
        // mov eax, 10; lock cmpxchg [rdi], rsi; ret: a mismatch loads rax.
        let cmpxchg = vec![
            0xb8, 0x0a, 0x00, 0x00, 0x00, 0xf0, 0x48, 0x0f, 0xb1, 0x37, 0xc3,
        ];
        let registers = [(7, 0x100), (6, 42)];
        assert_eq!(
            returns_with(Isa::X86_64, cmpxchg, &registers, &[(0x100, 7)]),
            7
        );
        // The same, then mov rax, [rdi]: a match stores rsi.
        let stored = vec![
            0xb8, 0x0a, 0x00, 0x00, 0x00, 0xf0, 0x48, 0x0f, 0xb1, 0x37, 0x48, 0x8b, 0x07, 0xc3,
        ];
        assert_eq!(
            returns_with(Isa::X86_64, stored, &registers, &[(0x100, 10)]),
            42
        );
        // xor eax, eax; bt rdi, 3; setb al; ret
        let bt = vec![
            0x31, 0xc0, 0x48, 0x0f, 0xba, 0xe7, 0x03, 0x0f, 0x92, 0xc0, 0xc3,
        ];
        assert_eq!(returns(Isa::X86_64, bt.clone(), &[(7, 8)]), 1);
        assert_eq!(returns(Isa::X86_64, bt, &[(7, 7)]), 0);
    }

    #[test]
    fn a_division_by_rdx_divides_by_its_value_before_the_remainder() {
        // mov eax, edi; cdq; idiv edx; ret: -5 / -1
        let code = vec![0x89, 0xf8, 0x99, 0xf7, 0xfa, 0xc3];
        assert_eq!(returns(Isa::X86_64, code, &[(7, (-5i64) as u64)]), 5);
    }

    #[test]
    fn pop_reads_the_slot_push_wrote() {
        // push rbx; pop rax; ret
        assert_eq!(returns(Isa::X86_64, vec![0x53, 0x58, 0xc3], &[(3, 7)]), 7);
    }

    #[test]
    fn a_branch_target_after_padding_starts_a_block() {
        // jmp 3; nop; ret
        let image = Image::from_code(Isa::X86_64, 0, vec![0xeb, 0x01, 0x90, 0xc3]);
        let blocks = lift(&image, 0, 4, &HashSet::new()).expect("lifts");
        assert!(blocks.iter().any(|block| block.start == 3), "{:?}", blocks);
    }

    #[test]
    fn a_store_of_the_zero_register_is_kept() {
        // str wzr, [sp, #8]; ret
        let code = words(&[0xb9000bff, 0xd65f03c0]);
        let image = Image::from_code(Isa::AArch64, 0, code);
        let blocks = lift(&image, 0, 8, &HashSet::new()).expect("lifts");
        assert!(
            matches!(
                blocks[0].stmts.first(),
                Some(Stmt::Store {
                    value: Expr::Const(0),
                    width: 4,
                    ..
                })
            ),
            "{:?}",
            blocks[0]
        );
    }

    #[test]
    fn a_cbnz_target_starts_a_block() {
        // mov x8, xzr; loop: ldrb w9, [x0, x8]; add x8, x8, #1; cbnz w9, loop; ret
        let code = words(&[0xaa1f03e8, 0x38686809, 0x91000508, 0x35ffffc9, 0xd65f03c0]);
        let image = Image::from_code(Isa::AArch64, 0, code);
        let blocks = lift(&image, 0, 20, &HashSet::new()).expect("lifts");
        assert!(blocks.iter().any(|block| block.start == 4), "{blocks:?}");
    }

    #[test]
    fn cbz_on_a_w_register_tests_the_low_half() {
        // cbz w0, #8; ret; ret
        let code = words(&[0x34000040, 0xd65f03c0, 0xd65f03c0]);
        let image = Image::from_code(Isa::AArch64, 0, code);
        let blocks = lift(&image, 0, 12, &HashSet::new()).expect("lifts");
        let Some(Stmt::Brif { lhs, .. }) = blocks[0].stmts.last() else {
            panic!("a conditional branch: {:?}", blocks[0]);
        };
        assert_eq!(expr_width(lhs), Some(32), "{lhs:?}");
    }

    /// Random bytes may decode to anything; analysis and rendering must still finish.
    #[test]
    fn random_code_never_panics() {
        for isa in [Isa::AArch64, Isa::X86_64] {
            for seed in 0..300u64 {
                let len = 4 + (hash(seed, 0) % 508) as usize;
                let code: Vec<u8> = (0..len as u64)
                    .map(|offset| hash(seed, offset + 1) as u8)
                    .collect();
                let function = Function {
                    addr: 0,
                    size: Some(len as u64),
                    size_estimated: false,
                    name: None,
                    aliases: Vec::new(),
                    sources: Vec::new(),
                };
                let image = Image::from_code(isa, 0, code);
                if let Ok(analysis) = analyze(&image, &function) {
                    crate::render::render(
                        &analysis.ir,
                        &analysis.references,
                        &crate::render::Symbols::default(),
                        &[],
                    );
                }
            }
        }
    }
    #[test]
    fn shared_lifts_use_the_normalized_extra_target_set() {
        let image = Image::from_code(Isa::X86_64, 0, vec![0x89, 0xf8, 0x01, 0xf0, 0xc3]);
        let summaries = |_| crate::loader::Summary::default();
        let plain = super::lift_shared(&image, 0, 5, &summaries).expect("plain lift");
        let empty = super::lift_shared_with_targets(&image, 0, 5, &HashSet::new(), &summaries)
            .expect("empty targets");
        assert!(std::sync::Arc::ptr_eq(&plain, &empty));
        let first =
            super::lift_shared_with_targets(&image, 0, 5, &HashSet::from([2, 4]), &summaries)
                .expect("first targets");
        let reordered =
            super::lift_shared_with_targets(&image, 0, 5, &HashSet::from([4, 2]), &summaries)
                .expect("reordered targets");
        let different =
            super::lift_shared_with_targets(&image, 0, 5, &HashSet::from([4]), &summaries)
                .expect("different targets");
        assert!(std::sync::Arc::ptr_eq(&first, &reordered));
        assert!(!std::sync::Arc::ptr_eq(&plain, &first));
        assert!(!std::sync::Arc::ptr_eq(&first, &different));
        assert!(first.iter().any(|block| block.start == 2));
        assert!(!different.iter().any(|block| block.start == 2));
        let again = super::lift_shared(&image, 0, 5, &summaries).expect("plain cached lift");
        assert!(std::sync::Arc::ptr_eq(&plain, &again));
    }

    #[test]
    fn shared_target_lifts_recheck_callees_outside_the_cache_lock() {
        let image = Image::from_code(Isa::X86_64, 0, vec![0xe8, 0x1b, 0, 0, 0, 0xc3]);
        let summaries = |_| {
            let _lock = image
                .lifts
                .0
                .try_lock()
                .expect("summary requested outside cache lock");
            crate::loader::Summary::default()
        };
        let targets = HashSet::from([5]);
        let first = super::lift_shared_with_targets(&image, 0, 6, &targets, &summaries)
            .expect("returning callee");
        let changed =
            super::lift_shared_with_targets(&image, 0, 6, &targets, &|_| crate::loader::Summary {
                noreturn: true,
                ..Default::default()
            })
            .expect("changed callee");
        assert!(!std::sync::Arc::ptr_eq(&first, &changed));
        assert!(
            changed
                .iter()
                .flat_map(|block| &block.stmts)
                .any(|stmt| matches!(stmt, Stmt::Trap))
        );
        let again = super::lift_shared_with_targets(&image, 0, 6, &targets, &summaries)
            .expect("retained previous version");
        assert!(std::sync::Arc::ptr_eq(&first, &again));
    }
}

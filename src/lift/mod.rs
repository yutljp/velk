mod aarch64;
mod arm32;
pub(crate) use arm32::fold_literals;
pub(crate) use arm32::listing as arm32_listing;
pub(crate) use arm32::position_independent_instruction as arm32_position_independent_instruction;
#[cfg(test)]
mod atomic_tests;
pub(crate) mod execution;
mod exits;
mod flags;
#[cfg(test)]
mod hardware;
pub(crate) mod pairs32;
mod stack_results;
mod windows;
mod x86_64;

pub(crate) use exits::stack_heights;
pub(crate) use stack_results::stack_results;
use stack_results::take_stack_results;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::error::LiftError;
use crate::ir::visit::{children, expr_reads};
use crate::ir::{Block, CallKind, Convention, Expr, FLAG_OPERANDS, RegRef, Stmt};
use crate::loader::{Image, Isa, Summary};

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
    zero_exporters: HashSet<u64>,
}

const ZERO_CARRIED: u16 = crate::ir::TEMP_BASE + 0x4c;

fn zero_carried(isa: Isa) -> u16 {
    if isa == Isa::Arm32 {
        crate::ir::TEMP_BASE + 0x54
    } else {
        ZERO_CARRIED
    }
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
#[expect(
    clippy::rc_buffer,
    reason = "Shared blocks retain Vec ownership so an unshared lift can be taken without cloning its blocks."
)]
struct Recorded {
    answers: Vec<(u64, Summary)>,
    without_summaries: bool,
    blocks: Result<Arc<Vec<Block>>, LiftError>,
}

/// Retain a lift without callee summaries alongside recent summarized lifts.
const KEPT_LIFTS: usize = 3;

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

#[expect(
    clippy::rc_buffer,
    reason = "Shared blocks retain Vec ownership so an unshared lift can be taken without cloning its blocks."
)]
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
    let unknown = calling(Summary::default());
    let without_summaries = answers.iter().all(|(_, answer)| *answer == unknown);
    let mut lifts = image.lifts.0.lock().expect("lifts lock");
    let kept = lifts.entry(key).or_default();
    if let Some(recorded) = kept.iter().find(|recorded| recorded.answers == answers) {
        return recorded.blocks.clone();
    }
    if kept.len() == KEPT_LIFTS {
        let oldest = kept
            .iter()
            .position(|recorded| recorded.without_summaries == without_summaries)
            .unwrap_or(0);
        kept.remove(oldest);
    }
    kept.push(Arc::new(Recorded {
        answers,
        without_summaries,
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
    let lifted = lift_unpaired(image, addr, size, extra_targets, summaries);
    lifted.map(|mut blocks| {
        if matches!(image.isa, Isa::I386 | Isa::Arm32) {
            for block in &mut blocks {
                let mut statements = Vec::new();
                for mut stmt in std::mem::take(&mut block.stmts) {
                    let target = match &stmt {
                        Stmt::Call { target, .. } => *target,
                        _ => None,
                    };
                    let pair = pairs32::call(image, target, &mut stmt);
                    let word_remainder = pairs32::word_remainder(image, target, &mut stmt);
                    let remainder = if (pair || word_remainder) && image.isa == Isa::Arm32 {
                        pairs32::remainder_arguments(image, target, &mut stmt)
                    } else {
                        None
                    };
                    let has_remainder = remainder.is_some();
                    if let Some(captures) = remainder {
                        statements.extend(captures);
                    }
                    statements.push(stmt);
                    if has_remainder {
                        statements.push(pairs32::remainder_value());
                    }
                    if pair {
                        statements.extend(pairs32::split_result(image.isa));
                    }
                    if word_remainder {
                        statements.extend(pairs32::split_word_result());
                    } else if has_remainder {
                        statements.extend(pairs32::split_remainder());
                    }
                }
                block.stmts = statements;
            }
        }
        drop_stack_probes(&mut blocks, image);
        blocks
    })
}

pub(crate) fn lift_for_execution(
    image: &Image,
    addr: u64,
    size: u64,
    targets: &HashSet<u64>,
) -> Result<Vec<Block>, LiftError> {
    lift_in_mode(
        image,
        addr,
        size,
        targets,
        &|_| Summary::default(),
        execution::Mode::Execution,
    )
}

pub(super) fn lift_unpaired(
    image: &Image,
    addr: u64,
    size: u64,
    extra_targets: &HashSet<u64>,
    summaries: Summaries<'_>,
) -> Result<Vec<Block>, LiftError> {
    lift_in_mode(
        image,
        addr,
        size,
        extra_targets,
        summaries,
        execution::Mode::Analysis,
    )
}

fn lift_in_mode(
    image: &Image,
    addr: u64,
    size: u64,
    extra_targets: &HashSet<u64>,
    summaries: Summaries<'_>,
    mode: execution::Mode,
) -> Result<Vec<Block>, LiftError> {
    let summaries: Summaries<'_> = &|target| calling(summaries(target));
    let addr = image.code_address(addr);
    let Some(bytes) = image.read_vaddr(addr, size) else {
        return Err(LiftError::Unreadable);
    };
    match image.isa {
        Isa::Arm32 => match mode {
            execution::Mode::Analysis => arm32::lift(image, addr, bytes, extra_targets, summaries),
            execution::Mode::Execution => {
                arm32::lift_in_mode(image, addr, bytes, extra_targets, summaries, mode)
            }
        },
        Isa::AArch64 => {
            let mut blocks = match lift_continuing(
                image,
                summaries,
                || execution::Located::new(aarch64::Lifter::new(image, summaries), mode),
                addr,
                bytes,
                &aarch64::decode,
                extra_targets,
            ) {
                Ok(blocks) => blocks,
                Err(error) => return Err(error),
            };
            if mode == execution::Mode::Analysis {
                aarch64::recover_atomic_loops(image, summaries, &mut blocks);
            }
            Ok(blocks)
        }
        Isa::I386 | Isa::X86_64 => {
            let mut blocks = match lift_continuing(
                image,
                summaries,
                || execution::Located::new(x86_64::Lifter::new(image, summaries), mode),
                addr,
                bytes,
                &if image.isa == Isa::I386 {
                    x86_64::decode32
                } else {
                    x86_64::decode
                },
                extra_targets,
            ) {
                Ok(result) => result,
                Err(error) => return Err(error),
            };
            if mode == execution::Mode::Execution {
                return Ok(blocks);
            }
            let direction = blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
                matches!(stmt, Stmt::Assign { dest, value } if dest.index == x86_64::DIRECTION && *value != Expr::constant(0))
            });
            if !direction {
                for stmt in blocks.iter_mut().flat_map(|block| &mut block.stmts) {
                    crate::ir::visit::replace_reads(
                        stmt,
                        &[(x86_64::DIRECTION, Expr::constant(0))],
                    );
                }
                for block in &mut blocks {
                    block.stmts.retain(|stmt| {
                        !matches!(stmt, Stmt::Assign { dest, .. } if dest.index == x86_64::DIRECTION)
                    });
                }
            }
            if direction && let Some(entry) = blocks.first_mut() {
                entry.stmts.insert(
                    0,
                    Stmt::Assign {
                        dest: RegRef {
                            index: x86_64::DIRECTION,
                            width: 64,
                        },
                        value: Expr::constant(0),
                    },
                );
            }
            if image.go {
                take_stack_results(&mut blocks, image, summaries);
            }
            Ok(blocks)
        }
        Isa::Unsupported => Err(LiftError::UnsupportedIsa),
    }
}

/// Drops the calls to the stack probe compilers place before they grow a
/// frame by a page or more. The probe touches each page the frame will
/// cover and keeps the registers the code around it uses, the arguments
/// included, which a call would leave unknown.
fn drop_stack_probes(blocks: &mut [Block], image: &Image) {
    if !matches!(
        image.format,
        crate::loader::Format::MachO | crate::loader::Format::Pe
    ) {
        return;
    }
    let sp = crate::arch::stack_pointer(image.isa);
    for block in blocks {
        // The import slot each register was loaded from in this block, and
        // the constant addresses the code computes on the way there.
        let mut slots: HashMap<u16, u64> = HashMap::new();
        let mut addresses: HashMap<u16, u64> = HashMap::new();
        let mut probes = Vec::new();
        for (position, stmt) in block.stmts.iter().enumerate() {
            let name = match stmt {
                Stmt::Call {
                    through: Some(Expr::Reg { index, width: 64 }),
                    ..
                } => slots
                    .get(index)
                    .filter(|slot| {
                        image
                            .import_addends
                            .get(slot)
                            .is_none_or(|addend| *addend == 0)
                    })
                    .and_then(|slot| image.imports.get(slot))
                    .map(String::as_str),
                Stmt::Call {
                    through: Some(through),
                    ..
                } => import_name(image, through),
                Stmt::Call {
                    target: Some(target),
                    through: None,
                    ..
                } => image
                    .functions
                    .get(target)
                    .filter(|function| function.sources.contains(&crate::loader::NameSource::Plt))
                    .and_then(|function| function.name.as_deref()),
                _ => None,
            };
            let probe = match image.format {
                crate::loader::Format::MachO => match image.isa {
                    Isa::X86_64 => name == Some("____chkstk_darwin"),
                    Isa::AArch64 => name == Some("___chkstk_darwin"),
                    Isa::Arm32 | Isa::I386 | Isa::Unsupported => false,
                },
                crate::loader::Format::Pe if image.isa == crate::loader::Isa::X86_64 => {
                    name == Some("__chkstk")
                }
                _ => false,
            };
            if probe {
                probes.push(position);
            }
            let mut slot = None;
            let mut address = None;
            if let Stmt::Assign { dest, value } = stmt
                && dest.width == 64
            {
                match value {
                    Expr::Load { addr, width: 8, .. } => {
                        slot = known_address(addr, &addresses)
                            .filter(|slot| image.imports.contains_key(slot))
                            .map(|slot| (dest.index, slot));
                    }
                    value => {
                        address = known_address(value, &addresses).map(|value| (dest.index, value));
                    }
                }
            }
            for register in crate::ir::visit::statement_registers(stmt).0 {
                slots.remove(&register);
                addresses.remove(&register);
            }
            if let Some((register, slot)) = slot {
                slots.insert(register, slot);
            }
            if let Some((register, value)) = address {
                addresses.insert(register, value);
            }
        }
        let mut dropped = Vec::new();
        for position in probes {
            dropped.push(position);
            // AArch64 code saves the link register on the stack around the
            // call; the save would read as a store into the frame.
            if image.isa == Isa::AArch64
                && let Some(restore) = link_restore(&block.stmts, position, sp)
                && let Some(save) = link_save(&block.stmts, position, sp)
            {
                dropped.push(restore);
                dropped.push(save);
            }
        }
        dropped.sort_unstable();
        dropped.dedup();
        for position in dropped.into_iter().rev() {
            if image.format == crate::loader::Format::Pe {
                // The Windows helper may clobber these scratch registers.
                block.stmts.splice(
                    position..=position,
                    [10, 11].map(|index| Stmt::Assign {
                        dest: crate::ir::RegRef { index, width: 64 },
                        value: Expr::apply(crate::ir::Operation::Undefined, Vec::new()),
                    }),
                );
            } else {
                block.stmts.remove(position);
            }
        }
    }
}

const LINK_REGISTER: u16 = 30;

/// The statement right after the call at `call` that loads the link
/// register back from the top of the stack.
fn link_restore(stmts: &[Stmt], call: usize, sp: u16) -> Option<usize> {
    let position = call.checked_add(1)?;
    match stmts.get(position)? {
        Stmt::Assign {
            dest,
            value: Expr::Load { addr, width: 8, .. },
        } if dest.index == LINK_REGISTER
            && matches!(addr.as_ref(), Expr::Reg { index, width: 64 } if *index == sp) =>
        {
            Some(position)
        }
        _ => None,
    }
}

/// The last store of the link register before the call at `call`, when it
/// stores to the stack.
fn link_save(stmts: &[Stmt], call: usize, sp: u16) -> Option<usize> {
    let position = stmts[..call].iter().rposition(|stmt| {
        matches!(stmt, Stmt::Store { value: Expr::Reg { index, width: 64 }, width: 8, .. }
            if *index == LINK_REGISTER)
    })?;
    let Stmt::Store { addr, .. } = &stmts[position] else {
        return None;
    };
    let from_sp = match addr {
        Expr::Reg { index, width: 64 } => *index == sp,
        Expr::Bin { lhs, rhs, .. } => {
            matches!(lhs.as_ref(), Expr::Reg { index, width: 64 } if *index == sp)
                && matches!(rhs.as_ref(), Expr::Const(_))
        }
        _ => false,
    };
    from_sp.then_some(position)
}

/// The constant an address expression of constants, additions and
/// registers holding known constants computes.
fn known_address(expr: &Expr, addresses: &HashMap<u16, u64>) -> Option<u64> {
    match expr {
        Expr::Const(value) => Some(*value),
        Expr::Reg { index, width: 64 } => addresses.get(index).copied(),
        Expr::Bin {
            op: crate::ir::BinOp::Add,
            lhs,
            rhs,
        } => match (known_address(lhs, addresses), known_address(rhs, addresses)) {
            (Some(lhs), Some(rhs)) => Some(lhs.wrapping_add(rhs)),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod smt_tests;

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

type Decoder<'a, I> = &'a dyn Fn(&[u8], u64) -> (Vec<Decoded<I>>, Option<String>);

/// The function's blocks, lifted again with the code its branches out
/// continue in, which is no tail call, until no more such code turns up.
fn lift_continuing<M: Machine>(
    image: &Image,
    summaries: Summaries<'_>,
    machine: impl Fn() -> M,
    addr: u64,
    bytes: &[u8],
    decode: Decoder<'_, M::Instruction>,
    extra_targets: &HashSet<u64>,
) -> Result<Vec<Block>, LiftError> {
    let mut pulled = exits::Pulled::new();
    let mut rounds = 0;
    loop {
        rounds += 1;
        let (decoded, stop) =
            decode_with_fragments(image, &machine(), addr, bytes, decode, &pulled);
        let (blocks, more) = match build_carrying(
            image,
            summaries,
            &machine,
            addr,
            &decoded,
            stop,
            extra_targets,
        ) {
            Ok(result) => result,
            Err(error) => return Err(error),
        };
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
    decode: Decoder<'_, M::Instruction>,
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

/// The arguments of a call reading `count` registers and `stack` slots
/// past them, as they stand at the call.
pub(crate) fn arguments(
    kind: CallKind,
    convention: Convention,
    isa: crate::loader::Isa,
    count: Option<usize>,
    stack: usize,
) -> Option<Vec<Expr>> {
    let Some(count) = count else {
        return None;
    };
    if kind.push_bytes(isa, convention).is_none() {
        return None;
    }
    let word = i64::from(crate::arch::pointer_bytes(isa));
    let stack = if isa == Isa::I386 {
        stack.max(count.saturating_sub(convention.arguments().len()))
    } else {
        stack
    };
    let mut args: Vec<Expr> = convention.arguments()[..count.min(convention.arguments().len())]
        .iter()
        .map(|register| Expr::reg(*register, crate::arch::pointer_bytes(isa) * 8))
        .collect();
    if let Some(start) = convention.stack_arguments() {
        let sp = crate::arch::stack_pointer(isa);
        for slot in 0..stack {
            // The slot the callee reads, as it lies from the stack pointer
            // at the call or jump.
            let Some(offset) = i64::try_from(slot)
                .ok()
                .and_then(|slot| slot.checked_mul(word))
                .and_then(|slot| start.checked_add(slot))
                .and_then(|callee| kind.stack_offset(isa, convention, callee))
            else {
                return None;
            };
            args.push(Expr::Load {
                addr: Box::new(Expr::bin(
                    crate::ir::BinOp::Add,
                    Expr::reg(sp, 64),
                    Expr::Const(offset as u64),
                )),
                width: word as u8,
                signed: false,
            });
        }
    }
    Some(args)
}

/// A call to `target`. A variadic library function's arguments are left to
/// the analysis, which counts them from its format string.
pub(crate) fn call(
    kind: CallKind,
    image: &Image,
    summaries: Summaries<'_>,
    target: Option<u64>,
) -> Stmt {
    let name = target
        .and_then(|target| image.functions.get(&target))
        .and_then(|function| function.name.as_deref());
    if image.go && name.is_some_and(|name| name.starts_with("runtime.gcWriteBarrier")) {
        return Stmt::Call {
            kind,
            target,
            through: None,
            convention: Convention::GoWriteBarrier,
            args: Some(Vec::new()),
            floats_named: false,
            abi: None,
            clobbers: None,
            outputs: crate::ir::fallback_call_outputs(Convention::GoWriteBarrier, None),
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
            .and_then(|name| crate::analysis::prototypes::for_image(name, image))
            .is_some_and(|prototype| prototype.format.is_some())
    });
    let summary = target.filter(|_| !variadic).map(summaries);
    let cleanup_slots = if convention == Convention::Stdcall {
        target
            .and_then(|target| image.callee_cleanup(target))
            .filter(|bytes| bytes.is_multiple_of(4))
            .map(|bytes| usize::from(bytes / 4))
    } else {
        None
    };
    let arity = summary.and_then(|summary| summary.arity).or(cleanup_slots);
    let stack = summary
        .map_or(0, |summary| summary.stack)
        .max(cleanup_slots.unwrap_or(0));
    let mut args = arguments(kind, convention, image.isa, arity, stack);
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
    let floats_named = append_float_arguments(
        &mut args,
        convention,
        summary.and_then(|summary| summary.floats),
    );
    if let (Some(args), Some(inputs)) = (&mut args, summary.and_then(|summary| summary.inputs)) {
        for arg in args {
            if let Expr::Reg { index, .. } = arg
                && convention.arguments().contains(index)
                && !inputs.contains(*index)
            {
                *arg = Expr::constant(0);
            }
        }
    }
    let clobbers = summary.and_then(|summary| summary.clobbers);
    Stmt::Call {
        kind,
        target,
        through: None,
        convention,
        args,
        floats_named,
        abi: None,
        outputs: crate::ir::fallback_call_outputs(convention, clobbers),
        clobbers,
        via: None,
    }
}

/// The function a pointer in data names, for a call or jump through it:
/// `call [slot]`, where the slot holds a known function's address and the
/// program cannot write another there.
pub(crate) fn pointer_target(image: &Image, through: &Expr) -> Option<u64> {
    let Some(slot) = pointer_slot(image, through) else {
        return None;
    };
    let Some(section) = image.section_at(slot) else {
        return None;
    };
    if section.executable || !section.read_only {
        return None;
    }
    let word = crate::arch::pointer_bytes(image.isa);
    let Some(bytes) = image.read_vaddr(slot, u64::from(word)) else {
        return None;
    };
    let target = if word == 4 {
        let Ok(bytes) = bytes.try_into() else {
            return None;
        };
        u64::from(u32::from_le_bytes(bytes))
    } else {
        let Ok(bytes) = bytes.try_into() else {
            return None;
        };
        u64::from_le_bytes(bytes)
    };
    image.functions.contains_key(&target).then_some(target)
}

fn pointer_slot(image: &Image, through: &Expr) -> Option<u64> {
    let Expr::Load { addr, width, .. } = through else {
        return None;
    };
    if *width != crate::arch::pointer_bytes(image.isa) {
        return None;
    }
    let Expr::Const(slot) = addr.as_ref() else {
        return None;
    };
    Some(*slot)
}

/// The name of the import whose slot `through` loads.
pub(crate) fn import_name<'a>(image: &'a Image, through: &Expr) -> Option<&'a str> {
    let Some(slot) = pointer_slot(image, through) else {
        return None;
    };
    if image
        .import_addends
        .get(&slot)
        .is_some_and(|addend| *addend != 0)
    {
        return None;
    }
    image.imports.get(&slot).map(String::as_str)
}

/// The import a call through `through` reaches, when it loads a slot the
/// dynamic linker fills, and what its name says of it.
pub(crate) fn import_called(image: &Image, through: &Expr) -> Option<crate::loader::Summary> {
    import_name(image, through).map(|name| crate::analysis::summary::import(image, name))
}

fn append_float_arguments(
    args: &mut Option<Vec<Expr>>,
    convention: Convention,
    floats: Option<usize>,
) -> bool {
    let (Some(args), Some(floats)) = (args, floats) else {
        return false;
    };
    let registers = convention.float_arguments();
    args.extend(
        registers[..floats.min(registers.len())]
            .iter()
            .map(|register| Expr::reg(*register, 64)),
    );
    true
}

/// A call to the address `through` computes. One through an import's slot
/// passes the arguments its prototype takes.
pub(crate) fn call_through(kind: CallKind, image: &Image, through: Expr) -> Stmt {
    let convention = import_name(image, &through)
        .and_then(|name| crate::analysis::prototypes::i386_import(image, name))
        .map_or_else(
            || Convention::of(image.isa, image.format, image.go),
            |properties| properties.0,
        );
    let variadic = crate::lift::import_name(image, &through)
        .and_then(|name| crate::analysis::prototypes::for_image(name, image))
        .is_some_and(|prototype| {
            prototype.format.is_some() || (kind == CallKind::Tail && prototype.variadic)
        });
    let summary = import_called(image, &through).filter(|_| !variadic);
    let arity = summary.as_ref().and_then(|summary| summary.arity);
    let mut args = arguments(kind, convention, image.isa, arity, 0);
    let floats_named = append_float_arguments(
        &mut args,
        convention,
        summary
            .as_ref()
            .and_then(|summary| summary.floats)
            .filter(|count| *count != 0),
    );
    Stmt::Call {
        kind,
        target: None,
        through: Some(through),
        convention,
        args,
        floats_named,
        abi: None,
        clobbers: None,
        outputs: crate::ir::fallback_call_outputs(convention, None),
        via: None,
    }
}

/// A jump out of the function: the callee's result is this function's,
/// unless the callee never returns.
fn tail_call(image: &Image, summaries: Summaries<'_>, target: Option<u64>) -> [Stmt; 2] {
    if target.is_some_and(|target| summaries(target).noreturn) {
        return [call(CallKind::Tail, image, summaries, target), Stmt::Trap];
    }
    [
        call(CallKind::Tail, image, summaries, target),
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
    let (blocks, exits, pulled) = match build(
        image,
        summaries,
        machine(),
        start,
        decoded,
        stop.clone(),
        extra_targets,
        &none,
    ) {
        Ok(result) => result,
        Err(error) => return Err(error),
    };
    let predecessors = flag_predecessors(&blocks);
    let mut carried = carry_flags(&blocks, &exits, extra_targets, &predecessors);
    carry_zero(
        image.isa,
        &blocks,
        &exits,
        extra_targets,
        &predecessors,
        &mut carried,
    );
    if carried.entry.is_empty() {
        return Ok((blocks, pulled));
    }
    let (blocks, _, pulled) = match build(
        image,
        summaries,
        machine(),
        start,
        decoded,
        stop,
        extra_targets,
        &carried,
    ) {
        Ok(result) => result,
        Err(error) => return Err(error),
    };
    Ok((blocks, pulled))
}

/// Normal predecessors in block and successor order, including repeated edges.
fn flag_predecessors(blocks: &[Block]) -> Vec<Vec<usize>> {
    let mut predecessors = vec![Vec::new(); blocks.len()];
    for index in 0..blocks.len() {
        for next in crate::ir::cfg::block_successors(blocks, index) {
            predecessors[next].push(index);
        }
    }
    predecessors
}

/// Whether a block reads flags its own code did not set: a branch on them,
/// or a select, setcc or carry left unsupported for want of them.
fn reads_unknown_flags(block: &Block) -> bool {
    block.stmts.iter().any(|stmt| match stmt {
        Stmt::BrifFlags { .. }
        | Stmt::Machine {
            instruction: crate::ir::MachineInstruction::ReadFlags,
            ..
        } => true,
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
    predecessors: &[Vec<usize>],
) -> CarriedFlags {
    let mut carried = CarriedFlags::default();
    let count = blocks.len();
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

/// A join may have a known zero flag even when its predecessors set it
/// with different operations or widths.
fn carry_zero(
    isa: Isa,
    blocks: &[Block],
    exits: &HashMap<u64, Exit>,
    extra_targets: &HashSet<u64>,
    predecessors: &[Vec<usize>],
    carried: &mut CarriedFlags,
) {
    if !matches!(isa, Isa::X86_64 | Isa::I386 | Isa::Arm32) {
        return;
    }
    let zero = |exit: &Exit| {
        exit.flags.as_ref().and_then(|flags| {
            flags
                .test(crate::ir::Cond::Eq, isa)
                .select(Expr::constant(1), Expr::constant(0))
        })
    };
    let mut reachable = vec![false; blocks.len()];
    let mut work = if blocks.is_empty() {
        Vec::new()
    } else {
        vec![0]
    };
    while let Some(index) = work.pop() {
        if reachable[index] {
            continue;
        }
        reachable[index] = true;
        work.extend(crate::ir::cfg::block_successors(blocks, index));
    }
    let mut known: Vec<_> = blocks
        .iter()
        .enumerate()
        .map(|(index, block)| {
            reachable[index]
                && index != 0
                && !extra_targets.contains(&block.start)
                && !predecessors[index].is_empty()
        })
        .collect();
    loop {
        let mut changed = false;
        for index in 1..blocks.len() {
            if !known[index] {
                continue;
            }
            if !predecessors[index]
                .iter()
                .all(|pred| match exits.get(&blocks[*pred].start) {
                    Some(exit) if exit.touched => zero(exit).is_some(),
                    Some(_) => known[*pred],
                    None => false,
                })
            {
                known[index] = false;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    for (index, block) in blocks.iter().enumerate() {
        if !known[index] || !reads_unknown_flags(block) || carried.entry.contains_key(&block.start)
        {
            continue;
        }
        carried.entry.insert(
            block.start,
            flags::Flags::zero(Expr::reg(zero_carried(isa), 64)),
        );
        let mut work = predecessors[index].clone();
        let mut seen = HashSet::new();
        while let Some(pred) = work.pop() {
            if !seen.insert(pred) {
                continue;
            }
            match exits.get(&blocks[pred].start) {
                Some(exit) if exit.touched => {
                    carried.zero_exporters.insert(blocks[pred].start);
                }
                _ => work.extend(predecessors[pred].iter().copied()),
            }
        }
    }
}

/// Ends a block: a block whose flags carry on passes their operands, before
/// the branch that leaves it.
fn finish_block<M: Machine>(
    machine: &M,
    isa: Isa,
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
    if carried.zero_exporters.contains(&start)
        && let Some(flags) = &exit
        && let Some(value) = flags
            .test(crate::ir::Cond::Eq, isa)
            .select(Expr::constant(1), Expr::constant(0))
    {
        let at = stmts
            .iter()
            .position(|stmt| {
                matches!(
                    stmt,
                    Stmt::Br { .. }
                        | Stmt::Brif { .. }
                        | Stmt::BrifFlags { .. }
                        | Stmt::Switch { .. }
                        | Stmt::BrIndirect { .. }
                )
            })
            .unwrap_or(stmts.len());
        stmts.insert(
            at,
            Stmt::Assign {
                dest: RegRef {
                    index: zero_carried(isa),
                    width: 64,
                },
                value,
            },
        );
    }
    exits.insert(
        start,
        Exit {
            flags: exit,
            touched: machine.flags_touched()
                || stmts.iter().any(|stmt| matches!(stmt, Stmt::Call { .. })),
        },
    );
    Block { start, stmts }
}

/// The blocks, the flags each leaves, and the code its branches out continue
/// in.
type Built = (Vec<Block>, HashMap<u64, Exit>, exits::Pulled);

#[expect(
    clippy::too_many_arguments,
    reason = "Block construction needs the decoded instructions, branch targets, and incoming machine state together."
)]
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
                    image.isa,
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
                    image.isa,
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
                image.isa,
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

    #[test]
    fn flag_predecessors_keep_repeated_edges_and_entry_backedges() {
        use crate::ir::Block;
        use std::collections::HashMap;
        let blocks = vec![
            Block {
                start: 0,
                stmts: vec![Stmt::Switch {
                    index: Expr::reg(0, 64),
                    cases: vec![(0, 8), (1, 8), (2, 99)],
                    default: Some(16),
                }],
            },
            Block {
                start: 8,
                stmts: vec![Stmt::BrifFlags {
                    cond: crate::ir::Cond::Eq,
                    target: 0,
                }],
            },
            Block {
                start: 16,
                stmts: vec![Stmt::BrifFlags {
                    cond: crate::ir::Cond::Eq,
                    target: 0,
                }],
            },
        ];
        let predecessors = super::flag_predecessors(&blocks);
        assert_eq!(predecessors, vec![vec![1, 2], vec![0, 0], vec![0, 1]]);
        let flags = super::flags::Flags::logic(Expr::reg(7, 64));
        let exits: HashMap<_, _> = blocks
            .iter()
            .map(|block| {
                (
                    block.start,
                    super::Exit {
                        flags: Some(flags.clone()),
                        touched: true,
                    },
                )
            })
            .collect();
        for extra in [HashSet::new(), HashSet::from([8, 16])] {
            let mut carried = super::carry_flags(&blocks, &exits, &extra, &predecessors);
            assert!(!carried.entry.contains_key(&0));
            assert_eq!(carried.entry.contains_key(&8), !extra.contains(&8));
            assert_eq!(carried.entry.contains_key(&16), !extra.contains(&16));
            super::carry_zero(
                Isa::X86_64,
                &blocks,
                &exits,
                &extra,
                &predecessors,
                &mut carried,
            );
            assert!(!carried.entry.contains_key(&0));
            for address in &extra {
                assert!(!carried.entry.contains_key(address));
            }
            let mut zero = super::CarriedFlags::default();
            super::carry_zero(
                Isa::X86_64,
                &blocks,
                &exits,
                &extra,
                &predecessors,
                &mut zero,
            );
            assert!(!zero.entry.contains_key(&0));
            assert_eq!(zero.entry.contains_key(&8), !extra.contains(&8));
            assert_eq!(zero.entry.contains_key(&16), !extra.contains(&16));
        }
    }

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
    fn x86_zero_extension_preserves_each_high_byte_source() {
        let originals = [
            (0, 0xfedcba9876543210),
            (1, 0x0123456789abcdef),
            (2, 0x800000007fffffff),
            (3, 0x7fffffff80000000),
        ];
        for source in 0..4u8 {
            for byte in 0..=255u64 {
                let mut registers = originals;
                registers[usize::from(source)].1 =
                    (registers[usize::from(source)].1 & !0xff00) | (byte << 8);
                for word_destination in [false, true] {
                    let mut code = if word_destination {
                        vec![0x66]
                    } else {
                        Vec::new()
                    };
                    code.extend([0x0f, 0xb6, 0xc4 + source, 0xc3]);
                    let expected = if word_destination {
                        (registers[0].1 & !0xffff) | byte
                    } else {
                        byte
                    };
                    assert_eq!(
                        returns(Isa::X86_64, code, &registers),
                        expected,
                        "source={source}, byte={byte}, word_destination={word_destination}"
                    );
                }
            }
        }
    }

    #[test]
    fn x86_zero_extension_keeps_low_byte_word_and_rex_sources() {
        let registers = [
            (0, 0xfedcba9876543210),
            (1, 0x0123456789abcdef),
            (2, 0x800000007fffffff),
            (3, 0x7fffffff80000000),
            (8, 0x80000000000000a5),
        ];
        for source in 0..4u8 {
            for (opcode, bits) in [(0xb6, 8), (0xb7, 16)] {
                let expected = registers[usize::from(source)].1 & ((1u64 << bits) - 1);
                let code = vec![0x0f, opcode, 0xc0 + source, 0xc3];
                assert_eq!(returns(Isa::X86_64, code, &registers), expected);
            }
        }
        assert_eq!(
            returns(
                Isa::X86_64,
                vec![0x40, 0xb4, 0x5a, 0x40, 0x0f, 0xb6, 0xc4, 0xc3],
                &registers
            ),
            0x5a
        );
        assert_eq!(
            returns(Isa::X86_64, vec![0x41, 0x0f, 0xb6, 0xc0, 0xc3], &registers),
            0xa5
        );
        assert_eq!(
            returns(Isa::X86_64, vec![0x48, 0x0f, 0xb7, 0xc1, 0xc3], &registers),
            0xcdef
        );
    }

    #[test]
    fn x86_sign_extension_preserves_each_high_byte_sign() {
        let originals = [
            (0, 0xfedcba9876543210),
            (1, 0x0123456789abcdef),
            (2, 0x800000007fffffff),
            (3, 0x7fffffff80000000),
        ];
        for source in 0..4u8 {
            for byte in 0..=255u64 {
                let mut registers = originals;
                registers[usize::from(source)].1 =
                    (registers[usize::from(source)].1 & !0xff00) | (byte << 8);
                let extended = byte as u8 as i8 as i64 as u64;
                for word_destination in [false, true] {
                    let mut code = if word_destination {
                        vec![0x66]
                    } else {
                        Vec::new()
                    };
                    code.extend([0x0f, 0xbe, 0xc4 + source, 0xc3]);
                    let expected = if word_destination {
                        (registers[0].1 & !0xffff) | (extended & 0xffff)
                    } else {
                        extended & 0xffffffff
                    };
                    assert_eq!(
                        returns(Isa::X86_64, code, &registers),
                        expected,
                        "source={source}, byte={byte}, word_destination={word_destination}"
                    );
                }
            }
        }
    }

    #[test]
    fn x86_sign_extension_keeps_low_word_dword_rex_and_memory_widths() {
        for input in [
            0,
            0x7f,
            0x80,
            0xff,
            0x7fff,
            0x8000,
            0xffff,
            0x7fffffff,
            0x80000000,
            u64::MAX,
        ] {
            let registers = [(0, 0xfedcba9876543210), (1, input), (7, 0x100), (8, input)];
            for wide in [false, true] {
                for (opcode, extended) in [
                    (0xbe, input as u8 as i8 as i64 as u64),
                    (0xbf, input as u16 as i16 as i64 as u64),
                ] {
                    let mut code = if wide { vec![0x48] } else { Vec::new() };
                    code.extend([0x0f, opcode, 0xc1, 0xc3]);
                    let expected = if wide {
                        extended
                    } else {
                        extended & 0xffffffff
                    };
                    assert_eq!(returns(Isa::X86_64, code, &registers), expected);
                }
            }
            let dword = input as u32 as i32 as i64 as u64;
            assert_eq!(
                returns(Isa::X86_64, vec![0x48, 0x63, 0xc1, 0xc3], &registers),
                dword
            );
            for (code, expected) in [
                (
                    vec![0x41, 0x0f, 0xbe, 0xc0, 0xc3],
                    input as u8 as i8 as u32 as u64,
                ),
                (
                    vec![0x49, 0x0f, 0xbe, 0xc0, 0xc3],
                    input as u8 as i8 as i64 as u64,
                ),
            ] {
                assert_eq!(returns(Isa::X86_64, code, &registers), expected);
            }
            for (code, expected) in [
                (
                    vec![0x0f, 0xbe, 0x07, 0xc3],
                    input as u8 as i8 as u32 as u64,
                ),
                (
                    vec![0x48, 0x0f, 0xbe, 0x07, 0xc3],
                    input as u8 as i8 as i64 as u64,
                ),
                (
                    vec![0x48, 0x0f, 0xbf, 0x07, 0xc3],
                    input as u16 as i16 as i64 as u64,
                ),
                (vec![0x48, 0x63, 0x07, 0xc3], dword),
            ] {
                assert_eq!(
                    returns_with(Isa::X86_64, code, &registers, &[(0x100, input)]),
                    expected
                );
            }
        }
        assert_eq!(
            returns(
                Isa::X86_64,
                vec![0x40, 0xb4, 0x80, 0x40, 0x0f, 0xbe, 0xc4, 0xc3],
                &[]
            ),
            0xffffff80
        );
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
    fn byte_division_uses_ax_and_writes_al_and_ah() {
        // mov ax, 0x0107; mov bh, 3; div bh; ret
        let unsigned = vec![0x66, 0xb8, 0x07, 0x01, 0xb7, 0x03, 0xf6, 0xf7, 0xc3];
        assert_eq!(
            returns(Isa::X86_64, unsigned, &[(0, 0x1234_5678_9abc_0000)]),
            0x1234_5678_9abc_0257
        );
        // mov ax, -263; mov bh, -3; idiv bh; ret
        let signed = vec![0x66, 0xb8, 0xf9, 0xfe, 0xb7, 0xfd, 0xf6, 0xff, 0xc3];
        assert_eq!(
            returns(Isa::X86_64, signed, &[(0, 0x1234_5678_9abc_0000)]),
            0x1234_5678_9abc_fe57
        );
    }

    #[test]
    fn signed_division_requires_a_matching_extension_width() {
        // cdq; idiv rcx: edx becomes 0xffffffff, leaving a positive 128-bit dividend.
        let code = [0x99, 0x48, 0xf7, 0xf9];
        for (result, expected) in [
            (vec![0xc3], 0x7fff_ffff_8000_0000),
            (vec![0x48, 0x89, 0xd0, 0xc3], 0x8000_0000),
        ] {
            assert_eq!(
                returns(
                    Isa::X86_64,
                    [code.to_vec(), result].concat(),
                    &[(0, 0x8000_0000), (1, 0x2_0000_0000)]
                ),
                expected
            );
        }
        // cqo; idiv ecx: rax is positive, so edx:eax holds positive 0x80000000.
        let code = [0x48, 0x99, 0xf7, 0xf9];
        for (result, expected) in [(vec![0xc3], 715_827_882), (vec![0x89, 0xd0, 0xc3], 2)] {
            assert_eq!(
                returns(
                    Isa::X86_64,
                    [code.to_vec(), result].concat(),
                    &[(0, 0x8000_0000), (1, 3)]
                ),
                expected
            );
        }
        // cwd; idiv bl: byte division still uses ax, independently of dx.
        assert_eq!(
            returns(
                Isa::X86_64,
                vec![0x66, 0x99, 0xf6, 0xfb, 0xc3],
                &[(0, 0x0107), (3, 3)]
            ),
            0x0257
        );
    }

    #[test]
    fn unsigned_division_preserves_high_dividend_bits_after_partial_zeroing() {
        for zero in [vec![0x66, 0x31, 0xd2], vec![0x30, 0xd2]] {
            // xor dx, dx (or xor dl, dl); div ecx
            for (result, expected) in [(vec![0xc3], 0x8000_0000), (vec![0x89, 0xd0, 0xc3], 7)] {
                assert_eq!(
                    returns(
                        Isa::X86_64,
                        [zero.clone(), vec![0xf7, 0xf1], result].concat(),
                        &[(0, 7), (1, 0x2_0000), (2, 0x1_00ff)]
                    ),
                    expected
                );
            }
        }
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
        for isa in [Isa::AArch64, Isa::X86_64, Isa::Arm32] {
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
                    library: None,
                    sources: Vec::new(),
                };
                let image = Image::from_code(isa, 0, code);
                if let Ok(analysis) = analyze(&image, &function, None) {
                    let _ = crate::render::render(
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

    #[test]
    fn caller_analysis_retains_the_lift_without_callee_summaries() {
        for (isa, code) in [
            (Isa::X86_64, vec![0xe8, 0x1b, 0, 0, 0, 0xc3]),
            (Isa::I386, vec![0xe8, 0x1b, 0, 0, 0, 0xc3]),
            (Isa::AArch64, vec![0x08, 0, 0, 0x94, 0xc0, 0x03, 0x5f, 0xd6]),
            (Isa::Arm32, vec![0x06, 0, 0, 0xeb, 0x1e, 0xff, 0x2f, 0xe1]),
        ] {
            let size = code.len() as u64;
            let image = Image::from_code(isa, 0, code);
            let unknown = |_| crate::loader::Summary::default();
            let first = super::lift_shared(&image, 0, size, &unknown).unwrap();
            for arity in 0..5 {
                let summaries = |_| crate::loader::Summary {
                    arity: Some(arity),
                    ..Default::default()
                };
                let cached = super::lift_shared(&image, 0, size, &summaries).unwrap();
                assert!(!std::sync::Arc::ptr_eq(&first, &cached), "{isa}");
                let uncached =
                    super::lift_with(&image, 0, size, &HashSet::new(), &summaries).unwrap();
                assert_eq!(format!("{cached:?}"), format!("{uncached:?}"));
            }
            let again = super::lift_shared(&image, 0, size, &unknown).unwrap();
            assert!(std::sync::Arc::ptr_eq(&first, &again), "{isa}");
            let lifts = image.lifts.0.lock().unwrap();
            assert!(lifts.values().all(|kept| kept.len() <= super::KEPT_LIFTS));
        }
    }

    /// The kind and arguments of the first call lifted from `bytes`.
    fn first_call(
        bytes: Vec<u8>,
        format: crate::loader::Format,
        summary: crate::loader::Summary,
    ) -> (crate::ir::CallKind, Option<Vec<Expr>>) {
        let len = bytes.len() as u64;
        let mut image = Image::from_code(Isa::X86_64, 0, bytes);
        image.format = format;
        image.functions.insert(
            32,
            Function {
                addr: 32,
                size: None,
                size_estimated: false,
                name: None,
                aliases: Vec::new(),
                library: None,
                sources: Vec::new(),
            },
        );
        let blocks = super::lift_shared(&image, 0, len, &|_| summary).unwrap();
        let Some(Stmt::Call { kind, args, .. }) = blocks
            .iter()
            .flat_map(|block| &block.stmts)
            .find(|stmt| matches!(stmt, Stmt::Call { .. }))
        else {
            panic!("a call");
        };
        (*kind, args.clone())
    }

    #[test]
    fn x86_calls_jumps_and_syscalls_keep_their_kind() {
        use crate::ir::CallKind;
        for (bytes, expected) in [
            (vec![0xe8, 0x1b, 0, 0, 0, 0xc3], CallKind::Invoke),
            (vec![0xe9, 0x1b, 0, 0, 0], CallKind::Tail),
            (vec![0x0f, 0x05, 0xc3], CallKind::Syscall),
        ] {
            let (kind, _) = first_call(bytes, crate::loader::Format::Elf, Default::default());
            assert_eq!(kind, expected);
        }
    }

    #[test]
    fn unused_integer_positions_do_not_clear_floating_inputs() {
        let summary = crate::loader::Summary {
            arity: Some(1),
            floats: Some(2),
            inputs: Some(Default::default()),
            ..Default::default()
        };
        let (_, args) = first_call(
            vec![0xe8, 0x1b, 0, 0, 0, 0xc3],
            crate::loader::Format::Elf,
            summary,
        );
        assert_eq!(
            args,
            Some(vec![
                Expr::constant(0),
                Expr::reg(18, 64),
                Expr::reg(20, 64)
            ])
        );
    }

    #[test]
    fn tail_call_stack_arguments_are_read_past_the_return_address() {
        // A jump pushes nothing: the callee's first stack argument lies
        // where it lay on this function's entry.
        for (format, count, invoke_offset, tail_offset) in [
            (crate::loader::Format::Elf, 6, 0, 8),
            (crate::loader::Format::Pe, 4, 32, 40),
        ] {
            for (opcode, expected) in [(0xe8, invoke_offset), (0xe9, tail_offset)] {
                let summary = crate::loader::Summary {
                    arity: Some(count),
                    stack: 1,
                    ..Default::default()
                };
                let (_, args) = first_call(vec![opcode, 0x1b, 0, 0, 0, 0xc3], format, summary);
                let args = args.expect("known arguments");
                assert_eq!(args.len(), count + 1);
                let wanted = Expr::Load {
                    addr: Box::new(Expr::bin(
                        crate::ir::BinOp::Add,
                        Expr::reg(4, 64),
                        Expr::Const(expected),
                    )),
                    width: 8,
                    signed: false,
                };
                assert_eq!(args.last(), Some(&wanted), "{opcode:#x}");
            }
        }
    }
}

#[cfg(test)]
mod i386_tests;

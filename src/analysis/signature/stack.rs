//! Recovery of arguments and results in the caller's stack frame.

use std::collections::HashMap;

use crate::ir::{Block, Convention, Expr, Stmt};
use crate::loader::Isa;

/// What the body uses of the caller's frame past the register arguments.
#[derive(Default)]
pub(super) struct StackFrame {
    /// The offsets of the 8-byte arguments.
    pub(super) offsets: Vec<i64>,
    /// How many bytes of each argument the body reads, under Go's assembly
    /// ABI; eight elsewhere.
    pub(super) widths: Vec<u8>,
    /// The results the body writes past the arguments, under Go's assembly
    /// ABI: offset and width.
    pub(super) results: Vec<(i64, u8)>,
}

/// The offsets of the arguments past the registers the body reads: loads
/// from the caller's frame, through the stack pointer or a frame pointer
/// set from it, up to the last one read. And under Go's assembly ABI, the
/// results that follow them: what the body writes past the last argument
/// read, or the slot whose address it hands to a call. The arguments then
/// run up to the first result.
pub(super) fn stack_arguments(
    blocks: &[Block],
    landing_pads: &[(u64, Vec<(u64, u64)>)],
    isa: Isa,
    convention: Convention,
) -> StackFrame {
    let Some(start) = convention.stack_arguments() else {
        return StackFrame::default();
    };
    let slot_bytes = i64::from(crate::arch::pointer_bytes(isa));
    let sp = crate::arch::stack_pointer(isa);
    let fp = crate::arch::frame_pointer(isa);
    let results = convention == Convention::GoAbi0;
    let incoming = matches!(
        convention,
        Convention::Aapcs32 | Convention::Aapcs64 | Convention::GoAmd64
    );
    // The registers holding a known offset from the stack pointer on entry,
    // as each block starts: the stack pointer and the frame pointer, and
    // under Go's assembly ABI, whose code may keep the stack pointer in
    // another register while it moves to another stack, any register.
    const STACK_SLOTS: usize = 64;
    type Frame = std::collections::BTreeMap<u16, i64>;
    type Written = [u8; STACK_SLOTS];
    let tracked = |register: u16| {
        register == sp || register == fp || (isa == Isa::Arm32 && register == 7) || results
    };
    let mut entry: Vec<Option<Frame>> = vec![None; blocks.len()];
    let mut written_entry = vec![[0; STACK_SLOTS]; blocks.len()];
    if blocks.is_empty() {
        return StackFrame::default();
    }
    entry[0] = Some(Frame::from([(sp, 0)]));
    // A register plus constants, nested as the upper half of a vector load
    // adds its eight bytes.
    fn based(expr: &Expr, i386: bool) -> Option<(u16, i64)> {
        match expr {
            Expr::Reg { index, width: 64 } => Some((*index, 0)),
            Expr::Bin {
                op: crate::ir::BinOp::And,
                lhs,
                rhs,
            } if i386 && matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) => based(lhs, i386),
            Expr::Bin {
                op: crate::ir::BinOp::Sub,
                lhs,
                rhs,
            } if i386 => match rhs.as_ref() {
                Expr::Const(delta) => based(lhs, i386).and_then(|(base, inner)| {
                    inner.checked_sub(*delta as i64).map(|at| (base, at))
                }),
                _ => None,
            },
            Expr::Bin {
                op: crate::ir::BinOp::Add,
                lhs,
                rhs,
            } => match rhs.as_ref() {
                Expr::Const(delta) => based(lhs, i386).and_then(|(base, inner)| {
                    inner.checked_add(*delta as i64).map(|at| (base, at))
                }),
                _ => None,
            },
            _ => None,
        }
    }
    let offset_of = |expr: &Expr, frame: &Frame| -> Option<i64> {
        let (base, delta) = match expr {
            Expr::Reg { .. }
            | Expr::Bin {
                op: crate::ir::BinOp::Add | crate::ir::BinOp::And,
                ..
            } => {
                let Some(base) = based(expr, isa == Isa::I386) else {
                    return None;
                };
                base
            }
            Expr::Bin {
                op: crate::ir::BinOp::Sub,
                lhs,
                rhs,
            } => match (lhs.as_ref(), rhs.as_ref()) {
                (Expr::Reg { index, width: 64 }, Expr::Const(delta)) => {
                    let Some(delta) = (*delta as i64).checked_neg() else {
                        return None;
                    };
                    (*index, delta)
                }
                _ => return None,
            },
            _ => return None,
        };
        if !tracked(base) {
            return None;
        }
        frame.get(&base).and_then(|at| at.checked_add(delta))
    };
    let located = |addr: &Expr, frame: &Frame, held: &HashMap<u16, i64>| {
        let through = based(addr, isa == Isa::I386)
            .and_then(|(base, delta)| held.get(&base).and_then(|at| at.checked_add(delta)));
        offset_of(addr, frame)
            .or(through)
            .filter(|at| *at >= start && at - start < 8 * STACK_SLOTS as i64)
    };
    let bounded_bytes = |at: i64, width: u8| {
        if !matches!(width, 1 | 2 | 4 | 8) {
            return None;
        }
        let Some(end) = at.checked_add(i64::from(width)) else {
            return None;
        };
        (end <= start + 8 * STACK_SLOTS as i64).then_some(at..end)
    };
    let step =
        |stmt: &Stmt, frame: &mut Frame, held: &mut HashMap<u16, i64>, written: &mut Written| {
            let assigned = match stmt {
                Stmt::Assign { dest, value } if dest.width == 64 => offset_of(value, frame),
                _ => None,
            };
            let preserved: Vec<_> = stmt
                .preserved_output_sources()
                .into_iter()
                .filter_map(|(output, source)| {
                    let dest = stmt.call_outputs()[output].dest;
                    if dest.width != 64 {
                        return None;
                    }
                    frame
                        .get(&source)
                        .or_else(|| held.get(&source))
                        .map(|offset| (dest.index, *offset))
                })
                .collect();
            if incoming
                && let Stmt::Store { addr, width, .. } = stmt
                && let Some(at) = located(addr, frame, held)
                && let Some(bytes) = bounded_bytes(at, *width)
            {
                for at in bytes {
                    let byte = (at - start) as usize;
                    written[byte / 8] |= 1 << (byte % 8);
                }
            }
            for register in crate::ir::visit::statement_registers(stmt).0 {
                held.remove(&register);
                if tracked(register) {
                    frame.remove(&register);
                }
            }
            if let Stmt::Assign { dest, .. } = stmt
                && let Some(at) = assigned
            {
                if tracked(dest.index) {
                    frame.insert(dest.index, at);
                }
                if dest.index != sp && dest.index != fp && at >= start {
                    held.insert(dest.index, at);
                }
            }
            for (destination, at) in preserved {
                if tracked(destination) {
                    frame.insert(destination, at);
                }
                if destination != sp && destination != fp && at >= start {
                    held.insert(destination, at);
                }
            }
        };
    let graph: Vec<_> = (0..blocks.len())
        .map(|index| crate::ir::cfg::block_successors_with_exceptions(blocks, index, landing_pads))
        .collect();
    let all: Vec<_> = (0..blocks.len()).collect();
    let mut queued = vec![false; blocks.len()];
    queued[0] = true;
    let mut work = vec![0];
    while let Some(index) = work.pop() {
        queued[index] = false;
        let mut frame = entry[index].clone().expect("visited");
        let mut held = HashMap::new();
        let mut written = written_entry[index];
        let edges = &graph[index];
        let mut exceptional: Option<(Frame, Written)> = None;
        for stmt in &blocks[index].stmts {
            step(stmt, &mut frame, &mut held, &mut written);
            if matches!(stmt, Stmt::Call { .. })
                && (!edges.exceptional.is_empty() || edges.unknown_exceptional)
            {
                match &mut exceptional {
                    None => exceptional = Some((frame.clone(), written)),
                    Some((before, bytes)) => {
                        before.retain(|register, at| frame.get(register) == Some(&*at));
                        for (byte, after) in bytes.iter_mut().zip(written) {
                            *byte &= after;
                        }
                    }
                }
            }
        }
        // An opaque instruction can unwind with unmodeled frame or memory effects.
        if blocks[index]
            .stmts
            .iter()
            .any(|stmt| matches!(stmt, Stmt::Unsupported { .. }))
        {
            exceptional = None;
        }
        let mut offer = |next: usize, frame: &Frame, written: &Written| {
            let merged = match &entry[next] {
                None => frame.clone(),
                Some(old) => old
                    .iter()
                    .filter(|(register, at)| frame.get(register) == Some(at))
                    .map(|(register, at)| (*register, *at))
                    .collect(),
            };
            let merged_written = if entry[next].is_none() {
                *written
            } else {
                std::array::from_fn(|slot| written_entry[next][slot] & written[slot])
            };
            if entry[next].as_ref() != Some(&merged) || written_entry[next] != merged_written {
                entry[next] = Some(merged);
                written_entry[next] = merged_written;
                if !std::mem::replace(&mut queued[next], true) {
                    work.push(next);
                }
            }
        };
        let normal = if edges.unknown_normal {
            &all
        } else {
            &edges.normal
        };
        for &next in normal {
            offer(next, &frame, &written);
        }
        let exceptional_targets = if edges.unknown_exceptional {
            &all
        } else {
            &edges.exceptional
        };
        if !exceptional_targets.is_empty() {
            let (frame, written) = exceptional.unwrap_or_else(|| (Frame::new(), [0; STACK_SLOTS]));
            for &next in exceptional_targets {
                offer(next, &frame, &written);
            }
        }
    }
    let mut last = None;
    // Under Go's assembly ABI: how far into each slot of the caller's frame
    // the body reads, the bytes it writes there, and the addresses in it
    // that it passes to a call.
    let mut extent: HashMap<i64, i64> = HashMap::new();
    let (mut written, mut handed): (Vec<(i64, i64)>, Vec<i64>) = (Vec::new(), Vec::new());
    let slot = |at: i64| at - (at - start).rem_euclid(slot_bytes);
    let mut scan = |block: &Block, mut frame: Frame, mut initialized: Written, effects: bool| {
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
            for (addr, width) in loads {
                let Some(at) = located(addr, &frame, &held) else {
                    continue;
                };
                if incoming {
                    if let Some(bytes) = bounded_bytes(at, width)
                        && let Some(needed) = bytes.rev().find(|at| {
                            let byte = (at - start) as usize;
                            initialized[byte / 8] & (1 << (byte % 8)) == 0
                        })
                    {
                        last = last.max(Some(slot(needed)));
                    }
                } else if (at - start) % slot_bytes == 0 {
                    last = last.max(Some(at));
                }
                if results {
                    let reach = extent.entry(slot(at)).or_default();
                    *reach = (*reach).max(at - slot(at) + i64::from(width));
                }
            }
            match stmt {
                Stmt::Store { addr, width, .. } if results && effects => {
                    if let Some(at) = located(addr, &frame, &held) {
                        written.push((at, i64::from(*width)));
                    }
                }
                Stmt::Call { .. } if results && effects => {
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
            step(stmt, &mut frame, &mut held, &mut initialized);
        }
    };
    for (index, block) in blocks.iter().enumerate() {
        if let Some(frame) = entry[index].clone() {
            scan(block, frame, written_entry[index], true);
        }
    }
    // Re-entry can erase the joined frame, but not a read on the first entry.
    scan(&blocks[0], Frame::from([(sp, 0)]), [0; STACK_SLOTS], false);
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
        (Some(first), _) => (start..first).step_by(slot_bytes as usize).collect(),
        (None, Some(last)) => (start..=last).step_by(slot_bytes as usize).collect(),
        (None, None) => Vec::new(),
    };
    let widths = offsets
        .iter()
        .map(|at| match extent.get(at) {
            Some(reach) => (*reach as u64).next_power_of_two().min(8) as u8,
            None => slot_bytes as u8,
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

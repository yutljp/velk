//! Whether the callers of a function read what it returns. A function
//! leaves a value in the return register whether or not it means one, so
//! its own body cannot tell a `void` function that last computed into that
//! register from one that returns it; its callers can. A call's result is
//! read when some path from the call reads the register before writing it.
//! A path that reaches the caller's own return passes the result on, which
//! reads it only when the caller returns a value in turn. An assignment used
//! only by the return, or a constant, is evidence of a result even when the
//! known callers discard it.

use std::collections::{HashMap, HashSet};

use crate::arch::RETURN;
use crate::ir::{Block, Expr, Stmt};
use crate::loader::{Image, Isa, NameSource};

/// Whether the function at `addr` has direct callers, none of them reads
/// its result, and it has no explicit result.
pub(crate) fn ignored_by_callers(image: &Image, addr: u64) -> bool {
    let Some(blocks) = body(image, addr) else {
        return false;
    };
    if returns_value(&blocks) || callers(image, addr).is_empty() {
        return false;
    }
    !reads(image, addr, &mut HashSet::new()).0
}

/// How many integer results past the first the function returns, as its
/// callers read them: the furthest result register some path from a call
/// reads before writing it counts with every one before it. Only for Go,
/// whose functions return several values in registers and whose callers
/// take them at once.
pub(crate) fn further_results(image: &Image, addr: u64) -> usize {
    further(image, addr, PASSED_ON)
}

/// How many callers in a row are followed where each returns the results
/// of the one it calls.
const PASSED_ON: u8 = 2;

/// `further_results`, following `passes` callers that return the results.
fn further(image: &Image, addr: u64, passes: u8) -> usize {
    let known = image
        .further_results
        .lock()
        .expect("result lock")
        .get(&(addr, passes))
        .copied();
    if let Some(known) = known {
        return known;
    }
    let (found, returned) = read_further_results(image, addr, passes);
    let mut cache = image.further_results.lock().expect("result lock");
    cache.insert((addr, passes), found);
    // With no caller returning them, following more of them finds the same.
    if !returned {
        for passes in 0..=PASSED_ON {
            cache.insert((addr, passes), found);
        }
    }
    found
}

/// The values the Go functions `ir` calls directly return, for those that
/// return more than one: a function returns as many as its callers read.
pub(crate) fn callee_results(
    image: &Image,
    ir: &crate::ir::FunctionIr,
) -> std::collections::BTreeMap<u64, usize> {
    let mut found = std::collections::BTreeMap::new();
    if !image.go {
        return found;
    }
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        if let Stmt::Call {
            target: Some(target),
            through: None,
            ..
        } = stmt
            && !found.contains_key(target)
        {
            let further = further_results(image, *target);
            if further > 0 {
                found.insert(*target, further + 1);
            }
        }
    }
    found
}

/// How many of the first `results` every path from the entry of `blocks`
/// writes before it returns, the first `taken` counting as written from
/// the start. A call writes them all.
fn set_before_returning(blocks: &[Block], results: &[u16], taken: usize) -> usize {
    let all = (1u32 << results.len()) - 1;
    let edges = crate::ir::cfg::all_edges(blocks, &[]);
    // What each block writes, and what is written where it returns.
    let mut written = vec![0u32; blocks.len()];
    for (index, block) in blocks.iter().enumerate() {
        for stmt in &block.stmts {
            if matches!(stmt, Stmt::Ret { .. }) {
                break;
            }
            if matches!(stmt, Stmt::Call { convention, .. }
                if *convention != crate::ir::Convention::GoWriteBarrier)
            {
                written[index] = all;
                continue;
            }
            let registers = crate::ir::visit::statement_registers(stmt).0;
            for (position, register) in results.iter().enumerate() {
                if registers.contains(register) {
                    written[index] |= 1 << position;
                }
            }
        }
    }
    // What is written on every path to the start of each block.
    let mut entered = vec![all; blocks.len()];
    if let Some(first) = entered.first_mut() {
        *first = all & ((1u32 << taken.min(31)) - 1);
    }
    loop {
        let mut changed = false;
        for index in 0..blocks.len() {
            let left = entered[index] | written[index];
            for &next in &edges[index].normal {
                let met = entered[next] & left;
                if next != 0 && met != entered[next] {
                    entered[next] = met;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    let mut set = all;
    for (index, block) in blocks.iter().enumerate() {
        if block
            .stmts
            .iter()
            .any(|stmt| matches!(stmt, Stmt::Ret { .. }))
        {
            set &= entered[index] | written[index];
        }
    }
    (!set).trailing_zeros() as usize
}

/// Whether the function is one the Go toolchain names as written for the
/// assembly ABI, which passes nothing in registers.
fn assembly(image: &Image, addr: u64) -> bool {
    image
        .functions
        .get(&addr)
        .and_then(|function| function.name.as_deref())
        .is_some_and(|name| name.ends_with(".abi0"))
}

/// The count, and whether some caller returns with results still unread.
fn read_further_results(image: &Image, addr: u64, passes: u8) -> (usize, bool) {
    let convention = crate::ir::Convention::of(image.isa, image.format, image.go);
    if !convention.go_registers() {
        return (0, false);
    }
    let summary = super::summary::summary(image, addr);
    if summary.noreturn || assembly(image, addr) {
        return (0, false);
    }
    // A register the function returns with unchanged is no result of it,
    // unless it is an argument, which it may return as it got it.
    let results: Vec<u16> = convention
        .results()
        .iter()
        .copied()
        .take_while(|register| !convention.float_arguments().contains(register))
        .enumerate()
        .take_while(|(position, register)| {
            summary
                .clobbers
                .is_none_or(|clobbers| clobbers.contains(*register))
                || summary.arity.is_some_and(|arity| *position < arity)
        })
        .map(|(_, register)| register)
        .skip(1)
        .collect();
    if results.is_empty() {
        return (0, false);
    }
    // No more than it sets itself or takes as arguments, which it may
    // return as it got them: what else it returns with as it was on entry
    // is no result of its own.
    let Some(own) = body(image, addr) else {
        return (0, false);
    };
    let taken = summary.arity.map_or(0, |arity| arity.saturating_sub(1));
    let results = &results[..set_before_returning(&own, &results, taken).min(results.len())];
    if results.is_empty() {
        return (0, false);
    }
    let all = (1u32 << results.len()) - 1;
    let mut furthest = 0;
    let mut returned = false;
    for caller in callers(image, addr) {
        let Some(blocks) = body(image, caller) else {
            continue;
        };
        let edges = crate::ir::cfg::all_edges(&blocks, &[]);
        for (first, block) in blocks.iter().enumerate() {
            for (at, stmt) in block.stmts.iter().enumerate() {
                if !matches!(stmt, Stmt::Call { target: Some(target), convention, .. }
                    if *target == addr && convention.go_registers())
                {
                    continue;
                }
                // Go keeps no value in a register over a call, so what a
                // path from this one reads before anything writes it is
                // what the callee left there.
                let mut reached: HashMap<usize, u32> = HashMap::new();
                let mut work = vec![(first, at + 1, all)];
                while let Some((index, from, mut pending)) = work.pop() {
                    for stmt in &blocks[index].stmts[from..] {
                        // A write barrier reads none of them and writes
                        // only where it leaves its buffer.
                        let barrier = matches!(
                            stmt,
                            Stmt::Call {
                                convention: crate::ir::Convention::GoWriteBarrier,
                                ..
                            }
                        );
                        // Another call writes them all; a return passes
                        // on the ones the caller returns in turn. What a
                        // callee takes as arguments is not counted: the
                        // number it takes is itself an estimate.
                        let passed = match stmt {
                            Stmt::Call { .. } if barrier => None,
                            Stmt::Call { .. } | Stmt::Unsupported { .. } => Some(0),
                            Stmt::Ret { .. } => {
                                returned = true;
                                match passes.checked_sub(1) {
                                    Some(passes) => Some(further(image, caller, passes) + 1),
                                    None => Some(0),
                                }
                            }
                            _ => None,
                        };
                        if let Some(passed) = passed {
                            for position in 0..results.len() {
                                if pending & (1 << position) != 0 && position + 1 < passed {
                                    furthest = furthest.max(position + 1);
                                }
                            }
                            pending = 0;
                            break;
                        }
                        let mut read = HashSet::new();
                        if !barrier {
                            for operand in stmt.operands() {
                                value_reads(operand, &mut read);
                            }
                        }
                        // Writing part of a register keeps bits nobody
                        // reads; so does a bit scan, which leaves it as
                        // it was only where the code makes no use of it.
                        if let Stmt::Assign { dest, value, .. } = stmt
                            && (partial_write_of(value, dest.index)
                                || super::signature::scan_source(value, dest.index).is_some())
                        {
                            read.remove(&dest.index);
                        }
                        let written = crate::ir::visit::statement_registers(stmt).0;
                        for (position, register) in results.iter().enumerate() {
                            if pending & (1 << position) == 0 {
                                continue;
                            }
                            if read.contains(register) {
                                furthest = furthest.max(position + 1);
                                pending &= !(1 << position);
                            } else if written.contains(register) {
                                pending &= !(1 << position);
                            }
                        }
                        if pending == 0 {
                            break;
                        }
                    }
                    // The ones up to the furthest found add nothing.
                    pending &= !((1u32 << furthest) - 1);
                    if pending == 0 {
                        continue;
                    }
                    for &next in &edges[index].normal {
                        let seen = reached.entry(next).or_default();
                        let fresh = pending & !*seen;
                        if fresh != 0 {
                            *seen |= fresh;
                            work.push((next, 0, fresh));
                        }
                    }
                }
            }
        }
    }
    (furthest, returned)
}

/// The registers whose values `expr` depends on: a register compared with
/// or subtracted from itself, as `sbb` of a register and itself does to
/// spread the carry, is none.
fn value_reads(expr: &Expr, into: &mut HashSet<u16>) {
    match expr {
        Expr::Reg { index, .. } => {
            into.insert(*index);
        }
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } if lhs == rhs => {
            value_reads(then, into);
            value_reads(els, into);
        }
        Expr::Bin {
            op: crate::ir::BinOp::Sub | crate::ir::BinOp::Xor,
            lhs,
            rhs,
        } if lhs == rhs => {}
        _ => {
            for child in crate::ir::visit::children(expr) {
                value_reads(child, into);
            }
        }
    }
}

/// Whether `value` is `(register & mask) | x` with `x` free of the register:
/// a write of part of it.
fn partial_write_of(value: &Expr, register: u16) -> bool {
    let Expr::Bin {
        op: crate::ir::BinOp::Or,
        lhs,
        rhs,
    } = value
    else {
        return false;
    };
    let kept = matches!(lhs.as_ref(), Expr::Bin {
        op: crate::ir::BinOp::And,
        lhs: inner,
        rhs: mask,
    } if matches!(inner.as_ref(), Expr::Reg { index, .. } if *index == register)
        && matches!(mask.as_ref(), Expr::Const(_)));
    let mut rest = HashSet::new();
    crate::ir::visit::collect_reads(rhs, &mut rest);
    kept && !rest.contains(&register)
}

/// Whether some path returns with the return register as the caller left
/// it, as a function that returns nothing does when no call or assignment
/// on the way sets it. Only for conventions that pass no argument there.
pub(crate) fn returns_unset(blocks: &[Block], convention: crate::ir::Convention) -> bool {
    if convention.arguments().contains(&RETURN) || blocks.is_empty() {
        return false;
    }
    let index: HashMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(position, block)| (block.start, position))
        .collect();
    // Whether the register may still be unset as each block starts.
    let mut unset = vec![false; blocks.len()];
    unset[0] = true;
    let mut pending = vec![0];
    while let Some(at) = pending.pop() {
        let mut still = true;
        for stmt in &blocks[at].stmts {
            if let Stmt::Ret { .. } = stmt {
                return true;
            }
            if crate::ir::visit::statement_registers(stmt)
                .0
                .contains(&RETURN)
            {
                still = false;
                break;
            }
        }
        if !still {
            continue;
        }
        let falls = at + 1;
        let next: Vec<usize> = match blocks[at].stmts.last() {
            Some(Stmt::Br {
                target: Some(target),
                ..
            }) => index.get(target).copied().into_iter().collect(),
            Some(Stmt::Brif { target, .. } | Stmt::BrifFlags { target, .. }) => index
                .get(target)
                .copied()
                .into_iter()
                .chain(std::iter::once(falls))
                .collect(),
            Some(Stmt::Switch { cases, default, .. }) => cases
                .iter()
                .map(|(_, target)| target)
                .chain(default)
                .filter_map(|target| index.get(target).copied())
                .collect(),
            Some(Stmt::Trap { .. } | Stmt::BrIndirect { .. } | Stmt::Br { target: None, .. }) => {
                Vec::new()
            }
            _ => vec![falls],
        };
        for successor in next {
            if successor < blocks.len() && !std::mem::replace(&mut unset[successor], true) {
                pending.push(successor);
            }
        }
    }
    false
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Fate {
    /// Every path writes the register first, or ends in a trap.
    Unused,
    /// Some path reaches the caller's return with it.
    Returned,
    Read,
}

/// The body without its callees' summaries, which would take lifting
/// everything they reach: a call then names no arguments.
#[expect(
    clippy::rc_buffer,
    reason = "Shared blocks retain Vec ownership so an unshared lift can be taken without cloning its blocks."
)]
fn body(image: &Image, addr: u64) -> Option<std::sync::Arc<Vec<Block>>> {
    let Some(value) = image.functions.get(&addr) else {
        return None;
    };
    if value.sources.contains(&NameSource::Plt) {
        return None;
    }
    super::summary::body(image, addr, &|_| crate::loader::Summary::default())
}

/// Whether some caller of `addr` reads its result, and whether the answer
/// leaned on a function still being decided, which `active` holds; such an
/// answer is not kept.
fn reads(image: &Image, addr: u64, active: &mut HashSet<u64>) -> (bool, bool) {
    if let Some(known) = image.result_reads.lock().expect("result lock").get(&addr) {
        return (*known, false);
    }
    // A cycle of calls passing the result on reads it only if something
    // outside the cycle does.
    if !active.insert(addr) {
        return (false, true);
    }
    let mut provisional = false;
    let mut read = false;
    for caller in callers(image, addr) {
        let Some(blocks) = body(image, caller) else {
            read = true;
            break;
        };
        let mut returned = false;
        for (index, block) in blocks.iter().enumerate() {
            for (position, stmt) in block.stmts.iter().enumerate() {
                if let Stmt::Call {
                    target: Some(target),
                    ..
                } = stmt
                    && *target == addr
                {
                    match fate(&blocks, index, position + 1, &mut HashMap::new()) {
                        Fate::Read => read = true,
                        Fate::Returned => returned = true,
                        Fate::Unused => {}
                    }
                }
            }
        }
        if read {
            break;
        }
        // A result passed on to the caller's return is read when the caller
        // returns a value: an explicit assignment, one its own callers read,
        // or, without callers, any value its body leaves in the register.
        if returned {
            let returns_value = if returns_value(&blocks) {
                true
            } else if callers(image, caller).is_empty() {
                writes_result(&blocks)
            } else {
                let (value, leaned) = reads(image, caller, active);
                provisional |= leaned;
                value
            };
            if returns_value {
                read = true;
                break;
            }
        }
    }
    active.remove(&addr);
    if read || !provisional {
        image
            .result_reads
            .lock()
            .expect("result lock")
            .insert(addr, read);
    }
    (read, provisional && !read)
}

/// The functions with a direct call or jump to `addr`.
pub(crate) fn callers(image: &Image, addr: u64) -> Vec<u64> {
    let index = image.branches_to.get_or_init(|| branches(image));
    let mut out: Vec<u64> = index
        .get(&addr)
        .into_iter()
        .flatten()
        .filter_map(|site| {
            let Some((start, function)) = image.functions.range(..=*site).next_back() else {
                return None;
            };
            let size = function.size.unwrap_or(super::UNKNOWN_SIZE);
            (*site < start.saturating_add(size)).then_some(*start)
        })
        .filter(|caller| *caller != addr)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Every direct call and jump in the executable sections, by target, and
/// those the object's relocations name.
fn branches(image: &Image) -> HashMap<u64, Vec<u64>> {
    let mut out: HashMap<u64, Vec<u64>> = HashMap::new();
    for section in image.sections.iter().filter(|section| section.executable) {
        let Some(bytes) = image.read_vaddr(section.vaddr, section.size) else {
            continue;
        };
        match image.isa {
            Isa::I386 | Isa::X86_64 => {
                for at in 0..bytes.len().saturating_sub(4) {
                    if !matches!(bytes[at], 0xe8 | 0xe9) {
                        continue;
                    }
                    let displacement =
                        i32::from_le_bytes(bytes[at + 1..at + 5].try_into().expect("four bytes"));
                    let site = section.vaddr + at as u64;
                    let target = site
                        .wrapping_add(5)
                        .wrapping_add(displacement as i64 as u64);
                    out.entry(target).or_default().push(site);
                }
            }
            Isa::AArch64 => {
                for (word, chunk) in bytes.as_chunks::<4>().0.iter().enumerate() {
                    let instruction = u32::from_le_bytes(*chunk);
                    // B and BL.
                    if instruction & 0x7c00_0000 != 0x1400_0000 {
                        continue;
                    }
                    let offset = ((instruction << 6) as i32 >> 4) as i64;
                    let site = section.vaddr + word as u64 * 4;
                    out.entry(site.wrapping_add(offset as u64))
                        .or_default()
                        .push(site);
                }
            }
            Isa::Arm32 | Isa::Unsupported => {}
        }
    }
    for (site, target) in &image.relocations {
        out.entry(*target).or_default().push(*site);
    }
    out
}

/// Whether some path writes the return register, as any value-returning
/// body does.
fn writes_result(blocks: &[Block]) -> bool {
    blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
        matches!(stmt, Stmt::Assign { dest, .. } if dest.index == RETURN)
            || matches!(stmt, Stmt::Call { .. })
    })
}

/// Whether a path returns a constant or assigns a value used only by its
/// return. Known callers may discard a result even though others can use it.
fn returns_value(blocks: &[Block]) -> bool {
    let mut predecessors = vec![Vec::new(); blocks.len()];
    let mut pending = Vec::new();
    for (index, block) in blocks.iter().enumerate() {
        if matches!(block.stmts.last(), Some(Stmt::Ret { .. })) {
            pending.push((index, false));
        }
        for next in crate::ir::cfg::block_successors(blocks, index) {
            predecessors[next].push(index);
        }
    }
    let mut seen = HashSet::new();
    while let Some((index, mut used)) = pending.pop() {
        if !seen.insert((index, used)) {
            continue;
        }
        let mut defined = false;
        for stmt in blocks[index].stmts.iter().rev() {
            if matches!(stmt, Stmt::Ret { .. }) {
                continue;
            }
            let (written, read) = crate::ir::visit::statement_registers(stmt);
            if written.contains(&RETURN) {
                if matches!(stmt, Stmt::Assign { value, .. }
                    if !used || matches!(value, Expr::Const(_)))
                {
                    return true;
                }
                defined = true;
                break;
            }
            used |= read.contains(&RETURN);
        }
        if !defined {
            for previous in &predecessors[index] {
                pending.push((*previous, used));
            }
        }
    }
    false
}

/// What becomes of the return register from statement `position` of block
/// `index` on.
fn fate(blocks: &[Block], index: usize, position: usize, memo: &mut HashMap<usize, Fate>) -> Fate {
    for stmt in &blocks[index].stmts[position..] {
        if let Some(fate) = event(stmt) {
            return fate;
        }
    }
    let mut worst = Fate::Unused;
    for next in crate::ir::cfg::block_successors(blocks, index) {
        let fate = match memo.get(&next) {
            Some(fate) => *fate,
            None => {
                // A loop back to a block under way adds nothing new.
                memo.insert(next, Fate::Unused);
                let fate = fate(blocks, next, 0, memo);
                memo.insert(next, fate);
                fate
            }
        };
        worst = worst.max(fate);
    }
    // A block that ends without a successor runs into unknown code.
    if crate::ir::cfg::block_successors(blocks, index).is_empty()
        && !matches!(
            blocks[index].stmts.last(),
            Some(Stmt::Trap { .. } | Stmt::Ret { .. })
        )
    {
        return Fate::Read;
    }
    worst
}

/// The register a call passes its first integer argument in.
fn first_argument(stmt: &Stmt) -> u16 {
    match stmt {
        Stmt::Call { convention, .. } => {
            convention.arguments().first().copied().unwrap_or(u16::MAX)
        }
        _ => u16::MAX,
    }
}

/// What `stmt` does with the return register, if it decides its fate.
fn event(stmt: &Stmt) -> Option<Fate> {
    let reads = |expr: &Expr| {
        let mut read = std::collections::HashSet::new();
        crate::ir::visit::collect_reads(expr, &mut read);
        read.contains(&RETURN)
    };
    match stmt {
        Stmt::Assign { dest, value, .. } if dest.index == RETURN => {
            // A write of the low bits keeps the rest without reading it.
            if let Expr::Bin { lhs, rhs, .. } = value
                && let Expr::Bin { lhs: kept, .. } = lhs.as_ref()
                && matches!(kept.as_ref(), Expr::Reg { index, .. } if *index == RETURN)
            {
                return reads(rhs).then_some(Fate::Read);
            }
            Some(if reads(value) {
                Fate::Read
            } else {
                Fate::Unused
            })
        }
        Stmt::Ret { .. } => Some(Fate::Returned),
        Stmt::Trap { .. } => Some(Fate::Unused),
        Stmt::Unsupported { .. } => Some(Fate::Read),
        // A call whose arguments are unknown may take the result as one,
        // where the return register is also the first argument.
        Stmt::Call { args: None, .. } if RETURN == first_argument(stmt) => Some(Fate::Read),
        Stmt::Call { .. } => {
            let (written, read) = crate::ir::visit::statement_registers(stmt);
            if read.contains(&RETURN) {
                Some(Fate::Read)
            } else if written.contains(&RETURN) {
                Some(Fate::Unused)
            } else {
                None
            }
        }
        other => other
            .operands()
            .into_iter()
            .any(reads)
            .then_some(Fate::Read),
    }
}

#[cfg(test)]
mod tests {
    use super::{Fate, fate};
    use crate::ir::{Block, Expr, RegRef, Stmt};

    fn after_call(rest: Vec<Stmt>) -> Fate {
        let blocks = vec![Block {
            start: 0,
            stmts: rest,
        }];
        fate(&blocks, 0, 0, &mut std::collections::HashMap::new())
    }

    fn assign(index: u16, value: Expr) -> Stmt {
        Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
            at: None,
        }
    }

    #[test]
    fn a_go_function_returns_as_many_values_as_its_callers_read() {
        for file in ["go_probe", "go_probe_arm64", "go_probe_arm64_1_27"] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(file);
            let image = crate::loader::load(&path).unwrap();
            let further = |name: &str| {
                let address = image
                    .functions
                    .values()
                    .find(|function| function.name.as_deref() == Some(name))
                    .expect("named function")
                    .addr;
                super::further_results(&image, address)
            };
            assert_eq!(further("main.divmod"), 1, "{file}");
            assert_eq!(further("main.add"), 0, "{file}");
            assert_eq!(further("main.sumSlice"), 0, "{file}");
            // A slice: pointer, length and capacity.
            assert_eq!(further("runtime.growslice"), 2, "{file}");
            // The write barrier keeps every register but its own.
            assert_eq!(further("runtime.gcWriteBarrier2"), 0, "{file}");
        }
    }

    #[test]
    fn a_register_compared_with_itself_is_not_read() {
        let reads = |expr: &Expr| {
            let mut found = std::collections::HashSet::new();
            super::value_reads(expr, &mut found);
            let mut found: Vec<u16> = found.into_iter().collect();
            found.sort_unstable();
            found
        };
        // carry ? 1 : 0 as `sbb` of a register and itself spreads it.
        let spread = Expr::Select {
            cond: crate::ir::Cond::Cc,
            lhs: Box::new(Expr::reg(10, 64)),
            rhs: Box::new(Expr::reg(10, 64)),
            then: Box::new(Expr::reg(3, 64)),
            els: Box::new(Expr::Const(0)),
        };
        assert_eq!(reads(&spread), [3]);
        let cleared = Expr::bin(crate::ir::BinOp::Xor, Expr::reg(9, 64), Expr::reg(9, 64));
        assert_eq!(reads(&cleared), [0u16; 0]);
        let sum = Expr::bin(crate::ir::BinOp::Add, Expr::reg(9, 64), Expr::reg(8, 64));
        assert_eq!(reads(&sum), [8, 9]);
    }

    #[test]
    fn results_count_while_every_path_to_a_return_sets_them() {
        let returns = || Stmt::Ret {
            value: Expr::reg(0, 64),
            at: None,
        };
        let branch = |target| Stmt::Brif {
            cond: crate::ir::Cond::Eq,
            lhs: Expr::reg(0, 64),
            rhs: Expr::Const(0),
            target,
            at: None,
        };
        // One path sets registers 1 and 2, the other only 1.
        let blocks = vec![
            Block {
                start: 0,
                stmts: vec![assign(1, Expr::Const(7)), branch(0x20)],
            },
            Block {
                start: 0x10,
                stmts: vec![assign(2, Expr::Const(8)), returns()],
            },
            Block {
                start: 0x20,
                stmts: vec![returns()],
            },
        ];
        assert_eq!(super::set_before_returning(&blocks, &[1, 2, 3], 0), 1);
        // An argument may be returned as it came.
        assert_eq!(super::set_before_returning(&blocks, &[2, 1, 3], 1), 2);
        assert_eq!(super::set_before_returning(&blocks, &[2, 1, 3], 0), 0);
        // What is written after the return does not count.
        let blocks = vec![Block {
            start: 0,
            stmts: vec![returns(), assign(1, Expr::Const(7))],
        }];
        assert_eq!(super::set_before_returning(&blocks, &[1], 0), 0);
    }

    #[test]
    fn explicit_return_assignment_is_not_an_incidental_result() {
        let ret = Stmt::Ret {
            value: Expr::reg(crate::arch::RETURN, 64),
            at: None,
        };
        let result = assign(crate::arch::RETURN, Expr::reg(8, 64));
        let store = Stmt::Store {
            addr: Expr::Const(0x2000),
            value: Expr::reg(crate::arch::RETURN, 64),
            width: 8,
            at: None,
        };
        let block = |stmts| [Block { start: 0, stmts }];
        assert!(super::returns_value(&block(vec![
            result.clone(),
            ret.clone()
        ])));
        assert!(!super::returns_value(&block(vec![
            result.clone(),
            store.clone(),
            ret.clone()
        ])));
        assert!(super::returns_value(&block(vec![
            assign(crate::arch::RETURN, Expr::Const(0)),
            store,
            ret.clone()
        ])));
        assert!(!super::returns_value(&block(vec![ret.clone()])));
        let call = Stmt::Call {
            abi: None,
            kind: crate::ir::CallKind::Invoke,
            target: Some(0x1000),
            through: None,
            convention: crate::ir::Convention::Aapcs64,
            args: Some(Vec::new()),
            floats_named: true,
            outputs: crate::ir::fallback_call_outputs(crate::ir::Convention::Aapcs64, None),
            clobbers: None,
            via: None,
            at: None,
        };
        assert!(!super::returns_value(&block(vec![
            result.clone(),
            call.clone(),
            ret.clone()
        ])));
        assert!(super::returns_value(&block(vec![call, result, ret])));
    }

    #[test]
    fn a_result_is_read_only_before_the_register_is_written() {
        let ret = Stmt::Ret {
            value: Expr::reg(0, 64),
            at: None,
        };
        assert_eq!(
            after_call(vec![assign(3, Expr::reg(0, 64)), ret.clone()]),
            Fate::Read
        );
        assert_eq!(
            after_call(vec![assign(0, Expr::Const(1)), ret.clone()]),
            Fate::Unused
        );
        assert_eq!(after_call(vec![ret]), Fate::Returned);
    }

    #[test]
    fn result_liveness_distinguishes_preserving_calls_and_named_destinations() {
        let mut call = Stmt::Call {
            kind: crate::ir::CallKind::Invoke,
            target: Some(0x1000),
            through: None,
            convention: crate::ir::Convention::SysV,
            args: Some(Vec::new()),
            floats_named: true,
            abi: None,
            outputs: crate::ir::fallback_call_outputs(
                crate::ir::Convention::SysV,
                Some(Default::default()),
            ),
            clobbers: Some(Default::default()),
            via: None,
            at: None,
        };
        assert_eq!(super::event(&call), None);
        let Stmt::Call {
            outputs, clobbers, ..
        } = &mut call
        else {
            unreachable!()
        };
        *clobbers = Some([2].into_iter().collect());
        *outputs = vec![crate::ir::CallOutput {
            register: 2,
            dest: RegRef {
                index: 0,
                width: 64,
            },
        }];
        assert_eq!(super::event(&call), Some(Fate::Unused));
        let Stmt::Call {
            outputs, clobbers, ..
        } = &mut call
        else {
            unreachable!()
        };
        *clobbers = Some(Default::default());
        *outputs = vec![crate::ir::CallOutput {
            register: 0,
            dest: RegRef {
                index: crate::ir::VARIABLE_BASE,
                width: 64,
            },
        }];
        assert_eq!(super::event(&call), Some(Fate::Read));
    }
}

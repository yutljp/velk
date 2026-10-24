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
    if blocks.iter().any(returns_value) || callers(image, addr).is_empty() {
        return false;
    }
    !reads(image, addr, &mut HashSet::new()).0
}

/// How many integer results past the first the function returns, as its
/// callers read them: the furthest result register some caller reads within
/// the few statements right after a call, before writing it, counts with
/// every one before it. Only for Go, whose functions return several values
/// in registers and whose callers take them at once.
pub(crate) fn further_results(image: &Image, addr: u64) -> usize {
    let convention = crate::ir::Convention::of(image.isa, image.format, image.go);
    if convention != crate::ir::Convention::GoAmd64 {
        return 0;
    }
    let results: Vec<u16> = convention
        .results()
        .iter()
        .copied()
        .take_while(|register| !convention.float_arguments().contains(register))
        .skip(1)
        .collect();
    let mut furthest = 0;
    for caller in callers(image, addr) {
        let Some(blocks) = body(image, caller) else {
            continue;
        };
        for block in blocks.iter() {
            let Some(at) = block.stmts.iter().position(
                |stmt| matches!(stmt, Stmt::Call { target: Some(target), .. } if *target == addr),
            ) else {
                continue;
            };
            let mut pending: Vec<(usize, u16)> = results.iter().copied().enumerate().collect();
            for stmt in block.stmts[at + 1..].iter().take(FURTHER_READS_WITHIN) {
                // Another call writes them all.
                if matches!(stmt, Stmt::Call { .. }) {
                    break;
                }
                let mut read = HashSet::new();
                for operand in stmt.operands() {
                    crate::ir::visit::collect_reads(operand, &mut read);
                }
                // Writing part of a register keeps bits nobody reads.
                if let Stmt::Assign { dest, value } = stmt
                    && partial_write_of(value, dest.index)
                {
                    read.remove(&dest.index);
                }
                let written = crate::ir::visit::statement_registers(stmt).0;
                pending.retain(|(position, register)| {
                    if read.contains(register) {
                        furthest = furthest.max(position + 1);
                        return false;
                    }
                    !written.contains(register)
                });
                if pending.is_empty() {
                    break;
                }
            }
        }
    }
    furthest
}

/// How many statements after a call its further results are looked for.
const FURTHER_READS_WITHIN: usize = 6;

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
            Some(Stmt::Trap | Stmt::BrIndirect { .. } | Stmt::Br { target: None }) => Vec::new(),
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
fn body(image: &Image, addr: u64) -> Option<std::sync::Arc<Vec<Block>>> {
    if image
        .functions
        .get(&addr)?
        .sources
        .contains(&NameSource::Plt)
    {
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
            let returns_value = if blocks.iter().any(returns_value) {
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
            Isa::X86_64 => {
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
            Isa::Unsupported => {}
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

/// Whether the block returns a constant or assigns a value used only by its
/// return. Known callers may discard a result even though others can use it.
fn returns_value(block: &Block) -> bool {
    if !matches!(block.stmts.last(), Some(Stmt::Ret { .. })) {
        return false;
    }
    let mut used = false;
    for stmt in block.stmts.iter().rev().skip(1) {
        let (written, read) = crate::ir::visit::statement_registers(stmt);
        if written.contains(&RETURN) {
            return matches!(stmt, Stmt::Assign { value, .. }
                if !used || matches!(value, Expr::Const(_)));
        }
        used |= read.contains(&RETURN);
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
            Some(Stmt::Trap | Stmt::Ret { .. })
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
        Stmt::Assign { dest, value } if dest.index == RETURN => {
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
        Stmt::Trap => Some(Fate::Unused),
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
        }
    }

    #[test]
    fn explicit_return_assignment_is_not_an_incidental_result() {
        let ret = Stmt::Ret {
            value: Expr::reg(crate::arch::RETURN, 64),
        };
        let result = assign(crate::arch::RETURN, Expr::reg(8, 64));
        let store = Stmt::Store {
            addr: Expr::Const(0x2000),
            value: Expr::reg(crate::arch::RETURN, 64),
            width: 8,
        };
        let block = |stmts| Block { start: 0, stmts };
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

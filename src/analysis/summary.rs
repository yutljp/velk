//! What each function is as a callee: how many arguments it reads and
//! whether it can return. A function's summary depends on its callees', so
//! summaries are settled one strongly connected part of the call graph at a
//! time, callees first, repeating within a part until nothing changes. The
//! result is the same whichever function is asked about first.

use std::collections::{HashMap, HashSet};

use super::{UNKNOWN_SIZE, signature};
use crate::ir::{Block, Stmt};
use crate::lift::lift_with;
use crate::loader::{Image, NameSource, Summary};

/// Library functions that never return, known by name because their code
/// lies in another module.
const NORETURN_IMPORTS: &[&str] = &[
    "abort",
    "exit",
    "_exit",
    "_Exit",
    "quick_exit",
    "__stack_chk_fail",
    "__assert_fail",
    "__assert_rtn",
    "__cxa_throw",
    "__cxa_rethrow",
    "__cxa_bad_cast",
    "__cxa_bad_typeid",
    "__cxa_throw_bad_array_new_length",
    "_Unwind_Resume",
    "longjmp",
    "_longjmp",
    "siglongjmp",
    "__longjmp_chk",
    "pthread_exit",
    "err",
    "errx",
    "verr",
    "verrx",
    "__fortify_fail",
    "__chk_fail",
    "ExitProcess",
];

/// The summary of the function at `addr`, computing it and those of every
/// function it reaches on first use.
pub fn summary(image: &Image, addr: u64) -> Summary {
    if let Some(known) = image.summaries.read().expect("summaries lock").get(&addr) {
        return *known;
    }
    if !image.functions.contains_key(&addr) {
        return Summary::default();
    }
    let mut cache = image.summaries.write().expect("summaries lock");
    if let Some(known) = cache.get(&addr) {
        return *known;
    }
    for part in parts_from(image, addr, &cache) {
        settle(image, &part, &mut cache);
    }
    cache.get(&addr).copied().unwrap_or_default()
}

/// The functions a body calls or jumps to, among the known functions.
fn callees(image: &Image, addr: u64) -> Vec<u64> {
    let Some(blocks) = body(image, addr, &|_| Summary::default()) else {
        return Vec::new();
    };
    let mut out: Vec<u64> = blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .filter_map(|stmt| match stmt {
            Stmt::Call {
                target: Some(target),
                ..
            } => Some(*target),
            _ => None,
        })
        .filter(|target| *target != addr && image.functions.contains_key(target))
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

pub(super) fn body(
    image: &Image,
    addr: u64,
    summaries: crate::lift::Summaries<'_>,
) -> Option<Vec<Block>> {
    let function = image.functions.get(&addr)?;
    let size = function.size.unwrap_or(UNKNOWN_SIZE);
    lift_with(image, addr, size, &HashSet::new(), summaries).ok()
}

/// The strongly connected parts of the call graph reachable from `root`
/// and not yet summarized, callees before callers.
fn parts_from(image: &Image, root: u64, known: &HashMap<u64, Summary>) -> Vec<Vec<u64>> {
    struct Node {
        index: usize,
        low: usize,
        on_stack: bool,
    }
    let mut nodes: HashMap<u64, Node> = HashMap::new();
    let mut edges: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut stack: Vec<u64> = Vec::new();
    let mut parts = Vec::new();
    let mut counter = 0;
    // Each frame: a function and how far through its callees the walk is.
    let mut walk: Vec<(u64, usize)> = Vec::new();
    let mut enter = |addr: u64,
                     nodes: &mut HashMap<u64, Node>,
                     stack: &mut Vec<u64>,
                     walk: &mut Vec<(u64, usize)>| {
        nodes.insert(
            addr,
            Node {
                index: counter,
                low: counter,
                on_stack: true,
            },
        );
        counter += 1;
        stack.push(addr);
        walk.push((addr, 0));
    };
    enter(root, &mut nodes, &mut stack, &mut walk);
    while let Some((addr, next)) = walk.last().copied() {
        let list = edges.entry(addr).or_insert_with(|| {
            callees(image, addr)
                .into_iter()
                .filter(|callee| !known.contains_key(callee))
                .collect()
        });
        if let Some(callee) = list.get(next).copied() {
            walk.last_mut().expect("frame").1 += 1;
            match nodes.get(&callee) {
                None => enter(callee, &mut nodes, &mut stack, &mut walk),
                Some(node) if node.on_stack => {
                    let index = node.index;
                    let low = &mut nodes.get_mut(&addr).expect("entered").low;
                    *low = (*low).min(index);
                }
                Some(_) => {}
            }
            continue;
        }
        walk.pop();
        let (index, low) = {
            let node = &nodes[&addr];
            (node.index, node.low)
        };
        if let Some((parent, _)) = walk.last() {
            let parent_low = &mut nodes.get_mut(parent).expect("entered").low;
            *parent_low = (*parent_low).min(low);
        }
        if low == index {
            let mut part = Vec::new();
            while let Some(member) = stack.pop() {
                nodes.get_mut(&member).expect("entered").on_stack = false;
                part.push(member);
                if member == addr {
                    break;
                }
            }
            part.sort_unstable();
            parts.push(part);
        }
    }
    parts
}

/// Summarizes the functions of one part, whose callees outside it are known.
fn settle(image: &Image, part: &[u64], cache: &mut HashMap<u64, Summary>) {
    let mut current: HashMap<u64, Summary> = part
        .iter()
        .map(|addr| (*addr, by_name(image, *addr)))
        .collect();
    // Within a cycle, start from what can only grow: no arguments, and
    // returning unless the name says otherwise; a pass can only add
    // arguments and remove returns, so the repetition ends.
    for _ in 0..8 {
        let mut changed = false;
        for addr in part {
            let lookup = |target: u64| {
                current
                    .get(&target)
                    .or_else(|| cache.get(&target))
                    .copied()
                    .unwrap_or_default()
            };
            let next = compute(image, *addr, &lookup);
            let merged = Summary {
                arity: match (current[addr].arity, next.arity) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (a, b) => a.or(b),
                },
                noreturn: current[addr].noreturn || next.noreturn,
                stack: current[addr].stack.max(next.stack),
                indirect_result: current[addr].indirect_result || next.indirect_result,
            };
            if merged != current[addr] {
                current.insert(*addr, merged);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    cache.extend(current);
}

/// What the name alone says: a known library function that never returns.
fn by_name(image: &Image, addr: u64) -> Summary {
    let Some(function) = image.functions.get(&addr) else {
        return Summary::default();
    };
    let noreturn = function.name.as_deref().is_some_and(|name| {
        let name = name
            .strip_prefix('_')
            .filter(|_| image.format == crate::loader::Format::MachO)
            .unwrap_or(name);
        NORETURN_IMPORTS.contains(&name)
    });
    // A linkage stub's callee takes what its prototype says.
    let arity = function
        .sources
        .contains(&NameSource::Plt)
        .then_some(function.name.as_deref())
        .flatten()
        .and_then(|name| super::prototypes::of(name, image.format == crate::loader::Format::MachO))
        .map(|prototype| prototype.fixed);
    Summary {
        arity,
        noreturn,
        stack: 0,
        indirect_result: false,
    }
}

fn compute(image: &Image, addr: u64, summaries: crate::lift::Summaries<'_>) -> Summary {
    let named = by_name(image, addr);
    let Some(function) = image.functions.get(&addr) else {
        return named;
    };
    // A linkage stub only jumps on: its callee is in another module.
    if function.sources.contains(&NameSource::Plt) {
        return named;
    }
    let Some(blocks) = body(image, addr, summaries) else {
        return named;
    };
    let signature = signature::recover(&blocks, image.isa, image.format, image.go);
    Summary {
        arity: Some(signature.params.len()),
        noreturn: named.noreturn || !can_return(&blocks),
        stack: signature.stack.len(),
        indirect_result: signature.indirect_result,
    }
}

/// Whether some path from the entry reaches a return, an unknown jump, or
/// the end of the code; a call that does not return ends its block in a trap.
fn can_return(blocks: &[Block]) -> bool {
    if blocks.is_empty() {
        return true;
    }
    let mut seen = vec![false; blocks.len()];
    let mut work = vec![0];
    while let Some(index) = work.pop() {
        if std::mem::replace(&mut seen[index], true) {
            continue;
        }
        let block = &blocks[index];
        match block.stmts.last() {
            Some(Stmt::Ret { .. } | Stmt::BrIndirect { .. } | Stmt::Br { target: None }) => {
                return true;
            }
            Some(Stmt::Trap) => {}
            last => {
                let next = crate::ir::cfg::block_successors(blocks, index);
                // Code that runs off the end of what was lifted may go anywhere.
                let terminated = matches!(
                    last,
                    Some(
                        Stmt::Br { .. }
                            | Stmt::Brif { .. }
                            | Stmt::BrifFlags { .. }
                            | Stmt::Switch { .. }
                    )
                );
                if next.is_empty() && !terminated {
                    return true;
                }
                work.extend(next);
            }
        }
    }
    false
}

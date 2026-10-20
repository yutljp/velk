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

/// Functions of the Go and Rust runtimes that never return, which the
/// analysis cannot always prove: they throw, panic or exit through code it
/// does not follow. Names match exactly, or by prefix where they end in `*`.
const NORETURN_RUNTIME: &[&str] = &[
    "runtime.throw",
    "runtime.fatal",
    "runtime.fatalthrow",
    "runtime.fatalpanic",
    "runtime.gopanic",
    "runtime.Goexit",
    "runtime.panicdivide",
    "runtime.panicshift",
    "runtime.panicmem*",
    "runtime.panicIndex*",
    "runtime.panicSlice*",
    "runtime.goPanic*",
    "runtime.panicdottype*",
    "runtime.panicnildottype",
    "runtime.panicunsafe*",
    "os.Exit",
    "core::panicking::panic*",
    "core::panicking::assert_failed*",
    "core::option::unwrap_failed",
    "core::option::expect_failed",
    "core::result::unwrap_failed",
    "core::slice::index::slice_*",
    "core::str::slice_error_fail*",
    "alloc::alloc::handle_alloc_error",
    "alloc::raw_vec::capacity_overflow",
    "alloc::raw_vec::handle_error",
    "std::process::abort",
    "std::process::exit",
    "std::panicking::begin_panic*",
    "std::panicking::rust_panic_with_hook",
    "__rustc::rust_panic",
    "std::sys::pal::unix::abort_internal",
];

/// Functions whose code never returns that the caller still sees return:
/// `runtime.mcall` leaves for another stack, and the goroutine resumes past
/// the call when it is scheduled again.
const RETURNING_RUNTIME: &[&str] = &["runtime.mcall"];

fn runtime_noreturn(name: &str) -> bool {
    NORETURN_RUNTIME
        .iter()
        .any(|known| match known.split_once('*') {
            Some((prefix, _)) => name.starts_with(prefix),
            None => name == *known,
        })
}

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
    let mut recursive = HashSet::new();
    let mut edges = HashMap::new();
    for part in parts_from(image, addr, &cache, &mut recursive, &mut edges) {
        let cyclic = part.len() > 1 || recursive.contains(&part[0]);
        settle(image, &part, cyclic, &edges, &mut cache);
    }
    cache.get(&addr).copied().unwrap_or_default()
}

/// The functions a body calls or jumps to, among the known functions, and
/// whether it calls itself.
fn callees(image: &Image, addr: u64) -> (Vec<u64>, bool) {
    let Some(blocks) = body(image, addr, &|_| Summary::default()) else {
        return (Vec::new(), false);
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
        .filter(|target| image.functions.contains_key(target))
        .collect();
    out.sort_unstable();
    out.dedup();
    let calls_itself = out.contains(&addr);
    out.retain(|target| *target != addr);
    (out, calls_itself)
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
/// and not yet summarized, callees before callers; the functions that call
/// themselves go into `recursive`.
fn parts_from(
    image: &Image,
    root: u64,
    known: &HashMap<u64, Summary>,
    recursive: &mut HashSet<u64>,
    edges: &mut HashMap<u64, Vec<u64>>,
) -> Vec<Vec<u64>> {
    struct Node {
        index: usize,
        low: usize,
        on_stack: bool,
    }
    let mut nodes: HashMap<u64, Node> = HashMap::new();
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
            let (callees, calls_itself) = callees(image, addr);
            if calls_itself {
                recursive.insert(addr);
            }
            callees
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
/// A part that is no cycle needs one pass: nothing in it depends on itself.
/// In a cycle, a function is summarized again only when one it calls
/// changed.
fn settle(
    image: &Image,
    part: &[u64],
    cyclic: bool,
    edges: &HashMap<u64, Vec<u64>>,
    cache: &mut HashMap<u64, Summary>,
) {
    let mut current: HashMap<u64, Summary> = part
        .iter()
        .map(|addr| (*addr, by_name(image, *addr)))
        .collect();
    // Who calls each function, within the part.
    let mut callers: HashMap<u64, Vec<u64>> = HashMap::new();
    for caller in part {
        for callee in edges.get(caller).into_iter().flatten() {
            if current.contains_key(callee) {
                callers.entry(*callee).or_default().push(*caller);
            }
        }
        // One calling itself depends on itself.
        callers.entry(*caller).or_default().push(*caller);
    }
    // Start from what can only grow: no arguments, and returning unless the
    // name says otherwise; a pass can only add arguments and remove
    // returns, so the work ends.
    let mut pending: std::collections::VecDeque<u64> = part.iter().copied().collect();
    let mut queued: HashSet<u64> = part.iter().copied().collect();
    let mut passes: HashMap<u64, usize> = HashMap::new();
    while let Some(addr) = pending.pop_front() {
        queued.remove(&addr);
        let count = passes.entry(addr).or_default();
        *count += 1;
        if *count > 8 {
            continue;
        }
        let lookup = |target: u64| {
            current
                .get(&target)
                .or_else(|| cache.get(&target))
                .copied()
                .unwrap_or_default()
        };
        let next = compute(image, addr, &lookup);
        let merged = Summary {
            arity: match (current[&addr].arity, next.arity) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            },
            floats: match (current[&addr].floats, next.floats) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            },
            noreturn: current[&addr].noreturn || next.noreturn,
            stack: current[&addr].stack.max(next.stack),
            indirect_result: current[&addr].indirect_result || next.indirect_result,
        };
        if merged != current[&addr] {
            current.insert(addr, merged);
            if cyclic {
                for caller in callers.get(&addr).into_iter().flatten() {
                    if queued.insert(*caller) {
                        pending.push_back(*caller);
                    }
                }
            }
        }
    }
    cache.extend(current);
}

/// What the name alone says: a known library function that never returns.
fn by_name(image: &Image, addr: u64) -> Summary {
    let Some(function) = image.functions.get(&addr) else {
        return Summary::default();
    };
    let Some(name) = function.name.as_deref() else {
        return Summary::default();
    };
    named(image, name, function.sources.contains(&NameSource::Plt))
}

/// What is known of an imported function another module defines, by its
/// name.
pub(crate) fn import(image: &Image, name: &str) -> Summary {
    named(image, name, true)
}

/// What a function's name says; an import's also gives the arguments its
/// prototype takes.
fn named(image: &Image, name: &str, imported: bool) -> Summary {
    let unprefixed = name
        .strip_prefix('_')
        .filter(|_| image.format == crate::loader::Format::MachO)
        .unwrap_or(name);
    let noreturn = NORETURN_IMPORTS.contains(&unprefixed) || runtime_noreturn(unprefixed);
    let arity = imported
        .then(|| super::prototypes::of(name, image.format == crate::loader::Format::MachO))
        .flatten()
        .map(|prototype| prototype.fixed);
    Summary {
        arity,
        floats: None,
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
    let convention = image.convention_of(addr);
    let signature = signature::recover(&blocks, image.isa, convention, image.go);
    // A Go closure's context is no argument a call passes in order.
    let count = |registers: &[u16]| {
        signature
            .params
            .iter()
            .filter(|param| param.name != "closure" && registers.contains(&param.index))
            .count()
    };
    Summary {
        arity: Some(count(convention.arguments())),
        floats: Some(count(convention.float_arguments())),
        noreturn: named.noreturn
            || (!can_return(&blocks)
                && !function
                    .name
                    .as_deref()
                    .is_some_and(|name| RETURNING_RUNTIME.contains(&name))),
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

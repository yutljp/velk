//! What each function is as a callee: how many arguments it reads and
//! whether it can return. A function's summary depends on its callees', so
//! summaries are settled one strongly connected part of the call graph at a
//! time, callees first, repeating within a part until nothing changes. Parts
//! that do not call each other, and the functions of one round within a
//! part, are summarized in parallel. The result is the same whichever
//! function is asked about first, and however many threads there are.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError};

use super::{UNKNOWN_SIZE, signature};
use crate::ir::{Block, Stmt};
use crate::lift::{calling, lift_shared};
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
    let (edges, recursive) = call_graph(image, addr, &cache);
    let parts = parts_from(addr, &edges);
    let settled = settle_parts(image, &parts, &recursive, &edges, &cache);
    cache.extend(settled);
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
) -> Option<Arc<Vec<Block>>> {
    let function = image.functions.get(&addr)?;
    let size = function.size.unwrap_or(UNKNOWN_SIZE);
    lift_shared(image, addr, size, summaries).ok()
}

/// The calls of every function reachable from `root` and not yet
/// summarized, to others of them, and those of them that call themselves.
/// Each round lifts the functions the one before found, in parallel.
fn call_graph(
    image: &Image,
    root: u64,
    known: &HashMap<u64, Summary>,
) -> (HashMap<u64, Vec<u64>>, HashSet<u64>) {
    let mut edges = HashMap::new();
    let mut recursive = HashSet::new();
    let mut round = vec![root];
    while !round.is_empty() {
        let found = in_parallel(&round, |addr| callees(image, *addr));
        let mut next = Vec::new();
        for (addr, (callees, calls_itself)) in round.into_iter().zip(found) {
            if calls_itself {
                recursive.insert(addr);
            }
            let callees: Vec<u64> = callees
                .into_iter()
                .filter(|callee| !known.contains_key(callee))
                .collect();
            next.extend(&callees);
            edges.insert(addr, callees);
        }
        next.sort_unstable();
        next.dedup();
        next.retain(|addr| !edges.contains_key(addr));
        round = next;
    }
    (edges, recursive)
}

/// The strongly connected parts of the call graph from `root`, callees
/// before callers.
fn parts_from(root: u64, edges: &HashMap<u64, Vec<u64>>) -> Vec<Vec<u64>> {
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
        if let Some(callee) = edges[&addr].get(next).copied() {
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

/// Settles each part once the parts it calls are, those that do not
/// depend on each other on different threads. A part reads only the
/// summaries of its callees, which are final by then, so the order the
/// parts go in changes nothing.
fn settle_parts(
    image: &Image,
    parts: &[Vec<u64>],
    recursive: &HashSet<u64>,
    edges: &HashMap<u64, Vec<u64>>,
    known: &HashMap<u64, Summary>,
) -> HashMap<u64, Summary> {
    let part_of: HashMap<u64, usize> = parts
        .iter()
        .enumerate()
        .flat_map(|(index, part)| part.iter().map(move |addr| (*addr, index)))
        .collect();
    let mut waiting = vec![0; parts.len()];
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); parts.len()];
    for (index, part) in parts.iter().enumerate() {
        let mut called: Vec<usize> = part
            .iter()
            .flat_map(|addr| &edges[addr])
            .map(|callee| part_of[callee])
            .filter(|callee| *callee != index)
            .collect();
        called.sort_unstable();
        called.dedup();
        waiting[index] = called.len();
        for callee in called {
            dependents[callee].push(index);
        }
    }
    let settled: HashMap<u64, OnceLock<Summary>> = part_of
        .keys()
        .map(|addr| (*addr, OnceLock::new()))
        .collect();
    let outside = |target: u64| {
        settled
            .get(&target)
            .and_then(OnceLock::get)
            .or_else(|| known.get(&target))
            .copied()
    };
    let queue = Mutex::new(Queue {
        ready: (0..parts.len())
            .filter(|index| waiting[*index] == 0)
            .collect(),
        waiting,
        left: parts.len(),
    });
    let wake = Condvar::new();
    let work = || {
        let _abort = Abort(&queue, &wake);
        loop {
            let index = {
                let mut queue = queue.lock().expect("parts lock");
                loop {
                    if let Some(index) = queue.ready.pop_front() {
                        break index;
                    }
                    if queue.left == 0 {
                        return;
                    }
                    queue = wake.wait(queue).expect("parts lock");
                }
            };
            let part = &parts[index];
            let cyclic = part.len() > 1 || recursive.contains(&part[0]);
            for (addr, summary) in settle(image, part, cyclic, edges, &outside) {
                settled[&addr].set(summary).expect("settled once");
            }
            let mut queue = queue.lock().expect("parts lock");
            queue.left -= 1;
            for dependent in &dependents[index] {
                queue.waiting[*dependent] -= 1;
                if queue.waiting[*dependent] == 0 {
                    queue.ready.push_back(*dependent);
                }
            }
            wake.notify_all();
        }
    };
    let workers = threads().min(parts.len());
    if workers <= 1 {
        work();
    } else {
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(work);
            }
        });
    }
    settled
        .into_iter()
        .map(|(addr, summary)| (addr, summary.into_inner().expect("every part settled")))
        .collect()
}

/// The parts ready to settle, how many unsettled parts each other one
/// calls, and how many are left.
struct Queue {
    ready: VecDeque<usize>,
    waiting: Vec<usize>,
    left: usize,
}

/// Stops the other workers when one panics, so the panic reaches the
/// caller instead of leaving them waiting.
struct Abort<'a>(&'a Mutex<Queue>, &'a Condvar);

impl Drop for Abort<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let mut queue = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            queue.ready.clear();
            queue.left = 0;
            self.1.notify_all();
        }
    }
}

fn threads() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
}

/// `work` on each item, spread over the machine's threads; the results come
/// in the items' order.
fn in_parallel<T: Sync, R: Send>(items: &[T], work: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let workers = threads().min(items.len());
    if workers <= 1 {
        return items.iter().map(work).collect();
    }
    let next = AtomicUsize::new(0);
    let mut done: Vec<(usize, R)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                scope.spawn(|| {
                    let mut done = Vec::new();
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(item) = items.get(index) else {
                            return done;
                        };
                        done.push((index, work(item)));
                    }
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| {
                handle
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            })
            .collect()
    });
    done.sort_unstable_by_key(|(index, _)| *index);
    done.into_iter().map(|(_, result)| result).collect()
}

/// Summarizes the functions of one part, whose callees outside it are
/// settled, as `outside` gives them.
/// A part that is no cycle needs one pass: nothing in it depends on itself.
/// In a cycle, a function is summarized again only when one it calls
/// changed.
fn settle(
    image: &Image,
    part: &[u64],
    cyclic: bool,
    edges: &HashMap<u64, Vec<u64>>,
    outside: &(dyn Fn(u64) -> Option<Summary> + Sync),
) -> HashMap<u64, Summary> {
    // A narrow return starts assumed and can only be disproved, as a cycle
    // of tail calls returns 32 bits when every way out of it does.
    let mut current: HashMap<u64, Summary> = part
        .iter()
        .map(|addr| {
            let summary = Summary {
                narrow_return: true,
                ..by_name(image, *addr)
            };
            (*addr, summary)
        })
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
    // returns and narrow returns, so the work ends.
    // Each round summarizes again, in parallel, every function one it calls
    // changed in the round before.
    let mut pending: Vec<u64> = part.to_vec();
    let mut passes: HashMap<u64, usize> = HashMap::new();
    let mut seen: HashMap<u64, Seen> = HashMap::new();
    let mut unsettled = false;
    while !pending.is_empty() {
        pending.retain(|addr| {
            let count = passes.entry(*addr).or_default();
            *count += 1;
            unsettled |= *count > 8;
            *count <= 8
        });
        let found = {
            let lookup = |target: u64| {
                current
                    .get(&target)
                    .copied()
                    .or_else(|| outside(target))
                    .unwrap_or_default()
            };
            in_parallel(&pending, |addr| {
                compute(image, *addr, &lookup, seen.get(addr))
            })
        };
        let mut next = Vec::new();
        for (addr, (found, lifted)) in pending.iter().zip(found) {
            if let Some(lifted) = lifted {
                seen.insert(*addr, lifted);
            }
            let merged = merge(current[addr], found);
            // A caller reads only what its lift and its narrow return do.
            let heard = |summary: Summary| (calling(summary), summary.narrow_return);
            if cyclic && heard(merged) != heard(current[addr]) {
                next.extend(callers.get(addr).into_iter().flatten());
            }
            current.insert(*addr, merged);
        }
        next.sort_unstable();
        next.dedup();
        pending = next;
    }
    // Given up on before it settled, a narrow return is still only assumed.
    if unsettled {
        for summary in current.values_mut() {
            summary.narrow_return = false;
        }
    }
    current
}

/// What a function is known to be once a pass finds `next`: what only
/// grows keeps the most either says.
fn merge(current: Summary, next: Summary) -> Summary {
    Summary {
        arity: match (current.arity, next.arity) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        },
        floats: match (current.floats, next.floats) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        },
        pointers: current.pointers | next.pointers,
        noreturn: current.noreturn || next.noreturn,
        stack: current.stack.max(next.stack),
        stack_widths: next.stack_widths,
        stack_results: next.stack_results,
        indirect_result: current.indirect_result || next.indirect_result,
        narrow_return: current.narrow_return && next.narrow_return,
    }
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
        pointers: 0,
        noreturn,
        stack: 0,
        stack_widths: [0; 16],
        stack_results: [(0, 0); 9],
        indirect_result: false,
        narrow_return: false,
    }
}

/// A function's body as a pass found it, and the signature recovered from
/// it, which the next pass keeps if the body is the same.
type Seen = (Arc<Vec<Block>>, Arc<signature::Signature>);

fn compute(
    image: &Image,
    addr: u64,
    summaries: crate::lift::Summaries<'_>,
    seen: Option<&Seen>,
) -> (Summary, Option<Seen>) {
    let named = by_name(image, addr);
    let Some(function) = image.functions.get(&addr) else {
        return (named, None);
    };
    // A linkage stub only jumps on: its callee is in another module.
    if function.sources.contains(&NameSource::Plt) {
        return (named, None);
    }
    let Some(blocks) = body(image, addr, summaries) else {
        return (named, None);
    };
    let convention = image.convention_of(addr);
    let signature = match seen {
        Some((before, signature)) if Arc::ptr_eq(before, &blocks) => signature.clone(),
        _ => Arc::new(signature::recover(&blocks, image.isa, convention, image.go)),
    };
    // A Go closure's context is no argument a call passes in order.
    let count = |registers: &[u16]| {
        signature
            .params
            .iter()
            .filter(|param| param.name != "closure" && registers.contains(&param.index))
            .count()
    };
    let summary = Summary {
        arity: Some(count(convention.arguments())),
        floats: Some(count(convention.float_arguments())),
        pointers: convention
            .arguments()
            .iter()
            .enumerate()
            .filter(|(_, register)| {
                signature
                    .params
                    .iter()
                    .any(|param| param.index == **register && param.ty.is_pointer())
            })
            .fold(0, |bits, (position, _)| bits | 1 << position),
        noreturn: named.noreturn
            || (!can_return(&blocks)
                && !function
                    .name
                    .as_deref()
                    .is_some_and(|name| RETURNING_RUNTIME.contains(&name))),
        stack: signature.stack.len(),
        stack_widths: std::array::from_fn(|slot| match signature.stack_widths.get(slot) {
            Some(8) | None => 0,
            Some(width) => *width,
        }),
        stack_results: std::array::from_fn(|position| {
            match (
                signature.stack_results.get(position),
                convention.stack_arguments(),
            ) {
                (Some((at, width)), Some(start)) => ((at - start) as u16, *width),
                _ => (0, 0),
            }
        }),
        indirect_result: signature.indirect_result,
        // One returning on the stack leaves nothing in the return register.
        narrow_return: signature.stack_results.is_empty()
            && crate::passes::widths::returns_32(&blocks, &|target| {
                summaries(target).narrow_return
            }),
    };
    (summary, Some((blocks, signature)))
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

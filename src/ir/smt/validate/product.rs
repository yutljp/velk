//! Checks a pass application as a whole, for rewrites a statement-by-
//! statement comparison cannot justify: a register renamed throughout the
//! function, a frame address taken from another register, a constant known
//! from another block, or an assignment dropped or added.
//!
//! The function before the pass and the one after it run side by side, block
//! by block. Assignments are private to each side; every other statement is
//! paired with the one at the same place on the other side, and must do the
//! same thing: store the same bytes at the same address, branch the same way,
//! return the same value, call with the same inputs. Each block is checked
//! from any entry states of the two sides related by that block's
//! invariants, equations between an expression of the original function and
//! one of the rewritten function. The invariants are inferred: candidates
//! come from where the rewritten statements differ, and those any edge can
//! break are dropped until every edge keeps the rest (Houdini). Both sides
//! start the function in the same state.
//!
//! A callee, like a machine instruction, is taken to compute what it changes
//! from what it reads: given the same inputs on both sides it changes the
//! same registers and memory the same way. A call reads what the IR says it
//! does: its expressions, the registers its convention reads unnamed, those
//! its declaration names, and memory; the stack pointer only when its
//! declaration names it. A register the callee changes that one of the
//! call's outputs takes changes only in that output's destination: the
//! register keeps its value, as `statement_writes` has the passes read it.
//!
//! A callee whose summary finds it returning 32-bit values returns its
//! result zero-extended, and one whose summary finds it taking no result
//! address reads none in x8, for a pass that relies on the summary.
//!
//! A callee of known arguments leaves the caller's frame alone at and above
//! the end of its stack arguments, eight bytes for each argument from where
//! its convention places them, when the function before the pass uses no
//! address in its frame as a value: such a frame is reached only through
//! the stack pointer, and the callee owns only its arguments' slots. A byte
//! is kept only where both sides' stack pointers place it past them.
//!
//! An undefined value is any value, chosen independently where it appears.
//! An operation without an SMT model is one unknown function of its
//! arguments, the same on both sides.
//!
//! A function's result is what its return type keeps, the type being the
//! one the pass leaves: the low bits of an integer type's width, fewer when
//! the pass has every return read one register at a narrower width, and
//! nothing for a function returning nothing. Which type the callers see is the
//! signature recovery's inference; this check takes it as given.
//!
//! An application the inferred equations do not prove is put to z3's Horn
//! engine as a whole: one relation per block between the two sides' states
//! on entry, which it may find any invariant for, or refute with a path
//! from the function's start. On an architecture with 32-bit addresses the
//! function starts with its stack pointer clear of address zero and of the
//! top of the address space by more than any frame, as the passes take
//! frame addresses not to wrap; and its stack pointer is aligned as the
//! function's entry alignment says, which its convention gives, or the
//! kernel for an executable's entry point.

mod candidates;
mod horn;
mod run;
mod side;
mod solver;
#[cfg(test)]
mod tests;

use candidates::candidates;
use horn::horn;
use run::{Run, run, start, starting};
use solver::Stats;
pub(super) use solver::{Reply, Solver};

use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use super::{Script, Strategy};
use crate::ir::smt::constant;
use crate::ir::{Block, Expr, Stmt};

/// How far each statement of each side finds the stack pointer from its
/// value on entry; none in a block no edge from the entry reaches.
#[derive(Debug, Clone)]
pub struct Frames {
    pub before: Vec<Vec<Option<i64>>>,
    pub after: Vec<Vec<Option<i64>>>,
}

/// How far the stack pointer `sp` is from its value on entry before each
/// statement of `blocks`, along the edges the product follows; none when a
/// statement moves it other than by a constant or two edges bring it to a
/// block at different places.
pub(crate) fn stack_offsets(blocks: &[Block], sp: u16) -> Option<Vec<Vec<Option<i64>>>> {
    let index: BTreeMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(position, block)| (block.start, position))
        .collect();
    let mut entries: Vec<Option<i64>> = vec![None; blocks.len()];
    let mut offsets: Vec<Vec<Option<i64>>> = blocks
        .iter()
        .map(|block| vec![None; block.stmts.len()])
        .collect();
    let mut pending = Vec::new();
    if !blocks.is_empty() {
        entries[0] = Some(0);
        pending.push(0);
    }
    while let Some(position) = pending.pop() {
        let mut offset = entries[position]?;
        let mut targets = Vec::new();
        let mut ended = false;
        for (number, stmt) in blocks[position].stmts.iter().enumerate() {
            offsets[position][number] = Some(offset);
            match stmt {
                Stmt::Assign { dest, value, .. } if dest.index == sp => {
                    let Expr::Bin { op, lhs, rhs } = value else {
                        return None;
                    };
                    let (Expr::Reg { index, width: 64 }, Expr::Const(constant)) = (&**lhs, &**rhs)
                    else {
                        return None;
                    };
                    if dest.width != 64 || *index != sp {
                        return None;
                    }
                    offset = match op {
                        crate::ir::BinOp::Add => offset.wrapping_add(*constant as i64),
                        crate::ir::BinOp::Sub => offset.wrapping_sub(*constant as i64),
                        _ => return None,
                    };
                }
                _ if crate::ir::visit::statement_registers(stmt).0.contains(&sp) => return None,
                Stmt::Brif { target, .. } => targets.push((*target, offset)),
                Stmt::Br { target, .. } => {
                    targets.extend(target.map(|target| (target, offset)));
                    ended = true;
                }
                Stmt::Switch { cases, default, .. } => {
                    targets.extend(cases.iter().map(|(_, target)| (*target, offset)));
                    targets.extend(default.map(|target| (target, offset)));
                    ended = true;
                }
                Stmt::Ret { .. } | Stmt::Trap { .. } | Stmt::BrIndirect { .. } => ended = true,
                _ => {}
            }
            if ended {
                break;
            }
        }
        let mut next: Vec<(usize, i64)> = targets
            .into_iter()
            .filter_map(|(target, offset)| Some((*index.get(&target)?, offset)))
            .collect();
        if !ended && position + 1 < blocks.len() {
            next.push((position + 1, offset));
        }
        for (target, offset) in next {
            match entries[target] {
                Some(known) if known != offset => return None,
                Some(_) => {}
                None => {
                    entries[target] = Some(offset);
                    pending.push(target);
                }
            }
        }
    }
    Some(offsets)
}

/// A pass application recorded for the whole-function check.
#[derive(Debug, Clone)]
pub struct Application {
    pub site: &'static str,
    pub tag: String,
    /// The application's place among the passes applied to the work named
    /// by `tag`.
    pub index: usize,
    pub before: Vec<Block>,
    pub after: Vec<Block>,
    /// Whether exceptions unwind into blocks of the function, which then
    /// start in states no edge describes.
    pub landing_pads: bool,
    /// The stack pointer, on an architecture with 32-bit addresses.
    pub narrow_stack: Option<u16>,
    /// The stack pointer, when the function hands out no address of its
    /// frame.
    pub private_frame: Option<u16>,
    /// Where, besides, each side's stack pointer is before each statement,
    /// when only constants move it and no statement of the function
    /// reaches memory in ways atomics cannot be ordered around, so no
    /// atomic or barrier writes the frame below its stack pointer on entry.
    pub frames: Option<Frames>,
    /// The function's calling convention.
    pub convention: crate::ir::Convention,
    /// The stack pointer and what the function knows of it on entry.
    pub entry_alignment: Option<(u16, crate::ir::EntryAlignment)>,
    /// The low bits of a returned value the function's return type keeps,
    /// as the pass leaves the type; none when it returns nothing.
    pub returned: Option<u32>,
    /// Callees the pass takes to return 32-bit values, as their summaries
    /// find them.
    pub narrow_results: BTreeSet<u64>,
    /// Callees the pass takes to read no result address in `AArch64`'s x8,
    /// as their summaries find them.
    pub without_result_address: BTreeSet<u64>,
    /// Machine registers whose values on entry fit in 32 bits.
    pub narrow_registers: BTreeSet<u16>,
    /// Parameters the function enters with in two registers, low half first.
    pub entry_pairs: BTreeMap<u16, (u16, u16)>,
}

impl Application {
    /// The value register `index` enters the function with, in terms of the
    /// entry symbols `r{index}`: a parameter in two registers joins them.
    fn entry(&self, index: u16) -> String {
        match self.entry_pairs.get(&index) {
            Some((low, high)) => format!(
                "(bvor (bvshl r{high} {}) (bvand r{low} {}))",
                constant(32),
                constant(0xffff_ffff)
            ),
            None => format!("r{index}"),
        }
    }

    /// The facts the entry symbols of `registers` meet.
    fn entry_facts<'a>(&self, registers: impl Iterator<Item = &'a u16>) -> Vec<String> {
        registers
            .filter(|register| self.narrow_registers.contains(register))
            .map(|register| format!("(bvult r{register} {})", constant(1 << 32)))
            .collect()
    }
}

/// Where a 32-bit architecture's stack pointer is when a function starts:
/// clear of address zero and of the top of the address space by more than
/// any frame, so frame addresses computed in 32 bits do not wrap.
const NARROW_STACK: (u64, u64) = (1 << 20, (1 << 32) - (1 << 20));

/// The outcome of checking an [`Application`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The rewritten function does what the original did.
    Proved,
    /// An obligation the inferred invariants do not discharge, and a state
    /// that breaks it. Either the pass changed what the function does, or
    /// it relies on a fact the invariants cannot express.
    NotProved { what: String, state: String },
    /// The application has something the check does not model.
    Unchecked(&'static str),
    /// The solver gave up on an obligation.
    Unknown { what: String, reason: String },
}

/// Equations between an expression of the original function, evaluated by
/// its side, and one of the rewritten function, evaluated by the other.
type Candidate = (Expr, Expr);

/// Checks `application` with one solver process.
#[must_use]
pub fn check(application: &Application, rlimit: u64, bounded_rlimit: u64) -> Verdict {
    let Some(mut solver) = Solver::start() else {
        return Verdict::Unknown {
            what: String::new(),
            reason: "z3 unavailable".to_owned(),
        };
    };
    check_with(application, &mut solver, rlimit, bounded_rlimit)
}

/// The same, with where the solver work went.
#[must_use]
pub fn check_measured(
    application: &Application,
    rlimit: u64,
    bounded_rlimit: u64,
) -> (Verdict, Stats) {
    let Some(mut solver) = Solver::start() else {
        return (
            Verdict::Unknown {
                what: String::new(),
                reason: "z3 unavailable".to_owned(),
            },
            Stats::default(),
        );
    };
    let verdict = check_with(application, &mut solver, rlimit, bounded_rlimit);
    (verdict, std::mem::take(&mut solver.stats))
}

fn check_with(
    application: &Application,
    solver: &mut Solver,
    rlimit: u64,
    bounded_rlimit: u64,
) -> Verdict {
    // A callee that may write any memory makes queries the solver decides
    // quickly; keeping a private frame's bytes across calls is for an
    // application that model refutes, the refutation saying nothing while
    // the frame's bytes are kept out.
    let coarse = Application {
        private_frame: None,
        ..application.clone()
    };
    let verdict = check_model(&coarse, solver, rlimit, bounded_rlimit);
    if application.private_frame.is_some() && matches!(verdict, Verdict::NotProved { .. }) {
        return check_model(application, solver, rlimit, bounded_rlimit);
    }
    verdict
}

fn check_model(
    application: &Application,
    solver: &mut Solver,
    rlimit: u64,
    bounded_rlimit: u64,
) -> Verdict {
    if application.landing_pads {
        return Verdict::Unchecked("exceptions unwind into the function");
    }
    let (before, after) = (&application.before, &application.after);
    if before.len() != after.len()
        || before
            .iter()
            .zip(after)
            .any(|(old, new)| old.start != new.start)
    {
        return Verdict::Unchecked("blocks were added, removed or reordered");
    }
    let product = match Product::new(application) {
        Ok(product) => product,
        Err(reason) => return Verdict::Unchecked(reason),
    };
    solver.stats.blocks = before.len();
    solver.stats.candidates = product.candidates.len();

    // Each stronger strategy is for what the ones before leave undecided:
    // the bounded one for an edge's whole group of candidates, then, if
    // candidates were dropped undecided, for each of them. Replies are
    // kept, so a stage asks again only what was undecided.
    let strategies = [
        (Strategy::WordLevel, rlimit),
        (Strategy::Integer, rlimit),
        (Strategy::Bounded, bounded_rlimit),
    ];
    // Most applications are proved with a tenth of the limits, and a query
    // left undecided with them is mostly left undecided with all of them,
    // each undecided group being asked again in parts; so the inference
    // first runs with a tenth, and only an application it leaves unproved
    // has the whole limits.
    let tenth = strategies.map(|(strategy, limit)| (strategy, limit / 10));
    if product
        .equations(application, solver, &tenth, false)
        .failed
        .is_none()
    {
        return Verdict::Proved;
    }
    let quick = product.equations(application, solver, &strategies, false);
    if quick.failed.is_none() {
        return Verdict::Proved;
    }
    let first = if quick.undecided {
        product.equations(application, solver, &strategies, true)
    } else {
        quick
    };
    let Some(failed) = first.failed else {
        return Verdict::Proved;
    };
    let horned = solver.horn(
        &horn(application, &first.checked, &product.registers),
        bounded_rlimit,
    );
    match horned {
        Reply::Sat(_) => Verdict::Proved,
        Reply::Unsat => match failed {
            Verdict::NotProved { what, state } => Verdict::NotProved {
                what,
                state: format!("{state}, on a path from the function's start"),
            },
            Verdict::Unknown { what, .. } => Verdict::NotProved {
                what,
                state: "on a path from the function's start".to_owned(),
            },
            other => other,
        },
        Reply::Unknown(_) => failed,
    }
}

/// Both sides of every block, run from the entry states, with the
/// candidate invariants and what holds when the function starts.
struct Product {
    blocks: BTreeMap<u64, usize>,
    candidates: Vec<Candidate>,
    /// The registers a candidate makes equal on the two sides.
    registers: Vec<u16>,
    runs: Vec<Run>,
    start: (Script, Vec<String>),
    /// The blocks a path from the first block reaches.
    reached: Vec<bool>,
    /// Whether an edge leads back to the first block.
    entered_again: bool,
}

/// The invariants inferred and the obligation checked under them.
struct Equations {
    /// The first obligation the invariants leave unproved.
    failed: Option<Verdict>,
    checked: Vec<Checked>,
    /// Whether every strategy left some query undecided.
    undecided: bool,
}

impl Product {
    fn new(application: &Application) -> Result<Self, &'static str> {
        let before = &application.before;
        let blocks: BTreeMap<u64, usize> = before
            .iter()
            .enumerate()
            .map(|(index, block)| (block.start, index))
            .collect();
        let candidates = candidates(application);
        let registers: Vec<u16> = candidates
            .iter()
            .filter_map(|candidate| match candidate {
                (
                    Expr::Reg {
                        index: a,
                        width: 64,
                    },
                    Expr::Reg {
                        index: b,
                        width: 64,
                    },
                ) if a == b => Some(*a),
                _ => None,
            })
            .collect();
        let unshared = Rc::new(BTreeSet::new());
        let runs = (0..before.len())
            .map(|index| {
                run(
                    application,
                    index,
                    &blocks,
                    &candidates,
                    &registers,
                    &unshared,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let start = start(application, &candidates);
        // The function starts in its first block; one no path from there
        // reaches never runs, as the function has no landing pads and no
        // indirect branches.
        let mut reached = vec![false; before.len()];
        let mut work = vec![0];
        while let Some(block) = work.pop() {
            if !std::mem::replace(&mut reached[block], true) {
                work.extend(runs[block].edges.iter().map(|edge| edge.target));
            }
        }
        let entered_again = runs
            .iter()
            .enumerate()
            .any(|(block, run)| reached[block] && run.edges.iter().any(|edge| edge.target == 0));
        Ok(Self {
            blocks,
            candidates,
            registers,
            runs,
            start,
            reached,
            entered_again,
        })
    }

    /// Infers the invariants and checks the obligations under them, asking
    /// each query with `strategies` in turn until one decides it. The part of
    /// an undecided group of candidates is asked with the first strategy
    /// only, and so is a single candidate unless `thorough`.
    fn equations(
        &self,
        application: &Application,
        solver: &mut Solver,
        strategies: &[(Strategy, u64)],
        thorough: bool,
    ) -> Equations {
        let before = &application.before;
        let all: BTreeSet<usize> = (0..self.candidates.len()).collect();
        let mut invariants: Vec<BTreeSet<usize>> = vec![all; before.len()];
        // An invariant the solver leaves undecided on an edge is dropped
        // without a counterexample, so an obligation that fails later proves
        // nothing about the rewrite.
        let mut undecided = None;
        let mut left = false;
        // How many replies in a row the bounded strategy left undecided:
        // after so many it is asked no more, as on some functions it decides
        // nothing for hours at its large limit.
        const GIVE_UP: usize = 16;
        let mut streak = 0;
        // `all` asks with every strategy rather than the first; `split`
        // says an undecided reply is asked again in parts.
        let mut ask = |solver: &mut Solver, query: &str, names: &[&str], all: bool, split: bool| {
            let mut reply = Reply::Unknown("no strategy".to_owned());
            for &(strategy, rlimit) in &strategies[..if all { strategies.len() } else { 1 }] {
                if !matches!(reply, Reply::Unknown(_)) {
                    break;
                }
                let bounded = strategy == Strategy::Bounded;
                if bounded && streak >= GIVE_UP {
                    continue;
                }
                reply = solver.values(query, rlimit, strategy, names);
                if bounded {
                    streak = if matches!(reply, Reply::Unknown(_)) {
                        streak + 1
                    } else {
                        0
                    };
                }
            }
            left |= !split && matches!(reply, Reply::Unknown(_));
            reply
        };

        loop {
            solver.stats.rounds += 1;
            let mut weakened = false;
            let mut edges: Vec<(Option<usize>, usize)> = vec![(None, 0)];
            for (source, run) in self.runs.iter().enumerate() {
                if self.reached[source] {
                    edges.extend((0..run.edges.len()).map(|edge| (Some(source), edge)));
                }
            }
            for (source, edge) in edges {
                let (script, assumed, path, holds, target) = match source {
                    None => (
                        &self.start.0,
                        String::from("true"),
                        "true",
                        &self.start.1,
                        0,
                    ),
                    Some(source) => {
                        let run = &self.runs[source];
                        let edge = &run.edges[edge];
                        (
                            &run.script,
                            conjunction(&invariants[source], &run.assumed),
                            edge.path.as_str(),
                            &edge.holds,
                            edge.target,
                        )
                    }
                };
                // Candidates the solver leaves undecided together are asked
                // about in halves, so only those undecided alone are dropped.
                let whole = invariants[target].len();
                let mut groups: Vec<BTreeSet<usize>> = vec![invariants[target].clone()];
                while let Some(group) = groups.pop() {
                    if group.is_empty() {
                        continue;
                    }
                    let kept = conjunction(&group, holds);
                    let assertion = format!("(and {assumed} {path} (not {kept}))");
                    let (query, _) = script.query(&assertion);
                    let names: Vec<&str> = group
                        .iter()
                        .map(|&candidate| holds[candidate].as_str())
                        .collect();
                    let all = group.len() == whole || (group.len() == 1 && thorough);
                    match ask(solver, &query, &names, all, group.len() > 1) {
                        Reply::Unsat => {}
                        Reply::Sat(values) => {
                            for (candidate, value) in group.iter().zip(values) {
                                if !value {
                                    invariants[target].remove(candidate);
                                }
                            }
                            weakened = true;
                        }
                        Reply::Unknown(_) if group.len() > 1 => {
                            let mut first = group;
                            let second = first.split_off(
                                &first
                                    .iter()
                                    .nth(first.len() / 2)
                                    .copied()
                                    .expect("two or more"),
                            );
                            groups.push(first);
                            groups.push(second);
                        }
                        Reply::Unknown(reason) => {
                            undecided.get_or_insert(format!(
                                "invariants at block {:#x} dropped: {reason}",
                                before[target].start
                            ));
                            invariants[target].retain(|candidate| !group.contains(candidate));
                            weakened = true;
                        }
                    }
                }
            }
            if !weakened {
                break;
            }
        }

        let mut checked: Vec<Checked> = Vec::new();
        let mut failed = None;
        for (index, invariant) in invariants.iter().enumerate() {
            if !self.reached[index] {
                continue;
            }
            let shared: BTreeSet<u16> = invariant
                .iter()
                .filter_map(|&candidate| match &self.candidates[candidate] {
                    (
                        Expr::Reg {
                            index: a,
                            width: 64,
                        },
                        Expr::Reg {
                            index: b,
                            width: 64,
                        },
                    ) if a == b => Some(*a),
                    _ => None,
                })
                .collect();
            let mut run = run(
                application,
                index,
                &self.blocks,
                &self.candidates,
                &self.registers,
                &Rc::new(shared.clone()),
            )
            .expect("a block that ran once runs again");
            let mut assumed = conjunction(invariant, &run.assumed);
            // A first block no edge leads back to starts as the function does.
            if index == 0 && !self.entered_again {
                let facts = starting(application, &self.registers, &shared, &mut run.script);
                assumed = format!("(and {assumed} {facts})");
            }
            if failed.is_none() {
                for (what, mismatch) in &run.obligations {
                    let assertion = format!("(and {assumed} {mismatch})");
                    let (query, symbols) = run.script.query(&assertion);
                    let reply = ask(solver, &query, &[], true, false);
                    let what = format!("block {:#x}: {what}", before[index].start);
                    failed = match reply {
                        Reply::Unsat => continue,
                        Reply::Sat(_) => Some(match undecided.take() {
                            Some(reason) => Verdict::Unknown { what, reason },
                            None => Verdict::NotProved {
                                state: solver.model(&query, &symbols),
                                what,
                            },
                        }),
                        Reply::Unknown(reason) => Some(Verdict::Unknown { what, reason }),
                    };
                    break;
                }
            }
            checked.push(Checked {
                index,
                shared,
                invariant: invariant
                    .iter()
                    .map(|&candidate| run.assumed[candidate].clone())
                    .collect(),
                run,
            });
        }
        Equations {
            failed,
            checked,
            undecided: left,
        }
    }
}

/// A reached block run from entry states its inferred invariants relate.
struct Checked {
    index: usize,
    /// The registers the invariants make equal, one symbol on both sides.
    shared: BTreeSet<u16>,
    /// The invariants, as Booleans of the run's script.
    invariant: Vec<String>,
    run: Run,
}

fn conjunction(chosen: &BTreeSet<usize>, terms: &[String]) -> String {
    if chosen.is_empty() {
        return "true".to_owned();
    }
    let mut text = String::from("(and");
    for &index in chosen {
        text.push(' ');
        text.push_str(&terms[index]);
    }
    text.push(')');
    text
}

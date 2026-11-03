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

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::rc::Rc;

use super::{
    BITS, MEMORY, Script, Strategy, expressions, modeled, registers_read, shape, unmodeled,
};
use crate::ir::smt::{Value, condition, constant, low, memory_value, memory_value_resolved};
use crate::ir::{Block, Cond, Expr, RegRef, Stmt};

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

/// One side's symbolic state within a block.
#[derive(Clone)]
struct Side {
    /// The prefix of the symbols for the registers' values on entry.
    entry: &'static str,
    /// Registers the block's invariants make equal on the two sides on
    /// entry, which both sides read as one symbol.
    shared: Rc<BTreeSet<u16>>,
    registers: BTreeMap<u16, String>,
    memory: String,
    /// The definedness of everything this side computed so far.
    defined: String,
    /// What both sides know of the one memory they share.
    facts: Rc<Facts>,
}

/// Facts of the memory both sides of a block share.
#[derive(Default)]
struct Facts {
    /// A Boolean of the script that holds of every fact so far.
    known: RefCell<String>,
    /// The memories calls left that keep bytes of the frame.
    layers: RefCell<Vec<Layer>>,
}

/// The memory a call leaves, which keeps the bytes of the memory before it
/// that both sides' stack pointers place at `bound` or more past them.
struct Layer {
    memory: String,
    inner: String,
    stack: (String, String),
    bound: String,
}

impl Side {
    fn new(
        entry: &'static str,
        shared: &Rc<BTreeSet<u16>>,
        memory: &str,
        facts: &Rc<Facts>,
    ) -> Self {
        Self {
            entry,
            shared: Rc::clone(shared),
            registers: BTreeMap::new(),
            memory: memory.to_owned(),
            defined: "true".to_owned(),
            facts: Rc::clone(facts),
        }
    }

    /// What the side's statements so far assume: their definedness, and
    /// what both sides know of the memory.
    fn premise(&self) -> String {
        let known = self.facts.known.borrow();
        if known.is_empty() {
            self.defined.clone()
        } else {
            format!("(and {} {known})", self.defined)
        }
    }

    /// For each byte `expr` loads from a memory a call left, that the
    /// memory holds the byte the memory before the call held, where the
    /// call keeps it: the definition of the layer, at the bytes read.
    fn layer_facts(&self, script: &mut Script, expr: &Expr) {
        if self.facts.layers.borrow().is_empty() {
            return;
        }
        let mut loads = Vec::new();
        collect_loads(expr, &mut loads);
        for (addr, width) in loads {
            if opaque_any(addr) {
                continue;
            }
            let address = memory_value(addr, &self.registers, &self.memory).term;
            let mut facts = Vec::new();
            for byte in 0..u64::from(width) {
                let at = format!("(bvadd {address} {})", constant(byte));
                for layer in self.facts.layers.borrow().iter() {
                    facts.push(format!(
                        "(=> (and (bvsge (bvsub {at} {}) {bound}) (bvsge (bvsub {at} {}) {bound})) \
                         (= (select {} {at}) (select {} {at})))",
                        layer.stack.0,
                        layer.stack.1,
                        layer.memory,
                        layer.inner,
                        bound = layer.bound,
                    ));
                }
            }
            let mut known = self.facts.known.borrow_mut();
            let conjunction = format!("(and {} {})", known_or_true(&known), facts.join(" "));
            *known = script.define("Bool", conjunction);
        }
    }

    fn term(&mut self, script: &mut Script, index: u16) -> String {
        if let Some(term) = self.registers.get(&index) {
            return term.clone();
        }
        let name = if self.shared.contains(&index) {
            format!("s{index}")
        } else {
            format!("{}{index}", self.entry)
        };
        script.declare(&name, BITS);
        self.registers.insert(index, name.clone());
        name
    }

    fn read(&mut self, script: &mut Script, expr: &Expr) -> Value {
        let mut read = BTreeSet::new();
        registers_read(expr, &mut read);
        for index in read {
            self.term(script, index);
        }
        self.layer_facts(script, expr);
        memory_value(expr, &self.registers, &self.memory)
    }

    fn assume(&mut self, script: &mut Script, defined: &str) {
        if defined != "(and true )" && defined != "true" {
            self.defined = script.define("Bool", format!("(and {} {defined})", self.defined));
        }
    }

    fn set(&mut self, dest: RegRef, term: &str) {
        self.registers
            .insert(dest.index, low(term, u32::from(dest.width)));
    }

    fn assign(&mut self, script: &mut Script, dest: RegRef, value: &Expr) {
        let mut read = BTreeSet::new();
        registers_read(value, &mut read);
        for index in read {
            self.term(script, index);
        }
        self.layer_facts(script, value);
        // Each undefined value is any value, independently; an operation the
        // solver does not model is one function of its arguments on both
        // sides.
        let mut unmodeled = Vec::new();
        opaque(value, &mut unmodeled);
        let mut operands: Vec<(&Expr, String)> = Vec::new();
        for node in unmodeled {
            let Expr::Apply { op, args } = node else {
                unreachable!("an unmodeled operation is an application");
            };
            let term = if *op == crate::ir::Operation::Undefined {
                script.havoc(BITS)
            } else {
                let terms: Vec<String> = args
                    .iter()
                    .map(|arg| {
                        let resolved: Vec<(&Expr, &str)> = operands
                            .iter()
                            .map(|(node, term)| (*node, term.as_str()))
                            .collect();
                        let arg =
                            memory_value_resolved(arg, &self.registers, &self.memory, &resolved);
                        self.assume(script, &arg.defined);
                        arg.term
                    })
                    .collect();
                script.function(*op, &terms)
            };
            operands.push((node, term));
        }
        let resolved: Vec<(&Expr, &str)> = operands
            .iter()
            .map(|(node, term)| (*node, term.as_str()))
            .collect();
        let value = memory_value_resolved(value, &self.registers, &self.memory, &resolved);
        self.assume(script, &value.defined);
        let term = script.define(BITS, value.term);
        self.set(dest, &term);
    }

    fn store(&mut self, script: &mut Script, addr: &str, value: &str, width: u8) {
        let address = script.define(BITS, addr.to_owned());
        let stored = script.define(BITS, value.to_owned());
        let mut memory = self.memory.clone();
        for byte in 0..width {
            let first = u32::from(byte) * 8;
            memory = format!(
                "(store {memory} (bvadd {address} {}) ((_ extract {} {first}) {stored}))",
                constant(u64::from(byte)),
                first + 7,
            );
        }
        self.memory = script.define(MEMORY, memory);
    }
}

/// A way out of a block into another, with both sides' states there.
struct Edge {
    target: usize,
    /// When the original side takes it.
    path: String,
    /// Each candidate invariant of the target, in these states.
    holds: Vec<String>,
    /// Each register of the original side, then of the rewritten side, and
    /// the memory, in these states.
    exit: Vec<String>,
}

/// Both sides of one block, run from the entry states.
struct Run {
    script: Script,
    /// Each candidate invariant, in the entry states.
    assumed: Vec<String>,
    edges: Vec<Edge>,
    /// What each obligation compares, and the assertion that it differs.
    obligations: Vec<(String, String)>,
}

/// Equations between an expression of the original function, evaluated by
/// its side, and one of the rewritten function, evaluated by the other.
type Candidate = (Expr, Expr);

/// Checks `application` with one solver process.
#[must_use]
pub fn check(application: &Application, rlimit: u64, bit_level_rlimit: u64) -> Verdict {
    let Some(mut solver) = Solver::start() else {
        return Verdict::Unknown {
            what: String::new(),
            reason: "z3 unavailable".to_owned(),
        };
    };
    check_with(application, &mut solver, rlimit, bit_level_rlimit)
}

/// The same, with where the solver work went.
#[must_use]
pub fn check_measured(
    application: &Application,
    rlimit: u64,
    bit_level_rlimit: u64,
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
    let verdict = check_with(application, &mut solver, rlimit, bit_level_rlimit);
    (verdict, std::mem::take(&mut solver.stats))
}

fn check_with(
    application: &Application,
    solver: &mut Solver,
    rlimit: u64,
    bit_level_rlimit: u64,
) -> Verdict {
    // A callee that may write any memory makes queries the solver decides
    // quickly; keeping a private frame's bytes across calls is for an
    // application that model refutes, the refutation saying nothing while
    // the frame's bytes are kept out.
    let coarse = Application {
        private_frame: None,
        ..application.clone()
    };
    let verdict = check_model(&coarse, solver, rlimit, bit_level_rlimit);
    if application.private_frame.is_some() && matches!(verdict, Verdict::NotProved { .. }) {
        return check_model(application, solver, rlimit, bit_level_rlimit);
    }
    verdict
}

fn check_model(
    application: &Application,
    solver: &mut Solver,
    rlimit: u64,
    bit_level_rlimit: u64,
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
    // candidates were dropped undecided, for each of them; the bit-level
    // one, the slowest, for what the Horn query, bounded in time, leaves
    // after them. Replies are kept, so a stage asks again only what was
    // undecided.
    let strategies = [
        (Strategy::WordLevel, rlimit),
        (Strategy::Bounded, bit_level_rlimit),
    ];
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
    let mut horned = solver.horn(
        &horn(application, &first.checked, &product.registers),
        bit_level_rlimit,
    );
    let mut failed = failed;
    if matches!(horned, Reply::Unknown(_)) && first.undecided {
        let full = product.equations(
            application,
            solver,
            &[
                (Strategy::WordLevel, rlimit),
                (Strategy::Bounded, bit_level_rlimit),
                (Strategy::BitLevel, bit_level_rlimit),
            ],
            true,
        );
        let Some(again) = full.failed else {
            return Verdict::Proved;
        };
        failed = again;
        horned = solver.horn(
            &horn(application, &full.checked, &product.registers),
            bit_level_rlimit,
        );
    }
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
        // `all` asks with every strategy rather than the first; `split`
        // says an undecided reply is asked again in parts.
        let mut ask = |solver: &mut Solver, query: &str, names: &[&str], all: bool, split: bool| {
            let mut reply = Reply::Unknown("no strategy".to_owned());
            for &(strategy, rlimit) in &strategies[..if all { strategies.len() } else { 1 }] {
                if !matches!(reply, Reply::Unknown(_)) {
                    break;
                }
                reply = solver.values(query, rlimit, strategy, names);
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
                                state: solver.model(&symbols),
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

/// What both sides' entry symbols in `script` meet when the function starts:
/// the two sides agree, and the entry facts of the application hold.
fn starting(
    application: &Application,
    registers: &[u16],
    shared: &BTreeSet<u16>,
    script: &mut Script,
) -> String {
    let mut name = |prefix: &str, register: u16| {
        let name = if shared.contains(&register) {
            format!("s{register}")
        } else {
            format!("{prefix}{register}")
        };
        script.declare(&name, BITS);
        name
    };
    let mut facts = Vec::new();
    for &register in registers {
        let (before, after) = (name("b", register), name("a", register));
        if before != after {
            facts.push(format!("(= {before} {after})"));
        }
        if application.narrow_registers.contains(&register) {
            facts.push(format!("(bvult {before} {})", constant(1 << 32)));
        }
        if application.narrow_stack == Some(register) {
            facts.push(format!(
                "(bvuge {before} {}) (bvule {before} {})",
                constant(NARROW_STACK.0),
                constant(NARROW_STACK.1)
            ));
        }
        if let Some((sp, alignment)) = application.entry_alignment
            && sp == register
        {
            facts.push(format!(
                "(= (bvand {before} {}) {})",
                constant(alignment.modulus - 1),
                constant(alignment.residue)
            ));
        }
        if let Some(&(low, high)) = application.entry_pairs.get(&register) {
            let (low, high) = (name("b", low), name("b", high));
            facts.push(format!(
                "(= {before} (bvor (bvshl {high} {}) (bvand {low} {})))",
                constant(32),
                constant(0xffff_ffff)
            ));
        }
    }
    format!("(and true {})", facts.join(" "))
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

/// The wall-clock bound on one Horn query, in seconds, besides its
/// resource limit, which the Horn engine does not always heed. A query it
/// stops leaves the verdict the equations gave, so the bound can only turn a
/// proof into that verdict, never the other way.
const HORN_SECONDS: u32 = 120;
/// The memory bound on one Horn query, in megabytes.
const HORN_MEGABYTES: u32 = 2048;

/// Whether the Horn clauses `text` are satisfiable, asked of a z3 process of
/// their own that the bounds above stop.
fn solve_horn(text: &str, rlimit: u64) -> Reply {
    let Ok(mut child) = Command::new("z3")
        .args([
            "-in",
            "-smt2",
            &format!("-T:{HORN_SECONDS}"),
            &format!("-memory:{HORN_MEGABYTES}"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    else {
        return Reply::Unknown("z3 unavailable".to_owned());
    };
    let written = child
        .stdin
        .take()
        .map(|mut stdin| write!(stdin, "(set-option :rlimit {rlimit})\n{text}"));
    let Ok(output) = child.wait_with_output() else {
        return Reply::Unknown("z3 did not finish".to_owned());
    };
    if !matches!(written, Some(Ok(()))) {
        return Reply::Unknown("z3 stopped reading the clauses".to_owned());
    }
    let answer = String::from_utf8_lossy(&output.stdout);
    match answer.trim() {
        "sat" => Reply::Sat(Vec::new()),
        "unsat" => Reply::Unsat,
        other => Reply::Unknown(other.to_owned()),
    }
}

/// Horn clauses over one relation per block, between the two sides' states
/// on entry, that are satisfiable exactly when some invariant keeps every
/// obligation from failing. A relation takes only the registers and memory
/// its block, or a block after it, still reads; the inferred invariants,
/// inductive already, hold in every clause from their block, and a register
/// they make equal on the two sides is one argument.
fn horn(application: &Application, checked: &[Checked], registers: &[u16]) -> String {
    let position: BTreeMap<usize, usize> = checked
        .iter()
        .enumerate()
        .map(|(position, block)| (block.index, position))
        .collect();
    // Each argument a block's relation may take: its entry symbol, and
    // where it sits in an edge's exit states.
    let arguments: Vec<Vec<(String, usize)>> = checked
        .iter()
        .map(|block| {
            let mut all = Vec::new();
            for (number, &register) in registers.iter().enumerate() {
                if block.shared.contains(&register) {
                    all.push((format!("s{register}"), number));
                } else {
                    all.push((format!("b{register}"), number));
                    all.push((format!("a{register}"), registers.len() + number));
                }
            }
            all.push(("m".to_owned(), 2 * registers.len()));
            all
        })
        .collect();
    let entries = |block: usize, texts: &[&str]| -> BTreeSet<String> {
        let (_, free) = checked[block].run.script.needed(texts);
        arguments[block]
            .iter()
            .filter(|(name, _)| free.contains(name.as_str()))
            .map(|(name, _)| name.clone())
            .collect()
    };
    let mut needed: Vec<BTreeSet<String>> = checked
        .iter()
        .enumerate()
        .map(|(block, checked)| {
            let mut texts: Vec<&str> = checked
                .run
                .obligations
                .iter()
                .map(|(_, mismatch)| mismatch.as_str())
                .collect();
            texts.extend(checked.run.edges.iter().map(|edge| edge.path.as_str()));
            entries(block, &texts)
        })
        .collect();
    loop {
        let mut grew = false;
        for block in 0..checked.len() {
            for edge in &checked[block].run.edges {
                let target = position[&edge.target];
                let exits: Vec<&str> = arguments[target]
                    .iter()
                    .filter(|(name, _)| needed[target].contains(name))
                    .map(|(_, at)| edge.exit[*at].as_str())
                    .collect();
                for name in entries(block, &exits) {
                    grew |= needed[block].insert(name);
                }
            }
        }
        if !grew {
            break;
        }
    }
    let taken = |block: usize| -> Vec<&(String, usize)> {
        arguments[block]
            .iter()
            .filter(|(name, _)| needed[block].contains(name))
            .collect()
    };
    let relation = |block: usize, values: &[&str]| -> String {
        if values.is_empty() {
            format!("block{}", checked[block].index)
        } else {
            format!("(block{} {})", checked[block].index, values.join(" "))
        }
    };
    let sort = |name: &str| if name == "m" { MEMORY } else { BITS };

    let mut text = String::from("(set-logic HORN)\n");
    let mut clauses = String::new();
    let mut counts = false;
    for (block, checked_block) in checked.iter().enumerate() {
        let sorts: Vec<&str> = taken(block).iter().map(|(name, _)| sort(name)).collect();
        writeln!(
            text,
            "(declare-fun block{} ({}) Bool)",
            checked_block.index,
            sorts.join(" ")
        )
        .expect("writing to a String");
    }
    let first = position[&0];
    let start: Vec<String> = taken(first)
        .iter()
        .map(|(name, _)| {
            if name == "m" {
                "m".to_owned()
            } else {
                application.entry(name[1..].parse().expect("a register's entry symbol"))
            }
        })
        .collect();
    let mut entered = BTreeSet::new();
    for name in taken(first)
        .iter()
        .map(|(name, _)| name)
        .filter(|name| *name != "m")
    {
        let index: u16 = name[1..].parse().expect("a register's entry symbol");
        match application.entry_pairs.get(&index) {
            Some((low, high)) => entered.extend([*low, *high]),
            None => {
                entered.insert(index);
            }
        }
    }
    let names: Vec<String> = entered.iter().map(|index| format!("r{index}")).collect();
    let mut variables: BTreeSet<&str> = names.iter().map(String::as_str).collect();
    let mut bounds = application.entry_facts(entered.iter());
    if let Some(sp) = application.narrow_stack
        && variables.contains(format!("r{sp}").as_str())
    {
        bounds.push(format!(
            "(bvuge r{sp} {}) (bvule r{sp} {})",
            constant(NARROW_STACK.0),
            constant(NARROW_STACK.1)
        ));
    }
    if let Some((sp, alignment)) = application.entry_alignment
        && variables.contains(format!("r{sp}").as_str())
    {
        bounds.push(format!(
            "(= (bvand r{sp} {}) {})",
            constant(alignment.modulus - 1),
            constant(alignment.residue)
        ));
    }
    let bound = if bounds.is_empty() {
        String::new()
    } else {
        format!("(and {})", bounds.join(" "))
    };
    variables.insert("m");
    let declared: String = variables
        .iter()
        .map(|name| format!("({name} {})", sort(name)))
        .collect();
    let head = relation(first, &start.iter().map(String::as_str).collect::<Vec<_>>());
    if bound.is_empty() {
        writeln!(clauses, "(assert (forall ({declared}) {head}))")
    } else {
        writeln!(
            clauses,
            "(assert (forall ({declared}) (=> {bound} {head})))"
        )
    }
    .expect("writing to a String");
    for (block, checked_block) in checked.iter().enumerate() {
        let names: Vec<&str> = taken(block).iter().map(|(name, _)| name.as_str()).collect();
        let held: Vec<&str> = checked_block
            .invariant
            .iter()
            .filter(|invariant| {
                let (_, free) = checked_block.run.script.needed(&[invariant.as_str()]);
                free.iter()
                    .all(|name| needed[block].contains(*name) || !is_entry(name))
            })
            .map(String::as_str)
            .collect();
        let holds = format!("(and {} {})", relation(block, &names), held.join(" "));
        for edge in &checked_block.run.edges {
            let target = position[&edge.target];
            let values: Vec<&str> = taken(target)
                .iter()
                .map(|(_, at)| edge.exit[*at].as_str())
                .collect();
            let body = format!("(and {holds} {})", edge.path);
            let (clause, count) = checked_block
                .run
                .script
                .clause(&body, &relation(target, &values));
            clauses.push_str(&clause);
            counts |= count;
        }
        for (_, mismatch) in &checked_block.run.obligations {
            let body = format!("(and {holds} {mismatch})");
            let (clause, count) = checked_block.run.script.clause(&body, "false");
            clauses.push_str(&clause);
            counts |= count;
        }
    }
    if counts {
        text.push_str(super::COUNT8);
    }
    text.push_str(&clauses);
    text.push_str("(check-sat)\n");
    text
}

/// Whether `name` is a symbol for a value a block enters with.
fn is_entry(name: &str) -> bool {
    name == "m"
        || ["s", "b", "a"].iter().any(|prefix| {
            name.strip_prefix(prefix).is_some_and(|rest| {
                !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit())
            })
        })
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

/// The candidates in the states both sides start the function in.
fn start(application: &Application, candidates: &[Candidate]) -> (Script, Vec<String>) {
    let mut script = Script::default();
    script.declare("m", MEMORY);
    let unshared = Rc::new(BTreeSet::new());
    let facts = Rc::new(Facts::default());
    let mut before = Side::new("r", &unshared, "m", &facts);
    let mut after = Side::new("r", &unshared, "m", &facts);
    // A narrow register enters zero-extended, and a parameter in two
    // registers as the two joined.
    let mut entered = BTreeSet::new();
    for candidate in candidates {
        for expr in [&candidate.0, &candidate.1] {
            registers_read(expr, &mut entered);
        }
    }
    let mut halves: BTreeSet<u16> = application
        .entry_pairs
        .values()
        .flat_map(|(low, high)| [*low, *high])
        .collect();
    halves.extend(entered.iter().copied());
    for &register in &halves {
        if application.narrow_registers.contains(&register) {
            let low = format!("q{register}");
            script.declare(&low, "(_ BitVec 32)");
            let term = script.define(BITS, format!("((_ zero_extend 32) {low})"));
            before.registers.insert(register, term.clone());
            after.registers.insert(register, term);
        }
    }
    for (&parameter, &(low, high)) in &application.entry_pairs {
        let low = before.term(&mut script, low);
        let high = before.term(&mut script, high);
        let term = script.define(
            BITS,
            format!(
                "(bvor (bvshl {high} {}) (bvand {low} {}))",
                constant(32),
                constant(0xffff_ffff)
            ),
        );
        before.registers.insert(parameter, term.clone());
        after.registers.insert(parameter, term);
    }
    let holds = candidates
        .iter()
        .map(|candidate| instantiate(&mut script, &mut before, &mut after, candidate))
        .collect();
    (script, holds)
}

/// The candidate's truth as a named Boolean.
fn instantiate(
    script: &mut Script,
    before: &mut Side,
    after: &mut Side,
    (old, new): &Candidate,
) -> String {
    let old = before.read(script, old);
    let new = after.read(script, new);
    script.define("Bool", format!("(= {} {})", old.term, new.term))
}

fn observable(stmt: &Stmt) -> bool {
    !matches!(stmt, Stmt::Assign { .. })
}

/// The obligation that the two values agree wherever the original's is
/// defined, given `path`: the assertion that they do not.
/// Whether the two values are the same terms with the same definedness, so
/// that they cannot differ.
fn same(before: &Side, after: &Side, old: &Value, new: &Value) -> bool {
    old.term == new.term && old.defined == new.defined && before.defined == after.defined
}

fn differs(path: &str, before: &Side, after: &Side, old: &Value, new: &Value, bits: u32) -> String {
    format!(
        "(and {path} {} {} (or (not {}) (not {}) (not (= {} {}))))",
        before.premise(),
        old.defined,
        after.defined,
        new.defined,
        low(&old.term, bits),
        low(&new.term, bits)
    )
}

fn run(
    application: &Application,
    index: usize,
    blocks: &BTreeMap<u64, usize>,
    candidates: &[Candidate],
    registers: &[u16],
    shared: &Rc<BTreeSet<u16>>,
) -> Result<Run, &'static str> {
    let old = &application.before[index].stmts;
    let new = &application.after[index].stmts;
    let mut script = Script::default();
    script.declare("m", MEMORY);
    for &register in registers {
        script.declare(&format!("b{register}"), BITS);
        script.declare(&format!("a{register}"), BITS);
    }
    let facts = Rc::new(Facts::default());
    let mut before = Side::new("b", shared, "m", &facts);
    let mut after = Side::new("a", shared, "m", &facts);
    let assumed = {
        let (mut before, mut after) = (before.clone(), after.clone());
        candidates
            .iter()
            .map(|candidate| instantiate(&mut script, &mut before, &mut after, candidate))
            .collect()
    };
    let old_observable: Vec<usize> = (0..old.len()).filter(|&i| observable(&old[i])).collect();
    let new_observable: Vec<usize> = (0..new.len()).filter(|&i| observable(&new[i])).collect();
    if old_observable.len() != new_observable.len() {
        return Err("statements other than assignments were added or removed");
    }
    let target = |address: u64| {
        blocks
            .get(&address)
            .copied()
            .ok_or("a branch leaves the blocks")
    };
    let mut edges: Vec<(usize, String, Side, Side)> = Vec::new();
    let mut obligations = Vec::new();
    let mut path = "true".to_owned();
    let (mut next_old, mut next_new) = (0, 0);
    let mut ended = false;
    for (&at_old, &at_new) in old_observable.iter().zip(&new_observable) {
        for stmt in &old[next_old..at_old] {
            if let Stmt::Assign { dest, value, .. } = stmt {
                before.assign(&mut script, *dest, value);
            }
        }
        for stmt in &new[next_new..at_new] {
            if let Stmt::Assign { dest, value, .. } = stmt {
                after.assign(&mut script, *dest, value);
            }
        }
        (next_old, next_new) = (at_old + 1, at_new + 1);
        let (old_stmt, new_stmt) = (&old[at_old], &new[at_new]);
        if shape(old_stmt) != shape(new_stmt) {
            return Err("a statement other than an assignment changed kind");
        }
        if expressions(old_stmt)
            .into_iter()
            .chain(expressions(new_stmt))
            .any(|expr| unmodeled(expr).is_some())
        {
            return Err("a statement other than an assignment applies an unmodeled operation");
        }
        let what = format!("{old_stmt:?} became {new_stmt:?}");
        let compare = |script: &mut Script,
                       before: &mut Side,
                       after: &mut Side,
                       old: &Expr,
                       new: &Expr,
                       bits: u32,
                       obligations: &mut Vec<(String, String)>|
         -> (Value, Value) {
            let old = before.read(script, old);
            let new = after.read(script, new);
            if !same(before, after, &old, &new) {
                obligations.push((
                    what.clone(),
                    differs(&path, before, after, &old, &new, bits),
                ));
            }
            (old, new)
        };
        match (old_stmt, new_stmt) {
            (
                Stmt::Store {
                    addr, value, width, ..
                },
                Stmt::Store {
                    addr: new_addr,
                    value: new_value,
                    ..
                },
            ) => {
                let (a, b) = compare(
                    &mut script,
                    &mut before,
                    &mut after,
                    addr,
                    new_addr,
                    64,
                    &mut obligations,
                );
                let (v, w) = compare(
                    &mut script,
                    &mut before,
                    &mut after,
                    value,
                    new_value,
                    u32::from(*width) * 8,
                    &mut obligations,
                );
                before.assume(&mut script, &a.defined);
                before.assume(&mut script, &v.defined);
                after.assume(&mut script, &b.defined);
                after.assume(&mut script, &w.defined);
                before.store(&mut script, &a.term, &v.term, *width);
                after.store(&mut script, &b.term, &w.term, *width);
            }
            (
                Stmt::Brif {
                    cond,
                    lhs,
                    rhs,
                    target: address,
                    ..
                },
                Stmt::Brif {
                    cond: new_cond,
                    lhs: new_lhs,
                    rhs: new_rhs,
                    ..
                },
            ) => {
                let old = truth(&mut script, &mut before, *cond, lhs, rhs);
                let new = truth(&mut script, &mut after, *new_cond, new_lhs, new_rhs);
                if !same(&before, &after, &old, &new) {
                    obligations.push((
                        what.clone(),
                        format!(
                            "(and {path} {} {} (or (not {}) (not {}) (not (= {} {}))))",
                            before.premise(),
                            old.defined,
                            after.defined,
                            new.defined,
                            old.term,
                            new.term
                        ),
                    ));
                }
                before.assume(&mut script, &old.defined);
                after.assume(&mut script, &new.defined);
                let taken = script.define("Bool", format!("(and {path} {})", old.term));
                edges.push((target(*address)?, taken, before.clone(), after.clone()));
                path = script.define("Bool", format!("(and {path} (not {}))", old.term));
            }
            (
                Stmt::Br {
                    target: Some(address),
                    ..
                },
                Stmt::Br { .. },
            ) => {
                edges.push((
                    target(*address)?,
                    path.clone(),
                    before.clone(),
                    after.clone(),
                ));
                ended = true;
            }
            (
                Stmt::Switch {
                    index,
                    cases,
                    default,
                    ..
                },
                Stmt::Switch {
                    index: new_index, ..
                },
            ) => {
                let (old, new) = compare(
                    &mut script,
                    &mut before,
                    &mut after,
                    index,
                    new_index,
                    64,
                    &mut obligations,
                );
                before.assume(&mut script, &old.defined);
                after.assume(&mut script, &new.defined);
                let mut others = Vec::new();
                for (number, address) in cases {
                    let test = format!("(= {} {})", old.term, constant(*number as u64));
                    let taken = script.define("Bool", format!("(and {path} {test})"));
                    edges.push((target(*address)?, taken, before.clone(), after.clone()));
                    others.push(format!("(not {test})"));
                }
                if let Some(address) = default {
                    let taken = script.define("Bool", format!("(and {path} {})", others.join(" ")));
                    edges.push((target(*address)?, taken, before.clone(), after.clone()));
                }
                ended = true;
            }
            (
                Stmt::Ret { value, .. },
                Stmt::Ret {
                    value: new_value, ..
                },
            ) => {
                if let Some(bits) = application.returned {
                    compare(
                        &mut script,
                        &mut before,
                        &mut after,
                        value,
                        new_value,
                        bits,
                        &mut obligations,
                    );
                }
                ended = true;
            }
            (Stmt::Trap { .. }, Stmt::Trap { .. }) => {
                obligations.push((
                    what.clone(),
                    format!("(and {path} {} (not {}))", before.premise(), after.defined),
                ));
                ended = true;
            }
            (Stmt::Call { .. }, Stmt::Call { .. }) => {
                let old_inputs = expressions(old_stmt);
                let new_inputs = expressions(new_stmt);
                for (old, new) in old_inputs.into_iter().zip(new_inputs) {
                    let (a, b) = compare(
                        &mut script,
                        &mut before,
                        &mut after,
                        old,
                        new,
                        64,
                        &mut obligations,
                    );
                    before.assume(&mut script, &a.defined);
                    after.assume(&mut script, &b.defined);
                }
                let mut read: BTreeSet<u16> = old_stmt.unnamed_call_reads().into_iter().collect();
                read.extend(old_stmt.declared_call_reads());
                let mut new_read: BTreeSet<u16> =
                    new_stmt.unnamed_call_reads().into_iter().collect();
                new_read.extend(new_stmt.declared_call_reads());
                read.extend(new_read);
                // A callee whose summary takes no result address does not
                // read the register that would carry one.
                if let Stmt::Call {
                    target: Some(target),
                    args: Some(_),
                    abi: None,
                    convention: crate::ir::Convention::Aapcs64,
                    ..
                } = old_stmt
                    && application.without_result_address.contains(target)
                {
                    read.remove(&8);
                }
                for register in read {
                    let old = before.term(&mut script, register);
                    let new = after.term(&mut script, register);
                    if old != new {
                        obligations.push((
                            format!("{what}: register {register} read by the callee"),
                            format!("(and {path} {} (not (= {old} {new})))", before.premise()),
                        ));
                    }
                }
                let changed = old_stmt.call_clobbers();
                let mut fresh: BTreeMap<u16, String> = changed
                    .iter()
                    .map(|&register| (register, script.havoc(BITS)))
                    .collect();
                if let Stmt::Call {
                    target: Some(target),
                    ..
                } = old_stmt
                    && application.narrow_results.contains(target)
                    && !old_stmt.has_declared_call()
                    && let Some(primary) = old_stmt.primary_call_output()
                    && let Some(value) = fresh.get_mut(&primary.register)
                {
                    let low = script.havoc("(_ BitVec 32)");
                    *value = script.define(BITS, format!("((_ zero_extend 32) {low})"));
                }
                // A changed register an output takes leaves its value in the
                // output's destination alone, as the passes read a call: the
                // register itself keeps what it held.
                let routed: BTreeSet<u16> = old_stmt
                    .call_outputs()
                    .iter()
                    .map(|output| output.register)
                    .collect();
                for side in [&mut before, &mut after] {
                    let outputs: Vec<(RegRef, String)> = old_stmt
                        .call_outputs()
                        .iter()
                        .map(|output| {
                            let value = fresh
                                .get(&output.register)
                                .cloned()
                                .unwrap_or_else(|| side.term(&mut script, output.register));
                            (output.dest, value)
                        })
                        .collect();
                    for (&register, term) in &fresh {
                        if !routed.contains(&register) {
                            side.registers.insert(register, term.clone());
                        }
                    }
                    for (dest, value) in outputs {
                        side.set(dest, &value);
                    }
                }
                let memory = script.havoc(MEMORY);
                let owned = match (application.private_frame, old_stmt) {
                    (
                        Some(sp),
                        Stmt::Call {
                            args: Some(args),
                            convention,
                            ..
                        },
                    ) if *convention != crate::ir::Convention::GoAbi0 => {
                        convention.stack_arguments().map(|start| {
                            (
                                sp,
                                start - convention.pushed_by_call() + 8 * args.len() as i64,
                            )
                        })
                    }
                    _ => None,
                };
                // What the callee may write of the frame starts at the stack
                // pointer and ends past its stack arguments, at most eight
                // bytes each; the rest of a frame no address of which is
                // handed out keeps its bytes. A pass may move the stack
                // pointer of one side, so a byte is kept only where both
                // sides' stack pointers place it past the arguments. The two
                // sides enter each block with one memory and store the same
                // bytes in pairs, so the callee is given one memory and
                // leaves one.
                if let Some((sp, owned)) = owned {
                    let stack = (before.term(&mut script, sp), after.term(&mut script, sp));
                    before.facts.layers.borrow_mut().push(Layer {
                        memory: memory.clone(),
                        inner: before.memory.clone(),
                        stack,
                        bound: constant(owned as u64),
                    });
                }
                before.memory.clone_from(&memory);
                after.memory = memory;
            }
            (
                Stmt::Machine {
                    inputs, outputs, ..
                },
                Stmt::Machine {
                    inputs: new_inputs, ..
                },
            ) => {
                for (old, new) in inputs.iter().zip(new_inputs) {
                    let (a, b) = compare(
                        &mut script,
                        &mut before,
                        &mut after,
                        old,
                        new,
                        64,
                        &mut obligations,
                    );
                    before.assume(&mut script, &a.defined);
                    after.assume(&mut script, &b.defined);
                }
                for output in outputs {
                    let term = script.havoc(BITS);
                    before.set(*output, &term);
                    after.set(*output, &term);
                }
                let memory = script.havoc(MEMORY);
                before.memory.clone_from(&memory);
                after.memory = memory;
            }
            (Stmt::BrifFlags { .. }, _) => return Err("a branch on flags"),
            (Stmt::Br { target: None, .. }, _) => return Err("a branch to an unknown place"),
            (Stmt::BrIndirect { .. }, _) => return Err("an indirect branch"),
            (Stmt::Unsupported { .. }, _) => return Err("an unsupported statement"),
            _ => unreachable!("statements of one shape are of one kind"),
        }
        if ended {
            break;
        }
    }
    if !ended {
        for stmt in &old[next_old..] {
            if let Stmt::Assign { dest, value, .. } = stmt {
                before.assign(&mut script, *dest, value);
            }
        }
        for stmt in &new[next_new..] {
            if let Stmt::Assign { dest, value, .. } = stmt {
                after.assign(&mut script, *dest, value);
            }
        }
        if index + 1 < application.before.len() {
            edges.push((index + 1, path, before, after));
        }
    }
    for (target, path, before, after) in &edges {
        if after.defined != "true" && after.defined != before.defined {
            obligations.push((
                format!(
                    "the rewritten side is defined on the way to block {:#x}",
                    application.before[*target].start
                ),
                format!("(and {path} {} (not {}))", before.premise(), after.defined),
            ));
        }
    }
    let edges = edges
        .into_iter()
        .map(|(target, path, mut before, mut after)| {
            let holds = candidates
                .iter()
                .map(|candidate| instantiate(&mut script, &mut before, &mut after, candidate))
                .collect();
            let mut exit: Vec<String> = Vec::with_capacity(2 * registers.len() + 1);
            for side in [&mut before, &mut after] {
                for &register in registers {
                    exit.push(side.term(&mut script, register));
                }
            }
            exit.push(before.memory.clone());
            let path = format!("(and {path} {})", before.premise());
            Edge {
                target,
                path,
                holds,
                exit,
            }
        })
        .collect();
    Ok(Run {
        script,
        assumed,
        edges,
        obligations,
    })
}

fn truth(script: &mut Script, side: &mut Side, cond: Cond, lhs: &Expr, rhs: &Expr) -> Value {
    let a = side.read(script, lhs);
    let b = side.read(script, rhs);
    let bits = crate::ir::semantics::operand_width(lhs, rhs);
    Value {
        term: condition(cond, &a.term, &b.term, bits),
        defined: format!("(and {} {})", a.defined, b.defined),
    }
}

/// Every register equal on the two sides, and an equation for each pair of
/// differing subexpressions at one place of statements paired the way the
/// blocks list them, when what they read is still what the block entered
/// with.
fn candidates(application: &Application) -> Vec<Candidate> {
    let mut registers = BTreeSet::new();
    // The widths each register is read, written, stored or masked at: a
    // register whose low bits alone agree on the two sides is equal at those
    // widths only.
    let mut widths: BTreeMap<u16, BTreeSet<u8>> = BTreeMap::new();
    for block in application.before.iter().chain(&application.after) {
        for stmt in &block.stmts {
            for expr in expressions(stmt) {
                registers_read(expr, &mut registers);
                register_widths(expr, &mut widths);
            }
            match stmt {
                Stmt::Assign { dest, .. } => {
                    registers.insert(dest.index);
                    widths.entry(dest.index).or_default().insert(dest.width);
                }
                // A narrow store keeps the low bits of what it stores.
                Stmt::Store { value, width, .. } if *width < 8 => {
                    demand(value, width * 8, &mut widths);
                }
                Stmt::Call { .. } => {
                    registers.extend(stmt.unnamed_call_reads());
                    registers.extend(stmt.declared_call_reads());
                }
                _ => {}
            }
        }
    }
    // The low bits of a register an assignment demands are demanded of
    // what it is assigned.
    loop {
        let before = widths.clone();
        for block in application.before.iter().chain(&application.after) {
            for stmt in &block.stmts {
                if let Stmt::Assign { dest, value, .. } = stmt {
                    for &bits in before.get(&dest.index).into_iter().flatten() {
                        demand(value, bits, &mut widths);
                    }
                }
            }
        }
        if widths == before {
            break;
        }
    }
    let mut found: Vec<Candidate> = registers
        .into_iter()
        .map(|index| (Expr::reg(index, 64), Expr::reg(index, 64)))
        .collect();
    let narrow = |a: u16, b: u16| -> Vec<u8> {
        let none = BTreeSet::new();
        let (x, y) = (
            widths.get(&a).unwrap_or(&none),
            widths.get(&b).unwrap_or(&none),
        );
        x.union(y).copied().filter(|&width| width < 64).collect()
    };
    for &index in widths.keys() {
        for width in narrow(index, index) {
            found.push((Expr::reg(index, width), Expr::reg(index, width)));
        }
    }
    let mut seen: BTreeSet<String> = found.iter().map(|pair| format!("{pair:?}")).collect();
    for (old, new) in application.before.iter().zip(&application.after) {
        let paired: Vec<(&Stmt, &Stmt)> = if old.stmts.len() == new.stmts.len() {
            old.stmts.iter().zip(&new.stmts).collect()
        } else {
            let old: Vec<&Stmt> = old.stmts.iter().filter(|stmt| observable(stmt)).collect();
            let new: Vec<&Stmt> = new.stmts.iter().filter(|stmt| observable(stmt)).collect();
            old.into_iter().zip(new).collect()
        };
        let mut written = (BTreeSet::new(), BTreeSet::new());
        let mut stored = (false, false);
        for (old_stmt, new_stmt) in paired {
            // Two assignments at one place may assign different registers,
            // as a renaming does: the registers may then correspond too.
            let assignments = match (old_stmt, new_stmt) {
                (Stmt::Assign { dest: a, .. }, Stmt::Assign { dest: b, .. }) => {
                    if a.index != b.index {
                        let pair = (Expr::reg(a.index, 64), Expr::reg(b.index, 64));
                        if seen.insert(format!("{pair:?}")) {
                            found.push(pair);
                        }
                    }
                    true
                }
                _ => false,
            };
            if assignments || shape(old_stmt) == shape(new_stmt) {
                for (a, b) in expressions(old_stmt).into_iter().zip(expressions(new_stmt)) {
                    differences(a, b, &written, stored, &mut |pair| {
                        if seen.insert(format!("{pair:?}")) {
                            found.push(pair);
                        }
                    });
                }
            }
            for (stmt, written, stored) in [
                (old_stmt, &mut written.0, &mut stored.0),
                (new_stmt, &mut written.1, &mut stored.1),
            ] {
                writes(stmt, written, stored);
            }
        }
    }
    // Registers a copy or a renaming joins, on the two sides.
    let mut renamed: Vec<(u16, u16)> = found
        .iter()
        .filter_map(|pair| match pair {
            (Expr::Reg { index: a, .. }, Expr::Reg { index: b, .. }) if a != b => Some((*a, *b)),
            _ => None,
        })
        .collect();
    let mut push = |pair: Candidate| {
        if unmodeled(&pair.0).is_none()
            && unmodeled(&pair.1).is_none()
            && seen.insert(format!("{pair:?}"))
        {
            found.push(pair);
        }
    };
    // An assignment one side has and the other lacks: its register on that
    // side may hold what its expression computes on the other.
    let mut copies: Vec<(u16, u16)> = Vec::new();
    for (old, new) in application.before.iter().zip(&application.after) {
        let texts = |block: &Block| -> BTreeSet<String> {
            block.stmts.iter().map(|stmt| format!("{stmt:?}")).collect()
        };
        let (old_texts, new_texts) = (texts(old), texts(new));
        for (block, others, original) in [(old, &new_texts, true), (new, &old_texts, false)] {
            for stmt in &block.stmts {
                let Stmt::Assign { dest, value, .. } = stmt else {
                    continue;
                };
                if let Expr::Reg { index, .. } = value {
                    copies.push((dest.index, *index));
                }
                if others.contains(&format!("{stmt:?}")) {
                    continue;
                }
                let register = Expr::reg(dest.index, 64);
                let value = kept(value.clone(), dest.width);
                push(if original {
                    (register, value)
                } else {
                    (value, register)
                });
            }
        }
    }
    renamed.extend(copies);
    let mut classes: BTreeMap<u16, u16> = BTreeMap::new();
    fn root(classes: &BTreeMap<u16, u16>, mut register: u16) -> u16 {
        while let Some(&parent) = classes.get(&register) {
            if parent == register {
                break;
            }
            register = parent;
        }
        register
    }
    for (a, b) in renamed {
        let (a, b) = (root(&classes, a), root(&classes, b));
        classes.entry(a).or_insert(a);
        classes.entry(b).or_insert(b);
        if a != b {
            classes.insert(a.max(b), a.min(b));
        }
    }
    let mut members: BTreeMap<u16, Vec<u16>> = BTreeMap::new();
    for &register in classes.keys() {
        members
            .entry(root(&classes, register))
            .or_default()
            .push(register);
    }
    for class in members.values() {
        for &a in class {
            for &b in class {
                if a != b {
                    push((Expr::reg(a, 64), Expr::reg(b, 64)));
                    for width in narrow(a, b) {
                        push((Expr::reg(a, width), Expr::reg(b, width)));
                    }
                }
            }
        }
    }
    found
}

fn register_widths(expr: &Expr, widths: &mut BTreeMap<u16, BTreeSet<u8>>) {
    match expr {
        Expr::Reg { index, width } => {
            widths.entry(*index).or_default().insert(*width);
        }
        // A mask of the low bits reads those bits alone.
        Expr::Bin {
            op: crate::ir::BinOp::And,
            lhs,
            rhs,
        } => {
            if let Expr::Const(mask) = rhs.as_ref()
                && let Some(bits) = [8u8, 16, 32]
                    .into_iter()
                    .find(|&bits| *mask == (1u64 << bits) - 1)
            {
                demand(lhs, bits, widths);
            }
        }
        _ => {}
    }
    for child in crate::ir::visit::children(expr) {
        register_widths(child, widths);
    }
}

/// Records that only the low `bits` of `expr` matter, for each register
/// whose low `bits` alone decide them: through the operations whose low
/// bits depend on the low bits of their operands alone.
fn demand(expr: &Expr, bits: u8, widths: &mut BTreeMap<u16, BTreeSet<u8>>) {
    use crate::ir::BinOp;
    match expr {
        Expr::Reg { index, width } if bits < *width => {
            widths.entry(*index).or_default().insert(bits);
        }
        Expr::Bin {
            op: BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::And | BinOp::Or | BinOp::Xor,
            lhs,
            rhs,
        } => {
            demand(lhs, bits, widths);
            demand(rhs, bits, widths);
        }
        Expr::Bin {
            op: BinOp::Shl,
            lhs,
            ..
        } => demand(lhs, bits, widths),
        _ => {}
    }
}

/// `value` cut to the bits a destination of `width` bits keeps.
fn kept(value: Expr, width: u8) -> Expr {
    if width >= 64 {
        return value;
    }
    Expr::Bin {
        op: crate::ir::BinOp::And,
        lhs: Box::new(value),
        rhs: Box::new(Expr::Const((1u64 << width) - 1)),
    }
}

fn writes(stmt: &Stmt, written: &mut BTreeSet<u16>, stored: &mut bool) {
    match stmt {
        Stmt::Assign { dest, .. } => {
            written.insert(dest.index);
        }
        Stmt::Store { .. } => *stored = true,
        Stmt::Call { .. } => {
            written.extend(stmt.call_clobbers());
            written.extend(stmt.call_outputs().iter().map(|output| output.dest.index));
            *stored = true;
        }
        Stmt::Machine { outputs, .. } => {
            written.extend(outputs.iter().map(|output| output.index));
            *stored = true;
        }
        _ => {}
    }
}

fn differences(
    old: &Expr,
    new: &Expr,
    written: &(BTreeSet<u16>, BTreeSet<u16>),
    stored: (bool, bool),
    found: &mut impl FnMut(Candidate),
) {
    if old == new {
        return;
    }
    let entry = |expr: &Expr, written: &BTreeSet<u16>, stored: bool| {
        let mut read = BTreeSet::new();
        registers_read(expr, &mut read);
        read.is_disjoint(written) && !(stored && loads(expr)) && unmodeled(expr).is_none()
    };
    if entry(old, &written.0, stored.0) && entry(new, &written.1, stored.1) {
        found((old.clone(), new.clone()));
    }
    let (old_children, new_children) = (
        crate::ir::visit::children(old),
        crate::ir::visit::children(new),
    );
    if std::mem::discriminant(old) == std::mem::discriminant(new)
        && old_children.len() == new_children.len()
    {
        for (a, b) in old_children.into_iter().zip(new_children) {
            differences(a, b, written, stored, found);
        }
    }
}

/// The applications in `expr` of operations the solver does not model,
/// each after those among its arguments.
fn opaque<'a>(expr: &'a Expr, found: &mut Vec<&'a Expr>) {
    for child in crate::ir::visit::children(expr) {
        opaque(child, found);
    }
    if let Expr::Apply { op, .. } = expr
        && !modeled(*op)
    {
        found.push(expr);
    }
}

/// The address and width of each load in `expr`.
fn collect_loads<'a>(expr: &'a Expr, found: &mut Vec<(&'a Expr, u8)>) {
    if let Expr::Load { addr, width, .. } = expr {
        found.push((addr, *width));
    }
    for child in crate::ir::visit::children(expr) {
        collect_loads(child, found);
    }
}

/// Whether `expr` applies an operation the solver does not model.
fn opaque_any(expr: &Expr) -> bool {
    let mut found = Vec::new();
    opaque(expr, &mut found);
    !found.is_empty()
}

fn known_or_true(known: &str) -> &str {
    if known.is_empty() { "true" } else { known }
}

fn loads(expr: &Expr) -> bool {
    matches!(expr, Expr::Load { .. }) || crate::ir::visit::children(expr).into_iter().any(loads)
}

#[derive(Clone)]
enum Reply {
    Unsat,
    /// Satisfiable, with the requested Booleans' values in the model.
    Sat(Vec<bool>),
    Unknown(String),
}

/// A z3 process answering one query at a time.
pub(crate) struct Solver {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    stats: Stats,
    /// The replies to queries asked already, by query, strategy and limit.
    replies: HashMap<(String, Strategy, u64), Reply>,
    /// The replies to Horn clauses solved already, by clauses and limit.
    horns: HashMap<(String, u64), Reply>,
}

/// Where checking an application spent its solver work.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub blocks: usize,
    pub candidates: usize,
    /// Passes of the invariant inference over every edge.
    pub rounds: usize,
    /// Queries, undecided answers and seconds, by strategy: word-level,
    /// bounded, bit-level, Horn.
    pub queries: [usize; 4],
    pub undecided: [usize; 4],
    pub seconds: [f64; 4],
}

impl Solver {
    pub(crate) fn start() -> Option<Self> {
        let mut child = Command::new("z3")
            .args(["-in", "-smt2"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .ok()?;
        let stdin = child.stdin.take()?;
        let stdout = BufReader::new(child.stdout.take()?);
        Some(Self {
            child,
            stdin,
            stdout,
            stats: Stats::default(),
            replies: HashMap::new(),
            horns: HashMap::new(),
        })
    }

    fn line(&mut self) -> String {
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read z3 answer");
        line.trim().to_owned()
    }

    /// The parenthesized answer to a request, possibly over several lines.
    fn list(&mut self, request: &str) -> String {
        writeln!(self.stdin, "{request}").expect("write SMT request");
        self.stdin.flush().expect("flush SMT request");
        let mut text = String::new();
        let mut depth = 0i32;
        loop {
            let line = self.line();
            depth += line.matches('(').count() as i32 - line.matches(')').count() as i32;
            text.push_str(&line);
            text.push(' ');
            if depth <= 0 {
                break;
            }
        }
        text.trim().to_owned()
    }

    /// The reply to `query`, with the Booleans `names` in a model. A query
    /// asked again, its names being part of it, gets the reply it got.
    fn values(&mut self, query: &str, rlimit: u64, strategy: Strategy, names: &[&str]) -> Reply {
        let key = (format!("{query}{}", names.join(" ")), strategy, rlimit);
        if let Some(reply) = self.replies.get(&key) {
            return reply.clone();
        }
        let started = std::time::Instant::now();
        let reply = self.answer(query, rlimit, strategy, names);
        let kind = match strategy {
            Strategy::WordLevel => 0,
            Strategy::Bounded => 1,
            Strategy::BitLevel => 2,
        };
        self.stats.queries[kind] += 1;
        self.stats.seconds[kind] += started.elapsed().as_secs_f64();
        if matches!(reply, Reply::Unknown(_)) {
            self.stats.undecided[kind] += 1;
        }
        self.replies.insert(key, reply.clone());
        reply
    }

    /// Whether the Horn clauses `text` are satisfiable. Clauses solved
    /// already, such as when equations checked again keep the same ones,
    /// get the reply they got.
    fn horn(&mut self, text: &str, rlimit: u64) -> Reply {
        let key = (text.to_owned(), rlimit);
        if let Some(reply) = self.horns.get(&key) {
            return reply.clone();
        }
        let started = std::time::Instant::now();
        let reply = solve_horn(text, rlimit);
        self.stats.queries[3] += 1;
        self.stats.seconds[3] += started.elapsed().as_secs_f64();
        if matches!(reply, Reply::Unknown(_)) {
            self.stats.undecided[3] += 1;
        }
        self.horns.insert(key, reply.clone());
        reply
    }

    fn answer(&mut self, query: &str, rlimit: u64, strategy: Strategy, names: &[&str]) -> Reply {
        writeln!(
            self.stdin,
            "(reset)\n(set-option :rlimit {rlimit})\n{query}{}",
            strategy.check()
        )
        .expect("write SMT query");
        self.stdin.flush().expect("flush SMT query");
        let answer = self.line();
        match answer.as_str() {
            "unsat" => Reply::Unsat,
            "sat" if names.is_empty() => Reply::Sat(Vec::new()),
            "sat" => {
                let text = self.list(&format!("(get-value ({}))", names.join(" ")));
                let values: Vec<bool> = text
                    .split(|c: char| c.is_whitespace() || c == '(' || c == ')')
                    .filter_map(|token| match token {
                        "true" => Some(true),
                        "false" => Some(false),
                        _ => None,
                    })
                    .collect();
                assert_eq!(values.len(), names.len(), "z3 values: {text}");
                Reply::Sat(values)
            }
            answer => {
                let answer = answer.to_owned();
                let reason = self.list("(get-info :reason-unknown)");
                Reply::Unknown(format!("{answer} {reason}"))
            }
        }
    }

    fn model(&mut self, symbols: &[String]) -> String {
        if symbols.is_empty() {
            return String::new();
        }
        self.list(&format!("(get-value ({}))", symbols.join(" ")))
    }
}

impl Drop for Solver {
    fn drop(&mut self) {
        let _ = writeln!(self.stdin, "(exit)");
        let _ = self.stdin.flush();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::smt::raw_bin;
    use crate::ir::{BinOp, Convention};

    fn assign(index: u16, value: Expr) -> Stmt {
        Stmt::Assign {
            at: None,
            dest: RegRef { index, width: 64 },
            value,
        }
    }

    fn r(index: u16) -> Expr {
        Expr::reg(index, 64)
    }

    fn plus(index: u16, k: i64) -> Expr {
        raw_bin(BinOp::Add, r(index), Expr::Const(k as u64))
    }

    fn block(start: u64, stmts: Vec<Stmt>) -> Block {
        Block { start, stmts }
    }

    fn br(target: u64) -> Stmt {
        Stmt::Br {
            at: None,
            target: Some(target),
        }
    }

    fn ret(value: Expr) -> Stmt {
        Stmt::Ret { at: None, value }
    }

    fn store(addr: Expr, value: Expr) -> Stmt {
        Stmt::Store {
            at: None,
            addr,
            value,
            width: 8,
        }
    }

    fn call() -> Stmt {
        Stmt::Call {
            kind: crate::ir::CallKind::Invoke,
            target: Some(0x2000),
            through: None,
            convention: Convention::SysV,
            args: Some(Vec::new()),
            floats_named: false,
            abi: None,
            outputs: Vec::new(),
            clobbers: None,
            via: None,
            at: None,
        }
    }

    fn application(before: Vec<Block>, after: Vec<Block>) -> Application {
        Application {
            site: "test",
            tag: String::new(),
            index: 0,
            before,
            after,
            landing_pads: false,
            narrow_stack: None,
            private_frame: None,
            entry_alignment: None,
            returned: Some(64),
            narrow_results: BTreeSet::new(),
            without_result_address: BTreeSet::new(),
            narrow_registers: BTreeSet::new(),
            entry_pairs: BTreeMap::new(),
        }
    }

    fn verdict(before: Vec<Block>, after: Vec<Block>) -> Verdict {
        check(&application(before, after), 50_000_000, 1_000_000_000)
    }

    fn returning(before: Vec<Block>, after: Vec<Block>, returned: Option<u32>) -> Verdict {
        assuming(before, after, returned, BTreeSet::new())
    }

    fn assuming(
        before: Vec<Block>,
        after: Vec<Block>,
        returned: Option<u32>,
        narrow_results: BTreeSet<u64>,
    ) -> Verdict {
        check(
            &Application {
                site: "test",
                tag: String::new(),
                index: 0,
                before,
                after,
                landing_pads: false,
                narrow_stack: None,
                private_frame: None,
                entry_alignment: None,
                returned,
                narrow_results,
                without_result_address: BTreeSet::new(),
                narrow_registers: BTreeSet::new(),
                entry_pairs: BTreeMap::new(),
            },
            50_000_000,
            1_000_000_000,
        )
    }

    fn aligned(
        before: Vec<Block>,
        after: Vec<Block>,
        alignment: Option<crate::ir::EntryAlignment>,
    ) -> Verdict {
        check(
            &Application {
                site: "test",
                tag: String::new(),
                index: 0,
                before,
                after,
                landing_pads: false,
                narrow_stack: None,
                private_frame: None,
                entry_alignment: alignment.map(|alignment| (4, alignment)),
                returned: Some(64),
                narrow_results: BTreeSet::new(),
                without_result_address: BTreeSet::new(),
                narrow_registers: BTreeSet::new(),
                entry_pairs: BTreeMap::new(),
            },
            50_000_000,
            1_000_000_000,
        )
    }

    fn not_proved(verdict: &Verdict) -> bool {
        matches!(verdict, Verdict::NotProved { .. })
    }

    #[test]
    fn functions_are_compared_across_blocks_and_loops() {
        if Command::new("z3").arg("-version").output().is_err() {
            eprintln!("SKIP product validation: z3 unavailable");
            return;
        }
        // A register renamed throughout the function.
        let renamed = |k| {
            verdict(
                vec![
                    block(0, vec![assign(10, plus(0, 1)), br(1)]),
                    block(1, vec![ret(r(10))]),
                ],
                vec![
                    block(0, vec![assign(11, plus(0, k)), br(1)]),
                    block(1, vec![ret(r(11))]),
                ],
            )
        };
        assert_eq!(renamed(1), Verdict::Proved);
        assert!(not_proved(&renamed(2)));

        // A frame address taken from another register, through a loop that
        // keeps both registers or moves one of them.
        let framed = |step: Expr| {
            let body = |addr: Expr| {
                block(
                    1,
                    vec![
                        store(addr, r(0)),
                        assign(5, step.clone()),
                        Stmt::Brif {
                            at: None,
                            cond: Cond::Ne,
                            lhs: r(1),
                            rhs: Expr::Const(0),
                            target: 1,
                        },
                    ],
                )
            };
            verdict(
                vec![
                    block(0, vec![assign(5, plus(4, 8))]),
                    body(plus(5, -12)),
                    block(2, vec![ret(Expr::Const(0))]),
                ],
                vec![
                    block(0, vec![assign(5, plus(4, 8))]),
                    body(plus(4, -4)),
                    block(2, vec![ret(Expr::Const(0))]),
                ],
            )
        };
        assert_eq!(framed(r(5)), Verdict::Proved);
        assert!(not_proved(&framed(plus(5, 1))));

        // A constant another block assigned, or a value it did not fix.
        let constant = |value: Expr| {
            verdict(
                vec![
                    block(0, vec![assign(0, value.clone()), br(1)]),
                    block(1, vec![ret(r(0))]),
                ],
                vec![
                    block(0, vec![assign(0, value), br(1)]),
                    block(1, vec![ret(Expr::Const(7))]),
                ],
            )
        };
        assert_eq!(constant(Expr::Const(7)), Verdict::Proved);
        assert!(not_proved(&constant(r(1))));

        // A call keeps rbx (3) and may change r9 (9).
        let across = |register| {
            verdict(
                vec![
                    block(0, vec![assign(register, Expr::Const(5)), call()]),
                    block(1, vec![ret(r(register))]),
                ],
                vec![
                    block(0, vec![assign(register, Expr::Const(5)), call()]),
                    block(1, vec![ret(Expr::Const(5))]),
                ],
            )
        };
        assert_eq!(across(3), Verdict::Proved);
        assert!(not_proved(&across(9)));

        // A register a call changes keeps its value when an output takes
        // the change, and does not when none does.
        let routed = |outputs: Vec<crate::ir::CallOutput>| {
            let mut changing = call();
            if let Stmt::Call {
                outputs: taken,
                clobbers,
                ..
            } = &mut changing
            {
                *taken = outputs;
                let mut changed = crate::ir::Registers::default();
                changed.insert(0);
                *clobbers = Some(changed);
            }
            verdict(
                vec![
                    block(0, vec![assign(10, r(0)), changing.clone()]),
                    block(1, vec![ret(r(10))]),
                ],
                vec![block(0, vec![changing]), block(1, vec![ret(r(0))])],
            )
        };
        assert_eq!(
            routed(vec![crate::ir::CallOutput {
                register: 0,
                dest: RegRef {
                    index: 11,
                    width: 64
                },
            }]),
            Verdict::Proved
        );
        assert!(not_proved(&routed(Vec::new())));

        // A dropped assignment no one reads, and one the return reads.
        let dropped = |read| {
            verdict(
                vec![block(0, vec![assign(2, plus(0, 1)), ret(r(read))])],
                vec![block(0, vec![ret(r(read))])],
            )
        };
        assert_eq!(dropped(0), Verdict::Proved);
        assert!(not_proved(&dropped(2)));

        // An undefined value for bits nothing reads after, and for bits the
        // return reads.
        let undefined = |kept: u64| {
            let merged = |high: Expr| {
                raw_bin(
                    BinOp::Or,
                    raw_bin(BinOp::And, high, Expr::Const(!0xff)),
                    raw_bin(BinOp::And, r(1), Expr::Const(0xff)),
                )
            };
            let returned = ret(raw_bin(BinOp::And, r(2), Expr::Const(kept)));
            verdict(
                vec![block(0, vec![assign(2, merged(r(2))), returned.clone()])],
                vec![block(
                    0,
                    vec![
                        assign(
                            2,
                            merged(Expr::apply(crate::ir::Operation::Undefined, Vec::new())),
                        ),
                        returned,
                    ],
                )],
            )
        };
        assert_eq!(undefined(0xff), Verdict::Proved);
        assert!(not_proved(&undefined(0x1ff)));

        // High bits dropped that only a narrow store in another block would
        // read, and a store wide enough to read them.
        let stored = |width: u8| {
            let low = raw_bin(BinOp::And, r(1), Expr::Const(1));
            let merged = raw_bin(
                BinOp::Or,
                raw_bin(BinOp::And, r(10), Expr::Const(!0xff)),
                low.clone(),
            );
            let tail = block(
                1,
                vec![
                    Stmt::Store {
                        at: None,
                        addr: Expr::Const(0x1000),
                        value: r(10),
                        width,
                    },
                    ret(Expr::Const(0)),
                ],
            );
            verdict(
                vec![block(0, vec![assign(10, merged), br(1)]), tail.clone()],
                vec![block(0, vec![assign(10, low), br(1)]), tail],
            )
        };
        assert_eq!(stored(1), Verdict::Proved);
        assert!(not_proved(&stored(2)));

        // An operation the solver does not model, applied to the same
        // arguments on both sides of a renaming, and to others.
        let crc = |second: u16| {
            Expr::apply(
                crate::ir::Operation::Crc32 {
                    castagnoli: true,
                    bits: 32,
                },
                vec![r(1), r(second)],
            )
        };
        let unmodeled = |second: u16| {
            verdict(
                vec![
                    block(0, vec![assign(5, crc(3)), br(1)]),
                    block(1, vec![ret(r(5))]),
                ],
                vec![
                    block(0, vec![assign(6, crc(second)), br(1)]),
                    block(1, vec![ret(r(6))]),
                ],
            )
        };
        assert_eq!(unmodeled(3), Verdict::Proved);
        assert!(not_proved(&unmodeled(4)));

        // A frame slot read back past a call, which leaves the frame above
        // its stack arguments alone when no address of the frame is handed
        // out; and a slot among those arguments.
        let kept = |private: bool, offset: u64, args: usize| {
            let slot = raw_bin(BinOp::Add, r(4), Expr::Const(offset));
            let mut calling = call();
            if let Stmt::Call { args: taken, .. } = &mut calling {
                *taken = Some(vec![Expr::Const(0); args]);
            }
            let store = Stmt::Store {
                at: None,
                addr: slot.clone(),
                value: Expr::Const(7),
                width: 8,
            };
            let mut application = application(
                vec![block(
                    0,
                    vec![
                        store.clone(),
                        calling.clone(),
                        assign(
                            2,
                            Expr::Load {
                                addr: Box::new(slot),
                                width: 8,
                                signed: false,
                            },
                        ),
                        ret(r(2)),
                    ],
                )],
                vec![block(
                    0,
                    vec![store, calling, assign(2, Expr::Const(7)), ret(r(2))],
                )],
            );
            application.private_frame = private.then_some(4);
            check(&application, 50_000_000, 1_000_000_000)
        };
        assert_eq!(kept(true, 16, 0), Verdict::Proved);
        assert_eq!(kept(true, 16, 2), Verdict::Proved);
        assert!(not_proved(&kept(false, 16, 0)));
        assert!(not_proved(&kept(true, 0, 1)));
        assert!(not_proved(&kept(true, 16, 3)));

        // The same slot past a call, with the stack pointer of the rewritten
        // side left where the function entered, as a settled frame has it:
        // its slot lies among the call's arguments by that side's count.
        let settled = {
            let slot = |offset| raw_bin(BinOp::Add, r(4), Expr::Const(offset));
            let load = |offset| Expr::Load {
                addr: Box::new(slot(offset)),
                width: 8,
                signed: false,
            };
            let store = |offset| Stmt::Store {
                at: None,
                addr: slot(offset),
                value: Expr::Const(7),
                width: 8,
            };
            let mut calling = call();
            if let Stmt::Call { args, .. } = &mut calling {
                *args = Some(vec![Expr::Const(0); 3]);
            }
            let mut application = application(
                vec![block(
                    0,
                    vec![
                        assign(4, plus(4, -32)),
                        store(40),
                        calling.clone(),
                        assign(2, load(40)),
                        assign(4, plus(4, 32)),
                        ret(r(2)),
                    ],
                )],
                vec![block(
                    0,
                    vec![store(8), calling, assign(2, load(8)), ret(r(2))],
                )],
            );
            application.private_frame = Some(4);
            check(&application, 50_000_000, 1_000_000_000)
        };
        assert_eq!(settled, Verdict::Proved);

        // A mask a branch in another block makes redundant: a range the
        // equations cannot state, found from the Horn clauses; and the same
        // mask after a branch that says nothing of the sign.
        let masked = |cond| {
            let low = Expr::reg(1, 32);
            let quarter = raw_bin(BinOp::Shr, low.clone(), Expr::Const(2));
            let entry = block(
                0,
                vec![Stmt::Brif {
                    at: None,
                    cond,
                    lhs: low,
                    rhs: Expr::Const(0),
                    target: 2,
                }],
            );
            verdict(
                vec![
                    entry.clone(),
                    block(
                        1,
                        vec![ret(raw_bin(
                            BinOp::And,
                            quarter.clone(),
                            Expr::Const(0x1fff_ffff),
                        ))],
                    ),
                    block(2, vec![ret(Expr::Const(0))]),
                ],
                vec![
                    entry,
                    block(1, vec![ret(quarter)]),
                    block(2, vec![ret(Expr::Const(0))]),
                ],
            )
        };
        assert_eq!(masked(Cond::Lt), Verdict::Proved);
        assert!(not_proved(&masked(Cond::Eq)));

        // Rounding the stack pointer down is a known move when the entry
        // alignment fixes it, and not otherwise.
        let rounded = |alignment| {
            aligned(
                vec![
                    block(
                        0,
                        vec![
                            assign(4, plus(4, -8)),
                            assign(
                                4,
                                raw_bin(BinOp::And, r(4), Expr::Const(16u64.wrapping_neg())),
                            ),
                            store(r(4), r(0)),
                            br(1),
                        ],
                    ),
                    block(1, vec![ret(Expr::Const(0))]),
                ],
                vec![
                    block(0, vec![store(plus(4, -8), r(0)), br(1)]),
                    block(1, vec![ret(Expr::Const(0))]),
                ],
                alignment,
            )
        };
        let called = crate::ir::EntryAlignment {
            residue: 8,
            modulus: 16,
        };
        assert_eq!(rounded(Some(called)), Verdict::Proved);
        assert!(not_proved(&rounded(None)));
        assert!(not_proved(&rounded(Some(crate::ir::EntryAlignment {
            residue: 0,
            modulus: 16
        }))));

        // Registers renamed through a loop, every assignment with them; and
        // a renaming one use misses.
        let loop_with = |count: u16, index: u16, missed: bool| {
            vec![
                block(0, vec![assign(count, r(6)), assign(index, Expr::Const(0))]),
                block(
                    1,
                    vec![
                        store(plus(index, 0), r(7)),
                        assign(index, plus(index, 1)),
                        Stmt::Brif {
                            at: None,
                            cond: Cond::Ne,
                            lhs: r(count),
                            rhs: r(if missed { 2 } else { index }),
                            target: 1,
                        },
                    ],
                ),
                block(2, vec![ret(r(index))]),
            ]
        };
        assert_eq!(
            verdict(loop_with(1, 2, false), loop_with(4352, 4353, false)),
            Verdict::Proved
        );
        assert!(not_proved(&verdict(
            loop_with(1, 2, false),
            loop_with(4352, 4353, true)
        )));

        // A result cut to the return type's width, which keeps its low byte
        // only, or nothing at all.
        let cut = |returned| {
            returning(
                vec![block(0, vec![ret(r(0))])],
                vec![block(
                    0,
                    vec![ret(raw_bin(BinOp::And, r(0), Expr::Const(0xff)))],
                )],
                returned,
            )
        };
        assert_eq!(cut(Some(8)), Verdict::Proved);
        assert_eq!(cut(None), Verdict::Proved);
        assert!(not_proved(&cut(Some(16))));

        // A call's result taken as 32 bits, as the callee's summary finds it.
        let result = |narrow: BTreeSet<u64>| {
            let mut calling = call();
            if let Stmt::Call { outputs, .. } = &mut calling {
                *outputs = vec![crate::ir::CallOutput {
                    register: 0,
                    dest: RegRef {
                        index: 10,
                        width: 64,
                    },
                }];
            }
            assuming(
                vec![block(0, vec![calling.clone()]), block(1, vec![ret(r(10))])],
                vec![
                    block(0, vec![calling]),
                    block(
                        1,
                        vec![ret(raw_bin(BinOp::And, r(10), Expr::Const(0xffff_ffff)))],
                    ),
                ],
                Some(64),
                narrow,
            )
        };
        assert_eq!(result([0x2000].into()), Verdict::Proved);
        assert!(not_proved(&result(BTreeSet::new())));

        // A parameter in two 32-bit registers bound to one variable, which
        // holds what they do only when the registers enter 32 bits wide.
        let paired = |narrow: BTreeSet<u16>| {
            let joined = || raw_bin(BinOp::Or, raw_bin(BinOp::Shl, r(1), Expr::Const(32)), r(0));
            check(
                &Application {
                    site: "test",
                    tag: String::new(),
                    index: 0,
                    before: vec![block(0, vec![ret(joined())])],
                    after: vec![block(
                        0,
                        vec![
                            assign(0, raw_bin(BinOp::And, r(5000), Expr::Const(0xffff_ffff))),
                            assign(1, raw_bin(BinOp::Shr, r(5000), Expr::Const(32))),
                            ret(joined()),
                        ],
                    )],
                    landing_pads: false,
                    narrow_stack: None,
                    private_frame: None,
                    entry_alignment: None,
                    returned: Some(64),
                    narrow_results: BTreeSet::new(),
                    without_result_address: BTreeSet::new(),
                    narrow_registers: narrow,
                    entry_pairs: [(5000, (0, 1))].into(),
                },
                50_000_000,
                1_000_000_000,
            )
        };
        assert_eq!(paired([0, 1].into()), Verdict::Proved);
        assert!(not_proved(&paired(BTreeSet::new())));

        // A 32-bit frame address computed in 32 bits, which a 64-bit one
        // equals only on an architecture whose stack is 32 bits wide.
        let framed32 = |narrow: bool| {
            let low = |expr: Expr| raw_bin(BinOp::And, expr, Expr::Const(0xffff_ffff));
            check(
                &Application {
                    site: "test",
                    tag: String::new(),
                    index: 0,
                    before: vec![block(
                        0,
                        vec![
                            store(low(raw_bin(BinOp::Add, low(r(13)), Expr::Const(16))), r(1)),
                            ret(Expr::Const(0)),
                        ],
                    )],
                    after: vec![block(
                        0,
                        vec![store(plus(13, 16), r(1)), ret(Expr::Const(0))],
                    )],
                    landing_pads: false,
                    narrow_stack: narrow.then_some(13),
                    private_frame: None,
                    entry_alignment: None,
                    returned: Some(64),
                    narrow_results: BTreeSet::new(),
                    without_result_address: BTreeSet::new(),
                    narrow_registers: if narrow { [13].into() } else { BTreeSet::new() },
                    entry_pairs: BTreeMap::new(),
                },
                50_000_000,
                1_000_000_000,
            )
        };
        assert_eq!(framed32(true), Verdict::Proved);
        assert!(not_proved(&framed32(false)));

        // A value left in x8 before a call that reads it as a result address
        // unless the callee's summary says it takes none.
        let scratch = |without: BTreeSet<u64>| {
            let mut calling = call();
            if let Stmt::Call { convention, .. } = &mut calling {
                *convention = Convention::Aapcs64;
            }
            let mut application = Application {
                site: "test",
                tag: String::new(),
                index: 0,
                before: vec![
                    block(0, vec![assign(8, Expr::Const(5)), calling.clone()]),
                    block(1, vec![ret(Expr::Const(0))]),
                ],
                after: vec![block(0, vec![calling]), block(1, vec![ret(Expr::Const(0))])],
                landing_pads: false,
                narrow_stack: None,
                private_frame: None,
                entry_alignment: None,
                returned: Some(64),
                narrow_results: BTreeSet::new(),
                without_result_address: BTreeSet::new(),
                narrow_registers: BTreeSet::new(),
                entry_pairs: BTreeMap::new(),
            };
            application.without_result_address = without;
            check(&application, 50_000_000, 1_000_000_000)
        };
        assert_eq!(scratch([0x2000].into()), Verdict::Proved);
        assert!(not_proved(&scratch(BTreeSet::new())));

        // A division by zero the rewrite makes, though nothing reads it.
        assert!(not_proved(&verdict(
            vec![block(0, vec![ret(r(0))])],
            vec![block(
                0,
                vec![
                    assign(2, raw_bin(BinOp::DivU, r(0), Expr::Const(0))),
                    ret(r(0))
                ]
            )],
        )));
    }

    #[test]
    fn narrow_stores_and_masks_suggest_equations_of_their_bits() {
        let stored = Stmt::Store {
            at: None,
            addr: Expr::Const(0x1000),
            value: r(10),
            width: 1,
        };
        let masked = ret(raw_bin(BinOp::And, r(1), Expr::Const(0xffff)));
        let blocks = vec![block(0, vec![stored, masked])];
        let found = candidates(&application(blocks.clone(), blocks));
        for (index, width) in [(10, 8), (1, 16)] {
            assert!(
                found.contains(&(Expr::reg(index, width), Expr::reg(index, width))),
                "r{index} at {width} bits: {found:?}"
            );
        }
        assert!(!found.contains(&(Expr::reg(10, 16), Expr::reg(10, 16))));

        // Through the operations whose low bits their operands' low bits
        // decide, and through assignments; not through a shift right.
        let blocks = vec![block(
            0,
            vec![
                assign(2, raw_bin(BinOp::And, r(0), Expr::Const(0xffff_ffff))),
                assign(5, raw_bin(BinOp::Shr, r(6), Expr::Const(8))),
                Stmt::Store {
                    at: None,
                    addr: Expr::Const(0x1000),
                    value: raw_bin(BinOp::Add, r(2), raw_bin(BinOp::Xor, r(3), r(5))),
                    width: 1,
                },
                ret(Expr::Const(0)),
            ],
        )];
        let found = candidates(&application(blocks.clone(), blocks));
        for index in [0, 2, 3, 5] {
            assert!(
                found.contains(&(Expr::reg(index, 8), Expr::reg(index, 8))),
                "r{index} at 8 bits: {found:?}"
            );
        }
        assert!(!found.contains(&(Expr::reg(6, 8), Expr::reg(6, 8))));
    }
}

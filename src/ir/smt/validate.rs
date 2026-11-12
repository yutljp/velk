//! Checks each rewrite as decompilation applies it: the rewritten statement
//! must mean what the original meant, given the statements before it in its
//! block, for every register value and memory content at the block's entry.
//!
//! Passes record one obligation per changed statement. Nothing is recorded
//! until [`begin`] is called, so a build with the `validate` feature behaves
//! like any other until a caller asks for the checks.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

mod integer;
pub mod product;

use super::{Value, condition, constant, low, memory_value};
use crate::ir::{Cond, Expr, FunctionIr, LaneOp, Operation, Stmt};

static ENABLED: AtomicBool = AtomicBool::new(false);
static STATE: Mutex<State> = Mutex::new(State {
    tag: String::new(),
    obligations: Vec::new(),
    seen: Vec::new(),
    skipped: BTreeMap::new(),
    unchanged: 0,
    applied: 0,
    unchecked: BTreeSet::new(),
    fingerprints: BTreeMap::new(),
    revisit: None,
    applications: Vec::new(),
});

struct State {
    tag: String,
    obligations: Vec<Obligation>,
    /// Hashes of the queries recorded since the last [`take`], sorted.
    seen: Vec<u64>,
    skipped: BTreeMap<(&'static str, String), usize>,
    unchanged: usize,
    /// Pass applications since the last [`begin`] or [`revisit`].
    applied: usize,
    unchecked: BTreeSet<usize>,
    fingerprints: BTreeMap<usize, u64>,
    /// The applications to record whole, instead of checking statements.
    revisit: Option<BTreeSet<usize>>,
    applications: Vec<product::Application>,
}

/// One rewritten statement and the query whose satisfiability would show
/// that the rewrite changed what the statement does.
#[derive(Debug, Clone)]
pub struct Obligation {
    /// The pass and rewrite that changed the statement.
    pub site: &'static str,
    /// What the caller of [`begin`] named the work being decompiled.
    pub tag: String,
    pub before: String,
    pub after: String,
    /// The SMT-LIB declarations, definitions and assertion; [`solve`]
    /// adds the satisfiability check.
    pub query: String,
    /// The free bit-vector symbols of the query, for a counterexample.
    pub symbols: Vec<String>,
    /// The pass application that made the rewrite, as [`revisit`] takes it.
    pub application: usize,
}

/// What was recorded since the last [`take`].
#[derive(Debug, Default)]
pub struct Recorded {
    pub obligations: Vec<Obligation>,
    /// Rewrites that could not be checked, by site and reason.
    pub skipped: BTreeMap<(&'static str, String), usize>,
    /// Changed statements whose query repeated an earlier one.
    pub repeated: usize,
    /// Statements a pass visited without changing them.
    pub unchanged: usize,
    /// Applications with a rewrite the statement checks could not take.
    pub unchecked: BTreeSet<usize>,
    /// A hash of each changing application's function before and after.
    pub fingerprints: BTreeMap<usize, u64>,
    /// The applications [`revisit`] asked for.
    pub applications: Vec<product::Application>,
}

static REPEATED: AtomicUsize = AtomicUsize::new(0);

/// Starts recording, naming what is decompiled next in each obligation.
///
/// # Panics
///
/// When a thread recording before panicked.
pub fn begin(tag: &str) {
    let mut state = STATE.lock().expect("validation state");
    tag.clone_into(&mut state.tag);
    state.applied = 0;
    state.revisit = None;
    ENABLED.store(true, Ordering::SeqCst);
}

/// Starts recording the pass applications `wanted` whole, for the
/// whole-function check, when what is decompiled next repeats what was
/// decompiled after [`begin`] with the same tag.
///
/// # Panics
///
/// When a thread recording before panicked.
pub fn revisit(tag: &str, wanted: BTreeSet<usize>) {
    let mut state = STATE.lock().expect("validation state");
    tag.clone_into(&mut state.tag);
    state.applied = 0;
    state.revisit = Some(wanted);
    ENABLED.store(true, Ordering::SeqCst);
}

/// The low bits of a returned value the function keeps: those its return
/// type keeps, or fewer when every return reads one register at a narrower
/// width, which is the pass's choice of that type; none for `void`.
fn returned(ir: &FunctionIr) -> Option<u32> {
    let typed = match &ir.ret_type {
        crate::ir::CType::Void => return None,
        other => other.integer().map_or(64, |(bits, _)| bits.min(64)),
    };
    let mut widths = ir
        .blocks
        .iter()
        .filter_map(|block| match block.stmts.last() {
            Some(crate::ir::Stmt::Ret { value, .. }) => Some(match value {
                crate::ir::Expr::Reg { width, .. } => u32::from(*width),
                _ => 64,
            }),
            _ => None,
        });
    let first = widths.next();
    let narrowed = first.filter(|first| widths.all(|width| width == *first));
    Some(narrowed.map_or(typed, |narrowed| narrowed.min(typed)))
}

/// Stops recording and returns what was recorded.
///
/// # Panics
///
/// When a thread recording before panicked.
pub fn take() -> Recorded {
    ENABLED.store(false, Ordering::SeqCst);
    let mut state = STATE.lock().expect("validation state");
    state.seen.clear();
    Recorded {
        obligations: std::mem::take(&mut state.obligations),
        skipped: std::mem::take(&mut state.skipped),
        repeated: REPEATED.swap(0, Ordering::SeqCst),
        unchanged: std::mem::take(&mut state.unchanged),
        unchecked: std::mem::take(&mut state.unchecked),
        fingerprints: std::mem::take(&mut state.fingerprints),
        applications: std::mem::take(&mut state.applications),
    }
}

pub(crate) fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

fn skip(site: &'static str, reason: String) {
    let mut state = STATE.lock().expect("validation state");
    *state.skipped.entry((site, reason)).or_default() += 1;
    let application = state.applied;
    state.unchecked.insert(application);
}

fn fingerprint(before: &[crate::ir::Block], after: &[crate::ir::Block]) -> u64 {
    let mut hasher = std::hash::DefaultHasher::new();
    format!("{before:?}{after:?}").hash(&mut hasher);
    hasher.finish()
}

/// Runs the pass `site` on `ir` and records an obligation for each
/// statement it rewrote in place.
pub(crate) fn pass<R>(
    site: &'static str,
    ir: &mut FunctionIr,
    callees: &crate::passes::Callees,
    run: impl FnOnce(&mut FunctionIr) -> R,
) -> R {
    if !enabled() {
        return run(ir);
    }
    let before = ir.blocks.clone();
    let result = run(ir);
    let changed = format!("{:?}", before) != format!("{:?}", ir.blocks);
    let (application, revisiting) = {
        let mut state = STATE.lock().expect("validation state");
        state.applied += 1;
        let application = state.applied;
        if changed {
            state
                .fingerprints
                .insert(application, fingerprint(&before, &ir.blocks));
        }
        let revisiting = state.revisit.is_some();
        if changed
            && state
                .revisit
                .as_ref()
                .is_some_and(|wanted| wanted.contains(&application))
        {
            let tag = state.tag.clone();
            let sp = crate::arch::stack_pointer(ir.isa);
            let private_frame =
                (!crate::passes::memory::frame_addresses_escape(&before, sp)).then_some(sp);
            let exclusive = before.iter().flat_map(|block| &block.stmts).any(|stmt| {
                matches!(
                    stmt,
                    crate::ir::Stmt::Machine {
                        instruction: crate::ir::MachineInstruction::ArmCacheZero
                            | crate::ir::MachineInstruction::ArmExclusive { .. },
                        ..
                    }
                )
            });
            // A function that never moves its stack pointer has it on entry
            // everywhere, in a landing pad too; one that moves it is followed
            // along its edges, on an architecture with 64-bit addresses and
            // without unwinding.
            let offsets = |blocks: &[crate::ir::Block]| {
                let moved = blocks
                    .iter()
                    .flat_map(|block| &block.stmts)
                    .any(|stmt| crate::ir::visit::statement_registers(stmt).0.contains(&sp));
                if !moved {
                    Some(
                        blocks
                            .iter()
                            .map(|block| vec![Some(0); block.stmts.len()])
                            .collect(),
                    )
                } else if crate::arch::pointer_bytes(ir.isa) == 8 && ir.landing_pads.is_empty() {
                    product::stack_offsets(blocks, sp)
                } else {
                    None
                }
            };
            let frames = (private_frame.is_some() && !exclusive)
                .then(|| {
                    Some(product::Frames {
                        before: offsets(&before)?,
                        after: offsets(&ir.blocks)?,
                    })
                })
                .flatten();
            let stack_entries = [&before, &ir.blocks].map(|blocks| {
                product::stack_offsets(blocks, sp)
                    .map(|offsets| {
                        offsets
                            .iter()
                            .map(|block| block.first().copied().flatten())
                            .collect()
                    })
                    .unwrap_or_default()
            });
            state.applications.push(product::Application {
                site,
                tag,
                index: application,
                before,
                after: ir.blocks.clone(),
                landing_pads: !ir.landing_pads.is_empty(),
                narrow_stack: (crate::arch::pointer_bytes(ir.isa) == 4).then_some(sp),
                stack_entries: (sp, stack_entries),
                private_frame,
                frames,
                convention: ir.convention,
                entry_alignment: ir
                    .entry_alignment
                    .map(|alignment| (crate::arch::stack_pointer(ir.isa), alignment)),
                narrow_results: callees.narrow_results.iter().copied().collect(),
                without_result_address: callees.without_result_address.iter().copied().collect(),
                narrow_registers: match ir.isa {
                    crate::loader::Isa::Arm32 => (0..16).collect(),
                    crate::loader::Isa::I386 => (0..8).collect(),
                    _ => BTreeSet::new(),
                },
                entry_pairs: ir
                    .params
                    .iter()
                    .filter_map(|param| {
                        let low = param
                            .index
                            .checked_sub(crate::lift::pairs32::PARAMETER_BASE)
                            .filter(|low| *low < 16)?;
                        Some((param.index, (low, low + 1)))
                    })
                    .collect(),
                returned: returned(ir),
            });
            return result;
        }
        (application, revisiting)
    };
    if !changed || revisiting {
        return result;
    }
    let originals: BTreeMap<u64, &crate::ir::Block> =
        before.iter().map(|block| (block.start, block)).collect();
    let mut kept = BTreeSet::new();
    for block in &ir.blocks {
        let Some(original) = originals.get(&block.start) else {
            skip(site, "a block was added".to_owned());
            continue;
        };
        kept.insert(block.start);
        if original.stmts.len() != block.stmts.len()
            || original
                .stmts
                .iter()
                .zip(&block.stmts)
                .any(|(old, new)| shape(old) != shape(new))
        {
            // Statements dropped, added, moved or changed in kind: a
            // statement-by-statement comparison does not apply.
            if format!("{:?}", original.stmts) != format!("{:?}", block.stmts) {
                skip(
                    site,
                    "statements were added, removed or changed in kind".to_owned(),
                );
            }
            continue;
        }
        let mut state = Block::new();
        for (old, new) in original.stmts.iter().zip(&block.stmts) {
            state.rewrite(site, application, old, new);
            state.advance(new);
        }
    }
    if before.iter().any(|block| !kept.contains(&block.start)) {
        skip(site, "a block was removed".to_owned());
    }
    result
}

/// What a statement does, with its expressions taken out: two statements of
/// the same shape differ only in the values they compute.
fn shape(stmt: &Stmt) -> String {
    let mut shaped = stmt.clone();
    for expr in expressions_mut(&mut shaped) {
        *expr = Expr::Const(0);
    }
    if let Stmt::Brif { cond, .. } = &mut shaped {
        *cond = Cond::Eq;
    }
    format!("{:?}", shaped.with_origin(None))
}

fn expressions_mut(stmt: &mut Stmt) -> Vec<&mut Expr> {
    match stmt {
        Stmt::Assign { value, .. } | Stmt::Ret { value, .. } => vec![value],
        Stmt::Store { addr, value, .. } => vec![addr, value],
        Stmt::Brif { lhs, rhs, .. } => vec![lhs, rhs],
        Stmt::BrIndirect { target, .. } => vec![target],
        Stmt::Switch { index, .. } => vec![index],
        Stmt::Call { through, args, .. } => through
            .iter_mut()
            .chain(args.iter_mut().flatten())
            .collect(),
        Stmt::Machine { inputs, .. } => inputs.iter_mut().collect(),
        Stmt::BrifFlags { .. } | Stmt::Br { .. } | Stmt::Unsupported { .. } | Stmt::Trap { .. } => {
            Vec::new()
        }
    }
}

fn expressions(stmt: &Stmt) -> Vec<&Expr> {
    match stmt {
        Stmt::Assign { value, .. } | Stmt::Ret { value, .. } => vec![value],
        Stmt::Store { addr, value, .. } => vec![addr, value],
        Stmt::Brif { lhs, rhs, .. } => vec![lhs, rhs],
        Stmt::BrIndirect { target, .. } => vec![target],
        Stmt::Switch { index, .. } => vec![index],
        Stmt::Call { through, args, .. } => through.iter().chain(args.iter().flatten()).collect(),
        Stmt::Machine { inputs, .. } => inputs.iter().collect(),
        Stmt::BrifFlags { .. } | Stmt::Br { .. } | Stmt::Unsupported { .. } | Stmt::Trap { .. } => {
            Vec::new()
        }
    }
}

/// What a statement makes observable: values at the bits it keeps, or the
/// truth of the condition it branches on.
enum Effect<'s> {
    Bits(&'s Expr, u32),
    Truth(Cond, &'s Expr, &'s Expr),
}

fn effects(stmt: &Stmt) -> Vec<Effect<'_>> {
    match stmt {
        Stmt::Assign { dest, value, .. } => vec![Effect::Bits(value, u32::from(dest.width))],
        Stmt::Store {
            addr, value, width, ..
        } => vec![
            Effect::Bits(addr, 64),
            Effect::Bits(value, u32::from(*width) * 8),
        ],
        Stmt::Brif { cond, lhs, rhs, .. } => vec![Effect::Truth(*cond, lhs, rhs)],
        _ => expressions(stmt)
            .into_iter()
            .map(|expr| Effect::Bits(expr, 64))
            .collect(),
    }
}

/// An operation the SMT translation does not model, if `expr` applies one.
fn unmodeled(expr: &Expr) -> Option<Operation> {
    if let Expr::Apply { op, .. } = expr
        && !modeled(*op)
    {
        return Some(*op);
    }
    crate::ir::visit::children(expr)
        .into_iter()
        .find_map(unmodeled)
}

pub(super) fn modeled(op: Operation) -> bool {
    match op {
        Operation::Lanes(
            LaneOp::AddSaturatingUnsigned
            | LaneOp::AddSaturatingSigned
            | LaneOp::SubSaturatingSigned
            | LaneOp::MulHighSigned
            | LaneOp::MulHighUnsigned,
            bits,
        ) => bits <= 32,
        Operation::FloatAdd(_)
        | Operation::FloatSub(_)
        | Operation::FloatMul(_)
        | Operation::FloatDiv(_)
        | Operation::FloatSqrt(_)
        | Operation::FloatNegate(_)
        | Operation::FloatAbs(_)
        | Operation::FloatMulAdd(_)
        | Operation::FloatEqual(_)
        | Operation::FloatLess(_)
        | Operation::FloatLessEqual(_)
        | Operation::FloatUnordered(_)
        | Operation::IntToFloat { .. }
        | Operation::FloatToInt { .. }
        | Operation::FloatRound(..)
        | Operation::FloatConvert { .. }
        | Operation::Lanes(..)
        | Operation::InterleaveLow(_)
        | Operation::InterleaveHigh(_)
        | Operation::Widen { .. }
        | Operation::Narrow(_)
        | Operation::SignBits(_)
        | Operation::SumLanes(_)
        | Operation::Pack { .. }
        | Operation::SumLanesLong { .. }
        | Operation::CountLeadingZeros(_)
        | Operation::CountTrailingZeros(_)
        | Operation::PopCount(_)
        | Operation::ReverseBits(_) => true,
        Operation::MultiplyAddPairs
        | Operation::SumAbsoluteDifferences
        | Operation::Results
        | Operation::Undefined
        | Operation::Crc32 { .. }
        | Operation::Aes { .. }
        | Operation::WideDivide { .. } => false,
    }
}

fn registers_read(expr: &Expr, out: &mut BTreeSet<u16>) {
    if let Expr::Reg { index, .. } = expr {
        out.insert(*index);
    }
    for child in crate::ir::visit::children(expr) {
        registers_read(child, out);
    }
}

const BITS: &str = "(_ BitVec 64)";
const MEMORY: &str = "(Array (_ BitVec 64) (_ BitVec 8))";

/// SMT definitions and free symbols, from which queries take what they use.
#[derive(Default)]
struct Script {
    /// Name, sort and body of each definition, in the order made.
    definitions: Vec<(String, &'static str, String)>,
    named: BTreeMap<String, usize>,
    /// Symbols no statement determines, with their sorts.
    free: BTreeMap<String, &'static str>,
    /// Functions of bit-vectors standing for operations the solver does not
    /// model, with the number of arguments each takes.
    functions: BTreeMap<String, usize>,
    /// The definitions that apply one of them, with the function and the
    /// arguments.
    applied: BTreeMap<usize, (String, Vec<String>)>,
    fresh: usize,
}

impl Script {
    fn define(&mut self, sort: &'static str, body: String) -> String {
        let name = format!("d{}", self.fresh);
        self.fresh += 1;
        self.named.insert(name.clone(), self.definitions.len());
        self.definitions.push((name.clone(), sort, body));
        name
    }

    fn havoc(&mut self, sort: &'static str) -> String {
        let name = format!("h{}", self.fresh);
        self.fresh += 1;
        self.free.insert(name.clone(), sort);
        name
    }

    fn declare(&mut self, name: &str, sort: &'static str) {
        self.free.insert(name.to_owned(), sort);
    }

    /// `op`, which the solver does not model, applied to `args`: one
    /// function of its arguments, whatever it is, wherever it is applied.
    fn function(&mut self, op: Operation, args: &[String]) -> String {
        // The name spells the operation out, so two operations never share
        // one: each character not a letter or digit is escaped.
        let mut name = format!("op{}_", args.len());
        for c in format!("{op:?}").chars() {
            if c.is_ascii_alphanumeric() {
                name.push(c);
            } else {
                write!(name, "_{:02x}", u32::from(c)).expect("writing to a String");
            }
        }
        self.functions.insert(name.clone(), args.len());
        let body = if args.is_empty() {
            name.clone()
        } else {
            format!("({name} {})", args.join(" "))
        };
        self.applied
            .insert(self.definitions.len(), (name, args.to_vec()));
        self.define(BITS, body)
    }

    /// The declarations of the functions of `functions`.
    fn declarations(functions: &BTreeMap<String, usize>) -> String {
        let mut text = String::new();
        for (name, arity) in functions {
            writeln!(
                text,
                "(declare-fun {name} ({}) {BITS})",
                vec![BITS; *arity].join(" ")
            )
            .expect("writing to a String");
        }
        text
    }

    /// The script that asserts `assertion` with every definition it needs,
    /// and the bit-vector symbols it leaves free.
    fn query(&self, assertion: &str) -> (String, Vec<String>) {
        let (needed, free) = self.needed(&[assertion]);
        let mut script = String::from(PREAMBLE);
        if self.counts(&needed, &[assertion]) {
            script.push_str(COUNT8);
        }
        script.push_str(&Self::declarations(&self.functions));
        let mut symbols = Vec::new();
        for name in &free {
            let sort = self.free[*name];
            writeln!(script, "(declare-const {name} {sort})").expect("writing to a String");
            if sort == BITS {
                symbols.push((*name).to_owned());
            }
        }
        for index in needed {
            let (name, sort, body) = &self.definitions[index];
            writeln!(script, "(define-fun {name} () {sort} {body})").expect("writing to a String");
        }
        writeln!(script, "(assert {assertion})").expect("writing to a String");
        (script, symbols)
    }

    /// The definitions `texts` use, directly or through other definitions,
    /// and the free symbols among what they all read.
    fn needed<'a>(&'a self, texts: &[&'a str]) -> (BTreeSet<usize>, BTreeSet<&'a str>) {
        let mut needed = BTreeSet::new();
        let mut free = BTreeSet::new();
        let mut work = texts.to_vec();
        while let Some(text) = work.pop() {
            for token in tokens(text) {
                if let Some(&index) = self.named.get(token) {
                    if needed.insert(index) {
                        work.push(&self.definitions[index].2);
                    }
                } else if self.free.contains_key(token) {
                    free.insert(token);
                }
            }
        }
        (needed, free)
    }

    fn counts(&self, needed: &BTreeSet<usize>, texts: &[&str]) -> bool {
        texts.iter().any(|text| text.contains("count8"))
            || needed
                .iter()
                .any(|&index| self.definitions[index].2.contains("count8"))
    }

    /// The Horn clause that `head` holds whenever `body` does, for every
    /// value of the free symbols, each definition an equation in the body;
    /// and whether it needs the bit-counting function. A function standing
    /// for an unmodeled operation would be one the solver may choose, so
    /// each of its applications is a value of its own, equal to another
    /// where their arguments are.
    fn clause(&self, body: &str, head: &str) -> (String, bool) {
        let (needed, free) = self.needed(&[body, head]);
        let mut variables = String::new();
        for name in &free {
            write!(variables, "({name} {})", self.free[*name]).expect("writing to a String");
        }
        let mut premises = String::new();
        let mut applications: Vec<(&str, &str, &[String])> = Vec::new();
        for &index in &needed {
            let (name, sort, body) = &self.definitions[index];
            write!(variables, "({name} {sort})").expect("writing to a String");
            if let Some((function, args)) = self.applied.get(&index) {
                for &(other, other_function, other_args) in &applications {
                    if other_function == function {
                        let same: Vec<String> = args
                            .iter()
                            .zip(other_args)
                            .map(|(a, b)| format!("(= {a} {b})"))
                            .collect();
                        write!(
                            premises,
                            "(=> (and true {}) (= {name} {other})) ",
                            same.join(" ")
                        )
                        .expect("writing to a String");
                    }
                }
                applications.push((name, function, args));
                continue;
            }
            write!(premises, "(= {name} {body}) ").expect("writing to a String");
        }
        let implication = format!("(=> (and {premises}{body}) {head})");
        let clause = if variables.is_empty() {
            format!("(assert {implication})\n")
        } else {
            format!("(assert (forall ({variables}) {implication}))\n")
        };
        (clause, self.counts(&needed, &[body, head]))
    }
}

/// The symbolic state of a block after some of its statements: SMT
/// definitions for what they computed, and the register and memory terms
/// the next statement reads.
pub(crate) struct Block {
    script: Script,
    registers: BTreeMap<u16, String>,
    /// After a call, the prefix of the fresh symbols registers read as.
    clobbered: Option<String>,
    memory: String,
    /// The definedness of every statement so far.
    defined: String,
    /// Why the state no longer describes the block, once it does not.
    lost: Option<&'static str>,
}

impl Block {
    pub(crate) fn new() -> Self {
        let mut script = Script::default();
        script.declare("memory", MEMORY);
        Self {
            script,
            registers: BTreeMap::new(),
            clobbered: None,
            memory: "memory".to_owned(),
            defined: "true".to_owned(),
            lost: None,
        }
    }

    /// The state after `prefix`, for a pass that rewrites a statement out
    /// of order.
    #[cfg(test)]
    pub(crate) fn after(prefix: &[Stmt]) -> Self {
        let mut block = Self::new();
        for stmt in prefix {
            block.advance(stmt);
        }
        block
    }

    fn define(&mut self, sort: &'static str, body: String) -> String {
        self.script.define(sort, body)
    }

    fn havoc(&mut self, sort: &'static str) -> String {
        self.script.havoc(sort)
    }

    /// Gives every register `expr` reads a term: its entry value `r{i}`,
    /// or after a call a fresh one.
    fn prepare(&mut self, expr: &Expr) {
        let mut read = BTreeSet::new();
        registers_read(expr, &mut read);
        for index in read {
            if self.registers.contains_key(&index) {
                continue;
            }
            let name = match &self.clobbered {
                Some(prefix) => format!("{prefix}r{index}"),
                None => format!("r{index}"),
            };
            self.script.declare(&name, BITS);
            self.registers.insert(index, name);
        }
    }

    fn read(&mut self, expr: &Expr) -> Value {
        self.prepare(expr);
        memory_value(expr, &self.registers, &self.memory)
    }

    fn assume_defined(&mut self, defined: &str) {
        if defined != "(and true )" {
            let conjunction = format!("(and {} {defined})", self.defined);
            self.defined = self.define("Bool", conjunction);
        }
    }

    /// Steps past `stmt`, which the next statement of the block follows.
    pub(crate) fn advance(&mut self, stmt: &Stmt) {
        if self.lost.is_some() {
            return;
        }
        match stmt {
            Stmt::Assign { dest, value, .. } => {
                let term = if unmodeled(value).is_some() {
                    self.havoc(BITS)
                } else {
                    let value = self.read(value);
                    self.assume_defined(&value.defined);
                    self.define(BITS, value.term)
                };
                self.registers
                    .insert(dest.index, low(&term, u32::from(dest.width)));
            }
            Stmt::Store {
                addr, value, width, ..
            } => {
                if unmodeled(addr).is_some() || unmodeled(value).is_some() {
                    self.memory = self.havoc(MEMORY);
                    return;
                }
                let addr = self.read(addr);
                let value = self.read(value);
                self.assume_defined(&addr.defined);
                self.assume_defined(&value.defined);
                let address = self.define(BITS, addr.term);
                let stored = self.define(BITS, value.term);
                let mut memory = self.memory.clone();
                for byte in 0..*width {
                    let first = u32::from(byte) * 8;
                    memory = format!(
                        "(store {memory} (bvadd {address} {}) ((_ extract {} {first}) {stored}))",
                        constant(u64::from(byte)),
                        first + 7,
                    );
                }
                self.memory = self.define(MEMORY, memory);
            }
            Stmt::Machine { outputs, .. } => {
                for output in outputs {
                    let term = self.havoc(BITS);
                    self.registers
                        .insert(output.index, low(&term, u32::from(output.width)));
                }
                self.memory = self.havoc(MEMORY);
            }
            Stmt::Call { .. } | Stmt::Unsupported { .. } => {
                // Any register or memory byte may change.
                let epoch = format!("c{}", self.script.fresh);
                self.script.fresh += 1;
                self.registers.clear();
                self.clobbered = Some(epoch);
                self.memory = self.havoc(MEMORY);
            }
            // Falling through a conditional branch only narrows the states
            // that reach the next statement.
            Stmt::Brif { .. } | Stmt::BrifFlags { .. } => {}
            Stmt::Br { .. }
            | Stmt::BrIndirect { .. }
            | Stmt::Switch { .. }
            | Stmt::Ret { .. }
            | Stmt::Trap { .. } => self.lost = Some("a statement after the end of its block"),
        }
    }

    /// Records the obligation that `after`, in place of `before` at this
    /// point of the block, does what `before` did.
    pub(crate) fn rewrite(
        &mut self,
        site: &'static str,
        application: usize,
        before: &Stmt,
        after: &Stmt,
    ) {
        if !enabled() {
            return;
        }
        let before_text = format!("{before:?}");
        let after_text = format!("{after:?}");
        if before_text == after_text {
            STATE.lock().expect("validation state").unchanged += 1;
            return;
        }
        if let Some(reason) = self.lost {
            skip(site, reason.to_owned());
            return;
        }
        // What follows an unchecked rewrite may read what it changed.
        if shape(before) != shape(after) {
            skip(site, "the statement changed kind or target".to_owned());
            self.lost = Some("after a rewrite that was not checked");
            return;
        }
        if let Some(op) = expressions(before)
            .into_iter()
            .chain(expressions(after))
            .find_map(unmodeled)
        {
            skip(site, format!("unmodeled {op:?}"));
            self.lost = Some("after a rewrite that was not checked");
            return;
        }
        let mut differences = Vec::new();
        for (old, new) in effects(before).into_iter().zip(effects(after)) {
            let (old, new) = match (old, new) {
                (Effect::Bits(old, bits), Effect::Bits(new, _)) => {
                    let old = self.read(old);
                    let new = self.read(new);
                    (
                        Value {
                            term: low(&old.term, bits),
                            defined: old.defined,
                        },
                        Value {
                            term: low(&new.term, bits),
                            defined: new.defined,
                        },
                    )
                }
                (Effect::Truth(a, a_lhs, a_rhs), Effect::Truth(b, b_lhs, b_rhs)) => {
                    (self.truth(a, a_lhs, a_rhs), self.truth(b, b_lhs, b_rhs))
                }
                _ => unreachable!("statements of one shape have the same effects"),
            };
            if old.term == new.term && old.defined == new.defined {
                continue;
            }
            differences.push(format!(
                "(or (not (= {} {})) (and {} (not (= {} {}))))",
                old.defined, new.defined, old.defined, old.term, new.term
            ));
        }
        if differences.is_empty() {
            STATE.lock().expect("validation state").unchanged += 1;
            return;
        }
        let mismatch = format!("(and {} (or {}))", self.defined, differences.join(" "));
        let (query, symbols) = self.query(&mismatch);
        let mut hasher = std::hash::DefaultHasher::new();
        query.hash(&mut hasher);
        let hash = hasher.finish();
        let mut state = STATE.lock().expect("validation state");
        match state.seen.binary_search(&hash) {
            Ok(_) => {
                REPEATED.fetch_add(1, Ordering::Relaxed);
            }
            Err(position) => {
                state.seen.insert(position, hash);
                let tag = state.tag.clone();
                state.obligations.push(Obligation {
                    site,
                    tag,
                    before: before_text,
                    after: after_text,
                    query,
                    symbols,
                    application,
                });
            }
        }
    }

    fn truth(&mut self, cond: Cond, lhs: &Expr, rhs: &Expr) -> Value {
        let a = self.read(lhs);
        let b = self.read(rhs);
        let bits = crate::ir::semantics::operand_width(lhs, rhs);
        Value {
            term: condition(cond, &a.term, &b.term, bits),
            defined: format!("(and {} {})", a.defined, b.defined),
        }
    }

    fn query(&self, mismatch: &str) -> (String, Vec<String>) {
        self.script.query(mismatch)
    }
}

fn tokens(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| c.is_whitespace() || c == '(' || c == ')')
        .filter(|token| !token.is_empty())
}

const PREAMBLE: &str = "(set-option :produce-models true)\n";

/// The number of set bits of a byte, exactly.
const COUNT8: &str = "(define-fun count8 ((x (_ BitVec 8))) (_ BitVec 4) (bvadd \
    ((_ zero_extend 3) ((_ extract 0 0) x)) ((_ zero_extend 3) ((_ extract 1 1) x)) \
    ((_ zero_extend 3) ((_ extract 2 2) x)) ((_ zero_extend 3) ((_ extract 3 3) x)) \
    ((_ zero_extend 3) ((_ extract 4 4) x)) ((_ zero_extend 3) ((_ extract 5 5) x)) \
    ((_ zero_extend 3) ((_ extract 6 6) x)) ((_ zero_extend 3) ((_ extract 7 7) x))))\n";

/// How the solver looks for a state that tells two statements apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Strategy {
    /// Word-level reasoning, quick for most rewrites.
    WordLevel,
    /// Word-level reasoning after bounds propagation, which settles address
    /// arithmetic under masks that ranges keep exact.
    Bounded,
    /// Linear integer arithmetic over the query's integer values: each
    /// linear operation exact, memory an array of integers, and each other
    /// operation, such as a product of two variables, any function of its
    /// operands. Only its proofs are taken: a model it finds is left to the
    /// other strategies.
    Integer,
}

impl Strategy {
    /// The command that checks the query asserted before it.
    #[must_use]
    pub fn check(self) -> &'static str {
        match self {
            Self::WordLevel => {
                "(check-sat-using (then simplify solve-eqs (using-params simplify :som true :sort-sums true \
                 :bv-sort-ac true :bv-extract-prop true) reduce-bv-size smt))"
            }
            Self::Bounded => {
                "(check-sat-using (then simplify solve-eqs propagate-bv-bounds simplify \
                 reduce-bv-size smt))"
            }
            Self::Integer => {
                "(check-sat-using (then simplify solve-eqs propagate-ineqs simplify smt))"
            }
        }
    }

    /// `query` as the strategy asks it, or None when it cannot.
    pub(crate) fn query(self, query: &str) -> Option<std::borrow::Cow<'_, str>> {
        match self {
            Self::Integer => integer::translate(query).map(std::borrow::Cow::Owned),
            _ => Some(std::borrow::Cow::Borrowed(query)),
        }
    }
}

/// What the solver said about one obligation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// No state tells the two statements apart.
    Proved,
    /// A state that tells them apart, as the solver's model of the symbols.
    Counterexample(String),
    /// The solver gave up, with its reason.
    Unknown(String),
}

/// Answers each obligation with `workers` solver processes, each query
/// bounded by `rlimit` units of solver work rather than by elapsed time,
/// telling `answered` each answer and the seconds it took. Once an
/// obligation of an application is not proved, the application is checked
/// as a whole, so its obligations not asked yet are answered unknown
/// without asking.
///
/// # Panics
///
/// When the `z3` executable cannot be started or stops answering.
#[must_use]
pub fn solve(
    obligations: &[Obligation],
    workers: usize,
    rlimit: u64,
    strategies: &[Strategy],
    answered: &(dyn Fn(usize, &Answer, f64) + Sync),
) -> Vec<Answer> {
    let next = AtomicUsize::new(0);
    let answers: Mutex<Vec<Option<Answer>>> = Mutex::new(vec![None; obligations.len()]);
    let unproved: Mutex<BTreeSet<usize>> = Mutex::new(BTreeSet::new());
    std::thread::scope(|scope| {
        for _ in 0..workers.max(1) {
            scope.spawn(|| {
                let mut solver = product::Solver::start().expect("start z3");
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(obligation) = obligations.get(index) else {
                        break;
                    };
                    let started = std::time::Instant::now();
                    let answer = if unproved
                        .lock()
                        .expect("unproved applications")
                        .contains(&obligation.application)
                    {
                        Answer::Unknown(
                            "another rewrite of the application is not proved".to_owned(),
                        )
                    } else {
                        let mut answer = Answer::Unknown("no strategy".to_owned());
                        for &strategy in strategies {
                            answer = ask(&mut solver, obligation, rlimit, strategy);
                            if !matches!(answer, Answer::Unknown(_)) {
                                break;
                            }
                        }
                        answer
                    };
                    if answer != Answer::Proved {
                        unproved
                            .lock()
                            .expect("unproved applications")
                            .insert(obligation.application);
                    }
                    answered(index, &answer, started.elapsed().as_secs_f64());
                    answers.lock().expect("answers")[index] = Some(answer);
                }
            });
        }
    });
    answers
        .into_inner()
        .expect("answers")
        .into_iter()
        .map(|answer| answer.expect("every obligation answered"))
        .collect()
}

fn ask(
    solver: &mut product::Solver,
    obligation: &Obligation,
    rlimit: u64,
    strategy: Strategy,
) -> Answer {
    match solver.answer(&obligation.query, rlimit, strategy, &[]) {
        product::Reply::Unsat => Answer::Proved,
        product::Reply::Sat(_) => {
            Answer::Counterexample(solver.model(&obligation.query, &obligation.symbols))
        }
        product::Reply::Unknown(reason) => Answer::Unknown(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::smt::raw_bin;
    use crate::ir::{BinOp, RegRef};
    use std::process::Command;

    #[test]
    fn horn_clauses_relate_unmodeled_applications_by_their_arguments() {
        let mut script = Script::default();
        script.declare("x", BITS);
        script.declare("y", BITS);
        let op = Operation::Crc32 {
            castagnoli: false,
            bits: 8,
        };
        let a = script.function(op, &["x".to_owned()]);
        let b = script.function(op, &["y".to_owned()]);
        let (query, _) = script.query(&format!("(distinct {a} {b})"));
        assert!(query.contains("(declare-fun op1_Crc32"), "{query}");
        let (clause, _) = script.clause("true", &format!("(= {a} {b})"));
        assert!(!clause.contains("op1_"), "{clause}");
        assert!(
            clause.contains(&format!("(=> (and true (= y x)) (= {b} {a}))")),
            "{clause}"
        );
    }

    fn assign(index: u16, width: u8, value: Expr) -> Stmt {
        Stmt::Assign {
            at: None,
            dest: RegRef { index, width },
            value,
        }
    }

    /// The answer for rewriting `before` to `after` after `prefix`.
    fn answer(prefix: &[Stmt], before: &Stmt, after: &Stmt) -> Option<Answer> {
        let _serial = SERIAL.lock().expect("serial validation tests");
        begin("test");
        Block::after(prefix).rewrite("test", 0, before, after);
        let recorded = take();
        assert!(recorded.skipped.is_empty(), "{:?}", recorded.skipped);
        let mut answers = solve(
            &recorded.obligations,
            1,
            50_000_000,
            &[Strategy::WordLevel, Strategy::Integer],
            &|_, _, _| {},
        );
        assert!(answers.len() <= 1, "one rewrite records one obligation");
        answers.pop()
    }

    static SERIAL: Mutex<()> = Mutex::new(());

    fn refuted(answer: Option<Answer>) -> bool {
        matches!(answer, Some(Answer::Counterexample(_)))
    }

    #[test]
    fn a_quotient_recovered_from_a_reciprocal_is_proved() {
        if Command::new("z3").arg("-version").output().is_err() {
            eprintln!("SKIP rewrite validation: z3 unavailable");
            return;
        }
        // udiv3: the low word times 0xaaaaaaab, shifted right by 33.
        let word = || raw_bin(BinOp::And, Expr::reg(0, 64), Expr::Const(0xffff_ffff));
        let product = raw_bin(BinOp::Mul, word(), Expr::Const(0xaaaa_aaab));
        let scaled = raw_bin(BinOp::Shr, product, Expr::Const(33));
        let quotient = |divisor| raw_bin(BinOp::DivU, word(), Expr::Const(divisor));
        assert_eq!(
            answer(
                &[],
                &assign(1, 64, scaled.clone()),
                &assign(1, 64, quotient(3))
            ),
            Some(Answer::Proved)
        );
        // Over integers only proofs are taken; the word-level search finds
        // the counterexample to a wrong divisor.
        assert!(refuted(answer(
            &[],
            &assign(1, 64, scaled),
            &assign(1, 64, quotient(5))
        )));
    }

    #[test]
    fn rewrites_are_checked_against_the_statements_before_them() {
        if !crate::ir::smt::z3_available("rewrite validation") {
            return;
        }
        let r = |index| Expr::reg(index, 64);
        let sum = |index, k| raw_bin(BinOp::Add, r(index), Expr::Const(k));
        // A wrong constant is told apart.
        assert!(refuted(answer(
            &[],
            &assign(1, 64, sum(0, 1)),
            &assign(1, 64, sum(0, 2))
        )));
        // A constant the block assigned before the statement is known...
        let five = assign(3, 64, Expr::Const(5));
        assert_eq!(
            answer(
                std::slice::from_ref(&five),
                &assign(4, 64, sum(3, 1)),
                &assign(4, 64, Expr::Const(6))
            ),
            Some(Answer::Proved)
        );
        // ...until something the block does not model may change it.
        let unknown = Stmt::Unsupported {
            at: None,
            text: String::new(),
            writes: None,
        };
        assert!(refuted(answer(
            &[five, unknown],
            &assign(4, 64, sum(3, 1)),
            &assign(4, 64, Expr::Const(6))
        )));
        // Only the bits the destination keeps are compared.
        assert_eq!(
            answer(&[], &assign(1, 32, sum(0, 1 << 32)), &assign(1, 32, r(0))),
            Some(Answer::Proved)
        );
        assert!(refuted(answer(
            &[],
            &assign(1, 64, sum(0, 1 << 32)),
            &assign(1, 64, r(0))
        )));
        // A division by zero may not become a value.
        assert!(refuted(answer(
            &[],
            &assign(
                1,
                64,
                raw_bin(BinOp::Mul, raw_bin(BinOp::DivU, r(0), r(2)), Expr::Const(0))
            ),
            &assign(1, 64, Expr::Const(0))
        )));
        // A stored value is read back.
        let store = Stmt::Store {
            at: None,
            addr: r(0),
            value: r(1),
            width: 8,
        };
        let load = Expr::Load {
            addr: Box::new(r(0)),
            width: 8,
            signed: false,
        };
        assert_eq!(
            answer(&[store], &assign(2, 64, load), &assign(2, 64, r(1))),
            Some(Answer::Proved)
        );
        // A branch keeps the truth of its condition, not its operands.
        let branch = |cond, lhs, rhs| Stmt::Brif {
            at: None,
            cond,
            lhs,
            rhs,
            target: 0x10,
        };
        assert_eq!(
            answer(
                &[],
                &branch(Cond::Lt, r(0), r(1)),
                &branch(Cond::Gt, r(1), r(0))
            ),
            Some(Answer::Proved)
        );
        assert!(refuted(answer(
            &[],
            &branch(Cond::Lt, r(0), r(1)),
            &branch(Cond::Cc, r(0), r(1))
        )));
    }
}

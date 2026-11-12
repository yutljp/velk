//! A block run on both sides: its obligations and the edges it leaves by.

use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use super::side::{Facts, Kept, Layer, Side, undefined_count};
use super::{Application, Candidate, NARROW_STACK};
use crate::ir::smt::validate::{
    BITS, MEMORY, Script, expressions, registers_read, shape, unmodeled,
};
use crate::ir::smt::{Value, condition, constant, low};
use crate::ir::{Cond, Expr, RegRef, Stmt};

/// A way out of a block into another, with both sides' states there.
pub(super) struct Edge {
    pub(super) target: usize,
    /// When the original side takes it.
    pub(super) path: String,
    /// Each candidate invariant of the target, in these states.
    pub(super) holds: Vec<String>,
    /// Each register of the original side, then of the rewritten side, and
    /// the memory, in these states.
    pub(super) exit: Vec<String>,
}

/// Both sides of one block, run from the entry states.
pub(super) struct Run {
    pub(super) script: Script,
    /// Each candidate invariant, in the entry states.
    pub(super) assumed: Vec<String>,
    /// What the entry states meet on every path from the function's start.
    pub(super) facts: String,
    pub(super) edges: Vec<Edge>,
    /// What each obligation compares, and the assertion that it differs.
    pub(super) obligations: Vec<(String, String)>,
}

/// What both sides' entry symbols in `script` meet when the function starts:
/// the two sides agree, and the entry facts of the application hold.
pub(super) fn starting(
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

/// The candidates in the states both sides start the function in.
pub(super) fn start(application: &Application, candidates: &[Candidate]) -> (Script, Vec<String>) {
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
pub(super) fn instantiate(
    script: &mut Script,
    before: &mut Side,
    after: &mut Side,
    (old, new): &Candidate,
) -> String {
    let old = before.read(script, old);
    let new = after.read(script, new);
    script.define("Bool", format!("(= {} {})", old.term, new.term))
}

pub(super) fn observable(stmt: &Stmt) -> bool {
    !matches!(stmt, Stmt::Assign { .. })
}

/// The obligation that the two values agree wherever the original's is
/// defined, given `path`: the assertion that they do not.
/// Whether the two values are the same terms with the same definedness, so
/// that they cannot differ.
pub(super) fn same(before: &Side, after: &Side, old: &Value, new: &Value) -> bool {
    old.term == new.term && old.defined == new.defined && before.defined == after.defined
}

pub(super) fn differs(
    path: &str,
    before: &Side,
    after: &Side,
    old: &Value,
    new: &Value,
    bits: u32,
) -> String {
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

pub(super) fn run(
    application: &Application,
    index: usize,
    blocks: &BTreeMap<u64, usize>,
    candidates: &[Candidate],
    registers: &[u16],
    shared: &Rc<BTreeSet<u16>>,
    left: &BTreeSet<u16>,
) -> Result<Run, &'static str> {
    let old = &application.before[index].stmts;
    let new = &application.after[index].stmts;
    let pointer_bits = if application.narrow_stack.is_some() {
        32
    } else {
        64
    };
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
    // Both sides enter with one stack pointer; one that only constants move
    // starts each block that far from it, which on a 32-bit architecture
    // lies clear of the ends of the address space.
    let mut facts = vec!["true".to_owned()];
    let (sp, entries) = &application.stack_entries;
    let entered: Vec<Option<String>> = [&mut before, &mut after]
        .into_iter()
        .zip(entries)
        .map(|(side, entries)| {
            let offset = (*entries.get(index)?)?;
            Some(format!(
                "(bvsub {} {})",
                side.term(&mut script, *sp),
                constant(offset as u64)
            ))
        })
        .collect();
    if let [Some(old), Some(new)] = &entered[..] {
        facts.push(format!("(= {old} {new})"));
    }
    if application.narrow_stack.is_some() {
        for entered in entered.iter().flatten() {
            facts.push(format!(
                "(bvuge {entered} {}) (bvule {entered} {})",
                constant(NARROW_STACK.0),
                constant(NARROW_STACK.1)
            ));
        }
    }
    let facts = format!("(and {})", facts.join(" "));
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
    // What calls leave in registers they change and no output takes, on
    // the original side: any value. Those the block enters with are left so
    // on every path to it.
    let mut left_by_calls: BTreeSet<String> = left
        .iter()
        .map(|&register| before.term(&mut script, register))
        .collect();
    for (&at_old, &at_new) in old_observable.iter().zip(&new_observable) {
        assign_stretch(
            &mut script,
            &mut before,
            &mut after,
            &old[next_old..at_old],
            &new[next_new..at_new],
            &left_by_calls,
        );
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
                // Scratch a call passes by in a register it reads unnamed is
                // not what it reads, as `split_variables` takes it.
                if let Some(scratch) = application
                    .scratch_reads
                    .get(&(application.before[index].start, at_old))
                {
                    read.retain(|register| !scratch.contains(register));
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
                            left_by_calls.insert(term.clone());
                        }
                    }
                    for (dest, value) in outputs {
                        side.set(dest, &value);
                    }
                }
                let memory = script.havoc(MEMORY);
                let standard = |convention: crate::ir::Convention| {
                    application.convention == crate::ir::Convention::Aapcs64
                        && convention == crate::ir::Convention::Aapcs64
                };
                // The stack pointer, how far below where it was on entry
                // each side has it, and how far past that the frame is kept.
                let owned = match (application.private_frame, old_stmt) {
                    // A callee of the AArch64 procedure call standard whose
                    // arguments are unknown writes only the stack arguments,
                    // which its caller places in its own frame: nothing at
                    // or past where the caller's stack pointer was on entry.
                    (
                        Some(sp),
                        Stmt::Call {
                            args: None,
                            convention,
                            ..
                        },
                    ) if standard(*convention) => application.frames.as_ref().and_then(|frames| {
                        match (frames.before[index][at_old], frames.after[index][at_new]) {
                            (Some(old), Some(new)) => Some((sp, (old, new), 0)),
                            _ => None,
                        }
                    }),
                    (
                        Some(sp),
                        Stmt::Call {
                            args: Some(args),
                            convention,
                            ..
                        },
                    ) if !convention.go_assembly() => {
                        // A callee of Go's register convention spills its
                        // register arguments to the bottom of a caller of
                        // that convention's frame, where the caller keeps
                        // nothing it reads after the call: past what the
                        // stack carries, the callee changes no byte the
                        // caller reads, on x86-64 and on AArch64 alike. The
                        // AArch64 procedure call standard gives register
                        // arguments no place in the frame.
                        let register_arguments_unread = standard(*convention)
                            || (application.convention.go_registers()
                                && *convention == application.convention);
                        let written = if register_arguments_unread {
                            args.len().saturating_sub(convention.arguments().len())
                        } else {
                            args.len()
                        };
                        convention.stack_arguments().map(|start| {
                            (
                                sp,
                                (0, 0),
                                start - convention.pushed_by_call() + 8 * written as i64,
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
                if let Some((sp, (old_offset, new_offset), owned)) = owned {
                    let entry = |term: String, offset: i64| {
                        if offset == 0 {
                            term
                        } else {
                            format!("(bvsub {term} {})", constant(offset as u64))
                        }
                    };
                    let stack = (
                        entry(before.term(&mut script, sp), old_offset),
                        entry(after.term(&mut script, sp), new_offset),
                    );
                    before.facts.layers.borrow_mut().push(Layer {
                        memory: memory.clone(),
                        inner: before.memory.clone(),
                        sp: (sp, pointer_bits),
                        stack,
                        kept: Kept::Past(constant(owned as u64)),
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
                // The frame is kept below where each side's stack pointer
                // was on entry.
                if let Some(sp) = application.private_frame
                    && let Some(frames) = &application.frames
                    && let (Some(old_offset), Some(new_offset)) =
                        (frames.before[index][at_old], frames.after[index][at_new])
                    && crate::passes::memory::memory_ordering_barrier(old_stmt)
                {
                    let stack = (
                        format!(
                            "(bvsub {} {})",
                            before.term(&mut script, sp),
                            constant(old_offset as u64)
                        ),
                        format!(
                            "(bvsub {} {})",
                            after.term(&mut script, sp),
                            constant(new_offset as u64)
                        ),
                    );
                    before.facts.layers.borrow_mut().push(Layer {
                        memory: memory.clone(),
                        inner: before.memory.clone(),
                        sp: (sp, pointer_bits),
                        stack,
                        kept: Kept::Below,
                    });
                }
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
        assign_stretch(
            &mut script,
            &mut before,
            &mut after,
            &old[next_old..],
            &new[next_new..],
            &left_by_calls,
        );
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
        facts,
        edges,
        obligations,
    })
}

/// Runs the assignments of each side between the same two paired
/// statements. An assignment of an undefined value that both stretches make
/// alike, once each, gives it one value on both sides: the original may hold
/// any value there, so the one the rewritten function holds is among them,
/// and the obligations then ask only that the rewrite keep what the original
/// does with it.
fn assign_stretch(
    script: &mut Script,
    before: &mut Side,
    after: &mut Side,
    old: &[Stmt],
    new: &[Stmt],
    left_by_calls: &BTreeSet<String>,
) {
    type Key<'a> = (Option<u64>, RegRef, &'a Expr);
    fn key(stmt: &Stmt) -> Option<Key<'_>> {
        match stmt {
            Stmt::Assign {
                at, dest, value, ..
            } => Some((*at, *dest, value)),
            _ => None,
        }
    }
    let once = |stmts: &[Stmt], wanted: Key| {
        stmts
            .iter()
            .filter(|stmt| key(stmt) == Some(wanted))
            .count()
            == 1
    };
    let mut given: Vec<(Key, Vec<String>)> = Vec::new();
    for wanted in old.iter().filter_map(key) {
        let count = undefined_count(wanted.2);
        if count > 0 && once(old, wanted) && once(new, wanted) {
            given.push((wanted, (0..count).map(|_| script.havoc(BITS)).collect()));
        }
    }
    let names = |stmt| -> Vec<String> {
        let wanted = key(stmt);
        given
            .iter()
            .find(|(paired, _)| Some(*paired) == wanted)
            .map_or_else(Vec::new, |(_, names)| names.clone())
    };
    // Where the two sides assign one register differently at one place,
    // the undefined values may be chosen as the passes take them. Those of
    // the original are zero, as `simplify` takes them when it folds them.
    // One the rewritten side assigns where the original has an expression
    // is taken to be what that expression evaluates to, when it reads an
    // undefined value or a register holding what a call left, both any
    // value: the rewritten function then does, for one choice of its
    // undefined values, what the original does. An undefined value in place
    // of anything else stays any value, as a value the function computes is
    // not one to drop.
    type Place = (Option<u64>, RegRef);
    let mut chosen: Vec<(Place, Vec<String>)> = Vec::new();
    for stmt in old {
        let mut zeros = Vec::new();
        if let Stmt::Assign { at, dest, value } = stmt
            && once(old, (*at, *dest, value))
            && let [Stmt::Assign { value: other, .. }] = new
                .iter()
                .filter(|stmt| {
                    matches!(stmt, Stmt::Assign { at: a, dest: d, .. } if a == at && d == dest)
                })
                .collect::<Vec<_>>()[..]
            && other != value
        {
            zeros = vec![constant(0); undefined_count(value)];
            let mut holes = Vec::new();
            if filled(value, other, &mut holes) && !holes.is_empty() {
                let terms: Vec<String> = holes
                    .into_iter()
                    .map(|hole| match hole {
                        Expr::Reg { index, width: 64 } => {
                            let term = before.term(script, *index);
                            if left_by_calls.contains(&term) {
                                term
                            } else {
                                script.havoc(BITS)
                            }
                        }
                        _ if undefined_count(hole) > 0 => {
                            before.read(script, &zeroed(hole)).term
                        }
                        _ => script.havoc(BITS),
                    })
                    .collect();
                chosen.push(((*at, *dest), terms));
            }
        }
        if let Stmt::Assign { dest, value, .. } = stmt {
            let names = if zeros.is_empty() { names(stmt) } else { zeros };
            before.assign(script, *dest, value, &names);
        }
    }
    for stmt in new {
        if let Stmt::Assign { at, dest, value } = stmt {
            let terms = chosen
                .iter()
                .find(|(paired, _)| *paired == (*at, *dest))
                .map_or_else(|| names(stmt), |(_, terms)| terms.clone());
            after.assign(script, *dest, value, &terms);
        }
    }
}

/// `expr` with each undefined value it applies taken as zero.
fn zeroed(expr: &Expr) -> Expr {
    if matches!(
        expr,
        Expr::Apply {
            op: crate::ir::Operation::Undefined,
            ..
        }
    ) {
        return Expr::Const(0);
    }
    let mut zeroed = expr.clone();
    for child in crate::ir::visit::children_mut(&mut zeroed) {
        *child = self::zeroed(child);
    }
    zeroed
}

/// Whether `new` is `old` with some subexpressions replaced by undefined
/// values, collecting those subexpressions of `old` in the order the
/// undefined values are met as unmodeled operations.
fn filled<'a>(old: &'a Expr, new: &Expr, holes: &mut Vec<&'a Expr>) -> bool {
    if matches!(
        new,
        Expr::Apply {
            op: crate::ir::Operation::Undefined,
            ..
        }
    ) {
        holes.push(old);
        return true;
    }
    if old == new {
        return undefined_count(new) == 0;
    }
    let bare = |expr: &Expr| {
        let mut bare = expr.clone();
        for child in crate::ir::visit::children_mut(&mut bare) {
            *child = Expr::Const(0);
        }
        bare
    };
    let (old_children, new_children) = (
        crate::ir::visit::children(old),
        crate::ir::visit::children(new),
    );
    bare(old) == bare(new)
        && old_children.len() == new_children.len()
        && old_children
            .into_iter()
            .zip(new_children)
            .all(|(old, new)| filled(old, new, holes))
}

pub(super) fn truth(
    script: &mut Script,
    side: &mut Side,
    cond: Cond,
    lhs: &Expr,
    rhs: &Expr,
) -> Value {
    let a = side.read(script, lhs);
    let b = side.read(script, rhs);
    let bits = crate::ir::semantics::operand_width(lhs, rhs);
    Value {
        term: condition(cond, &a.term, &b.term, bits),
        defined: format!("(and {} {})", a.defined, b.defined),
    }
}

/// The registers each block of `blocks` enters holding what a call left in
/// them, a register it changes and no output takes, on every path from the
/// first block; none for a block no path reaches.
pub(super) fn left_on_entry(blocks: &[crate::ir::Block]) -> Vec<BTreeSet<u16>> {
    let index: BTreeMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(position, block)| (block.start, position))
        .collect();
    let mut entries: Vec<Option<BTreeSet<u16>>> = vec![None; blocks.len()];
    if blocks.is_empty() {
        return Vec::new();
    }
    entries[0] = Some(BTreeSet::new());
    let mut pending = vec![0];
    while let Some(position) = pending.pop() {
        let mut left = entries[position].clone().expect("a block reached");
        let mut targets = Vec::new();
        let mut ended = false;
        for stmt in &blocks[position].stmts {
            for register in crate::ir::visit::statement_registers(stmt).0 {
                left.remove(&register);
            }
            if matches!(stmt, Stmt::Call { .. }) {
                let routed: BTreeSet<u16> = stmt
                    .call_outputs()
                    .iter()
                    .map(|output| output.register)
                    .collect();
                for register in stmt.call_clobbers() {
                    if !routed.contains(&register) {
                        left.insert(register);
                    }
                }
                for output in stmt.call_outputs() {
                    left.remove(&output.dest.index);
                }
            }
            match stmt {
                Stmt::Brif { target, .. } => targets.push(*target),
                Stmt::Br { target, .. } => {
                    targets.extend(*target);
                    ended = true;
                }
                Stmt::Switch { cases, default, .. } => {
                    targets.extend(cases.iter().map(|(_, target)| *target));
                    targets.extend(*default);
                    ended = true;
                }
                Stmt::Ret { .. } | Stmt::Trap { .. } | Stmt::BrIndirect { .. } => ended = true,
                _ => {}
            }
            if ended {
                break;
            }
        }
        let mut next: Vec<usize> = targets
            .into_iter()
            .filter_map(|target| index.get(&target).copied())
            .collect();
        if !ended && position + 1 < blocks.len() {
            next.push(position + 1);
        }
        for target in next {
            let joined = match &entries[target] {
                None => left.clone(),
                Some(known) => known.intersection(&left).copied().collect(),
            };
            if entries[target].as_ref() != Some(&joined) {
                entries[target] = Some(joined);
                pending.push(target);
            }
        }
    }
    entries.into_iter().map(Option::unwrap_or_default).collect()
}

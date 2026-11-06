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
        assign_stretch(
            &mut script,
            &mut before,
            &mut after,
            &old[next_old..at_old],
            &new[next_new..at_new],
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
                        // A callee of Go's register convention spills its
                        // register arguments to the bottom of a caller of
                        // that convention's frame, where the caller keeps
                        // nothing it reads after the call: past what the
                        // stack carries, the callee changes no byte the
                        // caller reads.
                        let written = if application.convention == crate::ir::Convention::GoAmd64
                            && *convention == crate::ir::Convention::GoAmd64
                        {
                            args.len().saturating_sub(convention.arguments().len())
                        } else {
                            args.len()
                        };
                        convention.stack_arguments().map(|start| {
                            (sp, start - convention.pushed_by_call() + 8 * written as i64)
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
                if let Some(sp) = application.private_frame
                    && application.fixed_frame
                    && crate::passes::memory::memory_ordering_barrier(old_stmt)
                {
                    let stack = (before.term(&mut script, sp), after.term(&mut script, sp));
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
    for stmt in old {
        if let Stmt::Assign { dest, value, .. } = stmt {
            before.assign(script, *dest, value, &names(stmt));
        }
    }
    for stmt in new {
        if let Stmt::Assign { dest, value, .. } = stmt {
            after.assign(script, *dest, value, &names(stmt));
        }
    }
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

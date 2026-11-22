//! The Horn clauses of the product, for invariants equations cannot state.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Write as _;
use std::process::{Command, Stdio};

use super::solver::Reply;
use super::{Application, Checked, NARROW_STACK};
use crate::ir::smt::constant;
use crate::ir::smt::validate::{BITS, MEMORY};

/// The wall-clock bound on one Horn query, in seconds, besides its
/// resource limit, which the Horn engine does not always heed. A query it
/// stops leaves the verdict the equations gave, so the bound can only turn a
/// proof into that verdict, never the other way.
pub(super) const HORN_SECONDS: u32 = 120;
/// The memory bound on one Horn query, in megabytes.
pub(super) const HORN_MEGABYTES: u32 = 2048;

/// Whether the Horn clauses `text` are satisfiable, asked of a z3 process of
/// their own that the bounds above stop.
pub(super) fn solve_horn(text: &str, rlimit: u64, seconds: u32) -> Reply {
    let Ok(mut child) = Command::new("z3")
        .args([
            "-in",
            "-smt2",
            &format!("-T:{seconds}"),
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
pub(super) fn horn(application: &Application, checked: &[Checked], registers: &[u16]) -> String {
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
        let holds = format!(
            "(and {} {} {})",
            relation(block, &names),
            checked_block.run.facts,
            held.join(" ")
        );
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
        text.push_str(super::super::COUNT8);
    }
    text.push_str(&clauses);
    text.push_str("(check-sat)\n");
    text
}

/// Whether `name` is a symbol for a value a block enters with.
pub(super) fn is_entry(name: &str) -> bool {
    name == "m"
        || ["s", "b", "a"].iter().any(|prefix| {
            name.strip_prefix(prefix).is_some_and(|rest| {
                !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit())
            })
        })
}

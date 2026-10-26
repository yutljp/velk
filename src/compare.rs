//! Function comparison and conservative annotation transfer between program versions.

mod transfer;

pub use transfer::{Item as AnnotationTransfer, Report as TransferReport};

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use serde::Serialize;

use crate::deadline::passed;
use crate::error::Result;
use crate::ir::{CType, Convention, Expr};
use crate::loader::{Function, Isa};
use crate::project::Target;
use crate::service::Binary;
use crate::xrefs::{Kind, Xref};

/// A one-to-one function match, with evidence and reviewable text differences.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionMatch {
    /// Function in the original binary.
    pub first: Function,
    /// Function in the updated binary.
    pub second: Function,
    /// Evidence used to establish this pair.
    pub rule: &'static str,
    /// Agreement of the matching evidence, from zero to one.
    pub similarity: f64,
    /// A unified replacement hunk of the printed C, or empty for equal text.
    pub c_diff: String,
    /// A unified replacement hunk of the optimized IR blocks.
    pub block_diff: String,
}

/// Comparison results, with changed functions first and failures kept visible.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    /// Matched functions whose bytes or printed C differ, in original address order.
    pub changed: Vec<FunctionMatch>,
    /// Matched functions with equal bytes and printed C on the same architecture.
    pub identical: Vec<FunctionMatch>,
    /// Unmatched original functions, including ambiguous candidates.
    pub only_first: Vec<Function>,
    /// Unmatched updated functions, including ambiguous candidates.
    pub only_second: Vec<Function>,
    /// Analysis failures qualified by binary side and function address.
    pub failures: Vec<String>,
    /// Annotation results when transfer was requested.
    pub transfer: Option<TransferReport>,
}

struct Entry {
    function: Function,
    hash: Option<String>,
    constants: BTreeSet<u64>,
    strings: BTreeSet<String>,
    calls: BTreeSet<u64>,
    code: Option<String>,
    blocks: String,
    block_starts: Vec<u64>,
    bytes: Option<Vec<u8>>,
    layout: Option<StorageLayout>,
    origins: Vec<Target>,
}

#[derive(PartialEq)]
struct StorageLayout {
    convention: Convention,
    parameters: Vec<(u16, CType)>,
    stack_parameters: Vec<(i64, u64, usize, CType)>,
    result: CType,
    variadic: bool,
}

struct Snapshot {
    entries: Vec<Entry>,
    references: Vec<Xref>,
    failures: Vec<String>,
    isa: Isa,
    data_targets: BTreeSet<u64>,
}

impl Snapshot {
    fn read(binary: &mut Binary, deadline: Option<Instant>) -> Result<Self> {
        if let Err(error) = binary.refresh_project() {
            return Err(error);
        }
        let mut snapshot = Self {
            entries: Vec::new(),
            references: Vec::new(),
            failures: Vec::new(),
            isa: binary.image().isa,
            data_targets: BTreeSet::new(),
        };
        let index = match binary.navigation(deadline) {
            Ok(index) => index,
            Err(error) => return Err(error),
        };
        snapshot.references = index.xrefs.clone();
        for failure in &index.failures {
            snapshot
                .failures
                .push(format!("0x{:x}: {}", failure.function, failure.error));
        }
        let strings = index.strings().to_vec();
        for reference in &snapshot.references {
            if binary
                .image()
                .section_at(reference.target)
                .is_some_and(|section| section.loaded && !section.executable)
            {
                snapshot.data_targets.insert(reference.target);
            }
        }
        // Use binary names, not names supplied by the annotations being transferred.
        let functions: Vec<_> = binary.image().functions.values().cloned().collect();
        for function in functions {
            if let Err(error) = passed(deadline) {
                return Err(error);
            }
            let bytes = function.size.and_then(|size| {
                binary
                    .image()
                    .read_vaddr(function.addr, size)
                    .map(<[u8]>::to_vec)
            });
            let mut entry = Entry {
                function,
                hash: None,
                constants: BTreeSet::new(),
                strings: BTreeSet::new(),
                calls: BTreeSet::new(),
                code: None,
                blocks: String::new(),
                block_starts: Vec::new(),
                bytes,
                layout: None,
                origins: Vec::new(),
            };
            for literal in &strings {
                if literal
                    .xrefs
                    .iter()
                    .any(|reference| reference.function == entry.function.addr)
                {
                    entry.strings.insert(literal.text.clone());
                }
            }
            for reference in &snapshot.references {
                if reference.function == entry.function.addr && is_call(reference.kind) {
                    entry.calls.insert(reference.target);
                }
            }
            match binary.analysis(entry.function.addr, deadline) {
                Ok(analysis) => {
                    entry.hash = Some(crate::sigs::shape_hash(&analysis.ir));
                    entry.blocks = analysis.ir.render();
                    entry.layout = Some(StorageLayout {
                        convention: analysis.ir.convention,
                        parameters: analysis
                            .ir
                            .params
                            .iter()
                            .map(|parameter| (parameter.index, parameter.ty.clone()))
                            .collect(),
                        stack_parameters: analysis
                            .ir
                            .stack_params
                            .iter()
                            .map(|parameter| {
                                (
                                    parameter.offset,
                                    parameter.size,
                                    parameter.position,
                                    parameter.ty.clone(),
                                )
                            })
                            .collect(),
                        result: analysis.ir.ret_type.clone(),
                        variadic: analysis.ir.variadic,
                    });
                    for origin in crate::project::origins(&analysis.ir) {
                        if let Ok(target) = serde_json::from_value(origin["target"].clone()) {
                            entry.origins.push(target);
                        }
                    }
                    for block in &analysis.ir.blocks {
                        entry.block_starts.push(block.start);
                        for statement in &block.stmts {
                            for operand in statement.operands() {
                                constants(operand, &mut entry.constants);
                            }
                        }
                    }
                }
                Err(error) => snapshot
                    .failures
                    .push(format!("0x{:x}: {error}", entry.function.addr)),
            }
            entry
                .constants
                .retain(|value| binary.image().section_at(*value).is_none());
            match binary.decompile(entry.function.addr, None, deadline) {
                Ok(code) => entry.code = Some(code),
                Err(error) => snapshot
                    .failures
                    .push(format!("0x{:x}: {error}", entry.function.addr)),
            }
            snapshot.entries.push(entry);
        }
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        Ok(snapshot)
    }
}

fn constants(expression: &Expr, values: &mut BTreeSet<u64>) {
    if let Expr::Const(value) = expression {
        values.insert(*value);
    }
    for child in crate::ir::visit::children(expression) {
        constants(child, values);
    }
}

fn is_call(kind: Kind) -> bool {
    matches!(kind, Kind::Call | Kind::TailCall | Kind::ResolvedCall)
}

fn names(function: &Function) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for name in function.name.iter().chain(&function.aliases) {
        names.insert(crate::loader::demangle_name(name));
    }
    names
}

struct Pair {
    first: usize,
    second: usize,
    rule: &'static str,
    similarity: f64,
}

fn unique_pairs(
    first: &Snapshot,
    second: &Snapshot,
    pairs: &mut Vec<Pair>,
    rule: &'static str,
    keys: impl Fn(&Entry) -> BTreeSet<String>,
    deadline: Option<Instant>,
) -> Result<()> {
    let used_first: BTreeSet<_> = pairs.iter().map(|pair| pair.first).collect();
    let used_second: BTreeSet<_> = pairs.iter().map(|pair| pair.second).collect();
    let mut by_key = BTreeMap::<String, BTreeSet<usize>>::new();
    for (at, entry) in second.entries.iter().enumerate() {
        if used_second.contains(&at) {
            continue;
        }
        for key in keys(entry) {
            by_key.entry(key).or_default().insert(at);
        }
    }
    let mut candidates = Vec::new();
    let mut incoming = BTreeMap::<usize, usize>::new();
    for (a, left) in first.entries.iter().enumerate() {
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        if used_first.contains(&a) {
            continue;
        }
        let mut found = BTreeSet::<usize>::new();
        for key in keys(left) {
            if let Some(matches) = by_key.get(&key) {
                found.extend(matches);
            }
        }
        for b in &found {
            *incoming.entry(*b).or_default() += 1;
        }
        if found.len() == 1 {
            candidates.push((a, *found.first().expect("one candidate exists")));
        }
    }
    for (a, b) in candidates {
        if incoming.get(&b) == Some(&1) {
            pairs.push(Pair {
                first: a,
                second: b,
                rule,
                similarity: 1.0,
            });
        }
    }
    Ok(())
}

fn features(snapshot: &Snapshot, at: usize, pairs: &[Pair], first: bool) -> BTreeSet<String> {
    let entry = &snapshot.entries[at];
    let mut features = BTreeSet::new();
    for text in &entry.strings {
        features.insert(format!("string:{text}"));
    }
    for value in &entry.constants {
        if *value > 16 && *value != u64::MAX {
            features.insert(format!("constant:{value}"));
        }
    }
    for (index, pair) in pairs.iter().enumerate() {
        let matched = if first { pair.first } else { pair.second };
        let neighbour = &snapshot.entries[matched];
        if entry.calls.contains(&neighbour.function.addr) {
            features.insert(format!("callee:{index}"));
        }
        if neighbour.calls.contains(&entry.function.addr) {
            features.insert(format!("caller:{index}"));
        }
    }
    features
}

fn context_pairs(
    first: &Snapshot,
    second: &Snapshot,
    pairs: &mut Vec<Pair>,
    deadline: Option<Instant>,
) -> Result<()> {
    loop {
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        let left: Vec<_> = (0..first.entries.len())
            .map(|at| features(first, at, pairs, true))
            .collect();
        let right: Vec<_> = (0..second.entries.len())
            .map(|at| features(second, at, pairs, false))
            .collect();
        let mut scores = Vec::new();
        for (a, lhs) in left.iter().enumerate() {
            if let Err(error) = passed(deadline) {
                return Err(error);
            }
            if pairs.iter().any(|pair| pair.first == a) || first.entries[a].hash.is_none() {
                continue;
            }
            for (b, rhs) in right.iter().enumerate() {
                if pairs.iter().any(|pair| pair.second == b) || second.entries[b].hash.is_none() {
                    continue;
                }
                let common: Vec<_> = lhs.intersection(rhs).collect();
                let shared_string = common.iter().any(|value| value.starts_with("string:"));
                let shared_neighbours = common
                    .iter()
                    .filter(|value| value.starts_with("caller:") || value.starts_with("callee:"))
                    .count();
                if common.len() < 2 || (!shared_string && shared_neighbours < 2) {
                    continue;
                }
                let union = lhs.union(rhs).count();
                let score = common.len() as f64 / union.max(1) as f64;
                if score >= 0.55 {
                    scores.push((a, b, score));
                }
            }
        }
        let mut added = Vec::new();
        for &(a, b, score) in &scores {
            let ambiguous = scores.iter().any(|&(other_a, other_b, other_score)| {
                (other_a == a || other_b == b)
                    && (other_a, other_b) != (a, b)
                    && other_score + 0.15 > score
            });
            if !ambiguous {
                added.push(Pair {
                    first: a,
                    second: b,
                    rule: "references",
                    similarity: score,
                });
            }
        }
        if added.is_empty() {
            return Ok(());
        }
        pairs.extend(added);
    }
}

/// Compares loaded binaries and optionally copies annotations into the second project.
/// Existing destination targets are always preserved. Ambiguous evidence stays unmatched.
pub fn compare(
    first: &mut Binary,
    second: &mut Binary,
    carry: bool,
    deadline: Option<Instant>,
) -> Result<Report> {
    let left = match Snapshot::read(first, deadline) {
        Ok(snapshot) => snapshot,
        Err(error) => return Err(error),
    };
    let right = match Snapshot::read(second, deadline) {
        Ok(snapshot) => snapshot,
        Err(error) => return Err(error),
    };
    let report = match finish(first, second, left, right, carry, deadline) {
        Ok(report) => report,
        Err(error) => return Err(error),
    };
    if carry && let Err(error) = second.refresh_project() {
        return Err(error);
    }
    Ok(report)
}

fn finish(
    first: &Binary,
    second: &Binary,
    left: Snapshot,
    right: Snapshot,
    carry: bool,
    deadline: Option<Instant>,
) -> Result<Report> {
    let mut pairs = Vec::new();
    if let Err(error) = unique_pairs(
        &left,
        &right,
        &mut pairs,
        "name",
        |entry| names(&entry.function),
        deadline,
    ) {
        return Err(error);
    }
    if left.isa == right.isa {
        if let Err(error) = unique_pairs(
            &left,
            &right,
            &mut pairs,
            "shape",
            |entry| match &entry.hash {
                Some(hash) => BTreeSet::from([format!(
                    "{hash}:{:?}:{:?}:{}",
                    entry.constants,
                    entry.strings,
                    entry.calls.len()
                )]),
                None => BTreeSet::new(),
            },
            deadline,
        ) {
            return Err(error);
        }
        if let Err(error) = context_pairs(&left, &right, &mut pairs, deadline) {
            return Err(error);
        }
    }
    let mut report = Report {
        changed: Vec::new(),
        identical: Vec::new(),
        only_first: Vec::new(),
        only_second: Vec::new(),
        failures: Vec::new(),
        transfer: None,
    };
    for pair in &pairs {
        let a = &left.entries[pair.first];
        let b = &right.entries[pair.second];
        let matched = FunctionMatch {
            first: a.function.clone(),
            second: b.function.clone(),
            rule: pair.rule,
            similarity: pair.similarity,
            c_diff: diff(
                a.code.as_deref().unwrap_or("/* C unavailable */"),
                b.code.as_deref().unwrap_or("/* C unavailable */"),
            ),
            block_diff: diff(&a.blocks, &b.blocks),
        };
        if left.isa == right.isa
            && a.bytes.is_some()
            && a.bytes == b.bytes
            && a.code.is_some()
            && a.code == b.code
        {
            report.identical.push(matched);
        } else {
            report.changed.push(matched);
        }
    }
    report.changed.sort_by_key(|matched| matched.first.addr);
    report.identical.sort_by_key(|matched| matched.first.addr);
    for (at, entry) in left.entries.iter().enumerate() {
        if !pairs.iter().any(|pair| pair.first == at) {
            report.only_first.push(entry.function.clone());
        }
    }
    for (at, entry) in right.entries.iter().enumerate() {
        if !pairs.iter().any(|pair| pair.second == at) {
            report.only_second.push(entry.function.clone());
        }
    }
    for failure in &left.failures {
        report.failures.push(format!("first: {failure}"));
    }
    for failure in &right.failures {
        report.failures.push(format!("second: {failure}"));
    }
    if let Err(error) = passed(deadline) {
        return Err(error);
    }
    if carry {
        report.transfer = match transfer::carry(first, second, &left, &right, &pairs, deadline) {
            Ok(report) => Some(report),
            Err(error) => return Err(error),
        };
    }
    Ok(report)
}

// A single replacement hunk keeps memory linear even for very large functions.
fn diff(first: &str, second: &str) -> String {
    if first == second {
        return String::new();
    }
    let left: Vec<_> = first.split_inclusive('\n').collect();
    let right: Vec<_> = second.split_inclusive('\n').collect();
    let prefix = left.iter().zip(&right).take_while(|(a, b)| a == b).count();
    let suffix = left[prefix..]
        .iter()
        .rev()
        .zip(right[prefix..].iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    let mut out = format!(
        "--- first\n+++ second\n@@ -{},{} +{},{} @@\n",
        if left.len() - suffix == prefix {
            prefix
        } else {
            prefix + 1
        },
        left.len() - prefix - suffix,
        if right.len() - suffix == prefix {
            prefix
        } else {
            prefix + 1
        },
        right.len() - prefix - suffix
    );
    for (marker, lines) in [
        ("-", &left[prefix..left.len() - suffix]),
        ("+", &right[prefix..right.len() - suffix]),
    ] {
        for line in lines {
            out.push_str(marker);
            out.push_str(line);
            if !line.ends_with('\n') {
                out.push_str("\n\\ No newline at end of file\n");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::diff;

    #[test]
    fn differences_preserve_hunk_positions_and_missing_newlines() {
        assert_eq!(
            diff("", "a\n"),
            "--- first\n+++ second\n@@ -0,0 +1,1 @@\n+a\n"
        );
        assert_eq!(
            diff("a\n", ""),
            "--- first\n+++ second\n@@ -1,1 +0,0 @@\n-a\n"
        );
        assert_eq!(
            diff("same\nbefore\nlast\n", "same\nafter\nlast\n"),
            "--- first\n+++ second\n@@ -2,1 +2,1 @@\n-before\n+after\n"
        );
        assert!(diff("a", "a\n").contains("\\ No newline at end of file"));
        assert!(diff("a", "a").is_empty());
    }
}

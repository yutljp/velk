//! Copies supported annotations without replacing destination targets.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use serde::Serialize;

use super::{Pair, Snapshot};
use crate::deadline::passed;
use crate::error::Result;
use crate::project::{self, Storage, Target};
use crate::service::Binary;
use crate::xrefs::Kind;

/// An annotation copied or skipped, with an explicit reason.
#[derive(Serialize)]
pub struct Item {
    /// Target in the original project.
    pub source: Target,
    /// Corresponding updated target, when established.
    pub destination: Option<Target>,
    /// Why the entry was copied or skipped.
    pub reason: &'static str,
}

/// Results of an atomic, non-overwriting project update.
#[derive(Default, Serialize)]
pub struct Report {
    /// New destination entries written in this update.
    pub copied: Vec<Item>,
    /// Source entries left uncopied.
    pub skipped: Vec<Item>,
}

fn name_used(name: &str, target: &Target, destination: &project::Project, binary: &Binary) -> bool {
    let scope = |target: &Target| match target {
        Target::Parameter { function, .. } | Target::Local { function, .. } => Some(*function),
        _ => None,
    };
    if destination.annotations.iter().any(|annotation| {
        annotation.target != *target
            && scope(&annotation.target) == scope(target)
            && annotation.name.as_deref() == Some(name)
    }) {
        return true;
    }
    let (Target::Function { address } | Target::Global { address }) = target else {
        return false;
    };
    for function in binary.image().functions.values() {
        if function.addr != *address
            && function
                .name
                .as_ref()
                .is_some_and(|symbol| crate::render::sanitize(symbol) == name)
        {
            return true;
        }
    }
    binary
        .image()
        .data_symbols
        .iter()
        .any(|(other, symbol)| other != address && crate::render::sanitize(symbol) == name)
}

// Every use in an eligible matched function must agree, in both directions.
fn globals(left: &Snapshot, right: &Snapshot, pairs: &[Pair]) -> BTreeMap<u64, u64> {
    type Uses = BTreeMap<u64, BTreeSet<(usize, usize, usize, Kind)>>;
    let mut first = Uses::new();
    let mut second = Uses::new();
    for (index, pair) in pairs.iter().enumerate() {
        let a = &left.entries[pair.first];
        let b = &right.entries[pair.second];
        if left.isa != right.isa
            || a.hash.is_none()
            || a.hash != b.hash
            || a.constants != b.constants
            || a.block_starts.len() != b.block_starts.len()
        {
            continue;
        }
        for (snapshot, entry, uses) in [(left, a, &mut first), (right, b, &mut second)] {
            for reference in &snapshot.references {
                if reference.function != entry.function.addr
                    || !matches!(reference.kind, Kind::Read | Kind::Write | Kind::Address)
                    || !snapshot.data_targets.contains(&reference.target)
                {
                    continue;
                }
                let Some(block) = entry
                    .block_starts
                    .iter()
                    .position(|start| *start == reference.block)
                else {
                    continue;
                };
                uses.entry(reference.target).or_default().insert((
                    index,
                    block,
                    reference.statement,
                    reference.kind,
                ));
            }
        }
    }
    let mut result = BTreeMap::new();
    for (address, uses) in &first {
        if first.values().filter(|other| *other == uses).count() != 1 {
            continue;
        }
        let mut candidates = second.iter().filter(|(_, other)| *other == uses);
        if let (Some((destination, _)), None) = (candidates.next(), candidates.next()) {
            result.insert(*address, *destination);
        }
    }
    result
}

fn target(
    source: &Target,
    left: &Snapshot,
    right: &Snapshot,
    pairs: &[Pair],
    globals: &BTreeMap<u64, u64>,
) -> Option<Target> {
    if let Target::Comment { address } = source {
        let mut destinations = BTreeSet::new();
        for pair in pairs {
            let a = &left.entries[pair.first];
            let b = &right.entries[pair.second];
            if *address == a.function.addr {
                destinations.insert(b.function.addr);
                continue;
            }
            if left.isa != right.isa || a.bytes.is_none() || a.bytes != b.bytes {
                continue;
            }
            let Some(offset) = address.checked_sub(a.function.addr) else {
                continue;
            };
            let Some(bytes) = &a.bytes else {
                continue;
            };
            if usize::try_from(offset).is_ok_and(|offset| offset < bytes.len())
                && let Some(mapped) = b.function.addr.checked_add(offset)
            {
                destinations.insert(mapped);
            }
        }
        return match destinations.len() {
            1 => Some(Target::Comment {
                address: *destinations.first().expect("one destination exists"),
            }),
            _ => None,
        };
    }
    let address = match source {
        Target::Function { address } => *address,
        Target::Signature { function }
        | Target::Parameter { function, .. }
        | Target::Local { function, .. } => *function,
        Target::Global { address } => {
            return globals
                .get(address)
                .map(|address| Target::Global { address: *address });
        }
        Target::Declaration { .. } => return Some(source.clone()),
        Target::Classification { .. } | Target::Comment { .. } => return None,
    };
    let Some(pair) = pairs
        .iter()
        .find(|pair| left.entries[pair.first].function.addr == address)
    else {
        return None;
    };
    let a = &left.entries[pair.first];
    let b = &right.entries[pair.second];
    let destination = b.function.addr;
    match source {
        Target::Function { .. } => Some(Target::Function {
            address: destination,
        }),
        _ if left.isa != right.isa || a.layout.is_none() || a.layout != b.layout => None,
        Target::Signature { .. } => Some(Target::Signature {
            function: destination,
        }),
        Target::Parameter { storage, .. } | Target::Local { storage, .. } => {
            if matches!(source, Target::Local { .. }) && (a.bytes.is_none() || a.bytes != b.bytes) {
                return None;
            }
            if !a.origins.contains(source) {
                return None;
            }
            let mut storage = storage.clone();
            if let Storage::Definition { block, .. } = &mut storage {
                let Some(index) = a.block_starts.iter().position(|start| start == block) else {
                    return None;
                };
                let Some(start) = b.block_starts.get(index) else {
                    return None;
                };
                *block = *start;
            }
            let mapped = if matches!(source, Target::Parameter { .. }) {
                Target::Parameter {
                    function: destination,
                    storage,
                }
            } else {
                Target::Local {
                    function: destination,
                    storage,
                }
            };
            b.origins.contains(&mapped).then_some(mapped)
        }
        _ => None,
    }
}

pub(super) fn carry(
    first: &Binary,
    second: &Binary,
    left: &Snapshot,
    right: &Snapshot,
    pairs: &[Pair],
    deadline: Option<Instant>,
) -> Result<Report> {
    let same_project = match (
        std::fs::canonicalize(first.project_path()),
        std::fs::canonicalize(second.project_path()),
    ) {
        (Ok(first), Ok(second)) => first == second,
        _ => first.project_path() == second.project_path(),
    };
    if first.path() == second.path() || same_project {
        return Err(project::error(
            "comparison_destination",
            "annotation transfer requires distinct binaries and project files",
        ));
    }
    let source = match project::load_at(first.path(), first.project_path(), &mut None) {
        Ok(Some(project)) => project,
        Ok(None) => return Ok(Report::default()),
        Err(error) => return Err(error),
    };
    let globals = globals(left, right, pairs);
    let raw = second.input_options().raw.clone();
    project::update_cached(
        second.path(),
        second.project_path(),
        &mut None,
        |destination| {
            if let Err(error) = destination.set_raw_mapping(raw.as_ref()) {
                return Err(error);
            }
            let mut report = Report::default();
            let conflicting_types = source.annotations.iter().any(|annotation| {
                matches!(annotation.target, Target::Declaration { .. })
                    && destination
                        .get(&annotation.target)
                        .is_some_and(|existing| existing != annotation)
            });
            for annotation in &source.annotations {
                if let Err(error) = passed(deadline) {
                    return Err(error);
                }
                let mapped = target(&annotation.target, left, right, pairs, &globals);
                let reason = match &mapped {
                    None => Some("no unambiguous compatible target"),
                    Some(target) if destination.get(target).is_some() => {
                        Some("destination already has an annotation")
                    }
                    Some(target)
                        if annotation
                            .name
                            .as_ref()
                            .is_some_and(|name| name_used(name, target, destination, second)) =>
                    {
                        Some("name is already used at the destination")
                    }
                    _ if conflicting_types
                        && (annotation.c_type.is_some()
                            || matches!(
                                annotation.target,
                                Target::Signature { .. } | Target::Declaration { .. }
                            )) =>
                    {
                        Some("destination has a conflicting type declaration")
                    }
                    _ => None,
                };
                if let Some(reason) = reason {
                    report.skipped.push(Item {
                        source: annotation.target.clone(),
                        destination: mapped,
                        reason,
                    });
                    continue;
                }
                let mapped = mapped.expect("unmapped targets were skipped");
                let mut copied = annotation.clone();
                copied.target = mapped.clone();
                destination.set(copied);
                report.copied.push(Item {
                    source: annotation.target.clone(),
                    destination: Some(mapped),
                    reason: "matching target is unannotated",
                });
            }
            if let Err(error) = passed(deadline) {
                return Err(error);
            }
            Ok(report)
        },
    )
}

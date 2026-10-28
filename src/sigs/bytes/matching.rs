//! Full-body matching and conservative direct-call graph confirmation.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::time::Instant;

use super::{DirectCall, MAX_BYTES, MIN_BYTES, constants, normalize, registers};
use crate::deadline::passed;
use crate::error::Result;
use crate::loader::{ArmMode, Image, Isa};
use crate::sigs::{Candidate, Certainty, Database, Entry, Evidence};

pub(crate) enum MatchScope {
    Unnamed,
    All,
}

struct PossibleMatch<'database> {
    entries: Vec<&'database Entry>,
    calls: Vec<DirectCall>,
    name_eligible: bool,
}

pub(crate) fn identify(
    image: &Image,
    database: &Database,
    deadline: Option<Instant>,
    scope: MatchScope,
) -> Result<Vec<(u64, Evidence)>> {
    if matches!(image.isa, Isa::Arm32 | Isa::AArch64)
        && image.byte_order() != Some(object::Endianness::Little)
    {
        return Ok(Vec::new());
    }
    let mut index: HashMap<&[u8], Vec<&Entry>> = HashMap::new();
    let mut sizes = HashSet::new();
    for entry in &database.entries {
        if entry.isa == image.isa && entry.bytes.len() >= MIN_BYTES {
            index.entry(&entry.bytes).or_default().push(entry);
            sizes.insert(entry.bytes.len() as u64);
        }
    }
    let functions: Vec<_> = image.functions.values().collect();
    let found = crate::parallel::map(&functions, |function| {
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        if matches!(scope, MatchScope::Unnamed) && function.name.is_some() {
            return Ok(None);
        }
        if super::call_inside_named_function(image, function) {
            return Ok(None);
        }
        let Some(size) = function.size.filter(|size| *size <= MAX_BYTES) else {
            return Ok(None);
        };
        if !(0..=64).any(|padding| {
            size.checked_sub(padding)
                .is_some_and(|n| sizes.contains(&n))
        }) || (image.isa == Isa::Arm32 && image.arm_mode(function.addr) != ArmMode::Arm)
        {
            return Ok(None);
        }
        let Some(bytes) = image.read_vaddr(function.addr, size) else {
            return Ok(None);
        };
        let Some(body) = normalize::normalize(image.isa, bytes, function.addr, &HashSet::new())
        else {
            return Ok(None);
        };
        let mut entries = index
            .get(body.bytes.as_slice())
            .cloned()
            .unwrap_or_default();
        if let Some(alternative) = registers::alternative(image.isa, &body)
            && let Some(others) = index.get(alternative.as_slice())
        {
            entries.extend_from_slice(others);
        }
        if entries.is_empty() {
            return Ok(None);
        }
        let Some(constants) = constants::image_constants(image, &body) else {
            return Ok(None);
        };
        let entries: Vec<_> = entries
            .into_iter()
            .filter(|entry| entry.constants == constants)
            .collect();
        if entries.is_empty() {
            return Ok(None);
        }
        let evidence = body.name_eligible.then(|| Evidence {
            candidates: descriptions(&entries, database),
            certainty: Certainty::Unconfirmed,
        });
        Ok(Some((
            function.addr,
            PossibleMatch {
                entries,
                calls: body.calls,
                name_eligible: body.name_eligible,
            },
            evidence,
        )))
    });
    let mut possible = BTreeMap::new();
    let mut evidence = BTreeMap::new();
    for result in found {
        match result {
            Ok(Some((addr, body, description))) => {
                possible.insert(addr, body);
                if let Some(description) = description {
                    evidence.insert(addr, description);
                }
            }
            Ok(None) => {}
            Err(error) => return Err(error),
        }
    }
    // Keep alternatives until the graph can distinguish their destinations.
    loop {
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        let mut rejected = Vec::new();
        for (addr, body) in &possible {
            for (index, entry) in body.entries.iter().enumerate() {
                if entry.calls.len() != body.calls.len()
                    || body.calls.iter().zip(&entry.calls).any(|(call, expected)| {
                        !known_name(image, call.target, expected)
                            && possible.get(&call.target).is_none_or(|callee| {
                                !callee.entries.iter().any(|entry| entry.name == *expected)
                            })
                    })
                {
                    rejected.push((*addr, index));
                }
            }
        }
        if rejected.is_empty() {
            break;
        }
        for (addr, index) in rejected.into_iter().rev() {
            if let Some(body) = possible.get_mut(&addr) {
                body.entries.remove(index);
            }
        }
        possible.retain(|_, body| !body.entries.is_empty());
    }
    let mut addresses: HashMap<&str, HashSet<u64>> = HashMap::new();
    for (address, body) in &possible {
        for entry in &body.entries {
            addresses
                .entry(entry.name.as_str())
                .or_default()
                .insert(*address);
        }
    }
    for function in image.functions.values() {
        if !function
            .sources
            .contains(&crate::loader::NameSource::Signature)
            && let Some(name) = &function.name
            && let Some(known) = addresses.get_mut(name.as_str())
        {
            known.insert(function.addr);
        }
        for alias in &function.aliases {
            if let Some(known) = addresses.get_mut(alias.as_str()) {
                known.insert(function.addr);
            }
        }
    }
    let mut confirmed = HashSet::new();
    for (addr, body) in &possible {
        if unique_name(&body.entries) && addresses[body.entries[0].name.as_str()].len() == 1 {
            confirmed.insert(*addr);
        }
        if let Some(result) = evidence.get_mut(addr) {
            result.candidates = descriptions(&body.entries, database);
            if !unique_name(&body.entries) {
                result.certainty = Certainty::Ambiguous;
            }
        }
    }
    // Ambiguous destinations cannot confirm a caller, even in a cycle.
    loop {
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        let mut rejected = Vec::new();
        for addr in &confirmed {
            let body = &possible[addr];
            let valid = body
                .entries
                .iter()
                .any(|entry| destinations_confirmed(image, body, entry, &confirmed, &possible));
            if !valid {
                rejected.push(*addr);
            }
        }
        if rejected.is_empty() {
            break;
        }
        for addr in rejected {
            confirmed.remove(&addr);
        }
    }
    for addr in &confirmed {
        let body = &possible[addr];
        if !body.name_eligible {
            continue;
        }
        let entries: Vec<_> = body
            .entries
            .iter()
            .copied()
            .filter(|entry| destinations_confirmed(image, body, entry, &confirmed, &possible))
            .collect();
        let result = evidence
            .get_mut(addr)
            .expect("confirmed candidates have evidence");
        result.candidates = descriptions(&entries, database);
        result.certainty = Certainty::Exact;
    }
    Ok(evidence.into_iter().collect())
}

fn destinations_confirmed(
    image: &Image,
    body: &PossibleMatch<'_>,
    entry: &Entry,
    confirmed: &HashSet<u64>,
    possible: &BTreeMap<u64, PossibleMatch<'_>>,
) -> bool {
    body.calls.iter().zip(&entry.calls).all(|(call, expected)| {
        known_name(image, call.target, expected)
            || (confirmed.contains(&call.target)
                && possible[&call.target].entries[0].name == *expected)
    })
}

fn known_name(image: &Image, target: u64, expected: &str) -> bool {
    image.functions.get(&target).is_some_and(|function| {
        (!function
            .sources
            .contains(&crate::loader::NameSource::Signature)
            && function.name.as_deref() == Some(expected))
            || function.aliases.iter().any(|alias| alias == expected)
    })
}

fn unique_name(entries: &[&Entry]) -> bool {
    entries.iter().all(|entry| entry.name == entries[0].name)
}

fn descriptions(entries: &[&Entry], database: &Database) -> Vec<Candidate> {
    let mut candidates = BTreeSet::new();
    for entry in entries {
        candidates.insert(Candidate {
            name: entry.name.clone(),
            set: entry
                .set
                .clone()
                .unwrap_or_else(|| database.sources.join(", ")),
        });
    }
    candidates.into_iter().collect()
}

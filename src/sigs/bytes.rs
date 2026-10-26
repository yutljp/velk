//! Conservative instruction signatures for objects, archives, and loaded binaries.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::time::Instant;

use object::{Object, ObjectSection, ObjectSymbol};

use super::{Database, Entry};
use crate::deadline::passed;
use crate::error::{Error, Result};
use crate::loader::{Image, Isa};

mod normalize;
#[cfg(test)]
use normalize::normalize;

const MIN_BYTES: usize = 32;
const MAX_BYTES: u64 = 1 << 20;

#[derive(Debug, PartialEq)]
struct DirectCall {
    offset: usize,
    width: usize,
    target: u64,
}

struct Body {
    bytes: Vec<u8>,
    calls: Vec<DirectCall>,
}

fn make_entry(name: String, isa: Isa, body: Body, calls: Vec<String>) -> Entry {
    Entry {
        name,
        isa,
        size: body.bytes.len() as u64,
        hash: String::new(),
        tokens: Vec::new(),
        bytes: body.bytes,
        calls,
    }
}

pub(crate) fn image_entries(image: &Image, deadline: Option<Instant>) -> Result<Vec<Entry>> {
    let functions: Vec<_> = image.functions.values().collect();
    let found = crate::parallel::map(&functions, |function| {
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        let (Some(name), Some(size)) = (&function.name, function.size) else {
            return Ok(None);
        };
        if size > MAX_BYTES {
            return Ok(None);
        }
        let Some(bytes) = image.read_vaddr(function.addr, size) else {
            return Ok(None);
        };
        let Some(body) = normalize::normalize(image.isa, bytes, function.addr, &HashSet::new())
        else {
            return Ok(None);
        };
        let calls: Option<Vec<_>> = body
            .calls
            .iter()
            .map(|call| {
                image
                    .functions
                    .get(&call.target)
                    .and_then(|f| f.name.clone())
            })
            .collect();
        let Some(calls) = calls else {
            return Ok(None);
        };
        Ok(Some(make_entry(name.clone(), image.isa, body, calls)))
    });
    let mut entries = Vec::new();
    for result in found {
        match result {
            Ok(Some(entry)) => entries.push(entry),
            Ok(None) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(entries)
}

pub(crate) fn identify(
    image: &Image,
    database: &Database,
    deadline: Option<Instant>,
) -> Result<Vec<(u64, String)>> {
    let mut index: HashMap<&[u8], Vec<&Entry>> = HashMap::new();
    for entry in &database.entries {
        if entry.isa == image.isa && entry.bytes.len() >= MIN_BYTES {
            index.entry(&entry.bytes).or_default().push(entry);
        }
    }
    let functions: Vec<_> = image.functions.values().collect();
    let found = crate::parallel::map(&functions, |function| {
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        let Some(size) = function.size.filter(|size| *size <= MAX_BYTES) else {
            return Ok(None);
        };
        let Some(bytes) = image.read_vaddr(function.addr, size) else {
            return Ok(None);
        };
        let Some(body) = normalize::normalize(image.isa, bytes, function.addr, &HashSet::new())
        else {
            return Ok(None);
        };
        let Some(entries) = index.get(body.bytes.as_slice()) else {
            return Ok(None);
        };
        let first = entries[0];
        // Repeated copies of the same signature are harmless; aliases are ambiguous.
        if entries
            .iter()
            .any(|entry| entry.name != first.name || entry.calls != first.calls)
            || first.calls.len() != body.calls.len()
        {
            return Ok(None);
        }
        Ok(Some((function.addr, (first, body.calls))))
    });
    let mut candidates = BTreeMap::new();
    for result in found {
        match result {
            Ok(Some((addr, candidate))) => {
                candidates.insert(addr, candidate);
            }
            Ok(None) => {}
            Err(error) => return Err(error),
        }
    }

    // Prune until every direct edge agrees, including recursive components.
    loop {
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        let rejected: Vec<_> = candidates
            .iter()
            .filter_map(|(addr, (entry, calls))| {
                calls
                    .iter()
                    .zip(&entry.calls)
                    .any(|(call, expected)| {
                        candidates
                            .get(&call.target)
                            .is_none_or(|(callee, _)| &callee.name != expected)
                    })
                    .then_some(*addr)
            })
            .collect();
        if rejected.is_empty() {
            break;
        }
        for addr in rejected {
            candidates.remove(&addr);
        }
    }
    // One name cannot identify multiple distinct functions in the target.
    let mut counts = HashMap::new();
    for (entry, _) in candidates.values() {
        *counts.entry(&entry.name).or_insert(0) += 1;
    }
    let duplicate: HashSet<_> = candidates
        .iter()
        .filter_map(|(addr, (entry, _))| (counts[&entry.name] != 1).then_some(*addr))
        .collect();
    // Removing duplicate destinations must also remove their callers.
    let mut rejected = duplicate;
    loop {
        let previous = rejected.len();
        for (addr, (_, calls)) in &candidates {
            if calls.iter().any(|call| rejected.contains(&call.target)) {
                rejected.insert(*addr);
            }
        }
        if rejected.len() == previous {
            break;
        }
    }
    Ok(candidates
        .into_iter()
        .filter(|(addr, _)| !rejected.contains(addr))
        .map(|(addr, (entry, _))| (addr, entry.name.clone()))
        .collect())
}

/// Builds signatures directly from an object or archive without lifting its functions.
pub fn build(path: &Path, deadline: Option<Instant>) -> Result<Database> {
    if let Err(error) = passed(deadline) {
        return Err(error);
    }
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(source) => {
            return Err(Error::Io {
                path: path.to_owned(),
                source,
            });
        }
    };
    let mut entries = Vec::new();
    let mut sources = Vec::new();
    let source = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    if data.starts_with(b"!<arch>\n") {
        let archive = match object::read::archive::ArchiveFile::parse(data.as_slice()) {
            Ok(archive) => archive,
            Err(source) => {
                return Err(Error::Object {
                    path: path.to_owned(),
                    source,
                });
            }
        };
        for member in archive.members() {
            if let Err(error) = passed(deadline) {
                return Err(error);
            }
            let member = match member {
                Ok(member) => member,
                Err(source) => {
                    return Err(Error::Object {
                        path: path.to_owned(),
                        source,
                    });
                }
            };
            let bytes = match member.data(data.as_slice()) {
                Ok(bytes) => bytes,
                Err(source) => {
                    return Err(Error::Object {
                        path: path.to_owned(),
                        source,
                    });
                }
            };
            if let Ok(file) = object::File::parse(bytes) {
                if let Err(error) = object_entries(&file, &mut entries, deadline) {
                    return Err(error);
                }
                sources.push(format!(
                    "{}:{}",
                    source,
                    String::from_utf8_lossy(member.name())
                ));
            }
        }
    } else if let Ok(file) = object::File::parse(data.as_slice())
        && file.kind() == object::ObjectKind::Relocatable
    {
        if let Err(error) = object_entries(&file, &mut entries, deadline) {
            return Err(error);
        }
        sources.push(source);
    } else {
        let image = match crate::loader::load(path) {
            Ok(image) => image,
            Err(error) => return Err(error),
        };
        entries = match image_entries(&image, deadline) {
            Ok(entries) => entries,
            Err(error) => return Err(error),
        };
        sources.push(source);
    }
    let mut database = Database::new(entries);
    database.sources = sources;
    Ok(database)
}

fn object_entries(
    file: &object::File<'_>,
    entries: &mut Vec<Entry>,
    deadline: Option<Instant>,
) -> Result<()> {
    let isa = match file.architecture() {
        object::Architecture::X86_64 => Isa::X86_64,
        object::Architecture::Aarch64 => Isa::AArch64,
        _ => return Ok(()),
    };
    for section in file.sections() {
        if section.kind() != object::SectionKind::Text {
            continue;
        }
        let Ok(data) = section.data() else {
            continue;
        };
        let mut symbols: Vec<_> = file
            .symbols()
            .filter(|s| {
                s.kind() == object::SymbolKind::Text && s.section_index() == Some(section.index())
            })
            .collect();
        symbols.sort_by_key(|s| s.address());
        let relocations: Vec<_> = section.relocations().collect();
        for (index, symbol) in symbols.iter().enumerate() {
            if let Err(error) = passed(deadline) {
                return Err(error);
            }
            let Ok(name) = symbol.name() else {
                continue;
            };
            let Some(offset) = symbol
                .address()
                .checked_sub(section.address())
                .and_then(|v| usize::try_from(v).ok())
            else {
                continue;
            };
            let end = if symbol.size() != 0 {
                symbol.address().checked_add(symbol.size())
            } else {
                symbols[index + 1..]
                    .iter()
                    .find(|s| s.address() > symbol.address())
                    .map(|s| s.address())
                    .or_else(|| section.address().checked_add(data.len() as u64))
            };
            let Some(end) = end
                .and_then(|v| v.checked_sub(section.address()))
                .and_then(|v| usize::try_from(v).ok())
            else {
                continue;
            };
            let Some(bytes) = data.get(offset..end) else {
                continue;
            };
            let relevant: Vec<_> = relocations
                .iter()
                .filter(|(at, _)| (*at as u128) >= offset as u128 && (*at as u128) < end as u128)
                .collect();
            let relocated: HashSet<usize> = relevant
                .iter()
                .map(|(at, _)| (*at as usize).saturating_sub(offset))
                .collect();
            let Some(body) = normalize::normalize(isa, bytes, symbol.address(), &relocated) else {
                continue;
            };
            let mut calls = Vec::new();
            let mut valid = true;
            // Only direct branch relocations are supported. Data references are not wildcarded.
            for (at, relocation) in &relevant {
                let relative = (*at as usize).saturating_sub(offset);
                if !matches!(relocation.target(), object::RelocationTarget::Symbol(_)) {
                    valid = false;
                    break;
                }
                let branch = body.calls.iter().any(|call| {
                    let DirectCall {
                        offset: start,
                        width,
                        ..
                    } = call;
                    let encoded = bytes.get(*start..start.saturating_add(*width));
                    let zero_addend = match (isa, encoded) {
                        (Isa::X86_64, Some(encoded)) => encoded.iter().all(|byte| *byte == 0),
                        (Isa::AArch64, Some(encoded)) if encoded.len() == 4 => {
                            u32::from_le_bytes(encoded.try_into().unwrap_or_default()) & 0x03ff_ffff
                                == 0
                        }
                        _ => false,
                    };
                    *start == relative
                        && zero_addend
                        && ((isa == Isa::X86_64
                            && *width == 4
                            && matches!(
                                relocation.kind(),
                                object::RelocationKind::Relative
                                    | object::RelocationKind::PltRelative
                            )
                            && relocation.size() == 32
                            && relocation.addend() == -4)
                            || (isa == Isa::AArch64
                                && relocation.size() == 26
                                && matches!(
                                    relocation.kind(),
                                    object::RelocationKind::Relative
                                        | object::RelocationKind::PltRelative
                                )
                                && match relocation.flags() {
                                    object::RelocationFlags::MachO { r_type, .. } => r_type.0 == 2,
                                    object::RelocationFlags::Elf { r_type } => {
                                        matches!(r_type.0, 282 | 283)
                                    }
                                    _ => false,
                                }
                                && relocation.addend() == 0))
                });
                if !branch {
                    valid = false;
                    break;
                }
            }
            if !valid {
                continue;
            }
            for call in &body.calls {
                let DirectCall {
                    offset: start,
                    target,
                    ..
                } = call;
                let relocation = relevant
                    .iter()
                    .find(|(at, _)| (*at as usize).saturating_sub(offset) == *start);
                let name = match relocation {
                    Some((_, relocation)) => {
                        let object::RelocationTarget::Symbol(index) = relocation.target() else {
                            valid = false;
                            break;
                        };
                        file.symbol_by_index(index)
                            .ok()
                            .filter(|symbol| {
                                matches!(
                                    symbol.kind(),
                                    object::SymbolKind::Text | object::SymbolKind::Unknown
                                )
                            })
                            .and_then(|symbol| symbol.name().ok().map(str::to_owned))
                    }
                    None => file
                        .symbols()
                        .find(|symbol| {
                            symbol.kind() == object::SymbolKind::Text
                                && symbol.section_index() == Some(section.index())
                                && symbol.address() == *target
                        })
                        .and_then(|symbol| symbol.name().ok().map(str::to_owned)),
                };
                let Some(name) = name else {
                    valid = false;
                    break;
                };
                calls.push(crate::loader::demangle_name(&name));
            }
            if valid {
                entries.push(make_entry(
                    crate::loader::demangle_name(name),
                    isa,
                    body,
                    calls,
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;

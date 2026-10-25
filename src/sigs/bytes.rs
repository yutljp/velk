//! Conservative instruction signatures for objects, archives, and loaded binaries.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::time::Instant;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic};
use object::{Object, ObjectSection, ObjectSymbol};
use yaxpeax_arm::armv8::a64;

use super::{Database, Entry};
use crate::deadline::passed;
use crate::error::{Error, Result};
use crate::loader::{Image, Isa};

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

fn normalize(isa: Isa, bytes: &[u8], addr: u64, relocated: &HashSet<usize>) -> Option<Body> {
    if bytes.len() < MIN_BYTES || bytes.len() as u64 > MAX_BYTES {
        return None;
    }
    let Some(end) = addr.checked_add(bytes.len() as u64) else {
        return None;
    };
    let mut information = 0usize;
    let mut body = Body {
        bytes: bytes.to_vec(),
        calls: Vec::new(),
    };
    match isa {
        Isa::X86_64 => {
            let mut decoder = Decoder::with_ip(64, bytes, addr, DecoderOptions::NONE);
            let mut last_code_end = 0;
            let mut last_flow = FlowControl::Next;
            let mut local_targets = Vec::new();
            while decoder.can_decode() {
                let offset = decoder.position();
                let instruction = decoder.decode();
                if instruction.is_invalid() {
                    return None;
                }
                if instruction.is_ip_rel_memory_operand() {
                    return None;
                }
                let flow = instruction.flow_control();
                if !matches!(instruction.mnemonic(), Mnemonic::Nop | Mnemonic::Int3) {
                    information += instruction.len();
                    last_code_end = decoder.position();
                    last_flow = flow;
                }
                if matches!(
                    flow,
                    FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
                ) {
                    let target = instruction.near_branch_target();
                    if (addr..end).contains(&target) {
                        local_targets.push(target);
                    } else if flow == FlowControl::ConditionalBranch {
                        return None;
                    }
                }
                if matches!(
                    flow,
                    FlowControl::IndirectCall | FlowControl::IndirectBranch
                ) {
                    return None;
                }
                if matches!(flow, FlowControl::Call | FlowControl::UnconditionalBranch) {
                    let target = instruction.near_branch_target();
                    let constants = decoder.get_constant_offsets(&instruction);
                    let Some(start) = offset.checked_add(constants.immediate_offset()) else {
                        return None;
                    };
                    let width = constants.immediate_size();
                    if flow == FlowControl::Call
                        || !(addr..end).contains(&target)
                        || relocated.contains(&start)
                    {
                        if width == 0 {
                            return None;
                        }
                        let Some(end) = start.checked_add(width) else {
                            return None;
                        };
                        let Some(destination) = body.bytes.get_mut(start..end) else {
                            return None;
                        };
                        destination.fill(0);
                        body.calls.push(DirectCall {
                            offset: start,
                            width,
                            target,
                        });
                    }
                }
            }
            if matches!(
                last_flow,
                FlowControl::Return | FlowControl::UnconditionalBranch
            ) {
                let Some(code_end) = addr.checked_add(last_code_end as u64) else {
                    return None;
                };
                if local_targets.iter().any(|target| *target >= code_end) {
                    return None;
                }
                body.bytes.truncate(last_code_end);
            }
        }
        Isa::AArch64 => {
            use yaxpeax_arch::{Decoder as _, ReaderBuilder};
            if !bytes.len().is_multiple_of(4) {
                return None;
            }
            let mut reader = ReaderBuilder::<u64, u8>::read_at(bytes, 0);
            let decoder = a64::InstDecoder::default();
            let mut last_code_end = 0;
            let mut last_terminal = false;
            let mut local_targets = Vec::new();
            let chunks = bytes.as_chunks::<4>().0;
            for (index, chunk) in chunks.iter().enumerate() {
                let Ok(instruction) = decoder.decode(&mut reader) else {
                    return None;
                };
                if matches!(
                    instruction.opcode,
                    a64::Opcode::BR
                        | a64::Opcode::BLR
                        | a64::Opcode::BRAA
                        | a64::Opcode::BRAAZ
                        | a64::Opcode::BRAB
                        | a64::Opcode::BRABZ
                        | a64::Opcode::BLRAA
                        | a64::Opcode::BLRAAZ
                        | a64::Opcode::BLRAB
                        | a64::Opcode::BLRABZ
                ) {
                    return None;
                }
                let offset = index * 4;
                let word = u32::from_le_bytes(*chunk);
                if word != 0xd503_201f && word != 0 {
                    information += 4;
                    last_code_end = offset + 4;
                    last_terminal = word & 0xfc00_0000 == 0x1400_0000
                        || matches!(
                            instruction.opcode,
                            a64::Opcode::RET | a64::Opcode::RETAA | a64::Opcode::RETAB
                        );
                }
                // PC-relative data can change independently of the function body.
                if word & 0x1f00_0000 == 0x1000_0000 || word & 0x3b00_0000 == 0x1800_0000 {
                    return None;
                }
                let conditional =
                    word & 0xff00_0010 == 0x5400_0000 || word & 0x7e00_0000 == 0x3400_0000;
                let test_bit = word & 0x7e00_0000 == 0x3600_0000;
                if conditional || test_bit {
                    let delta = if test_bit {
                        (((word >> 5) & 0x3fff) << 18) as i32 >> 16
                    } else {
                        (((word >> 5) & 0x7ffff) << 13) as i32 >> 11
                    };
                    let Some(target) = addr
                        .checked_add(offset as u64)
                        .and_then(|pc| pc.checked_add_signed(i64::from(delta)))
                    else {
                        return None;
                    };
                    if !(addr..end).contains(&target) {
                        return None;
                    }
                    local_targets.push(target);
                }
                if word & 0x7c00_0000 == 0x1400_0000 {
                    let delta = ((word << 6) as i32 >> 4) as i64;
                    let Some(target) = addr
                        .checked_add(offset as u64)
                        .and_then(|pc| pc.checked_add_signed(delta))
                    else {
                        return None;
                    };
                    if (addr..end).contains(&target) {
                        local_targets.push(target);
                    }
                    if word & 0x8000_0000 != 0
                        || !(addr..end).contains(&target)
                        || relocated.contains(&offset)
                    {
                        body.bytes[offset..offset + 4]
                            .copy_from_slice(&(word & 0xfc00_0000).to_le_bytes());
                        body.calls.push(DirectCall {
                            offset,
                            width: 4,
                            target,
                        });
                    }
                }
            }
            if last_terminal {
                let Some(code_end) = addr.checked_add(last_code_end as u64) else {
                    return None;
                };
                if local_targets.iter().any(|target| *target >= code_end) {
                    return None;
                }
                body.bytes.truncate(last_code_end);
            }
        }
        Isa::Arm32 | Isa::Unsupported => return None,
    }
    if body.bytes.len() < MIN_BYTES {
        return None;
    }
    if information.saturating_sub(body.calls.iter().map(|call| call.width).sum()) < 24 {
        return None;
    }
    Some(body)
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

fn image_entries(image: &Image, deadline: Option<Instant>) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    for function in image.functions.values() {
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        let (Some(name), Some(size)) = (&function.name, function.size) else {
            continue;
        };
        if size > MAX_BYTES {
            continue;
        }
        let Some(bytes) = image.read_vaddr(function.addr, size) else {
            continue;
        };
        let Some(body) = normalize(image.isa, bytes, function.addr, &HashSet::new()) else {
            continue;
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
            continue;
        };
        entries.push(make_entry(name.clone(), image.isa, body, calls));
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
    let mut candidates = BTreeMap::new();
    for function in image.functions.values() {
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        let Some(size) = function.size.filter(|size| *size <= MAX_BYTES) else {
            continue;
        };
        let Some(bytes) = image.read_vaddr(function.addr, size) else {
            continue;
        };
        let Some(body) = normalize(image.isa, bytes, function.addr, &HashSet::new()) else {
            continue;
        };
        let Some(entries) = index.get(body.bytes.as_slice()) else {
            continue;
        };
        let first = entries[0];
        // Repeated copies of the same signature are harmless; aliases are ambiguous.
        if entries
            .iter()
            .any(|entry| entry.name != first.name || entry.calls != first.calls)
            || first.calls.len() != body.calls.len()
        {
            continue;
        }
        candidates.insert(function.addr, (first, body.calls));
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
            let Some(body) = normalize(isa, bytes, symbol.address(), &relocated) else {
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

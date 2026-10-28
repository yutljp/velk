//! Conservative instruction signatures for objects, archives, and loaded binaries.

use std::collections::HashSet;
use std::path::Path;
use std::time::Instant;

use object::{Object, ObjectSection, ObjectSymbol};

use super::{Database, Entry};
use crate::deadline::passed;
use crate::error::{Error, Result};
use crate::loader::{Function, Image, Isa, NameSource};

mod constants;
mod discover;
pub(crate) use discover::arm32 as discover_arm32;
mod matching;
mod normalize;
mod registers;
pub(crate) use matching::{MatchScope, identify};
#[cfg(test)]
use normalize::normalize;

const MIN_BYTES: usize = 4;
const MIN_NAMED_BYTES: usize = 32;
const MAX_BYTES: u64 = 1 << 20;

#[derive(Debug, PartialEq)]
struct DirectCall {
    offset: usize,
    width: usize,
    target: u64,
}

struct ConstantRead {
    offset: usize,
    next: usize,
    target: u64,
    size: usize,
}

struct Body {
    bytes: Vec<u8>,
    calls: Vec<DirectCall>,
    references: Vec<ConstantRead>,
    name_eligible: bool,
}

fn make_entry(
    name: String,
    isa: Isa,
    body: Body,
    calls: Vec<String>,
    constants: Vec<Vec<u8>>,
) -> Entry {
    Entry {
        name,
        isa,
        size: body.bytes.len() as u64,
        hash: String::new(),
        tokens: Vec::new(),
        bytes: body.bytes,
        calls,
        set: None,
        constants,
    }
}

pub(crate) fn has_unnamed_candidates(image: &Image) -> bool {
    // Normalization cannot lengthen a body, so shorter functions cannot produce naming evidence.
    // ARM discovery can find functions outside the current function extents.
    for function in image.functions.values() {
        if function.name.is_some() || call_inside_named_function(image, function) {
            continue;
        }
        if image.isa == Isa::Arm32 {
            return true;
        }
        let Some(size) = function
            .size
            .filter(|size| (MIN_NAMED_BYTES as u64..=MAX_BYTES).contains(size))
        else {
            continue;
        };
        if function.sources == [NameSource::Call] {
            let Some(bytes) = image.read_vaddr(function.addr, size) else {
                continue;
            };
            if !normalize::normalize(image.isa, bytes, function.addr, &HashSet::new())
                .is_some_and(|body| body.name_eligible)
            {
                continue;
            }
        }
        return true;
    }
    false
}

fn call_inside_named_function(image: &Image, function: &Function) -> bool {
    function.sources == [NameSource::Call]
        && image
            .functions
            .range(..function.addr)
            .rev()
            .any(|(_, enclosing)| {
                enclosing.name.is_some()
                    && enclosing.size.is_some_and(|size| {
                        enclosing
                            .addr
                            .checked_add(size)
                            .is_some_and(|end| function.addr < end)
                    })
            })
}

pub(crate) fn image_entries(image: &Image, deadline: Option<Instant>) -> Result<Vec<Entry>> {
    if matches!(image.isa, Isa::Arm32 | Isa::AArch64)
        && image.byte_order() != Some(object::Endianness::Little)
    {
        return Ok(Vec::new());
    }
    let functions: Vec<_> = image.functions.values().collect();
    let found = crate::parallel::map(&functions, |function| {
        if let Err(error) = passed(deadline) {
            return Err(error);
        }
        let (Some(name), Some(size)) = (&function.name, function.size) else {
            return Ok(None);
        };
        if size > MAX_BYTES
            || (image.isa == Isa::Arm32
                && image.arm_mode(function.addr) != crate::loader::ArmMode::Arm)
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
        let calls: Option<Vec<_>> = body
            .calls
            .iter()
            .map(|call| {
                image
                    .functions
                    .get(&call.target)
                    .and_then(|function| function.name.clone())
            })
            .collect();
        let Some(calls) = calls else {
            return Ok(None);
        };
        let Some(constants) = constants::image_constants(image, &body) else {
            return Ok(None);
        };
        Ok(Some(make_entry(
            name.clone(),
            image.isa,
            body,
            calls,
            constants,
        )))
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

/// Builds signatures directly from an object or archive without lifting its functions.
pub fn build(path: &Path, deadline: Option<Instant>) -> Result<Database> {
    if let Err(error) = passed(deadline) {
        return Err(error);
    }
    let file_bytes = match std::fs::read(path) {
        Ok(file_bytes) => file_bytes,
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
    if file_bytes.starts_with(b"!<arch>\n") {
        let archive = match object::read::archive::ArchiveFile::parse(file_bytes.as_slice()) {
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
            let bytes = match member.data(file_bytes.as_slice()) {
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
    } else if let Ok(file) = object::File::parse(file_bytes.as_slice())
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
        object::Architecture::I386 => Isa::I386,
        object::Architecture::Arm => Isa::Arm32,
        _ => return Ok(()),
    };
    if matches!(isa, Isa::Arm32 | Isa::AArch64) && file.endianness() != object::Endianness::Little {
        return Ok(());
    }
    for section in file.sections() {
        if section.kind() != object::SectionKind::Text {
            continue;
        }
        let Ok(section_bytes) = section.data() else {
            continue;
        };
        let mut symbols: Vec<_> = file
            .symbols()
            .filter(|symbol| {
                symbol.kind() == object::SymbolKind::Text
                    && symbol.section_index() == Some(section.index())
            })
            .collect();
        symbols.sort_by_key(|symbol| symbol.address());
        let relocations: Vec<_> = section.relocations().collect();
        for (index, symbol) in symbols.iter().enumerate() {
            if let Err(error) = passed(deadline) {
                return Err(error);
            }
            let Ok(name) = symbol.name() else {
                continue;
            };
            if isa == Isa::Arm32 && symbol.address() & 1 != 0 {
                continue;
            }
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
                    .find(|candidate| candidate.address() > symbol.address())
                    .map(|symbol| symbol.address())
                    .or_else(|| section.address().checked_add(section_bytes.len() as u64))
            };
            let Some(end) = end
                .and_then(|v| v.checked_sub(section.address()))
                .and_then(|v| usize::try_from(v).ok())
            else {
                continue;
            };
            let Some(bytes) = section_bytes.get(offset..end) else {
                continue;
            };
            let function_relocations: Vec<_> = relocations
                .iter()
                .filter(|(at, _)| (*at as u128) >= offset as u128 && (*at as u128) < end as u128)
                .collect();
            let relocation_offsets: HashSet<usize> = function_relocations
                .iter()
                .map(|(at, _)| (*at as usize).saturating_sub(offset))
                .collect();
            let Some(body) =
                normalize::normalize(isa, bytes, symbol.address(), &relocation_offsets)
            else {
                continue;
            };
            let Some(constants) =
                constants::object_constants(file, &body, &function_relocations, offset)
            else {
                continue;
            };
            let mut calls = Vec::new();
            let mut valid = true;
            // Constant loads were checked above; remaining relocations must be direct branches.
            for (at, relocation) in &function_relocations {
                let relative = (*at as usize).saturating_sub(offset);
                if body
                    .references
                    .iter()
                    .any(|reference| reference.offset == relative)
                {
                    continue;
                }
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
                        (Isa::X86_64 | Isa::I386, Some(encoded)) => encoded.iter().all(|byte| *byte == 0)
                            || (isa == Isa::I386 && encoded == [0xfc, 0xff, 0xff, 0xff]),
                        (Isa::AArch64, Some(encoded)) if encoded.len() == 4 => {
                            u32::from_le_bytes(encoded.try_into().unwrap_or_default()) & 0x03ff_ffff
                                == 0
                        }
                        (Isa::Arm32, Some(encoded)) if encoded.len() == 4 => {
                            u32::from_le_bytes(encoded.try_into().unwrap_or_default()) & 0x00ff_ffff
                                == 0x00ff_fffe
                        }
                        _ => false,
                    };
                    *start == relative
                        && zero_addend
                        && ((matches!(isa, Isa::X86_64 | Isa::I386)
                            && *width == 4
                            && matches!(
                                relocation.kind(),
                                object::RelocationKind::Relative
                                    | object::RelocationKind::PltRelative
                            )
                            && relocation.size() == 32
                            && (relocation.addend() == -4
                                || (isa == Isa::I386 && relocation.has_implicit_addend())))
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
                                && relocation.addend() == 0)
                            || (isa == Isa::Arm32
                                && matches!(relocation.flags(), object::RelocationFlags::Elf { r_type } if matches!(r_type.0, 28 | 29))
                                && relocation.has_implicit_addend()
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
                let relocation = function_relocations
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
                    constants,
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod diagnostics;
#[cfg(test)]
mod tests;

//! Normalize chained pointers before any image metadata is read.

use std::collections::BTreeMap;

use object::read::macho::Fixup;
use object::{Object, ObjectSegment};

pub(crate) struct Binding {
    pub(crate) name: String,
    pub(crate) addend: i64,
}

pub(in crate::loader) fn apply(
    file: &object::File<'_>,
    bytes: &mut [u8],
) -> Result<BTreeMap<u64, Binding>, String> {
    let mut bindings = BTreeMap::new();
    let object::File::MachO64(macho) = file else {
        return Ok(bindings);
    };
    if !file.is_little_endian() {
        return Ok(bindings);
    }
    let endian = macho.endian();
    let mut commands = match macho.macho_load_commands() {
        Ok(commands) => commands,
        Err(error) => return Err(format!("load commands: {error}")),
    };
    let segments: Vec<_> = macho.segments().collect();
    let base = segments
        .iter()
        .find_map(|segment| (segment.name() == Ok(Some("__TEXT"))).then_some(segment.address()));
    loop {
        let command = match commands.next() {
            Ok(Some(command)) => command,
            Ok(None) => break,
            Err(error) => return Err(format!("load command: {error}")),
        };
        let command = match command.dyld_chained_fixups() {
            Ok(Some(command)) => command,
            Ok(None) => continue,
            Err(error) => return Err(format!("chained load command: {error}")),
        };
        let Some(base) = base else {
            return Err("chained pointers have no __TEXT segment".to_owned());
        };
        let fixups = match command.chained_fixups(endian, macho.data()) {
            Ok(fixups) => fixups,
            Err(error) => return Err(format!("header: {error}")),
        };
        let mut imports = match fixups.imports(endian) {
            Ok(imports) => imports,
            Err(error) => return Err(format!("imports: {error}")),
        };
        let mut names = Vec::new();
        loop {
            match imports.next() {
                Ok(Some(import)) => names.push(import),
                Ok(None) => break,
                Err(error) => return Err(format!("import {}: {error}", names.len())),
            }
        }
        let mut definitions = BTreeMap::new();
        if names
            .iter()
            .any(|import| import.dylib == object::macho::BIND_SPECIAL_DYLIB_SELF)
        {
            use object::ObjectSymbol as _;
            for symbol in file.symbols() {
                if !symbol.is_undefined()
                    && let Ok(name) = symbol.name_bytes()
                {
                    definitions.insert(name.to_vec(), symbol.address());
                }
            }
            if let Ok(exports) = file.exports() {
                for export in exports.flatten() {
                    if let (
                        object::read::NameOrOrdinal::Name(name),
                        object::read::ExportTarget::Address { address },
                    ) = (export.name(), export.target())
                    {
                        definitions.insert(name.to_vec(), address);
                    }
                }
            }
        }
        let mut starts = match fixups.segments(endian) {
            Ok(starts) => starts,
            Err(error) => return Err(format!("segment starts: {error}")),
        };
        loop {
            let starts = match starts.next() {
                Ok(Some(starts)) => starts,
                Ok(None) => break,
                Err(error) => return Err(format!("segment starts: {error}")),
            };
            let Some(segment) = segments.get(starts.index() as usize) else {
                return Err(format!("invalid segment index {}", starts.index()));
            };
            let header = starts.header();
            let format = header.pointer_format.get(endian);
            if !matches!(format.0, 1 | 2 | 6 | 7 | 9 | 10 | 12) {
                return Err(format!(
                    "segment {}: unsupported pointer format {format:?}",
                    starts.index()
                ));
            }
            let page_size = u64::from(header.page_size.get(endian));
            if !matches!(page_size, 0x1000 | 0x4000)
                || base.checked_add(header.segment_offset.get(endian)) != Some(segment.address())
                || u64::from(header.page_count.get(endian)) > segment.size().div_ceil(page_size)
            {
                return Err(format!("segment {}: invalid page geometry", starts.index()));
            }
            let data = match segment.data() {
                Ok(data) => data,
                Err(error) => return Err(format!("segment {} data: {error}", starts.index())),
            };
            let (file_offset, file_size) = segment.file_range();
            let mut pointers = starts.fixups(endian, base, data);
            let mut visited = std::collections::BTreeSet::new();
            // Even repeated multi-start entries must be bounded by the file size.
            for _ in 0..=data.len() / 4 {
                let (offset, pointer) = match pointers.next() {
                    Ok(Some(pointer)) => pointer,
                    Ok(None) => break,
                    Err(error) => {
                        return Err(format!("segment {} pointer: {error}", starts.index()));
                    }
                };
                let Some(address) = segment.address().checked_add(offset) else {
                    return Err(format!(
                        "segment {}: pointer address overflow",
                        starts.index()
                    ));
                };
                let Some(end) = offset.checked_add(8) else {
                    return Err(format!("pointer at {address:#x}: offset overflow"));
                };
                if end > file_size
                    || end > segment.size()
                    || offset % 4 != 0
                    || offset % page_size + 8 > page_size
                    || visited
                        .range(offset.saturating_sub(7)..end)
                        .next()
                        .is_some()
                {
                    return Err(format!(
                        "pointer at {address:#x}: invalid or overlapping chain offset"
                    ));
                }
                visited.insert(offset);
                let raw = u64::from_le_bytes(
                    data[offset as usize..end as usize]
                        .try_into()
                        .expect("an eight-byte pointer"),
                );
                let next = if matches!(format.0, 2 | 6) {
                    ((raw >> 51) & 0xfff) * 4
                } else {
                    ((raw >> 51) & 0x7ff) * if matches!(format.0, 7 | 10) { 4 } else { 8 }
                };
                if next != 0 && offset % page_size + next + 8 > page_size {
                    return Err(format!("pointer at {address:#x}: chain leaves its page"));
                }
                let value = match pointer {
                    Fixup::Rebase(rebase) => {
                        // Absolute formats carry the top byte separately from the low target.
                        if rebase.auth.is_none() && matches!(format.0, 1 | 2 | 10) {
                            if format.0 == 2 {
                                (raw & 0xf_ffff_ffff) | ((raw >> 36) & 0xff) << 56
                            } else {
                                (raw & 0x7ff_ffff_ffff) | ((raw >> 43) & 0xff) << 56
                            }
                        } else {
                            let low = rebase.target_offset & 0x00ff_ffff_ffff_ffff;
                            let Some(target) = base.checked_add(low) else {
                                return Err(format!("pointer at {address:#x}: target overflow"));
                            };
                            target | (rebase.target_offset & 0xff00_0000_0000_0000)
                        }
                    }
                    Fixup::Bind(bind) => {
                        let Some(import) = names.get(bind.ordinal as usize) else {
                            return Err(format!(
                                "pointer at {address:#x}: invalid import ordinal {}",
                                bind.ordinal
                            ));
                        };
                        let name = match std::str::from_utf8(import.name) {
                            Ok(name) if !name.is_empty() => name,
                            _ => {
                                return Err(format!(
                                    "pointer at {address:#x}: invalid import name"
                                ));
                            }
                        };
                        let Some(addend) = import.addend.checked_add(i64::from(bind.addend)) else {
                            return Err(format!("pointer at {address:#x}: import addend overflow"));
                        };
                        if import.dylib == object::macho::BIND_SPECIAL_DYLIB_SELF
                            && let Some(target) = definitions.get(import.name)
                        {
                            let Some(target) = target.checked_add_signed(addend) else {
                                return Err(format!(
                                    "pointer at {address:#x}: self-bind target overflow"
                                ));
                            };
                            target
                        } else {
                            bindings.insert(
                                address,
                                Binding {
                                    name: name.to_owned(),
                                    addend,
                                },
                            );
                            // An external address is symbolic; never expose chain bits as a target.
                            0
                        }
                    }
                    _ => return Err(format!("pointer at {address:#x}: unsupported rebase")),
                };
                let Some(place) = file_offset
                    .checked_add(offset)
                    .and_then(|offset| usize::try_from(offset).ok())
                else {
                    return Err(format!("pointer at {address:#x}: file offset overflow"));
                };
                let Some(field) = place
                    .checked_add(8)
                    .and_then(|end| bytes.get_mut(place..end))
                else {
                    return Err(format!("pointer at {address:#x}: truncated file data"));
                };
                field.copy_from_slice(&value.to_le_bytes());
            }
        }
    }
    Ok(bindings)
}

#[cfg(test)]
mod tests;

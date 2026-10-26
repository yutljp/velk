//! Symbol references retained by relocations and Mach-O binding streams.

use std::collections::BTreeMap;

use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol, RelocationTarget};

use crate::loader::Image;

pub(super) fn read(image: &Image) -> BTreeMap<u64, String> {
    let mut names = image.imports.clone();
    let Ok(file) = object::File::parse(image.bytes.as_slice()) else {
        return names;
    };
    let bases = crate::loader::relocate::layout(&file);
    for section in file.sections() {
        let base = bases
            .get(&section.index())
            .copied()
            .unwrap_or(section.address());
        for (offset, relocation) in section.relocations() {
            let RelocationTarget::Symbol(index) = relocation.target() else {
                continue;
            };
            let Ok(symbol) = file.symbol_by_index(index) else {
                continue;
            };
            let (Ok(name), Some(address)) = (symbol.name(), base.checked_add(offset)) else {
                continue;
            };
            names.insert(address, name.to_owned());
        }
    }
    let object::File::MachO64(macho) = &file else {
        return names;
    };
    let segments: Vec<_> = macho
        .segments()
        .map(|segment| (segment.address(), segment.size()))
        .collect();
    let Ok(mut commands) = macho.macho_load_commands() else {
        return names;
    };
    while let Ok(Some(command)) = commands.next() {
        let Ok(Some(info)) = command.dyld_info() else {
            continue;
        };
        for binds in [
            info.binds(macho.endian(), image.bytes.as_slice(), 8),
            info.weak_binds(macho.endian(), image.bytes.as_slice(), 8),
        ] {
            let Ok(mut binds) = binds else {
                continue;
            };
            // A malformed repeat opcode must not cause unbounded work.
            for _ in 0..image.bytes.len() {
                let Ok(Some(bind)) = binds.next() else {
                    break;
                };
                let Some((base, size)) = segments.get(usize::from(bind.segment_index)) else {
                    continue;
                };
                if bind.segment_offset >= *size {
                    continue;
                }
                let (Some(address), Ok(name)) = (
                    base.checked_add(bind.segment_offset),
                    std::str::from_utf8(bind.symbol),
                ) else {
                    continue;
                };
                names.insert(address, name.to_owned());
            }
        }
    }
    names
}

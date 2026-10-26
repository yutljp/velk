//! PDB sidecar and embedded COFF debug-information readers.

use super::records::{Reader, u32_at};
use super::{Data, msf, symbols, types};
use object::{Object, ObjectSection, ObjectSymbol};
use std::path::Path;

pub(super) fn type_stream(bytes: &[u8]) -> types::Types {
    let (Some(header), Some(start), Some(end), Some(size)) = (
        u32_at(bytes, 4),
        u32_at(bytes, 8),
        u32_at(bytes, 12),
        u32_at(bytes, 16),
    ) else {
        return types::Types::default();
    };
    if u32_at(bytes, 0) != Some(20040203) || header < 56 || start != 0x1000 || end < start {
        return types::Types::default();
    }
    let Some(bytes) = bytes.get(header as usize..(header as usize).saturating_add(size as usize))
    else {
        return types::Types::default();
    };
    let mut types = types::Types::read(bytes, start);
    types.0.retain(|index, _| *index < end);
    types
}

pub(super) fn pdb(
    path: &Path,
    filename: &[u8],
    age: u32,
    guid: [u8; 16],
    sections: &[(u64, u64)],
) -> Data {
    let mut data = Data::default();
    // Resolve the filename beside the image; never follow a build machine's path.
    let filename = filename
        .rsplit(|byte| matches!(byte, b'/' | b'\\'))
        .next()
        .unwrap_or(&[]);
    let Ok(filename) = std::str::from_utf8(filename) else {
        return data;
    };
    if filename.is_empty() || filename == "." || filename == ".." {
        return data;
    }
    let Ok(bytes) = std::fs::read(path.with_file_name(filename)) else {
        return data;
    };
    let Some(msf) = msf::Msf::open(&bytes) else {
        return data;
    };
    let Some(identity) = msf.stream(1) else {
        return data;
    };
    if u32_at(&identity, 8) != Some(age) || identity.get(12..28) != Some(guid.as_slice()) {
        return data;
    }
    if let Some(types) = msf.stream(2) {
        data.types = type_stream(&types);
    }
    if let Some(ids) = msf.stream(4) {
        data.ids = type_stream(&ids);
    }
    // OMAP remaps optimized addresses; do not interpret them as image offsets.
    let Some(dbi) = msf.stream(3) else {
        return data;
    };
    if u32_at(&dbi, 0) != Some(u32::MAX)
        || u32_at(&dbi, 8) != Some(age)
        || dbi.get(58..60) != Some(0x8664u16.to_le_bytes().as_slice())
    {
        return Data::default();
    }
    let sizes = [24, 28, 32, 36, 40, 52].map(|at| u32_at(&dbi, at).unwrap_or(u32::MAX) as usize);
    let Some(offset) = sizes
        .into_iter()
        .try_fold(64usize, |sum, size| sum.checked_add(size))
    else {
        return Data::default();
    };
    let Some(size) = u32_at(&dbi, 48).map(|size| size as usize) else {
        return Data::default();
    };
    let Some(table) = dbi.get(offset..offset.saturating_add(size)) else {
        return Data::default();
    };
    for at in [6, 8] {
        if let Some(entry) = table.get(at..at + 2)
            && entry != u16::MAX.to_le_bytes().as_slice()
        {
            return Data::default();
        }
    }
    for symbols in msf.modules() {
        symbols::read(&mut data, &symbols, sections, true);
    }
    data
}

pub(super) fn coff(file: &object::File<'_>, sections: &[(u64, u64)]) -> Data {
    let mut data = Data::default();
    for section in file.sections() {
        if section.name().ok() == Some(".debug$T")
            && let Ok(bytes) = section.data()
            && u32_at(bytes, 0) == Some(4)
        {
            data.types = types::Types::read(&bytes[4..], 0x1000);
            break;
        }
    }
    for section in file.sections() {
        if section.name().ok() != Some(".debug$S") {
            continue;
        }
        let Ok(bytes) = section.data() else { continue };
        let mut bytes = bytes.to_vec();
        // CodeView addresses retain section offsets, rather than virtual addresses.
        for (offset, relocation) in section.relocations() {
            let object::RelocationTarget::Symbol(index) = relocation.target() else {
                continue;
            };
            let Ok(symbol) = file.symbol_by_index(index) else {
                continue;
            };
            let Some(section) = symbol.section_index() else {
                continue;
            };
            let Ok(offset) = usize::try_from(offset) else {
                continue;
            };
            match relocation.kind() {
                object::RelocationKind::SectionOffset => {
                    let Some(addend) = u32_at(&bytes, offset) else {
                        continue;
                    };
                    let Some(value) = symbol
                        .address()
                        .checked_add(u64::from(addend))
                        .and_then(|value| u32::try_from(value).ok())
                    else {
                        continue;
                    };
                    if let Some(place) = bytes.get_mut(offset..offset.saturating_add(4)) {
                        place.copy_from_slice(&value.to_le_bytes());
                    }
                }
                object::RelocationKind::SectionIndex => {
                    let Ok(index) = u16::try_from(section.0) else {
                        continue;
                    };
                    if let Some(place) = bytes.get_mut(offset..offset.saturating_add(2)) {
                        place.copy_from_slice(&index.to_le_bytes());
                    }
                }
                _ => {}
            }
        }
        if u32_at(&bytes, 0) != Some(4) {
            continue;
        }
        let mut reader = Reader(&bytes[4..]);
        while !reader.0.is_empty() {
            let (Some(kind), Some(size)) = (reader.u32(), reader.u32()) else {
                break;
            };
            let Some(bytes) = reader.take(size as usize) else {
                break;
            };
            if kind == 0xf1 {
                symbols::read(&mut data, bytes, sections, false);
            }
            if reader.take((4 - size as usize % 4) % 4).is_none() {
                break;
            }
        }
    }
    data
}

//! Windows debug declarations shared with the other debug-information consumers.

mod graph;
mod locations;
mod msf;
mod records;
mod symbols;
mod types;

use crate::loader::{Image, dwarf::FunctionTypes};
use object::{Object, ObjectSection, ObjectSymbol, SectionIndex};
use records::{Reader, u32_at};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::path::Path;

pub(super) const SOURCE: u64 = u64::MAX;

#[derive(Debug, Default)]
pub(crate) struct Data {
    types: types::Types,
    ids: types::Types,
    procedures: Vec<Procedure>,
    definitions: std::sync::OnceLock<(Vec<crate::ir::Definition>, Vec<crate::ir::Member>)>,
}

#[derive(Debug)]
struct Procedure {
    addr: u64,
    size: u64,
    name: String,
    signature: Option<FunctionTypes>,
    total: Option<u32>,
    variables: Vec<(String, u32, u16, i64)>,
}

impl Data {
    pub(super) fn functions(&self) -> Vec<super::dwarf::DwarfFunction> {
        self.procedures
            .iter()
            .map(|function| super::dwarf::DwarfFunction {
                addr: function.addr,
                size: function.size,
                name: function.name.clone(),
            })
            .collect()
    }

    pub(crate) fn function_types(&self, image: &Image, addr: u64) -> Option<FunctionTypes> {
        let mut matches = self
            .procedures
            .iter()
            .filter(|procedure| procedure.addr == addr);
        let Some(procedure) = matches.next() else {
            return None;
        };
        if matches.next().is_some() {
            return None;
        }
        let Some(mut signature) = procedure.signature.clone() else {
            return None;
        };
        let (definitions, members) = self.definitions.get_or_init(|| self.types.definitions());
        for ty in signature
            .params
            .iter_mut()
            .filter_map(|(_, ty)| ty.as_mut())
            .chain(signature.ret.iter_mut())
        {
            let mut target = ty;
            while let crate::ir::CType::Pointer(inner) = target {
                if let crate::ir::CType::Named(name) = inner.as_ref()
                    && name.starts_with("struct ")
                    && !definitions
                        .iter()
                        .any(|definition| definition.name == *name)
                {
                    **inner = crate::ir::CType::Void;
                    break;
                }
                target = inner;
            }
        }
        signature.definitions = definitions.clone();
        signature.members = members.clone();
        signature.locals = symbols::locals(self, image, procedure);
        Some(signature)
    }
}

fn type_stream(bytes: &[u8]) -> types::Types {
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

pub(super) fn read(
    path: &Path,
    file: &object::File<'_>,
    bases: &HashMap<SectionIndex, u64>,
) -> Data {
    if file.format() != object::BinaryFormat::Coff && file.format() != object::BinaryFormat::Pe {
        return Data::default();
    }
    if file.architecture() != object::Architecture::X86_64 {
        return Data::default();
    }
    let sections: Vec<_> = file
        .sections()
        .map(|section| {
            (
                bases
                    .get(&section.index())
                    .copied()
                    .unwrap_or(section.address()),
                section.size(),
            )
        })
        .collect();
    let mut data = Data::default();
    if let Ok(Some(info)) = file.pdb_info() {
        // Resolve the filename beside the image; never follow a build machine's path.
        let filename = info
            .path()
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
        if u32_at(&identity, 8) != Some(info.age())
            || identity.get(12..28) != Some(info.guid().as_slice())
        {
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
            || u32_at(&dbi, 8) != Some(info.age())
            || dbi.get(58..60) != Some(0x8664u16.to_le_bytes().as_slice())
        {
            return Data::default();
        }
        let sizes =
            [24, 28, 32, 36, 40, 52].map(|at| u32_at(&dbi, at).unwrap_or(u32::MAX) as usize);
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
            symbols::read(&mut data, &symbols, &sections, true);
        }
        return data;
    }
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
                symbols::read(&mut data, bytes, &sections, false);
            }
            if reader.take((4 - size as usize % 4) % 4).is_none() {
                break;
            }
        }
    }
    data
}

pub(crate) fn call_index(image: &Image) -> super::dwarf::calls::CallIndex {
    let mut addresses = BTreeMap::new();
    for function in &image.codeview.procedures {
        if let Some(types) = &function.signature {
            addresses
                .entry(function.addr)
                .or_insert_with(Vec::new)
                .push(types.source.function);
        }
    }
    super::dwarf::calls::CallIndex {
        addresses,
        unresolved_ranges: Vec::new(),
    }
}

pub(crate) fn call_unit(image: &Image) -> super::dwarf::calls::CallUnit {
    let mut unit = super::dwarf::calls::CallUnit::default();
    for function in &image.codeview.procedures {
        if let Some(types) = &function.signature {
            unit.functions
                .insert(types.source.function, Ok(types.clone()));
        }
    }
    unit.graph = std::sync::Arc::new(graph::read(&image.codeview.types));
    unit
}

#[cfg(test)]
mod tests;

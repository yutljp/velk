//! Windows debug declarations shared with the other debug-information consumers.

mod graph;
mod inputs;
mod locations;
mod msf;
mod records;
mod symbols;
mod types;

#[cfg(test)]
use inputs::type_stream;

use crate::loader::{Image, dwarf::FunctionTypes};
use object::{Object, ObjectSection, SectionIndex};
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
    if let Ok(Some(info)) = file.pdb_info() {
        return inputs::pdb(path, info.path(), info.age(), info.guid(), &sections);
    }
    inputs::coff(file, &sections)
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

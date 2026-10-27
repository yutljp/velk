//! Application of annotations to inferred analysis.
mod signatures;

use std::collections::HashSet;

use crate::error::Result;
use crate::ir::{CType, DebugLocal, FunctionIr};
use crate::loader::{Function, Image};
use crate::render::Symbols;

use super::types::Types;
use super::{Project, Storage, Target, error};

impl Project {
    pub(crate) fn classify(&self, image: &mut Image) -> Result<()> {
        for entry in &self.annotations {
            if let Target::Classification { address } = entry.target {
                if image.read_vaddr(address, 1).is_none() {
                    return Err(error(
                        "invalid_address",
                        format!("classification at unmapped address 0x{address:x}"),
                    ));
                }
                if entry.text.as_deref() == Some("data") {
                    image.functions.remove(&address);
                } else {
                    image.functions.entry(address).or_insert(Function {
                        addr: address,
                        size: None,
                        size_estimated: true,
                        name: None,
                        aliases: Vec::new(),
                        library: None,
                        sources: Vec::new(),
                    });
                }
            }
        }
        Ok(())
    }

    pub(crate) fn apply(&self, ir: &mut FunctionIr, symbols: &mut Symbols) -> Result<()> {
        if ir.isa == crate::loader::Isa::Arm32
            && self.annotations.iter().any(|entry| {
                entry.c_type.is_some()
                    || matches!(
                        entry.target,
                        Target::Declaration { .. } | Target::Signature { .. }
                    )
            })
        {
            return Err(error(
                "unsupported_type",
                "type annotations require a 64-bit target layout",
            ));
        }

        let types = match Types::new(self) {
            Ok(types) => types,
            Err(cause) => return Err(cause),
        };
        for name in &types.ordinary_names {
            if symbols
                .functions
                .values()
                .chain(symbols.data.values())
                .chain(symbols.import_slots.values())
                .any(|symbol| crate::render::sanitize(symbol) == *name)
            {
                return Err(error(
                    "name_collision",
                    format!("declaration name is already used by a symbol: {name}"),
                ));
            }
        }
        for definition in &types.definitions {
            if let Some(tag) = definition.name.strip_prefix("struct ")
                && ir.structures.iter().any(|structure| structure.name == tag)
            {
                return Err(error(
                    "name_collision",
                    format!(
                        "function at 0x{:x}: {} is an inferred layout; choose a distinct declaration name and bind it to the parameter or local",
                        ir.addr, definition.name
                    ),
                ));
            }
            symbols.user_definitions.insert(definition.name.clone());
            ir.definitions.retain(|old| old.name != definition.name);
            ir.members.retain(|old| {
                Some(old.structure.as_str()) != definition.name.strip_prefix("struct ")
            });
            ir.definitions.push(definition.clone());
        }
        ir.members.extend(types.members.clone());
        let signatures = self
            .annotations
            .iter()
            .filter(|entry| matches!(entry.target, Target::Signature { .. }));
        let others = self
            .annotations
            .iter()
            .filter(|entry| !matches!(entry.target, Target::Signature { .. }));
        for entry in signatures.chain(others) {
            let ty = match entry.c_type.as_deref().map(|ty| types.parse(ty)) {
                Some(Ok(ty)) => Some(ty),
                Some(Err(cause)) => return Err(cause),
                None => None,
            };
            match &entry.target {
                Target::Function { address } => {
                    if let Some(name) = &entry.name {
                        let existing = symbols.functions.get(address).map(String::as_str);
                        if (crate::analysis::prototypes::of(name, false).is_some()
                            || crate::analysis::prototypes::runtime(name).is_some())
                            && existing != Some(name.as_str())
                        {
                            return Err(error(
                                "name_collision",
                                format!("name is reserved for a known library function: {name}"),
                            ));
                        }
                        if types.ordinary_names.contains(name)
                            || (existing != Some(name.as_str())
                                && symbols
                                    .import_slots
                                    .values()
                                    .any(|symbol| crate::render::sanitize(symbol) == *name))
                            || symbols.functions.iter().any(|(other, existing)| {
                                other != address && crate::render::sanitize(existing) == *name
                            })
                            || symbols
                                .data
                                .values()
                                .any(|existing| crate::render::sanitize(existing) == *name)
                        {
                            return Err(error(
                                "name_collision",
                                format!("symbol name is already used: {name}"),
                            ));
                        }
                        if !symbols.functions.contains_key(address) {
                            symbols.unnamed_functions.insert(*address);
                        }
                        let original = symbols
                            .functions
                            .get(address)
                            .cloned()
                            .unwrap_or_else(|| format!("sub_{address:x}"));
                        symbols.original_functions.insert(*address, original);
                        symbols.functions.insert(*address, name.clone());
                        if *address == ir.addr {
                            ir.name = Some(name.clone());
                        }
                    }
                }
                Target::Global { address } => {
                    if let Some(name) = &entry.name {
                        if types.ordinary_names.contains(name)
                            || symbols
                                .import_slots
                                .values()
                                .any(|symbol| crate::render::sanitize(symbol) == *name)
                            || symbols.data.iter().any(|(other, existing)| {
                                other != address && crate::render::sanitize(existing) == *name
                            })
                            || symbols
                                .functions
                                .values()
                                .any(|existing| crate::render::sanitize(existing) == *name)
                        {
                            return Err(error(
                                "name_collision",
                                format!("symbol name is already used: {name}"),
                            ));
                        }
                        symbols.constant_names.remove(address);
                        symbols.data.insert(*address, name.clone());
                    }
                    if let Some(ty) = ty {
                        let (size, _) = match types.size(&ty) {
                            Ok(size) => size,
                            Err(cause) => return Err(cause),
                        };
                        ir.debug_globals.retain(|(old, _, _)| old != address);
                        ir.debug_globals.push((*address, ty, size));
                    }
                }
                Target::Parameter { function, storage } if *function == ir.addr => {
                    if ir.declared_signature.as_ref().is_some_and(|signature| {
                        match &signature.abi {
                            Ok(abi) => abi
                                .arguments
                                .iter()
                                .chain(&abi.result)
                                .any(|value| value.aggregate),
                            Err(_) => true,
                        }
                    }) {
                        return Err(error(
                            "unsupported_signature",
                            "parameter storage has an aggregate or unresolved source ABI",
                        ));
                    }
                    let param = match storage {
                        Storage::Register { register } => ir
                            .params
                            .iter_mut()
                            .find(|p| p.index == *register)
                            .map(|p| (&mut p.name, &mut p.ty)),
                        Storage::Stack { offset } => ir
                            .stack_params
                            .iter_mut()
                            .find(|p| p.offset == *offset)
                            .map(|p| (&mut p.name, &mut p.ty)),
                        Storage::Definition { .. } => None,
                    };
                    let Some((name, param_type)) = param else {
                        return Err(error(
                            "unknown_storage",
                            format!("no parameter at {storage:?} in 0x{function:x}"),
                        ));
                    };
                    if let Some(given) = &entry.name {
                        *name = given.clone();
                        if let Storage::Register { register } = storage {
                            symbols
                                .variable_names
                                .insert((ir.addr, *register), given.clone());
                        }
                    }
                    if let Some(ty) = ty {
                        if !ty.is_pointer() && ty.integer().is_none() {
                            return Err(error(
                                "unsupported_type",
                                "register and stack parameters require integer or pointer types",
                            ));
                        }
                        *param_type = ty;
                    }
                }
                Target::Local { function, storage } if *function == ir.addr => {
                    if let Storage::Stack { offset } = storage {
                        let locals = crate::render::project_locals(ir);
                        if !locals.iter().any(|(slot, _, _, _)| slot == offset) {
                            return Err(error(
                                "unknown_storage",
                                format!("no local at stack offset {offset} in 0x{function:x}"),
                            ));
                        }
                        if let Some(name) = &entry.name {
                            symbols.stack_names.insert((ir.addr, *offset), name.clone());
                        }
                        if let Some(ty) = ty {
                            let (size, _) = match types.size(&ty) {
                                Ok(size) => size,
                                Err(cause) => return Err(cause),
                            };
                            if !locals
                                .iter()
                                .any(|(slot, _, _, available)| slot == offset && *available == size)
                            {
                                return Err(error(
                                    "unsupported_stack_type",
                                    "stack type must fit one existing storage object exactly",
                                ));
                            }
                            if ty.is_pointer() || ty.integer().is_some() {
                                symbols.stack_types.insert((ir.addr, *offset), ty.clone());
                            }
                            let name = entry
                                .name
                                .clone()
                                .or_else(|| {
                                    ir.debug_locals
                                        .iter()
                                        .find(|local| local.slot == *offset)
                                        .map(|local| local.name.clone())
                                })
                                .unwrap_or_else(|| format!("stack_{:x}", offset.unsigned_abs()));
                            ir.debug_locals.retain(|local| local.slot != *offset);
                            ir.debug_locals.push(DebugLocal {
                                name,
                                ty,
                                slot: *offset,
                                size,
                            });
                        }
                    } else {
                        let index = match resolve(ir, storage) {
                            Ok(index) => index,
                            Err(cause) => return Err(cause),
                        };
                        if let Some(name) = &entry.name {
                            symbols
                                .variable_names
                                .insert((ir.addr, index), name.clone());
                        }
                        if let Some(ty) = ty {
                            if !ty.is_pointer() && ty.integer().is_none() {
                                return Err(error(
                                    "unsupported_type",
                                    "register locals require integer or pointer types",
                                ));
                            }
                            symbols.variable_types.insert((ir.addr, index), ty);
                        }
                    }
                }
                Target::Signature { function } => {
                    if let Err(cause) = signatures::apply(
                        &types,
                        entry.text.as_deref().unwrap_or_default(),
                        function,
                        ir,
                        symbols,
                    ) {
                        return Err(cause);
                    }
                }
                _ => {}
            }
        }
        let mut parameter_names = HashSet::new();
        if self.annotations.iter().any(|entry| matches!(entry.target, Target::Parameter { function, .. } | Target::Signature { function } if function == ir.addr)) {
            let names = ir.params.iter().map(|parameter| &parameter.name).chain(ir.stack_params.iter().map(|parameter| &parameter.name));
            for name in names {
                if !parameter_names.insert(name) || symbols.functions.values().chain(symbols.data.values()).chain(symbols.import_slots.values()).any(|symbol| symbol == name) {
                    return Err(error("name_collision", format!("parameter name is already used: {name}")));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn validate_rendered_names(&self, ir: &FunctionIr, code: &str) -> Result<()> {
        let types = match Types::new(self) {
            Ok(types) => types,
            Err(cause) => return Err(cause),
        };
        let names = self
            .annotations
            .iter()
            .filter(|entry| match entry.target {
                Target::Function { .. } | Target::Global { .. } => true,
                Target::Parameter { function, .. } | Target::Local { function, .. } => {
                    function == ir.addr
                }
                _ => false,
            })
            .filter_map(|entry| entry.name.as_ref())
            .chain(ir.params.iter().map(|param| &param.name))
            .chain(ir.stack_params.iter().map(|param| &param.name))
            .chain(types.ordinary_names.iter());
        for name in names {
            if code.contains(&format!("#define VELK_{name}\n")) {
                return Err(error(
                    "name_collision",
                    format!("name is used by an operation helper: {name}"),
                ));
            }
        }
        for entry in &self.annotations {
            if let Target::Declaration { name } = &entry.target
                && let Some(tag) = name
                    .strip_prefix("struct ")
                    .or_else(|| name.strip_prefix("enum "))
            {
                let prefixes = [
                    format!("struct {tag} {{"),
                    format!("union {tag} {{"),
                    format!("enum {tag} {{"),
                ];
                if code.lines().any(|line| {
                    prefixes
                        .iter()
                        .any(|prefix| line.trim_start().starts_with(prefix))
                }) {
                    return Err(error(
                        "name_collision",
                        format!("declaration tag is already used by generated support code: {tag}"),
                    ));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn comments(&self, ir: &FunctionIr) -> String {
        let mut text = String::new();
        for entry in &self.annotations {
            if let Target::Comment { address } = entry.target
                && (address == ir.addr
                    || address
                        .checked_sub(ir.addr)
                        .is_some_and(|offset| offset < ir.size))
            {
                let comment = entry
                    .text
                    .as_deref()
                    .unwrap_or_default()
                    .replace("*/", "* /")
                    .replace('?', "? ")
                    .replace(['\r', '\0', '\\'], " ");
                text.push_str(&format!("/* 0x{address:x}: {comment} */\n"));
            }
        }
        text
    }

    pub(crate) fn declarations(&self) -> Result<String> {
        match Types::new(self) {
            Ok(types) if types.declarations.is_empty() => Ok(String::new()),
            Ok(types) => Ok(crate::render::project_section(
                &types.declarations.join("\n"),
            )),
            Err(cause) => Err(cause),
        }
    }
}

fn resolve(ir: &FunctionIr, storage: &Storage) -> Result<u16> {
    let register = match storage {
        Storage::Register { register } | Storage::Definition { register, .. } => *register,
        Storage::Stack { .. } => unreachable!(),
    };
    let used: HashSet<_> = ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .flat_map(|stmt| {
            let (writes, reads) = crate::ir::visit::statement_registers(stmt);
            writes.into_iter().chain(reads)
        })
        .collect();
    let mut candidates = used
        .into_iter()
        .filter(|index| {
            ir.variable_registers.get(index).copied().unwrap_or(*index) == register
                && !ir.params.iter().any(|p| p.index == *index)
        })
        .filter(|index| match storage {
            Storage::Definition {
                block, statement, ..
            } => ir
                .blocks
                .iter()
                .flat_map(|block| {
                    block
                        .stmts
                        .iter()
                        .enumerate()
                        .map(move |(position, stmt)| (block.start, position, stmt))
                })
                .find(|(_, _, stmt)| {
                    crate::ir::visit::statement_registers(stmt)
                        .0
                        .contains(index)
                })
                .is_some_and(|(start, position, _)| start == *block && position == *statement),
            _ => true,
        });
    match (candidates.next(), candidates.next()) {
        (Some(index), None) => Ok(index),
        (None, _) => Err(error(
            "unknown_storage",
            format!("no local at {storage:?} in 0x{:x}", ir.addr),
        )),
        _ => Err(error(
            "ambiguous_storage",
            format!("multiple locals at {storage:?}; select a definition origin"),
        )),
    }
}

/// Returns stable annotation selectors for inferred parameters and locals, with their names and types.
#[must_use]
pub fn origins(ir: &FunctionIr) -> Vec<serde_json::Value> {
    use serde_json::json;
    let mut result = Vec::new();
    for param in &ir.params {
        result.push(json!({"target": Target::Parameter { function: ir.addr, storage: Storage::Register { register: param.index } }, "name": param.name, "c_type": param.ty.to_string()}));
    }
    for param in &ir.stack_params {
        result.push(json!({"target": Target::Parameter { function: ir.addr, storage: Storage::Stack { offset: param.offset } }, "name": param.name, "c_type": param.ty.to_string()}));
    }
    let mut seen = HashSet::new();
    for block in &ir.blocks {
        for (statement, stmt) in block.stmts.iter().enumerate() {
            for index in crate::ir::visit::statement_registers(stmt).0 {
                if !seen.insert(index) || ir.params.iter().any(|p| p.index == index) {
                    continue;
                }
                let register = ir.variable_registers.get(&index).copied().unwrap_or(index);
                if register == crate::arch::stack_pointer(ir.isa) {
                    continue;
                }
                result.push(json!({"target": Target::Local { function: ir.addr, storage: Storage::Definition { register, block: block.start, statement } }}));
            }
        }
    }
    for (offset, name, ty, _) in crate::render::project_locals(ir) {
        result.push(json!({"target": Target::Local { function: ir.addr, storage: Storage::Stack { offset } }, "name": name, "c_type": ty.to_string()}));
    }
    result
}

pub(crate) fn scalar_parameters(ir: &FunctionIr) -> Result<Vec<(String, CType)>> {
    if ir.variadic
        || !matches!(
            ir.convention,
            crate::ir::Convention::SysV
                | crate::ir::Convention::Win64
                | crate::ir::Convention::Aapcs64
        )
    {
        return Err(error(
            "unsupported_signature",
            "override requires a nonvariadic scalar ABI",
        ));
    }
    let count = ir.params.len().saturating_add(ir.stack_params.len());
    let mut registers = ir.params.iter();
    let mut parameters = Vec::new();
    for position in 0..count {
        let mut stack = ir
            .stack_params
            .iter()
            .filter(|param| param.position == position);
        let (name, ty) = match (stack.next(), stack.next()) {
            (Some(param), None) => (&param.name, &param.ty),
            (None, None) => match registers.next() {
                Some(param) => (&param.name, &param.ty),
                None => {
                    return Err(error(
                        "unsupported_signature",
                        "incomplete parameter storage mapping",
                    ));
                }
            },
            _ => {
                return Err(error(
                    "unsupported_signature",
                    "ambiguous stack parameter positions",
                ));
            }
        };
        if !ty.is_pointer() && ty.integer().is_none() {
            return Err(error(
                "unsupported_signature",
                "only integer and pointer parameters are supported",
            ));
        }
        parameters.push((name.clone(), ty.clone()));
    }
    if registers.next().is_some() || ir.stack_params.iter().any(|param| param.position >= count) {
        return Err(error(
            "unsupported_signature",
            "incomplete parameter storage mapping",
        ));
    }
    Ok(parameters)
}

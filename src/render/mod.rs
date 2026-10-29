mod abi;
mod abi_objects;
mod addresses;
mod aggregates;
mod body;
mod calls;
pub(crate) mod classes;
mod com_calls;
mod cost;
mod expr;
mod forwarding;
mod frame_registers;
mod function;
mod globals;
mod go_values;
mod initializers;
mod int;
mod jumps;
mod layouts;
mod locals;
mod machine;
mod naming;
mod params;
mod prelude;
mod provenance;
pub(crate) mod seh;
mod stack_bytes;
mod stmt;
mod string_functions;
mod string_loops;
pub mod structure;
mod support;
mod symbols;
mod transfers;
pub(crate) mod unions;
mod variables;
mod variadic;
mod vector_helpers;
mod vector_values;
mod virtual_calls;
mod widths;

pub use addresses::instruction_addresses;
use body::{indent, render_node, render_nodes, via_comment};
use calls::system_call_name;
#[cfg(test)]
use function::code_mentions;
pub(crate) use function::declaration;
pub(crate) use function::render_with_symbols;
pub(crate) use function::structure_definition;
pub(crate) use function::variable_types;
pub use function::{render, render_with_dependencies};
use function::{vacant_name, variable_name};
pub(crate) use globals::reserved_identifier;
pub use prelude::{Prelude, combine};
pub(crate) use prelude::{project_section, promoted_parameter};
pub(crate) use stmt::render_stmt;
use stmt::{argument, conformed, narrow_write, returned};
pub(crate) use symbols::FunctionSymbols;
pub use symbols::Symbols;

/// An x86 segment base supplied by the target execution context.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SegmentBase {
    Fs,
    Gs,
}

/// The external C binding for one required entry segment base.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegmentBaseRead {
    pub segment: SegmentBase,
    pub provider: String,
}

/// Printed code and the target state it requires from its caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rendered {
    pub code: String,
    pub segment_bases: Vec<SegmentBaseRead>,
    /// Memory and string effects replaced by standard function calls.
    pub inline_functions: Vec<InlineFunction>,
}

/// One recovered memory operation in the selected C body.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct InlineFunction {
    /// Standard function implementing the effect.
    pub function: String,
    /// Constant byte extent, or absent for a runtime count.
    pub bytes: Option<u64>,
}

use crate::arch::stack_pointer;
use expr::condition;
use std::collections::HashMap;

use crate::analysis::refs::Reference;
use crate::ir::{BinOp, CType, Expr, FunctionIr, Stmt};
use crate::passes::frame_slots::block_entry_frame_offsets;
use crate::render::expr::Ctx;
use crate::render::expr::render_at;
use crate::render::expr::render_expr;
use crate::render::expr::render_value;
use crate::render::expr::slot_access;
use crate::render::expr::type_of;
use crate::render::locals::Locals;
#[cfg(test)]
use crate::render::locals::stack_locals;
use crate::render::naming::member_access;
use crate::render::naming::narrow_registers;
use crate::render::structure::{Node, structure_best};

/// The loaded, non-executable ranges, where a constant address names data.
pub fn data_ranges(image: &crate::loader::Image) -> Vec<(u64, u64)> {
    image
        .sections
        .iter()
        .filter(|section| section.loaded && !section.executable)
        .map(|section| (section.vaddr, section.size))
        .collect()
}

/// The names of the functions and data objects, by address, and of the
/// imports by the slots that hold them. A function goes by its name without
/// the parameter list a demangled name ends in, when no other function has
/// that name too.
pub fn callee_names(image: &crate::loader::Image) -> Symbols {
    let import_wrappers = image.isa == crate::loader::Isa::I386
        && matches!(
            image.format,
            crate::loader::Format::Pe | crate::loader::Format::Coff
        );
    let base_name = |function: &crate::loader::Function, name: &str| {
        let base = sanitize(&short_name(name));
        if import_wrappers && function.sources.contains(&crate::loader::NameSource::Plt) {
            format!("{base}_plt")
        } else if !function.sources.contains(&crate::loader::NameSource::Plt)
            && crate::analysis::prototypes::runtime(name).is_none()
            && crate::analysis::prototypes::for_image(name, image).is_some()
        {
            // A defined body may implement a stub with a different signature.
            // Keep its recovered types without redeclaring a header's identifier.
            format!("{base}_{:x}", function.addr)
        } else {
            base
        }
    };
    let named: Vec<(u64, &crate::loader::Function, String)> = image
        .functions
        .iter()
        .filter_map(|(&address, function)| {
            let Some(name) = function.name.as_deref() else {
                return None;
            };
            Some((address, function, base_name(function, name)))
        })
        .collect();
    let mut bases: HashMap<&str, usize> = HashMap::new();
    for (_, function, base) in &named {
        if !import_wrappers && function.sources.contains(&crate::loader::NameSource::Plt) {
            continue;
        }
        *bases.entry(base.as_str()).or_default() += 1;
    }
    let mut used = std::collections::HashSet::new();
    let functions: HashMap<u64, String> = named
        .iter()
        .map(|(address, function, base)| {
            if !import_wrappers && function.sources.contains(&crate::loader::NameSource::Plt) {
                return (*address, base.clone());
            }
            let mut name = base.clone();
            if bases.get(base.as_str()) != Some(&1) {
                let candidate = format!("{base}_{address:x}");
                name = candidate.clone();
                let mut suffix = 2usize;
                while bases.contains_key(name.as_str()) || used.contains(&name) {
                    name = format!("{candidate}_{suffix}");
                    suffix += 1;
                }
            }
            used.insert(name.clone());
            (*address, name)
        })
        .collect();
    let mut symbols = Symbols {
        import_thunks: image
            .functions
            .iter()
            .filter_map(|(address, function)| {
                (!import_wrappers && function.sources.contains(&crate::loader::NameSource::Plt))
                    .then_some(*address)
            })
            .collect(),
        objc_selectors: image
            .objc_selectors
            .iter()
            .map(|(address, name)| (*address, name.clone()))
            .collect(),
        target_format: (image.byte_order() == Some(object::Endianness::Little))
            .then_some(image.format),
        library_prototypes: image
            .imports
            .values()
            .filter_map(|name| {
                crate::analysis::prototypes::for_image(name, image)
                    .map(|prototype| (sanitize(name), prototype.clone()))
            })
            .collect(),
        variadic_functions: crate::loader::dwarf::variadic::functions(image),
        runtime_parameters: image
            .functions
            .keys()
            .filter_map(|address| {
                crate::analysis::go_types::runtime(image, *address)
                    .map(|prototype| (*address, prototype.params.clone()))
            })
            .collect(),
        functions,
        cpp_classes: image.classes().to_vec(),
        cpp_signatures: image
            .classes()
            .iter()
            .flat_map(|class| &class.vtables)
            .flat_map(|table| &table.methods)
            .filter_map(|method| {
                crate::analysis::calls::virtual_signature(image, method.address)
                    .map(|signature| (method.address, signature))
            })
            .collect(),
        cpp_methods: image
            .functions
            .iter()
            .filter_map(|(addr, function)| {
                let Some(source) = function.name.as_deref() else {
                    return None;
                };
                if let Some(decorated) = source.strip_prefix('?')
                    && let Some((method, _)) = decorated.split_once('@')
                    && !method.is_empty()
                    && sanitize(method) == method
                    && !globals::reserved_identifier(method)
                {
                    return Some((*addr, format!("{method}()")));
                }
                let Some((head, tail)) = source.split_once('(') else {
                    return None;
                };
                let Some((_, method)) = head.rsplit_once("::") else {
                    return None;
                };
                Some((*addr, format!("{method}({tail}")))
            })
            .collect(),
        go_value_shapes: image
            .functions
            .iter()
            .filter_map(|(addr, function)| {
                let Some(name) = function.name.as_deref() else {
                    return None;
                };
                go_values::shape(name).map(|_| (*addr, name.to_owned()))
            })
            .collect(),
        allocator_names: image
            .functions
            .iter()
            .filter_map(|(address, function)| {
                let Some(name) = function.name.as_ref() else {
                    return None;
                };
                if provenance::allocation_is_reallocated(name).is_some() {
                    Some((*address, name.clone()))
                } else {
                    None
                }
            })
            .collect(),
        function_returns: image
            .functions
            .iter()
            .filter_map(|(address, function)| {
                let Some(name) = function.name.as_deref() else {
                    return None;
                };
                let prototype = if function.sources.contains(&crate::loader::NameSource::Plt) {
                    crate::analysis::prototypes::for_image(name, image)
                } else {
                    crate::analysis::prototypes::runtime(name)
                };
                let Some(prototype) = prototype else {
                    return None;
                };
                Some((*address, prototype.ret.clone()))
            })
            .collect(),
        import_returns: image
            .imports
            .iter()
            .filter_map(|(address, name)| {
                let prototype = crate::analysis::prototypes::for_image(name, image);
                let Some(prototype) = prototype else {
                    return None;
                };
                Some((*address, prototype.ret.clone()))
            })
            .collect(),
        import_slots: image
            .imports
            .iter()
            .map(|(address, name)| {
                let name = match crate::analysis::prototypes::variable(name, image) {
                    Some(variable) => format!("data_{}", variable.name),
                    None => name.clone(),
                };
                (*address, name)
            })
            .collect(),
        import_addends: image
            .import_addends
            .iter()
            .map(|(slot, addend)| (*slot, *addend))
            .collect(),
        library_variables: image
            .data_symbols
            .iter()
            .filter_map(|(address, name)| {
                crate::analysis::prototypes::variable(name, image)
                    .map(|variable| (*address, variable))
            })
            .collect(),
        data: image
            .data_symbols
            .iter()
            .map(|(address, name)| (*address, name.clone()))
            .collect(),
        ..Symbols::default()
    };
    classes::name_tables(image, &mut symbols);
    symbols.constant_names = crate::tables::names(image).into_iter().collect();
    for variable in symbols.library_variables.values() {
        symbols.reserved_names.insert(variable.name.clone());
    }
    for name in image
        .functions
        .values()
        .flat_map(|function| function.name.iter().chain(&function.aliases))
        .chain(image.imports.values())
        .chain(image.data_symbols.values())
    {
        symbols.reserve_name(name);
    }
    if image.format == crate::loader::Format::MachO {
        symbols.use_macho_c_names();
    }
    for name in symbols
        .functions
        .values()
        .chain(symbols.import_slots.values())
        .chain(symbols.data.values())
        .chain(symbols.constant_names.values())
        .cloned()
        .collect::<Vec<_>>()
    {
        symbols.reserve_name(&name);
    }
    symbols
}

/// A demangled name as callers read it: without its parameter list, its
/// generic arguments, or the module path past the last two parts, as
/// `<core::io::error::Error>::new::<&str>` reads `Error::new`.
pub(crate) fn short_name(name: &str) -> String {
    let base = without_parameters(name);
    let last = |path: &str, keep: usize| -> String {
        let parts: Vec<&str> = path.split("::").filter(|part| !part.is_empty()).collect();
        parts[parts.len().saturating_sub(keep)..].join("::")
    };
    // `<Type as Trait>::method` is the type's method.
    if let Some(inner) = base.strip_prefix('<')
        && let Some(close) = matching_angle_close(inner)
    {
        let (qualified, rest) = (&inner[..close], &inner[close + 1..]);
        let owner = without_generics(qualified.split(" as ").next().unwrap_or(qualified));
        let owner = last(&owner, 1);
        let rest = without_generics(rest);
        let short = format!("{owner}::{}", last(&rest, 2));
        return short.trim_end_matches("::").to_owned();
    }
    let short = last(&without_generics(base), 2);
    if short.is_empty() {
        base.to_owned()
    } else {
        short
    }
}

/// The name a function's own structures start with: its short name, which
/// need not differ from another function's, as each function's output
/// defines its structures afresh.
pub(crate) fn structure_prefix(name: Option<&str>, addr: u64) -> String {
    match name {
        Some(name) => sanitize(&short_name(name)),
        None => format!("sub_{addr:x}"),
    }
}

/// Where the `>` closing the `<` before `text` falls in it.
fn matching_angle_close(text: &str) -> Option<usize> {
    let mut depth = 1usize;
    for (at, c) in text.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => {
                depth -= 1;
                if depth == 0 {
                    return Some(at);
                }
            }
            _ => {}
        }
    }
    None
}

/// The text without any `<...>` and what they hold.
fn without_generics(text: &str) -> String {
    let mut out = String::new();
    let mut depth = 0usize;
    for c in text.chars() {
        match c {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out.replace("::::", "::")
}

/// A demangled name without the parameter list it ends in, as
/// `ns::f(int, long) const` without `(int, long) const`.
fn without_parameters(name: &str) -> &str {
    let trimmed = name.trim_end_matches(" const").trim_end_matches(['&', ' ']);
    if !trimmed.ends_with(')') {
        return name;
    }
    let mut depth = 0;
    for (at, c) in trimmed.char_indices().rev() {
        match c {
            ')' => depth += 1,
            '(' => {
                depth -= 1;
                if depth == 0 {
                    return if at == 0 { name } else { &trimmed[..at] };
                }
            }
            _ => {}
        }
    }
    name
}

pub(crate) fn sanitize(name: &str) -> String {
    let mut sanitized = String::with_capacity(name.len());
    for c in name.chars() {
        sanitized.push(if c.is_ascii_alphanumeric() || c == '_' {
            c
        } else {
            '_'
        });
    }
    sanitized
}

#[cfg(test)]
mod tests;

/// Inspect frame storage using the same layout that the renderer uses.
pub(crate) fn project_locals(
    ir: &crate::ir::FunctionIr,
) -> Vec<(i64, String, crate::ir::CType, u64)> {
    let types = variable_types(ir);
    let frames = crate::passes::frame_slots::block_entry_frame_offsets(
        ir,
        crate::arch::stack_pointer(ir.isa),
    );
    let roles = naming::roles::infer(ir, &Symbols::default());
    let locals =
        locals::stack_locals_with_roles(ir, &frames, &types, &Symbols::default(), &roles, &[]);
    let mut seen = std::collections::HashSet::new();
    locals
        .declarations
        .iter()
        .flat_map(|local| local.named())
        .filter(|local| seen.insert(local.slot))
        .map(|local| {
            (
                local.slot,
                local.name.clone(),
                local
                    .ty
                    .clone()
                    .unwrap_or_else(|| crate::ir::CType::int(local.width, local.signed)),
                if local.views.is_empty() {
                    u64::try_from(local.size)
                        .unwrap_or(0)
                        .max(u64::from(local.width))
                } else {
                    0
                },
            )
        })
        .collect()
}

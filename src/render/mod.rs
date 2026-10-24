mod abi;
mod abi_objects;
mod body;
mod calls;
mod expr;
mod frame_registers;
mod function;
mod globals;
mod int;
mod jumps;
mod layouts;
mod locals;
mod machine;
mod naming;
mod params;
mod prelude;
mod provenance;
mod stack_bytes;
mod stmt;
mod string_loops;
pub mod structure;
mod symbols;
mod transfers;
mod variables;
mod vector_helpers;
mod widths;

use body::{indent, render_node, render_nodes, via_comment};
use calls::system_call_name;
#[cfg(test)]
use function::code_mentions;
pub(crate) use function::structure_definition;
pub(crate) use function::variable_types;
use function::{declaration, vacant_name, variable_name};
pub use function::{render, render_with_dependencies};
pub(crate) use globals::reserved_identifier;
pub use prelude::{Prelude, combine};
pub(crate) use stmt::render_stmt;
use stmt::{argument, conformed, narrow_write, returned};
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
}

use crate::arch::stack_pointer;
use expr::condition;
use std::collections::HashMap;

use crate::analysis::refs::Reference;
use crate::ir::{BinOp, CType, Expr, FunctionIr, Stmt};
use crate::passes::frame_slots::block_frames;
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
    let mut bases: HashMap<String, usize> = HashMap::new();
    for function in image.functions.values() {
        if let Some(name) = &function.name {
            *bases.entry(sanitize(&short_name(name))).or_default() += 1;
        }
    }
    let mut used = std::collections::HashSet::new();
    let functions = image
        .functions
        .iter()
        .filter_map(|(address, function)| {
            let Some(name) = function.name.as_ref() else {
                return None;
            };
            let base = sanitize(&short_name(name));
            let mut name = base.clone();
            if bases.get(&base) != Some(&1) {
                let candidate = format!("{base}_{address:x}");
                name = candidate.clone();
                let mut suffix = 2;
                while bases.contains_key(&name) || used.contains(&name) {
                    name = format!("{candidate}_{suffix}");
                    suffix += 1;
                }
            }
            used.insert(name.clone());
            Some((*address, name))
        })
        .collect();
    let mut symbols = Symbols {
        functions,
        allocator_names: image
            .functions
            .iter()
            .filter_map(|(address, function)| {
                let Some(name) = function.name.as_ref() else {
                    return None;
                };
                if provenance::allocator(name).is_some() {
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
                    crate::analysis::prototypes::of(
                        name,
                        image.format == crate::loader::Format::MachO,
                    )
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
                let prototype = crate::analysis::prototypes::of(
                    name,
                    image.format == crate::loader::Format::MachO,
                );
                let Some(prototype) = prototype else {
                    return None;
                };
                Some((*address, prototype.ret.clone()))
            })
            .collect(),
        import_slots: image
            .imports
            .iter()
            .map(|(address, name)| (*address, name.clone()))
            .collect(),
        data: image
            .data_symbols
            .iter()
            .map(|(address, name)| (*address, name.clone()))
            .collect(),
        ..Symbols::default()
    };
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
        && let Some(close) = matching_close(inner)
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
fn matching_close(text: &str) -> Option<usize> {
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
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests;

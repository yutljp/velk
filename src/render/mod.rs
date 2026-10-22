mod abi;
mod abi_objects;
mod calls;
mod expr;
mod globals;
mod int;
mod locals;
mod naming;
mod params;
pub mod structure;
mod symbols;
mod variables;
mod widths;

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
use crate::render::expr::render_expr;
use crate::render::expr::render_value;
use crate::render::expr::slot_access;
use crate::render::expr::type_of;
use crate::render::expr::{render_at, render_value_at};
use crate::render::locals::Locals;
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
            let base = sanitize(&short_name(function.name.as_ref()?));
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
    for name in symbols.functions.values().cloned().collect::<Vec<_>>() {
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

/// The longest structure definition written on one line.
const STRUCTURE_LINE: usize = 100;

pub fn render(
    ir: &FunctionIr,
    references: &[Reference],
    symbols: &Symbols,
    data_ranges: &[(u64, u64)],
) -> String {
    render_with_dependencies(ir, references, symbols, data_ranges).code
}

/// Print entry segment reads as external providers without choosing their values.
pub fn render_with_dependencies(
    ir: &FunctionIr,
    references: &[Reference],
    symbols: &Symbols,
    data_ranges: &[(u64, u64)],
) -> Rendered {
    let mut folded = ir.clone();
    crate::analysis::variadic::drop_register_saves(&mut folded);
    params::fold_saved_parameters(&mut folded);
    // A saved parameter returned reads as the parameter now.
    crate::analysis::typing::apply_pointer_return(&mut folded);
    let mut logical = abi::prepare(&mut folded, symbols);
    let ir = &folded;
    let frames = block_frames(ir, stack_pointer(ir.isa));
    let variable_types =
        variables::variable_types(ir, &narrow_registers(ir), float_return(&ir.ret_type));
    let locals = stack_locals(ir, &frames, &variable_types);
    if let Some(logical) = &mut logical {
        let params: std::collections::HashSet<_> =
            ir.params.iter().map(|param| param.index).collect();
        let mut reserved: std::collections::HashSet<String> = locals
            .decls
            .iter()
            .map(|local| local.name.clone())
            .collect();
        for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
            let (writes, reads) = crate::ir::visit::statement_registers(stmt);
            for register in writes
                .into_iter()
                .chain(reads)
                .filter(|register| !params.contains(register))
            {
                reserved.insert(crate::ir::reg_name(ir.isa, register, 64));
                reserved.insert(crate::ir::reg_name(ir.isa, register, 32));
            }
        }
        logical.resolve_names(
            reserved,
            variable_types
                .values()
                .chain(locals.decls.iter().filter_map(|local| local.ty.as_ref()))
                .chain(ir.members.iter().map(|member| &member.ty))
                .chain(std::iter::once(&ir.ret_type))
                .map(ToString::to_string),
        );
    }
    render_with(
        ir,
        references,
        locals,
        symbols,
        data_ranges,
        logical.as_ref(),
    )
}

/// The precision of a float the function returns.
fn float_return(ty: &CType) -> Option<crate::ir::Precision> {
    ty.is_sse_float().then(|| {
        if ty.to_string().contains("double") {
            crate::ir::Precision::Double
        } else {
            crate::ir::Precision::Single
        }
    })
}

/// The type the output declares each variable with.
pub(crate) fn variable_types(ir: &FunctionIr) -> std::collections::BTreeMap<u16, CType> {
    variables::variable_types(ir, &narrow_registers(ir), float_return(&ir.ret_type))
}

/// Whether C scales arithmetic on a pointer of this type: it points at
/// something wider than a byte.
fn scales(ty: &CType) -> bool {
    match ty {
        CType::Pointer(target) => {
            !matches!(target.as_ref(), CType::Void) && ty.pointee_size() != Some(1)
        }
        _ => false,
    }
}

fn render_with(
    ir: &FunctionIr,
    references: &[Reference],
    locals: Locals,
    symbols: &Symbols,
    data_ranges: &[(u64, u64)],
    logical: Option<&abi::Plan>,
) -> Rendered {
    let mut names: HashMap<u16, &str> = ir
        .params
        .iter()
        .map(|param| (param.index, param.name.as_str()))
        .collect();
    // Any other general register the body uses is a variable of its own;
    // Go keeps the running goroutine in r14.
    let machine: Vec<(u16, String)> = general_registers(ir)
        .into_iter()
        .filter(|index| !names.contains_key(index))
        .map(|index| match index {
            14 if ir.convention == crate::ir::Convention::GoAmd64 => (index, "g".to_owned()),
            _ => (index, crate::ir::reg_name(ir.isa, index, 64)),
        })
        .collect();
    for (index, name) in &machine {
        names.insert(*index, name);
    }
    let wide_params: std::collections::HashSet<u16> = ir
        .params
        .iter()
        .filter(|param| !param.ty.is_narrow())
        .map(|param| param.index)
        .collect();
    let narrow_regs = narrow_registers(ir);
    let float_return = float_return(&ir.ret_type);
    let mut variable_types = variables::variable_types(ir, &narrow_regs, float_return);
    if let Some(logical) = logical {
        for capture in &logical.captures {
            variable_types.remove(&capture.register);
        }
        for pointer in &logical.pointers {
            variable_types.remove(&pointer.register);
        }
    }
    let mut declared_registers =
        declared_types(ir, &variable_types, machine.iter().map(|(index, _)| *index));
    let floats: HashMap<u16, crate::ir::Precision> = variable_types
        .iter()
        .filter_map(|(index, ty)| match ty.to_string().as_str() {
            "double" => Some((*index, crate::ir::Precision::Double)),
            "float" => Some((*index, crate::ir::Precision::Single)),
            _ => None,
        })
        .collect();
    let members: HashMap<(String, i64), crate::ir::Member> = ir
        .members
        .iter()
        .cloned()
        .chain(ir.structures.iter().flat_map(|structure| {
            structure.fields.iter().filter_map(move |(offset, ty)| {
                let width = match ty {
                    CType::Pointer(_) => 8,
                    _ => u64::from(CType::pointer_to(ty.clone()).pointee_size()?),
                };
                Some(crate::ir::Member {
                    structure: structure.name.clone(),
                    offset: i64::try_from(*offset).ok()?,
                    name: format!("field_0x{offset:x}"),
                    ty: ty.clone(),
                    width,
                })
            })
        }))
        .map(|member| ((member.structure.clone(), member.offset), member))
        .collect();
    let arrays: HashMap<String, naming::Layout> = ir
        .structures
        .iter()
        .filter_map(|structure| {
            let layout = naming::Layout {
                size: structure.size?,
            };
            Some((structure.name.clone(), layout))
        })
        .collect();
    let scaled: std::collections::HashSet<u16> = ir
        .params
        .iter()
        .map(|param| (param.index, &param.ty))
        .chain(variable_types.iter().map(|(index, ty)| (*index, ty)))
        .filter(|(_, ty)| scales(ty))
        .map(|(index, _)| index)
        .collect();
    let element_types = ir
        .params
        .iter()
        .map(|param| (param.index, &param.ty))
        .chain(variable_types.iter().map(|(index, ty)| (*index, ty)))
        .filter_map(|(index, ty)| match ty {
            CType::Pointer(target) => Some((index, target.as_ref().clone())),
            _ => None,
        })
        .collect();
    // `char` alone, which is neither `signed char` nor `unsigned char`.
    let plain_char = |ty: &CType| match ty {
        CType::Pointer(target) => match target.as_ref() {
            CType::Named(name) => name
                .split_whitespace()
                .filter(|word| !matches!(*word, "const" | "volatile"))
                .eq(["char"]),
            _ => false,
        },
        _ => false,
    };
    let mut plain_chars: std::collections::HashSet<String> = ir
        .params
        .iter()
        .filter(|param| plain_char(&param.ty))
        .map(|param| param.name.clone())
        .collect();
    plain_chars.extend(
        variable_types
            .iter()
            .filter(|(_, ty)| plain_char(ty))
            .map(|(index, _)| match names.get(index) {
                Some(name) => (*name).to_owned(),
                None => crate::ir::reg_name(ir.isa, *index, 64),
            }),
    );
    plain_chars.extend(
        locals
            .decls
            .iter()
            .filter(|local| local.ty.as_ref().is_some_and(plain_char))
            .map(|local| local.name.clone()),
    );
    let local_types = || {
        locals
            .decls
            .iter()
            .filter_map(|local| Some((local.name.clone(), local.ty.as_ref()?)))
    };
    let local_element_types = local_types()
        .filter_map(|(name, ty)| match ty {
            CType::Pointer(target) => Some((name, target.as_ref().clone())),
            _ => None,
        })
        .collect();
    let local_scaled = local_types()
        .filter(|(_, ty)| scales(ty))
        .map(|(name, _)| name)
        .collect();
    let mut reserved: Vec<String> = names
        .values()
        .map(|name| (*name).to_owned())
        .chain(locals.decls.iter().map(|local| local.name.clone()))
        .chain(ir.stack_params.iter().map(|param| param.name.clone()))
        .chain(
            variable_types
                .keys()
                .map(|index| crate::ir::reg_name(ir.isa, *index, 64)),
        )
        .chain(symbols.functions.values().map(|name| sanitize(name)))
        .chain(symbols.import_slots.values().map(|name| sanitize(name)))
        .collect();
    if let Some(logical) = logical {
        reserved.extend(logical.reserved_names());
    }
    reserved.push(sanitize(
        &symbols
            .functions
            .get(&ir.addr)
            .cloned()
            .or_else(|| ir.name.clone())
            .unwrap_or_else(|| format!("sub_{:x}", ir.addr)),
    ));
    reserved.extend(ir.blocks.iter().flat_map(|block| &block.stmts).filter_map(
        |stmt| match stmt {
            Stmt::Call {
                target: Some(target),
                through: None,
                ..
            } if !symbols.functions.contains_key(target) => Some(format!("sub_{target:x}")),
            _ => None,
        },
    ));
    for ty in ir
        .params
        .iter()
        .map(|param| &param.ty)
        .chain(ir.stack_params.iter().map(|param| &param.ty))
        .chain(variable_types.values())
        .chain(locals.decls.iter().filter_map(|local| local.ty.as_ref()))
        .chain(std::iter::once(&ir.ret_type))
    {
        reserved.extend(
            ty.to_string()
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .filter(|name| !name.is_empty())
                .map(str::to_owned),
        );
    }
    let mut reads = std::collections::HashSet::new();
    if ir.isa == crate::loader::Isa::X86_64 {
        for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
            for value in stmt.operands() {
                crate::ir::visit::expr_reads(value, &mut reads);
            }
        }
    }
    let needed: Vec<_> = [
        (SegmentBase::Fs, crate::arch::x86::FS_BASE, "fs"),
        (SegmentBase::Gs, crate::arch::x86::GS_BASE, "gs"),
    ]
    .into_iter()
    .filter(|(_, index, _)| reads.contains(index) && !names.contains_key(index))
    .collect();
    let mut segment_bases = Vec::new();
    if !needed.is_empty() {
        let mut segment_reserved: std::collections::HashSet<String> = reserved
            .iter()
            .cloned()
            .chain(symbols.reserved_names.iter().cloned())
            .chain(symbols.data.values().map(|name| sanitize(name)))
            .collect();
        for (segment, index, base) in needed {
            let provider = vacant_name(&format!("velk_x86_{base}_base"), &mut segment_reserved);
            let snapshot = vacant_name(&format!("{base}_base"), &mut segment_reserved);
            reserved.extend([provider.clone(), snapshot.clone()]);
            declared_registers.insert(index, declared(&CType::U64, false).expect("an integer"));
            segment_bases.push((segment, index, provider, snapshot));
        }
    }
    for (_, index, _, snapshot) in &segment_bases {
        names.insert(*index, snapshot);
    }
    let mut value_bits = int::value_bits(ir);
    if let Some(logical) = logical {
        for capture in &logical.captures {
            declared_registers.insert(
                capture.register,
                declared(&CType::U64, false).expect("an integer"),
            );
            value_bits.remove(&capture.register);
        }
    }
    let mut ctx = Ctx {
        abi: logical,
        isa: ir.isa,
        void_return: ir.ret_type == CType::Void,
        float_return,
        names,
        landing_pads: ir.landing_pads.iter().cloned().collect(),
        strings: references
            .iter()
            .filter(|reference| reference.pointer.is_none())
            .filter_map(|reference| Some((reference.addr, reference.text.clone()?)))
            .collect(),
        slots: locals.slots,
        parameter_addresses: locals.parameter_addresses,
        local_parts: locals.parts,
        local_widths: locals.widths,
        local_pointer_types: locals
            .decls
            .iter()
            .filter_map(|local| {
                let ty = local.ty.as_ref().filter(|ty| ty.is_pointer())?;
                Some((local.name.clone(), ty.to_string().trim_end().to_owned()))
            })
            .collect(),
        local_floats: locals
            .decls
            .iter()
            .filter_map(|local| {
                let precision = match local.ty.as_ref()?.to_string().as_str() {
                    "double" => crate::ir::Precision::Double,
                    "float" => crate::ir::Precision::Single,
                    _ => return None,
                };
                Some((local.name.clone(), precision))
            })
            .collect(),
        signed_locals: locals
            .decls
            .iter()
            .filter(|local| match &local.ty {
                Some(ty) => matches!(ty, CType::Int { signed: true, .. }),
                None => local.signed,
            })
            .map(|local| local.name.clone())
            .collect(),
        local_element_types,
        local_scaled,
        wide_params,
        symbols,
        globals: globals::Globals::new(symbols, reserved),
        data_ranges,
        members,
        element_types,
        plain_chars,
        arrays,
        narrow_regs,
        floats,
        scaled,
        returned: declared(&ir.ret_type, false),
        declared: declared_registers,
        pointer_types: ir
            .params
            .iter()
            .map(|param| (param.index, &param.ty))
            .chain(variable_types.iter().map(|(index, ty)| (*index, ty)))
            .filter(|(_, ty)| ty.is_pointer())
            .map(|(index, ty)| (index, ty.to_string().trim_end().to_owned()))
            .collect(),
        ret_pointer: ir
            .ret_type
            .is_pointer()
            .then(|| ir.ret_type.to_string().trim_end().to_owned()),
        value_bits,
        read_once: Default::default(),
        taken: Default::default(),
    };

    let mut out = String::new();
    let name = ir
        .name
        .clone()
        .unwrap_or_else(|| format!("sub_{:x}", ir.addr));
    out.push_str(&format!("/* velk pseudo-C: {name} @ 0x{:x} */\n", ir.addr));
    // The function goes by the name its callers use.
    let name = symbols.functions.get(&ir.addr).cloned().unwrap_or(name);
    for reference in references {
        out.push_str(&format!("/* ref: {} */\n", reference.describe()));
    }
    // A pointer read as one scalar is no structure, and one to a structure
    // the debug info names needs no note of its fields.
    for (access, line) in ir.accesses.iter().zip(ir.access_lines()) {
        if naming::scalar_pointer(&Expr::reg(access.register, 64), &ctx).is_none()
            && !ctx.element_types.get(&access.register).is_some_and(
                |target| matches!(target, CType::Named(name) if name.starts_with("struct ")),
            )
        {
            out.push_str(&format!("/* struct: {line} */\n"));
        }
    }
    // Each definition, to drop the ones nothing in the function names once
    // it is written: folding values into their readers can leave a
    // structure without its variable.
    let mut definitions: Vec<(String, String)> = Vec::new();
    let definitions_at = out.len();
    for structure in &ir.structures {
        let mut members = Vec::new();
        let mut end = 0;
        for (offset, ty) in &structure.fields {
            if *offset > end {
                members.push(format!("uint8_t gap_0x{end:x}[0x{:x}];", offset - end));
            }
            members.push(format!("{ty} field_0x{offset:x};"));
            end = offset
                + match ty {
                    CType::Pointer(_) => 8,
                    _ => CType::pointer_to(ty.clone())
                        .pointee_size()
                        .map_or(0, u64::from),
                };
        }
        if let Some(size) = structure.size
            && size > end
        {
            members.push(format!("uint8_t gap_0x{end:x}[0x{:x}];", size - end));
        }
        let definition = defined(&format!("struct {}", structure.name), &members);
        out.push_str(&definition);
        definitions.push((structure.name.clone(), definition));
    }
    let prototypes_at = out.len();
    out.push_str(&format!(
        "{} {{\n",
        declaration(
            &ir.ret_type,
            &format!(
                "{}({})",
                sanitize(&name),
                logical.map_or_else(|| signature(ir), abi::Plan::signature)
            )
        )
    ));
    let mut decls = locals.decls;
    // The numeric suffix of `local_N` is its order of first use.
    decls.sort_by_key(|local| {
        local
            .name
            .rsplit_once('_')
            .and_then(|(_, index)| index.parse::<usize>().ok())
            .unwrap_or(0)
    });
    // The body is rendered first so only slots it names get declared.
    let mut body = String::new();
    let mut nodes = structure_best(ir);
    // A function that returns nothing needs no return at its end, unless a
    // label stands before it.
    if ctx.void_return
        && matches!(nodes.last(), Some(Node::Stmt(Stmt::Ret { .. })))
        && !matches!(nodes.iter().rev().nth(1), Some(Node::Label(_)))
    {
        nodes.pop();
    }
    ctx.read_once = calls::read_once(&nodes);
    render_nodes(&nodes, 1, &mut body, &ctx);
    let segment_bases: Vec<_> = segment_bases
        .iter()
        .filter(|(_, _, _, snapshot)| code_mentions(&body, snapshot))
        .collect();
    // A function whose address the body takes is declared ahead of it,
    // with no type known for it.
    let own = sanitize(&name);
    let mut prototypes: String = ctx
        .taken
        .borrow()
        .iter()
        .filter(|taken| **taken != own)
        .map(|taken| format!("void {taken}(void);\n"))
        .collect();
    for (_, _, provider, _) in &segment_bases {
        prototypes.push_str(&format!("uint64_t {provider}(void);\n"));
    }
    out.insert_str(prototypes_at, &prototypes);
    let mut declared = 0;
    if let Some(logical) = logical {
        for declaration in logical.declarations() {
            indent(1, &mut out);
            out.push_str(&declaration);
            out.push('\n');
            declared += 1;
        }
    }
    for (_, _, provider, snapshot) in &segment_bases {
        indent(1, &mut out);
        out.push_str(&format!("uint64_t {snapshot} = {provider}();\n"));
        declared += 1;
    }
    for declaration in ctx.globals.declarations(&body) {
        indent(1, &mut out);
        out.push_str(&declaration);
        out.push('\n');
        declared += 1;
    }
    // A register the body uses beyond the parameters holds what it holds
    // on entry until the body sets it.
    for (_, name) in &machine {
        if variables::mentions(&body, name) {
            indent(1, &mut out);
            out.push_str(&format!("uint64_t {name};\n"));
            declared += 1;
        }
    }
    for (index, ty) in &variable_types {
        let name = ctx.register(*index, 64);
        // What a landing pad receives is no variable of the function.
        if matches!(*index, crate::ir::EXCEPTION | crate::ir::SELECTOR)
            || !variables::mentions(&body, &name)
        {
            continue;
        }
        indent(1, &mut out);
        out.push_str(&format!("{};\n", declaration(ty, &name)));
        declared += 1;
    }
    for local in &decls {
        if local.width == 0 || !body.contains(&local.name) {
            continue;
        }
        indent(1, &mut out);
        out.push_str(&format!(
            "{}; /* [sp{}{:x}] */\n",
            match &local.ty {
                Some(ty) => declaration(ty, &local.name),
                None => format!("{} {}", type_of(local.width, local.signed), local.name),
            },
            if local.slot < 0 { "-" } else { "+" },
            local.slot.unsigned_abs()
        ));
    }
    declared += decls
        .iter()
        .filter(|local| local.width != 0 && body.contains(&local.name))
        .count();
    if declared > 0 {
        out.push('\n');
    }
    out.push_str(&body);
    out.push_str("}\n");
    // The definition is the one place a structure nothing uses is named.
    for (name, definition) in definitions {
        if out.matches(&format!("struct {name} ")).count() == 1 {
            out = out.replacen(&definition, "", 1);
        }
    }
    let debug = debug_definitions(ir, &out);
    out.insert_str(definitions_at, &debug);
    Rendered {
        code: out,
        segment_bases: segment_bases
            .into_iter()
            .map(|(segment, _, provider, _)| SegmentBaseRead {
                segment: *segment,
                provider: provider.clone(),
            })
            .collect(),
    }
}

fn vacant_name(base: &str, reserved: &mut std::collections::HashSet<String>) -> String {
    let mut name = base.to_owned();
    let mut suffix = 2;
    while !reserved.insert(name.clone()) {
        name = format!("{base}_{suffix}");
        suffix += 1;
    }
    name
}

fn code_mentions(text: &str, name: &str) -> bool {
    let bytes = text.as_bytes();
    let mut at = 0;
    let mut member = false;
    while at < bytes.len() {
        if bytes[at..].starts_with(b"//") {
            while at < bytes.len() && bytes[at] != b'\n' {
                at += 1;
            }
        } else if bytes[at..].starts_with(b"/*") {
            at += 2;
            while at < bytes.len() && !bytes[at..].starts_with(b"*/") {
                at += 1;
            }
            at = (at + 2).min(bytes.len());
        } else if matches!(bytes[at], b'\'' | b'"') {
            member = false;
            let quote = bytes[at];
            at += 1;
            while at < bytes.len() {
                let next = bytes[at];
                at += 1;
                if next == b'\\' {
                    at = (at + 1).min(bytes.len());
                } else if next == quote {
                    break;
                }
            }
        } else if bytes[at..].starts_with(b"->") {
            member = true;
            at += 2;
        } else if bytes[at].is_ascii_alphabetic() || bytes[at] == b'_' {
            let start = at;
            while at < bytes.len() && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_') {
                at += 1;
            }
            if !member && &text[start..at] == name {
                return true;
            }
            member = false;
        } else {
            if !bytes[at].is_ascii_whitespace() {
                member = bytes[at] == b'.';
            }
            at += 1;
        }
    }
    false
}

/// A structure's definition: on one line when short, else a member a line.
fn defined(name: &str, members: &[String]) -> String {
    let line = format!("{name} {{ {} }};", members.join(" "));
    if line.len() <= STRUCTURE_LINE {
        return line + "\n";
    }
    let mut text = format!("{name} {{\n");
    for member in members {
        text.push_str(&format!("    {member}\n"));
    }
    text + "};\n"
}

/// The definitions from the debug info that the printed code needs to
/// compile: those of the structures and unions it reaches a member of or
/// holds by value, after those they hold by value in turn.
fn debug_definitions(ir: &FunctionIr, code: &str) -> String {
    let named = |name: &str| {
        code.match_indices(name).any(|(at, _)| {
            !code[at + name.len()..].starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
        })
    };
    let needed = |definition: &crate::ir::Definition| {
        named(&definition.name)
            && (definition.fields.iter().any(|field| {
                code.contains(&format!("->{field}")) || code.contains(&format!(".{field}"))
            }) || code
                .match_indices(&format!("{} ", definition.name))
                .any(|(at, _)| !code[at + definition.name.len() + 1..].starts_with('*')))
    };
    let mut ordered: Vec<&crate::ir::Definition> = Vec::new();
    fn place<'a>(
        definition: &'a crate::ir::Definition,
        all: &'a [crate::ir::Definition],
        ordered: &mut Vec<&'a crate::ir::Definition>,
        depth: usize,
    ) {
        if depth > 8 || ordered.iter().any(|placed| placed.name == definition.name) {
            return;
        }
        for inner in &definition.contains {
            if let Some(inner) = all.iter().find(|candidate| candidate.name == *inner) {
                place(inner, all, ordered, depth + 1);
            }
        }
        ordered.push(definition);
    }
    for definition in ir
        .definitions
        .iter()
        .filter(|definition| needed(definition))
    {
        place(definition, &ir.definitions, &mut ordered, 0);
    }
    ordered
        .iter()
        .map(|definition| {
            let mut members = definition.members.clone();
            if let Some(alignment) = definition.alignment
                && alignment.is_power_of_two()
                && !definition.compatible_profiles.is_empty()
                && let Some(first) = members.first_mut()
            {
                *first = format!("_Alignas({alignment}) {first}");
            }
            defined(&definition.name, &members)
        })
        .collect()
}

/// The general registers other than the stack pointer that the body reads
/// or writes.
fn general_registers(ir: &FunctionIr) -> std::collections::BTreeSet<u16> {
    let general = match ir.isa {
        crate::loader::Isa::X86_64 => 0..16,
        crate::loader::Isa::AArch64 => 0..31,
        crate::loader::Isa::Unsupported => 0..0,
    };
    let mut used = std::collections::HashSet::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        for value in stmt.operands() {
            crate::ir::visit::expr_reads(value, &mut used);
        }
        match stmt {
            Stmt::Assign { dest, .. }
            | Stmt::Call {
                result: Some(dest), ..
            } => {
                used.insert(dest.index);
            }
            _ => {}
        }
    }
    used.into_iter()
        .filter(|index| general.contains(index) && *index != stack_pointer(ir.isa))
        .collect()
}

/// How each parameter, variable and register named for the body is
/// declared, where its type is an integer or a pointer.
fn declared_types(
    ir: &FunctionIr,
    variables: &std::collections::BTreeMap<u16, CType>,
    machine: impl Iterator<Item = u16>,
) -> HashMap<u16, expr::Declared> {
    let mut types: HashMap<u16, expr::Declared> = machine
        .map(|index| (index, declared(&CType::U64, false).expect("an integer")))
        .collect();
    for (index, ty) in variables {
        types.extend(declared(ty, false).map(|declared| (*index, declared)));
    }
    for param in &ir.params {
        types.extend(declared(&param.ty, true).map(|declared| (param.index, declared)));
    }
    types
}

/// How a value of type `ty` is declared, for an integer or a pointer.
fn declared(ty: &CType, param: bool) -> Option<expr::Declared> {
    match ty.integer() {
        Some((bits, signed)) => Some(expr::Declared {
            bits,
            signed,
            param,
            integer: true,
        }),
        None => ty.is_pointer().then_some(expr::Declared {
            bits: 64,
            signed: false,
            param,
            integer: false,
        }),
    }
}

/// A store of `op(load(same address), rhs)` is a compound assignment.
fn update_of_same_location<'e>(
    addr: &Expr,
    value: &'e Expr,
    width: u8,
    ctx: &Ctx<'_>,
) -> Option<(&'static str, &'e Expr)> {
    // A mask to the stored width is the store's own truncation.
    let fits = |mask: &Expr| matches!(mask, Expr::Const(mask) if width < 8 && *mask == (1u64 << (u32::from(width) * 8)) - 1);
    let unmasked = |expr: &'e Expr| match expr {
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if fits(rhs) => lhs.as_ref(),
        other => other,
    };
    let Expr::Bin { op, lhs, rhs } = unmasked(value) else {
        return None;
    };
    // Keep explicit address conversions and byte scaling on pointer updates.
    if expr::print(lhs, ctx, 64).is_pointer() || expr::print(rhs, ctx, 64).is_pointer() {
        return None;
    }
    let symbol = match op {
        BinOp::Add => "+",
        BinOp::Sub => "-",
        BinOp::And => "&",
        BinOp::Or => "|",
        BinOp::Xor => "^",
        BinOp::Mul => "*",
        _ => return None,
    };
    let reads_place = |operand: &'e Expr| matches!(unmasked(operand), Expr::Load { addr: read, width: read_width, .. } if read.as_ref() == addr && *read_width == width);
    if reads_place(lhs) {
        return Some((symbol, rhs));
    }
    // `x = y + x` is `x += y` where the operands commute.
    let commutes = matches!(
        op,
        BinOp::Add | BinOp::And | BinOp::Or | BinOp::Xor | BinOp::Mul
    );
    (commutes && reads_place(rhs)).then_some((symbol, lhs))
}

/// The Linux name of a system call number, for the calls programs make
/// most.
fn system_call_name(convention: crate::ir::Convention, number: u64) -> Option<&'static str> {
    const X86: &[(u64, &str)] = &[
        (0, "read"),
        (1, "write"),
        (2, "open"),
        (3, "close"),
        (4, "stat"),
        (5, "fstat"),
        (8, "lseek"),
        (9, "mmap"),
        (10, "mprotect"),
        (11, "munmap"),
        (12, "brk"),
        (13, "rt_sigaction"),
        (14, "rt_sigprocmask"),
        (15, "rt_sigreturn"),
        (16, "ioctl"),
        (20, "writev"),
        (24, "sched_yield"),
        (27, "mincore"),
        (28, "madvise"),
        (35, "nanosleep"),
        (39, "getpid"),
        (56, "clone"),
        (57, "fork"),
        (59, "execve"),
        (60, "exit"),
        (61, "wait4"),
        (62, "kill"),
        (63, "uname"),
        (72, "fcntl"),
        (131, "sigaltstack"),
        (158, "arch_prctl"),
        (186, "gettid"),
        (200, "tkill"),
        (202, "futex"),
        (204, "sched_getaffinity"),
        (228, "clock_gettime"),
        (230, "clock_nanosleep"),
        (231, "exit_group"),
        (232, "epoll_wait"),
        (233, "epoll_ctl"),
        (234, "tgkill"),
        (257, "openat"),
        (281, "epoll_pwait"),
        (291, "epoll_create1"),
        (293, "pipe2"),
        (302, "prlimit64"),
        (318, "getrandom"),
    ];
    const ARM: &[(u64, &str)] = &[
        (17, "getcwd"),
        (25, "fcntl"),
        (29, "ioctl"),
        (56, "openat"),
        (57, "close"),
        (62, "lseek"),
        (63, "read"),
        (64, "write"),
        (66, "writev"),
        (93, "exit"),
        (94, "exit_group"),
        (98, "futex"),
        (101, "nanosleep"),
        (113, "clock_gettime"),
        (115, "clock_nanosleep"),
        (122, "sched_getaffinity"),
        (124, "sched_yield"),
        (129, "kill"),
        (130, "tkill"),
        (131, "tgkill"),
        (132, "sigaltstack"),
        (134, "rt_sigaction"),
        (135, "rt_sigprocmask"),
        (139, "rt_sigreturn"),
        (160, "uname"),
        (172, "getpid"),
        (178, "gettid"),
        (214, "brk"),
        (215, "munmap"),
        (220, "clone"),
        (221, "execve"),
        (222, "mmap"),
        (226, "mprotect"),
        (232, "mincore"),
        (233, "madvise"),
        (260, "wait4"),
        (261, "prlimit64"),
        (278, "getrandom"),
    ];
    let table = match convention {
        crate::ir::Convention::SyscallX86 => X86,
        crate::ir::Convention::SyscallArm => ARM,
        _ => return None,
    };
    table
        .iter()
        .find(|(known, _)| *known == number)
        .map(|(_, name)| *name)
}

/// The `case` labels for `values`: a run of three or more consecutive values
/// reads as one range, `case 2 ... 9`.
fn case_labels(values: &[i64]) -> Vec<String> {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let mut labels = Vec::new();
    let mut start = 0;
    while start < sorted.len() {
        let mut end = start;
        while end + 1 < sorted.len() && sorted[end + 1] == sorted[end].wrapping_add(1) {
            end += 1;
        }
        if end - start >= 2 {
            labels.push(format!("case {} ... {}", sorted[start], sorted[end]));
        } else {
            labels.extend(
                sorted[start..=end]
                    .iter()
                    .map(|value| format!("case {value}")),
            );
        }
        start = end + 1;
    }
    labels
}

/// `name` declared as `ty`, the star of a pointer next to the name.
fn declaration(ty: &CType, name: &str) -> String {
    if ty.is_pointer() {
        format!("{ty}{name}")
    } else {
        format!("{ty} {name}")
    }
}

pub(crate) fn signature(ir: &FunctionIr) -> String {
    let declare = declaration;
    // Parameters in the caller's frame take their declared places among the
    // register ones.
    let mut registers = ir.params.iter();
    let mut parts = Vec::new();
    for position in 0..ir.params.len() + ir.stack_params.len() {
        match ir
            .stack_params
            .iter()
            .find(|param| param.position == position)
        {
            Some(param) => parts.push(declare(&param.ty, &param.name)),
            None => {
                if let Some(param) = registers.next() {
                    parts.push(declare(&param.ty, &param.name));
                }
            }
        }
    }
    if ir.variadic {
        parts.push("...".to_owned());
    }
    if parts.is_empty() {
        return "void".to_owned();
    }
    parts.join(", ")
}

fn indent(depth: usize, out: &mut String) {
    for _ in 0..depth {
        out.push_str("    ");
    }
}

/// `init; while (cond) { body; step; }` as `for (init; cond; step) { body }`,
/// when `init` and `step` write the one register or local the condition
/// reads, `step` updates it from itself, and no `continue` in the body
/// would skip the step.
fn for_loop(init: &Stmt, looped: &Node, depth: usize, ctx: &Ctx<'_>) -> Option<String> {
    let Node::While {
        prefix,
        cond,
        lhs,
        rhs,
        body,
    } = looped
    else {
        return None;
    };
    if !prefix.is_empty() {
        return None;
    }
    let (Node::Stmt(step), rest) = body.split_last()? else {
        return None;
    };
    // What the counter is: a register or a frame slot's address.
    enum Counter<'e> {
        Register(u16),
        Slot(&'e Expr),
    }
    let counter = match init {
        Stmt::Assign { dest, .. } => Counter::Register(dest.index),
        Stmt::Store { addr, .. } => Counter::Slot(addr),
        _ => return None,
    };
    let reads = |expr: &Expr| -> bool {
        match &counter {
            Counter::Register(index) => {
                let mut read = std::collections::HashSet::new();
                crate::ir::visit::collect_reads(expr, &mut read);
                read.contains(index)
            }
            Counter::Slot(addr) => loads_from(expr, addr),
        }
    };
    let steps = match (&counter, step) {
        (Counter::Register(index), Stmt::Assign { dest, value }) => {
            dest.index == *index && reads(value)
        }
        (
            Counter::Slot(addr),
            Stmt::Store {
                addr: written,
                value,
                ..
            },
        ) => written == *addr && reads(value),
        _ => false,
    };
    if !steps || !(reads(lhs) || reads(rhs)) || continues(rest) {
        return None;
    }
    if let Counter::Slot(addr) = counter
        && !ctx.slots.contains_key(&render_expr(addr, ctx))
    {
        return None;
    }
    let clause = |stmt: &Stmt| {
        let text = render_stmt(stmt, ctx);
        text.strip_suffix(';').unwrap_or(&text).to_owned()
    };
    // A step of one reads as `i++` or `i += 1`'s shorter form.
    let step_text = {
        let text = clause(step);
        match text.split_once(" = ") {
            Some((name, value)) if value == format!("{name} + 0x1") => format!("{name}++"),
            Some((name, value)) if value == format!("{name} - 0x1") => format!("{name}--"),
            _ => match text.strip_suffix(" += 0x1") {
                Some(name) => format!("{name}++"),
                None => text,
            },
        }
    };
    let mut out = String::new();
    indent(depth, &mut out);
    out.push_str(&format!(
        "for ({}; {}; {}) {{\n",
        clause(init),
        condition(*cond, lhs, rhs, ctx),
        step_text
    ));
    render_nodes(rest, depth + 1, &mut out, ctx);
    indent(depth, &mut out);
    out.push_str("}\n");
    Some(out)
}

/// Whether a load from `addr` appears in `expr`.
fn loads_from(expr: &Expr, addr: &Expr) -> bool {
    matches!(expr, Expr::Load { addr: read, .. } if read.as_ref() == addr)
        || crate::ir::visit::children(expr)
            .into_iter()
            .any(|child| loads_from(child, addr))
}

/// Whether a `continue` in `nodes` goes to the loop they are the body of,
/// rather than to one nested in it.
fn continues(nodes: &[Node]) -> bool {
    nodes.iter().any(|node| match node {
        Node::Continue => true,
        Node::If { then, els, .. } => continues(then) || continues(els),
        Node::Switch { arms, default, .. } => {
            arms.iter().any(|(_, body)| continues(body))
                || default.as_ref().is_some_and(|body| continues(body))
        }
        _ => false,
    })
}

/// Whether a `break` among the nodes leaves the switch they are in, rather
/// than a loop or switch inside them.
fn leaves_switch(nodes: &[Node]) -> bool {
    nodes.iter().any(|node| match node {
        Node::Break => true,
        Node::If { then, els, .. } => leaves_switch(then) || leaves_switch(els),
        _ => false,
    })
}

/// Whether the statements up to the next call leave `rax` alone, and the
/// call, whose arguments are known, reads no more of it than `al`.
fn only_vector_count(rest: &[Node]) -> bool {
    for node in rest {
        let Node::Stmt(stmt) = node else {
            return false;
        };
        let (writes, reads) = crate::ir::visit::statement_registers(stmt);
        match stmt {
            Stmt::Call { args: Some(_), .. } => {
                return !stmt.operands().into_iter().any(|operand| {
                    let mut read = std::collections::HashSet::new();
                    crate::ir::visit::collect_reads(operand, &mut read);
                    read.contains(&crate::arch::RETURN)
                });
            }
            _ if writes.contains(&crate::arch::RETURN) || reads.contains(&crate::arch::RETURN) => {
                return false;
            }
            Stmt::Assign { .. } | Stmt::Store { .. } => {}
            _ => return false,
        }
    }
    false
}

fn render_nodes(nodes: &[Node], depth: usize, out: &mut String, ctx: &Ctx<'_>) {
    let mut index = 0;
    while index < nodes.len() {
        // A compare-and-exchange: the old value read, and the new one stored
        // in its place when the old one was the expected one.
        if let (
            Node::Stmt(Stmt::Assign {
                dest,
                value:
                    loaded @ Expr::Load {
                        addr,
                        width,
                        signed: false,
                    },
            }),
            Some(Node::Stmt(Stmt::Store {
                addr: stored,
                width: stored_width,
                value:
                    Expr::Select {
                        cond: crate::ir::Cond::Eq,
                        lhs,
                        rhs: expected,
                        then: replacement,
                        els,
                    },
            })),
        ) = (&nodes[index], nodes.get(index + 1))
            && stored == addr.as_ref()
            && stored_width == width
            && expr::copy_address(addr, *width, ctx).is_none()
            && expr::fits(expected, u32::from(*width) * 8, ctx)
            && matches!(lhs.as_ref(), Expr::Reg { index: read, .. } if *read == dest.index)
            && matches!(els.as_ref(), Expr::Reg { index: read, .. } if *read == dest.index)
        {
            indent(depth, out);
            let address = format!(
                "({} *){}",
                type_of(*width, false),
                expr::print_value_at(addr, ctx, 64, false)
                    .within(12, false)
                    .text
            );
            let bits = u32::from(*width) * 8;
            let expected = expr::print_value_at(expected, ctx, bits, false).address_integer();
            let replacement = expr::print_value_at(replacement, ctx, bits, false).address_integer();
            let call = int::Printed::new(
                format!(
                    "__sync_val_compare_and_swap({address}, {}, {})",
                    expected.text, replacement.text
                ),
                int::Int::promoted(bits, false),
                int::ALL,
                13,
            );
            let pointer = ctx.pointer_types.get(&dest.index).map(String::as_str);
            out.push_str(&format!(
                "{} = {};\n",
                ctx.register(dest.index, dest.width),
                narrow_write(
                    dest.index,
                    dest.width,
                    conformed(loaded, call, pointer, ctx),
                    ctx
                )
            ));
            index += 2;
            continue;
        }
        // A value assigned only to be returned right away reads as returned;
        // a constant also through the mask a narrow return puts on it.
        if let (
            Node::Stmt(Stmt::Assign { dest, value }),
            Some(Node::Stmt(Stmt::Ret { value: returned })),
        ) = (&nodes[index], nodes.get(index + 1))
            && dest.index >= crate::ir::VARIABLE_BASE
            && !ctx.void_return
            && let Some(value) = match returned {
                Expr::Reg { index: read, width } if *read == dest.index => (dest.width == *width
                    || matches!(value, Expr::Const(c) if dest.width < 64 && *c >> dest.width == 0))
                .then(|| value.clone()),
                Expr::Bin {
                    op: BinOp::And,
                    lhs,
                    rhs,
                } => match (lhs.as_ref(), rhs.as_ref(), value) {
                    (Expr::Reg { index: read, .. }, Expr::Const(mask), Expr::Const(c))
                        if *read == dest.index =>
                    {
                        Some(Expr::Const(c & mask))
                    }
                    _ => None,
                },
                _ => None,
            }
        {
            indent(depth, out);
            out.push_str(&render_stmt(&Stmt::Ret { value }, ctx));
            out.push('\n');
            index += 2;
            continue;
        }
        // A trap right after a call is the one a compiler puts after a call
        // that never returns; the call already ends the path.
        if matches!(nodes[index], Node::Stmt(Stmt::Trap))
            && index > 0
            && matches!(nodes[index - 1], Node::Stmt(Stmt::Call { .. }))
        {
            index += 1;
            continue;
        }
        // Consecutive instructions the lifter could not model read as one
        // note instead of one comment per instruction.
        if let Node::Stmt(Stmt::Unsupported { text, .. }) = &nodes[index] {
            let mut merged = text.clone();
            let mut count = 1;
            while let Some(Node::Stmt(Stmt::Unsupported { text, .. })) = nodes.get(index + count) {
                merged.push_str(", ");
                merged.push_str(text);
                count += 1;
            }
            indent(depth, out);
            if count > 1 {
                out.push_str(&format!(
                    "/* unsupported ({} steps): {} */\n",
                    count, merged
                ));
            } else {
                out.push_str(&format!("/* unsupported: {} */\n", merged));
            }
            index += count;
            continue;
        }
        // On x86-64, `al` tells a variadic callee how many vector registers
        // carry arguments; setting it is no part of the call as C writes it.
        if ctx.isa == crate::loader::Isa::X86_64
            && let Some(Node::Stmt(Stmt::Assign {
                dest,
                value: Expr::Const(0..=8),
            })) = nodes.get(index)
            && dest.index == crate::arch::RETURN
            && only_vector_count(&nodes[index + 1..])
        {
            index += 1;
            continue;
        }
        // A counter set before a loop that tests it and steps it last reads
        // as a `for`.
        if let (Some(Node::Stmt(init)), Some(looped)) = (nodes.get(index), nodes.get(index + 1))
            && let Some(text) = for_loop(init, looped, depth, ctx)
        {
            out.push_str(&text);
            index += 2;
            continue;
        }
        // A call whose returned value the next statement takes reads as one
        // expression: `x = f(a)` or `return f(a)`.
        if let (Some(Node::Stmt(call @ Stmt::Call { .. })), Some(Node::Stmt(next))) =
            (nodes.get(index), nodes.get(index + 1))
            && let Some(text) = fused_call(call, next, ctx)
        {
            indent(depth, out);
            out.push_str(&text);
            out.push('\n');
            index += 2;
            continue;
        }
        if let (Some(Node::Stmt(call @ Stmt::Call { .. })), Some(next)) =
            (nodes.get(index), nodes.get(index + 1))
            && let Some(text) = calls::call_in_reader(call, next, depth, ctx)
        {
            out.push_str(&text);
            index += 2;
            continue;
        }
        // A further result a call before returned in another register, past
        // the copies of its other results.
        let further = |node: &Node| -> Option<u16> {
            match node {
                Node::Stmt(Stmt::Assign {
                    value: Expr::Reg { index, .. },
                    ..
                }) => Some(*index),
                _ => None,
            }
        };
        let call_before = nodes[..index]
            .iter()
            .rev()
            .find(|node| further(node).is_none())
            .and_then(|node| match node {
                Node::Stmt(Stmt::Call { convention, .. }) => Some(*convention),
                _ => None,
            });
        if let (Some(convention), Node::Stmt(copy @ Stmt::Assign { .. })) =
            (call_before, &nodes[index])
            && let Some(register) = further(&nodes[index])
            && convention.results().first() != Some(&register)
            && convention.results().contains(&register)
            && nodes[..index]
                .iter()
                .rev()
                .take_while(|node| further(node).is_some())
                .all(|node| {
                    further(node).is_some_and(|other| {
                        convention.results().first() != Some(&other)
                            && convention.results().contains(&other)
                    })
                })
        {
            indent(depth, out);
            // The register no longer holds the parameter it is named for.
            match copy {
                Stmt::Assign { dest, .. } if ctx.names.contains_key(&register) => {
                    out.push_str(&format!(
                        "{} = {};",
                        ctx.register(dest.index, dest.width),
                        crate::ir::reg_name(ctx.isa, register, 64)
                    ));
                }
                _ => out.push_str(&render_stmt(copy, ctx)),
            }
            out.push_str(" /* also returned by the call */\n");
            index += 1;
            continue;
        }
        render_node(&nodes[index], depth, out, ctx);
        index += 1;
    }
}

/// Whether the expression reads only the return register, whole or masked.
fn reads_return(value: &Expr) -> bool {
    match value {
        Expr::Reg { index, .. } => *index == crate::arch::RETURN,
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } => matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) && reads_return(lhs),
        _ => false,
    }
}

/// `call` and the statement after it as one, when that statement only takes
/// the call's result.
fn fused_call(call: &Stmt, next: &Stmt, ctx: &Ctx<'_>) -> Option<String> {
    let Stmt::Call { result, .. } = call else {
        return None;
    };
    // The call as an expression, without the variable that may take its value.
    let mut bare = call.clone();
    if let Stmt::Call { result, .. } = &mut bare {
        *result = None;
    }
    let call_text = render_stmt(&bare, ctx);
    let call_text = call_text.strip_suffix(';')?;
    let comment = via_comment(call, ctx);
    let takes = |value: &Expr| match result {
        Some(dest) => matches!(value, Expr::Reg { index, .. } if *index == dest.index),
        None => reads_return(value),
    };
    match next {
        Stmt::Ret { value } if takes(value) && !ctx.void_return => {
            Some(format!("return {call_text};{comment}"))
        }
        Stmt::Store { value, .. } if result.is_none() && reads_return(value) => {
            let stored = render_stmt(next, ctx);
            let (target, _) = stored.split_once(" = ")?;
            Some(format!("{target} = {call_text};{comment}"))
        }
        Stmt::Assign { value, .. } if result.is_none() && reads_return(value) => {
            let assigned = render_stmt(next, ctx);
            let (target, _) = assigned.split_once(" = ")?;
            Some(format!("{target} = {call_text};{comment}"))
        }
        _ => None,
    }
}

/// What a call that was or is indirect reads its callee's address from,
/// as a comment after it.
fn via_comment(stmt: &Stmt, ctx: &Ctx<'_>) -> String {
    let Stmt::Call {
        target,
        via: Some(via),
        ..
    } = stmt
    else {
        return String::new();
    };
    let name = |addr: u64| {
        ctx.symbols
            .functions
            .get(&addr)
            .map_or_else(|| format!("sub_{addr:x}"), |name| sanitize(name))
    };
    match target {
        Some(_) => format!(" /* via {} */", via.describe(&name)),
        None => format!(" /* {} */", via.describe(&name)),
    }
}

fn render_node(node: &Node, depth: usize, out: &mut String, ctx: &Ctx<'_>) {
    match node {
        Node::Stmt(stmt) => {
            let text = render_stmt(stmt, ctx) + &via_comment(stmt, ctx);
            if !text.is_empty() {
                for line in text.lines() {
                    indent(depth, out);
                    out.push_str(line);
                    out.push('\n');
                }
            }
        }
        Node::Label(address) => {
            if let Some(sites) = ctx.landing_pads.get(address) {
                let ranges: Vec<String> = sites
                    .iter()
                    .map(|(start, end)| format!("0x{start:x}-0x{end:x}"))
                    .collect();
                indent(depth.saturating_sub(1), out);
                out.push_str(&format!(
                    "/* landing pad: an exception thrown by a call at {} arrives here */\n",
                    ranges.join(", ")
                ));
            }
            indent(depth.saturating_sub(1), out);
            out.push_str(&format!("L_{address:x}:\n"));
        }
        Node::If {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => {
            indent(depth, out);
            out.push_str(&format!("if ({}) {{\n", condition(*cond, lhs, rhs, ctx)));
            render_nodes(then, depth + 1, out, ctx);
            // An `else` holding only another `if` continues the chain.
            let mut els = els;
            while let [
                Node::If {
                    cond,
                    lhs,
                    rhs,
                    then,
                    els: rest,
                },
            ] = els.as_slice()
            {
                indent(depth, out);
                out.push_str(&format!(
                    "}} else if ({}) {{\n",
                    condition(*cond, lhs, rhs, ctx)
                ));
                render_nodes(then, depth + 1, out, ctx);
                els = rest;
            }
            if !els.is_empty() {
                indent(depth, out);
                out.push_str("} else {\n");
                render_nodes(els, depth + 1, out, ctx);
            }
            indent(depth, out);
            out.push_str("}\n");
        }
        // A switch whose cases only leave it runs its default when the value
        // is none of them.
        Node::Switch {
            index,
            arms,
            default: Some(default),
        } if !arms.is_empty()
            && arms.iter().map(|(values, _)| values.len()).sum::<usize>() <= 4
            && arms
                .iter()
                .all(|(_, body)| matches!(body.as_slice(), [Node::Break]))
            && let rest = match default.split_last() {
                Some((Node::Break, rest)) => rest,
                _ => default.as_slice(),
            }
            && !leaves_switch(rest) =>
        {
            let tests: Vec<String> = arms
                .iter()
                .flat_map(|(values, _)| values)
                .map(|value| {
                    condition(crate::ir::Cond::Ne, index, &Expr::Const(*value as u64), ctx)
                })
                .collect();
            indent(depth, out);
            out.push_str(&format!("if ({}) {{\n", tests.join(" && ")));
            render_nodes(rest, depth + 1, out, ctx);
            indent(depth, out);
            out.push_str("}\n");
        }
        Node::Switch {
            index,
            arms,
            default,
        } => {
            indent(depth, out);
            out.push_str(&format!("switch ({}) {{\n", expr::switch_index(index, ctx)));
            for (values, body) in arms {
                for label in case_labels(values) {
                    indent(depth, out);
                    out.push_str(&format!("{label}:\n"));
                }
                render_nodes(body, depth + 1, out, ctx);
            }
            // Cases taking every value a mask leaves need no default.
            let covered = match index {
                Expr::Bin {
                    op: crate::ir::BinOp::And,
                    rhs,
                    ..
                } => match **rhs {
                    Expr::Const(mask) if mask < 4096 => (0..=mask as i64)
                        .all(|value| arms.iter().any(|(values, _)| values.contains(&value))),
                    _ => false,
                },
                _ => false,
            };
            if default.is_some() || !covered {
                indent(depth, out);
                out.push_str("default:\n");
            }
            match default {
                Some(body) => render_nodes(body, depth + 1, out, ctx),
                None if covered => {}
                // A table with no bounds check: the compiler knew no other
                // value reaches it.
                None => {
                    indent(depth + 1, out);
                    out.push_str("__builtin_unreachable();\n");
                }
            }
            indent(depth, out);
            out.push_str("}\n");
        }
        Node::Break => {
            indent(depth, out);
            out.push_str("break;\n");
        }
        Node::Continue => {
            indent(depth, out);
            out.push_str("continue;\n");
        }
        Node::Forever { body } => {
            indent(depth, out);
            out.push_str("for (;;) {\n");
            render_nodes(body, depth + 1, out, ctx);
            indent(depth, out);
            out.push_str("}\n");
        }
        Node::While {
            prefix,
            cond,
            lhs,
            rhs,
            body,
        } => {
            indent(depth, out);
            if prefix.is_empty() {
                out.push_str(&format!("while ({}) {{\n", condition(*cond, lhs, rhs, ctx)));
                render_nodes(body, depth + 1, out, ctx);
            } else {
                out.push_str("while (true) {\n");
                render_nodes(prefix, depth + 1, out, ctx);
                indent(depth + 1, out);
                out.push_str(&format!(
                    "if ({}) break;\n",
                    condition(cond.invert(), lhs, rhs, ctx)
                ));
                render_nodes(body, depth + 1, out, ctx);
            }
            indent(depth, out);
            out.push_str("}\n");
        }
        Node::DoWhile {
            cond,
            lhs,
            rhs,
            body,
        } => {
            indent(depth, out);
            out.push_str("do {\n");
            render_nodes(body, depth + 1, out, ctx);
            indent(depth, out);
            out.push_str(&format!(
                "}} while ({});\n",
                condition(*cond, lhs, rhs, ctx)
            ));
        }
    }
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

/// A call's argument. One the code zero-extends from 32 bits was set as a
/// 32-bit register, which the callee reads as a 32-bit parameter.
fn argument(value: &Expr, ctx: &Ctx<'_>) -> String {
    let bits = match value {
        Expr::Bin {
            op: BinOp::And,
            rhs,
            ..
        } if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) => 32,
        _ => 64,
    };
    render_value_at(value, ctx, bits, false)
}

/// A returned value, of which the caller sees what the return type holds.
fn returned(value: &Expr, ctx: &Ctx<'_>) -> String {
    let printed = expr::print_value_at(
        value,
        ctx,
        ctx.returned.map_or(64, |returned| returned.bits),
        ctx.returned.is_some_and(|returned| returned.integer),
    );
    conformed(value, printed, ctx.ret_pointer.as_deref(), ctx)
}

/// The value as C takes it into a pointer of type `pointer`, or into an
/// integer when that is None: C converts between the two only by a cast.
fn conformed(value: &Expr, printed: int::Printed, pointer: Option<&str>, ctx: &Ctx<'_>) -> String {
    match pointer {
        Some(ty)
            if printed.is_pointer()
                && (matches!(value, Expr::Const(_) | Expr::Select { .. })
                    || naming::pointer_target(value, ctx).is_some_and(|target| {
                        CType::pointer_to(target).to_string().trim_end() != ty.trim_end()
                    })) =>
        {
            format!("({ty}){}", printed.within(12, false).text)
        }
        // Memory read whole is read as the pointer it holds.
        Some(ty)
            if !printed.is_pointer()
                && let Expr::Load { addr, width: 8, .. } = value
                && expr::copy_address(addr, 8, ctx).is_none()
                && let Some(address) = printed
                    .text
                    .strip_prefix("*(uint64_t *)")
                    .or_else(|| printed.text.strip_prefix("*(int64_t *)")) =>
        {
            format!("*({ty}*){address}")
        }
        Some(ty) if !printed.is_pointer() && !matches!(value, Expr::Const(0)) => {
            format!("({ty}){}", printed.within(12, false).text)
        }
        None => printed.address_integer().text,
        _ => printed.text,
    }
}

fn value_precision(value: &Expr, ctx: &Ctx<'_>) -> Option<crate::ir::Precision> {
    match value {
        Expr::Apply { op, .. } => op.result_precision(),
        Expr::Reg { index, .. } => ctx.floats.get(index).copied(),
        Expr::Load { addr, width, .. } => ctx
            .slots
            .get(&render_expr(addr, ctx))
            .and_then(|name| ctx.local_floats.get(name))
            .filter(|precision| precision.bits() / 8 == *width)
            .copied(),
        _ => None,
    }
}

fn stored_value(value: &Expr, bits: u32, ctx: &Ctx<'_>) -> int::Printed {
    let Some(precision) = value_precision(value, ctx) else {
        return expr::print_value_at(value, ctx, bits, false);
    };
    let float = match precision {
        crate::ir::Precision::Single => "float",
        crate::ir::Precision::Double => "double",
    };
    let integer = type_of(precision.bits() / 8, false);
    let value = expr::float_operand(value, precision, ctx, 0, false);
    int::Printed::new(
        format!("((union {{ {float} value; {integer} bits; }}){{ .value = {value} }}).bits"),
        int::Int::promoted(u32::from(precision.bits()), false),
        int::ALL,
        13,
    )
    .ranging(int::Range::Unsigned(u32::from(precision.bits())))
}

fn narrow_write(index: u16, width: u8, value: String, ctx: &Ctx<'_>) -> String {
    if width < 64
        && ctx
            .abi
            .is_some_and(|abi| abi.captures.iter().any(|capture| capture.register == index))
    {
        format!("({})({value})", type_of(width / 8, false))
    } else {
        value
    }
}

fn aggregate_return(value: &Expr, ctx: &Ctx<'_>) -> Option<String> {
    let result = ctx.abi?.result.as_ref()?;
    if result.indirect {
        return Some(format!("return {};", result.name));
    }
    let values: &[Expr] = match value {
        Expr::Apply {
            op: crate::ir::Operation::Results,
            args,
        } => args,
        value => std::slice::from_ref(value),
    };
    if values.len() != result.pieces.len() {
        return None;
    }
    let mut lines = vec!["{".to_owned()];
    for ((_, name), value) in result.pieces.iter().zip(values) {
        lines.push(format!(
            "    uint64_t {name} = {};",
            stored_value(value, 64, ctx).text
        ));
    }
    for (piece, name) in &result.pieces {
        lines.push(format!(
            "    __builtin_memcpy((unsigned char *)&{} + 0x{:x}, &{name}, {});",
            result.name, piece.object_offset, piece.bytes
        ));
    }
    lines.push(format!("    return {};", result.name));
    lines.push("}".to_owned());
    Some(lines.join("\n"))
}

pub(crate) fn render_stmt(stmt: &Stmt, ctx: &Ctx<'_>) -> String {
    match stmt {
        Stmt::Assign { dest, value } => {
            // A destination whose readers only use the low 32 bits takes its
            // 32-bit register name.
            let target = if ctx.narrow_regs.contains(&dest.index)
                && dest.index != 0
                && !ctx.wide_params.contains(&dest.index)
            {
                ctx.register(dest.index, 32)
            } else {
                ctx.register(dest.index, dest.width)
            };
            if ctx.abi.is_some_and(|abi| {
                abi.captures
                    .iter()
                    .any(|capture| capture.register == dest.index)
            }) {
                let value = stored_value(value, u32::from(dest.width), ctx).text;
                return format!(
                    "{target} = {};",
                    narrow_write(dest.index, dest.width, value, ctx)
                );
            }
            if let Some(precision) = ctx.floats.get(&dest.index) {
                return format!(
                    "{target} = {};",
                    expr::float_operand(value, *precision, ctx, 0, false)
                );
            }
            // The stack pointer moving reads as arithmetic, not a local's address.
            if dest.index == crate::arch::stack_pointer(ctx.isa) {
                return format!("{target} = {};", render_expr(value, ctx));
            }
            // C keeps of the value what the destination is declared to hold.
            let declared = ctx.declared.get(&dest.index);
            let printed = expr::print_value_at(
                value,
                ctx,
                declared.map_or(64, |declared| declared.bits),
                declared.is_some_and(|declared| declared.integer),
            );
            let pointer = ctx.pointer_types.get(&dest.index).map(String::as_str);
            format!("{target} = {};", conformed(value, printed, pointer, ctx))
        }
        Stmt::Store { addr, value, width } => {
            // Memory keeps of the value the bits stored.
            let stored = u32::from(*width) * 8;
            if let Some(address) = expr::copy_address(addr, *width, ctx) {
                let ty = type_of(*width, false);
                let value = conformed(value, stored_value(value, stored, ctx), None, ctx);
                return format!("__builtin_memcpy({address}, &({ty}){{{value}}}, {width});");
            }
            let precision = value_precision(value, ctx);
            let view = precision
                .filter(|precision| u32::from(precision.bits()) == stored)
                .map_or(globals::View::Unsigned(*width), globals::View::Float);
            if let Some(target) = naming::global_access_as(addr, view, ctx)
                .or_else(|| naming::array_access_as(addr, *width, view, ctx))
                .or_else(|| naming::flat_array_access_as(addr, *width, view, ctx))
            {
                if let Some(precision) = precision
                    && u32::from(precision.bits()) == stored
                {
                    return format!(
                        "{target} = {};",
                        expr::float_operand(value, precision, ctx, 0, false)
                    );
                }
                return match update_of_same_location(addr, value, *width, ctx) {
                    Some((op, rhs)) if precision.is_none() => {
                        format!("{target} {op}= {};", render_at(rhs, ctx, stored))
                    }
                    _ => {
                        let printed = stored_value(value, stored, ctx);
                        format!("{target} = {};", conformed(value, printed, None, ctx))
                    }
                };
            }
            if let Some(member) = member_access(addr, *width, ctx) {
                if let Some(precision) = precision
                    && member.precision() == Some(precision)
                {
                    return format!(
                        "{} = {};",
                        member.text,
                        expr::float_operand(value, precision, ctx, 0, false)
                    );
                }
                if member.precision().is_none() {
                    return match update_of_same_location(addr, value, *width, ctx)
                        .filter(|_| precision.is_none() && member.integer().is_some())
                    {
                        Some((op, rhs)) => {
                            format!("{} {op}= {};", member.text, render_at(rhs, ctx, stored))
                        }
                        None => {
                            let printed = stored_value(value, stored, ctx);
                            let pointer = member.ty.is_pointer().then(|| member.ty.to_string());
                            format!(
                                "{} = {};",
                                member.text,
                                conformed(value, printed, pointer.as_deref(), ctx)
                            )
                        }
                    };
                }
            }
            let address = render_expr(addr, ctx);
            match ctx.slots.get(&address) {
                Some(name) => {
                    let mut target = slot_access(name, *width, false, ctx);
                    if ctx
                        .local_floats
                        .get(name)
                        .is_some_and(|local| precision.is_some_and(|source| source != *local))
                    {
                        target = format!("*({} *)&{name}", type_of(*width, false));
                    }
                    if let Some(precision) = ctx.local_floats.get(name)
                        && target == *name
                    {
                        return format!(
                            "{target} = {};",
                            expr::float_operand(value, *precision, ctx, 0, false)
                        );
                    }
                    match update_of_same_location(addr, value, *width, ctx)
                        .filter(|_| precision.is_none())
                    {
                        Some((op, rhs)) => {
                            format!("{} {}= {};", target, op, render_at(rhs, ctx, stored))
                        }
                        None => {
                            let pointer = (target == *name)
                                .then(|| ctx.local_pointer_types.get(name))
                                .flatten()
                                .map(String::as_str);
                            let printed = stored_value(value, stored, ctx);
                            format!("{target} = {};", conformed(value, printed, pointer, ctx))
                        }
                    }
                }
                None => format!(
                    "*({} *)({}) = {};",
                    type_of(*width, false),
                    expr::local_plus_offset(addr, ctx).unwrap_or(address),
                    conformed(value, stored_value(value, stored, ctx), None, ctx)
                ),
            }
        }
        Stmt::Brif {
            cond,
            lhs,
            rhs,
            target,
        } => format!(
            "if ({}) {{ goto L_{:x}; }}",
            condition(*cond, lhs, rhs, ctx),
            target
        ),
        Stmt::BrifFlags { cond, target } => {
            format!("if (/* {} */ true) {{ goto L_{:x}; }}", cond.text(), target)
        }
        Stmt::Br { target } => match target {
            Some(target) => format!("goto L_{target:x};"),
            None => "goto <dynamic>;".to_owned(),
        },
        Stmt::BrIndirect { target } => {
            let target = render_value(target, ctx);
            format!("goto *({target});")
        }
        Stmt::Switch {
            index,
            cases,
            default,
        } => {
            let mut text = format!("switch ({}) {{\n", expr::switch_index(index, ctx));
            let mut start = 0;
            while start < cases.len() {
                let target = cases[start].1;
                let mut end = start + 1;
                while end < cases.len() && cases[end].1 == target {
                    end += 1;
                }
                let values: Vec<i64> = cases[start..end].iter().map(|(value, _)| *value).collect();
                for label in case_labels(&values) {
                    text.push_str(&format!("    {label}: goto L_{target:x};\n"));
                }
                start = end;
            }
            if let Some(target) = default {
                text.push_str(&format!("    default: goto L_{target:x};\n"));
            }
            text.push('}');
            text
        }
        Stmt::Call {
            target,
            through,
            args,
            result,
            convention,
            ..
        } => {
            // A system call's number reads as the name the system gives it.
            let number = match args.as_ref().and_then(|values| values.first()) {
                Some(Expr::Const(number)) => system_call_name(*convention, *number),
                _ => None,
            };
            let mut args: Vec<String> = args
                .iter()
                .flatten()
                .map(|arg| argument(arg, ctx))
                .collect();
            if let (Some(name), Some(first)) = (number, args.first_mut()) {
                *first = format!("SYS_{name}");
            }
            let callee = match (through, target) {
                _ if matches!(
                    convention,
                    crate::ir::Convention::SyscallX86 | crate::ir::Convention::SyscallArm
                ) =>
                {
                    "syscall".to_owned()
                }
                // A named slot's function is called by its name.
                (Some(Expr::Load { addr, width: 8, .. }), _)
                    if let Expr::Const(slot) = addr.as_ref()
                        && let Some(name) = ctx.symbols.import_slots.get(slot) =>
                {
                    sanitize(name)
                }
                // C calls through a value only of a function's pointer type.
                (Some(through), _) => {
                    let text = render_value(through, ctx);
                    if text.contains(char::is_whitespace) {
                        format!("((uint64_t (*)())({text}))")
                    } else {
                        format!("((uint64_t (*)()){text})")
                    }
                }
                (None, Some(target)) => match ctx.symbols.functions.get(target) {
                    Some(name) => sanitize(name),
                    None => format!("sub_{target:x}"),
                },
                (None, None) => "sub_<dynamic>".to_owned(),
            };
            let assigned = result.map_or(String::new(), |dest| {
                format!("{} = ", ctx.register(dest.index, 64))
            });
            format!("{assigned}{callee}({});", args.join(", "))
        }
        Stmt::Ret { value } if ctx.abi.is_some_and(|abi| abi.result.is_some()) => {
            aggregate_return(value, ctx).expect("validated aggregate result pieces")
        }
        Stmt::Ret {
            value:
                Expr::Apply {
                    op: crate::ir::Operation::Results,
                    args,
                },
        } if ctx.abi.is_some() && args.len() == 1 => {
            if let Some(precision) = ctx.float_return {
                format!(
                    "return {};",
                    expr::float_operand(&args[0], precision, ctx, 0, false)
                )
            } else {
                format!("return {};", returned(&args[0], ctx))
            }
        }
        // Several values, the further ones in a comment.
        Stmt::Ret {
            value:
                Expr::Apply {
                    op: crate::ir::Operation::Results,
                    args,
                },
        } if !ctx.void_return && !args.is_empty() => {
            let further: Vec<String> = args[1..].iter().map(|arg| render_value(arg, ctx)).collect();
            format!(
                "return {}; /* also returns {} */",
                returned(&args[0], ctx),
                further.join(", ")
            )
        }
        Stmt::Ret { value } => {
            // A function that returns nothing carries no meaningful value.
            if ctx.void_return {
                "return;".to_owned()
            } else if let Some(precision) = ctx.float_return {
                format!(
                    "return {};",
                    expr::float_operand(value, precision, ctx, 0, false)
                )
            } else {
                format!("return {};", returned(value, ctx))
            }
        }
        Stmt::Unsupported { text, .. } => format!("/* unsupported: {text} */"),
        Stmt::Trap => "__builtin_trap();".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SegmentBase, SegmentBaseRead, Symbols, callee_names, render, render_with_dependencies,
    };
    use crate::ir::{
        BinOp, CType, Expr, FunctionIr, Operation, Param, Precision, RegRef, Stmt, VARIABLE_BASE,
    };
    use crate::loader::Isa;
    use std::collections::HashMap;

    fn rendered(ir: &FunctionIr) -> String {
        render(ir, &[], &Symbols::default(), &[])
    }

    fn assign(index: u16, value: Expr) -> Stmt {
        Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
        }
    }

    fn load(addr: Expr, width: u8) -> Expr {
        Expr::Load {
            addr: Box::new(addr),
            width,
            signed: false,
        }
    }

    fn object_access_ir(stmts: Vec<Stmt>) -> FunctionIr {
        use crate::ir::{
            AbiLocation, AbiPiece, AbiProfile, DeclaredSignature, Definition, Passing,
            RegisterClass, SignatureAbi, ValueAbi,
        };
        let mut ir = FunctionIr::single_block(Isa::AArch64, stmts);
        ir.params = vec![Param {
            index: 0,
            name: "a0".to_owned(),
            ty: CType::U64,
        }];
        ir.definitions = vec![Definition {
            name: "struct bytes".to_owned(),
            members: vec!["unsigned char bytes[24];".to_owned()],
            fields: vec!["bytes".to_owned()],
            contains: vec![],
            size: 24,
            alignment: Some(1),
            compatible_profiles: vec![AbiProfile::Aapcs64],
        }];
        ir.declared_signature = Some(DeclaredSignature {
            params: vec![("value".to_owned(), CType::Named("struct bytes".to_owned()))],
            ret: CType::U64,
            variadic: false,
            abi: Ok(SignatureAbi {
                profile: AbiProfile::Aapcs64,
                arguments: vec![ValueAbi {
                    aggregate: true,
                    size: 24,
                    alignment: 1,
                    defined_bits: vec![(0, 192)],
                    passing: Passing::Indirect {
                        pointer: AbiLocation::Register(0),
                        returned_pointer: None,
                    },
                }],
                result: Some(ValueAbi {
                    aggregate: false,
                    size: 8,
                    alignment: 8,
                    defined_bits: vec![(0, 64)],
                    passing: Passing::Direct(vec![AbiPiece {
                        location: AbiLocation::Register(0),
                        object_offset: 0,
                        bytes: 8,
                        class: Some(RegisterClass::Integer),
                    }]),
                }),
            }),
        });
        ir
    }

    #[test]
    fn object_loads_copy_the_exact_width_and_preserve_signedness() {
        for width in [1, 2, 4, 8] {
            for signed in [false, true] {
                let mut ir = object_access_ir(vec![Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(Expr::bin(BinOp::Add, Expr::reg(0, 64), Expr::Const(1))),
                        width,
                        signed,
                    },
                }]);
                let code = rendered(&ir);
                let ty = super::type_of(width, false);
                assert!(
                    code.contains(&format!(
                        "__builtin_memcpy(({ty}[1]){{0}}, value_address + 0x1, {width})"
                    )),
                    "{code}"
                );
                if signed {
                    assert!(code.contains(super::type_of(width, true)), "{code}");
                }
                ir.declared_signature = None;
                ir.params[0].ty = CType::pointer_to(CType::int(1, false));
                assert!(!rendered(&ir).contains("__builtin_memcpy"));
            }
        }
    }

    #[test]
    fn overlapping_object_store_copies_its_source_before_writing() {
        let address = Expr::bin(BinOp::Add, Expr::reg(0, 64), Expr::Const(1));
        let ir = object_access_ir(vec![
            Stmt::Store {
                addr: address.clone(),
                value: load(Expr::reg(0, 64), 8),
                width: 8,
            },
            Stmt::Ret {
                value: load(address, 8),
            },
        ]);
        let code = rendered(&ir);
        let store = code
            .lines()
            .find(|line| line.contains("__builtin_memcpy(value_address + 0x1,"))
            .expect("an object store");
        assert_eq!(store.matches("__builtin_memcpy").count(), 2, "{code}");
        assert_eq!(store.matches("value_address, 8").count(), 1, "{code}");
        assert!(store.contains("&(uint64_t){"), "{code}");
    }

    #[test]
    fn object_pointer_load_converts_copied_integer_bits() {
        let mut ir = object_access_ir(vec![Stmt::Ret {
            value: load(Expr::reg(0, 64), 8),
        }]);
        ir.declared_signature.as_mut().unwrap().ret = CType::pointer_to(CType::int(1, false));
        let code = rendered(&ir);
        assert!(
            code.contains("__builtin_memcpy((uint64_t[1]){0}, value_address, 8)"),
            "{code}"
        );
        assert!(!code.contains("*(uint8_t **)__builtin_memcpy"), "{code}");
    }

    #[test]
    fn floating_object_loads_reinterpret_copied_bits() {
        for precision in [Precision::Single, Precision::Double] {
            let width = precision.bits() / 8;
            let ir = object_access_ir(vec![Stmt::Ret {
                value: Expr::apply(
                    Operation::FloatEqual(precision),
                    vec![
                        load(
                            Expr::bin(BinOp::Add, Expr::reg(0, 64), Expr::Const(1)),
                            width,
                        ),
                        Expr::Const(0),
                    ],
                ),
            }]);
            let code = rendered(&ir);
            let ty = super::type_of(width, false);
            assert!(
                code.contains(&format!(
                    "__builtin_memcpy(({ty}[1]){{0}}, value_address + 0x1, {width})"
                )),
                "{code}"
            );
            assert!(
                !code.contains("*(float *)") && !code.contains("*(double *)"),
                "{code}"
            );
        }
    }

    #[test]
    fn object_compare_exchange_patterns_keep_copy_accesses() {
        let address = Expr::bin(BinOp::Add, Expr::reg(0, 64), Expr::Const(1));
        let old = VARIABLE_BASE;
        let ir = object_access_ir(vec![
            assign(old, load(address.clone(), 8)),
            Stmt::Store {
                addr: address,
                width: 8,
                value: Expr::Select {
                    cond: crate::ir::Cond::Eq,
                    lhs: Box::new(Expr::reg(old, 64)),
                    rhs: Box::new(Expr::Const(5)),
                    then: Box::new(Expr::Const(7)),
                    els: Box::new(Expr::reg(old, 64)),
                },
            },
            Stmt::Ret {
                value: Expr::reg(old, 64),
            },
        ]);
        let code = rendered(&ir);
        assert_eq!(code.matches("__builtin_memcpy").count(), 2, "{code}");
        assert!(!code.contains("__sync_val_compare_and_swap"), "{code}");
    }

    fn scalar_stack_ir(stmts: Vec<Stmt>) -> FunctionIr {
        let mut ir = FunctionIr::single_block(Isa::X86_64, stmts);
        ir.params = [7, 6, 2, 1, 8, 9]
            .into_iter()
            .enumerate()
            .map(|(position, index)| Param {
                index,
                name: format!("a{position}"),
                ty: CType::U64,
            })
            .collect();
        ir.stack_params = (0..3)
            .map(|index| crate::ir::StackParam {
                offset: 8 * (index + 1),
                size: 8,
                name: format!("a{}", index + 6),
                ty: CType::U64,
                position: index as usize + 6,
            })
            .collect();
        ir
    }

    #[test]
    fn scalar_stack_parameter_parts_use_bounded_byte_copies() {
        let sp = crate::arch::stack_pointer(Isa::X86_64);
        let at = |offset| Expr::bin(BinOp::Add, Expr::reg(sp, 64), Expr::Const(offset));
        let ir = scalar_stack_ir(vec![Stmt::Ret {
            value: Expr::bin(
                BinOp::Add,
                load(at(31), 1),
                Expr::bin(BinOp::Add, load(at(24), 4), load(at(24), 8)),
            ),
        }]);
        let code = rendered(&ir);
        assert!(code.contains("(uint8_t *)&a8 + 0x7, 1)"), "{code}");
        assert!(code.contains("(uint8_t *)&a8 + 0x0, 4)"), "{code}");
        assert_eq!(code.matches("__builtin_memcpy").count(), 2, "{code}");
        assert!(!code.contains("rsp"), "{code}");
        let full = rendered(&scalar_stack_ir(vec![Stmt::Ret {
            value: load(at(24), 8),
        }]));
        assert!(full.contains("return a8;"), "{full}");
        assert!(!full.contains("__builtin_memcpy"), "{full}");
    }

    #[test]
    fn scalar_stack_parameter_parts_reject_unknown_or_incompatible_storage() {
        let sp = crate::arch::stack_pointer(Isa::X86_64);
        for (offset, width, ty) in [
            (31, 2, CType::U64),
            (24, 8, CType::U32),
            (28, 1, CType::U32),
            (31, 1, CType::Named("opaque_scalar".to_owned())),
        ] {
            let mut ir = scalar_stack_ir(vec![Stmt::Ret {
                value: load(
                    Expr::bin(BinOp::Add, Expr::reg(sp, 64), Expr::Const(offset)),
                    width,
                ),
            }]);
            ir.stack_params[2].ty = ty;
            let code = rendered(&ir);
            assert!(!code.contains("__builtin_memcpy"), "{code}");
            assert!(code.contains("rsp"), "{code}");
        }
        let mut ir = scalar_stack_ir(vec![Stmt::Ret {
            value: load(Expr::bin(BinOp::Add, Expr::reg(sp, 64), Expr::Const(25)), 1),
        }]);
        ir.stack_params[2].ty = CType::U32;
        let code = rendered(&ir);
        assert!(code.contains("(uint8_t *)&a8 + 0x1, 1)"), "{code}");
        assert!(!code.contains("rsp"), "{code}");
    }

    #[test]
    fn scalar_stack_parameter_parts_reject_ambiguous_frame_addresses() {
        let sp = crate::arch::stack_pointer(Isa::X86_64);
        let address = Expr::bin(BinOp::Add, Expr::reg(sp, 64), Expr::Const(31));
        let ir = scalar_stack_ir(vec![
            assign(VARIABLE_BASE, load(address.clone(), 1)),
            assign(sp, Expr::bin(BinOp::Sub, Expr::reg(sp, 64), Expr::Const(8))),
            Stmt::Ret {
                value: load(address, 1),
            },
        ]);
        let frames = super::block_frames(&ir, sp);
        let locals = super::stack_locals(&ir, &frames, &Default::default());
        assert!(locals.parameter_addresses.is_empty());
    }

    /// The condition printed for `return lhs <cond> rhs ? 1 : 0` in a
    /// function whose parameters are `params` (register, type) and which
    /// first assigns `copies` (variable, value).
    fn compared(
        isa: Isa,
        params: &[(u16, CType)],
        copies: &[(u16, Expr)],
        cond: crate::ir::Cond,
        lhs: Expr,
        rhs: Expr,
    ) -> String {
        let mut stmts: Vec<Stmt> = copies
            .iter()
            .map(|(index, value)| assign(*index, value.clone()))
            .collect();
        stmts.push(Stmt::Ret {
            value: Expr::Select {
                cond,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
                then: Box::new(Expr::Const(1)),
                els: Box::new(Expr::Const(0)),
            },
        });
        let mut ir = FunctionIr::single_block(isa, stmts);
        ir.params = params
            .iter()
            .enumerate()
            .map(|(position, (index, ty))| Param {
                index: *index,
                name: format!("a{position}"),
                ty: ty.clone(),
            })
            .collect();
        let text = rendered(&ir);
        let line = text
            .lines()
            .find_map(|line| line.trim().strip_prefix("return (")?.strip_suffix(");"))
            .unwrap_or_else(|| panic!("{text}"));
        line.to_owned()
    }

    fn mask(value: Expr, mask: u64) -> Expr {
        Expr::bin(BinOp::And, value, Expr::Const(mask))
    }

    #[test]
    fn a_signed_comparison_of_a_masked_byte_reads_the_byte_as_signed() {
        use crate::ir::Cond;
        let byte = VARIABLE_BASE;
        let copies = [(byte, load(Expr::reg(7, 64), 1))];
        let text = compared(
            Isa::X86_64,
            &[(7, CType::pointer_to(CType::Void))],
            &copies,
            Cond::Lt,
            mask(Expr::reg(byte, 64), 0xff),
            Expr::Const(0),
        );
        // Only ever read as a signed byte, the variable is one.
        assert_eq!(text, "v1 < 0x0");
        // An unsigned comparison of the same byte needs no mask, as the
        // variable holds only the byte.
        let text = compared(
            Isa::X86_64,
            &[(7, CType::pointer_to(CType::Void))],
            &copies,
            Cond::Cc,
            mask(Expr::reg(byte, 64), 0xff),
            Expr::Const(0xf0),
        );
        assert_eq!(text, "v1 < 0xf0");
        // Of a wider value, read whole elsewhere, it keeps the mask.
        let text = compared(
            Isa::X86_64,
            &[(7, CType::pointer_to(CType::Void))],
            &[(byte, load(Expr::reg(7, 64), 8)), (0, Expr::reg(byte, 64))],
            Cond::Cc,
            mask(Expr::reg(byte, 64), 0xff),
            Expr::Const(0xf0),
        );
        assert_eq!(text, "(v1 & 0xff) < 0xf0");
    }

    #[test]
    fn an_unsigned_comparison_of_a_signed_parameter_reads_it_unsigned() {
        use crate::ir::Cond;
        // C compares a signed parameter signed.
        let test = |cond| {
            compared(
                Isa::X86_64,
                &[(7, CType::I64)],
                &[],
                cond,
                Expr::reg(7, 64),
                Expr::Const(1),
            )
        };
        assert_eq!(test(Cond::Gt), "a0 > 0x1");
        assert_eq!(test(Cond::Hi), "(uint64_t)a0 > 0x1");
        assert_eq!(test(Cond::Cc), "(uint64_t)a0 < 0x1");
    }

    #[test]
    fn a_signed_comparison_of_unsigned_memory_reads_it_as_signed() {
        use crate::ir::Cond;
        let text = compared(
            Isa::AArch64,
            &[(0, CType::pointer_to(CType::Void))],
            &[],
            Cond::Gt,
            load(Expr::bin(BinOp::Add, Expr::reg(0, 64), Expr::Const(8)), 2),
            Expr::Const(5),
        );
        assert_eq!(text, "*(int16_t *)(a0 + 0x8) > 0x5");
    }

    #[test]
    fn both_operands_of_a_signed_32_bit_comparison_are_read_as_signed() {
        use crate::ir::Cond;
        let wide = [(0, CType::U64), (1, CType::U64)];
        let text = compared(
            Isa::AArch64,
            &wide,
            &[],
            Cond::Le,
            mask(Expr::reg(0, 64), 0xffff_ffff),
            mask(
                Expr::bin(BinOp::Sub, Expr::reg(1, 64), Expr::Const(2)),
                0xffff_ffff,
            ),
        );
        assert_eq!(text, "(int32_t)a0 <= (int32_t)(a1 - 0x2)");
        // A 32-bit signed parameter needs no cast.
        let text = compared(
            Isa::X86_64,
            &[(
                7,
                CType::Int {
                    bytes: 4,
                    signed: true,
                },
            )],
            &[],
            Cond::Lt,
            Expr::reg(7, 32),
            Expr::Const(5),
        );
        assert_eq!(text, "a0 < 0x5");
        // Nor does one whose register is masked to its width.
        let text = compared(
            Isa::AArch64,
            &[(
                0,
                CType::Int {
                    bytes: 4,
                    signed: true,
                },
            )],
            &[],
            Cond::Lt,
            mask(Expr::reg(0, 64), 0xffff_ffff),
            Expr::Const(1),
        );
        assert_eq!(text, "a0 < 0x1");
    }

    #[test]
    fn a_narrow_sum_compared_signed_wraps_at_its_width() {
        use crate::ir::Cond;
        let text = compared(
            Isa::X86_64,
            &[(7, CType::pointer_to(CType::Void))],
            &[],
            Cond::Ge,
            mask(
                Expr::bin(
                    BinOp::Add,
                    load(Expr::reg(7, 64), 1),
                    load(Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(1)), 1),
                ),
                0xff,
            ),
            Expr::Const(0),
        );
        assert_eq!(
            text,
            "(int8_t)(*(uint8_t *)(a0) + *(uint8_t *)(a0 + 0x1)) >= 0x0"
        );
    }

    #[test]
    fn an_unsigned_comparison_of_a_sign_extended_value_reads_all_64_bits() {
        use crate::ir::Cond;
        let text = compared(
            Isa::AArch64,
            &[(0, CType::U64)],
            &[],
            Cond::Cc,
            Expr::SignExtend {
                value: Box::new(Expr::reg(0, 64)),
                width: 1,
            },
            Expr::Const(0x80),
        );
        assert_eq!(text, "(uint64_t)(int8_t)(a0) < 0x80");
    }

    #[test]
    fn a_variable_read_narrower_than_declared_is_compared_by_that_part() {
        use crate::ir::Cond;
        let value = VARIABLE_BASE;
        let copies = [(value, load(Expr::reg(7, 64), 8))];
        let wide = Expr::bin(BinOp::Add, Expr::reg(value, 64), Expr::reg(value, 64));
        // Read whole elsewhere, the variable is 64 bits wide.
        let copies = [copies[0].clone(), (0, wide)];
        let text = compared(
            Isa::X86_64,
            &[(7, CType::U64)],
            &copies,
            Cond::Eq,
            Expr::reg(value, 32),
            Expr::Const(5),
        );
        assert_eq!(text, "(uint32_t)v1 == 0x5");
        let text = compared(
            Isa::X86_64,
            &[(7, CType::U64)],
            &copies,
            Cond::Lt,
            Expr::reg(value, 32),
            Expr::Const(5),
        );
        assert_eq!(text, "(int32_t)v1 < 0x5");
    }

    #[test]
    fn variables_are_declared_with_the_types_their_uses_give() {
        let (sum, pointer, count) = (VARIABLE_BASE, VARIABLE_BASE + 1, VARIABLE_BASE + 2);
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                assign(pointer, Expr::reg(7, 64)),
                assign(
                    sum,
                    Expr::Apply {
                        op: Operation::FloatAdd(Precision::Double),
                        args: vec![Expr::Const(0), load(Expr::reg(pointer, 64), 8)],
                    },
                ),
                assign(
                    count,
                    Expr::bin(BinOp::Shr, Expr::reg(6, 64), Expr::Const(1)),
                ),
                assign(
                    pointer,
                    Expr::bin(BinOp::Add, Expr::reg(pointer, 64), Expr::reg(count, 64)),
                ),
                Stmt::Ret {
                    value: Expr::reg(sum, 64),
                },
            ],
        );
        ir.ret_type = CType::Named("double".to_owned());
        let text = rendered(&ir);
        assert!(text.contains("    double v1;\n"), "{text}");
        assert!(text.contains("    double *v2;\n"), "{text}");
        assert!(text.contains("    int64_t v3;\n"), "{text}");
        // The pointer moved by bytes moves by bytes in C too.
        assert!(text.contains("v2 = (uint8_t *)v2 + v3;"), "{text}");
    }

    #[test]
    fn a_counter_kept_to_32_bits_is_a_32_bit_variable() {
        // v1 = 0; v1 = (v1 + 1) & 0xffffffff; *a0 = (int32_t)v1; return v1;
        let counter = VARIABLE_BASE;
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                assign(counter, Expr::Const(0)),
                assign(
                    counter,
                    Expr::bin(
                        BinOp::And,
                        Expr::bin(BinOp::Add, Expr::reg(counter, 64), Expr::Const(1)),
                        Expr::Const(0xffff_ffff),
                    ),
                ),
                Stmt::Store {
                    addr: Expr::reg(7, 64),
                    value: Expr::SignExtend {
                        value: Box::new(Expr::reg(counter, 64)),
                        width: 4,
                    },
                    width: 8,
                },
                Stmt::Ret {
                    value: Expr::reg(counter, 64),
                },
            ],
        );
        ir.ret_type = CType::I32;
        ir.params = vec![Param {
            index: 7,
            name: "a0".to_owned(),
            ty: CType::pointer_to(CType::I64),
        }];
        let text = rendered(&ir);
        assert!(text.contains("    int32_t v1;\n"), "{text}");
        assert!(text.contains("v1 = v1 + 0x1;"), "{text}");
        assert!(text.contains("*a0 = v1;"), "{text}");
    }

    #[test]
    fn a_32_bit_value_read_whole_is_a_32_bit_variable_without_a_sign() {
        // v1 = *(uint32_t *)a0; return v1 == a1;
        let value = VARIABLE_BASE;
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                assign(value, load(Expr::reg(7, 64), 4)),
                Stmt::Ret {
                    value: Expr::Select {
                        cond: crate::ir::Cond::Eq,
                        lhs: Box::new(Expr::reg(value, 64)),
                        rhs: Box::new(Expr::reg(6, 64)),
                        then: Box::new(Expr::Const(1)),
                        els: Box::new(Expr::Const(0)),
                    },
                },
            ],
        );
        ir.params = vec![
            Param {
                index: 7,
                name: "a0".to_owned(),
                ty: CType::pointer_to(CType::U32),
            },
            Param {
                index: 6,
                name: "a1".to_owned(),
                ty: CType::U64,
            },
        ];
        let text = rendered(&ir);
        assert!(text.contains("    uint32_t v1;\n"), "{text}");
        assert!(text.contains("v1 == a1"), "{text}");
    }

    #[test]
    fn a_narrow_local_takes_its_sign_from_how_it_is_loaded() {
        // *(int32_t *)(rsp - 0x10) = a0 + 1; return it, loaded with zeros or
        // with its sign. A copy of a0 itself would read as a0.
        let slot = || {
            Expr::bin(
                BinOp::Add,
                Expr::reg(4, 64),
                Expr::Const(0xffff_ffff_ffff_fff0),
            )
        };
        let declared = |signed: bool| {
            let mut ir = FunctionIr::single_block(
                Isa::X86_64,
                vec![
                    Stmt::Store {
                        addr: slot(),
                        value: Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(1)),
                        width: 4,
                    },
                    Stmt::Ret {
                        value: Expr::Load {
                            addr: Box::new(slot()),
                            width: 4,
                            signed,
                        },
                    },
                ],
            );
            ir.params = vec![Param {
                index: 7,
                name: "a0".to_owned(),
                ty: CType::I32,
            }];
            ir.ret_type = CType::I64;
            let text = rendered(&ir);
            text.lines()
                .find(|line| line.contains(" local_0;"))
                .unwrap_or_else(|| panic!("{text}"))
                .trim()
                .to_owned()
        };
        assert_eq!(declared(false), "uint32_t local_0; /* [sp-10] */");
        assert_eq!(declared(true), "int32_t local_0; /* [sp-10] */");
    }

    #[test]
    fn a_local_index_is_not_mistaken_for_a_pointer() {
        let slot = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const((-16i64) as u64));
        let index = load(slot.clone(), 8);
        for address in [
            Expr::bin(BinOp::Add, Expr::reg(7, 64), index.clone()),
            Expr::bin(BinOp::Add, index.clone(), Expr::reg(7, 64)),
            Expr::bin(
                BinOp::Add,
                Expr::bin(BinOp::And, Expr::reg(7, 64), Expr::Const(!7)),
                index.clone(),
            ),
            Expr::bin(BinOp::Add, load(Expr::reg(7, 64), 8), index),
        ] {
            let mut ir = FunctionIr::single_block(
                Isa::X86_64,
                vec![
                    Stmt::Store {
                        addr: slot.clone(),
                        value: Expr::bin(BinOp::Add, Expr::reg(6, 64), Expr::Const(1)),
                        width: 8,
                    },
                    Stmt::Ret {
                        value: load(address, 1),
                    },
                ],
            );
            ir.params = vec![
                Param {
                    index: 7,
                    name: "data".to_owned(),
                    ty: CType::pointer_to(CType::int(1, false)),
                },
                Param {
                    index: 6,
                    name: "index".to_owned(),
                    ty: CType::U64,
                },
            ];
            let text = rendered(&ir);
            assert!(text.contains("    int64_t local_0;"), "{text}");
            assert!(!text.contains("*local_0;"), "{text}");
        }
    }

    #[test]
    fn a_local_pointer_with_only_offsets_keeps_its_pointer_type() {
        let slot = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const((-16i64) as u64));
        let pointer = load(slot.clone(), 8);
        for address in [
            pointer.clone(),
            Expr::bin(BinOp::Add, pointer.clone(), Expr::Const(4)),
            Expr::bin(BinOp::Sub, pointer.clone(), Expr::Const(4)),
            Expr::bin(
                BinOp::Add,
                pointer,
                Expr::bin(BinOp::Shl, Expr::reg(6, 64), Expr::Const(2)),
            ),
        ] {
            let mut ir = FunctionIr::single_block(
                Isa::X86_64,
                vec![
                    Stmt::Store {
                        addr: slot.clone(),
                        value: Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(1)),
                        width: 8,
                    },
                    Stmt::Ret {
                        value: load(address, 1),
                    },
                ],
            );
            ir.params = vec![
                Param {
                    index: 7,
                    name: "data".to_owned(),
                    ty: CType::pointer_to(CType::int(1, false)),
                },
                Param {
                    index: 6,
                    name: "index".to_owned(),
                    ty: CType::U64,
                },
            ];
            let text = rendered(&ir);
            assert!(text.contains("    uint8_t *local_0;"), "{text}");
        }
    }

    #[test]
    fn an_integer_local_takes_a_pointer_as_its_address() {
        let slot = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const((-16i64) as u64));
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Store {
                    addr: slot.clone(),
                    value: Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(1)),
                    width: 8,
                },
                Stmt::Ret {
                    value: Expr::bin(BinOp::Shr, load(slot, 8), Expr::Const(1)),
                },
            ],
        );
        ir.params = vec![Param {
            index: 7,
            name: "data".to_owned(),
            ty: CType::pointer_to(CType::int(1, false)),
        }];
        let text = rendered(&ir);
        assert!(text.contains("    uint64_t local_0;"), "{text}");
        assert!(
            text.contains("local_0 = (uintptr_t)(data + 0x1);"),
            "{text}"
        );
    }

    #[test]
    fn a_pointer_local_takes_an_integer_with_a_cast() {
        let slot = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const((-16i64) as u64));
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Store {
                    addr: slot.clone(),
                    value: Expr::Const(0x1000),
                    width: 8,
                },
                Stmt::Ret {
                    value: load(load(slot, 8), 1),
                },
            ],
        );
        ir.ret_type = CType::U32;
        let text = rendered(&ir);
        assert!(text.contains("    uint8_t *local_0;"), "{text}");
        assert!(text.contains("local_0 = (uint8_t *)0x1000;"), "{text}");
    }

    #[test]
    fn an_integer_compare_exchange_takes_a_pointer_as_its_address() {
        let old = VARIABLE_BASE;
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                assign(old, load(Expr::reg(7, 64), 8)),
                Stmt::Store {
                    addr: Expr::reg(7, 64),
                    width: 8,
                    value: Expr::Select {
                        cond: crate::ir::Cond::Eq,
                        lhs: Box::new(Expr::reg(old, 64)),
                        rhs: Box::new(Expr::reg(6, 64)),
                        then: Box::new(Expr::Const(1)),
                        els: Box::new(Expr::reg(old, 64)),
                    },
                },
                Stmt::Ret {
                    value: Expr::reg(old, 64),
                },
            ],
        );
        ir.params = vec![
            Param {
                index: 7,
                name: "cell".to_owned(),
                ty: CType::pointer_to(CType::U64),
            },
            Param {
                index: 6,
                name: "expected".to_owned(),
                ty: CType::pointer_to(CType::Void),
            },
        ];
        let text = rendered(&ir);
        assert!(
            text.contains(
                "__sync_val_compare_and_swap((uint64_t *)cell, (uintptr_t)expected, 0x1)"
            ),
            "{text}"
        );
        ir.params[0].ty = CType::pointer_to(CType::Named("struct record".to_owned()));
        ir.members.push(crate::ir::Member {
            structure: "record".to_owned(),
            offset: 0,
            name: "pointer".to_owned(),
            ty: CType::pointer_to(CType::Void),
            width: 8,
        });
        let text = rendered(&ir);
        assert!(
            text.contains(
                "__sync_val_compare_and_swap((uint64_t *)cell, (uintptr_t)expected, 0x1)"
            ),
            "{text}"
        );
    }

    #[test]
    fn a_pointer_local_update_keeps_the_machine_byte_offset() {
        let slot = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const((-16i64) as u64));
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Store {
                    addr: slot.clone(),
                    value: Expr::reg(7, 64),
                    width: 8,
                },
                Stmt::Store {
                    addr: slot.clone(),
                    value: Expr::bin(BinOp::Add, load(slot.clone(), 8), Expr::Const(1)),
                    width: 8,
                },
                Stmt::Ret {
                    value: load(load(slot, 8), 4),
                },
            ],
        );
        ir.params = vec![Param {
            index: 7,
            name: "data".to_owned(),
            ty: CType::pointer_to(CType::U32),
        }];
        let text = rendered(&ir);
        assert!(text.contains("    uint32_t *local_0;"), "{text}");
        assert!(
            text.contains("local_0 = (uint8_t *)local_0 + 0x1;"),
            "{text}"
        );
        assert!(!text.contains("local_0 += 0x1"), "{text}");
    }

    #[test]
    fn an_integer_local_update_keeps_the_pointer_conversion() {
        let slot = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const((-16i64) as u64));
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Store {
                    addr: slot.clone(),
                    value: Expr::Const(0),
                    width: 8,
                },
                Stmt::Store {
                    addr: slot.clone(),
                    value: Expr::bin(BinOp::Add, load(slot.clone(), 8), Expr::reg(7, 64)),
                    width: 8,
                },
                Stmt::Ret {
                    value: Expr::bin(BinOp::Shr, load(slot, 8), Expr::Const(1)),
                },
            ],
        );
        ir.params = vec![Param {
            index: 7,
            name: "data".to_owned(),
            ty: CType::pointer_to(CType::int(1, false)),
        }];
        let text = rendered(&ir);
        assert!(
            text.contains("local_0 = (uintptr_t)(data + local_0);"),
            "{text}"
        );
        assert!(!text.contains("local_0 += data"), "{text}");
    }

    #[test]
    fn compare_exchange_does_not_truncate_a_wider_comparison() {
        let old = VARIABLE_BASE;
        for signed in [false, true] {
            let mut ir = FunctionIr::single_block(
                Isa::X86_64,
                vec![
                    assign(
                        old,
                        Expr::Load {
                            addr: Box::new(Expr::reg(7, 64)),
                            width: 1,
                            signed,
                        },
                    ),
                    Stmt::Store {
                        addr: Expr::reg(7, 64),
                        width: 1,
                        value: Expr::Select {
                            cond: crate::ir::Cond::Eq,
                            lhs: Box::new(Expr::reg(old, 64)),
                            rhs: Box::new(Expr::Const(0x101)),
                            then: Box::new(Expr::Const(2)),
                            els: Box::new(Expr::reg(old, 64)),
                        },
                    },
                    Stmt::Ret {
                        value: Expr::reg(old, 64),
                    },
                ],
            );
            ir.params = vec![Param {
                index: 7,
                name: "cell".to_owned(),
                ty: CType::pointer_to(CType::int(1, signed)),
            }];
            let text = rendered(&ir);
            assert!(!text.contains("__sync_val_compare_and_swap"), "{text}");
        }
    }

    #[test]
    fn a_trap_after_a_call_is_left_out_and_one_alone_is_kept() {
        let call = Stmt::Call {
            target: Some(0x1000),
            through: None,
            convention: crate::ir::Convention::SysV,
            args: Some(Vec::new()),
            floats_named: false,
            result: None,
            clobbers: None,
            via: None,
        };
        let mut ir = FunctionIr::single_block(Isa::X86_64, vec![call, Stmt::Trap]);
        ir.ret_type = CType::Void;
        let text = rendered(&ir);
        assert!(text.contains("sub_1000();"), "{text}");
        assert!(!text.contains("__builtin_trap"), "{text}");
        let ir = FunctionIr::single_block(Isa::X86_64, vec![Stmt::Trap]);
        assert!(rendered(&ir).contains("__builtin_trap();"));
    }

    #[test]
    fn a_spilled_32_bit_parameter_reads_as_itself() {
        // *(int32_t *)(rsp - 0x10) = a0; return the slot, and a 64-bit load
        // of it, which reads bytes the spill did not write.
        let slot = || {
            Expr::bin(
                BinOp::Add,
                Expr::reg(4, 64),
                Expr::Const(0xffff_ffff_ffff_fff0),
            )
        };
        let rendered_with = |width: u8| {
            let mut ir = FunctionIr::single_block(
                Isa::X86_64,
                vec![
                    Stmt::Store {
                        addr: slot(),
                        value: Expr::reg(7, 32),
                        width: 4,
                    },
                    Stmt::Ret {
                        value: Expr::Load {
                            addr: Box::new(slot()),
                            width,
                            signed: false,
                        },
                    },
                ],
            );
            ir.params = vec![Param {
                index: 7,
                name: "a0".to_owned(),
                ty: CType::I32,
            }];
            ir.ret_type = CType::U32;
            rendered(&ir)
        };
        let text = rendered_with(4);
        assert!(!text.contains("local_0"), "{text}");
        assert!(text.contains("return a0;"), "{text}");
        let text = rendered_with(8);
        assert!(text.contains("local_0 = a0;"), "{text}");
        // A byte of it reads the parameter's low byte.
        let text = rendered_with(1);
        assert!(!text.contains("local_0"), "{text}");
        assert!(text.contains("a0"), "{text}");
    }

    #[test]
    fn a_pointer_to_scalars_is_indexed_by_elements() {
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![Stmt::Ret {
                value: load(
                    Expr::bin(
                        BinOp::Add,
                        Expr::bin(
                            BinOp::Add,
                            Expr::reg(7, 64),
                            Expr::bin(BinOp::Mul, Expr::reg(6, 64), Expr::Const(8)),
                        ),
                        Expr::Const(0x10),
                    ),
                    8,
                ),
            }],
        );
        ir.params = vec![
            Param {
                index: 7,
                name: "a0".to_owned(),
                ty: CType::pointer_to(CType::I64),
            },
            Param {
                index: 6,
                name: "a1".to_owned(),
                ty: CType::I64,
            },
        ];
        let text = rendered(&ir);
        assert!(text.contains("return a0[a1 + 0x2];"), "{text}");
    }

    #[test]
    fn a_further_result_in_a_parameter_register_is_no_parameter() {
        // v1 = f(a0, a1); v2 = rbx; return results(v1, v2);
        let (first, second) = (VARIABLE_BASE, VARIABLE_BASE + 1);
        let convention = crate::ir::Convention::GoAmd64;
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Call {
                    target: Some(0x1000),
                    through: None,
                    convention,
                    args: Some(vec![Expr::reg(0, 64), Expr::reg(3, 64)]),
                    floats_named: false,
                    clobbers: None,
                    result: Some(RegRef {
                        index: first,
                        width: 64,
                    }),
                    via: None,
                },
                assign(second, Expr::reg(3, 64)),
                Stmt::Ret {
                    value: Expr::Apply {
                        op: Operation::Results,
                        args: vec![Expr::reg(first, 64), Expr::reg(second, 64)],
                    },
                },
            ],
        );
        ir.convention = convention;
        ir.params = ["a0", "a1"]
            .iter()
            .zip([0, 3])
            .map(|(name, index)| Param {
                index,
                name: (*name).to_owned(),
                ty: CType::I64,
            })
            .collect();
        let text = rendered(&ir);
        assert!(
            text.contains("v2 = rbx; /* also returned by the call */"),
            "{text}"
        );
        assert!(text.contains("return v1; /* also returns v2 */"), "{text}");
    }

    #[test]
    fn a_pointer_taken_as_an_integer_is_cast() {
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                assign(
                    VARIABLE_BASE,
                    Expr::bin(BinOp::And, Expr::reg(7, 64), Expr::Const(7)),
                ),
                Stmt::Ret {
                    value: Expr::Select {
                        cond: crate::ir::Cond::Ne,
                        lhs: Box::new(Expr::reg(VARIABLE_BASE, 64)),
                        rhs: Box::new(Expr::Const(0)),
                        then: Box::new(Expr::reg(7, 64)),
                        els: Box::new(Expr::Const(0)),
                    },
                },
            ],
        );
        ir.params = vec![Param {
            index: 7,
            name: "a0".to_owned(),
            ty: CType::pointer_to(CType::U32),
        }];
        ir.ret_type = CType::U64;
        let text = rendered(&ir);
        for line in [
            "    v1 = (uintptr_t)a0 & 0x7;\n",
            "    return (uintptr_t)(v1 != 0x0 ? a0 : 0x0);\n",
        ] {
            assert!(text.contains(line), "{line:?} in {text}");
        }
    }

    #[test]
    fn an_array_of_structures_is_indexed_by_elements() {
        // struct { int64_t field_0x0; int32_t field_0x8; } of 16 bytes.
        let element = VARIABLE_BASE;
        let field = VARIABLE_BASE + 1;
        let scaled = |offset: u64| {
            Expr::bin(
                BinOp::Add,
                Expr::bin(
                    BinOp::Add,
                    Expr::reg(7, 64),
                    Expr::bin(BinOp::Shl, Expr::reg(6, 64), Expr::Const(4)),
                ),
                Expr::Const(offset),
            )
        };
        let store = |addr: Expr, width: u8| Stmt::Store {
            addr,
            value: Expr::Const(0),
            width,
        };
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                store(scaled(8), 4),
                store(
                    Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(0x28)),
                    4,
                ),
                store(Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(8)), 4),
                assign(element, scaled(0)),
                store(Expr::reg(element, 64), 8),
                assign(
                    element,
                    Expr::bin(BinOp::Add, Expr::reg(element, 64), Expr::Const(0x20)),
                ),
                assign(field, scaled(8)),
                // Four bytes into a field is no field.
                Stmt::Ret {
                    value: load(scaled(0xc), 4),
                },
            ],
        );
        let name = "sub_0_a0".to_owned();
        ir.params = vec![
            Param {
                index: 7,
                name: "a0".to_owned(),
                ty: CType::pointer_to(CType::Named(format!("struct {name}"))),
            },
            Param {
                index: 6,
                name: "a1".to_owned(),
                ty: CType::I64,
            },
        ];
        ir.structures = vec![crate::ir::Structure {
            name,
            fields: vec![(0, CType::I64), (8, CType::I32)],
            size: Some(0x10),
            elements: vec![element],
        }];
        let text = rendered(&ir);
        for line in [
            "uint8_t gap_0xc[0x4]; };\n",
            "    struct sub_0_a0 *v1;\n",
            "    a0[a1].field_0x8 = 0x0;\n",
            "    a0[0x2].field_0x8 = 0x0;\n",
            "    a0->field_0x8 = 0x0;\n",
            "    v1 = a0 + a1;\n",
            "    v1->field_0x0 = 0x0;\n",
            "    v1 = v1 + 0x2;\n",
            "    v2 = (uintptr_t)&a0[a1].field_0x8;\n",
            "    return *(uint32_t *)((uint8_t *)a0 + ((uint64_t)a1 << 0x4) + 0xc);\n",
        ] {
            assert!(text.contains(line), "{line:?} in {text}");
        }
    }

    /// The function returning `value` from parameters `params` (register,
    /// type), printed whole.
    fn returning(params: &[(u16, CType)], ret_type: CType, value: Expr) -> String {
        let mut ir = FunctionIr::single_block(Isa::AArch64, vec![Stmt::Ret { value }]);
        ir.ret_type = ret_type;
        ir.params = params
            .iter()
            .enumerate()
            .map(|(position, (index, ty))| Param {
                index: *index,
                name: format!("a{position}"),
                ty: ty.clone(),
            })
            .collect();
        rendered(&ir)
    }

    /// The expression of the function's return statement.
    fn returned(params: &[(u16, CType)], ret_type: CType, value: Expr) -> String {
        let text = returning(params, ret_type, value);
        text.lines()
            .find_map(|line| line.trim().strip_prefix("return ")?.strip_suffix(';'))
            .unwrap_or_else(|| panic!("{text}"))
            .to_owned()
    }

    #[test]
    fn a_logical_shift_of_a_signed_value_shifts_it_without_its_sign() {
        let text = returned(
            &[(0, CType::I32)],
            CType::I32,
            Expr::bin(BinOp::Shr, Expr::reg(0, 32), Expr::Const(31)),
        );
        assert_eq!(text, "(uint32_t)a0 >> 0x1f");
        // An unsigned one needs no cast.
        let text = returned(
            &[(0, CType::U32)],
            CType::I32,
            Expr::bin(BinOp::Shr, Expr::reg(0, 32), Expr::Const(31)),
        );
        assert_eq!(text, "a0 >> 0x1f");
    }

    #[test]
    fn a_product_whose_high_bits_are_read_is_computed_at_64_bits() {
        let product = Expr::bin(BinOp::Mul, Expr::reg(0, 32), Expr::reg(1, 32));
        let text = returned(
            &[(0, CType::U32), (1, CType::U32)],
            CType::U32,
            mask(
                Expr::bin(BinOp::Shr, product.clone(), Expr::Const(1)),
                0xffff_ffff,
            ),
        );
        assert_eq!(text, "(uint64_t)a0 * a1 >> 0x1");
        // Read only in its low 32 bits, it stays as C computes it.
        let text = returned(
            &[(0, CType::U32), (1, CType::U32)],
            CType::U32,
            mask(product, 0xffff_ffff),
        );
        assert_eq!(text, "a0 * a1");
    }

    #[test]
    fn a_zero_extended_register_in_wider_arithmetic_is_read_without_its_sign() {
        let text = returned(
            &[(0, CType::I32), (1, CType::I32)],
            CType::I64,
            Expr::bin(
                BinOp::Sub,
                Expr::SignExtend {
                    value: Box::new(Expr::reg(0, 64)),
                    width: 4,
                },
                Expr::reg(1, 32),
            ),
        );
        assert_eq!(text, "(int64_t)a0 - (uint32_t)a1");
    }

    #[test]
    fn a_builtin_takes_its_argument_at_its_own_width() {
        let text = returned(
            &[(0, CType::I32)],
            CType::I32,
            Expr::Apply {
                op: Operation::PopCount(64),
                args: vec![Expr::reg(0, 32)],
            },
        );
        assert_eq!(text, "__builtin_popcountll((uint32_t)a0)");
    }

    #[test]
    fn a_mask_stays_on_a_sum_that_can_carry_out_of_it() {
        let low = |index| mask(Expr::reg(index, 64), 0xffff_ffff);
        let text = returned(
            &[(0, CType::I64), (1, CType::I64)],
            CType::I64,
            mask(Expr::bin(BinOp::Add, low(1), low(0)), 0xffff_ffff),
        );
        assert_eq!(text, "((a1 + a0) & 0xffffffff)");
        // Read in its low 32 bits only, it goes.
        let text = returned(
            &[(0, CType::I64), (1, CType::I64)],
            CType::I32,
            mask(Expr::bin(BinOp::Add, low(1), low(0)), 0xffff_ffff),
        );
        assert_eq!(text, "a1 + a0");
    }

    #[test]
    fn a_shifted_constant_has_the_width_of_the_shift() {
        let text = returned(
            &[(0, CType::U64)],
            CType::U64,
            Expr::bin(
                BinOp::Shl,
                Expr::Const(1),
                Expr::bin(BinOp::And, Expr::reg(0, 64), Expr::Const(0x3f)),
            ),
        );
        assert_eq!(text, "0x1ULL << (a0 & 0x3f)");
    }

    #[test]
    fn a_register_that_is_no_parameter_is_declared() {
        let text = returning(&[], CType::I64, Expr::reg(29, 64));
        assert!(text.contains("    uint64_t x29;\n"), "{text}");
    }

    #[test]
    fn segment_reads_have_ordered_providers_and_entry_snapshots() {
        let fs = crate::arch::x86::FS_BASE;
        let gs = crate::arch::x86::GS_BASE;
        for registers in [vec![fs], vec![gs], vec![gs, fs, fs]] {
            let value = registers
                .iter()
                .map(|index| load(Expr::reg(*index, 64), 8))
                .reduce(|lhs, rhs| Expr::bin(BinOp::Add, lhs, rhs))
                .unwrap();
            let ir = FunctionIr::single_block(Isa::X86_64, vec![Stmt::Ret { value }]);
            let symbols = Symbols::default();
            let rendered = render_with_dependencies(&ir, &[], &symbols, &[]);
            assert_eq!(render(&ir, &[], &symbols, &[]), rendered.code);
            let expected: Vec<_> = [(fs, SegmentBase::Fs, "fs"), (gs, SegmentBase::Gs, "gs")]
                .into_iter()
                .filter(|(index, _, _)| registers.contains(index))
                .map(|(_, segment, base)| SegmentBaseRead {
                    segment,
                    provider: format!("velk_x86_{base}_base"),
                })
                .collect();
            assert_eq!(rendered.segment_bases, expected);
            for binding in &rendered.segment_bases {
                let base = match binding.segment {
                    SegmentBase::Fs => "fs_base",
                    SegmentBase::Gs => "gs_base",
                };
                assert!(
                    rendered
                        .code
                        .contains(&format!("uint64_t {}(void);\n", binding.provider)),
                    "{}",
                    rendered.code
                );
                let snapshot = format!("    uint64_t {base} = {}();\n", binding.provider);
                assert_eq!(
                    rendered.code.matches(&snapshot).count(),
                    1,
                    "{}",
                    rendered.code
                );
                assert!(
                    rendered.code.contains(&format!("*(uint64_t *)({base})")),
                    "{}",
                    rendered.code
                );
            }
        }
    }

    #[test]
    fn segment_dependencies_only_supply_unbound_x86_inputs() {
        let fs = crate::arch::x86::FS_BASE;
        let gs = crate::arch::x86::GS_BASE;
        for (isa, index) in [(Isa::X86_64, 0), (Isa::AArch64, fs), (Isa::AArch64, gs)] {
            let ir = FunctionIr::single_block(
                isa,
                vec![Stmt::Ret {
                    value: Expr::reg(index, 64),
                }],
            );
            let rendered = render_with_dependencies(&ir, &[], &Symbols::default(), &[]);
            assert!(rendered.segment_bases.is_empty());
            assert!(!rendered.code.contains("velk_x86_"), "{}", rendered.code);
        }
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![Stmt::Ret {
                value: Expr::bin(BinOp::Add, Expr::reg(fs, 64), Expr::reg(gs, 64)),
            }],
        );
        ir.params = vec![Param {
            index: fs,
            name: "entry_fs".to_owned(),
            ty: CType::U64,
        }];
        let rendered = render_with_dependencies(&ir, &[], &Symbols::default(), &[]);
        assert_eq!(
            rendered.segment_bases,
            vec![SegmentBaseRead {
                segment: SegmentBase::Gs,
                provider: "velk_x86_gs_base".to_owned(),
            }]
        );
        assert!(
            rendered.code.contains("uint64_t sub_0(uint64_t entry_fs)"),
            "{}",
            rendered.code
        );
        assert!(
            rendered.code.contains("return entry_fs + gs_base;"),
            "{}",
            rendered.code
        );
        assert!(
            !rendered.code.contains("velk_x86_fs_base"),
            "{}",
            rendered.code
        );
    }

    #[test]
    fn narrow_segment_reads_truncate_the_full_width_snapshot() {
        for (width, ty) in [(8, "uint8_t"), (16, "uint16_t"), (32, "uint32_t")] {
            let ir = FunctionIr::single_block(
                Isa::X86_64,
                vec![Stmt::Ret {
                    value: Expr::reg(crate::arch::x86::FS_BASE, width),
                }],
            );
            let rendered = render_with_dependencies(&ir, &[], &Symbols::default(), &[]);
            assert_eq!(rendered.segment_bases.len(), 1);
            assert!(
                rendered
                    .code
                    .contains("uint64_t fs_base = velk_x86_fs_base();"),
                "{}",
                rendered.code
            );
            assert!(
                rendered.code.contains(&format!("return ({ty})fs_base;")),
                "{}",
                rendered.code
            );
        }
    }

    #[test]
    fn segment_dependencies_removed_from_the_body_need_no_provider() {
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::unsupported("fs_base"),
                Stmt::Ret {
                    value: Expr::reg(crate::arch::x86::FS_BASE, 64),
                },
            ],
        );
        ir.ret_type = CType::Void;
        let rendered = render_with_dependencies(&ir, &[], &Symbols::default(), &[]);
        assert!(
            rendered.code.contains("/* unsupported: fs_base */"),
            "{}",
            rendered.code
        );
        assert!(rendered.segment_bases.is_empty());
        assert!(
            !rendered.code.contains("velk_x86_fs_base"),
            "{}",
            rendered.code
        );
        assert!(
            !rendered.code.contains("uint64_t fs_base"),
            "{}",
            rendered.code
        );
    }

    #[test]
    fn retained_segment_identifiers_exclude_comments_and_literals() {
        let text =
            "/* fs_base π */ \"fs_base \\\"\" 'fs_base' // fs_base\nother_fs_base + fs_base_other";
        assert!(!super::code_mentions(text, "fs_base"));
        assert!(!super::code_mentions(
            "\"fs_base\\\" still inside\"",
            "fs_base"
        ));
        assert!(super::code_mentions(
            &format!("{text}\n(uint32_t)fs_base"),
            "fs_base"
        ));
        assert!(!super::code_mentions("/* fs_base", "fs_base"));
        assert!(!super::code_mentions("\"fs_base", "fs_base"));
        assert!(!super::code_mentions(
            "p-> /* field */ fs_base = q.\nfs_base;",
            "fs_base"
        ));
        assert!(super::code_mentions("p->fs_base = fs_base;", "fs_base"));
    }

    #[test]
    fn a_member_name_does_not_retain_an_unused_segment_snapshot() {
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Store {
                    addr: Expr::reg(0, 64),
                    value: Expr::Const(0),
                    width: 8,
                },
                Stmt::Ret {
                    value: Expr::reg(crate::arch::x86::FS_BASE, 64),
                },
            ],
        );
        ir.ret_type = CType::Void;
        ir.params = vec![Param {
            index: 0,
            name: "p".to_owned(),
            ty: CType::pointer_to(CType::Named("struct holder".to_owned())),
        }];
        ir.members.push(crate::ir::Member {
            structure: "holder".to_owned(),
            offset: 0,
            name: "fs_base".to_owned(),
            ty: CType::U64,
            width: 8,
        });
        let rendered = render_with_dependencies(&ir, &[], &Symbols::default(), &[]);
        assert!(
            rendered.code.contains("p->fs_base = 0x0;"),
            "{}",
            rendered.code
        );
        assert!(rendered.segment_bases.is_empty());
        assert!(
            !rendered.code.contains("velk_x86_fs_base"),
            "{}",
            rendered.code
        );
    }

    #[test]
    fn segment_bindings_keep_real_calls_parameters_and_data_distinct() {
        let call = |target, through| Stmt::Call {
            target: Some(target),
            through,
            convention: crate::ir::Convention::SysV,
            args: Some(Vec::new()),
            floats_named: false,
            result: None,
            clobbers: None,
            via: None,
        };
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                call(0x40, None),
                call(0x80, Some(load(Expr::Const(0x80), 8))),
                Stmt::Ret {
                    value: Expr::bin(
                        BinOp::Add,
                        Expr::bin(
                            BinOp::Add,
                            Expr::reg(crate::arch::x86::FS_BASE, 64),
                            Expr::reg(0, 64),
                        ),
                        Expr::bin(
                            BinOp::Add,
                            Expr::reg(crate::arch::x86::GS_BASE, 64),
                            load(Expr::Const(0x1000), 8),
                        ),
                    ),
                },
            ],
        );
        ir.params = vec![
            Param {
                index: 0,
                name: "fs_base".to_owned(),
                ty: CType::U64,
            },
            Param {
                index: 1,
                name: "velk_x86_fs_base_2".to_owned(),
                ty: CType::U64,
            },
        ];
        let symbols = Symbols {
            functions: HashMap::from([(0x40, "velk_x86_fs_base".to_owned())]),
            import_slots: HashMap::from([(0x80, "velk_x86_gs_base".to_owned())]),
            data: HashMap::from([(0x1000, "fs_base_2".to_owned())]),
            ..Symbols::default()
        };
        let rendered = render_with_dependencies(&ir, &[], &symbols, &[(0x1000, 8)]);
        assert_eq!(
            rendered.segment_bases,
            vec![
                SegmentBaseRead {
                    segment: SegmentBase::Fs,
                    provider: "velk_x86_fs_base_3".to_owned()
                },
                SegmentBaseRead {
                    segment: SegmentBase::Gs,
                    provider: "velk_x86_gs_base_2".to_owned()
                },
            ]
        );
        for text in [
            "    velk_x86_fs_base();\n",
            "    velk_x86_gs_base();\n",
            "    uint64_t fs_base_3 = velk_x86_fs_base_3();\n",
            "    uint64_t gs_base = velk_x86_gs_base_2();\n",
            "    uint64_t *const fs_base_2 = (uint64_t *)(uintptr_t)0x1000;\n",
            "fs_base_3 + fs_base",
            "gs_base + *fs_base_2",
        ] {
            assert!(
                rendered.code.contains(text),
                "missing {text:?}: {}",
                rendered.code
            );
        }
    }

    #[test]
    fn segment_providers_do_not_replace_the_functions_own_name() {
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![Stmt::Ret {
                value: Expr::reg(crate::arch::x86::FS_BASE, 64),
            }],
        );
        ir.name = Some("velk_x86_fs_base".to_owned());
        let rendered = render_with_dependencies(&ir, &[], &Symbols::default(), &[]);
        assert_eq!(
            rendered.segment_bases,
            vec![SegmentBaseRead {
                segment: SegmentBase::Fs,
                provider: "velk_x86_fs_base_2".to_owned(),
            }]
        );
        assert!(
            rendered.code.contains("uint64_t velk_x86_fs_base(void) {"),
            "{}",
            rendered.code
        );
        assert!(
            rendered
                .code
                .contains("uint64_t fs_base = velk_x86_fs_base_2();"),
            "{}",
            rendered.code
        );
    }

    #[test]
    fn a_function_whose_address_is_taken_is_declared_and_read_as_a_number() {
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![Stmt::Ret {
                value: Expr::Const(0x40),
            }],
        );
        ir.ret_type = CType::I64;
        let symbols = Symbols {
            functions: HashMap::from([(0x40, "square".to_owned())]),
            ..Symbols::default()
        };
        let text = render(&ir, &[], &symbols, &[]);
        assert!(text.contains("void square(void);\n"), "{text}");
        assert!(text.contains("    return (uintptr_t)square;\n"), "{text}");
    }

    #[test]
    fn symbol_kinds_keep_names_at_the_same_address() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/alt.o");
        let mut image = crate::loader::load(&path).unwrap();
        image.functions.clear();
        for (address, name) in [
            (0x40, "owner::method"),
            (0x80, "owner__method"),
            (0xc0, "owner__method_40"),
            (0x100, "owner__method_40_2"),
        ] {
            image.functions.insert(
                address,
                crate::loader::Function {
                    addr: address,
                    size: None,
                    size_estimated: false,
                    name: Some(name.to_owned()),
                    aliases: if address == 0x40 {
                        vec!["velk_x86_fs_base()".to_owned()]
                    } else {
                        Vec::new()
                    },
                    sources: Vec::new(),
                },
            );
        }
        image.imports.clear();
        image.imports.insert(0x40, "imported_object".to_owned());
        image.data_symbols.clear();
        image.data_symbols.insert(0x40, "object".to_owned());
        let symbols = callee_names(&image);
        assert_eq!(symbols.functions[&0x40], "owner__method_40_3");
        assert_eq!(symbols.functions[&0x80], "owner__method_80");
        assert_eq!(symbols.functions[&0xc0], "owner__method_40");
        assert_eq!(symbols.functions[&0x100], "owner__method_40_2");
        assert_eq!(symbols.import_slots[&0x40], "imported_object");
        assert_eq!(symbols.data[&0x40], "object");
        for name in [
            "owner::method",
            "owner__method",
            "owner__method_40_3",
            "velk_x86_fs_base()",
            "velk_x86_fs_base__",
            "velk_x86_fs_base",
            "imported_object",
            "object",
        ] {
            assert!(symbols.reserved_names.contains(name), "missing {name}");
        }
        let ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![Stmt::Ret {
                value: Expr::reg(crate::arch::x86::FS_BASE, 64),
            }],
        );
        let rendered = render_with_dependencies(&ir, &[], &symbols, &[]);
        assert_eq!(
            rendered.segment_bases,
            vec![SegmentBaseRead {
                segment: SegmentBase::Fs,
                provider: "velk_x86_fs_base_2".to_owned(),
            }]
        );
    }

    #[test]
    fn calls_distinguish_functions_from_import_slots() {
        let call = |through| Stmt::Call {
            target: Some(0x40),
            through,
            convention: crate::ir::Convention::SysV,
            args: Some(Vec::new()),
            floats_named: false,
            result: None,
            clobbers: None,
            via: None,
        };
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                call(None),
                call(Some(load(Expr::Const(0x40), 8))),
                Stmt::Ret {
                    value: Expr::Const(0),
                },
            ],
        );
        ir.ret_type = CType::Void;
        let symbols = Symbols {
            functions: HashMap::from([(0x40, "direct_function".to_owned())]),
            import_slots: HashMap::from([(0x40, "imported_function".to_owned())]),
            data: HashMap::from([(0x40, "data_object".to_owned())]),
            ..Symbols::default()
        };
        let text = render(&ir, &[], &symbols, &[]);
        assert!(text.contains("    direct_function();\n"), "{text}");
        assert!(text.contains("    imported_function();\n"), "{text}");
        assert!(!text.contains("data_object"), "{text}");
    }

    #[test]
    fn a_data_address_has_no_function_prototype() {
        let ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![Stmt::Ret {
                value: Expr::Const(0x40),
            }],
        );
        let symbols = Symbols {
            import_slots: HashMap::from([(0x40, "imported_object".to_owned())]),
            data: HashMap::from([(0x40, "data_object".to_owned())]),
            ..Symbols::default()
        };
        let text = render(&ir, &[], &symbols, &[(0x40, 8)]);
        assert!(!text.contains("void imported_object(void);"), "{text}");
        assert!(!text.contains("void data_object(void);"), "{text}");
    }

    #[test]
    fn global_views_do_not_shadow_unnamed_functions() {
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Call {
                    target: Some(0x40),
                    through: None,
                    convention: crate::ir::Convention::SysV,
                    args: Some(Vec::new()),
                    floats_named: false,
                    result: None,
                    clobbers: None,
                    via: None,
                },
                Stmt::Ret {
                    value: Expr::bin(
                        BinOp::Add,
                        load(Expr::Const(0x1000), 4),
                        load(Expr::Const(0x1004), 4),
                    ),
                },
            ],
        );
        ir.addr = 0x80;
        ir.ret_type = CType::U64;
        let symbols = Symbols {
            data: HashMap::from([(0x1000, "sub_40".to_owned()), (0x1004, "sub_80".to_owned())]),
            ..Symbols::default()
        };
        let text = render(&ir, &[], &symbols, &[(0x1000, 8)]);
        assert!(text.contains("uint64_t sub_80(void) {\n"), "{text}");
        assert!(text.contains("    sub_40();\n"), "{text}");
        assert!(text.contains("uint32_t *const sub_40_1000_u32 ="), "{text}");
        assert!(text.contains("uint32_t *const sub_80_1004_u32 ="), "{text}");
    }
}

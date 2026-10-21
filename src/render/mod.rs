mod expr;
mod int;
mod locals;
mod naming;
mod params;
pub mod structure;
mod variables;
mod widths;

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
use crate::render::naming::global_name;
use crate::render::naming::member_access;
use crate::render::naming::narrow_registers;
use crate::render::naming::struct_fields;
use crate::render::structure::{Node, structure_best};

/// The non-executable section ranges, where a constant address names a
/// global rather than a jump target.
pub fn data_ranges(image: &crate::loader::Image) -> Vec<(u64, u64)> {
    image
        .sections
        .iter()
        .filter(|section| !section.executable)
        .map(|section| (section.vaddr, section.size))
        .collect()
}

/// The names of the functions and data objects, by address, and of the
/// imports by the slots that hold them. A function goes by its name without
/// the parameter list a demangled name ends in, when no other function has
/// that name too.
pub fn callee_names(image: &crate::loader::Image) -> HashMap<u64, String> {
    let mut bases: HashMap<String, usize> = HashMap::new();
    for function in image.functions.values() {
        if let Some(name) = &function.name {
            *bases.entry(short_name(name)).or_default() += 1;
        }
    }
    image
        .imports
        .iter()
        .chain(&image.data_symbols)
        .map(|(address, name)| (*address, name.clone()))
        .chain(image.functions.iter().filter_map(|(address, function)| {
            let name = function.name.as_ref()?;
            let base = short_name(name);
            // Names that would meet take the address after them.
            Some((
                *address,
                if bases.get(&base) == Some(&1) {
                    base
                } else {
                    format!("{base}_{address:x}")
                },
            ))
        }))
        .collect()
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

pub fn render(
    ir: &FunctionIr,
    references: &[Reference],
    callees: &HashMap<u64, String>,
    data_ranges: &[(u64, u64)],
) -> String {
    let mut folded = ir.clone();
    params::fold_saved_parameters(&mut folded);
    let ir = &folded;
    let frames = block_frames(ir, stack_pointer(ir.isa));
    let variable_types =
        variables::variable_types(ir, &narrow_registers(ir), float_return(&ir.ret_type));
    let locals = stack_locals(ir, &frames, &variable_types);
    render_with(ir, references, locals, callees, data_ranges)
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
    callees: &HashMap<u64, String>,
    data_ranges: &[(u64, u64)],
) -> String {
    let mut names: HashMap<u16, &str> = ir
        .params
        .iter()
        .map(|param| (param.index, param.name.as_str()))
        .collect();
    // Go keeps the running goroutine in r14.
    if ir.convention == crate::ir::Convention::GoAmd64 {
        names.entry(14).or_insert("g");
    }
    // Any other general register the body uses is a variable of its own.
    let machine: Vec<(u16, String)> = general_registers(ir)
        .into_iter()
        .filter(|index| !names.contains_key(index))
        .map(|index| (index, crate::ir::reg_name(ir.isa, index, 64)))
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
    let fields = struct_fields(ir);
    let narrow_regs = narrow_registers(ir);
    let float_return = float_return(&ir.ret_type);
    let variable_types = variables::variable_types(ir, &narrow_regs, float_return);
    let declared_registers =
        declared_types(ir, &variable_types, machine.iter().map(|(index, _)| *index));
    let floats: HashMap<u16, crate::ir::Precision> = variable_types
        .iter()
        .filter_map(|(index, ty)| match ty.to_string().as_str() {
            "double" => Some((*index, crate::ir::Precision::Double)),
            "float" => Some((*index, crate::ir::Precision::Single)),
            _ => None,
        })
        .collect();
    let members: HashMap<(String, i64), String> = ir
        .members
        .iter()
        .map(|member| {
            (
                (member.structure.clone(), member.offset),
                member.name.clone(),
            )
        })
        .collect();
    // `struct pair *p` points at a `pair`, so `p->0x4` can take a name.
    let mut pointees: HashMap<u16, String> = ir
        .params
        .iter()
        .filter_map(|param| Some((param.index, param.ty.pointee_struct()?.to_owned())))
        .collect();
    let arrays: HashMap<String, naming::Layout> = ir
        .structures
        .iter()
        .filter_map(|structure| {
            let layout = naming::Layout {
                size: structure.size?,
                fields: structure
                    .fields
                    .iter()
                    .filter_map(|(offset, ty)| match ty {
                        CType::Int { bytes, .. } => Some((*offset, *bytes)),
                        _ => None,
                    })
                    .collect(),
            };
            Some((structure.name.clone(), layout))
        })
        .collect();
    let element_size = |ty: &CType| {
        ty.pointee_size()
            .map(u64::from)
            .or_else(|| Some(arrays.get(ty.pointee_struct()?)?.size))
    };
    // `int *p` points at ints, so `*(p + 4)` reads `p[1]`. A pointer whose
    // type the debug info names is believed; one recovered from its
    // accesses is taken for a scalar only when every access reads a whole
    // element, and otherwise reads as a structure's fields.
    let mut elements: HashMap<u16, u64> = ir
        .params
        .iter()
        .filter(|param| match &param.ty {
            CType::Pointer(target) if matches!(target.as_ref(), CType::Named(_)) => true,
            _ => {
                let size = param.ty.pointee_size().unwrap_or(0);
                size > 0
                    && fields.iter().all(|((base, offset), (width, _))| {
                        *base != param.index
                            || *offset == 0
                            || (*width == size && offset % i64::from(size) == 0)
                    })
            }
        })
        .filter_map(|param| Some((param.index, element_size(&param.ty)?)))
        .collect();
    let scaled: std::collections::HashSet<u16> = ir
        .params
        .iter()
        .map(|param| (param.index, &param.ty))
        .chain(variable_types.iter().map(|(index, ty)| (*index, ty)))
        .filter(|(_, ty)| scales(ty))
        .map(|(index, _)| index)
        .collect();
    // A pointer variable moves along its elements as a parameter does.
    for (index, ty) in &variable_types {
        if let Some(size) = element_size(ty) {
            elements.insert(*index, size);
        }
        if let Some(structure) = ty.pointee_struct() {
            pointees.insert(*index, structure.to_owned());
        }
    }
    let local_types = || {
        locals
            .decls
            .iter()
            .filter_map(|local| Some((local.name.clone(), local.ty.as_ref()?)))
    };
    let local_elements = local_types()
        .filter_map(|(name, ty)| Some((name, element_size(ty)?)))
        .collect();
    let local_pointees = local_types()
        .filter_map(|(name, ty)| Some((name, ty.pointee_struct()?.to_owned())))
        .collect();
    let local_scaled = local_types()
        .filter(|(_, ty)| scales(ty))
        .map(|(name, _)| name)
        .collect();
    let ctx = Ctx {
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
        local_widths: locals.widths,
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
        local_elements,
        local_pointees,
        local_scaled,
        wide_params,
        fields,
        callees,
        data_ranges,
        members,
        pointees,
        elements,
        arrays,
        narrow_regs,
        floats,
        scaled,
        returned: declared(&ir.ret_type, false),
        declared: declared_registers,
        value_bits: int::value_bits(ir),
        taken: Default::default(),
    };

    let mut out = String::new();
    let name = ir
        .name
        .clone()
        .unwrap_or_else(|| format!("sub_{:x}", ir.addr));
    out.push_str(&format!("/* velk pseudo-C: {name} @ 0x{:x} */\n", ir.addr));
    // The function goes by the name its callers use.
    let name = callees.get(&ir.addr).cloned().unwrap_or(name);
    for reference in references {
        out.push_str(&format!("/* ref: {} */\n", reference.describe()));
    }
    // A pointer read as one scalar is no structure, and one to a structure
    // the debug info names needs no note of its fields.
    for (access, line) in ir.accesses.iter().zip(ir.access_lines()) {
        if !ctx.elements.contains_key(&access.register)
            && !ctx.pointees.contains_key(&access.register)
        {
            out.push_str(&format!("/* struct: {line} */\n"));
        }
    }
    for structure in &ir.structures {
        out.push_str(&format!("struct {} {{\n", structure.name));
        let mut end = 0;
        for (offset, ty) in &structure.fields {
            if *offset > end {
                out.push_str(&format!(
                    "    uint8_t gap_0x{end:x}[0x{:x}];\n",
                    offset - end
                ));
            }
            out.push_str(&format!("    {ty} field_0x{offset:x};\n"));
            end = offset
                + match ty {
                    CType::Int { bytes, .. } => u64::from(*bytes),
                    _ => 0,
                };
        }
        if let Some(size) = structure.size
            && size > end
        {
            out.push_str(&format!("    uint8_t gap_0x{end:x}[0x{:x}];\n", size - end));
        }
        out.push_str("};\n");
    }
    let prototypes_at = out.len();
    out.push_str(&format!(
        "{} {{\n",
        declaration(
            &ir.ret_type,
            &format!("{}({})", sanitize(&name), signature(ir))
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
    render_nodes(&nodes, 1, &mut body, &ctx);
    // A function whose address the body takes is declared ahead of it,
    // with no type known for it.
    let own = sanitize(&name);
    let prototypes: String = ctx
        .taken
        .borrow()
        .iter()
        .filter(|taken| **taken != own)
        .map(|taken| format!("void {taken}(void);\n"))
        .collect();
    out.insert_str(prototypes_at, &prototypes);
    let mut declared = 0;
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
    out
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
    let symbol = match op {
        BinOp::Add => "+",
        BinOp::Sub => "-",
        BinOp::And => "&",
        BinOp::Or => "|",
        BinOp::Xor => "^",
        BinOp::Shl => "<<",
        BinOp::Shr => ">>",
        BinOp::Sar => ">>",
        BinOp::Mul => "*",
        _ => return None,
    };
    let reads_place = |operand: &'e Expr| matches!(unmasked(operand), Expr::Load { addr: read, .. } if read.as_ref() == addr);
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
                value: loaded @ Expr::Load { addr, width, .. },
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
            && matches!(lhs.as_ref(), Expr::Reg { index: read, .. } if *read == dest.index)
            && matches!(els.as_ref(), Expr::Reg { index: read, .. } if *read == dest.index)
        {
            indent(depth, out);
            out.push_str(&format!(
                "{} = __sync_val_compare_and_swap(&{}, {}, {});\n",
                ctx.register(dest.index, dest.width),
                render_expr(loaded, ctx),
                render_value(expected, ctx),
                render_value(replacement, ctx)
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
    let bare = match call {
        Stmt::Call { .. } if result.is_some() => {
            let mut bare = call.clone();
            if let Stmt::Call { result, .. } = &mut bare {
                *result = None;
            }
            bare
        }
        _ => call.clone(),
    };
    let call_text = render_stmt(&bare, ctx);
    let call_text = call_text.strip_suffix(';')?;
    let takes = |value: &Expr| match result {
        Some(dest) => matches!(value, Expr::Reg { index, .. } if *index == dest.index),
        None => reads_return(value),
    };
    match next {
        Stmt::Ret { value } if takes(value) && !ctx.void_return => {
            Some(format!("return {call_text};"))
        }
        Stmt::Store { value, .. } if result.is_none() && reads_return(value) => {
            let stored = render_stmt(next, ctx);
            let (target, _) = stored.split_once(" = ")?;
            Some(format!("{target} = {call_text};"))
        }
        Stmt::Assign { value, .. } if result.is_none() && reads_return(value) => {
            let assigned = render_stmt(next, ctx);
            let (target, _) = assigned.split_once(" = ")?;
            Some(format!("{target} = {call_text};"))
        }
        _ => None,
    }
}

fn render_node(node: &Node, depth: usize, out: &mut String, ctx: &Ctx<'_>) {
    match node {
        Node::Stmt(stmt) => {
            let text = render_stmt(stmt, ctx);
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
    render_value_at(
        value,
        ctx,
        ctx.returned.map_or(64, |returned| returned.bits),
        ctx.returned.is_some_and(|returned| returned.integer),
    )
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
            format!(
                "{target} = {};",
                render_value_at(
                    value,
                    ctx,
                    declared.map_or(64, |declared| declared.bits),
                    declared.is_some_and(|declared| declared.integer)
                )
            )
        }
        Stmt::Store { addr, value, width } => {
            // Memory keeps of the value the bits stored.
            let stored = u32::from(*width) * 8;
            if let Some(member) = member_access(addr, *width, ctx).or_else(|| {
                naming::array_access(addr, *width, ctx)
                    .or_else(|| naming::flat_array_access(addr, *width, ctx))
            }) {
                return match update_of_same_location(addr, value, *width) {
                    Some((op, rhs)) => {
                        format!("{} {}= {};", member, op, render_at(rhs, ctx, stored))
                    }
                    None => format!(
                        "{} = {};",
                        member,
                        render_value_at(value, ctx, stored, false)
                    ),
                };
            }
            let address = render_expr(addr, ctx);
            match ctx.slots.get(&address) {
                Some(name) => {
                    let target = slot_access(name, *width, false, ctx);
                    if let Some(precision) = ctx.local_floats.get(name) {
                        return format!(
                            "{target} = {};",
                            expr::float_operand(value, *precision, ctx, 0, false)
                        );
                    }
                    match update_of_same_location(addr, value, *width) {
                        Some((op, rhs)) => {
                            format!("{} {}= {};", target, op, render_at(rhs, ctx, stored))
                        }
                        None => format!(
                            "{} = {};",
                            target,
                            render_value_at(value, ctx, stored, false)
                        ),
                    }
                }
                None => match global_name(addr, *width, ctx) {
                    Some(name) => match update_of_same_location(addr, value, *width) {
                        Some((op, rhs)) => {
                            format!("{} {}= {};", name, op, render_at(rhs, ctx, stored))
                        }
                        None => {
                            format!("{} = {};", name, render_value_at(value, ctx, stored, false))
                        }
                    },
                    None => format!(
                        "*({} *)({}) = {};",
                        type_of(*width, false),
                        expr::local_plus_offset(addr, ctx).unwrap_or(address),
                        render_value_at(value, ctx, stored, false)
                    ),
                },
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
                        && let Some(name) = ctx.callees.get(slot) =>
                {
                    sanitize(name)
                }
                (Some(through), _) => format!("(*({}))", render_value(through, ctx)),
                (None, Some(target)) => match ctx.callees.get(target) {
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
    use super::render;
    use crate::ir::{
        BinOp, CType, Expr, FunctionIr, Operation, Param, Precision, RegRef, Stmt, VARIABLE_BASE,
    };
    use crate::loader::Isa;
    use std::collections::HashMap;

    fn rendered(ir: &FunctionIr) -> String {
        render(ir, &[], &HashMap::new(), &[])
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
            .find_map(|line| {
                line.trim()
                    .strip_prefix("return (")?
                    .strip_suffix(" ? 0x1 : 0x0);")
            })
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
        assert_eq!(text, "v1 < 0xf0 /* unsigned */");
        // Of a wider value, read whole elsewhere, it keeps the mask.
        let text = compared(
            Isa::X86_64,
            &[(7, CType::pointer_to(CType::Void))],
            &[(byte, load(Expr::reg(7, 64), 8)), (0, Expr::reg(byte, 64))],
            Cond::Cc,
            mask(Expr::reg(byte, 64), 0xff),
            Expr::Const(0xf0),
        );
        assert_eq!(text, "(v1 & 0xff) < 0xf0 /* unsigned */");
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
        assert_eq!(text, "(uint64_t)(int8_t)(a0) < 0x80 /* unsigned */");
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
        // *(int32_t *)(rsp - 0x10) = a0; return it, loaded with zeros or
        // with its sign.
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
                        value: Expr::reg(7, 64),
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
            "    uint8_t gap_0xc[0x4];\n};\n",
            "    struct sub_0_a0 *v1;\n",
            "    a0[a1].field_0x8 = 0x0;\n",
            "    a0[0x2].field_0x8 = 0x0;\n",
            "    a0->field_0x8 = 0x0;\n",
            "    v1 = a0 + a1;\n",
            "    v1->field_0x0 = 0x0;\n",
            "    v1 = v1 + 0x2;\n",
            "    v2 = &a0[a1].field_0x8;\n",
            "    return *(uint32_t *)((uint8_t *)a0 + (a1 << 0x4) + 0xc);\n",
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
    fn a_function_whose_address_is_taken_is_declared_and_read_as_a_number() {
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![Stmt::Ret {
                value: Expr::Const(0x40),
            }],
        );
        ir.ret_type = CType::I64;
        let callees = HashMap::from([(0x40, "square".to_owned())]);
        let text = render(&ir, &[], &callees, &[]);
        assert!(text.contains("void square(void);\n"), "{text}");
        assert!(text.contains("    return (uintptr_t)square;\n"), "{text}");
    }
}

mod expr;
mod locals;
mod naming;
mod params;
pub mod structure;
mod variables;

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
/// imports by the slots that hold them.
pub fn callee_names(image: &crate::loader::Image) -> HashMap<u64, String> {
    image
        .imports
        .iter()
        .chain(&image.data_symbols)
        .map(|(address, name)| (*address, name.clone()))
        .chain(image.functions.iter().filter_map(|(address, function)| {
            function.name.as_ref().map(|name| (*address, name.clone()))
        }))
        .collect()
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
    let wide_params: std::collections::HashSet<u16> = ir
        .params
        .iter()
        .filter(|param| !param.ty.is_narrow())
        .map(|param| param.index)
        .collect();
    let signed_params: std::collections::HashSet<u16> = ir
        .params
        .iter()
        .filter(|param| matches!(param.ty, crate::ir::CType::Int { signed: true, .. }))
        .map(|param| param.index)
        .collect();
    let fields = struct_fields(ir);
    let narrow_regs = narrow_registers(ir);
    let float_return = float_return(&ir.ret_type);
    let variable_types = variables::variable_types(ir, &narrow_regs, float_return);
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
    let pointees: HashMap<u16, String> = ir
        .params
        .iter()
        .filter_map(|param| Some((param.index, param.ty.pointee_struct()?.to_owned())))
        .collect();
    // `int *p` points at ints, so `*(p + 4)` reads `p[1]`. A pointer whose
    // type the debug info names is believed; one recovered from its
    // accesses is taken for a scalar only when nothing reads past it, and
    // otherwise reads as a structure's fields.
    let elements: HashMap<u16, u8> = ir
        .params
        .iter()
        .filter(|param| match &param.ty {
            CType::Pointer(target) if matches!(target.as_ref(), CType::Named(_)) => true,
            _ => fields
                .keys()
                .all(|(base, offset)| *base != param.index || *offset == 0),
        })
        .filter_map(|param| Some((param.index, param.ty.pointee_size()?)))
        .collect();
    let scaled: std::collections::HashSet<u16> = ir
        .params
        .iter()
        .map(|param| (param.index, &param.ty))
        .chain(variable_types.iter().map(|(index, ty)| (*index, ty)))
        .filter(|(_, ty)| match ty {
            CType::Pointer(target) => {
                !matches!(target.as_ref(), CType::Void) && ty.pointee_size() != Some(1)
            }
            _ => false,
        })
        .map(|(index, _)| index)
        .collect();
    // A pointer variable moves along scalars as a parameter does.
    let mut elements = elements;
    elements.extend(
        variable_types
            .iter()
            .filter_map(|(index, ty)| Some((*index, ty.pointee_size()?))),
    );
    let ctx = Ctx {
        isa: ir.isa,
        void_return: ir.ret_type == CType::Void,
        float_return,
        names,
        landing_pads: ir.landing_pads.iter().cloned().collect(),
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
        local_elements: locals
            .decls
            .iter()
            .filter_map(|local| Some((local.name.clone(), local.ty.as_ref()?.pointee_size()?)))
            .collect(),
        wide_params,
        signed_params,
        fields,
        callees,
        data_ranges,
        members,
        pointees,
        elements,
        narrow_regs,
        narrow_return: ir.ret_type.is_32_bit_int(),
        floats,
        scaled,
    };

    let mut out = String::new();
    let name = ir
        .name
        .clone()
        .unwrap_or_else(|| format!("sub_{:x}", ir.addr));
    out.push_str(&format!("/* velk pseudo-C: {name} @ 0x{:x} */\n", ir.addr));
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
        out.push_str("};\n");
    }
    out.push_str(&format!(
        "{} {}({}) {{\n",
        ir.ret_type,
        sanitize(&name),
        signature(ir)
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
    let mut declared = 0;
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
    let mut out = String::new();
    indent(depth, &mut out);
    out.push_str(&format!(
        "for ({}; {}; {}) {{\n",
        clause(init),
        condition(*cond, lhs, rhs, ctx),
        clause(step)
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
        // A further result the call before returned in another register.
        if let (
            Some(Node::Stmt(Stmt::Call { convention, .. })),
            Node::Stmt(
                copy @ Stmt::Assign {
                    value:
                        Expr::Reg {
                            index: register, ..
                        },
                    ..
                },
            ),
        ) = (
            index.checked_sub(1).and_then(|before| nodes.get(before)),
            &nodes[index],
        ) && convention.results().first() != Some(register)
            && convention.results().contains(register)
        {
            indent(depth, out);
            out.push_str(&render_stmt(copy, ctx));
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
        Node::Switch {
            index,
            arms,
            default,
        } => {
            indent(depth, out);
            out.push_str(&format!("switch ({}) {{\n", render_expr(index, ctx)));
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
            // A register whose readers only use the low 32 bits never needs
            // the zero extension, and the return register is already typed.
            if let Expr::Bin {
                op: BinOp::And,
                lhs,
                rhs,
            } = value
            {
                let truncates_param = match lhs.as_ref() {
                    Expr::Reg { index, .. } => ctx.wide_params.contains(index),
                    _ => false,
                };
                if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff))
                    && !truncates_param
                    && (ctx.narrow_regs.contains(&dest.index)
                        || (ctx.narrow_return && dest.index == 0))
                {
                    let value = match lhs.as_ref() {
                        Expr::Reg { index, .. } => ctx.register(*index, 32),
                        other => render_expr(other, ctx),
                    };
                    return format!("{target} = {value};");
                }
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
            format!("{target} = {};", render_value(value, ctx))
        }
        Stmt::Store { addr, value, width } => {
            if let Some(member) = member_access(addr, *width, ctx).or_else(|| {
                naming::array_access(addr, *width, ctx)
                    .or_else(|| naming::flat_array_access(addr, *width, ctx))
            }) {
                return match update_of_same_location(addr, value, *width) {
                    Some((op, rhs)) => format!("{} {}= {};", member, op, render_expr(rhs, ctx)),
                    None => format!("{} = {};", member, render_value(value, ctx)),
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
                            format!("{} {}= {};", target, op, render_expr(rhs, ctx))
                        }
                        None => format!("{} = {};", target, render_value(value, ctx)),
                    }
                }
                None => match global_name(addr, *width, ctx) {
                    Some(name) => match update_of_same_location(addr, value, *width) {
                        Some((op, rhs)) => {
                            format!("{} {}= {};", name, op, render_expr(rhs, ctx))
                        }
                        None => format!("{} = {};", name, render_value(value, ctx)),
                    },
                    None => format!(
                        "*({} *)({}) = {};",
                        type_of(*width, false),
                        address,
                        render_value(value, ctx)
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
            let mut text = format!("switch ({}) {{\n", render_expr(index, ctx));
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
                .map(|arg| render_value(arg, ctx))
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
                format!("return {};", render_value(value, ctx))
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
}

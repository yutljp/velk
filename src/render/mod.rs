mod expr;
mod locals;
mod naming;
pub mod structure;

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

/// The names of the functions and data objects, by address.
pub fn callee_names(image: &crate::loader::Image) -> HashMap<u64, String> {
    image
        .data_symbols
        .iter()
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
    let frames = block_frames(ir, stack_pointer(ir.isa));
    let locals = stack_locals(ir, &frames);
    render_with(ir, references, locals, callees, data_ranges)
}

fn render_with(
    ir: &FunctionIr,
    references: &[Reference],
    locals: Locals,
    callees: &HashMap<u64, String>,
    data_ranges: &[(u64, u64)],
) -> String {
    let names: HashMap<u16, &str> = ir
        .params
        .iter()
        .map(|param| (param.index, param.name.as_str()))
        .collect();
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
    let (pointer_params, fields) = struct_fields(ir);
    let narrow_regs = narrow_registers(ir);
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
    let ctx = Ctx {
        isa: ir.isa,
        void_return: ir.ret_type == CType::Void,
        float_return: ir.ret_type.is_sse_float().then(|| {
            if ir.ret_type.to_string().contains("double") {
                crate::ir::Precision::Double
            } else {
                crate::ir::Precision::Single
            }
        }),
        names,
        slots: locals.slots,
        local_widths: locals.widths,
        wide_params,
        signed_params,
        pointer_params,
        fields,
        callees,
        data_ranges,
        members,
        pointees,
        narrow_regs,
        narrow_return: ir.ret_type.is_32_bit_int(),
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
    for access in ir.access_lines() {
        out.push_str(&format!("/* struct: {access} */\n"));
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
    render_nodes(&structure_best(ir), 1, &mut body, &ctx);
    for local in &decls {
        if local.width == 0 || !body.contains(&local.name) {
            continue;
        }
        indent(1, &mut out);
        out.push_str(&format!(
            "{} {}; /* [sp{}{:x}] */\n",
            type_of(local.width, local.signed),
            local.name,
            if local.slot < 0 { "-" } else { "+" },
            local.slot.unsigned_abs()
        ));
    }
    let declared = decls
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

pub(crate) fn signature(ir: &FunctionIr) -> String {
    if ir.params.is_empty() {
        return "void".to_owned();
    }
    ir.params
        .iter()
        .map(|param| {
            if param.ty.is_pointer() {
                format!("{}{}", param.ty, param.name)
            } else {
                format!("{} {}", param.ty, param.name)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn indent(depth: usize, out: &mut String) {
    for _ in 0..depth {
        out.push_str("    ");
    }
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
            if els.is_empty() {
                indent(depth, out);
                out.push_str("}\n");
            } else {
                indent(depth, out);
                out.push_str("} else {\n");
                render_nodes(els, depth + 1, out, ctx);
                indent(depth, out);
                out.push_str("}\n");
            }
        }
        Node::Switch {
            index,
            arms,
            default,
        } => {
            indent(depth, out);
            out.push_str(&format!("switch ({}) {{\n", render_expr(index, ctx)));
            for (values, body) in arms {
                for value in values {
                    indent(depth, out);
                    out.push_str(&format!("case {value}:\n"));
                }
                render_nodes(body, depth + 1, out, ctx);
            }
            if let Some(body) = default {
                indent(depth, out);
                out.push_str("default:\n");
                render_nodes(body, depth + 1, out, ctx);
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
            // The stack pointer moving reads as arithmetic, not a local's address.
            if dest.index == crate::arch::stack_pointer(ctx.isa) {
                return format!("{target} = {};", render_expr(value, ctx));
            }
            format!("{target} = {};", render_value(value, ctx))
        }
        Stmt::Store { addr, value, width } => {
            if let Some(member) = member_access(addr, *width, ctx) {
                return match update_of_same_location(addr, value, *width) {
                    Some((op, rhs)) => format!("{} {}= {};", member, op, render_expr(rhs, ctx)),
                    None => format!("{} = {};", member, render_value(value, ctx)),
                };
            }
            let address = render_expr(addr, ctx);
            match ctx.slots.get(&address) {
                Some(name) => {
                    let target = slot_access(name, *width, false, ctx);
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
            for (value, target) in cases {
                text.push_str(&format!("    case {value}: goto L_{target:x};\n"));
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
            ..
        } => {
            let args: Vec<String> = args
                .iter()
                .flatten()
                .map(|arg| render_value(arg, ctx))
                .collect();
            let callee = match (through, target) {
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

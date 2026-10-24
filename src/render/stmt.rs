use super::body::case_labels;
use super::globals;
use super::{
    BinOp, CType, Ctx, Expr, Stmt, calls, condition, expr, int, member_access, naming, render_at,
    render_expr, render_value, slot_access, type_of,
};

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

/// A call's argument as the complete value of its physical operand.
pub(super) fn argument(value: &Expr, ctx: &Ctx<'_>) -> String {
    render_value(value, ctx)
}

/// A returned value, of which the caller sees what the return type holds.
pub(super) fn returned(value: &Expr, ctx: &Ctx<'_>) -> String {
    let printed = expr::print_declared_value(value, ctx, ctx.returned);
    conformed(value, printed, ctx.ret_pointer.as_deref(), ctx)
}

/// The value as C takes it into a pointer of type `pointer`, or into an
/// integer when that is None: C converts between the two only by a cast.
pub(super) fn conformed(
    value: &Expr,
    printed: int::Printed,
    pointer: Option<&str>,
    ctx: &Ctx<'_>,
) -> String {
    let printed = if pointer.is_some() && matches!(value, Expr::Const(_)) && !printed.is_pointer() {
        expr::print_address(value, ctx)
    } else {
        printed
    };
    match pointer {
        Some(ty)
            if printed.is_pointer()
                && ((matches!(value, Expr::Const(_) | Expr::Select { .. })
                    && naming::pointer_target(value, ctx).is_none())
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

pub(super) fn narrow_write(index: u16, width: u8, value: String, ctx: &Ctx<'_>) -> String {
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
    if !result.fields.is_empty() {
        if values.len() != result.fields.len() {
            return None;
        }
        let mut lines = vec!["{".to_owned()];
        for (field, value) in result.fields.iter().zip(values) {
            lines.push(format!(
                "    {}.{field} = (uint32_t)({});",
                result.name,
                stored_value(value, 32, ctx).text
            ));
        }
        lines.push(format!("    return {};", result.name));
        lines.push("}".to_owned());
        return Some(lines.join("\n"));
    }
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
            if ctx.raw_vector(dest.index) {
                let value = expr::print(value, ctx, 64).address_integer().text;
                let value = if dest.width < 64 {
                    format!(
                        "(uint64_t)({value}) & 0x{:x}",
                        crate::ir::semantics::mask(u32::from(dest.width))
                    )
                } else {
                    value
                };
                return format!("{target} = {value};");
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
            let printed = expr::print_declared_value(value, ctx, declared.copied());
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
            let printed = expr::switch_index(index, ctx);
            let mut text = format!("switch ({}) {{\n", printed.text);
            let mut start = 0;
            while start < cases.len() {
                let target = cases[start].1;
                let mut end = start + 1;
                while end < cases.len() && cases[end].1 == target {
                    end += 1;
                }
                let values: Vec<i64> = cases[start..end].iter().map(|(value, _)| *value).collect();
                for label in case_labels(&values, printed.ty.signed) {
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
        Stmt::Call { .. } => calls::render(stmt, ctx),
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

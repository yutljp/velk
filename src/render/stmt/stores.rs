//! Memory-store rendering.

use super::{
    conformed, stored_value, update_of_same_location, value_precision, without_update_mask,
};
use crate::ir::{BinOp, Expr};
use crate::render::{
    Ctx, expr, globals, member_access, naming, render_at, render_expr, slot_access, type_of,
};

pub(super) fn render(addr: &Expr, value: &Expr, width: &u8, ctx: &Ctx<'_>) -> String {
    let stored_bits = u32::from(*width) * 8;
    let member = member_access(addr, *width, ctx);
    let precision = value_precision(value, ctx);
    if naming::object_access(addr, *width, ctx)
        .is_none_or(|member| member.precision().is_some() && member.precision() != precision)
        && let Some(address) = expr::copy_address(addr, *width, ctx)
    {
        let ty = type_of(*width, false);
        let value = conformed(value, stored_value(value, stored_bits, ctx), None, ctx);
        return format!("__builtin_memcpy({address}, &({ty}){{{value}}}, {width});");
    }
    let view = precision
        .filter(|precision| u32::from(precision.bits()) == stored_bits)
        .map_or(globals::View::Unsigned(*width), globals::View::Float);
    if let Some(target) = naming::global_access_as(addr, view, ctx)
        .or_else(|| naming::array_access_as(addr, *width, view, ctx))
        .or_else(|| naming::flat_array_access_as(addr, *width, view, ctx))
    {
        if let Some(precision) = precision
            && u32::from(precision.bits()) == stored_bits
        {
            return format!(
                "{target} = {};",
                expr::float_assignment(value, precision, ctx)
            );
        }
        return match update_of_same_location(addr, value, *width, ctx) {
            Some((op, rhs)) if precision.is_none() => {
                format!("{target} {op}= {};", render_at(rhs, ctx, stored_bits))
            }
            _ => {
                let printed = stored_value(value, stored_bits, ctx);
                format!("{target} = {};", conformed(value, printed, None, ctx))
            }
        };
    }
    if let Some(member) = member {
        if let Some(precision) = precision
            && member.precision() == Some(precision)
        {
            return format!(
                "{} = {};",
                member.text,
                expr::float_assignment(value, precision, ctx)
            );
        }
        if member.precision().is_none() {
            return match update_of_same_location(addr, value, *width, ctx)
                .filter(|_| precision.is_none() && member.integer().is_some())
            {
                Some((op, rhs)) => {
                    format!(
                        "{} {op}= {};",
                        member.text,
                        render_at(rhs, ctx, stored_bits)
                    )
                }
                None => {
                    let printed = stored_value(value, stored_bits, ctx);
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
                    expr::float_assignment(value, *precision, ctx)
                );
            }
            match update_of_same_location(addr, value, *width, ctx).filter(|_| precision.is_none())
            {
                Some((op, rhs)) => {
                    format!("{} {}= {};", target, op, render_at(rhs, ctx, stored_bits))
                }
                None => {
                    let pointer = (target == *name)
                        .then(|| ctx.local_pointer_types.get(name))
                        .flatten()
                        .map(String::as_str);
                    let printed = stored_value(value, stored_bits, ctx);
                    if pointer.is_none()
                        && target == *name
                        && let Expr::Bin { op, lhs, .. } = without_update_mask(value, stored_bits)
                        && let Expr::Load {
                            addr: read,
                            width: read_width,
                            ..
                        } = without_update_mask(lhs, stored_bits)
                        && read.as_ref() == addr
                        && read_width == width
                        && let Some(symbol) = match op {
                            BinOp::Shl => Some("<<"),
                            BinOp::Shr | BinOp::Sar => Some(">>"),
                            _ => None,
                        }
                        && printed.strength == 9
                        && let Some(rhs) = printed.text.strip_prefix(&format!("{target} {symbol} "))
                    {
                        return format!("{target} {symbol}= {rhs};");
                    }
                    format!("{target} = {};", conformed(value, printed, pointer, ctx))
                }
            }
        }
        None => format!(
            "*({} *)({}) = {};",
            type_of(*width, false),
            expr::local_plus_offset(addr, ctx).unwrap_or(address),
            conformed(value, stored_value(value, stored_bits, ctx), None, ctx)
        ),
    }
}

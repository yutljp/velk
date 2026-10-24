use super::{ConstantUse, Ctx, print, print_in, render_expr, type_of};
use crate::ir::{BinOp, CType, Expr};
use crate::render::int::{ALL, Int, Printed, Range};
use crate::render::naming::{array_access, global_access, member_access};

/// A pointer whose arithmetic C scales, cast to count bytes.
pub(in crate::render) fn byte_pointer(expr: &Expr, ctx: &Ctx<'_>) -> Option<String> {
    match expr {
        Expr::Reg { index, width: 64 } if ctx.scaled.contains(index) => {
            Some(format!("(uint8_t *){}", ctx.register(*index, 64)))
        }
        Expr::Load { .. }
            if let Some((name, element)) = crate::render::naming::scalar_pointer(expr, ctx)
                && element != 1 =>
        {
            Some(format!("(uint8_t *){name}"))
        }
        Expr::Load { addr, width: 8, .. }
            if let Some(name) = ctx.slots.get(&render_expr(addr, ctx))
                && ctx.local_scaled.contains(name) =>
        {
            Some(format!("(uint8_t *){name}"))
        }
        Expr::Load { width: 8, .. }
            if let Some(target) = crate::render::naming::pointer_target(expr, ctx)
                && CType::pointer_to(target).pointee_size() != Some(1) =>
        {
            Some(format!(
                "(uint8_t *){}",
                print(expr, ctx, 64).within(12, false).text
            ))
        }
        _ => None,
    }
}

/// A sum through such a pointer, nested inside it, that is no whole number
/// of its elements, as bytes from the pointer: C would scale the part that
/// is, `a0 + a1` in `(a0 + a1 * 0x10) + 0xc`.
pub(super) fn byte_sum(value: &Expr, ctx: &Ctx<'_>) -> Option<String> {
    let Expr::Bin {
        op: BinOp::Add | BinOp::Sub,
        lhs,
        rhs,
    } = value
    else {
        return None;
    };
    let mut terms = Vec::new();
    crate::render::naming::sum_terms(value, false, &mut terms);
    let Some(at) = terms
        .iter()
        .position(|(term, negative)| !negative && byte_pointer(term, ctx).is_some())
    else {
        return None;
    };
    if terms
        .iter()
        .enumerate()
        .any(|(index, (term, _))| index != at && print(term, ctx, 64).is_pointer())
    {
        return None;
    }
    // On either side, the pointer is cast where it stands.
    if std::ptr::eq(terms[at].0, lhs.as_ref()) || std::ptr::eq(terms[at].0, rhs.as_ref()) {
        return None;
    }
    let Some(mut text) = byte_pointer(terms[at].0, ctx) else {
        return None;
    };
    for (term, negative) in terms
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != at)
        .map(|(_, term)| term)
    {
        text.push_str(&match (term, negative) {
            (Expr::Const(value), true) => format!(" - 0x{value:x}"),
            (Expr::Const(value), false) if *value >= 1 << 63 => {
                format!(" - 0x{:x}", value.wrapping_neg())
            }
            _ => format!(
                " + {}",
                print_in(term, ctx, 64, ConstantUse::Hex)
                    .within(10, true)
                    .text
            ),
        });
    }
    Some(text)
}

fn object_address(addr: &Expr, ctx: &Ctx<'_>) -> bool {
    let base = match addr {
        Expr::Reg { index, width: 64 } => *index,
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(_)) => {
            let Expr::Reg { index, width: 64 } = lhs.as_ref() else {
                return false;
            };
            *index
        }
        _ => return false,
    };
    ctx.abi
        .is_some_and(|abi| abi.pointers.iter().any(|binding| binding.register == base))
}

pub(in crate::render) fn copy_address(addr: &Expr, width: u8, ctx: &Ctx<'_>) -> Option<String> {
    let address = render_expr(addr, ctx);
    ctx.parameter_addresses
        .get(&(address.clone(), width))
        .cloned()
        .or_else(|| object_address(addr, ctx).then_some(address))
}

pub(super) fn copied_load(addr: &Expr, width: u8, ctx: &Ctx<'_>) -> Option<String> {
    let address = copy_address(addr, width, ctx)?;
    let ty = type_of(width, false);
    Some(format!(
        "*({ty} *)__builtin_memcpy(({ty}[1]){{0}}, {address}, {width})"
    ))
}

/// Memory read `width` bytes wide, by name where it has one.
pub(super) fn load(addr: &Expr, width: u8, signed: bool, ctx: &Ctx<'_>) -> Printed {
    if let Some(text) = copied_load(addr, width, ctx) {
        return global_load(text, width, signed, 12);
    }
    let member = member_access(addr, width, ctx)
        .filter(|member| member.integer().is_some() || member.ty.is_pointer());
    let mut plain_char = false;
    let (text, declared_signed) = if let Some(member) = member {
        let strength = if member.text.starts_with('*') { 12 } else { 13 };
        if member.ty.is_pointer() {
            return Printed::pointer(member.text, strength);
        }
        plain_char = member.plain_char();
        let (_, declared_signed) = member.integer().expect("an integer member");
        (member.text, declared_signed)
    } else if let Some(indexed) = array_access(addr, width, ctx)
        .or_else(|| crate::render::naming::flat_array_access(addr, width, ctx))
    {
        return global_load(indexed, width, signed, 13);
    } else {
        let address = render_expr(addr, ctx);
        match ctx.slots.get(&address) {
            Some(name) => {
                let mut text = slot_access(name, width, signed, ctx);
                if &text == name && ctx.local_floats.contains_key(name) {
                    text = format!("*({} *)&{name}", type_of(width, signed));
                }
                if width == 8 && &text == name && ctx.local_pointer_types.contains_key(name) {
                    return Printed::pointer(text, 13);
                }
                let declared = if &text == name {
                    ctx.signed_locals.contains(name)
                } else {
                    signed
                };
                (text, declared)
            }
            None => match global_access(addr, width, ctx) {
                Some(name) => return global_load(name, width, signed, 12),
                None => (
                    format!(
                        "*({} *)({})",
                        type_of(width, signed),
                        local_plus_offset(addr, ctx).unwrap_or(address)
                    ),
                    signed,
                ),
            },
        }
    };
    let bits = u32::from(width) * 8;
    // A `char` extends with a sign on some platforms and not on others:
    // only its own bits are known.
    if width == 1 && (plain_char || crate::render::naming::plain_char_access(addr, ctx)) {
        return Printed::new(text, Int::INT, bits, 13).ranging(Range::Signed(bits + 1));
    }
    let exact = match (declared_signed, signed) {
        (true, true) => 64,
        (false, false) => ALL,
        _ => bits,
    };
    Printed::new(text, Int::promoted(bits, declared_signed), exact, 13).ranging(
        if declared_signed {
            Range::Signed(bits)
        } else {
            Range::Unsigned(bits)
        },
    )
}

fn global_load(text: String, width: u8, signed: bool, strength: u8) -> Printed {
    let bits = u32::from(width) * 8;
    let value = Printed::new(text, Int::promoted(bits, false), ALL, strength)
        .ranging(Range::Unsigned(bits));
    if signed {
        value.cast(bits, true, 64)
    } else {
        value
    }
}

/// A local read or written whole by name, and through a cast when the access
/// covers only part of it.
/// `(uint8_t *)&local + offset` for a sum of the stack pointer, constants
/// and other terms whose stack part addresses a local.
pub(crate) fn local_plus_offset(value: &Expr, ctx: &Ctx<'_>) -> Option<String> {
    if let Some(part) = ctx.local_parts.get(&render_expr(value, ctx)) {
        return Some(part.clone());
    }
    let Some((slot, rest)) =
        crate::render::locals::offset_local(value, crate::arch::stack_pointer(ctx.isa))
    else {
        return None;
    };
    let Expr::Bin { lhs: base, rhs, .. } = &slot else {
        return None;
    };
    let Expr::Const(offset) = rhs.as_ref() else {
        return None;
    };
    // The buffer starts at the slot or a little below it.
    let Some((address, below)) =
        (0..crate::render::locals::BUFFER_REACH as u64).find_map(|below| {
            let start = Expr::bin(
                BinOp::Add,
                base.as_ref().clone(),
                Expr::Const(offset.wrapping_sub(below)),
            );
            let key = render_expr(&start, ctx);
            ctx.local_parts
                .get(&key)
                .cloned()
                .or_else(|| {
                    ctx.slots
                        .get(&key)
                        .map(|name| format!("(uint8_t *)&{name}"))
                })
                .map(|address| (address, below))
        })
    else {
        return None;
    };
    let Some(mut rest) = rest
        .into_iter()
        .cloned()
        .reduce(|sum, term| Expr::bin(BinOp::Add, sum, term))
    else {
        return None;
    };
    if below != 0 {
        rest = Expr::bin(BinOp::Add, rest, Expr::Const(below));
    }
    Some(format!(
        "{address} + {}",
        print_in(&rest, ctx, 64, ConstantUse::Hex)
            .within(super::binding(BinOp::Add), true)
            .text
    ))
}

pub(crate) fn slot_access(name: &str, width: u8, signed: bool, ctx: &Ctx<'_>) -> String {
    match ctx.local_widths.get(name) {
        Some(declared) if *declared != width => {
            format!("*({} *)&{name}", type_of(width, signed))
        }
        _ => name.to_owned(),
    }
}

use super::expr::{Ctx, bits_to_float, print_value_at};
use super::int::{ALL, Int, Printed};
use crate::ir::Expr;

pub(super) fn branch(target: u64, ctx: &Ctx<'_>) -> String {
    if ctx.block_addresses.contains(&target) {
        format!("goto L_{target:x};")
    } else {
        indirect(&Expr::Const(target), ctx)
    }
}

pub(super) fn indirect(target: &Expr, ctx: &Ctx<'_>) -> String {
    // The adapter executes the destination in the target's machine context,
    // without assuming a C prototype for an unresolved jump.
    let target = print_value_at(target, ctx, 64, true).text;
    let call = format!("{}({target})", ctx.jump_provider);
    if ctx.void_return {
        format!("{call}; return;")
    } else if let Some(precision) = ctx.float_return {
        let value = bits_to_float(Printed::new(call, Int::U64, ALL, 13), precision);
        format!("return {value};")
    } else if let Some(ty) = &ctx.return_pointer_type {
        format!("return ({ty})(uintptr_t){call};")
    } else {
        format!("return {call};")
    }
}

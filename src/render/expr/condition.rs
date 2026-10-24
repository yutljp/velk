use super::operation::{is_comparison, render_operation};
use super::{Ctx, load, print};
use crate::ir::{BinOp, Cond, Expr};
use crate::render::int::{ALL, Int, Printed, converted, zero_bits};

pub(crate) fn condition(cond: Cond, lhs: &Expr, rhs: &Expr, ctx: &Ctx<'_>) -> String {
    // A truth value tested against zero reads as the truth value itself.
    if let (Cond::Ne | Cond::Eq, Expr::Const(0)) = (cond, rhs)
        && let Some((text, _)) = logic(lhs, cond == Cond::Eq, ctx)
    {
        return text;
    }
    if let (Cond::Ne | Cond::Eq, Expr::Const(0), Expr::Apply { op, args }) = (cond, rhs, lhs)
        && is_comparison(*op)
    {
        let text = render_operation(*op, args, ctx);
        return if cond == Cond::Eq {
            format!("!({text})")
        } else {
            text
        };
    }
    let strength = match cond {
        Cond::Eq | Cond::Ne => 7,
        _ => 8,
    };
    let [mut a, mut b] = compared(cond, lhs, rhs, ctx);
    // C compares in the common type of the two sides: an unsigned test of
    // values one of which may be negative there reads one side unsigned,
    // which takes the other along.
    let common = a.ty.common(b.ty);
    let below_sign = |printed: &crate::render::int::Printed, expr: &Expr| match expr {
        Expr::Const(value) => *value >> (common.bits - 1) == 0,
        _ => {
            matches!(printed.range, crate::render::int::Range::Unsigned(bits) if bits < common.bits)
        }
    };
    if matches!(cond, Cond::Cs | Cond::Cc | Cond::Hi | Cond::Ls)
        && common.signed
        && !(below_sign(&a, lhs) && below_sign(&b, rhs))
    {
        if matches!(lhs, Expr::Const(_)) {
            b = b.clone().cast(common.bits, false, b.exact);
        } else {
            a = a.clone().cast(common.bits, false, a.exact);
        }
    }
    let a = a.within(strength, false).text;
    let b = b.within(strength, true).text;
    match cond {
        Cond::Eq => format!("{a} == {b}"),
        Cond::Ne => format!("{a} != {b}"),
        Cond::Lt => format!("{a} < {b}"),
        Cond::Ge => format!("{a} >= {b}"),
        Cond::Gt => format!("{a} > {b}"),
        Cond::Le => format!("{a} <= {b}"),
        Cond::Cs => format!("{a} >= {b}"),
        Cond::Cc => format!("{a} < {b}"),
        Cond::Hi => format!("{a} > {b}"),
        Cond::Ls => format!("{a} <= {b}"),
        Cond::Mi => "flags_mi /* mi */".to_owned(),
        Cond::Pl => "flags_pl /* pl */".to_owned(),
        Cond::Vs => "flags_vs /* vs */".to_owned(),
        Cond::Vc => "flags_vc /* vc */".to_owned(),
    }
}

/// The index a switch compares with its case values, which it reads as an
/// equality does.
pub(crate) fn switch_index(index: &Expr, ctx: &Ctx<'_>) -> Printed {
    let [index, _] = compared(Cond::Eq, index, &Expr::Const(0), ctx);
    index.address_integer()
}

/// How a comparison reads its operands.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reading {
    Equal,
    Signed,
    Unsigned,
}

fn reading(cond: Cond) -> Reading {
    match cond {
        Cond::Lt | Cond::Ge | Cond::Gt | Cond::Le => Reading::Signed,
        Cond::Cs | Cond::Cc | Cond::Hi | Cond::Ls => Reading::Unsigned,
        _ => Reading::Equal,
    }
}

/// The operands of a comparison, printed so that C, comparing them at the
/// type it converts both to, compares what the IR does: their low bits as
/// wide as the comparison, read with its sign. An operand C would read
/// otherwise is cast to the type of that width and sign.
fn compared(cond: Cond, lhs: &Expr, rhs: &Expr, ctx: &Ctx<'_>) -> [Printed; 2] {
    let reading = reading(cond);
    let bits = crate::ir::semantics::operand_width(lhs, rhs);
    let side = |side: &Expr| match side {
        // A signed comparison reads a constant with the top bit of the
        // operands' width set as the negative number it is.
        Expr::Const(value)
            if reading == Reading::Signed
                && *value & crate::ir::semantics::mask(bits) == *value
                && (*value >> (bits - 1)) & 1 == 1 =>
        {
            super::signed_constant(*value, bits)
        }
        _ => print(side, ctx, bits),
    };
    let exprs = [lhs, rhs];
    let mut sides = [side(lhs), side(rhs)];
    if reading == Reading::Equal
        && bits == 64
        && (sides[0].is_pointer() || sides[1].is_pointer())
        && sides
            .iter()
            .zip(exprs)
            .all(|(printed, expr)| printed.is_pointer() || matches!(expr, Expr::Const(0)))
    {
        return sides;
    }
    sides = sides.map(Printed::address_integer);
    // A cast changes the type the other operand is converted to.
    for _ in 0..2 {
        let ty = sides[0].ty.common(sides[1].ty);
        for (printed, expr) in sides.iter_mut().zip(exprs) {
            if !compares(printed, expr, ty, reading, bits, ctx) {
                *printed = reread(printed, expr, reading, bits, ctx);
            }
        }
    }
    sides
}

/// Whether C, converting `printed` to `ty`, compares the value the IR
/// compares for `expr`.
fn compares(
    printed: &Printed,
    expr: &Expr,
    ty: Int,
    reading: Reading,
    bits: u32,
    ctx: &Ctx<'_>,
) -> bool {
    if converted(printed, ty) < bits {
        return false;
    }
    // C compares no more bits than the IR, extended as the IR's are, with the
    // comparison's sign.
    if ty.bits <= bits
        && match reading {
            Reading::Equal => true,
            Reading::Signed => ty.signed,
            Reading::Unsigned => !ty.signed,
        }
    {
        return true;
    }
    // Or the value C compares is the IR's operand, extended as the
    // comparison reads it.
    let unsigned = if printed.exact == ALL {
        printed.unsigned_bits().min(zero_bits(expr, ctx))
    } else {
        printed.unsigned_bits()
    };
    let as_unsigned = unsigned <= bits && (!ty.signed || unsigned < ty.bits);
    match reading {
        Reading::Equal | Reading::Unsigned => as_unsigned,
        Reading::Signed => {
            let signed = printed.signed_bits().min(unsigned.saturating_add(1));
            unsigned < bits || (ty.signed && signed <= bits)
        }
    }
}

/// An operand C would compare as another value, cast to the type of the
/// comparison's width and sign. A mask to that width goes, as the cast
/// truncates; memory read as signed names the signed type instead; and a
/// narrow mask of no sign stays, as clear as a cast.
fn reread(printed: &Printed, expr: &Expr, reading: Reading, bits: u32, ctx: &Ctx<'_>) -> Printed {
    if !matches!(bits, 8 | 16 | 32 | 64) {
        return printed.clone();
    }
    let unmasked = match expr {
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(mask) if *mask == crate::ir::semantics::mask(bits)) => {
            Some(lhs.as_ref())
        }
        _ => None,
    };
    if reading == Reading::Signed {
        if let Expr::Load { addr, width, .. } = expr
            && u32::from(*width) * 8 == bits
        {
            let as_signed = load(addr, *width, true, ctx);
            if as_signed.text != printed.text {
                return as_signed;
            }
        }
    } else if bits < 32 && unmasked.is_some() {
        let whole = print(expr, ctx, ALL);
        if whole.exact == ALL {
            return whole;
        }
    }
    let inner = match unmasked {
        Some(lhs) => print(lhs, ctx, bits),
        None => printed.clone(),
    };
    inner.cast(bits, reading == Reading::Signed, bits)
}

/// How a logical expression joins its parts, for parenthesizing.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Joined {
    Single,
    And,
    Or,
}

/// A choice between truth values (one or zero) as `&&` and `||` of its
/// conditions, negated when `negate` is set; None for any other expression.
pub(super) fn logic(expr: &Expr, negate: bool, ctx: &Ctx<'_>) -> Option<(String, Joined)> {
    let Expr::Select {
        cond,
        lhs,
        rhs,
        then,
        els,
    } = expr
    else {
        return None;
    };
    let truth = |value: &Expr| match value {
        Expr::Const(value @ (0 | 1)) => Some((*value == 1) != negate),
        _ => None,
    };
    // The select's own condition, itself perhaps a truth value against zero.
    let test = |holds: bool| -> (String, Joined) {
        let cond = if holds { *cond } else { cond.invert() };
        if let (Cond::Ne | Cond::Eq, Expr::Const(0)) = (cond, rhs.as_ref())
            && let Some(joined) = logic(lhs, cond == Cond::Eq, ctx)
        {
            return joined;
        }
        (condition(cond, lhs, rhs, ctx), Joined::Single)
    };
    let within = |(text, joined): (String, Joined), join: Joined| {
        if joined == join || joined == Joined::Single {
            text
        } else {
            format!("({text})")
        }
    };
    let join = |first: (String, Joined), rest: &Expr, join: Joined| -> Option<(String, Joined)> {
        let rest = logic(rest, negate, ctx)?;
        let operator = if join == Joined::And { "&&" } else { "||" };
        Some((
            format!("{} {operator} {}", within(first, join), within(rest, join)),
            join,
        ))
    };
    match (truth(then), truth(els)) {
        (Some(true), Some(false)) => Some(test(true)),
        (Some(false), Some(true)) => Some(test(false)),
        (Some(_), Some(_)) => None,
        (None, Some(false)) => join(test(true), then, Joined::And),
        (Some(true), None) => join(test(true), els, Joined::Or),
        (Some(false), None) => join(test(false), els, Joined::And),
        (None, Some(true)) => join(test(false), then, Joined::Or),
        (None, None) => None,
    }
}

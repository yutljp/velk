use super::memory::copied_load;
use super::{Ctx, binary, integral, operand, precedence, print, render_expr, type_of};
use crate::ir::{BinOp, Expr, Operation, Precision, Rounding};
use crate::render::globals::View;
use crate::render::int::{ALL, Int, Printed, Range};
use crate::render::naming::{global_pointer, member_access};

pub(super) fn unmasked_float(expr: &Expr, precision: Precision) -> Option<&Expr> {
    let Expr::Bin {
        op: BinOp::And,
        lhs,
        rhs,
    } = expr
    else {
        return None;
    };
    let Expr::Apply { op, .. } = lhs.as_ref() else {
        return None;
    };
    let kept = crate::ir::semantics::mask(u32::from(precision.bits()));
    (op.result_precision() == Some(precision)
        && matches!(rhs.as_ref(), Expr::Const(mask) if mask & kept == kept))
    .then_some(lhs.as_ref())
}

/// An argument of a floating-point operation: a constant reads as the
/// number its bits hold.
pub(crate) fn float_operand(
    expr: &Expr,
    precision: Precision,
    ctx: &Ctx<'_>,
    parent: u8,
    right: bool,
) -> String {
    if let Some(plan) = ctx.variadic
        && plan.floating
        && precision == Precision::Double
        && matches!(expr, Expr::Load { addr, width: 8, .. } if matches!(addr.as_ref(), Expr::Reg { index, .. } if *index == plan.register))
    {
        return format!("va_arg({}, double)", plan.name);
    }
    if let Some(value) = unmasked_float(expr, precision) {
        return float_operand(value, precision, ctx, parent, right);
    }
    match expr {
        Expr::Const(bits) => {
            let value = match precision {
                Precision::Double => f64::from_bits(*bits),
                Precision::Single => f64::from(f32::from_bits(*bits as u32)),
            };
            if !value.is_finite() {
                return bits_float(print(expr, ctx, 64), precision);
            }
            let text = if value.is_finite() && value == value.trunc() && value.abs() < 1e15 {
                format!("{value:.1}")
            } else {
                format!("{value:e}")
            };
            if precision == Precision::Single {
                format!("{text}f")
            } else {
                text
            }
        }
        Expr::Reg { index, width }
            if ctx
                .readonly_floats
                .get(index)
                .is_some_and(|(_, known)| *known == precision)
                && *width >= precision.bits() =>
        {
            ctx.readonly_floats[index].0.clone()
        }
        // A register, or its low half, holds the float itself.
        Expr::Reg { index, width }
            if ctx.bit_values()
                && (ctx.floats.get(index) != Some(&precision)
                    || u32::from(*width) < u32::from(precision.bits())) =>
        {
            let bits = print(&Expr::reg(*index, *width), ctx, 64);
            bits_float(bits, precision)
        }
        Expr::Reg { index, .. } => ctx.register(*index, 64),
        Expr::Apply { op, args }
            if ctx.bit_values() && op.result_precision() == Some(precision) =>
        {
            Printed::opaque(render_operation(*op, args, ctx), precedence(expr))
                .within(parent, right)
                .text
        }
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if matches!(lhs.as_ref(), Expr::Reg { .. })
            && matches!(rhs.as_ref(), Expr::Const(0xffff_ffff))
            && (precision == Precision::Single || !ctx.bit_values()) =>
        {
            float_operand(lhs, precision, ctx, parent, right)
        }
        // Memory read as a float names the float type.
        Expr::Load { addr, width, .. } if u32::from(*width) * 8 == u32::from(precision.bits()) => {
            if let Some(bits) = copied_load(addr, *width, ctx) {
                return bits_float(Printed::opaque(bits, 12), precision);
            }
            let float_type = match precision {
                Precision::Single => "float",
                Precision::Double => "double",
            };
            if let Some(member) = member_access(addr, *width, ctx)
                && member.precision() == Some(precision)
            {
                return member.text;
            }
            let view = View::Float(precision);
            if let Some(indexed) = crate::render::naming::array_access_as(addr, *width, view, ctx)
                .or_else(|| crate::render::naming::flat_array_access_as(addr, *width, view, ctx))
            {
                return indexed;
            }
            let address = render_expr(addr, ctx);
            match ctx.slots.get(&address) {
                Some(name) if ctx.local_floats.get(name) == Some(&precision) => name.clone(),
                Some(name) => format!("*({float_type} *)&({name})"),
                None => match global_pointer(addr, view, ctx) {
                    Some(name) => format!("*{name}"),
                    None => format!("*({float_type} *)({address})"),
                },
            }
        }
        _ if ctx.bit_values() => bits_float(print(expr, ctx, 64), precision),
        _ => operand(expr, ctx, parent, right),
    }
}

pub(in crate::render) fn bits_float(bits: Printed, precision: Precision) -> String {
    let (float, integer) = match precision {
        Precision::Single => ("float", "uint32_t"),
        Precision::Double => ("double", "uint64_t"),
    };
    let bits = bits.within(12, false).text;
    format!("((union {{ {integer} bits; {float} value; }}){{ .bits = ({integer}){bits} }}).value")
}

/// The C function that rounds a float to an integral value this way.
fn rounding_function(rounding: Rounding) -> &'static str {
    match rounding {
        Rounding::TowardZero => "trunc",
        Rounding::NearestEven => "rint",
        Rounding::NearestAway => "round",
        Rounding::Down => "floor",
        Rounding::Up => "ceil",
    }
}

/// `op` applied to `args`, as C.
pub(super) fn render_operation(op: Operation, args: &[Expr], ctx: &Ctx<'_>) -> String {
    let infix = |precision, symbol: &str, strength| {
        format!(
            "{} {symbol} {}",
            float_operand(&args[0], precision, ctx, strength, false),
            float_operand(&args[1], precision, ctx, strength, true)
        )
    };
    let call = |name: &str, precision: Option<Precision>| {
        let parts: Vec<String> = args
            .iter()
            .map(|arg| match precision {
                Some(precision) => float_operand(arg, precision, ctx, 1, false),
                None => integral(arg, ctx, 64).text,
            })
            .collect();
        format!("{name}({})", parts.join(", "))
    };
    let suffix = |precision| {
        if precision == Precision::Single {
            "f"
        } else {
            ""
        }
    };
    let float_type = |precision| match precision {
        Precision::Single => "float",
        Precision::Double => "double",
    };
    let builtin = |name: &str, bits: u8| {
        let width = if bits == 64 { "ll" } else { "" };
        format!(
            "__builtin_{name}{width}({})",
            integral(&args[0], ctx, u32::from(bits)).text
        )
    };
    match op {
        Operation::FloatAdd(p) => infix(p, "+", 10),
        Operation::FloatSub(p) => infix(p, "-", 10),
        Operation::FloatMul(p) => infix(p, "*", 11),
        Operation::FloatDiv(p) => infix(p, "/", 11),
        Operation::FloatEqual(p) => infix(p, "==", 7),
        Operation::FloatLess(p) => infix(p, "<", 8),
        Operation::FloatLessEqual(p) => infix(p, "<=", 8),
        Operation::FloatUnordered(p) => call("isunordered", Some(p)),
        Operation::FloatSqrt(p) => call(&format!("sqrt{}", suffix(p)), Some(p)),
        Operation::FloatAbs(p) => call(&format!("fabs{}", suffix(p)), Some(p)),
        Operation::FloatNegate(p) => format!("-({})", float_operand(&args[0], p, ctx, 12, false)),
        Operation::FloatMulAdd(p) => call(&format!("fma{}", suffix(p)), Some(p)),
        Operation::IntToFloat { signed, bits, to } => {
            let operand = integral(&args[0], ctx, u32::from(bits));
            // An operand already of the integer type converts as it is.
            let typed = operand.ty
                == crate::render::int::Int {
                    bits: u32::from(bits),
                    signed,
                }
                && operand.exact >= u32::from(bits);
            if typed {
                format!("({}){}", float_type(to), operand.within(12, false).text)
            } else {
                format!(
                    "({})({}){}",
                    float_type(to),
                    type_of(bits / 8, signed),
                    operand.within(12, false).text
                )
            }
        }
        Operation::FloatToInt {
            signed,
            bits,
            from,
            rounding: Rounding::TowardZero,
            ..
        } => format!(
            "({}){}",
            type_of(bits / 8, signed),
            float_operand(&args[0], from, ctx, 12, false)
        ),
        Operation::FloatToInt {
            signed,
            bits,
            from,
            rounding,
            ..
        } => format!(
            "({}){}{}({})",
            type_of(bits / 8, signed),
            rounding_function(rounding),
            suffix(from),
            float_operand(&args[0], from, ctx, 1, false)
        ),
        Operation::FloatRound(p, rounding) => call(
            &format!("{}{}", rounding_function(rounding), suffix(p)),
            Some(p),
        ),
        Operation::FloatConvert { from, to } => format!(
            "({}){}",
            float_type(to),
            float_operand(&args[0], from, ctx, 12, false)
        ),
        Operation::Lanes(..)
        | Operation::InterleaveLow(_)
        | Operation::InterleaveHigh(_)
        | Operation::Widen { .. }
        | Operation::Narrow(_)
        | Operation::SignBits(_)
        | Operation::SumLanes(_)
        | Operation::Aes { .. }
        | Operation::Pack { .. }
        | Operation::MultiplyAddPairs
        | Operation::SumAbsoluteDifferences
        | Operation::SumLanesLong { .. }
        | Operation::Crc32 { .. }
        | Operation::Results => call(&crate::ir::operation_name(op), None),
        // Any value would do; the comment says none was meant.
        Operation::Undefined => "0 /* undefined */".to_owned(),
        Operation::CountLeadingZeros(bits) => builtin("clz", bits),
        Operation::CountTrailingZeros(bits) => builtin("ctz", bits),
        Operation::PopCount(bits) => builtin("popcount", bits),
        Operation::ReverseBits(bits) => {
            format!(
                "__builtin_bitreverse{bits}({})",
                integral(&args[0], ctx, u32::from(bits)).text
            )
        }
        // The halves joined into a dividend of twice the width.
        Operation::WideDivide {
            signed,
            remainder,
            bits,
        } => {
            let (narrow, wide) = match bits {
                64 => ("int64_t", "__int128"),
                32 => ("int32_t", "int64_t"),
                16 => ("int16_t", "int32_t"),
                _ => ("int8_t", "int16_t"),
            };
            let sign = if signed { "" } else { "u" };
            let wide = if signed || bits != 64 {
                format!("{sign}{wide}")
            } else {
                "unsigned __int128".to_owned()
            };
            format!(
                "({sign}{narrow})((({wide}){} << {bits} | {}) {} {})",
                integral(&args[0], ctx, u32::from(bits))
                    .within(12, false)
                    .text,
                integral(&args[1], ctx, u32::from(bits))
                    .within(9, true)
                    .text,
                if remainder { "%" } else { "/" },
                integral(&args[2], ctx, u32::from(bits))
                    .within(11, true)
                    .text
            )
        }
    }
}

/// `op` applied to `args`: the bit counts C has builtins for take their
/// argument at the builtin's width.
pub(super) fn operation(op: Operation, args: &[Expr], expr: &Expr, ctx: &Ctx<'_>) -> Printed {
    if op == Operation::Lanes(crate::ir::LaneOp::Add, 64) && args.len() == 2 {
        return binary(
            BinOp::Add,
            (integral(&args[0], ctx, 64), &args[0]),
            (integral(&args[1], ctx, 64), &args[1]),
            64,
            ctx,
        );
    }
    if ctx.bit_values()
        && let Some(precision) = op.result_precision()
    {
        return float_bits(render_operation(op, args, ctx), precision);
    }
    let builtin = |name: &str, bits: u8| {
        let (suffix, width) = if bits == 64 { ("ll", 64) } else { ("", 32) };
        Printed::new(
            format!(
                "__builtin_{name}{suffix}({})",
                integral(&args[0], ctx, width).text
            ),
            Int::INT,
            ALL,
            13,
        )
        .ranging(Range::Unsigned(7))
    };
    match op {
        Operation::CountLeadingZeros(bits) => builtin("clz", bits),
        Operation::CountTrailingZeros(bits) => builtin("ctz", bits),
        Operation::PopCount(bits) => builtin("popcount", bits),
        Operation::ReverseBits(bits) => Printed::new(
            format!(
                "__builtin_bitreverse{bits}({})",
                integral(&args[0], ctx, u32::from(bits)).text
            ),
            Int::promoted(u32::from(bits), false),
            ALL,
            13,
        ),
        Operation::FloatToInt { signed, bits, .. } | Operation::WideDivide { signed, bits, .. } => {
            Printed::new(
                render_operation(op, args, ctx),
                Int::promoted(u32::from(bits), signed),
                ALL,
                precedence(expr),
            )
        }
        _ if is_comparison(op) => Printed::new(
            render_operation(op, args, ctx),
            Int::INT,
            ALL,
            precedence(expr),
        ),
        _ => Printed::opaque(render_operation(op, args, ctx), precedence(expr)),
    }
}

pub(in crate::render) fn float_bits(value: String, precision: Precision) -> Printed {
    let (float, integer) = match precision {
        Precision::Single => ("float", "uint32_t"),
        Precision::Double => ("double", "uint64_t"),
    };
    Printed::new(
        format!("((union {{ {float} value; {integer} bits; }}){{ .value = {value} }}).bits"),
        Int::promoted(u32::from(precision.bits()), false),
        ALL,
        13,
    )
    .ranging(Range::Unsigned(u32::from(precision.bits())))
}

pub(super) fn is_comparison(op: Operation) -> bool {
    matches!(
        op,
        Operation::FloatEqual(_)
            | Operation::FloatLess(_)
            | Operation::FloatLessEqual(_)
            | Operation::FloatUnordered(_)
    )
}

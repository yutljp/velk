use std::collections::HashMap;

use crate::ir::{BinOp, Cond, Expr, Operation, Precision, Rounding, reg_name};
use crate::loader::Isa;
use crate::render::naming::array_access;
use crate::render::naming::global_name;
use crate::render::naming::member_access;
use crate::render::sanitize;

pub(crate) struct Ctx<'a> {
    pub(super) isa: Isa,
    /// The function returns nothing: a `return` carries no value.
    pub(super) void_return: bool,
    /// The precision of a float the function returns.
    pub(super) float_return: Option<Precision>,
    pub(super) names: HashMap<u16, &'a str>,
    /// Rendered stack address to local name, computed once per function so a
    /// load and its store share a name even after the stack pointer moves.
    pub(super) slots: HashMap<String, String>,
    /// Declared width of each local, so a mask to that width can be dropped.
    pub(super) local_widths: HashMap<String, u8>,
    /// The size of the scalars each pointer local points at.
    pub(super) local_elements: HashMap<String, u8>,
    /// Locals holding floats, with their precision.
    pub(super) local_floats: HashMap<String, Precision>,
    /// Parameters wider than 32 bits: masking one is a real truncation.
    pub(super) wide_params: std::collections::HashSet<u16>,
    /// Parameters declared as signed integers.
    pub(super) signed_params: std::collections::HashSet<u16>,
    /// The fields the accesses through each pointer parameter name.
    pub(super) fields: HashMap<(u16, i64), (u8, bool)>,
    pub(super) callees: &'a HashMap<u64, String>,
    /// Non-executable `(start, size)` ranges: a constant address inside one is a global.
    pub(super) data_ranges: &'a [(u64, u64)],
    /// Structure fields the debug info names, by struct and byte offset.
    pub(super) members: HashMap<(String, i64), String>,
    /// The struct type each pointer parameter points at, when known.
    pub(super) pointees: HashMap<u16, String>,
    /// The size of the scalar each pointer parameter points at.
    pub(super) elements: HashMap<u16, u8>,
    /// Registers whose readers only ever look at the low 32 bits.
    pub(super) narrow_regs: std::collections::HashSet<u16>,
    /// The function returns a 32-bit value, so reg 0 needs no truncation.
    pub(super) narrow_return: bool,
    /// Variables holding floats, with their precision.
    pub(super) floats: HashMap<u16, Precision>,
    /// Pointers whose arithmetic C scales by a pointee wider than a byte.
    pub(super) scaled: std::collections::HashSet<u16>,
}

impl Ctx<'_> {
    pub(super) fn register(&self, index: u16, width: u8) -> String {
        match self.names.get(&index) {
            Some(name) => (*name).to_owned(),
            None => reg_name(self.isa, index, width),
        }
    }
}

pub(crate) fn type_of(width: u8, signed: bool) -> &'static str {
    match (width, signed) {
        (1, false) => "uint8_t",
        (2, false) => "uint16_t",
        (4, false) => "uint32_t",
        (8, false) => "uint64_t",
        (1, true) => "int8_t",
        (2, true) => "int16_t",
        (4, true) => "int32_t",
        _ => "int64_t",
    }
}

pub(crate) fn operator(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "+",
        BinOp::Sub => "-",
        BinOp::Mul => "*",
        BinOp::MulHigh => "__umulh",
        BinOp::MulHighS => "__smulh",
        BinOp::And => "&",
        BinOp::Or => "|",
        BinOp::Xor => "^",
        BinOp::Shl => "<<",
        BinOp::Shr => ">>",
        BinOp::Sar => ">>",
        BinOp::DivS => "/",
        BinOp::ModS => "%",
        BinOp::DivU => "/",
        BinOp::ModU => "%",
    }
}

/// C binding strength; higher binds tighter.
fn precedence(expr: &Expr) -> u8 {
    match expr {
        Expr::Select { .. } => 1,
        Expr::Bin { op, .. } => match op {
            BinOp::Or => 4,
            BinOp::Xor => 5,
            BinOp::And => 6,
            BinOp::Shl | BinOp::Shr | BinOp::Sar => 9,
            BinOp::Add | BinOp::Sub => 10,
            BinOp::Mul
            | BinOp::DivS
            | BinOp::DivU
            | BinOp::ModS
            | BinOp::ModU
            | BinOp::MulHigh
            | BinOp::MulHighS => 11,
        },
        Expr::SignExtend { .. } => 12,
        Expr::Apply { op, .. } => match op {
            Operation::FloatAdd(_) | Operation::FloatSub(_) => 10,
            Operation::FloatMul(_) | Operation::FloatDiv(_) => 11,
            Operation::FloatLess(_) | Operation::FloatLessEqual(_) => 8,
            Operation::FloatEqual(_) => 7,
            Operation::IntToFloat { .. }
            | Operation::FloatToInt { .. }
            | Operation::FloatConvert { .. }
            | Operation::FloatNegate(_) => 12,
            _ => 13,
        },
        _ => 13,
    }
}

/// Binding strength of the printed text, which differs from the node's own
/// when it prints as a unary operator, a call, or with its own parentheses,
/// or when a 32-bit mask is elided.
fn printed_precedence(expr: &Expr, ctx: &Ctx<'_>) -> u8 {
    match expr {
        Expr::Select { .. }
        | Expr::Bin {
            op: BinOp::MulHigh | BinOp::MulHighS,
            ..
        } => return 13,
        Expr::Bin {
            op: BinOp::Sub,
            lhs,
            ..
        } if matches!(lhs.as_ref(), Expr::Const(0)) => return 12,
        Expr::Bin {
            op: BinOp::Xor,
            rhs,
            ..
        } if matches!(rhs.as_ref(), Expr::Const(u64::MAX)) => return 12,
        _ => {}
    }
    if let Expr::Bin {
        op: BinOp::And,
        lhs,
        rhs,
    } = expr
    {
        let mask = matches!(rhs.as_ref(), Expr::Const(0xffff_ffff));
        let elided = fits(lhs, 32, ctx)
            || mask_matches_local(lhs, rhs, ctx)
            || matches!(lhs.as_ref(), Expr::Reg { index, .. } if !ctx.wide_params.contains(index));
        if mask {
            return if elided {
                printed_precedence(lhs, ctx)
            } else {
                13
            };
        }
        // Another low mask over a value that fits prints as the value.
        if matches!(rhs.as_ref(), Expr::Const(mask) if mask.wrapping_add(1).is_power_of_two() && *mask != 0)
            && fits(lhs, rhs_bits(rhs), ctx)
        {
            return printed_precedence(lhs, ctx);
        }
    }
    precedence(expr)
}

/// An operand of an addition or a subtraction, where a typed pointer the
/// IR moves by bytes is counted as bytes.
fn pointer_operand(expr: &Expr, ctx: &Ctx<'_>, parent: u8, right: bool) -> String {
    match expr {
        Expr::Reg { index, .. } if ctx.scaled.contains(index) => {
            format!("(uint8_t *){}", ctx.register(*index, 64))
        }
        Expr::Load { .. }
            if let Some((name, element)) = crate::render::naming::scalar_pointer(expr, ctx)
                && element != 1 =>
        {
            format!("(uint8_t *){name}")
        }
        other => operand(other, ctx, parent, right),
    }
}

/// Renders a child of an operator with binding strength `parent`, adding
/// parentheses only when needed; `right` marks the right operand.
pub(crate) fn operand(expr: &Expr, ctx: &Ctx<'_>, parent: u8, right: bool) -> String {
    let text = render_expr(expr, ctx);
    let own = printed_precedence(expr, ctx);
    let binds = own > parent || (own == parent && !right);
    if binds || own >= 12 {
        text
    } else {
        format!("({text})")
    }
}

pub(crate) fn render_value(value: &Expr, ctx: &Ctx<'_>) -> String {
    // The address of a stack local reads as that.
    if matches!(value, Expr::Bin { .. })
        && let Some(name) = ctx.slots.get(&render_expr(value, ctx))
    {
        return format!("&{name}");
    }
    match value {
        // Only a top-level constant becomes a function name: an immediate
        // inside arithmetic can coincidentally equal a function address.
        Expr::Const(address) if *address != 0 => match ctx.callees.get(address) {
            Some(name) if in_data(*address, ctx) => format!("&{}", sanitize(name)),
            Some(name) => sanitize(name),
            None => render_expr(value, ctx),
        },
        // Each arm of a choice between addresses is a value of its own.
        Expr::Select {
            cond,
            lhs,
            rhs,
            then,
            els,
        } if matches!(then.as_ref(), Expr::Const(_)) && matches!(els.as_ref(), Expr::Const(_)) => {
            format!(
                "({} ? {} : {})",
                condition(*cond, lhs, rhs, ctx),
                render_value(then, ctx),
                render_value(els, ctx)
            )
        }
        _ => render_expr(value, ctx),
    }
}

fn in_data(address: u64, ctx: &Ctx<'_>) -> bool {
    ctx.data_ranges
        .iter()
        .any(|(start, size)| address >= *start && address < start.saturating_add(*size))
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
    match expr {
        Expr::Const(bits) => {
            let value = match precision {
                Precision::Double => f64::from_bits(*bits),
                Precision::Single => f64::from(f32::from_bits(*bits as u32)),
            };
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
        // A register, or its low half, holds the float itself.
        Expr::Reg { index, .. } => ctx.register(*index, 64),
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if matches!(lhs.as_ref(), Expr::Reg { .. })
            && matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) =>
        {
            float_operand(lhs, precision, ctx, parent, right)
        }
        // Memory read as a float names the float type.
        Expr::Load { addr, width, .. } if u32::from(*width) * 8 == u32::from(precision.bits()) => {
            let float_type = match precision {
                Precision::Single => "float",
                Precision::Double => "double",
            };
            if let Some(member) = member_access(addr, *width, ctx) {
                return member;
            }
            if let Some(indexed) = array_access(addr, *width, ctx)
                .or_else(|| crate::render::naming::flat_array_access(addr, *width, ctx))
            {
                return indexed;
            }
            let address = render_expr(addr, ctx);
            match ctx.slots.get(&address) {
                Some(name) => name.clone(),
                None => match global_name(addr, *width, ctx) {
                    Some(name) => name,
                    None => format!("*({float_type} *)({address})"),
                },
            }
        }
        _ => operand(expr, ctx, parent, right),
    }
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
fn render_operation(op: Operation, args: &[Expr], ctx: &Ctx<'_>) -> String {
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
                None => render_expr(arg, ctx),
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
        format!("__builtin_{name}{width}({})", render_expr(&args[0], ctx))
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
        Operation::FloatNegate(p) => format!("-{}", float_operand(&args[0], p, ctx, 12, false)),
        Operation::FloatMulAdd(p) => call(&format!("fma{}", suffix(p)), Some(p)),
        Operation::IntToFloat { signed, bits, to } => format!(
            "({})({}){}",
            float_type(to),
            type_of(bits / 8, signed),
            operand(&args[0], ctx, 12, false)
        ),
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
        | Operation::SignBits(_)
        | Operation::SumLanes(_)
        | Operation::Aes { .. } => call(&crate::ir::operation_name(op), None),
        Operation::CountLeadingZeros(bits) => builtin("clz", bits),
        Operation::CountTrailingZeros(bits) => builtin("ctz", bits),
        Operation::PopCount(bits) => builtin("popcount", bits),
        Operation::ReverseBits(bits) => {
            format!("__builtin_bitreverse{bits}({})", render_expr(&args[0], ctx))
        }
    }
}

pub(crate) fn render_expr(value: &Expr, ctx: &Ctx<'_>) -> String {
    match value {
        Expr::Apply { op, args } => render_operation(*op, args, ctx),
        Expr::Reg { index, width } => ctx.register(*index, *width),
        // A 64-bit constant just below zero is a small negative number.
        Expr::Const(value) if value.wrapping_neg() <= 1 << 31 && *value >= 1 << 63 => {
            format!("-0x{:x}", value.wrapping_neg())
        }
        Expr::Const(value) => format!("0x{value:x}"),
        Expr::Bin {
            op: BinOp::Sub,
            lhs,
            rhs,
        } if matches!(lhs.as_ref(), Expr::Const(0)) => {
            format!("-{}", operand(rhs, ctx, 12, false))
        }
        Expr::Bin {
            op: BinOp::Xor,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(u64::MAX)) => {
            format!("~{}", operand(lhs, ctx, 12, false))
        }
        // A mask of the low bits over a value that already fits in them
        // changes nothing.
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(mask) if mask.wrapping_add(1).is_power_of_two() && *mask != 0)
            && fits(lhs, rhs_bits(rhs), ctx) =>
        {
            render_expr(lhs, ctx)
        }
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if mask_matches_local(lhs, rhs, ctx) => render_expr(lhs, ctx),
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) => match lhs.as_ref() {
            // On a register other than a wide parameter, the mask reads as
            // the 32-bit register name.
            Expr::Reg { index, .. } if !ctx.wide_params.contains(index) => ctx.register(*index, 32),
            // Arithmetic and shifts bind tighter than `&`, but are
            // parenthesised anyway for readability.
            _ => {
                let strength = precedence(lhs);
                let left = if strength > 6 && strength < 12 {
                    format!("({})", render_expr(lhs, ctx))
                } else {
                    operand(lhs, ctx, 6, false)
                };
                format!("({left} & {})", render_expr(rhs, ctx))
            }
        },
        // Arithmetic on a pointer to scalars counts elements, as C does.
        Expr::Bin {
            op: BinOp::Add | BinOp::Sub,
            ..
        } if let Some((name, _, index)) = crate::render::naming::element_index(value, ctx) => {
            match index {
                Expr::Const(0) => name,
                Expr::Bin {
                    op: BinOp::Sub,
                    lhs,
                    rhs,
                } if matches!(lhs.as_ref(), Expr::Const(0)) => {
                    format!("{name} - {}", operand(&rhs, ctx, 10, true))
                }
                index => format!("{name} + {}", operand(&index, ctx, 10, true)),
            }
        }
        // A constant with the top bit set is a negative displacement.
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => match rhs.as_ref() {
            Expr::Const(value) if *value >= 1 << 63 => format!(
                "{} - 0x{:x}",
                pointer_operand(lhs, ctx, 10, false),
                value.wrapping_neg()
            ),
            _ => format!(
                "{} + {}",
                pointer_operand(lhs, ctx, 10, false),
                pointer_operand(rhs, ctx, 10, true)
            ),
        },
        Expr::Bin {
            op: BinOp::MulHigh,
            lhs,
            rhs,
        } => format!(
            "__umulh({}, {})",
            render_expr(lhs, ctx),
            render_expr(rhs, ctx)
        ),
        Expr::Bin {
            op: BinOp::MulHighS,
            lhs,
            rhs,
        } => format!(
            "__smulh({}, {})",
            render_expr(lhs, ctx),
            render_expr(rhs, ctx)
        ),
        // `/` and `%` read as unsigned on an unsigned operand, so a signed
        // division names its signedness unless the dividend is a signed
        // parameter.
        Expr::Bin {
            op: op @ (BinOp::DivS | BinOp::ModS),
            lhs,
            rhs,
        } if !signed_parameter(lhs, ctx) => {
            // Both operands, or C converts the signed one to unsigned.
            let bytes = crate::ir::visit::expr_width(lhs).map_or(8, |bits| bits / 8);
            let divisor = match rhs.as_ref() {
                Expr::Const(_) => operand(rhs, ctx, 11, true),
                _ if signed_parameter(rhs, ctx) => operand(rhs, ctx, 11, true),
                _ => format!("({})({})", type_of(bytes, true), render_expr(rhs, ctx)),
            };
            format!(
                "({})({}) {} {}",
                type_of(bytes, true),
                render_expr(lhs, ctx),
                operator(*op),
                divisor
            )
        }
        // C shifts a signed value arithmetically: a value that is not a
        // signed parameter already is cast to a signed type of its width.
        Expr::Bin {
            op: BinOp::Sar,
            lhs,
            rhs,
        } => {
            let signed_parameter = matches!(lhs.as_ref(), Expr::Reg { index, .. } if ctx.signed_params.contains(index));
            let shifted = if signed_parameter {
                operand(lhs, ctx, 9, false)
            } else {
                let bytes = (crate::ir::semantics::operand_width(lhs, rhs) / 8) as u8;
                format!("({}){}", type_of(bytes, true), operand(lhs, ctx, 12, false))
            };
            format!("{shifted} >> {}", operand(rhs, ctx, 9, true))
        }
        Expr::Bin { op, lhs, rhs } => {
            let strength = precedence(value);
            let side = |side: &Expr, right: bool| match side {
                // A bitwise operation reads a constant as its bits.
                Expr::Const(value) if matches!(op, BinOp::And | BinOp::Or | BinOp::Xor) => {
                    format!("0x{value:x}")
                }
                _ if matches!(op, BinOp::Sub) => pointer_operand(side, ctx, strength, right),
                _ => operand(side, ctx, strength, right),
            };
            format!("{} {} {}", side(lhs, false), operator(*op), side(rhs, true))
        }
        Expr::Load {
            addr,
            width,
            signed,
        } => {
            if let Some(member) = member_access(addr, *width, ctx) {
                return member;
            }
            if let Some(indexed) = array_access(addr, *width, ctx)
                .or_else(|| crate::render::naming::flat_array_access(addr, *width, ctx))
            {
                return indexed;
            }
            let address = render_expr(addr, ctx);
            match ctx.slots.get(&address) {
                Some(name) => slot_access(name, *width, *signed, ctx),
                None => match global_name(addr, *width, ctx) {
                    Some(name) => name,
                    None => format!("*({} *)({})", type_of(*width, *signed), address),
                },
            }
        }
        // A 32-bit value extends to 64 bits; a narrower one is promoted to
        // int anyway, which is as far as C would take it.
        Expr::SignExtend { value, width: 4 } => {
            format!("(int64_t)(int32_t)({})", render_expr(value, ctx))
        }
        Expr::SignExtend { value, width } => {
            format!("({})({})", type_of(*width, true), render_expr(value, ctx))
        }
        Expr::Select { .. } if let Some((text, _)) = logic(value, false, ctx) => {
            format!("({text})")
        }
        Expr::Select {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => format!(
            "({} ? {} : {})",
            condition(*cond, lhs, rhs, ctx),
            operand(then, ctx, 1, false),
            operand(els, ctx, 1, true)
        ),
    }
}

/// A signed parameter, read whole or as its low 32 bits.
fn signed_parameter(expr: &Expr, ctx: &Ctx<'_>) -> bool {
    let register = match expr {
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) => lhs.as_ref(),
        other => other,
    };
    matches!(register, Expr::Reg { index, .. } if ctx.signed_params.contains(index))
}

/// A local read or written whole by name, and through a cast when the access
/// covers only part of it.
pub(crate) fn slot_access(name: &str, width: u8, signed: bool, ctx: &Ctx<'_>) -> String {
    match ctx.local_widths.get(name) {
        Some(declared) if *declared != width => {
            format!("*({} *)&{name}", type_of(width, signed))
        }
        _ => name.to_owned(),
    }
}

/// The number of low bits a mask `2^n - 1` keeps.
fn rhs_bits(mask: &Expr) -> u32 {
    match mask {
        Expr::Const(mask) => mask.count_ones(),
        _ => 64,
    }
}

/// True when the value provably fits in `bits` bits.
pub(crate) fn fits(expr: &Expr, bits: u32, ctx: &Ctx<'_>) -> bool {
    match expr {
        Expr::Const(value) => bits >= 64 || (*value >> bits) == 0,
        // A named parameter that is not wide holds at most 32 bits,
        // whatever width the register read has.
        Expr::Reg { index, width } => {
            u32::from(*width) <= bits
                || (bits >= 32 && ctx.names.contains_key(index) && !ctx.wide_params.contains(index))
        }
        Expr::Load { width, .. } => u32::from(*width) * 8 <= bits,
        // A negative extended value fills the bits above, which only C's
        // 32-bit arithmetic wraps away.
        Expr::SignExtend { width, .. } => bits >= 32 && u32::from(*width) * 8 <= bits,
        Expr::Bin { op, lhs, rhs } => match op {
            BinOp::And => match rhs.as_ref() {
                Expr::Const(mask) => bits >= 64 || (*mask >> bits) == 0,
                _ => fits(lhs, bits, ctx) && fits(rhs, bits, ctx),
            },
            BinOp::Or | BinOp::Xor => fits(lhs, bits, ctx) && fits(rhs, bits, ctx),
            // Arithmetic on 32-bit operands wraps at 32 bits in C, which is
            // what the mask would do; narrower results carry out of the mask.
            BinOp::Add | BinOp::Sub | BinOp::Mul => {
                bits >= 32 && fits(lhs, bits, ctx) && fits(rhs, bits, ctx)
            }
            BinOp::Shl => {
                bits >= 32
                    && matches!(rhs.as_ref(), Expr::Const(amount) if *amount < 32)
                    && fits(lhs, bits, ctx)
            }
            BinOp::DivS | BinOp::DivU | BinOp::ModS | BinOp::ModU | BinOp::Shr | BinOp::Sar => {
                fits(lhs, bits, ctx) && fits(rhs, bits, ctx)
            }
            _ => false,
        },
        Expr::Select { then, els, .. } => fits(then, bits, ctx) && fits(els, bits, ctx),
        Expr::Apply { .. } => crate::ir::semantics::width(expr) <= bits,
    }
}

fn mask_matches_local(lhs: &Expr, rhs: &Expr, ctx: &Ctx<'_>) -> bool {
    let Expr::Const(mask) = rhs else {
        return false;
    };
    let Expr::Load { addr, .. } = lhs else {
        return false;
    };
    let Some(name) = ctx.slots.get(&render_expr(addr, ctx)) else {
        return false;
    };
    let Some(width) = ctx.local_widths.get(name) else {
        return false;
    };
    *width < 8 && *mask == (1u64 << (u32::from(*width) * 8)).wrapping_sub(1)
}

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
    // A signed comparison reads a constant with the top bit of the operands'
    // width set as the negative number it is.
    let signed = matches!(cond, Cond::Lt | Cond::Ge | Cond::Gt | Cond::Le);
    let bits = crate::ir::semantics::operand_width(lhs, rhs);
    let side = |side: &Expr, right: bool| match side {
        Expr::Const(value)
            if signed
                && (1..=64).contains(&bits)
                && *value & crate::ir::semantics::mask(bits) == *value
                && (*value >> (bits - 1)) & 1 == 1 =>
        {
            let magnitude = crate::ir::semantics::sign_extend(*value, bits).unsigned_abs();
            format!("-0x{magnitude:x}")
        }
        other => operand(other, ctx, strength, right),
    };
    let a = side(lhs, false);
    let b = side(rhs, true);
    match cond {
        Cond::Eq => format!("{a} == {b}"),
        Cond::Ne => format!("{a} != {b}"),
        Cond::Lt => format!("{a} < {b}"),
        Cond::Ge => format!("{a} >= {b}"),
        Cond::Gt => format!("{a} > {b}"),
        Cond::Le => format!("{a} <= {b}"),
        Cond::Cs => format!("{a} >= {b} /* unsigned */"),
        Cond::Cc => format!("{a} < {b} /* unsigned */"),
        Cond::Hi => format!("{a} > {b} /* unsigned */"),
        Cond::Ls => format!("{a} <= {b} /* unsigned */"),
        Cond::Mi => "flags_mi /* mi */".to_owned(),
        Cond::Pl => "flags_pl /* pl */".to_owned(),
        Cond::Vs => "flags_vs /* vs */".to_owned(),
        Cond::Vc => "flags_vc /* vc */".to_owned(),
    }
}

fn is_comparison(op: Operation) -> bool {
    matches!(
        op,
        Operation::FloatEqual(_)
            | Operation::FloatLess(_)
            | Operation::FloatLessEqual(_)
            | Operation::FloatUnordered(_)
    )
}

/// How a logical expression joins its parts, for parenthesizing.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Joined {
    Single,
    And,
    Or,
}

/// A choice between truth values (one or zero) as `&&` and `||` of its
/// conditions, negated when `negate` is set; None for any other expression.
fn logic(expr: &Expr, negate: bool, ctx: &Ctx<'_>) -> Option<(String, Joined)> {
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

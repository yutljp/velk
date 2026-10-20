use std::collections::HashMap;

use crate::ir::{BinOp, Cond, Expr, Operation, Precision, Rounding, reg_name};
use crate::loader::Isa;
use crate::render::int::{ALL, Int, Printed, Range, converted, fit, wrapped, zero_bits};
use crate::render::naming::array_access;
use crate::render::naming::global_name;
use crate::render::naming::member_access;
use crate::render::sanitize;

/// How a parameter or variable is declared.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Declared {
    pub(crate) bits: u32,
    pub(crate) signed: bool,
    /// A parameter, which arrives extended to 64 bits as its type says.
    pub(crate) param: bool,
    /// Of an integer type, which takes a function's address as a number.
    pub(crate) integer: bool,
}

pub(crate) struct Ctx<'a> {
    pub(super) isa: Isa,
    /// The function returns nothing: a `return` carries no value.
    pub(super) void_return: bool,
    /// The precision of a float the function returns.
    pub(super) float_return: Option<Precision>,
    pub(super) names: HashMap<u16, &'a str>,
    /// The landing pads, with the code ranges whose calls unwind into each.
    pub(super) landing_pads: HashMap<u64, Vec<(u64, u64)>>,
    /// The strings constants point at.
    pub(super) strings: HashMap<u64, String>,
    /// Rendered stack address to local name, computed once per function so a
    /// load and its store share a name even after the stack pointer moves.
    pub(super) slots: HashMap<String, String>,
    /// Declared width of each local, so a mask to that width can be dropped.
    pub(super) local_widths: HashMap<String, u8>,
    /// The size of the elements each pointer local points at.
    pub(super) local_elements: HashMap<String, u64>,
    /// The structure each pointer local points at.
    pub(super) local_pointees: HashMap<String, String>,
    /// Pointer locals whose arithmetic C scales by a pointee wider than a byte.
    pub(super) local_scaled: std::collections::HashSet<String>,
    /// Locals holding floats, with their precision.
    pub(super) local_floats: HashMap<String, Precision>,
    /// Locals declared as signed integers.
    pub(super) signed_locals: std::collections::HashSet<String>,
    /// Parameters wider than 32 bits: masking one is a real truncation.
    pub(super) wide_params: std::collections::HashSet<u16>,
    /// The fields the accesses through each pointer parameter name.
    pub(super) fields: HashMap<(u16, i64), (u8, bool)>,
    pub(super) callees: &'a HashMap<u64, String>,
    /// Non-executable `(start, size)` ranges: a constant address inside one is a global.
    pub(super) data_ranges: &'a [(u64, u64)],
    /// Structure fields the debug info names, by struct and byte offset.
    pub(super) members: HashMap<(String, i64), String>,
    /// The struct type each pointer parameter or variable points at, when known.
    pub(super) pointees: HashMap<u16, String>,
    /// The size of the element each pointer parameter or variable points at.
    pub(super) elements: HashMap<u16, u64>,
    /// The recovered structures arrays are made of, by name.
    pub(super) arrays: HashMap<String, crate::render::naming::Layout>,
    /// Registers whose readers only ever look at the low 32 bits.
    pub(super) narrow_regs: std::collections::HashSet<u16>,
    /// Variables holding floats, with their precision.
    pub(super) floats: HashMap<u16, Precision>,
    /// Pointers whose arithmetic C scales by a pointee wider than a byte.
    pub(super) scaled: std::collections::HashSet<u16>,
    /// The integer or pointer type the function returns.
    pub(super) returned: Option<Declared>,
    /// The integer type each named register is declared with.
    pub(super) declared: HashMap<u16, Declared>,
    /// The bits each variable's values fit in.
    pub(super) value_bits: HashMap<u16, u32>,
    /// The functions whose address the body takes, to declare ahead of it.
    pub(super) taken: std::cell::RefCell<std::collections::BTreeSet<String>>,
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

/// The C binding strength of a binary operator.
fn binding(op: BinOp) -> u8 {
    match op {
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
    }
}

/// C binding strength; higher binds tighter.
fn precedence(expr: &Expr) -> u8 {
    match expr {
        Expr::Select { .. } => 1,
        Expr::Bin { op, .. } => binding(*op),
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

/// A pointer whose arithmetic C scales, cast to count bytes.
fn byte_pointer(expr: &Expr, ctx: &Ctx<'_>) -> Option<String> {
    match expr {
        Expr::Reg { index, .. } if ctx.scaled.contains(index) => {
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
        _ => None,
    }
}

/// A sum through such a pointer, nested inside it, that is no whole number
/// of its elements, as bytes from the pointer: C would scale the part that
/// is, `a0 + a1` in `(a0 + a1 * 0x10) + 0xc`.
fn byte_sum(value: &Expr, ctx: &Ctx<'_>) -> Option<String> {
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
    let at = terms
        .iter()
        .position(|(term, negative)| !negative && byte_pointer(term, ctx).is_some())?;
    // On either side, the pointer is cast where it stands.
    if std::ptr::eq(terms[at].0, lhs.as_ref()) || std::ptr::eq(terms[at].0, rhs.as_ref()) {
        return None;
    }
    let mut text = byte_pointer(terms[at].0, ctx)?;
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
            _ => format!(" + {}", operand(term, ctx, 10, true)),
        });
    }
    Some(text)
}

/// Renders a child of an operator with binding strength `parent`, adding
/// parentheses only when needed; `right` marks the right operand.
pub(crate) fn operand(expr: &Expr, ctx: &Ctx<'_>, parent: u8, right: bool) -> String {
    print(expr, ctx, 64).within(parent, right).text
}

pub(crate) fn render_value(value: &Expr, ctx: &Ctx<'_>) -> String {
    render_value_at(value, ctx, 64, false)
}

/// A value whose reader looks at its low `bits` bits; `integer` marks a
/// reader of an integer type, which takes a function's address as a number.
pub(crate) fn render_value_at(value: &Expr, ctx: &Ctx<'_>, bits: u32, integer: bool) -> String {
    // The address of a stack local reads as that.
    if matches!(value, Expr::Bin { .. })
        && let Some(name) = ctx.slots.get(&render_expr(value, ctx))
    {
        return format!("&{name}");
    }
    // So does it with an offset added, as an index into a local buffer.
    if let Some(text) = local_plus_offset(value, ctx) {
        return text;
    }
    // And the address of a field of an element of an array of structures.
    if matches!(value, Expr::Bin { op: BinOp::Add, .. })
        && let Some(text) = crate::render::naming::field_address(value, ctx)
    {
        return text;
    }
    match value {
        // A constant pointing at a string reads as the string.
        Expr::Const(address) if let Some(text) = ctx.strings.get(address) => {
            format!(
                "\"{}\"",
                text.chars()
                    .flat_map(char::escape_default)
                    .collect::<String>()
            )
        }
        // Only a top-level constant becomes a function name: an immediate
        // inside arithmetic can coincidentally equal a function address.
        // The function is declared ahead of the one printed, and an integer
        // takes its address as a number.
        Expr::Const(address)
            if *address != 0
                && let Some(name) = ctx.callees.get(address) =>
        {
            let name = sanitize(name);
            ctx.taken.borrow_mut().insert(name.clone());
            let designator = if in_data(*address, ctx) {
                format!("&{name}")
            } else {
                name
            };
            if integer {
                format!("(uintptr_t){designator}")
            } else {
                designator
            }
        }
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
                render_value_at(then, ctx, bits, integer),
                render_value_at(els, ctx, bits, integer)
            )
        }
        _ => render_at(value, ctx, bits),
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
            print(&args[0], ctx, u32::from(bits)).within(12, false).text
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
        Operation::CountLeadingZeros(bits) => builtin("clz", bits),
        Operation::CountTrailingZeros(bits) => builtin("ctz", bits),
        Operation::PopCount(bits) => builtin("popcount", bits),
        Operation::ReverseBits(bits) => {
            format!("__builtin_bitreverse{bits}({})", render_expr(&args[0], ctx))
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
                operand(&args[0], ctx, 12, false),
                operand(&args[1], ctx, 9, true),
                if remainder { "%" } else { "/" },
                operand(&args[2], ctx, 11, true)
            )
        }
    }
}

pub(crate) fn render_expr(value: &Expr, ctx: &Ctx<'_>) -> String {
    print(value, ctx, 64).text
}

/// `value` as C for a reader that looks at its low `bits` bits.
pub(crate) fn render_at(value: &Expr, ctx: &Ctx<'_>, bits: u32) -> String {
    print(value, ctx, bits).text
}

/// `expr` as C whose value agrees with the IR's in the low `bits` bits
/// wherever C's types allow it: operations C would compute narrower are
/// widened, and values C would extend otherwise are cast.
pub(crate) fn print(expr: &Expr, ctx: &Ctx<'_>, bits: u32) -> Printed {
    fit(unfitted(expr, ctx, bits), expr, bits, ctx)
}

fn unfitted(value: &Expr, ctx: &Ctx<'_>, bits: u32) -> Printed {
    match value {
        Expr::Apply { op, args } => operation(*op, args, value, ctx),
        Expr::Reg { index, width } => register(*index, *width, ctx),
        Expr::Const(value) => constant(*value),
        Expr::Bin {
            op: BinOp::Sub,
            lhs,
            rhs,
        } if matches!(lhs.as_ref(), Expr::Const(0)) => {
            // A value equal to the IR's and short of the sign bit negates
            // without overflow.
            let small = zero_bits(rhs, ctx);
            let keeps = |negated: &Printed| {
                if negated.exact == ALL && negated.ty.signed && small < negated.ty.bits {
                    64
                } else {
                    wrapped(negated.exact, negated.ty)
                }
            };
            let negated = widened(print(rhs, ctx, bits), rhs, bits, keeps);
            let exact = keeps(&negated);
            Printed::new(
                format!("-{}", negated.within(12, false).text),
                negated.ty,
                exact,
                12,
            )
        }
        Expr::Bin {
            op: BinOp::Xor,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(u64::MAX)) => {
            // A signed value inverts its sign bits too, as the IR's 64 bits.
            let keeps = |inverted: &Printed| {
                if inverted.ty.signed {
                    inverted.exact.min(64)
                } else {
                    wrapped(inverted.exact, inverted.ty)
                }
            };
            let inverted = widened(print(lhs, ctx, bits), lhs, bits, keeps);
            let exact = keeps(&inverted);
            Printed::new(
                format!("~{}", inverted.within(12, false).text),
                inverted.ty,
                exact,
                12,
            )
        }
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if let Expr::Const(mask) = rhs.as_ref()
            && mask.wrapping_add(1).is_power_of_two()
            && *mask != 0 =>
        {
            masked(lhs, *mask, ctx, bits)
        }
        // Arithmetic on a pointer to scalars counts elements, as C does.
        Expr::Bin {
            op: BinOp::Add | BinOp::Sub,
            ..
        } if let Some((name, _, index)) = crate::render::naming::element_index(value, ctx) => {
            match index {
                Expr::Const(0) => Printed::opaque(name, 13),
                Expr::Bin {
                    op: BinOp::Sub,
                    lhs,
                    rhs,
                } if matches!(lhs.as_ref(), Expr::Const(0)) => {
                    Printed::opaque(format!("{name} - {}", operand(&rhs, ctx, 10, true)), 10)
                }
                index => {
                    Printed::opaque(format!("{name} + {}", operand(&index, ctx, 10, true)), 10)
                }
            }
        }
        Expr::Bin {
            op: BinOp::Add | BinOp::Sub,
            ..
        } if let Some(text) = byte_sum(value, ctx) => Printed::opaque(text, 10),
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => match rhs.as_ref() {
            // A constant with the top bit set is a negative displacement.
            Expr::Const(value) if *value >= 1 << 63 => {
                let magnitude = value.wrapping_neg();
                binary(
                    BinOp::Sub,
                    (pointer_side(lhs, ctx, bits), lhs),
                    (
                        Printed::new(format!("0x{magnitude:x}"), Int::literal(magnitude), ALL, 13),
                        rhs,
                    ),
                    bits,
                    ctx,
                )
            }
            _ => binary(
                BinOp::Add,
                (pointer_side(lhs, ctx, bits), lhs),
                (pointer_side(rhs, ctx, bits), rhs),
                bits,
                ctx,
            ),
        },
        Expr::Bin {
            op: op @ (BinOp::MulHigh | BinOp::MulHighS),
            lhs,
            rhs,
        } => {
            let ty = Int {
                bits: 64,
                signed: *op == BinOp::MulHighS,
            };
            Printed::new(
                format!(
                    "{}({}, {})",
                    operator(*op),
                    render_expr(lhs, ctx),
                    render_expr(rhs, ctx)
                ),
                ty,
                wrapped(ALL, ty),
                13,
            )
        }
        // C divides a signed value with a sign: each operand is read as the
        // signed type of the operation's width unless it already is one.
        Expr::Bin {
            op: op @ (BinOp::DivS | BinOp::ModS),
            lhs,
            rhs,
        } => {
            let width = crate::ir::semantics::operand_width(lhs, rhs);
            // A narrower signed value divides as its extension does, but
            // for the quotient of the least value by -1.
            let narrower = matches!(rhs.as_ref(), Expr::Const(divisor)
                if crate::ir::semantics::sign_extend(*divisor, width) != -1);
            let side = |side: &Expr| match side {
                Expr::Const(value) => signed_constant(*value, width),
                _ => {
                    let printed = print(side, ctx, width);
                    if printed.ty.signed
                        && (printed.ty.bits == width || (narrower && printed.ty.bits < width))
                        && printed.exact >= width
                    {
                        printed
                    } else {
                        printed.cast(width, true, width)
                    }
                }
            };
            let (dividend, divisor) = (side(lhs), side(rhs));
            Printed::new(
                format!(
                    "{} {} {}",
                    dividend.within(11, false).text,
                    operator(*op),
                    divisor.within(11, true).text
                ),
                dividend.ty.common(divisor.ty),
                width,
                11,
            )
            .ranging(Range::Signed(width))
        }
        // C divides without a sign only when the type it converts both
        // operands to has none and holds both whole.
        Expr::Bin {
            op: op @ (BinOp::DivU | BinOp::ModU),
            lhs,
            rhs,
        } => {
            let (mut dividend, mut divisor) = (print(lhs, ctx, ALL), print(rhs, ctx, ALL));
            let whole = |dividend: &Printed, divisor: &Printed| {
                let ty = dividend.ty.common(divisor.ty);
                converted(dividend, ty).min(converted(divisor, ty))
            };
            if whole(&dividend, &divisor) < ALL && dividend.exact >= 64 && divisor.exact >= 64 {
                if matches!(lhs.as_ref(), Expr::Const(_)) {
                    divisor = widen(divisor, true, true);
                } else {
                    dividend = widen(dividend, false, true);
                }
            }
            let ty = dividend.ty.common(divisor.ty);
            let exact = whole(&dividend, &divisor);
            Printed::new(
                format!(
                    "{} {} {}",
                    dividend.within(11, false).text,
                    operator(*op),
                    divisor.within(11, true).text
                ),
                ty,
                if exact == ALL {
                    ALL
                } else {
                    exact.min(ty.bits)
                },
                11,
            )
        }
        // C shifts a signed value arithmetically: a value that is not one
        // of the operation's width is cast to the signed type of that width.
        Expr::Bin {
            op: BinOp::Sar,
            lhs,
            rhs,
        } => {
            let width = crate::ir::semantics::operand_width(lhs, rhs);
            let shifted = print(lhs, ctx, width);
            let shifted = if shifted.ty.signed && shifted.ty.bits <= width && shifted.exact >= width
            {
                shifted
            } else {
                shifted.cast(width, true, width)
            };
            Printed::new(
                format!(
                    "{} >> {}",
                    shifted.within(9, false).text,
                    operand(rhs, ctx, 9, true)
                ),
                shifted.ty,
                width,
                9,
            )
            .ranging(Range::Signed(width))
        }
        // C shifts at the type of the shifted value.
        Expr::Bin {
            op: BinOp::Shl,
            lhs,
            rhs,
        } => {
            let amount = match rhs.as_ref() {
                Expr::Const(amount) if *amount < 64 => *amount as u32,
                _ => 0,
            };
            let keeps =
                |shifted: &Printed| wrapped(shifted.exact.saturating_add(amount), shifted.ty);
            let shifted = print(lhs, ctx, bits.saturating_sub(amount));
            let shifted = if keeps(&shifted) < bits && shifted.ty.bits < 64 {
                widen(shifted, matches!(lhs.as_ref(), Expr::Const(_)), true)
            } else {
                shifted
            };
            let exact = keeps(&shifted);
            Printed::new(
                format!(
                    "{} << {}",
                    shifted.within(9, false).text,
                    operand(rhs, ctx, 9, true)
                ),
                shifted.ty,
                exact,
                9,
            )
        }
        // A logical shift brings the bits above the reader's into view, and
        // zeros, which C brings in only above a value of no sign.
        Expr::Bin {
            op: BinOp::Shr,
            lhs,
            rhs,
        } => {
            let (needed, dropped) = match rhs.as_ref() {
                Expr::Const(amount) => {
                    let amount = (*amount).min(64) as u32;
                    ((bits + amount).min(ALL), amount)
                }
                _ => (ALL, 63),
            };
            let shifted = print(lhs, ctx, needed);
            let exact = if shifted.exact == ALL {
                ALL
            } else {
                shifted.exact.saturating_sub(dropped)
            };
            Printed::new(
                format!(
                    "{} >> {}",
                    shifted.within(9, false).text,
                    operand(rhs, ctx, 9, true)
                ),
                shifted.ty,
                exact,
                9,
            )
        }
        Expr::Bin { op, lhs, rhs } => {
            let side = |side: &Expr| match side {
                // A bitwise operation reads a constant as its bits.
                Expr::Const(value) if matches!(op, BinOp::And | BinOp::Or | BinOp::Xor) => {
                    Printed::new(format!("0x{value:x}"), Int::literal(*value), ALL, 13)
                }
                _ if matches!(op, BinOp::Sub) => pointer_side(side, ctx, bits),
                _ => print(side, ctx, bits),
            };
            binary(*op, (side(lhs), lhs), (side(rhs), rhs), bits, ctx)
        }
        Expr::Load {
            addr,
            width,
            signed,
        } => load(addr, *width, *signed, ctx),
        // A narrower signed value extends with its sign wherever C widens
        // it, so only a value of another type is cast.
        Expr::SignExtend { value, width } => {
            let from = u32::from(*width) * 8;
            let inner = print(value, ctx, from);
            if inner.ty.signed && inner.ty.bits == from && inner.exact >= from {
                Printed { exact: 64, ..inner }.ranging(Range::Signed(from))
            } else {
                Printed::new(
                    format!("({})({})", type_of(*width, true), inner.text),
                    Int::promoted(from, true),
                    64,
                    12,
                )
                .ranging(Range::Signed(from))
            }
        }
        Expr::Select { .. } if let Some((text, _)) = logic(value, false, ctx) => {
            Printed::new(format!("({text})"), Int::INT, ALL, 13).ranging(Range::Unsigned(1))
        }
        Expr::Select {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => {
            let keeps = |then: &Printed, els: &Printed| {
                let ty = then.ty.common(els.ty);
                converted(then, ty).min(converted(els, ty))
            };
            let (mut chosen, mut other) = (print(then, ctx, bits), print(els, ctx, bits));
            if keeps(&chosen, &other) < bits && chosen.ty.common(other.ty).bits < 64 {
                if matches!(then.as_ref(), Expr::Const(_)) {
                    other = widen(other, matches!(els.as_ref(), Expr::Const(_)), false);
                } else {
                    chosen = widen(chosen, false, false);
                }
            }
            let exact = keeps(&chosen, &other);
            let ty = chosen.ty.common(other.ty);
            Printed::new(
                format!(
                    "({} ? {} : {})",
                    condition(*cond, lhs, rhs, ctx),
                    chosen.within(1, false).text,
                    other.within(1, true).text
                ),
                ty,
                exact,
                13,
            )
        }
    }
}

/// `lhs op rhs` for an operator C applies at the type it converts both
/// operands to. When that type is narrower than the bits the reader
/// needs, the operand that keeps fewer of them is computed on at 64 bits.
fn binary(
    op: BinOp,
    (lhs, left): (Printed, &Expr),
    (rhs, right): (Printed, &Expr),
    bits: u32,
    ctx: &Ctx<'_>,
) -> Printed {
    let strength = binding(op);
    let (zero_left, zero_right) = (zero_bits(left, ctx), zero_bits(right, ctx));
    let keeps = |lhs: &Printed, rhs: &Printed| {
        let ty = lhs.ty.common(rhs.ty);
        let (a, b) = (converted(lhs, ty), converted(rhs, ty));
        // Operands equal to the IR's and too small to overflow C's type
        // give the IR's result.
        let room = ty.bits - u32::from(ty.signed);
        let whole = a == ALL && b == ALL;
        match op {
            BinOp::Add if whole && zero_left.max(zero_right) < room => ALL,
            BinOp::Mul if whole && zero_left + zero_right <= room => ALL,
            BinOp::Sub if whole && ty.signed && zero_left.max(zero_right) < ty.bits => 64,
            BinOp::And => {
                // What an operand equal to the IR's leaves clear is clear on
                // both sides.
                if (a == ALL && b >= zero_left) || (b == ALL && a >= zero_right) {
                    ALL
                } else {
                    a.min(b)
                }
            }
            BinOp::Or | BinOp::Xor => a.min(b),
            _ => wrapped(a.min(b), ty),
        }
    };
    let (mut lhs, mut rhs) = (lhs, rhs);
    if keeps(&lhs, &rhs) < bits && lhs.ty.common(rhs.ty).bits < 64 {
        let ty = lhs.ty.common(rhs.ty);
        let (constant_left, constant_right) = (
            matches!(left, Expr::Const(_)),
            matches!(right, Expr::Const(_)),
        );
        let widen_left = if constant_left == constant_right {
            converted(&lhs, ty) <= converted(&rhs, ty)
        } else {
            constant_right
        };
        if widen_left {
            lhs = widen(lhs, constant_left, false);
        } else {
            rhs = widen(rhs, constant_right, false);
        }
    }
    let exact = keeps(&lhs, &rhs);
    let ty = lhs.ty.common(rhs.ty);
    Printed::new(
        format!(
            "{} {} {}",
            lhs.within(strength, false).text,
            operator(op),
            rhs.within(strength, true).text
        ),
        ty,
        exact,
        strength,
    )
}

/// An operand of an addition or a subtraction, where a typed pointer the
/// IR moves by bytes is counted as bytes.
fn pointer_side(expr: &Expr, ctx: &Ctx<'_>, bits: u32) -> Printed {
    match byte_pointer(expr, ctx) {
        Some(text) => Printed::opaque(text, 12),
        None => print(expr, ctx, bits),
    }
}

/// `printed` computed on at 64 bits when what `keeps` says the result
/// keeps falls short of the reader's `bits`.
fn widened(printed: Printed, expr: &Expr, bits: u32, keeps: impl Fn(&Printed) -> u32) -> Printed {
    if keeps(&printed) >= bits || printed.ty.bits >= 64 {
        printed
    } else {
        widen(printed, matches!(expr, Expr::Const(_)), false)
    }
}

/// `printed` converted to the 64-bit type of its sign, so that C computes
/// on it at 64 bits: a constant takes a suffix, which is unsigned when
/// `unsigned` asks for it.
fn widen(printed: Printed, constant: bool, unsigned: bool) -> Printed {
    let exact = printed.exact;
    if constant {
        let signed = printed.ty.signed && !unsigned;
        Printed {
            text: format!("{}{}", printed.text, if signed { "LL" } else { "ULL" }),
            ty: Int { bits: 64, signed },
            ..printed
        }
    } else {
        let signed = printed.ty.signed && !unsigned;
        printed.cast(64, signed, exact)
    }
}

/// A register read `width` bits wide, as the variable or parameter that
/// holds it is declared.
fn register(index: u16, width: u8, ctx: &Ctx<'_>) -> Printed {
    let text = ctx.register(index, width);
    let read = u32::from(width);
    let Some(declared) = ctx.declared.get(&index) else {
        let ty = if read <= 32 { Int::U32 } else { Int::U64 };
        return Printed::new(text, ty, ALL, 13);
    };
    // A parameter arrives extended to 64 bits as its type says; a variable
    // holds no more than its own bits.
    let exact = if read < declared.bits {
        read
    } else if !declared.signed && (declared.param || read == declared.bits) {
        ALL
    } else if declared.param {
        read
    } else {
        declared.bits
    };
    Printed::new(
        text,
        Int::promoted(declared.bits, declared.signed),
        exact,
        13,
    )
    .ranging(if declared.signed {
        Range::Signed(declared.bits)
    } else {
        Range::Unsigned(declared.bits)
    })
}

fn constant(value: u64) -> Printed {
    // A 64-bit constant just below zero is a small negative number.
    if value >= 1 << 63 && value.wrapping_neg() < 1 << 31 {
        Printed::new(format!("-0x{:x}", value.wrapping_neg()), Int::INT, 64, 13)
            .ranging(Range::Signed(32))
    } else {
        Printed::new(format!("0x{value:x}"), Int::literal(value), ALL, 13)
    }
}

/// A constant operand of a signed operation `width` bits wide, as the
/// number of that sign it is.
fn signed_constant(value: u64, width: u32) -> Printed {
    let number = crate::ir::semantics::sign_extend(value, width);
    let magnitude = number.unsigned_abs();
    let long = Int {
        bits: 64,
        signed: true,
    };
    let (text, ty) = if number >= 0 || Int::literal(magnitude).signed {
        let sign = if number < 0 { "-" } else { "" };
        (format!("{sign}0x{magnitude:x}"), Int::literal(magnitude))
    } else if magnitude <= 0xffff_ffff {
        (format!("-0x{magnitude:x}LL"), long)
    } else {
        (format!("(int64_t)0x{:x}", number as u64), long)
    };
    Printed::new(text, ty, width, 13).ranging(Range::Signed(width))
}

/// `lhs & mask` for a mask of the low bits. The mask is left out when the
/// value already fits in them or the reader looks at no more bits.
fn masked(lhs: &Expr, mask: u64, ctx: &Ctx<'_>, bits: u32) -> Printed {
    let kept = mask.count_ones();
    let inner = print(lhs, ctx, bits.min(kept));
    let alone = if (inner.exact == ALL && zero_bits(lhs, ctx) <= kept)
        || (inner.exact >= kept && inner.unsigned_bits() <= kept)
    {
        ALL
    } else {
        inner.exact.min(kept)
    };
    if alone >= bits {
        return Printed {
            exact: alone,
            ..inner
        };
    }
    let ty = inner.ty.common(Int::literal(mask));
    let exact = match converted(&inner, ty) {
        exact if exact >= kept => ALL,
        exact => exact,
    };
    let (text, strength) = if mask == 0xffff_ffff {
        // Arithmetic and shifts bind tighter than `&`, but are
        // parenthesised anyway for readability.
        let left = if inner.strength > 6 && inner.strength < 12 {
            format!("({})", inner.text)
        } else {
            inner.within(6, false).text
        };
        (format!("({left} & 0xffffffff)"), 13)
    } else {
        (format!("{} & 0x{mask:x}", inner.within(6, false).text), 6)
    };
    Printed::new(text, ty, exact, strength).ranging(Range::Unsigned(kept))
}

/// Memory read `width` bytes wide, by name where it has one.
fn load(addr: &Expr, width: u8, signed: bool, ctx: &Ctx<'_>) -> Printed {
    let (text, declared_signed) = if let Some(member) = member_access(addr, width, ctx) {
        (member, signed)
    } else if let Some(indexed) = array_access(addr, width, ctx)
        .or_else(|| crate::render::naming::flat_array_access(addr, width, ctx))
    {
        (indexed, signed)
    } else {
        let address = render_expr(addr, ctx);
        match ctx.slots.get(&address) {
            Some(name) => {
                let text = slot_access(name, width, signed, ctx);
                let declared = if &text == name {
                    ctx.signed_locals.contains(name)
                } else {
                    signed
                };
                (text, declared)
            }
            None => match global_name(addr, width, ctx) {
                Some(name) => (name, signed),
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

/// `op` applied to `args`: the bit counts C has builtins for take their
/// argument at the builtin's width.
fn operation(op: Operation, args: &[Expr], expr: &Expr, ctx: &Ctx<'_>) -> Printed {
    let builtin = |name: &str, bits: u8| {
        let (suffix, width) = if bits == 64 { ("ll", 64) } else { ("", 32) };
        Printed::new(
            format!(
                "__builtin_{name}{suffix}({})",
                print(&args[0], ctx, width).text
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
                print(&args[0], ctx, u32::from(bits)).text
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

/// A local read or written whole by name, and through a cast when the access
/// covers only part of it.
/// `(uint8_t *)&local + offset` for a sum of the stack pointer, constants
/// and other terms whose stack part addresses a local.
pub(crate) fn local_plus_offset(value: &Expr, ctx: &Ctx<'_>) -> Option<String> {
    let (slot, rest) =
        crate::render::locals::offset_local(value, crate::arch::stack_pointer(ctx.isa))?;
    let Expr::Bin { lhs: base, rhs, .. } = &slot else {
        return None;
    };
    let Expr::Const(offset) = rhs.as_ref() else {
        return None;
    };
    // The buffer starts at the slot or a little below it.
    let (name, below) = (0..crate::render::locals::BUFFER_REACH as u64).find_map(|below| {
        let start = Expr::bin(
            BinOp::Add,
            base.as_ref().clone(),
            Expr::Const(offset.wrapping_sub(below)),
        );
        ctx.slots
            .get(&render_expr(&start, ctx))
            .map(|name| (name, below))
    })?;
    let mut rest = rest
        .into_iter()
        .cloned()
        .reduce(|sum, term| Expr::bin(BinOp::Add, sum, term))?;
    if below != 0 {
        rest = Expr::bin(BinOp::Add, rest, Expr::Const(below));
    }
    Some(format!("(uint8_t *)&{name} + {}", render_expr(&rest, ctx)))
}

pub(crate) fn slot_access(name: &str, width: u8, signed: bool, ctx: &Ctx<'_>) -> String {
    match ctx.local_widths.get(name) {
        Some(declared) if *declared != width => {
            format!("*({} *)&{name}", type_of(width, signed))
        }
        _ => name.to_owned(),
    }
}

/// True when the value provably fits in `bits` bits.
pub(crate) fn fits(expr: &Expr, bits: u32, ctx: &Ctx<'_>) -> bool {
    crate::ssa::ranges::of(expr).hi <= crate::ir::semantics::mask(bits)
        || typed_fits(expr, bits, ctx)
}

/// True when the C types of the operands keep the value within `bits`
/// bits. The value alone fitting says nothing of the types, so it is not
/// asked of the operands.
fn typed_fits(expr: &Expr, bits: u32, ctx: &Ctx<'_>) -> bool {
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
                _ => typed_fits(lhs, bits, ctx) && typed_fits(rhs, bits, ctx),
            },
            BinOp::Or | BinOp::Xor => typed_fits(lhs, bits, ctx) && typed_fits(rhs, bits, ctx),
            // Arithmetic on 32-bit operands wraps at 32 bits in C, which is
            // what the mask would do; narrower results carry out of the mask.
            BinOp::Add | BinOp::Sub | BinOp::Mul => {
                bits >= 32 && typed_fits(lhs, bits, ctx) && typed_fits(rhs, bits, ctx)
            }
            BinOp::Shl => {
                bits >= 32
                    && matches!(rhs.as_ref(), Expr::Const(amount) if *amount < 32)
                    && typed_fits(lhs, bits, ctx)
            }
            BinOp::DivS | BinOp::DivU | BinOp::ModS | BinOp::ModU | BinOp::Shr | BinOp::Sar => {
                typed_fits(lhs, bits, ctx) && typed_fits(rhs, bits, ctx)
            }
            _ => false,
        },
        Expr::Select { then, els, .. } => typed_fits(then, bits, ctx) && typed_fits(els, bits, ctx),
        Expr::Apply { .. } => crate::ir::semantics::width(expr) <= bits,
    }
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
    let [a, b] = compared(cond, lhs, rhs, ctx);
    let a = a.within(strength, false).text;
    let b = b.within(strength, true).text;
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

/// The index a switch compares with its case values, which it reads as an
/// equality does.
pub(crate) fn switch_index(index: &Expr, ctx: &Ctx<'_>) -> String {
    let [index, _] = compared(Cond::Eq, index, &Expr::Const(0), ctx);
    index.text
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
            let magnitude = crate::ir::semantics::sign_extend(*value, bits).unsigned_abs();
            match Int::literal(magnitude) {
                ty if ty.signed => Printed::new(format!("-0x{magnitude:x}"), ty, bits, 13)
                    .ranging(Range::Signed(bits)),
                _ => print(side, ctx, bits),
            }
        }
        _ => print(side, ctx, bits),
    };
    let exprs = [lhs, rhs];
    let mut sides = [side(lhs), side(rhs)];
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

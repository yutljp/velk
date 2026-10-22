use std::collections::HashMap;

use crate::ir::{BinOp, CType, Cond, Expr, Member, Operation, Precision, Rounding, reg_name};
use crate::loader::Isa;
use crate::render::globals::View;
use crate::render::int::{ALL, Int, Printed, Range, ValueKind, converted, fit, wrapped, zero_bits};
use crate::render::naming::array_access;
use crate::render::naming::member_access;
use crate::render::naming::{global_access, global_pointer};
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
    pub(super) abi: Option<&'a super::abi::Plan>,
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
    /// Byte addresses proven to fit a scalar stack parameter at this access width.
    pub(super) parameter_addresses: HashMap<(String, u8), String>,
    /// Rendered stack address within a wider local to that address as bytes
    /// into the local.
    pub(super) local_parts: HashMap<String, String>,
    /// Declared width of each local, so a mask to that width can be dropped.
    pub(super) local_widths: HashMap<String, u8>,
    pub(super) local_element_types: HashMap<String, CType>,
    /// Pointer locals whose arithmetic C scales by a pointee wider than a byte.
    pub(super) local_scaled: std::collections::HashSet<String>,
    /// Locals holding floats, with their precision.
    pub(super) local_floats: HashMap<String, Precision>,
    /// Locals declared as signed integers.
    pub(super) signed_locals: std::collections::HashSet<String>,
    /// Parameters wider than 32 bits: masking one is a real truncation.
    pub(super) wide_params: std::collections::HashSet<u16>,
    pub(super) symbols: &'a super::Symbols,
    pub(super) globals: crate::render::globals::Globals,
    /// Non-executable `(start, size)` ranges: a constant address inside one is a global.
    pub(super) data_ranges: &'a [(u64, u64)],
    /// Structure fields the debug info names, by struct and byte offset.
    pub(super) members: HashMap<(String, i64), Member>,
    pub(super) element_types: HashMap<u16, CType>,
    /// The pointers, by name, to `char`, whose sign the platform decides.
    pub(super) plain_chars: std::collections::HashSet<String>,
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
    /// The pointer type each named register is declared with, as a cast
    /// names it, and the function's return type when it is a pointer.
    pub(super) pointer_types: HashMap<u16, String>,
    /// The pointer type each pointer local is declared with.
    pub(super) local_pointer_types: HashMap<String, String>,
    pub(super) ret_pointer: Option<String>,
    /// The integer type each named register is declared with.
    pub(super) declared: HashMap<u16, Declared>,
    /// The bits each variable's values fit in.
    pub(super) value_bits: HashMap<u16, u32>,
    /// The variables the structured body reads just once.
    pub(super) read_once: std::collections::HashSet<u16>,
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
    print_value_at(value, ctx, bits, integer).text
}

/// A value after address names have been recovered, with the C category
/// of the recovered expression kept alongside its text.
pub(crate) fn print_value_at(value: &Expr, ctx: &Ctx<'_>, bits: u32, integer: bool) -> Printed {
    let printed = value_at(value, ctx, bits, integer);
    if integer {
        printed.address_integer()
    } else {
        printed
    }
}

fn value_at(value: &Expr, ctx: &Ctx<'_>, bits: u32, integer: bool) -> Printed {
    // The address of a stack local reads as that.
    if matches!(value, Expr::Bin { .. })
        && let Some(name) = ctx.slots.get(&render_expr(value, ctx))
    {
        return Printed::pointer(format!("&{name}"), 12);
    }
    // So does it with an offset added, as an index into a local buffer.
    if let Some(text) = local_plus_offset(value, ctx) {
        return Printed::pointer(text, 10);
    }
    // And the address of a field of an element of an array of structures.
    if matches!(value, Expr::Bin { op: BinOp::Add, .. })
        && let Some(text) = crate::render::naming::field_address(value, ctx)
    {
        return Printed::pointer(text, 12);
    }
    match value {
        // A constant pointing at a string reads as the string.
        Expr::Const(address) if let Some(text) = ctx.strings.get(address) => Printed::pointer(
            format!(
                "\"{}\"",
                text.chars()
                    .flat_map(char::escape_default)
                    .collect::<String>()
            ),
            13,
        ),
        Expr::Const(address)
            if (ctx.symbols.data.contains_key(address)
                || ctx.symbols.import_slots.contains_key(address))
                && let Some(name) = global_pointer(value, View::Unsigned(1), ctx) =>
        {
            Printed::pointer(name, 13)
        }
        // Only a top-level constant becomes a function name: an immediate
        // inside arithmetic can coincidentally equal a function address.
        // The function is declared ahead of the one printed, and an integer
        // takes its address as a number.
        Expr::Const(address)
            if *address != 0
                && let Some(name) = ctx.symbols.functions.get(address) =>
        {
            let name = sanitize(name);
            ctx.taken.borrow_mut().insert(name.clone());
            Printed::pointer(name, 13)
        }
        // Each arm of a choice between addresses is a value of its own.
        Expr::Select {
            cond,
            lhs,
            rhs,
            then,
            els,
        } if matches!(then.as_ref(), Expr::Const(_))
            && matches!(els.as_ref(), Expr::Const(_))
            && logic(value, false, ctx).is_none() =>
        {
            selected(
                (*cond, lhs, rhs),
                (then, print_value_at(then, ctx, bits, integer)),
                (els, print_value_at(els, ctx, bits, integer)),
                ctx,
                bits,
            )
        }
        _ => print(value, ctx, bits),
    }
}

fn unmasked_float(expr: &Expr, precision: Precision) -> Option<&Expr> {
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
    if let Some(value) = unmasked_float(expr, precision) {
        return float_operand(value, precision, ctx, parent, right);
    }
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
        Expr::Reg { index, width }
            if ctx.abi.is_some()
                && (ctx.floats.get(index) != Some(&precision)
                    || u32::from(*width) < u32::from(precision.bits())) =>
        {
            let bits = print(&Expr::reg(*index, *width), ctx, 64).text;
            bits_float(bits, precision)
        }
        Expr::Reg { index, .. } => ctx.register(*index, 64),
        Expr::Apply { op, args }
            if ctx.abi.is_some() && op.result_precision() == Some(precision) =>
        {
            render_operation(*op, args, ctx)
        }
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if matches!(lhs.as_ref(), Expr::Reg { .. })
            && matches!(rhs.as_ref(), Expr::Const(0xffff_ffff))
            && (precision == Precision::Single || ctx.abi.is_none()) =>
        {
            float_operand(lhs, precision, ctx, parent, right)
        }
        // Memory read as a float names the float type.
        Expr::Load { addr, width, .. } if u32::from(*width) * 8 == u32::from(precision.bits()) => {
            if let Some(bits) = copied_load(addr, *width, ctx) {
                return bits_float(bits, precision);
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
        _ if ctx.abi.is_some() => bits_float(print(expr, ctx, 64).text, precision),
        _ => operand(expr, ctx, parent, right),
    }
}

fn bits_float(bits: String, precision: Precision) -> String {
    let (float, integer) = match precision {
        Precision::Single => ("float", "uint32_t"),
        Precision::Double => ("double", "uint64_t"),
    };
    format!("((union {{ {integer} bits; {float} value; }}){{ .bits = ({integer})({bits}) }}).value")
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

/// An operand of an operation C applies to integers only: a pointer is
/// taken as its address, an integer.
fn integral(expr: &Expr, ctx: &Ctx<'_>, bits: u32) -> Printed {
    print(expr, ctx, bits).address_integer()
}

fn shift_count(expr: &Expr, ctx: &Ctx<'_>) -> (Printed, u32) {
    if let Expr::Const(amount) = expr {
        let amount = (amount & 63) as u32;
        return (constant(u64::from(amount)), amount);
    }
    if let Some(range) = value_range(expr, ctx)
        && range.hi <= 63
    {
        (integral(expr, ctx, 64), range.hi as u32)
    } else {
        (masked(expr, 63, ctx, 64), 63)
    }
}

fn shift(op: BinOp, lhs: &Expr, rhs: &Expr, ctx: &Ctx<'_>, bits: u32) -> Printed {
    let (count, maximum) = shift_count(rhs, ctx);
    if op != BinOp::Sar && maximum == 0 {
        return integral(lhs, ctx, bits);
    }
    if op == BinOp::Sar {
        let width = crate::ir::semantics::operand_width(lhs, rhs);
        let mut value = integral(lhs, ctx, width);
        if !value.ty.signed || value.ty.bits > width || value.exact < width {
            value = value.cast(width, true, width);
        }
        if maximum >= value.ty.bits {
            value = value.cast(64, true, width);
        }
        return Printed::new(
            if maximum == 0 {
                value.text
            } else {
                format!(
                    "{} >> {}",
                    value.within(9, false).text,
                    count.within(9, true).text
                )
            },
            value.ty,
            width,
            if maximum == 0 { value.strength } else { 9 },
        )
        .ranging(Range::Signed(width));
    }

    let amount = match rhs {
        Expr::Const(amount) if op == BinOp::Shl => (amount & 63) as u32,
        _ => 0,
    };
    let read = if op == BinOp::Shl && matches!(rhs, Expr::Const(_)) {
        bits.saturating_sub(amount)
    } else {
        64
    };
    let mut value = integral(lhs, ctx, read);
    let value_bits = value.unsigned_bits().min(if value.exact == ALL {
        zero_bits(lhs, ctx)
    } else {
        ALL
    });
    let result_bits = value_bits.saturating_add(maximum);
    let safe = maximum < value.ty.bits
        && match op {
            BinOp::Shl if value.ty.signed => result_bits < value.ty.bits,
            BinOp::Shl => bits <= value.ty.bits || result_bits <= value.ty.bits,
            _ => !value.ty.signed || value_bits < value.ty.bits,
        };
    if !safe {
        value = if matches!(lhs, Expr::Const(_)) {
            widen(value, true, true)
        } else {
            let exact = converted(&value, Int::U64);
            value.cast(64, false, exact)
        };
    }
    let exact = if op == BinOp::Shr
        || (value.exact == ALL && result_bits < value.ty.bits + u32::from(!value.ty.signed))
    {
        ALL
    } else {
        wrapped(value.exact.saturating_add(amount), value.ty)
    };
    Printed::new(
        format!(
            "{} {} {}",
            value.within(9, false).text,
            operator(op),
            count.within(9, true).text
        ),
        value.ty,
        exact,
        9,
    )
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
        Operation::FloatNegate(p) => format!("-{}", float_operand(&args[0], p, ctx, 12, false)),
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

pub(crate) fn render_expr(value: &Expr, ctx: &Ctx<'_>) -> String {
    print(value, ctx, 64).text
}

/// `value` as C for a reader that looks at its low `bits` bits.
pub(crate) fn render_at(value: &Expr, ctx: &Ctx<'_>, bits: u32) -> String {
    print(value, ctx, bits).text
}

pub(super) fn integer_sum(expr: &Expr, ctx: &Ctx<'_>) -> Printed {
    match expr {
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => binary(
            BinOp::Add,
            (integer_sum(lhs, ctx), lhs),
            (integer_sum(rhs, ctx), rhs),
            64,
            ctx,
        ),
        _ => integral(expr, ctx, 64),
    }
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
            let negated = widened(integral(rhs, ctx, bits), rhs, bits, keeps);
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
            let inverted = widened(integral(lhs, ctx, bits), lhs, bits, keeps);
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
        Expr::Bin {
            op: op @ (BinOp::Add | BinOp::Sub),
            lhs,
            rhs,
        } => arithmetic(value, *op, lhs, rhs, ctx, bits),
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
                    integral(lhs, ctx, 64).text,
                    integral(rhs, ctx, 64).text
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
                    let printed = integral(side, ctx, width);
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
            let (mut dividend, mut divisor) = (integral(lhs, ctx, ALL), integral(rhs, ctx, ALL));
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
        Expr::Bin {
            op: op @ (BinOp::Shl | BinOp::Shr | BinOp::Sar),
            lhs,
            rhs,
        } => shift(*op, lhs, rhs, ctx, bits),
        Expr::Bin { op, lhs, rhs } => {
            let side = |side: &Expr| match side {
                // A bitwise operation reads a constant as its bits.
                Expr::Const(value) if matches!(op, BinOp::And | BinOp::Or | BinOp::Xor) => {
                    Printed::new(format!("0x{value:x}"), Int::literal(*value), ALL, 13)
                }
                _ => integral(side, ctx, bits),
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
            let inner = integral(value, ctx, from);
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
        } => selected(
            (*cond, lhs, rhs),
            (then, print(then, ctx, bits)),
            (els, print(els, ctx, bits)),
            ctx,
            bits,
        ),
    }
}

fn arithmetic(
    value: &Expr,
    op: BinOp,
    lhs: &Expr,
    rhs: &Expr,
    ctx: &Ctx<'_>,
    bits: u32,
) -> Printed {
    let (left, right) = (print(lhs, ctx, bits), print(rhs, ctx, bits));
    // The IR subtracts addresses as bytes modulo the machine width. C's
    // pointer difference also requires a shared allocation and ptrdiff_t fit.
    if right.is_pointer() && (op == BinOp::Sub || left.is_pointer()) {
        return binary(
            op,
            (left.address_integer(), lhs),
            (right.address_integer(), rhs),
            bits,
            ctx,
        );
    }
    if left.is_pointer() || right.is_pointer() {
        if let Some((name, _, index)) = crate::render::naming::element_index(value, ctx) {
            return match index {
                Expr::Const(0) => Printed::pointer(name, 13),
                Expr::Bin {
                    op: BinOp::Sub,
                    lhs,
                    rhs,
                } if matches!(lhs.as_ref(), Expr::Const(0)) => Printed::pointer(
                    format!("{name} - {}", integral(&rhs, ctx, 64).within(10, true).text),
                    10,
                ),
                index => Printed::pointer(
                    format!(
                        "{name} + {}",
                        integral(&index, ctx, 64).within(10, true).text
                    ),
                    10,
                ),
            };
        }
        if let Some(text) = byte_sum(value, ctx) {
            return Printed::pointer(text, 10);
        }
    }
    let bytes = |expr: &Expr, printed: Printed| {
        if printed.is_pointer()
            && let Some(text) = byte_pointer(expr, ctx)
        {
            Printed::pointer(text, 12)
        } else {
            printed
        }
    };
    let left = bytes(lhs, left);
    let right = bytes(rhs, right);
    match (op, rhs) {
        (BinOp::Add, Expr::Const(value)) if *value >= 1 << 63 => {
            let magnitude = value.wrapping_neg();
            binary(
                BinOp::Sub,
                (left, lhs),
                (
                    Printed::new(format!("0x{magnitude:x}"), Int::literal(magnitude), ALL, 13),
                    rhs,
                ),
                bits,
                ctx,
            )
        }
        _ => binary(op, (left, lhs), (right, rhs), bits, ctx),
    }
}

fn selected(
    (cond, lhs, rhs): (Cond, &Expr, &Expr),
    (then, mut chosen): (&Expr, Printed),
    (els, mut other): (&Expr, Printed),
    ctx: &Ctx<'_>,
    bits: u32,
) -> Printed {
    let pointer = (chosen.is_pointer() || matches!(then, Expr::Const(0)))
        && (other.is_pointer() || matches!(els, Expr::Const(0)))
        && (chosen.is_pointer() || other.is_pointer());
    if pointer {
        return Printed::pointer(
            format!(
                "({} ? {} : {})",
                condition(cond, lhs, rhs, ctx),
                chosen.within(1, false).text,
                other.within(1, true).text
            ),
            13,
        );
    }
    chosen = chosen.address_integer();
    other = other.address_integer();
    let keeps = |then: &Printed, els: &Printed| {
        let ty = then.ty.common(els.ty);
        converted(then, ty).min(converted(els, ty))
    };
    if keeps(&chosen, &other) < bits && chosen.ty.common(other.ty).bits < 64 {
        if matches!(then, Expr::Const(_)) {
            other = widen(other, matches!(els, Expr::Const(_)), false);
        } else {
            chosen = widen(chosen, false, false);
        }
    }
    let exact = keeps(&chosen, &other);
    let ty = chosen.ty.common(other.ty);
    let kind = if chosen.kind == ValueKind::Opaque || other.kind == ValueKind::Opaque {
        ValueKind::Opaque
    } else {
        ValueKind::Integer
    };
    Printed {
        kind,
        ..Printed::new(
            format!(
                "({} ? {} : {})",
                condition(cond, lhs, rhs, ctx),
                chosen.within(1, false).text,
                other.within(1, true).text
            ),
            ty,
            exact,
            13,
        )
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
    if lhs.is_pointer() || rhs.is_pointer() {
        return Printed::pointer(
            format!(
                "{} {} {}",
                lhs.within(strength, false).text,
                operator(op),
                rhs.within(strength, true).text
            ),
            strength,
        );
    }
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
    if ctx.abi.is_some()
        && let Some(precision) = ctx.floats.get(&index)
    {
        let bits = float_bits(text, *precision);
        return if read < u32::from(precision.bits()) {
            bits.cast(read, false, ALL)
        } else {
            bits
        };
    }
    if ctx.pointer_types.contains_key(&index) {
        let pointer = Printed::pointer(text, 13);
        return if read < 64 {
            pointer.address_integer().cast(read, false, ALL)
        } else {
            pointer
        };
    }
    let Some(declared) = ctx.declared.get(&index) else {
        let ty = if read <= 32 { Int::U32 } else { Int::U64 };
        return Printed::new(text, ty, ALL, 13);
    };
    // A parameter arrives extended to 64 bits as its type says; a variable
    // holds no more than its own bits, which are all of a value that fits.
    let fits = !declared.param
        && ctx.value_bits.get(&index).is_some_and(|bits| {
            *bits < declared.bits || (*bits == declared.bits && !declared.signed)
        });
    let exact = if read < declared.bits {
        read
    } else if fits || (!declared.signed && (declared.param || read == declared.bits)) {
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
    let inner = integral(lhs, ctx, bits.min(kept));
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

pub(super) fn copy_address(addr: &Expr, width: u8, ctx: &Ctx<'_>) -> Option<String> {
    let address = render_expr(addr, ctx);
    ctx.parameter_addresses
        .get(&(address.clone(), width))
        .cloned()
        .or_else(|| object_address(addr, ctx).then_some(address))
}

fn copied_load(addr: &Expr, width: u8, ctx: &Ctx<'_>) -> Option<String> {
    let address = copy_address(addr, width, ctx)?;
    let ty = type_of(width, false);
    Some(format!(
        "*({ty} *)__builtin_memcpy(({ty}[1]){{0}}, {address}, {width})"
    ))
}

/// Memory read `width` bytes wide, by name where it has one.
fn load(addr: &Expr, width: u8, signed: bool, ctx: &Ctx<'_>) -> Printed {
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

/// `op` applied to `args`: the bit counts C has builtins for take their
/// argument at the builtin's width.
fn operation(op: Operation, args: &[Expr], expr: &Expr, ctx: &Ctx<'_>) -> Printed {
    if op == Operation::Lanes(crate::ir::LaneOp::Add, 64) && args.len() == 2 {
        return binary(
            BinOp::Add,
            (integral(&args[0], ctx, 64), &args[0]),
            (integral(&args[1], ctx, 64), &args[1]),
            64,
            ctx,
        );
    }
    if ctx.abi.is_some()
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

fn float_bits(value: String, precision: Precision) -> Printed {
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

/// A local read or written whole by name, and through a cast when the access
/// covers only part of it.
/// `(uint8_t *)&local + offset` for a sum of the stack pointer, constants
/// and other terms whose stack part addresses a local.
pub(crate) fn local_plus_offset(value: &Expr, ctx: &Ctx<'_>) -> Option<String> {
    if let Some(part) = ctx.local_parts.get(&render_expr(value, ctx)) {
        return Some(part.clone());
    }
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
    bits >= 64
        || value_range(expr, ctx).is_some_and(|range| range.hi <= crate::ir::semantics::mask(bits))
}

fn value_range(expr: &Expr, ctx: &Ctx<'_>) -> Option<crate::ssa::ranges::Fact> {
    crate::ssa::ranges::expression(expr, &|index, width| {
        let known = ctx.value_bits.get(&index).copied().unwrap_or(64);
        let parameter = ctx
            .declared
            .get(&index)
            .filter(|declared| declared.param && declared.integer && !declared.signed)
            .map_or(64, |declared| declared.bits);
        Some(crate::ssa::ranges::Fact::width(
            width.min(known).min(parameter),
        ))
    })
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
pub(crate) fn switch_index(index: &Expr, ctx: &Ctx<'_>) -> String {
    let [index, _] = compared(Cond::Eq, index, &Expr::Const(0), ctx);
    index.address_integer().text
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::ir::{BinOp, CType, Cond, Expr, FunctionIr, Operation, Param, Precision, Stmt};
    use crate::loader::Isa;

    fn function(stmts: Vec<Stmt>, params: &[CType]) -> FunctionIr {
        let mut ir = FunctionIr::single_block(Isa::X86_64, stmts);
        ir.params = params
            .iter()
            .zip([7, 6, 2])
            .enumerate()
            .map(|(position, (ty, index))| Param {
                index,
                name: format!("a{position}"),
                ty: ty.clone(),
            })
            .collect();
        ir.ret_type = CType::U64;
        ir
    }

    fn rendered(stmts: Vec<Stmt>, params: &[CType]) -> String {
        crate::render::render(
            &function(stmts, params),
            &[],
            &crate::render::Symbols::default(),
            &[],
        )
    }

    fn global_returned(value: Expr, ty: CType, params: &[CType]) -> String {
        let mut ir = function(vec![Stmt::Ret { value }], params);
        ir.ret_type = ty;
        let symbols = crate::render::Symbols {
            data: HashMap::from([(0x1000, "counter".to_owned())]),
            ..Default::default()
        };
        crate::render::render(&ir, &[], &symbols, &[(0x1000, 0x100)])
    }

    fn returned(value: Expr, params: &[CType]) -> String {
        rendered(vec![Stmt::Ret { value }], params)
    }

    fn pointer() -> CType {
        CType::pointer_to(CType::U32)
    }

    fn choice(then: Expr, els: Expr) -> Expr {
        Expr::Select {
            cond: Cond::Ne,
            lhs: Box::new(Expr::reg(6, 64)),
            rhs: Box::new(Expr::Const(0)),
            then: Box::new(then),
            els: Box::new(els),
        }
    }

    #[test]
    fn boolean_choices_render_as_truth_values_with_or_without_a_mask() {
        for (then, els, expected) in [(1, 0, "a0 == 0x0"), (0, 1, "a0 != 0x0")] {
            let choice = Expr::Select {
                cond: Cond::Eq,
                lhs: Box::new(Expr::reg(7, 32)),
                rhs: Box::new(Expr::Const(0)),
                then: Box::new(Expr::Const(then)),
                els: Box::new(Expr::Const(els)),
            };
            for value in [
                choice.clone(),
                Expr::bin(BinOp::And, choice.clone(), Expr::Const(0xffff_ffff)),
            ] {
                let text = returned(value, &[CType::I32]);
                assert!(text.contains(&format!("return ({expected});")), "{text}");
                assert!(!text.contains(" ? "), "{text}");
            }
            let text = returned(Expr::bin(BinOp::Mul, choice, Expr::Const(2)), &[CType::I32]);
            assert!(
                text.contains(&format!("return ({expected}) * 0x2;")),
                "{text}"
            );
        }
    }

    #[test]
    fn an_address_choice_still_recovers_the_named_address() {
        let text = global_returned(
            choice(Expr::Const(0x1000), Expr::Const(0)),
            CType::U64,
            &[CType::U64, CType::U64],
        );
        assert!(text.contains("uint8_t *const counter"), "{text}");
        assert!(
            text.contains("return (a1 != 0x0 ? (uintptr_t)counter : 0x0);"),
            "{text}"
        );
    }

    #[test]
    fn signed_global_reads_cast_the_unsigned_storage_at_the_access_width() {
        for (width, ty) in [
            (1, "int8_t"),
            (2, "int16_t"),
            (4, "int32_t"),
            (8, "int64_t"),
        ] {
            for addr in [
                Expr::Const(0x1000),
                Expr::bin(
                    BinOp::Add,
                    Expr::Const(0x1000),
                    Expr::bin(BinOp::Mul, Expr::reg(7, 64), Expr::Const(u64::from(width))),
                ),
            ] {
                let value = Expr::Load {
                    addr: Box::new(addr),
                    width,
                    signed: true,
                };
                let text = global_returned(value, CType::U64, &[CType::U64]);
                assert!(text.contains(&format!("({ty})")), "{text}");
                assert!(
                    text.contains(&format!("uint{}_t *const counter", width * 8)),
                    "{text}"
                );
                assert!(!text.contains(&format!("({ty})(uint64_t)")), "{text}");
            }
        }
    }

    #[test]
    fn covering_masks_keep_matching_float_results_in_float_consumers() {
        for (precision, ty, mask) in [
            (Precision::Single, "float", 0xffff_ffff),
            (Precision::Single, "float", 0xffff_ffff_ffff_ffff),
            (Precision::Double, "double", 0xffff_ffff_ffff_ffff),
        ] {
            let value = Expr::bin(
                BinOp::And,
                Expr::apply(
                    Operation::FloatAdd(precision),
                    vec![Expr::reg(7, 64), Expr::reg(6, 64)],
                ),
                Expr::Const(mask),
            );
            let text = global_returned(
                value,
                CType::Named(ty.to_owned()),
                &[CType::Named(ty.to_owned()), CType::Named(ty.to_owned())],
            );
            assert!(text.contains("return a0 + a1;"), "{text}");
        }
    }

    #[test]
    fn nested_masked_float_results_keep_precedence_and_fused_operations() {
        let float = CType::Named("float".to_owned());
        let params = [float.clone(), float.clone(), float.clone()];
        let masked = |value| Expr::bin(BinOp::And, value, Expr::Const(0xffff_ffff));
        let source = Expr::apply(
            Operation::FloatSub(Precision::Single),
            vec![Expr::reg(6, 64), Expr::reg(7, 64)],
        );
        let product = Expr::apply(
            Operation::FloatMul(Precision::Single),
            vec![source, Expr::reg(2, 64)],
        );
        let lerp = Expr::apply(
            Operation::FloatAdd(Precision::Single),
            vec![Expr::reg(7, 64), masked(product)],
        );
        let text = global_returned(lerp, float.clone(), &params);
        assert!(text.contains("return a0 + (a1 - a0) * a2;"), "{text}");

        let sum = Expr::apply(
            Operation::FloatAdd(Precision::Single),
            vec![Expr::reg(6, 64), Expr::reg(2, 64)],
        );
        let difference = Expr::apply(
            Operation::FloatSub(Precision::Single),
            vec![Expr::reg(7, 64), masked(sum)],
        );
        let text = global_returned(difference, float.clone(), &params);
        assert!(text.contains("return a0 - (a1 + a2);"), "{text}");

        let fused = Expr::apply(
            Operation::FloatMulAdd(Precision::Single),
            vec![Expr::reg(7, 64), Expr::reg(6, 64), Expr::reg(2, 64)],
        );
        let negated = Expr::apply(
            Operation::FloatNegate(Precision::Single),
            vec![masked(fused)],
        );
        let text = global_returned(negated, float, &params);
        assert!(text.contains("return -fmaf(a0, a1, a2);"), "{text}");
    }

    #[test]
    fn a_float_mask_view_rejects_changed_bits_and_precision() {
        let float = |precision| {
            Expr::apply(
                Operation::FloatAdd(precision),
                vec![Expr::reg(7, 64), Expr::reg(6, 64)],
            )
        };
        for (source, consumer, mask) in [
            (Precision::Single, Precision::Single, 0x7fff_ffff),
            (Precision::Single, Precision::Single, 0xffff_fffe),
            (Precision::Double, Precision::Single, 0xffff_ffff),
            (Precision::Double, Precision::Single, u64::MAX),
            (Precision::Single, Precision::Double, u64::MAX),
            (Precision::Double, Precision::Double, 0xffff_ffff),
        ] {
            let value = Expr::bin(BinOp::And, float(source), Expr::Const(mask));
            assert!(super::unmasked_float(&value, consumer).is_none());
        }
        let variable_mask = Expr::bin(BinOp::And, float(Precision::Single), Expr::reg(2, 64));
        assert!(super::unmasked_float(&variable_mask, Precision::Single).is_none());
        let integer = Expr::bin(
            BinOp::And,
            Expr::apply(
                Operation::FloatToInt {
                    signed: false,
                    bits: 32,
                    from: Precision::Single,
                    rounding: crate::ir::Rounding::TowardZero,
                    saturating: false,
                },
                vec![Expr::reg(7, 64)],
            ),
            Expr::Const(0xffff_ffff),
        );
        assert!(super::unmasked_float(&integer, Precision::Single).is_none());
    }

    #[test]
    fn float_global_reads_use_float_views_for_scalar_and_indexed_addresses() {
        for (precision, ty, one) in [
            (Precision::Single, "float", u64::from(1.0f32.to_bits())),
            (Precision::Double, "double", 1.0f64.to_bits()),
        ] {
            let width = precision.bits() / 8;
            let scaled =
                |index, factor| Expr::bin(BinOp::Mul, Expr::reg(index, 64), Expr::Const(factor));
            for addr in [
                Expr::Const(0x1000),
                Expr::bin(BinOp::Add, Expr::Const(0x1000), scaled(7, u64::from(width))),
                Expr::bin(
                    BinOp::Add,
                    Expr::bin(BinOp::Add, Expr::Const(0x1000), scaled(7, u64::from(width))),
                    scaled(6, u64::from(width) * 2),
                ),
            ] {
                let value = Expr::Apply {
                    op: Operation::FloatAdd(precision),
                    args: vec![
                        Expr::Load {
                            addr: Box::new(addr),
                            width,
                            signed: false,
                        },
                        Expr::Const(one),
                    ],
                };
                let text = global_returned(
                    value,
                    CType::Named(ty.to_owned()),
                    &[CType::U64, CType::U64],
                );
                assert!(text.contains(&format!("{ty} *const counter")), "{text}");
                assert!(
                    !text.contains(&format!("uint{}_t *const counter", width * 8)),
                    "{text}"
                );
                assert!(
                    text.contains("counter[") || text.contains("*counter +"),
                    "{text}"
                );
            }
        }
    }

    #[test]
    fn named_data_address_values_keep_the_address_and_arithmetic_immediates_stay_numeric() {
        let address = global_returned(Expr::Const(0x1000), CType::U64, &[]);
        assert!(address.contains("uint8_t *const counter"), "{address}");
        assert!(address.contains("return (uintptr_t)counter;"), "{address}");
        assert!(!address.contains("void counter(void);"), "{address}");

        let arithmetic = global_returned(
            Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(0x1000)),
            CType::U64,
            &[CType::U64],
        );
        assert!(arithmetic.contains("return a0 + 0x1000;"), "{arithmetic}");
        assert!(!arithmetic.contains("counter"), "{arithmetic}");
    }

    #[test]
    fn global_indices_take_pointer_values_as_integer_addresses() {
        let scaled =
            |index, factor| Expr::bin(BinOp::Mul, Expr::reg(index, 64), Expr::Const(factor));
        for (addr, width, expected) in [
            (
                Expr::bin(BinOp::Add, Expr::Const(0x1000), Expr::reg(7, 64)),
                1,
                "counter[(uintptr_t)a0]",
            ),
            (
                Expr::bin(BinOp::Add, Expr::Const(0x1000), scaled(7, 4)),
                4,
                "counter[(uintptr_t)a0]",
            ),
            (
                Expr::bin(
                    BinOp::Add,
                    Expr::bin(BinOp::Add, Expr::Const(0x1000), scaled(7, 4)),
                    scaled(6, 8),
                ),
                4,
                "counter[(uintptr_t)a0 + (uintptr_t)a1 * 0x2]",
            ),
        ] {
            let value = Expr::Load {
                addr: Box::new(addr),
                width,
                signed: false,
            };
            let text = global_returned(value, CType::U64, &[pointer(), pointer()]);
            assert!(text.contains(expected), "{expected:?} in {text}");
        }
    }

    #[test]
    fn flat_global_indices_keep_wide_products_and_sums_of_narrow_parameters() {
        let scaled =
            |index, factor| Expr::bin(BinOp::Mul, Expr::reg(index, 32), Expr::Const(factor));
        for addr in [
            Expr::bin(
                BinOp::Add,
                Expr::bin(BinOp::Add, Expr::Const(0x1000), scaled(7, 8)),
                scaled(6, 4),
            ),
            Expr::bin(
                BinOp::Add,
                Expr::bin(
                    BinOp::Add,
                    Expr::bin(BinOp::Add, Expr::Const(0x1000), scaled(7, 4)),
                    scaled(6, 4),
                ),
                scaled(2, 4),
            ),
        ] {
            let value = Expr::Load {
                addr: Box::new(addr),
                width: 4,
                signed: false,
            };
            let text = global_returned(value, CType::U64, &[CType::U32, CType::U32, CType::U32]);
            assert!(text.contains("counter["), "{text}");
            assert!(text.contains("(uint64_t)a0"), "{text}");
        }
    }

    #[test]
    fn address_sums_and_differences_compute_on_unsigned_machine_addresses() {
        for (op, lhs, rhs, expected) in [
            (
                BinOp::Add,
                Expr::reg(7, 64),
                Expr::reg(6, 64),
                "return (uintptr_t)a0 + (uintptr_t)a1;",
            ),
            (
                BinOp::Sub,
                Expr::reg(7, 64),
                Expr::reg(6, 64),
                "return (uintptr_t)a0 - (uintptr_t)a1;",
            ),
            (
                BinOp::Sub,
                Expr::Const(0x1000),
                Expr::reg(7, 64),
                "return 0x1000 - (uintptr_t)a0;",
            ),
        ] {
            let text = returned(Expr::bin(op, lhs, rhs), &[pointer(), pointer()]);
            assert!(text.contains(expected), "{expected:?} in {text}");
        }
    }

    #[test]
    fn offsets_preserve_pointer_arithmetic_in_bytes() {
        for (op, lhs, rhs, expected) in [
            (
                BinOp::Add,
                Expr::reg(7, 64),
                Expr::Const(4),
                "return (uintptr_t)(a0 + 0x1);",
            ),
            (
                BinOp::Sub,
                Expr::reg(7, 64),
                Expr::Const(4),
                "return (uintptr_t)(a0 - 0x1);",
            ),
            (
                BinOp::Add,
                Expr::Const(4),
                Expr::reg(7, 64),
                "return (uintptr_t)(a0 + 0x1);",
            ),
            (
                BinOp::Add,
                Expr::reg(7, 64),
                Expr::Const(1),
                "return (uintptr_t)((uint8_t *)a0 + 0x1);",
            ),
        ] {
            let text = returned(Expr::bin(op, lhs, rhs), &[pointer()]);
            assert!(text.contains(expected), "{expected:?} in {text}");
        }
    }

    #[test]
    fn a_pointer_selected_with_a_nonzero_integer_has_integer_arms() {
        for (value, expected) in [
            (
                choice(Expr::reg(7, 64), Expr::Const(1)),
                "return (a1 != 0x0 ? (uintptr_t)a0 : 0x1);",
            ),
            (
                choice(Expr::Const(1), Expr::reg(7, 64)),
                "return (a1 != 0x0 ? 0x1 : (uintptr_t)a0);",
            ),
            (
                choice(Expr::reg(7, 64), Expr::Const(0)),
                "return (uintptr_t)(a1 != 0x0 ? a0 : 0x0);",
            ),
        ] {
            let text = returned(value, &[pointer(), CType::U64]);
            assert!(text.contains(expected), "{expected:?} in {text}");
        }
    }

    #[test]
    fn integer_operations_read_pointers_as_addresses() {
        for (value, expected) in [
            (
                Expr::bin(BinOp::Sub, Expr::Const(0), Expr::reg(7, 64)),
                "return -(uintptr_t)a0;",
            ),
            (
                Expr::bin(BinOp::And, Expr::reg(7, 64), Expr::Const(7)),
                "return (uintptr_t)a0 & 0x7;",
            ),
            (
                Expr::bin(BinOp::Shl, Expr::Const(1), Expr::reg(7, 64)),
                "<< ((uintptr_t)a0 & 0x3f);",
            ),
            (
                Expr::Apply {
                    op: Operation::PopCount(64),
                    args: vec![Expr::reg(7, 64)],
                },
                "__builtin_popcountll((uintptr_t)a0)",
            ),
            (
                Expr::Apply {
                    op: Operation::IntToFloat {
                        signed: false,
                        bits: 64,
                        to: Precision::Double,
                    },
                    args: vec![Expr::reg(7, 64)],
                },
                "(double)(uintptr_t)a0",
            ),
        ] {
            let text = returned(value, &[pointer()]);
            assert!(text.contains(expected), "{expected:?} in {text}");
        }
    }

    #[test]
    fn a_narrow_pointer_register_read_stays_integer_during_arithmetic() {
        let text = returned(
            Expr::bin(BinOp::Add, Expr::reg(7, 32), Expr::Const(1)),
            &[pointer()],
        );
        assert!(text.contains("(uint32_t)(uintptr_t)a0"), "{text}");
        assert!(!text.contains("(uint8_t *)a0"), "{text}");
    }

    #[test]
    fn a_whole_pointer_local_load_is_an_address_but_a_partial_load_is_integer() {
        let slot = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const((-8i64) as u64));
        let loaded = |width| Expr::Load {
            addr: Box::new(slot.clone()),
            width,
            signed: false,
        };
        let setup = || {
            vec![
                Stmt::Store {
                    addr: slot.clone(),
                    value: Expr::reg(7, 64),
                    width: 8,
                },
                Stmt::Store {
                    addr: slot.clone(),
                    value: Expr::bin(BinOp::Add, loaded(8), Expr::Const(4)),
                    width: 8,
                },
                Stmt::Store {
                    addr: loaded(8),
                    value: Expr::Const(1),
                    width: 1,
                },
            ]
        };
        let mut stmts = setup();
        stmts.push(Stmt::Ret {
            value: Expr::bin(BinOp::And, loaded(8), Expr::Const(7)),
        });
        let text = rendered(stmts, &[CType::pointer_to(CType::int(1, false))]);
        assert!(text.contains("uint8_t *local_0;"), "{text}");
        assert!(text.contains("return (uintptr_t)local_0 & 0x7;"), "{text}");
        let mut stmts = setup();
        stmts.push(Stmt::Ret { value: loaded(4) });
        let text = rendered(stmts, &[CType::pointer_to(CType::int(1, false))]);
        assert!(text.contains("return *(uint32_t *)&local_0;"), "{text}");
    }

    #[test]
    fn shift_counts_wrap_at_sixty_four_and_bounded_counts_keep_their_mask() {
        for op in [BinOp::Shl, BinOp::Shr] {
            let identity = returned(
                Expr::bin(op, Expr::reg(7, 64), Expr::Const(64)),
                &[CType::U64],
            );
            assert!(identity.contains("return a0;"), "{identity}");
            let variable = returned(
                Expr::bin(op, Expr::reg(7, 64), Expr::reg(6, 64)),
                &[CType::U64, CType::U64],
            );
            assert!(variable.contains("(a1 & 0x3f)"), "{variable}");
            let bounded = returned(
                Expr::bin(
                    op,
                    Expr::reg(7, 64),
                    Expr::bin(BinOp::And, Expr::reg(6, 64), Expr::Const(31)),
                ),
                &[CType::U64, CType::U64],
            );
            assert!(bounded.contains("(a1 & 0x1f)"), "{bounded}");
            assert!(!bounded.contains("0x3f"), "{bounded}");
        }
    }

    #[test]
    fn wide_right_shift_counts_widen_narrow_c_operands() {
        let logical = returned(
            Expr::bin(BinOp::Shr, Expr::reg(7, 32), Expr::Const(40)),
            &[CType::U32],
        );
        assert!(
            logical.contains("return (uint64_t)a0 >> 0x28;"),
            "{logical}"
        );
        let arithmetic = returned(
            Expr::bin(BinOp::Sar, Expr::reg(7, 32), Expr::Const(40)),
            &[CType::U32],
        );
        assert!(
            arithmetic.contains("(int64_t)(int32_t)a0 >> 0x28"),
            "{arithmetic}"
        );
        assert!(arithmetic.contains("return (uint32_t)"), "{arithmetic}");
    }

    #[test]
    fn left_shifts_avoid_negative_and_overflowing_signed_c_operands() {
        let signed = returned(
            Expr::bin(BinOp::Shl, Expr::reg(7, 64), Expr::Const(1)),
            &[CType::I64],
        );
        assert!(signed.contains("return (uint64_t)a0 << 0x1;"), "{signed}");
        let mut ir = function(
            vec![Stmt::Ret {
                value: Expr::bin(BinOp::Shl, Expr::reg(7, 8), Expr::Const(24)),
            }],
            &[CType::int(1, false)],
        );
        ir.ret_type = CType::U32;
        let promoted = crate::render::render(&ir, &[], &crate::render::Symbols::default(), &[]);
        assert!(
            promoted.contains("return (uint64_t)a0 << 0x18;"),
            "{promoted}"
        );
    }

    #[test]
    fn left_shifts_only_keep_source_truncation_that_the_reader_observes() {
        let value = Expr::bin(BinOp::Shl, Expr::reg(7, 32), Expr::Const(1));
        let mut ir = function(vec![Stmt::Ret { value }], &[CType::U64]);
        ir.ret_type = CType::U32;
        let narrow = crate::render::render(&ir, &[], &crate::render::Symbols::default(), &[]);
        assert!(narrow.contains("return a0 << 0x1;"), "{narrow}");
        ir.ret_type = CType::U64;
        let wide = crate::render::render(&ir, &[], &crate::render::Symbols::default(), &[]);
        assert!(wide.contains("(uint32_t)a0"), "{wide}");
        assert!(!wide.contains("return a0 <<"), "{wide}");
    }

    #[test]
    fn masked_wrapping_right_shifts_keep_their_result_mask() {
        for count in [64, 65] {
            let value = Expr::bin(
                BinOp::And,
                Expr::bin(BinOp::Shr, Expr::reg(7, 64), Expr::Const(count)),
                Expr::Const(255),
            );
            let text = returned(value, &[CType::U64]);
            assert!(text.contains("& 0xff"), "{text}");
            assert!(!text.contains("0x40"), "{text}");
            assert!(!text.contains("0x41"), "{text}");
        }
    }
}

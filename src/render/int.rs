//! What C makes of printed integer expressions: the type the text has after
//! the integer promotions, and how far its value agrees with the IR's. The
//! IR computes on 64-bit values; C computes at the type of its operands,
//! extends a narrower value as its type says, and wraps at its width. The
//! printer compares the two to decide where a cast or a mask is needed.

use std::cmp::Ordering;
use std::collections::HashMap;

use crate::ir::{BinOp, Expr, FunctionIr, Operation, Stmt};
use crate::render::expr::{Ctx, type_of};

/// The agreement of a value equal to the IR's in every bit.
pub(crate) const ALL: u32 = 128;

/// An integer type as C computes with it: never narrower than `int`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Int {
    pub(crate) bits: u32,
    pub(crate) signed: bool,
}

impl Int {
    pub(crate) const INT: Int = Int {
        bits: 32,
        signed: true,
    };
    pub(crate) const U32: Int = Int {
        bits: 32,
        signed: false,
    };
    pub(crate) const U64: Int = Int {
        bits: 64,
        signed: false,
    };

    /// The type a value of a `bits`-bit type has after the integer promotions.
    pub(crate) fn promoted(bits: u32, signed: bool) -> Int {
        if bits < 32 {
            Int::INT
        } else {
            Int {
                bits: bits.min(64),
                signed,
            }
        }
    }

    /// The type C converts the operands of an arithmetic operator to.
    pub(crate) fn common(self, other: Int) -> Int {
        match self.bits.cmp(&other.bits) {
            Ordering::Greater => self,
            Ordering::Less => other,
            Ordering::Equal => Int {
                bits: self.bits,
                signed: self.signed && other.signed,
            },
        }
    }

    /// The type of a hexadecimal literal.
    pub(crate) fn literal(value: u64) -> Int {
        match value {
            0..=0x7fff_ffff => Int::INT,
            0x8000_0000..=0xffff_ffff => Int::U32,
            0x1_0000_0000..=0x7fff_ffff_ffff_ffff => Int {
                bits: 64,
                signed: true,
            },
            _ => Int::U64,
        }
    }
}

/// An expression printed as C.
#[derive(Clone, Debug)]
pub(crate) struct Printed {
    pub(crate) text: String,
    pub(crate) kind: ValueKind,
    /// The type of the text after the integer promotions.
    pub(crate) ty: Int,
    /// How many low bits of the printed value agree with the IR's value
    /// when both are extended without bound, the printed one as its type
    /// extends and the IR's with zeros; `ALL` when they are equal.
    pub(crate) exact: u32,
    /// How tightly the text binds, as the printer's precedence counts.
    pub(crate) strength: u8,
    /// What the printed value is known to fit in beyond its type.
    pub(crate) range: Range,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ValueKind {
    Integer,
    Pointer,
    Opaque,
}

/// The values a printed expression can take, as the bits they fit in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Range {
    Any,
    /// From zero below `2^n`.
    Unsigned(u32),
    /// From `-2^(n-1)` below `2^(n-1)`.
    Signed(u32),
}

impl Printed {
    pub(crate) fn new(text: String, ty: Int, exact: u32, strength: u8) -> Printed {
        Printed {
            text,
            kind: ValueKind::Integer,
            ty,
            exact,
            strength,
            range: Range::Any,
        }
    }

    pub(crate) fn ranging(self, range: Range) -> Printed {
        Printed { range, ..self }
    }

    /// The fewest bits the value fits in without a sign, ALL when unknown.
    pub(crate) fn unsigned_bits(&self) -> u32 {
        let own = match self.range {
            Range::Unsigned(bits) => bits,
            _ => ALL,
        };
        if self.ty.signed {
            own
        } else {
            own.min(self.ty.bits)
        }
    }

    /// The fewest bits the value fits in with a sign, ALL when unknown.
    pub(crate) fn signed_bits(&self) -> u32 {
        let own = match self.range {
            Range::Signed(bits) => bits,
            Range::Unsigned(bits) => bits + 1,
            Range::Any => ALL,
        };
        if self.ty.signed {
            own.min(self.ty.bits)
        } else {
            own
        }
    }

    /// Text whose scalar type the printer does not follow, such as a float.
    pub(crate) fn opaque(text: String, strength: u8) -> Printed {
        Printed {
            kind: ValueKind::Opaque,
            ..Printed::new(text, Int::U64, ALL, strength)
        }
    }

    pub(crate) fn pointer(text: String, strength: u8) -> Printed {
        Printed {
            kind: ValueKind::Pointer,
            ..Printed::new(text, Int::U64, ALL, strength)
        }
    }

    pub(crate) fn is_pointer(&self) -> bool {
        self.kind == ValueKind::Pointer
    }

    /// A pointer used as machine bits, without C's element scaling or
    /// pointer subtraction restrictions.
    pub(crate) fn address_integer(self) -> Printed {
        if self.is_pointer() {
            Printed::new(
                format!("(uintptr_t){}", self.within(12, false).text),
                Int::U64,
                ALL,
                12,
            )
        } else {
            self
        }
    }

    /// The text as an operand of an operator binding with `parent`,
    /// parenthesized when it binds more loosely; `right` marks the right
    /// operand.
    pub(crate) fn within(&self, parent: u8, right: bool) -> Printed {
        let binds = (self.strength > parent || (self.strength == parent && !right))
            && !(parent == 9 && self.strength == 10)
            && !(matches!(parent, 4..=6) && matches!(self.strength, 7 | 8));
        if binds || self.strength >= 12 {
            self.clone()
        } else {
            Printed {
                text: format!("({})", self.text),
                strength: 13,
                ..self.clone()
            }
        }
    }

    /// The value cast to the `bits`-bit type of the given sign, which then
    /// agrees with the IR's in `exact` bits.
    pub(crate) fn cast(self, bits: u32, signed: bool, exact: u32) -> Printed {
        if self.kind == ValueKind::Integer
            && self.ty == Int::promoted(bits, signed)
            && (bits >= 32
                || if signed {
                    self.signed_bits() <= bits
                } else {
                    self.unsigned_bits() <= bits
                })
        {
            return Printed { exact, ..self };
        }
        Printed::new(
            format!(
                "({}){}",
                type_of((bits / 8) as u8, signed),
                self.within(12, false).text
            ),
            Int::promoted(bits, signed),
            exact,
            12,
        )
        .ranging(if signed {
            Range::Signed(bits)
        } else {
            Range::Unsigned(bits)
        })
    }
}

/// How many low bits of `printed` still agree once C converts it to `to`.
pub(crate) fn converted(printed: &Printed, to: Int) -> u32 {
    let (from, exact) = (printed.ty, printed.exact);
    let kept = if to.bits < from.bits {
        exact.min(to.bits)
    } else if to.signed == from.signed
        || (from.signed && exact == ALL)
        || (to.bits > from.bits && to.signed)
    {
        exact
    } else {
        exact.min(to.bits)
    };
    // An unsigned 64-bit value right in all its bits is the IR's value.
    if kept >= 64 && to == Int::U64 {
        ALL
    } else {
        kept
    }
}

/// The agreement of a result C computes modulo the width of `ty` from
/// operands that agree in `exact` bits.
pub(crate) fn wrapped(exact: u32, ty: Int) -> u32 {
    let kept = exact.min(ty.bits);
    if kept >= 64 && !ty.signed { ALL } else { kept }
}

/// The number of bits the IR's value of `expr` fits in.
pub(crate) fn zero_bits(expr: &Expr, ctx: &Ctx<'_>) -> u32 {
    zero_bits_in(expr, &ctx.value_bits)
}

/// The bits each variable's values fit in, from what is assigned to it:
/// the least such widths that hold for every assignment.
pub(crate) fn value_bits(ir: &FunctionIr) -> HashMap<u16, u32> {
    let variable = |index: u16| (crate::ir::TEMP_BASE..crate::ir::VALUE_BASE).contains(&index);
    let mut known: HashMap<u16, u32> = HashMap::new();
    let mut assigned = Vec::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        match stmt {
            Stmt::Assign { dest, value } if variable(dest.index) => {
                known.entry(dest.index).or_insert(0);
                assigned.push((dest.index, value));
            }
            Stmt::Call { .. } => {
                for output in stmt.call_outputs() {
                    let bits = known.entry(output.dest.index).or_insert(0);
                    *bits = (*bits).max(u32::from(output.dest.width));
                }
            }
            _ => {}
        }
    }
    // Each round widens what an assignment shows to be wider, until none
    // does. A value that keeps growing, as a counter does a bit a round,
    // grows to the next width of an integer type at once.
    let mut grown: HashMap<u16, u32> = HashMap::new();
    for _ in 0..=64 {
        let mut changed = false;
        for (index, value) in &assigned {
            let mut bits = zero_bits_in(value, &known).min(range_bits(value, &known));
            let entry = known.entry(*index).or_insert(0);
            if bits > *entry {
                let times = grown.entry(*index).or_insert(0);
                *times += 1;
                if *times > 2 {
                    bits = [8, 16, 32, 64]
                        .into_iter()
                        .find(|width| *width >= bits)
                        .unwrap_or(64);
                }
                *entry = bits;
                changed = true;
            }
        }
        if !changed {
            return known;
        }
    }
    known.values_mut().for_each(|bits| *bits = 64);
    known
}

/// The bits the value of `expr` fits in as the value ranges bound it, each
/// register within the bits `known` gives it.
fn range_bits(expr: &Expr, known: &HashMap<u16, u32>) -> u32 {
    let read = |index: u16, width: u32| {
        Some(crate::ssa::ranges::Fact::width(
            width.min(known.get(&index).copied().unwrap_or(64)),
        ))
    };
    crate::ssa::ranges::expression(expr, &read).map_or(64, |fact| 64 - fact.hi.leading_zeros())
}

pub(super) fn zero_bits_in(expr: &Expr, known: &HashMap<u16, u32>) -> u32 {
    let bits = |expr| zero_bits_in(expr, known);
    match expr {
        Expr::Reg { index, width } => {
            u32::from(*width).min(known.get(index).copied().unwrap_or(64))
        }
        Expr::Const(value) => 64 - value.leading_zeros(),
        Expr::Load { width, signed, .. } => {
            if *signed {
                64
            } else {
                u32::from(*width) * 8
            }
        }
        Expr::SignExtend { .. } => 64,
        Expr::Bin { op, lhs, rhs } => match op {
            BinOp::And => bits(lhs).min(bits(rhs)),
            BinOp::Or | BinOp::Xor => bits(lhs).max(bits(rhs)),
            BinOp::Add => (bits(lhs).max(bits(rhs)) + 1).min(64),
            BinOp::Mul => (bits(lhs) + bits(rhs)).min(64),
            BinOp::Shl => match rhs.as_ref() {
                Expr::Const(amount) => (bits(lhs) + (amount & 63) as u32).min(64),
                _ => 64,
            },
            BinOp::Shr => match rhs.as_ref() {
                Expr::Const(amount) => bits(lhs).saturating_sub((amount & 63) as u32),
                _ => bits(lhs),
            },
            BinOp::DivU => bits(lhs),
            BinOp::ModU => bits(lhs).min(bits(rhs)),
            // The IR keeps the signed result to the operands' width.
            BinOp::Sar | BinOp::DivS | BinOp::ModS => crate::ir::semantics::operand_width(lhs, rhs),
            BinOp::Sub | BinOp::MulHigh | BinOp::MulHighS => 64,
        },
        Expr::Select { then, els, .. } => bits(then).max(bits(els)),
        Expr::Apply { op, .. } => match op {
            Operation::CountLeadingZeros(_)
            | Operation::CountTrailingZeros(_)
            | Operation::PopCount(_)
            | Operation::ReverseBits(_)
            | Operation::Crc32 { .. } => crate::ir::semantics::width(expr),
            _ => 64,
        },
    }
}

/// The width the IR's value of `expr` is sign-extended from, when it is.
pub(crate) fn sign_bits(expr: &Expr) -> Option<u32> {
    match expr {
        Expr::SignExtend { width, .. }
        | Expr::Load {
            width,
            signed: true,
            ..
        } => Some(u32::from(*width) * 8),
        _ => None,
    }
}

/// Makes `printed` agree with the IR's value of `expr` in `bits` bits where
/// a cast can: one to an unsigned type the value fits in, or to the signed
/// type it is extended from. A value that needs a wider operation is the
/// operation's to widen.
pub(crate) fn fit(mut printed: Printed, expr: &Expr, bits: u32, ctx: &Ctx<'_>) -> Printed {
    if printed.kind != ValueKind::Integer {
        return printed;
    }
    let zero = zero_bits(expr, ctx);
    // A value right in all the bits of its type is the IR's value when that
    // fits in fewer bits, or in as many without a sign.
    if printed.exact >= printed.ty.bits
        && (zero < printed.ty.bits || (zero == printed.ty.bits && !printed.ty.signed))
    {
        printed.exact = ALL;
    }
    if printed.exact >= bits {
        return printed;
    }
    if let Some(width) = [8, 16, 32, 64].into_iter().find(|width| *width >= zero)
        && width <= printed.exact
    {
        return printed.cast(width, false, ALL);
    }
    if bits <= 64
        && let Some(width) = sign_bits(expr)
        && width <= printed.exact
    {
        return printed.cast(width, true, 64);
    }
    printed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shift_widths_use_wrapped_counts() {
        let known = HashMap::from([(7, 8)]);
        for (amount, left, right) in [(63, 64, 0), (64, 8, 8), (65, 9, 7), (128, 8, 8)] {
            for (op, expected) in [(BinOp::Shl, left), (BinOp::Shr, right)] {
                let value = Expr::bin(op, Expr::reg(7, 64), Expr::Const(amount));
                assert_eq!(zero_bits_in(&value, &known), expected, "{op:?} {amount}");
            }
        }
    }

    #[test]
    fn shift_width_bounds_cover_evaluated_results() {
        for width in [8, 16, 32, 64] {
            let known = HashMap::from([(7, width)]);
            let source_mask = crate::ir::semantics::mask(width);
            for amount in [0, 1, 31, 32, 40, 63, 64, 65, 127, 128, u64::MAX] {
                for op in [BinOp::Shl, BinOp::Shr] {
                    let expr = Expr::bin(op, Expr::reg(7, 64), Expr::Const(amount));
                    let bound = zero_bits_in(&expr, &known);
                    for value in [0, 1, 1u64 << (width - 1), source_mask] {
                        let result = crate::ir::semantics::evaluate(&expr, &|index| {
                            (index == 7).then_some(value)
                        })
                        .expect("a register expression");
                        assert!(
                            64 - result.leading_zeros() <= bound,
                            "{width}-bit {value:x} {op:?} {amount}: {result:x} exceeds {bound} bits"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn address_conversion_only_changes_pointer_values() {
        let pointer = Printed::pointer("p + 0x1".to_owned(), 10).address_integer();
        assert_eq!(pointer.kind, ValueKind::Integer);
        assert_eq!(pointer.text, "(uintptr_t)(p + 0x1)");
        assert_eq!(pointer.ty, Int::U64);
        assert_eq!(pointer.exact, ALL);
        let opaque = Printed::opaque("sqrt(x)".to_owned(), 13).address_integer();
        assert_eq!(opaque.kind, ValueKind::Opaque);
        assert_eq!(opaque.text, "sqrt(x)");
    }

    fn printed(ty: Int, exact: u32) -> Printed {
        Printed::new("x".to_owned(), ty, exact, 13)
    }

    #[test]
    fn literals_take_the_first_type_that_holds_them() {
        assert_eq!(Int::literal(0x7fff_ffff), Int::INT);
        assert_eq!(Int::literal(0xffff_ffff), Int::U32);
        assert_eq!(Int::literal(1 << 32).bits, 64);
        assert_eq!(Int::literal(u64::MAX), Int::U64);
    }

    #[test]
    fn the_common_type_is_the_wider_or_the_unsigned_one() {
        let i64 = Int {
            bits: 64,
            signed: true,
        };
        assert_eq!(Int::INT.common(Int::U32), Int::U32);
        assert_eq!(i64.common(Int::U32), i64);
        assert_eq!(Int::INT.common(Int::U64), Int::U64);
    }

    #[test]
    fn converting_a_signed_value_to_a_wider_unsigned_type_keeps_its_own_bits() {
        // A signed int that agrees in 64 bits extends with its sign, which
        // a wider unsigned type keeps for 64 bits.
        assert_eq!(converted(&printed(Int::INT, 64), Int::U64), ALL);
        assert_eq!(converted(&printed(Int::INT, 32), Int::U64), 32);
        // A value equal to the IR's is not negative.
        assert_eq!(converted(&printed(Int::INT, ALL), Int::U32), ALL);
        // An unsigned int read as signed loses what is above its sign.
        assert_eq!(converted(&printed(Int::U32, ALL), Int::INT), 32);
    }

    #[test]
    fn a_result_wraps_at_its_type() {
        assert_eq!(wrapped(ALL, Int::U32), 32);
        assert_eq!(wrapped(64, Int::U64), ALL);
        assert_eq!(
            wrapped(
                ALL,
                Int {
                    bits: 64,
                    signed: true
                }
            ),
            64
        );
    }

    #[test]
    fn a_variable_fits_in_the_bits_its_values_range_over() {
        use crate::ir::{RegRef, VARIABLE_BASE};
        // v1 = load16(a0) / 0x100 is at most 0xff, which the bits of a
        // division alone would put at 16 bits.
        let ir = FunctionIr::single_block(
            crate::loader::Isa::X86_64,
            vec![Stmt::Assign {
                dest: RegRef {
                    index: VARIABLE_BASE,
                    width: 64,
                },
                value: Expr::bin(
                    BinOp::DivU,
                    Expr::Load {
                        addr: Box::new(Expr::reg(7, 64)),
                        width: 2,
                        signed: false,
                    },
                    Expr::Const(0x100),
                ),
            }],
        );
        assert_eq!(value_bits(&ir).get(&VARIABLE_BASE), Some(&8));
    }
}

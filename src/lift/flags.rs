//! The condition flags as the instruction that last set them leaves them,
//! and each condition as a test on that instruction's values.
//!
//! A subtraction's flags are what a comparison of its operands decides,
//! but a sum's carry and overflow, and the carry a logical operation
//! clears, are not; each condition is turned into the comparison that
//! decides it exactly, preferring one that reads as the source would.

use crate::ir::semantics::{mask, operand_width};
use crate::ir::{BinOp, Cond, Expr, Operation, Precision, Stmt};
use crate::loader::Isa;

/// The operation whose result set the flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Source {
    /// `lhs - rhs`, as a compare or a subtraction sets them.
    Difference,
    /// `lhs + rhs`.
    Sum,
    /// An x86 sum or difference including the incoming carry or borrow.
    WithCarry { subtract: bool },
    /// A logical result `lhs`, with carry and overflow cleared.
    Logic,
    /// Only zero and sign follow the result `lhs`; carry and overflow mean
    /// something else (an x86 shift by its width or more, `bsf`).
    Result,
    /// Only the zero flag, as a bit in `lhs`.
    Zero,
    /// An x86 shift's result `lhs`, with the carry the bit `rhs` it shifted
    /// out last; overflow is unknown.
    Shift,
    /// Set to the given N, Z, C and V bits, from high to low (AArch64).
    Fixed(u8),
    /// Only the carry is known, equal to the bit `lhs` (x86 `bt`).
    Carry,
    /// Only the carry and the overflow are known, both set when `lhs` is
    /// nonzero (an x86 multiply whose product did not fit).
    CarryOverflow,
    /// A floating-point comparison of `lhs` with `rhs`: x86 `ucomisd`,
    /// AArch64 `fcmp`.
    FloatCompare(Precision),
    /// Loaded from the byte `lhs` as x86 `sahf` loads them: sign from bit
    /// 7, zero 6, adjust 4, parity 2 and carry 0. Overflow, which the byte
    /// does not hold, is one or zero in `rhs` when known.
    Stored { overflow: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Flags {
    pub source: Source,
    pub lhs: Expr,
    pub rhs: Expr,
    input_carry: Option<Expr>,
    /// False when the instruction left the carry as it was (x86 `inc`, `dec`).
    pub carry: bool,
    /// Whether the x86 parity and adjust flags are clear whatever the
    /// result, as `popcnt` leaves them.
    pub low_cleared: bool,
    /// For a conditional compare, the condition under the earlier flags that
    /// chose this compare; when it fails the flags are `otherwise`.
    pub chosen: Option<Choice>,
    /// The width the operation computed at, when wider than its result reads:
    /// a 64-bit `ands` with `0xff` leaves a result whose sign bit is clear.
    pub width: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Choice {
    pub cond: Cond,
    pub lhs: Expr,
    pub rhs: Expr,
    pub otherwise: u8,
}

/// What a condition is under the flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Test {
    Always,
    Never,
    Compare(Cond, Expr, Expr),
    /// The flags do not decide it.
    Unknown,
}

impl Flags {
    pub fn difference(lhs: Expr, rhs: Expr) -> Self {
        Self::new(Source::Difference, lhs, rhs)
    }

    pub fn sum(lhs: Expr, rhs: Expr) -> Self {
        Self::new(Source::Sum, lhs, rhs)
    }

    pub fn with_carry(lhs: Expr, rhs: Expr, carry: Expr, subtract: bool, bits: u32) -> Self {
        Self {
            input_carry: Some(carry),
            width: Some(bits),
            ..Self::new(Source::WithCarry { subtract }, lhs, rhs)
        }
    }

    pub fn logic(result: Expr) -> Self {
        Self::new(Source::Logic, result, Expr::constant(0))
    }

    /// A logical result of an operation `width` bits wide.
    pub fn logic_at(result: Expr, width: u32) -> Self {
        Self {
            width: Some(width),
            ..Self::logic(result)
        }
    }

    pub fn result(result: Expr) -> Self {
        Self::new(Source::Result, result, Expr::constant(0))
    }

    pub fn zero(bit: Expr) -> Self {
        Self::new(Source::Zero, bit, Expr::constant(0))
    }

    pub fn shift(result: Expr, carry: Expr) -> Self {
        Self::new(Source::Shift, result, carry)
    }

    pub fn float_compare(lhs: Expr, rhs: Expr, precision: Precision) -> Self {
        Self::new(Source::FloatCompare(precision), lhs, rhs)
    }

    /// Whether the x86 parity flag is set (`even`) or clear: set by an even
    /// count of ones in the result's low byte, and after a floating-point
    /// comparison by a NaN.
    pub fn parity(&self, even: bool) -> Test {
        let set = match self.source {
            _ if self.chosen.is_some() => Test::Unknown,
            Source::FloatCompare(precision) => {
                holds(Operation::FloatUnordered(precision), &self.lhs, &self.rhs)
            }
            _ if self.low_cleared => Test::Never,
            Source::Stored { .. } => bit_set(&self.lhs, 2),
            Source::Difference
            | Source::Sum
            | Source::WithCarry { .. }
            | Source::Logic
            | Source::Shift => {
                let low = Expr::bin(BinOp::And, self.value(), Expr::constant(0xff));
                let folded = Expr::bin(
                    BinOp::And,
                    Expr::bin(
                        BinOp::Xor,
                        low.clone(),
                        Expr::bin(BinOp::Shr, low, Expr::constant(4)),
                    ),
                    Expr::constant(0xf),
                );
                // Bit n of 0x9669 is set when n has an even count of ones.
                bit_set(&Expr::bin(BinOp::Shr, Expr::constant(0x9669), folded), 0)
            }
            _ => Test::Unknown,
        };
        if even { set } else { not(set) }
    }

    /// Whether the x86 adjust flag is set: by a carry or borrow out of the
    /// result's low four bits.
    pub fn adjust(&self) -> Test {
        match self.source {
            _ if self.chosen.is_some() => Test::Unknown,
            Source::FloatCompare(_) => Test::Never,
            _ if self.low_cleared => Test::Never,
            Source::Stored { .. } => bit_set(&self.lhs, 4),
            Source::Difference | Source::Sum | Source::WithCarry { .. } => {
                let operands = Expr::bin(BinOp::Xor, self.lhs.clone(), self.rhs.clone());
                bit_set(&Expr::bin(BinOp::Xor, operands, self.value()), 4)
            }
            _ => Test::Unknown,
        }
    }

    /// The value whose low bits set parity and adjust.
    fn value(&self) -> Expr {
        if let Source::WithCarry { subtract } = self.source {
            let op = if subtract { BinOp::Sub } else { BinOp::Add };
            return Expr::bin(
                BinOp::And,
                Expr::bin(
                    op,
                    Expr::bin(op, self.lhs.clone(), self.rhs.clone()),
                    self.input_carry
                        .clone()
                        .expect("carry arithmetic has an input"),
                ),
                Expr::constant(mask(self.width.expect("carry arithmetic has a width"))),
            );
        }
        let op = match self.source {
            Source::Difference => BinOp::Sub,
            Source::Sum => BinOp::Add,
            _ => return self.lhs.clone(),
        };
        Expr::bin(op, self.lhs.clone(), self.rhs.clone())
    }

    /// Flags loaded from `byte` as x86 `sahf` loads them, with the overflow
    /// as one or zero when known.
    pub fn stored(byte: Expr, overflow: Option<Expr>) -> Self {
        let known = overflow.is_some();
        Self::new(
            Source::Stored { overflow: known },
            byte,
            overflow.unwrap_or(Expr::constant(0)),
        )
    }

    /// The same flags with parity and adjust clear.
    pub fn clearing_low(self) -> Self {
        Self {
            low_cleared: true,
            ..self
        }
    }

    pub fn carry(bit: Expr) -> Self {
        Self::new(Source::Carry, bit, Expr::constant(0))
    }

    pub fn carry_overflow(lost: Expr) -> Self {
        Self::new(Source::CarryOverflow, lost, Expr::constant(0))
    }

    pub fn fixed(nzcv: u8) -> Self {
        Self::new(Source::Fixed(nzcv), Expr::constant(0), Expr::constant(0))
    }

    fn new(source: Source, lhs: Expr, rhs: Expr) -> Self {
        Self {
            source,
            lhs,
            rhs,
            input_carry: None,
            carry: true,
            low_cleared: false,
            chosen: None,
            width: None,
        }
    }

    /// These flags when `earlier` holds, and `otherwise` when it does not,
    /// as a conditional compare sets them; None when `earlier` is unknown.
    pub fn chosen_by(self, earlier: Test, otherwise: u8) -> Option<Self> {
        match earlier {
            Test::Always => Some(self),
            Test::Never => Some(Self::fixed(otherwise)),
            Test::Compare(cond, lhs, rhs) => Some(Self {
                chosen: Some(Choice {
                    cond,
                    lhs,
                    rhs,
                    otherwise,
                }),
                ..self
            }),
            Test::Unknown => None,
        }
    }

    /// The same flags with each operand read from a `FLAG_CARRIED` register
    /// of its width, and the operands those registers receive.
    pub fn carried(&self) -> (Flags, Vec<Expr>) {
        let mut template = self.clone();
        let mut values = Vec::new();
        for (slot, operand) in crate::ir::FLAG_CARRIED
            .into_iter()
            .zip(template.operands_mut())
        {
            let width = match crate::ir::semantics::width(operand) {
                0 => 64,
                bits => bits as u8,
            };
            values.push(std::mem::replace(operand, Expr::reg(slot, width)));
        }
        (template, values)
    }

    /// Every expression the flags read, in the order of `FLAG_OPERANDS`.
    pub fn operands_mut(&mut self) -> Vec<&mut Expr> {
        let mut operands = vec![&mut self.lhs, &mut self.rhs];
        if let Some(carry) = &mut self.input_carry {
            operands.push(carry);
        }
        if let Some(choice) = &mut self.chosen {
            operands.push(&mut choice.lhs);
            operands.push(&mut choice.rhs);
        }
        operands
    }

    /// The flags with the carry left unknown.
    pub fn keeping_carry(self) -> Self {
        Self {
            carry: false,
            ..self
        }
    }

    /// `cond` under these flags. Conditions are named as after a compare,
    /// so on x86, whose carry is a borrow, `Cs` is "above or equal".
    pub fn test(&self, cond: Cond, isa: Isa) -> Test {
        let own = self.own_test(cond, isa);
        let Some(choice) = &self.chosen else {
            return own;
        };
        let when = Test::Compare(choice.cond, choice.lhs.clone(), choice.rhs.clone());
        if fixed_holds(cond, choice.otherwise) {
            not(both(when, not(own)))
        } else {
            both(when, own)
        }
    }

    fn own_test(&self, cond: Cond, isa: Isa) -> Test {
        let (a, b) = (&self.lhs, &self.rhs);
        let reads_carry = matches!(cond, Cond::Cs | Cond::Cc | Cond::Hi | Cond::Ls);
        if reads_carry && !self.carry {
            return Test::Unknown;
        }
        let bits = operand_width(a, b);
        let compare = |cond, lhs: &Expr, rhs: &Expr| Test::Compare(cond, lhs.clone(), rhs.clone());
        let zero = Expr::constant(0);
        match self.source {
            Source::Zero => match cond {
                Cond::Eq => compare(Cond::Ne, a, &zero),
                Cond::Ne => compare(Cond::Eq, a, &zero),
                _ => Test::Unknown,
            },
            Source::CarryOverflow => match cond {
                Cond::Cc | Cond::Vs => compare(Cond::Ne, a, &zero),
                Cond::Cs | Cond::Vc => compare(Cond::Eq, a, &zero),
                _ => Test::Unknown,
            },
            Source::Carry => {
                // On x86 "below" asks for a set carry, on AArch64 `hs`.
                let set = if isa == Isa::X86_64 {
                    Cond::Cc
                } else {
                    Cond::Cs
                };
                if cond == set {
                    compare(Cond::Ne, a, &zero)
                } else if cond == set.invert() {
                    compare(Cond::Eq, a, &zero)
                } else {
                    Test::Unknown
                }
            }
            Source::FloatCompare(precision) => float_test(a, b, precision, cond, isa),
            Source::Stored { overflow } => stored_test(a, b, overflow, cond),
            Source::Fixed(nzcv) => {
                if fixed_holds(cond, nzcv) {
                    Test::Always
                } else {
                    Test::Never
                }
            }
            Source::Difference => {
                let difference = || Expr::bin(BinOp::Sub, a.clone(), b.clone());
                // Overflow when the operands differ in sign and the
                // difference differs from the first.
                let overflow = || {
                    Expr::bin(
                        BinOp::And,
                        Expr::bin(BinOp::Xor, a.clone(), b.clone()),
                        Expr::bin(BinOp::Xor, a.clone(), difference()),
                    )
                };
                match (cond, b) {
                    (Cond::Mi, Expr::Const(0)) => compare(Cond::Lt, a, b),
                    (Cond::Pl, Expr::Const(0)) => compare(Cond::Ge, a, b),
                    (Cond::Mi, _) => Test::Compare(Cond::Lt, difference(), zero),
                    (Cond::Pl, _) => Test::Compare(Cond::Ge, difference(), zero),
                    (Cond::Vs, _) => Test::Compare(Cond::Lt, overflow(), zero),
                    (Cond::Vc, _) => Test::Compare(Cond::Ge, overflow(), zero),
                    _ => compare(cond, a, b),
                }
            }
            // The result reads narrower than the operation computed it: its
            // sign bit, that of the operation, is clear.
            Source::Logic
                if self.width.is_some_and(|width| width > bits)
                    && matches!(
                        cond,
                        Cond::Mi | Cond::Pl | Cond::Lt | Cond::Ge | Cond::Gt | Cond::Le
                    ) =>
            {
                match cond {
                    Cond::Mi | Cond::Lt => Test::Never,
                    Cond::Pl | Cond::Ge => Test::Always,
                    Cond::Gt => compare(Cond::Ne, a, &zero),
                    _ => compare(Cond::Eq, a, &zero),
                }
            }
            Source::Logic | Source::Result | Source::Shift => {
                let sign = |cond| match cond {
                    Cond::Mi => Cond::Lt,
                    Cond::Pl => Cond::Ge,
                    other => other,
                };
                match cond {
                    Cond::Eq | Cond::Ne | Cond::Mi | Cond::Pl => compare(sign(cond), a, &zero),
                    // On x86, where "below" asks for a set carry.
                    Cond::Cc if self.source == Source::Shift => compare(Cond::Ne, b, &zero),
                    Cond::Cs if self.source == Source::Shift => compare(Cond::Eq, b, &zero),
                    Cond::Hi | Cond::Ls if self.source == Source::Shift => {
                        let above = both(
                            Test::Compare(Cond::Eq, b.clone(), zero.clone()),
                            Test::Compare(Cond::Ne, a.clone(), zero.clone()),
                        );
                        if cond == Cond::Hi { above } else { not(above) }
                    }
                    _ if self.source != Source::Logic => Test::Unknown,
                    Cond::Vs => Test::Never,
                    Cond::Vc => Test::Always,
                    Cond::Ge | Cond::Lt | Cond::Gt | Cond::Le => compare(cond, a, &zero),
                    // The carry is clear: on AArch64 that fails `hs`; on x86
                    // it passes "above or equal", and "above" asks for nonzero.
                    _ => match (isa, cond) {
                        (Isa::X86_64, Cond::Cs) | (Isa::AArch64, Cond::Cc | Cond::Ls) => {
                            Test::Always
                        }
                        (Isa::X86_64, Cond::Cc) | (Isa::AArch64, Cond::Cs | Cond::Hi) => {
                            Test::Never
                        }
                        (_, Cond::Hi) => compare(Cond::Ne, a, &zero),
                        _ => compare(Cond::Eq, a, &zero),
                    },
                }
            }
            Source::Sum => sum(a, b, bits, cond, isa),
            Source::WithCarry { subtract } => {
                let bits = self.width.expect("carry arithmetic has a width");
                let result = self.value();
                let input = self
                    .input_carry
                    .clone()
                    .expect("carry arithmetic has an input");
                let carry = if subtract {
                    borrow_out(a, b, input)
                } else {
                    carry_out(a, b, input, bits)
                };
                let changed = Expr::bin(BinOp::Xor, a.clone(), result.clone());
                let signs = Expr::bin(BinOp::Xor, a.clone(), b.clone());
                let signs = if subtract {
                    signs
                } else {
                    Expr::bin(BinOp::Xor, signs, Expr::constant(mask(bits)))
                };
                let overflow = Expr::bin(BinOp::And, signs, changed);
                let negative = bit_set(&result, u64::from(bits - 1));
                let overflow_set = bit_set(&overflow, u64::from(bits - 1));
                let signed_less = bit_set(
                    &Expr::bin(BinOp::Xor, result.clone(), overflow),
                    u64::from(bits - 1),
                );
                let carry_set = compare(Cond::Ne, &carry, &zero);
                let zero = compare(Cond::Eq, &result, &zero);
                let above = both(not(carry_set.clone()), not(zero.clone()));
                let greater = both(not(zero.clone()), not(signed_less.clone()));
                match cond {
                    Cond::Eq => zero,
                    Cond::Ne => not(zero),
                    Cond::Cc => carry_set,
                    Cond::Cs => not(carry_set),
                    Cond::Mi => negative,
                    Cond::Pl => not(negative),
                    Cond::Vs => overflow_set,
                    Cond::Vc => not(overflow_set),
                    Cond::Hi => above,
                    Cond::Ls => not(above),
                    Cond::Lt => signed_less,
                    Cond::Ge => not(signed_less),
                    Cond::Gt => greater,
                    Cond::Le => not(greater),
                }
            }
        }
    }
}

/// Whether bit `bit` of `value` is set.
fn bit_set(value: &Expr, bit: u64) -> Test {
    let shifted = match bit {
        0 => value.clone(),
        _ => Expr::bin(BinOp::Shr, value.clone(), Expr::constant(bit)),
    };
    Test::Compare(
        Cond::Ne,
        Expr::bin(BinOp::And, shifted, Expr::constant(1)),
        Expr::constant(0),
    )
}

/// `cond` under x86 flags loaded from `byte`, with the overflow as one or
/// zero in `overflow` when `known`.
fn stored_test(byte: &Expr, overflow: &Expr, known: bool, cond: Cond) -> Test {
    let zero = || Expr::constant(0);
    let sign = || {
        Expr::bin(
            BinOp::And,
            Expr::bin(BinOp::Shr, byte.clone(), Expr::constant(7)),
            Expr::constant(1),
        )
    };
    // Neither carry nor zero: "above".
    let above = Test::Compare(
        Cond::Eq,
        Expr::bin(BinOp::And, byte.clone(), Expr::constant(0x41)),
        zero(),
    );
    let sign_is_overflow = || Test::Compare(Cond::Eq, sign(), overflow.clone());
    let greater = || both(not(bit_set(byte, 6)), sign_is_overflow());
    match cond {
        Cond::Eq => bit_set(byte, 6),
        Cond::Ne => not(bit_set(byte, 6)),
        Cond::Cc => bit_set(byte, 0),
        Cond::Cs => not(bit_set(byte, 0)),
        Cond::Mi => bit_set(byte, 7),
        Cond::Pl => not(bit_set(byte, 7)),
        Cond::Hi => above,
        Cond::Ls => not(above),
        _ if !known => Test::Unknown,
        Cond::Vs => Test::Compare(Cond::Ne, overflow.clone(), zero()),
        Cond::Vc => Test::Compare(Cond::Eq, overflow.clone(), zero()),
        Cond::Ge => sign_is_overflow(),
        Cond::Lt => not(sign_is_overflow()),
        Cond::Gt => greater(),
        Cond::Le => not(greater()),
    }
}

/// The test that a floating-point comparison holds.
fn holds(op: Operation, a: &Expr, b: &Expr) -> Test {
    Test::Compare(
        Cond::Ne,
        Expr::apply(op, vec![a.clone(), b.clone()]),
        Expr::constant(0),
    )
}

/// `cond` after comparing the floats `a` and `b`. On x86 a NaN sets zero,
/// parity and carry, and a smaller `a` the carry, while sign and overflow
/// are clear; on AArch64 a smaller `a` sets N, an equal one Z and C, a
/// larger one C, and a NaN C and V.
fn float_test(a: &Expr, b: &Expr, precision: Precision, cond: Cond, isa: Isa) -> Test {
    let less = |x, y| holds(Operation::FloatLess(precision), x, y);
    let less_equal = |x, y| holds(Operation::FloatLessEqual(precision), x, y);
    let equal = holds(Operation::FloatEqual(precision), a, b);
    let unordered = holds(Operation::FloatUnordered(precision), a, b);
    // Equal, or not comparable.
    let equal_or_unordered = || not(both(not(equal.clone()), not(unordered.clone())));
    match isa {
        Isa::X86_64 => match cond {
            Cond::Eq | Cond::Le => equal_or_unordered(),
            Cond::Ne | Cond::Gt => not(equal_or_unordered()),
            Cond::Cc => not(less_equal(b, a)),
            Cond::Cs => less_equal(b, a),
            Cond::Hi => less(b, a),
            Cond::Ls => not(less(b, a)),
            Cond::Mi | Cond::Vs | Cond::Lt => Test::Never,
            Cond::Pl | Cond::Vc | Cond::Ge => Test::Always,
        },
        _ => match cond {
            Cond::Eq => equal,
            Cond::Ne => not(equal),
            Cond::Cc | Cond::Mi => less(a, b),
            Cond::Cs | Cond::Pl => not(less(a, b)),
            Cond::Vs => unordered,
            Cond::Vc => not(unordered),
            Cond::Hi => not(less_equal(a, b)),
            Cond::Ls => less_equal(a, b),
            Cond::Ge => less_equal(b, a),
            Cond::Lt => not(less_equal(b, a)),
            Cond::Gt => less(b, a),
            Cond::Le => not(less(b, a)),
        },
    }
}

/// `cond` after `a + b` at `bits` wide.
fn sum(a: &Expr, b: &Expr, bits: u32, cond: Cond, isa: Isa) -> Test {
    let all = mask(bits);
    let lowest = 1u64 << (bits - 1);
    let s = Expr::bin(BinOp::Add, a.clone(), b.clone());
    if let Expr::Const(c) = b {
        let c = c & all;
        // Adding zero carries nothing and cannot overflow: AArch64 reads
        // that as a logical result, x86 as a compare with zero.
        if c == 0 {
            let flags = match isa {
                Isa::X86_64 => Flags::difference(a.clone(), Expr::constant(0)),
                _ => Flags::logic(a.clone()),
            };
            return flags.test(cond, isa);
        }
        // `a + c` against zero is `a` against `-c`, which fits unless `c`
        // is the lowest signed value.
        if c != lowest {
            let negated = Expr::constant(c.wrapping_neg() & all);
            let cond = match (isa, cond) {
                (_, Cond::Mi) => return Test::Compare(Cond::Lt, s, Expr::constant(0)),
                (_, Cond::Pl) => return Test::Compare(Cond::Ge, s, Expr::constant(0)),
                (_, Cond::Vs | Cond::Vc) => cond,
                // On x86 the carry of a sum is set when `a >= -c`, which
                // fails "above or equal" and "above".
                (Isa::X86_64, Cond::Cs | Cond::Hi) => Cond::Cc,
                (Isa::X86_64, Cond::Cc | Cond::Ls) => Cond::Cs,
                (_, other) => other,
            };
            if !matches!(cond, Cond::Vs | Cond::Vc) {
                return Test::Compare(cond, a.clone(), negated);
            }
        }
    }
    let zero = || Expr::constant(0);
    let negated = match b {
        Expr::Const(c) => Expr::constant(c.wrapping_neg() & all),
        _ => Expr::bin(BinOp::Sub, zero(), b.clone()),
    };
    let is_zero = Test::Compare(Cond::Eq, a.clone(), negated);
    // A carry out of the sum: `a > ~b`.
    let inverted = Expr::bin(BinOp::Xor, b.clone(), Expr::constant(all));
    let carry = Test::Compare(Cond::Hi, a.clone(), inverted);
    // The flags' carry: set by a carry on AArch64, clear on x86.
    let carry_flag = match isa {
        Isa::X86_64 => not(carry),
        _ => carry,
    };
    // Overflow when both operands differ in sign from the sum.
    let overflow_bits = Expr::bin(
        BinOp::And,
        Expr::bin(BinOp::Xor, a.clone(), s.clone()),
        Expr::bin(BinOp::Xor, b.clone(), s.clone()),
    );
    let overflow = Test::Compare(Cond::Lt, overflow_bits.clone(), zero());
    // Sign equal to overflow: the sum before wrapping is not negative.
    let not_negative = Test::Compare(
        Cond::Ge,
        Expr::bin(BinOp::Xor, s.clone(), overflow_bits),
        zero(),
    );
    match cond {
        Cond::Eq => is_zero,
        Cond::Ne => not(is_zero),
        Cond::Mi => Test::Compare(Cond::Lt, s, zero()),
        Cond::Pl => Test::Compare(Cond::Ge, s, zero()),
        Cond::Vs => overflow,
        Cond::Vc => not(overflow),
        Cond::Cs => carry_flag,
        Cond::Cc => not(carry_flag),
        Cond::Hi => both(carry_flag, not(is_zero)),
        Cond::Ls => not(both(carry_flag, not(is_zero))),
        Cond::Ge => not_negative,
        Cond::Lt => not(not_negative),
        Cond::Gt => both(not(is_zero), not_negative),
        Cond::Le => not(both(not(is_zero), not_negative)),
    }
}

/// One when `a + b + carry` carries out of `bits`, for a carry of one or zero.
pub(super) fn carry_out(a: &Expr, b: &Expr, carry: Expr, bits: u32) -> Expr {
    let inverted = Expr::bin(BinOp::Xor, b.clone(), Expr::constant(mask(bits)));
    let beyond = |cond| truth(Test::Compare(cond, a.clone(), inverted.clone()));
    choose(carry, beyond(Cond::Cs), beyond(Cond::Hi))
}

/// One when `a - b - borrow` borrows, for a borrow of one or zero.
pub(super) fn borrow_out(a: &Expr, b: &Expr, borrow: Expr) -> Expr {
    let below = |cond| truth(Test::Compare(cond, a.clone(), b.clone()));
    choose(borrow, below(Cond::Ls), below(Cond::Cc))
}

/// `then` when `bit` is set and `els` otherwise.
fn choose(bit: Expr, then: Expr, els: Expr) -> Expr {
    Expr::Select {
        cond: Cond::Ne,
        lhs: Box::new(bit),
        rhs: Box::new(Expr::constant(0)),
        then: Box::new(then),
        els: Box::new(els),
    }
}

/// One when the test holds and zero otherwise.
fn truth(test: Test) -> Expr {
    test.select(Expr::constant(1), Expr::constant(0))
        .expect("a decided test")
}

fn not(test: Test) -> Test {
    match test {
        Test::Always => Test::Never,
        Test::Never => Test::Always,
        Test::Compare(cond, lhs, rhs) => Test::Compare(cond.invert(), lhs, rhs),
        Test::Unknown => Test::Unknown,
    }
}

/// Both tests hold, as one comparison of a selected value with zero.
fn both(first: Test, second: Test) -> Test {
    match (first, second) {
        (Test::Never, _) | (_, Test::Never) => Test::Never,
        (Test::Always, other) | (other, Test::Always) => other,
        (Test::Unknown, _) | (_, Test::Unknown) => Test::Unknown,
        (Test::Compare(c1, l1, r1), Test::Compare(c2, l2, r2)) => {
            let inner = Expr::Select {
                cond: c2,
                lhs: Box::new(l2),
                rhs: Box::new(r2),
                then: Box::new(Expr::constant(1)),
                els: Box::new(Expr::constant(0)),
            };
            let outer = Expr::Select {
                cond: c1,
                lhs: Box::new(l1),
                rhs: Box::new(r1),
                then: Box::new(inner),
                els: Box::new(Expr::constant(0)),
            };
            Test::Compare(Cond::Ne, outer, Expr::constant(0))
        }
    }
}

impl Test {
    /// `then` when the test holds and `els` otherwise; None when the flags
    /// do not decide it.
    pub fn select(self, then: Expr, els: Expr) -> Option<Expr> {
        // A test that a truth value is nonzero, choosing one or zero, is
        // that truth value.
        if let (Test::Compare(Cond::Ne, value, Expr::Const(0)), Expr::Const(1), Expr::Const(0)) =
            (&self, &then, &els)
            && is_truth(value)
        {
            return Some(value.clone());
        }
        match self {
            Test::Always => Some(then),
            Test::Never => Some(els),
            Test::Compare(cond, lhs, rhs) => Some(Expr::Select {
                cond,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
                then: Box::new(then),
                els: Box::new(els),
            }),
            Test::Unknown => None,
        }
    }

    pub fn invert(self) -> Test {
        not(self)
    }

    /// A branch to `target` when the test holds; none when it never does,
    /// and one on flags from elsewhere, named by `cond`, when the flags
    /// here do not decide it.
    pub fn branch(self, cond: Cond, target: u64) -> Option<Stmt> {
        match self {
            Test::Always => Some(Stmt::Br {
                target: Some(target),
            }),
            Test::Never => None,
            Test::Compare(cond, lhs, rhs) => Some(Stmt::Brif {
                cond,
                lhs,
                rhs,
                target,
            }),
            Test::Unknown => Some(Stmt::BrifFlags { cond, target }),
        }
    }
}

/// Whether `cond` holds for AArch64 flags N, Z, C, V given as four bits.
fn fixed_holds(cond: Cond, nzcv: u8) -> bool {
    let (n, z, c, v) = (nzcv & 8 != 0, nzcv & 4 != 0, nzcv & 2 != 0, nzcv & 1 != 0);
    match cond {
        Cond::Eq => z,
        Cond::Ne => !z,
        Cond::Cs => c,
        Cond::Cc => !c,
        Cond::Mi => n,
        Cond::Pl => !n,
        Cond::Vs => v,
        Cond::Vc => !v,
        Cond::Hi => c && !z,
        Cond::Ls => !(c && !z),
        Cond::Ge => n == v,
        Cond::Lt => n != v,
        Cond::Gt => !z && n == v,
        Cond::Le => !(!z && n == v),
    }
}

/// Whether `expr` is one or zero: a choice between truth values.
fn is_truth(expr: &Expr) -> bool {
    match expr {
        Expr::Const(0 | 1) => true,
        Expr::Select { then, els, .. } => is_truth(then) && is_truth(els),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{Flags, Test, fixed_holds};
    use crate::ir::eval::hash;
    use crate::ir::semantics::{evaluate, holds, mask, operand_width, sign_extend};
    use crate::ir::{Cond, Expr};
    use crate::loader::Isa;

    const CONDITIONS: [Cond; 14] = [
        Cond::Eq,
        Cond::Ne,
        Cond::Cs,
        Cond::Cc,
        Cond::Mi,
        Cond::Pl,
        Cond::Vs,
        Cond::Vc,
        Cond::Hi,
        Cond::Ls,
        Cond::Ge,
        Cond::Lt,
        Cond::Gt,
        Cond::Le,
    ];

    /// N, Z, C and V as four bits, with C as AArch64 means it: a
    /// difference's "no borrow" and a sum's carry. x86 keeps a borrow and
    /// a carry, which the conditions read inverted.
    fn reference(kind: u8, a: u64, b: u64, bits: u32, isa: Isa) -> u8 {
        let all = mask(bits);
        let (a, b) = (a & all, b & all);
        let (result, carry, overflow) = match kind {
            0 => {
                let r = a.wrapping_sub(b) & all;
                (r, a >= b, ((a ^ b) & (a ^ r)) >> (bits - 1) & 1 == 1)
            }
            1 => {
                let r = a.wrapping_add(b) & all;
                let carry = u128::from(a) + u128::from(b) > u128::from(all);
                let carry = if isa == Isa::X86_64 { !carry } else { carry };
                (r, carry, ((a ^ r) & (b ^ r)) >> (bits - 1) & 1 == 1)
            }
            _ => (a, isa == Isa::X86_64, false),
        };
        let negative = sign_extend(result, bits) < 0;
        u8::from(negative) << 3
            | u8::from(result == 0) << 2
            | u8::from(carry) << 1
            | u8::from(overflow)
    }

    fn decided(test: &Test, registers: &[u64; 2]) -> Option<bool> {
        let value =
            |expr: &Expr| evaluate(expr, &|index| registers.get(usize::from(index)).copied());
        match test {
            Test::Always => Some(true),
            Test::Never => Some(false),
            Test::Compare(cond, lhs, rhs) => Some(holds(
                *cond,
                value(lhs)?,
                value(rhs)?,
                operand_width(lhs, rhs),
            )),
            Test::Unknown => None,
        }
    }

    #[test]
    fn every_condition_decides_as_the_flags_do() {
        const EDGES: [u64; 7] = [0, 1, 0x7f, 0x80, 0x7fff_ffff, 0x8000_0000, 1 << 63];
        for isa in [Isa::AArch64, Isa::X86_64] {
            for bits in [8u32, 32, 64] {
                for seed in 0..600u64 {
                    let pick = |key: u64| match hash(seed, key) % 3 {
                        0 => EDGES[(hash(seed, key + 9) % 7) as usize].wrapping_sub(hash(seed, 5) % 2),
                        _ => hash(seed, key + 3),
                    } & mask(bits);
                    let (a, b) = (pick(1), pick(2));
                    let lhs = Expr::reg(0, bits as u8);
                    // The second operand both as a register and as a constant.
                    for rhs in [Expr::reg(1, bits as u8), Expr::constant(b)] {
                        for kind in 0..3u8 {
                            let flags = match kind {
                                0 => Flags::difference(lhs.clone(), rhs.clone()),
                                1 => Flags::sum(lhs.clone(), rhs.clone()),
                                _ => Flags::logic(lhs.clone()),
                            };
                            let nzcv = reference(kind, a, b, bits, isa);
                            for cond in CONDITIONS {
                                let test = flags.test(cond, isa);
                                assert_eq!(
                                    decided(&test, &[a, b]),
                                    Some(fixed_holds(cond, nzcv)),
                                    "{isa:?} {bits}-bit kind {kind} {cond:?} a={a:#x} b={b:#x} rhs={rhs:?}: {test:?}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn carry_arithmetic_decides_all_conditions_at_each_width() {
        for bits in [8, 16, 32, 64] {
            for subtract in [false, true] {
                for carry in [0, 1] {
                    for seed in 0..600 {
                        let edges = [0, 1, mask(bits), 1 << (bits - 1), (1 << (bits - 1)) - 1];
                        let a = if seed < 25 {
                            edges[seed as usize % 5]
                        } else {
                            hash(seed, 0) & mask(bits)
                        };
                        let b = if seed < 25 {
                            edges[seed as usize / 5]
                        } else {
                            hash(seed, 1) & mask(bits)
                        };
                        let signed_a = i128::from(sign_extend(a, bits));
                        let signed_b = i128::from(sign_extend(b, bits));
                        let (result, borrowed, signed) = if subtract {
                            (
                                a.wrapping_sub(b).wrapping_sub(carry) & mask(bits),
                                u128::from(a) < u128::from(b) + u128::from(carry),
                                signed_a - signed_b - i128::from(carry),
                            )
                        } else {
                            (
                                a.wrapping_add(b).wrapping_add(carry) & mask(bits),
                                u128::from(a) + u128::from(b) + u128::from(carry)
                                    > u128::from(mask(bits)),
                                signed_a + signed_b + i128::from(carry),
                            )
                        };
                        let limit = 1i128 << (bits - 1);
                        let overflow = signed < -limit || signed >= limit;
                        let nzcv = u8::from(result >> (bits - 1) != 0) << 3
                            | u8::from(result == 0) << 2
                            | u8::from(!borrowed) << 1
                            | u8::from(overflow);
                        let flags = Flags::with_carry(
                            Expr::reg(0, bits as u8),
                            Expr::reg(1, bits as u8),
                            Expr::constant(carry),
                            subtract,
                            bits,
                        );
                        for cond in CONDITIONS {
                            assert_eq!(
                                decided(&flags.test(cond, Isa::X86_64), &[a, b]),
                                Some(fixed_holds(cond, nzcv)),
                                "{bits} bits, subtract {subtract}, carry {carry}, a {a:#x}, b {b:#x}, {cond:?}"
                            );
                        }
                        assert_eq!(
                            decided(&flags.parity(true), &[a, b]),
                            Some((result as u8).count_ones().is_multiple_of(2))
                        );
                        assert_eq!(
                            decided(&flags.adjust(), &[a, b]),
                            Some((a ^ b ^ result) & 16 != 0)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_conditional_compare_tests_both_conditions() {
        // cmp x0, x1; ccmp x2, x3, #0, eq: `eq` holds when both pairs match.
        let earlier = Flags::difference(Expr::reg(0, 64), Expr::reg(1, 64));
        let flags = Flags::difference(Expr::reg(2, 64), Expr::reg(3, 64))
            .chosen_by(earlier.test(Cond::Eq, Isa::AArch64), 0)
            .expect("known");
        let test = flags.test(Cond::Eq, Isa::AArch64);
        let value = |registers: [u64; 4]| match &test {
            Test::Compare(cond, lhs, rhs) => {
                let read = |expr: &Expr| {
                    evaluate(expr, &|index| registers.get(usize::from(index)).copied())
                        .expect("registers")
                };
                holds(*cond, read(lhs), read(rhs), operand_width(lhs, rhs))
            }
            other => panic!("{other:?}"),
        };
        assert!(value([1, 1, 2, 2]));
        assert!(!value([1, 0, 2, 2]));
        assert!(!value([1, 1, 2, 3]));
    }
}

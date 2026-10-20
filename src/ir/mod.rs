pub mod cfg;
#[cfg(test)]
pub mod eval;
pub(crate) mod semantics;
mod types;
pub mod visit;

pub use types::{Access, CType, Member, Param, StackParam, Structure};

/// The integer calling convention a call follows: which registers carry
/// its arguments and which it may overwrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Convention {
    Aapcs64,
    SysV,
    Win64,
    /// Go's internal register ABI on x86-64.
    GoAmd64,
    /// A Linux system call on x86-64: the number in rax, then the
    /// arguments; it overwrites rax, rcx and r11.
    SyscallX86,
    /// A Linux system call on AArch64: the number in x8, then the
    /// arguments; it overwrites x0.
    SyscallArm,
}

impl Convention {
    pub fn of(isa: crate::loader::Isa, format: crate::loader::Format, go: bool) -> Self {
        use crate::loader::{Format, Isa};
        match isa {
            Isa::AArch64 => Self::Aapcs64,
            _ if go => Self::GoAmd64,
            _ if matches!(format, Format::Pe | Format::Coff) => Self::Win64,
            _ => Self::SysV,
        }
    }

    /// Integer argument registers, in order.
    pub fn arguments(self) -> &'static [u16] {
        match self {
            Self::Aapcs64 => &[0, 1, 2, 3, 4, 5, 6, 7],
            Self::SysV => &[7, 6, 2, 1, 8, 9],
            Self::Win64 => &[1, 2, 8, 9],
            // rax, rbx, rcx, rdi, rsi, r8, r9, r10, r11.
            Self::GoAmd64 => &[0, 3, 1, 7, 6, 8, 9, 10, 11],
            Self::SyscallX86 => &[0, 7, 6, 2, 10, 8, 9],
            Self::SyscallArm => &[8, 0, 1, 2, 3, 4, 5],
        }
    }

    /// Where the arguments past the registers start, from the stack pointer
    /// on entry: past the return address on x86-64, and past the space
    /// Windows reserves for the register ones.
    pub fn stack_arguments(self) -> Option<i64> {
        match self {
            Self::SysV => Some(8),
            Self::Win64 => Some(40),
            Self::Aapcs64 => Some(0),
            Self::GoAmd64 | Self::SyscallX86 | Self::SyscallArm => None,
        }
    }

    /// Bytes a call pushes before the callee runs: the return address.
    pub fn pushed_by_call(self) -> i64 {
        match self {
            Self::Aapcs64 | Self::SyscallX86 | Self::SyscallArm => 0,
            Self::SysV | Self::Win64 | Self::GoAmd64 => 8,
        }
    }

    /// Floating-point argument registers, in order: the low halves of xmm0
    /// to xmm7 (xmm3 on Windows, xmm14 in Go's ABI), or of v0 to v7.
    pub fn float_arguments(self) -> &'static [u16] {
        match self {
            Self::Aapcs64 => &[32, 34, 36, 38, 40, 42, 44, 46],
            Self::SysV => &[18, 20, 22, 24, 26, 28, 30, 32],
            Self::Win64 => &[18, 20, 22, 24],
            Self::GoAmd64 => &[18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46],
            Self::SyscallX86 | Self::SyscallArm => &[],
        }
    }

    /// Registers a call may read: its arguments, the floating-point ones,
    /// and the ones in `call_extra`.
    pub fn call_reads(self) -> impl Iterator<Item = u16> {
        self.arguments()
            .iter()
            .chain(self.float_arguments())
            .chain(self.call_extra())
            .copied()
    }

    /// Registers a call whose integer arguments are named still reads: the
    /// floating-point arguments and those in `call_extra`.
    pub fn unnamed_reads(self) -> impl Iterator<Item = u16> {
        self.float_arguments()
            .iter()
            .chain(self.call_extra())
            .copied()
    }

    /// Registers a call may read besides its arguments: AArch64's indirect
    /// result register and the vector count a variadic SysV call takes in al.
    pub fn call_extra(self) -> &'static [u16] {
        match self {
            Self::Aapcs64 => &[8],
            Self::SysV => &[0],
            Self::Win64 | Self::GoAmd64 | Self::SyscallX86 | Self::SyscallArm => &[],
        }
    }

    /// Registers a call may leave changed.
    pub fn clobbered(self) -> &'static [u16] {
        match self {
            // And v0 to v7 and v16 to v31, and the high halves of v8 to v15.
            Self::Aapcs64 => &[
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 32, 33, 34, 35,
                36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 49, 51, 53, 55, 57, 59, 61, 63, 64,
                65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85,
                86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
            ],
            // And every xmm and ymm register.
            Self::SysV => &[
                0, 1, 2, 6, 7, 8, 9, 10, 11, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
                31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
                52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72,
                73, 74, 75, 76, 77, 78, 79, 80, 81,
            ],
            // And xmm0 to xmm5, and the upper halves of every ymm register.
            Self::Win64 => &[
                0, 1, 2, 8, 9, 10, 11, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 50, 51, 52,
                53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73,
                74, 75, 76, 77, 78, 79, 80, 81,
            ],
            // Everything but rsp, rbp, r14 (the goroutine) and r15.
            Self::GoAmd64 => &[
                0, 1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
                29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
                50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
                71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81,
            ],
            Self::SyscallX86 => &[0, 1, 11],
            Self::SyscallArm => &[0],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    /// High 64 bits of the unsigned 128-bit widening product.
    MulHigh,
    /// High 64 bits of the signed 128-bit widening product.
    MulHighS,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Sar,
    DivS,
    ModS,
    /// Truncating unsigned division.
    DivU,
    /// Remainder after unsigned division.
    ModU,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cond {
    Eq,
    Ne,
    Cs,
    Cc,
    Mi,
    Pl,
    Vs,
    Vc,
    Hi,
    Ls,
    Ge,
    Lt,
    Gt,
    Le,
}

impl Cond {
    pub fn from_code(code: u8) -> Option<Cond> {
        Some(match code & 0xf {
            0 => Cond::Eq,
            1 => Cond::Ne,
            2 => Cond::Cs,
            3 => Cond::Cc,
            4 => Cond::Mi,
            5 => Cond::Pl,
            6 => Cond::Vs,
            7 => Cond::Vc,
            8 => Cond::Hi,
            9 => Cond::Ls,
            10 => Cond::Ge,
            11 => Cond::Lt,
            12 => Cond::Gt,
            13 => Cond::Le,
            _ => return None,
        })
    }

    /// The complementary predicate (`!gt` is `le`).
    pub fn invert(self) -> Cond {
        match self {
            Cond::Eq => Cond::Ne,
            Cond::Ne => Cond::Eq,
            Cond::Cs => Cond::Cc,
            Cond::Cc => Cond::Cs,
            Cond::Mi => Cond::Pl,
            Cond::Pl => Cond::Mi,
            Cond::Vs => Cond::Vc,
            Cond::Vc => Cond::Vs,
            Cond::Hi => Cond::Ls,
            Cond::Ls => Cond::Hi,
            Cond::Ge => Cond::Lt,
            Cond::Lt => Cond::Ge,
            Cond::Gt => Cond::Le,
            Cond::Le => Cond::Gt,
        }
    }

    pub fn text(self) -> &'static str {
        match self {
            Cond::Eq => "eq",
            Cond::Ne => "ne",
            Cond::Cs => "cs",
            Cond::Cc => "cc",
            Cond::Mi => "mi",
            Cond::Pl => "pl",
            Cond::Vs => "vs",
            Cond::Vc => "vc",
            Cond::Hi => "hi",
            Cond::Ls => "ls",
            Cond::Ge => "ge",
            Cond::Lt => "lt",
            Cond::Gt => "gt",
            Cond::Le => "le",
        }
    }
}

/// The width of a floating-point value, held as its bit pattern in the low
/// 32 or 64 bits of a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Precision {
    Single,
    Double,
}

impl Precision {
    pub fn bits(self) -> u8 {
        match self {
            Precision::Single => 32,
            Precision::Double => 64,
        }
    }
}

/// How a float rounds to an integral value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rounding {
    TowardZero,
    /// To the nearest, ties to even, as the default rounding mode does.
    NearestEven,
    /// To the nearest, ties away from zero.
    NearestAway,
    Down,
    Up,
}

/// Which AES round: encryption or decryption, and whether it is the last,
/// which leaves out mixing the columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AesRound {
    Encrypt,
    EncryptLast,
    Decrypt,
    DecryptLast,
}

/// An operation on each pair of lanes of two vectors' halves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LaneOp {
    Add,
    Sub,
    /// The low half of the product.
    Mul,
    /// All ones where the comparison holds, zero where it does not.
    Equal,
    GreaterSigned,
    GreaterUnsigned,
    GreaterEqualSigned,
    GreaterEqualUnsigned,
    MinSigned,
    MinUnsigned,
    MaxSigned,
    MaxUnsigned,
    /// Each lane of the first shifted by the second argument, the same count
    /// for every lane; a count of the lane width or more clears the lane, or
    /// fills it with its sign.
    ShiftLeft,
    ShiftRight,
    ShiftRightSigned,
}

/// An operation `Expr::Apply` applies to its arguments, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    /// IEEE arithmetic, rounding to nearest.
    FloatAdd(Precision),
    FloatSub(Precision),
    FloatMul(Precision),
    FloatDiv(Precision),
    FloatSqrt(Precision),
    /// The sign flipped or cleared, NaNs included.
    FloatNegate(Precision),
    FloatAbs(Precision),
    /// `a * b + c`, rounded once.
    FloatMulAdd(Precision),
    /// One when the comparison holds and zero otherwise; a NaN makes the
    /// ordered comparisons false and `FloatUnordered` true.
    FloatEqual(Precision),
    FloatLess(Precision),
    FloatLessEqual(Precision),
    FloatUnordered(Precision),
    /// An integer of `bits` as a float.
    IntToFloat {
        signed: bool,
        bits: u8,
        to: Precision,
    },
    /// A float rounded to an integer of `bits`. Out of range, or for a NaN,
    /// it saturates (NaN to zero) when `saturating` is set, as AArch64 does,
    /// and otherwise gives the lowest signed value, as x86 does.
    FloatToInt {
        signed: bool,
        bits: u8,
        from: Precision,
        saturating: bool,
        rounding: Rounding,
    },
    /// A float rounded to an integral float.
    FloatRound(Precision, Rounding),
    FloatConvert {
        from: Precision,
        to: Precision,
    },
    /// Lanes of `bits` in two 64-bit halves, combined pair by pair.
    Lanes(LaneOp, u8),
    /// The lanes of `bits` in the low (or high) 32 bits of two halves, taken
    /// in turn, the first argument's first.
    InterleaveLow(u8),
    InterleaveHigh(u8),
    /// The top bit of each lane of `bits` in a half, lowest lane first.
    SignBits(u8),
    /// The sum of the lanes of `bits` in two halves, wrapping at `bits`.
    SumLanes(u8),
    /// Counts over the low `bits`; a zero value counts `bits`.
    CountLeadingZeros(u8),
    CountTrailingZeros(u8),
    PopCount(u8),
    ReverseBits(u8),
    /// One AES round on a 128-bit state and round key, each given as its
    /// low and high halves: the half of the new state `high` names.
    Aes {
        round: AesRound,
        high: bool,
    },
}

impl Operation {
    /// The precision of the float the operation computes, if it computes one.
    pub fn result_precision(self) -> Option<Precision> {
        match self {
            Operation::FloatAdd(p)
            | Operation::FloatSub(p)
            | Operation::FloatMul(p)
            | Operation::FloatDiv(p)
            | Operation::FloatSqrt(p)
            | Operation::FloatNegate(p)
            | Operation::FloatAbs(p)
            | Operation::FloatRound(p, _)
            | Operation::FloatMulAdd(p)
            | Operation::IntToFloat { to: p, .. }
            | Operation::FloatConvert { to: p, .. } => Some(p),
            _ => None,
        }
    }

    /// The precision of the floats the operation reads, if it reads any.
    pub fn argument_precision(self) -> Option<Precision> {
        match self {
            Operation::FloatAdd(p)
            | Operation::FloatSub(p)
            | Operation::FloatMul(p)
            | Operation::FloatDiv(p)
            | Operation::FloatSqrt(p)
            | Operation::FloatNegate(p)
            | Operation::FloatAbs(p)
            | Operation::FloatRound(p, _)
            | Operation::FloatMulAdd(p)
            | Operation::FloatEqual(p)
            | Operation::FloatLess(p)
            | Operation::FloatLessEqual(p)
            | Operation::FloatUnordered(p)
            | Operation::FloatToInt { from: p, .. }
            | Operation::FloatConvert { from: p, .. } => Some(p),
            _ => None,
        }
    }

    pub fn arity(self) -> usize {
        match self {
            Operation::FloatSqrt(_)
            | Operation::FloatNegate(_)
            | Operation::FloatAbs(_)
            | Operation::FloatRound(..)
            | Operation::IntToFloat { .. }
            | Operation::FloatToInt { .. }
            | Operation::FloatConvert { .. }
            | Operation::CountLeadingZeros(_)
            | Operation::CountTrailingZeros(_)
            | Operation::PopCount(_)
            | Operation::ReverseBits(_)
            | Operation::SignBits(_) => 1,
            Operation::FloatMulAdd(_) => 3,
            Operation::Aes { .. } => 4,
            _ => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Expr {
    Reg {
        index: u16,
        width: u8,
    },
    Const(u64),
    Bin {
        op: BinOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    Load {
        addr: Box<Expr>,
        width: u8,
        signed: bool,
    },
    SignExtend {
        value: Box<Expr>,
        width: u8,
    },
    Select {
        cond: Cond,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
        then: Box<Expr>,
        els: Box<Expr>,
    },
    Apply {
        op: Operation,
        args: Vec<Expr>,
    },
}

impl Expr {
    pub fn apply(op: Operation, args: Vec<Expr>) -> Self {
        debug_assert_eq!(args.len(), op.arity());
        Expr::Apply { op, args }
    }

    pub fn constant(value: u64) -> Self {
        Expr::Const(value)
    }

    pub fn reg(index: u16, width: u8) -> Self {
        Expr::Reg { index, width }
    }

    pub fn bin(op: BinOp, lhs: Expr, rhs: Expr) -> Self {
        if let (Expr::Const(a), Expr::Const(b)) = (&lhs, &rhs) {
            let value = match op {
                BinOp::Add => a.wrapping_add(*b),
                BinOp::Sub => a.wrapping_sub(*b),
                BinOp::Mul => a.wrapping_mul(*b),
                BinOp::And => *a & *b,
                BinOp::Or => *a | *b,
                BinOp::Xor => *a ^ *b,
                BinOp::Shl => a.wrapping_shl(*b as u32),
                BinOp::Shr => a.wrapping_shr(*b as u32),
                BinOp::Sar => (*a as i64).wrapping_shr(*b as u32) as u64,
                BinOp::DivS if *b != 0 => (*a as i64).wrapping_div(*b as i64) as u64,
                BinOp::ModS if *b != 0 => (*a as i64).wrapping_rem(*b as i64) as u64,
                BinOp::DivU if *b != 0 => a / b,
                BinOp::ModU if *b != 0 => a % b,
                BinOp::MulHigh => ((u128::from(*a) * u128::from(*b)) >> 64) as u64,
                BinOp::MulHighS => ((i128::from(*a as i64) * i128::from(*b as i64)) >> 64) as u64,
                BinOp::DivS | BinOp::ModS | BinOp::DivU | BinOp::ModU => {
                    return Expr::Bin {
                        op,
                        lhs: Box::new(lhs),
                        rhs: Box::new(rhs),
                    };
                }
            };
            return Expr::Const(value);
        }
        if matches!(op, BinOp::Shl | BinOp::Shr | BinOp::Sar) && matches!(rhs, Expr::Const(0)) {
            return lhs;
        }
        if matches!(op, BinOp::Add | BinOp::Sub | BinOp::Or | BinOp::Xor)
            && matches!(rhs, Expr::Const(0))
        {
            return lhs;
        }
        if matches!(op, BinOp::Add | BinOp::Or | BinOp::Xor) && matches!(lhs, Expr::Const(0)) {
            return rhs;
        }
        if matches!(op, BinOp::And | BinOp::Or) && lhs == rhs {
            return lhs;
        }
        if op == BinOp::Mul && matches!(rhs, Expr::Const(1)) {
            return lhs;
        }
        if op == BinOp::And
            && matches!(rhs, Expr::Const(0xffff_ffff))
            && matches!(
                &lhs,
                Expr::Bin {
                    op: BinOp::And,
                    rhs,
                    ..
                } if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff))
            )
        {
            return lhs;
        }
        Expr::Bin {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    pub fn render(&self, isa: crate::loader::Isa) -> String {
        match self {
            Expr::Reg { index, width } => reg_name(isa, *index, *width),
            Expr::Const(value) => format!("#0x{value:x}"),
            Expr::Bin { op, lhs, rhs } => {
                format!(
                    "({} {} {})",
                    lhs.render(isa),
                    operator(*op),
                    rhs.render(isa)
                )
            }
            Expr::Load {
                addr,
                width,
                signed,
            } => format!(
                "load{}({}){}",
                width * 8,
                addr.render(isa),
                if *signed { "s" } else { "" }
            ),
            Expr::SignExtend { value, width } => {
                format!("sext{}({})", width * 8, value.render(isa))
            }
            Expr::Select {
                cond,
                lhs,
                rhs,
                then,
                els,
            } => format!(
                "select {} {}, {} ? {}, {}",
                cond.text(),
                lhs.render(isa),
                rhs.render(isa),
                then.render(isa),
                els.render(isa)
            ),
            Expr::Apply { op, args } => format!(
                "{}({})",
                operation_name(*op),
                args.iter()
                    .map(|arg| arg.render(isa))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

/// The name of a lane operation, followed by its lane width.
pub(crate) fn lane_op_name(op: LaneOp) -> &'static str {
    match op {
        LaneOp::Add => "add_lanes",
        LaneOp::Sub => "sub_lanes",
        LaneOp::Mul => "mul_lanes",
        LaneOp::Equal => "equal_lanes",
        LaneOp::GreaterSigned => "greater_lanes",
        LaneOp::GreaterUnsigned => "greater_lanes_u",
        LaneOp::GreaterEqualSigned => "greater_equal_lanes",
        LaneOp::GreaterEqualUnsigned => "greater_equal_lanes_u",
        LaneOp::MinSigned => "min_lanes",
        LaneOp::MinUnsigned => "min_lanes_u",
        LaneOp::MaxSigned => "max_lanes",
        LaneOp::MaxUnsigned => "max_lanes_u",
        LaneOp::ShiftLeft => "shift_left_lanes",
        LaneOp::ShiftRight => "shift_right_lanes",
        LaneOp::ShiftRightSigned => "shift_right_lanes_s",
    }
}

fn rounding_name(rounding: Rounding) -> &'static str {
    match rounding {
        Rounding::TowardZero => "",
        Rounding::NearestEven => ".even",
        Rounding::NearestAway => ".away",
        Rounding::Down => ".down",
        Rounding::Up => ".up",
    }
}

/// The IR's name for an operation, with its precision or width.
pub(crate) fn operation_name(op: Operation) -> String {
    let p = |precision: Precision| match precision {
        Precision::Single => "s",
        Precision::Double => "d",
    };
    match op {
        Operation::FloatAdd(x) => format!("fadd.{}", p(x)),
        Operation::FloatSub(x) => format!("fsub.{}", p(x)),
        Operation::FloatMul(x) => format!("fmul.{}", p(x)),
        Operation::FloatDiv(x) => format!("fdiv.{}", p(x)),
        Operation::FloatSqrt(x) => format!("fsqrt.{}", p(x)),
        Operation::FloatNegate(x) => format!("fneg.{}", p(x)),
        Operation::FloatAbs(x) => format!("fabs.{}", p(x)),
        Operation::FloatMulAdd(x) => format!("fma.{}", p(x)),
        Operation::FloatEqual(x) => format!("feq.{}", p(x)),
        Operation::FloatLess(x) => format!("flt.{}", p(x)),
        Operation::FloatLessEqual(x) => format!("fle.{}", p(x)),
        Operation::FloatUnordered(x) => format!("funord.{}", p(x)),
        Operation::IntToFloat { signed, bits, to } => {
            format!("{}{bits}tof.{}", if signed { "s" } else { "u" }, p(to))
        }
        Operation::FloatToInt {
            signed,
            bits,
            from,
            saturating,
            rounding,
        } => format!(
            "f.{}to{}{bits}{}{}",
            p(from),
            if signed { "s" } else { "u" },
            rounding_name(rounding),
            if saturating { ".sat" } else { "" }
        ),
        Operation::FloatRound(x, rounding) => format!("fround{}.{}", rounding_name(rounding), p(x)),
        Operation::FloatConvert { from, to } => format!("f.{}tof.{}", p(from), p(to)),
        Operation::Lanes(op, bits) => format!("{}{bits}", lane_op_name(op)),
        Operation::InterleaveLow(bits) => format!("interleave_low{bits}"),
        Operation::InterleaveHigh(bits) => format!("interleave_high{bits}"),
        Operation::SignBits(bits) => format!("sign_bits{bits}"),
        Operation::SumLanes(bits) => format!("sum_lanes{bits}"),
        Operation::CountLeadingZeros(bits) => format!("clz{bits}"),
        Operation::CountTrailingZeros(bits) => format!("ctz{bits}"),
        Operation::PopCount(bits) => format!("popcount{bits}"),
        Operation::ReverseBits(bits) => format!("bitreverse{bits}"),
        Operation::Aes { round, high } => format!(
            "{}_{}",
            match round {
                AesRound::Encrypt => "aesenc",
                AesRound::EncryptLast => "aesenclast",
                AesRound::Decrypt => "aesdec",
                AesRound::DecryptLast => "aesdeclast",
            },
            if high { "high" } else { "low" }
        ),
    }
}

fn operator(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "+",
        BinOp::Sub => "-",
        BinOp::Mul => "*",
        BinOp::MulHigh => "hi128",
        BinOp::MulHighS => "hi128s",
        BinOp::And => "&",
        BinOp::Or => "|",
        BinOp::Xor => "^",
        BinOp::Shl => "<<",
        BinOp::Shr => ">>",
        BinOp::Sar => ">>>",
        BinOp::DivS => "/",
        BinOp::ModS => "%",
        BinOp::DivU => "/",
        BinOp::ModU => "%",
    }
}

use crate::loader::Isa;

const X86_NAMES64: [&str; 82] = [
    "rax",
    "rcx",
    "rdx",
    "rbx",
    "rsp",
    "rbp",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "fs_base",
    "gs_base",
    "xmm0",
    "xmm0_hi",
    "xmm1",
    "xmm1_hi",
    "xmm2",
    "xmm2_hi",
    "xmm3",
    "xmm3_hi",
    "xmm4",
    "xmm4_hi",
    "xmm5",
    "xmm5_hi",
    "xmm6",
    "xmm6_hi",
    "xmm7",
    "xmm7_hi",
    "xmm8",
    "xmm8_hi",
    "xmm9",
    "xmm9_hi",
    "xmm10",
    "xmm10_hi",
    "xmm11",
    "xmm11_hi",
    "xmm12",
    "xmm12_hi",
    "xmm13",
    "xmm13_hi",
    "xmm14",
    "xmm14_hi",
    "xmm15",
    "xmm15_hi",
    "ymm0_128",
    "ymm0_192",
    "ymm1_128",
    "ymm1_192",
    "ymm2_128",
    "ymm2_192",
    "ymm3_128",
    "ymm3_192",
    "ymm4_128",
    "ymm4_192",
    "ymm5_128",
    "ymm5_192",
    "ymm6_128",
    "ymm6_192",
    "ymm7_128",
    "ymm7_192",
    "ymm8_128",
    "ymm8_192",
    "ymm9_128",
    "ymm9_192",
    "ymm10_128",
    "ymm10_192",
    "ymm11_128",
    "ymm11_192",
    "ymm12_128",
    "ymm12_192",
    "ymm13_128",
    "ymm13_192",
    "ymm14_128",
    "ymm14_192",
    "ymm15_128",
    "ymm15_192",
];

/// Register indices from here up are per-function CSE temporaries, printed as
/// `t<n>`.
pub const TEMP_BASE: u16 = 0x1000;

/// The registers holding the operands the flags were set from, and those of
/// the condition that chose a conditional compare, after the instruction that
/// sets the flags, or a later one, overwrites what they read.
pub const FLAG_OPERANDS: [u16; 4] = [
    TEMP_BASE + 0x40,
    TEMP_BASE + 0x41,
    TEMP_BASE + 0x43,
    TEMP_BASE + 0x44,
];

/// The registers that carry the operands the flags were set from into a
/// block that reads them, from the end of each block before it.
pub const FLAG_CARRIED: [u16; 4] = [
    TEMP_BASE + 0x45,
    TEMP_BASE + 0x46,
    TEMP_BASE + 0x47,
    TEMP_BASE + 0x48,
];

/// The register holding a value an exchange overwrites before it is written
/// back.
pub const EXCHANGE: u16 = TEMP_BASE + 0x42;

/// The register holding a jump table's index where the code computing the
/// target overwrites the register it came in.
pub const SWITCH_INDEX: u16 = TEMP_BASE + 0x49;

/// Register indices from here up are the variables a parameter register
/// holds once its parameter is dead, printed as `v<n>`.
pub const VARIABLE_BASE: u16 = TEMP_BASE + 0x100;

/// Register indices from here up are SSA values, printed as `s<n>`.
pub const VALUE_BASE: u16 = 0x2000;

pub fn is_temp(index: u16) -> bool {
    index >= TEMP_BASE
}

pub fn temp_id(index: u16) -> u64 {
    u64::from(index - TEMP_BASE) + 1
}

pub fn reg_name(isa: Isa, index: u16, width: u8) -> String {
    let _ = (isa, width);
    if index >= VALUE_BASE {
        return format!("s{}", index - VALUE_BASE);
    }
    if index >= VARIABLE_BASE {
        return format!("v{}", index - VARIABLE_BASE + 1);
    }
    if is_temp(index) {
        return format!("t{isode}", isode = temp_id(index));
    }
    match isa {
        Isa::AArch64 if index >= crate::arch::aarch64::V0 => {
            let number = (index - crate::arch::aarch64::V0) / 2;
            match ((index - crate::arch::aarch64::V0) % 2, width) {
                (1, _) => format!("v{number}_hi"),
                (_, 32) => format!("s{number}"),
                _ => format!("d{number}"),
            }
        }
        Isa::AArch64 => {
            if index == 31 && width == 64 {
                "sp".to_owned()
            } else if width == 32 {
                format!("w{index}")
            } else {
                format!("x{index}")
            }
        }
        Isa::X86_64 => {
            let index = index as usize;
            let base = X86_NAMES64.get(index).copied().unwrap_or("reg");
            if width == 32 {
                match index {
                    0..=7 => format!("e{}", &base[1..]),
                    8..=15 => format!("{base}d"),
                    // The segment bases and xmm halves have no 32-bit names.
                    _ => format!("(uint32_t){base}"),
                }
            } else {
                base.to_owned()
            }
        }
        Isa::Unsupported => format!("reg{index}"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RegRef {
    pub index: u16,
    pub width: u8,
}

#[derive(Debug, Clone)]
pub enum Stmt {
    Assign {
        dest: RegRef,
        value: Expr,
    },
    Store {
        addr: Expr,
        value: Expr,
        width: u8,
    },
    Brif {
        cond: Cond,
        lhs: Expr,
        rhs: Expr,
        target: u64,
    },
    BrifFlags {
        cond: Cond,
        target: u64,
    },
    Br {
        target: Option<u64>,
    },
    BrIndirect {
        target: Expr,
    },
    Switch {
        index: Expr,
        cases: Vec<(i64, u64)>,
        default: Option<u64>,
    },
    Call {
        target: Option<u64>,
        /// The address an indirect call computes, when `target` is unknown.
        through: Option<Expr>,
        convention: Convention,
        /// The arguments, when the number the callee takes is known; else the
        /// call reads every argument register of its convention.
        args: Option<Vec<Expr>>,
        /// Where the returned value goes besides the return register, when a
        /// variable of its own holds it.
        result: Option<RegRef>,
    },
    Ret {
        value: Expr,
    },
    /// An instruction the lifter does not model, and the registers it may
    /// write, when known; otherwise it may write any machine register.
    Unsupported {
        text: String,
        writes: Option<Vec<u16>>,
    },
    /// A trap the CPU cannot return from (`int3`, `ud2`, `brk`).
    Trap,
}

impl Stmt {
    pub fn unsupported(text: impl Into<String>) -> Self {
        Stmt::Unsupported {
            text: text.into(),
            writes: None,
        }
    }

    /// Every expression the statement reads, in order.
    pub fn operands(&self) -> Vec<&Expr> {
        match self {
            Stmt::Assign { value, .. } | Stmt::Ret { value } => vec![value],
            Stmt::Store { addr, value, .. } => vec![addr, value],
            Stmt::Brif { lhs, rhs, .. } => vec![lhs, rhs],
            Stmt::BrIndirect { target } => vec![target],
            Stmt::Switch { index, .. } => vec![index],
            Stmt::Call { through, args, .. } => {
                through.iter().chain(args.iter().flatten()).collect()
            }
            Stmt::BrifFlags { .. } | Stmt::Br { .. } | Stmt::Unsupported { .. } | Stmt::Trap => {
                Vec::new()
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Block {
    pub start: u64,
    pub stmts: Vec<Stmt>,
}

#[derive(Debug, Clone)]
pub struct FunctionIr {
    pub isa: Isa,
    /// The calling convention the function itself follows.
    pub convention: Convention,
    pub params: Vec<Param>,
    /// Parameters the debug info places in the caller's stack frame.
    pub stack_params: Vec<StackParam>,
    /// The debug info declares further, variadic, parameters.
    pub variadic: bool,
    pub ret_type: CType,
    pub accesses: Vec<Access>,
    /// Structure fields the debug info names.
    pub members: Vec<Member>,
    /// Structures recovered from the accesses through pointer parameters.
    pub structures: Vec<Structure>,
    /// Argument registers a signed comparison reads.
    pub signed_params: std::collections::HashSet<u16>,
    pub addr: u64,
    pub name: Option<String>,
    pub size: u64,
    pub blocks: Vec<Block>,
}

impl FunctionIr {
    #[cfg(test)]
    pub(crate) fn single_block(isa: Isa, stmts: Vec<Stmt>) -> Self {
        Self {
            isa,
            convention: Convention::of(isa, crate::loader::Format::Elf, false),
            params: Vec::new(),
            stack_params: Vec::new(),
            variadic: false,
            ret_type: CType::U64,
            accesses: Vec::new(),
            members: Vec::new(),
            structures: Vec::new(),
            signed_params: std::collections::HashSet::new(),
            addr: 0,
            name: None,
            size: 0,
            blocks: vec![Block { start: 0, stmts }],
        }
    }

    /// Each pointer parameter's fields, as `a0 +0x8:uint32_t, +0x10:uint64_t`.
    pub fn access_lines(&self) -> Vec<String> {
        self.accesses
            .iter()
            .map(|access| {
                let name = self
                    .params
                    .iter()
                    .find(|param| param.index == access.register)
                    .map_or_else(
                        || reg_name(self.isa, access.register, 64),
                        |param| param.name.clone(),
                    );
                let fields: Vec<String> = access
                    .fields
                    .iter()
                    .map(|(offset, ty)| format!("+0x{offset:x}:{ty}"))
                    .collect();
                format!("{name} {}", fields.join(", "))
            })
            .collect()
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        let name = self.name.as_deref().unwrap_or("<unnamed>");
        out.push_str(&format!(
            "fn {name} @ 0x{:x} (size {})\n",
            self.addr, self.size
        ));
        for (index, block) in self.blocks.iter().enumerate() {
            out.push_str(&format!("  blk{index} @ 0x{:x}:\n", block.start));
            for stmt in &block.stmts {
                out.push_str("    ");
                out.push_str(&render_stmt(stmt, self.isa));
                out.push('\n');
            }
        }
        out
    }
}

fn render_stmt(stmt: &Stmt, isa: Isa) -> String {
    match stmt {
        Stmt::Assign { dest, value } => {
            format!(
                "{} = {}",
                reg_name(isa, dest.index, dest.width),
                value.render(isa)
            )
        }
        Stmt::Store { addr, value, width } => format!(
            "store{}({}, {})",
            width * 8,
            value.render(isa),
            addr.render(isa)
        ),
        Stmt::Brif {
            cond,
            lhs,
            rhs,
            target,
        } => format!(
            "brif {} {}, {} -> 0x{target:x}",
            cond.text(),
            lhs.render(isa),
            rhs.render(isa)
        ),
        Stmt::BrifFlags { cond, target } => {
            format!("brif {} -> 0x{target:x}", cond.text())
        }
        Stmt::Br { target } => match target {
            Some(target) => format!("br 0x{target:x}"),
            None => "br <dynamic>".to_owned(),
        },
        Stmt::BrIndirect { target } => format!("br {}", target.render(isa)),
        Stmt::Switch {
            index,
            cases,
            default,
        } => {
            let entries: Vec<String> = cases
                .iter()
                .map(|(value, target)| format!("{value}->0x{target:x}"))
                .collect();
            format!(
                "switch {} [{}] default {}",
                index.render(isa),
                entries.join(", "),
                default
                    .map(|t| format!("0x{t:x}"))
                    .unwrap_or_else(|| "<none>".to_owned())
            )
        }
        Stmt::Call {
            target,
            through,
            args: Some(args),
            result,
            ..
        } => {
            let args: Vec<String> = args.iter().map(|arg| arg.render(isa)).collect();
            let assigned = result.map_or(String::new(), |dest| {
                format!("{} = ", reg_name(isa, dest.index, dest.width))
            });
            assigned
                + &match (target, through) {
                    (Some(target), _) => format!("call 0x{target:x}({})", args.join(", ")),
                    (None, Some(through)) => {
                        format!("call *{}({})", through.render(isa), args.join(", "))
                    }
                    (None, None) => format!("call <dynamic>({})", args.join(", ")),
                }
        }
        Stmt::Call {
            target, through, ..
        } => match (target, through) {
            (Some(target), _) => format!("call 0x{target:x}"),
            (None, Some(through)) => format!("call *{}", through.render(isa)),
            (None, None) => "call <dynamic>".to_owned(),
        },
        Stmt::Ret { value } => format!("ret {}", value.render(isa)),
        Stmt::Unsupported { text, .. } => format!("unsupported: {text}"),
        Stmt::Trap => "trap".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::{BinOp, Expr};

    #[test]
    fn constant_folding_wraps_like_the_hardware() {
        let fold = |op, a: u64, b: u64| Expr::bin(op, Expr::Const(a), Expr::Const(b));
        let min = i64::MIN as u64;
        assert_eq!(fold(BinOp::DivS, min, u64::MAX), Expr::Const(min));
        assert_eq!(fold(BinOp::ModS, min, u64::MAX), Expr::Const(0));
        assert_eq!(fold(BinOp::Sar, min, 64), Expr::Const(min));
        assert_eq!(fold(BinOp::MulHighS, u64::MAX, 1), Expr::Const(u64::MAX));
        assert_eq!(
            fold(BinOp::MulHigh, u64::MAX, u64::MAX),
            Expr::Const(u64::MAX - 1)
        );
    }

    #[test]
    fn a_value_combined_with_itself_is_the_value() {
        let reg = Expr::Reg {
            index: 1,
            width: 64,
        };
        assert_eq!(Expr::bin(BinOp::And, reg.clone(), reg.clone()), reg);
        assert_eq!(Expr::bin(BinOp::Or, reg.clone(), reg.clone()), reg);
    }

    #[test]
    fn registers_without_32_bit_names_read_as_casts() {
        use crate::loader::Isa;
        assert_eq!(super::reg_name(Isa::X86_64, 9, 32), "r9d");
        assert_eq!(super::reg_name(Isa::X86_64, 20, 32), "(uint32_t)xmm1");
    }
}

mod convention;
mod print;
#[cfg(kani)]
mod proofs;
mod registers;
pub(crate) mod smt;

pub use calls::CallAbi;
pub use convention::{CallKind, Convention};
pub(crate) use print::*;
pub use registers::{
    EXCEPTION, EXCHANGE, FLAG_CARRIED, FLAG_OPERANDS, Registers, SELECTOR, SWITCH_INDEX, TEMP_BASE,
    VALUE_BASE, VARIABLE_BASE, is_temp, reg_name, temp_id,
};

pub(crate) mod abi;
pub(crate) mod calls;
pub mod cfg;
pub mod eval;
pub(crate) mod semantics;
pub mod trials;
mod types;
pub mod visit;

pub use types::{
    AbiIssue, AbiLocation, AbiPiece, AbiProfile, Access, CType, DeclaredSignature, Definition,
    Member, Param, Passing, RegisterClass, SignatureAbi, StackParam, Structure, ValueAbi,
};

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
    #[must_use]
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
    #[must_use]
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

    #[must_use]
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
    #[must_use]
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
    MixColumns,
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
    /// Signed low byte of each second-source lane: left if positive,
    /// logical right if negative; shifts beyond the lane produce zero.
    ShiftVariableUnsigned,
    /// Sums and differences held at the lane's limits instead of wrapping.
    AddSaturatingSigned,
    AddSaturatingUnsigned,
    SubSaturatingSigned,
    SubSaturatingUnsigned,
    /// The unsigned mean, rounded up.
    Average,
    /// The high half of the full product.
    MulHighSigned,
    MulHighUnsigned,
    /// The set bits of each lane of the first argument; the second is unused.
    PopCount,
    /// The leading zeros of each lane of the first argument; the second is
    /// unused.
    CountLeadingZeros,
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
    /// it saturates (NaN to zero) when `saturating` is set, as `AArch64` does,
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
    /// The lanes of `bits` in the low (or, when `high` is set, high) 32 bits
    /// of a half, each extended to twice `bits`.
    Widen {
        bits: u8,
        signed: bool,
        high: bool,
    },
    /// The lanes of `from` bits in two halves, each cut to its low half of
    /// the bits, the first argument's first.
    Narrow(u8),
    /// The top bit of each lane of `bits` in a half, lowest lane first.
    SignBits(u8),
    /// The sum of the lanes of `bits` in two halves, wrapping at `bits`.
    SumLanes(u8),
    /// The signed lanes of `from` bits in two halves narrowed to half as
    /// many bits, held at the narrow lane's limits: signed ones, or
    /// unsigned ones when `unsigned` is set. The first argument's come first.
    Pack {
        from: u8,
        unsigned: bool,
    },
    /// The signed 16-bit lanes of two halves multiplied pair by pair, each
    /// two neighbouring products summed into a 32-bit lane.
    MultiplyAddPairs,
    /// The sum of the absolute differences of the bytes of two halves.
    SumAbsoluteDifferences,
    /// The values a function returns in several registers, the first in the
    /// return register; as a value, the first.
    Results,
    /// What a register holds after a call that changes it without returning
    /// anything in it: no value the code may rely on. It takes no
    /// arguments, and the interpreter reads it as zero.
    Undefined,
    /// The sum of the lanes of `bits` in two halves, each extended first,
    /// in twice `bits`.
    SumLanesLong {
        bits: u8,
        signed: bool,
    },
    /// A CRC-32 step: the checksum in the first argument updated with the
    /// low `bits` of the second, bit-reflected, by the ISO-HDLC polynomial
    /// or, when `castagnoli` is set, Castagnoli's.
    Crc32 {
        castagnoli: bool,
        bits: u8,
    },
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
    /// A dividend of twice `bits`, given as its high and low halves, divided
    /// by a divisor of `bits`: the quotient, or the remainder. A divisor of
    /// zero, or a quotient too wide for `bits`, faults.
    WideDivide {
        signed: bool,
        remainder: bool,
        bits: u8,
    },
}

impl Operation {
    /// The precision of the float the operation computes, if it computes one.
    #[must_use]
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
    #[must_use]
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

    #[must_use]
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
            | Operation::Widen { .. }
            | Operation::SignBits(_) => 1,
            Operation::Undefined => 0,
            Operation::FloatMulAdd(_) => 3,
            Operation::Aes { .. } => 4,
            Operation::WideDivide { .. } => 3,
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
    #[must_use]
    pub fn apply(op: Operation, args: Vec<Expr>) -> Self {
        debug_assert_eq!(
            args.len(),
            op.arity(),
            "operation operands must match its arity"
        );
        Expr::Apply { op, args }
    }

    #[must_use]
    pub fn constant(value: u64) -> Self {
        Expr::Const(value)
    }

    #[must_use]
    pub fn reg(index: u16, width: u8) -> Self {
        Expr::Reg { index, width }
    }

    #[must_use]
    pub fn bin(op: BinOp, lhs: Expr, rhs: Expr) -> Self {
        if let (Expr::Const(a), Expr::Const(b)) = (&lhs, &rhs)
            && let Some(value) = semantics::scalar(op, *a, *b, 64)
        {
            return Expr::Const(value);
        }
        if matches!(op, BinOp::Shl | BinOp::Shr | BinOp::Sar) && matches!(rhs, Expr::Const(0)) {
            if op == BinOp::Sar {
                let bits = semantics::operand_width(&lhs, &rhs);
                if bits < 64 {
                    return Expr::bin(BinOp::And, lhs, Expr::Const(semantics::mask(bits)));
                }
            }
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
        // As `sbb rdx, rdx` starts, whatever rdx holds.
        if matches!(op, BinOp::Sub | BinOp::Xor)
            && lhs == rhs
            && !crate::passes::copies::reads_memory(&lhs)
            && !crate::passes::read_once::faults(&lhs)
        {
            return Expr::Const(0);
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
}

use crate::loader::Isa;

/// Where an indirect call takes its callee's address from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Via {
    pub table: Table,
    /// The slot's index in the table: from the address point of a C++
    /// table, among the methods of a Rust or Go one.
    pub slot: u64,
    /// For a call left indirect, the functions the slot holds in the
    /// tables it may read.
    pub candidates: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Table {
    /// A C++ virtual table, read through the object.
    Vtable,
    /// A Rust trait object's table: drop, size, align, then the methods.
    TraitObject,
    /// A Go interface table: interface, type, hash, then the methods.
    Itab,
    /// A Go function value, whose first word is the code.
    FuncValue,
    /// A pointer in constant data, at the address `slot` holds.
    Pointer,
    /// A register holding the code address itself.
    Register,
}

impl Via {
    /// What a comment after the call says of it.
    pub fn describe(&self, name: &dyn Fn(u64) -> String) -> String {
        let place = match self.table {
            Table::Vtable => format!("vtable slot {}", self.slot),
            Table::TraitObject => format!("trait object method {}", self.slot),
            Table::Itab => format!("itab method {}", self.slot),
            Table::FuncValue => "func value".to_owned(),
            Table::Pointer => format!("pointer at 0x{:x}", self.slot),
            Table::Register => "register".to_owned(),
        };
        if self.candidates.is_empty() {
            return place;
        }
        let names: Vec<String> = self.candidates.iter().map(|addr| name(*addr)).collect();
        format!("{place}: {}", names.join(", "))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RegRef {
    pub index: u16,
    pub width: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallOutput {
    pub register: u16,
    pub dest: RegRef,
}

#[must_use]
pub fn fallback_call_outputs(
    convention: Convention,
    clobbers: Option<Registers>,
) -> Vec<CallOutput> {
    let changed = convention.clobbered_by(clobbers);
    convention
        .results()
        .iter()
        .copied()
        .filter(|register| changed.contains(register))
        .map(|register| CallOutput {
            register,
            dest: RegRef {
                index: register,
                width: if convention == Convention::Aapcs32 {
                    32
                } else {
                    64
                },
            },
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MachineInstruction {
    /// `AArch64` system register encoded as o0:op1:CRn:CRm:op2.
    ArmSystem { register: u16, write: bool },
    /// `AArch64` DMB (0), DSB (1), or ISB (2), with its domain/type option.
    ArmBarrier { kind: u8, option: u8 },
    /// DC ZVA: zero the cache block containing the input address.
    ArmCacheZero,
    /// `RCpc` acquire load: address input, zero-extended value output.
    ArmLoadAcquire { width: u8 },
    /// Exclusive-monitor memory access. Loads return one or two values;
    /// stores take address and values, and return the architectural status.
    ArmExclusive {
        load: bool,
        width: u8,
        pair: bool,
        ordered: bool,
    },
    /// Atomic memory access, with width in bytes. Inputs are address, operand
    /// (except for loads), and expected value (for compare-exchange). The
    /// output is the observed value; stores have no output. A wide comparison
    /// appends the operand and expected high halves and returns both halves.
    Atomic {
        op: AtomicOp,
        width: u8,
        ordering: Ordering,
    },
    /// EAX and ECX inputs; EAX, EBX, ECX and EDX outputs, in that order.
    Cpuid,
    /// ECX input; one 64-bit extended-control-register output.
    Xgetbv,
    /// One 64-bit timestamp output.
    Rdtsc,
    /// A 64-bit timestamp and the 32-bit `IA32_TSC_AUX` value.
    Rdtscp,
    /// Mask and replacement-bit inputs; an RFLAGS output with RF and VM clear.
    ReadFlags,
    /// Requested RFLAGS input; the effective flags after the write as output.
    WriteFlags,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AtomicOp {
    Add,
    Sub,
    And,
    Or,
    Xor,
    Exchange,
    CompareExchange,
    Load,
    Store,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ordering {
    Relaxed,
    Acquire,
    Release,
    AcqRel,
    SeqCst,
}

impl Ordering {
    pub(crate) fn builtin(self) -> &'static str {
        match self {
            Self::Relaxed => "__ATOMIC_RELAXED",
            Self::Acquire => "__ATOMIC_ACQUIRE",
            Self::Release => "__ATOMIC_RELEASE",
            Self::AcqRel => "__ATOMIC_ACQ_REL",
            Self::SeqCst => "__ATOMIC_SEQ_CST",
        }
    }
}

#[derive(Debug, Clone)]
pub enum Stmt {
    /// An indivisible machine operation. Outputs are simultaneous writes.
    Machine {
        at: Option<u64>,
        instruction: MachineInstruction,
        inputs: Vec<Expr>,
        outputs: Vec<RegRef>,
    },
    Assign {
        /// The instruction that performs this effect, when known.
        at: Option<u64>,
        dest: RegRef,
        value: Expr,
    },
    Store {
        /// The instruction that performs this effect, when known.
        at: Option<u64>,
        addr: Expr,
        value: Expr,
        width: u8,
    },
    Brif {
        /// The instruction that performs this effect, when known.
        at: Option<u64>,
        cond: Cond,
        lhs: Expr,
        rhs: Expr,
        target: u64,
    },
    BrifFlags {
        /// The instruction that performs this effect, when known.
        at: Option<u64>,
        cond: Cond,
        target: u64,
    },
    Br {
        /// The instruction that performs this effect, when known.
        at: Option<u64>,
        target: Option<u64>,
    },
    BrIndirect {
        /// The instruction that performs this effect, when known.
        at: Option<u64>,
        target: Expr,
    },
    Switch {
        /// The instruction that performs this effect, when known.
        at: Option<u64>,
        index: Expr,
        cases: Vec<(i64, u64)>,
        default: Option<u64>,
    },
    Call {
        /// The instruction that performs this effect, when known.
        at: Option<u64>,
        kind: CallKind,
        target: Option<u64>,
        /// The address an indirect call computes, when `target` is unknown.
        through: Option<Expr>,
        convention: Convention,
        /// The arguments, when the number the callee takes is known; else the
        /// call reads every argument register of its convention.
        args: Option<Vec<Expr>>,
        /// `args` lists the floating-point arguments too, after the integer
        /// ones, so the call reads no other floating-point register.
        floats_named: bool,
        /// How the callee's debug-information declaration says this call
        /// passes its parameters and result, when there is one. The
        /// registers it names are read by the call besides `args`.
        abi: Option<std::sync::Arc<CallAbi>>,
        outputs: Vec<CallOutput>,
        /// The registers the callee may leave changed, when its summary
        /// knows them; else the call changes those its convention lets it.
        clobbers: Option<Registers>,
        /// The table the machine code loads the callee's address from,
        /// when it is one: for a call with `target` known, the indirect
        /// call it was; for one still through a pointer, the slot it reads.
        via: Option<Box<Via>>,
    },
    Ret {
        /// The instruction that performs this effect, when known.
        at: Option<u64>,
        value: Expr,
    },
    /// An instruction the lifter does not model, and the registers it may
    /// write, when known; otherwise it may write any machine register.
    Unsupported {
        at: Option<u64>,
        text: String,
        writes: Option<Vec<u16>>,
    },
    /// A trap the CPU cannot return from (`int3`, `ud2`, `brk`).
    Trap { at: Option<u64> },
}

impl Stmt {
    pub(crate) fn with_origin(mut self, address: Option<u64>) -> Self {
        self.set_origin(address);
        self
    }

    /// The instruction that performs this effect, or no known origin.
    #[must_use]
    #[inline]
    pub fn origin(&self) -> Option<u64> {
        match self {
            Self::Assign { at, .. }
            | Self::Store { at, .. }
            | Self::Call { at, .. }
            | Self::Brif { at, .. }
            | Self::BrifFlags { at, .. }
            | Self::Br { at, .. }
            | Self::BrIndirect { at, .. }
            | Self::Switch { at, .. }
            | Self::Ret { at, .. }
            | Self::Machine { at, .. }
            | Self::Unsupported { at, .. }
            | Self::Trap { at } => *at,
        }
    }

    #[inline]
    pub(crate) fn set_origin(&mut self, address: Option<u64>) {
        match self {
            Self::Assign { at, .. }
            | Self::Store { at, .. }
            | Self::Call { at, .. }
            | Self::Brif { at, .. }
            | Self::BrifFlags { at, .. }
            | Self::Br { at, .. }
            | Self::BrIndirect { at, .. }
            | Self::Switch { at, .. }
            | Self::Ret { at, .. }
            | Self::Machine { at, .. }
            | Self::Unsupported { at, .. }
            | Self::Trap { at } => *at = address,
        }
    }

    /// The registers a call's declaration reads besides its arguments: its
    /// parameters' registers and the stack pointer.
    #[must_use]
    pub fn declared_call_reads(&self) -> &[u16] {
        match self {
            Stmt::Call { abi: Some(abi), .. } => &abi.dependencies,
            _ => &[],
        }
    }

    #[must_use]
    pub fn has_declared_call(&self) -> bool {
        matches!(self, Stmt::Call { abi: Some(_), .. })
    }

    /// Whether a declared call passes something through memory: a stack
    /// argument, or an object or result by address.
    #[must_use]
    pub fn has_deferred_call_memory(&self) -> bool {
        matches!(self, Stmt::Call { abi: Some(abi), .. } if abi.deferred_memory)
    }

    #[must_use]
    pub fn call_outputs(&self) -> &[CallOutput] {
        match self {
            Stmt::Call { outputs, .. } => outputs,
            _ => &[],
        }
    }

    pub fn call_outputs_mut(&mut self) -> &mut [CallOutput] {
        match self {
            Stmt::Call { outputs, .. } => outputs,
            _ => &mut [],
        }
    }

    #[must_use]
    pub fn primary_call_output(&self) -> Option<&CallOutput> {
        let Stmt::Call {
            convention,
            outputs,
            ..
        } = self
        else {
            return None;
        };
        let primary = convention.results().first()?;
        outputs.iter().find(|output| output.register == *primary)
    }

    #[must_use]
    pub fn preserved_output_sources(&self) -> Vec<(usize, u16)> {
        let changed = self.call_clobbers();
        self.call_outputs()
            .iter()
            .enumerate()
            .filter(|(_, output)| !changed.contains(&output.register))
            .map(|(index, output)| (index, output.register))
            .collect()
    }

    /// The registers a call may leave changed; none for another statement.
    #[must_use]
    pub fn call_clobbers(&self) -> Vec<u16> {
        match self {
            Stmt::Call {
                convention,
                clobbers,
                ..
            } => convention.clobbered_by(*clobbers),
            _ => Vec::new(),
        }
    }

    /// The registers a call reads besides those its expressions name.
    #[must_use]
    pub fn unnamed_call_reads(&self) -> Vec<u16> {
        match self {
            // The register a call goes through holds the callee's address,
            // not an argument the convention reads unnamed.
            Stmt::Call {
                convention,
                args: Some(_),
                floats_named,
                through,
                ..
            } => {
                let mut addressing = rustc_hash::FxHashSet::default();
                if let Some(through) = through {
                    crate::ir::visit::collect_reads(through, &mut addressing);
                }
                convention
                    .unnamed_reads(*floats_named)
                    .into_iter()
                    .filter(|register| {
                        !addressing.contains(register)
                            || !convention.call_extra().contains(register)
                    })
                    .collect()
            }
            Stmt::Call {
                convention,
                through,
                floats_named,
                ..
            } => convention.call_reads_through(through.as_ref(), *floats_named),
            _ => Vec::new(),
        }
    }

    pub fn unsupported(text: impl Into<String>) -> Self {
        Stmt::Unsupported {
            at: None,
            text: text.into(),
            writes: None,
        }
    }

    /// Every expression the statement reads, in order.
    #[must_use]
    pub fn operands(&self) -> Vec<&Expr> {
        match self {
            Stmt::Machine { inputs, .. } => inputs.iter().collect(),
            Stmt::Assign { value, .. } | Stmt::Ret { value, .. } => vec![value],
            Stmt::Store { addr, value, .. } => vec![addr, value],
            Stmt::Brif { lhs, rhs, .. } => vec![lhs, rhs],
            Stmt::BrIndirect { target, .. } => vec![target],
            Stmt::Switch { index, .. } => vec![index],
            Stmt::Call { through, args, .. } => {
                through.iter().chain(args.iter().flatten()).collect()
            }
            Stmt::BrifFlags { .. }
            | Stmt::Br { .. }
            | Stmt::Unsupported { .. }
            | Stmt::Trap { .. } => Vec::new(),
        }
    }

    /// The same, to change.
    pub fn operands_mut(&mut self) -> Vec<&mut Expr> {
        match self {
            Stmt::Machine { inputs, .. } => inputs.iter_mut().collect(),
            Stmt::Assign { value, .. } | Stmt::Ret { value, .. } => vec![value],
            Stmt::Store { addr, value, .. } => vec![addr, value],
            Stmt::Brif { lhs, rhs, .. } => vec![lhs, rhs],
            Stmt::BrIndirect { target, .. } => vec![target],
            Stmt::Switch { index, .. } => vec![index],
            Stmt::Call { through, args, .. } => through
                .iter_mut()
                .chain(args.iter_mut().flatten())
                .collect(),
            Stmt::BrifFlags { .. }
            | Stmt::Br { .. }
            | Stmt::Unsupported { .. }
            | Stmt::Trap { .. } => Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Block {
    pub start: u64,
    pub stmts: Vec<Stmt>,
}

/// A source variable whose storage has a fixed entry-stack offset.
#[derive(Debug, Clone)]
pub struct DebugLocal {
    pub name: String,
    pub ty: CType,
    pub slot: i64,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct FunctionIr {
    pub isa: Isa,
    /// The calling convention the function itself follows.
    pub convention: Convention,
    pub params: Vec<Param>,
    /// The source declaration and its ABI mapping, separate from physical inputs.
    pub declared_signature: Option<DeclaredSignature>,
    /// Parameters the debug info places in the caller's stack frame.
    pub stack_params: Vec<StackParam>,
    /// Entry-stack bounds of register argument spill storage, when known.
    pub stack_spills: Option<(i64, i64)>,
    pub debug_locals: Vec<DebugLocal>,
    pub debug_registers: Vec<(u16, String)>,
    /// Fixed-address objects with source types from debug information.
    pub debug_globals: Vec<(u64, CType, u64)>,
    /// The debug info declares further, variadic, parameters.
    pub variadic: bool,
    pub ret_type: CType,
    pub accesses: Vec<Access>,
    /// Structure fields the debug info names.
    pub members: Vec<Member>,
    /// The structures and unions the debug info defines.
    pub definitions: Vec<Definition>,
    /// Structures recovered from the accesses through pointer parameters.
    pub structures: Vec<Structure>,
    /// Argument registers a signed comparison reads.
    pub signed_params: std::collections::HashSet<u16>,
    /// The blocks exceptions unwind into, each with the code ranges whose
    /// calls throw them there.
    pub landing_pads: Vec<(u64, Vec<(u64, u64)>)>,
    /// The variables the function passes where a callee takes a pointer.
    pub pointer_values: Vec<u16>,
    /// The frame slots, by offset from the stack pointer on entry, where the
    /// prologue saves registers that each return restores: no local of the
    /// function reaches into them.
    pub saved_slots: Vec<i64>,
    /// The lowest offset from the stack pointer on entry that the stack
    /// pointer reaches once its adjustments are gone; 0 while they remain.
    pub frame_bottom: i64,
    /// The declarations of functions called directly or addressed, from
    /// their debug information, where every parameter and the result is an
    /// integer or a pointer passed whole as the convention orders.
    pub callee_signatures: std::collections::BTreeMap<u64, DeclaredSignature>,
    /// The types the prototypes of the library functions the body calls
    /// give the variables it passes them and those holding their results.
    pub value_types: std::collections::BTreeMap<u16, CType>,
    /// The machine register each variable was split from.
    pub variable_registers: std::collections::BTreeMap<u16, u16>,
    pub addr: u64,
    pub name: Option<String>,
    pub size: u64,
    pub blocks: Vec<Block>,
}

impl FunctionIr {
    /// Creates a function with one block and no recovered types.
    pub(crate) fn single_block(isa: Isa, stmts: Vec<Stmt>) -> Self {
        Self {
            isa,
            convention: Convention::of(isa, crate::loader::Format::Elf, false),
            params: Vec::new(),
            declared_signature: None,
            stack_params: Vec::new(),
            stack_spills: None,
            debug_locals: Vec::new(),
            debug_registers: Vec::new(),
            debug_globals: Vec::new(),
            variadic: false,
            ret_type: CType::U64,
            accesses: Vec::new(),
            members: Vec::new(),
            definitions: Vec::new(),
            structures: Vec::new(),
            signed_params: std::collections::HashSet::new(),
            landing_pads: Vec::new(),
            pointer_values: Vec::new(),
            saved_slots: Vec::new(),
            frame_bottom: 0,
            callee_signatures: Default::default(),
            value_types: std::collections::BTreeMap::new(),
            variable_registers: std::collections::BTreeMap::new(),
            addr: 0,
            name: None,
            size: 0,
            blocks: vec![Block { start: 0, stmts }],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BinOp, Expr};

    #[test]
    fn fallback_outputs_use_precise_clobbers_and_primary_provenance() {
        use super::{Convention, Registers, Stmt, fallback_call_outputs};
        let mut call = Stmt::Call {
            kind: crate::ir::CallKind::Invoke,
            target: Some(0x1000),
            through: None,
            convention: Convention::SysV,
            args: Some(Vec::new()),
            floats_named: true,
            abi: None,
            outputs: fallback_call_outputs(Convention::SysV, Some([2].into_iter().collect())),
            clobbers: Some([2].into_iter().collect()),
            via: None,
            at: None,
        };
        assert_eq!(
            call.call_outputs()
                .iter()
                .map(|output| output.register)
                .collect::<Vec<_>>(),
            [2]
        );
        assert!(call.primary_call_output().is_none());
        assert!(fallback_call_outputs(Convention::SysV, Some(Registers::default())).is_empty());
        let outputs = fallback_call_outputs(Convention::Aapcs64, None);
        assert_eq!(
            outputs
                .iter()
                .map(|output| output.register)
                .collect::<Vec<_>>(),
            [0, 1, 32, 34]
        );
        assert!(
            outputs
                .iter()
                .all(|output| output.dest.index == output.register && output.dest.width == 64)
        );
        for dest in super::visit::statement_destinations_mut(&mut call) {
            dest.index = super::VARIABLE_BASE;
        }
        assert_eq!(call.call_outputs()[0].register, 2);
        let (written, _) = super::visit::statement_registers(&call);
        assert_eq!(written, [super::VARIABLE_BASE].into_iter().collect());
    }

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

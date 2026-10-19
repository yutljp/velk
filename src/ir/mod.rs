pub mod cfg;
#[cfg(test)]
pub mod eval;
pub(crate) mod semantics;
mod types;
pub mod visit;

pub use types::{Access, CType, Member, Param};

/// The integer calling convention a call follows: which registers carry
/// its arguments and which it may overwrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Convention {
    Aapcs64,
    SysV,
    Win64,
    /// Go's internal register ABI on x86-64.
    GoAmd64,
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
        }
    }

    /// Registers a call may read: its arguments, plus the ones in `call_extra`.
    pub fn call_reads(self) -> impl Iterator<Item = u16> {
        self.arguments().iter().chain(self.call_extra()).copied()
    }

    /// Registers a call may read besides its arguments: AArch64's indirect
    /// result register and the vector count a variadic SysV call takes in al.
    pub fn call_extra(self) -> &'static [u16] {
        match self {
            Self::Aapcs64 => &[8],
            Self::SysV => &[0],
            Self::Win64 | Self::GoAmd64 => &[],
        }
    }

    /// Registers a call may leave changed.
    pub fn clobbered(self) -> &'static [u16] {
        match self {
            Self::Aapcs64 => &[
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
            ],
            // And every xmm register.
            Self::SysV => &[
                0, 1, 2, 6, 7, 8, 9, 10, 11, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
                31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
            ],
            // And xmm0 to xmm5.
            Self::Win64 => &[
                0, 1, 2, 8, 9, 10, 11, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
            ],
            // Everything but rsp, rbp, r14 (the goroutine) and r15.
            Self::GoAmd64 => &[
                0, 1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
                29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
            ],
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
}

impl Expr {
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
        }
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

const X86_NAMES64: [&str; 50] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15", "fs_base", "gs_base", "xmm0", "xmm0_hi", "xmm1", "xmm1_hi", "xmm2", "xmm2_hi",
    "xmm3", "xmm3_hi", "xmm4", "xmm4_hi", "xmm5", "xmm5_hi", "xmm6", "xmm6_hi", "xmm7", "xmm7_hi",
    "xmm8", "xmm8_hi", "xmm9", "xmm9_hi", "xmm10", "xmm10_hi", "xmm11", "xmm11_hi", "xmm12",
    "xmm12_hi", "xmm13", "xmm13_hi", "xmm14", "xmm14_hi", "xmm15", "xmm15_hi",
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

/// The register holding a value an exchange overwrites before it is written
/// back.
pub const EXCHANGE: u16 = TEMP_BASE + 0x42;

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
    Unsupported {
        text: String,
    },
    /// A trap the CPU cannot return from (`int3`, `ud2`, `brk`).
    Trap,
}

impl Stmt {
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
    pub ret_type: CType,
    pub accesses: Vec<Access>,
    /// Structure fields the debug info names.
    pub members: Vec<Member>,
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
            ret_type: CType::U64,
            accesses: Vec::new(),
            members: Vec::new(),
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
        Stmt::Unsupported { text } => format!("unsupported: {text}"),
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

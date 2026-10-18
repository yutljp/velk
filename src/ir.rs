//! Register-expression IR used by the lifter and `velk lift`.

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    /// The predicate's complement, so a constant-true select reads with the
    /// condition the source comparison wrote (`!gt` renders as `le`).
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

#[derive(Debug, Clone)]
pub enum Expr {
    Reg { index: u16, width: u8 },
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
                BinOp::Sar => ((*a as i64) >> (*b as u32)) as u64,
                BinOp::DivS if *b != 0 => ((*a as i64) / (*b as i64)) as u64,
                BinOp::ModS if *b != 0 => ((*a as i64) % (*b as i64)) as u64,
                BinOp::DivU if *b != 0 => a / b,
                BinOp::ModU if *b != 0 => a % b,
                BinOp::MulHigh => {
                    let product = u128::from(*a) * u128::from(*b);
                    u64::try_from(product >> 64).unwrap_or(0)
                }
                BinOp::MulHighS => {
                    let product = i128::from(*a as i64) * i128::from(*b as i64);
                    u64::try_from(product >> 64).unwrap_or(0)
                }
                BinOp::DivS | BinOp::ModS | BinOp::DivU | BinOp::ModU => return Expr::Bin { op, lhs: Box::new(lhs), rhs: Box::new(rhs) },
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
                format!("({} {} {})", lhs.render(isa), operator(*op), rhs.render(isa))
            }
            Expr::Load { addr, width, signed } => format!(
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

const X86_NAMES64: [&str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12",
    "r13", "r14", "r15",
];

/// Synthetic register indices >= 0x1000 are printed as `t<n>`; they are per
/// function temporaries introduced by the CSE pass.
pub const TEMP_BASE: u16 = 0x1000;

pub fn is_temp(index: u16) -> bool {
    index >= TEMP_BASE
}

pub fn temp_id(index: u16) -> u64 {
    u64::from(index - TEMP_BASE) + 1
}

pub fn reg_name(isa: Isa, index: u16, width: u8) -> String {
    let _ = (isa, width);
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
                    _ => format!("{base}d"),
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

#[derive(Debug, Clone)]
pub struct Block {
    pub start: u64,
    pub stmts: Vec<Stmt>,
}

#[derive(Debug, Clone)]
pub struct FunctionIr {
    pub isa: Isa,
    pub params: Vec<crate::signature::Param>,
    pub ret_type: String,
    pub accesses: Vec<String>,
    /// `(struct name, byte offset, field name)` from the debug info.
    pub members: Vec<(String, i64, String)>,
    pub addr: u64,
    pub name: Option<String>,
    pub size: u64,
    pub blocks: Vec<Block>,
}

impl FunctionIr {
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
                default.map(|t| format!("0x{t:x}")).unwrap_or_else(|| "<none>".to_owned())
            )
        }
        Stmt::Call { target } => match target {
            Some(target) => format!("call 0x{target:x}"),
            None => "call <dynamic>".to_owned(),
        },
        Stmt::Ret { value } => format!("ret {}", value.render(isa)),
        Stmt::Unsupported { text } => format!("unsupported: {text}"),
        Stmt::Trap => "trap".to_owned(),
    }
}

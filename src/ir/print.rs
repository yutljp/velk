use super::{
    AesRound, BinOp, CallOutput, Expr, FunctionIr, LaneOp, Operation, Precision, Rounding, Stmt,
    reg_name,
};
use crate::loader::Isa;

/// The name of a lane operation.
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
        LaneOp::ShiftVariableUnsigned => "shift_variable_lanes_u",
        LaneOp::AddSaturatingSigned => "add_saturating_lanes",
        LaneOp::AddSaturatingUnsigned => "add_saturating_lanes_u",
        LaneOp::SubSaturatingSigned => "sub_saturating_lanes",
        LaneOp::SubSaturatingUnsigned => "sub_saturating_lanes_u",
        LaneOp::Average => "average_lanes_u",
        LaneOp::MulHighSigned => "mul_high_lanes",
        LaneOp::MulHighUnsigned => "mul_high_lanes_u",
        LaneOp::PopCount => "popcount_lanes",
        LaneOp::CountLeadingZeros => "clz_lanes",
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
        Operation::Widen { bits, signed, high } => format!(
            "widen_{}{bits}{}",
            if high { "high" } else { "low" },
            if signed { "_s" } else { "_u" }
        ),
        Operation::Narrow(from) => format!("narrow_lanes{from}"),
        Operation::SignBits(bits) => format!("sign_bits{bits}"),
        Operation::SumLanes(bits) => format!("sum_lanes{bits}"),
        Operation::Pack { from, unsigned } => {
            format!("pack_lanes{from}{}", if unsigned { "_u" } else { "" })
        }
        Operation::MultiplyAddPairs => "multiply_add_pairs16".to_owned(),
        Operation::SumLanesLong { bits, signed } => {
            format!("sum_lanes_long{bits}{}", if signed { "_s" } else { "" })
        }
        Operation::Crc32 { castagnoli, bits } => {
            format!("crc32{}_{bits}", if castagnoli { "c" } else { "" })
        }
        Operation::SumAbsoluteDifferences => "sum_absolute_differences8".to_owned(),
        Operation::Results => "results".to_owned(),
        Operation::Undefined => "undefined".to_owned(),
        Operation::CountLeadingZeros(bits) => format!("clz{bits}"),
        Operation::CountTrailingZeros(bits) => format!("ctz{bits}"),
        Operation::PopCount(bits) => format!("popcount{bits}"),
        Operation::ReverseBits(bits) => format!("bitreverse{bits}"),
        Operation::WideDivide {
            signed,
            remainder,
            bits,
        } => format!(
            "{}{}{bits}",
            if remainder {
                "wide_remainder"
            } else {
                "wide_divide"
            },
            if signed { "_s" } else { "_u" }
        ),
        Operation::Aes { round, high } => format!(
            "{}_{}",
            match round {
                AesRound::Encrypt => "aesenc",
                AesRound::EncryptLast => "aesenclast",
                AesRound::Decrypt => "aesdec",
                AesRound::DecryptLast => "aesdeclast",
                AesRound::MixColumns => "aesmc",
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
            outputs,
            ..
        } => {
            let args: Vec<String> = args.iter().map(|arg| arg.render(isa)).collect();
            let assigned = render_call_outputs(isa, outputs);
            let call = match (target, through) {
                (Some(target), _) => format!("call 0x{target:x}({})", args.join(", ")),
                (None, Some(through)) => {
                    format!("call *{}({})", through.render(isa), args.join(", "))
                }
                (None, None) => format!("call <dynamic>({})", args.join(", ")),
            };
            format!("{assigned}{call}")
        }
        Stmt::Call {
            target,
            through,
            outputs,
            ..
        } => {
            let assigned = render_call_outputs(isa, outputs);
            let call = match (target, through) {
                (Some(target), _) => format!("call 0x{target:x}"),
                (None, Some(through)) => format!("call *{}", through.render(isa)),
                (None, None) => "call <dynamic>".to_owned(),
            };
            format!("{assigned}{call}")
        }
        Stmt::Ret { value } => format!("ret {}", value.render(isa)),
        Stmt::Machine {
            instruction,
            inputs,
            outputs,
        } => format!(
            "{:?} {:?} ({})",
            instruction,
            outputs,
            inputs
                .iter()
                .map(|input| input.render(isa))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Stmt::Unsupported { text, .. } => format!("unsupported: {text}"),
        Stmt::Trap => "trap".to_owned(),
    }
}

fn render_call_outputs(isa: Isa, outputs: &[CallOutput]) -> String {
    if outputs.is_empty() {
        return String::new();
    }
    let names: Vec<String> = outputs
        .iter()
        .map(|output| {
            let dest = reg_name(isa, output.dest.index, output.dest.width);
            if output.dest.index == output.register {
                dest
            } else {
                format!("{dest}:{}", reg_name(isa, output.register, 64))
            }
        })
        .collect();
    format!("{} = ", names.join(", "))
}

impl Expr {
    #[must_use]
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

impl FunctionIr {
    /// Each pointer parameter's fields, as `a0 +0x8:uint32_t, +0x10:uint64_t`.
    #[must_use]
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
}

impl FunctionIr {
    #[must_use]
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

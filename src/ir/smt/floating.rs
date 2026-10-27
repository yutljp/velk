//! IEEE operations on the bit patterns held by scalar IR values.

use super::{Value, constant, low};
use crate::ir::{Operation, Precision, Rounding};

fn format_widths(precision: Precision) -> (u32, u32) {
    match precision {
        Precision::Single => (8, 24),
        Precision::Double => (11, 53),
    }
}

fn float(value: &str, precision: Precision) -> String {
    let (exponent, significand) = format_widths(precision);
    let bits = precision.bits();
    format!(
        "((_ to_fp {exponent} {significand}) ((_ extract {} 0) {value}))",
        bits - 1
    )
}

fn bits(value: &str, precision: Precision) -> String {
    let result = format!("(fp.to_ieee_bv {value})");
    if precision == Precision::Single {
        format!("((_ zero_extend 32) {result})")
    } else {
        result
    }
}

fn rounding(rounding: Rounding) -> &'static str {
    match rounding {
        Rounding::TowardZero => "RTZ",
        Rounding::NearestEven => "RNE",
        Rounding::NearestAway => "RNA",
        Rounding::Down => "RTN",
        Rounding::Up => "RTP",
    }
}

pub(super) fn operation(op: Operation, args: &[Value]) -> Option<String> {
    let precision = match op {
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
        | Operation::FloatUnordered(p) => p,
        Operation::IntToFloat { to, .. } => to,
        Operation::FloatConvert { from, .. } | Operation::FloatToInt { from, .. } => from,
        _ => return None,
    };
    let raw = &args[0].term;
    let a = float(raw, precision);
    let b = args.get(1).map(|value| float(&value.term, precision));
    let truth = |test: String| format!("(ite {test} {} {})", constant(1), constant(0));
    let result = match op {
        Operation::FloatNegate(_) => {
            return Some(format!(
                "(bvxor {} {})",
                low(raw, u32::from(precision.bits())),
                constant(1u64 << (precision.bits() - 1))
            ));
        }
        Operation::FloatAbs(_) => {
            return Some(format!(
                "(bvand {raw} {})",
                constant(crate::ir::semantics::mask(u32::from(precision.bits()) - 1))
            ));
        }
        Operation::FloatEqual(_) | Operation::FloatLess(_) | Operation::FloatLessEqual(_) => {
            let operator = match op {
                Operation::FloatEqual(_) => "fp.eq",
                Operation::FloatLess(_) => "fp.lt",
                _ => "fp.leq",
            };
            return Some(truth(format!(
                "({operator} {a} {})",
                b.expect("binary float operation")
            )));
        }
        Operation::FloatUnordered(_) => {
            return Some(truth(format!(
                "(or (fp.isNaN {a}) (fp.isNaN {}))",
                b.expect("binary float operation")
            )));
        }
        Operation::FloatAdd(_)
        | Operation::FloatSub(_)
        | Operation::FloatMul(_)
        | Operation::FloatDiv(_) => {
            let operator = match op {
                Operation::FloatAdd(_) => "fp.add",
                Operation::FloatSub(_) => "fp.sub",
                Operation::FloatMul(_) => "fp.mul",
                _ => "fp.div",
            };
            format!(
                "({operator} RNE {a} {})",
                b.expect("binary float operation")
            )
        }
        Operation::FloatSqrt(_) => format!("(fp.sqrt RNE {a})"),
        Operation::FloatMulAdd(_) => format!(
            "(fp.fma RNE {a} {} {})",
            b.expect("ternary float operation"),
            float(&args[2].term, precision)
        ),
        Operation::FloatRound(_, mode) => format!("(fp.roundToIntegral {} {a})", rounding(mode)),
        Operation::FloatConvert { to, .. } => {
            let (exponent, significand) = format_widths(to);
            return Some(bits(
                &format!("((_ to_fp {exponent} {significand}) RNE {a})"),
                to,
            ));
        }
        Operation::IntToFloat {
            signed,
            bits: width,
            to,
        } => {
            let (exponent, significand) = format_widths(to);
            let operator = if signed { "to_fp" } else { "to_fp_unsigned" };
            format!(
                "((_ {operator} {exponent} {significand}) RNE ((_ extract {} 0) {raw}))",
                width - 1
            )
        }
        Operation::FloatToInt {
            signed,
            bits: width,
            saturating,
            rounding: mode,
            ..
        } => {
            let rounded = format!("(fp.roundToIntegral {} {a})", rounding(mode));
            let (exponent, significand) = format_widths(precision);
            let boundary = 1u128 << (u32::from(width) - u32::from(signed));
            let upper = format!("((_ to_fp {exponent} {significand}) RNE {boundary}.0)");
            let lower = if signed {
                format!("(fp.neg {upper})")
            } else {
                format!("((_ to_fp {exponent} {significand}) RNE 0.0)")
            };
            let minimum = if signed { 1u64 << (width - 1) } else { 0 };
            let maximum = crate::ir::semantics::mask(u32::from(width) - u32::from(signed));
            let indefinite = 1u64 << (width - 1);
            let invalid =
                format!("(or (fp.isNaN {a}) (fp.lt {rounded} {lower}) (fp.geq {rounded} {upper}))");
            let fallback = if saturating {
                format!(
                    "(ite (fp.isNaN {a}) {} (ite (fp.lt {rounded} {lower}) {} {}))",
                    constant(0),
                    constant(minimum),
                    constant(maximum)
                )
            } else {
                constant(indefinite)
            };
            let operator = if signed { "fp.to_sbv" } else { "fp.to_ubv" };
            let converted = format!("((_ {operator} {width}) RTZ {rounded})");
            let converted = if width < 64 {
                format!("((_ zero_extend {}) {converted})", 64 - width)
            } else {
                converted
            };
            return Some(format!("(ite {invalid} {fallback} {converted})"));
        }
        _ => unreachable!("precision was selected for a modeled operation"),
    };
    Some(bits(&result, precision))
}

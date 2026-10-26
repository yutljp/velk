use crate::ir::semantics::{mask, operand_width};
use crate::ir::visit::assignment_at;
use crate::ir::{BinOp, Cond, Expr, Stmt};

use super::divisor::{magic_divisor, magic_divisor_signed64};

#[cfg(test)]
mod smt_tests;

// Register definitions stay distinct, including when a register is overwritten
// between the multiply and the proposed replacement.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    Input(u16),
    Const(u64),
    Bits(u32, Box<Value>),
    Signed(u32, Box<Value>),
    Bin(BinOp, u32, Box<Value>, Box<Value>),
    Select(Cond, u32, Box<Value>, Box<Value>, Box<Value>, Box<Value>),
}

fn constant(value: u64) -> Value {
    Value::Const(value)
}

fn bits(value: Value, width: u32) -> Value {
    if width == 64 || value_bits(&value) <= width {
        return value;
    }
    match value {
        Value::Const(value) => constant(value & mask(width)),
        Value::Bits(old, value) => bits(*value, old.min(width)),
        Value::Signed(old, value) if old >= width => bits(*value, width),
        Value::Bin(op @ (BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::And), old, a, b) => {
            bin(op, old.min(width), *a, *b)
        }
        Value::Bin(BinOp::Shl, old, a, b) => {
            Value::Bin(BinOp::Shl, old.min(width), Box::new(bits(*a, width)), b)
        }
        Value::Select(cond, compare, a, b, then, els) => Value::Select(
            cond,
            compare,
            a,
            b,
            Box::new(bits(*then, width)),
            Box::new(bits(*els, width)),
        ),
        value => Value::Bits(width, Box::new(value)),
    }
}

fn value_bits(value: &Value) -> u32 {
    match value {
        Value::Const(value) => 64 - value.leading_zeros(),
        Value::Bits(width, _) => *width,
        Value::Bin(BinOp::Shr, _, value, amount) => {
            if let Value::Const(amount) = amount.as_ref() {
                value_bits(value).saturating_sub((*amount & 63) as u32)
            } else {
                64
            }
        }
        Value::Bin(
            BinOp::Add
            | BinOp::Sub
            | BinOp::Mul
            | BinOp::And
            | BinOp::Shl
            | BinOp::Sar
            | BinOp::DivS
            | BinOp::ModS,
            width,
            ..,
        ) => *width,
        Value::Bin(BinOp::DivU, _, value, _) => value_bits(value),
        _ => 64,
    }
}

fn signed(value: Value, width: u32) -> Value {
    if width == 64 {
        return value;
    }
    let value = bits(value, width);
    if let Value::Const(value) = value {
        return constant(((value << (64 - width)) as i64 >> (64 - width)) as u64);
    }
    Value::Signed(width, Box::new(value))
}

fn bin(op: BinOp, width: u32, a: Value, b: Value) -> Value {
    if op == BinOp::And
        && let Value::Const(value) = b
    {
        if value == 0xffff_ffff {
            return bits(a, 32.min(width));
        }
        return Value::Bin(
            op,
            width,
            Box::new(bits(a, width)),
            Box::new(constant(value & mask(width))),
        );
    }
    let modular = matches!(op, BinOp::Add | BinOp::Sub | BinOp::Mul);
    let (a, b) = if modular {
        (bits(a, width), bits(b, width))
    } else {
        (a, b)
    };
    Value::Bin(op, width, Box::new(a), Box::new(b))
}

fn equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Bin(op, w, a, b), Value::Bin(other, v, c, d)) if op == other && w == v => {
            (equal(a, c) && equal(b, d))
                || (matches!(op, BinOp::Add | BinOp::Mul | BinOp::And)
                    && equal(a, d)
                    && equal(b, c))
        }
        (Value::Bits(w, a), Value::Bits(v, b)) | (Value::Signed(w, a), Value::Signed(v, b)) => {
            w == v && equal(a, b)
        }
        _ => a == b,
    }
}

fn read(stmts: &[Stmt], at: usize, expr: &Expr, budget: &mut usize) -> Option<Value> {
    if *budget == 0 {
        return None;
    }
    *budget -= 1;
    match expr {
        Expr::Const(value) => Some(constant(*value)),
        Expr::Reg { index, width } => {
            for before in (0..at).rev() {
                let (writes, _) = crate::ir::visit::statement_registers(&stmts[before]);
                if !writes.contains(index) {
                    continue;
                }
                let Some((dest, value)) = assignment_at(stmts, before) else {
                    return None;
                };
                let Some(value) = read(stmts, before, value, budget) else {
                    return None;
                };
                return Some(bits(bits(value, u32::from(dest.width)), u32::from(*width)));
            }
            Some(bits(Value::Input(*index), u32::from(*width)))
        }
        Expr::SignExtend { value, width } if matches!(width, 1 | 2 | 4 | 8) => {
            let Some(value) = read(stmts, at, value, budget) else {
                return None;
            };
            Some(signed(value, u32::from(*width) * 8))
        }
        Expr::Bin { op, lhs, rhs } => {
            let Some(a) = read(stmts, at, lhs, budget) else {
                return None;
            };
            let Some(b) = read(stmts, at, rhs, budget) else {
                return None;
            };
            // Add/subtract/multiply in the IR are modulo 2^64; only signed
            // operations take their interpretation width from the operands.
            let width = if matches!(op, BinOp::Sar | BinOp::DivS | BinOp::ModS) {
                operand_width(lhs, rhs)
            } else {
                64
            };
            Some(bin(*op, width, a, b))
        }
        Expr::Select {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => {
            let [Some(a), Some(b), Some(then), Some(els)] =
                [lhs, rhs, then, els].map(|expr| read(stmts, at, expr, budget))
            else {
                return None;
            };
            let width = operand_width(lhs, rhs);
            Some(Value::Select(
                *cond,
                width,
                Box::new(bits(a, width)),
                Box::new(bits(b, width)),
                Box::new(then),
                Box::new(els),
            ))
        }
        _ => None,
    }
}

fn products(value: &Value, found: &mut Vec<(BinOp, Value, u64)>) {
    match value {
        Value::Bin(op, _, a, b) => {
            if matches!(op, BinOp::Mul | BinOp::MulHigh | BinOp::MulHighS) {
                match (a.as_ref(), b.as_ref()) {
                    (input, Value::Const(magic)) | (Value::Const(magic), input) => {
                        found.push((*op, input.clone(), *magic));
                    }
                    _ => {}
                }
            }
            products(a, found);
            products(b, found);
        }
        Value::Bits(_, value) | Value::Signed(_, value) => products(value, found),
        _ => {}
    }
}

fn shift(value: Value, amount: u64, arithmetic: bool, width: u32) -> Value {
    if amount == 0 {
        return value;
    }
    bin(
        if arithmetic { BinOp::Sar } else { BinOp::Shr },
        if arithmetic { width } else { 64 },
        value,
        constant(amount),
    )
}

fn division(value: &Value, input: &Value, divisor: u64, signed_div: bool, width: u32) -> bool {
    if !matches!(width, 32 | 64) || divisor < 2 || (signed_div && divisor >= 1u64 << (width - 1)) {
        return false;
    }
    let existing = bin(
        if signed_div { BinOp::DivS } else { BinOp::DivU },
        if signed_div { width } else { 64 },
        input.clone(),
        constant(divisor),
    );
    if equal(value, &bits(existing, width)) {
        return true;
    }
    // A narrow dividend is either explicitly extended or read at 32 bits.
    let narrow = bits(input.clone(), 32);
    let domain = if equal(input, &narrow) || equal(input, &signed(narrow.clone(), 32)) {
        32
    } else {
        64
    };
    if signed_div && domain == 32 && width == 64 && equal(input, &narrow) {
        return false;
    }
    let base = if domain == 32 { narrow } else { input.clone() };
    if signed_div && divisor.is_power_of_two() && divisor < (1u64 << (width - 1)) {
        let delta = constant(divisor - 1);
        let adjusted = bin(BinOp::Add, width, base.clone(), delta);
        for cond in [Cond::Ge, Cond::Lt] {
            let (then, els) = if cond == Cond::Ge {
                (base.clone(), adjusted.clone())
            } else {
                (adjusted.clone(), base.clone())
            };
            let select = Value::Select(
                cond,
                width,
                Box::new(base.clone()),
                Box::new(constant(0)),
                Box::new(then),
                Box::new(els),
            );
            let expected = bits(
                shift(select, u64::from(divisor.trailing_zeros()), true, width),
                width,
            );
            if equal(value, &expected) {
                return true;
            }
        }
    }
    let mut candidates = Vec::new();
    products(value, &mut candidates);
    for (op, source, magic) in candidates {
        let expected_source = if signed_div && domain == 32 {
            signed(base.clone(), 32)
        } else {
            base.clone()
        };
        if !equal(&source, &expected_source) || magic == 0 {
            continue;
        }
        let high = matches!(op, BinOp::MulHigh | BinOp::MulHighS);
        if (signed_div && (op == BinOp::MulHigh || magic > i64::MAX as u64))
            || (!signed_div && op == BinOp::MulHighS)
            || (!high && (domain != 32 || magic > 0xffff_ffff))
        {
            continue;
        }
        let product = bin(op, 64, source, constant(magic));
        for extra in 0..64 {
            let total = extra + if high { 64 } else { 0 };
            let found = if signed_div {
                magic_divisor_signed64(magic, total, domain)
            } else {
                magic_divisor(magic, total, domain)
            };
            if found != Some(divisor) {
                continue;
            }
            if !signed_div {
                if equal(
                    value,
                    &bits(shift(product.clone(), extra, false, 64), width),
                ) {
                    return true;
                }
                continue;
            }
            for arithmetic in [false, true] {
                // Logical shifts preserve a signed quotient only after a
                // narrowing write discards the product's upper sign bits.
                if !arithmetic && (width != 32 || high || extra < 32) {
                    continue;
                }
                let main = bits(shift(product.clone(), extra, arithmetic, 64), width);
                let mut signs = vec![
                    shift(product.clone(), 63, false, 64),
                    shift(base.clone(), domain - 1, false, 64),
                ];
                if u64::from(width) >= domain {
                    signs.push(shift(main.clone(), u64::from(width - 1), false, width));
                }
                for sign in signs {
                    let expected = bin(BinOp::Add, width, main.clone(), sign);
                    if equal(value, &expected) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

// Match an exact multiply-back, retaining the complete quotient expression.
fn scaled(value: &Value, factor: u64, width: u32) -> Option<Value> {
    if factor == 1 {
        return Some(value.clone());
    }
    let Value::Bin(op, w, a, b) = value else {
        return None;
    };
    if *w != width {
        return None;
    }
    match (op, a.as_ref(), b.as_ref()) {
        (BinOp::Mul, a, Value::Const(n)) | (BinOp::Mul, Value::Const(n), a)
            if *n > 1 && factor.is_multiple_of(*n) =>
        {
            scaled(a, factor / n, width)
        }
        (BinOp::Add, a, b) if equal(a, b) && factor.is_multiple_of(2) => {
            scaled(a, factor / 2, width)
        }
        (BinOp::Add, a, b) => {
            for (plain, term) in [(a, b), (b, a)] {
                let Value::Bin(op, _, base, amount) = term else {
                    continue;
                };
                let Value::Const(amount) = amount.as_ref() else {
                    continue;
                };
                let n = match op {
                    BinOp::Shl => 1u64.checked_shl(u32::try_from(*amount).unwrap_or(u32::MAX)),
                    BinOp::Mul => Some(*amount),
                    _ => None,
                };
                let Some(n) = n.and_then(|n| n.checked_add(1)) else {
                    continue;
                };
                if equal(plain, base) && n > 1 && factor.is_multiple_of(n) {
                    return scaled(plain, factor / n, width);
                }
            }
            None
        }
        _ => None,
    }
}

fn remainder(value: &Value, input: &Value, divisor: u64, signed_div: bool, width: u32) -> bool {
    if !matches!(width, 32 | 64) || divisor < 2 || (signed_div && divisor >= 1u64 << (width - 1)) {
        return false;
    }
    if signed_div && divisor.is_power_of_two() && divisor < (1u64 << (width - 1)) {
        let input = bits(input.clone(), width);
        let adjusted = bin(BinOp::Add, width, input.clone(), constant(divisor - 1));
        for cond in [Cond::Ge, Cond::Lt] {
            let (then, els) = if cond == Cond::Ge {
                (input.clone(), adjusted.clone())
            } else {
                (adjusted.clone(), input.clone())
            };
            let select = Value::Select(
                cond,
                width,
                Box::new(input.clone()),
                Box::new(constant(0)),
                Box::new(then),
                Box::new(els),
            );
            let rounded = bin(BinOp::And, width, select, constant(divisor.wrapping_neg()));
            let expected = bin(BinOp::Sub, width, input.clone(), rounded);
            if equal(value, &expected) {
                return true;
            }
        }
        let negated = bin(BinOp::Sub, width, constant(0), input.clone());
        let positive = bin(BinOp::And, width, input.clone(), constant(divisor - 1));
        let negative = bin(
            BinOp::Sub,
            width,
            constant(0),
            bin(BinOp::And, width, negated.clone(), constant(divisor - 1)),
        );
        for cond in [Cond::Mi, Cond::Pl, Cond::Lt, Cond::Ge] {
            let (lhs, rhs) = if matches!(cond, Cond::Mi | Cond::Pl) {
                (constant(0), input.clone())
            } else {
                (negated.clone(), constant(0))
            };
            let (then, els) = if matches!(cond, Cond::Mi | Cond::Lt) {
                (positive.clone(), negative.clone())
            } else {
                (negative.clone(), positive.clone())
            };
            let expected = Value::Select(
                cond,
                width,
                Box::new(lhs),
                Box::new(rhs),
                Box::new(then),
                Box::new(els),
            );
            if equal(value, &expected) {
                return true;
            }
        }
    }
    let Value::Bin(BinOp::Sub, w, lhs, rhs) = value else {
        return false;
    };
    if *w != width || !equal(lhs, &bits(input.clone(), width)) {
        return false;
    }
    let Some(quotient) = scaled(rhs, divisor, width) else {
        return false;
    };
    division(&quotient, input, divisor, signed_div, width)
}

/// Prove the proposed replacement against the actual reaching definitions.
/// Candidate recognizers may skip copies, but the proof may not skip an
/// operation, a width change, or a write to a dividend or product register.
pub(super) fn equivalent(stmts: &[Stmt], at: usize, replacement: &Expr) -> bool {
    let Some((dest, original)) = assignment_at(stmts, at) else {
        return false;
    };
    let Expr::Bin { op, lhs, rhs } = replacement else {
        return false;
    };
    let Expr::Const(divisor) = rhs.as_ref() else {
        return false;
    };
    let Some(value) = read(stmts, at, original, &mut 512) else {
        return false;
    };
    let Some(input) = read(stmts, at, lhs, &mut 512) else {
        return false;
    };
    if matches!(op, BinOp::DivS | BinOp::ModS) && operand_width(lhs, rhs) > u32::from(dest.width) {
        return false;
    }
    let value = bits(value, u32::from(dest.width));
    let width = if matches!(op, BinOp::DivS | BinOp::ModS) {
        u32::from(dest.width).min(operand_width(lhs, rhs))
    } else {
        u32::from(dest.width)
    };
    match op {
        BinOp::DivU | BinOp::DivS => division(&value, &input, *divisor, *op == BinOp::DivS, width),
        BinOp::ModU | BinOp::ModS => remainder(&value, &input, *divisor, *op == BinOp::ModS, width),
        _ => false,
    }
}

pub(super) fn checked(stmts: &[Stmt], start: usize, at: usize, replacement: Expr) -> Option<Expr> {
    if equivalent(stmts, at, &replacement) {
        return Some(replacement);
    }
    let Expr::Bin { op, lhs, rhs } = replacement else {
        return None;
    };
    let Some(index) = super::unwrap_leaf(&lhs) else {
        return None;
    };
    let root = super::dividend_parameter(stmts, start, index);
    // A multiply may overwrite its input copy. Try the original source and
    // its narrow view, but prove each against the consumer's current values.
    for source in [root, index] {
        for width in [32, 64] {
            let proposed = Expr::bin(op, Expr::reg(source, width), rhs.as_ref().clone());
            if equivalent(stmts, at, &proposed) {
                return Some(proposed);
            }
        }
    }
    None
}

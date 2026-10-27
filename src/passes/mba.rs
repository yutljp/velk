//! Bounded normalization of mixed bitwise and arithmetic expressions.

use std::collections::BTreeMap;

use crate::ir::{BinOp, Expr, FunctionIr, Stmt};

#[cfg(test)]
mod tests;

// Each factor is an AND of a nonempty subset of at most three registers.
// Products retain repeated factors: integer multiplication is not bitwise AND.
type Polynomial = BTreeMap<Vec<u8>, u64>;

fn accumulate(polynomial: &mut Polynomial, factors: Vec<u8>, coefficient: u64) {
    let entry = polynomial.entry(factors).or_default();
    *entry = entry.wrapping_add(coefficient);
    polynomial.retain(|_, coefficient| *coefficient != 0);
}

fn collect_supported_registers(
    expr: &Expr,
    registers: &mut Vec<Expr>,
    nodes: &mut usize,
    depth: usize,
) -> bool {
    *nodes += 1;
    if *nodes > 192 || depth > 32 {
        return false;
    }
    match expr {
        Expr::Reg {
            width: 8 | 16 | 32 | 64,
            ..
        } => {
            if !registers.contains(expr) {
                registers.push(expr.clone());
            }
            registers.len() <= 3
        }
        Expr::Const(_) => true,
        Expr::Bin {
            op:
                BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::And | BinOp::Or | BinOp::Xor | BinOp::Shl,
            lhs,
            rhs,
        } => {
            collect_supported_registers(lhs, registers, nodes, depth + 1)
                && collect_supported_registers(rhs, registers, nodes, depth + 1)
        }
        _ => false,
    }
}

fn evaluate_boolean_assignment(expr: &Expr, registers: &[Expr], assignment: usize) -> Option<bool> {
    match expr {
        Expr::Const(0) => Some(false),
        Expr::Const(u64::MAX) => Some(true),
        Expr::Reg { .. } => {
            let Some(index) = registers.iter().position(|register| register == expr) else {
                return None;
            };
            Some(assignment & (1 << index) != 0)
        }
        Expr::Bin {
            op: op @ (BinOp::And | BinOp::Or | BinOp::Xor),
            lhs,
            rhs,
        } => {
            let (Some(a), Some(b)) = (
                evaluate_boolean_assignment(lhs, registers, assignment),
                evaluate_boolean_assignment(rhs, registers, assignment),
            ) else {
                return None;
            };
            match op {
                BinOp::And => Some(a & b),
                BinOp::Or => Some(a | b),
                _ => Some(a ^ b),
            }
        }
        _ => None,
    }
}

fn normalize(expr: &Expr, registers: &[Expr]) -> Option<Polynomial> {
    match expr {
        Expr::Const(value) => {
            let mut result = Polynomial::new();
            accumulate(&mut result, Vec::new(), *value);
            Some(result)
        }
        Expr::Reg { .. }
        | Expr::Bin {
            op: BinOp::And | BinOp::Or | BinOp::Xor,
            ..
        } => {
            let mut coefficients = Vec::new();
            for assignment in 0..(1 << registers.len()) {
                let Some(value) = evaluate_boolean_assignment(expr, registers, assignment) else {
                    return None;
                };
                coefficients.push(u64::from(value));
            }
            // Integer Möbius inversion expresses each output bit as a sum of
            // conjunctions. The constant bit one denotes an all-ones word.
            for index in 0..registers.len() {
                for subset in 0..coefficients.len() {
                    if subset & (1 << index) != 0 {
                        coefficients[subset] =
                            coefficients[subset].wrapping_sub(coefficients[subset ^ (1 << index)]);
                    }
                }
            }
            let mut result = Polynomial::new();
            accumulate(&mut result, Vec::new(), coefficients[0].wrapping_neg());
            for (subset, coefficient) in coefficients.into_iter().enumerate().skip(1) {
                accumulate(&mut result, vec![subset as u8], coefficient);
            }
            Some(result)
        }
        Expr::Bin {
            op: BinOp::Shl,
            lhs,
            rhs,
        } => {
            let Expr::Const(shift) = rhs.as_ref() else {
                return None;
            };
            let Some(mut result) = normalize(lhs, registers) else {
                return None;
            };
            for coefficient in result.values_mut() {
                *coefficient = coefficient.wrapping_shl((*shift & 63) as u32);
            }
            result.retain(|_, coefficient| *coefficient != 0);
            Some(result)
        }
        Expr::Bin { op, lhs, rhs } if matches!(op, BinOp::Add | BinOp::Sub | BinOp::Mul) => {
            let (Some(mut a), Some(b)) = (normalize(lhs, registers), normalize(rhs, registers))
            else {
                return None;
            };
            if *op == BinOp::Mul {
                let mut result = Polynomial::new();
                for (left, x) in &a {
                    for (right, y) in &b {
                        if left.len() + right.len() > 4 {
                            return None;
                        }
                        let mut factors = left.clone();
                        factors.extend(right);
                        factors.sort_unstable();
                        accumulate(&mut result, factors, x.wrapping_mul(*y));
                        if result.len() > 32 {
                            return None;
                        }
                    }
                }
                return Some(result);
            }
            for (factors, coefficient) in b {
                let coefficient = if *op == BinOp::Sub {
                    coefficient.wrapping_neg()
                } else {
                    coefficient
                };
                accumulate(&mut a, factors, coefficient);
            }
            (a.len() <= 32).then_some(a)
        }
        _ => None,
    }
}

fn conjunction(subset: u8, registers: &[Expr]) -> Expr {
    let mut result = None;
    for (index, register) in registers.iter().enumerate() {
        if subset & (1 << index) != 0 {
            result = Some(match result {
                Some(left) => Expr::bin(BinOp::And, left, register.clone()),
                None => register.clone(),
            });
        }
    }
    result.unwrap_or(Expr::Const(u64::MAX))
}

fn expression(polynomial: &Polynomial, registers: &[Expr]) -> Expr {
    let mut result = Expr::Const(0);
    for (factors, coefficient) in polynomial {
        let negative = (*coefficient as i64) < 0;
        let magnitude = if negative {
            coefficient.wrapping_neg()
        } else {
            *coefficient
        };
        let mut term = Expr::Const(magnitude);
        for subset in factors {
            term = Expr::bin(BinOp::Mul, conjunction(*subset, registers), term);
        }
        result = Expr::bin(if negative { BinOp::Sub } else { BinOp::Add }, result, term);
    }
    result
}

fn size(expr: &Expr) -> usize {
    1 + crate::ir::visit::children(expr)
        .into_iter()
        .map(size)
        .sum::<usize>()
}

fn arithmetic_and_bitwise_presence(expr: &Expr) -> (bool, bool) {
    let mut arithmetic = false;
    let mut bitwise = false;
    if let Expr::Bin { op, lhs, rhs } = expr {
        arithmetic = matches!(op, BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Shl);
        bitwise = matches!(op, BinOp::And | BinOp::Or | BinOp::Xor);
        for child in [lhs, rhs] {
            let (a, b) = arithmetic_and_bitwise_presence(child);
            arithmetic |= a;
            bitwise |= b;
        }
    }
    (arithmetic, bitwise)
}

fn has_nonconstant_bitwise_operands(expr: &Expr) -> bool {
    let Expr::Bin { op, lhs, rhs } = expr else {
        return false;
    };
    (matches!(op, BinOp::And | BinOp::Or | BinOp::Xor)
        && !matches!(lhs.as_ref(), Expr::Const(_))
        && !matches!(rhs.as_ref(), Expr::Const(_)))
        || has_nonconstant_bitwise_operands(lhs)
        || has_nonconstant_bitwise_operands(rhs)
}

fn replacement(expr: &Expr, preserve_width: bool) -> Option<Expr> {
    let mut registers = Vec::new();
    let mut nodes = 0;
    if !collect_supported_registers(expr, &mut registers, &mut nodes, 0)
        || nodes < 7
        || arithmetic_and_bitwise_presence(expr) != (true, true)
    {
        return None;
    }
    let Some(polynomial) = normalize(expr, &registers) else {
        return None;
    };
    let width = crate::ir::semantics::width(expr);
    // Expanding scaled complements loses the array index form used for
    // named structure fields. Retain it unless the arithmetic cancels.
    let combines_bits = has_nonconstant_bitwise_operands(expr);
    let mut best = expr.clone();
    let mut consider = |candidate: Expr| {
        if size(&candidate) < size(&best)
            && (combines_bits || matches!(candidate, Expr::Const(_) | Expr::Reg { .. }))
            && (!preserve_width || crate::ir::semantics::width(&candidate) == width)
            && normalize(&candidate, &registers).as_ref() == Some(&polynomial)
        {
            best = candidate;
        }
    };
    consider(expression(&polynomial, &registers));
    for a in &registers {
        consider(a.clone());
        consider(Expr::bin(BinOp::Xor, a.clone(), Expr::Const(u64::MAX)));
        for b in &registers {
            for op in [
                BinOp::Add,
                BinOp::Sub,
                BinOp::Mul,
                BinOp::And,
                BinOp::Or,
                BinOp::Xor,
            ] {
                consider(Expr::bin(op, a.clone(), b.clone()));
            }
        }
    }
    (best != *expr).then_some(best)
}

fn rewrite(expr: &mut Expr, preserve_width: bool) -> usize {
    // Try the complete expression first, so simplifying one term cannot hide
    // a cancellation between several terms of a polynomial.
    if let Some(result) = replacement(expr, preserve_width) {
        *expr = result;
        return 1;
    }
    let mut changed = 0;
    for child in crate::ir::visit::children_mut(expr) {
        changed += rewrite(child, /* preserve_width */ true);
    }
    changed
}

pub(super) fn simplify(ir: &mut FunctionIr) -> usize {
    let mut changed = 0;
    for block in &mut ir.blocks {
        for stmt in &mut block.stmts {
            match stmt {
                Stmt::Assign { value, .. } | Stmt::Ret { value } => {
                    changed += rewrite(value, /* preserve_width */ false)
                }
                Stmt::Store { addr, value, .. } => {
                    changed += rewrite(addr, /* preserve_width */ false);
                    changed += rewrite(value, /* preserve_width */ false);
                }
                Stmt::Brif { lhs, rhs, .. } => {
                    changed += rewrite(lhs, /* preserve_width */ true);
                    changed += rewrite(rhs, /* preserve_width */ true);
                }
                Stmt::BrIndirect { target } => {
                    changed += rewrite(target, /* preserve_width */ false)
                }
                Stmt::Switch { index, .. } => {
                    changed += rewrite(index, /* preserve_width */ false)
                }
                Stmt::Call { through, args, .. } => {
                    if let Some(through) = through {
                        changed += rewrite(through, /* preserve_width */ false);
                    }
                    for arg in args.iter_mut().flatten() {
                        changed += rewrite(arg, /* preserve_width */ false);
                    }
                }
                // Machine operations may infer signed input widths.
                Stmt::Machine { inputs, .. } => {
                    for input in inputs {
                        changed += rewrite(input, /* preserve_width */ true);
                    }
                }
                _ => {}
            }
        }
    }
    changed
}

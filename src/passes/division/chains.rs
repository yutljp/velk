use crate::ir::visit::assignment;
use crate::ir::{Expr, Stmt};
use crate::passes::division::divisor::magic_divisor;
use crate::passes::division::divisor::magic_divisor_signed;
use crate::passes::division::divisor::magic_divisor_signed64;
use crate::passes::division::shift_of;
use crate::passes::division::strip_and_mask;
use crate::passes::division::unwrap_leaf;

/// Recognizes the signed 64-bit high-part constant-reciprocal chain:
///
/// ARM64:   `p = hi128S(a, M)`, then either `r = p + p lsr 63` (k = 0) or
///          `m = asr(p, k); r = m + p lsr 63`.
/// x86-64:  `p = hi128S(a, M); low = a * M; q = p;` … then
///          `s = shr(p, 63)`, an optional `sar(p, k)`, and
///          `r = sign-part + main-part` in either operand order.
///
/// Between the multiply and the sum only register copies, zero-extension masks
/// of the product and one low-half multiply may appear; anything else aborts.
pub(crate) fn signed64_chain(
    statements: &[Stmt],
    start: usize,
    dest_index: u16,
    magic: u64,
    domain_bits: u64,
    high_part: bool,
) -> Option<(usize, Vec<usize>, u64)> {
    let mut product_aliases: Vec<u16> = vec![dest_index];
    let mut sign_alias: Option<u16> = None;
    let mut main_alias: Option<u16> = None;
    let mut extra_shift: Option<u64> = None;
    let mut steps: Vec<usize> = Vec::new();
    let mut low_seen = false;

    for (position, stmt) in statements
        .iter()
        .enumerate()
        .take(start + 8)
        .skip(start + 1)
    {
        let Some((dest_ref, value)) = assignment(stmt) else {
            return None;
        };
        let dest = dest_ref.index;
        let value = strip_and_mask(value);
        match value {
            // x86-64 one-operand `imul` also writes the low half of the
            // product; the chain does not use it.
            Expr::Bin {
                op: crate::ir::BinOp::Mul,
                ..
            } => {
                if low_seen {
                    return None;
                }
                low_seen = true;
                // The caller drops it only if nothing else reads it.
                steps.push(position);
                continue;
            }
            Expr::Reg { index, .. } => {
                if product_aliases.contains(index) || main_alias == Some(*index) {
                    product_aliases.push(dest);
                    steps.push(position);
                    continue;
                }
                return None;
            }
            // A zero-extension mask of the product acts as another copy.
            Expr::Bin {
                op: crate::ir::BinOp::And,
                lhs,
                ..
            } => {
                let base = match lhs.as_ref() {
                    Expr::Reg { index, .. } => Some(*index),
                    _ => None,
                };
                let binds_product = base.is_some_and(|index| {
                    product_aliases.contains(&index) || main_alias == Some(index)
                });
                if !binds_product {
                    return None;
                }
                product_aliases.push(dest);
                steps.push(position);
                continue;
            }
            Expr::Bin { op, lhs, rhs } => match (op, lhs.as_ref(), rhs.as_ref()) {
                // Sign flag: `p >> (width - 1)`, logical or arithmetic.
                (
                    crate::ir::BinOp::Shr | crate::ir::BinOp::Sar,
                    Expr::Reg { index, .. },
                    Expr::Const(shift),
                ) if matches!(*shift, 63 | 31)
                    || shift.checked_add(1) == Some(u64::from(dest_ref.width)) =>
                {
                    if product_aliases.contains(index) && sign_alias.is_none() {
                        sign_alias = Some(dest);
                        product_aliases.retain(|other| other != &dest);
                        steps.push(position);
                        continue;
                    }
                    return None;
                }
                (crate::ir::BinOp::Sar, Expr::Reg { index, .. }, Expr::Const(k)) => {
                    if *k < 63 && product_aliases.contains(index) && main_alias.is_none() {
                        main_alias = Some(dest);
                        extra_shift = Some(*k);
                        product_aliases.retain(|other| other != &dest);
                        steps.push(position);
                        continue;
                    }
                    return None;
                }
                (crate::ir::BinOp::Add, lhs, rhs) => {
                    let lhs = strip_and_mask(lhs);
                    let rhs = strip_and_mask(rhs);
                    let lhs_main = main_shape(lhs, &product_aliases, main_alias, extra_shift);
                    let rhs_main = main_shape(rhs, &product_aliases, main_alias, extra_shift);
                    let lhs_sign = sign_shape(lhs, &product_aliases, sign_alias);
                    let rhs_sign = sign_shape(rhs, &product_aliases, sign_alias);
                    if !((lhs_main && rhs_sign) || (lhs_sign && rhs_main)) {
                        return None;
                    }
                    // A high-part product already includes a 64-bit shift.
                    let total = if high_part {
                        64 + extra_shift.unwrap_or(0)
                    } else {
                        extra_shift.unwrap_or(0)
                    };
                    let Some(divisor) = magic_divisor_signed64(magic, total, domain_bits) else {
                        return None;
                    };
                    return Some((position, steps, divisor));
                }
                _ => return None,
            },
            _ => return None,
        }
    }
    None
}

/// True when a sum operand is the sign flag: `p >> 63` / `p >> 31` or the
/// register holding it.
fn sign_shape(expr: &Expr, product_aliases: &[u16], sign_alias: Option<u16>) -> bool {
    match expr {
        Expr::Bin {
            op: crate::ir::BinOp::Shr | crate::ir::BinOp::Sar,
            lhs,
            rhs,
        } => {
            // 31 when the chain runs on the zero-extended 32-bit value.
            if (matches!(rhs.as_ref(), Expr::Const(63)) || matches!(rhs.as_ref(), Expr::Const(31)))
                && let Some(index) = leaf_index(lhs)
            {
                return product_aliases.contains(&index);
            }
        }
        Expr::Reg { index, .. } => return sign_alias == Some(*index),
        _ => {}
    }
    false
}

fn leaf_index(expr: &Expr) -> Option<u16> {
    match expr {
        Expr::Reg { index, .. } => Some(*index),
        _ => None,
    }
}

/// True when a sum operand is the main term: the product, a copy of it, or the
/// product shifted right by the chain's extra shift.
fn main_shape(
    expr: &Expr,
    product_aliases: &[u16],
    main_alias: Option<u16>,
    extra_shift: Option<u64>,
) -> bool {
    match expr {
        Expr::Reg { index, .. } => product_aliases.contains(index) || main_alias == Some(*index),
        Expr::Bin {
            op: crate::ir::BinOp::Sar,
            lhs,
            rhs,
        } => matches!(
            (lhs.as_ref(), rhs.as_ref()),
            (Expr::Reg { index, .. }, Expr::Const(k))
                if product_aliases.contains(index) && extra_shift == Some(*k)
        ),
        _ => false,
    }
}

/// Recognizes the unsigned 64-bit chain of x86-64 one-operand `mul`:
/// `p = hi128(a, M)`, an optional low-half write, copies of the product, and a
/// final `p >> s`. Returns the shift's position, the steps to drop, and `d`.
pub(crate) fn unsigned64_chain(
    statements: &[Stmt],
    start: usize,
    dest_index: u16,
    magic: u64,
    domain_bits: u64,
) -> Option<(usize, Vec<usize>, u64)> {
    let mut product_aliases: Vec<u16> = vec![dest_index];
    let mut steps: Vec<usize> = Vec::new();
    let mut low_seen = false;

    for (position, stmt) in statements
        .iter()
        .enumerate()
        .take(start + 8)
        .skip(start + 1)
    {
        let Some((dest_ref, value)) = assignment(stmt) else {
            return None;
        };
        let dest = dest_ref.index;
        match value {
            // At most one low-half write of the same product.
            Expr::Bin {
                op: crate::ir::BinOp::Mul,
                ..
            } => {
                if low_seen {
                    return None;
                }
                low_seen = true;
                steps.push(position);
                continue;
            }
            Expr::Reg { index, .. } => {
                if product_aliases.contains(index) {
                    product_aliases.push(dest);
                    steps.push(position);
                    continue;
                }
                return None;
            }
            // A zero-extension mask of the product acts as another copy.
            Expr::Bin {
                op: crate::ir::BinOp::And,
                lhs,
                ..
            } => {
                let base = match lhs.as_ref() {
                    Expr::Reg { index, .. } => Some(*index),
                    _ => None,
                };
                let binds_product = base.is_some_and(|index| product_aliases.contains(&index));
                if !binds_product {
                    return None;
                }
                product_aliases.push(dest);
                steps.push(position);
                continue;
            }
            Expr::Bin { op, lhs, rhs } => match (op, lhs.as_ref(), rhs.as_ref()) {
                (crate::ir::BinOp::Shr, Expr::Reg { index, .. }, Expr::Const(shift)) => {
                    if *shift == 0 || *shift >= 64 || !product_aliases.contains(index) {
                        return None;
                    }
                    let total = 64 + shift;
                    let Some(divisor) = magic_divisor(magic, total, domain_bits) else {
                        return None;
                    };
                    return Some((position, steps, divisor));
                }
                (crate::ir::BinOp::Sar, _, _) | (crate::ir::BinOp::Add, _, _) => return None,
                _ => return None,
            },
            _ => return None,
        }
    }
    None
}

/// Recognizes the 32-bit signed chain: a widening multiply, register copies,
/// the sign flag `p >> 63`, the high half `p >> 32`, then their sum.
pub(crate) fn signed_chain(
    statements: &[Stmt],
    start: usize,
    dest_index: u16,
    magic: u64,
    domain_bits: u64,
) -> Option<(usize, Vec<usize>, u64)> {
    let mut aliases: std::collections::HashSet<u16> = {
        let mut set = std::collections::HashSet::new();
        set.insert(dest_index);
        set
    };
    let mut sign_register: Option<u16> = None;
    let mut steps: Vec<usize> = vec![start];

    for position in start + 1..start + 7 {
        let Some(next) = statements.get(position) else {
            return None;
        };
        let Some((dest_ref, value)) = assignment(next) else {
            return None;
        };
        let dest_index = dest_ref.index;
        if let Some((source, shift)) = shift_of(value) {
            if aliases.contains(&source) && shift == 63 && sign_register.is_none() {
                if dest_index == source {
                    aliases.remove(&source);
                }
                sign_register = Some(dest_index);
                steps.push(position);
                continue;
            }
            if aliases.contains(&source) && shift == 32 && sign_register.is_some() {
                if dest_index == source {
                    aliases.remove(&source);
                }
                steps.push(position);
                let Some(divisor) = magic_divisor_signed(magic, domain_bits)
                    .or_else(|| magic_divisor_signed(magic, 32))
                else {
                    return None;
                };
                // The sum must be the very next statement.
                if let Some(next) = statements.get(position + 1)
                    && let Some((_, sum_value)) = assignment(next)
                {
                    let sum_value = strip_and_mask(sum_value);
                    let matching_sum_divisor = |value: &Expr| {
                        let Expr::Bin {
                            op: crate::ir::BinOp::Add,
                            lhs,
                            rhs,
                        } = value
                        else {
                            return None;
                        };
                        let left = unwrap_leaf(lhs.as_ref());
                        let right = unwrap_leaf(rhs.as_ref());
                        let pair = matches!((left, right), (Some(a), Some(b))
                                if (Some(a) == sign_register || Some(b) == sign_register));
                        pair.then_some(divisor)
                    };
                    if let Some(divisor) = matching_sum_divisor(sum_value) {
                        return Some((position + 1, steps, divisor));
                    }
                }
                return None;
            }
            return None;
        }
        if let Expr::Reg { index: copied, .. } = value {
            if aliases.contains(copied) && dest_index != *copied {
                aliases.insert(dest_index);
                steps.push(position);
                continue;
            }
            return None;
        }
        return None;
    }
    None
}

use crate::ir::visit::assign_of;
use crate::ir::visit::assignment_at;
use crate::ir::{Expr, Stmt};
use crate::passes::division::chain_dividend_domain;
use crate::passes::division::dividend_parameter;
use crate::passes::division::strip_and_mask;
use crate::passes::division::unwrap_leaf;

/// Signed `x % 2^k` emitted as `neg t, x` / `and m, x, mask` /
/// `and t, t, mask` / `csneg r, m, t, mi`. The select's condition tests the
/// negated dividend's sign. Returns the steps to drop, the divisor, and the
/// dividend register and width.
pub(crate) fn cs_neg_chain(
    statements: &[Stmt],
    select_index: usize,
) -> Option<(Vec<usize>, u64, u16, u8)> {
    let Some((_, sel_value)) = assignment_at(statements, select_index) else {
        return None;
    };
    let Expr::Select {
        cond,
        lhs: cmp_lhs,
        rhs: cmp_rhs,
        then,
        els,
    } = sel_value
    else {
        return None;
    };
    // The condition tests the sign of the dividend's negation (`negs`),
    // as `0 - x < 0` or as the flags of comparing 0 with `x`.
    use crate::ir::Cond;
    let (negative, negation) = match (cond, cmp_lhs.as_ref(), cmp_rhs.as_ref()) {
        (Cond::Mi | Cond::Pl, Expr::Const(0), dividend) => (*cond == Cond::Mi, dividend),
        (
            Cond::Lt | Cond::Ge,
            Expr::Bin {
                op: crate::ir::BinOp::Sub,
                lhs,
                rhs,
            },
            Expr::Const(0),
        ) if matches!(lhs.as_ref(), Expr::Const(0)) => (*cond == Cond::Lt, rhs.as_ref()),
        _ => return None,
    };
    let Expr::Reg {
        index: dividend,
        width,
    } = strip_and_mask(negation)
    else {
        return None;
    };
    let (dividend, width) = (*dividend, *width);
    let negated_leaf = |expr: &Expr| -> Option<u16> {
        match expr {
            Expr::Bin {
                op: crate::ir::BinOp::Sub,
                lhs,
                rhs,
            } if matches!(lhs.as_ref(), Expr::Const(0)) => unwrap_leaf(strip_and_mask(rhs)),
            _ => None,
        }
    };
    let (plain, negated) = if negative { (then, els) } else { (els, then) };
    let Some(plain_leaf) = unwrap_leaf(strip_and_mask(plain)) else {
        return None;
    };
    let Some(negated_leaf) = negated_leaf(negated) else {
        return None;
    };
    let defining = |index: u16| -> Option<usize> {
        for probe in (0..select_index).rev() {
            let Some((dest, _)) = assignment_at(statements, probe) else {
                continue;
            };
            if dest.index == index {
                return Some(probe);
            }
        }
        None
    };
    let masked = |index: u16| -> Option<(usize, u64, u16)> {
        let probe = defining(index)?;
        let value = strip_and_mask(assignment_at(statements, probe)?.1);
        let Expr::Bin {
            op: crate::ir::BinOp::And,
            lhs,
            rhs,
        } = value
        else {
            return None;
        };
        let Expr::Const(mask) = rhs.as_ref() else {
            return None;
        };
        let Expr::Reg { index: source, .. } = strip_and_mask(lhs) else {
            return None;
        };
        Some((probe, *mask, *source))
    };
    let (plain_pos, plain_mask, plain_source) = masked(plain_leaf)?;
    let (negated_pos, negated_mask, negated_source) = masked(negated_leaf)?;
    if plain_mask != negated_mask {
        return None;
    }
    let divisor = plain_mask.wrapping_add(1);
    if divisor == 0 || !divisor.is_power_of_two() {
        return None;
    }
    // The negated branch's mask source may itself be re-masked; find the
    // `0 - x` that defines it.
    let (neg_pos, neg_source) = (0..negated_pos).rev().find_map(|probe| {
        let (dest, value) = assignment_at(statements, probe)?;
        if dest.index != negated_source {
            return None;
        }
        match strip_and_mask(value) {
            Expr::Bin {
                op: crate::ir::BinOp::Sub,
                lhs,
                rhs,
            } if matches!(lhs.as_ref(), Expr::Const(0)) => {
                let source = unwrap_leaf(strip_and_mask(rhs))?;
                Some((probe, source))
            }
            _ => None,
        }
    })?;
    let root_plain = dividend_parameter(statements, select_index, plain_source);
    let root_neg = dividend_parameter(statements, select_index, neg_source);
    if root_plain != dividend || root_neg != dividend {
        return None;
    }
    Some((
        vec![plain_pos, negated_pos, neg_pos],
        divisor,
        dividend,
        width,
    ))
}

/// Signed `x % 2^k` as `x - (select(x >= 0, x, x + (2^k - 1)) & -2^k)`.
/// Returns (sub position, select position, adjusted definition, divisor,
/// dividend, domain bits).
pub(crate) fn signed_select_mod_chain(
    statements: &[Stmt],
) -> Option<(usize, usize, Option<usize>, u64, Expr, u64)> {
    for sub_index in 0..statements.len() {
        let Some((_, sub_value)) = assign_of(&statements[sub_index]) else {
            continue;
        };
        let sub_value = strip_and_mask(sub_value);
        let Expr::Bin {
            op: crate::ir::BinOp::Sub,
            lhs,
            rhs,
        } = sub_value
        else {
            continue;
        };
        let Some(masked_reg) = unwrap_leaf(strip_and_mask(rhs)) else {
            continue;
        };
        let Some(and_index) = (0..sub_index).rev().take(4).find(|position| {
            assign_of(&statements[*position])
                .map(|(dest, _)| dest.index == masked_reg)
                .unwrap_or(false)
        }) else {
            continue;
        };
        let Some((_, and_value)) = assign_of(&statements[and_index]) else {
            continue;
        };
        let Expr::Bin {
            op: crate::ir::BinOp::And,
            lhs: masked,
            rhs: mask,
        } = strip_and_mask(and_value)
        else {
            continue;
        };
        let Expr::Const(mask) = mask.as_ref() else {
            continue;
        };
        // The mask is a negated power of two (`~15`, `~7`).
        let step = mask.wrapping_neg();
        if step == 0 || !step.is_power_of_two() {
            continue;
        }
        let Some(select_src) = unwrap_leaf(strip_and_mask(masked)) else {
            continue;
        };
        let Some(select_index) = (0..and_index).rev().take(4).find(|position| {
            assign_of(&statements[*position])
                .map(|(dest, _)| dest.index == select_src)
                .unwrap_or(false)
        }) else {
            continue;
        };
        let Some((_, select_value)) = assign_of(&statements[select_index]) else {
            continue;
        };
        let select_value = strip_and_mask(select_value);
        let Expr::Select {
            cond,
            rhs: zero,
            then,
            els,
            ..
        } = select_value
        else {
            continue;
        };
        if !matches!(cond, crate::ir::Cond::Ge | crate::ir::Cond::Lt)
            || !matches!(zero.as_ref(), Expr::Const(0))
        {
            continue;
        }
        let (plain, adjusted) = match cond {
            crate::ir::Cond::Ge => (then, els),
            _ => (els, then),
        };
        let leaf = strip_and_mask(plain).clone();
        let Expr::Reg {
            index: leaf_reg, ..
        } = leaf
        else {
            continue;
        };
        // The adjusted branch may be a register defined just before the select.
        let mut adjusted_def = None;
        let adjusted = match strip_and_mask(adjusted) {
            Expr::Reg { index, .. } => (0..select_index).rev().take(4).find_map(|position| {
                assign_of(&statements[position]).and_then(|(dest, value)| {
                    (dest.index == *index).then(|| {
                        adjusted_def = Some(position);
                        strip_and_mask(value)
                    })
                })
            })?,
            adjusted => adjusted,
        };
        let Expr::Bin {
            op: crate::ir::BinOp::Add,
            lhs: arm,
            rhs: delta,
        } = adjusted
        else {
            continue;
        };
        let Expr::Reg { index: arm_reg, .. } = strip_and_mask(arm) else {
            continue;
        };
        let Expr::Const(delta) = delta.as_ref() else {
            continue;
        };
        if delta.wrapping_add(1) != step {
            continue;
        }
        let root_plain = dividend_parameter(statements, select_index, leaf_reg);
        let root_arm = dividend_parameter(statements, select_index, *arm_reg);
        let Some(sub_leaf) = unwrap_leaf(strip_and_mask(lhs)) else {
            continue;
        };
        let root_sub = dividend_parameter(statements, sub_index, sub_leaf);
        if root_plain != root_arm || root_plain != root_sub {
            continue;
        }
        let domain = if matches!(
            leaf,
            Expr::Bin {
                op: crate::ir::BinOp::And,
                ..
            }
        ) {
            32
        } else {
            chain_dividend_domain(statements, select_index, &leaf)
        };
        return Some((sub_index, select_index, adjusted_def, step, leaf, domain));
    }
    None
}

/// Signed `x / 2^k` as `(x >= 0 ? x : x + (2^k - 1)) >> k`; the adjusted
/// value usually comes from a preceding `lea`.
pub(crate) fn signed_select_chain(
    statements: &[Stmt],
) -> Option<(usize, usize, Option<usize>, u64, Expr, u64)> {
    for sar_index in 0..statements.len() {
        let Some((sar_dest, value)) = assign_of(&statements[sar_index]) else {
            continue;
        };
        let sar_width = sar_dest.width;
        let value = strip_and_mask(value);
        let Expr::Bin {
            op: crate::ir::BinOp::Sar,
            lhs,
            rhs,
        } = value
        else {
            continue;
        };

        let (src, src_width, shift) = match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Reg { index, width }, Expr::Const(k)) => (index, *width, k),
            _ => continue,
        };
        if *shift == 0 || *shift >= 64 {
            continue;
        }
        let select_index = (0..sar_index).rev().take(4).find(|position| {
            assign_of(&statements[*position]).is_some_and(|(dest, _)| dest.index == *src)
        })?;
        let Some((_, select_value)) = assign_of(&statements[select_index]) else {
            continue;
        };
        let select_value = strip_and_mask(select_value);
        let Expr::Select {
            cond,
            lhs: _,
            rhs,
            then,
            els,
        } = select_value
        else {
            continue;
        };
        if !matches!(cond, crate::ir::Cond::Ge | crate::ir::Cond::Lt)
            || !matches!(rhs.as_ref(), Expr::Const(0))
        {
            continue;
        }
        let (plain, adjusted) = match cond {
            crate::ir::Cond::Ge => (then, els),
            _ => (els, then),
        };
        let leaf = strip_and_mask(plain);
        // The adjusted branch may be a register defined by the preceding `lea`.
        let mut adjusted_def = None;
        let adjusted = match strip_and_mask(adjusted) {
            Expr::Reg { index, .. } => {
                let resolved = (0..select_index).rev().take(4).find_map(|position| {
                    assign_of(&statements[position]).and_then(|(dest, value)| {
                        (dest.index == *index).then(|| {
                            adjusted_def = Some(position);
                            strip_and_mask(value)
                        })
                    })
                });
                match resolved {
                    Some(value) => value,
                    None => continue,
                }
            }
            adjusted => adjusted,
        };
        let (add_index, delta) = match adjusted {
            Expr::Bin {
                op: crate::ir::BinOp::Add,
                lhs: arm,
                rhs,
            } => {
                let arm = strip_and_mask(arm);
                match (arm, rhs.as_ref()) {
                    (Expr::Reg { index, .. }, Expr::Const(delta)) => (index, delta),
                    _ => continue,
                }
            }
            _ => continue,
        };
        // Both branches must trace back to the same dividend register.
        let Expr::Reg {
            index: leaf_reg, ..
        } = leaf
        else {
            continue;
        };
        let root_plain = dividend_parameter(statements, select_index, *leaf_reg);
        let root_adjusted = dividend_parameter(statements, select_index, *add_index);
        if root_plain != root_adjusted {
            continue;
        }
        let shift_delta = delta.wrapping_add(1);
        if shift_delta == 0 || !shift_delta.is_power_of_two() {
            continue;
        }
        // The shift runs at the dividend's width, so a 32-bit source or
        // result proves a 32-bit dividend even behind a zero-extension mask.
        let domain = if src_width == 32 || sar_width == 32 {
            32
        } else {
            match leaf {
                Expr::Bin {
                    op: crate::ir::BinOp::And,
                    ..
                } => 32,
                _ => chain_dividend_domain(statements, select_index, leaf),
            }
        };
        return Some((
            sar_index,
            select_index,
            adjusted_def,
            1u64 << shift,
            leaf.clone(),
            domain,
        ));
    }
    None
}

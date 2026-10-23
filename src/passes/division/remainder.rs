use crate::ir::visit::assign_of;
use crate::ir::visit::assignment_at;
use crate::ir::visit::statement_registers;
use crate::ir::{Expr, Stmt};
use crate::passes::division::dividend_parameter;
use crate::passes::division::remainder;
use crate::passes::division::strip_and_mask;
use crate::passes::division::unwrap_leaf;

/// True when every read of `reg` from `from` on is part of a remainder tail
/// (masks, then one `x - q * d`), which the rewrite collapses into `%`.
pub(crate) fn remainder_tail(stmts: &[Stmt], from: usize, reg: u16) -> bool {
    let mut unwound = false;
    for stmt in &stmts[from..] {
        let (_, reads) = statement_registers(stmt);
        if !reads.contains(&reg) {
            if unwound {
                continue;
            }
            continue;
        }
        if unwound {
            return false;
        }
        match tail_shape(stmt) {
            Some(true) => unwound = true,
            Some(false) => {}
            None => return false,
        }
    }
    unwound
}

/// `Some(true)` for the `x - q * d` unwind, `Some(false)` for a chain-tail
/// statement that only re-masks or sign-corrects the quotient.
fn tail_shape(stmt: &Stmt) -> Option<bool> {
    let Stmt::Assign { value, .. } = stmt else {
        return None;
    };
    match strip_and_mask(value) {
        Expr::Bin {
            op: crate::ir::BinOp::Sub,
            rhs,
            ..
        } => match strip_and_mask(rhs) {
            Expr::Bin {
                op: crate::ir::BinOp::Mul,
                ..
            } => Some(true),
            _ => None,
        },
        // `q & mask` and `(t + (t >> k)) & mask` are the chain's own tail.
        Expr::Bin {
            op: crate::ir::BinOp::And,
            ..
        } => Some(false),
        _ => None,
    }
}

/// Matches `x - (x / d) * d` after the widening product at `start`: quotient
/// shifts and copies, the multiply back by `d`, and the closing subtract.
/// Returns (sub position, steps to drop, divisor, signed, result width).
pub(crate) fn remainder_scan(
    statements: &[Stmt],
    start: usize,
    dest_index: u16,
) -> Option<(usize, Vec<usize>, u64, bool, u64)> {
    // The dividend register is read after the product too (sign flag,
    // subtract) but never joins the alias set.
    let dividend_reg = unwrap_leaf(
        statements
            .get(start)
            .and_then(assign_of)
            .map_or(&Expr::Const(0), |(_, value)| value),
    );
    let mut aliases: Vec<u16> = vec![dest_index];
    let mut signed = false;
    let mut factor: u64 = 1;
    let mut consumed: Vec<usize> = Vec::new();
    let mut position = start;
    let mut half_seen = false;

    for _ in 0..12 {
        position += 1;
        let Some((dest_ref, value)) = assignment_at(statements, position) else {
            return None;
        };

        let dest = dest_ref.index;
        let width = dest_ref.width;
        let value = strip_and_mask(value);
        match value {
            // A zero-extension mask acts as a copy.
            Expr::Bin {
                op: crate::ir::BinOp::And,
                lhs,
                rhs,
            } => {
                let Expr::Const(0xffff_ffff) = rhs.as_ref() else {
                    // Any other mask (e.g. `q & ~1`) changes the quotient;
                    // the plain division rewrite still applies.
                    return None;
                };
                let Expr::Reg { index, .. } = lhs.as_ref() else {
                    return None;
                };
                if !aliases.contains(index) && !is_shift_of(index, &aliases, statements) {
                    return None;
                }
                aliases.push(dest);
                consumed.push(position);
            }
            Expr::Reg { index, .. } => {
                if aliases.contains(index) {
                    aliases.push(dest);
                    consumed.push(position);
                    continue;
                }
                return None;
            }
            // The divisor loaded into a register for `msub` (`mov w9, #0xa`).
            Expr::Const(_) => {
                consumed.push(position);
                continue;
            }
            Expr::Bin { op, lhs, rhs } => match (op, lhs.as_ref(), rhs.as_ref()) {
                // x86-64 one-operand `mul` also writes the low half; unused.
                (crate::ir::BinOp::Mul, Expr::Reg { .. }, Expr::Const(_)) if !half_seen => {
                    half_seen = true;
                    consumed.push(position);
                    continue;
                }
                // `q >> (width - 1)` is the sign flag and makes the chain
                // signed; any other amount is the quotient shift.
                (
                    crate::ir::BinOp::Shr | crate::ir::BinOp::Sar,
                    Expr::Reg { index, .. },
                    Expr::Const(k),
                ) if aliases.contains(index) || dividend_reg == Some(*index) || !half_seen => {
                    if k.checked_add(1) == Some(u64::from(width)) {
                        signed = true;
                        if dest != *index {
                            aliases.push(dest);
                        }
                        consumed.push(position);
                        continue;
                    }
                    aliases.retain(|other| other != &dest);
                    aliases.push(dest);
                    consumed.push(position);
                    continue;
                }
                // Either the sign correction `hi + sign` or a multiply-back
                // step (`q + (q << k)`, `q + q * c`, `q + q`).
                (crate::ir::BinOp::Add, lhs, rhs) => {
                    let lhs = strip_and_mask(lhs);
                    let rhs = strip_and_mask(rhs);
                    let mut alias_ok = |expr: &Expr| -> bool {
                        if let Some(index) = unwrap_leaf(expr) {
                            return aliases.contains(&index);
                        }
                        if let Some((index, bits)) = shift_leaf(expr) {
                            if bits.checked_add(1) == Some(u64::from(width)) {
                                signed = true;
                            }
                            return aliases.contains(&index);
                        }
                        if let Some(index) = self_mul_leaf(expr) {
                            return aliases.contains(&index);
                        }
                        false
                    };
                    if !alias_ok(lhs) || !alias_ok(rhs) {
                        return None;
                    }
                    // `q + (q << k)` / `q + q * c` scales the running factor
                    // by `1 + 2^k` / `1 + c`.
                    if let Some((identity, factor_term)) = multiplier_step(lhs, rhs, &aliases) {
                        let factor_step = if identity {
                            let Some(step) = factor_term.checked_add(1) else {
                                return None;
                            };
                            step
                        } else {
                            factor_term
                        };
                        let Some(next_factor) = factor.checked_mul(factor_step) else {
                            return None;
                        };
                        factor = next_factor;
                        aliases.retain(|other| other != &dest);
                        aliases.push(dest);
                        consumed.push(position);
                        continue;
                    }
                    let both_plain = unwrap_leaf(lhs).zip(unwrap_leaf(rhs));
                    if let Some((a, b)) = both_plain
                        && a == b
                        && aliases.contains(&a)
                    {
                        let Some(next_factor) = factor.checked_mul(2) else {
                            return None;
                        };
                        factor = next_factor;
                        aliases.retain(|other| other != &dest);
                        aliases.push(dest);
                        consumed.push(position);
                        continue;
                    }
                    // Otherwise this is the sign correction `hi + sign`.
                    if dest != aliases.last().copied().unwrap_or(dest) {
                        aliases.push(dest);
                    }
                    consumed.push(position);
                    continue;
                }
                (crate::ir::BinOp::Mul, Expr::Reg { index, .. }, Expr::Const(d)) => {
                    // A standalone `q * d` read by the closing subtract.
                    if !aliases.contains(index) {
                        return None;
                    }
                    let Some(next_factor) = factor.checked_mul(*d) else {
                        return None;
                    };
                    factor = next_factor;
                    aliases.retain(|other| other != &dest);
                    aliases.push(dest);
                    consumed.push(position);
                    continue;
                }
                // The closing subtract reads the multiplied-back quotient,
                // either a chain register or `msub`'s `q * d`.
                (crate::ir::BinOp::Sub, _lhs, rhs) => {
                    let rhs = strip_and_mask(rhs);
                    let accu = match rhs {
                        Expr::Reg { .. } => unwrap_leaf(rhs),
                        Expr::Bin {
                            op: crate::ir::BinOp::Mul,
                            lhs,
                            ..
                        } => unwrap_leaf(strip_and_mask(lhs)),
                        _ => None,
                    };
                    let Some(accu) = accu else {
                        return None;
                    };
                    if factor < 2 || !aliases.contains(&accu) {
                        return None;
                    }
                    return Some((position, consumed, factor, signed, width as u64));
                }
                _ => return None,
            },
            _ => return None,
        }
    }
    None
}

/// True when `index` is a chain register or the destination of any left shift
/// in the block.
fn is_shift_of(index: &u16, aliases: &[u16], statements: &[Stmt]) -> bool {
    aliases.contains(index)
        || statements.iter().any(|stmt| match assign_of(stmt) {
            Some((
                dest,
                Expr::Bin {
                    op: crate::ir::BinOp::Shl,
                    ..
                },
            )) => dest.index == *index,
            _ => false,
        })
}

/// The register of `reg * const`.
fn self_mul_leaf(expr: &Expr) -> Option<u16> {
    let Expr::Bin {
        op: crate::ir::BinOp::Mul,
        lhs,
        rhs,
    } = expr
    else {
        return None;
    };
    let Expr::Const(_) = rhs.as_ref() else {
        return None;
    };
    unwrap_leaf(strip_and_mask(lhs))
}

/// The register and amount of a constant shift; the amount lets inline sign
/// flags be detected.
fn shift_leaf(expr: &Expr) -> Option<(u16, u64)> {
    let Expr::Bin {
        op: crate::ir::BinOp::Shl | crate::ir::BinOp::Shr | crate::ir::BinOp::Sar,
        lhs,
        rhs,
    } = expr
    else {
        return None;
    };
    let Expr::Const(bits) = rhs.as_ref() else {
        return None;
    };
    unwrap_leaf(strip_and_mask(lhs)).map(|index| (index, *bits))
}

/// One multiply-back step, `q + (q << k)` or `q + q * c`, with both operands
/// reading the same chain register. Returns `2^k` or `c`; the flag is always
/// true because the plain `q` term is present.
fn multiplier_step(lhs: &Expr, rhs: &Expr, aliases: &[u16]) -> Option<(bool, u64)> {
    let operand_factor = |expr: &Expr| -> Option<(u16, u64)> {
        match strip_and_mask(expr) {
            Expr::Bin {
                op: crate::ir::BinOp::Shl,
                lhs: base,
                rhs,
            } => {
                let Expr::Const(bits) = rhs.as_ref() else {
                    return None;
                };
                let Some(leaf) = unwrap_leaf(strip_and_mask(base)) else {
                    return None;
                };
                let Ok(bits) = u32::try_from(*bits) else {
                    return None;
                };
                1u64.checked_shl(bits).map(|factor| (leaf, factor))
            }
            Expr::Bin {
                op: crate::ir::BinOp::Mul,
                lhs: base,
                rhs,
            } => {
                let Expr::Const(value) = rhs.as_ref() else {
                    return None;
                };
                let Some(leaf) = unwrap_leaf(strip_and_mask(base)) else {
                    return None;
                };
                Some((leaf, *value))
            }
            _ => None,
        }
    };
    let copy = match operand_factor(rhs) {
        Some((leaf, value)) if unwrap_leaf(strip_and_mask(lhs)) == Some(leaf) => {
            Some((leaf, value, true))
        }
        _ => operand_factor(lhs)
            .filter(|(leaf, _)| unwrap_leaf(strip_and_mask(rhs)) == Some(*leaf))
            .map(|(leaf, value)| (leaf, value, true)),
    };
    let Some(copy) = copy else {
        return None;
    };
    let (leaf, value, _) = copy;
    if !aliases.contains(&leaf) {
        return None;
    }
    Some((true, value))
}

/// Extends already recorded division rewrites: a quotient `q = x / d` followed
/// by `x - (q + (q << k))` or `x - q * d` turns the subtract into `x % d`.
pub(crate) fn apply_remainder_follows(
    statements: &[Stmt],
    consumed: &mut std::collections::HashSet<usize>,
    replacements: &mut Vec<(usize, Expr)>,
    domains: &mut std::collections::HashSet<(u16, bool)>,
    narrowed: &mut Vec<(u16, bool)>,
    _wide_signed: &mut std::collections::HashSet<u16>,
    wide_signed_ret: &mut Vec<u16>,
) {
    let divisions: Vec<(usize, u64, bool, Expr)> = replacements
        .iter()
        .filter_map(|(position, expr)| match expr {
            Expr::Bin {
                op: crate::ir::BinOp::DivU,
                lhs,
                rhs,
            }
            | Expr::Bin {
                op: crate::ir::BinOp::DivS,
                lhs,
                rhs,
            } => {
                let unsigned = matches!(
                    expr,
                    Expr::Bin {
                        op: crate::ir::BinOp::DivU,
                        ..
                    }
                );
                let Expr::Const(divisor) = rhs.as_ref() else {
                    return None;
                };
                Some((*position, *divisor, unsigned, lhs.as_ref().clone()))
            }
            _ => None,
        })
        .collect();
    for (div_position, divisor, unsigned, dividend) in divisions {
        // Only one-step unwinds; `remainder_scan` handles multi-step ones.
        let unwind: Option<(usize, usize)> = single_mult_follow(statements, div_position, divisor)
            .or_else(|| direct_msub_follow(statements, div_position, divisor));
        let Some((mult_position, sub_position)) = unwind else {
            continue;
        };
        let leaf = remainder_leaf(&statements[sub_position]);
        // `x - q * d` is a remainder only of the value `q` divided.
        if !same_value(statements, div_position, &dividend, sub_position, &leaf) {
            continue;
        }
        let Some(replacement) = super::proof::checked(
            statements,
            div_position,
            sub_position,
            remainder(leaf.clone(), divisor, unsigned),
        ) else {
            continue;
        };
        consumed.insert(mult_position);
        // Retype the signature as for the chains `remainder_scan` matches.
        if let (Expr::Reg { width, .. }, Some((sub_dest, _))) =
            (&leaf, assignment_at(statements, sub_position))
        {
            if *width == 32 {
                let root = dividend_parameter(statements, div_position, 0);
                domains.insert((root, !unsigned));
                narrowed.push((sub_dest.index, !unsigned));
            } else if !unsigned {
                wide_signed_ret.push(sub_dest.index);
            }
        }
        replacements.push((sub_position, replacement));
    }
}

/// The register holding `expr` at `position`, followed back through plain
/// copies, with the statement that last defined it (`None` for the entry).
fn origin(statements: &[Stmt], position: usize, expr: &Expr) -> Option<(u16, Option<usize>)> {
    let mut register = unwrap_leaf(strip_and_mask(expr))?;
    let mut position = position;
    loop {
        let defined = statements[..position]
            .iter()
            .rposition(|stmt| matches!(assign_of(stmt), Some((dest, _)) if dest.index == register));
        let Some(at) = defined else {
            return Some((register, None));
        };
        let (_, value) = assign_of(&statements[at]).expect("an assignment");
        match unwrap_leaf(strip_and_mask(value)) {
            Some(source) if matches!(strip_and_mask(value), Expr::Reg { .. }) => {
                register = source;
                position = at;
            }
            _ => return Some((register, Some(at))),
        }
    }
}

/// Whether `a` read at `at_a` and `b` read at `at_b` hold the same value.
pub(crate) fn same_value(
    statements: &[Stmt],
    at_a: usize,
    a: &Expr,
    at_b: usize,
    b: &Expr,
) -> bool {
    match (origin(statements, at_a, a), origin(statements, at_b, b)) {
        (Some(left), Some(right)) => left == right,
        _ => a == b,
    }
}

/// The `msub`-lifted form: `x - (q * d)` in a single statement where `q`
/// reads the chain's own quotient register. `d` may be a literal or the
/// register assignment that carries it between the rewrite and the subtract.
fn direct_msub_follow(
    statements: &[Stmt],
    div_position: usize,
    divisor: u64,
) -> Option<(usize, usize)> {
    let Some(div_dest) = assignment_at(statements, div_position).map(|(dest, _)| dest.index) else {
        return None;
    };
    // Skip the divisor's register load and re-masks; the next statement must
    // be the subtract.
    let mut sub_position = None;
    for probe in 1..8 {
        let Some(stmt) = statements.get(div_position + probe) else {
            break;
        };
        let Some((_, value)) = assign_of(stmt) else {
            break;
        };
        if matches!(value, Expr::Const(_)) {
            continue;
        }
        if matches!(tail_shape(stmt), Some(false)) {
            continue;
        }
        sub_position = Some(div_position + probe);
        break;
    }
    let Some(sub_position) = sub_position else {
        return None;
    };
    let Some((_, sub_value)) = assignment_at(statements, sub_position) else {
        return None;
    };
    let sub_value = strip_and_mask(sub_value);
    let Expr::Bin {
        op: crate::ir::BinOp::Sub,
        rhs,
        ..
    } = sub_value
    else {
        return None;
    };
    let rhs = strip_and_mask(rhs);
    let Expr::Bin {
        op: crate::ir::BinOp::Mul,
        lhs,
        rhs: rhs2,
    } = rhs
    else {
        return None;
    };
    let factor = match strip_and_mask(rhs2) {
        Expr::Const(value) => *value,
        Expr::Reg { index, .. } => {
            let mut resolved = None;
            for probe in (div_position.saturating_sub(2)..sub_position).rev() {
                if let Some((dest, Expr::Const(value))) = assignment_at(statements, probe)
                    && dest.index == *index
                {
                    resolved = Some(*value);
                    break;
                }
            }
            let Some(value) = resolved else {
                return None;
            };
            value
        }
        _ => return None,
    };
    if factor != divisor {
        return None;
    }
    let Some(accu) = unwrap_leaf(strip_and_mask(lhs)) else {
        return None;
    };
    if accu != div_dest {
        return None;
    }
    Some((div_position, sub_position))
}

/// Matches `t = q + (q << k)` with `d == 1 + 2^k` right after the quotient,
/// then the subtract `x - t`.
fn single_mult_follow(
    statements: &[Stmt],
    div_position: usize,
    divisor: u64,
) -> Option<(usize, usize)> {
    let Some(div_dest) = assignment_at(statements, div_position).map(|(dest, _)| dest.index) else {
        return None;
    };
    let mult_position = div_position + 1;
    let Some((step_dest_ref, step_value)) = assignment_at(statements, mult_position) else {
        return None;
    };
    let step_value = strip_and_mask(step_value);
    let (lhs, rhs) = match step_value {
        Expr::Bin {
            op: crate::ir::BinOp::Add,
            lhs,
            rhs,
        } => (lhs.as_ref(), rhs.as_ref()),
        _ => return None,
    };
    let (plain, shifted) = if matches!(
        rhs,
        Expr::Bin {
            op: crate::ir::BinOp::Shl,
            ..
        }
    ) {
        (lhs, rhs)
    } else if matches!(
        lhs,
        Expr::Bin {
            op: crate::ir::BinOp::Shl,
            ..
        }
    ) {
        (rhs, lhs)
    } else {
        return None;
    };
    let Expr::Bin {
        op: crate::ir::BinOp::Shl,
        lhs: shift_base,
        rhs: shift_amount,
    } = shifted
    else {
        return None;
    };
    let Expr::Const(bits) = shift_amount.as_ref() else {
        return None;
    };
    let plain_leaf = unwrap_leaf(strip_and_mask(plain));
    let shift_leaf = unwrap_leaf(strip_and_mask(shift_base));
    let Some(plain_leaf) = plain_leaf else {
        return None;
    };
    let Some(shift_leaf) = shift_leaf else {
        return None;
    };
    if plain_leaf != div_dest || shift_leaf != div_dest {
        return None;
    }
    let Ok(bits) = u32::try_from(*bits) else {
        return None;
    };
    if 1u64
        .checked_shl(bits)
        .and_then(|factor| factor.checked_add(1))
        != Some(divisor)
    {
        return None;
    }
    let sub_position = mult_position + 1;
    let Some((_, sub_value)) = assignment_at(statements, sub_position) else {
        return None;
    };
    let sub_value = strip_and_mask(sub_value);
    let Expr::Bin {
        op: crate::ir::BinOp::Sub,
        rhs: sub_rhs,
        ..
    } = sub_value
    else {
        return None;
    };
    let Some(accu) = unwrap_leaf(strip_and_mask(sub_rhs)) else {
        return None;
    };
    if accu != step_dest_ref.index && accu != div_dest {
        return None;
    }
    Some((mult_position, sub_position))
}

/// The `x` of a remainder's `x - ...` subtract; `0` if the statement is not a
/// subtract.
pub(crate) fn remainder_leaf(stmt: &Stmt) -> Expr {
    match assign_of(stmt) {
        Some((_, value)) => {
            let value = strip_and_mask(value);
            if let Expr::Bin {
                op: crate::ir::BinOp::Sub,
                lhs,
                ..
            } = value
            {
                strip_and_mask(lhs).clone()
            } else {
                Expr::Const(0)
            }
        }
        None => Expr::Const(0),
    }
}

mod chains;
mod divisor;
mod proof;
mod remainder;
mod select;
mod widened;

#[cfg(test)]
mod smt_tests;

use crate::arch;
use crate::ir::CType;
use crate::ir::visit::assignment;
use crate::ir::visit::assignment_at;
use crate::ir::visit::statement_registers;
use crate::ir::{Expr, FunctionIr, Stmt};
use crate::passes::division::chains::signed_chain;
use crate::passes::division::chains::signed64_chain;
use crate::passes::division::chains::unsigned64_chain;
use crate::passes::division::divisor::magic_divisor;
use crate::passes::division::divisor::magic_matches;
use crate::passes::division::remainder::apply_remainder_follows;
use crate::passes::division::remainder::remainder_leaf;
use crate::passes::division::remainder::remainder_scan;
use crate::passes::division::remainder::remainder_tail;
use crate::passes::division::select::conditional_negation_chain;
use crate::passes::division::select::signed_select_chain;
use crate::passes::division::select::signed_select_mod_chain;
use crate::passes::division::widened::magic_product;
use crate::passes::division::widened::widened_signed_site;

/// Rewrites division and remainder by a constant (multiply by a magic number,
/// then shift) back to `x / d` and `x % d` when the constants prove the result
/// exact over the dividend's domain, and adjusts parameter and return types to
/// that domain.
pub fn recover_divisions(ir: &mut FunctionIr) {
    let mut domains: std::collections::HashSet<(u16, bool)> = std::collections::HashSet::new();
    let mut narrowed: Vec<(u16, bool)> = Vec::new();
    // Signed 64-bit chains prove an int64 dividend, so these widen instead.
    let mut wide_signed: std::collections::HashSet<u16> = std::collections::HashSet::new();
    let mut wide_signed_return_registers: Vec<u16> = Vec::new();
    for block in &mut ir.blocks {
        magic_block(
            block,
            &mut domains,
            &mut narrowed,
            &mut wide_signed,
            &mut wide_signed_return_registers,
        );
    }
    // A 32-bit quotient written to the return register proves a 32-bit return.
    for (dest_index, signed) in narrowed.drain(..) {
        if reaches_return(ir, dest_index)
            && (ir.ret_type == CType::U64 || ir.ret_type == CType::I64)
        {
            ir.ret_type = if signed { CType::I32 } else { CType::U32 };
        }
    }
    // A signed 64-bit quotient written to the return register proves an int64 return.
    if wide_signed_return_registers
        .iter()
        .any(|reg| reaches_return(ir, *reg))
    {
        ir.ret_type = CType::I64;
    }
    // Retype dividend parameters to the width the chain proved.
    for param in ir.params.iter_mut() {
        for (index, signed) in domains.iter() {
            if *index == param.index && !param.ty.is_pointer() {
                param.ty = if *signed { CType::I32 } else { CType::U32 };
            }
        }
        if wide_signed.contains(&param.index) {
            param.ty = CType::I64;
        }
    }
}

/// True when `reg` is the return register or is copied into it or returned.
fn reaches_return(ir: &FunctionIr, reg: u16) -> bool {
    let is_reg =
        |value: &Expr| matches!(strip_and_mask(value), Expr::Reg { index, .. } if *index == reg);
    reg == arch::RETURN
        || ir
            .blocks
            .iter()
            .flat_map(|block| &block.stmts)
            .any(|stmt| match stmt {
                Stmt::Assign { dest, value } => dest.index == arch::RETURN && is_reg(value),
                Stmt::Ret { value } => is_reg(value),
                _ => false,
            })
}

fn statement_register_dest_or_zero(block: &crate::ir::Block, index: usize) -> u16 {
    assignment_at(&block.stmts, index).map_or(0, |(dest, _)| dest.index)
}

fn magic_block(
    block: &mut crate::ir::Block,
    domains: &mut std::collections::HashSet<(u16, bool)>,
    narrowed: &mut Vec<(u16, bool)>,
    wide_signed: &mut std::collections::HashSet<u16>,
    wide_signed_return_registers: &mut Vec<u16>,
) {
    let mut consumed: std::collections::HashSet<usize> = std::collections::HashSet::new();
    let mut replacements: Vec<(usize, Expr)> = Vec::new();
    let mut index = 0usize;

    // The widened signed division written with named shifts:
    //   x = sext32(a) * m
    //   s = x >> 63      (or the sign of the truncated high half: v >> 31)
    //   x = x >> k
    //   r = (x & 0xffffffff) + (s & 0xffffffff)
    // is `a / d` (ARM64 `smull` plus two shifts).
    if let Some((probe, leaf, divisor)) = widened_signed_site(&block.stmts)
        && let Stmt::Assign { dest, value } = &mut block.stmts[probe]
    {
        let in_return = dest.index == 0;
        *value = division(leaf.clone(), divisor);
        if let Some(param) = operand_index(&leaf) {
            domains.insert((param, true));
        }
        if in_return {
            narrowed.push((0, true));
        }
    }

    // Signed power-of-two division collapses from its sign select; run before
    // the widening-product scans so either shape claims the block cleanly.
    if let Some((sar_index, select_index, adjusted_def, divisor, leaf, domain_bits)) =
        signed_select_chain(block.stmts.as_slice())
    {
        // Check uses of the select's result, not the dividend: the dividend
        // stays live in the rewritten expression.
        let select_src = statement_register_dest_or_zero(block, select_index);
        if single_use(block.stmts.as_slice(), select_index, sar_index, select_src)
            && dropped_dest_safe(
                block.stmts.as_slice(),
                select_index,
                sar_index,
                select_index,
            )
        {
            if let Some(param) = operand_index(&leaf) {
                let root = dividend_parameter(block.stmts.as_slice(), select_index, param);
                if domain_bits == 32 {
                    domains.insert((root, true));
                } else {
                    wide_signed.insert(root);
                }
            }
            let sar_dst = statement_register_dest_or_zero(block, sar_index);
            if domain_bits == 32 {
                narrowed.push((sar_dst, true));
            } else {
                wide_signed_return_registers.push(sar_dst);
            }
            consumed.insert(select_index);
            if let Some(def) = adjusted_def {
                consumed.insert(def);
            }
            // A 32-bit dividend divides as a 32-bit value, whatever the
            // register's upper half holds.
            let dividend = match (domain_bits, &leaf) {
                (32, Expr::Reg { index, .. }) => Expr::bin(
                    crate::ir::BinOp::And,
                    Expr::reg(*index, 64),
                    Expr::Const(0xffff_ffff),
                ),
                _ => leaf.clone(),
            };
            replacements.push((sar_index, division(dividend, divisor)));
        }
    }

    // Signed `x % 2^k` via `csneg`: a select over masked and negated-masked
    // values.
    for probe in 0..block.stmts.len() {
        if consumed.contains(&probe) {
            continue;
        }
        let Some((dest, value)) = assignment(&block.stmts[probe]) else {
            continue;
        };
        if !matches!(value, Expr::Select { .. }) {
            continue;
        }
        let Some((steps, divisor, dividend, width)) =
            conditional_negation_chain(block.stmts.as_slice(), probe)
        else {
            continue;
        };
        if !proof::equivalent(
            &block.stmts,
            probe,
            &remainder(Expr::reg(dividend, width), divisor, false),
        ) {
            continue;
        }
        // Every register the chain drops must be dead afterwards: only the
        // select (rewritten in place) and the chain's own steps may read it.
        let safe = steps.iter().all(|step| {
            let Some((dest, _)) = assignment(&block.stmts[*step]) else {
                return false;
            };
            block.stmts.iter().enumerate().all(|(offset, other)| {
                if offset == probe || offset == *step || steps.contains(&offset) {
                    return true;
                }
                if matches!(other, Stmt::Ret { .. }) {
                    return true;
                }
                let (_, reads) = statement_registers(other);
                !reads.contains(&dest.index)
            })
        });
        if !safe {
            continue;
        }
        for step in steps {
            consumed.insert(step);
        }
        let leaf = Expr::Reg {
            index: dividend,
            width,
        };
        if width == 32 {
            domains.insert((dividend, true));
            narrowed.push((dest.index, true));
        } else {
            wide_signed.insert(dividend);
            wide_signed_return_registers.push(dest.index);
        }
        replacements.push((probe, remainder(leaf, divisor, false)));
    }

    // Signed power-of-two modulus: `x - (select(x >= 0, x, x + d) & ~d)`
    // is one exact `% d`. It shares the division shape's sign select.
    if let Some((sub_index, select_index, adjusted_def, divisor, leaf, domain_bits)) =
        signed_select_mod_chain(block.stmts.as_slice())
    {
        let select_src = statement_register_dest_or_zero(block, select_index);
        if single_use(block.stmts.as_slice(), select_index, sub_index, select_src)
            && dropped_dest_safe(
                block.stmts.as_slice(),
                select_index,
                sub_index,
                select_index,
            )
        {
            if let Some(param) = operand_index(&leaf) {
                let root = dividend_parameter(block.stmts.as_slice(), select_index, param);
                if domain_bits == 32 {
                    domains.insert((root, true));
                } else {
                    wide_signed.insert(root);
                }
            }
            let sub_dst = statement_register_dest_or_zero(block, sub_index);
            if domain_bits == 32 {
                narrowed.push((sub_dst, true));
            } else {
                wide_signed_return_registers.push(sub_dst);
            }
            if let Some(def) = adjusted_def {
                consumed.insert(def);
            }
            replacements.push((sub_index, remainder(leaf, divisor, false)));
        }
    }

    while index < block.stmts.len() {
        if consumed.contains(&index) {
            index += 1;
            continue;
        }
        let Some((dest, value)) = assignment(&block.stmts[index]) else {
            index += 1;
            continue;
        };
        let Some((operand, magic, domain_bits)) = magic_product(value) else {
            index += 1;
            continue;
        };
        // Remainder chain `x - (x / d) * d`, rewritten to `x % d`.
        if let Some((sub_position, chain_steps, divisor, signed, width)) =
            remainder_scan(block.stmts.as_slice(), index, dest.index)
            && magic_matches(magic, divisor, domain_bits, signed)
            && let Some(replacement) = proof::checked(&block.stmts, index, sub_position, remainder(remainder_leaf(&block.stmts[sub_position]), divisor, !signed))
            && single_use(block.stmts.as_slice(), index, sub_position, dest.index)
            // `x - q * d` is a remainder only of the value `q` divided.
            && remainder::same_value(
                block.stmts.as_slice(),
                index,
                &operand,
                sub_position,
                &remainder_leaf(&block.stmts[sub_position]),
            )
        {
            let mut all_safe = true;
            for step in &chain_steps {
                if !dropped_dest_safe(block.stmts.as_slice(), index, sub_position, *step) {
                    all_safe = false;
                    break;
                }
            }
            if all_safe {
                if let Some(param_index) = operand_index(&operand) {
                    let root = dividend_parameter(block.stmts.as_slice(), index, param_index);
                    let sub =
                        assignment_at(&block.stmts, sub_position).map_or(0, |(dest, _)| dest.index);
                    // A zero-extension mask in the unwind proves the
                    // 32-bit domain even when the register is 64-bit.
                    let masked = assignment_at(&block.stmts, sub_position)
                        .map(|(_, value)| !std::ptr::eq(strip_and_mask(value), value))
                        .unwrap_or(false);
                    let width = if masked { 32 } else { width };
                    if width == 32 {
                        domains.insert((root, signed));
                        narrowed.push((sub, signed));
                    } else if signed {
                        wide_signed.insert(root);
                        wide_signed_return_registers.push(sub);
                    }
                }
                consumed.insert(index);
                for step in chain_steps {
                    consumed.insert(step);
                }
                replacements.push((sub_position, replacement));
                index = sub_position + 1;
                continue;
            }
        }

        // Unsigned chain: `p = A * M; r = p >> shift`. A high-part product
        // carries its own 64-bit shift, so the total is `64 + shift`.
        let high_part_product = matches!(
            value,
            Expr::Bin {
                op: crate::ir::BinOp::MulHigh | crate::ir::BinOp::MulHighS,
                ..
            }
        );
        if let Some((divisor, shift_index)) =
            block
                .stmts
                .get(index + 1)
                .and_then(|step| match assignment(step) {
                    Some((_, shr_value)) => {
                        let Some((source, shift)) = shift_of(shr_value) else {
                            return None;
                        };
                        if source != dest.index {
                            return None;
                        }
                        let (total, domain) = if high_part_product {
                            (64 + shift, 64)
                        } else {
                            (shift, domain_bits)
                        };
                        let Some(divisor) = magic_divisor(magic, total, domain)
                            .or_else(|| magic_divisor(magic, shift, 32))
                        else {
                            return None;
                        };
                        Some((divisor, index + 1))
                    }
                    _ => None,
                })
            && let Some(replacement) = proof::checked(
                &block.stmts,
                index,
                shift_index,
                division_unsigned(operand.clone(), divisor),
            )
        {
            if !single_use(block.stmts.as_slice(), index, shift_index, dest.index) {
                index += 1;
                continue;
            }
            // Narrowing only applies where the dividend fits 32 bits.
            if !high_part_product {
                if let Some(index) = operand_index(&operand) {
                    domains.insert((index, false));
                }
                if let Some(dest) = shift_dest_of(block, shift_index) {
                    narrowed.push((dest, false));
                }
            }
            consumed.insert(index);
            replacements.push((shift_index, replacement));
            index = shift_index + 1;
            continue;
        }

        // Unsigned 64-bit chain: the high-part product, then copies and the
        // one-operand `mul`'s low-half write before the final shift.
        if high_part_product
            && let Some((shift_index, chain_steps, divisor)) = unsigned64_chain(
                block.stmts.as_slice(),
                index,
                dest.index,
                magic,
                domain_bits,
            )
            && let Some(replacement) = proof::checked(
                &block.stmts,
                index,
                shift_index,
                division_unsigned(operand.clone(), divisor),
            )
        {
            if !single_use(block.stmts.as_slice(), index, shift_index, dest.index) {
                index += 1;
                continue;
            }
            let all_safe = chain_steps
                .iter()
                .all(|from| dropped_dest_safe(block.stmts.as_slice(), index, shift_index, *from));
            if !all_safe {
                index += 1;
                continue;
            }
            for step in &chain_steps {
                consumed.insert(*step);
            }
            consumed.insert(index);
            replacements.push((shift_index, replacement));
            index = shift_index + 1;
            continue;
        }

        // Signed 64-bit chain: the signed widening multiply plus its
        // sign-flag sum.
        let effective_domain = chain_dividend_domain(block.stmts.as_slice(), index, &operand);
        if let Some((sum_position, chain_steps, divisor)) = signed64_chain(
            block.stmts.as_slice(),
            index,
            dest.index,
            magic,
            effective_domain,
            high_part_product,
        ) && let Some(replacement) = proof::checked(
            &block.stmts,
            index,
            sum_position,
            division(operand.clone(), divisor),
        ) {
            if !single_use(block.stmts.as_slice(), index, sum_position, dest.index) {
                index += 1;
                continue;
            }
            let all_safe = chain_steps
                .iter()
                .all(|from| dropped_dest_safe(block.stmts.as_slice(), index, sum_position, *from));
            if !all_safe {
                index += 1;
                continue;
            }
            if let Some(leaf) = operand_index(&operand) {
                let root = dividend_parameter(block.stmts.as_slice(), index, leaf);
                if effective_domain == 32 {
                    domains.insert((root, true));
                } else {
                    wide_signed.insert(root);
                }
            }
            for step in &chain_steps {
                consumed.insert(*step);
            }
            consumed.insert(index);
            if let Some(stmt) = block.stmts.get(sum_position)
                && let Some((sum_dst, _)) = assignment(stmt)
            {
                if effective_domain == 32 {
                    narrowed.push((sum_dst.index, true));
                } else {
                    wide_signed_return_registers.push(sum_dst.index);
                }
            }
            replacements.push((sum_position, replacement));
            index = sum_position + 1;
            continue;
        }

        // Signed chain: the widening multiply, register copies, a sign flag
        // shift (63), a high-part shift (32), then the 32-bit sum.
        if let Some((sum_position, chain_steps, divisor)) = signed_chain(
            block.stmts.as_slice(),
            index,
            dest.index,
            magic,
            domain_bits,
        ) && let Some(replacement) = proof::checked(
            &block.stmts,
            index,
            sum_position,
            division(operand.clone(), divisor),
        ) {
            if !single_use(block.stmts.as_slice(), index, sum_position, dest.index) {
                index += 1;
                continue;
            }
            let all_safe = chain_steps
                .iter()
                .all(|from| dropped_dest_safe(block.stmts.as_slice(), index, sum_position, *from));
            if !all_safe {
                index += 1;
                continue;
            }
            if let Some(leaf) = operand_index(&operand) {
                domains.insert((leaf, true));
            }
            for step in &chain_steps {
                consumed.insert(*step);
            }
            consumed.insert(index);
            if let Some(stmt) = block.stmts.get(sum_position)
                && let Some((sum_dst, _)) = assignment(stmt)
            {
                narrowed.push((sum_dst.index, true));
            }
            replacements.push((sum_position, replacement));
            index = sum_position + 1;
            continue;
        }

        index += 1;
    }

    apply_remainder_follows(
        block.stmts.as_slice(),
        &mut consumed,
        &mut replacements,
        domains,
        narrowed,
        wide_signed_return_registers,
    );

    if consumed.is_empty() {
        return;
    }
    let mut kept: Vec<Stmt> = Vec::with_capacity(block.stmts.len());
    let mut pending = replacements;
    for (position, stmt) in block.stmts.drain(..).enumerate() {
        if let Some(slot) = pending.iter().position(|(target, _)| *target == position) {
            let (_, value) = pending.remove(slot);
            let mut node = stmt;
            if let Stmt::Assign {
                value: slot_expr, ..
            } = &mut node
            {
                *slot_expr = value;
            }
            kept.push(node);
            continue;
        }
        // Keep reaching definitions until dead-code elimination: a candidate
        // may have other live outputs besides the quotient it replaces.
        kept.push(stmt);
    }
    block.stmts = kept;
}

fn operand_index(operand: &Expr) -> Option<u16> {
    match operand {
        Expr::Reg { index, .. } => Some(*index),
        _ => None,
    }
}

fn shift_dest_of(block: &crate::ir::Block, index: usize) -> Option<u16> {
    block.stmts.get(index).and_then(statement_register_dest)
}

fn statement_register_dest(stmt: &Stmt) -> Option<u16> {
    match stmt {
        Stmt::Assign { dest, .. } => Some(dest.index),
        _ => None,
    }
}

pub(crate) fn leaf_domain(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Reg { width, .. } if *width == 32 || *width == 64 => Some(u64::from(*width)),
        Expr::SignExtend { width: 4, value } => leaf_domain(value),
        Expr::Bin {
            op: crate::ir::BinOp::And,
            lhs,
            rhs,
        } => {
            let Expr::Const(0xffff_ffff) = rhs.as_ref() else {
                return None;
            };
            matches!(**lhs, Expr::Reg { .. }).then_some(32)
        }
        Expr::SignExtend { width, .. } => Some(u64::from(*width) * 8),
        _ => None,
    }
}

pub(crate) fn shift_of(value: &Expr) -> Option<(u16, u64)> {
    let Expr::Bin {
        op: crate::ir::BinOp::Shr,
        lhs,
        rhs,
    } = value
    else {
        return None;
    };
    let Expr::Const(shift) = rhs.as_ref() else {
        return None;
    };
    if *shift >= 64 {
        return None;
    }
    let Some(source) = unwrap_leaf(lhs.as_ref()) else {
        return None;
    };
    Some((source, *shift))
}

pub(crate) fn unwrap_leaf(expr: &Expr) -> Option<u16> {
    match expr {
        Expr::Reg { index, .. } => Some(*index),
        Expr::SignExtend { width: 4, value } => unwrap_leaf(value),
        Expr::Bin {
            op: crate::ir::BinOp::And,
            lhs,
            rhs,
        } => {
            let Expr::Const(0xffff_ffff) = rhs.as_ref() else {
                return None;
            };
            match lhs.as_ref() {
                Expr::Reg { index, .. } => Some(*index),
                _ => unwrap_leaf(lhs.as_ref()),
            }
        }
        _ => None,
    }
}

/// Strips an outer `& 0xffffffff` zero-extension mask.
pub(crate) fn strip_and_mask(expr: &Expr) -> &Expr {
    match expr {
        Expr::Bin {
            op: crate::ir::BinOp::And,
            lhs,
            rhs,
        } => {
            if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) {
                lhs.as_ref()
            } else {
                expr
            }
        }
        _ => expr,
    }
}

/// True when `reg` is not read outside `span_start..=span_end`, except by a
/// return or a remainder tail that the same rewrite collapses.
fn single_use(stmts: &[Stmt], span_start: usize, span_end: usize, reg: u16) -> bool {
    for (position, stmt) in stmts.iter().enumerate() {
        if position >= span_start && position <= span_end {
            continue;
        }
        // A return reads the chain's rewritten output.
        if matches!(stmt, Stmt::Ret { .. }) {
            continue;
        }
        let (_, reads) = statement_registers(stmt);
        if reads.contains(&reg) && !remainder_tail(stmts, position, reg) {
            return false;
        }
    }
    true
}

/// The multiply's operand may be a copy of the real dividend; walk back through
/// register copies, extensions and masks to the register it came from.
pub(crate) fn dividend_parameter(statements: &[Stmt], chain_start: usize, leaf: u16) -> u16 {
    let mut current = leaf;
    for position in (0..chain_start).rev() {
        let Some((dest, value)) = assignment(&statements[position]) else {
            continue;
        };
        if dest.index != current {
            continue;
        }
        let step = match value {
            Expr::Reg { index, .. } if *index != current => Some(*index),
            Expr::SignExtend { value, .. } => match value.as_ref() {
                Expr::Reg { index, .. } => Some(*index),
                _ => None,
            },
            Expr::Bin {
                op: crate::ir::BinOp::And,
                lhs,
                ..
            } => match lhs.as_ref() {
                Expr::Reg { index, .. } => Some(*index),
                _ => None,
            },
            _ => None,
        };
        match step {
            Some(next) if next != current => current = next,
            _ => break,
        }
    }
    current
}

/// The dividend may enter a 64-bit register through a sign or zero extension
/// of a 32-bit value; report the value's true domain for the exactness check.
pub(crate) fn chain_dividend_domain(statements: &[Stmt], chain_start: usize, leaf: &Expr) -> u64 {
    let domain = leaf_domain(leaf).unwrap_or(64);
    if domain == 32 {
        return 32;
    }
    let Expr::Reg { index, .. } = leaf else {
        return domain;
    };
    for position in (0..chain_start).rev() {
        let Some((dest, value)) = assignment(&statements[position]) else {
            continue;
        };
        if dest.index != *index {
            continue;
        }
        return match value {
            Expr::SignExtend { width, .. } => u64::from(*width) * 8,
            Expr::Bin {
                op: crate::ir::BinOp::And,
                rhs,
                ..
            } if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) => 32,
            _ => domain,
        };
    }
    domain
}

pub(crate) fn division(dividend: Expr, divisor: u64) -> Expr {
    Expr::Bin {
        op: crate::ir::BinOp::DivS,
        lhs: Box::new(dividend),
        rhs: Box::new(Expr::Const(divisor)),
    }
}

fn division_unsigned(dividend: Expr, divisor: u64) -> Expr {
    Expr::Bin {
        op: crate::ir::BinOp::DivU,
        lhs: Box::new(dividend),
        rhs: Box::new(Expr::Const(divisor)),
    }
}

pub(crate) fn remainder(dividend: Expr, divisor: u64, unsigned: bool) -> Expr {
    Expr::Bin {
        op: if unsigned {
            crate::ir::BinOp::ModU
        } else {
            crate::ir::BinOp::ModS
        },
        lhs: Box::new(dividend),
        rhs: Box::new(Expr::Const(divisor)),
    }
}

/// True when the destination of the dropped statement at `position` is not
/// read outside `start..=end`, except by a return or a collapsed remainder tail.
fn dropped_dest_safe(statements: &[Stmt], start: usize, end: usize, position: usize) -> bool {
    let Some(stmt) = statements.get(position) else {
        return false;
    };
    let Some((dest, _)) = assignment(stmt) else {
        return false;
    };
    let reg = dest.index;
    for (offset, other) in statements.iter().enumerate() {
        if (offset >= start && offset <= end) || offset == position {
            continue;
        }
        if matches!(other, Stmt::Ret { .. }) {
            continue;
        }
        let (_, reads) = statement_registers(other);
        if reads.contains(&reg) && !remainder_tail(statements, offset, reg) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use crate::analysis::analyze;
    use crate::loader::{Function, Image, Isa};

    fn analyzed(isa: Isa, code: Vec<u8>) -> String {
        let function = Function {
            addr: 0,
            size: Some(code.len() as u64),
            size_estimated: false,
            name: None,
            aliases: Vec::new(),
            library: None,
            sources: Vec::new(),
        };
        let image = Image::from_code(isa, 0, code);
        analyze(&image, &function, None)
            .expect("the code lifts")
            .ir
            .render()
    }

    #[test]
    fn a_remainder_of_another_value_stays_a_subtraction() {
        // y = edi >> 1; edx = y - ((y + 2) / 3) * 3: the quotient divides y + 2.
        let code = vec![
            0x89, 0xfa, // mov edx, edi
            0xd1, 0xea, // shr edx, 1
            0x44, 0x8d, 0x4a, 0x02, // lea r9d, [rdx + 2]
            0x41, 0xba, 0xab, 0xaa, 0xaa, 0xaa, // mov r10d, 0xaaaaaaab
            0x4d, 0x0f, 0xaf, 0xd1, // imul r10, r9
            0x49, 0xc1, 0xea, 0x21, // shr r10, 0x21
            0x47, 0x8d, 0x0c, 0x52, // lea r9d, [r10 + r10 * 2]
            0x44, 0x29, 0xca, // sub edx, r9d
            0x89, 0xd0, // mov eax, edx
            0xc3, // ret
        ];
        let ir = analyzed(Isa::X86_64, code);
        assert!(!ir.contains("% #0x3"), "{ir}");
    }

    /// `AArch64` `x % 3` for signed `x`, multiplying the quotient back by `1 + 2^shift`.
    fn signed_mod_three(shift: u32) -> String {
        let words: [u32; 9] = [
            0x528a_aac8,                 // mov  w8, #0x5556
            0x72aa_aaa8,                 // movk w8, #0x5555, lsl #16
            0x9b28_7c08,                 // smull x8, w0, w8
            0xd37f_fd09,                 // lsr  x9, x8, #63
            0xd360_fd08,                 // lsr  x8, x8, #32
            0x0b09_0108,                 // add  w8, w8, w9
            0x0b08_0108 | (shift << 10), // add  w8, w8, w8, lsl #shift
            0x4b08_0000,                 // sub  w0, w0, w8
            0xd65f_03c0,                 // ret
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let function = Function {
            addr: 0,
            size: Some(code.len() as u64),
            size_estimated: false,
            name: None,
            aliases: Vec::new(),
            library: None,
            sources: Vec::new(),
        };
        let image = Image::from_code(Isa::AArch64, 0, code);
        analyze(&image, &function, None)
            .expect("the code lifts")
            .ir
            .render()
    }

    #[test]
    fn rewrites_a_remainder_whose_multiplier_matches_the_magic() {
        let ir = signed_mod_three(1);
        assert!(ir.contains("% #0x3"), "{ir}");
    }

    #[test]
    fn keeps_a_remainder_whose_multiplier_does_not_match_the_magic() {
        let ir = signed_mod_three(2);
        assert!(!ir.contains('%'), "{ir}");
    }
}

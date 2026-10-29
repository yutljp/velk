use super::{
    block_entry_frame_offsets, canonical_frame, frame_slot, rewrite_frame, substitute_frame_pointer,
};
use crate::arch::stack_pointer;
use crate::ir::{BinOp, Expr, FunctionIr, Stmt};
use std::collections::HashMap;

pub(crate) fn settle(ir: &mut FunctionIr) {
    fn uses_stack_pointer_as_base(expr: &Expr, sp: u16) -> bool {
        match expr {
            Expr::Reg { index, .. } if *index == sp => true,
            Expr::Bin {
                op: BinOp::Add,
                lhs,
                rhs,
            } => uses_stack_pointer_as_base(lhs, sp) || uses_stack_pointer_as_base(rhs, sp),
            Expr::Bin {
                op: BinOp::Sub,
                lhs,
                rhs,
            } if matches!(rhs.as_ref(), Expr::Const(_)) => uses_stack_pointer_as_base(lhs, sp),
            _ => false,
        }
    }
    fn remove_redundant_32_bit_mask(expr: &mut Expr, sp: u16) {
        for child in crate::ir::visit::children_mut(expr) {
            remove_redundant_32_bit_mask(child, sp);
        }
        if let Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } = expr
            && matches!(rhs.as_ref(), Expr::Const(0xffff_ffff))
            && (uses_stack_pointer_as_base(lhs, sp)
                || crate::ssa::ranges::of(lhs).possible() <= 0xffff_ffff)
        {
            *expr = *lhs.clone();
        }
    }
    fn fold_addresses(expr: &mut Expr, frame: i64, sp: u16) {
        for child in crate::ir::visit::children_mut(expr) {
            fold_addresses(child, frame, sp);
        }
        if let Expr::Bin {
            op: BinOp::Sub,
            lhs,
            rhs,
        } = expr
            && let (Some(left), Some(right)) =
                (frame_slot(lhs, frame, sp), frame_slot(rhs, frame, sp))
            && let Some(delta) = left.checked_sub(right)
        {
            *expr = Expr::constant(delta as u64);
            return;
        }
        if let Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } = expr
            && matches!(rhs.as_ref(), Expr::Const(0xffff_fffc))
            && let Some(offset) = frame_slot(lhs, frame, sp)
            && let Some(delta) = (offset & !3).checked_sub(frame)
        {
            // Both 32-bit conventions align the entry stack pointer to at least four bytes.
            *expr = Expr::bin(BinOp::Add, Expr::reg(sp, 64), Expr::constant(delta as u64));
        }
    }
    let sp = stack_pointer(ir.isa);
    let mut candidate = ir.clone();
    crate::passes::simplify::simplify(&mut candidate);
    let statements = candidate
        .blocks
        .iter_mut()
        .flat_map(|block| &mut block.stmts);
    for stmt in statements {
        for operand in stmt.operands_mut() {
            remove_redundant_32_bit_mask(operand, sp);
        }
    }
    let frames = block_entry_frame_offsets(&candidate, sp);
    substitute_frame_pointer(&mut candidate, &frames);
    let statements = candidate
        .blocks
        .iter_mut()
        .flat_map(|block| &mut block.stmts);
    for stmt in statements {
        for operand in stmt.operands_mut() {
            remove_redundant_32_bit_mask(operand, sp);
        }
    }
    crate::passes::simplify::simplify(&mut candidate);
    let frames = block_entry_frame_offsets(&candidate, sp);
    for (block, frame) in candidate.blocks.iter_mut().zip(&frames) {
        let Some(mut frame) = *frame else { continue };
        let mut aliases = HashMap::<u16, i64>::new();
        for stmt in &mut block.stmts {
            let mut replacements = Vec::new();
            for (register, offset) in &aliases {
                let Some(delta) = offset.checked_sub(frame) else {
                    return;
                };
                replacements.push((
                    *register,
                    Expr::bin(BinOp::Add, Expr::reg(sp, 64), Expr::constant(delta as u64)),
                ));
            }
            crate::ir::visit::replace_reads(stmt, &replacements);
            for operand in stmt.operands_mut() {
                remove_redundant_32_bit_mask(operand, sp);
                fold_addresses(operand, frame, sp);
            }
            let alias = match stmt {
                Stmt::Assign { dest, value, .. } if dest.index != sp => {
                    frame_slot(value, frame, sp).map(|offset| (dest.index, offset))
                }
                _ => None,
            };
            for register in crate::ir::visit::statement_registers(stmt).0 {
                aliases.remove(&register);
            }
            if let Some((register, offset)) = alias {
                aliases.insert(register, offset);
            }
            if let Stmt::Assign { dest, value, .. } = stmt
                && dest.index == sp
            {
                let Some(next) = frame_slot(value, frame, sp) else {
                    return;
                };
                frame = next;
            }
            if matches!(stmt, Stmt::Unsupported { .. } | Stmt::Machine { .. }) {
                aliases.clear();
            }
        }
    }
    crate::passes::dce::dce(&mut candidate);
    crate::passes::simplify::simplify(&mut candidate);
    let frames = block_entry_frame_offsets(&candidate, sp);
    let bounded = candidate.blocks.iter().zip(&frames).all(|(block, frame)| {
        let Some(mut frame) = *frame else {
            return false;
        };
        for stmt in &block.stmts {
            if let Stmt::Assign { dest, value, .. } = stmt
                && dest.index == sp
            {
                let Some(next) = frame_slot(value, frame, sp) else {
                    return false;
                };
                if next.unsigned_abs() > 1 << 20 {
                    return false;
                }
                frame = next;
            }
        }
        true
    });
    if bounded && canonical_frame(&candidate, &frames) {
        rewrite_frame(&mut candidate, &frames);
        *ir = candidate;
    }
}

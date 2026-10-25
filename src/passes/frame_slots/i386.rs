use super::{
    address_escapes, block_frames, canonical_frame, frame_slot, rewrite_frame,
    substitute_frame_pointer,
};
use crate::arch::stack_pointer;
use crate::ir::{BinOp, Expr, FunctionIr, Stmt};

pub(crate) fn settle(ir: &mut FunctionIr) {
    fn based(expr: &Expr) -> bool {
        match expr {
            Expr::Reg { index: 4, .. } => true,
            Expr::Bin {
                op: BinOp::Add | BinOp::Sub,
                lhs,
                rhs,
            } if matches!(rhs.as_ref(), Expr::Const(_)) => based(lhs),
            _ => false,
        }
    }
    fn unmask(expr: &mut Expr) {
        for child in crate::ir::visit::children_mut(expr) {
            unmask(child);
        }
        if let Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } = expr
            && matches!(rhs.as_ref(), Expr::Const(0xffff_ffff))
            && (based(lhs) || crate::ssa::ranges::of(lhs).possible() <= 0xffff_ffff)
        {
            *expr = *lhs.clone();
        }
    }
    let mut candidate = ir.clone();
    crate::passes::simplify::simplify(&mut candidate);
    let statements = candidate
        .blocks
        .iter_mut()
        .flat_map(|block| &mut block.stmts);
    for stmt in statements {
        for operand in stmt.operands_mut() {
            unmask(operand);
        }
    }
    let sp = stack_pointer(candidate.isa);
    let frames = block_frames(&candidate, sp);
    substitute_frame_pointer(&mut candidate, &frames);
    let statements = candidate
        .blocks
        .iter_mut()
        .flat_map(|block| &mut block.stmts);
    for stmt in statements {
        for operand in stmt.operands_mut() {
            unmask(operand);
        }
    }
    crate::passes::simplify::simplify(&mut candidate);
    let frames = block_frames(&candidate, sp);
    let bounded = candidate.blocks.iter().zip(&frames).all(|(block, frame)| {
        let Some(mut frame) = *frame else {
            return false;
        };
        for stmt in &block.stmts {
            if let Stmt::Assign { dest, value } = stmt
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
    if bounded && canonical_frame(&candidate, &frames) && !address_escapes(&candidate, &frames) {
        rewrite_frame(&mut candidate, &frames);
        *ir = candidate;
    }
}

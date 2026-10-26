//! Expressions for adjacent 64-bit vector halves.

use crate::ir::{BinOp, Expr};

/// A window at `offset` within its first half, with an optional following half.
pub(super) fn window(first: &Expr, next: Option<&Expr>, offset: u64) -> Expr {
    let low = Expr::bin(BinOp::Shr, first.clone(), Expr::constant(offset));
    match next {
        Some(next) if offset > 0 => Expr::bin(
            BinOp::Or,
            low,
            Expr::bin(BinOp::Shl, next.clone(), Expr::constant(64 - offset)),
        ),
        _ => low,
    }
}

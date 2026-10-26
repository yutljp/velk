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

#[cfg(kani)]
mod proofs {
    #[kani::proof]
    #[kani::unwind(1)]
    fn vector_window() {
        let first: u64 = kani::any();
        let next: u64 = kani::any();
        let offset: u64 = kani::any();
        kani::assume(offset < 64);
        let following: bool = kani::any();
        let first_expr = crate::ir::Expr::Const(first);
        let next_expr = crate::ir::Expr::Const(next);
        let result = super::window(&first_expr, following.then_some(&next_expr), offset);
        let combined = u128::from(first) | if following { u128::from(next) << 64 } else { 0 };
        match result {
            crate::ir::Expr::Const(value) => assert_eq!(value, (combined >> offset) as u64),
            _ => panic!("a window of constants must fold to a constant"),
        }
    }
}

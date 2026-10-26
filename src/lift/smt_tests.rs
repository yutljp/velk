use super::*;
use crate::ir::smt::{self, Proofs};

#[test]
fn rotations_and_byte_reversals_are_equivalent() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for bits in [8, 16, 32, 64] {
        let x = Expr::reg(0, bits);
        for right in [false, true] {
            for amount in [
                Expr::reg(1, 64),
                Expr::Const(0),
                Expr::Const(1),
                Expr::Const(u64::from(bits)),
                Expr::Const(63),
                Expr::Const(64),
                Expr::Const(u64::MAX),
            ] {
                let count = smt::term(&amount);
                let input = smt::term(&x);
                let input = format!("((_ extract {} 0) {input})", bits - 1);
                let count = format!("((_ extract {} 0) {count})", bits - 1);
                let rotated = format!(
                    "(ext_rotate_{} {input} {count})",
                    if right { "right" } else { "left" }
                );
                let expected = if bits < 64 {
                    format!("((_ zero_extend {}) {rotated})", 64 - bits)
                } else {
                    rotated
                };
                let actual = smt::low(
                    &smt::term(&rotate(x.clone(), amount.clone(), bits, right)),
                    u32::from(bits),
                );
                proofs.predicate(
                    format!("rotate/{bits}/{right}/{amount:?}"),
                    &expected,
                    &actual,
                );
            }
        }
        for chunk in [1, 2, 4, 8] {
            if chunk > bits / 8 {
                continue;
            }
            let input = smt::term(&x);
            let bytes = bits / 8;
            let mut pieces = Vec::new();
            for byte in (0..bytes).rev() {
                let source = byte / chunk * chunk + chunk - 1 - byte % chunk;
                pieces.push(format!(
                    "((_ extract {} {}) {input})",
                    u32::from(source) * 8 + 7,
                    u32::from(source) * 8
                ));
            }
            let mut expected = pieces[0].clone();
            for piece in &pieces[1..] {
                expected = format!("(concat {expected} {piece})");
            }
            if bits < 64 {
                expected = format!("((_ zero_extend {}) {expected})", 64 - bits);
            }
            let actual = smt::term(&reverse_bytes(x.clone(), bits, chunk));
            proofs.predicate(format!("reverse bytes/{bits}/{chunk}"), &expected, &actual);
        }
    }
    proofs.check();
}

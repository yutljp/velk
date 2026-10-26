use super::*;
use crate::ir::smt::{self, Proofs};

#[test]
fn unsigned_full_width_extension_retains_high_bits() {
    let actual = extend_shift(a64::ShiftStyle::UXTX, 0, Expr::Const(1 << 32), SizeCode::X)
        .expect("valid extension");
    assert_eq!(
        crate::ir::semantics::evaluate(&actual, &|_| None),
        Some(1 << 32)
    );
}

#[test]
fn extensions_and_shifts_are_equivalent() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for size in [SizeCode::W, SizeCode::X] {
        let bits = if size == SizeCode::X { 64 } else { 32 };
        for (style, source_bits, signed) in [
            (a64::ShiftStyle::UXTB, 8, false),
            (a64::ShiftStyle::UXTH, 16, false),
            (a64::ShiftStyle::UXTW, 32, false),
            (a64::ShiftStyle::UXTX, 64, false),
            (a64::ShiftStyle::SXTB, 8, true),
            (a64::ShiftStyle::SXTH, 16, true),
            (a64::ShiftStyle::SXTW, 32, true),
            (a64::ShiftStyle::SXTX, 64, true),
        ] {
            for amount in 0..=4 {
                let x = Expr::reg(0, bits);
                let input = smt::term(&x);
                let extended = if signed {
                    smt::signed(&input, source_bits)
                } else {
                    smt::low(&input, source_bits)
                };
                let expected = smt::low(
                    &format!("(bvshl {extended} {})", smt::constant(amount)),
                    u32::from(bits),
                );
                let actual = extend_shift(style, amount, x, size).expect("valid extension");
                proofs.predicate(
                    format!("extension/{size:?}/{style:?}/{amount}"),
                    &expected,
                    &smt::low(&smt::term(&actual), u32::from(bits)),
                );
            }
        }
    }
    proofs.check();
}

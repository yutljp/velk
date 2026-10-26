use super::*;
use crate::ir::smt::Proofs;

#[test]
fn accepted_reciprocals_are_exact_for_every_dividend() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    let mut accepted = 0;
    for bits in [8u64, 16, 32, 64] {
        for extra in 0..=5 {
            let shift = bits + extra;
            let power = 1u128 << shift;
            for candidate in 2..=65u128 {
                let estimate = power.div_ceil(candidate);
                for magic in [estimate.saturating_sub(1), estimate, estimate + 1] {
                    let Ok(magic) = u64::try_from(magic) else {
                        continue;
                    };
                    for is_signed in [false, true] {
                        let divisor = if is_signed {
                            magic_divisor_signed64(magic, shift, bits)
                        } else {
                            magic_divisor(magic, shift, bits)
                        };
                        let Some(divisor) = divisor else {
                            continue;
                        };
                        accepted += 1;
                        let limit = 1u128 << if is_signed { bits - 1 } else { bits };
                        let x = format!("(+ (* q {divisor}) r)");
                        let product = format!("(* {x} {magic})");
                        let lower = format!("(* q {power})");
                        let upper = format!("(* (+ q 1) {power})");
                        let domain =
                            format!("(and (>= q 0) (>= r 0) (< r {divisor}) (< {x} {limit}))");
                        let exact = format!("(and (<= {lower} {product}) (< {product} {upper}))");
                        proofs.predicate(
                            format!(
                                "reciprocal/{bits}/{shift}/{magic}/{divisor}/{is_signed}/positive"
                            ),
                            "true",
                            &format!("(=> {domain} {exact})"),
                        );
                        if is_signed {
                            let domain = format!(
                                "(and (>= q 0) (>= r 0) (< r {divisor}) (> {x} 0) (<= {x} {limit}))"
                            );
                            let exact =
                                format!("(and (< {lower} {product}) (<= {product} {upper}))");
                            proofs.predicate(
                                format!("reciprocal/{bits}/{shift}/{magic}/{divisor}/negative"),
                                "true",
                                &format!("(=> {domain} {exact})"),
                            );
                        }
                    }
                }
            }
        }
    }
    assert!(
        accepted > 1000,
        "the reciprocal corpus must exercise accepted certificates"
    );
    eprintln!("SMT: {accepted} accepted reciprocal certificates");
    proofs.check();
}

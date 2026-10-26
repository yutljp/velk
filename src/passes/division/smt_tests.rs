//! Match real division chains and prove their returned values symbolically.

use super::*;
use crate::ir::smt::{Proofs, raw_bin};
use crate::ir::{BinOp, Cond, RegRef};
use crate::loader::Isa;

fn assign(index: u16, width: u8, value: Expr) -> Stmt {
    Stmt::Assign {
        dest: RegRef { index, width },
        value,
    }
}

fn selected(cond: Cond, value: Expr, then: Expr, els: Expr) -> Expr {
    Expr::Select {
        cond,
        lhs: Box::new(value),
        rhs: Box::new(Expr::Const(0)),
        then: Box::new(then),
        els: Box::new(els),
    }
}

#[test]
fn signed_power_of_two_chain_matchers_are_equivalent() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    let mut accepted = 0;
    for bits in [32, 64] {
        for shift in [1, 2, 7, 16, 30] {
            let divisor = 1u64 << shift;
            let x = Expr::reg(0, bits);
            for cond in [Cond::Ge, Cond::Lt] {
                let adjusted = raw_bin(BinOp::Add, x.clone(), Expr::Const(divisor - 1));
                let (then, els) = if cond == Cond::Ge {
                    (x.clone(), Expr::reg(2, bits))
                } else {
                    (Expr::reg(2, bits), x.clone())
                };
                let select = selected(cond, x.clone(), then, els);
                for remainder in [false, true] {
                    let mut statements = vec![
                        assign(2, bits, adjusted.clone()),
                        assign(3, bits, select.clone()),
                    ];
                    if remainder {
                        statements.push(assign(
                            4,
                            bits,
                            raw_bin(
                                BinOp::And,
                                Expr::reg(3, bits),
                                Expr::Const(divisor.wrapping_neg()),
                            ),
                        ));
                        statements.push(assign(
                            5,
                            bits,
                            raw_bin(BinOp::Sub, x.clone(), Expr::reg(4, bits)),
                        ));
                    } else {
                        statements.push(assign(
                            5,
                            bits,
                            raw_bin(BinOp::Sar, Expr::reg(3, bits), Expr::Const(shift)),
                        ));
                    }
                    let at = statements.len() - 1;
                    let replacement = raw_bin(
                        if remainder { BinOp::ModS } else { BinOp::DivS },
                        x.clone(),
                        Expr::Const(divisor),
                    );
                    assert!(
                        proof::equivalent(&statements, at, &replacement),
                        "power-of-two proof must accept {bits}/{shift}/{cond:?}/{remainder}"
                    );
                    let matcher = if remainder {
                        signed_select_mod_chain(&statements)
                    } else {
                        signed_select_chain(&statements)
                    };
                    assert!(matcher.is_some(), "chain matcher must accept the template");
                    statements.push(Stmt::Ret {
                        value: Expr::reg(5, bits),
                    });
                    let before = FunctionIr::single_block(Isa::AArch64, statements);
                    let mut after = before.clone();
                    recover_divisions(&mut after);
                    assert_ne!(
                        before.render(),
                        after.render(),
                        "real pass must replace the chain"
                    );
                    proofs.function(
                        format!("power-of-two chain/{bits}/{shift}/{cond:?}/{remainder}"),
                        &before,
                        &after,
                    );
                    accepted += 1;
                }
            }
            let statements = vec![
                assign(2, bits, raw_bin(BinOp::Sub, Expr::Const(0), x.clone())),
                assign(
                    3,
                    bits,
                    raw_bin(BinOp::And, x.clone(), Expr::Const(divisor - 1)),
                ),
                assign(
                    4,
                    bits,
                    raw_bin(BinOp::And, Expr::reg(2, bits), Expr::Const(divisor - 1)),
                ),
                assign(
                    5,
                    bits,
                    selected(
                        Cond::Lt,
                        raw_bin(BinOp::Sub, Expr::Const(0), x.clone()),
                        Expr::reg(3, bits),
                        raw_bin(BinOp::Sub, Expr::Const(0), Expr::reg(4, bits)),
                    ),
                ),
                Stmt::Ret {
                    value: Expr::reg(5, bits),
                },
            ];
            assert!(
                cs_neg_chain(&statements, 3).is_some(),
                "sign-select matcher accepts"
            );
            let before = FunctionIr::single_block(Isa::AArch64, statements);
            let mut after = before.clone();
            recover_divisions(&mut after);
            assert_ne!(
                before.render(),
                after.render(),
                "sign-select pass must replace"
            );
            proofs.function(format!("negated remainder/{bits}/{shift}"), &before, &after);
        }
    }
    assert_eq!(accepted, 40);
    proofs.check();
}

#[test]
fn reciprocal_matchers_keep_their_certified_expression_shapes() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for bits in [32, 64] {
        for signed in [false, true] {
            let (magic, shift) = match (bits, signed) {
                (32, false) => (0xaaaa_aaab, 33),
                (32, true) => (0x5555_5556, 32),
                (64, false) => (0xaaaa_aaaa_aaaa_aaab, 65),
                _ => (0x5555_5555_5555_5556, 64),
            };
            let x = Expr::reg(0, bits);
            let source = if signed && bits == 32 {
                Expr::SignExtend {
                    value: Box::new(x.clone()),
                    width: 4,
                }
            } else {
                x.clone()
            };
            let product_op = if bits == 32 {
                BinOp::Mul
            } else if signed {
                BinOp::MulHighS
            } else {
                BinOp::MulHigh
            };
            let product = raw_bin(product_op, source, Expr::Const(magic));
            let mut statements = vec![assign(3, 64, product)];
            if signed {
                statements.push(assign(
                    4,
                    64,
                    raw_bin(BinOp::Shr, Expr::reg(3, 64), Expr::Const(63)),
                ));
                if bits == 32 {
                    statements.push(assign(
                        6,
                        64,
                        raw_bin(BinOp::Shr, Expr::reg(3, 64), Expr::Const(32)),
                    ));
                }
                statements.push(assign(
                    5,
                    bits,
                    raw_bin(
                        BinOp::Add,
                        Expr::reg(if bits == 32 { 6 } else { 3 }, bits),
                        Expr::reg(4, bits),
                    ),
                ));
            } else {
                statements.push(assign(
                    5,
                    bits,
                    raw_bin(
                        BinOp::Shr,
                        Expr::reg(3, 64),
                        Expr::Const(if bits == 32 { shift } else { shift - 64 }),
                    ),
                ));
            }
            let at = statements.len() - 1;
            let replacement = raw_bin(
                if signed { BinOp::DivS } else { BinOp::DivU },
                x.clone(),
                Expr::Const(3),
            );
            assert!(
                proof::equivalent(&statements, at, &replacement),
                "reciprocal normalizer must accept {bits}/{signed}"
            );
            if bits == 32 && signed {
                assert!(signed_chain(&statements, 0, 3, magic, 32).is_some());
                assert!(widened_signed_site(&statements).is_some());
            } else if signed {
                assert!(signed64_chain(&statements, 0, 3, magic, 64, true).is_some());
            } else if bits == 64 {
                assert!(unsigned64_chain(&statements, 0, 3, magic, 64).is_some());
            }
            statements.push(Stmt::Ret {
                value: Expr::reg(5, bits),
            });
            let before = FunctionIr::single_block(Isa::AArch64, statements);
            let mut after = before.clone();
            recover_divisions(&mut after);
            let expected = FunctionIr::single_block(
                Isa::AArch64,
                vec![
                    assign(5, bits, replacement),
                    Stmt::Ret {
                        value: Expr::reg(5, bits),
                    },
                ],
            );
            // The matcher must produce exactly the independently specified
            // quotient, not merely modify an unrelated statement.
            proofs.function(
                format!("reciprocal output/{bits}/{signed}"),
                &expected,
                &after,
            );
            assert_ne!(
                before.render(),
                after.render(),
                "reciprocal pass must change"
            );
            let power = 1u128 << shift;
            let limit = 1u128 << if signed { bits - 1 } else { bits };
            let x = "(+ (* q 3) r)";
            let domain = format!("(and (>= q 0) (>= r 0) (< r 3) (< {x} {limit}))");
            proofs.predicate(format!("matched reciprocal certificate/{bits}/{signed}"), "true", &format!("(=> {domain} (and (<= (* q {power}) (* {x} {magic})) (< (* {x} {magic}) (* (+ q 1) {power}))))"));
            if signed {
                let domain = format!("(and (>= q 0) (>= r 0) (< r 3) (> {x} 0) (<= {x} {limit}))");
                proofs.predicate(format!("matched negative certificate/{bits}"), "true", &format!("(=> {domain} (and (< (* q {power}) (* {x} {magic})) (<= (* {x} {magic}) (* (+ q 1) {power}))))"));
            }
        }
    }
    proofs.check();
}

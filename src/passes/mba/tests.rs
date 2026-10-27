use super::*;
use crate::ir::smt::{Proofs, raw_bin as bin};

fn replace_sum(expr: &mut Expr, sum: &Expr, plain: &Expr) -> usize {
    if expr == sum {
        *expr = plain.clone();
        return 1;
    }
    let mut count = 0;
    for child in crate::ir::visit::children_mut(expr) {
        count += replace_sum(child, sum, plain);
    }
    count
}

fn identity_examples(bits: u8) -> Vec<(Expr, Expr)> {
    let x = Expr::reg(0, bits);
    let y = Expr::reg(1, bits);
    let and = bin(BinOp::And, x.clone(), y.clone());
    let xor = bin(BinOp::Xor, x.clone(), y.clone());
    let or = bin(BinOp::Or, x.clone(), y.clone());
    let sum = bin(
        BinOp::Add,
        xor.clone(),
        bin(BinOp::Mul, and.clone(), Expr::Const(2)),
    );
    vec![
        (sum.clone(), bin(BinOp::Add, x.clone(), y.clone())),
        (
            bin(
                BinOp::Sub,
                bin(BinOp::Add, x.clone(), y.clone()),
                bin(BinOp::Mul, and.clone(), Expr::Const(2)),
            ),
            xor,
        ),
        (
            bin(
                BinOp::Sub,
                bin(BinOp::Add, x.clone(), y.clone()),
                and.clone(),
            ),
            or.clone(),
        ),
        (
            bin(BinOp::Sub, bin(BinOp::Add, or, and), y.clone()),
            x.clone(),
        ),
        (
            bin(
                BinOp::Sub,
                bin(BinOp::Mul, sum.clone(), Expr::Const(7)),
                bin(BinOp::Mul, x.clone(), Expr::Const(7)),
            ),
            bin(BinOp::Mul, y.clone(), Expr::Const(7)),
        ),
        (
            bin(
                BinOp::Add,
                bin(BinOp::Sub, sum.clone(), x.clone()),
                bin(BinOp::Sub, Expr::Const(42), y.clone()),
            ),
            Expr::Const(42),
        ),
        (
            bin(
                BinOp::Sub,
                bin(BinOp::Mul, sum.clone(), sum.clone()),
                bin(
                    BinOp::Add,
                    bin(BinOp::Mul, x.clone(), x.clone()),
                    bin(BinOp::Mul, y.clone(), y.clone()),
                ),
            ),
            bin(
                BinOp::Mul,
                bin(BinOp::Mul, y.clone(), x.clone()),
                Expr::Const(2),
            ),
        ),
        (
            bin(
                BinOp::Sub,
                bin(BinOp::Mul, sum, x.clone()),
                bin(BinOp::Mul, x.clone(), x.clone()),
            ),
            bin(BinOp::Mul, x, y),
        ),
    ]
}

#[test]
fn smt_linear_and_polynomial_mba() {
    assert!(Proofs::available(), "z3 is required for MBA proofs");
    let mut proofs = Proofs::default();
    for bits in [8, 16, 32, 64] {
        for (index, (before, expected)) in identity_examples(bits).into_iter().enumerate() {
            let after =
                replacement(&before, /* preserve_width */ false).expect("the identity simplifies");
            let registers = [Expr::reg(0, bits), Expr::reg(1, bits)];
            assert_eq!(
                normalize(&after, &registers),
                normalize(&expected, &registers)
            );
            assert!(
                size(&after) <= size(&expected),
                "{after:?} expected {expected:?}"
            );
            if index >= 6 {
                // The first obligation proves the sum identity. Congruence
                // replaces its occurrences before proving the ring step.
                let (sum, plain) = identity_examples(bits).remove(0);
                let mut arithmetic = before.clone();
                assert_eq!(
                    replace_sum(&mut arithmetic, &sum, &plain),
                    if index == 6 { 2 } else { 1 }
                );
                proofs.expression(format!("mba/{bits}/{index}/ring"), &arithmetic, &after, 64);
            } else {
                proofs.expression(format!("mba/{bits}/{index}"), &before, &after, 64);
            }
        }
    }
    proofs.check();
}

#[test]
fn smt_all_three_variable_boolean_functions() {
    assert!(Proofs::available(), "z3 is required for MBA proofs");
    let mut proofs = Proofs::default();
    for bits in [8, 16, 32, 64] {
        let registers: Vec<_> = (0..3).map(|index| Expr::reg(index, bits)).collect();
        for table in 0u16..256 {
            let mut before = Expr::Const(0);
            for assignment in 0..8 {
                if table & (1 << assignment) == 0 {
                    continue;
                }
                let mut term = Expr::Const(u64::MAX);
                for (index, register) in registers.iter().enumerate() {
                    let literal = if assignment & (1 << index) != 0 {
                        register.clone()
                    } else {
                        bin(BinOp::Xor, register.clone(), Expr::Const(u64::MAX))
                    };
                    term = bin(BinOp::And, term, literal);
                }
                before = bin(BinOp::Or, before, term);
            }
            let polynomial = normalize(&before, &registers).unwrap();
            let after = expression(&polynomial, &registers);
            // A linear bitwise sum is the sum of its bit positions. Check
            // every Boolean assignment with an arbitrary shared bit mask;
            // integer coefficients must agree before any width truncation.
            for assignment in 0..8 {
                let values: Vec<_> = (0..3)
                    .map(|index| {
                        (
                            index,
                            if assignment & (1 << index) == 0 {
                                Expr::Const(0)
                            } else {
                                Expr::reg(3, bits)
                            },
                        )
                    })
                    .collect();
                let before = crate::ir::visit::substitute_values(before.clone(), &values);
                let after = crate::ir::visit::substitute_values(after.clone(), &values);
                proofs.expression(
                    format!("mba/boolean/{bits}/{table}/{assignment}"),
                    &before,
                    &after,
                    64,
                );
            }
        }
    }
    proofs.check();
}

#[test]
fn rejects_effects_limits_and_incorrect_coefficients() {
    for bits in [8, 16, 32, 64] {
        let x = Expr::reg(0, bits);
        let y = Expr::reg(1, bits);
        for coefficient in [0, 1, 3, 4, u64::MAX] {
            let before = bin(
                BinOp::Add,
                bin(BinOp::Xor, x.clone(), y.clone()),
                bin(
                    BinOp::Mul,
                    bin(BinOp::And, x.clone(), y.clone()),
                    Expr::Const(coefficient),
                ),
            );
            let sum = bin(BinOp::Add, x.clone(), y.clone());
            let registers = [x.clone(), y.clone()];
            assert_ne!(normalize(&before, &registers), normalize(&sum, &registers));
            // A concrete negative control distinguishes each wrong coefficient.
            let actual = crate::ir::semantics::evaluate(&before, &|_| Some(1));
            assert_ne!(actual, Some(2));
        }
        for unsafe_value in [
            Expr::Load {
                addr: Box::new(x.clone()),
                width: 8,
                signed: false,
            },
            bin(BinOp::DivU, x.clone(), Expr::Const(0)),
            Expr::apply(crate::ir::Operation::Undefined, Vec::new()),
        ] {
            let before = bin(
                BinOp::Sub,
                bin(BinOp::Or, unsafe_value.clone(), y.clone()),
                bin(BinOp::And, unsafe_value, y.clone()),
            );
            assert!(replacement(&before, /* preserve_width */ false).is_none());
        }
        let (constant, _) = identity_examples(bits).remove(5);
        assert!(
            replacement(&constant, /* preserve_width */ true).is_none(),
            "width-changing constant must remain"
        );
        let masked = bin(
            BinOp::And,
            identity_examples(bits).remove(0).0,
            Expr::Const(0xff),
        );
        assert!(replacement(&masked, /* preserve_width */ false).is_none());
    }
    let mut large = identity_examples(64).remove(0).0;
    for _ in 0..40 {
        large = bin(BinOp::Add, large, Expr::Const(1));
    }
    assert!(replacement(&large, /* preserve_width */ false).is_none());
}

#[test]
fn smt_coefficients_shifts_complements_and_width_contexts() {
    assert!(Proofs::available(), "z3 is required for MBA proofs");
    let mut proofs = Proofs::default();
    for bits in [8, 16, 32, 64] {
        let registers = [Expr::reg(0, bits), Expr::reg(1, bits), Expr::reg(2, bits)];
        let sum = identity_examples(bits).remove(0).0;
        for shift in [0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 65, u64::MAX] {
            let before = bin(
                BinOp::Sub,
                bin(BinOp::Shl, sum.clone(), Expr::Const(shift)),
                bin(BinOp::Shl, registers[0].clone(), Expr::Const(shift)),
            );
            let after = replacement(&before, /* preserve_width */ false).unwrap();
            proofs.expression(format!("mba/shift/{bits}/{shift}"), &before, &after, 64);
        }
        for coefficient in [0, 1, 2, 3, 7, 0x8000000000000000, u64::MAX] {
            let before = bin(
                BinOp::Sub,
                bin(BinOp::Mul, Expr::Const(coefficient), sum.clone()),
                bin(BinOp::Mul, Expr::Const(coefficient), registers[0].clone()),
            );
            let after = replacement(&before, /* preserve_width */ false).unwrap();
            proofs.expression(
                format!("mba/coefficient/{bits}/{coefficient}"),
                &before,
                &after,
                64,
            );
        }
        let before = bin(
            BinOp::Add,
            bin(BinOp::Xor, registers[0].clone(), Expr::Const(u64::MAX)),
            bin(BinOp::Add, sum.clone(), Expr::Const(1)),
        );
        let after = replacement(&before, /* preserve_width */ false).unwrap();
        proofs.expression(format!("mba/complement/{bits}"), &before, &after, 64);
        let before = bin(
            BinOp::Add,
            bin(
                BinOp::Add,
                registers[0].clone(),
                bin(BinOp::Xor, registers[0].clone(), Expr::Const(u64::MAX)),
            ),
            Expr::Const(1),
        );
        let after = replacement(&before, /* preserve_width */ false).unwrap();
        assert_eq!(after, Expr::Const(0));
        proofs.expression(
            format!("mba/complement-constant/{bits}"),
            &before,
            &after,
            64,
        );
        for op in [BinOp::Sar, BinOp::DivS, BinOp::ModS] {
            let before = bin(op, identity_examples(bits).remove(5).0, Expr::Const(3));
            let mut after = before.clone();
            rewrite(&mut after, /* preserve_width */ false);
            assert_eq!(
                crate::ir::semantics::width(&before),
                crate::ir::semantics::width(&after)
            );
            proofs.expression(format!("mba/context/{bits}/{op:?}"), &before, &after, 64);
        }
        let before = bin(
            BinOp::Sub,
            bin(BinOp::Add, sum.clone(), registers[2].clone()),
            bin(BinOp::Add, registers[0].clone(), registers[2].clone()),
        );
        let after = replacement(&before, /* preserve_width */ false).unwrap();
        assert_eq!(after, registers[1]);
        proofs.expression(format!("mba/three/{bits}"), &before, &after, 64);
    }
    proofs.check();
}

#[test]
fn smt_polynomial_ring_operations() {
    assert!(Proofs::available(), "z3 is required for MBA proofs");
    let mut proofs = Proofs::default();
    for bits in [8, 16, 32, 64] {
        let registers = [Expr::reg(0, bits), Expr::reg(1, bits), Expr::reg(2, bits)];
        let a = bin(BinOp::Add, registers[0].clone(), registers[1].clone());
        let b = bin(BinOp::Sub, registers[0].clone(), registers[2].clone());
        for op in [BinOp::Add, BinOp::Sub, BinOp::Mul] {
            let before = bin(op, a.clone(), b.clone());
            let polynomial = normalize(&before, &registers).unwrap();
            let after = expression(&polynomial, &registers);
            proofs.expression(format!("mba/ring/{bits}/{op:?}"), &before, &after, 64);
        }
    }
    proofs.check();
}

#[test]
fn smt_negative_controls_have_counterexamples() {
    use crate::ir::smt;

    assert!(Proofs::available(), "z3 is required for MBA proofs");
    let mut proofs = Proofs::default();
    for bits in [8, 16, 32, 64] {
        let x = Expr::reg(0, bits);
        let y = Expr::reg(1, bits);
        for coefficient in [0, 1, 3, 4, u64::MAX] {
            let before = bin(
                BinOp::Add,
                bin(BinOp::Xor, x.clone(), y.clone()),
                bin(
                    BinOp::Mul,
                    bin(BinOp::And, x.clone(), y.clone()),
                    Expr::Const(coefficient),
                ),
            );
            let wrong = bin(BinOp::Add, x.clone(), y.clone());
            if let Some(after) = replacement(&before, /* preserve_width */ false) {
                assert_ne!(after, wrong);
            }
            proofs.predicate(
                format!("mba/negative/{bits}/{coefficient}"),
                &format!(
                    "(=> (and (= r0 {}) (= r1 {})) (not (= {} {})))",
                    smt::constant(1),
                    smt::constant(1),
                    smt::term(&before),
                    smt::term(&wrong)
                ),
                "true",
            );
        }
        if bits < 64 {
            let constant = bin(
                BinOp::Add,
                identity_examples(bits).remove(5).0,
                Expr::Const((1u64 << (bits - 1)) - 42),
            );
            let before = bin(BinOp::Sar, constant.clone(), Expr::Const(1));
            let mut after = before.clone();
            rewrite(&mut after, /* preserve_width */ false);
            assert_eq!(
                crate::ir::semantics::width(&before),
                crate::ir::semantics::width(&after)
            );
            let naive = bin(
                BinOp::Sar,
                replacement(&constant, /* preserve_width */ false).unwrap(),
                Expr::Const(1),
            );
            proofs.predicate(
                format!("mba/width-negative/{bits}"),
                &format!("(not (= {} {}))", smt::term(&before), smt::term(&naive)),
                "true",
            );
        }
    }
    proofs.check();
}

#[test]
fn scaled_complements_keep_array_index_structure() {
    for scale in [8, 16, 24, 32] {
        let index = bin(BinOp::Xor, Expr::reg(1, 64), Expr::Const(u64::MAX));
        let address = bin(
            BinOp::Add,
            bin(
                BinOp::Add,
                Expr::reg(0, 64),
                bin(BinOp::Mul, index, Expr::Const(scale)),
            ),
            Expr::Const(8),
        );
        let mut after = address.clone();
        assert_eq!(rewrite(&mut after, /* preserve_width */ false), 0);
        assert_eq!(after, address);
    }
    let x = Expr::reg(0, 64);
    let constant = bin(
        BinOp::Add,
        bin(
            BinOp::Add,
            x.clone(),
            bin(BinOp::Xor, x, Expr::Const(u64::MAX)),
        ),
        Expr::Const(1),
    );
    assert_eq!(
        replacement(&constant, /* preserve_width */ false),
        Some(Expr::Const(0))
    );
}

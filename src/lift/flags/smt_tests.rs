use super::*;
use crate::ir::smt::{self, CONDITIONS, Proofs};

fn decided(test: Test) -> Option<String> {
    match test {
        Test::Always => Some("true".to_owned()),
        Test::Never => Some("false".to_owned()),
        Test::Compare(cond, lhs, rhs) => Some(smt::condition(
            cond,
            &smt::term(&lhs),
            &smt::term(&rhs),
            operand_width(&lhs, &rhs),
        )),
        Test::Unknown => None,
    }
}

#[test]
fn condition_values_preserve_tests() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for bits in [8, 16, 32, 64] {
        for isa in [Isa::Arm32, Isa::AArch64, Isa::I386, Isa::X86_64] {
            for flags in [
                Flags::difference(Expr::reg(0, bits), Expr::reg(1, bits)),
                Flags::sum(Expr::reg(0, bits), Expr::reg(1, bits)),
            ] {
                let (byte, overflow) = super::super::condition_values(&flags, isa)
                    .expect("arithmetic sets all condition flags");
                let restored = Flags::stored(byte, Some(overflow));
                for cond in CONDITIONS {
                    let original = decided(flags.test(cond, isa)).expect("condition is known");
                    let reconstructed =
                        decided(restored.test(cond, isa)).expect("condition is known");
                    proofs.predicate(
                        format!(
                            "condition values/{bits}/{isa:?}/{:?}/{cond:?}",
                            flags.source
                        ),
                        &original,
                        &reconstructed,
                    );
                }
                if matches!(isa, Isa::I386 | Isa::X86_64) {
                    for even in [false, true] {
                        let original = decided(flags.parity(even)).expect("parity is known");
                        let reconstructed =
                            decided(restored.parity(even)).expect("parity is known");
                        proofs.predicate(
                            format!("condition parity/{bits}/{isa:?}/{:?}/{even}", flags.source),
                            &original,
                            &reconstructed,
                        );
                    }
                    let original = decided(flags.adjust()).expect("adjust is known");
                    let reconstructed = decided(restored.adjust()).expect("adjust is known");
                    proofs.predicate(
                        format!("condition adjust/{bits}/{isa:?}/{:?}", flags.source),
                        &original,
                        &reconstructed,
                    );
                }
            }
        }
    }
    proofs.check();
}

fn reference(cond: Cond, n: &str, z: &str, c: &str, v: &str) -> String {
    match cond {
        Cond::Eq => z.to_owned(),
        Cond::Ne => format!("(not {z})"),
        Cond::Cs => c.to_owned(),
        Cond::Cc => format!("(not {c})"),
        Cond::Hi => format!("(and {c} (not {z}))"),
        Cond::Ls => format!("(not (and {c} (not {z})))"),
        Cond::Mi => n.to_owned(),
        Cond::Pl => format!("(not {n})"),
        Cond::Vs => v.to_owned(),
        Cond::Vc => format!("(not {v})"),
        Cond::Ge => format!("(= {n} {v})"),
        Cond::Lt => format!("(not (= {n} {v}))"),
        Cond::Gt => format!("(and (not {z}) (= {n} {v}))"),
        Cond::Le => format!("(not (and (not {z}) (= {n} {v})))"),
    }
}

#[test]
fn integer_flag_recovery_is_equivalent() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for bits in [1, 8, 16, 32, 64] {
        for isa in [Isa::I386, Isa::X86_64, Isa::AArch64] {
            for source in [
                Source::Difference,
                Source::Sum,
                Source::Logic,
                Source::Result,
                Source::Shift,
                Source::Zero,
                Source::Carry,
                Source::CarryOverflow,
            ] {
                let a = Expr::reg(0, bits);
                let b = Expr::reg(1, bits);
                let flags = Flags::new(source, a.clone(), b.clone());
                let (a, b) = (smt::term(&a), smt::term(&b));
                let zero = smt::constant(0);
                let width = u32::from(bits);
                let result = match source {
                    Source::Difference => smt::low(&format!("(bvsub {a} {b})"), width),
                    Source::Sum => smt::low(&format!("(bvadd {a} {b})"), width),
                    _ => a.clone(),
                };
                let negative = format!("(bvslt {} {zero})", smt::signed(&result, width));
                let is_zero = if source == Source::Zero {
                    format!("(not (= {a} {zero}))")
                } else {
                    format!("(= {result} {zero})")
                };
                let carry = match source {
                    Source::Difference => format!("(bvuge {a} {b})"),
                    Source::Sum => {
                        let extended =
                            format!("(bvadd ((_ zero_extend 1) {a}) ((_ zero_extend 1) {b}))");
                        let wide = format!("(bvugt {extended} (_ bv{} 65))", mask(width));
                        if matches!(isa, Isa::X86_64 | Isa::I386) {
                            format!("(not {wide})")
                        } else {
                            wide
                        }
                    }
                    Source::Shift | Source::Carry => {
                        let bit = if source == Source::Shift { &b } else { &a };
                        if source == Source::Shift || matches!(isa, Isa::X86_64 | Isa::I386) {
                            format!("(= {bit} {zero})")
                        } else {
                            format!("(not (= {bit} {zero}))")
                        }
                    }
                    Source::CarryOverflow => format!("(= {a} {zero})"),
                    _ => matches!(isa, Isa::X86_64 | Isa::I386).to_string(),
                };
                let overflow = match source {
                    Source::Difference => format!(
                        "(bvslt {} {zero})",
                        smt::signed(
                            &format!("(bvand (bvxor {a} {b}) (bvxor {a} {result}))"),
                            width
                        )
                    ),
                    Source::Sum => {
                        // Overflow iff widening the signed sum changes it.
                        let exact = format!(
                            "(bvadd ((_ sign_extend 1) {}) ((_ sign_extend 1) {}))",
                            smt::signed(&a, width),
                            smt::signed(&b, width)
                        );
                        format!(
                            "(not (= {exact} ((_ sign_extend 1) {})))",
                            smt::signed(&result, width)
                        )
                    }
                    Source::CarryOverflow => format!("(not (= {a} {zero}))"),
                    _ => "false".to_owned(),
                };
                for cond in CONDITIONS {
                    let Some(actual) = decided(flags.test(cond, isa)) else {
                        continue;
                    };
                    let expected = reference(cond, &negative, &is_zero, &carry, &overflow);
                    proofs.predicate(
                        format!("flags/{bits}/{isa:?}/{source:?}/{cond:?}"),
                        &expected,
                        &actual,
                    );
                }
                if bits >= 8
                    && matches!(
                        source,
                        Source::Difference | Source::Sum | Source::Logic | Source::Shift
                    )
                {
                    let counts =
                        smt::term(&Expr::apply(Operation::PopCount(8), vec![flags.value()]));
                    for even in [false, true] {
                        let expected = format!(
                            "(= (bvand {counts} {}) {})",
                            smt::constant(1),
                            smt::constant(u64::from(!even))
                        );
                        let actual = decided(flags.parity(even)).expect("integer parity is known");
                        proofs.predicate(
                            format!("parity/{bits}/{isa:?}/{source:?}/{even}"),
                            &expected,
                            &actual,
                        );
                    }
                }
            }
        }
    }
    for nzcv in 0..16 {
        for cond in CONDITIONS {
            let expected = reference(
                cond,
                if nzcv & 8 != 0 { "true" } else { "false" },
                if nzcv & 4 != 0 { "true" } else { "false" },
                if nzcv & 2 != 0 { "true" } else { "false" },
                if nzcv & 1 != 0 { "true" } else { "false" },
            );
            let actual = decided(Flags::fixed(nzcv).test(cond, Isa::AArch64))
                .expect("fixed flags are known");
            proofs.predicate(format!("fixed/{nzcv}/{cond:?}"), &expected, &actual);
        }
    }
    proofs.check();
}

#[test]
fn carry_borrow_and_conditional_flags_are_equivalent() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for bits in [1, 8, 16, 32, 64] {
        let a = Expr::reg(0, bits);
        let b = Expr::reg(1, bits);
        let bit = Expr::reg(2, 1);
        let aw = format!("((_ zero_extend 1) {})", smt::term(&a));
        let bw = format!("((_ zero_extend 1) {})", smt::term(&b));
        let cw = format!("((_ zero_extend 1) {})", smt::term(&bit));
        let sum = format!("(bvadd (bvadd {aw} {bw}) {cw})");
        let carried = format!("((_ zero_extend 63) ((_ extract {bits} {bits}) {sum}))");
        proofs.predicate(
            format!("carry out/{bits}"),
            &carried,
            &smt::term(&carry_out(&a, &b, bit.clone(), u32::from(bits))),
        );
        let borrowed = format!(
            "(ite (bvult {aw} (bvadd {bw} {cw})) {} {})",
            smt::constant(1),
            smt::constant(0)
        );
        proofs.predicate(
            format!("borrow out/{bits}"),
            &borrowed,
            &smt::term(&borrow_out(&a, &b, bit)),
        );
    }
    for otherwise in 0..16 {
        for chosen in CONDITIONS {
            let when = smt::condition(
                chosen,
                &smt::term(&Expr::reg(2, 32)),
                &smt::term(&Expr::reg(3, 32)),
                32,
            );
            let own = Flags::difference(Expr::reg(0, 32), Expr::reg(1, 32));
            let mut flags = own.clone();
            flags.chosen = Some(Choice {
                cond: chosen,
                lhs: Expr::reg(2, 32),
                rhs: Expr::reg(3, 32),
                otherwise,
            });
            for cond in CONDITIONS {
                let original =
                    decided(own.test(cond, Isa::AArch64)).expect("difference decides conditions");
                let fallback = decided(Flags::fixed(otherwise).test(cond, Isa::AArch64))
                    .expect("fixed flags decide conditions");
                let expected = format!("(ite {when} {original} {fallback})");
                let actual = decided(flags.test(cond, Isa::AArch64))
                    .expect("conditional compare decides conditions");
                proofs.predicate(
                    format!("conditional flags/{otherwise}/{chosen:?}/{cond:?}"),
                    &expected,
                    &actual,
                );
            }
        }
    }
    proofs.check();
}

#[test]
fn saved_adjust_and_widened_logic_flags_are_equivalent() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    let byte = Expr::reg(0, 8);
    let overflow = Expr::reg(1, 1);
    let raw = smt::term(&byte);
    let bit = |index| format!("(= ((_ extract {index} {index}) {raw}) #b1)");
    for known in [false, true] {
        let flags = Flags::stored(byte.clone(), known.then(|| overflow.clone()));
        for cond in CONDITIONS {
            let actual = decided(flags.test(cond, Isa::X86_64));
            if !known
                && matches!(
                    cond,
                    Cond::Vs | Cond::Vc | Cond::Ge | Cond::Lt | Cond::Gt | Cond::Le
                )
            {
                assert!(actual.is_none(), "unknown overflow must stay unknown");
                continue;
            }
            let expected = reference(
                cond,
                &bit(7),
                &bit(6),
                &format!("(not {})", bit(0)),
                &format!("(= {} {})", smt::term(&overflow), smt::constant(1)),
            );
            proofs.predicate(
                format!("saved flags/{known}/{cond:?}"),
                &expected,
                &actual.expect("saved condition is known"),
            );
        }
        for even in [false, true] {
            proofs.predicate(
                format!("saved parity/{known}/{even}"),
                &if even {
                    bit(2)
                } else {
                    format!("(not {})", bit(2))
                },
                &decided(flags.parity(even)).expect("saved parity"),
            );
        }
        proofs.predicate(
            format!("saved adjust/{known}"),
            &bit(4),
            &decided(flags.adjust()).expect("saved adjust"),
        );
    }
    for bits in [8, 16, 32, 64] {
        let a = Expr::reg(0, bits);
        let b = Expr::reg(1, bits);
        let low_a = format!("((_ extract 3 0) {})", smt::term(&a));
        let low_b = format!("((_ extract 3 0) {})", smt::term(&b));
        for source in [Source::Difference, Source::Sum] {
            let flags = Flags::new(source, a.clone(), b.clone());
            let expected = if source == Source::Difference {
                format!("(bvult {low_a} {low_b})")
            } else {
                format!(
                    "(bvugt (bvadd ((_ zero_extend 1) {low_a}) ((_ zero_extend 1) {low_b})) (_ bv15 5))"
                )
            };
            proofs.predicate(
                format!("adjust/{bits}/{source:?}"),
                &expected,
                &decided(flags.adjust()).expect("arithmetic adjust"),
            );
        }
        for width in [32, 64] {
            if width <= u32::from(bits) {
                continue;
            }
            let flags = Flags::logic_at(a.clone(), width);
            for isa in [Isa::X86_64, Isa::AArch64] {
                for cond in CONDITIONS {
                    let expected = reference(
                        cond,
                        "false",
                        &format!("(= {} {})", smt::term(&a), smt::constant(0)),
                        if isa == Isa::X86_64 { "true" } else { "false" },
                        "false",
                    );
                    proofs.predicate(
                        format!("wide logic/{bits}/{width}/{isa:?}/{cond:?}"),
                        &expected,
                        &decided(flags.test(cond, isa)).expect("logic flags"),
                    );
                }
            }
        }
    }
    proofs.check();
}

#[test]
fn ieee_comparison_flags_are_equivalent() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for precision in [Precision::Single, Precision::Double] {
        let bits = precision.bits();
        let (exponent, significand) = if bits == 32 { (8, 24) } else { (11, 53) };
        let float = |index| {
            format!(
                "((_ to_fp {exponent} {significand}) ((_ extract {} 0) r{index}))",
                bits - 1
            )
        };
        let (a, b) = (float(0), float(1));
        let unordered = format!("(or (fp.isNaN {a}) (fp.isNaN {b}))");
        let equal = format!("(fp.eq {a} {b})");
        let less = format!("(fp.lt {a} {b})");
        for isa in [Isa::I386, Isa::X86_64, Isa::AArch64, Isa::Arm32] {
            let flags = Flags::float_compare(Expr::reg(0, bits), Expr::reg(1, bits), precision);
            let (n, z, c, v) = if matches!(isa, Isa::I386 | Isa::X86_64) {
                (
                    "false".to_owned(),
                    format!("(or {equal} {unordered})"),
                    format!("(not (or {less} {unordered}))"),
                    "false".to_owned(),
                )
            } else {
                (
                    less.clone(),
                    equal.clone(),
                    format!("(not {less})"),
                    unordered.clone(),
                )
            };
            for cond in CONDITIONS {
                proofs.predicate(
                    format!("float flags/{precision:?}/{isa:?}/{cond:?}"),
                    &reference(cond, &n, &z, &c, &v),
                    &decided(flags.test(cond, isa)).expect("float condition"),
                );
            }
            for even in [false, true] {
                let expected = if even {
                    unordered.clone()
                } else {
                    format!("(not {unordered})")
                };
                proofs.predicate(
                    format!("float parity/{precision:?}/{isa:?}/{even}"),
                    &expected,
                    &decided(flags.parity(even)).expect("float parity"),
                );
            }
            assert_eq!(flags.adjust(), Test::Never);
        }
    }
    proofs.check();
}

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

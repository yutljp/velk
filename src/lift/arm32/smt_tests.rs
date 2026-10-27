use super::*;
use crate::ir::smt::{self, Proofs};

#[test]
fn decoded_extend_add_matches_symbolic_rotation_and_addition() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    let image = Image::from_code(Isa::Arm32, 0, vec![0; 4]);
    let summaries = |_| Default::default();
    for mode in [ArmMode::Arm, ArmMode::Thumb] {
        for width in [1, 2] {
            for signed in [false, true] {
                for rotation in [0, 8, 16, 24] {
                    let word: u32 = if mode == ArmMode::Arm {
                        0xe680_0072
                            | (if signed { 0 } else { 1 << 22 })
                            | (if width == 1 { 2 << 20 } else { 3 << 20 })
                            | (1 << 16)
                            | ((rotation / 8) << 10)
                    } else {
                        0xfa01_f082
                            | (if signed { 0 } else { 1 << 20 })
                            | (if width == 1 { 1 << 22 } else { 0 })
                            | ((rotation / 8) << 4)
                    };
                    let bytes = if mode == ArmMode::Arm {
                        word.to_le_bytes()
                    } else {
                        let high = ((word >> 16) as u16).to_le_bytes();
                        let low = (word as u16).to_le_bytes();
                        [high[0], high[1], low[0], low[1]]
                    };
                    let instruction =
                        additional::decode(&bytes, mode).expect("extend-and-add encoding");
                    let mut lifter = Lifter {
                        image: &image,
                        summaries: &summaries,
                        stmts: Vec::new(),
                        flags: None,
                        float_comparison: false,
                        touched: false,
                    };
                    instruction.execute(&mut lifter, 0, mode == ArmMode::Thumb);
                    let rotated = format!(
                        "((_ zero_extend 32) ((_ rotate_right {rotation}) ((_ extract 31 0) r2)))"
                    );
                    let extended = if signed {
                        smt::signed(&rotated, width * 8)
                    } else {
                        smt::low(&rotated, width * 8)
                    };
                    let expected = smt::low(
                        &format!("(bvadd {} {extended})", smt::term(&Expr::reg(1, 32))),
                        32,
                    );
                    let [Stmt::Assign { dest, value }] = lifter.stmts.as_slice() else {
                        panic!("expected one assignment");
                    };
                    assert_eq!(dest.index, 0);
                    proofs.predicate(
                        format!("{mode:?}/{width}/{signed}/{rotation}"),
                        &expected,
                        &smt::term(&low(value.clone())),
                    );
                }
            }
        }
    }
    proofs.check();
}

#[test]
fn carry_arithmetic_is_symbolic() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    let image = Image::from_code(Isa::Arm32, 0, vec![0; 4]);
    let summaries = |_| Default::default();
    for opcode in [Opcode::ADC, Opcode::SBC, Opcode::RSC] {
        let mut lifter = Lifter {
            image: &image,
            summaries: &summaries,
            stmts: Vec::new(),
            flags: Some(Flags::difference(Expr::reg(3, 32), Expr::constant(1))),
            float_comparison: false,
            touched: false,
        };
        lifter.flags.as_mut().unwrap().width = Some(32);
        let instruction = Instruction {
            opcode,
            s: true,
            operands: [
                Operand::Reg(armv7::Reg::from_u8(2)),
                Operand::Reg(armv7::Reg::from_u8(0)),
                Operand::Reg(armv7::Reg::from_u8(1)),
                Operand::Nothing,
            ],
            ..Instruction::default()
        };
        assert_eq!(lifter.execute(&instruction, 0, 4, None), Some(false));
        let a = smt::term(&Expr::reg(if opcode == Opcode::RSC { 1 } else { 0 }, 32));
        let b = smt::term(&Expr::reg(if opcode == Opcode::RSC { 0 } else { 1 }, 32));
        let carry = format!(
            "(ite (= {} {}) {} {})",
            smt::term(&Expr::reg(3, 32)),
            smt::constant(0),
            smt::constant(0),
            smt::constant(1)
        );
        let incoming = Expr::Select {
            cond: Cond::Eq,
            lhs: Box::new(Expr::reg(3, 32)),
            rhs: Box::new(Expr::constant(0)),
            then: Box::new(Expr::constant(0)),
            els: Box::new(Expr::constant(1)),
        };
        let without_carry = smt::raw_bin(
            if opcode == Opcode::ADC {
                BinOp::Add
            } else {
                BinOp::Sub
            },
            Expr::reg(if opcode == Opcode::RSC { 1 } else { 0 }, 32),
            Expr::reg(if opcode == Opcode::RSC { 0 } else { 1 }, 32),
        );
        let adjustment = if opcode == Opcode::ADC {
            incoming.clone()
        } else {
            smt::raw_bin(BinOp::Xor, incoming.clone(), Expr::Const(1))
        };
        let exact_value = smt::raw_bin(
            if opcode == Opcode::ADC {
                BinOp::Add
            } else {
                BinOp::Sub
            },
            without_carry.clone(),
            adjustment,
        );
        let expected = smt::raw_bin(BinOp::And, exact_value.clone(), Expr::Const(0xffff_ffff));
        let mut statements = lifter.stmts.clone();
        statements.push(Stmt::Ret {
            value: Expr::reg(2, 64),
        });
        proofs.program(
            format!("carry arithmetic value/{opcode:?}"),
            &[Stmt::Ret {
                value: expected.clone(),
            }],
            &statements,
        );
        let wrong = smt::raw_bin(BinOp::And, without_carry, Expr::Const(0xffff_ffff));
        proofs.counterexample(
            format!("missing incoming carry or borrow/{opcode:?}"),
            &smt::term(&expected),
            &smt::term(&wrong),
        );
        proofs.counterexample(
            format!("missing result truncation/{opcode:?}"),
            &smt::term(&expected),
            &smt::term(&exact_value),
        );
        let exact = if opcode == Opcode::ADC {
            format!("(bvadd (bvadd {a} {b}) {carry})")
        } else {
            format!(
                "(bvsub (bvsub {a} {b}) (bvxor {carry} {}))",
                smt::constant(1)
            )
        };
        let signed_a = smt::signed(&a, 32);
        let signed_b = smt::signed(&b, 32);
        let signed_exact = if opcode == Opcode::ADC {
            format!("(bvadd (bvadd {signed_a} {signed_b}) {carry})")
        } else {
            format!(
                "(bvsub (bvsub {signed_a} {signed_b}) (bvxor {carry} {}))",
                smt::constant(1)
            )
        };
        let overflow = format!(
            "(or (bvslt {signed_exact} {}) (bvsgt {signed_exact} {}))",
            smt::constant(0xffff_ffff_8000_0000),
            smt::constant(0x7fff_ffff)
        );
        let flags = lifter.flags.as_ref().unwrap();
        for (cond, expected) in [
            (
                Cond::Eq,
                format!("(= {} {})", smt::low(&exact, 32), smt::constant(0)),
            ),
            (
                Cond::Mi,
                format!("(bvslt {} {})", smt::signed(&exact, 32), smt::constant(0)),
            ),
            (
                Cond::Cs,
                if opcode == Opcode::ADC {
                    format!("(bvugt {exact} {})", smt::constant(0xffff_ffff))
                } else {
                    format!(
                        "(bvuge {a} (bvadd {b} (bvxor {carry} {})))",
                        smt::constant(1)
                    )
                },
            ),
            (Cond::Vs, overflow.clone()),
            (Cond::Vc, format!("(not {overflow})")),
        ] {
            let actual = flags
                .test(cond, Isa::Arm32)
                .select(Expr::constant(1), Expr::constant(0))
                .unwrap();
            // Capture statements freeze the incoming carry before setting the output flags.
            let mut statements = lifter.stmts.clone();
            statements.push(Stmt::Ret { value: actual });
            // Substitute the captured carry so the predicate remains a pure expression.
            crate::ir::visit::replace_reads(
                statements.last_mut().unwrap(),
                &[(crate::ir::EXCHANGE, incoming.clone())],
            );
            let Stmt::Ret { value } = statements.last().unwrap() else {
                unreachable!()
            };
            proofs.predicate(
                format!("{opcode:?}/{cond:?}"),
                &format!("(ite {expected} {} {})", smt::constant(1), smt::constant(0)),
                &smt::term(value),
            );
            proofs.counterexample(
                format!("inverted carry-arithmetic flag/{opcode:?}/{cond:?}"),
                &format!("(ite {expected} {} {})", smt::constant(1), smt::constant(0)),
                &format!("(bvxor {} {})", smt::term(value), smt::constant(1)),
            );
        }
    }
    proofs.check();
}

#[test]
fn rotate_through_carry_preserves_value_and_flags() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    let image = Image::from_code(Isa::Arm32, 0, vec![0; 4]);
    let summaries = |_| Default::default();
    for set_flags in [false, true] {
        let mut flags = Flags::stored(Expr::reg(3, 8), Some(Expr::reg(4, 1)));
        flags.width = Some(32);
        let mut lifter = Lifter {
            image: &image,
            summaries: &summaries,
            stmts: Vec::new(),
            flags: Some(flags.clone()),
            float_comparison: false,
            touched: false,
        };
        let instruction = Instruction {
            opcode: Opcode::RRX,
            s: set_flags,
            operands: [
                Operand::Reg(armv7::Reg::from_u8(2)),
                Operand::Reg(armv7::Reg::from_u8(0)),
                Operand::Nothing,
                Operand::Nothing,
            ],
            ..Instruction::default()
        };
        assert_eq!(lifter.execute(&instruction, 0, 4, None), Some(false));
        let carry = flags
            .test(Cond::Cs, Isa::Arm32)
            .select(Expr::constant(1), Expr::constant(0))
            .unwrap();
        let x = smt::term(&Expr::reg(0, 32));
        let expected = format!(
            "(concat ((_ extract 0 0) {}) ((_ extract 31 1) r0))",
            smt::term(&carry)
        );
        let [Stmt::Assign { dest, value }] = lifter.stmts.as_slice() else {
            panic!("RRX assigns its destination once");
        };
        assert_eq!(dest.index, 2);
        let actual = smt::term(value);
        proofs.predicate(
            format!("RRX value/{set_flags}"),
            &format!("((_ zero_extend 32) {expected})"),
            &actual,
        );
        proofs.counterexample(
            format!("RRX missing carry/{set_flags}"),
            &actual,
            &format!("(bvlshr {x} {})", smt::constant(1)),
        );
        for cond in [Cond::Eq, Cond::Mi, Cond::Cs, Cond::Vs] {
            let expected_flag = if !set_flags || cond == Cond::Vs {
                let value = flags
                    .test(cond, Isa::Arm32)
                    .select(Expr::constant(1), Expr::constant(0))
                    .unwrap();
                smt::term(&value)
            } else {
                let condition = match cond {
                    Cond::Eq => format!("(= {expected} (_ bv0 32))"),
                    Cond::Mi => format!("(bvslt {expected} (_ bv0 32))"),
                    Cond::Cs => {
                        format!("(= (bvand {x} {}) {})", smt::constant(1), smt::constant(1))
                    }
                    _ => unreachable!(),
                };
                format!(
                    "(ite {condition} {} {})",
                    smt::constant(1),
                    smt::constant(0)
                )
            };
            let actual = lifter
                .flags
                .as_ref()
                .unwrap()
                .test(cond, Isa::Arm32)
                .select(Expr::constant(1), Expr::constant(0))
                .unwrap();
            proofs.predicate(
                format!("RRX flag/{set_flags}/{cond:?}"),
                &expected_flag,
                &smt::term(&actual),
            );
            proofs.counterexample(
                format!("RRX inverted flag/{set_flags}/{cond:?}"),
                &expected_flag,
                &format!("(bvxor {} {})", smt::term(&actual), smt::constant(1)),
            );
        }
        lifter.flags = None;
        assert_eq!(lifter.execute(&instruction, 0, 4, None), None);
    }
    proofs.check();
}

#[test]
fn shifted_carry_matches_extracted_bits() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for style in [
        ShiftStyle::LSL,
        ShiftStyle::LSR,
        ShiftStyle::ASR,
        ShiftStyle::ROR,
        ShiftStyle::RRX,
    ] {
        for amount in [0, 1, 7, 31, 32, 33, 63, 255] {
            let x = Expr::reg(0, 32);
            let old = Expr::bin(BinOp::And, Expr::reg(1, 32), Expr::constant(1));
            let actual =
                shifted_carry(x.clone(), style, &Expr::constant(amount), Some(old.clone()))
                    .unwrap();
            let bit = match (style, amount) {
                (ShiftStyle::RRX, _) => Some(0),
                (_, 0) => None,
                (ShiftStyle::LSL, 1..=32) => Some(32 - amount),
                (ShiftStyle::LSR, 1..=32) | (ShiftStyle::ASR, 1..=31) => Some(amount - 1),
                (ShiftStyle::ASR, _) => Some(31),
                (ShiftStyle::ROR, _) => Some((amount - 1) % 32),
                _ => Some(64),
            };
            let expected = match bit {
                None => smt::term(&old),
                Some(64) => smt::constant(0),
                Some(bit) => format!(
                    "((_ zero_extend 63) ((_ extract {bit} {bit}) {}))",
                    smt::term(&x)
                ),
            };
            proofs.predicate(
                format!("shift carry/{style:?}/{amount}"),
                &expected,
                &smt::term(&actual),
            );
        }
    }
    proofs.check();
}

#[test]
fn long_multiply_matches_a_wide_product() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    let image = Image::from_code(Isa::Arm32, 0, vec![0; 4]);
    let summaries = |_| Default::default();
    for opcode in [Opcode::UMULL, Opcode::SMULL, Opcode::UMLAL, Opcode::SMLAL] {
        let mut lifter = Lifter {
            image: &image,
            summaries: &summaries,
            stmts: Vec::new(),
            flags: None,
            float_comparison: false,
            touched: false,
        };
        let instruction = Instruction {
            opcode,
            operands: [0, 1, 2, 3].map(|index| Operand::Reg(armv7::Reg::from_u8(index))),
            ..Instruction::default()
        };
        assert_eq!(lifter.execute(&instruction, 0, 4, None), Some(false));
        lifter.stmts.push(Stmt::Ret {
            value: super::super::pairs32::join(Expr::reg(0, 32), Expr::reg(1, 32)),
        });
        let signed = matches!(opcode, Opcode::SMULL | Opcode::SMLAL);
        let extend = |index| {
            if signed {
                Expr::SignExtend {
                    value: Box::new(Expr::reg(index, 32)),
                    width: 4,
                }
            } else {
                Expr::reg(index, 32)
            }
        };
        let mut expected = Expr::Bin {
            op: BinOp::Mul,
            lhs: Box::new(extend(2)),
            rhs: Box::new(extend(3)),
        };
        if matches!(opcode, Opcode::UMLAL | Opcode::SMLAL) {
            expected = Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(expected),
                rhs: Box::new(super::super::pairs32::join(
                    Expr::reg(0, 32),
                    Expr::reg(1, 32),
                )),
            };
        }
        // Multiplication is compared through its actual 64-bit modular IR semantics.
        proofs.program(
            format!("long multiply/{opcode:?}"),
            &[Stmt::Ret { value: expected }],
            &lifter.stmts,
        );
    }
    proofs.check();
}

#[test]
fn rotated_extensions_and_shifted_operands_are_equivalent() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    let x = Expr::reg(0, 32);
    let input = "((_ extract 31 0) r0)";
    for bytes in [1, 2] {
        for signed in [false, true] {
            for rotation in [0, 8, 16, 24] {
                let rotated = format!("((_ zero_extend 32) ((_ rotate_right {rotation}) {input}))");
                let expected = if signed {
                    smt::signed(&rotated, u32::from(bytes) * 8)
                } else {
                    smt::low(&rotated, u32::from(bytes) * 8)
                };
                proofs.predicate(
                    format!("rotated extension/{bytes}/{signed}/{rotation}"),
                    &expected,
                    &smt::term(&extend(x.clone(), bytes, signed, rotation)),
                );
            }
        }
    }
    let amount = Expr::reg(1, 8);
    let count = smt::term(&amount);
    for style in [
        ShiftStyle::LSL,
        ShiftStyle::LSR,
        ShiftStyle::ASR,
        ShiftStyle::ROR,
    ] {
        let expected = match style {
            ShiftStyle::ROR => format!(
                "((_ zero_extend 32) (ext_rotate_right {input} ((_ extract 31 0) {count})))"
            ),
            ShiftStyle::ASR => smt::low(
                &format!("(bvashr {} {count})", smt::signed(&smt::term(&x), 32)),
                32,
            ),
            _ => smt::low(
                &format!(
                    "({} {} {count})",
                    if style == ShiftStyle::LSL {
                        "bvshl"
                    } else {
                        "bvlshr"
                    },
                    smt::term(&x)
                ),
                32,
            ),
        };
        let actual = shift_value(x.clone(), style, amount.clone()).expect("supported shift");
        proofs.predicate(
            format!("A32 shift/{style:?}"),
            &expected,
            &smt::low(&smt::term(&actual), 32),
        );
    }
    proofs.check();
}

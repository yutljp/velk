use super::*;
use crate::ir::smt::{self, Proofs};

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
        let exact = if opcode == Opcode::ADC {
            format!("(bvadd (bvadd {a} {b}) {carry})")
        } else {
            format!(
                "(bvsub (bvsub {a} {b}) (bvxor {carry} {}))",
                smt::constant(1)
            )
        };
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
        ] {
            let actual = flags
                .test(cond, Isa::Arm32)
                .select(Expr::constant(1), Expr::constant(0))
                .unwrap();
            // Capture statements freeze the incoming carry before setting the output flags.
            let mut statements = lifter.stmts.clone();
            statements.push(Stmt::Ret { value: actual });
            let expected_expr = Expr::Select {
                cond: Cond::Eq,
                lhs: Box::new(Expr::reg(3, 32)),
                rhs: Box::new(Expr::constant(0)),
                then: Box::new(Expr::constant(0)),
                els: Box::new(Expr::constant(1)),
            };
            // Substitute the captured carry so the predicate remains a pure expression.
            crate::ir::visit::replace_reads(
                statements.last_mut().unwrap(),
                &[(crate::ir::EXCHANGE, expected_expr)],
            );
            let Stmt::Ret { value } = statements.last().unwrap() else {
                unreachable!()
            };
            proofs.predicate(
                format!("{opcode:?}/{cond:?}"),
                &format!("(ite {expected} {} {})", smt::constant(1), smt::constant(0)),
                &smt::term(value),
            );
        }
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

//! Table lookup, variable shifts, and AES transformations.

use super::{
    BinOp, Cond, Expr, Instruction, LaneOp, Lifter, Operand, Operation, a64, by_halves, halves,
    lane_value, lanewise, vector,
};

pub(super) fn lift(lifter: &mut Lifter, ins: &Instruction) -> bool {
    use a64::Opcode as O;
    if !matches!(ins.opcode, O::USHL | O::TBL | O::TBX | O::AESE | O::AESMC) {
        return false;
    }
    let Some(dest) = vector(ins.operands[0]) else {
        lifter.incomplete.set(true);
        return true;
    };
    let ops = ins.operands;
    let result = match ins.opcode {
        O::USHL => {
            let (Some(a), Some(b)) = (vector(ops[1]), vector(ops[2])) else {
                lifter.incomplete.set(true);
                return true;
            };
            let (a, b) = (halves(a), halves(b));
            by_halves(a, b, |a, b| {
                lanewise(LaneOp::ShiftVariableUnsigned, dest.2, a, b)
            })
        }
        O::AESE | O::AESMC => {
            let Some(source) = vector(ops[1]) else {
                lifter.incomplete.set(true);
                return true;
            };
            let source = halves(source);
            let (round, state) = if ins.opcode == O::AESE {
                (
                    crate::ir::AesRound::EncryptLast,
                    by_halves(halves(dest), source, |a, b| Expr::bin(BinOp::Xor, a, b)),
                )
            } else {
                (crate::ir::AesRound::MixColumns, source)
            };
            let result = |high| {
                Expr::apply(
                    Operation::Aes { round, high },
                    vec![
                        state.0.clone(),
                        state.1.clone(),
                        Expr::constant(0),
                        Expr::constant(0),
                    ],
                )
            };
            (result(false), result(true))
        }
        _ => {
            let Operand::SIMDRegisterGroup(_, first, _, count) = ops[1] else {
                lifter.incomplete.set(true);
                return true;
            };
            let Some(indices) = vector(ops[2]) else {
                lifter.incomplete.set(true);
                return true;
            };
            if !(1..=4).contains(&count) {
                lifter.incomplete.set(true);
                return true;
            }
            let lookup = |half: u16| {
                let mut result = Expr::constant(0);
                for byte in 0..8 {
                    let index = lane_value((indices.0 + half, byte * 8, 8));
                    let mut value = if ins.opcode == O::TBX {
                        lane_value((dest.0 + half, byte * 8, 8))
                    } else {
                        Expr::constant(0)
                    };
                    for part in (0..u16::from(count) * 2).rev() {
                        let number = (first + part / 2) % 32;
                        let table = Expr::reg(crate::arch::aarch64::V0 + number * 2 + part % 2, 64);
                        let selected = Expr::bin(
                            BinOp::And,
                            Expr::bin(
                                BinOp::Shr,
                                table,
                                Expr::bin(
                                    BinOp::Mul,
                                    Expr::bin(BinOp::And, index.clone(), Expr::constant(7)),
                                    Expr::constant(8),
                                ),
                            ),
                            Expr::constant(255),
                        );
                        value = Expr::Select {
                            cond: Cond::Eq,
                            lhs: Box::new(Expr::bin(BinOp::Shr, index.clone(), Expr::constant(3))),
                            rhs: Box::new(Expr::constant(u64::from(part))),
                            then: Box::new(selected),
                            els: Box::new(value),
                        };
                    }
                    result = Expr::bin(
                        BinOp::Or,
                        result,
                        Expr::bin(BinOp::Shl, value, Expr::constant(byte * 8)),
                    );
                }
                result
            };
            (
                lookup(0),
                if dest.1 { lookup(1) } else { Expr::constant(0) },
            )
        }
    };
    lifter.write_vector(dest, result.0, result.1);
    true
}

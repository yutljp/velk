//! Checked recognition of simple stack-frame offsets.

use crate::ir::{BinOp, Expr};

pub(crate) fn checked_frame_slot(expr: &Expr, frame: i64, sp: u16) -> Option<i64> {
    let register = |value: &Expr| matches!(value, Expr::Reg { index, width: 64 } if *index == sp);
    let delta = match expr {
        value if register(value) => 0,
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (value, Expr::Const(delta)) | (Expr::Const(delta), value) if register(value) => {
                i128::from(*delta as i64)
            }
            _ => return None,
        },
        Expr::Bin {
            op: BinOp::Sub,
            lhs,
            rhs,
        } if register(lhs) => {
            let Expr::Const(delta) = rhs.as_ref() else {
                return None;
            };
            -i128::from(*delta as i64)
        }
        _ => return None,
    };
    i64::try_from(i128::from(frame) + delta).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binary(op: BinOp, lhs: Expr, rhs: Expr) -> Expr {
        Expr::Bin {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    #[test]
    fn checked_offsets_keep_their_grammar_and_signed_bounds() {
        let sp = 31;
        for frame in [i64::MIN, -16, 0, 16, i64::MAX] {
            assert_eq!(
                checked_frame_slot(&Expr::reg(sp, 64), frame, sp),
                Some(frame)
            );
            for delta in [i64::MIN, -1, 0, 1, i64::MAX] {
                let constant = Expr::Const(delta as u64);
                for (op, swapped, offset) in [
                    (BinOp::Add, false, i128::from(delta)),
                    (BinOp::Add, true, i128::from(delta)),
                    (BinOp::Sub, false, -i128::from(delta)),
                ] {
                    let (lhs, rhs) = if swapped {
                        (constant.clone(), Expr::reg(sp, 64))
                    } else {
                        (Expr::reg(sp, 64), constant.clone())
                    };
                    let address = binary(op, lhs, rhs);
                    let expected = i64::try_from(i128::from(frame) + offset).ok();
                    assert_eq!(
                        checked_frame_slot(&address, frame, sp),
                        expected,
                        "{address:?}"
                    );
                }
            }
            for base in [Expr::reg(sp, 32), Expr::reg(0, 64), Expr::Const(0)] {
                assert_eq!(checked_frame_slot(&base, frame, sp), None);
                for op in [BinOp::Add, BinOp::Sub] {
                    let address = binary(op, base.clone(), Expr::Const(8));
                    assert_eq!(checked_frame_slot(&address, frame, sp), None);
                }
            }
            for address in [
                binary(BinOp::Sub, Expr::Const(8), Expr::reg(sp, 64)),
                binary(BinOp::Add, Expr::reg(sp, 64), Expr::reg(0, 64)),
                binary(BinOp::Or, Expr::reg(sp, 64), Expr::Const(8)),
                binary(
                    BinOp::Add,
                    binary(BinOp::Add, Expr::reg(sp, 64), Expr::Const(8)),
                    Expr::Const(8),
                ),
            ] {
                assert_eq!(checked_frame_slot(&address, frame, sp), None);
            }
        }
        let address = binary(BinOp::Add, Expr::reg(sp, 64), Expr::Const(1));
        assert_eq!(
            super::super::frame_slot(&address, i64::MAX, sp),
            Some(i64::MIN)
        );
        assert_eq!(checked_frame_slot(&address, i64::MAX, sp), None);
    }
}

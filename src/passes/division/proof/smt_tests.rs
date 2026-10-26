use super::*;
use crate::ir::smt::{self, Proofs};

fn term(value: &Value) -> String {
    match value {
        Value::Input(index) => format!("r{index}"),
        Value::Const(value) => smt::constant(*value),
        Value::Bits(bits, value) => smt::low(&term(value), *bits),
        Value::Signed(bits, value) => smt::signed(&term(value), *bits),
        Value::Bin(op, width, a, b) => {
            let (mut a, mut b) = (term(a), term(b));
            if matches!(op, BinOp::Sar | BinOp::DivS | BinOp::ModS) {
                a = smt::signed(&a, *width);
                if *op != BinOp::Sar {
                    b = smt::signed(&b, *width);
                }
            }
            if matches!(op, BinOp::Shl | BinOp::Shr | BinOp::Sar) {
                b = smt::low(&b, 6);
            }
            let operator = match op {
                BinOp::Add => "bvadd",
                BinOp::Sub => "bvsub",
                BinOp::Mul => "bvmul",
                BinOp::And => "bvand",
                BinOp::Or => "bvor",
                BinOp::Xor => "bvxor",
                BinOp::Shl => "bvshl",
                BinOp::Shr => "bvlshr",
                BinOp::Sar => "bvashr",
                BinOp::DivU => "bvudiv",
                BinOp::ModU => "bvurem",
                BinOp::DivS => "bvsdiv",
                BinOp::ModS => "bvsrem",
                BinOp::MulHigh | BinOp::MulHighS => {
                    let extend = if *op == BinOp::MulHighS {
                        "sign_extend"
                    } else {
                        "zero_extend"
                    };
                    return format!(
                        "((_ extract 127 64) (bvmul ((_ {extend} 64) {a}) ((_ {extend} 64) {b})))"
                    );
                }
            };
            smt::low(&format!("({operator} {a} {b})"), *width)
        }
        Value::Select(cond, width, a, b, then, els) => format!(
            "(ite {} {} {})",
            smt::condition(*cond, &term(a), &term(b), *width),
            term(then),
            term(els)
        ),
    }
}

#[test]
fn normalization_preserves_modular_and_signed_values() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for width in [32, 64] {
        let a = Value::Input(0);
        let b = Value::Input(1);
        for op in [
            BinOp::Add,
            BinOp::Sub,
            BinOp::Mul,
            BinOp::And,
            BinOp::Or,
            BinOp::Xor,
            BinOp::Shl,
            BinOp::Shr,
            BinOp::Sar,
        ] {
            for rhs in [b.clone(), constant(0xffff_ffff), constant(0), constant(63)] {
                let raw = Value::Bin(op, 64, Box::new(a.clone()), Box::new(rhs.clone()));
                let normalized = bin(op, 64, a.clone(), rhs);
                for value in [raw, normalized] {
                    proofs.predicate(
                        format!("truncate/{width}/{op:?}/{value:?}"),
                        &smt::low(&term(&value), width),
                        &term(&bits(value.clone(), width)),
                    );
                    proofs.predicate(
                        format!("sign/{width}/{op:?}/{value:?}"),
                        &smt::signed(&term(&value), width),
                        &term(&signed(value.clone(), width)),
                    );
                }
            }
        }
        for cond in [Cond::Eq, Cond::Ne, Cond::Lt, Cond::Ge] {
            let value = Value::Select(
                cond,
                width,
                Box::new(a.clone()),
                Box::new(b.clone()),
                Box::new(a.clone()),
                Box::new(b.clone()),
            );
            proofs.predicate(
                format!("truncate select/{width}/{cond:?}"),
                &smt::low(&term(&value), width),
                &term(&bits(value, width)),
            );
        }
    }
    proofs.check();
}

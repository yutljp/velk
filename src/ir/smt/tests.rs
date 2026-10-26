use super::*;
use crate::ir::{FunctionIr, RegRef, Stmt};
use crate::loader::Isa;

fn bin(op: BinOp, lhs: Expr, rhs: Expr) -> Expr {
    Expr::Bin {
        op,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
    }
}

fn select(cond: Cond, lhs: Expr, rhs: Expr, then: Expr, els: Expr) -> Expr {
    Expr::Select {
        cond,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
        then: Box::new(then),
        els: Box::new(els),
    }
}

#[test]
fn a_zero_arithmetic_shift_still_truncates_its_operand() {
    for bits in [8, 16, 32] {
        let input = bin(BinOp::Add, Expr::reg(0, bits), Expr::reg(0, bits));
        let before = bin(BinOp::Sar, input.clone(), Expr::Const(0));
        let after = Expr::bin(BinOp::Sar, input, Expr::Const(0));
        let register = |index| (index == 0).then_some(1u64 << (bits - 1));
        assert_eq!(
            super::super::semantics::evaluate(&before, &register),
            Some(0)
        );
        assert_eq!(
            super::super::semantics::evaluate(&after, &register),
            Some(0)
        );
        let mut ir = FunctionIr::single_block(Isa::X86_64, vec![Stmt::Ret { value: before }]);
        crate::passes::simplify::simplify(&mut ir);
        let Stmt::Ret { value } = &ir.blocks[0].stmts[0] else {
            panic!("return remains");
        };
        assert_eq!(super::super::semantics::evaluate(value, &register), Some(0));
    }
}

#[test]
fn merging_masks_keeps_the_width_of_an_enclosing_signed_operation() {
    let value = bin(
        BinOp::And,
        bin(BinOp::And, Expr::reg(0, 16), Expr::Const(0xff)),
        Expr::Const(0xffff),
    );
    let value = bin(BinOp::Sar, value, Expr::Const(1));
    let register = |index| (index == 0).then_some(0x80);
    assert_eq!(
        super::super::semantics::evaluate(&value, &register),
        Some(0x40)
    );
    let mut ir = FunctionIr::single_block(Isa::X86_64, vec![Stmt::Ret { value }]);
    crate::passes::simplify::simplify(&mut ir);
    let Stmt::Ret { value } = &ir.blocks[0].stmts[0] else {
        panic!("return remains");
    };
    assert_eq!(
        super::super::semantics::evaluate(value, &register),
        Some(0x40)
    );
}

#[test]
fn propagated_constants_keep_the_assignment_truncation() {
    use crate::ir::eval;
    let setup = eval::Setup {
        seed: 0,
        convention: eval::Convention {
            arguments: &[],
            clobbered: &[],
        },
        registers: &[],
        memory: &[],
        step_limit: 16,
    };
    for bits in [8, 16, 32] {
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: 3,
                        width: bits,
                    },
                    value: Expr::Const(u64::MAX),
                },
                Stmt::Ret {
                    value: Expr::reg(3, 64),
                },
            ],
        );
        let original = eval::run(&ir, &setup);
        crate::passes::simplify::simplify(&mut ir);
        assert_eq!(eval::run(&ir, &setup), original, "assignment width {bits}");
    }
}

#[test]
fn equal_divisions_must_still_evaluate_the_denominator() {
    let divided = bin(BinOp::DivU, Expr::reg(0, 64), Expr::reg(1, 64));
    let registers = |index| match index {
        0 => Some(42),
        1 => Some(0),
        _ => None,
    };
    for op in [BinOp::Sub, BinOp::Xor] {
        let before = bin(op, divided.clone(), divided.clone());
        let after = Expr::bin(op, divided.clone(), divided.clone());
        assert_eq!(super::super::semantics::evaluate(&before, &registers), None);
        assert_eq!(super::super::semantics::evaluate(&after, &registers), None);
    }
}

#[test]
fn an_eight_byte_extension_keeps_the_high_half_of_a_merge() {
    let value = Expr::SignExtend {
        width: 8,
        value: Box::new(bin(
            BinOp::Or,
            bin(BinOp::And, Expr::reg(0, 64), Expr::Const(!0xffff_ffff)),
            Expr::reg(1, 32),
        )),
    };
    let registers = |index| match index {
        0 => Some(1u64 << 32),
        1 => Some(1),
        _ => None,
    };
    let expected = super::super::semantics::evaluate(&value, &registers);
    let mut ir = FunctionIr::single_block(Isa::X86_64, vec![Stmt::Ret { value }]);
    crate::passes::simplify::simplify(&mut ir);
    let Stmt::Ret { value } = &ir.blocks[0].stmts[0] else {
        panic!("return remains");
    };
    assert_eq!(
        super::super::semantics::evaluate(value, &registers),
        expected
    );
}

fn check_rewrite(proofs: &mut Proofs, name: &str, before: &Expr, after: &Expr) {
    if before == after {
        return;
    }
    proofs.expression(name, before, after, 64);
    if super::super::semantics::width(before) == super::super::semantics::width(after) {
        return;
    }
    for cond in CONDITIONS {
        let original = select(
            cond,
            before.clone(),
            Expr::reg(2, 8),
            Expr::Const(1),
            Expr::Const(0),
        );
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![Stmt::Ret {
                value: original.clone(),
            }],
        );
        crate::passes::simplify::simplify(&mut ir);
        let Stmt::Ret { value: actual } = &ir.blocks[0].stmts[0] else {
            panic!("return remains");
        };
        proofs.expression(format!("{name}/context/{cond:?}"), &original, actual, 64);
    }
    for amount in [0, 1] {
        let original = bin(BinOp::Sar, before.clone(), Expr::Const(amount));
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![Stmt::Ret {
                value: original.clone(),
            }],
        );
        crate::passes::simplify::simplify(&mut ir);
        let Stmt::Ret { value: actual } = &ir.blocks[0].stmts[0] else {
            panic!("return remains");
        };
        proofs.expression(format!("{name}/sar/{amount}"), &original, actual, 64);
    }
}

#[test]
fn constructors_and_simplification_are_equivalent() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for bits in [8, 16, 32, 64] {
        let x = Expr::reg(0, bits);
        let y = Expr::reg(1, bits);
        let c = Expr::Const;
        let mask = super::super::semantics::mask(u32::from(bits));
        let mut cases = Vec::new();
        let mut arbitrary = Expr::reg(0, bits);
        for part in 1..64 / bits {
            arbitrary = bin(
                BinOp::Or,
                arbitrary,
                bin(
                    BinOp::Shl,
                    Expr::reg(u16::from(part), bits),
                    Expr::Const(u64::from(part) * u64::from(bits)),
                ),
            );
        }
        proofs.expression(
            format!("zero arithmetic shift/arbitrary value/{bits}"),
            &bin(BinOp::Sar, arbitrary.clone(), c(0)),
            &Expr::bin(BinOp::Sar, arbitrary, c(0)),
            64,
        );
        for op in [BinOp::Sub, BinOp::Xor] {
            let divided = bin(BinOp::DivU, x.clone(), y.clone());
            proofs.expression(
                format!("discard division/{bits}/{op:?}"),
                &bin(op, divided.clone(), divided.clone()),
                &Expr::bin(op, divided.clone(), divided),
                64,
            );
        }
        for op in [
            BinOp::Add,
            BinOp::Sub,
            BinOp::Or,
            BinOp::Xor,
            BinOp::And,
            BinOp::Mul,
            BinOp::Shl,
            BinOp::Shr,
            BinOp::Sar,
        ] {
            for (a, b) in [
                (x.clone(), c(0)),
                (c(0), x.clone()),
                (x.clone(), x.clone()),
                (x.clone(), c(1)),
            ] {
                let before = bin(op, a.clone(), b.clone());
                let after = Expr::bin(op, a, b);
                check_rewrite(
                    &mut proofs,
                    &format!("constructor/{bits}/{op:?}/{before:?}"),
                    &before,
                    &after,
                );
                cases.push(before);
            }
        }
        for a in [0, 1, mask / 2, mask / 2 + 1, mask, u64::MAX] {
            for b in [0, 1, 2, 63, 64, mask, u64::MAX] {
                for op in [
                    BinOp::Add,
                    BinOp::Sub,
                    BinOp::Mul,
                    BinOp::MulHigh,
                    BinOp::MulHighS,
                    BinOp::And,
                    BinOp::Or,
                    BinOp::Xor,
                    BinOp::Shl,
                    BinOp::Shr,
                    BinOp::Sar,
                    BinOp::DivU,
                    BinOp::ModU,
                    BinOp::DivS,
                    BinOp::ModS,
                ] {
                    proofs.expression(
                        format!("constant/{bits}/{op:?}/{a}/{b}"),
                        &bin(op, c(a), c(b)),
                        &Expr::bin(op, c(a), c(b)),
                        64,
                    );
                }
            }
        }
        for k in [0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 65, 127, u64::MAX] {
            let shifted = bin(BinOp::Shl, x.clone(), c(k));
            cases.extend([
                bin(BinOp::Add, x.clone(), shifted.clone()),
                bin(BinOp::Sub, shifted.clone(), x.clone()),
                bin(BinOp::Mul, shifted, c(3)),
                bin(BinOp::Shl, bin(BinOp::Mul, x.clone(), c(3)), c(k)),
                bin(
                    BinOp::Or,
                    x.clone(),
                    bin(
                        BinOp::Shl,
                        bin(BinOp::And, bin(BinOp::Shr, x.clone(), c(k)), c(mask)),
                        c(k),
                    ),
                ),
            ]);
        }
        for offset in [0, 1, 0x80, 0xffff_ffff, 1 << 63, u64::MAX] {
            for delta in [0, 1, 0x100, u64::MAX] {
                for outer in [BinOp::Add, BinOp::Sub] {
                    for inner in [BinOp::Add, BinOp::Sub] {
                        cases.push(bin(outer, bin(inner, x.clone(), c(offset)), c(delta)));
                    }
                }
            }
        }
        for kept in [0, 1, 0x7f, 0xff, 0xffff, 0xffff_ffff, u64::MAX] {
            cases.extend([
                bin(BinOp::And, bin(BinOp::And, x.clone(), c(kept)), c(mask)),
                bin(
                    BinOp::And,
                    bin(BinOp::Or, bin(BinOp::And, x.clone(), c(!mask)), y.clone()),
                    c(kept),
                ),
            ]);
        }
        cases.push(bin(BinOp::Sub, c(0), bin(BinOp::Sub, c(0), x.clone())));
        for op in [
            BinOp::Add,
            BinOp::Sub,
            BinOp::Mul,
            BinOp::And,
            BinOp::Or,
            BinOp::Xor,
        ] {
            cases.push(bin(
                BinOp::And,
                bin(
                    op,
                    bin(BinOp::And, bin(BinOp::Add, x.clone(), c(1)), c(0xffff_ffff)),
                    bin(BinOp::And, bin(BinOp::Sub, y.clone(), c(1)), c(0xffff_ffff)),
                ),
                c(0xffff_ffff),
            ));
        }
        for bytes in [1, 2, 4, 8] {
            let low_mask = super::super::semantics::mask(u32::from(bytes) * 8);
            cases.push(Expr::SignExtend {
                width: bytes,
                value: Box::new(bin(BinOp::And, x.clone(), c(low_mask))),
            });
            cases.push(Expr::SignExtend {
                width: bytes,
                value: Box::new(bin(
                    BinOp::Or,
                    bin(BinOp::And, Expr::reg(0, 64), c(!0xffff_ffff)),
                    Expr::reg(1, 32),
                )),
            });
            cases.push(Expr::SignExtend {
                width: bytes,
                value: Box::new(bin(BinOp::And, x.clone(), c(0))),
            });
            cases.push(Expr::SignExtend {
                width: bytes,
                value: Box::new(bin(
                    BinOp::Or,
                    bin(BinOp::And, x.clone(), c(!low_mask)),
                    y.clone(),
                )),
            });
            cases.push(bin(
                BinOp::And,
                Expr::Load {
                    addr: Box::new(x.clone()),
                    width: bytes,
                    signed: false,
                },
                c(low_mask),
            ));
        }
        for cond in CONDITIONS {
            cases.extend([
                select(cond, x.clone(), x.clone(), y.clone(), c(11)),
                select(cond, c(mask), c(0), x.clone(), y.clone()),
            ]);
        }
        for (index, before) in cases.into_iter().enumerate() {
            let mut ir = FunctionIr::single_block(
                Isa::X86_64,
                vec![Stmt::Ret {
                    value: before.clone(),
                }],
            );
            crate::passes::simplify::simplify(&mut ir);
            let Stmt::Ret { value: after } = &ir.blocks[0].stmts[0] else {
                panic!("return remains");
            };
            check_rewrite(
                &mut proofs,
                &format!("simplify/{bits}/{index}/{before:?}"),
                &before,
                after,
            );
        }
    }
    proofs.check();
}

#[test]
fn lane_identities_and_bit_counts_are_equivalent() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for bits in [8, 16, 32, 64] {
        for lane in [
            LaneOp::Equal,
            LaneOp::GreaterEqualSigned,
            LaneOp::GreaterEqualUnsigned,
            LaneOp::Sub,
            LaneOp::GreaterSigned,
            LaneOp::GreaterUnsigned,
        ] {
            let before = Expr::apply(
                Operation::Lanes(lane, bits),
                vec![Expr::reg(0, 64), Expr::reg(0, 64)],
            );
            let mut ir = FunctionIr::single_block(
                Isa::AArch64,
                vec![Stmt::Ret {
                    value: before.clone(),
                }],
            );
            crate::passes::simplify::simplify(&mut ir);
            let Stmt::Ret { value: after } = &ir.blocks[0].stmts[0] else {
                panic!("return remains");
            };
            proofs.expression(format!("lanes/{bits}/{lane:?}"), &before, after, 64);
        }
    }
    for lane in [LaneOp::Sub, LaneOp::Equal] {
        let divided = bin(BinOp::DivU, Expr::reg(0, 64), Expr::reg(1, 64));
        let before = Expr::apply(Operation::Lanes(lane, 8), vec![divided.clone(), divided]);
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![Stmt::Ret {
                value: before.clone(),
            }],
        );
        crate::passes::simplify::simplify(&mut ir);
        let Stmt::Ret { value: after } = &ir.blocks[0].stmts[0] else {
            panic!("return remains");
        };
        proofs.expression(
            format!("lanes preserve division faults/{lane:?}"),
            &before,
            after,
            64,
        );
    }
    for args in [
        vec![Expr::reg(0, 64)],
        vec![Expr::reg(0, 64), Expr::reg(1, 64)],
    ] {
        let two_halves = args.len() == 2;
        let mut counts: Vec<Expr> = args
            .into_iter()
            .map(|arg| Expr::apply(Operation::Lanes(LaneOp::PopCount, 8), vec![arg]))
            .collect();
        if counts.len() == 1 {
            counts.push(Expr::Const(0));
        }
        let before = Expr::apply(
            Operation::SumLanesLong {
                bits: 8,
                signed: false,
            },
            counts,
        );
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![Stmt::Ret {
                value: before.clone(),
            }],
        );
        crate::passes::simplify::simplify(&mut ir);
        let Stmt::Ret { value: after } = &ir.blocks[0].stmts[0] else {
            panic!("return remains");
        };
        if !two_halves {
            proofs.expression("byte popcounts sum", &before, after, 64);
        } else {
            let expected = Expr::bin(
                BinOp::Add,
                Expr::apply(Operation::PopCount(64), vec![Expr::reg(0, 64)]),
                Expr::apply(Operation::PopCount(64), vec![Expr::reg(1, 64)]),
            );
            assert_eq!(after, &expected, "the two halves sum their own counts");
            let sum = bin(BinOp::Add, Expr::reg(0, 8), Expr::reg(1, 8));
            proofs.expression(
                "two byte-count sums fit the widened result",
                &bin(BinOp::And, sum.clone(), Expr::Const(0xffff)),
                &sum,
                64,
            );
        }
    }
    proofs.check();
}

#[test]
fn assignment_rewrites_preserve_truncation() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    let passes = [
        (
            "simplify",
            crate::passes::simplify::simplify as fn(&mut FunctionIr),
        ),
        ("copies", crate::passes::copies::copy_propagate),
        (
            "guarded copies",
            crate::passes::copies::copy_propagate_guarded,
        ),
        ("local copies", crate::passes::copies::inline_local_copies),
        ("read once", crate::passes::read_once::fold_values_read_once),
        ("CSE", crate::passes::cse::cse),
        ("SSA constants", crate::ssa::propagate_constants),
        ("SSA ranges", |ir| {
            crate::ssa::ranges::simplify(ir);
        }),
    ];
    for bits in [8, 16, 32, 64] {
        for read in [8, 16, 32, 64] {
            let mut values = vec![
                Expr::Const(0),
                Expr::Const(1),
                Expr::Const(1u64 << (bits - 1)),
                Expr::Const(u64::MAX),
                Expr::reg(0, 64),
                bin(BinOp::Add, Expr::reg(0, 64), Expr::reg(1, 64)),
                Expr::SignExtend {
                    value: Box::new(Expr::reg(0, 64)),
                    width: bits / 8,
                },
            ];
            for op in [BinOp::Sar, BinOp::And, BinOp::Sub] {
                values.push(bin(op, Expr::reg(0, bits), Expr::Const(1)));
            }
            for (index, assigned) in values.into_iter().enumerate() {
                let mut uses = vec![Expr::reg(3, read)];
                for op in [BinOp::Add, BinOp::Sar, BinOp::DivS, BinOp::ModS] {
                    uses.push(bin(op, Expr::reg(3, read), Expr::Const(3)));
                }
                for cond in CONDITIONS {
                    uses.push(select(
                        cond,
                        Expr::reg(3, read),
                        Expr::Const(0xff),
                        Expr::Const(1),
                        Expr::Const(0),
                    ));
                }
                for (use_index, value) in uses.into_iter().enumerate() {
                    let before = FunctionIr::single_block(
                        Isa::X86_64,
                        vec![
                            Stmt::Assign {
                                dest: RegRef {
                                    index: 3,
                                    width: bits,
                                },
                                value: assigned.clone(),
                            },
                            Stmt::Ret { value },
                        ],
                    );
                    for (name, pass) in passes {
                        let mut after = before.clone();
                        pass(&mut after);
                        proofs.program(
                            format!("{name}/{bits}/{read}/{index}/{use_index}"),
                            &before.blocks[0].stmts,
                            &after.blocks[0].stmts,
                        );
                    }
                }
            }
        }
    }
    proofs.check();
}

#[test]
fn inventory_matches_the_reviewed_sources() {
    use sha2::Digest;
    for line in include_str!("../../../tests/smt_inventory.tsv")
        .lines()
        .skip(1)
    {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 6, "inventory rows have six fields: {line}");
        let (path, number) = fields[0].rsplit_once(':').expect("inventory file and line");
        let number: usize = number.parse().expect("inventory source line");
        let source = std::fs::read_to_string(path).expect("inventory source exists");
        assert!(
            source
                .lines()
                .nth(number - 1)
                .is_some_and(|line| line.contains(fields[5])),
            "inventory location must match {line}"
        );
    }
    for line in include_str!("../../../tests/smt_sources.sha256").lines() {
        let (expected, path) = line.split_once("  ").expect("source digest and path");
        let source = std::fs::read(path).expect("inventoried source exists");
        assert_eq!(
            format!("{:x}", sha2::Sha256::digest(source)),
            expected,
            "revisit inventory and proof coverage after changing {path}"
        );
    }
}

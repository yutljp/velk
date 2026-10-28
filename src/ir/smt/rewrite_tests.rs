//! Symbolic templates for branch, memory, demand and expression rewrites.

use super::*;
use crate::ir::{Block, FunctionIr, RegRef};
use crate::loader::Isa;

fn assign(index: u16, width: u8, value: Expr) -> Stmt {
    Stmt::Assign {
        dest: RegRef { index, width },
        value,
    }
}

fn load(addr: Expr, width: u8, signed: bool) -> Expr {
    Expr::Load {
        addr: Box::new(addr),
        width,
        signed,
    }
}

#[test]
fn vector_byte_sums_match_scalar_addition() {
    if !Proofs::available() {
        return;
    }
    let input = Expr::reg(0, 32);
    let mut reference = Expr::Const(0);
    for shift in [0, 8, 16, 24] {
        let byte = raw_bin(
            BinOp::And,
            raw_bin(BinOp::Shr, input.clone(), Expr::Const(shift)),
            Expr::Const(255),
        );
        reference = raw_bin(BinOp::Add, reference, byte);
    }
    let widened = Expr::apply(
        Operation::Widen {
            bits: 8,
            signed: false,
            high: false,
        },
        vec![input.clone()],
    );
    let arm_sum = Expr::apply(Operation::SumLanes(16), vec![widened, Expr::Const(0)]);
    let interleaved = Expr::apply(Operation::InterleaveLow(8), vec![input, Expr::Const(0)]);
    let high = raw_bin(BinOp::Shr, interleaved.clone(), Expr::Const(32));
    let duplicated = raw_bin(
        BinOp::Or,
        high.clone(),
        raw_bin(BinOp::Shl, high, Expr::Const(32)),
    );
    let pairs = Expr::apply(
        Operation::Lanes(LaneOp::Add, 16),
        vec![duplicated, interleaved],
    );
    let shifted = Expr::apply(
        Operation::Lanes(LaneOp::ShiftRight, 32),
        vec![pairs.clone(), Expr::Const(16)],
    );
    let x86_sum = raw_bin(
        BinOp::And,
        Expr::apply(Operation::Lanes(LaneOp::Add, 16), vec![shifted, pairs]),
        Expr::Const(65535),
    );
    let mut proofs = Proofs::default();
    proofs.expression("AArch64 byte sum", &arm_sum, &reference, 64);
    proofs.expression("x86 byte sum", &x86_sum, &reference, 64);
    proofs.check();
}

fn branch(cond: Cond, lhs: Expr, rhs: Expr) -> FunctionIr {
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![Stmt::Brif {
            cond,
            lhs,
            rhs,
            target: 2,
        }],
    );
    ir.blocks.extend([
        Block {
            start: 1,
            stmts: vec![Stmt::Ret {
                value: Expr::Const(0),
            }],
        },
        Block {
            start: 2,
            stmts: vec![Stmt::Ret {
                value: Expr::Const(1),
            }],
        },
    ]);
    ir
}

#[test]
fn branch_offsets_and_round_trips_are_equivalent() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for bits in [8, 16, 32, 64] {
        let x = Expr::reg(0, bits);
        for offset in [1, 0x80, 0xffff_ffff, 1 << 63, u64::MAX] {
            for op in [BinOp::Add, BinOp::Sub] {
                let inverse = if op == BinOp::Add {
                    BinOp::Sub
                } else {
                    BinOp::Add
                };
                let offset = Expr::Const(offset);
                let inner = raw_bin(op, x.clone(), offset.clone());
                for masked in [false, true] {
                    let inner = if masked {
                        raw_bin(BinOp::And, inner.clone(), Expr::Const(0xffff_ffff))
                    } else {
                        inner.clone()
                    };
                    let round_trip = raw_bin(inverse, inner, offset.clone());
                    for cond in CONDITIONS {
                        let before = branch(cond, round_trip.clone(), Expr::Const(0x80));
                        let mut after = before.clone();
                        crate::passes::simplify::simplify(&mut after);
                        proofs.function(
                            format!("round trip/{bits}/{op:?}/{masked}/{cond:?}/{offset:?}"),
                            &before,
                            &after,
                        );
                    }
                }
                for cond in [Cond::Eq, Cond::Ne] {
                    let before = branch(
                        cond,
                        raw_bin(op, x.clone(), offset.clone()),
                        Expr::Const(0xff),
                    );
                    let mut after = before.clone();
                    crate::passes::simplify::simplify(&mut after);
                    assert_ne!(
                        format!("{:?}", before.blocks),
                        format!("{:?}", after.blocks),
                        "offset template must exercise the rewrite"
                    );
                    proofs.function(
                        format!("move offset/{bits}/{op:?}/{cond:?}/{offset:?}"),
                        &before,
                        &after,
                    );
                }
            }
        }
    }
    proofs.check();
}

#[test]
fn sums_substitutions_and_field_partitions_are_equivalent() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for bits in [8, 16, 32, 64] {
        let x = Expr::reg(0, bits);
        let y = Expr::reg(1, bits);
        for offset in [0, 1, u64::MAX] {
            let before = raw_bin(
                BinOp::Add,
                raw_bin(BinOp::Sub, x.clone(), Expr::Const(offset)),
                raw_bin(BinOp::Sub, y.clone(), x.clone()),
            );
            for negative in [false, true] {
                let mut terms = Vec::new();
                crate::ir::visit::sum_terms(&before, negative, &mut terms);
                let mut after = Expr::Const(0);
                for (value, subtract) in terms {
                    after = raw_bin(
                        if subtract { BinOp::Sub } else { BinOp::Add },
                        after,
                        value.clone(),
                    );
                }
                let expected = if negative {
                    raw_bin(BinOp::Sub, Expr::Const(0), before.clone())
                } else {
                    before.clone()
                };
                proofs.expression(
                    format!("sum terms/{bits}/{offset}/{negative}"),
                    &expected,
                    &after,
                    64,
                );
            }
            let replacement = raw_bin(
                BinOp::And,
                raw_bin(BinOp::Xor, y.clone(), Expr::Const(offset)),
                Expr::Const(crate::ir::semantics::mask(u32::from(bits))),
            );
            let mut registers = BTreeMap::new();
            registers.insert(0, term(&replacement));
            let after = crate::ir::visit::substitute_values(before.clone(), &[(0, replacement)]);
            proofs.predicate(
                format!("substitution/{bits}/{offset}"),
                &value(&before, &registers).term,
                &term(&after),
            );
        }
        for split in [1, 7, 8, 16, 31, 32, 63] {
            let mask = (1u64 << split) - 1;
            let before = raw_bin(
                BinOp::Or,
                raw_bin(
                    BinOp::Shl,
                    raw_bin(
                        BinOp::And,
                        raw_bin(BinOp::Shr, x.clone(), Expr::Const(split)),
                        Expr::Const(!mask >> split),
                    ),
                    Expr::Const(split),
                ),
                raw_bin(BinOp::And, x.clone(), Expr::Const(mask)),
            );
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
            if split < u64::from(bits) && split != 32 {
                assert_ne!(&before, after, "partition template must be rewritten");
            }
            super::tests::check_rewrite(
                &mut proofs,
                &format!("fields/{bits}/{split}"),
                &before,
                after,
            );
        }
    }
    proofs.check();
}

#[test]
fn stores_forwarding_and_fusion_are_equivalent() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for bits in [8, 16, 32, 64] {
        let width = bits / 8;
        let mask = crate::ir::semantics::mask(u32::from(bits));
        let addr = Expr::reg(2, 64);
        let x = Expr::reg(0, 64);
        for stored in [
            raw_bin(BinOp::And, x.clone(), Expr::Const(mask)),
            raw_bin(
                BinOp::Or,
                raw_bin(BinOp::And, Expr::reg(1, 64), Expr::Const(!mask)),
                x.clone(),
            ),
        ] {
            let before = FunctionIr::single_block(
                Isa::X86_64,
                vec![
                    Stmt::Store {
                        addr: addr.clone(),
                        value: stored,
                        width,
                    },
                    Stmt::Ret {
                        value: load(addr.clone(), width, false),
                    },
                ],
            );
            let mut after = before.clone();
            crate::passes::simplify::simplify(&mut after);
            proofs.function(
                format!("store masks/{bits}/{:?}", before.blocks),
                &before,
                &after,
            );
        }
        for signed in [false, true] {
            for overlap in [0, 1, 8] {
                let before = FunctionIr::single_block(
                    Isa::X86_64,
                    vec![
                        Stmt::Store {
                            addr: addr.clone(),
                            value: x.clone(),
                            width,
                        },
                        Stmt::Store {
                            addr: raw_bin(BinOp::Add, addr.clone(), Expr::Const(overlap)),
                            value: Expr::reg(1, 64),
                            width: 1,
                        },
                        Stmt::Ret {
                            value: load(addr.clone(), width, signed),
                        },
                    ],
                );
                let mut after = before.clone();
                crate::passes::memory::forward_stored_values(&mut after);
                proofs.function(
                    format!("forward overlap/{bits}/{signed}/{overlap}"),
                    &before,
                    &after,
                );
            }
            let before = FunctionIr::single_block(
                Isa::X86_64,
                vec![
                    Stmt::Store {
                        addr: addr.clone(),
                        value: x.clone(),
                        width,
                    },
                    Stmt::Ret {
                        value: load(addr.clone(), width, signed),
                    },
                ],
            );
            let mut after = before.clone();
            crate::passes::memory::forward_stored_values(&mut after);
            assert_ne!(
                format!("{:?}", before.blocks),
                format!("{:?}", after.blocks),
                "forwarding template must change"
            );
            proofs.function(format!("forward/{bits}/{signed}"), &before, &after);
        }
        for op in [BinOp::Add, BinOp::Sub, BinOp::And, BinOp::Or, BinOp::Xor] {
            let before = FunctionIr::single_block(
                Isa::X86_64,
                vec![
                    assign(3, bits, load(addr.clone(), width, false)),
                    assign(3, bits, raw_bin(op, Expr::reg(3, bits), Expr::reg(0, bits))),
                    Stmt::Store {
                        addr: addr.clone(),
                        value: Expr::reg(3, bits),
                        width,
                    },
                    Stmt::Ret {
                        value: load(addr.clone(), width, false),
                    },
                ],
            );
            let mut after = before.clone();
            crate::passes::memory::fuse_load_op_store(&mut after);
            proofs.function(format!("load/store fusion/{bits}/{op:?}"), &before, &after);
        }
    }
    proofs.check();
}

#[test]
fn cfg_propagation_and_demand_are_equivalent() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    let passes = [
        (
            "copies",
            crate::passes::copies::copy_propagate as fn(&mut FunctionIr),
        ),
        ("local copies", crate::passes::copies::inline_local_copies),
        ("read once", crate::passes::read_once::fold_values_read_once),
        ("CSE", crate::passes::cse::cse),
        ("SCCP", crate::ssa::propagate_constants),
        ("ranges", |ir| {
            crate::ssa::ranges::simplify(ir);
        }),
        ("demand", crate::ssa::narrow_partial_writes),
        ("widths", |ir| {
            crate::passes::widths::specialize_widths(ir, &|_| false);
        }),
    ];
    for bits in [8, 16, 32, 64] {
        let mask = crate::ir::semantics::mask(u32::from(bits));
        for cond in CONDITIONS {
            for narrow in [false, true] {
                let merged = raw_bin(
                    BinOp::Or,
                    raw_bin(BinOp::And, Expr::reg(3, 64), Expr::Const(!mask)),
                    raw_bin(BinOp::And, Expr::reg(0, 64), Expr::Const(mask)),
                );
                let used = if narrow {
                    raw_bin(BinOp::And, Expr::reg(3, 64), Expr::Const(mask))
                } else {
                    Expr::reg(3, 64)
                };
                let mut before = branch(cond, Expr::reg(0, bits), Expr::Const(0x80));
                before.blocks[0].stmts.insert(0, assign(3, 64, merged));
                before.blocks[1].stmts = vec![
                    assign(4, bits, Expr::Const(u64::MAX)),
                    Stmt::Br { target: Some(3) },
                ];
                before.blocks[2].stmts = vec![assign(4, bits, used), Stmt::Br { target: Some(3) }];
                before.blocks.push(Block {
                    start: 3,
                    stmts: vec![Stmt::Ret {
                        value: raw_bin(BinOp::Add, Expr::reg(4, 64), Expr::reg(0, 64)),
                    }],
                });
                for (name, pass) in passes {
                    let mut after = before.clone();
                    pass(&mut after);
                    proofs.function(
                        format!("CFG/{name}/{bits}/{cond:?}/{narrow}"),
                        &before,
                        &after,
                    );
                }
            }
        }
    }
    let before = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            assign(
                3,
                64,
                raw_bin(
                    BinOp::And,
                    raw_bin(BinOp::Add, Expr::reg(0, 32), Expr::reg(1, 32)),
                    Expr::Const(0xffff_ffff),
                ),
            ),
            Stmt::Ret {
                value: Expr::reg(3, 64),
            },
        ],
    );
    let mut after = before.clone();
    let narrowed = crate::passes::widths::specialize_widths(&mut after, &|_| false);
    assert!(
        narrowed.contains(&3),
        "width specialization must exercise the narrow variable"
    );
    proofs.function("whole-function width specialization", &before, &after);
    proofs.check();
}

#[test]
fn quotient_arithmetic_and_range_masks_are_equivalent() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for bits in [8, 16, 32, 64] {
        let x = Expr::reg(0, bits);
        for divisor in [0, 1, 2, 3, 8, 17] {
            let quotient = raw_bin(BinOp::DivU, x.clone(), Expr::Const(divisor));
            let mut cases = vec![raw_bin(
                BinOp::Sub,
                x.clone(),
                raw_bin(BinOp::Mul, quotient.clone(), Expr::Const(divisor)),
            )];
            for shift in [1, 7, 16, 31] {
                for masked in [false, true] {
                    let q = if masked {
                        raw_bin(BinOp::And, quotient.clone(), Expr::Const(0xffff_ffff))
                    } else {
                        quotient.clone()
                    };
                    cases.push(raw_bin(
                        BinOp::Add,
                        q.clone(),
                        raw_bin(BinOp::Shl, q, Expr::Const(shift)),
                    ));
                }
            }
            for (index, before) in cases.into_iter().enumerate() {
                let after = crate::passes::simplify::algebraic(before.clone());
                if bits <= 16 || divisor.is_power_of_two() || divisor <= 1 || index > 0 {
                    super::tests::check_rewrite(
                        &mut proofs,
                        &format!("quotient arithmetic/{bits}/{divisor}/{index}"),
                        &before,
                        &after,
                    );
                } else {
                    assert!(
                        matches!(
                            after,
                            Expr::Bin {
                                op: BinOp::ModU,
                                ..
                            }
                        ),
                        "multiply-back must become remainder"
                    );
                    proofs.predicate(format!("multiply-back integer decomposition/{bits}/{divisor}"), "true", &format!("(=> (and (>= q 0) (>= r 0) (< r {divisor})) (= (- (+ (* q {divisor}) r) (* q {divisor})) r))"));
                }
            }
        }
        for (magic, shift) in [(0xaaaa_aaab, 33), (0xcccc_cccd, 34), (0x8080_8081, 39)] {
            let before = raw_bin(
                BinOp::Shr,
                raw_bin(BinOp::Mul, x.clone(), Expr::Const(magic)),
                Expr::Const(shift),
            );
            let after = crate::passes::simplify::algebraic(before.clone());
            if bits <= 32 {
                assert_ne!(before, after, "reciprocal template must be accepted");
            }
            // The independent reciprocal certificates cover full 32-bit inputs;
            // smaller inputs also permit fast bit-vector checks of the recognizer.
            if bits <= 8 {
                proofs.expression(
                    format!("expression reciprocal/{bits}/{magic}/{shift}"),
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
fn full_width_power_of_two_reciprocals_are_equivalent() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for shift in [32, 33, 40, 61, 63] {
        let magic = 1u64 << 31;
        let divisor = 1u64 << (shift - 31);
        let before = raw_bin(
            BinOp::Shr,
            raw_bin(BinOp::Mul, Expr::reg(0, 32), Expr::Const(magic)),
            Expr::Const(shift),
        );
        let after = crate::passes::simplify::algebraic(before.clone());
        let expected = raw_bin(BinOp::DivU, Expr::reg(0, 32), Expr::Const(divisor));
        assert_eq!(after, expected, "the real reciprocal rewrite must match");
        proofs.expression(format!("full32 reciprocal/{shift}"), &before, &after, 64);
        let wrong = raw_bin(BinOp::DivU, Expr::reg(0, 32), Expr::Const(divisor / 2));
        proofs.counterexample(
            format!("wrong reciprocal shift/{shift}"),
            &super::term(&after),
            &super::term(&wrong),
        );
    }
    proofs.check();
}

#[test]
fn ieee_constant_folding_matches_the_solver() {
    use crate::ir::{Precision, Rounding};
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for precision in [Precision::Single, Precision::Double] {
        let encode = |number: f64| {
            if precision == Precision::Single {
                u64::from((number as f32).to_bits())
            } else {
                number.to_bits()
            }
        };
        let mut operations = vec![
            Operation::FloatAdd(precision),
            Operation::FloatSub(precision),
            Operation::FloatMul(precision),
            Operation::FloatDiv(precision),
            Operation::FloatSqrt(precision),
            Operation::FloatNegate(precision),
            Operation::FloatAbs(precision),
            Operation::FloatMulAdd(precision),
            Operation::FloatEqual(precision),
            Operation::FloatLess(precision),
            Operation::FloatLessEqual(precision),
            Operation::FloatUnordered(precision),
            Operation::FloatConvert {
                from: precision,
                to: if precision == Precision::Single {
                    Precision::Double
                } else {
                    Precision::Single
                },
            },
        ];
        for mode in [
            Rounding::TowardZero,
            Rounding::NearestEven,
            Rounding::NearestAway,
            Rounding::Down,
            Rounding::Up,
        ] {
            operations.push(Operation::FloatRound(precision, mode));
            for width in [8, 16, 32, 64] {
                for signed in [false, true] {
                    for saturating in [false, true] {
                        operations.push(Operation::FloatToInt {
                            signed,
                            bits: width,
                            from: precision,
                            saturating,
                            rounding: mode,
                        });
                    }
                }
            }
        }
        for op in operations {
            for number in [
                0.0,
                -0.0,
                1.0,
                -1.0,
                1.5,
                -2.5,
                f64::INFINITY,
                f64::NEG_INFINITY,
                f64::NAN,
                f64::MIN_POSITIVE,
                f64::MAX,
            ] {
                let mut args = vec![
                    Expr::Const(encode(number)),
                    Expr::Const(encode(2.0)),
                    Expr::Const(encode(-1.0)),
                ];
                args.truncate(op.arity());
                let before = Expr::Apply {
                    op,
                    args: args.clone(),
                };
                let values: Vec<u64> = args
                    .iter()
                    .map(|value| match value {
                        Expr::Const(value) => *value,
                        _ => unreachable!(),
                    })
                    .collect();
                let after = crate::ir::semantics::fold(op, &values)
                    .map(Expr::Const)
                    .unwrap_or_else(|| before.clone());
                proofs.expression(
                    format!("IEEE fold/{precision:?}/{op:?}/{number}"),
                    &before,
                    &after,
                    64,
                );
            }
        }
        for bits in [8, 16, 32, 64] {
            for signed in [false, true] {
                let op = Operation::IntToFloat {
                    signed,
                    bits,
                    to: precision,
                };
                for number in [
                    0,
                    1,
                    u64::MAX,
                    1 << (bits - 1),
                    0x0100_0001,
                    0x0020_0000_0000_0001,
                ] {
                    let before = Expr::Apply {
                        op,
                        args: vec![Expr::Const(number)],
                    };
                    let after = Expr::Const(
                        crate::ir::semantics::fold(op, &[number])
                            .expect("integer conversion folds"),
                    );
                    proofs.expression(
                        format!("integer to float/{precision:?}/{bits}/{signed}/{number}"),
                        &before,
                        &after,
                        64,
                    );
                }
            }
        }
    }
    proofs.check();
}

#[test]
fn integer_and_lane_constant_folding_matches_the_solver() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for bits in [8, 16, 32] {
        let mut operations = vec![
            Operation::CountLeadingZeros(bits),
            Operation::CountTrailingZeros(bits),
            Operation::ReverseBits(bits),
            Operation::SignBits(bits),
            Operation::SumLanes(bits),
            Operation::InterleaveLow(bits),
            Operation::InterleaveHigh(bits),
            Operation::Narrow(bits * 2),
            Operation::Pack {
                from: bits * 2,
                unsigned: false,
            },
            Operation::Pack {
                from: bits * 2,
                unsigned: true,
            },
        ];
        for signed in [false, true] {
            for high in [false, true] {
                operations.push(Operation::Widen { bits, signed, high });
            }
        }
        for lane in [
            LaneOp::Add,
            LaneOp::Sub,
            LaneOp::Mul,
            LaneOp::Equal,
            LaneOp::GreaterSigned,
            LaneOp::GreaterUnsigned,
            LaneOp::GreaterEqualSigned,
            LaneOp::GreaterEqualUnsigned,
            LaneOp::MinSigned,
            LaneOp::MinUnsigned,
            LaneOp::MaxSigned,
            LaneOp::MaxUnsigned,
            LaneOp::ShiftLeft,
            LaneOp::ShiftRight,
            LaneOp::ShiftRightSigned,
            LaneOp::ShiftVariableUnsigned,
            LaneOp::CountLeadingZeros,
            LaneOp::AddSaturatingSigned,
            LaneOp::AddSaturatingUnsigned,
            LaneOp::SubSaturatingSigned,
            LaneOp::SubSaturatingUnsigned,
            LaneOp::Average,
            LaneOp::MulHighSigned,
            LaneOp::MulHighUnsigned,
        ] {
            operations.push(Operation::Lanes(lane, bits));
        }
        for op in operations {
            for a in [0, 1, u64::MAX, 0x8080_7fff_00ff_0180, 0x1234_5678_9abc_def0] {
                for b in [0, 1, 8, 31, 64, u64::MAX, 0x7fff_8000_ffff_0001] {
                    let mut args = vec![Expr::Const(a), Expr::Const(b)];
                    args.truncate(op.arity());
                    let values: Vec<u64> = args
                        .iter()
                        .map(|value| match value {
                            Expr::Const(value) => *value,
                            _ => unreachable!(),
                        })
                        .collect();
                    proofs.expression(
                        format!("integer fold/{op:?}/{a}/{b}"),
                        &Expr::Apply { op, args },
                        &Expr::Const(
                            crate::ir::semantics::fold(op, &values)
                                .expect("integer operation folds"),
                        ),
                        64,
                    );
                }
            }
        }
    }
    proofs.check();
}

#[test]
fn private_frame_and_spill_rewrites_are_equivalent() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for isa in [Isa::X86_64, Isa::AArch64, Isa::Arm32] {
        let sp = crate::arch::stack_pointer(isa);
        for bits in [32, 64] {
            for offset in [8, 16, 32] {
                let slot = raw_bin(BinOp::Add, Expr::reg(sp, 64), Expr::Const(offset));
                let mut before = FunctionIr::single_block(
                    isa,
                    vec![
                        assign(
                            sp,
                            64,
                            raw_bin(BinOp::Sub, Expr::reg(sp, 64), Expr::Const(64)),
                        ),
                        Stmt::Store {
                            addr: slot.clone(),
                            value: Expr::reg(0, 64),
                            width: bits / 8,
                        },
                        assign(1, 64, load(slot, bits / 8, false)),
                        assign(
                            sp,
                            64,
                            raw_bin(BinOp::Add, Expr::reg(sp, 64), Expr::Const(64)),
                        ),
                        Stmt::Ret {
                            value: Expr::reg(1, 64),
                        },
                    ],
                );
                let mut after = before.clone();
                crate::passes::frame_slots::settle(&mut after);
                assert_ne!(
                    before.render(),
                    after.render(),
                    "frame template must be rewritten"
                );
                proofs.function_return_value(
                    format!("frame/{isa:?}/{bits}/{offset}"),
                    &before,
                    &after,
                );
                let variable = crate::ir::VARIABLE_BASE;
                before = FunctionIr::single_block(
                    isa,
                    vec![
                        assign(variable, 64, Expr::reg(0, 64)),
                        Stmt::Store {
                            addr: raw_bin(
                                BinOp::Add,
                                Expr::reg(sp, 64),
                                Expr::Const(offset.wrapping_neg()),
                            ),
                            value: Expr::reg(variable, 64),
                            width: bits / 8,
                        },
                        Stmt::Ret {
                            value: load(
                                raw_bin(
                                    BinOp::Add,
                                    Expr::reg(sp, 64),
                                    Expr::Const(offset.wrapping_neg()),
                                ),
                                bits / 8,
                                false,
                            ),
                        },
                    ],
                );
                after = before.clone();
                crate::passes::memory::forward_spilled_variables(&mut after);
                assert_ne!(
                    before.render(),
                    after.render(),
                    "spill template must be rewritten"
                );
                proofs.function_return_value(
                    format!("spill/{isa:?}/{bits}/{offset}"),
                    &before,
                    &after,
                );
            }
        }
    }
    proofs.check();
}

#[test]
fn range_branches_and_switch_pruning_preserve_results() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for bits in [8, 16, 32] {
        let mask = crate::ir::semantics::mask(u32::from(bits));
        for cond in CONDITIONS {
            let mut before = branch(cond, Expr::reg(3, bits), Expr::Const(mask + 1));
            before.blocks[0].stmts.insert(
                0,
                assign(
                    3,
                    bits,
                    raw_bin(BinOp::And, Expr::reg(0, 64), Expr::Const(mask)),
                ),
            );
            let mut after = before.clone();
            crate::ssa::ranges::simplify(&mut after);
            proofs.function(format!("range branch/{bits}/{cond:?}"), &before, &after);
        }
        for value in [
            Expr::Const(1),
            raw_bin(BinOp::And, Expr::reg(0, 64), Expr::Const(1)),
        ] {
            let mut before = FunctionIr::single_block(
                Isa::X86_64,
                vec![
                    assign(3, bits, value),
                    Stmt::Switch {
                        index: Expr::reg(3, 64),
                        cases: vec![(0, 1), (1, 2), (2, 3)],
                        default: Some(4),
                    },
                ],
            );
            for index in 1..=4 {
                before.blocks.push(Block {
                    start: index,
                    stmts: vec![Stmt::Ret {
                        value: Expr::Const(index),
                    }],
                });
            }
            let mut after = before.clone();
            crate::ssa::ranges::simplify(&mut after);
            assert_ne!(
                before.render(),
                after.render(),
                "switch range template must change"
            );
            proofs.function(
                format!("switch/ranges/{bits}/{:?}", before.blocks),
                &before,
                &after,
            );
            let mut after = before.clone();
            crate::ssa::propagate_constants(&mut after);
            proofs.function(
                format!("SCCP switch/{bits}/{:?}", before.blocks),
                &before,
                &after,
            );
        }
    }
    proofs.check();
}

#[test]
fn packed_lanes_match_scalar_saturation() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for from in [16u8, 32, 64] {
        for unsigned in [false, true] {
            let narrow = from / 2;
            let minimum = if unsigned {
                0
            } else {
                (-(1i64 << (narrow - 1))) as u64
            };
            let maximum = if unsigned {
                (1u64 << narrow) - 1
            } else {
                (1u64 << (narrow - 1)) - 1
            };
            let mut reference = Expr::Const(0);
            for index in 0..128 / u32::from(from) {
                let source = Expr::reg(if index < 64 / u32::from(from) { 0 } else { 1 }, 64);
                let shifted = raw_bin(
                    BinOp::Shr,
                    source,
                    Expr::Const(u64::from(
                        (index % (64 / u32::from(from))) * u32::from(from),
                    )),
                );
                let lane = Expr::SignExtend {
                    value: Box::new(shifted),
                    width: from / 8,
                };
                let upper = Expr::Select {
                    cond: Cond::Gt,
                    lhs: Box::new(lane.clone()),
                    rhs: Box::new(Expr::Const(maximum)),
                    then: Box::new(Expr::Const(maximum)),
                    els: Box::new(lane.clone()),
                };
                let held = Expr::Select {
                    cond: Cond::Lt,
                    lhs: Box::new(lane),
                    rhs: Box::new(Expr::Const(minimum)),
                    then: Box::new(Expr::Const(minimum)),
                    els: Box::new(upper),
                };
                let low = raw_bin(BinOp::And, held, Expr::Const((1u64 << narrow) - 1));
                reference = raw_bin(
                    BinOp::Or,
                    reference,
                    raw_bin(
                        BinOp::Shl,
                        low,
                        Expr::Const(u64::from(index * u32::from(narrow))),
                    ),
                );
            }
            proofs.expression(
                format!("pack scalar saturation/{from}/{unsigned}"),
                &Expr::Apply {
                    op: Operation::Pack { from, unsigned },
                    args: vec![Expr::reg(0, 64), Expr::reg(1, 64)],
                },
                &reference,
                64,
            );
        }
    }
    proofs.check();
}

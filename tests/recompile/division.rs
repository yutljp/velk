use super::*;

fn reg(index: u16, width: u8) -> Expr {
    Expr::reg(index, width)
}

fn assign(index: u16, width: u8, value: Expr) -> Stmt {
    Stmt::Assign {
        dest: velk::ir::RegRef { index, width },
        value,
        at: None,
    }
}

fn op(op: BinOp, a: Expr, b: Expr) -> Expr {
    Expr::bin(op, a, b)
}

fn constant(value: u64) -> Expr {
    Expr::Const(value)
}

fn sign_extend(value: Expr) -> Expr {
    Expr::SignExtend {
        value: Box::new(value),
        width: 4,
    }
}

fn select(negative: Expr, compare: u16, width: u8) -> Expr {
    Expr::Select {
        cond: Cond::Ge,
        lhs: Box::new(reg(compare, width)),
        rhs: Box::new(constant(0)),
        then: Box::new(reg(7, width)),
        els: Box::new(negative),
    }
}

fn power(delta: u64, shift: u64, compare: u16, width: u8, remainder: bool) -> Vec<Stmt> {
    let mut stmts = vec![
        assign(40, width, op(BinOp::Add, reg(7, width), constant(delta))),
        assign(41, width, select(reg(40, width), compare, width)),
    ];
    if remainder {
        stmts.extend([
            assign(42, width, op(BinOp::And, reg(41, width), constant(!7))),
            assign(43, width, op(BinOp::Sub, reg(7, width), reg(42, width))),
        ]);
    } else {
        stmts.push(assign(
            43,
            width,
            op(BinOp::Sar, reg(41, width), constant(shift)),
        ));
    }
    stmts
}

fn unsigned(shift: u64, input_width: u8, product_width: u8) -> Vec<Stmt> {
    vec![
        assign(
            40,
            product_width,
            op(BinOp::Mul, reg(7, input_width), constant(0xaaaa_aaab)),
        ),
        assign(41, 64, op(BinOp::Shr, reg(40, 64), constant(shift))),
        assign(
            42,
            32,
            op(
                BinOp::Add,
                reg(41, 32),
                op(BinOp::Shl, reg(41, 32), constant(1)),
            ),
        ),
        assign(43, 32, op(BinOp::Sub, reg(7, 32), reg(42, 32))),
    ]
}

fn signed_32_bit_division(sign: BinOp, sign_shift: u64, sum: u16) -> Vec<Stmt> {
    vec![
        assign(
            40,
            64,
            op(BinOp::Mul, sign_extend(reg(7, 32)), constant(0x5555_5556)),
        ),
        assign(41, 64, op(sign, reg(40, 64), constant(sign_shift))),
        assign(42, 64, op(BinOp::Shr, reg(40, 64), constant(32))),
        assign(43, 32, op(BinOp::Add, reg(sum, 32), reg(41, 32))),
    ]
}

fn signed_64_bit_division(sign: BinOp, sign_shift: u64) -> Vec<Stmt> {
    vec![
        assign(
            40,
            64,
            op(BinOp::MulHighS, reg(7, 64), constant(0x5555_5555_5555_5556)),
        ),
        assign(41, 64, op(sign, reg(40, 64), constant(sign_shift))),
        assign(43, 64, op(BinOp::Add, reg(40, 64), reg(41, 64))),
    ]
}

struct Case {
    name: String,
    stmts: Vec<Stmt>,
    width: u8,
    expected: Option<char>,
}

fn power_cases(cases: &mut Vec<Case>) {
    for width in [32, 64] {
        cases.push(Case {
            name: format!("power_valid_{width}"),
            stmts: power(7, 3, 7, width, false),
            width,
            expected: Some('/'),
        });
        cases.push(Case {
            name: format!("power_wrong_delta_{width}"),
            stmts: power(3, 3, 7, width, false),
            width,
            expected: None,
        });
        cases.push(Case {
            name: format!("power_wrong_predicate_{width}"),
            stmts: power(7, 3, 6, width, false),
            width,
            expected: None,
        });
        cases.push(Case {
            name: format!("power_mod_valid_{width}"),
            stmts: power(7, 3, 7, width, true),
            width,
            expected: Some('%'),
        });
        cases.push(Case {
            name: format!("power_mod_wrong_predicate_{width}"),
            stmts: power(7, 3, 6, width, true),
            width,
            expected: None,
        });
    }
    cases.push(Case {
        name: "power_shift_exceeds_width".into(),
        stmts: power(0xffff_ffff, 32, 7, 32, false),
        width: 32,
        expected: None,
    });
    let mut stale = power(7, 3, 7, 64, false);
    stale.insert(1, assign(7, 64, op(BinOp::Add, reg(7, 64), constant(1))));
    cases.push(Case {
        name: "power_stale_adjustment".into(),
        stmts: stale,
        width: 64,
        expected: None,
    });
}

fn signed_cases(cases: &mut Vec<Case>) {
    for (name, sign, amount, sum, expected) in [
        ("signed32_valid", BinOp::Shr, 63, 42, Some('/')),
        ("signed32_arithmetic_sign", BinOp::Sar, 63, 42, None),
        ("signed32_wrong_sign_shift", BinOp::Shr, 31, 42, None),
        ("signed32_wrong_sum", BinOp::Shr, 63, 6, None),
    ] {
        cases.push(Case {
            name: name.into(),
            stmts: signed_32_bit_division(sign, amount, sum),
            width: 32,
            expected,
        });
    }
    for (name, sign, amount, expected) in [
        ("signed64_valid", BinOp::Shr, 63, Some('/')),
        ("signed64_arithmetic_sign", BinOp::Sar, 63, None),
        ("signed64_wrong_sign_shift", BinOp::Shr, 31, None),
    ] {
        cases.push(Case {
            name: name.into(),
            stmts: signed_64_bit_division(sign, amount),
            width: 64,
            expected,
        });
    }
    let mut unshifted = signed_64_bit_division(BinOp::Shr, 63);
    unshifted[0] = assign(
        40,
        64,
        op(BinOp::MulHighS, reg(7, 64), constant(0x6666_6666_6666_6667)),
    );
    unshifted.insert(2, assign(42, 64, op(BinOp::Sar, reg(40, 64), constant(2))));
    cases.push(Case {
        name: "signed64_uses_unshifted_product".into(),
        stmts: unshifted,
        width: 64,
        expected: None,
    });
    let mut exact = signed_32_bit_division(BinOp::Shr, 63, 42);
    exact[0] = assign(
        40,
        64,
        op(BinOp::Mul, sign_extend(reg(7, 32)), constant(0x8000_0000)),
    );
    cases.push(Case {
        name: "signed_exact_reciprocal_needs_no_sign_addition".into(),
        stmts: exact,
        width: 32,
        expected: None,
    });
    let mut clobbered = signed_64_bit_division(BinOp::Shr, 63);
    clobbered.insert(1, assign(7, 64, op(BinOp::Mul, reg(7, 64), constant(3))));
    cases.push(Case {
        name: "signed64_overwritten_dividend".into(),
        stmts: clobbered,
        width: 64,
        expected: None,
    });
}

fn unsigned_cases(cases: &mut Vec<Case>) {
    for (name, shift, input, product, expected) in [
        ("unsigned_mod_valid", 33, 32, 64, Some('%')),
        ("unsigned_mod_wrong_shift", 32, 32, 64, None),
        ("unsigned_truncated_product", 33, 32, 32, None),
        ("unsigned_wide_low_product", 33, 64, 64, None),
    ] {
        cases.push(Case {
            name: name.into(),
            stmts: unsigned(shift, input, product),
            width: 32,
            expected,
        });
    }
    for (name, product_op, mask) in [
        ("unsigned64_masked_product", BinOp::MulHigh, !2),
        ("unsigned64_truncated_copy", BinOp::MulHigh, 0xffff_ffff),
        ("unsigned64_signed_product", BinOp::MulHighS, u64::MAX),
    ] {
        cases.push(Case {
            name: name.into(),
            stmts: vec![
                assign(
                    40,
                    64,
                    op(product_op, reg(7, 64), constant(0xaaaa_aaaa_aaaa_aaab)),
                ),
                assign(41, 64, op(BinOp::And, reg(40, 64), constant(mask))),
                assign(43, 64, op(BinOp::Shr, reg(41, 64), constant(1))),
            ],
            width: 64,
            expected: None,
        });
    }
}

fn widened_cases(cases: &mut Vec<Case>) {
    for (name, sign) in [
        ("widened_valid", BinOp::Shr),
        ("widened_arithmetic_sign", BinOp::Sar),
    ] {
        let mut stmts = signed_32_bit_division(sign, 63, 42);
        stmts[2] = assign(42, 64, op(BinOp::Sar, reg(40, 64), constant(32)));
        cases.push(Case {
            name: name.into(),
            stmts,
            width: 32,
            expected: if sign == BinOp::Shr { Some('/') } else { None },
        });
    }
    let mut csneg = vec![
        assign(40, 32, op(BinOp::Sub, constant(0), reg(7, 32))),
        assign(41, 32, op(BinOp::And, reg(7, 32), constant(3))),
        assign(42, 32, op(BinOp::And, reg(40, 32), constant(3))),
        assign(
            43,
            32,
            Expr::Select {
                cond: Cond::Lt,
                lhs: Box::new(op(BinOp::Sub, constant(0), reg(7, 32))),
                rhs: Box::new(constant(0)),
                then: Box::new(reg(41, 32)),
                els: Box::new(op(BinOp::Sub, constant(0), reg(42, 32))),
            },
        ),
    ];
    cases.push(Case {
        name: "csneg_valid".into(),
        stmts: csneg.clone(),
        width: 32,
        expected: Some('%'),
    });
    csneg.insert(3, assign(7, 32, op(BinOp::Add, reg(7, 32), constant(1))));
    cases.push(Case {
        name: "csneg_overwritten_dividend".into(),
        stmts: csneg,
        width: 32,
        expected: None,
    });
}

fn signed_rejection_cases(cases: &mut Vec<Case>) {
    let mut zero_extended = signed_32_bit_division(BinOp::Shr, 63, 42);
    zero_extended[0] = assign(40, 64, op(BinOp::Mul, reg(7, 32), constant(0x5555_5556)));
    cases.push(Case {
        name: "signed32_zero_extended_dividend".into(),
        stmts: zero_extended,
        width: 32,
        expected: None,
    });
    let mut large_divisor = signed_32_bit_division(BinOp::Shr, 63, 42);
    large_divisor[0] = assign(40, 64, op(BinOp::Mul, sign_extend(reg(7, 32)), constant(2)));
    cases.push(Case {
        name: "signed_divisor_exceeds_signed_width".into(),
        stmts: large_divisor,
        width: 32,
        expected: None,
    });
    for (name, step) in [
        (
            "unsigned64_overwritten_high_product",
            assign(
                40,
                64,
                op(BinOp::Mul, reg(7, 64), constant(0xaaaa_aaaa_aaaa_aaab)),
            ),
        ),
        ("unsigned64_narrow_copy", assign(40, 32, reg(40, 64))),
    ] {
        cases.push(Case {
            name: name.into(),
            stmts: vec![
                assign(
                    40,
                    64,
                    op(BinOp::MulHigh, reg(7, 64), constant(0xaaaa_aaaa_aaaa_aaab)),
                ),
                step,
                assign(43, 64, op(BinOp::Shr, reg(40, 64), constant(1))),
            ],
            width: 64,
            expected: None,
        });
    }
}

fn remainder_cases(cases: &mut Vec<Case>) {
    let mut factors = unsigned(33, 32, 64);
    factors.insert(2, assign(44, 32, op(BinOp::Add, reg(41, 32), reg(41, 32))));
    cases.push(Case {
        name: "remainder_factors_use_different_values".into(),
        stmts: factors,
        width: 32,
        expected: Some('/'),
    });
    let mut wrong_accumulator = unsigned(33, 32, 64);
    wrong_accumulator[3] = assign(43, 32, op(BinOp::Sub, reg(7, 32), reg(41, 32)));
    cases.push(Case {
        name: "remainder_uses_unscaled_quotient".into(),
        stmts: wrong_accumulator,
        width: 32,
        expected: Some('/'),
    });
    let mut masked = unsigned(33, 32, 64);
    masked.truncate(2);
    masked.extend([
        assign(41, 32, op(BinOp::And, reg(41, 32), constant(!1))),
        assign(
            43,
            32,
            op(
                BinOp::Sub,
                reg(7, 32),
                op(BinOp::Mul, reg(41, 32), constant(3)),
            ),
        ),
    ]);
    cases.push(Case {
        name: "remainder_masks_the_quotient".into(),
        stmts: masked,
        width: 32,
        expected: Some('/'),
    });
    let mut factor_overwritten = unsigned(33, 32, 64);
    factor_overwritten.truncate(2);
    factor_overwritten.extend([
        assign(44, 32, constant(3)),
        assign(44, 32, op(BinOp::And, reg(6, 64), constant(0xffff_ffff))),
        assign(
            43,
            32,
            op(
                BinOp::Sub,
                reg(7, 32),
                op(BinOp::Mul, reg(41, 32), reg(44, 32)),
            ),
        ),
    ]);
    cases.push(Case {
        name: "remainder_overwritten_factor".into(),
        stmts: factor_overwritten,
        width: 32,
        expected: Some('/'),
    });
}

fn live_result_cases(cases: &mut Vec<Case>) {
    let mut live_product = signed_32_bit_division(BinOp::Shr, 63, 42);
    live_product.push(Stmt::Ret {
        value: op(BinOp::Xor, reg(40, 64), reg(43, 32)),
        at: None,
    });
    cases.push(Case {
        name: "division_preserves_another_live_result".into(),
        stmts: live_product,
        width: 64,
        expected: Some('/'),
    });

    cases.push(Case {
        name: "unsigned_high_product_error_at_maximum".into(),
        stmts: vec![
            assign(
                40,
                64,
                op(BinOp::MulHigh, reg(7, 32), constant(0x8000_0000_8000_0001)),
            ),
            assign(41, 64, reg(40, 64)),
            assign(43, 64, op(BinOp::Shr, reg(41, 64), constant(1))),
        ],
        width: 64,
        expected: None,
    });
}

fn mixed_width_cases(cases: &mut Vec<Case>) {
    let mut mixed_width = power(7, 3, 7, 32, true);
    mixed_width[1] = assign(
        41,
        32,
        Expr::Select {
            cond: Cond::Ge,
            lhs: Box::new(reg(7, 32)),
            rhs: Box::new(constant(0)),
            then: Box::new(reg(7, 64)),
            els: Box::new(reg(40, 32)),
        },
    );
    mixed_width[3] = assign(43, 32, op(BinOp::Sub, reg(7, 64), reg(42, 32)));
    cases.push(Case {
        name: "remainder_uses_the_predicate_width".into(),
        stmts: mixed_width,
        width: 32,
        expected: Some('%'),
    });
}

fn successive_predicate_cases(cases: &mut Vec<Case>) {
    for remainder in [false, true] {
        let mut stmts = power(7, 3, 6, 64, remainder);
        stmts.extend([
            assign(50, 64, op(BinOp::Add, reg(7, 64), constant(7))),
            assign(51, 64, select(reg(50, 64), 7, 64)),
        ]);
        if remainder {
            stmts.extend([
                assign(52, 64, op(BinOp::And, reg(51, 64), constant(!7))),
                assign(53, 64, op(BinOp::Sub, reg(7, 64), reg(52, 64))),
            ]);
        } else {
            stmts.push(assign(53, 64, op(BinOp::Sar, reg(51, 64), constant(3))));
        }
        stmts.push(Stmt::Ret {
            value: op(BinOp::Xor, reg(43, 64), reg(53, 64)),
            at: None,
        });
        cases.push(Case {
            name: format!("valid_after_wrong_predicate_{remainder}"),
            stmts,
            width: 64,
            expected: Some(if remainder { '%' } else { '/' }),
        });
    }
}

fn source_preservation_cases(cases: &mut Vec<Case>) {
    for signed in [false, true] {
        let magic = if signed {
            0x5555_5555_5555_5556
        } else {
            0xaaaa_aaaa_aaaa_aaab
        };
        let mut stmts = vec![
            assign(0, 64, reg(7, 64)),
            assign(
                40,
                64,
                op(
                    if signed {
                        BinOp::MulHighS
                    } else {
                        BinOp::MulHigh
                    },
                    reg(0, 64),
                    constant(magic),
                ),
            ),
            assign(0, 64, op(BinOp::Mul, reg(0, 64), constant(magic))),
        ];
        if signed {
            stmts.push(assign(
                43,
                64,
                op(
                    BinOp::Add,
                    reg(40, 64),
                    op(BinOp::Shr, reg(40, 64), constant(63)),
                ),
            ));
        } else {
            stmts.push(assign(43, 64, op(BinOp::Shr, reg(40, 64), constant(1))));
        }
        cases.push(Case {
            name: format!("division_uses_the_unmodified_source_{signed}"),
            stmts,
            width: 64,
            expected: Some('/'),
        });
    }
    let mut extended = signed_32_bit_division(BinOp::Shr, 63, 42);
    extended[0] = assign(40, 64, op(BinOp::Mul, reg(0, 64), constant(0x5555_5556)));
    extended.insert(0, assign(0, 64, sign_extend(reg(7, 32))));
    extended[4] = assign(
        43,
        64,
        op(
            BinOp::And,
            op(BinOp::Add, reg(42, 32), reg(41, 32)),
            constant(0xffff_ffff),
        ),
    );
    cases.push(Case {
        name: "division_preserves_the_narrow_result".into(),
        stmts: extended,
        width: 32,
        expected: Some('/'),
    });
}

fn signed_width_cases(cases: &mut Vec<Case>) {
    let mut signed_mask = signed_64_bit_division(BinOp::Shr, 63);
    signed_mask.insert(1, assign(44, 64, op(BinOp::And, reg(40, 64), constant(7))));
    signed_mask[2] = assign(41, 64, op(BinOp::Shr, reg(44, 64), constant(63)));
    cases.push(Case {
        name: "signed64_masked_sign_source".into(),
        stmts: signed_mask,
        width: 64,
        expected: None,
    });
    let mut wide_product = signed_32_bit_division(BinOp::Shr, 63, 42);
    wide_product[0] = assign(40, 64, op(BinOp::Mul, reg(7, 64), constant(0x5555_5556)));
    cases.push(Case {
        name: "widened_requires_a_signed_narrow_input".into(),
        stmts: wide_product,
        width: 32,
        expected: None,
    });
    for sign in [BinOp::Shr, BinOp::Sar] {
        let mut stmts = signed_32_bit_division(BinOp::Shr, 63, 42);
        stmts.truncate(1);
        stmts.extend([
            assign(41, 64, op(BinOp::Shr, reg(40, 64), constant(32))),
            assign(42, 32, reg(41, 64)),
            assign(
                43,
                32,
                op(BinOp::Add, reg(42, 32), op(sign, reg(42, 32), constant(31))),
            ),
        ]);
        cases.push(Case {
            name: format!("widened_high_half_sign_{}", sign == BinOp::Shr),
            stmts,
            width: 32,
            expected: if sign == BinOp::Shr { Some('/') } else { None },
        });
    }

    let mut negative_magic = signed_32_bit_division(BinOp::Shr, 63, 42);
    negative_magic[0] = assign(
        40,
        64,
        op(
            BinOp::Mul,
            sign_extend(reg(7, 32)),
            sign_extend(constant(0x8000_0001)),
        ),
    );
    cases.push(Case {
        name: "signed_negative_multiplier_requires_add_back".into(),
        stmts: negative_magic,
        width: 32,
        expected: None,
    });
}

#[test]
fn printed_division_requires_the_complete_arithmetic_identity() {
    let mut cases = Vec::new();
    power_cases(&mut cases);
    signed_cases(&mut cases);
    unsigned_cases(&mut cases);
    widened_cases(&mut cases);
    signed_rejection_cases(&mut cases);
    remainder_cases(&mut cases);
    live_result_cases(&mut cases);
    mixed_width_cases(&mut cases);
    successive_predicate_cases(&mut cases);
    source_preservation_cases(&mut cases);
    signed_width_cases(&mut cases);

    let mut candidates = Vec::new();
    let mut unexpected = Vec::new();
    for Case {
        name,
        mut stmts,
        width,
        expected,
    } in cases
    {
        if !matches!(stmts.last(), Some(Stmt::Ret { .. })) {
            stmts.push(Stmt::Ret {
                value: reg(43, width),
                at: None,
            });
        }
        let original = synthetic_ir(
            &name,
            vec![
                Param {
                    index: 7,
                    name: "x".into(),
                    ty: CType::I64,
                },
                Param {
                    index: 6,
                    name: "y".into(),
                    ty: CType::I64,
                },
            ],
            if width == 32 { CType::U32 } else { CType::U64 },
            stmts,
        );
        let mut ir = original.clone();
        velk::passes::division::recover_divisions(&mut ir);
        velk::passes::dce::dce(&mut ir);
        let edges = [
            i64::MIN as u64,
            i64::MIN as u64 + 1,
            0xffff_ffff_8000_0000,
            0x8000_0000,
            0x8000_0001,
            0x7fff_ffff,
            0xffff_ffff,
            0x1_0000_0000,
            0x1_0000_0001,
            0x2_0000_0000,
            u64::MAX - 16,
            u64::MAX - 8,
            u64::MAX - 7,
            u64::MAX - 2,
            u64::MAX - 1,
            u64::MAX,
            0,
            1,
            2,
            3,
            7,
            8,
            9,
            16,
            i64::MAX as u64,
        ];
        let mut inputs: Vec<Vec<u64>> = edges
            .iter()
            .flat_map(|x| edges.iter().map(move |y| vec![*x, *y]))
            .collect();
        let mut seed = 0xace1_3456_789a_bcdeu64;
        for _ in 0..512 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            inputs.push(vec![seed, seed.rotate_left(23)]);
        }
        let mut candidate = printed_candidate(ir, inputs);
        let quotient = candidate.code.contains(" / ");
        let remainder = candidate.code.contains(" % ");
        if match expected {
            Some('/') => !quotient || remainder,
            Some('%') => !remainder,
            _ => quotient || remainder,
        } {
            unexpected.push(format!("{name}: {}", candidate.code));
        }
        candidate.ir = original;
        candidates.push(candidate);
    }
    assert!(unexpected.is_empty(), "{}", unexpected.join("\n"));
    check_candidates("division_identities", candidates, Mode::Registers, &[]);
}

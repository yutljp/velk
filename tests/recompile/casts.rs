use super::*;

#[test]
fn anonymous_data_offsets_keep_integer_address_arithmetic() {
    let mut candidates = Vec::new();
    for width in [1, 2, 4, 8] {
        for signed in [false, true] {
            let address = Expr::bin(
                BinOp::Add,
                Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(32)),
                Expr::bin(BinOp::Mul, Expr::reg(6, 64), Expr::Const(8)),
            );
            let ir = synthetic_ir(
                &format!("anonymous_offset_{width}_{signed}"),
                vec![
                    Param {
                        index: 7,
                        name: "p".into(),
                        ty: CType::pointer_to(CType::int(1, false)),
                    },
                    Param {
                        index: 6,
                        name: "index".into(),
                        ty: CType::U64,
                    },
                ],
                CType::U64,
                vec![Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(address),
                        width,
                        signed,
                    },
                }],
            );
            let mut candidate = printed_candidate(
                ir,
                [0, 1, 2, u64::MAX]
                    .into_iter()
                    .map(|index| vec![REGION + 16, index])
                    .collect(),
            );
            candidate.code =
                velk::render::render(&candidate.ir, &[], &Default::default(), &[(0, 0x1000)]);
            assert!(!candidate.code.contains("const "), "{}", candidate.code);
            assert!(
                candidate.code.contains("(uintptr_t)p"),
                "{}",
                candidate.code
            );
            candidates.push(candidate);
        }
    }
    check_candidates("anonymous-data-offsets", candidates, Mode::Memory, &[]);
}

#[test]
fn printed_signed_loads_preserve_extension_widths() {
    let mut candidates = Vec::new();
    for loaded in [1, 2, 4, 8] {
        for extended in [1, 2, 4, 8] {
            let ir = synthetic_ir(
                &format!("extend_load_{loaded}_{extended}"),
                vec![
                    Param {
                        index: 7,
                        name: "p".into(),
                        ty: CType::pointer_to(CType::int(1, false)),
                    },
                    Param {
                        index: 6,
                        name: "x".into(),
                        ty: CType::U64,
                    },
                ],
                CType::U64,
                vec![
                    Stmt::Store {
                        addr: Expr::reg(7, 64),
                        value: Expr::reg(6, 64),
                        width: loaded,
                    },
                    Stmt::Ret {
                        value: Expr::SignExtend {
                            value: Box::new(Expr::Load {
                                addr: Box::new(Expr::reg(7, 64)),
                                width: loaded,
                                signed: false,
                            }),
                            width: extended,
                        },
                    },
                ],
            );
            let candidate = printed_candidate(
                ir,
                [
                    0,
                    1,
                    0x7f,
                    0x80,
                    0x7fff,
                    0x8000,
                    0x7fff_ffff,
                    0x8000_0000,
                    1 << 63,
                    u64::MAX,
                ]
                .into_iter()
                .map(|x| vec![REGION + 1, x])
                .collect(),
            );
            if loaded == extended && loaded > 1 {
                assert!(
                    !candidate.code.contains(&format!("(int{}_t)*", loaded * 8)),
                    "{}",
                    candidate.code
                );
            }
            candidates.push(candidate);
        }
    }
    check_candidates("signed-load-widths", candidates, Mode::Memory, &[]);
}

#[test]
fn printed_local_types_preserve_byte_values_and_integer_uses() {
    use velk::ir::{RegRef, VARIABLE_BASE};

    let local = Expr::reg(VARIABLE_BASE, 64);
    let mut candidates = Vec::new();
    let edges = [0, 1, 127, 128, 255, 256, 0x8000_0000, u64::MAX];
    let counts = [0, 1, 7, 8, 31, 32, 63, 64, 65, u64::MAX];
    let inputs: Vec<Vec<u64>> = edges
        .iter()
        .flat_map(|value| counts.iter().map(move |count| vec![*value, *count]))
        .collect();
    for (name, definition, result) in [
        (
            "byte_local",
            Expr::bin(BinOp::And, Expr::reg(7, 64), Expr::Const(255)),
            local.clone(),
        ),
        (
            "shift_local",
            Expr::bin(BinOp::Xor, Expr::reg(7, 64), Expr::Const(1)),
            Expr::bin(BinOp::Shl, local.clone(), Expr::reg(6, 64)),
        ),
        (
            "logical_shift_local",
            Expr::bin(BinOp::Xor, Expr::reg(7, 64), Expr::Const(1)),
            Expr::bin(BinOp::Shr, local.clone(), Expr::Const(63)),
        ),
        (
            "narrow_read_wide_local",
            Expr::bin(BinOp::And, Expr::reg(7, 64), Expr::Const(255)),
            Expr::bin(
                BinOp::Add,
                Expr::bin(BinOp::Shl, local.clone(), Expr::reg(6, 64)),
                Expr::reg(VARIABLE_BASE, 8),
            ),
        ),
        (
            "wrapping_local",
            Expr::bin(BinOp::And, Expr::reg(7, 64), Expr::Const(0xffff_ffff)),
            Expr::bin(BinOp::Add, local.clone(), Expr::Const(1)),
        ),
        (
            "mixed_sign_local",
            Expr::bin(BinOp::Xor, Expr::reg(7, 64), Expr::Const(1)),
            Expr::Select {
                cond: Cond::Lt,
                lhs: Box::new(local.clone()),
                rhs: Box::new(Expr::reg(6, 64)),
                then: Box::new(Expr::bin(BinOp::Shr, local.clone(), Expr::Const(1))),
                els: Box::new(Expr::bin(BinOp::Shl, local.clone(), Expr::Const(1))),
            },
        ),
    ] {
        let ir = synthetic_ir(
            name,
            vec![
                Param {
                    index: 7,
                    name: "x".into(),
                    ty: CType::U64,
                },
                Param {
                    index: 6,
                    name: "count".into(),
                    ty: CType::U64,
                },
            ],
            CType::U64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: VARIABLE_BASE,
                        width: 64,
                    },
                    value: definition,
                },
                Stmt::Ret {
                    value: Expr::bin(BinOp::Add, result, local.clone()),
                },
            ],
        );
        let candidate = printed_candidate(ir, inputs.clone());
        if name == "byte_local" {
            assert!(
                candidate.code.contains("uint8_t v1 ="),
                "{}",
                candidate.code
            );
        }
        if matches!(
            name,
            "shift_local" | "logical_shift_local" | "narrow_read_wide_local"
        ) {
            assert!(
                candidate.code.contains("uint64_t v1 ="),
                "{}",
                candidate.code
            );
            assert!(!candidate.code.contains("(uint64_t)"), "{}", candidate.code);
            assert!(!candidate.code.contains("(uint8_t)"), "{}", candidate.code);
        }
        candidates.push(candidate);
    }
    check_candidates(
        "local_integer_types",
        candidates,
        Mode::Registers,
        &["-fsanitize=undefined", "-fno-sanitize-recover=all"],
    );
}

#[test]
fn printed_byte_load_locals_extend_every_value_exactly() {
    use velk::ir::{RegRef, VARIABLE_BASE};

    let mut candidates = Vec::new();
    for signed in [false, true] {
        let local = Expr::reg(VARIABLE_BASE, 64);
        let ir = synthetic_ir(
            if signed {
                "signed_byte_local"
            } else {
                "loaded_byte_local"
            },
            vec![Param {
                index: 7,
                name: "x".into(),
                ty: CType::U64,
            }],
            CType::U64,
            vec![
                Stmt::Store {
                    addr: Expr::Const(REGION),
                    value: Expr::reg(7, 64),
                    width: 1,
                },
                Stmt::Assign {
                    dest: RegRef {
                        index: VARIABLE_BASE,
                        width: 64,
                    },
                    value: Expr::Load {
                        addr: Box::new(Expr::Const(REGION)),
                        width: 1,
                        signed,
                    },
                },
                Stmt::Ret {
                    value: Expr::bin(BinOp::Add, local.clone(), local),
                },
            ],
        );
        let candidate = printed_candidate(ir, (0..256).map(|value| vec![value]).collect());
        if !signed {
            assert!(
                candidate.code.contains("uint8_t v1 ="),
                "{}",
                candidate.code
            );
        }
        candidates.push(candidate);
    }
    check_candidates("loaded_byte_locals", candidates, Mode::Memory, &[]);
}

#[test]
fn printed_integer_shifts_and_pointer_choices_avoid_identity_casts() {
    let mut candidates = Vec::new();
    let edges = [
        0,
        1,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_ffff,
        1 << 63,
        u64::MAX,
    ];
    let inputs: Vec<Vec<u64>> = edges
        .iter()
        .flat_map(|x| edges.iter().map(move |y| vec![*x, *y]))
        .collect();
    let shifted = Expr::bin(BinOp::Shl, Expr::reg(7, 64), Expr::Const(8));
    let ir = synthetic_ir(
        "identity_shift",
        vec![
            Param {
                index: 7,
                name: "x".into(),
                ty: CType::U64,
            },
            Param {
                index: 6,
                name: "y".into(),
                ty: CType::U64,
            },
        ],
        CType::U64,
        vec![Stmt::Ret {
            value: Expr::bin(
                BinOp::DivU,
                shifted,
                Expr::bin(BinOp::Or, Expr::reg(6, 64), Expr::Const(1)),
            ),
        }],
    );
    let candidate = printed_candidate(ir, inputs.clone());
    assert!(!candidate.code.contains("(uint64_t)"), "{}", candidate.code);
    candidates.push(candidate);
    for (name, other, null) in [
        ("same_pointers", CType::U64, false),
        ("null_pointer", CType::U64, true),
        ("different_pointers", CType::U32, false),
    ] {
        let ty = CType::pointer_to(CType::U64);
        let ir = synthetic_ir(
            name,
            vec![
                Param {
                    index: 7,
                    name: "x".into(),
                    ty: ty.clone(),
                },
                Param {
                    index: 6,
                    name: "y".into(),
                    ty: CType::pointer_to(other),
                },
            ],
            ty,
            vec![Stmt::Ret {
                value: Expr::Select {
                    cond: Cond::Ne,
                    lhs: Box::new(Expr::reg(7, 64)),
                    rhs: Box::new(Expr::Const(0)),
                    then: Box::new(Expr::reg(7, 64)),
                    els: Box::new(if null {
                        Expr::Const(0)
                    } else {
                        Expr::reg(6, 64)
                    }),
                },
            }],
        );
        let candidate = printed_candidate(ir, inputs.clone());
        assert_eq!(
            candidate.code.contains("return (uint64_t *)"),
            name == "different_pointers",
            "{}",
            candidate.code
        );
        candidates.push(candidate);
    }
    check_candidates("identity_casts", candidates, Mode::Memory, &[]);
}

#[test]
fn printed_byte_buffer_accesses_keep_signedness_and_wider_accesses() {
    let slot = |offset: u64| {
        Expr::bin(
            BinOp::Add,
            Expr::reg(4, 64),
            Expr::Const(offset.wrapping_sub(64)),
        )
    };
    let mut candidates = Vec::new();
    for (signed, width) in [(false, 1), (true, 1), (false, 2)] {
        let read = Expr::Load {
            addr: Box::new(slot(0)),
            width,
            signed,
        };
        let ret = Stmt::Ret { value: read };
        let mut ir = synthetic_ir(
            if signed {
                "signed_buffer_byte"
            } else if width == 1 {
                "buffer_byte"
            } else {
                "buffer_word"
            },
            vec![Param {
                index: 7,
                name: "x".into(),
                ty: CType::U64,
            }],
            CType::U64,
            vec![
                Stmt::Call {
                    abi: None,
                    kind: velk::ir::CallKind::Invoke,
                    target: Some(0x1000),
                    through: None,
                    convention: Convention::SysV,
                    args: Some(vec![slot(0), Expr::Const(0), Expr::Const(16)]),
                    floats_named: false,
                    outputs: Vec::new(),
                    clobbers: Some(Default::default()),
                    via: None,
                },
                Stmt::Store {
                    addr: slot(0),
                    value: Expr::Const(0),
                    width: 2,
                },
                Stmt::Store {
                    addr: slot(0),
                    value: Expr::reg(7, 64),
                    width: 1,
                },
                ret.clone(),
            ],
        );
        let mut symbols = velk::render::Symbols::default();
        symbols.functions.insert(0x1000, "memset".into());
        let code = velk::render::render(&ir, &[], &symbols, &[]);
        assert!(!code.contains("*(uint8_t *)(local_"), "{code}");
        // The bytes read and written at more than one width share a union.
        assert!(code.contains("local_0.f_0."), "{code}");
        assert!(!code.contains("*(uint16_t *)"), "{code}");
        ir.blocks[0].stmts = (0..16)
            .map(|offset| Stmt::Store {
                addr: slot(offset),
                value: Expr::Const(0),
                width: 1,
            })
            .collect();
        ir.blocks[0].stmts.push(Stmt::Store {
            addr: slot(0),
            value: Expr::reg(7, 64),
            width: 1,
        });
        ir.blocks[0].stmts.push(ret);
        let mut candidate = printed_candidate(ir, (0..256).map(|value| vec![value]).collect());
        candidate.code = format!("#include <string.h>\n{code}");
        candidates.push(candidate);
    }
    check_candidates("byte_buffer_casts", candidates, Mode::Memory, &[]);
}

#[test]
fn declared_narrow_signed_values_extend_without_casts() {
    let mut candidates = Vec::new();
    for (width, name) in [(1, "signed char"), (2, "short"), (4, "int")] {
        let ir = synthetic_ir(
            &format!("declared_signed_{width}"),
            vec![Param {
                index: 7,
                name: "x".into(),
                ty: CType::Named(name.into()),
            }],
            CType::I64,
            vec![Stmt::Ret {
                value: Expr::SignExtend {
                    value: Box::new(Expr::reg(7, width * 8)),
                    width,
                },
            }],
        );
        let candidate = printed_candidate(
            ir,
            [
                0,
                1,
                127,
                128,
                255,
                32767,
                32768,
                65535,
                0x7fff_ffff,
                0x8000_0000,
                u64::MAX,
            ]
            .into_iter()
            .map(|x| vec![x])
            .collect(),
        );
        assert!(candidate.code.contains("return x;"), "{}", candidate.code);
        candidates.push(candidate);
    }
    check_candidates(
        "declared-signed-extension",
        candidates,
        Mode::Registers,
        &[],
    );
}

#[test]
fn plain_char_zero_tests_preserve_both_char_signs() {
    let ir = synthetic_ir(
        "plain_char_zero",
        vec![
            Param {
                index: 7,
                name: "s".into(),
                ty: CType::pointer_to(CType::Named("char".into())),
            },
            Param {
                index: 6,
                name: "byte".into(),
                ty: CType::U64,
            },
        ],
        CType::U64,
        vec![
            Stmt::Store {
                addr: Expr::reg(7, 64),
                value: Expr::reg(6, 64),
                width: 1,
            },
            Stmt::Ret {
                value: Expr::Select {
                    cond: Cond::Ne,
                    lhs: Box::new(Expr::Load {
                        addr: Box::new(Expr::reg(7, 64)),
                        width: 1,
                        signed: false,
                    }),
                    rhs: Box::new(Expr::Const(0)),
                    then: Box::new(Expr::Const(1)),
                    els: Box::new(Expr::Const(0)),
                },
            },
        ],
    );
    for sign in ["-fsigned-char", "-funsigned-char"] {
        let mut candidates = Vec::new();
        for mask in [None, Some(0xffff_ffff), Some(0x7f)] {
            for comparison in [Cond::Eq, Cond::Ne] {
                let mut ir = ir.clone();
                if let Stmt::Ret {
                    value: Expr::Select { cond, lhs, .. },
                } = &mut ir.blocks[0].stmts[1]
                {
                    *cond = comparison;
                    if let Some(mask) = mask {
                        **lhs = Expr::bin(BinOp::And, lhs.as_ref().clone(), Expr::Const(mask));
                    }
                }
                let candidate =
                    printed_candidate(ir, (0..256).map(|byte| vec![REGION, byte]).collect());
                if mask != Some(0x7f) {
                    assert!(!candidate.code.contains("(uint8_t)"), "{}", candidate.code);
                }
                candidates.push(candidate);
            }
        }
        check_candidates("plain-char-zero", candidates, Mode::Memory, &[sign]);
    }
}

#[test]
fn printed_bitstream_ranges_preserve_bytes_shifts_and_wrapping() {
    use velk::ir::{RegRef, VARIABLE_BASE};

    let mut candidates = Vec::new();
    let counts = [0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 65, u64::MAX];
    let inputs: Vec<Vec<u64>> = (0..256)
        .map(|value| vec![value, 8])
        .chain(
            [
                0,
                1,
                127,
                128,
                255,
                256,
                65535,
                65536,
                0xffff_ffff,
                u64::MAX,
            ]
            .into_iter()
            .flat_map(|value| counts.iter().map(move |count| vec![value, *count])),
        )
        .collect();
    for width in [1, 2, 4] {
        let local = Expr::reg(VARIABLE_BASE, 64);
        let mask = (1u64 << (width * 8)) - 1;
        let mut ir = synthetic_ir(
            &format!("bitstream_range_{width}"),
            vec![
                Param {
                    index: 7,
                    name: "x".into(),
                    ty: CType::U64,
                },
                Param {
                    index: 6,
                    name: "count".into(),
                    ty: CType::U64,
                },
            ],
            CType::U64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: VARIABLE_BASE,
                        width: 64,
                    },
                    value: Expr::bin(BinOp::And, Expr::reg(7, 64), Expr::Const(mask)),
                },
                Stmt::Store {
                    addr: Expr::Const(REGION),
                    width,
                    value: Expr::bin(BinOp::Add, local.clone(), Expr::Const(1)),
                },
                Stmt::Ret {
                    value: Expr::bin(
                        BinOp::Or,
                        Expr::bin(BinOp::Shl, local.clone(), Expr::reg(6, 64)),
                        Expr::Select {
                            cond: Cond::Hi,
                            lhs: Box::new(local),
                            rhs: Box::new(Expr::Const(0x7f)),
                            then: Box::new(Expr::Const(1)),
                            els: Box::new(Expr::Const(0)),
                        },
                    ),
                },
            ],
        );
        ir.value_types.insert(VARIABLE_BASE, CType::int(8, true));
        let candidate = printed_candidate(ir, inputs.clone());
        assert!(
            candidate.code.contains("\n    int64_t v1 ="),
            "{}",
            candidate.code
        );
        assert!(candidate.code.contains("& 0x3f"), "{}", candidate.code);
        assert!(
            !candidate.code.contains("(uint64_t)v1 >"),
            "{}",
            candidate.code
        );
        assert!(!candidate.code.contains("(uint8_t)"), "{}", candidate.code);
        assert!(!candidate.code.contains("(uint16_t)"), "{}", candidate.code);
        candidates.push(candidate);
    }
    check_candidates(
        "bitstream_ranges",
        candidates,
        Mode::Memory,
        &["-fsanitize=undefined", "-fno-sanitize-recover=all"],
    );
}

#[test]
fn printed_integer_argument_parts_preserve_every_byte_and_sign() {
    let mut candidates = Vec::new();
    for argument_signed in [false, true] {
        for signed in [false, true] {
            for (offset, width) in [(0, 1), (7, 1), (1, 2), (0, 4), (3, 4)] {
                let mut ir = scalar_stack_ir(
                    &format!("argument_part_{argument_signed}_{signed}_{offset}_{width}"),
                    3,
                    vec![Stmt::Ret {
                        value: Expr::Load {
                            addr: Box::new(Expr::bin(
                                BinOp::Add,
                                Expr::reg(4, 64),
                                Expr::Const(24 + offset),
                            )),
                            width,
                            signed,
                        },
                    }],
                );
                if argument_signed {
                    ir.stack_params[2].ty = CType::int(8, true);
                    ir.declared_signature.as_mut().unwrap().params[8].1 = CType::int(8, true);
                }
                let inputs: Vec<Vec<u64>> = (0..256u64)
                    .chain([256, 65535, 65536, 0x7fff_ffff, 0x8000_0000, u64::MAX])
                    .map(|value| {
                        let mut input = vec![0; 9];
                        input[8] = value.wrapping_mul(0x0101_0101_0101_0101);
                        input
                    })
                    .collect();
                let upper = vec![0; inputs.len()];
                let batch = aggregate_candidates(ir, inputs, upper);
                for candidate in &batch {
                    assert!(
                        !candidate.code.contains("__builtin_memcpy"),
                        "{}",
                        candidate.code
                    );
                    assert!(candidate.code.contains("stack2"), "{}", candidate.code);
                }
                assert_aggregate_oracle(&batch, |input, _| {
                    let raw = (input[8] >> (8 * offset)) & byte_mask(width);
                    if signed {
                        match width {
                            1 => raw as i8 as i64 as u64,
                            2 => raw as i16 as i64 as u64,
                            4 => raw as i32 as i64 as u64,
                            _ => unreachable!(),
                        }
                    } else {
                        raw
                    }
                });
                candidates.extend(batch);
            }
        }
    }
    check_candidates(
        "integer_argument_parts",
        candidates,
        Mode::Registers,
        &["-fsanitize=undefined", "-fno-sanitize-recover=all"],
    );
}

#[test]
fn simplified_selections_keep_the_comparison_width() {
    let mut candidates = Vec::new();
    for (at, (cond, mask, add)) in [
        (Cond::Lt, 0xaa4c_90f6, 0),
        (Cond::Ge, 0xaa4c_90f6, 0),
        (Cond::Gt, 0xaa4c_90f6, 0),
        (Cond::Le, 0xaa4c_90f6, 0),
        (Cond::Cs, 0xffff_fffe, 2),
        (Cond::Cc, 0xffff_fffe, 2),
        (Cond::Hi, 0xffff_fffe, 2),
        (Cond::Ls, 0xffff_fffe, 2),
    ]
    .into_iter()
    .enumerate()
    {
        let masked = Expr::bin(
            BinOp::And,
            Expr::bin(BinOp::And, Expr::reg(7, 64), Expr::Const(mask)),
            Expr::Const(0xffff_ffff),
        );
        let ir = synthetic_ir(
            &format!("masked_selection_{at}"),
            vec![Param {
                index: 7,
                name: "x".into(),
                ty: CType::U64,
            }],
            CType::U64,
            vec![Stmt::Ret {
                value: Expr::Select {
                    cond,
                    lhs: Box::new(if add == 0 {
                        masked
                    } else {
                        Expr::bin(BinOp::Add, masked, Expr::Const(add))
                    }),
                    rhs: Box::new(Expr::Const(112)),
                    then: Box::new(Expr::Const(1)),
                    els: Box::new(Expr::Const(0)),
                },
            }],
        );
        let mut simplified = ir.clone();
        velk::passes::simplify::simplify(&mut simplified);
        let mut candidate = printed_candidate(
            ir,
            [0, 112, 0x8000_0000, 0xaa4c_90f6, u64::MAX]
                .into_iter()
                .map(|x| vec![x])
                .collect(),
        );
        candidate.code = velk::render::render(&simplified, &[], &Default::default(), &[]);
        assert!(candidate.code.contains("int32_t"), "{}", candidate.code);
        candidates.push(candidate);
    }
    check_candidates("masked_selections", candidates, Mode::Registers, &[]);
}

#[test]
fn simplified_branches_keep_zero_extended_bytes_positive() {
    let mut candidates = Vec::new();
    for width in [1, 2] {
        let slot = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const((-8i64) as u64));
        let mut ir = synthetic_ir(
            &format!("zero_extended_branch_{width}"),
            vec![Param {
                index: 7,
                name: "x".into(),
                ty: CType::U64,
            }],
            CType::U64,
            vec![
                Stmt::Store {
                    addr: slot.clone(),
                    value: Expr::reg(7, 64),
                    width,
                },
                Stmt::Brif {
                    cond: Cond::Lt,
                    lhs: Expr::bin(
                        BinOp::And,
                        Expr::bin(
                            BinOp::And,
                            Expr::Load {
                                addr: Box::new(slot),
                                width,
                                signed: false,
                            },
                            Expr::Const(if width == 1 { 0xff } else { 0xffff }),
                        ),
                        Expr::Const(0xffff_ffff),
                    ),
                    rhs: Expr::Const(35),
                    target: 0x20,
                },
            ],
        );
        for (start, value) in [(0x10, 1), (0x20, 2)] {
            ir.blocks.push(Block {
                start,
                stmts: vec![Stmt::Ret {
                    value: Expr::Const(value),
                }],
            });
        }
        let mut simplified = ir.clone();
        velk::passes::simplify::simplify(&mut simplified);
        let mut candidate = printed_candidate(
            ir,
            [0, 34, 35, 127, 128, 251, 32768, 65535]
                .into_iter()
                .map(|x| vec![x])
                .collect(),
        );
        candidate.code = velk::render::render(&simplified, &[], &Default::default(), &[]);
        candidates.push(candidate);
    }
    check_candidates("zero_extended_branches", candidates, Mode::Registers, &[]);
}

#[test]
fn signed_comparisons_keep_their_sign_with_unsigned_positive_operands() {
    let mut candidates = Vec::new();
    let edges = [0, 1, 127, 128, 255, 256, 0x7fff_ffff, 0x8000_0000, u64::MAX];
    let inputs: Vec<_> = edges
        .iter()
        .flat_map(|x| edges.iter().map(move |y| vec![*x, *y]))
        .collect();
    for bits in [32, 64] {
        for byte in [false, true] {
            for reversed in [false, true] {
                for (at, cond) in [Cond::Lt, Cond::Ge, Cond::Gt, Cond::Le]
                    .into_iter()
                    .enumerate()
                {
                    let negative = if byte {
                        Expr::SignExtend {
                            value: Box::new(Expr::reg(7, bits)),
                            width: 1,
                        }
                    } else {
                        Expr::reg(7, bits)
                    };
                    let positive = Expr::bin(BinOp::And, Expr::reg(6, bits), Expr::Const(255));
                    let (lhs, rhs) = if reversed {
                        (positive, negative)
                    } else {
                        (negative, positive)
                    };
                    let ir = synthetic_ir(
                        &format!("signed_positive_{bits}_{byte}_{reversed}_{at}"),
                        vec![
                            Param {
                                index: 7,
                                name: "x".into(),
                                ty: CType::int(bits / 8, true),
                            },
                            Param {
                                index: 6,
                                name: "y".into(),
                                ty: CType::int(bits / 8, false),
                            },
                        ],
                        CType::U64,
                        vec![Stmt::Ret {
                            value: Expr::Select {
                                cond,
                                lhs: Box::new(lhs),
                                rhs: Box::new(rhs),
                                then: Box::new(Expr::Const(1)),
                                els: Box::new(Expr::Const(0)),
                            },
                        }],
                    );
                    candidates.push(printed_candidate(ir, inputs.clone()));
                }
            }
        }
    }
    check_candidates(
        "signed-positive-comparisons",
        candidates,
        Mode::Registers,
        &[],
    );
}

#[test]
fn declared_destinations_supply_truncated_sign_extensions() {
    let mut candidates = Vec::new();
    for from in [1, 2, 4, 8] {
        for to in [1, 2, 4, 8] {
            for signed in [false, true] {
                for mask in [u64::MAX, 0xffff_ffff, 0x7f] {
                    let ir = synthetic_ir(
                        &format!("truncate_extension_{from}_{to}_{signed}_{mask}"),
                        vec![Param {
                            index: 7,
                            name: "x".into(),
                            ty: CType::U64,
                        }],
                        CType::int(to, signed),
                        vec![Stmt::Ret {
                            value: Expr::bin(
                                BinOp::And,
                                Expr::SignExtend {
                                    value: Box::new(Expr::reg(7, 64)),
                                    width: from,
                                },
                                Expr::Const(mask),
                            ),
                        }],
                    );
                    let candidate = printed_candidate(
                        ir,
                        [
                            0,
                            1,
                            127,
                            128,
                            255,
                            32767,
                            32768,
                            65535,
                            0x7fff_ffff,
                            0x8000_0000,
                            u64::MAX,
                        ]
                        .into_iter()
                        .map(|x| vec![x])
                        .collect(),
                    );
                    let kept = u64::MAX >> (64 - u32::from(to) * 8);
                    if to <= from && (signed || to > 1) && mask & kept == kept {
                        assert!(candidate.code.contains("return x;"), "{}", candidate.code);
                    }
                    candidates.push(candidate);
                }
            }
        }
    }
    check_candidates(
        "truncated-sign-extensions",
        candidates,
        Mode::Registers,
        &[],
    );
}

#[test]
fn unsigned_entry_copies_use_parameters_only_when_unchanged() {
    let mut binary =
        Binary::open(&common::fixtures_dir().join("metrics/aggregate_abi.x86_64.O0.debug.elf"))
            .unwrap();
    let address = binary.find("abi_pair_adjust").unwrap().addr;
    let original = binary.analysis(address, None).unwrap().ir.clone();
    let inputs: Vec<_> = [0, 1, u64::from(u32::MAX), 1 << 63, u64::MAX]
        .into_iter()
        .map(|x| vec![x, x ^ 1, x])
        .collect();
    let mut candidates = Vec::new();
    for written in [false, true] {
        for name in ["tail", "uint64_t"] {
            let mut ir = original.clone();
            ir.name = Some(format!("unsigned_entry_{written}_{name}"));
            let signature = ir.declared_signature.as_mut().unwrap();
            signature.params[1].0 = name.into();
            let abi = signature.abi.as_ref().unwrap();
            let Passing::Direct(pieces) = &abi.arguments[1].passing else {
                panic!()
            };
            let AbiLocation::Register(register) = pieces[0].location else {
                panic!()
            };
            if written {
                ir.blocks[0].stmts.insert(
                    0,
                    Stmt::Assign {
                        dest: velk::ir::RegRef {
                            index: register,
                            width: 64,
                        },
                        value: Expr::bin(BinOp::Add, Expr::reg(register, 64), Expr::Const(1)),
                    },
                );
            }
            let projected = aggregate_candidates(ir, inputs.clone(), vec![0; inputs.len()]);
            for candidate in &projected {
                assert_eq!(
                    candidate.code.contains(&format!("uint64_t {name}_bits =")),
                    written,
                    "{}",
                    candidate.code
                );
                assert!(
                    !candidate.code.contains("uint64_t value_bits ="),
                    "{}",
                    candidate.code
                );
            }
            candidates.extend(projected);
        }
    }
    check_candidates("unsigned-entry-copies", candidates, Mode::Registers, &[]);
}

#[test]
fn boolean_returns_keep_truncation_before_testing_for_zero() {
    let ir = synthetic_ir(
        "byte_nonzero",
        vec![Param {
            index: 7,
            name: "x".into(),
            ty: CType::U64,
        }],
        CType::Named("_Bool".into()),
        vec![Stmt::Ret {
            value: Expr::SignExtend {
                value: Box::new(Expr::reg(7, 64)),
                width: 1,
            },
        }],
    );
    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
    syntax::run_printed(&code, "", "return byte_nonzero(256) || !byte_nonzero(128);");
}

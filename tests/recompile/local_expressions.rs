use super::*;
use velk::ir::{RegRef, VARIABLE_BASE};

#[test]
fn printed_volatile_integer_reads_keep_their_order() {
    let candidate = printed_candidate(
        synthetic_ir(
            "ordered_volatile_integer",
            vec![
                Param {
                    index: 7,
                    name: "p".into(),
                    ty: CType::pointer_to(CType::U64),
                },
                Param {
                    index: 6,
                    name: "value".into(),
                    ty: CType::Named("volatile uint64_t".into()),
                },
            ],
            CType::U64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: VARIABLE_BASE,
                        width: 64,
                    },
                    value: Expr::bin(BinOp::Add, Expr::reg(6, 64), Expr::Const(1)),
                },
                Stmt::Store {
                    addr: Expr::reg(7, 64),
                    value: Expr::Const(7),
                    width: 8,
                },
                Stmt::Ret {
                    value: Expr::reg(VARIABLE_BASE, 64),
                },
            ],
        ),
        vec![vec![REGION, 0], vec![REGION, u64::MAX]],
    );
    let read = candidate.code.find("value + 1").unwrap();
    let store = candidate.code.find("*p = 7;").unwrap();
    assert!(read < store, "{}", candidate.code);
    check_candidates(
        "ordered-volatile-integer",
        vec![candidate],
        Mode::Memory,
        &[],
    );
}

#[test]
fn printed_volatile_fields_are_captured_once() {
    let path = common::fixtures_dir().join("metrics/structs.x86_64.O0.debug.elf");
    let mut binary = Binary::open(&path).unwrap();
    let address = binary.find("point_add").unwrap().addr;
    let mut ir = binary.analysis(address, None).unwrap().ir.clone();
    for member in &mut ir.members {
        if member.structure == "point" {
            member.ty = CType::Named("volatile int".into());
        }
    }
    for definition in &mut ir.definitions {
        for member in &mut definition.members {
            *member = member.replace("int ", "volatile int ");
        }
    }
    let Stmt::Store {
        value: Expr::Bin { lhs, rhs, .. },
        ..
    } = &mut ir.blocks[0].stmts[2]
    else {
        panic!("the first point field is the sum of two input fields");
    };
    *rhs = lhs.clone();
    let (inputs, upper) = aggregate_inputs(&[8, 8], 12);
    let candidates = aggregate_candidates(ir, inputs, upper);
    for candidate in &candidates {
        assert!(candidate.code.contains(" = a.x;"), "{}", candidate.code);
    }
    check_candidates("volatile-field-captures", candidates, Mode::Registers, &[]);
}

#[test]
fn printed_masked_float_expressions_keep_their_assignment_conversion() {
    let candidate = printed_candidate(
        synthetic_ir(
            "masked_float_assignment",
            vec![Param {
                index: 7,
                name: "p".into(),
                ty: CType::pointer_to(CType::U64),
            }],
            CType::U64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: VARIABLE_BASE,
                        width: 64,
                    },
                    value: Expr::bin(
                        BinOp::And,
                        Expr::Apply {
                            op: Operation::FloatAdd(Precision::Single),
                            args: vec![Expr::Const(0x3f80_0000), Expr::Const(0xbf80_0000)],
                        },
                        Expr::Const(0xffff_ffff),
                    ),
                },
                Stmt::Store {
                    addr: Expr::reg(7, 64),
                    value: Expr::Const(7),
                    width: 8,
                },
                Stmt::Ret {
                    value: Expr::reg(VARIABLE_BASE, 64),
                },
            ],
        ),
        vec![vec![REGION]],
    );
    assert!(
        candidate.code.contains("uint32_t v1 ="),
        "{}",
        candidate.code
    );
    assert!(candidate.code.contains("return v1;"), "{}", candidate.code);
    check_candidates(
        "masked-float-assignment",
        vec![candidate],
        Mode::Memory,
        &[],
    );
}

#[test]
fn printed_division_stays_before_memory_effects() {
    let candidate = printed_candidate(
        synthetic_ir(
            "ordered_integer_division",
            vec![
                Param {
                    index: 7,
                    name: "p".into(),
                    ty: CType::pointer_to(CType::U64),
                },
                Param {
                    index: 6,
                    name: "divisor".into(),
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
                    value: Expr::bin(BinOp::DivU, Expr::Const(100), Expr::reg(6, 64)),
                },
                Stmt::Store {
                    addr: Expr::reg(7, 64),
                    value: Expr::Const(7),
                    width: 8,
                },
                Stmt::Ret {
                    value: Expr::reg(VARIABLE_BASE, 64),
                },
            ],
        ),
        vec![vec![REGION, 1], vec![REGION, 3]],
    );
    let division = candidate.code.find(" / ").unwrap();
    let store = candidate.code.find("*p = 7;").unwrap();
    assert!(division < store, "{}", candidate.code);
    assert!(
        !candidate.code.contains("return 100 /"),
        "{}",
        candidate.code
    );
    check_candidates(
        "ordered-integer-division",
        vec![candidate],
        Mode::Memory,
        &[],
    );
}

#[test]
fn printed_record_indices_do_not_need_temporary_offsets() {
    for architecture in ["x86_64", "aarch64"] {
        let path = common::fixtures_dir()
            .join("metrics")
            .join(format!("structs.{architecture}.O0.debug.elf"));
        let mut binary = Binary::open(&path).unwrap();
        let address = binary.find("record_total").unwrap().addr;
        let code = binary.decompile(address, None, None).unwrap();
        assert!(!code.contains(" * 24;"), "{code}");
        assert!(!code.contains(" / 24]"), "{code}");
        assert!(code.contains("items[i]"), "{code}");
        syntax::run_printed(
            &code,
            "",
            "struct record items[3] = {{.value = -7, .count = 3}, {.value = 10000000000L, .count = -2}, {.value = 11, .count = 0}}; return record_total(items, -1) != 0 || record_total(items, 0) != 0 || record_total(items, 1) != -21 || record_total(items, 3) != -20000000021L;",
        );
    }
}

#[test]
fn printed_single_use_sign_extensions_keep_width_and_sign() {
    let mut candidates = Vec::new();
    for width in [32, 64] {
        for op in [BinOp::Add, BinOp::Sar, BinOp::Shr, BinOp::DivS] {
            let value = Expr::bin(
                BinOp::Mul,
                Expr::SignExtend {
                    value: Box::new(Expr::reg(7, 32)),
                    width: 4,
                },
                Expr::Const(24),
            );
            let original = synthetic_ir(
                &format!("signed_temporary_{width}_{op:?}"),
                vec![Param {
                    index: 7,
                    name: "x".into(),
                    ty: CType::U64,
                }],
                CType::U64,
                vec![
                    Stmt::Assign {
                        dest: RegRef {
                            index: VARIABLE_BASE,
                            width,
                        },
                        value,
                    },
                    Stmt::Ret {
                        value: Expr::bin(op, Expr::reg(VARIABLE_BASE, width), Expr::Const(3)),
                    },
                ],
            );
            let candidate = printed_candidate(
                original,
                [0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff, u64::MAX]
                    .into_iter()
                    .map(|x| vec![x])
                    .collect(),
            );
            candidates.push(candidate);
        }
    }
    check_candidates("signed-local-expressions", candidates, Mode::Registers, &[]);
}

#[test]
fn printed_immutable_integer_arguments_use_their_original_objects() {
    let mut candidates = Vec::new();
    for bytes in [1, 2, 4, 8] {
        for signed in [false, true] {
            let ty = CType::int(bytes, signed);
            let mut ir = integer_object_ir(u64::from(bytes), false);
            ir.name = Some(format!("integer_argument_{bytes}_{signed}"));
            ir.definitions[0].members = vec![format!("{ty} value;")];
            ir.definitions[0].fields = vec!["value".into()];
            ir.definitions[0].alignment = Some(u64::from(bytes));
            ir.members = vec![Member {
                structure: "bytes".into(),
                name: "value".into(),
                offset: 0,
                width: u64::from(bytes),
                ty: ty.clone(),
            }];
            let signature = ir.declared_signature.as_mut().unwrap();
            signature.params[1].1 = ty;
            let abi = signature.abi.as_mut().unwrap();
            abi.arguments[0].alignment = u64::from(bytes);
            abi.arguments[1].size = u64::from(bytes);
            abi.arguments[1].alignment = u64::from(bytes);
            abi.arguments[1].defined_bits = vec![(0, u64::from(bytes) * 8)];
            let Passing::Direct(pieces) = &mut abi.arguments[1].passing else {
                panic!("an integer argument is passed directly");
            };
            pieces[0].bytes = u64::from(bytes);
            let mask = Expr::Const(byte_mask(bytes));
            ir.blocks[0].stmts = vec![Stmt::Ret {
                value: Expr::bin(
                    BinOp::Xor,
                    Expr::bin(
                        BinOp::Shl,
                        Expr::bin(BinOp::And, Expr::reg(7, 64), mask.clone()),
                        Expr::Const(17),
                    ),
                    Expr::bin(BinOp::And, Expr::reg(6, 64), mask),
                ),
            }];
            let inputs: Vec<_> = [0, 1, 0x7f, 0x80, 0x7fff, 0x8000, 0x8000_0000, u64::MAX]
                .into_iter()
                .map(|x| vec![x, x.rotate_right(1)])
                .collect();
            let variants = aggregate_candidates(ir, inputs, vec![u64::MAX; 8]);
            for candidate in &variants {
                if bytes == 8 && !signed {
                    assert!(!candidate.code.contains("_bits"), "{}", candidate.code);
                } else {
                    assert!(candidate.code.contains("_bits"), "{}", candidate.code);
                }
                assert!(candidate.code.contains("value.value"), "{}", candidate.code);
            }
            candidates.extend(variants);
        }
    }
    check_candidates(
        "integer-argument-expressions",
        candidates,
        Mode::Registers,
        &[],
    );
}

#[test]
fn printed_widening_keeps_a_local_when_folding_adds_a_cast() {
    let candidate = printed_candidate(
        synthetic_ir(
            "widened_integer_temporary",
            vec![Param {
                index: 7,
                name: "x".into(),
                ty: CType::U32,
            }],
            CType::U64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: VARIABLE_BASE,
                        width: 64,
                    },
                    value: Expr::bin(BinOp::And, Expr::reg(7, 64), Expr::Const(0xff)),
                },
                Stmt::Ret {
                    value: Expr::bin(BinOp::Shl, Expr::reg(VARIABLE_BASE, 64), Expr::Const(40)),
                },
            ],
        ),
        [0, 1, 0xff, 0x100, u64::from(u32::MAX)]
            .into_iter()
            .map(|x| vec![x])
            .collect(),
    );
    assert!(candidate.code.contains(" v1 ="), "{}", candidate.code);
    assert!(
        candidate.code.contains("return v1 << 40;"),
        "{}",
        candidate.code
    );
    check_candidates(
        "widened-local-expression",
        vec![candidate],
        Mode::Registers,
        &[],
    );
}

#[test]
fn printed_masked_load_returns_do_not_need_integer_temporaries() {
    let mut candidates = Vec::new();
    for bytes in [1, 2, 4, 8] {
        for signed in [false, true] {
            for mask in [1, 0x55, 0x8000_0000, u64::MAX] {
                let ir = synthetic_ir(
                    &format!("masked_load_return_{bytes}_{signed}_{mask}"),
                    vec![Param {
                        index: 7,
                        name: "p".into(),
                        ty: CType::pointer_to(CType::U64),
                    }],
                    CType::U64,
                    vec![
                        Stmt::Assign {
                            dest: RegRef {
                                index: VARIABLE_BASE,
                                width: 64,
                            },
                            value: Expr::Load {
                                addr: Box::new(Expr::reg(7, 64)),
                                width: bytes,
                                signed,
                            },
                        },
                        Stmt::Ret {
                            value: Expr::bin(
                                BinOp::And,
                                Expr::reg(VARIABLE_BASE, 64),
                                Expr::Const(mask),
                            ),
                        },
                    ],
                );
                let mut folded = ir.clone();
                velk::passes::read_once::fold_values_read_once(&mut folded);
                let code = velk::render::render(&folded, &[], &Default::default(), &[]);
                if mask <= byte_mask(bytes) {
                    assert!(!code.contains(" v1"), "{code}");
                }
                let mut candidate = printed_candidate(ir, vec![vec![REGION]]);
                candidate.code = code;
                candidates.push(candidate);
            }
        }
    }
    check_candidates("masked-load-returns", candidates, Mode::Memory, &[]);
}

#[test]
fn unused_branch_results_leave_no_constant_temporaries() {
    let mut candidates = Vec::new();
    for isa in ["x86_64", "aarch64"] {
        let path = common::fixtures_dir().join(format!("metrics/control.{isa}.O2.debug.elf"));
        let mut binary = Binary::open(&path).unwrap();
        let address = binary.find("short_circuit").unwrap().addr;
        let ir = binary.analysis(address, None).unwrap().ir.clone();
        let candidate =
            printed_candidate(ir, vec![vec![REGION, 0], vec![REGION, 1], vec![REGION, 5]]);
        assert!(!candidate.code.contains(" = 0;"), "{}", candidate.code);
        assert!(!candidate.code.contains(" = 1;"), "{}", candidate.code);
        candidates.push(candidate);
    }
    check_candidates("unused-branch-results", candidates, Mode::Memory, &[]);
}

#[test]
fn parameter_copies_of_another_sign_fold_only_without_extra_conversions() {
    let mut candidates = Vec::new();
    for wide in [false, true] {
        for overwritten in [false, true] {
            let temp = VARIABLE_BASE;
            let mut stmts = vec![Stmt::Assign {
                dest: RegRef {
                    index: temp,
                    width: 32,
                },
                value: Expr::reg(7, 32),
            }];
            if overwritten {
                stmts.push(Stmt::Assign {
                    dest: RegRef {
                        index: 7,
                        width: 32,
                    },
                    value: Expr::Const(5),
                });
            }
            stmts.push(Stmt::Brif {
                cond: Cond::Eq,
                lhs: Expr::reg(6, 64),
                rhs: Expr::Const(0),
                target: 2,
            });
            let mut ir = synthetic_ir(
                &format!("parameter_sign_{wide}_{overwritten}"),
                vec![
                    Param {
                        index: 7,
                        name: "input".into(),
                        ty: CType::Named("int".into()),
                    },
                    Param {
                        index: 6,
                        name: "flag".into(),
                        ty: CType::U64,
                    },
                ],
                if wide { CType::U64 } else { CType::I32 },
                stmts,
            );
            ir.value_types.insert(temp, CType::U32);
            ir.blocks.push(Block {
                start: 1,
                stmts: vec![Stmt::Ret {
                    value: Expr::bin(BinOp::Add, Expr::reg(temp, 32), Expr::reg(temp, 32)),
                }],
            });
            ir.blocks.push(Block {
                start: 2,
                stmts: vec![Stmt::Ret {
                    value: Expr::Const(3),
                }],
            });
            let candidate = printed_candidate(
                ir,
                [0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff]
                    .into_iter()
                    .flat_map(|input| [vec![input, 0], vec![input, 1]])
                    .collect(),
            );
            if !wide && !overwritten {
                assert!(
                    !candidate.code.contains("uint32_t v1"),
                    "{}",
                    candidate.code
                );
            }
            if overwritten {
                assert!(candidate.code.contains(" = input;"), "{}", candidate.code);
            }
            candidates.push(candidate);
        }
    }
    check_candidates("parameter-copy-signs", candidates, Mode::Registers, &[]);
}

#[test]
fn repeated_parameter_folding_keeps_masked_byte_reads_narrow() {
    let path = common::fixtures_dir().join("arm32/structs.thumb.O0.elf");
    let mut binary = Binary::open(&path).unwrap();
    let address = binary.find("word_low_byte").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    assert!(code.contains("(uint8_t)a0"), "{code}");
    syntax::run_printed(
        &code,
        "",
        "return word_low_byte(0x101) != 1 || word_low_byte(-1) != 255;",
    );
}

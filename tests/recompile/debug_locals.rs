use super::*;

#[test]
fn branch_folding_preserves_unsigned_arithmetic_from_signed_parameters() {
    let temp = velk::ir::VARIABLE_BASE;
    let mut ir = synthetic_ir(
        "signed_parameter_copy",
        vec![
            Param {
                index: 7,
                name: "input".into(),
                ty: CType::I32,
            },
            Param {
                index: 6,
                name: "flag".into(),
                ty: CType::U64,
            },
        ],
        CType::U64,
        vec![
            Stmt::Assign {
                dest: velk::ir::RegRef {
                    index: temp,
                    width: 32,
                },
                value: Expr::reg(7, 32),
            },
            Stmt::Brif {
                cond: Cond::Eq,
                lhs: Expr::reg(6, 64),
                rhs: Expr::Const(0),
                target: 2,
            },
        ],
    );
    ir.blocks.push(Block {
        start: 1,
        stmts: vec![Stmt::Ret {
            value: Expr::bin(
                BinOp::And,
                Expr::bin(BinOp::Sub, Expr::reg(temp, 32), Expr::Const(1)),
                Expr::Const(0xffff_ffff),
            ),
        }],
    });
    ir.blocks.push(Block {
        start: 2,
        stmts: vec![Stmt::Ret {
            value: Expr::Const(0),
        }],
    });
    ir.value_types.insert(temp, CType::U32);
    velk::passes::read_once::fold_values_read_once(&mut ir);
    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
    assert!(code.contains("uint32_t v1"), "{code}");
    check_candidates(
        "signed-parameter-copy",
        vec![printed_candidate(
            ir,
            [0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff]
                .into_iter()
                .flat_map(|value| [vec![value, 0], vec![value, 1]])
                .collect(),
        )],
        Mode::Registers,
        &[],
    );
}

#[test]
fn pure_parameter_values_fold_into_one_branch_without_losing_snapshots() {
    let temp = velk::ir::VARIABLE_BASE;
    let mut candidates = Vec::new();
    for width in [32, 64] {
        for changed in [false, true] {
            for shared in [false, true] {
                let mut ir = synthetic_ir(
                    &format!("branch_temporary_{width}_{changed}_{shared}"),
                    vec![
                        Param {
                            index: 7,
                            name: "input".into(),
                            ty: CType::int(width / 8, false),
                        },
                        Param {
                            index: 6,
                            name: "flag".into(),
                            ty: CType::U64,
                        },
                    ],
                    CType::U64,
                    vec![
                        Stmt::Assign {
                            dest: velk::ir::RegRef { index: temp, width },
                            value: Expr::bin(BinOp::Add, Expr::reg(7, width), Expr::Const(1)),
                        },
                        Stmt::Brif {
                            cond: Cond::Eq,
                            lhs: Expr::reg(6, 64),
                            rhs: Expr::Const(0),
                            target: 2,
                        },
                    ],
                );
                let mut body = Vec::new();
                if changed {
                    body.push(Stmt::Assign {
                        dest: velk::ir::RegRef { index: 7, width },
                        value: Expr::Const(9),
                    });
                }
                body.push(Stmt::Ret {
                    value: Expr::bin(
                        BinOp::And,
                        Expr::bin(BinOp::Mul, Expr::reg(temp, width), Expr::Const(3)),
                        Expr::Const(if width == 32 { 0xffff_ffff } else { u64::MAX }),
                    ),
                });
                ir.blocks.push(Block {
                    start: 1,
                    stmts: body,
                });
                ir.blocks.push(Block {
                    start: 2,
                    stmts: vec![Stmt::Ret {
                        value: if shared {
                            Expr::reg(temp, width)
                        } else {
                            Expr::Const(0)
                        },
                    }],
                });
                ir.value_types.insert(temp, CType::int(width / 8, false));
                velk::passes::read_once::fold_values_read_once(&mut ir);
                let code = velk::render::render(&ir, &[], &Default::default(), &[]);
                assert_eq!(code.contains(" v1"), changed || shared, "{code}");
                candidates.push(printed_candidate(
                    ir,
                    [0, 1, u64::MAX, 1 << 63]
                        .into_iter()
                        .flat_map(|value| [vec![value, 0], vec![value, 1]])
                        .collect(),
                ));
            }
        }
    }
    check_candidates("branch-temporary", candidates, Mode::Registers, &[]);
}

#[test]
#[ignore = "syntax-checks every debug C/C++ fixture function"]
fn debug_fixture_functions_compile() {
    let fixtures: Vec<_> = common::fixtures()
        .into_iter()
        .filter(|path| path.starts_with("metrics") && path.to_string_lossy().contains(".debug."))
        .collect();
    assert!(!fixtures.is_empty());
    syntax::scan(&fixtures, "debug-syntax");
}

#[test]
fn named_integer_temporary_folds_into_its_only_use() {
    let arg = Convention::SysV.arguments()[0];
    let temp = velk::ir::VARIABLE_BASE;
    let mut ir = synthetic_ir(
        "named_integer_temporary",
        vec![Param {
            index: arg,
            name: "input".into(),
            ty: CType::U64,
        }],
        CType::U64,
        vec![
            Stmt::Assign {
                dest: velk::ir::RegRef {
                    index: temp,
                    width: 64,
                },
                value: Expr::bin(BinOp::Add, Expr::reg(arg, 64), Expr::Const(1)),
            },
            Stmt::Ret {
                value: Expr::bin(BinOp::Mul, Expr::reg(temp, 64), Expr::Const(3)),
            },
        ],
    );
    ir.value_types
        .insert(temp, CType::Named("unsigned long".into()));
    let before = velk::render::render(&ir, &[], &Default::default(), &[]);
    assert!(before.contains("unsigned long v1"), "{before}");
    velk::passes::read_once::fold_values_read_once(&mut ir);
    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
    assert!(!code.contains(" v1"), "{code}");
    check_candidates(
        "named-integer-temporary",
        vec![printed_candidate(
            ir,
            [0, 1, u64::MAX, 1 << 63]
                .into_iter()
                .map(|value| vec![value])
                .collect(),
        )],
        Mode::Registers,
        &[],
    );
}

fn slot(offset: i64) -> Expr {
    Expr::bin(
        BinOp::Add,
        Expr::reg(velk::arch::stack_pointer(Isa::X86_64), 64),
        Expr::Const(offset as u64),
    )
}

#[test]
fn stack_local_copies_use_the_slot_only_while_values_agree() {
    let arg = Convention::SysV.arguments()[0];
    let temp = velk::ir::VARIABLE_BASE;
    let mut candidates = Vec::new();
    for width in [32, 64] {
        for named in [false, true] {
            for overwrite in [false, true] {
                for partial in [false, true] {
                    let mut ir = synthetic_ir(
                        &format!("stack_copy_{width}_{named}_{overwrite}_{partial}"),
                        vec![Param {
                            index: arg,
                            name: "input".into(),
                            ty: CType::U32,
                        }],
                        CType::int(width / 8, false),
                        vec![
                            Stmt::Assign {
                                dest: velk::ir::RegRef { index: temp, width },
                                value: Expr::bin(BinOp::Xor, Expr::reg(arg, 32), Expr::Const(17)),
                            },
                            Stmt::Store {
                                addr: slot(-16),
                                value: Expr::reg(temp, width),
                                width: width / 8,
                            },
                            Stmt::Brif {
                                cond: if width == 32 { Cond::Lt } else { Cond::Eq },
                                lhs: Expr::reg(temp, width),
                                rhs: Expr::Const(0),
                                target: 2,
                            },
                        ],
                    );
                    if named {
                        ir.debug_locals.push(velk::ir::DebugLocal {
                            name: "sample".into(),
                            ty: CType::int(width / 8, false),
                            slot: -16,
                            size: u64::from(width / 8),
                        });
                    }
                    let mut body = Vec::new();
                    if overwrite {
                        body.push(Stmt::Store {
                            addr: slot(if partial { -15 } else { -16 }),
                            value: Expr::Const(0),
                            width: if partial { 1 } else { width / 8 },
                        });
                    }
                    body.push(Stmt::Ret {
                        value: Expr::bin(
                            BinOp::Add,
                            Expr::reg(temp, width),
                            Expr::Load {
                                addr: Box::new(slot(-16)),
                                width: width / 8,
                                signed: false,
                            },
                        ),
                    });
                    ir.blocks.push(Block {
                        start: 1,
                        stmts: body,
                    });
                    ir.blocks.push(Block {
                        start: 2,
                        stmts: vec![Stmt::Ret {
                            value: Expr::reg(temp, width),
                        }],
                    });
                    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
                    assert_eq!(code.contains("sample"), named, "{code}");
                    assert_eq!(code.contains(" v1"), overwrite, "{code}");
                    candidates.push(printed_candidate(
                        ir,
                        [0, 1, 17, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff]
                            .into_iter()
                            .map(|value| vec![value])
                            .collect(),
                    ));
                }
            }
        }
    }
    check_candidates("stack-local-copies", candidates, Mode::Memory, &[]);
}

#[test]
fn debug_local_types_preserve_signed_and_partial_loads() {
    let mut candidates = Vec::new();
    let arg = Convention::SysV.arguments()[0];
    for width in [1, 2, 4, 8] {
        for declared_signed in [false, true] {
            for signed_load in [false, true] {
                let mut ir = synthetic_ir(
                    &format!("debug_width_{width}_{declared_signed}_{signed_load}"),
                    vec![Param {
                        index: arg,
                        name: "input".into(),
                        ty: CType::U64,
                    }],
                    CType::U64,
                    vec![
                        Stmt::Store {
                            addr: slot(-16),
                            value: Expr::reg(arg, 64),
                            width,
                        },
                        Stmt::Ret {
                            value: Expr::Load {
                                addr: Box::new(slot(-16)),
                                width,
                                signed: signed_load,
                            },
                        },
                    ],
                );
                ir.debug_locals.push(velk::ir::DebugLocal {
                    name: "value".into(),
                    ty: if width == 4 && declared_signed {
                        CType::Named("int".into())
                    } else {
                        CType::int(width, declared_signed)
                    },
                    slot: -16,
                    size: u64::from(width),
                });
                let code = velk::render::render(&ir, &[], &Default::default(), &[]);
                if width < 8 {
                    assert!(code.contains(" value; /* [sp-10] */"), "{code}");
                    if declared_signed && !signed_load {
                        assert!(
                            code.contains(&format!("uint{}_t value;", width * 8)),
                            "{code}"
                        );
                    }
                    if width == 4 && declared_signed && signed_load {
                        assert!(code.contains("int value;"), "{code}");
                        assert!(!code.contains("(int32_t)value"), "{code}");
                    }
                }
                let inputs: Vec<Vec<u64>> = [
                    0,
                    1,
                    0x7f,
                    0x80,
                    0xff,
                    0x8000,
                    0xffff,
                    0x7fff_ffff,
                    0x8000_0000,
                    0xffff_ffff,
                    u64::MAX,
                ]
                .into_iter()
                .map(|value| vec![value])
                .collect();
                if width == 4 && declared_signed {
                    let mut rust = ir.clone();
                    rust.name = Some(format!("debug_rust_integer_{signed_load}"));
                    rust.debug_locals[0].ty = CType::Named("i32".into());
                    let code = velk::render::render(&rust, &[], &Default::default(), &[]);
                    assert!(!code.contains("i32 value;"), "{code}");
                    candidates.push(printed_candidate(rust, inputs.clone()));
                }
                if width == 4 {
                    let mut named = ir.clone();
                    named.name = Some(format!("debug_parameter_{declared_signed}_{signed_load}"));
                    named.params[0].ty = CType::Named(
                        if declared_signed {
                            "int"
                        } else {
                            "unsigned int"
                        }
                        .into(),
                    );
                    let code = velk::render::render(&named, &[], &Default::default(), &[]);
                    assert!(!code.contains("; /* [sp"), "{code}");
                    let mut overflow = named.clone();
                    overflow.name = Some(format!("debug_overflow_{declared_signed}_{signed_load}"));
                    let load = Expr::Load {
                        addr: Box::new(slot(-16)),
                        width: 4,
                        signed: false,
                    };
                    let increment = Expr::bin(
                        BinOp::And,
                        Expr::bin(BinOp::Add, load.clone(), Expr::Const(1)),
                        Expr::Const(0xffff_ffff),
                    );
                    overflow.blocks[0].stmts[1] = Stmt::Ret {
                        value: Expr::Select {
                            cond: Cond::Lt,
                            lhs: Box::new(Expr::SignExtend {
                                value: Box::new(increment),
                                width: 4,
                            }),
                            rhs: Box::new(Expr::SignExtend {
                                value: Box::new(load),
                                width: 4,
                            }),
                            then: Box::new(Expr::Const(1)),
                            els: Box::new(Expr::Const(0)),
                        },
                    };
                    candidates.push(printed_candidate(overflow, inputs.clone()));
                    candidates.push(printed_candidate(named, inputs.clone()));
                }
                if width > 1 {
                    let mut partial = ir.clone();
                    partial.name = Some(format!(
                        "debug_partial_{width}_{declared_signed}_{signed_load}"
                    ));
                    partial.blocks[0].stmts[1] = Stmt::Ret {
                        value: Expr::Load {
                            addr: Box::new(slot(-16)),
                            width: 1,
                            signed: signed_load,
                        },
                    };
                    candidates.push(printed_candidate(partial, inputs.clone()));
                }
                candidates.push(printed_candidate(ir, inputs));
            }
        }
    }
    check_candidates("debug-local-widths", candidates, Mode::Memory, &[]);
}

#[test]
fn debug_array_slots_share_typed_storage() {
    let arg = Convention::SysV.arguments()[0];
    let mut ir = synthetic_ir(
        "debug_array",
        vec![Param {
            index: arg,
            name: "input".into(),
            ty: CType::U64,
        }],
        CType::U64,
        vec![
            Stmt::Store {
                addr: slot(-16),
                value: Expr::reg(arg, 64),
                width: 4,
            },
            Stmt::Store {
                addr: slot(-12),
                value: Expr::Const(7),
                width: 4,
            },
            Stmt::Ret {
                value: Expr::bin(
                    BinOp::Add,
                    Expr::Load {
                        addr: Box::new(slot(-16)),
                        width: 4,
                        signed: false,
                    },
                    Expr::Load {
                        addr: Box::new(slot(-12)),
                        width: 4,
                        signed: false,
                    },
                ),
            },
        ],
    );
    ir.debug_locals.push(velk::ir::DebugLocal {
        name: "values".into(),
        ty: CType::Array(Box::new(CType::U32)),
        slot: -16,
        size: 8,
    });
    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
    assert!(code.contains("uint32_t values[0x2]"), "{code}");
    assert!(!code.contains("local_"), "{code}");
    assert!(!code.contains(".f_"), "{code}");
    check_candidates(
        "debug-local-array",
        vec![printed_candidate(
            ir,
            vec![vec![0], vec![u64::MAX], vec![0x8000_0000]],
        )],
        Mode::Memory,
        &[],
    );
}

#[test]
fn debug_structure_fields_preserve_signed_values() {
    let arg = Convention::SysV.arguments()[0];
    let mut ir = synthetic_ir(
        "debug_structure",
        vec![Param {
            index: arg,
            name: "input".into(),
            ty: CType::U64,
        }],
        CType::U64,
        vec![
            Stmt::Store {
                addr: slot(-16),
                value: Expr::reg(arg, 64),
                width: 4,
            },
            Stmt::Store {
                addr: slot(-12),
                value: Expr::Const(7),
                width: 4,
            },
            Stmt::Ret {
                value: Expr::bin(
                    BinOp::Add,
                    Expr::Load {
                        addr: Box::new(slot(-16)),
                        width: 4,
                        signed: true,
                    },
                    Expr::Load {
                        addr: Box::new(slot(-12)),
                        width: 4,
                        signed: true,
                    },
                ),
            },
        ],
    );
    ir.definitions.push(velk::ir::Definition {
        name: "struct pair".into(),
        members: vec!["int left;".into(), "int right;".into()],
        fields: vec!["left".into(), "right".into()],
        contains: vec![],
        size: 8,
        alignment: None,
        compatible_profiles: vec![velk::ir::AbiProfile::SysV],
    });
    for (offset, name) in [(0, "left"), (4, "right")] {
        ir.members.push(velk::ir::Member {
            structure: "struct pair".into(),
            offset,
            name: name.into(),
            ty: CType::I32,
            width: 4,
        });
    }
    ir.debug_locals.push(velk::ir::DebugLocal {
        name: "pair".into(),
        ty: CType::Named("struct pair".into()),
        slot: -16,
        size: 8,
    });
    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
    assert!(code.contains("struct pair pair;"), "{code}");
    assert!(code.contains("pair.left"), "{code}");
    check_candidates(
        "debug-local-structure",
        vec![printed_candidate(
            ir,
            vec![vec![0], vec![u64::MAX], vec![0x8000_0000]],
        )],
        Mode::Memory,
        &[],
    );
}

#[test]
fn bounded_narrow_copies_fold_without_changing_extended_values() {
    let temp = velk::ir::VARIABLE_BASE;
    let mut candidates = Vec::new();
    for width in [8, 16, 32] {
        for bounded in [false, true] {
            let value = if bounded {
                Expr::Select {
                    cond: Cond::Lt,
                    lhs: Box::new(Expr::reg(7, 32)),
                    rhs: Box::new(Expr::Const(0)),
                    then: Box::new(Expr::Const(1)),
                    els: Box::new(Expr::Const(0)),
                }
            } else {
                Expr::reg(7, 64)
            };
            let mut ir = synthetic_ir(
                &format!("narrow_copy_{width}_{bounded}"),
                vec![Param {
                    index: 7,
                    name: "input".into(),
                    ty: CType::U64,
                }],
                CType::U64,
                vec![
                    Stmt::Assign {
                        dest: velk::ir::RegRef { index: temp, width },
                        value,
                    },
                    Stmt::Ret {
                        value: Expr::reg(temp, 64),
                    },
                ],
            );
            ir.value_types.insert(temp, CType::int(width / 8, false));
            let mut candidate = printed_candidate(
                ir.clone(),
                [0, 1, 255, 256, 65535, 65536, 0x8000_0000, u64::MAX]
                    .into_iter()
                    .map(|value| vec![value])
                    .collect(),
            );
            velk::passes::read_once::fold_values_read_once(&mut ir);
            candidate.code = velk::render::render(&ir, &[], &Default::default(), &[]);
            if bounded {
                assert!(!candidate.code.contains(" v1"), "{}", candidate.code);
                assert!(candidate.code.contains("return "), "{}", candidate.code);
            }
            candidates.push(candidate);
        }
    }
    check_candidates("bounded-narrow-copies", candidates, Mode::Registers, &[]);
}

#[test]
fn private_return_slots_fold_only_at_the_return_width() {
    let mut candidates = Vec::new();
    for width in [1, 2, 4, 8] {
        for widened in [false, true] {
            let ir = synthetic_ir(
                &format!("return_slot_{width}_{widened}"),
                vec![Param {
                    index: 7,
                    name: "input".into(),
                    ty: CType::U64,
                }],
                if widened {
                    CType::U64
                } else {
                    CType::int(width, false)
                },
                vec![
                    Stmt::Store {
                        addr: slot(-16),
                        value: Expr::reg(7, 64),
                        width,
                    },
                    Stmt::Ret {
                        value: Expr::Load {
                            addr: Box::new(slot(-16)),
                            width,
                            signed: false,
                        },
                    },
                ],
            );
            let candidate = printed_candidate(
                ir,
                [0, 1, 255, 256, 65535, 65536, 0xffff_ffff, u64::MAX]
                    .into_iter()
                    .map(|value| vec![value])
                    .collect(),
            );
            assert_eq!(
                candidate.code.contains("local_"),
                widened && width != 8,
                "{}",
                candidate.code
            );
            candidates.push(candidate);
        }
    }
    check_candidates("private-return-slots", candidates, Mode::Registers, &[]);
    let escaped = synthetic_ir(
        "escaped_return_slot",
        vec![Param {
            index: 7,
            name: "output".into(),
            ty: CType::pointer_to(CType::U64),
        }],
        CType::U32,
        vec![
            Stmt::Store {
                addr: Expr::reg(7, 64),
                value: slot(-16),
                width: 8,
            },
            Stmt::Store {
                addr: slot(-16),
                value: Expr::Const(19),
                width: 4,
            },
            Stmt::Ret {
                value: Expr::Load {
                    addr: Box::new(slot(-16)),
                    width: 4,
                    signed: false,
                },
            },
        ],
    );
    let code = velk::render::render(&escaped, &[], &Default::default(), &[]);
    assert!(code.contains("local_"), "{code}");
    for isa in ["x86_64", "aarch64"] {
        let mut binary =
            Binary::open(&common::fixtures_dir().join(format!("metrics/float.{isa}.O0.debug.elf")))
                .unwrap();
        let address = binary.find("average").unwrap().addr;
        let code = binary.decompile(address, None, None).unwrap();
        assert!(!code.contains("double result;"), "{code}");
        syntax::run_printed(
            &code,
            "",
            "double values[] = {1.0, 2.0, 3.0}; return average(values, 3) != 2.0 || average(values, 0) != 0.0;",
        );
    }
}

#[test]
fn bounded_sign_extensions_do_not_widen_array_indices() {
    for isa in ["x86_64", "aarch64"] {
        let mut binary = Binary::open(
            &common::fixtures_dir().join(format!("metrics/memory.{isa}.O0.debug.elf")),
        )
        .unwrap();
        let address = binary.find("grid_get").unwrap().addr;
        let code = binary.decompile(address, None, None).unwrap();
        assert!(!code.contains("(int64_t)"), "{code}");
        syntax::run_printed(
            &code,
            "int grid[32];",
            "for (int i = 0; i < 32; ++i) grid[i] = i; for (int row = -16; row < 16; ++row) for (int col = -16; col < 16; ++col) if (grid_get(row, col) != (row & 3) * 8 + (col & 7)) return 1; return 0;",
        );
    }
}

#[test]
fn shifted_structure_offsets_keep_named_fields_and_negative_indices() {
    let mut binary =
        Binary::open(&common::fixtures_dir().join("metrics/struct_arrays.x86_64.O0.debug.elf"))
            .unwrap();
    let address = binary.find("item_last_key").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    assert!(code.contains(".count") && code.contains(".key"), "{code}");
    assert!(!code.contains("(uint8_t *)"), "{code}");
    syntax::run_printed(
        &code,
        "",
        "struct item items[3] = {{.key=7,.count=1},{.key=11,.count=0},{.key=19,.count=1}}; return item_last_key(items,3) != 19 || item_last_key(items,2) != 7;",
    );
    let mut binary =
        Binary::open(&common::fixtures_dir().join("metrics/struct_arrays.x86_64.O2.debug.elf"))
            .unwrap();
    let address = binary.find("item_weight").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    assert!(code.contains(".kind") && code.contains(".count"), "{code}");
    syntax::run_printed(
        &code,
        "",
        "struct item items[3] = {{.count=3,.kind=-2},{.count=5,.kind=7},{.count=-11,.kind=13}}; return item_weight(items+1,-1) != -6 || item_weight(items+1,0) != 35 || item_weight(items+1,1) != -143;",
    );
}

#[test]
fn narrow_loads_keep_their_existing_single_use_substitutions() {
    let temp = velk::ir::VARIABLE_BASE;
    let mut candidates = Vec::new();
    for width in [8, 16] {
        for assigned in [width, 32, 64] {
            let mut ir = synthetic_ir(
                &format!("direct_narrow_load_{width}_{assigned}"),
                vec![Param {
                    index: 7,
                    name: "input".into(),
                    ty: CType::pointer_to(CType::int(width / 8, false)),
                }],
                CType::U64,
                vec![
                    Stmt::Assign {
                        dest: velk::ir::RegRef {
                            index: temp,
                            width: assigned,
                        },
                        value: Expr::Load {
                            addr: Box::new(Expr::reg(7, 64)),
                            width: width / 8,
                            signed: false,
                        },
                    },
                    Stmt::Ret {
                        value: Expr::reg(temp, width),
                    },
                ],
            );
            ir.value_types.insert(temp, CType::int(width / 8, false));
            let mut candidate = printed_candidate(ir.clone(), vec![vec![REGION]]);
            velk::passes::read_once::fold_values_read_once(&mut ir);
            candidate.code = velk::render::render(&ir, &[], &Default::default(), &[]);
            assert!(!candidate.code.contains(" v1"), "{}", candidate.code);
            candidates.push(candidate);
        }
    }
    check_candidates("direct-narrow-loads", candidates, Mode::Memory, &[]);
}

#[test]
fn narrow_values_with_multiple_definitions_keep_their_snapshots() {
    let temp = velk::ir::VARIABLE_BASE;
    let load = |offset| Expr::Load {
        addr: Box::new(Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(offset))),
        width: 1,
        signed: false,
    };
    let mut ir = synthetic_ir(
        "repeated_narrow_value",
        vec![Param {
            index: 7,
            name: "input".into(),
            ty: CType::pointer_to(CType::int(1, false)),
        }],
        CType::U64,
        vec![
            Stmt::Assign {
                dest: velk::ir::RegRef {
                    index: temp,
                    width: 32,
                },
                value: load(0),
            },
            Stmt::Store {
                addr: Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(8)),
                value: Expr::reg(temp, 64),
                width: 1,
            },
            Stmt::Assign {
                dest: velk::ir::RegRef {
                    index: temp,
                    width: 32,
                },
                value: load(1),
            },
            Stmt::Ret {
                value: Expr::reg(temp, 64),
            },
        ],
    );
    ir.value_types.insert(temp, CType::int(1, false));
    let mut candidate = printed_candidate(ir.clone(), vec![vec![REGION]]);
    velk::passes::read_once::fold_values_read_once(&mut ir);
    assert_eq!(ir.blocks[0].stmts.len(), 4);
    candidate.code = velk::render::render(&ir, &[], &Default::default(), &[]);
    assert!(
        candidate
            .code
            .lines()
            .any(|line| line.starts_with("    uint8_t ")),
        "{}",
        candidate.code
    );
    check_candidates("repeated-narrow-value", vec![candidate], Mode::Memory, &[]);
}

#[test]
fn structured_return_copies_preserve_truncation_and_parameter_changes() {
    let temp = velk::ir::VARIABLE_BASE;
    let mut candidates = Vec::new();
    for width in [32, 64] {
        for changed in [false, true] {
            let mut ir = synthetic_ir(
                &format!("return_copy_{width}_{changed}"),
                vec![
                    Param {
                        index: 7,
                        name: "input".into(),
                        ty: CType::int(width / 8, true),
                    },
                    Param {
                        index: 6,
                        name: "flag".into(),
                        ty: CType::U64,
                    },
                ],
                CType::int(width / 8, true),
                vec![
                    Stmt::Assign {
                        dest: velk::ir::RegRef { index: temp, width },
                        value: Expr::reg(7, width),
                    },
                    Stmt::Brif {
                        cond: Cond::Eq,
                        lhs: Expr::reg(6, 64),
                        rhs: Expr::Const(0),
                        target: 2,
                    },
                ],
            );
            let mut body = Vec::new();
            if changed {
                body.push(Stmt::Assign {
                    dest: velk::ir::RegRef { index: 7, width },
                    value: Expr::Const(9),
                });
            }
            body.push(Stmt::Ret {
                value: Expr::bin(
                    BinOp::And,
                    Expr::reg(temp, width),
                    Expr::Const(if width == 32 { 0xffff_ffff } else { u64::MAX }),
                ),
            });
            ir.blocks.push(Block {
                start: 1,
                stmts: body,
            });
            ir.blocks.push(Block {
                start: 2,
                stmts: vec![
                    Stmt::Assign {
                        dest: velk::ir::RegRef { index: temp, width },
                        value: Expr::Const(0),
                    },
                    Stmt::Ret {
                        value: Expr::reg(temp, width),
                    },
                ],
            });
            ir.value_types.insert(temp, CType::int(width / 8, true));
            let candidate = printed_candidate(
                ir,
                [0, 1, 0x7fff_ffff, 0x8000_0000, 1 << 63, u64::MAX]
                    .into_iter()
                    .flat_map(|value| [vec![value, 0], vec![value, 1]])
                    .collect(),
            );
            if !changed {
                assert!(!candidate.code.contains(" v1"), "{}", candidate.code);
            }
            candidates.push(candidate);
        }
    }
    check_candidates("structured-return-copies", candidates, Mode::Registers, &[]);
}

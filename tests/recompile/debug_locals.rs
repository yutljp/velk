use super::*;

fn slot(offset: i64) -> Expr {
    Expr::bin(
        BinOp::Add,
        Expr::reg(velk::arch::stack_pointer(Isa::X86_64), 64),
        Expr::Const(offset as u64),
    )
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
                    ty: CType::int(width, declared_signed),
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

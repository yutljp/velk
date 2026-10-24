use super::*;
use velk::ir::RegRef;

#[test]
fn printed_switch_shared_targets_fallthrough_and_exit() {
    let argument = Convention::SysV.arguments()[0];
    let result = velk::ir::VARIABLE_BASE;
    let assign = |value| Stmt::Assign {
        dest: RegRef {
            index: result,
            width: 64,
        },
        value,
    };
    let jump = |target| Stmt::Br {
        target: Some(target),
    };
    let mut candidates = Vec::new();
    for sparse in [false, true] {
        let values = if sparse {
            [1, 17, 99, 200]
        } else {
            [0, 1, 2, 3]
        };
        let mut ir = synthetic_ir(
            if sparse {
                "sparse_switch_fallthrough"
            } else {
                "dense_switch_fallthrough"
            },
            vec![Param {
                index: argument,
                name: "input".into(),
                ty: CType::U64,
            }],
            CType::U64,
            Vec::new(),
        );
        ir.blocks = vec![
            Block {
                start: 0,
                stmts: vec![
                    assign(Expr::Const(5)),
                    Stmt::Switch {
                        index: Expr::reg(argument, 64),
                        cases: vec![
                            (values[1], 20),
                            (values[0], 10),
                            (values[2], 10),
                            (values[3], 30),
                        ],
                        default: Some(40),
                    },
                ],
            },
            Block {
                start: 10,
                stmts: vec![
                    assign(Expr::Const(7)),
                    Stmt::Brif {
                        cond: Cond::Eq,
                        lhs: Expr::bin(BinOp::And, Expr::reg(argument, 64), Expr::Const(1)),
                        rhs: Expr::Const(0),
                        target: 20,
                    },
                ],
            },
            Block {
                start: 15,
                stmts: vec![jump(50)],
            },
            Block {
                start: 20,
                stmts: vec![
                    assign(Expr::bin(
                        BinOp::Add,
                        Expr::reg(result, 64),
                        Expr::Const(11),
                    )),
                    jump(50),
                ],
            },
            Block {
                start: 30,
                stmts: vec![assign(Expr::Const(19)), jump(50)],
            },
            Block {
                start: 40,
                stmts: vec![assign(Expr::Const(23)), jump(50)],
            },
            Block {
                start: 50,
                stmts: vec![Stmt::Ret {
                    value: Expr::bin(BinOp::Add, Expr::reg(result, 64), Expr::reg(argument, 64)),
                }],
            },
        ];
        for block in ir
            .blocks
            .iter_mut()
            .filter(|block| matches!(block.start, 20 | 50))
        {
            let tail = block.stmts.pop().expect("a terminator");
            block.stmts.extend((1..=8).map(|value| {
                assign(Expr::bin(
                    BinOp::Xor,
                    Expr::reg(result, 64),
                    Expr::bin(BinOp::Add, Expr::reg(argument, 64), Expr::Const(value)),
                ))
            }));
            block.stmts.push(tail);
        }
        let candidate = printed_candidate(
            ir,
            (0..=202)
                .chain([u64::MAX])
                .map(|input| vec![input])
                .collect(),
        );
        assert!(candidate.code.contains("switch ("), "{}", candidate.code);
        assert!(
            candidate.code.contains("/* fallthrough */"),
            "{}",
            candidate.code
        );
        assert!(!candidate.code.contains("goto "), "{}", candidate.code);
        candidates.push(candidate);
    }
    check_candidates("switch-fallthrough", candidates, Mode::Registers, &[]);
}

#[test]
fn printed_switch_default_traps() {
    let argument = Convention::SysV.arguments()[0];
    let mut ir = synthetic_ir(
        "switch_default_trap",
        vec![Param {
            index: argument,
            name: "input".into(),
            ty: CType::U64,
        }],
        CType::U64,
        Vec::new(),
    );
    ir.blocks = vec![
        Block {
            start: 0,
            stmts: vec![Stmt::Switch {
                index: Expr::reg(argument, 64),
                cases: vec![(0, 10), (1, 20), (3, 10)],
                default: Some(30),
            }],
        },
        Block {
            start: 10,
            stmts: vec![Stmt::Ret {
                value: Expr::Const(7),
            }],
        },
        Block {
            start: 20,
            stmts: vec![Stmt::Ret {
                value: Expr::Const(11),
            }],
        },
        Block {
            start: 30,
            stmts: vec![
                Stmt::Call {
                    kind: velk::ir::CallKind::Invoke,
                    target: Some(0x200),
                    through: None,
                    convention: Convention::SysV,
                    args: Some(Vec::new()),
                    floats_named: true,
                    outputs: Vec::new(),
                    clobbers: Some(Default::default()),
                    via: None,
                },
                Stmt::Trap,
            ],
        },
    ];
    let mut candidate = printed_candidate(
        ir,
        (0..6).chain([u64::MAX]).map(|input| vec![input]).collect(),
    );
    assert!(candidate.code.contains("switch ("), "{}", candidate.code);
    assert!(candidate.code.contains("default:"), "{}", candidate.code);
    assert!(!candidate.code.contains("goto "), "{}", candidate.code);
    assert!(candidate.code.contains("sub_200();"), "{}", candidate.code);
    candidate.code = format!(
        "_Noreturn static void sub_200(void) {{ __builtin_trap(); }}\n{}",
        candidate.code
    );
    check_candidates("switch-default-trap", vec![candidate], Mode::Registers, &[]);
}

#[test]
fn printed_nested_switch_in_loop_continues_the_loop() {
    let argument = Convention::SysV.arguments()[0];
    let counter = velk::ir::VARIABLE_BASE;
    let result = counter + 1;
    let assign = |index, value| Stmt::Assign {
        dest: RegRef { index, width: 64 },
        value,
    };
    let jump = || Stmt::Br { target: Some(10) };
    let add = |value| {
        assign(
            result,
            Expr::bin(BinOp::Add, Expr::reg(result, 64), Expr::Const(value)),
        )
    };
    let mut ir = synthetic_ir(
        "nested_switch_loop",
        vec![Param {
            index: argument,
            name: "limit".into(),
            ty: CType::U64,
        }],
        CType::U64,
        Vec::new(),
    );
    ir.blocks = vec![
        Block {
            start: 0,
            stmts: vec![
                assign(counter, Expr::Const(0)),
                assign(result, Expr::Const(0)),
            ],
        },
        Block {
            start: 10,
            stmts: vec![Stmt::Brif {
                cond: Cond::Cs,
                lhs: Expr::reg(counter, 64),
                rhs: Expr::reg(argument, 64),
                target: 100,
            }],
        },
        Block {
            start: 20,
            stmts: vec![
                assign(
                    counter,
                    Expr::bin(BinOp::Add, Expr::reg(counter, 64), Expr::Const(1)),
                ),
                Stmt::Switch {
                    index: Expr::bin(BinOp::And, Expr::reg(counter, 64), Expr::Const(3)),
                    cases: vec![(0, 10), (1, 40), (2, 60)],
                    default: Some(70),
                },
            ],
        },
        Block {
            start: 40,
            stmts: vec![Stmt::Switch {
                index: Expr::bin(BinOp::And, Expr::reg(counter, 64), Expr::Const(4)),
                cases: vec![(0, 50)],
                default: Some(60),
            }],
        },
        Block {
            start: 50,
            stmts: vec![add(3), jump()],
        },
        Block {
            start: 60,
            stmts: vec![add(5), jump()],
        },
        Block {
            start: 70,
            stmts: vec![add(7), jump()],
        },
        Block {
            start: 100,
            stmts: vec![Stmt::Ret {
                value: Expr::reg(result, 64),
            }],
        },
    ];
    let candidate = printed_candidate(ir, (0..40).map(|input| vec![input]).collect());
    assert!(
        candidate.code.matches("switch (").count() >= 2,
        "{}",
        candidate.code
    );
    assert!(candidate.code.contains("continue;"), "{}", candidate.code);
    check_candidates("nested-switch-loop", vec![candidate], Mode::Registers, &[]);
}

#[test]
fn printed_switch_cases_skip_a_tiny_continuation_to_the_shared_exit() {
    let argument = Convention::SysV.arguments()[0];
    let result = velk::ir::VARIABLE_BASE;
    let assign = |value| Stmt::Assign {
        dest: RegRef {
            index: result,
            width: 64,
        },
        value,
    };
    let jump = |target| Stmt::Br {
        target: Some(target),
    };
    let mut ir = synthetic_ir(
        "switch_shared_exit",
        vec![Param {
            index: argument,
            name: "input".into(),
            ty: CType::U64,
        }],
        CType::U64,
        Vec::new(),
    );
    ir.blocks = vec![
        Block {
            start: 0,
            stmts: vec![
                assign(Expr::Const(5)),
                Stmt::Switch {
                    index: Expr::reg(argument, 64),
                    cases: vec![(0, 10), (1, 20)],
                    default: Some(90),
                },
            ],
        },
        Block {
            start: 10,
            stmts: vec![assign(Expr::Const(7)), jump(60)],
        },
        Block {
            start: 20,
            stmts: vec![assign(Expr::Const(11)), jump(60)],
        },
        Block {
            start: 60,
            stmts: vec![
                assign(Expr::bin(BinOp::Add, Expr::reg(result, 64), Expr::Const(5))),
                jump(90),
            ],
        },
        Block {
            start: 90,
            stmts: (1..=8)
                .map(|value| {
                    assign(Expr::bin(
                        BinOp::Xor,
                        Expr::reg(result, 64),
                        Expr::bin(BinOp::Add, Expr::reg(argument, 64), Expr::Const(value)),
                    ))
                })
                .chain([Stmt::Ret {
                    value: Expr::reg(result, 64),
                }])
                .collect(),
        },
    ];
    let candidate = printed_candidate(
        ir,
        (0..6).chain([u64::MAX]).map(|input| vec![input]).collect(),
    );
    assert!(candidate.code.contains("switch ("), "{}", candidate.code);
    assert!(!candidate.code.contains("goto "), "{}", candidate.code);
    assert_eq!(candidate.code.matches('^').count(), 8, "{}", candidate.code);
    check_candidates("switch-shared-exit", vec![candidate], Mode::Registers, &[]);
}

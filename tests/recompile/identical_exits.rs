use super::*;
use velk::ir::RegRef;

#[test]
fn printed_terminal_guards_keep_error_payloads_and_short_circuit_reads() {
    let arguments = Convention::SysV.arguments();
    let pointer = Expr::reg(arguments[0], 64);
    let input = Expr::reg(arguments[1], 64);
    let mut candidates = Vec::new();
    for different in [false, true] {
        let mut ir = synthetic_ir(
            "terminal_error_guards",
            vec![
                Param {
                    index: arguments[0],
                    name: "pointer".into(),
                    ty: CType::pointer_to(CType::U64),
                },
                Param {
                    index: arguments[1],
                    name: "input".into(),
                    ty: CType::U64,
                },
            ],
            CType::U64,
            Vec::new(),
        );
        ir.blocks = vec![
            Block {
                start: 0,
                stmts: vec![
                    Stmt::Store {
                        addr: pointer.clone(),
                        value: Expr::bin(BinOp::And, input.clone(), Expr::Const(1)),
                        width: 8,
                    },
                    Stmt::Brif {
                        cond: Cond::Eq,
                        lhs: input.clone(),
                        rhs: Expr::Const(0),
                        target: 30,
                    },
                ],
            },
            Block {
                start: 10,
                stmts: vec![Stmt::Brif {
                    cond: Cond::Eq,
                    lhs: Expr::Load {
                        addr: Box::new(pointer.clone()),
                        width: 8,
                        signed: false,
                    },
                    rhs: Expr::Const(0),
                    target: 40,
                }],
            },
            Block {
                start: 20,
                stmts: vec![Stmt::Ret {
                    value: Expr::Const(0),
                }],
            },
        ];
        for (start, error) in [(30, 19), (40, if different { 20 } else { 19 })] {
            ir.blocks.push(Block {
                start,
                stmts: vec![
                    Stmt::Store {
                        addr: pointer.clone(),
                        value: input.clone(),
                        width: 8,
                    },
                    Stmt::Store {
                        addr: Expr::bin(BinOp::Add, pointer.clone(), Expr::Const(8)),
                        value: Expr::Const(error),
                        width: 8,
                    },
                    Stmt::Ret {
                        value: Expr::Const(error),
                    },
                ],
            });
        }
        let candidate = printed_candidate(
            ir,
            [0, 1, 2, u64::MAX]
                .map(|input| vec![REGION, input])
                .to_vec(),
        );
        if !different {
            assert!(candidate.code.contains(" || "), "{}", candidate.code);
            assert_eq!(
                candidate.code.matches("pointer[1] = 19;").count(),
                1,
                "{}",
                candidate.code
            );
            assert_eq!(
                common::check_expected(
                    &common::root().join("tests/golden/terminal_error_guards.txt"),
                    &candidate.code,
                ),
                None,
            );
        }
        candidates.push(candidate);
    }
    check_candidates("terminal-error-guards", candidates, Mode::Memory, &[]);
}

#[test]
fn printed_identical_exits_preserve_constants_and_store_order() {
    let arguments = Convention::SysV.arguments();
    let variable = velk::ir::VARIABLE_BASE;
    let pointer = Expr::reg(arguments[0], 64);
    let input = Expr::reg(arguments[1], 64);
    let load = Expr::Load {
        addr: Box::new(pointer.clone()),
        width: 8,
        signed: false,
    };
    let assign = |value| Stmt::Assign {
        dest: RegRef {
            index: variable,
            width: 64,
        },
        value: Expr::Const(value),
    };
    for memory in [false, true] {
        let mut ir = synthetic_ir(
            if memory {
                "identical_store_exits"
            } else {
                "identical_error_exits"
            },
            vec![
                Param {
                    index: arguments[0],
                    name: "pointer".into(),
                    ty: if memory {
                        CType::pointer_to(CType::U64)
                    } else {
                        CType::U64
                    },
                },
                Param {
                    index: arguments[1],
                    name: "input".into(),
                    ty: CType::U64,
                },
            ],
            CType::U64,
            Vec::new(),
        );
        ir.blocks.push(Block {
            start: 0,
            stmts: vec![Stmt::Switch {
                index: input.clone(),
                cases: vec![(0, 10), (1, 20), (2, 30)],
                default: Some(40),
            }],
        });
        for (start, code) in [(10, 19), (20, 19), (30, 19), (40, 20)] {
            let mut stmts = Vec::new();
            if memory {
                stmts.push(Stmt::Store {
                    addr: pointer.clone(),
                    width: 8,
                    value: Expr::bin(BinOp::Add, load.clone(), Expr::Const(start)),
                });
            }
            stmts.push(assign(code));
            if memory {
                // Two dependent writes must happen once, in this order.
                for (op, constant) in [(BinOp::Add, 1), (BinOp::Mul, 3)] {
                    stmts.push(Stmt::Store {
                        addr: pointer.clone(),
                        width: 8,
                        value: Expr::bin(op, load.clone(), Expr::Const(constant)),
                    });
                }
            }
            stmts.push(Stmt::Br { target: Some(100) });
            ir.blocks.push(Block { start, stmts });
        }
        ir.blocks.push(Block {
            start: 100,
            stmts: vec![Stmt::Ret {
                value: Expr::bin(
                    BinOp::Add,
                    Expr::reg(variable, 64),
                    if memory { load.clone() } else { Expr::Const(0) },
                ),
            }],
        });
        let candidate = printed_candidate(
            ir,
            (0..6)
                .map(|input| vec![if memory { REGION } else { 0 }, input])
                .collect(),
        );
        assert!(candidate.code.contains("19"), "{}", candidate.code);
        assert!(candidate.code.contains("20"), "{}", candidate.code);
        if memory {
            assert_eq!(
                candidate.code.matches("*pointer += 1;").count(),
                1,
                "{}",
                candidate.code
            );
            assert_eq!(
                candidate.code.matches("*pointer *= 3;").count(),
                1,
                "{}",
                candidate.code
            );
        } else {
            assert_eq!(
                candidate.code.matches("19;").count(),
                1,
                "{}",
                candidate.code
            );
        }
        check_candidates(
            "identical-exits",
            vec![candidate],
            if memory {
                Mode::Memory
            } else {
                Mode::Registers
            },
            &[],
        );
    }
}

#[test]
fn shared_width_errors_preserve_cursor_and_truncation() {
    let arguments = Convention::SysV.arguments();
    let variable = velk::ir::VARIABLE_BASE;
    let pointer = Expr::reg(arguments[0], 64);
    let width = Expr::reg(arguments[1], 64);
    let length = Expr::reg(arguments[2], 64);
    let assign = |index, value| Stmt::Assign {
        dest: RegRef { index, width: 64 },
        value,
    };
    let mut ir = synthetic_ir(
        "width_errors",
        vec![
            Param {
                index: arguments[0],
                name: "cursor".into(),
                ty: CType::pointer_to(CType::U64),
            },
            Param {
                index: arguments[1],
                name: "width".into(),
                ty: CType::U64,
            },
            Param {
                index: arguments[2],
                name: "length".into(),
                ty: CType::U64,
            },
        ],
        CType::U64,
        Vec::new(),
    );
    ir.blocks.clear();
    ir.blocks.push(Block {
        start: 0,
        stmts: vec![Stmt::Switch {
            index: width,
            cases: vec![(1, 10), (2, 20), (4, 30), (8, 40)],
            default: Some(50),
        }],
    });
    for (start, bytes) in [(10, 1), (20, 2), (30, 4), (40, 8), (50, 255)] {
        ir.blocks.push(Block {
            start,
            stmts: vec![
                assign(variable, Expr::Const(19)),
                assign(variable + 1, Expr::Const(bytes)),
                Stmt::Br { target: Some(100) },
            ],
        });
    }
    ir.blocks.push(Block {
        start: 100,
        stmts: vec![Stmt::Brif {
            cond: Cond::Cc,
            lhs: length,
            rhs: Expr::reg(variable + 1, 64),
            target: 200,
        }],
    });
    ir.blocks.push(Block {
        start: 110,
        stmts: vec![
            Stmt::Store {
                addr: pointer.clone(),
                value: Expr::reg(variable + 1, 64),
                width: 8,
            },
            Stmt::Ret {
                value: Expr::Const(0),
            },
        ],
    });
    ir.blocks.push(Block {
        start: 200,
        stmts: vec![
            Stmt::Store {
                addr: pointer,
                value: Expr::reg(variable + 1, 64),
                width: 8,
            },
            Stmt::Ret {
                value: Expr::reg(variable, 64),
            },
        ],
    });
    let inputs = [0, 1, 2, 4, 8, 255]
        .into_iter()
        .flat_map(|width| {
            [0, 1, 2, 3, 4, 7, 8, 9, u64::MAX]
                .into_iter()
                .map(move |length| vec![REGION, width, length])
        })
        .collect();
    let candidate = printed_candidate(ir, inputs);
    assert_eq!(
        candidate.code.matches("19;").count(),
        1,
        "{}",
        candidate.code
    );
    check_candidates("width-errors", vec![candidate], Mode::Memory, &[]);
}

#[test]
fn shared_prefix_preserves_branch_input() {
    let argument = Convention::SysV.arguments()[0];
    let variable = velk::ir::VARIABLE_BASE;
    for destination in [variable, argument] {
        let mut ir = synthetic_ir(
            "shared_prefix",
            vec![Param {
                index: argument,
                name: "input".into(),
                ty: CType::U64,
            }],
            CType::U64,
            Vec::new(),
        );
        ir.blocks.clear();
        ir.blocks.push(Block {
            start: 0,
            stmts: vec![Stmt::Brif {
                cond: Cond::Eq,
                lhs: Expr::reg(argument, 64),
                rhs: Expr::Const(0),
                target: 20,
            }],
        });
        for (start, add) in [(10, 1), (20, 2)] {
            ir.blocks.push(Block {
                start,
                stmts: vec![
                    Stmt::Assign {
                        dest: RegRef {
                            index: destination,
                            width: 64,
                        },
                        value: Expr::Const(19),
                    },
                    Stmt::Ret {
                        value: Expr::bin(BinOp::Add, Expr::reg(destination, 64), Expr::Const(add)),
                    },
                ],
            });
        }
        let candidate = printed_candidate(
            ir,
            [0, 1, 2, u64::MAX].into_iter().map(|n| vec![n]).collect(),
        );
        assert!(candidate.code.contains("19"), "{}", candidate.code);
        if destination == variable {
            assert_eq!(
                candidate.code.matches("19;").count(),
                1,
                "{}",
                candidate.code
            );
        }
        check_candidates("shared-prefix", vec![candidate], Mode::Registers, &[]);
    }
}

#[test]
fn shared_decoder_errors_preserve_all_switch_exits_and_cursor() {
    let arguments = Convention::SysV.arguments();
    let error = velk::ir::VARIABLE_BASE;
    let detail = error + 1;
    let pointer = Expr::reg(arguments[0], 64);
    let mut ir = synthetic_ir(
        "shared_decoder_error",
        vec![
            Param {
                index: arguments[0],
                name: "cursor".into(),
                ty: CType::pointer_to(CType::U64),
            },
            Param {
                index: arguments[1],
                name: "width".into(),
                ty: CType::U64,
            },
            Param {
                index: arguments[2],
                name: "length".into(),
                ty: CType::U64,
            },
        ],
        CType::U64,
        Vec::new(),
    );
    let assign = |index, value| Stmt::Assign {
        dest: RegRef { index, width: 64 },
        value: Expr::Const(value),
    };
    ir.blocks = vec![Block {
        start: 0,
        stmts: vec![Stmt::Switch {
            index: Expr::reg(arguments[1], 64),
            cases: vec![(1, 10), (2, 20), (4, 30), (8, 40)],
            default: Some(50),
        }],
    }];
    for (start, bytes) in [(10, 1), (20, 2), (30, 4), (40, 8)] {
        ir.blocks.push(Block {
            start,
            stmts: vec![Stmt::Brif {
                cond: Cond::Cc,
                lhs: Expr::reg(arguments[2], 64),
                rhs: Expr::Const(bytes),
                target: 100,
            }],
        });
        ir.blocks.push(Block {
            start: start + 1,
            stmts: vec![
                Stmt::Store {
                    addr: pointer.clone(),
                    value: Expr::Const(bytes),
                    width: 8,
                },
                Stmt::Ret {
                    value: Expr::Const(0),
                },
            ],
        });
    }
    ir.blocks.push(Block {
        start: 50,
        stmts: vec![
            assign(error, 20),
            assign(detail, 255),
            Stmt::Br { target: Some(200) },
        ],
    });
    ir.blocks.push(Block {
        start: 100,
        stmts: vec![
            assign(error, 19),
            assign(detail, 0),
            Stmt::Br { target: Some(200) },
        ],
    });
    ir.blocks.push(Block {
        start: 200,
        stmts: vec![
            Stmt::Store {
                addr: pointer,
                value: Expr::reg(detail, 64),
                width: 8,
            },
            Stmt::Ret {
                value: Expr::reg(error, 64),
            },
        ],
    });
    let inputs = [0, 1, 2, 4, 8, 255]
        .into_iter()
        .flat_map(|width| {
            [0, 1, 2, 3, 4, 7, 8, 9, u64::MAX]
                .into_iter()
                .map(move |length| vec![REGION, width, length])
        })
        .collect();
    let candidate = printed_candidate(ir, inputs);
    assert_eq!(
        candidate.code.matches("19;").count(),
        1,
        "{}",
        candidate.code
    );
    check_candidates("shared-decoder-error", vec![candidate], Mode::Memory, &[]);
}

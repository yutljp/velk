use super::*;
use velk::ir::RegRef;

#[test]
fn printed_forward_exits_preserve_loop_tests_and_shared_stores() {
    let counter = velk::ir::VARIABLE_BASE;
    let value = Expr::reg(counter, 64);
    let branch = |target| Stmt::Br {
        target: Some(target),
    };
    let assign = |value| Stmt::Assign {
        dest: RegRef {
            index: counter,
            width: 64,
        },
        value,
    };
    let test = |cond, lhs, rhs, target| Stmt::Brif {
        cond,
        lhs,
        rhs,
        target,
    };
    let mut candidates = Vec::new();
    for bottom_test in [false, true] {
        let mut blocks = vec![Block {
            start: 0,
            stmts: vec![
                sc_store(SC_COUNTER, Expr::Const(0)),
                sc_store(SC_COUNTER + 8, Expr::Const(0)),
                assign(Expr::Const(0)),
                test(Cond::Eq, Expr::reg(7, 64), Expr::Const(u64::MAX), 80),
            ],
        }];
        let mut iteration = vec![
            sc_store(
                SC_COUNTER,
                Expr::bin(BinOp::Add, sc_load(SC_COUNTER), Expr::Const(1)),
            ),
            test(Cond::Eq, value.clone(), Expr::reg(6, 64), 80),
        ];
        let mut step = vec![assign(Expr::bin(BinOp::Add, value.clone(), Expr::Const(1)))];
        let count_test = sc_store(
            SC_COUNTER + 8,
            Expr::bin(BinOp::Add, sc_load(SC_COUNTER + 8), Expr::Const(1)),
        );
        if bottom_test {
            blocks.push(Block {
                start: 10,
                stmts: iteration,
            });
            step.push(count_test);
            step.push(test(Cond::Cc, value.clone(), Expr::reg(7, 64), 10));
        } else {
            blocks.push(Block {
                start: 10,
                stmts: vec![
                    count_test,
                    test(Cond::Cs, value.clone(), Expr::reg(7, 64), 40),
                ],
            });
            blocks.push(Block {
                start: 20,
                stmts: std::mem::take(&mut iteration),
            });
            step.push(branch(10));
        }
        blocks.push(Block {
            start: 30,
            stmts: step,
        });
        for (start, constant) in [(40, 0x123456789), (80, 0x987654321)] {
            let mut tail = Vec::new();
            for offset in 0..8 {
                tail.push(sc_store(
                    SC_RIGHT + offset * 8,
                    Expr::Const(constant + offset),
                ));
            }
            tail.push(Stmt::Ret {
                value: sc_load(SC_COUNTER),
            });
            blocks.push(Block { start, stmts: tail });
        }
        let ir = sc_ir(
            if bottom_test {
                "bottom_exit"
            } else {
                "top_exit"
            },
            vec![CType::U64; 2],
            blocks,
        );
        let inputs = [0, 1, 2, 5, u64::MAX]
            .into_iter()
            .flat_map(|limit| [0, 1, 3, 9].map(|stop| vec![limit, stop]))
            .collect();
        let candidate = printed_candidate(ir, inputs);
        assert_eq!(
            candidate.code.matches("0x123456789").count(),
            1,
            "{}",
            candidate.code
        );
        assert_eq!(
            candidate.code.matches("0x987654321").count(),
            1,
            "{}",
            candidate.code
        );
        candidates.push(candidate);
    }
    check_candidates("forward-exit-loops", candidates, Mode::Memory, &[]);
}

#[test]
fn printed_forward_exit_preserves_values_from_another_entry() {
    let arguments = Convention::SysV.arguments();
    let variable = velk::ir::VARIABLE_BASE;
    let assign = |value| Stmt::Assign {
        dest: RegRef {
            index: variable,
            width: 64,
        },
        value,
    };
    let test = |constant, target| Stmt::Brif {
        cond: Cond::Eq,
        lhs: Expr::reg(arguments[0], 64),
        rhs: Expr::Const(constant),
        target,
    };
    let branch = || Stmt::Br { target: Some(50) };
    let mut ir = synthetic_ir(
        "forward_exit_external_entry",
        vec![
            Param {
                index: arguments[0],
                name: "path".into(),
                ty: CType::U64,
            },
            Param {
                index: arguments[1],
                name: "value".into(),
                ty: CType::U64,
            },
        ],
        CType::U64,
        Vec::new(),
    );
    ir.blocks = vec![
        Block {
            start: 0,
            stmts: vec![assign(Expr::reg(arguments[1], 64)), test(0, 30)],
        },
        Block {
            start: 10,
            stmts: vec![assign(Expr::Const(7)), test(1, 50)],
        },
        Block {
            start: 20,
            stmts: vec![assign(Expr::Const(9)), branch()],
        },
        Block {
            start: 30,
            stmts: vec![branch()],
        },
        Block {
            start: 50,
            stmts: vec![Stmt::Ret {
                value: Expr::reg(variable, 64),
            }],
        },
    ];
    let inputs = (0..5)
        .flat_map(|path| [0, 1, 7, 9, u64::MAX].map(|value| vec![path, value]))
        .collect();
    check_candidates(
        "forward-exit-external-entry",
        vec![printed_candidate(ir, inputs)],
        Mode::Registers,
        &[],
    );
}

#[test]
fn printed_shared_return_tail_preserves_stores() {
    let arguments = Convention::SysV.arguments();
    let pointer = Expr::reg(arguments[0], 64);
    let input = Expr::reg(arguments[1], 64);
    let load = Expr::Load {
        addr: Box::new(pointer.clone()),
        width: 8,
        signed: false,
    };
    let test = |constant, target| Stmt::Brif {
        cond: Cond::Eq,
        lhs: input.clone(),
        rhs: Expr::Const(constant),
        target,
    };
    let store = |increment| Stmt::Store {
        addr: pointer.clone(),
        width: 8,
        value: Expr::bin(BinOp::Add, load.clone(), Expr::Const(increment)),
    };
    let mut ir = synthetic_ir(
        "shared_return_stores",
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
            stmts: vec![test(0, 100)],
        },
        Block {
            start: 10,
            stmts: vec![test(1, 100)],
        },
        Block {
            start: 20,
            stmts: vec![store(10), Stmt::Br { target: Some(100) }],
        },
        Block {
            start: 100,
            stmts: vec![test(2, 130)],
        },
        Block {
            start: 110,
            stmts: vec![store(1), Stmt::Ret { value: load }],
        },
        Block {
            start: 130,
            stmts: vec![Stmt::Ret {
                value: Expr::Const(99),
            }],
        },
    ];
    let candidate = printed_candidate(ir, (0..5).map(|input| vec![REGION, input]).collect());
    assert!(!candidate.code.contains("goto "), "{}", candidate.code);
    check_candidates("shared-return-stores", vec![candidate], Mode::Memory, &[]);
}

#[test]
fn printed_forward_exits_and_shared_conditional_returns() {
    let argument = Convention::SysV.arguments()[0];
    let value = Expr::reg(argument, 64);
    let branch = |target| Stmt::Br {
        target: Some(target),
    };
    let test = |constant, target| Stmt::Brif {
        cond: Cond::Eq,
        lhs: value.clone(),
        rhs: Expr::Const(constant),
        target,
    };
    let mut candidates = Vec::new();
    for nested in [false, true] {
        let mut ir = synthetic_ir(
            if nested {
                "shared_conditional_return"
            } else {
                "forward_exit"
            },
            vec![Param {
                index: argument,
                name: "input".into(),
                ty: CType::U64,
            }],
            CType::U64,
            Vec::new(),
        );
        let set = |constant| Stmt::Assign {
            dest: RegRef {
                index: 0,
                width: 64,
            },
            value: Expr::Const(constant),
        };
        ir.blocks = vec![
            Block {
                start: 0,
                stmts: vec![test(0, 40)],
            },
            Block {
                start: 10,
                stmts: vec![test(1, 40)],
            },
            Block {
                start: 20,
                stmts: vec![set(7), test(2, 50)],
            },
            Block {
                start: 30,
                stmts: vec![set(11), branch(50)],
            },
            Block {
                start: 40,
                stmts: vec![set(13), branch(50)],
            },
            Block {
                start: 50,
                stmts: if nested {
                    vec![test(3, 70)]
                } else {
                    vec![Stmt::Ret {
                        value: Expr::bin(BinOp::Add, Expr::reg(0, 64), value.clone()),
                    }]
                },
            },
        ];
        if nested {
            ir.blocks.extend([
                Block {
                    start: 60,
                    stmts: vec![Stmt::Ret {
                        value: Expr::reg(0, 64),
                    }],
                },
                Block {
                    start: 70,
                    stmts: vec![Stmt::Ret {
                        value: Expr::Const(19),
                    }],
                },
            ]);
        }
        let candidate = printed_candidate(
            ir,
            vec![vec![0], vec![1], vec![2], vec![3], vec![4], vec![u64::MAX]],
        );
        assert!(!candidate.code.contains("goto "), "{}", candidate.code);
        candidates.push(candidate);
    }
    check_candidates("forward-exits", candidates, Mode::Registers, &[]);
}

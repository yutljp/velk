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
                    abi: None,
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

#[test]
fn printed_switch_identical_bodies_at_distinct_targets() {
    let mut candidates = Vec::new();
    for (isa, convention) in [
        (Isa::X86_64, Convention::SysV),
        (Isa::AArch64, Convention::Aapcs64),
    ] {
        for chained in [false, true] {
            for width in [32, 64] {
                let argument = convention.arguments()[0];
                let mut ir = synthetic_ir(
                    &format!("shared_cases_{isa:?}_{chained}_{width}"),
                    vec![Param {
                        index: argument,
                        name: "input".into(),
                        ty: CType::U64,
                    }],
                    CType::U64,
                    Vec::new(),
                );
                ir.isa = isa;
                ir.convention = convention;
                let index = Expr::reg(argument, width);
                let cases = [(1, 100), (17, 110), (99, 120), (200, 130)];
                ir.blocks = if chained {
                    cases
                        .iter()
                        .enumerate()
                        .map(|(position, (value, target))| Block {
                            start: position as u64 * 10,
                            stmts: vec![Stmt::Brif {
                                cond: Cond::Eq,
                                lhs: index.clone(),
                                rhs: Expr::Const(*value as u64),
                                target: *target,
                            }],
                        })
                        .collect()
                } else {
                    vec![Block {
                        start: 0,
                        stmts: vec![Stmt::Switch {
                            index,
                            cases: cases.to_vec(),
                            default: Some(40),
                        }],
                    }]
                };
                for (start, value) in [(40, 89), (100, 77), (110, 77), (120, 83), (130, 77)] {
                    ir.blocks.push(Block {
                        start,
                        stmts: vec![Stmt::Ret {
                            value: Expr::Const(value),
                        }],
                    });
                }
                let inputs = (0..=202)
                    .chain([u64::MAX, 1 << 32, (1 << 32) + 17, 1 << 63])
                    .map(|input| vec![input])
                    .collect();
                let candidate = printed_candidate(ir, inputs);
                assert!(candidate.code.contains("switch ("), "{}", candidate.code);
                assert_eq!(
                    candidate.code.matches("return 77;").count(),
                    1,
                    "{}",
                    candidate.code
                );
                assert!(!candidate.code.contains("goto "), "{}", candidate.code);
                candidates.push(candidate);
            }
        }
    }
    check_candidates("switch-identical-bodies", candidates, Mode::Registers, &[]);
}

#[test]
fn printed_switch_shared_tails_preserve_store_order_and_default() {
    let mut candidates = Vec::new();
    for (isa, convention) in [
        (Isa::X86_64, Convention::SysV),
        (Isa::AArch64, Convention::Aapcs64),
    ] {
        for shared_default in [false, true] {
            let arguments = convention.arguments();
            let pointer = Expr::reg(arguments[0], 64);
            let load = Expr::Load {
                addr: Box::new(pointer.clone()),
                width: 8,
                signed: false,
            };
            let store = |op, value| Stmt::Store {
                addr: pointer.clone(),
                width: 8,
                value: Expr::bin(op, load.clone(), Expr::Const(value)),
            };
            let mut ir = synthetic_ir(
                &format!("shared_tail_{isa:?}_{shared_default}"),
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
            ir.isa = isa;
            ir.convention = convention;
            ir.blocks = vec![Block {
                start: 0,
                stmts: vec![Stmt::Switch {
                    index: Expr::reg(arguments[1], 64),
                    cases: vec![(0, 100), (1, 110), (2, 120)],
                    default: Some(130),
                }],
            }];
            for (start, prefix) in [(100, 2), (110, 1), (120, 0), (130, 0)] {
                let mut stmts = Vec::new();
                if start == 130 && !shared_default {
                    stmts.push(store(BinOp::Xor, 91));
                } else {
                    if prefix == 2 {
                        stmts.push(store(BinOp::Xor, 7));
                    }
                    if prefix >= 1 {
                        stmts.push(store(BinOp::Add, 13));
                    }
                    stmts.push(store(BinOp::Mul, 3));
                }
                stmts.push(Stmt::Ret {
                    value: load.clone(),
                });
                ir.blocks.push(Block { start, stmts });
            }
            let candidate = printed_candidate(
                ir,
                (0..6)
                    .chain([u64::MAX, 1 << 32, 1 << 63])
                    .map(|input| vec![REGION, input])
                    .collect(),
            );
            assert!(candidate.code.contains("switch ("), "{}", candidate.code);
            assert!(
                candidate.code.contains("/* fallthrough */"),
                "{}",
                candidate.code
            );
            assert_eq!(
                candidate.code.matches("*pointer *= 3;").count(),
                1,
                "{}",
                candidate.code
            );
            assert!(!candidate.code.contains("goto "), "{}", candidate.code);
            candidates.push(candidate);
        }
    }
    check_candidates("switch-shared-store-tails", candidates, Mode::Memory, &[]);
}

#[test]
fn printed_switch_prefixes_preserve_bounds_width_and_store_order() {
    let mut candidates = Vec::new();
    for (isa, convention) in [
        (Isa::X86_64, Convention::SysV),
        (Isa::AArch64, Convention::Aapcs64),
    ] {
        for width in [32, 64] {
            for variant in 0..4 {
                let write_index = variant == 1;
                let arguments = convention.arguments();
                let pointer = Expr::reg(arguments[0], 64);
                let load = Expr::Load {
                    addr: Box::new(pointer.clone()),
                    width: 8,
                    signed: false,
                };
                let mut ir = synthetic_ir(
                    &format!("shared_prefix_{isa:?}_{width}_{variant}"),
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
                ir.isa = isa;
                ir.convention = convention;
                ir.blocks = vec![Block {
                    start: 0,
                    stmts: vec![Stmt::Switch {
                        index: Expr::reg(arguments[1], width),
                        cases: (0..10)
                            .map(|value| {
                                (
                                    value + i64::from(variant == 2 && value >= 5),
                                    100 + value as u64 * 10,
                                )
                            })
                            .collect(),
                        default: Some(if variant == 3 { 250 } else { 300 }),
                    }],
                }];
                for value in 0..10 {
                    let mut stmts: Vec<_> = (0..=value)
                        .map(|step| Stmt::Store {
                            addr: pointer.clone(),
                            width: 8,
                            value: Expr::bin(
                                if step % 2 == 0 {
                                    BinOp::Add
                                } else {
                                    BinOp::Mul
                                },
                                load.clone(),
                                Expr::Const(step + 3),
                            ),
                        })
                        .collect();
                    if write_index {
                        stmts.insert(
                            0,
                            Stmt::Assign {
                                dest: RegRef {
                                    index: arguments[1],
                                    width: 64,
                                },
                                value: Expr::bin(
                                    BinOp::Add,
                                    Expr::reg(arguments[1], 64),
                                    Expr::Const(3),
                                ),
                            },
                        );
                    }
                    stmts.push(Stmt::Br { target: Some(300) });
                    ir.blocks.push(Block {
                        start: 100 + value * 10,
                        stmts,
                    });
                }
                if variant == 3 {
                    ir.blocks.push(Block {
                        start: 250,
                        stmts: vec![
                            Stmt::Store {
                                addr: pointer.clone(),
                                width: 8,
                                value: Expr::bin(BinOp::Xor, load.clone(), Expr::Const(47)),
                            },
                            Stmt::Br { target: Some(300) },
                        ],
                    });
                }
                ir.blocks.push(Block {
                    start: 300,
                    stmts: (100..108)
                        .map(|value| Stmt::Store {
                            addr: pointer.clone(),
                            width: 8,
                            value: Expr::bin(BinOp::Xor, load.clone(), Expr::Const(value)),
                        })
                        .chain([Stmt::Ret {
                            value: Expr::bin(BinOp::Add, load.clone(), Expr::reg(arguments[1], 64)),
                        }])
                        .collect(),
                });
                let candidate = printed_candidate(
                    ir,
                    (0..=11)
                        .chain([u64::MAX, 1 << 32, (1 << 32) + 9, 1 << 63])
                        .map(|input| vec![REGION, input])
                        .collect(),
                );
                assert_eq!(
                    candidate.code.matches("*pointer += 3;").count(),
                    if variant == 0 { 1 } else { 10 },
                    "{}",
                    candidate.code
                );
                assert_eq!(
                    candidate.code.contains("switch ("),
                    variant != 0,
                    "{}",
                    candidate.code
                );
                assert!(!candidate.code.contains("goto "), "{}", candidate.code);
                candidates.push(candidate);
            }
        }
    }
    check_candidates("switch-shared-prefixes", candidates, Mode::Memory, &[]);
}

#[test]
fn printed_inline_jump_table_bytes_do_not_become_stack_operations() {
    let scratch = scratch_dir("inline-jump-table");
    let assembly = scratch.join("switch.s");
    let object = scratch.join("switch.o");
    std::fs::write(
        &assembly,
        ".text\n.globl inline_switch\n.type inline_switch,@function\ninline_switch:\ncmpq $1,%rdi\nja .Ldefault\nleaq .Ltable(%rip),%rdx\nmovslq (%rdx,%rdi,4),%rax\naddq %rdx,%rax\njmpq *%rax\n.Ldefault:\nmovl $44,%eax\nret\n.Ltable:\n.long .Lzero-.Ltable\n.long .Lone-.Ltable\n.fill 0x52-(.-.Ltable),1,0x90\n.Lzero:\nmovl $11,%eax\nret\n.Lone:\nmovl $22,%eax\nret\n.size inline_switch,.-inline_switch\n",
    )
    .unwrap();
    let compiled = Command::new(compiler())
        .args(["--target=x86_64-unknown-linux-gnu", "-c"])
        .arg(&assembly)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{compiled:?}");
    let mut binary = Binary::open(&object).unwrap();
    let address = binary.find("inline_switch").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    assert!(!code.contains("unsupported"), "{code}");
    assert!(!code.contains("velk_entry_stack_pointer"), "{code}");
    syntax::run_printed(
        &code,
        "",
        "if(inline_switch(0)!=11 || inline_switch(1)!=22 || inline_switch(2)!=44 || inline_switch(UINT64_MAX)!=44) return 1;",
    );
    std::fs::remove_dir_all(scratch).ok();
}

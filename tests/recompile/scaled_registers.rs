use super::*;

#[test]
fn scaled_stack_values_do_not_leave_unused_frame_stores() {
    let path = common::fixtures_dir().join("metrics/l6_abi.win64.O0.debug.dll");
    let mut binary = Binary::open(&path).unwrap();
    let address = binary.find("tail_target").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    assert!(code.contains("return (uint32_t)x * 3 + 1;"), "{code}");
    assert!(!code.contains("local_"), "{code}");
    syntax::run_printed(
        &code,
        "",
        "for (int x = -100; x <= 100; ++x) if (tail_target(x) != x * 3 + 1) __builtin_trap();",
    );
}

#[test]
fn scaled_quotients_still_render_as_remainders() {
    for (fixture, function) in [
        ("arm64_div.o", "lmod3"),
        ("x64_div.o", "smod3x"),
        ("x64_div.o", "umod3x"),
    ] {
        let mut binary = Binary::open(&common::fixtures_dir().join(fixture)).unwrap();
        let address = binary.find(function).unwrap().addr;
        let code = binary.decompile(address, None, None).unwrap();
        assert!(code.contains("return a0 % 3;"), "{code}");
        let assertions = [i64::MIN, -100, -3, -1, 0, 1, 3, 100, i64::MAX]
            .into_iter()
            .map(|x| {
                let expected = match function {
                    "lmod3" => x % 3,
                    "smod3x" => i64::from((x as i32) % 3),
                    _ => i64::from((x as u32) % 3),
                };
                format!(
                    "if ({function}((int64_t)UINT64_C({})) != {expected}) __builtin_trap();",
                    x as u64
                )
            })
            .collect::<String>();
        syntax::run_printed(&code, "", &assertions);
    }
}

#[test]
fn scaled_register_sums_preserve_wrapping_and_comparison_widths() {
    let mut candidates = Vec::new();
    let inputs: Vec<_> = [
        0,
        1,
        127,
        128,
        255,
        256,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_ffff,
        0x8000_0000_0000_0000,
        u64::MAX,
    ]
    .into_iter()
    .map(|x| vec![x])
    .collect();
    for width in [8, 16, 32, 64] {
        let x = Expr::reg(7, width);
        let scale = |factor| Expr::bin(BinOp::Mul, x.clone(), Expr::Const(factor));
        for (case, value) in [
            ("sum", Expr::bin(BinOp::Add, x.clone(), scale(2))),
            ("reversed", Expr::bin(BinOp::Add, scale(2), x.clone())),
            ("difference", Expr::bin(BinOp::Sub, scale(2), scale(5))),
            ("overflow", Expr::bin(BinOp::Add, scale(u64::MAX), scale(2))),
            ("zero", Expr::bin(BinOp::Add, scale(u64::MAX), x.clone())),
            ("nested", Expr::bin(BinOp::Mul, scale(3), Expr::Const(8))),
            (
                "shift",
                Expr::bin(
                    BinOp::Add,
                    x.clone(),
                    Expr::bin(BinOp::Shl, x.clone(), Expr::Const(65)),
                ),
            ),
        ] {
            for compare in [false, true] {
                let result = if compare {
                    Expr::Select {
                        cond: Cond::Lt,
                        lhs: Box::new(value.clone()),
                        rhs: Box::new(Expr::Const(0)),
                        then: Box::new(Expr::Const(1)),
                        els: Box::new(Expr::Const(0)),
                    }
                } else {
                    value.clone()
                };
                let original = synthetic_ir(
                    &format!("scaled_{width}_{case}_{compare}"),
                    vec![Param {
                        index: 7,
                        name: "x".into(),
                        ty: CType::U64,
                    }],
                    CType::U64,
                    vec![Stmt::Ret { value: result }],
                );
                let mut optimized = original.clone();
                velk::passes::simplify::simplify(&mut optimized);
                let mut candidate = printed_candidate(original, inputs.clone());
                candidate.code = velk::render::render(&optimized, &[], &Default::default(), &[]);
                if width == 64 && case == "sum" && !compare {
                    assert!(
                        candidate.code.contains("return x * 3;"),
                        "{}",
                        candidate.code
                    );
                }
                candidates.push(candidate);
            }
        }
    }
    check_candidates(
        "scaled-registers",
        candidates,
        Mode::Registers,
        &["-fsanitize=undefined", "-fno-sanitize-recover=all"],
    );
}

#[test]
fn scaled_register_sums_keep_distinct_values_and_memory_reads() {
    let load = Expr::Load {
        addr: Box::new(Expr::reg(7, 64)),
        width: 8,
        signed: false,
    };
    for (left, right) in [
        (Expr::reg(7, 32), Expr::reg(7, 64)),
        (Expr::reg(7, 64), Expr::reg(6, 64)),
        (load.clone(), load),
    ] {
        let original = Expr::bin(
            BinOp::Add,
            left,
            Expr::bin(BinOp::Mul, right, Expr::Const(2)),
        );
        let mut ir = synthetic_ir(
            "distinct_scales",
            vec![],
            CType::U64,
            vec![Stmt::Ret {
                value: original.clone(),
            }],
        );
        velk::passes::simplify::simplify(&mut ir);
        let [Stmt::Ret { value }] = ir.blocks[0].stmts.as_slice() else {
            panic!("expected the return");
        };
        assert_eq!(*value, original);
    }
}

#[test]
fn spilled_absolute_offsets_use_integer_arithmetic_through_zero() {
    use velk::ir::{RegRef, VARIABLE_BASE};
    let slot = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const((-8i64) as u64));
    let load = Expr::Load {
        addr: Box::new(slot.clone()),
        width: 8,
        signed: false,
    };
    let mut candidates = Vec::new();
    for spilled_register in [false, true] {
        let offset = if spilled_register {
            Expr::reg(VARIABLE_BASE, 64)
        } else {
            load.clone()
        };
        let mut body = vec![Stmt::Store {
            addr: Expr::bin(BinOp::Add, Expr::Const(REGION), offset.clone()),
            value: Expr::Const(19),
            width: 1,
        }];
        if spilled_register {
            body.push(Stmt::Store {
                addr: slot.clone(),
                value: offset.clone(),
                width: 8,
            });
            body.push(Stmt::Assign {
                dest: RegRef {
                    index: VARIABLE_BASE,
                    width: 64,
                },
                value: Expr::bin(BinOp::Add, load.clone(), Expr::Const(1)),
            });
        } else {
            body.push(Stmt::Store {
                addr: slot.clone(),
                value: Expr::bin(BinOp::Sub, load.clone(), Expr::Const(1)),
                width: 8,
            });
        }
        body.push(Stmt::Brif {
            cond: if spilled_register { Cond::Cc } else { Cond::Hi },
            lhs: offset,
            rhs: Expr::Const(if spilled_register { 4 } else { 0 }),
            target: 0x10,
        });
        let initial = if spilled_register {
            Stmt::Assign {
                dest: RegRef {
                    index: VARIABLE_BASE,
                    width: 64,
                },
                value: Expr::Const(0),
            }
        } else {
            Stmt::Store {
                addr: slot.clone(),
                value: Expr::Const(7),
                width: 8,
            }
        };
        let mut ir = synthetic_ir(
            &format!("spilled_absolute_offset_{spilled_register}"),
            vec![],
            CType::U64,
            vec![initial],
        );
        ir.blocks.push(Block {
            start: 0x10,
            stmts: body,
        });
        ir.blocks.push(Block {
            start: 0x20,
            stmts: vec![Stmt::Ret {
                value: Expr::Const(7),
            }],
        });
        candidates.push(printed_candidate(ir, vec![vec![]]));
    }
    check_candidates(
        "spilled-absolute-offsets",
        candidates,
        Mode::Memory,
        &["-fsanitize=undefined", "-fno-sanitize-recover=all"],
    );
}

#[test]
fn nonzero_offsets_stay_integer_through_distinct_spill_registers() {
    use velk::ir::{RegRef, VARIABLE_BASE};
    let slot = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const((-8i64) as u64));
    let loaded = VARIABLE_BASE + 1;
    let mut ir = synthetic_ir(
        "nonzero_spill_offsets",
        vec![],
        CType::U64,
        vec![
            Stmt::Assign {
                dest: RegRef {
                    index: VARIABLE_BASE,
                    width: 64,
                },
                value: Expr::Const(3),
            },
            Stmt::Br { target: Some(16) },
        ],
    );
    ir.blocks.push(Block {
        start: 16,
        stmts: vec![
            Stmt::Store {
                addr: slot.clone(),
                value: Expr::reg(VARIABLE_BASE, 64),
                width: 8,
            },
            Stmt::Assign {
                dest: RegRef {
                    index: loaded,
                    width: 64,
                },
                value: Expr::Load {
                    addr: Box::new(slot),
                    width: 8,
                    signed: false,
                },
            },
            Stmt::Store {
                addr: Expr::bin(BinOp::Add, Expr::Const(REGION), Expr::reg(loaded, 64)),
                value: Expr::Const(19),
                width: 1,
            },
            Stmt::Assign {
                dest: RegRef {
                    index: VARIABLE_BASE,
                    width: 64,
                },
                value: Expr::bin(BinOp::Sub, Expr::reg(loaded, 64), Expr::Const(1)),
            },
            Stmt::Brif {
                cond: Cond::Ne,
                lhs: Expr::reg(loaded, 64),
                rhs: Expr::Const(0),
                target: 16,
            },
        ],
    });
    ir.blocks.push(Block {
        start: 32,
        stmts: vec![Stmt::Ret {
            value: Expr::Const(7),
        }],
    });
    check_candidates(
        "nonzero-spill-offsets",
        vec![printed_candidate(ir, vec![vec![]])],
        Mode::Memory,
        &["-fsanitize=undefined", "-fno-sanitize-recover=all"],
    );
}

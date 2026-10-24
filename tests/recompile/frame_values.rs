use super::*;
use velk::ir::RegRef;

fn slot(offset: i64) -> Expr {
    Expr::bin(
        BinOp::Add,
        Expr::reg(velk::arch::stack_pointer(Isa::X86_64), 64),
        Expr::Const(offset as u64),
    )
}

fn store(offset: i64, value: Expr, width: u8) -> Stmt {
    Stmt::Store {
        addr: slot(offset),
        value,
        width,
    }
}

fn load(offset: i64, width: u8, signed: bool) -> Expr {
    Expr::Load {
        addr: Box::new(slot(offset)),
        width,
        signed,
    }
}

fn assign(index: u16, width: u8, value: Expr) -> Stmt {
    Stmt::Assign {
        dest: RegRef { index, width },
        value,
    }
}

fn diamond(name: &str, width: u8, signed: bool) -> FunctionIr {
    let [a, b] = Convention::SysV.arguments()[..2] else {
        unreachable!()
    };
    let value = Expr::bin(
        BinOp::Xor,
        Expr::reg(a, 64),
        Expr::Const(0x8123_4567_89ab_cdef),
    );
    let mut ir = synthetic_ir(
        name,
        vec![
            Param {
                index: a,
                name: "a".into(),
                ty: CType::Int {
                    bytes: 8,
                    signed: false,
                },
            },
            Param {
                index: b,
                name: "b".into(),
                ty: CType::Int {
                    bytes: 8,
                    signed: false,
                },
            },
        ],
        CType::Int {
            bytes: 8,
            signed: false,
        },
        vec![Stmt::Brif {
            cond: Cond::Eq,
            lhs: Expr::reg(b, 64),
            rhs: Expr::Const(0),
            target: 0x20,
        }],
    );
    for start in [0x10, 0x20] {
        ir.blocks.push(Block {
            start,
            stmts: vec![
                store(-8, value.clone(), width),
                Stmt::Br { target: Some(0x30) },
            ],
        });
    }
    ir.blocks.push(Block {
        start: 0x30,
        stmts: vec![Stmt::Ret {
            value: load(-8, width, signed),
        }],
    });
    ir
}

fn forward(ir: &FunctionIr) -> FunctionIr {
    let mut optimized = ir.clone();
    velk::passes::memory::forward_stored_values(&mut optimized);
    velk::passes::copies::copy_propagate_guarded(&mut optimized);
    velk::passes::simplify::simplify(&mut optimized);
    velk::passes::dce::dce(&mut optimized);
    velk::passes::frame_slots::settle(&mut optimized);
    optimized
}

fn printed(ir: &FunctionIr) -> String {
    velk::render::render(ir, &[], &Default::default(), &[])
}

fn assert_forwarded(ir: &FunctionIr, expected: bool) {
    let text = printed(&forward(ir));
    let returns_slot = text
        .lines()
        .any(|line| line.contains("return ") && (line.contains("local_") || line.contains("rsp")));
    assert_eq!(returns_slot, !expected, "{text}");
    if expected {
        assert!(text.contains("return ") && text.contains("a ^"), "{text}");
    }
}

fn call() -> Stmt {
    Stmt::Call {
        target: Some(0x1000),
        through: None,
        convention: Convention::SysV,
        args: None,
        floats_named: false,
        outputs: velk::ir::fallback_call_outputs(Convention::SysV, None),
        clobbers: None,
        via: None,
    }
}

#[test]
fn printed_frame_join_values_keep_uncertain_reads() {
    let a = Convention::SysV.arguments()[0];
    let sp = velk::arch::stack_pointer(Isa::X86_64);
    let fp = velk::arch::frame_pointer(Isa::X86_64);
    let base = diamond("frame_join", 8, false);
    assert_forwarded(&base, true);
    let mut constant = diamond("frame_boolean", 1, false);
    for block in &mut constant.blocks[1..3] {
        block.stmts[0] = store(-8, Expr::Const(1), 1);
    }
    constant.blocks[3].stmts[0] = Stmt::Ret {
        value: Expr::bin(BinOp::And, load(-8, 1, false), Expr::Const(1)),
    };
    let text = printed(&forward(&constant));
    assert!(text.contains("return 0x1;"), "{text}");
    let mut unreachable = base.clone();
    unreachable.blocks.push(Block {
        start: 0x40,
        stmts: vec![
            store(-8, Expr::Const(7), 8),
            Stmt::Br { target: Some(0x30) },
        ],
    });
    assert_forwarded(&unreachable, true);
    for case in [
        "different",
        "uninitialized",
        "uninitialized_loop",
        "partial",
        "overlap",
        "redefined",
        "narrow_write",
        "escape",
        "call",
        "unknown_store",
        "unsupported",
        "exception",
        "unknown_exception",
        "unknown_edge",
        "missing_target",
        "moving_frame",
        "moving_frame_pointer",
        "dynamic_frame",
        "memory_value",
    ] {
        let mut ir = base.clone();
        ir.name = Some(format!("frame_{case}"));
        let before_jump = ir.blocks[1].stmts.len() - 1;
        match case {
            "different" => ir.blocks[1].stmts[0] = store(-8, Expr::Const(7), 8),
            "uninitialized" => {
                ir.blocks[1].stmts.remove(0);
            }
            "uninitialized_loop" => {
                ir.blocks[1].stmts[1] = Stmt::Br { target: Some(0) };
                ir.blocks[2].stmts.remove(0);
            }
            "partial" => ir.blocks[1].stmts[0] = store(-8, Expr::reg(a, 64), 4),
            "overlap" => ir.blocks[1]
                .stmts
                .insert(before_jump, store(-4, Expr::Const(7), 4)),
            "redefined" | "narrow_write" => ir.blocks[1].stmts.insert(
                before_jump,
                assign(
                    a,
                    if case == "narrow_write" { 8 } else { 64 },
                    Expr::Const(3),
                ),
            ),
            "escape" => ir.blocks[1]
                .stmts
                .insert(before_jump, assign(velk::ir::VARIABLE_BASE, 64, slot(-8))),
            "call" => ir.blocks[1].stmts.insert(before_jump, call()),
            "unknown_store" => ir.blocks[1].stmts.insert(
                before_jump,
                Stmt::Store {
                    addr: Expr::reg(a, 64),
                    value: Expr::Const(3),
                    width: 8,
                },
            ),
            "unsupported" => ir.blocks[1].stmts.insert(
                before_jump,
                Stmt::Unsupported {
                    text: "opaque".into(),
                    writes: Some(Vec::new()),
                },
            ),
            "exception" | "unknown_exception" => {
                ir.blocks[1].stmts.insert(before_jump, call());
                ir.landing_pads.push((
                    if case == "exception" { 0x30 } else { 0x80 },
                    vec![(0x10, 0x20)],
                ));
            }
            "unknown_edge" => ir.blocks[1].stmts[before_jump] = Stmt::Br { target: None },
            "missing_target" => ir.blocks[1].stmts[before_jump] = Stmt::Br { target: Some(0x80) },
            "moving_frame" => ir.blocks[1].stmts.insert(
                before_jump,
                assign(
                    sp,
                    64,
                    Expr::bin(BinOp::Sub, Expr::reg(sp, 64), Expr::Const(16)),
                ),
            ),
            "dynamic_frame" => ir.blocks[1]
                .stmts
                .insert(before_jump, assign(sp, 64, Expr::reg(a, 64))),
            "moving_frame_pointer" => {
                ir.blocks[0]
                    .stmts
                    .insert(0, assign(fp, 64, Expr::reg(sp, 64)));
                let address = Expr::bin(BinOp::Sub, Expr::reg(fp, 64), Expr::Const(8));
                for block in &mut ir.blocks[1..3] {
                    let Stmt::Store { addr, .. } = &mut block.stmts[0] else {
                        unreachable!()
                    };
                    *addr = address.clone();
                }
                ir.blocks[1].stmts.insert(
                    before_jump,
                    assign(
                        fp,
                        64,
                        Expr::bin(BinOp::Add, Expr::reg(fp, 64), Expr::Const(16)),
                    ),
                );
                ir.blocks[3].stmts[0] = Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(address),
                        width: 8,
                        signed: false,
                    },
                };
            }
            "memory_value" => {
                for block in &mut ir.blocks[1..3] {
                    block.stmts[0] = store(
                        -8,
                        Expr::Load {
                            addr: Box::new(Expr::reg(a, 64)),
                            width: 8,
                            signed: false,
                        },
                        8,
                    );
                }
            }
            _ => unreachable!(),
        }
        // Keep the escape visible to the analysis before dead-copy removal.
        let mut optimized = ir.clone();
        velk::passes::memory::forward_stored_values(&mut optimized);
        let text = printed(&optimized);
        assert!(
            text.lines().any(|line| line.contains("return ")
                && (line.contains("local_") || line.contains("rsp") || line.contains("rbp"))),
            "{case}: {text}"
        );
    }
}

#[test]
fn printed_frame_join_values_recompile_with_exact_widths_and_loops() {
    let a = Convention::SysV.arguments()[0];
    let b = Convention::SysV.arguments()[1];
    let sp = velk::arch::stack_pointer(Isa::X86_64);
    let mut cases = Vec::new();
    for width in [1, 2, 4, 8] {
        for signed in [false, true] {
            let ir = diamond(&format!("frame_width_{width}_{signed}"), width, signed);
            assert_forwarded(&ir, true);
            let mut register = ir.clone();
            register.name = Some(format!("frame_register_{width}_{signed}"));
            for block in &mut register.blocks[1..3] {
                block.stmts[0] = store(-8, Expr::reg(a, 64), width);
            }
            assert!(!printed(&forward(&register)).contains("local_"));
            cases.push(register);
            cases.push(ir);
        }
    }
    let mut different = diamond("frame_different", 8, false);
    different.blocks[1].stmts[0] = store(-8, Expr::reg(b, 64), 8);
    assert_forwarded(&different, false);
    cases.push(different);
    let mut moved = diamond("frame_adjusted", 8, false);
    moved.blocks[0].stmts.insert(
        0,
        assign(
            sp,
            64,
            Expr::bin(BinOp::Sub, Expr::reg(sp, 64), Expr::Const(16)),
        ),
    );
    assert_forwarded(&moved, true);
    cases.push(moved);
    for changes_value in [false, true] {
        let mut ir = diamond(&format!("frame_loop_{changes_value}"), 8, false);
        let initial = ir.blocks[1].stmts[0].clone();
        ir.blocks[0].stmts.insert(0, initial);
        ir.blocks[1].stmts = vec![assign(b, 64, Expr::Const(0)), Stmt::Br { target: Some(0) }];
        // Reenter the condition without rerunning the initializing store.
        let condition = ir.blocks[0].stmts.pop().unwrap();
        ir.blocks.insert(
            1,
            Block {
                start: 8,
                stmts: vec![condition],
            },
        );
        ir.blocks[2].stmts[1] = Stmt::Br { target: Some(8) };
        ir.blocks[3].stmts = vec![Stmt::Br { target: Some(0x30) }];
        if changes_value {
            ir.blocks[2].stmts.insert(0, store(-8, Expr::Const(7), 8));
        }
        assert_forwarded(&ir, !changes_value);
        cases.push(ir);
    }
    let mut partial = diamond("frame_partial", 8, false);
    partial.blocks[1]
        .stmts
        .insert(1, store(-4, Expr::Const(7), 4));
    assert_forwarded(&partial, false);
    cases.push(partial);
    let mut changed = diamond("frame_changed", 8, false);
    changed.blocks[1]
        .stmts
        .insert(1, assign(a, 64, Expr::Const(3)));
    assert_forwarded(&changed, false);
    cases.push(changed);
    for width in [1, 2, 4, 8] {
        let bits = u32::from(width) * 8;
        for condition in [false, true] {
            let mut ir = diamond(&format!("frame_constant_{width}_{condition}"), width, false);
            for block in &mut ir.blocks[1..3] {
                block.stmts[0] = store(-8, Expr::Const(1u64 << (bits - 1)), width);
            }
            if condition {
                ir.blocks[3].stmts = vec![Stmt::Brif {
                    cond: Cond::Lt,
                    lhs: load(-8, width, false),
                    rhs: Expr::Const(0),
                    target: 0x50,
                }];
                for (start, value) in [(0x40, 0), (0x50, 1)] {
                    ir.blocks.push(Block {
                        start,
                        stmts: vec![Stmt::Ret {
                            value: Expr::Const(value),
                        }],
                    });
                }
            } else {
                ir.blocks[3].stmts = vec![Stmt::Ret {
                    value: Expr::bin(
                        BinOp::And,
                        Expr::bin(BinOp::Sar, load(-8, width, false), Expr::Const(1)),
                        Expr::Const(u64::MAX >> (64 - bits)),
                    ),
                }];
            }
            let text = printed(&forward(&ir));
            if width < 8 {
                assert!(text.contains("local_"), "{text}");
            }
            cases.push(ir);
        }
    }
    let mut narrow = diamond("frame_narrow_source", 8, false);
    for block in &mut narrow.blocks[1..3] {
        block.stmts[0] = store(-8, Expr::reg(a, 8), 8);
    }
    narrow.blocks[3].stmts[0] = Stmt::Ret {
        value: Expr::Select {
            cond: Cond::Lt,
            lhs: Box::new(load(-8, 8, false)),
            rhs: Box::new(Expr::Const(0)),
            then: Box::new(Expr::Const(1)),
            els: Box::new(Expr::Const(0)),
        },
    };
    assert!(printed(&forward(&narrow)).contains("local_"));
    cases.push(narrow);
    let mut inputs = Vec::new();
    for value in [
        0,
        1,
        0x7f,
        0x80,
        0x7fff,
        0x8000,
        0x7fff_ffff,
        0x8000_0000,
        i64::MAX as u64,
        i64::MIN as u64,
        u64::MAX,
    ] {
        for branch in [0, 1] {
            inputs.push(vec![value, branch]);
        }
    }
    let mut random = 0x5eed_u64;
    for _ in 0..64 {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        inputs.push(vec![random, random & 1]);
    }
    let candidates = cases
        .into_iter()
        .map(|ir| {
            let selected = if ir
                .name
                .as_deref()
                .is_some_and(|name| name.starts_with("frame_constant_"))
            {
                vec![vec![0, 0], vec![0, 1]]
            } else {
                inputs.clone()
            };
            let mut candidate = printed_candidate(forward(&ir), selected);
            candidate.ir = ir;
            candidate
        })
        .collect();
    // Only the private frame is accessed; the driver's shared region is unused.
    check_candidates("frame-join-values", candidates, Mode::Registers, &[]);
}

#[test]
fn printed_frame_branch_comparisons_keep_direct_constants() {
    let path = common::fixtures_dir().join("metrics/control.aarch64.O0.debug.elf");
    let mut binary = Binary::open(&path).expect("the control fixture");
    let address = binary
        .image()
        .functions
        .values()
        .find(|function| function.name.as_deref() == Some("fallthrough"))
        .expect("the branch function")
        .addr;
    let text = binary
        .decompile(address, None, None)
        .expect("printed branch comparisons");
    assert!(text.contains("!= 0x1"), "{text}");
    assert!(text.contains("== 0x2"), "{text}");
    assert!(!text.contains("- 0x1 != 0x0"), "{text}");
}

#[test]
fn printed_local_offsets_preserve_operator_precedence() {
    let a = Expr::reg(7, 64);
    let shift = Expr::bin(BinOp::Shl, a.clone(), Expr::Const(2));
    let and = Expr::bin(BinOp::And, a.clone(), Expr::Const(1));
    let or = Expr::bin(BinOp::Or, a.clone(), Expr::Const(1));
    let select = Expr::Select {
        cond: Cond::Eq,
        lhs: Box::new(a.clone()),
        rhs: Box::new(Expr::Const(0)),
        then: Box::new(Expr::Const(2)),
        els: Box::new(Expr::Const(0)),
    };
    let sum = [shift.clone(), and.clone(), or.clone(), select.clone()]
        .into_iter()
        .reduce(|lhs, rhs| Expr::bin(BinOp::Add, lhs, rhs))
        .unwrap();
    let mut candidates = Vec::new();
    for (case, offset, expected) in [
        ("shift", shift, " + (a << 0x2)"),
        ("and", and, " + (a & 0x1)"),
        ("or", or, " + (a | 0x1)"),
        ("select", select, " + (a == 0x0 ? 0x2 : 0x0)"),
        (
            "sum",
            sum,
            " + ((a << 0x2) + (a & 0x1) + (a | 0x1) + (a == 0x0 ? 0x2 : 0x0))",
        ),
    ] {
        let address = Expr::bin(BinOp::Add, slot(-8), offset);
        let ir = synthetic_ir(
            &format!("local_offset_{case}"),
            vec![Param {
                index: 7,
                name: "a".into(),
                ty: CType::U64,
            }],
            CType::U64,
            vec![
                store(-8, Expr::Const(0x8877_6655_4433_2211), 8),
                Stmt::Store {
                    addr: address.clone(),
                    value: Expr::Const(0xa5),
                    width: 1,
                },
                Stmt::Ret {
                    value: Expr::bin(
                        BinOp::Xor,
                        load(-8, 8, false),
                        Expr::Load {
                            addr: Box::new(address),
                            width: 1,
                            signed: false,
                        },
                    ),
                },
            ],
        );
        let candidate = printed_candidate(ir, (0..=1).map(|a| vec![a]).collect());
        assert!(candidate.code.contains(expected), "{}", candidate.code);
        assert!(
            candidate.code.contains(&format!("(local_0{expected})")),
            "{}",
            candidate.code
        );
        candidates.push(candidate);
    }
    check_candidates("local-offset-precedence", candidates, Mode::Registers, &[]);
}

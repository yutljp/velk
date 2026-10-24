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
        kind: velk::ir::CallKind::Invoke,
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
                && (line.contains("local_")
                    || line.contains("rsp")
                    || line.contains("*(uint64_t *)"))),
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

#[test]
fn printed_promoted_slots_execute_joins_loops_and_alias_fallbacks() {
    let a = Convention::SysV.arguments()[0];
    let b = Convention::SysV.arguments()[1];
    for case in ["uninitialized", "call", "trap"] {
        let mut ir = diamond("promotion_fallback", 8, false);
        match case {
            "uninitialized" => {
                ir.blocks[1].stmts.remove(0);
            }
            "call" => ir.blocks[3].stmts.insert(0, call()),
            _ => ir.blocks[3].stmts = vec![Stmt::Trap],
        }
        velk::passes::memory::promote_frame_slots(&mut ir);
        assert!(printed(&ir).contains("local_"), "{case}: {}", printed(&ir));
    }
    let mut cases = Vec::new();
    for width in [1, 2, 4, 8] {
        for signed in [false, true] {
            let mut ir = diamond(&format!("promoted_join_{width}_{signed}"), width, signed);
            ir.blocks[1].stmts[0] = store(-8, Expr::reg(b, 64), width);
            cases.push((ir, true));
        }
    }
    let mut looping = diamond("promoted_loop", 8, false);
    looping.blocks[0]
        .stmts
        .insert(0, store(-8, Expr::reg(a, 64), 8));
    let condition = looping.blocks[0].stmts.pop().unwrap();
    looping.blocks.insert(
        1,
        Block {
            start: 8,
            stmts: vec![condition],
        },
    );
    looping.blocks[2].stmts = vec![
        store(
            -8,
            Expr::bin(BinOp::Add, load(-8, 8, false), Expr::Const(7)),
            8,
        ),
        assign(b, 64, Expr::Const(0)),
        Stmt::Br { target: Some(8) },
    ];
    looping.blocks[3].stmts = vec![Stmt::Br { target: Some(0x30) }];
    cases.push((looping, true));
    let mut snapshot = diamond("promoted_frame_snapshot", 8, false);
    let saved = velk::ir::TEMP_BASE + 51;
    snapshot.blocks[0].stmts.splice(
        0..0,
        [
            store(0, Expr::Const(11), 8),
            assign(saved, 64, load(0, 8, false)),
            store(0, Expr::Const(22), 8),
        ],
    );
    snapshot.blocks[3].stmts[0] = Stmt::Ret {
        value: Expr::bin(BinOp::Add, Expr::reg(saved, 64), load(-8, 8, false)),
    };
    cases.push((snapshot, false));
    let mut narrow = diamond("promoted_narrow_fallback", 8, false);
    narrow.blocks[3].stmts[0] = Stmt::Ret {
        value: load(-8, 1, true),
    };
    cases.push((narrow, false));
    let mut escaped = diamond("promoted_escape_fallback", 8, false);
    escaped.blocks[0]
        .stmts
        .insert(0, assign(velk::ir::TEMP_BASE + 50, 64, slot(-8)));
    escaped.blocks[3].stmts.insert(
        0,
        Stmt::Store {
            addr: Expr::reg(velk::ir::TEMP_BASE + 50, 64),
            value: Expr::reg(b, 64),
            width: 8,
        },
    );
    cases.push((escaped, false));
    let mut candidates = Vec::new();
    for (ir, promoted) in cases {
        let mut optimized = ir.clone();
        velk::passes::memory::promote_frame_slots(&mut optimized);
        let text = printed(&optimized);
        assert_eq!(
            !text.contains("local_") && !text.contains("rsp"),
            promoted,
            "{text}"
        );
        velk::passes::copies::copy_propagate_guarded(&mut optimized);
        velk::passes::simplify::simplify(&mut optimized);
        velk::passes::dce::dce(&mut optimized);
        velk::passes::frame_slots::settle(&mut optimized);
        let inputs = [0, 1, 0x80, 0x8000, 0x8000_0000, u64::MAX]
            .into_iter()
            .flat_map(|a| [vec![a, 0], vec![a, 1]])
            .collect();
        let mut candidate = printed_candidate(optimized, inputs);
        candidate.ir = ir;
        candidates.push(candidate);
    }
    check_candidates("promoted-frame-slots", candidates, Mode::Registers, &[]);
}

#[test]
fn printed_promoted_slots_survive_recursive_calls() {
    let sp = velk::arch::stack_pointer(Isa::X86_64);
    let mut invocation = call();
    if let Stmt::Call {
        args, floats_named, ..
    } = &mut invocation
    {
        *args = Some(vec![Expr::bin(
            BinOp::Sub,
            Expr::reg(7, 64),
            Expr::Const(1),
        )]);
        *floats_named = true;
    }
    let mut ir = synthetic_ir(
        "frame_recursive",
        vec![Param {
            index: 7,
            name: "a".into(),
            ty: CType::U64,
        }],
        CType::U64,
        vec![
            assign(
                sp,
                64,
                Expr::bin(BinOp::Sub, Expr::reg(sp, 64), Expr::Const(32)),
            ),
            store(16, Expr::reg(7, 64), 8),
            invocation,
            Stmt::Ret {
                value: Expr::bin(BinOp::Add, load(16, 8, false), Expr::reg(0, 64)),
            },
        ],
    );
    velk::passes::memory::promote_frame_slots(&mut ir);
    velk::passes::copies::copy_propagate_guarded(&mut ir);
    velk::passes::dce::dce(&mut ir);
    let symbols = velk::render::Symbols {
        functions: [(0x1000, "frame_helper".into())].into(),
        function_returns: [(0x1000, CType::U64)].into(),
        ..Default::default()
    };
    let code = velk::render::render(&ir, &[], &symbols, &[]);
    assert!(!code.contains("local_"), "{code}");
    let mut text = String::from(HEADER);
    text.push_str("static uint64_t frame_recursive(uint64_t);\nstatic uint64_t frame_helper(uint64_t n) { return n ? frame_recursive(n) : 0; }\n");
    text.push_str(&code);
    text.push_str("int main(void) { for (uint64_t n = 1; n < 12; ++n) if (frame_recursive(n) != n * (n + 1) / 2) return 1; return 0; }\n");
    let source = Program {
        text,
        ranges: Vec::new(),
    };
    let scratch = scratch_dir("frame-recursive");
    for level in LEVELS {
        let program = build(&source, &scratch, level, &[]);
        assert_eq!(run(&program, ""), "");
    }
    std::fs::remove_dir_all(scratch).ok();
}

#[test]
fn printed_call_slot_promotion_excludes_argument_and_escaping_slots() {
    let sp = velk::arch::stack_pointer(Isa::X86_64);
    for case in [
        "known",
        "unknown",
        "stack",
        "padding",
        "address",
        "register",
        "global",
        "red_zone",
        "shadow",
        "go",
        "narrow_sp",
    ] {
        let mut invocation = call();
        if let Stmt::Call {
            args, convention, ..
        } = &mut invocation
        {
            *args = Some(Vec::new());
            match case {
                "unknown" => *args = None,
                "stack" | "padding" => {
                    *args = Some(
                        (0..6)
                            .map(|_| Expr::Const(0))
                            .chain([load(16, if case == "padding" { 4 } else { 8 }, false)])
                            .collect(),
                    )
                }
                "address" => *args = Some(vec![slot(16)]),
                "shadow" => *convention = Convention::Win64,
                "go" => *convention = Convention::GoAmd64,
                _ => {}
            }
        }
        let mut stmts = vec![assign(
            sp,
            if case == "narrow_sp" { 32 } else { 64 },
            Expr::bin(BinOp::Sub, Expr::reg(sp, 64), Expr::Const(32)),
        )];
        let offset = match case {
            "red_zone" => -8,
            "padding" => 20,
            _ => 16,
        };
        let width = if case == "padding" { 4 } else { 8 };
        if case == "padding" {
            stmts.push(store(16, Expr::Const(3), 4));
        }
        stmts.push(store(offset, Expr::Const(7), width));
        if case == "register" {
            stmts.push(assign(3, 64, slot(offset)));
        } else if case == "global" {
            stmts.push(Stmt::Store {
                addr: Expr::Const(0x8000),
                value: slot(offset),
                width: 8,
            });
        }
        stmts.extend([
            invocation,
            Stmt::Ret {
                value: load(offset, width, false),
            },
        ]);
        let mut ir = synthetic_ir("frame_call_slot", Vec::new(), CType::U64, stmts);
        velk::passes::memory::promote_frame_slots(&mut ir);
        let code = printed(&ir);
        assert_eq!(
            code.lines().any(|line| line.contains("return ")
                && (line.contains("local_") || line.contains("rsp"))),
            case != "known",
            "{case}: {code}"
        );
    }
}

#[test]
fn printed_call_slots_execute_stack_arguments_and_address_writes() {
    let sp = velk::arch::stack_pointer(Isa::X86_64);
    let mut text = String::from(HEADER);
    text.push_str("static uint64_t frame_write(int64_t *p) { *p = 19; return 3; }\nstatic uint64_t frame_seven(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f, uint64_t g) { return a + b + c + d + e + f + g; }\n");
    for address in [false, true] {
        let mut invocation = call();
        if let Stmt::Call {
            args, floats_named, ..
        } = &mut invocation
        {
            *args = Some(if address {
                vec![slot(16)]
            } else {
                (1..=6)
                    .map(Expr::Const)
                    .chain([load(0, 8, false)])
                    .collect()
            });
            *floats_named = true;
        }
        let mut ir = synthetic_ir(
            if address {
                "frame_address_call"
            } else {
                "frame_stack_call"
            },
            Vec::new(),
            CType::U64,
            vec![
                assign(
                    sp,
                    64,
                    Expr::bin(BinOp::Sub, Expr::reg(sp, 64), Expr::Const(32)),
                ),
                store(0, Expr::Const(7), 8),
                store(16, Expr::Const(11), 8),
                invocation,
                Stmt::Ret {
                    value: Expr::bin(BinOp::Add, load(16, 8, false), Expr::reg(0, 64)),
                },
            ],
        );
        velk::passes::memory::promote_frame_slots(&mut ir);
        velk::passes::frame_slots::settle(&mut ir);
        velk::passes::copies::copy_propagate_guarded(&mut ir);
        velk::passes::dce::dce(&mut ir);
        let symbols = velk::render::Symbols {
            functions: [(
                0x1000,
                if address {
                    "frame_write".into()
                } else {
                    "frame_seven".into()
                },
            )]
            .into(),
            function_returns: [(0x1000, CType::U64)].into(),
            ..Default::default()
        };
        let code = velk::render::render(&ir, &[], &symbols, &[]);
        assert!(code.contains("local_"), "{code}");
        if !address {
            assert!(code.contains("return 0xb +"), "{code}");
        }
        text.push_str(&code);
    }
    text.push_str(
        "int main(void) { return frame_address_call() != 22 || frame_stack_call() != 39; }\n",
    );
    let source = Program {
        text,
        ranges: Vec::new(),
    };
    let scratch = scratch_dir("frame-call-memory");
    for level in LEVELS {
        let program = build(&source, &scratch, level, &[]);
        assert_eq!(run(&program, ""), "");
    }
    std::fs::remove_dir_all(scratch).ok();
}

#[test]
fn printed_context_saving_calls_keep_frame_storage() {
    let scratch = scratch_dir("context-frame-slots");
    std::fs::create_dir_all(&scratch).expect("create source directory");
    let source = scratch.join("context.c");
    let object = scratch.join("context.o");
    std::fs::write(&source, "__attribute__((noinline)) unsigned long setjmp(unsigned long n) { return n; }\nunsigned long context_value(unsigned long n) { unsigned long saved; if (n & 1) saved = 7; else saved = 11; setjmp(n); return saved; }\n").expect("write context source");
    let output = Command::new(COMPILER)
        .args([
            "-target",
            "x86_64-unknown-linux-gnu",
            "-O0",
            "-g",
            "-fno-builtin",
            "-c",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .output()
        .expect("compile context source");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut binary = Binary::open(&object).expect("open context object");
    let address = binary
        .image()
        .functions
        .values()
        .find(|function| function.name.as_deref() == Some("context_value"))
        .expect("context function")
        .addr;
    let code = binary
        .decompile(address, None, None)
        .expect("decompile context function");
    assert!(code.contains("setjmp("), "{code}");
    assert!(code.contains("local_"), "{code}");
    std::fs::remove_dir_all(scratch).ok();
}

#[test]
fn printed_promoted_recursive_products_preserve_wrapping_arithmetic() {
    for isa in ["aarch64", "x86_64"] {
        let path = common::fixtures_dir().join(format!("metrics/calls.{isa}.O0.debug.elf"));
        let binary = Binary::open(&path).expect("open recursive fixture");
        let address = binary
            .image()
            .functions
            .values()
            .find(|function| function.name.as_deref() == Some("factorial"))
            .expect("recursive function")
            .addr;
        for kind in ["debug", "stripped"] {
            let path = common::fixtures_dir().join(format!("metrics/calls.{isa}.O0.{kind}.elf"));
            let mut binary = Binary::open(&path).expect("open recursive fixture");
            let name = if kind == "debug" {
                "factorial".to_owned()
            } else {
                format!("sub_{address:x}")
            };
            let code = binary
                .decompile(address, None, None)
                .expect("decompile recursive function");
            assert!(code.contains("uint32_t"), "{code}");
            assert!(!code.contains("local_"), "{code}");
            let mut text = String::from(HEADER);
            text.push_str(&code);
            text.push_str(&format!("int main(void) {{ uint32_t want = 1; for (int n = 1; n <= 20; ++n) {{ want *= (uint32_t)n; if ((uint32_t){name}(n) != want) return 1; }} return 0; }}\n"));
            let source = Program {
                text,
                ranges: Vec::new(),
            };
            let scratch = scratch_dir(&format!("frame-product-{isa}-{kind}"));
            for level in LEVELS {
                let program = build(
                    &source,
                    &scratch,
                    level,
                    &["-fsanitize=undefined", "-fno-sanitize-recover=undefined"],
                );
                assert_eq!(run(&program, ""), "");
            }
            std::fs::remove_dir_all(scratch).ok();
        }
    }
}

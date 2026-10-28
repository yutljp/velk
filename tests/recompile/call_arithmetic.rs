use super::*;
use velk::ir::{CallOutput, RegRef, Registers, VARIABLE_BASE};

#[test]
fn call_results_stay_before_memory_and_conditional_reads() {
    let result = Expr::reg(VARIABLE_BASE, 64);
    for value in [
        Expr::bin(
            BinOp::Add,
            result.clone(),
            Expr::Load {
                addr: Box::new(Expr::reg(7, 64)),
                width: 8,
                signed: false,
            },
        ),
        Expr::bin(
            BinOp::Add,
            result.clone(),
            Expr::bin(BinOp::DivU, Expr::reg(7, 64), Expr::reg(6, 64)),
        ),
        Expr::Select {
            cond: Cond::Eq,
            lhs: Box::new(Expr::reg(7, 64)),
            rhs: Box::new(Expr::Const(0)),
            then: Box::new(result),
            els: Box::new(Expr::Const(0)),
        },
    ] {
        let ir = synthetic_ir(
            "ordered",
            vec![],
            CType::U64,
            vec![
                Stmt::Call {
                    abi: None,
                    kind: velk::ir::CallKind::Invoke,
                    target: Some(0x1000),
                    through: None,
                    convention: Convention::SysV,
                    args: Some(vec![]),
                    floats_named: false,
                    outputs: vec![CallOutput {
                        register: 0,
                        dest: RegRef {
                            index: VARIABLE_BASE,
                            width: 64,
                        },
                    }],
                    clobbers: Some(Registers(1)),
                    via: None,
                },
                Stmt::Ret { value },
            ],
        );
        let symbols = velk::render::Symbols {
            functions: [(0x1000, "helper".into())].into(),
            function_returns: [(0x1000, CType::U64)].into(),
            ..Default::default()
        };
        let code = velk::render::render(&ir, &[], &symbols, &[]);
        assert!(code.contains(" = helper();"), "{code}");
        assert!(
            !code
                .lines()
                .any(|line| line.contains("return ") && line.contains("helper(")),
            "{code}"
        );
    }
}

#[test]
fn printed_small_parameter_spills_reuse_the_parameter() {
    let mut candidates = Vec::new();
    for bytes in [1, 2] {
        for signed in [false, true] {
            let slot = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const((-16i64) as u64));
            let mut ir = synthetic_ir(
                &format!("spill_{bytes}_{signed}"),
                vec![Param {
                    index: 7,
                    name: "value".into(),
                    ty: CType::int(bytes, signed),
                }],
                CType::U64,
                vec![
                    Stmt::Store {
                        addr: slot.clone(),
                        value: Expr::reg(7, 64),
                        width: bytes,
                    },
                    Stmt::Ret {
                        value: Expr::Load {
                            addr: Box::new(slot),
                            width: bytes,
                            signed,
                        },
                    },
                ],
            );
            // Keep the public parameter's type available to the renderer.
            ir.value_types.insert(7, CType::int(bytes, signed));
            let candidate = printed_candidate(
                ir,
                [0, 1, 127, 128, 255, 32767, 32768, 65535, u64::MAX]
                    .into_iter()
                    .map(|x| vec![x])
                    .collect(),
            );
            assert!(!candidate.code.contains("[sp"), "{}", candidate.code);
            assert!(!candidate.code.contains("local_"), "{}", candidate.code);
            candidates.push(candidate);
        }
    }
    check_candidates("small_parameter_spills", candidates, Mode::Registers, &[]);
}

#[test]
fn printed_small_spill_with_overlapping_store_keeps_its_bytes() {
    let mut candidates = Vec::new();
    for (case, offset) in [-16i64, -1].into_iter().enumerate() {
        let slot = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const(offset as u64));
        let ir = synthetic_ir(
            &format!("overlapping_small_spill_{case}"),
            vec![Param {
                index: 7,
                name: "value".into(),
                ty: CType::int(2, false),
            }],
            CType::U64,
            vec![
                Stmt::Store {
                    addr: slot.clone(),
                    value: Expr::reg(7, 64),
                    width: 2,
                },
                Stmt::Store {
                    addr: Expr::bin(
                        BinOp::Add,
                        Expr::reg(4, 64),
                        Expr::Const((offset + 1) as u64),
                    ),
                    value: Expr::Const(0x56),
                    width: 1,
                },
                Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(slot),
                        width: 2,
                        signed: false,
                    },
                },
            ],
        );
        let candidate = printed_candidate(
            ir,
            [0, 255, 256, 65535].into_iter().map(|x| vec![x]).collect(),
        );
        if offset == -1 {
            assert!(candidate.code.contains("arg_0"), "{}", candidate.code);
        } else {
            assert!(candidate.code.contains("[sp"), "{}", candidate.code);
        }
        candidates.push(candidate);
    }
    check_candidates("overlapping_small_spill", candidates, Mode::Memory, &[]);
}

#[test]
fn printed_single_use_call_arithmetic_keeps_width_and_effects() {
    let scratch = scratch_dir("call-arithmetic");
    let mut text = String::from(HEADER);
    text.push_str(
        "static unsigned effects;\nstatic uint64_t helper(uint64_t x) { ++effects; return x; }\n",
    );
    for width in [32, 64] {
        for (suffix, value) in [
            ("wide", Expr::reg(VARIABLE_BASE, 64)),
            (
                "sum",
                Expr::bin(BinOp::Add, Expr::reg(VARIABLE_BASE, width), Expr::Const(1)),
            ),
            (
                "product",
                Expr::bin(BinOp::Mul, Expr::reg(VARIABLE_BASE, width), Expr::Const(3)),
            ),
            (
                "shift",
                Expr::bin(BinOp::Shr, Expr::reg(VARIABLE_BASE, width), Expr::Const(7)),
            ),
        ] {
            let name = format!("{suffix}_{width}");
            let ir = synthetic_ir(
                &name,
                vec![Param {
                    index: 7,
                    name: "x".into(),
                    ty: CType::U64,
                }],
                CType::U64,
                vec![
                    Stmt::Call {
                        abi: None,
                        kind: velk::ir::CallKind::Invoke,
                        target: Some(0x1000),
                        through: None,
                        convention: Convention::SysV,
                        args: Some(vec![Expr::reg(7, 64)]),
                        floats_named: false,
                        outputs: vec![CallOutput {
                            register: 0,
                            dest: RegRef {
                                index: VARIABLE_BASE,
                                width,
                            },
                        }],
                        clobbers: Some(Registers(1)),
                        via: None,
                    },
                    Stmt::Ret { value },
                ],
            );
            let symbols = velk::render::Symbols {
                functions: [(0x1000, "helper".into())].into(),
                function_returns: [(0x1000, CType::U64)].into(),
                ..Default::default()
            };
            let code = velk::render::render(&ir, &[], &symbols, &[]);
            assert!(!code.contains(" v1;"), "{code}");
            assert!(
                code.contains("return ") && code.contains("helper(x)"),
                "{code}"
            );
            text.push_str(&code);
        }
    }
    text.push_str("int main(void) {\n");
    for x in [
        0u64,
        1,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_ffff,
        0x8123_4567_89ab_cdef,
        u64::MAX,
    ] {
        for width in [32, 64] {
            let value = if width == 32 { x & 0xffff_ffff } else { x };
            for (suffix, want) in [
                ("wide", value),
                ("sum", value.wrapping_add(1)),
                ("product", value.wrapping_mul(3)),
                ("shift", value >> 7),
            ] {
                writeln!(text, "effects = 0; if ({suffix}_{width}(UINT64_C({x})) != UINT64_C({want}) || effects != 1) return 1;").unwrap();
            }
        }
    }
    text.push_str("return 0;\n}\n");
    let source = Program {
        text,
        ranges: Vec::new(),
    };
    for level in LEVELS {
        let executable = build(&source, &scratch, level, &[]);
        assert_eq!(run(&executable, ""), "");
    }
    std::fs::remove_dir_all(scratch).ok();
}

#[test]
fn printed_frame_reads_stay_before_stores_that_change_their_bytes() {
    let frame = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const((-8i64) as u64));
    let mut ir = synthetic_ir(
        "read_before_store",
        vec![Param {
            index: 7,
            name: "input".into(),
            ty: CType::U32,
        }],
        CType::U32,
        vec![
            Stmt::Store {
                addr: frame.clone(),
                value: Expr::reg(7, 32),
                width: 4,
            },
            Stmt::Assign {
                dest: RegRef {
                    index: VARIABLE_BASE,
                    width: 32,
                },
                value: Expr::bin(
                    BinOp::And,
                    Expr::Load {
                        addr: Box::new(frame.clone()),
                        width: 4,
                        signed: false,
                    },
                    Expr::Const(0x4c40ecca),
                ),
            },
            Stmt::Store {
                addr: frame,
                value: Expr::Const(1),
                width: 4,
            },
            Stmt::Ret {
                value: Expr::reg(VARIABLE_BASE, 32),
            },
        ],
    );
    let original = ir.clone();
    velk::passes::copies::copy_propagate_guarded(&mut ir);
    let mut candidate = printed_candidate(
        ir,
        [0, 1, 2, 0x4c40ecca, u32::MAX]
            .into_iter()
            .map(|x| vec![u64::from(x)])
            .collect(),
    );
    candidate.ir = original;
    check_candidates("read-before-store", vec![candidate], Mode::Registers, &[]);
}

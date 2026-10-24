use super::*;

#[test]
fn printed_integer_shifts_and_pointer_choices_avoid_identity_casts() {
    let mut candidates = Vec::new();
    let edges = [
        0,
        1,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_ffff,
        1 << 63,
        u64::MAX,
    ];
    let inputs: Vec<Vec<u64>> = edges
        .iter()
        .flat_map(|x| edges.iter().map(move |y| vec![*x, *y]))
        .collect();
    let shifted = Expr::bin(BinOp::Shl, Expr::reg(7, 64), Expr::Const(8));
    let ir = synthetic_ir(
        "identity_shift",
        vec![
            Param {
                index: 7,
                name: "x".into(),
                ty: CType::U64,
            },
            Param {
                index: 6,
                name: "y".into(),
                ty: CType::U64,
            },
        ],
        CType::U64,
        vec![Stmt::Ret {
            value: Expr::bin(
                BinOp::DivU,
                shifted,
                Expr::bin(BinOp::Or, Expr::reg(6, 64), Expr::Const(1)),
            ),
        }],
    );
    let candidate = printed_candidate(ir, inputs.clone());
    assert!(!candidate.code.contains("(uint64_t)"), "{}", candidate.code);
    candidates.push(candidate);
    for (name, other, null) in [
        ("same_pointers", CType::U64, false),
        ("null_pointer", CType::U64, true),
        ("different_pointers", CType::U32, false),
    ] {
        let ty = CType::pointer_to(CType::U64);
        let ir = synthetic_ir(
            name,
            vec![
                Param {
                    index: 7,
                    name: "x".into(),
                    ty: ty.clone(),
                },
                Param {
                    index: 6,
                    name: "y".into(),
                    ty: CType::pointer_to(other),
                },
            ],
            ty,
            vec![Stmt::Ret {
                value: Expr::Select {
                    cond: Cond::Ne,
                    lhs: Box::new(Expr::reg(7, 64)),
                    rhs: Box::new(Expr::Const(0)),
                    then: Box::new(Expr::reg(7, 64)),
                    els: Box::new(if null {
                        Expr::Const(0)
                    } else {
                        Expr::reg(6, 64)
                    }),
                },
            }],
        );
        let candidate = printed_candidate(ir, inputs.clone());
        assert_eq!(
            candidate.code.contains("return (uint64_t *)"),
            name == "different_pointers",
            "{}",
            candidate.code
        );
        candidates.push(candidate);
    }
    check_candidates("identity_casts", candidates, Mode::Memory, &[]);
}

#[test]
fn printed_byte_buffer_accesses_keep_signedness_and_wider_accesses() {
    let slot = |offset: u64| {
        Expr::bin(
            BinOp::Add,
            Expr::reg(4, 64),
            Expr::Const(offset.wrapping_sub(64)),
        )
    };
    let mut candidates = Vec::new();
    for (signed, width) in [(false, 1), (true, 1), (false, 2)] {
        let read = Expr::Load {
            addr: Box::new(slot(0)),
            width,
            signed,
        };
        let ret = Stmt::Ret { value: read };
        let mut ir = synthetic_ir(
            if signed {
                "signed_buffer_byte"
            } else if width == 1 {
                "buffer_byte"
            } else {
                "buffer_word"
            },
            vec![Param {
                index: 7,
                name: "x".into(),
                ty: CType::U64,
            }],
            CType::U64,
            vec![
                Stmt::Call {
                    kind: velk::ir::CallKind::Invoke,
                    target: Some(0x1000),
                    through: None,
                    convention: Convention::SysV,
                    args: Some(vec![slot(0), Expr::Const(0), Expr::Const(16)]),
                    floats_named: false,
                    outputs: Vec::new(),
                    clobbers: Some(Default::default()),
                    via: None,
                },
                Stmt::Store {
                    addr: slot(0),
                    value: Expr::Const(0),
                    width: 2,
                },
                Stmt::Store {
                    addr: slot(0),
                    value: Expr::reg(7, 64),
                    width: 1,
                },
                ret.clone(),
            ],
        );
        let mut symbols = velk::render::Symbols::default();
        symbols.functions.insert(0x1000, "memset".into());
        let code = velk::render::render(&ir, &[], &symbols, &[]);
        assert!(!code.contains("*(uint8_t *)(local_"), "{code}");
        assert!(code.contains("*(local_"), "{code}");
        if width == 2 {
            assert!(code.contains("*(uint16_t *)"), "{code}");
        }
        ir.blocks[0].stmts = (0..16)
            .map(|offset| Stmt::Store {
                addr: slot(offset),
                value: Expr::Const(0),
                width: 1,
            })
            .collect();
        ir.blocks[0].stmts.push(Stmt::Store {
            addr: slot(0),
            value: Expr::reg(7, 64),
            width: 1,
        });
        ir.blocks[0].stmts.push(ret);
        let mut candidate = printed_candidate(ir, (0..256).map(|value| vec![value]).collect());
        candidate.code = format!("#include <string.h>\n{code}");
        candidates.push(candidate);
    }
    check_candidates("byte_buffer_casts", candidates, Mode::Memory, &[]);
}

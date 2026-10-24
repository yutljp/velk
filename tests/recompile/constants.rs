use super::*;

#[test]
fn printed_constants_preserve_promotions_and_signed_values() {
    let mut candidates = Vec::new();
    let inputs: Vec<Vec<u64>> = [
        0,
        1,
        255,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_ffff,
        1 << 63,
        u64::MAX,
    ]
    .into_iter()
    .map(|value| vec![value])
    .collect();
    for (bits, ty) in [
        (32, CType::U32),
        (64, CType::U64),
        (32, CType::I32),
        (64, CType::I64),
    ] {
        for constant in [
            1,
            1000,
            100000,
            3_000_000_000,
            10_000_000_000,
            18_000_000_000_000_000_000,
            0x8000_0000,
            0xffff_ffff,
            1 << 63,
            u64::MAX,
        ] {
            for op in [BinOp::Add, BinOp::Mul, BinOp::DivU, BinOp::And] {
                let ir = synthetic_ir(
                    &format!("constant_{bits}_{constant}_{op:?}"),
                    vec![Param {
                        index: 7,
                        name: "x".into(),
                        ty: ty.clone(),
                    }],
                    CType::U64,
                    vec![Stmt::Ret {
                        value: Expr::bin(op, Expr::reg(7, bits), Expr::Const(constant)),
                    }],
                );
                let candidate = printed_candidate(ir, inputs.clone());
                if constant == 1 && op == BinOp::Add {
                    assert!(candidate.code.contains(" + 1"), "{}", candidate.code);
                }
                if constant == 1 && op == BinOp::And {
                    assert!(candidate.code.contains(" & 0x1"), "{}", candidate.code);
                }
                if op == BinOp::Mul {
                    for (value, literal) in [
                        (3_000_000_000, "3000000000U"),
                        (10_000_000_000, "10000000000LL"),
                        (18_000_000_000_000_000_000, "18000000000000000000ULL"),
                    ] {
                        if constant == value {
                            assert!(candidate.code.contains(literal), "{}", candidate.code);
                        }
                    }
                }
                candidates.push(candidate);
            }
            for cond in [Cond::Lt, Cond::Cc, Cond::Eq] {
                let ir = synthetic_ir(
                    &format!("compare_{bits}_{constant}_{cond:?}"),
                    vec![Param {
                        index: 7,
                        name: "x".into(),
                        ty: ty.clone(),
                    }],
                    CType::U64,
                    vec![Stmt::Ret {
                        value: Expr::Select {
                            cond,
                            lhs: Box::new(Expr::reg(7, bits)),
                            rhs: Box::new(Expr::Const(constant)),
                            then: Box::new(Expr::Const(1)),
                            els: Box::new(Expr::Const(0)),
                        },
                    }],
                );
                candidates.push(printed_candidate(ir, inputs.clone()));
            }
        }
    }
    for (ty, constant, expected) in [
        (CType::I32, 0xffff_ffff, "return -1;"),
        (CType::I64, u64::MAX, "return -1;"),
        (CType::I64, 1 << 63, "(-9223372036854775807LL - 1)"),
    ] {
        let ir = synthetic_ir(
            "signed_constant",
            vec![],
            ty,
            vec![Stmt::Ret {
                value: Expr::Const(constant),
            }],
        );
        let candidate = printed_candidate(ir, vec![vec![]]);
        assert!(candidate.code.contains(expected), "{}", candidate.code);
        candidates.push(candidate);
    }
    check_candidates("constant_bases", candidates, Mode::Registers, &[]);
}

#[test]
fn writable_printable_bytes_keep_their_storage() {
    let scratch = scratch_dir("writable-printable-bytes");
    let original = scratch.join("original.c");
    let executable = scratch.join("original");
    let source = "unsigned char buffer[128] = \"hhhhhhhh\";\n__attribute__((noinline)) unsigned update(unsigned index) { unsigned char *volatile p = buffer; p[index & 7] = 17; return p[index & 7]; }\nint main(void) { return update(4) != 17; }\n";
    std::fs::write(&original, source).unwrap();
    let compiled = Command::new(compiler())
        .args(["-O0", "-fno-stack-protector"])
        .arg(&original)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{compiled:?}");
    let mut binary = Binary::open(&executable).unwrap();
    let prefix = if cfg!(target_os = "macos") { "_" } else { "" };
    let address = binary.find(&format!("{prefix}update")).unwrap().addr;
    let buffer = *binary
        .image()
        .data_symbols
        .iter()
        .find(|(_, name)| *name == &format!("{prefix}buffer"))
        .unwrap()
        .0;
    let mut analysis = binary.analysis(address, None).unwrap().clone();
    analysis.ir.name = Some("printed_update".into());
    let code = velk::render::render(&analysis.ir, &analysis.references, &Default::default(), &[]);
    assert!(!code.contains("\"hhhhhhhh\""), "{code}");
    let mut code = code;
    for offset in 0..128 {
        for suffix in ["ULL", ""] {
            code = code.replace(
                &format!("0x{:x}{suffix}", buffer + offset),
                &format!("(uintptr_t)(buffer + {offset})"),
            );
        }
    }
    let program = Program {
        text: format!(
            "{HEADER}\nunsigned char buffer[128] = \"hhhhhhhh\";\n{code}\nint main(void) {{ return printed_update(4) != 17 || buffer[4] != 17; }}\n"
        ),
        ranges: Vec::new(),
    };
    for level in LEVELS {
        let executable = build(&program, &scratch, level, &[]);
        assert_eq!(run(&executable, ""), "", "{}", program.text);
    }
    std::fs::remove_dir_all(scratch).ok();
}

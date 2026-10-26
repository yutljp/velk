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
    for offset in (0..128).rev() {
        let address = buffer + offset;
        for literal in [format!("0x{address:x}"), address.to_string()] {
            for suffix in ["ULL", "LL", "U", ""] {
                code = code.replace(
                    &format!("{literal}{suffix}"),
                    &format!("(uintptr_t)(buffer + {offset})"),
                );
            }
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

#[test]
fn printed_high_products_use_widened_integer_multiplication() {
    let mut candidates = Vec::new();
    let values = [0, 1, u64::MAX, 1 << 63, (1 << 63) - 1, 0x101010101010101];
    for op in [BinOp::MulHigh, BinOp::MulHighS] {
        let ir = synthetic_ir(
            &format!("high_product_{op:?}"),
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
                value: Expr::bin(op, Expr::reg(7, 64), Expr::reg(6, 64)),
            }],
        );
        let mut inputs = Vec::new();
        for x in values {
            for y in values {
                inputs.push(vec![x, y]);
            }
        }
        let candidate = printed_candidate(ir, inputs);
        assert!(candidate.code.contains("__int128"), "{}", candidate.code);
        assert!(!candidate.code.contains("__smulh"), "{}", candidate.code);
        assert!(!candidate.code.contains("__umulh"), "{}", candidate.code);
        candidates.push(candidate);
    }
    check_candidates("high-products", candidates, Mode::Registers, &[]);
}

#[test]
fn printed_narrow_stores_discard_constant_upper_bits() {
    let mut candidates = Vec::new();
    for width in [1, 2, 4] {
        let ir = synthetic_ir(
            &format!("narrow_store_{width}"),
            vec![Param {
                index: 7,
                name: "p".into(),
                ty: CType::U64,
            }],
            CType::U64,
            vec![
                Stmt::Store {
                    addr: Expr::reg(7, 64),
                    value: Expr::Const(0x10000fffe),
                    width,
                },
                Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(Expr::reg(7, 64)),
                        width,
                        signed: false,
                    },
                },
            ],
        );
        let candidate = printed_candidate(ir, vec![vec![REGION]]);
        assert!(
            !candidate.code.contains("0x10000fffe"),
            "{}",
            candidate.code
        );
        candidates.push(candidate);
    }
    check_candidates("narrow-store-constants", candidates, Mode::Memory, &[]);
}

#[test]
fn printed_zero_extended_constant_returns_keep_unsigned_values() {
    let scratch = scratch_dir("constant-return-extension");
    for (target, body) in [
        ("x86_64-unknown-linux-gnu", "movl $0xfffffffb, %eax\nret"),
        ("aarch64-unknown-linux-gnu", "mov w0, #-5\nret"),
    ] {
        let assembly = scratch.join(format!("{target}.s"));
        let object = scratch.join(format!("{target}.o"));
        std::fs::write(&assembly, format!(".text\n.globl return_bits\n.type return_bits,@function\nreturn_bits:\n{body}\n.size return_bits, .-return_bits\n")).unwrap();
        let compiled = Command::new(compiler())
            .arg(format!("--target={target}"))
            .arg("-c")
            .arg(&assembly)
            .arg("-o")
            .arg(&object)
            .output()
            .unwrap();
        assert!(compiled.status.success(), "{compiled:?}");
        let mut binary = Binary::open(&object).unwrap();
        let address = binary.find("return_bits").unwrap().addr;
        let code = binary.decompile(address, None, None).unwrap();
        syntax::run_printed(
            &code,
            "",
            "if ((uint64_t)return_bits() != UINT64_C(0xfffffffb)) return 1;",
        );
    }
    std::fs::remove_dir_all(scratch).ok();
}

#[test]
fn printed_partial_writes_drop_unobserved_constant_upper_bits() {
    let mut ir = synthetic_ir(
        "low_partial_value",
        vec![Param {
            index: 7,
            name: "x".into(),
            ty: CType::U64,
        }],
        CType::U64,
        vec![
            Stmt::Assign {
                dest: velk::ir::RegRef {
                    index: 40,
                    width: 64,
                },
                value: Expr::bin(
                    BinOp::Or,
                    Expr::Const(0x100010000),
                    Expr::bin(BinOp::And, Expr::reg(7, 64), Expr::Const(0xffff)),
                ),
            },
            Stmt::Ret {
                value: Expr::SignExtend {
                    value: Box::new(Expr::reg(40, 64)),
                    width: 1,
                },
            },
        ],
    );
    let original = ir.clone();
    velk::ssa::narrow_partial_writes(&mut ir);
    let mut candidate = printed_candidate(
        ir,
        [0, 1, 255, 256, 65535, u64::MAX]
            .into_iter()
            .map(|x| vec![x])
            .collect(),
    );
    assert!(
        !candidate.code.contains("0x100010000"),
        "{}",
        candidate.code
    );
    candidate.ir = original;
    check_candidates(
        "partial-constant-bits",
        vec![candidate],
        Mode::Registers,
        &[],
    );
}

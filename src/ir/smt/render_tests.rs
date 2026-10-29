use super::*;
use crate::ir::{CType, FunctionIr, Param, Stmt};
use crate::loader::Isa;

#[test]
fn wrapping_arithmetic_avoids_c_overflow() {
    use std::io::Write;

    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("SKIP C overflow regression: clang unavailable");
        return;
    }
    let value = raw_bin(
        BinOp::And,
        raw_bin(BinOp::Add, Expr::reg(7, 32), Expr::reg(6, 32)),
        Expr::Const(0xff),
    );
    let mut ir = FunctionIr::single_block(Isa::X86_64, vec![Stmt::Ret { value, at: None }]);
    ir.name = Some("masked_sum".to_owned());
    ir.params = [7, 6]
        .into_iter()
        .enumerate()
        .map(|(position, index)| Param {
            index,
            name: format!("a{position}"),
            ty: CType::I32,
        })
        .collect();
    let code = crate::render::render(&ir, &[], &crate::render::Symbols::default(), &[]);
    let index = raw_bin(BinOp::Add, Expr::reg(6, 64), Expr::Const(2));
    let address = raw_bin(
        BinOp::Add,
        Expr::reg(7, 64),
        raw_bin(BinOp::Mul, index, Expr::Const(8)),
    );
    let mut indexed = FunctionIr::single_block(
        Isa::X86_64,
        vec![Stmt::Ret {
            value: Expr::Load {
                addr: Box::new(address),
                width: 8,
                signed: false,
            },
            at: None,
        }],
    );
    indexed.name = Some("indexed_value".to_owned());
    indexed.params = vec![
        Param {
            index: 7,
            name: "base".to_owned(),
            ty: CType::pointer_to(CType::I64),
        },
        Param {
            index: 6,
            name: "offset".to_owned(),
            ty: CType::I64,
        },
    ];
    let pointer_code =
        crate::render::render(&indexed, &[], &crate::render::Symbols::default(), &[]);
    let mut negated = FunctionIr::single_block(
        Isa::X86_64,
        vec![Stmt::Ret {
            value: raw_bin(BinOp::Sub, Expr::Const(0), Expr::reg(7, 64)),
            at: None,
        }],
    );
    negated.name = Some("negated_value".to_owned());
    negated.params = vec![Param {
        index: 7,
        name: "input".to_owned(),
        ty: CType::I64,
    }];
    let negative_code =
        crate::render::render(&negated, &[], &crate::render::Symbols::default(), &[]);
    let mut arithmetic_code = String::new();
    for bits in [32, 64] {
        for (name, op) in [("quotient", BinOp::DivS), ("remainder", BinOp::ModS)] {
            let mut divided = FunctionIr::single_block(
                Isa::X86_64,
                vec![Stmt::Ret {
                    value: raw_bin(op, Expr::reg(7, bits), Expr::reg(6, bits)),
                    at: None,
                }],
            );
            divided.name = Some(format!("{name}_{bits}"));
            divided.params = [7, 6]
                .into_iter()
                .enumerate()
                .map(|(position, index)| Param {
                    index,
                    name: format!("a{position}"),
                    ty: CType::int(bits / 8, true),
                })
                .collect();
            arithmetic_code.push_str(&crate::render::render(
                &divided,
                &[],
                &crate::render::Symbols::default(),
                &[],
            ));
        }
    }
    for bits in [8, 64] {
        for (name, op) in [
            ("leading", Operation::CountLeadingZeros(bits)),
            ("trailing", Operation::CountTrailingZeros(bits)),
        ] {
            let mut counted = FunctionIr::single_block(
                Isa::X86_64,
                vec![Stmt::Ret {
                    value: Expr::apply(op, vec![Expr::reg(7, 64)]),
                    at: None,
                }],
            );
            counted.name = Some(format!("{name}_{bits}"));
            counted.params = vec![Param {
                index: 7,
                name: "input".to_owned(),
                ty: CType::U64,
            }];
            arithmetic_code.push_str(&crate::render::render(
                &counted,
                &[],
                &crate::render::Symbols::default(),
                &[],
            ));
        }
    }
    let source = format!(
        "#include <stdint.h>\n{code}\n{pointer_code}\n{negative_code}\n{arithmetic_code}\nint main(void) {{ int64_t data[8] = {{10,20,30,40,50,60,70,80}}; return masked_sum(0x40000000, 0x40000001) != 1 || indexed_value(data + 3, -3) != 30 || indexed_value(data + 3, -5) != 10 || indexed_value(data + 3, 0) != 60 || negated_value(INT64_MIN) != (uint64_t)INT64_MIN || quotient_32(INT32_MIN, -1) != UINT64_C(0x80000000) || remainder_32(INT32_MIN, -1) != 0 || quotient_64(INT64_MIN, -1) != (uint64_t)INT64_MIN || remainder_64(INT64_MIN, -1) != 0 || quotient_64(-7, 3) != (uint64_t)-2 || remainder_32(-7, 3) != UINT64_C(0xffffffff) || leading_8(0) != 8 || leading_8(254) != 0 || trailing_8(256) != 8 || leading_64(0) != 64 || trailing_64(0) != 64; }}\n"
    );
    let directory = format!("target/smt-overflow-{}", std::process::id());
    std::fs::create_dir_all(&directory).expect("create C regression directory");
    let executable = format!("{directory}/check");
    let mut compiler = Command::new("clang")
        .args([
            "-x",
            "c",
            "-std=c11",
            "-fsanitize=undefined",
            "-fno-sanitize-recover=undefined",
            "-o",
            &executable,
            "-",
        ])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start C regression compiler");
    compiler
        .stdin
        .take()
        .expect("piped C compiler stdin")
        .write_all(source.as_bytes())
        .expect("write C regression source");
    let output = compiler.wait_with_output().expect("wait for C compiler");
    assert!(
        output.status.success(),
        "C regression must compile: {}\n{code}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(&executable)
        .output()
        .expect("execute printed C regression");
    std::fs::remove_dir_all(&directory).expect("remove C regression directory");
    assert!(
        output.status.success(),
        "printed C must execute without undefined behavior: {}\n{code}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn compiled_scalar_c_is_equivalent_to_ir() {
    if !Proofs::available() {
        return;
    }
    for executable in ["uv", "clang"] {
        if Command::new(executable).arg("--version").output().is_err() {
            eprintln!("SKIP rendered C SMT proofs: {executable} unavailable");
            return;
        }
    }
    let mut source = String::from("#include <stdint.h>\n");
    let mut originals = BTreeMap::new();
    for bits in [8, 16, 32, 64] {
        let types = [CType::int(bits / 8, false), CType::int(bits / 8, true)];
        for (signedness_index, ty) in types.into_iter().enumerate() {
            let mut reads = vec![bits];
            if bits < 64 {
                reads.push(64);
            }
            for read in reads {
                let x = Expr::reg(7, read);
                let y = Expr::reg(6, read);
                let mut cases = vec![
                    x.clone(),
                    raw_bin(BinOp::Sub, Expr::Const(0), x.clone()),
                    raw_bin(BinOp::Sub, Expr::Const(0), Expr::Const(1)),
                ];
                for width in [8, 16, 32, 64] {
                    for op in [
                        Operation::CountLeadingZeros(width),
                        Operation::CountTrailingZeros(width),
                    ] {
                        cases.push(Expr::apply(op, vec![x.clone()]));
                    }
                }
                for op in [
                    BinOp::Add,
                    BinOp::Sub,
                    BinOp::Mul,
                    BinOp::And,
                    BinOp::Or,
                    BinOp::Xor,
                ] {
                    cases.push(raw_bin(op, x.clone(), y.clone()));
                    cases.push(raw_bin(op, x.clone(), Expr::Const(u64::MAX)));
                }
                for op in [BinOp::DivU, BinOp::ModU, BinOp::DivS, BinOp::ModS] {
                    cases.push(raw_bin(op, x.clone(), Expr::Const(3)));
                    for divisor in [1, u64::MAX, 1 << (read - 1)] {
                        cases.push(raw_bin(op, x.clone(), Expr::Const(divisor)));
                        if op == BinOp::DivS {
                            cases.push(Expr::SignExtend {
                                value: Box::new(raw_bin(op, x.clone(), Expr::Const(divisor))),
                                width: read / 8,
                            });
                        }
                    }
                }
                for op in [BinOp::MulHigh, BinOp::MulHighS] {
                    cases.push(raw_bin(op, x.clone(), Expr::Const(3)));
                }
                for op in [BinOp::Shl, BinOp::Shr, BinOp::Sar] {
                    cases.push(raw_bin(op, x.clone(), y.clone()));
                    for amount in [0, 1, 31, 63, 64] {
                        cases.push(raw_bin(op, x.clone(), Expr::Const(amount)));
                    }
                }
                for mask in [0xff, 0xffff, 0xffff_ffff, u64::MAX] {
                    cases.push(raw_bin(
                        BinOp::And,
                        raw_bin(BinOp::Add, x.clone(), y.clone()),
                        Expr::Const(mask),
                    ));
                }
                for bytes in [1, 2, 4, 8] {
                    cases.push(Expr::SignExtend {
                        value: Box::new(x.clone()),
                        width: bytes,
                    });
                }
                for count_bits in [8, 16, 32, 64] {
                    for op in [
                        Operation::CountLeadingZeros(count_bits),
                        Operation::CountTrailingZeros(count_bits),
                    ] {
                        cases.push(Expr::Apply {
                            op,
                            args: vec![x.clone()],
                        });
                    }
                }
                for cond in &CONDITIONS[..10] {
                    cases.push(Expr::Select {
                        cond: *cond,
                        lhs: Box::new(x.clone()),
                        rhs: Box::new(y.clone()),
                        then: Box::new(Expr::Const(1)),
                        els: Box::new(Expr::Const(0)),
                    });
                    let truth = Expr::Select {
                        cond: *cond,
                        lhs: Box::new(y.clone()),
                        rhs: Box::new(Expr::Const(0)),
                        then: Box::new(Expr::Const(1)),
                        els: Box::new(Expr::Const(0)),
                    };
                    for (then, els) in [
                        (truth.clone(), Expr::Const(0)),
                        (Expr::Const(1), truth),
                        (x.clone(), Expr::Const(u64::MAX)),
                        (Expr::Const(1 << 63), y.clone()),
                    ] {
                        cases.push(Expr::Select {
                            cond: *cond,
                            lhs: Box::new(x.clone()),
                            rhs: Box::new(Expr::Const(0)),
                            then: Box::new(then),
                            els: Box::new(els),
                        });
                    }
                }
                for (index, value) in cases.into_iter().enumerate() {
                    let name = format!("smt_c_{bits}_{signedness_index}_{read}_{index}");
                    let mut ir = FunctionIr::single_block(
                        Isa::X86_64,
                        vec![Stmt::Ret {
                            value: value.clone(),
                            at: None,
                        }],
                    );
                    ir.name = Some(name.clone());
                    ir.params = [7, 6]
                        .into_iter()
                        .enumerate()
                        .map(|(position, index)| Param {
                            index,
                            name: format!("a{position}"),
                            ty: ty.clone(),
                        })
                        .collect();
                    source.push_str(&crate::render::render(
                        &ir,
                        &[],
                        &crate::render::Symbols::default(),
                        &[],
                    ));
                    source.push('\n');
                    let mut registers = BTreeMap::new();
                    for register in [7, 6] {
                        let input = low(&format!("r{register}"), u32::from(bits));
                        registers.insert(
                            register,
                            if signedness_index == 1 {
                                signed(&input, u32::from(bits))
                            } else {
                                input
                            },
                        );
                    }
                    originals.insert(name, super::value(&value, &registers));
                }
            }
        }
    }
    prove_rendered(source, originals);
}

fn prove_rendered(source: String, originals: BTreeMap<String, Value>) {
    use std::io::Write;
    let names: Vec<&String> = originals.keys().collect();
    let first = names.first().expect("rendered corpus is nonempty");
    std::fs::write(format!("target/{first}.c"), &source).expect("save rendered C corpus");
    let request = serde_json::json!({ "source": source, "names": names });
    let mut child = Command::new("uv")
        .args(["run", "--no-project", "tests/smt_c.py"])
        .env("UV_CACHE_DIR", "target/uv-cache")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start C AST translator");
    let mut stdin = child.stdin.take().expect("piped translator stdin");
    stdin
        .write_all(request.to_string().as_bytes())
        .expect("write C translation request");
    drop(stdin);
    let output = child.wait_with_output().expect("wait for C translator");
    assert!(
        output.status.success(),
        "C AST translation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let results: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("C translation JSON");
    let mut proofs = Proofs::default();
    for result in results.as_array().expect("C translation array") {
        let name = result["name"].as_str().expect("function name");
        let value = originals.get(name).expect("requested function");
        proofs.rendered(
            format!("rendered/{name}"),
            value,
            result["term"].as_str().expect("C SMT term"),
            result["defined"].as_str().expect("C validity condition"),
        );
    }
    proofs.check();
}

#[test]
fn compiled_assignments_and_return_conversions_are_equivalent() {
    if !Proofs::available() {
        return;
    }
    let mut source = String::from("#include <stdint.h>\n");
    let mut originals = BTreeMap::new();
    for bits in [8, 16, 32, 64] {
        for signed in [false, true] {
            let ty = CType::int(bits / 8, signed);
            let x = Expr::reg(7, 64);
            let y = Expr::reg(6, 64);
            let mask = crate::ir::semantics::mask(u32::from(bits));
            let mut expressions = vec![
                x.clone(),
                raw_bin(BinOp::Add, x.clone(), y.clone()),
                raw_bin(BinOp::Sub, x.clone(), y.clone()),
                raw_bin(BinOp::Mul, x.clone(), Expr::Const(3)),
            ];
            for op in [BinOp::Add, BinOp::Sub, BinOp::Xor] {
                expressions.push(raw_bin(
                    BinOp::And,
                    raw_bin(op, Expr::reg(3, bits), x.clone()),
                    Expr::Const(mask),
                ));
            }
            for (case, expression) in expressions.into_iter().enumerate() {
                for local in [false, true] {
                    let name = format!("smt_assignment_{bits}_{signed}_{case}_{local}");
                    let statements = if local {
                        vec![
                            Stmt::Assign {
                                dest: crate::ir::RegRef {
                                    index: 3,
                                    width: bits,
                                },
                                value: y.clone(),
                                at: None,
                            },
                            Stmt::Assign {
                                dest: crate::ir::RegRef {
                                    index: 3,
                                    width: bits,
                                },
                                value: expression.clone(),
                                at: None,
                            },
                            Stmt::Ret {
                                value: raw_bin(
                                    BinOp::Add,
                                    Expr::reg(3, bits),
                                    raw_bin(BinOp::Shr, Expr::reg(3, bits), Expr::Const(1)),
                                ),
                                at: None,
                            },
                        ]
                    } else {
                        // Give the update-shaped expressions a reaching definition too.
                        vec![
                            Stmt::Assign {
                                dest: crate::ir::RegRef {
                                    index: 3,
                                    width: bits,
                                },
                                value: y.clone(),
                                at: None,
                            },
                            Stmt::Ret {
                                value: expression.clone(),
                                at: None,
                            },
                        ]
                    };
                    let mut expected = returned(&statements);
                    expected.term = if signed {
                        super::signed(&expected.term, u32::from(bits))
                    } else {
                        low(&expected.term, u32::from(bits))
                    };
                    let mut ir = FunctionIr::single_block(Isa::X86_64, statements);
                    ir.name = Some(name.clone());
                    ir.ret_type = ty.clone();
                    ir.params = [7, 6]
                        .into_iter()
                        .enumerate()
                        .map(|(position, index)| Param {
                            index,
                            name: format!("a{position}"),
                            ty: CType::U64,
                        })
                        .collect();
                    source.push_str(&crate::render::render(
                        &ir,
                        &[],
                        &crate::render::Symbols::default(),
                        &[],
                    ));
                    source.push('\n');
                    originals.insert(name, expected);
                }
            }
        }
    }
    prove_rendered(source, originals);
}

#[test]
fn recovered_argument_conversions_preserve_native_pointer_bits() {
    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for pointer_bits in [32, 64] {
        let pointer = low("r0", pointer_bits);
        for integer_bits in [8, 16, 32, 64] {
            let through_integer = low(&pointer, integer_bits);
            let machine_argument = low("r0", pointer_bits.min(integer_bits));
            proofs.predicate(
                format!("pointer argument/{pointer_bits}/{integer_bits}"),
                &through_integer,
                &machine_argument,
            );
            proofs.predicate(
                format!("signed pointer argument/{pointer_bits}/{integer_bits}"),
                &super::signed(&through_integer, integer_bits),
                &super::signed(&machine_argument, integer_bits),
            );
        }
        let round_trip = low(&pointer, pointer_bits);
        proofs.predicate(
            format!("pointer round trip/{pointer_bits}"),
            &round_trip,
            &pointer,
        );
        let boolean = format!("(not (= {pointer} {}))", constant(0));
        let narrowed_boolean = format!("(not (= {} {}))", low(&pointer, 8), constant(0));
        proofs.counterexample(
            format!("boolean is not a byte/{pointer_bits}"),
            &boolean,
            &narrowed_boolean,
        );
    }
    proofs.check();
}

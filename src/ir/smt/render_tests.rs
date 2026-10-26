use super::*;
use crate::ir::{CType, FunctionIr, Param, Stmt};
use crate::loader::Isa;

fn bin(op: BinOp, lhs: Expr, rhs: Expr) -> Expr {
    Expr::Bin {
        op,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
    }
}

#[test]
fn wrapping_arithmetic_avoids_c_overflow() {
    use std::io::Write;

    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("SKIP C overflow regression: clang unavailable");
        return;
    }
    let value = bin(
        BinOp::And,
        bin(BinOp::Add, Expr::reg(7, 32), Expr::reg(6, 32)),
        Expr::Const(0xff),
    );
    let mut ir = FunctionIr::single_block(Isa::X86_64, vec![Stmt::Ret { value }]);
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
    let index = bin(BinOp::Add, Expr::reg(6, 64), Expr::Const(2));
    let address = bin(
        BinOp::Add,
        Expr::reg(7, 64),
        bin(BinOp::Mul, index, Expr::Const(8)),
    );
    let mut indexed = FunctionIr::single_block(
        Isa::X86_64,
        vec![Stmt::Ret {
            value: Expr::Load {
                addr: Box::new(address),
                width: 8,
                signed: false,
            },
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
            value: bin(BinOp::Sub, Expr::Const(0), Expr::reg(7, 64)),
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
    let source = format!(
        "#include <stdint.h>\n{code}\n{pointer_code}\n{negative_code}\nint main(void) {{ int64_t data[8] = {{10,20,30,40,50,60,70,80}}; return masked_sum(0x40000000, 0x40000001) != 1 || indexed_value(data + 3, -3) != 30 || indexed_value(data + 3, -5) != 10 || indexed_value(data + 3, 0) != 60 || negated_value(INT64_MIN) != (uint64_t)INT64_MIN; }}\n"
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
    use std::io::Write;

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
        for (is_signed, ty) in types.into_iter().enumerate() {
            let mut reads = vec![bits];
            if bits < 64 {
                reads.push(64);
            }
            for read in reads {
                let x = Expr::reg(7, read);
                let y = Expr::reg(6, read);
                let mut cases = vec![
                    x.clone(),
                    bin(BinOp::Sub, Expr::Const(0), x.clone()),
                    bin(BinOp::Sub, Expr::Const(0), Expr::Const(1)),
                ];
                for op in [
                    BinOp::Add,
                    BinOp::Sub,
                    BinOp::Mul,
                    BinOp::And,
                    BinOp::Or,
                    BinOp::Xor,
                ] {
                    cases.push(bin(op, x.clone(), y.clone()));
                    cases.push(bin(op, x.clone(), Expr::Const(u64::MAX)));
                }
                for op in [BinOp::DivU, BinOp::ModU, BinOp::DivS, BinOp::ModS] {
                    cases.push(bin(op, x.clone(), Expr::Const(3)));
                }
                for op in [BinOp::Shl, BinOp::Shr, BinOp::Sar] {
                    cases.push(bin(op, x.clone(), y.clone()));
                    for amount in [0, 1, 31, 63, 64] {
                        cases.push(bin(op, x.clone(), Expr::Const(amount)));
                    }
                }
                for mask in [0xff, 0xffff, 0xffff_ffff, u64::MAX] {
                    cases.push(bin(
                        BinOp::And,
                        bin(BinOp::Add, x.clone(), y.clone()),
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
                }
                for (index, value) in cases.into_iter().enumerate() {
                    let name = format!("smt_c_{bits}_{is_signed}_{read}_{index}");
                    let mut ir = FunctionIr::single_block(
                        Isa::X86_64,
                        vec![Stmt::Ret {
                            value: value.clone(),
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
                            if is_signed == 1 {
                                signed(&input, u32::from(bits))
                            } else {
                                input
                            },
                        );
                    }
                    originals.insert(name, (value, registers));
                }
            }
        }
    }
    let names: Vec<&String> = originals.keys().collect();
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
        let (value, registers) = originals.get(name).expect("requested function");
        proofs.rendered(
            format!("rendered/{name}/{value:?}"),
            value,
            registers,
            result["term"].as_str().expect("C SMT term"),
            result["defined"].as_str().expect("C validity condition"),
        );
    }
    proofs.check();
}

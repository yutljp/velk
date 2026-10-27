use super::*;

#[test]
fn go_register_and_stack_shapes_compile_and_preserve_all_words() {
    let mut source = String::from(HEADER);
    let mut prelude = velk::render::Prelude::default();
    for (runtime_function, count) in [
        ("printstring", 2),
        ("printslice", 3),
        ("printiface", 2),
        ("printeface", 2),
    ] {
        for stack in [false, true] {
            let registers = [0, 3, 1];
            let params = if stack {
                Vec::new()
            } else {
                registers[..count]
                    .iter()
                    .enumerate()
                    .map(|(i, index)| Param {
                        index: *index,
                        name: format!("a{i}"),
                        ty: CType::U64,
                    })
                    .collect()
            };
            let word = |i: usize| {
                if stack {
                    Expr::Load {
                        addr: Box::new(Expr::bin(
                            BinOp::Add,
                            Expr::reg(velk::arch::stack_pointer(Isa::X86_64), 64),
                            Expr::Const(8 + i as u64 * 8),
                        )),
                        width: 8,
                        signed: false,
                    }
                } else {
                    Expr::reg(registers[i], 64)
                }
            };
            let mut value = word(0);
            for i in 1..count {
                value = Expr::bin(BinOp::Xor, value, word(i));
            }
            let mut ir = synthetic_ir(
                &format!("runtime.{runtime_function}"),
                params,
                CType::U64,
                vec![
                    if stack {
                        Stmt::Store {
                            addr: Expr::bin(
                                BinOp::Add,
                                Expr::reg(velk::arch::stack_pointer(Isa::X86_64), 64),
                                Expr::Const(8),
                            ),
                            value: Expr::Const(66),
                            width: 1,
                        }
                    } else {
                        Stmt::Assign {
                            dest: velk::ir::RegRef {
                                index: 0,
                                width: 64,
                            },
                            value: Expr::bin(
                                BinOp::Or,
                                Expr::bin(BinOp::And, Expr::reg(0, 64), Expr::Const(!255u64)),
                                Expr::Const(66),
                            ),
                        }
                    },
                    Stmt::Ret { value },
                ],
            );
            ir.convention = if stack {
                Convention::GoAbi0
            } else {
                Convention::GoAmd64
            };
            if stack {
                ir.stack_params = (0..count)
                    .map(|i| velk::ir::StackParam {
                        offset: 8 + i as i64 * 8,
                        size: 8,
                        name: format!("a{i}"),
                        ty: CType::U64,
                        position: i,
                    })
                    .collect();
            }
            let name = format!(
                "{runtime_function}_{}",
                if stack { "stack" } else { "register" }
            );
            let symbols = velk::render::Symbols {
                functions: [(0, name.clone())].into(),
                ..Default::default()
            };
            let code = velk::render::render(&ir, &[], &symbols, &[]);
            let shape = match runtime_function {
                "printstring" => "go_string",
                "printslice" => "go_slice",
                _ => "go_iface",
            };
            assert!(code.contains(&format!("struct {shape} {{")), "{code}");
            assert!(
                code.contains(if count == 3 {
                    "slice.cap"
                } else if runtime_function == "printstring" {
                    "string.len"
                } else {
                    "iface.data"
                }),
                "{code}"
            );
            source.push_str(&prelude.extract(&code));
            source.push_str(&format!("\nstatic int check_{name}(uint64_t a, uint64_t b, uint64_t c) {{ return {name}(a, b{}) != (((a & ~UINT64_C(255)) | UINT64_C(66)) ^ b{}); }}\n", if count == 3 { ", c" } else { "" }, if count == 3 { " ^ c" } else { "" }));
        }
    }
    for (runtime_function, count) in [("printstring", 2), ("printslice", 3), ("printiface", 2)] {
        let registers = [0, 3, 1];
        let words: Vec<_> = registers[..count]
            .iter()
            .map(|index| Expr::reg(*index, 64))
            .collect();
        let mut value = words[0].clone();
        for word in &words[1..] {
            value = Expr::bin(BinOp::Xor, value, word.clone());
        }
        let mut ir = synthetic_ir(
            &format!("forward_{runtime_function}"),
            registers[..count]
                .iter()
                .enumerate()
                .map(|(i, index)| Param {
                    index: *index,
                    name: format!("a{i}"),
                    ty: CType::U64,
                })
                .collect(),
            CType::U64,
            vec![
                Stmt::Call {
                    kind: velk::ir::CallKind::Invoke,
                    target: Some(10),
                    through: None,
                    convention: Convention::GoAmd64,
                    args: Some(words),
                    floats_named: true,
                    abi: None,
                    outputs: Vec::new(),
                    clobbers: Some(Default::default()),
                    via: None,
                },
                Stmt::Ret { value },
            ],
        );
        ir.convention = Convention::GoAmd64;
        let symbols = velk::render::Symbols {
            functions: [(10, format!("sink_{runtime_function}"))].into(),
            function_returns: [(10, CType::Void)].into(),
            go_value_shapes: [(10, format!("runtime.{runtime_function}"))].into(),
            ..Default::default()
        };
        source.push_str(&format!("static uint64_t observed_{runtime_function};\nvoid sink_{runtime_function}(uint64_t a, uint64_t b{}) {{ observed_{runtime_function} = a ^ b{}; }}\n", if count == 3 { ", uint64_t c" } else { "" }, if count == 3 { " ^ c" } else { "" }));
        let code = velk::render::render(&ir, &[], &symbols, &[]);
        assert!(code.contains("struct go_"), "{code}");
        source.push_str(&prelude.extract(&code));
    }
    let definitions = prelude.render();
    assert_eq!(definitions.matches("struct go_iface {").count(), 1);
    source.insert_str(HEADER.len(), &definitions);
    source.push_str("\nint main(void) { for (uint64_t i = 0; i < 100; ++i) { uint64_t a = i * UINT64_C(0xfedcba987654321), b = ~a, c = i * UINT64_C(0xdeadbeef12345678);\n");
    for runtime_function in ["printstring", "printslice", "printiface", "printeface"] {
        for passing in ["stack", "register"] {
            source.push_str(&format!(
                "if (check_{runtime_function}_{passing}(a,b,c)) return 1;\n"
            ));
        }
    }
    for (runtime_function, count) in [("printstring", 2), ("printslice", 3), ("printiface", 2)] {
        source.push_str(&format!("if (forward_{runtime_function}(a,b{}) != (a ^ b{}) || observed_{runtime_function} != (a ^ b{})) return 1;\n", if count == 3 { ",c" } else { "" }, if count == 3 { " ^ c" } else { "" }, if count == 3 { " ^ c" } else { "" }));
    }
    source.push_str("} return 0; }\n");
    let scratch = scratch_dir("go-values");
    let input = scratch.join("values.c");
    std::fs::write(&input, source).unwrap();
    for level in ["-O0", "-O2"] {
        let executable = scratch.join(format!("values{level}"));
        let output = Command::new(compiler())
            .args(FLAGS)
            .args(["-Werror=implicit-function-declaration", level])
            .arg(&input)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(Command::new(executable).status().unwrap().success());
    }
    std::fs::remove_dir_all(scratch).ok();
}

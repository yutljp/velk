use super::*;
use crate::ir::{CallKind, FunctionIr, Param};
use crate::loader::Isa;
use crate::render::{self, Symbols};

fn analysis(isa: Isa, address: u64, name: &str, statements: Vec<Stmt>) -> Analysis {
    let mut ir = FunctionIr::single_block(isa, statements);
    ir.addr = address;
    ir.name = Some(name.into());
    Analysis {
        ir,
        callee_parameters: Default::default(),
        unused_parameters: Default::default(),
        import_parameters: Default::default(),
        references: Vec::new(),
        simplification: Default::default(),
    }
}

fn call(isa: Isa, target: u64, args: Vec<Expr>) -> Stmt {
    let convention = crate::ir::Convention::of(isa, crate::loader::Format::Elf, false);
    Stmt::Call {
        kind: CallKind::Invoke,
        target: Some(target),
        through: None,
        convention,
        args: Some(args),
        floats_named: false,
        abi: None,
        outputs: crate::ir::fallback_call_outputs(convention, None),
        clobbers: None,
        via: None,
    }
}

fn compile_and_run(source: &str, name: &str) {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // System V x86-64 keeps an unprototyped import declaration for its ABI.
    let executable = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("velk-{name}-{}", std::process::id()));
    let mut compiler = Command::new("cc")
        .args([
            "-std=c11",
            "-Werror",
            "-Wno-deprecated-non-prototype",
            "-x",
            "c",
            "-",
            "-o",
        ])
        .arg(&executable)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("C compiler");
    compiler
        .stdin
        .take()
        .expect("compiler input")
        .write_all(source.as_bytes())
        .expect("C source");
    let output = compiler.wait_with_output().expect("C compiler result");
    assert!(
        output.status.success(),
        "{}\n{source}",
        String::from_utf8_lossy(&output.stderr)
    );
    let status = Command::new(&executable).status().expect("compiled C");
    std::fs::remove_file(executable).expect("remove compiled C");
    assert!(status.success(), "{source}");
}

#[test]
fn unused_parameters_merge_every_caller_and_compile() {
    for isa in [Isa::I386, Isa::X86_64, Isa::AArch64, Isa::Arm32] {
        let image = Image::from_code(isa, 0, Vec::new());
        let mut functions = vec![analysis(
            isa,
            0x1000,
            "ignored",
            vec![Stmt::Ret {
                value: Expr::Const(37),
            }],
        )];
        for count in 0..=8 {
            functions.push(analysis(
                isa,
                0x3000 + count,
                &format!("ignored_{count}"),
                vec![Stmt::Ret {
                    value: Expr::Const(37),
                }],
            ));
            functions.push(analysis(
                isa,
                0x4000 + count,
                &format!("invoke_{count}"),
                vec![
                    call(isa, 0x3000 + count, (0..count).map(Expr::Const).collect()),
                    Stmt::Ret {
                        value: Expr::reg(crate::arch::RETURN, 64),
                    },
                ],
            ));
            functions.push(analysis(
                isa,
                0x2000 + count,
                &format!("caller_{count}"),
                vec![
                    call(isa, 0x1000, (0..count).map(Expr::Const).collect()),
                    Stmt::Ret {
                        value: Expr::reg(crate::arch::RETURN, 64),
                    },
                ],
            ));
        }
        recover(&image, &mut functions);
        for count in 1..=8 {
            assert_eq!(
                functions[0].unused_parameters[&(0x3000 + count)]
                    .params
                    .len(),
                count as usize
            );
        }
        assert_eq!(
            functions[0].unused_parameters[&0x1000].params,
            vec![CType::U64; 8]
        );
        let mut reversed = functions.clone();
        reversed.reverse();
        recover(&image, &mut reversed);
        for function in &reversed {
            assert_eq!(function.unused_parameters, functions[0].unused_parameters);
        }
        let mut symbols = Symbols::default();
        symbols
            .unused_parameters
            .extend(functions[0].unused_parameters.clone());
        for function in &functions {
            symbols.functions.insert(
                function.ir.addr,
                function.ir.name.clone().expect("fixture name"),
            );
            symbols
                .function_returns
                .insert(function.ir.addr, function.ir.ret_type.clone());
        }
        let mut source =
            String::from("#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n");
        for function in &functions {
            source.push_str(&render::render(&function.ir, &[], &symbols, &[]));
        }
        let mut source = render::combine(&source);
        assert!(source.contains("ignored(uint64_t unused_arg_0"), "{source}");
        assert!(!source.contains("(*)"), "{source}");
        source.push_str("int main(void) {\n");
        for count in 0..=8 {
            source.push_str(&format!("if (caller_{count}() != 37) return 1;\n"));
            source.push_str(&format!("if (invoke_{count}() != 37) return 1;\n"));
        }
        source.push_str("return 0; }\n");
        compile_and_run(&source, "unused-parameters");
    }
}

#[test]
fn unused_scalar_types_merge_without_changing_body_types() {
    let pointer = CType::pointer_to(CType::Named("const char".into()));
    assert_eq!(merge(&pointer, &CType::U64), CType::Named("_Bool".into()));
    for ty in [CType::U64, pointer, CType::Named("double".into())] {
        assert_eq!(
            merge(&CType::Named("_Bool".into()), &ty),
            CType::Named("_Bool".into())
        );
    }
    let isa = Isa::X86_64;
    let mut typed = analysis(
        isa,
        0x1000,
        "typed",
        vec![Stmt::Ret {
            value: Expr::reg(7, 64),
        }],
    );
    typed.ir.params.push(Param {
        index: 7,
        name: "value".into(),
        ty: CType::U64,
    });
    let mut functions = vec![
        typed,
        analysis(
            isa,
            0x2000,
            "caller",
            vec![call(isa, 0x1000, vec![Expr::Const(1), Expr::Const(2)])],
        ),
    ];
    recover(&Image::from_code(isa, 0, Vec::new()), &mut functions);
    assert!(functions[0].unused_parameters.is_empty());
    assert_eq!(functions[0].ir.params[0].ty, CType::U64);
}

#[test]
fn conflicting_unused_pointer_and_integer_arguments_compile_without_casts() {
    for isa in [Isa::I386, Isa::X86_64, Isa::AArch64, Isa::Arm32] {
        let image = Image::from_code(isa, 0, Vec::new());
        let mut functions = vec![analysis(
            isa,
            0x1000,
            "ignored",
            vec![Stmt::Ret {
                value: Expr::Const(37),
            }],
        )];
        for (position, ty) in [
            CType::U64,
            CType::pointer_to(CType::Named("const char".into())),
        ]
        .into_iter()
        .enumerate()
        {
            let mut caller = analysis(
                isa,
                0x2000 + position as u64,
                &format!("caller_{position}"),
                vec![
                    call(isa, 0x1000, vec![Expr::reg(7, 64)]),
                    Stmt::Ret {
                        value: Expr::Const(37),
                    },
                ],
            );
            caller.ir.params.push(Param {
                index: 7,
                name: "value".into(),
                ty,
            });
            functions.push(caller);
        }
        recover(&image, &mut functions);
        let symbols = Symbols {
            functions: functions
                .iter()
                .map(|analysis| {
                    (
                        analysis.ir.addr,
                        analysis.ir.name.clone().expect("fixture name"),
                    )
                })
                .collect(),
            unused_parameters: functions[0].unused_parameters.clone().into_iter().collect(),
            ..Default::default()
        };
        let mut source = String::new();
        for function in &functions {
            source.push_str(&render::render(&function.ir, &[], &symbols, &[]));
        }
        let source = render::combine(&source);
        assert!(source.contains("ignored(_Bool unused_arg_0)"), "{source}");
        assert!(!source.contains("(uintptr_t)"), "{source}");
        compile_and_run(
            &format!(
                "{source}\nint main(void) {{ return caller_0(UINT64_MAX) != 37 || caller_1(\"text\") != 37; }}"
            ),
            "unused-scalar-types",
        );
    }
}

#[test]
fn library_prelude_uses_the_prototype_despite_inferred_return_width() {
    for isa in [Isa::I386, Isa::X86_64, Isa::AArch64, Isa::Arm32] {
        let function = analysis(
            isa,
            0x2000,
            "call_abs",
            vec![
                call(isa, 0x1000, vec![Expr::Const((-19i64) as u64)]),
                Stmt::Ret {
                    value: Expr::reg(0, 64),
                },
            ],
        );
        let symbols = Symbols {
            functions: [(0x1000, "abs".into())].into(),
            function_returns: [(0x1000, CType::U64)].into(),
            ..Default::default()
        };
        let source = render::render(&function.ir, &[], &symbols, &[]);
        assert!(source.contains("#include <stdlib.h>"), "{source}");
        compile_and_run(
            &format!(
                "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n{source}\nint main(void) {{ return call_abs() != 19; }}"
            ),
            "library-declaration",
        );
    }
}

#[test]
fn unused_function_addresses_compile_without_integer_casts() {
    for isa in [Isa::I386, Isa::X86_64, Isa::AArch64, Isa::Arm32] {
        let mut image = Image::from_code(isa, 0, Vec::new());
        image.functions.insert(
            0x5000,
            crate::loader::Function {
                addr: 0x5000,
                size: Some(1),
                size_estimated: false,
                name: Some("callback".into()),
                aliases: Vec::new(),
                library: None,
                sources: Vec::new(),
            },
        );
        let mut functions = vec![
            analysis(
                isa,
                0x1000,
                "ignored",
                vec![Stmt::Ret {
                    value: Expr::Const(37),
                }],
            ),
            analysis(
                isa,
                0x2000,
                "invoke_callback",
                vec![
                    call(isa, 0x1000, vec![Expr::Const(0x5000)]),
                    Stmt::Ret {
                        value: Expr::Const(37),
                    },
                ],
            ),
            analysis(
                isa,
                0x5000,
                "callback",
                vec![Stmt::Ret {
                    value: Expr::Const(9),
                }],
            ),
        ];
        recover(&image, &mut functions);
        let symbols = Symbols {
            functions: functions
                .iter()
                .map(|analysis| {
                    (
                        analysis.ir.addr,
                        analysis.ir.name.clone().expect("fixture name"),
                    )
                })
                .collect(),
            function_returns: functions
                .iter()
                .map(|analysis| (analysis.ir.addr, analysis.ir.ret_type.clone()))
                .collect(),
            unused_parameters: functions[0].unused_parameters.clone().into_iter().collect(),
            ..Default::default()
        };
        let mut source = String::new();
        for function in &functions {
            source.push_str(&render::render(&function.ir, &[], &symbols, &[]));
        }
        let source = render::combine(&source);
        assert!(
            source.contains("ignored(const void *unused_arg_0)"),
            "{source}"
        );
        assert!(!source.contains("(uintptr_t)"), "{source}");
        compile_and_run(
            &format!("{source}\nint main(void) {{ return invoke_callback() != 37; }}"),
            "unused-function-address",
        );
    }
}

#[test]
fn address_operands_request_the_function_and_its_callers() {
    let isa = Isa::X86_64;
    let mut image = Image::from_code(isa, 0x1000, vec![0xc3]);
    image.functions.insert(
        0x1000,
        crate::loader::Function {
            addr: 0x1000,
            size: Some(1),
            size_estimated: false,
            name: Some("target".into()),
            aliases: Vec::new(),
            library: None,
            sources: Vec::new(),
        },
    );
    let root = analysis(
        isa,
        0x2000,
        "address",
        vec![Stmt::Ret {
            value: Expr::Const(0x1000),
        }],
    );
    assert!(root.references.is_empty());
    assert!(callers(&image, &root).contains(&0x1000));
}

#[test]
fn parameterized_function_addresses_do_not_request_body_analysis() {
    for isa in [Isa::I386, Isa::X86_64, Isa::AArch64, Isa::Arm32] {
        let mut image = Image::from_code(isa, 0x1000, Vec::new());
        image.functions.insert(
            0x1000,
            crate::loader::Function {
                addr: 0x1000,
                size: Some(1),
                size_estimated: false,
                name: Some("callback".into()),
                aliases: Vec::new(),
                library: None,
                sources: Vec::new(),
            },
        );
        image.summaries.write().unwrap().insert(
            0x1000,
            crate::loader::Summary {
                arity: Some(1),
                ..Default::default()
            },
        );
        let mut root = analysis(
            isa,
            0x2000,
            "address",
            vec![Stmt::Ret {
                value: Expr::Const(0x1000),
            }],
        );
        assert!(!callers(&image, &root).contains(&0x1000));
        root.ir.blocks[0]
            .stmts
            .insert(0, call(isa, 0x1000, vec![Expr::Const(7)]));
        assert!(callers(&image, &root).contains(&0x1000));
    }
}

#[test]
fn borrowed_call_parameters_print_like_owned_symbols() {
    for isa in [Isa::I386, Isa::X86_64, Isa::AArch64, Isa::Arm32] {
        let mut root = analysis(
            isa,
            0x2000,
            "invoke",
            vec![
                call(isa, 0x1000, vec![Expr::Const(7)]),
                call(isa, 0x3000, vec![Expr::Const(9)]),
                call(isa, 0x4000, vec![Expr::Const(11)]),
                Stmt::Ret {
                    value: Expr::Const(37),
                },
            ],
        );
        root.import_parameters.insert(0x3000, vec![CType::I32]);
        root.unused_parameters.insert(
            0x4000,
            crate::analysis::prototypes::Prototype {
                params: vec![CType::I32],
                ret: CType::U64,
                variadic: false,
                format: None,
                scans: false,
            },
        );
        let mut symbols = Symbols::default();
        for (address, name) in [
            (0x1000, "callee"),
            (0x3000, "imported"),
            (0x4000, "ignored"),
        ] {
            symbols.functions.insert(address, name.to_owned());
            symbols.function_returns.insert(address, CType::U64);
        }
        let mut owned = symbols.clone();
        owned
            .import_parameters
            .extend(root.import_parameters.clone());
        owned
            .unused_parameters
            .extend(root.unused_parameters.clone());
        let expected = render::render(&root.ir, &[], &owned, &[]);
        let borrowed = render::FunctionSymbols::new_with_analysis(&symbols, &root);
        let actual = render::render_with_symbols(&root.ir, &[], &borrowed, &[]).code;
        assert_eq!(actual, expected);
        assert!(std::ptr::eq(&borrowed.functions, &symbols.functions));
    }
}

#[test]
fn unknown_import_prototypes_preserve_promoted_values() {
    for isa in [Isa::I386, Isa::X86_64, Isa::AArch64, Isa::Arm32] {
        let mut image = Image::from_code(isa, 0, Vec::new());
        image.functions.insert(
            0x5000,
            crate::loader::Function {
                addr: 0x5000,
                size: Some(1),
                size_estimated: false,
                name: Some("external_value".into()),
                aliases: Vec::new(),
                library: None,
                sources: vec![crate::loader::NameSource::Plt],
            },
        );
        let mut functions = vec![analysis(
            isa,
            0x2000,
            "invoke_external",
            vec![
                call(isa, 0x5000, vec![Expr::Const(7), Expr::Const(0x100000000)]),
                Stmt::Ret {
                    value: Expr::reg(crate::arch::RETURN, 64),
                },
            ],
        )];
        recover(&image, &mut functions);
        assert_eq!(
            functions[0].import_parameters.get(&0x5000),
            Some(&vec![CType::I32, CType::I64])
        );
        let symbols = Symbols {
            functions: [(0x5000, "external_value".into())].into(),
            import_parameters: functions[0].import_parameters.clone().into_iter().collect(),
            ..Default::default()
        };
        let source = render::render(&functions[0].ir, &[], &symbols, &[]);
        assert!(
            source.contains("external_value(int32_t, int64_t)"),
            "{source}"
        );
        compile_and_run(
            &format!(
                "#include <stdint.h>\nuint64_t external_value(int32_t a, int64_t b) {{ return a + (b == INT64_C(4294967296)); }}\n{source}\nint main(void) {{ return invoke_external() != 8; }}"
            ),
            "import-values",
        );
        functions.push(analysis(
            isa,
            0x3000,
            "other",
            vec![call(isa, 0x5000, vec![Expr::Const(7)])],
        ));
        for function in &mut functions {
            function.import_parameters.clear();
        }
        recover(&image, &mut functions);
        assert!(!functions[0].import_parameters.contains_key(&0x5000));
        functions.reverse();
        for function in &mut functions {
            function.import_parameters.clear();
        }
        recover(&image, &mut functions);
        assert!(!functions[0].import_parameters.contains_key(&0x5000));
    }
}

#[test]
fn unknown_imports_reject_arguments_whose_conversion_is_uncertain() {
    let image = Image::from_code(Isa::X86_64, 0, Vec::new());
    let mut function = analysis(Isa::X86_64, 0x2000, "caller", Vec::new());
    for ty in [CType::Named("float".into()), CType::Named("double".into())] {
        function.ir.params = vec![Param {
            index: 7,
            name: "value".into(),
            ty,
        }];
        assert_eq!(
            import_argument_type(&image, &function, &Expr::reg(7, 64), None),
            None
        );
    }
    function.ir.params[0].ty = CType::Named("_Bool".into());
    assert_eq!(
        import_argument_type(&image, &function, &Expr::reg(7, 64), None),
        Some(CType::I32)
    );
    function.ir.params[0].ty = CType::U64;
    function.ir.blocks[0].stmts.push(Stmt::Assign {
        dest: crate::ir::RegRef {
            index: 7,
            width: 64,
        },
        value: Expr::Const(1),
    });
    assert_eq!(
        import_argument_type(&image, &function, &Expr::reg(7, 64), None),
        None
    );
}

#[test]
fn unknown_imports_require_every_discovered_caller() {
    let mut code = vec![0; 0x101];
    code[..5].copy_from_slice(&[0xe8, 0xfb, 0, 0, 0]);
    code[0x10..0x15].copy_from_slice(&[0xe8, 0xeb, 0, 0, 0]);
    code[0x100] = 0xc3;
    let mut image = Image::from_code(Isa::I386, 0x1000, code);
    for (addr, source) in [
        (0x1000, None),
        (0x1010, None),
        (0x1100, Some(crate::loader::NameSource::Plt)),
    ] {
        image.functions.insert(
            addr,
            crate::loader::Function {
                addr,
                size: Some(6),
                size_estimated: false,
                name: Some(format!("f_{addr:x}")),
                aliases: Vec::new(),
                library: None,
                sources: source.into_iter().collect(),
            },
        );
    }
    let root = analysis(
        Isa::I386,
        0x1000,
        "first",
        vec![call(Isa::I386, 0x1100, vec![Expr::Const(7)])],
    );
    assert!(callers(&image, &root).contains(&0x1010));
    let mut functions = vec![root];
    recover(&image, &mut functions);
    assert!(!functions[0].import_parameters.contains_key(&0x1100));
    functions.push(analysis(
        Isa::I386,
        0x1010,
        "second",
        vec![call(Isa::I386, 0x1100, vec![Expr::Const(8)])],
    ));
    recover(&image, &mut functions);
    assert_eq!(
        functions[0].import_parameters.get(&0x1100),
        Some(&vec![CType::I32])
    );
}

#[test]
fn sysv_unknown_imports_keep_the_unprototyped_call() {
    let mut image = Image::from_code(Isa::X86_64, 0, Vec::new());
    image.functions.insert(
        0x5000,
        crate::loader::Function {
            addr: 0x5000,
            size: Some(1),
            size_estimated: false,
            name: Some("external_value".into()),
            aliases: Vec::new(),
            library: None,
            sources: vec![crate::loader::NameSource::Plt],
        },
    );
    let mut functions = vec![analysis(
        Isa::X86_64,
        0x2000,
        "caller",
        vec![call(Isa::X86_64, 0x5000, vec![Expr::Const(7)])],
    )];
    recover(&image, &mut functions);
    let symbols = Symbols {
        functions: [(0x5000, "external_value".into())].into(),
        import_parameters: functions[0].import_parameters.clone().into_iter().collect(),
        ..Default::default()
    };
    let source = render::render(&functions[0].ir, &[], &symbols, &[]);
    assert!(source.contains("#if defined(__x86_64__) && !defined(_WIN32)\nuint64_t external_value();\n#else\nuint64_t external_value(int32_t);\n#endif"), "{source}");
}

#[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
#[test]
fn sysv_unknown_imports_supply_the_variadic_vector_count() {
    let mut image = Image::from_code(Isa::X86_64, 0, Vec::new());
    image.functions.insert(
        0x5000,
        crate::loader::Function {
            addr: 0x5000,
            size: Some(1),
            size_estimated: false,
            name: Some("external_count".into()),
            aliases: Vec::new(),
            library: None,
            sources: vec![crate::loader::NameSource::Plt],
        },
    );
    let mut functions = vec![analysis(
        Isa::X86_64,
        0x2000,
        "call_count",
        vec![
            call(Isa::X86_64, 0x5000, vec![Expr::Const(7)]),
            Stmt::Ret {
                value: Expr::reg(crate::arch::RETURN, 64),
            },
        ],
    )];
    recover(&image, &mut functions);
    let symbols = Symbols {
        functions: [(0x5000, "external_count".into())].into(),
        import_parameters: functions[0].import_parameters.clone().into_iter().collect(),
        ..Default::default()
    };
    let source = render::render(&functions[0].ir, &[], &symbols, &[]);
    let symbol = if cfg!(target_os = "macos") {
        "_external_count"
    } else {
        "external_count"
    };
    compile_and_run(
        &format!(
            "__asm__(\".globl {symbol}\\n{symbol}:\\n movzbl %al, %eax\\n ret\\n\");\n{source}\nint main(void) {{ __asm__ volatile(\"movb $7, %%al\" ::: \"rax\"); return call_count() != 0; }}"
        ),
        "import-vector-count",
    );
}

#[test]
fn win64_unknown_imports_keep_the_promoted_argument() {
    let mut image = Image::from_code(Isa::X86_64, 0, Vec::new());
    image.format = crate::loader::Format::Pe;
    image.functions.insert(
        0x5000,
        crate::loader::Function {
            addr: 0x5000,
            size: Some(1),
            size_estimated: false,
            name: Some("external_value".into()),
            aliases: Vec::new(),
            library: None,
            sources: vec![crate::loader::NameSource::Plt],
        },
    );
    let mut call = call(Isa::X86_64, 0x5000, vec![Expr::Const(7)]);
    if let Stmt::Call {
        convention,
        outputs,
        ..
    } = &mut call
    {
        *convention = crate::ir::Convention::Win64;
        *outputs = crate::ir::fallback_call_outputs(*convention, None);
    }
    let mut caller = analysis(
        Isa::X86_64,
        0x2000,
        "call_value",
        vec![
            call,
            Stmt::Ret {
                value: Expr::reg(crate::arch::RETURN, 64),
            },
        ],
    );
    caller.ir.convention = crate::ir::Convention::Win64;
    let mut functions = vec![caller];
    recover(&image, &mut functions);
    let symbols = Symbols {
        target_format: Some(crate::loader::Format::Pe),
        functions: [(0x5000, "external_value".into())].into(),
        import_parameters: functions[0].import_parameters.clone().into_iter().collect(),
        ..Default::default()
    };
    let source = render::render(&functions[0].ir, &[], &symbols, &[]);
    assert!(source.contains("external_value(int32_t)"), "{source}");
    compile_and_run(
        &format!(
            "#include <stdint.h>\nuint64_t external_value(int32_t value) {{ return value + 1; }}\n{source}\nint main(void) {{ return call_value() != 8; }}"
        ),
        "import-win64",
    );
}

#[test]
fn import_reads_a_parameter_before_the_call_clobbers_it() {
    let mut image = Image::from_code(Isa::AArch64, 0, Vec::new());
    image.functions.insert(
        0x5000,
        crate::loader::Function {
            addr: 0x5000,
            size: Some(1),
            size_estimated: false,
            name: Some("external_value".into()),
            aliases: Vec::new(),
            library: None,
            sources: vec![crate::loader::NameSource::Plt],
        },
    );
    let mut caller = analysis(
        Isa::AArch64,
        0x2000,
        "caller",
        vec![call(Isa::AArch64, 0x5000, vec![Expr::reg(0, 64)])],
    );
    caller.ir.params.push(Param {
        index: 0,
        name: "value".into(),
        ty: CType::U64,
    });
    let mut functions = vec![caller];
    recover(&image, &mut functions);
    assert_eq!(
        functions[0].import_parameters.get(&0x5000),
        Some(&vec![CType::U64])
    );
}

#[test]
fn unknown_import_string_literals_keep_their_pointer_value() {
    for isa in [Isa::I386, Isa::X86_64, Isa::AArch64, Isa::Arm32] {
        let mut image = Image::from_code(isa, 0, Vec::new());
        image.functions.insert(
            0x5000,
            crate::loader::Function {
                addr: 0x5000,
                size: Some(1),
                size_estimated: false,
                name: Some("external_text".into()),
                aliases: Vec::new(),
                library: None,
                sources: vec![crate::loader::NameSource::Plt],
            },
        );
        let mut caller = analysis(
            isa,
            0x2000,
            "call_text",
            vec![
                call(isa, 0x5000, vec![Expr::Const(0x9000)]),
                Stmt::Ret {
                    value: Expr::reg(crate::arch::RETURN, 64),
                },
            ],
        );
        caller.references.push(crate::analysis::refs::Reference {
            addr: 0x9000,
            section: ".rodata".into(),
            text: Some("hello".into()),
            pointer: None,
            guid: None,
        });
        let mut functions = vec![caller];
        recover(&image, &mut functions);
        let symbols = Symbols {
            functions: [(0x5000, "external_text".into())].into(),
            import_parameters: functions[0].import_parameters.clone().into_iter().collect(),
            ..Default::default()
        };
        let source = render::render(&functions[0].ir, &functions[0].references, &symbols, &[]);
        assert!(source.contains("external_text(char *)"), "{source}");
        assert!(source.contains("external_text(\"hello\")"), "{source}");
        compile_and_run(
            &format!(
                "#include <stdint.h>\nuint64_t external_text(char *value) {{ return value[0]; }}\n{source}\nint main(void) {{ return call_text() != 'h'; }}"
            ),
            "import-text",
        );
    }
}

#[test]
fn unknown_import_with_only_zero_argument_calls_has_a_void_parameter_list() {
    for isa in [Isa::I386, Isa::X86_64, Isa::AArch64, Isa::Arm32] {
        let mut image = Image::from_code(isa, 0, Vec::new());
        image.functions.insert(
            0x5000,
            crate::loader::Function {
                addr: 0x5000,
                size: Some(1),
                size_estimated: false,
                name: Some("external_zero".into()),
                aliases: Vec::new(),
                library: None,
                sources: vec![crate::loader::NameSource::Plt],
            },
        );
        let mut functions = vec![analysis(
            isa,
            0x2000,
            "call_zero",
            vec![
                call(isa, 0x5000, Vec::new()),
                Stmt::Ret {
                    value: Expr::reg(crate::arch::RETURN, 64),
                },
            ],
        )];
        recover(&image, &mut functions);
        let symbols = Symbols {
            functions: [(0x5000, "external_zero".into())].into(),
            import_parameters: functions[0].import_parameters.clone().into_iter().collect(),
            ..Default::default()
        };
        let source = render::render(&functions[0].ir, &[], &symbols, &[]);
        assert!(source.contains("external_zero(void)"), "{source}");
        compile_and_run(
            &format!(
                "#include <stdint.h>\nuint64_t external_zero(void) {{ return 37; }}\n{source}\nint main(void) {{ return call_zero() != 37; }}"
            ),
            "import-zero",
        );
    }
}

#[test]
fn unknown_import_bool_arguments_keep_their_promoted_values() {
    for isa in [Isa::I386, Isa::X86_64, Isa::AArch64, Isa::Arm32] {
        let index = match isa {
            Isa::I386 | Isa::X86_64 => 3,
            Isa::AArch64 => 19,
            Isa::Arm32 => 4,
            _ => unreachable!("fixture architecture"),
        };
        let mut image = Image::from_code(isa, 0, Vec::new());
        image.functions.insert(
            0x5000,
            crate::loader::Function {
                addr: 0x5000,
                size: Some(1),
                size_estimated: false,
                name: Some("external_bool".into()),
                aliases: Vec::new(),
                library: None,
                sources: vec![crate::loader::NameSource::Plt],
            },
        );
        let mut caller = analysis(
            isa,
            0x2000,
            "call_bool",
            vec![
                call(isa, 0x5000, vec![Expr::reg(index, 64)]),
                Stmt::Ret {
                    value: Expr::reg(crate::arch::RETURN, 64),
                },
            ],
        );
        caller.ir.params.push(Param {
            index,
            name: "value".into(),
            ty: CType::Named("_Bool".into()),
        });
        let mut functions = vec![caller];
        recover(&image, &mut functions);
        let symbols = Symbols {
            functions: [(0x5000, "external_bool".into())].into(),
            import_parameters: functions[0].import_parameters.clone().into_iter().collect(),
            ..Default::default()
        };
        let source = render::render(&functions[0].ir, &[], &symbols, &[]);
        assert!(source.contains("external_bool(int32_t)"), "{source}");
        compile_and_run(
            &format!(
                "#include <stdint.h>\nuint64_t external_bool(int32_t value) {{ return value ? 9 : 4; }}\n{source}\nint main(void) {{ return call_bool(0) != 4 || call_bool(1) != 9; }}"
            ),
            "import-bool",
        );
    }
}

#[test]
fn agreed_empty_arguments_keep_an_unspecified_declaration() {
    for isa in [Isa::I386, Isa::X86_64, Isa::AArch64, Isa::Arm32] {
        let image = Image::from_code(isa, 0, Vec::new());
        let mut functions = vec![
            analysis(
                isa,
                0x1000,
                "empty",
                vec![Stmt::Ret {
                    value: Expr::Const(7),
                }],
            ),
            analysis(
                isa,
                0x2000,
                "caller",
                vec![
                    call(isa, 0x1000, Vec::new()),
                    Stmt::Ret {
                        value: Expr::Const(0),
                    },
                ],
            ),
        ];
        recover(&image, &mut functions);
        let mut symbols = Symbols::default();
        symbols.functions.insert(0x1000, "empty".into());
        symbols
            .unused_parameters
            .extend(functions[1].unused_parameters.clone());
        let code = render::render(&functions[1].ir, &[], &symbols, &[]);
        assert!(code.contains("uint64_t empty();"), "{isa}: {code}");
        compile_and_run(
            &format!(
                "#include <stdint.h>\n{code}\nuint64_t empty(void) {{ return 7; }}\nint main(void) {{ return caller(); }}"
            ),
            &format!("empty-parameters-{isa}"),
        );
    }
}

#[test]
fn an_empty_parameter_list_does_not_hide_an_observed_machine_result() {
    for isa in [Isa::I386, Isa::X86_64, Isa::AArch64, Isa::Arm32] {
        for ret in [CType::Void, CType::I32] {
            let image = Image::from_code(isa, 0, Vec::new());
            let mut functions = vec![
                analysis(
                    isa,
                    0x1000,
                    "empty",
                    vec![Stmt::Ret {
                        value: Expr::Const(0),
                    }],
                ),
                analysis(
                    isa,
                    0x2000,
                    "caller",
                    vec![
                        call(isa, 0x1000, Vec::new()),
                        Stmt::Ret {
                            value: Expr::reg(0, 64),
                        },
                    ],
                ),
            ];
            let return_type = if ret == CType::Void {
                "uint64_t"
            } else {
                "int32_t"
            };
            functions[0].ir.ret_type = ret;
            recover(&image, &mut functions);
            let mut symbols = Symbols::default();
            symbols.functions.insert(0x1000, "empty".into());
            symbols
                .unused_parameters
                .extend(functions[1].unused_parameters.clone());
            let code = render::render(&functions[1].ir, &[], &symbols, &[]);
            assert!(
                code.contains(&format!("{return_type} empty();")),
                "{isa}: {code}"
            );
            compile_and_run(
                &format!(
                    "#include <stdint.h>\n{code}\n{return_type} empty(void) {{ return 0x80000000; }}\nint main(void) {{ return caller() != UINT64_C(0x80000000); }}"
                ),
                &format!("empty-result-{isa}"),
            );
        }
    }
}

#[test]
fn recovered_parameters_changed_by_promotions_keep_prototypes() {
    for ty in [
        CType::int(1, false),
        CType::int(2, true),
        CType::Named("_Bool".into()),
        CType::Named("float".into()),
    ] {
        let mut callee = analysis(
            Isa::X86_64,
            0x1000,
            "narrow",
            vec![Stmt::Ret {
                value: Expr::Const(37),
            }],
        );
        callee.ir.params.push(Param {
            index: 7,
            name: "value".into(),
            ty: ty.clone(),
        });
        let caller = analysis(
            Isa::X86_64,
            0x2000,
            "caller",
            vec![
                call(Isa::X86_64, 0x1000, vec![Expr::Const(1)]),
                Stmt::Ret {
                    value: Expr::Const(37),
                },
            ],
        );
        let mut functions = vec![callee, caller];
        crate::service::batch::share_parameters(&mut functions, false);
        assert_eq!(
            functions[1].callee_parameters.get(&0x1000),
            Some(&vec![ty.clone()])
        );
        let symbols = Symbols {
            functions: [(0x1000, "narrow".into())].into_iter().collect(),
            function_parameters: functions[1].callee_parameters.clone().into_iter().collect(),
            ..Default::default()
        };
        let code = render::render(&functions[1].ir, &[], &symbols, &[]);
        assert!(
            code.contains(&format!("narrow({ty} unused_arg_0);")),
            "{code}"
        );
        assert!(!code.contains("narrow();"), "{code}");
    }
}

use super::*;

fn compile_source(
    scratch: &Path,
    name: &str,
    target: &str,
    input: &Path,
    flags: &[&str],
) -> PathBuf {
    let object = scratch.join(format!("{name}.o"));
    let output = Command::new(compiler())
        .args([
            "-target",
            target,
            "-ffreestanding",
            "-fno-builtin",
            "-fno-optimize-sibling-calls",
            "-c",
        ])
        .args(flags)
        .arg(input)
        .arg("-o")
        .arg(&object)
        .output()
        .expect("fixture compiler starts");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    object
}

fn link(scratch: &Path, name: &str, objects: &[PathBuf], shared: bool) -> PathBuf {
    let executable = scratch.join(name);
    let mut command = Command::new("ld.lld");
    if shared {
        command.arg("-shared");
    } else {
        command.args(["-e", "main"]);
    }
    let output = command
        .args(objects)
        .arg("-o")
        .arg(&executable)
        .output()
        .expect("fixture linker starts");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    executable
}

#[test]
fn library_format_and_distant_integer_parameters_compile() {
    let scratch = scratch_dir("body-parameters");
    let object = compile_source(
        &scratch,
        "parameters",
        "x86_64-unknown-linux-gnu",
        &common::root().join("tests/data/body_types.c"),
        &["-O1", "-fPIC", "-fvisibility=hidden"],
    );
    let executable = link(&scratch, "parameters.so", &[object], /* shared */ true);
    let mut binary = Binary::open(&executable).unwrap();
    let address = binary.find("forward_format").unwrap().addr;
    let format = binary.decompile(address, None, None).unwrap();
    assert!(format.contains("const char *"), "{format}");
    assert!(format.contains("vprintf("), "{format}");
    let cli = Command::new(env!("CARGO_BIN_EXE_velk"))
        .args(["-D", "--cache", "off"])
        .arg(&executable)
        .arg("forward_format")
        .output()
        .unwrap();
    assert!(cli.status.success());
    assert_eq!(String::from_utf8_lossy(&cli.stdout).trim(), format.trim());
    let script = format!(
        "JSON.stringify({{code:velk.open({executable:?}).getFunction('forward_format').decompile()}})"
    );
    let outcome = velk::script::Engine::new().unwrap().run(&script, None);
    assert!(outcome.error.is_none(), "{:?}", outcome.error);
    let result: serde_json::Value = serde_json::from_str(&outcome.output).unwrap();
    assert_eq!(result["code"].as_str().unwrap().trim(), format.trim());
    let child = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let response = common::mcp_request(
        child,
        &serde_json::json!({
            "jsonrpc":"2.0", "id":1, "method":"tools/call",
            "params":{"name":"velk_run_script", "arguments":{"code":script}}
        }),
    );
    let response: serde_json::Value = serde_json::from_slice(&response.stdout).unwrap();
    assert_eq!(response["result"]["isError"], false, "{response}");
    let result: serde_json::Value =
        serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(result["code"].as_str().unwrap().trim(), format.trim());
    let original = binary.analysis(address, None).unwrap().ir.clone();
    for recovered_parameters in [false, true] {
        let mut ir = original.clone();
        ir.params[1].ty = CType::pointer_to(CType::U64);
        let mut symbols = velk::render::callee_names(binary.image());
        if recovered_parameters {
            for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
                if let Stmt::Call {
                    target: Some(target),
                    ..
                } = stmt
                {
                    symbols.function_parameters.insert(
                        *target,
                        vec![
                            CType::pointer_to(CType::Named("const char".into())),
                            CType::pointer_to(CType::Void),
                        ],
                    );
                }
            }
        }
        let format = velk::render::render(&ir, &[], &symbols, &[]);
        assert!(format.contains("(void *)"), "{format}");
        let source = scratch.join("format.c");
        std::fs::write(&source, &format).unwrap();
        let checked = Command::new(compiler())
            .args([
                "-target",
                if cfg!(target_os = "macos") {
                    "x86_64-apple-darwin"
                } else {
                    "x86_64-unknown-linux-gnu"
                },
                "-std=gnu11",
                "-fsyntax-only",
                "-Werror=int-conversion",
                "-Werror=incompatible-pointer-types",
            ])
            .arg(&source)
            .output()
            .unwrap();
        if cfg!(target_os = "macos") || cfg!(target_arch = "x86_64") {
            assert!(
                checked.status.success(),
                "{}\n{format}",
                String::from_utf8_lossy(&checked.stderr)
            );
        }
        let format = format.replace("vprintf(", "format_probe(");
        syntax::run_printed(
            &format!(
                "#include <stdio.h>\n#include <stdarg.h>\n#include <string.h>\nint format_probe(const char *, void *);\n{format}"
            ),
            "char actual[128]; int format_probe(const char *format, void *args) { return vsnprintf(actual, sizeof actual, format, *(va_list *)args); }\nint invoke(const char *format, ...) { va_list args; va_start(args, format); int result = forward_format(format, (void *)&args); va_end(args); return result; }",
            "char expected[128]; for(int i=-128;i<128;++i) { int n=snprintf(expected,sizeof expected,\"%d:%s\",i,\"value\"); if(invoke(\"%d:%s\",i,\"value\")!=n || strcmp(actual,expected)) return 1; } return 0;",
        );
    }
    for arch in ["x86_64", "aarch64", "i386", "armv7"] {
        let target = format!("{arch}-unknown-linux-gnu");
        let object = compile_source(
            &scratch,
            &format!("parameters-{arch}"),
            &target,
            &common::root().join("tests/data/body_types.c"),
            &["-O1", "-fPIC", "-fvisibility=hidden"],
        );
        let executable = link(
            &scratch,
            &format!("parameters-{arch}.so"),
            &[object],
            /* shared */ true,
        );
        let mut binary = Binary::open(&executable).unwrap();
        let names: Vec<_> = (0..9)
            .map(|i| format!("helper{i}"))
            .chain(["pointer_bits".into(), "main".into()])
            .collect();
        let mut definitions = Vec::new();
        for name in names {
            let address = binary.find(&name).unwrap().addr;
            definitions.push(binary.decompile(address, None, None).unwrap());
        }
        let code = velk::render::combine(&definitions.join("\n")).replace("main(", "entry_body(");
        if matches!(arch, "x86_64" | "aarch64") {
            assert!(code.contains("(uintptr_t)envp"), "{arch}: {code}");
        }
        syntax::run_printed(
            &code,
            "",
            "char *args[2]={0}; for(int i=-128;i<128;++i) if((uint32_t)entry_body(i,args,args)!=(uint32_t)(9*i+45+(uintptr_t)args+1)) return 1; return 0;",
        );
    }
}

#[test]
fn i386_stack_protected_register_inputs_preserve_bytes() {
    let scratch = scratch_dir("i386-register-inputs");
    let support = compile_source(
        &scratch,
        "support",
        "i386-unknown-linux-gnu",
        &common::root().join("tests/data/symbolic_streams.c"),
        &["-O2", "-fPIC"],
    );
    for optimization in ["-O2", "-Os"] {
        let object = compile_source(
            &scratch,
            &format!("split{optimization}"),
            "i386-unknown-linux-gnu",
            &common::root().join("tests/data/crackmes/split.c"),
            &[optimization, "-g", "-fPIE", "-fstack-protector-all"],
        );
        let executable = link(
            &scratch,
            &format!("split{optimization}"),
            &[object, support.clone()],
            /* shared */ false,
        );
        let mut binary = Binary::open(&executable).unwrap();
        let mut definitions = Vec::new();
        for name in ["first", "last", "check"] {
            let address = binary.find(name).unwrap().addr;
            let code = binary.decompile(address, None, None).unwrap();
            assert!(!code.contains("unused_arg"), "{code}");
            definitions.push(code);
        }
        let code = velk::render::combine(&definitions.join("\n"));
        let assertions = "unsigned char *s=mmap((void *)0x10000000,0x10000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON|MAP_FIXED,-1,0); if(s==MAP_FAILED) return 2; for(unsigned i=0;i<65536;++i) {s[0]=i;s[1]=i>>8;s[2]=i;s[3]=i>>8; int a=s[0]==70 && s[1]==76; int b=s[2]==65 && s[3]==71; if(first((uintptr_t)s)!=a || last((uintptr_t)s)!=b || check((uintptr_t)s)!=(a&&b)) return 1;} memcpy(s,\"FLAG\",4); return check((uintptr_t)s)!=1;";
        let program = Program {
            text: format!(
                "{HEADER}#include <sys/mman.h>\n#include <string.h>\n{code}\nint main(void) {{ {assertions} }}"
            ),
            ranges: Vec::new(),
        };
        let flags: &[&str] = if cfg!(target_os = "macos") {
            &["-arch", "x86_64", "-Wl,-pagezero_size,0x1000"]
        } else {
            &[]
        };
        for level in LEVELS {
            let executable = build(&program, &scratch, level, flags);
            let output = Command::new(executable).output().unwrap();
            assert!(output.status.success(), "{:?}\n{code}", output.status);
        }
    }
}

#[test]
fn i386_array_arguments_to_integer_stubs_compile() {
    let scratch = scratch_dir("i386-array-arguments");
    let support = compile_source(
        &scratch,
        "support",
        "i386-unknown-linux-gnu",
        &common::root().join("tests/data/symbolic_streams.c"),
        &["-O2", "-fPIC"],
    );
    let object = compile_source(
        &scratch,
        "argv",
        "i386-unknown-linux-gnu",
        &common::root().join("tests/data/crackmes/argv.c"),
        &["-O0", "-fno-pie"],
    );
    let executable = link(
        &scratch,
        "argv",
        &[object, support],
        /* shared */ false,
    );
    let mut binary = Binary::open(&executable).unwrap();
    let addresses: Vec<_> = binary.image().functions.keys().copied().collect();
    let definitions = binary.decompile_many(&addresses, None, None).unwrap();
    let code = velk::render::combine(
        &definitions
            .into_iter()
            .map(Result::unwrap)
            .collect::<Vec<_>>()
            .join("\n"),
    );
    assert!(code.contains("memset_"), "{code}");
    assert!(code.contains("(uintptr_t)(local_"), "{code}");
    let path = scratch.join("argv.c");
    std::fs::write(&path, &code).unwrap();
    let output = Command::new(compiler())
        .args([
            "-std=gnu11",
            "-fsyntax-only",
            "-Werror=int-conversion",
            "-Werror=incompatible-pointer-types",
        ])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{code}",
        String::from_utf8_lossy(&output.stderr)
    );
    let address = binary.find("memset").unwrap().addr;
    let name = velk::render::callee_names(binary.image()).functions[&address].clone();
    let code = binary.decompile(address, None, None).unwrap();
    syntax::run_printed(
        &code,
        "",
        &format!(
            "for(uint64_t i=0;i<65536;++i) if((uint32_t){name}(i*65537)!=(uint32_t)(i*65537)) return 1; return 0;"
        ),
    );
}

#[test]
fn matching_pointer_arguments_type_the_local_and_convert_void_pointers_implicitly() {
    use velk::ir::{RegRef, VARIABLE_BASE};
    for isa in [Isa::X86_64, Isa::I386, Isa::AArch64, Isa::Arm32] {
        let convention = Convention::of(isa, velk::loader::Format::Elf, false);
        let pointer = CType::pointer_to(CType::Named("char".into()));
        let call = |target, index| Stmt::Call {
            kind: velk::ir::CallKind::Invoke,
            target: Some(target),
            through: None,
            convention,
            args: Some(vec![Expr::reg(index, 64)]),
            floats_named: false,
            abi: None,
            outputs: Vec::new(),
            clobbers: None,
            via: None,
        };
        let mut ir = synthetic_ir(
            "forward_pointer",
            Vec::new(),
            CType::U64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: VARIABLE_BASE,
                        width: 64,
                    },
                    value: Expr::Load {
                        addr: Box::new(Expr::reg(0, 64)),
                        width: 8,
                        signed: false,
                    },
                },
                Stmt::Assign {
                    dest: RegRef {
                        index: VARIABLE_BASE + 1,
                        width: 64,
                    },
                    value: Expr::reg(VARIABLE_BASE, 64),
                },
                call(0x1000, VARIABLE_BASE),
                call(0x1000, VARIABLE_BASE + 1),
                call(0x2000, VARIABLE_BASE + 1),
                Stmt::Ret {
                    value: Expr::Const(0),
                },
            ],
        );
        ir.isa = isa;
        ir.name = Some("forward_pointer".into());
        ir.params.push(velk::ir::Param {
            index: 0,
            name: "input".into(),
            ty: CType::pointer_to(pointer.clone()),
        });
        let mut symbols = velk::render::Symbols::default();
        symbols.functions.insert(0x1000, "observe_pointer".into());
        symbols.function_parameters.insert(0x1000, vec![pointer]);
        symbols.function_returns.insert(0x1000, CType::Void);
        symbols.functions.insert(0x2000, "observe_void".into());
        symbols
            .function_parameters
            .insert(0x2000, vec![CType::pointer_to(CType::Void)]);
        symbols.function_returns.insert(0x2000, CType::Void);
        let code = velk::render::render(&ir, &[], &symbols, &[]);
        assert!(code.contains("char *"), "{isa}: {code}");
        assert!(!code.contains("observe_pointer((char *)"), "{isa}: {code}");
        assert!(!code.contains("(void *)"), "{isa}: {code}");
        syntax::run_printed(
            &code,
            "static char *expected; static int calls; void observe_pointer(char *value) { if(value != expected) __builtin_trap(); ++calls; } void observe_void(void *value) { observe_pointer(value); }",
            "char bytes[256]; for(int i=0;i<256;++i) { expected=bytes+i; calls=0; forward_pointer(&expected); if(calls!=3) return 1; } return 0;",
        );
        symbols.functions.insert(0x2000, "observe_integer".into());
        symbols.function_parameters.insert(0x2000, vec![CType::U64]);
        let code = velk::render::render(&ir, &[], &symbols, &[]);
        assert!(code.contains("(char *)"), "{isa}: {code}");
        syntax::run_printed(
            &code,
            "static char *expected; static int calls; void observe_pointer(char *value) { if(value != expected) __builtin_trap(); ++calls; } void observe_integer(uint64_t value) { if(value != (uintptr_t)expected) __builtin_trap(); ++calls; }",
            "char bytes[256]; for(int i=0;i<256;++i) { expected=bytes+i; calls=0; forward_pointer(&expected); if(calls!=3) return 1; } return 0;",
        );
    }
}

#[test]
fn void_pointer_conversions_preserve_required_qualifier_casts() {
    for (target, cast) in [
        (CType::Named("struct item".into()), false),
        (CType::Named("const uint8_t".into()), true),
        (
            CType::Array(Box::new(CType::Named("const uint8_t".into()))),
            true,
        ),
    ] {
        let ir = synthetic_ir(
            "object_address",
            vec![Param {
                index: 7,
                name: "input".into(),
                ty: CType::pointer_to(target),
            }],
            CType::pointer_to(CType::Void),
            vec![Stmt::Ret {
                value: Expr::reg(7, 64),
            }],
        );
        let code = velk::render::render(&ir, &[], &Default::default(), &[]);
        assert_eq!(code.contains("return (void *)"), cast, "{code}");
        syntax::run_printed(
            &format!("struct item {{ uint8_t value; }};\n{code}"),
            "",
            "uint8_t bytes[64]; for(int i=0;i<64;++i) if(object_address((void *)(bytes+i)) != bytes+i) return 1; return 0;",
        );
    }
}

#[test]
fn pointer_qualification_is_implicit_only_at_the_first_level() {
    let character = CType::Named("char".into());
    let constant_character = CType::Named("const char".into());
    for (source, target, cast) in [
        (character.clone(), constant_character.clone(), false),
        (
            CType::pointer_to(character),
            CType::pointer_to(constant_character),
            true,
        ),
    ] {
        let ir = synthetic_ir(
            "object_address",
            vec![Param {
                index: 7,
                name: "input".into(),
                ty: CType::pointer_to(source),
            }],
            CType::pointer_to(target),
            vec![Stmt::Ret {
                value: Expr::reg(7, 64),
            }],
        );
        let code = velk::render::render(&ir, &[], &Default::default(), &[]);
        assert_eq!(code.contains("return (const char *"), cast, "{code}");
        syntax::run_printed(
            &code,
            "",
            "uintptr_t slots[64]; for(int i=0;i<64;++i) if((const void *)object_address((void *)(slots+i)) != slots+i) return 1; return 0;",
        );
    }
}

#[test]
fn pointer_register_arguments_preserve_whole_addresses_and_partial_bits() {
    for isa in [Isa::I386, Isa::Arm32, Isa::X86_64, Isa::AArch64] {
        for width in [8, 16, 32] {
            let convention = Convention::of(isa, velk::loader::Format::Elf, false);
            let pointer = CType::pointer_to(CType::Named("char".into()));
            let mut ir = synthetic_ir(
                "forward_word",
                vec![Param {
                    index: 7,
                    name: "input".into(),
                    ty: pointer.clone(),
                }],
                CType::U64,
                vec![
                    Stmt::Call {
                        kind: velk::ir::CallKind::Invoke,
                        target: Some(0x1000),
                        through: None,
                        convention,
                        args: Some(vec![Expr::reg(7, width)]),
                        floats_named: false,
                        abi: None,
                        outputs: Vec::new(),
                        clobbers: None,
                        via: None,
                    },
                    Stmt::Ret {
                        value: Expr::Const(0),
                    },
                ],
            );
            ir.isa = isa;
            ir.convention = convention;
            let mut symbols = velk::render::Symbols::default();
            symbols.functions.insert(0x1000, "observe_pointer".into());
            symbols.function_parameters.insert(0x1000, vec![pointer]);
            symbols.function_returns.insert(0x1000, CType::Void);
            let code = velk::render::render(&ir, &[], &symbols, &[]);
            let narrow = width
                < if matches!(isa, Isa::X86_64 | Isa::AArch64) {
                    64
                } else {
                    32
                };
            let bits = (1u64 << width) - 1;
            assert_eq!(
                code.contains(&format!("& 0x{bits:x}")),
                narrow,
                "{isa}: {code}"
            );
            assert!(!code.contains("(uint32_t)(uintptr_t)"), "{code}");
            let mask = if narrow {
                format!("0x{bits:x}")
            } else {
                "UINTPTR_MAX".into()
            };
            syntax::run_printed(
                &code,
                &format!(
                    "static char *expected; void observe_pointer(char *value) {{ if((uintptr_t)value != ((uintptr_t)expected & {mask})) __builtin_trap(); }}"
                ),
                "char bytes[256]; for(int i=0;i<256;++i) { expected=bytes+i; forward_word(expected); } return 0;",
            );
        }
    }
}

#[test]
fn selected_function_addresses_keep_the_explicit_void_pointer_conversion() {
    for isa in [Isa::I386, Isa::Arm32, Isa::X86_64, Isa::AArch64] {
        let mut ir = synthetic_ir(
            "select_function",
            vec![Param {
                index: 7,
                name: "choose".into(),
                ty: CType::U64,
            }],
            CType::pointer_to(CType::Void),
            vec![Stmt::Ret {
                value: Expr::Select {
                    cond: Cond::Ne,
                    lhs: Box::new(Expr::reg(7, 64)),
                    rhs: Box::new(Expr::Const(0)),
                    then: Box::new(Expr::Const(0x1000)),
                    els: Box::new(Expr::Const(0x2000)),
                },
            }],
        );
        ir.isa = isa;
        let mut symbols = velk::render::Symbols::default();
        for (address, name) in [(0x1000, "function_one"), (0x2000, "function_two")] {
            symbols.functions.insert(address, name.into());
            symbols.function_returns.insert(address, CType::U64);
        }
        let code = velk::render::render(&ir, &[], &symbols, &[]);
        assert!(code.contains("return (void *)"), "{isa}: {code}");
        syntax::run_printed(
            &code,
            "uint64_t function_one(void) { return 1; } uint64_t function_two(void) { return 2; }",
            "for(int choose=-64;choose<=64;++choose) { uint64_t (*function)(void)=(uint64_t (*)(void))select_function(choose); if(function() != (choose ? 1 : 2)) return 1; } return 0;",
        );
    }
}

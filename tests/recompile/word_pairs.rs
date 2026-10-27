use super::*;

#[test]
fn stack_parameters_require_the_same_object_at_every_caller() {
    if Command::new("ld.lld").arg("--version").output().is_err() {
        eprintln!("ld.lld unavailable; i386 processor comparison skipped");
        return;
    }
    for scalar_caller in [false, true] {
        for level in ["-O0", "-O2"] {
            let scratch = scratch_dir(&format!("stack-objects-{scalar_caller}-{level}"));
            let callee_source = scratch.join("callee.c");
            let caller_source = scratch.join("caller.c");
            let callee = scratch.join("callee.o");
            let caller = scratch.join("caller.o");
            let image = scratch.join("combined.o");
            common::compiler::compile_file(
                Command::new(compiler())
                    .args(["-target", "i386-linux-gnu", "-c", "-fno-pic", level])
                    .arg(&callee_source)
                    .arg("-o")
                    .arg(&callee),
                &callee_source,
                "int stack_object(unsigned short a, unsigned long long b) { return a + (int)b; }",
            );
            let source = if scalar_caller {
                "extern int stack_object(unsigned short, unsigned long long);\nint object_caller(unsigned long long b) { return stack_object(7, b); }\nextern int stack_words(unsigned, unsigned, unsigned) __asm__(\"stack_object\");\nint scalar_caller(unsigned a, unsigned b) { return stack_words(7, a, b); }"
            } else {
                "extern int stack_object(unsigned short, unsigned long long);\nint object_caller(unsigned long long b) { return stack_object(7, b); }"
            };
            common::compiler::compile_file(
                Command::new(compiler())
                    .args(["-target", "i386-linux-gnu", "-c", "-g", "-fno-pic", level])
                    .arg(&caller_source)
                    .arg("-o")
                    .arg(&caller),
                &caller_source,
                source,
            );
            let output = Command::new("ld.lld")
                .args(["-r", "-m", "elf_i386"])
                .arg(&callee)
                .arg(&caller)
                .arg("-o")
                .arg(&image)
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            let mut binary = Binary::open(&image).unwrap();
            let address = binary.find("stack_object").unwrap().addr;
            let code = binary.decompile(address, None, None).unwrap();
            let ir = &binary.analysis(address, None).unwrap().ir;
            if scalar_caller {
                assert!(
                    ir.stack_params.iter().all(|param| param.size == 4),
                    "{code}"
                );
                syntax::run_printed(
                    &code,
                    "",
                    if ir.stack_params.len() == 3 {
                        "return stack_object(7, 17, 0xabcdef01) != 24;"
                    } else {
                        "return stack_object(7, 17) != 24;"
                    },
                );
            } else {
                assert_eq!(ir.stack_params.len(), 2, "{level}: {code}");
                assert_eq!(ir.stack_params[1].size, 8, "{code}");
                syntax::run_printed(
                    &code,
                    "",
                    "return stack_object(7, UINT64_C(0xabcdef0100000011)) != 24;",
                );
            }
        }
    }
}

#[test]
fn stack_words_and_call_results_match_original_c() {
    if Command::new("ld.lld").arg("--version").output().is_err() {
        eprintln!("ld.lld unavailable; i386 processor comparison skipped");
        return;
    }
    let original = include_str!("word_pairs.c");
    let functions = [
        "stack_callee",
        "stack_caller",
        "g",
        "h",
        "f",
        "return_callee",
        "return_caller",
        "observe_return",
        "multiply_callee",
        "multiply_caller",
        "observe_multiply",
        "narrow_sum",
        "use_narrow",
        "narrow_live_high",
        "use_live_high",
        "preserve_high",
    ];
    let original_reference = original
        .replace("typedef unsigned long long u64;", "")
        .replace("typedef signed long long i64;", "");
    let mut reference = String::from("#define g_a reference_g_a\n");
    for function in functions {
        writeln!(reference, "#define {function} reference_{function}").unwrap();
    }
    reference.push_str(&original_reference);
    reference.push_str("\n#undef g_a\n");
    for function in functions {
        writeln!(reference, "#undef {function}").unwrap();
    }
    for (target, mode, gcc, pie) in [
        ("i386-linux-gnu", "", false, false),
        ("i386-linux-gnu", "", true, false),
        ("i386-linux-gnu", "", true, true),
        ("armv7a-linux-gnueabihf", "-marm", false, false),
        ("armv7a-linux-gnueabihf", "-mthumb", false, false),
    ] {
        if gcc {
            if Command::new("gcc").arg("--version").output().is_err() {
                eprintln!("GCC is unavailable; Clang still checks i386 word pairs.");
                continue;
            }
            let scratch = scratch_dir("word-pairs-gcc-probe");
            let object = scratch.join("probe.o");
            let compiled = common::compiler::run(
                Command::new("gcc")
                    .args(["-m32", "-x", "c", "-c", "-", "-o"])
                    .arg(&object),
                Some("int probe;"),
            );
            if !compiled.status.success()
                || !std::fs::read(&object).is_ok_and(|bytes| {
                    bytes.starts_with(b"\x7fELF\x01\x01") && bytes.get(18..20) == Some(&[3, 0])
                })
            {
                eprintln!("GCC is unavailable; Clang still checks i386 word pairs.");
                continue;
            }
        }
        for level in ["-O0", "-O1", "-O2"] {
            for debug in [false, true] {
                let scratch = scratch_dir(&format!(
                    "word-pairs-{target}{mode}{level}-{debug}-{gcc}-{pie}"
                ));
                let source = scratch.join("original.c");
                let object = scratch.join("original.o");
                let image = scratch.join("original.elf");
                let mut command = if gcc {
                    Command::new("gcc")
                } else {
                    Command::new(compiler())
                };
                if gcc {
                    command.arg("-m32");
                } else {
                    command.args(["-target", target]);
                }
                command.args(["-c", "-fno-inline", "-fno-pic", "-fno-pie", level]);
                if pie {
                    command.arg("-fPIE");
                }
                if !mode.is_empty() {
                    command.arg(mode);
                }
                if debug {
                    command.arg("-g");
                }
                common::compiler::compile_file(
                    command.arg(&source).arg("-o").arg(&object),
                    &source,
                    original,
                );
                let linked = Command::new("ld.lld")
                    .args([
                        "-m",
                        if target.starts_with("i386") {
                            "elf_i386"
                        } else {
                            "armelf_linux_eabi"
                        },
                        "--entry=stack_caller",
                    ])
                    .arg(&object)
                    .arg("-o")
                    .arg(&image)
                    .output()
                    .unwrap();
                assert!(linked.status.success(), "{linked:?}");
                let mut binary = Binary::open(&image).unwrap();
                let mut definitions = String::new();
                for function in functions {
                    let address = binary.find(function).unwrap().addr;
                    let code = binary.decompile(address, None, None).unwrap();
                    if matches!(
                        function,
                        "g" | "return_callee"
                            | "return_caller"
                            | "multiply_callee"
                            | "multiply_caller"
                    ) {
                        assert!(
                            binary
                                .analysis(address, None)
                                .unwrap()
                                .ir
                                .ret_type
                                .integer()
                                .is_some_and(|(bits, _)| bits == 64),
                            "{target}{mode}{level} {debug}: {code}"
                        );
                    }
                    if matches!(
                        function,
                        "narrow_sum" | "narrow_live_high" | "preserve_high"
                    ) {
                        assert!(
                            binary
                                .analysis(address, None)
                                .unwrap()
                                .ir
                                .ret_type
                                .integer()
                                .is_some_and(|(bits, _)| bits == 32),
                            "{target}{mode}{level} {debug}: {code}"
                        );
                    }
                    if function == "narrow_live_high" {
                        let instructions = binary.disasm(address, 100).unwrap().join("\n");
                        assert!(
                            instructions.contains(if target.starts_with("i386") {
                                "edx"
                            } else {
                                "r1"
                            }),
                            "{instructions}"
                        );
                    }
                    assert!(!code.contains("also returned by the call"), "{code}");
                    definitions.push_str(&code);
                }
                let code = velk::render::combine(&definitions);
                let mut checks = String::new();
                for x in [-32768i32, -17, -1, 0, 1, 2, 5, 32767] {
                    writeln!(checks, "if ((uint64_t)multiply_caller({x}) != (uint64_t)reference_multiply_caller({x})) return 7;").unwrap();
                    writeln!(checks, "g_a = reference_g_a = 0; if ((uint32_t)f({x}) != (uint32_t)reference_f({x})) return 1; if ((uint32_t)stack_caller({x}) != (uint32_t)reference_stack_caller({x})) return 2; if ((uint64_t)return_caller({x}) != (uint64_t)reference_return_caller({x})) return 3;").unwrap();
                    for seed in [-1000, 1000] {
                        writeln!(checks, "g_a = reference_g_a = {seed}; if ((uint32_t)f({x}) != (uint32_t)reference_f({x})) return 1;").unwrap();
                    }
                }
                for b in [0u64, 0xffff_ffff, 0x8000_0000_0000_0000, u64::MAX] {
                    for a in [0u16, 1, u16::MAX] {
                        writeln!(checks, "if ((uint64_t)return_callee({a}, {b}ULL) != (uint64_t)reference_return_callee({a}, {b}ULL)) return 5;").unwrap();
                    }
                }
                for y in [i32::MIN, i32::MIN + 1, -715_827_883, 715_827_883, i32::MAX] {
                    writeln!(checks, "if ((uint64_t)multiply_caller({y}) != (uint64_t)reference_multiply_caller({y}) || (uint64_t)return_caller({y}) != (uint64_t)reference_return_caller({y})) return 8;").unwrap();
                }
                for x in [0u32, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
                    writeln!(checks, "if ((uint32_t)use_live_high({x}u) != reference_use_live_high({x}u)) return 4;").unwrap();
                    writeln!(checks, "if ((uint32_t)preserve_high({x}u) != reference_preserve_high({x}u)) return 6;").unwrap();
                }
                syntax::run_printed(
                    &code,
                    &format!(
                        "{reference}\n{} g_a;",
                        if debug { "int" } else { "uint32_t" }
                    ),
                    &format!("{checks} return 0;"),
                );
            }
        }
    }
}

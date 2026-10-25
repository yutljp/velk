use super::*;

#[test]
fn recompile_binds_the_target_entry_stack_pointer() {
    for isa in [Isa::AArch64, Isa::X86_64] {
        let mut ir = synthetic_ir(
            "entry_address",
            vec![],
            CType::U64,
            vec![Stmt::Ret {
                value: Expr::bin(
                    BinOp::Add,
                    Expr::reg(velk::arch::stack_pointer(isa), 64),
                    Expr::Const(24),
                ),
            }],
        );
        ir.isa = isa;
        ir.convention = Convention::of(isa, velk::loader::Format::Elf, false);
        let candidate = printed_candidate(ir, vec![vec![]]);
        assert!(candidate.code.contains("= velk_entry_stack_pointer();"));
        check_candidates("entry-stack-pointer", vec![candidate], Mode::Registers, &[]);
    }
}

#[test]
fn nested_negation_preserves_tokens_and_values() {
    let value = Expr::bin(BinOp::And, Expr::reg(7, 64), Expr::Const(4));
    let negate = |value| Expr::bin(BinOp::Sub, Expr::Const(0), value);
    let ir = synthetic_ir(
        "nested_negation",
        vec![Param {
            index: 7,
            name: "x".into(),
            ty: CType::U64,
        }],
        CType::U64,
        vec![Stmt::Ret {
            value: negate(negate(value)),
        }],
    );
    let candidate = printed_candidate(
        ir,
        [0, 1, 4, 5, u64::MAX]
            .into_iter()
            .map(|x| vec![x])
            .collect(),
    );
    assert!(
        candidate.code.contains("- -(x & 0x4)"),
        "{}",
        candidate.code
    );
    check_candidates("nested-negation", vec![candidate], Mode::Registers, &[]);
}

pub(super) fn run_printed(code: &str, support: &str, assertions: &str) {
    use std::hash::{Hash, Hasher};
    let mut hash = std::hash::DefaultHasher::new();
    code.hash(&mut hash);
    let scratch = scratch_dir(&format!("syntax-values-{:x}", hash.finish()));
    let source = scratch.join("values.c");
    std::fs::write(
        &source,
        format!("{HEADER}{code}\n{support}\nint main(void) {{ {assertions} }}"),
    )
    .unwrap();
    for level in LEVELS {
        let executable = scratch.join(format!("values{level}"));
        let output = Command::new(compiler())
            .args(FLAGS)
            .arg(level)
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{code}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            Command::new(&executable).status().unwrap().success(),
            "{code}"
        );
    }
}

#[test]
fn typed_global_objects_preserve_signed_bits_and_stores() {
    for signed in [false, true] {
        let mut ir = synthetic_ir(
            "read_object",
            vec![],
            CType::U64,
            vec![Stmt::Ret {
                value: Expr::Load {
                    addr: Box::new(Expr::Const(0x2000)),
                    width: 4,
                    signed,
                },
            }],
        );
        ir.debug_globals = vec![(0x2000, CType::I32, 4)];
        let symbols = velk::render::Symbols {
            data: [(0x2000, "object".into())].into(),
            ..Default::default()
        };
        let code = velk::render::render(&ir, &[], &symbols, &[(0x2000, 4)]);
        assert!(code.contains("extern int32_t object;"), "{code}");
        assert!(!code.contains("0x2000"), "{code}");
        run_printed(
            &code,
            "int32_t object = -1;",
            if signed {
                "return read_object() != UINT64_MAX;"
            } else {
                "return read_object() != UINT32_MAX;"
            },
        );
    }
    for isa in ["x86_64", "aarch64"] {
        let mut binary = Binary::open(
            &common::fixtures_dir().join(format!("metrics/l4_memory.{isa}.O0.debug.elf")),
        )
        .unwrap();
        let address = binary.find("bump").unwrap().addr;
        let code = binary.decompile(address, None, None).unwrap();
        assert!(code.contains("extern int g_counter;"), "{code}");
        assert!(!code.contains("*const g_counter"), "{code}");
        run_printed(
            &code,
            "int g_counter = 41;",
            "bump(); return g_counter != 42;",
        );
    }
}

#[test]
fn typed_global_struct_arrays_preserve_field_offsets() {
    let mut ir = synthetic_ir(
        "read_item",
        vec![Param {
            index: 7,
            name: "i".into(),
            ty: CType::U64,
        }],
        CType::U64,
        vec![Stmt::Ret {
            value: Expr::Load {
                addr: Box::new(Expr::bin(
                    BinOp::Add,
                    Expr::Const(0x2008),
                    Expr::bin(BinOp::Mul, Expr::reg(7, 64), Expr::Const(24)),
                )),
                width: 8,
                signed: false,
            },
        }],
    );
    ir.definitions = vec![velk::ir::Definition {
        name: "struct item".into(),
        members: vec![
            "uint64_t tag;".into(),
            "uint64_t value;".into(),
            "uint64_t count;".into(),
        ],
        fields: vec!["tag".into(), "value".into(), "count".into()],
        contains: vec![],
        size: 24,
        alignment: Some(8),
        compatible_profiles: vec![AbiProfile::SysV],
    }];
    ir.members = ["tag", "value", "count"]
        .iter()
        .enumerate()
        .map(|(i, name)| velk::ir::Member {
            structure: "item".into(),
            offset: i as i64 * 8,
            name: (*name).into(),
            ty: CType::U64,
            width: 8,
        })
        .collect();
    ir.debug_globals = vec![(
        0x2000,
        CType::Array(Box::new(CType::Named("struct item".into()))),
        72,
    )];
    let symbols = velk::render::Symbols {
        data: [(0x2000, "items".into())].into(),
        ..Default::default()
    };
    let code = velk::render::render(&ir, &[], &symbols, &[(0x2000, 72)]);
    assert!(code.contains("items[i].value"), "{code}");
    assert!(!code.contains("(uint8_t *)"), "{code}");
    run_printed(
        &code,
        "struct item items[] = {{1, 73, 2}, {3, 99, 4}, {5, UINT64_MAX, 6}};",
        "return read_item(0) != 73 || read_item(1) != 99 || read_item(2) != UINT64_MAX;",
    );
    ir.params[0].ty = CType::I32;
    ir.blocks[0].stmts = vec![
        Stmt::Assign {
            dest: velk::ir::RegRef {
                index: velk::ir::VARIABLE_BASE,
                width: 64,
            },
            value: Expr::bin(
                BinOp::Mul,
                Expr::SignExtend {
                    value: Box::new(Expr::reg(7, 32)),
                    width: 4,
                },
                Expr::Const(24),
            ),
        },
        Stmt::Ret {
            value: Expr::Load {
                addr: Box::new(Expr::bin(
                    BinOp::Add,
                    Expr::Const(0x2008),
                    Expr::reg(velk::ir::VARIABLE_BASE, 64),
                )),
                width: 8,
                signed: false,
            },
        },
    ];
    let code = velk::render::render(&ir, &[], &symbols, &[(0x2000, 72)]);
    assert!(code.contains("].value"), "{code}");
    assert!(!code.contains("(uint8_t *)"), "{code}");
    run_printed(
        &code,
        "struct item items[] = {{1, 73, 2}, {3, 99, 4}, {5, UINT64_MAX, 6}};",
        "return read_item(0) != 73 || read_item(1) != 99 || read_item(2) != UINT64_MAX;",
    );
    let Stmt::Assign {
        value: Expr::Bin { lhs, .. },
        ..
    } = &mut ir.blocks[0].stmts[0]
    else {
        unreachable!()
    };
    **lhs = Expr::reg(7, 64);
    let code = velk::render::render(&ir, &[], &symbols, &[(0x2000, 72)]);
    assert!(!code.contains("].value"), "{code}");
}

#[test]
fn float_register_integer_reads_preserve_bits() {
    let ir = synthetic_ir(
        "float_bits",
        vec![Param {
            index: 7,
            name: "x".into(),
            ty: CType::Named("double".into()),
        }],
        CType::U64,
        vec![Stmt::Ret {
            value: Expr::bin(BinOp::Shr, Expr::reg(7, 64), Expr::Const(47)),
        }],
    );
    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
    assert!(code.contains(".bits"), "{code}");
    run_printed(
        &code,
        "",
        "union { uint64_t bits; double value; } x = { .bits = UINT64_C(0x7ff8123456789abc) }; return float_bits(x.value) != (x.bits >> 47);",
    );
}

#[test]
fn nonfinite_float_literals_preserve_bits() {
    for (name, bits) in [
        ("nan_bits", 0xfff8_1234_5678_9abc),
        ("infinity_bits", 0x7ff0_0000_0000_0000),
    ] {
        let ir = synthetic_ir(
            name,
            vec![],
            CType::Named("double".into()),
            vec![Stmt::Ret {
                value: Expr::Const(bits),
            }],
        );
        let code = velk::render::render(&ir, &[], &Default::default(), &[]);
        assert!(!code.contains("NaN"), "{code}");
        assert!(code.contains(".bits"), "{code}");
        run_printed(
            &code,
            "",
            &format!(
                "union {{ uint64_t bits; double value; }} x = {{ .value = {name}() }}; return x.bits != UINT64_C({bits});"
            ),
        );
    }
}

#[test]
fn stack_pointer_reads_use_explicit_target_state() {
    for (isa, convention) in [
        (Isa::X86_64, Convention::SysV),
        (Isa::AArch64, Convention::Aapcs64),
    ] {
        let mut ir = synthetic_ir("stack_bits", vec![], CType::U64, vec![]);
        ir.isa = isa;
        ir.convention = convention;
        ir.blocks[0].stmts.push(Stmt::Ret {
            value: Expr::bin(
                BinOp::And,
                Expr::reg(velk::arch::stack_pointer(isa), 64),
                Expr::Const(255),
            ),
        });
        let code = velk::render::render(&ir, &[], &Default::default(), &[]);
        assert!(code.contains("= velk_entry_stack_pointer();"), "{code}");
        run_printed(
            &code,
            "uint64_t velk_entry_stack_pointer(void) { return 0x1234; }",
            "return stack_bits() != 0x34;",
        );
    }
}

#[test]
fn byte_offsets_convert_to_the_destination_pointer_type() {
    let pointer = CType::pointer_to(CType::U64);
    let ir = synthetic_ir(
        "byte_offset",
        vec![
            Param {
                index: 7,
                name: "p".into(),
                ty: pointer.clone(),
            },
            Param {
                index: 6,
                name: "n".into(),
                ty: CType::U64,
            },
        ],
        pointer,
        vec![Stmt::Ret {
            value: Expr::bin(BinOp::Sub, Expr::reg(7, 64), Expr::reg(6, 64)),
        }],
    );
    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
    assert!(code.contains("return (uint64_t *)"), "{code}");
    run_printed(
        &code,
        "",
        "uint64_t a[3] = {1, 2, 3}; return byte_offset(a + 2, 8) != a + 1;",
    );
}

#[test]
fn pointer_values_used_as_stack_indices_are_integer_offsets() {
    let stack = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const((-16i64) as u64));
    let mut statements: Vec<_> = (0..8)
        .map(|offset| Stmt::Store {
            addr: Expr::bin(BinOp::Add, stack.clone(), Expr::Const(offset)),
            value: Expr::Const(if offset == 3 { 73 } else { 0 }),
            width: 1,
        })
        .collect();
    statements.push(Stmt::Call {
        abi: None,
        kind: velk::ir::CallKind::Invoke,
        target: Some(0x1000),
        through: None,
        convention: Convention::SysV,
        args: Some(vec![Expr::bin(BinOp::Add, stack, Expr::reg(7, 64))]),
        floats_named: false,
        outputs: velk::ir::fallback_call_outputs(Convention::SysV, None),
        clobbers: None,
        via: None,
    });
    statements.push(Stmt::Ret {
        value: Expr::reg(0, 64),
    });
    let ir = synthetic_ir(
        "stack_index",
        vec![Param {
            index: 7,
            name: "index".into(),
            ty: CType::pointer_to(CType::Int {
                bytes: 1,
                signed: false,
            }),
        }],
        CType::U64,
        statements,
    );
    let symbols = velk::render::Symbols {
        functions: [(0x1000, "check_local".into())].into(),
        ..Default::default()
    };
    let code = velk::render::render(&ir, &[], &symbols, &[]);
    assert!(code.contains("(uintptr_t)index"), "{code}");
    run_printed(
        &format!("uint64_t check_local(uint8_t *);\n{code}"),
        "uint64_t check_local(uint8_t *p) { return *p; }",
        "return stack_index((uint8_t *)(uintptr_t)3) != 73;",
    );
}

#[test]
fn stack_pointer_assignments_keep_pointer_bits() {
    let ir = synthetic_ir(
        "stack_assignment",
        vec![Param {
            index: 7,
            name: "p".into(),
            ty: CType::pointer_to(CType::Int {
                bytes: 1,
                signed: false,
            }),
        }],
        CType::U64,
        vec![
            Stmt::Assign {
                dest: velk::ir::RegRef {
                    index: 4,
                    width: 64,
                },
                value: Expr::reg(7, 64),
            },
            Stmt::Ret {
                value: Expr::bin(BinOp::And, Expr::reg(4, 64), Expr::Const(255)),
            },
        ],
    );
    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
    assert!(code.contains("rsp = (uintptr_t)p;"), "{code}");
    run_printed(
        &code,
        "uint64_t velk_entry_stack_pointer(void) { return 0; }",
        "return stack_assignment((uint8_t *)(uintptr_t)0x1234) != 0x34;",
    );
}

#[test]
fn indirect_exit_calls_a_function_address() {
    let ir = synthetic_ir(
        "indirect_exit",
        vec![Param {
            index: 7,
            name: "target".into(),
            ty: CType::U64,
        }],
        CType::U64,
        vec![Stmt::BrIndirect {
            target: Expr::reg(7, 64),
        }],
    );
    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
    assert!(code.contains("return velk_jump_target(target);"), "{code}");
    run_printed(
        &code,
        "uint64_t velk_jump_target(uint64_t target) { return target == 0x1234 ? 73 : 0; }",
        "return indirect_exit(0x1234) != 73;",
    );
}

#[test]
fn branches_outside_the_function_use_a_target_adapter() {
    let mut ir = synthetic_ir(
        "external_branch",
        vec![Param {
            index: 7,
            name: "x".into(),
            ty: CType::U64,
        }],
        CType::U64,
        vec![Stmt::Switch {
            index: Expr::reg(7, 64),
            cases: vec![(1, 0x1234)],
            default: Some(4),
        }],
    );
    ir.blocks.push(Block {
        start: 4,
        stmts: vec![Stmt::Ret {
            value: Expr::Const(42),
        }],
    });
    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
    assert!(!code.contains("goto L_1234"), "{code}");
    assert!(code.contains("velk_jump_target(0x1234)"), "{code}");
    run_printed(
        &code,
        "uint64_t velk_jump_target(uint64_t target) { return target == 0x1234 ? 73 : 0; }",
        "return external_branch(1) != 73 || external_branch(2) != 42;",
    );
}

#[test]
fn syscall_numbers_do_not_depend_on_host_macros() {
    let ir = synthetic_ir(
        "target_syscall",
        vec![],
        CType::U64,
        vec![
            Stmt::Call {
                abi: None,
                kind: velk::ir::CallKind::Syscall,
                target: None,
                through: None,
                convention: Convention::SyscallX86,
                args: Some(vec![Expr::Const(60), Expr::Const(42)]),
                floats_named: false,
                outputs: velk::ir::fallback_call_outputs(Convention::SyscallX86, None),
                clobbers: None,
                via: None,
            },
            Stmt::Ret {
                value: Expr::reg(0, 64),
            },
        ],
    );
    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
    assert!(code.contains("60 /* SYS_exit */"), "{code}");
    run_printed(
        &format!("uint64_t syscall();\n{code}"),
        "uint64_t syscall(uint64_t number, uint64_t status) { return number == 60 && status == 42 ? 73 : 0; }",
        "return target_syscall() != 73;",
    );
}

#[test]
fn exception_values_have_explicit_bindings() {
    let ir = synthetic_ir(
        "exception_values",
        vec![],
        CType::U64,
        vec![Stmt::Ret {
            value: Expr::bin(
                BinOp::Add,
                Expr::reg(velk::ir::EXCEPTION, 64),
                Expr::reg(velk::ir::SELECTOR, 64),
            ),
        }],
    );
    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
    assert!(code.contains("velk_exception_value()"), "{code}");
    assert!(code.contains("velk_exception_selector()"), "{code}");
    run_printed(
        &code,
        "uint64_t velk_exception_value(void) { return 71; } uint64_t velk_exception_selector(void) { return 2; }",
        "return exception_values() != 73;",
    );
    let ir = synthetic_ir(
        "exception_pointer",
        vec![],
        CType::pointer_to(CType::Int {
            bytes: 1,
            signed: false,
        }),
        vec![Stmt::Ret {
            value: Expr::reg(velk::ir::EXCEPTION, 64),
        }],
    );
    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
    assert!(
        code.contains("return (uint8_t *)velk_exception_value();"),
        "{code}"
    );
    run_printed(
        &code,
        "uint64_t velk_exception_value(void) { return 0x1234; }",
        "return (uintptr_t)exception_pointer() != 0x1234;",
    );
}

#[test]
fn taken_callees_accept_arguments_and_return_values() {
    let ir = synthetic_ir(
        "taken_callee",
        vec![],
        CType::U64,
        vec![
            Stmt::Assign {
                dest: velk::ir::RegRef {
                    index: velk::ir::VARIABLE_BASE,
                    width: 64,
                },
                value: Expr::Const(0x1234_5678_9abc_def0),
            },
            Stmt::Call {
                abi: None,
                kind: velk::ir::CallKind::Invoke,
                target: Some(0x1234_5678_9abc_def0),
                through: None,
                convention: Convention::SysV,
                args: Some(vec![Expr::Const(73)]),
                floats_named: false,
                outputs: velk::ir::fallback_call_outputs(Convention::SysV, None),
                clobbers: None,
                via: None,
            },
            Stmt::Ret {
                value: Expr::bin(
                    BinOp::Add,
                    Expr::reg(0, 64),
                    Expr::reg(velk::ir::VARIABLE_BASE, 64),
                ),
            },
        ],
    );
    let symbols = velk::render::Symbols {
        functions: [(0x1234_5678_9abc_def0, "callee".into())].into(),
        ..Default::default()
    };
    let code = velk::render::render(&ir, &[], &symbols, &[]);
    assert!(code.contains("uint64_t callee();"), "{code}");
    run_printed(
        &code,
        "uint64_t callee(uint64_t x) { return x; }",
        "return taken_callee() != 73 + (uintptr_t)callee;",
    );
}

#[test]
fn unknown_call_targets_have_explicit_bindings() {
    let ir = synthetic_ir(
        "unknown_call",
        vec![],
        CType::U64,
        vec![
            Stmt::Call {
                abi: None,
                kind: velk::ir::CallKind::Invoke,
                target: None,
                through: None,
                convention: Convention::SysV,
                args: Some(vec![]),
                floats_named: false,
                outputs: velk::ir::fallback_call_outputs(Convention::SysV, None),
                clobbers: None,
                via: None,
            },
            Stmt::Ret {
                value: Expr::reg(0, 64),
            },
        ],
    );
    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
    assert!(code.contains("velk_dynamic_call_target()"), "{code}");
    run_printed(
        &code,
        "static uint64_t answer(void) { return 73; } uint64_t velk_dynamic_call_target(void) { return (uintptr_t)answer; }",
        "return unknown_call() != 73;",
    );
}

pub(super) fn return_types(symbols: &velk::render::Symbols) -> BTreeMap<String, CType> {
    symbols
        .function_returns
        .iter()
        .filter_map(|(address, ty)| {
            symbols
                .functions
                .get(address)
                .map(|name| (name.clone(), ty.clone()))
        })
        .chain(symbols.import_returns.iter().filter_map(|(address, ty)| {
            symbols
                .import_slots
                .get(address)
                .map(|name| (name.clone(), ty.clone()))
        }))
        .collect()
}

pub(super) fn check(code: &str, path: &Path, returns: &BTreeMap<String, CType>) -> Option<String> {
    check_with_compiler(code, path, returns, &compiler())
}

fn check_with_compiler(
    code: &str,
    path: &Path,
    returns: &BTreeMap<String, CType>,
    compiler: &Path,
) -> Option<String> {
    let mut prelude = velk::render::Prelude::default();
    let body = renamed(&prelude.extract(code), 0);
    let mut declarations = BTreeSet::new();
    loop {
        let source = syntax_source(&prelude, &body, &declarations, returns);
        std::fs::write(path, source).expect("saved syntax source");
        let output = syntax_command(compiler)
            .arg(path)
            .output()
            .expect("C compiler");
        if output.status.success() {
            return None;
        }
        let errors = String::from_utf8_lossy(&output.stderr);
        let mut added = false;
        for line in errors.lines() {
            if let Some(rest) = line.split("error: call to undeclared function '").nth(1)
                && let Some((name, _)) = rest.split_once('\'')
            {
                added |= declarations.insert(name.to_owned());
            }
        }
        if !added {
            return Some(
                errors
                    .lines()
                    .find_map(|line| {
                        line.split_once("error: ")
                            .map(|(_, message)| message.to_owned())
                    })
                    .unwrap_or_else(|| errors.into_owned()),
            );
        }
    }
}

fn syntax_source(
    prelude: &velk::render::Prelude,
    body: &str,
    declarations: &BTreeSet<String>,
    returns: &BTreeMap<String, CType>,
) -> String {
    let mut source = HEADER
        .lines()
        .filter(|line| {
            !line.starts_with("#include")
                || ["<inttypes.h>", "<stdbool.h>", "<stddef.h>", "<stdint.h>"]
                    .iter()
                    .any(|header| line.contains(header))
        })
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    source.push_str("#include <stdlib.h>\ntypedef struct syntax_file FILE;\ntypedef struct syntax_directory DIR;\ntypedef struct syntax_mutex pthread_mutex_t;\ntypedef struct syntax_mutex_attributes pthread_mutexattr_t;\ntypedef intptr_t off_t;\ntypedef intptr_t ssize_t;\ntypedef uintptr_t pthread_t;\ntypedef uint32_t pthread_key_t;\ntypedef int32_t pid_t;\n");
    for name in declarations {
        let ty = returns.get(name).cloned().unwrap_or(CType::U64);
        writeln!(source, "{ty} {name}();").unwrap();
    }
    source.push_str(&prelude.render());
    source.push_str(body);
    source
}

fn syntax_command(compiler: &Path) -> Command {
    let mut command = Command::new(compiler);
    if cfg!(target_os = "macos") {
        command.args(["-arch", "x86_64"]);
    }
    command.args(FLAGS).args([
        "-std=gnu11",
        "-fno-builtin",
        "-fsyntax-only",
        "-ferror-limit=0",
        "-Werror=implicit-function-declaration",
    ]);
    command
}

#[test]
fn library_allocation_calls_have_pointer_prototypes() {
    let scratch = scratch_dir("syntax-allocation-prototypes");
    let path = scratch.join("function.c");
    let code = "void *allocate(size_t size, void *ptr) { void *v = malloc(size); return realloc(v ? v : ptr, size); }";
    assert_eq!(check(code, &path, &BTreeMap::new()), None);
    let source = std::fs::read_to_string(path).unwrap();
    assert!(source.contains("#include <stdlib.h>"), "{source}");
    assert!(!source.contains("uint64_t malloc();"), "{source}");
    assert!(!source.contains("uint64_t realloc();"), "{source}");
}

#[test]
fn structure_pointer_returns_do_not_define_structure_tags() {
    let code =
        "struct dirent *read_directory(DIR *directory) {\n    return readdir(directory);\n}\n";
    assert!(defined_types(code).is_empty());
    assert!(renamed(code, 7).contains("struct dirent *velk_f7(DIR *directory) {"));
    let scratch = scratch_dir("syntax-structure-return");
    let returns = [(
        "readdir".into(),
        CType::pointer_to(CType::Named("struct dirent".into())),
    )]
    .into();
    assert_eq!(check(code, &scratch.join("function.c"), &returns), None);
}

#[test]
fn library_pointer_arguments_preserve_address_bits() {
    let ir = synthetic_ir(
        "parse_integer",
        vec![Param {
            index: 7,
            name: "address".into(),
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
                outputs: velk::ir::fallback_call_outputs(Convention::SysV, None),
                clobbers: None,
                via: None,
            },
            Stmt::Ret {
                value: Expr::reg(0, 64),
            },
        ],
    );
    let symbols = velk::render::Symbols {
        functions: [(0x1000, "atoi".into())].into(),
        ..Default::default()
    };
    let code = velk::render::render(&ir, &[], &symbols, &[]);
    assert!(code.contains("atoi((const char *)address)"), "{code}");
    let scratch = scratch_dir("syntax-library-pointer-argument");
    assert_eq!(
        check(&code, &scratch.join("function.c"), &BTreeMap::new()),
        None
    );
    run_printed(
        &format!("#include <stdlib.h>\n{code}"),
        "",
        "return parse_integer((uintptr_t)\"73\") != 73;",
    );
}

#[test]
#[ignore = "decompiles and syntax-checks every fixture function"]
fn every_fixture_function_compiles() {
    scan(&common::fixtures(), "whole-syntax");
}

#[test]
#[ignore = "decompiles and syntax-checks every AArch64 language fixture function"]
fn arm64_language_fixture_functions_compile() {
    scan(
        &[
            PathBuf::from("go_probe_arm64"),
            PathBuf::from("go_stripped_arm64"),
            PathBuf::from("rust_demo_arm64"),
            PathBuf::from("rust_probe_arm64"),
            PathBuf::from("rust_probe_arm64_stripped"),
        ],
        "arm64-language-syntax",
    );
}

#[test]
fn debug_fixture_functions_compile() {
    let fixtures: Vec<_> = common::fixtures()
        .into_iter()
        .filter(|fixture| {
            let name = fixture.to_string_lossy();
            name.contains(".debug.")
                || (name.starts_with("codeview/") && !name.contains(".stripped."))
                || name.starts_with("arm64_debug")
                || name.starts_with("member_types_")
                || (name.starts_with("seh_") && name.ends_with(".dll"))
        })
        .collect();
    scan(&fixtures, "debug-syntax");
}

#[test]
fn small_fixture_functions_compile() {
    scan(
        &[
            PathBuf::from("arm64.o"),
            PathBuf::from("pe64.obj"),
            PathBuf::from("x64_div.o"),
        ],
        "subset-syntax",
    );
}

#[test]
fn large_fixture_syntax_regressions() {
    large_fixture_syntax_with_compiler(&compiler(), "default");
}

#[test]
fn newer_clang_syntax_regressions() {
    let Ok(prefix) = Command::new("brew").args(["--prefix", "llvm"]).output() else {
        eprintln!("skipping newer Clang syntax regressions: Homebrew is unavailable");
        return;
    };
    if !prefix.status.success() {
        eprintln!("skipping newer Clang syntax regressions: LLVM is unavailable");
        return;
    }
    let compiler = PathBuf::from(String::from_utf8_lossy(&prefix.stdout).trim()).join("bin/clang");
    if !compiler.is_file() {
        eprintln!("skipping newer Clang syntax regressions: compiler is unavailable");
        return;
    }
    large_fixture_syntax_with_compiler(&compiler, "newer-clang");
}

fn large_fixture_syntax_with_compiler(compiler: &Path, name: &str) {
    for (fixture, addresses) in [
        (
            "go_probe",
            vec![
                0x40b400, 0x40dc80, 0x421c20, 0x438480, 0x4415e0, 0x44fce0, 0x461f80, 0x465140,
                0x4655c0, 0x4638a0,
            ],
        ),
        (
            "rust_probe",
            vec![
                0x4a7b1, 0x2b710, 0x2a850, 0x31bc0, 0x18a64, 0x29920, 0x3dc90, 0x404b0, 0x2c510,
            ],
        ),
    ] {
        let mut binary = Binary::open(&common::fixtures_dir().join(fixture)).unwrap();
        let symbols = velk::render::callee_names(binary.image());
        let returns = return_types(&symbols);
        let scratch = scratch_dir(&format!("syntax-{name}-{fixture}"));
        for address in addresses {
            let code = binary.decompile(address, None, None).unwrap();
            let error = check_with_compiler(&code, &scratch.join("function.c"), &returns, compiler);
            assert!(error.is_none(), "{fixture} 0x{address:x}: {error:?}");
        }
    }
}

#[test]
fn arm64_language_atomic_addresses_compile() {
    for fixture in ["go_probe_arm64", "go_stripped_arm64"] {
        let mut binary = Binary::open(&common::fixtures_dir().join(fixture)).unwrap();
        let symbols = velk::render::callee_names(binary.image());
        let scratch = scratch_dir(&format!("syntax-atomic-{fixture}"));
        let code = binary.decompile(0x527d0, None, None).unwrap();
        let error = check(&code, &scratch.join("function.c"), &return_types(&symbols));
        assert!(error.is_none(), "{fixture}: {error:?}");
    }
}

#[test]
fn arm64_language_library_types_and_stack_addresses_compile() {
    let mut binary = Binary::open(&common::fixtures_dir().join("rust_probe_arm64")).unwrap();
    let symbols = velk::render::callee_names(binary.image());
    let scratch = scratch_dir("syntax-arm64-rust");
    for address in [
        0x100001b30,
        0x1000037cc,
        0x100005bb0,
        0x100019894,
        0x1000358c4,
        0x1000359b4,
    ] {
        let code = binary.decompile(address, None, None).unwrap();
        let error = check(&code, &scratch.join("function.c"), &return_types(&symbols));
        assert!(error.is_none(), "0x{address:x}: {error:?}");
    }
}

fn check_batch(
    codes: &[(u64, String)],
    scratch: &Path,
    returns: &BTreeMap<String, CType>,
    compiler: &Path,
) -> Vec<(u64, Option<String>)> {
    let paths: Vec<_> = codes
        .iter()
        .map(|(address, code)| {
            let mut prelude = velk::render::Prelude::default();
            let body = renamed(&prelude.extract(code), 0);
            let path = scratch.join(format!("function-{address:x}.c"));
            std::fs::write(
                &path,
                syntax_source(&prelude, &body, &BTreeSet::new(), returns),
            )
            .expect("saved syntax source");
            path
        })
        .collect();
    let output = syntax_command(compiler)
        .args(&paths)
        .output()
        .expect("C compiler");
    codes
        .iter()
        .zip(paths)
        .map(|((address, code), path)| {
            let error = if output.status.success() {
                None
            } else {
                check_with_compiler(code, &path, returns, compiler)
            };
            if error.is_none() {
                std::fs::remove_file(path).expect("removed successful syntax source");
            }
            (*address, error)
        })
        .collect()
}

fn scan(fixtures: &[PathBuf], name: &str) {
    let scratch = scratch_dir(name);
    let compiler = compiler();
    let mut fixtures = fixtures.to_vec();
    fixtures.sort();
    let indexed: Vec<_> = fixtures.iter().enumerate().collect();
    let results = common::in_parallel(&indexed, |(index, fixture)| {
        let directory = scratch.join(format!("fixture-{index}"));
        std::fs::create_dir_all(&directory).expect("syntax fixture directory");
        let mut binary =
            Binary::open(&common::fixtures_dir().join(fixture)).expect("fixture opens");
        let mut functions: Vec<_> = binary.image().functions.values().cloned().collect();
        functions.sort_by_key(|function| function.addr);
        let symbols = velk::render::callee_names(binary.image());
        let returns = return_types(&symbols);
        let mut compiled = 0;
        let mut unavailable = 0;
        let mut errors = Vec::new();
        for chunk in functions.chunks(16) {
            let mut codes = Vec::new();
            for function in chunk {
                match binary.decompile(function.addr, None, None) {
                    Ok(code) => codes.push((function.addr, code)),
                    Err(error) => {
                        errors.push((function.addr, format!("unavailable: {error}"), None));
                        unavailable += 1;
                    }
                }
            }
            if codes.is_empty() {
                continue;
            }
            for (address, error) in check_batch(&codes, &directory, &returns, &compiler) {
                if let Some(error) = error {
                    errors.push((
                        address,
                        error,
                        Some(directory.join(format!("function-{address:x}.c"))),
                    ));
                } else {
                    compiled += 1;
                }
            }
        }
        errors.sort_by_key(|(address, _, _)| *address);
        (compiled, functions.len(), unavailable, errors)
    });
    let mut report = String::new();
    let mut failed = 0;
    let mut unavailable_total = 0;
    for (fixture, (compiled, total, unavailable, errors)) in fixtures.iter().zip(results) {
        for (address, error, path) in errors {
            writeln!(report, "{} 0x{address:x}: {error}", fixture.display()).unwrap();
            if let Some(path) = path {
                std::fs::copy(path, scratch.join(format!("failure-{failed}.c"))).unwrap();
                failed += 1;
            }
        }
        let summary = format!(
            "{}: {compiled}/{total} compile, {unavailable} unavailable",
            fixture.display(),
        );
        eprintln!("{summary}");
        writeln!(report, "{summary}").unwrap();
        std::fs::write(scratch.join("report.txt"), &report).unwrap();
        unavailable_total += unavailable;
    }
    assert_eq!(unavailable_total, 0, "{report}");
    assert_eq!(failed, 0, "{report}");
}

#[test]
fn syntax_batches_preserve_individual_failures() {
    let scratch = scratch_dir("syntax-batch-failures");
    let codes = vec![
        (1, "uint64_t same(void) { return 1; }".into()),
        (2, "uint64_t same(void) { return missing(2); }".into()),
        (
            3,
            "uint64_t same(void) { return ; deliberate syntax error }".into(),
        ),
        (
            4,
            "uint64_t *same(void) { return pointer_result(); }".into(),
        ),
    ];
    let returns = [("pointer_result".into(), CType::pointer_to(CType::U64))].into();
    let compiler = compiler();
    let results = check_batch(&codes, &scratch, &returns, &compiler);
    assert!(results[2].1.is_some());
    for ((address, code), (actual_address, actual)) in codes.iter().zip(results) {
        assert_eq!(*address, actual_address);
        let expected =
            check_with_compiler(code, &scratch.join("individual.c"), &returns, &compiler);
        assert_eq!(actual, expected);
        let saved = scratch.join(format!("function-{address:x}.c"));
        assert_eq!(saved.is_file(), actual.is_some());
        if actual.is_some() {
            assert!(
                std::fs::read_to_string(saved)
                    .unwrap()
                    .contains("deliberate syntax error")
            );
        }
    }
    assert!(
        check_batch(&codes[..1], &scratch, &returns, &compiler)[0]
            .1
            .is_none()
    );
}

#[test]
fn calls_to_declared_callees_pass_and_return_declared_types() {
    let mut binary =
        Binary::open(&common::fixtures_dir().join("metrics/calls.x86_64.O0.debug.elf")).unwrap();
    let mut prelude = velk::render::Prelude::default();
    let mut bodies = String::new();
    for name in [
        "is_even",
        "is_odd",
        "factorial",
        "sum9",
        "call_sum9",
        "twice",
        "square",
        "pick_op",
    ] {
        let addr = binary.find(name).expect("a function").addr;
        let code = binary.decompile(addr, None, None).unwrap();
        // The callee is declared as its debug information declares it, and
        // its result needs no conversion.
        assert!(!code.contains("((int32_t)("), "{code}");
        assert!(!code.contains("result ="), "{code}");
        bodies.push_str(&prelude.extract(&code));
    }
    assert!(
        prelude.render().contains("int is_odd(int);"),
        "{}",
        prelude.render()
    );
    assert!(
        prelude.render().contains("int is_even(int);"),
        "{}",
        prelude.render()
    );
    run_printed(
        &format!("{}{bodies}", prelude.render()),
        "",
        "return !(is_even(10) == 1 && is_odd(7) == 1 && is_even(7) == 0 && factorial(5) == 120 && call_sum9(6) == 42 && pick_op(0) == (void *)twice && pick_op(1) == (void *)square);",
    );
}

#[test]
fn declared_calls_convert_arguments_and_zero_extend_integer_results() {
    for (isa, convention) in [
        (Isa::X86_64, Convention::SysV),
        (Isa::AArch64, Convention::Aapcs64),
    ] {
        let result = convention.results()[0];
        let mut ir = synthetic_ir(
            "call_declared",
            vec![Param {
                index: convention.arguments()[0],
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
                    convention,
                    args: Some(vec![Expr::reg(convention.arguments()[0], 64)]),
                    floats_named: false,
                    outputs: vec![velk::ir::CallOutput {
                        register: result,
                        dest: velk::ir::RegRef {
                            index: result,
                            width: 64,
                        },
                    }],
                    clobbers: None,
                    via: None,
                },
                Stmt::Ret {
                    value: Expr::reg(result, 64),
                },
            ],
        );
        ir.isa = isa;
        ir.convention = convention;
        ir.callee_signatures.insert(
            0x1000,
            velk::ir::DeclaredSignature {
                params: vec![("x".into(), CType::I32)],
                ret: CType::I32,
                variadic: false,
                abi: Err(velk::ir::AbiIssue::UnknownLayout),
            },
        );
        let symbols = velk::render::Symbols {
            functions: [(0x1000, "callee".into())].into(),
            ..Default::default()
        };
        let code = velk::render::render(&ir, &[], &symbols, &[]);
        assert!(code.contains("int32_t callee(int32_t);"), "{code}");
        run_printed(
            &code,
            "int32_t callee(int32_t x) { return x; }",
            "return call_declared(0x1234567880000001ULL) != 0x80000001ULL || call_declared(0xffffffffffffffffULL) != 0xffffffffULL;",
        );
        let signature = ir.callee_signatures.get_mut(&0x1000).unwrap();
        signature.params[0].1 = CType::pointer_to(CType::I32);
        signature.ret = CType::pointer_to(CType::I32);
        let code = velk::render::render(&ir, &[], &symbols, &[]);
        assert!(code.contains("int32_t *callee(int32_t *);"), "{code}");
        run_printed(
            &code,
            "int32_t *callee(int32_t *x) { return x; }",
            "int32_t x = 7; return call_declared((uintptr_t)&x) != (uintptr_t)&x;",
        );
    }
}

#[test]
fn printed_stack_aggregate_initializers_preserve_every_byte() {
    for isa in [Isa::X86_64, Isa::AArch64] {
        for case in [
            "complete",
            "padding",
            "overlap",
            "reordered",
            "reversed",
            "copy",
            "dependent",
            "adjusted_dependent",
            "division",
            "union_first",
            "union_middle",
            "union_last",
        ] {
            let sp = velk::arch::stack_pointer(isa);
            let at =
                |offset: i64| Expr::bin(BinOp::Add, Expr::reg(sp, 64), Expr::Const(offset as u64));
            let load = |offset, width| Expr::Load {
                addr: Box::new(at(offset)),
                width,
                signed: false,
            };
            let argument = Convention::of(isa, velk::loader::Format::Elf, false).arguments()[0];
            let fields = if case.starts_with("union_") {
                vec![(-16, 4), (-12, 4), (-8, 8)]
            } else {
                vec![(-16, 1), (-15, 1), (-14, 2), (-12, 4), (-8, 8)]
            };
            let mut stmts = Vec::new();
            if case == "adjusted_dependent" {
                stmts.push(Stmt::Assign {
                    dest: velk::ir::RegRef {
                        index: sp,
                        width: 64,
                    },
                    value: at(-32),
                });
            }
            if case == "copy" {
                stmts.push(Stmt::Store {
                    addr: at(-64),
                    width: 8,
                    value: Expr::reg(argument, 64),
                });
            }
            for (part, &(offset, width)) in fields.iter().enumerate() {
                if case == "padding" && part == 1 {
                    continue;
                }
                stmts.push(Stmt::Store {
                    addr: at(offset),
                    width,
                    value: if case == "copy" {
                        load(-64, width)
                    } else if matches!(case, "dependent" | "adjusted_dependent") && part == 1 {
                        load(-16, 1)
                    } else if case == "division" && part == 1 {
                        Expr::bin(BinOp::DivU, Expr::reg(argument, 64), Expr::Const(2))
                    } else {
                        Expr::reg(argument, 64)
                    },
                });
            }
            if case == "overlap" {
                stmts.push(Stmt::Store {
                    addr: at(-8),
                    width: 1,
                    value: Expr::Const(7),
                });
            }
            if case == "reordered" {
                stmts.remove(1);
                stmts.insert(
                    0,
                    Stmt::Store {
                        addr: at(-15),
                        width: 1,
                        value: Expr::Const(9),
                    },
                );
            }
            if case == "reversed" {
                stmts.reverse();
            }
            let union_read = match case {
                "union_first" => Some((-16, 1)),
                "union_middle" => Some((-12, 2)),
                "union_last" => Some((-8, 4)),
                _ => None,
            };
            let convention = Convention::of(isa, velk::loader::Format::Elf, false);
            stmts.push(Stmt::Call {
                kind: velk::ir::CallKind::Invoke,
                target: Some(0x1000),
                through: None,
                convention,
                args: Some(vec![at(-16), Expr::reg(argument, 64)]),
                floats_named: false,
                abi: None,
                outputs: velk::ir::fallback_call_outputs(convention, None),
                clobbers: None,
                via: None,
            });
            stmts.push(Stmt::Ret {
                value: union_read.map_or(Expr::Const(0), |(offset, width)| load(offset, width)),
            });
            let mut ir = synthetic_ir(
                &format!(
                    "stack_initializer_{}_{case}",
                    if isa == Isa::X86_64 { "x64" } else { "arm64" }
                ),
                vec![Param {
                    index: argument,
                    name: "x".into(),
                    ty: CType::U64,
                }],
                CType::U64,
                stmts,
            );
            ir.isa = isa;
            ir.convention = Convention::of(isa, velk::loader::Format::Elf, false);
            let mut symbols = velk::render::Symbols::default();
            symbols.functions.insert(0x1000, "inspect_bytes".into());
            let code = velk::render::render(&ir, &[], &symbols, &[]);
            assert_eq!(
                code.contains("__typeof__"),
                matches!(
                    case,
                    "complete" | "overlap" | "reordered" | "reversed" | "copy"
                ) || union_read.is_some(),
                "{code}"
            );
            if case == "overlap" {
                assert!(code.contains("{ .as_i64 = x }"), "{code}");
            }
            let mut support = String::from(
                "int64_t inspect_bytes(void *p, uint64_t x) { uint8_t *b = p; uint64_t got; ",
            );
            for (part, &(offset, width)) in fields.iter().enumerate() {
                if case == "padding" && part == 1 {
                    continue;
                }
                let expected = if case == "reordered" && part == 1 {
                    "9".to_owned()
                } else if case == "division" && part == 1 {
                    "(x / 2)".to_owned()
                } else if case == "overlap" && part == 4 {
                    "((x & ~UINT64_C(255)) | 7)".to_owned()
                } else {
                    "x".to_owned()
                };
                let mask = u64::MAX >> (64 - u32::from(width) * 8);
                support.push_str(&format!("got = 0; __builtin_memcpy(&got, b + {}, {width}); if (got != (({expected}) & UINT64_C({mask}))) __builtin_trap(); ", offset + 16));
            }
            support.push_str("return 0; }");
            if case == "adjusted_dependent" {
                support.push_str(
                    "uint64_t velk_entry_stack_pointer(void) { return UINT64_C(0x100000); }",
                );
            }
            let code = format!("int64_t inspect_bytes(void *, uint64_t);\n{code}");
            let assertions = [0, 1, 0x80ff_ffff_8765_4321u64, u64::MAX]
                .into_iter()
                .map(|x| {
                    let mask =
                        union_read.map_or(0, |(_, width)| u64::MAX >> (64 - u32::from(width) * 8));
                    format!(
                        "if ({}(UINT64_C({x})) != UINT64_C({})) __builtin_trap();",
                        ir.name.as_ref().unwrap(),
                        x & mask
                    )
                })
                .collect::<String>();
            run_printed(&code, &support, &assertions);
        }
    }
}

use super::*;
use velk::ir::{CallOutput, RegRef, VARIABLE_BASE};

#[test]
fn integer_runtime_results_used_as_pointers_are_typed_once() {
    let result = VARIABLE_BASE;
    let call = |target: u64, args: Vec<Expr>, output: Option<u16>| Stmt::Call {
        kind: velk::ir::CallKind::Invoke,
        target: Some(target),
        through: None,
        convention: Convention::SysV,
        args: Some(args),
        floats_named: false,
        abi: None,
        outputs: output
            .map(|dest| {
                vec![CallOutput {
                    register: 0,
                    dest: RegRef {
                        index: dest,
                        width: 64,
                    },
                }]
            })
            .unwrap_or_default(),
        clobbers: Some(velk::ir::Registers(1)),
        via: None,
    };
    let ir = synthetic_ir(
        "split_runtime_results",
        vec![],
        CType::U64,
        vec![
            call(0x1000, vec![], Some(result)),
            call(0x2000, vec![Expr::reg(result, 64)], None),
            Stmt::Ret {
                value: Expr::Const(0),
            },
        ],
    );
    let symbols = velk::render::Symbols {
        functions: [
            (0x1000, "runtime_word".into()),
            (0x2000, "runtime_consume_pointer".into()),
        ]
        .into(),
        function_parameters: [(0x2000, vec![CType::pointer_to(CType::Void)])].into(),
        function_returns: [(0x1000, CType::U64), (0x2000, CType::Void)].into(),
        ..Default::default()
    };
    let code = velk::render::render(&ir, &[], &symbols, &[]);
    assert!(code.contains("runtime_consume_pointer(v"), "{code}");
    assert!(!code.contains("runtime_consume_pointer((void *)"), "{code}");
    assert!(code.contains("(void *)(runtime_word())"), "{code}");
    syntax::run_printed(
        &code,
        "uint8_t storage; const void *seen; \
         uint64_t runtime_word(void) { return (uintptr_t)&storage; } \
         void runtime_consume_pointer(void *value) { seen = value; }",
        "return split_runtime_results() == 0 && seen == &storage ? 0 : 1;",
    );
}

#[test]
fn runtime_pointer_return_variables_keep_their_pointer_type() {
    for (isa, convention) in [
        (Isa::X86_64, Convention::GoAmd64),
        (Isa::AArch64, Convention::Aapcs64),
    ] {
        let result = VARIABLE_BASE;
        let mut ir = synthetic_ir(
            "returned_runtime_pointer",
            vec![],
            CType::pointer_to(CType::int(1, false)),
            vec![Stmt::Call {
                kind: velk::ir::CallKind::Invoke,
                target: Some(0x1000),
                through: None,
                convention,
                args: Some(vec![]),
                floats_named: false,
                abi: None,
                outputs: vec![CallOutput {
                    register: 0,
                    dest: RegRef {
                        index: result,
                        width: 64,
                    },
                }],
                clobbers: None,
                via: None,
            }],
        );
        ir.isa = isa;
        ir.convention = convention;
        ir.blocks[0].stmts.push(Stmt::Brif {
            cond: Cond::Eq,
            lhs: Expr::reg(result, 64),
            rhs: Expr::Const(0),
            target: 1,
        });
        ir.blocks[0].stmts.push(Stmt::Ret {
            value: Expr::reg(result, 64),
        });
        ir.blocks.push(Block {
            start: 1,
            stmts: vec![Stmt::Ret {
                value: Expr::Const(0),
            }],
        });
        let symbols = velk::render::Symbols {
            functions: [(0x1000, "runtime_allocate".into())].into(),
            function_returns: [(0x1000, CType::pointer_to(CType::Void))].into(),
            ..Default::default()
        };
        let code = velk::render::render(&ir, &[], &symbols, &[]);
        assert!(
            code.contains("void *v1") || code.contains("uint8_t *v1"),
            "{code}"
        );
        assert!(!code.contains("(uint8_t *)v1"), "{code}");
        syntax::run_printed(
            &code,
            "static uint8_t storage; void *runtime_allocate(void) { return &storage; }",
            "return returned_runtime_pointer() != &storage;",
        );
    }
}

#[test]
fn go_spilled_pointer_arguments_preserve_full_and_partial_writes() {
    for isa in [Isa::X86_64, Isa::AArch64] {
        for partial in [false, true] {
            let sp = velk::arch::stack_pointer(isa);
            let slot = Expr::bin(BinOp::Sub, Expr::reg(sp, 64), Expr::Const(8));
            let load = Expr::Load {
                addr: Box::new(slot.clone()),
                width: 8,
                signed: false,
            };
            let mut stmts = vec![Stmt::Store {
                addr: slot.clone(),
                value: Expr::reg(0, 64),
                width: 8,
            }];
            if partial {
                stmts.push(Stmt::Store {
                    addr: slot,
                    value: Expr::Const(0x5a),
                    width: 1,
                });
            }
            for count in [1, 2] {
                stmts.push(Stmt::Call {
                    kind: velk::ir::CallKind::Invoke,
                    target: Some(0x1000),
                    through: None,
                    convention: if isa == Isa::X86_64 {
                        Convention::GoAmd64
                    } else {
                        Convention::Aapcs64
                    },
                    args: Some(vec![load.clone(), Expr::Const(count)]),
                    floats_named: false,
                    abi: None,
                    outputs: Vec::new(),
                    clobbers: Some(Default::default()),
                    via: None,
                });
            }
            stmts.push(Stmt::Ret { value: load });
            let mut ir = synthetic_ir(
                "spilled_pointer",
                vec![Param {
                    index: 0,
                    name: "input".into(),
                    ty: CType::U64,
                }],
                CType::U64,
                stmts,
            );
            ir.isa = isa;
            ir.convention = if isa == Isa::X86_64 {
                Convention::GoAmd64
            } else {
                Convention::Aapcs64
            };
            let symbols = velk::render::Symbols {
                functions: [(0x1000, "consume_pointer".into())].into(),
                function_parameters: [(0x1000, vec![CType::pointer_to(CType::Void), CType::I64])]
                    .into(),
                function_returns: [(0x1000, CType::Void)].into(),
                ..Default::default()
            };
            let code = velk::render::render(&ir, &[], &symbols, &[]);
            if !partial {
                assert!(code.contains("void *local_"), "{code}");
                assert!(code.contains("consume_pointer(local_"), "{code}");
            }
            let expected = if partial {
                "(input & ~UINT64_C(255)) | 0x5a"
            } else {
                "input"
            };
            syntax::run_printed(
                &code,
                "static uint64_t observed; void consume_pointer(void *pointer, int64_t count) { observed = observed * 3 + (uintptr_t)pointer + (uint64_t)count; }",
                &format!(
                    "for (uint64_t i = 0; i < 257; ++i) {{ uint64_t input = i * UINT64_C(0xfedcba987654321); uint64_t expected = {expected}; observed = 0; if (spilled_pointer(input) != expected || observed != (expected + 1) * 3 + expected + 2) return 1; }} return 0;"
                ),
            );
        }
    }
}

#[test]
fn go_fixture_functions_compile() {
    let fixtures = [
        "go_probe",
        "go_stripped",
        "go_probe_arm64",
        "go_stripped_arm64",
    ]
    .map(PathBuf::from);
    syntax::scan(&fixtures, "go-runtime-syntax");
}

#[test]
fn go_interface_conversions_return_full_pointers_and_copy_values() {
    for fixture in ["go_probe", "go_stripped"] {
        let mut binary = Binary::open(&common::fixtures_dir().join(fixture)).unwrap();
        let mut prelude = velk::render::Prelude::default();
        let mut bodies = String::new();
        for name in ["runtime.convT", "runtime.convTnoptr"] {
            let address = binary.find(name).unwrap().addr;
            let code = binary.decompile(address, None, None).unwrap();
            assert!(
                code.contains(&format!("void *{}(", name.replace('.', "_"))),
                "{code}"
            );
            assert!(code.contains("return v"), "{code}");
            assert!(!code.contains("return (uintptr_t)"), "{code}");
            bodies.push_str(&prelude.extract(&code));
        }
        let code = format!(
            "#include <stdint.h>\n#include <string.h>\n\
             static uint8_t storage[256];\n\
             static void *runtime_mallocgc(uint64_t size, void *type, int zero) {{\n\
                 (void)type; (void)zero; return size <= sizeof(storage) ? storage : 0;\n\
             }}\n\
             static void runtime_typedmemmove(void *type, void *dst, const void *src) {{\n\
                 memcpy(dst, src, *(uint64_t *)type);\n\
             }}\n\
             static void runtime_memmove(void *dst, const void *src, uint64_t size) {{\n\
                 memmove(dst, src, size);\n\
             }}\n{bodies}"
        );
        syntax::run_printed(
            &code,
            "",
            "uint8_t input[256]; for (unsigned i = 0; i < 256; ++i) input[i] = (uint8_t)(i * 193); \
             for (uint64_t size = 0; size <= sizeof(input); ++size) { \
                 memset(storage, 0, sizeof(storage)); \
                 if (runtime_convT(&size, input) != storage || memcmp(input, storage, size)) return 1; \
                 memset(storage, 0, sizeof(storage)); \
                 if (runtime_convTnoptr(&size, input) != storage || memcmp(input, storage, size)) return 2; \
             } return 0;",
        );
    }
}

#[test]
fn go_runtime_function_signatures_preserve_pointer_results_and_arguments() {
    for fixture in [
        "go_probe",
        "go_stripped",
        "go_probe_arm64",
        "go_stripped_arm64",
    ] {
        let mut binary = Binary::open(&common::fixtures_dir().join(fixture)).unwrap();
        for (name, parameters) in [
            ("runtime.convT", 2),
            ("runtime.convTnoptr", 2),
            ("runtime.convTstring", 2),
            ("runtime.newobject", 1),
            ("runtime.makeslice", 3),
            ("runtime.mapaccess1_fast32", 3),
            ("runtime.mapaccess1_faststr", 4),
        ] {
            let address = binary.find(name).unwrap().addr;
            let analysis = binary.analysis(address, None).unwrap();
            assert!(analysis.ir.ret_type.is_pointer(), "{fixture}: {name}");
            assert_eq!(analysis.ir.params.len(), parameters, "{fixture}: {name}");
        }
        let address = binary.find("runtime.readGOMEMLIMIT").unwrap().addr;
        let code = binary.decompile(address, None, None).unwrap();
        assert!(
            code.contains("runtime_printstring(\"GOMEMLIMIT=\", 11)"),
            "{code}"
        );
        assert!(code.contains("void runtime_printstring();"), "{code}");
        assert!(!code.contains("runtime_printstring(const void *"), "{code}");
        assert!(!code.contains("runtime_printstring((uintptr_t)"), "{code}");
    }
}

use crate::ir::{BinOp, Block, CType, Cond, Expr, FunctionIr, Param, RegRef, Stmt};
use crate::loader::Isa;

fn assign(index: u16, value: Expr) -> Stmt {
    Stmt::Assign {
        dest: RegRef { index, width: 64 },
        value,
        at: None,
    }
}

fn example_ir(name: &str, offset: u64, width: u8, fill: Option<u64>, n: u64) -> FunctionIr {
    let mut ir = FunctionIr::single_block(Isa::X86_64, vec![]);
    ir.name = Some(name.to_owned());
    ir.params = vec![Param {
        index: 2,
        name: "base".to_owned(),
        ty: CType::pointer_to(CType::Int {
            bytes: 1,
            signed: false,
        }),
    }];
    let mut step = vec![Stmt::Store {
        addr: Expr::reg(7, 64),
        value: match fill {
            Some(value) => Expr::Const(value),
            None => Expr::Load {
                addr: Box::new(Expr::reg(6, 64)),
                width,
                signed: false,
            },
        },
        width,
        at: None,
    }];
    for index in if fill.is_some() { vec![7] } else { vec![6, 7] } {
        step.push(assign(
            index,
            Expr::bin(
                BinOp::Add,
                Expr::reg(index, 64),
                Expr::Const(u64::from(width)),
            ),
        ));
    }
    step.push(assign(
        1,
        Expr::bin(BinOp::Sub, Expr::reg(1, 64), Expr::Const(1)),
    ));
    step.push(Stmt::Br {
        target: Some(10),
        at: None,
    });
    ir.blocks = vec![
        Block {
            start: 0,
            stmts: vec![
                assign(6, Expr::reg(2, 64)),
                assign(
                    7,
                    Expr::bin(BinOp::Add, Expr::reg(2, 64), Expr::Const(offset)),
                ),
                assign(1, Expr::Const(n)),
                Stmt::Br {
                    target: Some(10),
                    at: None,
                },
            ],
        },
        Block {
            start: 10,
            stmts: vec![Stmt::Brif {
                cond: Cond::Eq,
                lhs: Expr::reg(1, 64),
                rhs: Expr::Const(0),
                target: 30,
                at: None,
            }],
        },
        Block {
            start: 20,
            stmts: step,
        },
        Block {
            start: 30,
            stmts: vec![Stmt::Ret {
                value: Expr::bin(
                    BinOp::Add,
                    Expr::bin(BinOp::Sub, Expr::reg(7, 64), Expr::reg(2, 64)),
                    Expr::bin(
                        BinOp::Add,
                        Expr::bin(BinOp::Sub, Expr::reg(6, 64), Expr::reg(2, 64)),
                        Expr::reg(1, 64),
                    ),
                ),
                at: None,
            }],
        },
    ];
    ir
}

#[test]
fn copies_and_fills_compile_and_preserve_memory_and_final_registers() {
    let mut source = String::from("#include <stdint.h>\n#include <string.h>\n");
    for (name, offset, width, fill, n, builtin) in [
        ("copy_bytes", 32, 1, None, 8, Some("__builtin_memcpy")),
        ("copy_words", 32, 2, None, 4, Some("__builtin_memcpy")),
        ("overlap", 1, 1, None, 8, None),
        ("fill_bytes", 32, 1, Some(0xab), 8, Some("__builtin_memset")),
        (
            "fill_words",
            32,
            2,
            Some(0xabab),
            4,
            Some("__builtin_memset"),
        ),
        ("pattern", 32, 2, Some(0x1234), 4, None),
        ("empty", 32, 1, Some(0xab), 0, None),
    ] {
        let ir = example_ir(name, offset, width, fill, n);
        let rendered = crate::render::render_with_dependencies(&ir, &[], &Default::default(), &[]);
        let code = rendered.code;
        if let Some(builtin) = builtin {
            assert_eq!(
                rendered.inline_functions,
                vec![crate::render::InlineFunction {
                    function: builtin.trim_start_matches("__builtin_").to_owned(),
                    bytes: Some(8),
                }]
            );
            assert!(code.contains(builtin), "{name}\n{code}");
        } else {
            assert!(rendered.inline_functions.is_empty());
            assert!(!code.contains("__builtin_mem"), "{name}\n{code}");
        }
        source.push_str(&code);
    }
    let mut dynamic = example_ir("dynamic", 32, 1, Some(0xab), 8);
    dynamic.params.push(Param {
        index: 3,
        name: "n".to_owned(),
        ty: CType::U64,
    });
    dynamic.blocks[0].stmts[2] = assign(1, Expr::reg(3, 64));
    let rendered = crate::render::render_with_dependencies(&dynamic, &[], &Default::default(), &[]);
    assert_eq!(
        rendered.inline_functions,
        vec![crate::render::InlineFunction {
            function: "memset".to_owned(),
            bytes: None,
        }]
    );
    let code = rendered.code;
    assert!(code.contains("__builtin_memset"), "{code}");
    source.push_str(&code);
    for (name, ty) in [
        ("integer_fill", CType::U64),
        ("floating_fill", CType::Named("double".to_owned())),
    ] {
        let mut ir = example_ir(name, 32, 1, Some(0), 8);
        ir.params.push(Param {
            index: 0,
            name: "value".to_owned(),
            ty,
        });
        let Stmt::Store { value, .. } = &mut ir.blocks[2].stmts[0] else {
            unreachable!()
        };
        *value = Expr::reg(0, 64);
        let code = crate::render::render(&ir, &[], &Default::default(), &[]);
        assert!(code.contains("__builtin_memset"), "{code}");
        source.push_str(&code);
    }
    for (name, width, fill, bytes) in [
        ("rep_bytes", 1, None, vec![0xf3, 0xa4]),
        ("rep_words", 2, None, vec![0xf3, 0x66, 0xa5]),
        ("rep_dwords", 4, None, vec![0xf3, 0xa5]),
        ("rep_qwords", 8, None, vec![0xf3, 0x48, 0xa5]),
        (
            "rep_fill",
            8,
            Some(0xabab_abab_abab_abab),
            vec![0xf3, 0x48, 0xab],
        ),
    ] {
        let mut ir = example_ir(name, 32, width, fill, 1);
        let result = ir.blocks[3].stmts[0].clone();
        let mut code = vec![0x48, 0x89, 0xd6, 0x48, 0x8d, 0x7a, 32, 0xb9, 2, 0, 0, 0];
        if let Some(value) = fill {
            code.extend([0x48, 0xb8]);
            code.extend(value.to_le_bytes());
        }
        code.extend(bytes);
        code.push(0xc3);
        let image = crate::loader::Image::from_code(Isa::X86_64, 0, code.clone());
        ir.blocks = crate::lift::lift(&image, 0, code.len() as u64, &Default::default()).unwrap();
        for stmt in ir.blocks.iter_mut().flat_map(|block| &mut block.stmts) {
            if matches!(stmt, Stmt::Ret { .. }) {
                *stmt = result.clone();
            }
        }
        crate::passes::optimize(&mut ir, false);
        let code = crate::render::render(&ir, &[], &Default::default(), &[]);
        let operation = if fill.is_some() {
            "__builtin_memset"
        } else {
            "__builtin_memcpy"
        };
        assert!(code.contains(operation), "{code}");
        source.push_str(&code);
    }
    source.push_str(r#"
int main(void) {
    uint8_t a[64], b[64];
    union { uint64_t bits; double value; } fill_bits = { .bits = UINT64_C(0x3ff00000000000ab) };
    memset(a, 0, 64);
    if (integer_fill(a, UINT64_C(0xffffffffffffffab)) != 40 || a[32] != 0xab || a[39] != 0xab) return 37;
    if (floating_fill(a, fill_bits.value) != 40 || a[32] != 0xab || a[39] != 0xab) return 38;
    memset(a, 0, 64);
    if (dynamic(a, 0) != 32 || a[32] != 0) return 30;
    if (dynamic(a, 8) != 40 || a[32] != 0xab || a[39] != 0xab || a[40] != 0) return 31;
    for (int i = 0; i < 64; i++) a[i] = i + 1;
    if (rep_bytes(a) != 36 || a[32] != 1 || a[33] != 2) return 32;
    if (rep_words(a) != 40 || a[32] != 1 || a[33] != 2) return 33;
    if (rep_dwords(a) != 48 || a[35] != 4) return 35;
    if (rep_qwords(a) != 64 || a[39] != 8) return 36;
    if (rep_fill(a) != 48 || a[32] != 0xab || a[39] != 0xab) return 34;
    for (int k = 0; k < 7; k++) {
        for (int i = 0; i < 64; i++) a[i] = b[i] = i + 1;
        uint64_t result;
        switch (k) {
        case 0: result = copy_bytes(a); memcpy(b + 32, b, 8); break;
        case 1: result = copy_words(a); memcpy(b + 32, b, 8); break;
        case 2: result = overlap(a); for (int i = 0; i < 8; i++) b[i + 1] = b[i]; break;
        case 3: result = fill_bytes(a); memset(b + 32, 0xab, 8); break;
        case 4: result = fill_words(a); memset(b + 32, 0xab, 8); break;
        case 5: result = pattern(a); for (int i = 32; i < 40; i += 2) { b[i] = 0x34; b[i + 1] = 0x12; } break;
        default: result = empty(a); break;
        }
        if (memcmp(a, b, 64)) return 10 + k;
        uint64_t expected = k < 2 ? 48 : k == 2 ? 17 : k == 6 ? 32 : 40;
        if (result != expected) return 20 + k;
    }
    return 0;
}

"#);
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/string-loop-tests");
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("loops.c");
    let output = dir.join("loops");
    std::fs::write(&input, &source).unwrap();
    let compiled = std::process::Command::new("cc")
        .args(["-std=c11", "-Werror", "-O2"])
        .arg(&input)
        .arg("-o")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}\n{source}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    assert!(
        std::process::Command::new(output)
            .status()
            .unwrap()
            .success(),
        "{source}"
    );
}

#[test]
fn uncertain_aliases_backward_steps_and_overflow_keep_the_loop() {
    for kind in 0..5 {
        let mut ir = example_ir("copy", 32, 1, None, 8);
        match kind {
            0 => ir.blocks[0].stmts[1] = assign(7, Expr::reg(2, 64)),
            1 => ir.blocks[0].stmts[1] = assign(7, Expr::reg(3, 64)),
            2 => {
                ir.blocks[2].stmts[1] =
                    assign(6, Expr::bin(BinOp::Sub, Expr::reg(6, 64), Expr::Const(1)))
            }
            3 => ir = example_ir("copy", 32, 8, None, u64::MAX),
            _ => {
                ir.blocks[0].stmts.insert(1, assign(2, Expr::reg(3, 64)));
                ir.blocks[0].stmts.insert(2, assign(3, Expr::Const(0)));
            }
        }
        let code = crate::render::render(&ir, &[], &Default::default(), &[]);
        assert!(!code.contains("__builtin_memcpy"), "{kind}\n{code}");
    }
}

#[test]
fn object_provenance_preserves_printed_copy_behavior() {
    let mut source =
        String::from("#include <stdint.h>\n#include <stdlib.h>\n#include <string.h>\n");
    for (name, kind, builtin) in [
        ("stack_disjoint", 0, true),
        ("stack_overlap", 1, false),
        ("stack_heap", 2, true),
        ("global_copy", 3, true),
        ("parameter_copy", 4, false),
    ] {
        let mut ir = example_ir(name, 32, 1, None, 8);
        let sp = crate::arch::stack_pointer(ir.isa);
        let frame = |offset| Expr::bin(BinOp::Add, Expr::reg(sp, 64), Expr::Const(offset));
        let mut prefix = Vec::new();
        if kind < 3 {
            ir.params.clear();
            ir.debug_locals.push(crate::ir::DebugLocal {
                name: "bytes".to_owned(),
                ty: CType::Array(Box::new(CType::Int {
                    bytes: 1,
                    signed: false,
                })),
                slot: -64,
                size: 48,
            });
            for i in 0..48u64 {
                prefix.push(Stmt::Store {
                    addr: frame(i.wrapping_sub(64)),
                    value: Expr::Const(i + 1),
                    width: 1,
                    at: None,
                });
            }
            prefix.push(assign(6, frame(0u64.wrapping_sub(64))));
            if kind == 2 {
                let pointer = CType::pointer_to(CType::Int {
                    bytes: 1,
                    signed: false,
                });
                ir.value_types
                    .insert(crate::ir::VARIABLE_BASE, pointer.clone());
                ir.pointer_values.push(crate::ir::VARIABLE_BASE);
                ir.value_types.insert(7, pointer);
                prefix.push(Stmt::Call {
                    abi: None,
                    kind: crate::ir::CallKind::Invoke,
                    target: Some(0x1000),
                    through: None,
                    convention: ir.convention,
                    args: Some(vec![Expr::Const(8)]),
                    floats_named: false,
                    outputs: vec![crate::ir::CallOutput {
                        register: 0,
                        dest: RegRef {
                            index: crate::ir::VARIABLE_BASE,
                            width: 64,
                        },
                    }],
                    clobbers: Some(crate::ir::Registers(1)),
                    via: None,
                    at: None,
                });
                prefix.push(assign(7, Expr::reg(crate::ir::VARIABLE_BASE, 64)));
            } else {
                prefix.push(assign(
                    7,
                    frame(if kind == 0 {
                        0u64.wrapping_sub(32)
                    } else {
                        0u64.wrapping_sub(63)
                    }),
                ));
            }
        } else if kind == 3 {
            ir.params.clear();
            prefix.push(assign(6, Expr::Const(0x2000)));
            prefix.push(assign(7, Expr::Const(0x2100)));
        } else {
            ir.params.push(Param {
                index: 3,
                name: "destination".to_owned(),
                ty: ir.params[0].ty.clone(),
            });
            prefix.push(assign(6, Expr::reg(2, 64)));
            prefix.push(assign(7, Expr::reg(3, 64)));
        }
        prefix.extend(ir.blocks[0].stmts[2..].iter().cloned());
        ir.blocks[0].stmts = prefix;
        ir.blocks[3].stmts = vec![Stmt::Ret {
            value: Expr::Load {
                addr: Box::new(Expr::bin(BinOp::Sub, Expr::reg(7, 64), Expr::Const(1))),
                width: 1,
                signed: false,
            },
            at: None,
        }];
        let mut symbols = super::super::Symbols::default();
        symbols.functions.insert(0x1000, "malloc".to_owned());
        symbols.function_returns.insert(
            0x1000,
            crate::analysis::prototypes::of("malloc", false)
                .expect("malloc has a library prototype")
                .ret
                .clone(),
        );
        let code = crate::render::render(&ir, &[], &symbols, &[(0x2000, 0x200)]);
        assert_eq!(code.contains("__builtin_memcpy"), builtin, "{name}\n{code}");
        // Absolute global addresses need backing storage in this execution harness.
        let code = code
            .replace("extern uint8_t g_2000; /* address: 0x2000 */", "")
            .replace("extern uint8_t g_2100; /* address: 0x2100 */", "")
            .replace("(&g_2000)", "global_source")
            .replace("(&g_2100)", "global_destination")
            .replace("0x2000", "(uint64_t)global_source")
            .replace("0x2100", "(uint64_t)global_destination");
        source.push_str(&code);
    }
    source.insert_str(source.find('\n').unwrap() + 1, "static uint8_t global_source[8] = {1,2,3,4,5,6,7,8};\nstatic uint8_t global_destination[8];\n");
    source.push_str("int main(void) { uint8_t a[16] = {1,2,3,4,5,6,7,8}; return stack_disjoint() != 8 || stack_overlap() != 1 || stack_heap() != 8 || global_copy() != 8 || parameter_copy(a, a+1) != 1; }\n");
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/string-loop-tests");
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("provenance.c");
    let output = dir.join("provenance");
    std::fs::write(&input, &source).unwrap();
    let compiled = std::process::Command::new("cc")
        .args(["-std=c11", "-Werror", "-O2"])
        .arg(&input)
        .arg("-o")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}\n{source}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    assert!(
        std::process::Command::new(output)
            .status()
            .unwrap()
            .success(),
        "{source}"
    );
}

#[test]
fn allocation_ranges_and_pointer_age_limit_copy_folding() {
    for (name, size, load_after, offset, expected) in [
        ("malloc", 16, false, 0, true),
        ("calloc", 16, false, 0, true),
        ("calloc", u64::MAX, false, 0, false),
        ("runtime.newobject", 16, false, 0, false),
        ("__rust_alloc", 16, false, 0, true),
        ("__rustc::__rust_alloc", 16, false, 0, true),
        ("__rust_alloc_zeroed", 16, false, 0, true),
        ("operator new(unsigned long)", 16, false, 0, true),
        ("runtime.mallocgc", 16, false, 0, true),
        ("malloc", 16, true, 0, false),
        ("malloc", 16, false, 8, true),
        ("malloc", 16, false, 9, false),
        ("malloc", 4, false, 0, false),
        ("malloc", 32, false, 0, false),
        ("malloc", 16, false, u64::MAX, false),
        ("realloc", 16, false, 0, false),
        ("__rust_realloc", 16, false, 0, false),
        ("unknown", 16, false, 0, false),
    ] {
        let mut ir = example_ir("copy", 32, 1, None, 8);
        let output = crate::ir::VARIABLE_BASE;
        let load = assign(
            6,
            Expr::Load {
                addr: Box::new(Expr::reg(2, 64)),
                width: 8,
                signed: false,
            },
        );
        let call = Stmt::Call {
            abi: None,
            kind: crate::ir::CallKind::Invoke,
            target: Some(0x1000),
            through: None,
            convention: ir.convention,
            args: Some(vec![
                Expr::Const(size),
                Expr::Const(if name == "calloc" && size == u64::MAX {
                    2
                } else {
                    1
                }),
                Expr::Const(1),
                Expr::Const(size),
            ]),
            floats_named: false,
            outputs: vec![crate::ir::CallOutput {
                register: 0,
                dest: RegRef {
                    index: output,
                    width: 64,
                },
            }],
            clobbers: Some(crate::ir::Registers(1)),
            via: None,
            at: None,
        };
        let mut prefix = if load_after {
            vec![call, load]
        } else {
            vec![load, call]
        };
        let interrupted = name == "malloc" && size == 32;
        if interrupted {
            prefix.insert(
                1,
                Stmt::Call {
                    abi: None,
                    kind: crate::ir::CallKind::Invoke,
                    target: Some(0x2000),
                    through: None,
                    convention: ir.convention,
                    args: Some(vec![]),
                    floats_named: false,
                    outputs: vec![],
                    clobbers: Some(crate::ir::Registers(0)),
                    via: None,
                    at: None,
                },
            );
        }
        prefix.push(assign(
            7,
            Expr::bin(BinOp::Add, Expr::reg(output, 64), Expr::Const(offset)),
        ));
        prefix.extend(ir.blocks[0].stmts[2..].iter().cloned());
        ir.blocks[0].stmts = prefix;
        let tail = ir.blocks[0]
            .stmts
            .split_off(if interrupted { 3 } else { 2 });
        ir.blocks[0].stmts.push(Stmt::Brif {
            cond: Cond::Eq,
            lhs: Expr::reg(output, 64),
            rhs: Expr::Const(0),
            target: 40,
            at: None,
        });
        ir.blocks.insert(
            1,
            Block {
                start: 5,
                stmts: tail,
            },
        );
        ir.blocks.push(Block {
            start: 40,
            stmts: vec![Stmt::Trap { at: None }],
        });
        let mut image = crate::loader::Image::from_code(Isa::X86_64, 0, vec![0xc3]);
        image.functions.insert(
            0x1000,
            crate::loader::Function {
                addr: 0x1000,
                size: Some(1),
                size_estimated: false,
                name: Some(name.to_owned()),
                aliases: vec![],
                library: None,
                sources: vec![],
            },
        );
        let symbols = crate::render::callee_names(&image);
        let code = crate::render::render(&ir, &[], &symbols, &[]);
        assert_eq!(
            code.contains("__builtin_memcpy"),
            expected,
            "{name}, {size}, {load_after}, {offset}\n{code}"
        );
    }
}

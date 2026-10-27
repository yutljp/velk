use super::*;
use velk::ir::{CallOutput, RegRef, VARIABLE_BASE};

#[test]
fn ignored_calls_keep_explicit_results_before_a_shared_epilogue() {
    let scratch = scratch_dir("shared-result-epilogue");
    let source = scratch.join("result.s");
    let object = scratch.join("result.o");
    std::fs::write(
        &source,
        ".text
.globl shared_result
.type shared_result,@function
shared_result:
cbz w0, 1f
mov w0, #-64
b 2f
1: mov w0, #42
2: nop
ret
.size shared_result, .-shared_result
.globl ignored_result_caller
.type ignored_result_caller,@function
ignored_result_caller:
stp x29, x30, [sp, #-16]!
bl shared_result
mov w0, #0
ldp x29, x30, [sp], #16
ret
.size ignored_result_caller, .-ignored_result_caller
",
    )
    .unwrap();
    let compiled = Command::new(compiler())
        .args(["--target=aarch64-unknown-linux-gnu", "-c"])
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{compiled:?}");
    let mut binary = Binary::open(&object).unwrap();
    let address = binary.find("shared_result").unwrap().addr;
    let printed = binary.decompile(address, None, None).unwrap();
    assert!(!printed.contains("void shared_result"), "{printed}");
    syntax::run_printed(
        &printed,
        "",
        "if ((uint32_t)shared_result(0) != 42 || (uint32_t)shared_result(1) != UINT32_C(0xffffffc0)) __builtin_trap();",
    );
    std::fs::remove_dir_all(scratch).ok();
}

#[test]
fn folded_calls_keep_the_temporary_integer_conversion() {
    for ty in [CType::I64, CType::U64] {
        for op in [BinOp::Xor, BinOp::Sub, BinOp::Sar] {
            let mut ir = synthetic_ir(
                "converted_call",
                vec![],
                CType::U64,
                vec![
                    Stmt::Call {
                        abi: None,
                        kind: velk::ir::CallKind::Invoke,
                        target: Some(0x1000),
                        through: None,
                        convention: Convention::SysV,
                        args: Some(vec![]),
                        floats_named: true,
                        outputs: vec![CallOutput {
                            register: 0,
                            dest: RegRef {
                                index: VARIABLE_BASE,
                                width: 64,
                            },
                        }],
                        clobbers: None,
                        via: None,
                    },
                    Stmt::Ret {
                        value: Expr::bin(
                            op,
                            if op == BinOp::Sar {
                                Expr::reg(VARIABLE_BASE, 64)
                            } else {
                                Expr::bin(
                                    BinOp::And,
                                    Expr::reg(VARIABLE_BASE, 64),
                                    Expr::Const(0xffff_ffff),
                                )
                            },
                            Expr::Const(match op {
                                BinOp::Xor => u64::MAX,
                                BinOp::Sar => 63,
                                _ => 166,
                            }),
                        ),
                    },
                ],
            );
            ir.value_types.insert(VARIABLE_BASE, ty.clone());
            let mut symbols = velk::render::Symbols {
                functions: [(0x1000, "small_result".into())].into(),
                ..Default::default()
            };
            if op == BinOp::Sar {
                symbols.function_returns.insert(0x1000, CType::U64);
            }
            let printed = velk::render::render(&ir, &[], &symbols, &[]);
            if op != BinOp::Sar || ty == CType::I64 {
                assert!(printed.contains("64_t)(small_result())"), "{printed}");
            }
            let function_definition = if op == BinOp::Sar {
                "static uint64_t small_result(void) { return UINT64_MAX; }"
            } else {
                "static uint64_t small_result(void) { return 1; }"
            };
            let code = format!("{function_definition}\n{printed}");
            let expected = match op {
                BinOp::Xor => !1u64,
                BinOp::Sar => u64::MAX,
                _ => 1u64.wrapping_sub(166),
            };
            syntax::run_printed(
                &code,
                "",
                &format!("if (converted_call() != UINT64_C({expected})) __builtin_trap();"),
            );
        }
    }
}

#[test]
fn fused_memory_updates_keep_the_original_operand() {
    let mut candidates = Vec::new();
    for inline in [false, true] {
        let load = Expr::Load {
            addr: Box::new(Expr::reg(7, 64)),
            width: 4,
            signed: false,
        };
        let mut statements = Vec::new();
        if !inline {
            statements.push(Stmt::Assign {
                dest: RegRef {
                    index: 0,
                    width: 64,
                },
                value: load.clone(),
            });
        }
        statements.extend([
            Stmt::Assign {
                dest: RegRef {
                    index: 0,
                    width: 64,
                },
                value: Expr::bin(
                    BinOp::And,
                    if inline { load } else { Expr::reg(0, 64) },
                    Expr::reg(6, 32),
                ),
            },
            Stmt::Assign {
                dest: RegRef {
                    index: 6,
                    width: 64,
                },
                value: Expr::reg(2, 32),
            },
            Stmt::Store {
                addr: Expr::reg(7, 64),
                value: Expr::reg(0, 64),
                width: 8,
            },
            Stmt::Ret {
                value: Expr::reg(6, 32),
            },
        ]);
        let mut ir = synthetic_ir(
            if inline {
                "inline_update"
            } else {
                "separate_update"
            },
            vec![
                Param {
                    index: 7,
                    name: "p".into(),
                    ty: CType::pointer_to(CType::U64),
                },
                Param {
                    index: 6,
                    name: "mask".into(),
                    ty: CType::U32,
                },
                Param {
                    index: 2,
                    name: "replacement".into(),
                    ty: CType::U32,
                },
            ],
            CType::U32,
            statements,
        );
        let original = ir.clone();
        velk::passes::memory::fuse_load_op_store(&mut ir);
        let mut candidate = printed_candidate(
            ir,
            vec![vec![REGION, 0xffff_ffff, 0xfffa], vec![REGION, 0, 1]],
        );
        candidate.ir = original;
        candidates.push(candidate);
    }
    check_candidates("memory-update-operands", candidates, Mode::Memory, &[]);
}

#[test]
fn fused_memory_updates_keep_truncation_and_memory_order() {
    let mut candidates = Vec::new();
    for inline in [false, true] {
        for intervening_store in [false, true] {
            let load = Expr::Load {
                addr: Box::new(Expr::reg(7, 64)),
                width: 8,
                signed: false,
            };
            let mut statements = Vec::new();
            if !inline {
                statements.push(Stmt::Assign {
                    dest: RegRef {
                        index: 0,
                        width: 64,
                    },
                    value: load.clone(),
                });
            }
            statements.push(Stmt::Assign {
                dest: RegRef {
                    index: 0,
                    width: 64,
                },
                value: Expr::bin(
                    BinOp::And,
                    Expr::bin(
                        BinOp::Add,
                        if inline {
                            load.clone()
                        } else {
                            Expr::reg(0, 64)
                        },
                        Expr::Const(0x100000001),
                    ),
                    Expr::Const(0xffff_ffff),
                ),
            });
            if intervening_store {
                statements.push(Stmt::Store {
                    addr: Expr::reg(7, 64),
                    value: Expr::Const(0),
                    width: 8,
                });
            }
            statements.extend([
                Stmt::Store {
                    addr: Expr::reg(7, 64),
                    value: Expr::reg(0, 64),
                    width: 8,
                },
                Stmt::Ret { value: load },
            ]);
            let mut ir = synthetic_ir(
                &format!(
                    "update_{}_{}",
                    u8::from(inline),
                    u8::from(intervening_store)
                ),
                vec![Param {
                    index: 7,
                    name: "p".into(),
                    ty: CType::pointer_to(CType::U64),
                }],
                CType::U64,
                statements,
            );
            let original = ir.clone();
            velk::passes::memory::fuse_load_op_store(&mut ir);
            let mut candidate = printed_candidate(ir, vec![vec![REGION]]);
            candidate.ir = original;
            candidates.push(candidate);
        }
    }
    check_candidates("memory-update-truncation", candidates, Mode::Memory, &[]);
}

#[test]
fn indexed_stack_elements_share_storage_with_partial_reads() {
    let slot = |offset: i64| Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const(offset as u64));
    let mut statements = Vec::new();
    for index in 0..10 {
        statements.push(Stmt::Store {
            addr: slot(-128 + index * 8),
            value: Expr::Const(100 + index as u64),
            width: 8,
        });
    }
    let mut value = Expr::Load {
        addr: Box::new(Expr::bin(
            BinOp::Add,
            slot(-128),
            Expr::bin(BinOp::Mul, Expr::reg(7, 64), Expr::Const(8)),
        )),
        width: 8,
        signed: false,
    };
    for offset in [-96, -80] {
        value = Expr::bin(
            BinOp::Xor,
            value,
            Expr::Load {
                addr: Box::new(slot(offset)),
                width: 4,
                signed: false,
            },
        );
    }
    statements.push(Stmt::Ret { value });
    let ir = synthetic_ir(
        "partial_elements",
        vec![Param {
            index: 7,
            name: "index".into(),
            ty: CType::U64,
        }],
        CType::U64,
        statements,
    );
    let candidate = printed_candidate(ir, (0..10).map(|index| vec![index]).collect());
    check_candidates(
        "partial-stack-elements",
        vec![candidate],
        Mode::Registers,
        &[],
    );
}

#[test]
fn data_page_bases_use_the_data_address() {
    let mut ir = synthetic_ir(
        "data_page",
        vec![],
        CType::U64,
        vec![Stmt::Ret {
            value: Expr::Const(0x100001000),
        }],
    );
    ir.isa = Isa::AArch64;
    ir.convention = Convention::Aapcs64;
    let printed = velk::render::render(&ir, &[], &Default::default(), &[(0x1000019d0, 256)]);
    assert!(!printed.contains("0x100001000"), "{printed}");
    assert!(printed.contains("0x1000019d0"), "{printed}");
    syntax::run_printed(
        &bound_globals(&printed),
        "",
        "if (data_page() != UINT64_C(0x100001000)) __builtin_trap();",
    );
}

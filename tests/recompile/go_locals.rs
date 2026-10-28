use super::*;
use velk::ir::{CallKind, CallOutput, RegRef, VARIABLE_BASE};

fn assign(index: u16, value: Expr) -> Stmt {
    Stmt::Assign {
        dest: RegRef { index, width: 64 },
        value,
    }
}

#[test]
fn copies_across_branches_preserve_snapshots_and_remove_redundant_names() {
    let (source, saved) = (VARIABLE_BASE, VARIABLE_BASE + 1);
    let mut combined = String::new();
    for overwrite in [false, true] {
        let name = if overwrite {
            "keep_snapshot"
        } else {
            "fold_copy"
        };
        let mut ir = synthetic_ir(
            name,
            vec![
                Param {
                    index: 7,
                    name: "input".into(),
                    ty: CType::U64,
                },
                Param {
                    index: 6,
                    name: "flag".into(),
                    ty: CType::U64,
                },
            ],
            CType::U64,
            vec![
                assign(
                    source,
                    Expr::bin(BinOp::Xor, Expr::reg(7, 64), Expr::Const(123)),
                ),
                Stmt::Brif {
                    cond: Cond::Eq,
                    lhs: Expr::reg(6, 64),
                    rhs: Expr::Const(0),
                    target: 2,
                },
            ],
        );
        for start in [1, 2] {
            ir.blocks.push(Block {
                start,
                stmts: vec![
                    assign(saved, Expr::reg(source, 64)),
                    Stmt::Br { target: Some(3) },
                ],
            });
        }
        let mut tail = Vec::new();
        if overwrite {
            tail.push(assign(
                source,
                Expr::bin(BinOp::Add, Expr::reg(source, 64), Expr::Const(1)),
            ));
        }
        tail.push(Stmt::Ret {
            value: Expr::bin(BinOp::Add, Expr::reg(saved, 64), Expr::reg(source, 64)),
        });
        ir.blocks.push(Block {
            start: 3,
            stmts: tail,
        });
        ir.value_types = [(source, CType::U64), (saved, CType::U64)].into();
        let symbols = velk::render::Symbols {
            variable_names: [((ir.addr, saved), "snapshot".into())].into(),
            ..Default::default()
        };
        let code = velk::render::render(&ir, &[], &symbols, &[]);
        if !overwrite {
            assert!(!code.contains("snapshot"), "{code}");
        }
        combined.push_str(&code);
    }
    syntax::run_printed(
        &velk::render::combine(&combined),
        "",
        "for (uint64_t i = 0; i < 100; ++i) { uint64_t x = i * UINT64_C(0xfedcba987654321); for (uint64_t flag = 0; flag < 2; ++flag) { uint64_t value = x ^ 123; if (fold_copy(x, flag) != value + value || keep_snapshot(x, flag) != value + value + 1) return 1; } } return 0;",
    );
}

#[test]
fn incoming_go_parameter_spills_preserve_memory() {
    let slot = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const(16));
    let result = VARIABLE_BASE;
    let mut ir = synthetic_ir(
        "saved_go_argument",
        vec![
            Param {
                index: 0,
                name: "first".into(),
                ty: CType::U64,
            },
            Param {
                index: 3,
                name: "second".into(),
                ty: CType::U64,
            },
        ],
        CType::U64,
        vec![
            Stmt::Store {
                addr: slot.clone(),
                value: Expr::reg(3, 64),
                width: 8,
            },
            Stmt::Call {
                kind: CallKind::Invoke,
                target: Some(0x1000),
                through: None,
                convention: Convention::GoAmd64,
                args: Some(vec![Expr::reg(0, 64)]),
                floats_named: false,
                abi: None,
                outputs: vec![
                    CallOutput {
                        register: 0,
                        dest: RegRef {
                            index: result,
                            width: 64,
                        },
                    },
                    CallOutput {
                        register: 3,
                        dest: RegRef {
                            index: 3,
                            width: 64,
                        },
                    },
                ],
                clobbers: None,
                via: None,
            },
            Stmt::Ret {
                value: Expr::bin(
                    BinOp::Xor,
                    Expr::reg(result, 64),
                    Expr::Load {
                        addr: Box::new(slot),
                        width: 8,
                        signed: false,
                    },
                ),
            },
        ],
    );
    ir.convention = Convention::GoAmd64;
    ir.value_types.insert(result, CType::U64);
    let symbols = velk::render::Symbols {
        functions: [(0x1000, "go_result".into())].into(),
        function_returns: [(0x1000, CType::U64)].into(),
        ..Default::default()
    };
    let code = velk::render::render(&ir, &[], &symbols, &[]);
    assert!(!code.contains("[sp"), "{code}");
    assert!(code.contains("second"), "{code}");
    assert!(code.contains("velk_entry_stack_pointer"), "{code}");
    let helpers = "static uint64_t stack[8]; uint64_t velk_entry_stack_pointer(void) { return (uintptr_t)stack; } uint64_t go_result(uint64_t x) { return x + 17; }";
    syntax::run_printed(
        &code,
        helpers,
        "for (uint64_t i = 0; i < 100; ++i) { uint64_t x = i * UINT64_C(0xfedcba987654321), y = ~x; if (saved_go_argument(x, y) != ((x + 17) ^ y) || stack[2] != y) return 1; } return 0;",
    );
    ir.name = Some("saved_go_pointer".into());
    ir.params[1].ty = CType::pointer_to(CType::int(1, false));
    let code = velk::render::render(&ir, &[], &symbols, &[]);
    assert!(!code.contains("[sp"), "{code}");
    syntax::run_printed(
        &code,
        helpers,
        "uint8_t data[2]; for (uint64_t i = 0; i < 100; ++i) { uint8_t *p = &data[i % 2]; if (saved_go_pointer(i, p) != ((i + 17) ^ (uintptr_t)p) || stack[2] != (uintptr_t)p) return 1; } return 0;",
    );
}

#[test]
fn copy_chains_keep_values_from_before_source_overwrites() {
    let (source, first, second) = (VARIABLE_BASE, VARIABLE_BASE + 1, VARIABLE_BASE + 2);
    let mut ir = synthetic_ir(
        "copy_chain",
        vec![Param {
            index: 7,
            name: "input".into(),
            ty: CType::U64,
        }],
        CType::U64,
        vec![
            assign(
                source,
                Expr::bin(BinOp::Xor, Expr::reg(7, 64), Expr::Const(123)),
            ),
            assign(first, Expr::reg(source, 64)),
            assign(second, Expr::reg(first, 64)),
            assign(
                source,
                Expr::bin(BinOp::Add, Expr::reg(source, 64), Expr::Const(1)),
            ),
            Stmt::Ret {
                value: Expr::bin(BinOp::Add, Expr::reg(second, 64), Expr::reg(source, 64)),
            },
        ],
    );
    ir.value_types = [
        (source, CType::U64),
        (first, CType::U64),
        (second, CType::U64),
    ]
    .into();
    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
    assert!(code.contains("return "), "{code}");
    syntax::run_printed(
        &code,
        "",
        "for (uint64_t i = 0; i < 100; ++i) { uint64_t x = i * UINT64_C(0xfedcba987654321), value = x ^ 123; if (copy_chain(x) != value + value + 1) return 1; } return 0;",
    );
}

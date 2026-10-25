use super::*;
use velk::ir::{RegRef, VARIABLE_BASE};

#[test]
fn initializers_after_guards_preserve_control_and_memory_order() {
    let mut ir = synthetic_ir(
        "guarded_initial_value",
        vec![Param {
            index: 7,
            name: "p".into(),
            ty: CType::pointer_to(CType::U32),
        }],
        CType::U64,
        Vec::new(),
    );
    ir.blocks = vec![
        Block {
            start: 0,
            stmts: vec![Stmt::Brif {
                cond: Cond::Eq,
                lhs: Expr::reg(7, 64),
                rhs: Expr::Const(0),
                target: 20,
            }],
        },
        Block {
            start: 10,
            stmts: vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: VARIABLE_BASE,
                        width: 64,
                    },
                    value: Expr::Load {
                        addr: Box::new(Expr::reg(7, 64)),
                        width: 4,
                        signed: false,
                    },
                },
                Stmt::Store {
                    addr: Expr::reg(7, 64),
                    width: 4,
                    value: Expr::Const(7),
                },
                Stmt::Ret {
                    value: Expr::reg(VARIABLE_BASE, 64),
                },
            ],
        },
        Block {
            start: 20,
            stmts: vec![Stmt::Ret {
                value: Expr::Const(99),
            }],
        },
    ];
    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
    assert!(code.contains("uint32_t v1 = *p;"), "{code}");
    assert!(!code.contains("uint32_t v1;"), "{code}");
    syntax::run_printed(
        &code,
        "",
        "if (guarded_initial_value(0) != 99) __builtin_trap(); uint32_t inputs[] = {0, 1, UINT32_MAX}; for (unsigned i = 0; i < 3; ++i) { uint32_t x = inputs[i]; if (guarded_initial_value(&x) != inputs[i] || x != 7) __builtin_trap(); }",
    );
}

#[test]
fn initial_assignments_declare_locals_in_execution_order() {
    let first = Expr::reg(VARIABLE_BASE, 64);
    let second = Expr::reg(VARIABLE_BASE + 1, 64);
    let ir = synthetic_ir(
        "initial_values",
        vec![Param {
            index: 7,
            name: "x".into(),
            ty: CType::U64,
        }],
        CType::U64,
        vec![
            Stmt::Assign {
                dest: RegRef {
                    index: VARIABLE_BASE,
                    width: 64,
                },
                value: Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(1)),
            },
            Stmt::Assign {
                dest: RegRef {
                    index: VARIABLE_BASE + 1,
                    width: 64,
                },
                value: Expr::bin(BinOp::Mul, first.clone(), Expr::Const(2)),
            },
            Stmt::Ret {
                value: Expr::bin(BinOp::Xor, first, second),
            },
        ],
    );
    let candidate = printed_candidate(ir, [0, 1, u64::MAX].into_iter().map(|x| vec![x]).collect());
    assert!(
        candidate.code.contains("int64_t v1 = x + 1;"),
        "{}",
        candidate.code
    );
    assert!(
        candidate.code.contains("int64_t v2 = v1 * 2;"),
        "{}",
        candidate.code
    );
    assert!(
        !candidate.code.contains("int64_t v1;"),
        "{}",
        candidate.code
    );
    check_candidates("initial-values", vec![candidate], Mode::Registers, &[]);
}

#[test]
fn local_initializers_keep_loads_on_each_side_of_a_store() {
    let first = Expr::reg(VARIABLE_BASE, 64);
    let second = Expr::reg(VARIABLE_BASE + 1, 64);
    let load = Expr::Load {
        addr: Box::new(Expr::reg(7, 64)),
        width: 4,
        signed: false,
    };
    let ir = synthetic_ir(
        "memory_initial_values",
        vec![Param {
            index: 7,
            name: "p".into(),
            ty: CType::pointer_to(CType::U32),
        }],
        CType::U64,
        vec![
            Stmt::Assign {
                dest: RegRef {
                    index: VARIABLE_BASE,
                    width: 64,
                },
                value: load.clone(),
            },
            Stmt::Store {
                addr: Expr::reg(7, 64),
                value: Expr::bin(BinOp::Add, first.clone(), Expr::Const(1)),
                width: 4,
            },
            Stmt::Assign {
                dest: RegRef {
                    index: VARIABLE_BASE + 1,
                    width: 64,
                },
                value: load,
            },
            Stmt::Ret {
                value: Expr::bin(BinOp::Add, first, second),
            },
        ],
    );
    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
    assert!(code.contains("int64_t v1 = *p;"), "{code}");
    assert!(code.contains("int64_t v2 = *p;"), "{code}");
    syntax::run_printed(
        &code,
        "",
        "uint32_t inputs[] = { 0, 1, UINT32_MAX }; for (unsigned i = 0; i < 3; ++i) { uint32_t value = inputs[i]; uint64_t expected = (uint64_t)value + (uint32_t)(value + 1); if (memory_initial_values(&value) != expected) __builtin_trap(); }",
    );
}

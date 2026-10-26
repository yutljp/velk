use super::*;
use velk::ir::{RegRef, VARIABLE_BASE};

fn assign(index: u16, value: Expr) -> Stmt {
    Stmt::Assign {
        dest: RegRef { index, width: 64 },
        value,
    }
}

fn branch(cond: Cond, lhs: Expr, rhs: Expr, target: u64) -> Stmt {
    Stmt::Brif {
        cond,
        lhs,
        rhs,
        target,
    }
}

#[test]
fn printed_counted_loops_match_bounds_and_exits() {
    let mut candidates = Vec::new();
    let i = VARIABLE_BASE;
    let sum = VARIABLE_BASE + 1;
    let counter = || Expr::reg(i, 64);
    let total = || Expr::reg(sum, 64);
    let bound = || Expr::reg(7, 64);
    for (name, signed, wrap, early) in [
        ("signed_count", true, false, false),
        ("unsigned_count", false, false, false),
        ("wrapping_count", false, true, false),
        ("early_count", false, false, true),
    ] {
        let initial = if wrap { u64::MAX - 2 } else { 0 };
        let mut ir = synthetic_ir(
            name,
            vec![Param {
                index: 7,
                name: "bound".into(),
                ty: if signed { CType::I64 } else { CType::U64 },
            }],
            CType::U64,
            Vec::new(),
        );
        ir.blocks = vec![
            Block {
                start: 0,
                stmts: vec![branch(
                    if signed { Cond::Le } else { Cond::Eq },
                    bound(),
                    Expr::Const(initial),
                    50,
                )],
            },
            Block {
                start: 10,
                stmts: vec![assign(i, Expr::Const(initial)), assign(sum, Expr::Const(0))],
            },
            Block {
                start: 20,
                stmts: if early {
                    vec![branch(Cond::Eq, counter(), Expr::Const(3), 40)]
                } else {
                    Vec::new()
                },
            },
            Block {
                start: 30,
                stmts: vec![
                    assign(sum, Expr::bin(BinOp::Add, total(), counter())),
                    assign(i, Expr::bin(BinOp::Add, counter(), Expr::Const(1))),
                    branch(
                        if signed { Cond::Lt } else { Cond::Ne },
                        counter(),
                        bound(),
                        20,
                    ),
                ],
            },
            Block {
                start: 40,
                stmts: vec![Stmt::Ret { value: total() }],
            },
            Block {
                start: 50,
                stmts: vec![Stmt::Ret {
                    value: Expr::Const(0),
                }],
            },
        ];
        let inputs = if wrap {
            vec![initial, initial + 1, u64::MAX, 0, 1]
        } else if signed {
            vec![0, 1, 2, 7, u64::MAX, 1 << 63]
        } else {
            vec![0, 1, 2, 7]
        };
        let candidate = printed_candidate(ir, inputs.into_iter().map(|x| vec![x]).collect());
        assert!(candidate.code.contains("for ("), "{}", candidate.code);
        assert!(
            candidate.code.contains("++") || candidate.code.contains("+ 1"),
            "{}",
            candidate.code
        );
        candidates.push(candidate);
    }
    let mut ir = synthetic_ir(
        "unsigned_down",
        vec![Param {
            index: 7,
            name: "bound".into(),
            ty: CType::U64,
        }],
        CType::U64,
        Vec::new(),
    );
    ir.blocks = vec![
        Block {
            start: 0,
            stmts: vec![assign(sum, Expr::Const(0)), assign(i, bound())],
        },
        Block {
            start: 10,
            stmts: vec![branch(Cond::Eq, counter(), Expr::Const(0), 30)],
        },
        Block {
            start: 20,
            stmts: vec![
                assign(sum, Expr::bin(BinOp::Add, total(), counter())),
                assign(i, Expr::bin(BinOp::Sub, counter(), Expr::Const(1))),
                Stmt::Br { target: Some(10) },
            ],
        },
        Block {
            start: 30,
            stmts: vec![Stmt::Ret { value: total() }],
        },
    ];
    let candidate = printed_candidate(ir, vec![vec![0], vec![1], vec![2], vec![7]]);
    assert!(candidate.code.contains("for ("), "{}", candidate.code);
    assert!(
        candidate.code.contains("--") || candidate.code.contains("- 1"),
        "{}",
        candidate.code
    );
    candidates.push(candidate);
    check_candidates("counted-loops", candidates, Mode::Registers, &[]);
}

#[test]
fn printed_compound_updates_preserve_arithmetic_and_shift_counts() {
    let mut candidates = Vec::new();
    for (name, op, symbol) in [
        ("add_update", BinOp::Add, "+="),
        ("sub_update", BinOp::Sub, "-="),
        ("mul_update", BinOp::Mul, "*="),
        ("and_update", BinOp::And, "&="),
        ("or_update", BinOp::Or, "|="),
        ("xor_update", BinOp::Xor, "^="),
        ("left_update", BinOp::Shl, "<<="),
        ("right_update", BinOp::Shr, ">>="),
    ] {
        let ir = synthetic_ir(
            name,
            vec![
                Param {
                    index: 7,
                    name: "value".into(),
                    ty: CType::U64,
                },
                Param {
                    index: 6,
                    name: "amount".into(),
                    ty: CType::U64,
                },
            ],
            CType::U64,
            vec![
                assign(7, Expr::bin(op, Expr::reg(7, 64), Expr::reg(6, 64))),
                Stmt::Ret {
                    value: Expr::reg(7, 64),
                },
            ],
        );
        let mut inputs = Vec::new();
        for value in [0, 1, 1 << 63, u64::MAX] {
            for amount in [0, 1, 31, 63, 64, 65, u64::MAX] {
                inputs.push(vec![value, amount]);
            }
        }
        let candidate = printed_candidate(ir, inputs);
        assert!(candidate.code.contains(symbol), "{}", candidate.code);
        candidates.push(candidate);
    }
    for (name, op, symbol) in [
        ("masked_add_update", BinOp::Add, "+="),
        ("masked_sub_update", BinOp::Sub, "-="),
        ("masked_mul_update", BinOp::Mul, "*="),
    ] {
        let mask = |value| Expr::bin(BinOp::And, value, Expr::Const(0xffff_ffff));
        let ir = synthetic_ir(
            name,
            vec![
                Param {
                    index: 7,
                    name: "value".into(),
                    ty: CType::U32,
                },
                Param {
                    index: 6,
                    name: "amount".into(),
                    ty: CType::U32,
                },
            ],
            CType::U32,
            vec![
                assign(
                    7,
                    mask(Expr::bin(
                        op,
                        mask(Expr::reg(7, 64)),
                        mask(Expr::reg(6, 64)),
                    )),
                ),
                Stmt::Ret {
                    value: Expr::reg(7, 64),
                },
            ],
        );
        let candidate = printed_candidate(
            ir,
            vec![
                vec![0, 1],
                vec![0xffff_ffff, 2],
                vec![0x8000_0000, 0xffff_ffff],
            ],
        );
        assert!(candidate.code.contains(symbol), "{}", candidate.code);
        candidates.push(candidate);
    }
    check_candidates("compound-updates", candidates, Mode::Registers, &[]);
}

#[test]
fn printed_do_loop_keeps_a_distinct_entry_guard() {
    let i = VARIABLE_BASE;
    let mut ir = synthetic_ir(
        "distinct_guard",
        vec![Param {
            index: 7,
            name: "bound".into(),
            ty: CType::I64,
        }],
        CType::U64,
        Vec::new(),
    );
    ir.blocks = vec![
        Block {
            start: 0,
            stmts: vec![branch(Cond::Lt, Expr::reg(7, 64), Expr::Const(0), 40)],
        },
        Block {
            start: 10,
            stmts: vec![assign(i, Expr::Const(0))],
        },
        Block {
            start: 20,
            stmts: vec![
                assign(i, Expr::bin(BinOp::Add, Expr::reg(i, 64), Expr::Const(1))),
                branch(Cond::Lt, Expr::reg(i, 64), Expr::reg(7, 64), 20),
            ],
        },
        Block {
            start: 30,
            stmts: vec![Stmt::Ret {
                value: Expr::reg(i, 64),
            }],
        },
        Block {
            start: 40,
            stmts: vec![Stmt::Ret {
                value: Expr::Const(0),
            }],
        },
    ];
    let candidate = printed_candidate(ir, vec![vec![0], vec![1], vec![2], vec![u64::MAX]]);
    assert!(candidate.code.contains("do {"), "{}", candidate.code);
    check_candidates("distinct-loop-guard", vec![candidate], Mode::Registers, &[]);
}

#[test]
fn printed_continue_paths_update_the_counter_once() {
    let i = VARIABLE_BASE;
    let sum = VARIABLE_BASE + 1;
    let mut ir = synthetic_ir(
        "continued_count",
        vec![Param {
            index: 7,
            name: "bound".into(),
            ty: CType::U64,
        }],
        CType::U64,
        Vec::new(),
    );
    let step = || assign(i, Expr::bin(BinOp::Add, Expr::reg(i, 64), Expr::Const(1)));
    ir.blocks = vec![
        Block {
            start: 0,
            stmts: vec![assign(sum, Expr::Const(0)), assign(i, Expr::Const(0))],
        },
        Block {
            start: 10,
            stmts: vec![branch(Cond::Cs, Expr::reg(i, 64), Expr::reg(7, 64), 50)],
        },
        Block {
            start: 20,
            stmts: vec![branch(Cond::Eq, Expr::reg(i, 64), Expr::Const(1), 40)],
        },
        Block {
            start: 30,
            stmts: vec![
                assign(
                    sum,
                    Expr::bin(BinOp::Add, Expr::reg(sum, 64), Expr::reg(i, 64)),
                ),
                step(),
                Stmt::Br { target: Some(10) },
            ],
        },
        Block {
            start: 40,
            stmts: vec![step(), Stmt::Br { target: Some(10) }],
        },
        Block {
            start: 50,
            stmts: vec![Stmt::Ret {
                value: Expr::reg(sum, 64),
            }],
        },
    ];
    let candidate = printed_candidate(ir, vec![vec![0], vec![1], vec![2], vec![7]]);
    assert!(candidate.code.contains("for ("), "{}", candidate.code);
    check_candidates("continued-count", vec![candidate], Mode::Registers, &[]);
}

#[test]
fn printed_guarded_initialization_stays_conditional() {
    let i = VARIABLE_BASE;
    let mut ir = synthetic_ir(
        "guarded_initialization",
        vec![Param {
            index: 7,
            name: "bound".into(),
            ty: CType::U64,
        }],
        CType::U64,
        Vec::new(),
    );
    ir.blocks = vec![
        Block {
            start: 0,
            stmts: vec![
                assign(i, Expr::Const(9)),
                branch(Cond::Eq, Expr::reg(7, 64), Expr::Const(0), 30),
            ],
        },
        Block {
            start: 10,
            stmts: vec![assign(i, Expr::Const(0))],
        },
        Block {
            start: 20,
            stmts: vec![
                assign(i, Expr::bin(BinOp::Add, Expr::reg(i, 64), Expr::Const(1))),
                branch(Cond::Ne, Expr::reg(7, 64), Expr::reg(i, 64), 20),
            ],
        },
        Block {
            start: 30,
            stmts: vec![Stmt::Ret {
                value: Expr::reg(i, 64),
            }],
        },
    ];
    let candidate = printed_candidate(ir, vec![vec![0], vec![1], vec![2], vec![7]]);
    assert!(candidate.code.contains("for ("), "{}", candidate.code);
    assert!(candidate.code.contains("if ("), "{}", candidate.code);
    check_candidates(
        "guarded-initialization",
        vec![candidate],
        Mode::Registers,
        &[],
    );
}

#[test]
fn printed_guarded_unsigned_do_countdown_preserves_zero() {
    let i = VARIABLE_BASE;
    let sum = VARIABLE_BASE + 1;
    let mut ir = synthetic_ir(
        "guarded_down",
        vec![Param {
            index: 7,
            name: "bound".into(),
            ty: CType::U64,
        }],
        CType::U64,
        Vec::new(),
    );
    ir.blocks = vec![
        Block {
            start: 0,
            stmts: vec![branch(Cond::Eq, Expr::reg(7, 64), Expr::Const(0), 40)],
        },
        Block {
            start: 10,
            stmts: vec![assign(sum, Expr::Const(0)), assign(i, Expr::reg(7, 64))],
        },
        Block {
            start: 20,
            stmts: vec![
                assign(
                    sum,
                    Expr::bin(BinOp::Add, Expr::reg(sum, 64), Expr::reg(i, 64)),
                ),
                assign(i, Expr::bin(BinOp::Sub, Expr::reg(i, 64), Expr::Const(1))),
                branch(Cond::Ne, Expr::reg(i, 64), Expr::Const(0), 20),
            ],
        },
        Block {
            start: 30,
            stmts: vec![Stmt::Ret {
                value: Expr::reg(sum, 64),
            }],
        },
        Block {
            start: 40,
            stmts: vec![Stmt::Ret {
                value: Expr::Const(0),
            }],
        },
    ];
    let candidate = printed_candidate(ir, vec![vec![0], vec![1], vec![2], vec![7]]);
    assert!(candidate.code.contains("for ("), "{}", candidate.code);
    assert!(
        candidate.code.contains("--") || candidate.code.contains("- 1"),
        "{}",
        candidate.code
    );
    check_candidates("guarded-down", vec![candidate], Mode::Registers, &[]);
}

#[test]
fn printed_stack_shifts_keep_the_stored_width() {
    let mut candidates = Vec::new();
    for width in [1, 2, 4, 8] {
        for (op, symbol) in [(BinOp::Shl, "<<="), (BinOp::Shr, ">>=")] {
            let address = Expr::bin(BinOp::Sub, Expr::reg(4, 64), Expr::Const(8));
            let loaded = Expr::Load {
                addr: Box::new(address.clone()),
                width,
                signed: false,
            };
            let ir = synthetic_ir(
                &format!(
                    "stack_shift_{width}_{}",
                    if op == BinOp::Shl { "left" } else { "right" }
                ),
                vec![Param {
                    index: 7,
                    name: "value".into(),
                    ty: CType::U64,
                }],
                CType::U64,
                vec![
                    Stmt::Store {
                        addr: address.clone(),
                        width,
                        value: Expr::reg(7, 64),
                    },
                    Stmt::Store {
                        addr: address,
                        width,
                        value: Expr::bin(op, loaded.clone(), Expr::Const(1)),
                    },
                    Stmt::Ret { value: loaded },
                ],
            );
            let candidate = printed_candidate(
                ir,
                vec![vec![0], vec![1], vec![u64::MAX], vec![0x8000_0000]],
            );
            if width == 8 && op == BinOp::Shl {
                assert!(
                    candidate.code.contains("(uint64_t)result"),
                    "{}",
                    candidate.code
                );
                assert!(!candidate.code.contains(symbol), "{}", candidate.code);
            } else if width == 8 {
                assert!(
                    candidate.code.contains("return result >> 1;"),
                    "{}",
                    candidate.code
                );
            } else {
                assert!(candidate.code.contains(symbol), "{}", candidate.code);
            }
            candidates.push(candidate);
        }
    }
    check_candidates("stack-compound-shifts", candidates, Mode::Registers, &[]);
}

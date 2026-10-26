use super::*;
use velk::ir::{RegRef, VALUE_BASE, VARIABLE_BASE};

#[test]
fn printed_indexed_stack_pointer_assignments_preserve_byte_offsets() {
    let index = Convention::SysV.arguments()[0];
    let slot = |offset: i64| Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const(offset as u64));
    let address = Expr::bin(
        BinOp::Add,
        slot(-160),
        Expr::bin(BinOp::Shl, Expr::reg(index, 64), Expr::Const(2)),
    );
    let pointer = Expr::reg(VARIABLE_BASE, 64);
    let ir = synthetic_ir(
        "indexed_stack_pointer",
        vec![Param {
            index,
            name: "index".into(),
            ty: CType::U64,
        }],
        CType::U32,
        vec![
            Stmt::Store {
                addr: slot(-8),
                value: Expr::Const(0x12345678),
                width: 4,
            },
            Stmt::Store {
                addr: address.clone(),
                value: Expr::Const(7),
                width: 4,
            },
            Stmt::Assign {
                dest: RegRef {
                    index: VARIABLE_BASE,
                    width: 64,
                },
                value: address.clone(),
            },
            Stmt::Store {
                addr: pointer.clone(),
                value: Expr::Const(0x3456789a),
                width: 4,
            },
            Stmt::Ret {
                value: Expr::bin(
                    BinOp::Xor,
                    Expr::bin(
                        BinOp::Xor,
                        Expr::Load {
                            addr: Box::new(pointer),
                            width: 4,
                            signed: false,
                        },
                        Expr::Load {
                            addr: Box::new(address),
                            width: 4,
                            signed: false,
                        },
                    ),
                    Expr::Load {
                        addr: Box::new(slot(-8)),
                        width: 4,
                        signed: false,
                    },
                ),
            },
        ],
    );
    let candidate = printed_candidate(ir, (0..38).map(|index| vec![index]).collect());
    assert!(
        candidate.code.contains("uint32_t *v1 ="),
        "{}",
        candidate.code
    );
    assert!(
        candidate.code.contains("v1 = (uint32_t *)"),
        "{}",
        candidate.code
    );
    check_candidates(
        "indexed-stack-pointer",
        vec![candidate],
        Mode::Registers,
        &[],
    );
}

#[test]
fn printed_variables_at_and_above_ssa_boundary_are_declared() {
    let argument = Convention::SysV.arguments()[0];
    let mut statements = Vec::new();
    let mut value = Expr::reg(argument, 64);
    for index in [VALUE_BASE - 1, VALUE_BASE, VALUE_BASE + 1] {
        statements.push(Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value: Expr::bin(BinOp::Add, value, Expr::Const(1)),
        });
        value = Expr::reg(index, 64);
    }
    let value = [VALUE_BASE - 1, VALUE_BASE, VALUE_BASE + 1]
        .map(|index| Expr::bin(BinOp::Mul, Expr::reg(index, 64), Expr::reg(index, 64)))
        .into_iter()
        .reduce(|lhs, rhs| Expr::bin(BinOp::Add, lhs, rhs))
        .unwrap();
    statements.push(Stmt::Ret { value });
    let ir = synthetic_ir(
        "many_variables",
        vec![Param {
            index: argument,
            name: "input".into(),
            ty: CType::U64,
        }],
        CType::U64,
        statements,
    );
    let candidate = printed_candidate(ir, vec![vec![0], vec![1], vec![u64::MAX]]);
    for name in ["v3840", "s0", "s1"] {
        assert!(
            candidate.code.contains(&format!(" {name} =")),
            "{}",
            candidate.code
        );
    }
    check_candidates("many-variables", vec![candidate], Mode::Registers, &[]);
}

#[test]
fn pointer_self_updates_preserve_element_and_byte_offsets() {
    for (suffix, op, step, update) in [
        ("elements", BinOp::Add, 8, Some("p += 0x2;")),
        ("increment", BinOp::Add, 4, Some("++p;")),
        ("decrement", BinOp::Sub, 4, Some("--p;")),
        ("negative", BinOp::Add, u64::MAX - 3, Some("--p;")),
        ("bytes", BinOp::Add, 8, None),
    ] {
        let pointer = Expr::reg(7, 64);
        let mut params = vec![Param {
            index: 7,
            name: "p".into(),
            ty: CType::pointer_to(CType::U32),
        }];
        let offset = if update.is_none() {
            params.push(Param {
                index: 6,
                name: "offset".into(),
                ty: CType::U64,
            });
            Expr::reg(6, 64)
        } else {
            Expr::Const(step)
        };
        let ir = synthetic_ir(
            &format!("pointer_update_{suffix}"),
            params,
            CType::pointer_to(CType::U32),
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: 7,
                        width: 64,
                    },
                    value: Expr::bin(op, pointer.clone(), offset),
                },
                Stmt::Ret { value: pointer },
            ],
        );
        let candidate = printed_candidate(ir, vec![]);
        if let Some(update) = update {
            assert!(candidate.code.contains(update), "{}", candidate.code);
        } else {
            assert!(!candidate.code.contains("p +="), "{}", candidate.code);
        }
        let negative = op == BinOp::Sub || step > i64::MAX as u64;
        let sign = if negative { "-" } else { "+" };
        let distance = if step > i64::MAX as u64 {
            step.wrapping_neg()
        } else {
            step
        };
        let argument = if update.is_none() { ", 8" } else { "" };
        syntax::run_printed(
            &candidate.code,
            "",
            &format!(
                "uint32_t values[8] = {{0}}; uint32_t *p = values + 2; if ((uintptr_t)pointer_update_{suffix}(p{argument}) != (uintptr_t)p {sign} {distance}) __builtin_trap();"
            ),
        );
    }
}

#[test]
fn printed_global_offsets_keep_the_data_address_separate() {
    const BASE: u64 = 0x100002000;
    for width in [1, 2, 4, 8] {
        let offset = Expr::reg(VARIABLE_BASE, 64);
        let address = Expr::bin(
            BinOp::Add,
            Expr::bin(BinOp::Add, Expr::Const(BASE), offset.clone()),
            Expr::bin(BinOp::Mul, Expr::reg(6, 64), Expr::Const(width.into())),
        );
        let address = Expr::bin(BinOp::Add, address, Expr::Const(8));
        let ir = synthetic_ir(
            "global_offset",
            vec![
                Param {
                    index: 7,
                    name: "row".into(),
                    ty: CType::I64,
                },
                Param {
                    index: 6,
                    name: "column".into(),
                    ty: CType::I64,
                },
            ],
            CType::I64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: VARIABLE_BASE,
                        width: 64,
                    },
                    value: Expr::bin(BinOp::Shl, Expr::reg(7, 64), Expr::Const(3)),
                },
                Stmt::Store {
                    addr: address.clone(),
                    value: Expr::Const(u64::MAX),
                    width,
                },
                Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(address),
                        width,
                        signed: true,
                    },
                },
            ],
        );
        let code = velk::render::render(&ir, &[], &Default::default(), &[(BASE, 512)]);
        assert!(code.contains("/* address: 0x100002000 */"), "{code}");
        if width != 1 {
            assert!(
                !code.contains(&format!("0x{:x}]", BASE / u64::from(width))),
                "{code}"
            );
        }
        let code = format!(
            "#include <string.h>\n_Alignas(16) static uint8_t data[256];\n{}",
            bound_globals(&code).replace("0x100002000ULL", "(uintptr_t)(data + 128)")
        );
        syntax::run_printed(
            &code,
            "",
            &format!(
                "for (int row = -4; row <= 4; ++row) for (int column = -4; column <= 4; ++column) {{
                    memset(data, 0, sizeof(data));
                    if (global_offset(row, column) != -1) __builtin_trap();
                    int offset = 136 + row * 8 + column * {width};
                    for (int i = 0; i < 256; ++i)
                        if (data[i] != (i >= offset && i < offset + {width} ? 255 : 0)) __builtin_trap();
                }}"
            ),
        );
    }
}

#[test]
fn negative_literal_offsets_wrap_as_integers() {
    let offset = || Expr::reg(VARIABLE_BASE, 64);
    let sum = || Expr::reg(VARIABLE_BASE + 1, 64);
    let assign = |index, value| Stmt::Assign {
        dest: RegRef { index, width: 64 },
        value,
    };
    let mut ir = synthetic_ir("negative_offset", Vec::new(), CType::U64, Vec::new());
    ir.blocks = vec![
        Block {
            start: 0,
            stmts: vec![
                assign(VARIABLE_BASE, Expr::Const((-160i64) as u64)),
                assign(VARIABLE_BASE + 1, Expr::Const(0)),
            ],
        },
        Block {
            start: 10,
            stmts: vec![
                assign(
                    VARIABLE_BASE + 1,
                    Expr::bin(
                        BinOp::Add,
                        sum(),
                        Expr::Load {
                            addr: Box::new(Expr::bin(
                                BinOp::Add,
                                Expr::Const(0x20000100),
                                offset(),
                            )),
                            width: 2,
                            signed: false,
                        },
                    ),
                ),
                assign(
                    VARIABLE_BASE,
                    Expr::bin(BinOp::Add, offset(), Expr::Const(32)),
                ),
                Stmt::Brif {
                    cond: Cond::Ne,
                    lhs: offset(),
                    rhs: Expr::Const(0),
                    target: 10,
                },
            ],
        },
        Block {
            start: 20,
            stmts: vec![Stmt::Ret { value: sum() }],
        },
    ];
    let candidate = printed_candidate(ir, vec![Vec::new()]);
    assert!(candidate.code.contains("uint64_t v1"), "{}", candidate.code);
    assert!(!candidate.code.contains("*v1"), "{}", candidate.code);
    let code = format!(
        "static uint16_t data[160];\n{}",
        candidate
            .code
            .replace("0x20000100", "(uintptr_t)(data + 160)")
    );
    syntax::run_printed(
        &code,
        "",
        "for (int i = 0; i < 160; ++i) data[i] = i;\n\
         if (negative_offset() != 560) __builtin_trap();",
    );
}

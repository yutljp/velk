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

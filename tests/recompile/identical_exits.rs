use super::*;
use velk::ir::RegRef;

#[test]
fn printed_identical_exits_preserve_constants_and_store_order() {
    let arguments = Convention::SysV.arguments();
    let variable = velk::ir::VARIABLE_BASE;
    let pointer = Expr::reg(arguments[0], 64);
    let input = Expr::reg(arguments[1], 64);
    let load = Expr::Load {
        addr: Box::new(pointer.clone()),
        width: 8,
        signed: false,
    };
    let assign = |value| Stmt::Assign {
        dest: RegRef {
            index: variable,
            width: 64,
        },
        value: Expr::Const(value),
    };
    for memory in [false, true] {
        let mut ir = synthetic_ir(
            if memory {
                "identical_store_exits"
            } else {
                "identical_error_exits"
            },
            vec![
                Param {
                    index: arguments[0],
                    name: "pointer".into(),
                    ty: if memory {
                        CType::pointer_to(CType::U64)
                    } else {
                        CType::U64
                    },
                },
                Param {
                    index: arguments[1],
                    name: "input".into(),
                    ty: CType::U64,
                },
            ],
            CType::U64,
            Vec::new(),
        );
        ir.blocks.push(Block {
            start: 0,
            stmts: vec![Stmt::Switch {
                index: input.clone(),
                cases: vec![(0, 10), (1, 20), (2, 30)],
                default: Some(40),
            }],
        });
        for (start, code) in [(10, 19), (20, 19), (30, 19), (40, 20)] {
            let mut stmts = Vec::new();
            if memory {
                stmts.push(Stmt::Store {
                    addr: pointer.clone(),
                    width: 8,
                    value: Expr::bin(BinOp::Add, load.clone(), Expr::Const(start)),
                });
            }
            stmts.push(assign(code));
            if memory {
                // Two dependent writes must happen once, in this order.
                for (op, constant) in [(BinOp::Add, 1), (BinOp::Mul, 3)] {
                    stmts.push(Stmt::Store {
                        addr: pointer.clone(),
                        width: 8,
                        value: Expr::bin(op, load.clone(), Expr::Const(constant)),
                    });
                }
            }
            stmts.push(Stmt::Br { target: Some(100) });
            ir.blocks.push(Block { start, stmts });
        }
        ir.blocks.push(Block {
            start: 100,
            stmts: vec![Stmt::Ret {
                value: Expr::bin(
                    BinOp::Add,
                    Expr::reg(variable, 64),
                    if memory { load.clone() } else { Expr::Const(0) },
                ),
            }],
        });
        let candidate = printed_candidate(
            ir,
            (0..6)
                .map(|input| vec![if memory { REGION } else { 0 }, input])
                .collect(),
        );
        assert!(candidate.code.contains("19"), "{}", candidate.code);
        assert!(candidate.code.contains("20"), "{}", candidate.code);
        if memory {
            assert_eq!(
                candidate.code.matches("*pointer += 1;").count(),
                1,
                "{}",
                candidate.code
            );
            assert_eq!(
                candidate.code.matches("*pointer *= 3;").count(),
                1,
                "{}",
                candidate.code
            );
        } else {
            assert_eq!(
                candidate.code.matches("19;").count(),
                1,
                "{}",
                candidate.code
            );
        }
        check_candidates(
            "identical-exits",
            vec![candidate],
            if memory {
                Mode::Memory
            } else {
                Mode::Registers
            },
            &[],
        );
    }
}

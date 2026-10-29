use super::*;
use velk::ir::{AtomicOp, MachineInstruction, Ordering, RegRef, TEMP_BASE};

#[test]
fn printed_atomic_tests_preserve_width_order_and_old_values() {
    let scratch = scratch_dir("atomic-spelling");
    let mut text = String::from(HEADER);
    let mut checks = String::from("int main(void) {\n");
    for width in [1u8, 2, 4, 8] {
        for (op_index, op) in [
            AtomicOp::Load,
            AtomicOp::Store,
            AtomicOp::Add,
            AtomicOp::Sub,
            AtomicOp::And,
            AtomicOp::Or,
            AtomicOp::Xor,
            AtomicOp::Exchange,
            AtomicOp::CompareExchange,
        ]
        .into_iter()
        .enumerate()
        {
            for (order_index, ordering) in [
                Ordering::Relaxed,
                Ordering::Acquire,
                Ordering::Release,
                Ordering::AcqRel,
                Ordering::SeqCst,
            ]
            .into_iter()
            .enumerate()
            {
                if (op == AtomicOp::Load
                    && matches!(ordering, Ordering::Release | Ordering::AcqRel))
                    || (op == AtomicOp::Store
                        && matches!(ordering, Ordering::Acquire | Ordering::AcqRel))
                {
                    continue;
                }
                for keep_old in [false, true] {
                    let name = format!("atomic_{width}_{op_index}_{order_index}_{keep_old}");
                    let result = Expr::reg(TEMP_BASE, 64);
                    let mut ir = synthetic_ir(
                        &name,
                        vec![Param {
                            index: 7,
                            name: "p".into(),
                            ty: CType::pointer_to(CType::int(width, false)),
                        }],
                        CType::U64,
                        vec![Stmt::Machine {
                            at: None,
                            instruction: MachineInstruction::Atomic {
                                op,
                                width,
                                ordering,
                            },
                            inputs: vec![Expr::reg(7, 64), Expr::Const(0x103), Expr::Const(1)],
                            outputs: if op == AtomicOp::Store {
                                vec![]
                            } else {
                                vec![RegRef {
                                    index: TEMP_BASE,
                                    width: width * 8,
                                }]
                            },
                        }],
                    );
                    if op == AtomicOp::Store {
                        ir.blocks[0].stmts.push(Stmt::Ret {
                            value: Expr::Const(0),
                            at: None,
                        });
                    } else {
                        ir.blocks[0].stmts.push(Stmt::Brif {
                            cond: Cond::Eq,
                            lhs: result.clone(),
                            rhs: Expr::Const(1),
                            target: 0x20,
                            at: None,
                        });
                        ir.blocks.extend([
                            Block {
                                start: 0x10,
                                stmts: vec![Stmt::Ret {
                                    value: if keep_old {
                                        result.clone()
                                    } else {
                                        Expr::Const(0)
                                    },
                                    at: None,
                                }],
                            },
                            Block {
                                start: 0x20,
                                stmts: vec![Stmt::Ret {
                                    value: if keep_old {
                                        Expr::bin(BinOp::Add, result, Expr::Const(1000))
                                    } else {
                                        Expr::Const(1000)
                                    },
                                    at: None,
                                }],
                            },
                        ]);
                    }
                    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
                    let order = match ordering {
                        Ordering::Relaxed => "__ATOMIC_RELAXED",
                        Ordering::Acquire => "__ATOMIC_ACQUIRE",
                        Ordering::Release => "__ATOMIC_RELEASE",
                        Ordering::AcqRel => "__ATOMIC_ACQ_REL",
                        Ordering::SeqCst => "__ATOMIC_SEQ_CST",
                    };
                    assert!(code.contains(order), "{code}");
                    if op == AtomicOp::CompareExchange && (width == 8 || !keep_old) {
                        assert!(!code.contains(" expected ="), "{code}");
                        assert!(
                            code.lines().any(|line| line.contains("if (")
                                && line.contains("__atomic_compare_exchange_n")),
                            "{code}"
                        );
                    } else if !matches!(op, AtomicOp::Store | AtomicOp::CompareExchange) {
                        assert!(
                            code.lines()
                                .any(|line| line.contains("if (") && line.contains("__atomic_")),
                            "{code}"
                        );
                    }
                    text.push_str(&code);
                    let mask = u64::MAX >> (64 - width * 8);
                    for old in [0, 1, 2, mask, mask >> 1] {
                        let desired = 0x103 & mask;
                        let new = match op {
                            AtomicOp::Load => old,
                            AtomicOp::Store | AtomicOp::Exchange => desired,
                            AtomicOp::Add => old.wrapping_add(desired) & mask,
                            AtomicOp::Sub => old.wrapping_sub(desired) & mask,
                            AtomicOp::And => old & desired,
                            AtomicOp::Or => old | desired,
                            AtomicOp::Xor => old ^ desired,
                            AtomicOp::CompareExchange => {
                                if old == 1 {
                                    desired
                                } else {
                                    old
                                }
                            }
                        };
                        let returned = if op == AtomicOp::Store {
                            0
                        } else {
                            u64::from(old == 1) * 1000 + if keep_old { old } else { 0 }
                        };
                        writeln!(checks, "{{ uint{}_t x = UINT64_C({old}); if ({name}(&x) != UINT64_C({returned}) || x != UINT64_C({new})) return 1; }}", width * 8).unwrap();
                    }
                }
            }
        }
    }
    checks.push_str("return 0; }\n");
    text.push_str(&checks);
    let source = Program {
        text,
        ranges: Vec::new(),
    };
    for level in LEVELS {
        let executable = build(&source, &scratch, level, &[]);
        assert_eq!(run(&executable, ""), "");
    }
    std::fs::remove_dir_all(scratch).ok();
}

#[test]
fn printed_compare_exchange_keeps_a_wider_expected_test() {
    let scratch = scratch_dir("atomic-expected-width");
    let mut text = String::from(HEADER);
    for (name, expected) in [("wide_expected", 0x101), ("failure_test", 1)] {
        let mut ir = synthetic_ir(
            name,
            vec![Param {
                index: 7,
                name: "p".into(),
                ty: CType::pointer_to(CType::int(1, false)),
            }],
            CType::U64,
            vec![
                Stmt::Machine {
                    at: None,
                    instruction: MachineInstruction::Atomic {
                        op: AtomicOp::CompareExchange,
                        width: 1,
                        ordering: Ordering::AcqRel,
                    },
                    inputs: vec![Expr::reg(7, 64), Expr::Const(3), Expr::Const(expected)],
                    outputs: vec![RegRef {
                        index: TEMP_BASE,
                        width: 8,
                    }],
                },
                Stmt::Brif {
                    cond: Cond::Ne,
                    lhs: Expr::reg(TEMP_BASE, 64),
                    rhs: Expr::Const(expected),
                    target: 0x20,
                    at: None,
                },
            ],
        );
        ir.blocks.extend([
            Block {
                start: 0x10,
                stmts: vec![Stmt::Ret {
                    value: Expr::Const(0),
                    at: None,
                }],
            },
            Block {
                start: 0x20,
                stmts: vec![Stmt::Ret {
                    value: Expr::Const(1),
                    at: None,
                }],
            },
        ]);
        let code = velk::render::render(&ir, &[], &Default::default(), &[]);
        if expected > 255 {
            assert!(code.contains("uint8_t expected"), "{code}");
        } else {
            assert!(!code.contains("uint8_t expected"), "{code}");
        }
        assert!(
            code.contains("__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE"),
            "{code}"
        );
        text.push_str(&code);
    }
    for shared_comparison in [false, true] {
        let mut ir = synthetic_ir(
            if shared_comparison {
                "shared_comparison"
            } else {
                "desired_uses_output"
            },
            vec![Param {
                index: 7,
                name: "p".into(),
                ty: CType::pointer_to(CType::U64),
            }],
            CType::U64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: TEMP_BASE,
                        width: 64,
                    },
                    value: Expr::Const(5),
                    at: None,
                },
                Stmt::Machine {
                    at: None,
                    instruction: MachineInstruction::Atomic {
                        op: if shared_comparison {
                            AtomicOp::Add
                        } else {
                            AtomicOp::CompareExchange
                        },
                        width: 8,
                        ordering: Ordering::SeqCst,
                    },
                    inputs: vec![Expr::reg(7, 64), Expr::reg(TEMP_BASE, 64), Expr::Const(1)],
                    outputs: vec![RegRef {
                        index: TEMP_BASE,
                        width: 64,
                    }],
                },
                Stmt::Brif {
                    cond: Cond::Eq,
                    lhs: Expr::reg(TEMP_BASE, 64),
                    rhs: if shared_comparison {
                        Expr::Load {
                            addr: Box::new(Expr::reg(7, 64)),
                            width: 8,
                            signed: false,
                        }
                    } else {
                        Expr::Const(1)
                    },
                    target: 0x20,
                    at: None,
                },
            ],
        );
        ir.blocks.extend([
            Block {
                start: 0x10,
                stmts: vec![Stmt::Ret {
                    value: Expr::Const(0),
                    at: None,
                }],
            },
            Block {
                start: 0x20,
                stmts: vec![Stmt::Ret {
                    value: Expr::Const(1),
                    at: None,
                }],
            },
        ]);
        let code = velk::render::render(&ir, &[], &Default::default(), &[]);
        assert!(
            !code
                .lines()
                .any(|line| line.contains("if (") && line.contains("__atomic_")),
            "{code}"
        );
        text.push_str(&code);
    }
    text.push_str("int main(void) { uint8_t x = 1; if (wide_expected(&x) != 1 || x != 3) return 1; x = 2; if (failure_test(&x) != 1 || x != 2) return 2; x = 1; if (failure_test(&x) != 0 || x != 3) return 3; uint64_t y = 1; if (desired_uses_output(&y) != 1 || y != 5) return 4; y = 1; if (shared_comparison(&y) != 0 || y != 6) return 5; return 0; }\n");
    let source = Program {
        text,
        ranges: Vec::new(),
    };
    for level in LEVELS {
        let executable = build(&source, &scratch, level, &[]);
        assert_eq!(run(&executable, ""), "");
    }
    std::fs::remove_dir_all(scratch).ok();
}

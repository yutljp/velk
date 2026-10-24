use super::*;
use velk::ir::{RegRef, VARIABLE_BASE};

#[test]
fn printed_record_transfers_keep_recovered_frame_storage() {
    let at = |offset: i64| Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const(offset as u64));
    let load = |offset| Expr::Load {
        addr: Box::new(at(offset)),
        width: 8,
        signed: false,
    };
    let mut stmts = vec![
        Stmt::Store {
            addr: at(-16),
            value: Expr::Const(123),
            width: 8,
        },
        Stmt::Store {
            addr: at(-8),
            value: Expr::Const(456),
            width: 8,
        },
    ];
    for part in 0..2 {
        stmts.push(Stmt::Assign {
            dest: RegRef {
                index: VARIABLE_BASE + part as u16,
                width: 64,
            },
            value: load(-16 + part * 8),
        });
    }
    for part in 0..2 {
        stmts.push(Stmt::Store {
            addr: at(-32 + part * 8),
            value: Expr::reg(VARIABLE_BASE + part as u16, 64),
            width: 8,
        });
    }
    stmts.push(Stmt::Ret {
        value: Expr::bin(BinOp::Xor, load(-32), load(-24)),
    });
    let candidate = printed_candidate(
        synthetic_ir("record_frame_copy", vec![], CType::U64, stmts),
        vec![vec![]],
    );
    assert!(
        !candidate.code.contains("unsigned char"),
        "{}",
        candidate.code
    );
    check_candidates("record-frame-copy", vec![candidate], Mode::Registers, &[]);
}

#[test]
fn printed_record_transfers_snapshot_overlapping_ranges() {
    let mut candidates = Vec::new();
    let arguments = Convention::SysV.arguments();
    for size in [16, 32] {
        for (extra_read, typed, interleaved, separated) in [
            (false, false, false, false),
            (true, false, false, false),
            (false, true, false, false),
            (false, false, true, false),
            (false, false, false, true),
        ] {
            let at = |register, offset| {
                Expr::bin(BinOp::Add, Expr::reg(register, 64), Expr::Const(offset))
            };
            let mut stmts = vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: VARIABLE_BASE,
                        width: 64,
                    },
                    value: Expr::Const(123),
                },
                Stmt::Store {
                    addr: at(arguments[0], 96),
                    value: Expr::reg(VARIABLE_BASE, 64),
                    width: 8,
                },
            ];
            for part in 0..size / 8 {
                stmts.push(Stmt::Assign {
                    dest: RegRef {
                        index: VARIABLE_BASE + part as u16,
                        width: 64,
                    },
                    value: Expr::Load {
                        addr: Box::new(at(arguments[1], part * 8)),
                        width: 8,
                        signed: false,
                    },
                });
            }
            for part in 0..size / 8 {
                stmts.push(Stmt::Store {
                    addr: at(arguments[0], part * 8),
                    value: Expr::reg(VARIABLE_BASE + part as u16, 64),
                    width: 8,
                });
            }
            if interleaved {
                let loads = stmts[2..2 + (size / 8) as usize].to_vec();
                let stores = stmts[2 + (size / 8) as usize..].to_vec();
                stmts.truncate(2);
                stmts.extend(
                    loads
                        .into_iter()
                        .zip(stores)
                        .flat_map(|(load, store)| [load, store]),
                );
            }
            if separated {
                stmts.insert(
                    2 + (size / 8) as usize,
                    Stmt::Assign {
                        dest: RegRef {
                            index: VARIABLE_BASE + 10,
                            width: 64,
                        },
                        value: Expr::Load {
                            addr: Box::new(at(arguments[1], 128)),
                            width: 8,
                            signed: false,
                        },
                    },
                );
            }
            stmts.push(Stmt::Ret {
                value: if extra_read {
                    Expr::reg(VARIABLE_BASE, 64)
                } else if separated {
                    Expr::reg(VARIABLE_BASE + 10, 64)
                } else {
                    Expr::Const(0)
                },
            });
            let mut ir = synthetic_ir(
                &format!("record_copy_{size}_{extra_read}_{typed}_{interleaved}_{separated}"),
                arguments[..2]
                    .iter()
                    .enumerate()
                    .map(|(part, index)| Param {
                        index: *index,
                        name: ["dst", "src"][part].into(),
                        ty: CType::pointer_to(if typed {
                            CType::Named(format!("struct record_{size}"))
                        } else {
                            CType::int(1, false)
                        }),
                    })
                    .collect(),
                CType::U64,
                stmts,
            );
            if typed {
                ir.structures.push(velk::ir::Structure {
                    name: format!("record_{size}"),
                    fields: (0..size / 8).map(|part| (part * 8, CType::I64)).collect(),
                    size: Some(size),
                    elements: arguments[..2].to_vec(),
                });
            }
            let inputs = [(0, 64), (64, 0), (0, 0), (1, 0), (0, 1), (8, 0), (0, 8)]
                .into_iter()
                .map(|(dst, src)| vec![REGION + dst, REGION + src])
                .collect();
            let candidate = printed_candidate(ir, inputs);
            assert_eq!(
                candidate.code.contains("__builtin_memmove")
                    || candidate.code.contains("unsigned char"),
                !extra_read && !typed && !interleaved,
                "{}",
                candidate.code
            );
            if typed {
                assert!(
                    candidate
                        .code
                        .contains(&format!("((struct record_{size}[1])")),
                    "{}",
                    candidate.code
                );
            }
            candidates.push(candidate);
        }
    }
    check_candidates("record-transfers", candidates, Mode::Memory, &[]);
}

#[test]
fn printed_indexed_and_vector_record_moves_preserve_bytes() {
    let arguments = Convention::SysV.arguments();
    let mut candidates = Vec::new();
    for vector in [false, true] {
        for (global, padded) in [(false, false), (false, true), (true, false)] {
            let at = |parameter: usize, offset| {
                if global {
                    Expr::Const(REGION + parameter as u64 * 64 + offset)
                } else {
                    Expr::bin(
                        BinOp::Add,
                        Expr::reg(arguments[0], 64),
                        Expr::bin(
                            BinOp::Add,
                            Expr::bin(
                                BinOp::Mul,
                                Expr::reg(arguments[parameter + 1], 64),
                                Expr::Const(16),
                            ),
                            Expr::Const(offset),
                        ),
                    )
                }
            };
            let first = if vector {
                velk::arch::x86::XMM0
            } else {
                VARIABLE_BASE
            };
            let mut statements = Vec::new();
            for part in 0..2 {
                statements.push(Stmt::Assign {
                    dest: RegRef {
                        index: first + part,
                        width: 64,
                    },
                    value: Expr::Load {
                        addr: Box::new(at(1, u64::from(part) * 8)),
                        width: 8,
                        signed: false,
                    },
                });
            }
            for part in 0..2 {
                statements.push(Stmt::Store {
                    addr: at(0, u64::from(part) * 8),
                    value: Expr::reg(first + part, 64),
                    width: 8,
                });
            }
            statements.push(Stmt::Ret {
                value: Expr::Const(0),
            });
            let mut ir = synthetic_ir(
                &format!("indexed_record_{vector}_{global}_{padded}"),
                if global {
                    vec![]
                } else {
                    arguments[..3]
                        .iter()
                        .enumerate()
                        .map(|(part, index)| Param {
                            index: *index,
                            name: ["array", "i", "j"][part].into(),
                            ty: if part == 0 {
                                CType::pointer_to(CType::Named("struct item".into()))
                            } else {
                                CType::U64
                            },
                        })
                        .collect()
                },
                CType::U64,
                statements,
            );
            if !global {
                ir.structures.push(velk::ir::Structure {
                    name: "item".into(),
                    fields: vec![
                        (0, CType::U64),
                        (8, if padded { CType::U32 } else { CType::U64 }),
                    ],
                    size: Some(16),
                    elements: vec![arguments[0]],
                });
                let mut body = std::mem::take(&mut ir.blocks[0].stmts);
                let exit = body.pop().expect("return statement");
                for index in &arguments[1..3] {
                    body.push(Stmt::Assign {
                        dest: RegRef {
                            index: *index,
                            width: 64,
                        },
                        value: Expr::bin(BinOp::Add, Expr::reg(*index, 64), Expr::Const(1)),
                    });
                }
                let counter = VARIABLE_BASE + 8;
                body.push(Stmt::Assign {
                    dest: RegRef {
                        index: counter,
                        width: 64,
                    },
                    value: Expr::bin(BinOp::Add, Expr::reg(counter, 64), Expr::Const(1)),
                });
                body.push(Stmt::Brif {
                    cond: Cond::Ne,
                    lhs: Expr::reg(counter, 64),
                    rhs: Expr::Const(2),
                    target: 16,
                });
                ir.blocks = vec![
                    Block {
                        start: 0,
                        stmts: vec![Stmt::Assign {
                            dest: RegRef {
                                index: counter,
                                width: 64,
                            },
                            value: Expr::Const(0),
                        }],
                    },
                    Block {
                        start: 16,
                        stmts: body,
                    },
                    Block {
                        start: 32,
                        stmts: vec![exit],
                    },
                ];
            }
            let inputs = if global {
                vec![vec![]]
            } else {
                [(0, 1), (1, 0), (0, 0), (2, 3)]
                    .into_iter()
                    .map(|(i, j)| vec![REGION, i, j])
                    .collect()
            };
            let mut candidate = printed_candidate(ir, inputs);
            if global {
                let rejected = velk::render::render(
                    &candidate.ir,
                    &[],
                    &Default::default(),
                    &[(REGION, 16), (REGION + 64, 8)],
                );
                assert!(!rejected.contains("__builtin_memmove"), "{rejected}");
                assert!(!rejected.contains("_u64"), "{rejected}");
                candidate.code = velk::render::render(
                    &candidate.ir,
                    &[],
                    &Default::default(),
                    &[(REGION, 16), (REGION + 64, 16)],
                );
                assert!(
                    candidate.code.contains("__builtin_memmove"),
                    "{}",
                    candidate.code
                );
            } else if padded {
                assert!(
                    candidate.code.contains("__builtin_memmove"),
                    "{}",
                    candidate.code
                );
            } else {
                assert!(
                    candidate.code.contains("array[i] = array[j];"),
                    "{}",
                    candidate.code
                );
            }
            candidates.push(candidate);
        }
    }
    check_candidates("indexed-vector-records", candidates, Mode::Memory, &[]);
}

#[test]
fn printed_frame_buffer_transfers_use_one_object_extent() {
    let at = |offset: i64| Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const(offset as u64));
    let mut statements = Vec::new();
    for part in 0..4 {
        statements.push(Stmt::Store {
            addr: at(-64 + part * 8),
            value: Expr::Const(0x1234 + part as u64),
            width: 8,
        });
    }
    for part in 0..2 {
        statements.push(Stmt::Assign {
            dest: RegRef {
                index: VARIABLE_BASE + part,
                width: 64,
            },
            value: Expr::Load {
                addr: Box::new(at(-64 + i64::from(part) * 8)),
                width: 8,
                signed: false,
            },
        });
    }
    for part in 0..2 {
        statements.push(Stmt::Store {
            addr: at(-56 + i64::from(part) * 8),
            value: Expr::reg(VARIABLE_BASE + part, 64),
            width: 8,
        });
    }
    statements.push(Stmt::Ret {
        value: Expr::Load {
            addr: Box::new(at(-48)),
            width: 8,
            signed: false,
        },
    });
    let mut ir = synthetic_ir("frame_buffer_record", vec![], CType::U64, statements);
    ir.debug_locals.push(velk::ir::DebugLocal {
        name: "buffer".into(),
        ty: CType::Array(Box::new(CType::U64)),
        slot: -64,
        size: 32,
    });
    let candidate = printed_candidate(ir, vec![vec![]]);
    assert!(
        candidate.code.contains("__builtin_memmove"),
        "{}",
        candidate.code
    );
    check_candidates("frame-buffer-record", vec![candidate], Mode::Registers, &[]);
}

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
                    fields: (0..size / 8).map(|part| (part * 8, CType::U64)).collect(),
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
                candidate.code.contains("unsigned char"),
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

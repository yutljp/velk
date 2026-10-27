use super::*;
use velk::ir::{RegRef, VARIABLE_BASE};

#[test]
fn printed_partial_record_transfers_keep_members_without_extra_casts() {
    let arguments = Convention::SysV.arguments();
    let at = |parameter: usize, offset| {
        Expr::bin(
            BinOp::Add,
            Expr::reg(arguments[parameter], 64),
            Expr::Const(offset),
        )
    };
    let load = |offset| Expr::Load {
        addr: Box::new(at(1, offset)),
        width: 8,
        signed: false,
    };
    let mut ir = synthetic_ir(
        "partial_record_transfer",
        ["dst", "src"]
            .into_iter()
            .enumerate()
            .map(|(index, name)| Param {
                index: arguments[index],
                name: name.into(),
                ty: CType::pointer_to(CType::Named("struct record".into())),
            })
            .collect(),
        CType::U64,
        vec![
            Stmt::Assign {
                dest: RegRef {
                    index: VARIABLE_BASE,
                    width: 64,
                },
                value: load(16),
            },
            Stmt::Store {
                addr: at(0, 8),
                value: load(8),
                width: 8,
            },
            Stmt::Store {
                addr: at(0, 16),
                value: Expr::reg(VARIABLE_BASE, 64),
                width: 8,
            },
            Stmt::Ret {
                value: Expr::Const(0),
            },
        ],
    );
    ir.structures.push(velk::ir::Structure {
        name: "record".into(),
        fields: (0..4).map(|part| (part * 8, CType::U64)).collect(),
        size: Some(32),
        elements: arguments[..2].to_vec(),
    });
    let candidate = printed_candidate(
        ir,
        vec![
            vec![REGION, REGION + 64],
            vec![REGION, REGION],
            vec![REGION + 8, REGION],
            vec![REGION, REGION + 8],
        ],
    );
    assert!(
        !candidate.code.contains("__builtin_memmove"),
        "{}",
        candidate.code
    );
    assert!(
        candidate.code.contains("dst->f_8 = src->f_8;"),
        "{}",
        candidate.code
    );
    check_candidates(
        "partial-record-transfer",
        vec![candidate],
        Mode::Memory,
        &[],
    );
}

#[test]
fn printed_reordered_transfers_preserve_snapshots_and_word_offsets() {
    let arguments = Convention::SysV.arguments();
    let mut candidates = Vec::new();
    for words in [2usize, 3, 4] {
        let inline_part = words / 2;
        for inline in [false, true] {
            for transfer_case in 0..4 {
                let at = |parameter: usize, part: usize| {
                    Expr::bin(
                        BinOp::Add,
                        Expr::reg(arguments[parameter], 64),
                        Expr::Const(part as u64 * 8),
                    )
                };
                let load = |part| Expr::Load {
                    addr: Box::new(at(1, part)),
                    width: 8,
                    signed: false,
                };
                let mut statements = Vec::new();
                for part in (0..words).rev() {
                    if !inline || part != inline_part {
                        statements.push(Stmt::Assign {
                            dest: RegRef {
                                index: VARIABLE_BASE + part as u16,
                                width: 64,
                            },
                            value: load(part),
                        });
                    }
                }
                for position in 0..words {
                    let part = if transfer_case == 3 && inline {
                        (position + inline_part + 1) % words
                    } else {
                        (position + inline_part) % words
                    };
                    statements.push(Stmt::Store {
                        addr: at(0, if transfer_case == 1 { 0 } else { part }),
                        value: if inline && part == inline_part {
                            load(part)
                        } else {
                            Expr::reg(VARIABLE_BASE + part as u16, 64)
                        },
                        width: 8,
                    });
                }
                statements.push(Stmt::Ret {
                    value: if transfer_case == 2 {
                        Expr::reg(VARIABLE_BASE, 64)
                    } else {
                        Expr::Const(0)
                    },
                });
                let ir = synthetic_ir(
                    "reordered_transfer",
                    ["dst", "src"]
                        .into_iter()
                        .enumerate()
                        .map(|(index, name)| Param {
                            index: arguments[index],
                            name: name.into(),
                            ty: CType::pointer_to(CType::int(1, false)),
                        })
                        .collect(),
                    CType::U64,
                    statements,
                );
                let candidate = printed_candidate(
                    ir,
                    [(0, 64), (64, 0), (0, 0), (1, 0), (0, 1), (8, 0), (0, 8)]
                        .into_iter()
                        .map(|(dst, src)| vec![REGION + dst, REGION + src])
                        .collect(),
                );
                assert_eq!(
                    candidate
                        .code
                        .contains(&format!("__builtin_memmove(dst, src, {});", words * 8)),
                    transfer_case == 0 || (transfer_case == 3 && !inline),
                    "{}",
                    candidate.code,
                );
                if words == 4 && inline && transfer_case == 0 {
                    assert_eq!(
                        common::check_expected(
                            &common::root().join("tests/golden/reordered_transfer.txt"),
                            &candidate.code,
                        ),
                        None,
                    );
                }
                candidates.push(candidate);
            }
        }
    }
    check_candidates("reordered-transfers", candidates, Mode::Memory, &[]);
}

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
        for (extra_read, typed, interleaved, separated, integer) in [
            (false, false, false, false, false),
            (true, false, false, false, false),
            (false, true, false, false, false),
            (false, false, true, false, false),
            (false, false, false, true, false),
            (false, false, false, false, true),
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
                &format!(
                    "record_copy_{size}_{extra_read}_{typed}_{interleaved}_{separated}_{integer}"
                ),
                arguments[..2]
                    .iter()
                    .enumerate()
                    .map(|(part, index)| Param {
                        index: *index,
                        name: ["dst", "src"][part].into(),
                        ty: if integer {
                            CType::U64
                        } else {
                            CType::pointer_to(if typed {
                                CType::Named(format!("struct record_{size}"))
                            } else {
                                CType::int(1, false)
                            })
                        },
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
            if !extra_read && !typed && !interleaved && !separated {
                let arguments = if integer {
                    "__builtin_memmove((void *)(dst), (void *)(src),"
                } else {
                    "__builtin_memmove(dst, src,"
                };
                assert!(candidate.code.contains(arguments), "{}", candidate.code);
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
        candidate.code.contains("uint64_t buffer[0x4]")
            && !candidate.code.contains("local_")
            && !candidate.code.contains("*(uint64_t *)"),
        "{}",
        candidate.code
    );
    check_candidates("frame-buffer-record", vec![candidate], Mode::Registers, &[]);
}

#[test]
fn raw_memory_calls_preserve_bytes_past_a_string_terminator() {
    let ir = synthetic_ir(
        "copy_raw_bytes",
        vec![Param {
            index: 7,
            name: "out".into(),
            ty: CType::pointer_to(CType::int(1, false)),
        }],
        CType::U64,
        vec![
            Stmt::Call {
                abi: None,
                kind: velk::ir::CallKind::Invoke,
                target: Some(0x1000),
                through: None,
                convention: Convention::SysV,
                args: Some(vec![Expr::reg(7, 64), Expr::Const(0x2000), Expr::Const(32)]),
                floats_named: false,
                outputs: vec![],
                clobbers: Some(Default::default()),
                via: None,
            },
            Stmt::Ret {
                value: Expr::Const(7),
            },
        ],
    );
    let references = [velk::analysis::refs::Reference {
        guid: None,
        addr: 0x2000,
        section: ".rodata".into(),
        text: Some("ABC".into()),
        pointer: None,
    }];
    let symbols = velk::render::Symbols {
        functions: [(0x1000, "memcpy".into())].into(),
        ..Default::default()
    };
    let code = velk::render::render(&ir, &references, &symbols, &[]);
    assert!(!code.contains("(const void *)\"ABC\""), "{code}");
    assert!(code.contains("0x2000"), "{code}");
    let code = code.replace("0x2000", "(uintptr_t)bytes");
    let code = format!(
        "#include <string.h>\nstatic unsigned char bytes[32] = {{65,66,67,0,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118}};\n{code}"
    );
    syntax::run_printed(
        &code,
        "",
        "unsigned char out[32] = {0}; if (copy_raw_bytes(out) != 7 || memcmp(out, bytes, sizeof out)) return 1;",
    );
}

#[test]
fn printed_repeated_byte_stores_fill_only_the_written_range() {
    let mut candidates = Vec::new();
    for byte in [0u64, 0x5a, 0xff] {
        for changed in 0..3 {
            let mut offset = 0u64;
            let mut statements = Vec::new();
            for (part, width) in [8u8, 4, 2, 1].into_iter().enumerate() {
                let value = if changed == 1 && part == 1 {
                    byte ^ 1
                } else {
                    byte
                };
                statements.push(Stmt::Store {
                    addr: Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(offset)),
                    value: Expr::Const(value * (u64::MAX / 255)),
                    width,
                });
                offset += u64::from(width) + u64::from(changed == 2);
            }
            statements.push(Stmt::Ret {
                value: Expr::Const(0),
            });
            let ir = synthetic_ir(
                "repeated_byte_stores",
                vec![Param {
                    index: 7,
                    name: "dst".into(),
                    ty: CType::pointer_to(CType::int(1, false)),
                }],
                CType::U64,
                statements,
            );
            let candidate = printed_candidate(ir, vec![vec![REGION], vec![REGION + 1]]);
            assert_eq!(
                candidate
                    .code
                    .contains(&format!("__builtin_memset(dst, 0x{byte:x}, 15);")),
                changed == 0,
                "{}",
                candidate.code
            );
            if byte == 0x5a && changed == 0 {
                assert_eq!(
                    common::check_expected(
                        &common::root().join("tests/golden/repeated_byte_stores.txt"),
                        &candidate.code
                    ),
                    None
                );
            }
            candidates.push(candidate);
        }
    }
    check_candidates("repeated-byte-stores", candidates, Mode::Memory, &[]);
}

#[test]
fn printed_byte_fills_keep_named_global_objects_separate() {
    for overlapping in [false, true] {
        let mut ir = synthetic_ir(
            "clear_objects",
            vec![],
            CType::U64,
            vec![
                Stmt::Store {
                    addr: Expr::Const(0x2000),
                    value: Expr::Const(0),
                    width: 1,
                },
                Stmt::Store {
                    addr: Expr::Const(0x2001),
                    value: Expr::Const(0),
                    width: 1,
                },
                Stmt::Ret {
                    value: Expr::Const(0),
                },
            ],
        );
        ir.debug_globals = vec![
            (0x2000, CType::int(1, false), 1),
            (0x2001, CType::int(1, false), 1),
        ];
        if overlapping {
            ir.debug_globals
                .push((0x1fff, CType::Array(Box::new(CType::int(1, false))), 4));
        }
        let mut symbols = velk::render::Symbols {
            data: [(0x2000, "left".into()), (0x2001, "right".into())].into(),
            ..Default::default()
        };
        if overlapping {
            symbols.data.insert(0x1fff, "container".into());
        }
        let code = velk::render::render(&ir, &[], &symbols, &[(0x2000, 2)]);
        assert!(!code.contains("__builtin_memset"), "{code}");
        assert!(code.contains("left = 0;"), "{code}");
        assert!(code.contains("right = 0;"), "{code}");
        syntax::run_printed(
            &code,
            "uint8_t left = 1; uint8_t right = 2;",
            "clear_objects(); return left || right;",
        );
    }
}

#[test]
fn printed_global_fills_reuse_the_stored_words_address() {
    let ir = synthetic_ir(
        "clear_words",
        vec![],
        CType::U64,
        vec![
            Stmt::Store {
                addr: Expr::Const(REGION),
                value: Expr::Const(0),
                width: 8,
            },
            Stmt::Store {
                addr: Expr::Const(REGION + 8),
                value: Expr::Const(0),
                width: 8,
            },
            Stmt::Ret {
                value: Expr::Load {
                    addr: Box::new(Expr::Const(REGION)),
                    width: 8,
                    signed: false,
                },
            },
        ],
    );
    let symbols = velk::render::Symbols {
        data: [(REGION, "counter".into())].into(),
        ..Default::default()
    };
    let mut candidate = printed_candidate(ir.clone(), vec![vec![]]);
    candidate.code = velk::render::render(&ir, &[], &symbols, &[(REGION, 16)]);
    assert!(
        candidate
            .code
            .contains("__builtin_memset(counter, 0x0, 16);"),
        "{}",
        candidate.code
    );
    assert_eq!(
        candidate.code.matches("extern uint64_t counter[];").count(),
        1,
        "{}",
        candidate.code
    );
    assert!(!candidate.code.contains("counter_u8"), "{}", candidate.code);
    check_candidates("global-fill-address", vec![candidate], Mode::Memory, &[]);
}

#[test]
fn printed_global_copies_read_the_named_objects() {
    let mut ir = synthetic_ir(
        "copy_objects",
        vec![Param {
            index: 7,
            name: "dst".into(),
            ty: CType::pointer_to(CType::U64),
        }],
        CType::U64,
        vec![
            Stmt::Assign {
                dest: RegRef {
                    index: VARIABLE_BASE,
                    width: 64,
                },
                value: Expr::Load {
                    addr: Box::new(Expr::Const(0x2000)),
                    width: 8,
                    signed: false,
                },
            },
            Stmt::Assign {
                dest: RegRef {
                    index: VARIABLE_BASE + 1,
                    width: 64,
                },
                value: Expr::Load {
                    addr: Box::new(Expr::Const(0x2008)),
                    width: 8,
                    signed: false,
                },
            },
            Stmt::Store {
                addr: Expr::reg(7, 64),
                value: Expr::reg(VARIABLE_BASE, 64),
                width: 8,
            },
            Stmt::Store {
                addr: Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(8)),
                value: Expr::reg(VARIABLE_BASE + 1, 64),
                width: 8,
            },
            Stmt::Ret {
                value: Expr::Const(0),
            },
        ],
    );
    ir.debug_globals = vec![(0x2000, CType::U64, 8), (0x2008, CType::U64, 8)];
    let symbols = velk::render::Symbols {
        data: [(0x2000, "first".into()), (0x2008, "second".into())].into(),
        ..Default::default()
    };
    let code = velk::render::render(&ir, &[], &symbols, &[(0x2000, 16)]);
    assert!(!code.contains("__builtin_mem"), "{code}");
    assert!(code.contains("= first;"), "{code}");
    assert!(code.contains("= second;"), "{code}");
    syntax::run_printed(
        &code,
        "uint64_t first = UINT64_C(0x8000000000000001); uint64_t second = UINT64_MAX;",
        "uint64_t dst[2] = {0}; copy_objects(dst); return dst[0] != first || dst[1] != second;",
    );
}

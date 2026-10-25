use super::*;
use velk::ir::{RegRef, VARIABLE_BASE};

fn slot(offset: i64) -> Expr {
    Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const(offset as u64))
}

fn load(offset: i64) -> Expr {
    Expr::Load {
        addr: Box::new(slot(offset)),
        width: 4,
        signed: false,
    }
}

fn store(offset: i64, value: u64, width: u8) -> Stmt {
    Stmt::Store {
        addr: slot(offset),
        value: Expr::Const(value),
        width,
    }
}

#[test]
fn unused_frame_address_temporaries_disappear_after_rebasing() {
    let temporary = velk::ir::TEMP_BASE;
    let address = Expr::reg(temporary, 64);
    let ir = synthetic_ir(
        "frame_address_temporary",
        vec![Param {
            index: 7,
            name: "value".into(),
            ty: CType::U64,
        }],
        CType::U64,
        vec![
            Stmt::Assign {
                dest: RegRef {
                    index: temporary,
                    width: 64,
                },
                value: slot(-16),
            },
            Stmt::Store {
                addr: address.clone(),
                value: Expr::reg(7, 64),
                width: 8,
            },
            Stmt::Store {
                addr: Expr::bin(BinOp::Add, address.clone(), Expr::Const(7)),
                value: Expr::Const(0x81),
                width: 1,
            },
            Stmt::Ret {
                value: Expr::Load {
                    addr: Box::new(address),
                    width: 8,
                    signed: false,
                },
            },
        ],
    );
    let candidate = printed_candidate(
        ir,
        [0, 1, u64::MAX, 0x1234_5678_9abc_def0]
            .into_iter()
            .map(|value| vec![value])
            .collect(),
    );
    assert!(!candidate.code.contains("t1"), "{}", candidate.code);
    assert!(candidate.code.contains("local_0"), "{}", candidate.code);
    check_candidates(
        "frame-address-temporary",
        vec![candidate],
        Mode::Registers,
        &[],
    );
}

#[test]
fn printed_stack_arrays_preserve_call_and_indexed_writes() {
    let mut candidates = Vec::new();
    for (name, size, copy) in [
        ("frame_clear150", 150, false),
        ("frame_clear100", 100, false),
        ("frame_clear4", 4, false),
        ("frame_copy", 56, true),
        ("frame_copy_unknown", 56, true),
    ] {
        let mut statements = vec![store(-8, 0x12345678, 4)];
        if copy {
            for offset in (0..size).step_by(4) {
                statements.push(store(-256 + offset, 0x13579bdf, 4));
            }
        }
        let destination = if copy { -184 } else { -192 };
        let prefix = statements.clone();
        if copy {
            statements.push(Stmt::Assign {
                dest: velk::ir::RegRef {
                    index: velk::ir::VARIABLE_BASE,
                    width: 64,
                },
                value: slot(-192),
            });
        }
        statements.push(Stmt::Call {
            abi: None,
            kind: velk::ir::CallKind::Invoke,
            target: Some(0x1000),
            through: None,
            convention: Convention::SysV,
            args: Some(vec![
                if name.ends_with("unknown") {
                    Expr::bin(
                        BinOp::Add,
                        Expr::reg(velk::ir::VARIABLE_BASE, 64),
                        Expr::Const(8),
                    )
                } else if copy {
                    slot(destination)
                } else {
                    slot(-192)
                },
                if copy { slot(-256) } else { Expr::Const(0x5a) },
                Expr::Const(size as u64),
            ]),
            floats_named: false,
            outputs: Vec::new(),
            clobbers: Some(Default::default()),
            via: None,
        });
        statements.push(Stmt::Ret {
            value: Expr::bin(BinOp::Xor, load(destination + size - 4), load(-8)),
        });
        let mut ir = synthetic_ir(name, vec![], CType::U32, statements);
        if copy {
            let call_index = ir.blocks[0].stmts.len() - 2;
            let rest = ir.blocks[0].stmts.split_off(call_index);
            ir.blocks[0].stmts.push(Stmt::Br { target: Some(16) });
            ir.blocks.push(Block {
                start: 16,
                stmts: rest,
            });
        }
        let mut symbols = velk::render::Symbols::default();
        symbols
            .functions
            .insert(0x1000, if copy { "memcpy" } else { "memset" }.into());
        let unknown = name.ends_with("unknown");
        if unknown {
            symbols.functions.clear();
        }
        let code = velk::render::render(&ir, &[], &symbols, &[]);
        let ret = ir.blocks.last().unwrap().stmts.last().unwrap().clone();
        let extent = if unknown {
            256
        } else {
            size + if copy { 8 } else { 0 }
        };
        assert!(
            code.contains(&format!("[0x{extent:x}]"))
                || code.contains("struct __attribute__((packed))"),
            "{code}"
        );
        if !unknown {
            assert!(code.contains("uint32_t local_0;"), "{code}");
        }
        ir.blocks.truncate(1);
        ir.blocks[0].stmts = prefix;
        for offset in 0..size {
            let byte = if copy {
                (0x13579bdfu64 >> ((offset % 4) * 8)) & 0xff
            } else {
                0x5a
            };
            ir.blocks[0]
                .stmts
                .push(store(destination + offset, byte, 1));
        }
        ir.blocks[0].stmts.push(ret);
        let mut candidate = printed_candidate(ir, vec![vec![]]);
        candidate.code = format!(
            "#include <string.h>\n{}\n{code}",
            if unknown {
                "static void sub_1000(void *destination, const void *source, size_t size) { memcpy(destination, source, size); }"
            } else {
                ""
            }
        );
        candidates.push(candidate);
    }
    let index = Convention::SysV.arguments()[0];
    let address = Expr::bin(
        BinOp::Add,
        slot(-160),
        Expr::bin(BinOp::Shl, Expr::reg(index, 64), Expr::Const(2)),
    );
    let ir = synthetic_ir(
        "frame_index",
        vec![Param {
            index,
            name: "index".into(),
            ty: CType::U64,
        }],
        CType::U32,
        vec![
            store(-8, 0x12345678, 4),
            Stmt::Store {
                addr: address.clone(),
                value: Expr::Const(0x3456789a),
                width: 4,
            },
            Stmt::Ret {
                value: Expr::bin(
                    BinOp::Xor,
                    Expr::Load {
                        addr: Box::new(address),
                        width: 4,
                        signed: false,
                    },
                    load(-8),
                ),
            },
        ],
    );
    let candidate = printed_candidate(ir, (0..38).map(|index| vec![index]).collect());
    assert!(candidate.code.contains("[0xa0]"), "{}", candidate.code);
    candidates.push(candidate);
    // The two stores overlap without either access containing the other.
    let ir = synthetic_ir(
        "frame_overlapping_stores",
        vec![],
        CType::U32,
        vec![
            store(-8, 0x12345678, 4),
            store(-32, 0x1122334455667788, 8),
            store(-28, 0xaabbccddeeff0011, 8),
            Stmt::Ret {
                value: Expr::bin(BinOp::Xor, load(-28), load(-8)),
            },
        ],
    );
    let candidate = printed_candidate(ir, vec![vec![]]);
    assert!(
        candidate.code.contains("local_1.f_0.s2.f_4 = "),
        "{}",
        candidate.code
    );
    assert!(
        candidate.code.contains("uint32_t local_0;"),
        "{}",
        candidate.code
    );
    assert!(!candidate.code.contains("local_2"), "{}", candidate.code);
    candidates.push(candidate);
    check_candidates("stack-arrays", candidates, Mode::Registers, &[]);
}

#[test]
fn printed_stack_struct_shares_overlapping_accesses_in_a_union() {
    let mut ir = synthetic_ir(
        "frame_mixed_fields",
        vec![],
        CType::U32,
        vec![
            Stmt::Call {
                abi: None,
                kind: velk::ir::CallKind::Invoke,
                target: Some(0x1000),
                through: None,
                convention: Convention::SysV,
                args: Some(vec![slot(-64), Expr::Const(0x5a), Expr::Const(32)]),
                floats_named: false,
                outputs: Vec::new(),
                clobbers: Some(Default::default()),
                via: None,
            },
            store(-64, 0x123456789abcdef0, 8),
            store(-63, 0xaa, 1),
            store(-48, 0x13579bdf, 4),
            Stmt::Ret {
                value: Expr::bin(BinOp::Xor, load(-64), load(-48)),
            },
        ],
    );
    let mut symbols = velk::render::Symbols::default();
    symbols.functions.insert(0x1000, "memset".into());
    let code = velk::render::render(&ir, &[], &symbols, &[]);
    assert!(code.contains("uint32_t f_10;"), "{code}");
    assert!(code.contains("local_0.f_10 = 0x13579bdf;"), "{code}");
    assert!(code.contains("local_0.f_0.as_u8[1] = 170;"), "{code}");
    assert!(!code.contains("(uint8_t *)&local_0"), "{code}");
    ir.blocks[0].stmts.remove(0);
    for offset in (0..32).rev() {
        ir.blocks[0].stmts.insert(0, store(-64 + offset, 0x5a, 1));
    }
    let mut candidate = printed_candidate(ir, vec![vec![]]);
    candidate.code = format!("#include <string.h>\n{code}");
    check_candidates("stack-struct-fields", vec![candidate], Mode::Registers, &[]);
}

#[test]
fn printed_register_save_top_keeps_the_adjacent_scalar_separate() {
    let address =
        |offset: i64| Expr::bin(BinOp::Add, Expr::reg(31, 64), Expr::Const(offset as u64));
    let mut saves = Vec::new();
    for (position, register) in Convention::Aapcs64.arguments().iter().enumerate().skip(1) {
        saves.push(Stmt::Store {
            addr: address(-128 + position as i64 * 8),
            value: Expr::reg(*register, 64),
            width: 8,
        });
    }
    for (position, register) in Convention::Aapcs64.float_arguments().iter().enumerate() {
        for half in 0..2 {
            saves.push(Stmt::Store {
                addr: address(-256 + position as i64 * 16 + i64::from(half) * 8),
                value: Expr::reg(register + half, 64),
                width: 8,
            });
        }
    }
    let prefix = saves.len();
    saves.extend([
        Stmt::Call {
            abi: None,
            kind: velk::ir::CallKind::Invoke,
            target: Some(0x1000),
            through: None,
            convention: Convention::Aapcs64,
            args: Some(vec![address(-128), Expr::Const(0x5a), Expr::Const(64)]),
            floats_named: false,
            outputs: Vec::new(),
            clobbers: Some(Default::default()),
            via: None,
        },
        Stmt::Store {
            addr: address(-64),
            value: Expr::Const(0x12345678),
            width: 4,
        },
        Stmt::Store {
            addr: address(-60),
            value: Expr::Const(0),
            width: 4,
        },
        Stmt::Assign {
            dest: RegRef {
                index: VARIABLE_BASE,
                width: 64,
            },
            value: address(-64),
        },
        Stmt::Ret {
            value: Expr::bin(
                BinOp::Xor,
                Expr::Load {
                    addr: Box::new(Expr::bin(
                        BinOp::Sub,
                        Expr::reg(VARIABLE_BASE, 64),
                        Expr::Const(4),
                    )),
                    width: 4,
                    signed: false,
                },
                Expr::Load {
                    addr: Box::new(address(-64)),
                    width: 4,
                    signed: false,
                },
            ),
        },
    ]);
    let mut ir = synthetic_ir(
        "frame_register_top",
        vec![Param {
            index: 0,
            name: "named".into(),
            ty: CType::U64,
        }],
        CType::U32,
        saves,
    );
    ir.isa = Isa::AArch64;
    ir.convention = Convention::Aapcs64;
    ir.variadic = true;
    let mut symbols = velk::render::Symbols::default();
    symbols.functions.insert(0x1000, "memset".into());
    let code = velk::render::render(&ir, &[], &symbols, &[]);
    assert!(code.contains("[0x40]"), "{code}");
    assert!(code.contains("uint32_t local_1;"), "{code}");
    assert!(code.contains("local_0 + 0x40"), "{code}");
    assert!(!code.contains("&local_1"), "{code}");
    ir.blocks[0].stmts.drain(..prefix + 1);
    for offset in (0..64).rev() {
        ir.blocks[0].stmts.insert(
            0,
            Stmt::Store {
                addr: address(-128 + offset),
                value: Expr::Const(0x5a),
                width: 1,
            },
        );
    }
    let mut candidate = printed_candidate(ir, vec![vec![0]]);
    candidate.code = format!("#include <string.h>\n{code}");
    check_candidates("stack-register-top", vec![candidate], Mode::Registers, &[]);
}

#[test]
fn printed_stack_unions_read_each_width_as_the_machine_does() {
    let read = |offset: i64, width: u8, signed: bool| Expr::Load {
        addr: Box::new(slot(offset)),
        width,
        signed,
    };
    let value = [
        read(-60, 4, true),
        read(-60, 2, true),
        read(-57, 1, true),
        read(-62, 2, false),
        read(-45, 8, false),
        read(-48, 4, false),
    ]
    .into_iter()
    .fold(read(-64, 8, false), |sum, term| {
        Expr::bin(BinOp::Xor, sum, term)
    });
    let mut ir = synthetic_ir(
        "frame_views",
        vec![Param {
            index: 7,
            name: "x".into(),
            ty: CType::U64,
        }],
        CType::U64,
        vec![
            Stmt::Call {
                abi: None,
                kind: velk::ir::CallKind::Invoke,
                target: Some(0x1000),
                through: None,
                convention: Convention::SysV,
                args: Some(vec![slot(-64), Expr::Const(0x5a), Expr::Const(32)]),
                floats_named: false,
                outputs: Vec::new(),
                clobbers: Some(Default::default()),
                via: None,
            },
            Stmt::Store {
                addr: slot(-64),
                value: Expr::reg(7, 64),
                width: 8,
            },
            store(-60, 0x8001, 2),
            store(-57, 0x80, 1),
            // Eight bytes across two cells overlap the four read below
            // them: each is a field of one layer of a union.
            Stmt::Store {
                addr: slot(-45),
                value: Expr::reg(7, 64),
                width: 8,
            },
            Stmt::Ret { value },
        ],
    );
    let mut symbols = velk::render::Symbols::default();
    symbols.functions.insert(0x1000, "memset".into());
    let code = velk::render::render(&ir, &[], &symbols, &[]);
    assert!(code.contains("union {"), "{code}");
    assert!(code.contains("local_0.f_0.as_i32[1]"), "{code}");
    assert!(!code.contains("*(int16_t *)"), "{code}");
    assert!(code.contains("local_0.f_10.s1.f_13"), "{code}");
    ir.blocks[0].stmts.remove(0);
    for offset in (0..32).rev() {
        ir.blocks[0].stmts.insert(0, store(-64 + offset, 0x5a, 1));
    }
    let inputs = [
        0,
        1,
        0x8000_0000,
        0xffff_ffff_ffff_ffff,
        0x0123_4567_89ab_cdef,
    ]
    .into_iter()
    .map(|value| vec![value])
    .collect();
    let mut candidate = printed_candidate(ir, inputs);
    candidate.code = format!("#include <string.h>\n{code}");
    check_candidates("stack-unions", vec![candidate], Mode::Registers, &[]);
}

#[test]
fn printed_stack_index_held_in_a_pointer_variable_adds_as_an_integer() {
    let index = Expr::reg(7, 64);
    let ir = synthetic_ir(
        "frame_pointer_index",
        vec![Param {
            index: 7,
            name: "x".into(),
            ty: CType::pointer_to(CType::int(8, false)),
        }],
        CType::U64,
        vec![
            Stmt::Call {
                abi: None,
                kind: velk::ir::CallKind::Invoke,
                target: Some(0x1000),
                through: None,
                convention: Convention::SysV,
                args: Some(vec![slot(-64), Expr::Const(0x5a), Expr::Const(32)]),
                floats_named: false,
                outputs: Vec::new(),
                clobbers: Some(Default::default()),
                via: None,
            },
            Stmt::Ret {
                value: Expr::Load {
                    addr: Box::new(Expr::bin(BinOp::Add, slot(-58), index)),
                    width: 1,
                    signed: false,
                },
            },
        ],
    );
    let mut symbols = velk::render::Symbols::default();
    symbols.functions.insert(0x1000, "memset".into());
    let code = velk::render::render(&ir, &[], &symbols, &[]);
    assert!(
        code.contains("(uintptr_t)(local_0 + 0x6) + (uintptr_t)x"),
        "{code}"
    );
}

#[test]
fn printed_stack_records_indexed_through_each_field_are_one_array() {
    // Two fields of a sixteen-byte record written at an index, and the
    // first read back through the second's address and another index.
    let scaled = Expr::bin(BinOp::Mul, Expr::reg(7, 64), Expr::Const(16));
    let at = |offset: i64, index: Expr| Expr::bin(BinOp::Add, slot(offset), index);
    let mut ir = synthetic_ir(
        "frame_records",
        vec![Param {
            index: 7,
            name: "x".into(),
            ty: CType::U64,
        }],
        CType::U64,
        vec![
            Stmt::Store {
                addr: at(-64, scaled.clone()),
                value: Expr::Const(0x1111),
                width: 8,
            },
            Stmt::Store {
                addr: at(-56, scaled.clone()),
                value: Expr::Const(0x2222),
                width: 8,
            },
            Stmt::Assign {
                dest: RegRef {
                    index: 6,
                    width: 64,
                },
                value: Expr::bin(BinOp::Sub, scaled, Expr::Const(8)),
            },
            Stmt::Ret {
                value: Expr::Load {
                    addr: Box::new(at(-56, Expr::reg(6, 64))),
                    width: 8,
                    signed: false,
                },
            },
        ],
    );
    let body = std::mem::take(&mut ir.blocks[0].stmts);
    ir.blocks[0].stmts.push(Stmt::Brif {
        cond: Cond::Hi,
        lhs: Expr::reg(7, 64),
        rhs: Expr::Const(3),
        target: 2,
    });
    ir.blocks.push(Block {
        start: 1,
        stmts: body,
    });
    ir.blocks.push(Block {
        start: 2,
        stmts: vec![Stmt::Ret {
            value: Expr::Const(0),
        }],
    });
    let candidate = printed_candidate(
        ir,
        [0, 1, 2, 3, 4, u64::MAX]
            .into_iter()
            .map(|value| vec![value])
            .collect(),
    );
    assert!(
        !candidate.code.contains("*(uint64_t *)((uint8_t *)"),
        "{}",
        candidate.code
    );
    assert_eq!(
        common::check_expected(
            &common::root().join("tests/golden/indexed_frame_access.txt"),
            &candidate.code,
        ),
        None,
    );
    check_candidates("stack-records", vec![candidate], Mode::Registers, &[]);
}

#[test]
fn printed_stack_fields_of_a_region_read_at_an_index_see_its_writes() {
    let read = |offset: i64, width: u8| Expr::Load {
        addr: Box::new(slot(offset)),
        width,
        signed: false,
    };
    let value = Expr::bin(
        BinOp::Xor,
        Expr::bin(BinOp::Xor, read(-64, 8), read(-56, 4)),
        read(-48, 8),
    );
    let mut ir = synthetic_ir(
        "frame_indexed_fields",
        vec![Param {
            index: 7,
            name: "x".into(),
            ty: CType::U64,
        }],
        CType::U64,
        vec![
            Stmt::Call {
                abi: None,
                kind: velk::ir::CallKind::Invoke,
                target: Some(0x1000),
                through: None,
                convention: Convention::SysV,
                args: Some(vec![slot(-64), Expr::Const(0), Expr::Const(32)]),
                floats_named: false,
                outputs: Vec::new(),
                clobbers: Some(Default::default()),
                via: None,
            },
            store(-64, 0x1111_2222_3333_4444, 8),
            store(-56, 0x5555_6666, 4),
            store(-48, 0x7777_8888_9999_aaaa, 8),
            Stmt::Store {
                addr: Expr::bin(
                    BinOp::Add,
                    slot(-64),
                    Expr::bin(BinOp::Mul, Expr::reg(7, 64), Expr::Const(8)),
                ),
                value: Expr::reg(7, 64),
                width: 8,
            },
            Stmt::Ret { value },
        ],
    );
    let mut symbols = velk::render::Symbols::default();
    symbols.functions.insert(0x1000, "memset".into());
    let code = velk::render::render(&ir, &[], &symbols, &[]);
    assert!(code.contains("local_0.f_10"), "{code}");
    assert!(code.contains("(uintptr_t)((uint8_t *)&local_0)"), "{code}");
    ir.blocks[0].stmts.remove(0);
    for offset in (0..32).rev().step_by(8) {
        ir.blocks[0].stmts.insert(0, store(-64 + offset, 0, 8));
    }
    let mut candidate = printed_candidate(ir, (0..4).map(|value| vec![value]).collect());
    candidate.code = format!("#include <string.h>\n{code}");
    check_candidates(
        "stack-indexed-fields",
        vec![candidate],
        Mode::Registers,
        &[],
    );
}

#[test]
fn printed_stack_buffer_read_below_its_index_base_reaches_the_bytes_there() {
    // A byte stored at a fixed slot and read back through a negative index
    // from the slot above, as digits written backwards are.
    let ir = synthetic_ir(
        "frame_backwards",
        vec![Param {
            index: 7,
            name: "x".into(),
            ty: CType::U64,
        }],
        CType::U64,
        vec![
            store(-12, 0x41, 1),
            store(-11, 0x42, 1),
            store(-10, 0x43, 1),
            store(-9, 0x44, 1),
            Stmt::Ret {
                value: Expr::Load {
                    addr: Box::new(Expr::bin(
                        BinOp::Add,
                        slot(-9),
                        Expr::bin(BinOp::Sub, Expr::Const(0), Expr::reg(7, 64)),
                    )),
                    width: 1,
                    signed: false,
                },
            },
        ],
    );
    let candidate = printed_candidate(ir, (0..4).map(|value| vec![value]).collect());
    check_candidates("stack-backwards", vec![candidate], Mode::Registers, &[]);
}

#[test]
fn printed_frame_indices_keep_local_storage_when_also_used_in_global_addresses() {
    let index = VARIABLE_BASE;
    let frame = Expr::bin(BinOp::Add, slot(-124), Expr::reg(index, 64));
    let mut ir = synthetic_ir(
        "frame_and_global_index",
        vec![],
        CType::U32,
        vec![
            store(-136, 0, 8),
            store(-124, 0x1234, 2),
            store(-122, 0x56, 1),
            Stmt::Assign {
                dest: RegRef { index, width: 64 },
                value: Expr::Const(2),
            },
            Stmt::Br { target: Some(16) },
        ],
    );
    ir.blocks.push(Block {
        start: 16,
        stmts: vec![
            Stmt::Store {
                addr: Expr::bin(BinOp::Add, Expr::Const(REGION + 256), Expr::reg(index, 64)),
                value: Expr::Load {
                    addr: Box::new(frame),
                    width: 1,
                    signed: false,
                },
                width: 1,
            },
            Stmt::Assign {
                dest: RegRef { index, width: 64 },
                value: Expr::bin(BinOp::Sub, Expr::reg(index, 64), Expr::Const(1)),
            },
            Stmt::Brif {
                cond: Cond::Ne,
                lhs: Expr::reg(index, 64),
                rhs: Expr::Const(u64::MAX),
                target: 16,
            },
        ],
    });
    ir.blocks.push(Block {
        start: 32,
        stmts: vec![Stmt::Ret {
            value: Expr::Const(7),
        }],
    });
    let candidate = printed_candidate(ir, vec![vec![]]);
    assert!(
        !candidate.code.contains("velk_entry_stack_pointer"),
        "{}",
        candidate.code
    );
    check_candidates("frame-and-global-index", vec![candidate], Mode::Memory, &[]);
}

#[test]
fn printed_indexed_frame_bases_share_storage_across_adjacent_buffers() {
    let load = |base, offset| Expr::Load {
        addr: Box::new(Expr::bin(
            BinOp::Add,
            Expr::bin(
                BinOp::Add,
                Expr::reg(base, 64),
                Expr::bin(BinOp::Mul, Expr::reg(7, 64), Expr::Const(8)),
            ),
            Expr::Const(offset),
        )),
        width: 8,
        signed: false,
    };
    let mut statements: Vec<_> = (0..8)
        .map(|i| store(-64 + i * 8, (i + 1) as u64, 8))
        .collect();
    for (index, offset) in [(VARIABLE_BASE, -64), (VARIABLE_BASE + 1, -32)] {
        statements.push(Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value: slot(offset),
        });
    }
    statements.push(Stmt::Ret {
        value: Expr::bin(
            BinOp::Xor,
            load(VARIABLE_BASE, 48),
            load(VARIABLE_BASE + 1, 0),
        ),
    });
    let ir = synthetic_ir(
        "adjacent_indexed_buffers",
        vec![Param {
            index: 7,
            name: "index".into(),
            ty: CType::U64,
        }],
        CType::U64,
        statements,
    );
    let candidate = printed_candidate(ir, vec![vec![0], vec![1]]);
    check_candidates(
        "adjacent-indexed-buffers",
        vec![candidate],
        Mode::Registers,
        &[],
    );
}

#[test]
fn printed_wrapping_frame_indices_add_as_integer_addresses() {
    let address = Expr::bin(
        BinOp::Add,
        Expr::reg(VARIABLE_BASE, 64),
        Expr::bin(BinOp::Shl, Expr::reg(7, 64), Expr::Const(2)),
    );
    let ir = synthetic_ir(
        "wrapping_frame_index",
        vec![Param {
            index: 7,
            name: "index".into(),
            ty: CType::I64,
        }],
        CType::U32,
        vec![
            store(-64, 0, 8),
            store(-56, 0, 8),
            Stmt::Assign {
                dest: RegRef {
                    index: VARIABLE_BASE,
                    width: 64,
                },
                value: slot(-60),
            },
            Stmt::Store {
                addr: address,
                value: Expr::Const(1),
                width: 4,
            },
            Stmt::Ret { value: load(-64) },
        ],
    );
    let candidate = printed_candidate(ir, vec![vec![u64::MAX], vec![0], vec![1]]);
    check_candidates(
        "wrapping-frame-index",
        vec![candidate],
        Mode::Registers,
        &[],
    );
}

#[test]
fn printed_stack_indexes_include_subtracted_terms() {
    let index = Expr::reg(7, 64);
    let mut statements = vec![
        store(-64, 0x0706050403020100, 8),
        store(-56, 0x0f0e0d0c0b0a0908, 8),
        store(-48, 0x1716151413121110, 8),
    ];
    statements.push(Stmt::Ret {
        value: Expr::Load {
            addr: Box::new(Expr::bin(
                BinOp::Add,
                Expr::bin(BinOp::Sub, slot(-64), index.clone()),
                Expr::bin(BinOp::Shl, index, Expr::Const(3)),
            )),
            width: 1,
            signed: false,
        },
    });
    let ir = synthetic_ir(
        "stack_stride_seven",
        vec![Param {
            index: 7,
            name: "index".into(),
            ty: CType::U64,
        }],
        CType::U32,
        statements,
    );
    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
    assert!(!code.contains("velk_entry_stack_pointer"), "{code}");
    syntax::run_printed(
        &code,
        "",
        "for(unsigned i=0;i<4;++i) if(stack_stride_seven(i)!=7*i) return 1;",
    );
}

#[test]
fn printed_stack_pointer_loops_share_backward_indexed_storage() {
    let pointer = VARIABLE_BASE;
    let count = pointer + 1;
    let mut statements: Vec<Stmt> = (-64..=-24).step_by(8).map(|at| store(at, 0, 8)).collect();
    statements.extend([
        Stmt::Assign {
            dest: RegRef {
                index: pointer,
                width: 64,
            },
            value: slot(-24),
        },
        Stmt::Assign {
            dest: RegRef {
                index: count,
                width: 64,
            },
            value: Expr::Const(0),
        },
        Stmt::Br { target: Some(16) },
    ]);
    let mut ir = synthetic_ir("stack_backward_rows", vec![], CType::U32, statements);
    let mut body = Vec::new();
    for offset in [0i64, -16, -32] {
        body.push(Stmt::Store {
            addr: Expr::bin(
                BinOp::Add,
                Expr::reg(pointer, 64),
                Expr::Const(offset as u64),
            ),
            value: Expr::Const(0x1234),
            width: 2,
        });
    }
    body.extend([
        Stmt::Assign {
            dest: RegRef {
                index: pointer,
                width: 64,
            },
            value: Expr::bin(BinOp::Add, Expr::reg(pointer, 64), Expr::Const(2)),
        },
        Stmt::Assign {
            dest: RegRef {
                index: count,
                width: 64,
            },
            value: Expr::bin(BinOp::Add, Expr::reg(count, 64), Expr::Const(1)),
        },
        Stmt::Brif {
            cond: Cond::Ne,
            lhs: Expr::reg(count, 64),
            rhs: Expr::Const(3),
            target: 16,
        },
    ]);
    ir.blocks.push(Block {
        start: 16,
        stmts: body,
    });
    let reads = [-56i64, -40, -24].map(|at| Expr::Load {
        addr: Box::new(slot(at)),
        width: 2,
        signed: false,
    });
    ir.blocks.push(Block {
        start: 32,
        stmts: vec![Stmt::Ret {
            value: reads
                .into_iter()
                .reduce(|a, b| Expr::bin(BinOp::Add, a, b))
                .unwrap(),
        }],
    });
    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
    syntax::run_printed(&code, "", "if(stack_backward_rows()!=3*0x1234) return 1;");
}

#[test]
fn bounded_indices_share_storage_with_mixed_width_stack_slots() {
    let scratch = scratch_dir("bounded-stack-slots");
    let assembly = scratch.join("bounded.s");
    let object = scratch.join("bounded.o");
    std::fs::write(
        &assembly,
        ".text
.globl bounded_slots
.type bounded_slots,@function
bounded_slots:
subq $64, %rsp
movl $9, 8(%rsp)
movq $3, 16(%rsp)
movq $0, 24(%rsp)
movq $0, 32(%rsp)
movl $7, %ecx
1:
movl %edi, 8(%rsp,%rcx,4)
decq %rcx
cmpq $5, %rcx
jne 1b
movzwl 16(%rsp), %eax
addl 32(%rsp), %eax
addl 36(%rsp), %eax
addq $64, %rsp
ret
.size bounded_slots, .-bounded_slots
",
    )
    .unwrap();
    let compiled = Command::new(compiler())
        .args(["--target=x86_64-unknown-linux-gnu", "-c"])
        .arg(&assembly)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{compiled:?}");
    let mut binary = Binary::open(&object).unwrap();
    let address = binary.find("bounded_slots").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    assert!(!code.contains("uint8_t local_0[0x8]"), "{code}");
    syntax::run_printed(
        &code,
        "",
        "for (uint32_t x = 0; x < 50; ++x) {
        if ((uint32_t)bounded_slots(x * 0x87654321U) != 3 + 2 * (x * 0x87654321U)) __builtin_trap();
    }",
    );
    std::fs::remove_dir_all(scratch).ok();
}

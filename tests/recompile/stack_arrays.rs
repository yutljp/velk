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
    assert!(code.contains("local_0 + 0x6 + (uintptr_t)x"), "{code}");
}

#[test]
fn printed_stack_records_indexed_through_each_field_are_one_array() {
    // Two fields of a sixteen-byte record written at an index, and the
    // first read back through the second's address and another index.
    let scaled = Expr::bin(BinOp::Mul, Expr::reg(7, 64), Expr::Const(16));
    let at = |offset: i64, index: Expr| Expr::bin(BinOp::Add, slot(offset), index);
    let ir = synthetic_ir(
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
    let candidate = printed_candidate(ir, (0..4).map(|value| vec![value]).collect());
    check_candidates("stack-records", vec![candidate], Mode::Registers, &[]);
}

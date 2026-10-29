use super::*;
use velk::ir::AtomicOp;
use velk::ir::MachineInstruction;
use velk::ir::Ordering;
use velk::ir::RegRef;
use velk::ir::VARIABLE_BASE;

#[test]
fn wrapping_locals_keep_unsigned_bits_for_every_architecture() {
    let mut candidates = Vec::new();
    let counts = [0, 1, 2, 3, 7];
    for isa in [Isa::X86_64, Isa::I386, Isa::AArch64, Isa::Arm32] {
        let bits = if velk::arch::pointer_bytes(isa) == 4 {
            32
        } else {
            64
        };
        let width = bits as u8;
        let integer = CType::int(width / 8, false);
        let values = if bits == 32 {
            [
                0,
                1,
                0x7fff_ffff,
                0x8000_0000,
                u32::MAX as u64 - 1,
                u32::MAX as u64,
            ]
        } else {
            [0, 1, 0x7fff_ffff, 0x8000_0000, u64::MAX - 1, u64::MAX]
        };
        let inputs: Vec<Vec<u64>> = values
            .iter()
            .flat_map(|value| counts.map(|count| vec![*value, count]))
            .collect();
        let mut ir = synthetic_ir(
            &format!("unsigned_wrapping_{isa:?}"),
            vec![
                Param {
                    index: 7,
                    name: "input".into(),
                    ty: integer.clone(),
                },
                Param {
                    index: 6,
                    name: "count".into(),
                    ty: integer.clone(),
                },
            ],
            integer,
            Vec::new(),
        );
        ir.isa = isa;
        let value = VARIABLE_BASE;
        let counter = VARIABLE_BASE + 1;
        ir.blocks = vec![
            Block {
                start: 0,
                stmts: vec![
                    Stmt::Assign {
                        dest: RegRef {
                            index: value,
                            width,
                        },
                        value: Expr::reg(7, width),
                        at: None,
                    },
                    Stmt::Assign {
                        dest: RegRef {
                            index: counter,
                            width,
                        },
                        value: Expr::Const(0),
                        at: None,
                    },
                    Stmt::Br {
                        target: Some(1),
                        at: None,
                    },
                ],
            },
            Block {
                start: 1,
                stmts: vec![Stmt::Brif {
                    cond: Cond::Eq,
                    lhs: Expr::reg(counter, width),
                    rhs: Expr::reg(6, width),
                    target: 3,
                    at: None,
                }],
            },
            Block {
                start: 2,
                stmts: vec![
                    Stmt::Assign {
                        dest: RegRef {
                            index: value,
                            width,
                        },
                        value: Expr::bin(BinOp::Add, Expr::reg(value, width), Expr::Const(1)),
                        at: None,
                    },
                    Stmt::Assign {
                        dest: RegRef {
                            index: counter,
                            width,
                        },
                        value: Expr::bin(BinOp::Add, Expr::reg(counter, width), Expr::Const(1)),
                        at: None,
                    },
                    Stmt::Brif {
                        cond: Cond::Ne,
                        lhs: Expr::reg(counter, width),
                        rhs: Expr::reg(6, width),
                        target: 2,
                        at: None,
                    },
                ],
            },
            Block {
                start: 3,
                stmts: vec![Stmt::Ret {
                    value: Expr::reg(value, width),
                    at: None,
                }],
            },
        ];
        let candidate = printed_candidate(ir, inputs.clone());
        assert!(
            candidate.code.lines().any(|line| {
                let line = line.trim_start();
                line.starts_with(&format!("uint{bits}_t result"))
                    || line.starts_with(&format!("uint{bits}_t v"))
            }),
            "{}",
            candidate.code
        );
        assert!(
            !candidate.code.contains(&format!("(uint{bits}_t)")),
            "{}",
            candidate.code
        );
        assert!(
            !candidate.code.contains(&format!("(int{bits}_t)")),
            "{}",
            candidate.code
        );
        candidates.push(candidate);
    }
    check_candidates("unsigned-wrapping-locals", candidates, Mode::Registers, &[]);
}

#[test]
fn unsigned_parameter_arithmetic_matches_machine_bits_for_every_architecture() {
    let mut candidates = Vec::new();
    for isa in [Isa::X86_64, Isa::I386, Isa::AArch64, Isa::Arm32] {
        let bits = if velk::arch::pointer_bytes(isa) == 4 {
            32
        } else {
            64
        };
        let width = bits as u8;
        let integer = CType::int(width / 8, false);
        let values = if bits == 32 {
            [
                0,
                1,
                0x7fff_ffff,
                0x8000_0000,
                u32::MAX as u64 - 1,
                u32::MAX as u64,
            ]
        } else {
            [0, 1, 0x7fff_ffff, 0x8000_0000, u64::MAX - 1, u64::MAX]
        };
        for (name, operator, right) in [
            ("add", BinOp::Add, 1),
            ("subtract", BinOp::Sub, 1),
            ("multiply", BinOp::Mul, 3),
            ("shift", BinOp::Shl, 7),
        ] {
            let mut ir = synthetic_ir(
                &format!("unsigned_parameter_{name}_{isa:?}"),
                vec![Param {
                    index: 7,
                    name: "input".into(),
                    ty: integer.clone(),
                }],
                integer.clone(),
                vec![Stmt::Ret {
                    value: Expr::bin(operator, Expr::reg(7, width), Expr::Const(right)),
                    at: None,
                }],
            );
            ir.isa = isa;
            let candidate =
                printed_candidate(ir, values.iter().map(|value| vec![*value]).collect());
            assert!(
                candidate.code.contains(&format!("uint{bits}_t input")),
                "{}",
                candidate.code
            );
            assert!(
                !candidate.code.contains(&format!("(uint{bits}_t)")),
                "{}",
                candidate.code
            );
            candidates.push(candidate);
        }
    }
    check_candidates(
        "unsigned-parameter-arithmetic",
        candidates,
        Mode::Registers,
        &[],
    );
}

#[test]
fn returned_address_copies_keep_pointer_types() {
    use velk::ir::{RegRef, VARIABLE_BASE};

    let mut candidates = Vec::new();
    for isa in [Isa::X86_64, Isa::AArch64] {
        for width in [1, 2, 4, 8] {
            let pointer = Expr::reg(VARIABLE_BASE, 64);
            let copy = Expr::reg(VARIABLE_BASE + 1, 64);
            let mut ir = synthetic_ir(
                &format!("returned_copy_{isa:?}_{width}"),
                vec![
                    Param {
                        index: 7,
                        name: "p".into(),
                        ty: CType::pointer_to(CType::int(width, false)),
                    },
                    Param {
                        index: 6,
                        name: "q".into(),
                        ty: CType::pointer_to(CType::int(width, false)),
                    },
                    Param {
                        index: 5,
                        name: "choose".into(),
                        ty: CType::U64,
                    },
                ],
                CType::U64,
                vec![
                    Stmt::Assign {
                        dest: RegRef {
                            index: VARIABLE_BASE,
                            width: 64,
                        },
                        value: Expr::Select {
                            cond: Cond::Ne,
                            lhs: Box::new(Expr::reg(5, 64)),
                            rhs: Box::new(Expr::Const(0)),
                            then: Box::new(Expr::reg(7, 64)),
                            els: Box::new(Expr::reg(6, 64)),
                        },
                        at: None,
                    },
                    Stmt::Assign {
                        dest: RegRef {
                            index: VARIABLE_BASE + 1,
                            width: 64,
                        },
                        value: pointer.clone(),
                        at: None,
                    },
                    Stmt::Store {
                        addr: copy,
                        value: Expr::Const(0x807f_ff01_8000_ffff),
                        width,
                        at: None,
                    },
                    Stmt::Ret {
                        value: pointer,
                        at: None,
                    },
                ],
            );
            ir.isa = isa;
            let inputs = [0, 1, u64::MAX]
                .into_iter()
                .flat_map(|choose| {
                    [32, 64, 256, REGION_SIZE - 64]
                        .map(|offset| vec![REGION + offset, REGION + 16, choose])
                })
                .collect();
            let candidate = printed_candidate(ir, inputs);
            assert!(
                candidate.code.contains(&format!("uint{}_t *v1", width * 8)),
                "{}",
                candidate.code
            );
            assert!(!candidate.code.contains("v2 = ("), "{}", candidate.code);
            candidates.push(candidate);
        }
    }
    check_candidates("address-copies", candidates, Mode::Memory, &[]);
}

#[test]
fn byte_accesses_through_wide_pointer_offsets_keep_one_conversion() {
    let mut candidates = Vec::new();
    for isa in [Isa::X86_64, Isa::I386, Isa::AArch64, Isa::Arm32] {
        for signed in [false, true] {
            for offset in [1, 3, 7, 9, 15] {
                let address = Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(offset));
                let mut ir = synthetic_ir(
                    &format!("byte_offset_{isa:?}_{signed}_{offset}"),
                    vec![Param {
                        index: 7,
                        name: "p".into(),
                        ty: CType::pointer_to(CType::U64),
                    }],
                    CType::U64,
                    vec![
                        Stmt::Store {
                            addr: address.clone(),
                            value: Expr::Const(0x80),
                            width: 1,
                            at: None,
                        },
                        Stmt::Ret {
                            value: Expr::Load {
                                addr: Box::new(address),
                                width: 1,
                                signed,
                            },
                            at: None,
                        },
                    ],
                );
                ir.isa = isa;
                let inputs = (0..16)
                    .map(|index| vec![region_start(isa) + 32 + index * 128])
                    .collect();
                let candidate = printed_candidate(ir, inputs);
                assert!(
                    candidate.code.contains("*((uint8_t *)p +"),
                    "{}",
                    candidate.code
                );
                assert!(
                    !candidate.code.contains("*(uint8_t *)"),
                    "{}",
                    candidate.code
                );
                if velk::arch::pointer_bytes(isa) == 4 {
                    let name = candidate.ir.name.as_ref().expect("a named test function");
                    let expected = if signed { u64::MAX - 127 } else { 128 };
                    syntax::run_printed(
                        &candidate.code,
                        "",
                        &format!(
                            "uint64_t words[4] = {{0}}; return {name}(words) != UINT64_C({expected}) || ((uint8_t *)words)[{offset}] != 128;"
                        ),
                    );
                } else {
                    candidates.push(candidate);
                }
            }
        }
    }
    check_candidates("byte-pointer-offsets", candidates, Mode::Memory, &[]);
}

#[test]
fn selected_scalar_pointers_keep_access_width_and_sign() {
    let mut candidates = Vec::new();
    for width in [1, 2, 4, 8] {
        for signed in [false, true] {
            let address = Expr::Select {
                cond: Cond::Ne,
                lhs: Box::new(Expr::reg(5, 64)),
                rhs: Box::new(Expr::Const(0)),
                then: Box::new(Expr::reg(7, 64)),
                els: Box::new(Expr::reg(6, 64)),
            };
            let ir = synthetic_ir(
                &format!("selected_pointer_{width}_{signed}"),
                vec![
                    Param {
                        index: 7,
                        name: "p".into(),
                        ty: CType::pointer_to(CType::int(width, signed)),
                    },
                    Param {
                        index: 6,
                        name: "q".into(),
                        ty: CType::pointer_to(CType::int(width, signed)),
                    },
                    Param {
                        index: 5,
                        name: "choose".into(),
                        ty: CType::U64,
                    },
                ],
                CType::U64,
                vec![
                    Stmt::Store {
                        addr: address.clone(),
                        value: Expr::Const(0x807f_ff01_8000_ffff),
                        width,
                        at: None,
                    },
                    Stmt::Ret {
                        value: Expr::Load {
                            addr: Box::new(address),
                            width,
                            signed,
                        },
                        at: None,
                    },
                ],
            );
            let candidate = printed_candidate(
                ir,
                vec![
                    vec![REGION + 32, REGION + 64, 0],
                    vec![REGION + 32, REGION + 64, 1],
                ],
            );
            assert!(
                candidate.code.contains("*(choose != 0 ? p : q)"),
                "{}",
                candidate.code
            );
            candidates.push(candidate);
        }
    }
    check_candidates("selected-scalar-pointers", candidates, Mode::Memory, &[]);
}

#[test]
fn selected_global_addresses_keep_the_requested_access_width() {
    let mut ir = synthetic_ir(
        "selected_global",
        vec![Param {
            index: 7,
            name: "choose".into(),
            ty: CType::U64,
        }],
        CType::U64,
        vec![Stmt::Ret {
            value: Expr::Load {
                addr: Box::new(Expr::Select {
                    cond: Cond::Ne,
                    lhs: Box::new(Expr::reg(7, 64)),
                    rhs: Box::new(Expr::Const(0)),
                    then: Box::new(Expr::Const(0x2000)),
                    els: Box::new(Expr::Const(0x3000)),
                }),
                width: 8,
                signed: false,
            },
            at: None,
        }],
    );
    ir.debug_globals = vec![(0x2000, CType::U64, 8), (0x3000, CType::U64, 8)];
    let symbols = velk::render::Symbols {
        data: [(0x2000, "first".into()), (0x3000, "second".into())].into(),
        library_variables: [(0x2000, "first"), (0x3000, "second")]
            .map(|(address, name)| {
                (
                    address,
                    velk::analysis::prototypes::LibraryVariable {
                        name: name.into(),
                        ty: CType::U64,
                        size: 8,
                        header: "stdint.h".into(),
                    },
                )
            })
            .into(),
        ..Default::default()
    };
    let code = velk::render::render(&ir, &[], &symbols, &[(0x2000, 8), (0x3000, 8)]);
    assert!(code.contains("*(uint64_t *)"), "{code}");
    let code = code
        .replace("0x2000", "((uintptr_t)&first)")
        .replace("0x3000", "((uintptr_t)&second)");
    let code = format!("#include <stdint.h>\nextern uint64_t first, second;\n{code}");
    syntax::run_printed(
        &code,
        "uint64_t first = UINT64_C(0x123456789abcdef0); uint64_t second = UINT64_C(0xfedcba9876543210);",
        "return selected_global(0) != second || selected_global(1) != first;",
    );
}

#[test]
fn narrow_address_assignments_keep_truncation_on_32_bit_targets() {
    let path = common::fixtures_dir().join("arm32/control.arm.O2.elf");
    let mut binary = Binary::open(&path).expect("open ARM32 control flow fixture");
    let addr = binary
        .image()
        .functions
        .values()
        .find(|function| function.name.as_deref() == Some("short_circuit"))
        .expect("short_circuit fixture function")
        .addr;
    let code = binary
        .decompile(addr, None, None)
        .expect("decompile short_circuit");
    assert!(code.contains("v1 = (uint32_t)(uintptr_t)p;"), "{code}");
}

#[test]
fn integer_destinations_supply_outer_conversions() {
    let mut candidates = Vec::new();
    for isa in [Isa::X86_64, Isa::I386, Isa::AArch64, Isa::Arm32] {
        let input_bits = if matches!(isa, Isa::I386 | Isa::Arm32) {
            32
        } else {
            64
        };
        for bits in [16, 32, 64] {
            for signed in [false, true] {
                let mut ir = synthetic_ir(
                    &format!("destination_{isa:?}_{bits}_{signed}"),
                    vec![Param {
                        index: 7,
                        name: "x".into(),
                        ty: CType::int(input_bits / 8, false),
                    }],
                    CType::int(bits / 8, signed),
                    vec![Stmt::Ret {
                        value: Expr::SignExtend {
                            value: Box::new(Expr::reg(7, input_bits)),
                            width: bits / 8,
                        },
                        at: None,
                    }],
                );
                ir.isa = isa;
                let candidate = printed_candidate(
                    ir,
                    [
                        0,
                        1,
                        0x7fff,
                        0x8000,
                        0xffff,
                        0x7fff_ffff,
                        0x8000_0000,
                        0xffff_ffff,
                        1 << 63,
                        u64::MAX,
                    ]
                    .into_iter()
                    .map(|x| vec![x & (u64::MAX >> (64 - input_bits))])
                    .collect(),
                );
                assert!(candidate.code.contains("return x;"), "{}", candidate.code);
                candidates.push(candidate);
            }
        }
    }
    check_candidates(
        "integer-destination-conversions",
        candidates,
        Mode::Registers,
        &[],
    );
}

#[test]
fn mixed_width_pointer_variables_use_bytes_without_changing_accesses() {
    use velk::ir::{RegRef, VARIABLE_BASE};

    let mut candidates = Vec::new();
    for width in [2, 4, 8] {
        for signed in [false, true] {
            let pointer = Expr::reg(VARIABLE_BASE, 64);
            let ir = synthetic_ir(
                &format!("mixed_pointer_{width}_{signed}"),
                vec![Param {
                    index: 7,
                    name: "p".into(),
                    ty: CType::pointer_to(CType::int(1, false)),
                }],
                CType::U64,
                vec![
                    Stmt::Assign {
                        dest: RegRef {
                            index: VARIABLE_BASE,
                            width: 64,
                        },
                        value: Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(8)),
                        at: None,
                    },
                    Stmt::Store {
                        addr: pointer.clone(),
                        value: Expr::Const(0x807f_ff01_8000_ffff),
                        width,
                        at: None,
                    },
                    Stmt::Store {
                        addr: Expr::bin(BinOp::Add, pointer.clone(), Expr::Const(1)),
                        value: Expr::Const(0x80),
                        width: 1,
                        at: None,
                    },
                    Stmt::Ret {
                        value: Expr::Load {
                            addr: Box::new(pointer),
                            width,
                            signed,
                        },
                        at: None,
                    },
                ],
            );
            let candidate = printed_candidate(ir, vec![vec![REGION + 16]]);
            assert!(candidate.code.contains("uint8_t *v1"), "{}", candidate.code);
            assert!(
                !candidate.code.contains("*(uint8_t *)"),
                "{}",
                candidate.code
            );
            candidates.push(candidate);
        }
    }
    check_candidates("mixed-pointer-widths", candidates, Mode::Memory, &[]);
}

#[test]
fn address_integer_spills_keep_pointer_offsets_and_integer_reads() {
    let mut candidates = Vec::new();
    for isa in [Isa::X86_64, Isa::AArch64] {
        let sp = velk::arch::stack_pointer(isa);
        for offset in [0, 8, 16] {
            let slot = Expr::bin(BinOp::Sub, Expr::reg(sp, 64), Expr::Const(8));
            let address = Expr::bin(
                BinOp::Add,
                Expr::Load {
                    addr: Box::new(slot.clone()),
                    width: 8,
                    signed: false,
                },
                Expr::Const(offset),
            );
            let mut ir = synthetic_ir(
                &format!("address_spill_{isa:?}_{offset}"),
                vec![Param {
                    index: 7,
                    name: "address".into(),
                    ty: CType::U64,
                }],
                CType::U64,
                vec![
                    Stmt::Store {
                        addr: slot.clone(),
                        value: Expr::reg(7, 64),
                        width: 8,
                        at: None,
                    },
                    Stmt::Ret {
                        value: Expr::Load {
                            addr: Box::new(address),
                            width: 8,
                            signed: false,
                        },
                        at: None,
                    },
                ],
            );
            ir.isa = isa;
            let input = region_start(isa) + 32;
            let candidate = printed_candidate(ir, vec![vec![input]]);
            assert!(
                candidate.code.contains("uint64_t *local_0"),
                "{}",
                candidate.code
            );
            let access = if offset == 0 {
                "*local_0".to_owned()
            } else {
                format!("local_0[{}]", offset / 8)
            };
            assert!(candidate.code.contains(&access), "{}", candidate.code);
            candidates.push(candidate);
        }

        let slot = Expr::bin(BinOp::Sub, Expr::reg(sp, 64), Expr::Const(8));
        let address = Expr::bin(
            BinOp::Add,
            Expr::Load {
                addr: Box::new(slot.clone()),
                width: 8,
                signed: false,
            },
            Expr::Const(8),
        );
        let mut ir = synthetic_ir(
            &format!("address_spill_store_{isa:?}"),
            vec![Param {
                index: 7,
                name: "address".into(),
                ty: CType::U64,
            }],
            CType::U64,
            vec![
                Stmt::Store {
                    addr: slot,
                    value: Expr::reg(7, 64),
                    width: 8,
                    at: None,
                },
                Stmt::Store {
                    addr: address.clone(),
                    value: Expr::Const(0x1122_3344_5566_7788),
                    width: 8,
                    at: None,
                },
                Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(address),
                        width: 8,
                        signed: false,
                    },
                    at: None,
                },
            ],
        );
        ir.isa = isa;
        let candidate = printed_candidate(ir, vec![vec![region_start(isa) + 32]]);
        assert!(
            candidate.code.contains("uint64_t *local_0"),
            "{}",
            candidate.code
        );
        assert!(
            candidate.code.contains("local_0[1] = "),
            "{}",
            candidate.code
        );
        candidates.push(candidate);

        let slot = Expr::bin(BinOp::Sub, Expr::reg(sp, 64), Expr::Const(8));
        let address = Expr::bin(
            BinOp::Add,
            Expr::Load {
                addr: Box::new(slot.clone()),
                width: 8,
                signed: false,
            },
            Expr::Const(8),
        );
        let mut ir = synthetic_ir(
            &format!("address_spill_atomic_{isa:?}"),
            vec![Param {
                index: 7,
                name: "address".into(),
                ty: CType::U64,
            }],
            CType::U64,
            vec![
                Stmt::Store {
                    addr: slot,
                    value: Expr::reg(7, 64),
                    width: 8,
                    at: None,
                },
                Stmt::Machine {
                    at: None,
                    instruction: MachineInstruction::Atomic {
                        op: AtomicOp::Add,
                        width: 8,
                        ordering: Ordering::SeqCst,
                    },
                    inputs: vec![address, Expr::Const(1)],
                    outputs: vec![RegRef {
                        index: VARIABLE_BASE,
                        width: 64,
                    }],
                },
                Stmt::Ret {
                    value: Expr::reg(VARIABLE_BASE, 64),
                    at: None,
                },
            ],
        );
        ir.isa = isa;
        let candidate = printed_candidate(ir, vec![vec![region_start(isa) + 32]]);
        assert!(
            candidate.code.contains("uint64_t *local_0"),
            "{}",
            candidate.code
        );
        assert!(
            candidate.code.contains("local_0 + 0x1"),
            "{}",
            candidate.code
        );
        candidates.push(candidate);

        let slot = Expr::bin(BinOp::Sub, Expr::reg(sp, 64), Expr::Const(8));
        let address = Expr::bin(
            BinOp::Add,
            Expr::Load {
                addr: Box::new(slot.clone()),
                width: 8,
                signed: false,
            },
            Expr::Const(8),
        );
        let mut ir = synthetic_ir(
            &format!("address_spill_integer_read_{isa:?}"),
            vec![Param {
                index: 7,
                name: "address".into(),
                ty: CType::U64,
            }],
            CType::U64,
            vec![
                Stmt::Store {
                    addr: slot.clone(),
                    value: Expr::reg(7, 64),
                    width: 8,
                    at: None,
                },
                Stmt::Assign {
                    at: None,
                    dest: RegRef {
                        index: VARIABLE_BASE,
                        width: 64,
                    },
                    value: Expr::Load {
                        addr: Box::new(slot.clone()),
                        width: 8,
                        signed: false,
                    },
                },
                Stmt::Ret {
                    value: Expr::bin(
                        BinOp::Add,
                        Expr::Load {
                            addr: Box::new(address),
                            width: 8,
                            signed: false,
                        },
                        Expr::bin(BinOp::Shr, Expr::reg(VARIABLE_BASE, 64), Expr::Const(1)),
                    ),
                    at: None,
                },
            ],
        );
        ir.isa = isa;
        let candidate = printed_candidate(ir, vec![vec![region_start(isa) + 32]]);
        assert!(
            candidate
                .code
                .lines()
                .any(|line| line.contains("local_0;") && !line.contains('*')),
            "{}",
            candidate.code
        );
        candidates.push(candidate);
    }
    check_candidates("address-integer-spills", candidates, Mode::Memory, &[]);
}

#[test]
fn object_pointers_convert_to_void_without_identity_casts() {
    for (source, target) in [
        (CType::U32, CType::Void),
        (CType::U32, CType::Named("const void".into())),
        (CType::Void, CType::U32),
    ] {
        let ir = synthetic_ir(
            "object_address",
            vec![Param {
                index: 7,
                name: "p".into(),
                ty: CType::pointer_to(source),
            }],
            CType::pointer_to(target),
            vec![Stmt::Ret {
                value: Expr::reg(7, 64),
                at: None,
            }],
        );
        let code = velk::render::render(&ir, &[], &Default::default(), &[]);
        assert!(code.contains("return p;"), "{code}");
        syntax::run_printed(
            &code,
            "",
            "uint32_t value = 42; return object_address(&value) != &value || object_address(0) != 0;",
        );
    }
}

#[test]
fn anonymous_data_offsets_keep_integer_address_arithmetic() {
    let mut candidates = Vec::new();
    for width in [1, 2, 4, 8] {
        for signed in [false, true] {
            let address = Expr::bin(
                BinOp::Add,
                Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(32)),
                Expr::bin(BinOp::Mul, Expr::reg(6, 64), Expr::Const(8)),
            );
            let ir = synthetic_ir(
                &format!("anonymous_offset_{width}_{signed}"),
                vec![
                    Param {
                        index: 7,
                        name: "p".into(),
                        ty: CType::pointer_to(CType::int(1, false)),
                    },
                    Param {
                        index: 6,
                        name: "index".into(),
                        ty: CType::U64,
                    },
                ],
                CType::U64,
                vec![Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(address),
                        width,
                        signed,
                    },
                    at: None,
                }],
            );
            let mut candidate = printed_candidate(
                ir,
                [0, 1, 2, u64::MAX]
                    .into_iter()
                    .map(|index| vec![REGION + 16, index])
                    .collect(),
            );
            candidate.code =
                velk::render::render(&candidate.ir, &[], &Default::default(), &[(0, 0x1000)]);
            assert!(!candidate.code.contains("const "), "{}", candidate.code);
            assert!(
                candidate.code.contains("(uintptr_t)p"),
                "{}",
                candidate.code
            );
            candidates.push(candidate);
        }
    }
    check_candidates("anonymous-data-offsets", candidates, Mode::Memory, &[]);
}

#[test]
fn printed_signed_loads_preserve_extension_widths() {
    let mut candidates = Vec::new();
    for loaded in [1, 2, 4, 8] {
        for extended in [1, 2, 4, 8] {
            let ir = synthetic_ir(
                &format!("extend_load_{loaded}_{extended}"),
                vec![
                    Param {
                        index: 7,
                        name: "p".into(),
                        ty: CType::pointer_to(CType::int(1, false)),
                    },
                    Param {
                        index: 6,
                        name: "x".into(),
                        ty: CType::U64,
                    },
                ],
                CType::U64,
                vec![
                    Stmt::Store {
                        addr: Expr::reg(7, 64),
                        value: Expr::reg(6, 64),
                        width: loaded,
                        at: None,
                    },
                    Stmt::Ret {
                        value: Expr::SignExtend {
                            value: Box::new(Expr::Load {
                                addr: Box::new(Expr::reg(7, 64)),
                                width: loaded,
                                signed: false,
                            }),
                            width: extended,
                        },
                        at: None,
                    },
                ],
            );
            let candidate = printed_candidate(
                ir,
                [
                    0,
                    1,
                    0x7f,
                    0x80,
                    0x7fff,
                    0x8000,
                    0x7fff_ffff,
                    0x8000_0000,
                    1 << 63,
                    u64::MAX,
                ]
                .into_iter()
                .map(|x| vec![REGION + 1, x])
                .collect(),
            );
            if loaded == extended && loaded > 1 {
                assert!(
                    !candidate.code.contains(&format!("(int{}_t)*", loaded * 8)),
                    "{}",
                    candidate.code
                );
            }
            candidates.push(candidate);
        }
    }
    check_candidates("signed-load-widths", candidates, Mode::Memory, &[]);
}

#[test]
fn printed_local_types_preserve_byte_values_and_integer_uses() {
    use velk::ir::{RegRef, VARIABLE_BASE};

    let local = Expr::reg(VARIABLE_BASE, 64);
    let mut candidates = Vec::new();
    let edges = [0, 1, 127, 128, 255, 256, 0x8000_0000, u64::MAX];
    let counts = [0, 1, 7, 8, 31, 32, 63, 64, 65, u64::MAX];
    let inputs: Vec<Vec<u64>> = edges
        .iter()
        .flat_map(|value| counts.iter().map(move |count| vec![*value, *count]))
        .collect();
    for (name, definition, result) in [
        (
            "byte_local",
            Expr::bin(BinOp::And, Expr::reg(7, 64), Expr::Const(255)),
            local.clone(),
        ),
        (
            "shift_local",
            Expr::bin(BinOp::Xor, Expr::reg(7, 64), Expr::Const(1)),
            Expr::bin(BinOp::Shl, local.clone(), Expr::reg(6, 64)),
        ),
        (
            "logical_shift_local",
            Expr::bin(BinOp::Xor, Expr::reg(7, 64), Expr::Const(1)),
            Expr::bin(BinOp::Shr, local.clone(), Expr::Const(63)),
        ),
        (
            "narrow_read_wide_local",
            Expr::bin(BinOp::And, Expr::reg(7, 64), Expr::Const(255)),
            Expr::bin(
                BinOp::Add,
                Expr::bin(BinOp::Shl, local.clone(), Expr::reg(6, 64)),
                Expr::reg(VARIABLE_BASE, 8),
            ),
        ),
        (
            "wrapping_local",
            Expr::bin(BinOp::And, Expr::reg(7, 64), Expr::Const(0xffff_ffff)),
            Expr::bin(BinOp::Add, local.clone(), Expr::Const(1)),
        ),
        (
            "mixed_sign_local",
            Expr::bin(BinOp::Xor, Expr::reg(7, 64), Expr::Const(1)),
            Expr::Select {
                cond: Cond::Lt,
                lhs: Box::new(local.clone()),
                rhs: Box::new(Expr::reg(6, 64)),
                then: Box::new(Expr::bin(BinOp::Shr, local.clone(), Expr::Const(1))),
                els: Box::new(Expr::bin(BinOp::Shl, local.clone(), Expr::Const(1))),
            },
        ),
    ] {
        let ir = synthetic_ir(
            name,
            vec![
                Param {
                    index: 7,
                    name: "x".into(),
                    ty: CType::U64,
                },
                Param {
                    index: 6,
                    name: "count".into(),
                    ty: CType::U64,
                },
            ],
            CType::U64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: VARIABLE_BASE,
                        width: 64,
                    },
                    value: definition,
                    at: None,
                },
                Stmt::Ret {
                    value: Expr::bin(BinOp::Add, result, local.clone()),
                    at: None,
                },
            ],
        );
        let candidate = printed_candidate(ir, inputs.clone());
        if name == "byte_local" {
            assert!(
                candidate.code.contains("uint8_t v1 ="),
                "{}",
                candidate.code
            );
        }
        if matches!(
            name,
            "shift_local" | "logical_shift_local" | "narrow_read_wide_local"
        ) {
            assert!(
                candidate.code.contains("uint64_t v1 ="),
                "{}",
                candidate.code
            );
            assert!(!candidate.code.contains("(uint64_t)"), "{}", candidate.code);
            assert!(!candidate.code.contains("(uint8_t)"), "{}", candidate.code);
        }
        candidates.push(candidate);
    }
    check_candidates(
        "local_integer_types",
        candidates,
        Mode::Registers,
        &["-fsanitize=undefined", "-fno-sanitize-recover=all"],
    );
}

#[test]
fn printed_byte_load_locals_extend_every_value_exactly() {
    use velk::ir::{RegRef, VARIABLE_BASE};

    let mut candidates = Vec::new();
    for signed in [false, true] {
        let local = Expr::reg(VARIABLE_BASE, 64);
        let ir = synthetic_ir(
            if signed {
                "signed_byte_local"
            } else {
                "loaded_byte_local"
            },
            vec![Param {
                index: 7,
                name: "x".into(),
                ty: CType::U64,
            }],
            CType::U64,
            vec![
                Stmt::Store {
                    addr: Expr::Const(REGION),
                    value: Expr::reg(7, 64),
                    width: 1,
                    at: None,
                },
                Stmt::Assign {
                    dest: RegRef {
                        index: VARIABLE_BASE,
                        width: 64,
                    },
                    value: Expr::Load {
                        addr: Box::new(Expr::Const(REGION)),
                        width: 1,
                        signed,
                    },
                    at: None,
                },
                Stmt::Ret {
                    value: Expr::bin(BinOp::Add, local.clone(), local),
                    at: None,
                },
            ],
        );
        let candidate = printed_candidate(ir, (0..256).map(|value| vec![value]).collect());
        if !signed {
            assert!(
                candidate.code.contains("uint8_t v1 ="),
                "{}",
                candidate.code
            );
        }
        candidates.push(candidate);
    }
    check_candidates("loaded_byte_locals", candidates, Mode::Memory, &[]);
}

#[test]
fn printed_integer_shifts_and_pointer_choices_avoid_identity_casts() {
    let mut candidates = Vec::new();
    let edges = [
        0,
        1,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_ffff,
        1 << 63,
        u64::MAX,
    ];
    let inputs: Vec<Vec<u64>> = edges
        .iter()
        .flat_map(|x| edges.iter().map(move |y| vec![*x, *y]))
        .collect();
    let shifted = Expr::bin(BinOp::Shl, Expr::reg(7, 64), Expr::Const(8));
    let ir = synthetic_ir(
        "identity_shift",
        vec![
            Param {
                index: 7,
                name: "x".into(),
                ty: CType::U64,
            },
            Param {
                index: 6,
                name: "y".into(),
                ty: CType::U64,
            },
        ],
        CType::U64,
        vec![Stmt::Ret {
            value: Expr::bin(
                BinOp::DivU,
                shifted,
                Expr::bin(BinOp::Or, Expr::reg(6, 64), Expr::Const(1)),
            ),
            at: None,
        }],
    );
    let candidate = printed_candidate(ir, inputs.clone());
    assert!(!candidate.code.contains("(uint64_t)"), "{}", candidate.code);
    candidates.push(candidate);
    for (name, other, null) in [
        ("same_pointers", CType::U64, false),
        ("null_pointer", CType::U64, true),
        ("different_pointers", CType::U32, false),
    ] {
        let ty = CType::pointer_to(CType::U64);
        let ir = synthetic_ir(
            name,
            vec![
                Param {
                    index: 7,
                    name: "x".into(),
                    ty: ty.clone(),
                },
                Param {
                    index: 6,
                    name: "y".into(),
                    ty: CType::pointer_to(other),
                },
            ],
            ty,
            vec![Stmt::Ret {
                value: Expr::Select {
                    cond: Cond::Ne,
                    lhs: Box::new(Expr::reg(7, 64)),
                    rhs: Box::new(Expr::Const(0)),
                    then: Box::new(Expr::reg(7, 64)),
                    els: Box::new(if null {
                        Expr::Const(0)
                    } else {
                        Expr::reg(6, 64)
                    }),
                },
                at: None,
            }],
        );
        let candidate = printed_candidate(ir, inputs.clone());
        assert_eq!(
            candidate.code.contains("return (uint64_t *)"),
            name == "different_pointers",
            "{}",
            candidate.code
        );
        candidates.push(candidate);
    }
    check_candidates("identity_casts", candidates, Mode::Memory, &[]);
}

#[test]
fn printed_byte_buffer_accesses_keep_signedness_and_wider_accesses() {
    let slot = |offset: u64| {
        Expr::bin(
            BinOp::Add,
            Expr::reg(4, 64),
            Expr::Const(offset.wrapping_sub(64)),
        )
    };
    let mut candidates = Vec::new();
    for (signed, width) in [(false, 1), (true, 1), (false, 2)] {
        let read = Expr::Load {
            addr: Box::new(slot(0)),
            width,
            signed,
        };
        let return_statement = Stmt::Ret {
            value: read,
            at: None,
        };
        let mut ir = synthetic_ir(
            if signed {
                "signed_buffer_byte"
            } else if width == 1 {
                "buffer_byte"
            } else {
                "buffer_word"
            },
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
                    args: Some(vec![slot(0), Expr::Const(0), Expr::Const(16)]),
                    floats_named: false,
                    outputs: Vec::new(),
                    clobbers: Some(Default::default()),
                    via: None,
                    at: None,
                },
                Stmt::Store {
                    addr: slot(0),
                    value: Expr::Const(0),
                    width: 2,
                    at: None,
                },
                Stmt::Store {
                    addr: slot(0),
                    value: Expr::reg(7, 64),
                    width: 1,
                    at: None,
                },
                return_statement.clone(),
            ],
        );
        let mut symbols = velk::render::Symbols::default();
        symbols.functions.insert(0x1000, "memset".into());
        let code = velk::render::render(&ir, &[], &symbols, &[]);
        assert!(!code.contains("*(uint8_t *)(local_"), "{code}");
        // The bytes read and written at more than one width share a union.
        assert!(code.contains("local_0.f_0."), "{code}");
        assert!(!code.contains("*(uint16_t *)"), "{code}");
        ir.blocks[0].stmts = (0..16)
            .map(|offset| Stmt::Store {
                addr: slot(offset),
                value: Expr::Const(0),
                width: 1,
                at: None,
            })
            .collect();
        ir.blocks[0].stmts.push(Stmt::Store {
            addr: slot(0),
            value: Expr::reg(7, 64),
            width: 1,
            at: None,
        });
        ir.blocks[0].stmts.push(return_statement);
        let mut candidate = printed_candidate(ir, (0..256).map(|value| vec![value]).collect());
        candidate.code = format!("#include <string.h>\n{code}");
        candidates.push(candidate);
    }
    check_candidates("byte_buffer_casts", candidates, Mode::Memory, &[]);
}

#[test]
fn declared_narrow_signed_values_extend_without_casts() {
    let mut candidates = Vec::new();
    for (width, name) in [(1, "signed char"), (2, "short"), (4, "int")] {
        let ir = synthetic_ir(
            &format!("declared_signed_{width}"),
            vec![Param {
                index: 7,
                name: "x".into(),
                ty: CType::Named(name.into()),
            }],
            CType::I64,
            vec![Stmt::Ret {
                value: Expr::SignExtend {
                    value: Box::new(Expr::reg(7, width * 8)),
                    width,
                },
                at: None,
            }],
        );
        let candidate = printed_candidate(
            ir,
            [
                0,
                1,
                127,
                128,
                255,
                32767,
                32768,
                65535,
                0x7fff_ffff,
                0x8000_0000,
                u64::MAX,
            ]
            .into_iter()
            .map(|x| vec![x])
            .collect(),
        );
        assert!(candidate.code.contains("return x;"), "{}", candidate.code);
        candidates.push(candidate);
    }
    check_candidates(
        "declared-signed-extension",
        candidates,
        Mode::Registers,
        &[],
    );
}

#[test]
fn plain_char_zero_tests_preserve_both_char_signs() {
    let ir = synthetic_ir(
        "plain_char_zero",
        vec![
            Param {
                index: 7,
                name: "s".into(),
                ty: CType::pointer_to(CType::Named("char".into())),
            },
            Param {
                index: 6,
                name: "byte".into(),
                ty: CType::U64,
            },
        ],
        CType::U64,
        vec![
            Stmt::Store {
                addr: Expr::reg(7, 64),
                value: Expr::reg(6, 64),
                width: 1,
                at: None,
            },
            Stmt::Ret {
                value: Expr::Select {
                    cond: Cond::Ne,
                    lhs: Box::new(Expr::Load {
                        addr: Box::new(Expr::reg(7, 64)),
                        width: 1,
                        signed: false,
                    }),
                    rhs: Box::new(Expr::Const(0)),
                    then: Box::new(Expr::Const(1)),
                    els: Box::new(Expr::Const(0)),
                },
                at: None,
            },
        ],
    );
    for sign in ["-fsigned-char", "-funsigned-char"] {
        let mut candidates = Vec::new();
        for mask in [None, Some(0xffff_ffff), Some(0x7f)] {
            for comparison in [Cond::Eq, Cond::Ne] {
                let mut ir = ir.clone();
                if let Stmt::Ret {
                    value: Expr::Select { cond, lhs, .. },
                    ..
                } = &mut ir.blocks[0].stmts[1]
                {
                    *cond = comparison;
                    if let Some(mask) = mask {
                        **lhs = Expr::bin(BinOp::And, lhs.as_ref().clone(), Expr::Const(mask));
                    }
                }
                let candidate =
                    printed_candidate(ir, (0..256).map(|byte| vec![REGION, byte]).collect());
                if mask != Some(0x7f) {
                    assert!(!candidate.code.contains("(uint8_t)"), "{}", candidate.code);
                }
                candidates.push(candidate);
            }
        }
        check_candidates("plain-char-zero", candidates, Mode::Memory, &[sign]);
    }
}

#[test]
fn printed_bitstream_ranges_preserve_bytes_shifts_and_wrapping() {
    use velk::ir::{RegRef, VARIABLE_BASE};

    let mut candidates = Vec::new();
    let counts = [0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 65, u64::MAX];
    let inputs: Vec<Vec<u64>> = (0..256)
        .map(|value| vec![value, 8])
        .chain(
            [
                0,
                1,
                127,
                128,
                255,
                256,
                65535,
                65536,
                0xffff_ffff,
                u64::MAX,
            ]
            .into_iter()
            .flat_map(|value| counts.iter().map(move |count| vec![value, *count])),
        )
        .collect();
    for width in [1, 2, 4] {
        let local = Expr::reg(VARIABLE_BASE, 64);
        let mask = (1u64 << (width * 8)) - 1;
        let mut ir = synthetic_ir(
            &format!("bitstream_range_{width}"),
            vec![
                Param {
                    index: 7,
                    name: "x".into(),
                    ty: CType::U64,
                },
                Param {
                    index: 6,
                    name: "count".into(),
                    ty: CType::U64,
                },
            ],
            CType::U64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: VARIABLE_BASE,
                        width: 64,
                    },
                    value: Expr::bin(BinOp::And, Expr::reg(7, 64), Expr::Const(mask)),
                    at: None,
                },
                Stmt::Store {
                    addr: Expr::Const(REGION),
                    width,
                    value: Expr::bin(BinOp::Add, local.clone(), Expr::Const(1)),
                    at: None,
                },
                Stmt::Ret {
                    value: Expr::bin(
                        BinOp::Or,
                        Expr::bin(BinOp::Shl, local.clone(), Expr::reg(6, 64)),
                        Expr::Select {
                            cond: Cond::Hi,
                            lhs: Box::new(local),
                            rhs: Box::new(Expr::Const(0x7f)),
                            then: Box::new(Expr::Const(1)),
                            els: Box::new(Expr::Const(0)),
                        },
                    ),
                    at: None,
                },
            ],
        );
        ir.value_types.insert(VARIABLE_BASE, CType::int(8, true));
        let candidate = printed_candidate(ir, inputs.clone());
        assert!(
            candidate.code.contains("\n    int64_t v1 ="),
            "{}",
            candidate.code
        );
        assert!(candidate.code.contains("& 0x3f"), "{}", candidate.code);
        assert!(
            !candidate.code.contains("(uint64_t)v1 >"),
            "{}",
            candidate.code
        );
        assert!(!candidate.code.contains("(uint8_t)"), "{}", candidate.code);
        assert!(!candidate.code.contains("(uint16_t)"), "{}", candidate.code);
        candidates.push(candidate);
    }
    check_candidates(
        "bitstream_ranges",
        candidates,
        Mode::Memory,
        &["-fsanitize=undefined", "-fno-sanitize-recover=all"],
    );
}

#[test]
fn printed_integer_argument_parts_preserve_every_byte_and_sign() {
    let mut candidates = Vec::new();
    for argument_signed in [false, true] {
        for signed in [false, true] {
            for (offset, width) in [(0, 1), (7, 1), (1, 2), (0, 4), (3, 4)] {
                let mut ir = scalar_stack_ir(
                    &format!("argument_part_{argument_signed}_{signed}_{offset}_{width}"),
                    3,
                    vec![Stmt::Ret {
                        value: Expr::Load {
                            addr: Box::new(Expr::bin(
                                BinOp::Add,
                                Expr::reg(4, 64),
                                Expr::Const(24 + offset),
                            )),
                            width,
                            signed,
                        },
                        at: None,
                    }],
                );
                if argument_signed {
                    ir.stack_params[2].ty = CType::int(8, true);
                    ir.declared_signature.as_mut().unwrap().params[8].1 = CType::int(8, true);
                }
                let inputs: Vec<Vec<u64>> = (0..256u64)
                    .chain([256, 65535, 65536, 0x7fff_ffff, 0x8000_0000, u64::MAX])
                    .map(|value| {
                        let mut input = vec![0; 9];
                        input[8] = value.wrapping_mul(0x0101_0101_0101_0101);
                        input
                    })
                    .collect();
                let upper = vec![0; inputs.len()];
                let batch = aggregate_candidates(ir, inputs, upper);
                for candidate in &batch {
                    assert!(
                        !candidate.code.contains("__builtin_memcpy"),
                        "{}",
                        candidate.code
                    );
                    assert!(candidate.code.contains("stack2"), "{}", candidate.code);
                }
                assert_aggregate_oracle(&batch, |input, _| {
                    let raw = (input[8] >> (8 * offset)) & byte_mask(width);
                    if signed {
                        match width {
                            1 => raw as i8 as i64 as u64,
                            2 => raw as i16 as i64 as u64,
                            4 => raw as i32 as i64 as u64,
                            _ => unreachable!(),
                        }
                    } else {
                        raw
                    }
                });
                candidates.extend(batch);
            }
        }
    }
    check_candidates(
        "integer_argument_parts",
        candidates,
        Mode::Registers,
        &["-fsanitize=undefined", "-fno-sanitize-recover=all"],
    );
}

#[test]
fn simplified_selections_keep_the_comparison_width() {
    let mut candidates = Vec::new();
    for (index, (cond, mask, add)) in [
        (Cond::Lt, 0xaa4c_90f6, 0),
        (Cond::Ge, 0xaa4c_90f6, 0),
        (Cond::Gt, 0xaa4c_90f6, 0),
        (Cond::Le, 0xaa4c_90f6, 0),
        (Cond::Cs, 0xffff_fffe, 2),
        (Cond::Cc, 0xffff_fffe, 2),
        (Cond::Hi, 0xffff_fffe, 2),
        (Cond::Ls, 0xffff_fffe, 2),
    ]
    .into_iter()
    .enumerate()
    {
        let masked = Expr::bin(
            BinOp::And,
            Expr::bin(BinOp::And, Expr::reg(7, 64), Expr::Const(mask)),
            Expr::Const(0xffff_ffff),
        );
        let ir = synthetic_ir(
            &format!("masked_selection_{index}"),
            vec![Param {
                index: 7,
                name: "x".into(),
                ty: CType::U64,
            }],
            CType::U64,
            vec![Stmt::Ret {
                value: Expr::Select {
                    cond,
                    lhs: Box::new(if add == 0 {
                        masked
                    } else {
                        Expr::bin(BinOp::Add, masked, Expr::Const(add))
                    }),
                    rhs: Box::new(Expr::Const(112)),
                    then: Box::new(Expr::Const(1)),
                    els: Box::new(Expr::Const(0)),
                },
                at: None,
            }],
        );
        let mut simplified = ir.clone();
        velk::passes::simplify::simplify(&mut simplified);
        let mut candidate = printed_candidate(
            ir,
            [0, 112, 0x8000_0000, 0xaa4c_90f6, u64::MAX]
                .into_iter()
                .map(|x| vec![x])
                .collect(),
        );
        candidate.code = velk::render::render(&simplified, &[], &Default::default(), &[]);
        assert!(candidate.code.contains("int32_t"), "{}", candidate.code);
        candidates.push(candidate);
    }
    check_candidates("masked_selections", candidates, Mode::Registers, &[]);
}

#[test]
fn simplified_branches_keep_zero_extended_bytes_positive() {
    let mut candidates = Vec::new();
    for width in [1, 2] {
        let slot = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const((-8i64) as u64));
        let mut ir = synthetic_ir(
            &format!("zero_extended_branch_{width}"),
            vec![Param {
                index: 7,
                name: "x".into(),
                ty: CType::U64,
            }],
            CType::U64,
            vec![
                Stmt::Store {
                    addr: slot.clone(),
                    value: Expr::reg(7, 64),
                    width,
                    at: None,
                },
                Stmt::Brif {
                    cond: Cond::Lt,
                    lhs: Expr::bin(
                        BinOp::And,
                        Expr::bin(
                            BinOp::And,
                            Expr::Load {
                                addr: Box::new(slot),
                                width,
                                signed: false,
                            },
                            Expr::Const(if width == 1 { 0xff } else { 0xffff }),
                        ),
                        Expr::Const(0xffff_ffff),
                    ),
                    rhs: Expr::Const(35),
                    target: 0x20,
                    at: None,
                },
            ],
        );
        for (start, value) in [(0x10, 1), (0x20, 2)] {
            ir.blocks.push(Block {
                start,
                stmts: vec![Stmt::Ret {
                    value: Expr::Const(value),
                    at: None,
                }],
            });
        }
        let mut simplified = ir.clone();
        velk::passes::simplify::simplify(&mut simplified);
        let mut candidate = printed_candidate(
            ir,
            [0, 34, 35, 127, 128, 251, 32768, 65535]
                .into_iter()
                .map(|x| vec![x])
                .collect(),
        );
        candidate.code = velk::render::render(&simplified, &[], &Default::default(), &[]);
        candidates.push(candidate);
    }
    check_candidates("zero_extended_branches", candidates, Mode::Registers, &[]);
}

#[test]
fn signed_comparisons_keep_their_sign_with_unsigned_positive_operands() {
    let mut candidates = Vec::new();
    let edges = [0, 1, 127, 128, 255, 256, 0x7fff_ffff, 0x8000_0000, u64::MAX];
    let inputs: Vec<_> = edges
        .iter()
        .flat_map(|x| edges.iter().map(move |y| vec![*x, *y]))
        .collect();
    for bits in [32, 64] {
        for byte in [false, true] {
            for reversed in [false, true] {
                for (index, cond) in [Cond::Lt, Cond::Ge, Cond::Gt, Cond::Le]
                    .into_iter()
                    .enumerate()
                {
                    let negative = if byte {
                        Expr::SignExtend {
                            value: Box::new(Expr::reg(7, bits)),
                            width: 1,
                        }
                    } else {
                        Expr::reg(7, bits)
                    };
                    let positive = Expr::bin(BinOp::And, Expr::reg(6, bits), Expr::Const(255));
                    let (lhs, rhs) = if reversed {
                        (positive, negative)
                    } else {
                        (negative, positive)
                    };
                    let ir = synthetic_ir(
                        &format!("signed_positive_{bits}_{byte}_{reversed}_{index}"),
                        vec![
                            Param {
                                index: 7,
                                name: "x".into(),
                                ty: CType::int(bits / 8, true),
                            },
                            Param {
                                index: 6,
                                name: "y".into(),
                                ty: CType::int(bits / 8, false),
                            },
                        ],
                        CType::U64,
                        vec![Stmt::Ret {
                            value: Expr::Select {
                                cond,
                                lhs: Box::new(lhs),
                                rhs: Box::new(rhs),
                                then: Box::new(Expr::Const(1)),
                                els: Box::new(Expr::Const(0)),
                            },
                            at: None,
                        }],
                    );
                    candidates.push(printed_candidate(ir, inputs.clone()));
                }
            }
        }
    }
    check_candidates(
        "signed-positive-comparisons",
        candidates,
        Mode::Registers,
        &[],
    );
}

#[test]
fn declared_destinations_supply_truncated_sign_extensions() {
    let mut candidates = Vec::new();
    for from in [1, 2, 4, 8] {
        for to in [1, 2, 4, 8] {
            for signed in [false, true] {
                for mask in [u64::MAX, 0xffff_ffff, 0x7f] {
                    let ir = synthetic_ir(
                        &format!("truncate_extension_{from}_{to}_{signed}_{mask}"),
                        vec![Param {
                            index: 7,
                            name: "x".into(),
                            ty: CType::U64,
                        }],
                        CType::int(to, signed),
                        vec![Stmt::Ret {
                            value: Expr::bin(
                                BinOp::And,
                                Expr::SignExtend {
                                    value: Box::new(Expr::reg(7, 64)),
                                    width: from,
                                },
                                Expr::Const(mask),
                            ),
                            at: None,
                        }],
                    );
                    let candidate = printed_candidate(
                        ir,
                        [
                            0,
                            1,
                            127,
                            128,
                            255,
                            32767,
                            32768,
                            65535,
                            0x7fff_ffff,
                            0x8000_0000,
                            u64::MAX,
                        ]
                        .into_iter()
                        .map(|x| vec![x])
                        .collect(),
                    );
                    let kept = u64::MAX >> (64 - u32::from(to) * 8);
                    if to <= from && (signed || to > 1) && mask & kept == kept {
                        assert!(candidate.code.contains("return x;"), "{}", candidate.code);
                    }
                    candidates.push(candidate);
                }
            }
        }
    }
    check_candidates(
        "truncated-sign-extensions",
        candidates,
        Mode::Registers,
        &[],
    );
}

#[test]
fn unsigned_entry_copies_use_parameters_only_when_unchanged() {
    let mut binary =
        Binary::open(&common::fixtures_dir().join("metrics/aggregate_abi.x86_64.O0.debug.elf"))
            .unwrap();
    let address = binary.find("abi_pair_adjust").unwrap().addr;
    let original = binary.analysis(address, None).unwrap().ir.clone();
    let inputs: Vec<_> = [0, 1, u64::from(u32::MAX), 1 << 63, u64::MAX]
        .into_iter()
        .map(|x| vec![x, x ^ 1, x])
        .collect();
    let mut candidates = Vec::new();
    for written in [false, true] {
        for name in ["tail", "uint64_t"] {
            let mut ir = original.clone();
            ir.name = Some(format!("unsigned_entry_{written}_{name}"));
            let signature = ir.declared_signature.as_mut().unwrap();
            signature.params[1].0 = name.into();
            let abi = signature.abi.as_ref().unwrap();
            let Passing::Direct(pieces) = &abi.arguments[1].passing else {
                panic!()
            };
            let AbiLocation::Register(register) = pieces[0].location else {
                panic!()
            };
            if written {
                ir.blocks[0].stmts.insert(
                    0,
                    Stmt::Assign {
                        dest: velk::ir::RegRef {
                            index: register,
                            width: 64,
                        },
                        value: Expr::bin(BinOp::Add, Expr::reg(register, 64), Expr::Const(1)),
                        at: None,
                    },
                );
            }
            let projected = aggregate_candidates(ir, inputs.clone(), vec![0; inputs.len()]);
            for candidate in &projected {
                assert_eq!(
                    candidate.code.contains(&format!("uint64_t {name}_bits =")),
                    written,
                    "{}",
                    candidate.code
                );
                assert!(
                    !candidate.code.contains("uint64_t value_bits ="),
                    "{}",
                    candidate.code
                );
            }
            candidates.extend(projected);
        }
    }
    check_candidates("unsigned-entry-copies", candidates, Mode::Registers, &[]);
}

#[test]
fn boolean_returns_keep_truncation_before_testing_for_zero() {
    let ir = synthetic_ir(
        "byte_nonzero",
        vec![Param {
            index: 7,
            name: "x".into(),
            ty: CType::U64,
        }],
        CType::Named("_Bool".into()),
        vec![Stmt::Ret {
            value: Expr::SignExtend {
                value: Box::new(Expr::reg(7, 64)),
                width: 1,
            },
            at: None,
        }],
    );
    let code = velk::render::render(&ir, &[], &Default::default(), &[]);
    syntax::run_printed(&code, "", "return byte_nonzero(256) || !byte_nonzero(128);");
}

#[test]
fn high_products_keep_sign_conversion_and_the_sixty_four_bit_result() {
    let mut candidates = Vec::new();
    let edges = [0, 1, 0x7fff_ffff, 0x8000_0000, 1 << 63, u64::MAX];
    for signed in [false, true] {
        for operand_signed in [false, true] {
            for shift in [0, 1, 63] {
                let ty = CType::int(8, operand_signed);
                let ir = synthetic_ir(
                    &format!("high_product_{signed}_{operand_signed}_{shift}"),
                    vec![
                        Param {
                            index: 7,
                            name: "a".into(),
                            ty: ty.clone(),
                        },
                        Param {
                            index: 6,
                            name: "b".into(),
                            ty,
                        },
                    ],
                    CType::U64,
                    vec![Stmt::Ret {
                        value: Expr::bin(
                            BinOp::Shr,
                            Expr::bin(
                                if signed {
                                    BinOp::MulHighS
                                } else {
                                    BinOp::MulHigh
                                },
                                Expr::reg(7, 64),
                                Expr::reg(6, 64),
                            ),
                            Expr::Const(shift),
                        ),
                        at: None,
                    }],
                );
                let candidate = printed_candidate(
                    ir,
                    edges
                        .iter()
                        .flat_map(|a| edges.iter().map(move |b| vec![*a, *b]))
                        .collect(),
                );
                if signed == operand_signed {
                    assert!(!candidate.code.contains("(int64_t)a"), "{}", candidate.code);
                    assert!(
                        !candidate.code.contains("(uint64_t)a"),
                        "{}",
                        candidate.code
                    );
                    assert!(!candidate.code.contains("(int64_t)b"), "{}", candidate.code);
                    assert!(
                        !candidate.code.contains("(uint64_t)b"),
                        "{}",
                        candidate.code
                    );
                }
                candidates.push(candidate);
            }
        }
    }
    check_candidates("typed-high-products", candidates, Mode::Registers, &[]);
}

#[test]
fn high_products_use_the_destination_conversion_only_at_the_assignment_boundary() {
    let mut candidates = Vec::new();
    for signed in [false, true] {
        for bits in [32, 64] {
            for nested in [false, true] {
                let product = Expr::bin(
                    if signed {
                        BinOp::MulHighS
                    } else {
                        BinOp::MulHigh
                    },
                    Expr::reg(7, 64),
                    Expr::reg(6, 64),
                );
                let value = if nested {
                    Expr::bin(BinOp::Shr, product, Expr::Const(1))
                } else {
                    product
                };
                let candidate = printed_candidate(
                    synthetic_ir(
                        &format!("high_destination_{signed}_{bits}_{nested}"),
                        vec![
                            Param {
                                index: 7,
                                name: "a".into(),
                                ty: CType::int(8, signed),
                            },
                            Param {
                                index: 6,
                                name: "b".into(),
                                ty: CType::int(8, signed),
                            },
                        ],
                        CType::int(bits / 8, signed),
                        vec![Stmt::Ret { value, at: None }],
                    ),
                    [0, 1, 1 << 31, 1 << 63, u64::MAX]
                        .into_iter()
                        .flat_map(|a| [0, 1, 1 << 63, u64::MAX].map(|b| vec![a, b]))
                        .collect(),
                );
                if !nested {
                    assert!(
                        !candidate.code.contains("return (uint64_t)"),
                        "{}",
                        candidate.code
                    );
                    assert!(
                        !candidate.code.contains("return (int64_t)"),
                        "{}",
                        candidate.code
                    );
                }
                candidates.push(candidate);
            }
        }
    }
    check_candidates(
        "high-product-destinations",
        candidates,
        Mode::Registers,
        &[],
    );
}

#[test]
fn double_arithmetic_keeps_one_double_operand_and_integer_signedness() {
    let mut candidates = Vec::new();
    for signed in [false, true] {
        let converted = Expr::Apply {
            op: Operation::IntToFloat {
                signed,
                bits: 32,
                to: Precision::Double,
            },
            args: vec![Expr::reg(7, 32)],
        };
        let value = Expr::Apply {
            op: Operation::FloatToInt {
                signed: true,
                bits: 64,
                from: Precision::Double,
                rounding: velk::ir::Rounding::TowardZero,
                saturating: false,
            },
            args: vec![Expr::Apply {
                op: Operation::FloatDiv(Precision::Double),
                args: vec![converted, Expr::Const(2.0f64.to_bits())],
            }],
        };
        let candidate = printed_candidate(
            synthetic_ir(
                &format!("implicit_double_{signed}"),
                vec![Param {
                    index: 7,
                    name: "x".into(),
                    ty: CType::int(4, signed),
                }],
                CType::int(8, true),
                vec![Stmt::Ret { value, at: None }],
            ),
            [0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff]
                .map(|x| vec![x])
                .to_vec(),
        );
        assert!(candidate.code.contains("x / 2.0"), "{}", candidate.code);
        assert!(!candidate.code.contains("(double)x"), "{}", candidate.code);
        candidates.push(candidate);
    }
    let widened = |value: f32| Expr::Apply {
        op: Operation::FloatConvert {
            from: Precision::Single,
            to: Precision::Double,
        },
        args: vec![Expr::Const(u64::from(value.to_bits()))],
    };
    let value = Expr::Apply {
        op: Operation::FloatToInt {
            signed: true,
            bits: 64,
            from: Precision::Double,
            rounding: velk::ir::Rounding::TowardZero,
            saturating: false,
        },
        args: vec![Expr::Apply {
            op: Operation::FloatAdd(Precision::Double),
            args: vec![widened(16_777_216.0), widened(1.0)],
        }],
    };
    let candidate = printed_candidate(
        synthetic_ir(
            "double_from_two_floats",
            vec![],
            CType::int(8, true),
            vec![Stmt::Ret { value, at: None }],
        ),
        vec![vec![]],
    );
    assert_eq!(
        candidate.code.matches("(double)").count(),
        1,
        "{}",
        candidate.code
    );
    candidates.push(candidate);
    check_candidates("implicit-double-operands", candidates, Mode::Registers, &[]);
}

#[test]
fn floating_assignments_supply_conversions_and_keep_arithmetic_precision() {
    use velk::ir::{Operation, Precision, RegRef, VARIABLE_BASE};

    for (from, to) in [
        (Precision::Single, Precision::Double),
        (Precision::Double, Precision::Single),
    ] {
        let source = if from == Precision::Single {
            "float"
        } else {
            "double"
        };
        let target = if to == Precision::Single {
            "float"
        } else {
            "double"
        };
        let ir = synthetic_ir(
            "converted_sum",
            vec![Param {
                index: 7,
                name: "x".into(),
                ty: CType::Named(source.into()),
            }],
            CType::Named(target.into()),
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: VARIABLE_BASE,
                        width: to.bits(),
                    },
                    value: Expr::Apply {
                        op: Operation::FloatConvert { from, to },
                        args: vec![Expr::reg(7, from.bits())],
                    },
                    at: None,
                },
                Stmt::Ret {
                    value: Expr::Apply {
                        op: Operation::FloatAdd(to),
                        args: vec![Expr::reg(VARIABLE_BASE, to.bits()); 2],
                    },
                    at: None,
                },
            ],
        );
        let code = velk::render::render(&ir, &[], &Default::default(), &[]);
        assert!(code.contains(&format!("{target} v1 = x;")), "{code}");
        assert!(code.contains("return v1 + v1;"), "{code}");
        syntax::run_printed(
            &code,
            "",
            &format!(
                "{source} values[] = {{0.0, -0.0, 1.0, 0x1.000001p0, 0x1.fffffep127}}; for (unsigned i = 0; i < sizeof(values)/sizeof(values[0]); ++i) {{ {target} x = values[i]; if (converted_sum(values[i]) != x + x) return 1; }} return 0;"
            ),
        );
    }
}

#[test]
fn derived_structure_pointers_keep_validated_field_types() {
    use velk::ir::{AbiProfile, Definition, Member, RegRef, VARIABLE_BASE};

    let mut candidates = Vec::new();
    for offset in [0, 2] {
        for duplicate in [false, true] {
            let mut ir = synthetic_ir(
                &format!("derived_fields_{offset}_{duplicate}"),
                vec![
                    Param {
                        index: 7,
                        name: "items".into(),
                        ty: CType::pointer_to(CType::Named("struct item".into())),
                    },
                    Param {
                        index: 6,
                        name: "i".into(),
                        ty: CType::U32,
                    },
                ],
                CType::U64,
                vec![
                    Stmt::Assign {
                        dest: RegRef {
                            index: VARIABLE_BASE,
                            width: 64,
                        },
                        value: Expr::bin(
                            BinOp::Add,
                            Expr::reg(7, 64),
                            Expr::bin(
                                BinOp::Add,
                                Expr::bin(BinOp::Mul, Expr::reg(6, 32), Expr::Const(8)),
                                Expr::Const(offset),
                            ),
                        ),
                        at: None,
                    },
                    Stmt::Ret {
                        value: Expr::bin(
                            BinOp::Add,
                            Expr::Load {
                                addr: Box::new(Expr::reg(VARIABLE_BASE, 64)),
                                width: 4,
                                signed: false,
                            },
                            Expr::Load {
                                addr: Box::new(Expr::bin(
                                    BinOp::Add,
                                    Expr::reg(VARIABLE_BASE, 64),
                                    Expr::Const(4),
                                )),
                                width: 2,
                                signed: true,
                            },
                        ),
                        at: None,
                    },
                ],
            );
            ir.definitions.push(Definition {
                name: "struct item".into(),
                members: vec![
                    "uint32_t count;".into(),
                    "int16_t kind;".into(),
                    "uint8_t gap_0x6[0x2];".into(),
                ],
                fields: vec!["count".into(), "kind".into()],
                contains: vec![],
                size: 8,
                alignment: Some(4),
                compatible_profiles: vec![AbiProfile::SysV],
            });
            ir.members.extend([
                Member {
                    structure: "item".into(),
                    offset: 0,
                    name: "count".into(),
                    ty: CType::U32,
                    width: 4,
                },
                Member {
                    structure: "item".into(),
                    offset: 4,
                    name: "kind".into(),
                    ty: CType::int(2, true),
                    width: 2,
                },
            ]);
            if duplicate {
                ir.definitions.push(ir.definitions[0].clone());
            }
            let candidate = printed_candidate(ir, [0, 1, 2].map(|i| vec![REGION + 16, i]).to_vec());
            if offset == 0 && !duplicate {
                assert!(
                    candidate.code.contains("struct item *v1 = items + i;"),
                    "{}",
                    candidate.code
                );
                assert!(candidate.code.contains("v1->kind"), "{}", candidate.code);
            } else {
                assert!(
                    !candidate.code.contains("struct item *v1"),
                    "{}",
                    candidate.code
                );
            }
            candidates.push(candidate);
        }
    }
    check_candidates("derived-structure-fields", candidates, Mode::Memory, &[]);
}

#[test]
fn aligned_byte_offsets_use_typed_pointers_only_for_proven_multiples() {
    use velk::ir::{RegRef, VARIABLE_BASE};

    let offset = VARIABLE_BASE;
    let count = offset + 1;
    let sum = offset + 2;
    let mut candidates = Vec::new();
    for stride in [6, 32] {
        for initial in [Some(0), Some(2), None] {
            let mut ir = synthetic_ir(
                &format!("aligned_offsets_{stride}_{initial:?}"),
                vec![
                    Param {
                        index: 7,
                        name: "p".into(),
                        ty: CType::pointer_to(CType::I32),
                    },
                    Param {
                        index: 6,
                        name: "start".into(),
                        ty: CType::U64,
                    },
                ],
                CType::U64,
                vec![
                    Stmt::Assign {
                        dest: RegRef {
                            index: offset,
                            width: 64,
                        },
                        value: initial.map_or(Expr::reg(6, 64), Expr::Const),
                        at: None,
                    },
                    Stmt::Assign {
                        dest: RegRef {
                            index: count,
                            width: 64,
                        },
                        value: Expr::Const(2),
                        at: None,
                    },
                    Stmt::Assign {
                        dest: RegRef {
                            index: sum,
                            width: 64,
                        },
                        value: Expr::Const(0),
                        at: None,
                    },
                    Stmt::Br {
                        target: Some(1),
                        at: None,
                    },
                ],
            );
            ir.blocks.extend([
                Block {
                    start: 1,
                    stmts: vec![Stmt::Brif {
                        cond: Cond::Eq,
                        lhs: Expr::reg(count, 64),
                        rhs: Expr::Const(0),
                        target: 3,
                        at: None,
                    }],
                },
                Block {
                    start: 2,
                    stmts: vec![
                        Stmt::Assign {
                            dest: RegRef {
                                index: sum,
                                width: 64,
                            },
                            value: Expr::bin(
                                BinOp::Add,
                                Expr::reg(sum, 64),
                                Expr::Load {
                                    addr: Box::new(Expr::bin(
                                        BinOp::Add,
                                        Expr::reg(7, 64),
                                        Expr::reg(offset, 64),
                                    )),
                                    width: 8,
                                    signed: false,
                                },
                            ),
                            at: None,
                        },
                        Stmt::Assign {
                            dest: RegRef {
                                index: offset,
                                width: 64,
                            },
                            value: Expr::bin(
                                BinOp::Add,
                                Expr::reg(offset, 64),
                                Expr::Const(stride),
                            ),
                            at: None,
                        },
                        Stmt::Assign {
                            dest: RegRef {
                                index: count,
                                width: 64,
                            },
                            value: Expr::bin(BinOp::Sub, Expr::reg(count, 64), Expr::Const(1)),
                            at: None,
                        },
                        Stmt::Br {
                            target: Some(1),
                            at: None,
                        },
                    ],
                },
                Block {
                    start: 3,
                    stmts: vec![Stmt::Ret {
                        value: Expr::reg(sum, 64),
                        at: None,
                    }],
                },
            ]);
            ir.name = Some(ir.name.as_ref().unwrap().replace(['(', ')', ':'], "_"));
            ir.value_types.insert(offset, CType::I64);
            let candidate =
                printed_candidate(ir, [0, 2, 4].map(|start| vec![REGION + 16, start]).to_vec());
            assert_eq!(
                candidate.code.contains("(uint8_t *)p"),
                stride != 32 || initial != Some(0),
                "{}",
                candidate.code
            );
            candidates.push(candidate);
        }
    }
    check_candidates("aligned-byte-offsets", candidates, Mode::Memory, &[]);
}

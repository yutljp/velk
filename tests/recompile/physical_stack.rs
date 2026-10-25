use super::*;

pub(super) fn physical_stack_signature(ir: &FunctionIr) -> Option<DeclaredSignature> {
    let profile = match (ir.isa, ir.convention) {
        (Isa::AArch64, Convention::Aapcs64) => AbiProfile::Aapcs64,
        (Isa::X86_64, Convention::SysV) => AbiProfile::SysV,
        (
            Isa::I386,
            Convention::Cdecl | Convention::Stdcall | Convention::Fastcall | Convention::Thiscall,
        ) => AbiProfile::SysV,
        (Isa::X86_64, Convention::Win64) => AbiProfile::Win64,
        _ => return None,
    };
    let bytes = velk::arch::pointer_bytes(ir.isa);
    let scalar_integer = |ty: &CType| {
        if ir.isa == Isa::I386 {
            ty.integer().is_some_and(|(bits, _)| bits == 32)
        } else {
            matches!(ty, CType::Int { bytes: width, .. } if *width == bytes)
        }
    };
    if (ir.isa != Isa::I386 && ir.declared_signature.is_some())
        || ir.variadic
        || ir.stack_params.is_empty()
        || ir.params.len() + ir.stack_params.len() > 16
        || !scalar_integer(&ir.ret_type)
        || !ir.params.iter().all(|param| scalar_integer(&param.ty))
    {
        return None;
    }
    let registers = ir.convention.arguments();
    if !ir.params.iter().enumerate().all(|(position, param)| {
        registers
            .get(position)
            .is_some_and(|index| *index == param.index)
    }) {
        return None;
    }
    let Some(start) = ir.convention.stack_arguments() else {
        return None;
    };
    if !ir.stack_params.iter().enumerate().all(|(slot, param)| {
        param.offset == start + slot as i64 * i64::from(bytes)
            && param.size == u64::from(bytes)
            && scalar_integer(&param.ty)
            && param.position == ir.params.len() + slot
    }) {
        return None;
    }
    let scalar = |location| ValueAbi {
        aggregate: false,
        size: u64::from(bytes),
        alignment: u64::from(bytes),
        defined_bits: vec![(0, u64::from(bytes) * 8)],
        passing: Passing::Direct(vec![AbiPiece {
            location,
            object_offset: 0,
            bytes: u64::from(bytes),
            class: if matches!(location, AbiLocation::Register(_)) {
                Some(RegisterClass::Integer)
            } else {
                None
            },
        }]),
    };
    Some(DeclaredSignature {
        params: ir
            .params
            .iter()
            .map(|param| (param.name.clone(), param.ty.clone()))
            .chain(
                ir.stack_params
                    .iter()
                    .map(|param| (param.name.clone(), param.ty.clone())),
            )
            .collect(),
        ret: ir.ret_type.clone(),
        variadic: false,
        abi: Ok(SignatureAbi {
            profile,
            arguments: ir
                .params
                .iter()
                .map(|param| AbiLocation::Register(param.index))
                .chain(
                    ir.stack_params
                        .iter()
                        .map(|param| AbiLocation::Stack(param.offset)),
                )
                .map(scalar)
                .collect(),
            result: Some(scalar(AbiLocation::Register(0))),
        }),
    })
}

pub(super) fn physical_stack_call(ir: &FunctionIr, rows: usize) -> Option<AggregateCall> {
    let Some(signature) = physical_stack_signature(ir) else {
        return None;
    };
    let bytes = velk::arch::pointer_bytes(ir.isa);
    Some(AggregateCall {
        signature,
        result: ObjectSlice {
            offset: 0,
            bytes,
            mask: if bytes == 4 {
                u64::from(u32::MAX)
            } else {
                u64::MAX
            },
        },
        upper_bits: vec![0; rows],
    })
}

pub(super) fn incoming_stack_word(trial: u64, offset: i64) -> u64 {
    let address = eval::STACK_TOP.wrapping_add_signed(offset);
    u64::from_le_bytes(std::array::from_fn(|byte| {
        eval::hash(trial, address + byte as u64) as u8
    }))
}

pub(super) fn physical_scalar_stack_calls_require_complete_bounded_slots() {
    let ir = recovered_stack_test_ir(
        "physical_stack_contract",
        vec![Stmt::Ret {
            value: Expr::reg(0, 64),
        }],
    );
    let locations = |signature: DeclaredSignature| {
        signature
            .abi
            .unwrap()
            .arguments
            .into_iter()
            .map(|value| {
                let Passing::Direct(pieces) = value.passing else {
                    panic!("a direct scalar")
                };
                assert_eq!(pieces.len(), 1);
                pieces[0].location
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        locations(physical_stack_signature(&ir).unwrap()),
        (0..7)
            .map(AbiLocation::Register)
            .chain([0, 8, 16].map(AbiLocation::Stack))
            .collect::<Vec<_>>()
    );
    let mut sysv = scalar_stack_ir(
        "sysv_physical_stack_contract",
        3,
        vec![Stmt::Ret {
            value: Expr::reg(7, 64),
        }],
    );
    sysv.declared_signature = None;
    assert_eq!(
        locations(physical_stack_signature(&sysv).unwrap()),
        [7, 6, 2, 1, 8, 9]
            .map(AbiLocation::Register)
            .into_iter()
            .chain([8, 16, 24].map(AbiLocation::Stack))
            .collect::<Vec<_>>()
    );
    for change in 0..11 {
        let mut invalid = ir.clone();
        match change {
            0 => invalid.stack_params[0].size = 16,
            1 => invalid.stack_params[0].ty = CType::U32,
            2 => invalid.stack_params[1].offset = 16,
            3 => invalid.stack_params[0].offset = -8,
            4 => invalid.stack_params[0].position = 8,
            5 => invalid.params[0].ty = CType::U32,
            6 => invalid.variadic = true,
            7 => invalid.ret_type = CType::U32,
            8 => invalid.params[1].index = 2,
            9 => invalid.convention = Convention::Win64,
            10 => {
                invalid.stack_params = (0..10)
                    .map(|slot| velk::ir::StackParam {
                        offset: slot as i64 * 8,
                        size: 8,
                        name: format!("s{slot}"),
                        ty: CType::U64,
                        position: 7 + slot,
                    })
                    .collect()
            }
            _ => unreachable!(),
        }
        assert!(
            physical_stack_signature(&invalid).is_none(),
            "change {change}"
        );
    }
    let mut invalid = ir.clone();
    invalid.declared_signature = physical_stack_signature(&ir);
    assert!(physical_stack_signature(&invalid).is_none());
}

pub(super) fn printed_stripped_stack_fixtures_preserve_all_physical_inputs() {
    let mut candidates = Vec::new();
    for (optimization, addresses) in [("O0", [0x210468, 0x210628]), ("O2", [0x210290, 0x210338])] {
        let fixture = PathBuf::from(format!(
            "metrics/aggregate_abi.aarch64.{optimization}.stripped.elf"
        ));
        let prepared = prepare(&fixture, Mode::Memory);
        for address in addresses {
            let path = common::fixtures_dir().join(&fixture);
            let mut binary = Binary::open(&path).unwrap();
            let analysis = binary.analysis(address, None).unwrap();
            assert!(analysis.references.is_empty());
            let ir = analysis.ir.clone();
            assert_eq!(
                ir.params
                    .iter()
                    .map(|param| param.index)
                    .collect::<Vec<_>>(),
                vec![0, 1, 2, 3, 4, 5, 6]
            );
            assert_eq!(
                ir.stack_params
                    .iter()
                    .map(|param| (param.offset, param.size, param.position))
                    .collect::<Vec<_>>(),
                vec![(0, 8, 7), (8, 8, 8), (16, 8, 9)]
            );
            assert!(ir.declared_signature.is_none());
            assert!(ir.structures.is_empty());
            assert_eq!(qualifies(&ir, true, Mode::Memory), Ok(()));
            let original = prepared
                .candidates
                .iter()
                .find(|candidate| candidate.ir.addr == address)
                .unwrap_or_else(|| panic!("{optimization} {address:#x} was excluded"));
            assert_eq!(original.inputs.len(), trials::TRIALS as usize);
            assert!(original.marshalling.is_some());
            for (trial, input) in original.inputs.iter().enumerate() {
                let registers = trials::registers(binary.image(), trial as u64);
                let expected: Vec<_> = (0..7)
                    .map(|index| {
                        registers
                            .iter()
                            .find(|(register, _)| *register == index)
                            .unwrap()
                            .1
                    })
                    .chain([0, 8, 16].map(|offset| incoming_stack_word(trial as u64, offset)))
                    .collect();
                assert_eq!(*input, expected);
            }
            let mut candidate = Candidate {
                label: original.label.clone(),
                ir: ir.clone(),
                code: original.code.clone(),
                segment_bases: original.segment_bases.clone(),
                states: Vec::new(),
                marshalling: physical_stack_call(&ir, 24),
                params: original.params.clone(),
                inputs: original.inputs.clone(),
                void: false,
            };
            candidate.inputs.push(vec![0; 10]);
            candidate.inputs.push(vec![u64::MAX; 10]);
            for position in 0..10 {
                let mut input = vec![0; 10];
                input[position] = 1;
                candidate.inputs.push(input);
            }
            assert_eq!(candidate.inputs.len(), 24);
            assert_aggregate_oracle(std::slice::from_ref(&candidate), |input, _| {
                input
                    .iter()
                    .zip([1u64, 3, 5, 7, 11, 13, 17, 19, 23, 29])
                    .fold(0u64, |sum, (value, coefficient)| {
                        sum.wrapping_add(value.wrapping_mul(coefficient))
                    })
            });
            assert_eq!(
                candidate.code,
                binary.decompile(address, None, None).unwrap()
            );
            candidates.push(candidate);
        }
    }
    assert_eq!(candidates.len(), 4);
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.inputs.len())
            .sum::<usize>(),
        96
    );
    check_candidates("stripped-stack-fixtures", candidates, Mode::Memory, &[]);
}

fn recovered_stack_test_ir(name: &str, stmts: Vec<Stmt>) -> FunctionIr {
    let mut ir = synthetic_ir(
        name,
        (0..7)
            .map(|index| Param {
                index,
                name: format!("r{index}"),
                ty: CType::U64,
            })
            .collect(),
        CType::U64,
        stmts,
    );
    ir.isa = Isa::AArch64;
    ir.convention = Convention::Aapcs64;
    ir.stack_params = (0..3)
        .map(|slot| velk::ir::StackParam {
            offset: slot as i64 * 8,
            size: 8,
            name: format!("s{slot}"),
            ty: if slot == 1 { CType::I64 } else { CType::U64 },
            position: 7 + slot,
        })
        .collect();
    ir
}

pub(super) fn printed_stack_bytes_preserve_read_write_order_and_slot_boundaries() {
    let address = |offset| Expr::bin(BinOp::Add, Expr::reg(31, 64), Expr::Const(offset));
    let load = |offset, width| Expr::Load {
        addr: Box::new(address(offset)),
        width,
        signed: false,
    };
    let mut candidates = Vec::new();
    for (kind, widths) in [
        ("read", vec![1u8, 2, 4, 8]),
        ("read_then_write", vec![1, 2, 4, 8]),
        ("write_then_read", vec![1, 2, 4, 8]),
        ("cross_write", vec![2, 4, 8]),
        ("cross_read", vec![8]),
    ] {
        for width in widths {
            let offset = if kind == "cross_write" {
                7
            } else if width == 8 {
                0
            } else {
                1
            };
            let result = velk::ir::VARIABLE_BASE;
            let mut stmts = Vec::new();
            if matches!(kind, "read" | "cross_read" | "read_then_write") {
                stmts.push(Stmt::Assign {
                    dest: velk::ir::RegRef {
                        index: result,
                        width: 64,
                    },
                    value: load(
                        if kind == "cross_read" { 4 } else { offset },
                        if kind == "read_then_write" { 8 } else { width },
                    ),
                });
            }
            if matches!(kind, "read_then_write" | "write_then_read" | "cross_write") {
                stmts.push(Stmt::Store {
                    addr: address(offset),
                    value: Expr::reg(0, 64),
                    width,
                });
            }
            if matches!(kind, "write_then_read" | "cross_write") {
                stmts.push(Stmt::Assign {
                    dest: velk::ir::RegRef {
                        index: result,
                        width: 64,
                    },
                    value: load(0, 8),
                });
            }
            for part in 0..3 {
                stmts.push(Stmt::Store {
                    addr: Expr::Const(REGION + 0x1a00 + part * 8),
                    value: load(part * 8, 8),
                    width: 8,
                });
            }
            stmts.push(Stmt::Ret {
                value: Expr::reg(result, 64),
            });
            let mut ir = recovered_stack_test_ir(&format!("stack_bytes_{kind}_{width}"), stmts);
            if kind == "cross_read" {
                ir.params[0].name = "constexpr".to_owned();
                ir.stack_params[0].name = "nullptr".to_owned();
            }
            let mut inputs = Vec::new();
            for trial in 0..12u32 {
                let mut row = vec![0; 10];
                row[0] = 0x96a5_3cc3_f00f_5a69u64.rotate_left(trial * 5);
                row[7] = 0x0706_0504_0302_0100u64.rotate_left(trial * 3);
                row[8] = 0x8f8e_8d8c_8b8a_8988u64.rotate_right(trial * 7);
                row[9] = 0xf7f6_f5f4_f3f2_f1f0u64.rotate_left(trial * 11);
                inputs.push(row);
            }
            let mut candidate = printed_candidate(ir, inputs);
            if kind == "cross_read" {
                assert!(
                    candidate.code.contains("uint64_t constexpr_2"),
                    "{}",
                    candidate.code
                );
                assert!(
                    candidate.code.contains("uint64_t nullptr_2"),
                    "{}",
                    candidate.code
                );
            }
            let call = physical_stack_call(&candidate.ir, 12).unwrap();
            candidate.params = call
                .signature
                .params
                .iter()
                .map(|(_, ty)| ty.to_string())
                .collect();
            candidate.marshalling = Some(call);
            let fixture = Fixture {
                name: "stack byte oracle".into(),
                convention: eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                entry_registers: Vec::new(),
                initial_memory: Vec::new(),
                functions: 1,
                excluded: BTreeMap::new(),
                candidates: Vec::new(),
            };
            for (trial, input) in candidate.inputs.iter().enumerate() {
                let before: Vec<_> = input[7..]
                    .iter()
                    .flat_map(|word| word.to_le_bytes())
                    .collect();
                let mut after = before.clone();
                if matches!(kind, "read_then_write" | "write_then_read" | "cross_write") {
                    let offset = offset as usize;
                    after[offset..offset + usize::from(width)]
                        .copy_from_slice(&input[0].to_le_bytes()[..usize::from(width)]);
                }
                let (bytes, offset, count) = match kind {
                    "read" => (&before, offset as usize, usize::from(width)),
                    "cross_read" => (&before, 4, 8),
                    "read_then_write" => (&before, offset as usize, 8),
                    _ => (&after, 0, 8),
                };
                let mut returned = [0; 8];
                returned[..count].copy_from_slice(&bytes[offset..offset + count]);
                let expected = Outcome::Return {
                    value: u64::from_le_bytes(returned),
                    calls: Vec::new(),
                    memory: after
                        .into_iter()
                        .enumerate()
                        .map(|(byte, value)| (REGION + 0x1a00 + byte as u64, value))
                        .collect(),
                };
                assert_eq!(
                    interpret(&fixture, &candidate, trial as u64, input, Mode::Registers).unwrap(),
                    expected,
                    "{} trial {trial}",
                    candidate.label
                );
            }
            candidates.push(candidate);
        }
    }
    assert_eq!(candidates.len(), 16);
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.inputs.len())
            .sum::<usize>(),
        192
    );
    check_candidates(
        "stack-byte-boundaries",
        candidates,
        Mode::Memory,
        &["-fsanitize=alignment", "-fno-sanitize-recover=alignment"],
    );
}

pub(super) fn printed_stack_cross_slot_scalar_views_preserve_bits_and_frame_locations() {
    let address = |offset| Expr::bin(BinOp::Add, Expr::reg(31, 64), Expr::Const(offset));
    let load = |offset, width, signed| Expr::Load {
        addr: Box::new(address(offset)),
        width,
        signed,
    };
    let result = velk::ir::VARIABLE_BASE;
    let second = result + 1;
    let mut candidates = Vec::new();
    for kind in ["signed32", "float32", "float64", "changed_frame"] {
        let mut stmts = Vec::new();
        match kind {
            "signed32" => {
                stmts.push(Stmt::Assign {
                    dest: velk::ir::RegRef {
                        index: result,
                        width: 64,
                    },
                    value: load(7, 4, true),
                });
                stmts.push(Stmt::Store {
                    addr: Expr::Const(REGION + 0x1b00),
                    value: Expr::reg(result, 64),
                    width: 8,
                });
            }
            "float32" | "float64" => {
                let (offset, width, precision, half) = if kind == "float32" {
                    (7, 4, Precision::Single, u64::from(0.5f32.to_bits()))
                } else {
                    (4, 8, Precision::Double, 0.5f64.to_bits())
                };
                stmts.push(Stmt::Assign {
                    dest: velk::ir::RegRef {
                        index: result,
                        width: 64,
                    },
                    value: Expr::Apply {
                        op: Operation::FloatLess(precision),
                        args: vec![load(offset, width, false), Expr::Const(half)],
                    },
                });
                stmts.push(Stmt::Store {
                    addr: Expr::Const(REGION + 0x1b00),
                    value: Expr::Apply {
                        op: Operation::FloatNegate(precision),
                        args: vec![load(offset, width, false)],
                    },
                    width,
                });
            }
            "changed_frame" => {
                stmts.push(Stmt::Assign {
                    dest: velk::ir::RegRef {
                        index: result,
                        width: 64,
                    },
                    value: load(4, 8, false),
                });
                stmts.push(Stmt::Assign {
                    dest: velk::ir::RegRef {
                        index: 31,
                        width: 64,
                    },
                    value: address(8),
                });
                stmts.push(Stmt::Assign {
                    dest: velk::ir::RegRef {
                        index: second,
                        width: 64,
                    },
                    value: load(4, 8, false),
                });
                stmts.push(Stmt::Assign {
                    dest: velk::ir::RegRef {
                        index: 31,
                        width: 64,
                    },
                    value: Expr::bin(BinOp::Sub, Expr::reg(31, 64), Expr::Const(8)),
                });
                for (part, register) in [result, second].into_iter().enumerate() {
                    stmts.push(Stmt::Store {
                        addr: Expr::Const(REGION + 0x1b00 + part as u64 * 8),
                        value: Expr::reg(register, 64),
                        width: 8,
                    });
                }
                stmts.push(Stmt::Assign {
                    dest: velk::ir::RegRef {
                        index: result,
                        width: 64,
                    },
                    value: Expr::bin(BinOp::Xor, Expr::reg(result, 64), Expr::reg(second, 64)),
                });
            }
            _ => unreachable!(),
        }
        for part in 0..3 {
            stmts.push(Stmt::Store {
                addr: Expr::Const(REGION + 0x1a00 + part * 8),
                value: load(part * 8, 8, false),
                width: 8,
            });
        }
        stmts.push(Stmt::Ret {
            value: Expr::reg(result, 64),
        });
        let ir = recovered_stack_test_ir(&format!("stack_cross_view_{kind}"), stmts);
        let mut inputs = Vec::new();
        for trial in 0..12u32 {
            let mut row = vec![0; 10];
            let mut bytes: Vec<_> = [
                0x0706_0504_0302_0100u64.rotate_left(trial * 3),
                0x8f8e_8d8c_8b8a_8988u64.rotate_right(trial * 7),
                0xf7f6_f5f4_f3f2_f1f0u64.rotate_left(trial * 11),
            ]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
            let (offset, width, raw) = match kind {
                "signed32" => (
                    7,
                    4,
                    [
                        0,
                        1,
                        0x7fff_ffff,
                        0x8000_0000,
                        0xffff_ffff,
                        0x8000_0001,
                        0x1234_5678,
                        0x9234_5678,
                        0x0102_0304,
                        0x8102_0304,
                        0x55aa_c33c,
                        0xd5aa_c33c,
                    ][trial as usize],
                ),
                "float32" => (
                    7,
                    4,
                    u64::from(
                        [
                            0.0f32.to_bits(),
                            (-0.0f32).to_bits(),
                            1.25f32.to_bits(),
                            (-1.25f32).to_bits(),
                            0.5f32.to_bits(),
                            (-0.5f32).to_bits(),
                            f32::INFINITY.to_bits(),
                            f32::NEG_INFINITY.to_bits(),
                            0x7fc1_2345,
                            0xffc5_4321,
                            1,
                            0x8000_0001,
                        ][trial as usize],
                    ),
                ),
                "float64" => (
                    4,
                    8,
                    [
                        0.0f64.to_bits(),
                        (-0.0f64).to_bits(),
                        1.25f64.to_bits(),
                        (-1.25f64).to_bits(),
                        0.5f64.to_bits(),
                        (-0.5f64).to_bits(),
                        f64::INFINITY.to_bits(),
                        f64::NEG_INFINITY.to_bits(),
                        0x7ff8_1234_5678_9abc,
                        0xfff8_abcd_0123_4567,
                        1,
                        0x8000_0000_0000_0001,
                    ][trial as usize],
                ),
                "changed_frame" => (0, 0, 0),
                _ => unreachable!(),
            };
            bytes[offset..offset + width].copy_from_slice(&raw.to_le_bytes()[..width]);
            for (slot, word) in bytes.as_chunks::<8>().0.iter().enumerate() {
                row[7 + slot] = u64::from_le_bytes(*word);
            }
            inputs.push(row);
        }
        let mut candidate = printed_candidate(ir, inputs);
        let call = physical_stack_call(&candidate.ir, 12).unwrap();
        candidate.params = call
            .signature
            .params
            .iter()
            .map(|(_, ty)| ty.to_string())
            .collect();
        candidate.marshalling = Some(call);
        let fixture = Fixture {
            name: "stack cross view oracle".into(),
            convention: eval::Convention {
                arguments: &[],
                clobbered: &[],
            },
            entry_registers: Vec::new(),
            initial_memory: Vec::new(),
            functions: 1,
            excluded: BTreeMap::new(),
            candidates: Vec::new(),
        };
        for (trial, input) in candidate.inputs.iter().enumerate() {
            let bytes: Vec<_> = input[7..]
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect();
            let word = |offset, count| {
                let mut raw = [0; 8];
                raw[..count].copy_from_slice(&bytes[offset..offset + count]);
                u64::from_le_bytes(raw)
            };
            let (returned, observed) = match kind {
                "signed32" => {
                    let value = (word(7, 4) as u32 as i32) as i64 as u64;
                    (value, value.to_le_bytes().to_vec())
                }
                "float32" => {
                    let raw = word(7, 4) as u32;
                    (
                        u64::from(f32::from_bits(raw) < 0.5),
                        (raw ^ 0x8000_0000).to_le_bytes().to_vec(),
                    )
                }
                "float64" => {
                    let raw = word(4, 8);
                    (
                        u64::from(f64::from_bits(raw) < 0.5),
                        (raw ^ 0x8000_0000_0000_0000).to_le_bytes().to_vec(),
                    )
                }
                "changed_frame" => {
                    let first = word(4, 8);
                    let second = word(12, 8);
                    assert_ne!(
                        first, second,
                        "trial {trial} must distinguish frame locations"
                    );
                    (
                        first ^ second,
                        first
                            .to_le_bytes()
                            .into_iter()
                            .chain(second.to_le_bytes())
                            .collect(),
                    )
                }
                _ => unreachable!(),
            };
            let expected = Outcome::Return {
                value: returned,
                calls: Vec::new(),
                memory: bytes
                    .into_iter()
                    .enumerate()
                    .map(|(byte, value)| (REGION + 0x1a00 + byte as u64, value))
                    .chain(
                        observed
                            .into_iter()
                            .enumerate()
                            .map(|(byte, value)| (REGION + 0x1b00 + byte as u64, value)),
                    )
                    .collect(),
            };
            assert_eq!(
                interpret(&fixture, &candidate, trial as u64, input, Mode::Registers).unwrap(),
                expected,
                "{} trial {trial}",
                candidate.label
            );
        }
        candidates.push(candidate);
    }
    assert_eq!(candidates.len(), 4);
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.inputs.len())
            .sum::<usize>(),
        48
    );
    check_candidates(
        "stack-cross-slot-views",
        candidates,
        Mode::Memory,
        &["-fsanitize=alignment", "-fno-sanitize-recover=alignment"],
    );
}

pub(super) fn printed_stripped_x86_stack_fixtures_preserve_held_alias_inputs() {
    let mut candidates = Vec::new();
    for (optimization, addresses) in [
        ("O0", [0x201420, 0x201480, 0x201540, 0x2015a0]),
        ("O2", [0x2012c0, 0x201320, 0x2013c0, 0x201420]),
    ] {
        let fixture = PathBuf::from(format!(
            "metrics/aggregate_abi.x86_64.{optimization}.stripped.elf"
        ));
        let prepared = prepare(&fixture, Mode::Memory);
        let debug = Binary::open(&common::fixtures_dir().join(format!(
            "metrics/aggregate_abi.x86_64.{optimization}.debug.elf"
        )))
        .unwrap();
        let mut binary = Binary::open(&common::fixtures_dir().join(&fixture)).unwrap();
        for (name, address) in [
            "abi_exhaust_five",
            "abi_exhaust_seven",
            "abi_exhaust_five_aligned",
            "abi_exhaust_seven_aligned",
        ]
        .into_iter()
        .zip(addresses)
        {
            assert_eq!(debug.find(name).unwrap().addr, address);
            let analysis = binary.analysis(address, None).unwrap();
            assert!(analysis.references.is_empty());
            let ir = analysis.ir.clone();
            assert_eq!(ir.isa, Isa::X86_64);
            assert_eq!(ir.convention, Convention::SysV);
            assert!(ir.declared_signature.is_none());
            assert_eq!(
                ir.params
                    .iter()
                    .map(|param| param.index)
                    .collect::<Vec<_>>(),
                vec![7, 6, 2, 1, 8, 9]
            );
            let seven = matches!(name, "abi_exhaust_seven" | "abi_exhaust_seven_aligned");
            let slots = if seven { 4 } else { 2 };
            assert_eq!(
                ir.stack_params
                    .iter()
                    .map(|param| (param.offset, param.size, param.position))
                    .collect::<Vec<_>>(),
                (0..slots)
                    .map(|slot| ((slot as i64 + 1) * 8, 8, 6 + slot))
                    .collect::<Vec<_>>()
            );
            assert_eq!(qualifies(&ir, true, Mode::Memory), Ok(()));
            let original = prepared
                .candidates
                .iter()
                .find(|candidate| candidate.ir.addr == address)
                .unwrap_or_else(|| panic!("{optimization} {name} was excluded"));
            assert_eq!(original.inputs.len(), trials::TRIALS as usize);
            let original_call = original
                .marshalling
                .as_ref()
                .expect("a physical stack call");
            assert_eq!(
                original_call.signature.abi.as_ref().unwrap().profile,
                AbiProfile::SysV
            );
            let locations: Vec<_> = original_call
                .signature
                .abi
                .as_ref()
                .unwrap()
                .arguments
                .iter()
                .map(|value| {
                    assert!(!value.aggregate);
                    assert_eq!(value.size, 8);
                    let Passing::Direct(pieces) = &value.passing else {
                        panic!("a direct scalar")
                    };
                    assert_eq!(pieces.len(), 1);
                    pieces[0].location
                })
                .collect();
            assert_eq!(
                locations,
                [7, 6, 2, 1, 8, 9]
                    .map(AbiLocation::Register)
                    .into_iter()
                    .chain((0..slots).map(|slot| AbiLocation::Stack((slot as i64 + 1) * 8)))
                    .collect::<Vec<_>>()
            );
            for (trial, input) in original.inputs.iter().enumerate() {
                let registers = trials::registers(binary.image(), trial as u64);
                let expected: Vec<_> = [7, 6, 2, 1, 8, 9]
                    .into_iter()
                    .map(|index| {
                        registers
                            .iter()
                            .find(|(register, _)| *register == index)
                            .unwrap()
                            .1
                    })
                    .chain(
                        (0..slots)
                            .map(|slot| incoming_stack_word(trial as u64, (slot as i64 + 1) * 8)),
                    )
                    .collect();
                assert_eq!(*input, expected);
            }
            let words = 6 + slots;
            let rows = trials::TRIALS as usize + 2 + words;
            let mut candidate = Candidate {
                label: format!("x86_64 {optimization} {name}"),
                ir: ir.clone(),
                code: original.code.clone(),
                segment_bases: original.segment_bases.clone(),
                states: Vec::new(),
                marshalling: physical_stack_call(&ir, rows),
                params: original.params.clone(),
                inputs: original.inputs.clone(),
                void: false,
            };
            candidate.inputs.push(vec![0; words]);
            candidate.inputs.push(vec![u64::MAX; words]);
            for position in 0..words {
                let mut input = vec![0; words];
                input[position] = 1;
                candidate.inputs.push(input);
            }
            assert_eq!(candidate.inputs.len(), if seven { 24 } else { 22 });
            assert_aggregate_oracle(std::slice::from_ref(&candidate), |input, _| {
                if seven {
                    input
                        .iter()
                        .zip([1u64, 3, 5, 7, 11, 13, 17, 19, 23, 29])
                        .fold(0u64, |sum, (value, coefficient)| {
                            sum.wrapping_add(value.wrapping_mul(coefficient))
                        })
                } else {
                    input[0]
                        .wrapping_add(3u64.wrapping_mul(input[1]))
                        .wrapping_add(5u64.wrapping_mul(input[2]))
                        .wrapping_add(7u64.wrapping_mul(input[3]))
                        .wrapping_add(11u64.wrapping_mul(input[4]))
                        .wrapping_add(13u64.wrapping_mul(input[6]))
                        .wrapping_add(17u64.wrapping_mul(input[7]))
                        .wrapping_add(19u64.wrapping_mul(input[5]))
                }
            });
            assert_eq!(
                candidate.code,
                binary.decompile(address, None, None).unwrap()
            );
            assert!(candidate.ir.declared_signature.is_none());
            candidates.push(candidate);
        }
    }
    assert_eq!(candidates.len(), 8);
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.inputs.len())
            .sum::<usize>(),
        184
    );
    check_candidates("stripped-x86-stack-fixtures", candidates, Mode::Memory, &[]);
}

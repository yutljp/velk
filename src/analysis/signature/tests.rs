use super::recover;
use crate::ir::{BinOp, Block, Convention, Expr, RegRef, Stmt};
use crate::loader::{Format, Isa};

#[test]
fn argument_reads_after_internal_calls_follow_the_callee_clobbers() {
    for (isa, convention) in [
        (Isa::X86_64, Convention::SysV),
        (Isa::X86_64, Convention::Win64),
        (Isa::AArch64, Convention::Aapcs64),
        (Isa::Arm32, Convention::Aapcs32),
        (Isa::I386, Convention::Fastcall),
    ] {
        let register = convention.arguments()[1];
        for preserved in [false, true] {
            let clobbers = preserved.then_some(crate::ir::Registers::default());
            let blocks = [Block {
                start: 0,
                stmts: vec![
                    Stmt::Call {
                        kind: crate::ir::CallKind::Invoke,
                        target: Some(0x1000),
                        through: None,
                        convention,
                        args: Some(Vec::new()),
                        floats_named: true,
                        abi: None,
                        clobbers,
                        outputs: crate::ir::fallback_call_outputs(convention, clobbers),
                        via: None,
                    },
                    Stmt::Store {
                        addr: Expr::Const(0x2000),
                        value: Expr::reg(register, 32),
                        width: 4,
                    },
                    Stmt::Ret {
                        value: Expr::Const(0),
                    },
                ],
            }];
            let signature = recover(&blocks, isa, convention, false);
            assert_eq!(
                signature.params.len(),
                if preserved && convention != Convention::Aapcs64 {
                    2
                } else {
                    0
                }
            );
        }
    }
}

#[test]
fn boolean_guard_smt_checks_only_inputs_read_on_feasible_paths() {
    for guarded in [false, true] {
        let assign = |index, value| Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value: Expr::Const(value),
        };
        let blocks = [
            Block {
                start: 0,
                stmts: vec![
                    assign(2, 0),
                    Stmt::Brif {
                        cond: crate::ir::Cond::Eq,
                        lhs: Expr::reg(7, 32),
                        rhs: Expr::Const(0),
                        target: 20,
                    },
                ],
            },
            Block {
                start: 10,
                stmts: vec![assign(1, 42), assign(2, 1)],
            },
            Block {
                start: 20,
                stmts: vec![Stmt::Brif {
                    cond: crate::ir::Cond::Eq,
                    lhs: Expr::reg(if guarded { 2 } else { 6 }, 32),
                    rhs: Expr::Const(0),
                    target: 40,
                }],
            },
            Block {
                start: 30,
                stmts: vec![Stmt::Store {
                    addr: Expr::Const(0x2000),
                    value: Expr::reg(1, 64),
                    width: 8,
                }],
            },
            Block {
                start: 40,
                stmts: vec![Stmt::Ret {
                    value: Expr::Const(0),
                }],
            },
        ];
        let signature = recover(&blocks, Isa::X86_64, Convention::SysV, false);
        assert_eq!(signature.params.len(), if guarded { 1 } else { 4 });
        if guarded && crate::ir::smt::Proofs::available() {
            let mut before = crate::ir::FunctionIr::single_block(Isa::X86_64, Vec::new());
            before.blocks = blocks.to_vec();
            let mut after = before.clone();
            after.blocks[0].stmts.insert(0, assign(1, 0));
            let mut proofs = crate::ir::smt::Proofs::default();
            proofs.function("boolean-guard-entry-value", &before, &after);
            proofs.check();
        }
    }
}

#[test]
fn a_register_written_in_an_earlier_block_is_not_an_argument() {
    let blocks = vec![
        Block {
            start: 0,
            stmts: vec![Stmt::Assign {
                dest: RegRef {
                    index: 1,
                    width: 64,
                },
                value: Expr::Const(7),
            }],
        },
        Block {
            start: 4,
            stmts: vec![Stmt::Ret {
                value: Expr::bin(crate::ir::BinOp::Add, Expr::reg(0, 64), Expr::reg(1, 64)),
            }],
        },
    ];

    let signature = recover(
        &blocks,
        Isa::AArch64,
        Convention::of(Isa::AArch64, Format::Elf, false),
        false,
    );

    let params: Vec<u16> = signature.params.iter().map(|param| param.index).collect();
    assert_eq!(params, vec![0]);
}

#[test]
fn an_argument_kept_in_a_stack_slot_is_typed_by_its_loads() {
    // `str x0, [sp, #8]`, then x8 holds a count before it holds the
    // argument again and a load goes through it.
    let slot = Expr::bin(crate::ir::BinOp::Add, Expr::reg(31, 64), Expr::Const(8));
    let assign = |index, value| Stmt::Assign {
        dest: RegRef { index, width: 64 },
        value,
    };
    let load = |addr: Expr, width| Expr::Load {
        addr: Box::new(addr),
        width,
        signed: false,
    };
    let blocks = vec![Block {
        start: 0,
        stmts: vec![
            Stmt::Store {
                addr: slot.clone(),
                value: Expr::reg(0, 64),
                width: 8,
            },
            assign(8, Expr::reg(1, 64)),
            assign(
                9,
                Expr::bin(crate::ir::BinOp::Add, Expr::reg(8, 64), Expr::Const(1)),
            ),
            assign(8, load(slot, 8)),
            assign(10, load(Expr::reg(8, 64), 4)),
            Stmt::Ret {
                value: Expr::bin(crate::ir::BinOp::Add, Expr::reg(9, 64), Expr::reg(10, 64)),
            },
        ],
    }];
    let signature = recover(
        &blocks,
        Isa::AArch64,
        Convention::of(Isa::AArch64, Format::Elf, false),
        false,
    );
    let types: Vec<String> = signature
        .params
        .iter()
        .map(|param| param.ty.to_string())
        .collect();
    assert_eq!(types, vec!["uint32_t *", "uint64_t"]);
}

#[test]
fn arguments_past_the_registers_are_read_from_the_callers_frame() {
    // Every integer register is read, then `push rbp; mov rbp, rsp`
    // and a load of the second stack argument through rbp.
    let sum = [7u16, 6, 2, 1, 8, 9]
        .into_iter()
        .map(|register| Expr::reg(register, 64))
        .reduce(|a, b| Expr::bin(crate::ir::BinOp::Add, a, b))
        .expect("registers");
    let assign = |index, value| Stmt::Assign {
        dest: RegRef { index, width: 64 },
        value,
    };
    let blocks = vec![Block {
        start: 0,
        stmts: vec![
            assign(
                4,
                Expr::bin(crate::ir::BinOp::Sub, Expr::reg(4, 64), Expr::Const(8)),
            ),
            assign(5, Expr::reg(4, 64)),
            assign(
                0,
                Expr::Load {
                    addr: Box::new(Expr::bin(
                        crate::ir::BinOp::Add,
                        Expr::reg(5, 64),
                        Expr::Const(0x18),
                    )),
                    width: 8,
                    signed: false,
                },
            ),
            Stmt::Ret {
                value: Expr::bin(crate::ir::BinOp::Add, sum, Expr::reg(0, 64)),
            },
        ],
    }];
    let signature = recover(
        &blocks,
        Isa::X86_64,
        Convention::of(Isa::X86_64, Format::Elf, false),
        false,
    );
    assert_eq!(signature.params.len(), 6);
    assert_eq!(signature.stack, vec![8, 16]);
}

#[test]
fn go_assembly_results_follow_the_arguments_read() {
    // The stack pointer kept in r12 across a move to another stack, two
    // arguments read through it, the second a byte, then a result
    // stored and the address of the next handed to a call.
    let load = |base: u16, offset: u64, width: u8| Expr::Load {
        addr: Box::new(Expr::bin(
            crate::ir::BinOp::Add,
            Expr::reg(base, 64),
            Expr::Const(offset),
        )),
        width,
        signed: false,
    };
    let assign = |index, value| Stmt::Assign {
        dest: RegRef { index, width: 64 },
        value,
    };
    let blocks = vec![Block {
        start: 0,
        stmts: vec![
            assign(12, Expr::reg(4, 64)),
            assign(4, load(0, 0x38, 8)),
            assign(0, load(12, 8, 8)),
            assign(3, load(12, 0x10, 1)),
            assign(4, Expr::reg(12, 64)),
            Stmt::Store {
                addr: Expr::bin(crate::ir::BinOp::Add, Expr::reg(4, 64), Expr::Const(0x18)),
                value: Expr::reg(0, 64),
                width: 4,
            },
            assign(
                8,
                Expr::bin(crate::ir::BinOp::Add, Expr::reg(4, 64), Expr::Const(0x20)),
            ),
            Stmt::Call {
                kind: crate::ir::CallKind::Invoke,
                target: Some(0x2000),
                through: None,
                convention: Convention::GoAmd64,
                args: Some(vec![Expr::reg(3, 64), Expr::reg(8, 64)]),
                floats_named: false,
                abi: None,
                clobbers: None,
                outputs: crate::ir::fallback_call_outputs(Convention::GoAmd64, None),
                via: None,
            },
            Stmt::Ret {
                value: Expr::reg(0, 64),
            },
        ],
    }];
    let signature = recover(&blocks, Isa::X86_64, Convention::GoAbi0, true);
    assert_eq!(signature.stack, vec![8, 0x10]);
    assert_eq!(signature.stack_widths, vec![8, 1]);
    assert_eq!(signature.stack_results, vec![(0x18, 4), (0x20, 8)]);
}

fn params_of(stmts: Vec<Stmt>, isa: Isa) -> Vec<u16> {
    let blocks = vec![Block { start: 0, stmts }];
    recover(&blocks, isa, Convention::of(isa, Format::Elf, false), false)
        .params
        .iter()
        .map(|param| param.index)
        .collect()
}

#[test]
fn registers_before_the_last_argument_read_are_parameters() {
    // `if (x2 == 0) return; tail call`, passing x0 and x1 on unchanged.
    let stmts = vec![
        Stmt::Brif {
            cond: crate::ir::Cond::Eq,
            lhs: Expr::reg(2, 64),
            rhs: Expr::Const(0),
            target: 0x10,
        },
        Stmt::Ret {
            value: Expr::Const(0),
        },
    ];
    assert_eq!(params_of(stmts, Isa::AArch64), vec![0, 1, 2]);
}

#[test]
fn incoming_reads_follow_live_values_across_blocks() {
    let blocks = vec![
        Block {
            start: 0,
            stmts: vec![
                stack_assign(10, Expr::reg(7, 64)),
                stack_assign(11, Expr::reg(1, 64)),
                Stmt::Br { target: Some(16) },
            ],
        },
        Block {
            start: 16,
            stmts: vec![Stmt::Ret {
                value: Expr::reg(10, 64),
            }],
        },
    ];
    let signature = recover(&blocks, Isa::X86_64, Convention::SysV, false);
    assert_eq!(
        signature
            .params
            .iter()
            .map(|param| param.index)
            .collect::<Vec<_>>(),
        vec![7]
    );
    let mut expected: crate::ir::Registers = Convention::SysV.results().iter().copied().collect();
    expected.insert(7);
    assert_eq!(signature.inputs, Some(expected));
    let mut unknown = blocks;
    unknown[1].stmts = vec![Stmt::BrIndirect {
        target: Expr::reg(10, 64),
    }];
    assert!(
        recover(&unknown, Isa::X86_64, Convention::SysV, false)
            .inputs
            .is_none()
    );
    unknown[1].stmts = vec![Stmt::Br { target: Some(32) }];
    assert!(
        recover(&unknown, Isa::X86_64, Convention::SysV, false)
            .inputs
            .is_none()
    );
}

#[test]
fn floating_results_and_unchanged_secondary_results_keep_their_inputs() {
    for (isa, convention, dest, source) in [
        (Isa::X86_64, Convention::SysV, 18, 20),
        (Isa::X86_64, Convention::SysV, 10, 20),
        (Isa::AArch64, Convention::Aapcs64, 36, 38),
        (Isa::AArch64, Convention::Aapcs64, 38, 40),
    ] {
        let signature = recover(
            &[Block {
                start: 0,
                stmts: vec![
                    stack_assign(dest, Expr::reg(source, 64)),
                    Stmt::Ret {
                        value: Expr::reg(0, 64),
                    },
                ],
            }],
            isa,
            convention,
            false,
        );
        assert!(signature.params.iter().any(|param| param.index == source));
        let inputs = signature.inputs.unwrap();
        assert!(inputs.contains(source));
        assert!(inputs.contains(if isa == Isa::X86_64 { 2 } else { 1 }));
    }
}

#[test]
fn go_runtime_result_registers_keep_input_reads() {
    let signature = recover(
        &[Block {
            start: 0,
            stmts: vec![
                stack_assign(2, Expr::reg(3, 64)),
                Stmt::Ret {
                    value: Expr::reg(0, 64),
                },
            ],
        }],
        Isa::AArch64,
        Convention::Aapcs64,
        true,
    );
    assert!(signature.params.iter().any(|param| param.index == 3));
    assert!(signature.inputs.is_none());
}

#[test]
fn preserved_tail_call_outputs_are_inputs_only_when_read() {
    use crate::ir::{CallKind, CallOutput, Registers};
    for read in [None, Some(3)] {
        let mut stmts = vec![
            Stmt::Call {
                abi: None,
                kind: if read.is_some() {
                    CallKind::Invoke
                } else {
                    CallKind::Tail
                },
                target: Some(0x1000),
                through: None,
                convention: Convention::Aapcs64,
                args: Some(vec![Expr::reg(0, 64)]),
                floats_named: true,
                clobbers: Some(Registers(1)),
                outputs: (0..4)
                    .map(|index| CallOutput {
                        register: index,
                        dest: RegRef { index, width: 64 },
                    })
                    .collect(),
                via: None,
            },
            Stmt::Ret {
                value: Expr::Const(0),
            },
        ];
        if let Some(index) = read {
            stmts.insert(
                1,
                Stmt::Store {
                    addr: Expr::Const(0x2000),
                    value: Expr::reg(index, 64),
                    width: 8,
                },
            );
        }
        assert_eq!(
            params_of(stmts, Isa::AArch64),
            if read.is_some() {
                vec![0, 1, 2, 3]
            } else {
                vec![0]
            }
        );
    }
}

#[test]
fn the_kept_bits_of_a_partial_write_are_no_argument() {
    // cl = dil: rcx keeps its upper bits, which the body never uses.
    let stmts = vec![
        Stmt::Assign {
            dest: RegRef {
                index: 1,
                width: 64,
            },
            value: Expr::bin(
                crate::ir::BinOp::Or,
                Expr::bin(crate::ir::BinOp::And, Expr::reg(1, 64), Expr::Const(!0xff)),
                Expr::bin(crate::ir::BinOp::And, Expr::reg(7, 64), Expr::Const(0xff)),
            ),
        },
        Stmt::Ret {
            value: Expr::bin(crate::ir::BinOp::And, Expr::reg(1, 64), Expr::Const(0xff)),
        },
    ];
    assert_eq!(params_of(stmts, Isa::X86_64), vec![7]);
}

fn stack_address(base: u16, offset: i64) -> Expr {
    Expr::bin(BinOp::Add, Expr::reg(base, 64), Expr::Const(offset as u64))
}

fn stack_load(base: u16, offset: i64, width: u8) -> Expr {
    Expr::Load {
        addr: Box::new(stack_address(base, offset)),
        width,
        signed: false,
    }
}

fn stack_assign(index: u16, value: Expr) -> Stmt {
    Stmt::Assign {
        dest: RegRef { index, width: 64 },
        value,
    }
}

fn stack_store(base: u16, offset: i64, width: u8) -> Stmt {
    Stmt::Store {
        addr: stack_address(base, offset),
        value: Expr::Const(7),
        width,
    }
}

fn recover_aapcs_stack(stmts: Vec<Stmt>) -> super::Signature {
    recover(
        &[Block { start: 0, stmts }],
        Isa::AArch64,
        Convention::Aapcs64,
        false,
    )
}

#[test]
fn go_stack_arguments_exclude_register_spills() {
    let signature = recover(
        &[Block {
            start: 0,
            stmts: vec![
                stack_store(4, 16, 8),
                stack_assign(
                    12,
                    Expr::bin(
                        BinOp::Add,
                        Expr::reg(0, 64),
                        Expr::bin(BinOp::Add, stack_load(4, 8, 8), stack_load(4, 16, 8)),
                    ),
                ),
                Stmt::Ret {
                    value: Expr::reg(12, 64),
                },
            ],
        }],
        Isa::X86_64,
        Convention::GoAmd64,
        true,
    );
    assert_eq!(signature.stack, vec![8]);
    assert!(signature.stack_results.is_empty());
    assert!(signature.params.iter().any(|param| param.index == 0));
}

#[test]
fn incoming_stack_arguments_do_not_require_every_integer_register() {
    let registers = (0..7)
        .map(|index| Expr::reg(index, 64))
        .reduce(|lhs, rhs| Expr::bin(BinOp::Add, lhs, rhs))
        .unwrap();
    for framed in [false, true] {
        let mut stmts = Vec::new();
        let (base, displacement) = if framed {
            stmts.extend([
                stack_assign(
                    31,
                    Expr::bin(BinOp::Sub, Expr::reg(31, 64), Expr::Const(48)),
                ),
                stack_store(31, 0, 8),
                stack_store(31, 8, 8),
                stack_assign(29, Expr::reg(31, 64)),
            ]);
            (29, 48)
        } else {
            (31, 0)
        };
        let value = [0, 8, 16]
            .into_iter()
            .fold(registers.clone(), |sum, offset| {
                Expr::bin(BinOp::Add, sum, stack_load(base, displacement + offset, 8))
            });
        stmts.push(stack_assign(12, value));
        stmts.push(Stmt::Ret {
            value: Expr::reg(12, 64),
        });
        let signature = recover_aapcs_stack(stmts);
        assert_eq!(
            signature
                .params
                .iter()
                .map(|param| param.index)
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4, 5, 6]
        );
        assert_eq!(signature.stack, vec![0, 8, 16]);
        assert_eq!(signature.stack_widths, vec![8, 8, 8]);
        assert!(!signature.aggregate);
    }
}

#[test]
fn private_spills_saved_registers_and_return_addresses_are_not_arguments() {
    let signature = recover_aapcs_stack(vec![
        stack_assign(
            31,
            Expr::bin(BinOp::Sub, Expr::reg(31, 64), Expr::Const(32)),
        ),
        Stmt::Store {
            addr: stack_address(31, 0),
            value: Expr::reg(29, 64),
            width: 8,
        },
        Stmt::Store {
            addr: stack_address(31, 8),
            value: Expr::reg(30, 64),
            width: 8,
        },
        Stmt::Store {
            addr: stack_address(31, 16),
            value: Expr::reg(0, 64),
            width: 8,
        },
        Stmt::Ret {
            value: Expr::bin(
                BinOp::Add,
                Expr::bin(BinOp::Add, stack_load(31, 0, 8), stack_load(31, 8, 8)),
                stack_load(31, 16, 8),
            ),
        },
    ]);
    assert!(signature.stack.is_empty());
    assert_eq!(
        signature
            .params
            .iter()
            .map(|param| param.index)
            .collect::<Vec<_>>(),
        vec![0]
    );
    let signature = recover(
        &[Block {
            start: 0,
            stmts: vec![Stmt::Ret {
                value: stack_load(4, 0, 8),
            }],
        }],
        Isa::X86_64,
        Convention::SysV,
        false,
    );
    assert!(signature.stack.is_empty());
}

#[test]
fn incoming_stack_bytes_written_before_their_first_read_are_not_inputs() {
    for width in [1, 4, 8] {
        let signature = recover_aapcs_stack(vec![
            stack_store(31, 0, width),
            Stmt::Ret {
                value: stack_load(31, 0, 8),
            },
        ]);
        if width == 8 {
            assert!(signature.stack.is_empty());
        } else {
            assert_eq!(signature.stack, vec![0]);
        }
        let signature = recover_aapcs_stack(vec![
            stack_store(31, 0, width),
            Stmt::Ret {
                value: stack_load(31, 0, width),
            },
        ]);
        assert!(signature.stack.is_empty());
    }
    let signature = recover_aapcs_stack(vec![
        stack_assign(9, stack_load(31, 0, 8)),
        stack_store(31, 0, 8),
        Stmt::Ret {
            value: Expr::reg(9, 64),
        },
    ]);
    assert_eq!(signature.stack, vec![0]);
    let signature = recover_aapcs_stack(vec![
        Stmt::Store {
            addr: stack_address(31, 0),
            value: stack_load(31, 0, 8),
            width: 8,
        },
        Stmt::Ret {
            value: Expr::Const(0),
        },
    ]);
    assert_eq!(signature.stack, vec![0]);
}

#[test]
fn a_stack_write_must_cover_every_predecessor_to_remove_an_input() {
    for both in [false, true] {
        let mut left = Vec::new();
        if both {
            left.push(stack_store(31, 0, 8));
        }
        left.push(Stmt::Br { target: Some(24) });
        let blocks = vec![
            Block {
                start: 0,
                stmts: vec![Stmt::Brif {
                    cond: crate::ir::Cond::Eq,
                    lhs: Expr::reg(0, 64),
                    rhs: Expr::Const(0),
                    target: 16,
                }],
            },
            Block {
                start: 8,
                stmts: left,
            },
            Block {
                start: 16,
                stmts: vec![stack_store(31, 0, 8), Stmt::Br { target: Some(24) }],
            },
            Block {
                start: 24,
                stmts: vec![Stmt::Ret {
                    value: stack_load(31, 0, 8),
                }],
            },
        ];
        let signature = recover(&blocks, Isa::AArch64, Convention::Aapcs64, false);
        assert_eq!(signature.stack, if both { vec![] } else { vec![0] });
        assert!(!signature.aggregate);
    }
}

#[test]
fn unknown_stack_adjustments_preserve_only_a_stable_frame_pointer() {
    let dynamic = || {
        stack_assign(
            31,
            Expr::bin(BinOp::Sub, Expr::reg(31, 64), Expr::reg(0, 64)),
        )
    };
    let signature = recover_aapcs_stack(vec![
        dynamic(),
        Stmt::Ret {
            value: stack_load(31, 16, 8),
        },
    ]);
    assert!(signature.stack.is_empty());
    let signature = recover_aapcs_stack(vec![
        stack_assign(
            31,
            Expr::bin(BinOp::Sub, Expr::reg(31, 64), Expr::Const(32)),
        ),
        stack_assign(29, Expr::reg(31, 64)),
        dynamic(),
        Stmt::Ret {
            value: stack_load(29, 32, 8),
        },
    ]);
    assert_eq!(signature.stack, vec![0]);
    let signature = recover_aapcs_stack(vec![Stmt::Ret {
        value: Expr::Load {
            addr: Box::new(Expr::bin(BinOp::Add, Expr::reg(31, 64), Expr::reg(1, 64))),
            width: 8,
            signed: false,
        },
    }]);
    assert!(signature.stack.is_empty());
}

#[test]
fn only_surviving_stack_address_aliases_are_followed_across_calls() {
    for index in [9, 19] {
        let signature = recover_aapcs_stack(vec![
            stack_assign(index, stack_address(31, 0)),
            Stmt::Call {
                kind: crate::ir::CallKind::Invoke,
                target: Some(0x2000),
                through: None,
                convention: Convention::Aapcs64,
                args: Some(vec![]),
                floats_named: false,
                abi: None,
                clobbers: None,
                outputs: crate::ir::fallback_call_outputs(Convention::Aapcs64, None),
                via: None,
            },
            Stmt::Ret {
                value: stack_load(index, 0, 8),
            },
        ]);
        assert_eq!(signature.stack, if index == 19 { vec![0] } else { vec![] });
    }
}

#[test]
fn incoming_stack_recovery_keeps_its_frame_bound() {
    for offset in [-8, 512] {
        let signature = recover_aapcs_stack(vec![Stmt::Ret {
            value: stack_load(31, offset, 8),
        }]);
        assert!(signature.stack.is_empty());
    }
    let signature = recover_aapcs_stack(vec![Stmt::Ret {
        value: stack_load(31, 504, 8),
    }]);
    assert_eq!(signature.stack.len(), 64);
    assert_eq!(signature.stack.last(), Some(&504));
}

#[test]
fn incoming_stack_write_proofs_include_switch_and_flag_edges() {
    for branch in [
        Stmt::Switch {
            index: Expr::reg(0, 64),
            cases: vec![(0, 8)],
            default: Some(16),
        },
        Stmt::BrifFlags {
            cond: crate::ir::Cond::Eq,
            target: 16,
        },
    ] {
        let blocks = vec![
            Block {
                start: 0,
                stmts: vec![branch],
            },
            Block {
                start: 8,
                stmts: vec![stack_store(31, 0, 8), Stmt::Br { target: Some(24) }],
            },
            Block {
                start: 16,
                stmts: vec![Stmt::Br { target: Some(24) }],
            },
            Block {
                start: 24,
                stmts: vec![Stmt::Ret {
                    value: stack_load(31, 0, 8),
                }],
            },
        ];
        let signature = recover(&blocks, Isa::AArch64, Convention::Aapcs64, false);
        assert_eq!(signature.stack, vec![0]);
    }
    let blocks = vec![
        Block {
            start: 0,
            stmts: vec![Stmt::Br { target: None }],
        },
        Block {
            start: 8,
            stmts: vec![Stmt::Ret {
                value: stack_load(31, 0, 8),
            }],
        },
    ];
    assert_eq!(
        recover(&blocks, Isa::AArch64, Convention::Aapcs64, false).stack,
        vec![0]
    );
}

#[test]
fn truncated_frame_addresses_and_overrunning_loads_remain_unknown() {
    let signature = recover_aapcs_stack(vec![
        Stmt::Assign {
            dest: RegRef {
                index: 29,
                width: 32,
            },
            value: Expr::reg(31, 64),
        },
        Stmt::Ret {
            value: stack_load(29, 0, 8),
        },
    ]);
    assert!(signature.stack.is_empty());
    for (offset, width) in [(511, 2), (504, 16), (0, 0)] {
        let signature = recover_aapcs_stack(vec![Stmt::Ret {
            value: stack_load(31, offset, width),
        }]);
        assert!(signature.stack.is_empty());
    }
}

#[test]
fn unsupported_stack_widths_do_not_establish_input_or_overwrite_proofs() {
    let signature = recover_aapcs_stack(vec![Stmt::Ret {
        value: stack_load(31, 0, 3),
    }]);
    assert!(signature.stack.is_empty());
    let signature = recover_aapcs_stack(vec![
        stack_store(31, 0, 3),
        Stmt::Ret {
            value: stack_load(31, 0, 2),
        },
    ]);
    assert_eq!(signature.stack, vec![0]);
}

fn test_call() -> Stmt {
    Stmt::Call {
        kind: crate::ir::CallKind::Invoke,
        target: Some(0x1000),
        through: None,
        convention: Convention::Aapcs64,
        args: Some(Vec::new()),
        floats_named: true,
        abi: None,
        outputs: crate::ir::fallback_call_outputs(Convention::Aapcs64, None),
        clobbers: None,
        via: None,
    }
}

fn stack_argument_offsets(blocks: &[Block], pads: &[(u64, Vec<(u64, u64)>)]) -> Vec<i64> {
    super::stack_arguments(blocks, pads, Isa::AArch64, Convention::Aapcs64).offsets
}

#[test]
fn preserved_output_addresses_keep_their_pre_call_origin() {
    let destination = crate::ir::VARIABLE_BASE;
    for preserved in [false, true] {
        let mut call = test_call();
        let Stmt::Call {
            outputs, clobbers, ..
        } = &mut call
        else {
            unreachable!()
        };
        *clobbers = Some(if preserved {
            Default::default()
        } else {
            [0].into_iter().collect()
        });
        *outputs = vec![crate::ir::CallOutput {
            register: 0,
            dest: RegRef {
                index: destination,
                width: 64,
            },
        }];
        let signature = recover_aapcs_stack(vec![
            stack_assign(0, stack_address(31, 0)),
            call,
            Stmt::Ret {
                value: stack_load(destination, 0, 8),
            },
        ]);
        assert_eq!(signature.stack, if preserved { vec![0] } else { vec![] });
    }
}

#[test]
fn first_entry_reads_survive_unknown_backedges_without_adding_results() {
    for (isa, convention, sp, start) in [
        (Isa::AArch64, Convention::Aapcs64, 31, 0),
        (Isa::X86_64, Convention::GoAbi0, 4, 8),
    ] {
        for width in [1, 8] {
            let blocks = vec![
                Block {
                    start: 0,
                    stmts: vec![
                        stack_assign(sp, stack_address(sp, -16)),
                        stack_assign(12, stack_load(sp, start + 16, width)),
                        stack_store(sp, start + 16, 8),
                        stack_store(sp, start + 24, 8),
                        Stmt::Br { target: Some(8) },
                    ],
                },
                Block {
                    start: 8,
                    stmts: vec![
                        stack_assign(sp, Expr::reg(0, 64)),
                        Stmt::BrIndirect {
                            target: Expr::reg(1, 64),
                        },
                    ],
                },
            ];
            let frame = super::stack_arguments(&blocks, &[], isa, convention);
            assert_eq!(frame.offsets, vec![start]);
            assert_eq!(
                frame.widths,
                vec![if convention == Convention::GoAbi0 {
                    width
                } else {
                    8
                }]
            );
            assert!(frame.results.is_empty());
        }
    }
}

#[test]
fn first_entry_overwrites_keep_their_byte_coverage() {
    for (stored, loaded, needed) in [(8, 8, false), (4, 8, true), (1, 8, true), (8, 4, false)] {
        let blocks = vec![
            Block {
                start: 0,
                stmts: vec![
                    stack_store(31, 0, stored),
                    stack_assign(12, stack_load(31, 0, loaded)),
                    Stmt::Br { target: Some(8) },
                ],
            },
            Block {
                start: 8,
                stmts: vec![
                    stack_assign(31, Expr::reg(0, 64)),
                    Stmt::BrIndirect {
                        target: Expr::reg(1, 64),
                    },
                ],
            },
        ];
        assert_eq!(
            stack_argument_offsets(&blocks, &[]),
            if needed { vec![0] } else { vec![] }
        );
    }
}

#[test]
fn first_entry_scan_keeps_reads_before_an_opaque_frame_change_only() {
    for early in [false, true] {
        let mut first = Vec::new();
        if early {
            first.push(stack_assign(12, stack_load(31, 0, 8)));
        }
        first.extend([
            Stmt::Unsupported {
                text: "opaque frame change".to_owned(),
                writes: Some(vec![31]),
            },
            stack_assign(13, stack_load(31, 16, 8)),
            Stmt::Br { target: Some(8) },
        ]);
        let blocks = vec![
            Block {
                start: 0,
                stmts: first,
            },
            Block {
                start: 8,
                stmts: vec![Stmt::BrIndirect {
                    target: Expr::reg(1, 64),
                }],
            },
        ];
        assert_eq!(
            stack_argument_offsets(&blocks, &[]),
            if early { vec![0] } else { vec![] }
        );
    }
}

#[test]
fn unknown_predecessors_meet_frame_and_written_facts() {
    for indirect in [false, true] {
        for changed_sp in [false, true] {
            let mut unknown = Vec::new();
            if changed_sp {
                unknown.push(stack_assign(31, stack_address(31, 16)));
            }
            unknown.push(if indirect {
                Stmt::BrIndirect {
                    target: Expr::reg(1, 64),
                }
            } else {
                Stmt::Br { target: None }
            });
            let blocks = vec![
                Block {
                    start: 0,
                    stmts: vec![Stmt::Brif {
                        cond: crate::ir::Cond::Eq,
                        lhs: Expr::reg(0, 64),
                        rhs: Expr::Const(0),
                        target: 16,
                    }],
                },
                Block {
                    start: 8,
                    stmts: vec![stack_store(31, 0, 8), Stmt::Br { target: Some(24) }],
                },
                Block {
                    start: 16,
                    stmts: unknown,
                },
                Block {
                    start: 24,
                    stmts: vec![Stmt::Ret {
                        value: stack_load(31, 0, 8),
                    }],
                },
            ];
            assert_eq!(
                stack_argument_offsets(&blocks, &[]),
                if changed_sp { vec![] } else { vec![0] }
            );
        }
    }
    for before in [false, true] {
        let mut first = Vec::new();
        if before {
            first.push(stack_store(31, 0, 8));
        }
        first.push(Stmt::BrIndirect {
            target: Expr::reg(1, 64),
        });
        let blocks = vec![
            Block {
                start: 0,
                stmts: first,
            },
            Block {
                start: 8,
                stmts: vec![Stmt::Ret {
                    value: stack_load(31, 0, 8),
                }],
            },
        ];
        assert_eq!(
            stack_argument_offsets(&blocks, &[]),
            if before { vec![] } else { vec![0] }
        );
    }
}

#[test]
fn normal_and_exception_predecessors_must_both_overwrite() {
    for both in [false, true] {
        let mut pad = Vec::new();
        if both {
            pad.push(stack_store(31, 0, 8));
        }
        pad.push(Stmt::Br { target: Some(12) });
        let blocks = vec![
            Block {
                start: 0,
                stmts: vec![test_call()],
            },
            Block {
                start: 4,
                stmts: vec![stack_store(31, 0, 8), Stmt::Br { target: Some(12) }],
            },
            Block {
                start: 8,
                stmts: pad,
            },
            Block {
                start: 12,
                stmts: vec![Stmt::Ret {
                    value: stack_load(31, 0, 8),
                }],
            },
        ];
        assert_eq!(
            stack_argument_offsets(&blocks, &[(8, vec![(0, 4)])]),
            if both { vec![] } else { vec![0] }
        );
    }
}

#[test]
fn exception_states_meet_call_prefixes_instead_of_the_block_exit() {
    for before in [false, true] {
        for second_call in [false, true] {
            let mut first = Vec::new();
            if before {
                first.push(stack_store(31, 0, 8));
            }
            first.extend([test_call(), stack_store(31, 0, 8)]);
            if second_call {
                first.push(test_call());
            }
            first.push(Stmt::Br { target: Some(16) });
            let blocks = vec![
                Block {
                    start: 0,
                    stmts: first,
                },
                Block {
                    start: 8,
                    stmts: vec![Stmt::Br { target: Some(16) }],
                },
                Block {
                    start: 16,
                    stmts: vec![Stmt::Ret {
                        value: stack_load(31, 0, 8),
                    }],
                },
            ];
            assert_eq!(
                stack_argument_offsets(&blocks, &[(8, vec![(0, 8)])]),
                if before { vec![] } else { vec![0] }
            );
        }
    }
}

#[test]
fn exception_frame_origins_use_the_call_point() {
    for second_call in [false, true] {
        let mut first = vec![test_call(), stack_assign(31, stack_address(31, 16))];
        if second_call {
            first.push(test_call());
        }
        let blocks = vec![
            Block {
                start: 0,
                stmts: first,
            },
            Block {
                start: 8,
                stmts: vec![
                    stack_assign(31, stack_address(31, -16)),
                    Stmt::Br { target: Some(24) },
                ],
            },
            Block {
                start: 16,
                stmts: vec![Stmt::Br { target: Some(24) }],
            },
            Block {
                start: 24,
                stmts: vec![Stmt::Ret {
                    value: stack_load(31, 0, 8),
                }],
            },
        ];
        assert_eq!(
            stack_argument_offsets(&blocks, &[(16, vec![(0, 8)])]),
            if second_call { vec![] } else { vec![0] }
        );
    }
}

#[test]
fn missing_exception_targets_cannot_certify_the_normal_store() {
    let blocks = vec![
        Block {
            start: 0,
            stmts: vec![test_call(), stack_store(31, 0, 8)],
        },
        Block {
            start: 8,
            stmts: vec![Stmt::Ret {
                value: stack_load(31, 0, 8),
            }],
        },
    ];
    assert_eq!(
        stack_argument_offsets(&blocks, &[(0x100, vec![(0, 8)])]),
        vec![0]
    );
}

#[test]
fn loop_backedges_do_not_replace_the_initial_unwritten_state() {
    for before in [false, true] {
        let mut first = Vec::new();
        if before {
            first.push(stack_store(31, 0, 8));
        }
        first.push(Stmt::Br { target: Some(8) });
        let blocks = vec![
            Block {
                start: 0,
                stmts: first,
            },
            Block {
                start: 8,
                stmts: vec![
                    stack_assign(9, stack_load(31, 0, 8)),
                    stack_store(31, 0, 8),
                    Stmt::Brif {
                        cond: crate::ir::Cond::Ne,
                        lhs: Expr::reg(0, 64),
                        rhs: Expr::Const(0),
                        target: 8,
                    },
                ],
            },
            Block {
                start: 16,
                stmts: vec![Stmt::Ret {
                    value: Expr::reg(9, 64),
                }],
            },
        ];
        assert_eq!(
            stack_argument_offsets(&blocks, &[]),
            if before { vec![] } else { vec![0] }
        );
    }
}

#[test]
fn an_exception_range_spanning_call_blocks_keeps_the_earlier_call() {
    for before in [false, true] {
        let mut first = Vec::new();
        if before {
            first.push(stack_store(31, 0, 8));
        }
        first.push(test_call());
        let blocks = vec![
            Block {
                start: 0,
                stmts: first,
            },
            Block {
                start: 8,
                stmts: vec![stack_store(31, 0, 8)],
            },
            Block {
                start: 16,
                stmts: vec![test_call(), Stmt::Br { target: Some(32) }],
            },
            Block {
                start: 24,
                stmts: vec![Stmt::Br { target: Some(32) }],
            },
            Block {
                start: 32,
                stmts: vec![Stmt::Ret {
                    value: stack_load(31, 0, 8),
                }],
            },
        ];
        assert_eq!(
            stack_argument_offsets(&blocks, &[(24, vec![(0, 24)])]),
            if before { vec![] } else { vec![0] }
        );
    }
}

#[test]
fn an_entry_backedge_keeps_the_external_unwritten_root() {
    let blocks = vec![
        Block {
            start: 0,
            stmts: vec![
                stack_assign(9, stack_load(31, 0, 8)),
                stack_store(31, 0, 8),
                Stmt::Brif {
                    cond: crate::ir::Cond::Ne,
                    lhs: Expr::reg(0, 64),
                    rhs: Expr::Const(0),
                    target: 0,
                },
            ],
        },
        Block {
            start: 8,
            stmts: vec![Stmt::Ret {
                value: Expr::reg(9, 64),
            }],
        },
    ];
    assert_eq!(stack_argument_offsets(&blocks, &[]), vec![0]);
}

#[test]
fn opaque_exception_effects_remove_the_call_prefix_origin() {
    for opaque in [false, true] {
        let mut first = vec![test_call()];
        if opaque {
            first.push(Stmt::Unsupported {
                text: "opaque".to_owned(),
                writes: Some(Vec::new()),
            });
        }
        first.extend([stack_store(31, 0, 8), Stmt::Br { target: Some(16) }]);
        let blocks = vec![
            Block {
                start: 0,
                stmts: first,
            },
            Block {
                start: 8,
                stmts: vec![Stmt::Ret {
                    value: stack_load(31, 0, 8),
                }],
            },
            Block {
                start: 16,
                stmts: vec![Stmt::Ret {
                    value: stack_load(31, 0, 8),
                }],
            },
        ];
        assert_eq!(
            stack_argument_offsets(&blocks, &[(8, vec![(0, 8)])]),
            if opaque { vec![] } else { vec![0] }
        );
    }
}
#[test]
fn declared_calls_do_not_offer_positional_parameter_types() {
    let image = crate::loader::Image::from_code(Isa::AArch64, 0, Vec::new());
    for attached in [false, true] {
        let mut call = crate::lift::call(
            crate::ir::CallKind::Invoke,
            &image,
            &|_| Default::default(),
            Some(0x1000),
        );
        let Stmt::Call {
            args,
            floats_named,
            abi,
            ..
        } = &mut call
        else {
            unreachable!()
        };
        *args = Some(vec![Expr::reg(0, 64)]);
        *floats_named = true;
        *abi = attached.then(|| crate::ir::calls::test_call_abi(vec![0], false));
        let signature = super::recover_with(
            &[Block {
                start: 0,
                stmts: vec![call],
            }],
            &[],
            Isa::AArch64,
            Convention::Aapcs64,
            false,
            &|_| crate::analysis::prototypes::of("free", false),
        );
        let param = signature
            .params
            .iter()
            .find(|param| param.index == 0)
            .expect("forwarded parameter");
        assert_eq!(param.ty.is_pointer(), !attached);
    }
}

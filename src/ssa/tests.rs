use super::{build, entry_demands, lower, verify};
use crate::ir::{BinOp, Block, Cond, Expr, FunctionIr, Operation, Precision, RegRef, Stmt};
use crate::loader::Isa;

fn assign(index: u16, value: Expr) -> Stmt {
    Stmt::Assign {
        dest: RegRef { index, width: 64 },
        value,
    }
}

fn output_call(output_registers: &[u16], changed: &[u16]) -> Stmt {
    Stmt::Call {
        kind: crate::ir::CallKind::Invoke,
        target: Some(0x1000),
        through: None,
        convention: crate::ir::Convention::Aapcs64,
        args: Some(Vec::new()),
        floats_named: true,
        abi: None,
        outputs: output_registers
            .iter()
            .map(|register| crate::ir::CallOutput {
                register: *register,
                dest: RegRef {
                    index: *register,
                    width: 64,
                },
            })
            .collect(),
        clobbers: Some(changed.iter().copied().collect()),
        via: None,
    }
}

#[test]
fn all_call_outputs_keep_provenance_through_ssa_and_splitting() {
    use crate::ir::eval::{self, Setup};
    for output_registers in [&[32, 34, 36, 38][..], &[0, 32], &[0, 1]] {
        let sum =
            output_registers
                .iter()
                .enumerate()
                .fold(Expr::Const(0), |value, (at, register)| {
                    Expr::bin(
                        BinOp::Add,
                        value,
                        Expr::bin(
                            BinOp::Mul,
                            Expr::reg(*register, 64),
                            Expr::Const(at as u64 + 1),
                        ),
                    )
                });
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                output_call(output_registers, output_registers),
                Stmt::Ret { value: sum },
            ],
        );
        ir.convention = crate::ir::Convention::Aapcs64;
        for seed in [0, 1, u64::MAX] {
            let setup = Setup {
                seed,
                convention: eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &[],
                memory: &[],
                step_limit: 100,
            };
            let expected =
                output_registers
                    .iter()
                    .enumerate()
                    .fold(0_u64, |sum, (at, register)| {
                        sum.wrapping_add(
                            eval::hash(seed ^ 1, 0x2_0000 + u64::from(*register))
                                .wrapping_mul(at as u64 + 1),
                        )
                    });
            let before = eval::run(&ir, &setup);
            assert!(matches!(before, eval::Outcome::Return { value, .. } if value == expected));
            let mut defined = ir.clone();
            super::undefine_clobbered_reads(&mut defined);
            assert_eq!(eval::run(&defined, &setup), before);
            let mut ssa = build(&ir).unwrap();
            verify(&ssa).unwrap();
            let constants = super::sccp::constants(&ssa);
            let ranges = super::ranges::Ranges::solve(&ssa).unwrap();
            for (output, register) in ssa.ir.blocks[0].stmts[0]
                .call_outputs()
                .iter()
                .zip(output_registers)
            {
                assert_eq!(output.register, *register);
                assert!(!constants.contains_key(&output.dest.index));
                assert_eq!(
                    ranges.read(output.dest.index, 64, 0, 0),
                    Some(super::ranges::Fact::TOP)
                );
                assert!(
                    !ssa.implicit_writes
                        .get(&(0, 0))
                        .into_iter()
                        .flatten()
                        .any(|(physical, _)| physical == register)
                );
            }
            super::sccp::propagate(&mut ssa);
            verify(&ssa).unwrap();
            assert_eq!(eval::run(&lower(&ssa), &setup), before);
            let mut renamed = ir.clone();
            super::split_variables(&mut renamed, &(0..64).collect::<Vec<_>>());
            assert_eq!(eval::run(&renamed, &setup), before);
            let rebuilt = build(&renamed).unwrap();
            verify(&rebuilt).unwrap();
            for (output, register) in renamed.blocks[0].stmts[0]
                .call_outputs()
                .iter()
                .zip(output_registers)
            {
                assert_eq!(output.register, *register);
                assert!(output.dest.index >= crate::ir::VARIABLE_BASE);
                assert!(
                    !rebuilt
                        .implicit_writes
                        .get(&(0, 0))
                        .into_iter()
                        .flatten()
                        .any(|(physical, _)| physical == register)
                );
            }
            assert_eq!(eval::run(&lower(&rebuilt), &setup), before);
            crate::passes::dce::dce_flow(&mut renamed);
            assert_eq!(eval::run(&renamed, &setup), before);
        }
    }
}

#[test]
fn canonical_call_aliases_preserve_both_readers_and_unnamed_inputs() {
    use crate::ir::eval::{self, Setup};
    let named = crate::ir::VARIABLE_BASE + 100;
    let observe = 0x4000_0080_0000;
    for changed in [false, true] {
        for unnamed in [false, true] {
            for seed in [0, 1, 0x1234_5678] {
                for initial in [0, 0x8123_4567_ffff_0011, u64::MAX] {
                    let mut ir = FunctionIr::single_block(
                        Isa::AArch64,
                        vec![
                            assign(0, Expr::Const(initial)),
                            output_call(
                                if changed { &[0] } else { &[] },
                                if changed { &[0] } else { &[] },
                            ),
                            assign(named, Expr::reg(0, 64)),
                        ],
                    );
                    ir.convention = crate::ir::Convention::Aapcs64;
                    if unnamed {
                        let mut call = output_call(&[], &[]);
                        let Stmt::Call {
                            args,
                            floats_named,
                            target,
                            ..
                        } = &mut call
                        else {
                            unreachable!()
                        };
                        *args = None;
                        *floats_named = false;
                        *target = Some(0x2000);
                        ir.blocks[0].stmts.push(call);
                    }
                    ir.blocks[0].stmts.extend([
                        Stmt::Store {
                            addr: Expr::Const(observe),
                            value: Expr::reg(0, 64),
                            width: 8,
                        },
                        Stmt::Store {
                            addr: Expr::Const(observe + 8),
                            value: Expr::reg(named, 64),
                            width: 8,
                        },
                        Stmt::Ret {
                            value: Expr::bin(
                                BinOp::Add,
                                Expr::bin(BinOp::Mul, Expr::reg(0, 64), Expr::Const(3)),
                                Expr::bin(BinOp::Mul, Expr::reg(named, 64), Expr::Const(5)),
                            ),
                        },
                    ]);
                    let setup = Setup {
                        seed,
                        convention: eval::Convention {
                            arguments: &[],
                            clobbered: &[],
                        },
                        registers: &[],
                        memory: &[],
                        step_limit: 100,
                    };
                    let expected = if changed {
                        eval::hash(seed ^ 1, 0x2_0000)
                    } else {
                        initial
                    };
                    let before = eval::run(&ir, &setup);
                    let eval::Outcome::Return {
                        value,
                        calls,
                        memory,
                    } = &before
                    else {
                        panic!("{before:?}")
                    };
                    assert_eq!(*value, expected.wrapping_mul(8));
                    assert_eq!(calls.len(), if unnamed { 2 } else { 1 });
                    if unnamed {
                        assert_eq!(calls[1].arguments[0], expected);
                    }
                    for address in [observe, observe + 8] {
                        let word = u64::from_le_bytes(std::array::from_fn(|byte| {
                            memory[&(address + byte as u64)]
                        }));
                        assert_eq!(word, expected);
                    }
                    let ssa = build(&ir).unwrap();
                    verify(&ssa).unwrap();
                    let Stmt::Assign { dest: input, .. } = &ssa.ir.blocks[0].stmts[0] else {
                        unreachable!()
                    };
                    let source = if changed {
                        ssa.ir.blocks[0].stmts[1].call_outputs()[0].dest.index
                    } else {
                        input.index
                    };
                    let Stmt::Assign { dest: alias, value } = &ssa.ir.blocks[0].stmts[2] else {
                        unreachable!()
                    };
                    assert_eq!(*value, Expr::reg(source, 64));
                    assert_ne!(alias.index, source);
                    assert_eq!(eval::run(&lower(&ssa), &setup), before);
                    super::split_variables(&mut ir, &(0..31).collect::<Vec<_>>());
                    super::take_results_directly(&mut ir);
                    assert_eq!(eval::run(&ir, &setup), before);
                    let rebuilt = build(&ir).unwrap();
                    verify(&rebuilt).unwrap();
                    let first = ir.blocks[0]
                        .stmts
                        .iter()
                        .position(|stmt| {
                            matches!(
                                stmt,
                                Stmt::Call {
                                    target: Some(0x1000),
                                    ..
                                }
                            )
                        })
                        .unwrap();
                    if changed && unnamed {
                        assert_eq!(ir.blocks[0].stmts[first].call_outputs()[0].dest.index, 0);
                        let physical = rebuilt.ir.blocks[0].stmts[first].call_outputs()[0]
                            .dest
                            .index;
                        let next = ir.blocks[0]
                            .stmts
                            .iter()
                            .position(|stmt| {
                                matches!(
                                    stmt,
                                    Stmt::Call {
                                        target: Some(0x2000),
                                        ..
                                    }
                                )
                            })
                            .unwrap();
                        assert!(rebuilt.implicit_reads[&(0, next)].contains(&(0, physical)));
                    }
                    assert_eq!(eval::run(&lower(&rebuilt), &setup), before);
                    crate::passes::dce::dce_flow(&mut ir);
                    assert_eq!(eval::run(&ir, &setup), before);
                }
            }
        }
    }
}

#[test]
fn preserved_call_outputs_transfer_only_demanded_bits_to_the_prevalue() {
    for width in [32, 64] {
        let mut call = output_call(&[32, 38], &[]);
        for output in call.call_outputs_mut() {
            output.dest.index = crate::ir::VARIABLE_BASE + output.register;
        }
        let needed = if width == 32 { 0xffff_ffff } else { u64::MAX };
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                call,
                Stmt::Ret {
                    value: Expr::reg(crate::ir::VARIABLE_BASE + 38, width),
                },
            ],
        );
        ir.convention = crate::ir::Convention::Aapcs64;
        let demand = entry_demands(&ir, &[u64::MAX]).unwrap();
        assert_eq!(demand[&38], needed);
        assert_eq!(demand[&32], 0);
        let ssa = build(&ir).unwrap();
        verify(&ssa).unwrap();
        assert!(ssa.implicit_reads[&(0, 0)].contains(&(38, ssa.entry[&38])));
        let Stmt::Call {
            args, floats_named, ..
        } = &mut ir.blocks[0].stmts[0]
        else {
            unreachable!()
        };
        *args = None;
        *floats_named = false;
        assert_eq!(entry_demands(&ir, &[needed]).unwrap()[&38], u64::MAX);
    }
    let mut call = output_call(&[38], &[]);
    call.call_outputs_mut()[0].dest = RegRef {
        index: crate::ir::VARIABLE_BASE,
        width: 32,
    };
    let mut ir = FunctionIr::single_block(
        Isa::AArch64,
        vec![
            call,
            Stmt::Ret {
                value: Expr::reg(crate::ir::VARIABLE_BASE, 64),
            },
        ],
    );
    ir.convention = crate::ir::Convention::Aapcs64;
    assert_eq!(entry_demands(&ir, &[u64::MAX]).unwrap()[&38], 0xffff_ffff);
}

#[test]
fn preserved_call_output_keeps_its_producer_and_snapshots_crossed_destinations() {
    use crate::ir::eval::{self, Setup};
    let mut call = output_call(&[0, 1], &[]);
    call.call_outputs_mut()[0].dest.index = 1;
    call.call_outputs_mut()[1].dest.index = 0;
    let mut ir = FunctionIr::single_block(
        Isa::AArch64,
        vec![
            assign(0, Expr::Const(0x1234)),
            assign(1, Expr::Const(0xabcd)),
            call,
            Stmt::Ret {
                value: Expr::bin(BinOp::Sub, Expr::reg(0, 64), Expr::reg(1, 64)),
            },
        ],
    );
    ir.convention = crate::ir::Convention::Aapcs64;
    let setup = Setup {
        seed: 1,
        convention: eval::Convention {
            arguments: &[],
            clobbered: &[],
        },
        registers: &[],
        memory: &[],
        step_limit: 100,
    };
    let before = eval::run(&ir, &setup);
    assert!(matches!(before, eval::Outcome::Return { value, .. } if value == 0xabcd - 0x1234));
    let ssa = build(&ir).unwrap();
    verify(&ssa).unwrap();
    assert_eq!(eval::run(&lower(&ssa), &setup), before);
    super::split_variables(&mut ir, &[0, 1]);
    assert_eq!(eval::run(&ir, &setup), before);
    crate::passes::dce::dce_flow(&mut ir);
    assert_eq!(eval::run(&ir, &setup), before);
}

#[test]
fn forwarding_one_output_cannot_overwrite_an_intervening_old_value_read() {
    let named = crate::ir::VARIABLE_BASE;
    let saved = named + 1;
    let ir = FunctionIr::single_block(
        Isa::AArch64,
        vec![
            output_call(&[0], &[0]),
            assign(saved, Expr::reg(named, 64)),
            assign(named, Expr::reg(0, 64)),
            Stmt::Ret {
                value: Expr::bin(BinOp::Add, Expr::reg(named, 64), Expr::reg(saved, 64)),
            },
        ],
    );
    let mut forwarded = ir;
    super::take_results_directly(&mut forwarded);
    assert_eq!(forwarded.blocks[0].stmts[0].call_outputs()[0].dest.index, 0);
    assert_eq!(forwarded.blocks[0].stmts.len(), 4);
}

#[test]
fn forwarding_a_call_output_cannot_widen_its_definition() {
    use crate::ir::eval::{self, Setup};
    let first = crate::ir::VARIABLE_BASE;
    let second = first + 1;
    let mut call = output_call(&[0], &[0]);
    call.call_outputs_mut()[0].dest = RegRef {
        index: first,
        width: 32,
    };
    let ir = FunctionIr::single_block(
        Isa::AArch64,
        vec![
            call,
            assign(second, Expr::reg(first, 64)),
            Stmt::Ret {
                value: Expr::reg(second, 64),
            },
        ],
    );
    let mut forwarded = ir.clone();
    super::take_results_directly(&mut forwarded);
    assert_eq!(forwarded.blocks[0].stmts.len(), 3);
    assert_eq!(
        forwarded.blocks[0].stmts[0].call_outputs()[0].dest.width,
        32
    );
    for seed in [0, 1, 0x1234_5678] {
        let setup = Setup {
            seed,
            convention: eval::Convention {
                arguments: &[],
                clobbered: &[],
            },
            registers: &[],
            memory: &[],
            step_limit: 100,
        };
        let before = eval::run(&ir, &setup);
        assert!(matches!(before, eval::Outcome::Return { value, .. }
                if value == eval::hash(seed ^ 1, 0x2_0000) & 0xffff_ffff));
        assert_eq!(eval::run(&forwarded, &setup), before);
    }
}

#[test]
fn entry_demands_distinguish_each_result_piece_and_read_width() {
    let ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![Stmt::Ret {
            value: Expr::apply(Operation::Results, vec![Expr::reg(0, 64), Expr::reg(1, 16)]),
        }],
    );
    let demand = entry_demands(&ir, &[0xffff_ffff, 0xff]).unwrap();
    assert_eq!(demand[&0], 0xffff_ffff);
    assert_eq!(demand[&1], 0xff);
    let unknown = entry_demands(&ir, &[]).unwrap();
    assert_eq!(unknown[&0], u64::MAX);
    assert_eq!(unknown[&1], 0xffff);
    assert!(entry_demands(&ir, &[u64::MAX]).is_none());
    let scalar = FunctionIr::single_block(
        Isa::X86_64,
        vec![Stmt::Ret {
            value: Expr::reg(0, 64),
        }],
    );
    assert!(entry_demands(&scalar, &[1, 1]).is_none());
}

#[test]
fn entry_demands_use_floating_operand_precision_without_changing_partial_writes() {
    for (precision, expected) in [
        (Precision::Single, 0xffff_ffff),
        (Precision::Double, u64::MAX),
    ] {
        let ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![Stmt::Ret {
                value: Expr::apply(Operation::FloatNegate(precision), vec![Expr::reg(0, 64)]),
            }],
        );
        assert_eq!(entry_demands(&ir, &[u64::MAX]).unwrap()[&0], expected);
        let ssa = build(&ir).unwrap();
        assert_eq!(
            super::demanded_bits(&ssa, None, &Default::default())[&ssa.entry[&0]],
            u64::MAX
        );
    }
}

#[test]
fn entry_demands_keep_raw_float_bits_and_sign_extension_distinct() {
    let ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            Stmt::Store {
                addr: Expr::Const(0x1000),
                value: Expr::reg(0, 64),
                width: 8,
            },
            Stmt::Ret {
                value: Expr::SignExtend {
                    value: Box::new(Expr::reg(1, 64)),
                    width: 2,
                },
            },
        ],
    );
    let demand = entry_demands(&ir, &[u64::MAX]).unwrap();
    assert_eq!(demand[&0], u64::MAX);
    assert_eq!(demand[&1], 0xffff);
}

#[test]
fn entry_demands_follow_values_across_a_narrow_overwrite() {
    let ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            Stmt::Store {
                addr: Expr::Const(0x1000),
                value: Expr::reg(0, 64),
                width: 1,
            },
            Stmt::Assign {
                dest: RegRef {
                    index: 0,
                    width: 32,
                },
                value: Expr::Const(0x1_0000_0005),
            },
            Stmt::Ret {
                value: Expr::reg(0, 64),
            },
        ],
    );
    assert_eq!(entry_demands(&ir, &[u64::MAX]).unwrap()[&0], 0xff);
    let run = |value| {
        crate::ir::eval::run(
            &ir,
            &crate::ir::eval::Setup {
                seed: 0,
                convention: crate::ir::eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &[(0, value)],
                memory: &[],
                step_limit: 10,
            },
        )
    };
    let original = run(0x12);
    let crate::ir::eval::Outcome::Return {
        value,
        calls,
        memory,
    } = &original
    else {
        panic!("a return");
    };
    assert_eq!(*value, 5);
    assert!(calls.is_empty());
    assert_eq!(memory.get(&0x1000), Some(&0x12));
    assert_eq!(original, run(0xffff_ffff_ffff_ff12));
}

#[test]
fn entry_demands_reject_unknown_effects_and_missing_jump_targets() {
    for stmt in [
        Stmt::Unsupported {
            text: "unknown".to_owned(),
            writes: Some(Vec::new()),
        },
        Stmt::Br { target: None },
        Stmt::Br {
            target: Some(0x1234),
        },
        Stmt::BrIndirect {
            target: Expr::reg(0, 64),
        },
        Stmt::BrifFlags {
            cond: Cond::Eq,
            target: 0,
        },
        Stmt::Switch {
            index: Expr::reg(0, 64),
            cases: Vec::new(),
            default: None,
        },
    ] {
        assert!(entry_demands(&FunctionIr::single_block(Isa::X86_64, vec![stmt]), &[]).is_none());
    }
}

#[test]
fn entry_demands_follow_loop_phis_without_requiring_unused_upper_bits() {
    let mut ir = FunctionIr::single_block(Isa::X86_64, vec![Stmt::Br { target: Some(0x10) }]);
    ir.blocks.push(Block {
        start: 0x10,
        stmts: vec![
            assign(0, Expr::bin(BinOp::Add, Expr::reg(0, 64), Expr::Const(1))),
            Stmt::Brif {
                cond: Cond::Ne,
                lhs: Expr::reg(0, 8),
                rhs: Expr::reg(1, 8),
                target: 0x10,
            },
        ],
    });
    ir.blocks.push(Block {
        start: 0x20,
        stmts: vec![Stmt::Ret {
            value: Expr::reg(0, 64),
        }],
    });
    let demand = entry_demands(&ir, &[0xff]).unwrap();
    assert_eq!(demand[&0], 0xff);
    assert_eq!(demand[&1], 0xff);
}

#[test]
fn entry_demands_map_constant_right_shifts_and_select_arms() {
    for count in [0, 1, 63, 64, 65, 127] {
        let ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![Stmt::Ret {
                value: Expr::Select {
                    cond: Cond::Eq,
                    lhs: Box::new(Expr::reg(1, 8)),
                    rhs: Box::new(Expr::Const(0)),
                    then: Box::new(Expr::bin(BinOp::Shr, Expr::reg(0, 64), Expr::Const(count))),
                    els: Box::new(Expr::reg(2, 64)),
                },
            }],
        );
        let demand = entry_demands(&ir, &[0xf]).unwrap();
        assert_eq!(demand[&0], 0xfu64 << (count & 63));
        assert_eq!(demand[&1], 0xff);
        assert_eq!(demand[&2], 0xf);
        let ssa = build(&ir).unwrap();
        assert_eq!(
            super::demanded_bits(&ssa, None, &Default::default())[&ssa.entry[&0]],
            u64::MAX
        );
    }
}

fn stack_at(offset: i64) -> Expr {
    Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const(offset as u64))
}

fn stack_load(offset: i64, width: u8) -> Expr {
    Expr::Load {
        addr: Box::new(stack_at(offset)),
        width,
        signed: false,
    }
}

fn spill_then(value: Expr) -> FunctionIr {
    FunctionIr::single_block(
        Isa::X86_64,
        vec![
            Stmt::Store {
                addr: stack_at(-8),
                value: Expr::reg(7, 64),
                width: 4,
            },
            Stmt::Ret { value },
        ],
    )
}

#[test]
fn entry_demands_limit_private_spills_to_read_bytes() {
    for (value, expected) in [
        (stack_load(-8, 1), 0xff),
        (stack_load(-6, 2), 0xffff_0000),
        (
            Expr::bin(BinOp::Xor, stack_load(-9, 2), stack_load(-5, 2)),
            0xff00_00ff,
        ),
        (Expr::Const(0), 0),
    ] {
        let ir = spill_then(value);
        assert_eq!(entry_demands(&ir, &[u64::MAX]).unwrap()[&7], expected);
        let ssa = build(&ir).unwrap();
        assert_eq!(
            super::demanded_bits(&ssa, None, &Default::default())[&ssa.entry[&7]],
            0xffff_ffff
        );
    }
    let mut incoming = spill_then(stack_load(8, 1));
    if let Stmt::Store { addr, .. } = &mut incoming.blocks[0].stmts[0] {
        *addr = stack_at(8);
    }
    assert_eq!(
        entry_demands(&incoming, &[u64::MAX]).unwrap()[&7],
        0xffff_ffff
    );
}

#[test]
fn entry_demands_match_spill_positions_across_frames_and_blocks() {
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            assign(4, stack_at(-16)),
            Stmt::Store {
                addr: stack_at(8),
                value: Expr::reg(7, 64),
                width: 4,
            },
            Stmt::Store {
                addr: stack_at(12),
                value: Expr::reg(6, 64),
                width: 4,
            },
            Stmt::Br { target: Some(0x10) },
        ],
    );
    ir.blocks.push(Block {
        start: 0x10,
        stmts: vec![
            assign(4, stack_at(16)),
            Stmt::Ret {
                value: Expr::bin(BinOp::Or, stack_load(-7, 1), stack_load(-2, 1)),
            },
        ],
    });
    let ssa = build(&ir).unwrap();
    for (original, renamed) in ir.blocks.iter().zip(&ssa.ir.blocks) {
        assert_eq!(original.stmts.len(), renamed.stmts.len());
        for (original, renamed) in original.stmts.iter().zip(&renamed.stmts) {
            assert_eq!(
                std::mem::discriminant(original),
                std::mem::discriminant(renamed)
            );
        }
    }
    let demand = entry_demands(&ir, &[u64::MAX]).unwrap();
    assert_eq!(demand[&7], 0xff00);
    assert_eq!(demand[&6], 0xff_0000);
}

#[test]
fn entry_demands_keep_spills_whole_when_stack_addresses_are_unproven() {
    let load = |addr| Expr::Load {
        addr: Box::new(addr),
        width: 1,
        signed: false,
    };
    for value in [
        load(Expr::reg(8, 64)),
        load(Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::reg(8, 64))),
        load(Expr::bin(
            BinOp::Add,
            Expr::reg(4, 32),
            Expr::Const((-8i64) as u64),
        )),
        stack_load(i64::MAX, 1),
    ] {
        let ir = spill_then(value);
        assert_eq!(entry_demands(&ir, &[u64::MAX]).unwrap()[&7], 0xffff_ffff);
    }
    let mut escaped = spill_then(stack_load(-8, 1));
    escaped.blocks[0].stmts.insert(1, assign(8, stack_at(-8)));
    assert_eq!(
        entry_demands(&escaped, &[u64::MAX]).unwrap()[&7],
        0xffff_ffff
    );
    for value in [
        Expr::bin(BinOp::Sub, Expr::reg(4, 64), Expr::Const(i64::MIN as u64)),
        Expr::reg(8, 64),
    ] {
        let mut ir = spill_then(stack_load(-8, 1));
        ir.blocks[0].stmts.insert(0, assign(4, value));
        assert_eq!(entry_demands(&ir, &[u64::MAX]).unwrap()[&7], 0xffff_ffff);
    }
}

#[test]
fn entry_demands_keep_external_stores_and_unknown_frames_whole() {
    let mut external = spill_then(stack_load(-8, 1));
    external.blocks[0].stmts.insert(
        1,
        Stmt::Store {
            addr: Expr::reg(8, 64),
            value: Expr::reg(6, 64),
            width: 8,
        },
    );
    let demand = entry_demands(&external, &[u64::MAX]).unwrap();
    assert_eq!(demand[&7], 0xffff_ffff);
    assert_eq!(demand[&6], u64::MAX);
    let mut ir = spill_then(stack_load(-8, 1));
    ir.blocks[0].stmts[1] = Stmt::Brif {
        cond: Cond::Eq,
        lhs: Expr::reg(8, 64),
        rhs: Expr::Const(0),
        target: 0x20,
    };
    ir.blocks.push(Block {
        start: 0x10,
        stmts: vec![assign(4, stack_at(-16)), Stmt::Br { target: Some(0x20) }],
    });
    ir.blocks.push(Block {
        start: 0x20,
        stmts: vec![Stmt::Ret {
            value: stack_load(-8, 1),
        }],
    });
    assert_eq!(entry_demands(&ir, &[u64::MAX]).unwrap()[&7], 0xffff_ffff);
}

#[test]
fn entry_demands_keep_load_addresses_observable_in_unread_private_stores() {
    let mut ir = spill_then(Expr::Const(0));
    if let Stmt::Store { value, .. } = &mut ir.blocks[0].stmts[0] {
        *value = stack_load(-16, 1);
    }
    assert_eq!(entry_demands(&ir, &[u64::MAX]).unwrap()[&4], u64::MAX);
}

#[test]
fn entry_demands_keep_stores_outside_private_stack_memory_observable() {
    let span = crate::ir::eval::STACK_SPAN as i64;
    for (offset, width, expected) in [
        (-span, 4, 0xff),
        (-span - 4, 4, 0xffff_ffff),
        (-span - 2, 4, 0xffff_ffff),
        (-4, 8, u64::MAX),
    ] {
        let ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Store {
                    addr: stack_at(offset),
                    value: Expr::reg(7, 64),
                    width,
                },
                Stmt::Ret {
                    value: stack_load(offset, 1),
                },
            ],
        );
        assert_eq!(entry_demands(&ir, &[0xff]).unwrap()[&7], expected);
    }
    let ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            Stmt::Store {
                addr: stack_at(-2 * span),
                value: Expr::reg(7, 64),
                width: 8,
            },
            Stmt::Ret {
                value: Expr::reg(7, 8),
            },
        ],
    );
    assert_eq!(entry_demands(&ir, &[0xff]).unwrap()[&7], u64::MAX);
    let run = |value| {
        crate::ir::eval::run(
            &ir,
            &crate::ir::eval::Setup {
                seed: 0,
                convention: crate::ir::eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &[(7, value)],
                memory: &[],
                step_limit: 10,
            },
        )
    };
    let first = run(0x12);
    let second = run(0xffff_ffff_ffff_ff12);
    let (
        crate::ir::eval::Outcome::Return {
            value: left,
            memory: before,
            ..
        },
        crate::ir::eval::Outcome::Return {
            value: right,
            memory: after,
            ..
        },
    ) = (&first, &second)
    else {
        panic!("two returns")
    };
    assert_eq!(left, right);
    assert_ne!(before, after);
}

#[test]
fn entry_demands_keep_private_spills_whole_across_calls() {
    let mut ir = spill_then(stack_load(-8, 1));
    ir.blocks[0].stmts.insert(
        1,
        Stmt::Call {
            kind: crate::ir::CallKind::Invoke,
            target: Some(1),
            through: None,
            convention: crate::ir::Convention::SysV,
            args: Some(Vec::new()),
            floats_named: true,
            abi: None,
            outputs: crate::ir::fallback_call_outputs(crate::ir::Convention::SysV, None),
            clobbers: None,
            via: None,
        },
    );
    assert_eq!(entry_demands(&ir, &[u64::MAX]).unwrap()[&7], 0xffff_ffff);
}

/// `call; mov cl, 1; mov eax, ecx; ret` with the callee changing what
/// `clobbers` says.
fn byte_after_call(clobbers: Option<crate::ir::Registers>) -> FunctionIr {
    const RCX: u16 = 1;
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            Stmt::Call {
                kind: crate::ir::CallKind::Invoke,
                target: Some(0x2000),
                through: None,
                convention: crate::ir::Convention::SysV,
                args: Some(Vec::new()),
                floats_named: false,
                abi: None,
                outputs: crate::ir::fallback_call_outputs(crate::ir::Convention::SysV, clobbers),
                clobbers,
                via: None,
            },
            assign(
                RCX,
                Expr::bin(
                    BinOp::Or,
                    Expr::bin(BinOp::And, Expr::reg(RCX, 64), Expr::Const(!0xff)),
                    Expr::Const(1),
                ),
            ),
            Stmt::Ret {
                value: Expr::reg(RCX, 64),
            },
        ],
    );
    super::undefine_clobbered_reads(&mut ir);
    crate::passes::simplify::simplify(&mut ir);
    ir
}

#[test]
fn a_partial_write_over_a_register_a_call_destroyed_is_the_new_bits() {
    let ir = byte_after_call(None);
    assert!(matches!(
        &ir.blocks[0].stmts[1],
        Stmt::Assign {
            value: Expr::Const(1),
            ..
        }
    ));
}

#[test]
fn a_register_the_callee_keeps_holds_its_earlier_value() {
    let ir = byte_after_call(Some(crate::ir::Registers::default()));
    let Stmt::Assign { value, .. } = &ir.blocks[0].stmts[1] else {
        panic!("an assignment");
    };
    let mut read = std::collections::HashSet::new();
    crate::ir::visit::collect_reads(value, &mut read);
    assert!(read.contains(&1));
}

/// x = 0; loop: x = x + 1; if x != n goto loop; return x
fn counting_loop() -> FunctionIr {
    let x = Expr::reg(0, 64);
    let mut ir = FunctionIr::single_block(Isa::X86_64, vec![assign(0, Expr::Const(0))]);
    ir.blocks.push(Block {
        start: 0x10,
        stmts: vec![
            assign(0, Expr::bin(BinOp::Add, x.clone(), Expr::Const(1))),
            Stmt::Brif {
                cond: Cond::Ne,
                lhs: x.clone(),
                rhs: Expr::reg(7, 64),
                target: 0x10,
            },
        ],
    });
    ir.blocks.push(Block {
        start: 0x20,
        stmts: vec![Stmt::Ret { value: x }],
    });
    ir
}

#[test]
fn a_result_only_moved_on_goes_to_its_variable() {
    let (first, second) = (crate::ir::VARIABLE_BASE, crate::ir::VARIABLE_BASE + 1);
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            Stmt::Call {
                kind: crate::ir::CallKind::Invoke,
                target: Some(0x1000),
                through: None,
                convention: crate::ir::Convention::GoAbi0,
                args: Some(Vec::new()),
                floats_named: false,
                abi: None,
                clobbers: None,
                outputs: crate::ir::fallback_call_outputs(crate::ir::Convention::GoAbi0, None),
                via: None,
            },
            assign(first, Expr::reg(0, 64)),
            assign(second, Expr::reg(first, 64)),
            Stmt::Ret {
                value: Expr::reg(second, 64),
            },
        ],
    );
    super::take_results_directly(&mut ir);
    assert_eq!(ir.blocks[0].stmts.len(), 2);
    assert_eq!(
        ir.blocks[0].stmts[0]
            .primary_call_output()
            .unwrap()
            .dest
            .index,
        second
    );
}

#[test]
fn further_results_moved_on_go_to_their_variables() {
    // v1 = f(); v3 = rbx; v2 = v1; v4 = v3; return v2 + v4;
    let [first, second, third, fourth] =
        [0, 1, 2, 3].map(|offset| crate::ir::VARIABLE_BASE + offset);
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            Stmt::Call {
                kind: crate::ir::CallKind::Invoke,
                target: Some(0x1000),
                through: None,
                convention: crate::ir::Convention::GoAmd64,
                args: Some(Vec::new()),
                floats_named: false,
                abi: None,
                clobbers: None,
                outputs: crate::ir::fallback_call_outputs(crate::ir::Convention::GoAmd64, None),
                via: None,
            },
            assign(first, Expr::reg(0, 64)),
            assign(third, Expr::reg(3, 64)),
            assign(second, Expr::reg(first, 64)),
            assign(fourth, Expr::reg(third, 64)),
            Stmt::Ret {
                value: Expr::bin(BinOp::Add, Expr::reg(second, 64), Expr::reg(fourth, 64)),
            },
        ],
    );
    super::take_results_directly(&mut ir);
    let stmts = &ir.blocks[0].stmts;
    assert_eq!(stmts.len(), 2, "{}", ir.render());
    assert_eq!(stmts[0].primary_call_output().unwrap().dest.index, second);
    assert_eq!(
        stmts[0]
            .call_outputs()
            .iter()
            .find(|output| output.register == 3)
            .unwrap()
            .dest
            .index,
        fourth
    );
}

#[test]
fn a_loop_counter_joins_at_the_loop_header() {
    let ir = counting_loop();
    let ssa = build(&ir).expect("builds");
    assert_eq!(ssa.phis[1].len(), 1, "one φ for the counter");
    let phi = &ssa.phis[1][0];
    assert_eq!(ssa.register_of(phi.value), 0);
    // From the entry, the constant's value; from the back edge, the sum's.
    let defined = |block: usize| match &ssa.ir.blocks[block].stmts[0] {
        Stmt::Assign { dest, .. } => dest.index,
        other => panic!("{other:?}"),
    };
    assert_eq!(phi.args, vec![defined(0), defined(1)]);
    // The parameter n is read at its entry value.
    assert!(ssa.entry.contains_key(&7));
    verify(&ssa).expect("well formed");
}

#[test]
fn a_loop_back_to_the_entry_joins_the_entry_value() {
    // 0: if (rdi == 0) return rax; 1: rax = rax + 1; goto 0
    let rax = Expr::reg(0, 64);
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![Stmt::Brif {
            cond: Cond::Eq,
            lhs: Expr::reg(7, 64),
            rhs: Expr::Const(0),
            target: 0x20,
        }],
    );
    ir.blocks.push(Block {
        start: 0x10,
        stmts: vec![
            assign(0, Expr::bin(BinOp::Add, rax.clone(), Expr::Const(1))),
            Stmt::Br { target: Some(0) },
        ],
    });
    ir.blocks.push(Block {
        start: 0x20,
        stmts: vec![Stmt::Ret { value: rax }],
    });
    let ssa = build(&ir).expect("builds");
    verify(&ssa).expect("well formed");
    let phi = ssa.phis[0].first().expect("a φ at the entry");
    assert_eq!(
        phi.args[0], ssa.entry[&0],
        "the call brings the entry value"
    );
}

#[test]
fn a_partial_write_only_its_low_byte_is_read_of_drops_the_rest() {
    // r11b = 4; store8(r11): the bits r11 kept are never read.
    let keep = Expr::bin(BinOp::And, Expr::reg(11, 64), Expr::Const(!0xff));
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            assign(11, Expr::bin(BinOp::Or, keep, Expr::Const(4))),
            Stmt::Store {
                addr: Expr::reg(7, 64),
                value: Expr::reg(11, 64),
                width: 1,
            },
            Stmt::Ret {
                value: Expr::reg(0, 64),
            },
        ],
    );
    super::narrow_partial_writes(&mut ir);
    assert!(
        matches!(
            &ir.blocks[0].stmts[0],
            Stmt::Assign {
                value: Expr::Const(4),
                ..
            }
        ),
        "{}",
        ir.render()
    );
    // Returned whole, the kept bits stay.
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            assign(
                0,
                Expr::bin(
                    BinOp::Or,
                    Expr::bin(BinOp::And, Expr::reg(0, 64), Expr::Const(!0xff)),
                    Expr::Const(4),
                ),
            ),
            Stmt::Ret {
                value: Expr::reg(0, 64),
            },
        ],
    );
    super::narrow_partial_writes(&mut ir);
    assert!(
        !matches!(
            &ir.blocks[0].stmts[0],
            Stmt::Assign {
                value: Expr::Const(4),
                ..
            }
        ),
        "{}",
        ir.render()
    );
}

#[test]
fn lowering_gives_every_value_its_register_back() {
    let ir = counting_loop();
    let ssa = build(&ir).expect("builds");
    assert_ne!(ssa.ir.render(), ir.render());
    assert_eq!(lower(&ssa).render(), ir.render());
}

#[test]
fn variadic_stack_arguments_follow_the_call_kind() {
    let mut image =
        crate::loader::Image::from_code(Isa::X86_64, 0x4000, b"%d%d%d%d%d%d\0".to_vec());
    image.functions.insert(
        0x1000,
        crate::loader::Function {
            addr: 0x1000,
            size: None,
            size_estimated: false,
            name: Some("printf".to_owned()),
            aliases: Vec::new(),
            sources: Vec::new(),
        },
    );
    // The seventh argument is the first on the stack: at the call it
    // lies just above the stack pointer; at a jump, past the return
    // address the caller pushed.
    for (kind, expected) in [
        (crate::ir::CallKind::Invoke, 0),
        (crate::ir::CallKind::Tail, 8),
    ] {
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                assign(7, Expr::Const(0x4000)),
                Stmt::Call {
                    kind,
                    target: Some(0x1000),
                    through: None,
                    convention: crate::ir::Convention::SysV,
                    args: None,
                    floats_named: false,
                    abi: None,
                    clobbers: None,
                    outputs: crate::ir::fallback_call_outputs(crate::ir::Convention::SysV, None),
                    via: None,
                },
                Stmt::Ret {
                    value: Expr::Const(0),
                },
            ],
        );
        super::count_variadic_arguments(&mut ir, &image);
        let Stmt::Call {
            args: Some(args), ..
        } = &ir.blocks[0].stmts[1]
        else {
            panic!("format arguments");
        };
        assert_eq!(args.len(), 7);
        let stack = Expr::reg(4, 64);
        let wanted = Expr::Load {
            addr: Box::new(Expr::bin(BinOp::Add, stack, Expr::Const(expected))),
            width: 8,
            signed: false,
        };
        assert_eq!(args.last(), Some(&wanted), "{kind:?}");
    }
}
fn declared_call(dependencies: &[u16], deferred_memory: bool) -> Stmt {
    let mut call = output_call(&[], &[]);
    let Stmt::Call { abi, .. } = &mut call else {
        unreachable!()
    };
    *abi = Some(crate::ir::calls::test_call_abi(
        dependencies.to_vec(),
        deferred_memory,
    ));
    call
}

#[test]
fn declared_inputs_are_strong_roots_without_new_operands() {
    let mut call = output_call(&[38], &[]);
    let Stmt::Call { abi, .. } = &mut call else {
        unreachable!()
    };
    *abi = Some(crate::ir::calls::test_call_abi(vec![31, 38], true));
    assert!(call.has_declared_call());
    assert!(call.has_deferred_call_memory());
    assert_eq!(call.declared_call_reads(), &[31, 38]);
    assert!(call.operands().is_empty());
    assert!(!call.unnamed_call_reads().contains(&38));
    let (_, reads) = crate::ir::visit::statement_registers(&call);
    assert!(reads.contains(&31) && reads.contains(&38));
    let ir = FunctionIr::single_block(
        Isa::AArch64,
        vec![
            call,
            Stmt::Ret {
                value: Expr::Const(7),
            },
        ],
    );
    let ssa = build(&ir).unwrap();
    verify(&ssa).unwrap();
    for register in [31, 38] {
        assert!(ssa.implicit_reads[&(0, 0)].contains(&(register, ssa.entry[&register])));
        assert_eq!(entry_demands(&ir, &[]).unwrap()[&register], u64::MAX);
    }
    let mut fallback = ir;
    let Stmt::Call { abi, .. } = &mut fallback.blocks[0].stmts[0] else {
        unreachable!()
    };
    *abi = None;
    assert_eq!(entry_demands(&fallback, &[]).unwrap()[&38], 0);
    let lowered = lower(&ssa);
    assert_eq!(lowered.blocks[0].stmts[0].declared_call_reads(), &[31, 38]);
    assert!(lowered.blocks[0].stmts[0].operands().is_empty());
}

#[test]
fn declared_inputs_capture_each_calls_current_value() {
    let call = declared_call(&[38], false);
    let ir = FunctionIr::single_block(
        Isa::AArch64,
        vec![
            assign(38, Expr::Const(0x1122_3344_5566_7788)),
            call.clone(),
            assign(38, Expr::Const(0x8877_6655_4433_2211)),
            call,
            Stmt::Ret {
                value: Expr::Const(0),
            },
        ],
    );
    let ssa = build(&ir).unwrap();
    verify(&ssa).unwrap();
    let captured = |position| {
        ssa.implicit_reads[&(0, position)]
            .iter()
            .find(|(register, _)| *register == 38)
            .unwrap()
            .1
    };
    let first = captured(1);
    let second = captured(3);
    assert_ne!(first, second);
    let constants = super::sccp::constants(&ssa);
    assert_eq!(constants[&first], 0x1122_3344_5566_7788);
    assert_eq!(constants[&second], 0x8877_6655_4433_2211);
    for stmt in ssa.ir.blocks[0]
        .stmts
        .iter()
        .filter(|stmt| stmt.has_declared_call())
    {
        assert_eq!(stmt.declared_call_reads(), &[38]);
        assert!(!stmt.has_deferred_call_memory());
    }
}

#[test]
fn declared_vector_and_extra_inputs_keep_their_physical_storage() {
    let load = |offset: u64| Expr::Load {
        addr: Box::new(Expr::Const(0x4000 + offset)),
        width: 8,
        signed: false,
    };
    let mut call = declared_call(&[8, 36], false);
    let Stmt::Call { floats_named, .. } = &mut call else {
        unreachable!()
    };
    *floats_named = false;
    let mut ir = FunctionIr::single_block(
        Isa::AArch64,
        vec![
            assign(8, Expr::bin(BinOp::Add, Expr::reg(0, 64), Expr::Const(1))),
            assign(36, load(0)),
            assign(37, load(8)),
            call,
            Stmt::Ret {
                value: Expr::bin(BinOp::Add, Expr::reg(8, 64), Expr::reg(36, 64)),
            },
        ],
    );
    let setup = crate::ir::eval::Setup {
        seed: 1,
        convention: crate::ir::eval::Convention {
            arguments: &[],
            clobbered: &[],
        },
        registers: &[(0, 0x1234)],
        memory: &[
            (0x4000, 0x89ab_cdef_0123_4567),
            (0x4008, 0xfedc_ba98_7654_3210),
        ],
        step_limit: 100,
    };
    let before = crate::ir::eval::run(&ir, &setup);
    super::split_variables(&mut ir, &[8, 36, 37]);
    for register in [8, 36] {
        assert!(
            ir.blocks[0]
                .stmts
                .iter()
                .any(|stmt| matches!(stmt, Stmt::Assign { dest, .. } if dest.index == register))
        );
    }
    let call = ir.blocks[0]
        .stmts
        .iter()
        .find(|stmt| stmt.has_declared_call())
        .unwrap();
    assert_eq!(call.declared_call_reads(), &[8, 36]);
    assert_eq!(crate::ir::eval::run(&ir, &setup), before);
}

#[test]
fn declared_inputs_keep_all_phi_predecessors_in_the_required_register() {
    let mut ir = FunctionIr::single_block(Isa::AArch64, Vec::new());
    ir.blocks = vec![
        Block {
            start: 0,
            stmts: vec![Stmt::Brif {
                cond: Cond::Eq,
                lhs: Expr::reg(0, 64),
                rhs: Expr::Const(0),
                target: 20,
            }],
        },
        Block {
            start: 10,
            stmts: vec![
                assign(38, Expr::Const(0x1111)),
                Stmt::Br { target: Some(30) },
            ],
        },
        Block {
            start: 20,
            stmts: vec![
                assign(38, Expr::Const(0x2222)),
                Stmt::Br { target: Some(30) },
            ],
        },
        Block {
            start: 30,
            stmts: vec![
                declared_call(&[38], false),
                Stmt::Ret {
                    value: Expr::Const(7),
                },
            ],
        },
    ];
    let before = ir.clone();
    let ssa = build(&ir).unwrap();
    verify(&ssa).unwrap();
    let phi = ssa.phis[3]
        .iter()
        .find(|phi| ssa.register_of(phi.value) == 38)
        .unwrap();
    assert_eq!(phi.args.len(), 2);
    assert_ne!(phi.args[0], phi.args[1]);
    assert!(ssa.implicit_reads[&(3, 0)].contains(&(38, phi.value)));
    super::split_variables(&mut ir, &[38]);
    for block in [1, 2] {
        assert!(
            matches!(&ir.blocks[block].stmts[0], Stmt::Assign { dest, .. } if dest.index == 38)
        );
    }
    for selected in [0, 1] {
        let setup = crate::ir::eval::Setup {
            seed: 2,
            convention: crate::ir::eval::Convention {
                arguments: &[],
                clobbered: &[],
            },
            registers: &[(0, selected)],
            memory: &[],
            step_limit: 100,
        };
        assert_eq!(
            crate::ir::eval::run(&ir, &setup),
            crate::ir::eval::run(&before, &setup)
        );
    }
}

#[test]
fn declared_input_load_producers_survive_dce_without_fallback_evaluation() {
    let call = declared_call(&[38], true);
    let mut fallback = call.clone();
    let Stmt::Call { abi, .. } = &mut fallback else {
        unreachable!()
    };
    *abi = None;
    let load = assign(
        38,
        Expr::Load {
            addr: Box::new(Expr::Const(0x4000)),
            width: 8,
            signed: false,
        },
    );
    let mut ir = FunctionIr::single_block(
        Isa::AArch64,
        vec![
            load,
            call,
            Stmt::Ret {
                value: Expr::Const(7),
            },
        ],
    );
    let fallback = FunctionIr::single_block(
        Isa::AArch64,
        vec![
            fallback,
            Stmt::Ret {
                value: Expr::Const(7),
            },
        ],
    );
    let setup = crate::ir::eval::Setup {
        seed: 3,
        convention: crate::ir::eval::Convention {
            arguments: &[],
            clobbered: &[],
        },
        registers: &[],
        memory: &[(0x4000, 0x8123_4567_89ab_cdef)],
        step_limit: 100,
    };
    let expected = crate::ir::eval::Outcome::Return {
        value: 7,
        calls: vec![crate::ir::eval::Call {
            target: Some(0x1000),
            arguments: Vec::new(),
        }],
        memory: (0x4000..0x4008)
            .zip(0x8123_4567_89ab_cdefu64.to_le_bytes())
            .collect(),
    };
    assert_eq!(crate::ir::eval::run(&fallback, &setup), expected);
    assert_eq!(crate::ir::eval::run(&ir, &setup), expected);
    crate::passes::dce::dce_flow(&mut ir);
    assert!(
        matches!(&ir.blocks[0].stmts[0], Stmt::Assign { dest, value: Expr::Load { width: 8, .. } } if dest.index == 38)
    );
    assert!(ir.blocks[0].stmts[1].operands().is_empty());
    assert_eq!(crate::ir::eval::run(&ir, &setup), expected);
}

#[test]
fn declared_calls_do_not_reconstruct_variadic_fallback_arguments() {
    let mut image = crate::loader::Image::from_code(Isa::AArch64, 0x4000, b"%d\0".to_vec());
    image.functions.insert(
        0x1000,
        crate::loader::Function {
            addr: 0x1000,
            size: None,
            size_estimated: false,
            name: Some("printf".to_owned()),
            aliases: Vec::new(),
            sources: Vec::new(),
        },
    );
    let mut attached = declared_call(&[0], false);
    let mut fallback = output_call(&[], &[]);
    for call in [&mut attached, &mut fallback] {
        let Stmt::Call { args, .. } = call else {
            unreachable!()
        };
        *args = None;
    }
    let before = format!("{attached:?}");
    let mut ir = FunctionIr::single_block(
        Isa::AArch64,
        vec![
            assign(0, Expr::Const(0x4000)),
            attached,
            fallback,
            Stmt::Ret {
                value: Expr::Const(0),
            },
        ],
    );
    super::count_variadic_arguments(&mut ir, &image);
    assert_eq!(format!("{:?}", ir.blocks[0].stmts[1]), before);
    assert!(
        matches!(&ir.blocks[0].stmts[2], Stmt::Call { args: Some(args), .. } if args.len() == 2)
    );
}

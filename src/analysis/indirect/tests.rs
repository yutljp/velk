use super::*;
use crate::ir::{CallOutput, RegRef, VARIABLE_BASE};
use crate::loader::{Function, Isa, Section};

#[test]
fn pointer_offsets_smt_preserve_native_addresses() {
    use crate::ir::smt::{Proofs, raw_bin};
    let image = Image::from_code(Isa::I386, 0, Vec::new());
    let tracker = Tracker {
        image: &image,
        sp: 4,
        loads: Default::default(),
        constructors: false,
        returns: None,
    };
    let mut proofs = Proofs::default();
    for offset in [
        0,
        1,
        u64::from(u32::MAX),
        0x1_0000_0000,
        i64::MAX as u64,
        u64::MAX,
    ] {
        let before = raw_bin(
            BinOp::And,
            raw_bin(BinOp::Add, Expr::reg(4, 64), Expr::Const(offset)),
            Expr::Const(u64::from(u32::MAX)),
        );
        let Value::Sym(_, narrowed) = tracker.eval(&State::entry(), &before, (0, 0), &mut 0) else {
            panic!("symbolic pointer must retain its base");
        };
        let after = raw_bin(BinOp::Add, Expr::reg(4, 32), Expr::Const(narrowed));
        proofs.expression(format!("pointer-offset/{offset:x}"), &before, &after, 32);
    }
    if Proofs::available() {
        proofs.check();
    }
    assert!(tracker.may_alias(
        Value::Sym(Base::Entry(4), 0xffff_fffe),
        4,
        Value::Sym(Base::Entry(4), 0),
        1
    ));
    assert!(!tracker.may_alias(
        Value::Sym(Base::Entry(4), 0xffff_fffe),
        2,
        Value::Sym(Base::Entry(4), 0),
        1
    ));
    assert!(tracker.may_alias(Value::Const(0, None), 8, Value::Const(1 << 63, None), 8));
    let wide_image = Image::from_code(Isa::X86_64, 0, Vec::new());
    let wide_tracker = Tracker {
        image: &wide_image,
        ..tracker
    };
    assert!(!wide_tracker.may_alias(Value::Const(0, None), 8, Value::Const(1 << 63, None), 8));
}

#[test]
fn stored_code_addresses_use_the_target_pointer_width() {
    for (isa, code) in [
        (Isa::I386, vec![0x8b, 0x44, 0x24, 4, 0xc3]),
        (Isa::X86_64, vec![0x8d, 0x47, 1, 0xc3]),
        (
            Isa::Arm32,
            [0xe2800001u32, 0xe12fff1e]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect(),
        ),
        (
            Isa::AArch64,
            [0x11000400u32, 0xd65f03c0]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect(),
        ),
    ] {
        let size = code.len() as u64;
        let mut image = Image::from_code(isa, 0x80, code);
        image.functions.insert(
            0x80,
            Function {
                addr: 0x80,
                size: Some(size),
                size_estimated: false,
                name: Some("increment".to_owned()),
                aliases: Vec::new(),
                library: None,
                sources: Vec::new(),
            },
        );
        let width = crate::arch::pointer_bytes(isa);
        for offset in [0, 8, 24, u64::from(u32::MAX)] {
            for overlap in [false, true] {
                let slot = Expr::bin(
                    BinOp::Add,
                    Expr::reg(crate::arch::stack_pointer(isa), 64),
                    Expr::Const(offset),
                );
                let mut stmts = vec![Stmt::Store {
                    addr: slot.clone(),
                    value: Expr::Const(0x80),
                    width,
                }];
                if overlap {
                    stmts.push(Stmt::Store {
                        addr: slot.clone(),
                        value: Expr::reg(3, 64),
                        width: 1,
                    });
                }
                stmts.push(crate::lift::call_through(
                    crate::ir::CallKind::Invoke,
                    &image,
                    Expr::Load {
                        addr: Box::new(slot),
                        width,
                        signed: false,
                    },
                ));
                stmts.push(Stmt::Ret {
                    value: Expr::reg(0, 64),
                });
                let mut blocks = [Block { start: 0, stmts }];
                resolve(&mut blocks, &[], &image);
                let call = blocks[0]
                    .stmts
                    .iter()
                    .find(|stmt| matches!(stmt, Stmt::Call { .. }))
                    .unwrap();
                assert_eq!(
                    matches!(
                        call,
                        Stmt::Call {
                            target: Some(0x80),
                            through: None,
                            ..
                        }
                    ),
                    !overlap,
                    "{isa:?}: {call:?}"
                );
            }
        }
    }
}

fn pointer_factory(isa: Isa, table: bool, factory: Vec<u8>) -> (Image, Vec<Block>) {
    let (caller, target) = match isa {
        Isa::X86_64 => (
            vec![
                0x48,
                0x83,
                0xec,
                8,
                0xe8,
                0x37,
                0,
                0,
                0,
                0xff,
                if table { 0x10 } else { 0xd0 },
                0x48,
                0x83,
                0xc4,
                8,
                0xc3,
            ],
            vec![0xb8, 7, 0, 0, 0, 0xc3],
        ),
        Isa::AArch64 => (
            [
                0xa9bf7bfdu32,
                0x9400000f,
                if table { 0xf9400008 } else { 0xaa0003e8 },
                0xd63f0100,
                0xa8c17bfd,
                0xd65f03c0,
            ]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(),
            [0x528000e0u32, 0xd65f03c0]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect(),
        ),
        Isa::Arm32 | Isa::I386 | Isa::Unsupported => unreachable!(),
    };
    let mut code = vec![0; 0x90];
    code[..caller.len()].copy_from_slice(&caller);
    code[0x40..0x40 + factory.len()].copy_from_slice(&factory);
    code[0x80..0x80 + target.len()].copy_from_slice(&target);
    code.extend_from_slice(&0x80u64.to_le_bytes());
    let mut image = Image::from_code(isa, 0, code);
    image.sections[0].size = 0x90;
    image.sections.push(Section {
        name: ".rodata".to_owned(),
        vaddr: 0x1000,
        size: 8,
        file_offset: Some(0x90),
        file_size: 8,
        executable: false,
        loaded: true,
        read_only: true,
    });
    for (addr, size, name) in [
        (0, caller.len(), "caller"),
        (0x40, factory.len(), "factory"),
        (0x80, target.len(), "target"),
    ] {
        image.functions.insert(
            addr,
            Function {
                addr,
                size: Some(size as u64),
                size_estimated: false,
                name: Some(name.to_owned()),
                aliases: Vec::new(),
                library: None,
                sources: Vec::new(),
            },
        );
    }
    let blocks = crate::lift::lift_shared(&image, 0, caller.len() as u64, &|_| Default::default())
        .expect("caller lifts");
    (image, std::sync::Arc::unwrap_or_clone(blocks))
}

fn constant_factory(isa: Isa, value: u32) -> Vec<u8> {
    match isa {
        Isa::X86_64 => {
            let mut code = vec![0xb8];
            code.extend_from_slice(&value.to_le_bytes());
            code.push(0xc3);
            code
        }
        Isa::AArch64 => [0xd2800000u32 | value << 5, 0xd65f03c0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(),
        Isa::Arm32 | Isa::I386 | Isa::Unsupported => unreachable!(),
    }
}

#[test]
fn overflowing_vtable_symbols_are_ignored() {
    let (mut image, _) = pointer_factory(Isa::X86_64, false, constant_factory(Isa::X86_64, 0x80));
    image.data_symbols.insert(u64::MAX - 7, "_ZTV5Shape".into());
    assert!(vtables(&image).is_empty());
}

#[test]
fn a_resolved_tail_call_stays_a_tail_call() {
    let (image, mut blocks) =
        pointer_factory(Isa::X86_64, false, constant_factory(Isa::X86_64, 0x80));
    let Some(Stmt::Call { kind, .. }) =
        blocks
            .iter_mut()
            .flat_map(|block| &mut block.stmts)
            .find(|stmt| {
                matches!(
                    stmt,
                    Stmt::Call {
                        through: Some(_),
                        ..
                    }
                )
            })
    else {
        panic!("an indirect call");
    };
    *kind = crate::ir::CallKind::Tail;
    resolve(&mut blocks, &[], &image);
    let resolved = blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .find_map(|stmt| match stmt {
            Stmt::Call {
                kind,
                target: Some(0x80),
                ..
            } => Some(*kind),
            _ => None,
        });
    assert_eq!(resolved, Some(crate::ir::CallKind::Tail));
}

#[test]
fn returned_pointer_factories_resolve_their_exact_callee() {
    for isa in [Isa::X86_64, Isa::AArch64] {
        for table in [false, true] {
            let address = if table { 0x1000 } else { 0x80 };
            let (image, mut blocks) = pointer_factory(isa, table, constant_factory(isa, address));
            let factory = crate::lift::lift_shared(
                &image,
                0x40,
                image.functions[&0x40].size.unwrap(),
                &|_| Default::default(),
            )
            .expect("factory lifts");
            let mut ir = crate::ir::FunctionIr::single_block(isa, Vec::new());
            ir.blocks = std::sync::Arc::unwrap_or_clone(factory);
            let setup = crate::ir::eval::Setup {
                seed: 9,
                convention: crate::ir::eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &[(0, 0xdead_beef)],
                memory: &[],
                step_limit: 100,
            };
            match crate::ir::eval::run(&ir, &setup) {
                crate::ir::eval::Outcome::Return { value, .. } => {
                    assert_eq!(value, u64::from(address))
                }
                other => panic!("{other:?}"),
            }
            let factory_before = blocks
                .iter()
                .flat_map(|block| &block.stmts)
                .find(|stmt| {
                    matches!(
                        stmt,
                        Stmt::Call {
                            target: Some(0x40),
                            ..
                        }
                    )
                })
                .map(|stmt| format!("{stmt:?}"))
                .expect("factory call");
            resolve(&mut blocks, &[], &image);
            let calls: Vec<_> = blocks
                .iter()
                .flat_map(|block| &block.stmts)
                .filter(|stmt| matches!(stmt, Stmt::Call { .. }))
                .collect();
            assert_eq!(calls.len(), 2);
            assert_eq!(format!("{:?}", calls[0]), factory_before);
            let Stmt::Call {
                target: Some(0x80),
                via: Some(via),
                ..
            } = calls[1]
            else {
                panic!("{isa:?}: {calls:?}");
            };
            assert!(via.candidates.is_empty());
            if table {
                assert_eq!(via.table, Table::Pointer);
                assert_eq!(via.slot, 0x1000);
            }
        }
    }
}

#[test]
fn go_function_value_factories_keep_the_existing_table_provenance() {
    let (mut image, _) = pointer_factory(Isa::X86_64, true, constant_factory(Isa::X86_64, 0x1000));
    image.go = true;
    image.lifts = Default::default();
    let blocks = crate::lift::lift_shared(&image, 0, image.functions[&0].size.unwrap(), &|_| {
        Default::default()
    })
    .expect("Go caller lifts");
    let mut blocks = std::sync::Arc::unwrap_or_clone(blocks);
    resolve(&mut blocks, &[], &image);
    let calls: Vec<_> = blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .filter(|stmt| matches!(stmt, Stmt::Call { .. }))
        .collect();
    assert_eq!(calls.len(), 2);
    let Stmt::Call {
        target: Some(0x80),
        convention: Convention::GoAmd64,
        via: Some(via),
        ..
    } = calls[1]
    else {
        panic!("{calls:?}");
    };
    assert_eq!(via.table, Table::FuncValue);
    assert!(via.candidates.is_empty());
}

#[test]
fn constant_returns_require_agreement_from_symbolic_entries() {
    let mut same = vec![0x85, 0xff, 0x75, 6];
    same.extend(constant_factory(Isa::X86_64, 0x1000));
    same.extend(constant_factory(Isa::X86_64, 0x1000));
    let (image, _) = pointer_factory(Isa::X86_64, true, same.clone());
    assert_eq!(returned_by(&image, 0x40), Some(0x1000));

    let mut different = same[..10].to_vec();
    different.extend(constant_factory(Isa::X86_64, 0x80));
    let (image, _) = pointer_factory(Isa::X86_64, true, different);
    assert_eq!(returned_by(&image, 0x40), None);

    let mut argument = same[..10].to_vec();
    argument.extend([0x48, 0x89, 0xf8, 0xc3]);
    let (image, _) = pointer_factory(Isa::X86_64, true, argument);
    assert_eq!(returned_by(&image, 0x40), None);
    let (image, _) = pointer_factory(Isa::X86_64, true, vec![0x48, 0x89, 0xf8, 0xc3]);
    assert_eq!(returned_by(&image, 0x40), None);

    let mut joined = vec![0x85, 0xff, 0x75, 7];
    joined.extend(&constant_factory(Isa::X86_64, 0x1000)[..5]);
    joined.extend([0xeb, 5]);
    joined.extend(constant_factory(Isa::X86_64, 0x1000));
    let (image, _) = pointer_factory(Isa::X86_64, true, joined.clone());
    assert_eq!(returned_by(&image, 0x40), Some(0x1000));
    joined[12..16].copy_from_slice(&0x80u32.to_le_bytes());
    let (image, _) = pointer_factory(Isa::X86_64, true, joined);
    assert_eq!(returned_by(&image, 0x40), None);
}

#[test]
fn constant_returns_reject_mutation_calls_and_unmodeled_instructions() {
    for prefix in [
        vec![0x48, 0x89, 7],
        vec![0xe8, 0x3b, 0, 0, 0],
        vec![0x0f, 0xa2],
    ] {
        let mut code = prefix;
        code.extend(constant_factory(Isa::X86_64, 0x1000));
        let (image, mut caller) = pointer_factory(Isa::X86_64, true, code);
        assert_eq!(returned_by(&image, 0x40), None);
        resolve(&mut caller, &[], &image);
        assert!(
            caller
                .iter()
                .flat_map(|block| &block.stmts)
                .any(|stmt| matches!(
                    stmt,
                    Stmt::Call {
                        target: None,
                        through: Some(_),
                        ..
                    }
                ))
        );
    }
}

#[test]
fn constant_returns_only_read_immutable_in_bounds_words() {
    let mut code = vec![0x48, 0xa1];
    code.extend_from_slice(&0x1000u64.to_le_bytes());
    code.push(0xc3);
    let (mut image, _) = pointer_factory(Isa::X86_64, false, code);
    assert_eq!(returned_by(&image, 0x40), Some(0x80));
    image.sections[1].read_only = false;
    assert_eq!(returned_by(&image, 0x40), None);
    image.sections[1].read_only = true;
    image.sections[1].size = 7;
    assert_eq!(returned_by(&image, 0x40), None);

    let (mut image, mut caller) =
        pointer_factory(Isa::X86_64, true, constant_factory(Isa::X86_64, 0x1000));
    image.sections[1].read_only = false;
    resolve(&mut caller, &[], &image);
    assert!(
        caller
            .iter()
            .flat_map(|block| &block.stmts)
            .any(|stmt| matches!(
                stmt,
                Stmt::Call {
                    target: None,
                    through: Some(_),
                    ..
                }
            ))
    );
}

#[test]
fn constant_returns_require_exact_bounded_extents() {
    let (mut image, _) = pointer_factory(Isa::X86_64, false, constant_factory(Isa::X86_64, 0x80));
    assert_eq!(returned_by(&image, 0x40), Some(0x80));
    image.functions.get_mut(&0x40).unwrap().size_estimated = true;
    assert_eq!(returned_by(&image, 0x40), None);
    image.functions.get_mut(&0x40).unwrap().size_estimated = false;
    for size in [None, Some(0), Some(CONSTRUCTOR_SIZE + 1)] {
        image.functions.get_mut(&0x40).unwrap().size = size;
        assert_eq!(returned_by(&image, 0x40), None);
    }
    assert_eq!(returned_by(&image, 0x1234), None);
}

#[test]
fn constant_return_cfg_checks_every_exit_and_return() {
    use crate::ir::Cond;
    let (image, _) = pointer_factory(Isa::X86_64, false, constant_factory(Isa::X86_64, 0x80));
    let assign = Stmt::Assign {
        dest: RegRef {
            index: 0,
            width: 64,
        },
        value: Expr::Const(0x80),
    };
    let ret = Stmt::Ret {
        value: Expr::reg(0, 64),
    };
    let branch = Stmt::Brif {
        cond: Cond::Ne,
        lhs: Expr::reg(7, 64),
        rhs: Expr::Const(0),
        target: 0x48,
    };
    let valid = vec![
        Block {
            start: 0x40,
            stmts: vec![assign.clone(), branch],
        },
        Block {
            start: 0x44,
            stmts: vec![ret.clone()],
        },
        Block {
            start: 0x48,
            stmts: vec![ret.clone()],
        },
    ];
    assert_eq!(returned_from(&image, 0x40, 0x50, 0, &valid), Some(0x80));
    for last in [
        Stmt::Br { target: None },
        Stmt::Br { target: Some(0x40) },
        Stmt::Br { target: Some(0x46) },
        Stmt::Br { target: Some(0x80) },
        Stmt::BrIndirect {
            target: Expr::reg(7, 64),
        },
        Stmt::Brif {
            cond: Cond::Ne,
            lhs: Expr::reg(7, 64),
            rhs: Expr::Const(0),
            target: 0x46,
        },
        Stmt::BrifFlags {
            cond: Cond::Ne,
            target: 0x46,
        },
        Stmt::Switch {
            index: Expr::reg(7, 64),
            cases: vec![(0, 0x44)],
            default: None,
        },
        Stmt::Switch {
            index: Expr::reg(7, 64),
            cases: vec![(0, 0x46)],
            default: Some(0x48),
        },
        Stmt::Switch {
            index: Expr::reg(7, 64),
            cases: vec![(0, 0x44)],
            default: Some(0x46),
        },
    ] {
        let mut blocks = valid.clone();
        blocks[0].stmts[1] = last;
        assert_eq!(
            returned_from(&image, 0x40, 0x50, 0, &blocks),
            None,
            "{blocks:?}"
        );
    }
    let mut trap = valid.clone();
    trap[2].stmts = vec![Stmt::Trap];
    assert_eq!(returned_from(&image, 0x40, 0x50, 0, &trap), Some(0x80));
    let mut conflict = valid.clone();
    conflict[2].stmts.insert(
        0,
        Stmt::Assign {
            dest: RegRef {
                index: 0,
                width: 64,
            },
            value: Expr::Const(0x1000),
        },
    );
    assert_eq!(returned_from(&image, 0x40, 0x50, 0, &conflict), None);
    let mut unreached = valid;
    unreached.push(Block {
        start: 0x4c,
        stmts: vec![ret.clone()],
    });
    assert_eq!(returned_from(&image, 0x40, 0x50, 0, &unreached), None);
    for stmts in [
        vec![assign],
        vec![Stmt::Trap],
        vec![],
        vec![ret.clone(), ret],
    ] {
        assert_eq!(
            returned_from(&image, 0x40, 0x50, 0, &[Block { start: 0x40, stmts }]),
            None
        );
    }
}

#[test]
fn constant_return_outputs_use_provenance_and_simultaneous_sources() {
    let (image, _) = pointer_factory(Isa::X86_64, false, constant_factory(Isa::X86_64, 0x80));
    let tracker = Tracker {
        image: &image,
        sp: 4,
        loads: Default::default(),
        constructors: false,
        returns: Some(Default::default()),
    };
    let changed = Some([0, 2].into_iter().collect());
    let mut call = Stmt::Call {
        kind: crate::ir::CallKind::Invoke,
        target: Some(0x40),
        through: None,
        convention: Convention::SysV,
        args: Some(vec![Expr::reg(7, 64)]),
        floats_named: true,
        abi: None,
        outputs: vec![
            CallOutput {
                register: 2,
                dest: RegRef {
                    index: VARIABLE_BASE,
                    width: 64,
                },
            },
            CallOutput {
                register: 0,
                dest: RegRef {
                    index: 3,
                    width: 64,
                },
            },
            CallOutput {
                register: 3,
                dest: RegRef {
                    index: 0,
                    width: 64,
                },
            },
        ],
        clobbers: changed,
        via: None,
    };
    for _ in 0..2 {
        let mut state = State::entry();
        state.regs.insert(3, Value::Const(0x1234, None));
        tracker.step(&mut state, &call, (0, 0));
        assert_eq!(state.reg(3), Value::Const(0x80, None));
        assert_eq!(state.reg(0), Value::Const(0x1234, None));
        assert_eq!(
            state.reg(VARIABLE_BASE),
            Value::Sym(Base::Def(0, 0, u32::MAX - 2), 0)
        );
        let Stmt::Call { outputs, .. } = &mut call else {
            unreachable!()
        };
        outputs.reverse();
    }
    let output = call
        .call_outputs_mut()
        .iter_mut()
        .find(|output| output.register == 0)
        .unwrap();
    output.dest.index = VARIABLE_BASE + 1;
    output.dest.width = 32;
    let mut state = State::entry();
    tracker.step(&mut state, &call, (0, 0));
    assert_eq!(state.reg(VARIABLE_BASE + 1), Value::Unknown);
    let Stmt::Call {
        outputs, clobbers, ..
    } = &mut call
    else {
        unreachable!()
    };
    outputs
        .iter_mut()
        .find(|output| output.register == 0)
        .unwrap()
        .dest
        .width = 64;
    *clobbers = Some([2].into_iter().collect());
    state.regs.insert(0, Value::Const(0x3456, None));
    tracker.step(&mut state, &call, (0, 1));
    assert_eq!(state.reg(VARIABLE_BASE + 1), Value::Const(0x3456, None));
    let Stmt::Call {
        convention,
        clobbers,
        ..
    } = &mut call
    else {
        unreachable!()
    };
    *convention = Convention::Win64;
    *clobbers = changed;
    tracker.step(&mut state, &call, (0, 2));
    assert_eq!(
        state.reg(VARIABLE_BASE + 1),
        Value::Sym(Base::Def(0, 2, u32::MAX), 0)
    );
}

#[test]
fn returned_pointer_facts_do_not_cross_register_clobbers() {
    let (image, _) = pointer_factory(Isa::X86_64, true, constant_factory(Isa::X86_64, 0x1000));
    let tracker = Tracker {
        image: &image,
        sp: 4,
        loads: Default::default(),
        constructors: false,
        returns: Some(Default::default()),
    };
    let factory = crate::lift::call(
        crate::ir::CallKind::Invoke,
        &image,
        &|_| Default::default(),
        Some(0x40),
    );
    let mut state = State::entry();
    tracker.step(&mut state, &factory, (0, 0));
    let load = |register| Expr::Load {
        addr: Box::new(Expr::reg(register, 64)),
        width: 8,
        signed: false,
    };
    assert!(matches!(
        decide(&tracker, &state, &load(0), (0, 1)),
        Some(Decision::Direct(0x80, _))
    ));
    let mut assigned = state.clone();
    tracker.step(
        &mut assigned,
        &Stmt::Assign {
            dest: RegRef {
                index: 0,
                width: 64,
            },
            value: Expr::reg(7, 64),
        },
        (0, 1),
    );
    assert!(decide(&tracker, &assigned, &load(0), (0, 2)).is_none());
    tracker.step(
        &mut state,
        &Stmt::Assign {
            dest: RegRef {
                index: 3,
                width: 64,
            },
            value: Expr::reg(0, 64),
        },
        (0, 1),
    );
    let unknown = crate::lift::call(
        crate::ir::CallKind::Invoke,
        &image,
        &|_| Default::default(),
        None,
    );
    tracker.step(&mut state, &unknown, (0, 2));
    assert!(decide(&tracker, &state, &load(0), (0, 3)).is_none());
    assert!(matches!(
        decide(&tracker, &state, &load(3), (0, 3)),
        Some(Decision::Direct(0x80, _))
    ));
}

#[test]
fn returned_pointer_facts_require_a_closed_caller_cfg() {
    use crate::ir::Cond;
    let (image, _) = pointer_factory(Isa::X86_64, false, constant_factory(Isa::X86_64, 0x80));
    let factory = crate::lift::call(
        crate::ir::CallKind::Invoke,
        &image,
        &|_| Default::default(),
        Some(0x40),
    );
    let indirect = crate::lift::call_through(crate::ir::CallKind::Invoke, &image, Expr::reg(0, 64));
    let ret = Stmt::Ret {
        value: Expr::reg(0, 64),
    };
    let blocks = vec![
        Block {
            start: 0,
            stmts: vec![Stmt::Brif {
                cond: Cond::Ne,
                lhs: Expr::reg(7, 64),
                rhs: Expr::Const(0),
                target: 16,
            }],
        },
        Block {
            start: 8,
            stmts: vec![factory.clone(), Stmt::Br { target: Some(24) }],
        },
        Block {
            start: 16,
            stmts: vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: 0,
                        width: 64,
                    },
                    value: Expr::Const(0x1234),
                },
                Stmt::BrIndirect {
                    target: Expr::reg(6, 64),
                },
            ],
        },
        Block {
            start: 24,
            stmts: vec![indirect.clone(), ret.clone()],
        },
    ];
    for exit in [
        Stmt::BrIndirect {
            target: Expr::reg(6, 64),
        },
        Stmt::Br { target: None },
        Stmt::Br { target: Some(0x80) },
        Stmt::Brif {
            cond: Cond::Ne,
            lhs: Expr::reg(7, 64),
            rhs: Expr::Const(0),
            target: 0x80,
        },
        Stmt::Switch {
            index: Expr::reg(7, 64),
            cases: vec![(0, 24)],
            default: None,
        },
    ] {
        let mut caller = blocks.clone();
        caller[2].stmts[1] = exit;
        assert!(!closed_normal_flow(&caller, Edges::Any));
        resolve(&mut caller, &[], &image);
        assert!(matches!(
            caller[3].stmts[0],
            Stmt::Call {
                target: None,
                through: Some(_),
                ..
            }
        ));
    }
    let mut known_join = blocks;
    known_join[2].stmts[1] = Stmt::Br { target: Some(24) };
    assert!(closed_normal_flow(&known_join, Edges::Any));
    resolve(&mut known_join, &[], &image);
    assert!(matches!(
        known_join[3].stmts[0],
        Stmt::Call {
            target: None,
            through: Some(_),
            ..
        }
    ));

    let mut looped = vec![
        Block {
            start: 0,
            stmts: vec![factory, Stmt::Br { target: Some(8) }],
        },
        Block {
            start: 8,
            stmts: vec![Stmt::Brif {
                cond: Cond::Ne,
                lhs: Expr::reg(7, 64),
                rhs: Expr::Const(0),
                target: 8,
            }],
        },
        Block {
            start: 16,
            stmts: vec![indirect, ret],
        },
    ];
    assert!(closed_normal_flow(&looped, Edges::Any));
    resolve(&mut looped, &[], &image);
    assert!(matches!(
        looped[2].stmts[0],
        Stmt::Call {
            target: Some(0x80),
            ..
        }
    ));
    let mut missing_return = looped.clone();
    missing_return[2].stmts.pop();
    assert!(!closed_normal_flow(&missing_return, Edges::Any));
    let mut early_terminator = looped;
    early_terminator[1].stmts.push(Stmt::Assign {
        dest: RegRef {
            index: 0,
            width: 64,
        },
        value: Expr::Const(0x80),
    });
    assert!(!closed_normal_flow(&early_terminator, Edges::Any));
}

#[test]
fn returned_pointer_facts_do_not_flow_through_exception_edges() {
    let (image, _) = pointer_factory(Isa::X86_64, false, constant_factory(Isa::X86_64, 0x80));
    let ret = Stmt::Ret {
        value: Expr::reg(0, 64),
    };
    let mut blocks = vec![
        Block {
            start: 0,
            stmts: vec![
                crate::lift::call(
                    crate::ir::CallKind::Invoke,
                    &image,
                    &|_| Default::default(),
                    Some(0x40),
                ),
                Stmt::Br { target: Some(16) },
            ],
        },
        Block {
            start: 8,
            stmts: vec![
                crate::lift::call_through(crate::ir::CallKind::Invoke, &image, Expr::reg(0, 64)),
                ret.clone(),
            ],
        },
        Block {
            start: 16,
            stmts: vec![ret],
        },
    ];
    let pads = vec![(8, vec![(0, 4)])];
    assert!(closed_normal_flow(&blocks, Edges::Any));
    resolve(&mut blocks, &pads, &image);
    assert!(matches!(
        blocks[1].stmts[0],
        Stmt::Call {
            target: None,
            through: Some(_),
            ..
        }
    ));
    blocks[1].stmts[0] =
        crate::lift::call_through(crate::ir::CallKind::Invoke, &image, Expr::Const(0x80));
    resolve(&mut blocks, &pads, &image);
    assert!(matches!(
        blocks[1].stmts[0],
        Stmt::Call {
            target: Some(0x80),
            ..
        }
    ));
}

#[test]
fn indirect_tracking_uses_output_provenance_and_preserved_snapshots() {
    let image = Image::from_code(Isa::X86_64, 0, Vec::new());
    let tracker = Tracker {
        image: &image,
        sp: 4,
        loads: Default::default(),
        constructors: false,
        returns: None,
    };
    let changed = Some([2].into_iter().collect());
    let mut call = Stmt::Call {
        kind: crate::ir::CallKind::Invoke,
        target: Some(0x1000),
        through: None,
        convention: Convention::SysV,
        args: Some(Vec::new()),
        floats_named: true,
        abi: None,
        outputs: crate::ir::fallback_call_outputs(Convention::SysV, changed),
        clobbers: changed,
        via: None,
    };
    call.call_outputs_mut()[0].dest.index = VARIABLE_BASE;
    let mut state = State::entry();
    state.regs.insert(0, Value::Const(0x1111, None));
    state.regs.insert(2, Value::Const(0x2222, None));
    tracker.step(&mut state, &call, (0, 3));
    assert_eq!(state.reg(0), Value::Const(0x1111, None));
    assert_eq!(state.reg(2), Value::Const(0x2222, None));
    assert_eq!(
        state.reg(VARIABLE_BASE),
        Value::Sym(Base::Def(0, 3, u32::MAX - 2), 0)
    );

    let Stmt::Call { outputs, .. } = &mut call else {
        unreachable!()
    };
    *outputs = vec![
        CallOutput {
            register: 2,
            dest: RegRef {
                index: 0,
                width: 64,
            },
        },
        CallOutput {
            register: 0,
            dest: RegRef {
                index: VARIABLE_BASE,
                width: 64,
            },
        },
    ];
    let mut state = State::entry();
    state.regs.insert(0, Value::Const(0x1111, None));
    tracker.step(&mut state, &call, (0, 3));
    assert_eq!(state.reg(0), Value::Sym(Base::Def(0, 3, u32::MAX - 2), 0));
    assert_eq!(state.reg(VARIABLE_BASE), Value::Const(0x1111, None));
}
#[test]
fn declared_calls_are_not_replaced_by_indirect_resolution() {
    for attached in [false, true] {
        let (image, mut blocks) =
            pointer_factory(Isa::X86_64, false, constant_factory(Isa::X86_64, 0x80));
        let call = blocks
            .iter_mut()
            .flat_map(|block| &mut block.stmts)
            .find(|stmt| {
                matches!(
                    stmt,
                    Stmt::Call {
                        target: None,
                        through: Some(_),
                        ..
                    }
                )
            })
            .expect("indirect call");
        if let Stmt::Call { abi, .. } = call {
            *abi = attached.then(|| crate::ir::calls::test_call_abi(vec![7], false));
        }
        let before = format!("{blocks:?}");
        resolve(&mut blocks, &[], &image);
        if attached {
            assert_eq!(format!("{blocks:?}"), before);
        } else {
            assert!(
                blocks
                    .iter()
                    .flat_map(|block| &block.stmts)
                    .any(|stmt| matches!(
                        stmt,
                        Stmt::Call {
                            target: Some(0x80),
                            through: None,
                            ..
                        }
                    ))
            );
        }
    }
}

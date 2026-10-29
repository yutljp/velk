use super::{apply_partial_return, apply_void_return, apply_width_types};
use crate::ir::{BinOp, CType, Expr, FunctionIr, Stmt};
use crate::loader::Isa;

fn call_width_case() -> FunctionIr {
    let mut outputs = crate::ir::fallback_call_outputs(crate::ir::Convention::Aapcs64, None);
    outputs[0].dest.index = crate::ir::VARIABLE_BASE;
    let mut ir = FunctionIr::single_block(
        Isa::AArch64,
        vec![
            Stmt::Call {
                kind: crate::ir::CallKind::Invoke,
                target: Some(0x1000),
                through: None,
                convention: crate::ir::Convention::Aapcs64,
                args: Some(vec![Expr::bin(
                    BinOp::And,
                    Expr::reg(1, 64),
                    Expr::Const(0xffff_ffff),
                )]),
                floats_named: true,
                abi: None,
                outputs,
                clobbers: None,
                via: None,
                at: None,
            },
            Stmt::Ret {
                value: Expr::bin(
                    BinOp::And,
                    Expr::reg(crate::ir::VARIABLE_BASE, 64),
                    Expr::Const(0xffff_ffff),
                ),
                at: None,
            },
        ],
    );
    ir.params = vec![crate::ir::Param {
        index: 1,
        name: "a1".to_owned(),
        ty: CType::U64,
    }];
    ir
}

fn check_call_width(mut ir: FunctionIr, expected: CType) -> FunctionIr {
    use crate::ir::eval::{self, Setup};
    let original = ir.clone();
    let blocks = format!("{:?}", ir.blocks);
    apply_width_types(&mut ir, &Default::default());
    assert_eq!(
        ir.params.iter().find(|param| param.index == 1).unwrap().ty,
        expected
    );
    assert_eq!(format!("{:?}", ir.blocks), blocks);
    for (seed, value) in [(0, 0), (1, 0x8123_4567_89ab_cdef), (0x1234_5678, u64::MAX)] {
        let setup = Setup {
            seed,
            convention: eval::Convention {
                arguments: &[],
                clobbered: &[],
            },
            registers: &[(1, value), (2, 1)],
            memory: &[],
            step_limit: 100,
        };
        assert_eq!(eval::run(&ir, &setup), eval::run(&original, &setup));
    }
    ir
}

#[test]
fn call_output_width_ignores_only_unused_secondary_writes() {
    let ir = call_width_case();
    let live = super::live_call_outputs(&ir).unwrap();
    assert!(live.contains(&(0, 0, crate::ir::VARIABLE_BASE)));
    assert!(!live.contains(&(0, 0, 1)));
    let outputs = ir.blocks[0].stmts[0].call_outputs().to_vec();
    let narrowed = check_call_width(ir, CType::I32);
    assert_eq!(narrowed.blocks[0].stmts[0].call_outputs(), outputs);
}

#[test]
fn call_output_width_keeps_a_live_wide_store_and_unnamed_argument() {
    use crate::ir::eval::{self, Outcome, Setup};
    let mut stored = call_width_case();
    stored.blocks[0].stmts.insert(
        1,
        Stmt::Store {
            addr: Expr::Const(0x4000_0000),
            value: Expr::reg(1, 64),
            width: 8,
            at: None,
        },
    );
    let stored = check_call_width(stored, CType::I64);
    let mut unnamed = call_width_case();
    unnamed.blocks[0].stmts.insert(
        1,
        Stmt::Call {
            kind: crate::ir::CallKind::Invoke,
            target: Some(0x2000),
            through: None,
            convention: crate::ir::Convention::Aapcs64,
            args: None,
            floats_named: true,
            abi: None,
            outputs: Vec::new(),
            clobbers: Some(Default::default()),
            via: None,
            at: None,
        },
    );
    let unnamed = check_call_width(unnamed, CType::I64);
    for seed in [0, 1, 0x1234_5678] {
        let setup = Setup {
            seed,
            convention: eval::Convention {
                arguments: &[],
                clobbered: &[],
            },
            registers: &[(1, 7)],
            memory: &[],
            step_limit: 100,
        };
        let expected = eval::hash(seed ^ 1, 0x2_0001);
        assert_ne!(expected >> 32, 0);
        let Outcome::Return { memory, .. } = eval::run(&stored, &setup) else {
            unreachable!()
        };
        assert_eq!(
            u64::from_le_bytes(std::array::from_fn(
                |byte| memory[&(0x4000_0000 + byte as u64)]
            )),
            expected
        );
        let Outcome::Return { calls, .. } = eval::run(&unnamed, &setup) else {
            unreachable!()
        };
        assert_eq!(calls[1].arguments[1], expected);
    }
}

#[test]
fn call_output_width_handles_successor_joins_and_loop_uses() {
    use crate::ir::Block;
    let mut joined = call_width_case();
    let returned = joined.blocks[0].stmts.pop().unwrap();
    joined.blocks[0].stmts.push(Stmt::Brif {
        cond: crate::ir::Cond::Eq,
        lhs: Expr::reg(2, 64),
        rhs: Expr::Const(0),
        target: 20,
        at: None,
    });
    joined.blocks.extend([
        Block {
            start: 10,
            stmts: vec![Stmt::Br {
                target: Some(30),
                at: None,
            }],
        },
        Block {
            start: 20,
            stmts: vec![Stmt::Br {
                target: Some(30),
                at: None,
            }],
        },
        Block {
            start: 30,
            stmts: vec![
                Stmt::Store {
                    addr: Expr::Const(0x4000_0000),
                    value: Expr::reg(1, 64),
                    width: 8,
                    at: None,
                },
                returned.clone(),
            ],
        },
    ]);
    assert!(
        super::live_call_outputs(&joined)
            .unwrap()
            .contains(&(0, 0, 1))
    );
    check_call_width(joined, CType::I64);
    let mut looping = call_width_case();
    looping.blocks[0].stmts.pop();
    looping.blocks[0].stmts.push(Stmt::Br {
        target: Some(10),
        at: None,
    });
    looping.blocks.extend([
        Block {
            start: 10,
            stmts: vec![
                Stmt::Store {
                    addr: Expr::Const(0x4000_0000),
                    value: Expr::reg(1, 64),
                    width: 8,
                    at: None,
                },
                Stmt::Assign {
                    dest: crate::ir::RegRef {
                        index: 2,
                        width: 64,
                    },
                    value: Expr::bin(BinOp::Sub, Expr::reg(2, 64), Expr::Const(1)),
                    at: None,
                },
                Stmt::Brif {
                    cond: crate::ir::Cond::Eq,
                    lhs: Expr::reg(2, 64),
                    rhs: Expr::Const(0),
                    target: 10,
                    at: None,
                },
            ],
        },
        Block {
            start: 20,
            stmts: vec![returned],
        },
    ]);
    assert!(
        super::live_call_outputs(&looping)
            .unwrap()
            .contains(&(0, 0, 1))
    );
    check_call_width(looping, CType::I64);
}

#[test]
fn call_output_width_distinguishes_overwrites_and_pre_call_sources() {
    let mut overwritten = call_width_case();
    overwritten.blocks[0].stmts.insert(
        1,
        Stmt::Assign {
            dest: crate::ir::RegRef {
                index: 1,
                width: 32,
            },
            value: Expr::Const(7),
            at: None,
        },
    );
    overwritten.blocks[0].stmts.insert(
        2,
        Stmt::Store {
            addr: Expr::Const(0x4000_0000),
            value: Expr::reg(1, 64),
            width: 8,
            at: None,
        },
    );
    assert!(
        !super::live_call_outputs(&overwritten)
            .unwrap()
            .contains(&(0, 0, 1))
    );
    let live = super::live_call_outputs(&overwritten);
    assert_eq!(
        super::call_output_entry_demands(&overwritten, &live).unwrap()[&1],
        0xffff_ffff
    );
    check_call_width(overwritten, CType::I32);
    let mut preserved = call_width_case();
    let Stmt::Call { clobbers, .. } = &mut preserved.blocks[0].stmts[0] else {
        unreachable!()
    };
    *clobbers = Some([0].into_iter().collect());
    assert!(
        !super::live_call_outputs(&preserved)
            .unwrap()
            .contains(&(0, 0, 1))
    );
    check_call_width(preserved.clone(), CType::I32);
    preserved.blocks[0].stmts.insert(
        1,
        Stmt::Store {
            addr: Expr::Const(0x4000_0000),
            value: Expr::reg(1, 64),
            width: 8,
            at: None,
        },
    );
    check_call_width(preserved, CType::I64);
}

#[test]
fn call_output_width_retains_entry_high_bits_before_a_later_narrow_write() {
    let mut ir = call_width_case();
    ir.blocks[0].stmts.insert(
        0,
        Stmt::Store {
            addr: Expr::Const(0x4000_0000),
            value: Expr::reg(1, 64),
            width: 8,
            at: None,
        },
    );
    ir.blocks[0].stmts.insert(
        2,
        Stmt::Assign {
            dest: crate::ir::RegRef {
                index: 1,
                width: 32,
            },
            value: Expr::Const(7),
            at: None,
        },
    );
    ir.blocks[0].stmts.insert(
        3,
        Stmt::Store {
            addr: Expr::Const(0x4000_0008),
            value: Expr::reg(1, 64),
            width: 8,
            at: None,
        },
    );
    let live = super::live_call_outputs(&ir);
    assert!(!live.as_ref().unwrap().contains(&(0, 1, 1)));
    assert_eq!(
        super::call_output_entry_demands(&ir, &live).unwrap()[&1],
        u64::MAX
    );
    check_call_width(ir, CType::I64);
}

#[test]
fn call_output_width_entry_proof_includes_unnamed_bare_and_preserved_call_reads() {
    for args in [None, Some(vec![Expr::reg(1, 64)])] {
        let mut ir = call_width_case();
        ir.blocks[0].stmts.insert(
            0,
            Stmt::Call {
                kind: crate::ir::CallKind::Invoke,
                target: Some(0x2000),
                through: None,
                convention: crate::ir::Convention::Aapcs64,
                args,
                floats_named: true,
                abi: None,
                outputs: Vec::new(),
                clobbers: Some(Default::default()),
                via: None,
                at: None,
            },
        );
        ir.blocks[0].stmts.insert(
            2,
            Stmt::Assign {
                dest: crate::ir::RegRef {
                    index: 1,
                    width: 32,
                },
                value: Expr::Const(7),
                at: None,
            },
        );
        let live = super::live_call_outputs(&ir);
        assert_eq!(
            super::call_output_entry_demands(&ir, &live).unwrap()[&1],
            u64::MAX
        );
        check_call_width(ir, CType::I64);
    }
    let saved = crate::ir::VARIABLE_BASE + 1;
    let mut ir = call_width_case();
    ir.blocks[0].stmts.insert(
        0,
        Stmt::Call {
            kind: crate::ir::CallKind::Invoke,
            target: Some(0x2000),
            through: None,
            convention: crate::ir::Convention::Aapcs64,
            args: Some(Vec::new()),
            floats_named: true,
            abi: None,
            outputs: vec![crate::ir::CallOutput {
                register: 1,
                dest: crate::ir::RegRef {
                    index: saved,
                    width: 64,
                },
            }],
            clobbers: Some(Default::default()),
            via: None,
            at: None,
        },
    );
    ir.blocks[0].stmts.insert(
        2,
        Stmt::Assign {
            dest: crate::ir::RegRef {
                index: 1,
                width: 32,
            },
            value: Expr::Const(7),
            at: None,
        },
    );
    ir.blocks[0].stmts.insert(
        3,
        Stmt::Store {
            addr: Expr::Const(0x4000_0000),
            value: Expr::reg(saved, 64),
            width: 8,
            at: None,
        },
    );
    let live = super::live_call_outputs(&ir);
    assert_eq!(
        super::call_output_entry_demands(&ir, &live).unwrap()[&1],
        u64::MAX
    );
    check_call_width(ir, CType::I64);
}

#[test]
fn call_output_width_avoids_entry_solves_without_dead_wide_outputs() {
    let mut ordinary = FunctionIr::single_block(
        Isa::AArch64,
        vec![
            Stmt::Assign {
                dest: crate::ir::RegRef {
                    index: 1,
                    width: 32,
                },
                value: Expr::Const(7),
                at: None,
            },
            Stmt::Store {
                addr: Expr::Const(0x4000_0000),
                value: Expr::reg(1, 64),
                width: 8,
                at: None,
            },
            Stmt::Ret {
                value: Expr::Const(0),
                at: None,
            },
        ],
    );
    ordinary.params = vec![crate::ir::Param {
        index: 1,
        name: "a1".to_owned(),
        ty: CType::U64,
    }];
    let live = super::live_call_outputs(&ordinary);
    assert!(super::call_output_entry_demands(&ordinary, &live).is_none());
    check_call_width(ordinary, CType::I32);
    let mut used = call_width_case();
    let Stmt::Call { outputs, .. } = &mut used.blocks[0].stmts[0] else {
        unreachable!()
    };
    outputs.retain(|output| output.register == 1);
    used.blocks[0].stmts[1] = Stmt::Ret {
        value: Expr::reg(1, 64),
        at: None,
    };
    let live = super::live_call_outputs(&used);
    assert!(super::call_output_entry_demands(&used, &live).is_none());
    check_call_width(used, CType::I64);
}

#[test]
fn call_output_width_uses_all_live_fallback_for_unresolved_control() {
    use crate::ir::Block;
    let mut controls = Vec::new();
    let mut opaque = call_width_case();
    opaque.blocks[0].stmts.insert(
        1,
        Stmt::Unsupported {
            at: None,
            text: "unknown".to_owned(),
            writes: Some(vec![1]),
        },
    );
    controls.push(opaque);
    let mut external = call_width_case();
    external.blocks[0].stmts[1] = Stmt::Br {
        target: Some(0xffff),
        at: None,
    };
    controls.push(external);
    let mut indirect = call_width_case();
    indirect.blocks[0].stmts[1] = Stmt::BrIndirect {
        target: Expr::reg(2, 64),
        at: None,
    };
    controls.push(indirect);
    let mut switched = call_width_case();
    switched.blocks[0].stmts[1] = Stmt::Switch {
        index: Expr::reg(2, 64),
        cases: Vec::new(),
        default: None,
        at: None,
    };
    controls.push(switched);
    let mut exceptional = call_width_case();
    exceptional.landing_pads.push((10, vec![(0, 1)]));
    exceptional.blocks.push(Block {
        start: 10,
        stmts: vec![Stmt::Ret {
            value: Expr::Const(0),
            at: None,
        }],
    });
    controls.push(exceptional);
    for ir in controls {
        assert!(super::live_call_outputs(&ir).is_none());
        check_call_width(ir, CType::I64);
    }
}

#[test]
fn call_output_width_shares_live_output_facts_with_return_widths() {
    let mut wide = call_width_case();
    wide.ret_type = CType::U32;
    wide.blocks[0].stmts[1] = Stmt::Ret {
        value: Expr::reg(1, 64),
        at: None,
    };
    wide.blocks[0].stmts.insert(
        1,
        Stmt::Store {
            addr: Expr::Const(0x4000_0000),
            value: Expr::Const(0),
            width: 8,
            at: None,
        },
    );
    let live = super::live_call_outputs(&wide);
    assert!(super::returns_wide(
        &wide,
        &live,
        super::call_output_entry_demands(&wide, &live).as_ref(),
        &Default::default()
    ));
    let wide = check_call_width(wide, CType::I64);
    assert_eq!(wide.ret_type, CType::I64);
    let mut narrow = call_width_case();
    narrow.blocks[0].stmts[1] = Stmt::Ret {
        value: Expr::reg(1, 64),
        at: None,
    };
    narrow.blocks[0].stmts.insert(
        1,
        Stmt::Assign {
            dest: crate::ir::RegRef {
                index: 1,
                width: 32,
            },
            value: Expr::Const(7),
            at: None,
        },
    );
    let live = super::live_call_outputs(&narrow);
    assert!(!super::returns_wide(
        &narrow,
        &live,
        super::call_output_entry_demands(&narrow, &live).as_ref(),
        &Default::default()
    ));
    let narrow = check_call_width(narrow, CType::I32);
    assert_eq!(narrow.ret_type, CType::I32);
}

#[test]
fn call_output_width_restores_narrow_inputs_in_the_actual_call_fixture() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/calls_a64.o");
    let image = crate::loader::load(&path).unwrap();
    for name in ["apply_table", "apply_pointer"] {
        let function = image
            .functions
            .values()
            .find(|function| function.name.as_deref() == Some(name))
            .unwrap();
        let analysis = crate::analysis::analyze(&image, function, None).unwrap();
        assert_eq!(
            analysis
                .ir
                .params
                .iter()
                .find(|param| param.index == 1)
                .unwrap()
                .ty,
            CType::I32
        );
        assert!(
            analysis
                .ir
                .blocks
                .iter()
                .flat_map(|block| &block.stmts)
                .flat_map(Stmt::call_outputs)
                .any(|output| output.register == 1)
        );
    }
}

fn pointer_case(stmts: Vec<Stmt>) -> FunctionIr {
    let mut ir = FunctionIr::single_block(Isa::AArch64, stmts);
    ir.ret_type = CType::I64;
    ir.params = vec![
        crate::ir::Param {
            index: 0,
            name: "dst".to_owned(),
            ty: CType::pointer_to(CType::Void),
        },
        crate::ir::Param {
            index: 1,
            name: "src".to_owned(),
            ty: CType::pointer_to(CType::Void),
        },
        crate::ir::Param {
            index: 2,
            name: "n".to_owned(),
            ty: CType::U64,
        },
        crate::ir::Param {
            index: 3,
            name: "count".to_owned(),
            ty: CType::pointer_to(CType::U64),
        },
    ];
    ir
}

fn pointer_copy(dest: u16, index: u16) -> Stmt {
    Stmt::Assign {
        dest: crate::ir::RegRef {
            index: dest,
            width: 64,
        },
        value: Expr::reg(index, 64),
        at: None,
    }
}

fn pointer_import(dest: u16) -> Stmt {
    Stmt::Call {
        kind: crate::ir::CallKind::Invoke,
        target: None,
        through: Some(Expr::Load {
            addr: Box::new(Expr::Const(0x1000)),
            width: 8,
            signed: false,
        }),
        convention: crate::ir::Convention::Aapcs64,
        args: Some(vec![Expr::reg(0, 64), Expr::reg(1, 64), Expr::reg(2, 64)]),
        floats_named: true,
        abi: None,
        outputs: vec![crate::ir::CallOutput {
            register: 0,
            dest: crate::ir::RegRef {
                index: dest,
                width: 64,
            },
        }],
        clobbers: Some([0].into_iter().collect()),
        via: None,
        at: None,
    }
}

fn check_pointer_return(mut ir: FunctionIr, expected: CType) -> FunctionIr {
    use crate::ir::eval::{self, Setup};
    let mut image = crate::loader::Image::from_code(Isa::AArch64, 0, Vec::new());
    image.imports.insert(0x1000, "memcpy".to_owned());
    let before = ir.clone();
    super::apply_pointer_return_with(&mut ir, &|stmt| {
        crate::analysis::prototypes::called(&image, stmt)
    });
    assert_eq!(ir.ret_type, expected);
    let mut restored = ir.clone();
    restored.ret_type = before.ret_type.clone();
    assert_eq!(format!("{restored:?}"), format!("{before:?}"));
    for seed in [0, 1, 0x8123_4567_89ab_cdef] {
        let setup = Setup {
            seed,
            convention: eval::Convention {
                arguments: &[],
                clobbered: &[],
            },
            registers: &[
                (0, 0x4000_0000),
                (1, 0x4000_1000),
                (2, seed & 1),
                (3, 0x4000_2000),
            ],
            memory: &[(0x1000, 0x2000)],
            step_limit: 100,
        };
        assert_eq!(eval::run(&ir, &setup), eval::run(&before, &setup));
    }
    ir
}

#[test]
fn pointer_returns_follow_parameter_copies_and_same_type_selects() {
    let variable = crate::ir::VARIABLE_BASE;
    let ir = pointer_case(vec![
        pointer_copy(variable, 0),
        Stmt::Store {
            addr: Expr::reg(3, 64),
            value: Expr::reg(2, 64),
            width: 8,
            at: None,
        },
        Stmt::Ret {
            value: Expr::reg(variable, 64),
            at: None,
        },
    ]);
    let inferred = check_pointer_return(ir, CType::pointer_to(CType::Void));
    assert!(inferred.value_types.is_empty());
    let selected = Expr::Select {
        cond: crate::ir::Cond::Eq,
        lhs: Box::new(Expr::reg(2, 64)),
        rhs: Box::new(Expr::Const(0)),
        then: Box::new(Expr::reg(0, 64)),
        els: Box::new(Expr::reg(1, 64)),
    };
    check_pointer_return(
        pointer_case(vec![Stmt::Ret {
            value: selected,
            at: None,
        }]),
        CType::pointer_to(CType::Void),
    );
}

#[test]
fn renderer_pointer_inference_keeps_its_existing_bare_parameter_scope() {
    let variable = crate::ir::VARIABLE_BASE;
    let mut copied = pointer_case(vec![
        pointer_copy(variable, 0),
        Stmt::Ret {
            value: Expr::reg(variable, 64),
            at: None,
        },
    ]);
    super::apply_pointer_return(&mut copied);
    assert_eq!(copied.ret_type, CType::I64);
    let mut bare = pointer_case(vec![Stmt::Ret {
        value: Expr::reg(0, 64),
        at: None,
    }]);
    super::apply_pointer_return(&mut bare);
    assert_eq!(bare.ret_type, CType::pointer_to(CType::Void));
}

fn pointer_join(second: CType) -> FunctionIr {
    use crate::ir::Block;
    let variable = crate::ir::VARIABLE_BASE;
    let mut ir = pointer_case(Vec::new());
    ir.params[0].ty = CType::pointer_to(CType::I32);
    ir.params[1].ty = second;
    ir.blocks = vec![
        Block {
            start: 0,
            stmts: vec![Stmt::Brif {
                cond: crate::ir::Cond::Eq,
                lhs: Expr::reg(2, 64),
                rhs: Expr::Const(0),
                target: 20,
                at: None,
            }],
        },
        Block {
            start: 10,
            stmts: vec![
                pointer_copy(variable, 0),
                Stmt::Br {
                    target: Some(30),
                    at: None,
                },
            ],
        },
        Block {
            start: 20,
            stmts: vec![
                pointer_copy(variable, 1),
                Stmt::Br {
                    target: Some(30),
                    at: None,
                },
            ],
        },
        Block {
            start: 30,
            stmts: vec![Stmt::Ret {
                value: Expr::reg(variable, 64),
                at: None,
            }],
        },
    ];
    ir
}

#[test]
fn pointer_return_phis_require_every_incoming_type_to_match() {
    check_pointer_return(
        pointer_join(CType::pointer_to(CType::I32)),
        CType::pointer_to(CType::I32),
    );
    check_pointer_return(pointer_join(CType::pointer_to(CType::U64)), CType::I64);
    check_pointer_return(pointer_join(CType::U64), CType::I64);
    check_pointer_return(pointer_join(CType::Array(Box::new(CType::I32))), CType::I64);
}

#[test]
fn pointer_returns_follow_an_import_result_across_a_store_and_another_call() {
    let variable = crate::ir::VARIABLE_BASE;
    let saved = variable + 1;
    let mut other = pointer_import(variable + 2);
    let Stmt::Call {
        through,
        args,
        outputs,
        clobbers,
        ..
    } = &mut other
    else {
        unreachable!()
    };
    *through = None;
    *args = Some(Vec::new());
    outputs.clear();
    *clobbers = Some(Default::default());
    let ir = pointer_case(vec![
        pointer_import(variable),
        pointer_copy(saved, variable),
        other,
        Stmt::Store {
            addr: Expr::reg(3, 64),
            value: Expr::reg(2, 64),
            width: 8,
            at: None,
        },
        Stmt::Ret {
            value: Expr::reg(saved, 64),
            at: None,
        },
    ]);
    let inferred = check_pointer_return(ir, CType::pointer_to(CType::Void));
    assert!(inferred.value_types.is_empty());
}

#[test]
fn pointer_return_inference_does_not_reuse_an_overwritten_type() {
    let variable = crate::ir::VARIABLE_BASE;
    let constant = |index| Stmt::Assign {
        dest: crate::ir::RegRef { index, width: 64 },
        value: Expr::Const(7),
        at: None,
    };
    check_pointer_return(
        pointer_case(vec![
            constant(0),
            Stmt::Ret {
                value: Expr::reg(0, 64),
                at: None,
            },
        ]),
        CType::I64,
    );
    let mut ir = pointer_case(vec![
        pointer_import(variable),
        constant(variable),
        Stmt::Ret {
            value: Expr::reg(variable, 64),
            at: None,
        },
    ]);
    ir.value_types
        .insert(variable, CType::pointer_to(CType::Void));
    check_pointer_return(ir, CType::I64);
    let mut unknown = pointer_import(variable);
    let Stmt::Call {
        through, target, ..
    } = &mut unknown
    else {
        unreachable!()
    };
    *through = None;
    *target = Some(0x3000);
    check_pointer_return(
        pointer_case(vec![
            unknown,
            Stmt::Ret {
                value: Expr::reg(variable, 64),
                at: None,
            },
        ]),
        CType::I64,
    );
}

#[test]
fn pointer_return_inference_rejects_truncation_arithmetic_and_missing_outputs() {
    let variable = crate::ir::VARIABLE_BASE;
    for (dest_width, read_width) in [(32, 64), (64, 32)] {
        check_pointer_return(
            pointer_case(vec![
                Stmt::Assign {
                    dest: crate::ir::RegRef {
                        index: variable,
                        width: dest_width,
                    },
                    value: Expr::reg(0, read_width),
                    at: None,
                },
                Stmt::Ret {
                    value: Expr::reg(variable, 64),
                    at: None,
                },
            ]),
            CType::I64,
        );
    }
    check_pointer_return(
        pointer_case(vec![Stmt::Ret {
            value: Expr::bin(BinOp::Add, Expr::reg(0, 64), Expr::Const(1)),
            at: None,
        }]),
        CType::I64,
    );
    for missing in [false, true] {
        let mut call = pointer_import(variable);
        if missing {
            call.call_outputs_mut()[0].register = 1;
        } else {
            call.call_outputs_mut()[0].dest.width = 32;
        }
        check_pointer_return(
            pointer_case(vec![
                call,
                Stmt::Ret {
                    value: Expr::reg(variable, 64),
                    at: None,
                },
            ]),
            CType::I64,
        );
    }
}

#[test]
fn pointer_return_inference_respects_declarations_and_pointee_identity() {
    let returned = Stmt::Ret {
        value: Expr::reg(0, 64),
        at: None,
    };
    let mut declared = pointer_case(vec![returned.clone()]);
    declared.declared_signature = Some(crate::ir::DeclaredSignature {
        params: Vec::new(),
        ret: CType::U64,
        variadic: false,
        abi: Err(crate::ir::AbiIssue::UnknownLayout),
    });
    check_pointer_return(declared, CType::I64);
    let mut typed = pointer_case(vec![returned.clone()]);
    typed.ret_type = CType::pointer_to(CType::U64);
    check_pointer_return(typed, CType::pointer_to(CType::U64));
    let mut structure = pointer_case(vec![returned.clone()]);
    let pointer = CType::pointer_to(CType::Named("struct item".to_owned()));
    structure.params[0].ty = pointer.clone();
    check_pointer_return(structure, pointer);
    let mut pointer_to_array = pointer_case(vec![returned.clone()]);
    let pointer = CType::pointer_to(CType::Array(Box::new(CType::I32)));
    pointer_to_array.params[0].ty = pointer.clone();
    check_pointer_return(pointer_to_array, pointer);
    let mut array = pointer_case(vec![returned]);
    array.params[0].ty = CType::Array(Box::new(CType::I32));
    check_pointer_return(array, CType::I64);
}

#[test]
fn pointer_return_inference_refuses_unknown_exceptional_and_cyclic_edges() {
    use crate::ir::Block;
    let returned = Stmt::Ret {
        value: Expr::reg(0, 64),
        at: None,
    };
    check_pointer_return(
        pointer_case(vec![Stmt::unsupported("unknown"), returned.clone()]),
        CType::I64,
    );
    check_pointer_return(
        pointer_case(vec![
            Stmt::Brif {
                cond: crate::ir::Cond::Eq,
                lhs: Expr::reg(2, 64),
                rhs: Expr::Const(0),
                target: 0xffff,
                at: None,
            },
            returned.clone(),
        ]),
        CType::I64,
    );
    let mut exceptional = pointer_case(vec![
        pointer_import(crate::ir::VARIABLE_BASE),
        returned.clone(),
    ]);
    exceptional.landing_pads.push((10, vec![(0, 1)]));
    exceptional.blocks.push(Block {
        start: 10,
        stmts: vec![returned.clone()],
    });
    check_pointer_return(exceptional, CType::I64);
    let mut cyclic = pointer_case(Vec::new());
    cyclic.blocks = vec![
        Block {
            start: 0,
            stmts: vec![Stmt::Brif {
                cond: crate::ir::Cond::Eq,
                lhs: Expr::reg(2, 64),
                rhs: Expr::Const(0),
                target: 20,
                at: None,
            }],
        },
        Block {
            start: 10,
            stmts: vec![Stmt::Br {
                target: Some(0),
                at: None,
            }],
        },
        Block {
            start: 20,
            stmts: vec![returned],
        },
    ];
    check_pointer_return(cyclic, CType::I64);
}

#[test]
fn inferred_pointer_returns_keep_local_pointer_types_in_generated_c() {
    let variable = crate::ir::VARIABLE_BASE;
    let saved = variable + 1;
    let mut ir = pointer_case(vec![
        pointer_import(variable),
        pointer_copy(saved, variable),
        Stmt::Store {
            addr: Expr::reg(3, 64),
            value: Expr::reg(2, 64),
            width: 8,
            at: None,
        },
        Stmt::Ret {
            value: Expr::reg(saved, 64),
            at: None,
        },
    ]);
    ir.name = Some("copy_and_note".to_owned());
    let ir = check_pointer_return(ir, CType::pointer_to(CType::Void));
    let mut symbols = crate::render::Symbols::default();
    symbols.import_slots.insert(0x1000, "memcpy".to_owned());
    symbols
        .import_returns
        .insert(0x1000, CType::pointer_to(CType::Void));
    let rendered = crate::render::render(&ir, &[], &symbols, &[]);
    assert!(rendered.contains("void *copy_and_note("), "{rendered}");
    assert!(
        rendered.lines().any(|line| line.trim() == "return v1;"),
        "{rendered}"
    );
    assert!(!rendered.contains("return (void *)"), "{rendered}");
    assert!(ir.value_types.is_empty());
}

/// The type of a 32-bit parameter in rdi whose value is returned through `op`.
fn parameter_through(op: BinOp) -> CType {
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![Stmt::Ret {
            value: Expr::bin(op, Expr::reg(7, 32), Expr::Const(3)),
            at: None,
        }],
    );
    ir.params = vec![crate::ir::Param {
        index: 7,
        name: "a0".to_owned(),
        ty: CType::U32,
    }];
    apply_width_types(&mut ir, &Default::default());
    ir.params[0].ty.clone()
}

#[test]
fn wrapping_parameters_are_unsigned_unless_signed_operations_read_them() {
    assert_eq!(parameter_through(BinOp::Add), CType::U32);
    assert_eq!(parameter_through(BinOp::DivU), CType::U32);
    assert_eq!(parameter_through(BinOp::Shr), CType::U32);
    assert_eq!(parameter_through(BinOp::DivS), CType::I32);
}

fn returns_register(isa: Isa) -> CType {
    let mut ir = FunctionIr::single_block(
        isa,
        vec![Stmt::Ret {
            value: Expr::reg(0, 64),
            at: None,
        }],
    );
    apply_void_return(&mut ir);
    ir.ret_type
}

#[test]
fn a_return_of_only_the_low_byte_is_a_byte() {
    // sete al; ret: the rest of rax is whatever the caller left.
    let flag = Expr::Select {
        cond: crate::ir::Cond::Eq,
        lhs: Box::new(Expr::reg(7, 32)),
        rhs: Box::new(Expr::Const(4)),
        then: Box::new(Expr::Const(1)),
        els: Box::new(Expr::Const(0)),
    };
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![Stmt::Ret {
            value: Expr::bin(
                BinOp::Or,
                Expr::bin(BinOp::And, Expr::reg(0, 64), Expr::Const(!0xff)),
                flag.clone(),
            ),
            at: None,
        }],
    );
    apply_partial_return(&mut ir);
    assert_eq!(ir.ret_type, CType::int(1, false));
    assert!(matches!(
        &ir.blocks[0].stmts[0],
        Stmt::Ret { value, .. } if *value == Expr::bin(BinOp::And, flag, Expr::Const(0xff))
    ));
}

/// `mov r15b, 1` then `mov eax, r15d; ret`, or with `whole` a write of
/// all of r15 instead.
fn returns_r15(whole: bool) -> FunctionIr {
    const R15: u16 = 15;
    let one = if whole {
        Expr::Const(0x100)
    } else {
        Expr::bin(
            BinOp::Or,
            Expr::bin(BinOp::And, Expr::reg(R15, 64), Expr::Const(!0xff)),
            Expr::Const(1),
        )
    };
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            Stmt::Assign {
                dest: crate::ir::RegRef {
                    index: R15,
                    width: 64,
                },
                value: one,
                at: None,
            },
            Stmt::Assign {
                dest: crate::ir::RegRef {
                    index: 0,
                    width: 64,
                },
                value: Expr::bin(BinOp::And, Expr::reg(R15, 64), Expr::Const(0xffff_ffff)),
                at: None,
            },
            Stmt::Ret {
                value: Expr::reg(0, 64),
                at: None,
            },
        ],
    );
    ir.ret_type = CType::U32;
    apply_partial_return(&mut ir);
    ir
}

#[test]
fn a_return_copied_from_a_byte_of_another_register_is_a_byte() {
    let ir = returns_r15(false);
    assert_eq!(ir.ret_type, CType::int(1, false));
    assert!(matches!(
        &ir.blocks[0].stmts[2],
        Stmt::Ret { value, .. } if *value == Expr::bin(BinOp::And, Expr::reg(0, 64), Expr::Const(0xff))
    ));
    assert_eq!(returns_r15(true).ret_type, CType::U32);
}

#[test]
fn a_return_register_nothing_writes_holds_no_result() {
    assert_eq!(returns_register(Isa::X86_64), CType::Void);
}

#[test]
fn a_return_register_that_carries_the_first_argument_may_return_it() {
    // AArch64 `int id(int x) { return x; }` is a bare `ret`.
    assert_ne!(returns_register(Isa::AArch64), CType::Void);
}

#[test]
fn scalar_float_prototypes_type_only_the_matching_fp_output() {
    use crate::ir::{Convention, VARIABLE_BASE};
    for (isa, convention, output_register) in [
        (Isa::X86_64, Convention::SysV, crate::arch::x86::XMM0),
        (Isa::X86_64, Convention::Win64, crate::arch::x86::XMM0),
        (Isa::AArch64, Convention::Aapcs64, crate::arch::aarch64::V0),
    ] {
        for (name, ret) in [("strtof", "float"), ("strtod", "double")] {
            for present in [false, true] {
                let mut image = crate::loader::Image::from_code(isa, 0, Vec::new());
                image.imports.insert(0x1000, name.to_owned());
                let mut outputs = crate::ir::fallback_call_outputs(convention, None);
                outputs.retain(|output| present || output.register != output_register);
                outputs.reverse();
                for output in &mut outputs {
                    output.dest.index = VARIABLE_BASE + output.register;
                }
                let mut ir = FunctionIr::single_block(
                    isa,
                    vec![Stmt::Call {
                        kind: crate::ir::CallKind::Invoke,
                        target: None,
                        through: Some(Expr::Load {
                            addr: Box::new(Expr::Const(0x1000)),
                            width: 8,
                            signed: false,
                        }),
                        convention,
                        args: Some(Vec::new()),
                        floats_named: true,
                        abi: None,
                        outputs,
                        clobbers: None,
                        via: None,
                        at: None,
                    }],
                );
                super::apply_prototypes(&mut ir, &image);
                assert_eq!(
                    ir.value_types.get(&(VARIABLE_BASE + output_register)),
                    present.then(|| CType::Named(ret.to_owned())).as_ref()
                );
                assert!(!ir.value_types.contains_key(&VARIABLE_BASE));
                assert_eq!(ir.value_types.len(), usize::from(present));
            }
        }
    }
}

#[test]
fn a_defined_call_output_keeps_an_integer_return_nonvoid() {
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            Stmt::Call {
                kind: crate::ir::CallKind::Invoke,
                target: Some(0x1000),
                through: None,
                convention: crate::ir::Convention::SysV,
                args: Some(Vec::new()),
                floats_named: true,
                abi: None,
                outputs: crate::ir::fallback_call_outputs(
                    crate::ir::Convention::SysV,
                    Some([0].into_iter().collect()),
                ),
                clobbers: Some([0].into_iter().collect()),
                via: None,
                at: None,
            },
            Stmt::Ret {
                value: Expr::reg(0, 64),
                at: None,
            },
        ],
    );
    ir.ret_type = CType::U64;
    apply_void_return(&mut ir);
    assert_eq!(ir.ret_type, CType::U64);
}

#[test]
fn a_register_reads_as_signed_unless_more_unsigned_operations_read_it() {
    use crate::ir::Cond;
    let compare = |cond: Cond| Stmt::Brif {
        cond,
        lhs: Expr::reg(7, 64),
        rhs: Expr::Const(0),
        target: 0,
        at: None,
    };
    let evidence = |conds: &[Cond]| {
        let ir = FunctionIr::single_block(
            Isa::X86_64,
            conds.iter().map(|cond| compare(*cond)).collect(),
        );
        super::SignEvidence::of(&ir).mostly_signed(7)
    };
    assert!(evidence(&[]));
    assert!(evidence(&[Cond::Lt, Cond::Cc]));
    assert!(!evidence(&[Cond::Lt, Cond::Cc, Cond::Hi]));
}

#[test]
fn wrapping_parameters_use_unsigned_types_without_signed_evidence() {
    use crate::ir::{RegRef, VARIABLE_BASE};

    for (isa, width) in [(Isa::I386, 32), (Isa::X86_64, 64)] {
        let ty = CType::int((width / 8) as u8, true);
        let mut ir = FunctionIr::single_block(
            isa,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: VARIABLE_BASE,
                        width: width as u8,
                    },
                    value: Expr::bin(BinOp::Add, Expr::reg(7, width as u8), Expr::Const(1)),
                    at: None,
                },
                Stmt::Ret {
                    value: Expr::reg(VARIABLE_BASE, width as u8),
                    at: None,
                },
            ],
        );
        ir.params.push(crate::ir::Param {
            index: 7,
            name: "input".to_owned(),
            ty: ty.clone(),
        });
        ir.ret_type = ty;

        super::apply_width_types(&mut ir, &Default::default());

        assert_eq!(ir.params[0].ty, CType::int((width / 8) as u8, false));
    }
}

#[test]
fn wrapping_parameters_keep_signed_types_when_signed_operations_read_them() {
    use crate::ir::{RegRef, VARIABLE_BASE};

    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            Stmt::Assign {
                dest: RegRef {
                    index: VARIABLE_BASE,
                    width: 64,
                },
                value: Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(1)),
                at: None,
            },
            Stmt::Ret {
                value: Expr::bin(BinOp::DivS, Expr::reg(7, 64), Expr::Const(2)),
                at: None,
            },
        ],
    );
    ir.params.push(crate::ir::Param {
        index: 7,
        name: "input".to_owned(),
        ty: CType::I64,
    });
    ir.ret_type = CType::I64;

    super::apply_width_types(&mut ir, &Default::default());

    assert_eq!(ir.params[0].ty, CType::I64);

    ir.params[0].ty = CType::I64;
    ir.signed_params.insert(7);
    ir.blocks[0].stmts = vec![
        Stmt::Assign {
            dest: RegRef {
                index: VARIABLE_BASE,
                width: 64,
            },
            value: Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(1)),
            at: None,
        },
        Stmt::Ret {
            value: Expr::reg(VARIABLE_BASE, 64),
            at: None,
        },
    ];

    super::apply_width_types(&mut ir, &Default::default());

    assert_eq!(ir.params[0].ty, CType::I64);
}

#[test]
fn unsigned_parameter_arithmetic_matches_machine_bits_smt() {
    use crate::ir::smt::{self, Proofs};

    if !Proofs::available() {
        return;
    }
    let mut proofs = Proofs::default();
    for bits in [32, 64] {
        for operator in ["bvadd", "bvsub", "bvmul"] {
            let left = format!("((_ extract {} 0) r0)", bits - 1);
            let right = format!("((_ extract {} 0) r1)", bits - 1);
            let mut c_result = format!("({operator} {left} {right})");
            if bits == 32 {
                c_result = format!("((_ zero_extend 32) {c_result})");
            }
            let machine_result = smt::low(&format!("({operator} r0 r1)"), bits);
            proofs.predicate(
                format!("unsigned parameter arithmetic/{bits}/{operator}"),
                &machine_result,
                &c_result,
            );
        }
        let left = format!("((_ extract {} 0) r0)", bits - 1);
        let mut c_result = format!("(bvshl {left} (_ bv7 {bits}))");
        if bits == 32 {
            c_result = format!("((_ zero_extend 32) {c_result})");
        }
        let machine_result = smt::low("(bvshl r0 (_ bv7 64))", bits);
        proofs.predicate(
            format!("unsigned parameter arithmetic/{bits}/bvshl"),
            &machine_result,
            &c_result,
        );
    }
    proofs.check();
}

#[test]
fn declared_calls_do_not_offer_positional_library_argument_types() {
    use crate::ir::{Convention, VARIABLE_BASE};
    let mut image = crate::loader::Image::from_code(Isa::AArch64, 0, Vec::new());
    image.imports.insert(0x1000, "free".to_owned());
    for attached in [false, true] {
        let mut call = crate::lift::call_through(
            crate::ir::CallKind::Invoke,
            &image,
            Expr::Load {
                addr: Box::new(Expr::Const(0x1000)),
                width: 8,
                signed: false,
            },
        );
        let Stmt::Call { args, abi, .. } = &mut call else {
            unreachable!()
        };
        *args = Some(vec![Expr::reg(VARIABLE_BASE, 64)]);
        *abi = attached.then(|| crate::ir::calls::test_call_abi(vec![0], false));
        let mut ir = FunctionIr::single_block(Isa::AArch64, vec![call]);
        ir.convention = Convention::Aapcs64;
        let before = format!("{:?}", ir.blocks);
        super::apply_prototypes(&mut ir, &image);
        assert_eq!(
            ir.value_types.get(&VARIABLE_BASE),
            (!attached).then(|| CType::pointer_to(CType::Void)).as_ref()
        );
        assert_eq!(format!("{:?}", ir.blocks), before);
    }
}

#[test]
fn format_argument_written_by_body_is_mutable() {
    let mut image = crate::loader::Image::from_code(Isa::X86_64, 0x2000, b"%s\0".to_vec());
    image.imports.insert(0x1000, "printf".into());
    for writes in [false, true] {
        let mut call = crate::lift::call_through(
            crate::ir::CallKind::Invoke,
            &image,
            Expr::Load {
                addr: Box::new(Expr::Const(0x1000)),
                width: 8,
                signed: false,
            },
        );
        if let Stmt::Call { args, .. } = &mut call {
            *args = Some(vec![Expr::Const(0x2000), Expr::reg(7, 64)]);
        }
        let mut statements = vec![call];
        if writes {
            statements.push(Stmt::Store {
                addr: Expr::reg(7, 64),
                value: Expr::Const(65),
                width: 1,
                at: None,
            });
        }
        let mut ir = FunctionIr::single_block(Isa::X86_64, statements);
        ir.params.push(crate::ir::Param {
            index: 7,
            name: "a0".into(),
            ty: CType::U64,
        });
        super::apply_prototypes(&mut ir, &image);
        let expected = if writes { "char" } else { "const char" };
        assert_eq!(
            ir.params[0].ty,
            CType::pointer_to(CType::Named(expected.into()))
        );
        let text = crate::render::render(&ir, &[], &Default::default(), &[]);
        assert!(text.contains(&format!("{expected} *a0")), "{text}");
    }
}

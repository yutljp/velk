use super::{cse, safe_to_speculate};
use crate::ir::eval::{self, Outcome, Setup};
use crate::ir::{
    BinOp, Block, CType, Cond, Expr, FunctionIr, Operation, Param, Precision, RegRef, Rounding,
    Stmt, TEMP_BASE, VARIABLE_BASE,
};
use crate::loader::Isa;

const ANSWER: u64 = 0xfedc_ba98_7654_3210;

fn assign(index: u16, value: Expr) -> Stmt {
    Stmt::Assign {
        dest: RegRef { index, width: 64 },
        value,
        at: None,
    }
}

fn repeated(input: u16, addend: u64) -> Expr {
    let value = Expr::bin(BinOp::Add, Expr::reg(input, 64), Expr::Const(addend));
    Expr::bin(BinOp::Mul, value.clone(), value)
}

fn twice(value: Expr) -> Expr {
    Expr::bin(BinOp::Add, value.clone(), value)
}

fn choose(then: Expr, els: Expr) -> Expr {
    Expr::Select {
        cond: Cond::Eq,
        lhs: Box::new(Expr::reg(7, 64)),
        rhs: Box::new(Expr::Const(0)),
        then: Box::new(then),
        els: Box::new(els),
    }
}

fn function(value: Expr) -> FunctionIr {
    FunctionIr::single_block(Isa::X86_64, vec![Stmt::Ret { value, at: None }])
}

fn run(ir: &FunctionIr, registers: &[(u16, u64)]) -> Outcome {
    eval::run(
        ir,
        &Setup {
            seed: 0,
            convention: eval::Convention {
                arguments: &[],
                clobbered: &[],
            },
            registers,
            memory: &[],
            step_limit: 4096,
        },
    )
}

/// Runs `original` and its eliminated form, once and twice over, and
/// checks both return `expected`.
fn compare(original: &FunctionIr, registers: &[(u16, u64)], expected: u64) -> FunctionIr {
    let before = run(original, registers);
    assert_eq!(
        before,
        Outcome::Return {
            value: expected,
            calls: vec![],
            memory: Default::default(),
        }
    );
    let mut changed = original.clone();
    cse(&mut changed);
    assert_eq!(run(&changed, registers), before, "{}", changed.render());
    cse(&mut changed);
    assert_eq!(run(&changed, registers), before, "{}", changed.render());
    changed
}

fn definitions(ir: &FunctionIr) -> Vec<&Expr> {
    ir.blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .filter_map(|stmt| match stmt {
            Stmt::Assign { value, .. } => Some(value),
            _ => None,
        })
        .collect()
}

#[test]
fn cse_preserves_an_existing_temporary_used_in_a_later_block() {
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            assign(TEMP_BASE, Expr::Const(0xfedc_ba98_7654_3210)),
            assign(2, repeated(7, 1)),
            Stmt::Br {
                target: Some(1),
                at: None,
            },
        ],
    );
    ir.blocks.push(Block {
        start: 1,
        stmts: vec![Stmt::Ret {
            value: Expr::bin(BinOp::Add, Expr::reg(TEMP_BASE, 64), Expr::reg(2, 64)),
            at: None,
        }],
    });
    let original = ir.clone();
    cse(&mut ir);
    for input in [0u64, 2, 0x8000_0000, 0xffff_ffff_ffff_ffff] {
        let expected = 0xfedc_ba98_7654_3210u64.wrapping_add(input.wrapping_add(1).wrapping_pow(2));
        let before = run(&original, &[(7, input)]);
        assert!(matches!(&before, Outcome::Return { value, .. } if *value == expected));
        assert_eq!(run(&ir, &[(7, input)]), before);
    }
    assert_eq!(
        ir.blocks[0]
            .stmts
            .iter()
            .filter(|stmt| { matches!(stmt, Stmt::Assign { dest, .. } if dest.index == TEMP_BASE) })
            .count(),
        1
    );
}

#[test]
fn cse_processes_each_original_statement_once() {
    let leaf = Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(1));
    let product = Expr::bin(BinOp::Mul, leaf.clone(), leaf.clone());
    let value = Expr::bin(
        BinOp::Add,
        product.clone(),
        Expr::bin(BinOp::Add, product, leaf.clone()),
    );
    let original = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            assign(2, value),
            Stmt::Ret {
                value: Expr::reg(2, 64),
                at: None,
            },
        ],
    );
    let mut changed = original.clone();
    cse(&mut changed);
    for input in [0u64, 2, 0x8000_0000, u64::MAX] {
        let leaf = input.wrapping_add(1);
        let expected = leaf.wrapping_mul(leaf).wrapping_mul(2).wrapping_add(leaf);
        let before = run(&original, &[(7, input)]);
        assert!(matches!(&before, Outcome::Return { value, .. } if *value == expected));
        assert_eq!(run(&changed, &[(7, input)]), before);
    }
    // The sum, then the product of it, each bound once.
    let shared = Expr::reg(TEMP_BASE, 64);
    assert_eq!(
        definitions(&changed)[..2],
        [&leaf, &Expr::bin(BinOp::Mul, shared.clone(), shared)]
    );
    assert_eq!(changed.blocks[0].stmts.len(), 4);
}

#[test]
fn cse_binds_a_repeated_subtree_once_rather_than_its_parts() {
    let address = Expr::bin(
        BinOp::Add,
        Expr::reg(7, 64),
        Expr::bin(BinOp::Mul, Expr::reg(6, 64), Expr::Const(8)),
    );
    let load = Expr::Load {
        addr: Box::new(address.clone()),
        width: 8,
        signed: false,
    };
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            Stmt::Store {
                addr: address.clone(),
                value: Expr::bin(BinOp::Or, load, Expr::Const(1)),
                width: 8,
                at: None,
            },
            Stmt::Ret {
                value: Expr::Const(0),
                at: None,
            },
        ],
    );
    cse(&mut ir);
    assert_eq!(definitions(&ir), [&address]);
}

#[test]
fn cse_repeated_on_the_same_ir_keeps_a_live_generated_temporary() {
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            assign(2, repeated(7, 1)),
            Stmt::Ret {
                value: Expr::reg(2, 64),
                at: None,
            },
        ],
    );
    cse(&mut ir);
    let first_temp = match &ir.blocks[0].stmts[0] {
        Stmt::Assign { dest, .. } => dest.index,
        other => panic!("missing temporary: {other:?}"),
    };
    assert!((TEMP_BASE..VARIABLE_BASE).contains(&first_temp));
    ir.blocks[0].stmts.insert(1, assign(3, repeated(6, 2)));
    *ir.blocks[0].stmts.last_mut().unwrap() = Stmt::Ret {
        value: Expr::bin(BinOp::Add, Expr::reg(2, 64), Expr::reg(3, 64)),
        at: None,
    };
    let before = ir.clone();
    cse(&mut ir);
    cse(&mut ir);
    let mut optimized = before.clone();
    crate::passes::optimize(&mut optimized, false);
    crate::passes::optimize(&mut optimized, false);
    for (left, right) in [(2u64, 5u64), (0x1234_5678_9abc_def0, u64::MAX)] {
        let registers = [(7, left), (6, right)];
        let expected = left
            .wrapping_add(1)
            .wrapping_pow(2)
            .wrapping_add(right.wrapping_add(2).wrapping_pow(2));
        let outcome = run(&before, &registers);
        assert!(matches!(&outcome, Outcome::Return { value, .. } if *value == expected));
        assert_eq!(run(&ir, &registers), outcome);
        assert_eq!(run(&optimized, &registers), outcome);
    }
    assert_eq!(
        ir.blocks[0]
            .stmts
            .iter()
            .filter(|stmt| {
                matches!(stmt, Stmt::Assign { dest, .. } if dest.index == first_temp)
            })
            .count(),
        1
    );
}

#[test]
fn cse_retains_defined_expressions_when_temporary_slots_run_out() {
    let left = repeated(7, 1);
    let right = repeated(6, 2);
    for available in [None, Some(TEMP_BASE + 2)] {
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                assign(2, Expr::bin(BinOp::Add, left.clone(), right.clone())),
                Stmt::Ret {
                    value: Expr::reg(2, 64),
                    at: None,
                },
            ],
        );
        ir.params = (TEMP_BASE..VARIABLE_BASE)
            .filter(|index| Some(*index) != available)
            .map(|index| Param {
                index,
                name: format!("p{index}"),
                ty: CType::U64,
            })
            .collect();
        let original = ir.clone();
        cse(&mut ir);
        for (left, right) in [(2u64, 5u64), (u64::MAX, 0x8000_0000)] {
            let registers = [(7, left), (6, right)];
            let expected = left
                .wrapping_add(1)
                .wrapping_pow(2)
                .wrapping_add(right.wrapping_add(2).wrapping_pow(2));
            let before = run(&original, &registers);
            assert!(matches!(&before, Outcome::Return { value, .. } if *value == expected));
            assert_eq!(run(&ir, &registers), before);
        }
        let generated: Vec<_> = ir.blocks[0]
            .stmts
            .iter()
            .filter_map(|stmt| match stmt {
                Stmt::Assign { dest, .. } if dest.index >= TEMP_BASE => Some(dest.index),
                _ => None,
            })
            .collect();
        assert_eq!(generated, available.into_iter().collect::<Vec<_>>());
        if available.is_none() {
            assert_eq!(ir.render(), original.render());
        }
    }
}

#[test]
fn temporary_slots_exclude_all_fixed_roles_and_actual_register_uses() {
    let mut ir = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            assign(TEMP_BASE, Expr::reg(TEMP_BASE + 1, 64)),
            Stmt::Unsupported {
                at: None,
                text: String::new(),
                writes: Some(vec![TEMP_BASE + 2]),
            },
            Stmt::Ret {
                value: Expr::reg(TEMP_BASE + 3, 64),
                at: None,
            },
        ],
    );
    ir.blocks.push(Block {
        start: 1,
        stmts: vec![assign(TEMP_BASE + 4, Expr::Const(0))],
    });
    let pool = crate::ir::visit::unused_temporaries(&ir);
    assert!(pool.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(
        pool.iter()
            .all(|index| (TEMP_BASE..VARIABLE_BASE).contains(index))
    );
    for register in crate::ir::FLAG_OPERANDS
        .into_iter()
        .chain(crate::ir::FLAG_CARRIED)
        .chain([
            crate::ir::EXCHANGE,
            crate::ir::SWITCH_INDEX,
            crate::ir::EXCEPTION,
            crate::ir::SELECTOR,
        ])
        .chain(TEMP_BASE..TEMP_BASE + 5)
    {
        assert!(!pool.contains(&register), "reserved or used: {register}");
    }
    assert_eq!(pool.first(), Some(&(TEMP_BASE + 5)));
}

#[test]
fn cse_skips_fixed_slots_when_one_statement_needs_many_bindings() {
    let value = (1..=70).fold(Expr::Const(0), |sum, addend| {
        Expr::bin(BinOp::Add, sum, repeated(7, addend))
    });
    let original = FunctionIr::single_block(
        Isa::X86_64,
        vec![
            assign(2, value),
            Stmt::Ret {
                value: Expr::reg(2, 64),
                at: None,
            },
        ],
    );
    let mut changed = original.clone();
    cse(&mut changed);
    let generated: Vec<_> = changed.blocks[0]
        .stmts
        .iter()
        .filter_map(|stmt| match stmt {
            Stmt::Assign { dest, .. } if dest.index >= TEMP_BASE => Some(dest.index),
            _ => None,
        })
        .collect();
    assert_eq!(generated.len(), 70);
    for reserved in crate::ir::FLAG_OPERANDS
        .into_iter()
        .chain(crate::ir::FLAG_CARRIED)
        .chain([
            crate::ir::EXCHANGE,
            crate::ir::SWITCH_INDEX,
            crate::ir::EXCEPTION,
            crate::ir::SELECTOR,
        ])
    {
        assert!(!generated.contains(&reserved));
    }
    for input in [2u64, 0xffff_ffff_ffff_fffe] {
        let expected = (1..=70).fold(0u64, |sum, addend| {
            sum.wrapping_add(input.wrapping_add(addend).wrapping_pow(2))
        });
        let before = run(&original, &[(7, input)]);
        assert!(matches!(&before, Outcome::Return { value, .. } if *value == expected));
        assert_eq!(run(&changed, &[(7, input)]), before);
    }
}

#[test]
fn cse_does_not_evaluate_a_division_in_an_unselected_arm() {
    let quotient = Expr::bin(BinOp::DivU, Expr::reg(6, 64), Expr::reg(1, 64));
    let original = FunctionIr::single_block(
        Isa::X86_64,
        vec![Stmt::Ret {
            value: Expr::Select {
                cond: Cond::Eq,
                lhs: Box::new(Expr::reg(7, 64)),
                rhs: Box::new(Expr::Const(0)),
                then: Box::new(Expr::Const(0xfedc_ba98_7654_3210)),
                els: Box::new(Expr::bin(BinOp::Add, quotient.clone(), quotient)),
            },
            at: None,
        }],
    );
    let setup = Setup {
        seed: 0,
        convention: eval::Convention {
            arguments: &[],
            clobbered: &[],
        },
        registers: &[(7, 0), (6, 42), (1, 0)],
        memory: &[],
        step_limit: 16,
    };
    let expected = Outcome::Return {
        value: 0xfedc_ba98_7654_3210,
        calls: vec![],
        memory: Default::default(),
    };
    let before = eval::run(&original, &setup);
    assert_eq!(before, expected);
    let mut changed = original.clone();
    cse(&mut changed);
    assert_eq!(
        eval::run(&changed, &setup),
        before,
        "original:\n{}changed:\n{}",
        original.render(),
        changed.render(),
    );
}
#[test]
fn cse_keeps_all_scalar_division_kinds_in_their_selected_arm() {
    for op in [BinOp::DivS, BinOp::DivU, BinOp::ModS, BinOp::ModU] {
        let operation = Expr::bin(op, Expr::reg(6, 64), Expr::reg(1, 64));
        for guarded_then in [false, true] {
            let value = if guarded_then {
                choose(twice(operation.clone()), Expr::Const(ANSWER))
            } else {
                choose(Expr::Const(ANSWER), twice(operation.clone()))
            };
            let original = function(value);
            let unselected = [(7, u64::from(guarded_then)), (6, 42), (1, 0)];
            let changed = compare(&original, &unselected, ANSWER);
            assert!(definitions(&changed).is_empty());
            let selected = [(7, u64::from(!guarded_then)), (6, 42), (1, 7)];
            let expected = if matches!(op, BinOp::DivS | BinOp::DivU) {
                12
            } else {
                0
            };
            compare(&original, &selected, expected);
            let failing = [(7, u64::from(!guarded_then)), (6, 42), (1, 0)];
            assert_eq!(
                run(&original, &failing),
                Outcome::Unknown("division by zero")
            );
            assert_eq!(
                run(&changed, &failing),
                Outcome::Unknown("division by zero")
            );
        }
    }
}

#[test]
fn cse_keeps_wide_division_failure_conditions_inside_the_arm() {
    for remainder in [false, true] {
        for (high, low, divisor) in [(0u64, 7u64, 0u64), (1, 0, 1)] {
            let operation = Expr::apply(
                Operation::WideDivide {
                    signed: false,
                    remainder,
                    bits: 64,
                },
                vec![Expr::Const(high), Expr::Const(low), Expr::reg(1, 64)],
            );
            let original = function(choose(Expr::Const(ANSWER), twice(operation)));
            let registers = [(7, 0), (1, divisor)];
            let changed = compare(&original, &registers, ANSWER);
            assert!(definitions(&changed).is_empty());
            let failing = [(7, 1), (1, divisor)];
            assert_eq!(
                run(&original, &failing),
                Outcome::Unknown("division by zero")
            );
            assert_eq!(
                run(&changed, &failing),
                Outcome::Unknown("division by zero")
            );
        }
    }
}

#[test]
fn cse_keeps_a_nested_select_comparison_conditional() {
    let quotient = Expr::bin(BinOp::DivU, Expr::reg(6, 64), Expr::reg(1, 64));
    let inner = Expr::Select {
        cond: Cond::Eq,
        lhs: Box::new(twice(quotient)),
        rhs: Box::new(Expr::Const(12)),
        then: Box::new(Expr::Const(3)),
        els: Box::new(Expr::Const(5)),
    };
    let original = function(choose(Expr::Const(ANSWER), inner));
    let changed = compare(&original, &[(7, 0), (6, 42), (1, 0)], ANSWER);
    assert!(definitions(&changed).is_empty());
    compare(&original, &[(7, 1), (6, 42), (1, 7)], 3);
}

#[test]
fn cse_still_shares_total_integer_values_from_an_arm() {
    for op in [BinOp::Add, BinOp::Mul, BinOp::Xor, BinOp::Shl] {
        let operation = Expr::bin(op, Expr::reg(6, 64), Expr::Const(5));
        let original = function(choose(twice(operation.clone()), Expr::Const(ANSWER)));
        let expected = match op {
            BinOp::Add => 16,
            BinOp::Mul => 30,
            BinOp::Xor => 12,
            BinOp::Shl => 192,
            _ => unreachable!(),
        };
        let changed = compare(&original, &[(7, 0), (6, 3)], expected);
        assert!(definitions(&changed).contains(&&operation));
        compare(&original, &[(7, 1), (6, u64::MAX)], ANSWER);
    }
}

#[test]
fn cse_still_shares_a_whole_select_with_a_failing_unchosen_arm() {
    let quotient = Expr::bin(BinOp::DivU, Expr::reg(6, 64), Expr::reg(1, 64));
    let selection = choose(Expr::Const(ANSWER), twice(quotient));
    let original = function(twice(selection));
    let changed = compare(
        &original,
        &[(7, 0), (6, 42), (1, 0)],
        ANSWER.wrapping_mul(2),
    );
    assert_eq!(definitions(&changed).len(), 1);
    assert!(matches!(definitions(&changed)[0], Expr::Select { .. }));
    compare(&original, &[(7, 1), (6, 42), (1, 7)], 24);
}

#[test]
fn cse_preserves_comparison_sharing_and_an_earlier_required_binding() {
    let addition = Expr::bin(BinOp::Add, Expr::reg(6, 64), Expr::Const(1));
    let original = function(Expr::Select {
        cond: Cond::Eq,
        lhs: Box::new(twice(addition.clone())),
        rhs: Box::new(Expr::Const(8)),
        then: Box::new(Expr::Const(ANSWER)),
        els: Box::new(Expr::Const(5)),
    });
    let changed = compare(&original, &[(6, 3)], ANSWER);
    assert!(definitions(&changed).contains(&&addition));
    let quotient = Expr::bin(BinOp::DivU, Expr::reg(6, 64), Expr::reg(1, 64));
    let original = function(Expr::bin(
        BinOp::Add,
        quotient.clone(),
        choose(Expr::Const(5), quotient.clone()),
    ));
    let changed = compare(&original, &[(7, 0), (6, 42), (1, 7)], 11);
    assert_eq!(definitions(&changed), vec![&quotient]);
    let Some(Stmt::Ret {
        value: Expr::Bin { rhs, .. },
        ..
    }) = changed.blocks[0].stmts.last()
    else {
        panic!("missing selected reuse: {}", changed.render());
    };
    assert!(
        matches!(rhs.as_ref(), Expr::Select { els, .. } if matches!(els.as_ref(), Expr::Reg { .. }))
    );
    compare(&original, &[(7, 1), (6, 42), (1, 7)], 12);
}

#[test]
fn cse_does_not_detach_floating_or_opaque_apply_from_an_arm() {
    let operations = [
        Expr::apply(
            Operation::FloatDiv(Precision::Double),
            vec![Expr::reg(6, 64), Expr::reg(1, 64)],
        ),
        Expr::apply(
            Operation::FloatSqrt(Precision::Double),
            vec![Expr::reg(6, 64)],
        ),
        Expr::apply(
            Operation::FloatToInt {
                signed: true,
                bits: 64,
                from: Precision::Double,
                saturating: false,
                rounding: Rounding::TowardZero,
            },
            vec![Expr::reg(6, 64)],
        ),
        Expr::apply(Operation::Results, vec![Expr::reg(6, 64), Expr::reg(1, 64)]),
        Expr::apply(Operation::PopCount(64), vec![Expr::reg(6, 64)]),
    ];
    for operation in operations {
        let original = function(choose(Expr::Const(ANSWER), twice(operation.clone())));
        let changed = compare(
            &original,
            &[(7, 0), (6, 0xbff0_0000_0000_0000), (1, 0)],
            ANSWER,
        );
        assert!(definitions(&changed).is_empty());
        assert!(!safe_to_speculate(&operation));
    }
}

#[test]
fn conditional_division_survives_repeated_full_optimization() {
    let quotient = Expr::bin(BinOp::DivU, Expr::reg(6, 64), Expr::reg(1, 64));
    let original = function(choose(Expr::Const(ANSWER), twice(quotient)));
    let mut optimized = original.clone();
    crate::passes::optimize(&mut optimized, false);
    crate::passes::optimize(&mut optimized, false);
    for (condition, divisor, expected) in [(0u64, 0u64, ANSWER), (1, 7, 12)] {
        let registers = [(7, condition), (6, 42), (1, divisor)];
        assert_eq!(
            run(&original, &registers),
            Outcome::Return {
                value: expected,
                calls: vec![],
                memory: Default::default(),
            }
        );
        assert_eq!(run(&optimized, &registers), run(&original, &registers));
    }
}
#[test]
fn cse_preserves_a_wide_selected_constant_next_to_narrow_division() {
    let quotient = Expr::bin(BinOp::DivU, Expr::reg(6, 32), Expr::reg(1, 32));
    let selected = Expr::Select {
        cond: Cond::Eq,
        lhs: Box::new(Expr::reg(7, 64)),
        rhs: Box::new(Expr::Const(0)),
        then: Box::new(Expr::Const(0xfedc_ba98_7654_3210)),
        els: Box::new(Expr::bin(BinOp::Add, quotient.clone(), quotient)),
    };
    let original = FunctionIr::single_block(
        Isa::X86_64,
        vec![Stmt::Ret {
            value: Expr::bin(BinOp::Add, selected.clone(), selected),
            at: None,
        }],
    );
    let setup = Setup {
        seed: 0,
        convention: eval::Convention {
            arguments: &[],
            clobbered: &[],
        },
        registers: &[(7, 0), (6, 42), (1, 7)],
        memory: &[],
        step_limit: 32,
    };
    let expected = Outcome::Return {
        value: 0xfedc_ba98_7654_3210u64.wrapping_mul(2),
        calls: vec![],
        memory: Default::default(),
    };
    let before = eval::run(&original, &setup);
    assert_eq!(before, expected);
    let mut changed = original.clone();
    cse(&mut changed);
    assert_eq!(
        eval::run(&changed, &setup),
        before,
        "original:\n{}changed:\n{}",
        original.render(),
        changed.render()
    );
}
#[test]
fn cse_preserves_mixed_narrow_widths_under_signed_division() {
    for (op, left, right) in [
        (BinOp::Add, 1u64, 0x7fff_ffffu64),
        (BinOp::Or, 0x8000, 0x8000_0000),
    ] {
        let operand = Expr::bin(op, Expr::reg(6, 16), Expr::reg(1, 32));
        let value = twice(Expr::bin(BinOp::DivS, operand, Expr::reg(2, 32)));
        let bits = if op == BinOp::Add {
            (left as u16 as u32).wrapping_add(right as u32)
        } else {
            left as u16 as u32 | right as u32
        };
        let expected = u64::from((bits as i32).wrapping_div(2) as u32).wrapping_mul(2);
        let changed = compare(&function(value), &[(6, left), (1, right), (2, 2)], expected);
        assert!(
            changed.blocks[0]
                .stmts
                .iter()
                .any(|stmt| { matches!(stmt, Stmt::Assign { dest, .. } if dest.width == 32) })
        );
    }
}

#[test]
fn cse_does_not_give_a_constant_expression_a_register_width() {
    let constant = Expr::bin(BinOp::Add, Expr::Const(0xffff_ffff), Expr::Const(0));
    let value = twice(Expr::bin(BinOp::DivS, constant.clone(), Expr::reg(2, 32)));
    let changed = compare(&function(value), &[(2, 2)], 0);
    assert!(
        !changed.blocks[0]
            .stmts
            .iter()
            .any(|stmt| { matches!(stmt, Stmt::Assign { value, .. } if *value == constant) })
    );
}

#[test]
fn cse_retains_full_bits_when_narrow_inputs_produce_a_wider_value() {
    let cases = [
        (BinOp::Add, 0xffff_ffffu64, 1u64, 0x1_0000_0000u64),
        (BinOp::Sub, 0, 1, u64::MAX),
        (BinOp::Mul, 0xffff_ffff, 0xffff_ffff, 0xffff_fffe_0000_0001),
        (BinOp::Shl, 1, 32, 0x1_0000_0000),
        (BinOp::Or, 0, 0x100_0000_0000, 0x100_0000_0000),
    ];
    for (op, input, constant, result) in cases {
        let value = twice(Expr::bin(op, Expr::reg(6, 32), Expr::Const(constant)));
        let changed = compare(&function(value), &[(6, input)], result.wrapping_mul(2));
        assert!(
            changed.blocks[0]
                .stmts
                .iter()
                .all(|stmt| !matches!(stmt, Stmt::Assign { .. }))
        );
    }
}

#[test]
fn cse_keeps_proven_narrow_bindings_at_their_operand_width() {
    for (bits, mask, input, expected) in [
        (8u8, 0xffu64, 0x80u64, 0x180u64),
        (16, 0xffff, 0x8000, 0x18000),
    ] {
        let operand = Expr::bin(BinOp::And, Expr::reg(6, 64), Expr::Const(mask));
        let value = twice(Expr::bin(BinOp::DivS, operand, Expr::reg(2, bits)));
        let changed = compare(&function(value), &[(6, input), (2, 2)], expected);
        assert!(
            changed.blocks[0]
                .stmts
                .iter()
                .any(|stmt| { matches!(stmt, Stmt::Assign { dest, .. } if dest.width == bits) })
        );
    }
}

#[test]
fn temporary_slots_exclude_function_annotations_and_call_registers() {
    use crate::ir::{Access, CallKind, CallOutput, Convention, Structure};
    let temporary_register = |offset| TEMP_BASE + offset;
    let mut ir = FunctionIr::single_block(Isa::X86_64, vec![]);
    ir.params.push(Param {
        index: temporary_register(0),
        name: "p".into(),
        ty: CType::U64,
    });
    ir.signed_params.insert(temporary_register(1));
    ir.pointer_values.push(temporary_register(2));
    ir.value_types.insert(temporary_register(3), CType::U64);
    ir.variable_registers
        .insert(temporary_register(4), temporary_register(5));
    ir.accesses.push(Access {
        register: temporary_register(6),
        fields: vec![],
    });
    ir.structures.push(Structure {
        name: "s".into(),
        fields: vec![],
        size: None,
        elements: vec![temporary_register(7)],
    });
    ir.blocks[0].stmts.push(Stmt::Call {
        kind: CallKind::Invoke,
        target: None,
        through: Some(Expr::reg(temporary_register(8), 64)),
        convention: Convention::SysV,
        args: Some(vec![Expr::reg(temporary_register(9), 64)]),
        floats_named: true,
        abi: None,
        outputs: vec![CallOutput {
            register: temporary_register(10),
            dest: RegRef {
                index: temporary_register(11),
                width: 64,
            },
        }],
        clobbers: Some(Default::default()),
        via: None,
        at: None,
    });
    let pool = crate::ir::visit::unused_temporaries(&ir);
    for register in TEMP_BASE..temporary_register(12) {
        assert!(!pool.contains(&register), "named index: {register}");
    }
    assert_eq!(pool.first(), Some(&temporary_register(12)));
}

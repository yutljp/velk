use super::*;
use crate::ir::smt::{self, Proofs, raw_bin};
use crate::ir::{Block, Cond, RegRef, VARIABLE_BASE};
use crate::loader::Isa;

#[test]
fn identities_are_proved_at_every_integer_width() {
    assert!(
        Proofs::available(),
        "z3 is required to verify integer identities"
    );
    let mut proofs = Proofs::default();
    for bits in [8, 16, 32, 64] {
        let x = Expr::reg(0, bits);
        let mut identities = vec![
            raw_bin(BinOp::Xor, x.clone(), x.clone()),
            raw_bin(BinOp::Sub, x.clone(), x.clone()),
            raw_bin(
                BinOp::And,
                x.clone(),
                raw_bin(BinOp::Xor, x.clone(), Expr::Const(u64::MAX)),
            ),
        ];
        for op in [BinOp::Add, BinOp::Sub] {
            for offset in [1, 3, u64::MAX] {
                let product = raw_bin(
                    BinOp::Mul,
                    x.clone(),
                    raw_bin(op, x.clone(), Expr::Const(offset)),
                );
                identities.push(raw_bin(BinOp::And, product.clone(), Expr::Const(1)));
                identities.push(raw_bin(BinOp::ModU, product, Expr::Const(2)));
            }
        }
        identities.push(raw_bin(
            BinOp::Or,
            identities[0].clone(),
            identities[2].clone(),
        ));
        for op in [BinOp::Add, BinOp::Sub] {
            let odd = raw_bin(BinOp::Or, Expr::reg(1, 64), Expr::Const(1));
            let product = raw_bin(BinOp::Mul, x.clone(), raw_bin(op, x.clone(), odd));
            for (reduction, divisor) in [(BinOp::And, 1), (BinOp::ModU, 2)] {
                proofs.expression(
                    format!("constant-predicate/{bits}/{op:?}/{reduction:?}/odd-offset"),
                    &raw_bin(reduction, product.clone(), Expr::Const(divisor)),
                    &Expr::Const(0),
                    64,
                );
            }
        }
        for (index, value) in identities.iter().enumerate() {
            assert!(known_zero(value), "{value:?}");
            proofs.expression(
                format!("constant-predicate/{bits}/{index}"),
                value,
                &Expr::Const(0),
                64,
            );
            for cond in smt::CONDITIONS {
                let width = crate::ir::semantics::operand_width(value, &Expr::Const(1));
                let after = crate::ir::semantics::holds(cond, 0, 1, width);
                proofs.predicate(
                    format!("constant-predicate/{bits}/{index}/{cond:?}"),
                    &smt::condition(cond, &smt::term(value), &smt::constant(1), width),
                    if after { "true" } else { "false" },
                );
            }
        }
    }
    proofs.check();
}

#[test]
fn uncertain_or_faulting_expressions_remain() {
    let x = Expr::reg(0, 32);
    for offset in [0, 2, 4] {
        assert!(!known_zero(&raw_bin(
            BinOp::And,
            raw_bin(
                BinOp::Mul,
                x.clone(),
                raw_bin(BinOp::Add, x.clone(), Expr::Const(offset))
            ),
            Expr::Const(1)
        )));
    }
    for value in [
        Expr::Load {
            addr: Box::new(x.clone()),
            width: 4,
            signed: false,
        },
        raw_bin(BinOp::DivU, x.clone(), Expr::Const(0)),
        raw_bin(BinOp::ModS, x, Expr::Const(0)),
    ] {
        assert!(!known_zero(&raw_bin(BinOp::Xor, value.clone(), value)));
    }
}

fn assign(value: Expr) -> Stmt {
    Stmt::Assign {
        dest: RegRef {
            index: VARIABLE_BASE,
            width: 32,
        },
        value,
    }
}

fn dispatcher(value: Expr) -> FunctionIr {
    let mut ir = FunctionIr::single_block(Isa::X86_64, Vec::new());
    ir.blocks = vec![
        Block {
            start: 0,
            stmts: vec![assign(Expr::Const(11))],
        },
        Block {
            start: 10,
            stmts: vec![Stmt::Brif {
                cond: Cond::Eq,
                lhs: Expr::reg(VARIABLE_BASE, 32),
                rhs: Expr::Const(11),
                target: 40,
            }],
        },
        Block {
            start: 20,
            stmts: vec![Stmt::Brif {
                cond: Cond::Eq,
                lhs: Expr::reg(VARIABLE_BASE, 32),
                rhs: Expr::Const(29),
                target: 50,
            }],
        },
        Block {
            start: 30,
            stmts: vec![Stmt::Ret {
                value: Expr::Const(0),
            }],
        },
        Block {
            start: 40,
            stmts: vec![assign(value), Stmt::Br { target: Some(10) }],
        },
        Block {
            start: 50,
            stmts: vec![Stmt::Ret {
                value: Expr::Const(7),
            }],
        },
    ];
    ir
}

#[test]
fn unknown_transition_keeps_the_entire_dispatcher() {
    let mut ir = dispatcher(Expr::reg(7, 32));
    let before = format!("{ir:?}");
    assert_eq!(dispatcher::remove(&mut ir), 0);
    assert_eq!(format!("{ir:?}"), before);
}

#[test]
fn constant_transition_removes_dispatcher_tests() {
    let mut ir = dispatcher(Expr::Const(29));
    assert_eq!(dispatcher::remove(&mut ir), 2);
    assert!(
        !ir.blocks
            .iter()
            .flat_map(|block| &block.stmts)
            .any(|stmt| matches!(stmt, Stmt::Brif { .. }))
    );
}

#[test]
fn truncated_state_and_changed_select_operands_are_handled_safely() {
    let mut ir = dispatcher(Expr::Const(0x1_0000_001d));
    assert_eq!(dispatcher::remove(&mut ir), 2);
    assert!(ir.blocks.iter().any(|block| block.start == 50));
    let select = Expr::Select {
        cond: Cond::Eq,
        lhs: Box::new(Expr::reg(VARIABLE_BASE + 1, 32)),
        rhs: Box::new(Expr::Const(0)),
        then: Box::new(Expr::Const(29)),
        els: Box::new(Expr::Const(11)),
    };
    let mut ir = dispatcher(select);
    ir.blocks[4].stmts.insert(
        1,
        Stmt::Assign {
            dest: RegRef {
                index: VARIABLE_BASE + 1,
                width: 32,
            },
            value: Expr::Const(1),
        },
    );
    let before = format!("{ir:?}");
    assert_eq!(dispatcher::remove(&mut ir), 0);
    assert_eq!(format!("{ir:?}"), before);
}

#[test]
fn unresolved_edges_and_exception_handlers_keep_the_dispatcher() {
    let mut ir = dispatcher(Expr::Const(29));
    ir.blocks[4].stmts.push(Stmt::Br { target: Some(999) });
    assert_eq!(dispatcher::remove(&mut ir), 0);
    let mut ir = dispatcher(Expr::Const(29));
    ir.landing_pads.push((40, vec![(0, 10)]));
    assert_eq!(dispatcher::remove(&mut ir), 0);
}

#[test]
fn a_select_that_reads_its_destination_keeps_the_dispatcher() {
    let mut ir = dispatcher(Expr::Select {
        cond: Cond::Eq,
        lhs: Box::new(Expr::reg(VARIABLE_BASE, 32)),
        rhs: Box::new(Expr::Const(11)),
        then: Box::new(Expr::Const(29)),
        els: Box::new(Expr::Const(11)),
    });
    assert_eq!(dispatcher::remove(&mut ir), 0);
}

#[test]
fn switch_dispatchers_and_fallthrough_choices_are_recovered() {
    let mut ir = dispatcher(Expr::Select {
        cond: Cond::Eq,
        lhs: Box::new(Expr::reg(7, 32)),
        rhs: Box::new(Expr::Const(0)),
        then: Box::new(Expr::Const(29)),
        els: Box::new(Expr::Const(37)),
    });
    ir.blocks[1].stmts = vec![Stmt::Switch {
        index: Expr::reg(VARIABLE_BASE, 32),
        cases: vec![(11, 40), (29, 50)],
        default: Some(30),
    }];
    // Keep the case's conditional state assignment as a fallthrough edge.
    ir.blocks[4].stmts.pop();
    ir.blocks.insert(
        5,
        Block {
            start: 45,
            stmts: vec![Stmt::Br { target: Some(10) }],
        },
    );
    assert_eq!(dispatcher::remove(&mut ir), 3);
    assert!(
        !ir.blocks
            .iter()
            .flat_map(|block| &block.stmts)
            .any(|stmt| matches!(stmt, Stmt::Switch { .. }))
    );
}

#[test]
fn existing_dominating_checks_exclude_the_removed_paths() {
    assert!(
        Proofs::available(),
        "z3 is required to verify dominating checks"
    );
    let mut proofs = Proofs::default();
    let input = smt::term(&Expr::reg(0, 64));
    let zero = smt::constant(0);
    let one = smt::constant(1);
    let two = smt::constant(2);
    for bits in [8, 16, 32, 64] {
        let nonzero = smt::condition(Cond::Ne, &input, &zero, bits);
        let is_zero = smt::condition(Cond::Eq, &input, &zero, bits);
        proofs.predicate(
            format!("dominating-check/nonzero/{bits}"),
            &format!("(and {nonzero} {is_zero})"),
            "false",
        );
        let at_most_one = smt::condition(Cond::Ls, &input, &one, bits);
        let not_one = smt::condition(Cond::Ne, &input, &one, bits);
        proofs.predicate(
            format!("dominating-check/byte-tag/{bits}"),
            &format!("(and {at_most_one} {not_one} {nonzero})"),
            "false",
        );
        let at_least_two = smt::condition(Cond::Cs, &input, &two, bits);
        let at_most_two = smt::condition(Cond::Ls, &input, &two, bits);
        let not_two = smt::condition(Cond::Ne, &input, &two, bits);
        proofs.predicate(
            format!("dominating-check/length/{bits}"),
            &format!("(and {at_least_two} {at_most_two} {not_two})"),
            "false",
        );
    }
    proofs.check();
}

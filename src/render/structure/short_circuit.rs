//! Tests that only complete another one, joined with it as `&&` or `||`.
//! A compiler lowers `if (a && b)` to two branches that share where the
//! test fails, so the block after the whole condition has two entries and
//! structuring it as nested tests needs a goto. Joined, the condition is
//! one test again, a choice of truth values that reads as `&&` and `||`
//! and, like C's operators, evaluates its second test only when needed.

use std::collections::HashMap;

use super::{Node, compare_chain::predecessors};
use crate::ir::{Cond, Expr, FunctionIr, Stmt};

/// The most tests one joined condition holds.
const MAX_TESTS: usize = 4;

pub(super) fn fold_conditions(nodes: &mut Vec<Node>) {
    for node in nodes.iter_mut() {
        match node {
            Node::If { then, els, .. } => {
                fold_conditions(then);
                fold_conditions(els);
            }
            Node::While { prefix, body, .. } => {
                fold_conditions(prefix);
                fold_conditions(body);
            }
            Node::DoWhile { body, .. } | Node::Forever { body } => fold_conditions(body),
            Node::Switch { arms, default, .. } => {
                for (_, body) in arms {
                    fold_conditions(body);
                }
                if let Some(body) = default {
                    fold_conditions(body);
                }
            }
            _ => {}
        }
    }
    let mut at = 0;
    while at < nodes.len() {
        if let Some(combined) = nested_guard(&nodes[at]) {
            nodes[at] = combined;
            continue;
        }
        if let Some(next) = nodes.get(at + 1)
            && let Some(combined) = terminal_guards(&nodes[at], next)
        {
            nodes[at] = combined;
            nodes.remove(at + 1);
            continue;
        }
        at += 1;
    }
}

fn selected_guard(node: &Node) -> Option<(Expr, &[Node])> {
    let Node::If {
        cond,
        lhs,
        rhs,
        then,
        els,
    } = node
    else {
        return None;
    };
    if !value_comparison(*cond) {
        return None;
    }
    let condition = truth(*cond, lhs, rhs);
    if els.is_empty() && !then.is_empty() {
        Some((condition, then))
    } else if then.is_empty() && !els.is_empty() {
        Some((truth(Cond::Eq, &condition, &Expr::Const(0)), els))
    } else {
        None
    }
}

fn combined_guard(first: Expr, second: Expr, body: &[Node], either: bool) -> Option<Node> {
    let (then, els) = if either {
        (Expr::Const(1), second)
    } else {
        (second, Expr::Const(0))
    };
    let condition = Expr::Select {
        cond: Cond::Ne,
        lhs: Box::new(first),
        rhs: Box::new(Expr::Const(0)),
        then: Box::new(then),
        els: Box::new(els),
    };
    if tests(&condition) > MAX_TESTS {
        return None;
    }
    Some(Node::If {
        cond: Cond::Ne,
        lhs: condition,
        rhs: Expr::Const(0),
        then: body.to_vec(),
        els: Vec::new(),
    })
}

fn nested_guard(node: &Node) -> Option<Node> {
    let (first, body) = selected_guard(node)?;
    let [inner] = body else {
        return None;
    };
    let (second, body) = selected_guard(inner)?;
    combined_guard(first, second, body, false)
}

fn terminal_guards(first: &Node, second: &Node) -> Option<Node> {
    let (first, body) = selected_guard(first)?;
    let (second, other) = selected_guard(second)?;
    let same = match (body, other) {
        ([Node::Stmt(Stmt::Ret { value: one })], [Node::Stmt(Stmt::Ret { value: two })]) => {
            one == two
        }
        ([Node::Stmt(Stmt::Trap)], [Node::Stmt(Stmt::Trap)])
        | ([Node::Break], [Node::Break])
        | ([Node::Continue], [Node::Continue]) => true,
        _ => false,
    };
    if !same {
        return None;
    }
    combined_guard(first, second, body, true)
}

/// The function with each block that only tests, entered from one test
/// alone and going where that test goes on one side, joined into it.
pub(super) fn short_circuited(ir: &FunctionIr) -> Option<FunctionIr> {
    if ir
        .blocks
        .iter()
        .any(|block| matches!(block.stmts.last(), Some(Stmt::BrIndirect { .. })))
    {
        return None;
    }
    let mut ir = ir.clone();
    let mut changed = false;
    let mut block = 0;
    let mut entries = predecessors(&ir);
    let mut index = positions(&ir);
    while block < ir.blocks.len() {
        match join(&ir, &entries, &index, block) {
            Some((stmt, removed)) => {
                *ir.blocks[block].stmts.last_mut().expect("a test") = stmt;
                ir.blocks.remove(removed);
                entries = predecessors(&ir);
                index = positions(&ir);
                changed = true;
                // The joined test may complete the one before it in turn.
                block = block.saturating_sub(1);
            }
            None => block += 1,
        }
    }
    changed.then_some(ir)
}

fn positions(ir: &FunctionIr) -> HashMap<u64, usize> {
    ir.blocks
        .iter()
        .enumerate()
        .map(|(position, block)| (block.start, position))
        .collect()
}

// These conditions read processor flags rather than compare the two values.
fn value_comparison(cond: Cond) -> bool {
    !matches!(cond, Cond::Mi | Cond::Pl | Cond::Vs | Cond::Vc)
}

/// A test the condition can join: a comparison of values, not of flags.
fn test(stmt: Option<&Stmt>) -> Option<(Cond, &Expr, &Expr, u64)> {
    match stmt {
        Some(Stmt::Brif {
            cond,
            lhs,
            rhs,
            target,
        }) if value_comparison(*cond) => Some((*cond, lhs, rhs, *target)),
        _ => None,
    }
}

/// The test ending `block` joined with the block after it, or the one it
/// branches to, when that one only tests and nothing else enters it: the
/// new test and the position of the block it takes in.
fn join(
    ir: &FunctionIr,
    entries: &HashMap<u64, usize>,
    index: &HashMap<u64, usize>,
    block: usize,
) -> Option<(Stmt, usize)> {
    let Some((first, lhs, rhs, taken)) = test(ir.blocks[block].stmts.last()) else {
        return None;
    };
    let starts = |position: usize| ir.blocks.get(position).map(|block| block.start);
    let Some(fallthrough) = starts(block + 1) else {
        return None;
    };
    let position = |start: u64| index.get(&start).copied();
    let same = |one: u64, other: u64| same_place(ir, index, one, other);
    let first_test = || (first, lhs.clone(), rhs.clone());
    for second in [Some(block + 1), position(taken)].into_iter().flatten() {
        let candidate = &ir.blocks[second];
        if second == 0
            || second == block
            || entries.get(&candidate.start) != Some(&1)
            || candidate.stmts.len() != 1
        {
            continue;
        }
        let Some((cond, other_lhs, other_rhs, other)) = test(candidate.stmts.last()) else {
            continue;
        };
        let Some(after) = starts(second + 1) else {
            continue;
        };
        if [other, after].contains(&candidate.start) {
            continue;
        }
        let holds = truth(cond, other_lhs, other_rhs);
        let fails = truth(cond.invert(), other_lhs, other_rhs);
        let (test, then, els, target) = if second == block + 1 {
            if same(other, taken) {
                // a || b goes where both go; otherwise on.
                (first_test(), Expr::Const(1), holds, taken)
            } else if same(after, taken) {
                // !a && b goes where b goes; otherwise where both go.
                (
                    (first.invert(), lhs.clone(), rhs.clone()),
                    holds,
                    Expr::Const(0),
                    other,
                )
            } else {
                continue;
            }
        } else if same(other, fallthrough) {
            // a && !b goes where b falls; otherwise on.
            (first_test(), fails, Expr::Const(0), after)
        } else if same(after, fallthrough) {
            // a && b goes where b goes; otherwise on.
            (first_test(), holds, Expr::Const(0), other)
        } else {
            continue;
        };
        let (cond, lhs, rhs) = test;
        let joined = Expr::Select {
            cond,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
            then: Box::new(then),
            els: Box::new(els),
        };
        if tests(&joined) > MAX_TESTS {
            continue;
        }
        let stmt = Stmt::Brif {
            cond: Cond::Ne,
            lhs: joined,
            rhs: Expr::Const(0),
            target,
        };
        return Some((stmt, second));
    }
    None
}

/// Whether going to `one` does what going to `other` does: they lead to
/// the same block, or to blocks that only return the same value.
fn same_place(ir: &FunctionIr, index: &HashMap<u64, usize>, one: u64, other: u64) -> bool {
    let (one, other) = (settle(ir, index, one), settle(ir, index, other));
    if one == other {
        return true;
    }
    let stmts = |start: u64| {
        index
            .get(&start)
            .map(|position| ir.blocks[*position].stmts.as_slice())
    };
    match (stmts(one), stmts(other)) {
        (Some([Stmt::Ret { value: a }]), Some([Stmt::Ret { value: b }])) => a == b,
        (Some([Stmt::Trap]), Some([Stmt::Trap])) => true,
        _ => false,
    }
}

/// Where control goes from a block start, past blocks that only jump.
fn settle(ir: &FunctionIr, index: &HashMap<u64, usize>, mut target: u64) -> u64 {
    for _ in 0..8 {
        match index
            .get(&target)
            .map(|position| ir.blocks[*position].stmts.as_slice())
        {
            Some([Stmt::Br { target: Some(next) }]) if *next != target => target = *next,
            _ => break,
        }
    }
    target
}

/// A test as a truth value, one when it holds; a joined test already is one.
fn truth(cond: Cond, lhs: &Expr, rhs: &Expr) -> Expr {
    if cond == Cond::Ne && matches!(rhs, Expr::Const(0)) && is_truth(lhs) {
        return lhs.clone();
    }
    Expr::Select {
        cond,
        lhs: Box::new(lhs.clone()),
        rhs: Box::new(rhs.clone()),
        then: Box::new(Expr::Const(1)),
        els: Box::new(Expr::Const(0)),
    }
}

/// A choice whose every outcome is zero or one.
fn is_truth(expr: &Expr) -> bool {
    match expr {
        Expr::Select { then, els, .. } => [then, els]
            .into_iter()
            .all(|value| matches!(value.as_ref(), Expr::Const(0 | 1)) || is_truth(value)),
        _ => false,
    }
}

/// How many comparisons a truth value makes.
fn tests(expr: &Expr) -> usize {
    match expr {
        Expr::Select { lhs, then, els, .. } => {
            let own = if is_truth(lhs) { tests(lhs) } else { 1 };
            own + [then, els]
                .into_iter()
                .map(|value| if is_truth(value) { tests(value) } else { 0 })
                .sum::<usize>()
        }
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::fold_conditions;
    use crate::ir::eval::{self, Outcome};
    use crate::ir::{
        BinOp, Block, CType, Cond, Expr, FunctionIr, Operation, Param, Precision, RegRef,
        Registers, Stmt,
    };
    use crate::loader::Isa;
    use crate::render::structure::{Node, lower};

    const REGISTERS: [u16; 6] = [7, 6, 2, 1, 8, 9];
    const COUNTER: u64 = 0x1000;
    const DATA: u64 = 0x2000;
    type Row = [u64; 6];

    fn reg(position: usize) -> Expr {
        Expr::reg(REGISTERS[position], 64)
    }

    fn load(address: u64) -> Expr {
        Expr::Load {
            addr: Box::new(Expr::Const(address)),
            width: 8,
            signed: false,
        }
    }

    fn condition(cond: Cond, lhs: Expr, rhs: Expr, then: Vec<Node>, els: Vec<Node>) -> Node {
        Node::If {
            cond,
            lhs,
            rhs,
            then,
            els,
        }
    }

    fn guard(position: usize, selected: bool, body: Vec<Node>) -> Node {
        if selected {
            condition(Cond::Ne, reg(position), Expr::Const(0), body, Vec::new())
        } else {
            condition(Cond::Ne, reg(position), Expr::Const(0), Vec::new(), body)
        }
    }

    fn ret(value: Expr) -> Node {
        Node::Stmt(Stmt::Ret { value })
    }

    fn increment(amount: u64) -> Node {
        Node::Stmt(Stmt::Store {
            addr: Expr::Const(COUNTER),
            value: Expr::bin(BinOp::Add, load(COUNTER), Expr::Const(amount)),
            width: 8,
        })
    }

    fn call(target: u64) -> Node {
        Node::Stmt(Stmt::Call {
            kind: crate::ir::CallKind::Invoke,
            target: Some(target),
            through: None,
            convention: crate::ir::Convention::SysV,
            args: Some(vec![reg(0), reg(1)]),
            floats_named: true,
            abi: None,
            outputs: crate::ir::fallback_call_outputs(
                crate::ir::Convention::SysV,
                Some(Registers(0)),
            ),
            clobbers: Some(Registers(0)),
            via: None,
        })
    }

    fn template() -> FunctionIr {
        let mut ir = FunctionIr::single_block(Isa::X86_64, Vec::new());
        ir.name = Some("short_circuit_test".to_owned());
        ir.ret_type = CType::U64;
        ir.params = REGISTERS
            .iter()
            .enumerate()
            .map(|(position, index)| Param {
                index: *index,
                name: format!("argument_{position}"),
                ty: CType::U64,
            })
            .collect();
        ir
    }

    fn run(ir: &FunctionIr, row: &Row) -> Outcome {
        let registers: Vec<_> = REGISTERS.into_iter().zip(*row).collect();
        eval::run(
            ir,
            &eval::Setup {
                seed: 0x1234,
                convention: eval::Convention {
                    arguments: &REGISTERS,
                    clobbered: &[],
                },
                registers: &registers,
                memory: &[(COUNTER, 0), (DATA, 17)],
                step_limit: 1000,
            },
        )
    }

    fn compare(nodes: &[Node], rows: &[Row]) -> Vec<Node> {
        let mut after = nodes.to_vec();
        fold_conditions(&mut after);
        let original = lower::lower(&template(), nodes);
        let rewritten = lower::lower(&template(), &after);
        for row in rows {
            let expected = run(&original, row);
            assert!(
                !matches!(expected, Outcome::Unknown(_)),
                "unfinished baseline: {row:?} {expected:?}"
            );
            assert_eq!(
                run(&rewritten, row),
                expected,
                "{row:?}\nbefore={nodes:#?}\nafter={after:#?}"
            );
        }
        after
    }

    fn value(outcome: Outcome) -> u64 {
        let Outcome::Return { value, .. } = outcome else {
            panic!("expected a return: {outcome:?}")
        };
        value
    }

    fn rows() -> Vec<Row> {
        [0, 1, 2, u64::MAX]
            .into_iter()
            .flat_map(|a| {
                [0, 1, 2, u64::MAX]
                    .into_iter()
                    .map(move |b| [a, b, 0, 0, 0, 0])
            })
            .collect()
    }

    fn count_ifs(nodes: &[Node]) -> usize {
        nodes
            .iter()
            .map(|node| match node {
                Node::If { then, els, .. } => 1 + count_ifs(then) + count_ifs(els),
                Node::While { prefix, body, .. } => count_ifs(prefix) + count_ifs(body),
                Node::DoWhile { body, .. } | Node::Forever { body } => count_ifs(body),
                Node::Switch { arms, default, .. } => {
                    arms.iter().map(|(_, body)| count_ifs(body)).sum::<usize>()
                        + default.as_ref().map_or(0, |body| count_ifs(body))
                }
                _ => 0,
            })
            .sum()
    }

    fn reads(expr: &Expr, out: &mut Vec<u16>) {
        match expr {
            Expr::Reg { index, .. } => out.push(*index),
            _ => {
                for child in crate::ir::visit::children(expr) {
                    reads(child, out);
                }
            }
        }
    }

    fn assert_condition_read_order(nodes: &[Node], expected: &[u16]) {
        let Node::If { lhs, rhs, .. } = &nodes[0] else {
            panic!("missing joined condition")
        };
        let mut observed = Vec::new();
        reads(lhs, &mut observed);
        reads(rhs, &mut observed);
        assert_eq!(
            observed, expected,
            "each original predicate must occur once, left first"
        );
    }

    #[test]
    fn exception_entries_prevent_absorbing_a_landing_pad() {
        let branch = |position| Stmt::Brif {
            cond: Cond::Eq,
            lhs: reg(position),
            rhs: Expr::Const(0),
            target: 0x30,
        };
        let Node::Stmt(call) = call(0x5000) else {
            unreachable!()
        };
        let mut ir = template();
        ir.blocks = vec![
            Block {
                start: 0,
                stmts: vec![call, branch(0)],
            },
            Block {
                start: 0x10,
                stmts: vec![branch(1)],
            },
            Block {
                start: 0x20,
                stmts: vec![Stmt::Ret {
                    value: Expr::Const(1),
                }],
            },
            Block {
                start: 0x30,
                stmts: vec![Stmt::Ret {
                    value: Expr::Const(0),
                }],
            },
        ];
        assert!(super::short_circuited(&ir).is_some());
        ir.landing_pads = vec![(0x10, vec![(0, 0x10)])];
        assert!(super::short_circuited(&ir).is_none());
    }

    #[test]
    fn an_external_target_does_not_hide_a_joinable_fallthrough() {
        let mut ir = template();
        ir.blocks = vec![
            Block {
                start: 0,
                stmts: vec![Stmt::Brif {
                    cond: Cond::Eq,
                    lhs: reg(0),
                    rhs: Expr::Const(0),
                    target: 0x1000,
                }],
            },
            Block {
                start: 0x10,
                stmts: vec![Stmt::Brif {
                    cond: Cond::Eq,
                    lhs: reg(1),
                    rhs: Expr::Const(0),
                    target: 0x1000,
                }],
            },
            Block {
                start: 0x20,
                stmts: vec![Stmt::Ret {
                    value: Expr::Const(1),
                }],
            },
        ];
        let after = super::short_circuited(&ir).unwrap();
        assert_eq!(after.blocks.len(), 2);
        assert!(matches!(
            after.blocks[0].stmts.last(),
            Some(Stmt::Brif { target: 0x1000, .. })
        ));
    }

    #[test]
    fn nested_guards_preserve_all_selected_arm_orientations() {
        let rows = rows();
        for first in [false, true] {
            for second in [false, true] {
                let body = vec![call(0x5000), increment(1)];
                let nodes = vec![
                    guard(0, first, vec![guard(1, second, body)]),
                    ret(load(COUNTER)),
                ];
                let after = compare(&nodes, &rows);
                assert_eq!(count_ifs(&after), 1);
                assert_condition_read_order(&after, &REGISTERS[..2]);
                let rewritten = lower::lower(&template(), &after);
                for row in &rows {
                    let holds = (row[0] != 0) == first && (row[1] != 0) == second;
                    let outcome = run(&rewritten, row);
                    let Outcome::Return { value, calls, .. } = outcome else {
                        panic!("{outcome:?}")
                    };
                    assert_eq!(value, u64::from(holds));
                    assert_eq!(calls.len(), usize::from(holds));
                    if holds {
                        assert_eq!(calls[0].target, Some(0x5000));
                        assert_eq!(calls[0].arguments, row[..2]);
                    }
                }
            }
        }
    }

    #[test]
    fn hand_written_cfg_and_both_lowered_node_versions_agree() {
        let body = vec![call(0x5000), increment(1)];
        let nodes = vec![
            guard(0, true, vec![guard(1, true, body.clone())]),
            ret(load(COUNTER)),
        ];
        let after = compare(&nodes, &rows());
        let mut original = template();
        let branch = |position| Stmt::Brif {
            cond: Cond::Eq,
            lhs: reg(position),
            rhs: Expr::Const(0),
            target: 0x30,
        };
        let stmts = body
            .into_iter()
            .map(|node| {
                let Node::Stmt(stmt) = node else {
                    panic!("statement body")
                };
                stmt
            })
            .collect();
        original.blocks = vec![
            Block {
                start: 0,
                stmts: vec![branch(0)],
            },
            Block {
                start: 0x10,
                stmts: vec![branch(1)],
            },
            Block { start: 0x20, stmts },
            Block {
                start: 0x30,
                stmts: vec![Stmt::Ret {
                    value: load(COUNTER),
                }],
            },
        ];
        for row in &rows() {
            let expected = run(&original, row);
            assert!(!matches!(expected, Outcome::Unknown(_)));
            assert_eq!(run(&lower::lower(&template(), &nodes), row), expected);
            assert_eq!(run(&lower::lower(&template(), &after), row), expected);
        }
    }

    #[test]
    fn adjacent_identical_terminals_join_without_reordering() {
        let rows = rows();
        for first in [false, true] {
            for second in [false, true] {
                for terminal in [ret(Expr::Const(7)), ret(load(DATA)), Node::Stmt(Stmt::Trap)] {
                    let nodes = vec![
                        guard(0, first, vec![terminal.clone()]),
                        guard(1, second, vec![terminal]),
                        ret(Expr::Const(0)),
                    ];
                    let after = compare(&nodes, &rows);
                    assert_eq!(count_ifs(&after), 1);
                    assert_condition_read_order(&after, &REGISTERS[..2]);
                    if !matches!(&after[0], Node::If { .. }) {
                        panic!("missing joined terminal")
                    }
                }
            }
        }
    }

    #[test]
    fn common_return_division_stays_in_the_selected_terminal() {
        let returned = Expr::bin(BinOp::DivU, Expr::Const(200), reg(2));
        let nodes = vec![
            guard(0, true, vec![ret(returned.clone())]),
            condition(
                Cond::Hi,
                Expr::bin(BinOp::DivU, Expr::Const(100), reg(1)),
                Expr::Const(10),
                vec![ret(returned.clone())],
                Vec::new(),
            ),
            ret(Expr::Const(0)),
        ];
        let inputs = [
            [0, 20, 0, 0, 0, 0],
            [1, 0, 2, 0, 0, 0],
            [0, 1, 4, 0, 0, 0],
            [0, 20, 2, 0, 0, 0],
        ];
        let after = compare(&nodes, &inputs);
        assert_eq!(count_ifs(&after), 1);
        assert_eq!(after.len(), 2);
        assert_condition_read_order(&after, &REGISTERS[..2]);
        let Node::If { then, els, .. } = &after[0] else {
            panic!("missing joined condition")
        };
        let [Node::Stmt(Stmt::Ret { value: actual })] = then.as_slice() else {
            panic!("the selected body must contain one return")
        };
        assert!(els.is_empty());
        assert_eq!(actual, &returned);
        let mut return_reads = Vec::new();
        reads(actual, &mut return_reads);
        assert_eq!(return_reads, [REGISTERS[2]]);
        let original = lower::lower(&template(), &nodes);
        let rewritten = lower::lower(&template(), &after);
        for (row, expected) in inputs.iter().zip([0, 100, 50, 0]) {
            assert_eq!(value(run(&rewritten, row)), expected);
        }
        for row in [[1, 0, 0, 0, 0, 0], [0, 1, 0, 0, 0, 0], [0, 0, 2, 0, 0, 0]] {
            assert_eq!(run(&original, &row), Outcome::Unknown("division by zero"));
            assert_eq!(run(&rewritten, &row), Outcome::Unknown("division by zero"));
        }
    }

    #[test]
    fn skipped_second_comparison_does_not_divide_by_zero() {
        let divided = Expr::bin(BinOp::DivU, Expr::Const(100), reg(0));
        let inner = condition(
            Cond::Hi,
            divided.clone(),
            Expr::Const(10),
            vec![increment(1)],
            Vec::new(),
        );
        let and = vec![guard(0, true, vec![inner]), ret(load(COUNTER))];
        let rows = [0, 1, 2, 10, 11, u64::MAX].map(|value| [value, 0, 0, 0, 0, 0]);
        let after = compare(&and, &rows);
        assert_eq!(count_ifs(&after), 1);
        for row in &rows {
            let expected = u64::from(row[0] != 0 && 100 / row[0] > 10);
            assert_eq!(
                value(run(&lower::lower(&template(), &after), row)),
                expected
            );
        }
        let or = vec![
            guard(0, false, vec![ret(Expr::Const(7))]),
            condition(
                Cond::Hi,
                divided.clone(),
                Expr::Const(10),
                vec![ret(Expr::Const(7))],
                Vec::new(),
            ),
            ret(Expr::Const(0)),
        ];
        let after = compare(&or, &rows);
        assert_eq!(count_ifs(&after), 1);
        let unguarded = lower::lower(&template(), &[ret(divided)]);
        assert_eq!(
            run(&unguarded, &rows[0]),
            Outcome::Unknown("division by zero")
        );
    }

    #[test]
    fn comparison_chains_preserve_order_and_the_existing_limit() {
        for length in [3, 4, 5] {
            let mut body = vec![increment(1)];
            for position in (0..length).rev() {
                body = vec![guard(position, true, body)];
            }
            body.push(ret(load(COUNTER)));
            let mut inputs = vec![[1; 6]];
            for position in 0..length {
                let mut row = [1; 6];
                row[position] = 0;
                inputs.push(row);
            }
            let after = compare(&body, &inputs);
            assert_eq!(count_ifs(&after), if length <= 4 { 1 } else { 2 });
        }
    }

    #[test]
    fn intervening_statements_and_entry_labels_block_the_local_fold() {
        let barriers = [
            Node::Stmt(Stmt::Assign {
                dest: RegRef {
                    index: REGISTERS[2],
                    width: 64,
                },
                value: Expr::Const(9),
            }),
            Node::Stmt(Stmt::Store {
                addr: Expr::Const(DATA),
                value: reg(0),
                width: 8,
            }),
            call(0x6000),
            Node::Label(0x7000),
        ];
        for barrier in barriers {
            let nodes = vec![
                guard(0, true, vec![barrier, guard(1, true, vec![increment(1)])]),
                ret(load(COUNTER)),
            ];
            let after = compare(&nodes, &rows());
            assert_eq!(format!("{after:?}"), format!("{nodes:?}"));
        }
        let nodes = vec![
            guard(
                2,
                true,
                vec![Node::Stmt(Stmt::Br {
                    target: Some(0x7000),
                })],
            ),
            guard(
                0,
                true,
                vec![Node::Label(0x7000), guard(1, true, vec![increment(1)])],
            ),
            ret(load(COUNTER)),
        ];
        let after = compare(&nodes, &[[0, 1, 1, 0, 0, 0], [1, 1, 0, 0, 0, 0]]);
        assert_eq!(count_ifs(&after), 3);
    }

    #[test]
    fn separate_effects_nonempty_else_and_different_terminals_stay_distinct() {
        let sequential = vec![
            guard(0, true, vec![increment(1)]),
            guard(1, true, vec![increment(1)]),
            ret(load(COUNTER)),
        ];
        let after = compare(&sequential, &rows());
        assert_eq!(count_ifs(&after), 2);
        assert_eq!(
            value(run(&lower::lower(&template(), &after), &[1, 1, 0, 0, 0, 0])),
            2
        );
        for nodes in [
            vec![
                condition(
                    Cond::Ne,
                    reg(0),
                    Expr::Const(0),
                    vec![condition(
                        Cond::Ne,
                        reg(1),
                        Expr::Const(0),
                        vec![increment(1)],
                        vec![increment(2)],
                    )],
                    vec![increment(4)],
                ),
                ret(load(COUNTER)),
            ],
            vec![
                guard(0, true, vec![ret(Expr::Const(1))]),
                guard(1, true, vec![ret(Expr::Const(2))]),
                ret(Expr::Const(0)),
            ],
            vec![
                guard(0, true, vec![increment(1), ret(Expr::Const(7))]),
                guard(1, true, vec![increment(1), ret(Expr::Const(7))]),
                ret(Expr::Const(0)),
            ],
        ] {
            let after = compare(&nodes, &rows());
            assert_eq!(format!("{after:?}"), format!("{nodes:?}"));
        }
    }

    #[test]
    fn composed_and_or_shapes_keep_their_distinct_truth_tables() {
        let selected = || vec![ret(Expr::Const(7))];
        let left = vec![
            guard(0, true, vec![guard(1, true, selected())]),
            guard(2, true, selected()),
            ret(Expr::Const(0)),
        ];
        let right = vec![
            guard(
                0,
                true,
                vec![guard(1, true, selected()), guard(2, true, selected())],
            ),
            ret(Expr::Const(0)),
        ];
        let rows: Vec<_> = (0..8)
            .map(|bits| [bits & 1, bits >> 1 & 1, bits >> 2 & 1, 0, 0, 0])
            .collect();
        for (nodes, first_shape) in [(&left, true), (&right, false)] {
            let after = compare(nodes, &rows);
            assert_eq!(count_ifs(&after), 1);
            assert_condition_read_order(&after, &REGISTERS[..3]);
            for row in &rows {
                let (a, b, c) = (row[0] != 0, row[1] != 0, row[2] != 0);
                let expected = if first_shape {
                    (a && b) || c
                } else {
                    a && (b || c)
                };
                assert_eq!(
                    value(run(&lower::lower(&template(), &after), row)),
                    if expected { 7 } else { 0 }
                );
            }
        }
    }

    #[test]
    fn loop_continue_and_switch_break_keep_their_enclosing_targets() {
        let loop_nodes = vec![
            Node::Stmt(Stmt::Assign {
                dest: RegRef {
                    index: REGISTERS[3],
                    width: 64,
                },
                value: Expr::Const(0),
            }),
            Node::While {
                prefix: Vec::new(),
                cond: Cond::Cc,
                lhs: reg(3),
                rhs: Expr::Const(3),
                body: vec![
                    Node::Stmt(Stmt::Assign {
                        dest: RegRef {
                            index: REGISTERS[3],
                            width: 64,
                        },
                        value: Expr::bin(BinOp::Add, reg(3), Expr::Const(1)),
                    }),
                    guard(0, true, vec![Node::Continue]),
                    guard(1, true, vec![Node::Continue]),
                    increment(1),
                    Node::Break,
                ],
            },
            ret(load(COUNTER)),
        ];
        let after = compare(&loop_nodes, &rows());
        assert_eq!(count_ifs(&after), 1);
        for selector in [0, 1, 2] {
            let nodes = vec![
                Node::Switch {
                    index: reg(2),
                    arms: vec![(
                        vec![0],
                        vec![
                            guard(0, true, vec![Node::Break]),
                            guard(1, true, vec![Node::Break]),
                            increment(1),
                            Node::Break,
                        ],
                    )],
                    default: Some(vec![increment(2), Node::Break]),
                },
                ret(load(COUNTER)),
            ];
            let inputs: Vec<_> = rows()
                .into_iter()
                .map(|mut row| {
                    row[2] = selector;
                    row
                })
                .collect();
            let after = compare(&nodes, &inputs);
            assert_eq!(count_ifs(&after), 1);
        }
    }

    #[test]
    fn negated_float_truth_preserves_nan_and_infinity() {
        let less = Expr::Apply {
            op: Operation::FloatLess(Precision::Double),
            args: vec![reg(0), reg(1)],
        };
        let bits = [
            f64::NEG_INFINITY.to_bits(),
            (-1.0_f64).to_bits(),
            (-0.0_f64).to_bits(),
            0.0_f64.to_bits(),
            1.0_f64.to_bits(),
            f64::INFINITY.to_bits(),
            0x7ff8_0000_0000_0042,
        ];
        let mut inputs = Vec::new();
        for left in bits {
            for right in bits {
                for gate in [0, 2] {
                    inputs.push([left, right, gate, 0, 0, 0]);
                }
            }
        }
        for selected_true in [false, true] {
            let body = vec![guard(2, true, vec![increment(1)])];
            let first = if selected_true {
                condition(Cond::Eq, less.clone(), Expr::Const(0), body, Vec::new())
            } else {
                condition(Cond::Ne, less.clone(), Expr::Const(0), Vec::new(), body)
            };
            let nodes = vec![first, ret(load(COUNTER))];
            let after = compare(&nodes, &inputs);
            assert_eq!(count_ifs(&after), 1);
            for row in &inputs {
                let expected = u64::from(
                    f64::from_bits(row[0]).partial_cmp(&f64::from_bits(row[1]))
                        != Some(std::cmp::Ordering::Less)
                        && row[2] != 0,
                );
                assert_eq!(
                    value(run(&lower::lower(&template(), &after), row)),
                    expected
                );
            }
        }
    }

    #[test]
    fn false_selected_unordered_comparison_skips_the_faulting_or_arm() {
        let less = Expr::Apply {
            op: Operation::FloatLess(Precision::Double),
            args: vec![reg(0), reg(1)],
        };
        let divided = Expr::bin(BinOp::DivU, Expr::Const(100), reg(3));
        let nodes = vec![
            condition(
                Cond::Ne,
                less,
                Expr::Const(0),
                Vec::new(),
                vec![ret(Expr::Const(7))],
            ),
            condition(
                Cond::Hi,
                divided,
                Expr::Const(10),
                vec![ret(Expr::Const(7))],
                Vec::new(),
            ),
            ret(Expr::Const(0)),
        ];
        let rows = [
            [0x7ff8_0000_0000_0042, 1.0_f64.to_bits(), 0, 0, 0, 0],
            [f64::INFINITY.to_bits(), 1.0_f64.to_bits(), 0, 0, 0, 0],
            [1.0_f64.to_bits(), 2.0_f64.to_bits(), 0, 1, 0, 0],
            [1.0_f64.to_bits(), 2.0_f64.to_bits(), 0, 20, 0, 0],
        ];
        let after = compare(&nodes, &rows);
        assert_eq!(count_ifs(&after), 1);
        for (row, expected) in rows.iter().zip([7, 7, 7, 0]) {
            assert_eq!(
                value(run(&lower::lower(&template(), &after), row)),
                expected
            );
        }
    }

    #[test]
    fn real_optimized_fixtures_use_logical_operators_without_a_goto_requirement() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/metrics");
        for architecture in ["x86_64", "aarch64"] {
            let short_guard = if architecture == "aarch64" {
                "p == 0 || n < 1"
            } else {
                "p == 0 || n <= 0"
            };
            for (fixture, function, joined_guard) in [
                (
                    "memory",
                    "copy_bytes",
                    "n >= 8 && (uintptr_t)dst - (uintptr_t)src >= 32",
                ),
                ("control", "short_circuit", short_guard),
            ] {
                let path = root.join(format!("{fixture}.{architecture}.O2.debug.elf"));
                let mut binary = crate::service::Binary::open(&path).unwrap();
                let address = binary.find(function).unwrap().addr;
                let code = binary.decompile(address, None, None).unwrap();
                assert!(
                    code.contains(joined_guard),
                    "{} {function}: {code}",
                    path.display()
                );
            }
        }
    }
}

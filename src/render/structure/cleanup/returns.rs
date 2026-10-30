use super::{children, children_mut, terminates, writes_in};
use crate::ir::Stmt;
use crate::render::structure::Node;
use std::collections::HashMap;

/// The most statements a copied return tail runs before it returns.
const TAIL_STATEMENTS: usize = 6;

/// The most lines the copies of one return tail may add in all.
pub(super) const TAIL_LINES: usize = 8;

pub(crate) fn flatten_early_returns(nodes: &mut Vec<Node>) {
    for node in nodes.iter_mut() {
        for child in children_mut(node) {
            flatten_early_returns(child);
        }
    }

    let mut flattened = Vec::with_capacity(nodes.len());
    for node in nodes.drain(..) {
        match node {
            Node::If {
                at,
                cond,
                lhs,
                rhs,
                then,
                els,
                ..
            } if !els.is_empty() && terminates(&then) => {
                flattened.push(Node::If {
                    cond,
                    lhs,
                    rhs,
                    then,
                    els: Vec::new(),
                    at,
                });
                flattened.extend(els);
            }
            other => flattened.push(other),
        }
    }
    *nodes = flattened;
}

/// Replaces each jump to a label that only runs a few statements before
/// returning, or before trapping after a call that does not return, with
/// those statements, while that adds no more than a few lines in all. A
/// tail that reads as one line, as `return f(x);` does, is copied to every
/// jump: the copy takes no more room than the goto.
pub(crate) fn inline_return_tails(nodes: &mut Vec<Node>) {
    fn jumps(nodes: &[Node], counts: &mut HashMap<u64, usize>) {
        for node in nodes {
            if let Node::Stmt(
                Stmt::Br {
                    target: Some(target),
                    ..
                }
                | Stmt::Brif { target, .. },
            ) = node
            {
                *counts.entry(*target).or_default() += 1;
            }
            for child in children(node) {
                jumps(child, counts);
            }
        }
    }
    fn bounded(nodes: &[Node], remaining: &mut usize, known: &HashMap<u64, Vec<Node>>) -> bool {
        fn cleanup(nodes: &[Node]) -> bool {
            nodes.iter().any(|node| match node {
                Node::Stmt(Stmt::Store { .. } | Stmt::Call { .. }) => true,
                Node::If { then, els, .. } => cleanup(then) || cleanup(els),
                _ => false,
            })
        }
        for node in nodes {
            if let Node::Stmt(Stmt::Br {
                target: Some(target),
                ..
            }) = node
            {
                let Some(tail) = known.get(target) else {
                    return false;
                };
                if !cleanup(tail) || !bounded(tail, remaining, known) {
                    return false;
                }
                continue;
            }
            let Some(left) = remaining.checked_sub(1) else {
                return false;
            };
            *remaining = left;
            match node {
                Node::Stmt(
                    Stmt::Assign { .. }
                    | Stmt::Store { .. }
                    | Stmt::Call { .. }
                    | Stmt::Unsupported { .. }
                    | Stmt::Ret { .. }
                    | Stmt::Trap { .. },
                ) => {}
                Node::Stmt(Stmt::Brif { target, .. }) => {
                    let Some(tail) = known.get(target) else {
                        return false;
                    };
                    if !cleanup(tail) || !bounded(tail, remaining, known) {
                        return false;
                    }
                }
                Node::If { then, els, .. } => {
                    if !bounded(then, remaining, known) || !bounded(els, remaining, known) {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        true
    }
    fn collect(
        nodes: &[Node],
        following: &[&Node],
        known: &HashMap<u64, Vec<Node>>,
        tails: &mut HashMap<u64, Vec<Node>>,
    ) {
        for index in 0..nodes.len() {
            if let Node::Label(label) = nodes[index]
                && !known.contains_key(&label)
            {
                let mut tail = Vec::new();
                let mut remaining = TAIL_STATEMENTS + 1;
                let following_nodes = nodes[index + 1..].iter().chain(following.iter().copied());
                for next in following_nodes {
                    if matches!(next, Node::Label(_)) {
                        continue;
                    }
                    if !bounded(std::slice::from_ref(next), &mut remaining, known) {
                        break;
                    }
                    let mut expanded = vec![next.clone()];
                    replace(&mut expanded, known);
                    tail.extend(expanded);
                    if super::ends(&tail, false) {
                        tails.insert(label, tail);
                        break;
                    }
                }
            }
            if let Node::If { then, els, .. } = &nodes[index] {
                // Either arm falls through to the enclosing sequence. Keep
                // only as much of that sequence as a bounded tail can use.
                let continuation: Vec<&Node> = nodes[index + 1..]
                    .iter()
                    .chain(following.iter().copied())
                    .filter(|node| !matches!(node, Node::Label(_)))
                    .take(TAIL_STATEMENTS + 1)
                    .collect();
                collect(then, &continuation, known, tails);
                collect(els, &continuation, known, tails);
            } else {
                // Loop bodies repeat and switch cases may fall into another
                // case, so neither inherits the enclosing continuation.
                for child in children(&nodes[index]) {
                    collect(child, &[], known, tails);
                }
            }
        }
    }
    fn replace(nodes: &mut Vec<Node>, tails: &HashMap<u64, Vec<Node>>) {
        let mut index = 0;
        while index < nodes.len() {
            if let Node::Stmt(Stmt::Brif {
                cond,
                lhs,
                rhs,
                target,
                at,
            }) = &nodes[index]
                && let Some(tail) = tails.get(target)
            {
                nodes[index] = Node::If {
                    cond: *cond,
                    lhs: lhs.clone(),
                    rhs: rhs.clone(),
                    then: tail.clone(),
                    els: Vec::new(),
                    at: *at,
                };
                index += 1;
                continue;
            }
            if let Node::Stmt(Stmt::Br {
                target: Some(target),
                ..
            }) = &nodes[index]
                && let Some(tail) = tails.get(target)
            {
                let tail = tail.clone();
                let length = tail.len();
                nodes.splice(index..=index, tail);
                index += length;
                continue;
            }
            for child in children_mut(&mut nodes[index]) {
                replace(child, tails);
            }
            index += 1;
        }
    }
    let mut tails = HashMap::new();
    // A cleanup may jump to another short cleanup before returning or
    // resuming unwinding. Only expand tails already known to terminate;
    // cycles stay as branches, and the expanded body keeps the same bound.
    for _ in 0..=TAIL_STATEMENTS {
        let mut found = HashMap::new();
        collect(nodes, &[], &tails, &mut found);
        if found.is_empty() {
            break;
        }
        tails.extend(found);
    }
    let mut counts = HashMap::new();
    jumps(nodes, &mut counts);
    tails.retain(|label, tail| {
        let added = added_lines(tail);
        added.saturating_mul(counts.get(label).copied().unwrap_or(0)) <= TAIL_LINES
    });
    if !tails.is_empty() {
        replace(nodes, &tails);
    }
}

/// How many more lines a copy of `tail` takes than the goto it replaces:
/// one per statement before the last, but a return of what a call just
/// returned prints with the call.
fn added_lines(tail: &[Node]) -> usize {
    let fused = matches!(
        tail,
        [
            ..,
            Node::Stmt(Stmt::Call { .. }),
            Node::Stmt(Stmt::Ret { .. })
        ]
    );
    let lines: usize = tail
        .iter()
        .map(|node| match node {
            Node::If { then, els, .. } => {
                2 + added_lines(then)
                    + usize::from(!then.is_empty())
                    + if els.is_empty() {
                        0
                    } else {
                        1 + added_lines(els) + 1
                    }
            }
            _ => 1,
        })
        .sum();
    lines.saturating_sub(1 + usize::from(fused))
}

/// Returns the constant a variable holds on each path to a return, where
/// the path set it last, and drops assignments nothing reads any more.
pub(crate) fn return_known_constants(nodes: &mut Vec<Node>) {
    use crate::ir::Expr;
    type Known = std::collections::HashMap<u16, u64>;
    fn walk(nodes: &mut [Node], known: &mut Known) {
        for node in nodes.iter_mut() {
            // A jump into a nested body can bypass the assignments before it.
            if super::super::label_count(std::slice::from_ref(node)) != 0 {
                known.clear();
            }
            match node {
                Node::Stmt(Stmt::Ret { value, .. }) => {
                    let replaced = match value {
                        Expr::Reg { index, .. } => known.get(index).map(|c| Expr::Const(*c)),
                        Expr::Bin {
                            op: crate::ir::BinOp::And,
                            lhs,
                            rhs,
                        } => match (lhs.as_ref(), rhs.as_ref()) {
                            (Expr::Reg { index, .. }, Expr::Const(mask)) => {
                                known.get(index).map(|c| Expr::Const(c & mask))
                            }
                            _ => None,
                        },
                        _ => None,
                    };
                    if let Some(replaced) = replaced {
                        *value = replaced;
                    }
                }
                Node::Stmt(stmt) => {
                    for written in crate::ir::visit::statement_registers(stmt).0 {
                        known.remove(&written);
                    }
                    if let Stmt::Assign {
                        dest,
                        value: Expr::Const(c),
                        ..
                    } = stmt
                        && dest.index >= crate::ir::VARIABLE_BASE
                        && dest.width == 64
                    {
                        known.insert(dest.index, *c);
                    }
                }
                Node::If { then, els, .. } => {
                    let mut written = std::collections::HashSet::new();
                    writes_in(then, &mut written);
                    writes_in(els, &mut written);
                    walk(then, &mut known.clone());
                    walk(els, &mut known.clone());
                    known.retain(|variable, _| !written.contains(variable));
                }
                // A loop's body may run after its own later writes; a
                // label may be entered from anywhere.
                other => {
                    let mut written = std::collections::HashSet::new();
                    writes_in(std::slice::from_ref(other), &mut written);
                    for child in children_mut(other) {
                        walk(child, &mut Known::new());
                    }
                    if matches!(other, Node::Label(_)) {
                        known.clear();
                    }
                    known.retain(|variable, _| !written.contains(variable));
                }
            }
        }
    }
    walk(nodes, &mut Known::new());
    // Assignments to variables nothing reads now go.
    let mut read = std::collections::HashSet::new();
    reads_in(nodes, &mut read);
    drop_unread(nodes, &read);
}

/// The registers the nodes read, at any depth.
fn reads_in(nodes: &[Node], out: &mut std::collections::HashSet<u16>) {
    for node in nodes {
        match node {
            Node::Stmt(stmt) => out.extend(crate::ir::visit::statement_registers(stmt).1),
            Node::If {
                lhs,
                rhs,
                then,
                els,
                ..
            } => {
                crate::ir::visit::collect_reads(lhs, out);
                crate::ir::visit::collect_reads(rhs, out);
                reads_in(then, out);
                reads_in(els, out);
            }
            Node::DoWhile { lhs, rhs, body, .. } => {
                crate::ir::visit::collect_reads(lhs, out);
                crate::ir::visit::collect_reads(rhs, out);
                reads_in(body, out);
            }
            Node::While {
                prefix,
                lhs,
                rhs,
                body,
                ..
            } => {
                crate::ir::visit::collect_reads(lhs, out);
                crate::ir::visit::collect_reads(rhs, out);
                reads_in(prefix, out);
                reads_in(body, out);
            }
            Node::Forever { body } => reads_in(body, out),
            Node::Switch {
                index,
                arms,
                default,
                ..
            } => {
                crate::ir::visit::collect_reads(index, out);
                for (_, body) in arms {
                    reads_in(body, out);
                }
                if let Some(body) = default {
                    reads_in(body, out);
                }
            }
            Node::Label(_) | Node::Break { .. } | Node::Continue { .. } => {}
        }
    }
}

/// Drops the assignments of constants to variables `read` does not hold,
/// and those right before a return that does not read them.
fn drop_unread(nodes: &mut Vec<Node>, read: &std::collections::HashSet<u16>) {
    nodes.retain(|node| {
        !matches!(node, Node::Stmt(Stmt::Assign { dest, value: crate::ir::Expr::Const(_), .. })
            if dest.index >= crate::ir::VARIABLE_BASE && !read.contains(&dest.index))
    });
    let mut index = 0;
    while index + 1 < nodes.len() {
        if let (
            Node::Stmt(Stmt::Assign {
                dest,
                value: crate::ir::Expr::Const(_),
                ..
            }),
            Node::Stmt(ret @ Stmt::Ret { .. }),
        ) = (&nodes[index], &nodes[index + 1])
            && dest.index >= crate::ir::VARIABLE_BASE
            && !crate::ir::visit::statement_registers(ret)
                .1
                .contains(&dest.index)
        {
            nodes.remove(index);
            continue;
        }
        index += 1;
    }
    for node in nodes.iter_mut() {
        for child in children_mut(node) {
            drop_unread(child, read);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BinOp, Cond, Expr, FunctionIr};
    use crate::loader::Isa;
    use crate::render::structure::lower;

    fn guard(then: Vec<Node>, els: Vec<Node>) -> Node {
        Node::If {
            cond: Cond::Eq,
            lhs: Expr::reg(0, 64),
            rhs: Expr::Const(0),
            then,
            els,
            at: None,
        }
    }

    fn increment() -> Node {
        Node::Stmt(Stmt::Store {
            addr: Expr::reg(1, 64),
            value: Expr::bin(
                BinOp::Add,
                Expr::Load {
                    addr: Box::new(Expr::reg(1, 64)),
                    width: 8,
                    signed: false,
                },
                Expr::Const(1),
            ),
            width: 8,
            at: None,
        })
    }

    #[test]
    fn return_continuations_preserve_values_and_memory_smt() {
        use crate::ir::smt::Proofs;

        let available = Proofs::available();
        let mut proofs = Proofs::default();
        for isa in [Isa::I386, Isa::X86_64, Isa::AArch64, Isa::Arm32] {
            for depth in 1..=3 {
                for in_else in [false, true] {
                    let mut body = vec![Node::Label(10), increment()];
                    for _ in 0..depth {
                        body = if in_else {
                            vec![guard(vec![increment()], body)]
                        } else {
                            vec![guard(body, vec![increment()])]
                        };
                    }
                    let mut before = vec![guard(
                        vec![Node::Stmt(Stmt::Br {
                            target: Some(10),
                            at: None,
                        })],
                        Vec::new(),
                    )];
                    before.extend(body);
                    before.push(increment());
                    before.push(Node::Stmt(Stmt::Ret {
                        value: Expr::Load {
                            addr: Box::new(Expr::reg(1, 64)),
                            width: 8,
                            signed: false,
                        },
                        at: None,
                    }));
                    let mut after = before.clone();
                    inline_return_tails(&mut after);
                    assert!(matches!(&after[0], Node::If { then, .. }
                        if matches!(then.as_slice(), [Node::Stmt(Stmt::Store { .. }),
                            Node::Stmt(Stmt::Store { .. }), Node::Stmt(Stmt::Ret { .. })])));
                    if available {
                        let ir = FunctionIr::single_block(isa, Vec::new());
                        proofs.function(
                            format!("return continuation {isa:?} depth {depth} else {in_else}"),
                            &lower::lower(&ir, &before),
                            &lower::lower(&ir, &after),
                        );
                    }
                }
            }
        }
        if available {
            proofs.check();
        }
    }

    #[test]
    fn return_continuations_stop_at_loops_and_switch_cases() {
        let body = vec![Node::Label(10), increment()];
        for construct in [
            Node::Forever { body: body.clone() },
            Node::DoWhile {
                cond: Cond::Eq,
                lhs: Expr::reg(0, 64),
                rhs: Expr::Const(0),
                body: body.clone(),
                at: None,
            },
            Node::While {
                prefix: Vec::new(),
                cond: Cond::Eq,
                lhs: Expr::reg(0, 64),
                rhs: Expr::Const(0),
                body: body.clone(),
                at: None,
            },
            Node::Switch {
                index: Expr::reg(0, 64),
                arms: vec![(vec![0], body)],
                default: Some(vec![increment()]),
                at: None,
            },
        ] {
            let mut nodes = vec![
                Node::Stmt(Stmt::Br {
                    target: Some(10),
                    at: None,
                }),
                construct,
                Node::Stmt(Stmt::Ret {
                    value: Expr::Const(0),
                    at: None,
                }),
            ];
            inline_return_tails(&mut nodes);
            assert!(matches!(nodes[0], Node::Stmt(Stmt::Br { .. })));
        }
    }

    #[test]
    fn return_continuations_keep_the_total_copy_bound() {
        let tail = vec![Node::Label(10), increment()];
        let mut nodes = vec![
            Node::Stmt(Stmt::Br {
                target: Some(10),
                at: None,
            }),
            guard(tail, Vec::new()),
        ];
        nodes.extend(std::iter::repeat_with(increment).take(TAIL_STATEMENTS));
        nodes.push(Node::Stmt(Stmt::Ret {
            value: Expr::Const(0),
            at: None,
        }));
        inline_return_tails(&mut nodes);
        assert!(matches!(nodes[0], Node::Stmt(Stmt::Br { .. })));
    }

    #[test]
    fn cleanup_chains_preserve_values_and_memory_smt() {
        use crate::ir::smt::Proofs;

        let available = Proofs::available();
        let mut proofs = Proofs::default();
        for isa in [Isa::I386, Isa::X86_64, Isa::AArch64, Isa::Arm32] {
            for conditional in [false, true] {
                let jump = Node::Stmt(Stmt::Br {
                    target: Some(20),
                    at: None,
                });
                let mut before = vec![
                    guard(
                        vec![Node::Stmt(Stmt::Br {
                            target: Some(10),
                            at: None,
                        })],
                        Vec::new(),
                    ),
                    Node::Label(20),
                    increment(),
                    Node::Stmt(Stmt::Ret {
                        value: Expr::Load {
                            addr: Box::new(Expr::reg(1, 64)),
                            width: 8,
                            signed: false,
                        },
                        at: None,
                    }),
                    Node::Label(10),
                    increment(),
                ];
                if conditional {
                    before.push(guard(vec![jump.clone()], vec![increment()]));
                }
                before.push(jump);
                let mut after = before.clone();
                inline_return_tails(&mut after);
                let Node::If { then, .. } = &after[0] else {
                    panic!("the entry remains conditional");
                };
                assert!(super::super::ends(then, false), "{after:#?}");
                assert!(!format!("{then:?}").contains("Br {"), "{after:#?}");
                if available {
                    let ir = FunctionIr::single_block(isa, Vec::new());
                    proofs.function(
                        format!("cleanup chain {isa:?} conditional {conditional}"),
                        &lower::lower(&ir, &before),
                        &lower::lower(&ir, &after),
                    );
                }
            }
        }
        if available {
            proofs.check();
        }
    }

    #[test]
    fn cleanup_chains_keep_cycles_and_oversized_expansions() {
        let branch = |target| {
            Node::Stmt(Stmt::Br {
                target: Some(target),
                at: None,
            })
        };
        let mut cycle = vec![branch(10), Node::Label(10), increment(), branch(10)];
        let original = format!("{cycle:?}");
        inline_return_tails(&mut cycle);
        assert_eq!(format!("{cycle:?}"), original);

        let mut nodes = vec![branch(10), Node::Label(20)];
        nodes.extend(std::iter::repeat_with(increment).take(TAIL_STATEMENTS));
        nodes.extend([
            Node::Stmt(Stmt::Ret {
                value: Expr::Const(0),
                at: None,
            }),
            Node::Label(10),
            increment(),
            branch(20),
        ]);
        inline_return_tails(&mut nodes);
        assert!(matches!(
            nodes[0],
            Node::Stmt(Stmt::Br {
                target: Some(10),
                ..
            })
        ));

        let mut scalar = vec![
            branch(10),
            Node::Label(20),
            Node::Stmt(Stmt::Ret {
                value: Expr::Const(0),
                at: None,
            }),
            Node::Label(10),
            Node::Stmt(Stmt::Assign {
                dest: crate::ir::RegRef {
                    index: 0,
                    width: 64,
                },
                value: Expr::Const(0),
                at: None,
            }),
            branch(20),
        ];
        inline_return_tails(&mut scalar);
        assert!(matches!(
            scalar[0],
            Node::Stmt(Stmt::Br {
                target: Some(10),
                ..
            })
        ));
    }

    #[test]
    fn partial_forward_exits_preserve_values_and_memory_smt() {
        use crate::ir::smt::Proofs;

        let available = Proofs::available();
        let mut proofs = Proofs::default();
        for isa in [Isa::I386, Isa::X86_64, Isa::AArch64, Isa::Arm32] {
            for depth in 1..=3 {
                for in_else in [false, true] {
                    let mut branch = vec![
                        increment(),
                        Node::Stmt(Stmt::Br {
                            target: Some(40),
                            at: None,
                        }),
                    ];
                    for bit in 0..depth {
                        let (then, els) = if in_else {
                            (Vec::new(), branch)
                        } else {
                            (branch, Vec::new())
                        };
                        branch = vec![Node::If {
                            cond: Cond::Eq,
                            lhs: Expr::bin(BinOp::And, Expr::reg(0, 64), Expr::Const(1 << bit)),
                            rhs: Expr::Const(0),
                            then,
                            els,
                            at: None,
                        }];
                    }
                    let mut before = branch;
                    before.extend([
                        increment(),
                        Node::Label(40),
                        increment(),
                        Node::Stmt(Stmt::Ret {
                            value: Expr::Load {
                                addr: Box::new(Expr::reg(1, 64)),
                                width: 8,
                                signed: false,
                            },
                            at: None,
                        }),
                    ]);
                    let mut after = before.clone();
                    super::super::fold_forward_exits(&mut after);
                    assert!(!format!("{after:?}").contains("Br {"), "{after:#?}");
                    if available {
                        let ir = FunctionIr::single_block(isa, Vec::new());
                        proofs.function(
                            format!("partial forward exit {isa:?} depth {depth} else {in_else}"),
                            &lower::lower(&ir, &before),
                            &lower::lower(&ir, &after),
                        );
                    }
                }
            }
        }
        if available {
            proofs.check();
        }
    }

    #[test]
    fn partial_forward_exits_keep_labels_and_the_copy_bound() {
        let branch = || {
            guard(
                vec![guard(
                    vec![Node::Stmt(Stmt::Br {
                        target: Some(40),
                        at: None,
                    })],
                    Vec::new(),
                )],
                Vec::new(),
            )
        };
        for skipped in [
            vec![Node::Label(20), increment()],
            std::iter::repeat_with(increment).take(4).collect(),
        ] {
            let mut nodes = vec![branch()];
            nodes.extend(skipped);
            nodes.push(Node::Label(40));
            let original = format!("{nodes:?}");
            super::super::fold_forward_exits(&mut nodes);
            assert_eq!(format!("{nodes:?}"), original);
        }
        let mut fallthrough = vec![increment()];
        for _ in 0..4 {
            fallthrough = vec![guard(fallthrough.clone(), fallthrough)];
        }
        let mut nodes = vec![
            guard(vec![branch()], fallthrough),
            increment(),
            Node::Label(40),
        ];
        let original = format!("{nodes:?}");
        super::super::fold_forward_exits(&mut nodes);
        assert_eq!(format!("{nodes:?}"), original);
    }

    #[test]
    fn printed_return_continuations_execute_the_shared_stores_once() {
        use crate::ir::{CType, Param};
        use std::fs;
        use std::process::Command;

        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("return-continuations-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let mut source = String::from(
            "#include <stdint.h>\n#include <setjmp.h>\n\
             static jmp_buf resume_target;\n\
             static uint64_t trace_cell;\n\
             void record_cleanup(uint64_t *cell, uint64_t value) { *cell = *cell * 17 + value; }\n\
             void _Unwind_Resume(void *value) { (void)value; longjmp(resume_target, 1); }\n",
        );
        for (index, isa) in [Isa::I386, Isa::X86_64, Isa::AArch64, Isa::Arm32]
            .into_iter()
            .enumerate()
        {
            let mut ir = FunctionIr::single_block(isa, Vec::new());
            ir.name = Some(format!("continuation_{index}"));
            ir.params = vec![
                Param {
                    index: 0,
                    name: "flag".to_owned(),
                    ty: CType::U64,
                },
                Param {
                    index: 1,
                    name: "cell".to_owned(),
                    ty: CType::pointer_to(CType::U64),
                },
            ];
            let mut nodes = vec![
                guard(
                    vec![Node::Stmt(Stmt::Br {
                        target: Some(10),
                        at: None,
                    })],
                    Vec::new(),
                ),
                guard(vec![Node::Label(10), increment()], vec![increment()]),
                increment(),
                Node::Stmt(Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(Expr::reg(1, 64)),
                        width: 8,
                        signed: false,
                    },
                    at: None,
                }),
            ];
            inline_return_tails(&mut nodes);
            let code =
                crate::render::render(&lower::lower(&ir, &nodes), &[], &Default::default(), &[]);
            assert!(!code.contains("goto "), "{isa}: {code}");
            source.push_str(&code);
            ir.name = Some(format!("unwind_cleanup_{index}"));
            let call = |target, args| {
                Node::Stmt(Stmt::Call {
                    kind: crate::ir::CallKind::Invoke,
                    target: Some(target),
                    through: None,
                    convention: ir.convention,
                    args: Some(args),
                    floats_named: true,
                    abi: None,
                    outputs: Vec::new(),
                    clobbers: Some(Default::default()),
                    via: None,
                    at: None,
                })
            };
            let mut unwind = vec![
                guard(
                    vec![Node::Stmt(Stmt::Br {
                        target: Some(10),
                        at: None,
                    })],
                    Vec::new(),
                ),
                Node::Label(20),
                call(0x1000, vec![Expr::reg(1, 64), Expr::Const(2)]),
                call(0x2000, vec![Expr::reg(1, 64)]),
                Node::Stmt(Stmt::Trap { at: None }),
                Node::Label(10),
                call(0x1000, vec![Expr::reg(1, 64), Expr::Const(1)]),
                Node::Stmt(Stmt::Br {
                    target: Some(20),
                    at: None,
                }),
            ];
            inline_return_tails(&mut unwind);
            let symbols = crate::render::Symbols {
                functions: [
                    (0x1000, "record_cleanup".into()),
                    (0x2000, "_Unwind_Resume".into()),
                ]
                .into(),
                function_returns: [(0x1000, CType::Void), (0x2000, CType::Void)].into(),
                function_parameters: [
                    (0x1000, vec![CType::pointer_to(CType::U64), CType::U64]),
                    (0x2000, vec![CType::pointer_to(CType::Void)]),
                ]
                .into(),
                ..Default::default()
            };
            let code = crate::render::render(&lower::lower(&ir, &unwind), &[], &symbols, &[]);
            assert!(!code.contains("goto "), "{isa}: {code}");
            assert!(code.contains("_Unwind_Resume("), "{isa}: {code}");
            source.push_str(&code);
            ir.name = Some(format!("cleanup_chain_{index}"));
            let mut chain = vec![
                guard(
                    vec![Node::Stmt(Stmt::Br {
                        target: Some(10),
                        at: None,
                    })],
                    Vec::new(),
                ),
                Node::Label(20),
                increment(),
                Node::Stmt(Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(Expr::reg(1, 64)),
                        width: 8,
                        signed: false,
                    },
                    at: None,
                }),
                Node::Label(10),
                increment(),
                Node::Stmt(Stmt::Br {
                    target: Some(20),
                    at: None,
                }),
            ];
            inline_return_tails(&mut chain);
            let code =
                crate::render::render(&lower::lower(&ir, &chain), &[], &Default::default(), &[]);
            assert!(!code.contains("goto "), "{isa}: {code}");
            source.push_str(&code);
            ir.name = Some(format!("cleanup_layout_{index}"));
            let mut layout = vec![
                guard(
                    vec![Node::Stmt(Stmt::Br {
                        target: Some(40),
                        at: None,
                    })],
                    Vec::new(),
                ),
                increment(),
                Node::Stmt(Stmt::Br {
                    target: Some(60),
                    at: None,
                }),
                Node::Label(20),
                Node::Stmt(Stmt::Br {
                    target: Some(40),
                    at: None,
                }),
                Node::Label(30),
                Node::Stmt(Stmt::Br {
                    target: Some(60),
                    at: None,
                }),
                Node::Label(40),
            ];
            layout.extend(std::iter::repeat_with(increment).take(8));
            layout.extend([
                Node::Stmt(Stmt::Br {
                    target: Some(60),
                    at: None,
                }),
                Node::Label(60),
                Node::Stmt(Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(Expr::reg(1, 64)),
                        width: 8,
                        signed: false,
                    },
                    at: None,
                }),
            ]);
            let code =
                crate::render::render(&lower::lower(&ir, &layout), &[], &Default::default(), &[]);
            source.push_str(&code);
            ir.name = Some(format!("forward_{index}"));
            let test = |mask, then| Node::If {
                cond: Cond::Eq,
                lhs: Expr::bin(BinOp::And, Expr::reg(0, 64), Expr::Const(mask)),
                rhs: Expr::Const(0),
                then,
                els: Vec::new(),
                at: None,
            };
            let mut forward = vec![
                test(
                    1,
                    vec![
                        test(
                            2,
                            vec![Node::Stmt(Stmt::Br {
                                target: Some(10),
                                at: None,
                            })],
                        ),
                        increment(),
                    ],
                ),
                Node::Label(10),
                increment(),
                Node::Stmt(Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(Expr::reg(1, 64)),
                        width: 8,
                        signed: false,
                    },
                    at: None,
                }),
            ];
            super::super::fold_forward_exits(&mut forward);
            let code =
                crate::render::render(&lower::lower(&ir, &forward), &[], &Default::default(), &[]);
            assert!(!code.contains("goto "), "{isa}: {code}");
            source.push_str(&code);
            ir.name = Some(format!("partial_cleanup_{index}"));
            let mut partial = vec![
                test(
                    1,
                    vec![test(
                        2,
                        vec![
                            call(0x1000, vec![Expr::reg(1, 64), Expr::Const(1)]),
                            Node::Stmt(Stmt::Br {
                                target: Some(40),
                                at: None,
                            }),
                        ],
                    )],
                ),
                call(0x1000, vec![Expr::reg(1, 64), Expr::Const(2)]),
                Node::Label(40),
                call(0x1000, vec![Expr::reg(1, 64), Expr::Const(3)]),
                Node::Stmt(Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(Expr::reg(1, 64)),
                        width: 8,
                        signed: false,
                    },
                    at: None,
                }),
            ];
            super::super::fold_forward_exits(&mut partial);
            let code = crate::render::render(&lower::lower(&ir, &partial), &[], &symbols, &[]);
            assert!(!code.contains("goto "), "{isa}: {code}");
            source.push_str(&code);
        }
        source.push_str(
            "int main(void) {\n\
             uint64_t flags[] = {0, 1, 2, 3, UINT64_MAX};\n\
             for (unsigned i = 0; i < 5; ++i) {\n\
             for (uint64_t seed = 0; seed < 257; ++seed) {\n\
             uint64_t cell = UINT64_MAX - seed;\n\
             uint64_t expected = cell + 2;\n",
        );
        for index in 0..4 {
            source.push_str(&format!(
                "trace_cell = UINT64_MAX - seed;\n\
                 expected = flags[i] == 0 ? (trace_cell * 17 + 1) * 17 + 2 : trace_cell * 17 + 2;\n\
                 if (setjmp(resume_target) == 0) {{ unwind_cleanup_{index}(flags[i], &trace_cell); return 6; }}\n\
                 if (trace_cell != expected) return 7;\n\
                 expected = UINT64_MAX - seed + 2;\n"
            ));
            source.push_str(&format!(
                "cell = UINT64_MAX - seed;\n\
                 expected = (cell * 17 + ((flags[i] & 3) == 0 ? 1 : 2)) * 17 + 3;\n\
                 if (partial_cleanup_{index}(flags[i], &cell) != expected || cell != expected) return 5;\n\
                 expected = UINT64_MAX - seed + 2;\n"
            ));
            source.push_str(&format!(
                "cell = UINT64_MAX - seed;\n\
                 if (continuation_{index}(flags[i], &cell) != expected || cell != expected) return 1;\n"
            ));
            source.push_str(&format!(
                "cell = UINT64_MAX - seed;\n\
                 expected = cell + 1 + ((flags[i] & 1) == 0 && (flags[i] & 2) != 0);\n\
                 if (forward_{index}(flags[i], &cell) != expected || cell != expected) return 2;\n\
                 expected = UINT64_MAX - seed + 2;\n"
            ));
            source.push_str(&format!(
                "cell = UINT64_MAX - seed;\n\
                 expected = cell + (flags[i] == 0 ? 8 : 1);\n\
                 if (cleanup_layout_{index}(flags[i], &cell) != expected || cell != expected) return 4;\n\
                 expected = UINT64_MAX - seed + 2;\n"
            ));
            source.push_str(&format!(
                "cell = UINT64_MAX - seed;\n\
                 expected = cell + 1 + (flags[i] == 0);\n\
                 if (cleanup_chain_{index}(flags[i], &cell) != expected || cell != expected) return 3;\n\
                 expected = UINT64_MAX - seed + 2;\n"
            ));
        }
        source.push_str("}} return 0; }\n");
        let input = directory.join("continuations.c");
        let executable = directory.join("continuations");
        fs::write(&input, source).unwrap();
        for optimization in ["-O0", "-O2"] {
            let compiled = Command::new("clang")
                .args([
                    "-std=c11",
                    "-Werror=implicit-function-declaration",
                    optimization,
                ])
                .arg(&input)
                .arg("-o")
                .arg(&executable)
                .output()
                .unwrap();
            assert!(compiled.status.success(), "{compiled:?}");
            let result = Command::new(&executable).output().unwrap();
            assert!(result.status.success(), "{result:?}");
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn nested_label_invalidates_constants_after_the_branch() {
        let variable = crate::ir::VARIABLE_BASE;
        let mut nodes = vec![
            Node::Stmt(Stmt::Assign {
                dest: crate::ir::RegRef {
                    index: variable,
                    width: 64,
                },
                value: Expr::Const(7),
                at: None,
            }),
            Node::If {
                cond: Cond::Eq,
                lhs: Expr::reg(0, 64),
                rhs: Expr::Const(0),
                then: vec![Node::Label(10)],
                els: Vec::new(),
                at: None,
            },
            Node::Stmt(Stmt::Ret {
                value: Expr::reg(variable, 64),
                at: None,
            }),
        ];
        return_known_constants(&mut nodes);
        assert!(matches!(nodes.last(), Some(Node::Stmt(Stmt::Ret {
            value: Expr::Reg { index, .. },
            ..
        })) if *index == variable));
    }

    #[test]
    fn conditional_jump_inlines_a_closed_return_tree() {
        let return_node = || {
            Node::Stmt(Stmt::Ret {
                value: Expr::Const(1),
                at: None,
            })
        };
        let mut nodes = vec![
            Node::Stmt(Stmt::Brif {
                cond: Cond::Eq,
                lhs: Expr::reg(0, 64),
                rhs: Expr::Const(0),
                target: 10,
                at: None,
            }),
            return_node(),
            Node::Label(10),
            Node::If {
                cond: Cond::Eq,
                lhs: Expr::reg(1, 64),
                rhs: Expr::Const(0),
                then: vec![return_node()],
                els: vec![return_node()],
                at: None,
            },
        ];
        inline_return_tails(&mut nodes);
        assert!(matches!(&nodes[0], Node::If { then, .. }
            if matches!(then.as_slice(), [Node::If { .. }])));
    }

    #[test]
    fn return_tree_with_an_internal_label_is_not_copied() {
        let mut nodes = vec![
            Node::Stmt(Stmt::Br {
                target: Some(10),
                at: None,
            }),
            Node::Label(10),
            Node::If {
                cond: Cond::Eq,
                lhs: Expr::reg(0, 64),
                rhs: Expr::Const(0),
                then: vec![Node::Label(20)],
                els: Vec::new(),
                at: None,
            },
            Node::Stmt(Stmt::Ret {
                value: Expr::Const(1),
                at: None,
            }),
        ];
        inline_return_tails(&mut nodes);
        assert!(matches!(nodes[0], Node::Stmt(Stmt::Br { .. })));
    }
}

//! Inductive checks of scalar byte comparison and search loops.

use std::collections::BTreeSet;

use super::{Values, add, assignments, byte, evaluate, narrow, subtract};
use crate::ir::{Cond, Expr, Stmt};
use crate::render::{Ctx, InlineFunction, Node, render_expr};

#[derive(Clone)]
struct Test {
    cond: Cond,
    lhs: Expr,
    rhs: Expr,
    yes: bool,
}

#[derive(Clone)]
struct State {
    values: Values,
    tests: Vec<Test>,
    reads: Vec<Expr>,
    written: BTreeSet<u16>,
    required: BTreeSet<u16>,
}

enum Outcome {
    Continue,
    Return(Expr),
}

struct Path {
    state: State,
    outcome: Outcome,
}

fn used(value: &Expr, state: &mut State) {
    let mut reads = std::collections::HashSet::new();
    crate::ir::visit::collect_reads(value, &mut reads);
    for read in reads {
        if !state.written.contains(&read) {
            state.required.insert(read);
        }
    }
}

fn execute(
    nodes: &[Node],
    mut state: State,
    tail: &[Node],
    paths: &mut Vec<Path>,
    budget: &mut usize,
) -> bool {
    let Some((node, rest)) = nodes.split_first() else {
        return false;
    };
    let Some(remaining) = budget.checked_sub(1) else {
        return false;
    };
    *budget = remaining;
    match node {
        Node::Stmt(Stmt::Assign { dest, value }) => {
            used(value, &mut state);
            if !assignments(
                std::slice::from_ref(node),
                &mut state.values,
                &mut state.reads,
            ) {
                return false;
            }
            state.written.insert(dest.index);
            execute(rest, state, tail, paths, budget)
        }
        Node::Stmt(Stmt::Ret { value }) => {
            used(value, &mut state);
            let Some(value) = evaluate(value, &state.values, &mut state.reads) else {
                return false;
            };
            paths.push(Path {
                state,
                outcome: Outcome::Return(value),
            });
            true
        }
        Node::Continue => {
            paths.push(Path {
                state,
                outcome: Outcome::Continue,
            });
            true
        }
        Node::Break => execute(tail, state, &[], paths, budget),
        Node::If {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => {
            let bits = crate::ir::semantics::operand_width(lhs, rhs);
            used(lhs, &mut state);
            used(rhs, &mut state);
            let Some(lhs) = evaluate(lhs, &state.values, &mut state.reads) else {
                return false;
            };
            let Some(rhs) = evaluate(rhs, &state.values, &mut state.reads) else {
                return false;
            };
            if matches!(cond, Cond::Lt | Cond::Le | Cond::Gt | Cond::Ge)
                && (bits < 32 || !byte(&lhs) || !byte(&rhs))
            {
                return false;
            }
            let mut yes = state.clone();
            yes.tests.push(Test {
                cond: *cond,
                lhs: lhs.clone(),
                rhs: rhs.clone(),
                yes: true,
            });
            state.tests.push(Test {
                cond: *cond,
                lhs,
                rhs,
                yes: false,
            });
            let mut taken = then.clone();
            taken.extend_from_slice(rest);
            let mut other = els.clone();
            other.extend_from_slice(rest);
            execute(&taken, yes, tail, paths, budget) && execute(&other, state, tail, paths, budget)
        }
        _ => false,
    }
}

fn step(node: &Node, values: Values, tail: &[Node]) -> Option<Vec<Path>> {
    fn continues(nodes: &[Node]) -> bool {
        nodes.iter().any(|node| match node {
            Node::Continue => true,
            Node::If { then, els, .. } => continues(then) || continues(els),
            _ => false,
        })
    }
    match node {
        Node::DoWhile { body, .. } | Node::While { body, .. } | Node::Forever { body }
            if continues(body) =>
        {
            return None;
        }
        _ => {}
    }
    let test = |cond, lhs: &Expr, rhs: &Expr, then, els| Node::If {
        cond,
        lhs: lhs.clone(),
        rhs: rhs.clone(),
        then,
        els,
    };
    let nodes = match node {
        Node::DoWhile {
            cond,
            lhs,
            rhs,
            body,
        } => {
            let mut nodes = body.clone();
            nodes.push(test(*cond, lhs, rhs, vec![Node::Continue], tail.to_vec()));
            nodes
        }
        Node::While {
            prefix,
            cond,
            lhs,
            rhs,
            body,
        } => {
            let mut nodes = prefix.clone();
            let mut body = body.clone();
            body.push(Node::Continue);
            nodes.push(test(*cond, lhs, rhs, body, tail.to_vec()));
            nodes
        }
        Node::Forever { body } => {
            let mut nodes = body.clone();
            nodes.push(Node::Continue);
            nodes
        }
        _ => return None,
    };
    let state = State {
        values,
        tests: Vec::new(),
        reads: Vec::new(),
        written: BTreeSet::new(),
        required: BTreeSet::new(),
    };
    let mut paths = Vec::new();
    if !execute(&nodes, state, tail, &mut paths, &mut 256) {
        return None;
    }
    Some(paths)
}

enum Relation {
    Stable,
    Add(u64),
    Load,
}

fn related(value: &Expr, relation: &Relation, offset: Expr) -> Expr {
    match relation {
        Relation::Stable => value.clone(),
        Relation::Add(1) => add(value.clone(), offset),
        Relation::Add(_) => subtract(value.clone(), offset),
        Relation::Load => {
            let Expr::Load {
                addr,
                width,
                signed,
            } = value
            else {
                unreachable!("load relation has a load")
            };
            Expr::Load {
                addr: Box::new(add(*addr.clone(), offset)),
                width: *width,
                signed: *signed,
            }
        }
    }
}

fn induction(node: &Node, values: &Values, tail: &[Node], iteration: u16) -> Option<Vec<Path>> {
    let Some(sample) = step(node, values.clone(), tail) else {
        return None;
    };
    let Some(next) = sample
        .iter()
        .find(|path| matches!(path.outcome, Outcome::Continue))
    else {
        return None;
    };
    let required: BTreeSet<u16> = sample
        .iter()
        .flat_map(|path| path.state.required.iter().copied())
        .collect();
    let mut relations = Vec::new();
    let mut symbolic = values.clone();
    for index in required {
        let Some(before) = values.get(&index) else {
            return None;
        };
        let Some(after) = next.state.values.get(&index) else {
            return None;
        };
        let relation = if before == after {
            Relation::Stable
        } else if let Expr::Const(delta @ (1 | u64::MAX)) = subtract(after.clone(), before.clone())
        {
            Relation::Add(delta)
        } else if let (
            Expr::Load {
                addr: a,
                width: 1,
                signed: false,
            },
            Expr::Load {
                addr: b,
                width: 1,
                signed: false,
            },
        ) = (before, after)
            && subtract(*b.clone(), *a.clone()) == Expr::Const(1)
        {
            Relation::Load
        } else {
            return None;
        };
        symbolic.insert(index, related(before, &relation, Expr::reg(iteration, 64)));
        relations.push((index, relation));
    }
    let Some(paths) = step(node, symbolic, tail) else {
        return None;
    };
    for path in &paths {
        if !matches!(path.outcome, Outcome::Continue) {
            continue;
        }
        for (index, relation) in &relations {
            let expected = related(
                &values[index],
                relation,
                add(Expr::reg(iteration, 64), Expr::Const(1)),
            );
            if path.state.values.get(index) != Some(&expected) {
                return None;
            }
        }
    }
    Some(paths)
}

struct Case<'a> {
    sources: &'a [Expr],
    pair: [u64; 2],
    next_pair: [u64; 2],
    target: Option<&'a Expr>,
    bound: Option<(&'a Expr, u64)>,
    iteration: u16,
    entry: bool,
    terminated: bool,
}

impl Case<'_> {
    fn input(&self, value: &Expr) -> Option<u64> {
        if self.target == Some(value) {
            return Some(self.pair[1]);
        }
        if let Expr::Load {
            addr,
            width: 1,
            signed: false,
        } = value
        {
            for (index, source) in self.sources.iter().enumerate() {
                if addr.as_ref() == source {
                    return Some(self.pair[index]);
                }
                if **addr == add(source.clone(), Expr::Const(1)) {
                    return Some(self.next_pair[index]);
                }
            }
        }
        if *value == Expr::Const(0) {
            return Some(0);
        }
        None
    }

    fn predicate(&self, cond: Cond, lhs: &Expr, rhs: &Expr) -> Option<bool> {
        if !matches!(
            cond,
            Cond::Eq
                | Cond::Ne
                | Cond::Cc
                | Cond::Cs
                | Cond::Hi
                | Cond::Ls
                | Cond::Lt
                | Cond::Le
                | Cond::Gt
                | Cond::Ge
        ) {
            return None;
        }
        if self.target.is_some() && !matches!(cond, Cond::Eq | Cond::Ne) {
            return None;
        }
        if let (Expr::Load { addr: a, .. }, Expr::Load { addr: b, .. }) = (lhs, rhs) {
            let position = |address: &Expr| {
                self.sources.iter().find_map(|source| {
                    match subtract(address.clone(), source.clone()) {
                        Expr::Const(offset @ (0 | 1)) => Some(offset),
                        _ => None,
                    }
                })
            };
            if position(a) != position(b) {
                return None;
            }
        }
        if !self.terminated
            && ((matches!(lhs, Expr::Load { .. }) && *rhs == Expr::Const(0))
                || (matches!(rhs, Expr::Load { .. }) && *lhs == Expr::Const(0)))
        {
            return None;
        }
        if let (Some(a), Some(b)) = (self.input(lhs), self.input(rhs)) {
            return Some(crate::ir::semantics::holds(cond, a, b, 64));
        }
        if let Some((count, remaining_value)) = self.bound {
            let i = if self.entry {
                Expr::Const(0)
            } else {
                Expr::reg(self.iteration, 64)
            };
            let remaining = subtract(count.clone(), i.clone());
            if matches!(cond, Cond::Eq | Cond::Ne) {
                let difference = subtract(lhs.clone(), rhs.clone());
                for offset in [0, 1] {
                    let expected = subtract(remaining.clone(), Expr::Const(offset));
                    if difference == expected || difference == subtract(Expr::Const(0), expected) {
                        return Some((remaining_value == offset) == (cond == Cond::Eq));
                    }
                }
            }
            let operands = if (*lhs == remaining && *rhs == Expr::Const(0))
                || (*lhs == *count && *rhs == i)
            {
                Some((remaining_value, 0))
            } else if (*rhs == remaining && *lhs == Expr::Const(0)) || (*rhs == *count && *lhs == i)
            {
                Some((0, remaining_value))
            } else {
                None
            };
            if let Some((a, b)) = operands
                && matches!(
                    cond,
                    Cond::Eq | Cond::Ne | Cond::Cc | Cond::Cs | Cond::Hi | Cond::Ls
                )
            {
                return Some(crate::ir::semantics::holds(cond, a, b, 64));
            }
        }
        let Some(a) = self.constant(lhs) else {
            return None;
        };
        let Some(b) = self.constant(rhs) else {
            return None;
        };
        Some(crate::ir::semantics::holds(cond, a, b, 64))
    }

    fn constant(&self, value: &Expr) -> Option<u64> {
        super::constant(value, &|cond, lhs, rhs| self.predicate(cond, lhs, rhs))
    }

    fn active(&self, path: &Path) -> Option<bool> {
        for test in &path.state.tests {
            let Some(yes) = self.predicate(test.cond, &test.lhs, &test.rhs) else {
                return None;
            };
            if yes != test.yes {
                return Some(false);
            }
        }
        Some(true)
    }
}

enum Model<'a> {
    Compare {
        bits: u32,
        terminated: bool,
        count: Option<&'a Expr>,
    },
    Find {
        target: &'a Expr,
    },
}

enum Expected {
    Advance,
    Number(u64),
    Pointer(Expr),
}

impl Model<'_> {
    fn expected(&self, pair: [u64; 2], at_end: bool, address: &Expr) -> Expected {
        match self {
            Self::Find { .. } if pair[0] == pair[1] => Expected::Pointer(address.clone()),
            Self::Find { .. } if pair[0] == 0 => Expected::Number(0),
            Self::Find { .. } => Expected::Advance,
            Self::Compare { .. } if at_end => Expected::Number(0),
            Self::Compare { terminated, .. }
                if pair[0] == pair[1] && (!terminated || pair[0] != 0) =>
            {
                Expected::Advance
            }
            Self::Compare { .. } => Expected::Number(match pair[0].cmp(&pair[1]) {
                std::cmp::Ordering::Less => u64::MAX,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            }),
        }
    }

    fn agrees(&self, case: &Case<'_>, actual: &Expr, expected: &Expected) -> bool {
        match expected {
            Expected::Advance => false,
            Expected::Pointer(pointer) => actual == pointer,
            Expected::Number(expected) => {
                let Some(actual) = case.constant(actual) else {
                    return false;
                };
                let bits = match self {
                    Self::Compare { bits, .. } => *bits,
                    Self::Find { .. } => 64,
                };
                let mask = crate::ir::semantics::mask(bits);
                actual & mask == expected & mask
            }
        }
    }
}

fn enters(paths: &[Path], case: &Case<'_>, model: &Model<'_>) -> Option<bool> {
    let mut entered = None;
    for path in paths {
        let Some(active) = case.active(path) else {
            return None;
        };
        if !active {
            continue;
        }
        if entered.is_some() {
            return None;
        }
        match &path.outcome {
            Outcome::Continue => entered = Some(true),
            Outcome::Return(value) => {
                let at_end = case.bound.is_some_and(|(_, remaining)| remaining == 0);
                let expected = model.expected(case.pair, at_end, &case.sources[0]);
                if !model.agrees(case, value, &expected) {
                    return None;
                }
                entered = Some(false);
            }
        }
    }
    entered
}

fn equivalent(
    paths: &[Path],
    entry: &[Path],
    bases: &[Expr],
    sources: &[Expr],
    iteration: u16,
    model: Model<'_>,
) -> bool {
    let (target, count, terminated) = match model {
        Model::Find { target } => (Some(target), None, true),
        Model::Compare {
            count, terminated, ..
        } => (None, count, terminated),
    };
    let pairs: &[[u64; 2]] = if terminated {
        &[[0, 0], [0, 1], [1, 0], [1, 1], [1, 2], [2, 1]]
    } else {
        &[[1, 1], [1, 2], [2, 1]]
    };
    for remaining in 0u64..=3 {
        if count.is_none() && remaining != 3 {
            continue;
        }
        for pair in pairs {
            let initial = Case {
                sources: bases,
                pair: *pair,
                next_pair: *pair,
                target,
                bound: count.map(|count| (count, remaining)),
                iteration,
                entry: true,
                terminated,
            };
            let Some(allowed) = enters(entry, &initial, &model) else {
                return false;
            };
            if !allowed {
                continue;
            }
            let current = model.expected(*pair, count.is_some() && remaining == 0, &sources[0]);
            for next in pairs {
                if target.is_some() && (pair[1] == 0) != (next[1] == 0) {
                    continue;
                }
                let next = if target.is_some() {
                    let byte = if next[0] == 0 {
                        0
                    } else if next[0] == next[1] {
                        pair[1]
                    } else {
                        pair[1] + 1
                    };
                    [byte, pair[1]]
                } else {
                    *next
                };
                let next_remaining = remaining.saturating_sub(1);
                let following = Case {
                    sources: bases,
                    pair: next,
                    next_pair: next,
                    target,
                    bound: count.map(|count| (count, next_remaining)),
                    iteration,
                    entry: true,
                    terminated,
                };
                let Some(next_allowed) = enters(entry, &following, &model) else {
                    return false;
                };
                let next_address = add(sources[0].clone(), Expr::Const(1));
                let next_expected =
                    model.expected(next, count.is_some() && next_remaining == 0, &next_address);
                let case = Case {
                    sources,
                    pair: *pair,
                    next_pair: next,
                    target,
                    bound: count.map(|count| (count, remaining)),
                    iteration,
                    entry: false,
                    terminated,
                };
                let mut active = 0;
                for path in paths {
                    let Some(applies) = case.active(path) else {
                        return false;
                    };
                    if !applies {
                        continue;
                    }
                    active += 1;
                    match &path.outcome {
                        Outcome::Continue
                            if matches!(current, Expected::Advance) && next_allowed => {}
                        Outcome::Return(value) => {
                            let expected = if matches!(current, Expected::Advance) {
                                &next_expected
                            } else {
                                &current
                            };
                            if !model.agrees(&case, value, expected) {
                                return false;
                            }
                        }
                        _ => return false,
                    }
                }
                if active != 1 {
                    return false;
                }
            }
        }
    }
    true
}

pub(super) fn render(
    nodes: &[Node],
    initial: &Values,
    iteration: u16,
    ctx: &Ctx<'_>,
) -> Option<String> {
    if !(2..=3).contains(&ctx.ir.params.len()) {
        return None;
    }
    let Some(loop_index) = nodes.iter().position(|node| {
        matches!(
            node,
            Node::While { .. } | Node::DoWhile { .. } | Node::Forever { .. }
        )
    }) else {
        return None;
    };
    let mut prefix = nodes[..loop_index].to_vec();
    prefix.push(Node::Continue);
    let state = State {
        values: initial.clone(),
        tests: Vec::new(),
        reads: Vec::new(),
        written: BTreeSet::new(),
        required: BTreeSet::new(),
    };
    let mut entry = Vec::new();
    if !execute(&prefix, state, &[], &mut entry, &mut 128) {
        return None;
    }
    let Some(first) = entry
        .iter()
        .find(|path| matches!(path.outcome, Outcome::Continue))
    else {
        return None;
    };
    let values = &first.state.values;
    if entry
        .iter()
        .any(|path| matches!(path.outcome, Outcome::Continue) && path.state.values != *values)
    {
        return None;
    }
    let node = &nodes[loop_index];
    let Some(paths) = induction(node, values, &nodes[loop_index + 1..], iteration) else {
        return None;
    };
    let bases = [
        Expr::reg(ctx.ir.params[0].index, 64),
        Expr::reg(ctx.ir.params[1].index, 64),
    ];
    let sources = bases
        .clone()
        .map(|base| add(base, Expr::reg(iteration, 64)));
    let valid_read = |address: &Expr| {
        sources
            .iter()
            .any(|source| *address == *source || *address == add(source.clone(), Expr::Const(1)))
    };
    if paths
        .iter()
        .any(|path| path.state.reads.iter().any(|address| !valid_read(address)))
        || entry.iter().any(|path| {
            path.state
                .reads
                .iter()
                .any(|address| !bases.contains(address))
        })
    {
        return None;
    }
    let target = narrow(Expr::reg(ctx.ir.params[1].index, 64), 8);
    if ctx.ir.params.len() == 2
        && equivalent(
            &paths,
            &entry,
            &bases[..1],
            &sources[..1],
            iteration,
            Model::Find { target: &target },
        )
    {
        if super::is_current_function("strchr", ctx) {
            return None;
        }
        let cast = ctx.ret_pointer.as_deref().unwrap_or("uint64_t");
        let call = format!(
            "({cast})__builtin_strchr({}, (int)({}))",
            super::argument(&bases[0], "strchr", ctx),
            render_expr(&target, ctx)
        );
        ctx.inline_functions.borrow_mut().push(InlineFunction {
            function: "strchr".to_owned(),
            bytes: None,
        });
        return Some(format!("    return {call};\n"));
    }
    if ctx.ret_pointer.is_some() {
        return None;
    }
    let Some((bits, _)) = ctx.ir.ret_type.integer() else {
        return None;
    };
    let count = ctx.ir.params.get(2).map(|param| Expr::reg(param.index, 64));
    let function = if count.is_some()
        && equivalent(
            &paths,
            &entry,
            &bases,
            &sources,
            iteration,
            Model::Compare {
                bits,
                terminated: false,
                count: count.as_ref(),
            },
        ) {
        "memcmp"
    } else if equivalent(
        &paths,
        &entry,
        &bases,
        &sources,
        iteration,
        Model::Compare {
            bits,
            terminated: true,
            count: count.as_ref(),
        },
    ) {
        if count.is_some() { "strncmp" } else { "strcmp" }
    } else {
        return None;
    };
    if super::is_current_function(function, ctx) {
        return None;
    }
    let mut body = String::new();
    if let Some(count) = &count {
        body.push_str(&format!(
            "    if ({} == 0) {{\n        return 0;\n    }}\n",
            render_expr(count, ctx)
        ));
    }
    let count = count
        .map(|count| {
            let value =
                crate::render::expr::print_value_at(&count, ctx, 64, false).address_integer();
            format!(", {}", value.text)
        })
        .unwrap_or_default();
    let call = format!(
        "__builtin_{function}({}, {}{count})",
        super::argument(&bases[0], function, ctx),
        super::argument(&bases[1], function, ctx)
    );
    body.push_str(&super::comparison(&call, function, None, ctx));
    Some(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_do_loop_continues_require_condition_evaluation() {
        let node = Node::DoWhile {
            cond: Cond::Ne,
            lhs: Expr::Const(0),
            rhs: Expr::Const(0),
            body: vec![Node::Continue],
        };
        assert!(
            step(
                &node,
                Values::new(),
                &[Node::Stmt(Stmt::Ret {
                    value: Expr::Const(0)
                })]
            )
            .is_none()
        );
    }
}

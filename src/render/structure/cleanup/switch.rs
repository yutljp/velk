use super::{breaks_out, children, children_mut, ends};
use crate::ir::{Cond, Expr, Stmt};
use crate::render::structure::Node;
use std::collections::HashMap;

/// Folds the tests a compiler puts before a switch into it. A bounds check,
/// `v = x - k; if (v > n) t else switch (x) { ... }` with cases for every
/// value from `k` to `k + n`, is the switch with `t` as its default; a
/// test for one more value, `if (x == c) t` right before `switch (x)`, is
/// a case of it when `t` leaves. Neither takes a `t` with a `break` for an
/// enclosing loop, which in a switch would leave the switch instead.
pub(crate) fn absorb_switch_tests(nodes: &mut Vec<Node>) {
    let mut reads = HashMap::new();
    count_reads(nodes, &mut reads);
    absorb_in(nodes, &reads);
}

fn absorb_in(nodes: &mut Vec<Node>, reads: &HashMap<u16, usize>) {
    for node in nodes.iter_mut() {
        for body in children_mut(node) {
            absorb_in(body, reads);
        }
    }
    let mut index = 0;
    while index < nodes.len() {
        if index + 1 < nodes.len() && absorb_bounds_check(nodes, index, reads) {
            continue;
        }
        if index + 1 < nodes.len() && absorb_equality(nodes, index) {
            index = index.saturating_sub(1);
            continue;
        }
        index += 1;
    }
}

/// `nodes[index]` sets `v = x - k` and `nodes[index + 1]` checks `v`'s
/// bound around a switch on `x`.
fn absorb_bounds_check(nodes: &mut Vec<Node>, index: usize, reads: &HashMap<u16, usize>) -> bool {
    let Node::Stmt(Stmt::Assign { dest, value }) = &nodes[index] else {
        return false;
    };
    let (base, offset) = match unmasked(value) {
        Expr::Bin {
            op: crate::ir::BinOp::Sub,
            lhs,
            rhs,
        } => match rhs.as_ref() {
            Expr::Const(k) => (lhs.as_ref(), *k),
            _ => return false,
        },
        Expr::Bin {
            op: crate::ir::BinOp::Add,
            lhs,
            rhs,
        } => match rhs.as_ref() {
            Expr::Const(k) => (lhs.as_ref(), k.wrapping_neg()),
            _ => return false,
        },
        _ => return false,
    };
    let Node::If {
        cond,
        lhs,
        rhs: Expr::Const(bound),
        then,
        els,
    } = &nodes[index + 1]
    else {
        return false;
    };
    if !matches!(narrowed(lhs), Expr::Reg { index: tested, .. } if tested == dest.index) {
        return false;
    }
    // The values that take the switch: `v <= last`.
    let (last, inside, outside) = match cond {
        Cond::Hi => (*bound, els, then),
        Cond::Ls => (*bound, then, els),
        Cond::Cs if *bound > 0 => (*bound - 1, els, then),
        Cond::Cc if *bound > 0 => (*bound - 1, then, els),
        _ => return false,
    };
    let [
        Node::Switch {
            index: switched,
            arms,
            default: None,
        },
    ] = inside.as_slice()
    else {
        return false;
    };
    if narrowed(switched) != narrowed(base) || last > 4096 || breaks_out(outside) {
        return false;
    }
    let first = offset as i64;
    let covered = (0..=last as i64).all(|step| {
        arms.iter()
            .any(|(values, _)| values.contains(&first.wrapping_add(step)))
    });
    if !covered {
        return false;
    }
    let switch = Node::Switch {
        index: switched.clone(),
        arms: arms.clone(),
        default: Some(outside.clone()),
    };
    let variable = dest.index;
    nodes[index + 1] = switch;
    // The difference only fed the check.
    if reads.get(&variable) == Some(&1) {
        nodes.remove(index);
    }
    true
}

/// `expr` without a mask that keeps all of its value's low bits.
fn unmasked(expr: &Expr) -> &Expr {
    match expr {
        Expr::Bin {
            op: crate::ir::BinOp::And,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(0xff | 0xffff | 0xffff_ffff)) => lhs,
        _ => expr,
    }
}

/// A register read whole or through a mask of its low bits, as the read
/// of that many bits it is: `x0 & 0xffffffff` and `w0` read the same.
fn narrowed(expr: &Expr) -> Expr {
    match expr {
        Expr::Bin {
            op: crate::ir::BinOp::And,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Reg { index, width }, Expr::Const(mask @ (0xff | 0xffff | 0xffff_ffff)))
                if u32::from(*width) >= mask.count_ones() =>
            {
                Expr::Reg {
                    index: *index,
                    width: mask.count_ones() as u8,
                }
            }
            _ => expr.clone(),
        },
        _ => expr.clone(),
    }
}

/// How many times the code reads each register.
fn count_reads(nodes: &[Node], counts: &mut HashMap<u16, usize>) {
    fn expr(value: &Expr, counts: &mut HashMap<u16, usize>) {
        if let Expr::Reg { index, .. } = value {
            *counts.entry(*index).or_default() += 1;
        }
        for child in crate::ir::visit::children(value) {
            expr(child, counts);
        }
    }
    for node in nodes {
        match node {
            Node::Stmt(stmt) => {
                for operand in stmt.operands() {
                    expr(operand, counts);
                }
            }
            Node::If { lhs, rhs, .. }
            | Node::DoWhile { lhs, rhs, .. }
            | Node::While { lhs, rhs, .. } => {
                expr(lhs, counts);
                expr(rhs, counts);
            }
            Node::Switch { index, .. } => expr(index, counts),
            Node::Label(_) | Node::Break | Node::Continue | Node::Forever { .. } => {}
        }
        for body in children(node) {
            count_reads(body, counts);
        }
    }
}

/// `nodes[index]` is `if (x == c) t` with `t` leaving, and the switch on
/// `x` follows it or is all of its `else`; or the same as
/// `if (x != c) switch else t`.
fn absorb_equality(nodes: &mut Vec<Node>, index: usize) -> bool {
    let Node::If {
        cond,
        lhs,
        rhs: Expr::Const(value),
        then,
        els,
    } = &nodes[index]
    else {
        return false;
    };
    let (taken, other) = match cond {
        Cond::Eq => (then, els),
        Cond::Ne => (els, then),
        _ => return false,
    };
    // Where the switch is: inside the `if`, or right after it.
    let inside = match other.as_slice() {
        [Node::Switch { .. }] => true,
        [] if *cond == Cond::Eq => false,
        _ => return false,
    };
    let switch = if inside {
        &other[0]
    } else {
        match nodes.get(index + 1) {
            Some(node @ Node::Switch { .. }) => node,
            _ => return false,
        }
    };
    let Node::Switch {
        index: switched,
        arms,
        default,
    } = switch
    else {
        return false;
    };
    let value = *value as i64;
    if narrowed(switched) != narrowed(lhs)
        || !(0..1 << 31).contains(&value)
        || !ends(taken, false)
        || breaks_out(taken)
        || arms.iter().any(|(values, _)| values.contains(&value))
    {
        return false;
    }
    let mut arms = arms.clone();
    let at = arms
        .iter()
        .position(|(values, _)| values.iter().min().is_some_and(|first| *first > value))
        .unwrap_or(arms.len());
    arms.insert(at, (vec![value], taken.clone()));
    let joined = Node::Switch {
        index: switched.clone(),
        arms,
        default: default.clone(),
    };
    if inside {
        nodes[index] = joined;
    } else {
        nodes[index + 1] = joined;
        nodes.remove(index);
    }
    true
}

//! Counted-loop recovery.

use super::{indent, render_nodes};
use crate::ir::{BinOp, Expr, Stmt};
use crate::render::{Ctx, Node, condition, expr, render_expr, render_stmt};

/// `init; while (cond) { body; step; }` as `for (init; cond; step) { body }`,
/// when `init` and `step` write the one register or local the condition
/// reads, `step` updates it from itself, and no `continue` in the body
/// would skip the step.
pub(super) fn for_loop(
    init: &Stmt,
    looped: &Node,
    preceding: &[Node],
    depth: usize,
    ctx: &Ctx<'_>,
) -> Option<String> {
    let (cond, lhs, rhs, body) = match looped {
        Node::While {
            prefix,
            cond,
            lhs,
            rhs,
            body,
        } if prefix.is_empty() => (cond, lhs, rhs, body),
        Node::If {
            cond: guard,
            lhs: a,
            rhs: b,
            then,
            els,
        } if els.is_empty() => {
            let [
                Node::DoWhile {
                    cond,
                    lhs,
                    rhs,
                    body,
                },
            ] = then.as_slice()
            else {
                return None;
            };
            let Stmt::Assign {
                dest,
                value: initial,
            } = init
            else {
                return None;
            };
            // A partial write or a load could change the first test or
            // its side effects.
            if dest.width != 64 || !test_operand(initial) {
                return None;
            }
            if !full_reads(lhs, dest.index) || !full_reads(rhs, dest.index) {
                return None;
            }
            let values = [(dest.index, initial.clone())];
            let first_lhs = crate::ir::visit::substitute_values(lhs.clone(), &values);
            let first_rhs = crate::ir::visit::substitute_values(rhs.clone(), &values);
            if !same_test_width(*cond, lhs, rhs, &first_lhs, &first_rhs, ctx)
                || !test_operand(a)
                || !test_operand(b)
                || !same_test(*cond, &first_lhs, &first_rhs, *guard, a, b, ctx)
            {
                return None;
            }
            (cond, lhs, rhs, body)
        }
        Node::DoWhile {
            cond,
            lhs,
            rhs,
            body,
        } if first_test(init, *cond, lhs, rhs, preceding, ctx) => (cond, lhs, rhs, body),
        _ => return None,
    };
    let Some((Node::Stmt(step), rest)) = body.split_last() else {
        return None;
    };
    if let Some(text) =
        crate::render::string_loops::render(init, (*cond, lhs, rhs), body, preceding, depth, ctx)
    {
        return Some(text);
    }
    let Some(counter) = crate::render::naming::roles::counted(init, lhs, rhs, body) else {
        return None;
    };
    let mut continued;
    let rest = if continues(rest) {
        continued = rest.to_vec();
        if !move_continue_steps(&mut continued, step) {
            return None;
        }
        continued.as_slice()
    } else {
        rest
    };
    if let crate::render::naming::roles::NamedPlace::Slot(addr) = counter
        && !ctx.slots.contains_key(&render_expr(&addr, ctx))
    {
        return None;
    }
    let clause = |stmt: &Stmt| {
        let text = render_stmt(stmt, ctx);
        text.strip_suffix(';').unwrap_or(&text).to_owned()
    };
    // A step of one reads as `i++` or `i += 1`'s shorter form.
    let step_text = {
        let text = clause(step);
        if let Some(name) = text.strip_prefix("++") {
            format!("{name}++")
        } else if let Some(name) = text.strip_prefix("--") {
            format!("{name}--")
        } else {
            match text.split_once(" = ") {
                Some((name, value)) if value == format!("{name} + 1") => format!("{name}++"),
                Some((name, value)) if value == format!("{name} - 1") => format!("{name}--"),
                _ => match text.strip_suffix(" += 1") {
                    Some(name) => format!("{name}++"),
                    None => text,
                },
            }
        }
    };
    let mut output = String::new();
    indent(depth, &mut output);
    output.push_str(&format!(
        "for ({}; {}; {}) {{\n",
        clause(init),
        condition(*cond, lhs, rhs, ctx),
        step_text
    ));
    render_nodes(rest, depth + 1, &mut output, ctx);
    indent(depth, &mut output);
    output.push_str("}\n");
    Some(output)
}

// Prove the first bottom test from a preceding early-return guard. Walk
// assignments backwards so copied bounds still name the guarded value.
fn first_test(
    init: &Stmt,
    cond: crate::ir::Cond,
    lhs: &Expr,
    rhs: &Expr,
    preceding: &[Node],
    ctx: &Ctx<'_>,
) -> bool {
    let Stmt::Assign {
        dest,
        value: initial,
    } = init
    else {
        return false;
    };
    if dest.width != 64 || !test_operand(initial) {
        return false;
    }
    if cond == crate::ir::Cond::Ne
        && *lhs == Expr::reg(dest.index, 64)
        && *rhs == Expr::Const(0)
        && matches!(initial, Expr::Const(value) if *value != 0)
    {
        return true;
    }
    let original_lhs = lhs;
    let original_rhs = rhs;
    let mut lhs = lhs.clone();
    let mut rhs = rhs.clone();
    let mut assignments = Vec::new();
    for node in preceding.iter().rev() {
        match node {
            Node::Stmt(stmt @ Stmt::Assign { .. }) => assignments.push(stmt),
            Node::If {
                cond: guard,
                lhs: a,
                rhs: b,
                then,
                els,
            } if els.is_empty() && matches!(then.last(), Some(Node::Stmt(Stmt::Ret { .. }))) => {
                for stmt in &assignments {
                    let Stmt::Assign { dest, value } = stmt else {
                        return false;
                    };
                    if dest.width != 64 || !test_operand(value) {
                        return false;
                    }
                    if !full_reads(&lhs, dest.index) || !full_reads(&rhs, dest.index) {
                        return false;
                    }
                    let values = [(dest.index, value.clone())];
                    lhs = crate::ir::visit::substitute_values(lhs, &values);
                    rhs = crate::ir::visit::substitute_values(rhs, &values);
                }
                if !same_test_width(cond, original_lhs, original_rhs, &lhs, &rhs, ctx)
                    || !test_operand(&lhs)
                    || !test_operand(&rhs)
                    || !test_operand(a)
                    || !test_operand(b)
                {
                    return false;
                }
                let inverted = guard.invert();
                if same_test(cond, &lhs, &rhs, inverted, a, b, ctx) {
                    return true;
                }
                // A positive bound is nonzero, with either signedness.
                if cond == crate::ir::Cond::Ne {
                    let ((Expr::Const(0), bound) | (bound, Expr::Const(0))) = (&lhs, &rhs) else {
                        return false;
                    };
                    return matches!(
                        inverted,
                        crate::ir::Cond::Gt | crate::ir::Cond::Hi | crate::ir::Cond::Ne
                    ) && *b == Expr::Const(0)
                        && render_expr(bound, ctx) == render_expr(a, ctx);
                }
                return false;
            }
            _ => return false,
        }
    }
    false
}

fn same_test(
    cond: crate::ir::Cond,
    lhs: &Expr,
    rhs: &Expr,
    guard: crate::ir::Cond,
    a: &Expr,
    b: &Expr,
    ctx: &Ctx<'_>,
) -> bool {
    if condition(cond, lhs, rhs, ctx) == condition(guard, a, b, ctx) {
        return true;
    }
    let swapped = match cond {
        crate::ir::Cond::Eq | crate::ir::Cond::Ne => Some(cond),
        crate::ir::Cond::Lt => Some(crate::ir::Cond::Gt),
        crate::ir::Cond::Gt => Some(crate::ir::Cond::Lt),
        crate::ir::Cond::Le => Some(crate::ir::Cond::Ge),
        crate::ir::Cond::Ge => Some(crate::ir::Cond::Le),
        crate::ir::Cond::Hi => Some(crate::ir::Cond::Cc),
        crate::ir::Cond::Cc => Some(crate::ir::Cond::Hi),
        crate::ir::Cond::Cs => Some(crate::ir::Cond::Ls),
        crate::ir::Cond::Ls => Some(crate::ir::Cond::Cs),
        _ => None,
    };
    swapped.is_some_and(|cond| condition(cond, rhs, lhs, ctx) == condition(guard, a, b, ctx))
}

fn same_test_width(
    cond: crate::ir::Cond,
    lhs: &Expr,
    rhs: &Expr,
    first_lhs: &Expr,
    first_rhs: &Expr,
    ctx: &Ctx<'_>,
) -> bool {
    let bits = crate::ir::semantics::operand_width(first_lhs, first_rhs);
    bits == crate::ir::semantics::operand_width(lhs, rhs)
        || (matches!(cond, crate::ir::Cond::Eq | crate::ir::Cond::Ne)
            && expr::fits(first_lhs, bits, ctx)
            && expr::fits(first_rhs, bits, ctx))
}

fn full_reads(expr: &Expr, register: u16) -> bool {
    if let Expr::Reg { index, width } = expr
        && *index == register
    {
        return *width == 64;
    }
    crate::ir::visit::children(expr)
        .into_iter()
        .all(|child| full_reads(child, register))
}

fn test_operand(expr: &Expr) -> bool {
    match expr {
        Expr::Reg { .. } | Expr::Const(_) => true,
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(_)) => test_operand(lhs),
        _ => false,
    }
}

// A continue may share the for-step only when it has the identical
// register update immediately before it. Nested loops keep their own steps.
fn move_continue_steps(nodes: &mut Vec<Node>, step: &Stmt) -> bool {
    let Stmt::Assign { dest, value } = step else {
        return false;
    };
    let mut index = 0;
    while index < nodes.len() {
        match &mut nodes[index] {
            Node::Label(_) => return false,
            Node::Stmt(Stmt::Br { .. } | Stmt::Brif { .. } | Stmt::BrIndirect { .. }) => {
                return false;
            }
            Node::Continue => {
                if index == 0
                    || !matches!(&nodes[index - 1],
                    Node::Stmt(Stmt::Assign { dest: other, value: updated })
                    if other.index == dest.index && other.width == dest.width && updated == value)
                {
                    return false;
                }
                nodes.remove(index - 1);
                index -= 1;
            }
            Node::If { then, els, .. } => {
                if !move_continue_steps(then, step) || !move_continue_steps(els, step) {
                    return false;
                }
            }
            Node::Switch { arms, default, .. } => {
                for (_, body) in arms {
                    if !move_continue_steps(body, step) {
                        return false;
                    }
                }
                if let Some(body) = default
                    && !move_continue_steps(body, step)
                {
                    return false;
                }
            }
            _ => {}
        }
        index += 1;
    }
    true
}

/// Whether a `continue` in `nodes` goes to the loop they are the body of,
/// rather than to one nested in it.
fn continues(nodes: &[Node]) -> bool {
    nodes.iter().any(|node| match node {
        Node::Continue => true,
        Node::If { then, els, .. } => continues(then) || continues(els),
        Node::Switch { arms, default, .. } => {
            arms.iter().any(|(_, body)| continues(body))
                || default.as_ref().is_some_and(|body| continues(body))
        }
        _ => false,
    })
}

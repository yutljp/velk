mod loops;

use super::{
    BinOp, Ctx, Expr, Node, Stmt, calls, condition, conformed, expr, int, narrow_write,
    render_stmt, sanitize, type_of,
};

/// The `case` labels for `values`: a run of three or more consecutive values
/// reads as one range, `case 2 ... 9`.
pub(super) fn case_labels(values: &[i64], signed: bool) -> Vec<String> {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let mut labels = Vec::new();
    let mut start = 0;
    while start < sorted.len() {
        let mut end = start;
        while end + 1 < sorted.len()
            && sorted[end].checked_add(1) == Some(sorted[end + 1])
            && (signed || sorted[end] != -1)
        {
            end += 1;
        }
        if end - start >= 2 {
            labels.push(format!("case {} ... {}", sorted[start], sorted[end]));
        } else {
            labels.extend(
                sorted[start..=end]
                    .iter()
                    .map(|value| format!("case {value}")),
            );
        }
        start = end + 1;
    }
    labels
}

pub(super) fn indent(depth: usize, out: &mut String) {
    for _ in 0..depth {
        out.push_str("    ");
    }
}

/// Whether the statements up to the next call leave `rax` alone, and the
/// call, whose arguments are known, reads no more of it than `al`.
fn only_vector_count(rest: &[Node]) -> bool {
    for node in rest {
        let Node::Stmt(stmt) = node else {
            return false;
        };
        let (writes, reads) = crate::ir::visit::statement_registers(stmt);
        match stmt {
            Stmt::Call { args: Some(_), .. } => {
                return !stmt.operands().into_iter().any(|operand| {
                    let mut read = std::collections::HashSet::new();
                    crate::ir::visit::collect_reads(operand, &mut read);
                    read.contains(&crate::arch::RETURN)
                });
            }
            _ if writes.contains(&crate::arch::RETURN) || reads.contains(&crate::arch::RETURN) => {
                return false;
            }
            Stmt::Assign { .. } | Stmt::Store { .. } => {}
            _ => return false,
        }
    }
    false
}

pub(super) fn render_nodes(nodes: &[Node], depth: usize, out: &mut String, ctx: &Ctx<'_>) {
    let mut index = 0;
    while index < nodes.len() {
        if let (Node::Stmt(stmt), Some(next)) = (&nodes[index], nodes.get(index + 1))
            && let Some(text) = super::machine::in_condition(stmt, next, depth, ctx)
        {
            out.push_str(&text);
            index += 2;
            continue;
        }
        if let Some((count, text)) = super::aggregates::render(&nodes[index..], ctx)
            .or_else(|| super::transfers::render(&nodes[index..], ctx))
        {
            for line in text.lines() {
                indent(depth, out);
                out.push_str(line);
                out.push('\n');
            }
            index += count;
            continue;
        }
        // A compare-and-exchange: the old value read, and the new one stored
        // in its place when the old one was the expected one.
        if let (
            Node::Stmt(Stmt::Assign {
                dest,
                value:
                    loaded @ Expr::Load {
                        addr,
                        width,
                        signed: false,
                    },
            }),
            Some(Node::Stmt(Stmt::Store {
                addr: stored,
                width: stored_width,
                value:
                    Expr::Select {
                        cond: crate::ir::Cond::Eq,
                        lhs,
                        rhs: expected,
                        then: replacement,
                        els,
                    },
            })),
        ) = (&nodes[index], nodes.get(index + 1))
            && stored == addr.as_ref()
            && stored_width == width
            && expr::copy_address(addr, *width, ctx).is_none()
            && expr::fits(expected, u32::from(*width) * 8, ctx)
            && matches!(lhs.as_ref(), Expr::Reg { index: read, .. } if *read == dest.index)
            && matches!(els.as_ref(), Expr::Reg { index: read, .. } if *read == dest.index)
        {
            indent(depth, out);
            let address = format!(
                "({} *){}",
                type_of(*width, false),
                expr::print_value_at(addr, ctx, 64, false)
                    .within(12, false)
                    .text
            );
            let bits = u32::from(*width) * 8;
            let expected = expr::print_value_at(expected, ctx, bits, false).address_integer();
            let replacement = expr::print_value_at(replacement, ctx, bits, false).address_integer();
            let call = int::Printed::new(
                format!(
                    "__sync_val_compare_and_swap({address}, {}, {})",
                    expected.text, replacement.text
                ),
                int::Int::promoted(bits, false),
                int::ALL,
                13,
            );
            let pointer = ctx.pointer_types.get(&dest.index).map(String::as_str);
            out.push_str(&format!(
                "{} = {};\n",
                ctx.register(dest.index, dest.width),
                narrow_write(
                    dest.index,
                    dest.width,
                    conformed(loaded, call, pointer, ctx),
                    ctx
                )
            ));
            index += 2;
            continue;
        }
        // A value assigned only to be returned right away reads as returned;
        // a constant also through the mask a narrow return puts on it.
        if let (
            Node::Stmt(Stmt::Assign { dest, value }),
            Some(Node::Stmt(Stmt::Ret { value: returned })),
        ) = (&nodes[index], nodes.get(index + 1))
            && dest.index >= crate::ir::VARIABLE_BASE
            && !ctx.void_return
            && let Some(value) = match returned {
                Expr::Reg { index: read, width } if *read == dest.index => (dest.width == *width
                    || matches!(value, Expr::Const(c) if dest.width < 64 && *c >> dest.width == 0))
                .then(|| value.clone()),
                Expr::Bin {
                    op: BinOp::And,
                    lhs,
                    rhs,
                } => match (lhs.as_ref(), rhs.as_ref(), value) {
                    (Expr::Reg { index: read, .. }, Expr::Const(mask), Expr::Const(c))
                        if *read == dest.index =>
                    {
                        Some(Expr::Const(c & mask))
                    }
                    _ => None,
                },
                _ => None,
            }
        {
            indent(depth, out);
            out.push_str(&render_stmt(&Stmt::Ret { value }, ctx));
            out.push('\n');
            index += 2;
            continue;
        }
        // A trap right after a call is the one a compiler puts after a call
        // that never returns; the call already ends the path.
        if matches!(nodes[index], Node::Stmt(Stmt::Trap))
            && index > 0
            && matches!(nodes[index - 1], Node::Stmt(Stmt::Call { .. }))
        {
            index += 1;
            continue;
        }
        // Consecutive instructions the lifter could not model read as one
        // note instead of one comment per instruction.
        if let Node::Stmt(Stmt::Unsupported { text, .. }) = &nodes[index] {
            let mut merged = text.clone();
            let mut count = 1;
            while let Some(Node::Stmt(Stmt::Unsupported { text, .. })) = nodes.get(index + count) {
                merged.push_str(", ");
                merged.push_str(text);
                count += 1;
            }
            indent(depth, out);
            if count > 1 {
                out.push_str(&format!(
                    "/* unsupported ({} steps): {} */\n",
                    count, merged
                ));
            } else {
                out.push_str(&format!("/* unsupported: {} */\n", merged));
            }
            index += count;
            continue;
        }
        // On x86-64, `al` tells a variadic callee how many vector registers
        // carry arguments; setting it is no part of the call as C writes it.
        if ctx.isa == crate::loader::Isa::X86_64
            && let Some(Node::Stmt(Stmt::Assign {
                dest,
                value: Expr::Const(0..=8),
            })) = nodes.get(index)
            && dest.index == crate::arch::RETURN
            && only_vector_count(&nodes[index + 1..])
        {
            index += 1;
            continue;
        }
        // A counter set before a loop that tests it and steps it last reads
        // as a `for`.
        if let Node::Stmt(init) = &nodes[index] {
            let mut next = index + 1;
            while let Some(Node::Stmt(stmt @ Stmt::Assign { .. })) = nodes.get(next) {
                let Stmt::Assign {
                    dest,
                    value: Expr::Const(_),
                } = init
                else {
                    break;
                };
                let (writes, reads) = crate::ir::visit::statement_registers(stmt);
                if dest.width != 64 || writes.contains(&dest.index) || reads.contains(&dest.index) {
                    break;
                }
                next += 1;
            }
            if let Some(looped) = nodes.get(next)
                && let Some(text) = loops::for_loop(init, looped, &nodes[..next], depth, ctx)
            {
                render_nodes(&nodes[index + 1..next], depth, out, ctx);
                out.push_str(&text);
                index = next + 1;
                continue;
            }
        }
        // A call whose returned value the next statement takes reads as one
        // expression: `x = f(a)` or `return f(a)`.
        if let (
            Some(Node::Stmt(
                call @ Stmt::Call {
                    target: Some(target),
                    through: None,
                    ..
                },
            )),
            Some(Node::Stmt(Stmt::Assign { dest, value })),
            Some(Node::Stmt(Stmt::Ret { value: returned })),
        ) = (nodes.get(index), nodes.get(index + 1), nodes.get(index + 2))
            && ctx.callee_signatures.contains_key(target)
            && dest.index >= crate::ir::VARIABLE_BASE
            && *returned == Expr::reg(dest.index, dest.width)
            && let (Some(stored), Some(result)) = (ctx.declared.get(&dest.index), ctx.returned)
            && stored.integer
            && result.integer
            && stored.bits == result.bits
            && u32::from(dest.width) >= stored.bits
            && let Some(text) = calls::call_in_reader(
                call,
                &Node::Stmt(Stmt::Ret {
                    value: value.clone(),
                }),
                depth,
                ctx,
            )
        {
            out.push_str(&text);
            index += 3;
            continue;
        }
        if let (Some(Node::Stmt(call @ Stmt::Call { .. })), Some(Node::Stmt(next))) =
            (nodes.get(index), nodes.get(index + 1))
            && let Some(text) = fused_call(call, next, ctx)
        {
            indent(depth, out);
            out.push_str(&text);
            out.push('\n');
            index += 2;
            continue;
        }
        if let (Some(Node::Stmt(call @ Stmt::Call { .. })), Some(next)) =
            (nodes.get(index), nodes.get(index + 1))
            && let Some(text) = calls::call_in_reader(call, next, depth, ctx)
        {
            out.push_str(&text);
            index += 2;
            continue;
        }
        render_node(&nodes[index], depth, out, ctx);
        index += 1;
    }
}

/// `call` and the statement after it as one, when that statement only takes
/// the call's result.
fn fused_call(call: &Stmt, next: &Stmt, ctx: &Ctx<'_>) -> Option<String> {
    if let Stmt::Ret { value } = next {
        return calls::returned(call, value, ctx)
            .map(|text| format!("{text}{}", via_comment(call, ctx)));
    }
    let Some(result) = calls::scalar_fusion(call, ctx) else {
        return None;
    };
    if result.width != 64
        || ctx.floats.contains_key(&result.index)
        || ctx
            .declared
            .get(&result.index)
            .is_some_and(|declared| declared.bits < 64)
    {
        return None;
    }
    let Some(call_text) = calls::captured(call, ctx) else {
        return None;
    };
    let comment = via_comment(call, ctx);
    let takes = |value: &Expr| *value == Expr::reg(result.index, result.width);
    match next {
        Stmt::Store {
            value, width: 8, ..
        } if result.index < crate::ir::VARIABLE_BASE
            && ctx.read_once.contains(&result.index)
            && takes(value) =>
        {
            let stored = render_stmt(next, ctx);
            let Some((target, _)) = stored.split_once(" = ") else {
                return None;
            };
            Some(format!("{target} = {call_text};{comment}"))
        }
        Stmt::Assign { value, dest }
            if result.index < crate::ir::VARIABLE_BASE
                && ctx.read_once.contains(&result.index)
                && dest.width == 64
                && takes(value) =>
        {
            let assigned = render_stmt(next, ctx);
            let Some((target, _)) = assigned.split_once(" = ") else {
                return None;
            };
            Some(format!("{target} = {call_text};{comment}"))
        }
        _ => None,
    }
}

/// What a call that was or is indirect reads its callee's address from,
/// as a comment after it.
pub(super) fn via_comment(stmt: &Stmt, ctx: &Ctx<'_>) -> String {
    let Stmt::Call {
        target,
        via: Some(via),
        ..
    } = stmt
    else {
        return String::new();
    };
    let name = |addr: u64| {
        ctx.symbols
            .functions
            .get(&addr)
            .map_or_else(|| format!("sub_{addr:x}"), |name| sanitize(name))
    };
    match target {
        Some(_) => format!(" /* via {} */", via.describe(&name)),
        None => format!(" /* {} */", via.describe(&name)),
    }
}

pub(super) fn render_node(node: &Node, depth: usize, out: &mut String, ctx: &Ctx<'_>) {
    if let Node::If {
        cond,
        lhs,
        rhs,
        then,
        els,
    } = node
        && els.is_empty()
        && let [Node::Stmt(init), looped @ Node::DoWhile { .. }] = then.as_slice()
    {
        let guarded = Node::If {
            cond: *cond,
            lhs: lhs.clone(),
            rhs: rhs.clone(),
            then: vec![looped.clone()],
            els: Vec::new(),
        };
        if let Some(text) = loops::for_loop(init, &guarded, &[], depth + 1, ctx) {
            indent(depth, out);
            out.push_str(&format!("if ({}) {{\n", condition(*cond, lhs, rhs, ctx)));
            out.push_str(&text);
            indent(depth, out);
            out.push_str("}\n");
            return;
        }
    }
    match node {
        Node::Stmt(stmt) => {
            let text = format!("{}{}", render_stmt(stmt, ctx), via_comment(stmt, ctx));
            if !text.is_empty() {
                for line in text.lines() {
                    indent(depth, out);
                    out.push_str(line);
                    out.push('\n');
                }
            }
        }
        Node::Label(address) => {
            if let Some(sites) = ctx.landing_pads.get(address) {
                let ranges: Vec<String> = sites
                    .iter()
                    .map(|(start, end)| format!("0x{start:x}-0x{end:x}"))
                    .collect();
                indent(depth.saturating_sub(1), out);
                out.push_str(&format!(
                    "/* landing pad: an exception thrown by a call at {} arrives here */\n",
                    ranges.join(", ")
                ));
            }
            indent(depth.saturating_sub(1), out);
            out.push_str(&format!("L_{address:x}:\n"));
        }
        Node::If {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => {
            indent(depth, out);
            out.push_str(&format!("if ({}) {{\n", condition(*cond, lhs, rhs, ctx)));
            render_nodes(then, depth + 1, out, ctx);
            // An `else` holding only another `if` continues the chain.
            let mut els = els;
            while let [
                Node::If {
                    cond,
                    lhs,
                    rhs,
                    then,
                    els: rest,
                },
            ] = els.as_slice()
            {
                indent(depth, out);
                out.push_str(&format!(
                    "}} else if ({}) {{\n",
                    condition(*cond, lhs, rhs, ctx)
                ));
                render_nodes(then, depth + 1, out, ctx);
                els = rest;
            }
            if !els.is_empty() {
                indent(depth, out);
                out.push_str("} else {\n");
                render_nodes(els, depth + 1, out, ctx);
            }
            indent(depth, out);
            out.push_str("}\n");
        }
        // A switch whose cases only leave it runs its default when the value
        // is none of them.
        Node::Switch {
            index,
            arms,
            default: Some(default),
        } if !arms.is_empty()
            && arms.iter().map(|(values, _)| values.len()).sum::<usize>() <= 4
            && arms
                .iter()
                .all(|(_, body)| matches!(body.as_slice(), [Node::Break]))
            && let rest = match default.split_last() {
                Some((Node::Break, rest)) => rest,
                _ => default.as_slice(),
            }
            && !super::structure::breaks_out(rest) =>
        {
            let tests: Vec<String> = arms
                .iter()
                .flat_map(|(values, _)| values)
                .map(|value| {
                    condition(crate::ir::Cond::Ne, index, &Expr::Const(*value as u64), ctx)
                })
                .collect();
            indent(depth, out);
            out.push_str(&format!("if ({}) {{\n", tests.join(" && ")));
            render_nodes(rest, depth + 1, out, ctx);
            indent(depth, out);
            out.push_str("}\n");
        }
        Node::Switch {
            index,
            arms,
            default,
        } => {
            indent(depth, out);
            let printed = expr::switch_index(index, ctx);
            out.push_str(&format!("switch ({}) {{\n", printed.text));
            for (values, body) in arms {
                for label in case_labels(values, printed.ty.signed) {
                    indent(depth, out);
                    out.push_str(&format!("{label}:\n"));
                }
                render_nodes(body, depth + 1, out, ctx);
                if super::structure::case_falls_through(body) {
                    indent(depth + 1, out);
                    out.push_str("/* fallthrough */\n");
                }
            }
            // Cases taking every value a mask leaves need no default.
            let covered = match index {
                Expr::Bin {
                    op: crate::ir::BinOp::And,
                    rhs,
                    ..
                } => match **rhs {
                    Expr::Const(mask) if mask < 4096 => (0..=mask as i64)
                        .all(|value| arms.iter().any(|(values, _)| values.contains(&value))),
                    _ => false,
                },
                _ => false,
            };
            if default.is_some() || !covered {
                indent(depth, out);
                out.push_str("default:\n");
            }
            match default {
                Some(body) => render_nodes(body, depth + 1, out, ctx),
                None if covered => {}
                // A table with no bounds check: the compiler knew no other
                // value reaches it.
                None => {
                    indent(depth + 1, out);
                    out.push_str("__builtin_unreachable();\n");
                }
            }
            indent(depth, out);
            out.push_str("}\n");
        }
        Node::Break => {
            indent(depth, out);
            out.push_str("break;\n");
        }
        Node::Continue => {
            indent(depth, out);
            out.push_str("continue;\n");
        }
        Node::Forever { body } => {
            indent(depth, out);
            out.push_str("for (;;) {\n");
            render_nodes(body, depth + 1, out, ctx);
            indent(depth, out);
            out.push_str("}\n");
        }
        Node::While {
            prefix,
            cond,
            lhs,
            rhs,
            body,
        } => {
            indent(depth, out);
            if prefix.is_empty() {
                out.push_str(&format!("while ({}) {{\n", condition(*cond, lhs, rhs, ctx)));
                render_nodes(body, depth + 1, out, ctx);
            } else {
                out.push_str("while (true) {\n");
                render_nodes(prefix, depth + 1, out, ctx);
                indent(depth + 1, out);
                out.push_str(&format!(
                    "if ({}) break;\n",
                    condition(cond.invert(), lhs, rhs, ctx)
                ));
                render_nodes(body, depth + 1, out, ctx);
            }
            indent(depth, out);
            out.push_str("}\n");
        }
        Node::DoWhile {
            cond,
            lhs,
            rhs,
            body,
        } => {
            indent(depth, out);
            out.push_str("do {\n");
            render_nodes(body, depth + 1, out, ctx);
            indent(depth, out);
            out.push_str(&format!(
                "}} while ({});\n",
                condition(*cond, lhs, rhs, ctx)
            ));
        }
    }
}

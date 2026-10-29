//! Scalar string effects proved from loop state and memory accesses.

use std::collections::BTreeMap;

use crate::ir::{BinOp, Cond, Expr, Stmt};
use crate::render::{Ctx, InlineFunction, Node, render_expr};

mod bounded;
mod loops;
#[cfg(test)]
mod tests;

type Values = BTreeMap<u16, Expr>;

pub(super) fn is_current_function(function: &str, ctx: &Ctx<'_>) -> bool {
    let name = ctx
        .symbols
        .functions
        .get(&ctx.ir.addr)
        .or(ctx.ir.name.as_ref());
    match name {
        Some(name) => crate::render::sanitize(name) == function,
        None => false,
    }
}

fn constant(value: &Expr, predicate: &impl Fn(Cond, &Expr, &Expr) -> Option<bool>) -> Option<u64> {
    match value {
        Expr::Const(value) => Some(*value),
        Expr::Select {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => {
            let Some(yes) = predicate(*cond, lhs, rhs) else {
                return None;
            };
            constant(if yes { then } else { els }, predicate)
        }
        Expr::Bin { op, lhs, rhs } => {
            let Some(a) = constant(lhs, predicate) else {
                return None;
            };
            let Some(b) = constant(rhs, predicate) else {
                return None;
            };
            let Expr::Const(value) = Expr::bin(*op, Expr::Const(a), Expr::Const(b)) else {
                return None;
            };
            Some(value)
        }
        Expr::SignExtend { value, width } => {
            let Some(value) = constant(value, predicate) else {
                return None;
            };
            Some(crate::ir::semantics::sign_extend(value, u32::from(*width)) as u64)
        }
        _ => None,
    }
}

fn argument(value: &Expr, function: &str, ctx: &Ctx<'_>) -> String {
    let printed = crate::render::expr::print(value, ctx, 64);
    if let Expr::Reg { index, width: 64 } = value
        && let Some(ty) = ctx.pointer_types.get(index)
        && ((function == "memcmp" && !ty.contains("volatile") && !ty.contains('('))
            || ty == "char *"
            || ty == "const char *")
        && printed.is_pointer()
    {
        return printed.text;
    }
    format!("(const char *)(uint64_t)({})", render_expr(value, ctx))
}

fn comparison(call: &str, function: &str, bytes: Option<u64>, ctx: &Ctx<'_>) -> String {
    let mut reserved: std::collections::HashSet<String> =
        ctx.names.values().map(|name| (*name).to_owned()).collect();
    reserved.extend(ctx.slots.values().cloned());
    for block in &ctx.ir.blocks {
        for stmt in &block.stmts {
            let (writes, reads) = crate::ir::visit::statement_registers(stmt);
            for index in writes.into_iter().chain(reads) {
                reserved.insert(ctx.register(index, 64));
            }
        }
    }
    let name = crate::render::function::vacant_name("comparison", &mut reserved);
    ctx.inline_functions.borrow_mut().push(InlineFunction {
        function: function.to_owned(),
        bytes,
    });
    format!("    int {name} = {call};\n    return ({name} > 0) - ({name} < 0);\n")
}

// Addition is modulo 2^64, including pointer values in the machine IR.
fn sum(value: Expr) -> Expr {
    fn collect(value: Expr, negative: bool, terms: &mut Vec<(Expr, u64)>, constant: &mut u64) {
        match value {
            Expr::Const(value) => {
                *constant = if negative {
                    constant.wrapping_sub(value)
                } else {
                    constant.wrapping_add(value)
                };
            }
            Expr::Bin {
                op: BinOp::Add,
                lhs,
                rhs,
            } => {
                collect(*lhs, negative, terms, constant);
                collect(*rhs, negative, terms, constant);
            }
            Expr::Bin {
                op: BinOp::Sub,
                lhs,
                rhs,
            } => {
                collect(*lhs, negative, terms, constant);
                collect(*rhs, !negative, terms, constant);
            }
            value => {
                let coefficient = if negative { u64::MAX } else { 1 };
                if let Some((_, count)) = terms.iter_mut().find(|(term, _)| *term == value) {
                    *count = count.wrapping_add(coefficient);
                } else {
                    terms.push((value, coefficient));
                }
            }
        }
    }
    let mut terms = Vec::new();
    let mut constant = 0;
    collect(value, false, &mut terms, &mut constant);
    terms.retain(|(_, coefficient)| *coefficient != 0);
    terms.sort_by_cached_key(|(term, _)| format!("{term:?}"));
    let mut result = Expr::Const(constant);
    for (term, coefficient) in terms {
        result = if coefficient == u64::MAX {
            Expr::bin(BinOp::Sub, result, term)
        } else {
            Expr::bin(
                BinOp::Add,
                result,
                Expr::bin(BinOp::Mul, term, Expr::Const(coefficient)),
            )
        };
    }
    result
}

fn add(lhs: Expr, rhs: Expr) -> Expr {
    sum(Expr::bin(BinOp::Add, lhs, rhs))
}

fn subtract(lhs: Expr, rhs: Expr) -> Expr {
    sum(Expr::bin(BinOp::Sub, lhs, rhs))
}

fn byte(value: &Expr) -> bool {
    matches!(
        value,
        Expr::Load {
            width: 1,
            signed: false,
            ..
        }
    ) || matches!(value, Expr::Const(value) if *value <= 255)
        || matches!(value, Expr::Bin { op: BinOp::And, rhs, .. } if matches!(rhs.as_ref(), Expr::Const(mask) if *mask <= 255))
}

fn narrow(value: Expr, bits: u8) -> Expr {
    if let Expr::SignExtend {
        value: inner,
        width,
    } = &value
        && bits <= *width
    {
        return narrow(*inner.clone(), bits);
    }
    if bits == 64 || (bits >= 8 && byte(&value)) {
        value
    } else {
        let mask = crate::ir::semantics::mask(u32::from(bits));
        if let Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } = &value
            && let Expr::Const(previous) = rhs.as_ref()
        {
            return Expr::bin(BinOp::And, *lhs.clone(), Expr::Const(mask & previous));
        }
        Expr::bin(BinOp::And, value, Expr::Const(mask))
    }
}

fn evaluate(value: &Expr, values: &Values, reads: &mut Vec<Expr>) -> Option<Expr> {
    let result = match value {
        Expr::Const(_) => Some(value.clone()),
        Expr::Reg { index, width } => {
            let Some(value) = values.get(index) else {
                return None;
            };
            Some(narrow(value.clone(), *width))
        }
        Expr::Bin { op, lhs, rhs } => {
            if !matches!(
                op,
                BinOp::Add | BinOp::Sub | BinOp::And | BinOp::Or | BinOp::Xor
            ) {
                return None;
            }
            let Some(lhs) = evaluate(lhs, values, reads) else {
                return None;
            };
            let Some(rhs) = evaluate(rhs, values, reads) else {
                return None;
            };
            Some(match op {
                BinOp::Add => add(lhs, rhs),
                BinOp::Sub => subtract(lhs, rhs),
                BinOp::And if matches!(rhs, Expr::Const(0xff)) => narrow(lhs, 8),
                BinOp::And if matches!(rhs, Expr::Const(0xffff)) => narrow(lhs, 16),
                BinOp::And if matches!(rhs, Expr::Const(0xffff_ffff)) => narrow(lhs, 32),
                _ => Expr::bin(*op, lhs, rhs),
            })
        }
        Expr::Load {
            addr,
            width: 1,
            signed: false,
        } => {
            let Some(addr) = evaluate(addr, values, reads) else {
                return None;
            };
            reads.push(addr.clone());
            Some(Expr::Load {
                addr: Box::new(addr),
                width: 1,
                signed: false,
            })
        }
        Expr::Select {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => {
            let bits = crate::ir::semantics::operand_width(lhs, rhs);
            let Some(lhs) = evaluate(lhs, values, reads) else {
                return None;
            };
            let Some(rhs) = evaluate(rhs, values, reads) else {
                return None;
            };
            let Some(then) = evaluate(then, values, reads) else {
                return None;
            };
            let Some(els) = evaluate(els, values, reads) else {
                return None;
            };
            if matches!(cond, Cond::Lt | Cond::Le | Cond::Gt | Cond::Ge)
                && (bits < 32 || !byte(&lhs) || !byte(&rhs))
            {
                return None;
            }
            Some(Expr::Select {
                cond: *cond,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
                then: Box::new(then),
                els: Box::new(els),
            })
        }
        Expr::SignExtend { value, width } => {
            let Some(value) = evaluate(value, values, reads) else {
                return None;
            };
            if byte(&value) && *width >= 16 {
                return Some(value);
            }
            if let Expr::Const(value) = value {
                return Some(Expr::Const(
                    crate::ir::semantics::sign_extend(value, u32::from(*width)) as u64,
                ));
            }
            Some(Expr::SignExtend {
                value: Box::new(value),
                width: *width,
            })
        }
        _ => None,
    };
    match result {
        Some(value) if crate::passes::copies::expr_size(&value) <= 128 => Some(value),
        _ => None,
    }
}

fn assignments(nodes: &[Node], values: &mut Values, reads: &mut Vec<Expr>) -> bool {
    for node in nodes {
        let Node::Stmt(Stmt::Assign { dest, value, .. }) = node else {
            return false;
        };
        let Some(value) = evaluate(value, values, reads) else {
            return false;
        };
        if dest.width == 0 || dest.width > 64 {
            return false;
        }
        values.insert(dest.index, narrow(value, dest.width));
    }
    true
}

fn zero_test(
    cond: Cond,
    lhs: &Expr,
    rhs: &Expr,
    values: &Values,
    reads: &mut Vec<Expr>,
) -> Option<Expr> {
    if cond != Cond::Ne {
        return None;
    }
    let Some(lhs) = evaluate(lhs, values, reads) else {
        return None;
    };
    let Some(rhs) = evaluate(rhs, values, reads) else {
        return None;
    };
    let ((value, Expr::Const(0)) | (Expr::Const(0), value)) = (lhs, rhs) else {
        return None;
    };
    let Expr::Load { addr, width: 1, .. } = value else {
        return None;
    };
    Some(*addr)
}

fn returned(nodes: &[Node], values: &Values) -> Option<Expr> {
    let Some((Node::Stmt(Stmt::Ret { value, .. }), prefix)) = nodes.split_last() else {
        return None;
    };
    let mut values = values.clone();
    let mut reads = Vec::new();
    if !assignments(prefix, &mut values, &mut reads) {
        return None;
    }
    let result = evaluate(value, &values, &mut reads);
    if !reads.is_empty() {
        return None;
    }
    result
}

fn empty_return(nodes: &[Node]) -> bool {
    matches!(
        nodes,
        [Node::Stmt(Stmt::Ret {
            value: Expr::Const(0),
            ..
        })]
    )
}

fn length(nodes: &[Node], initial: &Values, iteration: u16) -> Option<Expr> {
    for (index, node) in nodes.iter().enumerate() {
        if let Node::If {
            cond: Cond::Ne,
            lhs,
            rhs,
            then,
            els,
            ..
        } = node
            && els.is_empty()
            && empty_return(&nodes[index + 1..])
        {
            let mut flattened = nodes[..index].to_vec();
            flattened.push(Node::If {
                cond: Cond::Eq,
                lhs: lhs.clone(),
                rhs: rhs.clone(),
                then: nodes[index + 1..].to_vec(),
                els: Vec::new(),
                at: None,
            });
            flattened.extend_from_slice(then);
            return length(&flattened, initial, iteration);
        }
    }
    let Some(loop_index) = nodes
        .iter()
        .position(|node| matches!(node, Node::DoWhile { .. }))
    else {
        return None;
    };
    let mut values = initial.clone();
    let mut prefix_reads = Vec::new();
    let mut guard = None;
    for node in &nodes[..loop_index] {
        if let Node::If {
            cond: Cond::Eq,
            lhs,
            rhs,
            then,
            els,
            ..
        } = node
            && els.is_empty()
            && empty_return(then)
            && guard.is_none()
        {
            let Some(addr) = zero_test(Cond::Ne, lhs, rhs, &values, &mut prefix_reads) else {
                return None;
            };
            guard = Some(addr);
        } else if !assignments(std::slice::from_ref(node), &mut values, &mut prefix_reads) {
            return None;
        }
    }
    if prefix_reads.iter().any(|read| Some(read) != guard.as_ref()) {
        return None;
    }
    let Node::DoWhile {
        cond,
        lhs,
        rhs,
        body,
        ..
    } = &nodes[loop_index]
    else {
        return None;
    };
    let mut after = values.clone();
    if !assignments(body, &mut after, &mut Vec::new()) {
        return None;
    }
    let mut carried = Vec::new();
    let mut symbolic = values.clone();
    for (index, before) in &values {
        if let Some(value) = after.get(index)
            && subtract(value.clone(), before.clone()) == Expr::Const(1)
        {
            symbolic.insert(*index, add(before.clone(), Expr::reg(iteration, 64)));
            carried.push(*index);
        }
    }
    if carried.is_empty() {
        return None;
    }
    // Other changed values must be assigned before the next iteration reads them.
    let mut defined = std::collections::HashSet::new();
    for node in body {
        let Node::Stmt(stmt) = node else { return None };
        let (writes, reads) = crate::ir::visit::statement_registers(stmt);
        for read in reads {
            if !defined.contains(&read)
                && !carried.contains(&read)
                && values.get(&read) != after.get(&read)
            {
                return None;
            }
        }
        defined.extend(writes);
    }
    let mut reads = Vec::new();
    if !assignments(body, &mut symbolic, &mut reads) {
        return None;
    }
    let Some(address) = zero_test(*cond, lhs, rhs, &symbolic, &mut reads) else {
        return None;
    };
    for index in carried {
        let expected = add(
            add(values[&index].clone(), Expr::reg(iteration, 64)),
            Expr::Const(1),
        );
        if symbolic.get(&index) != Some(&expected) {
            return None;
        }
    }
    if reads.iter().any(|read| *read != address) {
        return None;
    }
    let first = subtract(address, Expr::reg(iteration, 64));
    let guarded = guard.is_some();
    let source = if let Some(guard) = guard {
        if first != add(guard.clone(), Expr::Const(1)) {
            return None;
        }
        guard
    } else {
        first
    };
    let mut source_reads = std::collections::HashSet::new();
    crate::ir::visit::collect_reads(&source, &mut source_reads);
    if crate::passes::copies::reads_memory(&source) || source_reads.contains(&iteration) {
        return None;
    }
    let Some(result) = returned(&nodes[loop_index + 1..], &symbolic) else {
        return None;
    };
    let expected = add(Expr::reg(iteration, 64), Expr::Const(u64::from(guarded)));
    if result != expected {
        return None;
    }
    Some(source)
}

pub(super) fn render(nodes: &[Node], ctx: &Ctx<'_>) -> Option<String> {
    if ctx.void_return || ctx.float_return.is_some() || crate::arch::pointer_bytes(ctx.isa) != 8 {
        return None;
    }
    if ctx
        .ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .take(257)
        .count()
        > 256
    {
        return None;
    }
    let mut partial = BTreeMap::new();
    for param in &ctx.ir.params {
        if let Some((bits, _)) = param.ty.integer()
            && bits < 64
        {
            partial.insert(param.index, bits as u8);
        }
    }
    for stmt in ctx.ir.blocks.iter().flat_map(|block| &block.stmts) {
        if let Stmt::Assign { dest, .. } = stmt
            && dest.width < 32
        {
            partial
                .entry(dest.index)
                .and_modify(|width: &mut u8| *width = (*width).min(dest.width))
                .or_insert(dest.width);
        }
    }
    fn narrow_reads(value: &Expr, widths: &BTreeMap<u16, u8>, demand: u8) -> bool {
        if let Expr::Reg { index, width } = value
            && widths
                .get(index)
                .is_some_and(|written| (*width).min(demand) > *written)
        {
            return false;
        }
        if let Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } = value
            && let Expr::Const(mask) = rhs.as_ref()
        {
            let bits = (64 - mask.leading_zeros()) as u8;
            return narrow_reads(lhs, widths, demand.min(bits));
        }
        if let Expr::SignExtend { value, width } = value {
            return narrow_reads(value, widths, demand.min(*width));
        }
        crate::ir::visit::children(value)
            .iter()
            .all(|child| narrow_reads(child, widths, 64))
    }
    if ctx
        .ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .any(|stmt| {
            stmt.operands()
                .iter()
                .any(|value| !narrow_reads(value, &partial, 64))
        })
    {
        return None;
    }
    let mut initial = Values::new();
    for param in &ctx.ir.params {
        if param.ty.integer().is_none() && !param.ty.is_pointer() {
            return None;
        }
        let value = Expr::reg(param.index, 64);
        initial.insert(
            param.index,
            match param.ty.integer() {
                Some((bits, signed)) if bits <= 64 => {
                    let value = narrow(value, bits as u8);
                    if signed && bits < 64 {
                        Expr::SignExtend {
                            value: Box::new(value),
                            width: bits as u8,
                        }
                    } else {
                        value
                    }
                }
                Some(_) => return None,
                None => value,
            },
        );
    }
    let Some(iteration) = crate::ir::visit::unused_temporaries(ctx.ir)
        .first()
        .copied()
    else {
        return None;
    };
    if let Some(text) = loops::render(nodes, &initial, iteration, ctx) {
        return Some(text);
    }
    if ctx.return_pointer_type.is_some() {
        return None;
    }
    if let Some(text) = bounded::render(nodes, &initial, ctx) {
        return Some(text);
    }
    let Some(source) = length(nodes, &initial, iteration) else {
        return None;
    };
    if is_current_function("strlen", ctx) {
        return None;
    }
    ctx.inline_functions.borrow_mut().push(InlineFunction {
        function: "strlen".to_owned(),
        bytes: None,
    });
    Some(format!(
        "    return __builtin_strlen({});\n",
        argument(&source, "strlen", ctx)
    ))
}

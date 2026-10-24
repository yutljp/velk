use super::{CType, Ctx, Expr, Node, Stmt, expr, naming};
use crate::ir::{BinOp, VARIABLE_BASE};
use std::collections::{HashMap, HashSet};

pub(super) fn single_use_loads(ir: &crate::ir::FunctionIr) -> HashSet<(u16, Expr)> {
    if !ir.blocks.iter().any(|block| {
        block.stmts.windows(2).any(|pair| {
            pair.iter().all(|stmt| {
                matches!(stmt, Stmt::Assign {
            dest, value: Expr::Load { width: 8, signed: false, .. }
        } if dest.width == 64 && dest.index >= VARIABLE_BASE)
            })
        })
    }) {
        return HashSet::new();
    }
    let live_in = crate::ir::cfg::live_in(ir);
    let mut eligible = HashMap::new();
    for (index, block) in ir.blocks.iter().enumerate() {
        let mut counts: HashMap<_, usize> = crate::ir::cfg::live_out(ir, &live_in, index)
            .into_iter()
            .map(|register| (register, 2))
            .collect();
        for stmt in block.stmts.iter().rev() {
            if let Stmt::Assign {
                dest,
                value: value @ Expr::Load { width: 8, .. },
            } = stmt
                && dest.width == 64
                && dest.index >= VARIABLE_BASE
            {
                let once = !crate::ir::cfg::opaque(block) && counts.get(&dest.index) == Some(&1);
                // Identical loads can occur in separate blocks. Every such
                // definition must qualify because structured output has no
                // original statement addresses.
                eligible
                    .entry((dest.index, value.clone()))
                    .and_modify(|allowed| *allowed &= once)
                    .or_insert(once);
            }
            let (writes, reads) = crate::ir::visit::statement_registers(stmt);
            for register in writes {
                counts.remove(&register);
            }
            for register in reads {
                let count = counts.entry(register).or_default();
                *count = count.saturating_add(1).min(2);
            }
        }
    }
    eligible
        .into_iter()
        .filter_map(|(key, allowed)| allowed.then_some(key))
        .collect()
}

// Only pure address arithmetic can be evaluated after the other loads.
fn address(value: &Expr, ctx: &Ctx<'_>) -> bool {
    let key = super::render_expr(value, ctx);
    if ctx.slots.contains_key(&key) || ctx.local_parts.contains_key(&key) {
        return false;
    }
    match value {
        Expr::Reg { index, width: 64 } => *index != crate::arch::stack_pointer(ctx.isa),
        Expr::Const(value) => {
            !ctx.symbols.data.contains_key(value)
                && !ctx.data_ranges.iter().any(|(start, size)| {
                    value
                        .checked_sub(*start)
                        .is_some_and(|offset| offset < *size)
                })
        }
        Expr::Bin {
            op: BinOp::Add | BinOp::Sub | BinOp::Mul,
            lhs,
            rhs,
        } => address(lhs, ctx) && address(rhs, ctx),
        _ => false,
    }
}

fn follows(first: &Expr, next: &Expr, bytes: u64) -> bool {
    let (base, start) = crate::passes::memory::split_offset(first);
    let (next_base, next_start) = crate::passes::memory::split_offset(next);
    let Ok(bytes) = i64::try_from(bytes) else {
        return false;
    };
    base == next_base && start.checked_add(bytes) == Some(next_start)
}

fn record(source: &Expr, destination: &Expr, bytes: u64, ctx: &Ctx<'_>) -> Option<String> {
    let Some(CType::Named(ty)) = naming::pointer_target(source, ctx) else {
        return None;
    };
    if naming::pointer_target(destination, ctx) != Some(CType::Named(ty.clone())) {
        return None;
    }
    let Some(name) = ty.strip_prefix("struct ") else {
        return None;
    };
    if ctx
        .arrays
        .get(name)
        .is_none_or(|layout| layout.size != bytes)
    {
        return None;
    }
    let mut fields: Vec<_> = ctx
        .members
        .values()
        .filter(|field| field.structure == name)
        .collect();
    fields.sort_by_key(|field| field.offset);
    let mut end = 0;
    for field in fields {
        // Structure assignment need not copy padding. Restrict this form to
        // records entirely covered by unsigned integer members.
        let CType::Int {
            bytes: width,
            signed: false,
        } = field.ty
        else {
            return None;
        };
        if !matches!(width, 1 | 2 | 4 | 8)
            || field.offset < 0
            || field.offset as u64 != end
            || field.width != u64::from(width)
            || !end.is_multiple_of(u64::from(width))
        {
            return None;
        }
        let Some(next) = end.checked_add(field.width) else {
            return None;
        };
        end = next;
    }
    (end == bytes).then_some(ty)
}

/// Complete scalar loads followed by their unchanged stores. A byte temporary
/// preserves every byte, including padding, and snapshots overlapping ranges.
pub(super) fn render(nodes: &[Node], ctx: &Ctx<'_>) -> Option<(usize, String)> {
    let mut loads: Vec<(u16, &Expr)> = Vec::new();
    let mut bytes = 0u64;
    for node in nodes.iter().take(4) {
        let Node::Stmt(Stmt::Assign {
            dest,
            value:
                Expr::Load {
                    addr,
                    width: 8,
                    signed: false,
                },
        }) = node
        else {
            break;
        };
        if dest.width != 64
            || dest.index < VARIABLE_BASE
            || !(ctx.read_once.contains(&dest.index)
                || ctx.transfer_values.contains(&(
                    dest.index,
                    Expr::Load {
                        addr: addr.clone(),
                        width: 8,
                        signed: false,
                    },
                )))
            || !address(addr, ctx)
            || loads.iter().any(|(index, _)| *index == dest.index)
        {
            break;
        }
        if let Some((_, first)) = loads.first()
            && !follows(first, addr, bytes)
        {
            break;
        }
        loads.push((dest.index, addr.as_ref()));
        bytes += 8;
    }
    if !matches!(loads.len(), 2 | 4) {
        return None;
    }
    let mut between = Vec::new();
    for node in nodes.iter().skip(loads.len()).take(4) {
        let Node::Stmt(stmt @ Stmt::Assign { dest, value }) = node else {
            break;
        };
        let mut reads = HashSet::new();
        crate::ir::visit::collect_reads(value, &mut reads);
        if loads
            .iter()
            .any(|(register, _)| *register == dest.index || reads.contains(register))
        {
            return None;
        }
        between.push(stmt);
    }
    let mut destination = None;
    for (part, (register, _)) in loads.iter().enumerate() {
        let Some(Node::Stmt(Stmt::Store {
            addr,
            value,
            width: 8,
        })) = nodes.get(loads.len() + between.len() + part)
        else {
            return None;
        };
        if *value != Expr::reg(*register, 64) || !address(addr, ctx) {
            return None;
        }
        if let Some(first) = destination {
            if !follows(first, addr, part as u64 * 8) {
                return None;
            }
        } else {
            destination = Some(addr);
        }
    }
    let Some(destination) = destination else {
        return None;
    };
    let mut reads = std::collections::HashSet::new();
    crate::ir::visit::collect_reads(destination, &mut reads);
    if reads.is_empty() {
        return None;
    }
    let mut source_reads = HashSet::new();
    for (_, source) in &loads {
        crate::ir::visit::collect_reads(source, &mut source_reads);
    }
    // Absolute addresses and recovered frame objects require their own C
    // storage bindings; a raw numerical address cannot replace those bindings.
    if source_reads.is_empty() {
        return None;
    }
    reads.extend(source_reads);
    if loads.iter().any(|(register, _)| reads.contains(register)) {
        return None;
    }
    let record = record(loads[0].1, destination, bytes, ctx);
    let source = expr::print_address(loads[0].1, ctx).text;
    let destination = expr::print_address(destination, ctx).text;
    let consumed = loads.len() * 2 + between.len();
    if !between.is_empty() {
        let statements = between
            .iter()
            .map(|stmt| super::render_stmt(stmt, ctx))
            .collect::<Vec<_>>()
            .join("\n    ");
        let expressions = format!("{source} {destination} {statements}");
        let mut reserved = expressions
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .map(str::to_owned)
            .collect();
        let temporary = super::vacant_name("transfer", &mut reserved);
        return Some((
            consumed,
            format!(
                "{{\n    unsigned char {temporary}[{bytes}];\n    __builtin_memcpy({temporary}, (const void *)({source}), {bytes});\n    {statements}\n    __builtin_memcpy((void *)({destination}), {temporary}, {bytes});\n}}"
            ),
        ));
    }
    if let Some(ty) = record {
        return Some((
            consumed,
            format!("*({destination}) = (({ty}[1]){{*({source})}})[0];"),
        ));
    }
    Some((
        consumed,
        format!(
            "__builtin_memcpy((void *)({destination}), __builtin_memcpy((unsigned char[{bytes}]){{0}}, (const void *)({source}), {bytes}), {bytes});"
        ),
    ))
}

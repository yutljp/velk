use super::globals::View;
use super::{CType, Ctx, Expr, Node, Stmt, expr, naming};
use crate::ir::{BinOp, VARIABLE_BASE};
use std::collections::{HashMap, HashSet};

pub(super) fn single_use_loads(ir: &crate::ir::FunctionIr) -> HashSet<(u16, Expr)> {
    if !ir.blocks.iter().any(|block| {
        block.stmts.windows(2).any(|pair| {
            pair.iter().all(|stmt| {
                matches!(stmt, Stmt::Assign {
            dest, value: Expr::Load { width: 8, signed: false, .. }
        } if dest.width == 64 && (dest.index >= VARIABLE_BASE || crate::arch::vector_half(ir.isa, dest.index).is_some()))
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
                && (dest.index >= VARIABLE_BASE
                    || crate::arch::vector_half(ir.isa, dest.index).is_some())
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

fn valid_address(value: &Expr, bytes: u64, ctx: &Ctx<'_>) -> bool {
    // Adjacency in the image does not prove that named globals form one C object.
    if matches!(value, Expr::Const(address)
        if ctx.globals.containing(*address).is_some() || ctx.globals.target(*address).is_some())
    {
        return false;
    }
    let key = super::render_expr(value, ctx);
    if let Some((_, remaining)) = ctx.transfer_addresses.get(&key) {
        return *remaining >= bytes;
    }
    if let Expr::Const(value) = value {
        return ctx.data_ranges.iter().any(|(start, size)| {
            value
                .checked_sub(*start)
                .is_some_and(|offset| offset.checked_add(bytes).is_some_and(|end| end <= *size))
        });
    }
    address(value, ctx)
}

fn copy_address(value: &Expr, bytes: u64, view: View, ctx: &Ctx<'_>) -> Option<String> {
    if !valid_address(value, bytes, ctx) {
        return None;
    }
    let key = super::render_expr(value, ctx);
    if let Some((pointer, _)) = ctx.transfer_addresses.get(&key) {
        return Some(pointer.clone());
    }
    if let Expr::Const(value) = value {
        if bytes > view.width() {
            return Some(ctx.globals.array_pointer(*value, view));
        }
        return naming::global_pointer(&Expr::Const(*value), view, ctx);
    }
    let address = expr::print_address(value, ctx);
    Some(if address.is_pointer() {
        address.text
    } else {
        format!("(void *)({})", address.text)
    })
}

fn address_terms(value: &Expr) -> Option<(Vec<&Expr>, i64)> {
    let mut terms = Vec::new();
    naming::sum_terms(value, false, &mut terms);
    let mut base = Vec::new();
    let mut offset = 0i64;
    for (term, negative) in terms {
        if let Expr::Const(value) = term {
            let next = if negative {
                offset.checked_sub(*value as i64)
            } else {
                offset.checked_add(*value as i64)
            };
            let Some(next) = next else { return None };
            offset = next;
        } else if negative {
            return None;
        } else {
            base.push(term);
        }
    }
    Some((base, offset))
}

fn follows(first: &Expr, next: &Expr, bytes: u64) -> bool {
    let (Some((base, start)), Some((next_base, next_start))) =
        (address_terms(first), address_terms(next))
    else {
        return false;
    };
    let Ok(bytes) = i64::try_from(bytes) else {
        return false;
    };
    base == next_base && start.checked_add(bytes) == Some(next_start)
}

fn disjoint(source: &Expr, destination: &Expr, bytes: u64) -> bool {
    let (Some((source, start)), Some((destination, end))) =
        (address_terms(source), address_terms(destination))
    else {
        return false;
    };
    source == destination
        && start
            .checked_sub(end)
            .is_some_and(|distance| distance.unsigned_abs() >= bytes)
}

fn whole_elements(source: &Expr, destination: &Expr, bytes: u64, ctx: &Ctx<'_>) -> bool {
    match (
        naming::element_index(source, ctx),
        naming::element_index(destination, ctx),
    ) {
        (Some((source, size, _)), Some((destination, other_size, _))) => {
            source == destination && size == bytes && other_size == bytes
        }
        _ => source == destination,
    }
}

fn record_value(value: &Expr, pointer: &str, bytes: u64, ctx: &Ctx<'_>) -> String {
    if let Some((base, size, index)) = naming::element_index(value, ctx)
        && size == bytes
    {
        return format!("{base}[{}]", super::render_expr(&index, ctx));
    }
    format!("*({pointer})")
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
        // records entirely covered by integer members.
        let CType::Int { bytes: width, .. } = field.ty else {
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

/// Repeated byte stores and complete scalar copies. A byte temporary preserves
/// every byte, including padding, when a copy needs to snapshot overlapping ranges.
pub(super) fn render(nodes: &[Node], ctx: &Ctx<'_>) -> Option<(usize, String)> {
    fill(nodes, ctx)
        .or_else(|| ordered(nodes, ctx))
        .or_else(|| reordered(nodes, ctx))
}

fn fill(nodes: &[Node], ctx: &Ctx<'_>) -> Option<(usize, String)> {
    let Some(Node::Stmt(Stmt::Store {
        width: first_width, ..
    })) = nodes.first()
    else {
        return None;
    };
    let mut start = None;
    let mut byte = None;
    let mut bytes = 0u64;
    let mut count = 0;
    for node in nodes {
        let Node::Stmt(Stmt::Store {
            addr,
            value: Expr::Const(value),
            width,
        }) = node
        else {
            break;
        };
        if !matches!(width, 1 | 2 | 4 | 8) || !valid_address(addr, u64::from(*width), ctx) {
            break;
        }
        let pattern = value & 0xff;
        if (0..*width).any(|part| (value >> (u32::from(part) * 8)) & 0xff != pattern)
            || byte.is_some_and(|byte| byte != pattern)
            || start.is_some_and(|first| !follows(first, addr, bytes))
        {
            break;
        }
        let Some(next) = bytes.checked_add(u64::from(*width)) else {
            break;
        };
        start.get_or_insert(addr);
        byte = Some(pattern);
        bytes = next;
        count += 1;
    }
    if count < 2 {
        return None;
    }
    let (Some(start), Some(byte)) = (start, byte) else {
        return None;
    };
    let Some(destination) = copy_address(start, bytes, View::Unsigned(*first_width), ctx) else {
        return None;
    };
    let text = format!("__builtin_memset({destination}, 0x{byte:x}, {bytes});");
    let new_casts = super::cost::transfer_casts(&text);
    if new_casts != 0 {
        let original_casts: usize = nodes[..count]
            .iter()
            .filter_map(|node| match node {
                Node::Stmt(stmt) => {
                    Some(super::cost::transfer_casts(&super::render_stmt(stmt, ctx)))
                }
                _ => None,
            })
            .sum();
        if new_casts > original_casts {
            return None;
        }
    }
    Some((count, text))
}

fn ordered(nodes: &[Node], ctx: &Ctx<'_>) -> Option<(usize, String)> {
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
            || (dest.index < VARIABLE_BASE
                && crate::arch::vector_half(ctx.isa, dest.index).is_none())
            || !(ctx.read_once.contains(&dest.index)
                || ctx.transfer_values.contains(&(
                    dest.index,
                    Expr::Load {
                        addr: addr.clone(),
                        width: 8,
                        signed: false,
                    },
                )))
            || !valid_address(addr, 8, ctx)
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
        if *value != Expr::reg(*register, 64) || !valid_address(addr, 8, ctx) {
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
    // Recovering storage should not introduce a longer snapshot block.
    if loads.len() == 2
        && !between.is_empty()
        && (!address(loads[0].1, ctx) || !address(destination, ctx))
    {
        return None;
    }
    let mut reads = std::collections::HashSet::new();
    crate::ir::visit::collect_reads(destination, &mut reads);
    let mut source_reads = HashSet::new();
    for (_, source) in &loads {
        crate::ir::visit::collect_reads(source, &mut source_reads);
    }
    reads.extend(source_reads);
    if loads.iter().any(|(register, _)| reads.contains(register)) {
        return None;
    }
    if !valid_address(loads[0].1, bytes, ctx) || !valid_address(destination, bytes, ctx) {
        return None;
    }
    let record = record(loads[0].1, destination, bytes, ctx);
    let direct = disjoint(loads[0].1, destination, bytes)
        || whole_elements(loads[0].1, destination, bytes, ctx);
    let source_value = loads[0].1;
    let destination_value = destination;
    let Some(source) = copy_address(loads[0].1, bytes, View::Unsigned(1), ctx) else {
        return None;
    };
    let Some(destination) = copy_address(destination, bytes, View::Unsigned(1), ctx) else {
        return None;
    };
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
                "{{\n    unsigned char {temporary}[{bytes}];\n    __builtin_memcpy({temporary}, {source}, {bytes});\n    {statements}\n    __builtin_memcpy({destination}, {temporary}, {bytes});\n}}"
            ),
        ));
    }
    if let Some(ty) = record {
        let source = record_value(source_value, &source, bytes, ctx);
        let destination = record_value(destination_value, &destination, bytes, ctx);
        return Some((
            consumed,
            if direct {
                format!("{destination} = {source};")
            } else {
                format!("{destination} = (({ty}[1]){{{source}}})[0];")
            },
        ));
    }
    Some((
        consumed,
        format!("__builtin_memmove({destination}, {source}, {bytes});"),
    ))
}

/// Stores may visit the words in a different order, provided every read
/// happens before the first write and each word keeps its relative offset.
fn reordered(nodes: &[Node], ctx: &Ctx<'_>) -> Option<(usize, String)> {
    let mut loads = Vec::new();
    for node in nodes.iter().take(4) {
        let Node::Stmt(Stmt::Assign {
            dest,
            value:
                value @ Expr::Load {
                    addr,
                    width: 8,
                    signed: false,
                },
        }) = node
        else {
            break;
        };
        if dest.width != 64
            || (dest.index < VARIABLE_BASE
                && crate::arch::vector_half(ctx.isa, dest.index).is_none())
            || !(ctx.read_once.contains(&dest.index)
                || ctx.transfer_values.contains(&(dest.index, value.clone())))
            || loads.iter().any(|(register, _)| *register == dest.index)
            || !valid_address(addr, 8, ctx)
        {
            return None;
        }
        loads.push((dest.index, addr.as_ref()));
    }
    if loads.is_empty() {
        return None;
    }
    let mut sources: Vec<&Expr> = loads.iter().map(|(_, addr)| *addr).collect();
    if let Some(Node::Stmt(Stmt::Store {
        value:
            Expr::Load {
                addr,
                width: 8,
                signed: false,
            },
        width: 8,
        ..
    })) = nodes.get(loads.len())
    {
        sources.push(addr);
    }
    if !(2..=4).contains(&sources.len()) {
        return None;
    }
    let mut ordered = Vec::new();
    for source in &sources {
        let Some((base, offset)) = address_terms(source) else {
            return None;
        };
        ordered.push((base, offset, *source));
    }
    ordered.sort_by_key(|(_, offset, _)| *offset);
    let source = ordered[0].2;
    for (part, (base, offset, _)) in ordered.iter().enumerate() {
        if *base != ordered[0].0 || ordered[0].1.checked_add(part as i64 * 8) != Some(*offset) {
            return None;
        }
    }
    let mut stores = Vec::new();
    for part in 0..sources.len() {
        let Some(Node::Stmt(Stmt::Store {
            addr,
            value,
            width: 8,
        })) = nodes.get(loads.len() + part)
        else {
            return None;
        };
        let index = match value {
            Expr::Reg { index, width: 64 } => {
                let Some(index) = loads.iter().position(|(register, _)| register == index) else {
                    return None;
                };
                index
            }
            Expr::Load {
                width: 8,
                signed: false,
                ..
            } if part == 0 && sources.len() > loads.len() => loads.len(),
            _ => return None,
        };
        if stores.iter().any(|(other, _)| *other == index) || !valid_address(addr, 8, ctx) {
            return None;
        }
        stores.push((index, addr));
    }
    let Some((_, destination)) = stores.iter().find(|(index, _)| sources[*index] == source) else {
        return None;
    };
    for (index, addr) in &stores {
        let Some((_, offset)) = address_terms(sources[*index]) else {
            return None;
        };
        let Some(distance) = offset.checked_sub(ordered[0].1) else {
            return None;
        };
        if !follows(destination, addr, distance as u64) {
            return None;
        }
    }
    let bytes = sources.len() as u64 * 8;
    let mut reads = HashSet::new();
    for addr in sources
        .iter()
        .copied()
        .chain(stores.iter().map(|(_, addr)| *addr))
    {
        crate::ir::visit::collect_reads(addr, &mut reads);
    }
    if loads.iter().any(|(register, _)| reads.contains(register)) {
        return None;
    }
    let (Some(source), Some(destination)) = (
        copy_address(source, bytes, View::Unsigned(1), ctx),
        copy_address(destination, bytes, View::Unsigned(1), ctx),
    ) else {
        return None;
    };
    let consumed = loads.len() + sources.len();
    let text = format!("__builtin_memmove({destination}, {source}, {bytes});");
    let new_casts = super::cost::transfer_casts(&text);
    if new_casts != 0 {
        let mut original_casts = 0;
        let mut position = 0;
        while position < consumed {
            let remaining = &nodes[position..consumed];
            if let Some((count, text)) =
                super::aggregates::render(remaining, ctx).or_else(|| self::ordered(remaining, ctx))
            {
                original_casts += super::cost::transfer_casts(&text);
                position += count;
            } else if let Node::Stmt(stmt) = &nodes[position] {
                original_casts += super::cost::transfer_casts(&super::render_stmt(stmt, ctx));
                position += 1;
            } else {
                return None;
            }
        }
        if new_casts > original_casts {
            return None;
        }
    }
    Some((consumed, text))
}

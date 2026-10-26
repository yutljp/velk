//! Adjacent integer expressions after structured variables have been split.

use std::collections::HashSet;

use crate::ir::visit;
use crate::ir::{BinOp, CType, Expr, FunctionIr, RegRef, Stmt, VARIABLE_BASE};
use crate::render::expr::Ctx;
use crate::render::structure::Node;

pub(in crate::render) fn fold(ir: &FunctionIr, nodes: &mut Vec<Node>, ctx: &Ctx<'_>) -> bool {
    if ir.blocks.iter().any(crate::ir::cfg::opaque)
        || ir
            .params
            .iter()
            .map(|param| &param.ty)
            .chain(ir.value_types.values())
            .chain(ir.members.iter().map(|member| &member.ty))
            .chain(ir.debug_locals.iter().map(|local| &local.ty))
            .chain(ctx.symbols.variable_types.values())
            .any(|ty| matches!(ty, CType::Named(name) if name.split_whitespace().any(|word| word == "volatile")))
    {
        return false;
    }
    let changed = super::copies::fold(ir, nodes, ctx);
    let once = crate::render::calls::read_once(nodes);
    walk(nodes, ctx, &once) || changed
}

fn walk(nodes: &mut Vec<Node>, ctx: &Ctx<'_>, once: &HashSet<u16>) -> bool {
    let mut changed = false;
    for node in nodes.iter_mut() {
        match node {
            Node::If { then, els, .. } => {
                changed |= walk(then, ctx, once);
                changed |= walk(els, ctx, once);
            }
            Node::While { prefix, body, .. } => {
                changed |= walk(prefix, ctx, once);
                changed |= walk(body, ctx, once);
            }
            Node::DoWhile { body, .. } | Node::Forever { body } => {
                changed |= walk(body, ctx, once);
            }
            Node::Switch { arms, default, .. } => {
                for (_, body) in arms {
                    changed |= walk(body, ctx, once);
                }
                if let Some(body) = default {
                    changed |= walk(body, ctx, once);
                }
            }
            _ => {}
        }
    }
    let mut index = 0;
    while index + 1 < nodes.len() {
        let Node::Stmt(Stmt::Assign { dest, value }) = &nodes[index] else {
            index += 1;
            continue;
        };
        let supported_width = dest.width == 64
            || matches!(dest.width, 8 | 16 | 32) && unsigned_load_fits(value, dest.width);
        if dest.index < VARIABLE_BASE
            || !supported_width
            || !plain_register(dest.index, ctx)
            || !once.contains(&dest.index)
            || crate::passes::copies::expr_size(value) > 8
        {
            index += 1;
            continue;
        }
        let Node::Stmt(consumer) = &nodes[index + 1] else {
            index += 1;
            continue;
        };
        // Call arguments identify cached output bindings and must stay unchanged.
        if !visit::statement_registers(consumer).1.contains(&dest.index)
            || !matches!(
                consumer,
                Stmt::Assign { .. } | Stmt::Store { .. } | Stmt::Ret { .. }
            )
        {
            index += 1;
            continue;
        }
        let mut consumer = consumer.clone();
        let replaced = if matches!(value, Expr::Load { .. }) {
            load_into_store(&mut consumer, *dest, value, ctx)
        } else {
            (same_type_copy(dest.index, value, ctx)
                || unsigned_register(dest.index, ctx) && unsigned_value(value, ctx))
                && crate::passes::read_once::substitute(&mut consumer, *dest, value)
        };
        if !replaced
            || consumer
                .operands()
                .into_iter()
                .any(|value| crate::passes::copies::expr_size(value) > 16)
        {
            index += 1;
            continue;
        }
        nodes[index + 1] = Node::Stmt(consumer);
        nodes.remove(index);
        changed = true;
    }
    changed
}

fn load_into_store(stmt: &mut Stmt, dest: RegRef, load: &Expr, ctx: &Ctx<'_>) -> bool {
    let Stmt::Store { addr, value, width } = stmt else {
        return false;
    };
    let Expr::Reg { index, width: read } = value else {
        return false;
    };
    let lossless = unsigned_load_fits(load, dest.width.min(*read));
    if *index != dest.index
        || !matches!(width, 1 | 2 | 4 | 8)
        || (!lossless && u32::from(dest.width.min(*read)) < u32::from(*width) * 8)
        || !ctx.declared.get(index).is_some_and(|ty| ty.integer)
        || crate::passes::copies::reads_memory(addr)
        || crate::passes::read_once::faults(addr)
    {
        return false;
    }
    let mut sources = HashSet::new();
    visit::collect_reads(addr, &mut sources);
    if sources.iter().any(|source| !plain_register(*source, ctx)) {
        return false;
    }
    // The load still precedes the store. Narrow unsigned loads already zero-extend;
    // otherwise the store's width performs the definition's truncation.
    *value = load.clone();
    true
}

fn unsigned_load_fits(value: &Expr, bits: u8) -> bool {
    match value {
        Expr::Load {
            width: width @ (1 | 2 | 4),
            signed: false,
            ..
        } => u32::from(*width) * 8 <= u32::from(bits),
        _ => false,
    }
}

fn unsigned_register(index: u16, ctx: &Ctx<'_>) -> bool {
    plain_register(index, ctx)
        && ctx
            .declared
            .get(&index)
            .is_some_and(|ty| ty.integer && ty.bits == 64 && !ty.signed)
}

pub(super) fn plain_register(index: u16, ctx: &Ctx<'_>) -> bool {
    !ctx.names.get(&index).is_some_and(|name| {
        name.bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'_')
    })
}

pub(super) fn same_type_copy(dest: u16, value: &Expr, ctx: &Ctx<'_>) -> bool {
    let Expr::Reg { index, width: 64 } = value else {
        return false;
    };
    let (Some(dest), Some(source)) = (ctx.declared.get(&dest), ctx.declared.get(index)) else {
        return false;
    };
    plain_register(*index, ctx)
        && dest.integer
        && source.integer
        && dest.bits == source.bits
        && dest.signed == source.signed
}

fn unsigned_value(value: &Expr, ctx: &Ctx<'_>) -> bool {
    match value {
        Expr::Reg { index, width: 64 } => unsigned_register(*index, ctx),
        Expr::Bin {
            op: BinOp::Shr,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(0..=63)) => unsigned_value(lhs, ctx),
        Expr::Bin {
            op: BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::And | BinOp::Or | BinOp::Xor,
            lhs,
            rhs,
        } => {
            let left = unsigned_value(lhs, ctx);
            let right = unsigned_value(rhs, ctx);
            (left || right)
                && (left || matches!(lhs.as_ref(), Expr::Const(_)))
                && (right || matches!(rhs.as_ref(), Expr::Const(_)))
        }
        _ => false,
    }
}

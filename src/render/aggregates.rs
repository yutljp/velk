use super::{BinOp, CType, Ctx, Expr, Node, Stmt, locals::Local};
use std::collections::HashMap;

pub(super) struct Aggregate {
    name: String,
    start: i64,
    end: i64,
    fields: Vec<Field>,
}

struct Field {
    name: String,
    width: u8,
    member: Option<String>,
    slot: i64,
}

pub(super) fn layouts(locals: &[Local]) -> HashMap<String, Aggregate> {
    let mut layouts = HashMap::new();
    for local in locals {
        if local.ty.is_some() || local.fields.len() < 2 || local.size <= 0 {
            continue;
        }
        let mut end = Some(local.slot);
        let complete = local.fields.iter().all(|field| {
            if end != Some(field.slot)
                || !matches!(field.width, 1 | 2 | 4 | 8)
                || !matches!(field.ty, None | Some(CType::Int { .. } | CType::Pointer(_)))
            {
                return false;
            }
            end = field.slot.checked_add(i64::from(field.width));
            end.is_some()
        });
        // Assignment may leave padding unspecified, so every byte must be a field.
        let Some(end) = end else {
            continue;
        };
        if !complete || Some(end) != local.slot.checked_add(local.size) {
            continue;
        }
        let mut fields = Vec::new();
        for field in &local.fields {
            if field.views.is_empty() {
                fields.push(Field {
                    name: field.name.clone(),
                    width: field.width,
                    member: None,
                    slot: field.slot,
                });
                continue;
            }
            let Some(view) = field.views.iter().find(|view| {
                view.slot == field.slot
                    && view.width == field.width
                    && matches!(view.ty, None | Some(CType::Int { .. } | CType::Pointer(_)))
            }) else {
                break;
            };
            let Some(member) = view.name.strip_prefix(&format!("{}.", field.name)) else {
                break;
            };
            fields.push(Field {
                name: view.name.clone(),
                width: field.width,
                member: Some(member.to_owned()),
                slot: field.slot,
            });
        }
        if fields.len() != local.fields.len() {
            continue;
        }
        layouts.insert(
            local.name.clone(),
            Aggregate {
                name: local.name.clone(),
                start: local.slot,
                end,
                fields,
            },
        );
    }
    layouts
}

fn frame_offset(addr: &Expr, ctx: &Ctx<'_>) -> Option<i64> {
    let base = match addr {
        Expr::Reg { .. } => addr,
        Expr::Bin { lhs, rhs, .. } => match (lhs.as_ref(), rhs.as_ref()) {
            (base @ Expr::Reg { .. }, Expr::Const(_))
            | (Expr::Const(_), base @ Expr::Reg { .. }) => base,
            _ => return None,
        },
        _ => return None,
    };
    let sp = crate::arch::stack_pointer(ctx.isa);
    if !matches!(base, Expr::Reg { index, width: 64 } if *index == sp) {
        return None;
    }
    crate::passes::frame_slots::frame_slot(addr, 0, sp)
}

fn independent(value: &Expr, layout: &Aggregate, ctx: &Ctx<'_>) -> bool {
    match value {
        Expr::Reg { .. } | Expr::Const(_) => true,
        Expr::Bin {
            op: BinOp::DivS | BinOp::DivU | BinOp::ModS | BinOp::ModU,
            ..
        } => false,
        Expr::Bin { lhs, rhs, .. } => {
            independent(lhs, layout, ctx) && independent(rhs, layout, ctx)
        }
        Expr::SignExtend { value, .. } => independent(value, layout, ctx),
        Expr::Load {
            addr,
            width: width @ (1 | 2 | 4 | 8),
            ..
        } => {
            let Some(start) = frame_offset(addr, ctx) else {
                return false;
            };
            let Some(end) = start.checked_add(i64::from(*width)) else {
                return false;
            };
            end <= layout.start || start >= layout.end
        }
        _ => false,
    }
}

/// Full-field stores can be evaluated together when their values do not read the destination.
pub(super) fn render(nodes: &[Node], ctx: &Ctx<'_>) -> Option<(usize, String)> {
    if ctx.local_aggregates.is_empty() {
        return None;
    }
    let Some(Node::Stmt(Stmt::Store { addr, .. })) = nodes.first() else {
        return None;
    };
    let key = super::render_expr(addr, ctx);
    let Some(first) = ctx.slots.get(&key) else {
        return None;
    };
    let Some((local, _)) = first.split_once('.') else {
        return None;
    };
    let Some(layout) = ctx.local_aggregates.get(local) else {
        return None;
    };
    let mut values = vec![None; layout.fields.len()];
    for node in nodes.iter().take(layout.fields.len()) {
        let Node::Stmt(stmt @ Stmt::Store { addr, value, width }) = node else {
            return None;
        };
        let key = super::render_expr(addr, ctx);
        let Some(field) = ctx.slots.get(&key) else {
            return None;
        };
        let Some(part) = layout
            .fields
            .iter()
            .position(|entry| entry.name == *field && entry.width == *width)
        else {
            return None;
        };
        // The range comparison below uses entry-frame coordinates. Refuse
        // addresses still relative to an adjusted stack pointer.
        if frame_offset(addr, ctx) != Some(layout.fields[part].slot) {
            return None;
        }
        if values[part].is_some() || !independent(value, layout, ctx) {
            return None;
        }
        // Reuse the store's conversions, including pointer casts and truncation.
        let text = super::render_stmt(stmt, ctx);
        let prefix = format!("{field} = ");
        let Some(value) = text
            .strip_prefix(&prefix)
            .and_then(|value| value.strip_suffix(';'))
        else {
            return None;
        };
        values[part] = Some(match &layout.fields[part].member {
            Some(member) => format!("{{ .{member} = {value} }}"),
            None => value.to_owned(),
        });
    }
    let Some(values) = values.into_iter().collect::<Option<Vec<_>>>() else {
        return None;
    };
    Some((
        values.len(),
        format!(
            "{} = (__typeof__({})){{ {} }};",
            layout.name,
            layout.name,
            values.join(", ")
        ),
    ))
}

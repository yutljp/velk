use super::{BinOp, CType, Ctx, Expr, Node, Stmt, locals::Local};
use std::collections::HashMap;

pub(super) struct Aggregate {
    name: String,
    fields: Vec<(String, u8, Option<String>)>,
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
        if !complete || end != local.slot.checked_add(local.size) {
            continue;
        }
        let mut fields = Vec::new();
        for field in &local.fields {
            if field.views.is_empty() {
                fields.push((field.name.clone(), field.width, None));
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
            fields.push((view.name.clone(), field.width, Some(member.to_owned())));
        }
        if fields.len() != local.fields.len() {
            continue;
        }
        layouts.insert(
            fields[0].0.clone(),
            Aggregate {
                name: local.name.clone(),
                fields,
            },
        );
    }
    layouts
}

fn pure(value: &Expr) -> bool {
    match value {
        Expr::Reg { .. } | Expr::Const(_) => true,
        Expr::Bin {
            op: BinOp::DivS | BinOp::DivU | BinOp::ModS | BinOp::ModU,
            ..
        } => false,
        Expr::Bin { lhs, rhs, .. } => pure(lhs) && pure(rhs),
        _ => false,
    }
}

/// Full-field stores with no memory reads or trapping arithmetic can be evaluated together.
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
    let Some(layout) = ctx.local_aggregates.get(first) else {
        return None;
    };
    let mut values = Vec::new();
    for (node, (field, bytes, member)) in nodes.iter().zip(&layout.fields) {
        let Node::Stmt(stmt @ Stmt::Store { value, width, .. }) = node else {
            return None;
        };
        if width != bytes || !pure(value) {
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
        values.push(match member {
            Some(member) => format!("{{ .{member} = {value} }}"),
            None => value.to_owned(),
        });
    }
    if values.len() != layout.fields.len() {
        return None;
    }
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

//! Redundant local copies after structured variables have their final types.

use std::collections::HashMap;

use crate::ir::{Expr, FunctionIr, Stmt};
use crate::render::expr::Ctx;
use crate::render::structure::Node;

pub(super) fn fold(ir: &FunctionIr, nodes: &mut Vec<Node>, ctx: &Ctx<'_>) -> bool {
    let Some(mut renamed) = crate::passes::copies::redundant_copy_renames(ir) else {
        return false;
    };
    renamed.retain(|dest, source| {
        super::values::plain_register(*dest, ctx)
            && super::values::plain_register(*source, ctx)
            && (super::values::same_type_copy(*dest, &Expr::reg(*source, 64), ctx)
                || ctx
                    .pointer_types
                    .get(dest)
                    .is_some_and(|ty| ctx.pointer_types.get(source) == Some(ty)))
    });
    if renamed.is_empty() {
        return false;
    }
    rewrite(nodes, &renamed);
    true
}

fn rewrite(nodes: &mut Vec<Node>, renamed: &HashMap<u16, u16>) {
    nodes.retain(|node| {
        !matches!(node, Node::Stmt(Stmt::Assign { dest, .. }) if renamed.contains_key(&dest.index))
    });
    for node in nodes {
        match node {
            Node::Stmt(stmt) => crate::passes::coalesce::rename(stmt, renamed),
            Node::If {
                lhs,
                rhs,
                then,
                els,
                ..
            } => {
                crate::ir::visit::rename_registers(lhs, renamed);
                crate::ir::visit::rename_registers(rhs, renamed);
                rewrite(then, renamed);
                rewrite(els, renamed);
            }
            Node::While {
                lhs,
                rhs,
                prefix,
                body,
                ..
            } => {
                crate::ir::visit::rename_registers(lhs, renamed);
                crate::ir::visit::rename_registers(rhs, renamed);
                rewrite(prefix, renamed);
                rewrite(body, renamed);
            }
            Node::DoWhile { lhs, rhs, body, .. } => {
                crate::ir::visit::rename_registers(lhs, renamed);
                crate::ir::visit::rename_registers(rhs, renamed);
                rewrite(body, renamed);
            }
            Node::Forever { body } => rewrite(body, renamed),
            Node::Switch {
                index,
                arms,
                default,
                ..
            } => {
                crate::ir::visit::rename_registers(index, renamed);
                for (_, body) in arms {
                    rewrite(body, renamed);
                }
                if let Some(body) = default {
                    rewrite(body, renamed);
                }
            }
            _ => {}
        }
    }
}

use super::{Ctx, Node, body::indent, render_expr, render_stmt};
use crate::ir::{BinOp, Cond, Expr, RegRef, Stmt};

#[cfg(test)]
mod tests;

fn advanced(stmt: &Stmt, size: u64) -> Option<RegRef> {
    let Stmt::Assign { dest, value } = stmt else {
        return None;
    };
    if dest.width == 64
        && *value == Expr::bin(BinOp::Add, Expr::reg(dest.index, 64), Expr::Const(size))
    {
        Some(*dest)
    } else {
        None
    }
}

pub(super) fn render(
    init: &Stmt,
    test: (Cond, &Expr, &Expr),
    body: &[Node],
    preceding: &[Node],
    depth: usize,
    ctx: &Ctx<'_>,
) -> Option<String> {
    let Stmt::Assign {
        dest: count,
        value: initial,
    } = init
    else {
        return None;
    };
    if count.width != 64 || test != (Cond::Ne, &Expr::reg(count.index, 64), &Expr::Const(0)) {
        return None;
    }
    let Some((Node::Stmt(Stmt::Assign { dest, value }), rest)) = body.split_last() else {
        return None;
    };
    let decrement = Expr::bin(BinOp::Sub, Expr::reg(count.index, 64), Expr::Const(1));
    if dest != count
        || (*value != decrement && !(*initial == Expr::Const(1) && *value == Expr::Const(0)))
    {
        return None;
    }
    let Some((Node::Stmt(Stmt::Store { addr, value, width }), steps)) = rest.split_first() else {
        return None;
    };
    if ![1, 2, 4, 8].contains(width) {
        return None;
    }
    let n = match initial {
        Expr::Const(n) => Some(*n),
        Expr::Reg { width: 64, .. } => None,
        _ => return None,
    };
    let bytes = match n {
        Some(n) => {
            let Some(bytes) = n.checked_mul(u64::from(*width)) else {
                return None;
            };
            Expr::Const(bytes)
        }
        None if *width == 1 => Expr::reg(count.index, 64),
        None => return None,
    };
    let mut pointers = Vec::new();
    for step in steps {
        let Node::Stmt(stmt) = step else {
            return None;
        };
        let Some(pointer) = advanced(stmt, u64::from(*width)) else {
            return None;
        };
        if pointer.index == count.index || pointers.contains(&pointer) {
            return None;
        }
        pointers.push(pointer);
    }
    let Expr::Reg {
        index: destination,
        width: 64,
    } = addr
    else {
        return None;
    };
    if !pointers.iter().any(|p| p.index == *destination) {
        return None;
    }
    let address = |value: &Expr| {
        let text = render_expr(value, ctx);
        if matches!(value, Expr::Reg { index, .. } if ctx.pointer_types.contains_key(index)) {
            format!("(void *)({text})")
        } else {
            format!("(void *)(uint64_t)({text})")
        }
    };
    let call = match value {
        Expr::Load {
            addr: source,
            width: loaded,
            ..
        } if loaded == width && pointers.len() == 2 => {
            let Expr::Const(bytes) = bytes else {
                return None;
            };
            let Expr::Reg { index, width: 64 } = source.as_ref() else {
                return None;
            };
            if *index == *destination || !pointers.iter().any(|p| p.index == *index) {
                return None;
            }
            let facts = super::provenance::Facts::preceding(preceding, ctx);
            if !facts.disjoint(addr, source, bytes, ctx) {
                return None;
            }
            format!(
                "__builtin_memcpy({}, {}, 0x{bytes:x});",
                address(addr),
                address(source)
            )
        }
        _ if pointers.len() == 1 => {
            let mut reads = std::collections::HashSet::new();
            crate::ir::visit::collect_reads(value, &mut reads);
            if crate::passes::copies::reads_memory(value)
                || reads.contains(&count.index)
                || pointers.iter().any(|p| reads.contains(&p.index))
            {
                return None;
            }
            let byte = if *width == 1 {
                match value {
                    Expr::Const(value) => format!("0x{:x}", value & 0xff),
                    _ => format!(
                        "(uint8_t)({})",
                        super::stmt::stored_value(value, 8, ctx).text
                    ),
                }
            } else {
                let Expr::Const(pattern) = value else {
                    return None;
                };
                let byte = pattern & 0xff;
                if (0..*width).any(|i| (pattern >> (u32::from(i) * 8)) & 0xff != byte) {
                    return None;
                }
                format!("0x{byte:x}")
            };
            format!(
                "__builtin_memset({}, {byte}, {});",
                address(addr),
                render_expr(&bytes, ctx)
            )
        }
        _ => return None,
    };
    let mut out = String::new();
    if n.is_none() {
        indent(depth, &mut out);
        out.push_str(&render_stmt(init, ctx));
        out.push('\n');
    }
    let inner = if n.is_none() {
        indent(depth, &mut out);
        out.push_str(&format!(
            "if ({} != 0) {{\n",
            render_expr(&Expr::reg(count.index, 64), ctx)
        ));
        depth + 1
    } else {
        depth
    };
    if n != Some(0) {
        indent(inner, &mut out);
        out.push_str(&call);
        out.push('\n');
    }
    if n != Some(0) {
        for pointer in pointers {
            let stmt = Stmt::Assign {
                dest: pointer,
                value: Expr::bin(BinOp::Add, Expr::reg(pointer.index, 64), bytes.clone()),
            };
            indent(inner, &mut out);
            out.push_str(&render_stmt(&stmt, ctx));
            out.push('\n');
        }
    }
    if n.is_none() {
        indent(depth, &mut out);
        out.push_str("}\n");
    }
    indent(depth, &mut out);
    out.push_str(&render_stmt(
        &Stmt::Assign {
            dest: *count,
            value: Expr::Const(0),
        },
        ctx,
    ));
    out.push('\n');
    Some(out)
}

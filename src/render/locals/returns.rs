use crate::ir::{Expr, FunctionIr, Stmt};
use crate::render::structure::Node;

pub(in crate::render) fn fold(ir: &FunctionIr, nodes: &mut Vec<Node>) {
    let sp = crate::arch::stack_pointer(ir.isa);
    if !crate::passes::memory::fixed_private_frame(ir, sp) {
        return;
    }
    let bits = ir.ret_type.integer().map(|(bits, _)| bits).or_else(|| {
        ir.ret_type.is_sse_float().then(|| {
            if ir.ret_type.to_string().contains("double") {
                64
            } else {
                32
            }
        })
    });
    let Some(bits) = bits else { return };
    walk(nodes, sp, bits);
}

fn walk(nodes: &mut Vec<Node>, sp: u16, bits: u32) {
    for node in nodes.iter_mut() {
        match node {
            Node::If { then, els, .. } => {
                walk(then, sp, bits);
                walk(els, sp, bits);
            }
            Node::While { prefix, body, .. } => {
                walk(prefix, sp, bits);
                walk(body, sp, bits);
            }
            Node::DoWhile { body, .. } | Node::Forever { body } => walk(body, sp, bits),
            Node::Switch { arms, default, .. } => {
                for (_, body) in arms {
                    walk(body, sp, bits);
                }
                if let Some(body) = default {
                    walk(body, sp, bits);
                }
            }
            _ => {}
        }
    }
    let mut index = 0;
    while index + 1 < nodes.len() {
        if let (
            Node::Stmt(Stmt::Store { addr, value, width }),
            Node::Stmt(Stmt::Ret {
                value:
                    Expr::Load {
                        addr: read,
                        width: loaded,
                        ..
                    },
            }),
        ) = (&nodes[index], &nodes[index + 1])
            && read.as_ref() == addr
            && loaded == width
            && matches!(width, 1 | 2 | 4 | 8)
            && u32::from(*width) * 8 == bits
            && crate::passes::memory::private_address(addr, *width, sp)
        {
            // The return type performs the same truncation as the private store.
            nodes[index + 1] = Node::Stmt(Stmt::Ret {
                value: value.clone(),
            });
            nodes.remove(index);
            continue;
        }
        index += 1;
    }
}

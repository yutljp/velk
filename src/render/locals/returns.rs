use std::collections::BTreeMap;

use crate::ir::{BinOp, CType, Expr, FunctionIr, Stmt};
use crate::render::structure::Node;

pub(in crate::render) fn fold(ir: &FunctionIr, nodes: &mut Vec<Node>) {
    fold_register_returns(ir, nodes);
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

fn fold_register_returns(ir: &FunctionIr, nodes: &mut Vec<Node>) {
    let Some((bits, _)) = ir.ret_type.integer() else {
        return;
    };
    if matches!(&ir.ret_type, CType::Named(name)
        if name.split_whitespace().any(|word| matches!(word, "bool" | "_Bool")))
    {
        return;
    }
    let types = crate::render::variable_types(ir);
    fold_copies(ir, nodes, bits, &types);
}

fn fold_copies(ir: &FunctionIr, nodes: &mut Vec<Node>, bits: u32, types: &BTreeMap<u16, CType>) {
    for node in nodes.iter_mut() {
        if let Node::If { then, els, .. } = node {
            fold_copies(ir, then, bits, types);
            fold_copies(ir, els, bits, types);
        }
    }
    if !ends_in_return(nodes) {
        return;
    }
    let mut index = nodes.len();
    while index > 0 {
        index -= 1;
        let Node::Stmt(Stmt::Assign { dest, value }) = &nodes[index] else {
            continue;
        };
        if dest.index < crate::ir::VARIABLE_BASE
            || u32::from(dest.width) < bits
            || !matches!(value, Expr::Reg { .. } | Expr::Const(_))
            || types.get(&dest.index).is_some_and(|ty| {
                ty.integer().is_none()
                    || matches!(ty, CType::Named(name)
                        if name.split_whitespace().any(|word| word == "volatile"))
            })
        {
            continue;
        }
        if let Expr::Reg { index: source, .. } = value {
            let ty = ir
                .params
                .iter()
                .find(|param| param.index == *source)
                .map(|param| &param.ty)
                .or_else(|| types.get(source));
            if ty.is_none_or(|ty| {
                ty.integer().is_none()
                    || matches!(ty, CType::Named(name)
                    if name.split_whitespace().any(|word| word == "volatile"))
            }) {
                continue;
            }
        }
        let mut replacement = nodes[index + 1..].to_vec();
        if replace_returns(&mut replacement, dest.index, bits, value) == Some(true) {
            nodes.truncate(index);
            nodes.extend(replacement);
        }
    }
}

fn ends_in_return(nodes: &[Node]) -> bool {
    match nodes.last() {
        Some(Node::Stmt(Stmt::Ret { .. })) => true,
        Some(Node::If { then, els, .. }) => ends_in_return(then) && ends_in_return(els),
        _ => false,
    }
}

// Only return paths may follow the copy, so its source cannot change and
// no label can enter after the definition. The return type truncates it.
fn replace_returns(nodes: &mut [Node], register: u16, bits: u32, value: &Expr) -> Option<bool> {
    let mut replaced = false;
    for node in nodes {
        match node {
            Node::Stmt(Stmt::Ret { value: returned }) => {
                let mut inner = &*returned;
                loop {
                    inner = match inner {
                        Expr::Bin {
                            op: BinOp::And,
                            lhs,
                            rhs,
                        } if matches!(rhs.as_ref(), Expr::Const(mask)
                                if mask & crate::ir::semantics::mask(bits)
                                    == crate::ir::semantics::mask(bits)) =>
                        {
                            lhs
                        }
                        Expr::SignExtend { value, width } if u32::from(*width) * 8 >= bits => value,
                        _ => break,
                    };
                }
                if matches!(inner, Expr::Reg { index, width }
                    if *index == register && u32::from(*width) >= bits)
                {
                    *returned = value.clone();
                    replaced = true;
                } else {
                    let mut reads = rustc_hash::FxHashSet::default();
                    crate::ir::visit::expr_reads(returned, &mut reads);
                    if reads.contains(&register) {
                        return None;
                    }
                }
            }
            Node::If {
                lhs,
                rhs,
                then,
                els,
                ..
            } => {
                let mut reads = rustc_hash::FxHashSet::default();
                crate::ir::visit::expr_reads(lhs, &mut reads);
                crate::ir::visit::expr_reads(rhs, &mut reads);
                if reads.contains(&register) {
                    return None;
                }
                let Some(changed_then) = replace_returns(then, register, bits, value) else {
                    return None;
                };
                let Some(changed_else) = replace_returns(els, register, bits, value) else {
                    return None;
                };
                replaced |= changed_then || changed_else;
            }
            _ => return None,
        }
    }
    Some(replaced)
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

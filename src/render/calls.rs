//! A call whose result only the statement right after it reads, written
//! into that statement: `v3 = f(a0); g(v3, 0x1);` reads `g(f(a0), 0x1);`.

use std::collections::{HashMap, HashSet};

use crate::ir::{BinOp, Cond, Expr, Stmt, VARIABLE_BASE};
use crate::passes::copies::reads_memory;
use crate::render::expr::Ctx;
use crate::render::structure::Node;

/// The longest statement, without its indentation, a call may be written
/// into.
const LINE: usize = 100;
/// The longest call a condition may take in.
const CONDITION_CALL: usize = 60;

/// The variables the structured function reads exactly once.
pub(super) fn read_once(nodes: &[Node]) -> HashSet<u16> {
    let mut counts = HashMap::new();
    count_nodes(nodes, &mut counts);
    counts
        .into_iter()
        .filter(|(_, count)| *count == 1)
        .map(|(register, _)| register)
        .collect()
}

fn count_nodes(nodes: &[Node], counts: &mut HashMap<u16, usize>) {
    for node in nodes {
        match node {
            Node::Stmt(stmt) => {
                for operand in stmt.operands() {
                    count_expr(operand, counts);
                }
            }
            Node::If {
                lhs,
                rhs,
                then,
                els,
                ..
            } => {
                count_expr(lhs, counts);
                count_expr(rhs, counts);
                count_nodes(then, counts);
                count_nodes(els, counts);
            }
            Node::DoWhile { lhs, rhs, body, .. } => {
                count_expr(lhs, counts);
                count_expr(rhs, counts);
                count_nodes(body, counts);
            }
            Node::While {
                prefix,
                lhs,
                rhs,
                body,
                ..
            } => {
                count_nodes(prefix, counts);
                count_expr(lhs, counts);
                count_expr(rhs, counts);
                count_nodes(body, counts);
            }
            Node::Forever { body } => count_nodes(body, counts),
            Node::Switch {
                index,
                arms,
                default,
            } => {
                count_expr(index, counts);
                for (_, body) in arms {
                    count_nodes(body, counts);
                }
                if let Some(body) = default {
                    count_nodes(body, counts);
                }
            }
            Node::Label(_) | Node::Break | Node::Continue => {}
        }
    }
}

fn count_expr(expr: &Expr, counts: &mut HashMap<u16, usize>) {
    match expr {
        Expr::Reg { index, .. } => *counts.entry(*index).or_default() += 1,
        _ => {
            for child in crate::ir::visit::children(expr) {
                count_expr(child, counts);
            }
        }
    }
}

/// `call` written into `next`, the node after it, when `next` is the one
/// reader of the call's result and takes it whole, as an argument, a stored
/// or returned value, or one side of an equality test. No other part of
/// `next` reads memory, which the call may change, so the order C leaves
/// open among them does not matter.
pub(super) fn call_in_reader(
    call: &Stmt,
    next: &Node,
    depth: usize,
    ctx: &Ctx<'_>,
) -> Option<String> {
    let Stmt::Call {
        result: Some(result),
        args: Some(_),
        ..
    } = call
    else {
        return None;
    };
    let dest = result.index;
    if dest < VARIABLE_BASE || !ctx.read_once.contains(&dest) {
        return None;
    }
    // The variable keeps every bit the call returns.
    let declared = ctx.declared.get(&dest)?;
    if !declared.integer || declared.bits != u32::from(result.width) {
        return None;
    }
    let whole = |expr: &Expr| match expr {
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(_)) => {
            *lhs.as_ref() == Expr::reg(dest, result.width)
        }
        _ => *expr == Expr::reg(dest, result.width),
    };
    let apart = |exprs: &[&Expr]| exprs.iter().all(|expr| !reads_memory(expr));
    let condition = match next {
        Node::Stmt(Stmt::Call {
            through,
            args: Some(args),
            ..
        }) => {
            let at = args.iter().position(whole)?;
            let others: Vec<&Expr> = through
                .iter()
                .chain(
                    args.iter()
                        .enumerate()
                        .filter(|(position, _)| *position != at)
                        .map(|(_, arg)| arg),
                )
                .collect();
            if !apart(&others) {
                return None;
            }
            false
        }
        Node::Stmt(Stmt::Store { addr, value, .. }) if whole(value) && apart(&[addr]) => false,
        Node::Stmt(Stmt::Assign { value, .. } | Stmt::Ret { value }) if whole(value) => false,
        Node::If {
            cond: Cond::Eq | Cond::Ne,
            lhs,
            rhs,
            ..
        } if (whole(lhs) && apart(&[rhs])) || (whole(rhs) && apart(&[lhs])) => true,
        _ => return None,
    };
    if !super::via_comment(call, ctx).is_empty() {
        return None;
    }
    let mut bare = call.clone();
    if let Stmt::Call { result, .. } = &mut bare {
        *result = None;
    }
    let text = super::render_stmt(&bare, ctx);
    let text = text.strip_suffix(';')?;
    if condition && text.len() > CONDITION_CALL {
        return None;
    }
    let mut rendered = String::new();
    super::render_node(next, depth, &mut rendered, ctx);
    let (first, rest) = rendered.split_once('\n')?;
    if !condition && !rest.is_empty() {
        return None;
    }
    let name = ctx.register(dest, 64);
    let at = only_word(first, &name)?;
    let line = format!("{}{text}{}", &first[..at], &first[at + name.len()..]);
    if line.trim_start().len() > LINE {
        return None;
    }
    Some(format!("{line}\n{rest}"))
}

/// Where `word` stands in `line` as a whole word, when it does just once.
fn only_word(line: &str, word: &str) -> Option<usize> {
    let part = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut found = line.match_indices(word).filter(|(at, _)| {
        !line[..*at].ends_with(part) && !line[at + word.len()..].starts_with(part)
    });
    let (at, _) = found.next()?;
    found.next().is_none().then_some(at)
}

#[cfg(test)]
mod tests {
    use crate::ir::{CType, Convention, Expr, FunctionIr, Param, RegRef, Stmt, VARIABLE_BASE};
    use crate::loader::Isa;
    use std::collections::HashMap;

    fn call(target: u64, args: Vec<Expr>, result: Option<u16>) -> Stmt {
        Stmt::Call {
            target: Some(target),
            through: None,
            convention: Convention::SysV,
            args: Some(args),
            floats_named: false,
            result: result.map(|index| RegRef { index, width: 64 }),
            clobbers: None,
            via: None,
        }
    }

    /// `v1 = f(a0); g(v1, second); return 0;` as the output prints it.
    fn rendered(second: Expr) -> String {
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                call(0x1000, vec![Expr::reg(7, 64)], Some(VARIABLE_BASE)),
                call(0x2000, vec![Expr::reg(VARIABLE_BASE, 64), second], None),
                Stmt::Ret {
                    value: Expr::Const(0),
                },
            ],
        );
        ir.params = vec![
            Param {
                index: 7,
                name: "a0".to_owned(),
                ty: CType::I64,
            },
            Param {
                index: 6,
                name: "a1".to_owned(),
                ty: CType::pointer_to(CType::I64),
            },
        ];
        crate::render::render(&ir, &[], &HashMap::new(), &[])
    }

    #[test]
    fn a_result_read_once_reads_as_the_call() {
        let text = rendered(Expr::Const(1));
        assert!(text.contains("sub_2000(sub_1000(a0), 0x1);"), "{text}");
        assert!(!text.contains("v1"), "{text}");
    }

    #[test]
    fn a_result_stays_named_beside_a_read_of_memory() {
        let load = Expr::Load {
            addr: Box::new(Expr::reg(6, 64)),
            width: 8,
            signed: false,
        };
        let text = rendered(load);
        assert!(text.contains("v1 = sub_1000(a0);"), "{text}");
    }
}

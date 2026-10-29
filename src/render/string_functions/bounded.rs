//! Finite unsigned byte comparisons with an exact normalized result.

use super::{Values, assignments, evaluate, subtract};
use crate::ir::{Cond, Expr, Stmt};
use crate::render::{Ctx, Node};

const MAX_BYTES: usize = 32;

fn result(
    nodes: &[Node],
    mut values: Values,
    reads: &mut Vec<Expr>,
    budget: &mut usize,
) -> Option<Expr> {
    let Some((first, rest)) = nodes.split_first() else {
        return None;
    };
    let Some(remaining) = budget.checked_sub(1) else {
        return None;
    };
    *budget = remaining;
    match first {
        Node::Stmt(Stmt::Ret { value, .. }) if rest.is_empty() => evaluate(value, &values, reads),
        Node::Stmt(Stmt::Assign { .. }) => {
            if !assignments(std::slice::from_ref(first), &mut values, reads) {
                return None;
            }
            result(rest, values, reads, budget)
        }
        Node::If {
            cond,
            lhs,
            rhs,
            then,
            els,
            ..
        } => {
            let bits = crate::ir::semantics::operand_width(lhs, rhs);
            if matches!(cond, Cond::Lt | Cond::Le | Cond::Gt | Cond::Ge) && bits < 32 {
                return None;
            }
            let Some(lhs) = evaluate(lhs, &values, reads) else {
                return None;
            };
            let Some(rhs) = evaluate(rhs, &values, reads) else {
                return None;
            };
            if matches!(cond, Cond::Lt | Cond::Le | Cond::Gt | Cond::Ge)
                && (!super::byte(&lhs) || !super::byte(&rhs))
            {
                return None;
            }
            let mut yes = then.clone();
            if !matches!(yes.last(), Some(Node::Stmt(Stmt::Ret { .. }))) {
                yes.extend_from_slice(rest)
            }
            let mut no = els.clone();
            if !matches!(no.last(), Some(Node::Stmt(Stmt::Ret { .. }))) {
                no.extend_from_slice(rest)
            }
            let Some(then) = result(&yes, values.clone(), reads, budget) else {
                return None;
            };
            let Some(els) = result(&no, values, reads, budget) else {
                return None;
            };
            Some(Expr::Select {
                cond: *cond,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
                then: Box::new(then),
                els: Box::new(els),
            })
        }
        _ => None,
    }
}

fn location(address: &Expr, sources: &[Expr; 2]) -> Option<(usize, usize)> {
    for (source, base) in sources.iter().enumerate() {
        if let Expr::Const(offset) = subtract(address.clone(), base.clone())
            && offset < MAX_BYTES as u64
        {
            return Some((source, offset as usize));
        }
    }
    None
}

fn loaded(value: &Expr, sources: &[Expr; 2]) -> Option<(usize, usize)> {
    let Expr::Load {
        addr,
        width: 1,
        signed: false,
    } = value
    else {
        return None;
    };
    location(addr, sources)
}

struct Case<'a> {
    sources: &'a [Expr; 2],
    position: usize,
    pair: [u64; 2],
    terminated: bool,
}

impl Case<'_> {
    fn predicate(&self, cond: Cond, lhs: &Expr, rhs: &Expr) -> Option<bool> {
        if !matches!(
            cond,
            Cond::Eq
                | Cond::Ne
                | Cond::Cc
                | Cond::Cs
                | Cond::Hi
                | Cond::Ls
                | Cond::Lt
                | Cond::Le
                | Cond::Gt
                | Cond::Ge
        ) {
            return None;
        }
        let a = loaded(lhs, self.sources);
        let b = loaded(rhs, self.sources);
        let (left, right) = match (a, b) {
            (Some((a, i)), Some((b, j))) if i == j && i <= self.position => {
                let pair = if i < self.position { [1, 1] } else { self.pair };
                (pair[a], pair[b])
            }
            (Some((source, i)), None)
                if *rhs == Expr::Const(0) && self.terminated && i <= self.position =>
            {
                (
                    if i < self.position {
                        1
                    } else {
                        self.pair[source]
                    },
                    0,
                )
            }
            (None, Some((source, i)))
                if *lhs == Expr::Const(0) && self.terminated && i <= self.position =>
            {
                (
                    0,
                    if i < self.position {
                        1
                    } else {
                        self.pair[source]
                    },
                )
            }
            (None, None) => {
                let Some(a) = self.constant(lhs) else {
                    return None;
                };
                let Some(b) = self.constant(rhs) else {
                    return None;
                };
                (a, b)
            }
            _ => return None,
        };
        Some(crate::ir::semantics::holds(cond, left, right, 64))
    }

    fn constant(&self, value: &Expr) -> Option<u64> {
        super::constant(value, &|cond, lhs, rhs| self.predicate(cond, lhs, rhs))
    }
}

fn equivalent(
    value: &Expr,
    sources: &[Expr; 2],
    bytes: usize,
    bits: u32,
    terminated: bool,
) -> bool {
    let mask = crate::ir::semantics::mask(bits);
    for position in 0..bytes {
        let pairs: &[[u64; 2]] = if terminated {
            &[[0, 0], [0, 1], [1, 0], [1, 2], [2, 1]]
        } else {
            &[[1, 2], [2, 1]]
        };
        for pair in pairs {
            let case = Case {
                sources,
                position,
                pair: *pair,
                terminated,
            };
            let expected = match pair[0].cmp(&pair[1]) {
                std::cmp::Ordering::Less => u64::MAX,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            };
            if case.constant(value).map(|value| value & mask) != Some(expected & mask) {
                return false;
            }
        }
    }
    let case = Case {
        sources,
        position: bytes,
        pair: [1, 1],
        terminated,
    };
    case.constant(value).map(|value| value & mask) == Some(0)
}

pub(super) fn render(nodes: &[Node], values: &Values, ctx: &Ctx<'_>) -> Option<String> {
    if ctx.ir.params.len() != 2 {
        return None;
    }
    let Some((bits, _)) = ctx.ir.ret_type.integer() else {
        return None;
    };
    let sources = [
        Expr::reg(ctx.ir.params[0].index, 64),
        Expr::reg(ctx.ir.params[1].index, 64),
    ];
    let mut reads = Vec::new();
    let Some(value) = result(nodes, values.clone(), &mut reads, &mut 128) else {
        return None;
    };
    let mut bytes = 0;
    for address in reads {
        let Some((_, offset)) = location(&address, &sources) else {
            return None;
        };
        bytes = bytes.max(offset + 1);
    }
    if bytes == 0 {
        return None;
    }
    let function = if equivalent(&value, &sources, bytes, bits, /* terminated */ false) {
        "memcmp"
    } else if equivalent(&value, &sources, bytes, bits, /* terminated */ true) {
        "strncmp"
    } else {
        return None;
    };
    if super::is_current_function(function, ctx) {
        return None;
    }
    // The standard specifies the sign, not the magnitude, of comparison results.
    let call = format!(
        "__builtin_{function}({}, {}, {bytes})",
        super::argument(&sources[0], function, ctx),
        super::argument(&sources[1], function, ctx)
    );
    Some(super::comparison(&call, function, Some(bytes as u64), ctx))
}

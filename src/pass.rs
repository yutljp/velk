//! Local simplifications over the register-expression IR.

use std::collections::HashMap;

use crate::ir::{Expr, FunctionIr, Stmt};

/// Propagates constants within a basic block and simplifies expressions.
pub fn simplify(ir: &mut FunctionIr) {
    for block in &mut ir.blocks {
        let mut constants: HashMap<u16, u64> = HashMap::new();
        for stmt in &mut block.stmts {
            simplify_stmt(stmt, &mut constants);
        }
    }
}

fn simplify_stmt(stmt: &mut Stmt, constants: &mut HashMap<u16, u64>) {
    match stmt {
        Stmt::Assign { dest, value } => {
            let simplified = simplify_expr(value.clone(), constants);
            if let Expr::Const(value) = simplified {
                constants.insert(dest.index, value);
            } else {
                constants.remove(&dest.index);
            }
            *value = simplified;
        }
        Stmt::Store { addr, value, .. } => {
            *addr = simplify_expr(addr.clone(), constants);
            *value = simplify_expr(value.clone(), constants);
        }
        Stmt::Brif { lhs, rhs, .. } => {
            *lhs = simplify_expr(lhs.clone(), constants);
            *rhs = simplify_expr(rhs.clone(), constants);
        }
        Stmt::BrIndirect { target } => {
            *target = simplify_expr(target.clone(), constants);
        }
        Stmt::Switch { index, .. } => {
            *index = simplify_expr(index.clone(), constants);
        }
        Stmt::Ret { value } => {
            *value = simplify_expr(value.clone(), constants);
        }
        Stmt::Call { .. } | Stmt::Unsupported { .. } => {
            // Unknown effects may clobber registers.
            constants.clear();
        }
        Stmt::Br { .. } | Stmt::BrifFlags { .. } | Stmt::Trap => {}
    }
}

fn simplify_expr(expr: Expr, constants: &HashMap<u16, u64>) -> Expr {
    match expr {
        Expr::Reg { index, width } => match constants.get(&index) {
            Some(value) => Expr::constant(*value),
            None => Expr::Reg { index, width },
        },
        Expr::Const(_) => expr,
        Expr::Bin { op, lhs, rhs } => fold_offsets(algebraic(Expr::bin(
            op,
            simplify_expr(*lhs, constants),
            simplify_expr(*rhs, constants),
        ))),
        Expr::Load { addr, width, signed } => Expr::Load {
            addr: Box::new(simplify_expr(*addr, constants)),
            width,
            signed,
        },
        Expr::SignExtend { value, width } => {
            let value = simplify_expr(*value, constants);
            // `(int8_t)(x & 0xff)` — the mask already is the extension's
            // own truncation, so it adds nothing.
            let value = match value {
                Expr::Bin {
                    op: crate::ir::BinOp::And,
                    lhs,
                    rhs,
                } => match rhs.as_ref() {
                    Expr::Const(mask)
                        if *mask == (1u64 << (width.min(8) as u32 * 8)).wrapping_sub(1) =>
                    {
                        lhs.as_ref().clone()
                    }
                    _ => Expr::Bin {
                        op: crate::ir::BinOp::And,
                        lhs,
                        rhs,
                    },
                },
                other => other,
            };
            Expr::SignExtend {
                value: Box::new(value),
                width,
            }
        }
        Expr::Select {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => Expr::Select {
            cond,
            lhs: Box::new(simplify_expr(*lhs, constants)),
            rhs: Box::new(simplify_expr(*rhs, constants)),
            then: Box::new(simplify_expr(*then, constants)),
            els: Box::new(simplify_expr(*els, constants)),
        },
    }
}

/// Removes the algebraic identities compilers leave behind: a double
/// negation, and a subtract of zero.
fn algebraic(expr: Expr) -> Expr {
    let Expr::Bin { op, lhs, rhs } = &expr else {
        return expr;
    };
    let zero = |value: &Expr| matches!(value, Expr::Const(0));
    match op {
        // `0 - (0 - x)` is `x`; the absolute-value and negate shapes both
        // produce it.
        crate::ir::BinOp::Sub if zero(lhs) => {
            if let Expr::Bin {
                op: crate::ir::BinOp::Sub,
                lhs: inner,
                rhs: inner_rhs,
            } = rhs.as_ref()
            {
                if zero(inner) {
                    return inner_rhs.as_ref().clone();
                }
            }
            expr
        }
        // `x - 0` is `x`.
        crate::ir::BinOp::Sub if zero(rhs) => lhs.as_ref().clone(),
        // `x + 0` is `x`.
        crate::ir::BinOp::Add if zero(rhs) => lhs.as_ref().clone(),
        _ => expr,
    }
}

/// Reassociates constant offsets so an address reads as one base plus one
/// displacement (`(sp - 0x20) + 8` becomes `sp - 0x18`).
fn fold_offsets(expr: Expr) -> Expr {
    let Expr::Bin { op, lhs, rhs } = expr else {
        return expr;
    };
    let Expr::Const(delta) = rhs.as_ref() else {
        return Expr::Bin { op, lhs, rhs };
    };
    let Expr::Bin {
        op: inner_op,
        lhs: base,
        rhs: inner,
    } = lhs.as_ref()
    else {
        return Expr::Bin { op, lhs, rhs };
    };
    let Expr::Const(offset) = inner.as_ref() else {
        return Expr::Bin { op, lhs, rhs };
    };
    // The outer operator's contribution to the displacement.
    let outer = match op {
        crate::ir::BinOp::Add => *delta,
        crate::ir::BinOp::Sub => delta.wrapping_neg(),
        _ => return Expr::Bin { op, lhs, rhs },
    };
    let total = match inner_op {
        crate::ir::BinOp::Add => offset.wrapping_add(outer),
        crate::ir::BinOp::Sub => offset.wrapping_sub(outer),
        _ => return Expr::Bin { op, lhs, rhs },
    };
    Expr::bin(
        crate::ir::BinOp::Add,
        base.as_ref().clone(),
        Expr::constant(total),
    )
}

#[cfg(test)]
mod tests {
    use super::simplify;
    use crate::ir::{BinOp, Block, Expr, FunctionIr, RegRef, Stmt};

    #[test]
    fn inlines_a_masked_temporary() {
        let masked = |index: u16| {
            Expr::bin(
                BinOp::And,
                Expr::Reg { index, width: 64 },
                Expr::Const(0xffff_ffff),
            )
        };
        let mut ir = FunctionIr {
            isa: crate::loader::Isa::X86_64,
            params: Vec::new(),
            ret_type: "uint64_t".to_owned(),
            accesses: Vec::new(),
            members: Vec::new(),
            signed_params: std::collections::HashSet::new(),
            addr: 0,
            name: None,
            size: 0,
            blocks: vec![Block {
                start: 0,
                stmts: vec![
                    Stmt::Assign {
                        dest: RegRef { index: 0, width: 64 },
                        value: masked(1),
                    },
                    Stmt::Assign {
                        dest: RegRef { index: 2, width: 64 },
                        value: Expr::bin(BinOp::ModS, masked(0), masked(2)),
                    },
                    Stmt::Ret { value: masked(2) },
                ],
            }],
        };
        super::copy_propagate(&mut ir);
        assert!(
            !matches!(
                ir.blocks[0].stmts.first(),
                Some(Stmt::Assign { dest, .. }) if dest.index == 0
            ),
            "the masked copy should inline: {:?}",
            ir.blocks[0].stmts
        );
    }

    #[test]
    fn folds_constant_register_uses() {
        let mut ir = FunctionIr {
            isa: crate::loader::Isa::AArch64,
            params: Vec::new(),
            ret_type: "uint64_t".to_owned(),
            accesses: Vec::new(),
            members: Vec::new(),
            signed_params: std::collections::HashSet::new(),
            addr: 0,
            name: None,
            size: 0,
            blocks: vec![Block {
                start: 0,
                stmts: vec![
                    Stmt::Assign {
                        dest: RegRef {
                            index: 10,
                            width: 64,
                        },
                        value: Expr::Const(0x5556),
                    },
                    Stmt::Assign {
                        dest: RegRef {
                            index: 10,
                            width: 64,
                        },
                        value: Expr::bin(
                            BinOp::Or,
                            Expr::bin(
                                BinOp::And,
                                Expr::Reg {
                                    index: 10,
                                    width: 64,
                                },
                                Expr::Const(0xffff_ffff),
                            ),
                            Expr::Const(0x5555_0000),
                        ),
                    },
                    Stmt::Ret {
                        value: Expr::Reg {
                            index: 10,
                            width: 64,
                        },
                    },
                ],
            }],
        };

        simplify(&mut ir);

        let rendered = ir.render();
        assert!(rendered.contains("#0x55555556"), "{rendered}");
        assert!(rendered.contains("ret #0x55555556"), "{rendered}");
    }
}

/// Width specialization: registers used only as 32-bit values become 32-bit
/// variables, removing the zero-extension masks that the lifter emits.
pub fn specialize_widths(ir: &mut FunctionIr) -> std::collections::HashSet<u16> {
    use std::collections::{HashMap, HashSet};
    use crate::ir::BinOp;

    // A register write is 32-bit when the lifter wrapped the value in a
    // zero-extension mask; anything else writes the full 64-bit slot.
    let mut writes: HashMap<u16, Vec<u8>> = HashMap::new();
    for block in &ir.blocks {
        for stmt in &block.stmts {
            if let Stmt::Assign { dest, value } = stmt {
                let width = match value {
                    Expr::Bin {
                        op: BinOp::And, rhs, ..
                    } if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) => 32,
                    _ => 64,
                };
                writes.entry(dest.index).or_default().push(width);
            }
        }
    }

    // A return of a register that is only ever written at 32 bits reads the
    // 32-bit view of that register.
    for block in &mut ir.blocks {
        for stmt in &mut block.stmts {
            let Stmt::Ret { value } = stmt else {
                continue;
            };
            let Expr::Reg { index, width: 64 } = value else {
                continue;
            };
            let only_32 = writes.get(index).is_some_and(|widths| {
                !widths.is_empty() && widths.iter().all(|width| *width == 32)
            });
            if only_32 {
                *value = Expr::Reg {
                    index: *index,
                    width: 32,
                };
            }
        }
    }

    // Register reads: a masked reference to a whole slot is a 32-bit read,
    // an unmasked slot reference is a 64-bit read.
    let mut reads: HashMap<u16, Vec<u8>> = HashMap::new();
    for block in &mut ir.blocks {
        for stmt in &mut block.stmts {
            map_stmt(stmt, &mut |expr| {
                let expr = expr.clone();
                fn visit(expr: &Expr, reads: &mut HashMap<u16, Vec<u8>>) {
                    match expr {
                        Expr::Const(_) => {}
                        Expr::Reg { index, width } => {
                            reads.entry(*index).or_default().push(*width);
                        }
                        Expr::Bin {
                            op: BinOp::And, lhs, rhs, ..
                        } if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) => match lhs.as_ref()
                        {
                            Expr::Reg { index, .. } => {
                                reads.entry(*index).or_default().push(32);
                            }
                            other => visit(other, reads),
                        },
                        Expr::Bin { lhs, rhs, .. } => {
                            visit(lhs, reads);
                            visit(rhs, reads);
                        }
                        Expr::Load { addr, .. } => visit(addr, reads),
                        Expr::SignExtend { value, .. } => visit(value, reads),
                        Expr::Select {
                            lhs, rhs, then, els, ..
                        } => {
                            visit(lhs, reads);
                            visit(rhs, reads);
                            visit(then, reads);
                            visit(els, reads);
                        }
                    }
                }
                visit(&expr, &mut reads);
                expr
            });
        }
    }

    let uniform: HashSet<u16> = (0..u16::MAX)
        .filter(|index| {
            let read_all_32 = reads
                .get(index)
                .map_or(true, |widths| widths.iter().all(|width| *width == 32));
            let write_all_32 = writes
                .get(index)
                .map_or(true, |widths| widths.iter().all(|width| *width == 32));
            (reads.contains_key(index) || writes.contains_key(index)) && read_all_32 && write_all_32
        })
        .collect();

    for block in &mut ir.blocks {
        for stmt in &mut block.stmts {
            map_stmt(stmt, &mut |expr| rewrite_read_masks(expr, &uniform));
            if let Stmt::Assign { dest, value } = stmt {
                if uniform.contains(&dest.index) {
                    dest.width = 32;
                    if let Expr::Bin {
                        op: BinOp::And,
                        lhs,
                        rhs,
                    } = value
                    {
                        if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) {
                            *value = (**lhs).clone();
                        }
                    }
                }
            }
        }
    }

    uniform
}

fn rewrite_read_masks(expr: &Expr, uniform: &std::collections::HashSet<u16>) -> Expr {
    use crate::ir::BinOp;

    if let Expr::Bin {
        op: BinOp::And,
        lhs,
        rhs,
    } = expr
    {
        if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff))
            && let Expr::Reg { index, .. } = lhs.as_ref()
            && uniform.contains(index)
        {
            return Expr::Reg {
                index: *index,
                width: 32,
            };
        }
    }
    match expr {
        Expr::Bin { op, lhs, rhs } => Expr::bin(
            *op,
            rewrite_read_masks(lhs, uniform),
            rewrite_read_masks(rhs, uniform),
        ),
        Expr::Load { addr, width, signed } => Expr::Load {
            addr: Box::new(rewrite_read_masks(addr, uniform)),
            width: *width,
            signed: *signed,
        },
        Expr::SignExtend { value, width } => Expr::SignExtend {
            value: Box::new(rewrite_read_masks(value, uniform)),
            width: *width,
        },
        Expr::Select {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => Expr::Select {
            cond: *cond,
            lhs: Box::new(rewrite_read_masks(lhs, uniform)),
            rhs: Box::new(rewrite_read_masks(rhs, uniform)),
            then: Box::new(rewrite_read_masks(then, uniform)),
            els: Box::new(rewrite_read_masks(els, uniform)),
        },
        other => other.clone(),
    }
}

fn map_stmt(stmt: &mut Stmt, map: &mut dyn FnMut(&Expr) -> Expr) {
    match stmt {
        Stmt::Assign { value, .. } => *value = map(&*value),
        Stmt::Store { addr, value, .. } => {
            *addr = map(&*addr);
            *value = map(&*value);
        }
        Stmt::Brif { lhs, rhs, .. } => {
            *lhs = map(&*lhs);
            *rhs = map(&*rhs);
        }
        Stmt::Ret { value } => *value = map(&*value),
        Stmt::BrIndirect { target } => *target = map(&*target),
        Stmt::Switch { index, .. } => *index = map(&*index),
        _ => {}
    }
}

/// Per-block common-subexpression elimination: repeated pure subtrees are
/// bound once to a synthetic `t<n>` temporary, the way mature decompilers
/// emit temporary variables instead of repeating the same expression.
pub fn cse(ir: &mut FunctionIr) {
    use std::collections::HashMap;

    for block in &mut ir.blocks {
        for stmt_index in 0..block.stmts.len() {
            let mut counts: HashMap<String, usize> = HashMap::new();
            let snapshot = block.stmts[stmt_index].clone();
            count_stmt(&snapshot, &mut counts);
            if counts.values().all(|count| *count <= 1) {
                continue;
            }

            let mut bound: HashMap<String, u16> = HashMap::new();
            let mut next_id = crate::ir::TEMP_BASE;
            let mut pending: Vec<Stmt> = Vec::new();
            let stmt = std::mem::replace(
                &mut block.stmts[stmt_index],
                Stmt::Unsupported { text: String::new() },
            );
            let rewritten = match stmt {
                Stmt::Assign { dest, value } => Stmt::Assign {
                    dest,
                    value: bind(value, &counts, &mut bound, &mut pending, &mut next_id),
                },
                Stmt::Store { addr, value, width } => {
                    let addr = bind(addr, &counts, &mut bound, &mut pending, &mut next_id);
                    let value = bind(value, &counts, &mut bound, &mut pending, &mut next_id);
                    Stmt::Store { addr, value, width }
                }
                Stmt::Brif { cond, lhs, rhs, target } => Stmt::Brif {
                    cond,
                    lhs: bind(lhs, &counts, &mut bound, &mut pending, &mut next_id),
                    rhs: bind(rhs, &counts, &mut bound, &mut pending, &mut next_id),
                    target,
                },
                Stmt::Ret { value } => Stmt::Ret {
                    value: bind(value, &counts, &mut bound, &mut pending, &mut next_id),
                },
                Stmt::BrIndirect { target } => Stmt::BrIndirect {
                    target: bind(target, &counts, &mut bound, &mut pending, &mut next_id),
                },
                Stmt::Switch { index, cases, default } => Stmt::Switch {
                    index: bind(index, &counts, &mut bound, &mut pending, &mut next_id),
                    cases,
                    default,
                },
                other => other,
            };
            block.stmts[stmt_index] = rewritten;
            for (insert_position, definition) in pending.into_iter().enumerate() {
                block.stmts.insert(stmt_index + insert_position, definition);
            }
        }
    }
}

/// Bottom-up binding inside one statement: a pure subtree that contains an
/// operator and appears more than once in the same statement is emitted once
/// as a `t<n>` temporary.
fn bind(
    expr: Expr,
    counts: &HashMap<String, usize>,
    bound: &mut HashMap<String, u16>,
    pending: &mut Vec<Stmt>,
    next_id: &mut u16,
) -> Expr {
    let rewritten = match expr {
        Expr::Bin { op, lhs, rhs } => Expr::Bin {
            op,
            lhs: Box::new(bind(*lhs, counts, bound, pending, next_id)),
            rhs: Box::new(bind(*rhs, counts, bound, pending, next_id)),
        },
        Expr::Load { addr, width, signed } => Expr::Load {
            addr: Box::new(bind(*addr, counts, bound, pending, next_id)),
            width,
            signed,
        },
        Expr::SignExtend { value, width } => Expr::SignExtend {
            value: Box::new(bind(*value, counts, bound, pending, next_id)),
            width,
        },
        Expr::Select {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => Expr::Select {
            cond,
            lhs: Box::new(bind(*lhs, counts, bound, pending, next_id)),
            rhs: Box::new(bind(*rhs, counts, bound, pending, next_id)),
            then: Box::new(bind(*then, counts, bound, pending, next_id)),
            els: Box::new(bind(*els, counts, bound, pending, next_id)),
        },
        other => other,
    };

    let operator = matches!(
        rewritten,
        Expr::Bin { .. } | Expr::Select { .. } | Expr::SignExtend { .. }
    );
    if !operator {
        return rewritten;
    }
    let Some(key) = pure_key(&rewritten) else {
        return rewritten;
    };
    if counts.get(&key).copied().unwrap_or(0) <= 1 {
        return rewritten;
    }
    // The temporary holds whatever width its value computes at, so later
    // width reasoning sees a 32-bit value as 32-bit.
    let width = expr_width(&rewritten).unwrap_or(64);
    if let Some(index) = bound.get(&key).copied() {
        return Expr::Reg { index, width };
    }
    let index = *next_id;
    *next_id += 1;
    pending.push(Stmt::Assign {
        dest: crate::ir::RegRef { index, width },
        value: rewritten.clone(),
    });
    bound.insert(key, index);
    Expr::Reg { index, width }
}

fn count_stmt(stmt: &Stmt, counts: &mut std::collections::HashMap<String, usize>) {
    match stmt {
        Stmt::Assign { value, .. } => count_nodes(value, counts),
        Stmt::Store { addr, value, .. } => {
            count_nodes(addr, counts);
            count_nodes(value, counts);
        }
        Stmt::Brif { lhs, rhs, .. } => {
            count_nodes(lhs, counts);
            count_nodes(rhs, counts);
        }
        Stmt::Ret { value } => count_nodes(value, counts),
        Stmt::BrIndirect { target } => count_nodes(target, counts),
        Stmt::Switch { index, .. } => count_nodes(index, counts),
        _ => {}
    }
}

fn count_nodes(expr: &Expr, counts: &mut std::collections::HashMap<String, usize>) {
    if let Some(key) = pure_key(expr) {
        *counts.entry(key).or_insert(0) += 1;
    }
    for child in children(expr) {
        count_nodes(child, counts);
    }
}

fn children(expr: &Expr) -> Vec<&Expr> {
    match expr {
        Expr::Bin { lhs, rhs, .. } => vec![lhs.as_ref(), rhs.as_ref()],
        Expr::Select {
            lhs, rhs, then, els, ..
        } => vec![lhs.as_ref(), rhs.as_ref(), then.as_ref(), els.as_ref()],
        Expr::Load { addr, .. } => vec![addr.as_ref()],
        Expr::SignExtend { value, .. } => vec![value.as_ref()],
        _ => Vec::new(),
    }
}

/// Canonical key of a subtree; `None` when the subtree contains a load, since
/// loads may be volatile and must not be shared.
fn pure_key(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Const(value) => Some(format!("c{value}")),
        Expr::Reg { index, width } => Some(format!("r{index}/{width}")),
        Expr::Load { .. } => None,
        Expr::Bin { op, lhs, rhs } => {
            let lhs = pure_key(lhs)?;
            let rhs = pure_key(rhs)?;
            Some(format!("[{:?}|{lhs}|{rhs}]", op))
        }
        Expr::SignExtend { value, width } => Some(format!("[s{width}|{}]", pure_key(value)?)),
        Expr::Select {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => Some(format!(
            "[w{:?}|{}|{}|{}|{}]",
            cond,
            pure_key(lhs)?,
            pure_key(rhs)?,
            pure_key(then)?,
            pure_key(els)?
        )),
    }
}


/// Constant reciprocal recovery: mature compilers divide by a constant with a
/// widening multiply-and-shift pair. Both the unsigned `((x * M) >> S)` form
/// and the signed high-part-plus-sign-flag form are rewritten back to `x / D`
/// when the constants prove exact division over the dividend domain.
pub fn magic(ir: &mut FunctionIr) {
    let mut domains: std::collections::HashSet<(u16, bool)> = std::collections::HashSet::new();
    let mut narrowed: Vec<(u16, bool)> = Vec::new();
    // The signed 64-bit high-part chains widen the register domain instead of
    // narrowing it: the dividend is an int64 either way.
    let mut wide_signed: std::collections::HashSet<u16> = std::collections::HashSet::new();
    let mut wide_signed_ret: Vec<u16> = Vec::new();
    for block in &mut ir.blocks {
        magic_block(
            block,
            &mut domains,
            &mut narrowed,
            &mut wide_signed,
            &mut wide_signed_ret,
        );
    }
    // The reciprocal form reveals the true return width: its result feeds the
    // return register directly.
    for (dest_index, signed) in narrowed.drain(..) {
        if dest_index == 0 && (ir.ret_type == "uint64_t" || ir.ret_type == "int64_t") {
            ir.ret_type = if signed { "int32_t" } else { "uint32_t" }.to_owned();
        }
    }
    // The signed 64-bit chains speak the plain int64 domain; promote both the
    // dividend's parameter and the return register.
    wide_signed_ret.drain(..).for_each(|_| {
        ir.ret_type = "int64_t".to_owned();
    });
    // The reciprocal form shows the dividend width explicitly; narrow the
    // parameter type so the rendered division reads with the same width.
    for param in ir.params.iter_mut() {
        for (index, signed) in domains.iter() {
            if *index == param.index && !param.ty.ends_with('*') {
                param.ty = if *signed { "int32_t" } else { "uint32_t" }.to_owned();
            }
        }
        if wide_signed.contains(&param.index) {
            param.ty = "int64_t".to_owned();
        }
    }
}

/// Removes assignments whose value is a plain constant and whose destination is
/// reassigned before the next read; such statements only serve the reciprocal
/// chains this pass has already consumed.
/// Block-level dead-store elimination over the control flow: a definition
/// no path reads before overwriting it carries nothing, so the statement
/// leaves the pseudocode.
pub fn dce_flow(ir: &mut FunctionIr) {
    let count = ir.blocks.len();
    if count == 0 {
        return;
    }
    // An unmodeled instruction or an indirect jump may read anything, so
    // the blocks holding one keep every definition and read everything.
    let opaque: Vec<bool> = ir
        .blocks
        .iter()
        .map(|block| {
            block.stmts.iter().any(|stmt| {
                matches!(
                    stmt,
                    Stmt::Unsupported { .. }
                        | Stmt::BrIndirect { .. }
                        | Stmt::Br { target: None }
                )
            })
        })
        .collect();
    // Every register any statement could name, for the opaque blocks.
    let universe: std::collections::HashSet<u16> = (0..=31u16)
        .chain(crate::ir::TEMP_BASE..crate::ir::TEMP_BASE + 64)
        .collect();
    // A call writes whatever the callee writes, so nothing dies across it.
    let mut clobbered: std::collections::HashSet<u16> = std::collections::HashSet::new();
    for block in &ir.blocks {
        for stmt in &block.stmts {
            clobbered.extend(statement_registers(stmt).0);
        }
    }
    let successors: Vec<Vec<usize>> = (0..count).map(|index| successors(ir, index)).collect();
    let mut live_in: Vec<std::collections::HashSet<u16>> = vec![Default::default(); count];
    // Backward dataflow to a fixpoint: the loop is small and the sets are
    // register indices, so the sweep converges quickly.
    for _ in 0..count.max(4) * 2 {
        let mut changed = false;
        for index in (0..count).rev() {
            let mut live: std::collections::HashSet<u16> = successors[index]
                .iter()
                .flat_map(|next| live_in[*next].iter().copied())
                .collect();
            for stmt in ir.blocks[index].stmts.iter().rev() {
                if matches!(stmt, Stmt::Call { .. }) {
                    live.extend(clobbered.iter().copied());
                }
                let (writes, reads) = statement_registers(stmt);
                for written in &writes {
                    live.remove(written);
                }
                live.extend(reads);
            }
            if opaque[index] {
                live.extend(universe.iter().copied());
            }
            if live != live_in[index] {
                live_in[index] = live;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    for index in 0..count {
        if opaque[index] {
            continue;
        }
        let mut live: std::collections::HashSet<u16> = successors[index]
            .iter()
            .flat_map(|next| live_in[*next].iter().copied())
            .collect();
        let mut keep: Vec<bool> = vec![true; ir.blocks[index].stmts.len()];
        for (position, stmt) in ir.blocks[index].stmts.iter().enumerate().rev() {
            if matches!(stmt, Stmt::Call { .. }) {
                live.extend(clobbered.iter().copied());
            }
            let (writes, reads) = statement_registers(stmt);
            let pure = match stmt {
                Stmt::Assign { value, .. } => !reads_outside_frame(value),
                _ => true,
            };
            if let Stmt::Assign { dest, value } = stmt {
                let mut own = std::collections::HashSet::new();
                crate::pass::collect_reads(value, &mut own);
                if pure && !live.contains(&dest.index) && !own.contains(&dest.index) {
                    keep[position] = false;
                    continue;
                }
            }
            for written in &writes {
                live.remove(written);
            }
            live.extend(reads);
        }
        let kept: Vec<Stmt> = ir.blocks[index]
            .stmts
            .drain(..)
            .zip(keep)
            .filter_map(|(stmt, keep)| keep.then_some(stmt))
            .collect();
        ir.blocks[index].stmts = kept;
    }
}

/// The blocks a block can continue into.
fn successors(ir: &FunctionIr, index: usize) -> Vec<usize> {
    let find = |address: u64| ir.blocks.iter().position(|block| block.start == address);
    let fallthrough = (index + 1 < ir.blocks.len()).then_some(index + 1);
    let mut out = Vec::new();
    match ir.blocks[index].stmts.last() {
        Some(Stmt::Br {
            target: Some(target),
        }) => out.extend(find(*target)),
        Some(Stmt::Brif { target, .. }) | Some(Stmt::BrifFlags { target, .. }) => {
            out.extend(find(*target));
            out.extend(fallthrough);
        }
        Some(Stmt::Switch { cases, default, .. }) => {
            for (_, target) in cases {
                out.extend(find(*target));
            }
            if let Some(target) = default {
                out.extend(find(*target));
            }
        }
        Some(Stmt::Ret { .. }) | Some(Stmt::BrIndirect { .. }) | Some(Stmt::Trap) => {}
        _ => out.extend(fallthrough),
    }
    out
}

pub fn dce(ir: &mut FunctionIr) {
    // A register read in another block is live at this block's boundary, so
    // the per-block sweep must keep the definitions that feed it.
    let reads: Vec<std::collections::HashSet<u16>> = ir
        .blocks
        .iter()
        .map(|block| {
            block
                .stmts
                .iter()
                .flat_map(|stmt| statement_registers(stmt).1)
                .collect()
        })
        .collect();
    // A block inside a cycle reads its own live-outs again on the next
    // iteration, so its own reads are live at its boundary too.
    let cyclic = cyclic_blocks(ir);
    for (index, block) in ir.blocks.iter_mut().enumerate() {
        let mut outer: std::collections::HashSet<u16> = reads
            .iter()
            .enumerate()
            .filter(|(other, _)| *other != index)
            .flat_map(|(_, set)| set.iter().copied())
            .collect();
        if cyclic.contains(&index) {
            outer.extend(reads[index].iter().copied());
        }
        // A removed statement can strand the one feeding it, so sweep until
        // nothing changes.
        loop {
            let before = block.stmts.len();
            drop_dead_constants(block, &outer);
            if block.stmts.len() == before {
                break;
            }
        }
    }
}

fn drop_dead_constants(block: &mut crate::ir::Block, outer_reads: &std::collections::HashSet<u16>) {
    let mut keep: Vec<bool> = vec![true; block.stmts.len()];
    for (index, stmt) in block.stmts.iter().enumerate() {
        let Stmt::Assign { dest, value } = stmt else {
            continue;
        };
        // A read of memory outside the frame may be volatile, so it stays;
        // dead arithmetic (even a division) has no effect worth keeping.
        if reads_outside_frame(value) {
            continue;
        }
        if outer_reads.contains(&dest.index) {
            continue;
        }
        let mut dead = true;
        for later in block.stmts.iter().skip(index + 1) {
            let (writes, reads) = statement_registers(later);
            if reads.contains(&dest.index) {
                dead = false;
                break;
            }
            if writes.contains(&dest.index) {
                break;
            }
        }
        keep[index] = !dead;
    }
    let kept: Vec<Stmt> = block
        .stmts
        .drain(..)
        .zip(keep)
        .filter_map(|(stmt, keep)| keep.then_some(stmt))
        .collect();
    block.stmts = kept;
}

/// Recognizes a read-modify-write of one location: `t = *p; t = op(t, x);
/// *p = t` becomes `*p = op(*p, x)`, which a reader sees as `p += x`. The
/// temporary must be dead outside the triple, so the fusion only removes
/// statements nothing else can observe.
/// A store to a frame slot nothing ever reads is dead: the slot is a local,
/// and a function that handed its address to a callee is left alone.
pub fn drop_dead_frame_stores(ir: &mut FunctionIr) {
    let sp = stack_pointer(ir);
    // Every frame-slot address the body names, and whether one escapes.
    let mut read: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut escaped = false;
    let mut stores: Vec<(usize, usize, String)> = Vec::new();
    for (position, block) in ir.blocks.iter().enumerate() {
        for (index, stmt) in block.stmts.iter().enumerate() {
            match stmt {
                Stmt::Store { addr, value, .. } => {
                    if let Some(slot) = frame_slot_of(addr, sp) {
                        stores.push((position, index, slot));
                    } else if address_uses_frame(addr, sp) {
                        escaped = true;
                    }
                    collect_frame_reads(value, sp, &mut read);
                    if address_uses_frame(value, sp) {
                        escaped = true;
                    }
                }
                Stmt::Assign { dest, value } => {
                    // Moving the stack pointer is not an address that leaves.
                    if dest.index == sp {
                        continue;
                    }
                    collect_frame_reads(value, sp, &mut read);
                    if let Expr::Load { addr, .. } = value {
                        if frame_slot_of(addr, sp).is_none() && address_uses_frame(addr, sp) {
                            escaped = true;
                        }
                    } else if address_uses_frame(value, sp) {
                        escaped = true;
                    }
                }
                Stmt::Ret { value } => {
                    collect_frame_reads(value, sp, &mut read);
                    if address_uses_frame(value, sp) {
                        escaped = true;
                    }
                }
                Stmt::Brif { lhs, rhs, .. } => {
                    collect_frame_reads(lhs, sp, &mut read);
                    collect_frame_reads(rhs, sp, &mut read);
                    if address_uses_frame(lhs, sp) || address_uses_frame(rhs, sp) {
                        escaped = true;
                    }
                }
                _ => {}
            }
        }
    }
    // An address into the frame that leaves the store/load pair may be read
    // by a callee, so nothing about the slot is certain.
    if escaped {
        return;
    }
    let dead: std::collections::HashSet<(usize, usize)> = stores
        .into_iter()
        .filter(|(_, _, slot)| !read.contains(slot))
        .map(|(position, index, _)| (position, index))
        .collect();
    if dead.is_empty() {
        return;
    }
    for (position, block) in ir.blocks.iter_mut().enumerate() {
        let mut index = 0;
        block.stmts.retain(|_| {
            let keep = !dead.contains(&(position, index));
            index += 1;
            keep
        });
    }
}

/// The frame-slot key of an address, when it is exactly `sp + k`.
fn frame_slot_of(addr: &Expr, sp: u16) -> Option<String> {
    match addr {
        Expr::Reg { index, .. } if *index == sp => Some(format!("{sp}:0")),
        Expr::Bin {
            op: crate::ir::BinOp::Add,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Reg { index, .. }, Expr::Const(delta)) if *index == sp => {
                Some(format!("{sp}:{delta}"))
            }
            (Expr::Const(delta), Expr::Reg { index, .. }) if *index == sp => {
                Some(format!("{sp}:{delta}"))
            }
            _ => None,
        },
        _ => None,
    }
}

/// Every frame slot the value reads, found anywhere in it.
fn collect_frame_reads(
    expr: &Expr,
    sp: u16,
    read: &mut std::collections::HashSet<String>,
) {
    match expr {
        Expr::Load { addr, .. } => match frame_slot_of(addr, sp) {
            Some(slot) => {
                read.insert(slot);
            }
            None => collect_frame_reads(addr, sp, read),
        },
        Expr::Bin { lhs, rhs, .. } => {
            collect_frame_reads(lhs, sp, read);
            collect_frame_reads(rhs, sp, read);
        }
        Expr::SignExtend { value, .. } => collect_frame_reads(value, sp, read),
        Expr::Select {
            lhs, rhs, then, els, ..
        } => {
            collect_frame_reads(lhs, sp, read);
            collect_frame_reads(rhs, sp, read);
            collect_frame_reads(then, sp, read);
            collect_frame_reads(els, sp, read);
        }
        Expr::Reg { .. } | Expr::Const(_) => {}
    }
}

/// True when the expression computes a stack address that is not simply a
/// slot the code reads or writes: such a value may reach a callee.
fn address_uses_frame(expr: &Expr, sp: u16) -> bool {
    match expr {
        Expr::Reg { index, .. } => *index == sp,
        // A load through a slot is an ordinary local read; a load through
        // anything else carries the address it computed.
        Expr::Load { addr, .. } => frame_slot_of(addr, sp).is_none() && address_uses_frame(addr, sp),
        Expr::Bin { lhs, rhs, .. } => {
            address_uses_frame(lhs, sp) || address_uses_frame(rhs, sp)
        }
        Expr::SignExtend { value, .. } => address_uses_frame(value, sp),
        Expr::Select {
            lhs, rhs, then, els, ..
        } => {
            address_uses_frame(lhs, sp)
                || address_uses_frame(rhs, sp)
                || address_uses_frame(then, sp)
                || address_uses_frame(els, sp)
        }
        Expr::Const(_) => false,
    }
}

/// A definition read exactly once before the register is written again folds
/// into that reader, and the definition goes: the `-O0` shape
/// `x8 = w8; if (x8 & 0x80000000) ...` keeps no temporary.
pub fn inline_local_copies(ir: &mut FunctionIr) {
    // A definition inside a loop runs again on the next pass, so folding it
    // into its reader would drop the update: only blocks outside every
    // cycle are rewritten.
    let cyclic = cyclic_blocks(ir);
    for (position, block) in ir.blocks.iter_mut().enumerate() {
        if cyclic.contains(&position) {
            continue;
        }
        let mut index = 0;
        while index < block.stmts.len() {
            let Some((dest, value)) = (match &block.stmts[index] {
                Stmt::Assign { dest, value } => Some((dest.index, value.clone())),
                _ => None,
            }) else {
                index += 1;
                continue;
            };
            // Only a small pure expression is worth carrying to its reader.
            if expr_width(&value).is_none() || !is_pure(&value) {
                index += 1;
                continue;
            }
            // The registers the value reads must stay put until the use.
            let mut sources = std::collections::HashSet::new();
            crate::pass::collect_reads(&value, &mut sources);
            let mut reads = 0usize;
            let mut use_at = None;
            let mut clobbered = false;
            for position in index + 1..block.stmts.len() {
                let stmt = &block.stmts[position];
                let used = statement_reads(stmt);
                if used.contains(&dest) {
                    // A reader that names the register twice would have the
                    // value written out twice: only one read folds.
                    reads += count_reg(stmt, dest);
                    use_at = Some(position);
                }
                let written = statement_registers(stmt).0;
                if written.contains(&dest) {
                    break;
                }
                if written.intersection(&sources).next().is_some() {
                    clobbered = true;
                    break;
                }
            }
            let Some(use_at) = use_at else {
                index += 1;
                continue;
            };
            if reads != 1 || clobbered {
                index += 1;
                continue;
            }
            // Folding into a statement that writes what the value reads
            // would make the value depend on itself.
            if let Stmt::Assign { dest: reader, .. } = &block.stmts[use_at] {
                let mut reader_sources = std::collections::HashSet::new();
                crate::pass::collect_reads(&value, &mut reader_sources);
                if reader_sources.contains(&reader.index) {
                    index += 1;
                    continue;
                }
            }
            let mut ok = true;
            substitute_in_statement(&mut block.stmts[use_at], dest, &value, &mut ok);
            if !ok {
                index += 1;
                continue;
            }
            block.stmts.remove(index);
        }
    }
}

/// The blocks that can reach themselves: the bodies of the loops.
fn cyclic_blocks(ir: &FunctionIr) -> std::collections::HashSet<usize> {
    let index: std::collections::HashMap<u64, usize> = ir
        .blocks
        .iter()
        .enumerate()
        .map(|(position, block)| (block.start, position))
        .collect();
    let successors: Vec<Vec<usize>> = ir
        .blocks
        .iter()
        .map(|block| {
            let mut next = Vec::new();
            match block.stmts.last() {
                Some(Stmt::Brif { target, .. }) | Some(Stmt::BrifFlags { target, .. }) => {
                    if let Some(target) = index.get(target) {
                        next.push(*target);
                    }
                    next.push(
                        index
                            .get(&block.start)
                            .map(|position| position + 1)
                            .unwrap_or_default(),
                    );
                }
                Some(Stmt::Br {
                    target: Some(target),
                }) => {
                    if let Some(target) = index.get(target) {
                        next.push(*target);
                    }
                }
                Some(Stmt::Switch { cases, default, .. }) => {
                    for (_, target) in cases {
                        if let Some(target) = index.get(target) {
                            next.push(*target);
                        }
                    }
                    if let Some(target) = default {
                        if let Some(target) = index.get(target) {
                            next.push(*target);
                        }
                    }
                }
                Some(Stmt::Ret { .. }) | Some(Stmt::BrIndirect { .. }) | Some(Stmt::Trap) => {}
                _ => {
                    if let Some(position) = index.get(&block.start) {
                        next.push(position + 1);
                    }
                }
            }
            next.retain(|position| *position < ir.blocks.len());
            next
        })
        .collect();
    let mut cyclic = std::collections::HashSet::new();
    for start in 0..ir.blocks.len() {
        let mut seen = std::collections::HashSet::new();
        let mut stack = successors[start].clone();
        while let Some(next) = stack.pop() {
            if next == start {
                cyclic.insert(start);
                break;
            }
            if seen.insert(next) {
                stack.extend(successors[next].iter().copied());
            }
        }
    }
    cyclic
}

/// Replaces every read of `dest` in one statement with the value, which is
/// only correct when the value's own width fills the read exactly.
fn substitute_in_statement(stmt: &mut Stmt, dest: u16, value: &Expr, ok: &mut bool) {
    // The value's own width decides which reads it can fill.
    let width = expr_width(value).unwrap_or(64);
    match stmt {
        Stmt::Assign { value: target, .. } => {
            substitute_reg_inner(target, dest, width, value, ok)
        }
        Stmt::Store { addr, value: stored, .. } => {
            substitute_reg_inner(addr, dest, width, value, ok);
            substitute_reg_inner(stored, dest, width, value, ok);
        }
        Stmt::Brif { lhs, rhs, .. } => {
            substitute_reg_inner(lhs, dest, width, value, ok);
            substitute_reg_inner(rhs, dest, width, value, ok);
        }
        Stmt::Ret { value: returned } => {
            substitute_reg_inner(returned, dest, width, value, ok)
        }
        Stmt::Switch { index, .. } => substitute_reg_inner(index, dest, width, value, ok),
        Stmt::BrIndirect { target } => substitute_reg_inner(target, dest, width, value, ok),
        _ => {}
    }
}

/// True when evaluating the expression has no effect beyond its value.
fn is_pure(expr: &Expr) -> bool {
    match expr {
        Expr::Load { addr, .. } => is_pure(addr),
        Expr::Bin { lhs, rhs, .. } => is_pure(lhs) && is_pure(rhs),
        Expr::SignExtend { value, .. } => is_pure(value),
        Expr::Select {
            lhs, rhs, then, els, ..
        } => is_pure(lhs) && is_pure(rhs) && is_pure(then) && is_pure(els),
        Expr::Reg { .. } | Expr::Const(_) => true,
    }
}

/// A store the next statement reads back from the same slot hands its value
/// straight to the reader: `*(u32 *)&local_3 = w8; x8 = *(u32 *)&local_3;`
/// leaves `x8 = w8;` behind, which the later sweeps can act on.
pub fn forward_stored_values(ir: &mut FunctionIr) {
    let sp = stack_pointer(ir);
    for block in &mut ir.blocks {
        let mut pending: Vec<(String, Expr, Expr)> = Vec::new();
        for stmt in &mut block.stmts {
            match stmt {
                Stmt::Store {
                    addr, value, width, ..
                } => {
                    // Only a store of the same width to the same address can
                    // stand in for the load that reads it back.
                    let key = format!("{width}:{addr:?}");
                    pending.retain(|(stored, _, _)| *stored != key);
                    pending.push((key, addr.clone(), value.clone()));
                }
                Stmt::Call { .. } | Stmt::Unsupported { .. } => pending.clear(),
                Stmt::Assign { dest, value } => {
                    // Moving the stack pointer renames every frame slot, so
                    // the remembered addresses no longer mean what they did.
                    if dest.index == sp {
                        pending.clear();
                        continue;
                    }
                    forward_expr(value, &pending);
                }
                Stmt::Brif { lhs, rhs, .. } => {
                    forward_expr(lhs, &pending);
                    forward_expr(rhs, &pending);
                }
                Stmt::Ret { value } => forward_expr(value, &pending),
                _ => {}
            }
        }
    }
}

fn forward_expr(expr: &mut Expr, pending: &[(String, Expr, Expr)]) {
    match expr {
        Expr::Load { addr, width, .. } => {
            let key = format!("{width}:{addr:?}");
            if let Some((_, _, value)) = pending.iter().find(|(slot, _, _)| *slot == key) {
                *expr = value.clone();
                return;
            }
            forward_expr(addr, pending);
        }
        Expr::Bin { lhs, rhs, .. } => {
            forward_expr(lhs, pending);
            forward_expr(rhs, pending);
        }
        Expr::SignExtend { value, .. } => forward_expr(value, pending),
        Expr::Select {
            lhs, rhs, then, els, ..
        } => {
            forward_expr(lhs, pending);
            forward_expr(rhs, pending);
            forward_expr(then, pending);
            forward_expr(els, pending);
        }
        _ => {}
    }
}

pub fn fuse_load_op_store(ir: &mut FunctionIr) {
    for block in &mut ir.blocks {
        fuse_block(block);
    }
}

fn fuse_block(block: &mut crate::ir::Block) {
    let mut fused: Vec<usize> = Vec::new();
    let mut index = 0;
    while index < block.stmts.len() {
        if fused.contains(&index) {
            index += 1;
            continue;
        }
        // The update may already carry its load: `t = op(*p, x); *p = t`.
        if let Some((dest, address, update)) = inline_update(&block.stmts[index]) {
            if let Some(store_at) = store_back(&block.stmts, index, dest, &address) {
                if let Stmt::Store { value, .. } = &mut block.stmts[store_at] {
                    *value = update;
                }
                fused.push(index);
                index = store_at + 1;
                continue;
            }
        }
        let Some((dest, address, load)) = temporary_load(&block.stmts[index]) else {
            index += 1;
            continue;
        };
        // The next statement that touches the temporary must be the read
        // half of the update.
        let mut op_at = None;
        let mut clean = true;
        for probe in index + 1..block.stmts.len().min(index + 8) {
            let (writes, reads) = statement_registers(&block.stmts[probe]);
            if writes.contains(&dest) {
                op_at = Some(probe);
                break;
            }
            if reads.contains(&dest) {
                // Another consumer: this is not a single-use temporary.
                clean = false;
                break;
            }
        }
        let Some(op_at) = op_at else {
            index += 1;
            continue;
        };
        if !clean {
            index += 1;
            continue;
        }
        let Some((op, rhs)) = update_of(&block.stmts[op_at], dest) else {
            index += 1;
            continue;
        };
        // Then the temporary must be stored back to the same address.
        let mut store_at = None;
        let mut blocked = false;
        for probe in op_at + 1..block.stmts.len().min(op_at + 8) {
            let (writes, reads) = statement_registers(&block.stmts[probe]);
            if let Some((addr, value)) = store_pair(&block.stmts[probe]) {
                if address_eq(addr, &address) && reads_temporary(value, dest) == Some(true) {
                    store_at = Some(probe);
                    break;
                }
            }
            if reads.contains(&dest) || writes.contains(&dest) {
                blocked = true;
                break;
            }
        }
        let Some(store_at) = store_at else {
            index += 1;
            continue;
        };
        if blocked {
            index += 1;
            continue;
        }
        // Nothing may read the temporary after the store either.
        let mut escapes = false;
        for later in store_at + 1..block.stmts.len() {
            let (writes, reads) = statement_registers(&block.stmts[later]);
            if writes.contains(&dest) {
                break;
            }
            if reads.contains(&dest) {
                escapes = true;
                break;
            }
        }
        if escapes {
            index += 1;
            continue;
        }
        if let Stmt::Store { addr, value, .. } = &mut block.stmts[store_at] {
            *value = Expr::bin(op, load.clone(), rhs);
            let _ = addr;
        }
        fused.push(index);
        fused.push(op_at);
        index = store_at + 1;
    }
    if fused.is_empty() {
        return;
    }
    let kept: Vec<Stmt> = block
        .stmts
        .drain(..)
        .enumerate()
        .filter_map(|(position, stmt)| (!fused.contains(&position)).then_some(stmt))
        .collect();
    block.stmts = kept;
}

/// `t = *p` (optionally masked to the load's width).
fn temporary_load(stmt: &Stmt) -> Option<(u16, Expr, Expr)> {
    let Stmt::Assign { dest, value } = stmt else {
        return None;
    };
    let inner = strip_mask(value);
    let Expr::Load { addr, .. } = inner else {
        return None;
    };
    Some((dest.index, addr.as_ref().clone(), inner.clone()))
}

/// `t = op(t, rhs)` as the operator and its other operand.
fn update_of(stmt: &Stmt, dest: u16) -> Option<(crate::ir::BinOp, Expr)> {
    let Stmt::Assign { dest: written, value } = stmt else {
        return None;
    };
    if written.index != dest {
        return None;
    }
    let Expr::Bin { op, lhs, rhs } = strip_mask(value) else {
        return None;
    };
    let Expr::Reg { index, .. } = strip_mask(lhs) else {
        return None;
    };
    if *index != dest {
        return None;
    }
    Some((*op, rhs.as_ref().clone()))
}

/// `t = op(*p, x)` as the temporary, the address it updated and the new
/// value of the location.
fn inline_update(stmt: &Stmt) -> Option<(u16, Expr, Expr)> {
    let Stmt::Assign { dest, value } = stmt else {
        return None;
    };
    let Expr::Bin { op, lhs, rhs } = strip_mask(value) else {
        return None;
    };
    let read = strip_mask(lhs);
    let Expr::Load { addr, .. } = read else {
        return None;
    };
    // Rebuild the update around the plain read, so the renderer sees the
    // same shape a three-statement fusion produces.
    Some((
        dest.index,
        addr.as_ref().clone(),
        Expr::bin(*op, read.clone(), rhs.as_ref().clone()),
    ))
}

/// The statement storing the temporary back to the address it read,
/// provided nothing observes the temporary in between or after.
fn store_back(stmts: &[Stmt], index: usize, dest: u16, address: &Expr) -> Option<usize> {
    let mut store_at = None;
    for probe in index + 1..stmts.len().min(index + 8) {
        let (writes, reads) = statement_registers(&stmts[probe]);
        if let Some((addr, value)) = store_pair(&stmts[probe]) {
            if address_eq(addr, address) && reads_temporary(value, dest) == Some(true) {
                store_at = Some(probe);
                break;
            }
        }
        if reads.contains(&dest) || writes.contains(&dest) {
            return None;
        }
    }
    let store_at = store_at?;
    for later in store_at + 1..stmts.len() {
        let (writes, reads) = statement_registers(&stmts[later]);
        if writes.contains(&dest) {
            break;
        }
        if reads.contains(&dest) {
            return None;
        }
    }
    Some(store_at)
}

fn store_pair(stmt: &Stmt) -> Option<(&Expr, &Expr)> {
    match stmt {
        Stmt::Store { addr, value, .. } => Some((addr, value)),
        _ => None,
    }
}

/// True when the expression is a read of the register, possibly masked.
fn reads_temporary(value: &Expr, dest: u16) -> Option<bool> {
    let Expr::Reg { index, .. } = strip_mask(value) else {
        return Some(false);
    };
    Some(*index == dest)
}

fn address_eq(left: &Expr, right: &Expr) -> bool {
    format!("{left:?}") == format!("{right:?}")
}

/// Peels a `& mask` off the expression when the mask only truncates.
fn strip_mask(expr: &Expr) -> &Expr {
    match expr {
        Expr::Bin {
            op: crate::ir::BinOp::And,
            lhs,
            rhs,
        } => match rhs.as_ref() {
            Expr::Const(0xff)
            | Expr::Const(0xffff)
            | Expr::Const(0xffff_ffff)
            | Expr::Const(u64::MAX) => strip_mask(lhs),
            _ => expr,
        },
        _ => expr,
    }
}

/// Callee-saved register spills: the ABI prologue stores the registers the
/// function intends to borrow and the epilogue reads them back from the same
/// stack slot. Once the code is register-allocated that pair carries no
/// meaning, so drop both halves (and the frame adjustment when the stack is
/// not used for anything else).
///
/// The frame displacement is tracked in layout order, so a prologue and its
/// epilogue still name the same slot even though they sit in different
/// blocks and the stack pointer moved in between.
pub fn elide_callee_saves(ir: &mut FunctionIr) {
    let sp = stack_pointer(ir);
    struct Access {
        block: usize,
        position: usize,
        slot: i64,
        store: bool,
        reg: u16,
    }
    let mut accesses: Vec<Access> = Vec::new();
    let mut frame: i64 = 0;
    for (block_index, block) in ir.blocks.iter().enumerate() {
        for (position, stmt) in block.stmts.iter().enumerate() {
            match stmt {
                Stmt::Store { addr, value, .. } => {
                    let slot = stack_slot(addr, frame, sp);
                    if let (Some(slot), Expr::Reg { index, .. }) = (slot, value) {
                        accesses.push(Access {
                            block: block_index,
                            position,
                            slot,
                            store: true,
                            reg: *index,
                        });
                    }
                }
                Stmt::Assign { dest, value } => {
                    if let Expr::Load { addr, .. } = value {
                        if let Some(slot) = stack_slot(addr, frame, sp) {
                            accesses.push(Access {
                                block: block_index,
                                position,
                                slot,
                                store: false,
                                reg: dest.index,
                            });
                        }
                    }
                    if dest.index == sp {
                        if let Some(delta) = stack_delta(value, sp) {
                            frame = frame.wrapping_add(delta);
                        }
                    }
                }
                _ => {}
            }
        }
        // A conditional exit may reach a block whose frame differs.
        if matches!(block.stmts.last(), Some(Stmt::Brif { .. })) {
            frame = 0;
        }
    }
    // Each slot must be written once and read once, round-tripping the same
    // register, with that register untouched in between.
    let mut by_slot: HashMap<i64, Vec<usize>> = HashMap::new();
    for (index, access) in accesses.iter().enumerate() {
        by_slot.entry(access.slot).or_default().push(index);
    }
    let mut drop: std::collections::HashSet<(usize, usize)> = std::collections::HashSet::new();
    for list in by_slot.values() {
        if list.len() != 2 {
            continue;
        }
        let (first, second) = (&accesses[list[0]], &accesses[list[1]]);
        if !first.store || second.store || first.reg != second.reg || first.reg == sp {
            continue;
        }
        let mut borrowed = false;
        let mut frame_setup: Option<(usize, usize)> = None;
        'scan: for block_index in first.block..=second.block {
            let block = &ir.blocks[block_index];
            let start = if block_index == first.block {
                first.position + 1
            } else {
                0
            };
            let end = if block_index == second.block {
                second.position
            } else {
                block.stmts.len()
            };
            for position in start..end {
                let (writes, reads) = statement_registers(&block.stmts[position]);
                if reads.contains(&first.reg) {
                    borrowed = true;
                    break 'scan;
                }
                if writes.contains(&first.reg) {
                    // `mov fp, sp` is the frame setup, not a use of the
                    // register the prologue saved.
                    if is_frame_setup(&block.stmts[position], sp) {
                        frame_setup = Some((block_index, position));
                        continue;
                    }
                    borrowed = true;
                    break 'scan;
                }
            }
        }
        if borrowed {
            continue;
        }
        drop.insert((first.block, first.position));
        drop.insert((second.block, second.position));
        if let Some(position) = frame_setup {
            drop.insert(position);
        }
    }
    if drop.is_empty() {
        return;
    }
    // Without the spills, a frame that only existed to hold them can go too.
    let stack_still_used = ir.blocks.iter().enumerate().any(|(block_index, block)| {
        block.stmts.iter().enumerate().any(|(position, stmt)| {
            if drop.contains(&(block_index, position)) {
                return false;
            }
            let (writes, reads) = statement_registers(stmt);
            let touched = reads.contains(&sp) || writes.contains(&sp);
            if !touched {
                return false;
            }
            // The frame adjustments themselves are not a use.
            !matches!(
                stmt,
                Stmt::Assign { dest, value } if dest.index == sp && stack_delta(value, sp).is_some()
            )
        })
    });
    if !stack_still_used {
        for (block_index, block) in ir.blocks.iter().enumerate() {
            for (position, stmt) in block.stmts.iter().enumerate() {
                if let Stmt::Assign { dest, value } = stmt {
                    if dest.index == sp && stack_delta(value, sp).is_some() {
                        drop.insert((block_index, position));
                    }
                }
            }
        }
    }
    for (block_index, block) in ir.blocks.iter_mut().enumerate() {
        let mut keep = vec![true; block.stmts.len()];
        for (position, slot) in keep.iter_mut().enumerate() {
            if drop.contains(&(block_index, position)) {
                *slot = false;
            }
        }
        let kept: Vec<Stmt> = block
            .stmts
            .drain(..)
            .zip(keep)
            .filter_map(|(stmt, keep)| keep.then_some(stmt))
            .collect();
        block.stmts = kept;
    }
}

/// `mov fp, sp + k` — the frame pointer setup that follows a saved-register
/// store in a frame-pointer prologue.
fn is_frame_setup(stmt: &Stmt, sp: u16) -> bool {
    let Stmt::Assign { value, .. } = stmt else {
        return false;
    };
    match value {
        Expr::Reg { index, .. } => *index == sp,
        _ => stack_slot(value, 0, sp).is_some(),
    }
}

/// Frame-pointer elision: the `push rbp; mov rbp, rsp` / `mov rsp, rbp;
/// pop rbp` pair a compiler emits around every x86 function is pure noise
/// once the code is register-allocated. Drop the pair when the frame
/// pointer is never read in between and the stack pointer is only used by
/// the pair's own adjustments, so no address changes.
pub fn elide_frame_pointer(ir: &mut FunctionIr) {
    for block in &mut ir.blocks {
        elide_frame_pointer_block(block);
    }
}

fn elide_frame_pointer_block(block: &mut crate::ir::Block) {
    // The prologue: `rsp -= k`, `*(u64 *)rsp = rbp`, `rbp = rsp`.
    let Some((prologue, frame)) = frame_prologue(&block.stmts) else {
        return;
    };
    let Some(epilogue) = frame_epilogue(&block.stmts, frame) else {
        return;
    };
    // Nothing may read the frame pointer, and the stack pointer must stay
    // untouched, between the two ends of the pair.
    for position in prologue.end..epilogue.start {
        let (writes, reads) = statement_registers(&block.stmts[position]);
        let _ = writes;
        if reads.contains(&frame) || reads.contains(&STACK_POINTER) {
            return;
        }
    }
    // Remove the epilogue first so the prologue's indices stay valid.
    block.stmts.drain(epilogue.start..epilogue.end);
    block.stmts.drain(prologue.start..prologue.end);
}

/// The stack pointer's register index on both supported ISAs.
const STACK_POINTER: u16 = 4;

/// The stack pointer's register index for the function's ISA.
fn stack_pointer(ir: &FunctionIr) -> u16 {
    match ir.isa {
        crate::loader::Isa::AArch64 => 31,
        crate::loader::Isa::X86_64 => STACK_POINTER,
        crate::loader::Isa::Unsupported => STACK_POINTER,
    }
}

/// Canonical stack slot of a `sp + k` address, given the current frame
/// displacement, when the address is exactly that.
fn stack_slot(expr: &Expr, frame: i64, sp: u16) -> Option<i64> {
    let add = |offset: i64| Some(frame.wrapping_add(offset));
    match expr {
        Expr::Reg { index, .. } if *index == sp => Some(frame),
        Expr::Bin {
            op: crate::ir::BinOp::Add,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Reg { index, .. }, Expr::Const(delta)) if *index == sp => add(*delta as i64),
            (Expr::Const(delta), Expr::Reg { index, .. }) if *index == sp => add(*delta as i64),
            _ => None,
        },
        Expr::Bin {
            op: crate::ir::BinOp::Sub,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Reg { index, .. }, Expr::Const(delta)) if *index == sp => {
                add(-(*delta as i64))
            }
            _ => None,
        },
        _ => None,
    }
}

/// Reads `sp + k` / `sp - k` as a signed stack delta.
fn stack_delta(value: &Expr, sp: u16) -> Option<i64> {
    let Expr::Bin { op, lhs, rhs } = value else {
        return None;
    };
    if !matches!(lhs.as_ref(), Expr::Reg { index, .. } if *index == sp) {
        return None;
    }
    let Expr::Const(delta) = rhs.as_ref() else {
        return None;
    };
    let delta = *delta as i64;
    match op {
        crate::ir::BinOp::Add => Some(delta),
        crate::ir::BinOp::Sub => Some(-delta),
        _ => None,
    }
}

/// Matches `rsp -= k; *(u64 *)rsp = rbp; rbp = rsp` at the block's head and
/// returns the drained range plus the frame pointer's register.
fn frame_prologue(stmts: &[Stmt]) -> Option<(std::ops::Range<usize>, u16)> {
    let Stmt::Assign { dest: sp, value } = stmts.first()? else {
        return None;
    };
    if sp.index != STACK_POINTER {
        return None;
    }
    // The adjustment must reserve exactly one word.
    if stack_delta(value, STACK_POINTER)? != -(8i64) {
        return None;
    }
    // The saved register is stored, then becomes the frame pointer.
    let Stmt::Store { addr, value: saved, .. } = stmts.get(1)? else {
        return None;
    };
    if !matches!(addr, Expr::Reg { index, .. } if *index == STACK_POINTER) {
        return None;
    }
    let Expr::Reg { index: frame, .. } = saved else {
        return None;
    };
    let Stmt::Assign { dest: next, value: source } = stmts.get(2)? else {
        return None;
    };
    if next.index != *frame || !matches!(source, Expr::Reg { index, .. } if *index == STACK_POINTER) {
        return None;
    }
    Some((0..3, *frame))
}

/// Matches `rsp += k; rbp = *(u64 *)rsp` at the block's tail, returning the
/// range to drop. The saved register load must restore the same register.
fn frame_epilogue(stmts: &[Stmt], frame: u16) -> Option<std::ops::Range<usize>> {
    // A trailing `Ret` reads the restored frame's own result, so the pair
    // sits just before it.
    let mut len = stmts.len();
    if matches!(stmts.get(len.saturating_sub(1)), Some(Stmt::Ret { .. })) {
        len -= 1;
    }
    if len < 2 {
        return None;
    }
    let Stmt::Assign { dest: sp, value } = &stmts[len - 2] else {
        return None;
    };
    if sp.index != STACK_POINTER {
        return None;
    }
    if stack_delta(value, STACK_POINTER)? != 8 {
        return None;
    }
    let Stmt::Assign { dest: restored, value } = &stmts[len - 1] else {
        return None;
    };
    if restored.index != frame {
        return None;
    }
    let Expr::Load { addr, .. } = value else {
        return None;
    };
    if !matches!(addr.as_ref(), Expr::Reg { index, .. } if *index == STACK_POINTER) {
        return None;
    }
    Some(len - 2..len)
}

/// Copy propagation: a plain register copy folds into its single consumer,
/// the way mature decompilers inline the temporary a lift introduces.
/// Only single-use, width-preserving copies are folded so no value is
/// extended or truncated by accident.
pub fn copy_propagate(ir: &mut FunctionIr) {
    copy_propagate_with(ir, false);
}

/// The second inlining round runs after the CSE pass factored shared
/// subexpressions into temporaries, so it refuses to duplicate them.
pub fn copy_propagate_guarded(ir: &mut FunctionIr) {
    copy_propagate_with(ir, true);
}

fn copy_propagate_with(ir: &mut FunctionIr, avoid_duplication: bool) {
    let reads: Vec<std::collections::HashSet<u16>> = ir
        .blocks
        .iter()
        .map(|block| {
            block
                .stmts
                .iter()
                .flat_map(|stmt| statement_registers(stmt).1)
                .collect()
        })
        .collect();
    // A block inside a cycle reads its own live-outs again on the next
    // iteration, so its own reads are live at its boundary too.
    let cyclic = cyclic_blocks(ir);
    for (index, block) in ir.blocks.iter_mut().enumerate() {
        let mut outer: std::collections::HashSet<u16> = reads
            .iter()
            .enumerate()
            .filter(|(other, _)| *other != index)
            .flat_map(|(_, set)| set.iter().copied())
            .collect();
        if cyclic.contains(&index) {
            outer.extend(reads[index].iter().copied());
        }
        copy_propagate_block(block, &outer, avoid_duplication);
    }
}

fn copy_propagate_block(
    block: &mut crate::ir::Block,
    outer_reads: &std::collections::HashSet<u16>,
    avoid_duplication: bool,
) {
    let mut index = 0;
    while index < block.stmts.len() {
        let copy = match &block.stmts[index] {
            Stmt::Assign { dest, value } => {
                // A single-use temporary folds into its consumer: a plain
                // copy, the widening a 32-bit value enters the 64-bit
                // register file through, or a small pure expression.
                // The width the substitution must match is the one the reads
                // name; a value that carries its own conversion rides the
                // statement's own width instead.
                let fold_width = expr_width(value).unwrap_or(dest.width);
                let foldable = match value {
                    Expr::Reg { index: src, .. } => *src != dest.index,
                    Expr::SignExtend { .. } => true,
                    // A read outside the frame may be volatile, and a big
                    // expression only hurts readability once inlined.
                    _ => !reads_outside_frame(value) && expr_size(value) <= 8,
                };
                foldable.then(|| (dest.index, fold_width, value.clone()))
            }
            _ => None,
        };
        let Some((dest, width, template)) = copy else {
            index += 1;
            continue;
        };
        // A cross-block read keeps the temporary alive, unless this block
        // overwrites it again: readers then see the later value either way.
        let redefined = block.stmts.iter().skip(index + 1).any(|stmt| {
            statement_registers(stmt).0.contains(&dest)
        });
        if outer_reads.contains(&dest) && !redefined {
            index += 1;
            continue;
        }
        // The value's own registers must not change before the consumer.
        let mut sources: std::collections::HashSet<u16> = std::collections::HashSet::new();
        expr_reads(&template, &mut sources);
        if sources.contains(&dest) {
            index += 1;
            continue;
        }
        // One consumer, and no redefinition of the sources in between.
        let mut consumer = None;
        let mut foldable = true;
        for later in index + 1..block.stmts.len() {
            let (writes, reads) = statement_registers(&block.stmts[later]);
            let reads_dest = reads.contains(&dest);
            // A source rewritten by the consumer itself is fine: the read
            // happens before the write, exactly as the inlined text says.
            if writes.iter().any(|written| sources.contains(written)) && !reads_dest {
                foldable = false;
                break;
            }
            if reads_dest {
                if consumer.is_some() {
                    foldable = false;
                    break;
                }
                consumer = Some(later);
            }
            if writes.contains(&dest) {
                break;
            }
        }
        let Some(consumer) = consumer else {
            index += 1;
            continue;
        };
        if !foldable {
            index += 1;
            continue;
        }
        // Removing the copy is safe when the consumer rewrites the same
        // register (later reads see the new value) or when nothing else
        // reads the temporary before its next definition.
        let rewrites_dest = match assign_of(&block.stmts[consumer]) {
            Some((dest_ref, _)) => dest_ref.index == dest,
            None => false,
        };
        let mut other_reads = block.stmts.iter().enumerate().any(|(position, stmt)| {
            position != consumer
                && position != index
                && statement_registers(stmt).1.contains(&dest)
        });
        if other_reads && !rewrites_dest {
            // A read after the temporary is redefined observes the new
            // value, so only the reads before the next definition matter.
            let mut escapes = false;
            for later in consumer + 1..block.stmts.len() {
                let (writes, reads) = statement_registers(&block.stmts[later]);
                if writes.contains(&dest) {
                    break;
                }
                if reads.contains(&dest) {
                    escapes = true;
                    break;
                }
            }
            other_reads = escapes;
        }
        if !rewrites_dest && other_reads {
            index += 1;
            continue;
        }
        // Inlining a compound value into two reads would duplicate the
        // computation the CSE pass just factored out.
        let reads_in_consumer = count_reg(&block.stmts[consumer], dest);
        if avoid_duplication && reads_in_consumer > 1 && expr_size(&template) > 1 {
            index += 1;
            continue;
        }
        if !substitute_stmt(&mut block.stmts[consumer], dest, width, &template) {
            index += 1;
            continue;
        }
        block.stmts.remove(index);
        // The consumer shifted down by one, so the next iteration revisits
        // its position.
    }
}

/// The register width an expression computes at, when it is unambiguous.
/// `None` marks a value that carries its own conversion (a constant or a
/// sign extension), which inlines regardless of the consumer's width.
fn expr_width(expr: &Expr) -> Option<u8> {
    match expr {
        Expr::Reg { width, .. } => Some(*width),
        Expr::Const(_) => None,
        Expr::SignExtend { .. } => None,
        Expr::Load { width, .. } => Some(width.saturating_mul(8)),
        // A mask to 32 bits makes the value 32 bits wide whatever it
        // started as.
        Expr::Bin {
            op: crate::ir::BinOp::And,
            rhs,
            ..
        } if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) => Some(32),
        Expr::Bin { lhs, rhs, .. } => match (expr_width(lhs), expr_width(rhs)) {
            (Some(left), Some(right)) if left == right => Some(left),
            (Some(width), None) | (None, Some(width)) => Some(width),
            _ => None,
        },
        Expr::Select { then, els, .. } => match (expr_width(then), expr_width(els)) {
            (Some(left), Some(right)) if left == right => Some(left),
            (Some(width), None) | (None, Some(width)) => Some(width),
            _ => None,
        },
    }
}

/// Collects every register an expression reads.
pub fn collect_reads(expr: &Expr, out: &mut std::collections::HashSet<u16>) {
    match expr {
        Expr::Reg { index, .. } => {
            out.insert(*index);
        }
        Expr::Const(_) => {}
        Expr::Bin { lhs, rhs, .. } => {
            collect_reads(lhs, out);
            collect_reads(rhs, out);
        }
        Expr::Load { addr, .. } => collect_reads(addr, out),
        Expr::SignExtend { value, .. } => collect_reads(value, out),
        Expr::Select {
            lhs, rhs, then, els, ..
        } => {
            collect_reads(lhs, out);
            collect_reads(rhs, out);
            collect_reads(then, out);
            collect_reads(els, out);
        }
    }
}

/// Substitutes register reads with values, for folding a loop header into
/// the condition that consumes it.
pub fn substitute_values(expr: Expr, values: &[(u16, Expr)]) -> Expr {
    match expr {
        Expr::Reg { index, width } => match values.iter().find(|(reg, _)| *reg == index) {
            Some((_, value)) => value.clone(),
            None => Expr::Reg { index, width },
        },
        Expr::Const(value) => Expr::Const(value),
        Expr::Bin { op, lhs, rhs } => Expr::bin(
            op,
            substitute_values(*lhs, values),
            substitute_values(*rhs, values),
        ),
        Expr::Load { addr, width, signed } => Expr::Load {
            addr: Box::new(substitute_values(*addr, values)),
            width,
            signed,
        },
        Expr::SignExtend { value, width } => Expr::SignExtend {
            value: Box::new(substitute_values(*value, values)),
            width,
        },
        Expr::Select {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => Expr::Select {
            cond,
            lhs: Box::new(substitute_values(*lhs, values)),
            rhs: Box::new(substitute_values(*rhs, values)),
            then: Box::new(substitute_values(*then, values)),
            els: Box::new(substitute_values(*els, values)),
        },
    }
}

/// The registers a statement reads.
pub fn statement_reads(stmt: &Stmt) -> std::collections::HashSet<u16> {
    statement_registers(stmt).1
}

/// How many times a statement reads one register.
fn count_reg(stmt: &Stmt, reg: u16) -> usize {
    fn count(expr: &Expr, reg: u16) -> usize {
        match expr {
            Expr::Reg { index, .. } if *index == reg => 1,
            _ => children(expr).into_iter().map(|child| count(child, reg)).sum(),
        }
    }
    let mut total = 0;
    match stmt {
        Stmt::Assign { value, .. } => total += count(value, reg),
        Stmt::Store { addr, value, .. } => {
            total += count(addr, reg) + count(value, reg);
        }
        Stmt::Brif { lhs, rhs, .. } => total += count(lhs, reg) + count(rhs, reg),
        Stmt::Ret { value } => total += count(value, reg),
        Stmt::BrIndirect { target } => total += count(target, reg),
        _ => {}
    }
    total
}

/// Number of expression nodes, used to keep inlining from exploding.
fn expr_size(expr: &Expr) -> usize {
    1 + children(expr).into_iter().map(expr_size).sum::<usize>()
}

/// Applies the copy's value to every read inside one statement.
fn substitute_stmt(stmt: &mut Stmt, dest: u16, width: u8, template: &Expr) -> bool {
    let mut ok = true;
    match stmt {
        Stmt::Assign { value, .. } => substitute_reg_inner(value, dest, width, template, &mut ok),
        Stmt::Store { addr, value, .. } => {
            substitute_reg_inner(addr, dest, width, template, &mut ok);
            substitute_reg_inner(value, dest, width, template, &mut ok);
        }
        Stmt::Brif { lhs, rhs, .. } => {
            substitute_reg_inner(lhs, dest, width, template, &mut ok);
            substitute_reg_inner(rhs, dest, width, template, &mut ok);
        }
        Stmt::Ret { value } => substitute_reg_inner(value, dest, width, template, &mut ok),
        Stmt::BrIndirect { target } => {
            substitute_reg_inner(target, dest, width, template, &mut ok)
        }
        _ => ok = false,
    }
    ok
}

fn substitute_reg_inner(expr: &mut Expr, dest: u16, width: u8, template: &Expr, ok: &mut bool) {
    if !*ok {
        return;
    }
    if let Expr::Reg { index, width: read } = expr {
        if *index == dest {
            // A 32-bit value carries a zero-extended high half, so a wider
            // read of the same register takes it as well.
            let narrow_value = matches!(expr_width(template), Some(32));
            if *read != width && !(narrow_value && *read > 32 && width <= 32) {
                *ok = false;
                return;
            }
            *expr = template.clone();
        }
        return;
    }
    // A mask that fits in 32 bits asks only for those bits, so a 32-bit
    // value takes the masked read's place (the mask stays, without the
    // wider destination around it).
    if let Expr::Bin {
        op: crate::ir::BinOp::And,
        lhs,
        rhs,
    } = expr
    {
        let mask = match rhs.as_ref() {
            Expr::Const(mask) => Some(*mask),
            _ => None,
        };
        if let Some(mask) = mask {
            if mask <= 0xffff_ffff
                && matches!(lhs.as_ref(), Expr::Reg { index, .. } if *index == dest)
                && matches!(expr_width(template), Some(32))
            {
                let kept_mask = mask;
                *expr = Expr::bin(
                    crate::ir::BinOp::And,
                    template.clone(),
                    Expr::constant(kept_mask),
                );
                return;
            }
        }
    }
    match expr {
        Expr::Bin { lhs, rhs, .. } => {
            substitute_reg_inner(lhs, dest, width, template, ok);
            substitute_reg_inner(rhs, dest, width, template, ok);
        }
        Expr::Select {
            lhs, rhs, then, els, ..
        } => {
            substitute_reg_inner(lhs, dest, width, template, ok);
            substitute_reg_inner(rhs, dest, width, template, ok);
            substitute_reg_inner(then, dest, width, template, ok);
            substitute_reg_inner(els, dest, width, template, ok);
        }
        Expr::Load { addr, .. } => substitute_reg_inner(addr, dest, width, template, ok),
        Expr::SignExtend { value, .. } => {
            substitute_reg_inner(value, dest, width, template, ok)
        }
        _ => {}
    }
}

/// True when the expression loads through an address that is not a stack
/// slot: frame accesses are ordinary locals, everything else may be volatile.
fn reads_outside_frame(expr: &Expr) -> bool {
    match expr {
        Expr::Load { addr, .. } => {
            !address_uses_stack(addr) || reads_outside_frame(addr)
        }
        Expr::Bin { lhs, rhs, .. } => {
            reads_outside_frame(lhs) || reads_outside_frame(rhs)
        }
        Expr::SignExtend { value, .. } => reads_outside_frame(value),
        Expr::Select {
            lhs, rhs, then, els, ..
        } => {
            reads_outside_frame(lhs)
                || reads_outside_frame(rhs)
                || reads_outside_frame(then)
                || reads_outside_frame(els)
        }
        _ => false,
    }
}

fn address_uses_stack(expr: &Expr) -> bool {
    match expr {
        Expr::Reg { index, .. } => *index == STACK_POINTER || *index == 31,
        Expr::Bin { lhs, rhs, .. } => address_uses_stack(lhs) || address_uses_stack(rhs),
        Expr::SignExtend { value, .. } => address_uses_stack(value),
        _ => false,
    }
}

fn statement_registers(
    stmt: &Stmt,
) -> (
    std::collections::HashSet<u16>,
    std::collections::HashSet<u16>,
) {
    let mut writes = std::collections::HashSet::new();
    let mut reads = std::collections::HashSet::new();
    match stmt {
        Stmt::Assign { dest, value } => {
            writes.insert(dest.index);
            expr_reads(value, &mut reads);
        }
        Stmt::Store { addr, value, .. } => {
            expr_reads(addr, &mut reads);
            expr_reads(value, &mut reads);
        }
        Stmt::Brif { lhs, rhs, .. } => {
            expr_reads(lhs, &mut reads);
            expr_reads(rhs, &mut reads);
        }
        Stmt::Ret { value } => expr_reads(value, &mut reads),
        Stmt::BrIndirect { target } => expr_reads(target, &mut reads),
        _ => {}
    }
    (writes, reads)
}

/// Every register an expression reads, at any depth.
fn expr_reads(expr: &Expr, reads: &mut std::collections::HashSet<u16>) {
    match expr {
        Expr::Reg { index, .. } => {
            reads.insert(*index);
        }
        Expr::Const(_) => {}
        _ => {
            for child in children(expr) {
                expr_reads(child, reads);
            }
        }
    }
}

fn sar_dst_of(block: &crate::ir::Block, index: usize) -> u16 {
    assign_of(block.stmts.get(index).unwrap_or(&Stmt::Ret { value: Expr::Const(0) }))
        .map_or(0, |(dest, _)| dest.index)
}

fn magic_block(
    block: &mut crate::ir::Block,
    domains: &mut std::collections::HashSet<(u16, bool)>,
    narrowed: &mut Vec<(u16, bool)>,
    wide_signed: &mut std::collections::HashSet<u16>,
    wide_signed_ret: &mut Vec<u16>,
) {
    let mut consumed: std::collections::HashSet<usize> = std::collections::HashSet::new();
    let mut replacements: Vec<(usize, Expr)> = Vec::new();
    let mut index = 0usize;

    // Signed power-of-two division collapses from its sign select; run before
    // the widening-product scans so either shape claims the block cleanly.
    if let Some((sar_index, select_index, adjusted_def, divisor, leaf, domain_bits)) =
        signed_select_chain(block.stmts.as_slice())
    {
        // The gate follows the select's own result register, not the
        // dividend: the leaf keeps every pre-chain read.
        let select_src = sar_dst_of(block, select_index);
        if single_use(
            block.stmts.as_slice(),
            select_index,
            sar_index,
            select_src,
        ) && dropped_dest_safe(
            block.stmts.as_slice(),
            select_index,
            sar_index,
            select_index,
        ) {
            if let Some(param) = operand_index(&leaf) {
                let root = dividend_parameter(block.stmts.as_slice(), select_index, param);
                if domain_bits == 32 {
                    domains.insert((root, true));
                } else {
                    wide_signed.insert(root);
                }
            }
            let sar_dst = sar_dst_of(block, sar_index);
            if domain_bits == 32 {
                narrowed.push((sar_dst, true));
            } else {
                wide_signed_ret.push(sar_dst);
            }
            consumed.insert(select_index);
            if let Some(def) = adjusted_def {
                consumed.insert(def);
            }
            replacements.push((sar_index, division(leaf.clone(), divisor)));
        }
    }

    // The csneg family's low-bit modulo collapse: the select over negated
    // masked values is one exact `% d`.
    for probe in 0..block.stmts.len() {
        if consumed.contains(&probe) {
            continue;
        }
        let Some((dest, value)) = assign_of(&block.stmts[probe]) else {
            continue;
        };
        if !matches!(value, Expr::Select { .. }) {
            continue;
        }
        let Some((steps, divisor, dividend, width)) =
            cs_neg_chain(block.stmts.as_slice(), probe)
        else {
            continue;
        };
        // Every register the chain drops must be dead afterwards: only the
        // select (rewritten in place) and the chain's own steps may read it.
        let safe = steps.iter().all(|step| {
            let Some((dest, _)) = assign_of(&block.stmts[*step]) else {
                return false;
            };
            block.stmts.iter().enumerate().all(|(offset, other)| {
                if offset == probe || offset == *step || steps.contains(&offset) {
                    return true;
                }
                if matches!(other, Stmt::Ret { .. }) {
                    return true;
                }
                let (_, reads) = statement_registers(other);
                !reads.contains(&dest.index)
            })
        });
        if !safe {
            continue;
        }
        for step in steps {
            consumed.insert(step);
        }
        let leaf = Expr::Reg {
            index: dividend,
            width,
        };
        if width == 32 {
            domains.insert((dividend, true));
            narrowed.push((dest.index, true));
        } else {
            wide_signed.insert(dividend);
            wide_signed_ret.push(dest.index);
        }
        replacements.push((probe, remainder(leaf, divisor, false)));
    }

    // Signed power-of-two modulus: `x - (select(x >= 0, x, x + d) & ~d)`
    // is one exact `% d`. It shares the division shape's sign select.
    if let Some((sub_index, select_index, adjusted_def, divisor, leaf, domain_bits)) =
        signed_select_mod_chain(block.stmts.as_slice())
    {
        let select_src = sar_dst_of(block, select_index);
        if single_use(
            block.stmts.as_slice(),
            select_index,
            sub_index,
            select_src,
        ) && dropped_dest_safe(
            block.stmts.as_slice(),
            select_index,
            sub_index,
            select_index,
        ) {
            if let Some(param) = operand_index(&leaf) {
                let root = dividend_parameter(block.stmts.as_slice(), select_index, param);
                if domain_bits == 32 {
                    domains.insert((root, true));
                } else {
                    wide_signed.insert(root);
                }
            }
            let sub_dst = sar_dst_of(block, sub_index);
            if domain_bits == 32 {
                narrowed.push((sub_dst, true));
            } else {
                wide_signed_ret.push(sub_dst);
            }
            if let Some(def) = adjusted_def {
                consumed.insert(def);
            }
            replacements.push((sub_index, remainder(leaf, divisor, false)));
        }
    }

    while index < block.stmts.len() {
        if consumed.contains(&index) {
            index += 1;
            continue;
        }
        let Some((dest, value)) = assign_of(&block.stmts[index]) else {
            index += 1;
            continue;
        };
        let Some((operand, magic, domain_bits)) = magic_product(value) else {
            index += 1;
            continue;
        };
        if magic == 0 {
            index += 1;
            continue;
        }

        // Remainder chain: the quotient unwind reads `x - (x / d) * d` and
        // collapses into a single `% x`; its steps own nothing else.
        if let Some((sub_position, chain_steps, divisor, signed, width)) =
            remainder_scan(block.stmts.as_slice(), index, dest.index)
        {
            if single_use(block.stmts.as_slice(), index, sub_position, dest.index) {
                let mut all_safe = true;
                for step in &chain_steps {
                    if !dropped_dest_safe(
                        block.stmts.as_slice(),
                        index,
                        sub_position,
                        *step,
                    ) {
                        all_safe = false;
                        break;
                    }
                }
                if all_safe {
                    if let Some(param_index) = operand_index(&operand) {
                        let root = dividend_parameter(
                            block.stmts.as_slice(),
                            index,
                            param_index,
                        );
                        let sub = assign_of(&safe(&block.stmts, sub_position))
                            .map_or(0, |(dest, _)| dest.index);
                        // A zero-extension mask in the unwind proves the
                        // 32-bit domain even when the register is 64-bit.
                        let masked = assign_of(&safe(&block.stmts, sub_position))
                            .map(|(_, value)| !std::ptr::eq(strip_and_mask(value), value))
                            .unwrap_or(false);
                        let width = if masked { 32 } else { width };
                        // The quotient's own domain sets the register types.
                        if width == 32 {
                            domains.insert((root, signed));
                            narrowed.push((sub, signed));
                        } else if signed {
                            wide_signed.insert(root);
                            wide_signed_ret.push(sub);
                        }
                    }
                    consumed.insert(index);
                    for step in chain_steps {
                        consumed.insert(step);
                    }
                    let leaf = remainder_leaf(&safe(&block.stmts, sub_position));
                                    replacements.push((sub_position, remainder(leaf, divisor, !signed)));
                    index = sub_position + 1;
                    continue;
                }
            }
        }

        // Unsigned chain: `p = A * M; r = p >> shift`. A high-part product
        // carries its own 64-bit shift, so the total is `64 + shift`.
        let high_part_product = matches!(
            value,
            Expr::Bin {
                op: crate::ir::BinOp::MulHigh | crate::ir::BinOp::MulHighS,
                ..
            }
        );
        match block.stmts.get(index + 1).and_then(|step| match assign_of(step) {
            Some((_, shr_value)) => {
                let Some((source, shift)) = shift_of(shr_value) else {
                    return None;
                };
                if source != dest.index {
                    return None;
                }
                let (total, domain) = if high_part_product {
                    (64 + shift, 64)
                } else {
                    (shift, domain_bits)
                };
                let divisor = magic_divisor(magic, total, domain)
                    .or_else(|| magic_divisor(magic, shift, 32))?;
                Some((divisor, index + 1))
            }
            _ => None,
        }) {
            Some((divisor, shift_index)) => {
                if !single_use(block.stmts.as_slice(), index, shift_index, dest.index) {
                    index += 1;
                    continue;
                }
                // Narrowing only applies where the dividend fits 32 bits.
                if !high_part_product {
                    if let Some(index) = operand_index(&operand) {
                        domains.insert((index, false));
                    }
                    if let Some(dest) = shift_dest_of(&block, shift_index) {
                        narrowed.push((dest, false));
                    }
                }
                consumed.insert(index);
                replacements.push((shift_index, division_unsigned(operand.clone(), divisor)));
                index = shift_index + 1;
                continue;
            }
            None => {}
        }

        // Unsigned 64-bit copy-tolerant chain: the 1-operand mul's low half
        // sits between the widening product and the final shift.
        if high_part_product {
            if let Some((shift_index, chain_steps, divisor)) = unsigned64_chain(
                block.stmts.as_slice(),
                index,
                dest.index,
                magic,
                domain_bits,
            ) {
                if !single_use(block.stmts.as_slice(), index, shift_index, dest.index) {
                    index += 1;
                    continue;
                }
                let all_safe = chain_steps.iter().all(|from| {
                    dropped_dest_safe(block.stmts.as_slice(), index, shift_index, *from)
                });
                if !all_safe {
                    index += 1;
                    continue;
                }
                for step in &chain_steps {
                    consumed.insert(*step);
                }
                consumed.insert(index);
                replacements.push((shift_index, division_unsigned(operand.clone(), divisor)));
                index = shift_index + 1;
                continue;
            }
        }

        // Signed 64-bit chain: the signed widening multiply plus its
        // sign-flag sum. Consumed regardless of the low half's neutral write.
        let effective_domain = chain_dividend_domain(block.stmts.as_slice(), index, &operand);
        if let Some((sum_position, chain_steps, divisor)) = signed64_chain(
            block.stmts.as_slice(),
            index,
            dest.index,
            magic,
            effective_domain,
            high_part_product,
        ) {
            if !single_use(block.stmts.as_slice(), index, sum_position, dest.index) {
                index += 1;
                continue;
            }
            let all_safe = chain_steps
                .iter()
                .all(|from| dropped_dest_safe(block.stmts.as_slice(), index, sum_position, *from));
            if !all_safe {
                index += 1;
                continue;
            }
            if let Some(leaf) = operand_index(&operand) {
                let root = dividend_parameter(block.stmts.as_slice(), index, leaf);
                if effective_domain == 32 {
                    domains.insert((root, true));
                } else {
                    wide_signed.insert(root);
                }
            }
            for step in &chain_steps {
                consumed.insert(*step);
            }
            consumed.insert(index);
            if let Some(stmt) = block.stmts.get(sum_position) {
                if let Some((sum_dst, _)) = assign_of(stmt) {
                    if effective_domain == 32 {
                        narrowed.push((sum_dst.index, true));
                    } else {
                        wide_signed_ret.push(sum_dst.index);
                    }
                }
            }
            replacements.push((sum_position, division(operand.clone(), divisor)));
            index = sum_position + 1;
            continue;
        }

        // Signed chain: the widening multiply, register copies, a sign flag
        // shift (63), a high-part shift (32), then the 32-bit sum.
        if let Some((sum_position, chain_steps, divisor)) = signed_chain(
            block.stmts.as_slice(),
            index,
            dest.index,
            magic,
            domain_bits,
        ) {
            if !single_use(block.stmts.as_slice(), index, sum_position, dest.index) {
                index += 1;
                continue;
            }
            let all_safe = chain_steps
                .iter()
                .all(|from| dropped_dest_safe(block.stmts.as_slice(), index, sum_position, *from));
            if !all_safe {
                index += 1;
                continue;
            }
            if let Some(leaf) = operand_index(&operand) {
                domains.insert((leaf, true));
            }
            for step in &chain_steps {
                consumed.insert(*step);
            }
            consumed.insert(index);
            if let Some(stmt) = block.stmts.get(sum_position) {
                if let Some((sum_dst, _)) = assign_of(stmt) {
                    narrowed.push((sum_dst.index, true));
                }
            }
            replacements.push((sum_position, division(operand.clone(), divisor)));
            index = sum_position + 1;
            continue;
        }

        index += 1;
    }

    apply_remainder_follows(
        block.stmts.as_slice(),
        &mut consumed,
        &mut replacements,
        domains,
        narrowed,
        wide_signed,
        wide_signed_ret,
    );

    if consumed.is_empty() {
        return;
    }
    let mut kept: Vec<Stmt> = Vec::with_capacity(block.stmts.len());
    let mut pending = replacements;
    for (position, stmt) in block.stmts.drain(..).enumerate() {
        if let Some(slot) = pending.iter().position(|(target, _)| *target == position) {
            let (_, value) = pending.remove(slot);
            let mut node = stmt;
            if let Stmt::Assign { value: slot_expr, .. } = &mut node {
                *slot_expr = value;
            }
            kept.push(node);
            continue;
        }
        if consumed.contains(&position) {
            continue;
        }
        kept.push(stmt);
    }
    block.stmts = kept;
}

fn operand_index(operand: &Expr) -> Option<u16> {
    match operand {
        Expr::Reg { index, .. } => Some(*index),
        _ => None,
    }
}

/// The rewritten shift's destination, needed when the divisor result feeds the
/// return path.
fn shift_dest_of(block: &crate::ir::Block, index: usize) -> Option<u16> {
    block
        .stmts
        .get(index)
        .and_then(|statement| statement_register_dest(statement))
}

fn statement_register_dest(stmt: &Stmt) -> Option<u16> {
    match stmt {
        Stmt::Assign { dest, .. } => Some(dest.index),
        _ => None,
    }
}

fn magic_product(value: &Expr) -> Option<(Expr, u64, u64)> {
    let Expr::Bin {
        op: product_op,
        lhs,
        rhs,
    } = value
    else {
        return None;
    };
    if !matches!(
        product_op,
        crate::ir::BinOp::Mul
            | crate::ir::BinOp::MulHigh
            | crate::ir::BinOp::MulHighS
    ) {
        return None;
    }
    // The compiler may emit either operand order.
    let (leaf, magic_rhs) = if matches!(rhs.as_ref(), Expr::Const(_)) {
        (lhs.as_ref(), rhs.as_ref())
    } else if matches!(lhs.as_ref(), Expr::Const(_)) {
        (rhs.as_ref(), lhs.as_ref())
    } else {
        return None;
    };
    let Expr::Const(magic) = magic_rhs else {
        return None;
    };
    let high_part = matches!(
        product_op,
        crate::ir::BinOp::MulHigh | crate::ir::BinOp::MulHighS
    );
    let magic_cap = if high_part { u64::MAX } else { 0xffff_ffff };
    if *magic == 0 || *magic > magic_cap {
        return None;
    }
    let Some(domain_bits) = leaf_domain(leaf) else {
        return None;
    };
    let Some(operand) = leaf_operand(leaf) else {
        return None;
    };
    Some((operand, *magic, domain_bits))
}

/// Canonical dividend: a masked 64-bit slot becomes its 32-bit register form so
/// the division renders without the zero-extension noise.
fn leaf_operand(expr: &Expr) -> Option<Expr> {
    match expr {
        Expr::Reg { width, .. } if *width == 32 || *width == 64 => Some(expr.clone()),
        Expr::SignExtend { .. } => Some(expr.clone()),
        Expr::Bin {
            op: crate::ir::BinOp::And,
            lhs,
            rhs,
        } => {
            let Expr::Const(0xffff_ffff) = rhs.as_ref() else {
                return None;
            };
            match &**lhs {
                Expr::Reg { index, .. } => Some(Expr::Reg {
                    index: *index,
                    width: 32,
                }),
                _ => None,
            }
        }
        _ => None,
    }
}

fn leaf_domain(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Reg { width, .. } if *width == 32 || *width == 64 => Some(u64::from(*width)),
        Expr::Bin {
            op: crate::ir::BinOp::And,
            lhs,
            rhs,
        } => {
            let Expr::Const(0xffff_ffff) = rhs.as_ref() else {
                return None;
            };
            matches!(**lhs, Expr::Reg { .. }).then_some(32)
        }
        Expr::SignExtend { width, .. } => Some(u64::from(*width) * 8),
        _ => None,
    }
}

fn shift_of(value: &Expr) -> Option<(u16, u64)> {
    let Expr::Bin {
        op: crate::ir::BinOp::Shr,
        lhs,
        rhs,
    } = value
    else {
        return None;
    };
    let Expr::Const(shift) = rhs.as_ref() else {
        return None;
    };
    let Some(source) = unwrap_leaf(lhs.as_ref()) else {
        return None;
    };
    Some((source, *shift))
}

fn unwrap_leaf(expr: &Expr) -> Option<u16> {
    match expr {
        Expr::Reg { index, .. } => Some(*index),
        Expr::Bin {
            op: crate::ir::BinOp::And,
            lhs,
            rhs,
        } => {
            let Expr::Const(0xffff_ffff) = rhs.as_ref() else {
                return None;
            };
            match lhs.as_ref() {
                Expr::Reg { index, .. } => Some(*index),
                _ => unwrap_leaf(lhs.as_ref()),
            }
        }
        _ => None,
    }
}

/// Strips the lifter's trailing zero-extension wrapper so the underlying
/// expression can be matched.
fn strip_and_mask(expr: &Expr) -> &Expr {
    match expr {
        Expr::Bin {
            op: crate::ir::BinOp::And,
            lhs,
            rhs,
        } => {
            if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) {
                lhs.as_ref()
            } else {
                expr
            }
        }
        _ => expr,
    }
}


/// Restricts the rewrite to chains whose source register is written exactly
/// once inside the scanned statement: the rewritten value must not be reused.
fn single_use(stmts: &[Stmt], span_start: usize, span_end: usize, reg: u16) -> bool {
    for (position, stmt) in stmts.iter().enumerate() {
        if position >= span_start && position <= span_end {
            continue;
        }
        // A return that consumes the dividend's register only reads the chain's
        // own output, so rewriting is safe there.
        if matches!(stmt, Stmt::Ret { .. }) {
            continue;
        }
        let (_, reads) = statement_registers(stmt);
        if reads.contains(&reg) && !remainder_tail(stmts, position, reg) {
            return false;
        }
    }
    true
}

/// The reads of the quotient that belong to a rest of the remainder chain
/// (`x - q * d`): mask re-copies and the sign sum. Such a tail is collapsed
/// into `%` by `apply_remainder_follows`, so its reads do not escape.
fn remainder_tail(stmts: &[Stmt], from: usize, reg: u16) -> bool {
    let mut unwound = false;
    for position in from..stmts.len() {
        let stmt = &stmts[position];
        let (_, reads) = statement_registers(stmt);
        if !reads.contains(&reg) {
            if unwound {
                continue;
            }
            continue;
        }
        if unwound {
            // Anything reading the quotient after the unwind escapes.
            return false;
        }
        match tail_shape(stmt) {
            Some(true) => unwound = true,
            Some(false) => {}
            None => return false,
        }
    }
    unwound
}

/// `Some(true)` for the `x - q * d` unwind, `Some(false)` for a chain-tail
/// statement that only re-masks or sign-corrects the quotient.
fn tail_shape(stmt: &Stmt) -> Option<bool> {
    let Stmt::Assign { value, .. } = stmt else {
        return None;
    };
    match strip_and_mask(value) {
        Expr::Bin {
            op: crate::ir::BinOp::Sub,
            rhs,
            ..
        } => match strip_and_mask(rhs) {
            Expr::Bin {
                op: crate::ir::BinOp::Mul,
                ..
            } => Some(true),
            _ => None,
        },
        // `q & mask` and `(t + (t >> k)) & mask` are the chain's own tail.
        Expr::Bin {
            op: crate::ir::BinOp::And,
            ..
        } => Some(false),
        _ => None,
    }
}

/// Divisor recovery for the signed widening multiply `((x * M) >> S)` with
/// both the in-place high part (ARM64 `smulh`) and the x86-64 register-copy
/// chains. Exact over all `x` in `[-2^(n-1), 2^(n-1))` by the boundary checks.
fn magic_divisor_signed64(magic: u64, total_shift: u64, domain_bits: u64) -> Option<u64> {
    // A signed high-part chain can carry the whole quotient in the multiply's
    // own high 64 bits, so the total shift's floor is the domain width.
    if magic == 0 || total_shift < domain_bits || total_shift > 127
        || domain_bits > 64
    {
        return None;
    }
    let modulus: u128 = 1u128 << total_shift;
    let magic_ = u128::from(magic);
    let domain: u128 = 1u128 << domain_bits;
    let base = modulus / magic_;
    for offset in 0..=2u128 {
        let divisor = base + offset;
        if divisor == 0 || divisor >= domain {
            continue;
        }
        let product = divisor * magic_;
        if product < modulus {
            continue;
        }
        let slip = product - modulus;
        let inputs = (domain / 2 - 1) / divisor;
        if inputs * slip <= modulus && inputs * slip < magic_ {
            return u64::try_from(divisor).ok();
        }
    }
    None
}

/// Recognizes the signed 64-bit high-part constant-reciprocal chain:
///
/// ARM64:   `p = hi128S(a, M)`, then either `r = p + p lsr 63` (k = 0) or
///          `m = asr(p, k); r = m + p lsr 63`.
/// x86-64:  `p = hi128S(a, M); low = a * M; q = p;` … then
///          `s = shr(p, 63)`, an optional `sar(p, k)`, and
///          `r = sign-part + main-part` in either operand order.
///
/// Only pure register copies of the product may appear between the multiply
/// and the sum; anything else aborts the chain, so the rewrite is sound even
/// when the block carries other register traffic.
fn signed64_chain(
    statements: &[Stmt],
    start: usize,
    dest_index: u16,
    magic: u64,
    domain_bits: u64,
    high_part: bool,
) -> Option<(usize, Vec<usize>, u64)> {
    let mut p_aliases: Vec<u16> = vec![dest_index];
    let mut sign_alias: Option<u16> = None;
    let mut main_alias: Option<u16> = None;
    let mut extra_shift: Option<u64> = None;
    let mut steps: Vec<usize> = Vec::new();
    let mut low_seen = false;

    for position in (start + 1)..(start + 8).min(statements.len()) {
        let Some((dest_ref, value)) = assign_of(&statements[position]) else {
            return None;
        };
        let dest = dest_ref.index;
        // The chain's operands may be wrapped in the lifter's zero-extension
        // mask; the mask does not change the chain's value.
        let value = strip_and_mask(value);
        match value {
            // The x86-64 1-operand imul lift also emits the low half of the
            // same product; it carries nothing the chain needs.
            Expr::Bin {
                op: crate::ir::BinOp::Mul,
                ..
            } => {
                if low_seen {
                    return None;
                }
                low_seen = true;
                // The low half is dropped only when the chain's outcome owns
                // every remaining use of its destination.
                steps.push(position);
                continue;
            }
            // A pure register copy of the product's value.
            Expr::Reg { index, .. } => {
                if p_aliases.contains(index) || main_alias == Some(*index) {
                    p_aliases.push(dest);
                    steps.push(position);
                    continue;
                }
                return None;
            }
            // The lifter's zero-extension temp re-binds the product value and
            // narrows the chain's arithmetic width.
            Expr::Bin {
                op: crate::ir::BinOp::And,
                lhs,
                ..
            } => {
                let base = match lhs.as_ref() {
                    Expr::Reg { index, .. } => Some(*index),
                    _ => None,
                };
                let binds_product = base.map_or(false, |index| {
                    p_aliases.contains(&index) || main_alias == Some(index)
                });
                            if !binds_product {
                    return None;
                }
                p_aliases.push(dest);
                steps.push(position);
                continue;
            }
            Expr::Bin { op, lhs, rhs } => match (op, lhs.as_ref(), rhs.as_ref()) {
                // Sign flag: q = p lsr 63 (the ARM64 lsr / x86 shr form) or
                // q = p asr 63.
                (
                    crate::ir::BinOp::Shr | crate::ir::BinOp::Sar,
                    Expr::Reg { index, .. },
                    Expr::Const(shift),
                ) if matches!(*shift, 63 | 31) || *shift + 1 == u64::from(dest_ref.width) => {
                    if p_aliases.contains(index) && sign_alias.is_none() {
                        sign_alias = Some(dest);
                        p_aliases.retain(|other| other != &dest);
                        steps.push(position);
                        continue;
                    }
                    return None;
                }
                // Main-part shift: q = asr(p, k), k != 63.
                (
                    crate::ir::BinOp::Sar,
                    Expr::Reg { index, .. },
                    Expr::Const(k),
                ) => {
                                if *k != 63 && p_aliases.contains(index) && main_alias.is_none() {
                        main_alias = Some(dest);
                        extra_shift = Some(*k);
                        p_aliases.retain(|other| other != &dest);
                        steps.push(position);
                        continue;
                    }
                    return None;
                }
                // The sum: main-part + sign-flag in either operand order.
                (
                    crate::ir::BinOp::Add,
                    lhs,
                    rhs,
                ) => {
                    let lhs = strip_and_mask(lhs);
                    let rhs = strip_and_mask(rhs);
                    let lhs_main = sum_shape(lhs, &p_aliases, main_alias, extra_shift).is_some();
                    let rhs_main = sum_shape(rhs, &p_aliases, main_alias, extra_shift).is_some();
                    let lhs_sign = sign_shape(lhs, &p_aliases, sign_alias);
                    let rhs_sign = sign_shape(rhs, &p_aliases, sign_alias);
                    if !((lhs_main && rhs_sign) || (lhs_sign && rhs_main)) {
                        return None;
                    }
                    // A high-part product already carries the multiply's own
                    // 64-bit shift; a plain product's shift is the whole
                    // quotient shift.
                    let total = if high_part {
                        64 + extra_shift.unwrap_or(0)
                    } else {
                        extra_shift.unwrap_or(0)
                    };
                                    let divisor = magic_divisor_signed64(magic, total, domain_bits)?;
                                    return Some((position, steps, divisor));
                }
                _ => return None,
            },
            _ => return None,
        }
    }
    None
}

/// Sum operand classification. `Some(true)` = the main-part form (`p` or
/// `p asr k`), `Some(false)` = the sign-flag form, `None` = neither.
fn sign_shape(expr: &Expr, p_aliases: &[u16], sign_alias: Option<u16>) -> bool {
    match expr {
        Expr::Bin {
            op: crate::ir::BinOp::Shr | crate::ir::BinOp::Sar,
            lhs,
            rhs,
        } => {
            // The sign flag shifts by width-1: 63 for the plain width, 31
            // once the chain's arithmetic runs on the zero-extended narrow
            // value.
            if matches!(rhs.as_ref(), Expr::Const(63)) || matches!(rhs.as_ref(), Expr::Const(31)) {
                if let Some(index) = leaf_index(lhs) {
                    return p_aliases.contains(&index);
                }
            }
        }
        Expr::Reg { index, .. } => return sign_alias == Some(*index),
        _ => {}
    }
    false
}

fn leaf_index(expr: &Expr) -> Option<u16> {
    match expr {
        Expr::Reg { index, .. } => Some(*index),
        _ => None,
    }
}


/// Sum-side operand shape: a main-part register or shift, or a sign-flag
/// register or shift. Chains match only when one operand is each kind.
fn sum_shape(
    expr: &Expr,
    p_aliases: &[u16],
    sign_alias: Option<u16>,
    extra_shift: Option<u64>,
) -> Option<u64> {
    let reg_index = |expr: &Expr| -> Option<u16> {
        match expr {
            Expr::Reg { index, .. } => Some(*index),
            _ => None,
        }
    };
    // Sign-flag form: `p lsr 63` / `p asr 63`, or a register already holding it.
    match expr {
        Expr::Bin {
            op: crate::ir::BinOp::Shr | crate::ir::BinOp::Sar,
            lhs,
            rhs,
        } => {
            if matches!(rhs.as_ref(), Expr::Const(63)) {
                if let Some(index) = reg_index(lhs) {
                    if p_aliases.contains(&index) {
                        return Some(63);
                    }
                }
            }
        }
        Expr::Reg { index, .. } => {
            if sign_alias == Some(*index) {
                return Some(63);
            }
        }
        _ => {}
    }
    // Main-part form: p itself, or p asr k.
    match expr {
        Expr::Reg { index, .. } => {
            if p_aliases.contains(index) {
                return Some(extra_shift.unwrap_or(0));
            }
        }
        Expr::Bin {
            op: crate::ir::BinOp::Sar,
            lhs,
            rhs,
        } => {
            if let (Some(index), Expr::Const(k)) = (reg_index(lhs), rhs.as_ref()) {
                if p_aliases.contains(&index) && extra_shift == Some(*k) {
                    return Some(extra_shift.unwrap_or(0));
                }
            }
        }
        _ => {}
    }
    None
}

/// Recognizes the unsigned 64-bit high-part reciprocal chain supported by
/// x86-64's 1-operand `mul`: `p = hi128(a, M)`, an optional neutral low-half
/// write, register copies of the product, and a final `p >> s` shift. The
/// chain replaces only the final shift; the rest of the block is untouched.
fn unsigned64_chain(
    statements: &[Stmt],
    start: usize,
    dest_index: u16,
    magic: u64,
    domain_bits: u64,
) -> Option<(usize, Vec<usize>, u64)> {
    let mut p_aliases: Vec<u16> = vec![dest_index];
    let mut steps: Vec<usize> = Vec::new();
    let mut low_seen = false;

    for position in (start + 1)..(start + 8).min(statements.len()) {
        let Some((dest_ref, value)) = assign_of(&statements[position]) else {
            return None;
        };
        let dest = dest_ref.index;
        match value {
            // The 1-operand mul's low half is a neutral write of the same
            // product; skip at most one.
            Expr::Bin {
                op: crate::ir::BinOp::Mul,
                ..
            } => {
                if low_seen {
                    return None;
                }
                low_seen = true;
                steps.push(position);
                continue;
            }
            // A pure register copy of the product's value.
            Expr::Reg { index, .. } => {
                if p_aliases.contains(index) {
                    p_aliases.push(dest);
                    steps.push(position);
                    continue;
                }
                return None;
            }
            // The lifter's zero-extension temp re-binds the product value and
            // narrows the chain's arithmetic width.
            Expr::Bin {
                op: crate::ir::BinOp::And,
                lhs,
                ..
            } => {
                let base = match lhs.as_ref() {
                    Expr::Reg { index, .. } => Some(*index),
                    _ => None,
                };
                let binds_product = base.map_or(false, |index| p_aliases.contains(&index));
                if !binds_product {
                    return None;
                }
                p_aliases.push(dest);
                steps.push(position);
                continue;
            }
            Expr::Bin { op, lhs, rhs } => match (op, lhs.as_ref(), rhs.as_ref()) {
                // The final shift: the chain's output register writes it and
                // everything before is the widening product's plumbing.
                (crate::ir::BinOp::Shr, Expr::Reg { index, .. }, Expr::Const(shift)) => {
                    if *shift == 0 || *shift >= 64 || !p_aliases.contains(index) {
                        return None;
                    }
                    let total = 64 + shift;
                    let divisor = magic_divisor(magic, total, domain_bits)?;
                    return Some((position, steps, divisor));
                }
                (crate::ir::BinOp::Sar, _, _) | (crate::ir::BinOp::Add, _, _) => return None,
                _ => return None,
            },
            _ => return None,
        }
    }
    None
}

/// Beyond a copy-tolerant chain's opening, the widened multiply's operand
/// register may only be a local copy of the true dividend; walk upwards from
/// the multiply through pure register copies to the parameter that feeds it.
fn dividend_parameter(statements: &[Stmt], chain_start: usize, leaf: u16) -> u16 {
    let mut current = leaf;
    for position in (0..chain_start).rev() {
        let Some((dest, value)) = assign_of(&statements[position]) else {
            continue;
        };
        if dest.index != current {
            continue;
        }
        // Follow the widening or masking wrapper to the register it reads.
        let step = match value {
            Expr::Reg { index, .. } if *index != current => Some(*index),
            Expr::SignExtend { value, .. } => match value.as_ref() {
                Expr::Reg { index, .. } => Some(*index),
                _ => None,
            },
            Expr::Bin {
                op: crate::ir::BinOp::And,
                lhs,
                ..
            } => match lhs.as_ref() {
                Expr::Reg { index, .. } => Some(*index),
                _ => None,
            },
            _ => None,
        };
        match step {
            Some(next) if next != current => current = next,
            _ => break,
        }
    }
    current
}

/// The dividend may enter a 64-bit register through a sign or zero extension
/// of a 32-bit value; report the value's true domain for the exactness check.
fn chain_dividend_domain(statements: &[Stmt], chain_start: usize, leaf: &Expr) -> u64 {
    let domain = leaf_domain(leaf).unwrap_or(64);
    if domain == 32 {
        return 32;
    }
    let Expr::Reg { index, .. } = leaf else {
        return domain;
    };
    for position in (0..chain_start).rev() {
        let Some((dest, value)) = assign_of(&statements[position]) else {
            continue;
        };
        if dest.index != *index {
            continue;
        }
        return match value {
            Expr::SignExtend { width, .. } => u64::from(*width) * 8,
            Expr::Bin {
                op: crate::ir::BinOp::And,
                rhs,
                ..
            } if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) => 32,
            _ => domain,
        };
    }
    domain
}

/// Signed division by a power of two through the branchless sign select:
/// `r = (x >= 0 ? x : x + (2^k - 1)) >> k`, i.e. `x / 2^k`. The lift renders
/// the select and a preceding `lea`; both collapse into the shift's rewrite.
/// The csneg family's low-bit modulo. Compilers emit a truncating signed
/// `x % 2^k` as `neg t, x` / `and m, x, mask` / `and t, t, mask` /
/// `csneg r, m, t, mi`; the csneg lift renders a select whose condition is
/// the *negated* dividend's sign, so the positive branch is the masked
/// dividend and the negative one is the negated masked complement.
fn cs_neg_chain(statements: &[Stmt], select_index: usize) -> Option<(Vec<usize>, u64, u16, u8)> {
    // (consumed statements, divisor, dividend register, register width)
    let Some((_, sel_value)) = assign_of(&safe(statements, select_index)) else {
        return None;
    };
    let Expr::Select {
        cond,
        lhs: cmp_lhs,
        rhs: cmp_rhs,
        then,
        els,
    } = sel_value
    else {
        return None;
    };
    // The condition reads the dividend's negation (`subs xzr, x`).
    if !matches!(cond, crate::ir::Cond::Mi | crate::ir::Cond::Pl) {
        return None;
    }
    let Expr::Const(0) = cmp_lhs.as_ref() else {
        return None;
    };
    let Expr::Reg { index: dividend, width } = strip_and_mask(cmp_rhs) else {
        return None;
    };
    let (dividend, width) = (*dividend, *width);
    // The negation branch is `0 - reg`.
    let negated_leaf = |expr: &Expr| -> Option<u16> {
        match expr {
            Expr::Bin {
                op: crate::ir::BinOp::Sub,
                lhs,
                rhs,
            } if matches!(lhs.as_ref(), Expr::Const(0)) => unwrap_leaf(strip_and_mask(rhs)),
            _ => None,
        }
    };
    // Whichever branch is the plain value and which one is negated depends on
    // the condition's polarity.
    let (plain, negated) = match cond {
        crate::ir::Cond::Mi => (then, els),
        _ => (els, then),
    };
    let Some(plain_leaf) = unwrap_leaf(strip_and_mask(plain)) else {
        return None;
    };
    let Some(negated_leaf) = negated_leaf(negated) else {
        return None;
    };
    // The statement that defines a register right before the select.
    let defining = |index: u16| -> Option<usize> {
        for probe in (0..select_index).rev() {
            let Some((dest, _)) = assign_of(&safe(statements, probe)) else {
                continue;
            };
            if dest.index == index {
                return Some(probe);
            }
        }
        None
    };
    // Its value must be `source & mask`, returning the mask and the source.
    let masked = |index: u16| -> Option<(usize, u64, u16)> {
        let probe = defining(index)?;
        let value = strip_and_mask(assign_of(&safe(statements, probe))?.1);
        let Expr::Bin {
            op: crate::ir::BinOp::And,
            lhs,
            rhs,
        } = value
        else {
            return None;
        };
        let Expr::Const(mask) = rhs.as_ref() else {
            return None;
        };
        let Expr::Reg { index: source, .. } = strip_and_mask(lhs) else {
            return None;
        };
        Some((probe, *mask, *source))
    };
    let (plain_pos, plain_mask, plain_source) = masked(plain_leaf)?;
    let (negated_pos, negated_mask, negated_source) = masked(negated_leaf)?;
    if plain_mask != negated_mask {
        return None;
    }
    let divisor = plain_mask.wrapping_add(1);
    if divisor == 0 || !divisor.is_power_of_two() {
        return None;
    }
    // The plain mask reads the dividend itself; the other branch's source is
    // the register that holds its negation (that register may be re-masked
    // right before the select, so look for the negation itself).
    let (neg_pos, neg_source) = (0..negated_pos)
        .rev()
        .find_map(|probe| {
            let (dest, value) = assign_of(&safe(statements, probe))?;
            if dest.index != negated_source {
                return None;
            }
            match strip_and_mask(value) {
                Expr::Bin {
                    op: crate::ir::BinOp::Sub,
                    lhs,
                    rhs,
                } if matches!(lhs.as_ref(), Expr::Const(0)) => {
                    let source = unwrap_leaf(strip_and_mask(rhs))?;
                    Some((probe, source))
                }
                _ => None,
            }
        })?;
    // Both the plain mask and the negation must read the same dividend.
    let root_plain = dividend_parameter(statements, select_index, plain_source);
    let root_neg = dividend_parameter(statements, select_index, neg_source);
    if root_plain != dividend || root_neg != dividend {
        return None;
    }
    Some((vec![plain_pos, negated_pos, neg_pos], divisor, dividend, width))
}

fn signed_select_mod_chain(
    statements: &[Stmt],
) -> Option<(usize, usize, Option<usize>, u64, Expr, u64)> {
    // (sub position, select position, adjusted definition, divisor, leaf, domain)
    for sub_index in 0..statements.len() {
        let Some((_, sub_value)) = assign_of(&statements[sub_index]) else {
            continue;
        };
        let sub_value = strip_and_mask(sub_value);
        let Expr::Bin {
            op: crate::ir::BinOp::Sub,
            lhs,
            rhs,
        } = sub_value
        else {
            continue;
        };
        // The correction term is the sign-selected value floored by `~mask`.
        let Some(masked_reg) = unwrap_leaf(strip_and_mask(rhs)) else {
            continue;
        };
        let Some(and_index) = (0..sub_index).rev().take(4).find(|position| {
            assign_of(&statements[*position])
                .map(|(dest, _)| dest.index == masked_reg)
                .unwrap_or(false)
        }) else {
            continue;
        };
        let Some((_, and_value)) = assign_of(&statements[and_index]) else {
            continue;
        };
        let Expr::Bin {
            op: crate::ir::BinOp::And,
            lhs: masked,
            rhs: mask,
        } = strip_and_mask(and_value)
        else {
            continue;
        };
        let Expr::Const(mask) = mask.as_ref() else {
            continue;
        };
        // The floor mask is the negated power of two (`~15`, `~7`).
        let step = mask.wrapping_neg();
        if step == 0 || !step.is_power_of_two() {
            continue;
        }
        let Some(select_src) = unwrap_leaf(strip_and_mask(masked)) else {
            continue;
        };
        // The select that produces the corrected value sits just before.
        let Some(select_index) = (0..and_index).rev().take(4).find(|position| {
            assign_of(&statements[*position])
                .map(|(dest, _)| dest.index == select_src)
                .unwrap_or(false)
        }) else {
            continue;
        };
        let Some((_, select_value)) = assign_of(&statements[select_index]) else {
            continue;
        };
        let select_value = strip_and_mask(select_value);
        let Expr::Select {
            cond,
            rhs: zero,
            then,
            els,
            ..
        } = select_value
        else {
            continue;
        };
        // The predicate is the dividend's own sign test.
        if !matches!(cond, crate::ir::Cond::Ge | crate::ir::Cond::Lt)
            || !matches!(zero.as_ref(), Expr::Const(0))
        {
            continue;
        }
        let (plain, adjusted) = match cond {
            crate::ir::Cond::Ge => (then, els),
            _ => (els, then),
        };
        let leaf = strip_and_mask(plain).clone();
        let Expr::Reg { index: leaf_reg, .. } = leaf else {
            continue;
        };
        // The adjusted branch adds the mask itself; resolve its register.
        let mut adjusted_def = None;
        let adjusted = match strip_and_mask(adjusted) {
            Expr::Reg { index, .. } => {
                let resolved = (0..select_index).rev().take(4).find_map(|position| {
                    assign_of(&statements[position]).and_then(|(dest, value)| {
                        (dest.index == *index).then(|| {
                            adjusted_def = Some(position);
                            strip_and_mask(value)
                        })
                    })
                })?;
                resolved
            }
            adjusted => adjusted,
        };
        let Expr::Bin {
            op: crate::ir::BinOp::Add,
            lhs: arm,
            rhs: delta,
        } = adjusted
        else {
            continue;
        };
        let Expr::Reg { index: arm_reg, .. } = strip_and_mask(arm) else {
            continue;
        };
        let Expr::Const(delta) = delta.as_ref() else {
            continue;
        };
        if delta.wrapping_add(1) != step {
            continue;
        }
        // Both the plain branch and the correction must read the dividend.
        let root_plain = dividend_parameter(statements, select_index, leaf_reg);
        let root_arm = dividend_parameter(statements, select_index, *arm_reg);
        let Some(sub_leaf) = unwrap_leaf(strip_and_mask(lhs)) else {
            continue;
        };
        let root_sub = dividend_parameter(statements, sub_index, sub_leaf);
        if root_plain != root_arm || root_plain != root_sub {
            continue;
        }
        let domain = if matches!(leaf, Expr::Bin { op: crate::ir::BinOp::And, .. }) {
            32
        } else {
            chain_dividend_domain(statements, select_index, &leaf)
        };
        return Some((sub_index, select_index, adjusted_def, step, leaf, domain));
    }
    None
}

fn signed_select_chain(statements: &[Stmt]) -> Option<(usize, usize, Option<usize>, u64, Expr, u64)> {
    for sar_index in 0..statements.len() {
        let Some((sar_dest, value)) = assign_of(&statements[sar_index]) else {
            continue;
        };
        let sar_width = sar_dest.width;
        let value = strip_and_mask(value);
        let Expr::Bin {
            op: crate::ir::BinOp::Sar,
            lhs,
            rhs,
        } = value
        else {
            continue;
        };

        let (src, src_width, shift) = match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Reg { index, width }, Expr::Const(k)) => (index, *width, k),
            _ => continue,
        };
        if *shift == 0 || *shift >= 64 {
            continue;
        }
        // The shifted value must be the select, emitted just before.
        let select_index = (0..sar_index)
            .rev()
            .take(4)
            .find(|position| {
                assign_of(&statements[*position])
                    .map_or(false, |(dest, _)| dest.index == *src)
            })?;
        let Some((_, select_value)) = assign_of(&statements[select_index]) else {
            continue;
        };
        let select_value = strip_and_mask(select_value);
        let Expr::Select {
            cond,
            lhs: _,
            rhs,
            then,
            els,
        } = select_value
        else {
            continue;
        };
        // The predicate selects on the leaf's sign; accept either polarity.
        if !matches!(cond, crate::ir::Cond::Ge | crate::ir::Cond::Lt)
            || !matches!(rhs.as_ref(), Expr::Const(0))
        {
            continue;
        }
        let (plain, adjusted) = match cond {
            crate::ir::Cond::Ge => (then, els),
            _ => (els, then),
        };
        let leaf = strip_and_mask(plain);
        // The adjustment may be a register whose value the preceding `lea`
        // statement carries; resolve that register's latest definition.
        let mut adjusted_def = None;
        let adjusted = match strip_and_mask(adjusted) {
            Expr::Reg { index, .. } => {
                let resolved = (0..select_index).rev().take(4).find_map(|position| {
                    assign_of(&statements[position]).and_then(|(dest, value)| {
                        (dest.index == *index).then(|| {
                            adjusted_def = Some(position);
                            strip_and_mask(value)
                        })
                    })
                });
                match resolved {
                    Some(value) => value,
                    None => continue,
                }
            }
            adjusted => adjusted,
        };
        // The adjusted branch adds the divisor's own `(2^k - 1)` correction.
        let (add_index, delta) = match adjusted {
            Expr::Bin {
                op: crate::ir::BinOp::Add,
                lhs: arm,
                rhs,
            } => {
                let arm = strip_and_mask(arm);
                match (arm, rhs.as_ref()) {
                    (Expr::Reg { index, .. }, Expr::Const(delta)) => (index, delta),
                    _ => continue,
                }
            }
            _ => continue,
        };
        // Both branches must reach the same dividend: the plain branch and
        // the adjustment's base resolve to the same root register. A temp
        // leaf (a zero-extended widen) resolves through its def, so the
        // plain branch keeps its faithful expression.
        let Expr::Reg { index: leaf_reg, .. } = leaf else {
            continue;
        };
        let root_plain = dividend_parameter(statements, select_index, *leaf_reg);
        let root_adjusted = dividend_parameter(statements, select_index, *add_index);
        if root_plain != root_adjusted {
            continue;
        }
        let shift_delta = delta.wrapping_add(1);
        if shift_delta == 0 || !shift_delta.is_power_of_two() {
            continue;
        }
        // The shift that produces the quotient runs at the dividend's own
        // width, so a 32-bit shifted register (or a 32-bit result register)
        // proves a 32-bit dividend even when the value lives in a 64-bit
        // register behind a zero-extension mask.
        let domain = if src_width == 32 || sar_width == 32 {
            32
        } else {
            match leaf {
                Expr::Bin {
                    op: crate::ir::BinOp::And,
                    ..
                } => 32,
                _ => chain_dividend_domain(statements, select_index, leaf),
            }
        };
        return Some((
            sar_index,
            select_index,
            adjusted_def,
            1u64 << shift,
            leaf.clone(),
            domain,
        ));
    }
    None
}

/// Recognizes the remainder chain (`x - (x / d) * d` built from a widening
/// product, its quotient shifts, shifted-copy multipliers of the quotient and
/// the subtract): rewrites the subtract into `% x`. Consumes everything else.
fn remainder_scan(
    statements: &[Stmt],
    start: usize,
    dest_index: u16,
) -> Option<(usize, Vec<usize>, u64, bool, u64)> {
    // (sub position, consumed indices, divisor, signedness, param domain)
    // The dividend's own register (the chain's input leaf) reads before the
    // product and after it (the flag shift and the back-subtract); accept
    // its reads without claiming it into the alias set.
    let dividend_reg = unwrap_leaf(statements.get(start).and_then(assign_of).map_or(&Expr::Const(0), |(_, value)| value));
    let mut aliases: Vec<u16> = vec![dest_index];
    let mut signed = false;
    let mut factor: u64 = 1;
    let mut consumed: Vec<usize> = Vec::new();
    let mut position = start;
    let mut half_seen = false;

    for _ in 0..12 {
        position += 1;
        let Some((dest_ref, value)) = assign_of(&safe(statements, position)) else {
            return None;
        };

        let dest = dest_ref.index;
        let width = dest_ref.width;
        let value = strip_and_mask(value);
        match value {
            // The lifter's zero-extension temp re-binds the chain value.
            Expr::Bin {
                op: crate::ir::BinOp::And,
                lhs,
                rhs,
            } => {
                let Expr::Const(0xffff_ffff) = rhs.as_ref() else {
                    // A floor mask like `q & ~1` rebinds the quotient's low
                    // bit, so the following multiply is not exact; the
                    // chain's own division rewrite still fires.
                    return None;
                };
                let Expr::Reg { index, .. } = lhs.as_ref() else {
                    return None;
                };
                if !aliases.contains(index) && !is_shift_of(index, &aliases, statements) {
                    return None;
                }
                aliases.push(dest);
                consumed.push(position);
            }
            // A pure copy of a chain value.
            Expr::Reg { index, .. } => {
                if aliases.contains(index) {
                    aliases.push(dest);
                    consumed.push(position);
                    continue;
                }
                return None;
            }
            // The divisor's own register assignment: `d` itself; the msub
            // unwind's factor resolves through this register.
            // The divisor's own register assignment is part of the chain
            // (the `mov w9, #0xa` before an msub).
            Expr::Const(_) => {
                consumed.push(position);
                continue;
            }
            Expr::Bin { op, lhs, rhs } => match (op, lhs.as_ref(), rhs.as_ref()) {
                // The x86 1-op mul lift writes the low half right after
                // the high part; it carries nothing for the chain.
                (
                    crate::ir::BinOp::Mul,
                    Expr::Reg { .. },
                    Expr::Const(_),
                ) if !half_seen => {
                    half_seen = true;
                    consumed.push(position);
                    continue;
                }
                // The sign flag: q lsr width-1, either inline or its own
                // statement; the chain becomes signed.
                (
                    crate::ir::BinOp::Shr | crate::ir::BinOp::Sar,
                    Expr::Reg { index, .. },
                    Expr::Const(k),
                ) if aliases.contains(index)
                    || dividend_reg == Some(*index)
                    || !half_seen =>
                {
                    if *k + 1 == u64::from(width) {
                        signed = true;
                        if dest != *index {
                            aliases.push(dest);
                        }
                        consumed.push(position);
                        continue;
                    }
                    // The quotient's high-part shift; it writes its own
                    // register so the multiplier reads the result.
                    aliases.retain(|other| other != &dest);
                    aliases.push(dest);
                    consumed.push(position);
                    continue;
                }
                // The sum of the sign flag and the high part (or the two
                // register copies the lifter renders).
                (
                    crate::ir::BinOp::Add,
                    lhs,
                    rhs,
                ) => {
                    let lhs = strip_and_mask(lhs);
                    let rhs = strip_and_mask(rhs);
                    // Either operand may be the register or a shifted copy
                    // built over it; both must stay inside the alias set.
                    let mut alias_ok = |expr: &Expr| -> bool {
                        if let Some(index) = unwrap_leaf(expr) {
                            return aliases.contains(&index);
                        }
                        match shift_leaf(expr) {
                            Some((index, bits)) => {
                                if bits + 1 == u64::from(width) {
                                    signed = true;
                                }
                                return aliases.contains(&index);
                            }
                            None => {}
                        }
                        // The x86 lea-multiplier reads `q * constant`.
                        if let Some(index) = self_mul_leaf(expr) {
                            return aliases.contains(&index);
                        }
                        false
                    };
                    if !alias_ok(lhs) || !alias_ok(rhs) {
                        return None;
                    }
                    // A self-multiplier may settle first: the shifted or
                    // multiplied copy of the quotient times the identity
                    // read gives the divisor's factor.
                    if let Some((identity, factor_term)) = multiplier_step(&lhs, &rhs, &aliases)
                    {
                                        // The identity operand's presence decides the sum.
                        let factor_step = if identity {
                            1 + factor_term
                        } else {
                            factor_term
                        };
                        factor = factor.checked_mul(factor_step)?;
                        aliases.retain(|other| other != &dest);
                        aliases.push(dest);
                        consumed.push(position);
                        continue;
                    }
                    // A double self-multiply (`q + q`) is itself a factor 2.
                    let both_plain = unwrap_leaf(lhs).zip(unwrap_leaf(rhs));
                    if let Some((a, b)) = both_plain {
                        if a == b && aliases.contains(&a) {
                            factor = factor.checked_mul(2)?;
                            aliases.retain(|other| other != &dest);
                            aliases.push(dest);
                            consumed.push(position);
                            continue;
                        }
                    }
                    // Otherwise the sign flag and high part merge here.
                    if dest != aliases.last().copied().unwrap_or(dest) {
                        aliases.push(dest);
                    }
                    consumed.push(position);
                    continue;
                }
                (
                    crate::ir::BinOp::Mul,
                    Expr::Reg { index, .. },
                    Expr::Const(_),
                ) => {
                    // The msub unwind's own multiply: `q * d` names the
                    // divisor as a standalone statement.
                    if !aliases.contains(index) {
                        return None;
                    }
                    if let Expr::Const(value) = rhs.as_ref() {
                        let _ = value;
                    }
                    aliases.retain(|other| other != &dest);
                    aliases.push(dest);
                    consumed.push(position);
                    continue;
                }
                // The divisor back-subtract closes the chain: either a
                // plain chain register (the shifted-copy unwind) or the
                // `msub` form's `Mul(q, d)`.
                (
                    crate::ir::BinOp::Sub,
                    _lhs,
                    rhs,
                ) => {
                    let rhs = strip_and_mask(rhs);
                    let accu = match rhs {
                        // The unwind's identity register.
                        Expr::Reg { .. } => unwrap_leaf(rhs),
                        // The `msub` lift's multiply-over-use form.
                        Expr::Bin {
                            op: crate::ir::BinOp::Mul,
                            lhs,
                            ..
                        } => unwrap_leaf(strip_and_mask(lhs)),
                        _ => None,
                    };
                    let Some(accu) = accu else {
                        return None;
                    };
                    if factor < 2 || !aliases.contains(&accu) {
                        return None;
                    }
                    return Some((position, consumed, factor, signed, width as u64));
                }
                _ => return None,
            },
            _ => return None,
        }
    }
    None
}

/// Reads one statement's shift over an alias' register, if any.
fn is_shift_of(index: &u16, aliases: &[u16], statements: &[Stmt]) -> bool {
    aliases.contains(index)
        || statements.iter().any(|stmt| match assign_of(stmt) {
            Some((dest, Expr::Bin { op: crate::ir::BinOp::Shl, .. })) => dest.index == *index,
            _ => false,
        })
}

/// Reads `q * constant`'s base register, if that's all it is.
fn self_mul_leaf(expr: &Expr) -> Option<u16> {
    let Expr::Bin {
        op: crate::ir::BinOp::Mul,
        lhs,
        rhs,
    } = expr
    else {
        return None;
    };
    let Expr::Const(_) = rhs.as_ref() else {
        return None;
    };
    unwrap_leaf(strip_and_mask(lhs))
}

/// A shift over an alias whose register also lives in the chain set, with
/// its shift amount so inline sign flags can be detected.
fn shift_leaf(expr: &Expr) -> Option<(u16, u64)> {
    let Expr::Bin {
        op: crate::ir::BinOp::Shl | crate::ir::BinOp::Shr | crate::ir::BinOp::Sar,
        lhs,
        rhs,
    } = expr
    else {
        return None;
    };
    let Expr::Const(bits) = rhs.as_ref() else {
        return None;
    };
    unwrap_leaf(strip_and_mask(lhs)).map(|index| (index, *bits))
}

/// The shifted-copy multiplier's factor for this sum: `q + q << k` reads Qi.
/// One factor of the quotient multiplier: a shifted copy (`q + q << k`) or
/// the plain multiply the lea form sometimes renders (`q + q * 2`). Both
/// operands must read the same chain register.
fn multiplier_step(lhs: &Expr, rhs: &Expr, aliases: &[u16]) -> Option<(bool, u64)> {
    let operand_factor = |expr: &Expr| -> Option<(u16, u64)> {
        match &*strip_and_mask(expr) {
            // `q << k` contributes `2^k`.
            Expr::Bin {
                op: crate::ir::BinOp::Shl,
                lhs: base,
                rhs,
            } => {
                let Expr::Const(bits) = rhs.as_ref() else {
                    return None;
                };
                let leaf = unwrap_leaf(strip_and_mask(base))?;
                Some((leaf, 1u64 << bits))
            }
            // `q * value` contributes `value`.
            Expr::Bin {
                op: crate::ir::BinOp::Mul,
                lhs: base,
                rhs,
            } => {
                let Expr::Const(value) = rhs.as_ref() else {
                    return None;
                };
                let leaf = unwrap_leaf(strip_and_mask(base))?;
                Some((leaf, *value))
            }
            _ => None,
        }
    };
    // The identity flag reports the ledger register as a plain term.
    let copy = match operand_factor(rhs) {
        Some((leaf, value)) if unwrap_leaf(strip_and_mask(lhs)) == Some(leaf) => {
            Some((leaf, value, true))
        }
        _ => operand_factor(lhs)
            .filter(|(leaf, _)| unwrap_leaf(strip_and_mask(rhs)) == Some(*leaf))
            .map(|(leaf, value)| (leaf, value, true)),
    };
    let copy = copy?;
    let (leaf, value, _) = copy;
    if !aliases.contains(&leaf) {
        return None;
    }
    Some((true, value))
}

fn division(dividend: Expr, divisor: u64) -> Expr {
    Expr::Bin {
        op: crate::ir::BinOp::DivS,
        lhs: Box::new(dividend),
        rhs: Box::new(Expr::Const(divisor)),
    }
}

fn division_unsigned(dividend: Expr, divisor: u64) -> Expr {
    Expr::Bin {
        op: crate::ir::BinOp::DivU,
        lhs: Box::new(dividend),
        rhs: Box::new(Expr::Const(divisor)),
    }
}

fn remainder(dividend: Expr, divisor: u64, unsigned: bool) -> Expr {
    Expr::Bin {
        op: if unsigned { crate::ir::BinOp::ModU } else { crate::ir::BinOp::ModS },
        lhs: Box::new(dividend),
        rhs: Box::new(Expr::Const(divisor)),
    }
}

/// A remainder chain reassembles the quotient's own multiplier out of shifted
/// copies (`q += q << k` steps) and subtracts it back, so the whole sequence
/// reads `x - (x / d) * d`. Rewrites the subtract to a `% x` and consumes the
/// reassembly statements.
fn apply_remainder_follows(
    statements: &[Stmt],
    consumed: &mut std::collections::HashSet<usize>,
    replacements: &mut Vec<(usize, Expr)>,
    domains: &mut std::collections::HashSet<(u16, bool)>,
    narrowed: &mut Vec<(u16, bool)>,
    _wide_signed: &mut std::collections::HashSet<u16>,
    wide_signed_ret: &mut Vec<u16>,
) {
    // Each rewrite the chain scans emit is a division; find the one whose
    // dest feeds a multiplier unwind and a subtract.
    let divisions: Vec<(usize, u64, bool)> = replacements
        .iter()
        .filter_map(|(position, expr)| match expr {
            Expr::Bin {
                op: crate::ir::BinOp::DivU,
                rhs,
                ..
            }
            | Expr::Bin {
                op: crate::ir::BinOp::DivS,
                rhs,
                ..
            } => {
                let unsigned = matches!(
                    expr,
                    Expr::Bin {
                        op: crate::ir::BinOp::DivU,
                        ..
                    }
                );
                let Expr::Const(divisor) = rhs.as_ref() else {
                    return None;
                };
                Some((*position, *divisor, unsigned))
            }
            _ => None,
        })
        .collect();
    for (div_position, divisor, unsigned) in divisions {
        // The chain rewrites reading d's quotient may run one multiplier
        // step before the subtract; the whole remainder scan covers the
        // multi-step unwinds already.
        // The chain rewrites reading d's quotient may run one multiplier
        // step before the subtract; the statement scan covers the
        // multi-step unwinds already.
        let unwind: Option<(usize, usize)> =
            single_mult_follow(statements, div_position, divisor)
                .or_else(|| direct_msub_follow(statements, div_position, divisor));
        let Some((mult_position, sub_position)) = unwind else {
            continue;
        };
        consumed.insert(mult_position);
        let leaf = remainder_leaf(&statements[sub_position]);
        // The remainder's register speaks the chain's own domain, so the
        // signature narrows exactly like the statement scanner's.
        if let (Expr::Reg { width, .. }, Some((sub_dest, _))) = (
            &leaf,
            assign_of(&safe(statements, sub_position)),
        ) {
            if *width == 32 {
                let root = dividend_parameter(statements, div_position, 0);
                domains.insert((root, !unsigned));
                narrowed.push((sub_dest.index, !unsigned));
            } else if !unsigned {
                wide_signed_ret.push(sub_dest.index);
            }
        }
        replacements.push((sub_position, remainder(leaf, divisor, unsigned)));
    }
}

/// The `msub`-lifted form: `x - (q * d)` in a single statement where `q`
/// reads the chain's own quotient register. `d` may be a literal or the
/// register assignment that carries it between the rewrite and the subtract.
fn direct_msub_follow(
    statements: &[Stmt],
    div_position: usize,
    divisor: u64,
) -> Option<(usize, usize)> {
    let Some(div_dest) = assign_of(&safe(statements, div_position)).map(|(dest, _)| dest.index)
    else {
        return None;
    };
    // The tail between the recovered quotient and the unwind may carry the
    // divisor's own register assignment and the chain's re-masking / sign
    // correction; the first statement that is neither is the unwind.
    let mut sub_position = None;
    for probe in 1..8 {
        let Some(stmt) = statements.get(div_position + probe) else {
            break;
        };
        let Some((_, value)) = assign_of(stmt) else {
            break;
        };
        if matches!(value, Expr::Const(_)) {
            continue;
        }
        if matches!(tail_shape(stmt), Some(false)) {
            continue;
        }
        sub_position = Some(div_position + probe);
        break;
    }
    let Some(sub_position) = sub_position else {
        return None;
    };
    let Some((_, sub_value)) = assign_of(&safe(statements, sub_position)) else {
        return None;
    };
    let sub_value = strip_and_mask(sub_value);
    let Expr::Bin {
        op: crate::ir::BinOp::Sub,
        rhs,
        ..
    } = sub_value
    else {
        return None;
    };
    let rhs = strip_and_mask(rhs);
    let Expr::Bin {
        op: crate::ir::BinOp::Mul,
        lhs,
        rhs: rhs2,
    } = rhs
    else {
        return None;
    };
    // The factor sits as a literal or in the divisor's own register.
    let factor = match &*strip_and_mask(rhs2) {
        Expr::Const(value) => *value,
        Expr::Reg { index, .. } => {
            let mut resolved = None;
            for probe in (div_position.saturating_sub(2)..sub_position).rev() {
                if let Some((dest, Expr::Const(value))) = assign_of(&safe(statements, probe)) {
                    if dest.index == *index {
                        resolved = Some(*value);
                        break;
                    }
                }
            }
            let Some(value) = resolved else {
                return None;
            };
            value
        }
        _ => return None,
    };
    if factor != divisor {
        return None;
    }
    let Some(accu) = unwrap_leaf(strip_and_mask(lhs)) else {
        return None;
    };
    if accu != div_dest {
        return None;
    }
    Some((div_position, sub_position))
}

/// Finds the quotient multiplier's shifted-copy step and the subtract that
/// unwinds it, starting right after the chain's division rewrite.
fn single_mult_follow(
    statements: &[Stmt],
    div_position: usize,
    divisor: u64,
) -> Option<(usize, usize)> {
    // The step's own mask-stripped value must read exactly one shifted copy
    // of itself; the subtract then reads the step's dest.
    let Some(div_dest) = assign_of(&safe(statements, div_position)).map(|(dest, _)| dest.index)
    else {
        return None;
    };
    let mult_position = div_position + 1;
    let Some((step_dest_ref, step_value)) = assign_of(&safe(statements, mult_position)) else {
        return None;
    };
    let step_value = strip_and_mask(step_value);
    let (lhs, rhs) = match step_value {
        Expr::Bin {
            op: crate::ir::BinOp::Add,
            lhs,
            rhs,
        } => (lhs.as_ref(), rhs.as_ref()),
        _ => return None,
    };
    let (plain, shifted) = if matches!(rhs, Expr::Bin { op: crate::ir::BinOp::Shl, .. }) {
        (lhs, rhs)
    } else if matches!(lhs, Expr::Bin { op: crate::ir::BinOp::Shl, .. }) {
        (rhs, lhs)
    } else {
        return None;
    };
    let Expr::Bin {
        op: crate::ir::BinOp::Shl,
        lhs: shift_base,
        rhs: shift_amount,
    } = shifted
    else {
        return None;
    };
    let Expr::Const(bits) = shift_amount.as_ref() else {
        return None;
    };
    let plain_leaf = unwrap_leaf(strip_and_mask(plain));
    let shift_leaf = unwrap_leaf(strip_and_mask(shift_base));
    let Some(plain_leaf) = plain_leaf else {
        return None;
    };
    let Some(shift_leaf) = shift_leaf else {
        return None;
    };
    if plain_leaf != div_dest || shift_leaf != div_dest {
        return None;
    }
    if 1 + (1u64 << bits) != divisor {
        return None;
    }
    // The subtract closes the chain via the step's own register.
    let sub_position = mult_position + 1;
    let Some((_, sub_value)) = assign_of(&safe(statements, sub_position)) else {
        return None;
    };
    let sub_value = strip_and_mask(sub_value);
    let Expr::Bin {
        op: crate::ir::BinOp::Sub,
        rhs: sub_rhs,
        ..
    } = sub_value
    else {
        return None;
    };
    let Some(accu) = unwrap_leaf(strip_and_mask(sub_rhs)) else {
        return None;
    };
    if accu != step_dest_ref.index && accu != div_dest {
        return None;
    }
    Some((mult_position, sub_position))
}

fn safe<'a>(statements: &'a [Stmt], position: usize) -> &'a Stmt {
    statements.get(position).unwrap_or(&Stmt::Ret { value: Expr::Const(0) })
}

/// The subtract's dividend is the chain's own input value.
fn remainder_leaf(stmt: &Stmt) -> Expr {
    match assign_of(stmt) {
        Some((
            _,
            value,
        )) => {
            let value = strip_and_mask(value);
            if let Expr::Bin {
                op: crate::ir::BinOp::Sub,
                lhs,
                ..
            } = value
            {
                strip_and_mask(lhs).clone()
            } else {
                Expr::Const(0)
            }
        }
        None => Expr::Const(0),
    }
}

fn assign_of(stmt: &Stmt) -> Option<(crate::ir::RegRef, &Expr)> {
    match stmt {
        Stmt::Assign { dest, value } => Some((*dest, value)),
        _ => None,
    }
}

/// Divisor recovery for the unsigned widening multiply `((x * M) >> S)`, exact
/// over all `x` in `[0, 2^domain_bits)` by the boundary conditions.
fn magic_divisor(magic: u64, total_shift: u64, domain_bits: u64) -> Option<u64> {
    if magic == 0 || total_shift < domain_bits + 1 || total_shift > 127 || domain_bits > 64 {
        return None;
    }
    let modulus: u128 = 1u128 << total_shift;
    let magic_ = u128::from(magic);
    let domain: u128 = 1u128 << domain_bits;
    let base = modulus / magic_;
    for offset in 0..=2u128 {
        let divisor = base + offset;
        if divisor == 0 || divisor >= domain {
            continue;
        }
        let product = divisor * magic_;
        if product < modulus {
            continue;
        }
        let slip = product - modulus;
        let inputs = (domain - 1) / divisor;
        if inputs * slip < magic_ {
            return u64::try_from(divisor).ok();
        }
    }
    None
}

/// Divisor recovery for the signed `(hi + sign)` correction chain; the actual
/// shift is the 32-bit high half of the widening product.
fn magic_divisor_signed(magic: u64, domain_bits: u64) -> Option<u64> {
    const TOTAL_SHIFT: u64 = 32;
    if magic == 0 || magic > 0xffff_ffff || domain_bits != 32 {
        return None;
    }
    let modulus: u128 = 1u128 << TOTAL_SHIFT;
    let magic_ = u128::from(magic);
    let domain: u128 = 1u128 << domain_bits;
    let base = modulus / magic_;
    for offset in 0..=2u128 {
        let divisor = base + offset;
        if divisor == 0 || divisor >= domain {
            continue;
        }
        let product = divisor * magic_;
        if product < modulus {
            continue;
        }
        let slip = product - modulus;
        let inputs = (domain / 2 - 1) / divisor;
        if inputs * slip <= modulus && inputs * slip < magic_ {
            return u64::try_from(divisor).ok();
        }
    }
    None
}

/// Resolves the signed high-part chain: drops the widening multiply, any pure
/// register copies, the sign flag and the high half, then rewrites the sum.
fn signed_chain(
    statements: &[Stmt],
    start: usize,
    dest_index: u16,
    magic: u64,
    domain_bits: u64,
) -> Option<(usize, Vec<usize>, u64)> {
    let mut aliases: std::collections::HashSet<u16> = {
        let mut set = std::collections::HashSet::new();
        set.insert(dest_index);
        set
    };
    let mut hi: Option<u16> = None;
    let mut steps: Vec<usize> = vec![start];

    for position in start + 1..start + 7 {
        let Some(next) = statements.get(position) else {
            return None;
        };
        let Some((dst_ref, value)) = assign_of(next) else {
            return None;
        };
        let dst_index = dst_ref.index;
        if let Some((source, shift)) = shift_of(value) {
            if aliases.contains(&source) && shift == 63 && hi.is_none() {
                if dst_index == source {
                    aliases.remove(&source);
                }
                hi = Some(dst_index);
                steps.push(position);
                continue;
            }
            if aliases.contains(&source) && shift == 32 && hi.is_some() {
                if dst_index == source {
                    aliases.remove(&source);
                }
                steps.push(position);
                let divisor = magic_divisor_signed(magic, domain_bits)
                    .or_else(|| magic_divisor_signed(magic, 32))?;
                // The sum of both halves closes the chain.
                let mut probe = statements.iter().skip(position + 1).enumerate();
                if let Some((_, next)) = probe.next() {
                    if let Some((_, sum_value)) = assign_of(next) {
                        let sum_value = strip_and_mask(sum_value);
                        let sum_pairs = |value: &Expr| {
                            let Expr::Bin {
                                op: crate::ir::BinOp::Add,
                                lhs,
                                rhs,
                            } = value
                            else {
                                return None;
                            };
                            let left = unwrap_leaf(lhs.as_ref());
                            let right = unwrap_leaf(rhs.as_ref());
                            let pair = matches!((left, right), (Some(a), Some(b))
                                if (Some(a) == hi || Some(b) == hi));
                            pair.then_some(divisor)
                        };
                        if let Some(divisor) = sum_pairs(sum_value) {
                            return Some((position + 1, steps, divisor));
                        }
                    }
                }
                return None;
            }
            return None;
        }
        if let Expr::Reg { index: copied, .. } = value {
            if aliases.contains(copied) && dst_index != *copied {
                aliases.insert(dst_index);
                steps.push(position);
                continue;
            }
            return None;
        }
        return None;
    }
    None
}

/// Confirms the dropped statement's destination is not read outside the chain
/// window; the sum rewrite must own every remaining use.
fn dropped_dest_safe(statements: &[Stmt], start: usize, end: usize, position: usize) -> bool {
    let Some(stmt) = statements.get(position) else {
        return false;
    };
    let Some((dest, _)) = assign_of(stmt) else {
        return false;
    };
    let reg = dest.index;
    for (offset, other) in statements.iter().enumerate() {
        if (offset >= start && offset <= end) || offset == position {
            continue;
        }
        // A return consuming the rewritten chain's output is safe.
        if matches!(other, Stmt::Ret { .. }) {
            continue;
        }
        let (_, reads) = statement_registers(other);
        // The remainder tail that the same rewrite collapses may read the
        // dropped register; nothing else may.
        if reads.contains(&reg) && !remainder_tail(statements, offset, reg) {
            return false;
        }
    }
    true
}


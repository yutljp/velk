use rustc_hash::FxHashSet;

use crate::ir::{BinOp, Expr, Stmt};

/// The ordered terms of a sum, splitting subtraction only of constants.
pub(crate) fn sum_terms<'e>(expr: &'e Expr, negative: bool, out: &mut Vec<(&'e Expr, bool)>) {
    match expr {
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => {
            sum_terms(lhs, negative, out);
            sum_terms(rhs, negative, out);
        }
        Expr::Bin {
            op: BinOp::Sub,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(_)) => {
            sum_terms(lhs, negative, out);
            sum_terms(rhs, !negative, out);
        }
        other => out.push((other, negative)),
    }
}

pub(crate) fn children(expr: &Expr) -> Vec<&Expr> {
    match expr {
        Expr::Bin { lhs, rhs, .. } => vec![lhs.as_ref(), rhs.as_ref()],
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => vec![lhs.as_ref(), rhs.as_ref(), then.as_ref(), els.as_ref()],
        Expr::Load { addr, .. } => vec![addr.as_ref()],
        Expr::SignExtend { value, .. } => vec![value.as_ref()],
        Expr::Apply { args, .. } => args.iter().collect(),
        _ => Vec::new(),
    }
}

/// Counts occurrences of a register in an expression, including repeated reads.
pub(crate) fn count_register(expr: &Expr, register: u16) -> usize {
    match expr {
        Expr::Reg { index, .. } => usize::from(*index == register),
        _ => children(expr)
            .into_iter()
            .map(|child| count_register(child, register))
            .sum(),
    }
}

/// Renames register indices without changing read widths or simplifying expressions.
pub(crate) fn rename_registers(expr: &mut Expr, renamed: &std::collections::HashMap<u16, u16>) {
    if let Expr::Reg { index, .. } = expr
        && let Some(joined) = renamed.get(index)
    {
        *index = *joined;
    }
    for child in crate::ir::visit::children_mut(expr) {
        rename_registers(child, renamed);
    }
}

pub(crate) fn children_mut(expr: &mut Expr) -> Vec<&mut Expr> {
    match expr {
        Expr::Bin { lhs, rhs, .. } => vec![lhs.as_mut(), rhs.as_mut()],
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => vec![lhs.as_mut(), rhs.as_mut(), then.as_mut(), els.as_mut()],
        Expr::Load { addr, .. } => vec![addr.as_mut()],
        Expr::SignExtend { value, .. } => vec![value.as_mut()],
        Expr::Apply { args, .. } => args.iter_mut().collect(),
        _ => Vec::new(),
    }
}

/// The width an expression computes at. `None` for a constant, a sign
/// extension or mixed operand widths.
pub(crate) fn expr_width(expr: &Expr) -> Option<u8> {
    match expr {
        Expr::Reg { width, .. } => Some(*width),
        Expr::Const(_) => None,
        Expr::SignExtend { .. } => None,
        Expr::Load { width, .. } => Some(width.saturating_mul(8)),
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
        Expr::Apply { .. } => Some(crate::ir::semantics::width(expr) as u8),
    }
}

pub fn collect_reads<S: std::hash::BuildHasher>(
    expr: &Expr,
    out: &mut std::collections::HashSet<u16, S>,
) {
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
            lhs,
            rhs,
            then,
            els,
            ..
        } => {
            collect_reads(lhs, out);
            collect_reads(rhs, out);
            collect_reads(then, out);
            collect_reads(els, out);
        }
        Expr::Apply { args, .. } => {
            for arg in args {
                collect_reads(arg, out);
            }
        }
    }
}

/// Substitutes register reads with values, for folding a loop header into
/// the condition that consumes it.
/// Replaces the reads of each register in a statement with its value.
pub(crate) fn replace_reads(stmt: &mut Stmt, values: &[(u16, Expr)]) {
    let replace = |expr: &mut Expr| *expr = substitute_values(expr.clone(), values);
    match stmt {
        Stmt::Machine { inputs, .. } => {
            for input in inputs {
                replace(input);
            }
        }
        Stmt::Assign { value, .. } | Stmt::Ret { value } => replace(value),
        Stmt::Store { addr, value, .. } => {
            replace(addr);
            replace(value);
        }
        Stmt::Brif { lhs, rhs, .. } => {
            replace(lhs);
            replace(rhs);
        }
        Stmt::BrIndirect { target } => replace(target),
        Stmt::Switch { index, .. } => replace(index),
        Stmt::Call { through, args, .. } => {
            if let Some(through) = through {
                replace(through);
            }
            for arg in args.iter_mut().flatten() {
                replace(arg);
            }
        }
        _ => {}
    }
}

#[must_use]
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
        Expr::Load {
            addr,
            width,
            signed,
        } => Expr::Load {
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
        Expr::Apply { op, args } => Expr::Apply {
            op,
            args: args
                .into_iter()
                .map(|arg| substitute_values(arg, values))
                .collect(),
        },
    }
}

#[must_use]
pub fn statement_reads(stmt: &Stmt) -> FxHashSet<u16> {
    statement_registers(stmt).1
}

pub fn statement_destinations_mut(stmt: &mut Stmt) -> Vec<&mut super::RegRef> {
    match stmt {
        Stmt::Machine { outputs, .. } => outputs.iter_mut().collect(),
        Stmt::Assign { dest, .. } => vec![dest],
        Stmt::Call { outputs, .. } => outputs.iter_mut().map(|output| &mut output.dest).collect(),
        _ => Vec::new(),
    }
}

pub(crate) fn statement_writes(stmt: &Stmt) -> FxHashSet<u16> {
    let mut writes = FxHashSet::default();
    match stmt {
        Stmt::Machine { outputs, .. } => writes.extend(outputs.iter().map(|dest| dest.index)),
        Stmt::Assign { dest, .. } => {
            writes.insert(dest.index);
        }
        Stmt::Call { outputs, .. } => {
            writes.extend(outputs.iter().map(|output| output.dest.index));
            writes.extend(
                stmt.call_clobbers()
                    .into_iter()
                    .filter(|register| !outputs.iter().any(|output| output.register == *register)),
            );
        }
        // An unmodeled instruction may leave changed the registers it names,
        // or any machine register when they are not known.
        Stmt::Unsupported { writes: named, .. } => match named {
            Some(named) => writes.extend(named),
            None => writes.extend(crate::arch::machine_registers()),
        },
        _ => {}
    }
    writes
}

pub(crate) fn statement_registers(stmt: &Stmt) -> (FxHashSet<u16>, FxHashSet<u16>) {
    let writes = statement_writes(stmt);
    let mut reads = FxHashSet::default();
    match stmt {
        Stmt::Machine { inputs, .. } => {
            for input in inputs {
                expr_reads(input, &mut reads);
            }
        }
        Stmt::Assign { value, .. } => expr_reads(value, &mut reads),
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
        Stmt::Switch { index, .. } => expr_reads(index, &mut reads),
        Stmt::Call { through, args, .. } => {
            if let Some(through) = through {
                expr_reads(through, &mut reads);
            }
            for arg in args.iter().flatten() {
                expr_reads(arg, &mut reads);
            }
            reads.extend(stmt.unnamed_call_reads());
            reads.extend(stmt.declared_call_reads());
            reads.extend(
                stmt.preserved_output_sources()
                    .into_iter()
                    .map(|(_, register)| register),
            );
        }
        _ => {}
    }
    (writes, reads)
}

/// The temporaries no statement and no annotation of the function names,
/// nor any with a fixed role, in ascending order.
pub(crate) fn unused_temporaries(ir: &super::FunctionIr) -> Vec<u16> {
    let mut used = FxHashSet::default();
    used.extend(super::FLAG_OPERANDS);
    used.extend(super::FLAG_CARRIED);
    used.extend([
        super::EXCHANGE,
        super::SWITCH_INDEX,
        super::EXCEPTION,
        super::SELECTOR,
    ]);
    used.extend(ir.params.iter().map(|param| param.index));
    used.extend(ir.signed_params.iter().copied());
    used.extend(ir.pointer_values.iter().copied());
    used.extend(ir.value_types.keys().copied());
    used.extend(ir.variable_registers.keys().copied());
    used.extend(ir.variable_registers.values().copied());
    used.extend(ir.accesses.iter().map(|access| access.register));
    used.extend(
        ir.structures
            .iter()
            .flat_map(|structure| structure.elements.iter().copied()),
    );
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        let (writes, reads) = statement_registers(stmt);
        used.extend(writes);
        used.extend(reads);
        used.extend(stmt.call_outputs().iter().map(|output| output.register));
    }
    (super::TEMP_BASE..super::VARIABLE_BASE)
        .filter(|register| !used.contains(register))
        .collect()
}

pub(crate) fn expr_reads<S: std::hash::BuildHasher>(
    expr: &Expr,
    reads: &mut std::collections::HashSet<u16, S>,
) {
    collect_reads(expr, reads);
}

pub(crate) fn assignment_at(
    statements: &[Stmt],
    position: usize,
) -> Option<(crate::ir::RegRef, &Expr)> {
    statements.get(position).and_then(assignment)
}

pub(crate) fn assignment(stmt: &Stmt) -> Option<(crate::ir::RegRef, &Expr)> {
    match stmt {
        Stmt::Assign { dest, value } => Some((*dest, value)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BinOp, Cond, Operation, Precision};
    use std::collections::HashSet;

    #[test]
    fn statement_sets_preserve_temporary_and_ssa_indices() {
        for index in [
            0,
            127,
            128,
            crate::ir::TEMP_BASE,
            crate::ir::VARIABLE_BASE,
            crate::ir::VALUE_BASE,
            u16::MAX,
        ] {
            let stmt = Stmt::Assign {
                dest: crate::ir::RegRef { index, width: 64 },
                value: Expr::reg(index, 64),
            };
            let (writes, reads) = statement_registers(&stmt);
            assert_eq!(writes.len(), 1);
            assert_eq!(reads.len(), 1);
            assert!(writes.contains(&index));
            assert!(reads.contains(&index));
        }
    }

    #[test]
    fn sum_terms_preserve_order_signs_and_unsplit_expressions() {
        let a = Expr::reg(1, 64);
        let b = Expr::reg(2, 64);
        let scaled = Expr::bin(BinOp::Mul, b.clone(), Expr::Const(8));
        let difference = Expr::bin(BinOp::Sub, a.clone(), b);
        let sum = Expr::bin(
            BinOp::Add,
            Expr::bin(BinOp::Sub, a.clone(), Expr::Const(5)),
            Expr::bin(BinOp::Add, scaled.clone(), difference.clone()),
        );
        for negative in [false, true] {
            let mut terms = vec![(&a, false)];
            sum_terms(&sum, negative, &mut terms);
            assert_eq!(
                terms,
                vec![
                    (&a, false),
                    (&a, negative),
                    (&Expr::Const(5), !negative),
                    (&scaled, negative),
                    (&difference, negative),
                ]
            );
        }
    }

    #[test]
    fn register_collectors_cover_every_expression_and_keep_existing_reads() {
        let expression = Expr::Select {
            cond: Cond::Eq,
            lhs: Box::new(Expr::reg(1, 64)),
            rhs: Box::new(Expr::constant(0)),
            then: Box::new(Expr::Load {
                addr: Box::new(Expr::bin(BinOp::Add, Expr::reg(2, 64), Expr::reg(1, 64))),
                width: 8,
                signed: false,
            }),
            els: Box::new(Expr::apply(
                Operation::FloatAbs(Precision::Single),
                vec![Expr::SignExtend {
                    value: Box::new(Expr::reg(3, 8)),
                    width: 8,
                }],
            )),
        };
        let expected = HashSet::from([1, 2, 3, 9]);
        let mut collected = HashSet::from([9]);
        collect_reads(&expression, &mut collected);
        assert_eq!(collected, expected);
        let mut reads = HashSet::from([9]);
        expr_reads(&expression, &mut reads);
        assert_eq!(reads, expected);
        let mut narrow = Expr::Bin {
            op: BinOp::And,
            lhs: Box::new(Expr::reg(1, 8)),
            rhs: Box::new(Expr::Const(0xff)),
        };
        rename_registers(
            &mut narrow,
            &std::collections::HashMap::from([(1, 2), (2, 3)]),
        );
        assert_eq!(
            narrow,
            Expr::Bin {
                op: BinOp::And,
                lhs: Box::new(Expr::reg(2, 8)),
                rhs: Box::new(Expr::Const(0xff)),
            }
        );
    }
}

//! Shared storage for the two words of a vector value.

use std::collections::{BTreeMap, HashSet};

use crate::ir::{BinOp, CType, Expr, FunctionIr, Operation, Stmt};

pub(super) struct Group {
    pub(super) name: String,
    pub(super) fields: [(u16, String); 2],
}

#[derive(Clone, Copy)]
enum Use {
    Value,
    Scalar,
    Address,
}

pub(super) fn groups(
    ir: &FunctionIr,
    types: &BTreeMap<u16, CType>,
    reserved: &mut HashSet<String>,
) -> Vec<Group> {
    let origin = |index| ir.variable_registers.get(&index).copied().unwrap_or(index);
    if !types
        .keys()
        .any(|index| crate::arch::vector_half(ir.isa, origin(*index)) == Some(true))
    {
        return Vec::new();
    }
    let mut separate = HashSet::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        match stmt {
            Stmt::Assign { value, .. } | Stmt::Ret { value } => {
                separate_uses(value, Use::Value, &mut separate);
            }
            Stmt::Store { addr, value, .. } => {
                separate_uses(addr, Use::Address, &mut separate);
                separate_uses(value, Use::Value, &mut separate);
            }
            Stmt::Brif { lhs, rhs, .. } => {
                separate_uses(lhs, Use::Scalar, &mut separate);
                separate_uses(rhs, Use::Scalar, &mut separate);
            }
            _ => {
                let (writes, reads) = crate::ir::visit::statement_registers(stmt);
                separate.extend(writes);
                separate.extend(reads);
            }
        }
    }
    let mut used = HashSet::new();
    let mut groups = Vec::new();
    for block in &ir.blocks {
        for pair in block.stmts.windows(2) {
            let [
                Stmt::Assign { dest: low, .. },
                Stmt::Assign { dest: high, .. },
            ] = pair
            else {
                continue;
            };
            if low.width != 64
                || high.width != 64
                || crate::arch::vector_half(ir.isa, origin(low.index)) != Some(false)
                || origin(low.index).checked_add(1) != Some(origin(high.index))
            {
                continue;
            }
            let indices = [low.index, high.index];
            if indices.iter().any(|index| {
                used.contains(index)
                    || separate.contains(index)
                    || !types.get(index).is_some_and(|ty| member(ty).is_some())
                    || ir.params.iter().any(|param| param.index == *index)
            }) {
                continue;
            }
            let name = super::function::vacant_name("vector", reserved);
            let member = |index, half| {
                let lane = member(&types[&index]).expect("candidate types have a lane member");
                (index, format!("{name}.{half}.{lane}"))
            };
            groups.push(Group {
                fields: [member(low.index, "low"), member(high.index, "high")],
                name,
            });
            used.extend(indices);
        }
    }
    groups
}

fn member(ty: &CType) -> Option<&'static str> {
    match ty.integer() {
        Some((8, false)) => Some("u8"),
        Some((8, true)) => Some("i8"),
        Some((16, false)) => Some("u16"),
        Some((16, true)) => Some("i16"),
        Some((32, false)) => Some("u32"),
        Some((32, true)) => Some("i32"),
        Some((64, false)) => Some("u64"),
        Some((64, true)) => Some("i64"),
        _ => match ty.to_string().as_str() {
            "float" => Some("f32"),
            "double" => Some("f64"),
            _ => None,
        },
    }
}

fn separate_uses(expr: &Expr, usage: Use, separate: &mut HashSet<u16>) {
    if let Expr::Reg { index, width } = expr {
        if matches!(usage, Use::Address) || (matches!(usage, Use::Scalar) && *width == 64) {
            separate.insert(*index);
        }
        return;
    }
    let extraction = match expr {
        Expr::Bin {
            op: BinOp::And,
            rhs,
            ..
        } => {
            matches!(rhs.as_ref(), Expr::Const(mask) if *mask != u64::MAX)
        }
        Expr::Bin {
            op: BinOp::Shl | BinOp::Shr | BinOp::Sar,
            rhs,
            ..
        } => {
            matches!(rhs.as_ref(), Expr::Const(1..=63))
        }
        Expr::SignExtend { width, .. } => *width < 64,
        _ => false,
    };
    let usage = match (usage, expr) {
        (Use::Address, _) | (_, Expr::Load { .. }) => Use::Address,
        _ if extraction => Use::Value,
        (
            Use::Value,
            Expr::Bin {
                op: BinOp::And | BinOp::Or | BinOp::Xor | BinOp::Shl | BinOp::Shr,
                ..
            }
            | Expr::SignExtend { .. }
            | Expr::Apply {
                op: Operation::Lanes(..),
                ..
            },
        ) => Use::Value,
        _ => Use::Scalar,
    };
    for child in crate::ir::visit::children(expr) {
        separate_uses(child, usage, separate);
    }
}

pub(super) fn whole_writes(body: &str, groups: &[Group]) -> String {
    let lines: Vec<_> = body.split_inclusive('\n').collect();
    let mut out = String::with_capacity(body.len());
    let mut position = 0;
    while position < lines.len() {
        let line = lines[position];
        let mut combined = false;
        if let Some(next) = lines.get(position + 1) {
            let indentation = &line[..line.len() - line.trim_start().len()];
            for group in groups {
                let [(.., low), (.., high)] = &group.fields;
                let Some(low_value) = line
                    .trim_start()
                    .strip_prefix(&format!("{low} = "))
                    .and_then(|value| value.strip_suffix(";\n"))
                else {
                    continue;
                };
                let Some(high_value) = next
                    .strip_prefix(indentation)
                    .and_then(|line| line.strip_prefix(&format!("{high} = ")))
                    .and_then(|value| value.strip_suffix(";\n"))
                else {
                    continue;
                };
                if super::variables::mentions(low_value, &group.name)
                    || super::variables::mentions(high_value, &group.name)
                {
                    continue;
                }
                let low = &low[group.name.len()..];
                let high = &high[group.name.len()..];
                out.push_str(&format!("{indentation}{} = (struct velk_vector){{ {low} = {low_value}, {high} = {high_value} }};\n", group.name));
                combined = true;
                break;
            }
        }
        if combined {
            position += 2;
        } else {
            out.push_str(line);
            position += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::RegRef;
    use crate::loader::Isa;

    #[test]
    fn independent_half_arithmetic_keeps_scalar_storage() {
        let ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: 18,
                        width: 64,
                    },
                    value: Expr::Const(1),
                },
                Stmt::Assign {
                    dest: RegRef {
                        index: 19,
                        width: 64,
                    },
                    value: Expr::Const(2),
                },
                Stmt::Ret {
                    value: Expr::bin(BinOp::Add, Expr::reg(18, 64), Expr::reg(19, 64)),
                },
            ],
        );
        let types = [(18, CType::U64), (19, CType::U64)].into();
        assert!(groups(&ir, &types, &mut HashSet::new()).is_empty());
    }
}

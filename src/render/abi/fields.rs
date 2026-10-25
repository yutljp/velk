use super::{Capture, Plan};
use crate::ir::{BinOp, Expr, FunctionIr, Operation, Param, RegisterClass, Stmt};

pub(super) fn captures(ir: &FunctionIr, plan: &mut Plan) {
    for capture in &mut plan.captures {
        if capture.field.is_some() {
            continue;
        }
        let ty = plan.params[capture.parameter].1.to_string();
        capture.parts = integer_members(ir, &ty, &capture.piece);
    }
    if let Some(result) = &mut plan.result
        && result.fields.is_empty()
        && !result.indirect
    {
        result.parts = result
            .pieces
            .iter()
            .map(|(piece, _)| integer_members(ir, &result.ty.to_string(), piece))
            .collect();
    }
}

fn integer_members(
    ir: &FunctionIr,
    ty: &str,
    piece: &crate::ir::AbiPiece,
) -> Vec<crate::ir::Member> {
    if piece.bytes > 8 {
        return Vec::new();
    }
    let Some(structure) = ty.strip_prefix("struct ") else {
        return Vec::new();
    };
    let Some(definition) = ir
        .definitions
        .iter()
        .find(|definition| definition.name == ty)
    else {
        return Vec::new();
    };
    if ir
        .definitions
        .iter()
        .filter(|definition| definition.name == ty)
        .count()
        != 1
        || !super::super::layouts::usable(ir, definition, structure)
    {
        return Vec::new();
    }
    let Some(end) = piece.object_offset.checked_add(piece.bytes) else {
        return Vec::new();
    };
    let mut members: Vec<_> = ir
        .members
        .iter()
        .filter(|member| {
            member.structure == structure
                && member.offset >= 0
                && member.offset as u64 >= piece.object_offset
                && (member.offset as u64)
                    .checked_add(member.width)
                    .is_some_and(|stop| stop <= end)
        })
        .cloned()
        .collect();
    members.sort_by_key(|member| member.offset);
    let mut offset = piece.object_offset;
    let complete = members.iter().all(|member| {
        if member.offset as u64 != offset
            || matches!(&member.ty, crate::ir::CType::Named(name) if name.split_whitespace().any(|word| matches!(word, "bool" | "_Bool")))
            || !member
                .ty
                .integer()
                .is_some_and(|(bits, _)| u64::from(bits) == member.width * 8)
            || super::sanitize(&member.name) != member.name
            || super::super::globals::reserved_identifier(&member.name)
        {
            return false;
        }
        offset = offset.saturating_add(member.width);
        true
    });
    if complete && offset == end {
        members
    } else {
        Vec::new()
    }
}

// Limit projection to a complete straight-line copy and construction. No address
// or intermediate object survives this pattern, so neither can escape.
pub(super) fn project(
    ir: &mut FunctionIr,
    plan: &mut Plan,
    mut reserved: std::collections::HashSet<String>,
) {
    let Some(result) = &plan.result else { return };
    if result.indirect
        || result.pieces.len() != 1
        || !plan.pointers.is_empty()
        || ir.blocks.len() != 1
        || !ir.landing_pads.is_empty()
        || plan.captures.len() != plan.params.len()
        || plan.params.is_empty()
    {
        return;
    }
    let ty = result.ty.to_string();
    let Some(definition) = ir
        .definitions
        .iter()
        .find(|definition| definition.name == ty)
    else {
        return;
    };
    if !ty.starts_with("struct ")
        || definition.size != 8
        || definition.alignment != Some(4)
        || definition.fields.len() != 2
        || definition.members.len() != 2
        || !definition.contains.is_empty()
        || plan.params.iter().any(|(_, arg)| arg.to_string() != ty)
    {
        return;
    }
    let mut members: Vec<_> = ir
        .members
        .iter()
        .filter(|member| Some(member.structure.as_str()) == ty.strip_prefix("struct "))
        .collect();
    members.sort_by_key(|member| member.offset);
    if members.len() != 2
        || members.iter().enumerate().any(|(index, member)| {
            member.offset != index as i64 * 4
                || member.width != 4
                || member.ty.integer().map(|(bits, _)| bits) != Some(32)
                || member.name != definition.fields[index]
                || super::sanitize(&member.name) != member.name
                || super::super::globals::reserved_identifier(&member.name)
        })
    {
        return;
    }
    let Some(signature) = &ir.declared_signature else {
        return;
    };
    let Ok(abi) = &signature.abi else { return };
    if abi.arguments.iter().chain(&abi.result).any(|value| {
        !value.aggregate
            || value.size != 8
            || value.alignment != 4
            || value.defined_bits != [(0, 64)]
    }) {
        return;
    }
    if plan
        .captures
        .iter()
        .map(|capture| &capture.piece)
        .chain(result.pieces.iter().map(|(piece, _)| piece))
        .any(|piece| {
            piece.object_offset != 0
                || piece.bytes != 8
                || piece.class != Some(RegisterClass::Integer)
        })
    {
        return;
    }
    let stmts = &ir.blocks[0].stmts;
    let count = plan.captures.len();
    if stmts.len() != count.saturating_add(3) {
        return;
    }
    let sp = crate::arch::stack_pointer(ir.isa);
    let slot = |addr: &Expr| match addr {
        Expr::Reg { index, width: 64 } if *index == sp => Some(0),
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Reg { index, width: 64 }, Expr::Const(offset)) if *index == sp => {
                Some(*offset as i64)
            }
            _ => None,
        },
        _ => None,
    };
    let mut slots = Vec::new();
    for (stmt, capture) in stmts.iter().zip(&plan.captures) {
        let Stmt::Store {
            addr,
            value: Expr::Reg { index, width: 64 },
            width: 8,
        } = stmt
        else {
            return;
        };
        if *index != capture.register {
            return;
        }
        let Some(start) = slot(addr) else { return };
        let Some(end) = start.checked_add(8) else {
            return;
        };
        if start < -(crate::ir::eval::STACK_SPAN as i64) || end > 0 {
            return;
        }
        if slots
            .iter()
            .any(|&(other, stop)| start < stop && other < end)
        {
            return;
        }
        slots.push((start, end));
    }
    let Stmt::Ret {
        value: Expr::Apply {
            op: Operation::Results,
            args,
        },
    } = &stmts[count + 2]
    else {
        return;
    };
    let [Expr::Load { addr, width: 8, .. }] = args.as_slice() else {
        return;
    };
    let Some(output) = slot(addr) else { return };
    let Some(end) = output.checked_add(8) else {
        return;
    };
    if output < -(crate::ir::eval::STACK_SPAN as i64) || end > 0 {
        return;
    }
    if slots
        .iter()
        .any(|&(start, stop)| output < stop && start < end)
    {
        return;
    }
    let mut values = Vec::new();
    for field in 0..2 {
        let Stmt::Store {
            addr,
            value,
            width: 4,
        } = &stmts[count + field]
        else {
            return;
        };
        if slot(addr) != output.checked_add(field as i64 * 4) {
            return;
        }
        values.push(value.clone());
    }
    let mut next = ir
        .params
        .iter()
        .map(|param| param.index)
        .chain(ir.value_types.keys().copied())
        .chain(ir.variable_registers.keys().copied())
        .chain(ir.variable_registers.values().copied())
        .max()
        .unwrap_or(0)
        .max(crate::ir::VARIABLE_BASE);
    let mut captures = Vec::new();
    let mut registers = Vec::new();
    reserved.extend(plan.reserved_names());
    for capture in &plan.captures {
        let mut pair = Vec::new();
        for member in &members {
            let Some(index) = next.checked_add(1) else {
                return;
            };
            if index >= crate::ir::VALUE_BASE {
                return;
            }
            next = index;
            pair.push(index);
            let base = format!("{}_{}", capture.object, member.name);
            if super::super::globals::reserved_identifier(&base) {
                reserved.insert(base.clone());
            }
            captures.push(Capture {
                register: index,
                name: super::vacant_name(&base, &mut reserved),
                object: capture.object.clone(),
                piece: capture.piece.clone(),
                parameter: capture.parameter,
                field: Some(member.name.clone()),
                parts: Vec::new(),
                direct: None,
            });
        }
        registers.push(pair);
    }
    fn replace(
        expr: &mut Expr,
        slots: &[(i64, i64)],
        registers: &[Vec<u16>],
        slot: &impl Fn(&Expr) -> Option<i64>,
    ) -> bool {
        match expr {
            Expr::Load {
                addr,
                width: 4,
                signed: false,
            } => {
                let Some(offset) = slot(addr) else {
                    return false;
                };
                for (index, &(start, _)) in slots.iter().enumerate() {
                    for (field, register) in registers[index].iter().enumerate() {
                        if start.checked_add(field as i64 * 4) == Some(offset) {
                            *expr = Expr::reg(*register, 32);
                            return true;
                        }
                    }
                }
                false
            }
            Expr::Const(_) => true,
            Expr::Bin {
                op: BinOp::Add | BinOp::Sub | BinOp::And | BinOp::Or | BinOp::Xor,
                lhs,
                rhs,
            } => replace(lhs, slots, registers, slot) && replace(rhs, slots, registers, slot),
            _ => false,
        }
    }
    if !values
        .iter_mut()
        .all(|value| replace(value, &slots, &registers, &slot))
    {
        return;
    }
    plan.result.as_mut().unwrap().fields =
        members.iter().map(|member| member.name.clone()).collect();
    ir.params = captures
        .iter()
        .map(|capture| Param {
            index: capture.register,
            name: capture.name.clone(),
            ty: crate::ir::CType::U32,
        })
        .collect();
    plan.captures = captures;
    ir.blocks[0].stmts = vec![Stmt::Ret {
        value: Expr::Apply {
            op: Operation::Results,
            args: values,
        },
    }];
}

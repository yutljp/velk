//! Calls through header-derived COM interface fields.

use std::collections::{HashMap, HashSet};

use crate::ir::{BinOp, CType, Expr, FunctionIr, Stmt};
use crate::loader::Format;

use super::expr::Ctx;

fn slot(through: &Expr, pointer_width: u8) -> Option<(&Expr, u64)> {
    fn unmask(value: &Expr, pointer_width: u8) -> &Expr {
        match value {
            Expr::Bin {
                op: BinOp::And,
                lhs,
                rhs,
            } if pointer_width == 4 && **rhs == Expr::Const(0xffff_ffff) => lhs.as_ref(),
            _ => value,
        }
    }
    let Expr::Load { addr, width, .. } = through else {
        return None;
    };
    if *width != pointer_width {
        return None;
    }
    match unmask(addr, pointer_width) {
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => match rhs.as_ref() {
            Expr::Const(offset) => Some((unmask(lhs, pointer_width), *offset)),
            _ => None,
        },
        base => Some((base, 0)),
    }
}

fn receiver_type<'ir>(ir: &'ir FunctionIr, receiver: &Expr, depth: usize) -> Option<&'ir CType> {
    if depth == 0 {
        return None;
    }
    match receiver {
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if **rhs == Expr::Const(0xffff_ffff) => receiver_type(ir, lhs, depth - 1),
        Expr::Reg { index, width: 64 } => {
            if let Some(ty) = ir
                .params
                .iter()
                .find(|param| param.index == *index)
                .map(|param| &param.ty)
                .or_else(|| ir.value_types.get(index))
            {
                return Some(ty);
            }
            let mut assignments = ir
                .blocks
                .iter()
                .flat_map(|block| &block.stmts)
                .filter(|stmt| {
                    crate::ir::visit::statement_registers(stmt)
                        .0
                        .contains(index)
                });
            let Some(Stmt::Assign { value, .. }) = assignments.next() else {
                return None;
            };
            if assignments.next().is_some() {
                return None;
            }
            receiver_type(ir, value, depth - 1)
        }
        Expr::Load { addr, width, .. } if *width == crate::arch::pointer_bytes(ir.isa) => {
            let Some(offset) = crate::passes::frame_slots::checked_frame_slot(
                addr,
                0,
                crate::arch::stack_pointer(ir.isa),
            ) else {
                return None;
            };
            ir.stack_params
                .iter()
                .find(|param| param.offset == offset)
                .map(|param| &param.ty)
        }
        _ => None,
    }
}

fn method<'ir>(
    ir: &'ir FunctionIr,
    receiver: &Expr,
    offset: u64,
) -> Option<&'ir crate::ir::Member> {
    let ty = receiver_type(ir, receiver, 8);
    let Some(interface) = ty.and_then(CType::pointee_struct) else {
        return None;
    };
    let mut tables = ir.members.iter().filter(|member| {
        member.structure == interface && member.offset == 0 && member.name == "lpVtbl"
    });
    let Some(table) = tables.next() else {
        return None;
    };
    if tables.next().is_some() {
        return None;
    }
    let Some(table_name) = table.ty.pointee_struct() else {
        return None;
    };
    if table.width != u64::from(crate::arch::pointer_bytes(ir.isa))
        || table_name != format!("{interface}Vtbl")
    {
        return None;
    }
    let Ok(offset) = i64::try_from(offset) else {
        return None;
    };
    let mut methods = ir
        .members
        .iter()
        .filter(|member| member.structure == table_name && member.offset == offset);
    let Some(method) = methods.next() else {
        return None;
    };
    if methods.next().is_some() || method.width != u64::from(crate::arch::pointer_bytes(ir.isa)) {
        return None;
    }
    let CType::Pointer(function) = &method.ty else {
        return None;
    };
    let CType::Function { params, .. } = function.as_ref() else {
        return None;
    };
    if params.first().and_then(CType::pointee_struct) != Some(interface) {
        return None;
    }
    Some(method)
}

pub(super) fn prepare(ir: &mut FunctionIr, symbols: &super::Symbols) {
    if !matches!(symbols.target_format, Some(Format::Pe | Format::Coff)) {
        return;
    }
    let width = crate::arch::pointer_bytes(ir.isa);
    let mut reads = HashMap::<u16, usize>::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        for register in crate::ir::visit::statement_registers(stmt).1 {
            *reads.entry(register).or_default() += 1;
        }
    }
    for block_index in 0..ir.blocks.len() {
        for position in (1..ir.blocks[block_index].stmts.len()).rev() {
            let stmts = &ir.blocks[block_index].stmts;
            let Stmt::Assign {
                dest,
                value:
                    Expr::Load {
                        addr: receiver,
                        width: loaded,
                        ..
                    },
            } = &stmts[position - 1]
            else {
                continue;
            };
            let Stmt::Call {
                target: None,
                through: Some(through),
                args: Some(args),
                ..
            } = &stmts[position]
            else {
                continue;
            };
            let Some((base, offset)) = slot(through, width) else {
                continue;
            };
            let mut argument_reads = HashSet::new();
            for arg in args {
                crate::ir::visit::collect_reads(arg, &mut argument_reads);
            }
            if stmts[position].has_declared_call()
                || argument_reads.contains(&dest.index)
                || *loaded != width
                || dest.width != 64
                || *base != Expr::reg(dest.index, 64)
                || reads.get(&dest.index) != Some(&1)
                || args.first() != Some(receiver.as_ref())
                || method(ir, receiver, offset).is_none()
            {
                continue;
            }
            let table = Expr::Load {
                addr: receiver.clone(),
                width,
                signed: false,
            };
            let mut replacement = stmts[position].clone();
            crate::ir::visit::replace_reads(&mut replacement, &[(dest.index, table)]);
            let stmts = &mut ir.blocks[block_index].stmts;
            stmts[position] = replacement;
            stmts.remove(position - 1);
        }
    }
}

pub(super) fn expression(call: &Stmt, ctx: &Ctx<'_>) -> Option<String> {
    if call.has_declared_call() {
        return None;
    }
    if !matches!(ctx.symbols.target_format, Some(Format::Pe | Format::Coff)) {
        return None;
    }
    let Stmt::Call {
        target: None,
        through: Some(through),
        args: Some(args),
        convention,
        ..
    } = call
    else {
        return None;
    };
    let width = crate::arch::pointer_bytes(ctx.isa);
    let Some((
        Expr::Load {
            addr: receiver,
            width: loaded,
            ..
        },
        offset,
    )) = slot(through, width)
    else {
        return None;
    };
    if *loaded != width || args.first() != Some(receiver.as_ref()) {
        return None;
    }
    let Some(method) = method(ctx.ir, receiver, offset) else {
        return None;
    };
    let CType::Pointer(function) = &method.ty else {
        return None;
    };
    let CType::Function {
        params,
        ret,
        variadic: false,
        convention: declared,
    } = function.as_ref()
    else {
        return None;
    };
    if declared != convention
        || params.len() != args.len()
        || params
            .iter()
            .any(|ty| !ty.is_pointer() && ty.integer().is_none())
    {
        return None;
    }
    let Some((bits, _)) = ret.integer().filter(|(bits, _)| *bits <= 32) else {
        return None;
    };
    for output in call.call_outputs() {
        if !ctx.call_outputs.used(call, output) {
            continue;
        }
        if output.register != crate::arch::RETURN
            || !ctx
                .declared
                .get(&output.dest.index)
                .is_some_and(|ty| ty.integer && ty.bits <= bits)
        {
            return None;
        }
    }
    let mut arguments = Vec::new();
    for (arg, ty) in args.iter().zip(params) {
        let text = super::expr::print_value_at(arg, ctx, 64, false);
        let pointer = ty.is_pointer().then(|| ty.to_string());
        arguments.push(super::conformed(arg, text, pointer.as_deref(), ctx));
    }
    let Some(receiver_ty) = receiver_type(ctx.ir, receiver, 8) else {
        return None;
    };
    let pointer = receiver_ty.to_string();
    let receiver = super::conformed(
        receiver,
        super::expr::print_value_at(receiver, ctx, 64, false),
        Some(&pointer),
        ctx,
    );
    let receiver = if receiver.starts_with(['(', '*', '&']) {
        format!("({receiver})")
    } else {
        receiver
    };
    Some(format!(
        "{receiver}->lpVtbl->{}({})",
        method.name,
        arguments.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::smt::Proofs;

    #[test]
    fn com_vtable_target_substitution_smt() {
        if !Proofs::available() {
            return;
        }
        let mut proofs = Proofs::default();
        for arch in ["x86_64", "i686"] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(format!("tests/fixtures/com_{arch}.dll"));
            let mut binary = crate::service::Binary::open(&path).unwrap();
            let address = binary.find("com_release").unwrap().addr;
            let before = binary.analysis(address, None).unwrap().ir.clone();
            let mut after = before.clone();
            prepare(&mut after, &super::super::callee_names(binary.image()));
            assert_eq!(
                after.blocks[0].stmts.len() + 1,
                before.blocks[0].stmts.len()
            );
            let observe = |ir: &FunctionIr| {
                let mut statements = Vec::new();
                for stmt in &ir.blocks[0].stmts {
                    match stmt {
                        Stmt::Call {
                            through: Some(through),
                            ..
                        } => {
                            statements.push(Stmt::Ret {
                                value: through.clone(),
                            });
                            break;
                        }
                        other => statements.push(other.clone()),
                    }
                }
                statements
            };
            proofs.program(
                format!("COM vtable target {arch}"),
                &observe(&before),
                &observe(&after),
            );
        }
        proofs.check();
    }
}

//! Recover simple x86-32 COM calls from header types and debug parameters.

use std::collections::HashMap;

use crate::ir::{BinOp, CType, Convention, Expr, FunctionIr, RegRef, Stmt};
use crate::loader::{Format, Image, Isa};

use super::prototypes;

fn unmask(value: &Expr) -> &Expr {
    match value {
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if **rhs == Expr::Const(0xffff_ffff) => lhs,
        _ => value,
    }
}

fn value_type(
    value: &Expr,
    registers: &HashMap<u16, CType>,
    parameters: &HashMap<i64, CType>,
    image: &Image,
    depth: usize,
) -> Option<CType> {
    if depth == 0 {
        return None;
    }
    match unmask(value) {
        Expr::Reg {
            index,
            width: 32 | 64,
        } => registers.get(index).cloned(),
        Expr::Load { addr, width: 4, .. } => {
            let addr = unmask(addr);
            if let Some(offset) = crate::passes::frame_slots::checked_frame_slot(
                addr,
                0,
                crate::arch::stack_pointer(image.isa),
            ) {
                return parameters.get(&offset).cloned();
            }
            let (base, offset) = match addr {
                Expr::Bin {
                    op: BinOp::Add,
                    lhs,
                    rhs,
                } => match rhs.as_ref() {
                    Expr::Const(offset) => (unmask(lhs), *offset),
                    _ => return None,
                },
                base => (base, 0),
            };
            let Some(CType::Pointer(target)) =
                value_type(base, registers, parameters, image, depth - 1)
            else {
                return None;
            };
            let CType::Named(name) = target.as_ref() else {
                return None;
            };
            let Some(record) = prototypes::record(name, image) else {
                return None;
            };
            let Some(field) = record
                .fields
                .iter()
                .find(|field| field.offset == offset && field.width == 4)
            else {
                return None;
            };
            Some(prototypes::parse_type(&field.c_type))
        }
        _ => None,
    }
}

pub(super) fn recover_i386(
    ir: &mut FunctionIr,
    image: &Image,
    types: Option<&crate::loader::dwarf::FunctionTypes>,
) {
    if image.isa != Isa::I386
        || !matches!(image.format, Format::Pe | Format::Coff)
        || !matches!(ir.convention, Convention::Cdecl | Convention::Stdcall)
        || ir.blocks.len() != 1
    {
        return;
    }
    let Some(types) = types else { return };
    if types.variadic
        || super::abi::has_aggregate(types)
        || types.param_layouts.len() != types.params.len()
    {
        return;
    }
    if ir.blocks[0]
        .stmts
        .iter()
        .filter(|stmt| matches!(stmt, Stmt::Call { .. }))
        .count()
        != 1
    {
        return;
    }
    let mut parameters = HashMap::new();
    for (position, (_, ty)) in types.params.iter().enumerate() {
        let Some(ty) = ty else { return };
        if !ty.is_pointer() && !ty.integer().is_some_and(|(bits, _)| bits <= 32) {
            return;
        }
        let Ok(layout) = &types.param_layouts[position] else {
            return;
        };
        if !layout.trivial
            || !layout
                .alignment
                .is_some_and(|alignment| alignment.is_power_of_two() && alignment <= 4)
        {
            return;
        }
        let valid = if ty.is_pointer() {
            layout.kind == crate::ir::abi::LayoutKind::Pointer && layout.size == 4
        } else {
            matches!(
                layout.kind,
                crate::ir::abi::LayoutKind::Integer | crate::ir::abi::LayoutKind::Boolean
            ) && ty
                .integer()
                .is_some_and(|(bits, _)| u64::from(bits).div_ceil(8) == layout.size)
        };
        if !valid {
            return;
        }
        let Ok(position) = i64::try_from(position) else {
            return;
        };
        let Some(offset) = position
            .checked_add(1)
            .and_then(|position| position.checked_mul(4))
        else {
            return;
        };
        parameters.insert(offset, ty.clone());
    }
    let mut candidate = ir.clone();
    crate::passes::frame_slots::settle_i386(&mut candidate);
    let sp = crate::arch::stack_pointer(image.isa);
    if candidate.blocks[0]
        .stmts
        .iter()
        .any(|stmt| crate::ir::visit::statement_registers(stmt).0.contains(&sp))
    {
        return;
    }
    let mut registers = HashMap::new();
    let mut count = None;
    for stmt in &candidate.blocks[0].stmts {
        match stmt {
            Stmt::Assign { dest, value } => {
                let ty = value_type(value, &registers, &parameters, image, 8);
                registers.remove(&dest.index);
                if let Some(ty) = ty.filter(|_| dest.width >= 32) {
                    registers.insert(dest.index, ty);
                }
            }
            Stmt::Store { addr, width, .. } => {
                if let Some(offset) = crate::passes::frame_slots::checked_frame_slot(
                    addr,
                    0,
                    crate::arch::stack_pointer(image.isa),
                ) {
                    let Some(end) = offset.checked_add(i64::from(*width)) else {
                        return;
                    };
                    parameters.retain(|at, _| {
                        at.checked_add(4)
                            .is_some_and(|stop| stop <= offset || *at >= end)
                    });
                } else {
                    return;
                }
            }
            Stmt::Call {
                target: None,
                through: Some(through),
                args: None,
                ..
            } => {
                let Some(CType::Pointer(function)) =
                    value_type(through, &registers, &parameters, image, 8)
                else {
                    return;
                };
                let CType::Function {
                    params,
                    ret,
                    variadic: false,
                    convention: Convention::Stdcall,
                } = *function
                else {
                    return;
                };
                if !ret.is_pointer()
                    && *ret != CType::Void
                    && !ret.integer().is_some_and(|(bits, _)| bits <= 32)
                {
                    return;
                }
                if params
                    .iter()
                    .any(|ty| !ty.is_pointer() && !ty.integer().is_some_and(|(bits, _)| bits <= 32))
                {
                    return;
                }
                count = Some(params.len());
            }
            _ => {
                for register in crate::ir::visit::statement_registers(stmt).0 {
                    registers.remove(&register);
                }
            }
        }
    }
    let Some(count) = count else { return };
    let Some(cleanup) = count
        .checked_mul(4)
        .and_then(|bytes| i64::try_from(bytes).ok())
    else {
        return;
    };
    let Some(position) = ir.blocks[0]
        .stmts
        .iter()
        .position(|stmt| matches!(stmt, Stmt::Call { .. }))
    else {
        return;
    };
    let Stmt::Call {
        kind,
        convention,
        args,
        ..
    } = &mut ir.blocks[0].stmts[position]
    else {
        return;
    };
    let tail = *kind == crate::ir::CallKind::Tail;
    *convention = Convention::Stdcall;
    *args = crate::lift::arguments(*kind, *convention, image.isa, Some(count), 0);
    if !tail && cleanup != 0 {
        let sp = crate::arch::stack_pointer(image.isa);
        ir.blocks[0].stmts.insert(
            position + 1,
            Stmt::Assign {
                dest: RegRef {
                    index: sp,
                    width: 64,
                },
                value: Expr::bin(
                    BinOp::And,
                    Expr::bin(BinOp::Add, Expr::reg(sp, 64), Expr::Const(cleanup as u64)),
                    Expr::Const(0xffff_ffff),
                ),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdcall_recovery_requires_a_known_complete_signature() {
        let image = crate::loader::load(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/com_i686.dll"),
        )
        .unwrap();
        let function = image
            .functions
            .values()
            .find(|function| function.name.as_deref() == Some("_com_release"))
            .unwrap();
        let types = crate::loader::dwarf::function_types(&image, function.addr).unwrap();
        let mut original = FunctionIr::single_block(image.isa, Vec::new());
        original.blocks = crate::lift::lift(
            &image,
            function.addr,
            function.size.unwrap(),
            &Default::default(),
        )
        .unwrap();
        let mut recovered = original.clone();
        recover_i386(&mut recovered, &image, Some(&types));
        assert!(recovered.blocks[0].stmts.iter().any(|stmt| matches!(stmt, Stmt::Call { convention: Convention::Stdcall, args: Some(args), .. } if args.len() == 1)));
        for ty in [
            None,
            Some(CType::pointer_to(CType::Void)),
            Some(CType::U64),
            Some(CType::Named("float".into())),
        ] {
            let mut incomplete = types.clone();
            incomplete.params[0].1 = ty;
            let mut ir = original.clone();
            recover_i386(&mut ir, &image, Some(&incomplete));
            assert_eq!(ir.render(), original.render());
        }
        let mut fastcall = original.clone();
        fastcall.convention = Convention::Fastcall;
        let before = fastcall.render();
        recover_i386(&mut fastcall, &image, Some(&types));
        assert_eq!(fastcall.render(), before);
        let mut dynamic = original.clone();
        dynamic.blocks[0].stmts.insert(
            0,
            Stmt::Assign {
                dest: RegRef {
                    index: 4,
                    width: 64,
                },
                value: Expr::reg(0, 64),
            },
        );
        let before = dynamic.render();
        recover_i386(&mut dynamic, &image, Some(&types));
        assert_eq!(dynamic.render(), before);
        let mut multiple = original;
        let call = multiple.blocks[0]
            .stmts
            .iter()
            .find(|stmt| matches!(stmt, Stmt::Call { .. }))
            .unwrap()
            .clone();
        multiple.blocks[0].stmts.insert(0, call);
        let before = multiple.render();
        recover_i386(&mut multiple, &image, Some(&types));
        assert_eq!(multiple.render(), before);
    }
}

//! Applying scalar declarations to word pairs after register variables are split.

use crate::ir::{BinOp, Expr, FunctionIr, Param, StackParam};
use crate::lift::pairs32::{self, Location};
use crate::loader::dwarf::FunctionTypes;

pub(super) fn type_temporaries(ir: &mut FunctionIr) {
    if !matches!(ir.isa, crate::loader::Isa::I386 | crate::loader::Isa::Arm32) {
        return;
    }
    for (variable, register) in &ir.variable_registers {
        if pairs32::TEMPORARIES.contains(register) {
            ir.value_types.insert(*variable, crate::ir::CType::U64);
        }
    }
}

pub(super) fn place_parameters(types: &FunctionTypes, ir: &mut FunctionIr) {
    if types.variadic || super::abi::has_aggregate(types) {
        return;
    }
    place_named_parameters(&types.params, ir);
}

pub(super) fn place_inferred(
    params: Vec<crate::ir::CType>,
    ret: crate::ir::CType,
    ir: &mut FunctionIr,
) {
    place_inferred_parameters(params, ir);
    ir.ret_type = ret;
}

pub(super) fn place_inferred_parameters(params: Vec<crate::ir::CType>, ir: &mut FunctionIr) {
    let named: Vec<_> = params.into_iter().map(|ty| (None, Some(ty))).collect();
    place_named_parameters(&named, ir);
}

fn place_named_parameters(
    parameters: &[(Option<String>, Option<crate::ir::CType>)],
    ir: &mut FunctionIr,
) {
    let params: Option<Vec<_>> = parameters.iter().map(|(_, ty)| ty.clone()).collect();
    let Some(params) = params else { return };
    let Some(locations) = pairs32::locations(ir.isa, &params) else {
        return;
    };
    let mut registers = Vec::new();
    let mut stack = Vec::new();
    let mut reads = Vec::new();
    for (position, (((name, _), ty), (location, wide))) in
        parameters.iter().zip(params).zip(locations).enumerate()
    {
        let name = name.clone().unwrap_or_else(|| format!("a{position}"));
        match location {
            Location::Register(index) => {
                let parameter = if wide {
                    pairs32::PARAMETER_BASE + index
                } else {
                    index
                };
                registers.push(Param {
                    index: parameter,
                    name,
                    ty,
                });
                if wide {
                    reads.push((
                        index,
                        Expr::bin(
                            BinOp::And,
                            Expr::reg(parameter, 64),
                            Expr::constant(0xffff_ffff),
                        ),
                    ));
                    reads.push((
                        index + 1,
                        Expr::bin(BinOp::Shr, Expr::reg(parameter, 64), Expr::constant(32)),
                    ));
                }
            }
            Location::Stack(offset) => stack.push(StackParam {
                offset,
                size: if wide { 8 } else { 4 },
                name,
                ty,
                position,
            }),
        }
    }
    if let Some(entry) = ir.blocks.first_mut() {
        let mut setup = Vec::new();
        for (index, value) in reads {
            ir.value_types.insert(index, crate::ir::CType::U32);
            setup.push(crate::ir::Stmt::Assign {
                dest: crate::ir::RegRef { index, width: 64 },
                value,
            });
        }
        setup.append(&mut entry.stmts);
        entry.stmts = setup;
    }
    ir.params = registers;
    ir.stack_params = stack;
    narrow_parameter_loads(ir);
}

fn narrow_parameter_loads(ir: &mut FunctionIr) {
    fn walk(expr: &mut Expr, params: &[StackParam], sp: u16) {
        for child in crate::ir::visit::children_mut(expr) {
            walk(child, params, sp);
        }
        let Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } = expr
        else {
            return;
        };
        let Expr::Const(mask) = rhs.as_ref() else {
            return;
        };
        let Expr::Load { addr, width: 4, .. } = lhs.as_ref() else {
            return;
        };
        let Some(offset) = crate::passes::frame_slots::frame_slot(addr, 0, sp) else {
            return;
        };
        let Some(param) = params
            .iter()
            .find(|param| param.offset == offset && param.size == 4)
        else {
            return;
        };
        let Some((bits, false)) = param.ty.integer() else {
            return;
        };
        if !matches!(bits, 8 | 16) || *mask != (1u64 << bits) - 1 {
            return;
        }
        // The ABI allocates a readable word here. Only the declared value's bytes survive
        // the mask, whose expression width equals the unsigned narrow load's width.
        *expr = Expr::Load {
            addr: addr.clone(),
            width: (bits / 8) as u8,
            signed: false,
        };
    }
    let sp = crate::arch::stack_pointer(ir.isa);
    let statements = ir.blocks.iter_mut().flat_map(|block| &mut block.stmts);
    for stmt in statements {
        for operand in stmt.operands_mut() {
            walk(operand, &ir.stack_params, sp);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::smt::Proofs;
    use crate::ir::{CType, Stmt};
    use crate::loader::Isa;

    #[test]
    fn masked_parameter_loads_preserve_values_and_signed_contexts() {
        if !Proofs::available() {
            return;
        }
        let mut proofs = Proofs::default();
        for isa in [Isa::I386, Isa::Arm32] {
            for bits in [8, 16] {
                for shift in [0, 7, 15, 31] {
                    let value = Expr::bin(
                        BinOp::And,
                        Expr::Load {
                            addr: Box::new(Expr::reg(crate::arch::stack_pointer(isa), 64)),
                            width: 4,
                            signed: false,
                        },
                        Expr::Const((1 << bits) - 1),
                    );
                    let value = Expr::Bin {
                        op: BinOp::Sar,
                        lhs: Box::new(value),
                        rhs: Box::new(Expr::Const(shift)),
                    };
                    let mut ir = FunctionIr::single_block(isa, vec![Stmt::Ret { value }]);
                    ir.stack_params.push(StackParam {
                        offset: 0,
                        size: 4,
                        name: "value".into(),
                        ty: CType::int((bits / 8) as u8, false),
                        position: 0,
                    });
                    let before = ir.clone();
                    narrow_parameter_loads(&mut ir);
                    proofs.function(
                        format!("masked parameter/{isa:?}/{bits}/{shift}"),
                        &before,
                        &ir,
                    );
                }
            }
        }
        proofs.check();
    }
}

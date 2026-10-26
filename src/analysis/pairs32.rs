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
    for (position, ((name, _), (location, wide))) in parameters.iter().zip(locations).enumerate() {
        let name = name.clone().unwrap_or_else(|| format!("a{position}"));
        let ty = params[position].clone();
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
}

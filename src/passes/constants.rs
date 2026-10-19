//! Constant propagation across blocks: a read that only one definition
//! reaches, and that definition a constant, reads the constant.

use std::collections::{HashMap, HashSet};

use crate::ir::visit::{replace_reads, statement_registers};
use crate::ir::{Expr, FunctionIr, Stmt};
use crate::passes::webs::{Def, has_unknown_successors, reaching_definitions};

pub fn propagate_constants(ir: &mut FunctionIr) {
    if has_unknown_successors(ir) {
        return;
    }
    let constants: HashMap<(usize, usize), (u16, u64)> = ir
        .blocks
        .iter()
        .enumerate()
        .flat_map(|(block, contents)| {
            contents
                .stmts
                .iter()
                .enumerate()
                .filter_map(move |(position, stmt)| match stmt {
                    Stmt::Assign {
                        dest,
                        value: Expr::Const(value),
                    } => Some(((block, position), (dest.index, *value))),
                    _ => None,
                })
        })
        .collect();
    let registers: HashSet<u16> = constants.values().map(|(register, _)| *register).collect();
    let mut substitutions: Vec<((usize, usize), u16, u64)> = Vec::new();
    for register in registers {
        let Some(reaching) = reaching_definitions(ir, register) else {
            continue;
        };
        for (block, contents) in ir.blocks.iter().enumerate() {
            let mut current = reaching[block].clone();
            for (position, stmt) in contents.stmts.iter().enumerate() {
                let (writes, reads) = statement_registers(stmt);
                if reads.contains(&register)
                    && let [Def::At(at, offset)] = current.iter().copied().collect::<Vec<_>>()[..]
                    && let Some((_, value)) = constants.get(&(at, offset))
                    && (*value <= u64::from(u32::MAX) || !reads_narrow(stmt, register))
                {
                    substitutions.push(((block, position), register, *value));
                }
                if writes.contains(&register) {
                    current = HashSet::from([Def::At(block, position)]);
                }
            }
        }
    }
    for ((block, position), register, value) in substitutions {
        replace_reads(
            &mut ir.blocks[block].stmts[position],
            &[(register, Expr::Const(value))],
        );
    }
}

/// Whether the statement reads `register` at less than its full width,
/// which a wide constant would not fit.
fn reads_narrow(stmt: &Stmt, register: u16) -> bool {
    fn narrow(expr: &Expr, register: u16) -> bool {
        match expr {
            Expr::Reg { index, width } => *index == register && *width < 64,
            _ => crate::ir::visit::children(expr)
                .into_iter()
                .any(|child| narrow(child, register)),
        }
    }
    match stmt {
        Stmt::Assign { value, .. } | Stmt::Ret { value } => narrow(value, register),
        Stmt::Store { addr, value, .. } => narrow(addr, register) || narrow(value, register),
        Stmt::Brif { lhs, rhs, .. } => narrow(lhs, register) || narrow(rhs, register),
        Stmt::BrIndirect { target } => narrow(target, register),
        Stmt::Switch { index, .. } => narrow(index, register),
        Stmt::Call {
            through: Some(through),
            ..
        } => narrow(through, register),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::propagate_constants;
    use crate::ir::{BinOp, Block, Cond, Expr, FunctionIr, RegRef, Stmt};
    use crate::loader::Isa;

    #[test]
    fn a_constant_set_before_a_loop_reaches_the_loop() {
        let base = Expr::reg(9, 64);
        let mut ir = FunctionIr::single_block(Isa::AArch64, Vec::new());
        ir.blocks = vec![
            Block {
                start: 0,
                stmts: vec![Stmt::Assign {
                    dest: RegRef {
                        index: 9,
                        width: 64,
                    },
                    value: Expr::Const(0x100),
                }],
            },
            Block {
                start: 0x10,
                stmts: vec![
                    Stmt::Store {
                        addr: Expr::bin(BinOp::Add, base, Expr::Const(4)),
                        value: Expr::reg(8, 64),
                        width: 4,
                    },
                    Stmt::Brif {
                        cond: Cond::Ne,
                        lhs: Expr::reg(8, 64),
                        rhs: Expr::Const(0),
                        target: 0x10,
                    },
                ],
            },
            Block {
                start: 0x20,
                stmts: vec![Stmt::Ret {
                    value: Expr::reg(0, 64),
                }],
            },
        ];
        propagate_constants(&mut ir);
        assert!(
            matches!(
                &ir.blocks[1].stmts[0],
                Stmt::Store {
                    addr: Expr::Const(0x104),
                    ..
                }
            ),
            "{}",
            ir.render()
        );
    }
}

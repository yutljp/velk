//! Variadic functions. Under SysV and AArch64 a function taking further
//! arguments saves, on entry, every argument register past its named
//! parameters to a block of its frame, and the floating-point ones too
//! (SysV only when al says a vector register holds an argument), where
//! the code `va_arg` expands to finds them. Those registers are no
//! parameters, and the pseudo-C reads `...` for them instead of their saves.

use std::collections::HashSet;

use crate::ir::{BinOp, Cond, Convention, Expr, FunctionIr, Stmt};

/// Where a function saves the argument registers it does not name.
pub(crate) struct RegisterSaves {
    /// The integer argument registers past the named ones.
    pub unnamed: Vec<u16>,
    /// The statements saving them and the floating-point ones, by block and
    /// position.
    pub stores: Vec<(usize, usize)>,
    /// SysV's branch around the floating-point saves when al is zero, at
    /// the end of the entry block.
    pub guard: bool,
}

/// The register saves of a variadic function's entry, when it has them.
pub(crate) fn register_saves(ir: &FunctionIr) -> Option<RegisterSaves> {
    if !matches!(ir.convention, Convention::SysV | Convention::Aapcs64) || ir.blocks.is_empty() {
        return None;
    }
    let sp = crate::arch::stack_pointer(ir.isa);
    let index = |start: u64| ir.blocks.iter().position(|block| block.start == start);
    // SysV skips the floating-point saves, which come next, when al is zero.
    let guard = match ir.blocks[0].stmts.last() {
        Some(Stmt::Brif {
            cond: Cond::Eq,
            lhs:
                Expr::Bin {
                    op: BinOp::And,
                    lhs,
                    rhs,
                },
            rhs: Expr::Const(0),
            target,
        }) if ir.convention == Convention::SysV
            && matches!(
                lhs.as_ref(),
                Expr::Reg {
                    index: crate::arch::RETURN,
                    ..
                }
            )
            && matches!(rhs.as_ref(), Expr::Const(0xff)) =>
        {
            Some(index(*target)?)
        }
        _ => None,
    };
    if ir.convention == Convention::SysV && guard.is_none() {
        return None;
    }
    // The blocks the saves are in, entered one after another: the entry
    // block, then SysV's floating-point saves and the block both ways
    // through them reach.
    let floats_block = if guard.is_some() { 1 } else { 0 };
    let blocks: Vec<usize> = match guard {
        Some(join) if join == 2 => vec![0, 1, 2],
        Some(_) => return None,
        None => vec![0],
    };
    let mut stores: Vec<(usize, usize)> = Vec::new();
    // Each register saved before anything writes it, with the offset.
    let mut saved: Vec<(u16, u64)> = Vec::new();
    let mut written: HashSet<u16> = HashSet::new();
    for &block in &blocks {
        for (position, stmt) in ir.blocks[block].stmts.iter().enumerate() {
            if let Stmt::Store {
                addr,
                value: Expr::Reg { index, width: 64 },
                width: 8,
            } = stmt
                && let Some(offset) = slot(addr, sp)
                && !written.contains(index)
            {
                saved.push((*index, offset));
                stores.push((block, position));
            }
            written.extend(crate::ir::visit::statement_registers(stmt).0);
        }
    }
    let offset_of = |register: u16| {
        saved
            .iter()
            .find(|(saved, _)| *saved == register)
            .map(|(_, offset)| *offset)
    };
    // The integer registers past the named ones, each 8 bytes past the one
    // before, up to the last.
    let arguments = ir.convention.arguments();
    let first = arguments
        .iter()
        .position(|register| offset_of(*register).is_some())?;
    if first == 0 {
        return None;
    }
    let base = offset_of(arguments[first])?;
    for (position, register) in arguments.iter().enumerate().skip(first) {
        if offset_of(*register)? != base.wrapping_add(8 * (position - first) as u64) {
            return None;
        }
    }
    // Every floating-point argument register, both halves, 16 bytes apart.
    let floats = ir.convention.float_arguments();
    let float_base = offset_of(floats[0])?;
    for (position, register) in floats.iter().enumerate() {
        let low = float_base.wrapping_add(16 * position as u64);
        if offset_of(*register)? != low || offset_of(register + 1)? != low.wrapping_add(8) {
            return None;
        }
    }
    let unnamed: Vec<u16> = arguments[first..].to_vec();
    let mut keep: HashSet<u16> = unnamed.iter().copied().collect();
    for register in floats {
        keep.insert(*register);
        keep.insert(register + 1);
    }
    stores.retain(|(block, position)| {
        matches!(&ir.blocks[*block].stmts[*position],
            Stmt::Store { value: Expr::Reg { index, .. }, .. } if keep.contains(index))
    });
    // SysV's floating-point block holds nothing but their saves.
    if guard.is_some()
        && stores
            .iter()
            .filter(|(block, _)| *block == floats_block)
            .count()
            != ir.blocks[floats_block].stmts.len()
    {
        return None;
    }
    // The unnamed registers are read nowhere else: they hold no parameter.
    let reads_elsewhere = ir.blocks.iter().enumerate().any(|(block, contents)| {
        contents.stmts.iter().enumerate().any(|(position, stmt)| {
            !stores.contains(&(block, position))
                && stmt.operands().into_iter().any(|operand| {
                    let mut read = HashSet::new();
                    crate::ir::visit::collect_reads(operand, &mut read);
                    unnamed.iter().any(|register| read.contains(register))
                })
        })
    });
    if reads_elsewhere {
        return None;
    }
    Some(RegisterSaves {
        unnamed,
        stores,
        guard: guard.is_some(),
    })
}

/// The offset from the stack pointer an address names.
fn slot(addr: &Expr, sp: u16) -> Option<u64> {
    match addr {
        Expr::Reg { index, .. } if *index == sp => Some(0),
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Reg { index, .. }, Expr::Const(offset)) if *index == sp => Some(*offset),
            _ => None,
        },
        _ => None,
    }
}

/// Takes the argument registers a variadic function saves for its further
/// arguments out of its parameters.
pub(crate) fn mark_variadic(ir: &mut FunctionIr) {
    let Some(saves) = register_saves(ir) else {
        return;
    };
    ir.params
        .retain(|param| !saves.unnamed.contains(&param.index));
    ir.accesses
        .retain(|access| !saves.unnamed.contains(&access.register));
    ir.variadic = true;
}

/// Leaves out the saves of a variadic function's further arguments, and
/// SysV's test of al around them, which the `...` of its declaration stands
/// for.
pub(crate) fn drop_register_saves(ir: &mut FunctionIr) {
    if !ir.variadic {
        return;
    }
    let Some(saves) = register_saves(ir) else {
        return;
    };
    for (block, position) in saves.stores.iter().rev() {
        ir.blocks[*block].stmts.remove(*position);
    }
    if saves.guard {
        ir.blocks[0].stmts.pop();
    }
}

#[cfg(test)]
mod tests {
    use crate::ir::{BinOp, CType, Expr, FunctionIr, Param, Stmt};
    use crate::loader::Isa;

    /// An AArch64 entry saving x`from`..x7 and every vector argument register.
    fn saving_from(from: u16) -> FunctionIr {
        let sp = crate::arch::stack_pointer(Isa::AArch64);
        let store = |register: u16, offset: i64| Stmt::Store {
            addr: Expr::bin(BinOp::Add, Expr::reg(sp, 64), Expr::Const(offset as u64)),
            value: Expr::reg(register, 64),
            width: 8,
        };
        let mut stmts: Vec<Stmt> = (from..8)
            .map(|register| store(register, -0x40 + 8 * i64::from(register)))
            .collect();
        for (position, register) in (32u16..48).step_by(2).enumerate() {
            stmts.push(store(register, -0xc0 + 16 * position as i64));
            stmts.push(store(register + 1, -0xb8 + 16 * position as i64));
        }
        stmts.push(Stmt::Ret {
            value: Expr::reg(0, 64),
        });
        let mut ir = FunctionIr::single_block(Isa::AArch64, stmts);
        ir.params = (0..8)
            .map(|index| Param {
                index,
                name: format!("a{index}"),
                ty: CType::I64,
            })
            .collect();
        ir
    }

    #[test]
    fn the_saved_registers_past_the_named_ones_are_the_further_arguments() {
        let mut ir = saving_from(1);
        super::mark_variadic(&mut ir);
        assert!(ir.variadic);
        assert_eq!(ir.params.len(), 1);
        super::drop_register_saves(&mut ir);
        assert_eq!(ir.blocks[0].stmts.len(), 1);
        // Saving every argument register is an unoptimized function's spill
        // of its parameters.
        let mut ir = saving_from(0);
        super::mark_variadic(&mut ir);
        assert!(!ir.variadic);
        assert_eq!(ir.params.len(), 8);
    }
}

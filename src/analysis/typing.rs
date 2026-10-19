use crate::arch;
use crate::ir::{CType, FunctionIr};
use crate::loader::Image;

pub(crate) fn apply_width_types(ir: &mut FunctionIr, uniform_32: &std::collections::HashSet<u16>) {
    // A register only ever written, or only ever read, at 32 bits holds a 32-bit value.
    let narrow = |ir: &FunctionIr, index: u16| -> bool {
        uniform_32.contains(&index) || narrow_only(ir, index)
    };
    // The return type is re-decided from the optimized body, whose passes may
    // have removed or exposed the 32-bit writes the earlier guess relied on.
    let ret_is_wide = returns_wide(ir);
    let narrow_return = !ret_is_wide && ir.ret_type == CType::U64;
    let widen_return = ret_is_wide && ir.ret_type.is_32_bit_int();
    let decided: Vec<bool> = ir
        .params
        .iter()
        .map(|param| narrow(ir, param.index) && !param.ty.is_pointer() && param.ty != CType::I32)
        .collect();
    let signed: Vec<bool> = ir
        .params
        .iter()
        .map(|param| ir.signed_params.contains(&param.index) && !param.ty.is_pointer())
        .collect();
    for ((param, narrow), signed) in ir
        .params
        .iter_mut()
        .zip(decided.iter().copied())
        .zip(signed.iter().copied())
    {
        if signed {
            // Signedness comes from the comparison, width from the body.
            if param.ty == CType::U32 || (param.ty == CType::U64 && narrow) {
                param.ty = CType::I32;
            } else if param.ty == CType::U64 {
                param.ty = CType::I64;
            }
        } else if narrow {
            param.ty = CType::U32;
        }
    }
    // Heuristic: if any parameter is compared as signed, a narrowed return is signed too.
    let signed_ret = !ir.signed_params.is_empty();
    if narrow_return {
        ir.ret_type = if signed_ret { CType::I32 } else { CType::U32 };
    }
    if widen_return {
        ir.ret_type = if ir.ret_type == CType::I32 {
            CType::I64
        } else {
            CType::U64
        };
    }
}

/// The last value assigned to a register anywhere in the body.
fn last_definition(ir: &FunctionIr, index: u16) -> Option<crate::ir::Expr> {
    let mut found = None;
    for block in &ir.blocks {
        for stmt in &block.stmts {
            if let crate::ir::Stmt::Assign { dest, value } = stmt
                && dest.index == index
            {
                found = Some(value.clone());
            }
        }
    }
    found
}

/// True when the function's last return moves a value whose 64-bit inputs
/// are not explained by any narrow use.
fn returns_wide(ir: &FunctionIr) -> bool {
    let Some(value) = crate::ir::cfg::own_return(&ir.blocks) else {
        return false;
    };
    // Look through a wide register read to its last definition: a 32-bit
    // division is not wide just because it lands in a 64-bit register.
    let mut resolved = value.clone();
    if let crate::ir::Expr::Reg { index, width } = value
        && *width > 32
        && let Some(definition) = last_definition(ir, *index)
    {
        resolved = definition;
    }
    let mut wide: Vec<u16> = Vec::new();
    collect_wide_regs(&resolved, false, &mut wide);
    wide.iter()
        .any(|index| *index == WIDE_VALUE || !narrow_only(ir, *index))
}

/// A value that is wide on its own, without naming a register (an 8-byte
/// load, or a sign extension to 64 bits).
const WIDE_VALUE: u16 = u16::MAX;

fn collect_wide_regs(expr: &crate::ir::Expr, narrow: bool, wide: &mut Vec<u16>) {
    use crate::ir::Expr;
    match expr {
        Expr::Reg { index, width } => {
            if !narrow && *width > 32 {
                wide.push(*index);
            }
        }
        Expr::Const(_) => {}
        Expr::Bin { op, lhs, rhs } => {
            if matches!(op, crate::ir::BinOp::And)
                && matches!(rhs.as_ref(), Expr::Const(0xffff_ffff))
            {
                collect_wide_regs(lhs, true, wide);
                return;
            }
            // A division or remainder is as wide as its dividend.
            if matches!(
                op,
                crate::ir::BinOp::DivS
                    | crate::ir::BinOp::DivU
                    | crate::ir::BinOp::ModS
                    | crate::ir::BinOp::ModU
            ) {
                let dividend_narrow = matches!(
                    lhs.as_ref(),
                    Expr::SignExtend { width, .. } if *width <= 4
                ) || matches!(
                    lhs.as_ref(),
                    Expr::Bin { op: crate::ir::BinOp::And, rhs, .. }
                        if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff))
                );
                collect_wide_regs(lhs, narrow || dividend_narrow, wide);
                return;
            }
            collect_wide_regs(lhs, narrow, wide);
            collect_wide_regs(rhs, narrow, wide);
        }
        // The address width says nothing about the loaded value's width.
        Expr::Load { width, .. } => {
            if *width > 4 {
                wide.push(WIDE_VALUE);
            }
        }
        // The extension fills all 64 bits unless a mask narrows it again.
        Expr::SignExtend { value, .. } => {
            if !narrow {
                wide.push(WIDE_VALUE);
            }
            collect_wide_regs(value, true, wide);
        }
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => {
            collect_wide_regs(lhs, narrow, wide);
            collect_wide_regs(rhs, narrow, wide);
            collect_wide_regs(then, narrow, wide);
            collect_wide_regs(els, narrow, wide);
        }
    }
}

/// True when the register carries a 32-bit value: every write to it is
/// narrow, or — when nothing writes it — every read is a 32-bit view.
fn narrow_only(ir: &FunctionIr, register: u16) -> bool {
    let mut writes = false;
    let mut wide_write = false;
    let mut reads_narrow = true;
    let mut seen = false;
    for block in &ir.blocks {
        // A tail call's return reads the callee's result, not this register's value.
        let tail_call = matches!(
            block.stmts.as_slice(),
            [
                ..,
                crate::ir::Stmt::Call { .. },
                crate::ir::Stmt::Ret { .. }
            ]
        );
        let own = block.stmts.len() - usize::from(tail_call);
        for stmt in &block.stmts[..own] {
            collect_uses(
                stmt,
                register,
                &mut writes,
                &mut wide_write,
                &mut reads_narrow,
                &mut seen,
            );
        }
    }
    if !seen {
        return false;
    }
    if writes { !wide_write } else { reads_narrow }
}

fn collect_uses(
    stmt: &crate::ir::Stmt,
    register: u16,
    writes: &mut bool,
    wide_write: &mut bool,
    reads_narrow: &mut bool,
    seen: &mut bool,
) {
    use crate::ir::Stmt;
    match stmt {
        Stmt::Assign { dest, value } => {
            if dest.index == register {
                *writes = true;
                *seen = true;
                if dest.width > 32 && !masked_wide(value, register) {
                    *wide_write = true;
                }
            }
            // A 64-bit read feeding a 32-bit result uses only its low half.
            scan_reads(value, register, dest.width <= 32, reads_narrow, seen);
        }
        Stmt::Store { addr, value, width } => {
            scan_reads(addr, register, false, reads_narrow, seen);
            scan_reads(value, register, *width <= 4, reads_narrow, seen);
        }
        Stmt::Brif { lhs, rhs, .. } => {
            scan_reads(lhs, register, false, reads_narrow, seen);
            scan_reads(rhs, register, false, reads_narrow, seen);
        }
        Stmt::Ret { value } => scan_reads(value, register, false, reads_narrow, seen),
        Stmt::BrIndirect { target } => scan_reads(target, register, false, reads_narrow, seen),
        Stmt::Switch { index, .. } => scan_reads(index, register, false, reads_narrow, seen),
        _ => {}
    }
}

pub(crate) fn scan_reads(
    expr: &crate::ir::Expr,
    register: u16,
    narrow: bool,
    reads_narrow: &mut bool,
    seen: &mut bool,
) {
    use crate::ir::Expr;
    match expr {
        Expr::Reg { index, width } => {
            if *index != register {
                return;
            }
            *seen = true;
            if !narrow && *width > 32 {
                *reads_narrow = false;
            }
        }
        Expr::Const(_) => {}
        Expr::Bin { op, lhs, rhs } => {
            // Everything under `& 0xffffffff` reads at 32-bit width.
            if matches!(op, crate::ir::BinOp::And)
                && matches!(rhs.as_ref(), Expr::Const(0xffff_ffff))
            {
                scan_reads(lhs, register, true, reads_narrow, seen);
                return;
            }
            scan_reads(lhs, register, narrow, reads_narrow, seen);
            scan_reads(rhs, register, narrow, reads_narrow, seen);
        }
        Expr::Load { addr, .. } => scan_reads(addr, register, narrow, reads_narrow, seen),
        Expr::SignExtend { value, .. } => scan_reads(value, register, narrow, reads_narrow, seen),
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => {
            scan_reads(lhs, register, narrow, reads_narrow, seen);
            scan_reads(rhs, register, narrow, reads_narrow, seen);
            scan_reads(then, register, narrow, reads_narrow, seen);
            scan_reads(els, register, narrow, reads_narrow, seen);
        }
    }
}

/// True when a wide write is masked to 32 bits or provably fits in them.
fn masked_wide(value: &crate::ir::Expr, _register: u16) -> bool {
    use crate::ir::Expr;
    if matches!(
        value,
        Expr::Bin { op: crate::ir::BinOp::And, rhs, .. }
            if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff))
    ) {
        return true;
    }
    fits32(value)
}

fn fits32(value: &crate::ir::Expr) -> bool {
    use crate::ir::Expr;
    match value {
        Expr::Const(number) => (*number >> 32) == 0,
        Expr::Reg { width, .. } => u32::from(*width) <= 32,
        Expr::Load { width, .. } => u32::from(*width) * 8 <= 32,
        Expr::Bin { op, lhs, rhs } => match op {
            crate::ir::BinOp::And | crate::ir::BinOp::Or | crate::ir::BinOp::Xor => {
                fits32(lhs) && fits32(rhs)
            }
            // A quotient and a remainder are bounded by their operands, and
            // a right shift only ever loses bits.
            crate::ir::BinOp::DivS
            | crate::ir::BinOp::DivU
            | crate::ir::BinOp::ModS
            | crate::ir::BinOp::ModU
            | crate::ir::BinOp::Shr
            | crate::ir::BinOp::Sar => fits32(lhs) && fits32(rhs),
            _ => false,
        },
        Expr::Select { then, els, .. } => fits32(then) && fits32(els),
        Expr::SignExtend { .. } => false,
    }
}

fn reads_register(expr: &crate::ir::Expr, register: u16) -> bool {
    use crate::ir::Expr;
    match expr {
        Expr::Reg { index, .. } => *index == register,
        Expr::Const(_) => false,
        Expr::Bin { lhs, rhs, .. } => {
            reads_register(lhs, register) || reads_register(rhs, register)
        }
        Expr::Load { addr, .. } => reads_register(addr, register),
        Expr::SignExtend { value, .. } => reads_register(value, register),
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => {
            reads_register(lhs, register)
                || reads_register(rhs, register)
                || reads_register(then, register)
                || reads_register(els, register)
        }
    }
}

/// Marks the function void when the return register is never written, the body
/// has a side effect, and the register is used only by a bare return. Requiring
/// a side effect keeps `int id(int x)` from being mistaken for a void function
/// where the return register also carries the first argument; elsewhere a
/// return register nothing writes holds no result.
pub(crate) fn apply_void_return(ir: &mut FunctionIr) {
    use crate::ir::{Expr, Stmt};
    let mut written = false;
    let mut side_effect = false;
    let mut used_elsewhere = false;
    let mut saw_ret = false;
    for block in &ir.blocks {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Assign { dest, value } => {
                    if dest.index == arch::RETURN {
                        written = true;
                    }
                    used_elsewhere |= reads_register(value, arch::RETURN);
                }
                Stmt::Store { addr, value, .. } => {
                    side_effect = true;
                    used_elsewhere |= reads_register(addr, arch::RETURN);
                    used_elsewhere |= reads_register(value, arch::RETURN);
                }
                Stmt::Call { .. } => side_effect = true,
                Stmt::Ret { value } => {
                    saw_ret = true;
                    // Only a bare return of the register is allowed; returning
                    // anything else, a value folded into the return included,
                    // means the function produces a value.
                    used_elsewhere |=
                        !matches!(value, Expr::Reg { index, .. } if *index == arch::RETURN);
                }
                Stmt::Brif { lhs, rhs, .. } => {
                    used_elsewhere |= reads_register(lhs, arch::RETURN);
                    used_elsewhere |= reads_register(rhs, arch::RETURN);
                }
                Stmt::BrifFlags { .. } | Stmt::Br { .. } | Stmt::Trap => {}
                Stmt::BrIndirect { target } => {
                    used_elsewhere |= reads_register(target, arch::RETURN)
                }
                Stmt::Switch { index, .. } => used_elsewhere |= reads_register(index, arch::RETURN),
                // An unsupported instruction may write the return register.
                Stmt::Unsupported { .. } => return,
            }
        }
    }
    let carries_argument = ir.convention.arguments().contains(&arch::RETURN);
    if !saw_ret || written || (carries_argument && !side_effect) || used_elsewhere {
        return;
    }
    ir.ret_type = CType::Void;
    ir.params.retain(|param| param.index != arch::RETURN);
}

pub(crate) fn apply_dwarf_types(image: &Image, addr: u64, ir: &mut FunctionIr) {
    let Some(types) = crate::loader::dwarf::function_types(image, addr) else {
        return;
    };
    ir.members = types.members;
    if !types.params.is_empty() {
        // Debug info only renames and retypes the recovered parameters; it
        // never adds or drops any.
        let mut params = ir.params.clone();
        for (index, (name, ty)) in types.params.iter().enumerate() {
            let Some(param) = params.get_mut(index) else {
                break;
            };
            if let Some(name) = name {
                param.name = name.clone();
            }
            if let Some(ty) = ty {
                param.ty = ty.clone();
            }
        }
        ir.params = params;
    }
    if let Some(ret) = types.ret {
        ir.ret_type = ret;
    }
}

#[cfg(test)]
mod tests {
    use super::apply_void_return;
    use crate::ir::{CType, Expr, FunctionIr, Stmt};
    use crate::loader::Isa;

    fn returns_register(isa: Isa) -> CType {
        let mut ir = FunctionIr::single_block(
            isa,
            vec![Stmt::Ret {
                value: Expr::reg(0, 64),
            }],
        );
        apply_void_return(&mut ir);
        ir.ret_type
    }

    #[test]
    fn a_return_register_nothing_writes_holds_no_result() {
        assert_eq!(returns_register(Isa::X86_64), CType::Void);
    }

    #[test]
    fn a_return_register_that_carries_the_first_argument_may_return_it() {
        // AArch64 `int id(int x) { return x; }` is a bare `ret`.
        assert_ne!(returns_register(Isa::AArch64), CType::Void);
    }
}

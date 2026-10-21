use crate::arch;
use crate::ir::{CType, FunctionIr, Param};

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
    let evidence = SignEvidence::of(ir);
    // Without an unsigned operation on it, an integer is most likely signed,
    // as C's `int` and `long` are.
    let signed: Vec<bool> = ir
        .params
        .iter()
        .map(|param| {
            !param.ty.is_pointer()
                && (ir.signed_params.contains(&param.index)
                    || evidence.signed.contains(&param.index)
                    || !evidence.unsigned.contains(&param.index))
        })
        .collect();
    for ((param, narrow), signed) in ir
        .params
        .iter_mut()
        .zip(decided.iter().copied())
        .zip(signed.iter().copied())
    {
        // A type a prototype names is settled.
        if matches!(param.ty, CType::Named(_)) {
            continue;
        }
        if signed {
            // Signedness comes from the operations, width from the body.
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
    // As for the parameters, a returned integer no unsigned operation
    // computes is most likely signed.
    let mut returned = SignEvidence::default();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        if let crate::ir::Stmt::Ret { value } = stmt {
            returned.walk(value);
        }
    }
    if !returned.any_unsigned {
        if ir.ret_type == CType::U32 {
            ir.ret_type = CType::I32;
        } else if ir.ret_type == CType::U64 {
            ir.ret_type = CType::I64;
        }
    }
}

/// The registers signed operations read, and those unsigned ones read:
/// comparisons, divisions and right shifts.
#[derive(Default)]
pub(crate) struct SignEvidence {
    pub(crate) signed: std::collections::HashSet<u16>,
    pub(crate) unsigned: std::collections::HashSet<u16>,
    /// How many signed and unsigned operations read each register.
    pub(crate) counts: std::collections::HashMap<u16, (usize, usize)>,
    /// Some unsigned operation was seen, whatever it read.
    any_unsigned: bool,
}

impl SignEvidence {
    pub(crate) fn of(ir: &FunctionIr) -> Self {
        use crate::ir::Stmt;
        let mut evidence = Self::default();
        for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
            match stmt {
                Stmt::Assign { value, .. } | Stmt::Ret { value } => evidence.walk(value),
                Stmt::Store { addr, value, .. } => {
                    evidence.walk(addr);
                    evidence.walk(value);
                }
                Stmt::Brif { cond, lhs, rhs, .. } => {
                    evidence.compare(*cond, lhs, rhs);
                    evidence.walk(lhs);
                    evidence.walk(rhs);
                }
                Stmt::Switch { index, .. } => evidence.walk(index),
                Stmt::Call { .. } => {
                    for value in stmt.operands() {
                        evidence.walk(value);
                    }
                }
                _ => {}
            }
        }
        evidence
    }

    fn note(&mut self, signed: bool, operands: &[&crate::ir::Expr]) {
        let mut read = std::collections::HashSet::new();
        for operand in operands {
            crate::ir::visit::expr_reads(operand, &mut read);
        }
        for index in &read {
            let (signed_reads, unsigned_reads) = self.counts.entry(*index).or_default();
            if signed {
                *signed_reads += 1;
            } else {
                *unsigned_reads += 1;
            }
        }
        if signed {
            self.signed.extend(read);
        } else {
            self.any_unsigned = true;
            self.unsigned.extend(read);
        }
    }

    /// Whether the register reads as signed: no more unsigned operations
    /// read it than signed ones.
    pub(crate) fn mostly_signed(&self, index: u16) -> bool {
        self.counts
            .get(&index)
            .is_none_or(|(signed, unsigned)| signed >= unsigned)
    }

    fn compare(&mut self, cond: crate::ir::Cond, lhs: &crate::ir::Expr, rhs: &crate::ir::Expr) {
        use crate::ir::Cond;
        match cond {
            Cond::Lt | Cond::Le | Cond::Gt | Cond::Ge => self.note(true, &[lhs, rhs]),
            Cond::Cc | Cond::Cs | Cond::Hi | Cond::Ls => self.note(false, &[lhs, rhs]),
            _ => {}
        }
    }

    fn walk(&mut self, expr: &crate::ir::Expr) {
        use crate::ir::{BinOp, Expr};
        match expr {
            Expr::Bin { op, lhs, rhs } => match op {
                BinOp::DivS | BinOp::ModS => self.note(true, &[lhs, rhs]),
                BinOp::DivU | BinOp::ModU => self.note(false, &[lhs, rhs]),
                BinOp::Sar => self.note(true, &[lhs]),
                // Shifting the top bit down tests the sign.
                BinOp::Shr if matches!(rhs.as_ref(), Expr::Const(31 | 63)) => {
                    self.note(true, &[lhs])
                }
                BinOp::Shr => self.note(false, &[lhs]),
                _ => {}
            },
            Expr::SignExtend { value, .. } => self.note(true, &[value]),
            Expr::Select { cond, lhs, rhs, .. } => self.compare(*cond, lhs, rhs),
            _ => {}
        }
        for child in crate::ir::visit::children(expr) {
            self.walk(child);
        }
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
                && matches!(rhs.as_ref(), Expr::Const(mask) if *mask <= 0xffff_ffff)
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
        // An operation's result is as wide as it says, whatever it reads.
        Expr::Apply { .. } => {
            if !narrow && crate::ir::semantics::width(expr) > 32 {
                wide.push(WIDE_VALUE);
            }
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
        // A register passed whole takes the width the callee gives it.
        Stmt::Call { .. } => {
            for value in stmt.operands() {
                if !matches!(value, crate::ir::Expr::Reg { .. }) {
                    scan_reads(value, register, false, reads_narrow, seen);
                }
            }
        }
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
            // Everything under a mask within 32 bits reads at most 32 bits.
            if matches!(op, crate::ir::BinOp::And)
                && matches!(rhs.as_ref(), Expr::Const(mask) if *mask <= 0xffff_ffff)
            {
                scan_reads(lhs, register, true, reads_narrow, seen);
                return;
            }
            scan_reads(lhs, register, narrow, reads_narrow, seen);
            scan_reads(rhs, register, narrow, reads_narrow, seen);
        }
        Expr::Load { addr, .. } => scan_reads(addr, register, narrow, reads_narrow, seen),
        // An extension reads only its value's low bytes.
        Expr::SignExtend { value, .. } => scan_reads(value, register, true, reads_narrow, seen),
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
        // An operation reads the bits it names, whatever masks its result.
        Expr::Apply { op, args } => {
            let narrow = crate::ir::semantics::argument_bits(*op) <= 32;
            for arg in args {
                scan_reads(arg, register, narrow, reads_narrow, seen);
            }
        }
    }
}

/// True when a wide write is masked within 32 bits or provably fits in them.
fn masked_wide(value: &crate::ir::Expr, _register: u16) -> bool {
    use crate::ir::Expr;
    if matches!(
        value,
        Expr::Bin { op: crate::ir::BinOp::And, rhs, .. }
            if matches!(rhs.as_ref(), Expr::Const(mask) if *mask <= 0xffff_ffff)
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
        Expr::Apply { .. } => crate::ir::semantics::width(value) <= 32,
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
        Expr::Apply { args, .. } => args.iter().any(|arg| reads_register(arg, register)),
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

/// A function whose every return writes only the low byte or half-word of
/// the register it returns (`sete al; ret`, or `mov r15b, 1` then
/// `mov eax, r15d`) returns that narrow value: the convention leaves the
/// rest of the return register undefined for the caller.
pub(crate) fn apply_partial_return(ir: &mut FunctionIr) {
    use crate::ir::{BinOp, Expr, Stmt};
    // The new bits and their width in bytes, for `(r & keep) | value`, the
    // rest being the register's earlier value.
    let partial = |value: &Expr| -> Option<(Expr, u8)> {
        let Expr::Bin {
            op: BinOp::Or,
            lhs,
            rhs,
        } = value
        else {
            return None;
        };
        let Expr::Bin {
            op: BinOp::And,
            lhs: kept,
            rhs: keep,
        } = lhs.as_ref()
        else {
            return None;
        };
        if !matches!(kept.as_ref(), Expr::Reg { .. }) {
            return None;
        }
        let bytes = match keep.as_ref() {
            Expr::Const(0xffff_ffff_ffff_ff00) => 1,
            Expr::Const(0xffff_ffff_ffff_0000) => 2,
            _ => return None,
        };
        Some((rhs.as_ref().clone(), bytes))
    };
    // The register a return reads, whole or through a mask of its low bits.
    let returned = |value: &Expr| -> Option<(u16, u64)> {
        match value {
            Expr::Reg { index, .. } => Some((*index, u64::MAX)),
            Expr::Bin {
                op: BinOp::And,
                lhs,
                rhs,
            } => match (lhs.as_ref(), rhs.as_ref()) {
                (Expr::Reg { index, .. }, Expr::Const(mask)) => Some((*index, *mask)),
                _ => None,
            },
            _ => None,
        }
    };
    // A tail call returns its callee's value, whatever its width.
    let tail_call = |stmts: &[Stmt]| matches!(stmts, [.., Stmt::Call { .. }, Stmt::Ret { .. }]);
    let Some(ssa) = crate::ssa::build(ir) else {
        return;
    };
    let definitions: std::collections::HashMap<u16, &Expr> = ssa
        .ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .filter_map(|stmt| match stmt {
            Stmt::Assign { dest, value } => Some((dest.index, value)),
            _ => None,
        })
        .collect();
    let phis: std::collections::HashMap<u16, &[u16]> = ssa
        .phis
        .iter()
        .flatten()
        .map(|phi| (phi.value, phi.args.as_slice()))
        .collect();
    let mut width = None;
    for block in &ssa.ir.blocks {
        if tail_call(&block.stmts) {
            continue;
        }
        let Some(Stmt::Ret { value }) = block.stmts.last() else {
            continue;
        };
        // A register returns what each definition reaching the return puts
        // in it.
        let mut values = Vec::new();
        match returned(value) {
            Some((register, mask)) if crate::ssa::Ssa::is_value(register) && mask >= 0xffff => {
                let mut pending = vec![register];
                let mut seen = std::collections::HashSet::new();
                while let Some(value) = pending.pop() {
                    if !seen.insert(value) {
                        continue;
                    }
                    if let Some(args) = phis.get(&value) {
                        pending.extend(args.iter());
                    } else if let Some(definition) = definitions.get(&value) {
                        // A copy of another register, as `mov eax, r15d`
                        // makes, returns what that one holds.
                        match returned(definition) {
                            Some((copied, mask))
                                if crate::ssa::Ssa::is_value(copied) && mask >= 0xffff =>
                            {
                                pending.push(copied)
                            }
                            _ => values.push(*definition),
                        }
                    } else {
                        return;
                    }
                }
            }
            _ => values.push(value),
        }
        for value in values {
            // A small constant, as `xor eax, eax` makes, fits whatever
            // width the other returns show.
            if matches!(value, Expr::Const(constant) if *constant <= 0xff) {
                continue;
            }
            let Some((_, bytes)) = partial(value) else {
                return;
            };
            if width.is_some_and(|width| width != bytes) {
                return;
            }
            width = Some(bytes);
        }
    }
    let Some(bytes) = width else {
        return;
    };
    let mask = (1u64 << (u32::from(bytes) * 8)) - 1;
    for block in &mut ir.blocks {
        if tail_call(&block.stmts) {
            continue;
        }
        if let Some(Stmt::Ret { value }) = block.stmts.last_mut() {
            if let Some((low, _)) = partial(value) {
                *value = Expr::bin(BinOp::And, low, Expr::Const(mask));
            } else if let Some((register, _)) = returned(value) {
                *value = Expr::bin(BinOp::And, Expr::reg(register, 64), Expr::Const(mask));
            }
        }
    }
    ir.ret_type = CType::int(bytes, false);
}

/// Where each declared parameter lives, as the calling convention places
/// it: in registers (several for a structure up to 16 bytes) or in the
/// caller's frame. The debug info's signature replaces the recovered one,
/// unused parameters included; a parameter the convention does not
/// describe here keeps the recovered placement.
fn place_parameters(types: &crate::loader::dwarf::FunctionTypes, ir: &mut FunctionIr) {
    use crate::ir::{Convention, StackParam};
    let convention = ir.convention;
    if convention == Convention::GoAmd64 {
        return;
    }
    let integers = convention.arguments();
    let floats = convention.float_arguments();
    let recovered: std::collections::HashMap<u16, Param> = ir
        .params
        .iter()
        .map(|param| (param.index, param.clone()))
        .collect();
    let (mut next_int, mut next_float) = (0usize, 0usize);
    let mut stack = match convention {
        Convention::SysV => 8,
        Convention::Win64 => 40,
        Convention::Aapcs64 | Convention::GoAmd64 => 0,
        Convention::SyscallX86 | Convention::SyscallArm | Convention::GoWriteBarrier => return,
        Convention::GoAbi0 => 8,
    };
    let mut params = Vec::new();
    let mut stack_params = Vec::new();
    // A structure returned through memory comes back to the address the
    // caller passes first, ahead of the declared parameters.
    let hidden = types
        .ret_aggregate_size
        .is_some_and(|size| returned_in_memory(convention, size));
    if let (true, Some(ret)) = (hidden, &types.ret) {
        params.push(Param {
            index: integers[0],
            name: "result".to_owned(),
            ty: CType::pointer_to(ret.clone()),
        });
        next_int = 1;
    }
    let round = |size: u64| size.div_ceil(8) * 8;
    for (position, ((name, ty), size)) in types
        .params
        .iter()
        .zip(
            types
                .param_aggregate_sizes
                .iter()
                .chain(std::iter::repeat(&None)),
        )
        .enumerate()
    {
        let float = ty.as_ref().is_some_and(CType::is_sse_float);
        // The parameter's place, counting a leading result pointer.
        let index = position + usize::from(hidden);
        let name = name.clone().unwrap_or_else(|| format!("a{index}"));
        let ty = ty.clone().unwrap_or(CType::U64);
        // The registers a parameter takes, or None for the stack.
        let registers: Option<Vec<u16>> = match convention {
            // Windows passes the first four by position, a structure that
            // is not 1, 2, 4 or 8 bytes by reference.
            Convention::Win64 => (index < 4).then(|| {
                vec![if float {
                    floats[index]
                } else {
                    integers[index]
                }]
            }),
            _ => match size {
                // Larger structures go in memory on System V and by
                // reference on AArch64.
                Some(size) if *size > 16 && convention == Convention::SysV => None,
                Some(size) if *size > 16 => (next_int < integers.len()).then(|| {
                    next_int += 1;
                    vec![integers[next_int - 1]]
                }),
                Some(size) => {
                    let needed = size.div_ceil(8) as usize;
                    (next_int + needed <= integers.len()).then(|| {
                        next_int += needed;
                        integers[next_int - needed..next_int].to_vec()
                    })
                }
                None if float => (next_float < floats.len()).then(|| {
                    next_float += 1;
                    vec![floats[next_float - 1]]
                }),
                None => (next_int < integers.len()).then(|| {
                    next_int += 1;
                    vec![integers[next_int - 1]]
                }),
            },
        };
        match registers {
            Some(registers) => {
                for (part, register) in registers.iter().enumerate() {
                    let ty = if part == 0 { ty.clone() } else { CType::U64 };
                    let name = if part == 0 {
                        name.clone()
                    } else {
                        format!("{name}_{part}")
                    };
                    params.push(Param {
                        index: *register,
                        name,
                        ty,
                    });
                }
            }
            None => {
                let bytes = size.unwrap_or(8);
                stack_params.push(StackParam {
                    offset: stack,
                    size: bytes,
                    name,
                    ty,
                    position: index,
                });
                stack += round(bytes) as i64;
            }
        }
    }
    // Registers the body reads that the declaration does not name keep
    // their recovered parameter, unless the function is variadic, whose
    // further arguments those are.
    if !types.variadic {
        for param in recovered.values() {
            if !params.iter().any(|placed| placed.index == param.index)
                && !integers.contains(&param.index)
                && !floats.contains(&param.index)
            {
                params.push(param.clone());
            }
        }
    }
    ir.params = params;
    ir.stack_params = stack_params;
}

/// Whether a structure of `size` bytes is returned through memory the
/// caller provides, at an address passed as the first argument.
fn returned_in_memory(convention: crate::ir::Convention, size: u64) -> bool {
    use crate::ir::Convention;
    match convention {
        Convention::SysV => size > 16,
        Convention::Win64 => !matches!(size, 1 | 2 | 4 | 8),
        // AArch64 passes that address in x8, which is no argument.
        Convention::Aapcs64
        | Convention::GoAmd64
        | Convention::SyscallX86
        | Convention::SyscallArm
        | Convention::GoWriteBarrier
        | Convention::GoAbi0 => false,
    }
}

pub(crate) fn apply_dwarf_types(
    types: Option<crate::loader::dwarf::FunctionTypes>,
    ir: &mut FunctionIr,
) {
    let Some(types) = types else {
        return;
    };
    ir.members = types.members.clone();
    // Only a declaration whose every parameter has a type the debug info
    // could read replaces the recovered signature; otherwise its names go
    // onto the recovered parameters in order.
    if types.params.iter().all(|(_, ty)| ty.is_some()) {
        ir.variadic = types.variadic;
        if !types.params.is_empty() || types.ret_aggregate_size.is_some() {
            place_parameters(&types, ir);
        }
    } else {
        for (param, (name, ty)) in ir.params.iter_mut().zip(&types.params) {
            if let Some(name) = name {
                param.name = name.clone();
            }
            if let Some(ty) = ty {
                param.ty = ty.clone();
            }
        }
    }
    if let Some(ret) = types.ret {
        ir.ret_type = ret;
    }
}

/// The types the prototypes of the library functions the body calls give
/// the values it passes them and the values they return: the variables
/// that hold them, and the parameters it passes on unchanged where a
/// variadic function's format string takes them.
pub(crate) fn apply_prototypes(ir: &mut FunctionIr, image: &crate::loader::Image) {
    use crate::analysis::prototypes::{called, conversion_types, preferred};
    use crate::ir::{Expr, Stmt};
    // The register a value is, or the low half of.
    let held = |expr: &Expr| match expr {
        Expr::Reg { index, .. } => Some(*index),
        Expr::Bin {
            op: crate::ir::BinOp::And,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) => match lhs.as_ref() {
            Expr::Reg { index, .. } => Some(*index),
            _ => None,
        },
        _ => None,
    };
    let offer = |types: &mut std::collections::BTreeMap<u16, CType>, index: u16, ty: &CType| {
        let ty = match types.remove(&index) {
            Some(first) => preferred(first, ty),
            None => ty.clone(),
        };
        types.insert(index, ty);
    };
    let mut values = std::collections::BTreeMap::new();
    let mut variadic = std::collections::BTreeMap::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        let Stmt::Call {
            args: Some(args),
            result,
            ..
        } = stmt
        else {
            continue;
        };
        let Some(prototype) = called(image, stmt) else {
            continue;
        };
        let mut types: Vec<CType> = prototype.integer_params().cloned().collect();
        let fixed = types.len();
        if let Some(Expr::Const(address)) = prototype.format.and_then(|format| args.get(format))
            && let Some(format) = crate::ssa::c_string(image, *address)
        {
            types.extend(conversion_types(&format, prototype.scans));
        }
        for (position, (arg, ty)) in args.iter().zip(&types).enumerate() {
            let Some(index) = held(arg) else {
                continue;
            };
            if (crate::ir::TEMP_BASE..crate::ir::VALUE_BASE).contains(&index) {
                offer(&mut values, index, ty);
            } else if position >= fixed && ir.params.iter().any(|param| param.index == index) {
                offer(&mut variadic, index, ty);
            }
        }
        if let Some(dest) = result
            && prototype.ret != CType::Void
        {
            offer(&mut values, dest.index, &prototype.ret);
        }
    }
    for param in &mut ir.params {
        if let Some(ty) = variadic.get(&param.index) {
            settle_param(param, ty);
        }
    }
    ir.value_types = values;
}

/// Gives a parameter the type a prototype gives it, unless what the body
/// does with it says more: the elements a pointer's accesses read, rather
/// than `void *`, or that it is a pointer at all.
pub(crate) fn settle_param(param: &mut Param, ty: &CType) {
    let keep = param.ty.is_sse_float()
        || (param.ty.is_pointer()
            && (crate::analysis::prototypes::void_pointer(ty) || !ty.is_pointer()));
    if !keep {
        param.ty = ty.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::{apply_partial_return, apply_void_return, apply_width_types};
    use crate::ir::{BinOp, CType, Expr, FunctionIr, Stmt};
    use crate::loader::Isa;

    /// The type of a 32-bit parameter in rdi whose value is returned through `op`.
    fn parameter_through(op: BinOp) -> CType {
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![Stmt::Ret {
                value: Expr::bin(op, Expr::reg(7, 32), Expr::Const(3)),
            }],
        );
        ir.params = vec![crate::ir::Param {
            index: 7,
            name: "a0".to_owned(),
            ty: CType::U32,
        }];
        apply_width_types(&mut ir, &Default::default());
        ir.params[0].ty.clone()
    }

    #[test]
    fn an_integer_is_signed_unless_an_unsigned_operation_reads_it() {
        assert_eq!(parameter_through(BinOp::Add), CType::I32);
        assert_eq!(parameter_through(BinOp::DivU), CType::U32);
        assert_eq!(parameter_through(BinOp::Shr), CType::U32);
        assert_eq!(parameter_through(BinOp::DivS), CType::I32);
    }

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
    fn a_return_of_only_the_low_byte_is_a_byte() {
        // sete al; ret: the rest of rax is whatever the caller left.
        let flag = Expr::Select {
            cond: crate::ir::Cond::Eq,
            lhs: Box::new(Expr::reg(7, 32)),
            rhs: Box::new(Expr::Const(4)),
            then: Box::new(Expr::Const(1)),
            els: Box::new(Expr::Const(0)),
        };
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![Stmt::Ret {
                value: Expr::bin(
                    BinOp::Or,
                    Expr::bin(BinOp::And, Expr::reg(0, 64), Expr::Const(!0xff)),
                    flag.clone(),
                ),
            }],
        );
        apply_partial_return(&mut ir);
        assert_eq!(ir.ret_type, CType::int(1, false));
        assert!(matches!(
            &ir.blocks[0].stmts[0],
            Stmt::Ret { value } if *value == Expr::bin(BinOp::And, flag, Expr::Const(0xff))
        ));
    }

    /// `mov r15b, 1` then `mov eax, r15d; ret`, or with `whole` a write of
    /// all of r15 instead.
    fn returns_r15(whole: bool) -> FunctionIr {
        const R15: u16 = 15;
        let one = if whole {
            Expr::Const(0x100)
        } else {
            Expr::bin(
                BinOp::Or,
                Expr::bin(BinOp::And, Expr::reg(R15, 64), Expr::Const(!0xff)),
                Expr::Const(1),
            )
        };
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Assign {
                    dest: crate::ir::RegRef {
                        index: R15,
                        width: 64,
                    },
                    value: one,
                },
                Stmt::Assign {
                    dest: crate::ir::RegRef {
                        index: 0,
                        width: 64,
                    },
                    value: Expr::bin(BinOp::And, Expr::reg(R15, 64), Expr::Const(0xffff_ffff)),
                },
                Stmt::Ret {
                    value: Expr::reg(0, 64),
                },
            ],
        );
        ir.ret_type = CType::U32;
        apply_partial_return(&mut ir);
        ir
    }

    #[test]
    fn a_return_copied_from_a_byte_of_another_register_is_a_byte() {
        let ir = returns_r15(false);
        assert_eq!(ir.ret_type, CType::int(1, false));
        assert!(matches!(
            &ir.blocks[0].stmts[2],
            Stmt::Ret { value } if *value == Expr::bin(BinOp::And, Expr::reg(0, 64), Expr::Const(0xff))
        ));
        assert_eq!(returns_r15(true).ret_type, CType::U32);
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

    #[test]
    fn a_register_reads_as_signed_unless_more_unsigned_operations_read_it() {
        use crate::ir::Cond;
        let compare = |cond: Cond| Stmt::Brif {
            cond,
            lhs: Expr::reg(7, 64),
            rhs: Expr::Const(0),
            target: 0,
        };
        let evidence = |conds: &[Cond]| {
            let ir = FunctionIr::single_block(
                Isa::X86_64,
                conds.iter().map(|cond| compare(*cond)).collect(),
            );
            super::SignEvidence::of(&ir).mostly_signed(7)
        };
        assert!(evidence(&[]));
        assert!(evidence(&[Cond::Lt, Cond::Cc]));
        assert!(!evidence(&[Cond::Lt, Cond::Cc, Cond::Hi]));
    }
}

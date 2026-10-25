use crate::arch;
use crate::ir::{CType, FunctionIr, Param};

pub(crate) fn apply_width_types(ir: &mut FunctionIr, uniform_32: &std::collections::HashSet<u16>) {
    let outputs = live_call_outputs(ir);
    let entry = call_output_entry_demands(ir, &outputs);
    let demands = std::cell::OnceCell::new();
    // A register only ever written, or only ever read, at 32 bits holds a 32-bit value.
    let narrow = |ir: &FunctionIr, index: u16| -> bool {
        uniform_32.contains(&index) || narrow_only(ir, index, &outputs, entry.as_ref(), &demands)
    };
    // The return type is re-decided from the optimized body, whose passes may
    // have removed or exposed the 32-bit writes the earlier guess relied on.
    let ret_is_wide = returns_wide(ir, &outputs, entry.as_ref(), &demands);
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
            // Widening a zero-extended constant must not turn it negative.
            if matches!(value, crate::ir::Expr::Const(value) if *value > i32::MAX as u64 && *value <= u32::MAX as u64)
            {
                returned.any_unsigned = true;
            }
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
    /// Local C declarations also account for left shifts.
    variables: bool,
}

impl SignEvidence {
    pub(crate) fn of(ir: &FunctionIr) -> Self {
        Self::default().collect(ir)
    }

    pub(crate) fn of_variables(ir: &FunctionIr) -> Self {
        Self {
            variables: true,
            ..Self::default()
        }
        .collect(ir)
    }

    fn collect(mut self, ir: &FunctionIr) -> Self {
        use crate::ir::Stmt;
        for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
            match stmt {
                Stmt::Assign { value, .. } | Stmt::Ret { value } => self.walk(value),
                Stmt::Store { addr, value, .. } => {
                    self.walk(addr);
                    self.walk(value);
                }
                Stmt::Brif { cond, lhs, rhs, .. } => {
                    self.compare(*cond, lhs, rhs);
                    self.walk(lhs);
                    self.walk(rhs);
                }
                Stmt::Switch { index, .. } => self.walk(index),
                Stmt::Call { .. } => {
                    for value in stmt.operands() {
                        self.walk(value);
                    }
                }
                _ => {}
            }
        }
        self
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
                BinOp::Shr if !self.variables && matches!(rhs.as_ref(), Expr::Const(31 | 63)) => {
                    self.note(true, &[lhs])
                }
                BinOp::Shr => self.note(false, &[lhs]),
                BinOp::Shl if self.variables => self.note(false, &[lhs]),
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
fn returns_wide(
    ir: &FunctionIr,
    outputs: &LiveCallOutputs,
    entry: Option<&std::collections::HashMap<u16, u64>>,
    demands: &std::cell::OnceCell<Option<std::collections::HashMap<u16, u64>>>,
) -> bool {
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
        .any(|index| *index == WIDE_VALUE || !narrow_only(ir, *index, outputs, entry, demands))
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

type LiveCallOutputs = Option<std::collections::HashSet<(usize, usize, u16)>>;

fn call_output_entry_demands(
    ir: &FunctionIr,
    outputs: &LiveCallOutputs,
) -> Option<std::collections::HashMap<u16, u64>> {
    let outputs = outputs.as_ref()?;
    let excluded = ir.blocks.iter().enumerate().any(|(block, body)| {
        body.stmts.iter().enumerate().any(|(position, stmt)| {
            stmt.call_outputs().iter().any(|output| {
                output.dest.width > 32 && !outputs.contains(&(block, position, output.dest.index))
            })
        })
    });
    if excluded {
        crate::ssa::entry_demands(ir, &[])
    } else {
        None
    }
}

fn live_call_outputs(ir: &FunctionIr) -> LiveCallOutputs {
    use crate::ir::{Stmt, cfg, visit::statement_registers};
    use std::collections::HashSet;
    let mut outputs = HashSet::new();
    if !ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .any(|stmt| !stmt.call_outputs().is_empty())
    {
        return Some(outputs);
    }
    let starts: HashSet<_> = ir.blocks.iter().map(|block| block.start).collect();
    for (at, block) in ir.blocks.iter().enumerate() {
        let edges = cfg::block_successors_with_exceptions(&ir.blocks, at, &ir.landing_pads);
        if cfg::opaque(block)
            || edges.unknown_normal
            || edges.unknown_exceptional
            || !edges.exceptional.is_empty()
        {
            return None;
        }
        for stmt in &block.stmts {
            match stmt {
                Stmt::BrifFlags { .. } => return None,
                Stmt::Br {
                    target: Some(target),
                }
                | Stmt::Brif { target, .. }
                    if !starts.contains(target) =>
                {
                    return None;
                }
                Stmt::Switch { cases, default, .. }
                    if default.is_none()
                        || cases.iter().any(|(_, target)| !starts.contains(target))
                        || default.is_some_and(|target| !starts.contains(&target)) =>
                {
                    return None;
                }
                _ => {}
            }
        }
        if at + 1 == ir.blocks.len()
            && !matches!(
                block.stmts.last(),
                Some(
                    Stmt::Ret { .. }
                        | Stmt::Trap
                        | Stmt::Br { target: Some(_) }
                        | Stmt::Switch { .. }
                )
            )
        {
            return None;
        }
    }
    let incoming = cfg::live_in(ir);
    for (block, body) in ir.blocks.iter().enumerate() {
        let mut live = cfg::live_out(ir, &incoming, block);
        for (position, stmt) in body.stmts.iter().enumerate().rev() {
            for output in stmt.call_outputs() {
                if live.contains(&output.dest.index) {
                    outputs.insert((block, position, output.dest.index));
                }
            }
            let (writes, reads) = statement_registers(stmt);
            live.retain(|register| !writes.contains(register));
            live.extend(reads);
        }
    }
    Some(outputs)
}

/// True when the register carries a 32-bit value: every observed write is
/// narrow, or — when nothing writes it — every read is a 32-bit view.
fn narrow_only(
    ir: &FunctionIr,
    register: u16,
    outputs: &LiveCallOutputs,
    entry: Option<&std::collections::HashMap<u16, u64>>,
    demands: &std::cell::OnceCell<Option<std::collections::HashMap<u16, u64>>>,
) -> bool {
    let mut writes = false;
    let mut wide_write = false;
    let mut reads_narrow = true;
    let mut seen = false;
    let mut excluded_wide = false;
    for (block_index, block) in ir.blocks.iter().enumerate() {
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
        for (position, stmt) in block.stmts[..own].iter().enumerate() {
            let output_live = outputs
                .as_ref()
                .is_none_or(|outputs| outputs.contains(&(block_index, position, register)));
            excluded_wide |= !output_live
                && stmt
                    .call_outputs()
                    .iter()
                    .any(|output| output.dest.index == register && output.dest.width > 32);
            collect_uses(
                stmt,
                register,
                output_live,
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
    if writes
        && !wide_write
        && !reads_narrow
        && ir.params.iter().any(|param| param.index == register)
    {
        let entry = entry.or_else(|| {
            demands
                .get_or_init(|| crate::ssa::entry_demands(ir, &[]))
                .as_ref()
        });
        if entry.is_none_or(|entry| entry.get(&register).copied().unwrap_or(0) >> 32 != 0) {
            return false;
        }
    }
    if excluded_wide
        && entry.is_none_or(|entry| entry.get(&register).copied().unwrap_or(0) >> 32 != 0)
    {
        return false;
    }
    if writes { !wide_write } else { reads_narrow }
}

fn collect_uses(
    stmt: &crate::ir::Stmt,
    register: u16,
    output_live: bool,
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
            for output in stmt.call_outputs() {
                if output.dest.index == register && output_live {
                    *writes = true;
                    *seen = true;
                    *wide_write |= output.dest.width > 32;
                }
            }
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
        Expr::Load { addr, .. } => scan_reads(addr, register, false, reads_narrow, seen),
        // An extension reads only its value's low bytes.
        Expr::SignExtend { value, .. } => scan_reads(value, register, true, reads_narrow, seen),
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => {
            scan_reads(lhs, register, false, reads_narrow, seen);
            scan_reads(rhs, register, false, reads_narrow, seen);
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

pub(crate) fn apply_pointer_return(ir: &mut FunctionIr) {
    if ir.blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
        matches!(stmt, crate::ir::Stmt::Ret { value } if !matches!(value,
            crate::ir::Expr::Reg { index, width: 64 }
            if ir.params.iter().any(|param| param.index == *index && param.ty.is_pointer())))
    }) {
        return;
    }
    apply_pointer_return_with(ir, &|_| None);
}

pub(crate) fn apply_pointer_return_with(
    ir: &mut FunctionIr,
    callees: super::signature::Callees<'_>,
) {
    use crate::ir::{Expr, Stmt};
    use std::collections::{HashMap, HashSet};

    fn known(value: &Expr, types: &HashMap<u16, CType>) -> Option<CType> {
        match value {
            Expr::Reg { index, width: 64 } => types.get(index).cloned(),
            Expr::Select { then, els, .. } => {
                let ty = known(then, types)?;
                (known(els, types)? == ty).then_some(ty)
            }
            _ => None,
        }
    }

    if ir.declared_signature.is_some()
        || !matches!(ir.ret_type, CType::Int { bytes: 8, .. })
        || ir.blocks.is_empty()
    {
        return;
    }
    let starts: HashSet<u64> = ir.blocks.iter().map(|block| block.start).collect();
    for (at, block) in ir.blocks.iter().enumerate() {
        let edges =
            crate::ir::cfg::block_successors_with_exceptions(&ir.blocks, at, &ir.landing_pads);
        if edges.unknown_normal || edges.unknown_exceptional || !edges.exceptional.is_empty() {
            return;
        }
        for stmt in &block.stmts {
            match stmt {
                Stmt::Unsupported { .. }
                | Stmt::BrIndirect { .. }
                | Stmt::BrifFlags { .. }
                | Stmt::Br { target: None } => return,
                Stmt::Br {
                    target: Some(target),
                }
                | Stmt::Brif { target, .. }
                    if !starts.contains(target) =>
                {
                    return;
                }
                Stmt::Switch { cases, default, .. }
                    if default.is_none()
                        || cases.iter().any(|(_, target)| !starts.contains(target))
                        || default.is_some_and(|target| !starts.contains(&target)) =>
                {
                    return;
                }
                _ => {}
            }
        }
        if at + 1 == ir.blocks.len()
            && !matches!(
                block.stmts.last(),
                Some(
                    Stmt::Ret { .. }
                        | Stmt::Trap
                        | Stmt::Br { target: Some(_) }
                        | Stmt::Switch { .. }
                )
            )
        {
            return;
        }
    }
    if !crate::ir::cfg::cyclic_blocks(ir).is_empty() {
        return;
    }
    let Some(ssa) = crate::ssa::build(ir) else {
        return;
    };
    let mut types = HashMap::new();
    for param in &ir.params {
        if param.ty.is_pointer()
            && let Some(value) = ssa.entry.get(&param.index)
        {
            if types.get(value).is_some_and(|ty| *ty != param.ty) {
                return;
            }
            types.insert(*value, param.ty.clone());
        }
    }
    for (original, renamed) in ir.blocks.iter().zip(&ssa.ir.blocks) {
        for (stmt, renamed) in original.stmts.iter().zip(&renamed.stmts) {
            let Some(prototype) = callees(stmt) else {
                continue;
            };
            if prototype.ret.is_pointer()
                && let Some(output) = super::prototypes::scalar_call_output(renamed, &prototype.ret)
                && output.dest.width == 64
            {
                types.insert(output.dest.index, prototype.ret.clone());
            }
        }
    }
    loop {
        let before = types.len();
        for stmt in ssa.ir.blocks.iter().flat_map(|block| &block.stmts) {
            if let Stmt::Assign {
                dest: crate::ir::RegRef { index, width: 64 },
                value,
            } = stmt
                && let Some(ty) = known(value, &types)
            {
                types.insert(*index, ty);
            }
        }
        for phi in ssa.phis.iter().flatten() {
            if let Some(ty) = phi.args.first().and_then(|arg| types.get(arg)).cloned()
                && phi.args.iter().all(|arg| types.get(arg) == Some(&ty))
            {
                types.insert(phi.value, ty);
            }
        }
        if types.len() == before {
            break;
        }
    }
    let mut returned: Option<CType> = None;
    for stmt in ssa.ir.blocks.iter().flat_map(|block| &block.stmts) {
        let Stmt::Ret { value } = stmt else {
            continue;
        };
        let Some(ty) = known(value, &types) else {
            return;
        };
        if returned.as_ref().is_some_and(|previous| *previous != ty) {
            return;
        }
        returned = Some(ty);
    }
    if let Some(ty) = returned {
        ir.ret_type = ty;
    }
}

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
                Stmt::Call { .. } | Stmt::Machine { .. } => {
                    side_effect = true;
                    let (definitions, reads) = crate::ir::visit::statement_registers(stmt);
                    written |= definitions.contains(&arch::RETURN);
                    used_elsewhere |= reads.contains(&arch::RETURN);
                }
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
    if !saw_ret
        || written
        || (carries_argument && (ir.convention == crate::ir::Convention::Aapcs64 || !side_effect))
        || used_elsewhere
    {
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

/// Places a scalar declaration without changing aggregate physical inputs.
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
        Convention::Aapcs32 | Convention::Aapcs64 | Convention::GoAmd64 => 0,
        Convention::SyscallX86 | Convention::SyscallArm | Convention::GoWriteBarrier => return,
        Convention::GoAbi0 => 8,
    };
    let slot_bytes = if convention == Convention::Aapcs32 {
        4
    } else {
        8
    };
    let mut params = Vec::new();
    let mut stack_params = Vec::new();
    for (index, (name, ty)) in types.params.iter().enumerate() {
        let float = ty.as_ref().is_some_and(CType::is_sse_float);
        let name = name.clone().unwrap_or_else(|| format!("a{index}"));
        let ty = ty.clone().unwrap_or(CType::U64);
        let register = match convention {
            Convention::Win64 => (index < 4).then(|| {
                if float {
                    floats[index]
                } else {
                    integers[index]
                }
            }),
            _ if float => (next_float < floats.len()).then(|| {
                next_float += 1;
                floats[next_float - 1]
            }),
            _ => (next_int < integers.len()).then(|| {
                next_int += 1;
                integers[next_int - 1]
            }),
        };
        match register {
            Some(register) => params.push(Param {
                index: register,
                name,
                ty,
            }),
            None => {
                stack_params.push(StackParam {
                    offset: stack,
                    size: slot_bytes,
                    name,
                    ty,
                    position: index,
                });
                stack += slot_bytes as i64;
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

pub(crate) fn apply_dwarf_types(
    types: Option<crate::loader::dwarf::FunctionTypes>,
    ir: &mut FunctionIr,
) {
    let Some(types) = types else {
        return;
    };
    ir.members = types.members.clone();
    ir.debug_globals = types.globals.clone();
    ir.definitions = types.definitions.clone();
    if ir.convention == crate::ir::Convention::Aapcs32 && !super::abi::aapcs32_words(&types) {
        return;
    }
    if super::abi::has_aggregate(&types) {
        return;
    }
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
        if stmt.has_declared_call() {
            continue;
        }
        let Stmt::Call {
            args: Some(args), ..
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
        if let Some(output) = crate::analysis::prototypes::scalar_call_output(stmt, &prototype.ret)
        {
            offer(&mut values, output.dest.index, &prototype.ret);
        }
    }
    for param in &mut ir.params {
        if let Some(ty) = variadic.get(&param.index) {
            settle_param(param, ty);
        }
    }
    // A structure the body's accesses gave a variable says more than a
    // prototype's pointer.
    for (variable, ty) in values {
        ir.value_types.entry(variable).or_insert(ty);
    }
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

    fn call_width_case() -> FunctionIr {
        let mut outputs = crate::ir::fallback_call_outputs(crate::ir::Convention::Aapcs64, None);
        outputs[0].dest.index = crate::ir::VARIABLE_BASE;
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                Stmt::Call {
                    kind: crate::ir::CallKind::Invoke,
                    target: Some(0x1000),
                    through: None,
                    convention: crate::ir::Convention::Aapcs64,
                    args: Some(vec![Expr::bin(
                        BinOp::And,
                        Expr::reg(1, 64),
                        Expr::Const(0xffff_ffff),
                    )]),
                    floats_named: true,
                    abi: None,
                    outputs,
                    clobbers: None,
                    via: None,
                },
                Stmt::Ret {
                    value: Expr::bin(
                        BinOp::And,
                        Expr::reg(crate::ir::VARIABLE_BASE, 64),
                        Expr::Const(0xffff_ffff),
                    ),
                },
            ],
        );
        ir.params = vec![crate::ir::Param {
            index: 1,
            name: "a1".to_owned(),
            ty: CType::U64,
        }];
        ir
    }

    fn check_call_width(mut ir: FunctionIr, expected: CType) -> FunctionIr {
        use crate::ir::eval::{self, Setup};
        let original = ir.clone();
        let blocks = format!("{:?}", ir.blocks);
        apply_width_types(&mut ir, &Default::default());
        assert_eq!(
            ir.params.iter().find(|param| param.index == 1).unwrap().ty,
            expected
        );
        assert_eq!(format!("{:?}", ir.blocks), blocks);
        for (seed, value) in [(0, 0), (1, 0x8123_4567_89ab_cdef), (0x1234_5678, u64::MAX)] {
            let setup = Setup {
                seed,
                convention: eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &[(1, value), (2, 1)],
                memory: &[],
                step_limit: 100,
            };
            assert_eq!(eval::run(&ir, &setup), eval::run(&original, &setup));
        }
        ir
    }

    #[test]
    fn call_output_width_ignores_only_unused_secondary_writes() {
        let ir = call_width_case();
        let live = super::live_call_outputs(&ir).unwrap();
        assert!(live.contains(&(0, 0, crate::ir::VARIABLE_BASE)));
        assert!(!live.contains(&(0, 0, 1)));
        let outputs = ir.blocks[0].stmts[0].call_outputs().to_vec();
        let narrowed = check_call_width(ir, CType::I32);
        assert_eq!(narrowed.blocks[0].stmts[0].call_outputs(), outputs);
    }

    #[test]
    fn call_output_width_keeps_a_live_wide_store_and_unnamed_argument() {
        use crate::ir::eval::{self, Outcome, Setup};
        let mut stored = call_width_case();
        stored.blocks[0].stmts.insert(
            1,
            Stmt::Store {
                addr: Expr::Const(0x4000_0000),
                value: Expr::reg(1, 64),
                width: 8,
            },
        );
        let stored = check_call_width(stored, CType::I64);
        let mut unnamed = call_width_case();
        unnamed.blocks[0].stmts.insert(
            1,
            Stmt::Call {
                kind: crate::ir::CallKind::Invoke,
                target: Some(0x2000),
                through: None,
                convention: crate::ir::Convention::Aapcs64,
                args: None,
                floats_named: true,
                abi: None,
                outputs: Vec::new(),
                clobbers: Some(Default::default()),
                via: None,
            },
        );
        let unnamed = check_call_width(unnamed, CType::I64);
        for seed in [0, 1, 0x1234_5678] {
            let setup = Setup {
                seed,
                convention: eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &[(1, 7)],
                memory: &[],
                step_limit: 100,
            };
            let expected = eval::hash(seed ^ 1, 0x2_0001);
            assert_ne!(expected >> 32, 0);
            let Outcome::Return { memory, .. } = eval::run(&stored, &setup) else {
                unreachable!()
            };
            assert_eq!(
                u64::from_le_bytes(std::array::from_fn(
                    |byte| memory[&(0x4000_0000 + byte as u64)]
                )),
                expected
            );
            let Outcome::Return { calls, .. } = eval::run(&unnamed, &setup) else {
                unreachable!()
            };
            assert_eq!(calls[1].arguments[1], expected);
        }
    }

    #[test]
    fn call_output_width_handles_successor_joins_and_loop_uses() {
        use crate::ir::Block;
        let mut joined = call_width_case();
        let returned = joined.blocks[0].stmts.pop().unwrap();
        joined.blocks[0].stmts.push(Stmt::Brif {
            cond: crate::ir::Cond::Eq,
            lhs: Expr::reg(2, 64),
            rhs: Expr::Const(0),
            target: 20,
        });
        joined.blocks.extend([
            Block {
                start: 10,
                stmts: vec![Stmt::Br { target: Some(30) }],
            },
            Block {
                start: 20,
                stmts: vec![Stmt::Br { target: Some(30) }],
            },
            Block {
                start: 30,
                stmts: vec![
                    Stmt::Store {
                        addr: Expr::Const(0x4000_0000),
                        value: Expr::reg(1, 64),
                        width: 8,
                    },
                    returned.clone(),
                ],
            },
        ]);
        assert!(
            super::live_call_outputs(&joined)
                .unwrap()
                .contains(&(0, 0, 1))
        );
        check_call_width(joined, CType::I64);
        let mut looping = call_width_case();
        looping.blocks[0].stmts.pop();
        looping.blocks[0].stmts.push(Stmt::Br { target: Some(10) });
        looping.blocks.extend([
            Block {
                start: 10,
                stmts: vec![
                    Stmt::Store {
                        addr: Expr::Const(0x4000_0000),
                        value: Expr::reg(1, 64),
                        width: 8,
                    },
                    Stmt::Assign {
                        dest: crate::ir::RegRef {
                            index: 2,
                            width: 64,
                        },
                        value: Expr::bin(BinOp::Sub, Expr::reg(2, 64), Expr::Const(1)),
                    },
                    Stmt::Brif {
                        cond: crate::ir::Cond::Eq,
                        lhs: Expr::reg(2, 64),
                        rhs: Expr::Const(0),
                        target: 10,
                    },
                ],
            },
            Block {
                start: 20,
                stmts: vec![returned],
            },
        ]);
        assert!(
            super::live_call_outputs(&looping)
                .unwrap()
                .contains(&(0, 0, 1))
        );
        check_call_width(looping, CType::I64);
    }

    #[test]
    fn call_output_width_distinguishes_overwrites_and_pre_call_sources() {
        let mut overwritten = call_width_case();
        overwritten.blocks[0].stmts.insert(
            1,
            Stmt::Assign {
                dest: crate::ir::RegRef {
                    index: 1,
                    width: 32,
                },
                value: Expr::Const(7),
            },
        );
        overwritten.blocks[0].stmts.insert(
            2,
            Stmt::Store {
                addr: Expr::Const(0x4000_0000),
                value: Expr::reg(1, 64),
                width: 8,
            },
        );
        assert!(
            !super::live_call_outputs(&overwritten)
                .unwrap()
                .contains(&(0, 0, 1))
        );
        let live = super::live_call_outputs(&overwritten);
        assert_eq!(
            super::call_output_entry_demands(&overwritten, &live).unwrap()[&1],
            0xffff_ffff
        );
        check_call_width(overwritten, CType::I32);
        let mut preserved = call_width_case();
        let Stmt::Call { clobbers, .. } = &mut preserved.blocks[0].stmts[0] else {
            unreachable!()
        };
        *clobbers = Some([0].into_iter().collect());
        assert!(
            !super::live_call_outputs(&preserved)
                .unwrap()
                .contains(&(0, 0, 1))
        );
        check_call_width(preserved.clone(), CType::I32);
        preserved.blocks[0].stmts.insert(
            1,
            Stmt::Store {
                addr: Expr::Const(0x4000_0000),
                value: Expr::reg(1, 64),
                width: 8,
            },
        );
        check_call_width(preserved, CType::I64);
    }

    #[test]
    fn call_output_width_retains_entry_high_bits_before_a_later_narrow_write() {
        let mut ir = call_width_case();
        ir.blocks[0].stmts.insert(
            0,
            Stmt::Store {
                addr: Expr::Const(0x4000_0000),
                value: Expr::reg(1, 64),
                width: 8,
            },
        );
        ir.blocks[0].stmts.insert(
            2,
            Stmt::Assign {
                dest: crate::ir::RegRef {
                    index: 1,
                    width: 32,
                },
                value: Expr::Const(7),
            },
        );
        ir.blocks[0].stmts.insert(
            3,
            Stmt::Store {
                addr: Expr::Const(0x4000_0008),
                value: Expr::reg(1, 64),
                width: 8,
            },
        );
        let live = super::live_call_outputs(&ir);
        assert!(!live.as_ref().unwrap().contains(&(0, 1, 1)));
        assert_eq!(
            super::call_output_entry_demands(&ir, &live).unwrap()[&1],
            u64::MAX
        );
        check_call_width(ir, CType::I64);
    }

    #[test]
    fn call_output_width_entry_proof_includes_unnamed_bare_and_preserved_call_reads() {
        for args in [None, Some(vec![Expr::reg(1, 64)])] {
            let mut ir = call_width_case();
            ir.blocks[0].stmts.insert(
                0,
                Stmt::Call {
                    kind: crate::ir::CallKind::Invoke,
                    target: Some(0x2000),
                    through: None,
                    convention: crate::ir::Convention::Aapcs64,
                    args,
                    floats_named: true,
                    abi: None,
                    outputs: Vec::new(),
                    clobbers: Some(Default::default()),
                    via: None,
                },
            );
            ir.blocks[0].stmts.insert(
                2,
                Stmt::Assign {
                    dest: crate::ir::RegRef {
                        index: 1,
                        width: 32,
                    },
                    value: Expr::Const(7),
                },
            );
            let live = super::live_call_outputs(&ir);
            assert_eq!(
                super::call_output_entry_demands(&ir, &live).unwrap()[&1],
                u64::MAX
            );
            check_call_width(ir, CType::I64);
        }
        let saved = crate::ir::VARIABLE_BASE + 1;
        let mut ir = call_width_case();
        ir.blocks[0].stmts.insert(
            0,
            Stmt::Call {
                kind: crate::ir::CallKind::Invoke,
                target: Some(0x2000),
                through: None,
                convention: crate::ir::Convention::Aapcs64,
                args: Some(Vec::new()),
                floats_named: true,
                abi: None,
                outputs: vec![crate::ir::CallOutput {
                    register: 1,
                    dest: crate::ir::RegRef {
                        index: saved,
                        width: 64,
                    },
                }],
                clobbers: Some(Default::default()),
                via: None,
            },
        );
        ir.blocks[0].stmts.insert(
            2,
            Stmt::Assign {
                dest: crate::ir::RegRef {
                    index: 1,
                    width: 32,
                },
                value: Expr::Const(7),
            },
        );
        ir.blocks[0].stmts.insert(
            3,
            Stmt::Store {
                addr: Expr::Const(0x4000_0000),
                value: Expr::reg(saved, 64),
                width: 8,
            },
        );
        let live = super::live_call_outputs(&ir);
        assert_eq!(
            super::call_output_entry_demands(&ir, &live).unwrap()[&1],
            u64::MAX
        );
        check_call_width(ir, CType::I64);
    }

    #[test]
    fn call_output_width_avoids_entry_solves_without_dead_wide_outputs() {
        let mut ordinary = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                Stmt::Assign {
                    dest: crate::ir::RegRef {
                        index: 1,
                        width: 32,
                    },
                    value: Expr::Const(7),
                },
                Stmt::Store {
                    addr: Expr::Const(0x4000_0000),
                    value: Expr::reg(1, 64),
                    width: 8,
                },
                Stmt::Ret {
                    value: Expr::Const(0),
                },
            ],
        );
        ordinary.params = vec![crate::ir::Param {
            index: 1,
            name: "a1".to_owned(),
            ty: CType::U64,
        }];
        let live = super::live_call_outputs(&ordinary);
        assert!(super::call_output_entry_demands(&ordinary, &live).is_none());
        check_call_width(ordinary, CType::I32);
        let mut used = call_width_case();
        let Stmt::Call { outputs, .. } = &mut used.blocks[0].stmts[0] else {
            unreachable!()
        };
        outputs.retain(|output| output.register == 1);
        used.blocks[0].stmts[1] = Stmt::Ret {
            value: Expr::reg(1, 64),
        };
        let live = super::live_call_outputs(&used);
        assert!(super::call_output_entry_demands(&used, &live).is_none());
        check_call_width(used, CType::I64);
    }

    #[test]
    fn call_output_width_uses_all_live_fallback_for_unresolved_control() {
        use crate::ir::Block;
        let mut controls = Vec::new();
        let mut opaque = call_width_case();
        opaque.blocks[0].stmts.insert(
            1,
            Stmt::Unsupported {
                text: "unknown".to_owned(),
                writes: Some(vec![1]),
            },
        );
        controls.push(opaque);
        let mut external = call_width_case();
        external.blocks[0].stmts[1] = Stmt::Br {
            target: Some(0xffff),
        };
        controls.push(external);
        let mut indirect = call_width_case();
        indirect.blocks[0].stmts[1] = Stmt::BrIndirect {
            target: Expr::reg(2, 64),
        };
        controls.push(indirect);
        let mut switched = call_width_case();
        switched.blocks[0].stmts[1] = Stmt::Switch {
            index: Expr::reg(2, 64),
            cases: Vec::new(),
            default: None,
        };
        controls.push(switched);
        let mut exceptional = call_width_case();
        exceptional.landing_pads.push((10, vec![(0, 1)]));
        exceptional.blocks.push(Block {
            start: 10,
            stmts: vec![Stmt::Ret {
                value: Expr::Const(0),
            }],
        });
        controls.push(exceptional);
        for ir in controls {
            assert!(super::live_call_outputs(&ir).is_none());
            check_call_width(ir, CType::I64);
        }
    }

    #[test]
    fn call_output_width_shares_live_output_facts_with_return_widths() {
        let mut wide = call_width_case();
        wide.ret_type = CType::U32;
        wide.blocks[0].stmts[1] = Stmt::Ret {
            value: Expr::reg(1, 64),
        };
        wide.blocks[0].stmts.insert(
            1,
            Stmt::Store {
                addr: Expr::Const(0x4000_0000),
                value: Expr::Const(0),
                width: 8,
            },
        );
        let live = super::live_call_outputs(&wide);
        assert!(super::returns_wide(
            &wide,
            &live,
            super::call_output_entry_demands(&wide, &live).as_ref(),
            &Default::default()
        ));
        let wide = check_call_width(wide, CType::I64);
        assert_eq!(wide.ret_type, CType::I64);
        let mut narrow = call_width_case();
        narrow.blocks[0].stmts[1] = Stmt::Ret {
            value: Expr::reg(1, 64),
        };
        narrow.blocks[0].stmts.insert(
            1,
            Stmt::Assign {
                dest: crate::ir::RegRef {
                    index: 1,
                    width: 32,
                },
                value: Expr::Const(7),
            },
        );
        let live = super::live_call_outputs(&narrow);
        assert!(!super::returns_wide(
            &narrow,
            &live,
            super::call_output_entry_demands(&narrow, &live).as_ref(),
            &Default::default()
        ));
        let narrow = check_call_width(narrow, CType::I32);
        assert_eq!(narrow.ret_type, CType::I32);
    }

    #[test]
    fn call_output_width_restores_narrow_inputs_in_the_actual_call_fixture() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/calls_a64.o");
        let image = crate::loader::load(&path).unwrap();
        for name in ["apply_table", "apply_pointer"] {
            let function = image
                .functions
                .values()
                .find(|function| function.name.as_deref() == Some(name))
                .unwrap();
            let analysis = crate::analysis::analyze(&image, function, None).unwrap();
            assert_eq!(
                analysis
                    .ir
                    .params
                    .iter()
                    .find(|param| param.index == 1)
                    .unwrap()
                    .ty,
                CType::I32
            );
            assert!(
                analysis
                    .ir
                    .blocks
                    .iter()
                    .flat_map(|block| &block.stmts)
                    .flat_map(Stmt::call_outputs)
                    .any(|output| output.register == 1)
            );
        }
    }

    fn pointer_case(stmts: Vec<Stmt>) -> FunctionIr {
        let mut ir = FunctionIr::single_block(Isa::AArch64, stmts);
        ir.ret_type = CType::I64;
        ir.params = vec![
            crate::ir::Param {
                index: 0,
                name: "dst".to_owned(),
                ty: CType::pointer_to(CType::Void),
            },
            crate::ir::Param {
                index: 1,
                name: "src".to_owned(),
                ty: CType::pointer_to(CType::Void),
            },
            crate::ir::Param {
                index: 2,
                name: "n".to_owned(),
                ty: CType::U64,
            },
            crate::ir::Param {
                index: 3,
                name: "count".to_owned(),
                ty: CType::pointer_to(CType::U64),
            },
        ];
        ir
    }

    fn pointer_copy(dest: u16, index: u16) -> Stmt {
        Stmt::Assign {
            dest: crate::ir::RegRef {
                index: dest,
                width: 64,
            },
            value: Expr::reg(index, 64),
        }
    }

    fn pointer_import(dest: u16) -> Stmt {
        Stmt::Call {
            kind: crate::ir::CallKind::Invoke,
            target: None,
            through: Some(Expr::Load {
                addr: Box::new(Expr::Const(0x1000)),
                width: 8,
                signed: false,
            }),
            convention: crate::ir::Convention::Aapcs64,
            args: Some(vec![Expr::reg(0, 64), Expr::reg(1, 64), Expr::reg(2, 64)]),
            floats_named: true,
            abi: None,
            outputs: vec![crate::ir::CallOutput {
                register: 0,
                dest: crate::ir::RegRef {
                    index: dest,
                    width: 64,
                },
            }],
            clobbers: Some([0].into_iter().collect()),
            via: None,
        }
    }

    fn check_pointer_return(mut ir: FunctionIr, expected: CType) -> FunctionIr {
        use crate::ir::eval::{self, Setup};
        let mut image = crate::loader::Image::from_code(Isa::AArch64, 0, Vec::new());
        image.imports.insert(0x1000, "memcpy".to_owned());
        let before = ir.clone();
        super::apply_pointer_return_with(&mut ir, &|stmt| {
            crate::analysis::prototypes::called(&image, stmt)
        });
        assert_eq!(ir.ret_type, expected);
        let mut restored = ir.clone();
        restored.ret_type = before.ret_type.clone();
        assert_eq!(format!("{restored:?}"), format!("{before:?}"));
        for seed in [0, 1, 0x8123_4567_89ab_cdef] {
            let setup = Setup {
                seed,
                convention: eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &[
                    (0, 0x4000_0000),
                    (1, 0x4000_1000),
                    (2, seed & 1),
                    (3, 0x4000_2000),
                ],
                memory: &[(0x1000, 0x2000)],
                step_limit: 100,
            };
            assert_eq!(eval::run(&ir, &setup), eval::run(&before, &setup));
        }
        ir
    }

    #[test]
    fn pointer_returns_follow_parameter_copies_and_same_type_selects() {
        let variable = crate::ir::VARIABLE_BASE;
        let ir = pointer_case(vec![
            pointer_copy(variable, 0),
            Stmt::Store {
                addr: Expr::reg(3, 64),
                value: Expr::reg(2, 64),
                width: 8,
            },
            Stmt::Ret {
                value: Expr::reg(variable, 64),
            },
        ]);
        let inferred = check_pointer_return(ir, CType::pointer_to(CType::Void));
        assert!(inferred.value_types.is_empty());
        let selected = Expr::Select {
            cond: crate::ir::Cond::Eq,
            lhs: Box::new(Expr::reg(2, 64)),
            rhs: Box::new(Expr::Const(0)),
            then: Box::new(Expr::reg(0, 64)),
            els: Box::new(Expr::reg(1, 64)),
        };
        check_pointer_return(
            pointer_case(vec![Stmt::Ret { value: selected }]),
            CType::pointer_to(CType::Void),
        );
    }

    #[test]
    fn renderer_pointer_inference_keeps_its_existing_bare_parameter_scope() {
        let variable = crate::ir::VARIABLE_BASE;
        let mut copied = pointer_case(vec![
            pointer_copy(variable, 0),
            Stmt::Ret {
                value: Expr::reg(variable, 64),
            },
        ]);
        super::apply_pointer_return(&mut copied);
        assert_eq!(copied.ret_type, CType::I64);
        let mut bare = pointer_case(vec![Stmt::Ret {
            value: Expr::reg(0, 64),
        }]);
        super::apply_pointer_return(&mut bare);
        assert_eq!(bare.ret_type, CType::pointer_to(CType::Void));
    }

    fn pointer_join(second: CType) -> FunctionIr {
        use crate::ir::Block;
        let variable = crate::ir::VARIABLE_BASE;
        let mut ir = pointer_case(Vec::new());
        ir.params[0].ty = CType::pointer_to(CType::I32);
        ir.params[1].ty = second;
        ir.blocks = vec![
            Block {
                start: 0,
                stmts: vec![Stmt::Brif {
                    cond: crate::ir::Cond::Eq,
                    lhs: Expr::reg(2, 64),
                    rhs: Expr::Const(0),
                    target: 20,
                }],
            },
            Block {
                start: 10,
                stmts: vec![pointer_copy(variable, 0), Stmt::Br { target: Some(30) }],
            },
            Block {
                start: 20,
                stmts: vec![pointer_copy(variable, 1), Stmt::Br { target: Some(30) }],
            },
            Block {
                start: 30,
                stmts: vec![Stmt::Ret {
                    value: Expr::reg(variable, 64),
                }],
            },
        ];
        ir
    }

    #[test]
    fn pointer_return_phis_require_every_incoming_type_to_match() {
        check_pointer_return(
            pointer_join(CType::pointer_to(CType::I32)),
            CType::pointer_to(CType::I32),
        );
        check_pointer_return(pointer_join(CType::pointer_to(CType::U64)), CType::I64);
        check_pointer_return(pointer_join(CType::U64), CType::I64);
        check_pointer_return(pointer_join(CType::Array(Box::new(CType::I32))), CType::I64);
    }

    #[test]
    fn pointer_returns_follow_an_import_result_across_a_store_and_another_call() {
        let variable = crate::ir::VARIABLE_BASE;
        let saved = variable + 1;
        let mut other = pointer_import(variable + 2);
        let Stmt::Call {
            through,
            args,
            outputs,
            clobbers,
            ..
        } = &mut other
        else {
            unreachable!()
        };
        *through = None;
        *args = Some(Vec::new());
        outputs.clear();
        *clobbers = Some(Default::default());
        let ir = pointer_case(vec![
            pointer_import(variable),
            pointer_copy(saved, variable),
            other,
            Stmt::Store {
                addr: Expr::reg(3, 64),
                value: Expr::reg(2, 64),
                width: 8,
            },
            Stmt::Ret {
                value: Expr::reg(saved, 64),
            },
        ]);
        let inferred = check_pointer_return(ir, CType::pointer_to(CType::Void));
        assert!(inferred.value_types.is_empty());
    }

    #[test]
    fn pointer_return_inference_does_not_reuse_an_overwritten_type() {
        let variable = crate::ir::VARIABLE_BASE;
        let constant = |index| Stmt::Assign {
            dest: crate::ir::RegRef { index, width: 64 },
            value: Expr::Const(7),
        };
        check_pointer_return(
            pointer_case(vec![
                constant(0),
                Stmt::Ret {
                    value: Expr::reg(0, 64),
                },
            ]),
            CType::I64,
        );
        let mut ir = pointer_case(vec![
            pointer_import(variable),
            constant(variable),
            Stmt::Ret {
                value: Expr::reg(variable, 64),
            },
        ]);
        ir.value_types
            .insert(variable, CType::pointer_to(CType::Void));
        check_pointer_return(ir, CType::I64);
        let mut unknown = pointer_import(variable);
        let Stmt::Call {
            through, target, ..
        } = &mut unknown
        else {
            unreachable!()
        };
        *through = None;
        *target = Some(0x3000);
        check_pointer_return(
            pointer_case(vec![
                unknown,
                Stmt::Ret {
                    value: Expr::reg(variable, 64),
                },
            ]),
            CType::I64,
        );
    }

    #[test]
    fn pointer_return_inference_rejects_truncation_arithmetic_and_missing_outputs() {
        let variable = crate::ir::VARIABLE_BASE;
        for (dest_width, read_width) in [(32, 64), (64, 32)] {
            check_pointer_return(
                pointer_case(vec![
                    Stmt::Assign {
                        dest: crate::ir::RegRef {
                            index: variable,
                            width: dest_width,
                        },
                        value: Expr::reg(0, read_width),
                    },
                    Stmt::Ret {
                        value: Expr::reg(variable, 64),
                    },
                ]),
                CType::I64,
            );
        }
        check_pointer_return(
            pointer_case(vec![Stmt::Ret {
                value: Expr::bin(BinOp::Add, Expr::reg(0, 64), Expr::Const(1)),
            }]),
            CType::I64,
        );
        for missing in [false, true] {
            let mut call = pointer_import(variable);
            if missing {
                call.call_outputs_mut()[0].register = 1;
            } else {
                call.call_outputs_mut()[0].dest.width = 32;
            }
            check_pointer_return(
                pointer_case(vec![
                    call,
                    Stmt::Ret {
                        value: Expr::reg(variable, 64),
                    },
                ]),
                CType::I64,
            );
        }
    }

    #[test]
    fn pointer_return_inference_respects_declarations_and_pointee_identity() {
        let returned = Stmt::Ret {
            value: Expr::reg(0, 64),
        };
        let mut declared = pointer_case(vec![returned.clone()]);
        declared.declared_signature = Some(crate::ir::DeclaredSignature {
            params: Vec::new(),
            ret: CType::U64,
            variadic: false,
            abi: Err(crate::ir::AbiIssue::UnknownLayout),
        });
        check_pointer_return(declared, CType::I64);
        let mut typed = pointer_case(vec![returned.clone()]);
        typed.ret_type = CType::pointer_to(CType::U64);
        check_pointer_return(typed, CType::pointer_to(CType::U64));
        let mut structure = pointer_case(vec![returned.clone()]);
        let pointer = CType::pointer_to(CType::Named("struct item".to_owned()));
        structure.params[0].ty = pointer.clone();
        check_pointer_return(structure, pointer);
        let mut pointer_to_array = pointer_case(vec![returned.clone()]);
        let pointer = CType::pointer_to(CType::Array(Box::new(CType::I32)));
        pointer_to_array.params[0].ty = pointer.clone();
        check_pointer_return(pointer_to_array, pointer);
        let mut array = pointer_case(vec![returned]);
        array.params[0].ty = CType::Array(Box::new(CType::I32));
        check_pointer_return(array, CType::I64);
    }

    #[test]
    fn pointer_return_inference_refuses_unknown_exceptional_and_cyclic_edges() {
        use crate::ir::Block;
        let returned = Stmt::Ret {
            value: Expr::reg(0, 64),
        };
        check_pointer_return(
            pointer_case(vec![Stmt::unsupported("unknown"), returned.clone()]),
            CType::I64,
        );
        check_pointer_return(
            pointer_case(vec![
                Stmt::Brif {
                    cond: crate::ir::Cond::Eq,
                    lhs: Expr::reg(2, 64),
                    rhs: Expr::Const(0),
                    target: 0xffff,
                },
                returned.clone(),
            ]),
            CType::I64,
        );
        let mut exceptional = pointer_case(vec![
            pointer_import(crate::ir::VARIABLE_BASE),
            returned.clone(),
        ]);
        exceptional.landing_pads.push((10, vec![(0, 1)]));
        exceptional.blocks.push(Block {
            start: 10,
            stmts: vec![returned.clone()],
        });
        check_pointer_return(exceptional, CType::I64);
        let mut cyclic = pointer_case(Vec::new());
        cyclic.blocks = vec![
            Block {
                start: 0,
                stmts: vec![Stmt::Brif {
                    cond: crate::ir::Cond::Eq,
                    lhs: Expr::reg(2, 64),
                    rhs: Expr::Const(0),
                    target: 20,
                }],
            },
            Block {
                start: 10,
                stmts: vec![Stmt::Br { target: Some(0) }],
            },
            Block {
                start: 20,
                stmts: vec![returned],
            },
        ];
        check_pointer_return(cyclic, CType::I64);
    }

    #[test]
    fn inferred_pointer_returns_cast_integer_locals_in_generated_c() {
        let variable = crate::ir::VARIABLE_BASE;
        let saved = variable + 1;
        let mut ir = pointer_case(vec![
            pointer_import(variable),
            pointer_copy(saved, variable),
            Stmt::Store {
                addr: Expr::reg(3, 64),
                value: Expr::reg(2, 64),
                width: 8,
            },
            Stmt::Ret {
                value: Expr::reg(saved, 64),
            },
        ]);
        ir.name = Some("copy_and_note".to_owned());
        let ir = check_pointer_return(ir, CType::pointer_to(CType::Void));
        let mut symbols = crate::render::Symbols::default();
        symbols.import_slots.insert(0x1000, "memcpy".to_owned());
        symbols
            .import_returns
            .insert(0x1000, CType::pointer_to(CType::Void));
        let rendered = crate::render::render(&ir, &[], &symbols, &[]);
        assert!(rendered.contains("void *copy_and_note("), "{rendered}");
        assert!(
            rendered
                .lines()
                .any(|line| line.trim_start().starts_with("return (void *)")),
            "{rendered}"
        );
        assert!(ir.value_types.is_empty());
    }

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
    fn scalar_float_prototypes_type_only_the_matching_fp_output() {
        use crate::ir::{Convention, VARIABLE_BASE};
        for (isa, convention, output_register) in [
            (Isa::X86_64, Convention::SysV, crate::arch::x86::XMM0),
            (Isa::X86_64, Convention::Win64, crate::arch::x86::XMM0),
            (Isa::AArch64, Convention::Aapcs64, crate::arch::aarch64::V0),
        ] {
            for (name, ret) in [("strtof", "float"), ("strtod", "double")] {
                for present in [false, true] {
                    let mut image = crate::loader::Image::from_code(isa, 0, Vec::new());
                    image.imports.insert(0x1000, name.to_owned());
                    let mut outputs = crate::ir::fallback_call_outputs(convention, None);
                    outputs.retain(|output| present || output.register != output_register);
                    outputs.reverse();
                    for output in &mut outputs {
                        output.dest.index = VARIABLE_BASE + output.register;
                    }
                    let mut ir = FunctionIr::single_block(
                        isa,
                        vec![Stmt::Call {
                            kind: crate::ir::CallKind::Invoke,
                            target: None,
                            through: Some(Expr::Load {
                                addr: Box::new(Expr::Const(0x1000)),
                                width: 8,
                                signed: false,
                            }),
                            convention,
                            args: Some(Vec::new()),
                            floats_named: true,
                            abi: None,
                            outputs,
                            clobbers: None,
                            via: None,
                        }],
                    );
                    super::apply_prototypes(&mut ir, &image);
                    assert_eq!(
                        ir.value_types.get(&(VARIABLE_BASE + output_register)),
                        present.then(|| CType::Named(ret.to_owned())).as_ref()
                    );
                    assert!(!ir.value_types.contains_key(&VARIABLE_BASE));
                    assert_eq!(ir.value_types.len(), usize::from(present));
                }
            }
        }
    }

    #[test]
    fn a_defined_call_output_keeps_an_integer_return_nonvoid() {
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Call {
                    kind: crate::ir::CallKind::Invoke,
                    target: Some(0x1000),
                    through: None,
                    convention: crate::ir::Convention::SysV,
                    args: Some(Vec::new()),
                    floats_named: true,
                    abi: None,
                    outputs: crate::ir::fallback_call_outputs(
                        crate::ir::Convention::SysV,
                        Some([0].into_iter().collect()),
                    ),
                    clobbers: Some([0].into_iter().collect()),
                    via: None,
                },
                Stmt::Ret {
                    value: Expr::reg(0, 64),
                },
            ],
        );
        ir.ret_type = CType::U64;
        apply_void_return(&mut ir);
        assert_eq!(ir.ret_type, CType::U64);
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
    #[test]
    fn declared_calls_do_not_offer_positional_library_argument_types() {
        use crate::ir::{Convention, VARIABLE_BASE};
        let mut image = crate::loader::Image::from_code(Isa::AArch64, 0, Vec::new());
        image.imports.insert(0x1000, "free".to_owned());
        for attached in [false, true] {
            let mut call = crate::lift::call_through(
                crate::ir::CallKind::Invoke,
                &image,
                Expr::Load {
                    addr: Box::new(Expr::Const(0x1000)),
                    width: 8,
                    signed: false,
                },
            );
            let Stmt::Call { args, abi, .. } = &mut call else {
                unreachable!()
            };
            *args = Some(vec![Expr::reg(VARIABLE_BASE, 64)]);
            *abi = attached.then(|| crate::ir::calls::test_call_abi(vec![0], false));
            let mut ir = FunctionIr::single_block(Isa::AArch64, vec![call]);
            ir.convention = Convention::Aapcs64;
            let before = format!("{:?}", ir.blocks);
            super::apply_prototypes(&mut ir, &image);
            assert_eq!(
                ir.value_types.get(&VARIABLE_BASE),
                (!attached).then(|| CType::pointer_to(CType::Void)).as_ref()
            );
            assert_eq!(format!("{:?}", ir.blocks), before);
        }
    }
}

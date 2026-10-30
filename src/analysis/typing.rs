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
                    || (!evidence.unsigned.contains(&param.index)
                        && !(evidence.wrapping.contains(&param.index)
                            && param.ty.integer().is_some_and(|(bits, _)| bits >= 32))))
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
        } else if narrow || param.ty == CType::I32 {
            param.ty = CType::U32;
        } else if param.ty == CType::I64 {
            param.ty = CType::U64;
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
        if let crate::ir::Stmt::Ret { value, .. } = stmt {
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
    /// Registers read by operations whose exact bits require unsigned C arithmetic.
    pub(crate) wrapping: std::collections::HashSet<u16>,
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
                Stmt::Assign { value, .. } | Stmt::Ret { value, .. } => self.walk(value),
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
            Expr::Bin { op, lhs, rhs } => {
                if crate::ir::semantics::operand_width(lhs, rhs) >= 32 {
                    match op {
                        BinOp::Add | BinOp::Sub | BinOp::Mul => {
                            self.wrap(lhs);
                            self.wrap(rhs);
                        }
                        BinOp::Shl => self.wrap(lhs),
                        _ => {}
                    }
                }
                match op {
                    BinOp::DivS | BinOp::ModS => self.note(true, &[lhs, rhs]),
                    BinOp::DivU | BinOp::ModU => self.note(false, &[lhs, rhs]),
                    BinOp::Sar => self.note(true, &[lhs]),
                    // Shifting the top bit down tests the sign.
                    BinOp::Shr
                        if !self.variables && matches!(rhs.as_ref(), Expr::Const(31 | 63)) =>
                    {
                        self.note(true, &[lhs])
                    }
                    BinOp::Shr => self.note(false, &[lhs]),
                    BinOp::Shl if self.variables => self.note(false, &[lhs]),
                    _ => {}
                }
            }
            Expr::SignExtend { value, .. } => self.note(true, &[value]),
            Expr::Select { cond, lhs, rhs, .. } => self.compare(*cond, lhs, rhs),
            _ => {}
        }
        for child in crate::ir::visit::children(expr) {
            self.walk(child);
        }
    }

    fn wrap(&mut self, expr: &crate::ir::Expr) {
        crate::ir::visit::expr_reads(expr, &mut self.wrapping);
    }
}

/// The last value assigned to a register anywhere in the body.
fn last_definition(ir: &FunctionIr, index: u16) -> Option<&crate::ir::Expr> {
    let mut found = None;
    for block in &ir.blocks {
        for stmt in &block.stmts {
            if let crate::ir::Stmt::Assign { dest, value, .. } = stmt
                && dest.index == index
            {
                found = Some(value);
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
    let mut resolved = value;
    if let crate::ir::Expr::Reg { index, width } = value
        && *width > 32
        && let Some(definition) = last_definition(ir, *index)
    {
        resolved = definition;
    }
    let mut wide: Vec<u16> = Vec::new();
    collect_wide_registers(resolved, false, &mut wide);
    wide.iter()
        .any(|index| *index == WIDE_VALUE || !narrow_only(ir, *index, outputs, entry, demands))
}

/// A value that is wide on its own, without naming a register (an 8-byte
/// load, or a sign extension to 64 bits).
const WIDE_VALUE: u16 = u16::MAX;

fn collect_wide_registers(expr: &crate::ir::Expr, narrow: bool, wide: &mut Vec<u16>) {
    use crate::ir::Expr;
    match expr {
        Expr::Reg { index, width } => {
            if !narrow && *width > 32 {
                wide.push(*index);
            }
        }
        Expr::Const(value) => {
            if !narrow && *value > u64::from(u32::MAX) {
                wide.push(WIDE_VALUE);
            }
        }
        Expr::Bin { op, lhs, rhs } => {
            if matches!(op, crate::ir::BinOp::And)
                && matches!(rhs.as_ref(), Expr::Const(mask) if *mask <= 0xffff_ffff)
            {
                collect_wide_registers(lhs, true, wide);
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
                collect_wide_registers(lhs, narrow || dividend_narrow, wide);
                return;
            }
            collect_wide_registers(lhs, narrow, wide);
            collect_wide_registers(rhs, narrow, wide);
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
            collect_wide_registers(value, true, wide);
        }
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => {
            collect_wide_registers(lhs, narrow, wide);
            collect_wide_registers(rhs, narrow, wide);
            collect_wide_registers(then, narrow, wide);
            collect_wide_registers(els, narrow, wide);
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
    let Some(outputs) = outputs.as_ref() else {
        return None;
    };
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
    use crate::ir::visit::statement_registers;
    use crate::ir::{Stmt, cfg};
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
                    ..
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
                        | Stmt::Trap { .. }
                        | Stmt::Br {
                            target: Some(_),
                            ..
                        }
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
        let reversed_statements = body.stmts.iter().enumerate().rev();
        for (position, stmt) in reversed_statements {
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
    let mut uses = WidthUses {
        reads_narrow: true,
        ..WidthUses::default()
    };
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
            collect_uses(stmt, register, output_live, &mut uses);
        }
    }
    if !uses.seen {
        return false;
    }
    if uses.writes
        && !uses.wide_write
        && !uses.reads_narrow
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
    if uses.writes {
        !uses.wide_write
    } else {
        uses.reads_narrow
    }
}

#[derive(Default)]
struct WidthUses {
    writes: bool,
    wide_write: bool,
    reads_narrow: bool,
    seen: bool,
}

fn collect_uses(stmt: &crate::ir::Stmt, register: u16, output_live: bool, uses: &mut WidthUses) {
    use crate::ir::Stmt;
    match stmt {
        Stmt::Assign { dest, value, .. } => {
            if dest.index == register {
                uses.writes = true;
                uses.seen = true;
                if dest.width > 32 && !masked_wide(value) {
                    uses.wide_write = true;
                }
            }
            // A 64-bit read feeding a 32-bit result uses only its low half.
            scan_reads(
                value,
                register,
                dest.width <= 32,
                &mut uses.reads_narrow,
                &mut uses.seen,
            );
        }
        Stmt::Store {
            addr, value, width, ..
        } => {
            scan_reads(
                addr,
                register,
                false,
                &mut uses.reads_narrow,
                &mut uses.seen,
            );
            scan_reads(
                value,
                register,
                *width <= 4,
                &mut uses.reads_narrow,
                &mut uses.seen,
            );
        }
        Stmt::Brif { lhs, rhs, .. } => {
            scan_reads(lhs, register, false, &mut uses.reads_narrow, &mut uses.seen);
            scan_reads(rhs, register, false, &mut uses.reads_narrow, &mut uses.seen);
        }
        Stmt::Ret { value, .. } => scan_reads(
            value,
            register,
            false,
            &mut uses.reads_narrow,
            &mut uses.seen,
        ),
        Stmt::BrIndirect { target, .. } => scan_reads(
            target,
            register,
            false,
            &mut uses.reads_narrow,
            &mut uses.seen,
        ),
        Stmt::Switch { index, .. } => scan_reads(
            index,
            register,
            false,
            &mut uses.reads_narrow,
            &mut uses.seen,
        ),
        // A register passed whole takes the width the callee gives it.
        Stmt::Call { .. } => {
            for output in stmt.call_outputs() {
                if output.dest.index == register && output_live {
                    uses.writes = true;
                    uses.seen = true;
                    uses.wide_write |= output.dest.width > 32;
                }
            }
            for value in stmt.operands() {
                if !matches!(value, crate::ir::Expr::Reg { .. }) {
                    scan_reads(
                        value,
                        register,
                        false,
                        &mut uses.reads_narrow,
                        &mut uses.seen,
                    );
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
fn masked_wide(value: &crate::ir::Expr) -> bool {
    use crate::ir::Expr;
    if matches!(
        value,
        Expr::Bin { op: crate::ir::BinOp::And, rhs, .. }
            if matches!(rhs.as_ref(), Expr::Const(mask) if *mask <= 0xffff_ffff)
    ) {
        return true;
    }
    fits_32_bits(value)
}

fn fits_32_bits(value: &crate::ir::Expr) -> bool {
    use crate::ir::Expr;
    match value {
        Expr::Const(number) => (*number >> 32) == 0,
        Expr::Reg { width, .. } => u32::from(*width) <= 32,
        Expr::Load { width, .. } => u32::from(*width) * 8 <= 32,
        Expr::Bin { op, lhs, rhs } => match op {
            crate::ir::BinOp::And | crate::ir::BinOp::Or | crate::ir::BinOp::Xor => {
                fits_32_bits(lhs) && fits_32_bits(rhs)
            }
            // A quotient and a remainder are bounded by their operands, and
            // a right shift only ever loses bits.
            crate::ir::BinOp::DivS
            | crate::ir::BinOp::DivU
            | crate::ir::BinOp::ModS
            | crate::ir::BinOp::ModU
            | crate::ir::BinOp::Shr
            | crate::ir::BinOp::Sar => fits_32_bits(lhs) && fits_32_bits(rhs),
            _ => false,
        },
        Expr::Select { then, els, .. } => fits_32_bits(then) && fits_32_bits(els),
        Expr::SignExtend { .. } => false,
        Expr::Apply { .. } => crate::ir::semantics::width(value) <= 32,
    }
}

fn reads_register(expr: &crate::ir::Expr, register: u16) -> bool {
    use crate::ir::Expr;
    matches!(expr, Expr::Reg { index, .. } if *index == register)
        || crate::ir::visit::children(expr)
            .into_iter()
            .any(|child| reads_register(child, register))
}

pub(crate) fn apply_pointer_return(ir: &mut FunctionIr) {
    if ir.blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
        matches!(stmt, crate::ir::Stmt::Ret { value, .. } if !matches!(value,
            crate::ir::Expr::Reg { index, width: 64 }
            if ir.params.iter().any(|param| param.index == *index && param.ty.is_pointer())))
    }) {
        return;
    }
    apply_pointer_return_with(ir, &|_| None);
}

pub(crate) fn apply_pointer_return_with(
    ir: &mut FunctionIr,
    callees: super::signature::CalleePrototypeLookup<'_>,
) {
    use crate::ir::{Expr, Stmt};
    use std::collections::{HashMap, HashSet};

    fn known(value: &Expr, types: &HashMap<u16, CType>) -> Option<CType> {
        match value {
            Expr::Reg { index, width: 64 } => types.get(index).cloned(),
            Expr::Select { then, els, .. } => {
                let Some(ty) = known(then, types) else {
                    return None;
                };
                let Some(else_type) = known(els, types) else {
                    return None;
                };
                (else_type == ty).then_some(ty)
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
                | Stmt::Br { target: None, .. } => return,
                Stmt::Br {
                    target: Some(target),
                    ..
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
                        | Stmt::Trap { .. }
                        | Stmt::Br {
                            target: Some(_),
                            ..
                        }
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
                ..
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
        let Stmt::Ret { value, .. } = stmt else {
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
                Stmt::Assign { dest, value, .. } => {
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
                Stmt::Ret { value, .. } => {
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
                Stmt::BrifFlags { .. } | Stmt::Br { .. } | Stmt::Trap { .. } => {}
                Stmt::BrIndirect { target, .. } => {
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
    if !ir.blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
        matches!(
            stmt,
            Stmt::Assign {
                value: Expr::Bin { op: BinOp::Or, .. },
                ..
            } | Stmt::Ret {
                value: Expr::Bin { op: BinOp::Or, .. },
                ..
            }
        )
    }) {
        return;
    }
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
            Stmt::Assign { dest, value, .. } => Some((dest.index, value)),
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
        let Some(Stmt::Ret { value, .. }) = block.stmts.last() else {
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
        if let Some(Stmt::Ret { value, .. }) = block.stmts.last_mut() {
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
    if ir.isa == crate::loader::Isa::I386
        && matches!(convention, Convention::Cdecl | Convention::Stdcall)
        && types.params.iter().any(|(_, ty)| {
            ty.as_ref()
                .and_then(crate::analysis::prototypes::record_name)
                .is_some_and(crate::analysis::prototypes::is_i386_com_interface)
        })
    {
        super::pairs32::place_parameters(types, ir);
        return;
    }
    if matches!(convention, Convention::Cdecl | Convention::Aapcs32)
        && types
            .params
            .iter()
            .any(|(_, ty)| ty.as_ref().is_some_and(crate::lift::pairs32::wide))
    {
        super::pairs32::place_parameters(types, ir);
        return;
    }
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
        Convention::Cdecl | Convention::Stdcall | Convention::Fastcall | Convention::Thiscall => {
            return;
        }
        Convention::SysV => 8,
        Convention::Win64 => 40,
        Convention::Aapcs32 | Convention::Aapcs64 | Convention::GoAmd64 => 0,
        Convention::SyscallI386
        | Convention::SyscallX86
        | Convention::SyscallArm
        | Convention::GoWriteBarrier => return,
        Convention::GoAbi0 => 8,
    };
    let slot_bytes = u64::from(crate::arch::pointer_bytes(ir.isa));
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
        let typed_arguments = args.iter().zip(&types).enumerate();
        for (position, (arg, ty)) in typed_arguments {
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
    let mut written_through = std::collections::HashSet::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        if let Stmt::Store { addr, .. } = stmt {
            crate::ir::visit::collect_reads(addr, &mut written_through);
        }
    }
    for param in &mut ir.params {
        if let Some(ty) = variadic.get(&param.index) {
            let mut ty = ty.clone();
            if written_through.contains(&param.index)
                && let CType::Pointer(target) = &mut ty
                && let CType::Named(name) = target.as_mut()
                && let Some(mutable) = name.strip_prefix("const ")
            {
                *name = mutable.to_owned();
            }
            settle_param(param, &ty);
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
mod tests;

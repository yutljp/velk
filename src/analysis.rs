//! Dispatch from a loaded image to the ISA-specific lifter.

use crate::ir::FunctionIr;
use crate::loader::{Function, Image, Isa};

fn lift_once(
    image: &Image,
    function: &Function,
    size: u64,
    extra: &std::collections::HashSet<u64>,
) -> Result<FunctionIr, String> {
    match image.isa {
        Isa::AArch64 => {
            crate::lift::lift(image, function.addr, size, function.name.clone(), extra)
        }
        Isa::X86_64 => {
            crate::lift_x86::lift(image, function.addr, size, function.name.clone(), extra)
        }
        Isa::Unsupported => Err("unsupported instruction set".to_owned()),
    }
}

pub fn lift(image: &Image, function: &Function, size: u64) -> Result<FunctionIr, String> {
    let empty = std::collections::HashSet::new();
    let ir = lift_once(image, function, size, &empty)?;
    let recovered = crate::switch::recover(&ir, image);
    if recovered.is_empty() {
        let mut ir = ir;
        let uniform_32 = crate::pass::specialize_widths(&mut ir);
        crate::pass::cse(&mut ir);
        crate::pass::simplify(&mut ir);
        crate::pass::magic(&mut ir);
        // The idiom rewrites can leave algebraic identities behind, so
        // simplify again before the register-cleanup passes.
        crate::pass::simplify(&mut ir);
        // Idiom rewriting first, then the register-cleanup passes: the
        // frame pair must be matched before dead-store removal drops its
        // own `rbp = rsp`, and the copy pass feeds the final sweep.
        crate::pass::elide_frame_pointer(&mut ir);
        crate::pass::elide_callee_saves(&mut ir);
        // Inlining exposes fresh identities and fresh single uses, so run
        // the pair a second time. The first sweep removes dead readers
        // that would otherwise look like extra uses of a temporary.
        crate::pass::copy_propagate(&mut ir);
        crate::pass::dce(&mut ir);
        crate::pass::dce_flow(&mut ir);
        crate::pass::simplify(&mut ir);
        crate::pass::copy_propagate_guarded(&mut ir);
        crate::pass::dce(&mut ir);
        crate::pass::dce_flow(&mut ir);
        // A value just stored into a slot can feed its reader directly, and
        // the copy that leaves behind folds into its single reader.
        crate::pass::forward_stored_values(&mut ir);
        crate::pass::inline_local_copies(&mut ir);
        crate::pass::copy_propagate_guarded(&mut ir);
        crate::pass::simplify(&mut ir);
        crate::pass::dce(&mut ir);
        // A final peephole: a read-modify-write reads as one statement, and
        // the constants forwarded into it can leave earlier stores dead.
        crate::pass::fuse_load_op_store(&mut ir);
    crate::pass::simplify(&mut ir);
    crate::pass::dce(&mut ir);
        crate::pass::simplify(&mut ir);
        crate::pass::dce(&mut ir);
        apply_width_types(&mut ir, &uniform_32);
        apply_dwarf_types(image, function.addr, &mut ir);
        return Ok(ir);
    }

    let mut targets = std::collections::HashSet::new();
    for entry in &recovered {
        targets.extend(entry.targets());
    }
    let mut ir = lift_once(image, function, size, &targets)?;
    let recovered = crate::switch::recover(&ir, image);
    crate::switch::apply(&mut ir, &recovered);
    let uniform_32 = crate::pass::specialize_widths(&mut ir);
    crate::pass::cse(&mut ir);
    crate::pass::simplify(&mut ir);
    crate::pass::magic(&mut ir);
    // The idiom rewrites can leave algebraic identities behind, so
    // simplify again before the register-cleanup passes.
    crate::pass::simplify(&mut ir);
    // Idiom rewriting first, then the register-cleanup passes: the frame
    // pair must be matched before dead-store removal drops its own
    // `rbp = rsp`, and the copy pass feeds the final sweep.
    crate::pass::elide_frame_pointer(&mut ir);
    crate::pass::elide_callee_saves(&mut ir);
    // Inlining exposes fresh identities and fresh single uses, so run the
    // pair a second time. The first sweep removes dead readers that would
    // otherwise look like extra uses of a temporary.
    crate::pass::copy_propagate(&mut ir);
    crate::pass::dce(&mut ir);
    crate::pass::simplify(&mut ir);
    crate::pass::copy_propagate_guarded(&mut ir);
    crate::pass::dce(&mut ir);
    // A final peephole: a read-modify-write reads as one statement.
    crate::pass::fuse_load_op_store(&mut ir);
    crate::pass::simplify(&mut ir);
    crate::pass::dce(&mut ir);
    apply_width_types(&mut ir, &uniform_32);
    apply_dwarf_types(image, function.addr, &mut ir);
    Ok(ir)
}

fn apply_width_types(ir: &mut FunctionIr, uniform_32: &std::collections::HashSet<u16>) {
    // A register the function only ever writes 32 bits wide, or only ever
    // reads 32 bits wide, carries a 32-bit value: its declared type says so.
    let narrow = |ir: &FunctionIr, index: u16| -> bool {
        uniform_32.contains(&index) || narrow_only(ir, index)
    };
    // The return type follows the finished body: narrowing passes can
    // remove the 32-bit writes that once justified a narrower type, and a
    // wide return value that no narrowing explains widens it again.
    // The returned value's own registers decide the type: a computation the
    // body keeps at 32 bits returns 32 bits, and one that touches a wide
    // register that nothing narrows returns 64.
    let ret_is_wide = returns_wide(ir);
    let narrow_return = !ret_is_wide && ir.ret_type == "uint64_t";
    let widen_return =
        ret_is_wide && matches!(ir.ret_type.as_str(), "uint32_t" | "int32_t");
    // Decide every type before touching the parameter list.
    let decided: Vec<bool> = ir
        .params
        .iter()
        .map(|param| {
            narrow(ir, param.index) && !param.ty.ends_with('*') && param.ty != "int32_t"
        })
        .collect();
    let signed: Vec<bool> = ir
        .params
        .iter()
        .map(|param| ir.signed_params.contains(&param.index) && !param.ty.ends_with('*'))
        .collect();
    let decided = decided;
    for ((param, narrow), signed) in ir
        .params
        .iter_mut()
        .zip(decided.iter().copied())
        .zip(signed.iter().copied())
    {
        if signed {
            // The comparison asked for a signed value; the width comes from
            // the body, and an already signed type stays as it is.
            param.ty = match param.ty.as_str() {
                "uint32_t" => "int32_t".to_owned(),
                "uint64_t" => {
                    if narrow {
                        "int32_t"
                    } else {
                        "int64_t"
                    }
                    .to_owned()
                }
                _ => param.ty.clone(),
            };
        } else if narrow {
            param.ty = "uint32_t".to_owned();
        }
    }
    // A signed comparison somewhere in the body says the value it compares
    // is signed, and a function that returns such a value returns it signed.
    let signed_ret = !ir.signed_params.is_empty();
    if narrow_return {
        ir.ret_type = if signed_ret { "int32_t" } else { "uint32_t" }.to_owned();
    }
    if widen_return {
        ir.ret_type = if ir.ret_type == "int32_t" {
            "int64_t".to_owned()
        } else {
            "uint64_t".to_owned()
        };
    }
}

/// The last value assigned to a register anywhere in the body.
fn last_definition(ir: &FunctionIr, index: u16) -> Option<crate::ir::Expr> {
    let mut found = None;
    for block in &ir.blocks {
        for stmt in &block.stmts {
            if let crate::ir::Stmt::Assign { dest, value } = stmt {
                if dest.index == index {
                    found = Some(value.clone());
                }
            }
        }
    }
    found
}

/// True when the function's last return moves a value whose 64-bit inputs
/// are not explained by any narrow use.
fn returns_wide(ir: &FunctionIr) -> bool {
    let Some(value) = ir.blocks.iter().rev().find_map(|block| match block.stmts.last() {
        Some(crate::ir::Stmt::Ret { value }) => Some(value),
        _ => None,
    }) else {
        return false;
    };
    // A wide read of the return register follows one definition: a division
    // narrowed to 32 bits is not wide just because it lands in a 64-bit
    // register. A narrow read already states its width.
    let mut resolved = value.clone();
    if let crate::ir::Expr::Reg { index, width } = value {
        if *width > 32 {
            if let Some(definition) = last_definition(ir, *index) {
                resolved = definition;
            }
        }
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
            // A division or remainder keeps the width of its dividend: the
            // register it happens to land in says nothing about it.
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
        // The address a load reads through says nothing about the width of
        // the value it produces.
        Expr::Load { width, .. } => {
            if *width > 4 {
                wide.push(WIDE_VALUE);
            }
        }
        Expr::SignExtend { value, width } => {
            if *width > 4 {
                wide.push(WIDE_VALUE);
            }
            collect_wide_regs(value, narrow, wide);
        }
        Expr::Select {
            lhs, rhs, then, els, ..
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
        for stmt in &block.stmts {
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
    // A register the body never mentions says nothing about its width.
    if !seen {
        return false;
    }
    if writes {
        !wide_write
    } else {
        reads_narrow
    }
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
            // A 64-bit read that feeds a 32-bit result only contributes its
            // low half: the source can be a 32-bit value. A local is typed by
            // the narrowest use that explains every read, and this is that
            // rule for the trivial case.
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

fn scan_reads(
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
        Expr::SignExtend { value, .. } => {
            scan_reads(value, register, narrow, reads_narrow, seen)
        }
        Expr::Select {
            lhs, rhs, then, els, ..
        } => {
            scan_reads(lhs, register, narrow, reads_narrow, seen);
            scan_reads(rhs, register, narrow, reads_narrow, seen);
            scan_reads(then, register, narrow, reads_narrow, seen);
            scan_reads(els, register, narrow, reads_narrow, seen);
        }
    }
}

/// True when a wide write still only carries 32 bits of information: either
/// it is masked, or the value provably fits.
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

fn apply_dwarf_types(image: &Image, addr: u64, ir: &mut FunctionIr) {
    let Some(types) = crate::dwarf::function_types(image, addr) else {
        return;
    };
    ir.members = types.members.clone();
    if !types.params.is_empty() {
        // The debug info names the parameters the signature already found:
        // a unit that disagrees about how many there are is not trusted to
        // replace the inferred list.
        let mut params = ir.params.clone();
        for (index, (name, ty)) in types.params.iter().enumerate() {
            let Some(param) = params.get_mut(index) else {
                break;
            };
            if let Some(name) = name {
                param.name = name.clone();
            }
            // An unresolved debug type leaves the inferred one in place.
            if !ty.is_empty() {
                param.ty = ty.clone();
            }
        }
        if !params.is_empty() {
            let previous: Vec<String> = ir.params.iter().map(|param| param.name.clone()).collect();
            ir.params = params;
            for access in &mut ir.accesses {
                for (old, new) in previous.iter().zip(ir.params.iter()) {
                    let prefix = format!("{old} ");
                    if let Some(rest) = access.strip_prefix(&prefix) {
                        *access = format!("{} {}", new.name, rest);
                        break;
                    }
                }
            }
        }
    }
    if let Some(ret) = types.ret {
        ir.ret_type = ret;
    }
}

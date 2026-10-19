use std::collections::HashMap;

use crate::ir::{BinOp, Expr, FunctionIr, Stmt};
use crate::render::expr::Ctx;
use crate::render::expr::render_expr;

/// Registers never read wider than 32 bits, so their zero extension can be
/// left out.
pub(crate) fn narrow_registers(ir: &FunctionIr) -> std::collections::HashSet<u16> {
    let mut wide: std::collections::HashSet<u16> = std::collections::HashSet::new();
    let mut seen: std::collections::HashSet<u16> = std::collections::HashSet::new();
    for block in &ir.blocks {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Assign { value, .. } => scan_reads(value, &mut seen, &mut wide),
                Stmt::Store { addr, value, .. } => {
                    scan_reads(addr, &mut seen, &mut wide);
                    scan_reads(value, &mut seen, &mut wide);
                }
                Stmt::Brif { lhs, rhs, .. } => {
                    scan_reads(lhs, &mut seen, &mut wide);
                    scan_reads(rhs, &mut seen, &mut wide);
                }
                Stmt::Ret { value } => scan_reads(value, &mut seen, &mut wide),
                Stmt::BrIndirect { target } => scan_reads(target, &mut seen, &mut wide),
                Stmt::Switch { index, .. } => scan_reads(index, &mut seen, &mut wide),
                _ => {}
            }
        }
    }
    // The x86 segment bases and xmm halves have no 32-bit names to take.
    let named = |index: &u16| {
        ir.isa != crate::loader::Isa::X86_64 || !(16..crate::ir::TEMP_BASE).contains(index)
    };
    seen.into_iter()
        .filter(|index| !wide.contains(index) && named(index))
        .collect()
}

pub(crate) fn scan_reads(
    expr: &Expr,
    seen: &mut std::collections::HashSet<u16>,
    wide: &mut std::collections::HashSet<u16>,
) {
    match expr {
        Expr::Reg { index, width } => {
            seen.insert(*index);
            if u32::from(*width) > 32 {
                wide.insert(*index);
            }
        }
        Expr::Const(_) => {}
        Expr::Bin { op, lhs, rhs } => {
            // A masked read only observes the low 32 bits.
            if matches!(op, BinOp::And)
                && matches!(rhs.as_ref(), Expr::Const(0xffff_ffff))
                && let Expr::Reg { index, .. } = lhs.as_ref()
            {
                seen.insert(*index);
                scan_reads(rhs, seen, wide);
                return;
            }
            scan_reads(lhs, seen, wide);
            scan_reads(rhs, seen, wide);
        }
        Expr::Load { addr, .. } => scan_reads(addr, seen, wide),
        Expr::SignExtend { value, .. } => scan_reads(value, seen, wide),
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => {
            scan_reads(lhs, seen, wide);
            scan_reads(rhs, seen, wide);
            scan_reads(then, seen, wide);
            scan_reads(els, seen, wide);
        }
    }
}

/// `*(T *)(base + i * sizeof T)` indexes the table at `base`.
pub(crate) fn array_access(addr: &Expr, width: u8, ctx: &Ctx<'_>) -> Option<String> {
    let span = u64::from(width);
    let Expr::Bin {
        op: BinOp::Add,
        lhs,
        rhs,
    } = addr
    else {
        return None;
    };
    let (base, index) = match (lhs.as_ref(), rhs.as_ref()) {
        (Expr::Const(base), scaled) => (*base, scaled),
        (scaled, Expr::Const(base)) => (*base, scaled),
        _ => return None,
    };
    let index = match index {
        Expr::Bin {
            op: BinOp::Shl,
            lhs,
            rhs,
        } => match rhs.as_ref() {
            Expr::Const(shift) if (1u64 << (shift & 63)) == span => lhs.as_ref(),
            _ => return None,
        },
        Expr::Bin {
            op: BinOp::Mul,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Const(step), index) | (index, Expr::Const(step)) if *step == span => index,
            _ => return None,
        },
        _ => return None,
    };
    let name = global_name(&Expr::Const(base), width, ctx)?;
    Some(format!("{}[{}]", name, render_expr(index, ctx)))
}

/// Names a constant address in a data section from the access width and the
/// address: `*(uint64_t *)(0x140003000)` reads as `qword_140003000`.
pub(crate) fn global_name(addr: &Expr, width: u8, ctx: &Ctx<'_>) -> Option<String> {
    let Expr::Const(address) = addr else {
        return None;
    };
    if !ctx
        .data_ranges
        .iter()
        .any(|(start, size)| *address >= *start && *address < start.saturating_add(*size))
    {
        return None;
    }
    let kind = match width {
        1 => "byte",
        2 => "word",
        4 => "dword",
        _ => "qword",
    };
    Some(format!("{kind}_{address:x}"))
}

/// Every `register + offset` address a load inside `expr` reads through.
fn field_loads(expr: &Expr, out: &mut Vec<(u16, i64)>) {
    match expr {
        Expr::Load { addr, .. } => {
            if let Some((base, offset)) = member_address(addr) {
                out.push((base, offset));
            }
            field_loads(addr, out);
        }
        Expr::Bin { lhs, rhs, .. } => {
            field_loads(lhs, out);
            field_loads(rhs, out);
        }
        Expr::SignExtend { value, .. } => field_loads(value, out),
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => {
            field_loads(lhs, out);
            field_loads(rhs, out);
            field_loads(then, out);
            field_loads(els, out);
        }
        Expr::Reg { .. } | Expr::Const(_) => {}
    }
}

/// `(pointer register, byte offset)` to the `(width, signed)` of the field there.
pub(crate) type Fields = HashMap<(u16, i64), (u8, bool)>;

/// The pointer parameters and the fields their accesses name, so a member
/// reads as `p->field_0x4` instead of a cast.
pub(crate) fn struct_fields(ir: &FunctionIr) -> (std::collections::HashSet<u16>, Fields) {
    let pointer_params: std::collections::HashSet<u16> = ir
        .params
        .iter()
        .filter(|param| param.ty.is_pointer())
        .map(|param| param.index)
        .collect();
    let mut fields: HashMap<(u16, i64), (u8, bool)> = HashMap::new();
    for block in &ir.blocks {
        for stmt in &block.stmts {
            let (addr, width, signed) = match stmt {
                Stmt::Store {
                    addr, width, value, ..
                } => {
                    let signed = matches!(value, Expr::Const(_));
                    (addr, *width, signed)
                }
                Stmt::Assign { value, .. } => match value {
                    Expr::Load {
                        addr,
                        width,
                        signed,
                        ..
                    } => (addr.as_ref(), *width, *signed),
                    // Loads nested inside a larger expression still name fields.
                    other => {
                        let mut loads = Vec::new();
                        field_loads(other, &mut loads);
                        for (base, offset) in loads {
                            if pointer_params.contains(&base) {
                                fields.entry((base, offset)).or_insert((4, false));
                            }
                        }
                        continue;
                    }
                },
                Stmt::Ret { value } => {
                    let mut loads = Vec::new();
                    field_loads(value, &mut loads);
                    for (base, offset) in loads {
                        if pointer_params.contains(&base) {
                            fields.entry((base, offset)).or_insert((4, false));
                        }
                    }
                    continue;
                }
                _ => continue,
            };
            let Some((base, offset)) = member_address(addr) else {
                continue;
            };
            if !pointer_params.contains(&base) {
                continue;
            }
            fields.entry((base, offset)).or_insert((width, signed));
        }
    }
    (pointer_params, fields)
}

/// `p`, `p + k` or `p - k` as a register index and byte offset.
fn member_address(addr: &Expr) -> Option<(u16, i64)> {
    match addr {
        Expr::Reg { index, .. } => Some((*index, 0)),
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Reg { index, .. }, Expr::Const(delta)) => Some((*index, *delta as i64)),
            (Expr::Const(delta), Expr::Reg { index, .. }) => Some((*index, *delta as i64)),
            _ => None,
        },
        Expr::Bin {
            op: BinOp::Sub,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Reg { index, .. }, Expr::Const(delta)) => Some((*index, -(*delta as i64))),
            _ => None,
        },
        _ => None,
    }
}

/// Renders a member access when the field table has that offset at the
/// access's own width.
pub(crate) fn member_access(addr: &Expr, width: u8, ctx: &Ctx<'_>) -> Option<String> {
    let (base, offset) = member_address(addr)?;
    if !ctx.pointer_params.contains(&base) {
        return None;
    }
    let (field_width, _) = *ctx.fields.get(&(base, offset))?;
    if field_width != width {
        return None;
    }
    if let Some(pointee) = ctx.pointees.get(&base)
        && let Some(name) = ctx.members.get(&(pointee.clone(), offset))
    {
        return Some(format!("{}->{}", ctx.register(base, 64), name));
    }
    Some(format!("{}->field_0x{:x}", ctx.register(base, 64), offset))
}

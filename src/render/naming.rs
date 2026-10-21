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
                // A register passed whole takes the width the callee gives it.
                Stmt::Call { .. } => {
                    for value in stmt.operands() {
                        if !matches!(value, Expr::Reg { .. }) {
                            scan_reads(value, &mut seen, &mut wide);
                        }
                    }
                }
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
            // A read masked to 32 bits or fewer observes only the low 32 bits.
            if matches!(op, BinOp::And)
                && matches!(rhs.as_ref(), Expr::Const(mask) if *mask <= 0xffff_ffff)
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
        Expr::Apply { args, .. } => {
            for arg in args {
                scan_reads(arg, seen, wide);
            }
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

/// `*(T *)(base + a * k1 + b * k2)`, with each scale a multiple of the
/// element size, indexes the table at `base` by `a * (k1 / size) + ...`:
/// a two-dimensional array read as one row after another.
pub(crate) fn flat_array_access(addr: &Expr, width: u8, ctx: &Ctx<'_>) -> Option<String> {
    let size = u64::from(width);
    let mut terms = Vec::new();
    let mut base = None;
    let mut work = vec![addr];
    while let Some(expr) = work.pop() {
        match expr {
            Expr::Bin {
                op: BinOp::Add,
                lhs,
                rhs,
            } => work.extend([lhs.as_ref(), rhs.as_ref()]),
            Expr::Const(value) if base.is_none() => base = Some(*value),
            other => terms.push(other),
        }
    }
    let base = base?;
    if terms.len() < 2 {
        return None;
    }
    // Each term as an index and how many elements one step of it moves; a
    // 32-bit mask on a term that fits changes nothing.
    let scaled = |term: &Expr| -> Option<(Expr, u64)> {
        let term = match term {
            Expr::Bin {
                op: BinOp::And,
                lhs,
                rhs,
            } if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff))
                && crate::render::expr::fits(lhs, 32, ctx) =>
            {
                lhs.as_ref()
            }
            other => other,
        };
        let (index, scale) = match term {
            Expr::Bin {
                op: BinOp::Shl,
                lhs,
                rhs,
            } => match rhs.as_ref() {
                Expr::Const(shift) if *shift < 32 => (lhs.as_ref().clone(), 1u64 << shift),
                _ => return None,
            },
            Expr::Bin {
                op: BinOp::Mul,
                lhs,
                rhs,
            } => match (lhs.as_ref(), rhs.as_ref()) {
                (Expr::Const(step), index) | (index, Expr::Const(step)) => (index.clone(), *step),
                _ => return None,
            },
            _ => return None,
        };
        (scale % size == 0).then_some((index, scale / size))
    };
    let parts: Vec<(Expr, u64)> = terms.into_iter().map(scaled).collect::<Option<_>>()?;
    let name = global_name(&Expr::Const(base), width, ctx)?;
    let index: Vec<String> = parts
        .iter()
        .rev()
        .map(|(index, step)| match step {
            1 => crate::render::expr::operand(index, ctx, 10, false),
            step => format!(
                "{} * 0x{step:x}",
                crate::render::expr::operand(index, ctx, 11, false)
            ),
        })
        .collect();
    Some(format!("{}[{}]", name, index.join(" + ")))
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
    if let Some(name) = ctx.callees.get(address) {
        return Some(super::sanitize(name));
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
/// `(pointer register, byte offset)` to the `(width, signed)` of the field there.
pub(crate) type Fields = HashMap<(u16, i64), (u8, bool)>;

/// The fields the accesses through pointers name, so a member
/// reads as `p->field_0x4` instead of a cast.
pub(crate) fn struct_fields(ir: &FunctionIr) -> Fields {
    fn loads(expr: &Expr, out: &mut Vec<(Expr, u8, bool)>) {
        if let Expr::Load {
            addr,
            width,
            signed,
        } = expr
        {
            out.push((addr.as_ref().clone(), *width, *signed));
        }
        for child in crate::ir::visit::children(expr) {
            loads(child, out);
        }
    }
    // Pointer parameters, and variables whose accesses made a structure.
    let pointer_params: std::collections::HashSet<u16> = ir
        .params
        .iter()
        .filter(|param| param.ty.is_pointer())
        .map(|param| param.index)
        .chain(
            ir.value_types
                .iter()
                .filter(|(_, ty)| ty.pointee_struct().is_some())
                .map(|(index, _)| *index),
        )
        .collect();
    let mut accesses = Vec::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        if let Stmt::Store { addr, width, value } = stmt {
            accesses.push((addr.clone(), *width, matches!(value, Expr::Const(_))));
        }
        for value in stmt.operands() {
            loads(value, &mut accesses);
        }
    }
    let mut fields: Fields = HashMap::new();
    for (addr, width, signed) in accesses {
        if let Some((base, offset)) = member_address(&addr)
            && pointer_params.contains(&base)
        {
            fields.entry((base, offset)).or_insert((width, signed));
        }
    }
    fields
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

/// A recovered structure that arrays are made of: its size and the width of
/// the field at each offset.
pub(crate) struct Layout {
    pub(crate) size: u64,
    pub(crate) fields: HashMap<u64, u8>,
}

/// Renders a member access when the field table has that offset at the
/// access's own width.
pub(crate) fn member_access(addr: &Expr, width: u8, ctx: &Ctx<'_>) -> Option<String> {
    // A pointer to scalars reads as one, or as an array of them.
    if let Some((name, element, index)) = element_index(addr, ctx)
        && element == u64::from(width)
    {
        return Some(match index {
            Expr::Const(0) => format!("*{name}"),
            index => format!("{name}[{}]", render_expr(&index, ctx)),
        });
    }
    // An array of structures reads as an element's field.
    if let Some((element, field)) = array_field(addr, ctx)
        && field == width
    {
        return Some(element);
    }
    let (base, offset) = member_address(addr)?;
    let pointee = ctx.pointees.get(&base)?;
    if ctx.arrays.contains_key(pointee) {
        return None;
    }
    let (field_width, _) = *ctx.fields.get(&(base, offset))?;
    if field_width != width {
        return None;
    }
    if let Some(name) = ctx.members.get(&(pointee.clone(), offset)) {
        return Some(format!("{}->{}", ctx.register(base, 64), name));
    }
    Some(format!("{}->field_0x{:x}", ctx.register(base, 64), offset))
}

/// An address inside an element of an array of structures, as the field
/// there, `p[i].field_0x8` or `p->field_0x8`, and the field's width.
fn array_field(addr: &Expr, ctx: &Ctx<'_>) -> Option<(String, u8)> {
    let (name, _, index, offset, base) = element_terms(addr, ctx)?;
    let layout = ctx.arrays.get(pointee_of(base, ctx)?)?;
    let width = *layout.fields.get(&offset)?;
    let field = format!("field_0x{offset:x}");
    Some((
        match index {
            Expr::Const(0) => format!("{name}->{field}"),
            index => format!("{name}[{}].{field}", render_expr(&index, ctx)),
        },
        width,
    ))
}

/// The address of a field inside an element of an array of structures,
/// `&p[i].field_0x8`; the start of an element reads as `p + i`.
pub(crate) fn field_address(addr: &Expr, ctx: &Ctx<'_>) -> Option<String> {
    if element_index(addr, ctx).is_some() {
        return None;
    }
    let (field, _) = array_field(addr, ctx)?;
    Some(format!("&{field}"))
}

/// The structure the pointer `expr` points at: a register's, or a local's
/// the frame holds it in.
fn pointee_of<'c>(expr: &Expr, ctx: &'c Ctx<'_>) -> Option<&'c String> {
    match expr {
        Expr::Reg { index, .. } => ctx.pointees.get(index),
        Expr::Load { addr, width: 8, .. } => ctx
            .local_pointees
            .get(ctx.slots.get(&render_expr(addr, ctx))?),
        _ => None,
    }
}

/// The name of a pointer to elements and the size of each: a register, or
/// a local the frame holds it in.
pub(crate) fn scalar_pointer(expr: &Expr, ctx: &Ctx<'_>) -> Option<(String, u64)> {
    match expr {
        Expr::Reg { index, .. } => Some((ctx.register(*index, 64), *ctx.elements.get(index)?)),
        Expr::Load { addr, width: 8, .. } => {
            let name = ctx.slots.get(&render_expr(addr, ctx))?;
            Some((name.clone(), *ctx.local_elements.get(name)?))
        }
        _ => None,
    }
}

/// An address through a pointer to elements, `p + i * size + k * size`, as
/// the pointer, the size of its elements, and the element index `i + k`,
/// which C scales by itself.
pub(crate) fn element_index(addr: &Expr, ctx: &Ctx<'_>) -> Option<(String, u64, Expr)> {
    match element_terms(addr, ctx)? {
        (name, size, index, 0, _) => Some((name, size, index)),
        _ => None,
    }
}

/// Whether `addr` is an element of a pointer to `char`.
pub(crate) fn plain_char_access(addr: &Expr, ctx: &Ctx<'_>) -> bool {
    element_terms(addr, ctx).is_some_and(|(name, size, _, offset, _)| {
        size == 1 && offset == 0 && ctx.plain_chars.contains(&name)
    })
}

/// The terms of a sum, each with whether it is subtracted; only constants
/// are.
pub(crate) fn sum_terms<'e>(expr: &'e Expr, negative: bool, out: &mut Vec<(&'e Expr, bool)>) {
    match expr {
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => {
            sum_terms(lhs, negative, out);
            sum_terms(rhs, negative, out);
        }
        Expr::Bin {
            op: BinOp::Sub,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(_)) => {
            sum_terms(lhs, negative, out);
            sum_terms(rhs, !negative, out);
        }
        other => out.push((other, negative)),
    }
}

/// An address through a pointer to elements, `p + i * size + c`, as the
/// pointer, the size of its elements, the element index `i + c / size`,
/// the byte offset `c % size` within that element, and the pointer's term.
fn element_terms<'e>(addr: &'e Expr, ctx: &Ctx<'_>) -> Option<(String, u64, Expr, u64, &'e Expr)> {
    let mut found = Vec::new();
    sum_terms(addr, false, &mut found);
    let mut bases = found
        .iter()
        .enumerate()
        .filter(|(_, (_, negative))| !negative)
        .filter_map(|(at, (term, _))| Some((at, scalar_pointer(term, ctx)?)));
    let (base_at, (base, size)) = bases.next()?;
    if bases.next().is_some() {
        return None;
    }
    let mut constant: u64 = 0;
    let mut index: Option<Expr> = None;
    let mut add = |term: Expr| {
        index = Some(match index.take() {
            Some(sum) => Expr::bin(BinOp::Add, sum, term),
            None => term,
        });
    };
    for (at, (term, negative)) in found.iter().enumerate() {
        match term {
            _ if at == base_at => {}
            Expr::Const(value) if *negative => constant = constant.wrapping_sub(*value),
            Expr::Const(value) => constant = constant.wrapping_add(*value),
            _ if *negative => return None,
            other => {
                let (value, scale) = match other {
                    Expr::Bin {
                        op: BinOp::Mul,
                        lhs,
                        rhs,
                    } => match (lhs.as_ref(), rhs.as_ref()) {
                        (value, Expr::Const(scale)) | (Expr::Const(scale), value) => {
                            (value, *scale)
                        }
                        _ => (*other, 1),
                    },
                    Expr::Bin {
                        op: BinOp::Shl,
                        lhs,
                        rhs,
                    } => match rhs.as_ref() {
                        Expr::Const(shift) if *shift < 64 => (lhs.as_ref(), 1u64 << shift),
                        _ => (*other, 1),
                    },
                    _ => (*other, 1),
                };
                if scale % size != 0 {
                    return None;
                }
                add(match scale / size {
                    1 => value.clone(),
                    step => Expr::bin(BinOp::Mul, value.clone(), Expr::Const(step)),
                });
            }
        }
    }
    let size_signed = i64::try_from(size).ok()?;
    let offset = (constant as i64).rem_euclid(size_signed) as u64;
    let steps = (constant as i64).div_euclid(size_signed);
    let index = match (index, steps) {
        (None, steps) if steps < 0 => Expr::Bin {
            op: BinOp::Sub,
            lhs: Box::new(Expr::Const(0)),
            rhs: Box::new(Expr::Const(steps.unsigned_abs())),
        },
        (None, steps) => Expr::Const(steps as u64),
        (Some(index), 0) => index,
        (Some(index), steps) if steps < 0 => {
            Expr::bin(BinOp::Sub, index, Expr::Const(steps.unsigned_abs()))
        }
        (Some(index), steps) => Expr::bin(BinOp::Add, index, Expr::Const(steps as u64)),
    };
    Some((base, size, index, offset, found[base_at].0))
}

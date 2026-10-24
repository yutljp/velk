use crate::ir::{BinOp, CType, Expr, FunctionIr, Precision, Stmt};
use crate::render::expr::Ctx;
use crate::render::expr::render_expr;
use crate::render::globals::View;

/// Registers never read wider than 32 bits, so their zero extension can be
/// left out.
pub(crate) fn narrow_registers(ir: &FunctionIr) -> std::collections::HashSet<u16> {
    let mut wide: std::collections::HashSet<u16> = std::collections::HashSet::new();
    let mut seen: std::collections::HashSet<u16> = std::collections::HashSet::new();
    for block in &ir.blocks {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Machine { inputs, .. } => {
                    for input in inputs {
                        scan_reads(input, &mut seen, &mut wide);
                    }
                }
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
    array_access_as(addr, width, View::Unsigned(width), ctx)
}

pub(super) fn array_access_as(addr: &Expr, width: u8, view: View, ctx: &Ctx<'_>) -> Option<String> {
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
        other if span == 1 => other,
        _ => return None,
    };
    let name = global_pointer(&Expr::Const(base), view, ctx)?;
    Some(format!(
        "{}[{}]",
        name,
        crate::render::expr::print(index, ctx, 64)
            .address_integer()
            .text
    ))
}

/// `*(T *)(base + a * k1 + b * k2)`, with each scale a multiple of the
/// element size, indexes the table at `base` by `a * (k1 / size) + ...`:
/// a two-dimensional array read as one row after another.
pub(crate) fn flat_array_access(addr: &Expr, width: u8, ctx: &Ctx<'_>) -> Option<String> {
    flat_array_access_as(addr, width, View::Unsigned(width), ctx)
}

pub(super) fn flat_array_access_as(
    addr: &Expr,
    width: u8,
    view: View,
    ctx: &Ctx<'_>,
) -> Option<String> {
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
    let name = global_pointer(&Expr::Const(base), view, ctx)?;
    let index = parts
        .iter()
        .rev()
        .map(|(index, step)| match step {
            1 => index.clone(),
            step => Expr::bin(BinOp::Mul, index.clone(), Expr::Const(*step)),
        })
        .reduce(|sum, term| Expr::bin(BinOp::Add, sum, term))?;
    Some(format!(
        "{}[{}]",
        name,
        crate::render::expr::integer_sum(&index, ctx).text
    ))
}

pub(super) fn global_access(addr: &Expr, width: u8, ctx: &Ctx<'_>) -> Option<String> {
    global_access_as(addr, View::Unsigned(width), ctx)
}

pub(super) fn global_access_as(addr: &Expr, view: View, ctx: &Ctx<'_>) -> Option<String> {
    global_pointer(addr, view, ctx).map(|name| format!("*{name}"))
}

pub(super) fn global_pointer(addr: &Expr, view: View, ctx: &Ctx<'_>) -> Option<String> {
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
    Some(ctx.globals.pointer(*address, view))
}

/// `p`, `p + k` or `p - k` as a register index and byte offset.
fn member_address(addr: &Expr) -> Option<(u16, i64)> {
    match addr {
        Expr::Reg { index, width: 64 } => Some((*index, 0)),
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Reg { index, width: 64 }, Expr::Const(delta)) => Some((*index, *delta as i64)),
            (Expr::Const(delta), Expr::Reg { index, width: 64 }) => Some((*index, *delta as i64)),
            _ => None,
        },
        Expr::Bin {
            op: BinOp::Sub,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Reg { index, width: 64 }, Expr::Const(delta)) => {
                Some((*index, -(*delta as i64)))
            }
            _ => None,
        },
        _ => None,
    }
}

/// A recovered structure that arrays are made of, with its element size.
pub(crate) struct Layout {
    pub(crate) size: u64,
}

pub(crate) struct Place {
    pub(crate) text: String,
    pub(crate) ty: CType,
}

impl Place {
    pub(crate) fn integer(&self) -> Option<(u32, bool)> {
        if let CType::Named(name) = &self.ty
            && name
                .split_whitespace()
                .any(|word| matches!(word, "bool" | "_Bool"))
        {
            return None;
        }
        self.ty.integer()
    }

    pub(crate) fn precision(&self) -> Option<Precision> {
        self.ty.is_sse_float().then(|| {
            if self
                .ty
                .to_string()
                .split_whitespace()
                .any(|word| word == "float")
            {
                Precision::Single
            } else {
                Precision::Double
            }
        })
    }

    pub(crate) fn plain_char(&self) -> bool {
        matches!(&self.ty, CType::Named(name) if name.split_whitespace()
            .filter(|word| !matches!(*word, "const" | "volatile"))
            .eq(["char"]))
    }

    fn scalar(self, width: u64) -> Option<Self> {
        let bits = width * 8;
        (self
            .integer()
            .is_some_and(|(declared, _)| u64::from(declared) == bits)
            || (self.ty.is_pointer() && width == 8)
            || self
                .precision()
                .is_some_and(|precision| u64::from(precision.bits()) == bits))
        .then_some(self)
    }
}

/// Renders a member access when the field table has that offset at the
/// access's own width.
pub(crate) fn member_access(addr: &Expr, width: u8, ctx: &Ctx<'_>) -> Option<Place> {
    if width == 1
        && let Some(part) = ctx.local_parts.get(&render_expr(addr, ctx))
        && !part.contains('&')
    {
        return Some(Place {
            text: format!("*({part})"),
            ty: CType::int(1, false),
        });
    }
    // A pointer to scalars reads as one, or as an array of them.
    if let Some((name, element, index)) = element_index(addr, ctx)
        && element == u64::from(width)
    {
        let (_, _, _, _, base) = element_terms(addr, ctx)?;
        let ty = pointer_target(base, ctx)?;
        let text = match index {
            Expr::Const(0) => format!("*{name}"),
            index => format!(
                "{name}[{}]",
                crate::render::expr::integer_sum(&index, ctx).text
            ),
        };
        return Place { text, ty }.scalar(u64::from(width));
    }
    // An array of structures reads as an element's field.
    if let Some((place, field)) = array_field(addr, ctx)
        && field == u64::from(width)
    {
        return place.scalar(u64::from(width));
    }
    let (base, offset) = member_address(addr)?;
    let pointee = pointee_of(&Expr::reg(base, 64), ctx)?;
    if ctx.arrays.contains_key(&pointee) {
        return None;
    }
    let member = ctx.members.get(&(pointee, offset))?;
    if member.width != u64::from(width) {
        return None;
    }
    Place {
        text: format!("{}->{}", ctx.register(base, 64), member.name),
        ty: member.ty.clone(),
    }
    .scalar(u64::from(width))
}

/// An address inside an element of an array of structures, as the field
/// there, `p[i].field_0x8` or `p->field_0x8`, and the field's width.
fn array_field(addr: &Expr, ctx: &Ctx<'_>) -> Option<(Place, u64)> {
    let (name, _, index, offset, base) = element_terms(addr, ctx)?;
    let structure = pointee_of(base, ctx)?;
    ctx.arrays.get(&structure)?;
    let member = ctx.members.get(&(structure, offset as i64))?;
    Some((
        Place {
            text: match index {
                Expr::Const(0) => format!("{name}->{}", member.name),
                index => format!(
                    "{name}[{}].{}",
                    crate::render::expr::integer_sum(&index, ctx).text,
                    member.name
                ),
            },
            ty: member.ty.clone(),
        },
        member.width,
    ))
}

/// The address of a field inside an element of an array of structures,
/// `&p[i].field_0x8`; the start of an element reads as `p + i`.
pub(crate) fn field_address(addr: &Expr, ctx: &Ctx<'_>) -> Option<String> {
    if element_index(addr, ctx).is_some() {
        return None;
    }
    let (field, _) = array_field(addr, ctx)?;
    Some(format!("&{}", field.text))
}

/// The structure the pointer `expr` points at: a register's, or a local's
/// the frame holds it in.
fn pointee_of(expr: &Expr, ctx: &Ctx<'_>) -> Option<String> {
    let CType::Named(name) = pointer_target(expr, ctx)? else {
        return None;
    };
    name.strip_prefix("struct ").map(str::to_owned)
}

pub(super) fn pointer_target(expr: &Expr, ctx: &Ctx<'_>) -> Option<CType> {
    match expr {
        Expr::Select { then, els, .. } => {
            let target = match (then.as_ref(), els.as_ref()) {
                (Expr::Const(0), other) | (other, Expr::Const(0)) => {
                    return pointer_target(other, ctx);
                }
                _ => pointer_target(then, ctx),
            };
            if target == pointer_target(els, ctx) {
                target
            } else {
                None
            }
        }
        Expr::Reg { index, width: 64 } => ctx.element_types.get(index).cloned(),
        Expr::Load { addr, width: 8, .. } => {
            if let Some(ty) = ctx
                .slots
                .get(&render_expr(addr, ctx))
                .and_then(|name| ctx.local_element_types.get(name))
            {
                return Some(ty.clone());
            }
            let Some(member) = member_access(addr, 8, ctx) else {
                return None;
            };
            let CType::Pointer(target) = member.ty else {
                return None;
            };
            Some(*target)
        }
        Expr::Bin {
            op: BinOp::Add | BinOp::Sub,
            ..
        } => {
            let key = render_expr(expr, ctx);
            if ctx
                .local_parts
                .get(&key)
                .is_some_and(|part| !part.contains('&'))
            {
                return Some(CType::int(1, false));
            }
            if let Some(name) = ctx.slots.get(&key) {
                if let Some(target) = ctx.local_element_types.get(name) {
                    return Some(CType::pointer_to(target.clone()));
                }
                if let Some(width) = ctx.local_widths.get(name) {
                    return Some(CType::int(*width, ctx.signed_locals.contains(name)));
                }
            }
            if ctx
                .local_parts
                .get(&key)
                .is_some_and(|part| !part.contains('&') || part.starts_with("(uint8_t *)&"))
            {
                return Some(CType::int(1, false));
            }
            // Indexed frame addresses are printed as offsets into byte arrays.
            if super::expr::local_plus_offset(expr, ctx).is_some() {
                return Some(CType::int(1, false));
            }
            if let Some((_, _, _, 0, base)) = element_terms(expr, ctx) {
                return pointer_target(base, ctx);
            }
            let mut terms = Vec::new();
            sum_terms(expr, false, &mut terms);
            let mut bases = terms.iter().filter_map(|(term, negative)| {
                if super::expr::byte_pointer(term, ctx).is_some() {
                    Some((*term, *negative, 0))
                } else {
                    scalar_pointer(term, ctx).map(|(_, size)| (*term, *negative, size))
                }
            });
            let Some((base, false, size)) = bases.next() else {
                return None;
            };
            if bases.next().is_some() {
                return None;
            }
            if size == 1 {
                pointer_target(base, ctx)
            } else {
                Some(CType::int(1, false))
            }
        }
        _ => None,
    }
}

fn size_of(ty: &CType, ctx: &Ctx<'_>) -> Option<u64> {
    match ty {
        CType::Pointer(_) => Some(8),
        CType::Named(name) if name.starts_with("struct ") => ctx
            .arrays
            .get(name.strip_prefix("struct ")?)
            .map(|layout| layout.size),
        _ => CType::pointer_to(ty.clone()).pointee_size().map(u64::from),
    }
}

/// The name of a pointer to elements and the size of each: a register, or
/// a local the frame holds it in.
pub(crate) fn scalar_pointer(expr: &Expr, ctx: &Ctx<'_>) -> Option<(String, u64)> {
    match expr {
        Expr::Reg { index, width: 64 } => Some((
            ctx.register(*index, 64),
            size_of(&pointer_target(expr, ctx)?, ctx)?,
        )),
        Expr::Load { addr, width: 8, .. } => {
            let size = size_of(&pointer_target(expr, ctx)?, ctx)?;
            if let Some(name) = ctx.slots.get(&render_expr(addr, ctx)) {
                return Some((name.clone(), size));
            }
            let text = member_access(addr, 8, ctx)?.text;
            let text = if text.starts_with('*') {
                format!("({text})")
            } else {
                text
            };
            Some((text, size))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{CType, Definition, Member, Param, Structure};
    use crate::loader::Isa;

    fn address(offset: u64) -> Expr {
        if offset == 0 {
            Expr::reg(7, 64)
        } else {
            Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(offset))
        }
    }

    fn load(offset: u64, width: u8) -> Expr {
        Expr::Load {
            addr: Box::new(address(offset)),
            width,
            signed: false,
        }
    }

    fn function(stmts: Vec<Stmt>) -> FunctionIr {
        let mut ir = FunctionIr::single_block(Isa::X86_64, stmts);
        ir.params = vec![Param {
            index: 7,
            name: "p".to_owned(),
            ty: CType::pointer_to(CType::Named("struct record".to_owned())),
        }];
        ir
    }

    fn rendered(ir: &FunctionIr) -> String {
        crate::render::render(ir, &[], &crate::render::Symbols::default(), &[])
    }

    #[test]
    fn debug_storage_without_named_fields_uses_raw_memory_accesses() {
        let mut ir = function(vec![
            Stmt::Store {
                addr: address(0),
                value: Expr::Const(5),
                width: 1,
            },
            Stmt::Ret { value: load(0, 1) },
        ]);
        ir.definitions = vec![Definition {
            name: "struct record".to_owned(),
            members: vec!["uint8_t gap_0x0[0x4];".to_owned()],
            fields: Vec::new(),
            contains: Vec::new(),
            size: 4,
            alignment: None,
            compatible_profiles: Vec::new(),
        }];
        let text = rendered(&ir);
        assert!(text.contains("*(uint8_t *)(p) = 5;"), "{text}");
        assert!(text.contains("return *(uint8_t *)(p);"), "{text}");
        assert!(!text.contains("field_0x"), "{text}");
    }

    #[test]
    fn debug_named_fields_remain_named_beside_raw_storage() {
        let mut ir = function(vec![
            Stmt::Store {
                addr: address(4),
                value: Expr::Const(5),
                width: 1,
            },
            Stmt::Ret { value: load(0, 4) },
        ]);
        ir.definitions = vec![Definition {
            name: "struct record".to_owned(),
            members: vec![
                "uint32_t value;".to_owned(),
                "uint8_t gap_0x4[0x4];".to_owned(),
            ],
            fields: vec!["value".to_owned()],
            contains: Vec::new(),
            size: 8,
            alignment: None,
            compatible_profiles: Vec::new(),
        }];
        ir.members = vec![Member {
            structure: "record".to_owned(),
            offset: 0,
            name: "value".to_owned(),
            ty: CType::U32,
            width: 4,
        }];
        let text = rendered(&ir);
        assert!(text.contains("struct record { uint32_t value;"), "{text}");
        assert!(text.contains("return p->value;"), "{text}");
        assert!(
            text.contains("*(uint8_t *)((uint8_t *)p + 0x4) = 5;"),
            "{text}"
        );
        assert!(!text.contains("field_0x"), "{text}");
    }

    #[test]
    fn recovered_fields_remain_named_beside_raw_storage() {
        let mut ir = function(vec![
            Stmt::Store {
                addr: address(8),
                value: Expr::Const(5),
                width: 8,
            },
            Stmt::Store {
                addr: address(4),
                value: Expr::Const(6),
                width: 1,
            },
            Stmt::Ret { value: load(0, 4) },
        ]);
        ir.structures = vec![Structure {
            name: "record".to_owned(),
            fields: vec![(0, CType::U32), (8, CType::U64)],
            size: None,
            elements: Vec::new(),
        }];
        let text = rendered(&ir);
        assert!(text.contains("p->field_0x8 = 5;"), "{text}");
        assert!(text.contains("return p->field_0x0;"), "{text}");
        assert!(
            text.contains("*(uint8_t *)((uint8_t *)p + 0x4) = 6;"),
            "{text}"
        );
        assert!(!text.contains("field_0x4"), "{text}");
    }

    fn declared_member(stmts: Vec<Stmt>, ty: CType, width: u64, declaration: &str) -> FunctionIr {
        let mut ir = function(stmts);
        ir.members = vec![Member {
            structure: "record".to_owned(),
            offset: 0,
            name: "value".to_owned(),
            ty,
            width,
        }];
        ir.definitions = vec![Definition {
            name: "struct record".to_owned(),
            members: vec![declaration.to_owned()],
            fields: vec!["value".to_owned()],
            contains: Vec::new(),
            size: 0,
            alignment: None,
            compatible_profiles: Vec::new(),
        }];
        ir
    }

    #[test]
    fn a_read_spanning_two_declared_fields_keeps_the_full_memory_width() {
        let ir = declared_member(
            vec![Stmt::Ret { value: load(0, 8) }],
            CType::U32,
            4,
            "uint32_t value; uint32_t next;",
        );
        let text = rendered(&ir);
        assert!(text.contains("return *(uint64_t *)(p);"), "{text}");
        assert!(!text.contains("p->value"), "{text}");
    }

    #[test]
    fn a_partial_field_store_does_not_replace_the_whole_declared_member() {
        let ir = declared_member(
            vec![
                Stmt::Store {
                    addr: address(0),
                    width: 1,
                    value: Expr::Const(5),
                },
                Stmt::Ret { value: load(0, 8) },
            ],
            CType::U64,
            8,
            "uint64_t value;",
        );
        let text = rendered(&ir);
        assert!(text.contains("*(uint8_t *)(p) = 5;"), "{text}");
        assert!(text.contains("return p->value;"), "{text}");
        assert!(!text.contains("p->value ="), "{text}");
    }

    #[test]
    fn member_load_extensions_use_the_declared_sign() {
        for (ty, signed, declaration, expected) in [
            (
                CType::I32,
                false,
                "int32_t value;",
                "return (uint32_t)p->value;",
            ),
            (
                CType::U32,
                true,
                "uint32_t value;",
                "return (int32_t)p->value;",
            ),
            (
                CType::Named("char".to_owned()),
                false,
                "char value;",
                "return (uint8_t)p->value;",
            ),
        ] {
            let width = if declaration.starts_with("char") {
                1
            } else {
                4
            };
            let ir = declared_member(
                vec![Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(address(0)),
                        width,
                        signed,
                    },
                }],
                ty,
                u64::from(width),
                declaration,
            );
            let text = rendered(&ir);
            assert!(text.contains(expected), "{expected:?} in {text}");
        }
    }

    #[test]
    fn pointer_members_keep_integer_uses_and_offsets_in_bytes() {
        for (value, expected) in [
            (load(0, 8), "return (uintptr_t)p->value;"),
            (
                Expr::bin(BinOp::Add, load(0, 8), Expr::Const(1)),
                "return (uintptr_t)((uint8_t *)p->value + 0x1);",
            ),
        ] {
            let ir = declared_member(
                vec![Stmt::Ret { value }],
                CType::pointer_to(CType::U32),
                8,
                "uint32_t *value;",
            );
            let text = rendered(&ir);
            assert!(text.contains(expected), "{expected:?} in {text}");
        }
    }

    #[test]
    fn pointer_elements_preserve_dereference_grouping() {
        let mut ir = function(vec![Stmt::Ret {
            value: Expr::Load {
                addr: Box::new(load(0, 8)),
                width: 4,
                signed: false,
            },
        }]);
        ir.params[0].ty = CType::pointer_to(CType::pointer_to(CType::U32));
        let text = rendered(&ir);
        assert!(text.contains("return *(*p);"), "{text}");
    }

    #[test]
    fn an_unknown_pointee_size_keeps_pointer_member_offsets_in_bytes() {
        let ir = declared_member(
            vec![Stmt::Ret {
                value: Expr::bin(BinOp::Add, load(0, 8), Expr::Const(1)),
            }],
            CType::pointer_to(CType::Named("struct unknown".to_owned())),
            8,
            "struct unknown *value;",
        );
        let text = rendered(&ir);
        assert!(
            text.contains("return (uintptr_t)((uint8_t *)p->value + 0x1);"),
            "{text}"
        );
    }

    #[test]
    fn float_fields_are_named_only_when_read_as_their_declared_precision() {
        let mut ir = declared_member(
            vec![Stmt::Ret { value: load(0, 4) }],
            CType::Named("float".to_owned()),
            4,
            "float value;",
        );
        let integer = rendered(&ir);
        assert!(integer.contains("return *(uint32_t *)(p);"), "{integer}");
        ir.ret_type = CType::Named("float".to_owned());
        let floating = rendered(&ir);
        assert!(floating.contains("return p->value;"), "{floating}");
    }

    #[test]
    fn boolean_array_and_aggregate_storage_keeps_raw_accesses() {
        for (ty, width, declaration) in [
            (CType::Named("_Bool".to_owned()), 1, "_Bool value;"),
            (
                CType::Array(Box::new(CType::int(1, false))),
                4,
                "uint8_t value[4];",
            ),
            (
                CType::Named("struct inner".to_owned()),
                4,
                "struct inner value;",
            ),
        ] {
            let ir = declared_member(
                vec![
                    Stmt::Store {
                        addr: address(0),
                        width,
                        value: Expr::Const(2),
                    },
                    Stmt::Ret {
                        value: load(0, width),
                    },
                ],
                ty,
                u64::from(width),
                declaration,
            );
            let text = rendered(&ir);
            assert!(!text.contains("p->value"), "{text}");
            assert!(text.contains(" = 2;"), "{text}");
        }
    }

    #[test]
    fn float_locals_keep_the_bits_of_different_precision_and_partial_stores() {
        let slot = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const((-8i64) as u64));
        let float_sum = |precision, one| Expr::Apply {
            op: crate::ir::Operation::FloatAdd(precision),
            args: vec![Expr::Const(one), Expr::Const(0)],
        };
        for (width, value, expected) in [
            (
                4,
                float_sum(Precision::Double, 0x3ff0_0000_8000_0000),
                "*(uint32_t *)&local_0 = ((union { double value; uint64_t bits; })",
            ),
            (1, Expr::Const(5), "*(uint8_t *)&local_0 = 5;"),
        ] {
            let mut ir = function(vec![
                Stmt::Store {
                    addr: slot.clone(),
                    width: 4,
                    value: float_sum(Precision::Single, u64::from(1.0f32.to_bits())),
                },
                Stmt::Store {
                    addr: slot.clone(),
                    width,
                    value,
                },
                Stmt::Ret {
                    value: Expr::Apply {
                        op: crate::ir::Operation::FloatAdd(Precision::Single),
                        args: vec![
                            Expr::Load {
                                addr: Box::new(slot.clone()),
                                width: 4,
                                signed: false,
                            },
                            Expr::Const(0),
                        ],
                    },
                },
            ]);
            ir.params.clear();
            ir.ret_type = CType::Named("float".to_owned());
            let text = rendered(&ir);
            assert!(text.contains("float local_0;"), "{text}");
            assert!(text.contains(expected), "{expected:?} in {text}");
        }
    }

    #[test]
    fn aggregate_stack_parameters_keep_access_widths_and_unknown_offsets() {
        let stack = |offset| Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const(offset));
        let mut ir = declared_member(
            vec![
                Stmt::Store {
                    addr: stack(13),
                    width: 1,
                    value: Expr::Const(5),
                },
                Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(stack(8)),
                        width: 8,
                        signed: false,
                    },
                },
            ],
            CType::U32,
            4,
            "uint32_t value; uint32_t next;",
        );
        ir.params.clear();
        ir.stack_params = vec![crate::ir::StackParam {
            offset: 8,
            size: 8,
            name: "arg".to_owned(),
            ty: CType::Named("struct record".to_owned()),
            position: 0,
        }];
        let text = rendered(&ir);
        assert!(
            text.contains("*(uint8_t *)((uint8_t *)&arg + 0x5) = 5;"),
            "{text}"
        );
        assert!(
            text.contains("return *(uint64_t *)((uint8_t *)&arg + 0x0);"),
            "{text}"
        );
        assert!(!text.contains("arg.value"), "{text}");
        assert!(!text.contains("field_0x"), "{text}");
    }

    #[test]
    fn a_float_read_of_aggregate_stack_storage_reinterprets_the_loaded_bits() {
        let mut ir = declared_member(
            vec![Stmt::Ret {
                value: Expr::Apply {
                    op: crate::ir::Operation::FloatAdd(Precision::Single),
                    args: vec![
                        Expr::Load {
                            addr: Box::new(Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const(8))),
                            width: 4,
                            signed: false,
                        },
                        Expr::Const(0),
                    ],
                },
            }],
            CType::U32,
            4,
            "uint32_t value;",
        );
        ir.params.clear();
        ir.ret_type = CType::Named("float".to_owned());
        ir.stack_params = vec![crate::ir::StackParam {
            offset: 8,
            size: 4,
            name: "arg".to_owned(),
            ty: CType::Named("struct record".to_owned()),
            position: 0,
        }];
        let text = rendered(&ir);
        assert!(
            text.contains("*(float *)&(*(uint32_t *)((uint8_t *)&arg + 0x0))"),
            "{text}"
        );
        assert!(!text.contains("arg.value"), "{text}");
    }

    #[test]
    fn an_integer_read_of_a_float_local_uses_its_memory_bits() {
        let slot = Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const((-8i64) as u64));
        let mut ir = function(vec![
            Stmt::Store {
                addr: slot.clone(),
                width: 4,
                value: Expr::Apply {
                    op: crate::ir::Operation::FloatAdd(Precision::Single),
                    args: vec![Expr::Const(u64::from(1.0f32.to_bits())), Expr::Const(0)],
                },
            },
            Stmt::Ret {
                value: Expr::Load {
                    addr: Box::new(slot),
                    width: 4,
                    signed: false,
                },
            },
        ]);
        ir.params.clear();
        let text = rendered(&ir);
        assert!(text.contains("float local_0;"), "{text}");
        assert!(text.contains("return *(uint32_t *)&local_0;"), "{text}");
    }

    #[test]
    fn truncated_pointer_addresses_do_not_become_whole_pointer_members() {
        for addr in [
            Expr::reg(7, 32),
            Expr::bin(BinOp::Add, Expr::reg(7, 32), Expr::Const(4)),
            Expr::bin(BinOp::Add, Expr::Const(4), Expr::reg(7, 32)),
            Expr::bin(BinOp::Sub, Expr::reg(7, 32), Expr::Const(4)),
        ] {
            let mut ir = declared_member(
                vec![Stmt::Ret {
                    value: Expr::Load {
                        addr: Box::new(addr),
                        width: 4,
                        signed: false,
                    },
                }],
                CType::U32,
                4,
                "uint32_t value; uint32_t next;",
            );
            ir.members.extend([
                Member {
                    structure: "record".to_owned(),
                    offset: 4,
                    name: "next".to_owned(),
                    ty: CType::U32,
                    width: 4,
                },
                Member {
                    structure: "record".to_owned(),
                    offset: -4,
                    name: "before".to_owned(),
                    ty: CType::U32,
                    width: 4,
                },
            ]);
            let text = rendered(&ir);
            assert!(text.contains("(uint32_t)(uintptr_t)p"), "{text}");
            assert!(!text.contains("p->"), "{text}");
        }
    }
}

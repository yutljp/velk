use crate::arch::stack_pointer;
use std::collections::HashMap;

use crate::ir::CType;
use crate::ir::{BinOp, Expr, FunctionIr, Stmt};
use crate::passes::frame_slots::frame_slot;
use crate::render::expr::Ctx;
use crate::render::expr::render_expr;

/// A named frame slot, with the widest access it receives, and the float
/// or pointer type its uses show.
pub(super) struct Local {
    pub(super) name: String,
    pub(super) slot: i64,
    pub(super) width: u8,
    pub(super) signed: bool,
    pub(super) ty: Option<CType>,
}

pub(crate) struct Locals {
    pub(super) slots: HashMap<String, String>,
    pub(super) widths: HashMap<String, u8>,
    pub(super) decls: Vec<Local>,
}

/// Names frame slots `local_N` in order of first use. Accesses to one slot
/// share the name even when the stack pointer moved between them; a rendered
/// address that maps to two different slots stays unnamed.
pub(crate) fn stack_locals(
    ir: &FunctionIr,
    frames: &[Option<i64>],
    variables: &std::collections::BTreeMap<u16, CType>,
) -> Locals {
    let sp = stack_pointer(ir.isa);
    let base = Ctx {
        isa: ir.isa,
        void_return: ir.ret_type == CType::Void,
        float_return: None,
        names: HashMap::new(),
        landing_pads: HashMap::new(),
        strings: HashMap::new(),
        slots: HashMap::new(),
        local_widths: HashMap::new(),
        local_elements: HashMap::new(),
        local_pointees: HashMap::new(),
        local_scaled: std::collections::HashSet::new(),
        local_floats: HashMap::new(),
        signed_locals: std::collections::HashSet::new(),
        wide_params: std::collections::HashSet::new(),
        fields: HashMap::new(),
        callees: &HashMap::new(),
        data_ranges: &[],
        members: HashMap::new(),
        pointees: HashMap::new(),
        elements: HashMap::new(),
        arrays: HashMap::new(),
        narrow_regs: std::collections::HashSet::new(),
        floats: HashMap::new(),
        scaled: std::collections::HashSet::new(),
        returned: None,
        declared: HashMap::new(),
        value_bits: HashMap::new(),
        taken: Default::default(),
    };
    let mut accesses = frame_accesses(ir, sp, frames);
    // A buffer indexed from several nearby places is one local, from the
    // lowest of them.
    let buffers: Vec<i64> = accesses
        .iter()
        .filter(|(_, _, width, signed)| *width == 0 && *signed == Some(false))
        .filter_map(|(slot, ..)| *slot)
        .collect();
    accesses.retain(|(slot, _, width, signed)| {
        !(*width == 0
            && *signed == Some(false)
            && slot.is_some_and(|slot| {
                buffers
                    .iter()
                    .any(|lower| *lower < slot && slot - *lower < BUFFER_REACH)
            }))
    });
    let mut slot_names: HashMap<i64, Local> = HashMap::new();
    let mut rendered: HashMap<String, Option<i64>> = HashMap::new();
    // The slots some load extends with zeros below 32 bits, or takes as a
    // buffer, and those some load extends with its sign.
    let mut zero_loads = std::collections::HashSet::new();
    let mut sign_loads = std::collections::HashSet::new();
    for (slot, address, width, signed) in &accesses {
        let Some(slot) = slot else {
            continue;
        };
        if !slot_names.contains_key(slot) {
            let name = format!("local_{}", slot_names.len());
            slot_names.insert(
                *slot,
                Local {
                    name,
                    slot: *slot,
                    width: 0,
                    signed: true,
                    ty: None,
                },
            );
        }
        if let Some(local) = slot_names.get_mut(slot) {
            local.width = local.width.max(*width);
            match signed {
                Some(true) => {
                    sign_loads.insert(*slot);
                }
                Some(false) if *width < 4 => {
                    zero_loads.insert(*slot);
                }
                _ => {}
            }
        }
        let key = render_expr(address, &base);
        match rendered.get(&key) {
            Some(Some(existing)) if existing != slot => {
                rendered.insert(key, None);
            }
            Some(_) => {}
            None => {
                rendered.insert(key, Some(*slot));
            }
        }
    }
    // A local only ever pointed at, as a buffer a callee fills, has no
    // width of its own to read: it is declared as a 64-bit one.
    for local in slot_names.values_mut() {
        if local.width == 0 {
            local.width = 8;
        }
        // Only a load's extension says how the value is signed: one of 32
        // bits or fewer that no load extends with its sign is read whole
        // without one.
        local.signed = if local.width <= 4 {
            sign_loads.contains(&local.slot)
        } else {
            !zero_loads.contains(&local.slot)
        };
    }
    let mut slots: HashMap<String, String> = rendered
        .into_iter()
        .filter_map(|(key, slot)| {
            let slot = slot?;
            slot_names.get(&slot).map(|local| (key, local.name.clone()))
        })
        .collect();
    let mut widths: HashMap<String, u8> = slot_names
        .values()
        .map(|local| (local.name.clone(), local.width))
        .collect();
    // A parameter in the caller's frame reads by its name, a structure's
    // part by its field.
    for (address, slot, width) in stack_arguments(ir, sp, frames) {
        let Some(param) = ir.stack_params.iter().find(|param| {
            slot >= param.offset
                && slot.saturating_add(i64::from(width))
                    <= param.offset.saturating_add(param.size as i64)
        }) else {
            continue;
        };
        let within = slot - param.offset;
        let structure = param.ty.to_string();
        let structure = structure
            .strip_prefix("struct ")
            .or_else(|| structure.strip_prefix("union "));
        let name = match structure {
            Some(structure) => match ir
                .members
                .iter()
                .find(|member| member.structure == structure && member.offset == within)
            {
                Some(member) => format!("{}.{}", param.name, member.name),
                None => format!("{}.field_0x{within:x}", param.name),
            },
            None if within == 0 => param.name.clone(),
            None => continue,
        };
        let key = render_expr(&address, &base);
        widths.insert(name.clone(), width);
        slots.insert(key, name);
    }
    let (mut types, signs, points_to) = slot_types(ir, sp, frames, variables);
    // A local holding another's address points at what that one holds.
    for (slot, target) in points_to {
        let Some(target) = slot_names.get(&target) else {
            continue;
        };
        let element = target
            .ty
            .clone()
            .unwrap_or_else(|| CType::int(target.width, target.signed));
        types.entry(slot).or_insert(CType::pointer_to(element));
    }
    for (slot, ty) in types {
        if let Some(local) = slot_names.get_mut(&slot)
            && ty_width(&ty) == Some(local.width)
        {
            local.ty = Some(ty);
        }
    }
    // A signed operation on a local makes it signed, and an unsigned one
    // unsigned unless a signed one reads it too.
    for (slot, signed) in signs {
        if let Some(local) = slot_names.get_mut(&slot) {
            local.signed = signed;
        }
    }
    Locals {
        slots,
        widths,
        decls: slot_names.into_values().collect(),
    }
}

fn ty_width(ty: &CType) -> Option<u8> {
    match ty {
        CType::Pointer(_) => Some(8),
        CType::Named(name) if name == "double" => Some(8),
        CType::Named(name) if name == "float" => Some(4),
        _ => None,
    }
}

/// `float` or `double`.
fn float_type(precision: crate::ir::Precision) -> CType {
    CType::Named(
        match precision {
            crate::ir::Precision::Single => "float",
            crate::ir::Precision::Double => "double",
        }
        .to_owned(),
    )
}

/// The float or pointer type of each local slot: the type of a variable or
/// parameter stored in it or loaded from it, where those agree, or else a
/// float when a float operation reads it, and a pointer when an address
/// adds offsets to it. Pointers that disagree on what they point at point
/// at `void`.
fn slot_types(
    ir: &FunctionIr,
    sp: u16,
    frames: &[Option<i64>],
    variables: &std::collections::BTreeMap<u16, CType>,
) -> (HashMap<i64, CType>, HashMap<i64, bool>, HashMap<i64, i64>) {
    let typed = |index: u16| -> Option<CType> {
        let ty = variables.get(&index).cloned().or_else(|| {
            ir.params
                .iter()
                .find(|param| param.index == index)
                .map(|param| param.ty.clone())
        })?;
        ty_width(&ty).map(|_| ty)
    };
    let mut walk = Walk {
        frame: 0,
        sp,
        strong: Vec::new(),
        weak: Vec::new(),
        signs: Vec::new(),
    };
    let mut points_to: HashMap<i64, Option<i64>> = HashMap::new();
    for (position, block) in ir.blocks.iter().enumerate() {
        let Some(frame) = frames[position] else {
            continue;
        };
        walk.frame = frame;
        for stmt in &block.stmts {
            match stmt {
                Stmt::Store { addr, value, width } => {
                    if let Some(slot) = walk.local(addr) {
                        let ty = match value {
                            Expr::Reg { index, .. } => typed(*index),
                            Expr::Apply { op, .. } => op.result_precision().map(float_type),
                            _ => None,
                        };
                        if let Some(ty) = ty.filter(|ty| ty_width(ty) == Some(*width)) {
                            walk.strong.push((slot, ty));
                        }
                        if let Some(target) = walk.local(value) {
                            points_to.entry(slot).or_insert(Some(target));
                            if points_to[&slot] != Some(target) {
                                points_to.insert(slot, None);
                            }
                        }
                    }
                    walk.address(addr, CType::int(*width, false));
                }
                Stmt::Assign { dest, value } => {
                    if let Expr::Load { addr, .. } = value
                        && let Some(slot) = walk.local(addr)
                        && let Some(ty) = typed(dest.index)
                    {
                        walk.strong.push((slot, ty));
                    }
                }
                Stmt::Brif { cond, lhs, rhs, .. } => walk.compare(*cond, &[lhs, rhs]),
                _ => {}
            }
            for value in stmt.operands() {
                walk.visit(value);
            }
            if let Stmt::Assign { dest, value } = stmt
                && dest.index == sp
                && let Expr::Bin { op, rhs, .. } = value
                && let Expr::Const(delta) = rhs.as_ref()
            {
                walk.frame = match op {
                    BinOp::Add => walk.frame.wrapping_add(*delta as i64),
                    BinOp::Sub => walk.frame.wrapping_sub(*delta as i64),
                    _ => walk.frame,
                };
            }
        }
    }
    let settle = |evidence: Vec<(i64, CType)>| {
        let mut found: HashMap<i64, Option<CType>> = HashMap::new();
        for (slot, ty) in evidence {
            match found.get_mut(&slot) {
                None => {
                    found.insert(slot, Some(ty));
                }
                Some(Some(known)) if *known == ty => {}
                Some(Some(CType::Pointer(_))) if matches!(ty, CType::Pointer(_)) => {
                    found.insert(slot, Some(CType::pointer_to(CType::Void)));
                }
                Some(entry) => *entry = None,
            }
        }
        found
    };
    let strong = settle(std::mem::take(&mut walk.strong));
    let weak = settle(std::mem::take(&mut walk.weak));
    let mut types: HashMap<i64, CType> = weak
        .into_iter()
        .filter_map(|(slot, ty)| Some((slot, ty?)))
        .collect();
    for (slot, ty) in strong {
        match ty {
            Some(ty) => {
                types.insert(slot, ty);
            }
            None => {
                types.remove(&slot);
            }
        }
    }
    let mut signs: HashMap<i64, bool> = HashMap::new();
    for (slot, signed) in walk.signs {
        *signs.entry(slot).or_insert(signed) |= signed;
    }
    let points_to = points_to
        .into_iter()
        .filter_map(|(slot, target)| Some((slot, target?)))
        .filter(|(slot, _)| !types.contains_key(slot))
        .collect();
    (types, signs, points_to)
}

/// The walk `slot_types` makes, with the evidence it gathers by slot:
/// what is stored and loaded, and how the slot is used.
struct Walk {
    frame: i64,
    sp: u16,
    strong: Vec<(i64, CType)>,
    weak: Vec<(i64, CType)>,
    /// The slots signed (`true`) and unsigned operations read.
    signs: Vec<(i64, bool)>,
}

impl Walk {
    /// The local slot an address names.
    fn local(&self, addr: &Expr) -> Option<i64> {
        frame_slot(addr, self.frame, self.sp).filter(|slot| *slot < 0)
    }

    fn loaded(&self, expr: &Expr) -> Option<i64> {
        match expr {
            Expr::Load { addr, .. } => self.local(addr),
            Expr::Bin {
                op: BinOp::And,
                lhs,
                rhs,
            } if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) => self.loaded(lhs),
            Expr::SignExtend { value, .. } => self.loaded(value),
            _ => None,
        }
    }

    /// Notes the slots loaded anywhere in the operands of an operation of
    /// the given sign, other than for an address.
    fn sign(&mut self, signed: bool, operands: &[&Expr]) {
        for operand in operands {
            if let Some(slot) = self.loaded(operand) {
                self.signs.push((slot, signed));
            } else if !matches!(operand, Expr::Load { .. }) {
                self.sign(signed, &crate::ir::visit::children(operand));
            }
        }
    }

    fn compare(&mut self, cond: crate::ir::Cond, operands: &[&Expr]) {
        use crate::ir::Cond;
        match cond {
            Cond::Lt | Cond::Le | Cond::Gt | Cond::Ge => self.sign(true, operands),
            Cond::Cc | Cond::Cs | Cond::Hi | Cond::Ls => self.sign(false, operands),
            _ => {}
        }
    }

    fn visit(&mut self, expr: &Expr) {
        match expr {
            Expr::Apply { op, args } => {
                for arg in args {
                    // A float read from memory: the slot holds one, or the
                    // pointer it goes through points at one.
                    if let (Some(precision), Expr::Load { addr, width, .. }) =
                        (op.argument_precision(), arg)
                        && u32::from(*width) * 8 == u32::from(precision.bits())
                    {
                        match self.loaded(arg) {
                            Some(slot) => self.weak.push((slot, float_type(precision))),
                            None => self.address(addr, float_type(precision)),
                        }
                        self.visit(addr);
                    } else {
                        self.visit(arg);
                    }
                }
                return;
            }
            Expr::Load { addr, width, .. } => self.address(addr, CType::int(*width, false)),
            Expr::Bin { op, lhs, rhs } => match op {
                BinOp::DivS | BinOp::ModS => self.sign(true, &[lhs, rhs]),
                BinOp::DivU | BinOp::ModU => self.sign(false, &[lhs, rhs]),
                BinOp::Sar => self.sign(true, &[lhs]),
                BinOp::Shr => self.sign(false, &[lhs]),
                _ => {}
            },
            Expr::SignExtend { value, .. } => self.sign(true, &[value]),
            Expr::Select { cond, lhs, rhs, .. } => self.compare(*cond, &[lhs, rhs]),
            _ => {}
        }
        for child in crate::ir::visit::children(expr) {
            self.visit(child);
        }
    }

    /// An address that adds offsets to a pointer loaded from a slot makes
    /// that slot a pointer to `element`.
    fn address(&mut self, addr: &Expr, element: CType) {
        let mut terms = vec![addr];
        let mut bases = Vec::new();
        while let Some(term) = terms.pop() {
            match term {
                Expr::Bin {
                    op: BinOp::Add,
                    lhs,
                    rhs,
                } => terms.extend([lhs.as_ref(), rhs.as_ref()]),
                Expr::Bin {
                    op: BinOp::Sub,
                    lhs,
                    rhs,
                } if matches!(rhs.as_ref(), Expr::Const(_)) => terms.push(lhs),
                Expr::Load { width: 8, .. } => bases.extend(self.loaded(term)),
                _ => {}
            }
        }
        if let [slot] = bases.as_slice() {
            self.weak.push((*slot, CType::pointer_to(element)));
        }
    }
}

/// Every load and store anywhere in the function through the caller's
/// frame: its address, its slot from the entry stack pointer, and its width.
fn stack_arguments(ir: &FunctionIr, sp: u16, frames: &[Option<i64>]) -> Vec<(Expr, i64, u8)> {
    fn visit(expr: &Expr, frame: i64, sp: u16, out: &mut Vec<(Expr, i64, u8)>) {
        if let Expr::Load { addr, width, .. } = expr
            && let Some(slot) = frame_slot(addr, frame, sp)
            && slot >= 0
        {
            out.push((addr.as_ref().clone(), slot, *width));
        }
        for child in crate::ir::visit::children(expr) {
            visit(child, frame, sp, out);
        }
    }
    let mut out = Vec::new();
    for (position, block) in ir.blocks.iter().enumerate() {
        let Some(mut frame) = frames[position] else {
            continue;
        };
        for stmt in &block.stmts {
            if let Stmt::Store { addr, width, .. } = stmt
                && let Some(slot) = frame_slot(addr, frame, sp)
                && slot >= 0
            {
                out.push((addr.clone(), slot, *width));
            }
            for value in stmt.operands() {
                visit(value, frame, sp, &mut out);
            }
            if let Stmt::Assign { dest, value } = stmt
                && dest.index == sp
                && let Expr::Bin { op, rhs, .. } = value
                && let Expr::Const(delta) = rhs.as_ref()
            {
                frame = match op {
                    BinOp::Add => frame.wrapping_add(*delta as i64),
                    BinOp::Sub => frame.wrapping_sub(*delta as i64),
                    _ => frame,
                };
            }
        }
    }
    out
}

/// Every local slot a value reads. Only negative slots are locals; a
/// non-negative one is a stack argument and keeps its address.
fn frame_loads(expr: &Expr, frame: i64, sp: u16, out: &mut Vec<(Expr, i64, u8, bool)>) {
    match expr {
        Expr::Load {
            addr,
            width,
            signed,
        } => match frame_slot(addr, frame, sp) {
            Some(slot) if slot < 0 => out.push((addr.as_ref().clone(), slot, *width, *signed)),
            Some(_) => {}
            None => frame_loads(addr, frame, sp, out),
        },
        Expr::Bin { lhs, rhs, .. } => {
            frame_loads(lhs, frame, sp, out);
            frame_loads(rhs, frame, sp, out);
        }
        Expr::SignExtend { value, .. } => frame_loads(value, frame, sp, out),
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => {
            frame_loads(lhs, frame, sp, out);
            frame_loads(rhs, frame, sp, out);
            frame_loads(then, frame, sp, out);
            frame_loads(els, frame, sp, out);
        }
        Expr::Apply { args, .. } => {
            for arg in args {
                frame_loads(arg, frame, sp, out);
            }
        }
        _ => {}
    }
}

/// Every frame-relative store and load, with its slot (when known), the
/// address expression as written, its width, and for a load whether it
/// extends the value with its sign; a buffer whose address is taken counts
/// as a load of no width extended with zeros.
fn frame_accesses(
    ir: &FunctionIr,
    sp: u16,
    frames: &[Option<i64>],
) -> Vec<(Option<i64>, Expr, u8, Option<bool>)> {
    let mut accesses = Vec::new();
    for (position, block) in ir.blocks.iter().enumerate() {
        let Some(frame) = frames[position] else {
            continue;
        };
        let mut frame = frame;
        for stmt in &block.stmts {
            if let Stmt::Assign { dest, value } = stmt
                && dest.index == sp
            {
                if let Expr::Bin { op, rhs, .. } = value
                    && let Expr::Const(delta) = rhs.as_ref()
                {
                    frame = match op {
                        BinOp::Add => frame.wrapping_add(*delta as i64),
                        BinOp::Sub => frame.wrapping_sub(*delta as i64),
                        _ => frame,
                    };
                }
                continue;
            }
            if let Stmt::Store { addr, width, .. } = stmt {
                accesses.push((frame_slot(addr, frame, sp), addr.clone(), *width, None));
            }
            if let Stmt::Assign {
                value:
                    Expr::Load {
                        addr,
                        width,
                        signed,
                    },
                ..
            } = stmt
                && frame_slot(addr, frame, sp).is_some_and(|slot| slot >= 0)
            {
                accesses.push((
                    frame_slot(addr, frame, sp),
                    addr.as_ref().clone(),
                    *width,
                    Some(*signed),
                ));
            }
            // Loads anywhere in the statement, and the addresses of locals
            // it takes as values.
            let mut found = Vec::new();
            let mut taken = Vec::new();
            for value in stmt.operands() {
                let value = match stmt {
                    Stmt::Store { addr, .. } if std::ptr::eq(value, addr) => {
                        // The address a store writes is its access already;
                        // only what it is computed from counts here.
                        if frame_slot(addr, frame, sp).is_some() {
                            continue;
                        }
                        value
                    }
                    _ => value,
                };
                frame_loads(value, frame, sp, &mut found);
                frame_addresses(value, frame, sp, &mut taken);
            }
            for (addr, slot, width, signed) in found {
                accesses.push((Some(slot), addr, width, Some(signed)));
            }
            for (addr, slot, buffer) in taken {
                accesses.push((Some(slot), addr, 0, buffer.then_some(false)));
            }
        }
    }
    accesses
}

/// How far above a buffer's start another indexed place still counts as
/// inside it.
pub(crate) const BUFFER_REACH: i64 = 16;

/// A sum of the stack pointer, constants and other terms, split into the
/// stack pointer plus the constants and the other terms.
pub(crate) fn offset_local(expr: &Expr, sp: u16) -> Option<(Expr, Vec<&Expr>)> {
    fn terms<'a>(expr: &'a Expr, out: &mut Vec<&'a Expr>) {
        match expr {
            Expr::Bin {
                op: BinOp::Add,
                lhs,
                rhs,
            } => {
                terms(lhs, out);
                terms(rhs, out);
            }
            other => out.push(other),
        }
    }
    if !matches!(expr, Expr::Bin { op: BinOp::Add, .. }) {
        return None;
    }
    let mut parts = Vec::new();
    terms(expr, &mut parts);
    let mut base = None;
    let mut offset = 0u64;
    let mut rest = Vec::new();
    for part in parts {
        match part {
            Expr::Reg { index, width: 64 } if *index == sp && base.is_none() => base = Some(part),
            Expr::Const(value) => offset = offset.wrapping_add(*value),
            other => rest.push(other),
        }
    }
    if rest.is_empty() {
        return None;
    }
    Some((
        Expr::bin(BinOp::Add, base?.clone(), Expr::Const(offset)),
        rest,
    ))
}

/// The local slots an expression takes the address of as a value, not to
/// load through.
fn frame_addresses(expr: &Expr, frame: i64, sp: u16, out: &mut Vec<(Expr, i64, bool)>) {
    if let Some(slot) = frame_slot(expr, frame, sp) {
        if slot < 0 {
            out.push((expr.clone(), slot, false));
        }
        return;
    }
    // A local with an offset added, as an index into a buffer: the local
    // starts where the stack pointer and the constants put it.
    if let Some((base, rest)) = offset_local(expr, sp) {
        let slot = frame_slot(&base, frame, sp).unwrap_or(0);
        if slot < 0 {
            out.push((base, slot, true));
        }
        for term in rest {
            frame_addresses(term, frame, sp, out);
        }
        return;
    }
    match expr {
        Expr::Load { addr, .. } if frame_slot(addr, frame, sp).is_some() => {}
        Expr::Load { addr, .. } => frame_addresses(addr, frame, sp, out),
        other => {
            for child in crate::ir::visit::children(other) {
                frame_addresses(child, frame, sp, out);
            }
        }
    }
}

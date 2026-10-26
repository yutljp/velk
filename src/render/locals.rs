mod copies;
mod debug;
mod indexed;
mod returns;
mod values;

pub(super) use returns::fold as fold_returns;
pub(super) use values::fold as fold_values;

use super::unions::MemberIndex;
use crate::arch::stack_pointer;
use std::collections::HashMap;

use crate::ir::CType;
use crate::ir::{BinOp, Expr, FunctionIr, Stmt};
use crate::passes::frame_slots::frame_slot;
use crate::render::expr::render_expr;
use crate::render::expr::{Ctx, type_of};

/// A named frame slot with its access type and byte-array extent.
pub(super) struct Local {
    pub(super) name: String,
    pub(super) slot: i64,
    pub(super) width: u8,
    pub(super) size: i64,
    pub(super) signed: bool,
    pub(super) ty: Option<CType>,
    pub(super) fields: Vec<Local>,
    /// For a field the overlapping accesses of a region share: its union's
    /// members, one per slot and width read or written there.
    pub(super) views: Vec<Local>,
}

impl Local {
    /// The local, its fields and their union members.
    pub(super) fn named(&self) -> impl Iterator<Item = &Local> {
        std::iter::once(self)
            .chain(&self.fields)
            .chain(self.fields.iter().flat_map(|field| &field.views))
    }

    fn byte_address(&self, slot: i64) -> String {
        let offset = slot.saturating_sub(self.slot);
        if self.size > 0 && self.ty.is_some() {
            return if offset == 0 {
                format!("(uint8_t *)&{}", self.name)
            } else {
                format!("(uint8_t *)&{} + 0x{offset:x}", self.name)
            };
        }
        let mut start = 0;
        let mut gap = (self.size > 0 && self.fields.is_empty() && self.ty.is_none())
            .then_some(self.name.clone());
        for field in &self.fields {
            let field_offset = field.slot.saturating_sub(self.slot);
            if offset >= start && offset < field_offset {
                gap = Some(format!("{}.gap_{start:x}", self.name));
                break;
            }
            start = field_offset.saturating_add(i64::from(field.width));
        }
        if gap.is_none() && !self.fields.is_empty() && offset >= start && offset < self.size {
            gap = Some(format!("{}.gap_{start:x}", self.name));
        }
        let (base, delta) = match gap {
            Some(base) => (base, offset.saturating_sub(start)),
            None => (format!("(uint8_t *)&{}", self.name), offset),
        };
        if delta == 0 {
            base
        } else {
            format!("{base} + 0x{delta:x}")
        }
    }
}

pub(crate) struct Locals {
    pub(super) slots: HashMap<String, String>,
    pub(super) parts: HashMap<String, String>,
    pub(super) bounds: HashMap<String, String>,
    pub(super) transfer_addresses: HashMap<String, (String, u64)>,
    pub(super) widths: HashMap<String, u8>,
    /// For a union member named at an address, the other members there,
    /// by width.
    pub(super) views: HashMap<String, Vec<(u8, String)>>,
    pub(super) parameter_addresses: HashMap<(String, u8), String>,
    pub(super) parameter_reads: HashMap<(String, u8), super::expr::ParameterRead>,
    pub(super) decls: Vec<Local>,
}

impl Locals {
    pub(super) fn bind_register_tops(&mut self, ir: &FunctionIr) {
        let Some(saves) = crate::analysis::variadic::register_saves(ir) else {
            return;
        };
        let sp = stack_pointer(ir.isa);
        let frames = crate::passes::frame_slots::block_frames(ir, sp);
        let mut starts = std::collections::HashSet::new();
        let mut ends = std::collections::HashSet::new();
        for (position, block) in ir.blocks.iter().enumerate() {
            let mut frame = frames.get(position).copied().flatten();
            for (index, stmt) in block.stmts.iter().enumerate() {
                if saves.stores.contains(&(position, index))
                    && let Stmt::Store { addr, width, .. } = stmt
                    && let Some(slot) = frame.and_then(|frame| frame_slot(addr, frame, sp))
                    && let Some(end) = slot.checked_add(i64::from(*width))
                {
                    starts.insert(slot);
                    ends.insert(end);
                }
                frame = frame_after(stmt, frame, sp);
            }
        }
        ends.retain(|end| !starts.contains(end));
        for local in &self.decls {
            if local.size == 0 {
                continue;
            }
            let Some(end) = local.slot.checked_add(local.size) else {
                continue;
            };
            if !ends.contains(&end) {
                continue;
            }
            for next in self.decls.iter().filter(|next| next.slot == end) {
                for (key, name) in &self.slots {
                    if *name == next.name {
                        self.parts.insert(key.clone(), local.byte_address(end));
                    }
                }
            }
        }
    }
}

/// Names frame slots in order of first use. Accesses to one slot
/// share the name even when the stack pointer moved between them; a rendered
/// address that maps to two different slots stays unnamed.
#[cfg(test)]
pub(crate) fn stack_locals(
    ir: &FunctionIr,
    frames: &[Option<i64>],
    variables: &std::collections::BTreeMap<u16, CType>,
    symbols: &super::Symbols,
) -> Locals {
    let roles = super::naming::roles::infer(ir, symbols);
    stack_locals_with_roles(ir, frames, variables, symbols, &roles)
}

pub(super) fn stack_locals_with_roles(
    ir: &FunctionIr,
    frames: &[Option<i64>],
    variables: &std::collections::BTreeMap<u16, CType>,
    symbols: &super::Symbols,
    roles: &super::naming::roles::Roles,
) -> Locals {
    let sp = stack_pointer(ir.isa);
    let base = Ctx {
        ir,
        variadic: None,
        go_word_types: Default::default(),
        callee_signatures: Default::default(),
        abi: None,
        call_outputs: Default::default(),
        virtual_tables: Default::default(),
        block_addresses: Default::default(),
        jump_provider: String::new(),
        isa: ir.isa,
        void_return: ir.ret_type == CType::Void,
        float_return: None,
        names: HashMap::new(),
        landing_pads: HashMap::new(),
        strings: HashMap::new(),
        slots: HashMap::new(),
        parameter_addresses: HashMap::new(),
        parameter_reads: HashMap::new(),
        local_parts: HashMap::new(),
        frame_bounds: HashMap::new(),
        call_returns_used: Default::default(),
        transfer_addresses: HashMap::new(),
        frame_origins: HashMap::new(),
        frame_addresses: Vec::new(),
        local_widths: HashMap::new(),
        local_aggregates: HashMap::new(),
        local_views: HashMap::new(),
        local_element_types: HashMap::new(),
        local_scaled: std::collections::HashSet::new(),
        local_floats: HashMap::new(),
        signed_locals: std::collections::HashSet::new(),
        wide_params: std::collections::HashSet::new(),
        symbols: &super::Symbols::default(),
        globals: Default::default(),
        scaled_offsets: Default::default(),
        data_ranges: &[],
        members: HashMap::new(),
        member_views: HashMap::new(),
        element_types: HashMap::new(),
        plain_chars: std::collections::HashSet::new(),
        arrays: HashMap::new(),
        narrow_regs: std::collections::HashSet::new(),
        floats: HashMap::new(),
        readonly_floats: HashMap::new(),
        scaled: std::collections::HashSet::new(),
        returned: None,
        declared: HashMap::new(),
        pointer_types: HashMap::new(),
        local_pointer_types: HashMap::new(),
        ret_pointer: None,
        value_bits: HashMap::new(),
        read_once: Default::default(),
        transfer_values: Default::default(),
        taken: Default::default(),
    };
    let (accesses, elements) = frame_accesses(ir, sp, frames);
    let mut reserved = super::naming::roles::reserved(ir, symbols);
    reserved.extend((0..accesses.len()).map(|index| format!("local_{index}")));
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
                    size: 0,
                    signed: true,
                    ty: None,
                    fields: Vec::new(),
                    views: Vec::new(),
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
    debug::extend(ir, &mut slot_names);
    let extents = buffer_extents(ir, sp, symbols, &accesses);
    let indexed_extents = indexed::extents(ir, sp);
    let buffers: std::collections::HashSet<i64> = accesses
        .iter()
        .filter(|(_, _, width, _)| *width == 0)
        .filter_map(|(slot, ..)| *slot)
        .collect();
    // Buffers read at an index may reach one another, as the fields of an
    // array of records each indexed from their own address do.
    let indexed: std::collections::HashSet<i64> = accesses
        .iter()
        .filter(|(_, _, width, signed)| *width == 0 && *signed == Some(false))
        .filter_map(|(slot, ..)| *slot)
        .collect();
    // A leaf function may use the bytes below the stack pointer, too.
    let bottom = accesses
        .iter()
        .filter_map(|(slot, ..)| *slot)
        .fold(lowest_frame(ir, frames, sp).min(ir.frame_bottom), i64::min);
    let mut lowered: Vec<(i64, i64)> = Vec::new();
    let argument_accesses = stack_arguments(ir, sp, frames);
    let in_parameter = |slot: i64| {
        ir.stack_params.iter().any(|param| {
            slot.checked_sub(param.offset)
                .is_some_and(|within| within >= 0 && (within as u64) < param.size)
        })
    };
    let walked =
        !ir.variadic && !buffers.is_empty() && indexed::offsets_frame_pointer(ir, sp, frames);
    let frame_end = if walked {
        // An induction pointer can advance past the last access before its
        // exit test. Keep such addresses in the same object as the frame.
        argument_accesses
            .iter()
            .filter_map(|(_, slot, width)| slot.filter(|_| *width == 0))
            .filter(|slot| {
                !argument_accesses
                    .iter()
                    .any(|(_, at, width)| at == &Some(*slot) && *width > 0)
                    && !in_parameter(*slot)
            })
            .max()
            .unwrap_or(0)
            .max(0)
    } else {
        0
    };
    if walked && bottom < 0 {
        // Separate slots do not establish separate objects when a pointer
        // reaches them at offsets whose bounds have not been proved.
        lowered.push((bottom, frame_end));
    }
    for (slot, _, width, signed) in &accesses {
        let Some(slot) = slot else { continue };
        if *slot >= 0 || *width != 0 {
            continue;
        }
        // An address taken as a value may reach anything up to another
        // buffer or the top of the frame: what is done through it is not
        // seen here. An index reaches its elements too. In a variadic
        // function an address may be the end of the register save area,
        // which reaches below it instead.
        let next = match signed {
            Some(false) => indexed_end(
                *slot,
                elements.get(slot).copied().flatten(),
                &accesses,
                &buffers,
                &indexed,
                &ir.saved_slots,
            ),
            _ if !ir.variadic => indexed_end(
                *slot,
                None,
                &accesses,
                &buffers,
                &Default::default(),
                &ir.saved_slots,
            ),
            _ => slot_names
                .keys()
                .copied()
                .filter(|next| next > slot)
                .min()
                .unwrap_or(0),
        };
        let proven = extents
            .iter()
            .filter(|(start, _)| **start >= *slot && (**start < next || **start == *slot))
            .map(|(_, end)| *end)
            .max();
        let end = if matches!(ir.isa, crate::loader::Isa::I386 | crate::loader::Isa::Arm32)
            && proven.is_none()
            && signed.is_none()
        {
            // An escaping pointer can advance across other local objects.
            lowered.push((bottom, 0));
            0
        } else {
            proven.unwrap_or(next)
        };
        let end = end.max(indexed_extents.get(slot).copied().unwrap_or(end));
        if let Some(size) = end.checked_sub(*slot)
            && size >= i64::from(slot_names[slot].width)
            && (size > 8 || *signed == Some(false) || proven.is_some())
            && size > 0
            && let Some(local) = slot_names.get_mut(slot)
        {
            local.size = size;
        }
        // An index may be negative too: it reaches down to the bytes below
        // as far as it reaches up.
        if *signed == Some(false)
            && let Some(start) = indexed_start(
                *slot,
                elements.get(slot).copied().flatten(),
                &accesses,
                &buffers,
                &indexed,
                &ir.saved_slots,
                bottom,
            )
            && start < *slot
        {
            lowered.push((start, end.max(slot.saturating_add(1))));
        }
    }
    for (start, end) in lowered {
        let local = slot_names.entry(start).or_insert_with(|| Local {
            name: String::new(),
            slot: start,
            width: 0,
            size: 0,
            signed: true,
            ty: None,
            fields: Vec::new(),
            views: Vec::new(),
        });
        local.size = local.size.max(end.saturating_sub(start));
    }
    // An untyped address still needs scalar storage when no extent is known.
    for local in slot_names.values_mut() {
        if local.width == 0 {
            local.width = if local.size > 0 { 1 } else { 8 };
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
    let mut ordered: Vec<_> = slot_names.keys().copied().collect();
    ordered.sort_unstable();
    let mut outer: Option<i64> = None;
    for slot in ordered {
        if let Some(start) = outer {
            let end = start.saturating_add(
                slot_names[&start]
                    .size
                    .max(i64::from(slot_names[&start].width)),
            );
            if slot < end {
                let next_end = slot.saturating_add(
                    slot_names[&slot]
                        .size
                        .max(i64::from(slot_names[&slot].width)),
                );
                if (next_end > end || slot_names[&start].size > 0 || slot_names[&slot].size > 0)
                    && let Some(local) = slot_names.get_mut(&start)
                {
                    local.size = end.max(next_end).saturating_sub(start);
                }
                continue;
            }
        }
        outer = Some(slot);
    }
    // A slot that lies within a wider local is part of it: as a local of its
    // own, the wider one would not see what is written there.
    let within: HashMap<i64, i64> = slot_names
        .keys()
        .filter_map(|inner| {
            let end = inner.saturating_add(
                slot_names[inner]
                    .size
                    .max(i64::from(slot_names[inner].width)),
            );
            slot_names
                .values()
                .filter(|outer| {
                    outer.slot < *inner
                        && end
                            <= outer
                                .slot
                                .saturating_add(outer.size.max(i64::from(outer.width)))
                })
                .map(|outer| outer.slot)
                .min()
                .map(|outer| (*inner, outer))
        })
        .collect();
    type_storage(ir, sp, frames, variables, &mut slot_names);
    build_regions(&mut slot_names, &within, &accesses);
    slot_names.retain(|slot, _| !within.contains_key(slot));
    let mut order: Vec<i64> = Vec::new();
    for slot in accesses.iter().filter_map(|(slot, ..)| *slot) {
        let slot = within.get(&slot).copied().unwrap_or(slot);
        if slot_names.contains_key(&slot) && !order.contains(&slot) {
            order.push(slot);
        }
    }
    name_storage(
        ir,
        symbols,
        roles,
        &accesses,
        &order,
        &mut slot_names,
        &mut reserved,
    );
    let mut parts: HashMap<String, String> = rendered
        .iter()
        .filter_map(|(key, slot)| {
            let Some(slot) = slot else {
                return None;
            };
            let outer = within.get(slot).copied().unwrap_or(*slot);
            let Some(local) = slot_names.get(&outer) else {
                return None;
            };
            if outer == *slot && local.size == 0 {
                return None;
            }
            Some((key.clone(), local.byte_address(*slot)))
        })
        .collect();
    let mut slots: HashMap<String, String> = rendered
        .iter()
        .filter_map(|(key, slot)| {
            let Some(slot) = slot else {
                return None;
            };
            slot_names
                .get(slot)
                .filter(|local| local.size == 0)
                .map(|local| (key.clone(), local.name.clone()))
        })
        .collect();
    let mut widths: HashMap<String, u8> = slot_names
        .values()
        .map(|local| (local.name.clone(), local.width))
        .collect();
    for local in slot_names.values_mut() {
        for field in &mut local.fields {
            field.name = if field.name.starts_with('[') {
                format!("{}{}", local.name, field.name)
            } else {
                format!("{}.{}", local.name, field.name)
            };
            for view in &mut field.views {
                view.name = format!("{}.{}", field.name, view.name);
            }
        }
    }
    // An address names the field there, or the widest union member there,
    // whose other members of the same address are its views.
    let mut views: HashMap<String, Vec<(u8, String)>> = HashMap::new();
    for (key, slot) in &rendered {
        let Some(slot) = slot else { continue };
        let outer = within.get(slot).copied().unwrap_or(*slot);
        let Some(local) = slot_names.get(&outer) else {
            continue;
        };
        let Some(field) = local
            .fields
            .iter()
            .find(|field| field.slot == *slot || field.views.iter().any(|view| view.slot == *slot))
        else {
            continue;
        };
        let at: Vec<&Local> = field
            .views
            .iter()
            .filter(|view| view.slot == *slot)
            .collect();
        let named = at
            .iter()
            .copied()
            .max_by_key(|view| view.width)
            .unwrap_or(field);
        slots.insert(key.clone(), named.name.clone());
        widths.insert(named.name.clone(), named.width);
        parts.insert(key.clone(), format!("&{}", named.name));
        if at.len() > 1 {
            views.insert(
                named.name.clone(),
                at.iter()
                    .map(|view| (view.width, view.name.clone()))
                    .collect(),
            );
        }
    }
    // An index into a region with fields counts bytes from the region's
    // first byte, not from a field C would scale it by or bound it to.
    for (key, slot) in &rendered {
        let Some(slot) = slot else { continue };
        if !indexed.contains(slot) && !(walked && buffers.contains(slot)) {
            continue;
        }
        let outer = within.get(slot).copied().unwrap_or(*slot);
        let Some(local) = slot_names
            .get(&outer)
            .filter(|local| !local.fields.is_empty())
        else {
            continue;
        };
        let offset = slot.saturating_sub(local.slot);
        let address = if offset == 0 {
            format!("(uint8_t *)&{}", local.name)
        } else {
            format!("(uint8_t *)&{} + 0x{offset:x}", local.name)
        };
        parts.insert(key.clone(), address);
    }
    let mut parameter_reads = HashMap::new();
    let parameter_addresses =
        scalar_parameter_addresses(ir, &argument_accesses, &base, &mut parameter_reads);
    let mut origins: HashMap<String, Option<i64>> = HashMap::new();
    let mut part_origins: HashMap<String, Option<i64>> = HashMap::new();
    let mut access_widths: HashMap<String, Vec<u8>> = HashMap::new();
    for (address, slot, width) in &argument_accesses {
        let key = render_expr(address, &base);
        // A register-valued address consults parts, but not whole-slot names.
        if *width != 0 || !matches!(address, Expr::Reg { .. }) {
            let origin = origins.entry(key.clone()).or_insert(*slot);
            if *origin != *slot {
                *origin = None;
            }
        }
        let origin = part_origins.entry(key.clone()).or_insert(*slot);
        if *origin != *slot {
            *origin = None;
        }
        if *width != 0 {
            let seen = access_widths.entry(key).or_default();
            if !seen.contains(width) {
                seen.push(*width);
            }
        }
    }
    parts.retain(|key, _| !matches!(part_origins.get(key), Some(None)));
    for (key, slot) in &origins {
        if slot.is_none() || slot.is_some_and(in_parameter) {
            slots.remove(key);
            parts.remove(key);
        }
    }
    let mut bounds = HashMap::new();
    // A boundary used only as an address can be one past an existing object.
    for (address, slot, width) in &argument_accesses {
        let Some(slot) = slot else { continue };
        let key = render_expr(address, &base);
        if *width != 0
            || in_parameter(*slot)
            || parts.contains_key(&key)
            || part_origins.get(&key) != Some(&Some(*slot))
            || argument_accesses
                .iter()
                .any(|(_, at, width)| at == &Some(*slot) && *width != 0)
        {
            continue;
        }
        let Some(local) = slot_names
            .values()
            .filter(|local| {
                local.slot < 0
                    && *slot <= frame_end
                    && local.slot < *slot
                    && local
                        .slot
                        .checked_add(local.size.max(i64::from(local.width)))
                        .is_some_and(|end| *slot <= end)
                    && !within.contains_key(&local.slot)
            })
            .min_by_key(|local| local.slot)
        else {
            continue;
        };
        let address = local.byte_address(*slot);
        bounds.insert(key.clone(), address.clone());
        // Incoming variadic storage does not belong to the callee's frame object.
        if !ir.variadic || *slot < 0 {
            parts.insert(key, address);
        }
    }
    let mut bindings: HashMap<String, Option<(String, u8)>> = HashMap::new();
    for (address, slot, width) in &argument_accesses {
        if *width == 0 {
            continue;
        }
        let key = render_expr(address, &base);
        let binding = (|| {
            let Some(slot) = *slot else {
                return None;
            };
            if origins.get(&key) != Some(&Some(slot)) || !matches!(*width, 1 | 2 | 4 | 8) {
                return None;
            }
            let mut parameters = ir.stack_params.iter().filter(|param| {
                slot.checked_sub(param.offset).is_some_and(|within| {
                    within >= 0
                        && (within as u64)
                            .checked_add(u64::from(*width))
                            .is_some_and(|end| end <= param.size)
                })
            });
            let Some(param) = parameters.next() else {
                return None;
            };
            if parameters.next().is_some() {
                return None;
            }
            let Some(within) = slot.checked_sub(param.offset) else {
                return None;
            };
            let spelling = param.ty.to_string();
            let aggregate = spelling.starts_with("struct ") || spelling.starts_with("union ");
            let name = if aggregate {
                format!(
                    "*({} *)((uint8_t *)&{} + 0x{within:x})",
                    type_of(*width, false),
                    param.name
                )
            } else if scalar_storage_size(&param.ty) == Some(*width) && within == 0 {
                param.name.clone()
            } else {
                // Partial scalar accesses use the width-specific byte address below.
                return None;
            };
            if access_widths[&key].iter().any(|other| {
                other != width
                    && (aggregate || !parameter_addresses.contains_key(&(key.clone(), *other)))
            }) {
                return None;
            }
            Some((name, *width))
        })();
        // A partial scalar view does not compete with its whole-storage name.
        if binding.is_none() && parameter_addresses.contains_key(&(key.clone(), *width)) {
            continue;
        }
        let entry = bindings.entry(key).or_insert_with(|| binding.clone());
        if *entry != binding {
            *entry = None;
        }
    }
    for (key, binding) in bindings {
        if let Some((name, width)) = binding {
            widths.insert(name.clone(), width);
            slots.insert(key, name);
        }
    }
    let transfer_addresses = part_origins
        .iter()
        .filter_map(|(key, slot)| {
            let Some(slot) = slot else { return None };
            if !parts.contains_key(key) {
                return None;
            }
            let outer = within.get(slot).copied().unwrap_or(*slot);
            let Some(local) = slot_names.get(&outer).filter(|local| local.size > 0) else {
                return None;
            };
            let Some(offset) = slot.checked_sub(local.slot).filter(|offset| *offset >= 0) else {
                return None;
            };
            let Some(remaining) = local.size.checked_sub(offset).filter(|size| *size > 0) else {
                return None;
            };
            Some((
                key.clone(),
                (
                    format!("(uint8_t *)&{} + 0x{offset:x}", local.name),
                    remaining as u64,
                ),
            ))
        })
        .collect();
    Locals {
        slots,
        parts,
        bounds,
        transfer_addresses,
        widths,
        views,
        parameter_addresses,
        parameter_reads,
        decls: order
            .into_iter()
            .filter_map(|slot| slot_names.remove(&slot))
            .collect(),
    }
}

fn type_storage(
    ir: &FunctionIr,
    sp: u16,
    frames: &[Option<i64>],
    variables: &std::collections::BTreeMap<u16, CType>,
    slot_names: &mut HashMap<i64, Local>,
) {
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
}

fn name_storage(
    ir: &FunctionIr,
    symbols: &super::Symbols,
    roles: &super::naming::roles::Roles,
    accesses: &[FrameAccess],
    order: &[i64],
    slot_names: &mut HashMap<i64, Local>,
    reserved: &mut std::collections::HashSet<String>,
) {
    for (number, slot) in order.iter().enumerate() {
        if let Some(local) = slot_names.get_mut(slot) {
            local.name = format!("local_{number}");
        }
    }
    for local in slot_names.values_mut() {
        if local.size > 0 {
            local.ty = None;
        }
    }
    let mut debug_slots = debug::apply(ir, symbols, slot_names, accesses);
    for ((function, offset), name) in &symbols.stack_names {
        if *function != ir.addr {
            continue;
        }
        if let Some(local) = slot_names.get_mut(offset) {
            local.name = super::vacant_name(name, reserved);
            debug_slots.insert(*offset);
        } else {
            for local in slot_names.values_mut() {
                if let Some(field) = local.fields.iter_mut().find(|field| field.slot == *offset) {
                    field.name = super::vacant_name(name, reserved);
                    debug_slots.insert(local.slot);
                }
            }
        }
    }
    for ((function, offset), ty) in &symbols.stack_types {
        if *function != ir.addr {
            continue;
        }
        if let Some(local) = slot_names.get_mut(offset) {
            local.ty = Some(ty.clone());
            local.signed = ty.integer().is_some_and(|(_, signed)| signed);
        } else {
            for local in slot_names.values_mut() {
                if let Some(field) = local.fields.iter_mut().find(|field| field.slot == *offset) {
                    field.ty = Some(ty.clone());
                    field.signed = ty.integer().is_some_and(|(_, signed)| signed);
                }
            }
        }
    }
    reserved.extend(slot_names.values().map(|local| local.name.clone()));
    for slot in order {
        if debug_slots.contains(slot) {
            continue;
        }
        let role = accesses
            .iter()
            .filter(|(at, ..)| at == &Some(*slot))
            .find_map(|(_, address, ..)| roles.slot(address));
        if let Some(local) = slot_names.get_mut(slot)
            && local.fields.is_empty()
            && local.size == 0
            && let Some(role) = role
        {
            local.name = super::vacant_name(role, reserved);
        }
    }
}

/// The field of the region at `outer` that the overlapping accesses `group`
/// (slot and width, sorted) make: a plain one for a single access, or a
/// union whose members are the accesses' views of one aligned cell.
fn region_field(
    outer: i64,
    group: &[(i64, u8)],
    slot_names: &HashMap<i64, Local>,
    accesses: &[FrameAccess],
) -> Option<Local> {
    let Some(&(start, _)) = group.first() else {
        return None;
    };
    let name = format!("f_{:x}", start.saturating_sub(outer));
    if let [(slot, width)] = group {
        let Some(local) = slot_names.get(slot) else {
            return None;
        };
        if !matches!(width, 1 | 2 | 4 | 8) {
            return None;
        }
        return Some(Local {
            name,
            slot: *slot,
            width: *width,
            size: 0,
            signed: local.signed,
            ty: local.ty.clone(),
            fields: Vec::new(),
            views: Vec::new(),
        });
    }
    let Some(stop) = group
        .iter()
        .map(|(slot, width)| slot.saturating_add(i64::from(*width)))
        .max()
    else {
        return None;
    };
    let relative: Vec<(i64, u8)> = group
        .iter()
        .map(|(slot, width)| (slot.saturating_sub(outer), *width))
        .collect();
    let Some(cell) = super::unions::cell(&relative) else {
        let Ok(span) = u8::try_from(stop - start) else {
            return None;
        };
        return layered_field(outer, group, span, slot_names, accesses);
    };
    // One member per width, signed when a load of that width extends a
    // sign; an array of them when one is read past the cell's start.
    let signed = |width: u8| {
        if width == 8 {
            return slot_names
                .get(&start)
                .is_none_or(|local| local.width != 8 || local.signed);
        }
        accesses.iter().any(|(slot, _, at, sign)| {
            *at == width
                && *sign == Some(true)
                && slot.is_some_and(|slot| slot >= start && slot < stop)
        })
    };
    let views = group
        .iter()
        .map(|(slot, width)| {
            let signed = signed(*width);
            let indexed = group
                .iter()
                .any(|(other, size)| size == width && *other != start);
            let name = super::unions::member(
                *width,
                signed,
                slot - start,
                if indexed {
                    MemberIndex::Array
                } else {
                    MemberIndex::Scalar
                },
            );
            Local {
                name,
                slot: *slot,
                width: *width,
                size: 0,
                signed,
                ty: None,
                fields: Vec::new(),
                views: Vec::new(),
            }
        })
        .collect();
    Some(Local {
        name,
        slot: start,
        width: cell,
        size: 0,
        signed: false,
        ty: None,
        fields: Vec::new(),
        views,
    })
}

/// The union for overlapping accesses that fill no aligned cell, as a copy
/// of a few bytes through two overlapping moves does: each layer of
/// accesses that do not overlap one another is a packed structure in it,
/// whose fields are named by their offsets in the region.
fn layered_field(
    outer: i64,
    group: &[(i64, u8)],
    span: u8,
    slot_names: &HashMap<i64, Local>,
    accesses: &[FrameAccess],
) -> Option<Local> {
    let Some(&(start, _)) = group.first() else {
        return None;
    };
    if group
        .iter()
        .any(|(_, width)| !matches!(width, 1 | 2 | 4 | 8))
    {
        return None;
    }
    let mut ends: Vec<i64> = Vec::new();
    let mut views = Vec::new();
    for (slot, width) in group {
        let end = slot.saturating_add(i64::from(*width));
        let layer = match ends.iter().position(|last| *last <= *slot) {
            Some(layer) => {
                ends[layer] = end;
                layer
            }
            None => {
                ends.push(end);
                ends.len() - 1
            }
        };
        let signed = match slot_names.get(slot) {
            Some(local) if local.width == *width => local.signed,
            _ => accesses.iter().any(|(at, _, size, sign)| {
                *at == Some(*slot) && size == width && *sign == Some(true)
            }),
        };
        views.push(Local {
            name: format!("s{layer}.f_{:x}", slot.saturating_sub(outer)),
            slot: *slot,
            width: *width,
            size: 0,
            signed,
            ty: None,
            fields: Vec::new(),
            views: Vec::new(),
        });
    }
    Some(Local {
        name: format!("f_{:x}", start.saturating_sub(outer)),
        slot: start,
        width: span,
        size: 0,
        signed: false,
        ty: None,
        fields: Vec::new(),
        views,
    })
}

/// Where the reach of an index below the buffer at `slot` starts, when it
/// starts lower: slots below are its own elements as `indexed_end` takes
/// those above, down to the end of a saved register, of a slot that is no
/// element, or the bottom of the frame. Another buffer below reaches up to
/// this one already, unless it is in `crossed`.
fn indexed_start(
    slot: i64,
    element: Option<u8>,
    accesses: &[FrameAccess],
    buffers: &std::collections::HashSet<i64>,
    crossed: &std::collections::HashSet<i64>,
    saved: &[i64],
    bottom: i64,
) -> Option<i64> {
    let mut below: Vec<i64> = accesses
        .iter()
        .filter_map(|(other, ..)| *other)
        .chain(saved.iter().copied())
        .filter(|other| *other < slot && *other >= bottom)
        .collect();
    below.sort_unstable_by(|a, b| b.cmp(a));
    below.dedup();
    let mut start = bottom;
    for other in below {
        let end = accesses
            .iter()
            .filter(|(at, ..)| *at == Some(other))
            .map(|(_, _, width, _)| other.saturating_add(i64::from(*width).max(1)))
            .max()
            .unwrap_or_else(|| other.saturating_add(8))
            .min(slot);
        if saved.contains(&other) {
            start = end;
            break;
        }
        if buffers.contains(&other) && !crossed.contains(&other) {
            return None;
        }
        let Some(element) = element.filter(|element| *element > 0) else {
            continue;
        };
        let element = i64::from(element);
        let foreign = (slot - other) % element != 0
            || accesses.iter().any(|(at, _, width, _)| {
                *at == Some(other)
                    && *width != 0
                    && i64::from(*width) > element
                    && !(matches!(width, 4 | 8 | 16) && i64::from(*width) % element == 0)
            });
        if foreign {
            start = end;
            break;
        }
    }
    (start < slot).then_some(start)
}

/// The lowest the stack pointer goes in the function: below it nothing is
/// the frame's.
fn lowest_frame(ir: &FunctionIr, frames: &[Option<i64>], sp: u16) -> i64 {
    let mut bottom = 0;
    for (position, block) in ir.blocks.iter().enumerate() {
        let mut frame = frames.get(position).copied().flatten();
        for stmt in &block.stmts {
            if let Some(frame) = frame {
                bottom = frame.min(bottom);
            }
            frame = frame_after(stmt, frame, sp);
        }
        if let Some(frame) = frame {
            bottom = frame.min(bottom);
        }
    }
    bottom
}

/// Where the reach of an index into the buffer at `slot` ends. Slots read
/// at fixed offsets above it may be its own elements: one a whole number
/// of elements away and accessed only at the element width, or four, eight
/// or sixteen bytes at a time as an initializer is copied, is taken as one.
/// The first other slot, another buffer or the top of the frame ends it;
/// with no known element width, only another buffer or the top of the frame.
/// A buffer in `crossed` does not end it: the index may reach into it.
/// A slot in `saved` holds a register the function saves, which ends it.
fn indexed_end(
    slot: i64,
    element: Option<u8>,
    accesses: &[FrameAccess],
    buffers: &std::collections::HashSet<i64>,
    crossed: &std::collections::HashSet<i64>,
    saved: &[i64],
) -> i64 {
    let mut above: Vec<i64> = accesses
        .iter()
        .filter_map(|(other, ..)| *other)
        .chain(saved.iter().copied())
        .filter(|other| *other > slot && *other < 0)
        .collect();
    above.sort_unstable();
    above.dedup();
    for other in above {
        if saved.contains(&other) {
            return other;
        }
        if buffers.contains(&other) && !crossed.contains(&other) {
            return other;
        }
        let Some(element) = element.filter(|element| *element > 0) else {
            continue;
        };
        let element = i64::from(element);
        let foreign = (other - slot) % element != 0
            || accesses.iter().any(|(at, _, width, _)| {
                *at == Some(other)
                    && *width != 0
                    && i64::from(*width) > element
                    && !(matches!(width, 4 | 8 | 16) && i64::from(*width) % element == 0)
            });
        if foreign {
            return other;
        }
    }
    0
}

fn buffer_extents(
    ir: &FunctionIr,
    sp: u16,
    symbols: &super::Symbols,
    accesses: &[FrameAccess],
) -> HashMap<i64, i64> {
    use super::stack_bytes::{origin, origins, transfer};
    let mut extents = HashMap::new();
    if ir.blocks.is_empty() {
        return extents;
    }
    let Some(entries) = origins(ir, &std::collections::BTreeMap::from([(sp, Some(0))])) else {
        return extents;
    };
    for (position, block) in ir.blocks.iter().enumerate() {
        let Some(mut state) = entries.get(position).cloned().flatten() else {
            continue;
        };
        for stmt in &block.stmts {
            if let Stmt::Call {
                target,
                through,
                args: Some(args),
                ..
            } = stmt
            {
                let name = match through {
                    Some(Expr::Load { addr, width: 8, .. })
                        if let Expr::Const(slot) = addr.as_ref() =>
                    {
                        symbols.import_name(slot)
                    }
                    None => target.and_then(|target| symbols.semantic_function(target)),
                    _ => None,
                };
                let name = name.map(|name| name.trim_start_matches('_'));
                let buffer = name
                    .and_then(crate::analysis::prototypes::effects::lookup)
                    .and_then(|effects| effects.buffer.as_ref());
                let size = buffer.and_then(|buffer| match args.get(buffer.size) {
                    Some(Expr::Const(size)) => i64::try_from(*size).ok(),
                    _ => None,
                });
                for (index, arg) in args.iter().enumerate() {
                    let Some(Some(slot)) = origin(arg, &state) else {
                        continue;
                    };
                    if slot >= 0 {
                        continue;
                    }
                    let end = match size {
                        Some(size)
                            if buffer.is_some_and(|buffer| buffer.arguments.contains(&index)) =>
                        {
                            slot.checked_add(size).filter(|end| *end <= 0)
                        }
                        _ => {
                            let boundary = accesses
                                .iter()
                                .filter_map(|(offset, _, width, _)| {
                                    let Some(offset) = offset else { return None };
                                    (*offset > slot && *width == 0).then_some(*offset)
                                })
                                .chain(ir.saved_slots.iter().copied().filter(|saved| *saved > slot))
                                .min();
                            boundary.or(Some(0))
                        }
                    };
                    if let Some(end) = end {
                        extents
                            .entry(slot)
                            .and_modify(|old: &mut i64| *old = (*old).max(end))
                            .or_insert(end);
                    }
                }
            }
            transfer(stmt, &mut state);
        }
    }
    extents
}

pub(super) fn scalar_storage_size(ty: &CType) -> Option<u8> {
    if ty.is_pointer() {
        Some(8)
    } else if ty.is_sse_float() {
        Some(if ty.to_string().contains("double") {
            8
        } else {
            4
        })
    } else {
        ty.integer()
            .and_then(|(bits, _)| matches!(bits, 8 | 16 | 32 | 64).then_some((bits / 8) as u8))
    }
}

fn stack_offset(expr: &Expr, frame: i64, sp: u16) -> Option<i64> {
    crate::passes::frame_slots::checked_frame_slot(expr, frame, sp)
}

fn scalar_parameter_addresses(
    ir: &FunctionIr,
    accesses: &[(Expr, Option<i64>, u8)],
    ctx: &Ctx<'_>,
    reads: &mut HashMap<(String, u8), super::expr::ParameterRead>,
) -> HashMap<(String, u8), String> {
    type Source = (String, Option<super::expr::ParameterRead>);
    let mut addresses: HashMap<(String, u8), Option<Source>> = HashMap::new();
    for (addr, slot, width) in accesses {
        let source = (|| {
            if !matches!(*width, 1 | 2 | 4 | 8) {
                return None;
            }
            let Some(slot) = *slot else {
                return None;
            };
            let mut parts = ir.stack_params.iter().filter_map(|param| {
                let Some(size) = scalar_storage_size(&param.ty) else {
                    return None;
                };
                let extent = param.size.min(u64::from(size));
                let Some(within) = slot.checked_sub(param.offset) else {
                    return None;
                };
                let Some(end) = within.checked_add(i64::from(*width)) else {
                    return None;
                };
                (within >= 0 && end <= extent as i64).then_some((param, within, size))
            });
            let Some((param, within, size)) = parts.next() else {
                return None;
            };
            if parts.next().is_some() || (within == 0 && *width == size) {
                return None;
            }
            // Extract bytes in the IR's little-endian order.
            let read = param
                .ty
                .integer()
                .map(|(_, signed)| super::expr::ParameterRead {
                    name: param.name.clone(),
                    size,
                    shift: within as u32 * 8,
                    signed,
                });
            Some((format!("(uint8_t *)&{} + 0x{within:x}", param.name), read))
        })();
        let key = (render_expr(addr, ctx), *width);
        let entry = addresses.entry(key).or_insert_with(|| source.clone());
        if *entry != source {
            *entry = None;
        }
    }
    let mut result = HashMap::new();
    for (key, source) in addresses {
        let Some((address, read)) = source else {
            continue;
        };
        if let Some(read) = read {
            reads.insert(key.clone(), read);
        }
        result.insert(key, address);
    }
    result
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
        let Some(ty) = variables.get(&index).cloned().or_else(|| {
            ir.params
                .iter()
                .find(|param| param.index == index)
                .map(|param| param.ty.clone())
        }) else {
            return None;
        };
        ty_width(&ty).map(|_| ty)
    };
    let mut walk = Walk {
        frame: 0,
        sp,
        strong: Vec::new(),
        weak: Vec::new(),
        signs: Vec::new(),
        offsets: std::collections::HashSet::new(),
    };
    let mut points_to: HashMap<i64, Option<i64>> = HashMap::new();
    let mut constant_slots = std::collections::HashSet::new();
    let literal_offsets = super::variables::literal_offsets(ir);
    for (position, block) in ir.blocks.iter().enumerate() {
        let Some(frame) = frames[position] else {
            continue;
        };
        walk.frame = frame;
        for stmt in &block.stmts {
            match stmt {
                Stmt::Store { addr, value, width } => {
                    if let Some(slot) = walk.local(addr) {
                        if *width == 8
                            && (matches!(value, Expr::Const(_))
                                || matches!(value, Expr::Reg { index, .. } if literal_offsets.contains(index)))
                        {
                            constant_slots.insert(slot);
                        }
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
                    if let Expr::Load { addr, width, .. } = value
                        && let Some(slot) = walk.local(addr)
                    {
                        match typed(dest.index) {
                            Some(ty) => walk.strong.push((slot, ty)),
                            // A value loaded into a variable no type is known
                            // for is used as an integer.
                            None if *width == 8 && dest.width == 64 => {
                                walk.strong.push((slot, CType::int(8, false)))
                            }
                            None => {}
                        }
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
    constant_slots.retain(|slot| walk.offsets.contains(slot));
    types.retain(|slot, ty| !constant_slots.contains(slot) || !ty.is_pointer());
    let mut signs: HashMap<i64, bool> = HashMap::new();
    for (slot, signed) in walk.signs {
        *signs.entry(slot).or_insert(signed) |= signed;
    }
    let points_to = points_to
        .into_iter()
        .filter_map(|(slot, target)| Some((slot, target?)))
        .filter(|(slot, _)| !types.contains_key(slot) && !constant_slots.contains(slot))
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
    offsets: std::collections::HashSet<i64>,
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
                BinOp::Add | BinOp::Sub => {
                    for operand in [lhs, rhs] {
                        if let Some(slot) = self.loaded(operand) {
                            self.offsets.insert(slot);
                        }
                    }
                }
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

    /// A slot is the base only when every other term is an offset. Another
    /// register or load could be the base, leaving the slot an index.
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
                Expr::Load { width: 8, .. } if let Some(slot) = self.loaded(term) => {
                    bases.push(slot);
                }
                Expr::Const(_)
                | Expr::Bin {
                    op: BinOp::Mul | BinOp::Shl,
                    ..
                } => {}
                _ => return,
            }
        }
        if let [slot] = bases.as_slice() {
            self.weak.push((*slot, CType::pointer_to(element)));
        }
    }
}

fn frame_after(stmt: &Stmt, frame: Option<i64>, sp: u16) -> Option<i64> {
    if let Stmt::Assign { dest, value } = stmt
        && dest.index == sp
    {
        frame
            .filter(|_| dest.width == 64)
            .and_then(|frame| stack_offset(value, frame, sp))
    } else if crate::ir::visit::statement_registers(stmt).0.contains(&sp) {
        None
    } else {
        frame
    }
}

/// All memory accesses retain unknown frame origins as evidence against a global name.
fn stack_arguments(
    ir: &FunctionIr,
    sp: u16,
    frames: &[Option<i64>],
) -> Vec<(Expr, Option<i64>, u8)> {
    fn visit(expr: &Expr, frame: Option<i64>, sp: u16, out: &mut Vec<(Expr, Option<i64>, u8)>) {
        if matches!(expr, Expr::Bin { .. })
            || matches!(expr, Expr::Reg { index, .. } if *index == sp)
        {
            out.push((
                expr.clone(),
                frame.and_then(|frame| stack_offset(expr, frame, sp)),
                0,
            ));
        }
        if let Some((Expr::Bin { lhs, rhs, .. }, _)) = offset_local(expr, sp)
            && let Expr::Const(offset) = rhs.as_ref()
        {
            for below in 0..BUFFER_REACH as u64 {
                let base = Expr::bin(
                    BinOp::Add,
                    lhs.as_ref().clone(),
                    Expr::Const(offset.wrapping_sub(below)),
                );
                let slot = frame.and_then(|frame| stack_offset(&base, frame, sp));
                out.push((base, slot, 0));
            }
        }
        if let Expr::Load { addr, width, .. } = expr {
            out.push((
                addr.as_ref().clone(),
                frame.and_then(|frame| stack_offset(addr, frame, sp)),
                *width,
            ));
        }
        for child in crate::ir::visit::children(expr) {
            visit(child, frame, sp, out);
        }
    }
    let invariant = frames.len() == ir.blocks.len()
        && frames.first() == Some(&Some(0))
        && frames
            .iter()
            .all(|frame| frame.is_none() || *frame == Some(0))
        && ir.blocks.iter().all(|block| {
            let mut frame = Some(0);
            block.stmts.iter().all(|stmt| {
                frame = frame_after(stmt, frame, sp);
                !matches!(stmt, Stmt::Unsupported { .. }) && frame == Some(0)
            })
        });
    let frame_at = |index: usize| {
        if invariant {
            Some(0)
        } else {
            frames.get(index).copied().flatten()
        }
    };
    let mut out = Vec::new();
    let mut consistent = frames.first() == Some(&Some(0));
    for (position, block) in ir.blocks.iter().enumerate() {
        let mut frame = frame_at(position);
        let edges = crate::ir::cfg::block_successors_with_exceptions(
            &ir.blocks,
            position,
            &ir.landing_pads,
        );
        consistent &= invariant || (!edges.unknown_normal && !edges.unknown_exceptional);
        for stmt in &block.stmts {
            if let Stmt::Store { addr, width, .. } = stmt {
                out.push((
                    addr.clone(),
                    frame.and_then(|frame| stack_offset(addr, frame, sp)),
                    *width,
                ));
            }
            for value in stmt.operands() {
                visit(value, frame, sp, &mut out);
            }
            frame = frame_after(stmt, frame, sp);
            if matches!(stmt, Stmt::Call { .. }) {
                consistent &= edges
                    .exceptional
                    .iter()
                    .all(|next| frame_at(*next) == frame);
            } else if matches!(stmt, Stmt::Unsupported { .. }) && !edges.exceptional.is_empty() {
                consistent = false;
            }
        }
        consistent &= edges.normal.iter().all(|next| frame_at(*next) == frame);
    }
    if !consistent {
        for (_, slot, _) in &mut out {
            *slot = None;
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

fn build_regions(
    slot_names: &mut HashMap<i64, Local>,
    within: &HashMap<i64, i64>,
    accesses: &[FrameAccess],
) {
    // The fields of each region. An access no other overlaps is a field of
    // its own. Accesses that overlap one another become the members of one
    // union when they fill an aligned cell of two, four or eight bytes, each
    // a whole number of its widths into it, or else of a union of their
    // layers. A region read at an index has fields too: the index counts
    // from the region's first byte, so what it reaches is the same storage.
    let regions: Vec<(i64, i64)> = slot_names
        .values()
        .filter(|local| local.size > 0 && !within.contains_key(&local.slot))
        .map(|local| (local.slot, local.size))
        .collect();
    for (outer, size) in regions {
        let Some(end) = outer.checked_add(size) else {
            continue;
        };
        let inside = |slot: &Option<i64>| slot.is_some_and(|slot| slot >= outer && slot < end);
        // Fields cost each indexed access a cast to bytes and save one for
        // each fixed access: a region read more at an index stays bytes.
        let count = |indexed: bool| {
            accesses
                .iter()
                .filter(|(slot, _, width, signed)| {
                    inside(slot)
                        && if indexed {
                            *width == 0 && *signed == Some(false)
                        } else {
                            *width > 0
                        }
                })
                .count()
        };
        let indexed_accesses = count(true);
        if indexed_accesses > 0 && count(false) <= indexed_accesses {
            continue;
        }
        let mut placed: Vec<(i64, u8)> = accesses
            .iter()
            .filter(|(slot, _, width, _)| *width > 0 && inside(slot))
            .filter_map(|(slot, _, width, _)| slot.map(|slot| (slot, *width)))
            .collect();
        placed.sort_unstable();
        placed.dedup();
        let mut fields = Vec::new();
        let mut first = 0;
        while first < placed.len() {
            let (start, width) = placed[first];
            let mut stop = start.saturating_add(i64::from(width));
            let mut next = first + 1;
            while let Some((slot, width)) = placed.get(next).copied()
                && slot < stop
            {
                stop = stop.max(slot.saturating_add(i64::from(width)));
                next += 1;
            }
            if stop <= end
                && let Some(field) = region_field(outer, &placed[first..next], slot_names, accesses)
            {
                fields.push(field);
            }
            first = next;
        }
        if let Some(local) = slot_names.get_mut(&outer) {
            local.fields = fields;
        }
    }
}

/// A frame access: its slot, when known, the address as written, its width,
/// and for a load whether it extends the value with its sign.
type FrameAccess = (Option<i64>, Expr, u8, Option<bool>);

/// Every frame-relative store and load, with its slot (when known), the
/// address expression as written, its width, and for a load whether it
/// extends the value with its sign; a buffer whose address is taken counts
/// as a load of no width extended with zeros. Also the width of the
/// elements read or written at an index from each indexed buffer, when all
/// such accesses agree on one.
fn frame_accesses(
    ir: &FunctionIr,
    sp: u16,
    frames: &[Option<i64>],
) -> (Vec<FrameAccess>, HashMap<i64, Option<u8>>) {
    let mut accesses = Vec::new();
    let mut elements: HashMap<i64, Option<u8>> = HashMap::new();
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
                let (value, access) = match stmt {
                    Stmt::Store { addr, width, .. } if std::ptr::eq(value, addr) => {
                        // The address a store writes is its access already;
                        // only what it is computed from counts here.
                        if frame_slot(addr, frame, sp).is_some() {
                            continue;
                        }
                        (value, Some(*width))
                    }
                    _ => (value, None),
                };
                frame_loads(value, frame, sp, &mut found);
                if matches!(stmt, Stmt::Brif { .. }) {
                    comparison_addresses(
                        value,
                        frame,
                        sp,
                        ir.convention == crate::ir::Convention::Win64,
                        &mut taken,
                    );
                } else {
                    frame_addresses(
                        value,
                        frame,
                        sp,
                        access,
                        ir.convention == crate::ir::Convention::Win64,
                        &mut taken,
                    );
                }
            }
            for (addr, slot, width, signed) in found {
                accesses.push((Some(slot), addr, width, Some(signed)));
            }
            for (addr, slot, buffer, element) in taken {
                if buffer {
                    elements
                        .entry(slot)
                        .and_modify(|seen| {
                            if *seen != element {
                                *seen = None;
                            }
                        })
                        .or_insert(element);
                }
                accesses.push((Some(slot), addr, 0, buffer.then_some(false)));
            }
        }
    }
    indexed::extend(ir, sp, frames, &mut accesses);
    (accesses, elements)
}

/// How far above a buffer's start another indexed place still counts as
/// inside it.
pub(crate) const BUFFER_REACH: i64 = 16;

/// A sum of the stack pointer, constants and other terms, split into the
/// stack pointer plus the constants and the other terms.
pub(crate) fn offset_local(expr: &Expr, sp: u16) -> Option<(Expr, Vec<Expr>)> {
    fn terms(expr: &Expr, subtract: bool, out: &mut Vec<Expr>) {
        match expr {
            Expr::Bin {
                op: BinOp::Add,
                lhs,
                rhs,
            } => {
                terms(lhs, subtract, out);
                terms(rhs, subtract, out);
            }
            Expr::Bin {
                op: BinOp::Sub,
                lhs,
                rhs,
            } => {
                terms(lhs, subtract, out);
                terms(rhs, !subtract, out);
            }
            Expr::Const(value) if subtract => out.push(Expr::Const(value.wrapping_neg())),
            other if subtract => out.push(Expr::bin(BinOp::Sub, Expr::Const(0), other.clone())),
            other => out.push(other.clone()),
        }
    }
    if !matches!(
        expr,
        Expr::Bin {
            op: BinOp::Add | BinOp::Sub,
            ..
        }
    ) {
        return None;
    }
    let mut parts = Vec::new();
    terms(expr, false, &mut parts);
    let mut base = None;
    let mut offset = 0u64;
    let mut rest = Vec::new();
    for part in parts {
        match part {
            Expr::Reg { index, width: 64 } if index == sp && base.is_none() => base = Some(part),
            Expr::Const(value) => offset = offset.wrapping_add(value),
            other => rest.push(other),
        }
    }
    if rest.is_empty() {
        return None;
    }
    Some((
        Expr::bin(
            BinOp::Add,
            match base {
                Some(value) => value,
                None => return None,
            },
            Expr::Const(offset),
        ),
        rest,
    ))
}

/// The local slots an expression takes the address of as a value, not to
/// load through, whether each is indexed as a buffer, and the width of the
/// access made at an indexed address when the expression is that address.
fn frame_addresses(
    expr: &Expr,
    frame: i64,
    sp: u16,
    access: Option<u8>,
    home: bool,
    out: &mut Vec<(Expr, i64, bool, Option<u8>)>,
) {
    if let Some(slot) = frame_slot(expr, frame, sp) {
        if slot < 0 || (home && (8..40).contains(&slot)) {
            out.push((expr.clone(), slot, false, None));
        }
        return;
    }
    // A local with an offset added, as an index into a buffer: the local
    // starts where the stack pointer and the constants put it.
    if let Some((base, rest)) = offset_local(expr, sp) {
        let slot = frame_slot(&base, frame, sp).unwrap_or(0);
        if slot < 0 {
            out.push((base, slot, true, access));
        }
        for term in rest {
            frame_addresses(&term, frame, sp, None, home, out);
        }
        return;
    }
    match expr {
        Expr::Select {
            lhs,
            rhs,
            then,
            els,
            ..
        } => {
            comparison_addresses(lhs, frame, sp, home, out);
            comparison_addresses(rhs, frame, sp, home, out);
            frame_addresses(then, frame, sp, None, home, out);
            frame_addresses(els, frame, sp, None, home, out);
        }
        Expr::Load { addr, .. } if frame_slot(addr, frame, sp).is_some() => {}
        Expr::Load { addr, width, .. } => frame_addresses(addr, frame, sp, Some(*width), home, out),
        other => {
            for child in crate::ir::visit::children(other) {
                frame_addresses(child, frame, sp, None, home, out);
            }
        }
    }
}

// Comparing an address does not establish storage there; loads still do.
fn comparison_addresses(
    expr: &Expr,
    frame: i64,
    sp: u16,
    home: bool,
    out: &mut Vec<(Expr, i64, bool, Option<u8>)>,
) {
    if matches!(expr, Expr::Load { .. }) {
        frame_addresses(expr, frame, sp, None, home, out);
        return;
    }
    for child in crate::ir::visit::children(expr) {
        comparison_addresses(child, frame, sp, home, out);
    }
}

pub(super) fn bind_return_slot(ir: &FunctionIr, provider: &str, ctx: &mut Ctx<'_>) {
    let sp = stack_pointer(ir.isa);
    let frames = crate::passes::frame_slots::block_frames(ir, sp);
    let home = ir.convention == crate::ir::Convention::Win64
        && ir.stack_params.is_empty()
        && frame_accesses(ir, sp, &frames)
            .0
            .iter()
            .any(|(slot, _, width, _)| {
                *width == 0 && slot.is_some_and(|slot| (8..40).contains(&slot))
            });
    let accesses: Vec<_> = stack_arguments(ir, sp, &frames)
        .into_iter()
        .map(|(address, slot, width)| {
            let key = render_expr(&address, ctx);
            (address, key, slot, width)
        })
        .collect();
    let mut origins = HashMap::new();
    for (_, key, slot, _) in &accesses {
        let origin = origins.entry(key.clone()).or_insert(*slot);
        if *origin != *slot {
            *origin = None;
        }
    }
    for (address, key, slot, width) in &accesses {
        if origins.get(key) != Some(slot) {
            continue;
        }
        match (slot, width) {
            (Some(offset), width) if home && (8..40).contains(offset) => {
                let pointer = format!("((uint8_t *){provider}() + 0x{offset:x})");
                ctx.local_parts.insert(key.clone(), pointer.clone());
                if *width == 0 {
                    ctx.frame_addresses.push((address.clone(), pointer));
                } else if matches!(*width, 1 | 2 | 4 | 8) {
                    let name = format!("*({} *){pointer}", type_of(*width, false));
                    ctx.local_widths.insert(name.clone(), *width);
                    ctx.slots.insert(key.clone(), name);
                }
            }
            (Some(0), 8) => {
                let name = format!("*{provider}()");
                ctx.local_widths.insert(name.clone(), 8);
                ctx.slots.entry(key.clone()).or_insert(name);
                ctx.local_parts
                    .entry(key.clone())
                    .or_insert_with(|| format!("{provider}()"));
            }
            (Some(0), 0) if ir.convention == crate::ir::Convention::Win64 => {
                ctx.frame_addresses
                    .push((address.clone(), format!("{provider}()")));
            }
            (Some(8), 0) => {
                ctx.frame_addresses
                    .push((address.clone(), format!("({provider}() + 1)")));
            }
            _ => {}
        }
    }
    for (address, key, _, _) in accesses {
        let renamed = render_expr(&address, ctx);
        if let Some(name) = ctx.slots.get(&key).cloned() {
            ctx.slots.insert(renamed.clone(), name);
        }
        if let Some(part) = ctx.local_parts.get(&key).cloned() {
            ctx.local_parts.insert(renamed.clone(), part);
        }
        for width in [1, 2, 4, 8] {
            if let Some(read) = ctx.parameter_reads.get(&(key.clone(), width)).cloned() {
                ctx.parameter_reads.insert((renamed.clone(), width), read);
            }
            if let Some(part) = ctx.parameter_addresses.get(&(key.clone(), width)).cloned() {
                ctx.parameter_addresses
                    .insert((renamed.clone(), width), part);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::stack_locals;
    use crate::ir::{
        BinOp, CType, Convention, Expr, FunctionIr, Param, RegRef, StackParam, Stmt, VARIABLE_BASE,
    };
    use crate::loader::Isa;

    #[test]
    fn extended_frame_bounds_exclude_incoming_parameter_addresses() {
        let address = |slot: i64| Expr::bin(BinOp::Add, Expr::reg(4, 64), Expr::Const(slot as u64));
        let mut stmts = Vec::new();
        let values = [
            address(-32),
            Expr::bin(BinOp::Add, Expr::reg(VARIABLE_BASE, 64), Expr::Const(8)),
            address(32),
            address(8),
        ];
        let assignments = values.into_iter().enumerate();
        for (index, value) in assignments {
            stmts.push(Stmt::Assign {
                dest: RegRef {
                    index: VARIABLE_BASE + index as u16,
                    width: 64,
                },
                value,
            });
        }
        let mut ir = FunctionIr::single_block(Isa::X86_64, stmts);
        ir.stack_params.push(StackParam {
            offset: 8,
            size: 8,
            name: "incoming".to_owned(),
            ty: CType::U64,
            position: 0,
        });
        let locals = stack_locals(&ir, &[Some(0)], &Default::default(), &Default::default());
        assert_eq!(locals.decls.len(), 1);
        let local = &locals.decls[0];
        let parameter = local.byte_address(8);
        assert!(!locals.parts.values().any(|address| *address == parameter));
        assert!(!locals.bounds.values().any(|address| *address == parameter));
        assert!(
            locals
                .bounds
                .values()
                .any(|address| *address == local.byte_address(32))
        );
    }

    fn scalar_stack_binding(adjustment: Option<Expr>, slots: i64) -> FunctionIr {
        let loaded = || Expr::Load {
            addr: Box::new(Expr::reg(31, 64)),
            width: 8,
            signed: false,
        };
        let mut stmts = vec![Stmt::Assign {
            dest: RegRef {
                index: VARIABLE_BASE,
                width: 64,
            },
            value: loaded(),
        }];
        if let Some(value) = adjustment {
            stmts.push(Stmt::Assign {
                dest: RegRef {
                    index: 31,
                    width: 64,
                },
                value,
            });
        }
        stmts.push(Stmt::Ret {
            value: Expr::bin(BinOp::Xor, Expr::reg(VARIABLE_BASE, 64), loaded()),
        });
        let mut ir = FunctionIr::single_block(Isa::AArch64, stmts);
        ir.convention = Convention::Aapcs64;
        ir.ret_type = CType::U64;
        ir.params = vec![Param {
            index: 0,
            name: "adjustment".to_owned(),
            ty: CType::U64,
        }];
        ir.stack_params = (0..slots)
            .map(|slot| StackParam {
                offset: slot * 8,
                size: 8,
                name: format!("incoming_{slot}"),
                ty: CType::U64,
                position: slot as usize + 1,
            })
            .collect();
        ir
    }

    #[test]
    fn legacy_stack_binding_rejects_a_dynamic_sp_origin() {
        let ir = scalar_stack_binding(
            Some(Expr::bin(BinOp::Sub, Expr::reg(31, 64), Expr::reg(0, 64))),
            1,
        );
        let frames = crate::passes::frame_slots::block_frames(&ir, 31);
        let locals = stack_locals(&ir, &frames, &Default::default(), &Default::default());
        assert!(locals.slots.is_empty(), "{:?}", locals.slots);
        assert!(locals.parts.is_empty(), "{:?}", locals.parts);
        assert!(locals.parameter_addresses.is_empty());
    }

    #[test]
    fn legacy_stack_binding_rejects_different_constant_sp_origins() {
        let ir = scalar_stack_binding(
            Some(Expr::bin(BinOp::Add, Expr::reg(31, 64), Expr::Const(16))),
            3,
        );
        let frames = crate::passes::frame_slots::block_frames(&ir, 31);
        let locals = stack_locals(&ir, &frames, &Default::default(), &Default::default());
        assert!(locals.slots.is_empty(), "{:?}", locals.slots);
        assert!(locals.parts.is_empty(), "{:?}", locals.parts);
        assert!(locals.parameter_addresses.is_empty());
    }

    #[test]
    fn legacy_stack_binding_keeps_a_stable_sp_origin() {
        let ir = scalar_stack_binding(None, 1);
        let frames = crate::passes::frame_slots::block_frames(&ir, 31);
        let locals = stack_locals(&ir, &frames, &Default::default(), &Default::default());
        assert_eq!(locals.slots.len(), 1);
        assert!(
            locals.slots.values().any(|name| name == "incoming_0"),
            "{:?}",
            locals.slots
        );
        assert!(locals.parameter_addresses.is_empty());
    }
    fn set_access_widths(ir: &mut FunctionIr, first: u8, second: u8) {
        let Stmt::Assign {
            value: Expr::Load { width, .. },
            ..
        } = &mut ir.blocks[0].stmts[0]
        else {
            panic!("expected initial load");
        };
        *width = first;
        let Stmt::Ret {
            value: Expr::Bin { rhs, .. },
        } = ir.blocks[0].stmts.last_mut().unwrap()
        else {
            panic!("expected return expression");
        };
        let Expr::Load { width, .. } = rhs.as_mut() else {
            panic!("expected final load");
        };
        *width = second;
    }

    #[test]
    fn legacy_stack_binding_keeps_a_compatible_partial_view() {
        let mut ir = scalar_stack_binding(None, 1);
        set_access_widths(&mut ir, 8, 4);
        let locals = stack_locals(&ir, &[Some(0)], &Default::default(), &Default::default());
        assert!(locals.slots.values().any(|name| name == "incoming_0"));
        assert_eq!(locals.widths.get("incoming_0"), Some(&8));
        assert_eq!(locals.parameter_addresses.len(), 1);
        assert!(
            locals
                .parameter_addresses
                .keys()
                .any(|(_, width)| *width == 4)
        );
    }

    #[test]
    fn legacy_stack_binding_rejects_an_unsupported_same_address_width() {
        let mut ir = scalar_stack_binding(None, 1);
        set_access_widths(&mut ir, 8, 16);
        let locals = stack_locals(&ir, &[Some(0)], &Default::default(), &Default::default());
        assert!(locals.slots.is_empty(), "{:?}", locals.slots);
        assert!(locals.parts.is_empty());
        assert!(locals.parameter_addresses.is_empty());
    }

    #[test]
    fn legacy_stack_binding_rejects_access_past_actual_scalar_storage() {
        let mut ir = scalar_stack_binding(None, 1);
        ir.stack_params[0].ty = CType::U32;
        set_access_widths(&mut ir, 4, 8);
        let locals = stack_locals(&ir, &[Some(0)], &Default::default(), &Default::default());
        assert!(locals.slots.is_empty(), "{:?}", locals.slots);
        assert!(locals.parts.is_empty());
        assert!(locals.parameter_addresses.is_empty());
    }
    #[derive(Clone, Copy)]
    enum FrameBase {
        Dynamic,
        Fixed,
    }

    fn address_value_binding(dynamic: FrameBase, indexed: bool) -> super::Locals {
        let dynamic = matches!(dynamic, FrameBase::Dynamic);
        let mut ir = scalar_stack_binding(
            dynamic.then(|| Expr::bin(BinOp::Sub, Expr::reg(31, 64), Expr::reg(0, 64))),
            3,
        );
        let Stmt::Assign {
            value: Expr::Load { addr, .. },
            ..
        } = &mut ir.blocks[0].stmts[0]
        else {
            panic!("expected initial load");
        };
        **addr = Expr::bin(BinOp::Add, Expr::reg(31, 64), Expr::Const(16));
        let address = if indexed {
            Expr::bin(
                BinOp::Add,
                Expr::bin(BinOp::Add, Expr::reg(31, 64), Expr::Const(20)),
                Expr::reg(0, 64),
            )
        } else {
            Expr::bin(BinOp::Add, Expr::reg(31, 64), Expr::Const(16))
        };
        *ir.blocks[0].stmts.last_mut().unwrap() = Stmt::Ret { value: address };
        let frames = crate::passes::frame_slots::block_frames(&ir, 31);
        stack_locals(&ir, &frames, &Default::default(), &Default::default())
    }

    #[test]
    fn legacy_stack_binding_rejects_a_dynamic_address_value_origin() {
        let locals = address_value_binding(FrameBase::Dynamic, /* indexed */ false);
        assert!(locals.slots.is_empty(), "{:?}", locals.slots);
        assert!(locals.parts.is_empty());
    }

    #[test]
    fn legacy_stack_binding_keeps_a_stable_address_value_origin() {
        let locals = address_value_binding(FrameBase::Fixed, /* indexed */ false);
        assert!(locals.slots.values().any(|name| name == "incoming_2"));
    }

    #[test]
    fn legacy_stack_binding_rejects_a_dynamic_indexed_address_origin() {
        let locals = address_value_binding(FrameBase::Dynamic, /* indexed */ true);
        assert!(locals.slots.is_empty(), "{:?}", locals.slots);
        assert!(locals.parts.is_empty());
    }

    #[test]
    fn legacy_stack_binding_keeps_a_stable_indexed_address_origin() {
        let locals = address_value_binding(FrameBase::Fixed, /* indexed */ true);
        assert!(locals.slots.values().any(|name| name == "incoming_2"));
    }

    #[test]
    fn legacy_stack_binding_keeps_invariant_sp_with_an_indirect_exit() {
        let mut ir = scalar_stack_binding(None, 1);
        *ir.blocks[0].stmts.last_mut().unwrap() = Stmt::BrIndirect {
            target: Expr::reg(0, 64),
        };
        let locals = stack_locals(&ir, &[Some(0)], &Default::default(), &Default::default());
        assert!(locals.slots.values().any(|name| name == "incoming_0"));
    }
    fn invariant_unknown_entry() -> FunctionIr {
        let mut ir = scalar_stack_binding(None, 1);
        *ir.blocks[0].stmts.last_mut().unwrap() = Stmt::BrIndirect {
            target: Expr::reg(0, 64),
        };
        ir.blocks.push(crate::ir::Block {
            start: 8,
            stmts: vec![Stmt::Ret {
                value: Expr::Load {
                    addr: Box::new(Expr::reg(31, 64)),
                    width: 8,
                    signed: false,
                },
            }],
        });
        ir
    }

    fn binding_call(clobbers: Option<crate::ir::Registers>) -> Stmt {
        Stmt::Call {
            kind: crate::ir::CallKind::Invoke,
            target: Some(0x1000),
            through: None,
            convention: Convention::Aapcs64,
            args: Some(Vec::new()),
            floats_named: false,
            abi: None,
            outputs: crate::ir::fallback_call_outputs(Convention::Aapcs64, clobbers),
            clobbers,
            via: None,
        }
    }

    #[test]
    fn legacy_stack_binding_derives_an_invariant_unknown_entry() {
        let ir = invariant_unknown_entry();
        let locals = stack_locals(
            &ir,
            &[Some(0), None],
            &Default::default(),
            &Default::default(),
        );
        assert!(locals.slots.values().any(|name| name == "incoming_0"));
    }

    #[test]
    fn legacy_stack_binding_derives_an_invariant_exception_entry() {
        let mut ir = invariant_unknown_entry();
        ir.blocks[0].stmts.insert(1, binding_call(None));
        *ir.blocks[0].stmts.last_mut().unwrap() = Stmt::Ret {
            value: Expr::reg(VARIABLE_BASE, 64),
        };
        ir.landing_pads = vec![(8, vec![(0, 4)])];
        let locals = stack_locals(
            &ir,
            &[Some(0), None],
            &Default::default(),
            &Default::default(),
        );
        assert!(locals.slots.values().any(|name| name == "incoming_0"));
    }

    #[test]
    fn legacy_stack_binding_rejects_a_contradictory_known_entry() {
        let ir = invariant_unknown_entry();
        let locals = stack_locals(
            &ir,
            &[Some(0), Some(16)],
            &Default::default(),
            &Default::default(),
        );
        assert!(locals.slots.is_empty());
        assert!(locals.parts.is_empty());
    }

    #[test]
    fn legacy_stack_binding_rejects_an_opaque_unknown_entry() {
        let mut ir = invariant_unknown_entry();
        ir.blocks[1].stmts.insert(
            0,
            Stmt::Unsupported {
                text: "opaque".to_owned(),
                writes: Some(Vec::new()),
            },
        );
        let locals = stack_locals(
            &ir,
            &[Some(0), None],
            &Default::default(),
            &Default::default(),
        );
        assert!(locals.slots.is_empty());
        assert!(locals.parts.is_empty());
    }

    #[test]
    fn legacy_stack_binding_rejects_a_transient_unknown_entry_adjustment() {
        let mut ir = invariant_unknown_entry();
        for (position, op) in [BinOp::Sub, BinOp::Add].into_iter().enumerate() {
            ir.blocks[1].stmts.insert(
                position,
                Stmt::Assign {
                    dest: RegRef {
                        index: 31,
                        width: 64,
                    },
                    value: Expr::bin(op, Expr::reg(31, 64), Expr::Const(16)),
                },
            );
        }
        let locals = stack_locals(
            &ir,
            &[Some(0), None],
            &Default::default(),
            &Default::default(),
        );
        assert!(locals.slots.is_empty());
        assert!(locals.parts.is_empty());
    }

    #[test]
    fn legacy_stack_binding_rejects_a_call_that_clobbers_sp() {
        let mut ir = invariant_unknown_entry();
        ir.blocks[1]
            .stmts
            .insert(0, binding_call(Some([31].into_iter().collect())));
        let locals = stack_locals(
            &ir,
            &[Some(0), None],
            &Default::default(),
            &Default::default(),
        );
        assert!(locals.slots.is_empty());
        assert!(locals.parts.is_empty());
    }
}

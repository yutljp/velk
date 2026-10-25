use super::{Local, scalar_storage_size};
use crate::ir::{CType, DebugLocal, Expr, FunctionIr};
use std::collections::{HashMap, HashSet};

fn supported(ir: &FunctionIr, var: &DebugLocal) -> bool {
    match &var.ty {
        CType::Array(element) => scalar_storage_size(element).is_some_and(|size| {
            var.size.is_multiple_of(u64::from(size)) && !matches!(element.as_ref(), CType::Array(_))
        }),
        CType::Named(name) if name.starts_with("struct ") || name.starts_with("union ") => {
            ir.definitions.iter().any(|def| {
                def.name == *name
                    && !def.fields.is_empty()
                    && def.alignment.is_none_or(|alignment| alignment <= 16)
                    && def.size == var.size
                    && match ir.convention {
                        crate::ir::Convention::SysV => def
                            .compatible_profiles
                            .contains(&crate::ir::AbiProfile::SysV),
                        crate::ir::Convention::Win64 => def
                            .compatible_profiles
                            .contains(&crate::ir::AbiProfile::Win64),
                        crate::ir::Convention::Aapcs64 => def
                            .compatible_profiles
                            .contains(&crate::ir::AbiProfile::Aapcs64),
                        _ => false,
                    }
            })
        }
        ty => {
            scalar_storage_size(ty).is_some_and(|size| u64::from(size) == var.size)
                && !matches!(ty, CType::Named(name) if matches!(name.as_str(), "bool" | "_Bool" | "char"))
        }
    }
}

fn candidates(ir: &FunctionIr) -> Vec<&DebugLocal> {
    ir.debug_locals
        .iter()
        .filter(|var| {
            if !supported(ir, var) {
                return false;
            }
            let Some(end) = i64::try_from(var.size)
                .ok()
                .and_then(|size| var.slot.checked_add(size))
            else {
                return false;
            };
            !ir.debug_locals.iter().any(|other| {
                !std::ptr::eq(*var, other)
                    && other.slot < end
                    && i128::from(other.slot) + i128::from(other.size) > i128::from(var.slot)
            })
        })
        .collect()
}

pub(super) fn extend(ir: &FunctionIr, slots: &mut HashMap<i64, Local>) {
    for var in candidates(ir) {
        let aggregate = matches!(var.ty, CType::Array(_))
            || matches!(&var.ty, CType::Named(name) if name.starts_with("struct ") || name.starts_with("union "));
        if !aggregate {
            continue;
        }
        let Ok(size) = i64::try_from(var.size) else {
            continue;
        };
        let Some(end) = var.slot.checked_add(size) else {
            continue;
        };
        if slots.values().any(|local| {
            let local_end = local
                .slot
                .saturating_add(local.size.max(i64::from(local.width)));
            local.slot < end && local_end > var.slot && (local.slot < var.slot || local_end > end)
        }) {
            continue;
        }
        if !slots.keys().any(|slot| *slot >= var.slot && *slot < end) {
            continue;
        }
        slots
            .entry(var.slot)
            .or_insert_with(|| Local {
                name: String::new(),
                slot: var.slot,
                width: 1,
                size: 0,
                signed: false,
                ty: None,
                fields: Vec::new(),
                views: Vec::new(),
            })
            .size = size;
    }
}

pub(super) fn apply(
    ir: &FunctionIr,
    symbols: &crate::render::Symbols,
    slots: &mut HashMap<i64, Local>,
    accesses: &[(Option<i64>, Expr, u8, Option<bool>)],
) -> HashSet<i64> {
    let mut applied = HashSet::new();
    let mut reserved: HashSet<_> = slots
        .values()
        .map(|local| local.name.clone())
        .chain(ir.params.iter().map(|param| param.name.clone()))
        .chain(ir.stack_params.iter().map(|param| param.name.clone()))
        .chain(symbols.functions.values().cloned())
        .chain(symbols.import_slots.values().cloned())
        .chain(symbols.data.values().cloned())
        .chain(symbols.reserved_names.iter().cloned())
        .collect();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        let (writes, reads) = crate::ir::visit::statement_registers(stmt);
        for reg in writes.into_iter().chain(reads) {
            for width in [8, 16, 32, 64] {
                reserved.insert(crate::ir::reg_name(ir.isa, reg, width));
            }
        }
    }
    if let Some(name) = &ir.name {
        reserved.insert(crate::render::sanitize(name));
    }
    for var in candidates(ir) {
        let Some(local) = slots.get_mut(&var.slot) else {
            continue;
        };
        let aggregate = local.size > 0;
        if (aggregate && u64::try_from(local.size) != Ok(var.size))
            || (!aggregate && u64::from(local.width) != var.size)
        {
            continue;
        }
        // Do not turn a byte buffer or a differently typed value into a scalar.
        if aggregate && scalar_storage_size(&var.ty).is_some() {
            continue;
        }
        if !aggregate
            && (local.ty.as_ref().is_some_and(|ty| ty != &var.ty)
                || (var.ty.integer().is_none() && local.ty.as_ref() != Some(&var.ty)))
        {
            continue;
        }
        let mut name = var.name.clone();
        let mut suffix = 2u64;
        while reserved.contains(&name) || crate::render::globals::reserved_identifier(&name) {
            name = format!("{}_{suffix}", var.name);
            suffix = suffix.saturating_add(1);
        }
        reserved.insert(name.clone());
        local.name = name;
        applied.insert(var.slot);
        if let Some((bits, signed)) = var.ty.integer() {
            if u64::from(bits) == var.size.saturating_mul(8) {
                // Preserve unsigned arithmetic when the recovered loads require it.
                local.signed &= signed;
                // Debug names such as Rust's i32 need C storage types.
                local.ty = Some(
                    if local.signed == signed
                        && CType::pointer_to(var.ty.clone()).pointee_size() == Some(local.width)
                    {
                        var.ty.clone()
                    } else {
                        CType::int(local.width, local.signed)
                    },
                );
            }
        } else {
            local.ty = Some(var.ty.clone());
        }
        if aggregate {
            local.fields.clear();
            let mut fields = Vec::new();
            match &var.ty {
                CType::Array(element) => {
                    if let Some(size) = scalar_storage_size(element) {
                        let mut offsets: Vec<_> = accesses
                            .iter()
                            .filter_map(|(slot, _, width, _)| {
                                let Some(slot) = *slot else { return None };
                                let Some(offset) = slot.checked_sub(var.slot) else {
                                    return None;
                                };
                                (*width > 0
                                    && offset >= 0
                                    && (offset as u64) < var.size
                                    && offset % i64::from(size) == 0)
                                    .then_some(offset)
                            })
                            .collect();
                        offsets.sort_unstable();
                        offsets.dedup();
                        for offset in offsets {
                            fields.push((
                                offset,
                                format!("[{}]", offset / i64::from(size)),
                                element.as_ref().clone(),
                                size,
                            ));
                        }
                    }
                }
                CType::Named(name) => {
                    for member in ir.members.iter().filter(|member| {
                        member.structure == *name
                            || name
                                .strip_prefix("struct ")
                                .or_else(|| name.strip_prefix("union "))
                                == Some(member.structure.as_str())
                    }) {
                        if let Some(size) = scalar_storage_size(&member.ty)
                            && u64::from(size) == member.width
                        {
                            fields.push((
                                member.offset,
                                member.name.clone(),
                                member.ty.clone(),
                                size,
                            ));
                        }
                    }
                }
                _ => {}
            }
            for (offset, name, ty, width) in fields {
                if matches!(&ty, CType::Named(name) if matches!(name.as_str(), "char" | "bool" | "_Bool"))
                {
                    continue;
                }
                let Some(slot) = var.slot.checked_add(offset) else {
                    continue;
                };
                if offset < 0
                    || (offset as u64).saturating_add(u64::from(width)) > var.size
                    || accesses
                        .iter()
                        .any(|(at, _, size, _)| *at == Some(slot) && *size != 0 && *size != width)
                {
                    continue;
                }
                if matches!(ty.integer(), Some((_, true)))
                    && accesses.iter().any(|(at, _, size, signed)| {
                        *at == Some(slot) && *size > 0 && *signed == Some(false)
                    })
                {
                    continue;
                }
                let ty = match ty.integer() {
                    Some((bits, signed)) if bits == u32::from(width) * 8 => {
                        CType::int(width, signed)
                    }
                    _ => ty,
                };
                local.fields.push(Local {
                    name,
                    slot,
                    width,
                    size: 0,
                    signed: false,
                    ty: Some(ty),
                    fields: Vec::new(),
                    views: Vec::new(),
                });
            }
            local.fields.sort_by_key(|field| field.slot);
        }
    }
    applied
}

//! Named addresses for stores into incoming stack storage.

use super::{Ctx, FunctionIr, Locals, Stmt, render_expr};
use crate::ir::Expr;

pub(in crate::render) struct CallerArgument {
    pub(in crate::render) name: String,
    pub(in crate::render) provider: String,
    pub(in crate::render) offset: i64,
}

impl Locals {
    pub(super) fn bind_caller_arguments(
        &mut self,
        ir: &FunctionIr,
        accesses: &[(Expr, Option<i64>, u8)],
        symbols: &super::super::Symbols,
        ctx: &Ctx<'_>,
    ) -> Option<CallerArgument> {
        let mut reserved = super::super::naming::roles::reserved(ir, symbols);
        let mut stored = std::collections::HashSet::new();
        for block in &ir.blocks {
            for stmt in &block.stmts {
                if let Stmt::Store { addr, .. } = stmt {
                    stored.insert(render_expr(addr, ctx));
                }
            }
        }
        let mut first = None;
        for (address, slot, width) in accesses {
            let Some(slot) = slot else { continue };
            let Some(end) = slot.checked_add(i64::from(*width)) else {
                continue;
            };
            if *width == 0 || end <= 0 {
                continue;
            }
            let key = render_expr(address, ctx);
            if !stored.contains(&key)
                || self.slots.contains_key(&key)
                || self.parts.contains_key(&key)
                || self.parameter_addresses.contains_key(&(key, *width))
            {
                continue;
            }
            first = Some(first.map_or((*slot).max(0), |first: i64| first.min((*slot).max(0))));
        }
        let Some(first) = first else { return None };
        let mut origins = std::collections::HashMap::new();
        for (address, slot, _) in accesses {
            let key = render_expr(address, ctx);
            let origin = origins.entry(key).or_insert(*slot);
            if *origin != *slot {
                *origin = None;
            }
        }
        let name = super::super::function::vacant_name(&format!("arg_{first:x}"), &mut reserved);
        let function = super::super::sanitize(ir.name.as_deref().unwrap_or("function"));
        let provider = super::super::function::vacant_name(
            &format!("{function}_{:x}_{name}", ir.addr),
            &mut reserved,
        );
        for (address, slot, width) in accesses {
            let Some(slot) = slot else { continue };
            let Some(end) = slot.checked_add(i64::from(*width)) else {
                continue;
            };
            if *slot < first && (*width == 0 || end <= 0) {
                continue;
            }
            let key = render_expr(address, ctx);
            if origins.get(&key) != Some(&Some(*slot))
                || self.slots.contains_key(&key)
                || self.parts.contains_key(&key)
            {
                continue;
            }
            let Some(delta) = slot.checked_sub(first) else {
                continue;
            };
            let address = match delta {
                0 => name.clone(),
                delta if delta > 0 => format!("{name} + 0x{delta:x}"),
                delta => format!("{name} - 0x{:x}", delta.unsigned_abs()),
            };
            self.parts.insert(key, address);
        }
        Some(CallerArgument {
            name,
            provider,
            offset: first,
        })
    }
}

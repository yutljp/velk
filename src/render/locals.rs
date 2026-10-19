use crate::arch::stack_pointer;
use std::collections::HashMap;

use crate::ir::CType;
use crate::ir::{BinOp, Expr, FunctionIr, Stmt};
use crate::passes::frame_slots::frame_slot;
use crate::render::expr::Ctx;
use crate::render::expr::render_expr;

/// A named frame slot, with the widest access it receives.
pub(super) struct Local {
    pub(super) name: String,
    pub(super) slot: i64,
    pub(super) width: u8,
    pub(super) signed: bool,
}

pub(crate) struct Locals {
    pub(super) slots: HashMap<String, String>,
    pub(super) widths: HashMap<String, u8>,
    pub(super) decls: Vec<Local>,
}

/// Names frame slots `local_N` in order of first use. Accesses to one slot
/// share the name even when the stack pointer moved between them; a rendered
/// address that maps to two different slots stays unnamed.
pub(crate) fn stack_locals(ir: &FunctionIr, frames: &[Option<i64>]) -> Locals {
    let sp = stack_pointer(ir.isa);
    let base = Ctx {
        isa: ir.isa,
        void_return: ir.ret_type == CType::Void,
        names: HashMap::new(),
        slots: HashMap::new(),
        local_widths: HashMap::new(),
        wide_params: std::collections::HashSet::new(),
        signed_params: std::collections::HashSet::new(),
        pointer_params: std::collections::HashSet::new(),
        fields: HashMap::new(),
        callees: &HashMap::new(),
        data_ranges: &[],
        members: HashMap::new(),
        pointees: HashMap::new(),
        narrow_regs: std::collections::HashSet::new(),
        narrow_return: false,
    };
    let accesses = frame_accesses(ir, sp, frames);
    let mut slot_names: HashMap<i64, Local> = HashMap::new();
    let mut rendered: HashMap<String, Option<i64>> = HashMap::new();
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
                },
            );
        }
        if let Some(local) = slot_names.get_mut(slot) {
            local.width = local.width.max(*width);
            if !*signed {
                local.signed = false;
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
    let slots = rendered
        .into_iter()
        .filter_map(|(key, slot)| {
            let slot = slot?;
            slot_names.get(&slot).map(|local| (key, local.name.clone()))
        })
        .collect();
    let widths = slot_names
        .values()
        .map(|local| (local.name.clone(), local.width))
        .collect();
    Locals {
        slots,
        widths,
        decls: slot_names.into_values().collect(),
    }
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
        _ => {}
    }
}

/// Every frame-relative store and load, with its slot (when known) and the
/// address expression as written.
fn frame_accesses(
    ir: &FunctionIr,
    sp: u16,
    frames: &[Option<i64>],
) -> Vec<(Option<i64>, Expr, u8, bool)> {
    let mut accesses = Vec::new();
    for (position, block) in ir.blocks.iter().enumerate() {
        let Some(frame) = frames[position] else {
            continue;
        };
        let mut frame = frame;
        for stmt in &block.stmts {
            match stmt {
                Stmt::Store {
                    addr, value, width, ..
                } => {
                    let written = match value {
                        Expr::Const(_) => *width,
                        _ => *width,
                    };
                    accesses.push((frame_slot(addr, frame, sp), addr.clone(), written, false));
                }
                Stmt::Assign { dest, value } => {
                    if let Expr::Load {
                        addr,
                        width,
                        signed,
                    } = value
                    {
                        accesses.push((
                            frame_slot(addr, frame, sp),
                            addr.as_ref().clone(),
                            *width,
                            *signed,
                        ));
                    }
                    if dest.index == sp
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
                Stmt::Ret { .. } | Stmt::Call { .. } => {
                    let mut found = Vec::new();
                    for value in stmt.operands() {
                        frame_loads(value, frame, sp, &mut found);
                    }
                    for (addr, slot, width, signed) in found {
                        accesses.push((Some(slot), addr, width, signed));
                    }
                }
                _ => {}
            }
        }
    }
    accesses
}

//! Parameters kept across calls elsewhere. A function that needs an
//! argument after a call copies it to a register the call keeps, or spills
//! it to the stack, and copies it back where it passes it on. In the
//! pseudo-C the parameter holds its value all along, so those copies go and
//! the parameter's name reads in their place.

use std::collections::{HashMap, HashSet};

use crate::arch::stack_pointer;
use crate::ir::{BinOp, Expr, FunctionIr, Stmt, VARIABLE_BASE};
use crate::passes::copies::left_by_call;

pub(super) fn standard_main(ir: &mut FunctionIr, symbols: &super::Symbols) {
    let name = symbols
        .original_or_printed_function_name(ir.addr)
        .map(String::as_str)
        .or(ir.name.as_deref());
    if !matches!(name, Some("main" | "_main")) {
        return;
    }
    let arguments = ir.convention.arguments();
    let register_count = ir
        .params
        .iter()
        .filter_map(|param| {
            arguments
                .iter()
                .position(|index| *index == param.index)
                .map(|position| position + 1)
        })
        .max()
        .unwrap_or(0);
    let stack_count = ir
        .stack_params
        .iter()
        .map(|param| param.position.saturating_add(1))
        .max()
        .unwrap_or(0);
    let count = register_count.max(stack_count);
    let max_count = if symbols.target_format == Some(crate::loader::Format::MachO) {
        4
    } else {
        3
    };
    if count > max_count {
        return;
    }
    let count = if count == 1 { 2 } else { count };
    for (position, name) in ["argc", "argv", "envp", "apple"]
        .into_iter()
        .enumerate()
        .take(count)
    {
        let ty = if position == 0 {
            crate::ir::CType::Named("int".into())
        } else {
            crate::ir::CType::pointer_to(crate::ir::CType::pointer_to(crate::ir::CType::Named(
                "char".into(),
            )))
        };
        if let Some(param) = ir
            .stack_params
            .iter_mut()
            .find(|param| param.position == position)
        {
            param.name = name.into();
            param.ty = ty;
        } else if let Some(index) = arguments.get(position) {
            if let Some(param) = ir.params.iter_mut().find(|param| param.index == *index) {
                param.name = name.into();
                param.ty = ty;
            } else {
                ir.params.push(crate::ir::Param {
                    index: *index,
                    name: name.into(),
                    ty,
                });
            }
        } else if let Some(base) = ir.convention.stack_arguments() {
            let size = u64::from(crate::arch::pointer_bytes(ir.isa));
            let offset = base.saturating_add(
                (position.saturating_sub(arguments.len()) as i64).saturating_mul(size as i64),
            );
            ir.stack_params.push(crate::ir::StackParam {
                offset,
                size,
                name: name.into(),
                ty,
                position,
            });
        }
    }
    ir.params
        .sort_by_key(|param| arguments.iter().position(|index| *index == param.index));
    ir.stack_params.sort_by_key(|param| param.position);
    ir.ret_type = crate::ir::CType::Named("int".into());
    ir.declared_signature = None;
    ir.variadic = false;
}

pub(super) fn fold_saved_parameters(ir: &mut FunctionIr) {
    drop_unused_parameter_outputs(ir);
    let params: Vec<u16> = ir.params.iter().map(|param| param.index).collect();
    for param in params {
        fold_parameter_copies(ir, param, IntegerTypes::Exact);
    }
}

fn drop_unused_parameter_outputs(ir: &mut FunctionIr) {
    let params: HashSet<u16> = ir
        .params
        .iter()
        .filter(|param| param.ty.is_pointer() || param.ty.integer().is_some())
        .map(|param| param.index)
        .collect();
    if !ir.landing_pads.is_empty() || ir.blocks.iter().any(crate::ir::cfg::opaque) {
        return;
    }
    let live_in = crate::ir::cfg::live_in(ir);
    let exits: Vec<_> = (0..ir.blocks.len())
        .map(|index| crate::ir::cfg::live_out(ir, &live_in, index))
        .collect();
    for (block, mut live) in ir.blocks.iter_mut().zip(exits) {
        for stmt in block.stmts.iter_mut().rev() {
            let (writes, reads) = crate::ir::visit::statement_registers(stmt);
            // An unused result in an argument register does not overwrite the
            // C parameter. Keep declared result bindings unchanged.
            if let Stmt::Call {
                outputs, abi: None, ..
            } = stmt
            {
                outputs.retain(|output| {
                    output.dest.width != 64
                        || output.dest.index != output.register
                        || !params.contains(&output.dest.index)
                        || live.contains(&output.dest.index)
                });
            }
            for written in writes {
                live.remove(&written);
            }
            live.extend(reads);
        }
    }
}

#[derive(Clone, Copy)]
enum IntegerTypes {
    Exact,
    SameWidth,
}

/// Try copies with a different integer sign; the renderer checks conversion costs.
pub(super) fn integer_copy_candidate(ir: &FunctionIr) -> Option<FunctionIr> {
    if ir.params.iter().any(|param| {
        matches!(&param.ty, crate::ir::CType::Named(name)
            if name.split_whitespace().any(|word| word == "volatile"))
    }) {
        return None;
    }
    let params: Vec<u16> = ir
        .params
        .iter()
        .filter_map(|param| {
            let Some((bits, signed)) = param.ty.integer() else {
                return None;
            };
            ir.value_types
                .values()
                .any(|ty| ty.integer() == Some((bits, !signed)))
                .then_some(param.index)
        })
        .collect();
    if params.is_empty() {
        return None;
    }
    let mut candidate = ir.clone();
    let before: usize = ir.blocks.iter().map(|block| block.stmts.len()).sum();
    for param in params {
        fold_parameter_copies(&mut candidate, param, IntegerTypes::SameWidth);
    }
    let after: usize = candidate.blocks.iter().map(|block| block.stmts.len()).sum();
    (after < before).then_some(candidate)
}

/// Reuse an integer parameter after its only read initializes a mutable copy.
pub(super) fn mutable_copy_candidate(ir: &FunctionIr) -> Option<FunctionIr> {
    if !ir.landing_pads.is_empty()
        || ir.blocks.iter().any(crate::ir::cfg::opaque)
        || ir
            .blocks
            .iter()
            .flat_map(|block| &block.stmts)
            .any(|stmt| matches!(stmt, Stmt::Call { .. } | Stmt::Machine { .. }))
    {
        return None;
    }
    let Some(entry) = ir.blocks.first() else {
        return None;
    };
    if (0..ir.blocks.len()).any(|block| crate::ir::cfg::successors(ir, block).contains(&0)) {
        return None;
    }
    let types = crate::render::variable_types(ir);
    for (position, stmt) in entry.stmts.iter().enumerate() {
        let Stmt::Assign {
            dest,
            value: Expr::Reg {
                index: source,
                width,
            },
        } = stmt
        else {
            continue;
        };
        let Some(param) = ir.params.iter().find(|param| param.index == *source) else {
            continue;
        };
        let Some((bits, _)) = param.ty.integer() else {
            continue;
        };
        if dest.index < VARIABLE_BASE
            || !matches!(bits, 32 | 64)
            || u32::from(dest.width) != bits
            || u32::from(*width) < bits
            || types
                .get(&dest.index)
                .and_then(|ty| ty.integer())
                .map(|(bits, _)| bits)
                != Some(bits)
            || matches!(types.get(&dest.index), Some(crate::ir::CType::Named(name))
                if name.split_whitespace().any(|word| word == "volatile"))
            || matches!(&param.ty, crate::ir::CType::Named(name)
                if name.split_whitespace().any(|word| matches!(word, "volatile" | "bool" | "_Bool")))
        {
            continue;
        }
        let mut valid = true;
        let mut modified = false;
        for (block, body) in ir.blocks.iter().enumerate() {
            for (at, stmt) in body.stmts.iter().enumerate() {
                if block == 0 && at == position {
                    continue;
                }
                let (writes, reads) = crate::ir::visit::statement_registers(stmt);
                modified |= writes.contains(&dest.index);
                if writes.contains(source)
                    || reads.contains(source)
                    || (block == 0
                        && at < position
                        && (writes.contains(&dest.index) || reads.contains(&dest.index)))
                    || (writes.contains(&dest.index)
                        && !matches!(stmt, Stmt::Assign { dest: other, .. } if other.width == dest.width))
                {
                    valid = false;
                }
            }
        }
        if !valid || !modified {
            continue;
        }
        let mut candidate = ir.clone();
        candidate.blocks[0].stmts.remove(position);
        let renamed = HashMap::from([(dest.index, *source)]);
        for stmt in candidate
            .blocks
            .iter_mut()
            .flat_map(|block| &mut block.stmts)
        {
            crate::passes::coalesce::rename(stmt, &renamed);
        }
        return Some(candidate);
    }
    None
}

/// Where a copy comes from.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Source {
    Register(u16),
    /// The stack offset from the stack pointer.
    Slot(u64),
}

fn slot_accesses(ir: &FunctionIr, slot_of: &impl Fn(&Expr) -> Option<u64>) -> Vec<(u64, u8, bool)> {
    fn loads(expr: &Expr, slot_of: &impl Fn(&Expr) -> Option<u64>, out: &mut Vec<(u64, u8, bool)>) {
        if let Expr::Load { addr, width, .. } = expr
            && let Some(slot) = slot_of(addr)
        {
            out.push((slot, *width, false));
        }
        for child in crate::ir::visit::children(expr) {
            loads(child, slot_of, out);
        }
    }
    let mut accesses: Vec<(u64, u8, bool)> = Vec::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        if let Stmt::Store { addr, width, .. } = stmt
            && let Some(slot) = slot_of(addr)
        {
            accesses.push((slot, *width, true));
        }
        for operand in stmt.operands() {
            loads(operand, slot_of, &mut accesses);
        }
    }
    accesses
}

fn fold_parameter_copies(ir: &mut FunctionIr, param: u16, integer_types: IntegerTypes) {
    let sp = stack_pointer(ir.isa);
    let atomics = ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .any(crate::passes::memory::memory_ordering_barrier);
    let private_frame = crate::passes::memory::fixed_private_frame(ir, sp);
    // A slot whose address the code uses for anything but its own loads and
    // stores may change unseen, and a call of unknown arguments may read one
    // as an argument, so then only registers count.
    let slots = stack_only_as_slots(ir, sp)
        && !ir
            .blocks
            .iter()
            .flat_map(|block| &block.stmts)
            .any(|stmt| matches!(stmt, Stmt::Call { args: None, .. }));
    let spill_range = crate::passes::memory::spill_range(ir);
    let slot_of = |addr: &Expr| match addr {
        _ if !slots
            || !crate::passes::frame_slots::checked_frame_slot(addr, 0, sp).is_some_and(
                |offset| crate::passes::memory::private_slot(offset, 1, spill_range),
            )
            || (atomics
                && (!private_frame || !crate::passes::memory::private_address(addr, 8, sp))) =>
        {
            None
        }
        Expr::Reg { index, .. } if *index == sp => Some(0),
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Reg { index, .. }, Expr::Const(offset)) if *index == sp => Some(*offset),
            _ => None,
        },
        _ => None,
    };
    // A 32-bit parameter is copied in its 32-bit register.
    let narrow = ir
        .params
        .iter()
        .any(|held| held.index == param && held.ty.integer().is_some_and(|(bits, _)| bits == 32));
    let small_spill = ir
        .params
        .iter()
        .find(|held| held.index == param)
        .and_then(|held| {
            held.ty.integer().and_then(|(bits, _)| match bits {
                8 | 16 => Some((bits / 8) as u8),
                _ => None,
            })
        });
    let source_of = |value: &Expr| match value {
        Expr::Reg { index, width: 64 } => Some(Source::Register(*index)),
        Expr::Reg { index, width: 32 } if narrow => Some(Source::Register(*index)),
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if narrow && matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) => match lhs.as_ref() {
            Expr::Reg {
                index,
                width: 32 | 64,
            } => Some(Source::Register(*index)),
            _ => None,
        },
        Expr::Load { addr, width: 8, .. } => slot_of(addr).map(Source::Slot),
        Expr::Load { addr, width: 4, .. } if narrow => slot_of(addr).map(Source::Slot),
        _ => None,
    };
    // What each register and slot is given; `None` for anything but a copy.
    // A register a call before in the block left changed holds what the call
    // left there, such as a further result, not what it held on entry.
    let before_call = |stmts: &[Stmt], source: Option<Source>| {
        source.filter(|source| match source {
            Source::Register(index) => !left_by_call(stmts, *index),
            Source::Slot(_) => true,
        })
    };
    let mut defined: HashMap<Source, Vec<Option<Source>>> = HashMap::new();
    // The registers given more than the 32 bits of a narrow parameter.
    let mut given_wide: HashSet<u16> = HashSet::new();
    // The narrowest store to each slot: a wider load reads bytes it left.
    let mut stored: HashMap<u64, u8> = HashMap::new();
    for block in &ir.blocks {
        for (position, stmt) in block.stmts.iter().enumerate() {
            let earlier = &block.stmts[..position];
            match stmt {
                Stmt::Assign { dest, value } => {
                    let zero_extended = dest.width == 32
                        || matches!(
                            value,
                            Expr::Reg { width: 32, .. }
                                | Expr::Load {
                                    width: 4,
                                    signed: false,
                                    ..
                                }
                                | Expr::Bin { op: BinOp::And, .. }
                        );
                    if !zero_extended {
                        given_wide.insert(dest.index);
                    }
                    defined
                        .entry(Source::Register(dest.index))
                        .or_default()
                        .push(before_call(
                            earlier,
                            source_of(value)
                                .filter(|_| dest.width == 64 || (narrow && dest.width == 32)),
                        ))
                }
                Stmt::Store { addr, value, width } => {
                    if let Some(slot) = slot_of(addr) {
                        defined
                            .entry(Source::Slot(slot))
                            .or_default()
                            .push(before_call(
                                earlier,
                                match value {
                                    Expr::Reg { index, width: 64 } if *width == 8 => {
                                        Some(Source::Register(*index))
                                    }
                                    // Unoptimized code spills a 32-bit parameter
                                    // as its 32-bit register.
                                    Expr::Reg {
                                        index,
                                        width: 32 | 64,
                                    } if narrow && *width == 4 => Some(Source::Register(*index)),
                                    Expr::Reg {
                                        index,
                                        width: 32 | 64,
                                    } if small_spill == Some(*width) && *index == param => {
                                        Some(Source::Register(*index))
                                    }
                                    _ => None,
                                },
                            ));
                        let narrowest = stored.entry(slot).or_insert(*width);
                        *narrowest = (*narrowest).min(*width);
                        // A narrower store over part of a slot changes it too.
                        if *width != 8 && !(narrow && *width == 4) && small_spill != Some(*width) {
                            defined.entry(Source::Slot(slot)).or_default().push(None);
                        }
                    }
                }
                Stmt::Machine { outputs, .. } => {
                    for output in outputs {
                        defined
                            .entry(Source::Register(output.index))
                            .or_default()
                            .push(None);
                    }
                }
                Stmt::Call { .. } => {
                    for output in stmt.call_outputs() {
                        defined
                            .entry(Source::Register(output.dest.index))
                            .or_default()
                            .push(None);
                    }
                }
                _ => {}
            }
        }
    }
    // A slot read wider than its narrowest store, or touched at another
    // offset among its bytes, holds more than the value stored there.
    let accesses = slot_accesses(ir, &slot_of);
    let mixed = |slot: u64| {
        let narrowest = stored.get(&slot).copied().unwrap_or(8);
        let extent = accesses
            .iter()
            .filter(|(at, _, _)| *at == slot)
            .map(|(_, width, _)| u64::from(*width))
            .max()
            .unwrap_or(8);
        let start = slot as i64;
        let Some(end) = start.checked_add(extent as i64) else {
            return true;
        };
        accesses.iter().any(|(at, width, store)| {
            if *at == slot {
                !store && *width > narrowest
            } else {
                let other = *at as i64;
                let Some(other_end) = other.checked_add(i64::from(*width)) else {
                    return true;
                };
                other < end && start < other_end
            }
        })
    };
    // Incoming storage already holds a value independent of a later spill.
    let separate_input = |slot: u64| {
        let extent = accesses
            .iter()
            .filter(|(at, _, _)| *at == slot)
            .map(|(_, width, _)| i64::from(*width))
            .max()
            .unwrap_or(0);
        let start = slot as i64;
        let Some(end) = start.checked_add(extent).filter(|_| {
            extent > 0
                && u8::try_from(extent).is_ok_and(|width| {
                    crate::passes::memory::private_slot(start, width, spill_range)
                })
        }) else {
            return false;
        };
        ir.stack_params.iter().all(|param| {
            let Some(size) = i64::try_from(param.size).ok().filter(|size| *size > 0) else {
                return false;
            };
            let Some(input_end) = param.offset.checked_add(size) else {
                return false;
            };
            end <= param.offset || input_end <= start
        })
    };
    // The variables and slots holding nothing but the parameter's value.
    let origin = Source::Register(param);
    let parameter_integer = ir
        .params
        .iter()
        .find(|held| held.index == param)
        .and_then(|held| held.ty.integer());
    let mut aliases: HashSet<Source> = HashSet::new();
    loop {
        let before = aliases.len();
        for (place, sources) in &defined {
            let renamable = match place {
                Source::Register(index) => {
                    *index >= VARIABLE_BASE
                        && ir.value_types.get(index).is_none_or(|ty| {
                            let integer = ty.integer();
                            integer.is_none()
                                || integer == parameter_integer
                                || (matches!(integer_types, IntegerTypes::SameWidth)
                                    && integer.map(|(bits, _)| bits)
                                        == parameter_integer.map(|(bits, _)| bits)
                                    && !matches!(ty, crate::ir::CType::Named(name)
                                        if name.split_whitespace().any(|word| matches!(word, "volatile" | "bool" | "_Bool"))))
                        })
                }
                Source::Slot(slot) => !mixed(*slot) && separate_input(*slot),
            };
            if renamable
                && !aliases.contains(place)
                && sources.iter().all(|source| {
                    source.is_some_and(|source| source == origin || aliases.contains(&source))
                })
            {
                aliases.insert(*place);
            }
        }
        if aliases.len() == before {
            break;
        }
    }
    if aliases.is_empty() {
        return;
    }
    // The parameter's register may only get one of them back.
    let restored_only = defined.get(&origin).is_none_or(|sources| {
        sources
            .iter()
            .all(|source| source.is_some_and(|source| aliases.contains(&source)))
    });
    if !restored_only {
        return;
    }
    // A load no wider than the slot's stores reads the parameter's low bytes.
    let held = |value: &Expr| match value {
        Expr::Load { addr, width, .. } => slot_of(addr).is_some_and(|slot| {
            aliases.contains(&Source::Slot(slot))
                && stored
                    .get(&slot)
                    .is_some_and(|narrowest| width <= narrowest)
        }),
        _ => source_of(value).is_some_and(|source| aliases.contains(&source)),
    };
    let renames: Vec<(u16, Expr)> = aliases
        .iter()
        .filter_map(|alias| match alias {
            // One that holds only a narrow parameter's 32 bits reads them.
            Source::Register(index) if narrow && !given_wide.contains(index) => {
                Some((*index, Expr::reg(param, 32)))
            }
            Source::Register(index) => Some((*index, Expr::reg(param, 64))),
            Source::Slot(_) => None,
        })
        .collect();
    for block in &mut ir.blocks {
        block.stmts.retain(|stmt| match stmt {
            Stmt::Assign { dest, .. } => {
                dest.index != param && !aliases.contains(&Source::Register(dest.index))
            }
            Stmt::Store { addr, .. } => {
                !slot_of(addr).is_some_and(|slot| aliases.contains(&Source::Slot(slot)))
            }
            _ => true,
        });
        for stmt in &mut block.stmts {
            crate::ir::visit::replace_reads(stmt, &renames);
            // A load of a slot holding the parameter reads the parameter.
            replace_loads(stmt, &held, param);
        }
    }
}

/// Rewrites each load `held` accepts as a read of `param`.
fn replace_loads(stmt: &mut Stmt, held: &impl Fn(&Expr) -> bool, param: u16) {
    fn walk(expr: &mut Expr, held: &impl Fn(&Expr) -> bool, param: u16) {
        if held(expr)
            && let Expr::Load { width, signed, .. } = expr
        {
            *expr = match (*width, *signed) {
                (8, _) => Expr::reg(param, 64),
                (width, false) => Expr::reg(param, width * 8),
                (width, true) => Expr::SignExtend {
                    value: Box::new(Expr::reg(param, width * 8)),
                    width,
                },
            };
            return;
        }
        for child in crate::ir::visit::children_mut(expr) {
            walk(child, held, param);
        }
    }
    for expr in stmt.operands_mut() {
        walk(expr, held, param);
    }
}

/// True when the stack pointer appears only as the whole address of a load
/// or store, or as such an address plus a constant.
fn stack_only_as_slots(ir: &FunctionIr, sp: u16) -> bool {
    fn stack_pointer_use_is_safe(expr: &Expr, sp: u16, address: bool) -> bool {
        match expr {
            Expr::Reg { index, .. } => *index != sp || address,
            Expr::Bin {
                op: BinOp::Add,
                lhs,
                rhs,
            } if address
                && matches!(lhs.as_ref(), Expr::Reg { index, .. } if *index == sp)
                && matches!(rhs.as_ref(), Expr::Const(_)) =>
            {
                true
            }
            Expr::Load { addr, .. } => stack_pointer_use_is_safe(addr, sp, true),
            other => crate::ir::visit::children(other)
                .into_iter()
                .all(|child| stack_pointer_use_is_safe(child, sp, false)),
        }
    }
    ir.blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .all(|stmt| match stmt {
            Stmt::Store { addr, value, .. } => {
                stack_pointer_use_is_safe(addr, sp, true)
                    && stack_pointer_use_is_safe(value, sp, false)
            }
            Stmt::Assign { dest, value } => {
                dest.index != sp && stack_pointer_use_is_safe(value, sp, false)
            }
            other => other
                .operands()
                .into_iter()
                .all(|expr| stack_pointer_use_is_safe(expr, sp, false)),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{CType, Convention, Param, RegRef, StackParam, eval};
    use crate::loader::Isa;

    const OLD: u64 = 0x0706_0504_0302_0100;
    const NEW: u64 = 0x96a5_3cc3_f00f_5a69;
    const OTHER: u64 = 0xfedc_ba98_7654_3210;

    #[test]
    fn caller_frame_parameter_spills_preserve_memory() {
        use crate::ir::smt::Proofs;

        if !Proofs::available() {
            return;
        }
        let mut proofs = Proofs::default();
        for isa in [Isa::X86_64, Isa::I386, Isa::AArch64, Isa::Arm32] {
            let sp = stack_pointer(isa);
            for width in [1, 2, 4, 8] {
                for offset in [0, 8, u64::MAX] {
                    if width == 1 && offset == u64::MAX {
                        continue;
                    }
                    let mut before = FunctionIr::single_block(
                        isa,
                        vec![
                            Stmt::Store {
                                addr: Expr::bin(BinOp::Add, Expr::reg(sp, 64), Expr::Const(offset)),
                                value: Expr::reg(0, 64),
                                width,
                            },
                            Stmt::Ret {
                                value: Expr::Const(0),
                            },
                        ],
                    );
                    before.params.push(Param {
                        index: 0,
                        name: "value".into(),
                        ty: CType::int(width, false),
                    });
                    let mut after = before.clone();
                    fold_saved_parameters(&mut after);
                    proofs.function(
                        format!("parameter store/{isa:?}/{width}/{offset}"),
                        &before,
                        &after,
                    );
                }
            }
        }
        proofs.check();
    }

    #[test]
    fn parameter_result_bindings_stay_when_a_successor_reads_them() {
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![Stmt::Call {
                kind: crate::ir::CallKind::Invoke,
                target: Some(0x1000),
                through: None,
                convention: Convention::GoAmd64,
                args: Some(Vec::new()),
                floats_named: false,
                abi: None,
                outputs: vec![crate::ir::CallOutput {
                    register: 3,
                    dest: RegRef {
                        index: 3,
                        width: 64,
                    },
                }],
                clobbers: None,
                via: None,
            }],
        );
        ir.params.push(Param {
            index: 3,
            name: "input".into(),
            ty: CType::U64,
        });
        ir.blocks.push(crate::ir::Block {
            start: 1,
            stmts: vec![Stmt::Ret {
                value: Expr::reg(3, 64),
            }],
        });
        drop_unused_parameter_outputs(&mut ir);
        assert_eq!(ir.blocks[0].stmts[0].call_outputs().len(), 1);
        ir.blocks[1].stmts[0] = Stmt::Ret {
            value: Expr::Const(0),
        };
        drop_unused_parameter_outputs(&mut ir);
        assert!(ir.blocks[0].stmts[0].call_outputs().is_empty());
    }

    fn address(offset: i64) -> Expr {
        Expr::bin(BinOp::Add, Expr::reg(31, 64), Expr::Const(offset as u64))
    }

    fn load(offset: i64) -> Expr {
        Expr::Load {
            addr: Box::new(address(offset)),
            width: 8,
            signed: false,
        }
    }

    fn function(input: i64, stmts: Vec<Stmt>) -> FunctionIr {
        let mut ir = FunctionIr::single_block(Isa::AArch64, stmts);
        ir.convention = Convention::Aapcs64;
        ir.params = [0, 1]
            .into_iter()
            .map(|index| Param {
                index,
                name: format!("a{index}"),
                ty: CType::U64,
            })
            .collect();
        ir.stack_params = vec![StackParam {
            offset: input,
            size: 8,
            name: "incoming".to_owned(),
            ty: CType::U64,
            position: 2,
        }];
        ir
    }

    fn outcome(ir: &FunctionIr, initialized: i64) -> eval::Outcome {
        eval::run(
            ir,
            &eval::Setup {
                seed: 29,
                convention: eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &[(0, NEW), (1, OTHER)],
                memory: &[(eval::STACK_TOP.wrapping_add_signed(initialized), OLD)],
                step_limit: 1000,
            },
        )
    }

    #[test]
    fn incoming_reads_before_spills_keep_the_original_value() {
        for (input, slot) in [(0, 0), (8, 4), (8, 12), (-8, -4)] {
            let mut ir = function(
                input,
                vec![
                    Stmt::Assign {
                        dest: RegRef {
                            index: VARIABLE_BASE,
                            width: 64,
                        },
                        value: load(slot),
                    },
                    Stmt::Store {
                        addr: address(slot),
                        value: Expr::reg(0, 64),
                        width: 8,
                    },
                    Stmt::Store {
                        addr: Expr::Const(0x1000),
                        value: load(slot),
                        width: 8,
                    },
                    Stmt::Ret {
                        value: Expr::reg(VARIABLE_BASE, 64),
                    },
                ],
            );
            let expected = eval::Outcome::Return {
                value: OLD,
                calls: Vec::new(),
                memory: NEW
                    .to_le_bytes()
                    .into_iter()
                    .enumerate()
                    .map(|(byte, value)| (0x1000 + byte as u64, value))
                    .collect(),
            };
            assert_eq!(outcome(&ir, slot), expected);
            fold_saved_parameters(&mut ir);
            assert_eq!(outcome(&ir, slot), expected);
        }
    }

    #[test]
    fn only_private_spills_fold() {
        for (input, slot) in [(8, 0), (8, 16), (0, -8)] {
            let mut ir = function(
                input,
                vec![
                    Stmt::Store {
                        addr: address(slot),
                        value: Expr::reg(0, 64),
                        width: 8,
                    },
                    Stmt::Ret { value: load(slot) },
                ],
            );
            let expected = eval::Outcome::Return {
                value: NEW,
                calls: Vec::new(),
                memory: Default::default(),
            };
            assert_eq!(outcome(&ir, slot), expected);
            fold_saved_parameters(&mut ir);
            assert_eq!(outcome(&ir, slot), expected);
            if slot >= 0 {
                assert!(matches!(
                    ir.blocks[0].stmts.first(),
                    Some(Stmt::Store { .. })
                ));
                continue;
            }
            assert!(matches!(
                ir.blocks[0].stmts.as_slice(),
                [Stmt::Ret {
                    value: Expr::Reg {
                        index: 0,
                        width: 64
                    }
                }]
            ));
        }
    }

    #[test]
    fn overlapping_incoming_accesses_still_invalidate_adjacent_spills() {
        let mut ir = function(
            8,
            vec![
                Stmt::Store {
                    addr: address(0),
                    value: Expr::reg(0, 64),
                    width: 8,
                },
                Stmt::Store {
                    addr: address(4),
                    value: Expr::reg(1, 64),
                    width: 8,
                },
                Stmt::Ret { value: load(0) },
            ],
        );
        let expected = eval::Outcome::Return {
            value: (NEW & 0xffff_ffff) | ((OTHER & 0xffff_ffff) << 32),
            calls: Vec::new(),
            memory: Default::default(),
        };
        assert_eq!(outcome(&ir, 0), expected);
        fold_saved_parameters(&mut ir);
        assert_eq!(outcome(&ir, 0), expected);
    }

    #[test]
    fn unbounded_storage_does_not_become_a_spill_alias() {
        for (input, size, slot) in [
            (i64::MAX - 3, 8, -8),
            (0, u64::MAX, -8),
            (8, 0, 0),
            (0, 8, i64::MAX - 3),
        ] {
            let mut ir = function(
                input,
                vec![
                    Stmt::Store {
                        addr: address(slot),
                        value: Expr::reg(0, 64),
                        width: 8,
                    },
                    Stmt::Ret { value: load(slot) },
                ],
            );
            ir.stack_params[0].size = size;
            let before = format!("{ir:?}");
            fold_saved_parameters(&mut ir);
            assert_eq!(format!("{ir:?}"), before);
        }
    }
}

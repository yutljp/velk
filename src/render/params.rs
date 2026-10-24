//! Parameters kept across calls elsewhere. A function that needs an
//! argument after a call copies it to a register the call keeps, or spills
//! it to the stack, and copies it back where it passes it on. In the
//! pseudo-C the parameter holds its value all along, so those copies go and
//! the parameter's name reads in their place.

use std::collections::{HashMap, HashSet};

use crate::arch::stack_pointer;
use crate::ir::{BinOp, Expr, FunctionIr, Stmt, VARIABLE_BASE};
use crate::passes::copies::left_by_call;

pub(super) fn fold_saved_parameters(ir: &mut FunctionIr) {
    let params: Vec<u16> = ir.params.iter().map(|param| param.index).collect();
    for param in params {
        fold(ir, param);
    }
}

/// Where a copy comes from.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Source {
    Register(u16),
    /// The 8 bytes at this offset from the stack pointer.
    Slot(u64),
}

fn fold(ir: &mut FunctionIr, param: u16) {
    let sp = stack_pointer(ir.isa);
    let atomics = ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .any(crate::passes::memory::atomic);
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
    let slot_of = |addr: &Expr| match addr {
        _ if !slots
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
    let source_of = |value: &Expr| match value {
        Expr::Reg { index, width: 64 } => Some(Source::Register(*index)),
        Expr::Reg { index, width: 32 } if narrow => Some(Source::Register(*index)),
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if narrow && matches!(rhs.as_ref(), Expr::Const(0xffff_ffff)) => match lhs.as_ref() {
            Expr::Reg { index, .. } => Some(Source::Register(*index)),
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
                                    _ => None,
                                },
                            ));
                        let narrowest = stored.entry(slot).or_insert(*width);
                        *narrowest = (*narrowest).min(*width);
                        // A narrower store over part of a slot changes it too.
                        if *width != 8 && !(narrow && *width == 4) {
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
    fn loads(expr: &Expr, out: &mut Vec<(Expr, u8)>) {
        if let Expr::Load { addr, width, .. } = expr {
            out.push((addr.as_ref().clone(), *width));
        }
        for child in crate::ir::visit::children(expr) {
            loads(child, out);
        }
    }
    let mut accesses: Vec<(u64, u8, bool)> = Vec::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        if let Stmt::Store { addr, width, .. } = stmt
            && let Some(slot) = slot_of(addr)
        {
            accesses.push((slot, *width, true));
        }
        let mut loaded = Vec::new();
        for operand in stmt.operands() {
            loads(operand, &mut loaded);
        }
        accesses.extend(
            loaded
                .iter()
                .filter_map(|(addr, width)| slot_of(addr).map(|slot| (slot, *width, false))),
        );
    }
    let mixed = |slot: u64| {
        let narrowest = stored.get(&slot).copied().unwrap_or(8);
        let extent = accesses
            .iter()
            .filter(|(at, _, _)| *at == slot)
            .map(|(_, width, _)| u64::from(*width))
            .max()
            .unwrap_or(8);
        accesses.iter().any(|(at, width, store)| {
            if *at == slot {
                !store && *width > narrowest
            } else {
                *at < slot.wrapping_add(extent) && slot < at.wrapping_add(u64::from(*width))
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
        let Some(end) = start.checked_add(extent).filter(|_| extent > 0) else {
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
                            ty.integer().is_none() || ty.integer() == parameter_integer
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
        crate::ir::visit::children_mut(expr)
            .into_iter()
            .for_each(|child| walk(child, held, param));
    }
    for expr in stmt.operands_mut() {
        walk(expr, held, param);
    }
}

/// True when the stack pointer appears only as the whole address of a load
/// or store, or as such an address plus a constant.
fn stack_only_as_slots(ir: &FunctionIr, sp: u16) -> bool {
    fn ok(expr: &Expr, sp: u16, address: bool) -> bool {
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
            Expr::Load { addr, .. } => ok(addr, sp, true),
            other => crate::ir::visit::children(other)
                .into_iter()
                .all(|child| ok(child, sp, false)),
        }
    }
    ir.blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .all(|stmt| match stmt {
            Stmt::Store { addr, value, .. } => ok(addr, sp, true) && ok(value, sp, false),
            Stmt::Assign { dest, value } => dest.index != sp && ok(value, sp, false),
            other => other.operands().into_iter().all(|expr| ok(expr, sp, false)),
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
    fn adjacent_private_spills_still_fold() {
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

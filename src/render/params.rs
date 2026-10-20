//! Parameters kept across calls elsewhere. A function that needs an
//! argument after a call copies it to a register the call keeps, or spills
//! it to the stack, and copies it back where it passes it on. In the
//! pseudo-C the parameter holds its value all along, so those copies go and
//! the parameter's name reads in their place.

use std::collections::{HashMap, HashSet};

use crate::arch::stack_pointer;
use crate::ir::{BinOp, Expr, FunctionIr, Stmt, VARIABLE_BASE};

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
        _ if !slots => None,
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
        .any(|held| held.index == param && held.ty.is_32_bit_int());
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
        _ => None,
    };
    // What each register and slot is given; `None` for anything but a copy.
    let mut defined: HashMap<Source, Vec<Option<Source>>> = HashMap::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        match stmt {
            Stmt::Assign { dest, value } => defined
                .entry(Source::Register(dest.index))
                .or_default()
                .push(
                    source_of(value).filter(|_| dest.width == 64 || (narrow && dest.width == 32)),
                ),
            Stmt::Store { addr, value, width } => {
                if let Some(slot) = slot_of(addr) {
                    defined
                        .entry(Source::Slot(slot))
                        .or_default()
                        .push(match value {
                            Expr::Reg { index, width: 64 } if *width == 8 => {
                                Some(Source::Register(*index))
                            }
                            _ => None,
                        });
                    // A narrower store over part of a slot changes it too.
                    if *width != 8 {
                        defined.entry(Source::Slot(slot)).or_default().push(None);
                    }
                }
            }
            Stmt::Call {
                result: Some(result),
                ..
            } => defined
                .entry(Source::Register(result.index))
                .or_default()
                .push(None),
            _ => {}
        }
    }
    // The variables and slots holding nothing but the parameter's value.
    let origin = Source::Register(param);
    let mut aliases: HashSet<Source> = HashSet::new();
    loop {
        let before = aliases.len();
        for (place, sources) in &defined {
            let renamable = match place {
                Source::Register(index) => *index >= VARIABLE_BASE,
                Source::Slot(_) => true,
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
    if !aliases
        .iter()
        .any(|alias| matches!(alias, Source::Register(_)))
    {
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
    let held = |value: &Expr| source_of(value).is_some_and(|source| aliases.contains(&source));
    let renames: Vec<(u16, Expr)> = aliases
        .iter()
        .filter_map(|alias| match alias {
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
        if held(expr) && matches!(expr, Expr::Load { .. }) {
            *expr = Expr::reg(param, 64);
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

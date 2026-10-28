//! Fixed frame ranges accessed through addresses held in immutable locals.

use std::collections::{BTreeMap, HashMap};

use super::{Origins, base_register, origin, transfer};
use crate::ir::{Expr, FunctionIr, Stmt};

pub(super) fn ranges(ir: &FunctionIr, entries: &[Option<Origins>], sp: u16) -> Vec<(i64, i64)> {
    if ir.blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
        matches!(
            stmt,
            Stmt::Machine {
                instruction: crate::ir::MachineInstruction::ArmLoadAcquire { .. }
                    | crate::ir::MachineInstruction::ArmExclusive { .. }
                    | crate::ir::MachineInstruction::ArmCacheZero,
                ..
            }
        )
    }) {
        return Vec::new();
    }
    let mut definitions: HashMap<u16, usize> = HashMap::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        for register in crate::ir::visit::statement_registers(stmt).0 {
            *definitions.entry(register).or_default() += 1;
        }
    }
    let mut roots = HashMap::new();
    let mut copies = Vec::new();
    let mut accesses = Vec::new();
    for (block, entry) in ir.blocks.iter().zip(entries) {
        let Some(mut state) = entry.clone() else {
            continue;
        };
        for stmt in &block.stmts {
            if let Stmt::Assign { dest, value } = stmt
                && dest.index >= crate::ir::VARIABLE_BASE
                && definitions
                    .get(&dest.index)
                    .is_some_and(|count| *count == 1)
                && dest.width == 64
                && let Some(source) = base_register(value)
                && let Some(Some(start)) = origin(value, &state)
                && start < 0
            {
                if source == sp {
                    roots.insert(dest.index, start);
                } else {
                    copies.push((dest.index, source));
                }
            }
            let mut touches = Vec::new();
            if let Stmt::Store { addr, width, .. } = stmt {
                touches.push((addr, *width));
            }
            if let Stmt::Machine {
                instruction: crate::ir::MachineInstruction::Atomic { width, .. },
                inputs,
                ..
            } = stmt
                && let Some(addr) = inputs.first()
            {
                touches.push((addr, *width));
            }
            for value in stmt.operands() {
                loads(value, &mut touches);
            }
            for (addr, width) in touches {
                if let Some(Some(slot)) = origin(addr, &state) {
                    accesses.push((base_register(addr), slot, width));
                }
            }
            transfer(stmt, &mut state);
        }
    }
    loop {
        let mut changed = false;
        for (dest, source) in &copies {
            if !roots.contains_key(dest)
                && let Some(start) = roots.get(source).copied()
            {
                roots.insert(*dest, start);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut ends = BTreeMap::new();
    for (register, slot, width) in &accesses {
        let Some(root) = register.and_then(|register| roots.get(&register)) else {
            continue;
        };
        let Some(end) = slot.checked_add(i64::from(*width)) else {
            continue;
        };
        if slot >= root && end <= 0 && matches!(width, 1 | 2 | 4 | 8) {
            let last = ends.entry(*root).or_insert(*root);
            *last = end.max(*last);
        }
    }
    let mut ranges = Vec::new();
    for (start, end) in ends {
        let mut fields: Vec<_> = accesses
            .iter()
            .filter(|(_, slot, width)| {
                *slot < end && slot.saturating_add(i64::from(*width)) > start
            })
            .map(|(_, slot, width)| (*slot, *width))
            .collect();
        fields.sort_unstable();
        fields.dedup();
        let mut last = start;
        let mut valid = fields.len() >= 2;
        for (slot, width) in fields {
            let Some(next) = slot.checked_add(i64::from(width)) else {
                valid = false;
                break;
            };
            if slot < last || next > end || !matches!(width, 1 | 2 | 4 | 8) {
                valid = false;
                break;
            }
            last = next;
        }
        if valid {
            ranges.push((start, end));
        }
    }
    ranges
}

fn loads<'a>(expr: &'a Expr, touches: &mut Vec<(&'a Expr, u8)>) {
    if let Expr::Load { addr, width, .. } = expr {
        touches.push((addr, *width));
    }
    for child in crate::ir::visit::children(expr) {
        loads(child, touches);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BinOp, RegRef, VARIABLE_BASE};
    use crate::loader::Isa;

    #[test]
    fn overlapping_widths_and_reassigned_addresses_do_not_make_objects() {
        for isa in [Isa::X86_64, Isa::AArch64] {
            let sp = crate::arch::stack_pointer(isa);
            let at = |register, offset| {
                Expr::bin(BinOp::Add, Expr::reg(register, 64), Expr::Const(offset))
            };
            let assignment = Stmt::Assign {
                dest: RegRef {
                    index: VARIABLE_BASE,
                    width: 64,
                },
                value: at(sp, (-32i64) as u64),
            };
            let stores = [
                Stmt::Store {
                    addr: at(VARIABLE_BASE, 0),
                    value: Expr::Const(1),
                    width: 8,
                },
                Stmt::Store {
                    addr: at(VARIABLE_BASE, 16),
                    value: Expr::Const(2),
                    width: 8,
                },
            ];
            for case in 0..3 {
                let mut stmts = vec![assignment.clone()];
                stmts.extend(stores.clone());
                if case == 0 {
                    stmts.push(Stmt::Store {
                        addr: at(sp, (-28i64) as u64),
                        value: Expr::Const(3),
                        width: 4,
                    });
                } else if case == 1 {
                    stmts.push(assignment.clone());
                } else {
                    stmts.push(Stmt::Machine {
                        instruction: crate::ir::MachineInstruction::ArmLoadAcquire { width: 8 },
                        inputs: vec![at(VARIABLE_BASE, 4)],
                        outputs: vec![RegRef {
                            index: VARIABLE_BASE + 1,
                            width: 64,
                        }],
                    });
                }
                let ir = FunctionIr::single_block(isa, stmts);
                let entries = super::super::origins(&ir, &Origins::from([(sp, Some(0))])).unwrap();
                assert!(ranges(&ir, &entries, sp).is_empty());
            }
        }
    }
}

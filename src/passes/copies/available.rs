//! Copies whose source still holds the copied value at every use.

use std::collections::{HashMap, HashSet};

use crate::ir::visit;
use crate::ir::{CType, Expr, FunctionIr, Stmt, VARIABLE_BASE};

pub(crate) fn redundant_copy_renames(ir: &FunctionIr) -> Option<HashMap<u16, u16>> {
    if ir.blocks.is_empty()
        || !ir.landing_pads.is_empty()
        || ir.blocks.iter().any(crate::ir::cfg::opaque)
    {
        return None;
    }
    let types = crate::render::variable_types(ir);
    let mut copies = HashMap::new();
    let mut excluded = HashSet::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        let (writes, reads) = visit::statement_registers(stmt);
        let copy = match stmt {
            Stmt::Assign {
                dest,
                value: Expr::Reg { index, width: 64 },
                ..
            } if dest.width == 64 && dest.index >= VARIABLE_BASE && dest.index != *index => {
                let source = types.get(index);
                let same_type = source == types.get(&dest.index)
                    && source.is_some_and(|ty| matches!(ty, CType::Int { .. } | CType::Pointer(_)));
                same_type.then_some((dest.index, *index))
            }
            _ => None,
        };
        for written in writes {
            if let Some((dest, source)) = copy
                && dest == written
            {
                if copies.insert(dest, source).is_some_and(|old| old != source) {
                    excluded.insert(dest);
                }
            } else {
                excluded.insert(written);
            }
        }
        excluded.extend(stmt.declared_call_reads());
        excluded.extend(stmt.unnamed_call_reads());
        if matches!(stmt, Stmt::Call { .. }) {
            excluded.extend(reads);
        }
        excluded.extend(
            stmt.preserved_output_sources()
                .iter()
                .map(|(_, source)| *source),
        );
    }
    copies.retain(|dest, _| !excluded.contains(dest));
    if copies.is_empty() {
        return None;
    }
    let reached = crate::ir::cfg::reached(ir);
    let mut incoming = vec![Vec::new(); ir.blocks.len()];
    let mut disconnected = HashSet::new();
    for (index, block) in ir.blocks.iter().enumerate() {
        if !reached.contains(&block.start) {
            // Unreachable code can have an entry outside the modeled graph.
            for stmt in &block.stmts {
                let (writes, reads) = visit::statement_registers(stmt);
                disconnected.extend(writes);
                disconnected.extend(reads);
            }
            continue;
        }
        for next in crate::ir::cfg::successors(ir, index) {
            incoming[next].push(index);
        }
    }
    copies.retain(|dest, source| !disconnected.contains(dest) && !disconnected.contains(source));
    if copies.is_empty() {
        return None;
    }
    let all: HashSet<u16> = copies.keys().copied().collect();
    let mut exits = vec![all; ir.blocks.len()];
    let entry = |index: usize, exits: &[HashSet<u16>]| {
        if index == 0 || incoming[index].is_empty() {
            return HashSet::new();
        }
        let mut available = exits[incoming[index][0]].clone();
        for from in &incoming[index][1..] {
            available.retain(|dest| exits[*from].contains(dest));
        }
        available
    };
    loop {
        let mut changed = false;
        for (index, block) in ir.blocks.iter().enumerate() {
            let mut available = entry(index, &exits);
            for stmt in &block.stmts {
                transfer(stmt, &copies, &mut available);
            }
            changed |= available != exits[index];
            exits[index] = available;
        }
        if !changed {
            break;
        }
    }
    let mut valid: HashSet<u16> = copies.keys().copied().collect();
    for (index, block) in ir.blocks.iter().enumerate() {
        let mut available = entry(index, &exits);
        for stmt in &block.stmts {
            let (_, reads) = visit::statement_registers(stmt);
            valid.retain(|dest| !reads.contains(dest) || available.contains(dest));
            transfer(stmt, &copies, &mut available);
        }
    }
    copies.retain(|dest, _| valid.contains(dest));
    if copies.is_empty() {
        return None;
    }
    // Keep dependent copies: removing them together could introduce source reads
    // after the source's own copy stopped being available.
    let destinations: HashSet<u16> = copies.keys().copied().collect();
    copies.retain(|_, source| !destinations.contains(source));
    (!copies.is_empty()).then_some(copies)
}

fn transfer(stmt: &Stmt, copies: &HashMap<u16, u16>, available: &mut HashSet<u16>) {
    let (writes, _) = visit::statement_registers(stmt);
    available.retain(|dest| !writes.contains(dest) && !writes.contains(&copies[dest]));
    if let Stmt::Assign {
        dest,
        value: Expr::Reg { index, width: 64 },
        ..
    } = stmt
        && dest.width == 64
        && copies.get(&dest.index) == Some(index)
    {
        available.insert(dest.index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BinOp, Block, Cond, Param, RegRef};
    use crate::loader::Isa;

    fn redundant_copy_candidate(ir: &FunctionIr) -> Option<FunctionIr> {
        let Some(renamed) = redundant_copy_renames(ir) else {
            return None;
        };
        let mut candidate = ir.clone();
        for block in &mut candidate.blocks {
            block.stmts.retain(|stmt| {
                !matches!(stmt, Stmt::Assign { dest, .. } if renamed.contains_key(&dest.index))
            });
            for stmt in &mut block.stmts {
                crate::passes::coalesce::rename(stmt, &renamed);
            }
        }
        Some(candidate)
    }

    fn copy(dest: u16, source: u16) -> Stmt {
        Stmt::Assign {
            dest: RegRef {
                index: dest,
                width: 64,
            },
            value: Expr::reg(source, 64),
            at: None,
        }
    }

    fn diamond() -> FunctionIr {
        let (source, dest) = (VARIABLE_BASE, VARIABLE_BASE + 1);
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                Stmt::Assign {
                    dest: RegRef {
                        index: source,
                        width: 64,
                    },
                    value: Expr::bin(BinOp::Xor, Expr::reg(7, 64), Expr::Const(123)),
                    at: None,
                },
                Stmt::Brif {
                    cond: crate::ir::Cond::Eq,
                    lhs: Expr::reg(6, 64),
                    rhs: Expr::Const(0),
                    target: 2,
                    at: None,
                },
            ],
        );
        ir.params = vec![
            Param {
                index: 7,
                name: "input".into(),
                ty: CType::U64,
            },
            Param {
                index: 6,
                name: "flag".into(),
                ty: CType::U64,
            },
        ];
        ir.ret_type = CType::U64;
        ir.value_types = [(source, CType::U64), (dest, CType::U64)].into();
        for start in [1, 2] {
            ir.blocks.push(Block {
                start,
                stmts: vec![
                    copy(dest, source),
                    Stmt::Br {
                        target: Some(3),
                        at: None,
                    },
                ],
            });
        }
        ir.blocks.push(Block {
            start: 3,
            stmts: vec![Stmt::Ret {
                value: Expr::bin(BinOp::Add, Expr::reg(dest, 64), Expr::reg(source, 64)),
                at: None,
            }],
        });
        ir
    }

    #[test]
    fn copies_agree_at_joins_and_keep_narrow_reads() {
        let mut ir = diamond();
        ir.blocks[3].stmts[0] = Stmt::Ret {
            value: Expr::bin(
                BinOp::Add,
                Expr::reg(VARIABLE_BASE + 1, 8),
                Expr::bin(
                    BinOp::Add,
                    Expr::reg(VARIABLE_BASE + 1, 64),
                    Expr::reg(VARIABLE_BASE, 64),
                ),
            ),
            at: None,
        };
        let folded = redundant_copy_candidate(&ir).expect("both paths copy the same stable value");
        assert!(
            matches!(&folded.blocks[3].stmts[0], Stmt::Ret { value: Expr::Bin { lhs, .. }, .. }
            if **lhs == Expr::reg(VARIABLE_BASE, 8))
        );
        assert!(
            folded.blocks[1]
                .stmts
                .iter()
                .all(|stmt| !matches!(stmt, Stmt::Assign { .. }))
        );
    }

    #[test]
    fn missing_definitions_and_source_overwrites_keep_snapshots() {
        for case in 0..4 {
            let mut ir = diamond();
            match case {
                0 => {
                    ir.blocks[2].stmts.remove(0);
                }
                1 => ir.blocks[2].stmts.insert(1, copy(VARIABLE_BASE, 7)),
                2 => ir.blocks[3].stmts.insert(0, copy(VARIABLE_BASE, 7)),
                _ => ir.blocks[2].stmts[0] = copy(VARIABLE_BASE + 1, 7),
            }
            assert!(redundant_copy_candidate(&ir).is_none(), "case {case}");
        }
    }

    #[test]
    fn loops_must_reestablish_copies_after_source_updates() {
        let mut ir = diamond();
        ir.blocks[3].stmts = vec![
            Stmt::Assign {
                dest: RegRef {
                    index: VARIABLE_BASE,
                    width: 64,
                },
                value: Expr::bin(BinOp::Add, Expr::reg(VARIABLE_BASE, 64), Expr::Const(1)),
                at: None,
            },
            Stmt::Brif {
                cond: Cond::Ne,
                lhs: Expr::reg(VARIABLE_BASE + 1, 64),
                rhs: Expr::Const(0),
                target: 3,
                at: None,
            },
        ];
        assert!(redundant_copy_candidate(&ir).is_none());
    }

    #[test]
    fn copy_chains_do_not_extend_source_lifetimes() {
        let (source, first, second) = (VARIABLE_BASE, VARIABLE_BASE + 1, VARIABLE_BASE + 2);
        let mut ir = diamond();
        ir.blocks.truncate(1);
        ir.blocks[0].stmts.truncate(1);
        ir.blocks[0].stmts.extend([
            copy(first, source),
            copy(second, first),
            Stmt::Assign {
                dest: RegRef {
                    index: source,
                    width: 64,
                },
                value: Expr::bin(BinOp::Add, Expr::reg(source, 64), Expr::Const(1)),
                at: None,
            },
            Stmt::Ret {
                value: Expr::bin(BinOp::Add, Expr::reg(second, 64), Expr::reg(source, 64)),
                at: None,
            },
        ]);
        ir.value_types.insert(second, CType::U64);
        let renamed = redundant_copy_renames(&ir).expect("the first copy is redundant");
        assert_eq!(renamed, HashMap::from([(first, source)]));
    }
}

//! Variables joined where a copy moves a value from one to the other and
//! their lives do not overlap. Leaving SSA form names each value apart and
//! connects them with copies, as `v4 = v1; ... v1 = v4;` around a loop;
//! when no point needs both, they are one variable, and the copies go.

use std::collections::{HashMap, HashSet};

use crate::ir::cfg::{live_in, live_out, opaque};
use crate::ir::visit::statement_registers;
use crate::ir::{Expr, FunctionIr, Stmt, VARIABLE_BASE};

pub fn coalesce_copies(ir: &mut FunctionIr) {
    if ir.blocks.iter().any(opaque) {
        return;
    }
    // How many low bits each variable's values can have: a read of fewer
    // bits of another variable holds the same value only when it covers
    // them all.
    let mut bits: HashMap<u16, u32> = HashMap::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        let (dest, held) = match stmt {
            Stmt::Assign { dest, value } => {
                let hi = crate::ssa::ranges::of(value).hi;
                (*dest, (64 - hi.leading_zeros()).min(u32::from(dest.width)))
            }
            Stmt::Call {
                result: Some(result),
                ..
            } => (*result, u32::from(result.width)),
            _ => continue,
        };
        let most = bits.entry(dest.index).or_default();
        *most = (*most).max(held);
    }
    // A copy of another variable's value, as itself or masked to bits that
    // cover it.
    let same_value = |stmt: &Stmt| {
        let Stmt::Assign { dest, value } = stmt else {
            return None;
        };
        let (index, read) = match value {
            Expr::Reg { index, width } => (*index, u32::from(*width)),
            Expr::Bin {
                op: crate::ir::BinOp::And,
                lhs,
                rhs,
            } => match (lhs.as_ref(), rhs.as_ref()) {
                (Expr::Reg { index, width }, Expr::Const(mask))
                    if mask.wrapping_add(1) & mask == 0 =>
                {
                    (*index, u32::from(*width).min(mask.count_ones()))
                }
                _ => return None,
            },
            _ => return None,
        };
        (dest.index >= VARIABLE_BASE
            && index >= VARIABLE_BASE
            && index != dest.index
            && read.min(u32::from(dest.width)) >= bits.get(&index).copied().unwrap_or(64))
        .then_some((dest.index, index))
    };

    for block in &mut ir.blocks {
        sink_copied_definitions(&mut block.stmts, &same_value);
    }

    // Two variables interfere where one is given a value while the other,
    // holding another, is still to be read.
    let live_in = live_in(ir);
    let mut interferes: HashMap<u16, HashSet<u16>> = HashMap::new();
    let mut copies = Vec::new();
    for index in 0..ir.blocks.len() {
        let mut live = live_out(ir, &live_in, index);
        for stmt in ir.blocks[index].stmts.iter().rev() {
            let (writes, reads) = statement_registers(stmt);
            let copy = same_value(stmt);
            if let Some(copy) = copy {
                copies.push(copy);
            }
            for written in writes.iter().filter(|written| **written >= VARIABLE_BASE) {
                for other in live.iter().filter(|other| **other >= VARIABLE_BASE) {
                    if other != written && copy.is_none_or(|(_, source)| source != *other) {
                        interferes.entry(*written).or_default().insert(*other);
                        interferes.entry(*other).or_default().insert(*written);
                    }
                }
            }
            for written in &writes {
                live.remove(written);
            }
            live.extend(reads);
        }
    }
    // The variables live on entry hold what the caller left, which no copy
    // gave them.
    let entry: HashSet<u16> = live_in.first().cloned().unwrap_or_default();

    let mut leader: HashMap<u16, u16> = HashMap::new();
    let find = |leader: &HashMap<u16, u16>, mut variable: u16| {
        while let Some(next) = leader.get(&variable) {
            variable = *next;
        }
        variable
    };
    let mut members: HashMap<u16, Vec<u16>> = HashMap::new();
    let mut joined = false;
    for (dest, source) in copies {
        let (a, b) = (find(&leader, dest), find(&leader, source));
        if a == b || (entry.contains(&a) && entry.contains(&b)) {
            continue;
        }
        let group = |leader: u16, members: &HashMap<u16, Vec<u16>>| {
            members
                .get(&leader)
                .cloned()
                .unwrap_or_else(|| vec![leader])
        };
        let (first, second) = (group(a, &members), group(b, &members));
        let clash = first.iter().any(|x| {
            interferes
                .get(x)
                .is_some_and(|others| second.iter().any(|y| others.contains(y)))
        });
        if clash {
            continue;
        }
        // The lower index names the group, as the earlier variable does.
        let (keep, drop) = if a < b { (a, b) } else { (b, a) };
        leader.insert(drop, keep);
        let mut all = first;
        all.extend(second);
        members.remove(&drop);
        members.insert(keep, all);
        joined = true;
    }
    if !joined {
        return;
    }
    let renamed: HashMap<u16, u16> = leader
        .keys()
        .map(|variable| (*variable, find(&leader, *variable)))
        .collect();
    let class = |variable: u16| renamed.get(&variable).copied().unwrap_or(variable);
    for block in &mut ir.blocks {
        // A copy within one variable now moves nothing.
        block.stmts.retain(|stmt| {
            !same_value(stmt).is_some_and(|(dest, source)| class(dest) == class(source))
        });
        for stmt in &mut block.stmts {
            rename(stmt, &renamed);
        }
    }
}

/// Moves the definition of a value a copy later in the block moves on down
/// to just before that copy, when nothing between reads what it defines or
/// changes what it reads. A loop computes its next value early, as
/// `v4 = v4 >> 4; v5 = v1 & 0xf; ... v1 = v4;`, and the old value stays in
/// use beside the new one; given just before the copy, the two no longer
/// overlap and can be one variable.
fn sink_copied_definitions(
    stmts: &mut Vec<Stmt>,
    same_value: &impl Fn(&Stmt) -> Option<(u16, u16)>,
) {
    let mut copy = 0;
    while copy < stmts.len() {
        let Some((_, source)) = same_value(&stmts[copy]) else {
            copy += 1;
            continue;
        };
        let defines = |stmt: &Stmt| statement_registers(stmt).0.contains(&source);
        let Some(definition) = stmts[..copy].iter().rposition(defines) else {
            copy += 1;
            continue;
        };
        let Stmt::Assign { value, .. } = &stmts[definition] else {
            copy += 1;
            continue;
        };
        let mut reads = HashSet::new();
        crate::ir::visit::collect_reads(value, &mut reads);
        let loads = !load_free(value);
        let movable = stmts[definition + 1..copy].iter().all(|stmt| {
            let (writes, read) = statement_registers(stmt);
            !read.contains(&source)
                && writes.is_disjoint(&reads)
                && !(loads && matches!(stmt, Stmt::Store { .. } | Stmt::Call { .. }))
        });
        if movable && definition + 1 < copy {
            let moved = stmts.remove(definition);
            stmts.insert(copy - 1, moved);
        }
        copy += 1;
    }
}

/// Gives each variable `renamed` names the variable it joined.
fn rename(stmt: &mut Stmt, renamed: &HashMap<u16, u16>) {
    fn walk(expr: &mut Expr, renamed: &HashMap<u16, u16>) {
        if let Expr::Reg { index, .. } = expr
            && let Some(joined) = renamed.get(index)
        {
            *index = *joined;
        }
        for child in crate::ir::visit::children_mut(expr) {
            walk(child, renamed);
        }
    }
    match stmt {
        Stmt::Assign { dest, .. }
        | Stmt::Call {
            result: Some(dest), ..
        } => {
            if let Some(joined) = renamed.get(&dest.index) {
                dest.index = *joined;
            }
        }
        _ => {}
    }
    for expr in stmt.operands_mut() {
        walk(expr, renamed);
    }
}

fn load_free(expr: &Expr) -> bool {
    match expr {
        Expr::Load { .. } => false,
        _ => crate::ir::visit::children(expr).into_iter().all(load_free),
    }
}

#[cfg(test)]
mod tests {
    use super::coalesce_copies;
    use crate::ir::{BinOp, Block, Cond, Expr, FunctionIr, RegRef, Stmt, VARIABLE_BASE};
    use crate::loader::Isa;

    fn assign(index: u16, value: Expr) -> Stmt {
        Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
        }
    }

    /// v1 = load; v4 = v1; loop: { v4 = v4 >> 4; v5 = v1 & 0xf; v1 = v4;
    /// if (v4 != 0) loop } return v5.
    fn shifting_loop() -> FunctionIr {
        let (v1, v4, v5) = (VARIABLE_BASE, VARIABLE_BASE + 3, VARIABLE_BASE + 4);
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                assign(
                    v1,
                    Expr::Load {
                        addr: Box::new(Expr::reg(7, 64)),
                        width: 4,
                        signed: false,
                    },
                ),
                assign(v4, Expr::reg(v1, 64)),
            ],
        );
        ir.blocks.push(Block {
            start: 0x10,
            stmts: vec![
                assign(v4, Expr::bin(BinOp::Shr, Expr::reg(v4, 64), Expr::Const(4))),
                assign(
                    v5,
                    Expr::bin(BinOp::And, Expr::reg(v1, 64), Expr::Const(0xf)),
                ),
                assign(v1, Expr::reg(v4, 64)),
                Stmt::Brif {
                    cond: Cond::Ne,
                    lhs: Expr::reg(v4, 64),
                    rhs: Expr::Const(0),
                    target: 0x10,
                },
            ],
        });
        ir.blocks.push(Block {
            start: 0x20,
            stmts: vec![Stmt::Ret {
                value: Expr::reg(v5, 64),
            }],
        });
        ir
    }

    #[test]
    fn a_loop_value_and_its_next_one_become_one_variable() {
        let mut ir = shifting_loop();
        coalesce_copies(&mut ir);
        let text = ir.render();
        let copies = ir
            .blocks
            .iter()
            .flat_map(|block| &block.stmts)
            .filter(|stmt| {
                matches!(
                    stmt,
                    Stmt::Assign {
                        value: Expr::Reg { .. },
                        ..
                    }
                )
            })
            .count();
        assert_eq!(copies, 0, "{text}");
        // The next value is computed after the last read of the current one.
        let body = &ir.blocks[1].stmts;
        assert!(
            matches!(
                &body[0],
                Stmt::Assign {
                    value: Expr::Bin { op: BinOp::And, .. },
                    ..
                }
            ),
            "{text}"
        );
    }

    #[test]
    fn variables_holding_different_values_at_once_stay_apart() {
        // v2 = v1; v1 = v1 + 1; return v1 + v2: both are read after v1
        // changes.
        let (v1, v2) = (VARIABLE_BASE, VARIABLE_BASE + 1);
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                assign(v1, Expr::reg(7, 64)),
                assign(v2, Expr::reg(v1, 64)),
                assign(v1, Expr::bin(BinOp::Add, Expr::reg(v1, 64), Expr::Const(1))),
                Stmt::Ret {
                    value: Expr::bin(BinOp::Add, Expr::reg(v1, 64), Expr::reg(v2, 64)),
                },
            ],
        );
        coalesce_copies(&mut ir);
        assert!(
            ir.blocks[0].stmts.iter().any(
                |stmt| matches!(stmt, Stmt::Assign { dest, value: Expr::Reg { index, .. } }
                    if dest.index == v2 && *index == v1)
            ),
            "{}",
            ir.render()
        );
    }

    #[test]
    fn a_narrow_read_of_a_wider_value_is_no_copy() {
        // v2 = v1 & 0xffffffff where v1 can hold 64 bits changes the value.
        let (v1, v2) = (VARIABLE_BASE, VARIABLE_BASE + 1);
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                assign(v1, Expr::reg(7, 64)),
                assign(
                    v2,
                    Expr::bin(BinOp::And, Expr::reg(v1, 64), Expr::Const(0xffff_ffff)),
                ),
                Stmt::Ret {
                    value: Expr::reg(v2, 64),
                },
            ],
        );
        coalesce_copies(&mut ir);
        assert_eq!(ir.blocks[0].stmts.len(), 3, "{}", ir.render());
    }
}

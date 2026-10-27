//! Variables joined where a copy moves a value from one to the other and
//! their lives do not overlap. Leaving SSA form names each value apart and
//! connects them with copies, as `v4 = v1; ... v1 = v4;` around a loop;
//! when no point needs both, they are one variable, and the copies go.

use std::collections::{HashMap, HashSet};

use crate::ir::cfg::{live_in, live_out, opaque};
use crate::ir::visit::statement_registers;
use crate::ir::{Expr, FunctionIr, Stmt, VARIABLE_BASE};

mod pointers;
pub(crate) use pointers::reuse_pointers;

pub fn coalesce_copies(ir: &mut FunctionIr) {
    if ir.blocks.iter().any(opaque) {
        return;
    }
    // How many low bits each variable's values can have: a read of fewer
    // bits of another variable holds the same value only when it covers
    // them all.
    let mut bits: HashMap<u16, u32> = HashMap::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        if let Stmt::Assign { dest, value } = stmt {
            let hi = crate::ssa::ranges::of(value).hi;
            let held = (64 - hi.leading_zeros()).min(u32::from(dest.width));
            let most = bits.entry(dest.index).or_default();
            *most = (*most).max(held);
        }
        for output in stmt.call_outputs() {
            let most = bits.entry(output.dest.index).or_default();
            *most = (*most).max(u32::from(output.dest.width));
        }
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

    let (interferes, copies, entry) = interference(ir, &same_value);

    let mut groups = Groups::default();
    let mut joined = false;
    for (dest, source) in copies {
        joined |= groups.join(dest, source, &interferes, &entry);
    }
    // Values a register held one after another, of one width, are one
    // variable too where their lives do not overlap, as the register is
    // in the machine code: a counter reused for a second loop.
    let mut addresses = HashSet::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        if let Stmt::Store { addr, .. } = stmt {
            crate::ir::visit::collect_reads(addr, &mut addresses);
        }
        for operand in stmt.operands() {
            address_reads(operand, &mut addresses);
        }
    }
    // Only plain values: one that takes part in an address, as a base or
    // an index, would give its pointer type to the other's values.
    let mut kinds: HashMap<(u16, bool), Vec<u16>> = HashMap::new();
    for (variable, register) in &ir.variable_registers {
        if !bits.contains_key(variable) || addresses.contains(variable) {
            continue;
        }
        let wide = bits.get(variable).copied().unwrap_or(64) > 32;
        kinds.entry((*register, wide)).or_default().push(*variable);
    }
    let mut kinds: Vec<Vec<u16>> = kinds.into_values().collect();
    kinds.sort();
    for kind in kinds {
        for (at, variable) in kind.iter().enumerate() {
            for earlier in &kind[..at] {
                // Nor through a copy already joined to one.
                let addressed = |member: u16| {
                    groups
                        .group(member)
                        .iter()
                        .any(|other| addresses.contains(other))
                };
                if addressed(*earlier) || addressed(*variable) {
                    continue;
                }
                if groups.join(*earlier, *variable, &interferes, &entry) {
                    joined = true;
                    break;
                }
            }
        }
    }
    if !joined {
        return;
    }
    let renamed: HashMap<u16, u16> = groups
        .leader
        .keys()
        .map(|variable| (*variable, groups.find(*variable)))
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

type Interference = HashMap<u16, HashSet<u16>>;

fn interference(
    ir: &FunctionIr,
    same_value: &impl Fn(&Stmt) -> Option<(u16, u16)>,
) -> (Interference, Vec<(u16, u16)>, HashSet<u16>) {
    let live_in = live_in(ir);
    let mut interferes: Interference = HashMap::new();
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
    let entry = live_in.first().cloned().unwrap_or_default();
    (interferes, copies, entry)
}

/// Variables joined so far, each group named by its lowest variable.
#[derive(Default)]
struct Groups {
    leader: HashMap<u16, u16>,
    members: HashMap<u16, Vec<u16>>,
}

impl Groups {
    /// The members of the group `variable` is in.
    fn group(&self, variable: u16) -> Vec<u16> {
        let leader = self.find(variable);
        self.members
            .get(&leader)
            .cloned()
            .unwrap_or_else(|| vec![leader])
    }

    fn find(&self, mut variable: u16) -> u16 {
        while let Some(next) = self.leader.get(&variable) {
            variable = *next;
        }
        variable
    }

    /// Joins the groups of `a` and `b` unless a member of one interferes
    /// with a member of the other, or both hold what the caller left.
    fn join(
        &mut self,
        a: u16,
        b: u16,
        interferes: &HashMap<u16, HashSet<u16>>,
        entry: &HashSet<u16>,
    ) -> bool {
        let (a, b) = (self.find(a), self.find(b));
        if a == b {
            return false;
        }
        let (first, second) = (self.group(a), self.group(b));
        if first.iter().any(|x| entry.contains(x)) && second.iter().any(|x| entry.contains(x)) {
            return false;
        }
        let clash = first.iter().any(|x| {
            interferes
                .get(x)
                .is_some_and(|others| second.iter().any(|y| others.contains(y)))
        });
        if clash {
            return false;
        }
        // The lower index names the group, as the earlier variable does.
        let (keep, drop) = if a < b { (a, b) } else { (b, a) };
        self.leader.insert(drop, keep);
        let mut all = first;
        all.extend(second);
        self.members.remove(&drop);
        self.members.insert(keep, all);
        true
    }
}

/// The registers `expr`'s loads read their addresses from.
fn address_reads(expr: &Expr, out: &mut HashSet<u16>) {
    if let Expr::Load { addr, .. } = expr {
        crate::ir::visit::collect_reads(addr, out);
    }
    for child in crate::ir::visit::children(expr) {
        address_reads(child, out);
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
                && writes.iter().all(|register| !reads.contains(register))
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
pub(crate) fn rename(stmt: &mut Stmt, renamed: &HashMap<u16, u16>) {
    for dest in crate::ir::visit::statement_destinations_mut(stmt) {
        if let Some(joined) = renamed.get(&dest.index) {
            dest.index = *joined;
        }
    }
    for expr in stmt.operands_mut() {
        crate::ir::visit::rename_registers(expr, renamed);
    }
}

fn load_free(expr: &Expr) -> bool {
    !super::copies::reads_memory(expr)
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

    #[test]
    fn values_a_register_held_one_after_another_become_one_variable() {
        // v1 = a0 + 1; v2 = v1 * 2; v3 = a1 + 3; return v2 + v3, with v1 and
        // v3 from one register: v1 is dead before v3 is set.
        let (v1, v2, v3) = (VARIABLE_BASE, VARIABLE_BASE + 1, VARIABLE_BASE + 2);
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                assign(v1, Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(1))),
                assign(v2, Expr::bin(BinOp::Mul, Expr::reg(v1, 64), Expr::Const(2))),
                assign(v3, Expr::bin(BinOp::Add, Expr::reg(6, 64), Expr::Const(3))),
                Stmt::Ret {
                    value: Expr::bin(BinOp::Add, Expr::reg(v2, 64), Expr::reg(v3, 64)),
                },
            ],
        );
        ir.variable_registers = [(v1, 0), (v2, 1), (v3, 0)].into_iter().collect();
        let mut addressed = ir.clone();
        coalesce_copies(&mut ir);
        let written: Vec<u16> = ir.blocks[0]
            .stmts
            .iter()
            .filter_map(|stmt| match stmt {
                Stmt::Assign { dest, .. } => Some(dest.index),
                _ => None,
            })
            .collect();
        assert_eq!(written, [v1, v2, v1], "{}", ir.render());
        // One that an address reads stays apart.
        addressed.blocks[0].stmts[3] = Stmt::Ret {
            value: Expr::Load {
                addr: Box::new(Expr::reg(v3, 64)),
                width: 8,
                signed: false,
            },
        };
        coalesce_copies(&mut addressed);
        assert!(
            matches!(&addressed.blocks[0].stmts[2], Stmt::Assign { dest, .. } if dest.index == v3),
            "{}",
            addressed.render()
        );
    }

    #[test]
    fn a_register_reused_for_a_pointer_copy_keeps_the_values_apart() {
        // v1 = a0 + 1; v2 = v1 * 2; v3 = a1 + 3; v4 = v3; return *v4 + v2,
        // with v1 and v3 from one register: v3 moves on to an address, so
        // the integer before it in the register stays its own variable.
        let (v1, v2, v3, v4) = (
            VARIABLE_BASE,
            VARIABLE_BASE + 1,
            VARIABLE_BASE + 2,
            VARIABLE_BASE + 3,
        );
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                assign(v1, Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(1))),
                assign(v2, Expr::bin(BinOp::Mul, Expr::reg(v1, 64), Expr::Const(2))),
                assign(v3, Expr::bin(BinOp::Add, Expr::reg(6, 64), Expr::Const(3))),
                assign(v4, Expr::reg(v3, 64)),
                Stmt::Ret {
                    value: Expr::bin(
                        BinOp::Add,
                        Expr::Load {
                            addr: Box::new(Expr::reg(v4, 64)),
                            width: 8,
                            signed: false,
                        },
                        Expr::reg(v2, 64),
                    ),
                },
            ],
        );
        ir.variable_registers = [(v1, 0), (v2, 1), (v3, 0), (v4, 2)].into_iter().collect();
        coalesce_copies(&mut ir);
        let written: Vec<u16> = ir.blocks[0]
            .stmts
            .iter()
            .filter_map(|stmt| match stmt {
                Stmt::Assign { dest, .. } => Some(dest.index),
                _ => None,
            })
            .collect();
        assert_eq!(written, [v1, v2, v3], "{}", ir.render());
    }
    #[test]
    fn coalesces_every_call_output_without_renaming_physical_sources() {
        let output_registers = [32, 34, 36, 38];
        let mut outputs = crate::ir::fallback_call_outputs(crate::ir::Convention::Aapcs64, None);
        outputs.retain(|output| matches!(output.register, 32 | 34));
        outputs.extend([36, 38].into_iter().map(|register| crate::ir::CallOutput {
            register,
            dest: RegRef {
                index: register,
                width: 64,
            },
        }));
        for (index, output) in outputs.iter_mut().enumerate() {
            output.dest.index = VARIABLE_BASE + 4 + index as u16;
        }
        let mut stmts = vec![Stmt::Call {
            kind: crate::ir::CallKind::Invoke,
            target: Some(0x1000),
            through: None,
            convention: crate::ir::Convention::Aapcs64,
            args: Some(Vec::new()),
            floats_named: true,
            abi: None,
            clobbers: None,
            outputs,
            via: None,
        }];
        for index in 0..4u16 {
            stmts.push(Stmt::Assign {
                dest: RegRef {
                    index: VARIABLE_BASE + index,
                    width: 64,
                },
                value: Expr::reg(VARIABLE_BASE + 4 + index, 64),
            });
        }
        for index in 0..4u16 {
            stmts.push(Stmt::Store {
                addr: Expr::Const(0x1000 + u64::from(index) * 8),
                value: Expr::reg(VARIABLE_BASE + index, 64),
                width: 8,
            });
        }
        stmts.push(Stmt::Ret {
            value: Expr::Const(0),
        });
        let mut ir = FunctionIr::single_block(Isa::AArch64, stmts);
        let before = ir.clone();
        coalesce_copies(&mut ir);
        assert_eq!(ir.blocks[0].stmts.len(), 6, "{}", ir.render());
        assert_eq!(
            ir.blocks[0].stmts[0]
                .call_outputs()
                .iter()
                .map(|output| output.register)
                .collect::<Vec<_>>(),
            output_registers
        );
        assert_eq!(
            ir.blocks[0].stmts[0]
                .call_outputs()
                .iter()
                .map(|output| output.dest.index)
                .collect::<Vec<_>>(),
            [
                VARIABLE_BASE,
                VARIABLE_BASE + 1,
                VARIABLE_BASE + 2,
                VARIABLE_BASE + 3
            ]
        );
        for seed in [0, 1, 0x1234_5678] {
            let setup = crate::ir::eval::Setup {
                seed,
                convention: crate::ir::eval::Convention {
                    arguments: &[],
                    clobbered: &[],
                },
                registers: &[],
                memory: &[],
                step_limit: 64,
            };
            let expected = crate::ir::eval::run(&before, &setup);
            assert!(
                matches!(&expected, crate::ir::eval::Outcome::Return { memory, .. } if memory.len() == 32)
            );
            assert_eq!(crate::ir::eval::run(&ir, &setup), expected);
        }
    }
}

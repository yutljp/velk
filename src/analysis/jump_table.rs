use crate::ir::{BinOp, Block, Expr, Stmt};
use crate::loader::Image;

#[derive(Debug, Clone)]
pub struct Recovered {
    pub block_start: u64,
    pub index: Expr,
    pub cases: Vec<(i64, u64)>,
    pub default: Option<u64>,
    /// Where the table lies and how many bytes it takes, which the tests
    /// read the cases' targets from.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "The table location is inspected only by recovery tests."
        )
    )]
    pub table: (u64, u64),
}

impl Recovered {
    pub fn targets(&self) -> Vec<u64> {
        let mut targets: Vec<u64> = self.cases.iter().map(|(_, target)| *target).collect();
        targets.extend(self.default);
        targets
    }
}

/// The jump tables of the blocks. A table with no bounds check, as a
/// dispatch on an enum whose range the compiler knows, has its entries read
/// while they point into `extent` and before any address the code computes,
/// where the next table would begin. A table's address held in a register
/// since an earlier block counts, as found through the tables already read.
pub fn recover(blocks: &[Block], image: &Image, extent: std::ops::Range<u64>) -> Vec<Recovered> {
    let mut recovered = recover_once(blocks, image, &extent, &[]);
    for _ in 0..4 {
        let again = recover_once(blocks, image, &extent, &recovered);
        if again.len() <= recovered.len() {
            break;
        }
        recovered = again;
    }
    recovered
}

fn recover_once(
    blocks: &[Block],
    image: &Image,
    extent: &std::ops::Range<u64>,
    known: &[Recovered],
) -> Vec<Recovered> {
    let starts = image.addressed.get_or_init(|| addressed(image));
    let held = held_constants(blocks, known);
    let mut recovered = Vec::new();
    for (index, block) in blocks.iter().enumerate() {
        let Some(Stmt::BrIndirect { target }) = block.stmts.last() else {
            continue;
        };
        let checked = index
            .checked_sub(1)
            .and_then(|previous| blocks.get(previous));
        let bound = checked.and_then(bound);
        let limits = Limits {
            extent: extent.clone(),
            tables: starts,
            held: &held[index],
        };
        if let Some(mut entry) = recognize(block, target, image, bound, checked, &limits) {
            entry.block_start = block.start;
            recovered.push(entry);
        }
    }
    recovered
}

pub(crate) fn bound(block: &Block) -> Option<(i64, Option<u64>, i64, Expr)> {
    let Stmt::Brif {
        cond,
        lhs,
        rhs,
        target,
    } = block.stmts.last()?
    else {
        return Option::None;
    };
    if !matches!(cond, crate::ir::Cond::Hi | crate::ir::Cond::Cs) {
        return Option::None;
    }
    let Expr::Const(limit) = rhs else {
        return Option::None;
    };
    // The bounds check may test `x - k`; folding `k` into the case values
    // lets the switch read `x` with the source's own case values.
    let mut environment = std::collections::HashMap::new();
    for stmt in &block.stmts {
        if let Stmt::Assign { dest, value } = stmt {
            let resolved = resolve(value, &environment);
            environment.insert(dest.index, resolved);
        }
    }
    let resolved = cancel(resolve(lhs, &environment));
    let checked = unwrap_mask(&resolved);
    let (minimum, switch_base) = match checked {
        Expr::Bin {
            op: BinOp::Sub,
            lhs: value,
            rhs: offset,
        } => match constant(offset) {
            Some(offset) => (offset as i64, (**value).clone()),
            None => (0, checked.clone()),
        },
        Expr::Bin {
            op: BinOp::Add,
            lhs: value,
            rhs: offset,
        } => match constant(offset) {
            Some(offset) => (-(offset as i64), (**value).clone()),
            None => (0, checked.clone()),
        },
        _ => (0, checked.clone()),
    };
    Option::Some((
        *limit as i64 + 1,
        Option::Some(*target),
        minimum,
        switch_base,
    ))
}

pub fn apply(blocks: &mut [Block], recovered: &[Recovered]) {
    for entry in recovered {
        let Some(block) = blocks
            .iter_mut()
            .find(|block| block.start == entry.block_start)
        else {
            continue;
        };
        if !matches!(block.stmts.last(), Some(Stmt::BrIndirect { .. })) {
            continue;
        }
        block.stmts.pop();
        // A register the block leaves holding the index names it best.
        if let Some(register) = holding(block, &entry.index) {
            block.stmts.push(Stmt::Switch {
                index: Expr::reg(register, 64),
                cases: entry.cases.clone(),
                default: entry.default,
            });
            continue;
        }
        // The index reads the registers as the block receives them; one the
        // block writes first is read into a register of its own up front.
        let mut read = std::collections::HashSet::new();
        crate::ir::visit::collect_reads(&entry.index, &mut read);
        let overwritten = block.stmts.iter().any(|stmt| {
            crate::ir::visit::statement_registers(stmt)
                .0
                .iter()
                .any(|written| read.contains(written))
        });
        let index = if overwritten {
            block.stmts.insert(
                0,
                Stmt::Assign {
                    dest: crate::ir::RegRef {
                        index: crate::ir::SWITCH_INDEX,
                        width: 64,
                    },
                    value: entry.index.clone(),
                },
            );
            Expr::reg(crate::ir::SWITCH_INDEX, 64)
        } else {
            entry.index.clone()
        };
        block.stmts.push(Stmt::Switch {
            index,
            cases: entry.cases.clone(),
            default: entry.default,
        });
    }
}

/// Removes table bytes decoded as instructions when no control-flow path
/// reaches them. An unresolved jump may still enter them, so keeps them.
pub(super) fn drop_data(
    blocks: &mut Vec<Block>,
    recovered: &[Recovered],
    landing_pads: &[(u64, Vec<(u64, u64)>)],
) {
    if recovered.is_empty() {
        return;
    }
    let mut seen = vec![false; blocks.len()];
    let mut pending = vec![0];
    while let Some(index) = pending.pop() {
        if index >= blocks.len() || std::mem::replace(&mut seen[index], true) {
            continue;
        }
        let edges = crate::ir::cfg::block_successors_with_exceptions(blocks, index, landing_pads);
        if edges.unknown_normal || edges.unknown_exceptional {
            return;
        }
        pending.extend(edges.normal);
        pending.extend(edges.exceptional);
    }
    let mut index = 0;
    blocks.retain(|block| {
        let reached = seen[index];
        index += 1;
        reached
            || !recovered.iter().any(|entry| {
                let (start, size) = entry.table;
                block.start >= start && block.start - start < size
            })
    });
}

/// A 64-bit register the block's statements leave holding `index`.
fn holding(block: &Block, index: &Expr) -> Option<u16> {
    let mut environment = std::collections::HashMap::new();
    let mut found = None;
    for stmt in &block.stmts {
        let Stmt::Assign { dest, value } = stmt else {
            if !crate::ir::visit::statement_registers(stmt).0.is_empty() {
                found = None;
            }
            continue;
        };
        let resolved = resolve(value, &environment);
        if found == Some(dest.index) {
            found = None;
        }
        if dest.width == 64 && resolved == *index && found.is_none() {
            found = Some(dest.index);
        }
        environment.insert(dest.index, resolved);
    }
    found
}

/// The largest value the index may take, from how it is computed. A
/// register's width alone bounds nothing: the check may lie elsewhere.
fn largest(index: &Expr) -> u64 {
    crate::ssa::ranges::expression(index, &|_, _| Some(crate::ssa::ranges::Fact::TOP))
        .map_or(u64::MAX, |fact| fact.hi)
}

/// Where an unchecked table's entries may lead and where other tables begin.
struct Limits<'a> {
    extent: std::ops::Range<u64>,
    tables: &'a std::collections::HashSet<u64>,
    /// The registers holding a constant as the block starts.
    held: &'a std::collections::HashMap<u16, Expr>,
}

/// The registers holding one constant whenever each block starts, as a
/// table's address loaded before a loop that dispatches through it.
fn held_constants(
    blocks: &[Block],
    known: &[Recovered],
) -> Vec<std::collections::HashMap<u16, Expr>> {
    type Held = std::collections::HashMap<u16, Expr>;
    let index: std::collections::HashMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(position, block)| (block.start, position))
        .collect();
    let mut entry: Vec<Option<Held>> = vec![None; blocks.len()];
    if blocks.is_empty() {
        return Vec::new();
    }
    let direct = |at: usize| -> Vec<usize> {
        let falls = at + 1 < blocks.len();
        match blocks[at].stmts.last() {
            Some(Stmt::Br { target }) => target
                .and_then(|target| index.get(&target).copied())
                .into_iter()
                .collect(),
            Some(Stmt::Brif { target, .. } | Stmt::BrifFlags { target, .. }) => index
                .get(target)
                .copied()
                .into_iter()
                .chain(falls.then_some(at + 1))
                .collect(),
            Some(Stmt::Ret { .. } | Stmt::Trap | Stmt::BrIndirect { .. }) => Vec::new(),
            _ => falls.then_some(at + 1).into_iter().collect(),
        }
    };
    let tables: std::collections::HashMap<u64, Vec<usize>> = known
        .iter()
        .map(|table| {
            let targets = table
                .targets()
                .iter()
                .filter_map(|target| index.get(target).copied())
                .collect();
            (table.block_start, targets)
        })
        .collect();
    entry[0] = Some(Held::new());
    let mut pending = vec![0];
    while let Some(at) = pending.pop() {
        let Some(mut held) = entry[at].clone() else {
            continue;
        };
        for stmt in &blocks[at].stmts {
            match stmt {
                Stmt::Assign { dest, value } => {
                    let resolved = resolve(value, &held);
                    match constant(&resolved) {
                        Some(value) if dest.width == 64 => {
                            held.insert(dest.index, Expr::Const(value));
                        }
                        _ => {
                            held.remove(&dest.index);
                        }
                    }
                }
                other => {
                    for written in crate::ir::visit::statement_registers(other).0 {
                        held.remove(&written);
                    }
                }
            }
        }
        let next = match blocks[at].stmts.last() {
            Some(Stmt::BrIndirect { .. }) => {
                tables.get(&blocks[at].start).cloned().unwrap_or_default()
            }
            _ => direct(at),
        };
        for successor in next {
            let merged = match &entry[successor] {
                None => held.clone(),
                Some(existing) => existing
                    .iter()
                    .filter(|(register, value)| held.get(register) == Some(value))
                    .map(|(register, value)| (*register, value.clone()))
                    .collect(),
            };
            if entry[successor].as_ref() != Some(&merged) {
                entry[successor] = Some(merged);
                pending.push(successor);
            }
        }
    }
    entry.into_iter().map(Option::unwrap_or_default).collect()
}

/// The addresses `lea r, [rip + d]`, or `adrp` and the `add` right after it,
/// compute anywhere in the code.
pub(crate) fn addressed(image: &Image) -> std::collections::HashSet<u64> {
    let mut out = std::collections::HashSet::new();
    for section in image.sections.iter().filter(|section| section.executable) {
        let Some(bytes) = image.read_vaddr(section.vaddr, section.size) else {
            continue;
        };
        match image.isa {
            crate::loader::Isa::X86_64 => {
                for at in 0..bytes.len().saturating_sub(6) {
                    if bytes[at] & 0xf8 != 0x48
                        || bytes[at + 1] != 0x8d
                        || bytes[at + 2] & 0xc7 != 0x05
                    {
                        continue;
                    }
                    let displacement =
                        i32::from_le_bytes(bytes[at + 3..at + 7].try_into().expect("four bytes"));
                    out.insert(
                        (section.vaddr + at as u64 + 7).wrapping_add(displacement as i64 as u64),
                    );
                }
            }
            crate::loader::Isa::AArch64 => {
                let words: Vec<u32> = bytes
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|chunk| u32::from_le_bytes(*chunk))
                    .collect();
                for (index, pair) in words.windows(2).enumerate() {
                    let (adrp, add) = (pair[0], pair[1]);
                    // ADRP xd, then ADD xd', xd, #imm12 without a shift.
                    if adrp & 0x9f00_0000 != 0x9000_0000
                        || add & 0xffc0_0000 != 0x9100_0000
                        || (add >> 5) & 0x1f != adrp & 0x1f
                    {
                        continue;
                    }
                    let page = (((adrp >> 29) & 3) | (((adrp >> 5) & 0x7ffff) << 2)) as u64;
                    let page = ((page << 43) as i64 >> 31) as u64;
                    let site = section.vaddr + index as u64 * 4;
                    out.insert(
                        (site & !0xfff)
                            .wrapping_add(page)
                            .wrapping_add(u64::from((add >> 10) & 0xfff)),
                    );
                }
            }
            crate::loader::Isa::Arm32
            | crate::loader::Isa::I386
            | crate::loader::Isa::Unsupported => {}
        }
    }
    out
}

/// The registers the block's assignments leave, as expressions of the
/// registers it receives, given those known to hold `environment`.
fn environment_from(
    block: &Block,
    mut environment: std::collections::HashMap<u16, Expr>,
) -> std::collections::HashMap<u16, Expr> {
    for stmt in &block.stmts {
        if let Stmt::Assign { dest, value } = stmt {
            let resolved = resolve(value, &environment);
            environment.insert(dest.index, resolved);
        }
    }
    environment
}

fn recognize(
    block: &Block,
    target: &Expr,
    image: &Image,
    bound: Option<(i64, Option<u64>, i64, Expr)>,
    checked_block: Option<&Block>,
    limits: &Limits,
) -> Option<Recovered> {
    let resolved = resolve(target, &environment_from(block, limits.held.clone()));
    let (base, table, index, scale, entry) = table_pattern(&resolved)?;
    // A table the program may write holds no cases known here.
    if !image
        .section_at(table)
        .is_some_and(|section| section.read_only || section.executable)
    {
        return None;
    }
    let entry_bytes = match entry {
        Entry::Absolute => 8,
        Entry::Offset32 => 4,
        Entry::Byte => 1,
    };
    let read_case = |position: u64| -> Option<u64> {
        let offset = match entry {
            Entry::Absolute => {
                u64::from_le_bytes(image.read_vaddr(table + position * 8, 8)?.try_into().ok()?)
                    as i64
            }
            Entry::Offset32 => {
                let bytes = image.read_vaddr(table + position * 4, 4)?;
                i64::from(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            }
            Entry::Byte => i64::from(image.read_vaddr(table + position, 1)?[0]) << scale,
        };
        let case = base.wrapping_add(offset as u64);
        image
            .section_at(case)
            .is_some_and(|section| section.executable)
            .then_some(case)
    };
    // A known index leaves one way to go.
    if let Some(value) = constant(&index)
        && value < 4096
    {
        return Some(Recovered {
            block_start: block.start,
            index: Expr::Const(value),
            cases: vec![(value as i64, read_case(value)?)],
            default: None,
            table: (table + value * entry_bytes, entry_bytes),
        });
    }
    let (count, default, minimum, switch_base) = match bound {
        Some(bound) => bound,
        // An index masked to its low bits, or otherwise bounded, takes
        // every value up to its largest.
        None if let largest = largest(&index)
            && largest < 4096 =>
        {
            (largest as i64 + 1, None, 0, index.clone())
        }
        None => {
            let count = (0..4096u64)
                .take_while(|position| {
                    let at = table + position * entry_bytes;
                    (*position == 0 || !limits.tables.contains(&at))
                        && read_case(*position).is_some_and(|case| limits.extent.contains(&case))
                })
                .count();
            if count < 2 {
                return None;
            }
            (count as i64, None, 0, index.clone())
        }
    };
    if count <= 0 || count > 4096 {
        return None;
    }
    let mut read = std::collections::HashSet::new();
    crate::ir::visit::collect_reads(&switch_base, &mut read);
    let base_still_held = !checked_block
        .into_iter()
        .chain(std::iter::once(block))
        .flat_map(|block| &block.stmts)
        .any(|stmt| {
            crate::ir::visit::statement_registers(stmt)
                .0
                .iter()
                .any(|written| read.contains(written))
        });

    let mut cases = Vec::new();
    for position in 0..count {
        let Some(case) = read_case(position as u64) else {
            return None;
        };
        cases.push((minimum + position, case));
    }

    // The value the bounds check tested before taking the cases' lowest
    // off, while the registers it reads still hold it; otherwise the
    // table's index as the switch block receives it, moved back to the
    // values the cases name.
    let index = if minimum == 0 {
        index
    } else if base_still_held {
        switch_base
    } else {
        Expr::bin(BinOp::Add, index, Expr::Const(minimum as u64))
    };
    Some(Recovered {
        block_start: block.start,
        index,
        cases,
        default,
        table: (table, count as u64 * entry_bytes),
    })
}

/// How a table entry gives its case's address.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Entry {
    /// A byte, shifted and added to a base.
    Byte,
    /// A signed 32-bit offset from a base.
    Offset32,
    /// The address itself.
    Absolute,
}

/// `(x - k) + k` and `(x + k) - k` are `x`.
fn cancel(expr: Expr) -> Expr {
    if let Expr::Bin { op, lhs, rhs } = &expr
        && let Expr::Bin {
            op: inner_op,
            lhs: value,
            rhs: inner_rhs,
        } = lhs.as_ref()
        && inner_rhs == rhs
        && matches!(
            (op, inner_op),
            (BinOp::Add, BinOp::Sub) | (BinOp::Sub, BinOp::Add)
        )
    {
        return value.as_ref().clone();
    }
    expr
}

pub(crate) fn resolve(expr: &Expr, environment: &std::collections::HashMap<u16, Expr>) -> Expr {
    match expr {
        Expr::Reg { index, .. } => match environment.get(index) {
            Some(value) => value.clone(),
            None => expr.clone(),
        },
        Expr::Bin { op, lhs, rhs } => {
            Expr::bin(*op, resolve(lhs, environment), resolve(rhs, environment))
        }
        Expr::Load {
            addr,
            width,
            signed,
        } => Expr::Load {
            addr: Box::new(resolve(addr, environment)),
            width: *width,
            signed: *signed,
        },
        Expr::SignExtend { value, width } => Expr::SignExtend {
            value: Box::new(resolve(value, environment)),
            width: *width,
        },
        Expr::Select {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => Expr::Select {
            cond: *cond,
            lhs: Box::new(resolve(lhs, environment)),
            rhs: Box::new(resolve(rhs, environment)),
            then: Box::new(resolve(then, environment)),
            els: Box::new(resolve(els, environment)),
        },
        Expr::Apply { op, args } => Expr::Apply {
            op: *op,
            args: args.iter().map(|arg| resolve(arg, environment)).collect(),
        },
        Expr::Const(_) => expr.clone(),
    }
}

fn peel(expr: &Expr) -> &Expr {
    match expr {
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(_)) => peel(lhs),
        _ => expr,
    }
}

pub(crate) fn constant(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Const(value) => Some(*value),
        _ => None,
    }
}

/// Strips `& 0xffffffff` and `& u64::MAX` masks around the index.
fn unwrap_mask(expr: &Expr) -> &Expr {
    if let Expr::Bin {
        op: BinOp::And,
        lhs,
        rhs,
    } = expr
        && matches!(
            rhs.as_ref(),
            Expr::Const(0xffff_ffff) | Expr::Const(u64::MAX)
        )
    {
        return unwrap_mask(lhs);
    }
    expr
}

/// Matches `base + (table[index] << scale)` with a byte table,
/// `base + sext(table[index])` with a 32-bit signed offset table, or
/// `table[index]` with a table of addresses.
fn table_pattern(expr: &Expr) -> Option<(u64, u64, Expr, i64, Entry)> {
    if let Expr::Load { addr, width: 8, .. } = expr
        && let (Some(table), Some(index)) = (table_address(addr), index_expression(addr))
    {
        return Some((0, table, index, 0, Entry::Absolute));
    }
    let Expr::Bin {
        op: BinOp::Add,
        lhs,
        rhs,
    } = expr
    else {
        return Option::None;
    };

    // Variant A: base + (load1(table + index) << scale)
    let (base, value) = match (constant(lhs), constant(rhs)) {
        (Some(base), None) => (base, rhs.as_ref()),
        (None, Some(base)) => (base, lhs.as_ref()),
        _ => return Option::None,
    };
    if let Expr::Bin {
        op: BinOp::Shl,
        lhs,
        rhs,
    } = value
    {
        let peeled = peel(lhs);
        if let (
            Expr::Load {
                addr,
                width,
                signed,
            },
            Some(scale),
        ) = (peeled, constant(rhs))
            && *width == 1
            && !*signed
            && let (Some(table), Some(index)) = (table_address(addr), index_expression(addr))
        {
            return Some((base, table, index, scale as i64, Entry::Byte));
        }
    }

    // Variant B: base + sext(load4(table + (index << 2))), the sign extension
    // either in the load or around it.
    let entry = match peel(value) {
        Expr::SignExtend { value, width: 4 } => peel(value),
        other => other,
    };
    let signed = matches!(peel(value), Expr::SignExtend { width: 4, .. })
        || matches!(entry, Expr::Load { signed: true, .. });
    if let Expr::Load { addr, width: 4, .. } = entry
        && signed
        && let (Some(table), Some(index)) = (table_address(addr), index_expression(addr))
    {
        return Some((base, table, index, 0, Entry::Offset32));
    }

    Option::None
}

fn table_address(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => constant(lhs).or_else(|| constant(rhs)),
        Expr::Const(value) => Some(*value),
        _ => None,
    }
}

fn index_expression(expr: &Expr) -> Option<Expr> {
    match expr {
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => {
            if constant(lhs).is_some() {
                Some(unscale((**rhs).clone()))
            } else if constant(rhs).is_some() {
                Some(unscale((**lhs).clone()))
            } else {
                None
            }
        }
        // The index folded into the table's address.
        Expr::Const(_) => Some(Expr::Const(0)),
        _ => None,
    }
}

fn unscale(expr: Expr) -> Expr {
    match expr {
        Expr::Bin {
            op: BinOp::Mul,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(4 | 8)) => *lhs,
        Expr::Bin {
            op: BinOp::Shl,
            lhs,
            rhs,
        } => match rhs.as_ref() {
            Expr::Const(scale) if *scale > 0 => *lhs,
            _ => Expr::Bin {
                op: BinOp::Shl,
                lhs,
                rhs,
            },
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_data_keeps_normal_exceptional_and_unknown_entries() {
        let table = Recovered {
            block_start: 0,
            index: Expr::Const(0),
            cases: vec![(0, 20)],
            default: None,
            table: (10, 4),
        };
        let ret = || Stmt::Ret {
            value: Expr::Const(0),
        };
        let blocks = |entry| {
            vec![
                Block {
                    start: 0,
                    stmts: vec![entry],
                },
                Block {
                    start: 10,
                    stmts: vec![ret()],
                },
                Block {
                    start: 20,
                    stmts: vec![ret()],
                },
            ]
        };
        let mut dead = blocks(Stmt::Br { target: Some(20) });
        drop_data(&mut dead, std::slice::from_ref(&table), &[]);
        assert_eq!(
            dead.iter().map(|block| block.start).collect::<Vec<_>>(),
            [0, 20]
        );
        for entry in [
            Stmt::Br { target: Some(10) },
            Stmt::BrIndirect {
                target: Expr::reg(0, 64),
            },
        ] {
            let mut live = blocks(entry);
            drop_data(&mut live, std::slice::from_ref(&table), &[]);
            assert_eq!(live.len(), 3);
        }
        let mut exceptional = blocks(ret());
        exceptional[0].stmts.insert(
            0,
            Stmt::Unsupported {
                text: "unknown call".into(),
                writes: Some(Vec::new()),
            },
        );
        drop_data(&mut exceptional, &[table], &[(10, vec![(0, 1)])]);
        assert_eq!(exceptional.len(), 3);
    }
}

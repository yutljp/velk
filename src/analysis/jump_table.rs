use crate::ir::semantics::mask;
use crate::ir::{BinOp, Block, Expr, Stmt};
use crate::loader::Image;

#[derive(Debug, Clone)]
pub struct Recovered {
    pub block_start: u64,
    pub index: Expr,
    pub cases: Vec<(i64, u64)>,
    pub default: Option<u64>,
    /// The table location and size, used to remove decoded table data.
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
    if !blocks
        .iter()
        .any(|block| matches!(block.stmts.last(), Some(Stmt::BrIndirect { .. })))
    {
        return Vec::new();
    }
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
    let starts = image.addressed.get_or_init(|| referenced_addresses(image));
    let held = held_constants(blocks, known);
    let mut recovered = Vec::new();
    for (index, block) in blocks.iter().enumerate() {
        let Some(Stmt::BrIndirect { target, .. }) = block.stmts.last() else {
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

pub(crate) fn bound(block: &Block) -> Option<Bound> {
    let Some(last) = block.stmts.last() else {
        return None;
    };
    let Stmt::Brif {
        cond,
        lhs,
        rhs,
        target,
        ..
    } = last
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
    let environment = environment_from(block, std::collections::HashMap::new());
    let resolved = cancel(resolve(lhs, &environment));
    let checked = unwrap_mask(&resolved);
    let bits = match crate::ir::semantics::width(&resolved) {
        0 => 64,
        bits => bits.min(64),
    };
    let (minimum, switch_base) = match checked {
        Expr::Bin {
            op: BinOp::Sub,
            lhs: value,
            rhs: offset,
        } => match constant(offset) {
            Some(offset) => (lowest_case(Adjustment::Sub(offset)), (**value).clone()),
            None => (0, checked.clone()),
        },
        Expr::Bin {
            op: BinOp::Add,
            lhs: value,
            rhs: offset,
        } => match constant(offset) {
            Some(offset) => (lowest_case(Adjustment::Add(offset)), (**value).clone()),
            None => (0, checked.clone()),
        },
        _ => (0, checked.clone()),
    };
    // A count that does not fit stays a recognized check with no cases, so
    // the table is rejected rather than sized by scanning.
    let inclusive = *cond == crate::ir::Cond::Hi;
    let count = case_count(inclusive, *limit & mask(bits)).unwrap_or(0);
    Option::Some(Bound {
        count,
        default: Option::Some(*target),
        minimum,
        switch_base,
    })
}

/// What a bounds check before a table jump tells: how many cases pass it,
/// where the others go, the switch value of case 0 and the expression it is
/// read from.
pub(crate) struct Bound {
    count: i64,
    default: Option<u64>,
    minimum: i64,
    switch_base: Expr,
}

/// The constant a bounds check takes off or adds to the switch value
/// before comparing it with the case count.
#[derive(Clone, Copy)]
enum Adjustment {
    Sub(u64),
    Add(u64),
}

/// The switch value of case 0. Cases name values of the 64-bit expressions
/// the switch reads, so they wrap at 64 bits like the IR's arithmetic; a
/// check at a narrower width names them modulo its width.
fn lowest_case(adjustment: Adjustment) -> i64 {
    match adjustment {
        Adjustment::Sub(offset) => offset as i64,
        Adjustment::Add(offset) => (offset as i64).wrapping_neg(),
    }
}

/// The number of values an unsigned check lets through to the table, when
/// it fits the signed count the cases use: `value > limit` (inclusive)
/// passes `0..=limit`, `value >= limit` passes `0..limit`.
fn case_count(inclusive: bool, limit: u64) -> Option<i64> {
    let Ok(limit) = i64::try_from(limit) else {
        return None;
    };
    if inclusive {
        limit.checked_add(1)
    } else {
        Some(limit)
    }
}

/// The switch value of the case at `position`.
fn case_value(minimum: i64, position: i64) -> i64 {
    minimum.wrapping_add(position)
}

/// The address of entry `position` in a table of `entry_bytes`-byte entries,
/// unless it passes the end of the address space.
fn entry_address(table: u64, position: u64, entry_bytes: u64) -> Option<u64> {
    let Some(distance) = position.checked_mul(entry_bytes) else {
        return None;
    };
    table.checked_add(distance)
}

/// A byte entry shifted into its offset from the base, unless the shift
/// amount is outside a 64-bit value.
fn byte_offset(byte: u8, scale: i64) -> Option<i64> {
    let Ok(scale) = u32::try_from(scale) else {
        return None;
    };
    i64::from(byte).checked_shl(scale)
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
        let at = block.stmts.pop().and_then(|stmt| stmt.origin());
        // A register the block leaves holding the index names it best.
        if let Some(register) = register_holding_index(block, &entry.index) {
            block.stmts.push(Stmt::Switch {
                index: Expr::reg(register, 64),
                cases: entry.cases.clone(),
                default: entry.default,
                at,
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
                    at: None,
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
            at,
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
fn register_holding_index(block: &Block, index: &Expr) -> Option<u16> {
    let mut environment = std::collections::HashMap::new();
    let mut found = None;
    for stmt in &block.stmts {
        let Stmt::Assign { dest, value, .. } = stmt else {
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
            Some(Stmt::Br { target, .. }) => target
                .and_then(|target| index.get(&target).copied())
                .into_iter()
                .collect(),
            Some(Stmt::Brif { target, .. } | Stmt::BrifFlags { target, .. }) => index
                .get(target)
                .copied()
                .into_iter()
                .chain(falls.then_some(at + 1))
                .collect(),
            Some(Stmt::Ret { .. } | Stmt::Trap { .. } | Stmt::BrIndirect { .. }) => Vec::new(),
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
                Stmt::Assign { dest, value, .. } => {
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
pub(crate) fn referenced_addresses(image: &Image) -> std::collections::HashSet<u64> {
    let mut out = std::collections::HashSet::new();
    for section in image.sections.iter().filter(|section| section.executable) {
        let Some(bytes) = image.read_vaddr(section.vaddr, section.size) else {
            continue;
        };
        match image.isa {
            crate::loader::Isa::X86_64 => {
                for (at, window) in bytes.windows(7).enumerate() {
                    if let Some(address) =
                        rip_relative_lea(window, section.vaddr.wrapping_add(at as u64))
                    {
                        out.insert(address);
                    }
                }
            }
            crate::loader::Isa::AArch64 => {
                let words = bytes.as_chunks::<4>().0;
                for (index, pair) in words.windows(2).enumerate() {
                    let (adrp, add) = (u32::from_le_bytes(pair[0]), u32::from_le_bytes(pair[1]));
                    let site = section.vaddr.wrapping_add(index as u64 * 4);
                    if let Some(address) = adrp_add(adrp, add, site) {
                        out.insert(address);
                    }
                }
            }
            crate::loader::Isa::Arm32
            | crate::loader::Isa::I386
            | crate::loader::Isa::Unsupported => {}
        }
    }
    out
}

/// The address `lea r64, [rip + d]` at `site` computes.
fn rip_relative_lea(bytes: &[u8], site: u64) -> Option<u64> {
    if bytes[0] & 0xf8 != 0x48 || bytes[1] != 0x8d || bytes[2] & 0xc7 != 0x05 {
        return None;
    }
    let displacement = i32::from_le_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]);
    Some(
        site.wrapping_add(7)
            .wrapping_add(displacement as i64 as u64),
    )
}

/// The address `adrp xd, page` at `site` followed by `add xd', xd, #imm12`
/// (no shift) computes. An ADRP into the zero register pairs with no ADD,
/// whose register 31 is the stack pointer.
fn adrp_add(adrp: u32, add: u32, site: u64) -> Option<u64> {
    if adrp & 0x9f00_0000 != 0x9000_0000
        || adrp & 0x1f == 31
        || add & 0xffc0_0000 != 0x9100_0000
        || (add >> 5) & 0x1f != adrp & 0x1f
    {
        return None;
    }
    let page = (((adrp >> 29) & 3) | (((adrp >> 5) & 0x7ffff) << 2)) as u64;
    let page = ((page << 43) as i64 >> 31) as u64;
    Some(
        (site & !0xfff)
            .wrapping_add(page)
            .wrapping_add(u64::from((add >> 10) & 0xfff)),
    )
}

/// The registers the block's assignments leave, as expressions of the
/// registers it receives, given those known to hold `environment`.
fn environment_from(
    block: &Block,
    mut environment: std::collections::HashMap<u16, Expr>,
) -> std::collections::HashMap<u16, Expr> {
    for stmt in &block.stmts {
        if let Stmt::Assign { dest, value, .. } = stmt {
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
    bound: Option<Bound>,
    checked_block: Option<&Block>,
    limits: &Limits,
) -> Option<Recovered> {
    let resolved = resolve(target, &environment_from(block, limits.held.clone()));
    let Some((base, table, index, scale, entry)) = table_pattern(&resolved) else {
        return None;
    };
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
                let Some(at) = entry_address(table, position, 8) else {
                    return None;
                };
                let Some(vaddr) = image.read_vaddr(at, 8) else {
                    return None;
                };
                let Some(entry_bytes) = vaddr.try_into().ok() else {
                    return None;
                };
                u64::from_le_bytes(entry_bytes) as i64
            }
            Entry::Offset32 => {
                let Some(at) = entry_address(table, position, 4) else {
                    return None;
                };
                let Some(bytes) = image.read_vaddr(at, 4) else {
                    return None;
                };
                i64::from(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            }
            Entry::Byte => {
                let Some(at) = entry_address(table, position, 1) else {
                    return None;
                };
                let Some(entry_bytes) = image.read_vaddr(at, 1) else {
                    return None;
                };
                let Some(offset) = byte_offset(entry_bytes[0], scale) else {
                    return None;
                };
                offset
            }
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
        let Some(case) = read_case(value) else {
            return None;
        };
        let Some(at) = entry_address(table, value, entry_bytes) else {
            return None;
        };
        return Some(Recovered {
            block_start: block.start,
            index: Expr::Const(value),
            cases: vec![(value as i64, case)],
            default: None,
            table: (at, entry_bytes),
        });
    }
    let (count, default, minimum, switch_base) = match bound {
        Some(bound) => (bound.count, bound.default, bound.minimum, bound.switch_base),
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
                    let Some(at) = entry_address(table, *position, entry_bytes) else {
                        return false;
                    };
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
        cases.push((case_value(minimum, position), case));
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

fn strip_constant_masks(expr: &Expr) -> &Expr {
    match expr {
        Expr::Bin {
            op: BinOp::And,
            lhs,
            rhs,
        } if matches!(rhs.as_ref(), Expr::Const(_)) => strip_constant_masks(lhs),
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
        let peeled = strip_constant_masks(lhs);
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
    let entry = match strip_constant_masks(value) {
        Expr::SignExtend { value, width: 4 } => strip_constant_masks(value),
        other => other,
    };
    let signed = matches!(
        strip_constant_masks(value),
        Expr::SignExtend { width: 4, .. }
    ) || matches!(entry, Expr::Load { signed: true, .. });
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
    fn bounds_checks_with_extreme_constants_do_not_overflow() {
        let check_at = |cond, bits, op, offset: u64, limit: u64| Block {
            start: 0,
            stmts: vec![Stmt::Brif {
                cond,
                lhs: Expr::bin(op, Expr::reg(0, bits), Expr::Const(offset)),
                rhs: Expr::Const(limit),
                target: 8,
                at: None,
            }],
        };
        let check = |op, offset, limit| check_at(crate::ir::Cond::Hi, 64, op, offset, limit);
        let counted = |block| {
            let bound = bound(&block).unwrap();
            (bound.count, bound.minimum)
        };
        assert_eq!(counted(check(BinOp::Add, 1 << 63, 3)), (4, i64::MIN));
        assert_eq!(counted(check(BinOp::Sub, 5, i64::MAX as u64)), (0, 5));
        assert_eq!(counted(check(BinOp::Sub, 5, u64::MAX)).0, 0);
        assert_eq!(case_value(i64::MAX, 2), i64::MIN + 1);
        // `x >= 6` takes the default, so six cases pass; `x > 6` passes seven.
        assert_eq!(
            counted(check_at(crate::ir::Cond::Cs, 64, BinOp::Sub, 5, 6)),
            (6, 5)
        );
        assert_eq!(
            counted(check_at(crate::ir::Cond::Hi, 64, BinOp::Sub, 5, 6)),
            (7, 5)
        );
        // A 32-bit check counts at its own width.
        assert_eq!(
            counted(check_at(
                crate::ir::Cond::Hi,
                32,
                BinOp::Sub,
                5,
                0x1_0000_0003
            ))
            .0,
            4
        );
        assert_eq!(byte_offset(1, 64), None);
        assert_eq!(byte_offset(1, -1), None);
        assert_eq!(byte_offset(3, 2), Some(12));
        assert_eq!(entry_address(u64::MAX - 7, 1, 8), None);
    }

    #[test]
    fn direct_control_flow_does_not_scan_table_addresses() {
        for isa in [
            crate::loader::Isa::X86_64,
            crate::loader::Isa::AArch64,
            crate::loader::Isa::I386,
            crate::loader::Isa::Arm32,
        ] {
            let image = Image::from_code(isa, 0, Vec::new());
            let blocks = vec![
                Block {
                    start: 0,
                    stmts: vec![Stmt::Brif {
                        cond: crate::ir::Cond::Eq,
                        lhs: Expr::reg(0, 32),
                        rhs: Expr::Const(0),
                        target: 8,
                        at: None,
                    }],
                },
                Block {
                    start: 4,
                    stmts: vec![Stmt::Ret {
                        value: Expr::Const(1),
                        at: None,
                    }],
                },
                Block {
                    start: 8,
                    stmts: vec![Stmt::Ret {
                        value: Expr::Const(2),
                        at: None,
                    }],
                },
            ];
            assert!(recover(&blocks, &image, 0..12).is_empty());
            assert!(image.addressed.get().is_none());
        }
    }

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
            at: None,
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
        let mut dead = blocks(Stmt::Br {
            target: Some(20),
            at: None,
        });
        drop_data(&mut dead, std::slice::from_ref(&table), &[]);
        assert_eq!(
            dead.iter().map(|block| block.start).collect::<Vec<_>>(),
            [0, 20]
        );
        for entry in [
            Stmt::Br {
                target: Some(10),
                at: None,
            },
            Stmt::BrIndirect {
                target: Expr::reg(0, 64),
                at: None,
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
                at: None,
                text: "unknown call".into(),
                writes: Some(Vec::new()),
            },
        );
        drop_data(&mut exceptional, &[table], &[(10, vec![(0, 1)])]);
        assert_eq!(exceptional.len(), 3);
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// `lea` and `adrp`/`add` give the address the instruction definitions
    /// name, written here from the bit fields, at every site address.
    #[kani::proof]
    fn referenced_addresses_follow_the_encodings() {
        let bytes: [u8; 7] = kani::any();
        let site: u64 = kani::any();
        let lea =
            bytes[0] & 0xf8 == 0x48 && bytes[1] == 0x8d && bytes[2] >> 6 == 0 && bytes[2] & 7 == 5;
        let displacement = i128::from(i32::from_le_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]));
        let expected = (i128::from(site) + 7 + displacement).rem_euclid(1 << 64) as u64;
        assert_eq!(rip_relative_lea(&bytes, site), lea.then_some(expected));

        let adrp: u32 = kani::any();
        let add: u32 = kani::any();
        // ADRP: op=1 and bits 28..24 = 10000. ADD (immediate): sf=1, op=0, S=0,
        // bits 28..23 = 100010, sh=0, Rn the ADRP's Rd.
        let pair = adrp >> 31 == 1
            && (adrp >> 24) & 0x1f == 0x10
            && add >> 22 == 0x244
            && adrp & 0x1f != 31
            && (add >> 5) & 0x1f == adrp & 0x1f;
        let immediate = ((adrp >> 29) & 0x3) | ((adrp >> 3) & 0x1f_fffc);
        let pages = if immediate & (1 << 20) != 0 {
            i128::from(immediate) - (1 << 21)
        } else {
            i128::from(immediate)
        };
        let target = i128::from(site & !0xfff) + pages * 4096 + i128::from((add >> 10) & 0xfff);
        let target = target.rem_euclid(1 << 64) as u64;
        assert_eq!(adrp_add(adrp, add, site), pair.then_some(target));
        kani::cover!(pair && pages < 0, "a page below the site");
    }

    /// At every width, for every constant a check may add or take off and
    /// both unsigned checks, the values that pass are exactly the case
    /// positions `0..count`, and each gets back its own switch value modulo
    /// the check's width (exactly, at 64 bits).
    #[kani::proof]
    fn case_values_name_the_checked_value() {
        let bits: u32 = kani::any();
        kani::assume((1..=64).contains(&bits));
        let limit: u64 = kani::any();
        let offset: u64 = kani::any();
        let value: u64 = kani::any();
        kani::assume(value & mask(bits) == value);
        let subtract: bool = kani::any();
        let inclusive: bool = kani::any();
        let cond = if inclusive {
            crate::ir::Cond::Hi
        } else {
            crate::ir::Cond::Cs
        };
        let (adjustment, checked) = if subtract {
            (Adjustment::Sub(offset), value.wrapping_sub(offset))
        } else {
            (Adjustment::Add(offset), value.wrapping_add(offset))
        };
        let checked = checked & mask(bits);
        let minimum = lowest_case(adjustment);
        let Some(count) = case_count(inclusive, limit & mask(bits)) else {
            assert!(
                limit & mask(bits) > i64::MAX as u64
                    || (inclusive && limit & mask(bits) == i64::MAX as u64)
            );
            return;
        };
        let passes = !crate::ir::semantics::holds(cond, checked, limit, bits);
        assert_eq!(passes, (checked as i64) < count && checked < 1 << 63);
        if passes {
            let case = case_value(minimum, checked as i64) as u64;
            assert_eq!(case & mask(bits), value);
            if bits == 64 {
                assert_eq!(case, value);
            }
            kani::cover!(
                bits == 32 && offset > 0xffff_0000,
                "a 32-bit negative constant"
            );
            kani::cover!(!inclusive && count > 0, "an exclusive check");
        }
        let position: u64 = kani::any();
        if (position as i64) < count && position < 1 << 63 {
            assert!(!crate::ir::semantics::holds(cond, position, limit, bits));
        }
    }

    #[kani::proof]
    fn table_entries_stay_in_the_address_space() {
        let table: u64 = kani::any();
        let position: u64 = kani::any();
        let entry_bytes: u64 = kani::any();
        let exact = u128::from(table) + u128::from(position) * u128::from(entry_bytes);
        match entry_address(table, position, entry_bytes) {
            Some(at) => assert_eq!(u128::from(at), exact),
            None => {
                assert!(exact > u128::from(u64::MAX));
            }
        }
        let byte: u8 = kani::any();
        let scale: i64 = kani::any();
        match byte_offset(byte, scale) {
            Some(offset) => {
                assert!((0..64).contains(&scale));
                assert_eq!(offset as u64, (u64::from(byte)).wrapping_shl(scale as u32));
                kani::cover!(scale > 56 && byte > 1, "high bits leave the value");
            }
            None => {
                assert!(!(0..64).contains(&scale));
            }
        }
    }
}

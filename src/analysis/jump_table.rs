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
    #[cfg_attr(not(test), allow(dead_code))]
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
/// where the next table would begin.
pub fn recover(blocks: &[Block], image: &Image, extent: std::ops::Range<u64>) -> Vec<Recovered> {
    let starts = image.addressed.get_or_init(|| addressed(image));
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

/// Where an unchecked table's entries may lead and where other tables begin.
struct Limits<'a> {
    extent: std::ops::Range<u64>,
    tables: &'a std::collections::HashSet<u64>,
}

/// The addresses `lea r, [rip + d]`, or `adrp` and the `add` right after it,
/// compute anywhere in the code.
fn addressed(image: &Image) -> std::collections::HashSet<u64> {
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
            crate::loader::Isa::Unsupported => {}
        }
    }
    out
}

/// The registers the block's assignments leave, as expressions of the
/// registers it receives.
fn environment_of(block: &Block) -> std::collections::HashMap<u16, Expr> {
    let mut environment = std::collections::HashMap::new();
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
    let resolved = resolve(target, &environment_of(block));
    let (base, table, index, scale, entry) = table_pattern(&resolved)?;
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
    let (count, default, minimum, switch_base) = match bound {
        Some(bound) => bound,
        // An index masked to its low bits takes every value they hold.
        None if let Expr::Bin {
            op: BinOp::And,
            rhs: mask,
            ..
        } = &index
            && let Some(mask) = constant(mask)
            && mask < 4096
            && (mask + 1).is_power_of_two() =>
        {
            (mask as i64 + 1, None, 0, index.clone())
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
        cases.push((minimum + position, read_case(position as u64)?));
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

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

pub fn recover(blocks: &[Block], image: &Image) -> Vec<Recovered> {
    let mut recovered = Vec::new();
    for (index, block) in blocks.iter().enumerate() {
        let Some(Stmt::BrIndirect { target }) = block.stmts.last() else {
            continue;
        };
        let checked = index
            .checked_sub(1)
            .and_then(|previous| blocks.get(previous));
        let bound = checked.and_then(bound);
        if let Some(mut entry) = recognize(block, target, image, bound, checked) {
            entry.block_start = block.start;
            recovered.push(entry);
        }
    }
    recovered
}

/// The case targets of tables with no bounds check, such as a dispatch on an
/// enum whose range the compiler knows: entries are read while they point
/// into the code just after `function`, up to `reach` bytes.
pub fn unbounded_targets(blocks: &[Block], image: &Image, function: u64, reach: u64) -> Vec<u64> {
    let mut targets = Vec::new();
    for (index, block) in blocks.iter().enumerate() {
        let Some(Stmt::BrIndirect { target }) = block.stmts.last() else {
            continue;
        };
        // A bounds check gives the table's length; reading on would run
        // into the tables after it.
        if index
            .checked_sub(1)
            .and_then(|previous| blocks.get(previous))
            .and_then(bound)
            .is_some()
        {
            continue;
        }
        let mut environment = std::collections::HashMap::new();
        for stmt in &block.stmts {
            if let Stmt::Assign { dest, value } = stmt {
                let resolved = resolve(value, &environment);
                environment.insert(dest.index, resolved);
            }
        }
        let Some((base, table, _, scale, entry)) = table_pattern(&resolve(target, &environment))
        else {
            continue;
        };
        for position in 0..256u64 {
            let offset = match entry {
                Entry::Offset32 => match image.read_vaddr(table + position * 4, 4) {
                    Some(bytes) => {
                        i64::from(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
                    }
                    None => break,
                },
                Entry::Byte => match image.read_vaddr(table + position, 1) {
                    Some(bytes) => i64::from(bytes[0]) << scale,
                    None => break,
                },
                Entry::Absolute => break,
            };
            let case = base.wrapping_add(offset as u64);
            if !(function..function.saturating_add(reach)).contains(&case)
                || image
                    .section_at(case)
                    .is_none_or(|section| !section.executable)
            {
                break;
            }
            targets.push(case);
        }
    }
    targets
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

fn recognize(
    block: &Block,
    target: &Expr,
    image: &Image,
    bound: Option<(i64, Option<u64>, i64, Expr)>,
    checked_block: Option<&Block>,
) -> Option<Recovered> {
    let mut environment: std::collections::HashMap<u16, Expr> = std::collections::HashMap::new();
    for stmt in &block.stmts {
        if let Stmt::Assign { dest, value } = stmt {
            let resolved = resolve(value, &environment);
            environment.insert(dest.index, resolved);
        }
    }
    let resolved = resolve(target, &environment);
    let (base, table, index, scale, entry) = table_pattern(&resolved)?;

    let (count, default, minimum, switch_base) = bound?;
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
        let offset = if entry == Entry::Absolute {
            let bytes = image.read_vaddr(table + (position as u64) * 8, 8)?;
            u64::from_le_bytes(bytes.try_into().ok()?) as i64
        } else if entry == Entry::Offset32 {
            let bytes = image.read_vaddr(table + (position as u64) * 4, 4)?;
            i64::from(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        } else {
            let byte = image.read_vaddr(table + position as u64, 1)?[0];
            i64::from(byte) << scale
        };
        let case_target = base.wrapping_add(offset as u64);
        if image
            .section_at(case_target)
            .is_none_or(|section| !section.executable)
        {
            return None;
        }
        cases.push((minimum + position, case_target));
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
    let entry_bytes = match entry {
        Entry::Absolute => 8,
        Entry::Offset32 => 4,
        Entry::Byte => 1,
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

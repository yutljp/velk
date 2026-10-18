//! Jump-table switch recovery for AArch64 code produced by clang.

use crate::ir::{BinOp, Block, Expr, FunctionIr, Stmt};
use crate::loader::Image;

#[derive(Debug, Clone)]
pub struct Recovered {
    pub block_start: u64,
    pub index: Expr,
    pub cases: Vec<(i64, u64)>,
    pub default: Option<u64>,
}

impl Recovered {
    pub fn targets(&self) -> Vec<u64> {
        let mut targets: Vec<u64> = self.cases.iter().map(|(_, target)| *target).collect();
        targets.extend(self.default);
        targets
    }
}

pub fn recover(ir: &FunctionIr, image: &Image) -> Vec<Recovered> {
    let mut recovered = Vec::new();
    for (index, block) in ir.blocks.iter().enumerate() {
        let Some(Stmt::BrIndirect { target }) = block.stmts.last() else {
            continue;
        };
        let bound = index
            .checked_sub(1)
            .and_then(|previous| ir.blocks.get(previous))
            .and_then(bound);
        if let Some(mut entry) = recognize(block, target, image, bound) {
            entry.block_start = block.start;
            recovered.push(entry);
        }
    }
    recovered
}

fn bound(block: &Block) -> Option<(i64, Option<u64>, i64, Expr)> {
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
    // The bounds check may read a register that already holds `x - k`. Folding
    // that offset into the switch makes the case values read as the
    // source's own and the variable is `x` again.
    let mut environment = std::collections::HashMap::new();
    for stmt in &block.stmts {
        if let Stmt::Assign { dest, value } = stmt {
            let resolved = resolve(value, &environment);
            environment.insert(dest.index, resolved);
        }
    }
    let resolved = resolve(lhs, &environment);
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
    Option::Some((*limit as i64 + 1, Option::Some(*target), minimum, switch_base))
}

pub fn apply(ir: &mut FunctionIr, recovered: &[Recovered]) {
    for entry in recovered {
        let Some(block) = ir.blocks.iter_mut().find(|block| block.start == entry.block_start) else {
            continue;
        };
        if !matches!(block.stmts.last(), Some(Stmt::BrIndirect { .. })) {
            continue;
        }
        block.stmts.pop();
        block.stmts.push(Stmt::Switch {
            index: entry.index.clone(),
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
) -> Option<Recovered> {
    let mut environment: std::collections::HashMap<u16, Expr> = std::collections::HashMap::new();
    for stmt in &block.stmts {
        if let Stmt::Assign { dest, value } = stmt {
            let resolved = resolve(value, &environment);
            environment.insert(dest.index, resolved);
        }
    }
    let resolved = resolve(target, &environment);
    let (base, table, index, scale, signed) = table_pattern(&resolved)?;

    let (count, default, minimum, switch_base) = bound?;
    if count <= 0 || count > 4096 {
        return None;
    }

    let mut cases = Vec::new();
    for position in 0..count {
        let offset = if signed {
            let bytes = image.read_vaddr(table + (position as u64) * 4, 4)?;
            i64::from(i32::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
            ]))
        } else {
            let byte = image.read_vaddr(table + position as u64, 1)?[0];
            i64::from(byte) << scale
        };
        let case_target = base.wrapping_add(offset as u64);
        if image.section_at(case_target).is_none_or(|section| !section.executable) {
            return None;
        }
        cases.push((minimum + position, case_target));
    }

    // With an offset folded out, the switch reads its own variable again.
    let index = if minimum == 0 { index } else { switch_base };
    Some(Recovered {
        block_start: block.start,
        index,
        cases,
        default,
    })
}

fn resolve(expr: &Expr, environment: &std::collections::HashMap<u16, Expr>) -> Expr {
    match expr {
        Expr::Reg { index, .. } => match environment.get(index) {
            Some(value) => value.clone(),
            None => expr.clone(),
        },
        Expr::Bin { op, lhs, rhs } => Expr::bin(
            *op,
            resolve(lhs, environment),
            resolve(rhs, environment),
        ),
        Expr::Load { addr, width, signed } => Expr::Load {
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

fn constant(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Const(value) => Some(*value),
        _ => None,
    }
}

/// Drops a `& 0xffffffff` that only narrows the value.
fn unwrap_mask(expr: &Expr) -> &Expr {
    if let Expr::Bin {
        op: BinOp::And,
        lhs,
        rhs,
    } = expr
    {
        if matches!(rhs.as_ref(), Expr::Const(0xffff_ffff) | Expr::Const(u64::MAX)) {
            return unwrap_mask(lhs);
        }
    }
    expr
}

/// Matches `base + (table[index] << scale)` and its word-offset variant.
fn table_pattern(expr: &Expr) -> Option<(u64, u64, Expr, i64, bool)> {
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
        if let (Expr::Load { addr, width, signed }, Some(scale)) = (peeled, constant(rhs)) {
            if *width == 1 && !*signed {
                if let (Some(table), Some(index)) = (table_address(addr), index_expression(addr)) {
                    return Some((base, table, index, scale as i64, false));
                }
            }
        }
    }

    // Variant B: base + sext(load4(table + (index << 2)))
    if let Expr::Load {
        addr,
        width: 4,
        signed: true,
    } = peel(value)
    {
        if let (Some(table), Some(index)) = (table_address(addr), index_expression(addr)) {
            return Some((base, table, index, 0, true));
        }
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
            op: BinOp::Shl,
            lhs,
            rhs,
        } => match rhs.as_ref() {
            Expr::Const(scale) if *scale > 0 => *lhs,
            _ => Expr::Bin { op: BinOp::Shl, lhs, rhs },
        },
        other => other,
    }
}

/// A compare chain over one value, rebuilt as a switch.
///
/// A compiler lowers a small switch to a tree of compares instead of a jump
/// table, and reading the case bodies from that tree leaves a `goto` per
/// case. Walking the tree as ranges over one value gives the same
/// cases back, and the existing switch renderer then lays the bodies out.
pub struct ChainSwitch {
    pub block_start: u64,
    pub index: Expr,
    pub cases: Vec<(i64, u64)>,
    pub default: Option<u64>,
    pub blocks: Vec<u64>,
}

/// Drops the zero-extension a 32-bit read carries, so `w0` and
/// `(x0 & 0xffffffff)` compare equal.
fn normalized(expr: &Expr) -> Expr {
    if let Expr::Bin {
        op: BinOp::And,
        lhs,
        rhs,
    } = expr
    {
        if matches!(
            rhs.as_ref(),
            Expr::Const(0xffff_ffff) | Expr::Const(u64::MAX)
        ) {
            return normalized(lhs);
        }
    }
    expr.clone()
}

fn same_value(left: &Expr, right: &Expr) -> bool {
    format!("{:?}", normalized(left)) == format!("{:?}", normalized(right))
}

fn successors(ir: &FunctionIr, index: usize) -> Vec<usize> {
    let find = |address: u64| ir.blocks.iter().position(|block| block.start == address);
    let fallthrough = (index + 1 < ir.blocks.len()).then_some(index + 1);
    let mut out = Vec::new();
    match ir.blocks[index].stmts.last() {
        Some(Stmt::Br {
            target: Some(target),
        }) => out.extend(find(*target)),
        Some(Stmt::Brif { target, .. }) | Some(Stmt::BrifFlags { target, .. }) => {
            out.extend(find(*target));
            out.extend(fallthrough);
        }
        Some(Stmt::Switch { cases, default, .. }) => {
            for (_, target) in cases {
                out.extend(find(*target));
            }
            if let Some(target) = default {
                out.extend(find(*target));
            }
        }
        Some(Stmt::Ret { .. }) | Some(Stmt::BrIndirect { .. }) | Some(Stmt::Trap) => {}
        _ => out.extend(fallthrough),
    }
    out
}

fn predecessors(ir: &FunctionIr) -> std::collections::HashMap<u64, usize> {
    let mut counts: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    for (index, _) in ir.blocks.iter().enumerate() {
        for successor in successors(ir, index) {
            *counts.entry(ir.blocks[successor].start).or_default() += 1;
        }
    }
    counts
}

struct ChainWalk<'a> {
    ir: &'a FunctionIr,
    position: std::collections::HashMap<u64, usize>,
    value: Expr,
    cases: std::collections::BTreeMap<i64, u64>,
    default: Option<u64>,
    blocks: Vec<u64>,
    failed: bool,
}

impl ChainWalk<'_> {
    fn next_start(&self, at: u64) -> Option<u64> {
        let index = *self.position.get(&at)?;
        self.ir.blocks.get(index + 1).map(|block| block.start)
    }

    fn compare_at(&self, at: u64) -> Option<(crate::ir::Cond, i64, u64)> {
        let index = *self.position.get(&at)?;
        let Stmt::Brif {
            cond,
            lhs,
            rhs,
            target,
        } = self.ir.blocks[index].stmts.last()?
        else {
            return None;
        };
        let Expr::Const(k) = rhs else {
            return None;
        };
        if !same_value(lhs, &self.value) {
            return None;
        }
        Some((*cond, *k as i64, *target))
    }

    fn assign(&mut self, at: u64, lo: i64, hi: i64) {
        if hi < lo {
            return;
        }
        if hi - lo > 256 {
            self.failed = true;
            return;
        }
        for value in lo..=hi {
            match self.cases.get(&value) {
                Some(existing) if *existing != at => {
                    self.failed = true;
                    return;
                }
                Some(_) => {}
                None => {
                    self.cases.insert(value, at);
                }
            }
        }
    }

    fn walk(&mut self, at: u64, lo: i64, hi: i64) {
        if self.failed || hi < lo {
            return;
        }
        if self.blocks.contains(&at) {
            self.failed = true;
            return;
        }
        let Some((cond, k, target)) = self.compare_at(at) else {
            self.assign(at, lo, hi);
            return;
        };
        self.blocks.push(at);
        let (taken, rest): (Vec<(i64, i64)>, Vec<(i64, i64)>) = match cond {
            crate::ir::Cond::Eq => (
                if k >= lo && k <= hi { vec![(k, k)] } else { Vec::new() },
                vec![(lo, hi.min(k - 1)), (lo.max(k + 1), hi)],
            ),
            crate::ir::Cond::Ne => (
                vec![(lo, hi.min(k - 1)), (lo.max(k + 1), hi)],
                if k >= lo && k <= hi { vec![(k, k)] } else { Vec::new() },
            ),
            crate::ir::Cond::Lt | crate::ir::Cond::Cc => {
                (vec![(lo, hi.min(k - 1))], vec![(lo.max(k), hi)])
            }
            crate::ir::Cond::Le | crate::ir::Cond::Ls => {
                (vec![(lo, hi.min(k))], vec![(lo.max(k + 1), hi)])
            }
            crate::ir::Cond::Gt | crate::ir::Cond::Hi => {
                (vec![(lo.max(k + 1), hi)], vec![(lo, hi.min(k))])
            }
            crate::ir::Cond::Ge | crate::ir::Cond::Cs => {
                (vec![(lo.max(k), hi)], vec![(lo, hi.min(k - 1))])
            }
            _ => {
                self.failed = true;
                return;
            }
        };
        let taken: Vec<(i64, i64)> = taken
            .into_iter()
            .filter(|(low, high)| high >= low)
            .collect();
        let rest: Vec<(i64, i64)> = rest
            .into_iter()
            .filter(|(low, high)| high >= low)
            .collect();
        if taken.is_empty() && rest.len() == 1 && rest[0] == (lo, hi) {
            // Everything the walked range holds leaves the dispatch here.
            if self.default.is_none() {
                self.default = Some(target);
            }
        } else if let [(low, high)] = taken.as_slice() {
            if low == high {
                self.assign(target, *low, *high);
            } else {
                self.walk(target, *low, *high);
            }
        } else if taken.len() > 1 {
            // An inequality whose taken side is not contiguous: the dispatch
            // is not a switch over one value.
            self.failed = true;
            return;
        }
        for (low, high) in rest {
            let (low, high) = (low.max(lo), high.min(hi));
            if high < low {
                continue;
            }
            match self.next_start(at) {
                Some(next) => self.walk(next, low, high),
                None => self.failed = true,
            }
        }
    }
}

/// Rebuilds every compare tree that is a complete switch over one value.
pub fn recover_chains(ir: &FunctionIr) -> Vec<ChainSwitch> {
    let position: std::collections::HashMap<u64, usize> = ir
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start, index))
        .collect();
    let preds = predecessors(ir);
    let mut out: Vec<ChainSwitch> = Vec::new();
    for block in ir.blocks.iter() {
        let Some(Stmt::Brif { lhs, rhs, .. }) = block.stmts.last() else {
            continue;
        };
        if !matches!(rhs, Expr::Const(_)) {
            continue;
        }
        if out.iter().any(|chain| chain.blocks.contains(&block.start)) {
            continue;
        }
        let mut walk = ChainWalk {
            ir,
            position: position.clone(),
            value: lhs.clone(),
            cases: std::collections::BTreeMap::new(),
            default: None,
            blocks: Vec::new(),
            failed: false,
        };
        let mut lo = i64::MAX;
        let mut hi = i64::MIN;
        let mut range_compare = false;
        let mut cursor = Some(block.start);
        while let Some(at) = cursor {
            let Some((cond, k, _)) = walk.compare_at(at) else {
                break;
            };
            if !matches!(cond, crate::ir::Cond::Eq | crate::ir::Cond::Ne) {
                range_compare = true;
            }
            lo = lo.min(k);
            hi = hi.max(k);
            cursor = walk.next_start(at);
        }
        if lo == i64::MAX || hi == i64::MIN {
            continue;
        }
        if range_compare {
            lo = lo.min(0);
        }
        if hi - lo > 256 {
            continue;
        }
        walk.walk(block.start, lo, hi);
        if walk.failed || walk.cases.len() < 3 || walk.cases.len() > 256 {
            continue;
        }
        let case_lo = *walk.cases.keys().next().unwrap();
        let case_hi = *walk.cases.keys().next_back().unwrap();
        if case_hi - case_lo + 1 != walk.cases.len() as i64 {
            continue;
        }
        // Every case body must be outside the chain, and every chain block
        // but the head must be reachable only from the chain, so removing them
        // cannot strand another path.
        if walk.cases.values().any(|target| walk.blocks.contains(target)) {
            continue;
        }
        if walk
            .blocks
            .iter()
            .skip(1)
            .any(|start| preds.get(start).copied().unwrap_or(0) != 1)
        {
            continue;
        }
        out.push(ChainSwitch {
            block_start: block.start,
            // The chain compares the value with its zero-extension stripped,
            // and the dispatch reads best the same way.
            index: normalized(lhs),
            cases: walk.cases.iter().map(|(k, v)| (*k, *v)).collect(),
            default: walk.default,
            blocks: walk.blocks,
        });
    }
    out
}

/// Replaces each recovered chain's head with the dispatch and drops the rest
/// of the chain.
pub fn apply_chains(ir: &mut FunctionIr, chains: &[ChainSwitch]) {
    for chain in chains {
        let Some(index) = ir
            .blocks
            .iter()
            .position(|block| block.start == chain.block_start)
        else {
            continue;
        };
        ir.blocks[index].stmts.pop();
        ir.blocks[index].stmts.push(Stmt::Switch {
            index: chain.index.clone(),
            cases: chain.cases.clone(),
            default: chain.default,
        });
        ir.blocks.retain(|block| {
            block.start == chain.block_start || !chain.blocks.contains(&block.start)
        });
    }
}

use crate::ir::{BinOp, Expr, FunctionIr, Stmt};

/// An inclusive interval of case values.
type Range = (i64, i64);

/// A compare tree over one value, rebuilt as a switch.
///
/// Small switches are often compiled to compare trees instead of a jump
/// table; structuring the tree directly leaves a `goto` per case.
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
        && matches!(
            rhs.as_ref(),
            Expr::Const(0xffff_ffff) | Expr::Const(u64::MAX)
        )
    {
        return normalized(lhs);
    }
    expr.clone()
}

fn same_value(left: &Expr, right: &Expr) -> bool {
    normalized(left) == normalized(right)
}

pub(crate) fn successors(ir: &FunctionIr, index: usize) -> Vec<usize> {
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

pub(crate) fn predecessors(ir: &FunctionIr) -> std::collections::HashMap<u64, usize> {
    let mut counts: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    for (index, _) in ir.blocks.iter().enumerate() {
        for successor in successors(ir, index) {
            *counts.entry(ir.blocks[successor].start).or_default() += 1;
        }
    }
    counts
}

/// The interval of the value guaranteed on entry by the block's sole incoming
/// conditional edge, e.g. `x > 4` guarding a subtree that tests 5..9.
fn incoming_interval(
    ir: &FunctionIr,
    predecessors: &std::collections::HashMap<u64, usize>,
    destination: usize,
    value: &Expr,
    lo: i64,
    hi: i64,
) -> Option<(i64, i64)> {
    let destination_start = ir.blocks.get(destination)?.start;
    if predecessors.get(&destination_start).copied().unwrap_or(0) != 1 {
        return None;
    }
    let mut incoming = Vec::new();
    for (source, block) in ir.blocks.iter().enumerate() {
        let Some(last) = block.stmts.last() else {
            continue;
        };
        match last {
            Stmt::Brif {
                cond,
                lhs,
                rhs: Expr::Const(k),
                target,
            } if (*target == destination_start || source + 1 == destination)
                && same_value(lhs, value) =>
            {
                incoming.push((source, *cond, *k as i64, *target == destination_start));
            }
            _ => {}
        }
    }
    if incoming.len() != 1 {
        return None;
    }
    let (_, cond, k, taken_edge) = incoming[0];
    let (taken, rest): (Vec<Range>, Vec<Range>) = match cond {
        crate::ir::Cond::Eq => (
            if (lo..=hi).contains(&k) {
                vec![(k, k)]
            } else {
                Vec::new()
            },
            vec![
                (lo, hi.min(k.saturating_sub(1))),
                (lo.max(k.saturating_add(1)), hi),
            ],
        ),
        crate::ir::Cond::Ne => (
            vec![
                (lo, hi.min(k.saturating_sub(1))),
                (lo.max(k.saturating_add(1)), hi),
            ],
            if (lo..=hi).contains(&k) {
                vec![(k, k)]
            } else {
                Vec::new()
            },
        ),
        crate::ir::Cond::Lt => (
            vec![(lo, hi.min(k.saturating_sub(1)))],
            vec![(lo.max(k), hi)],
        ),
        crate::ir::Cond::Cc if lo >= 0 && k >= 0 => (
            vec![(lo, hi.min(k.saturating_sub(1)))],
            vec![(lo.max(k), hi)],
        ),
        crate::ir::Cond::Le => (
            vec![(lo, hi.min(k))],
            vec![(lo.max(k.saturating_add(1)), hi)],
        ),
        crate::ir::Cond::Ls if lo >= 0 && k >= 0 => (
            vec![(lo, hi.min(k))],
            vec![(lo.max(k.saturating_add(1)), hi)],
        ),
        crate::ir::Cond::Gt => (
            vec![(lo.max(k.saturating_add(1)), hi)],
            vec![(lo, hi.min(k))],
        ),
        crate::ir::Cond::Hi if lo >= 0 && k >= 0 => (
            vec![(lo.max(k.saturating_add(1)), hi)],
            vec![(lo, hi.min(k))],
        ),
        crate::ir::Cond::Ge => (
            vec![(lo.max(k), hi)],
            vec![(lo, hi.min(k.saturating_sub(1)))],
        ),
        crate::ir::Cond::Cs if lo >= 0 && k >= 0 => (
            vec![(lo.max(k), hi)],
            vec![(lo, hi.min(k.saturating_sub(1)))],
        ),
        _ => return None,
    };
    let intervals = if taken_edge { taken } else { rest };
    let intervals: Vec<_> = intervals
        .into_iter()
        .filter(|(start, end)| start <= end)
        .collect();
    match intervals.as_slice() {
        [(start, end)] => Some((*start, *end)),
        _ => None,
    }
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
        let (taken, rest): (Vec<Range>, Vec<Range>) = match cond {
            crate::ir::Cond::Eq => (
                if k >= lo && k <= hi {
                    vec![(k, k)]
                } else {
                    Vec::new()
                },
                vec![(lo, hi.min(k - 1)), (lo.max(k + 1), hi)],
            ),
            crate::ir::Cond::Ne => (
                vec![(lo, hi.min(k - 1)), (lo.max(k + 1), hi)],
                if k >= lo && k <= hi {
                    vec![(k, k)]
                } else {
                    Vec::new()
                },
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
        let rest: Vec<(i64, i64)> = rest.into_iter().filter(|(low, high)| high >= low).collect();
        if taken.is_empty() && rest.len() == 1 && rest[0] == (lo, hi) {
            // No in-range value takes the branch: its target is the default.
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
    for (block_index, block) in ir.blocks.iter().enumerate() {
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
            let full_lo = lo.min(0);
            if let Some((entry_lo, entry_hi)) =
                incoming_interval(ir, &preds, block_index, lhs, full_lo, hi)
            {
                lo = full_lo.max(entry_lo);
                hi = hi.min(entry_hi);
            } else {
                lo = full_lo;
            }
        }
        if hi < lo || hi.saturating_sub(lo) > 256 {
            continue;
        }
        walk.walk(block.start, lo, hi);
        // Two cases are enough: `structure_best` keeps the switch only when
        // it removes labels.
        if walk.failed || walk.cases.len() < 2 || walk.cases.len() > 256 {
            continue;
        }
        let case_lo = *walk.cases.keys().next().unwrap();
        let case_hi = *walk.cases.keys().next_back().unwrap();
        if case_hi - case_lo + 1 != walk.cases.len() as i64 {
            continue;
        }
        // Case bodies must lie outside the chain, and every chain block but
        // the head must have a single predecessor, so dropping them cannot
        // strand another path.
        if walk
            .cases
            .values()
            .any(|target| walk.blocks.contains(target))
        {
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

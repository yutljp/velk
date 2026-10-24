use crate::ir::visit::expr_width;
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

/// A register's low 32 bits as the 32-bit read they are, so `w0` and
/// `(x0 & 0xffffffff)` compare equal, while the whole register stays apart:
/// a test of the low half says nothing of the upper one.
fn normalized(expr: &Expr) -> Expr {
    if let Expr::Bin {
        op: BinOp::And,
        lhs,
        rhs,
    } = expr
    {
        match rhs.as_ref() {
            Expr::Const(u64::MAX) => return normalized(lhs),
            Expr::Const(0xffff_ffff) => {
                if let Expr::Reg {
                    index,
                    width: 32 | 64,
                } = normalized(lhs)
                {
                    return Expr::reg(index, 32);
                }
            }
            _ => {}
        }
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
        let edges =
            crate::ir::cfg::block_successors_with_exceptions(&ir.blocks, index, &ir.landing_pads);
        for successor in edges.normal.into_iter().chain(edges.exceptional) {
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

    /// The width of the value a chain block compares.
    fn width(&self, at: u64) -> Option<u32> {
        let index = *self.position.get(&at)?;
        match self.ir.blocks[index].stmts.last()? {
            Stmt::Brif { lhs, .. } => Some(expr_width(lhs).map_or(64, u32::from)),
            _ => None,
        }
    }

    /// Where the chain's compares send `value`.
    fn route(&self, head: u64, value: i64, bits: u32) -> Option<u64> {
        let mut at = head;
        for _ in 0..=self.blocks.len() {
            if !self.blocks.contains(&at) {
                return Some(at);
            }
            let (cond, k, target) = self.compare_at(at)?;
            at = if holds(cond, value, k, bits)? {
                target
            } else {
                self.next_start(at)?
            };
        }
        None
    }

    /// The switch's default when it sends every value where the chain does:
    /// each value in `lo..=hi` to its case or the default, and the values
    /// outside the range, whose compares all agree with one representative
    /// on each side or at the extremes, to the default. Without a default from
    /// the walk, it is where the values outside the range go.
    fn verified_default(&self, head: u64, lo: i64, hi: i64) -> Option<u64> {
        let bits = self.width(head)?;
        if self.blocks.iter().any(|at| self.width(*at) != Some(bits)) {
            return None;
        }
        let (min, max) = if bits >= 64 {
            (i64::MIN, i64::MAX)
        } else {
            (-(1i64 << (bits - 1)), (1i64 << (bits - 1)) - 1)
        };
        let outside: Vec<i64> = [
            lo.checked_sub(1),
            hi.checked_add(1),
            Some(min),
            Some(max),
            Some(-1),
        ]
        .into_iter()
        .flatten()
        .filter(|value| !(lo..=hi).contains(value))
        .collect();
        let default = match self.default {
            Some(default) => default,
            None => self.route(head, *outside.first()?, bits)?,
        };
        let in_range = (lo..=hi).all(|value| {
            self.route(head, value, bits)
                == Some(self.cases.get(&value).copied().unwrap_or(default))
        });
        let beyond = outside
            .iter()
            .all(|value| self.route(head, *value, bits) == Some(default));
        (in_range && beyond).then_some(default)
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

/// Whether `cond` holds between `value` and `k`, both taken at `bits` bits.
fn holds(cond: crate::ir::Cond, value: i64, k: i64, bits: u32) -> Option<bool> {
    use crate::ir::Cond;
    let shift = 64 - bits;
    let (a, b) = (
        (value as u64) << shift >> shift,
        (k as u64) << shift >> shift,
    );
    let (sa, sb) = (
        ((a << shift) as i64) >> shift,
        ((b << shift) as i64) >> shift,
    );
    Some(match cond {
        Cond::Eq => a == b,
        Cond::Ne => a != b,
        Cond::Lt => sa < sb,
        Cond::Ge => sa >= sb,
        Cond::Gt => sa > sb,
        Cond::Le => sa <= sb,
        Cond::Cc => a < b,
        Cond::Cs => a >= b,
        Cond::Hi => a > b,
        Cond::Ls => a <= b,
        Cond::Mi | Cond::Pl | Cond::Vs | Cond::Vc => return None,
    })
}

/// A chain of `==`/`!=` tests of one value against constants, as a switch.
fn equality_chain(
    ir: &FunctionIr,
    head: usize,
    positions: &std::collections::HashMap<u64, usize>,
    predecessors: &std::collections::HashMap<u64, usize>,
) -> Option<ChainSwitch> {
    let Stmt::Brif { lhs, .. } = ir.blocks[head].stmts.last()? else {
        return None;
    };
    let value = normalized(lhs);
    let Expr::Reg { width: 32 | 64, .. } = value else {
        return None;
    };
    let bits = expr_width(&value)?;
    let mut at = head;
    let mut blocks = Vec::new();
    let mut cases = std::collections::BTreeMap::new();
    let default = loop {
        let block = &ir.blocks[at];
        if blocks.contains(&block.start) {
            return None;
        }
        let Some(Stmt::Brif {
            cond,
            lhs,
            rhs: Expr::Const(k),
            target,
        }) = block.stmts.last()
        else {
            break block.start;
        };
        if !matches!(cond, crate::ir::Cond::Eq | crate::ir::Cond::Ne) || normalized(lhs) != value {
            break block.start;
        }
        if blocks.len() == 256
            || (at != head
                && (at == 0
                    || block.stmts.len() != 1
                    || predecessors.get(&block.start) != Some(&1)))
            || (bits == 32 && *k > i32::MAX as u64)
        {
            return None;
        }
        let fallthrough = ir.blocks.get(at + 1)?.start;
        let (case, next) = if *cond == crate::ir::Cond::Eq {
            (*target, fallthrough)
        } else {
            (fallthrough, *target)
        };
        positions.get(&case)?;
        if cases.insert(*k as i64, case).is_some() {
            return None;
        }
        blocks.push(block.start);
        at = *positions.get(&next)?;
    };
    if cases.len() < 2
        || cases.values().any(|target| blocks.contains(target))
        || cases
            .values()
            .filter(|target| **target != default)
            .collect::<std::collections::HashSet<_>>()
            .len()
            < 2
    {
        return None;
    }
    Some(ChainSwitch {
        block_start: ir.blocks[head].start,
        index: value,
        cases: cases.into_iter().collect(),
        default: Some(default),
        blocks,
    })
}

fn chain_is_available(blocks: &[u64], head: u64, entry: u64, accepted: &[ChainSwitch]) -> bool {
    blocks.iter().all(|start| {
        // The implicit function entry is absent from CFG predecessor counts.
        (*start != entry || *start == head)
            && !accepted.iter().any(|chain| chain.blocks.contains(start))
    })
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
        if let Some(chain) = equality_chain(ir, block_index, &position, &preds) {
            if chain_is_available(&chain.blocks, chain.block_start, ir.blocks[0].start, &out) {
                out.push(chain);
            }
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
        // The constants of every compare in the tree, along both edges.
        let mut lo = i64::MAX;
        let mut hi = i64::MIN;
        let mut range_compare = false;
        let mut pending = vec![block.start];
        let mut visited = std::collections::HashSet::new();
        while let Some(at) = pending.pop() {
            if !visited.insert(at) {
                continue;
            }
            let Some((cond, k, target)) = walk.compare_at(at) else {
                continue;
            };
            if !matches!(cond, crate::ir::Cond::Eq | crate::ir::Cond::Ne) {
                range_compare = true;
            }
            lo = lo.min(k);
            hi = hi.max(k);
            pending.push(target);
            pending.extend(walk.next_start(at));
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
        // A range check sends every case one way: it stays an `if`.
        let targets: std::collections::HashSet<u64> = walk.cases.values().copied().collect();
        if targets.len() < 2 {
            continue;
        }
        let case_lo = *walk.cases.keys().next().unwrap();
        let case_hi = *walk.cases.keys().next_back().unwrap();
        if case_hi - case_lo + 1 != walk.cases.len() as i64 {
            continue;
        }
        // Case bodies must lie outside the chain, and every chain block but
        // the head must hold only its compare and have a single predecessor,
        // so dropping them cannot lose an effect or strand another path.
        if walk
            .cases
            .values()
            .any(|target| walk.blocks.contains(target))
        {
            continue;
        }
        if walk.blocks.iter().skip(1).any(|start| {
            preds.get(start).copied().unwrap_or(0) != 1
                || ir.blocks[position[start]].stmts.len() != 1
        }) {
            continue;
        }
        let Some(default) = walk.verified_default(block.start, lo, hi) else {
            continue;
        };
        // One case beside the default is a plain test.
        if walk
            .cases
            .values()
            .filter(|target| **target != default)
            .collect::<std::collections::HashSet<_>>()
            .len()
            < 2
        {
            continue;
        }
        if !chain_is_available(&walk.blocks, block.start, ir.blocks[0].start, &out) {
            continue;
        }
        out.push(ChainSwitch {
            block_start: block.start,
            index: normalized(lhs),
            cases: walk.cases.iter().map(|(k, v)| (*k, *v)).collect(),
            default: Some(default),
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

#[cfg(test)]
mod tests {
    use super::{apply_chains, chain_is_available, equality_chain, predecessors, recover_chains};
    use crate::ir::{Block, Cond, Expr, FunctionIr, Stmt, eval};
    use crate::loader::Isa;

    /// `if (n <op> k) goto target; ...` over one 32-bit value, falling
    /// through to a return of 1.
    fn chain(compares: &[(Cond, u64, u64)]) -> FunctionIr {
        let mut ir = FunctionIr::single_block(Isa::AArch64, Vec::new());
        ir.blocks.clear();
        for (position, (cond, k, target)) in compares.iter().enumerate() {
            ir.blocks.push(Block {
                start: position as u64 * 4,
                stmts: vec![Stmt::Brif {
                    cond: *cond,
                    lhs: Expr::reg(0, 32),
                    rhs: Expr::Const(*k),
                    target: *target,
                }],
            });
        }
        for start in [compares.len() as u64 * 4, 0x100, 0x200] {
            ir.blocks.push(Block {
                start,
                stmts: vec![Stmt::Ret {
                    value: Expr::Const(start),
                }],
            });
        }
        ir
    }

    #[test]
    fn rebuilds_equality_tests_as_a_switch() {
        let chains = recover_chains(&chain(&[(Cond::Eq, 0, 0x100), (Cond::Eq, 1, 0x200)]));
        let [switch] = chains.as_slice() else {
            panic!("one switch");
        };
        assert_eq!(switch.cases, vec![(0, 0x100), (1, 0x200)]);
        assert_eq!(switch.default, Some(8));
    }

    #[test]
    fn a_range_test_wider_than_its_cases_is_no_switch() {
        // `n <= 0` also takes every negative value, which no case covers.
        let ir = chain(&[(Cond::Le, 0, 0x100), (Cond::Ne, 1, 0x200)]);
        assert!(recover_chains(&ir).is_empty());
    }

    fn dispatch(values: &[u64], width: u8, mixed: bool) -> FunctionIr {
        let mut ir = FunctionIr::single_block(Isa::AArch64, Vec::new());
        ir.blocks.clear();
        let body = |position: usize| Block {
            start: 0x10000 + position as u64 * 0x20,
            stmts: vec![
                Stmt::Store {
                    addr: Expr::Const(0x1000),
                    value: Expr::Const(position as u64 + 11),
                    width: 8,
                },
                Stmt::Ret {
                    value: Expr::Const(position as u64 + 11),
                },
            ],
        };
        let mut later = Vec::new();
        for (position, value) in values.iter().enumerate() {
            let inverse = mixed && position % 2 == 1;
            let next = if position + 1 == values.len() {
                0x8000
            } else {
                (position as u64 + 1) * 0x20
            };
            ir.blocks.push(Block {
                start: position as u64 * 0x20,
                stmts: vec![Stmt::Brif {
                    cond: if inverse { Cond::Ne } else { Cond::Eq },
                    lhs: Expr::reg(0, width),
                    rhs: Expr::Const(*value),
                    target: if inverse { next } else { body(position).start },
                }],
            });
            if inverse {
                ir.blocks.push(body(position));
            } else {
                later.push(body(position));
            }
        }
        ir.blocks.push(Block {
            start: 0x8000,
            stmts: vec![
                Stmt::Store {
                    addr: Expr::Const(0x1000),
                    value: Expr::Const(99),
                    width: 8,
                },
                Stmt::Ret {
                    value: Expr::Const(99),
                },
            ],
        });
        ir.blocks.extend(later);
        ir
    }

    fn equality_only(ir: &FunctionIr) -> Option<super::ChainSwitch> {
        let positions = ir
            .blocks
            .iter()
            .enumerate()
            .map(|(position, block)| (block.start, position))
            .collect();
        equality_chain(ir, 0, &positions, &predecessors(ir))
    }

    fn compare_dispatch(ir: &FunctionIr, values: &[u64], width: u8, inputs: &[u64]) {
        let chains = recover_chains(ir);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].cases.len(), values.len());
        let mut rewritten = ir.clone();
        apply_chains(&mut rewritten, &chains);
        let nodes = crate::render::structure::structure_best(ir);
        let lowered = crate::render::structure::lower::lower(ir, &nodes);
        for input in inputs {
            let registers = [(0, *input), (1, 17)];
            let setup = eval::Setup {
                seed: 123,
                convention: eval::Convention {
                    arguments: &[0],
                    clobbered: &[],
                },
                registers: &registers,
                memory: &[(0x1000, 777), (0x1010, 888)],
                step_limit: 4096,
            };
            let original = eval::run(ir, &setup);
            let eval::Outcome::Return {
                value,
                calls,
                memory,
            } = &original
            else {
                panic!("{original:?}")
            };
            let discriminant = if width == 32 {
                *input & 0xffff_ffff
            } else {
                *input
            };
            let expected = values
                .iter()
                .position(|value| *value == discriminant)
                .map_or(99, |position| position as u64 + 11);
            assert_eq!(*value, expected, "input {input:#x}");
            for offset in 0..8 {
                assert_eq!(memory[&(0x1000 + offset)], (expected >> (8 * offset)) as u8);
            }
            let head_call = matches!(ir.blocks[0].stmts.first(), Some(Stmt::Call { .. }));
            assert_eq!(
                calls,
                &if head_call {
                    vec![eval::Call {
                        target: Some(0x123),
                        arguments: vec![17],
                    }]
                } else {
                    Vec::new()
                }
            );
            for offset in 0..8 {
                let expected = if head_call { 123_u64 } else { 888 };
                assert_eq!(memory[&(0x1010 + offset)], (expected >> (8 * offset)) as u8);
            }
            assert_eq!(
                eval::run(&rewritten, &setup),
                original,
                "rewritten {input:#x}"
            );
            assert_eq!(
                eval::run(&lowered, &setup),
                original,
                "structured {input:#x}: {nodes:#?}"
            );
        }
    }

    #[test]
    fn sparse_equality_dispatch_keeps_gaps_and_narrow_input_bits() {
        let values = [1, 1000, 10000];
        compare_dispatch(
            &dispatch(&values, 32, false),
            &values,
            32,
            &[
                0,
                1,
                2,
                999,
                1000,
                1001,
                9999,
                10000,
                10001,
                u64::MAX,
                0x1234_5678_0000_03e8,
            ],
        );
        let mut masked = dispatch(&values, 32, false);
        for block in &mut masked.blocks {
            if let Some(Stmt::Brif { lhs, .. }) = block.stmts.last_mut() {
                *lhs = Expr::bin(
                    crate::ir::BinOp::And,
                    Expr::reg(0, 64),
                    Expr::Const(0xffff_ffff),
                );
            }
        }
        compare_dispatch(
            &masked,
            &values,
            32,
            &[1, 1000, 10000, 0x1234_5678_0000_03e8, u64::MAX],
        );
    }

    #[test]
    fn sparse_inequality_continuations_keep_their_original_default() {
        let values = [1, 1000, 10000, 100000];
        compare_dispatch(
            &dispatch(&values, 64, true),
            &values,
            64,
            &[0, 1, 1000, 10000, 100000, 999, 1001, u64::MAX],
        );
        let values = [1000, 10000];
        compare_dispatch(
            &dispatch(&values, 32, true),
            &values,
            32,
            &[0, 999, 1000, 1001, 9999, 10000, 10001],
        );
    }

    #[test]
    fn sparse_dispatch_preserves_all_head_effects() {
        let values = [1, 1000, 10000];
        let mut ir = dispatch(&values, 64, false);
        ir.blocks[0].stmts.insert(
            0,
            Stmt::Store {
                addr: Expr::Const(0x1010),
                value: Expr::Const(123),
                width: 8,
            },
        );
        ir.blocks[0].stmts.insert(
            0,
            Stmt::Call {
                kind: crate::ir::CallKind::Invoke,
                target: Some(0x123),
                through: None,
                convention: crate::ir::Convention::Aapcs64,
                args: Some(vec![Expr::reg(1, 64)]),
                floats_named: false,
                outputs: crate::ir::fallback_call_outputs(
                    crate::ir::Convention::Aapcs64,
                    Some(crate::ir::Registers(0)),
                ),
                clobbers: Some(crate::ir::Registers(0)),
                via: None,
            },
        );
        compare_dispatch(&ir, &values, 64, &[0, 1, 1000, 10000, u64::MAX]);
        let mut after = ir.clone();
        apply_chains(&mut after, &recover_chains(&ir));
        assert_eq!(
            format!("{:?}", &after.blocks[0].stmts[..2]),
            format!("{:?}", &ir.blocks[0].stmts[..2])
        );
    }

    #[test]
    fn sparse_dispatch_keeps_all_64_bit_case_patterns() {
        let values = [1, 1 << 63, u64::MAX];
        compare_dispatch(
            &dispatch(&values, 64, true),
            &values,
            64,
            &[
                0,
                1,
                2,
                (1 << 63) - 1,
                1 << 63,
                (1 << 63) + 1,
                u64::MAX - 1,
                u64::MAX,
            ],
        );
    }

    #[test]
    fn sparse_dispatch_keeps_shared_case_bodies() {
        let mut ir = dispatch(&[1, 1000, 10000], 64, false);
        let Stmt::Brif { target, .. } = &mut ir.blocks[1].stmts[0] else {
            unreachable!()
        };
        *target = 0x10000;
        let chains = recover_chains(&ir);
        assert_eq!(chains.len(), 1);
        assert_eq!(
            chains[0].cases,
            vec![(1, 0x10000), (1000, 0x10000), (10000, 0x10040)]
        );
        let mut after = ir.clone();
        apply_chains(&mut after, &chains);
        let nodes = crate::render::structure::structure_best(&ir);
        let lowered = crate::render::structure::lower::lower(&ir, &nodes);
        for input in [0, 1, 1000, 10000, u64::MAX] {
            let registers = [(0, input)];
            let setup = eval::Setup {
                seed: 123,
                convention: eval::Convention {
                    arguments: &[0],
                    clobbered: &[],
                },
                registers: &registers,
                memory: &[],
                step_limit: 1000,
            };
            let original = eval::run(&ir, &setup);
            let eval::Outcome::Return { value, .. } = original else {
                panic!("{original:?}")
            };
            assert_eq!(
                value,
                match input {
                    1 | 1000 => 11,
                    10000 => 13,
                    _ => 99,
                }
            );
            assert_eq!(eval::run(&after, &setup), original);
            assert_eq!(eval::run(&lowered, &setup), original);
        }
    }

    #[test]
    fn sparse_dispatch_has_a_test_count_bound_instead_of_a_value_span_bound() {
        for (count, accepted) in [(256, true), (257, false)] {
            let values: Vec<_> = (0..count).map(|index| index * 1000).collect();
            assert_eq!(
                equality_only(&dispatch(&values, 64, false)).is_some(),
                accepted
            );
        }
    }

    #[test]
    fn sparse_dispatch_does_not_remove_effectful_or_shared_continuations() {
        let original = dispatch(&[1, 1000, 10000], 64, false);
        for effect in [
            Stmt::Store {
                addr: Expr::Const(0x1000),
                value: Expr::Const(12),
                width: 8,
            },
            Stmt::Assign {
                dest: crate::ir::RegRef {
                    index: 0,
                    width: 64,
                },
                value: Expr::Const(1000),
            },
            Stmt::Call {
                kind: crate::ir::CallKind::Invoke,
                target: Some(0x123),
                through: None,
                convention: crate::ir::Convention::Aapcs64,
                args: Some(Vec::new()),
                floats_named: false,
                outputs: crate::ir::fallback_call_outputs(crate::ir::Convention::Aapcs64, None),
                clobbers: None,
                via: None,
            },
        ] {
            let mut ir = original.clone();
            ir.blocks[1].stmts.insert(0, effect);
            assert!(equality_only(&ir).is_none());
        }
        let mut ir = original.clone();
        ir.blocks.push(Block {
            start: 0x20000,
            stmts: vec![Stmt::Br { target: Some(0x20) }],
        });
        assert!(equality_only(&ir).is_none());
    }

    #[test]
    fn sparse_dispatch_rejects_cycles_duplicate_cases_and_missing_targets() {
        let original = dispatch(&[1, 1000, 10000], 64, false);
        for target in [0, 0x20, 0xdead] {
            let mut ir = original.clone();
            let Stmt::Brif {
                target: destination,
                ..
            } = &mut ir.blocks[0].stmts[0]
            else {
                unreachable!()
            };
            *destination = target;
            assert!(equality_only(&ir).is_none());
        }
        assert!(equality_only(&dispatch(&[1, 1, 10000], 64, false)).is_none());
        let mut ir = dispatch(&[1, 1000], 64, true);
        let Stmt::Brif { target, .. } = &mut ir.blocks[1].stmts[0] else {
            unreachable!()
        };
        *target = 0;
        assert!(equality_only(&ir).is_none());
    }

    #[test]
    fn sparse_dispatch_requires_one_pure_integer_register() {
        let original = dispatch(&[1, 1000, 10000], 32, false);
        for lhs in [
            Expr::reg(1, 32),
            Expr::reg(0, 64),
            Expr::Load {
                addr: Box::new(Expr::reg(0, 64)),
                width: 4,
                signed: false,
            },
        ] {
            let mut ir = original.clone();
            for block in &mut ir.blocks {
                if let Some(Stmt::Brif { lhs: value, .. }) = block.stmts.last_mut() {
                    *value = lhs.clone();
                }
            }
            if matches!(
                lhs,
                Expr::Reg { index: 1, .. } | Expr::Reg { width: 64, .. }
            ) {
                let Stmt::Brif { lhs, .. } = &mut ir.blocks[0].stmts[0] else {
                    unreachable!()
                };
                *lhs = Expr::reg(0, 32);
            }
            assert!(equality_only(&ir).is_none());
        }
        assert!(equality_only(&dispatch(&[1, 0x8000_0000], 32, false)).is_none());
        let mut ir = original;
        let Stmt::Brif { cond, .. } = &mut ir.blocks[0].stmts[0] else {
            unreachable!()
        };
        *cond = Cond::Gt;
        assert!(equality_only(&ir).is_none());
    }

    #[test]
    fn dispatch_recovery_keeps_the_implicit_entry_before_effectful_reentry() {
        for terminate_default in [false, true] {
            let test = |cond, value, target| Stmt::Brif {
                cond,
                lhs: Expr::reg(0, 64),
                rhs: Expr::Const(value),
                target,
            };
            let finish = |start, value| Block {
                start,
                stmts: vec![
                    Stmt::Store {
                        addr: Expr::Const(0x1010),
                        value: Expr::Const(value),
                        width: 8,
                    },
                    Stmt::Ret {
                        value: Expr::Const(value),
                    },
                ],
            };
            let mut effect = vec![Stmt::Store {
                addr: Expr::Const(0x1000),
                width: 8,
                value: Expr::bin(
                    crate::ir::BinOp::Add,
                    Expr::Load {
                        addr: Box::new(Expr::Const(0x1000)),
                        width: 8,
                        signed: false,
                    },
                    Expr::Const(1),
                ),
            }];
            if terminate_default {
                effect.push(Stmt::Assign {
                    dest: crate::ir::RegRef {
                        index: 0,
                        width: 64,
                    },
                    value: Expr::Const(10000),
                });
            }
            effect.push(Stmt::Br { target: Some(0x30) });
            let mut ir = FunctionIr::single_block(Isa::AArch64, Vec::new());
            ir.blocks = vec![
                Block {
                    start: 0,
                    stmts: vec![test(Cond::Eq, 1, 0x50)],
                },
                Block {
                    start: 0x10,
                    stmts: vec![test(Cond::Eq, 1000, 0x60)],
                },
                Block {
                    start: 0x20,
                    stmts: effect,
                },
                Block {
                    start: 0x30,
                    stmts: vec![test(Cond::Ne, 10000, 0)],
                },
                finish(0x40, 13),
                finish(0x50, 11),
                finish(0x60, 12),
            ];
            assert_eq!(predecessors(&ir).get(&0), Some(&1));
            let chains = recover_chains(&ir);
            assert_eq!(chains.len(), 1);
            assert_eq!(chains[0].blocks, [0, 0x10]);
            let mut rewritten = ir.clone();
            apply_chains(&mut rewritten, &chains);
            assert_eq!(rewritten.blocks[0].start, 0);
            let nodes = crate::render::structure::structure_best(&ir);
            let lowered = crate::render::structure::lower::lower(&ir, &nodes);
            let inputs: &[u64] = if terminate_default {
                &[1, 1000, 10000, 7]
            } else {
                &[1, 1000, 10000]
            };
            for input in inputs {
                let registers = [(0, *input)];
                let setup = eval::Setup {
                    seed: 123,
                    convention: eval::Convention {
                        arguments: &[0],
                        clobbered: &[],
                    },
                    registers: &registers,
                    memory: &[(0x1000, 0), (0x1010, 0)],
                    step_limit: 1000,
                };
                let value = match input {
                    1 => 11,
                    1000 => 12,
                    _ => 13,
                };
                let count = u64::from(!matches!(input, 1 | 1000));
                let memory = [(0x1000, count), (0x1010, value)]
                    .into_iter()
                    .flat_map(|(address, word)| {
                        word.to_le_bytes()
                            .into_iter()
                            .enumerate()
                            .map(move |(offset, byte)| (address + offset as u64, byte))
                    })
                    .collect();
                let expected = eval::Outcome::Return {
                    value,
                    calls: Vec::new(),
                    memory,
                };
                assert_eq!(eval::run(&ir, &setup), expected, "original {input}");
                assert_eq!(eval::run(&rewritten, &setup), expected, "rewritten {input}");
                assert_eq!(
                    eval::run(&lowered, &setup),
                    expected,
                    "structured {input}: {nodes:#?}"
                );
            }
        }
    }

    #[test]
    fn dispatch_candidates_cannot_overlap_or_remove_the_entry() {
        let accepted = super::ChainSwitch {
            block_start: 0x20,
            index: Expr::reg(0, 64),
            cases: vec![(1, 0x100), (1000, 0x200)],
            default: Some(0x300),
            blocks: vec![0x20, 0x30],
        };
        assert!(!chain_is_available(&[0x40, 0x20], 0x40, 0, &[accepted]));
        assert!(!chain_is_available(&[0x40, 0], 0x40, 0, &[]));
        assert!(chain_is_available(&[0, 0x10], 0, 0, &[]));
        assert!(chain_is_available(&[0x40, 0x50], 0x40, 0, &[]));
    }
}

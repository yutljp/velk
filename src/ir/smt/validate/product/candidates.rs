//! The equations between the two sides that may hold at a block's entry.

use std::collections::{BTreeMap, BTreeSet};

use super::run::observable;
use super::{Application, Candidate};
use crate::ir::smt::validate::{expressions, registers_read, shape, unmodeled};
use crate::ir::{Block, Expr, Stmt};

/// Every register equal on the two sides, and an equation for each pair of
/// differing subexpressions at one place of statements paired the way the
/// blocks list them, when what they read is still what the block entered
/// with.
pub(super) fn candidates(application: &Application) -> Vec<Candidate> {
    let mut registers = BTreeSet::new();
    // The widths each register is read, written, stored or masked at: a
    // register whose low bits alone agree on the two sides is equal at those
    // widths only.
    let mut widths: BTreeMap<u16, BTreeSet<u8>> = BTreeMap::new();
    for block in application.before.iter().chain(&application.after) {
        for stmt in &block.stmts {
            for expr in expressions(stmt) {
                registers_read(expr, &mut registers);
                register_widths(expr, &mut widths);
            }
            match stmt {
                Stmt::Assign { dest, .. } => {
                    registers.insert(dest.index);
                    widths.entry(dest.index).or_default().insert(dest.width);
                }
                // A narrow store keeps the low bits of what it stores.
                Stmt::Store { value, width, .. } if *width < 8 => {
                    demand(value, width * 8, &mut widths);
                }
                Stmt::Call { .. } => {
                    registers.extend(stmt.unnamed_call_reads());
                    registers.extend(stmt.declared_call_reads());
                }
                _ => {}
            }
        }
    }
    // The low bits of a register an assignment demands are demanded of
    // what it is assigned.
    loop {
        let before = widths.clone();
        for block in application.before.iter().chain(&application.after) {
            for stmt in &block.stmts {
                if let Stmt::Assign { dest, value, .. } = stmt {
                    for &bits in before.get(&dest.index).into_iter().flatten() {
                        demand(value, bits, &mut widths);
                    }
                }
            }
        }
        if widths == before {
            break;
        }
    }
    let mut found: Vec<Candidate> = registers
        .into_iter()
        .map(|index| (Expr::reg(index, 64), Expr::reg(index, 64)))
        .collect();
    let narrow = |a: u16, b: u16| -> Vec<u8> {
        let none = BTreeSet::new();
        let (x, y) = (
            widths.get(&a).unwrap_or(&none),
            widths.get(&b).unwrap_or(&none),
        );
        x.union(y).copied().filter(|&width| width < 64).collect()
    };
    for &index in widths.keys() {
        for width in narrow(index, index) {
            found.push((Expr::reg(index, width), Expr::reg(index, width)));
        }
    }
    let mut seen: BTreeSet<String> = found.iter().map(|pair| format!("{pair:?}")).collect();
    for (old, new) in application.before.iter().zip(&application.after) {
        let paired: Vec<(&Stmt, &Stmt)> = if old.stmts.len() == new.stmts.len() {
            old.stmts.iter().zip(&new.stmts).collect()
        } else {
            let old: Vec<&Stmt> = old.stmts.iter().filter(|stmt| observable(stmt)).collect();
            let new: Vec<&Stmt> = new.stmts.iter().filter(|stmt| observable(stmt)).collect();
            old.into_iter().zip(new).collect()
        };
        let mut written = (Written::default(), Written::default());
        for (old_stmt, new_stmt) in paired {
            // Two assignments at one place may assign different registers,
            // as a renaming does: the registers may then correspond too.
            let assignments = match (old_stmt, new_stmt) {
                (Stmt::Assign { dest: a, .. }, Stmt::Assign { dest: b, .. }) => {
                    if a.index != b.index {
                        let pair = (Expr::reg(a.index, 64), Expr::reg(b.index, 64));
                        if seen.insert(format!("{pair:?}")) {
                            found.push(pair);
                        }
                    }
                    true
                }
                _ => false,
            };
            if assignments || shape(old_stmt) == shape(new_stmt) {
                for (a, b) in expressions(old_stmt).into_iter().zip(expressions(new_stmt)) {
                    differences(a, b, &written, &mut |pair| {
                        if seen.insert(format!("{pair:?}")) {
                            found.push(pair);
                        }
                    });
                }
            }
            // A narrow store keeps the low bits of what it stores, which
            // may agree where the whole values do not.
            if let (
                Stmt::Store {
                    value: a, width, ..
                },
                Stmt::Store { value: b, .. },
            ) = (old_stmt, new_stmt)
                && *width < 8
                && a != b
                && written.0.keeps(a)
                && written.1.keeps(b)
                && unmodeled(a).is_none()
                && unmodeled(b).is_none()
            {
                let pair = (kept(a.clone(), width * 8), kept(b.clone(), width * 8));
                if seen.insert(format!("{pair:?}")) {
                    found.push(pair);
                }
            }
            written.0.record(old_stmt);
            written.1.record(new_stmt);
        }
    }
    // Registers a copy or a renaming joins, on the two sides.
    let mut renamed: Vec<(u16, u16)> = found
        .iter()
        .filter_map(|pair| match pair {
            (Expr::Reg { index: a, .. }, Expr::Reg { index: b, .. }) if a != b => Some((*a, *b)),
            _ => None,
        })
        .collect();
    let mut push = |pair: Candidate| {
        if unmodeled(&pair.0).is_none()
            && unmodeled(&pair.1).is_none()
            && seen.insert(format!("{pair:?}"))
        {
            found.push(pair);
        }
    };
    // An assignment one side has and the other lacks: its register on that
    // side may hold what its expression computes on the other.
    let mut copies: Vec<(u16, u16)> = Vec::new();
    for (old, new) in application.before.iter().zip(&application.after) {
        let texts = |block: &Block| -> BTreeSet<String> {
            block.stmts.iter().map(|stmt| format!("{stmt:?}")).collect()
        };
        let (old_texts, new_texts) = (texts(old), texts(new));
        for (block, others, original) in [(old, &new_texts, true), (new, &old_texts, false)] {
            for stmt in &block.stmts {
                let Stmt::Assign { dest, value, .. } = stmt else {
                    continue;
                };
                if let Expr::Reg { index, .. } = value {
                    copies.push((dest.index, *index));
                }
                if others.contains(&format!("{stmt:?}")) {
                    continue;
                }
                let register = Expr::reg(dest.index, 64);
                let value = kept(value.clone(), dest.width);
                push(if original {
                    (register, value)
                } else {
                    (value, register)
                });
            }
        }
    }
    renamed.extend(copies);
    let mut classes: BTreeMap<u16, u16> = BTreeMap::new();
    pub(super) fn root(classes: &BTreeMap<u16, u16>, mut register: u16) -> u16 {
        while let Some(&parent) = classes.get(&register) {
            if parent == register {
                break;
            }
            register = parent;
        }
        register
    }
    for (a, b) in renamed {
        let (a, b) = (root(&classes, a), root(&classes, b));
        classes.entry(a).or_insert(a);
        classes.entry(b).or_insert(b);
        if a != b {
            classes.insert(a.max(b), a.min(b));
        }
    }
    let mut members: BTreeMap<u16, Vec<u16>> = BTreeMap::new();
    for &register in classes.keys() {
        members
            .entry(root(&classes, register))
            .or_default()
            .push(register);
    }
    for class in members.values() {
        for &a in class {
            for &b in class {
                if a != b {
                    push((Expr::reg(a, 64), Expr::reg(b, 64)));
                    for width in narrow(a, b) {
                        push((Expr::reg(a, width), Expr::reg(b, width)));
                    }
                }
            }
        }
    }
    // A register assigned under a mask, or from a narrow load, may keep
    // within the mask, as a range the equations can say: a register equal
    // to one on the other side is equal to its masked value too.
    let mut masks: BTreeMap<u16, u64> = BTreeMap::new();
    let assigned = application
        .before
        .iter()
        .chain(&application.after)
        .flat_map(|block| &block.stmts)
        .filter_map(|stmt| {
            let Stmt::Assign { dest, value, .. } = stmt else {
                return None;
            };
            let mask = match value {
                Expr::Bin {
                    op: crate::ir::BinOp::And,
                    rhs,
                    ..
                } => match rhs.as_ref() {
                    Expr::Const(mask) => *mask,
                    _ => return None,
                },
                Expr::Load {
                    width,
                    signed: false,
                    ..
                } if *width < 8 => (1u64 << (8 * u32::from(*width))) - 1,
                _ => return None,
            };
            (mask.wrapping_add(1).is_power_of_two() && mask != u64::MAX)
                .then_some((dest.index, mask))
        });
    // The widest mask a register is assigned under is the one all its
    // assignments may keep within.
    for (register, mask) in assigned {
        let widest = masks.entry(register).or_insert(mask);
        *widest = (*widest).max(mask);
    }
    let pairs: Vec<(u16, u16)> = found
        .iter()
        .filter_map(|pair| match pair {
            (
                Expr::Reg {
                    index: a,
                    width: 64,
                },
                Expr::Reg {
                    index: b,
                    width: 64,
                },
            ) => Some((*a, *b)),
            _ => None,
        })
        .collect();
    let masked = |register: u16, mask: u64| Expr::Bin {
        op: crate::ir::BinOp::And,
        lhs: Box::new(Expr::reg(register, 64)),
        rhs: Box::new(Expr::Const(mask)),
    };
    for (a, b) in pairs {
        for pair in [
            masks
                .get(&a)
                .map(|&mask| (masked(a, mask), Expr::reg(b, 64))),
            masks
                .get(&b)
                .map(|&mask| (Expr::reg(a, 64), masked(b, mask))),
        ]
        .into_iter()
        .flatten()
        {
            if seen.insert(format!("{pair:?}")) {
                found.push(pair);
            }
        }
    }
    // A register a branch compares unsigned with a constant may stay at or
    // below it, as a loop's counter does, or below it: on each side, the
    // comparison holding is a candidate too.
    // Each bound is a register, a comparison it meets and a constant: at
    // or below it unsigned, at or below it signed, or at or above it
    // signed, as either way of a branch leaves it.
    use crate::ir::Cond;
    let mut bounded: BTreeSet<(u16, u8, u64)> = BTreeSet::new();
    const UNSIGNED_AT_MOST: u8 = 0;
    const AT_MOST: u8 = 1;
    const AT_LEAST: u8 = 2;
    for stmt in application
        .before
        .iter()
        .chain(&application.after)
        .flat_map(|block| &block.stmts)
    {
        if let Stmt::Brif { cond, lhs, rhs, .. } = stmt
            && let (Expr::Reg { index, width: 64 }, Expr::Const(limit)) = (lhs, rhs)
        {
            let limit = *limit;
            match cond {
                Cond::Cs | Cond::Cc | Cond::Hi | Cond::Ls => {
                    bounded.insert((*index, UNSIGNED_AT_MOST, limit));
                    if let Some(below) = limit.checked_sub(1) {
                        bounded.insert((*index, UNSIGNED_AT_MOST, below));
                    }
                }
                Cond::Lt | Cond::Ge | Cond::Le | Cond::Gt => {
                    let signed = limit as i64;
                    for (kind, bound) in [
                        (AT_MOST, Some(signed)),
                        (AT_MOST, signed.checked_sub(1)),
                        (AT_LEAST, Some(signed)),
                        (AT_LEAST, signed.checked_add(1)),
                    ] {
                        if let Some(bound) = bound {
                            bounded.insert((*index, kind, bound as u64));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    // So may a register copied from one, or chosen between copies.
    loop {
        let known = bounded.len();
        for stmt in application
            .before
            .iter()
            .chain(&application.after)
            .flat_map(|block| &block.stmts)
        {
            let Stmt::Assign { dest, value, .. } = stmt else {
                continue;
            };
            let sources: Vec<u16> = match value {
                Expr::Reg { index, width: 64 } => vec![*index],
                Expr::Select { then, els, .. } => [then, els]
                    .into_iter()
                    .filter_map(|arm| match arm.as_ref() {
                        Expr::Reg { index, width: 64 } => Some(*index),
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            };
            let limits: Vec<(u8, u64)> = sources
                .iter()
                .flat_map(|source| {
                    bounded
                        .range((*source, 0, 0)..=(*source, u8::MAX, u64::MAX))
                        .map(|(_, kind, limit)| (*kind, *limit))
                })
                .collect();
            bounded.extend(
                limits
                    .into_iter()
                    .map(|(kind, limit)| (dest.index, kind, limit)),
            );
        }
        if bounded.len() == known {
            break;
        }
    }
    for (register, kind, limit) in bounded {
        let within = || Expr::Select {
            cond: match kind {
                UNSIGNED_AT_MOST => Cond::Ls,
                AT_MOST => Cond::Le,
                _ => Cond::Ge,
            },
            lhs: Box::new(Expr::reg(register, 64)),
            rhs: Box::new(Expr::Const(limit)),
            then: Box::new(Expr::Const(1)),
            els: Box::new(Expr::Const(0)),
        };
        for pair in [(within(), Expr::Const(1)), (Expr::Const(1), within())] {
            if seen.insert(format!("{pair:?}")) {
                found.push(pair);
            }
        }
    }
    found
}

pub(super) fn register_widths(expr: &Expr, widths: &mut BTreeMap<u16, BTreeSet<u8>>) {
    match expr {
        Expr::Reg { index, width } => {
            widths.entry(*index).or_default().insert(*width);
        }
        // A mask of the low bits reads those bits alone.
        Expr::Bin {
            op: crate::ir::BinOp::And,
            lhs,
            rhs,
        } => {
            if let Expr::Const(mask) = rhs.as_ref()
                && let Some(bits) = [8u8, 16, 32]
                    .into_iter()
                    .find(|&bits| *mask == (1u64 << bits) - 1)
            {
                demand(lhs, bits, widths);
            }
        }
        _ => {}
    }
    for child in crate::ir::visit::children(expr) {
        register_widths(child, widths);
    }
}

/// Records that only the low `bits` of `expr` matter, for each register
/// whose low `bits` alone decide them: through the operations whose low
/// bits depend on the low bits of their operands alone.
pub(super) fn demand(expr: &Expr, bits: u8, widths: &mut BTreeMap<u16, BTreeSet<u8>>) {
    use crate::ir::BinOp;
    match expr {
        Expr::Reg { index, width } if bits < *width => {
            widths.entry(*index).or_default().insert(bits);
        }
        Expr::Bin {
            op: BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::And | BinOp::Or | BinOp::Xor,
            lhs,
            rhs,
        } => {
            demand(lhs, bits, widths);
            demand(rhs, bits, widths);
        }
        Expr::Bin {
            op: BinOp::Shl,
            lhs,
            ..
        } => demand(lhs, bits, widths),
        _ => {}
    }
}

/// `value` cut to the bits a destination of `width` bits keeps.
pub(super) fn kept(value: Expr, width: u8) -> Expr {
    if width >= 64 {
        return value;
    }
    Expr::Bin {
        op: crate::ir::BinOp::And,
        lhs: Box::new(value),
        rhs: Box::new(Expr::Const((1u64 << width) - 1)),
    }
}

/// What one side's statements have changed so far in a block.
#[derive(Default)]
pub(super) struct Written {
    registers: BTreeSet<u16>,
    /// The address and width of each store.
    stores: Vec<(Expr, u8)>,
    /// Whether a call or a machine statement may have written any memory.
    memory: bool,
}

impl Written {
    fn record(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Assign { dest, .. } => {
                self.registers.insert(dest.index);
            }
            Stmt::Store { addr, width, .. } => self.stores.push((addr.clone(), *width)),
            Stmt::Call { .. } => {
                self.registers.extend(stmt.call_clobbers());
                self.registers
                    .extend(stmt.call_outputs().iter().map(|output| output.dest.index));
                self.memory = true;
            }
            Stmt::Machine { outputs, .. } => {
                self.registers
                    .extend(outputs.iter().map(|output| output.index));
                self.memory = true;
            }
            _ => {}
        }
    }

    /// Whether `expr` still has the value it had at the block's entry: it
    /// reads no register written since, and each load reads bytes no store
    /// since wrote. The registers of the addresses are unwritten, so a load
    /// and a store at constant offsets from one base compare by offset.
    fn keeps(&self, expr: &Expr) -> bool {
        let mut read = BTreeSet::new();
        registers_read(expr, &mut read);
        read.is_disjoint(&self.registers)
            && (!loads(expr)
                || (!self.memory
                    && self.stores.iter().all(|(addr, width)| {
                        crate::passes::memory::loads_avoid(expr, addr, *width)
                    })))
    }
}

pub(super) fn differences(
    old: &Expr,
    new: &Expr,
    written: &(Written, Written),
    found: &mut impl FnMut(Candidate),
) {
    if old == new {
        return;
    }
    if written.0.keeps(old)
        && written.1.keeps(new)
        && unmodeled(old).is_none()
        && unmodeled(new).is_none()
    {
        found((old.clone(), new.clone()));
    }
    let (old_children, new_children) = (
        crate::ir::visit::children(old),
        crate::ir::visit::children(new),
    );
    if std::mem::discriminant(old) == std::mem::discriminant(new)
        && old_children.len() == new_children.len()
    {
        for (a, b) in old_children.into_iter().zip(new_children) {
            differences(a, b, written, found);
        }
    }
}

pub(super) fn loads(expr: &Expr) -> bool {
    matches!(expr, Expr::Load { .. }) || crate::ir::visit::children(expr).into_iter().any(loads)
}

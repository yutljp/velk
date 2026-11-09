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

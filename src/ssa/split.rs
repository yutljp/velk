use super::{Phi, Ssa, build, dom, explicit_reads, lower_with, named, rename_reads};
use crate::ir::{Expr, FunctionIr, Stmt, VALUE_BASE};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy)]
enum UpdateScope {
    Locals,
    Parameters,
}

/// The values joined through φs: each set is one variable of the program.
/// A φ whose value nothing in `needed` reads joins nothing.
fn congruence_classes(ssa: &Ssa, needed: &HashSet<u16>, scope: UpdateScope) -> Vec<usize> {
    let mut parent: Vec<usize> = (0..ssa.origin.len()).collect();
    fn find(parent: &mut [usize], mut index: usize) -> usize {
        while parent[index] != index {
            parent[index] = parent[parent[index]];
            index = parent[index];
        }
        index
    }
    for phi in ssa.phis.iter().flatten() {
        if !needed.contains(&phi.value) {
            continue;
        }
        let value = usize::from(phi.value - VALUE_BASE);
        for arg in &phi.args {
            let (a, b) = (
                find(&mut parent, value),
                find(&mut parent, usize::from(arg - VALUE_BASE)),
            );
            parent[a] = b;
        }
    }
    // Intermediate updates of a loop-carried local belong to that local too,
    // including a value restored from a spill before the final increment.
    let mut joined_phi = vec![false; parent.len()];
    for phi in ssa.phis.iter().flatten() {
        if needed.contains(&phi.value) {
            let root = find(&mut parent, usize::from(phi.value - VALUE_BASE));
            joined_phi[root] = true;
        }
    }
    fn note_address(expr: &Expr, values: &mut HashSet<u16>) {
        match expr {
            Expr::Reg {
                index,
                width: 32 | 64,
            } => {
                values.insert(*index);
            }
            Expr::Bin {
                op: crate::ir::BinOp::Add | crate::ir::BinOp::Sub,
                lhs,
                rhs,
            } if matches!(rhs.as_ref(), Expr::Const(_)) => note_address(lhs, values),
            _ => {}
        }
    }
    fn memory_addresses(expr: &Expr, values: &mut HashSet<u16>) {
        if let Expr::Load { addr, .. } = expr {
            note_address(addr, values);
        }
        for child in crate::ir::visit::children(expr) {
            memory_addresses(child, values);
        }
    }
    let mut addresses = HashSet::new();
    for stmt in ssa.ir.blocks.iter().flat_map(|block| &block.stmts) {
        match stmt {
            Stmt::Store { addr, .. } => note_address(addr, &mut addresses),
            Stmt::Ret { value } if ssa.ir.ret_type.is_pointer() => {
                note_address(value, &mut addresses)
            }
            _ => {}
        }
        for operand in stmt.operands() {
            memory_addresses(operand, &mut addresses);
        }
    }
    let mut addressed = vec![false; parent.len()];
    for value in addresses {
        let root = find(&mut parent, usize::from(value - VALUE_BASE));
        addressed[root] = true;
    }
    let mut updates = Vec::new();
    for stmt in ssa.ir.blocks.iter().flat_map(|block| &block.stmts) {
        if let Stmt::Assign { dest, value } = stmt {
            let defined = usize::from(dest.index - VALUE_BASE);
            let origin = ssa.origin[defined];
            let parameter = ssa.ir.params.iter().find(|param| param.index == origin);
            if origin < crate::ir::VARIABLE_BASE
                && (matches!(scope, UpdateScope::Locals) || parameter.is_none())
            {
                continue;
            }
            let pointer = parameter.is_some_and(|param| param.ty.is_pointer())
                || ssa
                    .ir
                    .value_types
                    .get(&origin)
                    .is_some_and(crate::ir::CType::is_pointer)
                || ssa.ir.pointer_values.contains(&origin)
                || ssa
                    .ir
                    .structures
                    .iter()
                    .any(|structure| structure.elements.contains(&origin));
            let updated = dest.width >= crate::arch::pointer_bytes(ssa.ir.isa) * 8
                && match value {
                    Expr::Bin {
                        op: crate::ir::BinOp::And | crate::ir::BinOp::Or | crate::ir::BinOp::Xor,
                        ..
                    } => !pointer,
                    Expr::Bin {
                        op: crate::ir::BinOp::Add | crate::ir::BinOp::Sub,
                        lhs,
                        rhs,
                    } if pointer => {
                        matches!((lhs.as_ref(), rhs.as_ref()), (Expr::Reg { index, width }, Expr::Const(_)) if *width == dest.width && ssa.register_of(*index) == origin)
                    }
                    Expr::Bin { .. } if origin < crate::ir::VARIABLE_BASE && !pointer => true,
                    _ => false,
                };
            for read in explicit_reads(stmt) {
                let used = usize::from(read - VALUE_BASE);
                if origin == ssa.origin[used] {
                    updates.push((defined, used, pointer && updated));
                    let entry_update = origin >= crate::ir::VARIABLE_BASE
                        || pointer
                        || matches!(
                            value,
                            Expr::Bin {
                                op: crate::ir::BinOp::And
                                    | crate::ir::BinOp::Or
                                    | crate::ir::BinOp::Xor,
                                ..
                            }
                        )
                        || ssa.entry.get(&origin).is_some_and(|entry| {
                            find(&mut parent, usize::from(*entry - VALUE_BASE))
                                == find(&mut parent, used)
                        });
                    let address_update = !pointer || addressed[find(&mut parent, defined)];
                    if updated && entry_update && address_update {
                        let a = find(&mut parent, defined);
                        let b = find(&mut parent, used);
                        parent[b] = a;
                        joined_phi[a] |= joined_phi[b];
                        addressed[a] |= addressed[b];
                    }
                }
            }
        }
    }
    loop {
        let mut changed = false;
        for &(defined, used, pointer_update) in &updates {
            let a = find(&mut parent, defined);
            let b = find(&mut parent, used);
            if a != b && (joined_phi[a] || (pointer_update && addressed[a])) {
                parent[b] = a;
                joined_phi[a] |= joined_phi[b];
                addressed[a] |= addressed[b];
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    (0..parent.len())
        .map(|index| find(&mut parent, index))
        .collect()
}

/// The values of vector register halves that hold vector data rather than
/// a scalar float: a half loaded together with the other one from the next
/// eight bytes, one an integer lane operation reads or gives, an integer
/// sum or product, and one computed from those without floating-point
/// arithmetic.
fn vector_values(ssa: &Ssa) -> HashSet<u16> {
    let isa = ssa.ir.isa;
    let half = |value: u16| {
        Ssa::is_value(value) && crate::arch::vector_half(isa, ssa.register_of(value)).is_some()
    };
    let mut vectors = HashSet::new();
    let mut derived: Vec<(u16, HashSet<u16>)> = Vec::new();
    for block in &ssa.ir.blocks {
        for (position, stmt) in block.stmts.iter().enumerate() {
            if let Stmt::Assign { dest, value } = stmt
                && half(dest.index)
            {
                let mut lanes = false;
                let mut float = false;
                lane_operands(value, &mut lanes, &mut float, &mut vectors, &half);
                // Integer sums and products of halves are lane arithmetic too.
                if let Expr::Bin {
                    op: crate::ir::BinOp::Add | crate::ir::BinOp::Sub | crate::ir::BinOp::Mul,
                    lhs,
                    rhs,
                } = value
                {
                    lanes = true;
                    for operand in [lhs, rhs] {
                        if let Expr::Reg { index, .. } = operand.as_ref()
                            && half(*index)
                        {
                            vectors.insert(*index);
                        }
                    }
                }
                if lanes && !float {
                    vectors.insert(dest.index);
                }
                let expected = match crate::arch::vector_half(isa, ssa.register_of(dest.index)) {
                    Some(true) => -8,
                    _ => 8,
                };
                if let Expr::Load { addr, width: 8, .. } = value
                    && let Some(other) = [position.checked_sub(1), Some(position + 1)]
                        .into_iter()
                        .flatten()
                        .find_map(|at| match block.stmts.get(at) {
                            Some(Stmt::Assign {
                                dest: other,
                                value:
                                    Expr::Load {
                                        addr: other_addr,
                                        width: 8,
                                        ..
                                    },
                            }) if half(other.index)
                                && ssa.register_of(other.index) ^ 1
                                    == ssa.register_of(dest.index)
                                && apart(addr, other_addr) == Some(expected) =>
                            {
                                Some(other.index)
                            }
                            _ => None,
                        })
                {
                    vectors.insert(dest.index);
                    vectors.insert(other);
                }
                if !float {
                    let mut reads = HashSet::new();
                    named(value, &mut reads);
                    derived.push((dest.index, reads));
                }
            }
        }
    }
    loop {
        let before = vectors.len();
        for (value, reads) in &derived {
            if reads.iter().any(|read| vectors.contains(read)) {
                vectors.insert(*value);
            }
        }
        for phi in ssa.phis.iter().flatten() {
            if half(phi.value) && phi.args.iter().any(|arg| vectors.contains(arg)) {
                vectors.insert(phi.value);
            }
        }
        if vectors.len() == before {
            return vectors;
        }
    }
}

/// Notes whether `expr` holds an integer lane operation or floating-point
/// arithmetic, adding the vector halves a lane operation reads to `vectors`.
fn lane_operands(
    expr: &Expr,
    lanes: &mut bool,
    float: &mut bool,
    vectors: &mut HashSet<u16>,
    half: &dyn Fn(u16) -> bool,
) {
    use crate::ir::Operation;
    if let Expr::Apply { op, args } = expr {
        match op {
            Operation::Lanes(..)
            | Operation::InterleaveLow(_)
            | Operation::InterleaveHigh(_)
            | Operation::SignBits(_)
            | Operation::SumLanes(_)
            | Operation::Pack { .. }
            | Operation::MultiplyAddPairs
            | Operation::SumAbsoluteDifferences
            | Operation::SumLanesLong { .. } => {
                *lanes = true;
                for arg in args {
                    if let Expr::Reg { index, .. } = arg
                        && half(*index)
                    {
                        vectors.insert(*index);
                    }
                }
            }
            Operation::FloatAdd(_)
            | Operation::FloatSub(_)
            | Operation::FloatMul(_)
            | Operation::FloatDiv(_)
            | Operation::FloatSqrt(_)
            | Operation::FloatNegate(_)
            | Operation::FloatAbs(_)
            | Operation::FloatMulAdd(_)
            | Operation::FloatEqual(_)
            | Operation::FloatLess(_)
            | Operation::FloatLessEqual(_)
            | Operation::FloatUnordered(_)
            | Operation::IntToFloat { .. }
            | Operation::FloatToInt { .. }
            | Operation::FloatRound(..)
            | Operation::FloatConvert { .. } => *float = true,
            _ => {}
        }
    }
    for child in crate::ir::visit::children(expr) {
        lane_operands(child, lanes, float, vectors, half);
    }
}

/// How many bytes `high` lies past `low`, when both are the same base plus
/// constants.
fn apart(low: &Expr, high: &Expr) -> Option<i64> {
    fn split(addr: &Expr) -> (Option<&Expr>, i64) {
        match addr {
            Expr::Const(offset) => (None, *offset as i64),
            Expr::Bin {
                op: crate::ir::BinOp::Add,
                lhs,
                rhs,
            } => match rhs.as_ref() {
                Expr::Const(offset) => (Some(lhs), *offset as i64),
                _ => (Some(addr), 0),
            },
            _ => (Some(addr), 0),
        }
    }
    let (low_base, low_offset) = split(low);
    let (high_base, high_offset) = split(high);
    (low_base == high_base).then(|| high_offset.wrapping_sub(low_offset))
}

/// Gives each variable a register of `registers` holds once the value it
/// held on entry is dead a name of its own, from `VARIABLE_BASE` up. The
/// variable holding the entry value keeps the register, and so does one a
/// call reads or writes without naming it.
pub fn split_variables(ir: &mut FunctionIr, registers: &[u16]) {
    split(ir, registers, UpdateScope::Locals);
}

pub(crate) fn split_render_variables(ir: &mut FunctionIr, registers: &[u16]) {
    split(ir, registers, UpdateScope::Parameters);
}

fn split(ir: &mut FunctionIr, registers: &[u16], scope: UpdateScope) {
    // An unknown successor could read any register.
    if ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .any(|stmt| matches!(stmt, Stmt::BrIndirect { .. } | Stmt::Br { target: None }))
    {
        return;
    }
    let Some(ssa) = build(ir) else {
        return;
    };
    let mut needed: HashSet<u16> = HashSet::new();
    for stmt in ssa.ir.blocks.iter().flat_map(|block| &block.stmts) {
        needed.extend(explicit_reads(stmt));
    }
    // A value a statement reads without naming it must be in its register,
    // but for vector data a call of unknown floating-point arguments could
    // only take as a scalar one, and for a value the code computes with in
    // a register a call reads unnamed besides its arguments, AArch64's
    // indirect result register or SysV's vector count: that is scratch the
    // call passes by.
    let vectors = vector_values(&ssa);
    let mut implicit: HashSet<u16> = HashSet::new();
    for (&(block, position), reads) in &ssa.implicit_reads {
        let stmt = &ssa.ir.blocks[block].stmts[position];
        let preserved = stmt.preserved_output_sources();
        let (floats, extra) = match stmt {
            Stmt::Call { convention, .. } => {
                (convention.float_arguments(), convention.call_extra())
            }
            _ => (&[][..], &[][..]),
        };
        implicit.extend(
            reads
                .iter()
                .filter(|(register, value)| {
                    stmt.declared_call_reads().contains(register)
                        || preserved.iter().any(|(_, source)| source == register)
                        || (!(floats.contains(register) && vectors.contains(value))
                            && !(extra.contains(register) && needed.contains(value)))
                })
                .map(|(_, value)| *value),
        );
    }
    needed.extend(&implicit);
    // A φ only such a call reads joins nothing, so the vector data and what
    // the register held before it can be variables apart.
    let mut pending: Vec<u16> = needed.iter().copied().collect();
    let phi_of: HashMap<u16, &Phi> = ssa
        .phis
        .iter()
        .flatten()
        .map(|phi| (phi.value, phi))
        .collect();
    while let Some(value) = pending.pop() {
        for arg in phi_of
            .get(&value)
            .map(|phi| &phi.args)
            .into_iter()
            .flatten()
        {
            if needed.insert(*arg) {
                pending.push(*arg);
            }
        }
    }
    let class = congruence_classes(&ssa, &needed, scope);
    let mut kept: HashSet<usize> = ssa
        .entry
        .values()
        .chain(&implicit)
        .chain(phi_of.keys().filter(|value| !needed.contains(value)))
        .map(|value| class[usize::from(value - VALUE_BASE)])
        .collect();
    // One a call defines, such as its result, moves into its variable
    // right after the call, when anything reads it.
    let mut read: HashSet<usize> = HashSet::new();
    for stmt in ssa.ir.blocks.iter().flat_map(|block| &block.stmts) {
        for value in explicit_reads(stmt) {
            if Ssa::is_value(value) {
                read.insert(class[usize::from(value - VALUE_BASE)]);
            }
        }
    }
    for arg in ssa.phis.iter().flatten().flat_map(|phi| &phi.args) {
        read.insert(class[usize::from(arg - VALUE_BASE)]);
    }
    for defined in ssa.implicit_writes.values() {
        for (_, value) in defined {
            let root = class[usize::from(value - VALUE_BASE)];
            kept.insert(root);
        }
    }
    for output in ssa
        .ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .flat_map(Stmt::call_outputs)
    {
        let root = class[usize::from(output.dest.index - VALUE_BASE)];
        if !read.contains(&root)
            || (matches!(scope, UpdateScope::Parameters)
                && ssa.origin[root] < crate::ir::VARIABLE_BASE)
        {
            kept.insert(root);
        }
    }
    // Code no path reaches keeps its registers.
    let dominators = dom::dominators(&ssa.successors);
    for (block, contents) in ssa.ir.blocks.iter().enumerate() {
        if block == 0 || dominators.idom[block].is_some() {
            continue;
        }
        for stmt in &contents.stmts {
            let mut stmt = stmt.clone();
            for dest in crate::ir::visit::statement_destinations_mut(&mut stmt) {
                kept.insert(class[usize::from(dest.index - VALUE_BASE)]);
            }
        }
    }
    // Number the new variables in the order their first definitions appear
    // in the code, a φ before the statements of its block and a call's
    // results in the order the convention returns them.
    let mut first: HashMap<usize, (usize, usize, u16)> = HashMap::new();
    let mut note = |value: u16, at: (usize, usize, u16)| {
        let root = class[usize::from(value - VALUE_BASE)];
        let entry = first.entry(root).or_insert(at);
        *entry = (*entry).min(at);
    };
    for (block, list) in ssa.phis.iter().enumerate() {
        for phi in list {
            note(phi.value, (block, 0, 0));
        }
    }
    for (block, contents) in ssa.ir.blocks.iter().enumerate() {
        for (position, stmt) in contents.stmts.iter().enumerate() {
            if let Stmt::Assign { dest, .. } = stmt {
                note(dest.index, (block, position + 1, 0));
            }
            for (rank, output) in stmt.call_outputs().iter().enumerate() {
                note(output.dest.index, (block, position + 1, rank as u16));
            }
            for (register, value) in ssa
                .implicit_writes
                .get(&(block, position))
                .into_iter()
                .flatten()
            {
                note(*value, (block, position + 1, *register));
            }
        }
    }
    // An already named local keeps its first defined web. Entry-only reads in
    // disconnected handler blocks must still see the assignment under that name.
    let mut existing: HashSet<u16> = needed
        .iter()
        .map(|value| class[usize::from(*value - VALUE_BASE)])
        .filter(|root| kept.contains(root) && first.contains_key(root))
        .map(|root| ssa.origin[root])
        .collect();
    let mut order: Vec<(usize, (usize, usize, u16))> = first
        .into_iter()
        .filter(|(root, _)| registers.contains(&ssa.origin[*root]) && !kept.contains(root))
        .collect();
    order.sort_by_key(|(root, at)| (*at, *root));
    order.retain(|(root, _)| {
        let origin = ssa.origin[*root];
        !ir.variable_registers.contains_key(&origin) || !existing.insert(origin)
    });
    let next = ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .flat_map(|stmt| {
            let (writes, reads) = crate::ir::visit::statement_registers(stmt);
            writes.into_iter().chain(reads)
        })
        .chain(ir.variable_registers.keys().copied())
        .filter(|index| (crate::ir::VARIABLE_BASE..VALUE_BASE).contains(index))
        .max()
        .map_or(crate::ir::VARIABLE_BASE, |index| index.saturating_add(1));
    if order.len() > usize::from(VALUE_BASE.saturating_sub(next)) {
        return;
    }
    let names: HashMap<usize, u16> = order
        .into_iter()
        .enumerate()
        .map(|(index, (root, _))| (root, next + index as u16))
        .collect();
    if names.is_empty() {
        return;
    }
    let origins: Vec<(u16, u16)> = names
        .iter()
        .map(|(root, name)| {
            let origin = ssa.origin[*root];
            (
                *name,
                ir.variable_registers
                    .get(&origin)
                    .copied()
                    .unwrap_or(origin),
            )
        })
        .collect();
    let renames: HashMap<u16, u16> = (0..ssa.origin.len())
        .filter_map(|index| {
            names
                .get(&class[index])
                .map(|name| (VALUE_BASE + index as u16, *name))
        })
        .collect();
    let mut lowered = lower_with(&ssa, &renames);
    // Code no path reaches, as a landing pad the unwinder enters, finds a
    // callee-saved register holding what it held across the calls: the
    // variable the register holds at every call, when that is one.
    let clobbered = ir.convention.clobbered();
    for register in registers.iter().filter(|register| {
        crate::arch::machine_registers().contains(register) && !clobbered.contains(register)
    }) {
        let held: HashSet<u16> = names
            .iter()
            .filter(|(root, _)| ssa.origin[**root] == *register)
            .map(|(_, name)| *name)
            .collect();
        let Some(variable) = held_across_calls(&lowered, &held, &dominators) else {
            continue;
        };
        for (block, contents) in lowered.blocks.iter_mut().enumerate() {
            if block == 0 || dominators.idom[block].is_some() {
                continue;
            }
            for stmt in &mut contents.stmts {
                rename_reads(stmt, &mut |index| {
                    if index == *register { variable } else { index }
                });
                if crate::ir::visit::statement_registers(stmt)
                    .0
                    .contains(register)
                {
                    break;
                }
            }
        }
    }
    *ir = lowered;
    ir.variable_registers.extend(origins);
}

/// The one variable of `held` that every call the entry reaches finds in
/// the register they share, following the writes of them forward. A tail
/// call has left the frame, so no landing pad of it can be entered.
fn held_across_calls(
    ir: &FunctionIr,
    held: &HashSet<u16>,
    dominators: &dom::Dominators,
) -> Option<u16> {
    if held.is_empty() {
        return None;
    }
    // Per block on entry: the variable in the register, `Some(None)` when
    // paths disagree or none was written.
    let mut entry: Vec<Option<Option<u16>>> = vec![None; ir.blocks.len()];
    entry[0] = Some(None);
    let mut work = vec![0];
    let merge = |before, current| match before {
        None => current,
        Some(old) if old == current => current,
        Some(_) => None,
    };
    let mut seen: Option<Option<u16>> = None;
    while let Some(index) = work.pop() {
        let mut current = entry[index].expect("visited");
        let stmts = &ir.blocks[index].stmts;
        for (position, stmt) in stmts.iter().enumerate() {
            match stmt {
                Stmt::Assign { dest, .. } if held.contains(&dest.index) => {
                    current = Some(dest.index);
                }
                Stmt::Call { .. } if matches!(stmts.get(position + 1), Some(Stmt::Ret { .. })) => {}
                Stmt::Call { .. } => {
                    seen = Some(merge(seen, current));
                }
                _ => {}
            }
        }
        for next in crate::ir::cfg::block_successors(&ir.blocks, index) {
            if dominators.idom[next].is_none() && next != 0 {
                continue;
            }
            let merged = merge(entry[next], current);
            if entry[next] != Some(merged) {
                entry[next] = Some(merged);
                work.push(next);
            }
        }
    }
    seen.flatten()
}

#[cfg(test)]
mod split_tests {
    use super::split_variables;
    use crate::ir::VARIABLE_BASE;
    use crate::ir::{BinOp, Block, CType, Cond, Expr, FunctionIr, Param, RegRef, Stmt};
    use crate::loader::Isa;

    const RSI: u16 = 6;

    fn function(blocks: Vec<Vec<Stmt>>) -> FunctionIr {
        let mut ir = FunctionIr::single_block(Isa::X86_64, Vec::new());
        ir.blocks = blocks
            .into_iter()
            .enumerate()
            .map(|(index, stmts)| Block {
                start: 0x10 * index as u64,
                stmts,
            })
            .collect();
        ir.params = vec![Param {
            index: RSI,
            name: "n".to_owned(),
            ty: CType::U64,
        }];
        ir
    }

    fn assign(index: u16, value: Expr) -> Stmt {
        Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
        }
    }

    fn counting_loop(start: Stmt) -> FunctionIr {
        let rsi = Expr::reg(RSI, 64);
        function(vec![
            vec![assign(0, rsi.clone()), start],
            vec![
                assign(RSI, Expr::bin(BinOp::Add, rsi.clone(), Expr::Const(1))),
                Stmt::Brif {
                    cond: Cond::Ne,
                    lhs: rsi.clone(),
                    rhs: Expr::reg(0, 64),
                    target: 0x10,
                },
            ],
            vec![Stmt::Ret { value: rsi }],
        ])
    }

    #[test]
    fn a_counter_reusing_a_dead_parameter_is_a_variable_of_its_own() {
        let mut ir = counting_loop(assign(RSI, Expr::Const(0)));
        split_variables(&mut ir, &[RSI]);
        let variable = Expr::reg(VARIABLE_BASE, 64);
        assert!(
            matches!(&ir.blocks[0].stmts[0], Stmt::Assign { value, .. } if *value == Expr::reg(RSI, 64))
        );
        assert!(
            matches!(&ir.blocks[0].stmts[1], Stmt::Assign { dest, .. } if dest.index == VARIABLE_BASE)
        );
        assert!(
            matches!(&ir.blocks[2].stmts[0], Stmt::Ret { value } if *value == variable),
            "{}",
            ir.render()
        );
    }

    #[test]
    fn a_named_local_splits_again_when_its_phi_is_gone() {
        let variable = VARIABLE_BASE;
        let mut ir = function(vec![vec![
            assign(variable, Expr::Const(7)),
            Stmt::Store {
                addr: Expr::reg(RSI, 64),
                value: Expr::reg(variable, 64),
                width: 8,
            },
            assign(
                variable,
                Expr::bin(BinOp::Add, Expr::reg(RSI, 64), Expr::Const(8)),
            ),
            Stmt::Ret {
                value: Expr::Load {
                    addr: Box::new(Expr::reg(variable, 64)),
                    width: 1,
                    signed: false,
                },
            },
        ]]);
        ir.variable_registers.insert(variable, 0);
        split_variables(&mut ir, &[variable]);
        assert!(
            matches!(&ir.blocks[0].stmts[0], Stmt::Assign { dest, .. } if dest.index == variable)
        );
        assert!(
            matches!(&ir.blocks[0].stmts[2], Stmt::Assign { dest, .. } if dest.index == variable + 1)
        );
        assert_eq!(ir.variable_registers.get(&(variable + 1)), Some(&0));
        let text = crate::render::render(&ir, &[], &Default::default(), &[]);
        assert!(text.contains("v1 = 7;"), "{text}");
        assert!(text.contains("*v2"), "{text}");
        let before = ir.render();
        split_variables(&mut ir, &[variable, variable + 1]);
        assert_eq!(ir.render(), before);
    }

    #[test]
    fn disconnected_reads_keep_the_first_defined_local_name() {
        let variable = VARIABLE_BASE;
        let mut ir = function(vec![
            vec![
                assign(variable, Expr::Const(7)),
                Stmt::Ret {
                    value: Expr::reg(variable, 64),
                },
            ],
            vec![Stmt::Ret {
                value: Expr::reg(variable, 64),
            }],
        ]);
        ir.variable_registers.insert(variable, 0);
        let before = ir.render();
        super::split_render_variables(&mut ir, &[variable]);
        assert_eq!(ir.render(), before);
    }

    #[test]
    fn a_parameter_the_loop_updates_keeps_its_register() {
        // The loop starts from the parameter itself.
        let mut ir = counting_loop(assign(1, Expr::Const(0)));
        let before = ir.render();
        split_variables(&mut ir, &[RSI]);
        assert_eq!(ir.render(), before);
    }

    /// Copies eight or sixteen bytes from rdi to rsi through xmm0, then calls
    /// through rax, which may take floating-point arguments.
    fn copy_through_xmm0(both_halves: bool) -> FunctionIr {
        const XMM0: u16 = 18;
        let at = |base: u16, offset: u64| {
            Expr::bin(BinOp::Add, Expr::reg(base, 64), Expr::Const(offset))
        };
        let load = |addr: Expr| Expr::Load {
            addr: Box::new(addr),
            width: 8,
            signed: false,
        };
        let store = |value: Expr, addr: Expr| Stmt::Store {
            addr,
            value,
            width: 8,
        };
        let mut stmts = vec![assign(XMM0, load(Expr::reg(7, 64)))];
        if both_halves {
            stmts.push(assign(XMM0 + 1, load(at(7, 8))));
        }
        stmts.push(store(Expr::reg(XMM0, 64), Expr::reg(RSI, 64)));
        if both_halves {
            stmts.push(store(Expr::reg(XMM0 + 1, 64), at(RSI, 8)));
        }
        stmts.push(Stmt::Call {
            kind: crate::ir::CallKind::Invoke,
            target: None,
            through: Some(Expr::reg(0, 64)),
            convention: crate::ir::Convention::SysV,
            args: None,
            floats_named: false,
            abi: None,
            clobbers: None,
            outputs: crate::ir::fallback_call_outputs(crate::ir::Convention::SysV, None),
            via: None,
        });
        stmts.push(Stmt::Ret {
            value: Expr::Const(0),
        });
        let mut ir = function(vec![stmts]);
        split_variables(&mut ir, &[XMM0, XMM0 + 1]);
        ir
    }

    #[test]
    fn sixteen_bytes_copied_through_a_vector_register_are_no_float_argument() {
        let ir = copy_through_xmm0(true);
        assert!(
            matches!(&ir.blocks[0].stmts[0], Stmt::Assign { dest, .. } if dest.index >= VARIABLE_BASE),
            "{}",
            ir.render()
        );
    }

    #[test]
    fn a_scalar_loaded_into_a_float_argument_register_stays_there() {
        let ir = copy_through_xmm0(false);
        assert!(
            matches!(&ir.blocks[0].stmts[0], Stmt::Assign { dest, .. } if dest.index == 18),
            "{}",
            ir.render()
        );
    }
}

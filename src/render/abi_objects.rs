use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::ir::{BinOp, CType, Expr, FunctionIr, Param, Stmt};

#[derive(Clone, Copy)]
pub(super) enum Source {
    Register(u16),
    Stack(i64),
}

pub(super) struct Object {
    pub name: String,
    pub size: u64,
    pub source: Source,
    pub output: bool,
    pub defined_bits: Vec<(u64, u64)>,
}

pub(super) struct Binding {
    pub register: u16,
    pub name: String,
    pub object: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Origin {
    Object(usize, i64),
    Stack(i64),
    Unknown,
}

type State = BTreeMap<u16, Origin>;

pub(super) fn prepare(ir: &mut FunctionIr, objects: &[Object]) -> Option<Vec<Binding>> {
    if objects.is_empty() {
        return Some(Vec::new());
    }
    let mut prepared = ir.clone();
    let bindings = prepare_inner(&mut prepared, objects)?;
    *ir = prepared;
    Some(bindings)
}

fn prepare_inner(ir: &mut FunctionIr, objects: &[Object]) -> Option<Vec<Binding>> {
    if ir.blocks.is_empty() || !ir.landing_pads.is_empty() {
        return None;
    }
    let sp = crate::arch::stack_pointer(ir.isa);
    let mut entry = State::new();
    entry.insert(sp, Origin::Stack(0));
    for (index, object) in objects.iter().enumerate() {
        if object.size == 0 || object.size > i64::MAX as u64 {
            return None;
        }
        if let Source::Register(register) = object.source
            && (register == sp || entry.insert(register, Origin::Object(index, 0)).is_some())
        {
            return None;
        }
        if let Source::Stack(offset) = object.source {
            let end = offset.checked_add(object.size as i64)?;
            if objects[..index].iter().any(|other| match other.source {
                Source::Stack(start) => {
                    start < end && offset < start.saturating_add(other.size as i64)
                }
                Source::Register(_) => false,
            }) {
                return None;
            }
        }
    }
    for (variable, register) in &ir.variable_registers {
        if entry.contains_key(register) && !entry.contains_key(variable) {
            entry.insert(*variable, Origin::Unknown);
        }
    }
    let entries = block_entries(ir, &entry)?;
    initialized_objects(ir, objects, &entries, &entry)?;
    let mut used: BTreeSet<u16> = ir.params.iter().map(|param| param.index).collect();
    used.extend(ir.variable_registers.keys());
    used.extend(ir.variable_registers.values());
    used.extend(ir.value_types.keys());
    let mut names: BTreeSet<String> = ir.params.iter().map(|param| param.name.clone()).collect();
    names.extend(ir.stack_params.iter().map(|param| param.name.clone()));
    names.extend(objects.iter().map(|object| object.name.clone()));
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        let (writes, reads) = crate::ir::visit::statement_registers(stmt);
        used.extend(writes);
        used.extend(reads);
    }
    let mut next = used
        .last()
        .copied()
        .unwrap_or(crate::ir::VARIABLE_BASE)
        .max(crate::ir::VARIABLE_BASE);
    let mut bindings = Vec::new();
    for object in objects {
        next = next.checked_add(1)?;
        let base = format!("{}_address", object.name);
        let mut name = base.clone();
        let mut suffix = 1;
        while names.contains(&name) {
            name = format!("{base}_{suffix}");
            suffix += 1;
        }
        names.insert(name.clone());
        bindings.push(Binding {
            register: next,
            name,
            object: object.name.clone(),
        });
    }
    for (index, block) in ir.blocks.iter_mut().enumerate() {
        let mut state = entries[index].clone().unwrap_or_else(|| entry.clone());
        let mut stmts = Vec::new();
        for mut stmt in std::mem::take(&mut block.stmts) {
            let remove = rewrite_statement(&mut stmt, &state, sp, objects, &bindings)?;
            transfer(&stmt, &mut state);
            if !remove {
                stmts.push(stmt);
            }
        }
        block.stmts = stmts;
    }
    ir.params.retain(|param| {
        !objects
            .iter()
            .any(|object| matches!(object.source, Source::Register(index) if index == param.index))
    });
    ir.params.extend(bindings.iter().map(|binding| Param {
        index: binding.register,
        name: binding.name.clone(),
        ty: CType::pointer_to(CType::int(1, false)),
    }));
    Some(bindings)
}

fn block_entries(ir: &FunctionIr, entry: &State) -> Option<Vec<Option<State>>> {
    let mut entries = vec![None; ir.blocks.len()];
    entries[0] = Some(entry.clone());
    let mut pending = VecDeque::from([0]);
    while let Some(index) = pending.pop_front() {
        let mut state = entries[index].clone()?;
        for stmt in &ir.blocks[index].stmts {
            if matches!(
                stmt,
                Stmt::Call { .. }
                    | Stmt::Unsupported { .. }
                    | Stmt::BrIndirect { .. }
                    | Stmt::Br { target: None }
            ) {
                return None;
            }
            transfer(stmt, &mut state);
        }
        for successor in crate::ir::cfg::successors(ir, index) {
            let changed = match &mut entries[successor] {
                None => {
                    entries[successor] = Some(state.clone());
                    true
                }
                Some(existing) => {
                    let keys: BTreeSet<u16> =
                        existing.keys().chain(state.keys()).copied().collect();
                    let mut changed = false;
                    for key in keys {
                        if existing.get(&key) != state.get(&key)
                            && existing.get(&key) != Some(&Origin::Unknown)
                        {
                            existing.insert(key, Origin::Unknown);
                            changed = true;
                        }
                    }
                    changed
                }
            };
            if changed && !pending.contains(&successor) {
                pending.push_back(successor);
            }
        }
    }
    Some(entries)
}

fn transfer(stmt: &Stmt, state: &mut State) {
    if let Stmt::Assign { dest, value } = stmt {
        let value = if dest.width == 64 {
            origin(value, state)
        } else if contains_origin(value, state) {
            Some(Origin::Unknown)
        } else {
            None
        };
        match value {
            Some(value) => {
                state.insert(dest.index, value);
            }
            None => {
                state.remove(&dest.index);
            }
        }
    }
}

fn origin(expr: &Expr, state: &State) -> Option<Origin> {
    match expr {
        Expr::Reg { index, width: 64 } => state.get(index).copied(),
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (value, Expr::Const(offset)) | (Expr::Const(offset), value) => {
                offset_origin(origin(value, state)?, *offset as i64)
            }
            _ => None,
        },
        Expr::Bin {
            op: BinOp::Sub,
            lhs,
            rhs,
        } => match rhs.as_ref() {
            Expr::Const(offset) => {
                offset_origin(origin(lhs, state)?, (*offset as i64).checked_neg()?)
            }
            _ => None,
        },
        _ => None,
    }
}

fn offset_origin(value: Origin, offset: i64) -> Option<Origin> {
    Some(match value {
        Origin::Object(object, base) => Origin::Object(object, base.checked_add(offset)?),
        Origin::Stack(base) => Origin::Stack(base.checked_add(offset)?),
        Origin::Unknown => Origin::Unknown,
    })
}

fn contains_origin(expr: &Expr, state: &State) -> bool {
    match expr {
        Expr::Reg { index, .. } => state.contains_key(index),
        _ => crate::ir::visit::children(expr)
            .into_iter()
            .any(|child| contains_origin(child, state)),
    }
}

fn rewrite_statement(
    stmt: &mut Stmt,
    state: &State,
    sp: u16,
    objects: &[Object],
    bindings: &[Binding],
) -> Option<bool> {
    match stmt {
        Stmt::Assign { dest, value } => {
            if let Some(address) = origin(value, state) {
                if dest.width != 64 || address == Origin::Unknown {
                    return None;
                }
                if dest.index == sp {
                    return matches!(address, Origin::Stack(_)).then_some(false);
                }
                return Some(true);
            }
            rewrite_value(value, state, sp, objects, bindings)?;
        }
        Stmt::Store { addr, value, width } => {
            rewrite_address(addr, *width, state, sp, objects, bindings)?;
            rewrite_value(value, state, sp, objects, bindings)?;
        }
        Stmt::Ret { value } => {
            if let Some(Origin::Object(index, 0)) = origin(value, state)
                && objects[index].output
            {
                *value = Expr::Const(0);
            } else {
                rewrite_value(value, state, sp, objects, bindings)?;
            }
        }
        Stmt::Call { .. }
        | Stmt::Unsupported { .. }
        | Stmt::BrIndirect { .. }
        | Stmt::Br { target: None } => return None,
        _ => {
            for value in stmt.operands_mut() {
                rewrite_value(value, state, sp, objects, bindings)?;
            }
        }
    }
    Some(false)
}

fn rewrite_value(
    expr: &mut Expr,
    state: &State,
    sp: u16,
    objects: &[Object],
    bindings: &[Binding],
) -> Option<()> {
    if let Expr::Load { addr, width, .. } = expr {
        return rewrite_address(addr, *width, state, sp, objects, bindings);
    }
    if let Expr::Reg { index, .. } = expr
        && state.contains_key(index)
    {
        return None;
    }
    for child in crate::ir::visit::children_mut(expr) {
        rewrite_value(child, state, sp, objects, bindings)?;
    }
    Some(())
}

fn rewrite_address(
    expr: &mut Expr,
    width: u8,
    state: &State,
    sp: u16,
    objects: &[Object],
    bindings: &[Binding],
) -> Option<()> {
    if let Some((index, offset)) = object_access(expr, width, state, objects)? {
        *expr = address_at(bindings[index].register, offset as i64);
        return Some(());
    }
    match origin(expr, state) {
        Some(Origin::Stack(offset)) => {
            let Origin::Stack(frame) = state.get(&sp)? else {
                return None;
            };
            *expr = address_at(sp, offset.checked_sub(*frame)?);
            Some(())
        }
        None => rewrite_value(expr, state, sp, objects, bindings),
        _ => None,
    }
}

fn address_at(register: u16, offset: i64) -> Expr {
    if offset == 0 {
        Expr::reg(register, 64)
    } else {
        Expr::bin(
            BinOp::Add,
            Expr::reg(register, 64),
            Expr::Const(offset as u64),
        )
    }
}

type Written = Vec<Vec<(u64, u64)>>;

fn initialized_objects(
    ir: &FunctionIr,
    objects: &[Object],
    origins: &[Option<State>],
    entry: &State,
) -> Option<()> {
    for object in objects {
        let bits = object.size.checked_mul(8)?;
        let mut end = 0;
        for &(offset, count) in &object.defined_bits {
            if count == 0 || offset < end {
                return None;
            }
            end = offset.checked_add(count)?;
            if end > bits {
                return None;
            }
        }
    }
    let empty = vec![Vec::new(); objects.len()];
    let mut entries: Vec<Option<Written>> = vec![None; ir.blocks.len()];
    entries[0] = Some(empty.clone());
    let mut pending = VecDeque::from([0]);
    while let Some(index) = pending.pop_front() {
        let mut written = entries[index].clone()?;
        let mut state = origins[index].clone()?;
        for stmt in &ir.blocks[index].stmts {
            record_store(stmt, &state, objects, &mut written)?;
            transfer(stmt, &mut state);
        }
        for successor in crate::ir::cfg::successors(ir, index) {
            let next = match &entries[successor] {
                None => written.clone(),
                Some(previous) => previous
                    .iter()
                    .zip(&written)
                    .map(|(left, right)| intersection(left, right))
                    .collect(),
            };
            if entries[successor].as_ref() != Some(&next) {
                entries[successor] = Some(next);
                if !pending.contains(&successor) {
                    pending.push_back(successor);
                }
            }
        }
    }
    for (index, block) in ir.blocks.iter().enumerate() {
        let mut state = origins[index].clone().unwrap_or_else(|| entry.clone());
        let mut written = entries[index].clone().unwrap_or_else(|| empty.clone());
        for stmt in &block.stmts {
            for value in stmt.operands() {
                initialized_loads(value, &state, objects, &written)?;
            }
            if matches!(stmt, Stmt::Ret { .. }) {
                for (index, object) in objects
                    .iter()
                    .enumerate()
                    .filter(|(_, object)| object.output)
                {
                    if object
                        .defined_bits
                        .iter()
                        .any(|&(offset, count)| !covered(&written[index], offset, count))
                    {
                        return None;
                    }
                }
            }
            record_store(stmt, &state, objects, &mut written)?;
            transfer(stmt, &mut state);
        }
    }
    Some(())
}

fn initialized_loads(
    expr: &Expr,
    state: &State,
    objects: &[Object],
    written: &Written,
) -> Option<()> {
    if let Expr::Load { addr, width, .. } = expr
        && let Some((index, offset)) = object_access(addr, *width, state, objects)?
    {
        let offset = offset.checked_mul(8)?;
        let count = u64::from(*width) * 8;
        let object = &objects[index];
        let ranges = if object.output {
            &written[index]
        } else {
            &object.defined_bits
        };
        if !covered(ranges, offset, count) {
            return None;
        }
    }
    for child in crate::ir::visit::children(expr) {
        initialized_loads(child, state, objects, written)?;
    }
    Some(())
}

fn record_store(
    stmt: &Stmt,
    state: &State,
    objects: &[Object],
    written: &mut Written,
) -> Option<()> {
    if let Stmt::Store { addr, width, .. } = stmt
        && let Some((index, offset)) = object_access(addr, *width, state, objects)?
        && objects[index].output
    {
        let start = offset.checked_mul(8)?;
        let end = start.checked_add(u64::from(*width) * 8)?;
        let ranges = &mut written[index];
        ranges.push((start, end - start));
        ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for &(offset, count) in ranges.iter() {
            if let Some((previous, length)) = merged.last_mut()
                && offset <= *previous + *length
            {
                *length = (*previous + *length).max(offset + count) - *previous;
            } else {
                merged.push((offset, count));
            }
        }
        *ranges = merged;
    }
    Some(())
}

fn covered(ranges: &[(u64, u64)], offset: u64, count: u64) -> bool {
    let Some(end) = offset.checked_add(count) else {
        return false;
    };
    let mut reached = offset;
    for &(start, count) in ranges {
        if start > reached {
            break;
        }
        reached = reached.max(start.saturating_add(count));
        if reached >= end {
            return true;
        }
    }
    false
}

fn intersection(left: &[(u64, u64)], right: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut common = Vec::new();
    for &(a, length_a) in left {
        for &(b, length_b) in right {
            let start = a.max(b);
            let end = (a + length_a).min(b + length_b);
            if start < end {
                common.push((start, end - start));
            }
        }
    }
    common
}

fn object_access(
    expr: &Expr,
    width: u8,
    state: &State,
    objects: &[Object],
) -> Option<Option<(usize, u64)>> {
    let (index, offset) = match origin(expr, state) {
        Some(Origin::Object(index, offset)) => (index, offset),
        Some(Origin::Stack(offset)) => {
            let end = offset.checked_add(i64::from(width))?;
            let mut found = None;
            for (index, object) in objects.iter().enumerate() {
                if let Source::Stack(start) = object.source
                    && start < end
                    && offset < start.checked_add(object.size as i64)?
                {
                    if found.is_some() {
                        return None;
                    }
                    found = Some((index, offset.checked_sub(start)?));
                }
            }
            let Some(found) = found else {
                return Some(None);
            };
            found
        }
        Some(Origin::Unknown) => return None,
        None => return Some(None),
    };
    if !matches!(width, 1 | 2 | 4 | 8)
        || offset < 0
        || (offset as u64).checked_add(u64::from(width))? > objects[index].size
    {
        return None;
    }
    Some(Some((index, offset as u64)))
}

#[cfg(test)]
mod tests {
    use super::{Object, Source, prepare};
    use crate::ir::{BinOp, Block, Expr, FunctionIr, RegRef, Stmt, VARIABLE_BASE};
    use crate::loader::Isa;

    fn object(source: Source) -> Object {
        Object {
            name: "value".to_owned(),
            size: 32,
            source,
            output: false,
            defined_bits: vec![(0, 256)],
        }
    }

    fn assign(index: u16, value: Expr) -> Stmt {
        Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
        }
    }

    fn at(index: u16, offset: i64) -> Expr {
        Expr::bin(BinOp::Add, Expr::reg(index, 64), Expr::Const(offset as u64))
    }

    fn load(index: u16, offset: i64) -> Expr {
        Expr::Load {
            addr: Box::new(at(index, offset)),
            width: 8,
            signed: false,
        }
    }

    #[test]
    fn indirect_addresses_use_the_copied_object_after_register_reuse() {
        let alias = VARIABLE_BASE;
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                assign(alias, at(0, 8)),
                assign(0, Expr::Const(7)),
                Stmt::Ret {
                    value: Expr::bin(BinOp::Add, load(alias, 8), Expr::reg(0, 64)),
                },
            ],
        );
        ir.variable_registers.insert(alias, 0);
        let bindings = prepare(&mut ir, &[object(Source::Register(0))]).unwrap();
        assert_eq!(ir.blocks[0].stmts.len(), 2);
        let Stmt::Ret {
            value: Expr::Bin { lhs, rhs, .. },
        } = &ir.blocks[0].stmts[1]
        else {
            panic!("{}", ir.render());
        };
        assert_eq!(lhs.as_ref(), &load(bindings[0].register, 16));
        assert_eq!(rhs.as_ref(), &Expr::reg(0, 64));
    }

    #[test]
    fn stack_object_aliases_keep_entry_offsets_across_stack_adjustments() {
        let sp = crate::arch::stack_pointer(Isa::X86_64);
        let alias = VARIABLE_BASE;
        let mut ir = FunctionIr::single_block(
            Isa::X86_64,
            vec![
                assign(alias, at(sp, 8)),
                assign(sp, at(sp, -16)),
                Stmt::Store {
                    addr: at(sp, 0),
                    value: Expr::Const(9),
                    width: 8,
                },
                Stmt::Ret {
                    value: load(alias, 24),
                },
            ],
        );
        let bindings = prepare(&mut ir, &[object(Source::Stack(8))]).unwrap();
        assert_eq!(ir.blocks[0].stmts.len(), 3);
        let Stmt::Store { addr, .. } = &ir.blocks[0].stmts[1] else {
            panic!("{}", ir.render());
        };
        assert_eq!(addr, &Expr::reg(sp, 64));
        let Stmt::Ret { value } = &ir.blocks[0].stmts[2] else {
            panic!("{}", ir.render());
        };
        assert_eq!(value, &load(bindings[0].register, 24));
    }

    #[test]
    fn pointer_values_and_out_of_bounds_accesses_reject_transactionally() {
        for value in [
            Expr::reg(0, 64),
            Expr::bin(BinOp::And, Expr::reg(0, 64), Expr::Const(255)),
            load(0, 25),
            load(0, -1),
        ] {
            let mut ir = FunctionIr::single_block(Isa::AArch64, vec![Stmt::Ret { value }]);
            let before = ir.render();
            assert!(prepare(&mut ir, &[object(Source::Register(0))]).is_none());
            assert_eq!(ir.render(), before);
            assert!(ir.params.is_empty());
        }
    }

    #[test]
    fn pointer_stores_and_partial_pointer_copies_are_rejected() {
        let cases = [
            vec![Stmt::Store {
                addr: Expr::Const(0x1000),
                value: Expr::reg(0, 64),
                width: 8,
            }],
            vec![Stmt::Assign {
                dest: RegRef {
                    index: VARIABLE_BASE,
                    width: 32,
                },
                value: Expr::reg(0, 32),
            }],
        ];
        for stmts in cases {
            let mut ir = FunctionIr::single_block(Isa::AArch64, stmts);
            assert!(prepare(&mut ir, &[object(Source::Register(0))]).is_none());
        }
    }

    #[test]
    fn differing_pointer_origins_at_a_join_are_rejected_when_read() {
        let alias = VARIABLE_BASE;
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![Stmt::Brif {
                cond: crate::ir::Cond::Eq,
                lhs: Expr::reg(1, 64),
                rhs: Expr::Const(0),
                target: 0x20,
            }],
        );
        ir.blocks.extend([
            Block {
                start: 0x10,
                stmts: vec![assign(alias, at(0, 8)), Stmt::Br { target: Some(0x30) }],
            },
            Block {
                start: 0x20,
                stmts: vec![assign(alias, at(0, 16)), Stmt::Br { target: Some(0x30) }],
            },
            Block {
                start: 0x30,
                stmts: vec![Stmt::Ret {
                    value: load(alias, 0),
                }],
            },
        ]);
        assert!(prepare(&mut ir, &[object(Source::Register(0))]).is_none());
    }

    #[test]
    fn only_an_output_objects_unmodified_address_may_be_a_return_echo() {
        let mut output = object(Source::Register(0));
        output.output = true;
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                Stmt::Store {
                    addr: at(0, 0),
                    value: Expr::Const(1),
                    width: 8,
                },
                Stmt::Store {
                    addr: at(0, 8),
                    value: Expr::Const(2),
                    width: 8,
                },
                Stmt::Store {
                    addr: at(0, 16),
                    value: Expr::Const(3),
                    width: 8,
                },
                Stmt::Store {
                    addr: at(0, 24),
                    value: Expr::Const(9),
                    width: 8,
                },
                Stmt::Ret {
                    value: Expr::reg(0, 64),
                },
            ],
        );
        assert!(prepare(&mut ir, &[output]).is_some());
        assert!(matches!(
            ir.blocks[0].stmts.last(),
            Some(Stmt::Ret {
                value: Expr::Const(0)
            })
        ));
    }

    #[test]
    fn overlapping_stack_objects_and_cross_boundary_accesses_are_rejected() {
        let sp = crate::arch::stack_pointer(Isa::X86_64);
        let mut ir = FunctionIr::single_block(Isa::X86_64, vec![Stmt::Ret { value: load(sp, 4) }]);
        assert!(prepare(&mut ir, &[object(Source::Stack(8))]).is_none());
        assert!(
            prepare(
                &mut ir,
                &[object(Source::Stack(8)), object(Source::Stack(16))]
            )
            .is_none()
        );
    }

    #[test]
    fn output_objects_require_writes_on_every_return_path() {
        let mut output = object(Source::Register(0));
        output.output = true;
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                Stmt::Store {
                    addr: at(0, 0),
                    value: Expr::Const(1),
                    width: 8,
                },
                Stmt::Ret {
                    value: Expr::reg(0, 64),
                },
            ],
        );
        assert!(prepare(&mut ir, &[output]).is_none());
    }

    #[test]
    fn output_reads_before_writes_and_input_padding_reads_are_rejected() {
        let mut output = object(Source::Register(0));
        output.output = true;
        let mut ir = FunctionIr::single_block(
            Isa::AArch64,
            vec![
                assign(VARIABLE_BASE, load(0, 0)),
                Stmt::Store {
                    addr: at(0, 0),
                    value: Expr::Const(1),
                    width: 8,
                },
                Stmt::Store {
                    addr: at(0, 8),
                    value: Expr::Const(2),
                    width: 8,
                },
                Stmt::Store {
                    addr: at(0, 16),
                    value: Expr::Const(3),
                    width: 8,
                },
                Stmt::Store {
                    addr: at(0, 24),
                    value: Expr::Const(4),
                    width: 8,
                },
                Stmt::Ret {
                    value: Expr::reg(0, 64),
                },
            ],
        );
        assert!(prepare(&mut ir, &[output]).is_none());
        let mut input = object(Source::Register(0));
        input.defined_bits = vec![(0, 32), (64, 64)];
        let mut ir = FunctionIr::single_block(Isa::AArch64, vec![Stmt::Ret { value: load(0, 0) }]);
        assert!(prepare(&mut ir, &[input]).is_none());
    }

    #[test]
    fn object_accesses_require_supported_scalar_widths() {
        for source in [Source::Register(0), Source::Stack(8)] {
            let address = match source {
                Source::Register(index) => Expr::reg(index, 64),
                Source::Stack(offset) => at(crate::arch::stack_pointer(Isa::AArch64), offset),
            };
            for width in [1, 2, 3, 4, 5, 6, 7, 8, 9, 16] {
                let supported = matches!(width, 1 | 2 | 4 | 8);
                let cases = [
                    vec![Stmt::Ret {
                        value: Expr::Load {
                            addr: Box::new(address.clone()),
                            width,
                            signed: false,
                        },
                    }],
                    vec![
                        Stmt::Store {
                            addr: address.clone(),
                            value: Expr::Const(7),
                            width,
                        },
                        Stmt::Ret {
                            value: Expr::Const(0),
                        },
                    ],
                ];
                for stmts in cases {
                    let mut ir = FunctionIr::single_block(Isa::AArch64, stmts);
                    let before = ir.render();
                    assert_eq!(prepare(&mut ir, &[object(source)]).is_some(), supported);
                    if !supported {
                        assert_eq!(ir.render(), before);
                        assert!(ir.params.is_empty());
                    }
                }
            }
        }
    }

    #[test]
    fn output_initialization_intersects_both_sides_of_a_diamond() {
        for second_written in [false, true] {
            let mut output = object(Source::Register(0));
            output.output = true;
            output.size = 8;
            output.defined_bits = vec![(0, 64)];
            let store = Stmt::Store {
                addr: Expr::reg(0, 64),
                value: Expr::Const(7),
                width: 8,
            };
            let mut ir = FunctionIr::single_block(
                Isa::AArch64,
                vec![Stmt::Brif {
                    cond: crate::ir::Cond::Eq,
                    lhs: Expr::reg(1, 64),
                    rhs: Expr::Const(0),
                    target: 0x20,
                }],
            );
            let mut second = Vec::new();
            if second_written {
                second.push(store.clone());
            }
            second.push(Stmt::Br { target: Some(0x30) });
            ir.blocks.extend([
                Block {
                    start: 0x10,
                    stmts: vec![store, Stmt::Br { target: Some(0x30) }],
                },
                Block {
                    start: 0x20,
                    stmts: second,
                },
                Block {
                    start: 0x30,
                    stmts: vec![Stmt::Ret {
                        value: Expr::reg(0, 64),
                    }],
                },
            ]);
            assert_eq!(prepare(&mut ir, &[output]).is_some(), second_written);
        }
    }
}

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::ir::{BinOp, CType, Expr, FunctionIr, Stmt, Structure};

mod pointers;

/// A load or store: its address, its width, and for a load whether it
/// sign-extends.
pub(super) struct MemoryAccess {
    addr: Expr,
    width: u8,
    signed: Option<bool>,
}

/// Gives a pointer parameter read or written at several fixed offsets a
/// structure of its own, one field per offset, when the accesses agree on
/// each field's width and no two overlap. A pointer indexed by multiples of
/// one size, or stepped by them, points into an array of such structures,
/// each that size, and so does an integer parameter used only so; one the
/// body indexes otherwise or moves points into an array of scalars, and
/// keeps its scalar type.
pub(crate) fn recover(ir: &mut FunctionIr) {
    let function = crate::render::structure_prefix(ir.name.as_deref(), ir.addr);
    let assigned: HashSet<u16> = ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .filter_map(|stmt| match stmt {
            Stmt::Assign { dest, .. } => Some(dest.index),
            _ => None,
        })
        .collect();
    let mut structures = Vec::new();
    for at in 0..ir.params.len() {
        let param = &ir.params[at];
        // An integer only ever offset may be the pointer into an array too.
        let integer = match &param.ty {
            CType::Pointer(target)
                if matches!(target.as_ref(), CType::Int { .. } | CType::Void) =>
            {
                false
            }
            CType::Int { bytes: 8, .. } if only_offset(ir, param.index) => true,
            _ => continue,
        };
        let index = param.index;
        let direct = !assigned.contains(&index);
        let name = format!("{function}_{}", param.name);
        let touches = memory_accesses(ir);
        let mut found = array(ir, index, direct, &touches, 2);
        // An index the code scaled into a register of its own is put back
        // into the addresses, where it shows the size.
        if found.is_none()
            && let Some(blocks) = inline_indexes(ir, index, direct)
        {
            let original = std::mem::replace(&mut ir.blocks, blocks);
            found = array(ir, index, direct, &memory_accesses(ir), 2);
            if found.is_none() {
                ir.blocks = original;
            }
        }
        let structure = match found {
            Some(mut array) => {
                array
                    .elements
                    .extend(pointers::normalize(ir, &array.phases));
                array.elements.sort_unstable();
                array.elements.dedup();
                Structure {
                    name,
                    fields: array.fields,
                    size: Some(array.size),
                    elements: array.elements,
                }
            }
            None if !direct || integer => continue,
            None => {
                let Some(FixedLayout { fields, aliases }) = fixed_layout(ir, index, &touches)
                else {
                    continue;
                };
                Structure {
                    name,
                    fields,
                    size: None,
                    elements: aliases.into_iter().filter(|copy| *copy != index).collect(),
                }
            }
        };
        ir.params[at].ty = CType::pointer_to(CType::Named(format!("struct {}", structure.name)));
        if structure.size.is_none() {
            for copy in &structure.elements {
                ir.value_types.insert(*copy, ir.params[at].ty.clone());
            }
        }
        structures.push(structure);
    }
    // A variable read or written at several fixed offsets points at a
    // structure as a parameter does: a pointer a call returns, or one the
    // code loads from another structure.
    // One stepped by a constant walks an array instead, as a copy loop's
    // pointer does; one loaded from its own field, as a walk along a list
    // is, still points at a structure each time.
    let stepped: HashSet<u16> = ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .filter_map(|stmt| {
            let Stmt::Assign { dest, value } = stmt else {
                return None;
            };
            let mut reads = HashSet::new();
            crate::ir::visit::collect_reads(value, &mut reads);
            (reads.contains(&dest.index) && !matches!(value, Expr::Reg { .. } | Expr::Load { .. }))
                .then_some(dest.index)
        })
        .collect();
    let mut touches = memory_accesses(ir);
    let mut variables: Vec<u16> = touches
        .iter()
        .flat_map(|touch| {
            let mut reads = HashSet::new();
            crate::ir::visit::collect_reads(&touch.addr, &mut reads);
            reads
                .into_iter()
                .filter(|base| *base >= crate::ir::VARIABLE_BASE)
        })
        .collect();
    loop {
        let mut changed = false;
        for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
            if let Stmt::Assign {
                dest,
                value: Expr::Reg { index, width: 64 },
            } = stmt
                && dest.width == 64
                && *index >= crate::ir::VARIABLE_BASE
                && variables.contains(&dest.index)
                && !variables.contains(index)
            {
                variables.push(*index);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    variables.sort_unstable();
    variables.dedup();
    // Variables whose fields match share one structure.
    let mut number = 0;
    for variable in variables {
        if stepped.contains(&variable)
            || structures
                .iter()
                .any(|structure| structure.elements.contains(&variable))
        {
            continue;
        }
        let mut found = array(ir, variable, true, &touches, 2);
        // As for a parameter, an index scaled into a register of its own
        // is put back into the addresses, where it shows the size.
        if found.is_none()
            && let Some(blocks) = inline_indexes(ir, variable, true)
        {
            let original = std::mem::replace(&mut ir.blocks, blocks);
            let inlined = memory_accesses(ir);
            found = array(ir, variable, true, &inlined, 2);
            if found.is_none() {
                ir.blocks = original;
            } else {
                touches = inlined;
            }
        }
        let (fields, size, aliases) = match found {
            Some(mut array) => {
                let normalized = pointers::normalize(ir, &array.phases);
                if !normalized.is_empty() {
                    touches = memory_accesses(ir);
                }
                array.elements.extend(normalized);
                array.elements.sort_unstable();
                array.elements.dedup();
                let mut aliases = array.elements;
                aliases.push(variable);
                (array.fields, Some(array.size), aliases)
            }
            None => {
                let Some(FixedLayout { fields, aliases }) = fixed_layout(ir, variable, &touches)
                else {
                    continue;
                };
                touches = memory_accesses(ir);
                (fields, None, aliases)
            }
        };
        let name = match structures
            .iter_mut()
            .find(|known| known.fields == fields && known.size == size)
        {
            Some(known) => {
                known.elements.extend(aliases.iter().copied());
                known.elements.sort_unstable();
                known.elements.dedup();
                known.name.clone()
            }
            None => {
                number += 1;
                let name = format!("{function}_s{number}");
                structures.push(Structure {
                    name: name.clone(),
                    fields,
                    size,
                    elements: aliases.clone(),
                });
                name
            }
        };
        if size.is_none() {
            for alias in aliases {
                ir.value_types.insert(
                    alias,
                    CType::pointer_to(CType::Named(format!("struct {name}"))),
                );
            }
        }
    }
    ir.structures.extend(structures);
}

struct FixedLayout {
    fields: Vec<(u64, CType)>,
    aliases: Vec<u16>,
}

fn fixed_layout(ir: &mut FunctionIr, base: u16, touches: &[MemoryAccess]) -> Option<FixedLayout> {
    if let Some(layout) = adjusted_layout(ir, base, touches) {
        return Some(layout);
    }
    let aliases = copies(ir, base);
    layout(&aliases, touches).map(|fields| FixedLayout { fields, aliases })
}

/// Fixed offsets from a pointer, represented by locals holding its original base.
fn adjusted_layout(
    ir: &mut FunctionIr,
    base: u16,
    touches: &[MemoryAccess],
) -> Option<FixedLayout> {
    let sources = holders(ir, base, true);
    let mut offsets = HashMap::from([(Base::Register(base), 0i64), (Base::Slot, 0)]);
    loop {
        let mut changed = false;
        for (register, definitions) in &sources.definitions {
            let own = Base::Register(*register);
            if offsets.contains_key(&own) {
                continue;
            }
            let offset = definitions.iter().find_map(|definition| {
                if !definition.scales.is_empty() {
                    return None;
                }
                offsets
                    .get(&definition.base)
                    .and_then(|offset| offset.checked_add(definition.constant))
            });
            if let Some(offset) = offset {
                offsets.insert(own, offset);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut phases = Vec::new();
    for (register, definitions) in &sources.definitions {
        let Some(offset) = offsets.get(&Base::Register(*register)) else {
            continue;
        };
        if definitions.iter().any(|definition| {
            !definition.scales.is_empty()
                || offsets
                    .get(&definition.base)
                    .and_then(|from| from.checked_add(definition.constant))
                    != Some(*offset)
        }) {
            continue;
        }
        if *offset != 0 {
            phases.push((*register, *offset as u64));
        }
    }
    if phases.is_empty() {
        let aliases = copies(ir, base);
        return layout(&aliases, touches).map(|fields| FixedLayout { fields, aliases });
    }
    if ir.blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
        matches!(
            stmt,
            Stmt::Machine {
                instruction: crate::ir::MachineInstruction::ArmLoadAcquire { .. }
                    | crate::ir::MachineInstruction::ArmExclusive { .. }
                    | crate::ir::MachineInstruction::ArmCacheZero,
                ..
            }
        )
    }) {
        return None;
    }
    let mut candidate = ir.clone();
    if pointers::normalize(&mut candidate, &phases).len() != phases.len() {
        return None;
    }
    let aliases = copies(&candidate, base);
    let Some(fields) = layout(&aliases, &memory_accesses(&candidate)) else {
        return None;
    };
    let mut end = 0;
    for (offset, ty) in &fields {
        if *offset < end {
            return None;
        }
        let Some(width) = CType::pointer_to(ty.clone()).pointee_size() else {
            return None;
        };
        let Some(next) = offset.checked_add(u64::from(width)) else {
            return None;
        };
        end = next;
    }
    // Adjusted aliases must not hide conflicting or unsupported accesses.
    if phases
        .iter()
        .any(|(register, _)| !aliases.contains(register))
    {
        return None;
    }
    *ir = candidate;
    Some(FixedLayout { fields, aliases })
}

/// Whole-register copies whose every definition keeps the same address.
fn copies(ir: &FunctionIr, base: u16) -> Vec<u16> {
    let mut definitions: BTreeMap<u16, Vec<Option<u16>>> = BTreeMap::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        let source = match stmt {
            Stmt::Assign {
                dest,
                value: Expr::Reg { index, width: 64 },
            } if dest.width == 64 => Some(*index),
            _ => None,
        };
        for register in crate::ir::visit::statement_registers(stmt).0 {
            definitions.entry(register).or_default().push(source);
        }
    }
    let mut aliases = vec![base];
    loop {
        let mut changed = false;
        for (dest, sources) in &definitions {
            if !aliases.contains(dest)
                && sources
                    .iter()
                    .all(|source| source.is_some_and(|source| aliases.contains(&source)))
            {
                aliases.push(*dest);
                changed = true;
            }
        }
        if !changed {
            return aliases;
        }
    }
}

/// Whether the function reads `register` only whole, or in sums.
fn only_offset(ir: &FunctionIr, register: u16) -> bool {
    fn whole(expr: &Expr, register: u16, as_value: bool) -> bool {
        match expr {
            Expr::Reg { index, width } => *index != register || (as_value && *width == 64),
            Expr::Bin {
                op: BinOp::Add | BinOp::Sub,
                lhs,
                rhs,
            } => whole(lhs, register, true) && whole(rhs, register, true),
            Expr::Load { addr, .. } => whole(addr, register, true),
            other => crate::ir::visit::children(other)
                .into_iter()
                .all(|child| whole(child, register, false)),
        }
    }
    ir.blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .flat_map(Stmt::operands)
        .all(|operand| whole(operand, register, true))
}

/// Every memory access of the function, including atomic fields.
pub(super) fn memory_accesses(ir: &FunctionIr) -> Vec<MemoryAccess> {
    let mut touches = Vec::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        if let Stmt::Store { addr, width, .. } = stmt {
            touches.push(MemoryAccess {
                addr: addr.clone(),
                width: *width,
                signed: None,
            });
        }
        if let Stmt::Machine {
            instruction: crate::ir::MachineInstruction::Atomic { width, .. },
            inputs,
            ..
        } = stmt
            && let Some(addr) = inputs.first()
        {
            touches.push(MemoryAccess {
                addr: addr.clone(),
                width: *width,
                signed: None,
            });
        }
        for value in stmt.operands() {
            loads(value, &mut touches);
        }
    }
    touches
}

/// Fields accessed through whole-register copies with consistent widths.
fn layout(aliases: &[u16], touches: &[MemoryAccess]) -> Option<Vec<(u64, CType)>> {
    layout_aliases(aliases, touches, 2)
}

pub(super) fn layout_at_least(
    base: u16,
    touches: &[MemoryAccess],
    minimum: usize,
) -> Option<Vec<(u64, CType)>> {
    layout_aliases(&[base], touches, minimum)
}

/// Check partial accesses against an element size established by another function.
pub(super) fn layout_with_size(
    ir: &FunctionIr,
    base: u16,
    touches: &[MemoryAccess],
    size: u64,
) -> Option<Vec<(u64, CType)>> {
    if !(2..=MAX_STRUCTURE_SIZE).contains(&size) {
        return None;
    }
    let holders = holders(ir, base, true);
    let Some(touched) = split_touches(&holders, touches) else {
        return None;
    };
    for split in touched
        .iter()
        .map(|(split, _)| split)
        .chain(holders.definitions.values().flatten())
    {
        if split.scales.iter().any(|scale| !scale.is_multiple_of(size)) {
            return None;
        }
    }
    match arrange(size, base, true, &holders, &touched, 0) {
        Some(array) => Some(array.fields),
        None => None,
    }
}

/// A stride supported by indexed accesses, including a single observed field.
pub(super) fn array_size(ir: &FunctionIr, base: u16, touches: &[MemoryAccess]) -> Option<u64> {
    array(ir, base, true, touches, 1).map(|array| array.size)
}

fn layout_aliases(
    aliases: &[u16],
    touches: &[MemoryAccess],
    minimum: usize,
) -> Option<Vec<(u64, CType)>> {
    fn uses_address(expr: &Expr, aliases: &[u16]) -> bool {
        match expr {
            Expr::Reg { index, .. } => aliases.contains(index),
            Expr::Load { .. } => false,
            other => crate::ir::visit::children(other)
                .into_iter()
                .any(|child| uses_address(child, aliases)),
        }
    }
    let mut fields: BTreeMap<(u64, u8), bool> = BTreeMap::new();
    let mut indirect = false;
    for touch in touches {
        if !uses_address(&touch.addr, aliases) {
            let mut reads = HashSet::new();
            crate::ir::visit::collect_reads(&touch.addr, &mut reads);
            indirect |= aliases.iter().any(|base| reads.contains(base));
            continue;
        }
        let offset = match &touch.addr {
            Expr::Reg { index, width: 64 } if aliases.contains(index) => 0,
            Expr::Bin {
                op: BinOp::Add,
                lhs,
                rhs,
            } => match (lhs.as_ref(), rhs.as_ref()) {
                (Expr::Reg { index, width: 64 }, Expr::Const(offset))
                | (Expr::Const(offset), Expr::Reg { index, width: 64 })
                    if aliases.contains(index) && *offset < 1 << 31 =>
                {
                    *offset
                }
                _ => return None,
            },
            _ => return None,
        };
        if !matches!(touch.width, 1 | 2 | 4 | 8) {
            return None;
        }
        *fields.entry((offset, touch.width)).or_default() |= touch.signed.unwrap_or(false);
    }
    if indirect {
        let mut end = 0;
        for (offset, width) in fields.keys() {
            if *offset < end {
                return None;
            }
            let Some(next) = offset.checked_add(u64::from(*width)) else {
                return None;
            };
            end = next;
        }
    }
    let Some(settled) = settle(&fields) else {
        return None;
    };
    if crate::render::unions::cells(&settled).len() < minimum {
        return None;
    }
    Some(settled)
}

/// The fields the accesses `fields` (offset and width, and whether a load
/// extends a sign) make: one per access no other overlaps, and one per
/// width for those that overlap in an aligned cell of two, four or eight
/// bytes, which a union declares; `None` for overlaps that fill no cell
/// and for fields not aligned to their width. The fields of one width in a
/// cell share their sign.
fn settle(fields: &BTreeMap<(u64, u8), bool>) -> Option<Vec<(u64, CType)>> {
    let mut settled = Vec::new();
    let entries: Vec<((u64, u8), bool)> =
        fields.iter().map(|(key, signed)| (*key, *signed)).collect();
    let mut first = 0;
    while first < entries.len() {
        let ((start, width), _) = entries[first];
        let mut stop = start.saturating_add(u64::from(width));
        let mut next = first + 1;
        while let Some(((offset, width), _)) = entries.get(next).copied()
            && offset < stop
        {
            stop = stop.max(offset.saturating_add(u64::from(width)));
            next += 1;
        }
        let group = &entries[first..next];
        first = next;
        let Ok(relative) = group
            .iter()
            .map(|((offset, width), _)| i64::try_from(*offset).map(|offset| (offset, *width)))
            .collect::<Result<Vec<(i64, u8)>, _>>()
        else {
            return None;
        };
        if group.len() > 1 && crate::render::unions::cell(&relative).is_none() {
            return None;
        }
        for ((offset, width), _) in group {
            if !matches!(width, 1 | 2 | 4 | 8) || !offset.is_multiple_of(u64::from(*width)) {
                return None;
            }
            let signed = group
                .iter()
                .any(|((_, other), signed)| other == width && *signed);
            settled.push((*offset, field_type(*width, signed)));
        }
    }
    Some(settled)
}

/// Use unsigned storage unless an access explicitly extends the sign.
fn field_type(width: u8, signed: bool) -> CType {
    CType::Int {
        bytes: width,
        signed,
    }
}

/// The largest structure an array is taken to be made of.
const MAX_STRUCTURE_SIZE: u64 = 1 << 16;

/// An array of structures a pointer parameter points into.
struct Array {
    size: u64,
    fields: Vec<(u64, CType)>,
    /// Variables that point at the start of an element.
    elements: Vec<u16>,
    phases: Vec<(u16, u64)>,
}

fn split_touches<'a>(
    holders: &PointerSources,
    touches: &'a [MemoryAccess],
) -> Option<Vec<(AddressParts, &'a MemoryAccess)>> {
    let mut touched = Vec::new();
    for touch in touches {
        match holders.split(&touch.addr) {
            Some(split) => touched.push((split, touch)),
            None if holders.exposes(&touch.addr) => return None,
            None => {}
        }
    }
    Some(touched)
}

/// The array of structures `param` points into: every address computed
/// from it, directly, through a stack slot holding it, or through a
/// register set from it, adds indexes scaled by multiples of one size and
/// a constant, and the constants modulo that size are the fields. The
/// fields must sit where C would place them, so that the size is the
/// structure's own and indexing by it moves as the code does.
fn array(
    ir: &FunctionIr,
    param: u16,
    direct: bool,
    touches: &[MemoryAccess],
    minimum: usize,
) -> Option<Array> {
    let holders = holders(ir, param, direct);
    let Some(touched) = split_touches(&holders, touches) else {
        return None;
    };
    let splits = || {
        touched
            .iter()
            .map(|(split, _)| split)
            .chain(holders.definitions.values().flatten())
    };
    let scale = splits()
        .flat_map(|split| split.scales.iter().copied())
        .fold(0, gcd);
    let sizes = 2..=MAX_STRUCTURE_SIZE;
    if scale != 0 {
        return sizes
            .contains(&scale)
            .then(|| arrange(scale, param, direct, &holders, &touched, minimum))
            .flatten();
    }
    // Without an index, the steps of a loop's pointer give the size, or a
    // multiple of it when the loop handles several elements a turn: then
    // the fields repeat within a step.
    let step = holders
        .definitions
        .iter()
        .flat_map(|(register, splits)| {
            splits
                .iter()
                .filter(move |split| split.base == Base::Register(*register))
        })
        .map(|split| split.constant.unsigned_abs())
        .fold(0, gcd);
    if !sizes.contains(&step) {
        return None;
    }
    let Some(whole) = arrange(step, param, direct, &holders, &touched, minimum) else {
        return None;
    };
    let fields: HashMap<u64, &CType> = whole
        .fields
        .iter()
        .map(|(offset, ty)| (*offset, ty))
        .collect();
    let period = (2..step).filter(|size| step % size == 0).find(|size| {
        whole
            .fields
            .iter()
            .all(|(offset, ty)| fields.get(&((offset + size) % step)) == Some(&ty))
    });
    match period {
        Some(size) => arrange(size, param, direct, &holders, &touched, minimum),
        None => Some(whole),
    }
}

/// The array of structures `size` bytes each that the accesses through
/// the holders of `param` make, if their fields agree.
fn arrange(
    size: u64,
    param: u16,
    direct: bool,
    holders: &PointerSources,
    touched: &[(AddressParts, &MemoryAccess)],
    minimum: usize,
) -> Option<Array> {
    // Where in an element each pointer points; a register stepped by whole
    // elements keeps its place.
    let mut phases: HashMap<Base, u64> = HashMap::from([(Base::Slot, 0)]);
    if direct {
        phases.insert(Base::Register(param), 0);
    }
    let within = |phase: u64, constant: i64| {
        (i128::from(phase) + i128::from(constant)).rem_euclid(i128::from(size)) as u64
    };
    loop {
        let mut progress = false;
        for (register, splits) in &holders.definitions {
            let own = Base::Register(*register);
            if phases.contains_key(&own) {
                continue;
            }
            if let Some(phase) = splits.iter().find_map(|split| {
                if split.base == own {
                    return None;
                }
                let Some(from) = phases.get(&split.base) else {
                    return None;
                };
                Some(within(*from, split.constant))
            }) {
                phases.insert(own, phase);
                progress = true;
            }
        }
        if !progress {
            break;
        }
    }
    for (register, splits) in &holders.definitions {
        let own = Base::Register(*register);
        let Some(&phase) = phases.get(&own) else {
            return None;
        };
        for split in splits {
            let (from, to) = if split.base == own {
                (0, 0)
            } else {
                let Some(&from) = phases.get(&split.base) else {
                    return None;
                };
                (from, phase)
            };
            if within(from, split.constant) != to {
                return None;
            }
        }
    }

    let mut fields: BTreeMap<u64, (u8, Option<bool>)> = BTreeMap::new();
    for (split, touch) in touched {
        if !matches!(touch.width, 1 | 2 | 4 | 8) {
            return None;
        }
        let offset = within(phases[&split.base], split.constant);
        let field = fields.entry(offset).or_insert((touch.width, touch.signed));
        if field.0 != touch.width {
            return None;
        }
        match (field.1, touch.signed) {
            (Some(known), Some(signed)) if known != signed && touch.width < 4 => return None,
            (None, signed) => field.1 = signed,
            _ => {}
        }
    }
    if fields.len() < minimum {
        return None;
    }
    let mut end = 0;
    for (offset, (width, _)) in &fields {
        let width = u64::from(*width);
        if *offset < end || !offset.is_multiple_of(width) || !size.is_multiple_of(width) {
            return None;
        }
        let Some(next) = offset.checked_add(width) else {
            return None;
        };
        end = next;
    }
    if end > size {
        return None;
    }
    Some(Array {
        size,
        fields: fields
            .into_iter()
            .map(|(offset, (width, signed))| (offset, field_type(width, signed.unwrap_or(false))))
            .collect(),
        elements: holders
            .definitions
            .keys()
            .filter(|register| phases[&Base::Register(**register)] == 0)
            .copied()
            .collect(),
        phases: holders
            .definitions
            .keys()
            .filter_map(|register| {
                let phase = phases[&Base::Register(*register)];
                (phase != 0).then_some((*register, phase))
            })
            .collect(),
    })
}

fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { gcd(b, a % b) }
}

/// What an address is computed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Base {
    Register(u16),
    /// A stack slot holding the parameter.
    Slot,
}

/// An address as the pointer it starts from, the scales of the indexes it
/// adds, and its constant.
#[derive(Debug)]
struct AddressParts {
    base: Base,
    scales: Vec<u64>,
    constant: i64,
}

/// Where a parameter's value is kept: the parameter itself, unless the body
/// assigns it, the stack slots only ever stored from it, and the registers
/// every definition of which offsets one of those, itself included.
struct PointerSources {
    direct: Option<u16>,
    slots: HashSet<String>,
    /// Each register set from the parameter, with its definitions.
    definitions: BTreeMap<u16, Vec<AddressParts>>,
}

fn holders(ir: &FunctionIr, param: u16, direct: bool) -> PointerSources {
    let stmts = || ir.blocks.iter().flat_map(|block| &block.stmts);
    let mut stored: HashMap<String, bool> = HashMap::new();
    let mut values: BTreeMap<u16, Vec<Option<&Expr>>> = BTreeMap::new();
    for stmt in stmts() {
        match stmt {
            Stmt::Store { addr, value, width } => {
                let from_param =
                    *width == 8 && matches!(value, Expr::Reg { index, .. } if *index == param);
                *stored.entry(format!("{addr:?}")).or_insert(true) &= from_param;
            }
            Stmt::Assign { dest, value } => values
                .entry(dest.index)
                .or_default()
                .push((dest.width == 64).then_some(value)),
            other => {
                for register in crate::ir::visit::statement_registers(other).0 {
                    values.entry(register).or_default().push(None);
                }
            }
        }
    }
    let mut holders = PointerSources {
        direct: direct.then_some(param),
        slots: stored
            .into_iter()
            .filter_map(|(slot, only)| only.then_some(slot))
            .collect(),
        definitions: BTreeMap::new(),
    };
    if stmts().any(|stmt| {
        matches!(
            stmt,
            Stmt::Machine {
                instruction: crate::ir::MachineInstruction::Atomic { .. },
                ..
            }
        )
    }) {
        let sp = crate::arch::stack_pointer(ir.isa);
        if !crate::passes::memory::fixed_private_frame(ir, sp) {
            holders.slots.clear();
        } else {
            let private: HashSet<_> = stmts()
                .filter_map(|stmt| match stmt {
                    Stmt::Store { addr, .. }
                        if crate::passes::memory::private_address(addr, 8, sp) =>
                    {
                        Some(format!("{addr:?}"))
                    }
                    _ => None,
                })
                .collect();
            holders.slots.retain(|slot| private.contains(slot));
        }
    }
    // Every register some definition of which adds to a holder, and then
    // only those every definition of which splits, stepping themselves or
    // each other as loops do.
    let assigned = |values: &[Option<&Expr>]| values.iter().all(Option::is_some);
    loop {
        let mut grew = false;
        for (register, values) in &values {
            if *register == param || holders.definitions.contains_key(register) || !assigned(values)
            {
                continue;
            }
            if values.iter().flatten().any(|value| holders.adds_to(value)) {
                holders.definitions.insert(*register, Vec::new());
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    loop {
        let registers: Vec<u16> = holders.definitions.keys().copied().collect();
        let mut shrank = false;
        for register in registers {
            let splits: Option<Vec<AddressParts>> = values[&register]
                .iter()
                .map(|value| {
                    let Some(value) = value else {
                        return None;
                    };
                    holders.split(value)
                })
                .collect();
            match splits {
                Some(splits) => {
                    holders.definitions.insert(register, splits);
                }
                None => {
                    holders.definitions.remove(&register);
                    shrank = true;
                }
            }
        }
        if !shrank {
            break;
        }
    }
    holders
}

impl PointerSources {
    fn base(&self, term: &Expr) -> Option<Base> {
        match term {
            Expr::Reg { index, width: 64 }
                if Some(*index) == self.direct || self.definitions.contains_key(index) =>
            {
                Some(Base::Register(*index))
            }
            Expr::Load { addr, width: 8, .. } if self.slots.contains(&format!("{addr:?}")) => {
                Some(Base::Slot)
            }
            _ => None,
        }
    }

    /// Whether `value` adds something to a holder of the parameter.
    fn adds_to(&self, value: &Expr) -> bool {
        let mut terms = Vec::new();
        crate::ir::visit::sum_terms(value, false, &mut terms);
        terms
            .iter()
            .any(|(term, negative)| !negative && self.base(term).is_some())
    }

    /// `addr` as one holder of the parameter plus scaled indexes and a
    /// constant, or `None` for any other address.
    fn split(&self, addr: &Expr) -> Option<AddressParts> {
        let mut terms = Vec::new();
        crate::ir::visit::sum_terms(addr, false, &mut terms);
        let mut base = None;
        let mut scales = Vec::new();
        let mut constant: i64 = 0;
        for (term, negative) in terms {
            if let Expr::Const(value) = term {
                constant = if negative {
                    constant.wrapping_sub(*value as i64)
                } else {
                    constant.wrapping_add(*value as i64)
                };
                continue;
            }
            if negative {
                return None;
            }
            if let Some(found) = self.base(term) {
                if base.replace(found).is_some() {
                    return None;
                }
                continue;
            }
            match scaled(term) {
                Some((index, scale)) if scale != 0 && !self.exposes(index) => scales.push(scale),
                _ => return None,
            }
        }
        let Some(base) = base else {
            return None;
        };
        Some(AddressParts {
            base,
            scales,
            constant,
        })
    }

    /// Whether `expr` computes with the parameter's value, rather than with
    /// what it points at.
    fn exposes(&self, expr: &Expr) -> bool {
        if self.base(expr).is_some() {
            return true;
        }
        match expr {
            Expr::Load { .. } => false,
            other => crate::ir::visit::children(other)
                .into_iter()
                .any(|child| self.exposes(child)),
        }
    }
}

/// Puts back into the addresses computed from `param` each register they
/// add that holds a scaled index, `i << n`, `i * k` or `i + i * k`, set
/// once where `i` reads as it does at the address, and drops the registers
/// no longer read: the blocks so changed, if any address is.
fn inline_indexes(ir: &FunctionIr, param: u16, direct: bool) -> Option<Vec<crate::ir::Block>> {
    let holders = holders(ir, param, direct);
    let mut writes: HashMap<u16, usize> = HashMap::new();
    let mut assigns: HashMap<u16, usize> = HashMap::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        for register in crate::ir::visit::statement_registers(stmt).0 {
            *writes.entry(register).or_default() += 1;
        }
        if let Stmt::Assign { dest, .. } = stmt {
            *assigns.entry(dest.index).or_default() += 1;
        }
    }
    // Each such register, with the index, its scale, and where it is set.
    let mut indexes: HashMap<u16, (Expr, u64, (usize, usize))> = HashMap::new();
    for (at, block) in ir.blocks.iter().enumerate() {
        for (position, stmt) in block.stmts.iter().enumerate() {
            if let Stmt::Assign { dest, value } = stmt
                && dest.index >= crate::ir::VARIABLE_BASE
                && writes.get(&dest.index) == Some(&1)
                && let Some((index, scale)) = index_scale(value)
            {
                indexes.insert(dest.index, (index.clone(), scale, (at, position)));
            }
        }
    }
    if indexes.is_empty() {
        return None;
    }
    let blocks = &ir.blocks;
    // Whether `index`, read where it is set, reads the same at `used`: in
    // the same block when nothing between writes what it reads, elsewhere
    // when it reads no memory and only registers set at most once.
    let same = |index: &Expr, (block, position): (usize, usize), (at, used): (usize, usize)| {
        let mut reads = HashSet::new();
        crate::ir::visit::collect_reads(index, &mut reads);
        let memory = crate::passes::copies::reads_memory(index);
        if at == block && used > position {
            return blocks[at].stmts[position + 1..used].iter().all(|stmt| {
                crate::ir::visit::statement_registers(stmt)
                    .0
                    .iter()
                    .all(|register| !reads.contains(register))
                    && !(memory
                        && matches!(
                            stmt,
                            Stmt::Store { .. }
                                | Stmt::Call { .. }
                                | Stmt::Unsupported { .. }
                                | Stmt::Machine { .. }
                        ))
            });
        }
        !memory
            && reads.iter().all(|register| match writes.get(register) {
                None => true,
                Some(1) => assigns.get(register) == Some(&1),
                Some(_) => false,
            })
    };
    let mut changed = blocks.clone();
    let mut any = false;
    for (at, block) in changed.iter_mut().enumerate() {
        for (position, stmt) in block.stmts.iter_mut().enumerate() {
            let mut lookup = |register: u16| {
                let (index, scale, set) = indexes.get(&register)?;
                same(index, *set, (at, position)).then(|| (index.clone(), *scale))
            };
            for operand in stmt.operands_mut() {
                any |= rewrite(operand, &holders, &mut lookup);
            }
        }
    }
    if !any {
        return None;
    }
    let read: HashSet<u16> = changed
        .iter()
        .flat_map(|block| &block.stmts)
        .flat_map(crate::ir::visit::statement_reads)
        .collect();
    let unread: HashSet<(usize, usize)> = indexes
        .iter()
        .filter(|(register, _)| !read.contains(register))
        .map(|(_, (_, _, set))| *set)
        .collect();
    for (at, block) in changed.iter_mut().enumerate() {
        let mut position = 0;
        block.stmts.retain(|_| {
            position += 1;
            !unread.contains(&(at, position - 1))
        });
    }
    Some(changed)
}

/// `i << n`, `i * k` or `i + i * k`, scaled or not, as the index and its
/// scale.
fn index_scale(value: &Expr) -> Option<(&Expr, u64)> {
    match scaled(value) {
        Some((inner, scale)) => Some(match repeated(inner) {
            Some((index, times)) => (index, times.wrapping_mul(scale)),
            None => (inner, scale),
        }),
        None => repeated(value),
    }
}

/// `i + i * k` as `i` and `k + 1`.
fn repeated(value: &Expr) -> Option<(&Expr, u64)> {
    let Expr::Bin {
        op: BinOp::Add,
        lhs,
        rhs,
    } = value
    else {
        return None;
    };
    [(lhs, rhs), (rhs, lhs)]
        .into_iter()
        .find_map(|(one, other)| {
            let (index, times) = scaled(other)?;
            (index == one.as_ref()).then_some((one.as_ref(), times.wrapping_add(1)))
        })
}

/// Replaces, in each sum adding to a holder of the parameter, the terms
/// that add or scale a register `lookup` gives an index for.
fn rewrite(
    expr: &mut Expr,
    holders: &PointerSources,
    lookup: &mut dyn FnMut(u16) -> Option<(Expr, u64)>,
) -> bool {
    let sum = matches!(
        expr,
        Expr::Bin {
            op: BinOp::Add | BinOp::Sub,
            ..
        }
    ) && holders.adds_to(expr);
    if !sum {
        return crate::ir::visit::children_mut(expr)
            .into_iter()
            .fold(false, |changed, child| {
                rewrite(child, holders, lookup) | changed
            });
    }
    let mut changed = false;
    for term in terms_mut(expr) {
        let (register, factor) = match term {
            Expr::Reg { index, width: 64 } => (*index, 1),
            Expr::Bin {
                op: BinOp::Mul,
                lhs,
                rhs,
            } => match (lhs.as_ref(), rhs.as_ref()) {
                (Expr::Reg { index, width: 64 }, Expr::Const(factor))
                | (Expr::Const(factor), Expr::Reg { index, width: 64 }) => (*index, *factor),
                _ => {
                    changed |= rewrite(term, holders, lookup);
                    continue;
                }
            },
            Expr::Bin {
                op: BinOp::Shl,
                lhs,
                rhs,
            } => match (lhs.as_ref(), rhs.as_ref()) {
                (Expr::Reg { index, width: 64 }, Expr::Const(shift)) if *shift < 32 => {
                    (*index, 1 << shift)
                }
                _ => {
                    changed |= rewrite(term, holders, lookup);
                    continue;
                }
            },
            other => {
                changed |= rewrite(other, holders, lookup);
                continue;
            }
        };
        if let Some((index, scale)) = lookup(register) {
            *term = Expr::bin(BinOp::Mul, index, Expr::Const(scale.wrapping_mul(factor)));
            changed = true;
        }
    }
    changed
}

/// The terms of a sum, as `flatten` finds them, to change.
fn terms_mut(expr: &mut Expr) -> Vec<&mut Expr> {
    let sum = match expr {
        Expr::Bin { op: BinOp::Add, .. } => true,
        Expr::Bin {
            op: BinOp::Sub,
            rhs,
            ..
        } => matches!(rhs.as_ref(), Expr::Const(_)),
        _ => false,
    };
    if !sum {
        return vec![expr];
    }
    match expr {
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => {
            let mut terms = terms_mut(lhs);
            terms.extend(terms_mut(rhs));
            terms
        }
        Expr::Bin { lhs, .. } => terms_mut(lhs),
        _ => Vec::new(),
    }
}

/// `i * k` or `i << n` as the index and its scale.
fn scaled(term: &Expr) -> Option<(&Expr, u64)> {
    match term {
        Expr::Bin {
            op: BinOp::Mul,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (index, Expr::Const(scale)) | (Expr::Const(scale), index) => Some((index, *scale)),
            _ => None,
        },
        Expr::Bin {
            op: BinOp::Shl,
            lhs,
            rhs,
        } => match rhs.as_ref() {
            Expr::Const(shift) if *shift < 32 => Some((lhs.as_ref(), 1 << shift)),
            _ => None,
        },
        _ => None,
    }
}

fn loads(expr: &Expr, out: &mut Vec<MemoryAccess>) {
    if let Expr::SignExtend { value, width } = expr
        && let Expr::Load {
            addr,
            width: loaded,
            ..
        } = value.as_ref()
        && width == loaded
    {
        out.push(MemoryAccess {
            addr: addr.as_ref().clone(),
            width: *width,
            signed: Some(true),
        });
        loads(addr, out);
        return;
    }
    if let Expr::Load {
        addr,
        width,
        signed,
    } = expr
    {
        out.push(MemoryAccess {
            addr: addr.as_ref().clone(),
            width: *width,
            signed: Some(*signed),
        });
    }
    for child in crate::ir::visit::children(expr) {
        loads(child, out);
    }
}

#[cfg(test)]
mod tests {
    mod typed;

    use super::recover;
    use crate::ir::{BinOp, CType, Expr, FunctionIr, Param, RegRef, Stmt, VARIABLE_BASE};
    use crate::loader::Isa;

    fn store(offset: u64, width: u8) -> Stmt {
        Stmt::Store {
            addr: Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(offset)),
            value: Expr::Const(0),
            width,
        }
    }

    fn load(addr: Expr, width: u8, signed: bool) -> Expr {
        Expr::Load {
            addr: Box::new(addr),
            width,
            signed,
        }
    }

    fn assign(index: u16, value: Expr) -> Stmt {
        Stmt::Assign {
            dest: RegRef { index, width: 64 },
            value,
        }
    }

    /// `base + index * scale + offset`.
    fn element(base: Expr, index: Expr, scale: u64, offset: u64) -> Expr {
        Expr::bin(
            BinOp::Add,
            Expr::bin(
                BinOp::Add,
                base,
                Expr::bin(BinOp::Mul, index, Expr::Const(scale)),
            ),
            Expr::Const(offset),
        )
    }

    fn pointer_function(stmts: Vec<Stmt>) -> FunctionIr {
        let mut ir = FunctionIr::single_block(Isa::X86_64, stmts);
        ir.params = vec![Param {
            index: 7,
            name: "a0".to_owned(),
            ty: CType::pointer_to(CType::U32),
        }];
        ir
    }

    #[test]
    fn a_pointer_variable_accessed_at_fixed_offsets_points_at_a_structure() {
        // v1 = *a0; v2 = *(a0 + 8); v1->0 = 0; v1->8 = 0; v2->0 = 0; v2->8 = 0.
        let (v1, v2) = (VARIABLE_BASE, VARIABLE_BASE + 1);
        let put = |base: u16, offset: u64| Stmt::Store {
            addr: Expr::bin(BinOp::Add, Expr::reg(base, 64), Expr::Const(offset)),
            value: Expr::Const(0),
            width: 8,
        };
        let mut ir = pointer_function(vec![
            assign(v1, load(Expr::reg(7, 64), 8, false)),
            assign(
                v2,
                load(
                    Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(8)),
                    8,
                    false,
                ),
            ),
            put(v1, 0),
            put(v1, 8),
            put(v2, 0),
            put(v2, 8),
        ]);
        recover(&mut ir);
        let given = |variable| ir.value_types.get(&variable).map(ToString::to_string);
        // The two share the one layout they have.
        assert_eq!(given(v1), given(v2));
        assert!(
            given(v1).is_some_and(|ty| ty.starts_with("struct ")),
            "{:?}",
            given(v1)
        );
        assert_eq!(ir.structures.len(), 1);
    }

    #[test]
    fn atomic_fields_contribute_to_layout_without_moving_loads() {
        use crate::ir::{AtomicOp, MachineInstruction, Ordering};

        for base in [7, VARIABLE_BASE] {
            let mut stmts = Vec::new();
            if base != 7 {
                stmts.push(assign(base, load(Expr::reg(7, 64), 8, false)));
            }
            stmts.push(assign(
                VARIABLE_BASE + 2,
                load(
                    Expr::bin(BinOp::Add, Expr::reg(base, 64), Expr::Const(8)),
                    8,
                    false,
                ),
            ));
            stmts.push(Stmt::Machine {
                instruction: MachineInstruction::Atomic {
                    op: AtomicOp::Add,
                    width: 8,
                    ordering: Ordering::SeqCst,
                },
                inputs: vec![Expr::reg(base, 64), Expr::Const(1)],
                outputs: vec![RegRef {
                    index: VARIABLE_BASE + 1,
                    width: 64,
                }],
            });
            stmts.push(Stmt::Ret {
                value: Expr::reg(VARIABLE_BASE + 2, 64),
            });
            let mut ir = pointer_function(stmts);
            let original = ir.blocks.clone();
            recover(&mut ir);
            assert_eq!(format!("{:?}", ir.blocks), format!("{original:?}"));
            assert!(
                ir.structures
                    .iter()
                    .any(|s| s.fields == vec![(0, CType::U64), (8, CType::U64)])
            );
            let code = crate::render::render(&ir, &[], &Default::default(), &[]);
            assert!(code.contains("->f_8"), "{code}");
            assert!(code.contains("__atomic_fetch_add(&"), "{code}");
            assert!(code.contains("->f_0, 0x1, __ATOMIC_SEQ_CST)"), "{code}");
        }
    }

    #[test]
    fn overlapping_atomic_fields_refuse_structure_layout() {
        use crate::ir::{AtomicOp, MachineInstruction, Ordering};

        let mut ir = pointer_function(vec![
            store(4, 8),
            Stmt::Machine {
                instruction: MachineInstruction::Atomic {
                    op: AtomicOp::Add,
                    width: 8,
                    ordering: Ordering::Relaxed,
                },
                inputs: vec![Expr::reg(7, 64), Expr::Const(1)],
                outputs: Vec::new(),
            },
        ]);
        recover(&mut ir);
        assert!(ir.structures.is_empty());
    }

    #[test]
    fn fields_at_fixed_offsets_make_a_structure() {
        let mut ir = pointer_function(vec![store(0, 4), store(8, 8)]);
        recover(&mut ir);
        assert_eq!(ir.params[0].ty.to_string(), "struct sub_0_a0 *");
        assert_eq!(
            ir.structures[0].fields,
            vec![(0, CType::U32), (8, CType::U64)]
        );
        assert_eq!(ir.structures[0].size, None);
    }

    #[test]
    fn overlapping_fields_make_no_structure() {
        let mut ir = pointer_function(vec![store(0, 8), store(4, 4)]);
        recover(&mut ir);
        assert!(ir.structures.is_empty());
        assert_eq!(ir.params[0].ty, CType::pointer_to(CType::U32));
    }

    #[test]
    fn fields_at_a_scaled_index_make_an_array_of_structures() {
        let mut ir = pointer_function(vec![
            Stmt::Store {
                addr: element(Expr::reg(7, 64), Expr::reg(6, 64), 0x10, 0),
                value: Expr::Const(0),
                width: 8,
            },
            Stmt::Ret {
                value: load(
                    element(Expr::reg(7, 64), Expr::reg(6, 64), 0x10, 0xc),
                    2,
                    true,
                ),
            },
        ]);
        recover(&mut ir);
        assert_eq!(ir.params[0].ty.to_string(), "struct sub_0_a0 *");
        let structure = &ir.structures[0];
        assert_eq!(structure.size, Some(0x10));
        assert_eq!(
            structure.fields,
            vec![
                (0, CType::U64),
                (
                    0xc,
                    CType::Int {
                        bytes: 2,
                        signed: true
                    }
                )
            ]
        );
    }

    #[test]
    fn pointers_stepping_through_the_array_place_their_fields() {
        // v1 = a0 + i * 0x18 + 0x10, stepped by whole elements; v2 points
        // at the start of one.
        let (v1, v2) = (VARIABLE_BASE, VARIABLE_BASE + 1);
        let mut ir = pointer_function(vec![
            assign(v1, element(Expr::reg(7, 64), Expr::reg(6, 64), 0x18, 0x10)),
            assign(
                v2,
                Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::Const(0x30)),
            ),
            assign(
                0,
                Expr::bin(
                    BinOp::Add,
                    load(
                        Expr::bin(BinOp::Sub, Expr::reg(v1, 64), Expr::Const(8)),
                        8,
                        false,
                    ),
                    load(Expr::reg(v1, 64), 2, true),
                ),
            ),
            assign(
                v1,
                Expr::bin(BinOp::Add, Expr::reg(v1, 64), Expr::Const(0x18)),
            ),
            Stmt::Store {
                addr: Expr::bin(BinOp::Add, Expr::reg(v2, 64), Expr::Const(8)),
                value: Expr::Const(0),
                width: 8,
            },
            Stmt::Ret {
                value: Expr::reg(0, 64),
            },
        ]);
        recover(&mut ir);
        let structure = &ir.structures[0];
        assert_eq!(structure.size, Some(0x18));
        assert_eq!(
            structure.fields,
            vec![
                (8, CType::U64),
                (
                    0x10,
                    CType::Int {
                        bytes: 2,
                        signed: true
                    }
                )
            ]
        );
        assert_eq!(structure.elements, vec![v1, v2]);
    }

    #[test]
    fn a_parameter_kept_on_the_stack_is_indexed_through_its_slot() {
        let slot = Expr::bin(
            BinOp::Add,
            Expr::reg(4, 64),
            Expr::Const(0xffff_ffff_ffff_fff8),
        );
        let kept = || load(slot.clone(), 8, false);
        let mut ir = pointer_function(vec![
            Stmt::Store {
                addr: slot.clone(),
                value: Expr::reg(7, 64),
                width: 8,
            },
            Stmt::Store {
                addr: element(kept(), Expr::reg(6, 64), 0xc, 0),
                value: Expr::Const(0),
                width: 4,
            },
            Stmt::Store {
                addr: element(kept(), Expr::reg(6, 64), 0xc, 8),
                value: Expr::Const(0),
                width: 4,
            },
        ]);
        recover(&mut ir);
        assert_eq!(ir.structures[0].size, Some(0xc));
        assert_eq!(
            ir.structures[0].fields,
            vec![(0, CType::U32), (8, CType::U32)]
        );
    }

    /// A loop reading `widths` at successive offsets from a pointer that
    /// steps `step` bytes a turn.
    fn stepping(widths: &[u8], step: u64) -> FunctionIr {
        let pointer = VARIABLE_BASE;
        let mut stmts = vec![assign(pointer, Expr::reg(7, 64))];
        let mut offset = 0;
        for width in widths {
            stmts.push(assign(
                VARIABLE_BASE + 1 + offset as u16,
                load(
                    Expr::bin(BinOp::Add, Expr::reg(pointer, 64), Expr::Const(offset)),
                    *width,
                    false,
                ),
            ));
            offset += 8;
        }
        stmts.push(assign(
            pointer,
            Expr::bin(BinOp::Add, Expr::reg(pointer, 64), Expr::Const(step)),
        ));
        pointer_function(stmts)
    }

    #[test]
    fn a_loop_taking_two_elements_a_turn_steps_by_one() {
        let mut ir = stepping(&[8, 4, 8, 4], 0x20);
        recover(&mut ir);
        assert_eq!(ir.structures[0].size, Some(0x10));
        assert_eq!(
            ir.structures[0].fields,
            vec![(0, CType::U64), (8, CType::U32)]
        );
    }

    #[test]
    fn a_loop_copying_words_stays_on_scalars() {
        let mut ir = stepping(&[8, 8, 8, 8], 0x20);
        recover(&mut ir);
        assert!(ir.structures.is_empty());
    }

    #[test]
    fn a_loop_over_elements_with_unread_fields_keeps_their_size() {
        let mut ir = stepping(&[4, 4], 0x18);
        recover(&mut ir);
        assert_eq!(ir.structures[0].size, Some(0x18));
    }

    #[test]
    fn an_index_scaled_in_a_register_of_its_own_is_put_back() {
        let scaled = VARIABLE_BASE;
        let at = |offset: u64| {
            Expr::bin(
                BinOp::Add,
                Expr::bin(BinOp::Add, Expr::reg(7, 64), Expr::reg(scaled, 64)),
                Expr::Const(offset),
            )
        };
        let mut ir = pointer_function(vec![
            assign(
                scaled,
                Expr::bin(BinOp::Shl, Expr::reg(6, 64), Expr::Const(4)),
            ),
            Stmt::Store {
                addr: at(0),
                value: Expr::Const(0),
                width: 8,
            },
            Stmt::Ret {
                value: load(at(8), 4, false),
            },
        ]);
        recover(&mut ir);
        assert_eq!(ir.structures[0].size, Some(0x10));
        let stmts = &ir.blocks[0].stmts;
        assert_eq!(stmts.len(), 2, "{stmts:?}");
        assert!(matches!(
            &stmts[0],
            Stmt::Store { addr, .. }
                if *addr == element(Expr::reg(7, 64), Expr::reg(6, 64), 0x10, 0)
        ));
    }

    #[test]
    fn an_integer_only_offset_points_into_an_array() {
        let element = VARIABLE_BASE;
        let mut ir = pointer_function(vec![
            assign(
                element,
                Expr::bin(
                    BinOp::Add,
                    Expr::bin(BinOp::Mul, Expr::reg(6, 64), Expr::Const(0xc)),
                    Expr::reg(7, 64),
                ),
            ),
            Stmt::Store {
                addr: Expr::reg(element, 64),
                value: Expr::Const(0),
                width: 4,
            },
            Stmt::Store {
                addr: Expr::bin(BinOp::Add, Expr::reg(element, 64), Expr::Const(8)),
                value: Expr::Const(0),
                width: 4,
            },
            Stmt::Ret {
                value: Expr::reg(7, 64),
            },
        ]);
        ir.params[0].ty = CType::I64;
        recover(&mut ir);
        assert_eq!(ir.params[0].ty.to_string(), "struct sub_0_a0 *");
        assert_eq!(ir.structures[0].size, Some(0xc));
        assert_eq!(ir.structures[0].elements, vec![element]);
    }

    #[test]
    fn an_integer_computed_with_is_no_pointer() {
        let mut ir = pointer_function(vec![
            Stmt::Store {
                addr: element(Expr::reg(7, 64), Expr::reg(6, 64), 0x10, 0),
                value: Expr::Const(0),
                width: 8,
            },
            Stmt::Store {
                addr: element(Expr::reg(7, 64), Expr::reg(6, 64), 0x10, 8),
                value: Expr::Const(0),
                width: 8,
            },
            Stmt::Ret {
                value: Expr::bin(BinOp::Mul, Expr::reg(7, 64), Expr::Const(3)),
            },
        ]);
        ir.params[0].ty = CType::I64;
        recover(&mut ir);
        assert!(ir.structures.is_empty());
        assert_eq!(ir.params[0].ty, CType::I64);
    }

    #[test]
    fn fields_c_would_place_elsewhere_make_no_array() {
        // A 4-byte field at offset 2 would be padded to offset 4 in C.
        let mut ir = pointer_function(vec![
            Stmt::Store {
                addr: element(Expr::reg(7, 64), Expr::reg(6, 64), 8, 0),
                value: Expr::Const(0),
                width: 2,
            },
            Stmt::Store {
                addr: element(Expr::reg(7, 64), Expr::reg(6, 64), 8, 2),
                value: Expr::Const(0),
                width: 4,
            },
        ]);
        recover(&mut ir);
        assert!(ir.structures.is_empty());
    }

    #[test]
    fn a_scalar_array_stays_one() {
        // a0[i] and a0[i + 1] are the same field of a 4-byte element.
        let mut ir = pointer_function(vec![
            Stmt::Store {
                addr: element(Expr::reg(7, 64), Expr::reg(6, 64), 4, 0),
                value: Expr::Const(0),
                width: 4,
            },
            Stmt::Store {
                addr: element(Expr::reg(7, 64), Expr::reg(6, 64), 4, 4),
                value: Expr::Const(0),
                width: 4,
            },
        ]);
        recover(&mut ir);
        assert!(ir.structures.is_empty());
        assert_eq!(ir.params[0].ty, CType::pointer_to(CType::U32));
    }
}

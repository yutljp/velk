use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::ir::{CType, CallKind, Expr, FunctionIr, Stmt, Structure};

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Node {
    Register(usize, u16),
    Return(usize),
    Global(u64),
    Address(u64),
    Computed(usize, usize),
    Field(usize, u16, u64),
}

fn field_address(value: &Expr) -> Option<(u16, u64)> {
    match value {
        Expr::Reg { index, width: 64 } => Some((*index, 0)),
        Expr::Bin {
            op: crate::ir::BinOp::Add,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Reg { index, width: 64 }, Expr::Const(offset))
            | (Expr::Const(offset), Expr::Reg { index, width: 64 })
                if *offset < 1 << 31 =>
            {
                Some((*index, *offset))
            }
            _ => None,
        },
        _ => None,
    }
}

fn structure_name(ty: &CType) -> Option<&str> {
    match ty {
        CType::Pointer(target) => match target.as_ref() {
            CType::Named(name) => name.strip_prefix("struct "),
            _ => None,
        },
        _ => None,
    }
}

fn immutable(value: &Expr, stable: &dyn Fn(u16) -> bool) -> bool {
    match value {
        Expr::Reg { index, width: 64 } => stable(*index),
        Expr::Const(_) => true,
        Expr::Bin { lhs, rhs, .. } => immutable(lhs, stable) && immutable(rhs, stable),
        _ => false,
    }
}

struct Components {
    nodes: BTreeMap<Node, Vec<Node>>,
    seeds: BTreeMap<Node, Structure>,
}

fn components(functions: &[&mut FunctionIr], data_ranges: &[(u64, u64)]) -> Components {
    let addresses: HashMap<_, _> = functions
        .iter()
        .enumerate()
        .map(|(i, ir)| (ir.addr, i))
        .collect();
    let writes: Vec<HashMap<u16, usize>> = functions
        .iter()
        .map(|ir| {
            let mut writes = HashMap::new();
            for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
                // Call clobbers describe machine registers, while the IR's
                // live results have explicit destinations of their own.
                let defined = match stmt {
                    Stmt::Call { outputs, .. } => {
                        outputs.iter().map(|output| output.dest.index).collect()
                    }
                    _ => crate::ir::visit::statement_registers(stmt).0,
                };
                for register in defined {
                    *writes.entry(register).or_insert(0) += 1;
                }
            }
            writes
        })
        .collect();
    let stable = |i: usize, register: u16| {
        let count = writes[i].get(&register).copied().unwrap_or(0);
        if functions[i]
            .params
            .iter()
            .any(|param| param.index == register)
        {
            count == 0
        } else {
            count == 1 && register >= crate::ir::TEMP_BASE
        }
    };
    let data_address = |address: u64| {
        data_ranges
            .iter()
            .any(|(start, size)| address >= *start && address - start < *size)
    };
    let mut copies = Vec::new();
    for (i, ir) in functions.iter().enumerate() {
        for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
            if let Stmt::Assign {
                dest,
                value: Expr::Reg { index, width: 64 },
            } = stmt
                && dest.width == 64
                && stable(i, dest.index)
                && stable(i, *index)
            {
                copies.push((Node::Register(i, dest.index), Node::Register(i, *index)));
            }
        }
    }
    let mut bases = BTreeMap::new();
    for (root, aliases) in group_nodes(&copies, BTreeMap::new()).nodes {
        for alias in aliases {
            bases.insert(alias, root);
        }
    }
    let field = |i: usize, address: &Expr| {
        let Some((register, offset)) = field_address(address) else {
            return None;
        };
        if !stable(i, register) {
            return None;
        }
        let base = Node::Register(i, register);
        let Node::Register(_, register) = bases.get(&base).copied().unwrap_or(base) else {
            return None;
        };
        Some(Node::Field(i, register, offset))
    };
    let computed: Vec<BTreeMap<String, usize>> = functions
        .iter()
        .enumerate()
        .map(|(i, ir)| {
            let mut values = BTreeMap::new();
            for value in ir
                .blocks
                .iter()
                .flat_map(|block| &block.stmts)
                .flat_map(Stmt::operands)
            {
                if matches!(value, Expr::Bin { .. })
                    && immutable(value, &|register| stable(i, register))
                {
                    let next = values.len();
                    values.entry(format!("{value:?}")).or_insert(next);
                }
            }
            values
        })
        .collect();
    let node = |i: usize, value: &Expr| match value {
        Expr::Reg { index, width: 64 } if stable(i, *index) => Some(Node::Register(i, *index)),
        Expr::Load { addr, width: 8, .. } => match addr.as_ref() {
            Expr::Const(address) if data_address(*address) => Some(Node::Global(*address)),
            other => field(i, other),
        },
        Expr::Const(address) if data_address(*address) => Some(Node::Address(*address)),
        Expr::Bin { .. } => computed[i]
            .get(&format!("{value:?}"))
            .map(|index| Node::Computed(i, *index)),
        _ => None,
    };
    let mut edges = Vec::new();
    let mut seeds = BTreeMap::new();
    for (i, ir) in functions.iter().enumerate() {
        let mut named = HashMap::new();
        for (register, ty) in ir
            .params
            .iter()
            .map(|param| (param.index, &param.ty))
            .chain(ir.value_types.iter().map(|(register, ty)| (*register, ty)))
        {
            if stable(i, register)
                && let Some(name) = structure_name(ty)
                && let Some(layout) = ir.structures.iter().find(|layout| layout.name == name)
            {
                let own = Node::Register(i, register);
                if let Some(previous) = named.insert(name, own) {
                    edges.push((previous, own));
                }
                seeds.insert(own, layout.clone());
            }
        }
        for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
            match stmt {
                Stmt::Assign { dest, value } if dest.width == 64 && stable(i, dest.index) => {
                    if let Some(from) = node(i, value) {
                        edges.push((Node::Register(i, dest.index), from));
                    }
                }
                Stmt::Ret { value }
                    if ir.ret_type.is_pointer()
                        && ir.blocks.iter().flat_map(|block| &block.stmts).all(
                            |stmt| match stmt {
                                Stmt::Ret { value } => node(i, value).is_some(),
                                _ => true,
                            },
                        ) =>
                {
                    if let Some(from) = node(i, value) {
                        edges.push((Node::Return(i), from));
                    }
                }
                Stmt::Store {
                    addr: Expr::Const(address),
                    value,
                    width: 8,
                } if data_address(*address) => {
                    if let Some(from) = node(i, value) {
                        edges.push((Node::Global(*address), from));
                    }
                }
                Stmt::Store {
                    addr,
                    value,
                    width: 8,
                } => {
                    if let Some(field) = field(i, addr)
                        && let Some(from) = node(i, value)
                    {
                        edges.push((field, from));
                    }
                }
                Stmt::Call {
                    kind: CallKind::Invoke | CallKind::Tail,
                    target: Some(target),
                    through: None,
                    args: Some(args),
                    outputs,
                    convention,
                    ..
                } => {
                    let Some(&callee) = addresses.get(target) else {
                        continue;
                    };
                    for (arg, register) in args.iter().zip(convention.arguments()) {
                        let Some(param) = functions[callee]
                            .params
                            .iter()
                            .find(|param| param.index == *register)
                        else {
                            continue;
                        };
                        if stable(callee, param.index)
                            && param.ty.is_pointer()
                            && let Some(from) = node(i, arg)
                        {
                            edges.push((from, Node::Register(callee, param.index)));
                        }
                    }
                    for output in outputs {
                        if functions[callee].ret_type.is_pointer()
                            && Some(&output.register) == convention.results().first()
                            && output.dest.width == 64
                            && stable(i, output.dest.index)
                        {
                            edges
                                .push((Node::Register(i, output.dest.index), Node::Return(callee)));
                        }
                    }
                    if matches!(
                        stmt,
                        Stmt::Call {
                            kind: CallKind::Tail,
                            ..
                        }
                    ) && ir.ret_type.is_pointer()
                        && functions[callee].ret_type.is_pointer()
                    {
                        edges.push((Node::Return(i), Node::Return(callee)));
                    }
                }
                _ => {}
            }
        }
    }
    group_nodes(&edges, seeds)
}

fn group_nodes(edges: &[(Node, Node)], seeds: BTreeMap<Node, Structure>) -> Components {
    let mut groups: BTreeMap<Node, Node> = edges
        .iter()
        .flat_map(|(a, b)| [(*a, *a), (*b, *b)])
        .chain(seeds.keys().map(|node| (*node, *node)))
        .collect();
    // Propagate the lowest node to a fixed point, including recursive calls.
    loop {
        let mut changed = false;
        for (a, b) in edges {
            let root = groups[a].min(groups[b]);
            for node in [a, b] {
                if groups[node] != root {
                    groups.insert(*node, root);
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    let mut components: BTreeMap<Node, Vec<Node>> = BTreeMap::new();
    for (node, root) in groups {
        components.entry(root).or_default().push(node);
    }
    Components {
        nodes: components,
        seeds,
    }
}

struct MergedLayout {
    fields: Vec<(u64, CType)>,
    size: Option<u64>,
}

fn merge_layouts(
    nodes: &[Node],
    seeds: &BTreeMap<Node, Structure>,
    functions: &[&mut FunctionIr],
    touches: &mut HashMap<usize, Vec<super::structures::MemoryAccess>>,
) -> Option<MergedLayout> {
    let layouts: Vec<_> = nodes.iter().filter_map(|node| seeds.get(node)).collect();
    if layouts.is_empty()
        && nodes
            .iter()
            .filter(|node| matches!(node, Node::Register(..)))
            .count()
            < 2
    {
        return None;
    }
    let mut fields = BTreeMap::new();
    let mut size = layouts.first().and_then(|layout| layout.size);
    let mut valid = true;
    let mut accessed = BTreeSet::new();
    if layouts.is_empty() {
        for node in nodes {
            let Node::Register(i, register) = *node else {
                continue;
            };
            let local_touches = touches
                .entry(i)
                .or_insert_with(|| super::structures::memory_accesses(functions[i]));
            if let Some(stride) =
                super::structures::array_size(functions[i], register, local_touches)
            {
                if size.is_some_and(|size| size != stride) {
                    valid = false;
                }
                size = Some(stride);
            }
        }
    }
    for layout in &layouts {
        if layout.size != size {
            valid = false;
        }
        for (offset, ty) in &layout.fields {
            if let Some(previous) = fields.insert(*offset, ty.clone())
                && previous != *ty
            {
                valid = false;
            }
        }
    }
    for node in nodes {
        if seeds.contains_key(node) {
            continue;
        }
        if let Node::Register(i, register) = *node {
            let given = functions[i]
                .params
                .iter()
                .find(|param| param.index == register)
                .map(|param| &param.ty)
                .or_else(|| functions[i].value_types.get(&register));
            if given.is_some_and(|ty| matches!(ty, CType::Pointer(target) if matches!(target.as_ref(), CType::Named(_)))) {
                valid = false;
                continue;
            }
            let local_touches = touches
                .entry(i)
                .or_insert_with(|| super::structures::memory_accesses(functions[i]));
            let local = match size {
                Some(size) => {
                    super::structures::layout_with_size(functions[i], register, local_touches, size)
                }
                None => super::structures::layout_at_least(register, local_touches, 0),
            };
            match local {
                Some(local) => {
                    if !local.is_empty() {
                        accessed.insert((i, register));
                    }
                    for (offset, ty) in local {
                        if let Some(previous) = fields.insert(offset, ty.clone())
                            && previous != ty
                        {
                            valid = false;
                        }
                    }
                }
                None => valid = false,
            }
        }
    }
    let mut end = 0u64;
    for (offset, ty) in &fields {
        let Some(width) = CType::pointer_to(ty.clone()).pointee_size().map(u64::from) else {
            valid = false;
            break;
        };
        if width == 0
            || !offset.is_multiple_of(width)
            || *offset < end
            || size.is_some_and(|size| !size.is_multiple_of(width))
        {
            valid = false;
            break;
        }
        let Some(next) = offset.checked_add(width) else {
            valid = false;
            break;
        };
        end = next;
    }
    if size.is_some_and(|size| end > size) {
        valid = false;
    }
    if !valid || fields.len() < 2 || (layouts.is_empty() && accessed.len() < 2) {
        return None;
    }
    let fields: Vec<_> = fields.into_iter().collect();
    Some(MergedLayout { fields, size })
}

/// Share only whole pointer values whose register has a single definition.
/// Conflicting connected layouts are left unchanged as a group.
pub(crate) fn share(functions: &mut [&mut FunctionIr], data_ranges: &[(u64, u64)]) {
    functions.sort_by_key(|ir| ir.addr);
    let Components {
        nodes: components,
        seeds,
    } = components(functions, data_ranges);
    let mut touches = HashMap::new();
    let mut names: Vec<Structure> = Vec::new();
    let mut serial = 1;
    for nodes in components.values() {
        let Some(MergedLayout { fields, size }) =
            merge_layouts(nodes, &seeds, functions, &mut touches)
        else {
            continue;
        };
        let name = if let Some(known) = names
            .iter()
            .find(|known| known.fields == fields && known.size == size)
        {
            known.name.clone()
        } else {
            let name = loop {
                let name = format!("S{serial}");
                serial += 1;
                let conflicts = functions.iter().any(|ir| {
                    ir.definitions.iter().any(|definition| {
                        definition.name.split_whitespace().next_back() == Some(name.as_str())
                    }) || ir.structures.iter().any(|known| {
                        known.name == name && (known.fields != fields || known.size != size)
                    })
                });
                if !conflicts {
                    break name;
                }
            };
            names.push(Structure {
                fields: fields.clone(),
                size,
                name: name.clone(),
                elements: Vec::new(),
            });
            name
        };
        let ty = CType::pointer_to(CType::Named(format!("struct {name}")));
        let mut replacements: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
        for node in nodes {
            match *node {
                Node::Register(i, register) => {
                    if let Some(layout) = seeds.get(node) {
                        replacements
                            .entry(i)
                            .or_default()
                            .insert(layout.name.clone());
                    }
                    let ir = &mut functions[i];
                    if let Some(param) = ir.params.iter_mut().find(|param| param.index == register)
                    {
                        if param.ty.is_pointer() {
                            param.ty = ty.clone();
                        }
                    } else if ir.value_types.get(&register).is_some_and(CType::is_pointer)
                        || ir.pointer_values.contains(&register)
                    {
                        ir.value_types.insert(register, ty.clone());
                    }
                }
                Node::Return(i) if functions[i].ret_type.is_pointer() => {
                    functions[i].ret_type = ty.clone()
                }
                _ => {}
            }
        }
        for (i, old) in replacements {
            let ir = &mut functions[i];
            let mut elements = Vec::new();
            ir.structures.retain(|layout| {
                if old.contains(&layout.name) {
                    elements.extend(&layout.elements);
                    false
                } else {
                    true
                }
            });
            // Return types and aliases can name the same local definition.
            for current in ir
                .params
                .iter_mut()
                .map(|param| &mut param.ty)
                .chain(ir.value_types.values_mut())
                .chain(std::iter::once(&mut ir.ret_type))
            {
                if structure_name(current).is_some_and(|name| old.contains(name)) {
                    *current = ty.clone();
                }
            }
            elements.sort_unstable();
            elements.dedup();
            if let Some(known) = ir.structures.iter_mut().find(|layout| layout.name == name) {
                known.elements.extend(elements);
                known.elements.sort_unstable();
                known.elements.dedup();
            } else {
                ir.structures.push(Structure {
                    name: name.clone(),
                    fields: fields.clone(),
                    size,
                    elements,
                });
            }
        }
        // Functions with only a partial access still need the shared declaration.
        for node in nodes {
            let (Node::Register(i, _) | Node::Return(i)) = *node else {
                continue;
            };
            let ir = &mut functions[i];
            if (ir.params.iter().any(|param| param.ty == ty)
                || ir.ret_type == ty
                || ir.value_types.values().any(|current| *current == ty))
                && !ir.structures.iter().any(|layout| layout.name == name)
            {
                ir.structures.push(Structure {
                    name: name.clone(),
                    fields: fields.clone(),
                    size,
                    elements: Vec::new(),
                });
            }
        }
    }
}

use super::unions::MemberIndex;
use super::{
    CType, Ctx, Expr, FunctionIr, HashMap, Locals, Node, Reference, Rendered, SegmentBase,
    SegmentBaseRead, Stmt, Symbols, abi, block_frames, calls, expr, globals, indent, int, naming,
    narrow_registers, params, render_expr, render_nodes, sanitize, stack_bytes, stack_pointer,
    type_of, variables,
};

#[must_use]
pub fn render(
    ir: &FunctionIr,
    references: &[Reference],
    symbols: &Symbols,
    data_ranges: &[(u64, u64)],
) -> String {
    render_with_dependencies(ir, references, symbols, data_ranges).code
}

/// Print entry segment reads as external providers without choosing their values.
#[must_use]
pub fn render_with_dependencies(
    ir: &FunctionIr,
    references: &[Reference],
    symbols: &Symbols,
    data_ranges: &[(u64, u64)],
) -> Rendered {
    crate::timing::scope!("render/function::render_with_dependencies");
    let original = render_unmerged(ir, references, symbols, data_ranges);
    let Some(merged) = super::structure::merge_exits::merged(ir) else {
        return original;
    };
    let candidate = render_unmerged(&merged, references, symbols, data_ranges);
    let lines = candidate.code.lines().count();
    let gotos = candidate.code.matches("goto ").count();
    let original_lines = original.code.lines().count();
    let original_gotos = original.code.matches("goto ").count();
    if lines <= original_lines
        && gotos <= original_gotos
        && (lines < original_lines || gotos < original_gotos)
    {
        candidate
    } else {
        original
    }
}

fn render_unmerged(
    ir: &FunctionIr,
    references: &[Reference],
    symbols: &Symbols,
    data_ranges: &[(u64, u64)],
) -> Rendered {
    let original = ir;
    let mut folded = ir.clone();
    for block in &mut folded.blocks {
        block.stmts.retain(|stmt| {
            !matches!(stmt,
                Stmt::Assign { dest, value: Expr::Reg { index, width: 64 } }
                    if dest.width == 64 && dest.index == *index
            )
        });
    }
    super::virtual_calls::prepare(&mut folded, symbols);
    let variadic = super::variadic::prepare(&mut folded, symbols);
    crate::analysis::variadic::drop_register_saves(&mut folded);
    params::fold_saved_parameters(&mut folded);
    // A saved parameter returned reads as the parameter now.
    crate::analysis::typing::apply_pointer_return(&mut folded);
    naming::roles::name_parameters(&mut folded, symbols);
    let float_entries = physical_float_parameters(&mut folded);
    let mut logical = abi::prepare(&mut folded, symbols);
    let mut incoming = if logical.is_none() {
        stack_bytes::prepare(&mut folded)
    } else {
        None
    };
    super::frame_registers::rebase(&mut folded);
    if crate::passes::copies::fold_debug_locals(&mut folded) {
        crate::passes::read_once::fold_values_read_once(&mut folded);
    }
    let types = variables::variable_types(
        &folded,
        &narrow_registers(&folded),
        float_return(&folded.ret_type),
    );
    variables::pointer_fields(&mut folded, &types);
    let ir = &folded;
    let frames = block_frames(ir, stack_pointer(ir.isa));
    let variable_types =
        variables::variable_types(ir, &narrow_registers(ir), float_return(&ir.ret_type));
    let (nodes, structured_ir) = super::structure::best_structure(ir);
    let block_addresses = structured_ir
        .blocks
        .iter()
        .map(|block| block.start)
        .collect();
    let roles = naming::roles::infer_with_nodes(ir, symbols, &nodes);
    let mut locals =
        super::locals::stack_locals_with_roles(ir, &frames, &variable_types, symbols, &roles);
    locals.bind_register_tops(original);
    if let Some(logical) = &mut logical {
        let params: std::collections::HashSet<_> =
            ir.params.iter().map(|param| param.index).collect();
        let mut reserved: std::collections::HashSet<String> = locals
            .decls
            .iter()
            .flat_map(|local| local.named())
            .map(|local| local.name.clone())
            .collect();
        for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
            let (writes, reads) = crate::ir::visit::statement_registers(stmt);
            for register in writes
                .into_iter()
                .chain(reads)
                .filter(|register| !params.contains(register))
            {
                reserved.insert(crate::ir::reg_name(ir.isa, register, 64));
                reserved.insert(crate::ir::reg_name(ir.isa, register, 32));
            }
        }
        logical.resolve_names(
            reserved,
            variable_types
                .values()
                .chain(
                    locals
                        .decls
                        .iter()
                        .flat_map(|local| local.named())
                        .filter_map(|local| local.ty.as_ref()),
                )
                .chain(ir.members.iter().map(|member| &member.ty))
                .chain(std::iter::once(&ir.ret_type))
                .map(ToString::to_string),
        );
    }
    if let Some(incoming) = &mut incoming {
        let mut reserved: std::collections::HashSet<String> = ir
            .params
            .iter()
            .map(|param| param.name.clone())
            .chain(ir.stack_params.iter().map(|param| param.name.clone()))
            .chain(
                locals
                    .decls
                    .iter()
                    .flat_map(|local| local.named())
                    .map(|local| local.name.clone()),
            )
            .chain(symbols.functions.values().map(|name| sanitize(name)))
            .chain(symbols.import_slots.values().map(|name| sanitize(name)))
            .chain(symbols.data.values().map(|name| sanitize(name)))
            .chain(symbols.reserved_names.iter().cloned())
            .collect();
        for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
            let (writes, reads) = crate::ir::visit::statement_registers(stmt);
            reserved.extend(
                writes
                    .into_iter()
                    .chain(reads)
                    .map(|index| crate::ir::reg_name(ir.isa, index, 64)),
            );
        }
        reserved.insert("__builtin_memcpy".to_owned());
        if let Some(name) = &ir.name {
            reserved.insert(sanitize(name));
        }
        for ty in ir
            .params
            .iter()
            .map(|param| &param.ty)
            .chain(ir.stack_params.iter().map(|param| &param.ty))
            .chain(variable_types.values())
            .chain(
                locals
                    .decls
                    .iter()
                    .flat_map(|local| local.named())
                    .filter_map(|local| local.ty.as_ref()),
            )
            .chain(ir.members.iter().map(|member| &member.ty))
            .chain(std::iter::once(&ir.ret_type))
        {
            reserved.extend(
                ty.to_string()
                    .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
                    .filter(|part| !part.is_empty())
                    .map(str::to_owned),
            );
        }
        incoming.name = vacant_name("incoming_bytes", &mut reserved);
    }
    render_with(
        ir,
        references,
        locals,
        symbols,
        data_ranges,
        EntryStorage {
            variadic: variadic.as_ref(),
            logical: logical.as_ref(),
            incoming: incoming.as_ref(),
            float_entries,
        },
        PreparedBody {
            nodes,
            roles,
            block_addresses,
        },
    )
}

/// The precision of a float the function returns.
fn float_return(ty: &CType) -> Option<crate::ir::Precision> {
    ty.is_sse_float().then(|| {
        if ty.to_string().contains("double") {
            crate::ir::Precision::Double
        } else {
            crate::ir::Precision::Single
        }
    })
}

/// The type the output declares each variable with.
pub(crate) fn variable_types(ir: &FunctionIr) -> std::collections::BTreeMap<u16, CType> {
    variables::variable_types(ir, &narrow_registers(ir), float_return(&ir.ret_type))
}

/// Whether C scales arithmetic on a pointer of this type: it points at
/// something wider than a byte.
fn scales(ty: &CType) -> bool {
    match ty {
        CType::Pointer(target) => {
            !matches!(target.as_ref(), CType::Void) && ty.pointee_size() != Some(1)
        }
        _ => false,
    }
}

struct EntryStorage<'a> {
    variadic: Option<&'a super::variadic::Plan>,
    logical: Option<&'a abi::Plan>,
    incoming: Option<&'a stack_bytes::Plan>,
    float_entries: std::collections::HashSet<u16>,
}

struct PreparedBody {
    nodes: Vec<Node>,
    block_addresses: std::collections::HashSet<u64>,
    roles: naming::roles::Roles,
}

fn render_with(
    ir: &FunctionIr,
    references: &[Reference],
    locals: Locals,
    symbols: &Symbols,
    data_ranges: &[(u64, u64)],
    entry: EntryStorage<'_>,
    body: PreparedBody,
) -> Rendered {
    let PreparedBody {
        mut nodes,
        roles,
        block_addresses,
    } = body;
    let EntryStorage {
        variadic,
        logical,
        incoming,
        float_entries,
    } = entry;
    let mut names: HashMap<u16, &str> = ir
        .params
        .iter()
        .filter(|param| {
            !(param.ty.is_sse_float() && crate::arch::vector_half(ir.isa, param.index).is_some())
        })
        .map(|param| (param.index, param.name.as_str()))
        .collect();
    if let Some(incoming) = incoming {
        names.insert(incoming.register, &incoming.name);
    }
    if let Some(logical) = logical {
        for capture in &logical.captures {
            if let Some(direct) = &capture.direct {
                names.insert(capture.register, direct);
            }
        }
    }
    let wide_params: std::collections::HashSet<u16> = ir
        .params
        .iter()
        .filter(|param| !param.ty.is_narrow())
        .map(|param| param.index)
        .collect();
    let narrow_regs = narrow_registers(ir);
    let float_return = float_return(&ir.ret_type);
    let mut variable_types = variables::variable_types(ir, &narrow_regs, float_return);
    if let Some(incoming) = incoming {
        variable_types.remove(&incoming.register);
    }
    if let Some(logical) = logical {
        for capture in &logical.captures {
            variable_types.remove(&capture.register);
        }
        for pointer in &logical.pointers {
            variable_types.remove(&pointer.register);
        }
    }
    let mut machine_reserved: std::collections::HashSet<String> = names
        .values()
        .map(|name| (*name).to_owned())
        .chain(ir.params.iter().map(|param| param.name.clone()))
        .chain(
            locals
                .decls
                .iter()
                .flat_map(|local| local.named())
                .map(|local| local.name.clone()),
        )
        .chain(ir.stack_params.iter().map(|param| param.name.clone()))
        .chain(
            variable_types
                .keys()
                .map(|index| crate::ir::reg_name(ir.isa, *index, 64)),
        )
        .chain(symbols.reserved_names.iter().cloned())
        .chain(symbols.functions.values().map(|name| sanitize(name)))
        .chain(symbols.import_slots.values().map(|name| sanitize(name)))
        .chain(symbols.data.values().map(|name| sanitize(name)))
        .collect();
    if let Some(logical) = logical {
        machine_reserved.extend(logical.reserved_names());
    }
    machine_reserved.insert(sanitize(
        &symbols
            .functions
            .get(&ir.addr)
            .cloned()
            .or_else(|| ir.name.clone())
            .unwrap_or_else(|| format!("sub_{:x}", ir.addr)),
    ));
    for ty in ir
        .params
        .iter()
        .map(|param| &param.ty)
        .chain(ir.stack_params.iter().map(|param| &param.ty))
        .chain(variable_types.values())
        .chain(
            locals
                .decls
                .iter()
                .flat_map(|local| local.named())
                .filter_map(|local| local.ty.as_ref()),
        )
        .chain(std::iter::once(&ir.ret_type))
    {
        machine_reserved.extend(
            ty.to_string()
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .filter(|name| !name.is_empty())
                .map(str::to_owned),
        );
    }
    // Any other machine register the body uses is a variable of its own;
    // Go keeps the running goroutine in r14.
    let (used_registers, written_registers) = machine_registers(ir, true);
    let readonly_floats = ir.params.iter()
        .filter(|param| float_entries.contains(&param.index) && !written_registers.contains(&param.index))
        .filter(|param| matches!(&param.ty, CType::Named(name) if name.split_whitespace().all(|word| matches!(word, "const" | "float" | "double"))))
        .filter_map(|param| self::float_return(&param.ty).map(|precision| (param.index, (param.name.clone(), precision))))
        .collect();
    let mut debug_names = Vec::new();
    for (register, source_name) in &ir.debug_registers {
        if ir
            .debug_registers
            .iter()
            .filter(|(other, _)| other == register)
            .count()
            != 1
        {
            continue;
        }
        let mut candidates = variable_types.keys().copied().filter(|index| {
            ir.variable_registers.get(index) == Some(register) && !names.contains_key(index)
        });
        let Some(index) = candidates.next() else {
            continue;
        };
        if candidates.next().is_some() {
            continue;
        }
        let base = if globals::reserved_identifier(source_name) {
            format!("{source_name}_2")
        } else {
            source_name.clone()
        };
        debug_names.push((index, vacant_name(&base, &mut machine_reserved)));
    }
    for (index, name) in &debug_names {
        names.insert(*index, name);
    }
    let role_names: Vec<_> = variable_types
        .keys()
        .copied()
        .filter(|index| !names.contains_key(index))
        .filter_map(|index| {
            roles
                .register(index)
                .map(|role| (index, vacant_name(role, &mut machine_reserved)))
        })
        .collect();
    for (index, name) in &role_names {
        names.insert(*index, name);
    }
    let machine: Vec<(u16, String)> = used_registers
        .into_iter()
        .filter(|index| !names.contains_key(index))
        .map(|index| {
            let name = if index == 14 && ir.convention == crate::ir::Convention::GoAmd64 {
                vacant_name("g", &mut machine_reserved)
            } else if let Some(role) = roles.register(index) {
                vacant_name(role, &mut machine_reserved)
            } else {
                variable_name(&mut machine_reserved)
            };
            (index, name)
        })
        .collect();
    for (index, name) in &machine {
        names.insert(*index, name);
    }
    // The printer introduces reads of physical call results not present as IR operands.
    let machine_ints = machine
        .iter()
        .map(|(index, _)| *index)
        .filter(|index| {
            written_registers.contains(index)
                && crate::arch::vector_half(ir.isa, *index).is_none()
                && !ir.blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
                    stmt.call_outputs()
                        .iter()
                        .any(|output| output.register == *index)
                })
        })
        .collect();
    let machine_widths = crate::render::widths::narrow_variables(
        ir,
        &machine_ints,
        &narrow_regs,
        &Default::default(),
    );
    for (index, width) in machine_widths {
        variable_types.insert(index, CType::int((width.bits().max(32) / 8) as u8, false));
    }
    let original_word_types = variable_types
        .iter()
        .map(|(index, ty)| (*index, ty.clone()))
        .chain(
            ir.params
                .iter()
                .map(|param| (param.index, param.ty.clone())),
        )
        .collect::<HashMap<_, _>>();
    let go_groups =
        super::go_values::groups(ir, symbols, &mut variable_types, &mut machine_reserved);
    for group in &go_groups {
        for (index, name, _) in &group.fields {
            names.insert(*index, name);
        }
    }
    let mut declared_registers =
        declared_types(ir, &variable_types, machine.iter().map(|(index, _)| *index));
    for group in &go_groups {
        for (index, _, ty) in &group.fields {
            if let Some(ty) = declared(ty, false) {
                declared_registers.insert(*index, ty);
            }
        }
    }
    let floats: HashMap<u16, crate::ir::Precision> = variable_types
        .iter()
        .chain(
            ir.params
                .iter()
                .filter(|param| crate::arch::vector_half(ir.isa, param.index).is_none())
                .map(|param| (&param.index, &param.ty)),
        )
        .filter_map(|(index, ty)| match ty.to_string().as_str() {
            "double" => Some((*index, crate::ir::Precision::Double)),
            "float" => Some((*index, crate::ir::Precision::Single)),
            _ => None,
        })
        .collect();
    // Each field of a recovered structure, and for the fields that share a
    // cell, the union member naming each.
    let mut member_views: HashMap<(String, i64), Vec<crate::ir::Member>> = HashMap::new();
    let mut members: HashMap<(String, i64), crate::ir::Member> = ir
        .members
        .iter()
        .cloned()
        .map(|member| ((member.structure.clone(), member.offset), member))
        .collect();
    for structure in &ir.structures {
        for (start, size, fields) in super::unions::cells(&structure.fields) {
            let Ok(start) = i64::try_from(start) else {
                continue;
            };
            let name = format!("field_0x{start:x}");
            if let [(_, ty)] = fields.as_slice() {
                members.insert(
                    (structure.name.clone(), start),
                    crate::ir::Member {
                        structure: structure.name.clone(),
                        offset: start,
                        name,
                        ty: ty.clone(),
                        width: size,
                    },
                );
                continue;
            }
            let Ok(start_u64) = u64::try_from(start) else {
                continue;
            };
            let views = union_views(start_u64, &fields);
            for (offset, width, signed) in &views {
                let indexed = views
                    .iter()
                    .any(|(other, size, _)| size == width && *other != 0);
                let member = super::unions::member(
                    *width,
                    *signed,
                    *offset,
                    if indexed {
                        MemberIndex::Array
                    } else {
                        MemberIndex::Scalar
                    },
                );
                let at = start.saturating_add(*offset);
                member_views
                    .entry((structure.name.clone(), at))
                    .or_default()
                    .push(crate::ir::Member {
                        structure: structure.name.clone(),
                        offset: at,
                        name: format!("{name}.{member}"),
                        ty: CType::int(*width, *signed),
                        width: u64::from(*width),
                    });
            }
        }
    }
    let mut arrays: HashMap<String, naming::Layout> = ir
        .structures
        .iter()
        .filter_map(|structure| {
            let Some(size) = structure.size else {
                return None;
            };
            let layout = naming::Layout { size };
            Some((structure.name.clone(), layout))
        })
        .collect();
    super::layouts::add_debug(ir, &mut arrays);
    let mut scaled: std::collections::HashSet<u16> = ir
        .params
        .iter()
        .map(|param| (param.index, &param.ty))
        .chain(variable_types.iter().map(|(index, ty)| (*index, ty)))
        .filter(|(_, ty)| scales(ty))
        .map(|(index, _)| index)
        .collect();
    for group in &go_groups {
        for (index, _, ty) in &group.fields {
            if !scales(ty) {
                scaled.remove(index);
            }
        }
    }
    let element_types = ir
        .params
        .iter()
        .map(|param| (param.index, &param.ty))
        .chain(variable_types.iter().map(|(index, ty)| (*index, ty)))
        .filter_map(|(index, ty)| match ty {
            CType::Pointer(target) => Some((index, target.as_ref().clone())),
            _ => None,
        })
        .collect();
    // `char` alone, which is neither `signed char` nor `unsigned char`.
    let plain_char = |ty: &CType| match ty {
        CType::Pointer(target) => match target.as_ref() {
            CType::Named(name) => name
                .split_whitespace()
                .filter(|word| !matches!(*word, "const" | "volatile"))
                .eq(["char"]),
            _ => false,
        },
        _ => false,
    };
    let mut plain_chars: std::collections::HashSet<String> = ir
        .params
        .iter()
        .filter(|param| plain_char(&param.ty))
        .map(|param| param.name.clone())
        .collect();
    plain_chars.extend(
        variable_types
            .iter()
            .filter(|(_, ty)| plain_char(ty))
            .map(|(index, _)| match names.get(index) {
                Some(name) => (*name).to_owned(),
                None => crate::ir::reg_name(ir.isa, *index, 64),
            }),
    );
    plain_chars.extend(
        locals
            .decls
            .iter()
            .flat_map(|local| local.named())
            .filter(|local| local.ty.as_ref().is_some_and(plain_char))
            .map(|local| local.name.clone()),
    );
    let local_types = || {
        locals
            .decls
            .iter()
            .flat_map(|local| local.named())
            .filter_map(|local| local.ty.as_ref().map(|ty| (local.name.clone(), ty)))
    };
    let local_element_types = local_types()
        .filter_map(|(name, ty)| match ty {
            CType::Pointer(target) => Some((name, target.as_ref().clone())),
            _ => None,
        })
        .collect();
    let local_scaled = local_types()
        .filter(|(_, ty)| scales(ty))
        .map(|(name, _)| name)
        .collect();
    let mut reserved: Vec<String> = names
        .values()
        .map(|name| (*name).to_owned())
        .chain(
            locals
                .decls
                .iter()
                .flat_map(|local| local.named())
                .map(|local| local.name.clone()),
        )
        .chain(ir.stack_params.iter().map(|param| param.name.clone()))
        .chain(
            variable_types
                .keys()
                .map(|index| crate::ir::reg_name(ir.isa, *index, 64)),
        )
        .chain(symbols.functions.values().map(|name| sanitize(name)))
        .chain(symbols.import_slots.values().map(|name| sanitize(name)))
        .collect();
    if let Some(logical) = logical {
        reserved.extend(logical.reserved_names());
    }
    reserved.push(sanitize(
        &symbols
            .functions
            .get(&ir.addr)
            .cloned()
            .or_else(|| ir.name.clone())
            .unwrap_or_else(|| format!("sub_{:x}", ir.addr)),
    ));
    reserved.extend(ir.blocks.iter().flat_map(|block| &block.stmts).filter_map(
        |stmt| match stmt {
            Stmt::Call {
                target: Some(target),
                through: None,
                ..
            } if !symbols.functions.contains_key(target) => Some(format!("sub_{target:x}")),
            _ => None,
        },
    ));
    for ty in ir
        .params
        .iter()
        .map(|param| &param.ty)
        .chain(ir.stack_params.iter().map(|param| &param.ty))
        .chain(variable_types.values())
        .chain(
            locals
                .decls
                .iter()
                .flat_map(|local| local.named())
                .filter_map(|local| local.ty.as_ref()),
        )
        .chain(std::iter::once(&ir.ret_type))
    {
        reserved.extend(
            ty.to_string()
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .filter(|name| !name.is_empty())
                .map(str::to_owned),
        );
    }
    let return_slot = if ir.isa == crate::loader::Isa::X86_64
        && matches!(
            ir.convention,
            crate::ir::Convention::GoAmd64
                | crate::ir::Convention::GoAbi0
                | crate::ir::Convention::Win64
        ) {
        let mut used = reserved
            .iter()
            .cloned()
            .chain(symbols.reserved_names.iter().cloned())
            .chain(symbols.data.values().map(|name| sanitize(name)))
            .collect();
        let provider = vacant_name("velk_return_address_slot", &mut used);
        reserved.push(provider.clone());
        Some(provider)
    } else {
        None
    };
    let mut reads = std::collections::HashSet::new();
    if ir.isa == crate::loader::Isa::X86_64 {
        for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
            for value in stmt.operands() {
                crate::ir::visit::expr_reads(value, &mut reads);
            }
        }
    }
    let needed: Vec<_> = [
        (SegmentBase::Fs, crate::arch::x86::FS_BASE, "fs"),
        (SegmentBase::Gs, crate::arch::x86::GS_BASE, "gs"),
    ]
    .into_iter()
    .filter(|(_, index, _)| reads.contains(index) && !names.contains_key(index))
    .collect();
    let mut segment_bases = Vec::new();
    if !needed.is_empty() {
        let mut segment_reserved: std::collections::HashSet<String> = reserved
            .iter()
            .cloned()
            .chain(symbols.reserved_names.iter().cloned())
            .chain(symbols.data.values().map(|name| sanitize(name)))
            .collect();
        for (segment, index, base) in needed {
            let provider = vacant_name(&format!("velk_x86_{base}_base"), &mut segment_reserved);
            let snapshot = vacant_name(&format!("{base}_base"), &mut segment_reserved);
            reserved.extend([provider.clone(), snapshot.clone()]);
            declared_registers.insert(index, declared(&CType::U64, false).expect("an integer"));
            segment_bases.push((segment, index, provider, snapshot));
        }
    }
    for (_, index, _, snapshot) in &segment_bases {
        names.insert(*index, snapshot);
    }
    let mut call_reserved: std::collections::HashSet<String> = reserved
        .iter()
        .cloned()
        .chain(symbols.reserved_names.iter().cloned())
        .chain(symbols.data.values().map(|name| sanitize(name)))
        .collect();
    let mut call_outputs = calls::Outputs::new(ir, &machine, &mut call_reserved);
    if !symbols.objc_selectors.is_empty() {
        call_outputs.find_selector_slots(ir);
    }
    if !call_outputs.temporary.is_empty() {
        reserved.push(call_outputs.temporary.clone());
    }
    reserved.extend(call_outputs.declarations.iter().cloned());
    let exception_providers: Vec<_> = [
        (crate::ir::EXCEPTION, "velk_exception_value"),
        (crate::ir::SELECTOR, "velk_exception_selector"),
    ]
    .into_iter()
    .map(|(index, base)| {
        let provider = vacant_name(base, &mut call_reserved);
        (index, format!("{provider}()"), provider)
    })
    .collect();
    for (index, expression, _) in &exception_providers {
        names.insert(*index, expression);
    }
    let mut value_bits = int::value_bits(ir);
    for index in &float_entries {
        value_bits.remove(index);
    }
    if let Some(logical) = logical {
        for capture in &logical.captures {
            declared_registers.insert(
                capture.register,
                declared(
                    &ir.params
                        .iter()
                        .find(|param| param.index == capture.register)
                        .map_or(CType::U64, |param| param.ty.clone()),
                    false,
                )
                .expect("an integer"),
            );
            value_bits.remove(&capture.register);
        }
    }
    let mut ctx = Ctx {
        variadic,
        callee_signatures: ir.callee_signatures.clone(),
        go_word_types: go_groups
            .iter()
            .flat_map(|group| &group.fields)
            .filter_map(|(index, _, _)| {
                original_word_types
                    .get(index)
                    .map(|ty| (*index, ty.clone()))
            })
            .collect(),
        abi: logical,
        call_outputs,
        virtual_tables: super::virtual_calls::Tables::new(ir, symbols, &mut call_reserved),
        block_addresses,
        jump_provider: vacant_name("velk_jump_target", &mut call_reserved),
        isa: ir.isa,
        void_return: ir.ret_type == CType::Void,
        float_return,
        readonly_floats,
        names,
        landing_pads: ir.landing_pads.iter().cloned().collect(),
        strings: references
            .iter()
            .filter(|reference| reference.pointer.is_none())
            .filter_map(|reference| reference.text.clone().map(|text| (reference.addr, text)))
            .collect(),
        slots: locals.slots,
        parameter_addresses: locals.parameter_addresses,
        parameter_reads: locals.parameter_reads,
        local_parts: locals.parts,
        transfer_addresses: locals.transfer_addresses,
        frame_origins: super::provenance::frame_origins(ir),
        frame_addresses: Vec::new(),
        local_widths: locals.widths,
        local_aggregates: super::aggregates::layouts(&locals.decls),
        local_views: locals.views,
        local_pointer_types: locals
            .decls
            .iter()
            .flat_map(|local| local.named())
            .filter_map(|local| {
                let Some(ty) = local.ty.as_ref().filter(|ty| ty.is_pointer()) else {
                    return None;
                };
                Some((local.name.clone(), ty.to_string().trim_end().to_owned()))
            })
            .collect(),
        local_floats: locals
            .decls
            .iter()
            .flat_map(|local| local.named())
            .filter_map(|local| {
                let Some(ty) = &local.ty else {
                    return None;
                };
                let precision = match ty.to_string().as_str() {
                    "double" => crate::ir::Precision::Double,
                    "float" => crate::ir::Precision::Single,
                    _ => return None,
                };
                Some((local.name.clone(), precision))
            })
            .collect(),
        signed_locals: locals
            .decls
            .iter()
            .flat_map(|local| local.named())
            .filter(|local| match &local.ty {
                Some(ty) => ty.integer().is_some_and(|(_, signed)| signed),
                None => local.signed,
            })
            .map(|local| local.name.clone())
            .collect(),
        local_element_types,
        local_scaled,
        wide_params,
        symbols,
        globals: {
            let mut globals = globals::Globals::new(symbols, reserved);
            globals.add_types(ir, &arrays);
            globals
        },
        data_ranges,
        members,
        member_views,
        element_types,
        plain_chars,
        arrays,
        scaled_offsets: if ir.members.is_empty() {
            HashMap::new()
        } else {
            naming::scaled_offsets(ir)
        },
        narrow_regs,
        floats,
        scaled,
        returned: declared(&ir.ret_type, false),
        declared: declared_registers,
        pointer_types: ir
            .params
            .iter()
            .map(|param| (param.index, &param.ty))
            .chain(variable_types.iter().map(|(index, ty)| (*index, ty)))
            .filter(|(_, ty)| ty.is_pointer())
            .map(|(index, ty)| (index, ty.to_string().trim_end().to_owned()))
            .collect(),
        ret_pointer: ir
            .ret_type
            .is_pointer()
            .then(|| ir.ret_type.to_string().trim_end().to_owned()),
        value_bits,
        read_once: Default::default(),
        transfer_values: super::transfers::single_use_loads(ir),
        taken: Default::default(),
    };
    super::go_values::bind_stack(&go_groups, &mut ctx);
    for index in [crate::ir::EXCEPTION, crate::ir::SELECTOR] {
        ctx.pointer_types.remove(&index);
        ctx.element_types.remove(&index);
        ctx.floats.remove(&index);
        ctx.declared
            .insert(index, declared(&CType::U64, false).expect("an integer"));
    }
    if let Some(incoming) = incoming {
        ctx.pointer_types
            .insert(incoming.register, "unsigned char *".to_owned());
        for &(offset, width) in &incoming.accesses {
            let address = render_expr(&incoming.address(offset), &ctx);
            ctx.parameter_addresses
                .insert((address.clone(), width), address);
        }
    }

    if let Some(provider) = &return_slot {
        super::locals::bind_return_slot(ir, provider, &mut ctx);
    }
    let mut out = String::new();
    out.push_str(&super::prelude::section(&super::go_values::definitions(
        &go_groups,
    )));
    out.push_str(&super::prelude::section(
        &super::vector_helpers::definitions(ir),
    ));
    let name = ir
        .name
        .clone()
        .unwrap_or_else(|| format!("sub_{:x}", ir.addr));
    out.push_str(&format!("/* velk pseudo-C: {name} @ 0x{:x} */\n", ir.addr));
    // The function goes by the name its callers use.
    let name = symbols.functions.get(&ir.addr).cloned().unwrap_or(name);
    for reference in references {
        out.push_str(&format!("/* ref: {} */\n", reference.describe()));
    }
    // A pointer read as one scalar is no structure, and one to a structure
    // the debug info names needs no note of its fields.
    for (access, line) in ir.accesses.iter().zip(ir.access_lines()) {
        if naming::scalar_pointer(&Expr::reg(access.register, 64), &ctx).is_none()
            && !ctx.element_types.get(&access.register).is_some_and(
                |target| matches!(target, CType::Named(name) if name.starts_with("struct ")),
            )
        {
            out.push_str(&format!("/* struct: {line} */\n"));
        }
    }
    // Each definition, to drop the ones nothing in the function names once
    // it is written: folding values into their readers can leave a
    // structure without its variable.
    let mut definitions: Vec<(String, String)> = Vec::new();
    let definitions_at = out.len();
    for structure in &ir.structures {
        let definition = structure_definition(structure);
        out.push_str(&definition);
        definitions.push((structure.name.clone(), definition));
    }
    if ir.blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
        matches!(stmt, Stmt::Machine { instruction, .. } if matches!(instruction,
            crate::ir::MachineInstruction::Cpuid | crate::ir::MachineInstruction::Xgetbv
            | crate::ir::MachineInstruction::Rdtsc | crate::ir::MachineInstruction::Rdtscp
            | crate::ir::MachineInstruction::ReadFlags | crate::ir::MachineInstruction::WriteFlags))
    }) {
        out.push_str(&super::prelude::section(
            "#include <cpuid.h>\n\n#include <x86intrin.h>\n\n",
        ));
    }
    let prototypes_at = out.len();
    if ir.blocks.iter().flat_map(|block| &block.stmts).any(|stmt| {
        matches!(
            stmt,
            Stmt::Machine {
                instruction: crate::ir::MachineInstruction::Xgetbv,
                ..
            }
        )
    }) {
        out.push_str("__attribute__((target(\"xsave\")))\n");
    }
    out.push_str(&format!(
        "{} {{\n",
        declaration(
            &ir.ret_type,
            &format!(
                "{}({})",
                sanitize(&name),
                logical.map_or_else(|| signature(ir), abi::Plan::signature)
            )
        )
    ));
    let decls = locals.decls;
    // The body is rendered first so only slots it names get declared.
    let mut body = String::new();
    // A function that returns nothing needs no return at its end, unless a
    // label stands before it.
    if ctx.void_return
        && matches!(nodes.last(), Some(Node::Stmt(Stmt::Ret { .. })))
        && !matches!(nodes.iter().rev().nth(1), Some(Node::Label(_)))
    {
        nodes.pop();
    }
    ctx.read_once = calls::read_once(&nodes);
    render_nodes(&nodes, 1, &mut body, &ctx);
    let shared_call_values = ctx.call_outputs.shared_declaration(&mut body);
    let segment_bases: Vec<_> = segment_bases
        .iter()
        .filter(|(_, _, _, snapshot)| code_mentions(&body, snapshot))
        .collect();
    // A function whose address the body takes is declared ahead of it,
    // with no type known for it.
    let own = sanitize(&name);
    let stack_name = crate::ir::reg_name(ir.isa, stack_pointer(ir.isa), 64);
    let stack_provider = (!ctx.names.contains_key(&stack_pointer(ir.isa))
        && variables::mentions(&body, &stack_name))
    .then(|| vacant_name("velk_entry_stack_pointer", &mut call_reserved));
    // The callees whose calls are printed with their declarations are
    // declared as their debug information declares them.
    let mut declared_callees: HashMap<String, String> = ir
        .callee_signatures
        .iter()
        .filter_map(|(target, signature)| {
            let callee = symbols
                .functions
                .get(target)
                .map_or_else(|| format!("sub_{target:x}"), |name| sanitize(name));
            if callee == own || !variables::mentions(&body, &callee) {
                return None;
            }
            let params = if signature.params.is_empty() {
                "void".to_owned()
            } else {
                signature
                    .params
                    .iter()
                    .map(|(_, ty)| ty.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let prototype = declaration(&signature.ret, &format!("{callee}({params})"));
            Some((callee, format!("{prototype};\n")))
        })
        .collect();
    if matches!(
        symbols.target_format,
        Some(crate::loader::Format::Elf | crate::loader::Format::Pe | crate::loader::Format::Coff)
    ) {
        for (callee, prototype) in &symbols.library_prototypes {
            if callee == &own
                || declared_callees.contains_key(callee)
                || !variables::mentions(&body, callee)
                || crate::analysis::prototypes::of(callee, false) == Some(prototype)
            {
                continue;
            }
            let mut records = Vec::new();
            for ty in prototype.params.iter().chain([&prototype.ret]) {
                if let Some(record) = crate::analysis::prototypes::record_name(ty) {
                    records.push(format!("{record}; "));
                }
            }
            records.sort();
            records.dedup();
            let params = if prototype.params.is_empty() {
                "void".to_owned()
            } else {
                prototype
                    .params
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let text = declaration(&prototype.ret, &format!("{callee}({params})"));
            // Keep tag declarations with the prototype when the prelude is sorted.
            declared_callees.insert(callee.clone(), format!("{}{text};\n", records.concat()));
        }
    }
    let mut prototypes: String = ctx
        .taken
        .borrow()
        .iter()
        .filter(|taken| **taken != own && !declared_callees.contains_key(*taken))
        .map(|taken| {
            if body.contains(&format!("{taken}(")) {
                let ty = symbols
                    .functions
                    .iter()
                    .find_map(|(address, name)| {
                        (sanitize(name) == *taken)
                            .then(|| symbols.function_returns.get(address))
                            .flatten()
                    })
                    .cloned()
                    .unwrap_or(CType::U64);
                format!("{ty} {taken}();\n")
            } else {
                format!("void {taken}(void);\n")
            }
        })
        .collect();
    let mut declared_callees: Vec<(String, String)> = declared_callees.into_iter().collect();
    declared_callees.sort();
    for (_, prototype) in declared_callees {
        prototypes.push_str(&prototype);
    }
    if let Some(provider) = &stack_provider {
        prototypes.push_str(&format!(
            "uint64_t {provider}(void); /* target entry stack pointer */\n"
        ));
    }
    for (_, _, provider) in &exception_providers {
        if code_mentions(&body, provider) {
            prototypes.push_str(&format!("uint64_t {provider}(void);\n"));
        }
    }
    let provider = &ctx.call_outputs.dynamic_target;
    if !provider.is_empty() && code_mentions(&body, provider) {
        prototypes.push_str(&format!("uint64_t {provider}(void);\n"));
    }
    if code_mentions(&body, &ctx.jump_provider) {
        prototypes.push_str(&format!("uint64_t {}(uint64_t);\n", ctx.jump_provider));
    }
    for (_, _, provider, _) in &segment_bases {
        prototypes.push_str(&format!("uint64_t {provider}(void);\n"));
    }
    if let Some(provider) = return_slot.filter(|provider| code_mentions(&body, provider)) {
        prototypes.push_str(&format!(
            "uint64_t *{provider}(void); /* target frame's return-address slot */\n"
        ));
    }
    out.insert_str(
        prototypes_at,
        &super::prelude::section(&prototypes.replace("\n", "\n\n")),
    );
    let tables = ctx.virtual_tables.declarations(&body);
    out.insert_str(prototypes_at, &tables);
    let declarations_at = out.len();
    let mut declared = 0;
    if let Some(plan) = variadic {
        out.push_str(&format!(
            "    va_list {};\n    va_start({}, {});\n",
            plan.name,
            plan.name,
            ir.params
                .last()
                .map(|param| param.name.as_str())
                .unwrap_or(&plan.last)
        ));
        declared += 1;
    }
    if let Some(provider) = &stack_provider {
        indent(1, &mut out);
        out.push_str(&format!("uint64_t {stack_name} = {provider}();\n"));
        declared += 1;
    }
    if let Some(logical) = logical {
        for declaration in logical.declarations() {
            if logical.pointers.iter().any(|binding| {
                declaration.starts_with(&format!("uint8_t *{} =", binding.name))
                    && !variables::mentions(&body, &binding.name)
            }) {
                continue;
            }
            indent(1, &mut out);
            out.push_str(&declaration);
            out.push('\n');
            declared += 1;
        }
    }
    if let Some(incoming) = incoming {
        for declaration in incoming.declarations() {
            indent(1, &mut out);
            out.push_str(&declaration);
            out.push('\n');
            declared += 1;
        }
    }
    for (_, _, provider, snapshot) in &segment_bases {
        indent(1, &mut out);
        out.push_str(&format!("uint64_t {snapshot} = {provider}();\n"));
        declared += 1;
    }
    for declaration in ctx.globals.declarations(&body) {
        indent(1, &mut out);
        out.push_str(&declaration);
        out.push('\n');
        declared += 1;
    }
    // A register the body uses beyond the parameters holds what it holds
    // on entry until the body sets it.
    for (index, name) in &machine {
        if variables::mentions(&body, name) && !variable_types.contains_key(index) {
            indent(1, &mut out);
            if float_entries.contains(index) {
                let param = ir
                    .params
                    .iter()
                    .find(|param| param.index == *index)
                    .expect("a floating formal");
                let precision =
                    self::float_return(&param.ty).expect("a floating entry representation");
                let bits = expr::float_bits(param.name.clone(), precision).text;
                out.push_str(&format!("uint64_t {name} = {bits};\n"));
            } else {
                out.push_str(&format!("uint64_t {name};\n"));
            }
            declared += 1;
        }
    }
    if let Some(declaration) = shared_call_values {
        indent(1, &mut out);
        out.push_str(&declaration);
        declared += 1;
    }
    for name in &ctx.call_outputs.declarations {
        if variables::mentions(&body, name) {
            indent(1, &mut out);
            out.push_str(&format!("uint64_t {name};\n"));
            declared += 1;
        }
    }
    for group in &go_groups {
        indent(1, &mut out);
        if group.initial.is_empty() {
            out.push_str(&format!("{} {};\n", group.ty, group.name));
        } else {
            out.push_str(&format!(
                "{} {} = {{ {} }};\n",
                group.ty,
                group.name,
                group.initial.join(", ")
            ));
        }
        declared += 1;
    }
    for (index, ty) in &variable_types {
        if go_groups
            .iter()
            .any(|group| group.fields.iter().any(|(field, _, _)| field == index))
        {
            continue;
        }
        let name = ctx.register(*index, 64);
        // What a landing pad receives is no variable of the function.
        if matches!(*index, crate::ir::EXCEPTION | crate::ir::SELECTOR)
            || !variables::mentions(&body, &name)
        {
            continue;
        }
        indent(1, &mut out);
        out.push_str(&format!("{};\n", declaration(ty, &name)));
        declared += 1;
    }
    for local in &decls {
        if local.width == 0 || !body.contains(&local.name) {
            continue;
        }
        indent(1, &mut out);
        out.push_str(&format!(
            "{}; /* [sp{}{:x}] */\n",
            match &local.ty {
                _ if !local.fields.is_empty() && local.ty.is_none() => {
                    let mut fields = Vec::new();
                    let mut end = 0;
                    for field in &local.fields {
                        let offset = field.slot.saturating_sub(local.slot);
                        if offset > end {
                            fields.push(format!("uint8_t gap_{end:x}[0x{:x}];", offset - end));
                        }
                        let name = field
                            .name
                            .rsplit('.')
                            .next()
                            .expect("splitting a string always yields at least one component");
                        fields.push(format!(
                            "{};",
                            match &field.ty {
                                _ if !field.views.is_empty() => union_declaration(field, name),
                                Some(ty) => declaration(ty, name),
                                None => format!("{} {name}", type_of(field.width, field.signed)),
                            }
                        ));
                        end = offset.saturating_add(i64::from(field.width));
                    }
                    if local.size > end {
                        fields.push(format!("uint8_t gap_{end:x}[0x{:x}];", local.size - end));
                    }
                    format!(
                        "_Alignas(16) struct __attribute__((packed)) {{ {} }} {}",
                        fields.join(" "),
                        local.name
                    )
                }
                Some(CType::Array(element)) if local.size > 0 => {
                    let size = super::locals::scalar_storage_size(element).unwrap_or(1);
                    format!(
                        "_Alignas(16) {}[0x{:x}]",
                        declaration(element, &local.name),
                        local.size / i64::from(size)
                    )
                }
                Some(ty) if local.size > 0 =>
                    format!("_Alignas(16) {}", declaration(ty, &local.name)),
                _ if local.size > 0 =>
                    format!("_Alignas(16) uint8_t {}[0x{:x}]", local.name, local.size),
                Some(ty) => declaration(ty, &local.name),
                None => format!("{} {}", type_of(local.width, local.signed), local.name),
            },
            if local.slot < 0 { "-" } else { "+" },
            local.slot.unsigned_abs()
        ));
    }
    declared += decls
        .iter()
        .filter(|local| local.width != 0 && body.contains(&local.name))
        .count();
    if declared > 0 {
        out.push('\n');
    }
    let candidates = variable_types.iter().filter_map(|(index, ty)| {
        if matches!(ty, CType::Array(_)) {
            return None;
        }
        let name = ctx.register(*index, 64);
        Some((name.clone(), declaration(ty, &name)))
    });
    let mut declarations = out.split_off(declarations_at);
    let initialized = super::initializers::fold(&mut declarations, &body, candidates);
    if declarations.trim().is_empty() {
        declarations.clear();
    }
    out.push_str(&declarations);
    out.push_str(&initialized);
    out.push_str("}\n");
    // The definition is the one place a structure nothing uses is named.
    for (name, definition) in definitions {
        if out.matches(&format!("struct {name} ")).count() == 1 {
            out = out.replacen(&definition, "", 1);
        }
    }
    out.insert_str(definitions_at, &ctx.globals.object_declarations(&body));
    let debug = debug_definitions(ir, &out, &ctx.arrays);
    out.insert_str(definitions_at, &debug);
    Rendered {
        code: super::prelude::combine(&if variadic.is_some() {
            format!("{}{out}", super::prelude::section("#include <stdarg.h>\n"))
        } else {
            out
        }),
        segment_bases: segment_bases
            .into_iter()
            .map(|(segment, _, provider, _)| SegmentBaseRead {
                segment: *segment,
                provider: provider.clone(),
            })
            .collect(),
    }
}

pub(super) fn variable_name(reserved: &mut std::collections::HashSet<String>) -> String {
    for index in 1usize.. {
        let name = format!("v{index}");
        if reserved.insert(name.clone()) {
            return name;
        }
    }
    unreachable!("all variable names are reserved")
}

pub(super) fn vacant_name(base: &str, reserved: &mut std::collections::HashSet<String>) -> String {
    let mut name = base.to_owned();
    let mut suffix = 2;
    while !reserved.insert(name.clone()) {
        name = format!("{base}_{suffix}");
        suffix += 1;
    }
    name
}

pub(super) fn code_mentions(text: &str, name: &str) -> bool {
    let bytes = text.as_bytes();
    let mut at = 0;
    let mut member = false;
    while at < bytes.len() {
        if bytes[at..].starts_with(b"//") {
            while at < bytes.len() && bytes[at] != b'\n' {
                at += 1;
            }
        } else if bytes[at..].starts_with(b"/*") {
            at += 2;
            while at < bytes.len() && !bytes[at..].starts_with(b"*/") {
                at += 1;
            }
            at = (at + 2).min(bytes.len());
        } else if matches!(bytes[at], b'\'' | b'"') {
            member = false;
            let quote = bytes[at];
            at += 1;
            while at < bytes.len() {
                let next = bytes[at];
                at += 1;
                if next == b'\\' {
                    at = (at + 1).min(bytes.len());
                } else if next == quote {
                    break;
                }
            }
        } else if bytes[at..].starts_with(b"->") {
            member = true;
            at += 2;
        } else if bytes[at].is_ascii_alphabetic() || bytes[at] == b'_' {
            let start = at;
            while at < bytes.len() && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_') {
                at += 1;
            }
            if !member && &text[start..at] == name {
                return true;
            }
            member = false;
        } else {
            if !bytes[at].is_ascii_whitespace() {
                member = bytes[at] == b'.';
            }
            at += 1;
        }
    }
    false
}

/// A structure's definition: on one line when short, else a member a line.
pub(crate) fn structure_definition(structure: &crate::ir::Structure) -> String {
    let mut members = Vec::new();
    let mut end = 0;
    for (offset, size, fields) in super::unions::cells(&structure.fields) {
        if offset > end {
            members.push(format!("uint8_t gap_0x{end:x}[0x{:x}];", offset - end));
        }
        let name = format!("field_0x{offset:x}");
        match fields.as_slice() {
            [(_, ty)] => members.push(format!("{};", declaration(ty, &name))),
            _ => members.push(format!(
                "union {{ {} }} {name};",
                super::unions::members(
                    u8::try_from(size).unwrap_or(8),
                    &union_views(offset, &fields)
                )
                .join(" ")
            )),
        }
        end = offset.saturating_add(size);
    }
    if let Some(size) = structure.size
        && size > end
    {
        members.push(format!("uint8_t gap_0x{end:x}[0x{:x}];", size - end));
    }
    defined(&format!("struct {}", structure.name), &members)
}

/// The accesses a structure's cell at `start` shares: each field's offset
/// into the cell, width and sign.
fn union_views(start: u64, fields: &[(u64, CType)]) -> Vec<(i64, u8, bool)> {
    fields
        .iter()
        .filter_map(|(offset, ty)| {
            let (bits, signed) = ty.integer()?;
            let width = u8::try_from(bits / 8).ok()?;
            let offset = i64::try_from(offset.checked_sub(start)?).ok()?;
            Some((offset, width, signed))
        })
        .collect()
}

fn defined(name: &str, members: &[String]) -> String {
    let line = format!("{name} {{ {} }};", members.join(" "));
    if line.len() <= STRUCTURE_LINE {
        return format!("{line}\n");
    }
    let mut text = format!("{name} {{\n");
    for member in members {
        text.push_str(&format!("    {member}\n"));
    }
    format!("{text}}};\n")
}

/// The definitions from the debug info that the printed code needs to
/// compile: those reached by member access, held by value, or sized for
/// pointer arithmetic, after those they hold by value in turn.
fn debug_definitions(
    ir: &FunctionIr,
    code: &str,
    arrays: &HashMap<String, naming::Layout>,
) -> String {
    let named = |name: &str| {
        code.match_indices(name).any(|(at, _)| {
            !code[at + name.len()..].starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
        })
    };
    let needed = |definition: &crate::ir::Definition| {
        named(&definition.name)
            && (definition
                .name
                .strip_prefix("struct ")
                .is_some_and(|name| arrays.contains_key(name))
                || definition.fields.iter().any(|field| {
                    code.contains(&format!("->{field}")) || code.contains(&format!(".{field}"))
                })
                || code
                    .match_indices(&format!("{} ", definition.name))
                    .any(|(at, _)| !code[at + definition.name.len() + 1..].starts_with('*')))
    };
    let mut ordered: Vec<&crate::ir::Definition> = Vec::new();
    fn place<'a>(
        definition: &'a crate::ir::Definition,
        all: &'a [crate::ir::Definition],
        ordered: &mut Vec<&'a crate::ir::Definition>,
        depth: usize,
    ) {
        if depth > 8 || ordered.iter().any(|placed| placed.name == definition.name) {
            return;
        }
        for inner in &definition.contains {
            if let Some(inner) = all.iter().find(|candidate| candidate.name == *inner) {
                place(inner, all, ordered, depth + 1);
            }
        }
        ordered.push(definition);
    }
    for definition in ir
        .definitions
        .iter()
        .filter(|definition| needed(definition))
    {
        place(definition, &ir.definitions, &mut ordered, 0);
    }
    ordered
        .iter()
        .map(|definition| {
            let mut members = definition.members.clone();
            if let Some(alignment) = definition.alignment
                && alignment.is_power_of_two()
                && !definition.compatible_profiles.is_empty()
                && let Some(first) = members.first_mut()
            {
                *first = format!("_Alignas({alignment}) {first}");
            }
            let text = defined(&definition.name, &members);
            if definition.name.starts_with("struct go_")
                || crate::analysis::prototypes::is_library_record(definition)
            {
                super::prelude::section(&format!("{text}\n"))
            } else {
                text
            }
        })
        .collect()
}

fn physical_float_parameters(ir: &mut FunctionIr) -> std::collections::HashSet<u16> {
    let mut captured = std::collections::HashSet::new();
    if !ir.params.iter().any(|param| {
        param.ty.is_sse_float() && crate::arch::vector_half(ir.isa, param.index).is_some()
    }) {
        return captured;
    }
    let reads = if ir.landing_pads.is_empty() {
        crate::ssa::entry_demands(ir, &[])
    } else {
        None
    };
    for param in &mut ir.params {
        if crate::arch::vector_half(ir.isa, param.index).is_none() {
            continue;
        }
        let Some(precision) = float_return(&param.ty) else {
            continue;
        };
        let supplied = crate::ir::semantics::mask(u32::from(precision.bits()));
        if reads
            .as_ref()
            .is_none_or(|reads| reads.get(&param.index).copied().unwrap_or(0) & !supplied != 0)
        {
            param.ty = CType::U64;
        } else if reads
            .as_ref()
            .is_some_and(|reads| reads.contains_key(&param.index))
        {
            captured.insert(param.index);
        }
    }
    captured
}

/// The general and vector slots the body reads or writes, except the stack pointer.
fn machine_registers(
    ir: &FunctionIr,
    track_writes: bool,
) -> (
    std::collections::BTreeSet<u16>,
    std::collections::HashSet<u16>,
) {
    let general = match ir.isa {
        crate::loader::Isa::X86_64 => 0..16,
        crate::loader::Isa::AArch64 => 0..31,
        crate::loader::Isa::Arm32 => 0..15,
        crate::loader::Isa::Unsupported => 0..0,
    };
    let mut used = std::collections::HashSet::new();
    let mut written = std::collections::HashSet::new();
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        if track_writes {
            written.extend(crate::ir::visit::statement_registers(stmt).0);
        }
        for value in stmt.operands() {
            crate::ir::visit::expr_reads(value, &mut used);
        }
        if let Stmt::Assign { dest, .. } = stmt {
            used.insert(dest.index);
        }
        used.extend(stmt.call_outputs().iter().map(|output| output.dest.index));
    }
    let used = used
        .into_iter()
        .filter(|index| {
            (general.contains(index) || crate::arch::vector_half(ir.isa, *index).is_some())
                && *index != stack_pointer(ir.isa)
        })
        .collect();
    (used, written)
}

/// How each parameter, variable and register named for the body is
/// declared, where its type is an integer or a pointer.
fn declared_types(
    ir: &FunctionIr,
    variables: &std::collections::BTreeMap<u16, CType>,
    machine: impl Iterator<Item = u16>,
) -> HashMap<u16, expr::Declared> {
    let mut types: HashMap<u16, expr::Declared> = machine
        .map(|index| (index, declared(&CType::U64, false).expect("an integer")))
        .collect();
    for (index, ty) in variables {
        types.extend(declared(ty, false).map(|declared| (*index, declared)));
    }
    for param in &ir.params {
        types.extend(declared(&param.ty, true).map(|declared| (param.index, declared)));
    }
    types
}

/// How a value of type `ty` is declared, for an integer or a pointer.
fn declared(ty: &CType, param: bool) -> Option<expr::Declared> {
    match ty.integer() {
        Some((bits, signed)) => Some(expr::Declared {
            bits,
            signed,
            param,
            integer: true,
        }),
        None => ty.is_pointer().then_some(expr::Declared {
            bits: 64,
            signed: false,
            param,
            integer: false,
        }),
    }
}

/// The union a field of a local declares for the accesses that share it,
/// one member per width from the widest, `union { int64_t as_i64; uint32_t
/// as_u32[2]; } f_8`, and one packed structure per layer of accesses that
/// do not overlap one another.
fn union_declaration(field: &super::locals::Local, name: &str) -> String {
    let mut views: Vec<(i64, u8, bool)> = Vec::new();
    let mut layers: std::collections::BTreeMap<&str, Vec<&super::locals::Local>> =
        std::collections::BTreeMap::new();
    for view in &field.views {
        let Some(path) = view
            .name
            .strip_prefix(field.name.as_str())
            .and_then(|path| path.strip_prefix('.'))
        else {
            continue;
        };
        if let Some((layer, _)) = path.split_once('.') {
            layers.entry(layer).or_default().push(view);
            continue;
        }
        views.push((
            view.slot.saturating_sub(field.slot),
            view.width,
            view.signed,
        ));
    }
    let mut members = super::unions::members(field.width, &views);
    for (layer, mut fields) in layers {
        fields.sort_by_key(|view| view.slot);
        let mut parts = Vec::new();
        let mut end = 0;
        for view in fields {
            let offset = view.slot.saturating_sub(field.slot);
            if offset > end {
                parts.push(format!("uint8_t gap_{end:x}[0x{:x}];", offset - end));
            }
            let Some(member) = view.name.rsplit('.').next() else {
                continue;
            };
            parts.push(format!("{} {member};", type_of(view.width, view.signed)));
            end = offset.saturating_add(i64::from(view.width));
        }
        members.push(format!(
            "struct __attribute__((packed)) {{ {} }} {layer};",
            parts.join(" ")
        ));
    }
    format!("union {{ {} }} {name}", members.join(" "))
}

/// `name` declared as `ty`, the star of a pointer next to the name.
pub(crate) fn declaration(ty: &CType, name: &str) -> String {
    if ty.is_pointer() {
        format!("{ty}{name}")
    } else {
        format!("{ty} {name}")
    }
}

fn signature(ir: &FunctionIr) -> String {
    let declare = declaration;
    // Parameters in the caller's frame take their declared places among the
    // register ones.
    let mut registers = ir.params.iter();
    let mut parts = Vec::new();
    for position in 0..ir.params.len() + ir.stack_params.len() {
        match ir
            .stack_params
            .iter()
            .find(|param| param.position == position)
        {
            Some(param) => parts.push(declare(&param.ty, &param.name)),
            None => {
                if let Some(param) = registers.next() {
                    parts.push(declare(&param.ty, &param.name));
                }
            }
        }
    }
    if ir.variadic {
        parts.push("...".to_owned());
    }
    if parts.is_empty() {
        return "void".to_owned();
    }
    parts.join(", ")
}

/// The longest structure definition written on one line.
const STRUCTURE_LINE: usize = 100;

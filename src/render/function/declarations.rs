//! Local declaration emission and initializer placement candidates.

use super::{
    CType, Ctx, FunctionIr, SegmentBase, abi, declaration, expr, indent, stack_bytes, type_of,
    union_declaration, variables,
};

pub(super) struct Input<'a> {
    pub(super) ir: &'a FunctionIr,
    pub(super) ctx: &'a Ctx<'a>,
    pub(super) mentions: &'a variables::Mentions<'a>,
    pub(super) body: &'a str,
    pub(super) variadic: Option<&'a super::super::variadic::Plan>,
    pub(super) logical: Option<&'a abi::Plan>,
    pub(super) incoming: Option<&'a stack_bytes::Plan>,
    pub(super) stack_provider: Option<&'a str>,
    pub(super) stack_name: &'a str,
    pub(super) caller_argument: Option<&'a super::super::locals::CallerArgument>,
    pub(super) segment_bases: &'a [&'a (SegmentBase, u16, String, String)],
    pub(super) machine: &'a [(u16, String)],
    pub(super) float_entries: &'a std::collections::HashSet<u16>,
    pub(super) shared_call_values: Option<&'a str>,
    pub(super) go_groups: &'a [super::super::go_values::Group],
    pub(super) vector_groups: &'a [super::super::vector_values::Group],
    pub(super) variable_types: &'a std::collections::BTreeMap<u16, CType>,
    pub(super) decls: &'a [super::super::locals::Local],
}

pub(super) struct Declarations {
    pub(super) text: String,
    pub(super) candidates: Vec<(String, String)>,
}

pub(super) fn emit(input: Input<'_>) -> Declarations {
    let Input {
        ir,
        ctx,
        body,
        mentions,
        variadic,
        logical,
        incoming,
        stack_provider,
        stack_name,
        caller_argument,
        segment_bases,
        machine,
        float_entries,
        shared_call_values,
        go_groups,
        vector_groups,
        variable_types,
        decls,
    } = input;
    let mut addresses = std::collections::HashSet::new();
    if matches!(ir.isa, crate::loader::Isa::I386 | crate::loader::Isa::Arm32) {
        addresses.extend(ctx.frame_origins.keys().copied());
        fn base(expr: &crate::ir::Expr) -> Option<u16> {
            match expr {
                crate::ir::Expr::Reg { index, .. } => Some(*index),
                crate::ir::Expr::Bin {
                    op: crate::ir::BinOp::Add | crate::ir::BinOp::Sub | crate::ir::BinOp::And,
                    lhs,
                    ..
                } => base(lhs),
                _ => None,
            }
        }
        for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
            if let crate::ir::Stmt::Store { addr, .. } = stmt {
                addresses.extend(base(addr));
            }
            let mut pending = stmt.operands();
            while let Some(expr) = pending.pop() {
                if let crate::ir::Expr::Load { addr, .. } = expr {
                    addresses.extend(base(addr));
                }
                pending.extend(crate::ir::visit::children(expr));
            }
        }
    }
    let mut out = String::new();
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
    }
    if let Some(provider) = stack_provider {
        indent(1, &mut out);
        out.push_str(&format!("uint64_t {stack_name} = {provider}();\n"));
    }
    if let Some(argument) = caller_argument
        && mentions.contains(&argument.name)
    {
        out.push_str(&format!(
            "    uint8_t *{} = {};\n",
            argument.name, argument.provider
        ));
    }
    if let Some(logical) = logical {
        for declaration in logical.declarations() {
            if logical.pointers.iter().any(|binding| {
                declaration.starts_with(&format!("uint8_t *{} =", binding.name))
                    && !mentions.contains(&binding.name)
            }) {
                continue;
            }
            indent(1, &mut out);
            out.push_str(&declaration);
            out.push('\n');
        }
    }
    if let Some(incoming) = incoming {
        for declaration in incoming.declarations() {
            indent(1, &mut out);
            out.push_str(&declaration);
            out.push('\n');
        }
    }
    for (_, _, provider, snapshot) in segment_bases {
        indent(1, &mut out);
        out.push_str(&format!("uint64_t {snapshot} = {provider}();\n"));
    }
    // A register the body uses beyond the parameters holds what it holds
    // on entry until the body sets it.
    for (index, name) in machine {
        if mentions.contains(name) && !variable_types.contains_key(index) {
            indent(1, &mut out);
            if float_entries.contains(index) {
                let param = ir
                    .params
                    .iter()
                    .find(|param| param.index == *index)
                    .expect("a floating formal");
                let precision =
                    super::float_return(&param.ty).expect("a floating entry representation");
                let bits = expr::float_bits(param.name.clone(), precision).text;
                out.push_str(&format!("uint64_t {name} = {bits};\n"));
            } else {
                out.push_str(&format!("uint64_t {name};\n"));
            }
        }
    }
    if let Some(declaration) = shared_call_values {
        indent(1, &mut out);
        out.push_str(declaration);
    }
    for name in &ctx.call_outputs.declarations {
        if mentions.contains(name) {
            indent(1, &mut out);
            out.push_str(&format!("uint64_t {name};\n"));
        }
    }
    for group in go_groups {
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
    }
    for (index, ty) in variable_types {
        if ir.params.iter().any(|param| param.index == *index) {
            continue;
        }
        if vector_groups
            .iter()
            .any(|group| group.fields.iter().any(|(field, _)| field == index))
        {
            continue;
        }
        if go_groups
            .iter()
            .any(|group| group.fields.iter().any(|(field, _, _)| field == index))
        {
            continue;
        }
        let name = ctx.register(*index, 64);
        // What a landing pad receives is no variable of the function.
        if matches!(*index, crate::ir::EXCEPTION | crate::ir::SELECTOR) || !mentions.contains(&name)
        {
            continue;
        }
        indent(1, &mut out);
        let address_type = CType::Named("uintptr_t".to_owned());
        let ty = if addresses.contains(index) && ty.integer().is_some_and(|(bits, _)| bits <= 32) {
            &address_type
        } else {
            ty
        };
        out.push_str(&format!("{};\n", declaration(ty, &name)));
    }
    for group in vector_groups {
        if mentions.contains(&group.name) {
            indent(1, &mut out);
            out.push_str(&format!("struct velk_vector {};\n", group.name));
        }
    }
    for local in decls {
        if local.width == 0 || !body.contains(&local.name) {
            continue;
        }
        indent(1, &mut out);
        out.push_str(&format!(
            "{}; /* [sp{}{:x}] */\n",
            match &local.ty {
                _ if !local.fields.is_empty() && local.ty.is_none() => {
                    field_layout(local)
                }
                Some(CType::Array(element)) if local.size > 0 => {
                    let size = super::super::locals::scalar_storage_size(element).unwrap_or(1);
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
    if !out.is_empty() {
        out.push('\n');
    }
    let candidates = variable_types
        .iter()
        .filter_map(|(index, ty)| {
            if matches!(ty, CType::Array(_)) {
                return None;
            }
            let name = ctx.register(*index, 64);
            Some((name.clone(), declaration(ty, &name)))
        })
        .chain(vector_groups.iter().map(|group| {
            (
                group.name.clone(),
                format!("struct velk_vector {}", group.name),
            )
        }))
        .collect();
    Declarations {
        text: out,
        candidates,
    }
}

fn field_layout(local: &super::super::locals::Local) -> String {
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

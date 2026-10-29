//! Named storage for words whose Go runtime use proves their value shape.

use std::collections::{BTreeMap, HashSet};

use super::{Symbols, function::vacant_name};
use crate::ir::{CType, Convention, Expr, FunctionIr, Stmt};

pub(super) struct Group {
    pub(super) name: String,
    pub(super) ty: &'static str,
    pub(super) fields: Vec<(u16, String, CType)>,
    pub(super) initial: Vec<String>,
    pub(super) stack_fields: Vec<(String, String, CType)>,
}

pub(crate) fn shape(name: &str) -> Option<&'static str> {
    match name {
        "runtime.printstring" => Some("struct go_string"),
        "runtime.printslice" => Some("struct go_slice"),
        "runtime.printiface" | "runtime.printeface" => Some("struct go_iface"),
        _ => None,
    }
}

pub(super) fn groups(
    ir: &FunctionIr,
    symbols: &Symbols,
    types: &mut BTreeMap<u16, CType>,
    reserved: &mut HashSet<String>,
) -> Vec<Group> {
    if !matches!(ir.convention, Convention::GoAmd64 | Convention::GoAbi0) {
        return Vec::new();
    }
    let mut candidates = Vec::new();
    if let Some(ty) = ir.name.as_deref().and_then(shape) {
        candidates.push((
            ty,
            ir.params
                .iter()
                .map(|param| Expr::reg(param.index, 64))
                .collect::<Vec<_>>(),
        ));
    }
    for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
        if let Stmt::Call {
            target: Some(target),
            args: Some(args),
            ..
        } = stmt
            && let Some(ty) = symbols.go_value_shapes.get(target)
            && let Some(ty) = shape(ty)
        {
            candidates.push((ty, args.clone()));
        }
    }
    let mut stack_group = None;
    if ir.params.is_empty()
        && let Some(ty) = ir.name.as_deref().and_then(shape)
    {
        let fields = crate::loader::go::types::shape_fields(ty);
        if ir.stack_params.len() == fields.len()
            && ir.stack_params.iter().all(|param| {
                param.size == 8 && param.ty.integer().is_some_and(|(bits, _)| bits == 64)
            })
            && ir
                .stack_params
                .windows(2)
                .all(|pair| pair[0].offset.checked_add(8) == Some(pair[1].offset))
        {
            let name = vacant_name(ty.trim_start_matches("struct go_"), reserved);
            let mut group = Group {
                name,
                ty,
                fields: Vec::new(),
                initial: Vec::new(),
                stack_fields: Vec::new(),
            };
            for (param, (field, field_ty, _)) in ir.stack_params.iter().zip(fields) {
                group
                    .initial
                    .push(initializer(field, &field_ty, &param.name));
                group.stack_fields.push((
                    param.name.clone(),
                    format!("{}.{field}", group.name),
                    field_ty,
                ));
            }
            stack_group = Some(group);
        }
    }
    let mut used = HashSet::new();
    let mut groups = Vec::new();
    for (ty, args) in candidates {
        let fields = crate::loader::go::types::shape_fields(ty);
        if args.len() != fields.len() {
            continue;
        }
        let mut indices = Vec::new();
        for arg in &args {
            let Expr::Reg { index, width: 64 } = arg else {
                break;
            };
            let known = types.get(index).or_else(|| {
                ir.params
                    .iter()
                    .find(|param| param.index == *index)
                    .map(|param| &param.ty)
            });
            if used.contains(index)
                || indices.contains(index)
                || !known.is_some_and(|ty| {
                    ty.is_pointer() || ty.integer().is_some_and(|(bits, _)| bits == 64)
                })
            {
                break;
            }
            indices.push(*index);
        }
        if indices.len() != fields.len() {
            continue;
        }
        let name = vacant_name(ty.trim_start_matches("struct go_"), reserved);
        let mut group = Group {
            name,
            ty,
            fields: Vec::new(),
            initial: Vec::new(),
            stack_fields: Vec::new(),
        };
        for (index, (field, field_ty, _)) in indices.into_iter().zip(fields) {
            if let Some(param) = ir.params.iter().find(|param| param.index == index) {
                group
                    .initial
                    .push(initializer(field, &field_ty, &param.name));
            }
            types.insert(index, field_ty.clone());
            used.insert(index);
            group
                .fields
                .push((index, format!("{}.{field}", group.name), field_ty));
        }
        groups.push(group);
    }
    groups.extend(stack_group);
    groups
}

pub(super) fn definitions(groups: &[Group]) -> String {
    crate::loader::go::types::shapes()
        .iter()
        .filter(|definition| groups.iter().any(|group| group.ty == definition.name))
        .map(|definition| {
            format!(
                "{} {{ {} }};\n\n",
                definition.name,
                definition.members.join(" ")
            )
        })
        .collect()
}

pub(super) fn bind_stack(groups: &[Group], ctx: &mut super::Ctx<'_>) {
    for group in groups {
        for (source, name, ty) in &group.stack_fields {
            ctx.local_widths.insert(name.clone(), 8);
            for slot in ctx.slots.values_mut() {
                if slot == source {
                    *slot = name.clone();
                }
            }
            for part in ctx
                .local_parts
                .values_mut()
                .chain(ctx.parameter_addresses.values_mut())
            {
                let pattern = format!("&{source}");
                let mut replaced = String::new();
                let mut rest = part.as_str();
                while let Some((before, after)) = rest.split_once(&pattern) {
                    replaced.push_str(before);
                    if after.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
                        replaced.push_str(&pattern);
                    } else {
                        replaced.push('&');
                        replaced.push_str(name);
                    }
                    rest = after;
                }
                replaced.push_str(rest);
                *part = replaced;
            }
            for read in ctx.parameter_reads.values_mut() {
                if read.name == *source {
                    read.name = if ty.is_pointer() {
                        format!("(uint64_t)(uintptr_t){name}")
                    } else {
                        name.clone()
                    };
                    read.signed = !ty.is_pointer();
                }
            }
            if ty.is_pointer() {
                ctx.local_pointer_types.insert(name.clone(), ty.to_string());
            } else {
                ctx.signed_locals.insert(name.clone());
            }
        }
    }
}

fn initializer(field: &str, ty: &CType, source: &str) -> String {
    let value = if ty.is_pointer() {
        format!("({ty})(uintptr_t){source}")
    } else {
        format!("({ty}){source}")
    };
    format!(".{field} = {value}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{CallKind, Param};
    use crate::loader::Isa;

    #[test]
    fn unrelated_repeated_or_narrow_words_keep_scalar_storage() {
        for (known, args) in [
            (false, vec![Expr::reg(0, 64), Expr::reg(3, 64)]),
            (true, vec![Expr::reg(0, 64), Expr::reg(0, 64)]),
            (true, vec![Expr::reg(0, 32), Expr::reg(3, 64)]),
        ] {
            let mut ir = FunctionIr::single_block(
                Isa::X86_64,
                vec![
                    Stmt::Call {
                        kind: CallKind::Invoke,
                        target: Some(10),
                        through: None,
                        convention: Convention::GoAmd64,
                        args: Some(args),
                        floats_named: true,
                        abi: None,
                        outputs: Vec::new(),
                        clobbers: Some(Default::default()),
                        via: None,
                        at: None,
                    },
                    Stmt::Ret {
                        value: Expr::Const(0),
                        at: None,
                    },
                ],
            );
            ir.convention = Convention::GoAmd64;
            ir.ret_type = CType::U64;
            ir.params = [0, 3]
                .into_iter()
                .enumerate()
                .map(|(i, index)| Param {
                    index,
                    name: format!("a{i}"),
                    ty: CType::U64,
                })
                .collect();
            let symbols = Symbols {
                functions: [(10, "print_words".into())].into(),
                go_value_shapes: if known {
                    [(10, "runtime.printstring".into())].into()
                } else {
                    Default::default()
                },
                ..Default::default()
            };
            let code = crate::render::render(&ir, &[], &symbols, &[]);
            assert!(!code.contains("struct go_string"), "{code}");
            assert!(code.contains("print_words("), "{code}");
        }
    }
}

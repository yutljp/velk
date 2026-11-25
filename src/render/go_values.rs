//! Named storage for words whose Go runtime use proves their value shape.

use std::collections::{BTreeMap, HashSet};

use super::Symbols;
use super::function::vacant_name;
use crate::ir::{CType, Convention, Expr, FunctionIr, Stmt};

pub(super) struct Group {
    pub(super) name: String,
    pub(super) ty: &'static str,
    pub(super) fields: Vec<(u16, String, CType)>,
    pub(super) initial: Vec<String>,
    pub(super) stack_fields: Vec<(String, String, CType)>,
}

/// A name for each type descriptor of a Go image, from the name Go gives
/// the type: `type_main_Rect` for `main.Rect`, `type_ptr_main_Rect` for a
/// pointer to it, `type_slice_string` for `[]string`. A name another
/// descriptor has, or a long one, ends with the descriptor's address.
/// An interface table is named after its type and its interface:
/// `itab_ptr_os_File_io_Writer`.
pub(super) fn type_names(image: &crate::loader::Image) -> Vec<(u64, String)> {
    if !image.go {
        return Vec::new();
    }
    let types = image
        .go_types
        .get_or_init(|| crate::loader::go::types::read(image));
    let mut taken = std::collections::HashSet::new();
    let described = types
        .names
        .iter()
        .map(|(address, name)| (*address, type_identifier(name)));
    // An interface table reads as its type, then the interface.
    let tables = types.tables.iter().map(|(address, (interface, ty))| {
        let part = |descriptor: &u64| {
            let identifier = type_identifier(&types.names[descriptor]);
            identifier
                .strip_prefix("type")
                .unwrap_or(&identifier)
                .to_owned()
        };
        (*address, format!("itab{}{}", part(ty), part(interface)))
    });
    described
        .chain(tables)
        .map(|(address, mut identifier)| {
            if identifier.len() > 48 {
                identifier.truncate(48);
                identifier = format!("{}_{address:x}", identifier.trim_end_matches('_'));
            } else if taken.contains(&identifier) {
                identifier = format!("{identifier}_{address:x}");
            }
            taken.insert(identifier.clone());
            (address, identifier)
        })
        .collect()
}

/// `name`, a type as Go writes it, as a C identifier.
fn type_identifier(name: &str) -> String {
    let mut identifier = String::from("type");
    let word = |identifier: &mut String, text: &str| {
        if !identifier.ends_with('_') {
            identifier.push('_');
        }
        identifier.push_str(text);
    };
    let mut rest = name;
    while let Some(c) = rest.chars().next() {
        let mut taken = c.len_utf8();
        if c == '*' {
            word(&mut identifier, "ptr_");
        } else if let Some(after) = rest.strip_prefix("[]") {
            word(&mut identifier, "slice_");
            taken = rest.len() - after.len();
        } else if c == '['
            && let Some(end) = rest.find(']')
            && rest[1..end].bytes().all(|byte| byte.is_ascii_digit())
            && end > 1
        {
            word(&mut identifier, &format!("array{}_", &rest[1..end]));
            taken = end + 1;
        } else if c.is_ascii_alphanumeric() {
            if identifier == "type" {
                identifier.push('_');
            }
            identifier.push(c);
        } else if !identifier.ends_with('_') {
            identifier.push('_');
        }
        rest = &rest[taken..];
    }
    identifier.trim_end_matches('_').to_owned()
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
    reserved: &mut super::names::Names<'_>,
) -> Vec<Group> {
    if !matches!(
        ir.convention,
        Convention::GoAmd64 | Convention::GoArm64 | Convention::GoAbi0 | Convention::GoAbi0Arm64
    ) {
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

#[cfg(test)]
mod type_name_tests {
    #[test]
    fn go_type_names_read_as_identifiers() {
        for (name, identifier) in [
            ("main.Rect", "type_main_Rect"),
            ("*main.Rect", "type_ptr_main_Rect"),
            ("[]string", "type_slice_string"),
            ("[4]uint8", "type_array4_uint8"),
            ("**[]*int", "type_ptr_ptr_slice_ptr_int"),
            ("map[string]int", "type_map_string_int"),
            ("func(int, string) error", "type_func_int_string_error"),
            (
                "struct { F uintptr; X0 *int }",
                "type_struct_F_uintptr_X0_ptr_int",
            ),
            ("interface {}", "type_interface"),
            ("internal/abi.Type", "type_internal_abi_Type"),
            ("型", "type"),
        ] {
            assert_eq!(super::type_identifier(name), identifier, "{name}");
        }
    }

    #[test]
    fn fixture_type_descriptors_have_distinct_names() {
        for file in ["go_probe", "go_probe_arm64", "go_probe_arm64_1_27"] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(file);
            let image = crate::loader::load(&path).unwrap();
            let names = super::type_names(&image);
            assert!(names.len() >= 400, "{file}: {}", names.len());
            let distinct: std::collections::HashSet<&String> =
                names.iter().map(|(_, name)| name).collect();
            assert_eq!(distinct.len(), names.len(), "{file}");
            for wanted in [
                "type_string",
                "type_int",
                "type_ptr_runtime_g",
                "type_error",
            ] {
                assert!(
                    distinct.iter().any(|name| *name == wanted),
                    "{file}: {wanted}"
                );
            }
            for (_, name) in &names {
                assert!(
                    name.len() <= 66
                        && name
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
                    "{file}: {name}"
                );
            }
        }
    }
}

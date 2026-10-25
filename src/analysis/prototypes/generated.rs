//! Header-derived declarations and record layouts, loaded on first use.
//!
//! `macos.json` version 1 contains 869 scalar signatures, 135 record layouts,
//! 124 typedefs, and seven enums from the macOS 27.0 SDK. Source metadata records
//! compiler versions, target triples, header names, and header SHA-256 hashes.
//! No glibc or Win32 dataset is included. Only Mach-O inputs use this library.
//!
//! The generator retains declarations and layouts matching on arm64 and x86-64.
//! It checks every admitted signature against the headers and compiles size,
//! alignment, and field-offset assertions for both targets. Enum integer types
//! are queried with compiler compatibility expressions without running target code.
//!
//! Aggregate values, long doubles, vectors, blocks, callbacks, mixed integer/float
//! signatures, stack arguments, and new variadic signatures are excluded. Handwritten
//! declarations supply format metadata and unsupported signatures. Typedefs resolve
//! to supported C types; enum values and typedef spellings remain in the data.
//!
//! Debug definitions take precedence over library records. Unrepresented members
//! remain byte arrays; packed layouts requiring reduced scalar alignment are
//! excluded. Private SDK tags and records defined by the basic C headers stay
//! opaque to avoid conflicting with system declarations. Shared prelude sections
//! declare each referenced record once in combined output.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use serde::Deserialize;

use super::Prototype;
use crate::ir::{AbiProfile, CType, Definition, FunctionIr, Member};
use crate::loader::{Format, Image};

#[derive(Deserialize)]
struct Source<'a> {
    version: u32,
    #[serde(borrow)]
    functions: HashMap<&'a str, &'a str>,
    #[serde(borrow)]
    records: HashMap<&'a str, Record<'a>>,
}

#[derive(Deserialize)]
struct Record<'a> {
    size: u64,
    align: u64,
    opaque: bool,
    #[serde(borrow)]
    fields: Vec<Field<'a>>,
}

#[derive(Deserialize)]
struct Field<'a> {
    offset: u64,
    #[serde(borrow)]
    name: &'a str,
    #[serde(borrow)]
    ty: &'a str,
    width: u64,
}

struct Library {
    functions: HashMap<&'static str, Prototype>,
    records: HashMap<&'static str, Record<'static>>,
}

fn library() -> &'static Library {
    static LIBRARY: OnceLock<Library> = OnceLock::new();
    LIBRARY.get_or_init(|| {
        let source: Source<'static> =
            serde_json::from_str(include_str!("macos.json")).expect("valid generated type library");
        assert_eq!(source.version, 1, "supported type library version");
        Library {
            functions: source
                .functions
                .values()
                .map(|text| super::parse(text))
                .collect(),
            records: source.records,
        }
    })
}

pub(super) fn of(name: &str) -> Option<&'static Prototype> {
    library().functions.get(name)
}

pub(crate) fn is_library_record(definition: &Definition) -> bool {
    let Some(record) = library().records.get(definition.name.as_str()) else {
        return false;
    };
    !record.opaque
        && definition.contains.is_empty()
        && definition.size == record.size
        && definition.alignment == Some(record.align)
        && definition
            .fields
            .iter()
            .map(String::as_str)
            .eq(record.fields.iter().map(|field| field.name))
        && record.fields.iter().all(|field| {
            definition.members.contains(&format!(
                "{};",
                crate::render::declaration(&super::parse_type(field.ty), field.name)
            ))
        })
}

fn record_name(ty: &CType) -> Option<&str> {
    match ty {
        CType::Pointer(target) | CType::Array(target) => record_name(target),
        CType::Named(name) => {
            let name = name.strip_prefix("const ").unwrap_or(name);
            name.starts_with("struct ").then_some(name)
        }
        _ => None,
    }
}

/// Add only records reached by typed values, without replacing debug types.
pub(crate) fn apply_records(ir: &mut FunctionIr, image: &Image) {
    if image.format != Format::MachO || image.byte_order() != Some(object::Endianness::Little) {
        return;
    }
    let params = ir.params.iter().map(|param| &param.ty);
    let stack_params = ir.stack_params.iter().map(|param| &param.ty);
    let types = params
        .chain(stack_params)
        .chain(ir.value_types.values())
        .chain([&ir.ret_type]);
    let mut pending = Vec::new();
    for ty in types {
        if let Some(name) = record_name(ty) {
            pending.push(name.to_owned());
        }
    }
    let mut visited = HashSet::new();
    while let Some(name) = pending.pop() {
        if !visited.insert(name.clone())
            || ir
                .definitions
                .iter()
                .any(|definition| definition.name == name)
            || ir
                .members
                .iter()
                .any(|member| format!("struct {}", member.structure) == name)
        {
            continue;
        }
        let Some(record) = library().records.get(name.as_str()) else {
            continue;
        };
        if record.opaque {
            continue;
        }
        let mut members = Vec::new();
        let mut fields = Vec::new();
        let mut offset = 0;
        for field in &record.fields {
            let Field {
                offset: at,
                name: field_name,
                ty: text,
                width,
            } = *field;
            if at > offset {
                members.push(format!("uint8_t gap_0x{offset:x}[0x{:x}];", at - offset));
            }
            let ty = super::parse_type(text);
            if let Some(inner) = record_name(&ty) {
                pending.push(inner.to_owned());
            }
            members.push(format!("{};", crate::render::declaration(&ty, field_name)));
            fields.push(field_name.to_owned());
            ir.members.push(Member {
                structure: name[7..].to_owned(),
                offset: at as i64,
                name: field_name.to_owned(),
                ty,
                width,
            });
            offset = at + width;
        }
        if offset < record.size {
            members.push(format!(
                "uint8_t gap_0x{offset:x}[0x{:x}];",
                record.size - offset
            ));
        }
        ir.definitions.push(Definition {
            name,
            members,
            fields,
            contains: Vec::new(),
            size: record.size,
            alignment: Some(record.align),
            compatible_profiles: vec![AbiProfile::SysV, AbiProfile::Aapcs64],
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_library_records_require_matching_definitions_without_dependencies() {
        let mut definition = Definition {
            name: "struct iovec".into(),
            members: vec!["void *iov_base;".into(), "size_t iov_len;".into()],
            fields: vec!["iov_base".into(), "iov_len".into()],
            contains: Vec::new(),
            size: 16,
            alignment: Some(8),
            compatible_profiles: vec![AbiProfile::SysV, AbiProfile::Aapcs64],
        };
        assert!(is_library_record(&definition));
        definition.contains.push("struct custom".into());
        assert!(!is_library_record(&definition));
        definition.contains.clear();
        definition.members[0] = "struct custom iov_base;".into();
        assert!(!is_library_record(&definition));
    }

    #[test]
    fn generated_signatures_have_supported_scalar_abi_types() {
        assert!(library().functions.len() > 800);
        for (name, prototype) in &library().functions {
            assert!(prototype.fixed() <= 6 && prototype.floats() <= 8, "{name}");
            assert!(
                prototype.params.iter().all(CType::is_sse_float)
                    || prototype.params.iter().all(|ty| !ty.is_sse_float()),
                "{name}"
            );
            let types = prototype.params.iter().chain([&prototype.ret]);
            for ty in types {
                assert!(
                    matches!(ty, CType::Void | CType::Pointer(_))
                        || ty.integer().is_some()
                        || ty.is_sse_float(),
                    "{name}: {ty}"
                );
            }
        }
        let mask = of("umask").unwrap();
        assert_eq!(mask.ret.integer(), Some((16, false)));
        assert!(
            of("div").is_none(),
            "aggregate return needs ABI classification"
        );
    }

    #[test]
    fn generated_fields_fit_the_record_without_overlap() {
        assert!(library().records["struct sigaction"].opaque);
        assert!(
            library().records["struct iovec"]
                .fields
                .iter()
                .any(|field| field.offset == 8
                    && field.name == "iov_len"
                    && field.ty == "size_t"
                    && field.width == 8)
        );
        for (name, record) in &library().records {
            assert!(record.align.is_power_of_two());
            assert!(record.size.is_multiple_of(record.align));
            let mut end = 0;
            for field in &record.fields {
                let ty = super::super::parse_type(field.ty);
                assert!(
                    field.offset >= end && field.width > 0,
                    "{name}: {}",
                    field.ty
                );
                assert!(ty.is_pointer() || ty.integer().is_some() || ty.is_sse_float());
                end = field.offset.checked_add(field.width).unwrap();
                assert!(end <= record.size);
            }
        }
    }

    #[test]
    fn macos_declarations_do_not_supply_other_platforms() {
        assert!(super::super::of("getgrgid_r", false).is_none());
        assert_eq!(super::super::of("_getgrgid_r", true).unwrap().fixed(), 5);
        assert_eq!(
            super::super::of("_pthread_self", true).unwrap().pointers(),
            0
        );
        assert!(
            super::super::of("_pthread_self", true)
                .unwrap()
                .ret
                .is_pointer()
        );
    }
}

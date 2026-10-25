//! Header-derived declarations and record layouts, loaded on first use.
//!
//! Each format uses its own lazily loaded dataset. Target-specific declarations
//! and record layouts are checked by the generator with the target compiler.
//! Unsupported calling sequences remain with the handwritten declarations.
//! Aggregate values, callbacks, variadic calls, and mixed integer/float parameters
//! are excluded. Active lifters receive register arguments only. Unsupported typedef
//! spellings resolve to scalar or pointer types; their original spellings remain
//! in the source data.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use serde::Deserialize;

use super::Prototype;
use crate::ir::{AbiProfile, CType, Definition, FunctionIr, Member};
use crate::loader::{Format, Image, Isa};

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

#[derive(Deserialize)]
struct Targets<'a> {
    version: u32,
    #[serde(borrow)]
    targets: HashMap<&'a str, Target<'a>>,
}

#[derive(Deserialize)]
struct Target<'a> {
    #[serde(borrow)]
    functions: HashMap<&'a str, &'a str>,
    #[serde(borrow)]
    records: HashMap<&'a str, Record<'a>>,
    #[serde(default, borrow)]
    imports: HashMap<&'a str, &'a str>,
}

struct TargetLibrary {
    library: Library,
    imports: HashMap<&'static str, &'static str>,
}

static WINDOWS: OnceLock<HashMap<&'static str, TargetLibrary>> = OnceLock::new();
static LINUX: OnceLock<HashMap<&'static str, TargetLibrary>> = OnceLock::new();

fn targets(text: &'static str) -> HashMap<&'static str, TargetLibrary> {
    let source: Targets<'static> =
        serde_json::from_str(text).expect("valid generated target libraries");
    assert_eq!(source.version, 2, "supported target library version");
    source
        .targets
        .into_iter()
        .map(|(name, target)| {
            (
                name,
                TargetLibrary {
                    library: Library {
                        functions: target
                            .functions
                            .values()
                            .map(|text| super::parse(text))
                            .collect(),
                        records: target.records,
                    },
                    imports: target.imports,
                },
            )
        })
        .collect()
}

fn target_library(image: &Image) -> Option<&'static TargetLibrary> {
    if image.byte_order() != Some(object::Endianness::Little) {
        return None;
    }
    let (libraries, name) = match (image.format, image.isa) {
        (Format::Pe | Format::Coff, Isa::X86_64) => (
            WINDOWS.get_or_init(|| targets(include_str!("windows.json"))),
            "x86_64-w64-mingw32",
        ),
        (Format::Elf, Isa::X86_64) => (
            LINUX.get_or_init(|| targets(include_str!("linux.json"))),
            "x86_64-linux-gnu",
        ),
        (Format::Elf, Isa::AArch64) => (
            LINUX.get_or_init(|| targets(include_str!("linux.json"))),
            "aarch64-linux-gnu",
        ),
        _ => return None,
    };
    libraries.get(name)
}

pub(super) fn for_image(name: &str, image: &Image) -> Option<&'static Prototype> {
    let Some(target) = target_library(image) else {
        return None;
    };
    if image.format == Format::Elf {
        return target
            .library
            .functions
            .get(super::undecorated(name, false));
    }
    if let Some((dll, function)) = name.split_once('!') {
        let qualified = format!("{}!{function}", dll.to_ascii_lowercase());
        return target
            .imports
            .get(qualified.as_str())
            .and_then(|name| target.library.functions.get(name));
    }
    // A name alone cannot establish which DLL exports a Windows declaration.
    let mut qualified = None;
    for (slot, imported) in &image.imports {
        if imported != name {
            continue;
        }
        let Some(full_name) = image.qualified_imports.get(slot) else {
            continue;
        };
        if qualified.is_some_and(|previous| previous != full_name) {
            return None;
        }
        qualified = Some(full_name);
    }
    let Some(qualified) = qualified else {
        return None;
    };
    target
        .imports
        .get(qualified.as_str())
        .and_then(|name| target.library.functions.get(name))
}

fn image_library(image: &Image) -> Option<&'static Library> {
    if image.byte_order() != Some(object::Endianness::Little) {
        return None;
    }
    if image.format == Format::MachO && matches!(image.isa, Isa::X86_64 | Isa::AArch64) {
        return Some(library());
    }
    target_library(image).map(|target| &target.library)
}

static MACOS: OnceLock<Library> = OnceLock::new();

fn library() -> &'static Library {
    MACOS.get_or_init(|| {
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
    let libraries = WINDOWS.get().into_iter().chain(LINUX.get());
    let records = libraries.flat_map(|targets| targets.values().map(|target| &target.library));
    records.chain(MACOS.get()).any(|library| {
        let Some(record) = library.records.get(definition.name.as_str()) else {
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
    })
}

pub(crate) fn record_name(ty: &CType) -> Option<&str> {
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
    let Some(library) = image_library(image) else {
        return;
    };
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
        let Some(record) = library.records.get(name.as_str()) else {
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
            offset = at.saturating_add(width);
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
            compatible_profiles: vec![match image.format {
                Format::Pe | Format::Coff => AbiProfile::Win64,
                _ if image.isa == Isa::AArch64 => AbiProfile::Aapcs64,
                _ => AbiProfile::SysV,
            }],
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_libraries_do_not_cross_formats_or_architectures() {
        let mut image = Image::from_code(Isa::X86_64, 0x1000, Vec::new());
        assert_eq!(
            for_image("umask", &image).unwrap().ret.integer(),
            Some((32, false))
        );
        assert!(!for_image("pthread_self", &image).unwrap().ret.is_pointer());
        assert!(for_image("kernel32.dll!OpenProcess", &image).is_none());
        image.format = Format::Pe;
        assert!(for_image("getgrgid_r", &image).is_none());
        assert!(for_image("OpenProcess", &image).is_none());
        assert!(
            for_image("KERNEL32.DLL!OpenProcess", &image)
                .unwrap()
                .ret
                .is_pointer()
        );
        assert!(for_image("other.dll!OpenProcess", &image).is_none());
        assert!(for_image("kernel32.dll!#1", &image).is_none());
        assert_eq!(
            for_image("kernel32.dll!_lclose", &image)
                .unwrap()
                .ret
                .integer(),
            Some((32, true))
        );
        assert_eq!(
            for_image("user32.dll!GetWindowLongW", &image)
                .unwrap()
                .ret
                .integer(),
            Some((32, true))
        );
        let wide = for_image("kernel32.dll!lstrlenW", &image).unwrap();
        assert_eq!(
            wide.params[0],
            CType::pointer_to(CType::Named("const unsigned short".into()))
        );
        image.isa = Isa::AArch64;
        assert!(for_image("kernel32.dll!OpenProcess", &image).is_none());
        image.format = Format::Elf;
        assert_eq!(
            for_image("umask", &image).unwrap().ret.integer(),
            Some((32, false))
        );
        image.isa = Isa::Unsupported;
        assert!(for_image("umask", &image).is_none());
    }

    #[test]
    fn shared_library_records_require_matching_definitions_without_dependencies() {
        library();
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
    fn all_target_declarations_use_supported_scalar_types_and_fitted_fields() {
        for text in [include_str!("windows.json"), include_str!("linux.json")] {
            let targets = targets(text);
            assert_eq!(targets.len(), 2);
            for (target, data) in targets {
                assert!(!data.library.functions.is_empty(), "{target}");
                for (name, prototype) in &data.library.functions {
                    for ty in prototype.params.iter().chain([&prototype.ret]) {
                        assert!(
                            matches!(ty, CType::Void | CType::Pointer(_))
                                || ty.integer().is_some()
                                || ty.is_sse_float(),
                            "{target}: {name}: {ty}"
                        );
                    }
                }
                for (name, record) in &data.library.records {
                    assert!(record.align.is_power_of_two(), "{target}: {name}");
                    assert!(record.size.is_multiple_of(record.align), "{target}: {name}");
                    let mut end = 0;
                    for field in &record.fields {
                        assert!(field.offset >= end && field.width > 0, "{target}: {name}");
                        end = field.offset.checked_add(field.width).unwrap();
                        assert!(end <= record.size, "{target}: {name}");
                    }
                }
            }
        }
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

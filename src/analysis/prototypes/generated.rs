//! Header-derived declarations and record layouts, loaded on first use.
//!
//! Each format uses its own lazily loaded dataset. Target-specific declarations
//! and record layouts are checked by the generator with the target compiler.
//! Unsupported calling sequences remain with the handwritten declarations.
//! Aggregate values, variadic calls, and mixed integer/float parameters
//! are excluded from import signatures. Function pointer fields retain their
//! prototypes and calling conventions. Unsupported typedef
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
    #[serde(default, borrow)]
    variables: HashMap<&'a str, Variable<'a>>,
}

#[derive(Deserialize)]
struct Variable<'a> {
    #[serde(rename = "type", borrow)]
    ty: &'a str,
    size: u64,
    #[serde(borrow)]
    header: &'a str,
}

pub(crate) fn variable(name: &str, image: &Image) -> Option<super::LibraryVariable> {
    let Some(library) = image_library(image) else {
        return None;
    };
    let name = super::undecorated(name, image.format == Format::MachO);
    let name = if image.format == Format::MachO {
        name.strip_prefix('_').unwrap_or(name)
    } else {
        name
    };
    let Some(variable) = library.variables.get(name) else {
        return None;
    };
    Some(super::LibraryVariable {
        name: name.to_owned(),
        ty: super::parse_type(variable.ty),
        size: variable.size,
        header: variable.header.to_owned(),
    })
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
    variables: HashMap<&'static str, Variable<'static>>,
}

pub(super) fn record(name: &str, image: &Image) -> Option<super::LibraryRecord> {
    let Some(library) = image_library(image) else {
        return None;
    };
    let Some(record) = library.records.get(name) else {
        return None;
    };
    let mut fields = Vec::new();
    for field in &record.fields {
        let ty = super::parse_type(field.ty);
        let function = match &ty {
            CType::Pointer(target) => match target.as_ref() {
                CType::Function {
                    params,
                    ret,
                    convention,
                    variadic,
                } => {
                    let convention = match convention {
                        crate::ir::Convention::Stdcall => "stdcall",
                        crate::ir::Convention::Fastcall => "fastcall",
                        crate::ir::Convention::Thiscall => "thiscall",
                        crate::ir::Convention::Win64 => "win64",
                        _ => "c",
                    };
                    Some(super::LibraryFunction {
                        parameters: params.iter().map(ToString::to_string).collect(),
                        return_type: ret.to_string(),
                        calling_convention: convention.to_owned(),
                        variadic: *variadic,
                    })
                }
                _ => None,
            },
            _ => None,
        };
        fields.push(super::LibraryField {
            name: field.name.to_owned(),
            offset: field.offset,
            width: field.width,
            c_type: ty.to_string(),
            function,
        });
    }
    Some(super::LibraryRecord {
        name: name.to_owned(),
        size: record.size,
        alignment: record.align,
        opaque: record.opaque,
        fields,
    })
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
    variables: HashMap<&'a str, Variable<'a>>,
    #[serde(default, borrow)]
    imports: HashMap<&'a str, &'a str>,
    #[serde(default, borrow)]
    conventions: HashMap<&'a str, &'a str>,
    #[serde(default, borrow)]
    typedefs: HashMap<&'a str, &'a str>,
    #[serde(default, borrow)]
    guids: HashMap<&'a str, [u8; 16]>,
}

struct TargetLibrary {
    library: Library,
    imports: HashMap<&'static str, &'static str>,
    conventions: HashMap<&'static str, &'static str>,
    typedefs: HashMap<&'static str, &'static str>,
    guids: HashMap<[u8; 16], Vec<&'static str>>,
}

static WINDOWS: OnceLock<HashMap<&'static str, TargetLibrary>> = OnceLock::new();
static LINUX: OnceLock<HashMap<&'static str, TargetLibrary>> = OnceLock::new();

pub(crate) fn is_i386_com_interface(name: &str) -> bool {
    if !name.starts_with("struct I") {
        return false;
    }
    let libraries = WINDOWS.get_or_init(|| targets(include_str!("windows.json")));
    libraries["i686-w64-mingw32"]
        .library
        .records
        .get(name)
        .is_some_and(|record| {
            record
                .fields
                .iter()
                .any(|field| field.offset == 0 && field.name == "lpVtbl" && field.width == 4)
        })
}

fn targets(text: &'static str) -> HashMap<&'static str, TargetLibrary> {
    let source: Targets<'static> =
        serde_json::from_str(text).expect("valid generated target libraries");
    assert_eq!(source.version, 2, "supported target library version");
    source
        .targets
        .into_iter()
        .map(|(name, target)| {
            let mut guids = HashMap::<[u8; 16], Vec<&str>>::new();
            for (name, bytes) in target.guids {
                guids.entry(bytes).or_default().push(name);
            }
            for names in guids.values_mut() {
                names.sort_unstable();
            }
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
                        variables: target.variables,
                    },
                    imports: target.imports,
                    conventions: target.conventions,
                    typedefs: target.typedefs,
                    guids,
                },
            )
        })
        .collect()
}

pub(super) fn guid_at(image: &Image, address: u64) -> Option<super::LibraryGuid> {
    if !matches!(image.format, Format::Pe | Format::Coff) {
        return None;
    }
    let Some(section) = image.section_at(address) else {
        return None;
    };
    if section.executable || !section.read_only {
        return None;
    }
    if !address
        .checked_sub(section.vaddr)
        .and_then(|offset| offset.checked_add(16))
        .is_some_and(|end| end <= section.size && end <= section.file_size)
    {
        return None;
    }
    let Some(bytes) = image.read_vaddr(address, 16) else {
        return None;
    };
    let Ok(bytes) = <[u8; 16]>::try_from(bytes) else {
        return None;
    };
    let Some(library) = target_library(image) else {
        return None;
    };
    let Some(names) = library.guids.get(&bytes) else {
        return None;
    };
    let first = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let second = u16::from_le_bytes([bytes[4], bytes[5]]);
    let third = u16::from_le_bytes([bytes[6], bytes[7]]);
    Some(super::LibraryGuid {
        names: names.iter().map(|name| (*name).to_owned()).collect(),
        value: format!(
            "{first:08x}-{second:04x}-{third:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
        ),
        bytes,
    })
}

fn target_library(image: &Image) -> Option<&'static TargetLibrary> {
    if image.byte_order() != Some(object::Endianness::Little) {
        return None;
    }
    let (libraries, name) = match (image.format, image.isa) {
        (Format::Pe | Format::Coff, Isa::I386) => (
            WINDOWS.get_or_init(|| targets(include_str!("windows.json"))),
            "i686-w64-mingw32",
        ),
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
    resolved_windows_import(target, image, name).map(|(_, prototype)| prototype)
}

fn resolved_windows_import<'a>(
    target: &'a TargetLibrary,
    image: &Image,
    name: &str,
) -> Option<(&'static str, &'a Prototype)> {
    let Some(qualified) = qualified_name(name, image) else {
        return None;
    };
    let Some(name) = windows_import_name(target, qualified) else {
        return None;
    };
    target
        .library
        .functions
        .get(name)
        .map(|prototype| (name, prototype))
}

fn qualified_name<'a>(name: &'a str, image: &'a Image) -> Option<&'a str> {
    if name.contains('!') {
        return Some(name);
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
        qualified = Some(full_name.as_str());
    }
    qualified
}

pub(crate) fn i386_import(image: &Image, name: &str) -> Option<(crate::ir::Convention, u16)> {
    if image.isa != Isa::I386 {
        return None;
    }
    let Some(target) = target_library(image) else {
        return None;
    };
    let Some((name, prototype)) = resolved_windows_import(target, image, name) else {
        return None;
    };
    let convention = match target.conventions.get(name).copied() {
        Some("c") => crate::ir::Convention::Cdecl,
        Some("stdcall") => crate::ir::Convention::Stdcall,
        _ => return None,
    };
    if convention == crate::ir::Convention::Cdecl {
        return Some((convention, 0));
    }
    let mut bytes = 0u16;
    for ty in &prototype.params {
        let size = match ty {
            CType::Pointer(_) => 4,
            CType::Int { bytes, .. } => u16::from(*bytes),
            CType::Named(name) if name == "float" => 4,
            CType::Named(name) if name == "double" => 8,
            _ => {
                let Some((bits, _)) = ty.integer() else {
                    return None;
                };
                let Ok(bytes) = u16::try_from(bits / 8) else {
                    return None;
                };
                bytes
            }
        };
        let Some(total) = size
            .checked_add(3)
            .and_then(|size| bytes.checked_add(size & !3))
        else {
            return None;
        };
        bytes = total;
    }
    Some((convention, bytes))
}

fn windows_import_name(target: &TargetLibrary, name: &str) -> Option<&'static str> {
    let Some((dll, function)) = name.split_once('!') else {
        return None;
    };
    if function.starts_with('#') {
        return None;
    }
    let dll = dll.to_ascii_lowercase();
    let qualified = format!("{dll}!{function}");
    if let Some(name) = target.imports.get(qualified.as_str()) {
        return Some(name);
    }
    // The legacy CRT exports time with the target's native time_t width.
    if dll == "msvcrt.dll" && function == "time" {
        let declaration = match target.typedefs.get("time_t").copied() {
            Some("long") => "_time32",
            Some("long long") => "_time64",
            _ => return None,
        };
        return Some(declaration);
    }
    let host = if dll.starts_with("api-ms-win-crt-") && dll.ends_with("-l1-1-0.dll") {
        "ucrtbase.dll"
    } else if dll.starts_with("api-ms-win-core-") && dll.ends_with(".dll") {
        "kernel32.dll"
    } else if dll.starts_with("api-ms-win-security-") && dll.ends_with(".dll") {
        "advapi32.dll"
    } else {
        dll.as_str()
    };
    let qualified = format!("{host}!{function}");
    target.imports.get(qualified.as_str()).copied()
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
            variables: source.variables,
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

fn record_dependencies(ty: &CType, pending: &mut Vec<String>) {
    match ty {
        CType::Function { params, ret, .. } => {
            record_dependencies(ret, pending);
            for param in params {
                record_dependencies(param, pending);
            }
        }
        CType::Pointer(target) | CType::Array(target) => record_dependencies(target, pending),
        _ => {
            if let Some(name) = record_name(ty) {
                pending.push(name.to_owned());
            } else if let CType::Named(name) = ty
                && let name = name.strip_prefix("const ").unwrap_or(name)
                && name.starts_with("union ")
            {
                pending.push(name.to_owned());
            }
        }
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
        record_dependencies(ty, &mut pending);
    }
    let mut visited = HashSet::new();
    while let Some(name) = pending.pop() {
        if !visited.insert(name.clone()) {
            continue;
        }
        if ir
            .definitions
            .iter()
            .any(|definition| definition.name == name)
            || ir
                .members
                .iter()
                .any(|member| format!("struct {}", member.structure) == name)
        {
            for member in &ir.members {
                if name.strip_prefix("struct ") == Some(member.structure.as_str()) {
                    record_dependencies(&member.ty, &mut pending);
                }
            }
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
            record_dependencies(&ty, &mut pending);
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
    fn guid_matches_require_complete_read_only_windows_data() {
        let datasets = targets(include_str!("windows.json"));
        assert!(datasets["i686-w64-mingw32"].guids.len() >= 600);
        assert_eq!(
            datasets["i686-w64-mingw32"].guids,
            datasets["x86_64-w64-mingw32"].guids
        );
        for arch in ["x86_64", "i686"] {
            let mut image = crate::loader::load(
                &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join(format!("tests/fixtures/com_{arch}.dll")),
            )
            .unwrap();
            let address = *image
                .data_symbols
                .iter()
                .find(|(_, name)| name.trim_start_matches('_') == "IID_IUnknown")
                .unwrap()
                .0;
            let guid = guid_at(&image, address).unwrap();
            assert!(guid.names.iter().any(|name| name == "IID_IUnknown"));
            assert_eq!(guid.value, "00000000-0000-0000-c000-000000000046");
            assert_eq!(
                guid.bytes,
                [0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46]
            );
            let start = image.section_at(address).unwrap().vaddr;
            let section = image
                .sections
                .iter()
                .position(|section| section.vaddr == start)
                .unwrap();
            let size = image.sections[section].size;
            let file_size = image.sections[section].file_size;
            image.sections[section].size = address - start + 15;
            assert!(guid_at(&image, address).is_none());
            image.sections[section].size = size;
            image.sections[section].file_size = address - start + 15;
            assert!(guid_at(&image, address).is_none());
            image.sections[section].file_size = file_size;
            image.sections[section].read_only = false;
            assert!(guid_at(&image, address).is_none());
            image.sections[section].read_only = true;
            image.sections[section].executable = true;
            assert!(guid_at(&image, address).is_none());
            image.sections[section].executable = false;
            image.format = Format::Elf;
            assert!(guid_at(&image, address).is_none());
            assert!(guid_at(&image, u64::MAX).is_none());
        }
    }

    #[test]
    fn windows_vtables_retain_typed_methods_and_target_layouts() {
        let libraries = targets(include_str!("windows.json"));
        for (target, data) in libraries {
            let width = if target.starts_with("i686") { 4 } else { 8 };
            let convention = if width == 4 {
                crate::ir::Convention::Stdcall
            } else {
                crate::ir::Convention::Win64
            };
            for interface in ["IUnknown", "IDispatch", "IStream"] {
                let name = format!("struct {interface}Vtbl");
                let record = &data.library.records[name.as_str()];
                assert!(record.fields.len() >= 3, "{target}: {name}");
                for (slot, method) in ["QueryInterface", "AddRef", "Release"].iter().enumerate() {
                    let field = &record.fields[slot];
                    assert_eq!(field.name, *method, "{target}: {name}");
                    assert_eq!(field.offset, slot as u64 * width);
                    assert_eq!(field.width, width);
                    let CType::Pointer(ty) = super::super::parse_type(field.ty) else {
                        panic!("{}", field.ty)
                    };
                    let CType::Function {
                        params,
                        ret,
                        convention: actual,
                        variadic,
                    } = *ty
                    else {
                        panic!("{}", field.ty)
                    };
                    assert_eq!(actual, convention);
                    assert!(!variadic);
                    assert_eq!(params.len(), if slot == 0 { 3 } else { 1 });
                    assert_eq!(params[0].pointee_struct(), Some(interface));
                    assert_eq!(ret.integer(), Some((32, slot == 0)));
                }
            }
            let stream = &data.library.records["struct IStreamVtbl"];
            assert_eq!(stream.fields.len(), 14, "{target}");
            assert!(
                stream
                    .fields
                    .iter()
                    .any(|field| field.name == "Read" && field.offset == 3 * width)
            );
        }
    }

    #[test]
    fn rendered_windows_function_pointer_declarations_compile_for_both_targets() {
        use std::process::Command;

        for (target, data) in targets(include_str!("windows.json")) {
            let mut pending = Vec::new();
            let mut declarations = Vec::new();
            for record in data.library.records.values() {
                for field in &record.fields {
                    let ty = super::super::parse_type(field.ty);
                    if !field.ty.contains("(*") {
                        continue;
                    }
                    record_dependencies(&ty, &mut pending);
                    let name = format!("callback_{}", declarations.len());
                    declarations.push(format!(
                        "typedef {};\n",
                        crate::render::declaration(&ty, &name)
                    ));
                }
            }
            assert!(
                declarations.len() > 1000,
                "{target}: {}",
                declarations.len()
            );
            pending.sort();
            pending.dedup();
            let mut text = String::from("#include <stdint.h>\n#include <stddef.h>\n");
            for tag in pending {
                text.push_str(&format!("{tag};\n"));
            }
            text.extend(declarations);
            let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target/library-function-fields");
            std::fs::create_dir_all(&directory).unwrap();
            let source = directory.join(format!("{target}.c"));
            std::fs::write(&source, text).unwrap();
            let output = Command::new("clang")
                .args([
                    "-target",
                    target,
                    "-ffreestanding",
                    "-std=c11",
                    "-fsyntax-only",
                    "-Werror",
                ])
                .arg(&source)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{target}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn i386_stdcall_import_cleanup_preserves_following_arguments() {
        let code = vec![
            0x6a, 7, 0xff, 0x15, 0x00, 0x20, 0x00, 0x00, 0x8b, 0x44, 0x24, 0x04, 0x50, 0xff, 0x15,
            0x00, 0x20, 0x00, 0x00, 0xc3,
        ];
        let size = code.len() as u64;
        let mut image = Image::from_code(Isa::I386, 0x1000, code);
        image.format = Format::Pe;
        image.imports.insert(0x2000, "GetFileType".into());
        image
            .qualified_imports
            .insert(0x2000, "kernel32.dll!GetFileType".into());
        let function = crate::loader::Function {
            addr: 0x1000,
            size: Some(size),
            size_estimated: false,
            name: Some("two_calls".into()),
            aliases: Vec::new(),
            library: None,
            sources: Vec::new(),
        };
        image.functions.insert(function.addr, function.clone());
        let analysis = crate::analysis::analyze(&image, &function, None).unwrap();
        let code =
            crate::render::render(&analysis.ir, &[], &crate::render::callee_names(&image), &[]);
        assert!(code.contains("GetFileType((void *)0x7)"), "{code}");
        assert!(code.contains("GetFileType((void *)a0)"), "{code}");
        assert!(!code.contains("esp"), "{code}");
    }

    #[test]
    fn i386_import_conventions_and_cleanup_use_the_target_library() {
        let mut image = Image::from_code(Isa::I386, 0x1000, Vec::new());
        image.format = Format::Pe;
        assert_eq!(
            i386_import(&image, "kernel32.dll!GetFileType"),
            Some((crate::ir::Convention::Stdcall, 4))
        );
        assert_eq!(
            i386_import(&image, "kernel32.dll!GetLastError"),
            Some((crate::ir::Convention::Stdcall, 0))
        );
        assert_eq!(
            i386_import(&image, "msvcrt.dll!calloc"),
            Some((crate::ir::Convention::Cdecl, 0))
        );
        assert_eq!(
            i386_import(&image, "kernel32.dll!VirtualAlloc"),
            Some((crate::ir::Convention::Stdcall, 16))
        );
        assert_eq!(i386_import(&image, "other.dll!GetFileType"), None);
        assert_eq!(
            for_image("msvcrt.dll!time", &image).unwrap().ret.integer(),
            Some((32, true))
        );
        image.isa = Isa::X86_64;
        assert_eq!(
            for_image("msvcrt.dll!time", &image).unwrap().ret.integer(),
            Some((64, true))
        );
        assert_eq!(i386_import(&image, "kernel32.dll!GetFileType"), None);
    }

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
    fn windows_crt_dll_names_and_forwarders_preserve_signatures() {
        let mut image = Image::from_code(Isa::X86_64, 0x1000, Vec::new());
        image.format = Format::Pe;
        for dll in [
            "MSVCRT.DLL",
            "UCRTBASE.DLL",
            "API-MS-WIN-CRT-STRING-L1-1-0.DLL",
        ] {
            let prototype = for_image(&format!("{dll}!wcscpy_s"), &image).unwrap();
            assert_eq!(prototype.fixed(), 3);
            assert_eq!(prototype.params[1].integer(), Some((64, false)));
            assert_eq!(
                prototype.params[0],
                CType::pointer_to(CType::Named("unsigned short".into()))
            );
            assert!(for_image(&format!("{dll}!#42"), &image).is_none());
        }
        assert!(for_image("other.dll!wcscpy_s", &image).is_none());
        assert!(for_image("msvcrt.dll!WCSCPY_S", &image).is_none());
        let number = for_image("msvcrt.dll!strtol", &image).unwrap();
        assert_eq!(number.ret.integer(), Some((32, true)));
        assert!(for_image("api-ms-win-core-file-l1-1-0.dll!GetFileType", &image).is_some());
        assert!(for_image("api-ms-win-security-base-l1-1-0.dll!RegCloseKey", &image).is_some());
        image.imports.insert(0x2000, "wcscpy_s".into());
        image
            .qualified_imports
            .insert(0x2000, "MsVcRt.DlL!wcscpy_s".into());
        assert_eq!(for_image("wcscpy_s", &image).unwrap().fixed(), 3);
        assert!(for_image("msvcrt.dll!printf", &image).is_none());
        assert!(super::super::for_image("printf", &image).unwrap().variadic);
        let windows = WINDOWS.get().unwrap();
        let x86 = &windows["i686-w64-mingw32"];
        let name = windows_import_name(x86, "msvcrt.dll!wcscpy_s").unwrap();
        let copy = &x86.library.functions[name];
        assert_eq!(copy.params[1].integer(), Some((32, false)));
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

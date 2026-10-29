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
use serde_json::value::RawValue;

use super::Prototype;
use crate::ir::{AbiProfile, CType, Definition, FunctionIr, Member};
use crate::loader::{Format, Image, Isa};

#[derive(Deserialize)]
struct Source<'a> {
    version: u32,
    #[serde(borrow)]
    functions: HashMap<&'a str, &'a RawValue>,
    #[serde(default, borrow)]
    parameter_names: HashMap<&'a str, &'a RawValue>,
    #[serde(borrow)]
    records: HashMap<&'a str, &'a RawValue>,
    #[serde(default, borrow)]
    variables: HashMap<&'a str, &'a RawValue>,
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
    let Some(variable) = library.variable(name) else {
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
    functions: HashMap<&'static str, Function>,
    records: HashMap<&'static str, RecordData>,
    variables: HashMap<&'static str, VariableData>,
}

struct Function {
    text: &'static RawValue,
    parameter_names: Option<&'static RawValue>,
    inherit_parameter_names: bool,
    prototype: OnceLock<Prototype>,
}

impl Function {
    fn prototype(&self) -> &Prototype {
        self.prototype.get_or_init(|| {
            let text: &'static str =
                serde_json::from_str(self.text.get()).expect("valid generated prototype text");
            let (name, mut prototype) = super::parse(text);
            if let Some(names) = self.parameter_names {
                let names: Vec<&str> =
                    serde_json::from_str(names.get()).expect("valid generated parameter names");
                prototype.parameter_names = names.into_iter().map(str::to_owned).collect();
            }
            if self.inherit_parameter_names {
                inherit_parameter_name(name, &mut prototype);
            }
            prototype
        })
    }
}

impl std::ops::Deref for Function {
    type Target = Prototype;

    fn deref(&self) -> &Self::Target {
        self.prototype()
    }
}

struct RecordData {
    text: &'static RawValue,
    record: OnceLock<Record<'static>>,
}

impl RecordData {
    fn record(&self) -> &Record<'static> {
        self.record
            .get_or_init(|| serde_json::from_str(self.text.get()).expect("valid generated record"))
    }
}

impl std::ops::Deref for RecordData {
    type Target = Record<'static>;

    fn deref(&self) -> &Self::Target {
        self.record()
    }
}

struct VariableData {
    text: &'static RawValue,
    variable: OnceLock<Variable<'static>>,
}

impl VariableData {
    fn variable(&self) -> &Variable<'static> {
        self.variable.get_or_init(|| {
            serde_json::from_str(self.text.get()).expect("valid generated variable")
        })
    }
}

impl Library {
    fn prototype(&self, name: &str) -> Option<&Prototype> {
        self.functions.get(name).map(Function::prototype)
    }

    fn record(&self, name: &str) -> Option<&Record<'static>> {
        self.records.get(name).map(RecordData::record)
    }

    fn variable(&self, name: &str) -> Option<&Variable<'static>> {
        self.variables.get(name).map(VariableData::variable)
    }
}

pub(super) fn record(name: &str, image: &Image) -> Option<super::LibraryRecord> {
    let Some(library) = image_library(image) else {
        return None;
    };
    let Some(record) = library.record(name) else {
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
    functions: HashMap<&'a str, &'a RawValue>,
    #[serde(borrow)]
    records: HashMap<&'a str, &'a RawValue>,
    #[serde(default, borrow)]
    variables: HashMap<&'a str, &'a RawValue>,
    #[serde(default, borrow)]
    imports: HashMap<&'a str, &'a str>,
    #[serde(default, borrow)]
    parameter_names: HashMap<&'a str, &'a RawValue>,
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
        .record(name)
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
            let Target {
                functions,
                records,
                variables,
                imports,
                parameter_names,
                conventions,
                typedefs,
                guids: target_guids,
            } = target;
            let mut guids = HashMap::<[u8; 16], Vec<&str>>::new();
            for (name, bytes) in target_guids {
                guids.entry(bytes).or_default().push(name);
            }
            for names in guids.values_mut() {
                names.sort_unstable();
            }
            (
                name,
                TargetLibrary {
                    library: Library {
                        functions: functions
                            .into_iter()
                            .map(|(name, text)| {
                                (
                                    name,
                                    Function {
                                        text,
                                        parameter_names: parameter_names.get(name).copied(),
                                        inherit_parameter_names: false,
                                        prototype: OnceLock::new(),
                                    },
                                )
                            })
                            .collect(),
                        records: records
                            .into_iter()
                            .map(|(name, text)| {
                                (
                                    name,
                                    RecordData {
                                        text,
                                        record: OnceLock::new(),
                                    },
                                )
                            })
                            .collect(),
                        variables: variables
                            .into_iter()
                            .map(|(name, text)| {
                                (
                                    name,
                                    VariableData {
                                        text,
                                        variable: OnceLock::new(),
                                    },
                                )
                            })
                            .collect(),
                    },
                    imports,
                    conventions,
                    typedefs,
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
    let qualified = if matches!(image.format, Format::Pe | Format::Coff) {
        let Some(qualified) = qualified_name(name, image) else {
            return None;
        };
        Some(qualified)
    } else {
        None
    };
    let Some(target) = target_library(image) else {
        return None;
    };
    if image.format == Format::Elf {
        return target.library.prototype(super::undecorated(name, false));
    }
    let Some(qualified) = qualified else {
        return None;
    };
    resolved_windows_import(target, qualified).map(|(_, prototype)| prototype)
}

pub(super) fn inherit_parameter_name(name: &str, prototype: &mut Prototype) {
    if !prototype.parameter_names.is_empty() {
        return;
    }
    let libraries = LINUX.get_or_init(|| targets(include_str!("linux.json")));
    let Some(source) = libraries.get("x86_64-linux-gnu") else {
        return;
    };
    let Some(source) = source.library.prototype(name) else {
        return;
    };
    if prototype.params == source.params
        && source.parameter_names.len() == prototype.params.len()
        && source.parameter_names.iter().any(|name| !name.is_empty())
    {
        prototype.parameter_names = source.parameter_names.clone();
    }
}

fn resolved_windows_import<'a>(
    target: &'a TargetLibrary,
    qualified: &str,
) -> Option<(&'static str, &'a Prototype)> {
    let Some(name) = windows_import_name(target, qualified) else {
        return None;
    };
    target
        .library
        .prototype(name)
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
    let Some(qualified) = qualified_name(name, image) else {
        return None;
    };
    let Some(target) = target_library(image) else {
        return None;
    };
    let Some((name, prototype)) = resolved_windows_import(target, qualified) else {
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
        let functions = source
            .functions
            .into_iter()
            .map(|(name, text)| {
                (
                    name,
                    Function {
                        text,
                        parameter_names: source.parameter_names.get(name).copied(),
                        inherit_parameter_names: true,
                        prototype: OnceLock::new(),
                    },
                )
            })
            .collect();
        let records = source
            .records
            .into_iter()
            .map(|(name, text)| {
                (
                    name,
                    RecordData {
                        text,
                        record: OnceLock::new(),
                    },
                )
            })
            .collect();
        let variables = source
            .variables
            .into_iter()
            .map(|(name, text)| {
                (
                    name,
                    VariableData {
                        text,
                        variable: OnceLock::new(),
                    },
                )
            })
            .collect();
        Library {
            functions,
            records,
            variables,
        }
    })
}

pub(super) fn of(name: &str) -> Option<&'static Prototype> {
    library().prototype(name)
}

pub(crate) fn is_library_record(definition: &Definition) -> bool {
    let libraries = WINDOWS.get().into_iter().chain(LINUX.get());
    let records = libraries.flat_map(|targets| targets.values().map(|target| &target.library));
    records.chain(MACOS.get()).any(|library| {
        let Some(record) = library.record(definition.name.as_str()) else {
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
    // The renderer also checks existing definitions against header records.
    if pending.is_empty() && ir.definitions.is_empty() {
        return;
    }
    let Some(library) = image_library(image) else {
        return;
    };
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
        let Some(record) = library.record(name.as_str()) else {
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
mod tests;

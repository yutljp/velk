//! Validation of supported C declarations and types.
use std::collections::{BTreeMap, HashSet};

use crate::error::Result;
use crate::ir::{AbiIssue, AbiProfile, CType, DeclaredSignature, Definition, Member};

use super::{Project, Target, error};

pub(super) fn identifier(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !crate::render::reserved_identifier(name)
        && !name.starts_with('_')
        && !name.starts_with("velk_")
        && !name.starts_with("VELK_")
        && !matches!(
            name,
            "va_arg" | "va_start" | "va_end" | "va_copy" | "va_list"
        )
        && !name.strip_prefix("sub_").is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

#[derive(Default)]
pub(super) struct Types {
    known: BTreeMap<String, (CType, u64, u64)>,
    pub definitions: Vec<Definition>,
    pub members: Vec<Member>,
    pub declarations: Vec<String>,
    pub ordinary_names: HashSet<String>,
}

impl Types {
    pub fn new(project: &Project) -> Result<Self> {
        let mut types = Self::default();
        let mut tags = HashSet::new();
        for entry in &project.annotations {
            if let Target::Declaration { name } = &entry.target
                && let Some(tag) = name
                    .strip_prefix("struct ")
                    .or_else(|| name.strip_prefix("enum "))
                && !tags.insert(tag)
            {
                return Err(error(
                    "invalid_declaration",
                    "struct and enum tags must be distinct",
                ));
            }
        }
        // Forward declarations allow pointers to structures defined later.
        for entry in &project.annotations {
            if let Target::Declaration { name } = &entry.target
                && let Some(tag) = name.strip_prefix("struct ")
                && identifier(tag)
            {
                types
                    .known
                    .insert(name.clone(), (CType::Named(name.clone()), 0, 1));
            }
        }
        for entry in &project.annotations {
            if let Target::Declaration { name } = &entry.target
                && let Err(cause) =
                    types.declaration(name, entry.text.as_deref().unwrap_or_default())
            {
                return Err(cause);
            }
        }
        Ok(types)
    }

    pub fn parse(&self, text: &str) -> Result<CType> {
        let text = text.trim();
        if text.len() > 4096 || text.bytes().filter(|b| *b == b'*').count() > 16 {
            return Err(error(
                "unsupported_type",
                "type exceeds supported length or pointer depth",
            ));
        }
        if let Some(base) = text.strip_suffix('*') {
            let ty = match self.parse(base) {
                Ok(ty) => ty,
                Err(cause) => return Err(cause),
            };
            let mut depth = 1;
            let mut target = &ty;
            while let CType::Pointer(inner) = target {
                depth += 1;
                if depth > 16 {
                    return Err(error(
                        "unsupported_type",
                        "expanded type exceeds supported pointer depth",
                    ));
                }
                target = inner;
            }
            return Ok(CType::pointer_to(ty));
        }
        let ty = match text {
            "void" => CType::Void,
            "int8_t" | "signed char" => CType::int(1, true),
            "uint8_t" | "unsigned char" => CType::int(1, false),
            "int16_t" | "short" | "short int" => CType::int(2, true),
            "uint16_t" | "unsigned short" => CType::int(2, false),
            "int32_t" | "int" | "signed int" => CType::int(4, true),
            "uint32_t" | "unsigned" | "unsigned int" => CType::int(4, false),
            "int64_t" | "long long" => CType::int(8, true),
            "uint64_t" | "unsigned long long" => CType::int(8, false),
            name => match self.known.get(name) {
                Some((ty, _, _)) => ty.clone(),
                None => {
                    return Err(error(
                        "unsupported_type",
                        format!("unsupported C type: {text}"),
                    ));
                }
            },
        };
        Ok(ty)
    }

    pub fn size(&self, ty: &CType) -> Result<(u64, u64)> {
        match ty {
            CType::Pointer(_) => Ok((8, 8)),
            CType::Int { bytes, .. } => Ok((u64::from(*bytes), u64::from(*bytes))),
            CType::Named(name) => match self.known.get(name) {
                Some((_, size, align)) if *size > 0 => Ok((*size, *align)),
                _ => Err(error("unknown_layout", format!("incomplete type: {name}"))),
            },
            _ => Err(error(
                "unsupported_type",
                format!("no object layout for {ty}"),
            )),
        }
    }

    fn named(&self, text: &str) -> Result<(String, CType)> {
        let text = text.trim();
        if !text.is_ascii() {
            return Err(error(
                "invalid_declaration",
                "C declarations must use ASCII identifiers",
            ));
        }
        let start = text
            .rfind(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .map_or(0, |index| index + 1);
        let name = &text[start..];
        if !identifier(name) {
            return Err(error(
                "invalid_declaration",
                format!("expected a named scalar declaration: {text}"),
            ));
        }
        match self.parse(text[..start].trim()) {
            Ok(ty) => Ok((name.to_owned(), ty)),
            Err(cause) => Err(cause),
        }
    }

    pub fn signature(&self, text: &str) -> Result<DeclaredSignature> {
        let Some((ret, params)) = text.trim().trim_end_matches(';').split_once('(') else {
            return Err(error(
                "invalid_signature",
                "expected return_type (type name, ...)",
            ));
        };
        let Some(params) = params.strip_suffix(')') else {
            return Err(error("invalid_signature", "signature must end with ')'"));
        };
        let ret = match self.parse(ret) {
            Ok(ty) => ty,
            Err(cause) => return Err(cause),
        };
        if ret != CType::Void && !ret.is_pointer() && ret.integer().is_none() {
            return Err(error(
                "unsupported_signature",
                "only integer and pointer results are supported",
            ));
        }
        let mut names = HashSet::new();
        let mut parsed = Vec::new();
        if !params.trim().is_empty() && params.trim() != "void" {
            for param in params.split(',') {
                let (name, ty) = match self.named(param) {
                    Ok(param) => param,
                    Err(cause) => return Err(cause),
                };
                if (!ty.is_pointer() && ty.integer().is_none()) || !names.insert(name.clone()) {
                    return Err(error(
                        "unsupported_signature",
                        "parameters require distinct names and integer or pointer types",
                    ));
                }
                parsed.push((name, ty));
            }
        }
        Ok(DeclaredSignature {
            params: parsed,
            ret,
            variadic: false,
            abi: Err(AbiIssue::UnsupportedType),
        })
    }

    fn declaration(&mut self, name: &str, text: &str) -> Result<()> {
        let text = text.trim();
        let emitted = text.split_whitespace().collect::<Vec<_>>().join(" ");
        if let Some(alias) = text
            .strip_prefix("typedef ")
            .and_then(|s| s.strip_suffix(';'))
        {
            return self.typedef_declaration(name, alias, emitted);
        }
        let Some((head, body)) = text.split_once('{') else {
            return Err(error(
                "invalid_declaration",
                "expected struct, enum, or typedef declaration",
            ));
        };
        let Some(body) = body.trim().strip_suffix("};") else {
            return Err(error(
                "invalid_declaration",
                "declaration must end with '};'",
            ));
        };
        if head.trim() != name {
            return Err(error(
                "invalid_declaration",
                "declaration name does not match its key",
            ));
        }
        if let Some(tag) = name.strip_prefix("enum ") {
            return self.enum_declaration(name, tag, body, emitted);
        }
        let Some(tag) = name.strip_prefix("struct ") else {
            return Err(error(
                "unsupported_declaration",
                "only struct, enum, and typedef declarations are supported",
            ));
        };
        self.struct_declaration(name, tag, body, emitted)
    }

    fn typedef_declaration(&mut self, name: &str, alias: &str, emitted: String) -> Result<()> {
        let (found, ty) = match self.named(alias) {
            Ok(value) => value,
            Err(cause) => return Err(cause),
        };
        if found != name
            || self.known.contains_key(name)
            || !self.ordinary_names.insert(name.to_owned())
        {
            return Err(error(
                "invalid_declaration",
                "typedef name is duplicate or does not match its key",
            ));
        }
        let (size, align) = match self.size(&ty) {
            Ok(layout) => layout,
            Err(cause) => return Err(cause),
        };
        self.known.insert(name.to_owned(), (ty, size, align));
        self.declarations.push(emitted);
        Ok(())
    }

    fn enum_declaration(
        &mut self,
        name: &str,
        tag: &str,
        body: &str,
        emitted: String,
    ) -> Result<()> {
        if !identifier(tag) || body.trim().is_empty() {
            return Err(error("invalid_declaration", "invalid enum"));
        }
        let mut names = HashSet::new();
        let mut next = 0i64;
        for value in body.trim().trim_end_matches(',').split(',') {
            let (key, number) = match value.trim().split_once('=') {
                Some((key, number)) => (key.trim(), number.trim().parse::<i64>().ok()),
                None => (value.trim(), Some(next)),
            };
            let Some(number) = number.filter(|n| i32::try_from(*n).is_ok()) else {
                return Err(error(
                    "invalid_declaration",
                    "enum values must be decimal signed 32-bit integers",
                ));
            };
            if !identifier(key) || !names.insert(key) || !self.ordinary_names.insert(key.to_owned())
            {
                return Err(error(
                    "invalid_declaration",
                    "invalid or duplicate enum member",
                ));
            }
            next = number.saturating_add(1);
        }
        self.known
            .insert(name.to_owned(), (CType::int(4, true), 4, 4));
        self.declarations.push(emitted);
        Ok(())
    }

    fn struct_declaration(
        &mut self,
        name: &str,
        tag: &str,
        body: &str,
        emitted: String,
    ) -> Result<()> {
        if !identifier(tag) || body.trim().is_empty() {
            return Err(error("invalid_declaration", "invalid struct"));
        }
        let mut offset = 0u64;
        let mut alignment = 1u64;
        let mut members = Vec::new();
        let mut fields = Vec::new();
        let mut contains = Vec::new();
        for field in body.trim().trim_end_matches(';').split(';') {
            let (field, ty) = match self.named(field) {
                Ok(value) => value,
                Err(cause) => return Err(cause),
            };
            if field.starts_with("gap_0x") {
                return Err(error(
                    "invalid_declaration",
                    "field name conflicts with explicit padding",
                ));
            }
            if fields.contains(&field) {
                return Err(error("invalid_declaration", "duplicate struct field"));
            }
            let (size, align) = match self.size(&ty) {
                Ok(layout) => layout,
                Err(cause) => return Err(cause),
            };
            let previous = offset;
            offset = match offset.checked_add(align - 1) {
                Some(value) => value & !(align - 1),
                None => return Err(error("layout_overflow", "struct offset overflow")),
            };
            if offset > previous {
                members.push(format!(
                    "uint8_t gap_0x{previous:x}[0x{:x}];",
                    offset - previous
                ));
            }
            if offset > i64::MAX as u64 {
                return Err(error(
                    "layout_overflow",
                    "struct offset exceeds signed address range",
                ));
            }
            self.members.push(Member {
                structure: tag.to_owned(),
                offset: offset as i64,
                name: field.clone(),
                ty: ty.clone(),
                width: size,
            });
            members.push(format!("{ty} {field};"));
            fields.push(field);
            if let CType::Named(nested) = &ty {
                contains.push(nested.clone());
            }
            alignment = alignment.max(align);
            offset = match offset.checked_add(size) {
                Some(value) => value,
                None => return Err(error("layout_overflow", "struct size overflow")),
            };
        }
        let size = match offset.checked_add(alignment - 1) {
            Some(value) => value & !(alignment - 1),
            None => return Err(error("layout_overflow", "struct size overflow")),
        };
        if size > offset {
            members.push(format!("uint8_t gap_0x{offset:x}[0x{:x}];", size - offset));
        }
        self.known.insert(
            name.to_owned(),
            (CType::Named(name.to_owned()), size, alignment),
        );
        self.definitions.push(Definition {
            name: name.to_owned(),
            members,
            fields,
            contains,
            size,
            alignment: Some(alignment),
            compatible_profiles: vec![AbiProfile::SysV, AbiProfile::Win64, AbiProfile::Aapcs64],
        });
        self.declarations.push(emitted);
        Ok(())
    }
}

//! `CodeView` types and verified C structure layouts.

use super::records::{Reader, records};
use crate::ir::abi::{LayoutField, LayoutKind, TypeLayout};
use crate::ir::{AbiProfile, CType, Definition, Member, Precision};
use std::collections::BTreeMap;

#[derive(Debug, Default)]
pub(super) struct Types(pub BTreeMap<u32, (u16, Vec<u8>)>);

pub(super) fn valid_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    text.len() <= 96
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !crate::render::reserved_identifier(text)
}

fn modifier(mut data: Reader<'_>) -> Option<u32> {
    let (Some(inner), Some(flags)) = (data.u32(), data.u16()) else {
        return None;
    };
    (flags & !7 == 0).then_some(inner)
}

impl Types {
    pub fn read(bytes: &[u8], start: u32) -> Self {
        let mut types = BTreeMap::new();
        for (index, (kind, data)) in records(bytes).enumerate() {
            let Some(index) = u32::try_from(index).ok().and_then(|i| start.checked_add(i)) else {
                break;
            };
            types.insert(index, (kind, data.to_vec()));
        }
        Self(types)
    }

    pub fn record(&self, index: u32) -> Option<(u16, Reader<'_>)> {
        self.0.get(&index).map(|(kind, data)| (*kind, Reader(data)))
    }

    fn primitive(index: u32) -> Option<(CType, TypeLayout)> {
        if index >= 0x1000 {
            return None;
        }
        if index & 0xf00 != 0 {
            if index & 0xf00 != 0x600 {
                return None;
            }
            let Some((target, _)) = Self::primitive(index & 0xff) else {
                return None;
            };
            return Some((
                CType::pointer_to(target),
                TypeLayout {
                    size: 8,
                    alignment: Some(8),
                    kind: LayoutKind::Pointer,
                    trivial: true,
                },
            ));
        }
        let (spelling, size, kind) = match index {
            3 => (CType::Void, 0, LayoutKind::Integer),
            0x10 | 0x68 | 0x70 => (CType::int(1, true), 1, LayoutKind::Integer),
            0x20 | 0x69 => (CType::int(1, false), 1, LayoutKind::Integer),
            0x11 | 0x72 => (CType::int(2, true), 2, LayoutKind::Integer),
            0x21 | 0x73 | 0x71 => (CType::int(2, false), 2, LayoutKind::Integer),
            0x12 | 0x74 => (CType::I32, 4, LayoutKind::Integer),
            0x22 | 0x75 => (CType::U32, 4, LayoutKind::Integer),
            0x13 | 0x76 => (CType::I64, 8, LayoutKind::Integer),
            0x23 | 0x77 => (CType::U64, 8, LayoutKind::Integer),
            0x30 => (CType::Named("_Bool".into()), 1, LayoutKind::Boolean),
            0x40 => (
                CType::Named("float".into()),
                4,
                LayoutKind::Float(Precision::Single),
            ),
            0x41 => (
                CType::Named("double".into()),
                8,
                LayoutKind::Float(Precision::Double),
            ),
            _ => return None,
        };
        Some((
            spelling,
            TypeLayout {
                size,
                alignment: Some(size.max(1)),
                kind,
                trivial: true,
            },
        ))
    }

    pub fn spelling(&self, index: u32, depth: usize) -> Option<CType> {
        if depth == 0 {
            return None;
        }
        if let Some((ty, _)) = Self::primitive(index) {
            return Some(ty);
        }
        let Some((kind, mut data)) = self.record(index) else {
            return None;
        };
        match kind {
            0x1001 => {
                let Some(inner) = modifier(data) else {
                    return None;
                };
                self.spelling(inner, depth - 1)
            }
            0x1002 => {
                let (Some(inner), Some(attributes)) = (data.u32(), data.u32()) else {
                    return None;
                };
                if attributes & 0x1f != 12
                    || (attributes >> 5) & 7 != 0
                    || (attributes >> 13) & 0x3f != 8
                {
                    return None;
                }
                match self.spelling(inner, depth - 1) {
                    Some(CType::Array(_)) => None,
                    Some(target) => Some(CType::pointer_to(target)),
                    None => None,
                }
            }
            0x1505 | 0x1504 => {
                let Some((_, _, text, _)) = self.structure(index) else {
                    return None;
                };
                valid_identifier(&text).then(|| CType::Named(format!("struct {text}")))
            }
            0x1503 => {
                let Some(inner) = data.u32() else { return None };
                self.spelling(inner, depth - 1)
                    .map(|ty| CType::Array(Box::new(ty)))
            }
            _ => None,
        }
    }

    pub(super) fn structure(&self, index: u32) -> Option<(u16, u32, String, u64)> {
        let Some((kind, mut data)) = self.record(index) else {
            return None;
        };
        if !matches!(kind, 0x1504 | 0x1505) {
            return None;
        }
        let (Some(_count), Some(properties), Some(fields)) = (data.u16(), data.u16(), data.u32())
        else {
            return None;
        };
        if data.take(8).is_none() {
            return None;
        }
        let (Some(size), Some(name)) = (data.number(), data.name()) else {
            return None;
        };
        Some((properties, fields, name, size))
    }

    pub(super) fn complete(&self, index: u32) -> Option<u32> {
        let Some((_, _, name, _)) = self.structure(index) else {
            return None;
        };
        let mut matching = self.0.keys().copied().filter(|other| {
            self.structure(*other)
                .is_some_and(|(flags, _, other_name, _)| flags & 0x80 == 0 && name == other_name)
        });
        let result = matching.next();
        if matching.next().is_some() {
            return None;
        }
        result
    }

    pub fn fields(&self, index: u32) -> Option<Vec<(String, u32, u64)>> {
        let Some((kind, mut data)) = self.record(index) else {
            return None;
        };
        if kind != 0x1203 {
            return None;
        }
        let mut fields = Vec::new();
        while !data.0.is_empty() {
            if data.0[0] >= 0xf0 {
                let count = usize::from(data.0[0] & 0xf);
                if count == 0 || data.take(count).is_none() {
                    return None;
                }
                continue;
            }
            if data.u16() != Some(0x150d) || data.u16().is_none() {
                return None;
            }
            let (Some(ty), Some(at), Some(text)) = (data.u32(), data.number(), data.name()) else {
                return None;
            };
            if !valid_identifier(&text) {
                return None;
            }
            fields.push((text, ty, at));
        }
        Some(fields)
    }

    pub fn layout(&self, index: u32, depth: usize) -> Option<TypeLayout> {
        self.layout_with_budget(index, depth, &mut 4096)
    }

    pub(super) fn layout_with_budget(
        &self,
        index: u32,
        depth: usize,
        budget: &mut usize,
    ) -> Option<TypeLayout> {
        if *budget == 0 {
            return None;
        }
        *budget -= 1;
        if depth == 0 {
            return None;
        }
        if let Some((_, layout)) = Self::primitive(index) {
            return Some(layout);
        }
        let Some((kind, mut data)) = self.record(index) else {
            return None;
        };
        match kind {
            0x1001 => {
                let Some(inner) = modifier(data) else {
                    return None;
                };
                self.layout_with_budget(inner, depth - 1, budget)
            }
            0x1002 => {
                if self.spelling(index, depth).is_none() {
                    return None;
                }
                Some(TypeLayout {
                    size: 8,
                    alignment: Some(8),
                    kind: LayoutKind::Pointer,
                    trivial: true,
                })
            }
            0x1503 => {
                let (Some(inner), Some(_)) = (data.u32(), data.u32()) else {
                    return None;
                };
                let Some(size) = data.number() else {
                    return None;
                };
                let Some(element) = self.layout_with_budget(inner, depth - 1, budget) else {
                    return None;
                };
                if element.size == 0 || size == 0 || size % element.size != 0 {
                    return None;
                }
                Some(TypeLayout {
                    size,
                    alignment: element.alignment,
                    kind: LayoutKind::Array {
                        count: size / element.size,
                        element: Box::new(element),
                    },
                    trivial: true,
                })
            }
            0x1504 | 0x1505 => {
                let Some(index) = self.complete(index) else {
                    return None;
                };
                let Some((flags, fields, _, size)) = self.structure(index) else {
                    return None;
                };
                // Packed and nontrivial C++ layouts require more than member offsets.
                if flags & !0x600 != 0 {
                    return None;
                }
                let Some(fields) = self.fields(fields) else {
                    return None;
                };
                let Some((_, mut header)) = self.record(index) else {
                    return None;
                };
                if header.u16().map(usize::from) != Some(fields.len()) {
                    return None;
                }
                let names: std::collections::HashSet<_> =
                    fields.iter().map(|(name, _, _)| name.clone()).collect();
                if names.len() != fields.len() {
                    return None;
                }
                let mut layouts = Vec::new();
                let mut end = 0u64;
                let mut alignment = 1;
                for (_, ty, at) in fields {
                    if at > end && names.contains(&format!("gap_0x{end:x}")) {
                        return None;
                    }
                    let Some(layout) = self.layout_with_budget(ty, depth - 1, budget) else {
                        return None;
                    };
                    let Some(align) = layout.alignment else {
                        return None;
                    };
                    if layout.size == 0 || at < end || at % align != 0 {
                        return None;
                    }
                    let Some(next) = at.checked_add(layout.size) else {
                        return None;
                    };
                    if next > size {
                        return None;
                    }
                    end = next;
                    alignment = alignment.max(align);
                    let Some(bit_offset) = at.checked_mul(8) else {
                        return None;
                    };
                    layouts.push(LayoutField {
                        bit_offset,
                        bit_size: None,
                        defined: true,
                        layout,
                    });
                }
                let rounded = end
                    .checked_add(alignment - 1)
                    .map(|end| end / alignment * alignment);
                if size == 0
                    || rounded != Some(size)
                    || (size > end && names.contains(&format!("gap_0x{end:x}")))
                {
                    return None;
                }
                Some(TypeLayout {
                    size,
                    alignment: Some(alignment),
                    kind: LayoutKind::Struct(layouts),
                    trivial: true,
                })
            }
            _ => None,
        }
    }

    pub fn procedure(&self, index: u32) -> Option<(u32, Vec<u32>, bool)> {
        let Some((kind, mut data)) = self.record(index) else {
            return None;
        };
        if kind != 0x1008 {
            return None;
        }
        let Some(ret) = data.u32() else { return None };
        let Some(convention) = data.take(2) else {
            return None;
        };
        if !matches!(convention[0], 0 | 4) || convention[1] != 0 {
            return None;
        }
        let (Some(count), Some(args)) = (data.u16(), data.u32()) else {
            return None;
        };
        let Some((0x1201, mut data)) = self.record(args) else {
            return None;
        };
        let Some(length) = data.u32().map(|n| n as usize) else {
            return None;
        };
        if length > data.0.len() / 4 || length > 4096 {
            return None;
        }
        let mut args = Vec::new();
        for _ in 0..length {
            let Some(arg) = data.u32() else { return None };
            args.push(arg);
        }
        let variadic = args.last() == Some(&0);
        if variadic {
            args.pop();
        }
        if args.len() != usize::from(count) || args.iter().any(|ty| matches!(ty, 0 | 3)) {
            return None;
        }
        Some((ret, args, variadic))
    }

    pub fn definitions(&self) -> (Vec<Definition>, Vec<Member>) {
        let mut definitions = Vec::new();
        let mut budget = self.0.values().map(|(_, bytes)| bytes.len() / 4).sum();
        for index in self.0.keys().copied() {
            let Some((flags, fields, text, size)) = self.structure(index) else {
                continue;
            };
            if flags & 0x80 != 0 || !valid_identifier(&text) {
                continue;
            }
            let Some(layout) = self.layout_with_budget(index, 16, &mut budget) else {
                continue;
            };
            let Some(fields) = self.fields(fields) else {
                continue;
            };
            let structure = format!("struct {text}");
            let mut declarations = Vec::new();
            let mut names = Vec::new();
            let mut contains = Vec::new();
            let mut end = 0;
            let mut valid = true;
            for (text, ty, at) in fields {
                let (Some(spelling), Some(layout)) = (self.spelling(ty, 16), self.layout(ty, 16))
                else {
                    valid = false;
                    break;
                };
                let Some(declaration) = self.declaration(ty, &text, 16) else {
                    valid = false;
                    break;
                };
                if names.contains(&text) {
                    valid = false;
                    break;
                }
                if at > end {
                    declarations.push(format!("uint8_t gap_0x{end:x}[0x{:x}];", at - end));
                }
                declarations.push(declaration);
                names.push(text.clone());
                let mut inner = &spelling;
                while let CType::Array(element) = inner {
                    inner = element;
                }
                if let CType::Named(named) = inner
                    && named.starts_with("struct ")
                {
                    contains.push(named.clone());
                }
                end = at.saturating_add(layout.size);
            }
            if !valid {
                continue;
            }
            if end < size {
                declarations.push(format!("uint8_t gap_0x{end:x}[0x{:x}];", size - end));
            }
            definitions.push(Definition {
                name: structure,
                members: declarations,
                fields: names,
                contains,
                size,
                alignment: layout.alignment,
                compatible_profiles: vec![AbiProfile::Win64],
            });
        }
        let mut members = Vec::new();
        for index in self.0.keys().copied() {
            let Some((flags, _, text, _)) = self.structure(index) else {
                continue;
            };
            if flags & 0x80 != 0
                || !definitions
                    .iter()
                    .any(|definition| definition.name == format!("struct {text}"))
            {
                continue;
            }
            self.flatten(index, &text, "", 0, 8, &mut members);
        }
        (definitions, members)
    }

    fn flatten(
        &self,
        index: u32,
        structure: &str,
        prefix: &str,
        base: u64,
        depth: usize,
        members: &mut Vec<Member>,
    ) {
        if depth == 0 {
            return;
        }
        let Some(index) = self.complete(index) else {
            return;
        };
        let Some((_, fields, _, _)) = self.structure(index) else {
            return;
        };
        let Some(fields) = self.fields(fields) else {
            return;
        };
        for (text, ty, at) in fields {
            let Some(at) = base.checked_add(at) else {
                continue;
            };
            let path = format!("{prefix}{text}");
            let (Some(spelling), Some(layout)) = (self.spelling(ty, 16), self.layout(ty, 16))
            else {
                continue;
            };
            if matches!(&spelling, CType::Named(text) if text.starts_with("struct ")) {
                self.flatten(ty, structure, &format!("{path}."), at, depth - 1, members);
            } else if let Ok(offset) = i64::try_from(at) {
                members.push(Member {
                    structure: structure.into(),
                    offset,
                    name: path,
                    ty: spelling,
                    width: layout.size,
                });
            }
        }
    }

    fn declaration(&self, index: u32, text: &str, depth: usize) -> Option<String> {
        if depth == 0 {
            return None;
        }
        if let Some((kind, mut data)) = self.record(index) {
            if kind == 0x1001 {
                let Some(inner) = data.u32() else { return None };
                return self.declaration(inner, text, depth - 1);
            }
            if kind == 0x1503 {
                let Some(inner) = data.u32() else { return None };
                let Some(layout) = self.layout(index, depth) else {
                    return None;
                };
                let LayoutKind::Array { count, .. } = layout.kind else {
                    return None;
                };
                return self.declaration(inner, &format!("{text}[{count}]"), depth - 1);
            }
        }
        self.spelling(index, depth).map(|ty| {
            let separator = if ty.is_pointer() { "" } else { " " };
            format!("{ty}{separator}{text};")
        })
    }
}

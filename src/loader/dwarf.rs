//! Function names and ranges from DWARF debug information.

use gimli::{AttributeValue, Dwarf, EndianSlice, LittleEndian, SectionId, Unit};

use crate::ir::{CType, Member};
use crate::loader::Image;

#[derive(Debug, Clone)]
pub struct DwarfFunction {
    pub addr: u64,
    pub size: u64,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct FunctionTypes {
    /// Parameter names and types; either may be absent from the debug info.
    pub params: Vec<(Option<String>, Option<CType>)>,
    pub ret: Option<CType>,
    /// The named fields of every structure in the unit.
    pub members: Vec<Member>,
}

fn attribute<'a>(
    entry: &gimli::DebuggingInformationEntry<EndianSlice<'a, LittleEndian>>,
    name: gimli::DwAt,
) -> Option<AttributeValue<EndianSlice<'a, LittleEndian>>> {
    entry
        .attrs()
        .iter()
        .find(|attribute| attribute.name() == name)
        .map(|attribute| attribute.value())
}

fn resolve_low(
    dwarf: &Dwarf<EndianSlice<'_, LittleEndian>>,
    unit: &Unit<EndianSlice<'_, LittleEndian>>,
    entry: &gimli::DebuggingInformationEntry<EndianSlice<'_, LittleEndian>>,
) -> Option<u64> {
    let value = attribute(entry, gimli::DW_AT_low_pc)?;
    match value {
        AttributeValue::DebugAddrIndex(index) => dwarf.address(unit, index).ok(),
        other => attribute_offset(dwarf, unit, other),
    }
}

fn type_name(
    dwarf: &Dwarf<EndianSlice<'_, LittleEndian>>,
    unit: &Unit<EndianSlice<'_, LittleEndian>>,
    offset: gimli::UnitOffset<usize>,
    depth: usize,
) -> Option<CType> {
    if depth == 0 {
        return None;
    }
    let entry = unit.entry(offset).ok()?;
    // A base type's name may have several words (`unsigned char`).
    let name = attribute(&entry, gimli::DW_AT_name).and_then(|value| {
        let text = dwarf
            .attr_string(unit, value)
            .ok()?
            .to_string_lossy()
            .into_owned();
        text.split(' ').all(plausible_name).then_some(text)
    });
    let outer = attribute(&entry, gimli::DW_AT_type).and_then(|value| match value {
        AttributeValue::UnitRef(offset) => Some(offset),
        _ => None,
    });
    match entry.tag() {
        gimli::DW_TAG_pointer_type => {
            let target = outer
                .and_then(|offset| type_name(dwarf, unit, offset, depth - 1))
                .unwrap_or(CType::Void);
            Some(CType::pointer_to(target))
        }
        gimli::DW_TAG_const_type
        | gimli::DW_TAG_volatile_type
        | gimli::DW_TAG_restrict_type
        | gimli::DW_TAG_typedef => {
            outer.and_then(|offset| type_name(dwarf, unit, offset, depth - 1))
        }
        gimli::DW_TAG_structure_type => Some(CType::Named(format!("struct {}", name?))),
        gimli::DW_TAG_union_type => Some(CType::Named(format!("union {}", name?))),
        gimli::DW_TAG_enumeration_type => Some(CType::Named(format!("enum {}", name?))),
        gimli::DW_TAG_array_type => {
            let element = outer.and_then(|offset| type_name(dwarf, unit, offset, depth - 1))?;
            Some(CType::Array(Box::new(element)))
        }
        _ => name.map(CType::Named),
    }
}

pub fn function_types(image: &Image, addr: u64) -> Option<FunctionTypes> {
    let dwarf = Dwarf::load(|id| -> Result<EndianSlice<'_, LittleEndian>, ()> {
        Ok(EndianSlice::new(section(image, id), LittleEndian))
    })
    .ok()?;

    let mut units = dwarf.units();
    while let Ok(Some(header)) = units.next() {
        let Ok(unit) = dwarf.unit(header) else {
            continue;
        };
        let mut entries = unit.entries();
        while let Ok(Some(entry)) = entries.next_dfs() {
            if entry.tag() != gimli::DW_TAG_subprogram {
                continue;
            }
            if resolve_low(&dwarf, &unit, entry) != Some(addr) {
                continue;
            }
            // A subprogram without a type returns nothing.
            let ret = match attribute(entry, gimli::DW_AT_type) {
                None => Some(crate::ir::CType::Void),
                Some(value) => match value {
                    AttributeValue::UnitRef(offset) => type_name(&dwarf, &unit, offset, 8),
                    _ => None,
                }
                .filter(plausible_type),
            };
            let depth = entry.depth();
            let mut params = Vec::new();
            while let Ok(Some(child)) = entries.next_dfs() {
                if child.depth() <= depth {
                    break;
                }
                if child.depth() != depth + 1 || child.tag() != gimli::DW_TAG_formal_parameter {
                    continue;
                }
                let name = attribute(child, gimli::DW_AT_name)
                    .and_then(|value| attribute_string(&dwarf, &unit, value));
                let ty = attribute(child, gimli::DW_AT_type)
                    .and_then(|value| match value {
                        AttributeValue::UnitRef(offset) => type_name(&dwarf, &unit, offset, 8),
                        _ => None,
                    })
                    .filter(plausible_type);
                params.push((name, ty));
            }
            if params.is_empty() && ret.is_none() {
                continue;
            }
            return Some(FunctionTypes {
                params,
                ret,
                members: structure_members(&dwarf, &unit),
            });
        }
    }
    None
}

/// Each structure's name and direct fields: offset, name and type.
type StructureFields = std::collections::HashMap<
    gimli::UnitOffset,
    (
        Option<String>,
        Vec<(u64, String, Option<gimli::UnitOffset>)>,
    ),
>;

/// The named fields of every structure in the unit, by byte offset. A field
/// that is itself a structure or union names the fields inside it with a
/// path, as `max.x`, since an access reaches those.
fn structure_members(
    dwarf: &Dwarf<EndianSlice<'_, LittleEndian>>,
    unit: &Unit<EndianSlice<'_, LittleEndian>>,
) -> Vec<Member> {
    use std::collections::HashMap;
    // The direct fields of each structure, and what each type alias names.
    let mut fields: StructureFields = HashMap::new();
    let mut aliases: HashMap<gimli::UnitOffset, gimli::UnitOffset> = HashMap::new();
    let mut entries = unit.entries();
    let mut current: Option<gimli::UnitOffset> = None;
    let type_of =
        |entry: &gimli::DebuggingInformationEntry<EndianSlice<'_, LittleEndian>>| match attribute(
            entry,
            gimli::DW_AT_type,
        ) {
            Some(AttributeValue::UnitRef(offset)) => Some(offset),
            _ => None,
        };
    while let Ok(Some(entry)) = entries.next_dfs() {
        match entry.tag() {
            gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type => {
                let name = attribute(entry, gimli::DW_AT_name)
                    .and_then(|value| attribute_string(dwarf, unit, value));
                fields.insert(entry.offset(), (name, Vec::new()));
                current = Some(entry.offset());
            }
            gimli::DW_TAG_typedef | gimli::DW_TAG_const_type | gimli::DW_TAG_volatile_type => {
                if let Some(target) = type_of(entry) {
                    aliases.insert(entry.offset(), target);
                }
            }
            gimli::DW_TAG_member => {
                // A bit-field shares its word with others; no name covers the word.
                let Some(structure) =
                    current.filter(|_| attribute(entry, gimli::DW_AT_bit_size).is_none())
                else {
                    continue;
                };
                let Some(name) = attribute(entry, gimli::DW_AT_name)
                    .and_then(|value| attribute_string(dwarf, unit, value))
                else {
                    continue;
                };
                // A union's fields all start at its beginning.
                let offset = attribute(entry, gimli::DW_AT_data_member_location)
                    .and_then(|value| attribute_offset(dwarf, unit, value))
                    .unwrap_or(0);
                let ty = type_of(entry);
                if let Some((_, list)) = fields.get_mut(&structure) {
                    list.push((offset, name, ty));
                }
            }
            _ => {}
        }
    }

    let resolve = |mut ty: gimli::UnitOffset| {
        for _ in 0..8 {
            match aliases.get(&ty) {
                Some(next) => ty = *next,
                None => break,
            }
        }
        ty
    };
    fn flatten(
        structure: gimli::UnitOffset,
        base: u64,
        prefix: &str,
        depth: usize,
        fields: &StructureFields,
        resolve: &dyn Fn(gimli::UnitOffset) -> gimli::UnitOffset,
        out: &mut Vec<(u64, String)>,
    ) {
        let Some((_, list)) = fields.get(&structure) else {
            return;
        };
        for (offset, name, ty) in list {
            let path = format!("{prefix}{name}");
            let inner = ty.map(resolve).filter(|inner| fields.contains_key(inner));
            match inner {
                Some(inner) if depth < 4 => flatten(
                    inner,
                    base + offset,
                    &format!("{path}."),
                    depth + 1,
                    fields,
                    resolve,
                    out,
                ),
                _ => out.push((base + offset, path)),
            }
        }
    }
    let mut members = Vec::new();
    for (offset, (name, _)) in &fields {
        let Some(structure) = name else {
            continue;
        };
        let mut flat = Vec::new();
        flatten(*offset, 0, "", 0, &fields, &resolve, &mut flat);
        // Fields sharing an offset, as in a union, keep the first.
        let mut seen = std::collections::HashSet::new();
        for (field_offset, path) in flat {
            if seen.insert(field_offset) {
                members.push(Member {
                    structure: structure.clone(),
                    offset: field_offset as i64,
                    name: path,
                });
            }
        }
    }
    members.sort_by(|a, b| (&a.structure, a.offset).cmp(&(&b.structure, b.offset)));
    members
}

fn section(image: &Image, id: SectionId) -> &[u8] {
    image.section_data(id.name()).unwrap_or(&[])
}

fn attribute_string(
    dwarf: &Dwarf<EndianSlice<'_, LittleEndian>>,
    unit: &Unit<EndianSlice<'_, LittleEndian>>,
    value: AttributeValue<EndianSlice<'_, LittleEndian>>,
) -> Option<String> {
    let string = dwarf.attr_string(unit, value).ok()?;
    let text = string.to_string_lossy().into_owned();
    // A non-identifier means the string was misread, e.g. from an unrelocated
    // string offset; the caller then falls back to a synthesized name.
    plausible_name(&text).then_some(text)
}

/// True for a string that can be a compiler-emitted C identifier.
fn plausible_name(text: &str) -> bool {
    let mut characters = text.chars();
    let starts_well = characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_');
    starts_well && text.len() <= 96 && characters.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Rejects type names built from misread strings.
fn plausible_type(ty: &CType) -> bool {
    let text = ty.to_string();
    !text.is_empty()
        && text.len() <= 96
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | ' ' | '*' | '[' | ']'))
}

fn attribute_offset(
    dwarf: &Dwarf<EndianSlice<'_, LittleEndian>>,
    unit: &Unit<EndianSlice<'_, LittleEndian>>,
    value: AttributeValue<EndianSlice<'_, LittleEndian>>,
) -> Option<u64> {
    match value {
        AttributeValue::DebugAddrIndex(index) => dwarf.address(unit, index).ok(),
        AttributeValue::Addr(value) => Some(value),
        AttributeValue::Udata(value) => Some(value),
        AttributeValue::Data1(value) => Some(u64::from(value)),
        AttributeValue::Data2(value) => Some(u64::from(value)),
        AttributeValue::Data4(value) => Some(u64::from(value)),
        AttributeValue::Data8(value) => Some(value),
        _ => None,
    }
}

pub fn functions(image: &Image) -> Vec<DwarfFunction> {
    let dwarf = Dwarf::load(|id| -> Result<EndianSlice<'_, LittleEndian>, ()> {
        Ok(EndianSlice::new(section(image, id), LittleEndian))
    });
    let Ok(dwarf) = dwarf else {
        return Vec::new();
    };

    let mut functions = Vec::new();
    let mut units = dwarf.units();
    while let Ok(Some(header)) = units.next() {
        let Ok(unit) = dwarf.unit(header) else {
            continue;
        };
        let mut entries = unit.entries();
        while let Ok(Some(entry)) = entries.next_dfs() {
            if entry.tag() != gimli::DW_TAG_subprogram {
                continue;
            }
            let mut name = None;
            let mut linkage = None;
            let mut low = None;
            let mut high = None;
            for attribute in entry.attrs() {
                match attribute.name() {
                    gimli::DW_AT_name => {
                        name = attribute_string(&dwarf, &unit, attribute.value());
                    }
                    gimli::DW_AT_linkage_name | gimli::DW_AT_MIPS_linkage_name => {
                        linkage = attribute_string(&dwarf, &unit, attribute.value());
                    }
                    gimli::DW_AT_low_pc => {
                        low = attribute_offset(&dwarf, &unit, attribute.value());
                    }
                    gimli::DW_AT_high_pc => {
                        high = attribute_offset(&dwarf, &unit, attribute.value());
                    }
                    _ => {}
                }
            }
            let (Some(low), Some(high)) = (low, high) else {
                continue;
            };
            let Some(name) = linkage.or(name) else {
                continue;
            };
            let (addr, size) = if high > low {
                (low, high - low)
            } else {
                (low, high)
            };
            if addr == 0 || size == 0 {
                continue;
            }
            functions.push(DwarfFunction { addr, size, name });
        }
    }
    functions.sort_by_key(|function| function.addr);
    functions.dedup_by_key(|function| function.addr);
    functions
}



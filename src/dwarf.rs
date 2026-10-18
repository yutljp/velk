//! Function names and ranges from DWARF debug information.

use gimli::{AttributeValue, Dwarf, EndianSlice, LittleEndian, SectionId, Unit};

use crate::loader::Image;

#[derive(Debug, Clone)]
pub struct DwarfFunction {
    pub addr: u64,
    pub size: u64,
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub struct FunctionTypes {
    pub params: Vec<(Option<String>, String)>,
    pub ret: Option<String>,
    /// `(struct name, byte offset, field name)` for every structure the
    /// debug info describes.
    pub members: Vec<(String, i64, String)>,
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
) -> Option<String> {
    if depth == 0 {
        return None;
    }
    let entry = unit.entry(offset).ok()?;
    let name = attribute(&entry, gimli::DW_AT_name)
        .and_then(|value| attribute_string(dwarf, unit, value));
    let outer = attribute(&entry, gimli::DW_AT_type)
        .and_then(|value| match value {
            AttributeValue::UnitRef(offset) => Some(offset),
            _ => None,
        });
    match entry.tag() {
        gimli::DW_TAG_pointer_type => {
            let inner = outer
                .and_then(|offset| type_name(dwarf, unit, offset, depth - 1))
                .unwrap_or_else(|| "void".to_owned());
            Some(format!("{inner} *"))
        }
        gimli::DW_TAG_const_type
        | gimli::DW_TAG_volatile_type
        | gimli::DW_TAG_restrict_type
        | gimli::DW_TAG_typedef => {
            outer.and_then(|offset| type_name(dwarf, unit, offset, depth - 1))
        }
        gimli::DW_TAG_structure_type => Some(format!("struct {}", name?)),
        gimli::DW_TAG_union_type => Some(format!("union {}", name?)),
        gimli::DW_TAG_enumeration_type => Some(format!("enum {}", name?)),
        gimli::DW_TAG_base_type => name,
        gimli::DW_TAG_array_type => {
            let inner = outer.and_then(|offset| type_name(dwarf, unit, offset, depth - 1))?;
            Some(format!("{inner} []"))
        }
        _ => name,
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
            let mut types = FunctionTypes::default();
            types.ret = attribute(entry, gimli::DW_AT_type)
                .and_then(|value| match value {
                    AttributeValue::UnitRef(offset) => {
                        type_name(&dwarf, &unit, offset, 8)
                    }
                    _ => None,
                })
                .and_then(|name| checked(Some(name)));
            let depth = entry.depth();
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
                        AttributeValue::UnitRef(offset) => {
                            type_name(&dwarf, &unit, offset, 8)
                        }
                        _ => None,
                    })
                    .and_then(|name| checked(Some(name)))
                    // An unresolved type leaves the inferred one alone.
                    .unwrap_or_default();
                types.params.push((name, ty));
            }
            if types.params.is_empty() && types.ret.is_none() {
                continue;
            }
            types.members = structure_members(&dwarf, &unit);
            return Some(types);
        }
    }
    None
}

/// The named fields of every structure in the unit, by byte offset.
fn structure_members(
    dwarf: &Dwarf<EndianSlice<'_, LittleEndian>>,
    unit: &Unit<EndianSlice<'_, LittleEndian>>,
) -> Vec<(String, i64, String)> {
    let mut members = Vec::new();
    let mut entries = unit.entries();
    let mut current: Option<String> = None;
    while let Ok(Some(entry)) = entries.next_dfs() {
        match entry.tag() {
            gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type => {
                current = attribute(entry, gimli::DW_AT_name)
                    .and_then(|value| attribute_string(dwarf, unit, value));
            }
            gimli::DW_TAG_member => {
                let Some(structure) = current.clone() else {
                    continue;
                };
                let Some(name) = attribute(entry, gimli::DW_AT_name)
                    .and_then(|value| attribute_string(dwarf, unit, value))
                else {
                    continue;
                };
                let Some(offset) = attribute(entry, gimli::DW_AT_data_member_location)
                    .and_then(|value| attribute_offset(dwarf, unit, value))
                else {
                    continue;
                };
                members.push((structure, offset as i64, name));
            }
            _ => {}
        }
    }
    members
}

fn section<'a>(image: &'a Image, id: SectionId) -> &'a [u8] {
    image.section_data(id.name()).unwrap_or(&[])
}

fn attribute_string(
    dwarf: &Dwarf<EndianSlice<'_, LittleEndian>>,
    unit: &Unit<EndianSlice<'_, LittleEndian>>,
    value: AttributeValue<EndianSlice<'_, LittleEndian>>,
) -> Option<String> {
    let string = dwarf.attr_string(unit, value).ok()?;
    let text = string.to_string_lossy().into_owned();
    // A name that is not an identifier did not come from the attribute we
    // asked for (a string-table base the linker would have fixed up, for
    // instance), so the synthesized name is better than the garbage.
    plausible_name(&text).then_some(text)
}

/// True for a C identifier a debugger could have emitted as a name.
fn plausible_name(text: &str) -> bool {
    let mut characters = text.chars();
    let starts_well = characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_');
    starts_well
        && text.len() <= 96
        && characters.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A type name may carry qualifiers and pointer stars, but not the bytes of
/// an unrelated string.
fn plausible_type(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 96
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | ' ' | '*' | '[' | ']'))
}

pub fn type_name_checked(name: Option<String>) -> Option<String> {
    name.filter(|text| plausible_type(text))
}

fn checked(name: Option<String>) -> Option<String> {
    type_name_checked(name)
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

//! Function names and ranges from DWARF debug information.

use gimli::{AttributeValue, Dwarf, EndianSlice, LittleEndian, SectionId, Unit};

use crate::ir::abi::TypeLayout;
use crate::ir::calls::{FunctionSource, TypeSource};
use crate::ir::{AbiIssue, AbiProfile, CType, Definition, Member};
use crate::loader::Image;

mod aggregates;
mod globals;

mod layout;
mod locals;
pub(crate) mod variadic;

use aggregates::{definitions, definitions_with_sources, structure_members};

#[derive(Debug, Clone)]
pub struct DwarfFunction {
    pub addr: u64,
    pub size: u64,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct FunctionTypes {
    pub globals: Vec<(u64, CType, u64)>,
    pub locals: Vec<crate::ir::DebugLocal>,
    pub registers: Vec<(u16, String)>,
    /// Parameter names and types; either may be absent from the debug info.
    pub params: Vec<(Option<String>, Option<CType>)>,
    pub ret: Option<CType>,
    /// The size of a returned structure or union, which decides whether it
    /// comes back in registers or through memory the caller provides.
    pub ret_aggregate_size: Option<u64>,
    /// The size of each parameter that is a structure or union.
    pub param_aggregate_sizes: Vec<Option<u64>>,
    /// Further, variadic, parameters follow the declared ones.
    pub variadic: bool,
    /// The named fields of every structure in the unit.
    pub members: Vec<Member>,
    /// The C definition of every named structure and union in the unit.
    pub definitions: Vec<Definition>,
    pub(crate) param_layouts: Vec<Result<TypeLayout, AbiIssue>>,
    pub(crate) ret_layout: Result<Option<TypeLayout>, AbiIssue>,
    pub(crate) abi_profile: Result<AbiProfile, AbiIssue>,
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "Declaration origins are currently inspected only by tests."
        )
    )]
    pub(crate) source: FunctionSource,
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
    let Ok(entry) = unit.entry(offset) else {
        return None;
    };
    // A base type's name may have several words (`unsigned char`).
    let name = attribute(&entry, gimli::DW_AT_name).and_then(|value| {
        let Ok(text) = dwarf.attr_string(unit, value) else {
            return None;
        };
        let text = text.to_string_lossy().into_owned();
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
        gimli::DW_TAG_structure_type => name.map(|name| CType::Named(format!("struct {name}"))),
        gimli::DW_TAG_union_type => name.map(|name| CType::Named(format!("union {name}"))),
        gimli::DW_TAG_enumeration_type => {
            outer.and_then(|offset| type_name(dwarf, unit, offset, depth - 1))
        }
        gimli::DW_TAG_array_type => {
            let Some(element) = outer.and_then(|offset| type_name(dwarf, unit, offset, depth - 1))
            else {
                return None;
            };
            Some(CType::Array(Box::new(element)))
        }
        gimli::DW_TAG_base_type => {
            let ty = CType::Named(match name {
                Some(name) => name,
                None => return None,
            });
            let size = attribute(&entry, gimli::DW_AT_byte_size).and_then(byte_count);
            if let (Some((bits, _)), Some(bytes)) = (ty.integer(), size)
                && u64::from(bits) != bytes.saturating_mul(8)
            {
                if !matches!(bytes, 1 | 2 | 4 | 8) {
                    return None;
                }
                let signed = match attribute(&entry, gimli::DW_AT_encoding) {
                    Some(AttributeValue::Encoding(
                        gimli::DW_ATE_signed | gimli::DW_ATE_signed_char,
                    )) => true,
                    Some(AttributeValue::Encoding(
                        gimli::DW_ATE_unsigned
                        | gimli::DW_ATE_unsigned_char
                        | gimli::DW_ATE_boolean,
                    )) => false,
                    _ => return None,
                };
                return Some(CType::int(bytes as u8, signed));
            }
            Some(ty)
        }
        _ => name.map(CType::Named),
    }
}

/// The byte size of a structure or union type, through typedefs and
/// qualifiers; None for any other type.
fn aggregate_size(
    unit: &Unit<EndianSlice<'_, LittleEndian>>,
    offset: gimli::UnitOffset<usize>,
    depth: usize,
) -> Option<u64> {
    if depth == 0 {
        return None;
    }
    let entry = unit.entry(offset).ok()?;
    match entry.tag() {
        gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type => {
            match attribute(&entry, gimli::DW_AT_byte_size)? {
                AttributeValue::Data8(_) => None,
                value => byte_count(value),
            }
        }
        gimli::DW_TAG_typedef | gimli::DW_TAG_const_type | gimli::DW_TAG_volatile_type => {
            match attribute(&entry, gimli::DW_AT_type)? {
                AttributeValue::UnitRef(inner) => aggregate_size(unit, inner, depth - 1),
                _ => None,
            }
        }
        _ => None,
    }
}

pub fn function_types(image: &Image, addr: u64) -> Option<FunctionTypes> {
    if let Some(types) = image.codeview.function_types(image, addr) {
        return Some(types);
    }
    if image.byte_order() != Some(object::Endianness::Little) {
        return None;
    }
    let dwarf = Dwarf::load(|id| -> Result<EndianSlice<'_, LittleEndian>, ()> {
        Ok(EndianSlice::new(section(image, id), LittleEndian))
    });
    let Ok(dwarf) = dwarf else { return None };

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
            let ret_aggregate_size = match attribute(entry, gimli::DW_AT_type) {
                Some(AttributeValue::UnitRef(offset)) => aggregate_size(&unit, offset, 8),
                _ => None,
            };
            let ret_layout = match attribute(entry, gimli::DW_AT_type) {
                None => Ok(None),
                Some(AttributeValue::UnitRef(offset)) => layout::read(&unit, offset, 16).map(Some),
                _ => Err(AbiIssue::UnknownLayout),
            };
            let abi_profile = crate::ir::abi::profile(image.isa, image.format)
                .and_then(|profile| layout::function_profile(&unit, entry).map(|()| profile));
            // A subprogram without a type returns nothing.
            let ret = match attribute(entry, gimli::DW_AT_type) {
                None => Some(crate::ir::CType::Void),
                Some(value) => match value {
                    AttributeValue::UnitRef(offset) => type_name(&dwarf, &unit, offset, 8),
                    _ => None,
                }
                .filter(plausible_type),
            };
            let mut registers = Vec::new();
            let locals = locals::read(image, &dwarf, &unit, entry, &mut registers);
            let Some(function) = source_id(&unit, entry.offset()) else {
                continue;
            };
            let result = match attribute(entry, gimli::DW_AT_type) {
                Some(AttributeValue::UnitRef(offset)) => source_id(&unit, offset),
                _ => None,
            };
            let depth = entry.depth();
            let mut params = Vec::new();
            let mut param_aggregate_sizes = Vec::new();
            let mut param_layouts = Vec::new();
            let mut parameters = Vec::new();
            let mut variadic = false;
            while let Ok(Some(child)) = entries.next_dfs() {
                if child.depth() <= depth {
                    break;
                }
                if child.depth() == depth + 1 && child.tag() == gimli::DW_TAG_unspecified_parameters
                {
                    variadic = true;
                }
                if child.depth() != depth + 1 || child.tag() != gimli::DW_TAG_formal_parameter {
                    continue;
                }
                parameters.push(match attribute(child, gimli::DW_AT_type) {
                    Some(AttributeValue::UnitRef(offset)) => source_id(&unit, offset),
                    _ => None,
                });
                param_aggregate_sizes.push(match attribute(child, gimli::DW_AT_type) {
                    Some(AttributeValue::UnitRef(offset)) => aggregate_size(&unit, offset, 8),
                    _ => None,
                });
                param_layouts.push(match attribute(child, gimli::DW_AT_type) {
                    Some(AttributeValue::UnitRef(offset)) => layout::read(&unit, offset, 16),
                    _ => Err(AbiIssue::UnknownLayout),
                });
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
            let definitions = definitions(&dwarf, &unit, abi_profile.ok());
            return Some(FunctionTypes {
                globals: globals::read(&dwarf, &unit, image),
                locals,
                registers,
                params,
                ret,
                ret_aggregate_size,
                param_aggregate_sizes,
                variadic,
                members: structure_members(&dwarf, &unit, &definitions),
                definitions,
                param_layouts,
                ret_layout,
                abi_profile,
                source: FunctionSource {
                    function,
                    parameters,
                    result,
                },
            });
        }
    }
    None
}

/// A byte count in an attribute.
fn byte_count(value: AttributeValue<EndianSlice<'_, LittleEndian>>) -> Option<u64> {
    match value {
        AttributeValue::Udata(size) => Some(size),
        AttributeValue::Data1(size) => Some(u64::from(size)),
        AttributeValue::Data2(size) => Some(u64::from(size)),
        AttributeValue::Data4(size) => Some(u64::from(size)),
        AttributeValue::Data8(size) => Some(size),
        _ => None,
    }
}

/// The byte size of a type, through typedefs and qualifiers, and of an
/// array by its element count.
fn type_size(
    unit: &Unit<EndianSlice<'_, LittleEndian>>,
    offset: gimli::UnitOffset<usize>,
    depth: usize,
) -> Option<u64> {
    if depth == 0 {
        return None;
    }
    let entry = unit.entry(offset).ok()?;
    let inner = || match attribute(&entry, gimli::DW_AT_type)? {
        AttributeValue::UnitRef(inner) => type_size(unit, inner, depth - 1),
        _ => None,
    };
    match entry.tag() {
        gimli::DW_TAG_typedef
        | gimli::DW_TAG_const_type
        | gimli::DW_TAG_volatile_type
        | gimli::DW_TAG_restrict_type => inner(),
        gimli::DW_TAG_pointer_type => Some(
            attribute(&entry, gimli::DW_AT_byte_size)
                .and_then(byte_count)
                .unwrap_or(8),
        ),
        gimli::DW_TAG_array_type => {
            let element = inner()?;
            let mut count = 1u64;
            let mut tree = unit.entries_tree(Some(offset)).ok()?;
            let root = tree.root().ok()?;
            let mut children = root.children();
            while let Ok(Some(child)) = children.next() {
                let child = child.entry();
                if child.tag() != gimli::DW_TAG_subrange_type {
                    continue;
                }
                let length = match attribute(child, gimli::DW_AT_count).and_then(byte_count) {
                    Some(length) => length,
                    None => attribute(child, gimli::DW_AT_upper_bound)
                        .and_then(byte_count)?
                        .checked_add(1)?,
                };
                count = count.checked_mul(length)?;
            }
            element.checked_mul(count)
        }
        _ => attribute(&entry, gimli::DW_AT_byte_size).and_then(byte_count),
    }
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
        && match ty {
            CType::Pointer(target) | CType::Array(target) => plausible_type(target),
            CType::Function { .. } => false,
            _ => text
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | ' ' | '*' | '[' | ']')),
        }
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
    if image.byte_order() != Some(object::Endianness::Little) {
        return Vec::new();
    }
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
                    // An address form gives the end; a constant form, the size.
                    gimli::DW_AT_high_pc => {
                        let value = attribute.value();
                        let address = matches!(
                            value,
                            AttributeValue::Addr(_) | AttributeValue::DebugAddrIndex(_)
                        );
                        high = attribute_offset(&dwarf, &unit, value).map(|high| (high, address));
                    }
                    _ => {}
                }
            }
            let (Some(low), Some((high, address))) = (low, high) else {
                continue;
            };
            let Some(name) = linkage.or(name) else {
                continue;
            };
            let size = if address {
                high.checked_sub(low)
            } else {
                Some(high)
            };
            let Some(size) = size.filter(|size| *size > 0 && low.checked_add(*size).is_some())
            else {
                continue;
            };
            if low == 0 {
                continue;
            }
            functions.push(DwarfFunction {
                addr: low,
                size,
                name,
            });
        }
    }
    functions.sort_by_key(|function| function.addr);
    functions.dedup_by_key(|function| function.addr);
    functions
}

fn source_id(
    unit: &Unit<EndianSlice<'_, LittleEndian>>,
    offset: gimli::UnitOffset<usize>,
) -> Option<TypeSource> {
    Some(TypeSource {
        unit: unit
            .header
            .offset()
            .to_debug_info_offset(&unit.header)?
            .0
            .try_into()
            .ok()?,
        die: offset.0,
    })
}

pub(crate) mod calls;
#[cfg(test)]
mod tests;

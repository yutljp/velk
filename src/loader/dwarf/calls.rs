//! Callee declarations from DWARF: which subprogram starts at each
//! address, and the types its parameters and result name.

use std::sync::Arc;

use gimli::{AttributeValue, Dwarf, EndianSlice, LittleEndian, Unit};

use super::{
    FunctionTypes, aggregate_size, attribute, attribute_offset, attribute_string, byte_count,
    definitions_with_sources, layout, plausible_type, section, source_id, type_name,
};
use crate::ir::abi::TypeLayout;
use crate::ir::calls::{CallType, FunctionSource, TypeGraph, TypeSource};
use crate::ir::{AbiIssue, AbiProfile, CType};
use crate::loader::Image;

#[derive(Debug, Default)]
pub(crate) struct CallIndex {
    pub addresses: std::collections::BTreeMap<u64, Vec<TypeSource>>,
    pub unresolved_ranges: Vec<std::ops::Range<u64>>,
}

#[derive(Debug, Default)]
pub(crate) struct CallUnit {
    pub functions: std::collections::BTreeMap<TypeSource, Result<FunctionTypes, AbiIssue>>,
    pub graph: Arc<TypeGraph>,
}

fn call_dwarf(image: &Image) -> Result<Dwarf<EndianSlice<'_, LittleEndian>>, AbiIssue> {
    if image.byte_order() != Some(object::Endianness::Little) {
        return Err(AbiIssue::UnsupportedProfile);
    }
    Dwarf::load(|id| -> Result<EndianSlice<'_, LittleEndian>, AbiIssue> {
        Ok(EndianSlice::new(section(image, id), LittleEndian))
    })
}

fn call_entry<'a>(
    dwarf: &Dwarf<EndianSlice<'a, LittleEndian>>,
    unit: &Unit<EndianSlice<'a, LittleEndian>>,
    entry: &gimli::DebuggingInformationEntry<EndianSlice<'a, LittleEndian>>,
) -> Result<(Option<u64>, Vec<std::ops::Range<u64>>), AbiIssue> {
    let explicit =
        attribute(entry, gimli::DW_AT_entry_pc).or_else(|| attribute(entry, gimli::DW_AT_low_pc));
    let address = match explicit {
        Some(value) => {
            let offset = match attribute_offset(dwarf, unit, value).ok_or(AbiIssue::UnknownLayout) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            Some(offset)
        }
        None => None,
    };
    let mut ranges = Vec::new();
    if attribute(entry, gimli::DW_AT_ranges).is_some() {
        let mut entries = match dwarf
            .die_ranges(unit, entry)
            .map_err(|_| AbiIssue::UnknownLayout)
        {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        loop {
            let range = match entries.next().map_err(|_| AbiIssue::UnknownLayout) {
                Ok(Some(range)) => range,
                Ok(None) => break,
                Err(error) => return Err(error),
            };

            if range.begin < range.end {
                ranges.push(range.begin..range.end);
            }
        }
    }
    Ok((
        address.or_else(|| ranges.first().map(|range| range.start)),
        ranges,
    ))
}

pub(super) fn call_origins(
    unit: &Unit<EndianSlice<'_, LittleEndian>>,
    offset: gimli::UnitOffset<usize>,
) -> Result<Vec<gimli::UnitOffset<usize>>, AbiIssue> {
    fn visit(
        unit: &Unit<EndianSlice<'_, LittleEndian>>,
        offset: gimli::UnitOffset<usize>,
        pending: &mut Vec<gimli::UnitOffset<usize>>,
        result: &mut Vec<gimli::UnitOffset<usize>>,
    ) -> Result<(), AbiIssue> {
        if pending.contains(&offset) || pending.len() >= 32 || result.len() >= 256 {
            return Err(AbiIssue::UnknownLayout);
        }
        if result.contains(&offset) {
            return Ok(());
        }
        pending.push(offset);
        result.push(offset);
        let entry = match unit.entry(offset).map_err(|_| AbiIssue::UnknownLayout) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        for name in [gimli::DW_AT_abstract_origin, gimli::DW_AT_specification] {
            if let Some(value) = attribute(&entry, name) {
                let AttributeValue::UnitRef(parent) = value else {
                    return Err(AbiIssue::UnknownLayout);
                };
                if let Err(error) = visit(unit, parent, pending, result) {
                    return Err(error);
                }
            }
        }
        pending.pop();
        Ok(())
    }
    let mut result = Vec::new();
    if let Err(error) = visit(unit, offset, &mut Vec::new(), &mut result) {
        return Err(error);
    }
    let type_entry = match unit.entry(offset).map_err(|_| AbiIssue::UnknownLayout) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let tag = type_entry.tag();
    for parent in &result {
        let parent_entry = match unit.entry(*parent).map_err(|_| AbiIssue::UnknownLayout) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        if parent_entry.tag() != tag {
            return Err(AbiIssue::UnknownLayout);
        }
    }
    Ok(result)
}

fn call_attribute<'a>(
    unit: &Unit<EndianSlice<'a, LittleEndian>>,
    origins: &[gimli::UnitOffset<usize>],
    name: gimli::DwAt,
) -> Result<Option<AttributeValue<EndianSlice<'a, LittleEndian>>>, AbiIssue> {
    let mut found = None;
    for offset in origins {
        let entry = match unit.entry(*offset).map_err(|_| AbiIssue::UnknownLayout) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        if let Some(value) = attribute(&entry, name) {
            if found.as_ref().is_some_and(|before| *before != value) {
                return Err(AbiIssue::UnknownLayout);
            }
            found = Some(value);
        }
    }
    Ok(found)
}

fn call_parameters(
    unit: &Unit<EndianSlice<'_, LittleEndian>>,
    origins: &[gimli::UnitOffset<usize>],
) -> Result<(Vec<gimli::UnitOffset<usize>>, bool), AbiIssue> {
    let mut found: Option<(Vec<gimli::UnitOffset<usize>>, bool)> = None;
    for offset in origins {
        let mut tree = match unit
            .entries_tree(Some(*offset))
            .map_err(|_| AbiIssue::UnknownLayout)
        {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let root = match tree.root().map_err(|_| AbiIssue::UnknownLayout) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let mut children = root.children();
        let mut parameters = Vec::new();
        let mut variadic = false;
        loop {
            let child = match children.next().map_err(|_| AbiIssue::UnknownLayout) {
                Ok(Some(child)) => child,
                Ok(None) => break,
                Err(error) => return Err(error),
            };

            match child.entry().tag() {
                gimli::DW_TAG_formal_parameter => parameters.push(child.entry().offset()),
                gimli::DW_TAG_unspecified_parameters => variadic = true,
                _ => {}
            }
        }
        if parameters.is_empty() && !variadic {
            continue;
        }
        if let Some((before, before_variadic)) = &found {
            if *before_variadic != variadic || before.len() != parameters.len() {
                return Err(AbiIssue::UnknownLayout);
            }
            for (before, parameter) in before.iter().zip(&parameters) {
                let type_origins = match call_origins(unit, *before) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let before = match call_attribute(unit, &type_origins, gimli::DW_AT_type) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let origins = match call_origins(unit, *parameter) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let parameter = match call_attribute(unit, &origins, gimli::DW_AT_type) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if before != parameter {
                    return Err(AbiIssue::UnknownLayout);
                }
            }
        } else {
            found = Some((parameters, variadic));
        }
    }
    Ok(found.unwrap_or_default())
}

fn call_function_types(
    dwarf: &Dwarf<EndianSlice<'_, LittleEndian>>,
    unit: &Unit<EndianSlice<'_, LittleEndian>>,
    entry: &gimli::DebuggingInformationEntry<EndianSlice<'_, LittleEndian>>,
    profile: AbiProfile,
) -> Result<FunctionTypes, AbiIssue> {
    let origins = match call_origins(unit, entry.offset()) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let prototyped = match call_attribute(unit, &origins, gimli::DW_AT_prototyped) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    if prototyped != Some(AttributeValue::Flag(true)) {
        return Err(AbiIssue::UnsupportedProfile);
    }
    let type_attribute = match call_attribute(unit, &origins, gimli::DW_AT_calling_convention) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    match type_attribute {
        None | Some(AttributeValue::CallingConvention(gimli::DW_CC_normal)) => {}
        _ => return Err(AbiIssue::UnsupportedProfile),
    }
    let type_attribute = match call_attribute(unit, &origins, gimli::DW_AT_type) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let result = match type_attribute {
        None => None,
        Some(AttributeValue::UnitRef(offset)) => Some(offset),
        _ => return Err(AbiIssue::UnknownLayout),
    };
    let ret = match result {
        None => Some(CType::Void),
        Some(offset) => type_name(dwarf, unit, offset, 16).filter(plausible_type),
    };
    let ret_layout = result
        .map(|offset| layout::read(unit, offset, 16))
        .transpose();
    let ret_aggregate_size = result.and_then(|offset| aggregate_size(unit, offset, 16));
    let (children, variadic) = match call_parameters(unit, &origins) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let mut params = Vec::new();
    let mut parameters = Vec::new();
    let mut param_layouts = Vec::new();
    let mut param_aggregate_sizes = Vec::new();
    for offset in children {
        let origins = match call_origins(unit, offset) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let type_attribute = match call_attribute(unit, &origins, gimli::DW_AT_type) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let Some(AttributeValue::UnitRef(offset)) = type_attribute else {
            return Err(AbiIssue::UnknownLayout);
        };
        let name = origins.iter().find_map(|offset| {
            unit.entry(*offset)
                .ok()
                .and_then(|entry| attribute(&entry, gimli::DW_AT_name))
                .and_then(|value| attribute_string(dwarf, unit, value))
        });
        params.push((
            name,
            type_name(dwarf, unit, offset, 16).filter(plausible_type),
        ));
        parameters.push(source_id(unit, offset));
        param_layouts.push(layout::read(unit, offset, 16));
        param_aggregate_sizes.push(aggregate_size(unit, offset, 16));
    }
    let function = match source_id(unit, entry.offset()).ok_or(AbiIssue::UnknownLayout) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    Ok(FunctionTypes {
        globals: Vec::new(),
        params,
        ret,
        ret_aggregate_size,
        param_aggregate_sizes,
        variadic,
        locals: Vec::new(),
        registers: Vec::new(),
        members: Vec::new(),
        definitions: Vec::new(),
        param_layouts,
        ret_layout,
        abi_profile: Ok(profile),
        source: FunctionSource {
            function,
            parameters,
            result: result.and_then(|offset| source_id(unit, offset)),
        },
    })
}

pub(crate) fn call_index(image: &Image) -> Result<CallIndex, AbiIssue> {
    let codeview = crate::loader::codeview::call_index(image);
    let mut found = match dwarf_call_index(image) {
        Ok(found) => found,
        Err(issue) if codeview.addresses.is_empty() => return Err(issue),
        Err(_) => return Ok(codeview),
    };
    for (address, sources) in codeview.addresses {
        found.addresses.entry(address).or_default().extend(sources);
    }
    Ok(found)
}

fn dwarf_call_index(image: &Image) -> Result<CallIndex, AbiIssue> {
    let dwarf = match call_dwarf(image) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let mut found = CallIndex::default();
    let mut units = dwarf.units();
    loop {
        let header = match units.next().map_err(|_| AbiIssue::UnknownLayout) {
            Ok(Some(header)) => header,
            Ok(None) => break,
            Err(error) => return Err(error),
        };

        let unit = match dwarf.unit(header).map_err(|_| AbiIssue::UnknownLayout) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let mut entries = unit.entries();
        loop {
            let entry = match entries.next_dfs().map_err(|_| AbiIssue::UnknownLayout) {
                Ok(Some(entry)) => entry,
                Ok(None) => break,
                Err(error) => return Err(error),
            };

            if entry.tag() != gimli::DW_TAG_subprogram {
                continue;
            }
            let Ok((address, ranges)) = call_entry(&dwarf, &unit, entry) else {
                continue;
            };
            if let Some(address) = address {
                let Some(source) = source_id(&unit, entry.offset()) else {
                    continue;
                };
                found.addresses.entry(address).or_default().push(source);
            }
            for range in ranges {
                match address.filter(|address| range.contains(address)) {
                    Some(address) => {
                        if range.start < address {
                            found.unresolved_ranges.push(range.start..address);
                        }
                        if let Some(after) =
                            address.checked_add(1).filter(|after| *after < range.end)
                        {
                            found.unresolved_ranges.push(after..range.end);
                        }
                    }
                    None => found.unresolved_ranges.push(range),
                }
            }
        }
    }
    Ok(found)
}

fn call_dimensions(
    unit: &Unit<EndianSlice<'_, LittleEndian>>,
    entry: &gimli::DebuggingInformationEntry<EndianSlice<'_, LittleEndian>>,
    source: &TypeLayout,
) -> Result<Vec<u64>, AbiIssue> {
    let crate::ir::abi::LayoutKind::Array { element, count } = &source.kind else {
        return Err(AbiIssue::UnknownLayout);
    };
    if !matches!(
        attribute(entry, gimli::DW_AT_ordering),
        None | Some(AttributeValue::Ordering(gimli::DW_ORD_row_major))
    ) || attribute(entry, gimli::DW_AT_bit_stride).is_some()
        || attribute(entry, gimli::DW_AT_GNU_vector).is_some()
    {
        return Err(AbiIssue::UnsupportedType);
    }
    if let Some(stride) = attribute(entry, gimli::DW_AT_byte_stride)
        && layout::number(stride) != Some(element.size)
    {
        return Err(AbiIssue::UnknownLayout);
    }
    let mut tree = match unit
        .entries_tree(Some(entry.offset()))
        .map_err(|_| AbiIssue::UnknownLayout)
    {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let root = match tree.root().map_err(|_| AbiIssue::UnknownLayout) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let mut children = root.children();
    let mut dimensions = Vec::new();
    let mut product = 1u64;
    loop {
        let child = match children.next().map_err(|_| AbiIssue::UnknownLayout) {
            Ok(Some(child)) => child,
            Ok(None) => break,
            Err(error) => return Err(error),
        };

        let child = child.entry();
        if child.tag() != gimli::DW_TAG_subrange_type {
            continue;
        }
        if dimensions.len() >= 256
            || attribute(child, gimli::DW_AT_abstract_origin).is_some()
            || attribute(child, gimli::DW_AT_specification).is_some()
            || attribute(child, gimli::DW_AT_byte_stride).is_some()
            || attribute(child, gimli::DW_AT_bit_stride).is_some()
        {
            return Err(AbiIssue::UnknownLayout);
        }
        let lower_bound = match attribute(child, gimli::DW_AT_lower_bound)
            .map(|value| layout::number(value).ok_or(AbiIssue::UnknownLayout))
            .transpose()
        {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let lower = lower_bound.unwrap_or(0);
        if lower != 0 {
            return Err(AbiIssue::UnsupportedType);
        }
        let count = match attribute(child, gimli::DW_AT_count)
            .map(|value| layout::number(value).ok_or(AbiIssue::UnknownLayout))
            .transpose()
        {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let upper_bound = match attribute(child, gimli::DW_AT_upper_bound)
            .map(|value| layout::number(value).ok_or(AbiIssue::UnknownLayout))
            .transpose()
        {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let upper = match upper_bound
            .map(|value| value.checked_add(1).ok_or(AbiIssue::UnknownLayout))
            .transpose()
        {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        if count
            .zip(upper)
            .is_some_and(|(count, upper)| count != upper)
        {
            return Err(AbiIssue::UnknownLayout);
        }
        let length = match count.or(upper).ok_or(AbiIssue::UnknownLayout) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        product = match product.checked_mul(length).ok_or(AbiIssue::UnknownLayout) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        dimensions.push(length);
    }
    if dimensions.is_empty() || product != *count {
        return Err(AbiIssue::UnknownLayout);
    }
    Ok(dimensions)
}

fn call_enumerators(
    dwarf: &Dwarf<EndianSlice<'_, LittleEndian>>,
    unit: &Unit<EndianSlice<'_, LittleEndian>>,
    entry: &gimli::DebuggingInformationEntry<EndianSlice<'_, LittleEndian>>,
) -> Result<Vec<(String, i128)>, AbiIssue> {
    let mut tree = match unit
        .entries_tree(Some(entry.offset()))
        .map_err(|_| AbiIssue::UnknownLayout)
    {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let root = match tree.root().map_err(|_| AbiIssue::UnknownLayout) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let mut children = root.children();
    let mut enumerators = Vec::new();
    loop {
        let child = match children.next().map_err(|_| AbiIssue::UnknownLayout) {
            Ok(Some(child)) => child,
            Ok(None) => break,
            Err(error) => return Err(error),
        };

        let child = child.entry();
        if child.tag() != gimli::DW_TAG_enumerator {
            continue;
        }
        if enumerators.len() >= 65536
            || attribute(child, gimli::DW_AT_abstract_origin).is_some()
            || attribute(child, gimli::DW_AT_specification).is_some()
        {
            return Err(AbiIssue::UnknownLayout);
        }
        let name = match attribute(child, gimli::DW_AT_name)
            .and_then(|value| attribute_string(dwarf, unit, value))
            .ok_or(AbiIssue::UnknownLayout)
        {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let value = match attribute(child, gimli::DW_AT_const_value) {
            Some(AttributeValue::Sdata(value)) => i128::from(value),
            Some(value) => {
                let size = match byte_count(value).ok_or(AbiIssue::UnknownLayout) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                i128::from(size)
            }
            None => return Err(AbiIssue::UnknownLayout),
        };
        enumerators.push((name, value));
    }
    Ok(enumerators)
}

pub(crate) fn call_unit(image: &Image, source: u64) -> Result<CallUnit, AbiIssue> {
    if source == crate::loader::codeview::SOURCE {
        return Ok(crate::loader::codeview::call_unit(image));
    }
    dwarf_call_unit(image, source)
}

fn dwarf_call_unit(image: &Image, source: u64) -> Result<CallUnit, AbiIssue> {
    let dwarf = match call_dwarf(image) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let mut units = dwarf.units();
    loop {
        let header = match units.next().map_err(|_| AbiIssue::UnknownLayout) {
            Ok(Some(header)) => header,
            Ok(None) => break,
            Err(error) => return Err(error),
        };

        if header
            .offset()
            .to_debug_info_offset(&header)
            .and_then(|offset| u64::try_from(offset.0).ok())
            != Some(source)
        {
            continue;
        }
        let unit = match dwarf.unit(header).map_err(|_| AbiIssue::UnknownLayout) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let mut found = CallUnit::default();
        let mut supported = false;
        let mut entries = unit.entries();
        loop {
            let entry = match entries.next_dfs().map_err(|_| AbiIssue::UnknownLayout) {
                Ok(Some(entry)) => entry,
                Ok(None) => break,
                Err(error) => return Err(error),
            };

            if entry.tag() != gimli::DW_TAG_subprogram {
                continue;
            }
            let Ok((Some(_), _)) = call_entry(&dwarf, &unit, entry) else {
                continue;
            };
            let Some(id) = source_id(&unit, entry.offset()) else {
                continue;
            };
            let profile = crate::ir::abi::profile(image.isa, image.format)
                .and_then(|profile| layout::function_profile(&unit, entry).map(|()| profile));
            let types =
                profile.and_then(|profile| call_function_types(&dwarf, &unit, entry, profile));
            supported |= types.as_ref().is_ok_and(|types| {
                !types.variadic
                    && types.ret.is_some()
                    && types.ret_layout.is_ok()
                    && types.params.iter().all(|(_, ty)| ty.is_some())
                    && types.param_layouts.iter().all(Result::is_ok)
            });
            found.functions.insert(id, types);
        }
        if !supported {
            return Ok(found);
        }
        let mut graph = TypeGraph::default();
        let profile = crate::ir::abi::profile(image.isa, image.format).ok();
        for (offset, definition, members) in definitions_with_sources(&dwarf, &unit, profile) {
            let id = match source_id(&unit, offset).ok_or(AbiIssue::UnknownLayout) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            graph.definitions.insert(id, definition);
            graph.generated_members.insert(id, members);
        }
        let mut entries = unit.entries();
        loop {
            let entry = match entries.next_dfs().map_err(|_| AbiIssue::UnknownLayout) {
                Ok(Some(entry)) => entry,
                Ok(None) => break,
                Err(error) => return Err(error),
            };

            if !matches!(
                entry.tag(),
                gimli::DW_TAG_base_type
                    | gimli::DW_TAG_pointer_type
                    | gimli::DW_TAG_array_type
                    | gimli::DW_TAG_structure_type
                    | gimli::DW_TAG_union_type
                    | gimli::DW_TAG_enumeration_type
                    | gimli::DW_TAG_typedef
                    | gimli::DW_TAG_const_type
                    | gimli::DW_TAG_volatile_type
                    | gimli::DW_TAG_restrict_type
            ) {
                continue;
            }
            let Some(id) = source_id(&unit, entry.offset()) else {
                continue;
            };
            let mut references = Vec::new();
            let mut members = Vec::new();
            let mut complete = attribute(entry, gimli::DW_AT_abstract_origin).is_none()
                && attribute(entry, gimli::DW_AT_specification).is_none();
            if let Some(value) = attribute(entry, gimli::DW_AT_type) {
                match value {
                    AttributeValue::UnitRef(offset) => {
                        let reference =
                            match source_id(&unit, offset).ok_or(AbiIssue::UnknownLayout) {
                                Ok(value) => value,
                                Err(error) => return Err(error),
                            };
                        references.push(reference)
                    }
                    _ => complete = false,
                }
            }
            if matches!(
                entry.tag(),
                gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type
            ) {
                let mut tree = match unit
                    .entries_tree(Some(entry.offset()))
                    .map_err(|_| AbiIssue::UnknownLayout)
                {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let root = match tree.root().map_err(|_| AbiIssue::UnknownLayout) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let mut children = root.children();
                loop {
                    let child = match children.next().map_err(|_| AbiIssue::UnknownLayout) {
                        Ok(Some(child)) => child,
                        Ok(None) => break,
                        Err(error) => return Err(error),
                    };

                    let child = child.entry();
                    if child.tag() != gimli::DW_TAG_member {
                        continue;
                    }
                    match attribute(child, gimli::DW_AT_type) {
                        Some(AttributeValue::UnitRef(offset)) => {
                            let source =
                                match source_id(&unit, offset).ok_or(AbiIssue::UnknownLayout) {
                                    Ok(value) => value,
                                    Err(error) => return Err(error),
                                };
                            references.push(source);
                            let name = attribute(child, gimli::DW_AT_name)
                                .and_then(|value| attribute_string(&dwarf, &unit, value));
                            members.push((name, source));
                            complete &= attribute(child, gimli::DW_AT_abstract_origin).is_none()
                                && attribute(child, gimli::DW_AT_specification).is_none();
                        }
                        _ => complete = false,
                    }
                }
            }
            let source_layout = layout::read(&unit, entry.offset(), 16);
            let mut dimensions = Vec::new();
            if entry.tag() == gimli::DW_TAG_array_type {
                match source_layout
                    .as_ref()
                    .map_err(|issue| *issue)
                    .and_then(|layout| call_dimensions(&unit, entry, layout))
                {
                    Ok(found) => dimensions = found,
                    Err(_) => complete = false,
                }
            }
            if matches!(
                entry.tag(),
                gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type
            ) && attribute(entry, gimli::DW_AT_declaration).is_none()
                && source_layout.is_err()
            {
                complete = false;
            }
            let mut enumerators = Vec::new();
            if entry.tag() == gimli::DW_TAG_enumeration_type {
                match call_enumerators(&dwarf, &unit, entry) {
                    Ok(found) => enumerators = found,
                    Err(_) => complete = false,
                }
            }
            graph.types.insert(
                id,
                CallType {
                    tag: entry.tag().0,
                    name: attribute(entry, gimli::DW_AT_name)
                        .and_then(|value| attribute_string(&dwarf, &unit, value)),
                    spelling: type_name(&dwarf, &unit, entry.offset(), 16).filter(plausible_type),
                    size: attribute(entry, gimli::DW_AT_byte_size).and_then(byte_count),
                    encoding: match attribute(entry, gimli::DW_AT_encoding) {
                        Some(AttributeValue::Encoding(encoding)) => Some(u16::from(encoding.0)),
                        _ => None,
                    },
                    layout: source_layout,
                    dimensions,
                    enumerators,
                    references,
                    members,
                    complete,
                    pointer: entry.tag() == gimli::DW_TAG_pointer_type,
                    aggregate: matches!(
                        entry.tag(),
                        gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type
                    ),
                },
            );
        }
        found.graph = Arc::new(graph);
        return Ok(found);
    }
    Err(AbiIssue::UnknownLayout)
}

#[cfg(test)]
mod tests;

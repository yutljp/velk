use super::{attribute, plausible_type, type_name, type_size};
use crate::ir::CType;
use crate::loader::Image;
use gimli::{AttributeValue, Dwarf, EndianSlice, LittleEndian, Operation, Unit};

pub(super) fn read(
    dwarf: &Dwarf<EndianSlice<'_, LittleEndian>>,
    unit: &Unit<EndianSlice<'_, LittleEndian>>,
    image: &Image,
) -> Vec<(u64, CType, u64)> {
    let mut globals = Vec::new();
    let mut entries = unit.entries();
    let Ok(Some(root)) = entries.next_dfs() else {
        return globals;
    };
    if !matches!(
        attribute(root, gimli::DW_AT_language),
        Some(AttributeValue::Language(
            gimli::DW_LANG_C
                | gimli::DW_LANG_C89
                | gimli::DW_LANG_C99
                | gimli::DW_LANG_C11
                | gimli::DW_LANG_C17
                | gimli::DW_LANG_C_plus_plus
                | gimli::DW_LANG_C_plus_plus_03
                | gimli::DW_LANG_C_plus_plus_11
                | gimli::DW_LANG_C_plus_plus_14
                | gimli::DW_LANG_C_plus_plus_17
                | gimli::DW_LANG_C_plus_plus_20
        ))
    ) {
        return globals;
    }
    while let Ok(Some(entry)) = entries.next_dfs() {
        if entry.tag() != gimli::DW_TAG_variable {
            continue;
        }
        let Some(AttributeValue::Exprloc(expression)) = attribute(entry, gimli::DW_AT_location)
        else {
            continue;
        };
        let mut operations = expression.operations(unit.encoding());
        let address = match operations.next() {
            Ok(Some(Operation::Address { address })) => address,
            Ok(Some(Operation::AddressIndex { index })) => match dwarf.address(unit, index) {
                Ok(address) => address,
                Err(_) => continue,
            },
            _ => continue,
        };
        if !matches!(operations.next(), Ok(None)) || !image.data_symbols.contains_key(&address) {
            continue;
        }
        let Some(AttributeValue::UnitRef(offset)) = attribute(entry, gimli::DW_AT_type) else {
            continue;
        };
        let Some(ty) = type_name(dwarf, unit, offset, 8).filter(plausible_type) else {
            continue;
        };
        if unqualified(unit, offset, 8)
            && let Some(size) = type_size(unit, offset, 8)
            && size != 0
            && address.checked_add(size).is_some()
        {
            globals.push((address, ty, size));
        }
    }
    globals
}

// The renderer does not preserve volatile or atomic type qualifiers.
fn unqualified(
    unit: &Unit<EndianSlice<'_, LittleEndian>>,
    offset: gimli::UnitOffset<usize>,
    depth: usize,
) -> bool {
    if depth == 0 {
        return false;
    }
    let Ok(entry) = unit.entry(offset) else {
        return false;
    };
    match entry.tag() {
        gimli::DW_TAG_base_type | gimli::DW_TAG_structure_type => true,
        gimli::DW_TAG_typedef | gimli::DW_TAG_array_type => {
            let Some(AttributeValue::UnitRef(inner)) = attribute(&entry, gimli::DW_AT_type) else {
                return false;
            };
            unqualified(unit, inner, depth - 1)
        }
        _ => false,
    }
}

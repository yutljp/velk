//! Scalar virtual-method declarations whose result type is in a specification.

use gimli::{AttributeValue, Dwarf, EndianSlice, LittleEndian};

use crate::loader::Image;

use super::FunctionTypes;

pub(crate) fn function_types(image: &Image, address: u64) -> Option<FunctionTypes> {
    let Some(mut types) = super::function_types(image, address) else {
        return None;
    };
    if types.abi_profile.is_ok() {
        return Some(types);
    }
    let Ok(profile) = crate::ir::abi::profile(image.isa, image.format) else {
        return None;
    };
    let Ok(dwarf) = Dwarf::load(|id| -> Result<EndianSlice<'_, LittleEndian>, ()> {
        Ok(EndianSlice::new(super::section(image, id), LittleEndian))
    }) else {
        return None;
    };
    let mut units = dwarf.units();
    while let Ok(Some(header)) = units.next() {
        let Ok(unit) = dwarf.unit(header) else {
            continue;
        };
        let mut entries = unit.entries();
        while let Ok(Some(entry)) = entries.next_dfs() {
            if entry.tag() != gimli::DW_TAG_subprogram
                || super::resolve_low(&dwarf, &unit, entry) != Some(address)
            {
                continue;
            }
            let Ok(origins) = super::calls::call_origins(&unit, entry.offset()) else {
                return None;
            };
            let mut result = None;
            for origin in origins {
                let Ok(origin) = unit.entry(origin) else {
                    return None;
                };
                match super::attribute(&origin, gimli::DW_AT_calling_convention) {
                    None | Some(AttributeValue::CallingConvention(gimli::DW_CC_normal)) => {}
                    _ => return None,
                }
                let Ok(mut tree) = unit.entries_tree(Some(origin.offset())) else {
                    return None;
                };
                let Ok(root) = tree.root() else {
                    return None;
                };
                let mut children = root.children();
                let mut count = 0usize;
                loop {
                    let child = match children.next() {
                        Ok(Some(child)) => child,
                        Ok(None) => break,
                        Err(_) => return None,
                    };
                    match child.entry().tag() {
                        gimli::DW_TAG_formal_parameter => count = count.saturating_add(1),
                        gimli::DW_TAG_unspecified_parameters => return None,
                        _ => {}
                    }
                }
                if count != types.params.len() {
                    return None;
                }
                if let Some(value) = super::attribute(&origin, gimli::DW_AT_type) {
                    if result.is_some_and(|known| known != value) {
                        return None;
                    }
                    result = Some(value);
                }
            }
            let Some(AttributeValue::UnitRef(result)) = result else {
                return None;
            };
            let Some(ret) = super::type_name(&dwarf, &unit, result, 16) else {
                return None;
            };
            if !ret.is_pointer()
                && !ret
                    .integer()
                    .is_some_and(|(bits, _)| matches!(bits, 32 | 64))
            {
                return None;
            }
            let Ok(layout) = super::layout::read(&unit, result, 16) else {
                return None;
            };
            types.ret = Some(ret);
            types.ret_layout = Ok(Some(layout));
            types.ret_aggregate_size = None;
            types.abi_profile = Ok(profile);
            return Some(types);
        }
    }
    None
}

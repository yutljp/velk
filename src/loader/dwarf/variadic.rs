use std::collections::{HashMap, HashSet};

use gimli::{Dwarf, EndianSlice, LittleEndian, SectionId};

use crate::loader::{Format, Image, Isa};

/// Mach-O uses native section names for the declaration that distinguishes a
/// variadic stack cursor from a named stack argument's address.
pub(crate) fn functions(image: &Image) -> HashMap<u64, usize> {
    let mut found = HashMap::new();
    let mut conflicts = HashSet::new();
    if image.format != Format::MachO
        || image.isa != Isa::AArch64
        || image.byte_order() != Some(object::Endianness::Little)
    {
        return found;
    }
    let dwarf = Dwarf::load(|id| -> Result<EndianSlice<'_, LittleEndian>, ()> {
        let name = match id {
            SectionId::DebugStrOffsets => "__debug_str_offs".to_owned(),
            _ => format!("__{}", id.name().trim_start_matches('.')),
        };
        Ok(EndianSlice::new(
            image.section_data(&name).unwrap_or(&[]),
            LittleEndian,
        ))
    });
    let Ok(dwarf) = dwarf else {
        return found;
    };
    let mut units = dwarf.units();
    while let Ok(Some(header)) = units.next() {
        let Ok(unit) = dwarf.unit(header) else {
            continue;
        };
        let mut entries = unit.entries();
        let mut function = None;
        while let Ok(Some(entry)) = entries.next_dfs() {
            if function.is_some_and(|(depth, _, _)| entry.depth() <= depth) {
                function = None;
            }
            if entry.tag() == gimli::DW_TAG_subprogram {
                function = super::resolve_low(&dwarf, &unit, entry)
                    .map(|address| (entry.depth(), address, 0usize));
            }
            if entry.tag() == gimli::DW_TAG_formal_parameter
                && let Some((depth, _, count)) = &mut function
                && entry.depth() == *depth + 1
            {
                *count = count.saturating_add(1);
            }
            if entry.tag() == gimli::DW_TAG_unspecified_parameters
                && let Some((depth, address, count)) = function
                && entry.depth() == depth + 1
                && image.functions.contains_key(&address)
                && found
                    .insert(address, count)
                    .is_some_and(|previous| previous != count)
            {
                conflicts.insert(address);
            }
        }
    }
    found.retain(|address, _| !conflicts.contains(address));
    found
}

//! Aggregate declarations and flattened member paths from DWARF.

use super::{
    attribute, attribute_offset, attribute_string, byte_count, layout, plausible_type, source_id,
    type_name, type_size,
};
use crate::ir::calls::CallMember;
use crate::ir::{AbiProfile, CType, Definition, Member};
use gimli::{AttributeValue, Dwarf, EndianSlice, LittleEndian, Unit};

/// The C definition of each named structure and union in the unit whose
/// members all have a known type and size; a member that is a bit-field,
/// or of an unnamed type, is left a gap of its bytes.
pub(super) fn definitions(
    dwarf: &Dwarf<EndianSlice<'_, LittleEndian>>,
    unit: &Unit<EndianSlice<'_, LittleEndian>>,
    profile: Option<AbiProfile>,
) -> Vec<Definition> {
    definitions_with_sources(dwarf, unit, profile)
        .into_iter()
        .map(|(_, definition, _)| definition)
        .collect()
}

pub(super) fn definitions_with_sources(
    dwarf: &Dwarf<EndianSlice<'_, LittleEndian>>,
    unit: &Unit<EndianSlice<'_, LittleEndian>>,
    profile: Option<AbiProfile>,
) -> Vec<(gimli::UnitOffset<usize>, Definition, Vec<CallMember>)> {
    let mut found = Vec::new();
    let mut entries = unit.entries();
    let mut aggregates = Vec::new();
    while let Ok(Some(entry)) = entries.next_dfs() {
        let union = match entry.tag() {
            gimli::DW_TAG_structure_type => false,
            gimli::DW_TAG_union_type => true,
            _ => continue,
        };
        // A declaration alone has no members to give.
        if attribute(entry, gimli::DW_AT_declaration).is_some() {
            continue;
        }
        let Some(name) = attribute(entry, gimli::DW_AT_name)
            .and_then(|value| attribute_string(dwarf, unit, value))
        else {
            continue;
        };
        let Some(size) = attribute(entry, gimli::DW_AT_byte_size).and_then(byte_count) else {
            continue;
        };
        aggregates.push((entry.offset(), name, union, size));
    }
    'aggregates: for (offset, name, union, size) in aggregates {
        let keyword = if union { "union" } else { "struct" };
        let mut members = Vec::new();
        let mut generated_members = Vec::new();
        let mut fields = Vec::new();
        let mut contains = Vec::new();
        let mut end = 0u64;
        let Ok(mut tree) = unit.entries_tree(Some(offset)) else {
            continue;
        };
        let Ok(root) = tree.root() else {
            continue;
        };
        let mut children = root.children();
        while let Ok(Some(child)) = children.next() {
            let child = child.entry();
            if child.tag() != gimli::DW_TAG_member {
                continue;
            }
            let at = if union {
                0
            } else {
                attribute(child, gimli::DW_AT_data_member_location)
                    .and_then(|value| attribute_offset(dwarf, unit, value))
                    .unwrap_or(0)
            };
            let Some(AttributeValue::UnitRef(ty_offset)) = attribute(child, gimli::DW_AT_type)
            else {
                continue 'aggregates;
            };
            let Some(width) = type_size(unit, ty_offset, 8) else {
                continue 'aggregates;
            };
            if at < end {
                // A bit-field sharing bytes with the one before.
                continue;
            }
            let member_name = attribute(child, gimli::DW_AT_name)
                .and_then(|value| attribute_string(dwarf, unit, value));
            let ty = type_name(dwarf, unit, ty_offset, 8).filter(plausible_type);
            let declared = match (member_name, ty) {
                (Some(member_name), Some(ty))
                    if attribute(child, gimli::DW_AT_bit_size).is_none() =>
                {
                    let Some(declaration) =
                        layout::declaration(dwarf, unit, ty_offset, &member_name, 16)
                    else {
                        continue 'aggregates;
                    };
                    let mut contained = &ty;
                    while let CType::Array(element) = contained {
                        contained = element;
                    }
                    if let CType::Named(named) = contained
                        && (named.starts_with("struct ") || named.starts_with("union "))
                    {
                        contains.push(named.clone());
                    }
                    fields.push(member_name.clone());
                    let Some(ty) = source_id(unit, ty_offset) else {
                        continue 'aggregates;
                    };
                    Some((
                        declaration,
                        CallMember::Field {
                            name: member_name,
                            ty,
                            offset: at,
                            bytes: width,
                        },
                    ))
                }
                _ => None,
            };
            if union {
                if let Some((declaration, member)) = declared {
                    members.push(declaration);
                    generated_members.push(member);
                }
                continue;
            }
            if at > end {
                members.push(format!("uint8_t gap_0x{end:x}[0x{:x}];", at - end));
                generated_members.push(CallMember::Bytes {
                    offset: end,
                    bytes: at - end,
                });
            }
            let width = if declared.is_none() {
                width.min(size.saturating_sub(at))
            } else {
                width
            };
            if width == 0 {
                continue;
            }
            match declared {
                Some((declaration, member)) => {
                    members.push(declaration);
                    generated_members.push(member);
                }
                None => {
                    members.push(format!("uint8_t gap_0x{at:x}[0x{width:x}];"));
                    generated_members.push(CallMember::Bytes {
                        offset: at,
                        bytes: width,
                    });
                }
            }
            end = at.saturating_add(width);
        }
        if !union && size > end {
            members.push(format!("uint8_t gap_0x{end:x}[0x{:x}];", size - end));
            generated_members.push(CallMember::Bytes {
                offset: end,
                bytes: size - end,
            });
        }
        if union && members.is_empty() && size > 0 {
            members.push(format!("uint8_t gap_0x0[0x{size:x}];"));
            generated_members.push(CallMember::Bytes {
                offset: 0,
                bytes: size,
            });
        }
        if members.is_empty() {
            continue;
        }
        let original = layout::read(unit, offset, 16);
        let generated = layout::generated(dwarf, unit, offset, 16);
        let alignment = generated.as_ref().ok().and_then(|layout| layout.alignment);
        let compatible_profiles = profile
            .filter(|profile| {
                let (Ok(original), Ok(generated)) = (&original, &generated) else {
                    return false;
                };
                crate::ir::abi::compatible(*profile, original, generated).is_ok()
            })
            .into_iter()
            .collect();
        found.push((
            offset,
            Definition {
                name: format!("{keyword} {name}"),
                members,
                fields,
                contains,
                size,
                alignment,
                compatible_profiles,
            },
            generated_members,
        ));
    }
    found
}

/// Each structure's name and direct fields: offset, name and type.
type StructureFields = std::collections::HashMap<
    gimli::UnitOffset,
    (Option<String>, Vec<(u64, String, gimli::UnitOffset)>),
>;

/// The named fields of every structure in the unit, by byte offset. A field
/// that is itself a structure or union names the fields inside it with a
/// path, as `max.x`, since an access reaches those.
pub(super) fn structure_members(
    dwarf: &Dwarf<EndianSlice<'_, LittleEndian>>,
    unit: &Unit<EndianSlice<'_, LittleEndian>>,
    definitions: &[Definition],
) -> Vec<Member> {
    use std::collections::HashMap;
    let mut fields: StructureFields = HashMap::new();
    let mut aliases: HashMap<gimli::UnitOffset, gimli::UnitOffset> = HashMap::new();
    let mut declared = HashMap::new();
    let mut entries = unit.entries();
    let mut ancestors = Vec::new();
    let type_of =
        |entry: &gimli::DebuggingInformationEntry<EndianSlice<'_, LittleEndian>>| match attribute(
            entry,
            gimli::DW_AT_type,
        ) {
            Some(AttributeValue::UnitRef(offset)) => Some(offset),
            _ => None,
        };
    while let Ok(Some(entry)) = entries.next_dfs() {
        while ancestors
            .last()
            .is_some_and(|(depth, _)| *depth >= entry.depth())
        {
            ancestors.pop();
        }
        match entry.tag() {
            gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type => {
                let name = attribute(entry, gimli::DW_AT_name)
                    .and_then(|value| attribute_string(dwarf, unit, value));
                let keyword = if entry.tag() == gimli::DW_TAG_union_type {
                    "union"
                } else {
                    "struct"
                };
                if let Some(definition) = name.as_ref().and_then(|name| {
                    definitions
                        .iter()
                        .find(|definition| definition.name == format!("{keyword} {name}"))
                }) {
                    declared.insert(entry.offset(), &definition.fields);
                }
                fields.insert(entry.offset(), (name, Vec::new()));
                ancestors.push((entry.depth(), entry.offset()));
            }
            gimli::DW_TAG_typedef
            | gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type => {
                if let Some(target) = type_of(entry) {
                    aliases.insert(entry.offset(), target);
                }
            }
            gimli::DW_TAG_member => {
                let Some((depth, structure)) = ancestors.last() else {
                    continue;
                };
                if entry.depth() != depth + 1 || attribute(entry, gimli::DW_AT_bit_size).is_some() {
                    continue;
                }
                let Some(name) = attribute(entry, gimli::DW_AT_name)
                    .and_then(|value| attribute_string(dwarf, unit, value))
                else {
                    continue;
                };
                if !declared
                    .get(structure)
                    .is_some_and(|names| names.contains(&name))
                {
                    continue;
                }
                let Some(ty) = type_of(entry) else {
                    continue;
                };
                let offset = attribute(entry, gimli::DW_AT_data_member_location)
                    .and_then(|value| attribute_offset(dwarf, unit, value))
                    .unwrap_or(0);
                if let Some((_, list)) = fields.get_mut(structure) {
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
        out: &mut Vec<(u64, String, gimli::UnitOffset)>,
    ) {
        let Some((_, list)) = fields.get(&structure) else {
            return;
        };
        for (offset, name, ty) in list {
            let Some(at) = base.checked_add(*offset) else {
                continue;
            };
            let path = format!("{prefix}{name}");
            let inner = resolve(*ty);
            if fields.contains_key(&inner) && depth < 4 {
                flatten(
                    inner,
                    at,
                    &format!("{path}."),
                    depth + 1,
                    fields,
                    resolve,
                    out,
                );
            } else {
                out.push((at, path, *ty));
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
        for (field_offset, path, ty_offset) in flat {
            let Some(ty) = type_name(dwarf, unit, ty_offset, 8).filter(plausible_type) else {
                continue;
            };
            let Some(width) = type_size(unit, ty_offset, 8).filter(|width| *width > 0) else {
                continue;
            };
            let Ok(offset) = i64::try_from(field_offset) else {
                continue;
            };
            if seen.insert(field_offset) {
                members.push(Member {
                    structure: structure.clone(),
                    offset,
                    name: path,
                    ty,
                    width,
                });
            }
        }
    }
    members.sort_by(|a, b| (&a.structure, a.offset).cmp(&(&b.structure, b.offset)));
    members
}

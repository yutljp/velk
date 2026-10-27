use super::{attribute, attribute_string, byte_count, plausible_type, type_name, type_size};
use crate::ir::abi::{LayoutField, LayoutKind, TypeLayout};
use crate::ir::{AbiIssue, Precision};
use gimli::{AttributeValue, Dwarf, EndianSlice, LittleEndian, Unit};

type Reader<'a> = EndianSlice<'a, LittleEndian>;

pub(super) fn function_profile(
    unit: &Unit<Reader<'_>>,
    function: &gimli::DebuggingInformationEntry<Reader<'_>>,
) -> Result<(), AbiIssue> {
    let mut entries = unit.entries();
    let root = entries
        .next_dfs()
        .map_err(|_| AbiIssue::UnknownLayout)?
        .ok_or(AbiIssue::UnknownLayout)?;
    if !matches!(
        attribute(root, gimli::DW_AT_language),
        Some(AttributeValue::Language(
            gimli::DW_LANG_C
                | gimli::DW_LANG_C89
                | gimli::DW_LANG_C99
                | gimli::DW_LANG_C11
                | gimli::DW_LANG_C17
        ))
    ) {
        return Err(AbiIssue::UnsupportedProfile);
    }
    match attribute(function, gimli::DW_AT_calling_convention) {
        None | Some(AttributeValue::CallingConvention(gimli::DW_CC_normal)) => Ok(()),
        _ => Err(AbiIssue::UnsupportedProfile),
    }
}

pub(super) fn number(value: AttributeValue<Reader<'_>>) -> Option<u64> {
    match value {
        AttributeValue::Sdata(value) => value.try_into().ok(),
        value => byte_count(value),
    }
}

fn alignment(value: Option<AttributeValue<Reader<'_>>>) -> Result<Option<u64>, AbiIssue> {
    value
        .map(|value| {
            number(value)
                .filter(|n| n.is_power_of_two())
                .ok_or(AbiIssue::UnknownLayout)
        })
        .transpose()
}

fn type_offset(
    entry: &gimli::DebuggingInformationEntry<Reader<'_>>,
) -> Result<gimli::UnitOffset, AbiIssue> {
    match attribute(entry, gimli::DW_AT_type) {
        Some(AttributeValue::UnitRef(offset)) => Ok(offset),
        _ => Err(AbiIssue::UnknownLayout),
    }
}

pub(super) fn read(
    unit: &Unit<Reader<'_>>,
    offset: gimli::UnitOffset,
    depth: usize,
) -> Result<TypeLayout, AbiIssue> {
    if depth == 0 {
        return Err(AbiIssue::UnknownLayout);
    }
    let entry = unit.entry(offset).map_err(|_| AbiIssue::UnknownLayout)?;
    let explicit_alignment = alignment(attribute(&entry, gimli::DW_AT_alignment))?;
    let byte_size = attribute(&entry, gimli::DW_AT_byte_size).and_then(number);
    if matches!(
        entry.tag(),
        gimli::DW_TAG_typedef
            | gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type
            | gimli::DW_TAG_atomic_type
    ) {
        let mut layout = read(unit, type_offset(&entry)?, depth - 1)?;
        if explicit_alignment.is_some() {
            layout.alignment = explicit_alignment;
        }
        return Ok(layout);
    }
    let (size, natural_alignment, kind, trivial) = match entry.tag() {
        gimli::DW_TAG_pointer_type => {
            let size = byte_size.unwrap_or(u64::from(unit.encoding().address_size));
            (size, Some(size), LayoutKind::Pointer, true)
        }
        gimli::DW_TAG_base_type => {
            let size = byte_size.ok_or(AbiIssue::UnknownLayout)?;
            let kind = match attribute(&entry, gimli::DW_AT_encoding) {
                Some(AttributeValue::Encoding(
                    gimli::DW_ATE_signed
                    | gimli::DW_ATE_unsigned
                    | gimli::DW_ATE_signed_char
                    | gimli::DW_ATE_unsigned_char,
                )) => LayoutKind::Integer,
                Some(AttributeValue::Encoding(gimli::DW_ATE_boolean)) if size == 1 => {
                    LayoutKind::Boolean
                }
                Some(AttributeValue::Encoding(gimli::DW_ATE_float)) => match size {
                    4 => LayoutKind::Float(Precision::Single),
                    8 => LayoutKind::Float(Precision::Double),
                    _ => return Err(AbiIssue::UnsupportedType),
                },
                _ => return Err(AbiIssue::UnsupportedType),
            };
            if !matches!(size, 1 | 2 | 4 | 8 | 16) {
                return Err(AbiIssue::UnsupportedType);
            }
            (size, Some(size), kind, true)
        }
        gimli::DW_TAG_enumeration_type => {
            let mut layout = read(unit, type_offset(&entry)?, depth - 1)?;
            if !matches!(layout.kind, LayoutKind::Integer) {
                return Err(AbiIssue::UnsupportedType);
            }
            if explicit_alignment.is_some() {
                layout.alignment = explicit_alignment;
            }
            return Ok(layout);
        }
        gimli::DW_TAG_array_type => {
            let element = read(unit, type_offset(&entry)?, depth - 1)?;
            let count = array_count(unit, offset)?;
            if attribute(&entry, gimli::DW_AT_byte_stride)
                .and_then(number)
                .is_some_and(|stride| stride != element.size)
                || attribute(&entry, gimli::DW_AT_bit_stride).is_some()
            {
                return Err(AbiIssue::UnsupportedType);
            }
            let size = element
                .size
                .checked_mul(count)
                .ok_or(AbiIssue::UnknownLayout)?;
            if byte_size.is_some_and(|declared| declared != size) {
                return Err(AbiIssue::UnknownLayout);
            }
            let alignment = element.alignment;
            let trivial = element.trivial;
            (
                size,
                alignment,
                LayoutKind::Array {
                    element: Box::new(element),
                    count,
                },
                trivial,
            )
        }
        gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type | gimli::DW_TAG_class_type => {
            if attribute(&entry, gimli::DW_AT_declaration).is_some() {
                return Err(AbiIssue::UnknownLayout);
            }
            let size = byte_size.ok_or(AbiIssue::UnknownLayout)?;
            let union = entry.tag() == gimli::DW_TAG_union_type;
            let mut trivial = entry.tag() != gimli::DW_TAG_class_type
                && matches!(
                    attribute(&entry, gimli::DW_AT_calling_convention),
                    None | Some(AttributeValue::CallingConvention(
                        gimli::DW_CC_normal | gimli::DW_CC_pass_by_value
                    ))
                );
            let mut fields = Vec::new();
            let mut tree = unit
                .entries_tree(Some(offset))
                .map_err(|_| AbiIssue::UnknownLayout)?;
            let root = tree.root().map_err(|_| AbiIssue::UnknownLayout)?;
            let mut children = root.children();
            while let Some(child) = children.next().map_err(|_| AbiIssue::UnknownLayout)? {
                let child = child.entry();
                if matches!(
                    child.tag(),
                    gimli::DW_TAG_inheritance | gimli::DW_TAG_subprogram
                ) {
                    trivial = false;
                }
                if child.tag() != gimli::DW_TAG_member {
                    continue;
                }
                if attribute(child, gimli::DW_AT_external) == Some(AttributeValue::Flag(true)) {
                    continue;
                }
                if attribute(child, gimli::DW_AT_alignment).is_some() {
                    return Err(AbiIssue::UnsupportedType);
                }
                let field = read(unit, type_offset(child)?, depth - 1)?;
                trivial &= field.trivial;
                let bit_size = attribute(child, gimli::DW_AT_bit_size).and_then(number);
                let at = if union || attribute(child, gimli::DW_AT_data_bit_offset).is_some() {
                    0
                } else {
                    attribute(child, gimli::DW_AT_data_member_location)
                        .and_then(number)
                        .ok_or(AbiIssue::UnknownLayout)?
                };
                let bit_offset = field_bit_offset(child, at, field.size, bit_size)?;
                let defined = bit_size.is_none() || attribute(child, gimli::DW_AT_name).is_some();
                fields.push(LayoutField {
                    bit_offset,
                    bit_size,
                    layout: field,
                    defined,
                });
            }
            let kind = if union {
                LayoutKind::Union(fields)
            } else {
                LayoutKind::Struct(fields)
            };
            (size, None, kind, trivial)
        }
        _ => return Err(AbiIssue::UnsupportedType),
    };
    Ok(TypeLayout {
        size,
        alignment: explicit_alignment.or(natural_alignment),
        kind,
        trivial,
    })
}

fn field_bit_offset(
    entry: &gimli::DebuggingInformationEntry<Reader<'_>>,
    at: u64,
    storage_size: u64,
    bit_size: Option<u64>,
) -> Result<u64, AbiIssue> {
    if let Some(offset) = attribute(entry, gimli::DW_AT_data_bit_offset) {
        return number(offset).ok_or(AbiIssue::UnknownLayout);
    }
    let start = at.checked_mul(8).ok_or(AbiIssue::UnknownLayout)?;
    match attribute(entry, gimli::DW_AT_bit_offset) {
        Some(offset) => {
            let offset = number(offset).ok_or(AbiIssue::UnknownLayout)?;
            let size = bit_size.ok_or(AbiIssue::UnknownLayout)?;
            let low = storage_size
                .checked_mul(8)
                .and_then(|storage| storage.checked_sub(offset))
                .and_then(|high| high.checked_sub(size))
                .ok_or(AbiIssue::UnknownLayout)?;
            start.checked_add(low).ok_or(AbiIssue::UnknownLayout)
        }
        None => Ok(start),
    }
}

pub(super) fn array_count(
    unit: &Unit<Reader<'_>>,
    offset: gimli::UnitOffset,
) -> Result<u64, AbiIssue> {
    let mut tree = unit
        .entries_tree(Some(offset))
        .map_err(|_| AbiIssue::UnknownLayout)?;
    let root = tree.root().map_err(|_| AbiIssue::UnknownLayout)?;
    let mut children = root.children();
    let mut count = None;
    while let Some(child) = children.next().map_err(|_| AbiIssue::UnknownLayout)? {
        let child = child.entry();
        if child.tag() != gimli::DW_TAG_subrange_type {
            continue;
        }
        let lower = match attribute(child, gimli::DW_AT_lower_bound) {
            Some(value) => number(value).ok_or(AbiIssue::UnknownLayout)?,
            None => 0,
        };
        let length = match attribute(child, gimli::DW_AT_count) {
            Some(value) => number(value),
            None => attribute(child, gimli::DW_AT_upper_bound)
                .and_then(number)
                .and_then(|upper| upper.checked_sub(lower))
                .and_then(|n| n.checked_add(1)),
        }
        .ok_or(AbiIssue::UnknownLayout)?;
        count = Some(
            count
                .unwrap_or(1u64)
                .checked_mul(length)
                .ok_or(AbiIssue::UnknownLayout)?,
        );
    }
    count.ok_or(AbiIssue::UnknownLayout)
}

pub(super) fn declaration(
    dwarf: &Dwarf<Reader<'_>>,
    unit: &Unit<Reader<'_>>,
    offset: gimli::UnitOffset,
    name: &str,
    depth: usize,
) -> Option<String> {
    if depth == 0 {
        return None;
    }
    let entry = unit.entry(offset).ok()?;
    match entry.tag() {
        gimli::DW_TAG_typedef
        | gimli::DW_TAG_const_type
        | gimli::DW_TAG_volatile_type
        | gimli::DW_TAG_restrict_type
        | gimli::DW_TAG_atomic_type => {
            declaration(dwarf, unit, type_offset(&entry).ok()?, name, depth - 1)
        }
        gimli::DW_TAG_array_type => {
            let count = array_count(unit, offset).ok()?;
            declaration(
                dwarf,
                unit,
                type_offset(&entry).ok()?,
                &format!("{name}[{count}]"),
                depth - 1,
            )
        }
        _ => {
            let ty = type_name(dwarf, unit, offset, depth).filter(plausible_type)?;
            let separator = if ty.is_pointer() { "" } else { " " };
            Some(format!("{ty}{separator}{name};"))
        }
    }
}

fn bytes(size: u64) -> TypeLayout {
    TypeLayout {
        size,
        alignment: Some(1),
        kind: LayoutKind::Array {
            element: Box::new(TypeLayout {
                size: 1,
                alignment: Some(1),
                kind: LayoutKind::Integer,
                trivial: true,
            }),
            count: size,
        },
        trivial: true,
    }
}

fn rounded(value: u64, alignment: u64) -> Result<u64, AbiIssue> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or(AbiIssue::UnknownLayout)
}

pub(super) fn generated(
    dwarf: &Dwarf<Reader<'_>>,
    unit: &Unit<Reader<'_>>,
    offset: gimli::UnitOffset,
    depth: usize,
) -> Result<TypeLayout, AbiIssue> {
    let original = crate::ir::abi::canonical(&read(unit, offset, depth)?)?;
    let entry = unit.entry(offset).map_err(|_| AbiIssue::UnknownLayout)?;
    match entry.tag() {
        gimli::DW_TAG_typedef
        | gimli::DW_TAG_const_type
        | gimli::DW_TAG_volatile_type
        | gimli::DW_TAG_restrict_type
        | gimli::DW_TAG_atomic_type => {
            return generated(dwarf, unit, type_offset(&entry)?, depth - 1);
        }
        gimli::DW_TAG_array_type => {
            let element = generated(dwarf, unit, type_offset(&entry)?, depth - 1)?;
            let count = array_count(unit, offset)?;
            return Ok(TypeLayout {
                size: element
                    .size
                    .checked_mul(count)
                    .ok_or(AbiIssue::UnknownLayout)?,
                alignment: element.alignment,
                trivial: element.trivial,
                kind: LayoutKind::Array {
                    element: Box::new(element),
                    count,
                },
            });
        }
        gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type => {}
        _ => return Ok(original),
    }
    let union = entry.tag() == gimli::DW_TAG_union_type;
    let mut fields = Vec::new();
    let mut source_end = 0;
    let mut generated_end = 0;
    let mut natural_alignment = 1;
    let mut tree = unit
        .entries_tree(Some(offset))
        .map_err(|_| AbiIssue::UnknownLayout)?;
    let root = tree.root().map_err(|_| AbiIssue::UnknownLayout)?;
    let mut children = root.children();
    while let Some(child) = children.next().map_err(|_| AbiIssue::UnknownLayout)? {
        let child = child.entry();
        if child.tag() != gimli::DW_TAG_member {
            continue;
        }
        let at = if union {
            0
        } else {
            attribute(child, gimli::DW_AT_data_member_location)
                .and_then(number)
                .unwrap_or(0)
        };
        let offset = type_offset(child)?;
        let width = type_size(unit, offset, 8).ok_or(AbiIssue::UnknownLayout)?;
        if at < source_end {
            continue;
        }
        let named = attribute(child, gimli::DW_AT_name)
            .and_then(|value| attribute_string(dwarf, unit, value));
        let declared = named.and_then(|name| {
            type_name(dwarf, unit, offset, 8).filter(plausible_type)?;
            attribute(child, gimli::DW_AT_bit_size)
                .is_none()
                .then(|| declaration(dwarf, unit, offset, &name, 16))
                .flatten()
        });
        let field = if declared.is_some() {
            generated(dwarf, unit, offset, depth - 1)?
        } else if union {
            continue;
        } else {
            bytes(width.min(original.size.saturating_sub(at)))
        };
        if field.size == 0 {
            continue;
        }
        if !union && at > source_end {
            let gap = bytes(at - source_end);
            fields.push(LayoutField {
                bit_offset: generated_end * 8,
                bit_size: None,
                layout: gap,
                defined: true,
            });
            generated_end = generated_end
                .checked_add(at - source_end)
                .ok_or(AbiIssue::UnknownLayout)?;
        }
        let alignment = field.alignment.ok_or(AbiIssue::UnknownLayout)?;
        natural_alignment = natural_alignment.max(alignment);
        let placed = if union {
            0
        } else {
            rounded(generated_end, alignment)?
        };
        if placed != at {
            return Err(AbiIssue::IncompatibleDefinition);
        }
        generated_end = generated_end.max(
            placed
                .checked_add(field.size)
                .ok_or(AbiIssue::UnknownLayout)?,
        );
        source_end = if union {
            0
        } else {
            at.checked_add(field.size).ok_or(AbiIssue::UnknownLayout)?
        };
        fields.push(LayoutField {
            bit_offset: placed.checked_mul(8).ok_or(AbiIssue::UnknownLayout)?,
            bit_size: None,
            layout: field,
            defined: true,
        });
    }
    if union && fields.is_empty() {
        fields.push(LayoutField {
            bit_offset: 0,
            bit_size: None,
            layout: bytes(original.size),
            defined: true,
        });
        generated_end = original.size;
    } else if !union && original.size > source_end {
        let gap = bytes(original.size - source_end);
        fields.push(LayoutField {
            bit_offset: generated_end
                .checked_mul(8)
                .ok_or(AbiIssue::UnknownLayout)?,
            bit_size: None,
            layout: gap,
            defined: true,
        });
        generated_end = generated_end
            .checked_add(original.size - source_end)
            .ok_or(AbiIssue::UnknownLayout)?;
    }
    let alignment = original.alignment.ok_or(AbiIssue::UnknownLayout)?;
    if alignment < natural_alignment {
        return Err(AbiIssue::IncompatibleDefinition);
    }
    Ok(TypeLayout {
        size: rounded(generated_end, alignment)?,
        alignment: Some(alignment),
        kind: if union {
            LayoutKind::Union(fields)
        } else {
            LayoutKind::Struct(fields)
        },
        trivial: original.trivial,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{AbiProfile, RegisterClass};

    #[test]
    fn aggregate_debug_layouts_preserve_fields_and_bit_ranges() {
        for (isa, profile) in [
            ("x86_64", AbiProfile::SysV),
            ("aarch64", AbiProfile::Aapcs64),
        ] {
            for level in ["O0", "O2"] {
                let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
                    "tests/fixtures/metrics/structs.{isa}.{level}.debug.elf"
                ));
                let binary = crate::service::Binary::open(&path).expect("fixture");
                let types = |name| {
                    let function = binary.find(name).expect("function");
                    super::super::function_types(binary.image(), function.addr).expect("types")
                };
                let point = types("point_add");
                assert_eq!(point.abi_profile, Ok(profile));
                assert_eq!(point.param_layouts.len(), 2);
                for layout in &point.param_layouts {
                    let layout = layout.as_ref().expect("point layout");
                    assert_eq!((layout.size, layout.alignment), (8, None));
                    let LayoutKind::Struct(fields) = &layout.kind else {
                        panic!("point fields");
                    };
                    assert_eq!(
                        fields
                            .iter()
                            .map(|field| field.bit_offset)
                            .collect::<Vec<_>>(),
                        [0, 32]
                    );
                }
                assert_eq!(
                    point
                        .ret_layout
                        .as_ref()
                        .expect("result")
                        .as_ref()
                        .expect("point")
                        .size,
                    8
                );
                let flags = types("flags_level");
                let layout = flags.param_layouts[0].as_ref().expect("flags layout");
                assert_eq!((layout.size, layout.alignment), (4, None));
                let canonical = crate::ir::abi::canonical(layout).expect("canonical flags");
                assert_eq!(canonical.alignment, Some(4));
                let classified =
                    crate::ir::abi::classify(profile, &canonical).expect("flags classification");
                assert_eq!(classified.defined_bits, [(0, 8)]);
                let definition = flags
                    .definitions
                    .iter()
                    .find(|definition| definition.name == "struct flags")
                    .expect("flags definition");
                assert_eq!((definition.size, definition.alignment), (4, Some(4)));
                assert_eq!(definition.compatible_profiles, [profile]);
                assert!(
                    definition
                        .members
                        .iter()
                        .all(|member| member.starts_with("uint8_t gap_"))
                );
                let word = types("word_low_byte");
                let layout = word.param_layouts[0].as_ref().expect("union layout");
                let LayoutKind::Union(fields) = &layout.kind else {
                    panic!("union alternatives");
                };
                assert_eq!(fields.len(), 3);
                assert!(fields.iter().any(|field| matches!(
                    field.layout.kind,
                    LayoutKind::Float(Precision::Single)
                )));
                assert!(
                    fields.iter().any(|field| matches!(
                        field.layout.kind,
                        LayoutKind::Array { count: 4, .. }
                    ))
                );
                let canonical = crate::ir::abi::canonical(layout).expect("canonical union");
                let classified =
                    crate::ir::abi::classify(profile, &canonical).expect("union classification");
                let crate::ir::abi::ValueClass::Registers(pieces) = classified.passing else {
                    panic!("union register");
                };
                assert_eq!(pieces.len(), 1);
                assert_eq!(pieces[0].class, RegisterClass::Integer);
            }
        }
    }

    #[test]
    fn nested_debug_layouts_do_not_lose_pointer_and_tail_members() {
        for isa in ["a64", "x64"] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(format!("tests/fixtures/member_types_{isa}.elf"));
            let binary = crate::service::Binary::open(&path).expect("fixture");
            let function = binary.find("read_outer").expect("function");
            let types = super::super::function_types(binary.image(), function.addr).expect("types");
            let definition = types
                .definitions
                .iter()
                .find(|definition| definition.name == "struct outer")
                .expect("outer definition");
            assert_eq!((definition.size, definition.alignment), (24, Some(8)));
            assert_eq!(definition.compatible_profiles.len(), 1);
        }
    }
}

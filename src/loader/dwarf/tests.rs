use super::functions;
use crate::loader::Image;

/// A version 4 compilation unit with 8-byte addresses holding `dies`.
pub(super) fn information(dies: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 4];
    bytes.extend(4u16.to_le_bytes());
    bytes.extend(0u32.to_le_bytes());
    bytes.push(8);
    bytes.extend(dies);
    let length = u32::try_from(bytes.len() - 4).unwrap();
    bytes[..4].copy_from_slice(&length.to_le_bytes());
    bytes
}

/// An image whose only sections are the given debug information.
pub(super) fn image(info: &[u8], abbrev: &[u8]) -> Image {
    let mut bytes = Vec::new();
    let mut sections = Vec::new();
    for (name, data) in [(".debug_info", info), (".debug_abbrev", abbrev)] {
        sections.push(crate::loader::Section {
            name: name.to_owned(),
            vaddr: 0,
            size: data.len() as u64,
            file_offset: Some(bytes.len() as u64),
            executable: false,
            loaded: false,
            read_only: true,
        });
        bytes.extend(data);
    }
    let mut image = Image::from_code(crate::loader::Isa::AArch64, 0, bytes);
    image.sections = sections;
    image
}

pub(super) fn function_range_data() -> (Vec<u8>, Vec<u8>) {
    // Abbreviation 2: name, low_pc (addr), high_pc (data4);
    // abbreviation 3: name, low_pc (addr), high_pc (addr).
    let abbrev = [
        1, 0x11, 1, 0, 0, 2, 0x2e, 0, 0x03, 0x08, 0x11, 0x01, 0x12, 0x06, 0, 0, 3, 0x2e, 0, 0x03,
        0x08, 0x11, 0x01, 0x12, 0x01, 0, 0, 0,
    ];
    let mut dies = vec![1];
    for (name, low, size) in [
        ("relative_larger_than_low", 0x30u64, 0x3du32),
        ("relative_smaller_than_low", 0x1000, 0x20),
        ("relative_overflow", u64::MAX - 1, 4),
    ] {
        dies.push(2);
        dies.extend(name.as_bytes());
        dies.push(0);
        dies.extend(low.to_le_bytes());
        dies.extend(size.to_le_bytes());
    }
    for (name, low, high) in [
        ("absolute", 0x50u64, 0x74u64),
        ("absolute_reversed", 0x200, 0x1ff),
        ("absolute_empty", 0x400, 0x400),
    ] {
        dies.push(3);
        dies.extend(name.as_bytes());
        dies.push(0);
        dies.extend(low.to_le_bytes());
        dies.extend(high.to_le_bytes());
    }
    dies.push(0);
    (abbrev.to_vec(), dies)
}

#[test]
fn function_ranges_distinguish_address_and_constant_high_pc() {
    use gimli::AttributeValue;

    for (value, expected) in [
        (AttributeValue::Data1(u8::MAX), Some(u64::from(u8::MAX))),
        (AttributeValue::Data2(u16::MAX), Some(u64::from(u16::MAX))),
        (AttributeValue::Data4(u32::MAX), Some(u64::from(u32::MAX))),
        (AttributeValue::Data8(u64::MAX), Some(u64::MAX)),
        (AttributeValue::Udata(u64::MAX), Some(u64::MAX)),
        (AttributeValue::Sdata(0), Some(0)),
        (AttributeValue::Sdata(i64::MAX), Some(i64::MAX as u64)),
        (AttributeValue::Sdata(-1), None),
        (AttributeValue::Addr(8), None),
        (AttributeValue::Flag(true), None),
        (AttributeValue::UnitRef(gimli::UnitOffset(8)), None),
    ] {
        assert_eq!(super::layout::number(value), expected);
    }
    let (abbrev, dies) = function_range_data();
    let ranges: Vec<_> = functions(&image(&information(&dies), &abbrev))
        .into_iter()
        .map(|function| (function.name, function.addr, function.size))
        .collect();
    assert_eq!(
        ranges,
        vec![
            ("relative_larger_than_low".to_owned(), 0x30, 0x3d),
            ("absolute".to_owned(), 0x50, 0x24),
            ("relative_smaller_than_low".to_owned(), 0x1000, 0x20),
        ]
    );
}

#[test]
fn source_stack_variables_have_entry_relative_locations() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/metrics");
    for name in [
        "struct_arrays.x86_64.O0.debug.elf",
        "integers.aarch64.O0.debug.elf",
    ] {
        let binary = crate::service::Binary::open(&root.join(name)).expect("fixture");
        let image = binary.image();
        let locals: Vec<_> = image
            .functions
            .values()
            .filter_map(|function| super::function_types(image, function.addr))
            .flat_map(|types| types.locals)
            .collect();
        assert!(!locals.is_empty(), "{name}");
        assert!(
            locals.iter().all(|local| local.size > 0 && local.slot < 0),
            "{locals:?}"
        );
    }
}

#[test]
fn invalid_local_location_does_not_hide_the_next_variable() {
    let abbrev = [
        1, 0x11, 1, 0, 0, 2, 0x2e, 1, 0x03, 0x08, 0x11, 0x01, 0x12, 0x06, 0x40, 0x18, 0, 0, 3,
        0x34, 0, 0x03, 0x08, 0x49, 0x13, 0x02, 0x18, 0, 0, 4, 0x24, 0, 0x03, 0x08, 0x0b, 0x0b,
        0x3e, 0x0b, 0, 0, 0,
    ];
    let mut dies = vec![1, 2, b'f', 0];
    dies.extend(0x1000u64.to_le_bytes());
    dies.extend(0x20u32.to_le_bytes());
    dies.extend([1, 0x9c]); // DW_OP_call_frame_cfa
    let mut refs = Vec::new();
    for (name, expr) in [("invalid", &[0xff][..]), ("value", &[0x91, 0x78][..])] {
        dies.push(3);
        dies.extend(name.as_bytes());
        dies.push(0);
        refs.push(dies.len());
        dies.extend([0; 4]);
        dies.push(expr.len() as u8);
        dies.extend(expr);
    }
    dies.push(0);
    let ty = u32::try_from(dies.len() + 11).unwrap();
    dies.extend([4, b'i', b'n', b't', 0, 4, 5, 0]);
    for offset in refs {
        dies[offset..offset + 4].copy_from_slice(&ty.to_le_bytes());
    }
    let image = image(&information(&dies), &abbrev);
    image
        .stack_rows
        .set(vec![crate::loader::unwind::StackRow {
            start: 0x1000,
            end: 0x1020,
            at_entry: true,
            cfa: (gimli::Register(31), 0),
        }])
        .unwrap();
    let types = super::function_types(&image, 0x1000).expect("function types");
    assert_eq!(types.locals.len(), 1);
    assert_eq!(types.locals[0].name, "value");
    assert_eq!(types.locals[0].slot, -8);
    assert_eq!(types.locals[0].size, 4);
}

#[test]
fn malformed_call_address_does_not_hide_other_declarations() {
    // The first subprogram has an invalid indexed address; the second has an address.
    let abbrev = [
        1, 0x11, 1, 0, 0, 2, 0x2e, 0, 0x11, 0x1b, 0, 0, 3, 0x2e, 0, 0x11, 0x01, 0x27, 0x19, 0, 0, 0,
    ];
    let mut dies = vec![1, 2, 0, 3];
    dies.extend(0x1000u64.to_le_bytes());
    dies.push(0);
    let image = image(&information(&dies), &abbrev);
    let index = super::calls::call_index(&image).unwrap();
    assert_eq!(index.addresses.len(), 1);
    let source = index.addresses[&0x1000][0];
    let unit = super::calls::call_unit(&image, source.unit).unwrap();
    assert!(unit.functions.contains_key(&source));
    assert_eq!(unit.functions.len(), 1);
}

#[test]
fn call_index_keeps_duplicate_addresses_for_compatibility_checks() {
    let abbrev = [1, 0x11, 1, 0, 0, 2, 0x2e, 0, 0x11, 0x01, 0, 0, 0];
    let mut dies = vec![1];
    for _ in 0..2 {
        dies.push(2);
        dies.extend(0x1000u64.to_le_bytes());
    }
    dies.push(0);
    let image = image(&information(&dies), &abbrev);
    let index = super::calls::call_index(&image).unwrap();
    assert_eq!(index.addresses[&0x1000].len(), 2);
    assert_ne!(index.addresses[&0x1000][0], index.addresses[&0x1000][1]);
}

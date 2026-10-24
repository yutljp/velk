use super::functions;
use crate::loader::Image;

/// A version 4 compilation unit with 8-byte addresses holding `dies`.
fn information(dies: &[u8]) -> Vec<u8> {
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
fn image(info: &[u8], abbrev: &[u8]) -> Image {
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

#[test]
fn function_ranges_distinguish_address_and_constant_high_pc() {
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

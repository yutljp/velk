use super::*;

const BASE: u64 = 0x1_0000_0000;
const FIXUPS_OFFSET: usize = 0x3000;

fn u16_at(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn u32_at(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn u64_at(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn fixture(format: u16, pointers: &[u64], import_format: u32, addend: i64) -> Vec<u8> {
    let mut bytes = vec![0; 0x3100];
    u32_at(&mut bytes, 0, 0xfeed_facf);
    u32_at(&mut bytes, 4, object::macho::CPU_TYPE_ARM64.0);
    u32_at(&mut bytes, 12, object::macho::MH_DYLIB.0);
    u32_at(&mut bytes, 16, 3);
    u32_at(&mut bytes, 20, 160);
    for (index, name) in [b"__TEXT", b"__DATA"].iter().enumerate() {
        let offset = 32 + index * 72;
        u32_at(&mut bytes, offset, 0x19);
        u32_at(&mut bytes, offset + 4, 72);
        bytes[offset + 8..offset + 14].copy_from_slice(*name);
        u64_at(&mut bytes, offset + 24, BASE + index as u64 * 0x1000);
        u64_at(&mut bytes, offset + 32, 0x1000);
        u64_at(&mut bytes, offset + 40, index as u64 * 0x1000);
        u64_at(&mut bytes, offset + 48, 0x1000);
    }
    u32_at(&mut bytes, 176, 0x8000_0034);
    u32_at(&mut bytes, 180, 16);
    u32_at(&mut bytes, 184, FIXUPS_OFFSET as u32);
    u32_at(&mut bytes, 188, 0x100);
    u32_at(&mut bytes, FIXUPS_OFFSET + 4, 28);
    u32_at(&mut bytes, FIXUPS_OFFSET + 8, 68);
    u32_at(&mut bytes, FIXUPS_OFFSET + 12, 96);
    u32_at(&mut bytes, FIXUPS_OFFSET + 16, 1);
    u32_at(&mut bytes, FIXUPS_OFFSET + 20, import_format);
    u32_at(&mut bytes, FIXUPS_OFFSET + 28, 2);
    u32_at(&mut bytes, FIXUPS_OFFSET + 36, 16);
    u32_at(&mut bytes, FIXUPS_OFFSET + 44, 24);
    u16_at(&mut bytes, FIXUPS_OFFSET + 48, 0x1000);
    u16_at(&mut bytes, FIXUPS_OFFSET + 50, format);
    u64_at(&mut bytes, FIXUPS_OFFSET + 52, 0x1000);
    u16_at(&mut bytes, FIXUPS_OFFSET + 64, 1);
    if import_format == 2 {
        u32_at(&mut bytes, FIXUPS_OFFSET + 72, addend as u32);
    } else if import_format == 3 {
        u64_at(&mut bytes, FIXUPS_OFFSET + 76, addend as u64);
    }
    bytes[FIXUPS_OFFSET + 96..FIXUPS_OFFSET + 104].copy_from_slice(b"_object\0");
    for (index, pointer) in pointers.iter().enumerate() {
        u64_at(&mut bytes, 0x1000 + index * 8, *pointer);
    }
    bytes
}

fn decode(bytes: &[u8]) -> Result<(Vec<u8>, BTreeMap<u64, Binding>), String> {
    let file = object::File::parse(bytes).unwrap();
    let mut patched = std::borrow::Cow::Borrowed(bytes);
    match apply(&file, &mut patched) {
        Ok(bindings) => Ok((patched.into_owned(), bindings)),
        Err(error) => Err(error),
    }
}

fn pointer(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[test]
fn decoding_copies_borrowed_input_only_when_patching_pointers() {
    let original = fixture(6, &[0x888], 1, 0);
    let file = object::File::parse(original.as_slice()).unwrap();
    let mut patched = std::borrow::Cow::Borrowed(original.as_slice());
    assert!(apply(&file, &mut patched).unwrap().is_empty());
    assert!(matches!(patched, std::borrow::Cow::Owned(_)));
    assert_eq!(pointer(&patched, 0x1000), BASE + 0x888);
    assert_eq!(pointer(&original, 0x1000), 0x888);

    let mut original = original;
    u32_at(&mut original, 16, 2);
    u32_at(&mut original, 20, 144);
    let file = object::File::parse(original.as_slice()).unwrap();
    let mut patched = std::borrow::Cow::Borrowed(original.as_slice());
    assert!(apply(&file, &mut patched).unwrap().is_empty());
    assert!(matches!(patched, std::borrow::Cow::Borrowed(_)));
}

#[test]
fn absolute_and_relative_formats_preserve_targets_and_top_bytes() {
    for format in [1, 2, 6, 7, 9, 10, 12] {
        let absolute = matches!(format, 1 | 2 | 10);
        let target = if absolute { BASE + 0x888 } else { 0x888 };
        let high = if matches!(format, 2 | 6) { 36 } else { 43 };
        let raw = target | (0xabu64 << high);
        let (bytes, bindings) = decode(&fixture(format, &[raw], 1, 0)).unwrap();
        assert_eq!(
            pointer(&bytes, 0x1000),
            0xab00_0001_0000_0888,
            "format {format}"
        );
        assert!(bindings.is_empty());
    }
}

#[test]
fn chain_links_and_import_addends_are_removed_from_image_words() {
    for format in [1, 2, 6, 7, 9, 10, 12] {
        let wide = matches!(format, 2 | 6);
        let absolute = matches!(format, 1 | 2 | 10);
        let first = if absolute { BASE + 0x20 } else { 0x20 };
        let stride = if wide || matches!(format, 7 | 10) {
            4
        } else {
            8
        };
        let first = first | ((8 / stride) << 51);
        let bind = if wide {
            (1 << 63) | (7 << 24)
        } else {
            (1 << 62) | (7 << 32)
        };
        for import_format in [1, 2, 3] {
            let import_addend = if import_format == 1 { 0 } else { -12 };
            let original = fixture(format, &[first, bind], import_format, import_addend);
            let (bytes, bindings) = decode(&original).unwrap();
            assert_eq!(pointer(&bytes, 0x1000), BASE + 0x20);
            assert_eq!(pointer(&bytes, 0x1008), 0);
            assert_eq!(bindings[&(BASE + 0x1008)].name, "_object");
            assert_eq!(bindings[&(BASE + 0x1008)].addend, import_addend + 7);
        }
    }
}

#[test]
fn authenticated_targets_and_signed_arm64e_addends_survive() {
    for format in [1, 7, 9, 10, 12] {
        let auth = (1 << 63) | (0x5a5a << 32) | (7 << 48);
        let (bytes, _) = decode(&fixture(format, &[auth | 0x888], 1, 0)).unwrap();
        assert_eq!(pointer(&bytes, 0x1000), BASE + 0x888);
        let (_, bindings) = decode(&fixture(format, &[auth | (1 << 62)], 3, -23)).unwrap();
        assert_eq!(bindings[&(BASE + 0x1000)].addend, -23);
        let raw = (1 << 62) | (0x7ffff << 32);
        let (_, bindings) = decode(&fixture(format, &[raw], 1, 0)).unwrap();
        assert_eq!(bindings[&(BASE + 0x1000)].addend, -1);
    }
}

#[test]
fn userland24_uses_all_twenty_four_ordinal_bits() {
    // 0x10000 must not silently become ordinal zero.
    let raw = (1 << 62) | 0x10000;
    assert!(decode(&fixture(12, &[raw], 1, 0)).is_err());
    assert!(decode(&fixture(9, &[raw], 1, 0)).is_ok());
}

#[test]
fn malformed_chains_fail_with_context() {
    let original = fixture(6, &[0], 1, 0);
    for (at, value) in [
        (FIXUPS_OFFSET, 1),
        (FIXUPS_OFFSET + 4, u32::MAX),
        (FIXUPS_OFFSET + 8, u32::MAX),
        (FIXUPS_OFFSET + 12, u32::MAX),
        (FIXUPS_OFFSET + 16, u32::MAX),
        (FIXUPS_OFFSET + 20, 99),
        (FIXUPS_OFFSET + 24, 1),
        (FIXUPS_OFFSET + 36, u32::MAX),
        (FIXUPS_OFFSET + 44, u32::MAX),
    ] {
        let mut bytes = original.clone();
        u32_at(&mut bytes, at, value);
        assert!(decode(&bytes).is_err(), "field at {at:#x}");
    }
    for raw in [(1 << 63) | 1, 0xfff << 51] {
        let error = decode(&fixture(6, &[raw], 1, 0)).err().unwrap();
        assert!(error.contains("pointer at 0x100001000"), "{error}");
    }
    let error = decode(&fixture(6, &[1 << 51], 1, 0)).err().unwrap();
    assert!(
        error.contains("pointer at 0x100001004: invalid or overlapping"),
        "{error}"
    );
    let raw = (1 << 63) | (1 << 24);
    assert!(decode(&fixture(6, &[raw], 3, i64::MAX)).is_err());
    let mut bytes = original;
    u16_at(&mut bytes, FIXUPS_OFFSET + 50, 8);
    assert!(decode(&bytes).is_err());
}

#[test]
fn multiple_starts_in_a_page_are_independent_chains() {
    let mut bytes = fixture(6, &[0x123, 0x456], 1, 0);
    u32_at(&mut bytes, FIXUPS_OFFSET + 8, 80);
    u32_at(&mut bytes, FIXUPS_OFFSET + 44, 28);
    u16_at(&mut bytes, FIXUPS_OFFSET + 66, 0x8001);
    u16_at(&mut bytes, FIXUPS_OFFSET + 68, 0);
    u16_at(&mut bytes, FIXUPS_OFFSET + 70, 0x8008);
    let (patched, _) = decode(&bytes).unwrap();
    assert_eq!(pointer(&patched, 0x1000), BASE + 0x123);
    assert_eq!(pointer(&patched, 0x1008), BASE + 0x456);
    u16_at(&mut bytes, FIXUPS_OFFSET + 70, 0x8000);
    assert!(decode(&bytes).is_err());
}

#[test]
fn large_userland24_ordinals_resolve_the_correct_import() {
    for authenticated in [false, true] {
        let raw = (u64::from(authenticated) << 63) | (1 << 62) | 0x10000;
        let mut bytes = fixture(12, &[raw], 1, 0);
        let symbols = 68 + 4 * 0x10001;
        bytes.resize(FIXUPS_OFFSET + symbols + 16, 0);
        let size = (bytes.len() - FIXUPS_OFFSET) as u32;
        u32_at(&mut bytes, 188, size);
        u32_at(&mut bytes, FIXUPS_OFFSET + 12, symbols as u32);
        u32_at(&mut bytes, FIXUPS_OFFSET + 16, 0x10001);
        bytes[FIXUPS_OFFSET + 68..FIXUPS_OFFSET + symbols].fill(0);
        u32_at(&mut bytes, FIXUPS_OFFSET + 68 + 4 * 0x10000, 8 << 9);
        bytes[FIXUPS_OFFSET + symbols..FIXUPS_OFFSET + symbols + 16]
            .copy_from_slice(b"_object\0_target\0");
        let (_, bindings) = decode(&bytes).unwrap();
        assert_eq!(bindings[&(BASE + 0x1000)].name, "_target");
    }
}

#[test]
fn self_binds_resolve_defined_symbols_with_their_addends() {
    let mut bytes = fixture(6, &[(1 << 63) | (7 << 24)], 2, -3);
    u32_at(&mut bytes, 16, 4);
    u32_at(&mut bytes, 20, 184);
    u32_at(&mut bytes, 192, 2);
    u32_at(&mut bytes, 196, 24);
    u32_at(&mut bytes, 200, 0x2800);
    u32_at(&mut bytes, 204, 1);
    u32_at(&mut bytes, 208, 0x2810);
    u32_at(&mut bytes, 212, 9);
    u32_at(&mut bytes, 0x2800, 1);
    bytes[0x2804] = 0x0f;
    bytes[0x2805] = 1;
    u64_at(&mut bytes, 0x2808, BASE + 0x888);
    bytes[0x2810..0x2819].copy_from_slice(b"\0_object\0");
    let (patched, bindings) = decode(&bytes).unwrap();
    assert_eq!(pointer(&patched, 0x1000), BASE + 0x88c);
    assert!(bindings.is_empty());
}

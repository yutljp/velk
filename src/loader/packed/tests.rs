//! Header mutations and marker changes on self-built reference inputs.

use super::*;

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/upx")
        .join(name);
    fs::read(path).unwrap()
}

#[test]
fn overwritten_magic_and_renamed_sections_still_decode_by_structure() {
    for name in [
        "x86_64.nrv2b.elf",
        "i386.nrv2d.elf",
        "arm.nrv2e.elf",
        "aarch64.lzma.elf",
        "x86_64.nrv2b.filter49.exe",
        "i386.lzma.filter46.exe",
    ] {
        let bytes = fixture(name);
        let mut report = detect(&bytes).unwrap();
        let expected = unpack(&bytes, &mut report).unwrap();
        let mut changed = bytes.clone();
        for offset in memchr::memmem::find_iter(&bytes, b"UPX!") {
            changed[offset..offset + 4].copy_from_slice(b"XXXX");
        }
        for offset in memchr::memmem::find_iter(&bytes, b"UPX") {
            if matches!(changed.get(offset + 3), Some(b'0' | b'1' | b'2')) {
                changed[offset..offset + 3].copy_from_slice(b"abc");
            }
        }
        let mut report = detect(&changed).unwrap_or_else(|| panic!("{name}"));
        assert_eq!(unpack(&changed, &mut report).unwrap(), expected, "{name}");
        assert!(report.method.starts_with("built-in"));
    }
}

#[test]
fn truncated_images_and_mutated_headers_never_return_partial_output() {
    for name in [
        "x86_64.nrv2b.elf",
        "i386.nrv2d.elf",
        "arm.nrv2e.elf",
        "aarch64.lzma.elf",
        "x86_64.nrv2b.filter49.exe",
        "i386.lzma.filter46.exe",
    ] {
        let bytes = fixture(name);
        let decode = |bytes: &[u8]| {
            if name.ends_with(".elf") {
                elf::unpack(bytes)
            } else {
                pe::unpack(bytes)
            }
        };
        let expected = decode(&bytes).unwrap();
        for length in 0..bytes.len() {
            if let Ok(output) = decode(&bytes[..length]) {
                assert_eq!(output, expected, "{name}: truncation at {length}");
            }
        }
        for offset in 0..bytes.len().min(512) {
            let mut changed = bytes.clone();
            changed[offset] ^= 0xff;
            if let Ok(output) = decode(&changed) {
                assert!(output.len() <= MAX_FILE_SIZE as usize);
            }
        }
    }
}

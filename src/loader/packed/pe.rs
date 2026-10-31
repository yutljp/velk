//! Reconstruct PE headers, sections, compressed imports, and base relocations.

use std::collections::BTreeMap;

use super::format::{Checksum, number, slice};
use super::{DecodeError, MAX_FILE_SIZE, decompress, filter};

struct Section {
    address: usize,
    offset: usize,
    size: usize,
}

struct Header {
    end: usize,
    optional: usize,
    directories: usize,
    word: usize,
    machine: usize,
    sections: Vec<Section>,
}

fn header(bytes: &[u8], offset: usize) -> Result<Header, DecodeError> {
    if let Err(error) = slice(bytes, offset, 24) {
        return Err(error);
    }
    let pe_signature = match slice(bytes, offset, 4) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    if pe_signature != b"PE\0\0" {
        return Err(DecodeError::invalid(offset, "invalid PE signature"));
    }
    let machine = match number(bytes, offset + 4, 2) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let count = match number(bytes, offset + 6, 2) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let optional = offset + 24;
    let size = match number(bytes, offset + 20, 2) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let magic = match number(bytes, optional, 2) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let (word, directories) = match (machine, magic, size) {
        (0x14c, 0x10b, 224) => (4, optional + 96),
        (0x8664, 0x20b, 240) => (8, optional + 112),
        _ => {
            return Err(DecodeError::Unsupported(
                "PE machine or optional header layout".to_owned(),
            ));
        }
    };
    let mut invalid_counts = count == 0 || count > 96;
    if !invalid_counts {
        invalid_counts = match number(bytes, directories - 4, 4) {
            Ok(value) => value != 16,
            Err(error) => return Err(error),
        };
    }
    if invalid_counts {
        return Err(DecodeError::Unsupported(
            "PE section or directory count".to_owned(),
        ));
    }
    let end = optional + size + count * 40;
    if let Err(error) = slice(bytes, offset, end - offset) {
        return Err(error);
    }
    let mut sections = Vec::new();
    for index in 0..count {
        let start = optional + size + index * 40;
        let address = match number(bytes, start + 12, 4) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let size = match number(bytes, start + 16, 4) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let offset = match number(bytes, start + 20, 4) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        if address > MAX_FILE_SIZE as usize
            || size > MAX_FILE_SIZE as usize - address
            || offset > MAX_FILE_SIZE as usize
            || size > MAX_FILE_SIZE as usize - offset
        {
            return Err(DecodeError::invalid(start, "PE section exceeds 128 MiB"));
        }
        sections.push(Section {
            address,
            offset,
            size,
        });
    }
    Ok(Header {
        end,
        optional,
        directories,
        word,
        machine,
        sections,
    })
}

fn locate(bytes: &[u8], header: &Header) -> Result<usize, DecodeError> {
    let end = bytes.len().saturating_sub(31).min(4096);
    for offset in header.end..end {
        let pack = &bytes[offset..offset + 32];
        if pack[4] != 13 || !matches!(pack[5], 9 | 36) || pack[7] > 10 {
            continue;
        }
        let checksum: u32 = pack[4..31].iter().map(|byte| u32::from(*byte)).sum();
        if checksum % 251 == u32::from(pack[31]) {
            return Ok(offset);
        }
        if &pack[..4] == b"UPX!" {
            return Err(DecodeError::invalid(
                offset,
                "UPX PackHeader checksum mismatch",
            ));
        }
    }
    Err(DecodeError::Unsupported(
        "PE UPX PackHeader layout".to_owned(),
    ))
}

pub(super) fn recognizes(bytes: &[u8]) -> bool {
    let Ok(offset) = number(bytes, 60, 4) else {
        return false;
    };
    let Ok(header) = header(bytes, offset) else {
        return false;
    };
    locate(bytes, &header).is_ok()
}

fn put(bytes: &mut [u8], offset: usize, value: usize, width: usize) -> Result<(), DecodeError> {
    let end = offset.checked_add(width);
    let Some(output) = end.and_then(|end| bytes.get_mut(offset..end)) else {
        return Err(DecodeError::invalid(
            offset,
            "PE write outside recovered image",
        ));
    };
    output.copy_from_slice(&(value as u64).to_le_bytes()[..width]);
    Ok(())
}

fn string(bytes: &[u8], offset: usize) -> Result<&[u8], DecodeError> {
    let Some(rest) = bytes.get(offset..) else {
        return Err(DecodeError::invalid(offset, "PE string outside image"));
    };
    let Some(length) = rest.iter().position(|byte| *byte == 0) else {
        return Err(DecodeError::invalid(offset, "unterminated PE string"));
    };
    Ok(&rest[..=length])
}

fn image_offset(address: usize, base: usize) -> Result<usize, DecodeError> {
    match address.checked_sub(base) {
        Some(offset) => Ok(offset),
        None => Err(DecodeError::invalid(
            address,
            "PE address precedes the compressed image",
        )),
    }
}

fn copy(bytes: &mut [u8], offset: usize, source: &[u8]) -> Result<(), DecodeError> {
    let end = offset.checked_add(source.len());
    let Some(output) = end.and_then(|end| bytes.get_mut(offset..end)) else {
        return Err(DecodeError::invalid(
            offset,
            "PE data outside recovered image",
        ));
    };
    output.copy_from_slice(source);
    Ok(())
}

fn imports(
    image: &mut [u8],
    source: &[u8],
    packed_imports: &[u8],
    header: &Header,
    base: usize,
    mut names: usize,
    mut position: usize,
) -> Result<usize, DecodeError> {
    let descriptor_rva = match number(source, header.directories + 8, 4) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let mut descriptor = match image_offset(descriptor_rva, base) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let size = match number(source, header.directories + 12, 4) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let end = match descriptor
        .checked_add(size)
        .ok_or_else(|| DecodeError::invalid(descriptor, "PE import size overflow"))
    {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    if let Err(error) = slice(image, descriptor, size) {
        return Err(error);
    }
    enum Import<'input> {
        Name { thunk: usize, name: &'input [u8] },
        Ordinal { thunk: usize, ordinal: usize },
    }
    let mut functions = Vec::new();
    loop {
        let library = match number(source, position, 4) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        position += 4;
        if library == 0 {
            break;
        }
        if descriptor + 20 > end {
            return Err(DecodeError::invalid(
                descriptor,
                "too many compressed PE import descriptors",
            ));
        }
        let mut thunk = match number(source, position, 4) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        position += 4;
        if let Err(error) = slice(image, thunk, header.word) {
            return Err(error);
        }
        let library = match string(packed_imports, library) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let names_offset = match image_offset(names, base) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        if let Err(error) = copy(image, names_offset, library) {
            return Err(error);
        }
        if let Err(error) = put(image, descriptor + 12, names, 4) {
            return Err(error);
        }
        if let Err(error) = put(image, descriptor + 16, thunk + base, 4) {
            return Err(error);
        }
        names += library.len();
        loop {
            let kind = match number(source, position, 1) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            position += 1;
            let import = match kind {
                0 => break,
                1 => {
                    let name = match string(source, position) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    position += name.len();
                    Import::Name { thunk, name }
                }
                0xff => {
                    let ordinal = match number(source, position, 2) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    position += 2;
                    Import::Ordinal { thunk, ordinal }
                }
                _ => {
                    return Err(DecodeError::Unsupported(format!(
                        "compressed PE import kind 0x{kind:02x}"
                    )));
                }
            };
            if let Err(error) = slice(image, thunk, header.word) {
                return Err(error);
            }
            functions.push(import);
            thunk += header.word;
        }
        if let Err(error) = put(image, thunk, 0, header.word) {
            return Err(error);
        }
        descriptor += 20;
    }
    for import in functions {
        match import {
            Import::Name { thunk, name } => {
                names = (names + 1) & !1;
                let offset = match image_offset(names, base) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if let Err(error) = put(image, offset, 0, 2) {
                    return Err(error);
                }
                if let Err(error) = copy(image, offset + 2, name) {
                    return Err(error);
                }
                if let Err(error) = put(image, thunk, names, header.word) {
                    return Err(error);
                }
                names += 2 + name.len();
            }
            Import::Ordinal { thunk, ordinal } => {
                let value = ordinal | (1usize << (header.word * 8 - 1));
                if let Err(error) = put(image, thunk, value, header.word) {
                    return Err(error);
                }
            }
        }
    }
    Ok(position)
}

fn relocations(
    image: &mut [u8],
    source: &[u8],
    header: &Header,
    base: usize,
    mut position: usize,
) -> Result<usize, DecodeError> {
    let image_base = match number(
        source,
        header.optional + if header.word == 8 { 24 } else { 28 },
        header.word,
    ) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let Some(address_base) = image_base.checked_add(base) else {
        return Err(DecodeError::invalid(
            header.optional,
            "PE image base overflow",
        ));
    };
    let mut offset = 0usize;
    let mut pages: BTreeMap<usize, Vec<u16>> = BTreeMap::new();
    let mut previous_end = 0;
    loop {
        let mut delta = match number(source, position, 1) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        position += 1;
        if delta == 0 {
            break;
        }
        if delta >= 0xf0 {
            let low_bits = match number(source, position, 2) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            delta = ((delta & 15) << 16) | low_bits;
            position += 2;
        }
        let Some(next) = offset.checked_add(delta) else {
            return Err(DecodeError::invalid(
                position,
                "PE relocation offset overflow",
            ));
        };
        offset = next;
        let Some(start) = offset.checked_sub(4) else {
            return Err(DecodeError::invalid(
                position,
                "invalid PE relocation location",
            ));
        };
        if start < previous_end {
            return Err(DecodeError::Unsupported(
                "overlapping PE base relocations".to_owned(),
            ));
        }
        if let Err(error) = slice(image, start, header.word) {
            return Err(error);
        }
        previous_end = start + header.word;
        let mut relative = 0usize;
        let table_bytes = match slice(source, start, header.word) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        for byte in table_bytes {
            let Some(value) = relative
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
            else {
                return Err(DecodeError::invalid(start, "PE relocation value overflow"));
            };
            relative = value;
        }
        let Some(value) = address_base.checked_add(relative) else {
            return Err(DecodeError::invalid(start, "PE relocated address overflow"));
        };
        if header.word == 4 && value > u32::MAX as usize {
            return Err(DecodeError::invalid(start, "PE relocation exceeds 32 bits"));
        }
        if let Err(error) = put(image, start, value, header.word) {
            return Err(error);
        }
        let address = start + base;
        let kind = if header.word == 8 { 10 } else { 3 };
        pages
            .entry(address & !0xfff)
            .or_default()
            .push(((kind << 12) | (address & 0xfff)) as u16);
    }
    let directory = match number(source, header.directories + 40, 4) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let size = match number(source, header.directories + 44, 4) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let mut table = Vec::new();
    for (page, mut entries) in pages {
        if !entries.len().is_multiple_of(2) {
            entries.push(0);
        }
        table.extend_from_slice(&(page as u32).to_le_bytes());
        table.extend_from_slice(&((8 + entries.len() * 2) as u32).to_le_bytes());
        for entry in entries {
            table.extend_from_slice(&entry.to_le_bytes());
        }
    }
    if table.len() != size {
        return Err(DecodeError::Unsupported(
            "PE relocation block layout".to_owned(),
        ));
    }
    let table_offset = match image_offset(directory, base) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    if let Err(error) = copy(image, table_offset, &table) {
        return Err(error);
    }
    Ok(position)
}

pub(super) fn unpack(bytes: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let pe_offset = match number(bytes, 60, 4) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let packed = match header(bytes, pe_offset) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    for section in &packed.sections {
        if let Err(error) = slice(bytes, section.offset, section.size) {
            return Err(error);
        }
    }
    let packed_end = packed
        .sections
        .iter()
        .map(|section| section.offset + section.size)
        .max();
    if packed_end != Some(bytes.len()) {
        return Err(DecodeError::Unsupported("PE file overlay".to_owned()));
    }
    let offset = match locate(bytes, &packed) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let pack = match slice(bytes, offset, 32) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    if !matches!(pack[28], 0 | 0x26 | 0x46 | 0x49) {
        return Err(DecodeError::Unsupported(format!(
            "PE branch filter 0x{:02x}",
            pack[28]
        )));
    }
    if pack[30] != 0 {
        return Err(DecodeError::Unsupported(format!(
            "UPX PackHeader parameter at byte 30: 0x{:02x}",
            pack[30]
        )));
    }
    if pack[5] != if packed.word == 8 { 36 } else { 9 } {
        return Err(DecodeError::invalid(
            offset,
            "UPX format does not match PE machine",
        ));
    }
    let size = match number(pack, 16, 4) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let compressed = match number(pack, 20, 4) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let file_size = match number(pack, 24, 4) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    if size < 4
        || size > MAX_FILE_SIZE as usize
        || file_size < packed.end
        || file_size > MAX_FILE_SIZE as usize
        || compressed == 0
        || compressed > size
    {
        return Err(DecodeError::invalid(offset, "invalid PE UPX sizes"));
    }
    let data = match slice(bytes, offset + 32, compressed) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let mut checksum = Checksum::new();
    checksum.update(data);
    let stored_checksum = match number(pack, 12, 4) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    if checksum.value() != stored_checksum {
        return Err(DecodeError::invalid(
            offset,
            "PE UPX compressed checksum mismatch",
        ));
    }
    let decoded = match decompress(data, size, pack[6]) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let mut checksum = Checksum::new();
    checksum.update(&decoded);
    let stored_checksum = match number(pack, 8, 4) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    if checksum.value() != stored_checksum {
        return Err(DecodeError::invalid(
            offset,
            "PE UPX uncompressed checksum mismatch",
        ));
    }
    let original_offset = match number(&decoded, decoded.len() - 4, 4) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let original = match header(&decoded, original_offset) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    if packed.machine != original.machine {
        return Err(DecodeError::invalid(
            original_offset,
            "recovered PE machine differs",
        ));
    }
    for index in [2, 4, 9, 10, 11, 13, 14] {
        let directory_size = match number(&decoded, original.directories + index * 8, 4) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        if directory_size != 0 {
            return Err(DecodeError::Unsupported(format!(
                "PE directory {index} reconstruction"
            )));
        }
    }
    let Some(first) = packed.sections.first() else {
        return Err(DecodeError::invalid(
            pe_offset,
            "PE has no compressed image section",
        ));
    };
    let base = first.address;
    let mut image = decoded[..original_offset].to_vec();
    let code = match number(&decoded, original.optional + 20, 4) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let code_size = match number(&decoded, original.optional + 4, 4) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    if code != base || code_size > image.len() {
        return Err(DecodeError::Unsupported("PE code filter range".to_owned()));
    }
    if let Err(error) = filter::decode(&mut image[..code_size], pack[28], pack[29]) {
        return Err(error);
    }
    let mut footer = original.end;
    let mut imports_end = None;
    let import_directory_size = match number(&decoded, original.directories + 8, 4) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    if import_directory_size != 0 {
        let imports_offset = match number(&decoded, footer, 4) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let names = match number(&decoded, footer + 4, 4) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        footer += 8;
        let address = match number(bytes, packed.directories + 8, 4) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let Some(section) = packed
            .sections
            .iter()
            .find(|section| address >= section.address && address - section.address < section.size)
        else {
            return Err(DecodeError::invalid(
                address,
                "packed PE import directory is outside sections",
            ));
        };
        let start = section.offset + address - section.address;
        let packed_imports = match slice(bytes, start, section.size - (address - section.address)) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let new_imports_end = match imports(
            &mut image,
            &decoded,
            packed_imports,
            &original,
            base,
            names,
            imports_offset,
        ) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        imports_end = Some(new_imports_end);
    }
    let relocation_directory_size = match number(&decoded, original.directories + 40, 4) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    if relocation_directory_size != 0 {
        let relocations_offset = match number(&decoded, footer, 4) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        if imports_end.is_some_and(|end| end != relocations_offset) {
            return Err(DecodeError::invalid(
                relocations_offset,
                "PE import table end mismatch",
            ));
        }
        let relocation_encoding = match number(&decoded, footer + 4, 1) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        if relocation_encoding != 0 {
            return Err(DecodeError::Unsupported(
                "PE relocation encoding".to_owned(),
            ));
        }
        footer += 5;
        let end = match relocations(&mut image, &decoded, &original, base, relocations_offset) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        if end != original_offset {
            return Err(DecodeError::invalid(
                end,
                "PE relocation table end mismatch",
            ));
        }
    } else if imports_end.is_some_and(|end| end != original_offset) {
        return Err(DecodeError::invalid(
            original_offset,
            "PE import table end mismatch",
        ));
    }
    if footer != decoded.len() - 4 {
        return Err(DecodeError::Unsupported(
            "PE recovery metadata layout".to_owned(),
        ));
    }
    let header_size = original.end - original_offset;
    let mut output = vec![0; file_size];
    let header_bytes = match slice(bytes, 0, pe_offset) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    if let Err(error) = copy(&mut output, 0, header_bytes) {
        return Err(error);
    }
    let bytes = match slice(&decoded, original_offset, header_size) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    if let Err(error) = copy(&mut output, pe_offset, bytes) {
        return Err(error);
    }
    for index in [6, 12] {
        let offset = pe_offset + original.directories - original_offset + index * 8;
        if let Err(error) = put(&mut output, offset, 0, 8) {
            return Err(error);
        }
    }
    let mut end = pe_offset + header_size;
    for section in &original.sections {
        if section.offset < end || section.offset + section.size > file_size {
            return Err(DecodeError::Unsupported(
                "overlapping or unordered PE sections".to_owned(),
            ));
        }
        let offset = match image_offset(section.address, base) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let available = image.len().saturating_sub(offset).min(section.size);
        let bytes = match slice(&image, offset, available) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        if let Err(error) = copy(&mut output, section.offset, bytes) {
            return Err(error);
        }
        end = section.offset + section.size;
    }
    if end != file_size {
        return Err(DecodeError::Unsupported("PE file overlay".to_owned()));
    }
    Ok(output)
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(10)]
    fn image_writes() {
        let mut bytes: [u8; 8] = kani::any();
        let original = bytes;
        let offset: usize = kani::any();
        let value: usize = kani::any();
        let width: usize = kani::any();
        // Callers write fields of at most eight bytes.
        kani::assume(width <= 8);
        let in_range = offset
            .checked_add(width)
            .is_some_and(|end| end <= bytes.len());
        match put(&mut bytes, offset, value, width) {
            Ok(()) => {
                assert!(in_range, "a write succeeds only inside the image");
                assert_eq!(
                    bytes[offset..offset + width],
                    (value as u64).to_le_bytes()[..width]
                );
                assert_eq!(bytes[..offset], original[..offset]);
                assert_eq!(bytes[offset + width..], original[offset + width..]);
            }
            Err(_) => {
                assert!(!in_range, "an in-range write always succeeds");
                assert_eq!(bytes, original);
            }
        }
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn image_copies() {
        let mut bytes: [u8; 8] = kani::any();
        let original = bytes;
        let source: [u8; 4] = kani::any();
        let length: usize = kani::any();
        kani::assume(length <= source.len());
        let offset: usize = kani::any();
        let in_range = offset
            .checked_add(length)
            .is_some_and(|end| end <= bytes.len());
        match copy(&mut bytes, offset, &source[..length]) {
            Ok(()) => {
                assert!(in_range, "a copy succeeds only inside the image");
                assert_eq!(bytes[offset..offset + length], source[..length]);
                assert_eq!(bytes[..offset], original[..offset]);
                assert_eq!(bytes[offset + length..], original[offset + length..]);
            }
            Err(_) => {
                assert!(!in_range, "an in-range copy always succeeds");
                assert_eq!(bytes, original);
            }
        }
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn image_strings_and_offsets() {
        let bytes: [u8; 8] = kani::any();
        let offset: usize = kani::any();
        match string(&bytes, offset) {
            Ok(text) => {
                let (last, body) = text.split_last().expect("a returned string is terminated");
                assert_eq!(*last, 0);
                assert!(
                    !body.contains(&0),
                    "the string ends at its first terminator"
                );
                assert_eq!(text, &bytes[offset..offset + text.len()]);
            }
            Err(_) => {
                assert!(offset > bytes.len() || !bytes[offset..].contains(&0));
            }
        }
        let address: usize = kani::any();
        let base: usize = kani::any();
        match image_offset(address, base) {
            Ok(offset) => assert_eq!(offset + base, address),
            Err(_) => assert!(address < base),
        }
    }

    // Room for a PE32+ header with one section. Only header offsets 0 through 8 are checked.
    #[kani::proof]
    #[kani::unwind(5)]
    fn headers_from_arbitrary_bytes() {
        let bytes: [u8; 312] = kani::any();
        let offset: usize = kani::any();
        kani::assume(offset <= 8);
        if let Ok(header) = header(&bytes, offset) {
            assert!(
                header.end <= bytes.len(),
                "the section table lies inside the input"
            );
            assert!(header.directories < header.end);
            kani::cover!(header.word == 8, "a PE32+ header is read");
        }
    }
}

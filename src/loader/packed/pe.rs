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
    slice(bytes, offset, 24)?;
    if slice(bytes, offset, 4)? != b"PE\0\0" {
        return Err(DecodeError::invalid(offset, "invalid PE signature"));
    }
    let machine = number(bytes, offset + 4, 2)?;
    let count = number(bytes, offset + 6, 2)?;
    let optional = offset + 24;
    let size = number(bytes, offset + 20, 2)?;
    let (word, directories) = match (machine, number(bytes, optional, 2)?, size) {
        (0x14c, 0x10b, 224) => (4, optional + 96),
        (0x8664, 0x20b, 240) => (8, optional + 112),
        _ => {
            return Err(DecodeError::Unsupported(
                "PE machine or optional header layout".to_owned(),
            ));
        }
    };
    if count == 0 || count > 96 || number(bytes, directories - 4, 4)? != 16 {
        return Err(DecodeError::Unsupported(
            "PE section or directory count".to_owned(),
        ));
    }
    let end = optional + size + count * 40;
    slice(bytes, offset, end - offset)?;
    let mut sections = Vec::new();
    for index in 0..count {
        let start = optional + size + index * 40;
        let address = number(bytes, start + 12, 4)?;
        let size = number(bytes, start + 16, 4)?;
        let offset = number(bytes, start + 20, 4)?;
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
    let mut descriptor = image_offset(number(source, header.directories + 8, 4)?, base)?;
    let size = number(source, header.directories + 12, 4)?;
    let end = descriptor
        .checked_add(size)
        .ok_or_else(|| DecodeError::invalid(descriptor, "PE import size overflow"))?;
    slice(image, descriptor, size)?;
    enum Import<'input> {
        Name { thunk: usize, name: &'input [u8] },
        Ordinal { thunk: usize, ordinal: usize },
    }
    let mut functions = Vec::new();
    loop {
        let library = number(source, position, 4)?;
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
        let mut thunk = number(source, position, 4)?;
        position += 4;
        slice(image, thunk, header.word)?;
        let library = string(packed_imports, library)?;
        copy(image, image_offset(names, base)?, library)?;
        put(image, descriptor + 12, names, 4)?;
        put(image, descriptor + 16, thunk + base, 4)?;
        names += library.len();
        loop {
            let kind = number(source, position, 1)?;
            position += 1;
            let import = match kind {
                0 => break,
                1 => {
                    let name = string(source, position)?;
                    position += name.len();
                    Import::Name { thunk, name }
                }
                0xff => {
                    let ordinal = number(source, position, 2)?;
                    position += 2;
                    Import::Ordinal { thunk, ordinal }
                }
                _ => {
                    return Err(DecodeError::Unsupported(format!(
                        "compressed PE import kind 0x{kind:02x}"
                    )));
                }
            };
            slice(image, thunk, header.word)?;
            functions.push(import);
            thunk += header.word;
        }
        put(image, thunk, 0, header.word)?;
        descriptor += 20;
    }
    for import in functions {
        match import {
            Import::Name { thunk, name } => {
                names = (names + 1) & !1;
                let offset = image_offset(names, base)?;
                put(image, offset, 0, 2)?;
                copy(image, offset + 2, name)?;
                put(image, thunk, names, header.word)?;
                names += 2 + name.len();
            }
            Import::Ordinal { thunk, ordinal } => {
                let value = ordinal | (1usize << (header.word * 8 - 1));
                put(image, thunk, value, header.word)?;
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
    let image_base = number(
        source,
        header.optional + if header.word == 8 { 24 } else { 28 },
        header.word,
    )?;
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
        let mut delta = number(source, position, 1)?;
        position += 1;
        if delta == 0 {
            break;
        }
        if delta >= 0xf0 {
            delta = ((delta & 15) << 16) | number(source, position, 2)?;
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
        slice(image, start, header.word)?;
        previous_end = start + header.word;
        let mut relative = 0usize;
        for byte in slice(source, start, header.word)? {
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
        put(image, start, value, header.word)?;
        let address = start + base;
        let kind = if header.word == 8 { 10 } else { 3 };
        pages
            .entry(address & !0xfff)
            .or_default()
            .push(((kind << 12) | (address & 0xfff)) as u16);
    }
    let directory = number(source, header.directories + 40, 4)?;
    let size = number(source, header.directories + 44, 4)?;
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
    copy(image, image_offset(directory, base)?, &table)?;
    Ok(position)
}

pub(super) fn unpack(bytes: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let pe_offset = number(bytes, 60, 4)?;
    let packed = header(bytes, pe_offset)?;
    for section in &packed.sections {
        slice(bytes, section.offset, section.size)?;
    }
    let packed_end = packed
        .sections
        .iter()
        .map(|section| section.offset + section.size)
        .max();
    if packed_end != Some(bytes.len()) {
        return Err(DecodeError::Unsupported("PE file overlay".to_owned()));
    }
    let offset = locate(bytes, &packed)?;
    let pack = slice(bytes, offset, 32)?;
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
    let size = number(pack, 16, 4)?;
    let compressed = number(pack, 20, 4)?;
    let file_size = number(pack, 24, 4)?;
    if size < 4
        || size > MAX_FILE_SIZE as usize
        || file_size < packed.end
        || file_size > MAX_FILE_SIZE as usize
        || compressed == 0
        || compressed > size
    {
        return Err(DecodeError::invalid(offset, "invalid PE UPX sizes"));
    }
    let data = slice(bytes, offset + 32, compressed)?;
    let mut checksum = Checksum::new();
    checksum.update(data);
    if checksum.value() != number(pack, 12, 4)? {
        return Err(DecodeError::invalid(
            offset,
            "PE UPX compressed checksum mismatch",
        ));
    }
    let decoded = decompress(data, size, pack[6])?;
    let mut checksum = Checksum::new();
    checksum.update(&decoded);
    if checksum.value() != number(pack, 8, 4)? {
        return Err(DecodeError::invalid(
            offset,
            "PE UPX uncompressed checksum mismatch",
        ));
    }
    let original_offset = number(&decoded, decoded.len() - 4, 4)?;
    let original = header(&decoded, original_offset)?;
    if packed.machine != original.machine {
        return Err(DecodeError::invalid(
            original_offset,
            "recovered PE machine differs",
        ));
    }
    for index in [2, 4, 9, 10, 11, 13, 14] {
        if number(&decoded, original.directories + index * 8, 4)? != 0 {
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
    let code = number(&decoded, original.optional + 20, 4)?;
    let code_size = number(&decoded, original.optional + 4, 4)?;
    if code != base || code_size > image.len() {
        return Err(DecodeError::Unsupported("PE code filter range".to_owned()));
    }
    filter::decode(&mut image[..code_size], pack[28], pack[29])?;
    let mut footer = original.end;
    let mut imports_end = None;
    if number(&decoded, original.directories + 8, 4)? != 0 {
        let imports_offset = number(&decoded, footer, 4)?;
        let names = number(&decoded, footer + 4, 4)?;
        footer += 8;
        let address = number(bytes, packed.directories + 8, 4)?;
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
        let packed_imports = slice(bytes, start, section.size - (address - section.address))?;
        imports_end = Some(imports(
            &mut image,
            &decoded,
            packed_imports,
            &original,
            base,
            names,
            imports_offset,
        )?);
    }
    if number(&decoded, original.directories + 40, 4)? != 0 {
        let relocations_offset = number(&decoded, footer, 4)?;
        if imports_end.is_some_and(|end| end != relocations_offset) {
            return Err(DecodeError::invalid(
                relocations_offset,
                "PE import table end mismatch",
            ));
        }
        if number(&decoded, footer + 4, 1)? != 0 {
            return Err(DecodeError::Unsupported(
                "PE relocation encoding".to_owned(),
            ));
        }
        footer += 5;
        let end = relocations(&mut image, &decoded, &original, base, relocations_offset)?;
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
    copy(&mut output, 0, slice(bytes, 0, pe_offset)?)?;
    copy(
        &mut output,
        pe_offset,
        slice(&decoded, original_offset, header_size)?,
    )?;
    for index in [6, 12] {
        let offset = pe_offset + original.directories - original_offset + index * 8;
        put(&mut output, offset, 0, 8)?;
    }
    let mut end = pe_offset + header_size;
    for section in &original.sections {
        if section.offset < end || section.offset + section.size > file_size {
            return Err(DecodeError::Unsupported(
                "overlapping or unordered PE sections".to_owned(),
            ));
        }
        let offset = image_offset(section.address, base)?;
        let available = image.len().saturating_sub(offset).min(section.size);
        copy(
            &mut output,
            section.offset,
            slice(&image, offset, available)?,
        )?;
        end = section.offset + section.size;
    }
    if end != file_size {
        return Err(DecodeError::Unsupported("PE file overlay".to_owned()));
    }
    Ok(output)
}

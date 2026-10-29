//! String extraction from loaded data sections.
use super::StringLiteral;
use crate::loader::Image;

pub(super) fn strings(image: &Image) -> Vec<StringLiteral> {
    let mut result = Vec::new();
    for section in image
        .sections
        .iter()
        .filter(|s| s.loaded && (!s.executable || image.format == crate::loader::Format::Raw))
    {
        let Some(bytes) = image.read_vaddr(section.vaddr, section.size) else {
            continue;
        };
        extract(bytes, section.vaddr, &section.name, &mut result);
    }
    result.sort_by_key(|literal| literal.addr);
    result
}

pub(super) fn at(image: &Image, address: u64) -> Option<String> {
    let Some(section) = image.sections.iter().find(|section| {
        section.loaded
            && (!section.executable || image.format == crate::loader::Format::Raw)
            && address >= section.vaddr
            && address < section.vaddr.saturating_add(section.size)
    }) else {
        return None;
    };
    let Some(bytes) = image.read_vaddr(section.vaddr, section.size) else {
        return None;
    };
    at_bytes(bytes, section.vaddr, address, &section.name)
}

pub(super) fn at_bytes(bytes: &[u8], base: u64, address: u64, section: &str) -> Option<String> {
    const WINDOW: usize = 200;

    let Some(relative) = address.checked_sub(base) else {
        return None;
    };
    let Ok(offset) = usize::try_from(relative) else {
        return None;
    };
    if offset >= bytes.len() {
        return None;
    }
    if offset != 0
        && bytes.get(offset - 1).is_some_and(|byte| {
            *byte != 0 && (*byte >= 0x20 || matches!(*byte, b'\n' | b'\r' | b'\t'))
        })
    {
        return None;
    }
    let end = offset.saturating_add(WINDOW).min(bytes.len());
    let Some(bytes) = bytes.get(offset..end) else {
        return None;
    };
    let mut literals = Vec::new();
    extract(bytes, address, section, &mut literals);
    literals
        .into_iter()
        .find(|literal| literal.addr == address)
        .map(|literal| literal.text)
}

pub(super) fn extract(bytes: &[u8], base: u64, section: &str, result: &mut Vec<StringLiteral>) {
    let mut add = |start: usize, end: usize, encoding: &str, text: String| {
        if text.chars().count() < 4
            || !text
                .chars()
                .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        {
            return;
        }
        let Some(addr) = base.checked_add(start as u64) else {
            return;
        };
        result.push(StringLiteral {
            addr,
            section: section.to_owned(),
            encoding: encoding.to_owned(),
            text,
            bytes: end - start,
            xrefs: Vec::new(),
        });
    };
    let mut utf8 = |mut start: usize, end: usize| {
        while start < end {
            match std::str::from_utf8(&bytes[start..end]) {
                Ok(text) => {
                    add(
                        start,
                        end,
                        if text.is_ascii() { "ascii" } else { "utf8" },
                        text.to_owned(),
                    );
                    break;
                }
                Err(error) => {
                    let valid_end = start.saturating_add(error.valid_up_to());
                    if valid_end > start
                        && let Ok(text) = std::str::from_utf8(&bytes[start..valid_end])
                    {
                        add(
                            start,
                            valid_end,
                            if text.is_ascii() { "ascii" } else { "utf8" },
                            text.to_owned(),
                        );
                    }
                    start = valid_end.saturating_add(error.error_len().unwrap_or(1));
                }
            }
        }
    };
    let mut start = 0;
    for (at, byte) in bytes.iter().enumerate() {
        if *byte != 0 && (*byte >= 0x20 || matches!(*byte, b'\n' | b'\r' | b'\t')) {
            continue;
        }
        utf8(start, at);
        start = at + 1;
    }
    utf8(start, bytes.len());
    // Both alignments are needed for packed data.
    for alignment in 0..2 {
        let mut start = alignment;
        let mut units = Vec::new();
        for at in (alignment..bytes.len().saturating_sub(1)).step_by(2) {
            let unit = u16::from_le_bytes([bytes[at], bytes[at + 1]]);
            if unit != 0 && !(unit < 0x20 && !matches!(unit, 9 | 10 | 13)) {
                units.push(unit);
                continue;
            }
            if let Ok(text) = String::from_utf16(&units) {
                add(start, at, "utf16le", text);
            }
            units.clear();
            start = at + 2;
        }
        if let Ok(text) = String::from_utf16(&units) {
            add(
                start,
                start.saturating_add(units.len().saturating_mul(2)),
                "utf16le",
                text,
            );
        }
    }
}

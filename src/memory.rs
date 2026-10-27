//! Byte searches and bounded, typed reads of loaded image sections.
mod types;

use std::borrow::Cow;
use std::time::Instant;

use serde_json::{Value, json};

use crate::deadline::passed;
use crate::error::{Error, Result};
use crate::loader::{Image, Isa, Section};

pub(crate) fn error(message: impl Into<String>) -> Error {
    Error::Memory(message.into())
}

pub(crate) fn little_endian(image: &Image, order: &str) -> Result<bool> {
    match order {
        "little" => Ok(true),
        "big" => Ok(false),
        "native" => match image.byte_order() {
            Some(object::Endianness::Little) => Ok(true),
            Some(object::Endianness::Big) => Ok(false),
            None => Err(error("image byte order is unknown")),
        },
        _ => Err(error("byte order must be native, little or big")),
    }
}

pub(crate) fn pointer_width(image: &Image) -> Result<u64> {
    match image.isa {
        Isa::I386 | Isa::Arm32 => Ok(4),
        Isa::X86_64 | Isa::AArch64 => Ok(8),
        Isa::Unsupported => Err(error("image pointer width is unknown")),
    }
}

pub(crate) fn section_bytes<'image>(
    image: &'image Image,
    section: &Section,
) -> Option<&'image [u8]> {
    if !section.loaded {
        return None;
    }
    let Some(offset) = section.file_offset else {
        return None;
    };
    image.read(offset, image.section_file_size(section))
}

pub(crate) fn span(image: &Image, address: u64, size: u64) -> Result<(&Section, u64)> {
    let Some(end) = address.checked_add(size) else {
        return Err(error(format!(
            "read at 0x{address:x}: address overflow for {size} bytes"
        )));
    };
    for section in &image.sections {
        let Some(section_end) = section.vaddr.checked_add(section.size) else {
            continue;
        };
        if section.loaded && address >= section.vaddr && address < section_end && end <= section_end
        {
            return Ok((section, address - section.vaddr));
        }
    }
    Err(error(format!(
        "read at 0x{address:x} of {size} bytes is unmapped or crosses a section boundary"
    )))
}

pub(crate) fn bytes(image: &Image, address: u64, size: u64) -> Result<Cow<'_, [u8]>> {
    let (section, offset) = match span(image, address, size) {
        Ok(span) => span,
        Err(error) => return Err(error),
    };
    let (Ok(start), Ok(size)) = (usize::try_from(offset), usize::try_from(size)) else {
        return Err(error("read size exceeds the host address space"));
    };
    if section.file_offset.is_none() {
        if image.section_file_size(section) != 0 {
            return Err(error(format!(
                "read at 0x{address:x}: section file offset is invalid"
            )));
        }
        if size > 16 * 1024 * 1024 {
            return Err(error("read exceeds 16 MiB"));
        }
        return Ok(Cow::Owned(vec![0; size]));
    }
    if let Some(section_bytes) = section_bytes(image, section)
        && let Some(end) = start.checked_add(size)
    {
        if let Some(requested_bytes) = section_bytes.get(start..end) {
            return Ok(Cow::Borrowed(requested_bytes));
        }
        if size > 16 * 1024 * 1024 {
            return Err(error("read exceeds 16 MiB"));
        }
        let mut value = vec![0; size];
        if let Some(prefix) = section_bytes.get(start..) {
            value[..prefix.len()].copy_from_slice(prefix);
        }
        return Ok(Cow::Owned(value));
    }
    Err(error(format!(
        "read at 0x{address:x} of {size} bytes: section file data is truncated"
    )))
}

pub(crate) use crate::loader::image_reads::unsigned;

/// Options for a search within loaded sections.
#[derive(Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Search {
    /// Pattern interpretation: hex, ascii, utf16 or integer.
    pub encoding: String,
    /// Integer width in bytes (1, 2, 4 or 8).
    pub width: Option<u8>,
    /// Native image order, little or big.
    pub byte_order: String,
    /// Inclusive lower bound as an address string.
    pub start: Option<String>,
    /// Exclusive upper bound for the complete match.
    pub end: Option<String>,
    /// Exact loaded section name, when restricted.
    pub section: Option<String>,
}

impl Default for Search {
    fn default() -> Self {
        Self {
            encoding: "hex".to_owned(),
            width: None,
            byte_order: "native".to_owned(),
            start: None,
            end: None,
            section: None,
        }
    }
}

fn pattern(image: &Image, text: &str, options: &Search) -> Result<Vec<Option<u8>>> {
    if text.len() > 65536 {
        return Err(error("search pattern exceeds 65536 bytes of text"));
    }
    if options.encoding != "integer" && options.width.is_some() {
        return Err(error("width is only used for integer searches"));
    }
    let little = match little_endian(image, &options.byte_order) {
        Ok(little) => little,
        Err(error) => return Err(error),
    };
    let pattern = match options.encoding.as_str() {
        "hex" => {
            let mut result = Vec::new();
            for token in text.split_whitespace() {
                if token == "??" {
                    result.push(None);
                } else if token.len() == 2 && token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    match u8::from_str_radix(token, 16) {
                        Ok(byte) => result.push(Some(byte)),
                        Err(_) => return Err(error(format!("invalid hex byte: {token}"))),
                    }
                } else {
                    return Err(error(format!(
                        "invalid hex byte: {token}; use two hex digits or ??"
                    )));
                }
            }
            result
        }
        "ascii" => {
            if !text.is_ascii() {
                return Err(error("ASCII search text contains a non-ASCII character"));
            }
            text.bytes().map(Some).collect()
        }
        "utf16" => {
            let mut result = Vec::new();
            for unit in text.encode_utf16() {
                let pair = if little {
                    unit.to_le_bytes()
                } else {
                    unit.to_be_bytes()
                };
                result.extend(pair.map(Some));
            }
            result
        }
        "integer" => {
            let Some(width @ (1 | 2 | 4 | 8)) = options.width else {
                return Err(error("integer search requires width 1, 2, 4 or 8 (bytes)"));
            };
            let value = if let Some(magnitude) = text.strip_prefix('-') {
                let Some(magnitude) = crate::addr::parse(magnitude) else {
                    return Err(error(
                        "integer search requires a decimal or 0x-prefixed integer",
                    ));
                };
                if magnitude > (1u64 << (width * 8 - 1)) {
                    return Err(error(format!(
                        "integer {text} does not fit in {width} signed bytes"
                    )));
                }
                0u64.wrapping_sub(magnitude)
            } else {
                let Some(value) = crate::addr::parse(text) else {
                    return Err(error(
                        "integer search requires a decimal or 0x-prefixed integer",
                    ));
                };
                if width < 8 && value >= (1u64 << (width * 8)) {
                    return Err(error(format!(
                        "integer {text} does not fit in {width} bytes"
                    )));
                }
                value
            };
            let encoded = if little {
                value.to_le_bytes()
            } else {
                value.to_be_bytes()
            };
            let encoded_bytes = if little {
                &encoded[..usize::from(width)]
            } else {
                &encoded[8 - usize::from(width)..]
            };
            encoded_bytes.iter().copied().map(Some).collect()
        }
        _ => return Err(error("encoding must be hex, ascii, utf16 or integer")),
    };
    if pattern.is_empty() {
        return Err(error("search pattern is empty"));
    }
    Ok(pattern)
}

pub(crate) fn containing_function(image: &Image, address: u64) -> Option<u64> {
    image
        .functions
        .range(..=address)
        .next_back()
        .filter(|(start, function)| function.size.is_some_and(|size| address - **start < size))
        .map(|(start, _)| *start)
}

pub(crate) fn search(
    image: &Image,
    text: &str,
    options: &Search,
    deadline: Option<Instant>,
) -> Result<Value> {
    let pattern = match pattern(image, text, options) {
        Ok(pattern) => pattern,
        Err(error) => return Err(error),
    };
    let mut bounds = [0, u64::MAX];
    for (index, text) in [options.start.as_ref(), options.end.as_ref()]
        .into_iter()
        .enumerate()
    {
        if let Some(text) = text {
            let Some(address) = crate::addr::parse(text) else {
                return Err(Error::BadAddress(text.clone()));
            };
            bounds[index] = address;
        }
    }
    if bounds[0] > bounds[1] {
        return Err(error("search start is greater than end"));
    }
    if let Some(name) = &options.section
        && !image
            .sections
            .iter()
            .any(|section| section.loaded && &section.name == name)
    {
        return Err(error(format!("no loaded section named {name}")));
    }
    let mut matches = Vec::new();
    for section in &image.sections {
        if options
            .section
            .as_ref()
            .is_some_and(|name| &section.name != name)
        {
            continue;
        }
        if !section.loaded {
            continue;
        }
        let Some(section_end) = section.vaddr.checked_add(section.size) else {
            continue;
        };
        let start = section.vaddr.max(bounds[0]);
        let end = section_end.min(bounds[1]);
        if start >= end {
            continue;
        }
        let (Ok(low), Ok(high)) = (
            usize::try_from(start - section.vaddr),
            usize::try_from(end - section.vaddr),
        ) else {
            continue;
        };
        let file_data = match section_bytes(image, section) {
            Some(bytes) => bytes,
            None if section.file_offset.is_none() && image.section_file_size(section) == 0 => &[],
            None => continue,
        };
        let Some(candidate_count) = (high - low)
            .checked_sub(pattern.len())
            .and_then(|count| count.checked_add(1))
        else {
            continue;
        };
        let Some(mut candidate_end) = low.checked_add(candidate_count) else {
            continue;
        };
        let matches_zeros = pattern.iter().all(|byte| byte.is_none_or(|byte| byte == 0));
        if matches_zeros {
            let zero_count = candidate_end.saturating_sub(low.max(file_data.len()));
            if zero_count > 65536usize.saturating_sub(matches.len()) {
                return Err(error(
                    "search exceeds 65536 matches; narrow the address range or pattern",
                ));
            }
        } else {
            candidate_end = candidate_end.min(file_data.len());
        }
        for offset in low..candidate_end {
            if offset.is_multiple_of(4096)
                && let Err(error) = passed(deadline)
            {
                return Err(error);
            }
            if pattern.iter().enumerate().all(|(index, wanted)| {
                wanted.is_none_or(|wanted| {
                    file_data.get(offset + index).copied().unwrap_or(0) == wanted
                })
            }) {
                let Some(address) = section.vaddr.checked_add(offset as u64) else {
                    continue;
                };
                if matches.len() >= 65536 {
                    return Err(error(
                        "search exceeds 65536 matches; narrow the address range or pattern",
                    ));
                }
                matches.push(json!({"addr": crate::addr::format(address), "section": section.name, "function": containing_function(image, address).map(crate::addr::format)}));
            }
        }
    }
    if let Err(error) = passed(deadline) {
        return Err(error);
    }
    Ok(json!({"matches": matches}))
}

pub(crate) use types::read;

#[cfg(test)]
mod tests;

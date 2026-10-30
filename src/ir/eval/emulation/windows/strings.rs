//! Bounded UTF-8/UTF-16 conversion and string lengths.

use super::{Runner, Stop};

fn utf8_with_replacements(bytes: &[u8]) -> String {
    let mut text = String::new();
    let mut remaining = bytes;
    while !remaining.is_empty() {
        match std::str::from_utf8(remaining) {
            Ok(valid) => {
                text.push_str(valid);
                break;
            }
            Err(error) => {
                let valid_length = error.valid_up_to();
                let Ok(valid) = std::str::from_utf8(&remaining[..valid_length]) else {
                    unreachable!("valid_up_to identifies valid UTF-8");
                };
                text.push_str(valid);
                remaining = &remaining[valid_length..];
                let invalid_length = match error.error_len() {
                    Some(1) if invalid_utf8_second_byte(remaining) => 2,
                    Some(length) => length,
                    None => remaining.len(),
                };
                text.push('\u{fffd}');
                remaining = &remaining[invalid_length..];
            }
        }
    }
    text
}

fn invalid_utf8_second_byte(bytes: &[u8]) -> bool {
    let Some((&lead, rest)) = bytes.split_first() else {
        return false;
    };
    let Some(&second) = rest.first() else {
        return false;
    };
    matches!(
        (lead, second),
        (0xe0, 0x80..=0x9f) | (0xed, 0xa0..=0xbf) | (0xf0, 0x80..=0x8f) | (0xf4, 0x90..=0xbf)
    )
}

impl Runner<'_> {
    pub(super) fn wide_units(&mut self, address: u64, length: i32) -> Result<Vec<u16>, Stop> {
        let limit = if length == -1 {
            super::super::HEAP_SIZE / 2
        } else {
            length as u64
        };
        if limit > super::super::HEAP_SIZE / 2 {
            return Err(Stop::Error("UTF-16 read exceeds 16 MiB".to_owned()));
        }
        let mut units = Vec::new();
        for offset in 0..limit {
            let Some(at) = address.checked_add(offset * 2) else {
                return Err(Stop::Error("UTF-16 address overflows".to_owned()));
            };
            let Some(high) = at.checked_add(1) else {
                return Err(Stop::Error("UTF-16 address overflows".to_owned()));
            };
            let low = match self.read_byte(at) {
                Ok(value) => value,
                Err(stop) => return Err(stop),
            };
            let high = match self.read_byte(high) {
                Ok(value) => value,
                Err(stop) => return Err(stop),
            };
            let unit = u16::from_le_bytes([low, high]);
            units.push(unit);
            if length == -1 && unit == 0 {
                return Ok(units);
            }
        }
        if length == -1 {
            return Err(Stop::Error(
                "UTF-16 string has no NUL within 16 MiB".to_owned(),
            ));
        }
        Ok(units)
    }

    pub(super) fn windows_string_api(&mut self, name: &str, args: &[u64]) -> Result<u64, Stop> {
        if name.starts_with("lstrlen") {
            if args[0] == 0 {
                return Ok(0);
            }
            return if name == "lstrlenW" {
                match self.wide_units(args[0], -1) {
                    Ok(units) => Ok((units.len() - 1) as u64),
                    Err(stop) => Err(stop),
                }
            } else {
                match self.bytes_at(args[0], None) {
                    Ok(bytes) => Ok(bytes.len() as u64),
                    Err(stop) => Err(stop),
                }
            };
        }
        let code_page = args[0] as u32;
        let flags = args[1] as u32;
        let length = args[3] as i32;
        let capacity = args[5] as i32;
        let to_wide = name == "MultiByteToWideChar";
        if length == 0
            || length < -1
            || capacity < 0
            || args[2] == 0
            || (capacity != 0 && args[4] == 0)
            || args[2] == args[4]
            || (!to_wide && code_page == 65001 && (args[6] != 0 || args[7] != 0))
        {
            return self.windows_failure(87);
        }
        if !matches!(code_page, 0 | 1252 | 65001) {
            return Err(Stop::Error(format!(
                "unsupported Windows code page {code_page}"
            )));
        }
        let allowed = if code_page == 65001 {
            if to_wide { 8 } else { 0x80 }
        } else if to_wide {
            0xf
        } else {
            0x600
        };
        if flags & !allowed != 0 || (to_wide && flags & 3 == 3) {
            return self.windows_failure(1004);
        }
        let bytes = if to_wide {
            let mut input = match self.bytes_at(
                args[2],
                if length == -1 {
                    None
                } else {
                    Some(length as usize)
                },
            ) {
                Ok(bytes) => bytes,
                Err(stop) => return Err(stop),
            };
            if length == -1 {
                input.push(0);
            }
            if code_page != 65001 && !input.is_ascii() {
                return Err(Stop::Error(
                    "Windows ANSI conversion requires ASCII".to_owned(),
                ));
            }
            let text = match std::str::from_utf8(&input) {
                Ok(text) => std::borrow::Cow::Borrowed(text),
                Err(_) if flags & 8 != 0 => return self.windows_failure(1113),
                Err(_) => std::borrow::Cow::Owned(utf8_with_replacements(&input)),
            };
            let mut bytes = Vec::new();
            for unit in text.encode_utf16() {
                bytes.extend_from_slice(&unit.to_le_bytes());
            }
            bytes
        } else {
            let units = match self.wide_units(args[2], length) {
                Ok(units) => units,
                Err(stop) => return Err(stop),
            };
            let (text, invalid) = match String::from_utf16(&units) {
                Ok(text) => (text, false),
                Err(_) => (String::from_utf16_lossy(&units), true),
            };
            if code_page != 65001 {
                if !text.is_ascii() {
                    return Err(Stop::Error(
                        "Windows ANSI conversion requires ASCII".to_owned(),
                    ));
                }
                if args[7] != 0
                    && let Err(stop) = self.store_bytes(args[7], &0u32.to_le_bytes())
                {
                    return Err(stop);
                }
            }
            let bytes = text.into_bytes();
            let count = bytes.len();
            if capacity != 0 && (capacity as usize) < count {
                return self.windows_failure(122);
            }
            if invalid && flags & 0x80 != 0 {
                return self.windows_failure(1113);
            }
            bytes
        };
        let count = bytes.len() / if to_wide { 2 } else { 1 };
        if capacity == 0 {
            return Ok(count as u64);
        }
        if (capacity as usize) < count {
            return self.windows_failure(122);
        }
        match self.store_bytes(args[4], &bytes) {
            Ok(()) => Ok(count as u64),
            Err(stop) => Err(stop),
        }
    }
}

//! Typed values decoded without reading across section boundaries.
use std::time::Instant;

use serde_json::{Map, Value, json};

use crate::deadline::passed;
use crate::error::Result;
use crate::ir::{CType, Definition, Member};
use crate::loader::Image;

use super::{bytes, error, little_endian, pointer_width, span, unsigned};

const MAX_VALUES: u64 = 65536;
const MAX_BYTES: u64 = 16 * 1024 * 1024;

struct Reader<'image> {
    image: &'image Image,
    little: bool,
    definitions: Vec<Definition>,
    members: Vec<Member>,
    remaining: u64,
    deadline: Option<Instant>,
}

impl Reader<'_> {
    fn scalar(&self, name: &str) -> Option<(u64, bool)> {
        let (size, signed) = match name {
            "u8" | "uint8_t" | "unsigned char" => (1, false),
            "i8" | "int8_t" | "signed char" => (1, true),
            "u16" | "uint16_t" | "unsigned short" => (2, false),
            "i16" | "int16_t" | "short" | "short int" => (2, true),
            "u32" | "uint32_t" | "unsigned" | "unsigned int" => (4, false),
            "i32" | "int32_t" | "int" | "signed int" => (4, true),
            "u64" | "uint64_t" | "unsigned long long" => (8, false),
            "i64" | "int64_t" | "long long" | "long long int" => (8, true),
            "f32" | "float" => (4, false),
            "f64" | "double" => (8, false),
            _ => return None,
        };
        Some((size, signed))
    }

    fn array(&self, name: &str) -> Result<Option<(String, u64)>> {
        if name.ends_with(']') {
            let Some((base, dimensions)) = name.split_once('[') else {
                return Err(error("array type must be TYPE[N]"));
            };
            let Some((count, rest)) = dimensions.split_once(']') else {
                return Err(error("array type must be TYPE[N]"));
            };
            let Ok(count) = count.parse::<u64>() else {
                return Err(error("array length must be an unsigned integer"));
            };
            if count == 0 || count > MAX_VALUES {
                return Err(error("array length must be between 1 and 65536"));
            }
            if !rest.is_empty() && !rest.starts_with('[') {
                return Err(error("invalid array dimensions"));
            }
            return Ok(Some((format!("{}{rest}", base.trim()), count)));
        }
        Ok(None)
    }

    fn size(&self, name: &str, depth: usize) -> Result<u64> {
        if depth > 16 {
            return Err(error("type nesting exceeds 16 levels"));
        }
        let array = match self.array(name) {
            Ok(array) => array,
            Err(error) => return Err(error),
        };
        if let Some((base, count)) = array {
            let size = match self.size(&base, depth + 1) {
                Ok(size) => size,
                Err(error) => return Err(error),
            };
            return match size.checked_mul(count).filter(|size| *size <= MAX_BYTES) {
                Some(size) => Ok(size),
                None => Err(error("array size exceeds 16 MiB")),
            };
        }
        if let Some((size, _)) = self.scalar(name) {
            return Ok(size);
        }
        if name == "pointer" || name.ends_with('*') {
            return pointer_width(self.image);
        }
        if name.starts_with("struct ") {
            let mut found = self
                .definitions
                .iter()
                .filter(|definition| definition.name == name);
            if let Some(definition) = found.next() {
                // Different compilation units may give the same tag different layouts.
                if found.any(|other| {
                    other.size != definition.size || other.members != definition.members
                }) {
                    return Err(error(format!("ambiguous debug type: {name}")));
                }
                if definition.size > 0 && definition.size <= MAX_BYTES {
                    return Ok(definition.size);
                }
            }
        }
        Err(error(format!("unknown or unsupported memory type: {name}")))
    }

    fn value(&mut self, address: u64, name: &str, depth: usize) -> Result<(Value, u64)> {
        if let Err(error) = passed(self.deadline) {
            return Err(error);
        }
        if self.remaining == 0 || depth > 16 {
            return Err(error("read exceeds value count or type nesting limit"));
        }
        self.remaining -= 1;
        if name == "cstring" || name == "utf16" {
            return self.string(address, name == "utf16");
        }
        let size = match self.size(name, depth) {
            Ok(size) => size,
            Err(error) => return Err(error),
        };
        let value_bytes = match bytes(self.image, address, size) {
            Ok(data) => data,
            Err(error) => return Err(error),
        };
        let array = match self.array(name) {
            Ok(array) => array,
            Err(error) => return Err(error),
        };
        if let Some((base, count)) = array {
            let mut values = Vec::new();
            let mut at = address;
            for _ in 0..count {
                let (value, width) = match self.value(at, &base, depth + 1) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                values.push(value);
                at = match at.checked_add(width) {
                    Some(at) => at,
                    None => return Err(error("array address overflow")),
                };
            }
            return Ok((json!(values), size));
        }
        if name.starts_with("struct ") {
            let tag = name.trim_start_matches("struct ");
            let fields: Vec<Member> = self
                .members
                .iter()
                .filter(|member| member.structure == tag)
                .cloned()
                .collect();
            let mut result = Map::new();
            for field in fields {
                if result.contains_key(&field.name) {
                    continue;
                }
                let Ok(offset) = u64::try_from(field.offset) else {
                    return Err(error("negative debug field offset"));
                };
                let Some(end) = offset.checked_add(field.width).filter(|end| *end <= size) else {
                    return Err(error("debug field exceeds structure size"));
                };
                let Some(at) = address.checked_add(offset) else {
                    return Err(error("debug field address overflow"));
                };
                let field_type = match self.member_type(&field.ty, end - offset, depth + 1) {
                    Ok(name) => name,
                    Err(error) => return Err(error),
                };
                let (value, width) = match self.value(at, &field_type, depth + 1) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if width != field.width {
                    return Err(error(format!(
                        "unsupported debug field layout: {}",
                        field.name
                    )));
                }
                result.insert(field.name, value);
            }
            if result.is_empty() {
                return Err(error(format!("no readable fields for {name}")));
            }
            return Ok((Value::Object(result), size));
        }
        let raw = unsigned(&value_bytes, self.little);
        let value = match name {
            "f32" | "float" => {
                let value = f32::from_bits(raw as u32);
                if value.is_finite() {
                    json!(value)
                } else {
                    json!(value.to_string())
                }
            }
            "f64" | "double" => {
                let value = f64::from_bits(raw);
                if value.is_finite() {
                    json!(value)
                } else {
                    json!(value.to_string())
                }
            }
            "pointer" => json!(crate::addr::format(raw)),
            _ if name.ends_with('*') => json!(crate::addr::format(raw)),
            _ => {
                let signed = self.scalar(name).is_some_and(|(_, signed)| signed);
                if signed {
                    let shift = 64 - size * 8;
                    let value = ((raw << shift) as i64) >> shift;
                    if size == 8 {
                        json!(value.to_string())
                    } else {
                        json!(value)
                    }
                } else if size == 8 {
                    json!(crate::addr::format(raw))
                } else {
                    json!(raw)
                }
            }
        };
        Ok((value, size))
    }

    fn member_type(&self, ty: &CType, width: u64, depth: usize) -> Result<String> {
        match ty {
            CType::Array(base) => {
                let base_name = match self.member_type(base, 0, depth + 1) {
                    Ok(name) => name,
                    Err(error) => return Err(error),
                };
                let size = match self.size(&base_name, depth + 1) {
                    Ok(size) => size,
                    Err(error) => return Err(error),
                };
                if width == 0 || !width.is_multiple_of(size) {
                    return Err(error("unknown debug array length"));
                }
                Ok(format!("{base_name}[{}]", width / size))
            }
            CType::Named(name)
                if matches!(
                    name.as_str(),
                    "long" | "long int" | "unsigned long" | "long unsigned int"
                ) =>
            {
                if !matches!(width, 4 | 8) {
                    return Err(error("unknown debug long width"));
                }
                Ok(format!(
                    "{}{}",
                    if name.contains("unsigned") { "u" } else { "i" },
                    width * 8
                ))
            }
            _ => Ok(ty.to_string()),
        }
    }

    fn string(&self, address: u64, utf16: bool) -> Result<(Value, u64)> {
        let width = if utf16 { 2 } else { 1 };
        let mut consumed = 0u64;
        let mut units = Vec::new();
        loop {
            if let Err(error) = passed(self.deadline) {
                return Err(error);
            }
            consumed += width;
            if consumed > MAX_BYTES {
                return Err(error("unterminated string exceeds 16 MiB"));
            }
            // Validate the entire prefix, so adjacent sections cannot complete a string.
            if let Err(error) = span(self.image, address, consumed) {
                return Err(error);
            }
            let Some(at) = address.checked_add(consumed - width) else {
                return Err(error("string address overflow"));
            };
            let unit_bytes = match bytes(self.image, at, width) {
                Ok(data) => data,
                Err(error) => return Err(error),
            };
            let unit = unsigned(&unit_bytes, self.little) as u16;
            if unit == 0 {
                break;
            }
            units.push(unit);
        }
        let text = if utf16 {
            match String::from_utf16(&units) {
                Ok(text) => text,
                Err(_) => return Err(error(format!("invalid UTF-16 string at 0x{address:x}"))),
            }
        } else {
            let bytes: Vec<u8> = units.into_iter().map(|unit| unit as u8).collect();
            match String::from_utf8(bytes) {
                Ok(text) => text,
                Err(_) => return Err(error(format!("C string at 0x{address:x} is not UTF-8"))),
            }
        };
        Ok((json!(text), consumed))
    }
}

pub(crate) fn read(
    image: &Image,
    address: u64,
    name: &str,
    count: u64,
    deadline: Option<Instant>,
) -> Result<Value> {
    if let Err(error) = passed(deadline) {
        return Err(error);
    }
    if count > MAX_VALUES || name.len() > 4096 {
        return Err(error(
            "read count exceeds 65536 or type name exceeds 4096 bytes",
        ));
    }
    let little = match little_endian(image, "native") {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let mut reader = Reader {
        image,
        little,
        definitions: Vec::new(),
        members: Vec::new(),
        remaining: MAX_VALUES,
        deadline,
    };
    if name.contains("struct ") {
        for function in image.functions.values() {
            if let Err(error) = passed(deadline) {
                return Err(error);
            }
            if let Some(types) = crate::loader::dwarf::function_types(image, function.addr) {
                reader.definitions.extend(types.definitions);
                reader.members.extend(types.members);
                if reader.definitions.len() > MAX_VALUES as usize
                    || reader.members.len() > MAX_VALUES as usize
                {
                    return Err(error(
                        "debug type information exceeds 65536 definitions or fields",
                    ));
                }
            }
        }
    }
    let mut values = Vec::new();
    let mut at = address;
    for _ in 0..count {
        let (value, size) = match reader.value(at, name.trim(), 0) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        values.push(value);
        at = match at.checked_add(size) {
            Some(at) => at,
            None => return Err(error(format!("read at 0x{address:x}: address overflow"))),
        };
        if at - address > MAX_BYTES {
            return Err(error("read exceeds 16 MiB"));
        }
        if let Err(error) = span(image, address, at - address) {
            return Err(error);
        }
    }
    if count == 0 {
        if let Err(error) = span(image, address, 0) {
            return Err(error);
        }
        if name != "cstring"
            && name != "utf16"
            && let Err(error) = reader.size(name.trim(), 0)
        {
            return Err(error);
        }
    }
    Ok(
        json!({"addr": crate::addr::format(address), "type": name, "values": values, "bytes": at - address}),
    )
}

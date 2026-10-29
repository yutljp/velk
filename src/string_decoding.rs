//! Strings recovered from bounded execution with known inputs.

use std::time::Instant;

use serde::Serialize;

use crate::loader::Image;

/// A terminated string observed after a decoder returns or before a string use.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecodedString {
    /// Address of the output buffer in the emulated address space.
    #[serde(serialize_with = "crate::addr::serialize")]
    pub addr: u64,
    /// Function containing the call or inline decoding instructions.
    #[serde(serialize_with = "crate::addr::serialize")]
    pub function: u64,
    /// Instruction at the decoder call or the subsequent string use.
    #[serde(serialize_with = "crate::addr::serialize")]
    pub site: u64,
    /// Function that produced the bytes; the containing function for inline code.
    #[serde(serialize_with = "crate::addr::serialize")]
    pub decoder: u64,
    /// Loaded name of the decoding function, when available.
    pub decoder_name: Option<String>,
    /// Constant argument immediately after the buffer length, when available.
    pub key: Option<u64>,
    /// Whether the buffer belongs to the emulated stack.
    pub stack: bool,
    /// Strictly validated encoding: UTF-8 or little-endian UTF-16.
    pub encoding: &'static str,
    /// Recovered text, excluding its terminator.
    pub text: String,
    #[serde(skip)]
    pub(crate) target: Option<u64>,
}

/// A scalar string or integer found in a decoded configuration buffer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum ConfigurationValue {
    /// A string value.
    String(String),
    /// An integer value.
    Integer(i64),
}

/// A field extracted from a decoded configuration buffer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigurationField {
    /// Field name or flattened JSON path.
    pub name: String,
    /// String or integer value.
    pub value: ConfigurationValue,
}

/// A decoded buffer recognized as a configuration document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecodedConfiguration {
    /// Address of the decoded buffer in the emulated address space.
    #[serde(serialize_with = "crate::addr::serialize")]
    pub addr: u64,
    /// Function containing the decoder call.
    #[serde(serialize_with = "crate::addr::serialize")]
    pub function: u64,
    /// Instruction at the decoder call or subsequent string use.
    #[serde(serialize_with = "crate::addr::serialize")]
    pub site: u64,
    /// Function that produced the bytes.
    #[serde(serialize_with = "crate::addr::serialize")]
    pub decoder: u64,
    /// Loaded decoder name, when available.
    pub decoder_name: Option<String>,
    /// Constant key argument, when available.
    pub key: Option<u64>,
    /// Original decoded text.
    pub text: String,
    /// Configuration fields in source order.
    pub fields: Vec<ConfigurationField>,
}

pub(crate) fn recover(
    image: &Image,
    function: u64,
    deadline: Option<Instant>,
) -> Option<Vec<DecodedString>> {
    crate::ir::eval::emulation::recover_strings(image, function, deadline)
}

pub(crate) fn decode_text(bytes: &[u8]) -> Option<(&'static str, String)> {
    let printable = |text: &str| {
        text.chars().count() >= 4
            && text
                .chars()
                .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
    };
    if let Some(end) = bytes.iter().position(|byte| *byte == 0)
        && let Ok(text) = std::str::from_utf8(&bytes[..end])
        && printable(text)
    {
        return Some(("utf8", text.to_owned()));
    }
    let mut units = Vec::new();
    for pair in bytes.as_chunks::<2>().0 {
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        if unit == 0 {
            return match String::from_utf16(&units) {
                Ok(text) if printable(&text) => Some(("utf16le", text)),
                _ => None,
            };
        }
        units.push(unit);
    }
    None
}

/// Extracts flat string and integer fields from JSON or delimited key/value text.
#[must_use]
pub fn configurations(strings: &[DecodedString]) -> Vec<DecodedConfiguration> {
    let mut configurations = Vec::new();
    for string in strings {
        let Some(fields) = configuration_fields(&string.text) else {
            continue;
        };
        configurations.push(DecodedConfiguration {
            addr: string.addr,
            function: string.function,
            site: string.site,
            decoder: string.decoder,
            decoder_name: string.decoder_name.clone(),
            key: string.key,
            text: string.text.clone(),
            fields,
        });
    }
    configurations
}

fn configuration_fields(text: &str) -> Option<Vec<ConfigurationField>> {
    let mut fields = Vec::new();
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
        collect_json_fields(&value, "", &mut fields);
    }
    if fields.len() < 2 {
        fields.clear();
        for part in text.split(['&', ';', '\n', ',']) {
            let part = part.trim().trim_matches(['{', '}', '[', ']']);
            let Some((name, value)) = part.split_once(['=', ':']) else {
                continue;
            };
            let name = name.trim().trim_matches(['"', '\'']);
            let value = value.trim().trim_matches(['"', '\'']);
            if name.is_empty() || value.is_empty() {
                continue;
            }
            let value = parse_configuration_value(value);
            fields.push(ConfigurationField {
                name: name.to_owned(),
                value,
            });
        }
    }
    (fields.len() >= 2).then_some(fields)
}

fn collect_json_fields(
    value: &serde_json::Value,
    prefix: &str,
    fields: &mut Vec<ConfigurationField>,
) {
    match value {
        serde_json::Value::Object(object) => {
            for (name, value) in object {
                let path = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}.{name}")
                };
                collect_json_fields(value, &path, fields);
            }
        }
        serde_json::Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                let path = format!("{prefix}[{index}]");
                collect_json_fields(value, &path, fields);
            }
        }
        serde_json::Value::String(value) => fields.push(ConfigurationField {
            name: prefix.to_owned(),
            value: ConfigurationValue::String(value.clone()),
        }),
        serde_json::Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                fields.push(ConfigurationField {
                    name: prefix.to_owned(),
                    value: ConfigurationValue::Integer(value),
                });
            }
        }
        _ => {}
    }
}

fn parse_configuration_value(value: &str) -> ConfigurationValue {
    let parsed = value
        .strip_prefix("0x")
        .and_then(|digits| i64::from_str_radix(digits, 16).ok())
        .or_else(|| value.parse::<i64>().ok());
    match parsed {
        Some(value) => ConfigurationValue::Integer(value),
        None => ConfigurationValue::String(value.to_owned()),
    }
}

pub(crate) fn comment(string: &DecodedString) -> String {
    let mut escaped = String::new();
    for character in string.text.chars() {
        match character {
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '/' => escaped.push_str("\\057"),
            _ => escaped.push(character),
        }
    }
    format!(" /* decoded at 0x{:x}: \"{escaped}\" */", string.site)
}

pub(crate) fn annotate(
    code: &mut String,
    strings: &[DecodedString],
    ir: &crate::ir::FunctionIr,
    symbols: &crate::render::Symbols,
) {
    let mut insertions = std::collections::BTreeMap::<usize, String>::new();
    let mut trailing = String::new();
    for string in strings {
        let mut position = None;
        if let Some(target) = string.target {
            let count = ir.blocks.iter().flat_map(|block| &block.stmts)
                .filter(|stmt| matches!(stmt, crate::ir::Stmt::Call { target: Some(address), .. } if *address == target)).count();
            let buffer = symbols
                .data
                .get(&string.addr)
                .map(|name| crate::render::sanitize(name));
            if count == 1 || buffer.is_some() {
                let name = symbols
                    .functions
                    .get(&target)
                    .or_else(|| symbols.import_slots.get(&target))
                    .map_or_else(
                        || format!("sub_{target:x}"),
                        |name| crate::render::sanitize(name),
                    );
                position = call_end(
                    code,
                    &name,
                    if count == 1 { None } else { buffer.as_deref() },
                );
            }
        }
        if let Some(position) = position {
            insertions
                .entry(position)
                .or_default()
                .push_str(&comment(string));
        } else {
            trailing.push_str(comment(string).trim_start());
            trailing.push('\n');
        }
    }
    for (position, text) in insertions.into_iter().rev() {
        code.insert_str(position, &text);
    }
    code.push_str(&trailing);
}

fn call_end(code: &str, name: &str, buffer: Option<&str>) -> Option<usize> {
    let bytes = code.as_bytes();
    let mut at = code.find("/* velk pseudo-C:").unwrap_or(code.len());
    let mut braces = 0usize;
    let mut parentheses = 0usize;
    let mut call_depth = None;
    let mut buffer_seen = false;
    let mut found = None;
    while at < bytes.len() {
        match bytes[at] {
            b'/' if bytes.get(at + 1) == Some(&b'*') => {
                let Some(end) = code[at + 2..].find("*/") else {
                    return None;
                };
                at += end + 4;
            }
            b'/' if bytes.get(at + 1) == Some(&b'/') => {
                at = code[at..]
                    .find('\n')
                    .map_or(bytes.len(), |end| at + end + 1);
            }
            quote @ (b'"' | b'\'') => {
                at += 1;
                while at < bytes.len() {
                    if bytes[at] == b'\\' {
                        at = at.saturating_add(2);
                    } else if bytes[at] == quote {
                        at += 1;
                        break;
                    } else {
                        at += 1;
                    }
                }
            }
            b'{' => {
                braces += 1;
                at += 1;
            }
            b'}' => {
                braces = braces.saturating_sub(1);
                at += 1;
            }
            b'(' => {
                parentheses += 1;
                at += 1;
            }
            b')' => {
                if call_depth == Some(parentheses) {
                    if (buffer.is_none() || buffer_seen) && found.replace(at + 1).is_some() {
                        return None;
                    }
                    call_depth = None;
                }
                parentheses = parentheses.saturating_sub(1);
                at += 1;
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = at;
                while at < bytes.len() && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_') {
                    at += 1;
                }
                if call_depth.is_some() && buffer == Some(&code[start..at]) {
                    buffer_seen = true;
                }
                if braces > 0 && &code[start..at] == name {
                    let mut next = at;
                    while bytes.get(next).is_some_and(u8::is_ascii_whitespace) {
                        next += 1;
                    }
                    if bytes.get(next) == Some(&b'(') {
                        call_depth = Some(parentheses + 1);
                        buffer_seen = false;
                    }
                }
            }
            _ => {
                at += 1;
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_requires_a_terminator_and_valid_printable_characters() {
        assert_eq!(decode_text(b"hello\0").unwrap().1, "hello");
        assert!(decode_text(b"hello").is_none());
        assert!(decode_text(b"abc\0").is_none());
        assert!(decode_text(b"ab\x01cd\0").is_none());
        assert!(decode_text(&[0xff, 0xff, 0xff, 0]).is_none());
        let wide: Vec<u8> = "wide sample\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(
            decode_text(&wide).unwrap(),
            ("utf16le", "wide sample".to_owned())
        );
        assert!(decode_text(&[0, 0xd8, 0, 0]).is_none());
    }

    #[test]
    fn call_locations_ignore_declarations_comments_and_literal_contents() {
        let code = "/* velk pseudo-C: f */\nint f(void) { /* decode(p) */ const char *s = \"decode(p)\"; return decode(p, (1 + 2)); }\n";
        let end = call_end(code, "decode", Some("p")).unwrap();
        assert_eq!(&code[..end], code.split_once("; }").unwrap().0);
        assert!(call_end(code, "decode", Some("q")).is_none());
        let repeated = "/* velk pseudo-C: f */ int f(void) { decode(p); decode(q); }";
        assert!(call_end(repeated, "decode", None).is_none());
        assert!(call_end(repeated, "decode", Some("p")).is_some());
    }

    #[test]
    fn configurations_extract_json_and_delimited_scalar_fields() {
        let decoded = |text: &str| DecodedString {
            addr: 1,
            function: 2,
            site: 3,
            decoder: 4,
            decoder_name: Some("decode".to_owned()),
            key: Some(93),
            stack: false,
            encoding: "utf8",
            text: text.to_owned(),
            target: None,
        };
        let results = configurations(&[
            decoded(r#"{"host":"example.test","port":443}"#),
            decoded("host=example.test;port=443;mode=fast"),
            decoded("ordinary decoded string"),
        ]);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].key, Some(93));
        assert_eq!(results[0].fields.len(), 2);
        assert_eq!(results[0].fields[0].name, "host");
        assert_eq!(results[0].fields[1].value, ConfigurationValue::Integer(443));
        assert_eq!(
            results[1].fields[0].value,
            ConfigurationValue::String("example.test".to_owned())
        );
        assert_eq!(results[1].fields[1].value, ConfigurationValue::Integer(443));
    }
}

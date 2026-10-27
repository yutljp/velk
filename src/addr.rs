#[must_use]
pub fn format(value: u64) -> String {
    format!("0x{value:x}")
}

/// Reads `0x`-prefixed hexadecimal or plain decimal.
#[must_use]
pub fn parse(text: &str) -> Option<u64> {
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(digits) => u64::from_str_radix(digits, 16).ok(),
        None if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) => text.parse().ok(),
        None => None,
    }
}

pub fn serialize<S: serde::Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&format(*value))
}

pub fn serialize_option<S: serde::Serializer>(
    value: &Option<u64>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => serialize(value, serializer),
        None => serializer.serialize_none(),
    }
}

pub fn deserialize<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    use serde::Deserialize;
    let text = match String::deserialize(deserializer) {
        Ok(text) => text,
        Err(error) => return Err(error),
    };
    match parse(&text) {
        Some(address) => Ok(address),
        None => Err(serde::de::Error::custom("invalid address")),
    }
}

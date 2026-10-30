//! Checked reads and checksums shared by UPX executable formats.

use super::DecodeError;

pub(super) fn slice(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], DecodeError> {
    let end = offset.checked_add(length);
    match end.and_then(|end| bytes.get(offset..end)) {
        Some(bytes) => Ok(bytes),
        None => Err(DecodeError::invalid(offset, "truncated UPX field or block")),
    }
}

pub(super) fn number(bytes: &[u8], offset: usize, length: usize) -> Result<usize, DecodeError> {
    let mut value = 0u64;
    let field_bytes = match slice(bytes, offset, length) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    for (index, byte) in field_bytes.iter().enumerate() {
        value |= u64::from(*byte) << (index * 8);
    }
    match usize::try_from(value) {
        Ok(value) => Ok(value),
        Err(_) => Err(DecodeError::invalid(
            offset,
            "UPX field does not fit an address",
        )),
    }
}

pub(super) struct Checksum {
    low: u32,
    high: u32,
}

impl Checksum {
    pub(super) fn new() -> Self {
        Self { low: 1, high: 0 }
    }

    pub(super) fn update(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(5552) {
            for byte in chunk {
                self.low += u32::from(*byte);
                self.high += self.low;
            }
            self.low %= 65521;
            self.high %= 65521;
        }
    }

    pub(super) fn value(&self) -> usize {
        ((self.high << 16) | self.low) as usize
    }
}

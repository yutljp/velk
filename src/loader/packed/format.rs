//! Checked reads and checksums shared by UPX executable formats.

use super::DecodeError;

/// The longest run of bytes whose sums cannot overflow before they are reduced.
const CHECKSUM_CHUNK: usize = 5552;

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
        for chunk in bytes.chunks(CHECKSUM_CHUNK) {
            for byte in chunk {
                self.add(*byte);
            }
            self.low %= 65521;
            self.high %= 65521;
        }
    }

    fn add(&mut self, byte: u8) {
        self.low += u32::from(byte);
        self.high += self.low;
    }

    pub(super) fn value(&self) -> usize {
        ((self.high << 16) | self.low) as usize
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(10)]
    fn field_reads() {
        let bytes: [u8; 8] = kani::any();
        let offset: usize = kani::any();
        let length: usize = kani::any();
        let in_range = offset
            .checked_add(length)
            .is_some_and(|end| end <= bytes.len());
        match slice(&bytes, offset, length) {
            Ok(field) => {
                kani::cover!(
                    length > 0 && offset + length == bytes.len(),
                    "a field ends at the input end"
                );
                assert!(in_range, "a field is returned only inside the input");
                assert_eq!(field, &bytes[offset..offset + length]);
            }
            Err(_) => {
                kani::cover!(
                    offset < bytes.len(),
                    "a field starting inside the input runs past it"
                );
                assert!(!in_range, "an in-range field is always returned")
            }
        }
        // Callers read fields of at most eight bytes.
        kani::assume(length <= 8);
        match number(&bytes, offset, length) {
            Ok(value) => {
                kani::cover!(length == 8, "an eight-byte number is read");
                let mut wide = [0; 8];
                wide[..length].copy_from_slice(&bytes[offset..offset + length]);
                assert_eq!(value as u64, u64::from_le_bytes(wide));
            }
            Err(_) => assert!(!in_range, "an in-range field always fits a 64-bit address"),
        }
    }

    // Induction over one chunk: before byte `index`, low is at most 65520 + 255 * index and
    // high at most 65520 * (index + 1) + 255 * index * (index + 1) / 2. Both bounds hold at the
    // start of a chunk, where low and high are reduced below 65521.
    #[kani::proof]
    fn checksum_chunk_cannot_overflow() {
        let index: u64 = kani::any();
        kani::assume(index < CHECKSUM_CHUNK as u64);
        let low: u32 = kani::any();
        let high: u32 = kani::any();
        kani::assume(u64::from(low) <= 65520 + 255 * index);
        kani::assume(u64::from(high) <= 65520 * (index + 1) + 255 * index * (index + 1) / 2);
        let mut checksum = Checksum { low, high };
        checksum.add(kani::any());
        kani::cover!(
            index + 1 == CHECKSUM_CHUNK as u64,
            "the last byte of a chunk is added"
        );
        let next = index + 1;
        assert!(u64::from(checksum.low) <= 65520 + 255 * next);
        assert!(u64::from(checksum.high) <= 65520 * (next + 1) + 255 * next * (next + 1) / 2);
    }
}

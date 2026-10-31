//! Bounded NRV decoding. A failed read invalidates the entire compressed block.

use super::DecodeError;

struct Bits<'input> {
    input: &'input [u8],
    position: usize,
    word: u32,
    remaining: u8,
    word_bytes: u8,
}

impl Bits<'_> {
    fn byte(&mut self) -> Result<u8, DecodeError> {
        let Some(&byte) = self.input.get(self.position) else {
            return Err(DecodeError::invalid(self.position, "truncated NRV stream"));
        };
        self.position += 1;
        Ok(byte)
    }

    fn bit(&mut self) -> Result<usize, DecodeError> {
        if self.remaining == 0 {
            self.word = 0;
            for index in 0..self.word_bytes {
                let byte = match self.byte() {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                self.word |= u32::from(byte) << (index * 8);
            }
            self.remaining = self.word_bytes * 8;
        }
        self.remaining -= 1;
        Ok(((self.word >> self.remaining) & 1) as usize)
    }

    fn extend(&mut self, value: usize, limit: usize) -> Result<usize, DecodeError> {
        let bit = match self.bit() {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        match value
            .checked_mul(2)
            .and_then(|value| value.checked_add(bit))
        {
            Some(value) if value <= limit => Ok(value),
            _ => Err(DecodeError::invalid(
                self.position,
                "NRV integer exceeds its limit",
            )),
        }
    }
}

/// Appends `length` bytes copied from `offset` bytes back, unless the source precedes the block
/// or the block would grow past `size`.
fn copy_match(output: &mut Vec<u8>, offset: usize, length: usize, size: usize) -> bool {
    if offset == 0 || offset > output.len() || length > size.saturating_sub(output.len()) {
        return false;
    }
    for _ in 0..length {
        output.push(output[output.len() - offset]);
    }
    true
}

pub(super) fn decode(input: &[u8], size: usize, method: u8) -> Result<Vec<u8>, DecodeError> {
    if !matches!(method, 2 | 3 | 5 | 6 | 8 | 9) {
        return Err(DecodeError::Unsupported(format!("NRV method {method}")));
    }
    if size > super::MAX_FILE_SIZE as usize {
        return Err(DecodeError::invalid(0, "NRV output exceeds 128 MiB"));
    }
    let word_bytes = if matches!(method, 3 | 6 | 9) { 1 } else { 4 };
    let method = if word_bytes == 1 { method - 1 } else { method };
    let mut bits = Bits {
        input,
        position: 0,
        word: 0,
        remaining: 0,
        word_bytes,
    };
    let mut output = Vec::new();
    let mut previous = 1;
    loop {
        loop {
            let bit = match bits.bit() {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            if bit == 0 {
                break;
            }

            if output.len() == size {
                return Err(DecodeError::invalid(bits.position, "too many NRV literals"));
            }
            let literal = match bits.byte() {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            output.push(literal);
        }
        let mut offset = 1;
        loop {
            offset = match bits.extend(offset, 0x1000002) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let bit = match bits.bit() {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            if bit != 0 {
                break;
            }
            if method != 2 {
                offset = match bits.extend(offset - 1, 0x1000002) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
            }
        }
        let mut length;
        if offset == 2 {
            offset = previous;
            length = match bits.bit() {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
        } else {
            let byte = match bits.byte() {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            offset = (offset - 3) * 256 + usize::from(byte);
            if offset == 0xffffffff {
                break;
            }
            if method != 2 {
                length = (!offset) & 1;
                offset >>= 1;
            } else {
                length = match bits.bit() {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
            }
            offset += 1;
            previous = offset;
        }
        if method == 8 {
            if length != 0 {
                let bit = match bits.bit() {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                length = 1 + bit;
            } else {
                let flag = match bits.bit() {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if flag != 0 {
                    let bit = match bits.bit() {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    length = 3 + bit;
                } else {
                    length = 1;
                    loop {
                        length = match bits.extend(length, size) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        };
                        let bit = match bits.bit() {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        };
                        if bit != 0 {
                            break;
                        }
                    }
                    length += 3;
                }
            }
        } else {
            let bit = match bits.bit() {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            length = length * 2 + bit;
            if length == 0 {
                length = 1;
                loop {
                    length = match bits.extend(length, size) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    let bit = match bits.bit() {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    if bit != 0 {
                        break;
                    }
                }
                length += 2;
            }
        }
        let threshold = if method == 2 { 0xd00 } else { 0x500 };
        length += usize::from(offset > threshold) + 1;
        if !copy_match(&mut output, offset, length, size) {
            return Err(DecodeError::invalid(
                bits.position,
                "invalid NRV match distance or length",
            ));
        }
    }
    if output.len() != size || bits.position != input.len() {
        return Err(DecodeError::invalid(
            bits.position,
            "NRV size or end marker mismatch",
        ));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_and_truncated_streams_never_exceed_the_output_limit() {
        let mut state = 0x918fb2c4u32;
        let mut input = [0u8; 128];
        for iteration in 0..32768 {
            for byte in &mut input {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *byte = state as u8;
            }
            let length = iteration % (input.len() + 1);
            let size = (state & 4095) as usize;
            for method in [2, 3, 5, 6, 8, 9] {
                if let Ok(output) = decode(&input[..length], size, method) {
                    assert_eq!(output.len(), size);
                }
                assert!(decode(&input[..length], usize::MAX, method).is_err());
            }
        }
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    // One step from any reachable reader state: a word is refilled only when no bits remain.
    #[kani::proof]
    #[kani::unwind(6)]
    fn bit_reads() {
        let input: [u8; 4] = kani::any();
        let word_bytes: u8 = if kani::any() { 1 } else { 4 };
        let remaining: u8 = kani::any();
        kani::assume(remaining <= word_bytes * 8);
        let position: usize = kani::any();
        kani::assume(position <= input.len());
        let mut bits = Bits {
            input: &input,
            position,
            word: kani::any(),
            remaining,
            word_bytes,
        };
        if let Ok(bit) = bits.bit() {
            assert!(bit <= 1);
            assert!(bits.remaining < word_bytes * 8);
        }
        assert!(bits.position <= input.len());
        let value: usize = kani::any();
        let limit: usize = kani::any();
        if let Ok(extended) = bits.extend(value, limit) {
            assert!(
                extended <= limit,
                "an extended integer never exceeds its limit"
            );
        }
    }

    #[kani::proof]
    #[kani::unwind(8)]
    fn match_copies() {
        let start: [u8; 4] = kani::any();
        let length: usize = kani::any();
        kani::assume(length <= start.len());
        let mut output = start[..length].to_vec();
        let offset: usize = kani::any();
        let count: usize = kani::any();
        let size: usize = kani::any();
        kani::assume(size <= 6);
        // Decode stops adding literals once the block reaches its size.
        kani::assume(length <= size);
        if copy_match(&mut output, offset, count, size) {
            assert!(output.len() == length + count && output.len() <= size);
            for index in length..output.len() {
                assert!(output[index] == output[index - offset]);
            }
        } else {
            assert!(
                output[..] == start[..length],
                "a rejected match leaves the block unchanged"
            );
        }
    }
}

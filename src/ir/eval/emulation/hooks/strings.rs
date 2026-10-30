//! C string operations and integer conversions used by library hooks.

use super::{CallKind, Convention, HEAP_SIZE, Hook, Runner, Stop};

impl Runner<'_> {
    // Argument and memory failures abort the call rather than guessing a result.
    pub(super) fn scalar_string_hook(
        &mut self,
        hook: Hook,
        first: u64,
        convention: Convention,
        kind: CallKind,
    ) -> Result<u64, Stop> {
        if matches!(
            hook,
            Hook::FindByteReverse | Hook::FindSubstring | Hook::Duplicate | Hook::DuplicateN
        ) {
            return self.extended_string_hook(hook, first, convention, kind);
        }
        if matches!(
            hook,
            Hook::Integer
                | Hook::LongInteger
                | Hook::IntegerEnd
                | Hook::LongLongIntegerEnd
                | Hook::UnsignedIntegerEnd
                | Hook::UnsignedLongLongIntegerEnd
        ) {
            return self.integer_string_hook(hook, first, convention, kind);
        }
        let second = if matches!(hook, Hook::Integer) {
            0
        } else {
            match self.argument(1, convention, kind) {
                Ok(value) => value,
                Err(error) => return Err(error),
            }
        };
        let source = if matches!(hook, Hook::StringCopyN) {
            second
        } else {
            first
        };
        let maximum = if matches!(hook, Hook::StringCopyN) {
            match self.argument(2, convention, kind) {
                Ok(value) => value,
                Err(error) => return Err(error),
            }
        } else if matches!(hook, Hook::LengthN) {
            second
        } else {
            HEAP_SIZE
        };
        if maximum > HEAP_SIZE {
            return Err(Stop::Error("string operation exceeds 16 MiB".into()));
        }
        let mut ended = false;
        let mut found_character = None;
        for offset in 0..maximum {
            let Some(address) = source.checked_add(offset) else {
                return Err(Stop::Error("string address overflows".into()));
            };
            let byte = if ended {
                0
            } else {
                match self.read_byte(address) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                }
            };
            if matches!(hook, Hook::Character | Hook::ReverseCharacter) && byte == second as u8 {
                if matches!(hook, Hook::Character) {
                    return Ok(address);
                }
                found_character = Some(address);
            }
            if matches!(hook, Hook::StringCopyN) {
                let Some(destination) = first.checked_add(offset) else {
                    return Err(Stop::Error("string destination overflows".into()));
                };
                if let Err(error) = self.write_byte(destination, byte) {
                    return Err(error);
                }
            }
            if byte == 0 {
                if matches!(hook, Hook::LengthN) {
                    return Ok(offset);
                }
                if matches!(hook, Hook::Character | Hook::ReverseCharacter) {
                    return Ok(found_character.unwrap_or(0));
                }
                ended = true;
            }
        }
        if matches!(hook, Hook::Character | Hook::ReverseCharacter) && !ended {
            return Err(Stop::Error("string exceeds 16 MiB".into()));
        }
        Ok(if matches!(hook, Hook::StringCopyN) {
            first
        } else if matches!(hook, Hook::Character | Hook::ReverseCharacter) {
            found_character.unwrap_or(0)
        } else {
            maximum
        })
    }

    fn extended_string_hook(
        &mut self,
        hook: Hook,
        first: u64,
        convention: Convention,
        kind: CallKind,
    ) -> Result<u64, Stop> {
        if matches!(hook, Hook::FindByteReverse) {
            let argument = match self.argument(1, convention, kind) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let character = argument as u8;
            let count = match self.argument(2, convention, kind) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            if count > HEAP_SIZE {
                return Err(Stop::Error("memory search exceeds 16 MiB".into()));
            }
            let mut found = None;
            for offset in 0..count {
                let Some(address) = first.checked_add(offset) else {
                    return Err(Stop::Error("memory search address overflows".into()));
                };
                let byte = match self.read_byte(address) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if byte == character {
                    found = Some(address);
                }
            }
            return Ok(found.unwrap_or(0));
        }
        if matches!(hook, Hook::FindSubstring) {
            let needle = match self.argument(1, convention, kind) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let mut needle_bytes = Vec::new();
            let mut needle_ended = false;
            for offset in 0..HEAP_SIZE {
                let Some(address) = needle.checked_add(offset) else {
                    return Err(Stop::Error("substring address overflows".into()));
                };
                let byte = match self.read_byte(address) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if byte == 0 {
                    needle_ended = true;
                    break;
                }
                needle_bytes.push(byte);
            }
            if !needle_ended {
                return Err(Stop::Error("substring needle exceeds 16 MiB".into()));
            }
            if needle_bytes.is_empty() {
                return Ok(first);
            }
            for offset in 0..HEAP_SIZE {
                let Some(address) = first.checked_add(offset) else {
                    return Err(Stop::Error("substring address overflows".into()));
                };
                let byte = match self.read_byte(address) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if byte == 0 {
                    return Ok(0);
                }
                if byte == needle_bytes[0] {
                    let mut matched = true;
                    let remaining_needle_bytes = needle_bytes.iter().enumerate().skip(1);
                    for (index, expected) in remaining_needle_bytes {
                        let Some(candidate) = address.checked_add(index as u64) else {
                            return Err(Stop::Error("substring address overflows".into()));
                        };
                        let candidate_byte = match self.read_byte(candidate) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        };
                        if candidate_byte == 0 || candidate_byte != *expected {
                            matched = false;
                            break;
                        }
                    }
                    if matched {
                        return Ok(address);
                    }
                }
            }
            return Err(Stop::Error("string exceeds 16 MiB".into()));
        }
        let requested_limit = if matches!(hook, Hook::DuplicateN) {
            match self.argument(1, convention, kind) {
                Ok(value) => value,
                Err(error) => return Err(error),
            }
        } else {
            HEAP_SIZE
        };
        let limit = requested_limit.min(HEAP_SIZE);
        let mut bytes = Vec::new();
        let mut string_ended = false;
        for offset in 0..limit {
            let Some(address) = first.checked_add(offset) else {
                return Err(Stop::Error("string address overflows".into()));
            };
            let byte = match self.read_byte(address) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            if byte == 0 {
                string_ended = true;
                break;
            }
            bytes.push(byte);
        }
        if !string_ended && (matches!(hook, Hook::Duplicate) || requested_limit > HEAP_SIZE) {
            return Err(Stop::Error("string exceeds 16 MiB".into()));
        }
        let address = self.allocate(bytes.len() as u64 + 1);
        if address == 0 {
            return Ok(0);
        }
        let terminated_bytes = bytes.iter().copied().chain([0]).enumerate();
        for (offset, byte) in terminated_bytes {
            let Some(destination) = address.checked_add(offset as u64) else {
                return Err(Stop::Error("string destination overflows".into()));
            };
            if let Err(error) = self.write_byte(destination, byte) {
                return Err(error);
            }
        }
        Ok(address)
    }

    fn integer_string_hook(
        &mut self,
        hook: Hook,
        first: u64,
        convention: Convention,
        kind: CallKind,
    ) -> Result<u64, Stop> {
        let end_pointer = matches!(
            hook,
            Hook::IntegerEnd
                | Hook::LongLongIntegerEnd
                | Hook::UnsignedIntegerEnd
                | Hook::UnsignedLongLongIntegerEnd
        );
        let end_address = if end_pointer {
            match self.argument(1, convention, kind) {
                Ok(value) => value,
                Err(error) => return Err(error),
            }
        } else {
            0
        };
        let requested_base = if end_pointer {
            match self.argument(2, convention, kind) {
                Ok(value) => value,
                Err(error) => return Err(error),
            }
        } else {
            10
        };
        if requested_base != 0 && !(2..=36).contains(&requested_base) {
            return Err(Stop::Error(format!(
                "integer conversion base {requested_base} is outside 0..=36 or 2..=36"
            )));
        }
        let mut bytes = Vec::new();
        let mut ended = false;
        for offset in 0..HEAP_SIZE {
            let Some(address) = first.checked_add(offset) else {
                return Err(Stop::Error("integer string address overflows".into()));
            };
            let byte = match self.read_byte(address) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            if byte == 0 {
                ended = true;
                break;
            }
            bytes.push(byte);
        }
        if !ended {
            return Err(Stop::Error("integer string exceeds 16 MiB".into()));
        }
        let mut position = 0;
        while bytes.get(position).is_some_and(u8::is_ascii_whitespace) {
            position += 1;
        }
        let negative = bytes.get(position) == Some(&b'-');
        if negative || bytes.get(position) == Some(&b'+') {
            position += 1;
        }
        let mut base = requested_base;
        let has_hex_prefix = bytes.get(position) == Some(&b'0')
            && matches!(bytes.get(position + 1), Some(b'x' | b'X'))
            && bytes
                .get(position + 2)
                .and_then(|byte| digit_value(*byte))
                .is_some_and(|digit| digit < 16);
        if base == 0 {
            if has_hex_prefix {
                base = 16;
            } else if bytes.get(position) == Some(&b'0') {
                base = 8;
            } else {
                base = 10;
            }
        }
        if base == 16 && has_hex_prefix {
            position += 2;
        }
        let digit_start = position;
        let unsigned = matches!(
            hook,
            Hook::UnsignedIntegerEnd | Hook::UnsignedLongLongIntegerEnd
        );
        let bits = match hook {
            Hook::Integer => 32,
            Hook::LongInteger | Hook::IntegerEnd | Hook::UnsignedIntegerEnd
                if matches!(
                    self.image.format,
                    crate::loader::Format::Pe | crate::loader::Format::Coff
                ) =>
            {
                32
            }
            Hook::LongInteger | Hook::IntegerEnd | Hook::UnsignedIntegerEnd => {
                u32::from(crate::arch::pointer_bytes(self.image.isa)) * 8
            }
            Hook::LongLongIntegerEnd | Hook::UnsignedLongLongIntegerEnd => 64,
            _ => 64,
        };
        let sign_bit = 1u64 << (bits - 1);
        let limit = if unsigned {
            if bits == 64 {
                u64::MAX
            } else {
                (1u64 << bits) - 1
            }
        } else if negative {
            sign_bit
        } else {
            sign_bit - 1
        };
        let mut value = 0u64;
        let mut overflow = false;
        while let Some(&byte) = bytes.get(position) {
            let Some(digit) = digit_value(byte) else {
                break;
            };
            if digit >= base {
                break;
            }
            let next = u128::from(value) * u128::from(base) + u128::from(digit);
            if next > u128::from(limit) {
                overflow = true;
                value = limit;
            } else {
                value = next as u64;
            }
            position += 1;
        }
        if end_pointer && end_address != 0 {
            let consumed = if position > digit_start { position } else { 0 };
            let Some(address) = first.checked_add(consumed as u64) else {
                return Err(Stop::Error("integer end address overflows".into()));
            };
            self.machine.store(
                end_address,
                address,
                crate::arch::pointer_bytes(self.image.isa),
            );
            if let Err(error) = self.memory_error() {
                return Err(error);
            }
        }
        if position == digit_start {
            return Ok(0);
        }
        if overflow
            && end_pointer
            && let Err(error) = self.set_errno(34)
        {
            return Err(error);
        }
        if overflow {
            return Ok(limit);
        }
        let result = if unsigned {
            if negative {
                value.wrapping_neg() & limit
            } else {
                value
            }
        } else if negative {
            value.wrapping_neg()
        } else {
            value
        };
        Ok(if bits < 64 {
            result & ((1u64 << bits) - 1)
        } else {
            result
        })
    }
}

fn digit_value(byte: u8) -> Option<u64> {
    match byte {
        b'0'..=b'9' => Some(u64::from(byte - b'0')),
        b'a'..=b'z' => Some(u64::from(byte - b'a' + 10)),
        b'A'..=b'Z' => Some(u64::from(byte - b'A' + 10)),
        _ => None,
    }
}

//! Bounded scanf integer, character and string conversions.

use super::{Arguments, Runner, Stop, error};

impl Runner<'_> {
    // A bad format, argument or destination invalidates the entire hook.
    pub(super) fn scan_input(
        &mut self,
        format: &[u8],
        input: &[u8],
        args: &mut Arguments,
    ) -> Result<(u64, usize), Stop> {
        let mut position = 0;
        let mut consumed = 0;
        let mut assignments = 0;
        let mut conversions = 0;
        let mut input_failure = false;
        let pointer_bytes = crate::arch::pointer_bytes(self.image.isa);
        while position < format.len() {
            if let Err(error) = self.tick() {
                return Err(error);
            }
            let byte = format[position];
            position += 1;
            if byte.is_ascii_whitespace() {
                while input.get(consumed).is_some_and(u8::is_ascii_whitespace) {
                    if let Err(error) = self.tick() {
                        return Err(error);
                    }
                    consumed += 1;
                }
                continue;
            }
            if byte != b'%' || format.get(position) == Some(&b'%') {
                if byte == b'%' {
                    position += 1;
                }
                if input.get(consumed) != Some(&byte) {
                    input_failure = consumed == input.len();
                    break;
                }
                consumed += 1;
                continue;
            }
            let start = position - 1;
            let suppress = format.get(position) == Some(&b'*');
            if suppress {
                position += 1;
            }
            let mut width = 0usize;
            while let Some(digit @ b'0'..=b'9') = format.get(position) {
                let Some(next) = width
                    .checked_mul(10)
                    .and_then(|width| width.checked_add((digit - b'0') as usize))
                    .filter(|width| *width <= super::HEAP_SIZE as usize)
                else {
                    return Err(error("scanf width exceeds 16 MiB"));
                };
                width = next;
                position += 1;
            }
            let length_start = position;
            while matches!(
                format.get(position),
                Some(b'h' | b'l' | b'z' | b't' | b'j' | b'L')
            ) {
                position += 1;
            }
            let length = &format[length_start..position];
            let Some(&conversion) = format.get(position) else {
                return Err(error("unsupported scanf specifier: trailing %"));
            };
            position += 1;
            if !matches!(
                conversion,
                b'd' | b'i' | b'u' | b'x' | b'X' | b'o' | b'c' | b's'
            ) || (matches!(conversion, b'c' | b's') && !length.is_empty())
            {
                return Err(error(format!(
                    "unsupported scanf specifier {}",
                    String::from_utf8_lossy(&format[start..position])
                )));
            }
            if conversion != b'c' {
                while input.get(consumed).is_some_and(u8::is_ascii_whitespace) {
                    if let Err(error) = self.tick() {
                        return Err(error);
                    }
                    consumed += 1;
                }
            }
            if consumed == input.len() {
                input_failure = true;
                break;
            }
            let maximum = if width == 0 {
                if conversion == b'c' {
                    1
                } else {
                    input.len() - consumed
                }
            } else {
                width
            };
            let end = consumed.saturating_add(maximum).min(input.len());
            let mut bytes = Vec::new();
            if matches!(conversion, b'c' | b's') {
                while consumed < end
                    && (conversion == b'c' || !input[consumed].is_ascii_whitespace())
                {
                    if let Err(error) = self.tick() {
                        return Err(error);
                    }
                    bytes.push(input[consumed]);
                    consumed += 1;
                }
                if conversion == b's' {
                    bytes.push(0);
                }
            } else {
                let negative = input.get(consumed) == Some(&b'-');
                if matches!(input.get(consumed), Some(b'+' | b'-')) {
                    consumed += 1;
                }
                let mut radix = match conversion {
                    b'x' | b'X' => 16,
                    b'o' => 8,
                    _ => 10,
                };
                if conversion == b'i' && input.get(consumed) == Some(&b'0') {
                    radix = 8;
                }
                if (matches!(conversion, b'i' | b'x' | b'X'))
                    && consumed + 1 < end
                    && input[consumed] == b'0'
                    && matches!(input[consumed + 1], b'x' | b'X')
                {
                    consumed += 2;
                    radix = 16;
                }
                let digit_start = consumed;
                let mut value = 0u64;
                while consumed < end {
                    let Some(digit) = (input[consumed] as char).to_digit(radix) else {
                        break;
                    };
                    if let Err(error) = self.tick() {
                        return Err(error);
                    }
                    let Some(next) = value
                        .checked_mul(u64::from(radix))
                        .and_then(|value| value.checked_add(u64::from(digit)))
                    else {
                        return Err(error("scanf integer exceeds 64 bits"));
                    };
                    value = next;
                    consumed += 1;
                }
                if consumed == digit_start {
                    break;
                }
                if negative {
                    value = value.wrapping_neg();
                }
                let width = match super::formatting::integer_width(
                    length,
                    pointer_bytes,
                    matches!(
                        self.image.format,
                        crate::loader::Format::Pe | crate::loader::Format::Coff
                    ),
                ) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                bytes.extend_from_slice(&value.to_le_bytes()[..width as usize]);
            }
            conversions += 1;
            if !suppress {
                let destination = match args.next(self, pointer_bytes) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if let Err(error) = self.store_bytes(destination, &bytes) {
                    return Err(error);
                }
                assignments += 1;
            }
        }
        Ok((
            if assignments == 0 && conversions == 0 && input_failure {
                u64::from(u32::MAX)
            } else {
                assignments
            },
            consumed,
        ))
    }
}

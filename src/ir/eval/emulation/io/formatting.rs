//! Integer and string printf conversions for the target data model.

use super::{Arguments, HEAP_SIZE, Runner, Stop, error};

#[derive(Default)]
struct Format {
    left: bool,
    plus: bool,
    space: bool,
    alternate: bool,
    zero: bool,
    width: usize,
    precision: Option<usize>,
    length: Vec<u8>,
}

fn number(format: &[u8], position: &mut usize) -> Result<usize, Stop> {
    let mut value = 0usize;
    while let Some(byte @ b'0'..=b'9') = format.get(*position) {
        let Some(next) = value
            .checked_mul(10)
            .and_then(|value| value.checked_add((byte - b'0') as usize))
            .filter(|value| *value <= HEAP_SIZE as usize)
        else {
            return Err(error("format width or precision exceeds 16 MiB"));
        };
        value = next;
        *position += 1;
    }
    Ok(value)
}

pub(super) fn integer_width(length: &[u8], pointer: u8, windows: bool) -> Result<u8, Stop> {
    match length {
        b"hh" => Ok(1),
        b"h" => Ok(2),
        b"" => Ok(4),
        b"l" => Ok(if windows { 4 } else { pointer }),
        b"ll" | b"j" => Ok(8),
        b"z" | b"t" => Ok(pointer),
        _ => Err(error(format!(
            "unsupported format length {}",
            String::from_utf8_lossy(length)
        ))),
    }
}

fn signed_magnitude(value: u64, bits: u8) -> u64 {
    let signed = (value << (64 - bits)) as i64 >> (64 - bits);
    signed.unsigned_abs()
}

impl Runner<'_> {
    // Any unsupported conversion or failed argument read invalidates the entire output hook.
    pub(super) fn format_output(
        &mut self,
        format: &[u8],
        args: &mut Arguments,
    ) -> Result<Vec<u8>, Stop> {
        let pointer_bytes = crate::arch::pointer_bytes(self.image.isa);
        let windows = matches!(
            self.image.format,
            crate::loader::Format::Pe | crate::loader::Format::Coff
        );
        let mut output = Vec::new();
        let mut position = 0;
        while position < format.len() {
            if let Err(error) = self.tick() {
                return Err(error);
            }
            if format[position] != b'%' {
                output.push(format[position]);
                position += 1;
                continue;
            }
            let start = position;
            position += 1;
            if format.get(position) == Some(&b'%') {
                output.push(b'%');
                position += 1;
                continue;
            }
            let mut spec = Format::default();
            loop {
                match format.get(position) {
                    Some(b'-') => spec.left = true,
                    Some(b'+') => spec.plus = true,
                    Some(b' ') => spec.space = true,
                    Some(b'#') => spec.alternate = true,
                    Some(b'0') => spec.zero = true,
                    _ => break,
                }
                position += 1;
            }
            if format.get(position) == Some(&b'*') {
                let argument = match args.next(self, 4) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let width = argument as u32 as i32;
                spec.left |= width < 0;
                spec.width = width.unsigned_abs() as usize;
                position += 1;
            } else {
                spec.width = match number(format, &mut position) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
            }
            if format.get(position) == Some(&b'.') {
                position += 1;
                if format.get(position) == Some(&b'*') {
                    let argument = match args.next(self, 4) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    let precision = argument as u32 as i32;
                    if precision >= 0 {
                        spec.precision = Some(precision as usize);
                    }
                    position += 1;
                } else {
                    let precision = match number(format, &mut position) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    spec.precision = Some(precision);
                }
            }
            while let Some(byte @ (b'h' | b'l' | b'z' | b't' | b'j' | b'L')) = format.get(position)
            {
                spec.length.push(*byte);
                position += 1;
            }
            let Some(&conversion) = format.get(position) else {
                return Err(error("unsupported format specifier: trailing %"));
            };
            position += 1;
            if !matches!(
                conversion,
                b'd' | b'i' | b'u' | b'x' | b'X' | b'o' | b'c' | b's' | b'p'
            ) || (matches!(conversion, b'c' | b's' | b'p') && !spec.length.is_empty())
            {
                return Err(error(format!(
                    "unsupported format specifier {}",
                    String::from_utf8_lossy(&format[start..position])
                )));
            }
            if spec.width > HEAP_SIZE as usize
                || spec
                    .precision
                    .is_some_and(|precision| precision > HEAP_SIZE as usize)
            {
                return Err(error("format width or precision exceeds 16 MiB"));
            }
            let mut prefix = Vec::new();
            let mut formatted_value = Vec::new();
            let numeric = !matches!(conversion, b's' | b'c');
            if conversion == b's' {
                let base = match args.next(self, pointer_bytes) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if let Some(precision) = spec.precision {
                    for offset in 0..precision {
                        let item_address = match super::address(base, offset) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        };
                        let byte = match self.read_byte(item_address) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        };
                        if byte == 0 {
                            break;
                        }
                        formatted_value.push(byte);
                    }
                } else {
                    formatted_value = match self.bytes_at(base, None) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                }
            } else if conversion == b'c' {
                let argument = match args.next(self, 4) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                formatted_value.push(argument as u8);
            } else {
                let width = if conversion == b'p' {
                    pointer_bytes
                } else {
                    match integer_width(&spec.length, pointer_bytes, windows) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    }
                };
                let raw = match args.next(self, width.max(4)) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let bits = width * 8;
                let value = if bits == 64 {
                    raw
                } else {
                    raw & ((1u64 << bits) - 1)
                };
                let signed = matches!(conversion, b'd' | b'i');
                let negative = signed && value & (1u64 << (bits - 1)) != 0;
                let absolute = if negative {
                    signed_magnitude(value, bits)
                } else {
                    value
                };
                if negative {
                    prefix.push(b'-');
                } else if signed && spec.plus {
                    prefix.push(b'+');
                } else if signed && spec.space {
                    prefix.push(b' ');
                }
                let text = match conversion {
                    b'x' | b'p' => format!("{absolute:x}"),
                    b'X' => format!("{absolute:X}"),
                    b'o' => format!("{absolute:o}"),
                    _ => absolute.to_string(),
                };
                formatted_value = text.into_bytes();
                if value == 0 && spec.precision == Some(0) {
                    formatted_value.clear();
                }
                if conversion == b'p' {
                    if value == 0 {
                        // The modeled libc uses the common Linux null-pointer spelling.
                        formatted_value = b"(nil)".to_vec();
                        spec.zero = false;
                        spec.precision = None;
                    } else {
                        prefix.extend_from_slice(b"0x");
                    }
                } else if spec.alternate && value != 0 && matches!(conversion, b'x' | b'X') {
                    prefix.extend_from_slice(if conversion == b'X' { b"0X" } else { b"0x" });
                }
                if conversion == b'o'
                    && spec.alternate
                    && formatted_value.first() != Some(&b'0')
                    && spec.precision.unwrap_or(0) <= formatted_value.len()
                {
                    prefix.push(b'0');
                }
            }
            let zeros = if numeric {
                spec.precision
                    .unwrap_or(0)
                    .saturating_sub(formatted_value.len())
            } else {
                0
            };
            let padding = spec
                .width
                .saturating_sub(prefix.len() + zeros + formatted_value.len());
            let total = prefix
                .len()
                .saturating_add(zeros)
                .saturating_add(formatted_value.len())
                .saturating_add(padding);
            if output.len().saturating_add(total) > HEAP_SIZE as usize {
                return Err(error("formatted output exceeds 16 MiB"));
            }
            let zero_padding = numeric && spec.zero && !spec.left && spec.precision.is_none();
            if !spec.left && !zero_padding {
                output.resize(output.len() + padding, b' ');
            }
            output.extend_from_slice(&prefix);
            if zero_padding {
                output.resize(output.len() + padding, b'0');
            }
            output.resize(output.len() + zeros, b'0');
            output.extend_from_slice(&formatted_value);
            if spec.left {
                output.resize(output.len() + padding, b' ');
            }
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::smt::{self, Proofs};

    #[test]
    fn smt_signed_magnitude_matches_target_integer_width() {
        if !Proofs::available() {
            return;
        }
        let mut proofs = Proofs::default();
        for bits in [8, 16, 32, 64] {
            for value in [0, 1, 127, 128, 255, 0x8000, 0x8000_0000, 1 << 63, u64::MAX] {
                let signed = smt::signed("r0", u32::from(bits));
                let shift = smt::constant(u64::from(64 - bits));
                let actual = format!("(bvashr (bvshl r0 {shift}) {shift})");
                let absolute = format!(
                    "(ite (bvslt {actual} {}) (bvneg {actual}) {actual})",
                    smt::constant(0)
                );
                let expected = format!(
                    "(ite (bvslt {signed} {}) (bvneg {signed}) {signed})",
                    smt::constant(0)
                );
                proofs.predicate(
                    format!("magnitude template {bits}"),
                    &format!("(= {absolute} {expected})"),
                    "true",
                );
                proofs.predicate(
                    format!("magnitude instance {bits} {value}"),
                    &format!(
                        "(=> (= r0 {}) (= {absolute} {}))",
                        smt::constant(value),
                        smt::constant(signed_magnitude(value, bits))
                    ),
                    "true",
                );
            }
        }
        proofs.check();
    }
}

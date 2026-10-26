//! Scalar decoding of exception-table values.

pub(super) fn uleb(mut take: impl FnMut(u64) -> Option<u64>) -> Option<u64> {
    let mut value = 0;
    for shift in (0..64).step_by(7) {
        let Some(byte) = take(1) else {
            return None;
        };
        if shift == 63 && byte > 1 {
            return None;
        }
        value |= (byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

pub(super) fn sleb(mut take: impl FnMut(u64) -> Option<u64>) -> Option<i64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let Some(byte) = take(1) else {
            return None;
        };
        if shift == 63 && byte != 0 && byte != 0x7f {
            return None;
        }
        value |= (byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            if byte & 0x40 != 0 && shift < 63 {
                value |= u64::MAX << (shift + 7);
            }
            return Some(value as i64);
        }
    }
    None
}

pub(super) fn encoded(
    encoding: u8,
    place: u64,
    pointer_bytes: u8,
    mut take: impl FnMut(u64) -> Option<u64>,
) -> Option<u64> {
    let value = match encoding & 0x0f {
        0 => take(u64::from(pointer_bytes)),
        1 => uleb(&mut take),
        2 => take(2),
        3 => take(4),
        4 | 12 => take(8),
        9 => sleb(&mut take).map(|value| value as u64),
        10 => take(2).map(|value| value as i16 as i64 as u64),
        11 => take(4).map(|value| value as i32 as i64 as u64),
        _ => None,
    };
    let Some(value) = value else {
        return None;
    };
    if value == 0 {
        return Some(0);
    }
    match encoding & 0x70 {
        0 => Some(value),
        0x10 if encoding & 0x08 != 0 => place.checked_add_signed(value as i64),
        0x10 => place.checked_add(value),
        _ => None,
    }
}

#[cfg(kani)]
mod proofs;

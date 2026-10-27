//! Byte-slice inputs for the scalar exception-table decoder.

struct Bytes<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Bytes<'_> {
    fn take(&mut self, size: u64) -> Option<u64> {
        let Some(end) = self.at.checked_add(size as usize) else {
            return None;
        };
        let Some(bytes) = self.bytes.get(self.at..end) else {
            return None;
        };
        let mut value = [0; 8];
        value[..bytes.len()].copy_from_slice(bytes);
        self.at = end;
        Some(u64::from_le_bytes(value))
    }
}

#[kani::proof]
#[kani::unwind(12)]
fn leb_readers() {
    let bytes: [u8; 10] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    let mut reader = Bytes {
        bytes: &bytes[..len],
        at: 0,
    };
    let unsigned = super::uleb(|size| reader.take(size));
    assert!(reader.at <= len);
    if unsigned.is_some() {
        assert!(reader.at > 0 && reader.at <= 10);
    }
    let end = bytes[..len].iter().position(|byte| byte & 0x80 == 0);
    let mut wide = 0u128;
    if let Some(end) = end {
        for (index, byte) in bytes[..=end].iter().enumerate() {
            wide |= u128::from(byte & 0x7f) << (7 * index);
        }
        assert_eq!(unsigned, u64::try_from(wide).ok());
        assert_eq!(reader.at, end + 1);
    } else {
        assert_eq!(unsigned, None);
    }
    kani::cover!(
        unsigned == Some(u64::MAX),
        "a ten-byte unsigned maximum is decoded"
    );
    kani::cover!(
        len == 10 && bytes[9] == 2 && unsigned.is_none(),
        "an overflowing unsigned LEB is rejected"
    );
    reader.at = 0;
    let signed = super::sleb(|size| reader.take(size));
    assert!(reader.at <= len);
    if signed.is_some() {
        assert!(reader.at > 0 && reader.at <= 10);
    }
    if let Some(end) = end {
        let expected = if bytes[end] & 0x40 == 0 {
            wide as i128
        } else {
            wide as i128 - (1i128 << (7 * (end + 1)))
        };
        assert_eq!(signed, i64::try_from(expected).ok());
        assert_eq!(reader.at, end + 1);
    } else {
        assert_eq!(signed, None);
    }
    kani::cover!(
        signed == Some(i64::MIN),
        "a ten-byte signed minimum is decoded"
    );
    kani::cover!(
        len == 9 && end.is_none(),
        "a truncated continuation sequence is rejected"
    );
}

#[kani::proof]
#[kani::unwind(12)]
fn leb_round_trip() {
    let value: u64 = kani::any();
    let mut bytes = [0u8; 10];
    let mut remaining = value;
    let mut len = 0;
    loop {
        let byte = (remaining & 0x7f) as u8;
        remaining >>= 7;
        bytes[len] = byte | if remaining != 0 { 0x80 } else { 0 };
        len += 1;
        if remaining == 0 {
            break;
        }
    }
    let mut reader = Bytes {
        bytes: &bytes[..len],
        at: 0,
    };
    assert_eq!(super::uleb(|size| reader.take(size)), Some(value));
    assert_eq!(reader.at, len);
    kani::cover!(len == 10, "the longest unsigned encoding is used");
    kani::cover!(value == 0 && len == 1, "zero uses one byte");
}

#[kani::proof]
#[kani::unwind(12)]
fn encoded_pointers() {
    let bytes: [u8; 16] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    let base: u64 = kani::any();
    let encoding: u8 = kani::any();
    let pointer_bytes = if kani::any() { 4 } else { 8 };
    let mut reader = Bytes {
        bytes: &bytes[..len],
        at: 0,
    };
    let result = super::encoded(encoding, base, pointer_bytes, |size| reader.take(size));
    assert!(reader.at <= len);
    let size = match encoding & 0x0f {
        0 => pointer_bytes,
        2 | 10 => 2,
        3 | 11 => 4,
        4 | 12 => 8,
        _ => return,
    };
    if len < usize::from(size) {
        assert_eq!(result, None);
        assert_eq!(reader.at, 0);
        kani::cover!(true, "a truncated fixed-width pointer is rejected");
        return;
    }
    assert_eq!(reader.at, usize::from(size));
    let raw = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let bits = 8 * u32::from(size);
    let unsigned = raw & (u64::MAX >> (64 - bits));
    let signed = ((raw << (64 - bits)) as i64) >> (64 - bits);
    let value = if encoding & 8 == 0 {
        unsigned
    } else {
        signed as u64
    };
    let expected = if value == 0 {
        Some(0)
    } else {
        match encoding & 0x70 {
            0 => Some(value),
            0x10 if encoding & 8 != 0 => base.checked_add_signed(signed),
            0x10 => base.checked_add(unsigned),
            _ => None,
        }
    };
    assert_eq!(result, expected);
    kani::cover!(
        encoding == 0x1b && signed < 0 && result.is_some(),
        "a negative PC-relative pointer is decoded"
    );
    kani::cover!(
        encoding == 0x14 && value != 0 && result.is_none(),
        "an overflowing PC-relative pointer is rejected"
    );
}

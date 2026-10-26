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
    reader.at = 0;
    let signed = super::sleb(|size| reader.take(size));
    assert!(reader.at <= len);
    if signed.is_some() {
        assert!(reader.at > 0 && reader.at <= 10);
    }
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
    let _ = super::encoded(encoding, base, pointer_bytes, |size| reader.take(size));
    assert!(reader.at <= len);
}

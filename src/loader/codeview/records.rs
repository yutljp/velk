//! Bounded little-endian CodeView record access.

pub(super) struct Reader<'a>(pub &'a [u8]);

impl<'a> Reader<'a> {
    pub fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let Some((head, tail)) = self.0.split_at_checked(count) else {
            return None;
        };
        self.0 = tail;
        Some(head)
    }

    pub fn u16(&mut self) -> Option<u16> {
        self.take(2)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn name(&mut self) -> Option<String> {
        let Some(end) = self.0.iter().position(|byte| *byte == 0) else {
            return None;
        };
        let name = std::str::from_utf8(&self.0[..end]).ok().map(str::to_owned);
        self.0 = &self.0[end + 1..];
        name
    }

    pub fn number(&mut self) -> Option<u64> {
        let Some(leaf) = self.u16() else { return None };
        match leaf {
            0..0x8000 => Some(u64::from(leaf)),
            0x8002 => self.u16().map(u64::from),
            0x8004 => self.u32().map(u64::from),
            0x800a => self
                .take(8)
                .map(|bytes| u64::from_le_bytes(bytes.try_into().expect("eight bytes"))),
            _ => None,
        }
    }
}

pub(super) fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let Some(tail) = bytes.get(at..) else {
        return None;
    };
    Reader(tail).u32()
}

pub(super) fn records(mut bytes: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        let mut reader = Reader(bytes);
        let Some(len) = reader.u16() else {
            bytes = &[];
            return None;
        };
        let Some(record) = reader.take(usize::from(len)) else {
            bytes = &[];
            return None;
        };
        bytes = reader.0;
        let mut record = Reader(record);
        match record.u16() {
            Some(kind) => Some((kind, record.0)),
            None => Some((0, &[][..])),
        }
    })
}

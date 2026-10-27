//! Checked file ranges and concrete image words.

use super::Image;

pub(super) fn read_range(bytes: &[u8], slice_offset: u64, offset: u64, len: u64) -> Option<&[u8]> {
    let Some(offset) = offset.checked_sub(slice_offset) else {
        return None;
    };
    let Some(end) = offset.checked_add(len) else {
        return None;
    };
    let (Ok(start), Ok(end)) = (usize::try_from(offset), usize::try_from(end)) else {
        return None;
    };
    bytes.get(start..end)
}

pub(super) fn bounded_bytes(image: &Image, address: u64, size: u64) -> Option<&[u8]> {
    let Some(section) = image.section_at(address) else {
        return None;
    };
    if address
        .checked_add(size)
        .is_none_or(|end| end > section.vaddr.saturating_add(section.size))
    {
        return None;
    }
    image.read_vaddr(address, size)
}

pub(crate) fn word(image: &Image, address: u64, size: u64) -> Option<u64> {
    if size > 8 {
        return None;
    }
    let Some(bytes) = bounded_bytes(image, address, size) else {
        return None;
    };
    Some(unsigned(bytes, /* little */ true))
}

pub(crate) fn unsigned(data: &[u8], little: bool) -> u64 {
    let mut value = 0u64;
    if little {
        for byte in data.iter().rev() {
            value = (value << 8) | u64::from(*byte);
        }
    } else {
        for byte in data {
            value = (value << 8) | u64::from(*byte);
        }
    }
    value
}

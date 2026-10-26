use super::{Frame, FrameKind};
use crate::loader::{Image, Isa};

pub(super) fn frames(image: &Image) -> Vec<Frame> {
    if image.isa != Isa::X86_64 {
        return Vec::new();
    }
    let Some((base, data)) = crate::loader::seh::exception_directory(image) else {
        return Vec::new();
    };
    let mut frames = Vec::new();
    for entry in data.as_chunks::<12>().0 {
        let rva = |offset| {
            u64::from(u32::from_le_bytes(
                entry[offset..offset + 4]
                    .try_into()
                    .expect("each field is a four-byte slice of a twelve-byte entry"),
            ))
        };
        let (Some(start), Some(end), Some(unwind)) = (
            base.checked_add(rva(0)),
            base.checked_add(rva(4)),
            base.checked_add(rva(8)),
        ) else {
            continue;
        };
        if end <= start || rva(8) & 3 != 0 {
            continue;
        }
        let Some(section) = image.section_at(start) else {
            continue;
        };
        if !section.executable || end > section.vaddr.saturating_add(section.size) {
            continue;
        }
        let Some(header) = image.read_vaddr(unwind, 4) else {
            continue;
        };
        // Chained unwind records describe additional ranges of an existing function.
        if header[0] & 7 != 1 || header[0] >> 3 & !3 != 0 || u64::from(header[1]) > end - start {
            continue;
        }
        let codes_size = 4 + u64::from(header[2]) * 2;
        let Some(section) = image.section_at(unwind) else {
            continue;
        };
        if unwind
            .checked_add(codes_size)
            .is_none_or(|end| end > section.vaddr.saturating_add(section.size))
            || image.read_vaddr(unwind, codes_size).is_none()
        {
            continue;
        }
        frames.push(Frame {
            start,
            size: end - start,
            kind: FrameKind::Entry,
        });
    }
    frames.sort_by_key(|frame| frame.start);
    frames.dedup_by_key(|frame| frame.start);
    frames
}

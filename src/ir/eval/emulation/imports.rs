//! Resolves ARM ELF linkage entries without requiring the dynamic linker.

use crate::loader::{Format, Image, Isa};

pub(super) fn arm32_slot(image: &Image, target: u64) -> Option<u64> {
    if image.isa != Isa::Arm32 || image.format != Format::Elf {
        return None;
    }
    let target = image.code_address(target);
    let Some(section) = image.section_at(target) else {
        return None;
    };
    if section.name != ".plt" || section.size.saturating_sub(target - section.vaddr) < 12 {
        return None;
    }
    let Ok(address) = u32::try_from(target) else {
        return None;
    };
    if target.saturating_add(12) > 1u64 << 32 {
        return None;
    }
    let Some(bytes) = image.read_vaddr(target, 12) else {
        return None;
    };
    let words: [u32; 3] = std::array::from_fn(|index| {
        let start = index * 4;
        u32::from_le_bytes([
            bytes[start],
            bytes[start + 1],
            bytes[start + 2],
            bytes[start + 3],
        ])
    });
    let Some(slot) = crate::loader::arm_linkage::slot(words, address) else {
        return None;
    };
    image
        .imports
        .contains_key(&u64::from(slot))
        .then_some(u64::from(slot))
}

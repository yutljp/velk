//! A32 entry addresses recorded in the ARM exception index.

use crate::error::Result;
use crate::loader::{ArmMode, Image};
use std::time::Instant;

pub(super) fn arm_starts(image: &Image, deadline: Option<Instant>) -> Result<Vec<u64>> {
    let mut starts = Vec::new();
    for section in &image.sections {
        if !section.loaded || !section.name.starts_with(".ARM.exidx") {
            continue;
        }
        let Some(bytes) = image.section_data(&section.name) else {
            continue;
        };
        if !bytes.len().is_multiple_of(8) {
            continue;
        }
        let mut previous = None;
        for (index, entry) in bytes.as_chunks::<8>().0.iter().enumerate() {
            if let Err(error) = crate::deadline::passed(deadline) {
                return Err(error);
            }
            let word =
                u32::from_le_bytes(entry[..4].try_into().expect("an index word has four bytes"));
            if word & 0x8000_0000 != 0 {
                break;
            }
            let delta = i64::from((word << 1) as i32 >> 1);
            let Some(address) = (index as u64)
                .checked_mul(8)
                .and_then(|offset| section.vaddr.checked_add(offset))
                .and_then(|place| place.checked_add_signed(delta))
            else {
                break;
            };
            let physical = address & !1;
            if previous.is_some_and(|previous| physical <= previous) {
                break;
            }
            previous = Some(physical);
            if address > u64::from(u32::MAX)
                || address & 1 != 0
                || !physical.is_multiple_of(4)
                || image
                    .arm_modes
                    .get(&physical)
                    .is_some_and(|mode| *mode != ArmMode::Arm)
            {
                continue;
            }
            if image.sections.iter().any(|code| {
                code.executable
                    && code.loaded
                    && physical >= code.vaddr
                    && physical < code.vaddr.saturating_add(code.size)
            }) {
                starts.push(physical);
            }
        }
    }
    Ok(starts)
}

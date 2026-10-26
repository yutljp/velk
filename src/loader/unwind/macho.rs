//! LSDA references indexed by Mach-O compact unwind tables.

use object::{Object, ObjectSegment};

use super::{Region, lsda};
use crate::loader::Image;
use crate::loader::classes;

pub(super) fn regions(image: &Image) -> Vec<Region> {
    let mut regions = Vec::new();
    let Some(section) = image
        .sections
        .iter()
        .find(|section| section.name == "__unwind_info")
    else {
        return regions;
    };
    let Ok(file) = object::File::parse(image.bytes.as_slice()) else {
        return regions;
    };
    let Some(base) = file
        .segments()
        .find(|segment| segment.name() == Ok(Some("__TEXT")))
        .map(|segment| segment.address())
    else {
        return regions;
    };
    let field = |offset| {
        section
            .vaddr
            .checked_add(offset)
            .and_then(|at| classes::word(image, at, 4))
    };
    let (Some(1), Some(index), Some(count)) = (field(0), field(20), field(24)) else {
        return regions;
    };
    let Some(index_end) = count
        .checked_mul(12)
        .and_then(|size| index.checked_add(size))
    else {
        return regions;
    };
    if count < 2 || index_end > section.size {
        return regions;
    }
    for row in 0..count - 1 {
        let at = index + row * 12;
        let (Some(start), Some(end)) = (field(at + 8), field(at + 20)) else {
            continue;
        };
        if end < start || end > section.size || (end - start) % 8 != 0 {
            continue;
        }
        for index in 0..(end - start) / 8 {
            let at = start + index * 8;
            let (Some(function), Some(table)) = (
                field(at).and_then(|offset| base.checked_add(offset)),
                field(at + 4).and_then(|offset| base.checked_add(offset)),
            ) else {
                continue;
            };
            if !image.functions.contains_key(&function) {
                continue;
            }
            regions.extend(lsda::read(image, table, function));
        }
    }
    regions
}

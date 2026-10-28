//! Register argument spill bounds from Go's argument liveness metadata.

use std::collections::HashMap;

use crate::loader::{Image, Isa};

pub(super) fn ranges(image: &Image) -> HashMap<u64, (i64, i64)> {
    let mut ranges = HashMap::new();
    if !matches!(image.isa, Isa::X86_64 | Isa::AArch64) {
        return ranges;
    }
    let Some(table) = super::pclntab(image) else {
        return ranges;
    };
    let Some(header) = crate::loader::image_reads::bounded_bytes(image, table.vaddr, 8) else {
        return ranges;
    };
    if header[..4] != [0xf1, 0xff, 0xff, 0xff] || header[7] != 8 {
        return ranges;
    }
    let Some(module) = super::moduledata(image, table.vaddr) else {
        return ranges;
    };
    let field = |offset| module.checked_add(offset);
    let (Some((table, length)), Some((entries, count)), Some(text), Some(data)) = (
        field(super::MODULE_PC_TABLE).and_then(|address| super::slice_at(image, address)),
        field(super::MODULE_FUNCTION_TABLE).and_then(|address| super::slice_at(image, address)),
        field(super::MODULE_TEXT).and_then(|address| super::u64_at(image, address)),
        field(320).and_then(|address| super::u64_at(image, address)),
    ) else {
        return ranges;
    };
    if count > 200_001 {
        return ranges;
    }
    let Some(bytes) = count.checked_mul(8) else {
        return ranges;
    };
    let (Some(entries), Some(table)) = (
        crate::loader::image_reads::bounded_bytes(image, entries, bytes),
        crate::loader::image_reads::bounded_bytes(image, table, length),
    ) else {
        return ranges;
    };
    let entries = entries.as_chunks::<8>().0;
    let functions = entries.iter().take(count.saturating_sub(1) as usize);
    for entry in functions {
        let pc = u32::from_le_bytes(entry[..4].try_into().expect("four bytes"));
        let offset = u32::from_le_bytes(entry[4..].try_into().expect("four bytes"));
        let Some(function) = table.get(offset as usize..) else {
            continue;
        };
        let Some(header) = function.get(..44) else {
            continue;
        };
        // FUNCDATA_ArgLiveInfo is entry six after the PCDATA offsets.
        if header[43] <= 6 {
            continue;
        }
        let args = i32::from_le_bytes(header[8..12].try_into().expect("four bytes"));
        let count = u32::from_le_bytes(header[28..32].try_into().expect("four bytes"));
        let Some(offset) = u64::from(count)
            .checked_add(6)
            .and_then(|count| count.checked_mul(4))
            .and_then(|offset| offset.checked_add(44))
        else {
            continue;
        };
        let Ok(offset) = usize::try_from(offset) else {
            continue;
        };
        let Some(offset) = super::super::discover::read_word(function, offset) else {
            continue;
        };
        if offset == u32::MAX || args <= 0 {
            continue;
        }
        let Some(address) = data.checked_add(u64::from(offset)) else {
            continue;
        };
        let Some(live) = crate::loader::image_reads::bounded_bytes(image, address, 1) else {
            continue;
        };
        let start = i64::from(live[0]);
        let end = i64::from(args);
        let Some(address) = text.checked_add(u64::from(pc)) else {
            continue;
        };
        if start < end {
            // Both supported Go ports reserve one word before argument storage.
            ranges.insert(address, (start + 8, end + 8));
        }
    }
    ranges
}

#[cfg(test)]
mod tests {
    #[test]
    fn unsupported_or_truncated_tables_do_not_claim_spill_storage() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/go_probe");
        for mutation in 0..4 {
            let mut image = crate::loader::load(&path).unwrap();
            let section = image
                .sections
                .iter_mut()
                .find(|section| section.name == ".gopclntab")
                .unwrap();
            let offset = section.file_offset.unwrap() as usize;
            match mutation {
                0 => image.bytes[offset] = 0xf0,
                1 => image.bytes[offset + 7] = 4,
                2 => section.size = 4,
                _ => image.isa = crate::loader::Isa::Arm32,
            }
            assert!(super::ranges(&image).is_empty(), "mutation {mutation}");
        }
    }

    #[test]
    fn fixture_spills_follow_stack_arguments() {
        for (file, address) in [("go_probe", 0x466d00), ("go_probe_arm64", 0x77490)] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(file);
            let image = crate::loader::load(&path).unwrap();
            let ranges = super::ranges(&image);
            assert_eq!(ranges.get(&address).copied(), Some((8, 32)), "{file}");
        }
    }
}

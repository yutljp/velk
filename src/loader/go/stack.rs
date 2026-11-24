//! Register argument spill bounds from Go's argument liveness metadata.

use std::collections::HashMap;

use crate::loader::{Image, Isa};

pub(super) fn ranges(image: &Image) -> HashMap<u64, (i64, i64)> {
    let mut ranges = HashMap::new();
    // FUNCDATA_ArgLiveInfo is entry six after the PCDATA offsets.
    function_data(image, 6, |address, args, data| {
        let Some(live) = crate::loader::image_reads::bounded_bytes(image, data, 1) else {
            return;
        };
        let start = i64::from(live[0]);
        let end = i64::from(args);
        if start < end {
            // Both supported Go ports reserve one word before argument storage.
            ranges.insert(address, (start + 8, end + 8));
        }
    });
    ranges
}

/// How many registers carry the arguments of each function, from the list
/// Go keeps for printing them in a traceback: one offset and size for
/// each word of an argument a register passes. A list cut short, as a
/// long one is, tells nothing.
pub(super) fn argument_registers(image: &Image) -> HashMap<u64, usize> {
    let mut counts = HashMap::new();
    // FUNCDATA_ArgInfo is entry five.
    function_data(image, 5, |address, _, data| {
        let mut count = 0;
        let mut at = data;
        loop {
            let Some(byte) = crate::loader::image_reads::bounded_bytes(image, at, 1) else {
                return;
            };
            at += 1;
            match byte[0] {
                // The end of the list.
                0xff => break,
                // The start and the end of a structure or an array.
                0xfe | 0xfd => {}
                // Arguments left out, or one too far to describe.
                0xfc | 0xfb => return,
                _ => {
                    count += 1;
                    at += 1;
                }
            }
            if count > 64 {
                return;
            }
        }
        counts.insert(address, count);
    });
    counts
}

/// Calls `visit` for each function that has the entry `index` of Go's
/// function data, with the function's address, the bytes of its
/// arguments and the address of the entry's data.
fn function_data(image: &Image, index: u8, mut visit: impl FnMut(u64, i32, u64)) {
    if !matches!(image.isa, Isa::X86_64 | Isa::AArch64) {
        return;
    }
    let Some(table) = super::pclntab(image) else {
        return;
    };
    let Some(header) = crate::loader::image_reads::bounded_bytes(image, table.vaddr, 8) else {
        return;
    };
    if header[..4] != [0xf1, 0xff, 0xff, 0xff] || header[7] != 8 {
        return;
    }
    let Some(module) = super::moduledata(image, table.vaddr) else {
        return;
    };
    let Some(layout) = super::module_layout(image, module, table.vaddr) else {
        return;
    };
    let field = |offset| module.checked_add(offset);
    let (Some((table, length)), Some((entries, count)), Some(text), Some(data)) = (
        field(super::MODULE_PC_TABLE).and_then(|address| super::slice_at(image, address)),
        field(super::MODULE_FUNCTION_TABLE).and_then(|address| super::slice_at(image, address)),
        field(super::MODULE_TEXT).and_then(|address| super::u64_at(image, address)),
        field(layout.function_data).and_then(|address| super::u64_at(image, address)),
    ) else {
        return;
    };
    if count > 200_001 {
        return;
    }
    let Some(bytes) = count.checked_mul(8) else {
        return;
    };
    let (Some(entries), Some(table)) = (
        crate::loader::image_reads::bounded_bytes(image, entries, bytes),
        crate::loader::image_reads::bounded_bytes(image, table, length),
    ) else {
        return;
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
        if header[43] <= index {
            continue;
        }
        let args = i32::from_le_bytes(header[8..12].try_into().expect("four bytes"));
        let count = u32::from_le_bytes(header[28..32].try_into().expect("four bytes"));
        let Some(offset) = u64::from(count)
            .checked_add(u64::from(index))
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
        let (Some(data), Some(address)) = (
            data.checked_add(u64::from(offset)),
            text.checked_add(u64::from(pc)),
        ) else {
            continue;
        };
        visit(address, args, data);
    }
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
        for (file, name) in [
            ("go_probe", "main.sumSlice"),
            ("go_probe_arm64", "main.sumSlice"),
            ("go_probe_arm64_1_27", "main.sumSlice"),
        ] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(file);
            let image = crate::loader::load(&path).unwrap();
            let address = image
                .functions
                .values()
                .find(|function| function.name.as_deref() == Some(name))
                .expect("named function")
                .addr;
            let ranges = super::ranges(&image);
            assert_eq!(ranges.get(&address).copied(), Some((8, 32)), "{file}");
        }
    }

    #[test]
    fn argument_registers_follow_the_types_of_the_arguments() {
        for file in ["go_probe", "go_probe_arm64", "go_probe_arm64_1_27"] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(file);
            let image = crate::loader::load(&path).unwrap();
            let counts = super::argument_registers(&image);
            // A slice fills three registers, two integers two.
            for (name, expected) in [("main.sumSlice", 3), ("main.divmod", 2)] {
                let address = image
                    .functions
                    .values()
                    .find(|function| function.name.as_deref() == Some(name))
                    .expect("named function")
                    .addr;
                assert_eq!(counts.get(&address), Some(&expected), "{file}: {name}");
            }
        }
    }

    #[test]
    fn module_data_layout_follows_the_go_release() {
        let layout = |file: &str| {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(file);
            let image = crate::loader::load(&path).unwrap();
            let table = crate::loader::go::pclntab(&image).unwrap().vaddr;
            let module = crate::loader::go::moduledata(&image, table).unwrap();
            crate::loader::go::module_layout(&image, module, table)
        };
        for file in ["go_probe", "go_probe_arm64"] {
            let found = layout(file).expect("Go 1.23 layout");
            assert_eq!((found.types_end, found.function_data), (304, 320), "{file}");
            assert_eq!(found.links, Some((352, 376)), "{file}");
        }
        let found = layout("go_probe_arm64_1_27").expect("Go 1.27 layout");
        assert_eq!((found.types_end, found.function_data), (312, 344));
        assert_eq!(found.links, None);
    }
}

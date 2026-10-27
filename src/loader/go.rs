//! Go binary function-name recovery through the pclntab/moduledata tables.

use crate::loader::Image;

pub(crate) mod types;

const MODULE_NAMES: u64 = 8;
const MODULE_PC_TABLE: u64 = 104;
const MODULE_FUNCTION_TABLE: u64 = 128;
const MODULE_TEXT: u64 = 176;
const MODULE_TEXT_END: u64 = 184;
const MODULE_TYPES: usize = 296;
const MODULE_TYPES_END: usize = 304;
const MODULE_TYPE_LINKS: usize = 352;
const MODULE_INTERFACE_LINKS: usize = 376;
const MODULE_TYPE_DATA_SIZE: u64 = 456;

#[derive(Debug, Clone)]
pub struct GoFunction {
    pub addr: u64,
    pub name: String,
}

fn bytes_at(image: &Image, addr: u64, len: u64) -> Option<&[u8]> {
    super::image_reads::bounded_bytes(image, addr, len)
}

fn u64_at(image: &Image, addr: u64) -> Option<u64> {
    let Some(bytes) = bytes_at(image, addr, 8) else {
        return None;
    };
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn slice_at(image: &Image, addr: u64) -> Option<(u64, u64)> {
    let Some(length) = addr.checked_add(8) else {
        return None;
    };
    match (u64_at(image, addr), u64_at(image, length)) {
        (Some(pointer), Some(length)) => Some((pointer, length)),
        _ => None,
    }
}

fn c_string(bytes: &[u8]) -> Option<&[u8]> {
    let bytes = &bytes[..bytes.len().min(128)];
    let Some(end) = bytes.iter().position(|byte| *byte == 0) else {
        return None;
    };
    if end < 3 {
        return None;
    }
    let text = &bytes[..end];
    if !text
        .iter()
        .all(|byte| (0x20..0x7f).contains(byte) || *byte == b'\t')
    {
        return None;
    }
    Some(text)
}

fn pclntab(image: &Image) -> Option<&crate::loader::Section> {
    image.sections.iter().find(|section| {
        section
            .name
            .trim_start_matches(['.', '_'])
            .starts_with("gopclntab")
    })
}

fn moduledata(image: &Image, pclntab: u64) -> Option<u64> {
    for section in &image.sections {
        if section.executable || section.size < 8 {
            continue;
        }
        let Some(bytes) = bytes_at(image, section.vaddr, section.size) else {
            continue;
        };
        for (index, word) in bytes.as_chunks::<8>().0.iter().enumerate() {
            let value = u64::from_le_bytes(*word);
            if value == pclntab {
                let Some(candidate) = (index as u64)
                    .checked_mul(8)
                    .and_then(|offset| section.vaddr.checked_add(offset))
                else {
                    continue;
                };
                if candidate.checked_add(MODULE_TEXT_END).is_none() {
                    continue;
                }
                let Some(text_addr) = candidate.checked_add(MODULE_TEXT) else {
                    continue;
                };
                let pclntable = slice_at(image, candidate + MODULE_PC_TABLE);
                let ftab = slice_at(image, candidate + MODULE_FUNCTION_TABLE);
                let text = u64_at(image, text_addr);
                let funcnametab = slice_at(image, candidate + MODULE_NAMES);
                if let (
                    Some((table, _)),
                    Some((ftab_ptr, ftab_len)),
                    Some(text),
                    Some((names, names_len)),
                ) = (pclntable, ftab, text, funcnametab)
                {
                    let in_image = |address: u64| image.section_at(address).is_some();
                    if in_image(table)
                        && in_image(ftab_ptr)
                        && in_image(names)
                        && ftab_len > 1
                        && ftab_len < 1_000_000
                        && names_len > 0
                        && image
                            .section_at(text)
                            .is_some_and(|section| section.executable)
                    {
                        return Some(candidate);
                    }
                }
            }
        }
    }
    None
}

pub fn functions(image: &Image) -> Vec<GoFunction> {
    let Some(tab) = pclntab(image) else {
        return Vec::new();
    };
    let Some(data) = moduledata(image, tab.vaddr) else {
        return Vec::new();
    };
    let (
        Some((pclntable, pclntable_len)),
        Some((ftab_ptr, ftab_len)),
        Some(text),
        Some((names, names_len)),
    ) = (
        slice_at(image, data + MODULE_PC_TABLE),
        slice_at(image, data + MODULE_FUNCTION_TABLE),
        u64_at(image, data + MODULE_TEXT),
        slice_at(image, data + MODULE_NAMES),
    )
    else {
        return Vec::new();
    };
    if ftab_len <= 1 || ftab_len > 1_000_000 {
        return Vec::new();
    }

    let Some(ftab_size) = ftab_len.checked_mul(8) else {
        return Vec::new();
    };
    let (Some(entries), Some(data), Some(names)) = (
        bytes_at(image, ftab_ptr, ftab_size),
        bytes_at(image, pclntable, pclntable_len),
        bytes_at(image, names, names_len),
    ) else {
        return Vec::new();
    };
    let mut functions = Vec::new();
    walk_table(entries, data, names, text, |addr, name| {
        if image
            .section_at(addr)
            .is_some_and(|section| section.executable)
        {
            functions.push(GoFunction {
                addr,
                name: String::from_utf8_lossy(name).into_owned(),
            });
        }
    });
    functions
}

fn walk_table(
    entries: &[u8],
    data: &[u8],
    names: &[u8],
    text: u64,
    mut emit: impl FnMut(u64, &[u8]),
) {
    let count = (entries.len() / 8).saturating_sub(1).min(200_000);
    for entry in entries.as_chunks::<8>().0.iter().take(count) {
        let entry_off = u32::from_le_bytes(entry[..4].try_into().expect("four bytes"));
        let func_off = i32::from_le_bytes(entry[4..].try_into().expect("four bytes"));
        let Ok(function) = usize::try_from(func_off) else {
            continue;
        };
        let Some(name_field) = function.checked_add(4) else {
            continue;
        };
        let Some(name_off) = super::discover::read_word(data, name_field) else {
            continue;
        };
        let Ok(name_offset) = usize::try_from(name_off as i32) else {
            continue;
        };
        let Some(name_bytes) = names.get(name_offset..) else {
            continue;
        };
        let Some(name) = c_string(name_bytes) else {
            continue;
        };
        let Some(addr) = text.checked_add(u64::from(entry_off)) else {
            continue;
        };
        emit(addr, name);
    }
}

#[cfg(test)]
mod tests {
    use crate::ir::Convention;
    use crate::loader::{Image, Isa, Section};

    #[test]
    fn abi0_wrappers_initialize_fixed_registers_before_the_call() {
        let code = vec![
            0x45, 0x0f, 0x57, 0xff, 0x64, 0x4c, 0x8b, 0x34, 0x25, 0xf8, 0xff, 0xff, 0xff, 0xe8, 0,
            0, 0, 0, 0xc3,
        ];
        for (bytes, expected) in [
            (code.clone(), Convention::GoAbi0),
            (code[..14].to_vec(), Convention::GoAmd64),
            ([vec![0xb8], code.clone()].concat(), Convention::GoAmd64),
            ([vec![0xc3], code].concat(), Convention::GoAmd64),
        ] {
            let length = bytes.len();
            let mut image = Image::from_code(Isa::X86_64, 0x1000, bytes);
            image.go = true;
            crate::loader::upsert(
                &mut image.functions,
                0x1000,
                Some("wrapper".into()),
                Some(length as u64),
                crate::loader::NameSource::Pclntab,
            );
            assert_eq!(image.convention_of(0x1000), expected);
        }
    }

    #[test]
    fn discovers_functions_after_an_unreadable_section() {
        for unreadable in [false, true] {
            let mut image = table_image(Isa::X86_64);
            if unreadable {
                image.sections.insert(
                    0,
                    Section {
                        name: ".bss".into(),
                        vaddr: 0x8000,
                        size: 8,
                        file_offset: None,
                        file_size: 0,
                        executable: false,
                        loaded: true,
                        read_only: false,
                    },
                );
            }
            image.add_go_functions();
            assert!(image.go, "unreadable section: {unreadable}");
            assert_eq!(image.functions.len(), 1);
            assert_eq!(image.functions[&0x1020].name.as_deref(), Some("main.work"));
            assert_eq!(image.convention_of(0x1020), Convention::GoAmd64);
        }
    }

    fn table_image(isa: Isa) -> Image {
        let mut image = Image::from_code(isa, 0x1000, vec![0xc3; 64]);
        let mut data = vec![0; 184];
        for (offset, value) in [
            (0, 0x4000u64),
            (8, 0x5000),
            (16, 128),
            (104, 0x6000),
            (112, 256),
            (128, 0x7000),
            (136, 2),
            (176, 0x1000),
        ] {
            data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        let mut names = vec![0; 128];
        names[..10].copy_from_slice(b"main.work\0");
        let mut table = vec![0; 16];
        table[..4].copy_from_slice(&0x20u32.to_le_bytes());
        for (name, vaddr, bytes) in [
            (".data", 0x2000, data),
            (".gopclntab", 0x4000, vec![0; 8]),
            (".names", 0x5000, names),
            (".funcdata", 0x6000, vec![0; 512]),
            (".functab", 0x7000, table),
        ] {
            image.sections.push(Section {
                name: name.into(),
                vaddr,
                size: bytes.len() as u64,
                file_offset: (image.bytes.len() as u64).checked_add(image.slice_offset),
                file_size: bytes.len() as u64,
                executable: false,
                loaded: true,
                read_only: false,
            });
            image.bytes.extend(bytes);
        }
        image
    }

    fn write_word(image: &mut Image, section: &str, offset: usize, bytes: &[u8]) {
        let section = image
            .sections
            .iter()
            .find(|item| item.name == section)
            .unwrap();
        let start = section.file_offset.unwrap() as usize + offset;
        image.bytes[start..start + bytes.len()].copy_from_slice(bytes);
    }

    #[test]
    fn invalid_table_offsets_do_not_name_functions() {
        for isa in [Isa::X86_64, Isa::AArch64] {
            for (section, offset, bytes) in [
                (".functab", 4, (-8i32).to_le_bytes().to_vec()),
                (".functab", 4, i32::MIN.to_le_bytes().to_vec()),
                (".functab", 4, 256i32.to_le_bytes().to_vec()),
                (".functab", 4, 252i32.to_le_bytes().to_vec()),
                (".funcdata", 4, (-1i32).to_le_bytes().to_vec()),
                (".funcdata", 4, 128i32.to_le_bytes().to_vec()),
                (".data", 16, 9u64.to_le_bytes().to_vec()),
                (".data", 112, 7u64.to_le_bytes().to_vec()),
                (".data", 136, 3u64.to_le_bytes().to_vec()),
                (".functab", 0, 64u32.to_le_bytes().to_vec()),
            ] {
                let mut image = table_image(isa);
                write_word(&mut image, section, offset, &bytes);
                assert!(
                    super::functions(&image).is_empty(),
                    "{isa:?}: {section}, {offset}, {bytes:?}"
                );
            }
        }
    }

    #[test]
    fn wrapped_tables_and_code_addresses_are_rejected() {
        for isa in [Isa::X86_64, Isa::AArch64] {
            for (name, field) in [(".functab", 128), (".funcdata", 104), (".names", 8)] {
                let mut image = table_image(isa);
                let base = u64::MAX - 3;
                write_word(&mut image, ".data", field, &base.to_le_bytes());
                image
                    .sections
                    .iter_mut()
                    .find(|section| section.name == name)
                    .unwrap()
                    .vaddr = base;
                let mut low = image
                    .sections
                    .iter()
                    .find(|section| section.name == ".funcdata")
                    .unwrap()
                    .clone();
                low.name = ".low".into();
                low.vaddr = 0;
                low.size = 128;
                low.file_size = 128;
                image.sections.push(low);
                assert!(super::functions(&image).is_empty(), "{isa:?}: {name}");
            }
            let mut image = table_image(isa);
            let base = u64::MAX - 16;
            write_word(&mut image, ".data", 176, &base.to_le_bytes());
            image.sections[0].vaddr = base;
            assert!(super::functions(&image).is_empty(), "{isa:?}: text");
        }
    }

    #[test]
    fn negative_function_offsets_do_not_read_before_the_table() {
        for isa in [Isa::X86_64, Isa::AArch64] {
            let mut image = table_image(isa);
            write_word(&mut image, ".functab", 4, &(-8i32).to_le_bytes());
            write_word(&mut image, ".data", 104, &0x6008u64.to_le_bytes());
            assert!(super::functions(&image).is_empty());
        }
    }

    #[test]
    fn names_at_the_end_of_the_table_are_bounded() {
        for isa in [Isa::X86_64, Isa::AArch64] {
            let mut image = table_image(isa);
            write_word(&mut image, ".data", 16, &10u64.to_le_bytes());
            let functions = super::functions(&image);
            assert_eq!(functions.len(), 1);
            assert_eq!(functions[0].name, "main.work");
            write_word(&mut image, ".data", 16, &9u64.to_le_bytes());
            assert!(super::functions(&image).is_empty());
        }
    }

    fn table_functions(
        entries: &[u8],
        data: &[u8],
        names: &[u8],
        text: u64,
    ) -> Vec<super::GoFunction> {
        let mut functions = Vec::new();
        super::walk_table(entries, data, names, text, |addr, name| {
            functions.push(super::GoFunction {
                addr,
                name: String::from_utf8_lossy(name).into_owned(),
            });
        });
        functions
    }

    #[test]
    fn invalid_entries_do_not_hide_later_valid_entries() {
        let mut entries = [0; 24];
        entries[4..8].copy_from_slice(&(-1i32).to_le_bytes());
        entries[8..12].copy_from_slice(&32u32.to_le_bytes());
        let functions = table_functions(&entries, &[0; 8], b"main.work\0", 0x1000);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].addr, 0x1020);
        assert_eq!(functions[0].name, "main.work");
        for length in 0..16 {
            assert!(
                table_functions(&entries[..length], &[0; 8], b"main.work\0", 0x1000).is_empty()
            );
        }
        assert!(table_functions(&entries, &[0; 8], b"main.work", 0x1000).is_empty());
    }
}

#[cfg(kani)]
mod proofs {
    #[kani::proof]
    #[kani::unwind(9)]
    fn go_table_walk() {
        let entries: [u8; 24] = kani::any();
        let data: [u8; 16] = kani::any();
        let names: [u8; 8] = kani::any();
        let entries_len: usize = kani::any();
        let data_len: usize = kani::any();
        let names_len: usize = kani::any();
        kani::assume(entries_len <= entries.len());
        kani::assume(data_len <= data.len());
        kani::assume(names_len <= names.len());
        let text: u64 = kani::any();
        let mut count = 0;
        super::walk_table(
            &entries[..entries_len],
            &data[..data_len],
            &names[..names_len],
            text,
            |addr, name| {
                count += 1;
                assert!(addr >= text);
                assert!(addr - text <= u64::from(u32::MAX));
                assert!(name.len() >= 3 && name.len() < names_len);
            },
        );
        assert!(count <= (entries_len / 8).saturating_sub(1));
        kani::cover!(count == 2, "two function entries are accepted");
        kani::cover!(
            count == 1
                && entries_len == 24
                && i32::from_le_bytes(entries[4..8].try_into().unwrap()) < 0,
            "a rejected first entry does not hide the second"
        );
    }

    #[kani::proof]
    #[kani::unwind(17)]
    fn go_table_offsets() {
        let entry: u32 = kani::any();
        let offset: i32 = kani::any();
        let name_offset: i32 = kani::any();
        let text: u64 = kani::any();
        let mut entries = [0; 16];
        entries[..4].copy_from_slice(&entry.to_le_bytes());
        entries[4..8].copy_from_slice(&offset.to_le_bytes());
        let mut data = [0; 8];
        data[4..].copy_from_slice(&name_offset.to_le_bytes());
        let valid = offset == 0
            && name_offset >= 0
            && name_offset <= 6
            && u64::from(entry) <= u64::MAX - text;
        let mut count = 0;
        super::walk_table(&entries, &data, b"main.work\0", text, |addr, name| {
            count += 1;
            assert!(valid);
            assert_eq!(addr, text + u64::from(entry));
            assert_eq!(name, &b"main.work"[name_offset as usize..]);
        });
        assert_eq!(count, usize::from(valid));
        kani::cover!(
            valid && entry != 0 && name_offset == 6,
            "a nonzero address and final valid name suffix are accepted"
        );
        kani::cover!(
            u64::from(entry) > u64::MAX - text && count == 0,
            "an overflowing function address is rejected"
        );
    }
}

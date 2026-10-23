//! Go binary function-name recovery through the pclntab/moduledata tables.

use crate::loader::Image;

#[derive(Debug, Clone)]
pub struct GoFunction {
    pub addr: u64,
    pub name: String,
}

fn bytes_at(image: &Image, addr: u64, len: u64) -> Option<&[u8]> {
    image.read_vaddr(addr, len)
}

fn u32_at(image: &Image, addr: u64) -> Option<u32> {
    let bytes = bytes_at(image, addr, 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn i32_at(image: &Image, addr: u64) -> Option<i32> {
    u32_at(image, addr).map(|value| value as i32)
}

fn u64_at(image: &Image, addr: u64) -> Option<u64> {
    let bytes = bytes_at(image, addr, 8)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn slice_at(image: &Image, addr: u64) -> Option<(u64, u64)> {
    Some((u64_at(image, addr)?, u64_at(image, addr + 8)?))
}

fn c_string(image: &Image, addr: u64) -> Option<String> {
    let bytes = bytes_at(image, addr, 128)?;
    let end = bytes.iter().position(|byte| *byte == 0)?;
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
    Some(String::from_utf8_lossy(text).into_owned())
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
                let Some(text_addr) = candidate.checked_add(176) else {
                    continue;
                };
                let pclntable = slice_at(image, candidate + 104);
                let ftab = slice_at(image, candidate + 128);
                let text = u64_at(image, text_addr);
                let funcnametab = slice_at(image, candidate + 8);
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
    let _ = tab;
    let Some(data) = moduledata(image, tab.vaddr) else {
        return Vec::new();
    };
    let (Some((pclntable, _)), Some((ftab_ptr, ftab_len)), Some(text), Some((names, names_len))) = (
        slice_at(image, data + 104),
        slice_at(image, data + 128),
        u64_at(image, data + 176),
        slice_at(image, data + 8),
    ) else {
        return Vec::new();
    };
    if ftab_len <= 1 || ftab_len > 1_000_000 {
        return Vec::new();
    }

    let count = ftab_len.saturating_sub(1).min(200_000);
    let mut functions = Vec::new();
    for index in 0..count {
        let entry = ftab_ptr + index * 8;
        let (Some(entry_off), Some(func_off)) = (u32_at(image, entry), i32_at(image, entry + 4))
        else {
            break;
        };
        let function = pclntable.wrapping_add(func_off as i64 as u64);
        let name_off = match i32_at(image, function + 4) {
            Some(value) => value,
            None => continue,
        };
        if name_off < 0 || name_off as u64 >= names_len {
            continue;
        }
        let Some(name) = c_string(image, names.wrapping_add(name_off as u64)) else {
            continue;
        };
        functions.push(GoFunction {
            addr: text.wrapping_add(entry_off as u64),
            name,
        });
    }
    functions
}

#[cfg(test)]
mod tests {
    use crate::ir::Convention;
    use crate::loader::{Image, Isa, Section};

    #[test]
    fn discovers_functions_after_an_unreadable_section() {
        for unreadable in [false, true] {
            let mut image = Image::from_code(Isa::X86_64, 0x1000, vec![0xc3; 64]);
            if unreadable {
                image.sections.insert(
                    0,
                    Section {
                        name: ".bss".into(),
                        vaddr: 0x8000,
                        size: 8,
                        file_offset: None,
                        executable: false,
                        loaded: true,
                        read_only: false,
                    },
                );
            }
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
                (".funcdata", 0x6000, vec![0; 256]),
                (".functab", 0x7000, table),
            ] {
                image.sections.push(Section {
                    name: name.into(),
                    vaddr,
                    size: bytes.len() as u64,
                    file_offset: Some(image.bytes.len() as u64),
                    executable: false,
                    loaded: true,
                    read_only: false,
                });
                image.bytes.extend(bytes);
            }
            image.add_go_functions();
            assert!(image.go, "unreadable section: {unreadable}");
            assert_eq!(image.functions.len(), 1);
            assert_eq!(image.functions[&0x1020].name.as_deref(), Some("main.work"));
            assert_eq!(image.convention_of(0x1020), Convention::GoAmd64);
        }
    }
}

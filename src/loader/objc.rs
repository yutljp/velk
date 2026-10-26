use super::{Format, Image, NameSource, upsert};

fn word(image: &Image, address: u64, offset: u64, width: u64) -> Option<u64> {
    let address = address.checked_add(offset)?;
    let section = image.section_at(address)?;
    if address.checked_add(width)? > section.vaddr.checked_add(section.size)? {
        return None;
    }
    let bytes = image.read_vaddr(address, width)?;
    Some(match width {
        4 => u32::from_le_bytes(bytes.try_into().ok()?) as u64,
        8 => u64::from_le_bytes(bytes.try_into().ok()?),
        _ => return None,
    })
}

fn string(image: &Image, address: u64, selector: bool) -> Option<String> {
    let section = image.section_at(address)?;
    if selector && section.name != "__objc_methname" {
        return None;
    }
    let remaining = section
        .size
        .checked_sub(address.checked_sub(section.vaddr)?)?;
    let bytes = image.read_vaddr(address, remaining.min(4096))?;
    let end = bytes.iter().position(|byte| *byte == 0)?;
    let name = std::str::from_utf8(&bytes[..end]).ok()?;
    // Restrict annotations to runtime identifiers so metadata cannot end a C comment.
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_:.$".contains(&byte))
    {
        return None;
    }
    Some(name.to_owned())
}

fn relative(image: &Image, address: u64, offset: u64) -> Option<u64> {
    let field = address.checked_add(offset)?;
    let displacement = word(image, field, 0, 4)? as u32 as i32;
    field.checked_add_signed(displacement as i64)
}

fn class_ro(image: &Image, address: u64) -> Option<u64> {
    // The low three bits of class_data_bits_t hold flags in 64-bit images.
    word(image, address, 32, 8).map(|bits| bits & !7)
}

fn class_name(image: &Image, address: u64) -> Option<String> {
    let ro = class_ro(image, address)?;
    string(image, word(image, ro, 24, 8)?, false)
}

fn methods(image: &mut Image, list: u64, owner: &str, kind: char) {
    let (Some(flags), Some(count)) = (word(image, list, 0, 4), word(image, list, 4, 4)) else {
        return;
    };
    let small = flags & 0x8000_0000 != 0;
    let stride = flags & 0xfffc;
    if stride != if small { 12 } else { 24 } {
        return;
    }
    let Some(size) = count
        .checked_mul(stride)
        .and_then(|size| size.checked_add(8))
    else {
        return;
    };
    let Some(section) = image.section_at(list) else {
        return;
    };
    if size > section.size.saturating_sub(list - section.vaddr)
        || image.read_vaddr(list, size).is_none()
    {
        return;
    }
    for index in 0..count {
        let Some(entry) = index
            .checked_mul(stride)
            .and_then(|at| at.checked_add(8))
            .and_then(|at| list.checked_add(at))
        else {
            continue;
        };
        let (name, imp) = if small {
            let name = relative(image, entry, 0).and_then(|address| {
                if flags & 0x4000_0000 != 0 {
                    Some(address)
                } else {
                    word(image, address, 0, 8)
                }
            });
            (name, relative(image, entry, 8))
        } else {
            (word(image, entry, 0, 8), word(image, entry, 16, 8))
        };
        let (Some(name), Some(imp)) = (name, imp) else {
            continue;
        };
        let Some(selector) = string(image, name, true) else {
            continue;
        };
        if !image
            .section_at(imp)
            .is_some_and(|section| section.executable)
        {
            continue;
        }
        upsert(
            &mut image.functions,
            imp,
            Some(format!("{kind}[{owner} {selector}]")),
            None,
            NameSource::Objc,
        );
    }
}

pub(super) fn read(image: &mut Image) {
    if image.format != Format::MachO
        || !matches!(image.isa, super::Isa::AArch64 | super::Isa::X86_64)
        || image.byte_order() != Some(object::Endianness::Little)
    {
        return;
    }
    let sections: Vec<_> = image
        .sections
        .iter()
        .filter(|section| {
            matches!(
                section.name.as_str(),
                "__objc_classlist" | "__objc_catlist" | "__objc_selrefs"
            )
        })
        .map(|section| (section.name.clone(), section.vaddr, section.size))
        .collect();
    for (name, base, size) in sections {
        if image.read_vaddr(base, size).is_none() {
            continue;
        }
        for offset in (0..size.saturating_sub(7)).step_by(8) {
            let Some(slot) = base.checked_add(offset) else {
                continue;
            };
            let Some(address) = word(image, slot, 0, 8) else {
                continue;
            };
            if name == "__objc_selrefs" {
                if let Some(selector) = string(image, address, true) {
                    image.objc_selectors.insert(slot, selector);
                }
                continue;
            }
            let class = if name == "__objc_catlist" {
                word(image, address, 8, 8)
            } else {
                Some(address)
            };
            let Some(class) = class else {
                continue;
            };
            let Some(owner) = class_name(image, class) else {
                continue;
            };
            if name == "__objc_catlist" {
                for (offset, kind) in [(16, '-'), (24, '+')] {
                    if let Some(list) = word(image, address, offset, 8) {
                        methods(image, list, &owner, kind);
                    }
                }
            } else {
                for (class, kind) in [(Some(class), '-'), (word(image, class, 0, 8), '+')] {
                    if let Some(ro) = class.and_then(|class| class_ro(image, class))
                        && let Some(list) = word(image, ro, 32, 8)
                    {
                        methods(image, list, &owner, kind);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> Image {
        let mut image = Image::from_code(super::super::Isa::AArch64, 0x2000, vec![0; 1024]);
        image.sections[0].size = 16;
        image.sections.push(super::super::Section {
            name: "__objc_methname".into(),
            vaddr: 0x2010,
            size: 1008,
            file_offset: Some(16),
            file_size: 1008,
            loaded: true,
            executable: false,
            read_only: true,
        });
        image.bytes[0x100..0x105].copy_from_slice(b"test\0");
        image
    }

    #[test]
    fn method_list_formats_and_invalid_entries() {
        for flags in [24u32, 0x8000_000c, 0xc000_000c] {
            let mut image = image();
            image.bytes[0x20..0x24].copy_from_slice(&flags.to_le_bytes());
            image.bytes[0x24..0x28].copy_from_slice(&2u32.to_le_bytes());
            for index in 0..2 {
                let small = flags & 0x8000_0000 != 0;
                let entry = 0x28 + index * if small { 12 } else { 24 };
                let imp = if index == 0 { 0x2300u64 } else { 0x2000 };
                if small {
                    let name = if flags & 0x4000_0000 != 0 {
                        0x2100
                    } else {
                        0x2200
                    };
                    image.bytes[0x200..0x208].copy_from_slice(&0x2100u64.to_le_bytes());
                    image.bytes[entry..entry + 4]
                        .copy_from_slice(&((name - (0x2000 + entry) as i64) as i32).to_le_bytes());
                    image.bytes[entry + 8..entry + 12].copy_from_slice(
                        &((imp as i64 - (0x2000 + entry + 8) as i64) as i32).to_le_bytes(),
                    );
                } else {
                    image.bytes[entry..entry + 8].copy_from_slice(&0x2100u64.to_le_bytes());
                    image.bytes[entry + 16..entry + 24].copy_from_slice(&imp.to_le_bytes());
                }
            }
            methods(&mut image, 0x2020, "Example", '-');
            assert_eq!(
                image.functions[&0x2000].name.as_deref(),
                Some("-[Example test]")
            );
            assert_eq!(image.functions.len(), 1);
            image.functions.clear();
            image.bytes[0x24..0x28].copy_from_slice(&u32::MAX.to_le_bytes());
            methods(&mut image, 0x2020, "Example", '-');
            assert!(image.functions.is_empty());
        }
    }

    #[test]
    fn selector_comments_reject_control_text_and_unterminated_strings() {
        let mut image = image();
        image.bytes[0x100..0x105].copy_from_slice(b"*/x\0\0");
        assert!(string(&image, 0x2100, true).is_none());
        image.bytes[0x100..].fill(b'x');
        assert!(string(&image, 0x2100, true).is_none());
        assert!(word(&image, u64::MAX, 8, 8).is_none());
    }
}

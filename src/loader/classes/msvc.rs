//! Absolute MSVC x86 and image-relative x64 RTTI descriptors.

use std::collections::BTreeMap;

use object::Object;

use super::{Base, Class, VirtualBase, Vtable};
use crate::loader::Image;

const PRIMITIVES: [(&str, &str); 6] = [
    (".H", "int"),
    (".I", "unsigned int"),
    (".J", "long"),
    (".N", "double"),
    (".M", "float"),
    (".D", "char"),
];

pub(crate) fn type_name(image: &Image, address: u64) -> Option<String> {
    let Some(at) = address.checked_add(2 * u64::from(crate::arch::pointer_bytes(image.isa))) else {
        return None;
    };
    let Some(name) = super::text(image, at) else {
        return None;
    };
    if let Some((_, name)) = PRIMITIVES.iter().find(|(tag, _)| *tag == name) {
        return Some((*name).to_owned());
    }
    let Some(name) = name
        .strip_prefix(".?AV")
        .or_else(|| name.strip_prefix(".?AU"))
    else {
        return None;
    };
    let Some(name) = name.strip_suffix("@@") else {
        return None;
    };
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_@".contains(&byte))
    {
        return None;
    }
    let parts: Vec<_> = name.split('@').rev().collect();
    Some(parts.join("::"))
}

pub(super) fn read(image: &Image) -> Vec<Class> {
    let Ok(file) = object::File::parse(image.bytes.as_slice()) else {
        return Vec::new();
    };
    let width = u64::from(crate::arch::pointer_bytes(image.isa));
    let base = if width == 8 {
        file.relative_address_base()
    } else {
        0
    };
    let mut classes = BTreeMap::<u64, Class>::new();
    for section in &image.sections {
        if !section.loaded || section.executable || !section.read_only {
            continue;
        }
        let Some(bytes) = image.read_vaddr(section.vaddr, section.size) else {
            continue;
        };
        for (index, chunk) in bytes.chunks_exact(width as usize).enumerate() {
            let mut value = [0; 8];
            value[..chunk.len()].copy_from_slice(chunk);
            let locator = u64::from_le_bytes(value);
            if crate::loader::image_reads::word(image, locator, 4) != Some(u64::from(width == 8)) {
                continue;
            }
            let field = |offset| {
                locator
                    .checked_add(offset)
                    .and_then(|at| crate::loader::image_reads::word(image, at, 4))
            };
            let rva = |offset| field(offset).and_then(|rva| base.checked_add(rva));
            let (Some(offset), Some(displacement), Some(info), Some(hierarchy)) =
                (field(4), field(8), rva(12), rva(16))
            else {
                continue;
            };
            if width == 8 && rva(20) != Some(locator) {
                continue;
            }
            let Some(name) = type_name(image, info) else {
                continue;
            };
            let Some(bases) = bases(image, base, hierarchy, info) else {
                continue;
            };
            let Some(point) = section.vaddr.checked_add(index as u64 * width + width) else {
                break;
            };
            let methods = super::methods(image, point);
            if methods.is_empty() {
                continue;
            }
            let class = classes.entry(info).or_insert_with(|| Class {
                name,
                type_info: info,
                bases,
                vtables: Vec::new(),
            });
            class.vtables.push(Vtable {
                address: point,
                offset: offset as i64,
                construction_displacement: Some(displacement as u32),
                methods,
            });
        }
    }
    for section in &image.sections {
        if !section.loaded || section.executable || section.file_offset.is_none() {
            continue;
        }
        let Some(bytes) = image.read_vaddr(section.vaddr, section.size) else {
            continue;
        };
        for (index, chunk) in bytes.chunks_exact(width as usize).enumerate() {
            let mut value = [0; 8];
            value[..chunk.len()].copy_from_slice(chunk);
            let target = u64::from_le_bytes(value);
            let Some(function) = image.functions.get(&target) else {
                continue;
            };
            if function.name.as_deref() != Some("??_7type_info@@6B@") {
                continue;
            }
            let Some(info) = section.vaddr.checked_add(index as u64 * width) else {
                break;
            };
            let Some(name) = type_name(image, info)
                .filter(|name| !PRIMITIVES.iter().any(|(_, primitive)| name == primitive))
            else {
                continue;
            };
            classes.entry(info).or_insert_with(|| Class {
                name,
                type_info: info,
                bases: Vec::new(),
                vtables: Vec::new(),
            });
        }
    }
    classes.into_values().collect()
}

fn bases(image: &Image, base: u64, hierarchy: u64, own: u64) -> Option<Vec<Base>> {
    let field = |offset| {
        hierarchy
            .checked_add(offset)
            .and_then(|at| crate::loader::image_reads::word(image, at, 4))
    };
    let (Some(0), Some(count), Some(array)) = (
        field(0),
        field(8),
        field(12).and_then(|rva| base.checked_add(rva)),
    ) else {
        return None;
    };
    if count == 0 || count > 4096 {
        return None;
    }
    let mut out = Vec::new();
    let mut next = 0;
    for index in 0..count {
        let Some(descriptor) = array
            .checked_add(index * 4)
            .and_then(|at| crate::loader::image_reads::word(image, at, 4))
            .and_then(|rva| base.checked_add(rva))
        else {
            return None;
        };
        let field = |offset| {
            descriptor
                .checked_add(offset)
                .and_then(|at| crate::loader::image_reads::word(image, at, 4))
        };
        let (
            Some(info),
            Some(contained),
            Some(member),
            Some(pointer),
            Some(entry),
            Some(attributes),
        ) = (
            field(0).and_then(|rva| base.checked_add(rva)),
            field(4),
            field(8),
            field(12),
            field(16),
            field(20),
        )
        else {
            return None;
        };
        if index == 0 {
            if info != own || contained != count - 1 {
                return None;
            }
            next = 1;
            continue;
        }
        if index != next {
            continue;
        }
        let Some(end) = index
            .checked_add(1)
            .and_then(|value| value.checked_add(contained))
        else {
            return None;
        };
        if end > count {
            return None;
        }
        next = end;
        let Some(name) = type_name(image, info) else {
            return None;
        };
        let is_virtual = pointer as i32 != -1;
        out.push(Base {
            name,
            offset: (!is_virtual).then_some(member as i32 as i64),
            is_virtual,
            is_public: attributes & 0x0d == 0,
            vtable_offset: None,
            vbtable: is_virtual.then_some(VirtualBase {
                pointer_offset: pointer as i32,
                entry_offset: entry as i32,
                member_offset: member as i32,
            }),
        });
    }
    Some(out)
}

pub(super) struct Thunk {
    pub(super) target: u64,
    pub(super) size: u64,
}

pub(super) fn adjustment_thunk(image: &Image, address: u64) -> Option<Thunk> {
    let Some(section) = image.section_at(address) else {
        return None;
    };
    let available = section
        .vaddr
        .saturating_add(section.size)
        .saturating_sub(address)
        .min(15);
    let Some(bytes) = image.read_vaddr(address, available) else {
        return None;
    };
    // These adjust only the Windows x64 object argument before a tail jump.
    let size = if bytes.starts_with(&[
        0x31, 0xc0, 0x2b, 0x41, 0xfc, 0x48, 0x98, 0x48, 0x01, 0xc1, 0xe9,
    ]) {
        15
    } else if bytes.starts_with(&[0x48, 0x83, 0xc1]) && bytes.get(4) == Some(&0xe9) {
        9
    } else if bytes.starts_with(&[0x48, 0x81, 0xc1]) && bytes.get(7) == Some(&0xe9) {
        12
    } else {
        return None;
    };
    let Some(displacement) = bytes.get(size - 4..size) else {
        return None;
    };
    let displacement =
        i32::from_le_bytes(displacement.try_into().expect("a four-byte displacement"));
    let Some(end) = address.checked_add(size as u64) else {
        return None;
    };
    let Some(target) = end.checked_add_signed(i64::from(displacement)) else {
        return None;
    };
    if (address..end).contains(&target)
        || !image
            .section_at(target)
            .is_some_and(|section| section.executable)
    {
        return None;
    }
    Some(Thunk {
        target,
        size: size as u64,
    })
}

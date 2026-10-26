//! Runtime type layouts for 64-bit, little-endian Go images.

use std::collections::{BTreeMap, BTreeSet};

use crate::ir::{CType, Definition, Member};
use crate::loader::{Image, Isa};

#[derive(Debug, Default)]
pub(crate) struct Types {
    pub(crate) layouts: BTreeMap<u64, Layout>,
    start: u64,
    end: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct Layout {
    pub(crate) definition: Definition,
    pub(crate) members: Vec<Member>,
}

struct Reader<'a> {
    image: &'a Image,
    start: u64,
    end: u64,
}

impl Reader<'_> {
    fn bytes(&self, addr: u64, size: u64) -> Option<&[u8]> {
        let Some(end) = addr.checked_add(size) else {
            return None;
        };
        if addr < self.start || end > self.end {
            return None;
        }
        self.image.read_vaddr(addr, size)
    }

    fn word(&self, addr: u64) -> Option<u64> {
        self.bytes(addr, 8)
            .map(|bytes| u64::from_le_bytes(bytes.try_into().expect("eight bytes")))
    }

    fn name(&self, addr: u64) -> Option<String> {
        let mut length = 0u64;
        for index in 0..5 {
            let Some(at) = addr.checked_add(1 + index) else {
                return None;
            };
            let Some(bytes) = self.bytes(at, 1) else {
                return None;
            };
            length |= u64::from(bytes[0] & 127) << (7 * index);
            if bytes[0] & 128 == 0 {
                if length == 0 || length > 4096 {
                    return None;
                }
                let Some(at) = at.checked_add(1) else {
                    return None;
                };
                let Some(bytes) = self.bytes(at, length) else {
                    return None;
                };
                return std::str::from_utf8(bytes).ok().map(str::to_owned);
            }
        }
        None
    }

    fn header(&self, addr: u64) -> Option<(u64, u8, u8)> {
        let Some(bytes) = self.bytes(addr, 48) else {
            return None;
        };
        let size = u64::from_le_bytes(bytes[..8].try_into().expect("eight bytes"));
        let align = bytes[21];
        if size > 1 << 30 || !align.is_power_of_two() || align > 8 || bytes[22] != align {
            return None;
        }
        Some((size, align, bytes[23] & 31))
    }

    fn scalar(&self, addr: u64) -> Option<(CType, u64, u8)> {
        let Some((size, align, kind)) = self.header(addr) else {
            return None;
        };
        let ty = match (kind, size, align) {
            (1 | 8, 1, 1) => CType::int(1, false),
            (3, 1, 1) => CType::int(1, true),
            (4, 2, 2) => CType::int(2, true),
            (5, 4, 4) => CType::int(4, true),
            (2 | 6, 8, 8) => CType::I64,
            (9, 2, 2) => CType::int(2, false),
            (10, 4, 4) => CType::int(4, false),
            (7 | 11 | 12, 8, 8) => CType::U64,
            (22 | 26, 8, 8) => CType::pointer_to(CType::Void),
            (24, 16, 8) => CType::Named("struct go_string".into()),
            (23, 24, 8) => CType::Named("struct go_slice".into()),
            (20, 16, 8) => CType::Named("struct go_iface".into()),
            _ => return None,
        };
        Some((ty, size, align))
    }

    fn structure(&self, addr: u64) -> Option<Layout> {
        let Some((size, align, 25)) = self.header(addr) else {
            return None;
        };
        let Some(header) = self.bytes(addr, 80) else {
            return None;
        };
        let name_offset = i32::from_le_bytes(header[40..44].try_into().expect("four bytes"));
        let Some(name_addr) = self.start.checked_add_signed(i64::from(name_offset)) else {
            return None;
        };
        let Some(mut name) = self.name(name_addr) else {
            return None;
        };
        if header[20] & 2 != 0 {
            let Some(short) = name.strip_prefix('*') else {
                return None;
            };
            name = short.to_owned();
        }
        let name = format!("go_{}_{addr:x}", crate::render::sanitize(&name));
        let fields = u64::from_le_bytes(header[56..64].try_into().expect("eight bytes"));
        let count = u64::from_le_bytes(header[64..72].try_into().expect("eight bytes"));
        let capacity = u64::from_le_bytes(header[72..80].try_into().expect("eight bytes"));
        if count == 0 || count > 4096 || count > capacity {
            return None;
        }
        let mut declarations = Vec::new();
        let mut members = Vec::new();
        let mut names = BTreeSet::new();
        let mut contains = BTreeSet::new();
        let mut end = 0;
        let mut max_align = 1;
        for index in 0..count {
            let Some(at) = fields.checked_add(index * 24) else {
                return None;
            };
            let Some(bytes) = self.bytes(at, 24) else {
                return None;
            };
            let word = |at| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"));
            let Some(field_name) = self.name(word(0)) else {
                return None;
            };
            let field_name = crate::render::sanitize(&field_name);
            if field_name.is_empty()
                || field_name.starts_with(|c: char| c.is_ascii_digit())
                || field_name.starts_with("go_padding_")
                || crate::render::reserved_identifier(&field_name)
                || !names.insert(field_name.clone())
            {
                return None;
            }
            let Some((ty, width, field_align)) = self.scalar(word(8)) else {
                return None;
            };
            let offset = word(16);
            let Some(next) = offset.checked_add(width) else {
                return None;
            };
            if offset < end || next > size || offset % u64::from(field_align) != 0 {
                return None;
            }
            max_align = max_align.max(field_align);
            if offset > end {
                declarations.push(format!("uint8_t go_padding_{end:x}[{}];", offset - end));
            }
            declarations.push(format!("{ty} {field_name};"));
            let shape = match &ty {
                CType::Named(name) => Some(name.clone()),
                _ => None,
            };
            if let Some(shape) = shape {
                contains.insert(shape.clone());
                for (part, part_ty, part_offset) in shape_fields(&shape) {
                    members.push(Member {
                        structure: name.clone(),
                        offset: (offset + part_offset) as i64,
                        name: format!("{field_name}.{part}"),
                        ty: part_ty,
                        width: 8,
                    });
                }
            } else {
                members.push(Member {
                    structure: name.clone(),
                    offset: offset as i64,
                    name: field_name,
                    ty,
                    width,
                });
            }
            end = next;
        }
        if max_align != align || size % u64::from(align) != 0 {
            return None;
        }
        if end < size {
            declarations.push(format!("uint8_t go_padding_{end:x}[{}];", size - end));
        }
        Some(Layout {
            definition: Definition {
                name: format!("struct {name}"),
                members: declarations,
                fields: members.iter().map(|member| member.name.clone()).collect(),
                contains: contains.into_iter().collect(),
                size,
                alignment: None,
                compatible_profiles: Vec::new(),
            },
            members,
        })
    }
}

pub(crate) fn shape_fields(name: &str) -> Vec<(&'static str, CType, u64)> {
    let pointer = CType::pointer_to(CType::Void);
    match name {
        "struct go_string" => vec![
            ("ptr", CType::pointer_to(CType::int(1, false)), 0),
            ("len", CType::I64, 8),
        ],
        "struct go_slice" => vec![
            ("ptr", pointer, 0),
            ("len", CType::I64, 8),
            ("cap", CType::I64, 16),
        ],
        "struct go_iface" => vec![("type", pointer.clone(), 0), ("data", pointer, 8)],
        _ => Vec::new(),
    }
}

pub(crate) fn shapes() -> Vec<Definition> {
    ["struct go_string", "struct go_slice", "struct go_iface"]
        .into_iter()
        .map(|name| {
            let fields = shape_fields(name);
            Definition {
                name: name.into(),
                members: fields
                    .iter()
                    .map(|(field, ty, _)| format!("{ty} {field};"))
                    .collect(),
                fields: fields.iter().map(|(field, _, _)| (*field).into()).collect(),
                contains: Vec::new(),
                size: fields.len() as u64 * 8,
                alignment: None,
                compatible_profiles: Vec::new(),
            }
        })
        .collect()
}

pub(crate) fn read(image: &Image) -> Types {
    let mut types = Types::default();
    if !image.go
        || !matches!(image.isa, Isa::X86_64 | Isa::AArch64)
        || image.byte_order() != Some(object::Endianness::Little)
    {
        return types;
    }
    let Some(tab) = super::pclntab(image) else {
        return types;
    };
    if image.read_vaddr(tab.vaddr, 8) != Some(&[0xf1, 0xff, 0xff, 0xff, 0, 0, 1, 8])
        && image.read_vaddr(tab.vaddr, 8) != Some(&[0xf1, 0xff, 0xff, 0xff, 0, 0, 4, 8])
    {
        return types;
    }
    let Some(module) = super::moduledata(image, tab.vaddr) else {
        return types;
    };
    let Some(data) = image.read_vaddr(module, super::MODULE_TYPE_DATA_SIZE) else {
        return types;
    };
    let word = |at| u64::from_le_bytes(data[at..at + 8].try_into().expect("eight bytes"));
    // Go 1.20 and later include coverage counters before the type region.
    let reader = Reader {
        image,
        start: word(super::MODULE_TYPES),
        end: word(super::MODULE_TYPES_END),
    };
    if reader.start >= reader.end {
        return types;
    }
    types.start = reader.start;
    types.end = reader.end;
    let mut pending = Vec::new();
    for (at, width) in [
        (super::MODULE_TYPE_LINKS, 4u64),
        (super::MODULE_INTERFACE_LINKS, 8),
    ] {
        let count = word(at + 8);
        if count > 100_000 || count > word(at + 16) {
            continue;
        }
        let Some(bytes) = image.read_vaddr(word(at), count * width) else {
            continue;
        };
        for bytes in bytes.chunks_exact(width as usize) {
            if width == 4 {
                let offset = i32::from_le_bytes(bytes.try_into().expect("four bytes"));
                if let Some(addr) = reader.start.checked_add_signed(i64::from(offset)) {
                    pending.push(addr);
                }
            } else {
                let addr = u64::from_le_bytes(bytes.try_into().expect("eight bytes"));
                if let Some(bytes) = image.read_vaddr(addr, 16) {
                    pending.extend(
                        bytes
                            .as_chunks::<8>()
                            .0
                            .iter()
                            .map(|word| u64::from_le_bytes(*word)),
                    );
                }
            }
        }
    }
    let mut visited = BTreeSet::new();
    while let Some(addr) = pending.pop() {
        if visited.len() >= 100_000 || !visited.insert(addr) {
            continue;
        }
        let Some((_, _, kind)) = reader.header(addr) else {
            continue;
        };
        if kind == 22 {
            if let Some(element) = addr.checked_add(48).and_then(|at| reader.word(at)) {
                pending.push(element);
            }
        } else if kind == 25
            && let Some(layout) = reader.structure(addr)
        {
            types.layouts.insert(addr, layout);
        }
    }
    types
}

impl Types {
    pub(crate) fn layout(&self, image: &Image, addr: u64) -> Option<Layout> {
        self.layouts.get(&addr).cloned().or_else(|| {
            Reader {
                image,
                start: self.start,
                end: self.end,
            }
            .structure(addr)
        })
    }
}

#[cfg(test)]
mod tests;

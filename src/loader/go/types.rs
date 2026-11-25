//! Runtime type layouts for 64-bit, little-endian Go images.

use std::collections::{BTreeMap, BTreeSet};

use crate::ir::{CType, Definition, Member};
use crate::loader::{Image, Isa};

#[derive(Debug, Default)]
pub(crate) struct Types {
    pub(crate) layouts: BTreeMap<u64, Layout>,
    /// The name of each type whose descriptor was reached, by the address
    /// of the descriptor, as Go writes the type.
    pub(crate) names: BTreeMap<u64, String>,
    /// The interface and the type each interface table joins, by the
    /// address of the table.
    pub(crate) tables: BTreeMap<u64, (u64, u64)>,
    /// The integer registers each function a method table holds returns
    /// in, as the types of its results fill them, by the address of the
    /// function. `None` where a result is a float or goes on the stack.
    pub(crate) methods: BTreeMap<u64, Option<usize>>,
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
        let alignment = bytes[21];
        if size > 1 << 30 || !alignment.is_power_of_two() || alignment > 8 || bytes[22] != alignment
        {
            return None;
        }
        Some((size, alignment, bytes[23] & 31))
    }

    /// The name the descriptor at `addr` gives its type.
    fn type_name(&self, addr: u64) -> Option<String> {
        let Some(header) = self.bytes(addr, 48) else {
            return None;
        };
        let offset = i32::from_le_bytes(header[40..44].try_into().expect("four bytes"));
        let Some(name) = self
            .start
            .checked_add_signed(i64::from(offset))
            .and_then(|at| self.name(at))
        else {
            return None;
        };
        // The name of a pointer to the type is kept, for both.
        if header[20] & 2 == 0 {
            Some(name)
        } else {
            name.strip_prefix('*').map(str::to_owned)
        }
    }

    /// The descriptors the one at `addr`, of `kind`, names: the types of
    /// its elements, fields, parameters and methods, and the pointer to it.
    fn referenced(&self, addr: u64, kind: u8) -> Vec<u64> {
        let word = |at: u64| addr.checked_add(at).and_then(|at| self.word(at));
        // A type named by its distance from the start of the region.
        let offset = |at: Option<u64>| {
            let Some(bytes) = at.and_then(|at| self.bytes(at, 4)) else {
                return None;
            };
            let offset = i32::from_le_bytes(bytes.try_into().expect("four bytes"));
            (offset > 0)
                .then(|| self.start.checked_add_signed(i64::from(offset)))
                .flatten()
        };
        let mut found: Vec<Option<u64>> = vec![offset(addr.checked_add(44))];
        match kind {
            17 => found.extend([word(48), word(56)]),
            18 | 22 | 23 => found.push(word(48)),
            21 => found.extend([word(48), word(56)]),
            19 => {
                let counts = self.bytes(addr + 48, 4).map(|bytes| {
                    let inputs = u16::from_le_bytes([bytes[0], bytes[1]]);
                    let outputs = u16::from_le_bytes([bytes[2], bytes[3]]) & 0x7fff;
                    u64::from(inputs) + u64::from(outputs)
                });
                let methods = self
                    .bytes(addr + 20, 1)
                    .is_some_and(|flags| flags[0] & 1 != 0);
                let first = if methods { 72 } else { 56 };
                for index in 0..counts.unwrap_or(0).min(512) {
                    found.push(word(first + index * 8));
                }
            }
            20 => {
                if let (Some(methods), Some(count)) = (word(56), word(64)) {
                    for index in 0..count.min(4096) {
                        found.push(offset(methods.checked_add(index * 8 + 4)));
                    }
                }
            }
            25 => {
                if let (Some(fields), Some(count)) = (word(56), word(64)) {
                    for index in 0..count.min(4096) {
                        found.push(
                            fields
                                .checked_add(index * 24 + 8)
                                .and_then(|at| self.word(at)),
                        );
                    }
                }
            }
            _ => {}
        }
        found.into_iter().flatten().collect()
    }

    /// The integer registers a value of the type at `addr` fills when Go
    /// passes it in registers: one for each word of a string, a slice or
    /// an interface, and those of each field of a structure. `None` for
    /// a type with a float in it and for an array of several elements,
    /// which is passed on the stack.
    fn registers(&self, addr: u64, depth: u8) -> Option<usize> {
        let Some((size, _, kind)) = self.header(addr) else {
            return None;
        };
        if size == 0 {
            return Some(0);
        }
        match kind {
            1..=12 | 18 | 19 | 21 | 22 | 26 => Some(1),
            20 | 24 => Some(2),
            23 => Some(3),
            17 if depth < 8 && self.word(addr + 64) == Some(1) => self
                .word(addr + 48)
                .and_then(|element| self.registers(element, depth + 1)),
            25 if depth < 8 => {
                let (Some(fields), Some(count)) = (self.word(addr + 56), self.word(addr + 64))
                else {
                    return None;
                };
                let mut total = 0;
                for index in 0..count.min(4096) {
                    let Some(field) = fields
                        .checked_add(index * 24 + 8)
                        .and_then(|at| self.word(at))
                        .and_then(|field| self.registers(field, depth + 1))
                    else {
                        return None;
                    };
                    total += field;
                }
                Some(total)
            }
            _ => None,
        }
    }

    /// The methods the descriptor at `addr`, of `kind`, lists with their
    /// functions: each function's offset in the text, and the integer
    /// registers its results fill, no more than `limit`.
    fn methods(&self, addr: u64, kind: u8, limit: usize) -> Vec<(u32, Option<usize>)> {
        let mut found = Vec::new();
        let base = match kind {
            17 => 72,
            18 => 64,
            19 | 22 | 23 => 56,
            20 | 25 => 80,
            21 => 136,
            _ => 48,
        };
        let Some(record) = self.bytes(addr + base, 16) else {
            return found;
        };
        let count = u64::from(u16::from_le_bytes([record[4], record[5]]));
        let first = u64::from(u32::from_le_bytes(
            record[8..12].try_into().expect("four bytes"),
        ));
        for index in 0..count {
            let Some(entry) = self.bytes(addr + base + first + index * 16, 16) else {
                break;
            };
            let field = |at: usize| i32::from_le_bytes(entry[at..at + 4].try_into().expect("four"));
            let Some(signature) = (field(4) > 0)
                .then(|| self.start.checked_add_signed(i64::from(field(4))))
                .flatten()
            else {
                continue;
            };
            let Some((_, _, 19)) = self.header(signature) else {
                continue;
            };
            let Some(counts) = self.bytes(signature + 48, 4) else {
                continue;
            };
            let inputs = u64::from(u16::from_le_bytes([counts[0], counts[1]]));
            let outputs = u64::from(u16::from_le_bytes([counts[2], counts[3]]) & 0x7fff);
            let listed = self
                .bytes(signature + 20, 1)
                .is_some_and(|flags| flags[0] & 1 != 0);
            let types = signature + if listed { 72 } else { 56 };
            let mut results = Some(0);
            for index in inputs..inputs + outputs {
                let filled = self
                    .word(types + index * 8)
                    .and_then(|ty| self.registers(ty, 0));
                results = results.zip(filled).map(|(total, filled)| total + filled);
            }
            let results = results.filter(|total| *total <= limit);
            // The function an interface reaches, and the one called directly.
            for function in [field(8), field(12)] {
                if function >= 0 {
                    found.push((function as u32, results));
                }
            }
        }
        found
    }

    /// The interface tables laid one after another in the `length` bytes
    /// at `offset` of the region, as Go 1.27 keeps them: each is its
    /// interface, its type, a hash and one function for each method of
    /// the interface.
    fn tables(&self, offset: u64, length: u64) -> Vec<(u64, u64, u64)> {
        let mut found = Vec::new();
        let Some(mut at) = self.start.checked_add(offset) else {
            return found;
        };
        let Some(stop) = at.checked_add(length) else {
            return found;
        };
        while at < stop && found.len() < 100_000 {
            let (Some(interface), Some(ty)) = (self.word(at), self.word(at + 8)) else {
                break;
            };
            let Some((_, _, 20)) = self.header(interface) else {
                break;
            };
            let Some(methods) = self.word(interface + 64) else {
                break;
            };
            if methods == 0 || methods > 4096 {
                break;
            }
            found.push((at, interface, ty));
            at += 24 + methods * 8;
        }
        found
    }

    /// The type descriptors laid one after another in the first `length`
    /// bytes of the region, as Go 1.27 keeps them in place of a list of
    /// links; those before the first that does not read as one.
    fn descriptors(&self, length: u64) -> Vec<u64> {
        let mut found = Vec::new();
        let Some(stop) = self.start.checked_add(length) else {
            return found;
        };
        // One word comes before the first descriptor.
        let mut at = self.start.saturating_add(8);
        while at < stop && found.len() < 100_000 {
            let Some(size) = self.descriptor_size(at) else {
                break;
            };
            found.push(at);
            let Some(next) = at.checked_add(size) else {
                break;
            };
            at = next.next_multiple_of(8);
        }
        found
    }

    /// The bytes the descriptor at `addr` takes: its own fields by kind,
    /// the record of its methods when it has one, what its kind appends,
    /// and the methods.
    fn descriptor_size(&self, addr: u64) -> Option<u64> {
        let Some((_, _, kind)) = self.header(addr) else {
            return None;
        };
        let Some(flags) = self.bytes(addr + 20, 1) else {
            return None;
        };
        let count = |at: u64, size: u64| {
            self.bytes(addr + at, size).map(|bytes| {
                let mut word = [0; 8];
                word[..bytes.len()].copy_from_slice(bytes);
                u64::from_le_bytes(word)
            })
        };
        let (base, appended) = match kind {
            1..=16 | 24 | 26 => (48, 0),
            17 => (72, 0),
            18 => (64, 0),
            19 => {
                let (Some(inputs), Some(outputs)) = (count(48, 2), count(50, 2)) else {
                    return None;
                };
                (56, (inputs + (outputs & 0x7fff)) * 8)
            }
            20 => {
                let Some(methods) = count(64, 8) else {
                    return None;
                };
                (80, methods.saturating_mul(8))
            }
            21 => (136, 0),
            22 | 23 => (56, 0),
            25 => {
                let Some(fields) = count(64, 8) else {
                    return None;
                };
                (80, fields.saturating_mul(24))
            }
            _ => return None,
        };
        let methods = if flags[0] & 1 == 0 {
            0
        } else {
            let Some(methods) = count(base + 4, 2) else {
                return None;
            };
            16 + methods * 16
        };
        base.checked_add(appended)
            .and_then(|size| size.checked_add(methods))
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
    let Some(layout) = super::module_layout(image, module, tab.vaddr) else {
        return types;
    };
    let word = |at: u64| {
        module
            .checked_add(at)
            .and_then(|address| super::u64_at(image, address))
            .unwrap_or(0)
    };
    // Go 1.20 and later include coverage counters before the type region.
    let reader = Reader {
        image,
        start: word(super::MODULE_TYPES),
        end: word(layout.types_end),
    };
    if reader.start >= reader.end {
        return types;
    }
    types.start = reader.start;
    types.end = reader.end;
    let mut pending = Vec::new();
    let links = layout
        .links
        .map(|(types, interfaces)| [(types, 4u64), (interfaces, 8)]);
    for (at, width) in links.into_iter().flatten() {
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
                    let (words, _) = bytes.as_chunks::<8>();
                    let interface = u64::from_le_bytes(words[0]);
                    let ty = u64::from_le_bytes(words[1]);
                    types.tables.insert(addr, (interface, ty));
                    pending.extend([interface, ty]);
                }
            }
        }
    }
    if layout.links.is_none() {
        pending.extend(reader.descriptors(word(304)));
        for (addr, interface, ty) in reader.tables(word(320), word(328)) {
            types.tables.insert(addr, (interface, ty));
            pending.extend([interface, ty]);
        }
    }
    let text = word(super::MODULE_TEXT);
    let registers = if image.isa == Isa::X86_64 { 9 } else { 16 };
    let flags = |addr: u64| reader.bytes(addr + 20, 1).map_or(0, |flags| flags[0]);
    let mut visited = BTreeSet::new();
    while let Some(addr) = pending.pop() {
        if visited.len() >= 100_000 || !visited.insert(addr) {
            continue;
        }
        let Some((_, _, kind)) = reader.header(addr) else {
            continue;
        };
        if !(1..=26).contains(&kind) {
            continue;
        }
        let Some(name) = reader.type_name(addr) else {
            continue;
        };
        types.names.insert(addr, name);
        if flags(addr) & 1 != 0 {
            for (offset, results) in reader.methods(addr, kind, registers) {
                let function = text.wrapping_add(u64::from(offset));
                // A function two tables hold keeps what they agree on.
                types
                    .methods
                    .entry(function)
                    .and_modify(|known| {
                        if *known != results {
                            *known = None;
                        }
                    })
                    .or_insert(results);
            }
        }
        pending.extend(reader.referenced(addr, kind));
        if kind == 25
            && let Some(layout) = reader.structure(addr)
        {
            types.layouts.insert(addr, layout);
        }
    }
    types.tables.retain(|_, (interface, ty)| {
        types.names.contains_key(interface) && types.names.contains_key(ty)
    });
    types
}

impl Types {
    pub(crate) fn layout(&self, image: &Image, addr: u64) -> Option<Layout> {
        self.layouts.get(&addr).cloned().or_else(|| {
            let reader = Reader {
                image,
                start: self.start,
                end: self.end,
            };
            if let Some(layout) = reader.structure(addr) {
                return Some(layout);
            }
            let Some((CType::Named(name), _, _)) = reader.scalar(addr) else {
                return None;
            };
            let Some(definition) = shapes().into_iter().find(|shape| shape.name == name) else {
                return None;
            };
            let members = shape_fields(&name)
                .into_iter()
                .map(|(field, ty, offset)| Member {
                    structure: name.trim_start_matches("struct ").to_owned(),
                    offset: offset as i64,
                    name: field.to_owned(),
                    ty,
                    width: 8,
                })
                .collect();
            Some(Layout {
                definition,
                members,
            })
        })
    }
}

#[cfg(test)]
mod tests;

//! Windows x64 language-specific exception tables.

use object::Object;

use super::{Image, Isa, NameSource, unwind, upsert};

#[derive(Debug)]
pub(crate) struct Handler {
    pub function: u64,
    pub address: u64,
    pub data: u64,
    pub name: Option<String>,
    pub scopes: Vec<Scope>,
    pub catches: Vec<(i32, i32, u64)>,
}

#[derive(Debug)]
pub(crate) struct Scope {
    pub begin: u64,
    pub end: u64,
    pub filter: u32,
    pub handler: u64,
    pub target: Option<u64>,
}

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_bytes(image: &Image, address: u64, size: u64) -> Option<&[u8]> {
    let Some(section) = image.section_at(address) else {
        return None;
    };
    if address
        .checked_add(size)
        .is_none_or(|end| end > section.vaddr.saturating_add(section.size))
    {
        return None;
    }
    image.read_vaddr(address, size)
}

fn code(image: &Image, address: u64) -> bool {
    image.section_at(address).is_some_and(|s| s.executable)
        && read_bytes(image, address, 1).is_some()
}

pub(super) fn read(image: &Image) -> Vec<Handler> {
    if image.isa != Isa::X86_64 {
        return Vec::new();
    }
    let Ok(file) = object::read::pe::PeFile64::parse(image.bytes.as_slice()) else {
        return Vec::new();
    };
    let Some(directory) = file.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION) else {
        return Vec::new();
    };
    let Ok(entries) = directory.data(file.data(), &file.section_table()) else {
        return Vec::new();
    };
    let base = file.relative_address_base();
    let frames: std::collections::BTreeMap<_, _> = unwind::frames(image)
        .into_iter()
        .map(|frame| (frame.start, frame.size))
        .collect();
    let mut handlers = Vec::new();
    for entry in entries.as_chunks::<12>().0 {
        let (Some(function), Some(unwind)) = (
            base.checked_add(u64::from(word(entry, 0))),
            base.checked_add(u64::from(word(entry, 8))),
        ) else {
            continue;
        };
        if word(entry, 8) & 3 != 0 {
            continue;
        }
        if frames.get(&function).copied()
            != Some(u64::from(word(entry, 4)).saturating_sub(u64::from(word(entry, 0))))
        {
            continue;
        }
        let Some(header) = read_bytes(image, unwind, 4) else {
            continue;
        };
        if header[0] & 7 != 1
            || header[0] >> 3 & 3 == 0
            || header[0] >> 3 & !3 != 0
            || u64::from(header[1]) > frames[&function]
        {
            continue;
        }
        let aligned_size = 4 + u64::from(header[2]).div_ceil(2) * 4;
        if read_bytes(image, unwind, aligned_size).is_none() {
            continue;
        }
        let Some(handler_data) = unwind.checked_add(aligned_size) else {
            continue;
        };
        let Some(bytes) = read_bytes(image, handler_data, 8) else {
            continue;
        };
        let (Some(address), Some(data)) = (
            base.checked_add(u64::from(word(bytes, 0))),
            handler_data.checked_add(4),
        ) else {
            continue;
        };
        if !code(image, address) {
            continue;
        }
        let name = image.functions.get(&address).and_then(|f| f.name.clone());
        let mut handler = Handler {
            function,
            address,
            data,
            name,
            scopes: Vec::new(),
            catches: Vec::new(),
        };
        match handler.name.as_deref() {
            Some("__C_specific_handler") => {
                let count = u64::from(word(bytes, 4));
                let Some(table) = read_bytes(image, data.saturating_add(4), count * 16) else {
                    continue;
                };
                for row in table.as_chunks::<16>().0 {
                    let (Some(begin), Some(end), Some(action), Some(target)) = (
                        base.checked_add(u64::from(word(row, 0))),
                        base.checked_add(u64::from(word(row, 4))),
                        base.checked_add(u64::from(word(row, 8))),
                        base.checked_add(u64::from(word(row, 12))),
                    ) else {
                        continue;
                    };
                    let filter = word(row, 8);
                    let finally = word(row, 12) == 0;
                    if begin < function
                        || end <= begin
                        || end > function.saturating_add(frames[&function])
                        || (!finally && !code(image, target))
                        || ((finally || filter != 1) && !code(image, action))
                    {
                        continue;
                    }
                    handler.scopes.push(Scope {
                        begin,
                        end,
                        filter,
                        handler: action,
                        target: if finally { None } else { Some(target) },
                    });
                }
            }
            Some("__CxxFrameHandler3") => {
                let Some(info) = base.checked_add(u64::from(word(bytes, 4))) else {
                    continue;
                };
                handler.data = info;
                read_catches(image, base, info, &mut handler.catches);
            }
            _ => {}
        }
        handlers.push(handler);
    }
    handlers
}

fn read_catches(image: &Image, base: u64, info: u64, catches: &mut Vec<(i32, i32, u64)>) {
    let Some(header) = read_bytes(image, info, 40) else {
        return;
    };
    if word(header, 0) & 0x1fff_ffff != 0x1993_0522 {
        return;
    }
    let Some(table) = base.checked_add(u64::from(word(header, 16))) else {
        return;
    };
    let Some(rows) = read_bytes(image, table, u64::from(word(header, 12)) * 20) else {
        return;
    };
    for row in rows.as_chunks::<20>().0 {
        let low = word(row, 0) as i32;
        let high = word(row, 4) as i32;
        if low < 0 || high < low || word(row, 8) as i32 <= high || word(row, 8) >= word(header, 4) {
            continue;
        }
        let Some(table) = base.checked_add(u64::from(word(row, 16))) else {
            continue;
        };
        let Some(entries) = read_bytes(image, table, u64::from(word(row, 12)) * 20) else {
            continue;
        };
        for entry in entries.as_chunks::<20>().0 {
            let Some(address) = base.checked_add(u64::from(word(entry, 12))) else {
                continue;
            };
            if code(image, address) {
                catches.push((low, high, address));
            }
        }
    }
}

pub(super) fn discover(image: &mut Image) {
    for handler in &image.exception_handlers {
        let parent = image
            .functions
            .get(&handler.function)
            .and_then(|f| f.name.clone())
            .unwrap_or_else(|| format!("sub_{:x}", handler.function));
        for (index, scope) in handler.scopes.iter().enumerate() {
            let (address, role) = if scope.target.is_none() {
                (scope.handler, "finally")
            } else if scope.filter != 1 {
                (scope.handler, "except_filter")
            } else {
                continue;
            };
            upsert(
                &mut image.functions,
                address,
                Some(format!("{parent}__{role}_{index}")),
                None,
                NameSource::Unwind,
            );
        }
        // Exception targets in a scope table are blocks in the parent frame,
        // not independently callable function entries.
        for (index, &(_, _, address)) in handler.catches.iter().enumerate() {
            if address == handler.function {
                continue;
            }
            upsert(
                &mut image.functions,
                address,
                Some(format!("{parent}__catch_{index}")),
                None,
                NameSource::Unwind,
            );
        }
    }
}

#[cfg(test)]
mod tests;

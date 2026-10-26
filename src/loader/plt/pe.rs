use std::collections::{HashMap, HashSet};

use object::read::pe::Import;
use object::{LittleEndian, Object, ObjectSection};

struct NamedImport {
    name: String,
    dll: String,
}

pub(super) fn imports<Pe: object::read::pe::ImageNtHeaders>(
    file: &object::read::pe::PeFile<'_, Pe>,
) -> HashMap<u64, String> {
    named_imports(file)
        .into_iter()
        .map(|(slot, import)| (slot, import.name))
        .collect()
}

pub(super) fn qualified_imports<Pe: object::read::pe::ImageNtHeaders>(
    file: &object::read::pe::PeFile<'_, Pe>,
) -> HashMap<u64, String> {
    named_imports(file)
        .into_iter()
        .map(|(slot, import)| (slot, format!("{}!{}", import.dll, import.name)))
        .collect()
}

fn named_imports<Pe: object::read::pe::ImageNtHeaders>(
    file: &object::read::pe::PeFile<'_, Pe>,
) -> HashMap<u64, NamedImport> {
    let word = if file.is_64() { 8 } else { 4 };
    let Ok(Some(table)) = file.import_table() else {
        return HashMap::new();
    };
    let Ok(mut descriptors) = table.descriptors() else {
        return HashMap::new();
    };
    let mut imports = HashMap::new();
    while let Ok(Some(descriptor)) = descriptors.next() {
        let Ok(dll) = table.name(descriptor.name.get(LittleEndian)) else {
            continue;
        };
        let dll = String::from_utf8_lossy(dll).to_ascii_lowercase();
        let first = descriptor.first_thunk.get(LittleEndian);
        if first == 0 {
            continue;
        }
        let lookup = descriptor.original_first_thunk.get(LittleEndian);
        let Ok(mut thunks) = table.thunks(if lookup == 0 { first } else { lookup }) else {
            continue;
        };
        let Some(mut slot) = file.relative_address_base().checked_add(u64::from(first)) else {
            continue;
        };
        let mut rva = first;
        while let Ok(Some(thunk)) = thunks.next::<Pe>() {
            if file
                .section_table()
                .pe_data_at(file.data(), rva)
                .is_none_or(|data| data.len() < word as usize)
            {
                break;
            }
            if let Ok(Import::Name(_, name)) = table.import::<Pe>(thunk)
                && !name.is_empty()
            {
                imports.insert(
                    slot,
                    NamedImport {
                        name: String::from_utf8_lossy(name).into_owned(),
                        dll: dll.clone(),
                    },
                );
            }
            let Some(next) = slot.checked_add(word) else {
                break;
            };
            slot = next;
            let Some(next) = rva.checked_add(word as u32) else {
                break;
            };
            rva = next;
        }
    }
    imports
}

pub(super) fn stubs<Pe: object::read::pe::ImageNtHeaders>(
    file: &object::read::pe::PeFile<'_, Pe>,
) -> Vec<(u64, String)> {
    if !matches!(
        file.architecture(),
        object::Architecture::I386 | object::Architecture::X86_64
    ) {
        return Vec::new();
    }
    let imports = imports(file);
    let mut stubs = Vec::new();
    for section in file.sections() {
        if section.kind() != object::SectionKind::Text {
            continue;
        }
        let Ok(bytes) = section.data() else { continue };
        let returns: HashSet<_> = if file.architecture() == object::Architecture::I386 {
            iced_x86::Decoder::with_ip(32, bytes, section.address(), iced_x86::DecoderOptions::NONE)
                .into_iter()
                .filter(|ins| ins.flow_control() == iced_x86::FlowControl::Return)
                .map(|ins| ins.next_ip())
                .collect()
        } else {
            Default::default()
        };
        for (address, slot) in super::x86_slots_mode(
            bytes,
            section.address(),
            if file.is_64() { 64 } else { 32 },
            None,
        ) {
            let Some(offset) = address.checked_sub(section.address()) else {
                continue;
            };
            let Ok(offset) = usize::try_from(offset) else {
                continue;
            };
            if offset != 0
                && !matches!(bytes.get(offset - 1), Some(0xcc | 0x90))
                && !returns.contains(&address)
            {
                continue;
            }
            if let Some(name) = imports.get(&slot) {
                stubs.push((address, name.clone()));
            }
        }
    }
    stubs
}

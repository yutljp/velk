use std::collections::HashMap;

use object::read::pe::Import;
use object::{LittleEndian, Object, ObjectSection};

pub(super) fn imports(file: &object::read::pe::PeFile64<'_>) -> HashMap<u64, String> {
    let Ok(Some(table)) = file.import_table() else {
        return HashMap::new();
    };
    let Ok(mut descriptors) = table.descriptors() else {
        return HashMap::new();
    };
    let mut imports = HashMap::new();
    while let Ok(Some(descriptor)) = descriptors.next() {
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
        while let Ok(Some(thunk)) = thunks.next::<object::pe::ImageNtHeaders64>() {
            if file
                .section_table()
                .pe_data_at(file.data(), rva)
                .is_none_or(|data| data.len() < 8)
            {
                break;
            }
            if let Ok(Import::Name(_, name)) = table.import::<object::pe::ImageNtHeaders64>(thunk)
                && !name.is_empty()
            {
                imports.insert(slot, String::from_utf8_lossy(name).into_owned());
            }
            let Some(next) = slot.checked_add(8) else {
                break;
            };
            slot = next;
            let Some(next) = rva.checked_add(8) else {
                break;
            };
            rva = next;
        }
    }
    imports
}

pub(super) fn stubs(file: &object::read::pe::PeFile64<'_>) -> Vec<(u64, String)> {
    if file.architecture() != object::Architecture::X86_64 {
        return Vec::new();
    }
    let imports = imports(file);
    let mut stubs = Vec::new();
    for section in file.sections() {
        if section.kind() != object::SectionKind::Text {
            continue;
        }
        let Ok(bytes) = section.data() else { continue };
        for (address, slot) in super::x86_slots(bytes, section.address()) {
            let Some(offset) = address.checked_sub(section.address()) else {
                continue;
            };
            let Ok(offset) = usize::try_from(offset) else {
                continue;
            };
            if offset != 0 && !matches!(bytes.get(offset - 1), Some(0xcc | 0x90)) {
                continue;
            }
            if let Some(name) = imports.get(&slot) {
                stubs.push((address, name.clone()));
            }
        }
    }
    stubs
}

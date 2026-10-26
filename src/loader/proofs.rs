//! Bounded checks of the object readers used by the loader.

use object::{Object, ObjectSection};

fn tables<'data>(file: impl Object<'data>) {
    for section in file.sections() {
        let _ = section.name();
        let _ = section.data();
        for _ in section.relocations() {}
    }
}

#[kani::proof]
#[kani::unwind(132)]
fn elf_tables() {
    let bytes: [u8; 128] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    if let Ok(file) = object::read::elf::ElfFile32::<object::Endianness>::parse(&bytes[..len]) {
        tables(file);
    }
    if let Ok(file) = object::read::elf::ElfFile64::<object::Endianness>::parse(&bytes[..len]) {
        tables(file);
    }
}

#[kani::proof]
#[kani::unwind(516)]
fn pe_tables() {
    let bytes: [u8; 512] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    if let Ok(file) = object::read::pe::PeFile32::parse(&bytes[..len]) {
        tables(file);
    }
    if let Ok(file) = object::read::pe::PeFile64::parse(&bytes[..len]) {
        tables(file);
    }
}

#[kani::proof]
#[kani::unwind(132)]
fn macho_tables() {
    let bytes: [u8; 128] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    if let Ok(file) = object::read::macho::MachOFile32::<object::Endianness>::parse(&bytes[..len]) {
        tables(file);
    }
    if let Ok(file) = object::read::macho::MachOFile64::<object::Endianness>::parse(&bytes[..len]) {
        tables(file);
    }
}

#[kani::proof]
#[kani::unwind(20)]
fn image_ranges() {
    let bytes: [u8; 16] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    let image = super::Image::from_code(super::Isa::X86_64, 0, bytes[..len].to_vec());
    let offset: u64 = kani::any();
    let size: u64 = kani::any();
    let result = image.read(offset, size);
    assert_eq!(
        result.is_some(),
        offset <= len as u64 && size <= len as u64 - offset
    );
    if let Some(data) = result {
        assert_eq!(data.len() as u64, size);
    }
}

#[kani::proof]
#[kani::unwind(36)]
fn dwarf_units() {
    let bytes: [u8; 32] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    let debug = gimli::DebugInfo::new(&bytes[..len], gimli::LittleEndian);
    let mut units = debug.units();
    while let Ok(Some(unit)) = units.next() {
        assert!(unit.length_including_self() <= len);
    }
}

#[kani::proof]
#[kani::unwind(36)]
fn unwind_entries() {
    use gimli::UnwindSection;
    let bytes: [u8; 32] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    let frame = gimli::EhFrame::new(&bytes[..len], gimli::LittleEndian);
    let bases = gimli::BaseAddresses::default();
    let mut entries = frame.entries(&bases);
    while let Ok(Some(entry)) = entries.next() {
        if let gimli::CieOrFde::Fde(partial) = entry {
            let _ = partial.parse(gimli::EhFrame::cie_from_offset);
        }
    }
}

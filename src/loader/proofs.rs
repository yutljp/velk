//! Bounded checks of the object readers used by the loader.

use object::{Object, ObjectSection};

fn pe_tables<Pe: object::read::pe::ImageNtHeaders>(bytes: &[u8]) {
    let Ok(file) = object::read::pe::PeFile::<Pe>::parse(bytes) else {
        return;
    };
    for section in file.sections() {
        kani::cover!(true, "a section is visited");
        let data = section.data();
        if let Ok(data) = data {
            assert!(data.len() <= bytes.len());
            kani::cover!(!data.is_empty(), "nonempty section data is read");
        }
        // The generic PE iterator is empty; read the COFF table directly.
        if let Ok(relocations) = section.pe_section().coff_relocations(bytes) {
            assert!(relocations.len() <= 1);
            kani::cover!(!relocations.is_empty(), "a COFF relocation is read");
        }
    }
}

fn elf_tables<Elf: object::read::elf::FileHeader>(bytes: &[u8]) {
    use object::read::elf::SectionHeader;
    let header = Elf::parse(bytes).unwrap();
    let endian = header.endian().unwrap();
    let Ok(sections) = header.sections(endian, bytes) else {
        return;
    };
    for section in sections.iter() {
        kani::cover!(true, "a section is visited");
        if let Ok(data) = section.data(endian, bytes) {
            assert!(data.len() <= 24);
            kani::cover!(data.len() == 24, "the largest modeled section is read");
        }
        if let Ok(Some((entries, _))) = section.rel(endian, bytes) {
            kani::cover!(!entries.is_empty(), "a REL entry is read");
            assert!(std::mem::size_of_val(entries) <= 24);
        }
        if let Ok(Some((entries, _))) = section.rela(endian, bytes) {
            kani::cover!(!entries.is_empty(), "a RELA entry is read");
            assert!(std::mem::size_of_val(entries) <= 24);
        }
    }
}

fn macho_tables<Mach: object::read::macho::MachHeader>(bytes: &[u8]) {
    use object::read::macho::{Section, Segment};
    let header = Mach::parse(bytes, 0).unwrap();
    let endian = header.endian().unwrap();
    let mut commands = header.load_commands(endian, bytes, 0).unwrap();
    while let Ok(Some(command)) = commands.next() {
        if let Ok(Some((segment, data))) = Mach::Segment::from_command(command) {
            let sections = segment.sections(endian, data).unwrap();
            for entry in segment.section_offsets(endian, sections) {
                let Ok((section, offset)) = entry else {
                    continue;
                };
                kani::cover!(true, "a section is visited");
                if let Ok(data) = section.data(endian, bytes, offset) {
                    assert!(data.len() <= bytes.len());
                    kani::cover!(!data.is_empty(), "nonempty section data is read");
                }
                if let Ok(relocations) = section.relocations(endian, bytes) {
                    assert!(relocations.len() <= 1);
                    kani::cover!(!relocations.is_empty(), "a Mach-O relocation is read");
                }
            }
        }
    }
}

// One null section and one arbitrary section with at most twenty-four data bytes.
#[kani::proof]
#[kani::unwind(5)]
fn elf32_tables() {
    let mut bytes: [u8; 136] = kani::any();
    bytes[..16].copy_from_slice(b"\x7fELF\x01\x01\x01\0\0\0\0\0\0\0\0\0");
    bytes[46..52].copy_from_slice(&[40, 0, 2, 0, 1, 0]);
    bytes[32..36].copy_from_slice(&52u32.to_le_bytes());
    bytes[52..92].fill(0);
    kani::assume(u32::from_le_bytes(bytes[112..116].try_into().unwrap()) <= 24);
    bytes[28..32].fill(0); // No program headers.
    bytes[44..46].fill(0);
    elf_tables::<object::elf::FileHeader32<object::Endianness>>(&bytes);
}

#[kani::proof]
#[kani::unwind(5)]
fn elf64_tables() {
    let mut bytes: [u8; 200] = kani::any();
    bytes[..16].copy_from_slice(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0");
    bytes[58..64].copy_from_slice(&[64, 0, 2, 0, 1, 0]);
    bytes[40..48].copy_from_slice(&64u64.to_le_bytes());
    bytes[64..128].fill(0);
    kani::assume(u64::from_le_bytes(bytes[160..168].try_into().unwrap()) <= 24);
    bytes[32..40].fill(0);
    bytes[56..58].fill(0);
    elf_tables::<object::elf::FileHeader64<object::Endianness>>(&bytes);
}

#[kani::proof]
#[kani::unwind(3)]
fn pe32_tables() {
    let mut bytes: [u8; 352] = kani::any();
    bytes[..2].copy_from_slice(b"MZ");
    bytes[60..64].copy_from_slice(&64u32.to_le_bytes());
    bytes[64..68].copy_from_slice(b"PE\0\0");
    bytes[70..72].copy_from_slice(&1u16.to_le_bytes());
    bytes[76..84].fill(0);
    bytes[84..86].copy_from_slice(&224u16.to_le_bytes());
    bytes[88..90].copy_from_slice(&0x10bu16.to_le_bytes());
    bytes[180..184].fill(0); // No data directories.
    bytes[312] = 0;
    kani::assume(u16::from_le_bytes(bytes[344..346].try_into().unwrap()) <= 1);
    pe_tables::<object::pe::ImageNtHeaders32>(&bytes);
}

#[kani::proof]
#[kani::unwind(3)]
fn pe64_tables() {
    let mut bytes: [u8; 368] = kani::any();
    bytes[..2].copy_from_slice(b"MZ");
    bytes[60..64].copy_from_slice(&64u32.to_le_bytes());
    bytes[64..68].copy_from_slice(b"PE\0\0");
    bytes[70..72].copy_from_slice(&1u16.to_le_bytes());
    bytes[76..84].fill(0);
    bytes[84..86].copy_from_slice(&240u16.to_le_bytes());
    bytes[88..90].copy_from_slice(&0x20bu16.to_le_bytes());
    bytes[196..200].fill(0);
    bytes[328] = 0;
    kani::assume(u16::from_le_bytes(bytes[360..362].try_into().unwrap()) <= 1);
    pe_tables::<object::pe::ImageNtHeaders64>(&bytes);
}

#[kani::proof]
#[kani::unwind(3)]
fn macho32_tables() {
    let mut bytes: [u8; 152] = kani::any();
    bytes[..4].copy_from_slice(&0xfeed_faceu32.to_le_bytes());
    bytes[16..24].copy_from_slice(&[1, 0, 0, 0, 124, 0, 0, 0]);
    bytes[28..36].copy_from_slice(&[1, 0, 0, 0, 124, 0, 0, 0]);
    bytes[76..80].copy_from_slice(&1u32.to_le_bytes());
    bytes[84] = 0;
    kani::assume(u32::from_le_bytes(bytes[136..140].try_into().unwrap()) <= 1);
    macho_tables::<object::macho::MachHeader32<object::Endianness>>(&bytes);
}

#[kani::proof]
#[kani::unwind(3)]
fn macho64_tables() {
    let mut bytes: [u8; 184] = kani::any();
    bytes[..4].copy_from_slice(&0xfeed_facfu32.to_le_bytes());
    bytes[16..24].copy_from_slice(&[1, 0, 0, 0, 152, 0, 0, 0]);
    bytes[32..40].copy_from_slice(&[0x19, 0, 0, 0, 152, 0, 0, 0]);
    bytes[96..100].copy_from_slice(&1u32.to_le_bytes());
    bytes[104] = 0;
    kani::assume(u32::from_le_bytes(bytes[164..168].try_into().unwrap()) <= 1);
    macho_tables::<object::macho::MachHeader64<object::Endianness>>(&bytes);
}

#[kani::proof]
#[kani::unwind(17)]
fn image_ranges() {
    let bytes: [u8; 16] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    let offset: u64 = kani::any();
    let size: u64 = kani::any();
    let slice_offset: u64 = kani::any();
    let result = super::read_range(&bytes[..len], slice_offset, offset, size);
    let relative = offset.checked_sub(slice_offset);
    assert_eq!(
        result.is_some(),
        relative.is_some_and(|offset| offset <= len as u64 && size <= len as u64 - offset)
    );
    if let Some(data) = result {
        assert_eq!(data.len() as u64, size);
        let start = relative.unwrap() as usize;
        assert_eq!(data, &bytes[start..start + size as usize]);
    }
    kani::cover!(
        result.is_some() && size == 16,
        "the entire image range is read"
    );
    kani::cover!(
        offset < slice_offset && result.is_none(),
        "an address below the base is rejected"
    );
    kani::cover!(
        offset == u64::MAX && result.is_none(),
        "a maximal address is rejected"
    );
}

#[kani::proof]
#[kani::unwind(3)]
fn dwarf_units() {
    let mut bytes: [u8; 12] = kani::any();
    bytes[..6].copy_from_slice(&[8, 0, 0, 0, 4, 0]);
    bytes[10] = if kani::any() { 4 } else { 8 };
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    let debug = gimli::DebugInfo::new(&bytes[..len], gimli::LittleEndian);
    let mut units = debug.units();
    let unit = units.next();
    assert_eq!(matches!(unit, Ok(Some(_))), len == bytes.len());
    if let Ok(Some(unit)) = unit {
        assert_eq!(unit.length_including_self(), len);
        assert_eq!(unit.version(), 4);
        assert_eq!(unit.address_size(), bytes[10]);
        assert_eq!(
            unit.debug_abbrev_offset().0,
            u32::from_le_bytes(bytes[6..10].try_into().unwrap()) as usize
        );
        assert!(matches!(units.next(), Ok(None)));
        kani::cover!(
            unit.address_size() == 8,
            "a complete 64-bit-address unit is read"
        );
    }
    kani::cover!(len == 11, "a truncated unit is checked");
}

#[kani::proof]
#[kani::unwind(3)]
fn unwind_entries() {
    use gimli::UnwindSection;
    let mut bytes: [u8; 16] = kani::any();
    bytes[..10].copy_from_slice(&[12, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
    kani::assume(bytes[10] < 128 && bytes[11] < 128);
    let frame = gimli::EhFrame::new(&bytes, gimli::LittleEndian);
    let bases = gimli::BaseAddresses::default();
    let mut entries = frame.entries(&bases);
    let Some(gimli::CieOrFde::Cie(cie)) = entries.next().unwrap() else {
        panic!("the entry is a CIE");
    };
    assert_eq!(cie.code_alignment_factor(), u64::from(bytes[10]));
    let data_alignment = ((bytes[11] as i8) << 1) >> 1;
    assert_eq!(cie.data_alignment_factor(), i64::from(data_alignment));
    assert_eq!(cie.return_address_register().0, u16::from(bytes[12]));
    kani::cover!(data_alignment < 0, "a negative data alignment is decoded");
    assert!(matches!(entries.next(), Ok(None)));
}

fn check_unwind_fde(address_size: u8) {
    use gimli::UnwindSection;
    let mut bytes: [u8; 40] = kani::any();
    bytes[..16].copy_from_slice(&[12, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0x78, 16, 0, 0, 0]);
    let length = 4 + 2 * u32::from(address_size);
    bytes[16..20].copy_from_slice(&length.to_le_bytes());
    bytes[20..24].copy_from_slice(&20u32.to_le_bytes());
    let end = 24 + 2 * usize::from(address_size);
    let mut frame = gimli::EhFrame::new(&bytes[..end], gimli::LittleEndian);
    frame.set_address_size(address_size);
    let bases = gimli::BaseAddresses::default();
    let mut entries = frame.entries(&bases);
    assert!(matches!(entries.next(), Ok(Some(gimli::CieOrFde::Cie(_)))));
    let entry = entries.next().unwrap().unwrap();
    let gimli::CieOrFde::Fde(partial) = entry else {
        panic!("the second entry is an FDE");
    };
    let fde = partial.parse(gimli::EhFrame::cie_from_offset).unwrap();
    let address = if address_size == 4 {
        u64::from(u32::from_le_bytes(bytes[24..28].try_into().unwrap()))
    } else {
        u64::from_le_bytes(bytes[24..32].try_into().unwrap())
    };
    assert_eq!(fde.initial_address(), address);
    let range = if address_size == 4 {
        u64::from(u32::from_le_bytes(bytes[28..32].try_into().unwrap()))
    } else {
        u64::from_le_bytes(bytes[32..40].try_into().unwrap())
    };
    assert_eq!(fde.len(), range);
    kani::cover!(
        address == u64::MAX >> (64 - 8 * address_size),
        "the largest address is decoded"
    );
    kani::cover!(range > 0, "a nonempty function range is decoded");
    assert!(matches!(entries.next(), Ok(None)));
}

#[kani::proof]
#[kani::unwind(3)]
fn unwind_fde32() {
    check_unwind_fde(4);
}

#[kani::proof]
#[kani::unwind(3)]
fn unwind_fde64() {
    check_unwind_fde(8);
}

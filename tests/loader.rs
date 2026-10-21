//! What the loader reads where the program reads it: pointers a dynamic
//! loader fills, and data a damaged header places out of reach.

mod common;

use velk::service::Binary;

/// Dynamic relocations name symbols by their place in the dynamic symbol
/// table, which the full table, with static functions in it, numbers apart.
#[test]
fn dynamic_relocations_fill_the_symbols_they_name() {
    let binary = Binary::open(&common::fixtures_dir().join("shared_pointers_x64.so"))
        .unwrap_or_else(|error| panic!("{error}"));
    let image = binary.image();
    let address = |name: &str| {
        image
            .functions
            .values()
            .find(|function| function.name.as_deref() == Some(name))
            .map(|function| function.addr)
            .or_else(|| {
                image
                    .data_symbols
                    .iter()
                    .find(|(_, symbol)| *symbol == name)
                    .map(|(addr, _)| *addr)
            })
            .unwrap_or_else(|| panic!("no symbol {name}"))
    };
    let word = |addr: u64| {
        u64::from_le_bytes(
            image
                .read_vaddr(addr, 8)
                .expect("readable")
                .try_into()
                .expect("8 bytes"),
        )
    };
    let (target, pointer) = (address("target"), address("table_ptr"));
    assert_eq!(word(pointer), target, "table_ptr holds target");
    let got = image
        .sections
        .iter()
        .find(|section| section.name == ".got")
        .expect("a .got");
    assert!(
        (got.vaddr..got.vaddr + got.size)
            .step_by(8)
            .any(|slot| word(slot) == pointer),
        "a .got slot holds table_ptr"
    );
}

/// The ELF section header of `name` given the address `addr`.
fn place_section(bytes: &mut [u8], name: &[u8], addr: u64) {
    let read = |bytes: &[u8], at: usize, size: usize| {
        bytes[at..at + size]
            .iter()
            .rev()
            .fold(0u64, |value, byte| value << 8 | u64::from(*byte))
    };
    let headers = read(bytes, 0x28, 8) as usize;
    let entry = read(bytes, 0x3a, 2) as usize;
    let count = read(bytes, 0x3c, 2) as usize;
    let names = read(bytes, 0x3e, 2) as usize;
    let strings = read(bytes, headers + names * entry + 0x18, 8) as usize;
    for index in 0..count {
        let header = headers + index * entry;
        let start = strings + read(bytes, header, 4) as usize;
        if bytes[start..].starts_with(name) && bytes[start + name.len()] == 0 {
            bytes[header + 0x10..header + 0x18].copy_from_slice(&addr.to_le_bytes());
        }
    }
}

/// Code a damaged header places at the end of the address space loads,
/// lists and analyzes without overflowing an address.
#[test]
fn a_section_past_the_address_space_is_left_out() {
    for fixture in ["cpp_virtual_x64.elf", "l5_switch.elf", "cold_gcc"] {
        let mut bytes = std::fs::read(common::fixtures_dir().join(fixture)).expect("a fixture");
        place_section(&mut bytes, b".text", 0xffff_ffff_ffff_fff0);
        let path =
            std::env::temp_dir().join(format!("velk-placed-{}-{fixture}", std::process::id()));
        std::fs::write(&path, &bytes).expect("a scratch file");
        if let Ok(mut binary) = Binary::open(&path) {
            let addrs: Vec<u64> = binary.image().functions.keys().copied().collect();
            for addr in addrs {
                let _ = binary.decompile(addr, None);
            }
        }
        std::fs::remove_file(&path).ok();
    }
}

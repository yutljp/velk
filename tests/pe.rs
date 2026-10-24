mod common;

use object::Object;
use velk::loader::{self, NameSource};

#[test]
fn windows_unwind_ranges_bound_stripped_functions() {
    for opt in ["O0", "O2"] {
        let debug = loader::load(
            &common::fixtures_dir().join(format!("metrics/windows.win64.{opt}.debug.dll")),
        )
        .unwrap();
        let stripped = loader::load(
            &common::fixtures_dir().join(format!("metrics/windows.win64.{opt}.stripped.dll")),
        )
        .unwrap();
        assert_eq!(stripped.entry, None);
        for name in ["call_import", "large_frame", "saved_xmm"] {
            let function = debug
                .functions
                .values()
                .find(|function| function.name.as_deref() == Some(name))
                .unwrap();
            let recovered = &stripped.functions[&function.addr];
            assert!(recovered.sources.contains(&NameSource::Unwind));
            assert_eq!(recovered.size, function.size);
            assert!(!recovered.size_estimated);
        }
    }
}

#[test]
fn malformed_windows_unwind_entries_do_not_hide_later_functions() {
    let path = common::fixtures_dir().join("metrics/windows.win64.O2.stripped.dll");
    let original = std::fs::read(&path).unwrap();
    let image = loader::load(&path).unwrap();
    let base = object::File::parse(original.as_slice())
        .unwrap()
        .relative_address_base();
    let pdata = image
        .sections
        .iter()
        .find(|section| section.name == ".pdata")
        .unwrap();
    let offset = pdata.file_offset.unwrap() as usize;
    let first = base
        + u64::from(u32::from_le_bytes(
            original[offset..offset + 4].try_into().unwrap(),
        ));
    let later = base
        + u64::from(u32::from_le_bytes(
            original[offset + 12..offset + 16].try_into().unwrap(),
        ));
    let unwind = base
        + u64::from(u32::from_le_bytes(
            original[offset + 8..offset + 12].try_into().unwrap(),
        ));
    let unwind_offset = image.virtual_offset(unwind).unwrap() as usize;
    let scratch = common::root().join("target/pe-malformed.dll");
    for case in 0..4 {
        let mut bytes = original.clone();
        match case {
            0 => bytes[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes()),
            1 => bytes[offset + 4..offset + 8].fill(0),
            2 => bytes[unwind_offset] = 0x21,
            3 => bytes[unwind_offset + 2] = 255,
            _ => unreachable!(),
        }
        std::fs::write(&scratch, bytes).unwrap();
        let damaged = loader::load(&scratch).unwrap();
        assert!(
            !damaged
                .functions
                .get(&first)
                .is_some_and(|function| function.sources.contains(&NameSource::Unwind)),
            "case {case}"
        );
        assert!(
            damaged.functions[&later]
                .sources
                .contains(&NameSource::Unwind),
            "case {case}"
        );
    }
    std::fs::remove_file(scratch).unwrap();
}

#[test]
fn malformed_import_names_do_not_hide_later_slots() {
    let path = common::fixtures_dir().join("metrics/windows.win64.O2.stripped.dll");
    let original = std::fs::read(&path).unwrap();
    let image = loader::load(&path).unwrap();
    let file = object::read::pe::PeFile64::parse(original.as_slice()).unwrap();
    let table = file.import_table().unwrap().unwrap();
    let descriptor = table.descriptors().unwrap().next().unwrap().unwrap();
    let lookup = descriptor.original_first_thunk.get(object::LittleEndian);
    let offset = image
        .virtual_offset(file.relative_address_base() + u64::from(lookup))
        .unwrap() as usize;
    let scratch = common::root().join("target/pe-import-malformed.dll");
    for value in [u64::from(u32::MAX), 0x8000_0000_0000_0001] {
        let mut bytes = original.clone();
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        std::fs::write(&scratch, bytes).unwrap();
        let damaged = loader::load(&scratch).unwrap();
        assert!(!damaged.imports.values().any(|name| name == "__chkstk"));
        assert!(
            damaged
                .imports
                .values()
                .any(|name| name == "imported_value")
        );
    }
    let machine = file.dos_header().e_lfanew.get(object::LittleEndian) as usize + 4;
    let mut bytes = original.clone();
    bytes[machine..machine + 2]
        .copy_from_slice(&object::pe::IMAGE_FILE_MACHINE_ARM64.0.to_le_bytes());
    std::fs::write(&scratch, bytes).unwrap();
    let other_arch = loader::load(&scratch).unwrap();
    assert!(
        other_arch
            .imports
            .values()
            .any(|name| name == "imported_value")
    );
    assert!(
        !other_arch
            .functions
            .values()
            .any(|function| function.sources.contains(&NameSource::Plt))
    );
    std::fs::remove_file(scratch).unwrap();
}

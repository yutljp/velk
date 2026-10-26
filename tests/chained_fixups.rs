//! Chained and classic Mach-O pointers must describe the same program.

mod common;

use std::collections::BTreeMap;
use std::process::Command;

use velk::loader::Pointer;
use velk::service::Binary;

fn fixture(arch: &str, mode: &str) -> Binary {
    Binary::open(&common::root().join(format!("tests/metadata/chained/{arch}.{mode}.dylib")))
        .expect("linked Mach-O fixture loads")
}

fn data_address(binary: &Binary, name: &str) -> u64 {
    *binary
        .image()
        .data_symbols
        .iter()
        .find(|(_, symbol)| symbol.as_str() == name)
        .unwrap_or_else(|| panic!("missing {name}: {:?}", binary.image().data_symbols))
        .0
}

#[test]
fn chained_rtti_and_objective_c_match_classic_metadata() {
    for arch in ["arm64", "x86_64"] {
        let chained = fixture(arch, "chained");
        let classic = fixture(arch, "classic");
        let classes = |binary: &Binary| {
            let mut classes = BTreeMap::new();
            for class in binary.image().classes() {
                classes.insert(
                    class.name.clone(),
                    (
                        class
                            .bases
                            .iter()
                            .map(|base| {
                                (
                                    base.name.clone(),
                                    base.offset,
                                    base.is_virtual,
                                    base.vtable_offset,
                                )
                            })
                            .collect::<Vec<_>>(),
                        class
                            .vtables
                            .iter()
                            .map(|table| {
                                (
                                    table.offset,
                                    table
                                        .methods
                                        .iter()
                                        .map(|method| (method.slot, method.name.clone()))
                                        .collect::<Vec<_>>(),
                                )
                            })
                            .collect::<Vec<_>>(),
                    ),
                );
            }
            classes
        };
        assert_eq!(classes(&chained), classes(&classic), "{arch}");
        assert_eq!(chained.image().classes().len(), 6);
        let objc_names = |binary: &Binary| {
            binary
                .image()
                .functions
                .values()
                .filter(|function| function.sources.contains(&velk::loader::NameSource::Objc))
                .map(|function| function.name.clone().unwrap())
                .collect::<std::collections::BTreeSet<_>>()
        };
        assert_eq!(objc_names(&chained), objc_names(&classic));
        assert_eq!(objc_names(&chained).len(), 5);
        assert_eq!(
            chained.image().objc_selectors.values().collect::<Vec<_>>(),
            classic.image().objc_selectors.values().collect::<Vec<_>>()
        );
    }
}

#[test]
fn tables_globals_and_pointer_reads_see_decoded_addresses_and_addends() {
    for arch in ["arm64", "x86_64"] {
        let binary = fixture(arch, "chained");
        let table = data_address(&binary, "_function_table");
        let local = binary.find("local_function").unwrap().addr;
        assert_eq!(
            binary.image().read_pointer(table),
            Some(Pointer::Address(local))
        );
        let bytes = binary.image().read_vaddr(table, 8).unwrap();
        assert_eq!(u64::from_le_bytes(bytes.try_into().unwrap()), local);
        assert_eq!(
            binary.image().read_pointer(table + 8),
            Some(Pointer::Import {
                name: "_imported_function",
                addend: 0
            })
        );
        let data = data_address(&binary, "_data_pointer");
        assert_eq!(
            binary.image().read_pointer(data),
            Some(Pointer::Import {
                name: "_imported_data",
                addend: 12
            })
        );
        let text = data_address(&binary, "_text_pointer");
        let Pointer::Address(text) = binary.image().read_pointer(text).unwrap() else {
            panic!("a local string pointer")
        };
        let bytes = binary.image().read_vaddr(text, 23).unwrap();
        assert_eq!(bytes, b"chained pointer string\0");
        for class in binary.image().classes() {
            for table in &class.vtables {
                for method in &table.methods {
                    assert_eq!(
                        binary.image().read_pointer(table.address + method.slot * 8),
                        Some(Pointer::Address(method.address))
                    );
                }
            }
        }
    }
}

#[test]
fn chained_calls_and_names_print_as_compilable_c() {
    for arch in ["arm64", "x86_64"] {
        for mode in ["classic", "chained"] {
            let mut binary = fixture(arch, mode);
            for name in [
                "dispatch",
                "single",
                "table_call",
                "data_read",
                "text_read",
                "-[Counter add:with:]",
            ] {
                let address = binary.find(name).unwrap().addr;
                let code = binary.decompile(address, None, None).unwrap();
                let output = common::compiler::run(
                    Command::new("clang").args([
                        "-x",
                        "c",
                        "-std=c11",
                        "-fsyntax-only",
                        "-Werror=implicit-function-declaration",
                        "-",
                    ]),
                    Some(&code),
                );
                assert!(
                    output.status.success(),
                    "{arch} {mode} {name}: {}\n{code}",
                    String::from_utf8_lossy(&output.stderr)
                );
                if name == "single" {
                    assert!(code.contains("Single__Single"), "{code}");
                }
            }
        }
    }
}

#[test]
fn fixup_load_errors_identify_the_invalid_pointer() {
    let path = common::root().join("tests/metadata/chained/arm64.chained.dylib");
    let mut bytes = std::fs::read(&path).unwrap();
    let binary = Binary::open(&path).unwrap();
    let slot = data_address(&binary, "_data_pointer");
    let offset = binary.image().virtual_offset(slot).unwrap() as usize;
    let raw = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
    bytes[offset..offset + 8].copy_from_slice(&(raw | 0xff_ffff).to_le_bytes());
    let path = common::root().join("target/chained-invalid-ordinal.dylib");
    std::fs::write(&path, bytes).unwrap();
    let error = Binary::open(&path).err().unwrap().to_string();
    assert!(
        error.contains(&format!("pointer at {slot:#x}: invalid import ordinal")),
        "{error}"
    );
}

#[test]
fn imported_data_slots_preserve_addends_and_runtime_writes_in_printed_c() {
    for arch in ["arm64", "x86_64"] {
        for mode in ["classic", "chained"] {
            let mut binary = fixture(arch, mode);
            let address = binary.find("data_read").unwrap().addr;
            let code = binary.decompile(address, None, None).unwrap();
            if mode == "chained" {
                assert!(
                    code.contains("Initial pointer: imported_data, byte addend 12."),
                    "{code}"
                );
            }
            let source = format!(
                "{code}\nuint64_t data_pointer;\nint main(void) {{ int32_t imported_data[8] = {{1,2,3,17,29,6,7,8}}; data_pointer = (uintptr_t)(imported_data + 3); if (data_read() != 17) return 1; data_pointer = (uintptr_t)(imported_data + 4); return data_read() != 29; }}\n"
            );
            for opt in ["-O0", "-O2"] {
                let path =
                    common::root().join(format!("target/chained-data-{arch}-{mode}-{}", &opt[1..]));
                let output = common::compiler::run(
                    Command::new("clang")
                        .args([
                            "-x",
                            "c",
                            "-std=c11",
                            opt,
                            "-Werror=implicit-function-declaration",
                            "-o",
                        ])
                        .arg(&path)
                        .arg("-"),
                    Some(&source),
                );
                assert!(
                    output.status.success(),
                    "{}\n{source}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(Command::new(path).status().unwrap().success());
            }
        }
    }
}

#[test]
fn chained_metadata_survives_removal_of_the_symbol_table() {
    for arch in ["arm64", "x86_64"] {
        let original = fixture(arch, "chained");
        let path = common::root().join(format!("tests/metadata/chained/{arch}.chained.dylib"));
        let mut bytes = std::fs::read(path).unwrap();
        let count = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let mut at = 32;
        for _ in 0..count {
            let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
            let size = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap());
            if kind == 2 {
                bytes[at + 12..at + 16].fill(0);
            }
            at += size as usize;
        }
        let path = common::root().join(format!("target/chained-no-symbols-{arch}.dylib"));
        std::fs::write(&path, bytes).unwrap();
        let stripped = Binary::open(&path).unwrap();
        let names = |binary: &Binary| {
            binary
                .image()
                .classes()
                .iter()
                .map(|class| class.name.clone())
                .collect::<std::collections::BTreeSet<_>>()
        };
        assert_eq!(names(&stripped), names(&original));
        let objc = stripped
            .image()
            .functions
            .values()
            .filter(|function| function.sources.contains(&velk::loader::NameSource::Objc))
            .count();
        assert_eq!(objc, 5);
        for class in stripped.image().classes() {
            for table in &class.vtables {
                assert!(!table.methods.is_empty());
                for method in &table.methods {
                    assert!(stripped.function(method.address).is_ok());
                }
            }
        }
    }
}

#[test]
fn universal_slice_offsets_do_not_change_decoded_pointers() {
    for arch in ["arm64", "x86_64"] {
        let thin = fixture(arch, "chained");
        let path = common::root().join(format!("tests/metadata/chained/{arch}.chained.dylib"));
        let slice = std::fs::read(path).unwrap();
        let mut bytes = Vec::new();
        for value in [
            0xcafe_babeu32,
            1,
            u32::from_le_bytes(slice[4..8].try_into().unwrap()),
            u32::from_le_bytes(slice[8..12].try_into().unwrap()),
            4096,
            slice.len() as u32,
            12,
        ] {
            bytes.extend(value.to_be_bytes());
        }
        bytes.resize(4096, 0);
        bytes.extend(slice);
        let path = common::root().join(format!("target/chained-universal-{arch}.dylib"));
        std::fs::write(&path, bytes).unwrap();
        let architecture = if arch == "arm64" {
            velk::loader::Architecture::Arm64
        } else {
            velk::loader::Architecture::X86_64
        };
        let binary = Binary::open_with_options(&path, None, Some(architecture)).unwrap();
        assert_eq!(binary.image().slice_offset, 4096);
        for name in ["_function_table", "_data_pointer", "_text_pointer"] {
            let address = data_address(&thin, name);
            assert_eq!(
                binary.image().read_pointer(address),
                thin.image().read_pointer(address)
            );
            assert_eq!(
                binary.image().virtual_offset(address),
                thin.image()
                    .virtual_offset(address)
                    .map(|offset| offset + 4096)
            );
        }
    }
}

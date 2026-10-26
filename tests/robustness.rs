//! Damaged files: truncated or with flipped bytes, every fixture either loads or
//! fails with an error, and every function it lists analyzes without a panic.

mod common;

use velk::ir::eval;
use velk::service::Binary;

/// Variants of `bytes`: cut at several lengths, and with a few bytes overwritten.
fn damaged(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut variants = Vec::new();
    for fraction in [1, 2, 3, 5, 8] {
        variants.push(bytes[..bytes.len() * fraction / 10].to_vec());
    }
    for seed in 0..6 {
        let mut copy = bytes.to_vec();
        for flip in 0..16 {
            let position = (eval::hash(seed, flip) % bytes.len() as u64) as usize;
            copy[position] = eval::hash(seed, flip + 100) as u8;
        }
        variants.push(copy);
    }
    variants
}

#[test]
fn damaged_fixtures_never_panic() {
    let scratch = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("damaged");
    std::fs::create_dir_all(&scratch).expect("creating the scratch directory");
    let fixtures: Vec<_> = common::fixtures()
        .into_iter()
        .filter(|fixture| !fixture.starts_with("metrics"))
        .collect();
    common::in_parallel(&fixtures, |fixture| {
        let bytes = std::fs::read(common::fixtures_dir().join(fixture)).expect("reading a fixture");
        let name = fixture.to_string_lossy().replace('/', "_");
        for (index, variant) in damaged(&bytes).into_iter().enumerate() {
            let path = scratch.join(format!("{name}.{index}"));
            std::fs::write(&path, &variant).expect("writing a damaged copy");
            let Ok(mut binary) = Binary::open(&path) else {
                continue;
            };
            let addrs: Vec<u64> = binary.image().functions.keys().copied().take(200).collect();
            for addr in addrs {
                let _ = binary.decompile(addr, None, None);
                let _ = binary.card(addr, 240, None, None);
            }
        }
    });
}

#[test]
fn universal_macho_selects_host_and_lists_unavailable_architectures() {
    let scratch = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(&scratch).unwrap();
    let arm = std::fs::read(common::fixtures_dir().join("universal_arm64.o")).unwrap();
    let x86 = std::fs::read(common::fixtures_dir().join("universal_x86_64.o")).unwrap();
    for (name, magic) in [("fat32", 0xcafe_babe_u32), ("fat64", 0xcafe_babf_u32)] {
        let path = scratch.join(name);
        let mut bytes = magic.to_be_bytes().to_vec();
        bytes.extend_from_slice(&2_u32.to_be_bytes());
        let mut offset = 4096_u64;
        for (cpu, slice) in [(0x0100_000c_u32, &arm), (0x0100_0007, &x86)] {
            bytes.extend_from_slice(&cpu.to_be_bytes());
            let subtype = u32::from_le_bytes(slice[8..12].try_into().unwrap());
            bytes.extend_from_slice(&subtype.to_be_bytes());
            if magic == 0xcafe_babe {
                bytes.extend_from_slice(&(offset as u32).to_be_bytes());
                bytes.extend_from_slice(&(slice.len() as u32).to_be_bytes());
            } else {
                bytes.extend_from_slice(&offset.to_be_bytes());
                bytes.extend_from_slice(&(slice.len() as u64).to_be_bytes());
            }
            bytes.extend_from_slice(&0_u32.to_be_bytes());
            if magic == 0xcafe_babf {
                bytes.extend_from_slice(&0_u32.to_be_bytes());
            }
            offset += slice.len() as u64;
        }
        bytes.resize(4096, 0);
        bytes.extend_from_slice(&arm);
        bytes.extend_from_slice(&x86);
        std::fs::write(&path, bytes).unwrap();
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_velk"))
            .args(["--functions", "--json"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output.stderr);
        let listing: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let expected = if cfg!(target_arch = "aarch64") {
            "aarch64"
        } else {
            "x86_64"
        };
        assert_eq!(listing["arch"], expected);
        assert!(!listing["functions"].as_array().unwrap().is_empty());
        assert_eq!(listing["slices"][0]["arch"], "arm64");
        assert_eq!(listing["slices"][1]["arch"], "x86_64");
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_velk"))
            .args(["--functions", "--arch", "arm64e"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8(output.stderr).unwrap();
        assert_eq!(error.lines().count(), 1, "{error}");
        assert!(error.contains("no slice matching Arm64e"), "{error}");
        assert!(error.contains("available slices: arm64, x86_64"), "{error}");
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn decompile_continues_after_an_undecodable_function() {
    use object::write::{Object, Symbol, SymbolSection};
    use object::{
        Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
    };

    let mut object = Object::new(BinaryFormat::Elf, Architecture::Aarch64, Endianness::Little);
    let section = object.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
    object.append_section_data(
        section,
        &[0, 0, 0, 0, 0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6],
        4,
    );
    for (name, value, size) in [("undecodable", 0, 1), ("last", 4, 8)] {
        object.add_symbol(Symbol {
            name: name.as_bytes().to_vec(),
            value,
            size,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(section),
            flags: SymbolFlags::None,
        });
    }
    let scratch = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(&scratch).unwrap();
    let path = scratch.join("undecodable-function.o");
    std::fs::write(&path, object.write().unwrap()).unwrap();
    for targets in [&["undecodable", "last"][..], &["*"][..]] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_velk"))
            .arg("--decompile")
            .arg(&path)
            .args(targets)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let code = String::from_utf8(output.stdout).unwrap();
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(code.contains("last("), "{code}");
        assert!(code.contains("return 42;"), "{code}");
        assert!(error.contains("no instruction could be decoded"), "{error}");
        let executable = scratch.join(format!("continued-{}.exe", targets.len()));
        let source =
            format!("#include <stdint.h>\n{code}\nint main(void) {{ return last() != 42; }}\n");
        let compiled = common::compiler::run(
            std::process::Command::new("clang")
                .args(["-x", "c", "-"])
                .arg("-o")
                .arg(&executable),
            Some(&source),
        );
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        assert!(
            std::process::Command::new(&executable)
                .status()
                .unwrap()
                .success()
        );
        std::fs::remove_file(executable).unwrap();
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn large_symbol_tables_preserve_function_boundaries() {
    use object::write::{Object, Symbol, SymbolSection};
    use object::{
        Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
    };

    let mut object = Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let section = object.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
    let count = 20_000_u32;
    for index in 0..count {
        let mut code = vec![0xb8];
        code.extend_from_slice(&index.to_le_bytes());
        code.push(0xc3);
        let value = object.append_section_data(section, &code, 1);
        object.add_symbol(Symbol {
            name: format!("value_{index}").into_bytes(),
            value,
            size: 0,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(section),
            flags: SymbolFlags::None,
        });
    }
    let scratch = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(&scratch).unwrap();
    let path = scratch.join("many-functions.o");
    std::fs::write(&path, object.write().unwrap()).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--functions")
        .arg(&path)
        .args(["--json", "--limit", "20000"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    let listing: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let functions = listing["functions"].as_array().unwrap();
    assert_eq!(functions.len(), count as usize);
    for (index, function) in functions.iter().enumerate() {
        assert_eq!(function["addr"], format!("0x{:x}", index * 6));
        assert_eq!(function["size"], 6);
    }
    let mut binary = Binary::open(&path).unwrap();
    let code = binary
        .decompile(u64::from(count - 1) * 6, None, None)
        .unwrap();
    assert!(code.contains("return 0x4e1f;"), "{code}");
    std::fs::remove_file(path).unwrap();
}

fn robustness_input(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/robustness")
        .join(name)
}

#[test]
fn go_function_table_near_address_limit_does_not_overflow() {
    let path = robustness_input("go_table_overflow.elf");
    let mut binary = Binary::open(&path).expect("the file is a valid ELF");
    let addrs: Vec<u64> = binary.image().functions.keys().copied().take(20).collect();
    for addr in addrs {
        let _ = binary.decompile(addr, None, None);
    }
}

#[test]
fn cyclic_export_tries_finish_loading() {
    for name in [
        "export_trie_cycle_macho.bin",
        "export_trie_cycle_arm64.bin",
        "export_trie_cycle_x86_64.bin",
    ] {
        let path = robustness_input(name);
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut binary = Binary::open(&path).expect("the file is a valid Mach-O");
            let addrs: Vec<u64> = binary.image().functions.keys().copied().take(20).collect();
            for addr in addrs {
                let _ = binary.decompile(addr, None, None);
            }
            let _ = sender.send(());
        });
        let finished = receiver.recv_timeout(std::time::Duration::from_secs(10));
        assert!(finished.is_ok(), "{name} stalled while loading");
    }
}

//! Damaged files: truncated or with flipped bytes, every fixture either loads or
//! fails with an error, and every function it lists analyzes without a panic.

mod common;

use velk::service::Binary;

fn mix(seed: u64, key: u64) -> u64 {
    let mut value = seed ^ key.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

/// Variants of `bytes`: cut at several lengths, and with a few bytes overwritten.
fn damaged(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut variants = Vec::new();
    for fraction in [1, 2, 3, 5, 8] {
        variants.push(bytes[..bytes.len() * fraction / 10].to_vec());
    }
    for seed in 0..6 {
        let mut copy = bytes.to_vec();
        for flip in 0..16 {
            let position = (mix(seed, flip) % bytes.len() as u64) as usize;
            copy[position] = mix(seed, flip + 100) as u8;
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
fn universal_macho_explains_how_to_select_an_architecture() {
    let scratch = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(&scratch).unwrap();
    for (name, magic) in [("fat32", 0xcafe_babe_u32), ("fat64", 0xcafe_babf_u32)] {
        let path = scratch.join(name);
        let mut bytes = magic.to_be_bytes().to_vec();
        bytes.extend_from_slice(&0_u32.to_be_bytes());
        bytes.resize(32, 0);
        std::fs::write(&path, bytes).unwrap();
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_velk"))
            .arg("--functions")
            .arg(&path)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8(output.stderr).unwrap();
        assert_eq!(error.lines().count(), 1, "{error}");
        assert!(error.contains("universal Mach-O"), "{error}");
        assert!(error.contains("extract one architecture"), "{error}");
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

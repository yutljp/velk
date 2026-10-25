use std::path::Path;

use velk::service::Binary;
use velk::sigs::{self, Database};

#[test]
fn stripped_fixture_matches_agree_with_symbols_and_apply_names() {
    for (source, target) in [
        ("go_probe", "go_stripped"),
        ("rust_probe", "rust_probe_stripped"),
        ("go_probe_arm64", "go_stripped_arm64"),
        ("rust_probe_arm64", "rust_probe_arm64_stripped"),
        ("x64_loops.o", "x64_loops_stripped.o"),
        ("arm64_loops.o", "arm64_loops_stripped.o"),
        ("cold_gcc", "cold_gcc_stripped"),
    ] {
        let source_path = Path::new("tests/fixtures").join(source);
        let target_path = Path::new("tests/fixtures").join(target);
        let reference = Binary::open(if target.starts_with("go_") {
            &target_path
        } else {
            &source_path
        })
        .unwrap();
        let db = sigs::build(&source_path, None).unwrap();
        let mut binary = Binary::open(&target_path).unwrap();
        let result = binary.identify(&db, None).unwrap();
        let mut renamed = 0;
        for matched in &result.matches {
            let original = &reference.image().functions[&matched.addr];
            assert!(
                original.name.as_ref() == Some(&matched.matched)
                    || original.aliases.contains(&matched.matched),
                "{target} at {:x}: {} != {:?}",
                matched.addr,
                matched.matched,
                original.name
            );
            if matched.current.is_none() {
                renamed += 1;
                assert_eq!(
                    binary.image().functions[&matched.addr].name.as_ref(),
                    Some(&matched.matched)
                );
            }
        }
        eprintln!(
            "{target}: entries={} matches={} renamed={renamed} false_positives=0",
            db.entries.len(),
            result.matches.len()
        );
        if target == "cold_gcc_stripped" {
            assert!(result.matches.is_empty());
        } else {
            assert!(!result.matches.is_empty(), "{target}: no coverage");
        }
    }
}

#[test]
fn ambiguous_and_wrong_architecture_entries_are_rejected() {
    let path = Path::new("tests/fixtures/x64_loops.o");
    let db = sigs::build(path, None).unwrap();
    assert!(!db.entries.is_empty());
    let mut ambiguous = db.entries.clone();
    for entry in &db.entries {
        let mut alias = entry.clone();
        alias.name.push_str("_alias");
        ambiguous.push(alias);
    }
    assert!(
        Binary::open(path)
            .unwrap()
            .identify(&Database::new(ambiguous), None)
            .unwrap()
            .matches
            .is_empty()
    );
    let mut wrong_isa = db;
    for entry in &mut wrong_isa.entries {
        entry.isa = velk::loader::Isa::AArch64;
    }
    assert!(
        Binary::open(path)
            .unwrap()
            .identify(&wrong_isa, None)
            .unwrap()
            .matches
            .is_empty()
    );
}

#[test]
fn changed_suffix_and_unresolved_calls_are_rejected() {
    let path = Path::new("tests/fixtures/go_probe");
    let mut db = sigs::build(path, None).unwrap();
    assert!(db.entries.iter().any(|entry| entry.bytes.len() > 128));
    for entry in &mut db.entries {
        if let Some(byte) = entry.bytes.last_mut() {
            *byte ^= 1;
        }
    }
    assert!(
        Binary::open(path)
            .unwrap()
            .identify(&db, None)
            .unwrap()
            .matches
            .is_empty()
    );
    let mut db = sigs::build(path, None).unwrap();
    for entry in &mut db.entries {
        for call in &mut entry.calls {
            *call = "missing_destination".to_owned();
        }
    }
    let matches = Binary::open(path)
        .unwrap()
        .identify(&db, None)
        .unwrap()
        .matches;
    assert!(matches.iter().all(|matched| {
        db.entries
            .iter()
            .any(|entry| entry.name == matched.matched && entry.calls.is_empty())
    }));
}

#[test]
fn renamed_function_prints_c_that_runs() {
    let db = sigs::build(Path::new("tests/fixtures/arm64_loops.o"), None).unwrap();
    let mut binary = Binary::open(Path::new("tests/fixtures/arm64_loops_stripped.o")).unwrap();
    // Populate the analysis cache before identification to check its invalidation.
    let before = binary.decompile(0, None, None).unwrap();
    let _ = binary.navigation(None).unwrap();
    assert!(!before.contains("count_bits("));
    let code = binary.decompile(0, Some(&db), None).unwrap();
    assert!(code.contains("count_bits("), "{code}");
    assert_eq!(binary.summary(0, None).unwrap()["name"], "count_bits");
    let dir = Path::new("target/signature-c-test");
    std::fs::create_dir_all(dir).unwrap();
    let source = dir.join("count_bits.c");
    let executable = dir.join("count_bits");
    std::fs::write(&source, format!("#include <stdint.h>\n{code}\nint main(void) {{ for (uint32_t x=0; x<10000; ++x) {{ if (count_bits(x) != __builtin_popcount(x)) return 1; }} return count_bits(-1) != 32; }}\n")).unwrap();
    let output = std::process::Command::new("clang")
        .args(["-std=c11", "-Werror", "-O2"])
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        std::process::Command::new(&executable)
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn script_identification_refreshes_functions_and_decompilation() {
    let dir = Path::new("target/signature-script-test");
    std::fs::create_dir_all(dir).unwrap();
    let script = dir.join("identify.js");
    std::fs::write(&script, r#"
const db = velk.buildSignatures("tests/fixtures/arm64_loops.o").database;
const b = velk.open("tests/fixtures/arm64_loops_stripped.o");
const before = b.functions();
if (before.some(f => f.name !== null)) throw Error("expected stripped functions");
const result = b.identify(db);
if (result.matches.length !== 4) throw Error("missing matches");
if (b.functions().some(f => f.name === null)) throw Error("stale function list");
if (!b.getFunction("count_bits").decompile().includes("count_bits(")) throw Error("name not applied");
console.log("signatures applied");
"#).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("-r")
        .arg(&script)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("signatures applied"));
}

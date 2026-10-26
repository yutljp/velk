//! Universal Mach-O selection and valid arm64e pointer semantics.

mod common;

use std::fs;
use std::process::Command;

use velk::loader::{Architecture, Isa};
use velk::service::Binary;

#[test]
fn universal_slices_match_thin_images_and_original_file_offsets() {
    let path = common::root().join("tests/universal/universal.o");
    let bytes = fs::read(&path).unwrap();
    for (arch, name, isa) in [
        (Architecture::Arm64, "universal_arm64.o", Isa::AArch64),
        (Architecture::X86_64, "universal_x86_64.o", Isa::X86_64),
    ] {
        let mut fat = Binary::open_with_options(&path, None, Some(arch)).unwrap();
        let mut thin = Binary::open(&common::fixtures_dir().join(name)).unwrap();
        assert_eq!(fat.image().isa, isa);
        assert_eq!(fat.image().slices.len(), 2);
        assert!(fat.image().slice_offset > 0);
        for function in thin.functions() {
            let offset = fat.image().virtual_offset(function.addr).unwrap();
            let size = function.size.unwrap() as usize;
            assert_eq!(
                fat.image().read(offset, size as u64).unwrap(),
                &bytes[offset as usize..offset as usize + size]
            );
            assert_eq!(
                fat.decompile(function.addr, None, None).unwrap(),
                thin.decompile(function.addr, None, None).unwrap()
            );
        }
        assert!(fat.image().read(fat.image().slice_offset - 1, 1).is_none());
    }
    let default = Binary::open(&path).unwrap();
    assert_eq!(
        default.image().isa,
        if cfg!(target_arch = "aarch64") {
            Isa::AArch64
        } else {
            Isa::X86_64
        }
    );
    let error = Binary::open_with_options(&path, None, Some(Architecture::Arm64e))
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("available slices: x86_64, arm64"), "{error}");
}

#[test]
fn scripts_keep_simultaneous_architecture_handles_independent() {
    let engine = velk::script::Engine::new().unwrap();
    let path = common::root().join("tests/universal/universal.o");
    let script = format!(
        r#"
        const a = velk.open({path:?}, {{arch: "arm64"}});
        const x = velk.open({path:?}, {{arch: "x86_64"}});
        const ac = a.getFunction("_sum3").disasm().join("\n");
        const xc = x.getFunction("_sum3").disasm().join("\n");
        if (a.slices.length !== 2 || a.arch !== "aarch64" || x.arch !== "x86_64") throw Error("metadata");
        if (ac === xc || !ac.includes("ret") || !xc.includes("ret")) throw Error("slice cache");
        const sig = x.buildSignatures().database.entries;
        if (sig.length === 0 || sig.some(e => e.isa !== "x86_64")) throw Error("signature slice");
        a.getFunction("_sum3").decompile();
    "#
    );
    let result = engine.run(&script, None);
    assert!(
        result.error.is_none(),
        "{:?}: {}",
        result.error,
        result.output
    );
}

fn fat64(slice: &[u8], offset: u64, size: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in [0xcafe_babfu32, 1, 0x0100_000c, 0] {
        bytes.extend(value.to_be_bytes());
    }
    bytes.extend(offset.to_be_bytes());
    bytes.extend(size.to_be_bytes());
    bytes.extend([0; 8]);
    bytes.resize(64, 0);
    bytes.extend(slice);
    bytes
}

#[test]
fn fat64_bounds_and_malformed_architecture_tables() {
    let thin = fs::read(common::fixtures_dir().join("universal_arm64.o")).unwrap();
    let path = common::root().join("target/macos-native-fat64");
    for (offset, size, valid) in [
        (64, thin.len() as u64, true),
        (u64::MAX, 16, false),
        (64, u64::MAX, false),
        (64, 4, false),
    ] {
        fs::write(&path, fat64(&thin, offset, size)).unwrap();
        let result = Binary::open_with_options(&path, None, Some(Architecture::Arm64));
        assert_eq!(result.is_ok(), valid);
        if let Err(error) = result {
            assert!(
                error.to_string().contains("available slices: arm64"),
                "{error}"
            );
        }
    }
    let mut bytes = fat64(&thin, 64, thin.len() as u64);
    bytes[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
    fs::write(&path, bytes).unwrap();
    assert!(Binary::open(&path).is_err());
    fs::remove_file(path).unwrap();
}

#[test]
fn every_native_fixture_function_prints_compilable_c() {
    let directory = common::root().join("target/macos-native-compile");
    fs::create_dir_all(&directory).unwrap();
    for fixture in ["arm64e.o", "universal_arm64.o", "universal_x86_64.o"] {
        let mut binary = Binary::open(&common::fixtures_dir().join(fixture)).unwrap();
        for function in binary.functions() {
            let code = binary.decompile(function.addr, None, None).unwrap();
            assert!(!code.contains("unsupported"), "{code}");
            assert!(!code.contains("__asm"), "{code}");
            let source = directory.join(format!("{}.c", function.addr));
            fs::write(&source, format!("#include <stdint.h>\n{code}")).unwrap();
            let result = Command::new("clang")
                .args(["-std=c11", "-Werror=implicit-function-declaration", "-c"])
                .arg(&source)
                .arg("-o")
                .arg(directory.join(format!("{}.o", function.addr)))
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{code}\n{}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
    }
}

#[test]
fn signed_returns_and_pointer_loads_run_as_printed() {
    let mut binary = Binary::open(&common::fixtures_dir().join("arm64e.o")).unwrap();
    let mut code = String::from("#include <stdint.h>\n");
    for name in [
        "signed_return",
        "signed_return_a",
        "pointer_identity",
        "load_a",
        "load_b",
        "load_writeback",
        "load_sp",
        "branch_a",
        "branch_b",
        "branch_az",
        "branch_bz",
        "invoke_a",
        "invoke_b",
        "invoke_az",
        "invoke_bz",
    ] {
        let function = binary.find(name).unwrap();
        code.push_str(&binary.decompile(function.addr, None, None).unwrap());
    }
    code.push_str(
        r#"
static uint64_t answer(void) { return 42; }
int main(void) {
    void *target = (void *)(uintptr_t)&answer;
    if (branch_a(target) != 42 || branch_b(target) != 42 || branch_az(target) != 42 || branch_bz(target) != 42) return 5;
    if (invoke_a(target) != 42 || invoke_b(target) != 42 || invoke_az(target) != 42 || invoke_bz(target) != 42) return 6;
    uint64_t values[3] = {11, 23, 37};
    for (uint64_t i = 0; i < 100; ++i) {
        if (signed_return(i) != i + 7 || signed_return_a(i) != i + 9) return 1;
        if (pointer_identity(i) != i || load_sp(i) != i) return 2;
    }
    if (load_a(values) != 23 || load_b(&values[1]) != 11) return 3;
    if (load_writeback(values) != (uintptr_t)&values[1] + 23) return 4;
    return 0;
}
"#,
    );
    let source = common::root().join("target/macos-native-values.c");
    let executable = source.with_extension("exe");
    fs::write(&source, code).unwrap();
    let result = Command::new("clang")
        .args(["-std=c11", "-Werror=implicit-function-declaration"])
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(Command::new(executable).status().unwrap().success());
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn arm64e_hardware_validates_authenticated_returns_calls_and_loads() {
    let executable = common::root().join("target/macos-native-hardware");
    let result = Command::new("clang")
        .args(["-arch", "arm64e"])
        .arg(common::root().join("tests/arm64e_hardware.c"))
        .arg(common::fixtures_dir().join("arm64e.o"))
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(Command::new(executable).status().unwrap().success());
}

#[test]
fn universal_linked_image_keeps_function_starts_and_imports() {
    let fixture = common::fixtures_dir().join("rust_probe_arm64_stripped");
    let bytes = fs::read(&fixture).unwrap();
    let path = common::root().join("target/macos-native-linked-fat64");
    fs::write(&path, fat64(&bytes, 64, bytes.len() as u64)).unwrap();
    let mut thin = Binary::open(&fixture).unwrap();
    let mut fat = Binary::open_with_options(&path, None, Some(Architecture::Arm64)).unwrap();
    assert_eq!(fat.image().entry, thin.image().entry);
    assert_eq!(fat.image().imports, thin.image().imports);
    assert_eq!(fat.functions().len(), thin.functions().len());
    for address in [0x10002e658, 0x10002e66c] {
        assert_eq!(
            fat.decompile(address, None, None).unwrap(),
            thin.decompile(address, None, None).unwrap()
        );
    }
    fs::remove_file(path).unwrap();
}

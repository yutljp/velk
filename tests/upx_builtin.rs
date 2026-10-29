//! Built-in decoding is compared with independently packed, self-built programs.

mod common;

use std::fs;

use velk::service::Binary;

#[test]
fn elf_matches_the_reference_file() {
    let directory = common::root().join("tests/data/upx");
    for arch in ["x86_64", "i386", "aarch64", "arm"] {
        for method in ["nrv2b", "nrv2d", "nrv2e", "lzma"] {
            let input = directory.join(format!("{arch}.{method}.elf"));
            let recovered =
                Binary::open(&input).unwrap_or_else(|error| panic!("{arch} {method}: {error}"));
            assert!(
                recovered
                    .image()
                    .packing
                    .as_ref()
                    .unwrap()
                    .method
                    .starts_with("built-in"),
                "{arch} {method}"
            );
            let saved = common::root().join(format!("target/upx-saved-{arch}-{method}.elf"));
            let _ = fs::remove_file(&saved);
            recovered.image().save_unpacked(&saved).unwrap();
            assert_eq!(
                fs::read(&saved).unwrap(),
                fs::read(directory.join(format!("{arch}.elf"))).unwrap(),
                "{arch} {method}"
            );
        }
    }
}

#[test]
fn pe_imports_and_relocations_match_the_reference_file() {
    let directory = common::root().join("tests/data/upx");
    for arch in ["x86_64", "i386"] {
        for method in ["nrv2b", "nrv2d", "nrv2e", "lzma"] {
            for filter in ["0", "26", "46", "49"] {
                let input = directory.join(format!("{arch}.{method}.filter{filter}.exe"));
                let recovered =
                    Binary::open(&input).unwrap_or_else(|error| panic!("{arch} {method}: {error}"));
                assert!(
                    recovered
                        .image()
                        .packing
                        .as_ref()
                        .unwrap()
                        .method
                        .starts_with("built-in")
                );
                let saved =
                    common::root().join(format!("target/upx-saved-{arch}-{method}-{filter}.exe"));
                let _ = fs::remove_file(&saved);
                recovered.image().save_unpacked(&saved).unwrap();
                let expected = fs::read(directory.join(format!("{arch}.reference.exe"))).unwrap();
                let actual = fs::read(&saved).unwrap();
                let different = actual.iter().zip(&expected).position(|(a, b)| a != b);
                assert!(
                    actual == expected,
                    "{arch} {method} filter {filter}: first difference {different:x?}"
                );
            }
        }
    }
}

#[test]
fn cli_javascript_and_mcp_recover_without_upx_on_path() {
    use std::process::{Command, Stdio};

    use serde_json::json;

    let directory = common::root().join(format!("target/upx-no-tools-{}", std::process::id()));
    let no_tools = directory.join("no-tools");
    fs::create_dir_all(&no_tools).unwrap();
    for (index, name) in [
        "x86_64.nrv2b.elf",
        "i386.lzma.elf",
        "arm.nrv2e.elf",
        "aarch64.lzma.elf",
        "x86_64.nrv2d.filter46.exe",
        "i386.nrv2b.filter49.exe",
    ]
    .iter()
    .enumerate()
    {
        let input = common::root().join("tests/data/upx").join(name);
        for interface in ["cli", "javascript", "mcp"] {
            let saved = directory.join(format!("{index}-{interface}"));
            let _ = fs::remove_file(&saved);
            let code = format!(
                "const b=velk.open({}, {{cache:false}}); if(!b.packing.method.startsWith('built-in')) throw Error('decoder'); b.saveUnpacked({}); b.getFunction('add3').decompile()",
                json!(input),
                json!(saved)
            );
            let mut command = Command::new(env!("CARGO_BIN_EXE_velk"));
            command.env("PATH", &no_tools);
            let output = match interface {
                "cli" => command
                    .args(["-D", "--cache", "off", "--save-unpacked"])
                    .arg(&saved)
                    .arg(&input)
                    .arg("add3")
                    .output()
                    .unwrap(),
                "javascript" => {
                    let script = directory.join("recover.js");
                    fs::write(&script, &code).unwrap();
                    command.arg("--run").arg(script).output().unwrap()
                }
                _ => {
                    let child = command
                        .arg("--mcp")
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn()
                        .unwrap();
                    let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"velk_run_script","arguments":{"code":code}}});
                    let output = common::mcp_request(child, &request);
                    let response: serde_json::Value =
                        serde_json::from_slice(&output.stdout).unwrap();
                    assert_eq!(response["result"]["isError"], false, "{response}");
                    output
                }
            };
            assert!(output.status.success(), "{name} {interface}: {output:?}");
            let mut original = Binary::open(&input).unwrap();
            let reference = directory.join(format!("{index}-reference"));
            let _ = fs::remove_file(&reference);
            original.image().save_unpacked(&reference).unwrap();
            assert_eq!(
                fs::read(&saved).unwrap(),
                fs::read(&reference).unwrap(),
                "{name} {interface}"
            );
            let address = original.find("add3").unwrap().addr;
            assert!(!original.decompile(address, None, None).unwrap().is_empty());
        }
    }
}

#[test]
fn unsupported_variants_name_the_reason_when_upx_is_unavailable() {
    use std::process::Command;

    let directory = common::root().join(format!("target/upx-unsupported-{}", std::process::id()));
    let no_tools = directory.join("no-tools");
    fs::create_dir_all(&no_tools).unwrap();
    let input = directory.join("overlay.exe");
    let mut bytes =
        fs::read(common::root().join("tests/data/upx/x86_64.nrv2b.filter49.exe")).unwrap();
    bytes.extend_from_slice(b"file overlay");
    fs::write(&input, bytes).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .env("PATH", no_tools)
        .env("TMPDIR", &directory)
        .args(["-D", "--cache", "off"])
        .arg(input)
        .arg("add3")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains("unsupported built-in UPX variant (PE file overlay)"),
        "{error}"
    );
    assert!(error.contains("fallback failed"), "{error}");
}

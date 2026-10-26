//! Direct UPX recovery is complete before normal analysis or saving begins.

mod common;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::json;
use velk::service::Binary;

fn directory(name: &str) -> PathBuf {
    let directory = common::root()
        .join("target/packed-tests")
        .join(format!("{name}-{}", std::process::id()));
    fs::create_dir_all(&directory).expect("creating packed input test directory");
    directory
}

fn run(command: &mut Command) {
    let output = command.output().expect("running a fixture command");
    assert!(output.status.success(), "{command:?}: {output:?}");
}

fn fixture(directory: &Path, target: &str, pe: bool) -> PathBuf {
    let source = directory.join("program.c");
    fs::write(
        &source,
        r#"
volatile unsigned char data[16384] = {'U','P','X','!',0,2,3};
volatile int result;
__attribute__((noinline)) int add3(int a, int b, int c) { return a + b + c; }
void start(void) { result = add3(data[0],data[1],data[2]); for (;;) {} }
"#,
    )
    .expect("writing the packed input fixture source");
    let original = directory.join(if pe { "original.exe" } else { "original.elf" });
    let mut compiler = Command::new("clang");
    compiler.args([
        "-target",
        target,
        "-O1",
        "-fno-stack-protector",
        "-fno-builtin",
        "-fno-pic",
        "-fno-pie",
    ]);
    if pe {
        let object = directory.join("program.obj");
        run(compiler.arg("-c").arg(&source).arg("-o").arg(&object));
        run(Command::new("lld-link")
            .args([
                "/nodefaultlib",
                "/entry:start",
                "/subsystem:console",
                "/fixed",
                "/export:add3",
                "/Brepro",
            ])
            .arg(format!("/out:{}", original.display()))
            .arg(object));
    } else {
        run(compiler
            .args([
                "-nostdlib",
                "-static",
                "-fuse-ld=lld",
                "-Wl,-e,start",
                "-Wl,--build-id=none",
            ])
            .arg(&source)
            .arg("-o")
            .arg(&original));
    }
    original
}

#[test]
fn upx_elf_and_pe_both_x86_widths_recover_identical_function_output() {
    if Command::new("upx").arg("--version").output().is_err() {
        eprintln!("UPX fixture tests skipped: upx is not installed");
        return;
    }
    for (name, target, pe) in [
        ("elf64", "x86_64-linux-gnu", false),
        ("elf32", "i686-linux-gnu", false),
        ("pe64", "x86_64-pc-windows-msvc", true),
        ("pe32", "i686-pc-windows-msvc", true),
    ] {
        let directory = directory(name);
        let original_path = fixture(&directory, target, pe);
        let packed_path = directory.join("packed");
        run(Command::new("upx")
            .args(["-q", "-f", "-o"])
            .arg(&packed_path)
            .arg(&original_path));
        let packed_bytes = fs::read(&packed_path).unwrap();
        let detection = velk::loader::packed::detect(&packed_bytes).unwrap();
        assert_eq!(detection.packer, "UPX");
        assert!(
            detection
                .version
                .as_deref()
                .is_some_and(|version| version.starts_with(|c: char| c.is_ascii_digit())),
            "{detection:?}"
        );
        let mut original = Binary::open(&original_path).unwrap();
        let mut recovered = Binary::open(&packed_path).unwrap();
        let original_address = original.find("add3").unwrap().addr;
        let recovered_address = recovered.find("add3").unwrap().addr;
        assert_eq!(original_address, recovered_address, "{name}");
        assert_eq!(
            original.decompile(original_address, None, None).unwrap(),
            recovered.decompile(recovered_address, None, None).unwrap(),
            "{name}"
        );
        assert!(
            recovered
                .image()
                .packing
                .as_ref()
                .unwrap()
                .method
                .contains("direct decoder")
        );
        let starts: Vec<u64> = original.image().functions.keys().copied().collect();
        assert_eq!(
            starts,
            recovered
                .image()
                .functions
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            "{name}"
        );
        for address in starts {
            assert_eq!(
                original
                    .decompile(address, None, None)
                    .map_err(|error| error.to_string()),
                recovered
                    .decompile(address, None, None)
                    .map_err(|error| error.to_string()),
                "{name}: 0x{address:x}"
            );
        }
        let original_code = original
            .decompile(original_address, None, None)
            .unwrap()
            .replace("add3(", "original_add3(");
        let recovered_code = recovered.decompile(recovered_address, None, None).unwrap();
        let source = format!(
            r#"
#include <stdint.h>
{original_code}
{recovered_code}
int main(void) {{
    uint32_t state = 1;
    for (unsigned i=0; i<4096; ++i) {{
        state = state * 1664525u + 1013904223u;
        uint32_t a=state, b=state ^ UINT32_MAX, c=state >> 3, expected=a+b+c;
        if ((uint32_t)add3(a,b,c) != expected || (uint32_t)original_add3(a,b,c) != expected) return 1;
    }}
    return 0;
}}
"#
        );
        let native = directory.join("native");
        common::compiler::compile_file(
            Command::new("clang")
                .args(["-O2", "-Werror=implicit-function-declaration"])
                .arg(directory.join("check.c"))
                .arg("-o")
                .arg(&native),
            &directory.join("check.c"),
            &source,
        );
        run(&mut Command::new(native));
        let saved = directory.join("saved");
        recovered.image().save_unpacked(&saved).unwrap();
        assert!(recovered.image().save_unpacked(&saved).is_err());
        assert!(Binary::open(&saved).unwrap().image().packing.is_none());
        // An infinite-loop entry is never run by the direct decoder.
        assert_eq!(
            Binary::open(&saved).unwrap().image().entry,
            original.image().entry
        );
        let script = directory.join("recover.js");
        let script_saved = directory.join("script-saved");
        fs::write(&script, format!("const b=velk.open({}); if(b.packing.packer !== 'UPX') throw Error('packer'); b.saveUnpacked({}); b.getFunction('add3').decompile()", json!(packed_path), json!(script_saved))).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_velk"))
            .arg("--run")
            .arg(&script)
            .output()
            .unwrap();
        assert!(output.status.success(), "{name}: {output:?}");
        let cli_saved = directory.join("cli-saved");
        let output = Command::new(env!("CARGO_BIN_EXE_velk"))
            .args(["-D", "--save-unpacked"])
            .arg(&cli_saved)
            .arg(&packed_path)
            .arg("add3")
            .output()
            .unwrap();
        assert!(output.status.success(), "{name}: {output:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("direct decoder"));
        let mcp_saved = directory.join("mcp-saved");
        let code = format!(
            "const b=velk.open({}); b.saveUnpacked({}); b.getFunction('add3').decompile()",
            json!(packed_path),
            json!(mcp_saved)
        );
        let mut child = Command::new(env!("CARGO_BIN_EXE_velk"))
            .arg("--mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"velk_run_script","arguments":{"code":code}}});
        writeln!(child.stdin.take().unwrap(), "{request}").unwrap();
        let response = child.wait_with_output().unwrap();
        assert!(response.status.success(), "{response:?}");
        let response: serde_json::Value = serde_json::from_slice(&response.stdout).unwrap();
        assert_eq!(response["result"]["isError"], false, "{response:?}");
        assert!(mcp_saved.is_file());
        let truncated = directory.join("damaged");
        fs::write(&truncated, &packed_bytes[..packed_bytes.len() / 2]).unwrap();
        assert!(Binary::open(&truncated).is_err(), "{name}");
    }
}

#[test]
fn damaged_upx_and_unpacked_save_requests_fail_clearly() {
    let directory = directory("invalid");
    let path = directory.join("damaged");
    let mut bytes = vec![0; 256];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[64..68].copy_from_slice(b"UPX!");
    fs::write(&path, &bytes).unwrap();
    let error = Binary::open(&path).err().unwrap();
    assert!(error.to_string().contains("packed input:"), "{error}");
    let original = Binary::open(&common::fixtures_dir().join("l0_arith_x64.o")).unwrap();
    assert!(
        original
            .image()
            .save_unpacked(&directory.join("unused"))
            .is_err()
    );
    assert!(!directory.join("unused").exists());
    assert!(velk::loader::packed::detect(b"UPX! is an ordinary raw byte string").is_none());
}

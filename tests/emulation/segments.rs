//! ELF load permissions and zero-filled memory, including the final page.

use super::*;

#[test]
fn elf_segments_include_zero_filled_pages() {
    use object::{Object, ObjectSection};

    for arch in ["x86_64", "i386", "aarch64", "armv7", "thumbv7"] {
        let directory = common::root().join(format!("target/segment-memory-{arch}"));
        fs::create_dir_all(&directory).unwrap();
        let source = directory.join("memory.c");
        let object = directory.join("memory.o");
        common::compiler::compile_file(
            Command::new("clang")
                .arg(format!("--target={arch}-unknown-linux-gnu"))
                .args(["-O0", "-ffreestanding", "-fno-stack-protector", "-c"])
                .arg(&source)
                .arg("-o")
                .arg(&object),
            &source,
            "unsigned char initialized[4] = {1, 2, 3, 4};\nunsigned char zeroed[4100];\nint segment_read(volatile unsigned char *p) { return *p; }\nint segment_write(volatile unsigned char *p) { *p = 37; return *p; }\n",
        );
        let path = directory.join("memory.elf");
        let output = Command::new("ld.lld")
            .args(["-e", "segment_write"])
            .arg(&object)
            .arg("-o")
            .arg(&path)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let bytes = fs::read(&path).unwrap();
        let file = object::File::parse(bytes.as_slice()).unwrap();
        let bss = file.section_by_name(".bss").unwrap();
        let bss_end = bss.address() + bss.size();
        let page_end = (bss_end + 4095) & !4095;
        assert!(page_end > bss_end);
        let binary = Binary::open(&path).unwrap();
        for address in [bss.address(), bss_end - 1, bss_end, page_end - 1] {
            let options: Options =
                serde_json::from_value(json!({"arguments": [format!("0x{address:x}")]})).unwrap();
            let report = emulation::run(&binary, "segment_read", &options, None).unwrap();
            assert_eq!(report.return_value, "0x0", "{arch} {address:x}: {report:?}");
            let report = emulation::run(&binary, "segment_write", &options, None).unwrap();
            assert_eq!(
                report.return_value, "0x25",
                "{arch} {address:x}: {report:?}"
            );
            assert!(report.error.is_none(), "{report:?}");
        }
        let options: Options =
            serde_json::from_value(json!({"arguments": [format!("0x{page_end:x}")]})).unwrap();
        let report = emulation::run(&binary, "segment_write", &options, None).unwrap();
        assert!(report.error.is_some(), "{arch}: {report:?}");
        if arch == "x86_64" {
            use std::process::Stdio;

            let options = json!({"arguments": [format!("0x{bss_end:x}")]});
            let output = Command::new(env!("CARGO_BIN_EXE_velk"))
                .args(["--emulate", "--json"])
                .arg(&path)
                .arg("segment_write")
                .arg("--emulation-options")
                .arg(options.to_string())
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            let cli: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(cli["returnValue"], "0x25");
            let script = format!(
                "velk.open({}).getFunction('segment_write').emulate({options})",
                json!(path)
            );
            let result = velk::script::Engine::new().unwrap().run(&script, None);
            assert!(result.error.is_none(), "{:?}", result.error);
            assert_eq!(serde_json::from_str::<Value>(&result.output).unwrap(), cli);
            let child = Command::new(env!("CARGO_BIN_EXE_velk"))
                .arg("--mcp")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let request = json!({"jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{"name":"velk_emulate", "arguments":{"path":path, "start":"segment_write", "options":options}}});
            let output = common::mcp_request(child, &request);
            let response: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(response["result"]["isError"], false, "{response}");
            let report: Value =
                serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap())
                    .unwrap();
            assert_eq!(report, cli);
        }
    }
}

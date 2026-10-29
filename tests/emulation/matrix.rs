//! Native differential checks shared by all execution interfaces.

use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::OnceLock;

use serde_json::{Value, json};
use velk::emulation::{self, Options};
use velk::service::Binary;

use crate::common;

pub(super) const ROUTINES: [&str; 10] = [
    "xor_key",
    "rolling_xor",
    "rc4",
    "base64_decode",
    "crc32",
    "adler32",
    "xtea_decrypt",
    "stack_string",
    "substitution",
    "length_decode",
];
pub(super) const ARCHITECTURES: [&str; 5] = ["x86_64", "aarch64", "i386", "arm32", "thumb32"];
pub(super) const HEAP: u64 = 0x1000_0000;

pub(super) fn fixtures() -> &'static Path {
    static DIRECTORY: OnceLock<PathBuf> = OnceLock::new();
    DIRECTORY.get_or_init(|| {
        let directory =
            common::root().join(format!("target/emulation-matrix-{}", std::process::id()));
        let output = Command::new("sh")
            .arg(common::root().join("tests/make_emulation_fixtures.sh"))
            .arg(&directory)
            .output()
            .expect("building emulation fixtures");
        assert!(output.status.success(), "{output:?}");
        directory
    })
}

pub(super) struct Interfaces {
    engine: velk::script::Engine,
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
}

impl Interfaces {
    pub(super) fn new() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_velk"))
            .arg("--mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("starting MCP server");
        let input = child.stdin.take().expect("MCP input");
        let output = BufReader::new(child.stdout.take().expect("MCP output"));
        Self {
            engine: velk::script::Engine::new().expect("JavaScript engine"),
            child,
            input: Some(input),
            output,
        }
    }

    pub(super) fn check(
        &mut self,
        path: &Path,
        binary: &Binary,
        start: &str,
        options: Value,
    ) -> Value {
        use std::io::{BufRead as _, Write as _};

        let parsed: Options = serde_json::from_value(options.clone()).expect("test options");
        let report = emulation::run(binary, start, &parsed, None).expect("valid initial state");
        let expected = serde_json::to_value(report).expect("serializing execution report");
        let compare = |actual: &Value, interface: &str| {
            if parsed.time_limit_ms > 0 && expected["reason"] == "time limit" {
                // The deadline can interrupt different instructions in separate processes.
                for field in ["reason", "error", "heapBase", "heapSize", "stackPointer"] {
                    assert_eq!(
                        actual[field], expected[field],
                        "{interface}: {start} {options}"
                    );
                }
            } else {
                assert_eq!(
                    actual,
                    &expected,
                    "{interface}: {} {start} {options}",
                    path.display()
                );
            }
        };
        let success = matches!(
            expected["reason"].as_str(),
            Some("return" | "end address" | "exit")
        );
        let cli = Command::new(env!("CARGO_BIN_EXE_velk"))
            .args(["--emulate", "--json"])
            .arg(path)
            .arg(start)
            .arg("--emulation-options")
            .arg(options.to_string())
            .output()
            .expect("running CLI");
        assert_eq!(cli.status.success(), success, "{start}: {cli:?}");
        let actual: Value = serde_json::from_slice(&cli.stdout).expect("CLI report JSON");
        compare(&actual, "CLI");
        for selection in [
            format!(".emulate({}, {options})", json!(start)),
            format!(".getFunction({}).emulate({options})", json!(start)),
        ] {
            // A raw data address need not be a discovered function.
            if selection.starts_with(".getFunction") && velk::addr::parse(start).is_some() {
                continue;
            }
            let script = format!("velk.open({}){selection}", json!(path));
            let result = self.engine.run(&script, None);
            assert!(result.error.is_none(), "{start}: {:?}", result.error);
            let actual: Value =
                serde_json::from_str(&result.output).expect("JavaScript report JSON");
            compare(&actual, "JavaScript");
        }
        let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"velk_emulate","arguments":{"path":path,"start":start,"options":options}}});
        writeln!(self.input.as_mut().expect("open MCP input"), "{request}").expect("MCP request");
        let mut line = String::new();
        assert_ne!(self.output.read_line(&mut line).expect("MCP response"), 0);
        let response: Value = serde_json::from_str(&line).expect("MCP response JSON");
        assert_eq!(response["result"]["isError"], !success, "{response}");
        let actual: Value = serde_json::from_str(
            response["result"]["content"][0]["text"]
                .as_str()
                .expect("MCP text"),
        )
        .expect("MCP report JSON");
        compare(&actual, "MCP");
        expected
    }
}

impl Drop for Interfaces {
    fn drop(&mut self) {
        drop(self.input.take());
        assert!(self.child.wait().expect("MCP shutdown").success());
    }
}

pub(super) fn bytes_after(report: &Value, address: u64, initial: &[u8]) -> Vec<u8> {
    let mut bytes = initial.to_vec();
    for region in report["memory"].as_array().expect("changed memory") {
        let start = velk::addr::parse(region["address"].as_str().expect("region address"))
            .expect("hex address");
        for (offset, byte) in region["bytes"]
            .as_array()
            .expect("region bytes")
            .iter()
            .enumerate()
        {
            if let Some(index) = (start + offset as u64).checked_sub(address)
                && let Some(slot) = bytes.get_mut(index as usize)
            {
                *slot = byte.as_u64().expect("byte") as u8;
            }
        }
    }
    bytes
}

pub(super) fn value(report: &Value) -> u32 {
    assert_eq!(report["reason"], "return", "{report}");
    velk::addr::parse(report["returnValue"].as_str().expect("return value"))
        .expect("integer return") as u32
}

fn inputs() -> Vec<(Vec<u8>, u32)> {
    let mut inputs = Vec::new();
    for mut seed in [0, 1, 0x9e37_79b9u32, u32::MAX] {
        for length in [0, 1, 2, 3, 7, 8, 15, 16, 31, 64, 255, 256, 1025] {
            let mut bytes = Vec::new();
            for _ in 0..length {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                bytes.push((seed >> 24) as u8);
            }
            inputs.push((bytes, seed));
        }
    }
    inputs.push(((0..=255).collect(), 0));
    inputs.push((vec![0; 257], u32::MAX));
    inputs.push((vec![255; 257], 0x8000_0000));
    inputs.push((b"AAECAwQFBgcICQoLDA0ODw==".to_vec(), 93));
    inputs.push((b" SGVsbG8sIHdvcmxkIQ==\n".to_vec(), 0x1234_5678));
    inputs
}

fn reference(architecture: &str, optimization: &str, inputs: &[(Vec<u8>, u32)]) -> Vec<u8> {
    let input_architecture = architecture;
    let architecture = if cfg!(target_os = "macos") {
        if architecture == "x86_64" {
            "x86_64"
        } else {
            "arm64"
        }
    } else {
        "host"
    };
    let directory = fixtures();
    let input = directory.join(format!("{input_architecture}.{optimization}.input"));
    let output = directory.join(format!("{input_architecture}.{optimization}.output"));
    let mut input_bytes = Vec::new();
    for routine in 0..ROUTINES.len() {
        for (bytes, key) in inputs {
            for word in [routine as u32, bytes.len() as u32, *key] {
                input_bytes.extend(word.to_le_bytes());
            }
            input_bytes.extend(bytes);
        }
    }
    fs::write(&input, input_bytes).expect("native input");
    let status = Command::new(directory.join(format!("{architecture}.{optimization}.native")))
        .stdin(fs::File::open(input).expect("reference input"))
        .stdout(fs::File::create(&output).expect("reference output"))
        .status()
        .expect("running native reference");
    assert!(status.success(), "{architecture}: {status}");
    fs::read(output).expect("reference output")
}

fn matrix(architecture: &str) {
    let inputs = inputs();
    let mut interfaces = Interfaces::new();
    for optimization in ["O0", "O2"] {
        let mut paths = vec![fixtures().join(format!("{architecture}.{optimization}.elf"))];
        if cfg!(target_os = "macos") && matches!(architecture, "x86_64" | "aarch64") {
            let native_architecture = if architecture == "aarch64" {
                "arm64"
            } else {
                architecture
            };
            paths.push(fixtures().join(format!("{native_architecture}.{optimization}.native")));
        }
        for path in paths {
            let binary = Binary::open(&path).expect("loading routine fixture");
            let reference = reference(architecture, optimization, &inputs);
            let mut offset = 0;
            for routine in ROUTINES {
                for (index, (bytes, key)) in inputs.iter().enumerate() {
                    let expected = u32::from_le_bytes(
                        reference[offset..offset + 4]
                            .try_into()
                            .expect("reference result"),
                    );
                    offset += 4;
                    // Sentinel bytes catch stores outside the supplied buffer, including empty input.
                    let mut initial = vec![0xa5; 16];
                    initial.extend(bytes);
                    initial.extend([0x5a; 16]);
                    let options = json!({"arguments":[HEAP+16,bytes.len(),key],"memory":[{"address":HEAP,"bytes":initial}],"stepLimit":20000000,"timeLimitMs":30000});
                    let report = interfaces.check(&path, &binary, routine, options);
                    assert_eq!(
                        value(&report),
                        expected,
                        "{architecture} {optimization} {routine} input {index}"
                    );
                    let actual = bytes_after(&report, HEAP, &initial);
                    assert_eq!(&actual[..16], &[0xa5; 16]);
                    assert_eq!(
                        &actual[16..16 + bytes.len()],
                        &reference[offset..offset + bytes.len()],
                        "{architecture} {optimization} {routine} input {index}"
                    );
                    assert_eq!(&actual[16 + bytes.len()..], &[0x5a; 16]);
                    offset += bytes.len();
                }
                eprintln!(
                    "{routine} {architecture} {optimization} {}: {} inputs, 0 mismatches (library, CLI, JavaScript binary/function, MCP)",
                    path.extension().expect("fixture format").to_string_lossy(),
                    inputs.len()
                );
            }
            assert_eq!(offset, reference.len());
        }
    }
}

#[test]
fn x86_64_routines() {
    matrix("x86_64");
}
#[test]
fn aarch64_routines() {
    matrix("aarch64");
}
#[test]
fn i386_routines() {
    matrix("i386");
}
#[test]
fn arm32_routines() {
    matrix("arm32");
}
#[test]
fn thumb32_routines() {
    matrix("thumb32");
}

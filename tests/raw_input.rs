//! Headerless code uses the same printed-C and execution interfaces as object files.

mod common;

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use velk::emulation::{self, MemoryWrite, Options, Word};
use velk::loader::{ByteOrder, OpenOptions, RawArchitecture, RawOptions};
use velk::service::{Binary, Session};

fn scratch(name: &str) -> PathBuf {
    let path = common::root()
        .join("target/raw-tests")
        .join(format!("{name}-{}", std::process::id()));
    fs::create_dir_all(&path).expect("creating raw input test directory");
    path
}

fn cases() -> [(RawArchitecture, &'static str); 5] {
    [
        (
            RawArchitecture::X86_64,
            "../raw_fixtures/l0_arith_x64.nodebug.o",
        ),
        (
            RawArchitecture::I386,
            "metrics/l0_arith.i386.O2.stripped.elf",
        ),
        (
            RawArchitecture::Aarch64,
            "../raw_fixtures/l0_arith_a64.nodebug.o",
        ),
        (
            RawArchitecture::Arm32,
            "../raw_fixtures/l0_arith.arm.O2.nodebug.elf",
        ),
        (
            RawArchitecture::Thumb,
            "../raw_fixtures/l0_arith.thumb.O2.nodebug.elf",
        ),
    ]
}

fn extracted(
    arch: RawArchitecture,
    fixture: &str,
    directory: &str,
) -> (Binary, PathBuf, OpenOptions) {
    let directory = scratch(directory).join(format!("{arch:?}"));
    fs::create_dir_all(&directory).expect("creating architecture test directory");
    let binary =
        Binary::open(&common::fixtures_dir().join(fixture)).expect("opening original fixture");
    let function = binary
        .find("add3")
        .expect("finding the arithmetic function");
    let bytes = binary
        .image()
        .read_vaddr(
            function.addr,
            function.size.expect("the fixture function has a size"),
        )
        .expect("reading original code");
    let path = directory.join("code.bin");
    fs::write(&path, bytes).expect("writing extracted code");
    let options = OpenOptions {
        arch: None,
        raw: Some(RawOptions {
            arch,
            base: 0x7000,
            entries: Vec::new(),
            byte_order: ByteOrder::Little,
        }),
    };
    (binary, path, options)
}

fn normalized(code: &str, name: &str, address: u64) -> String {
    code.replace(name, "add3")
        .replace(&format!("0x{address:x}"), "ADDRESS")
}

#[test]
fn extracted_functions_print_and_execute_like_the_original_on_every_architecture() {
    for (arch, fixture) in cases() {
        let (mut original, path, options) = extracted(arch, fixture, "semantics");
        let mut raw = Binary::open_input(&path, None, &options).unwrap();
        let original_address = original.find("add3").unwrap().addr;
        let raw_code = raw.decompile(0x7000, None, None).unwrap();
        let original_code = original.decompile(original_address, None, None).unwrap();
        assert_eq!(
            normalized(&raw_code, "sub_7000", 0x7000),
            normalized(&original_code, "add3", original_address),
            "{arch:?}"
        );
        let write = Options {
            memory: vec![MemoryWrite {
                address: Word::Integer(0x7000),
                bytes: Some(vec![0]),
                value: None,
                width: None,
            }],
            ..Options::default()
        };
        let protected = emulation::run(&raw, "0x7000", &write, None).unwrap_err();
        assert!(
            protected.to_string().contains("protected section raw"),
            "{arch:?}: {protected}"
        );
        let mut state = 1u32;
        for index in 0..96 {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            let a = [0, 1, u32::MAX, 0x8000_0000, 0x7fff_ffff, state][index % 6];
            let b = state.rotate_left(11);
            let c = state.rotate_right(7);
            let arguments = vec![
                Word::Integer(u64::from(a)),
                Word::Integer(u64::from(b)),
                Word::Integer(u64::from(c)),
            ];
            let execution = Options {
                arguments,
                ..Options::default()
            };
            for (binary, start) in [
                (&raw, "0x7000".to_owned()),
                (&original, format!("0x{original_address:x}")),
            ] {
                let report = emulation::run(binary, &start, &execution, None).unwrap();
                assert_eq!(report.reason, "return", "{arch:?}: {report:?}");
                assert_eq!(
                    velk::addr::parse(&report.return_value).unwrap() as u32,
                    a.wrapping_add(b).wrapping_add(c),
                    "{arch:?}: {report:?}"
                );
            }
        }
        let source = format!(
            r#"
#include <stdint.h>
{original_code}
{raw_code}
int main(void) {{
    uint32_t state = 1;
    uint32_t edge[] = {{0, 1, UINT32_MAX, 0x80000000u, 0x7fffffffu}};
    for (unsigned i=0; i<4096; ++i) {{
        state = state * 1664525u + 1013904223u;
        uint32_t a = i < 5 ? edge[i] : state, b = state ^ 0xdeadbeefu, c = state >> 3;
        uint32_t expected = a + b + c;
        if ((uint32_t)add3(a,b,c) != expected || (uint32_t)sub_7000(a,b,c) != expected) return 1;
    }}
    return 0;
}}
"#
        );
        let executable = path.with_extension("native");
        common::compiler::compile_file(
            Command::new("clang")
                .args(["-O2", "-Werror=implicit-function-declaration"])
                .arg(path.with_extension("c"))
                .arg("-o")
                .arg(&executable),
            &path.with_extension("c"),
            &source,
        );
        let result = Command::new(executable).output().unwrap();
        assert!(result.status.success(), "{arch:?}: {result:?}");
    }
}

fn mcp(requests: &[Value]) -> Vec<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("starting the MCP server");
    let mut input = child.stdin.take().expect("MCP input is piped");
    for request in requests {
        writeln!(input, "{request}").expect("sending an MCP request");
    }
    drop(input);
    let output = child
        .wait_with_output()
        .expect("waiting for the MCP server");
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout)
        .expect("MCP output is UTF-8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("MCP output is JSON"))
        .collect()
}

#[test]
fn cli_scripts_and_mcp_accept_each_mapping_and_the_documented_examples() {
    for (arch, fixture) in cases() {
        let (_, path, options) = extracted(arch, fixture, "interfaces");
        let raw = options.raw.as_ref().unwrap();
        let arch_name = serde_json::to_value(arch).unwrap();
        let listing = Command::new(env!("CARGO_BIN_EXE_velk"))
            .args([
                "-D",
                "--raw-arch",
                arch_name.as_str().unwrap(),
                "--load-address",
                "0x7000",
            ])
            .arg(&path)
            .arg("0x7000")
            .output()
            .unwrap();
        assert!(listing.status.success(), "{arch:?}: {listing:?}");
        assert!(String::from_utf8_lossy(&listing.stdout).contains("sub_7000("));
        let code = format!(
            "const b = velk.open({}, {{raw:{}}}); if (b.format !== 'raw') throw Error('format'); b.getFunction('0x7000').decompile()",
            json!(path),
            json!(raw)
        );
        let script = path.with_extension("js");
        fs::write(&script, &code).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_velk"))
            .arg("--run")
            .arg(&script)
            .output()
            .unwrap();
        assert!(output.status.success(), "{arch:?}: {output:?}");
        let responses = mcp(&[
            json!({"jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{"name":"velk_run_script", "arguments":{"code":code}}}),
            json!({"jsonrpc":"2.0", "id":2, "method":"tools/call", "params":{"name":"velk_emulate", "arguments":{"path":path,"raw":raw,"start":"0x7000","options":{"arguments":[1,2,3]}}}}),
        ]);
        assert_eq!(responses[0]["result"]["isError"], false, "{responses:?}");
        assert_eq!(
            responses[0]["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .trim(),
            String::from_utf8(output.stdout).unwrap().trim()
        );
        assert_eq!(responses[1]["result"]["isError"], false, "{responses:?}");
        let report: Value = serde_json::from_str(
            responses[1]["result"]["content"][0]["text"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(report["returnValue"], "0x6");
    }
}

#[test]
fn raw_strings_search_annotations_and_cached_mappings_work() {
    let directory = scratch("navigation");
    let path = directory.join("code.bin");
    fs::write(&path, b"\xb8\x2a\x00\x00\x00\xc3hello raw world\0").unwrap();
    let options = OpenOptions {
        arch: None,
        raw: Some(RawOptions {
            arch: RawArchitecture::X86_64,
            base: 0x7000,
            entries: vec![0x7000],
            byte_order: ByteOrder::Little,
        }),
    };
    let mut session = Session::default();
    assert_eq!(
        session
            .open_input(&path, None, &options)
            .unwrap()
            .image()
            .entry,
        Some(0x7000)
    );
    let mut alternate = options.clone();
    alternate.raw.as_mut().unwrap().base = 0x8000;
    alternate.raw.as_mut().unwrap().entries = vec![0x8000];
    assert_eq!(
        session
            .open_input(&path, None, &alternate)
            .unwrap()
            .image()
            .entry,
        Some(0x8000)
    );
    assert_eq!(
        session
            .open_input(&path, None, &options)
            .unwrap()
            .image()
            .entry,
        Some(0x7000)
    );
    let project = directory.join("analysis.json");
    let code = format!(
        r#"
const b = velk.open({}, {{raw:{}, project:{}}});
if (!b.strings({{decode:false}}).strings.some(s => s.text === 'hello raw world')) throw Error('strings');
if (b.search('hello raw world', {{encoding:'ascii'}}).matches.length !== 1) throw Error('search');
b.projectSet({{target:{{kind:'function',address:'0x7000'}}, name:'answer'}});
b.getFunction('answer').decompile()
"#,
        json!(path),
        json!(options.raw),
        json!(project)
    );
    let engine = velk::script::Engine::new().unwrap();
    let outcome = engine.run(&code, None);
    assert!(
        outcome.error.is_none(),
        "{:?}: {}",
        outcome.error,
        outcome.output
    );
    let mut reopened = Binary::open_with_project(&path, Some(&project)).unwrap();
    assert_eq!(reopened.image().entry, Some(0x7000));
    assert!(
        reopened
            .decompile(0x7000, None, None)
            .unwrap()
            .contains("answer(")
    );
    assert!(Binary::open_input(&path, Some(&project), &alternate).is_err());
    let other = directory.join("other.bin");
    fs::copy(&path, &other).unwrap();
    let other_project = directory.join("other.json");
    let code = format!(
        "const a=velk.open({},{{project:{}}}); const b=velk.open({},{{project:{},raw:{}}}); a.compare(b,{{carryAnnotations:true}})",
        json!(path),
        json!(project),
        json!(other),
        json!(other_project),
        json!(alternate.raw)
    );
    let result = engine.run(&code, None);
    assert!(
        result.error.is_none(),
        "{:?}: {}",
        result.error,
        result.output
    );
    let reopened = Binary::open_with_project(&other, Some(&other_project)).unwrap();
    assert_eq!(reopened.image().entry, Some(0x8000));
    assert_eq!(reopened.find("answer").unwrap().addr, 0x8000);
}

#[test]
fn malformed_mappings_fail_without_guessing_an_architecture() {
    let directory = scratch("invalid");
    let path = directory.join("code.bin");
    fs::write(&path, [0xc3]).unwrap();
    assert!(Binary::open(&path).is_err());
    let valid = RawOptions {
        arch: RawArchitecture::X86_64,
        base: 0x7000,
        entries: Vec::new(),
        byte_order: ByteOrder::Little,
    };
    for raw in [
        RawOptions {
            base: u64::MAX,
            ..valid.clone()
        },
        RawOptions {
            arch: RawArchitecture::I386,
            base: 1 << 32,
            ..valid.clone()
        },
        RawOptions {
            arch: RawArchitecture::Arm32,
            base: 3,
            ..valid.clone()
        },
        RawOptions {
            entries: vec![0x7001],
            ..valid.clone()
        },
        RawOptions {
            arch: RawArchitecture::Arm32,
            entries: vec![0x7000, 0x7001],
            ..valid.clone()
        },
        RawOptions {
            byte_order: ByteOrder::Big,
            ..valid.clone()
        },
    ] {
        let error = Binary::open_input(
            &path,
            None,
            &OpenOptions {
                arch: None,
                raw: Some(raw),
            },
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("raw input:"), "{error}");
    }
    fs::write(&path, []).unwrap();
    assert!(
        Binary::open_input(
            &path,
            None,
            &OpenOptions {
                arch: None,
                raw: Some(valid)
            }
        )
        .is_err()
    );
}

#[test]
fn entries_references_and_full_precision_addresses_survive_script_handles() {
    let directory = scratch("entries");
    let path = directory.join("calls.bin");
    fs::write(&path, [0xe8, 1, 0, 0, 0, 0xc3, 0xb8, 42, 0, 0, 0, 0xc3]).unwrap();
    let engine = velk::script::Engine::new().unwrap();
    for arch in ["x86_64", "i386"] {
        let code = format!(
            r#"
const b = velk.open({}, {{raw:{{arch:{},base:'0x7000',entries:['0x7000','0x7006']}}}});
if (b.xrefs('0x7006').xrefs.length !== 1) throw Error('call reference');
if (b.emulate('0x7000').returnValue !== '0x2a') throw Error('execution');
if (b.readMemory('0x7000','u8').values[0] !== 232) throw Error('memory');
b.getFunction('0x7000').decompile()
"#,
            json!(path),
            json!(arch)
        );
        let result = engine.run(&code, None);
        assert!(
            result.error.is_none(),
            "{:?}: {}",
            result.error,
            result.output
        );
    }
    let code = format!(
        r#"
const b = velk.open({}, {{raw:{{arch:'x86_64',base:'0x20000000007000',entries:['0x20000000007000','0x20000000007006']}}}});
b.getFunction('0x20000000007000').emulate().returnValue
"#,
        json!(path)
    );
    let result = engine.run(&code, None);
    assert!(
        result.error.is_none(),
        "{:?}: {}",
        result.error,
        result.output
    );
    assert_eq!(result.output, "0x2a");
}

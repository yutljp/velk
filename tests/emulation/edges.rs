//! Library boundaries, limits, and the published execution examples.

use std::process::Command;

use serde_json::{Value, json};
use velk::service::Binary;

use super::matrix::{self, ARCHITECTURES, HEAP, Interfaces};
use crate::common;

const HOOKS: [&str; 12] = [
    "hook_copy",
    "hook_move",
    "hook_set",
    "hook_length",
    "hook_compare",
    "hook_compare_n",
    "hook_string_copy",
    "hook_allocate",
    "hook_calloc",
    "hook_overflow",
    "hook_free",
    "hook_complement_span",
];
const HEAP_END: u64 = HEAP + (1 << 24);

#[test]
fn extend_add_printed_c_compiles_and_matches_integer_reference() {
    use std::fmt::Write as _;

    let mut interfaces = Interfaces::new();
    let edges = [0u32, 1, 127, 128, 255, 65535, 0x8000_0000, u32::MAX];
    for mode in ["arm", "thumb"] {
        let path = matrix::fixtures().join(format!("{mode}.extensions.elf"));
        let mut binary = Binary::open(&path).expect("extension instruction fixture");
        let mut printed = String::new();
        let mut checks = String::new();
        for (name, rotation, width, signed) in [
            ("extend_byte", 0, 8, false),
            ("extend_half", 8, 16, false),
            ("extend_signed_byte", 16, 8, true),
            ("extend_signed_half", 24, 16, true),
        ] {
            let address = binary.find(name).expect("extension function").addr;
            let code = binary
                .decompile(address, None, None)
                .expect("printed extension");
            assert!(!code.contains("__asm__"), "{code}");
            printed.push_str(&code);
            for addend in edges {
                for source in edges {
                    let rotated = source.rotate_right(rotation);
                    let extended = match (width, signed) {
                        (8, false) => u32::from(rotated as u8),
                        (16, false) => u32::from(rotated as u16),
                        (8, true) => i32::from(rotated as i8) as u32,
                        (16, true) => i32::from(rotated as i16) as u32,
                        _ => unreachable!("byte or halfword"),
                    };
                    let expected = addend.wrapping_add(extended);
                    let report = interfaces.check(
                        &path,
                        &binary,
                        name,
                        json!({"arguments":[addend,source]}),
                    );
                    assert_eq!(
                        matrix::value(&report),
                        expected,
                        "{mode} {name} {addend:x} {source:x}"
                    );
                    writeln!(checks, "if ((uint32_t){name}((int32_t)UINT32_C({addend}), (int32_t)UINT32_C({source})) != UINT32_C({expected})) return 1;").expect("C assertions");
                }
            }
        }
        let source = format!(
            "{}\nint main(void) {{\n{checks}return 0;\n}}\n",
            velk::render::combine(&printed)
        );
        let source_path = matrix::fixtures().join(format!("{mode}.printed.c"));
        let executable = matrix::fixtures().join(format!("{mode}.printed"));
        common::compiler::compile_file(
            Command::new("clang")
                .args(["-std=c11", "-O2", "-Werror"])
                .arg(&source_path)
                .arg("-o")
                .arg(&executable),
            &source_path,
            &source,
        );
        assert!(
            Command::new(executable)
                .status()
                .expect("printed C execution")
                .success()
        );
    }
}

fn native_hook(
    architecture: &str,
    optimization: &str,
    arguments: [usize; 4],
    bytes: &[u8],
) -> Vec<u8> {
    let host = if cfg!(target_os = "macos") {
        if architecture == "x86_64" {
            "x86_64"
        } else {
            "arm64"
        }
    } else {
        "host"
    };
    let path = matrix::fixtures().join(format!("{host}.{optimization}.hooks.native"));
    let mut command = Command::new(path);
    command.args(arguments.map(|argument| argument.to_string()));
    let input = matrix::fixtures().join("hook.input");
    std::fs::write(&input, bytes).expect("libc input");
    let output = command
        .stdin(std::fs::File::open(input).expect("libc input file"))
        .output()
        .expect("native libc reference");
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout.len(), 132);
    output.stdout
}

fn assert_error(report: &Value, text: &str, address: u64) {
    assert_eq!(report["reason"], "error", "{report}");
    let message = report["error"].as_str().expect("error diagnostic");
    assert!(message.contains(text), "{message}");
    assert!(message.contains(&velk::addr::format(address)), "{message}");
    assert!(message.contains("instruction 0x"), "{message}");
}

#[test]
fn hooks_match_libc_and_check_mapped_boundaries() {
    let mut interfaces = Interfaces::new();
    for architecture in ARCHITECTURES {
        for optimization in ["O0", "O2"] {
            let path = matrix::fixtures().join(format!("{architecture}.{optimization}.hooks.elf"));
            let binary = Binary::open(&path).expect("hook fixture");
            let readonly = symbol(&binary, "hook_read_only");
            let section = binary
                .image()
                .section_at(readonly)
                .expect("read-only section");
            let end = section.vaddr + section.size;
            let source = binary
                .image()
                .read_vaddr(end - 4, 4)
                .expect("section's final bytes");
            let report = interfaces.check(
                &path,
                &binary,
                "hook_copy",
                json!({"arguments":[HEAP,end-4,4]}),
            );
            assert_eq!(matrix::value(&report), 1);
            assert_eq!(matrix::bytes_after(&report, HEAP, &[0; 4]), source);
            let mut cases = Vec::new();
            for routine in 0..HOOKS.len() {
                for size in [0, 1, 17] {
                    cases.push((routine, 0, 64, size));
                }
            }
            // Both overlap directions, identical ranges, and strings ending at the last mapped byte.
            cases.extend([
                (1, 1, 0, 31),
                (1, 0, 1, 31),
                (1, 0, 0, 32),
                (0, 0, 127, 1),
                (3, 127, 0, 0),
                (3, 120, 0, 0),
                (4, 63, 127, 0),
                (5, 63, 127, 1),
                (5, 62, 126, 1),
                (5, 62, 126, 2),
                (5, 62, 126, 128),
                (6, 120, 64, 0),
                (6, 0, 127, 0),
                (11, 0, 0, 0),
                (11, 0, 127, 0),
                (11, 127, 0, 0),
                (11, 0, 64, 0),
            ]);
            for (routine, destination, source, size) in cases {
                let mut initial: Vec<u8> = (0..128).map(|i| ((i % 64) + 128) as u8).collect();
                initial[63] = 0;
                initial[127] = 0;
                initial[62] = 255;
                initial[126] = 1;
                // strcpy at 120 needs a short source.
                if routine == 6 && destination == 120 {
                    initial[68] = 0;
                }
                let native = native_hook(
                    architecture,
                    optimization,
                    [routine, destination, source, size],
                    &initial,
                );
                let base = HEAP_END - 128;
                let pointer = if routine == 10 {
                    0
                } else {
                    base + destination as u64
                };
                let options = json!({"arguments":[pointer,base+source as u64,size],"memory":[{"address":base,"bytes":initial}]});
                // Allocate away from the boundary; initial heap bytes reserve space before malloc.
                let options = if matches!(routine, 7..=9) {
                    json!({"arguments":[HEAP,HEAP+64,size]})
                } else {
                    options
                };
                let report = interfaces.check(&path, &binary, HOOKS[routine], options);
                let expected = u32::from_le_bytes(native[..4].try_into().expect("libc result"));
                assert_eq!(
                    matrix::value(&report),
                    expected,
                    "{architecture} {optimization} {} n={size}",
                    HOOKS[routine]
                );
                if !matches!(routine, 7..=9) {
                    assert_eq!(
                        matrix::bytes_after(&report, base, &initial),
                        native[4..],
                        "{architecture} {optimization} {}",
                        HOOKS[routine]
                    );
                }
            }
            for hook in ["hook_allocate", "hook_calloc"] {
                let report =
                    interfaces.check(&path, &binary, hook, json!({"arguments":[0,0,16777217]}));
                assert_eq!(matrix::value(&report), 0, "bounded heap exhaustion");
            }
            let report = interfaces.check(
                &path,
                &binary,
                "hook_allocate",
                json!({"arguments":[0,0,16777216]}),
            );
            assert_eq!(
                matrix::value(&report),
                1,
                "an allocation can fill the heap exactly"
            );
            for hook in ["hook_set", "hook_calloc"] {
                let report = interfaces.check(
                    &path,
                    &binary,
                    hook,
                    json!({"arguments":[HEAP,HEAP+64,4096],"stepLimit":50}),
                );
                assert_eq!(report["reason"], "step limit", "{report}");
                assert_eq!(report["steps"], 50);
            }
            for (hook, args, memory, message, address) in [
                (
                    "hook_copy",
                    vec![HEAP_END - 1, HEAP, 2],
                    json!([]),
                    "unmapped memory write",
                    HEAP_END,
                ),
                (
                    "hook_copy",
                    vec![HEAP, HEAP_END - 1, 2],
                    json!([]),
                    "unmapped memory read",
                    HEAP_END,
                ),
                (
                    "hook_length",
                    vec![HEAP_END - 1, 0, 0],
                    json!([{"address":HEAP_END-1,"bytes":[1]}]),
                    "unmapped memory read",
                    HEAP_END,
                ),
                (
                    "hook_compare",
                    vec![HEAP_END - 1, HEAP, 0],
                    json!([{"address":HEAP_END-1,"bytes":[1]},{"address":HEAP,"bytes":[1,0]}]),
                    "unmapped memory read",
                    HEAP_END,
                ),
                (
                    "hook_compare_n",
                    vec![HEAP_END - 1, HEAP, 2],
                    json!([{"address":HEAP_END-1,"bytes":[1]},{"address":HEAP,"bytes":[1,0]}]),
                    "unmapped memory read",
                    HEAP_END,
                ),
                (
                    "hook_string_copy",
                    vec![HEAP_END - 1, HEAP, 0],
                    json!([{"address":HEAP,"bytes":[1,0]}]),
                    "unmapped memory write",
                    HEAP_END,
                ),
                (
                    "hook_set",
                    vec![HEAP_END - 1, 0, 2],
                    json!([]),
                    "unmapped memory write",
                    HEAP_END,
                ),
                (
                    "hook_free",
                    vec![HEAP + 1, 0, 0],
                    json!([]),
                    "unallocated pointer",
                    HEAP + 1,
                ),
                (
                    "hook_copy",
                    vec![HEAP, HEAP + 64, 16777217],
                    json!([]),
                    "exceeds 16 MiB",
                    HEAP + 64,
                ),
                (
                    "hook_set",
                    vec![HEAP, 0, 16777217],
                    json!([]),
                    "exceeds 16 MiB",
                    HEAP,
                ),
            ] {
                let report = interfaces.check(
                    &path,
                    &binary,
                    hook,
                    json!({"arguments":args,"memory":memory}),
                );
                assert_error(&report, message, address);
            }
            let report = interfaces.check(
                &path,
                &binary,
                "hook_copy",
                json!({"arguments":[HEAP+1,HEAP,5]}),
            );
            assert_error(&report, "overlap", HEAP + 1);
            assert!(
                report["error"]
                    .as_str()
                    .expect("overlap error")
                    .contains(&velk::addr::format(HEAP))
            );
            eprintln!(
                "hooks {architecture} {optimization}: libc results, buffer bytes, mapping errors and heap limits agree across interfaces"
            );
        }
    }
}

fn symbol(binary: &Binary, name: &str) -> u64 {
    binary
        .image()
        .data_symbols
        .iter()
        .find(|(_, candidate)| candidate.as_str() == name)
        .map(|(&address, _)| address)
        .expect("fixture data symbol")
}

#[test]
fn execution_limits_and_permissions_agree_across_interfaces() {
    let mut interfaces = Interfaces::new();
    for architecture in ARCHITECTURES {
        for optimization in ["O0", "O2"] {
            let path = matrix::fixtures().join(format!("{architecture}.{optimization}.elf"));
            let binary = Binary::open(&path).expect("routine fixture");
            let readonly = symbol(&binary, "read_only");
            let writable_address = symbol(&binary, "writable");
            let code = binary.find("store_byte").expect("store function").addr;
            for (start, options, message, address) in [
                (
                    "store_byte".to_owned(),
                    json!({"arguments":[readonly]}),
                    "protected",
                    readonly,
                ),
                (
                    "store_byte".to_owned(),
                    json!({"arguments":[code]}),
                    "protected",
                    code,
                ),
                (
                    "load_byte".to_owned(),
                    json!({"arguments":["0x12345000"]}),
                    "unmapped memory read",
                    0x1234_5000,
                ),
                (
                    "store_byte".to_owned(),
                    json!({"arguments":["0x12345000"]}),
                    "unmapped memory write",
                    0x1234_5000,
                ),
                (
                    velk::addr::format(writable_address),
                    json!({}),
                    "non-executable",
                    writable_address,
                ),
                (
                    "0x12345000".to_owned(),
                    json!({}),
                    "unmapped code",
                    0x1234_5000,
                ),
            ] {
                assert_error(
                    &interfaces.check(&path, &binary, &start, options),
                    message,
                    address,
                );
            }
            let report = interfaces.check(&path, &binary, "recurse", json!({"arguments":[HEAP],"memory":[{"address":HEAP,"value":200,"width":4}],"stepLimit":1000000}));
            assert_eq!(report["reason"], "error", "{report}");
            assert!(
                report["error"]
                    .as_str()
                    .expect("depth error")
                    .contains("call depth exceeds 128"),
                "{report}"
            );
            for (options, reason, steps) in [
                (
                    json!({"arguments":[HEAP],"memory":[{"address":HEAP,"value":1,"width":4}],"stepLimit":40}),
                    "step limit",
                    Some(40),
                ),
                (json!({"stepLimit":0}), "step limit", Some(0)),
                (json!({"timeLimitMs":0}), "time limit", Some(0)),
            ] {
                let report = interfaces.check(&path, &binary, "spin", options);
                assert_eq!(report["reason"], reason, "{report}");
                if let Some(steps) = steps {
                    assert_eq!(report["steps"], steps);
                }
            }
            let report = interfaces.check(&path, &binary, "spin", json!({"arguments":[HEAP],"memory":[{"address":HEAP,"value":1,"width":4}],"timeLimitMs":20,"stepLimit":20000000}));
            assert_eq!(report["reason"], "time limit", "{report}");
            // Read the last byte of a loaded read-only section.
            let section = binary
                .image()
                .section_at(readonly)
                .expect("read-only section");
            let end = section.vaddr + section.size;
            let expected = binary
                .image()
                .read_vaddr(end - 1, 1)
                .expect("last section byte")[0];
            assert_eq!(
                matrix::value(&interfaces.check(
                    &path,
                    &binary,
                    "load_byte",
                    json!({"arguments":[end-1]})
                )),
                u32::from(expected)
            );
        }
    }
}

#[test]
fn published_emulation_examples_execute() {
    let path = matrix::fixtures().join("x86_64.O0.elf");
    let binary = Binary::open(&path).expect("documentation fixture");
    let io_path = matrix::fixtures().join("x86_64.O0.io.elf");
    let io_binary = Binary::open(&io_path).expect("I/O documentation fixture");
    let file_path = matrix::fixtures().join("x86_64.O0.streams.elf");
    let file_binary = Binary::open(&file_path).expect("file documentation fixture");
    let mut interfaces = Interfaces::new();
    for document in [
        "docs/EMULATION.md",
        "docs/EMULATION.ja.md",
        "README.md",
        "README.ja.md",
    ] {
        let text =
            std::fs::read_to_string(common::root().join(document)).expect("published document");
        let mut count = 0;
        for line in text.lines().filter(|line| {
            line.starts_with("velk --emulate app.elf ")
                || line.starts_with("velk --emulate path/to/binary ")
        }) {
            let (command, tail) = line
                .split_once("--emulation-options '")
                .expect("documented CLI options");
            let options = tail.split('\'').next().expect("quoted JSON");
            let start = command
                .split_whitespace()
                .nth(3)
                .expect("documented routine");
            let is_io = matches!(start, "check_flag" | "main" | "decode_buffer");
            let (example_path, example_binary) = if start == "read_file" {
                (&file_path, &file_binary)
            } else if is_io {
                (&io_path, &io_binary)
            } else {
                (&path, &binary)
            };
            let report = interfaces.check(
                example_path,
                example_binary,
                start,
                serde_json::from_str(options).expect("documented JSON"),
            );
            if start == "decode" {
                assert_eq!(
                    matrix::bytes_after(&report, HEAP, &[53, 56, 49, 49, 50, 93]),
                    b"hello\0"
                );
            } else if start == "read_file" {
                assert_eq!(report["reason"], "return", "{report}");
                assert_eq!(report["files"]["input"], json!([79, 75, 10]));
            } else if start == "check_flag" {
                assert_eq!(report["stdout"], "Correct\n");
            } else if start == "main" {
                assert_eq!(report["stdout"], "argc=2 argv0=app argv1=candidate\n");
            } else if start == "decode_buffer" {
                assert_eq!(report["reads"][0]["value"], "hello");
            } else {
                assert_eq!(matrix::value(&report), 6);
            }
            count += 1;
        }
        assert!(count > 0, "{document}: documentation examples disappeared");
        if document.starts_with("docs/") {
            let script = text
                .split("```js\n")
                .nth(1)
                .expect("JavaScript example")
                .split("```")
                .next()
                .expect("JavaScript fence");
            let script = script.replace("\"app.elf\"", &json!(path).to_string());
            let engine = velk::script::Engine::new().expect("JavaScript engine");
            let output = engine.run(&script, None);
            assert!(output.error.is_none(), "{document}: {:?}", output.error);
            assert_eq!(output.output, "hello");
        }
    }
}

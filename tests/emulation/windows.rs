//! Windows process setup, export resolution and API boundary checks.

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::Path;
use std::process::{Output, Stdio};
use std::time::{Duration, Instant};

use super::*;

fn fixtures() -> &'static Path {
    static DIRECTORY: OnceLock<PathBuf> = OnceLock::new();
    DIRECTORY.get_or_init(|| {
        let directory =
            common::root().join(format!("target/windows-emulation-{}", std::process::id()));
        let output = Command::new("sh")
            .arg(common::root().join("tools/make_windows_emulation_fixtures.sh"))
            .arg(&directory)
            .output()
            .expect("build Windows fixtures");
        assert!(output.status.success(), "{output:?}");
        directory
    })
}

fn options() -> Value {
    json!({"stepLimit":2000000,"timeLimitMs":10000})
}

fn registry_options() -> Value {
    json!({"windows":{"registry":{"HKEY_CURRENT_USER\\Software\\VelkEmulationTest":{
        "Number":{"type":4,"bytes":[239,205,171,137]},
        "Text":{"type":1,"bytes":[72,0,101,0,108,0,108,0,111,0,0,0]},
        "":{"type":1,"bytes":[229,101,0,0]},
        "Bytes":{"type":3,"bytes":[0,255,7]},
        "Raw":{"type":1,"bytes":[88,0]}
    }}},"stepLimit":2000000,"timeLimitMs":10000})
}

fn serve(path: &Path, start: &str, options: &Value) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start script server");
    let mut input = child.stdin.take().expect("script server input");
    let code = format!(
        "velk.open({}).emulate({}, {})",
        json!(path),
        json!(start),
        options
    );
    writeln!(input, "{}", json!({"id":1,"code":code})).expect("write script request");
    drop(input);
    let mut line = String::new();
    BufReader::new(child.stdout.take().expect("script server output"))
        .read_line(&mut line)
        .expect("read script reply");
    assert!(child.wait().expect("script server exit").success());
    let reply: Value = serde_json::from_str(&line).expect("script reply JSON");
    assert!(reply["error"].is_null(), "{reply}");
    reply["result"].clone()
}

#[test]
fn windows_process_and_imports() {
    let mut interfaces = matrix::Interfaces::new();
    for architecture in ["x86_64", "i386"] {
        for optimization in ["O0", "O2"] {
            let path = fixtures().join(format!("{architecture}.{optimization}.exe"));
            let binary = Binary::open(&path).unwrap();
            for function in [
                "process_state",
                "resolve_exports",
                "process_parameters",
                "thread_storage",
                "process_clocks",
                "callback_state",
            ] {
                let mut settings = options();
                settings["arguments"] = json!(["0x87654321"]);
                let report = interfaces.check(&path, &binary, function, settings.clone());
                assert_eq!(
                    report["reason"], "return",
                    "{architecture} {optimization} {function}: {report}"
                );
                assert_eq!(
                    report["returnValue"], "0x1",
                    "{architecture} {optimization} {function}: {report}"
                );
                if optimization == "O2" && function == "process_state" {
                    assert_eq!(serve(&path, function, &settings), report);
                    for check in [
                        "PEB.BeingDebugged",
                        "PEB.NtGlobalFlag",
                        "IsDebuggerPresent",
                        "CheckRemoteDebuggerPresent",
                    ] {
                        assert!(
                            report["antiAnalysis"]
                                .as_array()
                                .unwrap()
                                .contains(&json!(check)),
                            "{report}"
                        );
                    }
                    let calls = report["apiCalls"].as_array().unwrap();
                    assert!(
                        calls
                            .iter()
                            .any(|call| call["name"] == "kernel32.dll!SetLastError"
                                && call["arguments"] == json!(["0x87654321"])),
                        "{report}"
                    );
                }
            }
            let report = interfaces.check(&path, &binary, "entry", options());
            assert_eq!(report["reason"], "exit", "{report}");
            assert_eq!(report["returnValue"], "0x25", "{report}");
            assert_eq!(report["stdout"], "1 1 1 1 1\n", "{report}");
            let address = execute(&binary, "tls_events_address", options()).return_value;
            let mut settings = options();
            settings["arguments"] = json!([37]);
            settings["reads"] =
                json!([{"address":address,"length":16,"format":"integers","width":4}]);
            let report = interfaces.check(&path, &binary, "finish", settings.clone());
            assert_eq!(report["returnValue"], "0x25", "{report}");
            assert_eq!(report["stdout"], "", "{report}");
            assert!(
                report["apiCalls"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|call| { call["name"] == "kernel32.dll!WriteFile" }),
                "{report}"
            );
            assert_eq!(
                report["reads"][0]["value"],
                json!(["1", "1", "0", "0"]),
                "{report}"
            );
            assert_eq!(serve(&path, "finish", &settings), report);
        }
    }
}

#[test]
fn windows_crt_exit_order() {
    let mut interfaces = matrix::Interfaces::new();
    for architecture in ["x86_64", "i386"] {
        for optimization in ["O0", "O2"] {
            for library in ["exit", "ucrt_exit"] {
                let path = fixtures().join(format!("{architecture}.{library}.{optimization}.exe"));
                let binary = Binary::open(&path).unwrap();
                let address = execute(&binary, "events_address", options()).return_value;
                for mode in [0, 1] {
                    let mut settings = options();
                    settings["arguments"] = json!([mode]);
                    settings["files"] = json!({"exit.bin":[]});
                    settings["reads"] =
                        json!([{"address":address,"length":4,"width":4,"format":"integers"}]);
                    let report = interfaces.check(&path, &binary, "finish", settings.clone());
                    assert_eq!(report["reason"], "exit", "{report}");
                    assert_eq!(report["returnValue"], "0x25", "{report}");
                    let (output, events, direct) = if mode == 0 {
                        ("body\nsecond\nfirst\n", "213", "direct:213\n")
                    } else {
                        ("body\n", "3", "direct:3\n")
                    };
                    assert_eq!(report["stdout"], output, "{report}");
                    assert_eq!(report["files"]["exit.bin"], json!(output.as_bytes()));
                    assert_eq!(report["files"]["detach.bin"], json!(direct.as_bytes()));
                    assert_eq!(report["reads"][0]["value"], json!([events]), "{report}");
                    let calls = report["apiCalls"].as_array().unwrap();
                    let dll = if library == "exit" {
                        "msvcrt.dll!printf"
                    } else {
                        "ucrtbase.dll!__stdio_common_vfprintf"
                    };
                    assert!(calls.iter().any(|call| call["name"] == dll));
                    assert_eq!(
                        calls
                            .iter()
                            .filter(|call| call["name"] == "kernel32.dll!WriteFile")
                            .count(),
                        1
                    );
                    assert_eq!(serve(&path, "finish", &settings), report);
                }
            }
        }
    }
}

#[test]
fn windows_exception_dispatch() {
    let mut interfaces = matrix::Interfaces::new();
    for architecture in ["x86_64", "i386"] {
        for optimization in ["O0", "O2"] {
            let path = fixtures().join(format!("{architecture}.seh.{optimization}.exe"));
            let binary = Binary::open(&path).unwrap();
            let address = execute(&binary, "observed_address", options()).return_value;
            let searched = execute(&binary, "searched_address", options()).return_value;
            for (mode, code, access) in [
                (0, "3221225477", "1"),
                (1, "3221225620", "0"),
                (2, "2147483651", "0"),
                (3, "3221225477", "2"),
            ] {
                let mut settings = options();
                settings["arguments"] = json!([mode]);
                settings["reads"] = json!([{"address":address,"length":16,"width":4,"format":"integers"},{"address":searched,"length":4,"width":4,"format":"integers"}]);
                let report = interfaces.check(&path, &binary, "run_exception", settings.clone());
                assert_eq!(
                    report["reason"], "return",
                    "{architecture} {optimization} {mode}: {report}"
                );
                assert_eq!(report["returnValue"], "0x25", "{report}");
                assert_eq!(
                    report["reads"][0]["value"],
                    json!([code, "1", access, "0"]),
                    "{report}"
                );
                assert_eq!(report["reads"][1]["value"], json!(["1"]), "{report}");
                assert_eq!(serve(&path, "run_exception", &settings), report);
            }
        }
    }
}

#[test]
fn windows_exception_boundaries() {
    let mut interfaces = matrix::Interfaces::new();
    for architecture in ["x86_64", "i386"] {
        let path = fixtures().join(format!("{architecture}.seh.O2.exe"));
        let binary = Binary::open(&path).unwrap();
        let action = execute(&binary, "action_address", options()).return_value;
        for function in ["run_exception", "run_undefined_context"] {
            for base in ["0xffffffffffffffff", "0x10000000"] {
                let mut settings = options();
                settings["registers"] = if architecture == "x86_64" {
                    json!({"gs_base":base})
                } else {
                    json!({"fs_base":if base == "0x10000000" { base } else { "0xffffffff" }})
                };
                let report = interfaces.check(&path, &binary, function, settings.clone());
                assert!(
                    report["error"]
                        .as_str()
                        .unwrap()
                        .contains("invalid Windows TEB"),
                    "{report}"
                );
                assert_eq!(serve(&path, function, &settings), report);
            }
        }
        let saved_pointer = execute(&binary, "context_pointer_address", options()).return_value;
        let mut settings = options();
        let width = if architecture == "x86_64" { 8 } else { 4 };
        settings["reads"] =
            json!([{"address":saved_pointer,"length":width,"width":width,"format":"integers"}]);
        let report = interfaces.check(&path, &binary, "run_exception", settings.clone());
        assert_eq!(report["reason"], "return", "{report}");
        let context: u64 = report["reads"][0]["value"][0]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        settings["reads"] = json!([{"address":format!("0x{:x}", context + if width == 8 { 68 } else { 192 }),"length":4,"width":4,"format":"integers"}]);
        let report = interfaces.check(&path, &binary, "run_exception", settings.clone());
        assert!(
            report["error"]
                .as_str()
                .unwrap()
                .contains("unsupported Windows CONTEXT field"),
            "{report}"
        );
        assert_eq!(serve(&path, "run_exception", &settings), report);
        for (value, error) in [
            (1, "unhandled Windows exception"),
            (2, "unsupported SEH disposition 2"),
            (3, "unsupported Windows CONTEXT field"),
            (4, "write to unsupported Windows CONTEXT field"),
            (5, "nested Windows exception"),
            (6, "is not executable"),
            (
                7,
                if architecture == "i386" {
                    "invalid SEH registration chain"
                } else {
                    "unhandled Windows exception"
                },
            ),
        ] {
            let mut settings = options();
            settings["arguments"] = json!([0]);
            settings["memory"] = json!([{"address":action,"width":4,"value":value}]);
            let report = interfaces.check(&path, &binary, "run_exception", settings.clone());
            assert_eq!(report["reason"], "error", "{report}");
            assert!(
                report["error"].as_str().unwrap().contains(error),
                "{architecture} {value}: {report}"
            );
            assert_eq!(serve(&path, "run_exception", &settings), report);
        }
        for value in [8, 9] {
            let mut settings = options();
            settings["arguments"] = json!([0]);
            settings["memory"] = json!([{"address":action,"width":4,"value":value}]);
            settings["stepLimit"] = json!(10000);
            let report = interfaces.check(&path, &binary, "run_exception", settings);
            assert_eq!(
                report["reason"],
                if value == 8 { "exit" } else { "step limit" },
                "{report}"
            );
        }
        let mut settings = options();
        settings["memory"] = json!([{"address":action,"width":4,"value":10}]);
        let report = interfaces.check(&path, &binary, "run_undefined_context", settings);
        if architecture == "i386" {
            assert_eq!(report["returnValue"], "unknown", "{report}");
        } else {
            assert!(
                report["error"]
                    .as_str()
                    .unwrap()
                    .contains("undefined register"),
                "{report}"
            );
        }
    }
}

#[test]
fn windows_exception_skips_epilogue_handlers() {
    let mut interfaces = matrix::Interfaces::new();
    for optimization in ["O0", "O2"] {
        let path = fixtures().join(format!("x86_64.seh.{optimization}.exe"));
        let binary = Binary::open(&path).unwrap();
        let observed = execute(&binary, "observed_address", options()).return_value;
        for mode in 0..4 {
            let mut settings = options();
            settings["arguments"] = json!([mode]);
            settings["reads"] =
                json!([{"address":observed,"length":16,"width":4,"format":"integers"}]);
            let report = interfaces.check(&path, &binary, "run_epilogue", settings.clone());
            assert_eq!(report["reason"], "error", "{report}");
            assert!(
                report["error"]
                    .as_str()
                    .unwrap()
                    .contains("unhandled Windows exception"),
                "{report}"
            );
            assert_eq!(
                report["reads"][0]["value"],
                json!(["0", "0", "0", "0"]),
                "{report}"
            );
            assert_eq!(serve(&path, "run_epilogue", &settings), report);
            let report = interfaces.check(&path, &binary, "run_prefixed_return", settings.clone());
            assert_eq!(report["reason"], "return", "{report}");
            assert_eq!(report["returnValue"], "0x25", "{report}");
            assert_eq!(serve(&path, "run_prefixed_return", &settings), report);
        }
    }
}

#[test]
fn windows_rejects_invalid_unwind_records() {
    let path = fixtures().join("x86_64.seh.O2.exe");
    let binary = Binary::open(&path).unwrap();
    let image = binary.image();
    let base = image.entry.unwrap() & !0xffff;
    let section = image
        .sections
        .iter()
        .find(|section| section.name == ".pdata")
        .unwrap();
    let entries = image.read_vaddr(section.vaddr, section.file_size).unwrap();
    let row = entries
        .as_chunks::<12>()
        .0
        .iter()
        .find(|row| {
            let unwind = base + u64::from(u32::from_le_bytes(row[8..12].try_into().unwrap()));
            match image.read_vaddr(unwind, 4) {
                Some(header) => header[0] & 8 != 0 && header[2] != 0,
                None => false,
            }
        })
        .unwrap();
    let unwind = base + u64::from(u32::from_le_bytes(row[8..12].try_into().unwrap()));
    let offset = image.virtual_offset(unwind).unwrap() as usize;
    let bytes = fs::read(&path).unwrap();
    for (index, value) in [(0, 0), (0, 0x21), (2, 255)] {
        let mut malformed = bytes.clone();
        malformed[offset + index] = value;
        let path = fixtures().join(format!("x86_64.unwind-{index}-{value}.exe"));
        fs::write(&path, malformed).unwrap();
        let binary = Binary::open(&path).unwrap();
        let report = execute(&binary, "run_exception", options());
        assert_eq!(report.reason, "error", "{report:?}");
        assert!(
            report.error.as_deref().unwrap().contains(if index == 0 {
                "UNWIND_INFO"
            } else {
                "unwind"
            }),
            "{index} {value}: {report:?}"
        );
    }
}

#[test]
fn windows_thread_callbacks() {
    let mut interfaces = matrix::Interfaces::new();
    for architecture in ["x86_64", "i386"] {
        for optimization in ["O0", "O2"] {
            let path = fixtures().join(format!("{architecture}.threads.{optimization}.exe"));
            let binary = Binary::open(&path).unwrap();
            let address = execute(&binary, "events_address", options()).return_value;
            for mode in [0, 1] {
                let mut settings = options();
                settings["arguments"] = json!([mode]);
                settings["reads"] =
                    json!([{"address":address,"length":16,"width":4,"format":"integers"}]);
                let report = interfaces.check(&path, &binary, "thread_storage", settings.clone());
                assert_eq!(
                    report["reason"], "return",
                    "{architecture} {optimization} {mode}: {report}"
                );
                assert_eq!(report["returnValue"], "0x1", "{report}");
                assert_eq!(
                    report["reads"][0]["value"],
                    json!(["0", "1", "1", "1"]),
                    "{report}"
                );
                assert_eq!(serve(&path, "thread_storage", &settings), report);
            }
            let report = interfaces.check(&path, &binary, "entry", options());
            assert_eq!(report["reason"], "exit", "{report}");
            assert_eq!(report["returnValue"], "0x25", "{report}");
            assert_eq!(report["stdout"], "1\n1\n", "{report}");
            for mode in 0..7 {
                let mut settings = options();
                settings["arguments"] = json!([mode]);
                let report = interfaces.check(&path, &binary, "thread_boundary", settings.clone());
                if matches!(mode, 0 | 1 | 3) {
                    assert_eq!(report["returnValue"], "0x1", "{report}");
                } else {
                    assert_eq!(report["reason"], "error", "{report}");
                }
                assert_eq!(serve(&path, "thread_boundary", &settings), report);
            }
        }
    }
}

#[test]
fn windows_heap_and_virtual_memory() {
    let checksum = |length: u32| {
        let mut value = 0u32;
        for index in 0..length {
            value = value
                .wrapping_mul(31)
                .wrapping_add((index * 17 + 3) as u8 as u32);
        }
        value
    };
    let mut expected = String::new();
    let mut size = 0u32;
    while size < 130 {
        expected.push_str(&format!("1 1 {size} {}\n", checksum(size + 1)));
        size += 1 + size / 8;
    }
    expected.push_str("1 1\n");
    let mut interfaces = matrix::Interfaces::new();
    for architecture in ["x86_64", "i386"] {
        for optimization in ["O0", "O2"] {
            let path = fixtures().join(format!("{architecture}.memory.{optimization}.exe"));
            let binary = Binary::open(&path).unwrap();
            let address = execute(&binary, "memory_address", options()).return_value;
            for size in [0, 1, 7, 8, 15, 16, 17, 31, 32, 127, 255, 4095] {
                for function in ["heap_state", "virtual_state"] {
                    let mut settings = options();
                    settings["arguments"] = json!([if function == "virtual_state" {
                        size + 1
                    } else {
                        size
                    }]);
                    settings["reads"] =
                        json!([{"address":address,"length":16,"format":"integers","width":4}]);
                    let report = interfaces.check(&path, &binary, function, settings.clone());
                    assert_eq!(
                        report["reason"], "return",
                        "{architecture} {optimization} {function} {size}: {report}"
                    );
                    assert_eq!(
                        report["returnValue"], "0x1",
                        "{architecture} {optimization} {function} {size}: {report}"
                    );
                    let values = report["reads"][0]["value"].as_array().unwrap();
                    if function == "heap_state" {
                        assert_eq!(values[0], "1");
                        assert_eq!(values[1], size.to_string());
                    } else {
                        assert_eq!(values[2], "1");
                        assert_eq!(values[3], checksum(size + 1).to_string());
                    }
                    if size == 17 {
                        assert_eq!(serve(&path, function, &settings), report);
                    }
                }
            }
            for function in ["virtual_boundaries", "dynamic_heap"] {
                let report = interfaces.check(&path, &binary, function, options());
                assert_eq!(
                    report["returnValue"], "0x1",
                    "{architecture} {optimization} {function}: {report}"
                );
            }
            let report = interfaces.check(&path, &binary, "entry", options());
            assert_eq!(report["reason"], "exit", "{report}");
            assert_eq!(report["returnValue"], "0x25", "{report}");
            assert_eq!(report["stdout"], expected, "{report}");
        }
    }
}

#[test]
fn windows_strings() {
    let mut interfaces = matrix::Interfaces::new();
    for architecture in ["x86_64", "i386"] {
        for optimization in ["O0", "O2"] {
            let path = fixtures().join(format!("{architecture}.strings.{optimization}.exe"));
            let binary = Binary::open(&path).unwrap();
            for function in [
                "string_lengths",
                "conversion_boundaries",
                "documented_parameter_checks",
                "dynamic_conversion",
            ] {
                let report = interfaces.check(&path, &binary, function, options());
                assert_eq!(report["returnValue"], "0x1", "{report}");
                assert_eq!(serve(&path, function, &options()), report);
            }
            for (code_page, length, error) in [
                (932, 1, "code page"),
                (0, 1, "requires ASCII"),
                (65001, i32::MAX, "exceeds 16 MiB"),
            ] {
                let mut settings = options();
                settings["arguments"] =
                    json!([code_page, 0, "0x10000000", length, "0x10000010", 8]);
                settings["memory"] = json!([{"address":"0x10000000","bytes":[255,0]}]);
                let report = interfaces.check(&path, &binary, "convert_buffer", settings.clone());
                assert!(
                    report["error"].as_str().unwrap().contains(error),
                    "{report}"
                );
                assert_eq!(serve(&path, "convert_buffer", &settings), report);
            }
            for (mode, index, length, capacity, flags, count, error) in [
                (0, 0, -1, 8, 0, 1, 73),
                (0, 1, -1, 0, 0, 6, 73),
                (0, 2, 3, 8, 0, 3, 73),
                (0, 3, -1, 8, 8, 2, 73),
                (0, 4, -1, 8, 8, 3, 73),
                (0, 5, -1, 8, 8, 3, 73),
                (0, 5, -1, 1, 8, 0, 122),
                (0, 6, -1, 8, 8, 0, 1113),
                (0, 6, -1, 8, 0, 2, 73),
                (0, 7, -1, 8, 0, 2, 73),
                (0, 8, -1, 8, 0, 3, 73),
                (0, 0, -1, 8, 1, 0, 1004),
                (0, 1, -1, 8, 1, 0, 1004),
                (0, 2, -1, 8, 1, 0, 1004),
                (0, 3, -1, 8, 1, 0, 1004),
                (0, 4, -1, 8, 1, 0, 1004),
                (0, 5, -1, 8, 1, 0, 1004),
                (0, 6, -1, 8, 1, 0, 1004),
                (0, 7, -1, 8, 1, 0, 1004),
                (0, 8, -1, 8, 1, 0, 1004),
                (0, 9, -1, 8, 1, 0, 1004),
                (1, 5, -1, 8, 0x80, 5, 73),
                (1, 5, -1, 4, 0, 0, 122),
                (1, 6, -1, 8, 0x80, 0, 1113),
                (1, 6, -1, 8, 0, 4, 73),
                (1, 2, 3, 8, 0, 3, 73),
            ] {
                let mut settings = options();
                settings["arguments"] = json!([mode, index, length, capacity, flags]);
                // Negative C int arguments are represented by their 32-bit bit patterns.
                settings["arguments"][2] = json!(length as u32);
                let report = interfaces.check(&path, &binary, "conversion", settings.clone());
                assert_eq!(report["reason"], "return", "{report}");
                assert_eq!(report["returnValue"], format!("0x{count:x}"), "{report}");
                let prefix = format!("{mode} {index} {length} {capacity} {flags}: {count} {error}");
                assert!(
                    report["stdout"].as_str().unwrap().starts_with(&prefix),
                    "{report}"
                );
                if mode == 0 && index == 5 && capacity == 8 && flags == 8 {
                    assert!(
                        report["stdout"]
                            .as_str()
                            .unwrap()
                            .contains("5555 d83d de00 0 5555"),
                        "{report}"
                    );
                }
                if mode == 1 && index == 5 && capacity == 8 {
                    assert!(
                        report["stdout"]
                            .as_str()
                            .unwrap()
                            .contains("55 f0 9f 98 80 0 55"),
                        "{report}"
                    );
                }
                if index == 5 {
                    assert_eq!(serve(&path, "conversion", &settings), report);
                }
            }
        }
    }
}

#[test]
fn windows_files_and_console() {
    let mut interfaces = matrix::Interfaces::new();
    for architecture in ["x86_64", "i386"] {
        for optimization in ["O0", "O2"] {
            let path = fixtures().join(format!("{architecture}.files.{optimization}.exe"));
            let binary = Binary::open(&path).unwrap();
            let address = execute(&binary, "file_address", options()).return_value;
            for length in [0, 1, 2, 7, 15, 31, 64, 127, 255, 256] {
                let mut settings = options();
                settings["arguments"] = json!([length]);
                settings["reads"] =
                    json!([{"address":address,"length":12,"format":"integers","width":4}]);
                let report = interfaces.check(&path, &binary, "file_roundtrip", settings.clone());
                assert_eq!(report["reason"], "return", "{report}");
                assert_eq!(report["returnValue"], "0x1", "{report}");
                let expected: Vec<u8> = (0..length).map(|i| (i * 17 + 3) as u8).collect();
                assert_eq!(report["files"]["record.bin"], json!(expected), "{report}");
                assert_eq!(report["reads"][0]["value"][0], "1", "{report}");
                if length == 31 {
                    assert_eq!(serve(&path, "file_roundtrip", &settings), report);
                }
            }
            for function in [
                "file_boundaries",
                "console_output",
                "read_supplied",
                "process_output",
            ] {
                let mut settings = options();
                settings["files"] = json!({"input.bin":[65,0,66]});
                settings["stdin"] = json!({"text":"OK"});
                let report = interfaces.check(&path, &binary, function, settings.clone());
                assert_eq!(report["reason"], "return", "{report}");
                assert_eq!(report["returnValue"], "0x1", "{report}");
                if function == "console_output" {
                    assert_eq!(report["stdout"], "ASCII日😀", "{report}");
                    assert_eq!(report["stderr"], "error\0\n", "{report}");
                }
                if function == "process_output" {
                    assert_eq!(report["stdout"], "peb\n", "{report}");
                }
                assert_eq!(serve(&path, function, &settings), report);
            }
            let report = interfaces.check(&path, &binary, "entry", options());
            assert_eq!(report["reason"], "exit", "{report}");
            assert_eq!(report["returnValue"], "0x25", "{report}");
            assert!(
                report["stdout"]
                    .as_str()
                    .is_some_and(|output| { output.starts_with("peb\noutput\n0 1 0\n") }),
                "{report}"
            );
            for mode in 0..5 {
                let mut settings = options();
                settings["arguments"] = json!([mode]);
                let report = interfaces.check(&path, &binary, "unsupported_file", settings.clone());
                assert_eq!(report["reason"], "error", "{report}");
                assert_eq!(serve(&path, "unsupported_file", &settings), report);
            }
            let report = interfaces.check(&path, &binary, "process_files", options());
            assert_eq!(report["returnValue"], "0x1", "{report}");
            assert_eq!(report["files"]["/proc/self/maps"], json!([88]), "{report}");
            for mode in 0..3 {
                let mut settings = options();
                settings["arguments"] = json!([mode]);
                let report = interfaces.check(&path, &binary, "mixed_files", settings.clone());
                if mode == 0 {
                    assert_eq!(report["returnValue"], "0x1", "{report}");
                    assert_eq!(report["files"]["shared.bin"], json!([88]), "{report}");
                } else {
                    assert!(
                        report["error"]
                            .as_str()
                            .unwrap()
                            .contains("simultaneous CRT"),
                        "{report}"
                    );
                }
                assert_eq!(serve(&path, "mixed_files", &settings), report);
            }
        }
    }
}

#[test]
fn windows_registry() {
    let mut interfaces = matrix::Interfaces::new();
    for architecture in ["x86_64", "i386"] {
        for optimization in ["O0", "O2"] {
            let path = fixtures().join(format!("{architecture}.registry.{optimization}.exe"));
            let binary = Binary::open(&path).unwrap();
            for function in ["registry_values", "entry"] {
                let settings = registry_options();
                let report = interfaces.check(&path, &binary, function, settings.clone());
                if function == "entry" {
                    assert_eq!(report["reason"], "exit", "{report}");
                    assert_eq!(report["returnValue"], "0x25", "{report}");
                    assert_eq!(report["stdout"], "1\n1 2\n4 5\n5 87\n6 87\n", "{report}");
                } else {
                    assert_eq!(report["reason"], "return", "{report}");
                    assert_eq!(report["returnValue"], "0x1", "{report}");
                }
                assert_eq!(serve(&path, function, &settings), report);
            }
            let report = interfaces.check(&path, &binary, "registry_values", options());
            assert_eq!(report["returnValue"], "0x0", "{report}");
            for (mode, value) in [(1, 2), (4, 5), (5, 87), (6, 87)] {
                let mut settings = registry_options();
                settings["arguments"] = json!([mode]);
                let report = interfaces.check(&path, &binary, "registry_boundaries", settings);
                assert_eq!(report["returnValue"], format!("0x{value:x}"), "{report}");
            }
            let mut settings = registry_options();
            settings["arguments"] = json!([3]);
            let report = interfaces.check(&path, &binary, "registry_boundaries", settings);
            assert!(
                report["error"]
                    .as_str()
                    .unwrap()
                    .contains("default registry view"),
                "{report}"
            );
        }
    }
}

#[test]
fn windows_registry_parameter_checks() {
    let mut interfaces = matrix::Interfaces::new();
    for architecture in ["x86_64", "i386"] {
        for optimization in ["O0", "O2"] {
            let path = fixtures().join(format!("{architecture}.registry.{optimization}.exe"));
            let binary = Binary::open(&path).unwrap();
            // Wine accepts unsupported open flags and handles not opened as registry keys.
            for (mode, value) in [(0, 87), (2, 6)] {
                let mut settings = registry_options();
                settings["arguments"] = json!([mode]);
                let report =
                    interfaces.check(&path, &binary, "registry_boundaries", settings.clone());
                assert_eq!(report["reason"], "return", "{report}");
                assert_eq!(report["returnValue"], format!("0x{value:x}"), "{report}");
                assert_eq!(serve(&path, "registry_boundaries", &settings), report);
            }
            // Supply unterminated data directly instead of passing it to RegSetValueExW.
            let settings = registry_options();
            let report =
                interfaces.check(&path, &binary, "registry_unterminated", settings.clone());
            assert_eq!(report["reason"], "return", "{report}");
            assert_eq!(report["returnValue"], "0x1", "{report}");
            assert_eq!(serve(&path, "registry_unterminated", &settings), report);
        }
    }
}

#[test]
fn windows_ucrt_rejects_missing_exports() {
    let engine = velk::script::Engine::new().unwrap();
    let mut server = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = server.stdin.take().unwrap();
    let mut responses = BufReader::new(server.stdout.take().unwrap());
    for architecture in ["x86_64", "i386"] {
        for optimization in ["O0", "O2"] {
            let path = fixtures().join(format!("{architecture}.ucrt.{optimization}.exe"));
            let bytes = fs::read(&path).unwrap();
            let import = b"__stdio_common_vfprintf\0";
            let offset = bytes
                .windows(import.len())
                .rposition(|bytes| bytes == import)
                .unwrap();
            for name in [
                "printf", "fprintf", "sprintf", "snprintf", "sscanf", "atexit", "_onexit",
            ] {
                let mut invalid = bytes.clone();
                invalid[offset..offset + import.len()].fill(0);
                invalid[offset..offset + name.len()].copy_from_slice(name.as_bytes());
                let path =
                    fixtures().join(format!("{architecture}.{optimization}.missing-{name}.exe"));
                fs::write(&path, invalid).unwrap();
                let binary = Binary::open(&path).unwrap();
                assert!(binary.image().imports.values().any(|import| import == name));
                for skip_calls in [false, true] {
                    let settings = Options {
                        skip_calls,
                        ..Default::default()
                    };
                    let error = emulation::run(&binary, "crt_memory", &settings, None).unwrap_err();
                    assert!(
                        error
                            .to_string()
                            .contains(&format!("unavailable Windows export ucrtbase.dll!{name}")),
                        "{error}"
                    );
                }
                let output = Command::new(env!("CARGO_BIN_EXE_velk"))
                    .args(["--emulate", "--json"])
                    .arg(&path)
                    .arg("crt_memory")
                    .output()
                    .unwrap();
                assert!(!output.status.success(), "{output:?}");
                assert!(
                    String::from_utf8_lossy(&output.stderr)
                        .contains(&format!("ucrtbase.dll!{name}")),
                    "{output:?}"
                );
                let script = format!("velk.open({}).emulate('crt_memory')", json!(path));
                let result = engine.run(&script, None);
                assert!(
                    result
                        .error
                        .unwrap()
                        .contains(&format!("ucrtbase.dll!{name}"))
                );
                let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"velk_emulate","arguments":{"path":path,"start":"crt_memory"}}});
                writeln!(input, "{request}").unwrap();
                let mut line = String::new();
                responses.read_line(&mut line).unwrap();
                let response: Value = serde_json::from_str(&line).unwrap();
                assert_eq!(response["result"]["isError"], true, "{response}");
                assert!(
                    response
                        .to_string()
                        .contains(&format!("ucrtbase.dll!{name}")),
                    "{response}"
                );
            }
        }
    }
    drop(input);
    assert!(server.wait().unwrap().success());
}

#[test]
fn windows_crt() {
    let mut interfaces = matrix::Interfaces::new();
    for architecture in ["x86_64", "i386"] {
        for optimization in ["O0", "O2"] {
            for library in ["crt", "ucrt"] {
                let path = fixtures().join(format!("{architecture}.{library}.{optimization}.exe"));
                let binary = Binary::open(&path).unwrap();
                if library == "ucrt" {
                    let report = interfaces.check(&path, &binary, "crt_exports", options());
                    assert_eq!(report["returnValue"], "0x1", "{report}");
                    for capacity in 0..=8 {
                        let mut settings = options();
                        settings["arguments"] = json!([capacity]);
                        let report =
                            interfaces.check(&path, &binary, "crt_truncation", settings.clone());
                        assert_eq!(report["returnValue"], "0x1", "{report}");
                        assert_eq!(serve(&path, "crt_truncation", &settings), report);
                    }
                    for (mode, error) in [
                        (0, "unsupported options 0x100000000"),
                        (1, "explicit locales"),
                    ] {
                        let mut settings = options();
                        settings["arguments"] = json!([mode]);
                        let report =
                            interfaces.check(&path, &binary, "crt_options", settings.clone());
                        assert!(
                            report["error"].as_str().unwrap().contains(error),
                            "{report}"
                        );
                        assert_eq!(serve(&path, "crt_options", &settings), report);
                    }
                }
                for size in [0, 1, 7, 15, 16, 31, 127, 255, 257] {
                    let mut settings = options();
                    settings["arguments"] = json!([size]);
                    let report = interfaces.check(&path, &binary, "crt_memory", settings);
                    assert_eq!(report["returnValue"], "0x1", "{report}");
                }
                for function in ["crt_strings", "crt_format", "crt_file"] {
                    let mut settings = options();
                    settings["files"] = json!({"crt.bin":[]});
                    let report = interfaces.check(&path, &binary, function, settings.clone());
                    assert_eq!(report["reason"], "return", "{report}");
                    assert_eq!(report["returnValue"], "0x1", "{report}");
                    if function == "crt_file" {
                        assert_eq!(
                            report["files"]["crt.bin"],
                            json!([65, 10, 66, 0, 67]),
                            "{report}"
                        );
                    }
                    if library == "ucrt" && function == "crt_format" {
                        assert_eq!(report["stdout"], "stdout:37\n", "{report}");
                        assert_eq!(report["stderr"], "stderr:OK\n", "{report}");
                    }
                    assert_eq!(serve(&path, function, &settings), report);
                }
                let report = interfaces.check(&path, &binary, "crt_buffer_full", options());
                assert_eq!(report["reason"], "return", "{report}");
                assert_eq!(report["returnValue"], "0x1", "{report}");
                assert_eq!(report["stdout"], "X".repeat(512), "{report}");
                assert_eq!(serve(&path, "crt_buffer_full", &options()), report);
                if library == "ucrt" {
                    let report = interfaces.check(&path, &binary, "crt_buffering", options());
                    assert_eq!(report["reason"], "return", "{report}");
                    assert_eq!(report["returnValue"], "0x1", "{report}");
                    assert_eq!(report["stdout"], "unbuffered\n", "{report}");
                    assert_eq!(serve(&path, "crt_buffering", &options()), report);
                }
                for mode in [0, 1] {
                    let mut settings = options();
                    settings["arguments"] = json!([mode]);
                    let report =
                        interfaces.check(&path, &binary, "unsupported_crt", settings.clone());
                    assert!(
                        report["error"].as_str().unwrap().contains(if mode == 0 {
                            "binary mode"
                        } else {
                            "!rand"
                        }),
                        "{report}"
                    );
                    assert_eq!(serve(&path, "unsupported_crt", &settings), report);
                }
            }
        }
    }
}

#[test]
fn windows_programs() {
    for architecture in ["x86_64", "i386"] {
        let binary = Binary::open(&fixtures().join(format!("{architecture}.probe.exe"))).unwrap();
        let report = execute(&binary, "entry", options());
        assert_eq!(report.reason, "exit", "{report:?}");
        assert_eq!(report.return_value, "0x25", "{report:?}");
        for optimization in ["O0", "O2"] {
            for group in ["strings", "files", "registry", "crt", "ucrt"] {
                let path = fixtures().join(format!("{architecture}.{group}.{optimization}.exe"));
                let binary = Binary::open(&path).unwrap();
                let mut settings = registry_options();
                settings["stepLimit"] = json!(50000000);
                settings["timeLimitMs"] = json!(60000);
                settings["files"] = json!({"crt.bin":[]});
                let report = execute(&binary, "entry", settings);
                assert_eq!(
                    report.reason, "exit",
                    "{architecture} {group} {optimization}: {report:?}"
                );
                assert_eq!(report.return_value, "0x25", "{report:?}");
                if group == "strings" {
                    assert!(report.stdout.starts_with("1 1 1\n"), "{report:?}");
                }
                if matches!(group, "crt" | "ucrt") {
                    assert!(report.stdout.contains("1 1 1\nputs\n!\n"), "{report:?}");
                }
            }
        }
    }
}

#[test]
fn windows_memory_failures() {
    let mut interfaces = matrix::Interfaces::new();
    for architecture in ["x86_64", "i386"] {
        for optimization in ["O0", "O2"] {
            let path = fixtures().join(format!("{architecture}.memory.{optimization}.exe"));
            let binary = Binary::open(&path).unwrap();
            for pointer in ["0x1", "0xffffffff", "0xffffffffffffffff"] {
                let mut settings = options();
                settings["arguments"] = json!([pointer]);
                let report =
                    interfaces.check(&path, &binary, "virtual_invalid_output", settings.clone());
                assert_eq!(report["reason"], "error", "{report}");
                assert!(
                    report["error"]
                        .as_str()
                        .unwrap()
                        .contains("VirtualProtect: invalid output pointer"),
                    "{report}"
                );
                assert_eq!(serve(&path, "virtual_invalid_output", &settings), report);
            }
            for function in [
                "heap_oversize",
                "heap_reallocation_failure",
                "virtual_oversize",
                "virtual_overflow",
            ] {
                for size in ["0x10000000", "0xffffffff", "0xffffffffffffffff"] {
                    if function == "virtual_overflow"
                        && (size == "0x10000000"
                            || (architecture == "x86_64" && size == "0xffffffff"))
                    {
                        continue;
                    }
                    let mut settings = options();
                    settings["arguments"] = json!([size]);
                    let report = interfaces.check(&path, &binary, function, settings);
                    assert_eq!(
                        report["reason"], "return",
                        "{architecture} {function} {size}: {report}"
                    );
                    assert_eq!(
                        report["returnValue"],
                        if function.starts_with("heap_") {
                            "0x1"
                        } else {
                            "0x0"
                        },
                        "{architecture} {function} {size}: {report}"
                    );
                }
            }
            for mode in 0..10 {
                let mut settings = options();
                settings["arguments"] = json!([mode]);
                let report = interfaces.check(&path, &binary, "virtual_fault", settings.clone());
                if mode == 8 {
                    assert_eq!(report["reason"], "return", "{report}");
                    assert_eq!(report["returnValue"], "0x7", "{report}");
                    assert_eq!(serve(&path, "virtual_fault", &settings), report);
                    continue;
                }
                assert_eq!(
                    report["reason"], "error",
                    "{architecture} {optimization} {mode}: {report}"
                );
                let error = report["error"].as_str().unwrap();
                assert!(
                    error.contains(if mode == 9 {
                        "non-base release address is unsupported"
                    } else if mode == 4 {
                        "unmapped memory"
                    } else {
                        "protected mapping"
                    }),
                    "{report}"
                );
                assert_eq!(serve(&path, "virtual_fault", &settings), report);
            }
        }
    }
}

#[test]
fn windows_options_and_boundaries() {
    let mut interfaces = matrix::Interfaces::new();
    for architecture in ["x86_64", "i386"] {
        let path = fixtures().join(format!("{architecture}.O0.exe"));
        let binary = Binary::open(&path).unwrap();
        for code in [0, 1, 37, 255, u32::MAX] {
            let mut settings = options();
            settings["arguments"] = json!([code]);
            let report = interfaces.check(&path, &binary, "finish", settings);
            assert_eq!(report["reason"], "exit", "{report}");
            assert_eq!(report["returnValue"], format!("0x{code:x}"));
        }
        for error in [0, 1, 0x7fff_ffff, u32::MAX] {
            let mut settings = options();
            settings["arguments"] = json!([error]);
            let report = interfaces.check(&path, &binary, "process_state", settings);
            assert_eq!(report["returnValue"], "0x1", "{report}");
        }
        let mut settings = options();
        settings["windows"] = json!({"commandLine":"program.exe 日本語", "imagePath":"C:\\tests\\app.exe", "environment":{"EMPTY":"", "NAME":"value"}});
        settings["arguments"] = json!(["0x10000000"]);
        settings["memory"] = json!([{"address":"0x10000000","bytes":vec![0;128]}]);
        settings["reads"] = json!([{"address":"0x10000000", "length":32,"format":"bytes"}]);
        let report = interfaces.check(&path, &binary, "copy_parameters", settings.clone());
        let expected: Vec<u8> = "program.exe 日本語\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(report["reads"][0]["bytes"], json!(expected));
        assert_eq!(serve(&path, "copy_parameters", &settings), report);
        for (function, text) in [
            ("copy_image_path", "C:\\tests\\App.exe"),
            ("copy_module_name", "App.exe"),
        ] {
            settings["windows"]["imagePath"] = json!("C:\\tests\\App.exe");
            let expected: Vec<u8> = text
                .encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes)
                .collect();
            settings["reads"][0]["length"] = json!(expected.len());
            let report = interfaces.check(&path, &binary, function, settings.clone());
            assert_eq!(report["reads"][0]["bytes"], json!(expected));
        }
        let report = interfaces.check(&path, &binary, "sleep_forever", options());
        assert!(
            report["error"]
                .as_str()
                .unwrap()
                .contains("Sleep(INFINITE)"),
            "{report}"
        );
        let mut settings = options();
        settings["arguments"] = json!([0]);
        let report = interfaces.check(&path, &binary, "counter_to", settings);
        assert!(
            report["error"].as_str().unwrap().contains("unmapped"),
            "{report}"
        );
        let mut settings = options();
        settings["arguments"] = json!([2]);
        settings["antiAnalysis"] = json!({"clockTicksPerInstruction":0});
        let report = interfaces.check(&path, &binary, "tick_after_sleep", settings);
        assert_eq!(report["returnValue"], "0x2", "{report}");
        for (function, expected) in [("tick_high", "0x1"), ("tick_low", "0xfffffffc")] {
            let mut settings = options();
            settings["antiAnalysis"] = json!({"clockTicksPerInstruction":0});
            let report = interfaces.check(&path, &binary, function, settings);
            assert_eq!(report["returnValue"], expected, "{report}");
        }
        let report = interfaces.check(&path, &binary, "write_export", options());
        assert!(
            report["error"]
                .as_str()
                .unwrap()
                .contains("protected mapping"),
            "{report}"
        );
        let mut settings = options();
        settings["windows"] = json!({"environment":{"EMPTY":"", "NAME":"value"}});
        settings["arguments"] = json!(["0x10000000"]);
        settings["memory"] = json!([{"address":"0x10000000","bytes":vec![0;128]}]);
        let environment: Vec<u8> = "EMPTY=\0NAME=value\0\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        settings["reads"] =
            json!([{"address":"0x10000000","length":environment.len(),"format":"bytes"}]);
        let report = interfaces.check(&path, &binary, "copy_environment", settings);
        assert_eq!(report["reads"][0]["bytes"], json!(environment));
        let slot = binary
            .image()
            .imports
            .iter()
            .find(|(_, name)| name.as_str() == "GetCurrentProcessId")
            .unwrap()
            .0;
        let replacement = binary.find("replacement_process_id").unwrap().addr;
        let mut settings = options();
        settings["memory"] = json!([{"address":format!("0x{slot:x}"),"value":format!("0x{replacement:x}"),"width":if architecture == "x86_64" {8} else {4}}]);
        // PE IAT sections are read-only in the input; redirects can also be made by the code itself.
        // Explicit memory initialization follows the input's section permissions.
        let parsed: Options = serde_json::from_value(settings).unwrap();
        assert!(emulation::run(&binary, "current_process_id", &parsed, None).is_err());
        let mut settings = options();
        settings["callReturns"] = json!({"GetCurrentProcessId":42});
        let report = interfaces.check(&path, &binary, "current_process_id", settings);
        assert_eq!(report["returnValue"], "0x2a", "{report}");
        let mut settings = options();
        settings["callReturns"] = json!({format!("0x{slot:x}"):43});
        let report = interfaces.check(&path, &binary, "current_process_id", settings);
        assert_eq!(report["returnValue"], "0x2b", "{report}");
        let report = interfaces.check(&path, &binary, "tail_process_id", options());
        assert_eq!(report["reason"], "return", "{report}");
        assert_eq!(report["returnValue"], "0x3e8", "{report}");
        let mut settings = options();
        settings["arguments"] = json!([0]);
        settings["antiAnalysis"] = json!({"debuggerPresent":true});
        let report = interfaces.check(&path, &binary, "process_state", settings);
        assert_eq!(report["returnValue"], "0x0", "{report}");
        for value in [0, 1] {
            let mut settings = options();
            settings["arguments"] = json!([value]);
            settings["antiAnalysis"] = json!({"debuggerPresent":value == 0});
            let report = interfaces.check(&path, &binary, "patch_debugger_flag", settings);
            assert_eq!(report["returnValue"], format!("0x{value:x}"), "{report}");
        }
    }
}

#[test]
fn windows_unknown_apis_stop_by_name() {
    let mut interfaces = matrix::Interfaces::new();
    for architecture in ["x86_64", "i386"] {
        let path = fixtures().join(format!("{architecture}.unknown.dll"));
        let binary = Binary::open(&path).unwrap();
        for function in ["unknown_import", "unknown_export"] {
            let report = interfaces.check(&path, &binary, function, options());
            assert!(
                report["error"]
                    .as_str()
                    .unwrap()
                    .contains("kernel32.dll!UnknownWindowsApi"),
                "{report}"
            );
            assert_eq!(serve(&path, function, &options()), report);
            let mut settings = options();
            settings["callReturns"] = json!({"UnknownWindowsApi":7});
            let report = interfaces.check(&path, &binary, function, settings);
            assert_eq!(report["returnValue"], "0x7", "{report}");
            let mut settings = options();
            settings["skipCalls"] = json!(true);
            let report = interfaces.check(&path, &binary, function, settings);
            assert_eq!(report["returnValue"], "0x0", "{report}");
        }
    }
}

#[test]
fn windows_documented_command() {
    let output = Command::new("sh")
        .arg("tools/make_windows_emulation_fixtures.sh")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    for path in ["docs/EMULATION.md", "docs/EMULATION.ja.md"] {
        let text = fs::read_to_string(common::root().join(path)).unwrap();
        let lines = text
            .lines()
            .filter(|line| line.starts_with("velk --emulate target/windows-emulation-fixtures/"));
        for line in lines {
            let command = format!("exec \"$1\" {}", line.strip_prefix("velk ").unwrap());
            let output = Command::new("sh")
                .args(["-c", &command, "documentation"])
                .arg(env!("CARGO_BIN_EXE_velk"))
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            let report: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(
                report["returnValue"],
                if line.contains("documented_registry") {
                    "0x25"
                } else {
                    "0x1"
                },
                "{report}"
            );
        }
    }
}

#[test]
fn windows_rejects_invalid_process_options_and_pe_tables() {
    for architecture in ["x86_64", "i386"] {
        let path = fixtures().join(format!("{architecture}.O0.exe"));
        let binary = Binary::open(&path).unwrap();
        for windows in [
            json!({"commandLine":"a\u{0000}b"}),
            json!({"environment":{"A":"1","a":"2"}}),
            json!({"environment":{"A=B":"1"}}),
            json!({"registry":{"unknown\\path":{}}}),
            json!({"registry":{"HKEY_CURRENT_USER":{"A":{"type":3,"bytes":[]},"a":{"type":3,"bytes":[]}}}}),
            json!({"registry":{"HKEY_CURRENT_USER":{},"hkey_current_user":{}}}),
        ] {
            let parsed: Options = serde_json::from_value(json!({"windows":windows})).unwrap();
            assert!(emulation::run(&binary, "process_state", &parsed, None).is_err());
        }
        let bytes = fs::read(&path).unwrap();
        let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
        let optional = pe + 24;
        let directories = optional + if architecture == "x86_64" { 112 } else { 96 };
        let base = binary.image().entry.unwrap() & !0xffff;
        let tls = u32::from_le_bytes(
            bytes[directories + 72..directories + 76]
                .try_into()
                .unwrap(),
        );
        let tls = binary
            .image()
            .virtual_offset(base + u64::from(tls))
            .unwrap() as usize;
        let width = if architecture == "x86_64" { 8 } else { 4 };
        let edits = [
            (optional + 60, 4, u64::from(u32::MAX)),
            (tls + width, width, 1),
            (tls + width * 3, width, u64::MAX),
            (tls + width * 4, 4, u64::from(u32::MAX)),
        ];
        for (index, (offset, width, value)) in edits.into_iter().enumerate() {
            let mut malformed = bytes.clone();
            malformed[offset..offset + width].copy_from_slice(&value.to_le_bytes()[..width]);
            let path = fixtures().join(format!("{architecture}.malformed-{index}.exe"));
            fs::write(&path, malformed).unwrap();
            if let Ok(binary) = Binary::open(&path) {
                let start = format!("0x{:x}", base + 0x1000);
                let result = emulation::run(&binary, &start, &Options::default(), None);
                assert!(
                    result.is_err(),
                    "accepted malformed PE case {index}: {result:?}"
                );
            }
        }
    }
}

// File-backed output avoids waiting for pipes inherited by Wine's child processes.
fn wine_output(command: &mut Command, phase: &str, timeout: Duration) -> std::io::Result<Output> {
    let stdout = fixtures().join(format!("wine-{phase}.stdout"));
    let stderr = fixtures().join(format!("wine-{phase}.stderr"));
    // Each I/O failure prevents this command's output from being compared.
    let mut child = command
        .env("WINEDLLOVERRIDES", "winedbg.exe=d")
        .stdout(fs::File::create(&stdout)?)
        .stderr(fs::File::create(&stderr)?)
        .spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return Ok(Output {
                    status,
                    stdout: fs::read(&stdout)?,
                    stderr: fs::read(&stderr)?,
                });
            }
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            result => {
                if child.kill().is_ok() {
                    let _ = child.wait();
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "Wine {phase} timed out or could not be checked: {result:?}; stdout: {}; stderr: {}",
                        String::from_utf8_lossy(&fs::read(&stdout)?),
                        String::from_utf8_lossy(&fs::read(&stderr)?),
                    ),
                ));
            }
        }
    }
}

fn wine_starts(command: &mut Command, expected: i32, phase: &str) -> bool {
    match wine_output(command, phase, Duration::from_secs(45)) {
        Ok(output) if output.status.code() == Some(expected) => true,
        result => {
            eprintln!("skipping native Windows comparisons: Wine {phase}: {result:?}");
            false
        }
    }
}

#[test]
fn windows_reference_timeout() {
    fixtures();
    let start = Instant::now();
    let error = wine_output(
        Command::new("sh").args(["-c", "printf output; printf error >&2; exec sleep 5"]),
        "timeout",
        Duration::from_millis(100),
    )
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(
        error.to_string().contains("stdout: output; stderr: error"),
        "{error}"
    );
    assert!(start.elapsed() < Duration::from_secs(3));
}

#[test]
fn windows_matches_wine() {
    let mut differences = Vec::new();
    let prefix = fixtures().join("wine");
    let runtime = fixtures().join("wine-runtime");
    fs::create_dir_all(&runtime).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let initialized = wine_starts(
        Command::new("wineboot")
            .arg("-i")
            .env("WINEPREFIX", &prefix)
            .env("XDG_RUNTIME_DIR", &runtime)
            .env("TMPDIR", &runtime)
            .env("WINEDEBUG", "-all"),
        0,
        "initialization",
    );
    if !initialized {
        return;
    }
    for (name, value) in [("Auto", "0"), ("Debugger", "")] {
        for view in ["/reg:64", "/reg:32"] {
            let phase = format!("debugger-{name}-{}", &view[5..]);
            let output = wine_output(
                Command::new("wine")
                    .env("WINEPREFIX", &prefix)
                    .env("WINEDEBUG", "-all")
                    .env("XDG_RUNTIME_DIR", &runtime)
                    .env("TMPDIR", &runtime)
                    .args([
                        "reg",
                        "add",
                        r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\AeDebug",
                        "/v",
                        name,
                        "/t",
                        "REG_SZ",
                        "/d",
                        value,
                        "/f",
                        view,
                    ]),
                &phase,
                Duration::from_secs(45),
            )
            .expect("disable Wine crash debugger");
            assert!(output.status.success(), "{output:?}");
        }
    }
    for architecture in ["x86_64", "i386"] {
        if !wine_starts(
            Command::new("wine")
                .env("WINEPREFIX", &prefix)
                .env("WINEDEBUG", "-all")
                .env("XDG_RUNTIME_DIR", &runtime)
                .env("TMPDIR", &runtime)
                .arg(fixtures().join(format!("{architecture}.probe.exe"))),
            37,
            &format!("{architecture}-probe"),
        ) {
            continue;
        }
        for optimization in ["O0", "O2"] {
            for group in [
                "",
                "memory.",
                "strings.",
                "files.",
                "registry.",
                "crt.",
                "ucrt.",
                "exit.",
                "ucrt_exit.",
                "seh.",
                "threads.",
            ] {
                let path = fixtures().join(format!("{architecture}.{group}{optimization}.exe"));
                let phase = format!("{architecture}.{group}{optimization}");
                let native = match wine_output(
                    Command::new("wine")
                        .env("WINEPREFIX", &prefix)
                        .env("WINEDEBUG", "-all")
                        .env("XDG_RUNTIME_DIR", &runtime)
                        .env("TMPDIR", &runtime)
                        .current_dir(fixtures())
                        .arg(&path),
                    &phase,
                    Duration::from_secs(45),
                ) {
                    Ok(native) => native,
                    Err(error) => {
                        differences.push(format!("{phase}: {error}"));
                        continue;
                    }
                };
                if native.status.code() != Some(37) {
                    differences.push(format!("{phase}: Wine exit status {:?}", native.status));
                }
                let binary = Binary::open(&path).unwrap();
                let mut settings = if group == "registry." {
                    registry_options()
                } else {
                    options()
                };
                settings["stepLimit"] = json!(50000000);
                settings["timeLimitMs"] = json!(60000);
                if matches!(group, "crt." | "ucrt.") {
                    settings["files"] = json!({"crt.bin":[]});
                }
                if matches!(group, "exit." | "ucrt_exit.") {
                    settings["files"] = json!({"exit.bin":[]});
                }
                let report = execute(&binary, "entry", settings);
                if report.reason != "exit" || report.return_value != "0x25" {
                    differences.push(format!("{phase}: {report:?}"));
                }
                for (stream, actual, expected) in [
                    ("stdout", report.stdout, native.stdout),
                    ("stderr", report.stderr, native.stderr),
                ] {
                    let expected = match String::from_utf8(expected) {
                        Ok(expected) => expected.replace("\r\n", "\n"),
                        Err(error) => {
                            differences.push(format!("{phase} {stream}: {error}"));
                            continue;
                        }
                    };
                    if actual != expected {
                        differences.push(format!(
                            "{phase} {stream}: emulation {actual:?}, Wine {expected:?}"
                        ));
                    }
                }
                let file = match group {
                    "files." => Some("record.bin"),
                    "crt." | "ucrt." => Some("crt.bin"),
                    // Callback side effects are checked by the interfaces.
                    "exit." | "ucrt_exit." => Some("exit.bin"),
                    _ => None,
                };
                if let Some(file) = file {
                    match fs::read(fixtures().join(file)) {
                        Ok(expected) => {
                            if report.files.get(file) != Some(&expected) {
                                differences.push(format!("{phase}: {file} bytes differ"));
                            }
                        }
                        Err(error) => differences.push(format!("{phase}: {file}: {error}")),
                    }
                }
            }
        }
    }
    assert!(differences.is_empty(), "{}", differences.join("\n"));
}

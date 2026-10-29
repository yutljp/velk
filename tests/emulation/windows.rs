//! Windows process setup, export resolution and API boundary checks.

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::Path;
use std::process::Stdio;

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
fn windows_memory_failures() {
    let mut interfaces = matrix::Interfaces::new();
    for architecture in ["x86_64", "i386"] {
        for optimization in ["O0", "O2"] {
            let path = fixtures().join(format!("{architecture}.memory.{optimization}.exe"));
            let binary = Binary::open(&path).unwrap();
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
        let line = text
            .lines()
            .find(|line| line.starts_with("velk --emulate target/windows-emulation-fixtures/"))
            .unwrap();
        let command = format!("exec \"$1\" {}", line.strip_prefix("velk ").unwrap());
        let output = Command::new("sh")
            .args(["-c", &command, "documentation"])
            .arg(env!("CARGO_BIN_EXE_velk"))
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["returnValue"], "0x1", "{report}");
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

#[test]
#[ignore = "requires Wine with permission to create its runtime sockets"]
fn windows_matches_wine() {
    let prefix = fixtures().join("wine");
    let runtime = fixtures().join("wine-runtime");
    fs::create_dir_all(&runtime).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let initialized = Command::new("wineboot")
        .arg("-i")
        .env("WINEPREFIX", &prefix)
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("TMPDIR", &runtime)
        .env("WINEDEBUG", "-all")
        .output()
        .expect("initialize Wine reference");
    assert!(initialized.status.success(), "{initialized:?}");
    for architecture in ["x86_64", "i386"] {
        for optimization in ["O0", "O2"] {
            for group in ["", "memory."] {
                let path = fixtures().join(format!("{architecture}.{group}{optimization}.exe"));
                let native = Command::new("wine")
                    .env("WINEPREFIX", &prefix)
                    .env("WINEDEBUG", "-all")
                    .env("XDG_RUNTIME_DIR", &runtime)
                    .env("TMPDIR", &runtime)
                    .arg(&path)
                    .output()
                    .expect("Wine reference");
                assert_eq!(native.status.code(), Some(37), "{native:?}");
                let binary = Binary::open(&path).unwrap();
                let report = execute(&binary, "entry", options());
                assert_eq!(report.reason, "exit", "{report:?}");
                assert_eq!(report.return_value, "0x25");
                assert_eq!(
                    report.stdout,
                    String::from_utf8(native.stdout)
                        .unwrap()
                        .replace("\r\n", "\n")
                );
            }
        }
    }
}

//! Standard input/output and memory reads across the execution interfaces.

use std::process::Command;

use serde_json::{Value, json};
use velk::service::Binary;

use super::matrix::{self, Interfaces};

fn read(symbol: &str) -> Value {
    json!({"symbol":symbol})
}

#[test]
fn program_io_interfaces() {
    let mut interfaces = Interfaces::new();
    for architecture in matrix::ARCHITECTURES {
        for optimization in ["O0", "O2"] {
            let path = matrix::fixtures().join(format!("{architecture}.{optimization}.io.elf"));
            let binary = Binary::open(&path).expect("I/O fixture");
            for input in ["flag{input}\n", "wrong\n", ""] {
                let report = interfaces.check(
                    &path,
                    &binary,
                    "check_flag",
                    json!({"stdin":{"text":input}}),
                );
                assert_eq!(report["reason"], "return", "{architecture} {report}");
                assert_eq!(
                    report["stdout"],
                    if input.is_empty() {
                        ""
                    } else if input.starts_with("flag") {
                        "Correct\n"
                    } else {
                        "Wrong\n"
                    }
                );
            }
            let report =
                interfaces.check(&path, &binary, "main", json!({"argv":["app", "candidate"]}));
            assert_eq!(report["reason"], "return", "{architecture} {report}");
            assert_eq!(report["stdout"], "argc=2 argv0=app argv1=candidate\n");
            let report = interfaces.check(&path, &binary, "decode_buffer", json!({"reads":[read("decoded"), {"register":if architecture == "x86_64" {"rax"} else if architecture == "i386" {"eax"} else if architecture == "aarch64" {"x0"} else {"r0"},"format":"hex"}]}));
            assert_eq!(report["reads"][0]["value"], "hello", "{report}");
            assert_eq!(report["reads"][1]["value"], "68 65 6c 6c 6f");
            let report = interfaces.check(
                &path,
                &binary,
                "output_calls",
                json!({"reads":[{"symbol":"decoded","length":24,"format":"bytes"}]}),
            );
            assert_eq!(report["reason"], "return", "{architecture} {report}");
            assert_eq!(report["stdout"], "out!ABCD");
            assert_eq!(report["stderr"], "error:3err!?");
            assert_eq!(matrix::value(&report), 908);
            assert_eq!(
                &report["reads"][0]["bytes"].as_array().expect("bytes")[..9],
                &json!([99, 111, 100, 101, 58, 48, 48, 48, 55])
                    .as_array()
                    .expect("expected")[..]
            );
            let report = interfaces.check(
                &path,
                &binary,
                "input_calls",
                json!({"stdin":{"hex":"41 42 43 44 45 46 47 0a"},"reads":[read("decoded")]}),
            );
            assert_eq!(
                report["reads"][0]["value"], "A|BC|DE|FG",
                "{architecture} {report}"
            );
            assert_eq!(matrix::value(&report), 21);
            let report = interfaces.check(
                &path,
                &binary,
                "scan_calls",
                json!({"stdin":{"text":"-27 sample ! 0x123"},"reads":[read("decoded")]}),
            );
            assert_eq!(
                report["reads"][0]["value"], "-27|sample|!|291|255",
                "{architecture} {report}"
            );
        }
    }
}

#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "the emulated libc follows glibc")]
fn printf_matches_native_libc() {
    let mut interfaces = Interfaces::new();
    for architecture in matrix::ARCHITECTURES {
        let path = matrix::fixtures().join(format!("{architecture}.O2.io.elf"));
        let binary = Binary::open(&path).expect("format fixture");
        for value in [
            i32::MIN,
            -1000000,
            -127,
            -1,
            0,
            1,
            7,
            31,
            255,
            4096,
            i32::MAX,
        ] {
            let native = Command::new(matrix::fixtures().join("host.io.native"))
                .args(["format", &value.to_string()])
                .output()
                .expect("libc reference");
            assert!(native.status.success());
            let report = interfaces.check(
                &path,
                &binary,
                "format_value",
                json!({"arguments":[(value as u32).to_string()]}),
            );
            assert_eq!(report["reason"], "return", "{architecture} {report}");
            assert_eq!(
                report["stdout"],
                String::from_utf8(native.stdout).expect("formatted ASCII"),
                "{architecture} {value}"
            );
        }
        for value in [
            i32::MIN,
            -65537,
            -129,
            -1,
            0,
            127,
            255,
            32768,
            65535,
            i32::MAX,
        ] {
            let native = Command::new(matrix::fixtures().join("host.io.native"))
                .args(["corner", &value.to_string()])
                .output()
                .expect("libc reference");
            assert!(native.status.success());
            let report = interfaces.check(
                &path,
                &binary,
                "format_corner",
                json!({"arguments":[(value as u32).to_string()]}),
            );
            assert_eq!(report["reason"], "return", "{architecture} {report}");
            assert_eq!(
                report["stdout"],
                String::from_utf8(native.stdout).expect("formatted ASCII"),
                "{architecture} {value}"
            );
        }
        for value in [i64::MIN, -1, 0, 1, 0x123456789abcdef, i64::MAX] {
            let native = Command::new(matrix::fixtures().join("host.io.native"))
                .args(["wide", &value.to_string()])
                .output()
                .expect("libc reference");
            assert!(native.status.success());
            let arguments = if matches!(architecture, "i386" | "arm32" | "thumb32") {
                json!([value as u32 as u64, (value as u64 >> 32) as u32 as u64])
            } else {
                json!([(value as u64).to_string()])
            };
            let report = interfaces.check(
                &path,
                &binary,
                "format_wide",
                json!({"arguments":arguments}),
            );
            assert_eq!(report["reason"], "return", "{architecture} {report}");
            assert_eq!(
                report["stdout"],
                String::from_utf8(native.stdout).expect("formatted ASCII"),
                "{architecture} {value}"
            );
        }
    }
}

#[test]
fn io_errors_and_reads() {
    let mut interfaces = Interfaces::new();
    let path = matrix::fixtures().join("x86_64.O0.io.elf");
    let binary = Binary::open(&path).expect("I/O fixture");
    for (function, options, message) in [
        ("unsupported_format", json!({}), "%f"),
        ("unsupported_scan", json!({"stdin":{"text":"1"}}), "%f"),
        ("invalid_fd", json!({}), "fd 4"),
        ("invalid_stream", json!({}), "stream pointer"),
        (
            "decode_buffer",
            json!({"reads":[{"address":1,"length":1}]}),
            "unmapped memory",
        ),
        (
            "decode_buffer",
            json!({"reads":[{"symbol":"missing"}]}),
            "unknown data symbol",
        ),
    ] {
        let report = interfaces.check(&path, &binary, function, options);
        assert_eq!(report["reason"], "error", "{report}");
        assert!(
            report["error"].as_str().expect("error").contains(message),
            "{report}"
        );
    }
    let report = interfaces.check(&path, &binary, "empty_input", json!({}));
    assert_eq!(matrix::value(&report), u32::MAX);
    let report = interfaces.check(&path, &binary, "truncated_string", json!({}));
    assert_eq!(matrix::value(&report), 3);
    let report = interfaces.check(
        &path,
        &binary,
        "decode_buffer",
        json!({"reads":[{"address":"0x10000000","length":8,"format":"integers","width":4}]}),
    );
    assert_eq!(report["reads"][0]["value"], json!(["0", "0"]));
    let file = matrix::fixtures().join("input.txt");
    std::fs::write(&file, "flag{input}\n").expect("stdin file");
    let report = interfaces.check(&path, &binary, "check_flag", json!({"stdin":{"file":file}}));
    assert_eq!(report["stdout"], "Correct\n");
    let cli = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--emulate")
        .arg(&path)
        .arg("check_flag")
        .args(["--emulation-options", "{\"stdin\":{\"text\":\"wrong\\n\"}}"])
        .output()
        .expect("text CLI");
    assert!(cli.status.success());
    let text = String::from_utf8(cli.stdout).expect("CLI UTF-8");
    assert!(
        text.contains("Stop: return")
            && text.contains("stdout:\nWrong\n")
            && text.contains("Return: 0x0"),
        "{text}"
    );
}

fn native_input(mode: &str, input: &str) -> std::process::Output {
    use std::io::Write as _;
    use std::process::Stdio;
    let mut child = Command::new(matrix::fixtures().join("host.io.native"))
        .arg(mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("native I/O reference");
    child
        .stdin
        .take()
        .expect("reference stdin")
        .write_all(input.as_bytes())
        .expect("reference input");
    child.wait_with_output().expect("native reference result")
}

#[test]
fn input_matches_native_libc() {
    let mut interfaces = Interfaces::new();
    for architecture in matrix::ARCHITECTURES {
        let path = matrix::fixtures().join(format!("{architecture}.O0.io.elf"));
        let binary = Binary::open(&path).expect("input fixture");
        for input in [
            "flag{input}\n",
            "wrong\n",
            "",
            "\n",
            "flag{input}",
            "flag{input}\nignored",
            "flag{input}\0\n",
        ] {
            let native = native_input("check", input);
            let report = interfaces.check(
                &path,
                &binary,
                "check_flag",
                json!({"stdin":{"text":input}}),
            );
            assert_eq!(
                report["stdout"],
                String::from_utf8(native.stdout).expect("reference text")
            );
            assert_eq!(
                matrix::value(&report),
                native.status.code().expect("reference exit") as u32
            );
        }
        for input in [
            "9223372036854775807 127 ignore abc",
            "-9223372036854775808 -128 skip xyz",
            "0 0 skip a",
            "-1 -1 skip word",
            "",
            "no",
            "17",
            "17 2",
            "17 2 skip",
        ] {
            let native = native_input("scan", input);
            assert!(native.status.success());
            let report = interfaces.check(
                &path,
                &binary,
                "scan_value",
                json!({"stdin":{"text":input},"reads":[read("decoded")]}),
            );
            assert_eq!(
                report["reason"], "return",
                "{architecture} {input:?} {report}"
            );
            let text = String::from_utf8(native.stdout).expect("reference text");
            let lines: Vec<&str> = text.lines().collect();
            assert_eq!(
                report["reads"][0]["value"], lines[0],
                "{architecture} {input:?} {report}"
            );
            let count = lines[1].parse::<i32>().expect("reference count") as u32;
            assert_eq!(matrix::value(&report), count, "{architecture} {input:?}");
        }
        for input in ["ABCDEFG\n", "ABCDE\n", "ABCDE", "ABCD", "A", ""] {
            let native = native_input("input", input);
            let report = interfaces.check(
                &path,
                &binary,
                "input_calls",
                json!({"stdin":{"text":input},"reads":[read("decoded")]}),
            );
            assert_eq!(
                report["reason"], "return",
                "{architecture} {input:?} {report}"
            );
            let text = String::from_utf8_lossy(&native.stdout);
            let lines: Vec<&str> = text.lines().collect();
            // getchar EOF is printed through %c as a non-UTF-8 byte by the fixture.
            assert_eq!(
                report["reads"][0]["value"], lines[0],
                "{architecture} {input:?} {report}"
            );
            assert_eq!(
                matrix::value(&report),
                lines[1].parse::<u32>().expect("reference count")
            );
        }
    }
}

#[test]
fn output_buffers_match_native_libc() {
    let mut interfaces = Interfaces::new();
    let native = native_input("output", "");
    assert!(native.status.success());
    for architecture in matrix::ARCHITECTURES {
        let path = matrix::fixtures().join(format!("{architecture}.O2.io.elf"));
        let binary = Binary::open(&path).expect("output fixture");
        let report = interfaces.check(
            &path,
            &binary,
            "output_calls",
            json!({"reads":[{"symbol":"decoded","length":32,"format":"bytes"}]}),
        );
        assert_eq!(report["reason"], "return", "{architecture} {report}");
        let bytes: Vec<u8> = report["reads"][0]["bytes"]
            .as_array()
            .expect("bytes")
            .iter()
            .map(|value| value.as_u64().expect("byte") as u8)
            .collect();
        let first = String::from_utf8_lossy(&bytes[..9]);
        let second = String::from_utf8_lossy(&bytes[16..20]);
        let expected = format!(
            "{}\n{first}|{second}\n{}\n",
            report["stdout"].as_str().expect("stdout"),
            matrix::value(&report)
        );
        assert_eq!(native.stdout, expected.as_bytes(), "{architecture}");
        assert_eq!(
            native.stderr,
            report["stderr"].as_str().expect("stderr").as_bytes()
        );
    }
}

#[test]
fn input_and_read_bounds() {
    let path = matrix::fixtures().join("x86_64.O0.io.elf");
    let binary = Binary::open(&path).expect("bounds fixture");
    let mut interfaces = Interfaces::new();
    for options in [
        json!({"reads":[{"address":"0x10000000","length":16777217}]}),
        json!({"reads":[{"address":"0x10000000","length":3,"format":"integers","width":2}]}),
        json!({"reads":[{"address":"0x10000000","length":1,"format":"integers","width":3}]}),
        json!({"reads":[{"address":1,"symbol":"decoded"}]}),
        json!({"reads":[{"register":"al"}]}),
        json!({"memory":[{"address":"0x7fffff000ffe","bytes":[1,2]}],"reads":[{"address":"0x7fffff000ffe"}]}),
    ] {
        let report = interfaces.check(&path, &binary, "decode_buffer", options);
        assert_eq!(report["reason"], "error", "{report}");
    }
    let report = interfaces.check(
        &path,
        &binary,
        "decode_buffer",
        json!({"stepLimit":0,"reads":[{"symbol":"decoded","length":1,"format":"bytes"}]}),
    );
    assert_eq!(report["reason"], "step limit");
    assert_eq!(report["reads"][0]["value"], json!([0]));
    let report = interfaces.check(
        &path,
        &binary,
        "output_calls",
        json!({"reads":[{"register":"rdi","length":1}]}),
    );
    assert_eq!(report["reason"], "error");
    assert!(
        report["error"]
            .as_str()
            .expect("read error")
            .contains("undefined register")
    );
    let report = interfaces.check(
        &path,
        &binary,
        "check_flag",
        json!({"callReturns":{"fgets":0},"stdin":{"text":"flag{input}\n"}}),
    );
    assert_eq!(matrix::value(&report), 2);
    assert_eq!(report["stdout"], "");
    for options in [
        json!({"argv":["app\u{0}bad"]}),
        json!({"argv":["app"],"arguments":[1]}),
        json!({"stdin":{"hex":"a"}}),
        json!({"stdin":{"hex":"xx"}}),
        json!({"stdin":{"file":"does-not-exist"}}),
    ] {
        let parsed = serde_json::from_value(options).expect("options schema");
        assert!(velk::emulation::run(&binary, "main", &parsed, None).is_err());
    }
}

#[test]
fn variadic_io_matches_native_libc() {
    let mut interfaces = Interfaces::new();
    let native = native_input("voutput", "");
    assert!(native.status.success());
    for architecture in matrix::ARCHITECTURES {
        for optimization in ["O0", "O2"] {
            let path = matrix::fixtures().join(format!("{architecture}.{optimization}.io.elf"));
            let binary = Binary::open(&path).expect("variadic fixture");
            let mut count = 0;
            let mut stdout = String::new();
            let mut stderr = String::new();
            for function in [
                "variadic_stdout",
                "variadic_error",
                "variadic_string",
                "variadic_bounded",
            ] {
                let report =
                    interfaces.check(&path, &binary, function, json!({"reads":[read("decoded")]}));
                assert_eq!(
                    report["reason"], "return",
                    "{architecture} {optimization} {report}"
                );
                count += matrix::value(&report);
                stdout.push_str(report["stdout"].as_str().expect("stdout"));
                stderr.push_str(report["stderr"].as_str().expect("stderr"));
                if function == "variadic_string" {
                    assert_eq!(report["reads"][0]["value"], "code:0007");
                }
            }
            assert_eq!(
                native.stdout,
                format!("{stdout}code:0007|00ab\n{count}\n").as_bytes(),
                "{architecture} {optimization}"
            );
            assert_eq!(native.stderr, stderr.as_bytes());
            for (function, value) in [
                ("variadic_scan", 12),
                ("variadic_scan_file", 34),
                ("variadic_scan_string", 27),
            ] {
                let report = interfaces.check(
                    &path,
                    &binary,
                    function,
                    json!({"stdin":{"text":value.to_string()},"reads":[read("decoded")]}),
                );
                assert_eq!(
                    report["reason"], "return",
                    "{architecture} {optimization} {report}"
                );
                assert_eq!(report["reads"][0]["value"], value.to_string());
                assert_eq!(matrix::value(&report), value);
            }
        }
    }
}

#[test]
fn automatic_string_recovery_does_not_assume_stdin_is_empty() {
    for architecture in matrix::ARCHITECTURES {
        for optimization in ["O0", "O2"] {
            let path = matrix::fixtures().join(format!("{architecture}.{optimization}.io.elf"));
            let mut binary = Binary::open(&path).expect("input-dependent decoder");
            let function = binary.find("input_decode").expect("decoder").addr;
            assert!(
                binary.decoded_strings_at(function, None).is_empty(),
                "{architecture} {optimization}"
            );
            let options = serde_json::from_value(json!({"reads":[read("decoded")]}))
                .expect("explicit execution options");
            let report = velk::emulation::run(&binary, "input_decode", &options, None)
                .expect("explicit emulation");
            assert_eq!(
                report.reason, "return",
                "{architecture} {optimization} {report:?}"
            );
            assert_eq!(report.reads[0].value, "hello");
        }
    }
}

#[test]
fn windows_arm64_long_uses_four_bytes() {
    let path = matrix::fixtures().join("arm64.dll");
    let binary = Binary::open(&path).expect("Windows ARM64 format fixture");
    let mut interfaces = Interfaces::new();
    for (function, imported) in [("print_long", "printf"), ("scan_long", "sscanf")] {
        let options = velk::emulation::Options::default();
        let report = velk::emulation::run(&binary, function, &options, None).expect("PE execution");
        // The PE import thunk has not resolved its target. Keep the compiled
        // argument state and invoke the hook through an explicit import slot.
        assert_eq!(report.reason, "error");
        assert!(
            report
                .error
                .as_ref()
                .expect("import stop")
                .contains("unmapped code")
        );
        let slot = binary
            .image()
            .imports
            .iter()
            .find(|(_, name)| name.as_str() == imported)
            .map(|(&address, _)| address)
            .expect("import slot");
        let mut registers = report.registers;
        registers.insert("x16".into(), velk::addr::format(slot));
        let memory: Vec<Value> = report
            .memory
            .iter()
            .map(|region| json!({"address":region.address,"bytes":region.bytes}))
            .collect();
        let mut options = json!({"registers":registers,"memory":memory});
        if function == "scan_long" {
            options["reads"] = json!([{"address":registers["x2"],"length":8,"format":"hex"}]);
        }
        let result = interfaces.check(&path, &binary, "invoke_import", options);
        assert_eq!(result["reason"], "return", "{result}");
        if function == "print_long" {
            assert_eq!(result["stdout"], "-1|18446744073709551615");
        } else {
            assert_eq!(result["reads"][0]["value"], "e5 ff ff ff 78 56 34 12");
        }
    }
}

#[test]
fn descriptor_arguments_ignore_bits_above_the_c_int_width() {
    let mut interfaces = Interfaces::new();
    for architecture in matrix::ARCHITECTURES {
        let path = matrix::fixtures().join(format!("{architecture}.O2.io.elf"));
        let binary = Binary::open(&path).expect("descriptor fixture");
        let report = interfaces.check(
            &path,
            &binary,
            "write_descriptor",
            json!({"arguments":["0xffffffff00000001"]}),
        );
        assert_eq!(report["reason"], "return", "{architecture} {report}");
        assert_eq!(report["stdout"], "fd");
        assert_eq!(matrix::value(&report), 2);
        let report = interfaces.check(&path, &binary, "read_descriptor", json!({"arguments":["0xffffffff00000000"],"stdin":{"text":"ok"},"reads":[read("decoded")]}));
        assert_eq!(report["reason"], "return", "{architecture} {report}");
        assert_eq!(report["reads"][0]["value"], "ok");
        assert_eq!(matrix::value(&report), 2);
    }
}

#[test]
fn integer_flags_widths_and_precisions_match_native_libc() {
    let mut cases = Vec::new();
    for conversion in ['d', 'i', 'u', 'o', 'x', 'X'] {
        let signed = matches!(conversion, 'd' | 'i');
        let flags: &[&str] = if signed {
            &["", "0", "-", "+", " ", "+0", " 0", "-+", "-0"]
        } else if conversion == 'u' {
            &["", "0", "-", "-0"]
        } else {
            &["", "0", "-", "-0", "#", "#0", "-#", "-#0"]
        };
        for flag in flags {
            for width in ["", "1", "8", "20"] {
                for precision in ["", ".0", ".1", ".8"] {
                    for value in [0, 1, 8, 255, i32::MAX as u32, 0x80000000, u32::MAX] {
                        let format = format!("%{flag}{width}{precision}{conversion}");
                        let argument = if signed {
                            (value as i32).to_string()
                        } else {
                            value.to_string()
                        };
                        let native = Command::new(matrix::fixtures().join("host.io.native"))
                            .args([
                                if signed { "signed" } else { "unsigned" },
                                &format,
                                &argument,
                            ])
                            .output()
                            .expect("libc format reference");
                        assert!(native.status.success());
                        cases.push((
                            format,
                            value,
                            signed,
                            String::from_utf8(native.stdout).expect("formatted ASCII"),
                        ));
                    }
                }
            }
        }
    }
    for architecture in matrix::ARCHITECTURES {
        let path = matrix::fixtures().join(format!("{architecture}.O2.io.elf"));
        let binary = Binary::open(&path).expect("format matrix fixture");
        for (format, value, signed, expected) in &cases {
            let bytes: Vec<u8> = format.bytes().chain([0]).collect();
            let options = serde_json::from_value(json!({"arguments":["0x10000000",value],"memory":[{"address":"0x10000000","bytes":bytes}]})).expect("format options");
            let report = velk::emulation::run(
                &binary,
                if *signed {
                    "format_signed"
                } else {
                    "format_unsigned"
                },
                &options,
                None,
            )
            .expect("format run");
            assert_eq!(
                report.reason, "return",
                "{architecture} {format} {value} {report:?}"
            );
            assert_eq!(&report.stdout, expected, "{architecture} {format} {value}");
        }
    }
}

#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "the emulated libc follows glibc")]
fn scanf_integer_widths_and_prefixes_match_native_libc() {
    let mut cases = Vec::new();
    for conversion in ['d', 'i', 'u', 'o', 'x', 'X'] {
        let function = if matches!(conversion, 'd' | 'i') {
            "scan_signed"
        } else {
            "scan_unsigned"
        };
        for width in ["", "1", "2", "4"] {
            let format = format!("%{width}{conversion}%c");
            for input in [
                "", " ", "+", "-", "0", "0x", "0xg", "-0x", "00", "08", "12z", " -27z", "0xff!",
                "word", " + z", "00017",
            ] {
                let native = Command::new(matrix::fixtures().join("host.io.native"))
                    .args([function, &format, input])
                    .output()
                    .expect("libc scanf reference");
                assert!(native.status.success());
                let text = String::from_utf8(native.stdout).expect("scanf reference text");
                let mut lines = text.lines();
                let expected = lines.next().expect("reference values").to_owned();
                let count = lines
                    .next()
                    .expect("reference count")
                    .parse::<i32>()
                    .expect("count") as u32;
                cases.push((function, format.clone(), input, expected, count));
            }
        }
    }
    for architecture in matrix::ARCHITECTURES {
        let path = matrix::fixtures().join(format!("{architecture}.O2.io.elf"));
        let binary = Binary::open(&path).expect("scanf matrix fixture");
        for (function, format, input, expected, count) in &cases {
            let format_bytes: Vec<u8> = format.bytes().chain([0]).collect();
            let input_bytes: Vec<u8> = input.bytes().chain([0]).collect();
            let options = serde_json::from_value(json!({"arguments":["0x10000000","0x10000100"],"memory":[{"address":"0x10000000","bytes":format_bytes},{"address":"0x10000100","bytes":input_bytes}],"reads":[read("decoded")]})).expect("scanf options");
            let report =
                velk::emulation::run(&binary, function, &options, None).expect("scanf execution");
            assert_eq!(
                report.reason, "return",
                "{architecture} {format} {input:?} {report:?}"
            );
            assert_eq!(
                report.reads[0].value, *expected,
                "{architecture} {format} {input:?}"
            );
            assert_eq!(
                velk::addr::parse(&report.return_value),
                Some(u64::from(*count)),
                "{architecture} {format} {input:?}"
            );
        }
    }
}

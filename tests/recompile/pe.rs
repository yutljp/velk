use super::*;

#[test]
fn every_pe_function_compiles() {
    let fixtures: Vec<_> = common::fixtures()
        .into_iter()
        .filter(|path| {
            (path.to_string_lossy().contains(".win64.")
                || path.to_string_lossy().contains(".win32.")
                || path.to_string_lossy().contains(".pe32."))
                || path.file_name().is_some_and(|name| {
                    name.to_string_lossy().starts_with("seh.")
                        || name.to_string_lossy().starts_with("seh_cpp.")
                })
        })
        .collect();
    assert!(!fixtures.is_empty());
    let scratch = scratch_dir("pe-syntax");
    let source = scratch.join("check.c");
    let mut summary = String::new();
    let mut failures = Vec::new();
    for fixture in fixtures {
        let mut binary = Binary::open(&common::fixtures_dir().join(&fixture)).unwrap();
        let addresses: Vec<_> = binary.image().functions.keys().copied().collect();
        let mut compiled = 0;
        for address in &addresses {
            let code = binary
                .decompile_with_dependencies(*address, None, None)
                .unwrap()
                .code;
            std::fs::write(
                &source,
                format!("#include <stdint.h>\n#include <stdbool.h>\n#include <stddef.h>\n#include <stdlib.h>\n{code}"),
            )
            .unwrap();
            let output = Command::new(compiler())
                .args(FLAGS)
                .args([
                    "-fsyntax-only",
                    "-ferror-limit=0",
                    "-Wno-implicit-function-declaration",
                ])
                .arg(&source)
                .output()
                .unwrap();
            if output.status.success() {
                compiled += 1;
            } else {
                failures.push(format!(
                    "{} {address:#x}:\n{code}\n{}",
                    fixture.display(),
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }
        writeln!(
            summary,
            "{}: {compiled}/{} compile",
            fixture.display(),
            addresses.len()
        )
        .unwrap();
    }
    std::fs::remove_dir_all(scratch).unwrap();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    let expected = common::root().join("tests/golden/pe_syntax.txt");
    assert!(
        common::check_expected(&expected, &summary).is_none(),
        "PE syntax counts changed"
    );
}

#[test]
fn windows_aggregate_results_preserve_every_field() {
    let mut candidates = Vec::new();
    for opt in ["O0", "O2"] {
        let mut binary = Binary::open(
            &common::fixtures_dir().join(format!("metrics/windows.win64.{opt}.debug.dll")),
        )
        .unwrap();
        let address = binary.find("make_triple").unwrap().addr;
        let ir = binary.analysis(address, None).unwrap().ir.clone();
        let signature = ir.declared_signature.as_ref().unwrap();
        let abi = signature.abi.as_ref().unwrap();
        assert_eq!(abi.profile, AbiProfile::Win64);
        assert!(matches!(
            abi.result.as_ref().unwrap().passing,
            Passing::Indirect {
                pointer: AbiLocation::Register(1),
                ..
            }
        ));
        let (inputs, upper) = aggregate_inputs(&[8], 12);
        let batch = aggregate_candidates(ir, inputs, upper);
        assert_aggregate_oracle(&batch, |input, slice| match slice.offset {
            0 => input[0],
            8 => input[0].wrapping_add(1),
            16 => input[0] ^ 9,
            _ => panic!("unexpected result offset"),
        });
        assert_eq!(batch.len(), 3);
        candidates.extend(batch);
    }
    check_candidates(
        "windows-aggregate-results",
        candidates,
        Mode::Registers,
        &[],
    );
}

#[test]
fn windows_imports_keep_arguments_and_saved_xmm_values() {
    let scratch = scratch_dir("windows-imports");
    for opt in ["O0", "O2"] {
        let mut binary = Binary::open(
            &common::fixtures_dir().join(format!("metrics/windows.win64.{opt}.debug.dll")),
        )
        .unwrap();
        assert!(
            binary
                .image()
                .imports
                .values()
                .any(|name| name == "imported_value")
        );
        for name in ["call_import", "saved_xmm"] {
            let address = binary.find(name).unwrap().addr;
            let code = binary.decompile(address, None, None).unwrap();
            assert!(code.contains("imported_value("), "{code}");
            assert!(!code.contains("imported_value()"), "{code}");
            let text = format!(
                "{HEADER}\nint imported_value(int value, ...) {{ return value * 2; }}\n{code}\nint main(void) {{ return call_import(-9) != -15; }}\n"
            );
            let text = if name == "saved_xmm" {
                text.replace(
                    "return call_import(-9) != -15",
                    "return saved_xmm(1.25) != 15.25",
                )
            } else {
                text
            };
            let source = Program {
                text,
                ranges: Vec::new(),
            };
            for level in LEVELS {
                let executable = build(&source, &scratch, level, &[]);
                assert!(
                    Command::new(executable).status().unwrap().success(),
                    "{opt} {name}: {code}"
                );
            }
        }
    }
    std::fs::remove_dir_all(scratch).unwrap();
}

#[test]
fn windows_stack_arguments_and_probes_preserve_results() {
    let scratch = scratch_dir("windows-stack");
    for opt in ["O0", "O2"] {
        let debug = Binary::open(
            &common::fixtures_dir().join(format!("metrics/windows.win64.{opt}.debug.dll")),
        )
        .unwrap();
        let addresses: Vec<_> = ["large_frame", "stack_arguments"]
            .into_iter()
            .map(|name| (name, debug.find(name).unwrap().addr))
            .collect();
        for variant in ["debug", "stripped"] {
            let mut binary = Binary::open(
                &common::fixtures_dir().join(format!("metrics/windows.win64.{opt}.{variant}.dll")),
            )
            .unwrap();
            for &(name, address) in &addresses {
                let ir = &binary.analysis(address, None).unwrap().ir;
                assert!(
                    !ir.blocks
                        .iter()
                        .flat_map(|block| &block.stmts)
                        .any(|stmt| matches!(stmt, Stmt::Call { .. }))
                );
                let code = binary.decompile(address, None, None).unwrap();
                assert!(!code.contains("__chkstk"), "{code}");
                let code = renamed(&code, 0);
                let driver = if name == "stack_arguments" {
                    r#"
int main(void) {
    uint64_t a[6] = {1, 2, 3, 4, 5, 6};
    for (unsigned trial = 0; trial < 64; trial++) {
        a[trial % 6] = trial % 2 ? UINT64_MAX - trial : UINT64_C(0x8123456789abcdef) + trial;
        uint64_t expected = a[0] + 3*a[1] + 5*a[2] + 7*a[3] + 11*a[4] + 13*a[5];
        if (velk_f0(a[0], a[1], a[2], a[3], a[4], a[5]) != expected) return 1;
    }
    return 0;
}
"#
                } else {
                    r#"
int main(void) {
    int values[] = {0, 127, 128, 255, 8191, 8192, -1, -128, -129};
    for (unsigned i = 0; i < sizeof values / sizeof *values; i++) {
        if ((int32_t)velk_f0(values[i]) != (int8_t)values[i]) return 1;
    }
    return 0;
}
"#
                };
                let source = Program {
                    text: format!("{HEADER}{code}{driver}"),
                    ranges: Vec::new(),
                };
                for level in LEVELS {
                    let executable = build(&source, &scratch, level, &[]);
                    assert!(
                        Command::new(executable).status().unwrap().success(),
                        "{opt} {variant} {name}: {code}"
                    );
                }
            }
        }
    }
    std::fs::remove_dir_all(scratch).unwrap();
}

#[test]
fn windows_long_types_keep_their_recorded_widths() {
    let scratch = scratch_dir("windows-long");
    for opt in ["O0", "O2"] {
        for (case, name) in [("integers", "labs_value"), ("calls", "sum9")] {
            let mut binary = Binary::open(
                &common::fixtures_dir().join(format!("metrics/{case}.win64.{opt}.debug.dll")),
            )
            .unwrap();
            let address = binary.find(name).unwrap().addr;
            let ir = &binary.analysis(address, None).unwrap().ir;
            assert_eq!(ir.ret_type, CType::I32);
            assert!(ir.params.iter().all(|param| param.ty == CType::I32));
            assert!(ir.stack_params.iter().all(|param| param.ty == CType::I32));
            let code = renamed(&binary.decompile(address, None, None).unwrap(), 0);
            let driver = if name == "sum9" {
                r#"
int main(void) {
    int32_t values[] = {0, -1, INT32_MIN, INT32_MAX, 0x12345678};
    for (unsigned i = 0; i < sizeof values / sizeof *values; i++) {
        int32_t x = values[i];
        uint32_t expected = (uint32_t)x * 9;
        if ((uint32_t)velk_f0(x, x, x, x, x, x, x, x, x) != expected) return 1;
    }
    return 0;
}
"#
            } else {
                r#"
int main(void) {
    int32_t values[] = {0, -1, INT32_MIN, INT32_MAX, -0x12345678};
    for (unsigned i = 0; i < sizeof values / sizeof *values; i++) {
        int32_t x = values[i];
        uint32_t expected = x < 0 ? 0U - (uint32_t)x : (uint32_t)x;
        if ((uint32_t)velk_f0(x) != expected) return 1;
    }
    return 0;
}
"#
            };
            let source = Program {
                text: format!("{HEADER}{code}{driver}"),
                ranges: Vec::new(),
            };
            for level in LEVELS {
                let executable = build(&source, &scratch, level, &[]);
                assert!(
                    Command::new(executable).status().unwrap().success(),
                    "{opt} {name}: {code}"
                );
            }
        }
    }
    std::fs::remove_dir_all(scratch).unwrap();
}

#[test]
fn windows_argument_register_saves_share_the_target_frame() {
    let mut candidates = Vec::new();
    for opt in ["O0", "O2"] {
        let debug = Binary::open(
            &common::fixtures_dir().join(format!("metrics/calls.win64.{opt}.debug.dll")),
        )
        .unwrap();
        let address = debug.find("sum_varargs").unwrap().addr;
        let mut binary = Binary::open(
            &common::fixtures_dir().join(format!("metrics/calls.win64.{opt}.stripped.dll")),
        )
        .unwrap();
        let mut ir = binary.analysis(address, None).unwrap().ir.clone();
        ir.name = Some("windows_saved_arguments".into());
        assert_eq!(ir.params.len(), 4);
        let mut inputs = Vec::new();
        for count in 0..=3 {
            for value in [0, u64::MAX, 0x8000_0000, 0x1234_5678_9abc_def0] {
                inputs.push(vec![
                    count,
                    value,
                    value.wrapping_sub(1),
                    value ^ 0x8000_0000,
                ]);
            }
        }
        let candidate = printed_candidate(ir, inputs);
        assert!(
            candidate
                .code
                .contains("target frame's return-address slot"),
            "{}",
            candidate.code
        );
        candidates.push(candidate);
    }
    check_candidates("windows-saved-arguments", candidates, Mode::Memory, &[]);
}

#[test]
fn windows_integer_and_float_arguments_share_positions() {
    let scratch = scratch_dir("windows-argument-positions");
    for opt in ["O0", "O2"] {
        let debug = Binary::open(
            &common::fixtures_dir().join(format!("metrics/aggregate_abi.win64.{opt}.debug.dll")),
        )
        .unwrap();
        let address = debug.find("abi_hfa1_adjust").unwrap().addr;
        let mut binary = Binary::open(
            &common::fixtures_dir().join(format!("metrics/aggregate_abi.win64.{opt}.stripped.dll")),
        )
        .unwrap();
        let ir = &binary.analysis(address, None).unwrap().ir;
        assert_eq!(
            ir.params
                .iter()
                .map(|param| param.index)
                .collect::<Vec<_>>(),
            [1, 20]
        );
        let code = renamed(&binary.decompile(address, None, None).unwrap(), 0);
        let source = Program {
            text: format!(
                r#"{HEADER}{code}
int main(void) {{
    double values[] = {{0.0, -0.0, 1.25, -2.5, 1e20, -1e-20}};
    for (unsigned i = 0; i < sizeof values / sizeof *values; i++) {{
        union {{ double value; uint64_t bits; }} input = {{.value = values[i]}};
        union {{ double value; uint64_t bits; }} expected = {{.value = values[i] + 0.5}};
        if ((uint64_t)velk_f0(input.bits, 0.5) != expected.bits) return 1;
    }}
    return 0;
}}
"#
            ),
            ranges: Vec::new(),
        };
        for level in LEVELS {
            let executable = build(&source, &scratch, level, &[]);
            assert!(
                Command::new(executable).status().unwrap().success(),
                "{opt}: {code}"
            );
        }
    }
    std::fs::remove_dir_all(scratch).unwrap();
}

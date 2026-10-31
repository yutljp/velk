use super::*;

fn i386_fixtures() -> Vec<std::path::PathBuf> {
    common::fixtures()
        .into_iter()
        .filter(|path| {
            let name = path.to_string_lossy();
            name.contains(".i386.") || name.contains(".win32.")
        })
        .collect()
}

#[test]
fn i386_fixture_functions_match_reference_values() {
    let fixtures = i386_fixtures();
    for fixture in &fixtures {
        let mut binary = Binary::open(&common::fixtures_dir().join(fixture)).unwrap();
        let name = fixture.to_string_lossy();
        let cases: &[(&str, &str)] = if name.contains("l0_arith") {
            &[
                ("add3", "return add3(3, 4, 5) != 12 || add3(-1, 1, 7) != 7;"),
                ("scale", "return scale(8) != 59 || scale(-7) != -46;"),
                ("pick", "return pick(-1, 3) != 3 || pick(7, -9) != 7;"),
                ("negate", "return negate(17) != -17 || negate(-5) != 5;"),
            ]
        } else if name.contains("l1_branch") {
            &[
                (
                    "classify",
                    "return classify(-17) != -1 || classify(0) != 0 || classify(8) != 1;",
                ),
                (
                    "clamp",
                    "return clamp(-7, -3, 8) != -3 || clamp(99, -3, 8) != 8 || clamp(0, -3, 8) != 0;",
                ),
                (
                    "sign_of",
                    "return sign_of(-17) != -1 || sign_of(0) != 0 || sign_of(8) != 1;",
                ),
            ]
        } else {
            continue;
        };
        for (function, assertions) in cases {
            let address = binary.find(function).unwrap().addr;
            let code = binary.decompile(address, None, None).unwrap();
            assert!(
                !code.contains("velk_entry_stack_pointer"),
                "{}: {code}",
                fixture.display()
            );
            let rendered = velk::render::callee_names(binary.image()).functions[&address].clone();
            let assertions = assertions.replace(&format!("{function}("), &format!("{rendered}("));
            syntax::run_printed(&code, "", &assertions);
        }
        eprintln!(
            "{}: {} reference functions passed",
            fixture.display(),
            cases.len()
        );
    }
    assert_eq!(fixtures.len(), 28);
}

#[test]
fn i386_every_fixture_function_compiles() {
    let fixtures = i386_fixtures();
    syntax::scan(&fixtures, "i386-syntax");
}

#[test]
fn i386_calling_conventions_preserve_arguments_and_cleanup() {
    for optimization in ["O0", "O2"] {
        for variant in ["debug", "stripped"] {
            let mut binary = Binary::open(&common::fixtures_dir().join(format!(
                "metrics/conventions.win32.{optimization}.{variant}.dll"
            )))
            .unwrap();
            for (function, expected, arguments) in [
                ("cdecl_add", Convention::Cdecl, "17, 3"),
                ("stdcall_add", Convention::Stdcall, "17, 3"),
                ("fastcall_add", Convention::Fastcall, "13, 3, 4"),
                ("thiscall_add", Convention::Thiscall, "17, 3"),
            ] {
                let address = binary.find(function).unwrap().addr;
                assert_eq!(binary.image().convention_of(address), expected);
                let rendered =
                    velk::render::callee_names(binary.image()).functions[&address].clone();
                let code = binary.decompile(address, None, None).unwrap();
                assert!(!code.contains("velk_entry_stack_pointer"), "{code}");
                syntax::run_printed(&code, "", &format!("return {rendered}({arguments}) != 20;"));
            }
            let address = binary.find("call_conventions").unwrap().addr;
            let rendered = velk::render::callee_names(binary.image()).functions[&address].clone();
            let mut definitions = Vec::new();
            for function in ["cdecl_add", "stdcall_add", "fastcall_add", "thiscall_add"] {
                let callee = binary.find(function).unwrap().addr;
                definitions.push(binary.decompile(callee, None, None).unwrap());
            }
            definitions.push(binary.decompile(address, None, None).unwrap());
            let code = velk::render::combine(&definitions.join("\n"));
            assert!(!code.contains("velk_entry_stack_pointer"), "{code}");
            syntax::run_printed(
                &code,
                "",
                &format!(
                    "for (int x=-9;x<10;x++) if ({rendered}(x) != 4*x+15) return 1; return 0;"
                ),
            );
        }
    }
}

#[test]
fn i386_import_arguments_follow_the_cdecl_stack_layout() {
    for optimization in ["O0", "O2"] {
        for variant in ["debug", "stripped"] {
            let mut binary = Binary::open(&common::fixtures_dir().join(format!(
                "metrics/imports.win32.{optimization}.{variant}.dll"
            )))
            .unwrap();
            let address = binary.find("import_call").unwrap().addr;
            let rendered = velk::render::callee_names(binary.image()).functions[&address].clone();
            let code = binary.decompile(address, None, None).unwrap();
            assert!(code.contains("abs("), "{code}");
            syntax::run_printed(
                &format!("#include <stdlib.h>\n{code}"),
                "",
                &format!("return {rendered}(-17) != 20 || {rendered}(3) != 6;"),
            );
        }
    }
}

#[test]
fn i386_pic_calls_to_defined_plt_symbols_keep_stack_arguments() {
    for optimization in ["O0", "O2"] {
        for variant in ["debug", "stripped"] {
            let mut binary = Binary::open(&common::fixtures_dir().join(format!(
                "metrics/relocations.i386.{optimization}.{variant}.elf"
            )))
            .unwrap();
            let callee = binary
                .image()
                .functions
                .values()
                .find(|function| {
                    function.name.as_deref() == Some("add_bias")
                        && !function.sources.contains(&velk::loader::NameSource::Plt)
                })
                .unwrap()
                .addr;
            let address = binary.find("via_plt").unwrap().addr;
            let rendered = velk::render::callee_names(binary.image()).functions[&address].clone();
            let code = velk::render::combine(&format!(
                "{}\n{}",
                binary.decompile(callee, None, None).unwrap(),
                binary.decompile(address, None, None).unwrap()
            ));
            assert!(!code.contains("velk_entry_stack_pointer"), "{code}");
            syntax::run_printed(
                &code,
                "",
                &format!("return {rendered}(-17) != -10 || {rendered}(3) != 10;"),
            );
        }
    }
}

#[test]
fn i386_pic_library_calls_keep_their_stack_arguments() {
    for optimization in ["O0", "O2"] {
        for variant in ["debug", "stripped"] {
            let mut binary = Binary::open(&common::fixtures_dir().join(format!(
                "metrics/relocations.i386.{optimization}.{variant}.elf"
            )))
            .unwrap();
            let imported = binary.find("imported").unwrap().addr;
            let stub = binary
                .image()
                .functions
                .values()
                .find(|function| {
                    function.name.as_deref() == Some("abs")
                        && function.sources.contains(&velk::loader::NameSource::Plt)
                })
                .unwrap()
                .addr;
            let names = velk::render::callee_names(binary.image());
            let function = names.functions[&imported].clone();
            let thunk = names.functions[&stub].clone();
            let code = format!(
                "#include <stdlib.h>\n{}\n{}",
                binary.decompile(stub, None, None).unwrap(),
                binary.decompile(imported, None, None).unwrap()
            );
            assert!(!code.contains("velk_entry_stack_pointer"), "{code}");
            syntax::run_printed(
                &code,
                "",
                &format!("return {function}(-17) != 20 || {thunk}(-17) != 17;"),
            );
        }
    }
}

#[test]
fn generic_comparison_includes_debug_and_stripped_i386_integers() {
    let mut functions = 0;
    let mut candidates = 0;
    let mut excluded = BTreeMap::new();
    for fixture in common::fixtures() {
        let name = fixture.to_string_lossy();
        if !name.contains(".i386.") && !name.contains(".win32.") {
            continue;
        }
        let prepared = prepare(&fixture, Mode::Memory);
        functions += prepared.functions;
        candidates += prepared.candidates.len();
        for (reason, count) in prepared.excluded {
            *excluded.entry(reason).or_insert(0) += count;
        }
    }
    assert_eq!(functions, 104);
    assert_eq!(candidates, 76, "{excluded:?}");
    assert_eq!(excluded, BTreeMap::from([("calls", 28)]));
}

#[test]
fn windows_crt_functions_compile() {
    syntax::scan(
        &[
            PathBuf::from("crt_windows.i686.exe"),
            PathBuf::from("crt_windows.x86_64.exe"),
        ],
        "windows-crt-syntax",
    );
}

#[test]
fn windows_crt_format_arguments_reach_the_printed_call() {
    let mut binary = Binary::open(&common::fixtures_dir().join("crt_windows.i686.exe")).unwrap();
    let address = binary.find("crt_format").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    assert!(code.contains("printf_plt(\"%d\\n\", a0)"), "{code}");
    let code = code.replace("printf_plt(", "format_probe(");
    syntax::run_printed(
        &format!("int format_probe(const char *, int);\n{code}"),
        "int format_probe(const char *format, int value) { return format[0] == '%' && format[1] == 'd' ? value : 999; }",
        "return crt_format(-17) != -17 || crt_format(73) != 73;",
    );
    let address = binary.find("printf").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    assert!(
        code.contains("int printf_plt(const char *format, ...)"),
        "{code}"
    );
    assert!(code.contains("vprintf(format, args)"), "{code}");
    syntax::run_printed(
        &format!("#include <stdio.h>\n{code}"),
        "",
        "return printf_plt(\"%s:%d\", \"x\", 7) != 3;",
    );
}

#[test]
fn windows_stdcall_imports_preserve_printed_arguments() {
    let mut binary = Binary::open(&common::fixtures_dir().join("windows_types.pe32.dll")).unwrap();
    let address = binary.find("windows_file").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    assert!(code.contains("GetFileType("), "{code}");
    syntax::run_printed(
        &code,
        "uint32_t GetFileType(void *file) { return (uintptr_t)file + 3; }",
        "return windows_file(17) != 20 || windows_file(73) != 76;",
    );
}

#[test]
fn i386_absolute_jump_table_preserves_cases_and_values() {
    let mut binary = Binary::open(&common::fixtures_dir().join("i386_switch.elf")).unwrap();
    let address = binary.find("sw").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    assert!(code.contains("switch ("), "{code}");
    for (value, target) in (5..=10).zip(["a", "b", "c", "d", "e", "f"]) {
        let start = code.find(&format!("case {value}:")).expect("switch case");
        let body = &code[start..];
        let end = body[1..].find("case ").map_or(body.len(), |at| at + 1);
        assert!(body[..end].contains(&format!("{target}();")), "{code}");
    }
    assert!(code.contains("g = 0;"), "{code}");
    let mut definitions = Vec::new();
    for name in ["a", "b", "c", "d", "e", "f"] {
        let callee = binary.find(name).unwrap().addr;
        definitions.push(binary.decompile(callee, None, None).unwrap());
    }
    definitions.push(code);
    let code = velk::render::combine(&definitions.join("\n"));
    syntax::run_printed(
        &code,
        "uint32_t g;",
        "for (unsigned x=0;x<256;x++) for (unsigned initial=0;initial<128;initial++) {\n\
         g=initial; unsigned expected=0;\n\
         switch(x) {case 5:expected=initial+1;break;case 6:expected=initial*3;break;\n\
         case 7:expected=initial^7;break;case 8:expected=initial-9;break;\n\
         case 9:expected=initial<<1;break;case 10:expected=initial|5;break;}\n\
         if ((unsigned)sw(x)!=expected || g!=expected) return 1; }\n\
         g=17; if(sw(UINT32_MAX)!=0 || g!=0) return 1; return 0;",
    );
}

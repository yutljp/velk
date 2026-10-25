use super::*;

#[test]
fn i386_fixture_functions_match_reference_values() {
    let fixtures: Vec<_> = common::fixtures()
        .into_iter()
        .filter(|path| {
            let name = path.to_string_lossy();
            name.contains(".i386.") || name.contains(".win32.")
        })
        .collect();
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
    let fixtures: Vec<_> = common::fixtures()
        .into_iter()
        .filter(|path| {
            let name = path.to_string_lossy();
            name.contains(".i386.") || name.contains(".win32.")
        })
        .collect();
    syntax::scan(&fixtures, "i386-syntax");
}

#[test]
fn i386_calling_conventions_preserve_arguments_and_cleanup() {
    for opt in ["O0", "O2"] {
        for variant in ["debug", "stripped"] {
            let mut binary = Binary::open(
                &common::fixtures_dir()
                    .join(format!("metrics/conventions.win32.{opt}.{variant}.dll")),
            )
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
    for opt in ["O0", "O2"] {
        for variant in ["debug", "stripped"] {
            let mut binary = Binary::open(
                &common::fixtures_dir().join(format!("metrics/imports.win32.{opt}.{variant}.dll")),
            )
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
    for opt in ["O0", "O2"] {
        for variant in ["debug", "stripped"] {
            let mut binary = Binary::open(
                &common::fixtures_dir()
                    .join(format!("metrics/relocations.i386.{opt}.{variant}.elf")),
            )
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
    for opt in ["O0", "O2"] {
        for variant in ["debug", "stripped"] {
            let mut binary = Binary::open(
                &common::fixtures_dir()
                    .join(format!("metrics/relocations.i386.{opt}.{variant}.elf")),
            )
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
            {
                syntax::run_printed(
                    &code,
                    "",
                    &format!("return {function}(-17) != 20 || {thunk}(-17) != 17;"),
                );
            }
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

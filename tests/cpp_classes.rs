//! RTTI recovery and the C output for linked C++ fixtures.

mod common;

use std::collections::BTreeSet;
use std::fmt::Write;
use std::process::Command;

use velk::service::Binary;

const FORMATS: [&str; 3] = ["elf", "dll", "dylib"];

#[test]
fn stripped_classes_and_offsets_match_the_source() {
    let mut golden = String::new();
    for format in FORMATS {
        for variant in ["debug", "stripped"] {
            let path = common::fixtures_dir().join(format!("cpp/rtti.{variant}.{format}"));
            let binary = Binary::open(&path).unwrap();
            let classes = binary.image().classes();
            let names: BTreeSet<_> = classes.iter().map(|class| class.name.as_str()).collect();
            assert_eq!(
                names,
                BTreeSet::from(["Error", "Multiple", "Other", "Root", "Single", "Virtual"]),
                "{format} {variant}: {classes:?}"
            );
            let class = |name| classes.iter().find(|class| class.name == name).unwrap();
            assert_eq!(class("Single").bases[0].name, "Root");
            assert_eq!(class("Single").bases[0].offset, Some(0));
            let bases = &class("Multiple").bases;
            assert_eq!(bases.len(), 2);
            assert_eq!(
                (&bases[0].name, bases[0].offset),
                (&"Root".to_owned(), Some(0))
            );
            assert_eq!(
                (&bases[1].name, bases[1].offset),
                (&"Other".to_owned(), Some(16))
            );
            let base = &class("Virtual").bases[0];
            assert_eq!(base.name, "Root");
            assert!(base.is_virtual);
            if format == "dll" {
                let location = base.vbtable.as_ref().unwrap();
                assert_eq!(
                    (
                        location.pointer_offset,
                        location.entry_offset,
                        location.member_offset
                    ),
                    (0, 4, 0)
                );
                assert_eq!(base.offset, None);
                assert_eq!(
                    class("Virtual").vtables[0].construction_displacement,
                    Some(4)
                );
            } else {
                assert_eq!(base.offset, Some(16));
                assert_eq!(base.vtable_offset, Some(-24));
            }
            assert_eq!(
                class("Multiple")
                    .vtables
                    .iter()
                    .map(|table| table.offset)
                    .collect::<Vec<_>>(),
                vec![0, 16]
            );
            assert!(class("Error").vtables.is_empty());
            writeln!(golden, "{format} {variant}: correct=6 wrong=0 missed=0").unwrap();
            for class in classes {
                writeln!(
                    golden,
                    "{} at {:#x}: bases {:?}",
                    class.name,
                    class.type_info,
                    class
                        .bases
                        .iter()
                        .map(|base| (&base.name, base.offset, base.is_virtual))
                        .collect::<Vec<_>>()
                )
                .unwrap();
                for table in &class.vtables {
                    writeln!(
                        golden,
                        "  vtable {:#x} offset {}: {:?}",
                        table.address,
                        table.offset,
                        table
                            .methods
                            .iter()
                            .map(|method| (method.slot, method.address))
                            .collect::<Vec<_>>()
                    )
                    .unwrap();
                }
            }
            let output = Command::new(env!("CARGO_BIN_EXE_velk"))
                .args(["--classes"])
                .arg(&path)
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            let listed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(listed, serde_json::json!(classes));
        }
    }
    if let Some(difference) = common::check_expected(
        &common::root().join("tests/golden/cpp_classes.txt"),
        &golden,
    ) {
        panic!("{difference}");
    }
}

#[test]
fn typed_and_nested_catches_are_printed_in_debug_and_stripped_files() {
    let mut golden = String::new();
    for format in FORMATS {
        let mut named =
            Binary::open(&common::fixtures_dir().join(format!("cpp/rtti.debug.{format}"))).unwrap();
        let mut stripped =
            Binary::open(&common::fixtures_dir().join(format!("cpp/rtti.stripped.{format}")))
                .unwrap();
        for (name, types) in [
            ("catch_one", &["Error"][..]),
            ("catch_many", &["Error", "int", "..."][..]),
            ("catch_nested", &["Error", "int"][..]),
            ("catch_cleanup", &["..."][..]),
        ] {
            let address = named.find(name).unwrap().addr;
            for (variant, binary) in [("debug", &mut named), ("stripped", &mut stripped)] {
                let code = binary.decompile(address, None, None).unwrap();
                for name in types {
                    assert!(
                        code.contains(&format!("catch ({name}")),
                        "{format} {variant} {name}: {code}"
                    );
                }
                let regions = code.matches("/* try {").count();
                assert!(regions > 0, "{code}");
                writeln!(golden, "{format} {variant} {name}: regions={regions}").unwrap();
                for line in code.lines().filter(|line| {
                    line.contains("protected code")
                        || line.contains("catch (")
                        || line.contains("cleanup {")
                }) {
                    writeln!(golden, "{line}").unwrap();
                }
            }
        }
    }
    if let Some(difference) = common::check_expected(
        &common::root().join("tests/golden/cpp_exceptions.txt"),
        &golden,
    ) {
        panic!("{difference}");
    }
}

#[test]
fn every_cpp_fixture_function_compiles_as_c() {
    let mut failures = Vec::new();
    let mut checked = 0;
    for format in FORMATS {
        for variant in ["debug", "stripped"] {
            let path = common::fixtures_dir().join(format!("cpp/rtti.{variant}.{format}"));
            let mut binary = Binary::open(&path).unwrap();
            let addresses: Vec<_> = binary.image().functions.keys().copied().collect();
            for address in addresses {
                let code = match binary.decompile(address, None, None) {
                    Ok(code) => code,
                    Err(error) => {
                        failures.push(format!("{format} {variant} {address:#x}: {error}"));
                        continue;
                    }
                };
                let output = common::compiler::run(
                    Command::new("clang").args([
                        "-x",
                        "c",
                        "-std=c11",
                        "-fsyntax-only",
                        "-Werror=implicit-function-declaration",
                        "-",
                    ]),
                    Some(&code),
                );
                checked += 1;
                if !output.status.success() {
                    failures.push(format!(
                        "{format} {variant} {address:#x}: {}\n{code}",
                        String::from_utf8_lossy(&output.stderr)
                    ));
                }
            }
        }
    }
    assert!(checked > 100);
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn named_class_views_preserve_virtual_dispatch_and_base_offsets() {
    use velk::ir::{Expr, Stmt};

    let mut binary = Binary::open(&common::fixtures_dir().join("cpp/rtti.debug.elf")).unwrap();
    let address = binary.find("dispatch").unwrap().addr;
    let original = binary.analysis(address, None).unwrap().ir.clone();
    for name in ["Single", "Multiple"] {
        let mut ir = original.clone();
        ir.definitions.clear();
        let symbols = velk::render::callee_names(binary.image());
        let class = symbols
            .cpp_classes
            .iter()
            .find(|class| class.name == name)
            .unwrap();
        let candidate = class
            .vtables
            .iter()
            .find(|table| table.offset == 0)
            .unwrap()
            .methods[0]
            .address;
        let parameter = ir.params[0].index;
        for statement in ir.blocks.iter_mut().flat_map(|block| &mut block.stmts) {
            if let Stmt::Call {
                via: Some(via),
                args,
                through,
                ..
            } = statement
            {
                via.candidates = vec![candidate];
                *through = Some(Expr::Load {
                    addr: Box::new(Expr::Load {
                        addr: Box::new(Expr::reg(parameter, 64)),
                        width: 8,
                        signed: false,
                    }),
                    width: 8,
                    signed: false,
                });
                *args = Some(vec![Expr::reg(parameter, 64)]);
            }
        }
        let code = velk::render::render(&ir, &[], &symbols, &[]);
        assert!(code.contains(&format!("struct {name} {{")), "{code}");
        assert!(code.contains("base_Root"), "{code}");
        assert!(code.contains("->vtable->value("), "{code}");
        let mut source = code;
        writeln!(source, "\n#include <stddef.h>\n_Static_assert(offsetof(struct {name}, base_Root) == 0, \"primary base offset\");").unwrap();
        if name == "Multiple" {
            writeln!(source, "_Static_assert(offsetof(struct Multiple, base_Other) == 16, \"secondary base offset\");").unwrap();
        }
        source.push_str("\nstatic uint64_t method(uint64_t *object) { return object[1] + 7; }\nint main(void) { uint64_t table[] = {(uintptr_t)method}; uint64_t object[] = {(uintptr_t)table, 23, 0}; return dispatch((void *)object) != 30; }\n");
        let directory = common::root().join(format!("target/cpp-view-{name}"));
        std::fs::create_dir_all(&directory).unwrap();
        for opt in ["-O0", "-O2"] {
            let executable = directory.join(&opt[1..]);
            let output = common::compiler::run(
                Command::new("clang")
                    .args(["-x", "c", "-std=c11", opt, "-o"])
                    .arg(&executable)
                    .arg("-"),
                Some(&source),
            );
            assert!(
                output.status.success(),
                "{}\n{source}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(Command::new(&executable).status().unwrap().success());
        }
    }
}

#[test]
fn msvc_debug_ranges_keep_funclets_out_of_the_parent_body() {
    let mut debug = Binary::open(&common::fixtures_dir().join("cpp/rtti.debug.dll")).unwrap();
    let stripped = Binary::open(&common::fixtures_dir().join("cpp/rtti.stripped.dll")).unwrap();
    for name in ["single", "virtual_base", "catch_many", "catch_nested"] {
        let function = debug.find(name).unwrap();
        let address = function.addr;
        assert_eq!(function.size, stripped.find(name).unwrap().size, "{name}");
        let code = debug.decompile(address, None, None).unwrap();
        assert!(
            !code.contains("\nL_"),
            "detached funclet in {name}:\n{code}"
        );
    }
}

#[test]
fn rtti_discovers_pe_virtual_methods_without_symbols_or_unwind_frames() {
    let binary = Binary::open(&common::fixtures_dir().join("cpp/rtti.stripped.dll")).unwrap();
    let mut discovered = 0;
    for class in binary.image().classes() {
        for table in &class.vtables {
            for method in &table.methods {
                let function = binary.function(method.address).unwrap();
                if function.sources.contains(&velk::loader::NameSource::Rtti) {
                    discovered += 1;
                    assert!(function.name.is_none());
                }
            }
        }
    }
    assert!(discovered >= 5);
}

#[test]
fn msvc_virtual_base_thunks_forward_the_adjusted_object_in_printed_c() {
    use velk::ir::{CallKind, Stmt};

    let mut binary = Binary::open(&common::fixtures_dir().join("cpp/rtti.stripped.dll")).unwrap();
    let class = binary
        .image()
        .classes()
        .iter()
        .find(|class| class.name == "Virtual")
        .unwrap();
    let address = class.vtables[0].methods[0].address;
    let ir = &binary.analysis(address, None).unwrap().ir;
    let target = ir
        .blocks
        .iter()
        .flat_map(|block| &block.stmts)
        .find_map(|statement| {
            if let Stmt::Call {
                kind: CallKind::Tail,
                target: Some(target),
                args: Some(args),
                ..
            } = statement
            {
                assert_eq!(args.len(), 1);
                Some(*target)
            } else {
                None
            }
        })
        .expect("the adjustment thunk must end in an explicit tail call");
    let code = binary.decompile(address, None, None).unwrap();
    assert!(!code.contains("velk_jump_target"), "{code}");
    assert!(code.contains("a0[-1]"), "{code}");
    let mut source = String::from("#include <stdint.h>\nstatic uint32_t storage[32];\n");
    source.push_str(&code);
    writeln!(source, "\nuint64_t sub_{target:x}(uint8_t *object) {{ return (uintptr_t)object - (uintptr_t)storage; }}\nint main(void) {{ uint32_t *object = storage + 16; int32_t adjustments[] = {{-16, -8, 0, 8, 16}}; for (unsigned i = 0; i < 5; ++i) {{ object[-1] = (uint32_t)adjustments[i]; if (sub_{address:x}(object) != 64 - adjustments[i]) return 1; }} return 0; }}").unwrap();
    let directory = common::root().join("target/cpp-virtual-adjustment");
    std::fs::create_dir_all(&directory).unwrap();
    for opt in ["-O0", "-O2"] {
        let executable = directory.join(&opt[1..]);
        let output = common::compiler::run(
            Command::new("clang")
                .args(["-x", "c", "-std=c11", opt, "-o"])
                .arg(&executable)
                .arg("-"),
            Some(&source),
        );
        assert!(
            output.status.success(),
            "{}\n{source}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(Command::new(&executable).status().unwrap().success());
    }
}

#[test]
fn classes_and_offsets_use_the_32_bit_abi_in_debug_and_stripped_images() {
    for architecture in ["i386", "arm", "thumb", "x86"] {
        let format = if architecture == "x86" { "dll" } else { "elf" };
        for variant in ["debug", "stripped"] {
            let fixture = format!("tests/metadata/cpp32/rtti.{architecture}.{variant}.{format}");
            let path = common::root().join(&fixture);
            let mut binary = Binary::open(&path).unwrap();
            let classes = binary.image().classes();
            let names: BTreeSet<_> = classes.iter().map(|class| class.name.as_str()).collect();
            assert_eq!(
                names,
                BTreeSet::from(["Error", "Multiple", "Other", "Root", "Single", "Virtual"]),
                "{fixture}"
            );
            let class = |name| classes.iter().find(|class| class.name == name).unwrap();
            assert_eq!(class("Single").bases[0].name, "Root");
            assert_eq!(class("Single").bases[0].offset, Some(0));
            let multiple = class("Multiple");
            assert_eq!(
                multiple
                    .bases
                    .iter()
                    .map(|base| (base.name.as_str(), base.offset, base.is_virtual))
                    .collect::<Vec<_>>(),
                vec![("Root", Some(0), false), ("Other", Some(8), false)]
            );
            assert_eq!(
                multiple
                    .vtables
                    .iter()
                    .map(|table| table.offset)
                    .collect::<Vec<_>>(),
                vec![0, 8]
            );
            let base = &class("Virtual").bases[0];
            assert!(base.is_virtual && base.is_public);
            assert_eq!(base.name, "Root");
            if architecture == "x86" {
                let location = base.vbtable.as_ref().unwrap();
                assert_eq!(
                    (
                        location.pointer_offset,
                        location.entry_offset,
                        location.member_offset
                    ),
                    (0, 4, 0)
                );
                assert_eq!(base.offset, None);
                assert_eq!(
                    class("Virtual").vtables[0].construction_displacement,
                    Some(4)
                );
            } else {
                assert_eq!(base.offset, Some(8));
                assert_eq!(base.vtable_offset, Some(-12));
            }
            assert!(class("Error").vtables.is_empty());
            let root_method = class("Root").vtables[0].methods[0].address;
            let method_count = if architecture == "x86" { 2 } else { 3 };
            assert_eq!(class("Root").vtables[0].methods.len(), method_count);
            for class in classes {
                for table in &class.vtables {
                    for method in &table.methods {
                        assert!(
                            binary.function(method.address).is_ok(),
                            "{fixture} {method:?}"
                        );
                        if architecture == "thumb" {
                            assert_eq!(
                                binary.image().arm_mode(method.address),
                                velk::loader::ArmMode::Thumb
                            );
                        }
                    }
                }
            }
            let output = Command::new(env!("CARGO_BIN_EXE_velk"))
                .args(["--classes"])
                .arg(&path)
                .output()
                .unwrap();
            assert!(output.status.success());
            let listed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(listed, serde_json::json!(classes));
            let code = binary.decompile(root_method, None, None).unwrap();
            let output = common::compiler::run(
                Command::new("clang").args([
                    "-x",
                    "c",
                    "-std=c11",
                    "-fsyntax-only",
                    "-Werror=implicit-function-declaration",
                    "-",
                ]),
                Some(&code),
            );
            assert!(
                output.status.success(),
                "{fixture}: {}\n{code}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

#[test]
fn recovered_virtual_prototypes_preserve_full_register_results() {
    use velk::ir::{CType, Stmt};

    for format in ["elf", "dll"] {
        let mut binary =
            Binary::open(&common::fixtures_dir().join(format!("cpp/rtti.debug.{format}"))).unwrap();
        let address = binary.find("dispatch").unwrap().addr;
        let mut ir = binary.analysis(address, None).unwrap().ir.clone();
        let mut symbols = velk::render::callee_names(binary.image());
        let class = symbols
            .cpp_classes
            .iter()
            .find(|class| class.name == "Root")
            .unwrap();
        let target = class
            .vtables
            .iter()
            .find(|table| table.offset == 0)
            .unwrap()
            .methods[0]
            .address;
        assert!(symbols.cpp_signatures.contains_key(&target), "{format}");
        ir.ret_type = CType::U64;
        ir.definitions.clear();
        ir.params[0].ty = CType::pointer_to(CType::U64);
        for stmt in ir.blocks.iter_mut().flat_map(|block| &mut block.stmts) {
            if let Stmt::Call { via: Some(via), .. } = stmt {
                via.candidates = vec![target];
            }
        }
        let code = velk::render::render(&ir, &[], &symbols, &[]);
        assert!(code.contains("(*value)(void *)"), "{code}");
        assert!(code.contains("->vtable->value("), "{code}");
        let mut source = code;
        source.push_str(
            r#"
static int method(void *object) { return (int)((uint64_t *)object)[1]; }
int main(void) {
    uintptr_t table[] = {(uintptr_t)method};
    uint64_t object[] = {(uintptr_t)table, 0};
    uint32_t values[] = {0, 1, 0x7fffffff, 0x80000000, 0xfffffff9, 0xffffffff};
    for (unsigned i = 0; i < 6; ++i) {
        object[1] = values[i];
        if (dispatch((void *)object) != (uint64_t)values[i]) return 1;
    }
    return 0;
}
"#,
        );
        let directory = common::root().join(format!("target/cpp-virtual-prototype-{format}"));
        std::fs::create_dir_all(&directory).unwrap();
        for opt in ["-O0", "-O2"] {
            let executable = directory.join(&opt[1..]);
            let output = common::compiler::run(
                Command::new("clang")
                    .args(["-x", "c", "-std=c11", opt, "-o"])
                    .arg(&executable)
                    .arg("-"),
                Some(&source),
            );
            assert!(
                output.status.success(),
                "{}\n{source}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                Command::new(&executable).status().unwrap().success(),
                "{source}"
            );
        }
        symbols
            .cpp_signatures
            .get_mut(&target)
            .unwrap()
            .params
            .clear();
        let code = velk::render::render(&ir, &[], &symbols, &[]);
        assert!(code.contains("(*value)()"), "{code}");
    }
}

#[test]
fn virtual_call_targets_match_recovered_slots() {
    use velk::ir::{Stmt, Table};

    let mut fixtures = Vec::new();
    for format in FORMATS {
        for variant in ["debug", "stripped"] {
            fixtures.push(format!("cpp/rtti.{variant}.{format}"));
        }
    }
    for arch in ["x64", "a64"] {
        fixtures.push(format!("cpp_virtual_{arch}.elf"));
        fixtures.push(format!("cpp_virtual_{arch}_stripped.elf"));
    }
    let mut golden = String::new();
    for fixture in fixtures {
        let reference = Binary::open(
            &common::fixtures_dir().join(
                fixture
                    .replace(".stripped.", ".debug.")
                    .replace("_stripped", ""),
            ),
        )
        .unwrap();
        let mut tables: Vec<_> = reference
            .image()
            .classes()
            .iter()
            .flat_map(|class| &class.vtables)
            .map(|table| table.address)
            .collect();
        for (address, name) in &reference.image().data_symbols {
            if name.trim_start_matches('_').starts_with("ZTV") {
                tables.push(address.checked_add(16).unwrap());
            }
        }
        let mut binary = Binary::open(&common::fixtures_dir().join(&fixture)).unwrap();
        let addresses: Vec<_> = binary.image().functions.keys().copied().collect();
        let mut calls = 0;
        let mut direct = 0;
        let mut named = 0;
        let mut raw = 0;
        for address in addresses {
            let ir = binary.analysis(address, None).unwrap().ir.clone();
            for stmt in ir.blocks.iter().flat_map(|block| &block.stmts) {
                let Stmt::Call {
                    target,
                    via: Some(via),
                    ..
                } = stmt
                else {
                    continue;
                };
                if via.table != Table::Vtable {
                    continue;
                }
                calls += 1;
                direct += usize::from(target.is_some());
                for candidate in target.iter().chain(&via.candidates) {
                    assert!(
                        tables.iter().any(|table| {
                            let at = table.checked_add(via.slot.checked_mul(8).unwrap()).unwrap();
                            matches!(binary.image().read_pointer(at), Some(velk::loader::Pointer::Address(found)) if found == *candidate)
                        }),
                        "{fixture} {address:#x}: {via:?}"
                    );
                }
            }
            let code = binary.decompile(address, None, None).unwrap();
            for line in code.lines().filter(|line| line.contains("/* vtable slot")) {
                named += usize::from(line.contains("->"));
                raw += usize::from(line.contains("(*)())"));
            }
        }
        assert_eq!(calls, direct + named + raw, "{fixture}");
        writeln!(
            golden,
            "{fixture}: direct={direct} named={named} unresolved={raw}"
        )
        .unwrap();
    }
    if let Some(difference) = common::check_expected(
        &common::root().join("tests/golden/virtual_calls.txt"),
        &golden,
    ) {
        panic!("{difference}");
    }
}

#[test]
fn virtual_calls_match_in_cli_javascript_and_mcp() {
    use std::process::Stdio;

    use serde_json::Value;
    use serde_json::json;

    for format in ["elf", "dll"] {
        let path = common::fixtures_dir().join(format!("cpp/rtti.debug.{format}"));
        let mut binary = Binary::open(&path).unwrap();
        let address = binary.find("dispatch").unwrap().addr;
        let expected = binary.decompile(address, None, None).unwrap();
        assert!(expected.contains("->vtable->value("), "{expected}");
        let output = Command::new(env!("CARGO_BIN_EXE_velk"))
            .args(["--cache", "off", "-D"])
            .arg(&path)
            .arg("dispatch")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().trim(),
            expected.trim()
        );
        let script = format!(
            "JSON.stringify({{code:velk.open({path:?}).getFunction('dispatch').decompile()}})"
        );
        let outcome = velk::script::Engine::new().unwrap().run(&script, None);
        assert!(outcome.error.is_none(), "{:?}", outcome.error);
        let value: Value = serde_json::from_str(&outcome.output).unwrap();
        assert_eq!(value["code"], expected);
        let child = Command::new(env!("CARGO_BIN_EXE_velk"))
            .arg("--mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let output = common::mcp_request(
            child,
            &json!({
                "jsonrpc":"2.0", "id":1, "method":"tools/call",
                "params":{"name":"velk_run_script", "arguments":{"code":script}}
            }),
        );
        assert!(output.status.success(), "{output:?}");
        let response: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(response["result"]["isError"], false, "{response}");
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert_eq!(serde_json::from_str::<Value>(text).unwrap(), value);
    }
    for document in ["docs/CPP_CLASSES.md", "docs/CPP_CLASSES.ja.md"] {
        let text = std::fs::read_to_string(common::root().join(document)).unwrap();
        let command = text
            .lines()
            .find(|line| line.starts_with("velk -D "))
            .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_velk"))
            .args(command.split_whitespace().skip(1))
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("int (*other)(void *)")
        );
    }
}

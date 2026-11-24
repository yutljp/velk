mod common;

use std::fs;
use std::process::Command;

use velk::service::Binary;

#[test]
fn stripped_main_lookup_is_consistent_across_interfaces() {
    use std::io::Write as _;
    use std::process::Stdio;

    let directory = common::root().join("target/output-polish-errors");
    fs::create_dir_all(&directory).unwrap();
    let source = directory.join("input.c");
    fs::write(&source, "int main(void) { return 0; }\n").unwrap();
    let executable = directory.join("input");
    let output = Command::new("clang")
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let binary = Binary::open(&executable).unwrap();
    assert!(!binary.image().stripped);
    assert!(
        !binary
            .find("missing_function")
            .unwrap_err()
            .to_string()
            .contains("stripped")
    );
    assert!(
        Command::new("strip")
            .arg(&executable)
            .status()
            .unwrap()
            .success()
    );
    let binary = Binary::open(&executable).unwrap();
    assert!(binary.image().stripped);
    let address = binary.find("main").unwrap().addr;
    let address = format!("0x{address:x}");

    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("-D")
        .arg(&executable)
        .arg("main")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let code = String::from_utf8(output.stdout).unwrap();
    assert!(code.contains("int main(void)"), "{code}");
    let decompiled_source = directory.join("decompiled.c");
    fs::write(&decompiled_source, code).unwrap();
    let decompiled_executable = directory.join("decompiled");
    let output = Command::new("clang")
        .arg(&decompiled_source)
        .arg("-o")
        .arg(&decompiled_executable)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let original_status = Command::new(&executable).status().unwrap();
    let decompiled_status = Command::new(&decompiled_executable).status().unwrap();
    assert_eq!(decompiled_status.code(), original_status.code());

    let script = format!(
        "velk.open({path:?}).getFunction('main').addr",
        path = executable.display().to_string()
    );
    let outcome = velk::script::Engine::new().unwrap().run(&script, None);
    assert!(outcome.error.is_none(), "{:?}", outcome.error);
    assert_eq!(outcome.output.trim(), address);

    let request = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "velk_run_script", "arguments": {"code": script}}
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{request}").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let text = response["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains(&address), "{text}");

    let mut child = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(
        child.stdin.take().unwrap(),
        "{}",
        serde_json::json!({
            "id": 1,
            "code": format!("velk.open({path:?}).getFunction('main').addr", path = executable.display().to_string())
        })
    )
    .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["result"], address);
}

#[cfg(target_os = "macos")]
#[test]
fn string_arguments_recompile_with_apple_stack_varargs() {
    let directory = common::root().join("target/output-polish");
    fs::create_dir_all(&directory).unwrap();
    let source = directory.join("input.c");
    fs::write(
        &source,
        r#"
extern int snprintf(char *, unsigned long, const char *, ...);
extern char *strcpy(char *, const char *);
int format(char *dst, const char *text) {
    return snprintf(dst, 64, "value: %s %d %lld", text, -7, 1234567890123LL);
}
char *copy(char *dst) { return strcpy(dst, "copied"); }
int main(void) { return 0; }
"#,
    )
    .unwrap();
    let object = directory.join("input.o");
    let output = Command::new("clang")
        .args([
            "-target",
            "arm64-apple-macos11",
            "-O1",
            "-g",
            "-fno-builtin",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut binary = Binary::open(&object).unwrap();
    let mut functions = String::new();
    for name in ["format", "copy"] {
        let address = binary.find(name).unwrap().addr;
        let code = binary.decompile(address, None, None).unwrap();
        assert!(!code.contains("/* undefined */"), "{code}");
        assert!(!code.contains("(const char *)\""), "{code}");
        assert!(!code.contains("(char *)\""), "{code}");
        functions.push_str(&code);
    }
    let functions = velk::render::combine(&functions);
    let driver = format!(
        r#"
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
{functions}
int main(void) {{
    char actual[64], expected[64];
    const char *inputs[] = {{"", "auto", "never", "a%sb"}};
    for (unsigned i = 0; i < sizeof(inputs) / sizeof(inputs[0]); ++i) {{
        int a = format(actual, inputs[i]);
        int b = snprintf(expected, sizeof(expected), "value: %s %d %lld", inputs[i], -7, 1234567890123LL);
        if (a != b || strcmp(actual, expected)) return 1;
    }}
    if (copy(actual) != actual || strcmp(actual, "copied")) return 2;
    return 0;
}}
"#
    );
    fs::write(directory.join("printed.c"), &driver).unwrap();
    for optimization in ["-O0", "-O2"] {
        let executable = directory.join(format!("run{optimization}"));
        let output = common::compiler::run(
            Command::new("clang")
                .args([
                    optimization,
                    "-Werror=implicit-function-declaration",
                    "-x",
                    "c",
                    "-",
                ])
                .arg("-o")
                .arg(&executable),
            Some(&driver),
        );
        assert!(
            output.status.success(),
            "{}\n{driver}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            Command::new(&executable).status().unwrap().success(),
            "{driver}"
        );
    }
}

/// The code of the function `name` of the fixture `fixture`.
fn named_function(fixture: &str, name: &str) -> String {
    let mut binary = Binary::open(&common::fixtures_dir().join(fixture)).expect("a fixture");
    let address = binary
        .image()
        .functions
        .values()
        .find(|function| function.name.as_deref() == Some(name))
        .expect("a named function")
        .addr;
    binary
        .decompile(address, None, None)
        .expect("the function's code")
}

#[test]
fn go_results_types_and_returned_strings_read_by_name() {
    for fixture in ["go_probe_arm64", "go_probe_arm64_1_27"] {
        // Two values are members of one structure, on both sides.
        let callee = named_function(fixture, "main.divmod");
        assert!(
            callee.contains("struct velk_results2 { int64_t r0; int64_t r1; };")
                && callee.contains("struct velk_results2 main_divmod(int64_t a0, int64_t a1) {")
                && callee.contains("return (struct velk_results2){ "),
            "{fixture}: {callee}"
        );
        let caller = named_function(fixture, "main.main");
        assert!(
            caller.contains("struct velk_results2 main_divmod();")
                && caller.contains("results = main_divmod(7, 3);")
                && caller.contains("= results.r1;"),
            "{fixture}: {caller}"
        );
        assert!(
            !caller.contains("also returned by the call"),
            "{fixture}: {caller}"
        );
        // A string returned as a pointer and a length reads as its text.
        let returned = named_function(fixture, "runtime.debugCallCheck");
        assert!(
            returned.contains(
                "return (struct velk_results2){ (uintptr_t)\"executing on Go runtime stack\", 29 };"
            ),
            "{fixture}: {returned}"
        );
        // A type switch compares with the descriptor of the type.
        let switched = named_function(fixture, "runtime.preprintpanics.func1");
        assert!(
            switched.contains("== (uintptr_t)(&type_string)")
                && switched.contains("extern uint8_t type_string; /* address: 0x"),
            "{fixture}: {switched}"
        );
    }
    // A method no call names returns what the method table of its type
    // says: a string, in two registers.
    for fixture in ["go_probe_arm64", "go_probe_arm64_1_27", "go_stripped"] {
        let method = named_function(fixture, "runtime.errorString.Error");
        assert!(
            method.contains("struct velk_results2 runtime_errorString_Error("),
            "{fixture}: {method}"
        );
    }
    // A method that returns the string it is called on takes both of its
    // words as parameters.
    for fixture in ["go_probe_arm64", "go_probe_arm64_1_27"] {
        let method = named_function(fixture, "runtime.plainError.Error");
        assert!(
            method.contains(
                "struct velk_results2 runtime_plainError_Error(int64_t a0, int64_t a1) {"
            ) && method.contains("return (struct velk_results2){ a0, a1 };"),
            "{fixture}: {method}"
        );
    }
    // An interface table reads as its type and its interface.
    for (fixture, function, table) in [
        (
            "go_probe_arm64",
            "runtime.mapKeyError2",
            "itab_runtime_errorString_error",
        ),
        (
            "go_probe_arm64_1_27",
            "internal/runtime/maps.mapKeyError2",
            "itab_maps_unhashableTypeError_error",
        ),
    ] {
        let code = named_function(fixture, function);
        assert!(
            code.contains(&format!("return (uintptr_t)(&{table});"))
                && code.contains(&format!("extern uint8_t {table}; /* address: 0x")),
            "{fixture}: {code}"
        );
    }
}

/// A value of two words comes back in two registers under the System V
/// and AArch64 conventions, as a Rust slice does.
#[test]
fn a_value_returned_in_two_registers_is_a_structure_of_both() {
    for fixture in ["rust_demo", "rust_demo_arm64"] {
        let callee = named_function(
            fixture,
            "<gimli::read::abbrev::Attributes as core::ops::deref::Deref>::deref",
        );
        assert!(
            callee.contains("struct velk_results2 Attributes__deref(")
                && callee.contains("return (struct velk_results2){ "),
            "{fixture}: {callee}"
        );
        // A caller takes both members.
        let caller = named_function(
            fixture,
            "addr2line::function::name_entry::<gimli::read::endian_slice::EndianSlice<gimli::endianity::LittleEndian>>",
        );
        assert!(
            caller.contains("results = Attributes__deref(") && caller.contains("= results.r1;"),
            "{fixture}: {caller}"
        );
    }
    // Debug information made for line numbers alone names no type: the
    // function is not taken to return nothing.
    let code = named_function(
        "rust_demo",
        "<std::backtrace_rs::symbolize::gimli::elf::Object>::section",
    );
    assert!(
        code.contains("struct velk_results2 Object__section("),
        "{code}"
    );
}

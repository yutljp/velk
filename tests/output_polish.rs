#![cfg(target_os = "macos")]

mod common;

use std::fs;
use std::process::Command;

use velk::service::Binary;

#[test]
fn stripped_name_errors_include_entry_and_listing_hint() {
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
    let entry = binary.image().entry.unwrap();
    let message = binary.find("main").unwrap_err().to_string();
    assert!(message.contains("binary is stripped"), "{message}");
    assert!(message.contains(&format!("entry 0x{entry:x}")), "{message}");
    assert!(message.contains("--functions"), "{message}");
    assert_eq!(message.lines().count(), 1);

    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("-D")
        .arg(&executable)
        .arg("main")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        format!("error: {message}")
    );

    let script = format!(
        "(() => {{ try {{ velk.open({path:?}).getFunction('main'); }} catch (error) {{ return error.message; }} }})()",
        path = executable.display().to_string()
    );
    let outcome = velk::script::Engine::new().unwrap().run(&script, None);
    assert!(outcome.error.is_none(), "{:?}", outcome.error);
    assert_eq!(outcome.output.trim(), message);

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
    assert!(text.contains(&message), "{text}");
}

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

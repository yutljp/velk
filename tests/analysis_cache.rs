//! Persistence must preserve public results, including compiled C behavior.

mod common;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use velk::loader::OpenOptions;
use velk::service::{Binary, CacheLocation};

fn cache_test_directory(name: &str) -> PathBuf {
    let path = common::root()
        .join("target/analysis-cache-tests")
        .join(format!("{name}-{}", std::process::id()));
    fs::create_dir_all(&path).expect("cache test directory");
    path
}

fn options(path: &Path) -> OpenOptions {
    OpenOptions {
        cache: Some(CacheLocation::Path(path.to_owned())),
        ..OpenOptions::default()
    }
}

fn list_functions_cli(path: &Path, cache: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_velk"))
        .args(["--cache", cache, "--functions", "--json"])
        .arg(path)
        .output()
        .expect("running velk")
}

#[test]
fn cached_c_and_navigation_match_uncached_results_on_every_architecture() {
    let directory = cache_test_directory("architectures");
    for (name, fixture) in [
        ("x86_64", "../raw_fixtures/l0_arith_x64.nodebug.o"),
        ("i386", "metrics/l0_arith.i386.O2.stripped.elf"),
        ("aarch64", "../raw_fixtures/l0_arith_a64.nodebug.o"),
        ("arm32", "../raw_fixtures/l0_arith.arm.O2.nodebug.elf"),
        ("thumb", "../raw_fixtures/l0_arith.thumb.O2.nodebug.elf"),
    ] {
        let path = common::fixtures_dir().join(fixture);
        let cache = directory.join(format!("{name}.json"));
        let _ = fs::remove_file(&cache);
        let mut uncached = Binary::open_input(
            &path,
            None,
            &OpenOptions {
                cache: Some(CacheLocation::Enabled(false)),
                ..OpenOptions::default()
            },
        )
        .unwrap();
        let address = uncached.find("add3").unwrap().addr;
        let expected = uncached.decompile(address, None, None).unwrap();
        let functions = serde_json::to_value(uncached.functions()).unwrap();
        let navigation = serde_json::to_value(uncached.navigation(None).unwrap()).unwrap();
        for _ in 0..2 {
            let mut binary = Binary::open_input(&path, None, &options(&cache)).unwrap();
            assert_eq!(
                serde_json::to_value(binary.functions()).unwrap(),
                functions,
                "{name}"
            );
            assert_eq!(
                binary.decompile(address, None, None).unwrap(),
                expected,
                "{name}"
            );
            assert_eq!(
                serde_json::to_value(binary.navigation(None).unwrap()).unwrap(),
                navigation,
                "{name}"
            );
        }
        let bytes = fs::read(&cache).unwrap();
        let envelope: Value =
            serde_json::from_slice(bytes.split(|byte| *byte == b'\n').next().unwrap()).unwrap();
        let saved: Value = serde_json::from_str(envelope["payload"].as_str().unwrap()).unwrap();
        assert!(
            !saved["summaries"].as_object().unwrap().is_empty(),
            "{name}"
        );
        assert!(envelope["navigation"].is_string(), "{name}");
        for operation in ["--decompile", "--xrefs"] {
            let mut results = Vec::new();
            for selection in ["off", cache.to_str().unwrap()] {
                let result = Command::new(env!("CARGO_BIN_EXE_velk"))
                    .args([operation, "--cache", selection])
                    .arg(&path)
                    .arg(format!("0x{address:x}"))
                    .output()
                    .unwrap();
                assert!(result.status.success(), "{name}: {result:?}");
                results.push(result.stdout);
            }
            assert_eq!(results[0], results[1], "{name}: {operation}");
        }
        let source = format!(
            r#"#include <stdint.h>
{expected}
int main(void) {{
    uint32_t state = 1;
    uint32_t edge[] = {{0, 1, UINT32_MAX, 0x80000000u, 0x7fffffffu}};
    for (unsigned i = 0; i < 4096; ++i) {{
        state = state * 1664525u + 1013904223u;
        uint32_t a = i < 5 ? edge[i] : state, b = state ^ 0xdeadbeefu, c = state >> 3;
        if ((uint32_t)add3(a, b, c) != a + b + c) return 1;
    }}
    return 0;
}}
"#
        );
        let source_path = directory.join(format!("{name}.c"));
        let executable = directory.join(name);
        common::compiler::compile_file(
            Command::new("clang")
                .args(["-O2", "-Werror=implicit-function-declaration"])
                .arg(&source_path)
                .arg("-o")
                .arg(&executable),
            &source_path,
            &source,
        );
        assert!(
            Command::new(executable).status().unwrap().success(),
            "{name}"
        );
    }
}

#[test]
fn cli_handles_damage_parallel_writers_and_disabled_cache() {
    let directory = cache_test_directory("cli");
    let binary = directory.join("input.o");
    fs::copy(common::fixtures_dir().join("tail_calls.o"), &binary).unwrap();
    let path = directory.join("analysis.json");
    let path_text = path.to_str().unwrap();
    let expected = list_functions_cli(&binary, "off");
    assert!(expected.status.success(), "{expected:?}");
    for bytes in [
        b"{".as_slice(),
        b"{}",
        b"null",
        b"{\"payload\":\"partial\"}",
    ] {
        fs::write(&path, bytes).unwrap();
        let result = list_functions_cli(&binary, path_text);
        assert!(result.status.success(), "{result:?}");
        assert_eq!(result.stdout, expected.stdout);
        assert!(result.stderr.is_empty(), "{result:?}");
    }
    let mut children = Vec::new();
    fs::remove_file(&path).unwrap();
    for _ in 0..6 {
        children.push(
            Command::new(env!("CARGO_BIN_EXE_velk"))
                .args(["--cache", path_text, "--functions", "--json"])
                .arg(&binary)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
    }
    for child in children {
        let result = child.wait_with_output().unwrap();
        assert!(result.status.success(), "{result:?}");
        assert_eq!(result.stdout, expected.stdout);
        assert!(result.stderr.is_empty(), "{result:?}");
    }
    assert_eq!(
        list_functions_cli(&binary, path_text).stdout,
        expected.stdout
    );
    assert!(fs::read_dir(&directory).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")
    }));
    let disabled = directory.join("disabled.json");
    let result = Command::new(env!("CARGO_BIN_EXE_velk"))
        .env("VELK_CACHE", &disabled)
        .args(["--cache", "off", "--functions", "--json"])
        .arg(&binary)
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(!disabled.exists());
    let result = Command::new(env!("CARGO_BIN_EXE_velk"))
        .env("VELK_CACHE", &disabled)
        .args(["--functions", "--json"])
        .arg(&binary)
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(disabled.exists());
    assert_eq!(result.stdout, expected.stdout);
    let default_path = binary.with_file_name("input.o.velk-cache");
    let _ = fs::remove_file(&default_path);
    assert!(list_functions_cli(&binary, "off").status.success());
    assert!(!default_path.exists());
    let result = Command::new(env!("CARGO_BIN_EXE_velk"))
        .env_remove("VELK_CACHE")
        .arg("--functions")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(default_path.exists());
}

#[cfg(unix)]
#[test]
fn unwritable_destination_warns_once_and_preserves_output() {
    use std::os::unix::fs::PermissionsExt;
    let directory = cache_test_directory("permissions");
    let path = common::fixtures_dir().join("tail_calls.o");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o555)).unwrap();
    let result = list_functions_cli(&path, directory.join("cache.json").to_str().unwrap());
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(result.status.success(), "{result:?}");
    assert_eq!(result.stdout, list_functions_cli(&path, "off").stdout);
    let diagnostic = String::from_utf8(result.stderr).unwrap();
    assert_eq!(
        diagnostic.matches("analysis cache: cannot save").count(),
        1,
        "{diagnostic}"
    );
}

#[test]
fn javascript_and_mcp_use_the_same_cache_options() {
    let directory = cache_test_directory("interfaces");
    let path = common::fixtures_dir().join("tail_calls.o");
    let cache = directory.join("script.json");
    let code = format!(
        "const b = velk.open({}, {{cache:{}}}); b.getFunction('tail_one').decompile()",
        json!(path),
        json!(cache)
    );
    let script = directory.join("query.js");
    fs::write(&script, &code).unwrap();
    let javascript = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--run")
        .arg(&script)
        .output()
        .unwrap();
    assert!(javascript.status.success(), "{javascript:?}");
    assert!(cache.exists());
    let mut child = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let request = json!({"jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{"name":"velk_run_script", "arguments":{"code":code}}});
    writeln!(child.stdin.take().unwrap(), "{request}").unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success(), "{result:?}");
    assert!(result.stderr.is_empty(), "{result:?}");
    let response: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(
        response["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .trim(),
        std::str::from_utf8(&javascript.stdout).unwrap().trim()
    );
    fs::remove_file(&cache).unwrap();
    fs::write(
        &script,
        format!(
            "velk.open({}, {{cache:false}}).getFunction('tail_one').decompile()",
            json!(path)
        ),
    )
    .unwrap();
    let disabled = Command::new(env!("CARGO_BIN_EXE_velk"))
        .env("VELK_CACHE", &cache)
        .arg("--run")
        .arg(&script)
        .output()
        .unwrap();
    assert!(disabled.status.success(), "{disabled:?}");
    assert_eq!(disabled.stdout, javascript.stdout);
    assert!(!cache.exists());
}

#[test]
fn documentation_examples_run_with_the_documented_precedence() {
    let directory = cache_test_directory("documentation");
    let source_path = directory.join("app.c");
    common::compiler::compile_file(
        Command::new("clang")
            .arg("-c")
            .arg(&source_path)
            .arg("-o")
            .arg(directory.join("app.elf")),
        &source_path,
        "int main(void) { return 0; }\n",
    );
    let executable = env!("CARGO_BIN_EXE_velk");
    let docs = fs::read_to_string(common::root().join("docs/ANALYSIS_CACHE.md")).unwrap();
    let shell = docs
        .split("```sh\n")
        .nth(1)
        .unwrap()
        .split("```")
        .next()
        .unwrap();
    for line in shell.lines() {
        let line = line.replace("velk --", &format!("'{executable}' --"));
        let result = Command::new("sh")
            .args(["-lc", &line])
            .current_dir(&directory)
            .env_remove("VELK_CACHE")
            .output()
            .unwrap();
        assert!(result.status.success(), "{line}: {result:?}");
    }
    let javascript = docs
        .split("```js\n")
        .nth(1)
        .unwrap()
        .split("```")
        .next()
        .unwrap();
    fs::write(directory.join("example.js"), javascript).unwrap();
    let result = Command::new(executable)
        .args(["--run", "example.js"])
        .current_dir(&directory)
        .output()
        .unwrap();
    assert!(result.status.success(), "{result:?}");
}

#[test]
fn cached_metadata_preserves_entries_classes_and_exception_information() {
    let directory = cache_test_directory("formats");
    for fixture in [
        "arm64_macho.o",
        "pe64.exe",
        "cpp/rtti.stripped.dylib",
        "cpp/rtti.stripped.dll",
        "cpp/rtti.stripped.elf",
        "seh_cpp.O2.dll",
    ] {
        let path = common::fixtures_dir().join(fixture);
        let cache = directory.join(fixture.replace('/', "-"));
        let _ = fs::remove_file(&cache);
        let baseline = Binary::open_input(
            &path,
            None,
            &OpenOptions {
                cache: Some(CacheLocation::Enabled(false)),
                ..OpenOptions::default()
            },
        )
        .unwrap();
        let expected = json!({"entry":baseline.image().entry,"functions":baseline.functions(),"classes":baseline.image().classes()});
        for _ in 0..2 {
            let cached = Binary::open_input(&path, None, &options(&cache)).unwrap();
            assert_eq!(
                json!({"entry":cached.image().entry,"functions":cached.functions(),"classes":cached.image().classes()}),
                expected,
                "{fixture}"
            );
        }
    }
}

#[test]
fn project_changes_rebuild_function_lists_and_reference_names() {
    use sha2::{Digest, Sha256};
    let directory = cache_test_directory("annotations");
    let path = directory.join("input.o");
    fs::copy(common::fixtures_dir().join("tail_calls.o"), &path).unwrap();
    let project_path = directory.join("project.json");
    let cache_path = directory.join("analysis.cache");
    let cached = options(&cache_path);
    let disabled = OpenOptions {
        cache: Some(CacheLocation::Enabled(false)),
        ..OpenOptions::default()
    };
    let mut binary = Binary::open_input(&path, Some(&project_path), &cached).unwrap();
    let address = binary.find("tail_one").unwrap().addr;
    binary.navigation(None).unwrap();
    drop(binary);
    let hash = format!("{:x}", Sha256::digest(fs::read(&path).unwrap()));
    for annotation in [
        json!({"target":{"kind":"function","address":format!("0x{address:x}")},"name":"renamed_function"}),
        json!({"target":{"kind":"classification","address":format!("0x{address:x}")},"text":"data"}),
    ] {
        fs::write(
            &project_path,
            serde_json::to_vec(
                &json!({"version":1,"binary_sha256":hash,"annotations":[annotation]}),
            )
            .unwrap(),
        )
        .unwrap();
        let mut baseline = Binary::open_input(&path, Some(&project_path), &disabled).unwrap();
        let functions = serde_json::to_value(baseline.functions()).unwrap();
        let xrefs = serde_json::to_value(baseline.navigation(None).unwrap()).unwrap();
        for _ in 0..2 {
            let mut binary = Binary::open_input(&path, Some(&project_path), &cached).unwrap();
            assert_eq!(serde_json::to_value(binary.functions()).unwrap(), functions);
            assert_eq!(
                serde_json::to_value(binary.navigation(None).unwrap()).unwrap(),
                xrefs
            );
        }
    }
}

#[test]
fn mcp_tools_forward_explicit_cache_selection() {
    let directory = cache_test_directory("mcp-tools");
    let path = common::fixtures_dir().join("tail_calls.o");
    let disabled = directory.join("disabled.cache");
    let mut child = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--mcp")
        .env("VELK_CACHE", &disabled)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    for (index, name) in ["velk_classes", "velk_emulate"].into_iter().enumerate() {
        let cache = directory.join(format!("{index}.cache"));
        let mut arguments = json!({"path":path,"cache":cache});
        if name == "velk_emulate" {
            arguments["start"] = json!("tail_one");
            arguments["options"] = json!({"arguments":[5]});
        }
        let request = json!({"jsonrpc":"2.0","id":index,"method":"tools/call","params":{"name":name,"arguments":arguments}});
        writeln!(input, "{request}").unwrap();
    }
    let request = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"velk_classes","arguments":{"path":path,"cache":false}}});
    writeln!(input, "{request}").unwrap();
    drop(input);
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success(), "{result:?}");
    assert!(result.stderr.is_empty(), "{result:?}");
    let output = std::str::from_utf8(&result.stdout).unwrap();
    for response in output.lines() {
        let response: Value = serde_json::from_str(response).unwrap();
        assert_eq!(response["result"]["isError"], false, "{response}");
    }
    assert_eq!(output.lines().count(), 3);
    for index in 0..2 {
        assert!(directory.join(format!("{index}.cache")).exists());
    }
    assert!(!disabled.exists());
}

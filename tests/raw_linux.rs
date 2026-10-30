//! Linux assembly instructions through rendering and execution interfaces.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use serde_json::{Value, json};
use velk::emulation;
use velk::service::Binary;
use velk::symbolic;

fn fixtures() -> &'static Path {
    static DIRECTORY: OnceLock<PathBuf> = OnceLock::new();
    DIRECTORY.get_or_init(|| {
        let out = common::root()
            .join("target/raw-linux-tests")
            .join(std::process::id().to_string());
        let result = Command::new("bash")
            .arg(common::root().join("tests/scripts/make_raw_linux_fixtures.sh"))
            .arg(&out)
            .output()
            .expect("fixture build starts");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        out
    })
}

#[test]
fn linux_syscalls_capture_short_reads_writes_exit_and_unknown_numbers() {
    for arch in ["x86_64", "i386", "aarch64"] {
        let mut binary = Binary::open(&fixtures().join(format!("{arch}.elf"))).expect("ELF opens");
        for input in ["", "a", "abcd", "abcdef"] {
            let options =
                serde_json::from_value(json!({"stdin": {"text": input}})).expect("I/O options");
            let report =
                emulation::run(&binary, "io_entry", &options, None).expect("emulation starts");
            assert_eq!(report.reason, "return", "{arch}: {:?}", report.error);
            assert_eq!(report.stdout, &input[..input.len().min(4)]);
        }
        for name in ["terminate", "terminate_group"] {
            let report =
                emulation::run(&binary, name, &Default::default(), None).expect("emulation starts");
            assert_eq!(report.reason, "exit", "{arch}: {:?}", report.error);
        }
        let report = emulation::run(&binary, "unknown", &Default::default(), None)
            .expect("emulation starts");
        assert!(
            report
                .error
                .as_deref()
                .is_some_and(|error| error.contains("unsupported Linux syscall 9999")),
            "{arch}: {report:?}"
        );
        let address = binary.find("io_entry").expect("entry exists").addr;
        let code = binary
            .decompile(address, None, None)
            .expect("entry renders");
        assert!(
            code.contains("linux_read(") && code.contains("linux_write("),
            "{arch}: {code}"
        );
        assert!(!code.contains("unsupported"), "{arch}: {code}");
        let source = fixtures().join(format!("{arch}-rendered.c"));
        std::fs::write(&source, &code).expect("rendered source writes");
        let output = Command::new("clang")
            .args([
                "-std=c17",
                "-Werror=implicit-function-declaration",
                "-fsyntax-only",
            ])
            .arg(&source)
            .output()
            .expect("rendered C compiler starts");
        assert!(
            output.status.success(),
            "{arch}: {}\n{code}",
            String::from_utf8_lossy(&output.stderr)
        );
        let options = serde_json::from_value(json!({"stdin": 4, "returns": {"eq": 4}}))
            .expect("symbolic I/O options");
        let report = symbolic::explore(&binary, "io_entry", &options).expect("symbolic I/O starts");
        assert!(
            report.found,
            "{arch}: {} {:?}",
            report.reason, report.diagnostics
        );
        let inputs = report.inputs.expect("symbolic input exists");
        assert_eq!(inputs.stdout, inputs.stdin, "{arch}");
        if arch == "i386" {
            let options = serde_json::from_value(json!({"stdin": 4, "returns": {"eq": 4}}))
                .expect("nested syscall options");
            let report =
                symbolic::explore(&binary, "nested", &options).expect("nested syscall exploration");
            assert!(report.found, "{} {:?}", report.reason, report.diagnostics);
        }
        for name in ["terminate", "terminate_group", "unknown"] {
            let mut state = symbolic::State::new(&binary, name, &Default::default())
                .expect("symbolic state starts");
            match state.step(&binary, &[]) {
                Ok(symbolic::Step::Stopped(reason)) if name != "unknown" => {
                    assert_eq!(reason, "exit")
                }
                Ok(symbolic::Step::Stopped(reason)) if name == "unknown" => {
                    assert!(
                        reason.contains("unsupported Linux syscall 9999"),
                        "{reason}"
                    );
                }
                Err(error) if name == "unknown" => {
                    assert!(error.to_string().contains("unsupported Linux syscall 9999"))
                }
                _ => panic!("unexpected syscall outcome for {arch} {name}"),
            }
        }
    }
}

#[test]
fn raw_assembly_discovers_call_only_helper_and_explores_stdin() {
    let path = fixtures().join("raw.elf");
    let mut binary = Binary::open(&path).expect("assembly ELF opens");
    let frame = binary
        .find("frame_dummy")
        .expect("frame symbol exists")
        .clone();
    let helper = binary
        .image()
        .functions
        .values()
        .find(|function| {
            function.addr > frame.addr && function.addr < frame.addr + frame.size.unwrap()
        })
        .expect("call-only helper is discovered")
        .addr;
    let helper_code = binary
        .decompile(helper, None, None)
        .expect("helper renders");
    assert!(!helper_code.contains("unsupported"), "{helper_code}");
    assert!(
        helper_code.contains("a0") && helper_code.contains("a3"),
        "{helper_code}"
    );
    let framed = binary
        .image()
        .functions
        .values()
        .find(|function| function.addr > helper && function.addr < frame.addr + frame.size.unwrap())
        .expect("framed call target is discovered")
        .addr;
    let params = &binary
        .analysis(framed, None)
        .expect("framed helper analyzes")
        .ir
        .params;
    assert_eq!(
        params.len(),
        1,
        "saved registers are not arguments: {params:?}"
    );
    assert_eq!(params[0].index, 0, "the helper reads rax");
    let main = binary.find("main").expect("main exists").addr;
    let code = binary.decompile(main, None, None).expect("main renders");
    assert!(code.contains("linux_read("), "{code}");
    assert!(code.contains("__builtin_memset"), "{code}");
    assert!(!code.contains("unsupported"), "{code}");
    let options =
        serde_json::from_value(json!({"stdin": {"text": "swordfish"}, "stepLimit": 200000}))
            .expect("I/O options");
    let report = emulation::run(&binary, "main", &options, None).expect("emulation starts");
    assert_eq!(report.stdout, "success\n", "{report:?}");
    let success = binary.find("success").expect("success exists").addr;
    let failure = binary.find("failure").expect("failure exists").addr;
    let setup = json!({"stdin": 9, "find": [format!("0x{success:x}")], "avoid": [format!("0x{failure:x}")], "stepLimit": 200000, "pathLimit": 4096});
    let options = serde_json::from_value(setup.clone()).expect("symbolic options");
    let report = symbolic::explore(&binary, "main", &options).expect("exploration starts");
    assert!(report.found, "{} {:?}", report.reason, report.diagnostics);
    let inputs = report.inputs.expect("found input");
    assert_eq!(inputs.stdin, b"swordfish");
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .args(["--explore", "main", "--json", "--symbolic-options"])
        .arg(setup.to_string())
        .arg("--find")
        .arg(format!("0x{success:x}"))
        .arg(&path)
        .output()
        .expect("exploration CLI starts");
    assert!(output.status.success(), "{output:?}");
    let cli: Value = serde_json::from_slice(&output.stdout).expect("exploration JSON");
    assert_eq!(cli["inputs"]["stdin"], json!(b"swordfish"));
    let engine = velk::script::Engine::new().expect("JavaScript engine starts");
    let outcome = engine.run(
        &format!("velk.open({}).explore('main', {setup})", json!(path)),
        None,
    );
    assert!(outcome.error.is_none(), "{:?}", outcome.error);
    assert_eq!(
        serde_json::from_str::<Value>(&outcome.output).expect("JavaScript exploration JSON"),
        cli
    );
    let child = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--mcp")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("exploration MCP starts");
    let output = common::mcp_request(
        child,
        &json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"velk_explore","arguments":{"path":path,"start":"main","options":setup}}}),
    );
    let response: Value = serde_json::from_slice(&output.stdout).expect("exploration MCP JSON");
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert_eq!(
        serde_json::from_str::<Value>(
            response["result"]["content"][0]["text"]
                .as_str()
                .expect("exploration report")
        )
        .expect("exploration report JSON"),
        cli
    );
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        use std::io::Write;
        use std::process::Stdio;
        let mut child = Command::new(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("native process starts");
        child
            .stdin
            .take()
            .expect("native stdin")
            .write_all(&inputs.stdin)
            .expect("input replays");
        let output = child.wait_with_output().expect("native process exits");
        assert!(output.status.success());
        assert_eq!(output.stdout, b"success\n");
    }
}

#[test]
fn raw_syscall_interfaces_capture_the_same_output() {
    use std::process::Stdio;
    let engine = velk::script::Engine::new().expect("JavaScript engine starts");
    for arch in ["x86_64", "i386", "aarch64"] {
        let path = fixtures().join(format!("{arch}.elf"));
        for start in ["io_entry", "terminate", "terminate_group"] {
            let options = json!({"stdin": {"text": "abcd"}});
            let output = Command::new(env!("CARGO_BIN_EXE_velk"))
                .args(["--emulate", "--json"])
                .arg(&path)
                .arg(start)
                .arg("--emulation-options")
                .arg(options.to_string())
                .output()
                .expect("CLI starts");
            assert!(output.status.success(), "{output:?}");
            let cli: Value = serde_json::from_slice(&output.stdout).expect("CLI JSON");
            assert_eq!(cli["stdout"], if start == "io_entry" { "abcd" } else { "" });
            let script = format!(
                "velk.open({}).getFunction('{start}').emulate({options})",
                json!(path)
            );
            let result = engine.run(&script, None);
            assert!(result.error.is_none(), "{:?}", result.error);
            assert_eq!(
                serde_json::from_str::<Value>(&result.output).expect("JavaScript JSON"),
                cli
            );
            let child = Command::new(env!("CARGO_BIN_EXE_velk"))
                .arg("--mcp")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .expect("MCP starts");
            let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"velk_emulate","arguments":{"path":path,"start":start,"options":options}}});
            let output = common::mcp_request(child, &request);
            let response: Value = serde_json::from_slice(&output.stdout).expect("MCP JSON");
            assert_eq!(response["result"]["isError"], false, "{response}");
            assert_eq!(
                serde_json::from_str::<Value>(
                    response["result"]["content"][0]["text"]
                        .as_str()
                        .expect("MCP report")
                )
                .expect("report JSON"),
                cli
            );
        }
    }
}

#[test]
#[cfg_attr(
    not(any(target_arch = "x86_64", target_os = "macos")),
    ignore = "requires native or translated x86-64 execution"
)]
fn printed_string_instructions_match_assembly_memory_flags_and_counts() {
    use std::fmt::Write as _;
    let mut binary = Binary::open(&fixtures().join("strings.elf")).expect("string fixture opens");
    let mut source = String::from("#include <stdint.h>\n#include <string.h>\n#include <stdio.h>\n");
    let mut checks = String::new();
    let functions: Vec<_> = binary
        .image()
        .functions
        .values()
        .filter_map(|function| {
            function
                .name
                .as_deref()
                .map(|name| (function.addr, name.to_owned()))
        })
        .collect();
    for (address, name) in functions {
        let code = binary
            .decompile(address, None, None)
            .expect("string operation renders");
        assert!(!code.contains("unsupported"), "{code}");
        let ir = &binary.analysis(address, None).expect("string analysis").ir;
        let first = ir.params[0].ty.to_string();
        let second = ir.params[1].ty.to_string();
        let renamed = code.replace(&format!("{name}("), &format!("{name}_c("));
        source.push_str(&renamed);
        writeln!(source, "extern uint64_t {name}(void *, void *, uint64_t);")
            .expect("native declaration");
        writeln!(checks, r#"
        for (unsigned seed = 0; seed < 16; seed++) {{
            for (unsigned count = 0; count <= 3; count++) {{
                unsigned char a[128], b[128], c[128], d[128];
                for (unsigned i = 0; i < 128; i++) {{
                    a[i] = c[i] = (unsigned char)(seed * 17 + i);
                    b[i] = d[i] = (unsigned char)(seed % 2 ? seed * 17 + i : i * 3);
                }}
                uint64_t expected = {name}(a + 64, b + 64, count);
                uint64_t actual = {name}_c(({first})(uintptr_t)(c + 64), ({second})(uintptr_t)(d + 64), count);
                if (actual != expected || memcmp(a, c, 128) || memcmp(b, d, 128)) {{
                    fprintf(stderr, "{name} seed=%u count=%u expected=%llu actual=%llu\n", seed, count, (unsigned long long)expected, (unsigned long long)actual);
                    return 1;
                }}
            }}
        }}
        "#).expect("native comparison");
    }
    writeln!(source, "int main(void) {{ {checks} return 0; }}").expect("comparison main");
    let path = fixtures().join("strings-rendered.c");
    std::fs::write(&path, source).expect("comparison source writes");
    let program = fixtures().join("strings-rendered");
    let mut compiler = Command::new("clang");
    if cfg!(target_os = "macos") {
        compiler.args(["-arch", "x86_64"]);
    }
    let output = compiler
        .args(["-std=c17", "-O1", "-Werror=implicit-function-declaration"])
        .arg(&path)
        .arg(fixtures().join("strings.S"))
        .arg("-o")
        .arg(&program)
        .output()
        .expect("comparison compiler starts");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(&program)
        .output()
        .expect("native comparison starts");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

mod common;

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use velk::service::Binary;

fn listing(path: &str, function: &str) -> Vec<velk::disasm::DisassemblyLine> {
    let binary = Binary::open(&common::fixtures_dir().join(path)).expect("open fixture");
    let address = binary.find(function).expect("find function").addr;
    binary.disasm(address, 64).expect("disassemble function")
}

fn has_comment(lines: &[velk::disasm::DisassemblyLine], comment: &str) -> bool {
    lines
        .iter()
        .any(|line| line.comment.as_deref() == Some(comment))
}

#[test]
fn adds_comments_for_elf_pe_macho_and_arm32_targets() {
    let x86_64 = listing("metrics/strings.x86_64.O2.debug.elf", "pick");
    assert!(has_comment(&x86_64, "kName"), "{x86_64:?}");

    let aarch64 = listing("strings.o", "pick");
    assert!(has_comment(&aarch64, "kName"), "{aarch64:?}");

    let i386_elf = listing("metrics/relocations.i386.O2.debug.elf", "via_plt");
    assert!(has_comment(&i386_elf, "add_bias"), "{i386_elf:?}");

    let aarch64_elf = listing("metrics/calls.aarch64.O2.debug.elf", "factorial");
    assert!(
        has_comment(&aarch64_elf, "factorial+0x10"),
        "{aarch64_elf:?}"
    );

    let i386_pe = listing("crt_windows.i686.exe", "crt_string");
    assert!(has_comment(&i386_pe, "strchr"), "{i386_pe:?}");

    let x86_64_pe = listing("crt_windows.x86_64.exe", "crt_string");
    assert!(has_comment(&x86_64_pe, "strchr"), "{x86_64_pe:?}");

    let aarch64_macho = listing("cpp/rtti.debug.dylib", "_single");
    assert!(
        has_comment(&aarch64_macho, "Single::Single(int)"),
        "{aarch64_macho:?}"
    );
    assert!(
        has_comment(&aarch64_macho, "__Unwind_Resume"),
        "{aarch64_macho:?}"
    );

    let aarch64_macho = listing("arm64_macho.o", "_helper");
    let branch = aarch64_macho
        .iter()
        .find(|line| line.instruction.starts_with("b."))
        .expect("Mach-O branch instruction");
    assert_eq!(branch.comment, None);
}

#[test]
fn command_json_has_a_comment_field_and_text_comments_align() {
    let fixture = common::fixtures_dir().join("crt_windows.x86_64.exe");
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .args(["--disasm"])
        .arg(&fixture)
        .args(["crt_string", "--json"])
        .output()
        .expect("run JSON disassembly");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines: Vec<Value> = serde_json::from_slice(&output.stdout).expect("JSON listing");
    assert!(lines.iter().all(|line| line.get("comment").is_some()));
    assert!(lines.iter().any(|line| line["comment"] == "strchr"));

    let fixture = common::fixtures_dir().join("go_probe");
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .args(["--disasm"])
        .arg(&fixture)
        .args(["main.main", "--limit", "40"])
        .output()
        .expect("run text disassembly");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    let comment_columns: Vec<_> = text.lines().filter_map(|line| line.find(" ; ")).collect();
    assert!(comment_columns.len() > 1);
    assert!(
        comment_columns
            .iter()
            .all(|column| *column == comment_columns[0])
    );
}

#[test]
fn javascript_mcp_and_serve_return_the_same_instruction_comments() {
    let fixture = common::fixtures_dir().join("crt_windows.x86_64.exe");
    let code = format!(
        "const b=velk.open({:?}); JSON.stringify(b.getFunction('crt_string').disasm())",
        fixture.to_string_lossy()
    );

    let mcp = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start MCP server");
    let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{"name":"velk_run_script","arguments":{"code":code}}});
    let output = common::mcp_request(mcp, &request);
    assert!(output.status.success());
    let response: Value = serde_json::from_slice(&output.stdout).expect("MCP response");
    let mcp_lines: Value = serde_json::from_str(
        response["result"]["content"][0]["text"]
            .as_str()
            .expect("MCP script result"),
    )
    .expect("MCP instruction records");

    let mut serve = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start script server");
    let mut input = serve.stdin.take().expect("script server input");
    let mut output = BufReader::new(serve.stdout.take().expect("script server output"));
    writeln!(input, "{}", json!({"id":1,"code":code})).expect("send script request");
    input.flush().expect("flush script request");
    let mut response = String::new();
    output
        .read_line(&mut response)
        .expect("read script response");
    let response: Value = serde_json::from_str(&response).expect("script server response");
    let serve_lines: Value =
        serde_json::from_str(response["result"].as_str().expect("script result"))
            .expect("script instruction records");
    drop(input);
    assert!(serve.wait().expect("script server exit").success());
    assert_eq!(mcp_lines, serve_lines);
    assert!(
        mcp_lines
            .as_array()
            .is_some_and(|lines| lines.iter().all(|line| line.get("comment").is_some()))
    );
}

#[test]
fn arm32_fixture_uses_a_literal_pool_pointer_to_find_the_string() {
    let path = common::fixtures_dir().join("arm32/strings.arm.O2.elf");
    let lines = listing_path(&path, "pick");
    assert!(has_comment(&lines, "\"velk-aarch64-string\""), "{lines:?}");
}

fn listing_path(path: &Path, function: &str) -> Vec<velk::disasm::DisassemblyLine> {
    let binary = Binary::open(path).expect("open fixture");
    let address = binary.find(function).expect("find function").addr;
    binary.disasm(address, 16).expect("disassemble function")
}

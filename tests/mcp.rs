//! Exercises the public stdio protocol as an MCP client.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

fn exchange(requests: &[Value]) -> Vec<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the MCP server starts");
    let mut stdin = child.stdin.take().expect("piped input");
    for request in requests {
        writeln!(stdin, "{request}").expect("the request is written");
    }
    drop(stdin);
    let output = child.wait_with_output().expect("the MCP server exits");
    assert!(output.status.success(), "{:?}", output);
    assert!(output.stderr.is_empty(), "{:?}", output);
    String::from_utf8(output.stdout)
        .expect("UTF-8 responses")
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSON-RPC response"))
        .collect()
}

fn tool(id: usize, name: &str, arguments: Value) -> Value {
    json!({"jsonrpc":"2.0", "id":id, "method":"tools/call",
        "params":{"name":name, "arguments":arguments}})
}

fn script(id: usize, code: &str) -> Value {
    tool(id, "velk_run_script", json!({"code":code}))
}

fn text(response: &Value) -> &str {
    response["result"]["content"][0]["text"]
        .as_str()
        .expect("a text tool result")
}

#[test]
fn discovery_and_fresh_scripts_work_over_stdio() {
    let path = common::fixtures_dir().join("arm64.o");
    let responses = exchange(&[
        json!({"jsonrpc":"2.0", "id":0, "method":"initialize",
            "params":{"protocolVersion":"2024-11-05"}}),
        json!({"jsonrpc":"2.0", "method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0", "id":1, "method":"tools/list"}),
        tool(2, "velk_read_api", json!({})),
        tool(3, "velk_read_api", json!({"topic":"binary"})),
        script(
            4,
            &format!("const b=velk.open({path:?}); b.getFunction('sum3').decompile()"),
        ),
        script(5, "typeof b"),
    ]);
    assert_eq!(responses.len(), 6, "notifications have no response");
    assert_eq!(responses[0]["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(responses[1]["result"]["tools"].as_array().unwrap().len(), 2);
    assert!(text(&responses[2]).contains("fresh context"));
    assert!(text(&responses[3]).contains("interface Binary"));
    let mut binary = velk::service::Binary::open(&path).unwrap();
    let addr = binary.find("sum3").unwrap().addr;
    assert_eq!(
        text(&responses[4]),
        binary.decompile(addr, None, None).unwrap()
    );
    assert_eq!(text(&responses[5]), "undefined");
}

#[test]
fn errors_are_actionable_and_the_server_recovers() {
    let path = common::fixtures_dir().join("arm64.o");
    let prefix = format!("const b=velk.open({path:?}); ");
    let run = |id, code| script(id, &format!("{prefix}{code}"));
    let responses = exchange(&[
        run(0, "b.getFunction('sum33')"),
        run(1, "b.getFunction('0xffffffffffffffff')"),
        run(2, "b.getFunction('*').decompile()"),
        script(
            3,
            &format!("velk.open({:?})", common::root().join("Cargo.toml")),
        ),
        script(4, "function fail(){throw new Error('broken')} fail()"),
        tool(
            5,
            "velk_run_script",
            json!({"code":"while(true){}", "timeout_ms":5}),
        ),
        script(6, "({answer:42})"),
        tool(7, "velk_read_api", json!({"topic":"x".repeat(30_000)})),
    ]);
    for (index, response) in responses.iter().enumerate() {
        assert_eq!(response["id"], index);
        assert_eq!(response["result"]["isError"], index != 6, "{response}");
        assert!(!text(response).contains("at <eval>"), "{response}");
        assert!(text(response).chars().count() <= 4_000, "{response}");
    }
    assert!(text(&responses[0]).contains("sum3 (0x0)"));
    assert!(text(&responses[1]).contains("exact function start"));
    assert!(text(&responses[2]).contains("slice(0, 5)"));
    assert!(text(&responses[3]).contains("expected an ELF, PE/COFF or Mach-O file"));
    assert_eq!(text(&responses[4]), "error: Error: broken");
    assert!(text(&responses[5]).contains("increase timeout_ms"));
    assert_eq!(text(&responses[6]), "{\"answer\":42}");
}

#[test]
fn large_results_are_bounded_and_slices_retrieve_the_rest() {
    let path = common::fixtures_dir().join("arm64.o");
    let code = format!(
        "const b=velk.open({path:?}); for(const f of b.functions()) console.log(f.decompile())"
    );
    let responses = exchange(&[
        script(0, "'あ🦀'.repeat(20000)"),
        tool(
            1,
            "velk_run_script",
            json!({"code":code, "max_output_chars":256}),
        ),
        script(
            2,
            &format!(
                "velk.open({path:?}).getFunction('sum_arr').decompile().split('\\n').slice(0,20).join('\\n')"
            ),
        ),
        script(
            3,
            &format!(
                "velk.open({path:?}).getFunction('sum_arr').decompile().split('\\n').slice(20).join('\\n')"
            ),
        ),
    ]);
    assert_eq!(text(&responses[0]).chars().count(), 4_000);
    assert_eq!(text(&responses[1]).chars().count(), 256);
    assert!(text(&responses[1]).contains("truncated"));
    for response in &responses {
        assert_eq!(response["result"]["isError"], false, "{response}");
    }
    let mut binary = velk::service::Binary::open(&path).unwrap();
    let address = binary.find("sum_arr").unwrap().addr;
    let code = binary.decompile(address, None, None).unwrap();
    assert_eq!(
        format!("{}\n{}", text(&responses[2]), text(&responses[3])),
        code
    );
}

#[test]
fn annotations_refresh_navigation_and_later_scripts() {
    let directory = common::root()
        .join("target")
        .join(format!("mcp-project-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("calls.o");
    let project = directory.join("analysis.json");
    std::fs::copy(common::fixtures_dir().join("tail_calls.o"), &path).unwrap();
    let prefix = format!("const b=velk.open({path:?},{{project:{project:?}}}); ");
    let run = |id, code| script(id, &format!("{prefix}{code}"));
    let responses = exchange(&[
        run(0, "b.xrefs('tail_one')"),
        run(
            1,
            "b.projectSet({target:{kind:'function',address:b.getFunction('tail_one').addr},name:'analyzed_tail'})",
        ),
        run(2, "b.getFunction('analyzed_tail').decompile()"),
        run(
            3,
            "({name:b.getFunction('analyzed_tail').summary().name,callees:b.callees('tail_two').functions,xrefs:b.xrefs('analyzed_tail').xrefs})",
        ),
        run(
            4,
            "b.projectRemove({kind:'function',address:b.getFunction('analyzed_tail').addr})",
        ),
        run(5, "b.getFunction('tail_one').summary().name"),
    ]);
    for response in &responses {
        assert_eq!(response["result"]["isError"], false, "{response}");
    }
    assert!(text(&responses[2]).contains("analyzed_tail(int32_t"));
    let navigation: Value = serde_json::from_str(text(&responses[3])).unwrap();
    assert_eq!(navigation["name"], "analyzed_tail");
    assert_eq!(navigation["callees"][0]["name"], "analyzed_tail");
    assert_eq!(navigation["xrefs"][0]["name"], "analyzed_tail");
    assert_eq!(text(&responses[5]), "tail_one");
    std::fs::remove_dir_all(directory).unwrap();
}

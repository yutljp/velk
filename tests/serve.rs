use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

#[test]
fn requests_share_a_process_and_preserve_json_values() {
    let binary = "target/serve-return.bin";
    std::fs::write(binary, [0xc3]).expect("write raw binary");
    let mut child = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start server");
    let mut input = child.stdin.take().expect("stdin");
    let mut output = BufReader::new(child.stdout.take().expect("stdout"));
    let requests = [
        "{\"id\":18446744073709551617,\"code\":\"1\"}".to_owned(),
        json!({"id":{"key":1},"code":"console.log('hello', 42); ({address:'0xffffffffffffffff', value:[true,null]})"}).to_string(),
        json!({"id":2,"code":"'x'.repeat(1100000)"}).to_string(),
        json!({"id":3,"code":"throw new Error('failure')"}).to_string(),
        json!({"id":4,"code":"console.log('before timeout'); while (true) {}","timeout_ms":5}).to_string(),
        "invalid".to_owned(),
        json!({"id":7,"code":"velk.open('target/serve-return.bin', {raw:{arch:'x86_64',base:'0xffffffffffff0000'},cache:false}).entry"}).to_string(),
        json!({"id":5,"code":"42"}).to_string(),
    ];
    let mut replies = Vec::new();
    for request in requests {
        writeln!(input, "{request}").expect("write request");
        input.flush().expect("flush request");
        let mut line = String::new();
        output.read_line(&mut line).expect("read reply");
        if replies.is_empty() {
            assert!(line.contains("\"id\":18446744073709551617"));
        }
        replies.push(serde_json::from_str::<Value>(&line).expect("JSON reply"));
    }
    assert!(replies[0]["id"].is_number());
    assert_eq!(replies[1]["id"], json!({"key":1}));
    assert_eq!(replies[1]["result"]["address"], "0xffffffffffffffff");
    assert_eq!(replies[1]["log"], json!(["hello 42"]));
    assert_eq!(
        replies[2]["result"].as_str().expect("string").len(),
        1_100_000
    );
    assert!(
        replies[3]["error"]["message"]
            .as_str()
            .expect("message")
            .contains("failure")
    );
    assert!(
        replies[4]["error"]["message"]
            .as_str()
            .expect("message")
            .contains("timed out")
    );
    assert_eq!(replies[4]["log"], json!(["before timeout"]));
    assert!(replies[5]["id"].is_null());
    assert_eq!(replies[6]["result"], "0xffffffffffff0000");
    assert_eq!(replies[7]["result"], 42);
    input.write_all(b"\xff\n").expect("invalid UTF-8 request");
    input.flush().expect("flush request");
    let mut line = String::new();
    output.read_line(&mut line).expect("read error");
    let reply: Value = serde_json::from_str(&line).expect("JSON reply");
    assert!(reply["id"].is_null());
    writeln!(input, "{}", json!({"id":6,"code":"7"})).expect("request");
    input.flush().expect("flush request");
    line.clear();
    output.read_line(&mut line).expect("read reply");
    let reply: Value = serde_json::from_str(&line).expect("JSON reply");
    assert_eq!(reply["result"], 7);
    drop(input);
    assert!(child.wait().expect("wait for EOF").success());
    std::fs::remove_file(binary).expect("remove raw binary");
}

#[test]
fn result_matches_mcp_and_repeated_analysis() {
    let code = "velk.open('tests/fixtures/arm64.o', {cache:false}).getFunction('sum3').decompile()";
    let mut server = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start server");
    let mut input = server.stdin.take().expect("stdin");
    let mut output = BufReader::new(server.stdout.take().expect("stdout"));
    let mut results = Vec::new();
    for id in 0..2 {
        writeln!(input, "{}", json!({"id":id,"code":code})).expect("request");
        input.flush().expect("flush");
        let mut line = String::new();
        output.read_line(&mut line).expect("reply");
        let reply: Value = serde_json::from_str(&line).expect("JSON reply");
        results.push(reply["result"].clone());
    }
    drop(input);
    assert!(server.wait().expect("wait").success());
    assert_eq!(results[0], results[1]);
    let mut mcp = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start MCP");
    writeln!(mcp.stdin.take().expect("stdin"), "{}", json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"velk_run_script","arguments":{"code":code,"max_output_chars":20000}}})).expect("request");
    let response = mcp.wait_with_output().expect("MCP reply");
    let response: Value = serde_json::from_slice(&response.stdout).expect("JSON reply");
    let expected = match results[0].as_str() {
        Some(text) => text.to_owned(),
        None => results[0].to_string(),
    };
    assert_eq!(response["result"]["content"][0]["text"], expected);
}

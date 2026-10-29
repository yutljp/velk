//! Checks indicator extraction from source-built executable fixtures.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

fn fixtures() -> std::path::PathBuf {
    let directory = common::root().join("target/iocs-tests");
    let output = Command::new("sh")
        .arg(common::root().join("tests/make_iocs_fixtures.sh"))
        .arg(&directory)
        .output()
        .expect("build IOC fixtures");
    assert!(output.status.success(), "{output:?}");
    directory
}

fn names(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .expect("indicator array")
        .iter()
        .map(|indicator| indicator["kind"].as_str().expect("indicator kind"))
        .collect()
}

fn assert_indicator_data(value: &Value) {
    let indicators = value.as_array().expect("indicator array");
    let kinds: Vec<_> = names(value);
    for kind in [
        "url",
        "domain",
        "ip",
        "email",
        "windowsPath",
        "posixPath",
        "registryKey",
        "userAgent",
    ] {
        assert!(kinds.contains(&kind), "missing {kind}: {value}");
    }
    for indicator in indicators {
        assert_eq!(
            indicator
                .as_object()
                .expect("indicator object")
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            ["kind", "references", "sources", "value"]
        );
        assert!(
            indicator["sources"]
                .as_array()
                .expect("source array")
                .iter()
                .any(|source| source == "staticString")
        );
    }
    let urls: Vec<_> = indicators
        .iter()
        .filter(|item| item["kind"] == "url")
        .collect();
    assert!(
        urls.iter()
            .any(|item| item["value"] == "https://bad.example.com/path")
    );
    assert!(
        urls.iter()
            .any(|item| item["value"] == "http://bad.example.org/path")
    );
    assert!(
        urls.iter()
            .any(|item| item["value"] == "ftp://files.example.org/a")
    );
    assert!(
        urls.iter()
            .any(|item| item["value"] == "ws://socket.example.info/")
    );
    assert!(
        urls.iter()
            .any(|item| item["value"] == "wss://socket.example.net/")
    );
    for rejected in [
        "1.2.3.4",
        "1.2.3.999",
        "notes.example.com.txt",
        "Zm9vYmFyMTIzNDU2",
    ] {
        assert!(
            !indicators.iter().any(|item| item["value"] == rejected
                && ["ip", "domain", "email"]
                    .contains(&item["kind"].as_str().expect("indicator kind"))),
            "unexpected classification for {rejected}: {value}"
        );
    }
    assert!(
        indicators.iter().any(|item| {
            item["kind"] == "domain"
                && item["value"] == "example.com"
                && item["sources"]
                    .as_array()
                    .expect("source array")
                    .contains(&json!("decodedString"))
        }),
        "decoded string source was not retained: {value}"
    );
    for (kind, expected) in [
        ("url", "https://bad.example.com/path"),
        ("domain", "example.com"),
        ("ip", "8.8.8.8"),
        ("email", "analyst@example.org"),
        ("windowsPath", "C:\\Windows\\Temp\\bad.exe"),
        ("posixPath", "/usr/local/bin/bad"),
        ("registryKey", "HKLM\\Software\\Bad"),
        ("userAgent", "Mozilla/5.0 (X11; Linux x86_64"),
    ] {
        assert!(
            indicators.iter().any(|item| {
                item["kind"] == kind
                    && item["value"] == expected
                    && !item["references"]
                        .as_array()
                        .expect("reference array")
                        .is_empty()
            }),
            "missing reference for {kind} {expected}: {value}"
        );
    }
}

fn parse_script_result(code: &str) -> Value {
    let outcome = velk::script::Engine::new()
        .expect("create script engine")
        .run(code, None);
    assert!(outcome.error.is_none(), "{:?}", outcome.error);
    serde_json::from_str(&outcome.output).expect("JSON script result")
}

#[test]
fn elf_and_pe_match_cli_javascript_mcp_and_serve() {
    let directory = fixtures();
    for file in ["iocs.elf", "iocs.exe", "iocs.macho"] {
        let path = directory.join(file);
        let cli = Command::new(env!("CARGO_BIN_EXE_velk"))
            .arg("--iocs")
            .arg("--json")
            .arg(&path)
            .output()
            .expect("run IOC CLI");
        assert!(cli.status.success(), "{cli:?}");
        let cli: Value = serde_json::from_slice(&cli.stdout).expect("JSON CLI output");
        assert_indicator_data(&cli);
        let javascript_result = json!({"indicators": cli.clone()});
        let code = format!("JSON.stringify(velk.open({path:?}).iocs())");
        let javascript = parse_script_result(&code);
        assert_eq!(javascript, javascript_result);
        let short_code =
            format!("JSON.stringify(velk.open({path:?}).iocs().indicators.slice(0, 2))");
        let short_result = parse_script_result(&short_code);
        let expected_short = Value::Array(cli.as_array().unwrap()[..2].to_vec());
        assert_eq!(short_result, expected_short);

        let mut mcp = Command::new(env!("CARGO_BIN_EXE_velk"))
            .arg("--mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("start MCP server");
        let request = json!({"jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{"name":"velk_run_script", "arguments":{"code":short_code}}});
        writeln!(mcp.stdin.take().expect("MCP stdin"), "{request}").expect("write MCP request");
        let response = mcp.wait_with_output().expect("read MCP response");
        assert!(response.status.success(), "{response:?}");
        let response: Value = serde_json::from_slice(&response.stdout).expect("JSON MCP response");
        let mcp_text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("MCP tool text");
        let mcp_result = serde_json::from_str::<Value>(mcp_text)
            .unwrap_or_else(|error| panic!("{error}: {mcp_text:?}"));
        assert_eq!(mcp_result, short_result);

        let mut serve = Command::new(env!("CARGO_BIN_EXE_velk"))
            .arg("--serve")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("start serve process");
        writeln!(
            serve.stdin.take().expect("serve stdin"),
            "{}",
            json!({"id":1,"code":short_code})
        )
        .expect("write serve request");
        let response = serve.wait_with_output().expect("read serve response");
        assert!(response.status.success(), "{response:?}");
        let response: Value =
            serde_json::from_slice(&response.stdout).expect("JSON serve response");
        assert_eq!(
            serde_json::from_str::<Value>(response["result"].as_str().expect("serve result"))
                .expect("JSON script result"),
            short_result
        );

        let text = Command::new(env!("CARGO_BIN_EXE_velk"))
            .arg("--iocs")
            .arg(&path)
            .output()
            .expect("run text CLI");
        assert!(text.status.success());
        let text = String::from_utf8(text.stdout).expect("UTF-8 text output");
        assert!(text.contains("url\n") && text.contains("https://bad.example.com/path"));
    }
}

#[test]
fn crypto_constant_names_come_from_the_existing_detector() {
    let path = common::fixtures_dir().join("go_probe");
    let result = parse_script_result(&format!("JSON.stringify(velk.open({path:?}).iocs())"));
    assert!(
        result["indicators"]
            .as_array()
            .expect("indicator array")
            .iter()
            .any(|item| {
                item["kind"] == "cryptoConstant"
                    && item["value"] == "chacha_salsa_constants"
                    && item["sources"]
                        .as_array()
                        .expect("source array")
                        .contains(&json!("staticConstant"))
                    && !item["references"]
                        .as_array()
                        .expect("reference array")
                        .is_empty()
            }),
        "crypto constant was not retained: {result}"
    );
}

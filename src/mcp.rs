//! MCP server over stdio: one tool runs velk scripts, one serves their API docs.

use std::io::{BufRead, Write};
use std::time::Duration;

use serde_json::{Value, json};

use crate::script::Engine;

const MAX_OUTPUT_CHARS: usize = 20_000;
const DEFAULT_TIMEOUT_MS: u64 = 10_000;
const MAX_TIMEOUT_MS: u64 = 120_000;

const RUN_DESCRIPTION: &str = "Run a JavaScript snippet against the velk binary-analysis API and \
return what it prints with console.log, then the value of its last expression. Filter and \
aggregate inside the script so only the answer comes back. Opened binaries stay cached across \
calls. Call velk_read_api for the full API.\n\nExample:\nconst b = velk.open(\"/path/to/bin\");\n\
b.functions({ named: false }).length;\nconst f = b.getFunction(\"main\");\nconsole.log(f.signature());\n\
f.decompile();";

const READ_DESCRIPTION: &str = "Read the velk script API. Without a topic, returns the overview \
and the list of topics; with a topic, returns its TypeScript declarations.";

const TOPICS: [(&str, &str); 3] = [
    ("binary", include_str!("api/binary.d.ts")),
    ("func", include_str!("api/func.d.ts")),
    ("types", include_str!("api/types.d.ts")),
];

pub fn serve() -> Result<(), String> {
    let engine = Engine::new()?;
    let mut stdout = std::io::stdout().lock();
    for line in std::io::stdin().lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        let Ok(request) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if let Some(response) = handle(&engine, &request) {
            writeln!(stdout, "{response}").map_err(|e| e.to_string())?;
            stdout.flush().map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn handle(engine: &Engine, request: &Value) -> Option<Value> {
    let id = request.get("id")?.clone();
    let result = match request.get("method")?.as_str()? {
        "initialize" => Ok(json!({
            "protocolVersion": request
                .pointer("/params/protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or("2024-11-05"),
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "velk", "version": env!("CARGO_PKG_VERSION") }
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools() })),
        "tools/call" => call_tool(engine, request),
        _ => Err((-32601, "method not found")),
    };
    Some(match result {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err((code, message)) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": code, "message": message }
        }),
    })
}

fn tools() -> Value {
    json!([
        {
            "name": "velk_run_script",
            "description": RUN_DESCRIPTION,
            "inputSchema": {
                "type": "object",
                "properties": {
                    "code": { "type": "string", "description": "JavaScript source" },
                    "timeout_ms": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_TIMEOUT_MS,
                        "description": format!("Default {DEFAULT_TIMEOUT_MS}")
                    }
                },
                "required": ["code"],
                "additionalProperties": false
            }
        },
        {
            "name": "velk_read_api",
            "description": READ_DESCRIPTION,
            "inputSchema": {
                "type": "object",
                "properties": {
                    "topic": { "type": "string", "enum": TOPICS.map(|(name, _)| name) }
                },
                "additionalProperties": false
            }
        }
    ])
}

fn call_tool(engine: &Engine, request: &Value) -> Result<Value, (i32, &'static str)> {
    let arguments = request.pointer("/params/arguments").unwrap_or(&Value::Null);
    let (text, is_error) = match request.pointer("/params/name").and_then(Value::as_str) {
        Some("velk_run_script") => run_script(engine, arguments),
        Some("velk_read_api") => read_api(arguments),
        Some(_) => return Err((-32602, "unknown tool")),
        None => return Err((-32602, "missing tool name")),
    };
    Ok(json!({
        "content": [{ "type": "text", "text": text }],
        "isError": is_error
    }))
}

fn run_script(engine: &Engine, arguments: &Value) -> (String, bool) {
    let Some(code) = arguments.get("code").and_then(Value::as_str) else {
        return ("missing code".to_owned(), true);
    };
    let millis = arguments
        .get("timeout_ms")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_TIMEOUT_MS)
        .clamp(1, MAX_TIMEOUT_MS);
    let outcome = engine.run(code, Some(Duration::from_millis(millis)));
    let mut text = truncate(outcome.output);
    if let Some(error) = &outcome.error {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&format!("error: {error}"));
    }
    (text, outcome.error.is_some())
}

fn read_api(arguments: &Value) -> (String, bool) {
    match arguments.get("topic").and_then(Value::as_str) {
        None => (include_str!("api/index.md").to_owned(), false),
        Some(topic) => match TOPICS.iter().find(|(name, _)| *name == topic) {
            Some((_, text)) => ((*text).to_owned(), false),
            None => (format!("unknown topic: {topic}"), true),
        },
    }
}

fn truncate(mut text: String) -> String {
    let Some((cut, _)) = text.char_indices().nth(MAX_OUTPUT_CHARS) else {
        return text;
    };
    let dropped = text[cut..].chars().count();
    text.truncate(cut);
    text.push_str(&format!(
        "\n[truncated {dropped} chars; filter or slice inside the script and run again]"
    ));
    text
}

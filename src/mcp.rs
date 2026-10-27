//! Serves analysis requests over the Model Context Protocol.
#![deny(missing_docs)]

use std::io::{BufRead, Write};
use std::time::Duration;

use serde_json::{Value, json};

use crate::error::{Error, Result};
use crate::script::{Engine, Outcome};

type RpcError = (i32, &'static str);

const PARSE_ERROR: RpcError = (-32700, "parse error");
const INVALID_REQUEST: RpcError = (-32600, "invalid request");
const METHOD_NOT_FOUND: RpcError = (-32601, "method not found");

const MIN_OUTPUT_CHARS: usize = 256;
const DEFAULT_OUTPUT_CHARS: usize = 4_000;
const MAX_OUTPUT_CHARS: usize = 20_000;
const MAX_ERROR_CHARS: usize = 2_000;
const DEFAULT_TIMEOUT_MS: u64 = 10_000;
const MAX_TIMEOUT_MS: u64 = 120_000;

const TRUNCATION_NOTICE: &str = "\n[truncated; filter or slice inside the script]";

const RUN_DESCRIPTION: &str = "Run synchronous JavaScript against the cached binary-analysis API. \
Start with velk_read_api, then e.g. const b = velk.open('/path/to/binary'); \
b.functions().slice(0, 5).map(f => ({addr:f.addr,name:f.name})). \
Each call has fresh JS variables; binaries and analysis remain cached. \
Return console output, then the final value, limited to 4000 characters by default. \
Slice arrays or C text inside the script to retrieve subsequent pages. \
Select one function with b.getFunction(nameOrAddr); '*' is not supported. \
First navigation queries build a whole-binary index and may need a larger timeout_ms.";

const READ_DESCRIPTION: &str = "Read this first: omit topic for API overview and worked examples. \
Use binary for opening, listing, navigation and annotations; func for per-function \
decompilation and inspection; types for returned object fields.";

/// API topic names and their embedded documentation.
pub const TOPICS: [(&str, &str); 4] = [
    ("binary", include_str!("script/api/binary.d.ts")),
    ("func", include_str!("script/api/func.d.ts")),
    ("types", include_str!("script/api/types.d.ts")),
    ("emulation", include_str!("script/api/emulation.d.ts")),
];

/// Serves newline-delimited JSON-RPC requests on standard input and output.
pub fn serve() -> Result<()> {
    let engine = Engine::new()?;
    let mut stdout = std::io::stdout().lock();
    for line in std::io::stdin().lock().lines() {
        let line = line.map_err(Error::Stdio)?;
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(request) => handle(&engine, &request),
            Err(_) => Some(reply(Value::Null, Err(PARSE_ERROR))),
        };
        if let Some(response) = response {
            writeln!(stdout, "{response}").map_err(Error::Stdio)?;
            stdout.flush().map_err(Error::Stdio)?;
        }
    }
    Ok(())
}

/// Answers a request; notifications, which carry no id, get no reply.
fn handle(engine: &Engine, request: &Value) -> Option<Value> {
    let id = request.get("id")?.clone();
    let result = match request.get("method").and_then(Value::as_str) {
        Some("initialize") => Ok(json!({
            "protocolVersion": request
                .pointer("/params/protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or("2024-11-05"),
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "velk", "version": env!("CARGO_PKG_VERSION") }
        })),
        Some("ping") => Ok(json!({})),
        Some("tools/list") => Ok(json!({ "tools": tools() })),
        Some("tools/call") => call_tool(engine, request),
        Some(_) => Err(METHOD_NOT_FOUND),
        None => Err(INVALID_REQUEST),
    };
    Some(reply(id, result))
}

/// Exercises request dispatch without executing supplied scripts or opening files.
#[cfg(feature = "fuzzing")]
pub fn fuzz_request(engine: &Engine, bytes: &[u8]) {
    let Ok(mut request) = serde_json::from_slice::<Value>(bytes) else {
        return;
    };
    if let Some(arguments) = request.pointer_mut("/params/arguments")
        && let Some(arguments) = arguments.as_object_mut()
    {
        if arguments.get("code").is_some_and(Value::is_string) {
            arguments.insert("code".to_owned(), json!(""));
        }
        arguments.remove("path");
    }
    let _ = handle(engine, &request);
}

fn reply(id: Value, result: std::result::Result<Value, RpcError>) -> Value {
    match result {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err((code, message)) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": code, "message": message }
        }),
    }
}

fn tools() -> Value {
    json!([
        {
            "name": "velk_run_script",
            "description": RUN_DESCRIPTION,
            "inputSchema": {
                "type": "object",
                "properties": {
                    "code": { "type": "string", "description": "Synchronous JavaScript; no await or imports. Reopen the binary in each script. The last expression is returned." },
                    "max_output_chars": {
                        "type": "integer",
                        "minimum": MIN_OUTPUT_CHARS,
                        "maximum": MAX_OUTPUT_CHARS,
                        "default": DEFAULT_OUTPUT_CHARS,
                        "description": format!("Final text limit in Unicode characters; default {DEFAULT_OUTPUT_CHARS}")
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_TIMEOUT_MS,
                        "default": DEFAULT_TIMEOUT_MS,
                        "description": "Time budget in milliseconds, checked at JavaScript interrupts and analysis boundaries; first navigation on large binaries can be slow."
                    }
                },
                "required": ["code"],
                "additionalProperties": false
            }
        },
        {
            "name": "velk_classes",
            "description": "List C++ classes recovered from RTTI, with vtable addresses, direct bases and offsets, and virtual methods. Unknown method names and dynamic offsets are null.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "cache": { "type": ["string", "boolean"], "description": "Cache file path, or false to disable persistence" },
                    "arch": { "type": "string", "enum": ["arm64", "arm64e", "x86_64"] }
                },
                "required": ["path"],
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
        },
        {
            "name": "velk_emulate",
            "description": "Execute a function or virtual address through the IR interpreter. Returns stdout, stderr, requested memory reads, final registers, return value, changed memory, steps, stop reason and optional trace. Read the emulation API topic for options. No system calls or host code execute.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "cache": { "type": ["string", "boolean"], "description": "Cache file path, or false to disable persistence" },
                    "start": { "type": "string", "description": "Function name or virtual address" },
                    "options": { "type": "object", "description": "EmulationOptions from the emulation API topic" },
                    "arch": { "type": "string", "enum": ["x86_64", "arm64", "arm64e"] },
                    "raw": { "type": "object", "description": "RawOptions from the binary API topic" }
                },
                "required": ["path", "start"],
                "additionalProperties": false
            }
        }
    ])
}

fn call_tool(engine: &Engine, request: &Value) -> std::result::Result<Value, RpcError> {
    let arguments = request.pointer("/params/arguments").unwrap_or(&Value::Null);
    let (text, is_error) = match request.pointer("/params/name").and_then(Value::as_str) {
        Some("velk_emulate") => emulate(engine, arguments),
        Some("velk_run_script") => run_script(engine, arguments),
        Some("velk_classes") => {
            let Some(path) = arguments.get("path").and_then(Value::as_str) else {
                return Ok(
                    json!({ "content": [{ "type": "text", "text": "missing path" }], "isError": true }),
                );
            };
            let code = classes_script(path, arguments);
            run_script(
                engine,
                &json!({"code": code, "max_output_chars": MAX_OUTPUT_CHARS}),
            )
        }
        Some("velk_read_api") => read_api(arguments),
        Some(_) => return Err((-32602, "unknown tool")),
        None => return Err((-32602, "missing tool name")),
    };
    Ok(json!({
        "content": [{ "type": "text", "text": text }],
        "isError": is_error
    }))
}

fn classes_script(path: &str, arguments: &Value) -> String {
    let path = json!(path);
    let options = json!({"arch": arguments.get("arch"), "cache": arguments.get("cache")});
    format!("velk.open({path}, {options}).classes()")
}

fn emulation_script(path: &str, start: &str, arguments: &Value) -> String {
    let options = arguments
        .get("options")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let open = json!({ "arch": arguments.get("arch"), "raw": arguments.get("raw"), "cache": arguments.get("cache") });
    format!(
        "velk.open({}, {}).emulate({}, {})",
        json!(path),
        open,
        json!(start),
        options
    )
}

fn evaluate_script(engine: &Engine, code: &str, millis: u64) -> Outcome {
    engine.run(code, Some(Duration::from_millis(millis)))
}

fn emulate(engine: &Engine, arguments: &Value) -> (String, bool) {
    let Some(path) = arguments.get("path").and_then(Value::as_str) else {
        return ("missing path".to_owned(), true);
    };
    let Some(start) = arguments.get("start").and_then(Value::as_str) else {
        return ("missing start".to_owned(), true);
    };
    let code = emulation_script(path, start, arguments);
    let outcome = evaluate_script(engine, &code, MAX_TIMEOUT_MS);
    match outcome.error {
        Some(error) => (error, true),
        None => {
            let failed = serde_json::from_str::<Value>(&outcome.output)
                .ok()
                .and_then(|value| {
                    value
                        .get("reason")
                        .and_then(Value::as_str)
                        .map(|reason| !matches!(reason, "return" | "end address"))
                })
                .unwrap_or(true);
            (outcome.output, failed)
        }
    }
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
    let limit = arguments
        .get("max_output_chars")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_OUTPUT_CHARS as u64)
        .clamp(MIN_OUTPUT_CHARS as u64, MAX_OUTPUT_CHARS as u64) as usize;
    let outcome = evaluate_script(engine, code, millis);
    (
        script_output(&outcome.output, outcome.error.as_deref(), limit),
        outcome.error.is_some(),
    )
}

fn read_api(arguments: &Value) -> (String, bool) {
    match arguments.get("topic").and_then(Value::as_str) {
        None => (include_str!("script/api/index.md").to_owned(), false),
        Some(topic) => match TOPICS.iter().find(|(name, _)| *name == topic) {
            Some((_, text)) => ((*text).to_owned(), false),
            None => (
                "unknown topic; use binary, func, types or emulation, or omit topic for the overview"
                    .to_owned(),
                true,
            ),
        },
    }
}

fn script_output(output: &str, error: Option<&str>, limit: usize) -> String {
    let error = error
        .map(|error| {
            if error.starts_with("timed out after ") {
                format!("error: {error}; reduce the work per script or increase timeout_ms (maximum {MAX_TIMEOUT_MS}); interrupted navigation indexing restarts on retry")
            } else {
                format!("error: {error}")
            }
        })
        .unwrap_or_default();
    let output_chars = output.chars().count();
    let error_chars = error.chars().count();
    let separator = usize::from(output_chars > 0 && error_chars > 0);
    let truncated = output_chars + error_chars + separator > limit || error_chars > MAX_ERROR_CHARS;
    let body = limit.saturating_sub(if truncated {
        TRUNCATION_NOTICE.chars().count()
    } else {
        0
    });
    let kept_error = error_chars.min(MAX_ERROR_CHARS).min(body);
    let room = if kept_error > 0 {
        body.saturating_sub(kept_error + 1)
    } else {
        body
    };
    let mut text: String = output.chars().take(room).collect();
    if kept_error > 0 {
        if !text.is_empty() {
            text.push('\n');
        }
        text.extend(error.chars().take(kept_error));
    }
    if truncated {
        text.push_str(TRUNCATION_NOTICE);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_script_keeps_the_text_only_protocol_response() {
        let engine = Engine::new().expect("a script engine");
        let response = handle(
            &engine,
            &json!({
                "jsonrpc": "2.0",
                "id": 42,
                "method": "tools/call",
                "params": {
                    "name": "velk_run_script",
                    "arguments": { "code": "console.log('progress'); ({answer: 42})" }
                }
            }),
        )
        .expect("a request receives a response");
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 42);
        let result = &response["result"];
        assert_eq!(result.as_object().expect("an object").len(), 2);
        assert_eq!(result["isError"], false);
        assert_eq!(
            result["content"],
            json!([{ "type": "text", "text": "progress\n{\"answer\":42}" }])
        );
    }

    #[test]
    fn script_output_limits_default_and_clamp_like_timeouts() {
        let engine = Engine::new().expect("a script engine");
        for (requested, expected) in [
            (None, DEFAULT_OUTPUT_CHARS),
            (Some(json!(MIN_OUTPUT_CHARS)), MIN_OUTPUT_CHARS),
            (Some(json!(MAX_OUTPUT_CHARS)), MAX_OUTPUT_CHARS),
            (Some(json!(0)), MIN_OUTPUT_CHARS),
            (Some(json!(100_000)), MAX_OUTPUT_CHARS),
            (Some(json!(-1)), DEFAULT_OUTPUT_CHARS),
            (Some(json!("invalid")), DEFAULT_OUTPUT_CHARS),
        ] {
            let mut arguments = json!({ "code": "'x'.repeat(30000)" });
            if let Some(requested) = requested {
                arguments["max_output_chars"] = requested;
            }
            let (text, is_error) = run_script(&engine, &arguments);
            assert!(!is_error, "{text}");
            assert_eq!(text.chars().count(), expected);
            assert!(text.ends_with(TRUNCATION_NOTICE), "{text}");
        }
    }

    #[test]
    fn unicode_output_keeps_a_safe_prefix_inside_the_complete_budget() {
        let output = "あ🦀e\u{301}".repeat(500);
        let text = script_output(&output, None, MIN_OUTPUT_CHARS);
        let prefix = output
            .chars()
            .take(MIN_OUTPUT_CHARS - TRUNCATION_NOTICE.chars().count())
            .collect::<String>();
        assert_eq!(text, format!("{prefix}{TRUNCATION_NOTICE}"));
        assert_eq!(text.chars().count(), MIN_OUTPUT_CHARS);
        for output in ["x".repeat(MIN_OUTPUT_CHARS), "🦀".repeat(MIN_OUTPUT_CHARS)] {
            assert_eq!(script_output(&output, None, MIN_OUTPUT_CHARS), output);
        }
    }

    #[test]
    fn short_output_and_error_separators_are_unchanged() {
        for (output, error, expected) in [
            ("", None, ""),
            ("answer", None, "answer"),
            ("progress", Some("boom"), "progress\nerror: boom"),
            ("progress\n", Some("boom"), "progress\n\nerror: boom"),
            ("", Some("boom"), "error: boom"),
        ] {
            assert_eq!(script_output(output, error, MIN_OUTPUT_CHARS), expected);
        }
    }

    #[test]
    fn an_error_survives_long_output_and_keeps_its_error_flag() {
        let engine = Engine::new().expect("a script engine");
        let (text, is_error) = run_script(
            &engine,
            &json!({
                "code": "console.log('x'.repeat(2000)); throw new Error('boom')",
                "max_output_chars": MIN_OUTPUT_CHARS,
            }),
        );
        assert!(is_error);
        assert!(text.contains("error: Error: boom"), "{text}");
        assert!(text.ends_with(TRUNCATION_NOTICE), "{text}");
        assert!(text.chars().count() <= MIN_OUTPUT_CHARS, "{text}");
    }

    #[test]
    fn a_long_error_is_marked_when_either_limit_omits_it() {
        let error = "失敗".repeat(3000);
        for limit in [MIN_OUTPUT_CHARS, DEFAULT_OUTPUT_CHARS] {
            let text = script_output("", Some(&error), limit);
            assert!(text.starts_with("error: "), "{text}");
            let prefix = text
                .strip_suffix(TRUNCATION_NOTICE)
                .expect("an omission notice");
            assert_eq!(
                prefix.chars().count(),
                MAX_ERROR_CHARS.min(limit - TRUNCATION_NOTICE.chars().count())
            );
            assert!(text.chars().count() <= limit);
        }
    }

    #[test]
    fn discovery_and_tool_errors_keep_their_existing_shapes() {
        let schema = tools();
        let output = &schema[0]["inputSchema"]["properties"]["max_output_chars"];
        assert_eq!(output["minimum"], MIN_OUTPUT_CHARS);
        assert_eq!(output["maximum"], MAX_OUTPUT_CHARS);
        assert_eq!(schema[0]["inputSchema"]["required"], json!(["code"]));
        assert_eq!(
            read_api(&json!({ "topic": "func" })),
            (TOPICS[1].1.to_owned(), false)
        );
        let engine = Engine::new().expect("a script engine");
        assert_eq!(
            run_script(&engine, &json!({})),
            ("missing code".to_owned(), true)
        );
        assert_eq!(
            call_tool(&engine, &json!({ "params": { "name": "missing" } })),
            Err((-32602, "unknown tool"))
        );
    }
}

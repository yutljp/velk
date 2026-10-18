//! Minimal MCP (Model Context Protocol) server over stdio.

use std::io::{BufRead, Write};

use serde_json::{json, Value};

use crate::{analysis, code, fncard, loader, pass, refs, sigs};

pub fn serve() -> Result<(), String> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.map_err(|error| error.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if let Some(response) = handle(&request) {
            let text = serde_json::to_string(&response).map_err(|error| error.to_string())?;
            writeln!(stdout, "{text}").map_err(|error| error.to_string())?;
            stdout.flush().map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

fn handle(request: &Value) -> Option<Value> {
    let id = request.get("id").cloned();
    let method = request.get("method")?.as_str()?;
    if id.is_none() {
        return None;
    }
    let id = id.unwrap();
    let response = match method {
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
        "tools/call" => call_tool(request),
        _ => Err((-32601, "method not found")),
    };

    Some(match response {
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
        tool(
            "inspect",
            "List discovered functions and section counts",
            json!({
                "path": string_schema(),
                "limit": { "type": "integer", "minimum": 1 },
                "json": { "type": "boolean" }
            })
        ),
        tool(
            "fncard",
            "Function card with hard reasons, preview, strings and signature match",
            target_schema()
        ),
        tool(
            "report",
            "JSON dossier with typed signature, accesses, references and evidence id",
            target_schema()
        ),
        tool(
            "decompile",
            "Pseudo-C for one function",
            target_schema()
        ),
        tool(
            "siggen",
            "Build a signature database from named functions",
            json!({
                "path": string_schema(),
                "output": string_schema()
            })
        ),
        tool(
            "identify",
            "Match functions against a signature database",
            json!({
                "path": string_schema(),
                "sigs": string_schema()
            })
        )
    ])
}

fn tool(name: &str, description: &str, properties: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": ["path"],
            "additionalProperties": false
        },
    })
}

fn string_schema() -> Value {
    json!({ "type": "string" })
}

fn target_schema() -> Value {
    json!({
        "path": string_schema(),
        "name": string_schema(),
        "addr": { "type": "integer", "minimum": 0 },
        "preview": { "type": "integer", "minimum": 1 },
        "sigs": string_schema()
    })
}

fn call_tool(request: &Value) -> Result<Value, (i32, &'static str)> {
    let name = request
        .pointer("/params/name")
        .and_then(Value::as_str)
        .ok_or((-32602, "missing tool name"))?;
    let arguments = request
        .pointer("/params/arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let text = match dispatch(name, &arguments) {
        Ok(text) => text,
        Err(message) => {
            return Ok(json!({
                "content": [{ "type": "text", "text": format!("error: {message}") }],
                "isError": true
            }));
        }
    };
    Ok(json!({ "content": [{ "type": "text", "text": text }] }))
}

fn path_argument(arguments: &Value) -> Result<std::path::PathBuf, String> {
    arguments
        .get("path")
        .and_then(Value::as_str)
        .map(std::path::PathBuf::from)
        .ok_or_else(|| "missing path".to_owned())
}

fn function_argument<'a>(
    image: &'a loader::Image,
    arguments: &Value,
) -> Result<&'a loader::Function, String> {
    let name = arguments.get("name").and_then(Value::as_str);
    let addr = arguments.get("addr").and_then(Value::as_u64);
    if let Some(name) = name {
        return image
            .find_function_by_name(name)
            .ok_or_else(|| format!("function not found: {name}"));
    }
    if let Some(addr) = addr {
        return image
            .functions
            .get(&addr)
            .ok_or_else(|| format!("function not found: 0x{addr:x}"));
    }
    Err("missing name or addr".to_owned())
}

fn database(arguments: &Value) -> Result<Option<sigs::Database>, String> {
    match arguments.get("sigs").and_then(Value::as_str) {
        Some(path) => {
            let text = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
            let database = serde_json::from_str(&text).map_err(|error| error.to_string())?;
            Ok(Some(database))
        }
        None => Ok(None),
    }
}

fn dispatch(name: &str, arguments: &Value) -> Result<String, String> {
    let path = path_argument(arguments)?;
    match name {
        "inspect" => {
            let image = loader::load(&path)?;
            let limit = arguments
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(40) as usize;
            let summary = json!({
                "format": image.format.to_string(),
                "isa": image.isa.to_string(),
                "entry": image.entry,
                "n_sections": image.sections.len(),
                "n_functions": image.functions.len(),
                "named_functions": image.functions.values().filter(|f| f.name.is_some()).count(),
                "functions": image.functions.values().take(limit).map(|function| json!({
                    "addr": function.addr,
                    "size": function.size,
                    "name": function.name,
                    "source": function.source.iter().map(ToString::to_string).collect::<Vec<_>>(),
                })).collect::<Vec<_>>(),
            });
            Ok(serde_json::to_string_pretty(&summary).map_err(|error| error.to_string())?)
        }
        "fncard" => {
            let image = loader::load(&path)?;
            let function = function_argument(&image, arguments)?;
            let preview = arguments
                .get("preview")
                .and_then(Value::as_u64)
                .unwrap_or(24) as usize;
            let size = function.size.unwrap_or(256);
            let mut lifted = analysis::lift(&image, function, size).ok();
            if let Some(ir) = lifted.as_mut() {
                pass::simplify(ir);
            }
            let references = lifted
                .as_ref()
                .map(|ir| refs::collect(ir, &image))
                .unwrap_or_default();
            let strings: Vec<String> = references
                .iter()
                .filter_map(|reference| reference.text.clone())
                .collect();
            let hints = refs::name_hints(&strings);
            let accesses = lifted
                .as_ref()
                .map(|ir| ir.accesses.clone())
                .unwrap_or_default();
            let database = database(arguments)?;
            let identified = match (&database, &lifted) {
                (Some(database), Some(ir)) => sigs::lookup(database, ir),
                _ => None,
            };
            let card = fncard::build(
                &image,
                function,
                preview,
                lifted.as_ref(),
                strings,
                hints,
                accesses,
                identified,
            );
            Ok(serde_json::to_string_pretty(&card).map_err(|error| error.to_string())?)
        }
        "report" => {
            let image = loader::load(&path)?;
            let function = function_argument(&image, arguments)?;
            let preview = arguments
                .get("preview")
                .and_then(Value::as_u64)
                .unwrap_or(16) as usize;
            let size = function.size.unwrap_or(256);
            let mut lifted = analysis::lift(&image, function, size)?;
            pass::simplify(&mut lifted);
            let references = refs::collect(&lifted, &image);
            let strings: Vec<String> = references
                .iter()
                .filter_map(|reference| reference.text.clone())
                .collect();
            let hints = refs::name_hints(&strings);
            let database = database(arguments)?;
            let identified = database.as_ref().and_then(|database| sigs::lookup(database, &lifted));
            let card = fncard::build(
                &image,
                function,
                preview,
                Some(&lifted),
                strings.clone(),
                hints.clone(),
                lifted.accesses.clone(),
                identified.clone(),
            );
            let tokens = sigs::tokens(&lifted);
            let evidence = sigs::hash(&tokens);
            let params: Vec<Value> = lifted
                .params
                .iter()
                .map(|param| json!({ "name": param.name, "type": param.ty }))
                .collect();
            let dossier = json!({
                "evidence": evidence,
                "card": card,
                "signature": { "return": lifted.ret_type, "params": params },
                "accesses": lifted.accesses,
                "references": references.iter().map(|reference| reference.describe()).collect::<Vec<_>>(),
                "strings": strings,
                "name_hints": hints,
                "identified": identified,
                "tokens": tokens.len(),
            });
            Ok(serde_json::to_string_pretty(&dossier).map_err(|error| error.to_string())?)
        }
        "decompile" => {
            let image = loader::load(&path)?;
            let function = function_argument(&image, arguments)?;
            let size = function.size.unwrap_or(256);
            let mut lifted = analysis::lift(&image, function, size)?;
            pass::simplify(&mut lifted);
            let references = refs::collect(&lifted, &image);
            let database = database(arguments)?;
            let mut text = String::new();
            if let Some(database) = &database {
                if let Some(matched) = sigs::lookup(database, &lifted) {
                    text.push_str(&format!("/* identified: {matched} */\n"));
                }
            }
            text.push_str(&code::render(&mut lifted, &references, &code::callee_names(&image), code::data_ranges(&image)));
            Ok(text)
        }
        "siggen" => {
            let output = arguments
                .get("output")
                .and_then(Value::as_str)
                .ok_or_else(|| "missing output".to_owned())?;
            let image = loader::load(&path)?;
            let database = sigs::build(&image);
            let text = serde_json::to_string_pretty(&database).map_err(|error| error.to_string())?;
            std::fs::write(output, text).map_err(|error| error.to_string())?;
            Ok(format!("{} entries -> {output}", database.entries.len()))
        }
        "identify" => {
            let sigs_path = arguments
                .get("sigs")
                .and_then(Value::as_str)
                .ok_or_else(|| "missing sigs".to_owned())?;
            let image = loader::load(&path)?;
            let text = std::fs::read_to_string(sigs_path).map_err(|error| error.to_string())?;
            let database: sigs::Database =
                serde_json::from_str(&text).map_err(|error| error.to_string())?;
            let matches = sigs::identify(&image, &database);
            Ok(serde_json::to_string_pretty(&matches.iter().map(|hit| json!({
                "addr": hit.addr,
                "size": hit.size,
                "current": hit.current,
                "matched": hit.matched,
            })).collect::<Vec<_>>())
            .map_err(|error| error.to_string())?)
        }
        other => Err(format!("unknown tool: {other}")),
    }
}

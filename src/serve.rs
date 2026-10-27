//! Serves the script API as newline-delimited JSON.

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::time::Duration;

use serde_json::value::RawValue;
use serde_json::{Value, json};

use crate::error::{Error, Result};
use crate::script::Engine;

/// Reads requests from standard input and writes one response per line.
pub fn serve() -> Result<()> {
    let engine = match Engine::new() {
        Ok(engine) => engine,
        Err(error) => return Err(error),
    };
    let mut output = std::io::stdout().lock();
    let mut input = std::io::stdin().lock();
    loop {
        let mut line = Vec::new();
        match input.read_until(b'\n', &mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) => return Err(Error::Stdio(error)),
        }
        let request = serde_json::from_slice::<HashMap<String, Box<RawValue>>>(&line);
        let (response, id) = match request {
            Ok(mut request) => {
                let id = request.remove("id");
                let mut request = match serde_json::to_value(request) {
                    Ok(request) => request,
                    Err(error) => return Err(Error::Stdio(std::io::Error::other(error))),
                };
                if id.is_some() {
                    request["id"] = json!(true);
                }
                let response = handle(&engine, &request);
                let id = if response.get("id").is_some_and(|id| !id.is_null()) {
                    id.as_ref().map_or("null", |id| id.get()).to_owned()
                } else {
                    "null".to_owned()
                };
                (response, id)
            }
            Err(error) => (
                json!({"id": null, "error": {"message": error.to_string(), "stack": null}, "log": []}),
                "null".to_owned(),
            ),
        };
        let mut fields = response;
        if let Some(object) = fields.as_object_mut() {
            object.remove("id");
        }
        let fields = fields.to_string();
        if let Err(error) = writeln!(output, "{{\"id\":{id},{}", &fields[1..]) {
            return Err(Error::Stdio(error));
        }
        if let Err(error) = output.flush() {
            return Err(Error::Stdio(error));
        }
    }
    Ok(())
}

fn handle(engine: &Engine, request: &Value) -> Value {
    let Some(id) = request.get("id") else {
        return json!({"id": null, "error": {"message": "missing id", "stack": null}, "log": []});
    };
    let Some(code) = request.get("code").and_then(Value::as_str) else {
        return json!({"id": null, "error": {"message": "missing or invalid code", "stack": null}, "log": []});
    };
    let millis = request
        .get("timeout_ms")
        .and_then(Value::as_u64)
        .unwrap_or(10_000)
        .clamp(1, 120_000);
    let outcome = engine.run_structured(code, Some(Duration::from_millis(millis)));
    match outcome.error {
        Some(error) => {
            json!({"id": id, "error": {"message": error, "stack": outcome.stack}, "log": outcome.log})
        }
        None => json!({"id": id, "result": outcome.result, "log": outcome.log}),
    }
}

//! Project annotation operations for scripts.
use super::BinaryRef;
use crate::error::Result;
use crate::service::Session;
use serde_json::{Value, json};
use std::time::Instant;

pub(super) fn handle(
    session: &mut Session,
    bin: BinaryRef,
    action: String,
    value: Value,
    deadline: Option<Instant>,
) -> Result<Value> {
    let binary = match bin.open(session) {
        Ok(binary) => binary,
        Err(error) => return Err(error),
    };
    let destination = binary.project_path().to_owned();
    let raw = binary.input_options().raw.clone();
    let command = match action.as_str() {
        "origins" => {
            let binary = match bin.open(session) {
                Ok(binary) => binary,
                Err(cause) => return Err(cause),
            };
            let address = match binary.find(value.as_str().unwrap_or_default()) {
                Ok(function) => function.addr,
                Err(cause) => return Err(cause),
            };
            return match binary.analysis(address, deadline) {
                Ok(analysis) => Ok(json!(crate::project::origins(&analysis.ir))),
                Err(cause) => Err(cause),
            };
        }
        "set" => crate::project::cli::Command::Set {
            json: value.to_string(),
        },
        "get" => crate::project::cli::Command::Get {
            target: value.to_string(),
        },
        "remove" => crate::project::cli::Command::Remove {
            target: value.to_string(),
        },
        "list" => crate::project::cli::Command::List,
        "export" => crate::project::cli::Command::Export,
        "import" => {
            return crate::project::update_cached(
                &bin,
                &destination,
                &mut binary.project_digest,
                |project| {
                    let mut imported: crate::project::Project = match serde_json::from_value(value)
                    {
                        Ok(imported) => imported,
                        Err(cause) => {
                            return Err(crate::project::error("project_json", cause.to_string()));
                        }
                    };
                    if imported
                        .raw
                        .as_ref()
                        .is_some_and(|mapping| Some(mapping) != raw.as_ref())
                    {
                        return Err(crate::project::error(
                            "invalid_mapping",
                            "imported project uses a different raw mapping",
                        ));
                    }
                    if let Err(error) = project.set_raw_mapping(raw.as_ref()) {
                        return Err(error);
                    }
                    imported.raw = raw;
                    *project = imported;
                    Ok(json!({"ok": true}))
                },
            );
        }
        _ => {
            return Err(crate::project::error(
                "invalid_operation",
                format!("unknown project action: {action}"),
            ));
        }
    };
    crate::project::cli::execute_cached(
        crate::project::cli::Cli {
            binary: bin.to_path_buf(),
            arch: bin.arch(),
            raw,
            project: Some(destination),
            command,
        },
        &mut binary.project_digest,
    )
}

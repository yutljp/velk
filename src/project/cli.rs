//! JSON annotation operations.
use super::{Annotation, Project, Target, error};
use crate::error::Result;
use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;

/// Arguments for one JSON annotation operation.
pub struct Cli {
    pub binary: PathBuf,
    /// Architecture selected for function analysis.
    pub arch: Option<crate::loader::Architecture>,
    /// Explicit headerless mapping.
    pub raw: Option<crate::loader::RawOptions>,
    /// Persistent analysis cache selection.
    pub cache: Option<crate::service::CacheLocation>,
    pub command: Command,
    pub project: Option<PathBuf>,
}

#[derive(Debug, PartialEq, Eq)]
/// Annotation operations available to terminal and script callers.
pub enum Command {
    /// List stable parameter and local storage targets for a function.
    Origins { function: String },
    /// Set one annotation from a JSON object.
    Set { json: String },
    /// Get one annotation by its JSON target.
    Get { target: String },
    /// List all annotations.
    List,
    /// Remove one annotation by its JSON target.
    Remove { target: String },
    /// Export the complete versioned JSON document to stdout.
    Export,
    /// Replace annotations from a complete JSON document read from a file.
    Import { file: PathBuf },
}

/// Executes an annotation operation and returns its JSON response.
pub fn execute(cli: Cli) -> Result<Value> {
    execute_cached(cli, &mut None)
}

pub(crate) fn execute_cached(mut cli: Cli, digest: &mut Option<String>) -> Result<Value> {
    cli.binary = match fs::canonicalize(&cli.binary) {
        Ok(binary) => binary,
        Err(cause) => return Err(super::io(&cli.binary, cause)),
    };
    let destination = cli.project.unwrap_or_else(|| super::path(&cli.binary));
    if cli.raw.is_some()
        && let Err(error) = crate::service::Binary::open_input(
            &cli.binary,
            Some(&destination),
            &crate::loader::OpenOptions {
                cache: cli.cache.clone(),
                arch: cli.arch,
                raw: cli.raw.clone(),
            },
        )
    {
        return Err(error);
    }
    match cli.command {
        Command::Origins { function } => {
            let mut binary = match crate::service::Binary::open_input(
                &cli.binary,
                Some(&destination),
                &crate::loader::OpenOptions {
                    cache: cli.cache.clone(),
                    arch: cli.arch,
                    raw: cli.raw.clone(),
                },
            ) {
                Ok(binary) => binary,
                Err(cause) => return Err(cause),
            };
            let address = match binary.find(&function) {
                Ok(function) => function.addr,
                Err(cause) => return Err(cause),
            };
            match binary.analysis(address, None) {
                Ok(analysis) => Ok(json!(super::origins(&analysis.ir))),
                Err(cause) => Err(cause),
            }
        }
        Command::Set { json: text } => {
            let annotation: Annotation = match serde_json::from_str(&text) {
                Ok(value) => value,
                Err(cause) => return Err(error("project_json", cause.to_string())),
            };
            super::update_cached(&cli.binary, &destination, digest, |project| {
                if let Err(error) = project.set_raw_mapping(cli.raw.as_ref()) {
                    return Err(error);
                }
                project.set(annotation);
                Ok(json!({"ok": true}))
            })
        }
        Command::Remove { target } => {
            let target = match parse_target(&target) {
                Ok(value) => value,
                Err(cause) => return Err(cause),
            };
            super::update_cached(&cli.binary, &destination, digest, |project| {
                if let Err(error) = project.set_raw_mapping(cli.raw.as_ref()) {
                    return Err(error);
                }
                Ok(json!({"removed": project.remove(&target)}))
            })
        }
        Command::Import { file } => {
            let text = match fs::read(&file) {
                Ok(text) => text,
                Err(cause) => return Err(super::io(&file, cause)),
            };
            let mut imported: Project = match serde_json::from_slice(&text) {
                Ok(value) => value,
                Err(cause) => return Err(error("project_json", cause.to_string())),
            };
            if let Some(raw) = &cli.raw {
                if imported.raw.as_ref().is_some_and(|mapping| mapping != raw) {
                    return Err(error(
                        "invalid_mapping",
                        "imported project uses a different raw mapping",
                    ));
                }
                imported.raw = Some(raw.clone());
            }
            super::update_cached(&cli.binary, &destination, digest, |project| {
                if let Err(error) = project.set_raw_mapping(cli.raw.as_ref()) {
                    return Err(error);
                }
                *project = imported;
                Ok(json!({"ok": true}))
            })
        }
        command => {
            let project = match super::load_at(&cli.binary, &destination, digest) {
                Ok(value) => value,
                Err(cause) => return Err(cause),
            };
            match command {
                Command::List => Ok(json!(project.map(|p| p.annotations).unwrap_or_default())),
                Command::Get { target } => {
                    let target = match parse_target(&target) {
                        Ok(value) => value,
                        Err(cause) => return Err(cause),
                    };
                    Ok(json!(project.as_ref().and_then(|p| p.get(&target))))
                }
                Command::Export => match project {
                    Some(mut project) => {
                        if let Err(error) = project.set_raw_mapping(cli.raw.as_ref()) {
                            return Err(error);
                        }
                        Ok(json!(project))
                    }
                    None => super::update_cached(&cli.binary, &destination, digest, |project| {
                        if let Err(error) = project.set_raw_mapping(cli.raw.as_ref()) {
                            return Err(error);
                        }
                        Ok(json!(project))
                    }),
                },
                _ => unreachable!(),
            }
        }
    }
}

fn parse_target(text: &str) -> Result<Target> {
    match serde_json::from_str(text) {
        Ok(value) => Ok(value),
        Err(cause) => Err(error("project_json", cause.to_string())),
    }
}

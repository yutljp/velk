//! Executes parsed binary, script and transport operations.

use std::path::Path;
use std::process::ExitCode;

use serde_json::json;
use velk::error::{Error, Result};
use velk::service::Binary;
use velk::sigs::Database;
use velk::{mcp, script};

use super::Command;
use crate::terminal::{Language, Terminal};
use crate::{cli_output, decompile_functions, write_json};

fn compare_binaries(
    path: &Path,
    other: &Path,
    project: Option<&Path>,
    other_project: Option<&Path>,
    arch: Option<velk::loader::Architecture>,
    carry_annotations: bool,
) -> Result<velk::compare::Report> {
    let mut first = match Binary::open_with_options(path, project, arch) {
        Ok(binary) => binary,
        Err(error) => return Err(error),
    };
    let mut second = match Binary::open_with_options(other, other_project, arch) {
        Ok(binary) => binary,
        Err(error) => return Err(error),
    };
    velk::compare::compare(&mut first, &mut second, carry_annotations, None)
}

pub(crate) fn run(
    command: Command,
    project: Option<&Path>,
    arch: Option<velk::loader::Architecture>,
    decode_strings: bool,
) -> Result<ExitCode> {
    match command {
        Command::Compare {
            path,
            other,
            other_project,
            carry_annotations,
        } => {
            let result = compare_binaries(
                &path,
                &other,
                project,
                other_project.as_deref(),
                arch,
                carry_annotations,
            );
            return Ok(match result {
                Ok(report) => {
                    println!("{}", json!(report));
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!(
                        "{}",
                        json!({"code": "comparison_error", "message": error.to_string()})
                    );
                    ExitCode::FAILURE
                }
            });
        }
        Command::Emulate {
            path,
            start,
            options,
        } => {
            let binary = match Binary::open_with_options(&path, project, arch) {
                Ok(binary) => binary,
                Err(error) => return Err(error),
            };
            let options: velk::emulation::Options = match options {
                Some(text) => match serde_json::from_str(&text) {
                    Ok(options) => options,
                    Err(error) => {
                        return Err(Error::Emulation(format!("invalid options: {error}")));
                    }
                },
                None => velk::emulation::Options::default(),
            };
            let report = match velk::emulation::run(&binary, &start, &options, None) {
                Ok(report) => report,
                Err(error) => return Err(error),
            };
            println!("{:#}", json!(report));
            return Ok(
                if matches!(report.reason.as_str(), "return" | "end address") {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                },
            );
        }
        Command::Navigation { path, query } => {
            let mut binary = match Binary::open_with_options(&path, project, arch) {
                Ok(binary) => binary,
                Err(error) => return Err(error),
            };
            match velk::xrefs::query::run(&mut binary, query, None) {
                Ok(value) => println!("{value:#}"),
                Err(error) => return Err(error),
            }
        }

        Command::Functions { path, limit, json } => {
            let binary = match Binary::open_with_options(&path, project, arch) {
                Ok(binary) => binary,
                Err(error) => return Err(error),
            };
            if json {
                cli_output::print_functions_json(&binary, limit);
            } else {
                cli_output::print_functions(&binary, limit);
            }
        }
        Command::Classes { path } => {
            let binary = match Binary::open_with_options(&path, project, arch) {
                Ok(binary) => binary,
                Err(error) => return Err(error),
            };
            println!("{:#}", json!(binary.image().classes()));
        }
        Command::Sections { path } => {
            let binary = match Binary::open_with_options(&path, project, arch) {
                Ok(binary) => binary,
                Err(error) => return Err(error),
            };
            cli_output::print_sections(&binary);
        }
        Command::Card {
            path,
            function,
            budget,
            signatures,
        } => {
            let signatures = match signatures.as_deref().map(Database::load).transpose() {
                Ok(signatures) => signatures,
                Err(error) => return Err(error),
            };
            let mut binary = match Binary::open_with_options(&path, project, arch) {
                Ok(binary) => binary,
                Err(error) => return Err(error),
            };
            let addr = match binary.find(&function) {
                Ok(found) => found.addr,
                Err(error) => return Err(error),
            };
            let card = match binary.card(addr, budget, signatures.as_ref(), None) {
                Ok(card) => card,
                Err(error) => return Err(error),
            };
            println!("{:#}", json!(card));
        }
        Command::Decompile {
            path,
            functions,
            signatures,
        } => {
            let signatures = match signatures.as_deref().map(Database::load).transpose() {
                Ok(signatures) => signatures,
                Err(error) => return Err(error),
            };
            let mut binary = match Binary::open_with_options(&path, project, arch) {
                Ok(binary) => binary,
                Err(error) => return Err(error),
            };
            binary.set_string_decoding(decode_strings);
            let addresses =
                if functions.is_empty() || functions.iter().any(|function| function == "*") {
                    binary.image().functions.keys().copied().collect::<Vec<_>>()
                } else {
                    let mut addresses = Vec::new();
                    for target in &functions {
                        match binary.find(target) {
                            Ok(found) => addresses.push(found.addr),
                            Err(error) => return Err(error),
                        }
                    }
                    addresses
                };
            return Ok(decompile_functions(
                &mut binary,
                &addresses,
                &functions.join(", "),
                signatures.as_ref(),
            ));
        }
        Command::Disasm {
            path,
            function,
            limit,
        } => {
            let binary = match Binary::open_with_options(&path, project, arch) {
                Ok(binary) => binary,
                Err(error) => return Err(error),
            };
            let addr = match binary.find(&function) {
                Ok(found) => found.addr,
                Err(error) => return Err(error),
            };
            let listing = match binary.disasm(addr, limit.unwrap_or(usize::MAX)) {
                Ok(listing) => listing,
                Err(error) => return Err(error),
            };
            if Terminal::stdout().interactive() {
                let code: String = listing.iter().map(|line| format!("{line}\n")).collect();
                cli_output::print_code(&binary, addr, &function, &code, Language::Disassembly);
            } else {
                for line in listing {
                    println!("{line}");
                }
            }
        }
        Command::Ir { path, function } => {
            let mut binary = match Binary::open_with_options(&path, project, arch) {
                Ok(binary) => binary,
                Err(error) => return Err(error),
            };
            let addr = match binary.find(&function) {
                Ok(found) => found.addr,
                Err(error) => return Err(error),
            };
            let code = match binary.analysis(addr, None) {
                Ok(analysis) => analysis.ir.render(),
                Err(error) => return Err(error),
            };
            cli_output::print_code(&binary, addr, &function, &code, Language::Ir);
        }
        Command::BuildSignatures { path, output } => {
            let database = if arch.is_some() {
                let mut binary = match Binary::open_with_options(&path, project, arch) {
                    Ok(binary) => binary,
                    Err(error) => return Err(error),
                };
                match binary.build_signatures(None) {
                    Ok(result) => result.database,
                    Err(error) => return Err(error),
                }
            } else {
                match velk::sigs::build(&path, None) {
                    Ok(database) => database,
                    Err(error) => return Err(error),
                }
            };
            if let Err(error) = write_json(&output, &json!(database)) {
                return Err(error);
            }
            eprintln!(
                "{}",
                Terminal::stderr().success(&format!(
                    "{} entries -> {}",
                    database.entries.len(),
                    output.display(),
                )),
            );
        }
        Command::Identify {
            path,
            signatures,
            limit,
        } => {
            let database = match Database::load(&signatures) {
                Ok(database) => database,
                Err(error) => return Err(error),
            };
            let mut binary = match Binary::open_with_options(&path, project, arch) {
                Ok(binary) => binary,
                Err(error) => return Err(error),
            };
            let identification = match binary.identify(&database, None) {
                Ok(identification) => identification,
                Err(error) => return Err(error),
            };
            cli_output::print_identification(&binary, &identification, limit);
        }
        Command::Run { script } => {
            let code = match std::fs::read_to_string(&script) {
                Ok(code) => code,
                Err(source) => {
                    return Err(Error::Io {
                        path: script,
                        source,
                    });
                }
            };
            let engine = match script::Engine::new() {
                Ok(engine) => engine,
                Err(error) => return Err(error),
            };
            let outcome = engine.run(&code, None);
            if !outcome.output.is_empty() {
                println!("{}", outcome.output);
            }
            if let Some(error) = outcome.error {
                eprintln!("error: {error}");
                return Ok(ExitCode::FAILURE);
            }
        }
        Command::Mcp => {
            if let Err(error) = mcp::serve() {
                return Err(error);
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

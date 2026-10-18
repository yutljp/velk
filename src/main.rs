//! velk: LLM-facing binary analysis engine.

mod analysis;
mod code;
mod dwarf;
mod fncard;
mod go;
mod ir;
mod lift;
mod lift_x86;
mod loader;
mod mcp;
mod structure;
mod switch;
mod pass;
mod refs;
mod script;
mod session;
mod signature;
mod sigs;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use loader::Image;

#[derive(Parser)]
#[command(name = "velk", version, about = "Binary analysis engine for LLM agents")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List discovered functions.
    Inspect {
        path: std::path::PathBuf,
        /// Maximum number of rows to print.
        #[arg(long, default_value_t = 40)]
        limit: usize,
        /// Emit a JSON summary instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Print a function card as JSON.
    Fncard {
        path: std::path::PathBuf,
        #[arg(long, group = "target")]
        name: Option<String>,
        #[arg(long, group = "target", value_parser = parse_number)]
        addr: Option<u64>,
        /// Maximum disassembly lines in the preview.
        #[arg(long, default_value_t = 24)]
        preview: usize,
        /// Signature database for function identification.
        #[arg(long)]
        sigs: Option<std::path::PathBuf>,
    },
    /// List sections.
    Sections { path: std::path::PathBuf },
    /// Run the MCP server over stdio.
    Mcp,
    /// Run a JavaScript file against the velk script API.
    Run { path: std::path::PathBuf },
    /// Build a signature database from named functions.
    Siggen {
        path: std::path::PathBuf,
        /// Destination JSON file.
        #[arg(long)]
        output: std::path::PathBuf,
    },
    /// Emit a JSON dossier with an evidence identifier for one function.
    Report {
        path: std::path::PathBuf,
        #[arg(long, group = "target")]
        name: Option<String>,
        #[arg(long, group = "target", value_parser = parse_number)]
        addr: Option<u64>,
        /// Maximum disassembly lines in the preview.
        #[arg(long, default_value_t = 16)]
        preview: usize,
        /// Signature database for function identification.
        #[arg(long)]
        sigs: Option<std::path::PathBuf>,
    },
    /// Match functions against a signature database.
    Identify {
        path: std::path::PathBuf,
        /// Signature database produced by `siggen`.
        #[arg(long)]
        sigs: std::path::PathBuf,
        /// Maximum number of rows to print.
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Print pseudo-C for one function.
    Decompile {
        path: std::path::PathBuf,
        #[arg(long, group = "target")]
        name: Option<String>,
        #[arg(long, group = "target", value_parser = parse_number)]
        addr: Option<u64>,
        /// Signature database for function identification.
        #[arg(long)]
        sigs: Option<std::path::PathBuf>,
    },
    /// Dump IR for one function.
    Lift {
        path: std::path::PathBuf,
        #[arg(long, group = "target")]
        name: Option<String>,
        #[arg(long, group = "target", value_parser = parse_number)]
        addr: Option<u64>,
    },
}

fn parse_number(text: &str) -> Result<u64, std::num::ParseIntError> {
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => text.parse(),
    }
}

fn main() -> ExitCode {
    let Cli { command } = Cli::parse();
    match run(command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> Result<(), String> {
    let started = std::time::Instant::now();
    match command {
        Command::Inspect { path, limit, json } => {
            let image = loader::load(&path)?;
            if json {
                let summary = serde_json::json!({
                    "format": image.format.to_string(),
                    "isa": image.isa.to_string(),
                    "entry": image.entry,
                    "n_sections": image.sections.len(),
                    "n_functions": image.functions.len(),
                    "named_functions": image.functions.values().filter(|f| f.name.is_some()).count(),
                });
                println!("{}", serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())?);
            } else {
                println!(
                    "format: {}, isa: {}, entry: {}, sections: {}, functions: {}, named: {}",
                    image.format,
                    image.isa,
                    image.entry.map(|e| format!("0x{e:x}")).unwrap_or_else(|| "-".to_owned()),
                    image.sections.len(),
                    image.functions.len(),
                    image.functions.values().filter(|f| f.name.is_some()).count(),
                );
                print_functions(&image, limit);
            }
        }
        Command::Fncard {
            path,
            name,
            addr,
            preview,
            sigs,
        } => {
            let image = loader::load(&path)?;
            let function = select_function(&image, name.as_deref(), addr)?;
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
            let identified = match (&sigs, &lifted) {
                (Some(path), Some(ir)) => {
                    let database = load_database(path)?;
                    sigs::lookup(&database, ir)
                }
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
            println!("{}", serde_json::to_string_pretty(&card).map_err(|e| e.to_string())?);
        }
        Command::Mcp => {
            mcp::serve()?;
        }
        Command::Run { path } => {
            let code = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
            let outcome = script::Engine::new()?.run(&code, None);
            if !outcome.output.is_empty() {
                println!("{}", outcome.output);
            }
            if let Some(error) = outcome.error {
                return Err(error);
            }
        }
        Command::Sections { path } => {
            let image = loader::load(&path)?;
            print_sections(&image);
        }
        Command::Report {
            path,
            name,
            addr,
            preview,
            sigs,
        } => {
            let image = loader::load(&path)?;
            let function = select_function(&image, name.as_deref(), addr)?;
            let size = function.size.unwrap_or(256);
            let mut lifted = analysis::lift(&image, function, size)?;
            pass::simplify(&mut lifted);
            let references = refs::collect(&lifted, &image);
            let strings: Vec<String> = references
                .iter()
                .filter_map(|reference| reference.text.clone())
                .collect();
            let hints = refs::name_hints(&strings);
            let identified = match &sigs {
                Some(path) => {
                    let database = load_database(path)?;
                    sigs::lookup(&database, &lifted)
                }
                None => None,
            };
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
            let params: Vec<serde_json::Value> = lifted
                .params
                .iter()
                .map(|param| {
                    serde_json::json!({
                        "name": param.name,
                        "type": param.ty,
                    })
                })
                .collect();
            let dossier = serde_json::json!({
                "evidence": evidence,
                "card": card,
                "signature": {
                    "return": lifted.ret_type,
                    "params": params,
                },
                "accesses": lifted.accesses,
                "references": references
                    .iter()
                    .map(|reference| reference.describe())
                    .collect::<Vec<_>>(),
                "strings": strings,
                "name_hints": hints,
                "identified": identified,
                "tokens": tokens.len(),
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&dossier).map_err(|e| e.to_string())?
            );
        }
        Command::Siggen { path, output } => {
            let image = loader::load(&path)?;
            let database = sigs::build(&image);
            let text = serde_json::to_string_pretty(&database).map_err(|e| e.to_string())?;
            std::fs::write(&output, text).map_err(|e| e.to_string())?;
            eprintln!(
                "[{} entries -> {}]",
                database.entries.len(),
                output.display()
            );
        }
        Command::Identify { path, sigs, limit } => {
            let image = loader::load(&path)?;
            let text = std::fs::read_to_string(&sigs).map_err(|e| e.to_string())?;
            let database: sigs::Database =
                serde_json::from_str(&text).map_err(|e| e.to_string())?;
            let matches = sigs::identify(&image, &database);
            for hit in matches.iter().take(limit) {
                println!(
                    "0x{:<10x} {:>6}  {}  (currently: {})",
                    hit.addr,
                    hit.size,
                    hit.matched,
                    hit.current.as_deref().unwrap_or("unnamed")
                );
            }
            println!(
                "identified {} of {} functions",
                matches.len(),
                image.functions.len()
            );
        }
        Command::Decompile {
            path,
            name,
            addr,
            sigs,
        } => {
            let image = loader::load(&path)?;
            let function = select_function(&image, name.as_deref(), addr)?;
            let size = function.size.unwrap_or(256);
            let mut lifted = analysis::lift(&image, function, size)?;
            pass::simplify(&mut lifted);
            let references = refs::collect(&lifted, &image);
            if let Some(path) = sigs {
                let database = load_database(&path)?;
                if let Some(matched) = sigs::lookup(&database, &lifted) {
                    println!("/* identified: {matched} */");
                }
            }
            print!("{}", code::render(&mut lifted, &references, &code::callee_names(&image), code::data_ranges(&image)));
        }
        Command::Lift { path, name, addr } => {
            let image = loader::load(&path)?;
            let function = select_function(&image, name.as_deref(), addr)?;
            let size = function.size.unwrap_or(256);
            let mut lifted = analysis::lift(&image, function, size)?;
            pass::simplify(&mut lifted);
            print!("{}", lifted.render());
        }
    }
    eprintln!("[{} ms]", started.elapsed().as_millis());
    Ok(())
}

fn load_database(path: &std::path::Path) -> Result<sigs::Database, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

fn select_function<'a>(
    image: &'a Image,
    name: Option<&str>,
    addr: Option<u64>,
) -> Result<&'a loader::Function, String> {
    match (name, addr) {
        (Some(name), _) => image
            .find_function_by_name(name)
            .ok_or_else(|| format!("function not found: {name}")),
        (None, Some(addr)) => image
            .functions
            .get(&addr)
            .ok_or_else(|| format!("no function at 0x{addr:x}")),
        (None, None) => Err("specify --name or --addr".to_owned()),
    }
}

fn print_functions(image: &Image, limit: usize) {
    println!("{:<14} {:>10} {:<26} {}", "addr", "size", "name", "source");
    for function in image.functions.values().take(limit) {
        println!(
            "0x{:<12x} {:>10} {:<26} {}",
            function.addr,
            function.size.map(|s| s.to_string()).unwrap_or_else(|| "?".to_owned()),
            function.name.as_deref().unwrap_or("<unnamed>").chars().take(26).collect::<String>(),
            function.source.iter().map(ToString::to_string).collect::<Vec<_>>().join(","),
        );
    }
}

fn print_sections(image: &Image) {
    println!("{:<16} {:>12} {:>10} {:>12}  exec", "section", "vaddr", "size", "file");
    for section in &image.sections {
        println!(
            "{:<16} 0x{:010x} {:>10} {:>12}  {}",
            section.name,
            section.vaddr,
            section.size,
            section.file_offset.map(|o| format!("0x{o:x}")).unwrap_or_else(|| "-".to_owned()),
            if section.executable { "x" } else { "" },
        );
    }
}

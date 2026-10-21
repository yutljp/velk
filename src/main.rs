use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde_json::json;

use velk::error::{Error, Result};
use velk::service::{Binary, Failure};
use velk::sigs::Database;
use velk::{addr, card, mcp, script};

#[derive(Parser)]
#[command(
    name = "velk",
    version,
    about = "Binary analysis engine for LLM agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List the discovered functions.
    Functions {
        path: PathBuf,
        #[arg(long, default_value_t = 40)]
        limit: usize,
        /// Print JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// List the sections.
    Sections { path: PathBuf },
    /// Print a function card as JSON.
    Card {
        path: PathBuf,
        /// Name or address of the function.
        function: String,
        /// Approximate size of the card in tokens.
        #[arg(long, default_value_t = card::DEFAULT_BUDGET)]
        budget: usize,
        #[arg(long)]
        signatures: Option<PathBuf>,
    },
    /// Print pseudo-C for one function.
    Decompile {
        path: PathBuf,
        /// Name or address of the function.
        function: String,
        #[arg(long)]
        signatures: Option<PathBuf>,
    },
    /// Print the disassembly of one function.
    Disasm {
        path: PathBuf,
        /// Name or address of the function.
        function: String,
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Print the optimized IR of one function.
    Ir {
        path: PathBuf,
        /// Name or address of the function.
        function: String,
    },
    /// Build a signature database from the named functions.
    BuildSignatures {
        path: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Match functions against a signature database.
    Identify {
        path: PathBuf,
        #[arg(long)]
        signatures: PathBuf,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Run a JavaScript file against the script API.
    Run { script: PathBuf },
    /// Serve the script API over MCP on standard input and output.
    Mcp,
}

/// Lets a closed pipe end the process quietly, as for other command-line
/// tools, instead of failing the next write.
#[cfg(unix)]
fn exit_on_closed_pipe() {
    unsafe extern "C" {
        fn signal(signum: i32, handler: usize) -> usize;
    }
    // SIGPIPE is 13 and the default action 0 on Linux and macOS.
    unsafe {
        signal(13, 0);
    }
}

fn main() -> ExitCode {
    #[cfg(unix)]
    exit_on_closed_pipe();
    match run(Cli::parse().command) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> Result<ExitCode> {
    match command {
        Command::Functions { path, limit, json } => {
            let binary = Binary::open(&path)?;
            if json {
                print_functions_json(&binary, limit);
            } else {
                print_functions(&binary, limit);
            }
        }
        Command::Sections { path } => print_sections(&Binary::open(&path)?),
        Command::Card {
            path,
            function,
            budget,
            signatures,
        } => {
            let signatures = signatures.as_deref().map(Database::load).transpose()?;
            let mut binary = Binary::open(&path)?;
            let addr = binary.find(&function)?.addr;
            let card = binary.card(addr, budget, signatures.as_ref())?;
            println!("{:#}", json!(card));
        }
        Command::Decompile {
            path,
            function,
            signatures,
        } => {
            let signatures = signatures.as_deref().map(Database::load).transpose()?;
            let mut binary = Binary::open(&path)?;
            let addr = binary.find(&function)?.addr;
            print!("{}", binary.decompile(addr, signatures.as_ref())?);
        }
        Command::Disasm {
            path,
            function,
            limit,
        } => {
            let binary = Binary::open(&path)?;
            let addr = binary.find(&function)?.addr;
            for line in binary.disasm(addr, limit.unwrap_or(usize::MAX))? {
                println!("{line}");
            }
        }
        Command::Ir { path, function } => {
            let mut binary = Binary::open(&path)?;
            let addr = binary.find(&function)?.addr;
            print!("{}", binary.analysis(addr)?.ir.render());
        }
        Command::BuildSignatures { path, output } => {
            let build = Binary::open(&path)?.build_signatures(None)?;
            write_json(&output, &json!(build.database))?;
            eprintln!(
                "{} entries -> {}",
                build.database.entries.len(),
                output.display()
            );
            report_failures(&build.failures);
        }
        Command::Identify {
            path,
            signatures,
            limit,
        } => {
            let database = Database::load(&signatures)?;
            let mut binary = Binary::open(&path)?;
            let identification = binary.identify(&database, None)?;
            for hit in identification.matches.iter().take(limit) {
                println!(
                    "{:<14} {:>6}  {}  (currently: {})",
                    addr::format(hit.addr),
                    hit.size.map_or("?".to_owned(), |size| size.to_string()),
                    hit.matched,
                    hit.current.as_deref().unwrap_or("unnamed")
                );
            }
            println!(
                "identified {} of {} functions",
                identification.matches.len(),
                binary.image().functions.len()
            );
            report_failures(&identification.failures);
        }
        Command::Run { script } => {
            let code = std::fs::read_to_string(&script).map_err(|source| Error::Io {
                path: script.clone(),
                source,
            })?;
            let outcome = script::Engine::new()?.run(&code, None);
            if !outcome.output.is_empty() {
                println!("{}", outcome.output);
            }
            if let Some(error) = outcome.error {
                eprintln!("error: {error}");
                return Ok(ExitCode::FAILURE);
            }
        }
        Command::Mcp => mcp::serve()?,
    }
    Ok(ExitCode::SUCCESS)
}

fn write_json(path: &Path, value: &serde_json::Value) -> Result<()> {
    std::fs::write(path, format!("{value:#}\n")).map_err(|source| Error::Io {
        path: path.to_owned(),
        source,
    })
}

fn report_failures(failures: &[Failure]) {
    if failures.is_empty() {
        return;
    }
    eprintln!("{} functions could not be lifted:", failures.len());
    for failure in failures {
        eprintln!("  {}: {}", addr::format(failure.addr), failure.error);
    }
}

fn print_functions_json(binary: &Binary, limit: usize) {
    let image = binary.image();
    let summary = json!({
        "format": image.format,
        "arch": image.isa,
        "entry": image.entry.map(addr::format),
        "sections": image.sections.len(),
        "functionCount": image.functions.len(),
        "functions": image.functions.values().take(limit).collect::<Vec<_>>(),
    });
    println!("{summary:#}");
}

fn print_functions(binary: &Binary, limit: usize) {
    let image = binary.image();
    println!(
        "format: {}, arch: {}, entry: {}, sections: {}, functions: {}, named: {}",
        image.format,
        image.isa,
        image.entry.map_or("-".to_owned(), addr::format),
        image.sections.len(),
        image.functions.len(),
        image
            .functions
            .values()
            .filter(|f| f.name.is_some())
            .count(),
    );
    println!("{:<14} {:>10} {:<26} sources", "addr", "size", "name");
    for function in image.functions.values().take(limit) {
        let name: String = function
            .name
            .as_deref()
            .unwrap_or("<unnamed>")
            .chars()
            .take(26)
            .collect();
        let sources: Vec<String> = function.sources.iter().map(ToString::to_string).collect();
        println!(
            "{:<14} {:>10} {:<26} {}",
            addr::format(function.addr),
            function
                .size
                .map_or("?".to_owned(), |size| size.to_string()),
            name,
            sources.join(","),
        );
    }
}

fn print_sections(binary: &Binary) {
    println!(
        "{:<16} {:>12} {:>10} {:>12}  exec",
        "section", "addr", "size", "file"
    );
    for section in &binary.image().sections {
        println!(
            "{:<16} 0x{:010x} {:>10} {:>12}  {}",
            section.name,
            section.vaddr,
            section.size,
            section.file_offset.map_or("-".to_owned(), addr::format),
            if section.executable { "x" } else { "" },
        );
    }
}

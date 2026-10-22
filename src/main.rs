mod terminal;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::builder::{
    Styles,
    styling::{AnsiColor, Style},
};
use clap::{Parser, Subcommand};
use serde_json::json;

use terminal::{Language, Terminal};

use velk::error::{Error, Result};
use velk::service::{Binary, Failure};
use velk::sigs::Database;
use velk::{addr, card, mcp, script};

const HELP_STYLES: Styles = Styles::styled()
    .header(Style::new().bold())
    .usage(Style::new().bold())
    .literal(AnsiColor::Cyan.on_default())
    .placeholder(AnsiColor::Cyan.on_default());

#[derive(Parser)]
#[command(
    name = "velk",
    version,
    about = "Binary analysis for terminals and agents",
    styles = HELP_STYLES,
    after_help = "Examples:\n  velk functions app.elf\n  velk decompile app.elf main\n  velk -d app.elf main\n\nUse 'velk <COMMAND> --help' for command-specific options."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List the discovered functions.
    #[command(after_help = "Example:\n  velk functions app.elf --limit 100")]
    Functions {
        /// Binary file to analyze.
        path: PathBuf,
        /// Maximum number of functions to show.
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
    #[command(
        after_help = "Examples:\n  velk decompile app.elf main\n  velk decompile app.elf 0x401000"
    )]
    Decompile {
        /// Binary file to analyze.
        path: PathBuf,
        /// Name or address of the function.
        function: String,
        #[arg(long)]
        signatures: Option<PathBuf>,
    },
    /// Print the disassembly of one function.
    #[command(
        short_flag = 'd',
        long_flag = "disasm",
        after_help = "Examples:\n  velk -d app.elf main\n  velk --disasm app.elf 0x401000\n  velk disasm app.elf main --limit 20"
    )]
    Disasm {
        /// Binary file to analyze.
        path: PathBuf,
        /// Name or address of the function.
        function: String,
        /// Maximum number of disassembly lines to show.
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
            eprintln!("{} {error}", Terminal::stderr().error("error:"));
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
            let code = binary.decompile(addr, signatures.as_ref())?;
            print_code(&binary, addr, &function, &code, Language::C);
        }
        Command::Disasm {
            path,
            function,
            limit,
        } => {
            let binary = Binary::open(&path)?;
            let addr = binary.find(&function)?.addr;
            let listing = binary.disasm(addr, limit.unwrap_or(usize::MAX))?;
            if Terminal::stdout().interactive() {
                let code: String = listing.iter().map(|line| format!("{line}\n")).collect();
                print_code(&binary, addr, &function, &code, Language::Disassembly);
            } else {
                for line in listing {
                    println!("{line}");
                }
            }
        }
        Command::Ir { path, function } => {
            let mut binary = Binary::open(&path)?;
            let addr = binary.find(&function)?.addr;
            let code = binary.analysis(addr)?.ir.render();
            print_code(&binary, addr, &function, &code, Language::Ir);
        }
        Command::BuildSignatures { path, output } => {
            let build = Binary::open(&path)?.build_signatures(None)?;
            write_json(&output, &json!(build.database))?;
            eprintln!(
                "{}",
                Terminal::stderr().success(&format!(
                    "{} entries -> {}",
                    build.database.entries.len(),
                    output.display(),
                )),
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
            let terminal = Terminal::stdout();
            if terminal.interactive() {
                println!(
                    "{}  {}",
                    terminal.heading("Identified functions"),
                    binary.path().display()
                );
                println!(
                    "{}\n",
                    terminal.muted(&format!(
                        "{} · {}",
                        binary.image().format,
                        binary.image().isa
                    ))
                );
                println!(
                    "{}",
                    terminal.heading(&format!(
                        "{:<18} {:>10}  Match (current name)",
                        "Address", "Size"
                    ))
                );
            }
            for hit in identification.matches.iter().take(limit) {
                if terminal.interactive() {
                    println!(
                        "{} {:>10}  {}  (currently: {})",
                        terminal.address(&format!("{:<18}", addr::format(hit.addr))),
                        hit.size.map_or("?".to_owned(), |size| size.to_string()),
                        hit.matched,
                        hit.current.as_deref().unwrap_or("unnamed"),
                    );
                    continue;
                }
                println!(
                    "{:<14} {:>6}  {}  (currently: {})",
                    addr::format(hit.addr),
                    hit.size.map_or("?".to_owned(), |size| size.to_string()),
                    hit.matched,
                    hit.current.as_deref().unwrap_or("unnamed")
                );
            }
            if terminal.interactive() {
                println!();
            }
            println!(
                "identified {} of {} functions",
                identification.matches.len(),
                binary.image().functions.len()
            );
            if terminal.interactive() {
                println!();
            }
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
    let terminal = Terminal::stderr();
    eprintln!(
        "{}",
        terminal.warning(&format!(
            "{} functions could not be lifted:",
            failures.len()
        ))
    );
    for failure in failures {
        eprintln!(
            "  {}: {}",
            terminal.address(&addr::format(failure.addr)),
            failure.error
        );
    }
}

fn print_code(binary: &Binary, addr: u64, requested: &str, code: &str, language: Language) {
    let terminal = Terminal::stdout();
    if !terminal.interactive() {
        print!("{code}");
        return;
    }
    let name = binary
        .image()
        .functions
        .get(&addr)
        .and_then(|function| function.name.as_deref())
        .unwrap_or(requested);
    let title = match language {
        Language::C => "Pseudo-C",
        Language::Ir => "IR",
        Language::Disassembly => "Disassembly",
    };
    let metadata = format!(
        "{} · {} · {}",
        binary.path().display(),
        binary.image().isa,
        addr::format(addr),
    );
    print!(
        "{}",
        terminal.block(&format!("{title}  {name}"), &metadata, code, language)
    );
}

fn print_functions_terminal(binary: &Binary, limit: usize, terminal: Terminal) {
    let image = binary.image();
    let named = image
        .functions
        .values()
        .filter(|function| function.name.is_some())
        .count();
    println!(
        "{}  {}",
        terminal.heading("Functions"),
        binary.path().display()
    );
    println!(
        "{}",
        terminal.muted(&format!(
            "{} · {} · entry {} · {} sections",
            image.format,
            image.isa,
            image.entry.map_or("-".to_owned(), addr::format),
            image.sections.len(),
        ))
    );
    println!(
        "{}\n",
        terminal.muted(&format!(
            "{} functions · {named} named",
            image.functions.len()
        ))
    );
    println!(
        "{}",
        terminal.heading(&format!(
            "{:<18} {:>10}  {:<22}  Name",
            "Address", "Size", "Sources",
        ))
    );
    for function in image.functions.values().take(limit) {
        let sources = function
            .sources
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{} {:>10}  {}  {}",
            terminal.address(&format!("{:<18}", addr::format(function.addr))),
            function
                .size
                .map_or("?".to_owned(), |size| size.to_string()),
            terminal.muted(&format!("{sources:<22}")),
            function.name.as_deref().unwrap_or("<unnamed>"),
        );
    }
    println!();
    let shown = image.functions.len().min(limit);
    if shown < image.functions.len() {
        println!(
            "{}\n",
            terminal.muted(&format!(
                "Showing {shown} of {} functions",
                image.functions.len()
            ))
        );
    }
}

fn print_sections_terminal(binary: &Binary, terminal: Terminal) {
    let image = binary.image();
    println!(
        "{}  {}",
        terminal.heading("Sections"),
        binary.path().display()
    );
    println!(
        "{}\n",
        terminal.muted(&format!(
            "{} · {} · {} sections",
            image.format,
            image.isa,
            image.sections.len()
        ))
    );
    println!(
        "{}",
        terminal.heading(&format!(
            "{:<18} {:>10} {:>14}  {:<4} Section",
            "Address", "Size", "File", "Exec",
        ))
    );
    for section in &image.sections {
        println!(
            "{} {:>10} {:>14}  {:<4} {}",
            terminal.address(&format!("{:<18}", addr::format(section.vaddr))),
            section.size,
            section.file_offset.map_or("-".to_owned(), addr::format),
            if section.executable { "x" } else { "" },
            section.name,
        );
    }
    println!();
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
    let terminal = Terminal::stdout();
    if terminal.interactive() {
        print_functions_terminal(binary, limit, terminal);
        return;
    }
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
    let terminal = Terminal::stdout();
    if terminal.interactive() {
        print_sections_terminal(binary, terminal);
        return;
    }
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

#[cfg(test)]
mod tests {
    use super::{Cli, Command};
    use clap::Parser;
    use clap::error::ErrorKind;
    use std::path::Path;

    #[test]
    fn disassembly_flag_names_select_the_existing_command() {
        for selection in ["disasm", "-d", "--disasm"] {
            for function in ["sum3", "0x1e0"] {
                for limited in [false, true] {
                    let mut args = vec!["velk", selection, "binary", function];
                    if limited {
                        args.extend(["--limit", "12"]);
                    }
                    let Command::Disasm {
                        path,
                        function: selected,
                        limit,
                    } = Cli::try_parse_from(args).unwrap().command
                    else {
                        panic!("expected disassembly command");
                    };
                    assert_eq!(path, Path::new("binary"));
                    assert_eq!(selected, function);
                    assert_eq!(limit, limited.then_some(12));
                }
            }
        }
    }

    #[test]
    fn disassembly_flag_names_keep_required_operands() {
        for selection in ["disasm", "-d", "--disasm"] {
            for args in [vec!["velk", selection], vec!["velk", selection, "binary"]] {
                let error = match Cli::try_parse_from(args) {
                    Ok(_) => panic!("expected missing operands"),
                    Err(error) => error,
                };
                assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
            }
        }
    }

    #[test]
    fn disassembly_flag_names_are_not_global_options() {
        for args in [
            vec!["velk", "mcp", "-d"],
            vec!["velk", "run", "script.js", "--disasm"],
            vec!["velk", "decompile", "binary", "sum3", "-d"],
            vec!["velk", "-d", "binary", "sum3", "--json"],
            vec!["velk", "-d", "--disasm", "binary", "sum3"],
        ] {
            let error = match Cli::try_parse_from(args) {
                Ok(_) => panic!("expected unsupported option"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), ErrorKind::UnknownArgument);
        }
    }
}

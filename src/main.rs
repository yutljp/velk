#![cfg_attr(not(test), deny(clippy::missing_assert_message))]

mod terminal;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::builder::{
    Styles,
    styling::{AnsiColor, Style},
};
use clap::{ArgGroup, Parser};
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
    override_usage = "velk <OPERATION> [OPTIONS] [INPUT] [FUNCTION]",
    group(ArgGroup::new("operation").required(true).multiple(false).args([
        "annotate", "annotation", "annotations", "unannotate", "export_project", "import_project", "origins",
        "functions", "sections", "card", "decompile", "disasm", "ir",
        "build_signatures", "identify", "run", "mcp", "xrefs", "callers", "callees", "path", "strings", "constants", "summary"
    ])),
    group(ArgGroup::new("multi_target").args(["decompile", "path"])),
    group(ArgGroup::new("graph").args(["callers", "callees", "path"])),
    after_help = "Examples:\n  velk -f app.elf\n  velk -D app.elf main\n  velk --disasm app.elf 0x401000 --limit 20\n  velk --build-signatures app.elf --output signatures.json\n  velk -r analysis.js\n  velk --annotations app.elf\n  velk --xrefs app.elf main\n  velk --path app.elf main helper --depth 4\n  velk --strings app.elf --contains hello\n\nChoose one operation. Use --help to list its arguments and options.\nProject and annotation operations return JSON results and JSON errors after argument parsing."
)]
struct Cli {
    /// Select a Mach-O architecture (default: host architecture).
    #[arg(long, value_enum, conflicts_with_all = ["run", "mcp"])]
    arch: Option<velk::loader::Architecture>,
    /// Set one annotation from a JSON object.
    #[arg(long, help_heading = "Operations (choose one)")]
    annotate: bool,
    /// Get one annotation by its JSON target.
    #[arg(long, help_heading = "Operations (choose one)")]
    annotation: bool,
    /// List persistent annotations as JSON.
    #[arg(long, help_heading = "Operations (choose one)")]
    annotations: bool,
    /// Remove one annotation by its JSON target.
    #[arg(long, help_heading = "Operations (choose one)")]
    unannotate: bool,
    /// Export persistent annotations as JSON.
    #[arg(long, help_heading = "Operations (choose one)")]
    export_project: bool,
    /// Import a project from a JSON file.
    #[arg(long, help_heading = "Operations (choose one)")]
    import_project: bool,
    /// List stable parameter and local storage targets for a function.
    #[arg(long, help_heading = "Operations (choose one)")]
    origins: bool,
    /// Annotation file location; defaults to <binary>.velk.json.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["run", "mcp"])]
    project: Option<PathBuf>,
    /// List the discovered functions.
    #[arg(short = 'f', long, help_heading = "Operations (choose one)")]
    functions: bool,
    /// List the sections.
    #[arg(short = 's', long, help_heading = "Operations (choose one)")]
    sections: bool,
    /// Print a function card as JSON.
    #[arg(short = 'c', long, help_heading = "Operations (choose one)")]
    card: bool,
    /// Print pseudo-C for one function.
    #[arg(short = 'D', long, help_heading = "Operations (choose one)")]
    decompile: bool,
    /// Print the disassembly of one function.
    #[arg(short = 'd', long, help_heading = "Operations (choose one)")]
    disasm: bool,
    /// Print the optimized IR of one function.
    #[arg(short = 'i', long, help_heading = "Operations (choose one)")]
    ir: bool,
    /// Build a signature database from the named functions.
    #[arg(short = 'b', long, help_heading = "Operations (choose one)")]
    build_signatures: bool,
    /// Match functions against a signature database.
    #[arg(short = 'I', long, help_heading = "Operations (choose one)")]
    identify: bool,
    /// Run a JavaScript file against the script API.
    #[arg(short = 'r', long, help_heading = "Operations (choose one)")]
    run: bool,
    /// Serve the script API over MCP on standard input and output.
    #[arg(short = 'm', long, help_heading = "Operations (choose one)")]
    mcp: bool,
    /// Code and data references, as JSON.
    #[arg(long, help_heading = "Operations (choose one)")]
    xrefs: bool,
    /// Callers (default depth: 1), as JSON.
    #[arg(long, help_heading = "Operations (choose one)")]
    callers: bool,
    /// Callees (default depth: 1), as JSON.
    #[arg(long, help_heading = "Operations (choose one)")]
    callees: bool,
    /// Shortest call path (default depth: 32), as JSON.
    #[arg(long, help_heading = "Operations (choose one)")]
    path: bool,
    /// Detected strings with references, as JSON.
    #[arg(long, help_heading = "Operations (choose one)")]
    strings: bool,
    /// Matching decoded instruction immediates, as JSON.
    #[arg(long, help_heading = "Operations (choose one)")]
    constants: bool,
    /// Compact function summary, as JSON.
    #[arg(long, help_heading = "Operations (choose one)")]
    summary: bool,
    /// References originating in the target function; only with --xrefs.
    #[arg(long, requires = "xrefs", conflicts_with_all = ["functions", "sections", "card", "decompile", "disasm", "ir", "build_signatures", "identify", "run", "mcp", "callers", "callees", "path", "strings", "constants", "summary"])]
    from: bool,
    /// Maximum call depth; only with --callers, --callees or --path.
    #[arg(long, requires = "graph", conflicts_with_all = ["functions", "sections", "card", "decompile", "disasm", "ir", "build_signatures", "identify", "run", "mcp", "xrefs", "strings", "constants", "summary"])]
    depth: Option<usize>,
    /// Case-sensitive substring; only with --strings.
    #[arg(long, requires = "strings", conflicts_with_all = ["functions", "sections", "card", "decompile", "disasm", "ir", "build_signatures", "identify", "run", "mcp", "xrefs", "callers", "callees", "path", "constants", "summary"])]
    contains: Option<String>,
    /// Binary file, or JavaScript file with --run; required except with --mcp.
    #[arg(
        value_name = "INPUT",
        required_unless_present = "mcp",
        conflicts_with = "mcp"
    )]
    input: Option<PathBuf>,
    /// Function, address, constant, annotation/target JSON, or project import file.
    #[arg(
        value_name = "FUNCTION",
        required_if_eq_any([
            ("annotate", "true"), ("annotation", "true"), ("unannotate", "true"), ("import_project", "true"), ("origins", "true"),
            ("card", "true"), ("decompile", "true"),
            ("disasm", "true"), ("ir", "true"), ("xrefs", "true"), ("callers", "true"), ("callees", "true"), ("path", "true"), ("constants", "true"), ("summary", "true")
        ]),
        conflicts_with_all = ["functions", "sections", "build_signatures", "identify", "run", "mcp", "strings", "annotations", "export_project"]
    )]
    function: Option<String>,
    /// Destination for --path, or a second function to decompile.
    #[arg(
        value_name = "FUNCTION",
        requires = "multi_target",
        required_if_eq("path", "true"),
        conflicts_with_all = ["functions", "sections", "card", "disasm", "ir", "build_signatures", "identify", "run", "mcp", "xrefs", "callers", "callees", "strings", "constants", "summary"])]
    destination: Option<String>,
    /// Additional functions to decompile; use '*' for all functions.
    #[arg(value_name = "FUNCTION", requires = "decompile", conflicts_with_all = ["functions", "sections", "card", "disasm", "ir", "build_signatures", "identify", "run", "mcp", "xrefs", "callers", "callees", "path", "strings", "constants", "summary"])]
    additional_functions: Vec<String>,
    /// Maximum functions (default: 40), matches (default: 100), or instructions (default: all).
    #[arg(
        long,
        value_name = "N",
        conflicts_with_all = ["annotate", "annotation", "annotations", "unannotate", "export_project", "import_project", "origins", "xrefs", "callers", "callees", "path", "strings", "constants", "summary", "sections", "card", "decompile", "ir", "build_signatures", "run", "mcp"]
    )]
    limit: Option<usize>,
    #[arg(
        long,
        value_name = "TOKENS",
        conflicts_with_all = ["annotate", "annotation", "annotations", "unannotate", "export_project", "import_project", "origins", "xrefs", "callers", "callees", "path", "strings", "constants", "summary", "functions", "sections", "decompile", "disasm", "ir", "build_signatures", "identify", "run", "mcp"],
        help = format!("Approximate card size in tokens (default: {}); only with --card", card::DEFAULT_BUDGET)
    )]
    budget: Option<usize>,
    /// Print the function list as JSON; only with --functions.
    #[arg(
        long,
        conflicts_with_all = ["annotate", "annotation", "annotations", "unannotate", "export_project", "import_project", "origins", "xrefs", "callers", "callees", "path", "strings", "constants", "summary", "sections", "card", "decompile", "disasm", "ir", "build_signatures", "identify", "run", "mcp"]
    )]
    json: bool,
    /// Signature database; required for --identify, optional for --card and --decompile.
    #[arg(
        long,
        value_name = "FILE",
        required_if_eq("identify", "true"),
        conflicts_with_all = ["annotate", "annotation", "annotations", "unannotate", "export_project", "import_project", "origins", "xrefs", "callers", "callees", "path", "strings", "constants", "summary", "functions", "sections", "disasm", "ir", "build_signatures", "run", "mcp"]
    )]
    signatures: Option<PathBuf>,
    /// Signature database to write; required with --build-signatures.
    #[arg(
        long,
        value_name = "FILE",
        required_if_eq("build_signatures", "true"),
        conflicts_with_all = ["annotate", "annotation", "annotations", "unannotate", "export_project", "import_project", "origins", "xrefs", "callers", "callees", "path", "strings", "constants", "summary", "functions", "sections", "card", "decompile", "disasm", "ir", "identify", "run", "mcp"]
    )]
    output: Option<PathBuf>,
}

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
enum Command {
    Navigation {
        path: PathBuf,
        query: velk::xrefs::query::Query,
    },
    Functions {
        path: PathBuf,
        limit: usize,
        json: bool,
    },
    Sections {
        path: PathBuf,
    },
    Card {
        path: PathBuf,
        function: String,
        budget: usize,
        signatures: Option<PathBuf>,
    },
    Decompile {
        path: PathBuf,
        functions: Vec<String>,
        signatures: Option<PathBuf>,
    },
    Disasm {
        path: PathBuf,
        function: String,
        limit: Option<usize>,
    },
    Ir {
        path: PathBuf,
        function: String,
    },
    BuildSignatures {
        path: PathBuf,
        output: PathBuf,
    },
    Identify {
        path: PathBuf,
        signatures: PathBuf,
        limit: usize,
    },
    Run {
        script: PathBuf,
    },
    Mcp,
}

impl Cli {
    fn into_command(self) -> Command {
        if self.xrefs
            || self.callers
            || self.callees
            || self.path
            || self.strings
            || self.constants
            || self.summary
        {
            use velk::xrefs::query::Query;
            let target = self.function.unwrap_or_default();
            let query = if self.xrefs {
                Query::Xrefs {
                    target,
                    from: self.from,
                }
            } else if self.callers {
                Query::Callers {
                    target,
                    depth: self.depth.unwrap_or(1),
                }
            } else if self.callees {
                Query::Callees {
                    target,
                    depth: self.depth.unwrap_or(1),
                }
            } else if self.path {
                Query::Path {
                    from: target,
                    to: self.destination.expect("clap requires a destination"),
                    depth: self.depth.unwrap_or(32),
                }
            } else if self.strings {
                Query::Strings {
                    contains: self.contains,
                }
            } else if self.constants {
                Query::Constants { value: target }
            } else {
                Query::Summary { target }
            };
            return Command::Navigation {
                path: self.input.expect("clap requires input"),
                query,
            };
        }
        match self {
            Self {
                functions: true,
                input: Some(path),
                limit,
                json,
                ..
            } => Command::Functions {
                path,
                limit: limit.unwrap_or(40),
                json,
            },
            Self {
                sections: true,
                input: Some(path),
                ..
            } => Command::Sections { path },
            Self {
                card: true,
                input: Some(path),
                function: Some(function),
                budget,
                signatures,
                ..
            } => Command::Card {
                path,
                function,
                budget: budget.unwrap_or(card::DEFAULT_BUDGET),
                signatures,
            },
            Self {
                decompile: true,
                input: Some(path),
                function: Some(function),
                destination,
                additional_functions,
                signatures,
                ..
            } => Command::Decompile {
                path,
                functions: std::iter::once(function)
                    .chain(destination)
                    .chain(additional_functions)
                    .collect(),
                signatures,
            },
            Self {
                disasm: true,
                input: Some(path),
                function: Some(function),
                limit,
                ..
            } => Command::Disasm {
                path,
                function,
                limit,
            },
            Self {
                ir: true,
                input: Some(path),
                function: Some(function),
                ..
            } => Command::Ir { path, function },
            Self {
                build_signatures: true,
                input: Some(path),
                output: Some(output),
                ..
            } => Command::BuildSignatures { path, output },
            Self {
                identify: true,
                input: Some(path),
                signatures: Some(signatures),
                limit,
                ..
            } => Command::Identify {
                path,
                signatures,
                limit: limit.unwrap_or(100),
            },
            Self {
                run: true,
                input: Some(script),
                ..
            } => Command::Run { script },
            Self { mcp: true, .. } => Command::Mcp,
            _ => unreachable!("clap validates the operation and its arguments"),
        }
    }
}

/// Lets a closed pipe end the process quietly, as for other command-line
/// tools, instead of failing the next write.
#[cfg(unix)]
fn exit_on_closed_pipe() {
    unsafe extern "C" {
        fn signal(signum: i32, handler: usize) -> usize;
    }
    // SAFETY: SIGPIPE is 13 and SIG_DFL is 0 on Linux and macOS; no Rust
    // handler or pointer is passed. The standard library has no signal API.
    unsafe {
        signal(13, 0);
    }
}

fn main() -> ExitCode {
    use clap::CommandFactory;

    #[cfg(unix)]
    exit_on_closed_pipe();
    if std::env::args_os().len() == 1 {
        let _ = Cli::command().print_long_help();
        return ExitCode::from(2);
    }
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            let _ = error.print();
            return ExitCode::SUCCESS;
        }
        Err(mut error) => {
            error.insert(
                clap::error::ContextKind::Usage,
                clap::error::ContextValue::StyledStr(Cli::command().render_usage()),
            );
            let _ = error.print();
            return ExitCode::from(2);
        }
    };
    let project = cli.project.clone();
    let operation = if cli.annotate {
        Some(velk::project::cli::Command::Set {
            json: cli.function.clone().unwrap_or_default(),
        })
    } else if cli.annotation {
        Some(velk::project::cli::Command::Get {
            target: cli.function.clone().unwrap_or_default(),
        })
    } else if cli.annotations {
        Some(velk::project::cli::Command::List)
    } else if cli.unannotate {
        Some(velk::project::cli::Command::Remove {
            target: cli.function.clone().unwrap_or_default(),
        })
    } else if cli.export_project {
        Some(velk::project::cli::Command::Export)
    } else if cli.import_project {
        Some(velk::project::cli::Command::Import {
            file: PathBuf::from(cli.function.clone().unwrap_or_default()),
        })
    } else if cli.origins {
        Some(velk::project::cli::Command::Origins {
            function: cli.function.clone().unwrap_or_default(),
        })
    } else {
        None
    };
    if let Some(command) = operation {
        return match velk::project::cli::execute(velk::project::cli::Cli {
            binary: cli.input.expect("clap requires input"),
            arch: cli.arch,
            project,
            command,
        }) {
            Ok(value) => {
                println!("{value:#}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                let value = match &error {
                    Error::Project(detail) => json!(detail),
                    _ => json!({"code": "analysis_error", "message": error.to_string()}),
                };
                eprintln!("{value}");
                ExitCode::FAILURE
            }
        };
    }
    let arch = cli.arch;
    match run(cli.into_command(), project.as_deref(), arch) {
        Ok(code) => code,
        Err(Error::Project(detail)) => {
            eprintln!("{}", json!(detail));
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("{} {error}", Terminal::stderr().error("error:"));
            ExitCode::FAILURE
        }
    }
}

fn run(
    command: Command,
    project: Option<&Path>,
    arch: Option<velk::loader::Architecture>,
) -> Result<ExitCode> {
    match command {
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
            let binary = Binary::open_with_options(&path, project, arch)?;
            if json {
                print_functions_json(&binary, limit);
            } else {
                print_functions(&binary, limit);
            }
        }
        Command::Sections { path } => {
            print_sections(&Binary::open_with_options(&path, project, arch)?)
        }
        Command::Card {
            path,
            function,
            budget,
            signatures,
        } => {
            let signatures = signatures.as_deref().map(Database::load).transpose()?;
            let mut binary = Binary::open_with_options(&path, project, arch)?;
            let addr = binary.find(&function)?.addr;
            let card = binary.card(addr, budget, signatures.as_ref(), None)?;
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
            let addresses = if functions.iter().any(|function| function == "*") {
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
            let binary = Binary::open_with_options(&path, project, arch)?;
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
            let mut binary = Binary::open_with_options(&path, project, arch)?;
            let addr = binary.find(&function)?.addr;
            let code = binary.analysis(addr, None)?.ir.render();
            print_code(&binary, addr, &function, &code, Language::Ir);
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
                velk::sigs::build(&path, None)?
            };
            write_json(&output, &json!(database))?;
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
            let database = Database::load(&signatures)?;
            let mut binary = Binary::open_with_options(&path, project, arch)?;
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

fn decompile_functions(
    binary: &mut Binary,
    addresses: &[u64],
    title: &str,
    signatures: Option<&Database>,
) -> ExitCode {
    use std::time::{Duration, Instant};

    let mut code = String::new();
    let mut status = ExitCode::SUCCESS;
    for &addr in addresses {
        let deadline = Instant::now() + Duration::from_secs(10);
        match binary.decompile(addr, signatures, Some(deadline)) {
            Ok(text) => code.push_str(&text),
            Err(error) => {
                eprintln!("error: function at 0x{addr:x}: {error}");
                status = ExitCode::FAILURE;
            }
        }
    }
    let code = velk::render::combine(&code);
    let addr = addresses.first().copied().unwrap_or(0);
    print_code(binary, addr, title, &code, Language::C);
    status
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
    let functions = binary.functions();
    let name = functions
        .iter()
        .find(|function| function.addr == addr)
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
    let functions = binary.functions();
    if !image.slices.is_empty() {
        let names: Vec<&str> = image
            .slices
            .iter()
            .map(|slice| slice.arch.as_str())
            .collect();
        println!(
            "slices: {}, selected offset: {:#x}",
            names.join(", "),
            image.slice_offset
        );
    }
    let named = functions
        .iter()
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
    for function in functions.iter().take(limit) {
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
        "slices": image.slices,
        "sliceOffset": image.slice_offset,
        "entry": image.entry.map(addr::format),
        "sections": image.sections.len(),
        "functionCount": image.functions.len(),
        "functions": binary.functions().iter().take(limit).collect::<Vec<_>>(),
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
    let functions = binary.functions();
    println!(
        "format: {}, arch: {}, entry: {}, sections: {}, functions: {}, named: {}",
        image.format,
        image.isa,
        image.entry.map_or("-".to_owned(), addr::format),
        image.sections.len(),
        image.functions.len(),
        functions.iter().filter(|f| f.name.is_some()).count(),
    );
    if !image.slices.is_empty() {
        let names: Vec<&str> = image
            .slices
            .iter()
            .map(|slice| slice.arch.as_str())
            .collect();
        println!(
            "slices: {}, selected offset: {:#x}",
            names.join(", "),
            image.slice_offset
        );
    }
    println!("{:<14} {:>10} {:<26} sources", "addr", "size", "name");
    for function in functions.iter().take(limit) {
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
    use std::path::PathBuf;
    use velk::card;

    const OPERATIONS: [(&str, &str); 10] = [
        ("-f", "--functions"),
        ("-s", "--sections"),
        ("-c", "--card"),
        ("-D", "--decompile"),
        ("-d", "--disasm"),
        ("-i", "--ir"),
        ("-b", "--build-signatures"),
        ("-I", "--identify"),
        ("-r", "--run"),
        ("-m", "--mcp"),
    ];

    fn parse(args: &[&str]) -> Command {
        Cli::try_parse_from(std::iter::once("velk").chain(args.iter().copied()))
            .unwrap()
            .into_command()
    }

    fn error(args: &[&str]) -> clap::Error {
        match Cli::try_parse_from(std::iter::once("velk").chain(args.iter().copied())) {
            Ok(_) => panic!("expected invalid arguments: {args:?}"),
            Err(error) => error,
        }
    }

    #[test]
    fn project_flags_share_the_operation_parser() {
        for flag in [
            "--annotate",
            "--annotation",
            "--unannotate",
            "--import-project",
            "--origins",
        ] {
            assert!(
                Cli::try_parse_from([
                    "velk",
                    flag,
                    "binary",
                    "value",
                    "--project",
                    "annotations.json"
                ])
                .is_ok()
            );
            assert!(Cli::try_parse_from(["velk", flag, "binary"]).is_err());
        }
        for flag in [
            "--annotate",
            "--annotation",
            "--annotations",
            "--unannotate",
            "--export-project",
            "--import-project",
            "--origins",
        ] {
            assert!(Cli::try_parse_from(["velk", flag, "binary", "--functions"]).is_err());
            assert!(Cli::try_parse_from(["velk", flag, "binary", "--json"]).is_err());
            assert!(Cli::try_parse_from(["velk", flag, "binary", "--limit", "2"]).is_err());
        }
        assert!(Cli::try_parse_from(["velk", "--annotations", "binary"]).is_ok());
        assert!(Cli::try_parse_from(["velk", "--export-project", "binary"]).is_ok());
        assert!(Cli::try_parse_from(["velk", "project", "binary", "list"]).is_err());
    }

    #[test]
    fn navigation_operations_validate_arguments() {
        use velk::xrefs::query::Query;
        assert_eq!(
            parse(&["--path", "binary", "a", "b"]),
            Command::Navigation {
                path: PathBuf::from("binary"),
                query: Query::Path {
                    from: "a".into(),
                    to: "b".into(),
                    depth: 32
                },
            }
        );
        assert_eq!(
            parse(&["binary", "--xrefs", "a", "--from"]),
            Command::Navigation {
                path: PathBuf::from("binary"),
                query: Query::Xrefs {
                    target: "a".into(),
                    from: true
                },
            }
        );
        for flag in [
            "--xrefs",
            "--callers",
            "--callees",
            "--path",
            "--constants",
            "--summary",
        ] {
            error(&[flag, "binary"]);
            error(&[flag, "binary", "a", "--functions"]);
            error(&[flag, "binary", "a", "--json"]);
            error(&[flag, "binary", "a", "--limit", "2"]);
            error(&[flag.trim_start_matches('-'), "binary", "a"]);
        }
        for args in [
            vec!["--path", "binary", "a", "b", "c"],
            vec!["--summary", "binary", "a", "b"],
            vec!["--strings", "binary", "a"],
            vec!["--strings", "binary", "--from"],
            vec!["--summary", "binary", "a", "--depth", "2"],
            vec!["--xrefs", "binary", "a", "--contains", "hi"],
        ] {
            error(&args);
        }
        for args in [
            vec!["--callers", "binary", "a", "--depth", "0"],
            vec!["--callees", "binary", "a"],
            vec!["--strings", "binary", "--contains", "hi"],
            vec!["--constants", "binary", "0x12"],
            vec!["--summary", "binary", "a"],
        ] {
            parse(&args);
        }
    }

    #[test]
    fn short_and_long_operations_select_the_same_command() {
        let cases = [
            (
                vec!["binary", "--limit", "12", "--json"],
                Command::Functions {
                    path: PathBuf::from("binary"),
                    limit: 12,
                    json: true,
                },
            ),
            (
                vec!["binary"],
                Command::Sections {
                    path: PathBuf::from("binary"),
                },
            ),
            (
                vec![
                    "binary",
                    "sum3",
                    "--budget",
                    "360",
                    "--signatures",
                    "db.json",
                ],
                Command::Card {
                    path: PathBuf::from("binary"),
                    function: "sum3".into(),
                    budget: 360,
                    signatures: Some(PathBuf::from("db.json")),
                },
            ),
            (
                vec!["binary", "0x1e0", "--signatures", "db.json"],
                Command::Decompile {
                    path: PathBuf::from("binary"),
                    functions: vec!["0x1e0".into()],
                    signatures: Some(PathBuf::from("db.json")),
                },
            ),
            (
                vec!["binary", "sum3", "--limit", "12"],
                Command::Disasm {
                    path: PathBuf::from("binary"),
                    function: "sum3".into(),
                    limit: Some(12),
                },
            ),
            (
                vec!["binary", "sum3"],
                Command::Ir {
                    path: PathBuf::from("binary"),
                    function: "sum3".into(),
                },
            ),
            (
                vec!["binary", "--output", "db.json"],
                Command::BuildSignatures {
                    path: PathBuf::from("binary"),
                    output: PathBuf::from("db.json"),
                },
            ),
            (
                vec!["binary", "--signatures", "db.json", "--limit", "12"],
                Command::Identify {
                    path: PathBuf::from("binary"),
                    signatures: PathBuf::from("db.json"),
                    limit: 12,
                },
            ),
            (
                vec!["script.js"],
                Command::Run {
                    script: PathBuf::from("script.js"),
                },
            ),
            (vec![], Command::Mcp),
        ];
        for ((short, long), (operands, expected)) in OPERATIONS.into_iter().zip(cases) {
            for flag in [short, long] {
                let args: Vec<_> = std::iter::once(flag)
                    .chain(operands.iter().copied())
                    .collect();
                assert_eq!(parse(&args), expected, "{flag}");
            }
        }
    }

    #[test]
    fn operation_defaults_are_preserved() {
        assert_eq!(
            parse(&["-f", "binary"]),
            Command::Functions {
                path: PathBuf::from("binary"),
                limit: 40,
                json: false,
            }
        );
        assert_eq!(
            parse(&["-c", "binary", "sum3"]),
            Command::Card {
                path: PathBuf::from("binary"),
                function: "sum3".into(),
                budget: card::DEFAULT_BUDGET,
                signatures: None,
            }
        );
        assert_eq!(
            parse(&["-d", "binary", "sum3"]),
            Command::Disasm {
                path: PathBuf::from("binary"),
                function: "sum3".into(),
                limit: None,
            }
        );
        assert_eq!(
            parse(&["-I", "binary", "--signatures", "db.json"]),
            Command::Identify {
                path: PathBuf::from("binary"),
                signatures: PathBuf::from("db.json"),
                limit: 100,
            }
        );
    }

    #[test]
    fn every_pair_of_operations_conflicts() {
        for (index, (short, _)) in OPERATIONS.iter().enumerate() {
            for (_, long) in OPERATIONS.iter().skip(index + 1) {
                assert_eq!(error(&[short, long]).kind(), ErrorKind::ArgumentConflict);
            }
        }
    }

    #[test]
    fn operations_require_their_own_operands() {
        for (_, flag) in OPERATIONS.into_iter().take(9) {
            assert_eq!(error(&[flag]).kind(), ErrorKind::MissingRequiredArgument);
        }
        for flag in ["--card", "--decompile", "--disasm", "--ir"] {
            assert_eq!(
                error(&[flag, "binary"]).kind(),
                ErrorKind::MissingRequiredArgument
            );
        }
        for flag in ["--build-signatures", "--identify"] {
            assert_eq!(
                error(&[flag, "binary"]).kind(),
                ErrorKind::MissingRequiredArgument
            );
        }
    }

    #[test]
    fn local_options_and_extra_operands_are_rejected() {
        for args in [
            vec!["-s", "binary", "--limit", "1"],
            vec!["-d", "binary", "sum3", "--budget", "20"],
            vec!["-D", "binary", "sum3", "--json"],
            vec!["-d", "binary", "sum3", "--signatures", "db.json"],
            vec!["-f", "binary", "--output", "db.json"],
            vec!["-f", "binary", "sum3"],
            vec!["-s", "binary", "sum3"],
            vec!["-b", "binary", "sum3", "--output", "db.json"],
            vec!["-I", "binary", "sum3", "--signatures", "db.json"],
            vec!["-r", "script.js", "sum3"],
            vec!["-m", "binary"],
            vec!["-m", "--limit", "1"],
        ] {
            error(&args);
        }
    }

    #[test]
    fn single_operation_options_conflict_with_every_other_operation() {
        for (allowed, option) in [
            ("--card", vec!["--budget", "20"]),
            ("--functions", vec!["--json"]),
            ("--build-signatures", vec!["--output", "db.json"]),
        ] {
            for (_, operation) in OPERATIONS {
                if operation == allowed {
                    continue;
                }
                let mut args = vec![operation];
                if operation != "--mcp" {
                    args.push("binary");
                }
                if matches!(operation, "--card" | "--decompile" | "--disasm" | "--ir") {
                    args.push("sum3");
                }
                if operation == "--build-signatures" {
                    args.extend(["--output", "db.json"]);
                }
                if operation == "--identify" {
                    args.extend(["--signatures", "db.json"]);
                }
                args.extend(option.iter().copied());
                assert_eq!(error(&args).kind(), ErrorKind::ArgumentConflict, "{args:?}");
            }
        }
    }

    #[test]
    fn an_operation_flag_is_required() {
        assert_eq!(error(&[]).kind(), ErrorKind::MissingRequiredArgument);
        assert_eq!(
            error(&["binary", "sum3"]).kind(),
            ErrorKind::MissingRequiredArgument
        );
        error(&["binary", "--json"]);
        error(&["binary", "--budget", "20"]);
        for (_, flag) in OPERATIONS {
            assert!(Cli::try_parse_from(["velk", flag.trim_start_matches('-')]).is_err());
        }
        assert!(Cli::try_parse_from(["velk", "help"]).is_err());
    }

    #[test]
    fn operation_flags_and_positional_delimiters_follow_standard_parsing() {
        assert_eq!(
            parse(&["binary", "--functions", "--limit", "2"]),
            Command::Functions {
                path: PathBuf::from("binary"),
                limit: 2,
                json: false,
            }
        );
        assert_eq!(
            parse(&["-f", "--", "functions"]),
            Command::Functions {
                path: PathBuf::from("functions"),
                limit: 40,
                json: false,
            }
        );
        assert_eq!(
            parse(&["-d", "--", "-binary", "-sum3"]),
            Command::Disasm {
                path: PathBuf::from("-binary"),
                function: "-sum3".into(),
                limit: None,
            }
        );
    }

    #[test]
    fn help_is_available_for_every_operation() {
        for args in std::iter::once(vec!["--help"])
            .chain(OPERATIONS.into_iter().map(|(_, flag)| vec![flag, "--help"]))
        {
            let help = error(&args);
            assert_eq!(help.kind(), ErrorKind::DisplayHelp);
            let text = help.to_string();
            assert!(text.contains("Operations (choose one)"));
            assert!(text.contains("INPUT"));
            assert!(text.contains("FUNCTION"));
            assert!(text.contains("Examples:"));
            assert!(text.contains(&format!("default: {}", card::DEFAULT_BUDGET)));
        }
        for flag in ["-V", "--version"] {
            assert_eq!(error(&[flag]).kind(), ErrorKind::DisplayVersion);
            assert_eq!(error(&["-m", flag]).kind(), ErrorKind::DisplayVersion);
        }
    }
}

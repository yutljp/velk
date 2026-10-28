//! Argument definitions, parsing and operation selection.

mod execute;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::builder::Styles;
use clap::builder::styling::{AnsiColor, Style};
use clap::{ArgGroup, Parser};
use velk::card;

pub(super) use execute::run;

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
        "compare", "annotate", "annotation", "annotations", "unannotate", "export_project", "import_project", "origins",
        "api_docs", "functions", "classes", "sections", "card", "decompile", "disasm", "ir",
        "build_signatures", "identify", "run", "mcp", "serve", "emulate", "explore", "xrefs", "callers", "callees", "path", "strings", "constants", "summary", "search", "read_memory", "detect_constants"
    ])),
    group(ArgGroup::new("multi_target").args(["decompile", "path"])),
    group(ArgGroup::new("graph").args(["callers", "callees", "path"])),
    after_help = "Examples:\n  velk -f app.elf\n  velk -D app.elf main\n  velk --disasm app.elf 0x401000 --limit 20\n  velk --build-signatures app.elf --output signatures.json\n  velk -r analysis.js\n  velk --annotations app.elf\n  velk --xrefs app.elf main\n  velk --path app.elf main helper --depth 4\n  velk --strings app.elf --contains hello\n\nChoose one operation. Use --help to list its arguments and options.\nProject and annotation operations return JSON results and JSON errors after argument parsing."
)]
pub(super) struct Cli {
    /// List API topics, or print the documentation for one topic.
    #[arg(long, exclusive = true, num_args = 0..=1, default_missing_value = "", value_name = "TOPIC", help_heading = "Operations (choose one)")]
    api_docs: Option<String>,
    /// Compare INPUT with a second binary supplied as FUNCTION; return JSON.
    #[arg(long, help_heading = "Operations (choose one)")]
    compare: bool,
    /// Copy annotations to matching targets without replacing existing entries.
    #[arg(long, requires = "compare", conflicts_with_all = ["emulate", "explore", "annotate", "annotation", "annotations", "unannotate", "export_project", "import_project", "origins", "functions", "sections", "card", "decompile", "disasm", "ir", "build_signatures", "identify", "run", "mcp", "serve", "xrefs", "callers", "callees", "path", "strings", "constants", "summary"])]
    carry_annotations: bool,
    /// Project file for the second binary; defaults to its sidecar.
    #[arg(long, requires = "compare", value_name = "PATH", conflicts_with_all = ["emulate", "explore", "annotate", "annotation", "annotations", "unannotate", "export_project", "import_project", "origins", "functions", "sections", "card", "decompile", "disasm", "ir", "build_signatures", "identify", "run", "mcp", "serve", "xrefs", "callers", "callees", "path", "strings", "constants", "summary"])]
    other_project: Option<PathBuf>,
    /// Execute a function or address through the IR interpreter; print a text report (or JSON with --json).
    #[arg(long, help_heading = "Operations (choose one)")]
    emulate: bool,
    /// Search for a path to --find from this function or address.
    #[arg(
        long,
        requires = "find",
        value_name = "FUNCTION",
        help_heading = "Operations (choose one)"
    )]
    explore: Option<String>,
    /// Target virtual address (repeatable).
    #[arg(long, requires = "explore", value_parser = crate::parse_address)]
    find: Vec<u64>,
    /// Address whose paths are discarded (repeatable).
    #[arg(long, requires = "explore", value_parser = crate::parse_address)]
    avoid: Vec<u64>,
    /// Number of symbolic stdin bytes.
    #[arg(long, requires = "explore")]
    stdin: Option<usize>,
    /// Initial state and limits as JSON; see velk --api-docs emulation.
    #[arg(long, requires = "emulate", value_name = "JSON", conflicts_with_all = ["compare", "annotate", "annotation", "annotations", "unannotate", "export_project", "import_project", "origins", "functions", "classes", "sections", "card", "decompile", "disasm", "ir", "build_signatures", "identify", "run", "mcp", "serve", "xrefs", "callers", "callees", "path", "strings", "constants", "summary", "search", "read_memory", "detect_constants"])]
    emulation_options: Option<String>,
    /// Instruction set for a headerless input file.
    #[arg(long, value_enum, requires = "load_address", conflicts_with_all = ["arch", "compare", "run", "mcp", "serve"])]
    pub(super) raw_arch: Option<velk::loader::RawArchitecture>,
    /// Virtual address of the first raw input byte (hex or decimal).
    #[arg(long, requires = "raw_arch", value_parser = crate::parse_address)]
    pub(super) load_address: Option<u64>,
    /// Raw entry point (repeatable); defaults to the load address.
    #[arg(long, requires = "raw_arch", value_parser = crate::parse_address)]
    pub(super) entry: Vec<u64>,
    /// Raw byte order (default: little); big-endian code is not supported.
    #[arg(long, requires = "raw_arch", value_enum, default_value = "little")]
    pub(super) raw_byte_order: velk::loader::ByteOrder,
    /// Save a successfully unpacked executable to a new file before analysis.
    #[arg(long, conflicts_with_all = ["run", "mcp", "serve", "compare"])]
    pub(super) save_unpacked: Option<PathBuf>,
    /// Select a Mach-O architecture (default: host architecture).
    #[arg(long, value_enum, conflicts_with_all = ["run", "mcp", "serve"])]
    pub(super) arch: Option<velk::loader::Architecture>,
    /// Set one annotation from a JSON object.
    #[arg(long, help_heading = "Operations (choose one)")]
    pub(super) annotate: bool,
    /// Get one annotation by its JSON target.
    #[arg(long, help_heading = "Operations (choose one)")]
    pub(super) annotation: bool,
    /// List persistent annotations as JSON.
    #[arg(long, help_heading = "Operations (choose one)")]
    pub(super) annotations: bool,
    /// Remove one annotation by its JSON target.
    #[arg(long, help_heading = "Operations (choose one)")]
    pub(super) unannotate: bool,
    /// Export persistent annotations as JSON.
    #[arg(long, help_heading = "Operations (choose one)")]
    pub(super) export_project: bool,
    /// Import a project from a JSON file.
    #[arg(long, help_heading = "Operations (choose one)")]
    pub(super) import_project: bool,
    /// List stable parameter and local storage targets for a function.
    #[arg(long, help_heading = "Operations (choose one)")]
    pub(super) origins: bool,
    /// Analysis cache file; use off to disable (default: `VELK_CACHE` or `<binary>.velk-cache`).
    #[arg(long, value_name = "PATH|off", conflicts_with_all = ["run", "mcp", "serve"])]
    pub(super) cache: Option<String>,
    /// Annotation file location; defaults to <binary>.velk.json.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["run", "mcp", "serve"])]
    pub(super) project: Option<PathBuf>,
    /// List the discovered functions.
    #[arg(short = 'f', long, help_heading = "Operations (choose one)")]
    functions: bool,
    /// List C++ classes, virtual tables and bases as JSON.
    #[arg(long, help_heading = "Operations (choose one)")]
    classes: bool,
    /// List the sections.
    #[arg(short = 's', long, help_heading = "Operations (choose one)")]
    sections: bool,
    /// Print a function card as JSON.
    #[arg(short = 'c', long, help_heading = "Operations (choose one)")]
    card: bool,
    /// Print pseudo-C for selected functions, or all functions when none are specified.
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
    /// Serve the script API as newline-delimited JSON.
    #[arg(long, help_heading = "Operations (choose one)")]
    serve: bool,
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
    /// Disable automatic string recovery in strings output and printed C.
    #[arg(long)]
    pub(super) no_string_decoding: bool,
    /// Matching decoded instruction immediates, as JSON.
    #[arg(long, help_heading = "Operations (choose one)")]
    constants: bool,
    /// Search loaded sections for bytes, text or an integer, as JSON.
    #[arg(long, help_heading = "Operations (choose one)")]
    search: bool,
    /// Read typed values from a loaded address, as JSON.
    #[arg(long, help_heading = "Operations (choose one)")]
    read_memory: bool,
    /// Detect exact standard constant tables and immediate groups, as JSON.
    #[arg(long, help_heading = "Operations (choose one)")]
    detect_constants: bool,
    /// Search encoding (default: hex).
    #[arg(long, requires = "search", value_parser = ["hex", "ascii", "utf16", "integer"])]
    encoding: Option<String>,
    /// Integer search width in bytes; required for integer searches.
    #[arg(long, requires = "search", value_parser = ["1", "2", "4", "8"])]
    width: Option<String>,
    /// Search byte order (default: native).
    #[arg(long, requires = "search", value_parser = ["native", "little", "big"])]
    byte_order: Option<String>,
    /// Inclusive search start address.
    #[arg(long, requires = "search")]
    start: Option<String>,
    /// Exclusive search end address; complete matches must fit before it.
    #[arg(long, requires = "search")]
    end: Option<String>,
    /// Loaded section name to search.
    #[arg(long, requires = "search")]
    section: Option<String>,
    /// Memory type: u8, u16, u32, u64, i8, i16, i32, i64, f32, f64, pointer, cstring, utf16, TYPE[N], or struct NAME.
    #[arg(
        long = "type",
        requires = "read_memory",
        required_if_eq("read_memory", "true")
    )]
    type_name: Option<String>,
    /// Number of memory values to read (default: 1).
    #[arg(long, requires = "read_memory")]
    count: Option<u64>,
    /// Compact function summary, as JSON.
    #[arg(long, help_heading = "Operations (choose one)")]
    summary: bool,
    /// References originating in the target function; only with --xrefs.
    #[arg(long, requires = "xrefs", conflicts_with_all = ["emulate", "explore", "classes", "search", "read_memory", "detect_constants", "functions", "sections", "card", "decompile", "disasm", "ir", "build_signatures", "identify", "run", "mcp", "serve", "callers", "callees", "path", "strings", "constants", "summary"])]
    from: bool,
    /// Maximum call depth; only with --callers, --callees or --path.
    #[arg(long, requires = "graph", conflicts_with_all = ["emulate", "explore", "classes", "search", "read_memory", "detect_constants", "functions", "sections", "card", "decompile", "disasm", "ir", "build_signatures", "identify", "run", "mcp", "serve", "xrefs", "strings", "constants", "summary"])]
    depth: Option<usize>,
    /// Case-sensitive substring; only with --strings.
    #[arg(long, requires = "strings", conflicts_with_all = ["emulate", "explore", "classes", "search", "read_memory", "detect_constants", "functions", "sections", "card", "decompile", "disasm", "ir", "build_signatures", "identify", "run", "mcp", "serve", "xrefs", "callers", "callees", "path", "constants", "summary"])]
    contains: Option<String>,
    /// Binary file, or JavaScript file with --run; omitted with --mcp, --serve or --api-docs.
    #[arg(
        value_name = "INPUT",
        required_unless_present_any = ["mcp", "serve", "api_docs"],
        conflicts_with_all = ["mcp", "serve", "api_docs"]
    )]
    pub(super) input: Option<PathBuf>,
    /// Function, address, constant, second binary, annotation/target JSON, or project import file.
    #[arg(
        value_name = "FUNCTION",
        required_if_eq_any([
            ("compare", "true"),
            ("annotate", "true"), ("annotation", "true"), ("unannotate", "true"), ("import_project", "true"), ("origins", "true"),
            ("emulate", "true"),
            ("card", "true"),
            ("disasm", "true"), ("ir", "true"), ("xrefs", "true"), ("callers", "true"), ("callees", "true"), ("path", "true"), ("constants", "true"), ("summary", "true"), ("search", "true"), ("read_memory", "true")
        ]),
        conflicts_with_all = ["explore", "classes", "functions", "sections", "build_signatures", "identify", "run", "mcp", "serve", "strings", "annotations", "export_project", "detect_constants"]
    )]
    pub(super) function: Option<String>,
    /// Destination for --path, or a second function to decompile.
    #[arg(
        value_name = "FUNCTION",
        requires = "multi_target",
        required_if_eq("path", "true"),
        conflicts_with_all = ["emulate", "explore", "classes", "search", "read_memory", "detect_constants", "functions", "sections", "card", "disasm", "ir", "build_signatures", "identify", "run", "mcp", "serve", "xrefs", "callers", "callees", "strings", "constants", "summary"])]
    destination: Option<String>,
    /// Additional functions to decompile; use '*' for all functions.
    #[arg(value_name = "FUNCTION", requires = "decompile", conflicts_with_all = ["emulate", "explore", "classes", "search", "read_memory", "detect_constants", "functions", "sections", "card", "disasm", "ir", "build_signatures", "identify", "run", "mcp", "serve", "xrefs", "callers", "callees", "path", "strings", "constants", "summary"])]
    additional_functions: Vec<String>,
    /// Maximum functions (default: 40), matches (default: 100), or instructions (default: all).
    #[arg(
        long,
        value_name = "N",
        conflicts_with_all = ["emulate", "explore", "classes", "compare", "search", "read_memory", "detect_constants", "annotate", "annotation", "annotations", "unannotate", "export_project", "import_project", "origins", "xrefs", "callers", "callees", "path", "strings", "constants", "summary", "sections", "card", "decompile", "ir", "build_signatures", "run", "mcp", "serve"]
    )]
    limit: Option<usize>,
    #[arg(
        long,
        value_name = "TOKENS",
        conflicts_with_all = ["emulate", "explore", "classes", "compare", "search", "read_memory", "detect_constants", "annotate", "annotation", "annotations", "unannotate", "export_project", "import_project", "origins", "xrefs", "callers", "callees", "path", "strings", "constants", "summary", "functions", "sections", "decompile", "disasm", "ir", "build_signatures", "identify", "run", "mcp", "serve"],
        help = format!("Approximate card size in tokens (default: {}); only with --card", card::DEFAULT_BUDGET)
    )]
    budget: Option<usize>,
    /// Print function lists or emulation results as JSON.
    #[arg(
        long,
        conflicts_with_all = ["classes", "compare", "search", "read_memory", "detect_constants", "annotate", "annotation", "annotations", "unannotate", "export_project", "import_project", "origins", "xrefs", "callers", "callees", "path", "strings", "constants", "summary", "sections", "card", "decompile", "disasm", "ir", "build_signatures", "identify", "run", "mcp", "serve"]
    )]
    json: bool,
    /// Disable the embedded library signature sets.
    #[arg(long)]
    pub(super) no_default_signatures: bool,
    /// Add a user signature database to the enabled library sets.
    #[arg(
        long,
        value_name = "FILE",
        conflicts_with_all = ["build_signatures", "run", "mcp", "serve", "annotate", "annotation", "annotations", "unannotate", "export_project", "import_project", "origins"]
    )]
    pub(super) signatures: Vec<PathBuf>,
    /// Signature database to write; required with --build-signatures.
    #[arg(
        long,
        value_name = "FILE",
        required_if_eq("build_signatures", "true"),
        conflicts_with_all = ["emulate", "explore", "classes", "compare", "search", "read_memory", "detect_constants", "annotate", "annotation", "annotations", "unannotate", "export_project", "import_project", "origins", "xrefs", "callers", "callees", "path", "strings", "constants", "summary", "functions", "sections", "card", "decompile", "disasm", "ir", "identify", "run", "mcp", "serve"]
    )]
    output: Option<PathBuf>,
}

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(super) enum Command {
    Api {
        topic: String,
    },
    Compare {
        path: PathBuf,
        other: PathBuf,
        other_project: Option<PathBuf>,
        carry_annotations: bool,
    },
    Explore {
        path: PathBuf,
        start: String,
        options: velk::symbolic::Options,
        json: bool,
    },
    Emulate {
        path: PathBuf,
        start: String,
        options: Option<String>,
        json: bool,
    },
    Navigation {
        path: PathBuf,
        query: velk::xrefs::query::Query,
    },
    Functions {
        path: PathBuf,
        limit: usize,
        json: bool,
    },
    Classes {
        path: PathBuf,
    },
    Sections {
        path: PathBuf,
    },
    Card {
        path: PathBuf,
        function: String,
        budget: usize,
    },
    Decompile {
        path: PathBuf,
        functions: Vec<String>,
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
        limit: usize,
    },
    Run {
        script: PathBuf,
    },
    Mcp,
    Serve,
}

impl Cli {
    pub(super) fn into_command(self) -> Command {
        if let Some(topic) = self.api_docs {
            return Command::Api { topic };
        }
        if self.compare {
            return Command::Compare {
                path: self.input.expect("clap requires input"),
                other: PathBuf::from(self.function.expect("clap requires the second binary")),
                other_project: self.other_project,
                carry_annotations: self.carry_annotations,
            };
        }
        if let Some(start) = self.explore {
            let word = |value| velk::emulation::Word::Text(format!("0x{value:x}"));
            return Command::Explore {
                path: self.input.expect("clap requires input"),
                start,
                options: velk::symbolic::Options {
                    find: self.find.into_iter().map(word).collect(),
                    avoid: self.avoid.into_iter().map(word).collect(),
                    stdin: self.stdin.unwrap_or(0),
                    ..Default::default()
                },
                json: self.json,
            };
        }
        if self.emulate {
            return Command::Emulate {
                path: self.input.expect("clap requires input"),
                start: self.function.expect("clap requires a function or address"),
                options: self.emulation_options,
                json: self.json,
            };
        }
        if self.search
            || self.read_memory
            || self.detect_constants
            || self.xrefs
            || self.callers
            || self.callees
            || self.path
            || self.strings
            || self.constants
            || self.summary
        {
            use velk::xrefs::query::Query;
            let target = self.function.unwrap_or_default();
            let query = if self.search {
                Query::Search {
                    pattern: target,
                    options: velk::memory::Search {
                        encoding: self.encoding.unwrap_or_else(|| "hex".to_owned()),
                        width: self
                            .width
                            .map(|width| width.parse().expect("clap restricts integer widths")),
                        byte_order: self.byte_order.unwrap_or_else(|| "native".to_owned()),
                        start: self.start,
                        end: self.end,
                        section: self.section,
                    },
                }
            } else if self.read_memory {
                Query::ReadMemory {
                    target,
                    type_name: self.type_name.expect("clap requires a type"),
                    count: self.count.unwrap_or(1),
                }
            } else if self.detect_constants {
                Query::DetectConstants
            } else if self.xrefs {
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
                    decode: !self.no_string_decoding,
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
                classes: true,
                input: Some(path),
                ..
            } => Command::Classes { path },
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
                ..
            } => Command::Card {
                path,
                function,
                budget: budget.unwrap_or(card::DEFAULT_BUDGET),
            },
            Self {
                decompile: true,
                input: Some(path),
                function,
                destination,
                additional_functions,
                ..
            } => Command::Decompile {
                path,
                functions: function
                    .into_iter()
                    .chain(destination)
                    .chain(additional_functions)
                    .collect(),
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
                limit,
                ..
            } => Command::Identify {
                path,
                limit: limit.unwrap_or(100),
            },
            Self {
                run: true,
                input: Some(script),
                ..
            } => Command::Run { script },
            Self { mcp: true, .. } => Command::Mcp,
            Self { serve: true, .. } => Command::Serve,
            _ => unreachable!("clap validates the operation and its arguments"),
        }
    }
}

pub(super) fn parse() -> Result<Cli, ExitCode> {
    use clap::CommandFactory;

    if std::env::args_os().len() == 1 {
        let _ = Cli::command().print_long_help();
        return Err(ExitCode::from(2));
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
            return Err(ExitCode::SUCCESS);
        }
        Err(mut error) => {
            error.insert(
                clap::error::ContextKind::Usage,
                clap::error::ContextValue::StyledStr(Cli::command().render_usage()),
            );
            let _ = error.print();
            return Err(ExitCode::from(2));
        }
    };
    Ok(cli)
}

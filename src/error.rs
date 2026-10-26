use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("raw input: {0}")]
    Raw(String),
    #[error("packed input: {0}")]
    Packed(String),
    /// An invalid memory request or an unavailable image range or type.
    #[error("memory query: {0}")]
    Memory(String),

    #[error("emulation: {0}")]
    Emulation(String),
    #[error("{0}")]
    Project(crate::project::ProjectError),
    #[error("{}: {source}", path.display())]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{}: {source}; expected an ELF, PE/COFF or Mach-O file", path.display())]
    Object {
        path: PathBuf,
        source: object::Error,
    },
    #[error("{}: not a signature database: {source}", path.display())]
    SignatureFile {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("not a signature database: {0}")]
    SignatureData(serde_json::Error),
    #[error("signature database version {} is not supported; rebuild it (expected {expected})", found.map_or("missing".to_owned(), |v| v.to_string()))]
    SignatureVersion { found: Option<u64>, expected: u32 },
    #[error("Mach-O architecture selection: {0}")]
    Architecture(String),
    #[error("Mach-O fixups: {0}")]
    MachOFixups(String),
    #[error("not an address: \"{0}\" (use 0x-prefixed hex or decimal)")]
    BadAddress(String),
    #[error("no function at 0x{0:x}")]
    NoFunctionAt(u64),
    #[error("no function matches \"{0}\"")]
    NoFunctionNamed(String),
    #[error("no function matches \"{name}\"; binary is stripped; entry {}; use --functions to list addresses", entry.map_or("unavailable".to_owned(), |address| format!("0x{address:x}")))]
    StrippedFunctionName { name: String, entry: Option<u64> },
    #[error(
        "\"{name}\" matches {total} functions: {}{}; pass an exact name or address",
        shown.join(", "),
        if *total > shown.len() { ", ..." } else { "" }
    )]
    AmbiguousName {
        name: String,
        shown: Vec<String>,
        total: usize,
    },
    #[error("function at 0x{addr:x}: {source}")]
    Lift { addr: u64, source: LiftError },
    #[error("standard input or output: {0}")]
    Stdio(std::io::Error),
    #[error("script engine: {0}")]
    Engine(rquickjs::Error),
    #[error("the time allowed ran out")]
    TimedOut,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum LiftError {
    #[error("the instruction set is not supported")]
    UnsupportedIsa,
    #[error("the function's bytes are outside the file")]
    Unreadable,
    #[error("no instruction could be decoded")]
    NoInstructions,
    #[error("the call argument count in the block at 0x{block:x} is unknown")]
    UnknownArguments { block: u64 },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

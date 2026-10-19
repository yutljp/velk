use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{}: {source}", path.display())]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{}: {source}", path.display())]
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
    #[error("not an address: \"{0}\" (use 0x-prefixed hex or decimal)")]
    BadAddress(String),
    #[error("no function at 0x{0:x}")]
    NoFunctionAt(u64),
    #[error("no function matches \"{0}\"")]
    NoFunctionNamed(String),
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
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum LiftError {
    #[error("the instruction set is not supported")]
    UnsupportedIsa,
    #[error("the function's bytes are outside the file")]
    Unreadable,
    #[error("no instruction could be decoded")]
    NoInstructions,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

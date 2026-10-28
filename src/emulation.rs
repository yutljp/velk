//! Bounded execution of loaded machine code through the IR interpreter.

mod memory;
pub(crate) mod tls;
pub(crate) use memory::{HEAP_SIZE, Memory};

use std::collections::BTreeMap;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::service::Binary;

/// An unsigned integer, or a decimal or hexadecimal string for full precision.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum Word {
    /// An integer representable exactly in JavaScript.
    Integer(u64),
    /// A decimal or hexadecimal integer.
    Text(String),
}

impl Word {
    pub(crate) fn value(&self) -> Result<u64> {
        match self {
            Self::Integer(value) if *value < (1 << 53) => Ok(*value),
            Self::Text(text) => match crate::addr::parse(text) {
                Some(value) => Ok(value),
                None => Err(invalid(format!("invalid unsigned integer: {text}"))),
            },
            Self::Integer(_) => Err(invalid("use a string for integers above 2^53 - 1")),
        }
    }
}

/// Bytes or a little-endian integer to place in mapped memory before execution.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemoryWrite {
    /// Start address in the emulated address space.
    pub address: Word,
    /// Raw bytes; mutually exclusive with value and width.
    pub bytes: Option<Vec<u8>>,
    /// Unsigned integer to store.
    pub value: Option<Word>,
    /// Integer width in bytes: 1, 2, 4 or 8.
    pub width: Option<u8>,
}

/// Input bytes, supplied directly or loaded from a file before execution.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Input {
    /// UTF-8 text.
    Text(String),
    /// Hexadecimal byte pairs, with optional ASCII whitespace.
    Hex(String),
    /// File read by the host before execution.
    File(String),
}

impl Input {
    pub(crate) fn bytes(&self) -> Result<Vec<u8>> {
        use std::io::Read;
        let bytes = match self {
            Self::Text(text) => text.as_bytes().to_vec(),
            Self::Hex(text) => {
                let digits: Vec<u8> = text
                    .bytes()
                    .filter(|byte| !byte.is_ascii_whitespace())
                    .collect();
                if !digits.len().is_multiple_of(2) {
                    return Err(invalid("stdin hex needs pairs of digits"));
                }
                let mut bytes = Vec::new();
                for pair in digits.as_chunks::<2>().0 {
                    let (Some(high), Some(low)) = (
                        (pair[0] as char).to_digit(16),
                        (pair[1] as char).to_digit(16),
                    ) else {
                        return Err(invalid("stdin contains an invalid hex digit"));
                    };
                    bytes.push((high * 16 + low) as u8);
                }
                bytes
            }
            Self::File(path) => {
                let file = match std::fs::File::open(path) {
                    Ok(file) => file,
                    Err(error) => return Err(invalid(format!("stdin file {path}: {error}"))),
                };
                let mut bytes = Vec::new();
                if let Err(error) = file.take(HEAP_SIZE + 1).read_to_end(&mut bytes) {
                    return Err(invalid(format!("stdin file {path}: {error}")));
                }
                bytes
            }
        };
        if bytes.len() as u64 > HEAP_SIZE {
            return Err(invalid("stdin exceeds 16 MiB"));
        }
        Ok(bytes)
    }
}

/// How to display bytes read after execution.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReadFormat {
    /// UTF-8 text, replacing invalid sequences.
    #[default]
    String,
    /// An array of byte values.
    Bytes,
    /// Hexadecimal byte pairs.
    Hex,
    /// Unsigned little-endian integers, represented as decimal strings.
    Integers,
}

/// A mapped memory range to read after execution.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemoryRead {
    /// Exactly one of address, symbol and register must be supplied.
    pub address: Option<Word>,
    /// A defined data symbol.
    pub symbol: Option<String>,
    /// A full register name whose final value is the address.
    pub register: Option<String>,
    /// Byte count; omit to read up to a terminating NUL (at most 16 MiB).
    pub length: Option<usize>,
    /// Display format, default string.
    #[serde(default)]
    pub format: ReadFormat,
    /// Integer width in bytes (1, 2, 4, 8); required for integers.
    pub width: Option<u8>,
}

/// The bytes and formatted value of a requested post-execution read.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadResult {
    /// Start address in hexadecimal.
    pub address: String,
    /// Exact byte values, excluding the terminating NUL for unbounded reads.
    pub bytes: Vec<u8>,
    /// Text, byte array, hex dump, or array of decimal integer strings.
    pub value: serde_json::Value,
}

/// Initial state and execution bounds. Each run starts from a fresh image.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Options {
    /// Base of a dedicated 4 KiB thread-local mapping; chosen automatically when absent.
    pub tls_base: Option<Word>,
    /// Stack guard, truncated to pointer width; default 0x6a09e667bb67ae00.
    pub canary: Option<Word>,
    /// Stdin bytes consumed in order by input hooks; absent means EOF.
    pub stdin: Option<Input>,
    /// Additional descriptors bound to stdin.
    pub stdin_descriptors: Vec<u32>,
    /// Explicit virtual paths and file bytes; no host files are opened.
    pub files: BTreeMap<String, Vec<u8>>,
    /// Main arguments, including argv[0]; supplies argc and a NUL-terminated argv.
    pub argv: Option<Vec<String>>,
    /// Memory ranges to inspect after execution.
    pub reads: Vec<MemoryRead>,
    /// Stop before executing any of these instruction addresses.
    pub end: Vec<Word>,
    /// Initial values keyed by full machine register name.
    pub registers: BTreeMap<String, Word>,
    /// Integer or pointer arguments, in the recovered convention's order.
    pub arguments: Vec<Word>,
    /// Initial writes into writable sections, the stack or the heap.
    pub memory: Vec<MemoryWrite>,
    /// Maximum executed IR statements, including hook work units.
    pub step_limit: usize,
    /// Maximum elapsed milliseconds, including lifting.
    pub time_limit_ms: u64,
    /// Include visited instruction addresses.
    pub trace: bool,
    /// Explicit results for calls, keyed by imported name or target address.
    pub call_returns: BTreeMap<String, Word>,
    /// Treat unhandled calls as returning zero.
    pub skip_calls: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            tls_base: None,
            canary: None,
            stdin: None,
            stdin_descriptors: Vec::new(),
            files: BTreeMap::new(),
            argv: None,
            reads: Vec::new(),
            end: Vec::new(),
            registers: BTreeMap::new(),
            arguments: Vec::new(),
            memory: Vec::new(),
            step_limit: 100_000,
            time_limit_ms: 1_000,
            trace: false,
            call_returns: BTreeMap::new(),
            skip_calls: false,
        }
    }
}

/// A contiguous region whose final bytes differ from the initial state.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryChange {
    /// First changed address, in hexadecimal.
    pub address: String,
    /// Final byte values.
    pub bytes: Vec<u8>,
    /// Hexadecimal dump of the final bytes.
    pub hex: String,
}

/// Final state, also returned when execution stops on an error or a limit.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    /// Virtual file contents committed by fflush or fclose.
    pub files: BTreeMap<String, Vec<u8>>,
    /// Captured stdout, decoded as UTF-8 with replacement for invalid sequences.
    pub stdout: String,
    /// Captured stderr, decoded as UTF-8 with replacement for invalid sequences.
    pub stderr: String,
    /// Requested memory reads.
    pub reads: Vec<ReadResult>,
    /// Machine register names mapped to hexadecimal values, or "unknown".
    pub registers: BTreeMap<String, String>,
    /// Integer return register in hexadecimal, or "unknown" when not defined.
    pub return_value: String,
    /// Regions changed by execution, including stack writes.
    pub memory: Vec<MemoryChange>,
    /// Number of executed IR statements and hook work units.
    pub steps: usize,
    /// Return, end address, trap, step limit, time limit, or error.
    pub reason: String,
    /// Instruction at which execution stopped, in hexadecimal.
    pub address: String,
    /// Explanation including the failing instruction address.
    pub error: Option<String>,
    /// Visited instruction addresses, when requested.
    pub trace: Vec<String>,
    /// First address of the zero-initialized, writable heap area.
    pub heap_base: String,
    /// Heap capacity in bytes.
    pub heap_size: u64,
    /// Initial stack pointer, in hexadecimal.
    pub stack_pointer: String,
}

pub(crate) fn invalid(message: impl Into<String>) -> Error {
    Error::Emulation(message.into())
}

/// Executes a function name or virtual address with the supplied initial state.
/// Unsupported operations stop with an error in the returned final-state report.
pub fn run(
    binary: &Binary,
    start: &str,
    options: &Options,
    deadline: Option<Instant>,
) -> Result<Report> {
    let address = match crate::addr::parse(start) {
        Some(address) => address,
        None => match binary.find(start) {
            Ok(function) => function.addr,
            Err(error) => return Err(error),
        },
    };
    crate::ir::eval::emulation::run(binary.image(), address, options, deadline)
}

//! Bounded execution of loaded machine code through the IR interpreter.

mod memory;
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

/// Initial state and execution bounds. Each run starts from a fresh image.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Options {
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

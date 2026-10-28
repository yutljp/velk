//! Bounded symbolic execution over the same lifted IR used by emulation.

mod solver;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub use crate::ir::eval::symbolic::{State, Step, Term};
pub(crate) use solver::{Solver, invalid};

/// A memory range whose bytes become independent symbolic inputs.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MemoryInput {
    /// Concrete start address.
    pub address: crate::emulation::Word,
    /// Number of bytes.
    pub size: usize,
}

/// Initial inputs and deterministic execution limits.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Options {
    /// Addresses to reach before executing the instruction there.
    pub find: Vec<crate::emulation::Word>,
    /// Addresses whose paths are discarded before execution.
    pub avoid: Vec<crate::emulation::Word>,
    /// Number of symbolic stdin bytes.
    pub stdin: usize,
    /// Symbolic argument indices, starting at zero.
    pub arguments: Vec<usize>,
    /// Concrete values for arguments not selected as symbolic.
    pub argument_values: Vec<crate::emulation::Word>,
    /// Symbolic argv string lengths, including argv[0]; terminators are concrete.
    pub argv: Vec<usize>,
    /// Physical register indices to make symbolic.
    pub registers: Vec<u16>,
    /// Concrete physical register values.
    pub register_values: BTreeMap<u16, crate::emulation::Word>,
    /// Memory ranges to make symbolic.
    pub memory: Vec<MemoryInput>,
    /// Maximum IR statements per path, including instruction markers.
    pub step_limit: usize,
    /// Maximum total states visited by exploration.
    pub path_limit: usize,
    /// Maximum possible values of a symbolic address before reporting a limit.
    pub address_limit: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            find: Vec::new(),
            avoid: Vec::new(),
            stdin: 0,
            arguments: Vec::new(),
            argument_values: Vec::new(),
            argv: Vec::new(),
            registers: Vec::new(),
            register_values: BTreeMap::new(),
            memory: Vec::new(),
            step_limit: 100_000,
            path_limit: 256,
            address_limit: 8,
        }
    }
}

/// Concrete values from one consistent satisfying assignment.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Inputs {
    /// Stdin bytes in consumption order.
    pub stdin: Vec<u8>,
    /// Argv bytes, excluding their zero terminators.
    pub argv: Vec<Vec<u8>>,
    /// Scalar argument values, in hexadecimal.
    pub arguments: BTreeMap<usize, String>,
    /// Initial symbolic memory bytes keyed by hexadecimal address.
    pub memory: BTreeMap<String, u8>,
    /// Initial symbolic registers keyed by physical index.
    pub registers: BTreeMap<u16, String>,
}

/// A search result, including deterministic limits and partial-search diagnostics.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    /// Whether a satisfiable state reached a requested address.
    pub found: bool,
    /// Stop reason, or `found`.
    pub reason: String,
    /// Concrete initial values when found.
    pub inputs: Option<Inputs>,
    /// Visited instruction addresses in hexadecimal.
    pub path: Vec<String>,
    /// Number of states visited.
    pub paths: usize,
    /// Reasons discarded or incomplete paths stopped.
    pub diagnostics: Vec<String>,
}

/// Finds the first satisfiable path in deterministic depth-first order.
pub fn explore(
    binary: &crate::service::Binary,
    start: &str,
    options: &Options,
) -> crate::error::Result<Report> {
    let state = match State::new(binary, start, options) {
        Ok(state) => state,
        Err(error) => return Err(error),
    };
    state.explore(binary, options)
}

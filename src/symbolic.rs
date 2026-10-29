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
    /// Answers used for common debugger and environment checks.
    pub anti_analysis: crate::emulation::AntiAnalysisOptions,
    /// Base of a dedicated 4 KiB thread-local mapping; chosen automatically when absent.
    pub tls_base: Option<crate::emulation::Word>,
    /// Fixed Unix time in seconds for `time()`; default zero.
    pub time: Option<crate::emulation::Word>,
    /// Stack guard, truncated to pointer width; default 0x6a09e667bb67ae00.
    pub canary: Option<crate::emulation::Word>,
    /// Addresses to reach before executing the instruction there.
    pub find: Vec<crate::emulation::Word>,
    /// Comparison on the outermost return value.
    pub returns: Option<ReturnCondition>,
    /// Addresses whose paths are discarded before execution.
    pub avoid: Vec<crate::emulation::Word>,
    /// Number of symbolic stdin bytes.
    pub stdin: usize,
    /// Additional descriptors bound to the same stdin stream.
    pub stdin_descriptors: Vec<u32>,
    /// Virtual file inputs; each array fixes a length of independent symbolic bytes.
    pub files: BTreeMap<String, Vec<u8>>,
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
            anti_analysis: crate::emulation::AntiAnalysisOptions::default(),
            tls_base: None,
            canary: None,
            time: None,
            find: Vec::new(),
            returns: None,
            avoid: Vec::new(),
            stdin: 0,
            stdin_descriptors: Vec::new(),
            files: BTreeMap::new(),
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
    /// Initial file bytes under the satisfying assignment, keyed by virtual path.
    pub files: BTreeMap<String, Vec<u8>>,
    /// File contents committed by fflush or fclose under the same assignment.
    pub file_outputs: BTreeMap<String, Vec<u8>>,
    /// Stdin bytes in consumption order.
    pub stdin: Vec<u8>,
    /// Recorded output bytes under this same satisfying assignment.
    pub stdout: Vec<u8>,
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
    /// Whether a satisfiable state reached a target or satisfied the return condition.
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

/// Comparison against a constant return value. Ordered comparisons are signed 64-bit.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ReturnCondition {
    /// Equal to the constant.
    Eq(#[serde(deserialize_with = "return_constant")] crate::emulation::Word),
    /// Different from the constant.
    Ne(#[serde(deserialize_with = "return_constant")] crate::emulation::Word),
    /// Signed less than the constant.
    Lt(#[serde(deserialize_with = "return_constant")] crate::emulation::Word),
    /// Signed greater than the constant.
    Gt(#[serde(deserialize_with = "return_constant")] crate::emulation::Word),
}
impl ReturnCondition {
    pub(crate) fn comparison(&self) -> crate::error::Result<(crate::ir::Cond, u64)> {
        use crate::ir::Cond;
        let (cond, word) = match self {
            Self::Eq(word) => (Cond::Eq, word),
            Self::Ne(word) => (Cond::Ne, word),
            Self::Lt(word) => (Cond::Lt, word),
            Self::Gt(word) => (Cond::Gt, word),
        };
        if let crate::emulation::Word::Text(text) = word
            && text.starts_with('-')
        {
            return match text.parse::<i64>() {
                Ok(value) => Ok((cond, value as u64)),
                Err(error) => Err(invalid(format!(
                    "invalid signed return constant {text}: {error}"
                ))),
            };
        }
        match word.value() {
            Ok(value) => Ok((cond, value)),
            Err(error) => Err(error),
        }
    }
}
/// Finds inputs satisfying a condition on the outermost function's return value.
pub fn solve(
    binary: &crate::service::Binary,
    start: &str,
    options: &Options,
) -> crate::error::Result<Report> {
    if options.returns.is_none() || !options.find.is_empty() {
        return Err(invalid("solve requires returns and no find addresses"));
    }
    explore(binary, start, options)
}
/// One conditional branch side that was not shown to be feasible.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BranchProof {
    /// Instruction address in hexadecimal.
    pub address: String,
    /// Whether this is the taken side.
    pub taken: bool,
    /// `unsat` for an exhaustive proof, otherwise `unknown`.
    pub status: String,
    /// Explanation of an incomplete proof or an unreachable instruction.
    pub reason: Option<String>,
}
/// Branch analysis result. Incomplete exploration never claims global unreachability.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FeasibilityReport {
    /// Conditional sides with no feasible witness.
    pub branches: Vec<BranchProof>,
    /// Whether all reachable states finished normally.
    pub complete: bool,
    /// Number of explored states.
    pub paths: usize,
    /// Unsupported operations and exploration limits.
    pub diagnostics: Vec<String>,
}
/// Reports branch sides infeasible in every visited calling and path context.
pub fn branch_feasibility(
    binary: &crate::service::Binary,
    start: &str,
    options: &Options,
) -> crate::error::Result<FeasibilityReport> {
    let state = match State::new(binary, start, options) {
        Ok(state) => state,
        Err(error) => return Err(error),
    };
    state.branch_feasibility(binary, options)
}

fn return_constant<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<crate::emulation::Word, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Constant {
        Unsigned(u64),
        Signed(i64),
        Text(String),
    }
    match Constant::deserialize(deserializer) {
        Ok(Constant::Unsigned(value)) => Ok(crate::emulation::Word::Integer(value)),
        Ok(Constant::Signed(value)) if value > -(1i64 << 53) => {
            Ok(crate::emulation::Word::Text(value.to_string()))
        }
        Ok(Constant::Signed(_)) => Err(serde::de::Error::custom(
            "use a string for return constants below -2^53 + 1",
        )),
        Ok(Constant::Text(text)) => Ok(crate::emulation::Word::Text(text)),
        Err(error) => Err(error),
    }
}

//! Signature databases and informational IR shape hashes.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::ir::{BinOp, Expr, FunctionIr, Stmt};
use crate::loader::Isa;

mod bytes;
pub use bytes::build;
pub(crate) use bytes::{identify, image_entries};
const TOKEN_LIMIT: usize = 128;
const VERSION: u32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// A named instruction signature or informational IR shape.
pub struct Entry {
    /// Function name from the source symbol table.
    pub name: String,
    /// Instruction set used to decode the body.
    pub isa: Isa,
    /// Function body length in bytes.
    pub size: u64,
    /// Informational IR shape digest; empty for instruction signatures.
    pub hash: String,
    /// Informational IR shape tokens; empty for instruction signatures.
    pub tokens: Vec<String>,
    /// Normalized instruction bytes; empty for an IR-only entry.
    #[serde(default)]
    pub bytes: Vec<u8>,
    /// Direct destination names in instruction order.
    #[serde(default)]
    pub calls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Versioned signatures and the input files from which they were built.
pub struct Database {
    /// Serialization format version.
    pub version: u32,
    /// Candidate function signatures.
    pub entries: Vec<Entry>,
    /// Input file names and archive member names.
    #[serde(default)]
    pub sources: Vec<String>,
}

impl Database {
    /// Creates a database sorted by function name.
    #[must_use]
    pub fn new(mut entries: Vec<Entry>) -> Self {
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Self {
            version: VERSION,
            entries,
            sources: Vec::new(),
        }
    }

    /// Reads and validates a JSON database, reporting its path on read or parse errors.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
            path: path.to_owned(),
            source,
        })?;
        let value = serde_json::from_str(&text).map_err(|source| Error::SignatureFile {
            path: path.to_owned(),
            source,
        })?;
        Self::from_json(value)
    }

    /// Validates the format version and deserializes a database.
    pub fn from_json(value: serde_json::Value) -> Result<Self> {
        let found = value.get("version").and_then(serde_json::Value::as_u64);
        if found != Some(u64::from(VERSION)) {
            return Err(Error::SignatureVersion {
                found,
                expected: VERSION,
            });
        }
        serde_json::from_value(value).map_err(Error::SignatureData)
    }

    /// Finds an unambiguous informational IR shape; does not identify library functions.
    #[must_use]
    pub fn lookup(&self, ir: &FunctionIr) -> Option<&Entry> {
        let tokens = tokens(ir);
        if tokens.is_empty() {
            return None;
        }
        let digest = hash(&tokens);
        let mut matches = self.entries.iter().filter(|entry| {
            entry.bytes.is_empty()
                && entry.isa == ir.isa
                && entry.hash == digest
                && entry.tokens == tokens
        });
        let Some(first) = matches.next() else {
            return None;
        };
        matches
            .all(|entry| entry.name == first.name)
            .then_some(first)
    }
}

/// The database entry for a named function, or `None` when its body has no shape to match.
#[must_use]
pub fn entry(name: &str, size: Option<u64>, ir: &FunctionIr) -> Option<Entry> {
    let tokens = tokens(ir);
    (!tokens.is_empty()).then(|| Entry {
        name: name.to_owned(),
        isa: ir.isa,
        size: size.unwrap_or(0),
        hash: hash(&tokens),
        tokens,
        bytes: Vec::new(),
        calls: Vec::new(),
    })
}

/// Computes an informational digest of the lifted IR shape.
#[must_use]
pub fn shape_hash(ir: &FunctionIr) -> String {
    hash(&tokens(ir))
}

fn tokens(ir: &FunctionIr) -> Vec<String> {
    let mut out = Vec::new();
    for block in &ir.blocks {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Assign { value, .. } => expr_tokens(value, &mut out),
                Stmt::Store {
                    addr, value, width, ..
                } => {
                    expr_tokens(addr, &mut out);
                    expr_tokens(value, &mut out);
                    out.push(format!("store{}", width * 8));
                }
                Stmt::Brif { cond, .. } => out.push(format!("brif:{}", cond.text())),
                Stmt::BrifFlags { cond, .. } => out.push(format!("brifflags:{}", cond.text())),
                Stmt::Br { .. } => out.push("br".to_owned()),
                Stmt::BrIndirect { target } => {
                    expr_tokens(target, &mut out);
                    out.push("brind".to_owned());
                }
                Stmt::Switch { cases, index, .. } => {
                    expr_tokens(index, &mut out);
                    out.push(format!("switch:{}", cases.len()));
                }
                Stmt::Call { args, .. } => {
                    for arg in args.iter().flatten() {
                        expr_tokens(arg, &mut out);
                    }
                    out.push(format!("call:{}", args.as_ref().map_or(0, Vec::len)));
                }
                // The returned value separates two functions that both end
                // in a single return.
                Stmt::Ret { value } => {
                    expr_tokens(value, &mut out);
                    out.push("ret".to_owned());
                }
                Stmt::Trap => out.push("trap".to_owned()),
                Stmt::Machine { instruction, .. } => out.push(format!("machine:{instruction:?}")),
                Stmt::Unsupported { .. } => out.push("unsupported".to_owned()),
            }
            if out.len() >= TOKEN_LIMIT {
                out.truncate(TOKEN_LIMIT);
                return out;
            }
        }
    }
    out
}

fn expr_tokens(expr: &Expr, out: &mut Vec<String>) {
    match expr {
        Expr::Reg { .. } => out.push("reg".to_owned()),
        Expr::Const(_) => out.push("imm".to_owned()),
        Expr::Bin { op, lhs, rhs } => {
            expr_tokens(lhs, out);
            expr_tokens(rhs, out);
            out.push(operator(*op).to_owned());
        }
        Expr::Load { addr, width, .. } => {
            expr_tokens(addr, out);
            out.push(format!("load{}", width * 8));
        }
        Expr::SignExtend { value, width } => {
            expr_tokens(value, out);
            out.push(format!("sext{}", width * 8));
        }
        Expr::Select {
            cond,
            lhs,
            rhs,
            then,
            els,
        } => {
            expr_tokens(lhs, out);
            expr_tokens(rhs, out);
            expr_tokens(then, out);
            expr_tokens(els, out);
            out.push(format!("select:{}", cond.text()));
        }
        Expr::Apply { op, args } => {
            for arg in args {
                expr_tokens(arg, out);
            }
            out.push(crate::ir::operation_name(*op));
        }
    }
}

fn operator(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "add",
        BinOp::Sub => "sub",
        BinOp::Mul => "mul",
        BinOp::MulHigh => "mulh",
        BinOp::MulHighS => "mulhs",
        BinOp::And => "and",
        BinOp::Or => "or",
        BinOp::Xor => "xor",
        BinOp::Shl => "shl",
        BinOp::Shr => "shr",
        BinOp::Sar => "sar",
        BinOp::DivS => "divs",
        BinOp::ModS => "mods",
        BinOp::DivU => "divu",
        BinOp::ModU => "modu",
    }
}

fn hash(tokens: &[String]) -> String {
    let mut value: u64 = 0xcbf2_9ce4_8422_2325;
    for token in tokens {
        for byte in token.as_bytes() {
            value ^= u64::from(*byte);
            value = value.wrapping_mul(0x0000_0100_0000_01b3);
        }
        value ^= u64::from(b'|');
        value = value.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{value:016x}")
}

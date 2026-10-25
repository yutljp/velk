use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::ir::{BinOp, Expr, FunctionIr, Stmt};
use crate::loader::Isa;

const TOKEN_LIMIT: usize = 128;
const VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub isa: Isa,
    pub size: u64,
    pub hash: String,
    pub tokens: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Database {
    pub version: u32,
    pub entries: Vec<Entry>,
}

impl Database {
    #[must_use]
    pub fn new(mut entries: Vec<Entry>) -> Self {
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Self {
            version: VERSION,
            entries,
        }
    }

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

    #[must_use]
    pub fn lookup(&self, ir: &FunctionIr) -> Option<&Entry> {
        let tokens = tokens(ir);
        if tokens.is_empty() {
            return None;
        }
        let digest = hash(&tokens);
        self.entries.iter().find(|entry| entry.hash == digest)
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
    })
}

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

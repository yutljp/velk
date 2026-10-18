//! Self-generated function signatures: build a shape database from symbols
//! and match unnamed functions against it.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::analysis;
use crate::ir::{Expr, FunctionIr, Stmt};
use crate::loader::Image;

const TOKEN_LIMIT: usize = 128;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub isa: String,
    pub size: u64,
    pub hash: String,
    pub tokens: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Database {
    pub version: u32,
    pub entries: Vec<Entry>,
}

#[derive(Debug, Clone)]
pub struct Match {
    pub addr: u64,
    pub size: u64,
    pub current: Option<String>,
    pub matched: String,
}

pub fn tokens(ir: &FunctionIr) -> Vec<String> {
    let mut out = Vec::new();
    for block in &ir.blocks {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Assign { value, .. } => expr_tokens(value, &mut out),
                // The stored value and the address are part of the shape.
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
                Stmt::Call { .. } => out.push("call".to_owned()),
                // The returned value separates two functions that both end
                // in a single return.
                Stmt::Ret { value } => {
                    expr_tokens(value, &mut out);
                    out.push("ret".to_owned());
                }
                Stmt::Trap => out.push("trap".to_owned()),
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
            out.push(format!("{}", operator(*op)));
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
    }
}

fn operator(op: crate::ir::BinOp) -> &'static str {
    use crate::ir::BinOp;
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

pub fn hash(tokens: &[String]) -> String {
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

pub fn build(image: &Image) -> Database {
    let mut entries = Vec::new();
    for function in image.functions.values() {
        let Some(name) = function.name.as_ref() else {
            continue;
        };
        let size = function.size.unwrap_or(256);
        let Ok(lifted) = analysis::lift(image, function, size) else {
            continue;
        };
        let tokens = tokens(&lifted);
        if tokens.is_empty() {
            continue;
        }
        entries.push(Entry {
            name: name.clone(),
            isa: image.isa.to_string(),
            size: function.size.unwrap_or(0),
            hash: hash(&tokens),
            tokens,
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Database {
        version: 1,
        entries,
    }
}

pub fn lookup(database: &Database, ir: &FunctionIr) -> Option<String> {
    let tokens = tokens(ir);
    if tokens.is_empty() {
        return None;
    }
    let digest = hash(&tokens);
    database
        .entries
        .iter()
        .find(|entry| entry.hash == digest)
        .map(|entry| entry.name.clone())
}

pub fn identify(image: &Image, database: &Database) -> Vec<Match> {
    let index: HashMap<&str, &Entry> = database
        .entries
        .iter()
        .map(|entry| (entry.hash.as_str(), entry))
        .collect();
    let mut matches = Vec::new();
    for function in image.functions.values() {
        let size = function.size.unwrap_or(256);
        let Ok(lifted) = analysis::lift(image, function, size) else {
            continue;
        };
        let tokens = tokens(&lifted);
        if tokens.is_empty() {
            continue;
        }
        let digest = hash(&tokens);
        if let Some(entry) = index.get(digest.as_str()) {
            matches.push(Match {
                addr: function.addr,
                size: function.size.unwrap_or(0),
                current: function.name.clone(),
                matched: entry.name.clone(),
            });
        }
    }
    matches
}

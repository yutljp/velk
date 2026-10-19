use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::addr;
use crate::card::DEFAULT_BUDGET;
use crate::error::{Error, Result};
use crate::service::{Binary, Failure, Session};
use crate::sigs::Database;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "camelCase", deny_unknown_fields)]
pub enum Request {
    Open {
        path: PathBuf,
    },
    Sections {
        bin: PathBuf,
    },
    Functions {
        bin: PathBuf,
    },
    Find {
        bin: PathBuf,
        target: String,
    },
    Card {
        bin: PathBuf,
        addr: String,
        budget: Option<usize>,
    },
    Decompile {
        bin: PathBuf,
        addr: String,
    },
    Disasm {
        bin: PathBuf,
        addr: String,
        limit: Option<usize>,
    },
    Ir {
        bin: PathBuf,
        addr: String,
    },
    Signature {
        bin: PathBuf,
        addr: String,
    },
    References {
        bin: PathBuf,
        addr: String,
    },
    Strings {
        bin: PathBuf,
        addr: String,
    },
    ShapeHash {
        bin: PathBuf,
        addr: String,
    },
    BuildSignatures {
        bin: PathBuf,
    },
    /// `signatures` is either a database or the path to its JSON file.
    Identify {
        bin: PathBuf,
        signatures: Value,
    },
}

pub fn handle(session: &mut Session, request: Request) -> Result<Value> {
    match request {
        Request::Open { path } => {
            let binary = session.open(&path)?;
            let image = binary.image();
            Ok(json!({
                "id": binary.path(),
                "path": binary.path(),
                "format": image.format,
                "arch": image.isa,
                "entry": image.entry.map(addr::format),
            }))
        }
        Request::Sections { bin } => Ok(json!(session.open(&bin)?.image().sections)),
        Request::Functions { bin } => Ok(json!(
            session
                .open(&bin)?
                .image()
                .functions
                .values()
                .collect::<Vec<_>>()
        )),
        Request::Find { bin, target } => Ok(json!(session.open(&bin)?.find(&target)?)),
        Request::Card { bin, addr, budget } => {
            let card =
                session
                    .open(&bin)?
                    .card(parse(&addr)?, budget.unwrap_or(DEFAULT_BUDGET), None)?;
            Ok(json!(card))
        }
        Request::Decompile { bin, addr } => {
            Ok(json!(session.open(&bin)?.decompile(parse(&addr)?, None)?))
        }
        Request::Disasm { bin, addr, limit } => Ok(json!(
            session
                .open(&bin)?
                .disasm(parse(&addr)?, limit.unwrap_or(usize::MAX))?
        )),
        Request::Ir { bin, addr } => Ok(json!(analysis(session, &bin, &addr)?.ir.render())),
        Request::Signature { bin, addr } => {
            let ir = &analysis(session, &bin, &addr)?.ir;
            Ok(json!({
                "return": ir.ret_type.to_string(),
                "params": ir.params.iter().map(|p| json!({ "name": p.name, "type": p.ty.to_string() })).collect::<Vec<_>>(),
            }))
        }
        Request::References { bin, addr } => Ok(analysis(session, &bin, &addr)?
            .references
            .iter()
            .map(|reference| {
                json!({
                    "addr": addr::format(reference.addr),
                    "section": reference.section,
                    "text": reference.text,
                    "pointer": reference.pointer.map(addr::format),
                })
            })
            .collect()),
        Request::Strings { bin, addr } => Ok(json!(analysis(session, &bin, &addr)?.strings())),
        Request::ShapeHash { bin, addr } => {
            Ok(json!(session.open(&bin)?.shape_hash(parse(&addr)?)?))
        }
        Request::BuildSignatures { bin } => {
            let build = session.open(&bin)?.build_signatures();
            Ok(json!({ "database": build.database, "failures": failures(&build.failures) }))
        }
        Request::Identify { bin, signatures } => {
            let database = match signatures {
                Value::String(path) => Database::load(path.as_ref())?,
                value => Database::from_json(value)?,
            };
            let identification = session.open(&bin)?.identify(&database);
            Ok(json!({
                "matches": identification.matches.iter().map(|m| json!({
                    "addr": addr::format(m.addr),
                    "size": m.size,
                    "current": m.current,
                    "matched": m.matched,
                })).collect::<Vec<_>>(),
                "failures": failures(&identification.failures),
            }))
        }
    }
}

fn analysis<'a>(
    session: &'a mut Session,
    bin: &std::path::Path,
    text: &str,
) -> Result<&'a crate::analysis::Analysis> {
    let addr = parse(text)?;
    let binary: &'a mut Binary = session.open(bin)?;
    binary.analysis(addr)
}

fn parse(text: &str) -> Result<u64> {
    addr::parse(text).ok_or_else(|| Error::BadAddress(text.to_owned()))
}

fn failures(failures: &[Failure]) -> Vec<Value> {
    failures
        .iter()
        .map(|f| json!({ "addr": addr::format(f.addr), "error": f.error.to_string() }))
        .collect()
}

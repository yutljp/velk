//! Deserializes and executes the operations exposed to analysis scripts.

use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::addr;
use crate::card::DEFAULT_BUDGET;
use crate::deadline::passed;
use crate::error::{Error, Result};
use crate::service::{Binary, Failure, Session};
use crate::sigs::Database;

/// An analysis operation and its arguments.
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "camelCase", deny_unknown_fields)]
pub enum Request {
    /// Resolves a navigation query.
    Navigate {
        /// Path identifying the binary to analyze.
        bin: PathBuf,
        /// Navigation target and result options.
        query: crate::xrefs::query::Query,
    },
    /// Opens a binary and returns its metadata.
    Open {
        /// Path of the binary to open.
        path: PathBuf,
    },
    /// Lists the binary sections.
    Sections {
        /// Path identifying the binary to analyze.
        bin: PathBuf,
    },
    /// Lists discovered functions.
    Functions {
        /// Path identifying the binary to analyze.
        bin: PathBuf,
    },
    /// Resolves a function name or address.
    Find {
        /// Path identifying the binary to analyze.
        bin: PathBuf,
        /// Function name or address to resolve.
        target: String,
    },
    /// Builds a bounded function summary.
    Card {
        /// Path identifying the binary to analyze.
        bin: PathBuf,
        /// Function address in hexadecimal or decimal.
        addr: String,
        /// Maximum summary size; absence uses the default budget.
        budget: Option<usize>,
    },
    /// Renders a function as C.
    Decompile {
        /// Path identifying the binary to analyze.
        bin: PathBuf,
        /// Function address in hexadecimal or decimal.
        addr: String,
    },
    /// Lists decoded instructions.
    Disasm {
        /// Path identifying the binary to analyze.
        bin: PathBuf,
        /// Function address in hexadecimal or decimal.
        addr: String,
        /// Maximum instruction count; absence leaves it unlimited.
        limit: Option<usize>,
    },
    /// Renders a function in the intermediate representation.
    Ir {
        /// Path identifying the binary to analyze.
        bin: PathBuf,
        /// Function address in hexadecimal or decimal.
        addr: String,
    },
    /// Builds a function signature.
    Signature {
        /// Path identifying the binary to analyze.
        bin: PathBuf,
        /// Function address in hexadecimal or decimal.
        addr: String,
    },
    /// Lists references to a function.
    References {
        /// Path identifying the binary to analyze.
        bin: PathBuf,
        /// Function address in hexadecimal or decimal.
        addr: String,
    },
    /// Lists strings referenced by a function.
    Strings {
        /// Path identifying the binary to analyze.
        bin: PathBuf,
        /// Function address in hexadecimal or decimal.
        addr: String,
    },
    /// Computes a function structure hash.
    ShapeHash {
        /// Path identifying the binary to analyze.
        bin: PathBuf,
        /// Function address in hexadecimal or decimal.
        addr: String,
    },
    /// Builds a signature database for a binary.
    BuildSignatures {
        /// Path identifying the binary to analyze.
        bin: PathBuf,
    },
    /// `signatures` is either a database or the path to its JSON file.
    Identify {
        /// Path identifying the binary to analyze.
        bin: PathBuf,
        /// Signature database or path to its JSON file.
        signatures: Value,
    },
}

/// Answers `request`; analysis stops at pass boundaries once `deadline` passes.
pub fn handle(
    session: &mut Session,
    request: Request,
    deadline: Option<std::time::Instant>,
) -> Result<Value> {
    match request {
        Request::Navigate { bin, query } => {
            let binary = match session.open(&bin) {
                Ok(binary) => binary,
                Err(error) => return Err(error),
            };
            crate::xrefs::query::run(binary, query, deadline)
        }
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
            let card = session.open(&bin)?.card(
                parse(&addr)?,
                budget.unwrap_or(DEFAULT_BUDGET),
                None,
                deadline,
            )?;
            Ok(json!(card))
        }
        Request::Decompile { bin, addr } => Ok(json!(session.open(&bin)?.decompile(
            parse(&addr)?,
            None,
            deadline
        )?)),
        Request::Disasm { bin, addr, limit } => Ok(json!(
            session
                .open(&bin)?
                .disasm(parse(&addr)?, limit.unwrap_or(usize::MAX))?
        )),
        Request::Ir { bin, addr } => {
            let analysis = analysis(session, &bin, &addr, deadline)?;
            passed(deadline)?;
            Ok(json!(analysis.ir.render()))
        }
        Request::Signature { bin, addr } => {
            let ir = &analysis(session, &bin, &addr, deadline)?.ir;
            Ok(json!({
                "return": ir.ret_type.to_string(),
                "params": ir.params.iter().map(|p| json!({ "name": p.name, "type": p.ty.to_string() })).collect::<Vec<_>>(),
            }))
        }
        Request::References { bin, addr } => Ok(analysis(session, &bin, &addr, deadline)?
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
        Request::Strings { bin, addr } => {
            Ok(json!(analysis(session, &bin, &addr, deadline)?.strings()))
        }
        Request::ShapeHash { bin, addr } => Ok(json!(
            session.open(&bin)?.shape_hash(parse(&addr)?, deadline)?
        )),
        Request::BuildSignatures { bin } => {
            let build = session.open(&bin)?.build_signatures(deadline)?;
            Ok(json!({ "database": build.database, "failures": failures(&build.failures) }))
        }
        Request::Identify { bin, signatures } => {
            let database = match signatures {
                Value::String(path) => Database::load(path.as_ref())?,
                value => Database::from_json(value)?,
            };
            let identification = session.open(&bin)?.identify(&database, deadline)?;
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
    deadline: Option<std::time::Instant>,
) -> Result<&'a crate::analysis::Analysis> {
    let addr = parse(text)?;
    let binary: &'a mut Binary = session.open(bin)?;
    binary.analysis(addr, deadline)
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

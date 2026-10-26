//! Deserializes and executes the operations exposed to analysis scripts.

mod compare;
mod project;

use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::addr;
use crate::card::DEFAULT_BUDGET;
use crate::deadline::passed;
use crate::error::{Error, Result};
use crate::service::{Binary, Failure, Session};
use crate::sigs::Database;

/// A binary path with an optional architecture selection.
#[derive(Deserialize)]
#[serde(untagged)]
pub enum BinaryRef {
    /// A path using the default architecture.
    Path(PathBuf),
    /// A path with an explicit architecture.
    Selected {
        /// Path of the binary.
        path: PathBuf,
        /// Requested architecture.
        arch: Option<crate::loader::Architecture>,
    },
}

impl BinaryRef {
    fn arch(&self) -> Option<crate::loader::Architecture> {
        match self {
            Self::Path(_) => None,
            Self::Selected { arch, .. } => *arch,
        }
    }
}

impl std::ops::Deref for BinaryRef {
    type Target = std::path::Path;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Path(path) | Self::Selected { path, .. } => path,
        }
    }
}

/// An analysis operation and its arguments.
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "camelCase", deny_unknown_fields)]
pub enum Request {
    /// Compares two program versions and optionally carries annotations.
    Compare {
        /// Original binary.
        first: BinaryRef,
        /// Updated binary.
        second: BinaryRef,
        /// Whether to copy annotations into unannotated destination targets.
        #[serde(default, rename = "carryAnnotations")]
        carry_annotations: bool,
    },
    /// Resolves a navigation query.
    Navigate {
        /// Path identifying the binary to analyze.
        bin: BinaryRef,
        /// Navigation target and result options.
        query: crate::xrefs::query::Query,
    },
    /// Reads or updates persistent analysis annotations.
    Project {
        /// Path of the annotated binary.
        bin: BinaryRef,
        /// Annotation operation to perform.
        action: String,
        /// Target or annotation supplied to the operation.
        #[serde(default)]
        value: Value,
    },
    /// Opens a binary and returns its metadata.
    Open {
        /// Path of the binary to open.
        path: PathBuf,
        /// Optional annotation file location.
        project: Option<PathBuf>,
        /// Requested Mach-O architecture.
        arch: Option<crate::loader::Architecture>,
    },
    /// Lists recovered C++ classes.
    Classes {
        /// Path identifying the binary to analyze.
        bin: BinaryRef,
    },
    /// Lists the binary sections.
    Sections {
        /// Path identifying the binary to analyze.
        bin: BinaryRef,
    },
    /// Lists discovered functions.
    Functions {
        /// Path identifying the binary to analyze.
        bin: BinaryRef,
    },
    /// Resolves a function name or address.
    Find {
        /// Path identifying the binary to analyze.
        bin: BinaryRef,
        /// Function name or address to resolve.
        target: String,
    },
    /// Builds a bounded function summary.
    Card {
        /// Path identifying the binary to analyze.
        bin: BinaryRef,
        /// Function address in hexadecimal or decimal.
        addr: String,
        /// Maximum summary size; absence uses the default budget.
        budget: Option<usize>,
    },
    /// Renders a function as C.
    Decompile {
        /// Path identifying the binary to analyze.
        bin: BinaryRef,
        /// Function address in hexadecimal or decimal.
        addr: String,
    },
    /// Lists decoded instructions.
    Disasm {
        /// Path identifying the binary to analyze.
        bin: BinaryRef,
        /// Function address in hexadecimal or decimal.
        addr: String,
        /// Maximum instruction count; absence leaves it unlimited.
        limit: Option<usize>,
    },
    /// Renders a function in the intermediate representation.
    Ir {
        /// Path identifying the binary to analyze.
        bin: BinaryRef,
        /// Function address in hexadecimal or decimal.
        addr: String,
    },
    /// Builds a function signature.
    Signature {
        /// Path identifying the binary to analyze.
        bin: BinaryRef,
        /// Function address in hexadecimal or decimal.
        addr: String,
    },
    /// Lists references to a function.
    References {
        /// Path identifying the binary to analyze.
        bin: BinaryRef,
        /// Function address in hexadecimal or decimal.
        addr: String,
    },
    /// Lists strings referenced by a function.
    Strings {
        /// Path identifying the binary to analyze.
        bin: BinaryRef,
        /// Function address in hexadecimal or decimal.
        addr: String,
    },
    /// Computes a function structure hash.
    ShapeHash {
        /// Path identifying the binary to analyze.
        bin: BinaryRef,
        /// Function address in hexadecimal or decimal.
        addr: String,
    },
    /// Builds a signature database for a binary.
    BuildSignatures {
        /// Path identifying the binary to analyze.
        bin: BinaryRef,
    },
    /// `signatures` is either a database or the path to its JSON file.
    Identify {
        /// Path identifying the binary to analyze.
        bin: BinaryRef,
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
            let binary = match session.open_arch(&bin, bin.arch()) {
                Ok(binary) => binary,
                Err(error) => return Err(error),
            };
            crate::xrefs::query::run(binary, query, deadline)
        }
        Request::Compare {
            first,
            second,
            carry_annotations,
        } => compare::handle(session, first, second, carry_annotations, deadline),
        Request::Project { bin, action, value } => {
            project::handle(session, bin, action, value, deadline)
        }
        Request::Open {
            path,
            project,
            arch,
        } => {
            let binary = match session.open_with_options(&path, project.as_deref(), arch) {
                Ok(binary) => binary,
                Err(error) => return Err(error),
            };
            let image = binary.image();
            Ok(json!({
                "id": { "path": binary.path(), "arch": arch },
                "path": binary.path(),
                "format": image.format,
                "arch": image.isa,
                "slices": image.slices,
                "sliceOffset": image.slice_offset,
                "entry": image.entry.map(addr::format),
            }))
        }
        Request::Classes { bin } => {
            let binary = match session.open_arch(&bin, bin.arch()) {
                Ok(binary) => binary,
                Err(error) => return Err(error),
            };
            Ok(json!(binary.image().classes()))
        }
        Request::Sections { bin } => {
            Ok(json!(session.open_arch(&bin, bin.arch())?.image().sections))
        }
        Request::Functions { bin } => Ok(json!(session.open_arch(&bin, bin.arch())?.functions())),
        Request::Find { bin, target } => {
            let binary = match session.open_arch(&bin, bin.arch()) {
                Ok(binary) => binary,
                Err(error) => return Err(error),
            };
            let addr = match binary.find(&target) {
                Ok(function) => function.addr,
                Err(error) => return Err(error),
            };
            Ok(json!(
                binary
                    .functions()
                    .into_iter()
                    .find(|function| function.addr == addr)
            ))
        }
        Request::Card { bin, addr, budget } => {
            let card = session.open_arch(&bin, bin.arch())?.card(
                parse(&addr)?,
                budget.unwrap_or(DEFAULT_BUDGET),
                None,
                deadline,
            )?;
            Ok(json!(card))
        }
        Request::Decompile { bin, addr } => Ok(json!(
            session
                .open_arch(&bin, bin.arch())?
                .decompile(parse(&addr)?, None, deadline)?
        )),
        Request::Disasm { bin, addr, limit } => Ok(json!(
            session
                .open_arch(&bin, bin.arch())?
                .disasm(parse(&addr)?, limit.unwrap_or(usize::MAX))?
        )),
        Request::Ir { bin, addr } => {
            let analysis = analysis(session, &bin, &addr, deadline)?;
            passed(deadline)?;
            Ok(json!(analysis.ir.render()))
        }
        Request::Signature { bin, addr } => {
            let binary = match session.open_arch(&bin, bin.arch()) {
                Ok(binary) => binary,
                Err(error) => return Err(error),
            };
            let address = match parse(&addr) {
                Ok(address) => address,
                Err(error) => return Err(error),
            };
            let ir = match binary.annotated_ir(address, deadline) {
                Ok(ir) => ir,
                Err(error) => return Err(error),
            };
            let params = match crate::project::scalar_parameters(&ir) {
                Ok(params) => params,
                Err(_) => ir
                    .params
                    .iter()
                    .map(|param| (param.name.clone(), param.ty.clone()))
                    .collect(),
            };
            Ok(json!({
                "return": ir.ret_type.to_string(),
                "params": params.iter().map(|(name, ty)| json!({ "name": name, "type": ty.to_string() })).collect::<Vec<_>>(),
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
            session
                .open_arch(&bin, bin.arch())?
                .shape_hash(parse(&addr)?, deadline)?
        )),
        Request::BuildSignatures { bin } => {
            if bin.arch().is_some() {
                let binary = match session.open_arch(&bin, bin.arch()) {
                    Ok(binary) => binary,
                    Err(error) => return Err(error),
                };
                return match binary.build_signatures(deadline) {
                    Ok(result) => Ok(
                        json!({ "database": result.database, "failures": failures(&result.failures) }),
                    ),
                    Err(error) => Err(error),
                };
            }
            let database = match crate::sigs::build(&bin, deadline) {
                Ok(database) => database,
                Err(error) => return Err(error),
            };
            Ok(json!({ "database": database, "failures": [] }))
        }
        Request::Identify { bin, signatures } => {
            let database = match signatures {
                Value::String(path) => Database::load(path.as_ref())?,
                value => Database::from_json(value)?,
            };
            let identification = session
                .open_arch(&bin, bin.arch())?
                .identify(&database, deadline)?;
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
    bin: &BinaryRef,
    text: &str,
    deadline: Option<std::time::Instant>,
) -> Result<&'a crate::analysis::Analysis> {
    let addr = match parse(text) {
        Ok(addr) => addr,
        Err(error) => return Err(error),
    };
    let binary: &'a mut Binary = match session.open_arch(bin, bin.arch()) {
        Ok(binary) => binary,
        Err(error) => return Err(error),
    };
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

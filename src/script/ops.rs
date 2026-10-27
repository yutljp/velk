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
use crate::service::{Binary, Failure, Session, SignatureOptions};
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
        /// Signature selection used by this binary handle.
        #[serde(default, rename = "signatureOptions")]
        signature_options: SignatureOptions,
        /// Explicit headerless mapping.
        raw: Option<crate::loader::RawOptions>,
    },
}

impl BinaryRef {
    pub(crate) fn open<'session>(
        &self,
        session: &'session mut Session,
    ) -> Result<&'session mut Binary> {
        session.open_input_with_signatures(self, None, &self.options(), &self.signature_options())
    }

    fn signature_options(&self) -> SignatureOptions {
        match self {
            Self::Path(_) => SignatureOptions::default(),
            Self::Selected {
                signature_options, ..
            } => signature_options.clone(),
        }
    }

    fn options(&self) -> crate::loader::OpenOptions {
        match self {
            Self::Path(_) => crate::loader::OpenOptions::default(),
            Self::Selected { arch, raw, .. } => crate::loader::OpenOptions {
                arch: *arch,
                raw: raw.clone(),
            },
        }
    }

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
    /// Reads a target header's structure layout and function pointer signatures.
    LibraryType {
        /// Path identifying the binary and its target.
        bin: BinaryRef,
        /// The C structure tag, including `struct`.
        name: String,
    },
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
    /// Executes loaded code with explicit state and limits.
    Emulate {
        /// Path identifying the binary.
        bin: BinaryRef,
        /// Function name or virtual address.
        start: String,
        /// Initial state and execution bounds.
        #[serde(default)]
        options: crate::emulation::Options,
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
        /// Embedded and additional signature sets to use.
        #[serde(default, rename = "signatureOptions")]
        signature_options: SignatureOptions,
        /// Explicit headerless mapping.
        raw: Option<crate::loader::RawOptions>,
    },
    /// Saves a completely recovered executable to a new file.
    SaveUnpacked {
        /// Open binary to save.
        bin: BinaryRef,
        /// Destination, which must not exist.
        path: PathBuf,
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
        /// Include automatically recovered strings as comments.
        #[serde(default = "decode_strings_default", rename = "decodeStrings")]
        decode_strings: bool,
    },
    /// Renders selected functions concurrently, in address-list order.
    DecompileMany {
        /// Path identifying the binary to analyze.
        bin: BinaryRef,
        /// Function addresses; absence selects every function.
        addresses: Option<Vec<String>>,
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
        /// Include strings recovered from known execution inputs.
        #[serde(default = "decode_strings_default")]
        decode: bool,
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

fn decode_strings_default() -> bool {
    true
}

/// Executes one request against the session's cached binaries.
pub fn handle(
    session: &mut Session,
    request: Request,
    deadline: Option<std::time::Instant>,
) -> Result<Value> {
    match request {
        Request::Emulate {
            bin,
            start,
            options,
        } => {
            let binary = match bin.open(session) {
                Ok(binary) => binary,
                Err(error) => return Err(error),
            };
            match crate::emulation::run(binary, &start, &options, deadline) {
                Ok(report) => Ok(json!(report)),
                Err(error) => Err(error),
            }
        }
        Request::Navigate { bin, query } => {
            let binary = match bin.open(session) {
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
            signature_options,
            raw,
        } => {
            let binary = match session.open_input_with_signatures(
                &path,
                project.as_deref(),
                &crate::loader::OpenOptions { arch, raw },
                &signature_options,
            ) {
                Ok(binary) => binary,
                Err(error) => return Err(error),
            };
            let image = binary.image();
            Ok(json!({
                "id": { "path": binary.path(), "arch": arch, "raw": binary.input_options().raw, "signatureOptions": signature_options },
                "path": binary.path(),
                "format": image.format,
                "packing": image.packing,
                "arch": image.isa,
                "slices": image.slices,
                "sliceOffset": image.slice_offset,
                "entry": image.entry.map(addr::format),
            }))
        }
        Request::SaveUnpacked { bin, path } => {
            let binary = match bin.open(session) {
                Ok(binary) => binary,
                Err(error) => return Err(error),
            };
            match binary.image().save_unpacked(&path) {
                Ok(()) => Ok(json!({"saved": path})),
                Err(error) => Err(error),
            }
        }
        Request::LibraryType { bin, name } => {
            let binary = match bin.open(session) {
                Ok(binary) => binary,
                Err(error) => return Err(error),
            };
            Ok(json!(crate::analysis::prototypes::record(
                &name,
                binary.image()
            )))
        }
        Request::Classes { bin } => {
            let binary = match bin.open(session) {
                Ok(binary) => binary,
                Err(error) => return Err(error),
            };
            Ok(json!(binary.image().classes()))
        }
        Request::Sections { bin } => Ok(json!(
            match bin.open(session) {
                Ok(binary) => binary,
                Err(error) => return Err(error),
            }
            .image()
            .sections
        )),
        Request::Functions { bin } => Ok(json!(
            match bin.open(session) {
                Ok(binary) => binary,
                Err(error) => return Err(error),
            }
            .functions()
        )),
        Request::Find { bin, target } => {
            let binary = match bin.open(session) {
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
            let card = match bin.open(session) {
                Ok(binary) => binary,
                Err(error) => return Err(error),
            }
            .card(
                parse(&addr)?,
                budget.unwrap_or(DEFAULT_BUDGET),
                None,
                deadline,
            )?;
            Ok(json!(card))
        }
        Request::Decompile {
            bin,
            addr,
            decode_strings,
        } => {
            let binary = match bin.open(session) {
                Ok(binary) => binary,
                Err(error) => return Err(error),
            };
            binary.set_string_decoding(decode_strings);
            let address = match parse(&addr) {
                Ok(address) => address,
                Err(error) => return Err(error),
            };
            match binary.decompile(address, None, deadline) {
                Ok(code) => Ok(json!(code)),
                Err(error) => Err(error),
            }
        }
        Request::DecompileMany { bin, addresses } => {
            let binary = match bin.open(session) {
                Ok(binary) => binary,
                Err(error) => return Err(error),
            };
            binary.set_string_decoding(true);
            let addresses = match addresses {
                Some(addresses) => {
                    let mut parsed = Vec::with_capacity(addresses.len());
                    for address in addresses {
                        match parse(&address) {
                            Ok(address) => parsed.push(address),
                            Err(error) => return Err(error),
                        }
                    }
                    parsed
                }
                None => binary.image().functions.keys().copied().collect(),
            };
            let results = match binary.decompile_many(&addresses, None, deadline) {
                Ok(results) => results,
                Err(error) => return Err(error),
            };
            let mut output = Vec::with_capacity(results.len());
            for (addr, result) in addresses.into_iter().zip(results) {
                output.push(match result {
                    Ok(code) => json!({ "addr": crate::addr::format(addr), "code": code, "error": null }),
                    Err(error) => json!({ "addr": crate::addr::format(addr), "code": null, "error": error.to_string() }),
                });
            }
            Ok(json!(output))
        }
        Request::Disasm { bin, addr, limit } => Ok(json!(
            bin.open(session)?
                .disasm(parse(&addr)?, limit.unwrap_or(usize::MAX))?
        )),
        Request::Ir { bin, addr } => {
            let analysis = analysis(session, &bin, &addr, deadline)?;
            passed(deadline)?;
            Ok(json!(analysis.ir.render()))
        }
        Request::Signature { bin, addr } => {
            let binary = match bin.open(session) {
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
                Err(_)
                    if ir.params.is_empty()
                        && matches!(
                            ir.convention,
                            crate::ir::Convention::Cdecl | crate::ir::Convention::Stdcall
                        ) =>
                {
                    let mut params: Vec<_> = ir.stack_params.iter().collect();
                    params.sort_by_key(|param| param.position);
                    params
                        .into_iter()
                        .map(|param| (param.name.clone(), param.ty.clone()))
                        .collect()
                }
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
                    "guid": reference.guid,
                })
            })
            .collect()),
        Request::Strings { bin, addr, decode } => {
            let mut strings = match analysis(session, &bin, &addr, deadline) {
                Ok(analysis) => analysis.strings(),
                Err(error) => return Err(error),
            };
            if decode {
                let address = match parse(&addr) {
                    Ok(address) => address,
                    Err(error) => return Err(error),
                };
                let binary = match bin.open(session) {
                    Ok(binary) => binary,
                    Err(error) => return Err(error),
                };
                for string in binary.decoded_strings_at(address, deadline) {
                    if !strings.contains(&string.text) {
                        strings.push(string.text.clone());
                    }
                }
            }
            Ok(json!(strings))
        }
        Request::ShapeHash { bin, addr } => Ok(json!(
            bin.open(session)?.shape_hash(parse(&addr)?, deadline)?
        )),
        Request::BuildSignatures { bin } => {
            if bin.arch().is_some() || bin.options().raw.is_some() {
                let binary = match bin.open(session) {
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
            let identification = bin.open(session)?.identify(&database, deadline)?;
            Ok(json!({
                "matches": identification.matches.iter().map(|m| json!({
                    "addr": addr::format(m.addr),
                    "size": m.size,
                    "current": m.current,
                    "matched": m.matched,
                    "evidence": m.evidence,
                })).collect::<Vec<_>>(),
                "candidates": identification.candidates.iter().map(|(address, evidence)| json!({
                    "addr": addr::format(*address), "evidence": evidence,
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
    let binary: &'a mut Binary = match bin.open(session) {
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

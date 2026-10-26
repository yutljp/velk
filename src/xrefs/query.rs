//! Query results shared by CLI and scripts.
use crate::error::{Error, Result};
use crate::service::Binary;
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Instant;

/// A navigation or memory operation shared by the query interfaces.
#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum Query {
    /// Searches loaded sections for a byte, text or integer pattern.
    Search {
        /// Text interpreted according to the selected encoding.
        pattern: String,
        /// Pattern encoding and section or address restrictions.
        #[serde(default)]
        options: crate::memory::Search,
    },
    /// Decodes complete typed values within one loaded section.
    ReadMemory {
        /// Virtual address or a symbol resolving to one.
        target: String,
        /// Scalar, string, array or debug structure type.
        #[serde(rename = "type")]
        type_name: String,
        /// Number of consecutive values; defaults to one.
        #[serde(default = "one_count")]
        count: u64,
    },
    /// Finds exact standard constant signatures and their references.
    DetectConstants,
    Xrefs {
        target: String,
        #[serde(default)]
        from: bool,
    },
    Callers {
        target: String,
        #[serde(default = "one")]
        depth: usize,
    },
    Callees {
        target: String,
        #[serde(default = "one")]
        depth: usize,
    },
    Path {
        from: String,
        to: String,
        #[serde(default = "path_depth")]
        depth: usize,
    },
    Strings {
        contains: Option<String>,
    },
    Constants {
        value: String,
    },
    Summary {
        target: String,
    },
}
fn one_count() -> u64 {
    1
}
fn one() -> usize {
    1
}
fn path_depth() -> usize {
    32
}

/// Answers a query against the loaded image, honoring the optional deadline.
pub fn run(binary: &mut Binary, query: Query, deadline: Option<Instant>) -> Result<Value> {
    match query {
        Query::Search { pattern, options } => {
            crate::memory::search(binary.image(), &pattern, &options, deadline)
        }
        Query::ReadMemory {
            target,
            type_name,
            count,
        } => {
            let address = match binary.find_address(&target) {
                Ok(address) => address,
                Err(error) => return Err(error),
            };
            crate::memory::read(binary.image(), address, &type_name, count, deadline)
        }
        Query::DetectConstants => crate::tables::detect(binary, deadline),
        Query::Constants { value } => {
            let Some(value) = crate::addr::parse(&value) else {
                return Err(Error::BadAddress(value));
            };
            match super::constants::search(binary.image(), value, deadline) {
                Ok(matches) => Ok(json!({ "matches": matches })),
                Err(error) => Err(error),
            }
        }
        Query::Summary { target } => {
            let addr = match binary.find_address(&target) {
                Ok(addr) => addr,
                Err(error) => return Err(error),
            };
            binary.summary(addr, deadline)
        }
        Query::Strings { contains } => {
            let index = match binary.navigation(deadline) {
                Ok(index) => index,
                Err(error) => return Err(error),
            };
            Ok(
                json!({ "strings": index.strings().iter().filter(|s| contains.as_ref().is_none_or(|text| s.text.contains(text))).collect::<Vec<_>>(), "failures": index.failures }),
            )
        }
        Query::Xrefs { target, from } => {
            let addr = match binary.find_address(&target) {
                Ok(addr) => addr,
                Err(error) => return Err(error),
            };
            let index = match binary.navigation(deadline) {
                Ok(index) => index,
                Err(error) => return Err(error),
            };
            Ok(
                json!({ "xrefs": if from { index.from(addr) } else { index.to(addr) }, "failures": index.failures }),
            )
        }
        Query::Path { from, to, depth } => {
            let from = match binary.find_address(&from) {
                Ok(addr) => addr,
                Err(error) => return Err(error),
            };
            let to = match binary.find_address(&to) {
                Ok(addr) => addr,
                Err(error) => return Err(error),
            };
            let index = match binary.navigation(deadline) {
                Ok(index) => index,
                Err(error) => return Err(error),
            };
            Ok(
                json!({ "path": index.path(from, to, depth).into_iter().map(crate::addr::format).collect::<Vec<_>>(), "failures": index.failures }),
            )
        }
        Query::Callers { ref target, depth } | Query::Callees { ref target, depth } => {
            let addr = match binary.find_address(target) {
                Ok(addr) => addr,
                Err(error) => return Err(error),
            };
            let callers = matches!(query, Query::Callers { .. });
            let names: std::collections::BTreeMap<_, _> = binary
                .functions()
                .into_iter()
                .map(|f| (f.addr, f.name))
                .chain(
                    binary
                        .image()
                        .imports
                        .iter()
                        .map(|(addr, name)| (*addr, Some(name.clone()))),
                )
                .collect();
            let index = match binary.navigation(deadline) {
                Ok(index) => index,
                Err(error) => return Err(error),
            };
            Ok(
                json!({ "functions": index.graph(addr, callers, depth).into_iter().map(|addr| json!({ "addr": crate::addr::format(addr), "name": names.get(&addr).cloned().flatten() })).collect::<Vec<_>>(), "failures": index.failures }),
            )
        }
    }
}

//! Query results shared by CLI and scripts.
use crate::error::{Error, Result};
use crate::service::Binary;
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Instant;

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum Query {
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
fn one() -> usize {
    1
}
fn path_depth() -> usize {
    32
}

pub fn run(binary: &mut Binary, query: Query, deadline: Option<Instant>) -> Result<Value> {
    let resolve = |text: &str| binary.find_address(text);
    match query {
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
            let addr = match resolve(&target) {
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
            let addr = match resolve(&target) {
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
            let from = match resolve(&from) {
                Ok(addr) => addr,
                Err(error) => return Err(error),
            };
            let to = match resolve(&to) {
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
            let addr = match resolve(target) {
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

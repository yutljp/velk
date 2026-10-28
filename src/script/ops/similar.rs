//! Similarity requests use the session's existing binary handles and indexes.

use std::time::Instant;

use serde_json::{Value, json};

use super::BinaryRef;
use crate::error::{Error, Result};
use crate::service::Session;

pub(super) fn search(
    session: &mut Session,
    bin: BinaryRef,
    target: String,
    other: Option<BinaryRef>,
    limit: usize,
    deadline: Option<Instant>,
) -> Result<Value> {
    let binary = match bin.open(session) {
        Ok(binary) => binary,
        Err(error) => return Err(error),
    };
    let addr = match binary.find(&target) {
        Ok(function) => function.addr,
        Err(error) => return Err(error),
    };
    let Some(other) = other else {
        return binary
            .similar(addr, limit, deadline)
            .map(|report| json!(report));
    };
    if let Err(error) = binary.analysis(addr, deadline) {
        return Err(error);
    }
    let index = match binary.similarity_index(deadline) {
        Ok(index) => index,
        Err(error) => return Err(error),
    };
    let Some(features) = index.features(addr) else {
        return Err(Error::NoFunctionAt(addr));
    };
    let binary = match other.open(session) {
        Ok(binary) => binary,
        Err(error) => return Err(error),
    };
    let index = match binary.similarity_index(deadline) {
        Ok(index) => index,
        Err(error) => return Err(error),
    };
    index
        .search(&features, None, limit, deadline)
        .map(|report| json!(report))
}

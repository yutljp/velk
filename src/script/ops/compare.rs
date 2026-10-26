//! Comparison requests shared by JavaScript and MCP.

use std::time::Instant;

use serde_json::{Value, json};

use super::BinaryRef;
use crate::error::Result;
use crate::service::{Binary, Session};

pub(super) fn handle(
    session: &mut Session,
    first: BinaryRef,
    second: BinaryRef,
    carry: bool,
    deadline: Option<Instant>,
) -> Result<Value> {
    let first_project = match first.open(session) {
        Ok(binary) => binary.project_path().to_owned(),
        Err(error) => return Err(error),
    };
    let second_project = match second.open(session) {
        Ok(binary) => binary.project_path().to_owned(),
        Err(error) => return Err(error),
    };
    let mut first = match Binary::open_input_with_signatures(
        &first,
        Some(&first_project),
        &first.options(),
        &first.signature_options(),
    ) {
        Ok(binary) => binary,
        Err(error) => return Err(error),
    };
    let mut second = match Binary::open_input_with_signatures(
        &second,
        Some(&second_project),
        &second.options(),
        &second.signature_options(),
    ) {
        Ok(binary) => binary,
        Err(error) => return Err(error),
    };
    match crate::compare::compare(&mut first, &mut second, carry, deadline) {
        Ok(report) => Ok(json!(report)),
        Err(error) => Err(error),
    }
}

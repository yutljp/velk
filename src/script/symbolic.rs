//! JavaScript handles for live symbolic states and opaque bit-vector terms.

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::error::Result;
use crate::ir::Cond;
use crate::script::ops::BinaryRef;
use crate::service::Session;
use crate::symbolic::{State, Step, Term, invalid};

const STATE_LIMIT: usize = 256;
const TERM_LIMIT: usize = 65_536;

#[derive(Default)]
pub(super) struct Registry {
    states: BTreeMap<usize, State>,
    terms: Vec<Term>,
    next: usize,
}

impl Registry {
    fn insert(&mut self, state: State, reserved: usize) -> Result<usize> {
        if self.states.len() >= STATE_LIMIT.saturating_sub(reserved) {
            return Err(invalid("symbolic state limit reached"));
        }
        let index = self.next;
        self.next = match self
            .next
            .checked_add(1)
            .ok_or_else(|| invalid("state handle overflow"))
        {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        self.states.insert(index, state);
        Ok(index)
    }

    fn term(&mut self, term: Term) -> Result<Value> {
        if self.terms.len() >= TERM_LIMIT {
            return Err(invalid("symbolic term limit reached"));
        }
        let id = self.terms.len();
        self.terms.push(term);
        Ok(json!({"id": id}))
    }

    fn lookup(&self, value: &Value) -> Result<Term> {
        let id: usize = match field(value, "id") {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        self.terms
            .get(id)
            .cloned()
            .ok_or_else(|| invalid("unknown term handle"))
    }
}

fn field<T: DeserializeOwned>(value: &Value, name: &str) -> Result<T> {
    match serde_json::from_value(value.get(name).cloned().unwrap_or(Value::Null)) {
        Ok(value) => Ok(value),
        Err(error) => Err(invalid(format!("invalid symbolic {name}: {error}"))),
    }
}

pub(super) fn handle(
    session: &mut Session,
    registry: &mut Registry,
    request: Value,
) -> Result<Value> {
    let bin: BinaryRef = match field(&request, "bin") {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let action: String = match field(&request, "action") {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let binary = match bin.open(session) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    if action == "create" {
        let start: String = match field(&request, "start") {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let options = match field(&request, "options") {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let start_state = match State::new(binary, &start, &options) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        return registry.insert(start_state, 0).map(|id| json!(id));
    }
    let id: usize = match field(&request, "state") {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let Some(mut state) = registry.states.remove(&id) else {
        return Err(invalid("unknown symbolic state handle"));
    };
    if action == "dispose" {
        return Ok(Value::Null);
    }
    let result = (|| match action.as_str() {
        "fork" => {
            let id = match registry.insert(state.clone(), 1) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            Ok(json!(id))
        }
        "term" => {
            let term = match state.symbolic() {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            registry.term(term)
        }
        "constant" => {
            let value: crate::emulation::Word = match field(&request, "value") {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let constant = match value.value() {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            registry.term(Term::constant(constant))
        }
        "readRegister" => {
            let register_index = match field(&request, "index") {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let register = match state.read_register(register_index) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            registry.term(register)
        }
        "writeRegister" => {
            let term = match registry.lookup(&request["term"]) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let register_index = match field(&request, "index") {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            if let Err(error) = state.write_register(register_index, term) {
                return Err(error);
            }
            Ok(Value::Null)
        }
        "readMemory" => {
            let at: crate::emulation::Word = match field(&request, "at") {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let memory_address = match at.value() {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let read_size = match field(&request, "size") {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let terms = match state.read_memory(binary, memory_address, read_size) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            if terms.len() > TERM_LIMIT.saturating_sub(registry.terms.len()) {
                return Err(invalid("symbolic term limit reached"));
            }
            let handles: Vec<Value> = match terms
                .into_iter()
                .map(|term| registry.term(term))
                .collect::<Result<_>>()
            {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            Ok(json!(handles))
        }
        "writeMemory" => {
            let at: crate::emulation::Word = match field(&request, "at") {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let values: Vec<Value> = match field(&request, "terms") {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let terms: Vec<Term> = match values
                .iter()
                .map(|value| registry.lookup(value))
                .collect::<Result<_>>()
            {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let write_address = match at.value() {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            if let Err(error) = state.write_memory(binary, write_address, &terms) {
                return Err(error);
            }
            Ok(Value::Null)
        }
        "constrain" => {
            let lhs = match registry.lookup(&request["lhs"]) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let rhs = match registry.lookup(&request["rhs"]) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let condition: String = match field(&request, "condition") {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let cond = match condition.as_str() {
                "eq" => Cond::Eq,
                "ne" => Cond::Ne,
                "ult" => Cond::Cc,
                "ule" => Cond::Ls,
                "ugt" => Cond::Hi,
                "uge" => Cond::Cs,
                "slt" => Cond::Lt,
                "sle" => Cond::Le,
                "sgt" => Cond::Gt,
                "sge" => Cond::Ge,
                _ => return Err(invalid("unknown symbolic condition")),
            };
            let bit_count = match field(&request, "bits") {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            if let Err(error) = state.constrain(cond, &lhs, &rhs, bit_count) {
                return Err(error);
            }
            Ok(Value::Null)
        }
        "satisfiable" => {
            let satisfiable = match state.satisfiable() {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            Ok(json!(satisfiable))
        }
        "evaluate" => {
            let term = match registry.lookup(&request["term"]) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let solution_count = match field(&request, "count") {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let values = match state.evaluate(&term, solution_count) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            Ok(json!(
                values
                    .into_iter()
                    .map(crate::addr::format)
                    .collect::<Vec<_>>()
            ))
        }
        "bounds" => {
            let term = match registry.lookup(&request["term"]) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };

            let bounds = match state.bounds(&term) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            Ok(json!(bounds.map(|(min, max)| [
                crate::addr::format(min),
                crate::addr::format(max)
            ])))
        }
        "address" => Ok(json!(crate::addr::format(state.address()))),
        "step" => {
            let words: Vec<crate::emulation::Word> = match field(&request, "until") {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let until = match words
                .iter()
                .map(crate::emulation::Word::value)
                .collect::<Result<Vec<_>>>()
            {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let step = match state.step(binary, &until) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            match step {
                Step::Reached => Ok(
                    json!({"reason": "address", "address": crate::addr::format(state.address())}),
                ),
                Step::Stopped(reason) => Ok(json!({"reason": reason})),
                Step::Branch(states) => {
                    if states.len() > STATE_LIMIT.saturating_sub(registry.states.len() + 1) {
                        return Err(invalid("symbolic state limit reached"));
                    }
                    let mut ids = Vec::new();
                    for state in states {
                        let id = match registry.insert(state, 1) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        };
                        ids.push(id);
                    }
                    Ok(json!({"reason": "branch", "states": ids}))
                }
            }
        }
        _ => Err(invalid("unknown symbolic action")),
    })();
    registry.states.insert(id, state);
    result
}

//! JavaScript handles for live symbolic states and opaque bit-vector terms.

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::error::Result;
use crate::ir::Cond;
use crate::script::ops::BinaryRef;
use crate::service::Session;
use crate::symbolic::{State, Step, Term, invalid};

#[derive(Default)]
pub(super) struct Registry {
    states: BTreeMap<usize, State>,
    terms: Vec<Term>,
    next: usize,
}

impl Registry {
    fn insert(&mut self, state: State) -> Result<usize> {
        let index = self.next;
        self.next = self
            .next
            .checked_add(1)
            .ok_or_else(|| invalid("state handle overflow"))?;
        self.states.insert(index, state);
        Ok(index)
    }

    fn term(&mut self, term: Term) -> Value {
        let id = self.terms.len();
        self.terms.push(term);
        json!({"id": id})
    }

    fn lookup(&self, value: &Value) -> Result<Term> {
        let id: usize = field(value, "id")?;
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
    let bin: BinaryRef = field(&request, "bin")?;
    let action: String = field(&request, "action")?;
    let binary = bin.open(session)?;
    if action == "create" {
        let start: String = field(&request, "start")?;
        let options = field(&request, "options")?;
        return registry
            .insert(State::new(binary, &start, &options)?)
            .map(|id| json!(id));
    }
    let id: usize = field(&request, "state")?;
    let Some(mut state) = registry.states.remove(&id) else {
        return Err(invalid("unknown symbolic state handle"));
    };
    if action == "dispose" {
        return Ok(Value::Null);
    }
    let result = (|| match action.as_str() {
        "fork" => Ok(json!(registry.insert(state.clone())?)),
        "term" => Ok(registry.term(state.symbolic()?)),
        "constant" => {
            let value: crate::emulation::Word = field(&request, "value")?;
            Ok(registry.term(Term::constant(value.value()?)))
        }
        "readRegister" => Ok(registry.term(state.read_register(field(&request, "index")?)?)),
        "writeRegister" => {
            let term = registry.lookup(&request["term"])?;
            state.write_register(field(&request, "index")?, term)?;
            Ok(Value::Null)
        }
        "readMemory" => {
            let at: crate::emulation::Word = field(&request, "at")?;
            let terms = state.read_memory(binary, at.value()?, field(&request, "size")?)?;
            let handles: Vec<Value> = terms.into_iter().map(|term| registry.term(term)).collect();
            Ok(json!(handles))
        }
        "writeMemory" => {
            let at: crate::emulation::Word = field(&request, "at")?;
            let values: Vec<Value> = field(&request, "terms")?;
            let terms: Vec<Term> = values
                .iter()
                .map(|value| registry.lookup(value))
                .collect::<Result<_>>()?;
            state.write_memory(binary, at.value()?, &terms)?;
            Ok(Value::Null)
        }
        "constrain" => {
            let lhs = registry.lookup(&request["lhs"])?;
            let rhs = registry.lookup(&request["rhs"])?;
            let condition: String = field(&request, "condition")?;
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
            state.constrain(cond, &lhs, &rhs, field(&request, "bits")?)?;
            Ok(Value::Null)
        }
        "satisfiable" => Ok(json!(state.satisfiable()?)),
        "evaluate" => {
            let term = registry.lookup(&request["term"])?;
            let values = state.evaluate(&term, field(&request, "count")?)?;
            Ok(json!(
                values
                    .into_iter()
                    .map(crate::addr::format)
                    .collect::<Vec<_>>()
            ))
        }
        "bounds" => {
            let term = registry.lookup(&request["term"])?;
            Ok(json!(state.bounds(&term)?.map(|(min, max)| [
                crate::addr::format(min),
                crate::addr::format(max)
            ])))
        }
        "address" => Ok(json!(crate::addr::format(state.address()))),
        "step" => {
            let words: Vec<crate::emulation::Word> = field(&request, "until")?;
            let until = words
                .iter()
                .map(crate::emulation::Word::value)
                .collect::<Result<Vec<_>>>()?;
            match state.step(binary, &until)? {
                Step::Reached => Ok(
                    json!({"reason": "address", "address": crate::addr::format(state.address())}),
                ),
                Step::Stopped(reason) => Ok(json!({"reason": reason})),
                Step::Branch(states) => {
                    let mut ids = Vec::new();
                    for state in states {
                        ids.push(registry.insert(state)?);
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

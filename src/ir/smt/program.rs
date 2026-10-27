//! Acyclic control flow and byte-array memory for pass equivalence checks.

use super::{Proofs, Value, condition, constant, low, memory_value};
use crate::ir::{FunctionIr, Stmt};
use std::collections::BTreeMap;

#[derive(Clone)]
struct State {
    registers: BTreeMap<u16, String>,
    memory: String,
    defined: String,
}

struct Returned {
    value: Value,
    memory: String,
}

fn execute(ir: &FunctionIr, block: usize, mut state: State, mut path: Vec<usize>) -> Returned {
    assert!(!path.contains(&block), "SMT CFG templates must be acyclic");
    path.push(block);
    let target = |address| {
        ir.blocks
            .iter()
            .position(|block| block.start == address)
            .expect("branch target exists")
    };
    for statement in &ir.blocks[block].stmts {
        let read = |expr| memory_value(expr, &state.registers, &state.memory);
        match statement {
            Stmt::Assign { dest, value } => {
                let value = read(value);
                state.defined = format!("(and {} {})", state.defined, value.defined);
                state
                    .registers
                    .insert(dest.index, low(&value.term, u32::from(dest.width)));
            }
            Stmt::Store { addr, value, width } => {
                let addr = read(addr);
                let value = read(value);
                state.defined =
                    format!("(and {} {} {})", state.defined, addr.defined, value.defined);
                for byte in 0..*width {
                    let offset = constant(u64::from(byte));
                    let first = u32::from(byte) * 8;
                    state.memory = format!(
                        "(store {} (bvadd {} {offset}) ((_ extract {} {first}) {}))",
                        state.memory,
                        addr.term,
                        first + 7,
                        value.term
                    );
                }
            }
            Stmt::Ret { value } => {
                let mut value = read(value);
                value.defined = format!("(and {} {})", state.defined, value.defined);
                return Returned {
                    value,
                    memory: state.memory,
                };
            }
            Stmt::Br {
                target: Some(address),
            } => return execute(ir, target(*address), state, path),
            Stmt::Brif {
                cond,
                lhs,
                rhs,
                target: address,
            } => {
                let a = read(lhs);
                let b = read(rhs);
                let test = condition(
                    *cond,
                    &a.term,
                    &b.term,
                    crate::ir::semantics::operand_width(lhs, rhs),
                );
                state.defined = format!("(and {} {} {})", state.defined, a.defined, b.defined);
                let then = execute(ir, target(*address), state.clone(), path.clone());
                let els = execute(ir, block + 1, state, path);
                return Returned {
                    value: Value {
                        term: format!("(ite {test} {} {})", then.value.term, els.value.term),
                        defined: format!(
                            "(ite {test} {} {})",
                            then.value.defined, els.value.defined
                        ),
                    },
                    memory: format!("(ite {test} {} {})", then.memory, els.memory),
                };
            }
            Stmt::Switch {
                index,
                cases,
                default,
            } => {
                let index = read(index);
                state.defined = format!("(and {} {})", state.defined, index.defined);
                let mut result = match default {
                    Some(default) => execute(ir, target(*default), state.clone(), path.clone()),
                    None => Returned {
                        value: Value {
                            term: constant(0),
                            defined: "false".to_owned(),
                        },
                        memory: state.memory.clone(),
                    },
                };
                for (number, address) in cases {
                    let arm = execute(ir, target(*address), state.clone(), path.clone());
                    let test = format!("(= {} {})", index.term, constant(*number as u64));
                    result.value.term =
                        format!("(ite {test} {} {})", arm.value.term, result.value.term);
                    result.value.defined = format!(
                        "(ite {test} {} {})",
                        arm.value.defined, result.value.defined
                    );
                    result.memory = format!("(ite {test} {} {})", arm.memory, result.memory);
                }
                return result;
            }
            Stmt::Trap => {
                return Returned {
                    value: Value {
                        term: constant(0),
                        defined: "false".to_owned(),
                    },
                    memory: state.memory,
                };
            }
            _ => panic!("unsupported SMT CFG statement: {statement:?}"),
        }
    }
    execute(ir, block + 1, state, path)
}

impl Proofs {
    pub(crate) fn function_return_value(
        &mut self,
        name: impl Into<String>,
        before: &FunctionIr,
        after: &FunctionIr,
    ) {
        let state = State {
            registers: BTreeMap::new(),
            memory: "memory".to_owned(),
            defined: "true".to_owned(),
        };
        let before = execute(before, 0, state.clone(), Vec::new()).value;
        let after = execute(after, 0, state, Vec::new()).value;
        self.cases.push((
            name.into(),
            format!(
                "(or (not (= {} {})) (and {} (not (= {} {}))))",
                before.defined, after.defined, before.defined, before.term, after.term
            ),
        ));
    }

    pub(crate) fn function(
        &mut self,
        name: impl Into<String>,
        before: &FunctionIr,
        after: &FunctionIr,
    ) {
        let state = State {
            registers: BTreeMap::new(),
            memory: "memory".to_owned(),
            defined: "true".to_owned(),
        };
        let before = execute(before, 0, state.clone(), Vec::new());
        let after = execute(after, 0, state, Vec::new());
        self.cases.push((
            name.into(),
            format!(
                "(or (not (= {} {})) (and {} (or (not (= {} {})) (not (= {} {})))))",
                before.value.defined,
                after.value.defined,
                before.value.defined,
                before.value.term,
                after.value.term,
                before.memory,
                after.memory
            ),
        ));
    }
}

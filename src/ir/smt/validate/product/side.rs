//! What each side of the product holds: its registers, memory and the facts both sides share.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use crate::ir::smt::validate::{BITS, MEMORY, Script, modeled, registers_read};
use crate::ir::smt::{Value, constant, low, memory_value, memory_value_resolved};
use crate::ir::{Expr, RegRef};

/// One side's symbolic state within a block.
#[derive(Clone)]
pub(super) struct Side {
    /// The prefix of the symbols for the registers' values on entry.
    pub(super) entry: &'static str,
    /// Registers the block's invariants make equal on the two sides on
    /// entry, which both sides read as one symbol.
    pub(super) shared: Rc<BTreeSet<u16>>,
    pub(super) registers: BTreeMap<u16, String>,
    pub(super) memory: String,
    /// The definedness of everything this side computed so far.
    pub(super) defined: String,
    /// What both sides know of the one memory they share.
    pub(super) facts: Rc<Facts>,
}

/// Facts of the memory both sides of a block share.
#[derive(Default)]
pub(super) struct Facts {
    /// A Boolean of the script that holds of every fact so far.
    pub(super) known: RefCell<String>,
    /// The memories calls left that keep bytes of the frame.
    pub(super) layers: RefCell<Vec<Layer>>,
}

/// The memory a statement leaves, which keeps the bytes of the memory
/// before it that both sides' stack pointers place where `kept` says. Only
/// a load from the stack pointer plus a constant reads a kept byte: a
/// pointer from elsewhere may reach the frames of the function's callers,
/// which a callee may be handed and write.
pub(super) struct Layer {
    pub(super) memory: String,
    pub(super) inner: String,
    /// The stack pointer and the width addresses read it at.
    pub(super) sp: (u16, u8),
    pub(super) stack: (String, String),
    pub(super) kept: Kept,
}

/// Where a layer keeps the bytes before it, from the stack pointer.
pub(super) enum Kept {
    /// At this many bytes or more past it: a call leaves the frame past
    /// the arguments it may write.
    Past(String),
    /// Below it: an atomic or barrier writes no byte of a frame whose
    /// address the function hands out nowhere.
    Below,
}

impl Side {
    pub(super) fn new(
        entry: &'static str,
        shared: &Rc<BTreeSet<u16>>,
        memory: &str,
        facts: &Rc<Facts>,
    ) -> Self {
        Self {
            entry,
            shared: Rc::clone(shared),
            registers: BTreeMap::new(),
            memory: memory.to_owned(),
            defined: "true".to_owned(),
            facts: Rc::clone(facts),
        }
    }

    /// What the side's statements so far assume: their definedness, and
    /// what both sides know of the memory.
    pub(super) fn premise(&self) -> String {
        let known = self.facts.known.borrow();
        if known.is_empty() {
            self.defined.clone()
        } else {
            format!("(and {} {known})", self.defined)
        }
    }

    /// For each byte `expr` loads from a memory a call left, that the
    /// memory holds the byte the memory before the call held, where the
    /// call keeps it: the definition of the layer, at the bytes read.
    pub(super) fn layer_facts(&self, script: &mut Script, expr: &Expr) {
        if self.facts.layers.borrow().is_empty() {
            return;
        }
        let mut loads = Vec::new();
        collect_loads(expr, &mut loads);
        for (addr, width) in loads {
            if opaque_any(addr) {
                continue;
            }
            let base = crate::passes::memory::split_offset(addr).0;
            let address = memory_value(addr, &self.registers, &self.memory).term;
            let mut facts = Vec::new();
            for byte in 0..u64::from(width) {
                let at = format!("(bvadd {address} {})", constant(byte));
                for layer in self.facts.layers.borrow().iter() {
                    if !matches!(base, Expr::Reg { index, width } if (*index, *width) == layer.sp) {
                        continue;
                    }
                    let kept = |stack: &str| match &layer.kept {
                        Kept::Past(bound) => format!("(bvsge (bvsub {at} {stack}) {bound})"),
                        Kept::Below => format!("(bvslt (bvsub {at} {stack}) {})", constant(0)),
                    };
                    facts.push(format!(
                        "(=> (and {} {}) (= (select {} {at}) (select {} {at})))",
                        kept(&layer.stack.0),
                        kept(&layer.stack.1),
                        layer.memory,
                        layer.inner,
                    ));
                }
            }
            if facts.is_empty() {
                continue;
            }
            let mut known = self.facts.known.borrow_mut();
            let conjunction = format!("(and {} {})", known_or_true(&known), facts.join(" "));
            *known = script.define("Bool", conjunction);
        }
    }

    pub(super) fn term(&mut self, script: &mut Script, index: u16) -> String {
        if let Some(term) = self.registers.get(&index) {
            return term.clone();
        }
        let name = if self.shared.contains(&index) {
            format!("s{index}")
        } else {
            format!("{}{index}", self.entry)
        };
        script.declare(&name, BITS);
        self.registers.insert(index, name.clone());
        name
    }

    pub(super) fn read(&mut self, script: &mut Script, expr: &Expr) -> Value {
        let mut read = BTreeSet::new();
        registers_read(expr, &mut read);
        for index in read {
            self.term(script, index);
        }
        self.layer_facts(script, expr);
        memory_value(expr, &self.registers, &self.memory)
    }

    pub(super) fn assume(&mut self, script: &mut Script, defined: &str) {
        if defined != "(and true )" && defined != "true" {
            self.defined = script.define("Bool", format!("(and {} {defined})", self.defined));
        }
    }

    pub(super) fn set(&mut self, dest: RegRef, term: &str) {
        self.registers
            .insert(dest.index, low(term, u32::from(dest.width)));
    }

    /// Assigns `value` to `dest`, its undefined values being `undefined` in
    /// order, as many as given, and any values after them.
    pub(super) fn assign(
        &mut self,
        script: &mut Script,
        dest: RegRef,
        value: &Expr,
        undefined: &[String],
    ) {
        let mut read = BTreeSet::new();
        registers_read(value, &mut read);
        for index in read {
            self.term(script, index);
        }
        self.layer_facts(script, value);
        // Each undefined value is any value, independently unless given; an
        // operation the solver does not model is one function of its
        // arguments on both sides.
        let mut unmodeled = Vec::new();
        opaque(value, &mut unmodeled);
        let mut operands: Vec<(&Expr, String)> = Vec::new();
        let mut given = undefined.iter();
        for node in unmodeled {
            let Expr::Apply { op, args } = node else {
                unreachable!("an unmodeled operation is an application");
            };
            let term = if *op == crate::ir::Operation::Undefined {
                given.next().cloned().unwrap_or_else(|| script.havoc(BITS))
            } else {
                let terms: Vec<String> = args
                    .iter()
                    .map(|arg| {
                        let resolved: Vec<(&Expr, &str)> = operands
                            .iter()
                            .map(|(node, term)| (*node, term.as_str()))
                            .collect();
                        let arg =
                            memory_value_resolved(arg, &self.registers, &self.memory, &resolved);
                        self.assume(script, &arg.defined);
                        arg.term
                    })
                    .collect();
                script.function(*op, &terms)
            };
            operands.push((node, term));
        }
        let resolved: Vec<(&Expr, &str)> = operands
            .iter()
            .map(|(node, term)| (*node, term.as_str()))
            .collect();
        let value = memory_value_resolved(value, &self.registers, &self.memory, &resolved);
        self.assume(script, &value.defined);
        let term = script.define(BITS, value.term);
        self.set(dest, &term);
    }

    pub(super) fn store(&mut self, script: &mut Script, addr: &str, value: &str, width: u8) {
        let address = script.define(BITS, addr.to_owned());
        let stored = script.define(BITS, value.to_owned());
        let mut memory = self.memory.clone();
        for byte in 0..width {
            let first = u32::from(byte) * 8;
            memory = format!(
                "(store {memory} (bvadd {address} {}) ((_ extract {} {first}) {stored}))",
                constant(u64::from(byte)),
                first + 7,
            );
        }
        self.memory = script.define(MEMORY, memory);
    }
}

/// The applications in `expr` of operations the solver does not model,
/// each after those among its arguments.
pub(super) fn opaque<'a>(expr: &'a Expr, found: &mut Vec<&'a Expr>) {
    for child in crate::ir::visit::children(expr) {
        opaque(child, found);
    }
    if let Expr::Apply { op, .. } = expr
        && !modeled(*op)
    {
        found.push(expr);
    }
}

/// The address and width of each load in `expr`.
pub(super) fn collect_loads<'a>(expr: &'a Expr, found: &mut Vec<(&'a Expr, u8)>) {
    if let Expr::Load { addr, width, .. } = expr {
        found.push((addr, *width));
    }
    for child in crate::ir::visit::children(expr) {
        collect_loads(child, found);
    }
}

/// How many undefined values `expr` applies.
pub(super) fn undefined_count(expr: &Expr) -> usize {
    let mut found = Vec::new();
    opaque(expr, &mut found);
    found
        .iter()
        .filter(
            |node| matches!(node, Expr::Apply { op, .. } if *op == crate::ir::Operation::Undefined),
        )
        .count()
}

/// Whether `expr` applies an operation the solver does not model.
pub(super) fn opaque_any(expr: &Expr) -> bool {
    let mut found = Vec::new();
    opaque(expr, &mut found);
    !found.is_empty()
}

pub(super) fn known_or_true(known: &str) -> &str {
    if known.is_empty() { "true" } else { known }
}

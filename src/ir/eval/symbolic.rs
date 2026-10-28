//! Symbolic evaluation of lifted expressions using the shared SMT translation.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet};
use std::rc::Rc;

use crate::emulation::Memory;
use crate::error::{Error, Result};
use crate::ir::semantics;
use crate::ir::smt;
use crate::ir::{Block, CallKind, CallOutput, Cond, Expr, Stmt};
use crate::loader::{Image, Isa};
use crate::service::Binary;
use crate::symbolic::{Inputs, Options, Report, Solver, invalid};

/// An opaque 64-bit bit-vector value, optionally known without a solver query.
#[derive(Clone)]
pub struct Term {
    text: String,
    concrete: Option<u64>,
    session: Option<Rc<RefCell<Solver>>>,
}

impl Term {
    /// Creates a concrete 64-bit term.
    #[must_use]
    pub fn constant(value: u64) -> Self {
        Self {
            text: smt::constant(value),
            concrete: Some(value),
            session: None,
        }
    }
}

#[derive(Clone)]
struct Cursor {
    blocks: Rc<[Block]>,
    block: usize,
    statement: usize,
}

#[derive(Clone)]
struct ReturnFrame {
    cursor: Cursor,
    temporaries: BTreeMap<u16, Term>,
    outputs: Vec<CallOutput>,
    pushed: u64,
    return_address: u64,
}

/// A forkable execution state. Forks share immutable solver definitions only.
#[derive(Clone)]
pub struct State {
    solver: Rc<RefCell<Solver>>,
    source_digest: [u8; 32],
    isa: Isa,
    convention: crate::ir::Convention,
    registers: BTreeMap<u16, Term>,
    memory: BTreeMap<u64, Term>,
    constraints: Vec<String>,
    cursor: Cursor,
    address: u64,
    steps: usize,
    options: Options,
    path: Vec<String>,
    stdin: Vec<Term>,
    input_position: usize,
    argv: Vec<Vec<Term>>,
    arguments: BTreeMap<usize, Term>,
    input_memory: BTreeMap<u64, Term>,
    input_registers: BTreeMap<u16, Term>,
    returns: Vec<ReturnFrame>,
    stop: Option<String>,
}

/// Result of stepping to a branch, target address, or execution boundary.
pub enum Step {
    /// Successors, with the taken branch first; infeasible states are removed.
    Branch(Vec<State>),
    /// The next instruction is one of the requested stop addresses.
    Reached,
    /// Execution stopped, including returns, traps, and deterministic limits.
    Stopped(String),
}

enum Failure {
    Error(Error),
    Address(Term, Vec<u64>, bool),
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self::Error(error)
    }
}

type Evaluation<T> = Result<T, Failure>;

impl State {
    /// Creates a state at a function name or virtual address.
    pub fn new(binary: &Binary, start: &str, options: &Options) -> Result<Self> {
        if options.address_limit == 0 || options.address_limit > 256 || options.path_limit == 0 {
            return Err(invalid(
                "addressLimit must be 1..256 and pathLimit must be positive",
            ));
        }
        let total = options.stdin.saturating_add(
            options
                .argv
                .iter()
                .copied()
                .fold(0usize, usize::saturating_add),
        );
        let total = options
            .memory
            .iter()
            .fold(total, |total, range| total.saturating_add(range.size));
        if total.saturating_add(options.argv.len()) > 65536 {
            return Err(invalid("symbolic byte inputs exceed 65536"));
        }
        let image = binary.image();
        if !matches!(image.isa, Isa::X86_64 | Isa::AArch64)
            || image.byte_order() == Some(object::Endianness::Big)
        {
            return Err(invalid(
                "symbolic execution supports little-endian x86-64 and AArch64",
            ));
        }
        let address = binary.find_address(start)?;
        let blocks = lift(image, address)?;
        let solver = Rc::new(RefCell::new(Solver::new()?));
        let mut state = Self {
            solver,
            source_digest: image.input_digest,
            isa: image.isa,
            convention: image.convention_of(address),
            registers: BTreeMap::new(),
            memory: BTreeMap::new(),
            constraints: Vec::new(),
            cursor: Cursor {
                blocks: Rc::from(blocks),
                block: 0,
                statement: 0,
            },
            address,
            steps: 0,
            options: options.clone(),
            path: Vec::new(),
            stdin: Vec::new(),
            input_position: 0,
            argv: Vec::new(),
            arguments: BTreeMap::new(),
            input_memory: BTreeMap::new(),
            input_registers: BTreeMap::new(),
            returns: Vec::new(),
            stop: None,
        };
        let physical = super::emulation::physical_registers(image.isa);
        for &register in &physical {
            state.registers.insert(register, Term::constant(0));
        }
        let stack = super::stack_top(image.isa) - if image.isa == Isa::X86_64 { 8 } else { 0 };
        state
            .registers
            .insert(crate::arch::stack_pointer(image.isa), Term::constant(stack));
        state
            .registers
            .insert(crate::lift::execution::DIRECTION, Term::constant(0));
        for (&index, value) in &options.register_values {
            if !physical.contains(&index) {
                return Err(invalid(format!("unknown physical register {index}")));
            }
            state
                .registers
                .insert(index, Term::constant(value.value()?));
        }
        let convention = image.convention_of(address);
        for (index, value) in options.argument_values.iter().enumerate() {
            let Some(&register) = convention.arguments().get(index) else {
                return Err(invalid("stack arguments are not supported"));
            };
            let term = Term::constant(value.value()?);
            state.arguments.insert(index, term.clone());
            state.registers.insert(register, term);
        }
        for &index in &options.arguments {
            let Some(&register) = convention.arguments().get(index) else {
                return Err(invalid("symbolic stack arguments are not supported"));
            };
            let term = state.symbolic()?;
            state.arguments.insert(index, term.clone());
            state.registers.insert(register, term);
        }
        for &index in &options.registers {
            if !physical.contains(&index) {
                return Err(invalid("symbolic inputs require physical registers"));
            }
            let term = state.symbolic()?;
            state.input_registers.insert(index, term.clone());
            for (&argument, value) in &mut state.arguments {
                if convention.arguments().get(argument) == Some(&index) {
                    *value = term.clone();
                }
            }
            state.registers.insert(index, term);
        }
        for range in &options.memory {
            let address = range.address.value()?;
            for offset in 0..range.size {
                let Some(at) = address.checked_add(offset as u64) else {
                    return Err(invalid("symbolic memory range overflows"));
                };
                let byte = state.symbolic_byte()?;
                state.write_memory(binary, at, std::slice::from_ref(&byte))?;
                state.input_memory.insert(at, byte);
            }
        }
        for _ in 0..options.stdin {
            let byte = state.symbolic_byte()?;
            state.stdin.push(byte);
        }
        if !options.argv.is_empty() {
            if !options.arguments.is_empty() || !options.argument_values.is_empty() {
                return Err(invalid("argv and scalar arguments are mutually exclusive"));
            }
            let memory = Memory::new(image).map_err(invalid)?;
            let heap_end = memory
                .heap_base
                .checked_add(crate::emulation::HEAP_SIZE)
                .ok_or_else(|| invalid("heap address overflows"))?;
            let mut base = memory.heap_base;
            for &address in state.memory.keys() {
                if (memory.heap_base..heap_end).contains(&address) {
                    base = base.max(
                        address
                            .checked_add(1)
                            .ok_or_else(|| invalid("heap input range overflows"))?,
                    );
                }
            }
            let strings = options
                .argv
                .iter()
                .copied()
                .fold(options.argv.len(), usize::saturating_add);
            let required = (options.argv.len() + 1)
                .saturating_mul(8)
                .saturating_add(strings);
            if base
                .checked_add(required as u64)
                .is_none_or(|end| end > heap_end)
            {
                return Err(invalid("argv exceeds heap capacity"));
            }
            let mut address = base
                .checked_add((options.argv.len() as u64 + 1).saturating_mul(8))
                .ok_or_else(|| invalid("argv table overflows"))?;
            for (index, &length) in options.argv.iter().enumerate() {
                state.store(image, base + index as u64 * 8, &Term::constant(address), 8)?;
                let mut bytes = Vec::new();
                for _ in 0..length {
                    let byte = state.symbolic_byte()?;
                    state
                        .constraints
                        .push(format!("(not (= {} {}))", byte.text, smt::constant(0)));
                    state.memory.insert(address, byte.clone());
                    bytes.push(byte);
                    address = address
                        .checked_add(1)
                        .ok_or_else(|| invalid("argv address overflows"))?;
                }
                state.memory.insert(address, Term::constant(0));
                address = address
                    .checked_add(1)
                    .ok_or_else(|| invalid("argv terminator overflows"))?;
                state.argv.push(bytes);
            }
            state.store(
                image,
                base + options.argv.len() as u64 * 8,
                &Term::constant(0),
                8,
            )?;
            state.registers.insert(
                convention.arguments()[0],
                Term::constant(options.argv.len() as u64),
            );
            state
                .registers
                .insert(convention.arguments()[1], Term::constant(base));
        }
        Ok(state)
    }

    /// Creates an unconstrained 64-bit value in this state's solver session.
    pub fn symbolic(&self) -> Result<Term> {
        let text = self.solver.borrow_mut().define(None)?;
        Ok(Term {
            text,
            concrete: None,
            session: Some(Rc::clone(&self.solver)),
        })
    }

    fn symbolic_byte(&self) -> Result<Term> {
        let term = self.symbolic()?;
        self.bind(smt::low(&term.text, 8))
    }

    fn bind(&self, expression: String) -> Result<Term> {
        let text = self.solver.borrow_mut().define(Some(&expression))?;
        Ok(Term {
            text,
            concrete: None,
            session: Some(Rc::clone(&self.solver)),
        })
    }

    /// Reads a physical or lifted register. Uninitialized registers are errors.
    pub fn read_register(&self, index: u16) -> Result<Term> {
        self.registers.get(&index).cloned().ok_or_else(|| {
            invalid(format!(
                "undefined register {index} at 0x{:x}",
                self.address
            ))
        })
    }

    /// Writes a full register value. Partial writes are represented by the lifted IR.
    pub fn write_register(&mut self, index: u16, term: Term) -> Result<()> {
        self.check_term(&term)?;
        if !super::emulation::physical_registers(self.isa).contains(&index) {
            return Err(invalid(format!("unknown physical register {index}")));
        }
        if self.steps == 0 {
            self.input_registers.insert(index, term.clone());
            for (&argument, value) in &mut self.arguments {
                if self.convention.arguments().get(argument) == Some(&index) {
                    *value = term.clone();
                }
            }
        }
        self.registers.insert(index, term);
        Ok(())
    }

    fn check_binary(&self, binary: &Binary) -> Result<()> {
        if binary.image().input_digest != self.source_digest || binary.image().isa != self.isa {
            return Err(invalid("state belongs to another binary or architecture"));
        }
        Ok(())
    }

    fn check_term(&self, term: &Term) -> Result<()> {
        if let Some(session) = &term.session
            && !Rc::ptr_eq(session, &self.solver)
        {
            return Err(invalid("term belongs to another solver session"));
        }
        Ok(())
    }

    /// Reads byte terms from concrete addresses using emulation's memory mapping.
    pub fn read_memory(&self, binary: &Binary, address: u64, size: usize) -> Result<Vec<Term>> {
        self.check_binary(binary)?;
        let memory = Memory::new(binary.image()).map_err(invalid)?;
        if !memory.check(address, size as u64, /* write */ false) {
            return Err(memory_failure(&memory));
        }
        let mut bytes = Vec::new();
        for offset in 0..size {
            let at = address + offset as u64;
            let byte = self
                .memory
                .get(&at)
                .cloned()
                .unwrap_or_else(|| Term::constant(u64::from(memory.byte(at))));
            bytes.push(byte);
        }
        if memory.fault.borrow().is_some() {
            return Err(memory_failure(&memory));
        }
        Ok(bytes)
    }

    /// Writes low eight bits of each term to writable concrete byte addresses.
    pub fn write_memory(&mut self, binary: &Binary, address: u64, bytes: &[Term]) -> Result<()> {
        self.check_binary(binary)?;
        let memory = Memory::new(binary.image()).map_err(invalid)?;
        if !memory.check(address, bytes.len() as u64, /* write */ true) {
            return Err(memory_failure(&memory));
        }
        for (offset, byte) in bytes.iter().enumerate() {
            let byte = self.low(byte, 8)?;
            let at = address + offset as u64;
            if self.steps == 0 {
                self.input_memory.insert(at, byte.clone());
            }
            self.memory.insert(at, byte);
        }
        Ok(())
    }

    /// Adds a comparison constraint. Width must be 1..64 bits.
    pub fn constrain(&mut self, cond: Cond, lhs: &Term, rhs: &Term, bits: u32) -> Result<()> {
        self.check_term(lhs)?;
        self.check_term(rhs)?;
        if !(1..=64).contains(&bits) {
            return Err(invalid("constraint width must be 1..64"));
        }
        self.constraints
            .push(smt::condition(cond, &lhs.text, &rhs.text, bits));
        Ok(())
    }

    /// Checks the complete path constraints without changing them.
    pub fn satisfiable(&self) -> Result<bool> {
        Ok(self
            .solver
            .borrow_mut()
            .query(&self.constraints, None)?
            .is_some())
    }

    /// Enumerates up to `count` unsigned values, in increasing order.
    pub fn evaluate(&self, term: &Term, count: usize) -> Result<Vec<u64>> {
        self.check_term(term)?;
        if count > 256 {
            return Err(invalid("value count exceeds 256"));
        }
        self.enumerate(term, count)
    }

    fn enumerate(&self, term: &Term, count: usize) -> Result<Vec<u64>> {
        let mut constraints = self.constraints.clone();
        let mut values = Vec::new();
        for _ in 0..count {
            let Some(value) = self.extreme(term, &constraints, /* maximum */ false)? else {
                break;
            };
            values.push(value);
            constraints.push(format!("(bvugt {} {})", term.text, smt::constant(value)));
        }
        Ok(values)
    }

    /// Returns the unsigned minimum and maximum, or None for an infeasible state.
    pub fn bounds(&self, term: &Term) -> Result<Option<(u64, u64)>> {
        self.check_term(term)?;
        let Some(minimum) = self.extreme(term, &self.constraints, /* maximum */ false)? else {
            return Ok(None);
        };
        let Some(maximum) = self.extreme(term, &self.constraints, /* maximum */ true)? else {
            return Err(invalid(
                "solver gave inconsistent satisfiability results for bounds",
            ));
        };
        Ok(Some((minimum, maximum)))
    }

    fn extreme(&self, term: &Term, constraints: &[String], maximum: bool) -> Result<Option<u64>> {
        if self.solver.borrow_mut().query(constraints, None)?.is_none() {
            return Ok(None);
        }
        if let Some(value) = term.concrete {
            return Ok(Some(value));
        }
        let mut low = 0u64;
        let mut high = u64::MAX;
        while low < high {
            let middle = low + (high - low) / 2;
            let mut trial = constraints.to_vec();
            trial.push(format!(
                "({} {} {})",
                if maximum { "bvugt" } else { "bvule" },
                term.text,
                smt::constant(middle)
            ));
            let sat = self.solver.borrow_mut().query(&trial, None)?.is_some();
            if sat == maximum {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        Ok(Some(low))
    }

    fn low(&self, value: &Term, bits: u32) -> Result<Term> {
        self.check_term(value)?;
        match value.concrete {
            Some(value) => Ok(Term::constant(value & semantics::mask(bits))),
            None => self.bind(smt::low(&value.text, bits)),
        }
    }

    fn resolve(&self, term: Term) -> Evaluation<u64> {
        if let Some(value) = term.concrete {
            return Ok(value);
        }
        let value = self
            .solver
            .borrow_mut()
            .query(&self.constraints, Some(&term.text))?;
        if let Some(value) = value {
            let mut trial = self.constraints.clone();
            trial.push(format!("(not (= {} {}))", term.text, smt::constant(value)));
            if self.solver.borrow_mut().query(&trial, None)?.is_none() {
                return Ok(value);
            }
        }
        let values = self.enumerate(&term, self.options.address_limit + 1)?;
        if values.len() == 1 {
            return Ok(values[0]);
        }
        let limited = values.len() > self.options.address_limit;
        Err(Failure::Address(
            term,
            values
                .into_iter()
                .take(self.options.address_limit)
                .collect(),
            limited,
        ))
    }

    fn store(&mut self, image: &Image, address: u64, term: &Term, width: u8) -> Result<()> {
        if width == 0 || width > 8 {
            return Err(invalid("invalid memory width"));
        }
        let memory = Memory::new(image).map_err(invalid)?;
        if !memory.check(address, u64::from(width), /* write */ true) {
            return Err(memory_failure(&memory));
        }
        for byte in 0..width {
            let value = match term.concrete {
                Some(value) => Term::constant((value >> (u32::from(byte) * 8)) & 255),
                None => self.bind(smt::low(
                    &format!(
                        "(bvlshr {} {})",
                        term.text,
                        smt::constant(u64::from(byte) * 8)
                    ),
                    8,
                ))?,
            };
            self.memory.insert(address + u64::from(byte), value);
        }
        Ok(())
    }

    fn eval(&self, binary: &Binary, expression: &Expr) -> Evaluation<Term> {
        match expression {
            Expr::Const(value) => return Ok(Term::constant(*value)),
            Expr::Reg { index, width } => {
                if !(1..=64).contains(width) {
                    return Err(invalid("invalid register width").into());
                }
                return Ok(self.low(&self.read_register(*index)?, u32::from(*width))?);
            }
            Expr::Load {
                addr,
                width,
                signed,
            } => {
                if *width == 0 || *width > 8 {
                    return Err(invalid("invalid load width").into());
                }
                let address = self.resolve(self.eval(binary, addr)?)?;
                let bytes = self.read_memory(binary, address, usize::from(*width))?;
                let mut text = smt::constant(0);
                let mut concrete = Some(0u64);
                for (index, byte) in bytes.iter().enumerate() {
                    text = format!(
                        "(bvor {text} (bvshl {} {}))",
                        byte.text,
                        smt::constant(index as u64 * 8)
                    );
                    concrete = concrete
                        .zip(byte.concrete)
                        .map(|(sum, byte)| sum | (byte << (index * 8)));
                }
                if *signed {
                    text = smt::signed(&text, u32::from(*width) * 8);
                    concrete = concrete
                        .map(|value| semantics::sign_extend(value, u32::from(*width) * 8) as u64);
                }
                return Ok(match concrete {
                    Some(value) => Term::constant(value),
                    None => self.bind(text)?,
                });
            }
            Expr::Select {
                cond,
                lhs,
                rhs,
                then,
                els,
            } => {
                let a = self.eval(binary, lhs)?;
                let b = self.eval(binary, rhs)?;
                let bits = semantics::operand_width(lhs, rhs);
                if let (Some(a), Some(b)) = (a.concrete, b.concrete) {
                    return self.eval(
                        binary,
                        if semantics::holds(*cond, a, b, bits) {
                            then
                        } else {
                            els
                        },
                    );
                }
                let test = smt::condition(*cond, &a.text, &b.text, bits);
                let test = self.bind(format!(
                    "(ite {test} {} {})",
                    smt::constant(1),
                    smt::constant(0)
                ))?;
                let choice = self.resolve(test)?;
                return self.eval(binary, if choice == 1 { then } else { els });
            }
            Expr::SignExtend { width, .. } if !(1..=8).contains(width) => {
                return Err(invalid("invalid extension width").into());
            }
            Expr::Apply {
                op: crate::ir::Operation::Undefined,
                ..
            } => return Err(invalid("undefined operation result").into()),
            _ => {}
        }
        let mut operands = Vec::new();
        let mut all_concrete = true;
        for child in crate::ir::visit::children(expression) {
            let value = self.eval(binary, child)?;
            all_concrete &= value.concrete.is_some();
            operands.push((child, value));
        }
        if all_concrete {
            let convention = super::Convention {
                arguments: &[],
                clobbered: &[],
            };
            let machine = super::Machine {
                strict_memory: None,
                source: None,
                isa: binary.image().isa,
                convention: &convention,
                seed: 0,
                registers: std::collections::HashMap::new(),
                memory: std::collections::HashMap::new(),
                calls: Vec::new(),
                blocks: &[],
                block_indices_by_address: std::collections::HashMap::new(),
            };
            let concrete: Vec<(&Expr, u64)> = operands
                .iter()
                .map(|(expr, value)| (*expr, value.concrete.expect("all operands are concrete")))
                .collect();
            return match machine.eval_resolved(expression, &concrete) {
                Ok(value) => Ok(Term::constant(value)),
                Err(reason) => Err(invalid(reason).into()),
            };
        }
        if matches!(expression, Expr::Apply { .. }) {
            return Err(invalid("operation with symbolic operands is not supported").into());
        }
        let terms: Vec<(&Expr, &str)> = operands
            .iter()
            .map(|(expr, value)| (*expr, value.text.as_str()))
            .collect();
        let translated = smt::resolved_value(expression, &terms);
        // Undefined arithmetic is an execution error, rather than a silently removed path.
        if matches!(
            expression,
            Expr::Bin {
                op: crate::ir::BinOp::DivU
                    | crate::ir::BinOp::DivS
                    | crate::ir::BinOp::ModU
                    | crate::ir::BinOp::ModS,
                ..
            }
        ) && self
            .solver
            .borrow_mut()
            .query(
                &[
                    self.constraints.clone(),
                    vec![format!("(not {})", translated.defined)],
                ]
                .concat(),
                None,
            )?
            .is_some()
        {
            return Err(invalid("arithmetic may be undefined (division by zero)").into());
        }
        Ok(self.bind(translated.term)?)
    }

    /// Evaluates a lifted expression in the current register and memory state.
    /// A symbolic memory address must have exactly one possible value here.
    pub fn expression(&self, binary: &Binary, expression: &Expr) -> Result<Term> {
        self.check_binary(binary)?;
        match self.eval(binary, expression) {
            Ok(term) => Ok(term),
            Err(Failure::Error(error)) => Err(error),
            Err(Failure::Address(_, _, _)) => Err(invalid("expression requires a fork; use step")),
        }
    }

    /// Current instruction address, before executing its statements.
    #[must_use]
    pub fn address(&self) -> u64 {
        self.address
    }

    fn jump(&mut self, binary: &Binary, target: u64) -> Result<()> {
        let Some(block) = self
            .cursor
            .blocks
            .iter()
            .position(|block| block.start == target)
        else {
            self.cursor = Cursor {
                blocks: Rc::from(lift(binary.image(), target)?),
                block: 0,
                statement: 0,
            };
            return Ok(());
        };
        self.cursor.block = block;
        self.cursor.statement = 0;
        Ok(())
    }

    /// Runs until a branch or stop address. Returned successors may be stepped independently.
    pub fn step(&mut self, binary: &Binary, until: &[u64]) -> Result<Step> {
        self.check_binary(binary)?;
        for &address in until {
            let imported = binary.image().imports.contains_key(&address)
                || binary
                    .image()
                    .functions
                    .get(&address)
                    .is_some_and(|function| {
                        function.sources.contains(&crate::loader::NameSource::Plt)
                    });
            if imported {
                return Err(invalid(format!(
                    "stopping at imported address 0x{address:x} is unsupported; use the call-site address"
                )));
            }
        }
        loop {
            if let Some(reason) = &self.stop {
                return Ok(Step::Stopped(reason.clone()));
            }
            let Some(block) = self.cursor.blocks.get(self.cursor.block) else {
                return Ok(Step::Stopped("execution left lifted code".to_owned()));
            };
            let Some(statement) = block.stmts.get(self.cursor.statement).cloned() else {
                self.cursor.block += 1;
                self.cursor.statement = 0;
                continue;
            };
            if let Stmt::Assign {
                dest,
                value: Expr::Const(address),
            } = &statement
                && dest.index == crate::lift::execution::ADDRESS
            {
                self.address = *address;
                if until.contains(address) {
                    return Ok(Step::Reached);
                }
            }
            if self.steps >= self.options.step_limit {
                return Ok(Step::Stopped("step budget".to_owned()));
            }
            let before = self.clone();
            self.steps += 1;
            self.cursor.statement += 1;
            match self.statement(binary, &statement) {
                Ok(Some(Step::Branch(states))) => {
                    self.stop = Some("state has forked; step a successor".to_owned());
                    return Ok(Step::Branch(states));
                }
                Ok(Some(Step::Stopped(reason))) => {
                    self.stop = Some(reason.clone());
                    return Ok(Step::Stopped(reason));
                }
                Ok(Some(Step::Reached)) => return Ok(Step::Reached),
                Ok(None) => {}
                Err(Failure::Error(error)) => {
                    let reason = format!("0x{:x}: {error}", self.address);
                    self.stop = Some(reason.clone());
                    return Ok(Step::Stopped(reason));
                }
                Err(Failure::Address(term, values, limited)) => {
                    let mut successors = Vec::new();
                    for value in values {
                        let mut state = before.clone();
                        state.constraints.push(format!(
                            "(= {} {})",
                            term.text,
                            smt::constant(value)
                        ));
                        successors.push(state);
                    }
                    if limited {
                        // A separate stopped successor preserves the incomplete-search diagnostic.
                        let mut state = before;
                        state.stop = Some("address enumeration bound reached".to_owned());
                        successors.push(state);
                    }
                    self.stop = Some("state has forked; step a successor".to_owned());
                    return Ok(Step::Branch(successors));
                }
            }
        }
    }

    fn statement(&mut self, binary: &Binary, statement: &Stmt) -> Evaluation<Option<Step>> {
        match statement {
            Stmt::Assign { dest, value } => {
                if dest.index == crate::lift::execution::ADDRESS {
                    self.path.push(crate::addr::format(self.address));
                } else {
                    let value = self.eval(binary, value)?;
                    let value = self.low(&value, u32::from(dest.width))?;
                    self.registers.insert(dest.index, value);
                }
            }
            Stmt::Store { addr, value, width } => {
                let address = self.resolve(self.eval(binary, addr)?)?;
                let value = self.eval(binary, value)?;
                self.store(binary.image(), address, &value, *width)?;
            }
            Stmt::Brif {
                cond,
                lhs,
                rhs,
                target,
            } => {
                let a = self.eval(binary, lhs)?;
                let b = self.eval(binary, rhs)?;
                let test =
                    smt::condition(*cond, &a.text, &b.text, semantics::operand_width(lhs, rhs));
                let mut taken = self.clone();
                taken.constraints.push(test.clone());
                if let Err(error) = taken.jump(binary, *target) {
                    taken.stop = Some(error.to_string());
                }
                let mut fallthrough = self.clone();
                fallthrough.constraints.push(format!("(not {test})"));
                let mut successors = Vec::new();
                for state in [taken, fallthrough] {
                    if state.satisfiable()? {
                        successors.push(state);
                    }
                }
                return Ok(Some(Step::Branch(successors)));
            }
            Stmt::Br {
                target: Some(target),
            } => self.jump(binary, *target)?,
            Stmt::BrIndirect { target } => {
                let target = self.resolve(self.eval(binary, target)?)?;
                self.jump(binary, target)?;
            }
            Stmt::Call {
                kind,
                target,
                through,
                convention,
                outputs,
                ..
            } => {
                let target = match target {
                    Some(target) => *target,
                    None => match through {
                        Some(expression @ Expr::Load { addr, .. }) if matches!(addr.as_ref(), Expr::Const(slot) if binary.image().imports.contains_key(slot)) =>
                        {
                            let Expr::Const(slot) = addr.as_ref() else {
                                return Err(invalid("invalid import slot").into());
                            };
                            if self
                                .memory
                                .range(*slot..slot.saturating_add(8))
                                .next()
                                .is_some()
                            {
                                self.resolve(self.eval(binary, expression)?)?
                            } else {
                                *slot
                            }
                        }
                        Some(expression) => self.resolve(self.eval(binary, expression)?)?,
                        None => return Err(invalid("unsupported call target").into()),
                    },
                };
                self.call(binary, target, *convention, *kind, outputs)?;
            }
            Stmt::Ret { value } => {
                let value = self.eval(binary, value)?;
                self.registers.insert(crate::arch::RETURN, value);
                let Some(frame) = self.returns.pop() else {
                    return Ok(Some(Step::Stopped("return".to_owned())));
                };
                if frame.pushed != 0 {
                    let sp = crate::arch::stack_pointer(binary.image().isa);
                    let stack = self.resolve(self.read_register(sp)?)?;
                    let target = self.eval(
                        binary,
                        &Expr::Load {
                            addr: Box::new(Expr::Const(stack)),
                            width: 8,
                            signed: false,
                        },
                    )?;
                    if self.resolve(target)? != frame.return_address {
                        return Err(invalid("unsupported changed return address").into());
                    }
                    let instruction =
                        super::emulation::x86_instruction_at(binary.image(), self.address)
                            .map_err(invalid)?;
                    let cleanup = if instruction.mnemonic() == iced_x86::Mnemonic::Ret
                        && instruction.op_count() != 0
                    {
                        u64::from(instruction.immediate16())
                    } else {
                        0
                    };
                    let stack = stack
                        .checked_add(frame.pushed)
                        .and_then(|value| value.checked_add(cleanup))
                        .ok_or_else(|| invalid("return stack overflows"))?;
                    self.registers.insert(sp, Term::constant(stack));
                }
                if binary.image().isa == Isa::AArch64 {
                    let bytes = binary
                        .image()
                        .read_vaddr(self.address, 4)
                        .ok_or_else(|| invalid("missing return instruction"))?;
                    let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    if word & 0xffff_fc1f != 0xd65f_0000 {
                        return Err(invalid("unsupported authenticated return").into());
                    }
                    let register = ((word >> 5) & 31) as u16;
                    let target = self.resolve(self.read_register(register)?)?;
                    if target != frame.return_address {
                        return Err(invalid("unsupported changed return address").into());
                    }
                }
                let mut outputs = Vec::new();
                for output in &frame.outputs {
                    outputs.push((output.dest, self.registers.get(&output.register).cloned()));
                }
                self.registers.retain(|index, _| {
                    *index < crate::ir::TEMP_BASE || *index == crate::lift::execution::DIRECTION
                });
                self.registers.extend(frame.temporaries);
                for (dest, value) in outputs {
                    match value {
                        Some(value) => {
                            self.registers
                                .insert(dest.index, self.low(&value, u32::from(dest.width))?);
                        }
                        None => {
                            self.registers.remove(&dest.index);
                        }
                    }
                }
                self.cursor = frame.cursor;
            }
            Stmt::Trap => return Ok(Some(Step::Stopped("trap".to_owned()))),
            Stmt::Unsupported { text, .. } => {
                return Err(invalid(format!("unsupported instruction: {text}")).into());
            }
            _ => {
                return Err(
                    invalid(format!("unsupported symbolic statement: {statement:?}")).into(),
                );
            }
        }
        Ok(None)
    }

    fn inputs(&self) -> Result<Inputs> {
        let mut state = self.clone();
        let mut result = Inputs::default();
        let mut choose = |term: &Term| -> Result<u64> {
            let Some(value) = state.extreme(term, &state.constraints, /* maximum */ false)? else {
                return Err(invalid("reached state is unsatisfiable"));
            };
            state
                .constraints
                .push(format!("(= {} {})", term.text, smt::constant(value)));
            Ok(value)
        };
        for byte in &self.stdin {
            result.stdin.push(choose(byte)? as u8);
        }
        for argument in &self.argv {
            let mut bytes = Vec::new();
            for byte in argument {
                bytes.push(choose(byte)? as u8);
            }
            result.argv.push(bytes);
        }
        for (&index, term) in &self.arguments {
            result
                .arguments
                .insert(index, crate::addr::format(choose(term)?));
        }
        for (&address, term) in &self.input_memory {
            result
                .memory
                .insert(crate::addr::format(address), choose(term)? as u8);
        }
        for (&index, term) in &self.input_registers {
            result
                .registers
                .insert(index, crate::addr::format(choose(term)?));
        }
        Ok(result)
    }

    /// Explores successors from this state in deterministic depth-first order.
    pub fn explore(self, binary: &Binary, options: &Options) -> Result<Report> {
        let find: Vec<u64> = options
            .find
            .iter()
            .map(crate::emulation::Word::value)
            .collect::<Result<_>>()?;
        let avoid: Vec<u64> = options
            .avoid
            .iter()
            .map(crate::emulation::Word::value)
            .collect::<Result<_>>()?;
        if find.is_empty() {
            return Err(invalid("at least one find address is required"));
        }
        let until: Vec<u64> = find.iter().chain(&avoid).copied().collect();
        let mut pending = vec![self];
        let mut report = Report {
            found: false,
            reason: "paths exhausted".to_owned(),
            inputs: None,
            path: Vec::new(),
            paths: 0,
            diagnostics: Vec::new(),
        };
        while let Some(mut state) = pending.pop() {
            if report.paths >= options.path_limit {
                report.reason = "path budget".to_owned();
                break;
            }
            report.paths += 1;
            if !state.satisfiable()? {
                continue;
            }
            match state.step(binary, &until)? {
                Step::Reached if avoid.contains(&state.address) => {
                    report.diagnostics.push("avoided".to_owned());
                }
                Step::Reached => {
                    report.found = true;
                    report.reason = "found".to_owned();
                    report.inputs = Some(state.inputs()?);
                    report.path = state.path;
                    report.path.push(crate::addr::format(state.address));
                    return Ok(report);
                }
                Step::Branch(states) => pending.extend(states.into_iter().rev()),
                Step::Stopped(reason) => report.diagnostics.push(reason),
            }
        }
        if report.reason == "paths exhausted" && !report.diagnostics.is_empty() {
            if report.diagnostics.iter().all(|reason| reason == "avoided") {
                report.reason = "all paths avoided".to_owned();
            } else if report
                .diagnostics
                .iter()
                .any(|reason| reason.contains("address enumeration bound"))
            {
                report.reason = "address enumeration bound reached".to_owned();
            } else if report
                .diagnostics
                .iter()
                .any(|reason| reason.contains("budget"))
            {
                report.reason = "step budget".to_owned();
            } else if let Some(reason) = report
                .diagnostics
                .iter()
                .find(|reason| reason.contains("unsupported"))
            {
                report.reason = reason.clone();
            }
        }
        report.diagnostics.sort();
        report.diagnostics.dedup();
        Ok(report)
    }
}

fn memory_failure(memory: &Memory<'_>) -> Error {
    invalid(
        memory
            .fault
            .borrow_mut()
            .take()
            .unwrap_or_else(|| "invalid memory access".to_owned()),
    )
}

fn lift(image: &Image, address: u64) -> Result<Vec<Block>> {
    let Some(section) = image
        .section_at(address)
        .filter(|section| section.executable)
    else {
        return Err(invalid(format!(
            "unmapped executable address 0x{address:x}"
        )));
    };
    let available = section.size.saturating_sub(address - section.vaddr);
    let size = image
        .functions
        .range(..=address)
        .next_back()
        .and_then(|(_, function)| {
            function
                .size
                .and_then(|size| function.addr.checked_add(size))
        })
        .filter(|end| *end > address)
        .map_or(available, |end| available.min(end - address));
    if size > 65536 {
        return Err(invalid("function code range exceeds 64 KiB"));
    }
    match crate::lift::lift_for_execution(image, address, size, &HashSet::new()) {
        Ok(blocks) => Ok(blocks),
        Err(error) => Err(invalid(format!("cannot lift 0x{address:x}: {error}"))),
    }
}

impl State {
    fn call(
        &mut self,
        binary: &Binary,
        target: u64,
        convention: crate::ir::Convention,
        kind: CallKind,
        outputs: &[CallOutput],
    ) -> Evaluation<()> {
        if kind != CallKind::Invoke {
            return Err(invalid("unsupported symbolic tail call").into());
        }
        let image = binary.image();
        let name = image.imports.get(&target).map(String::as_str).or_else(|| {
            image
                .functions
                .get(&target)
                .filter(|function| function.sources.contains(&crate::loader::NameSource::Plt))
                .and_then(|function| function.name.as_deref())
        });
        if let Some(name) = name {
            use super::emulation::hooks::{self, Hook};
            use super::emulation::io::{self, Operation};
            let result = match hooks::find(name) {
                Some(Hook::Io(Operation::Getchar)) => {
                    io::next_input(&self.stdin, &mut self.input_position)
                        .unwrap_or_else(|| Term::constant(u64::from(u32::MAX)))
                }
                Some(Hook::Io(Operation::Read)) => {
                    let mut args = Vec::new();
                    for &register in convention.arguments().iter().take(3) {
                        args.push(self.resolve(self.read_register(register)?)?);
                    }
                    if args.len() != 3 || args[0] as u32 != 0 {
                        return Err(invalid("unsupported read descriptor or convention").into());
                    }
                    if args[2] > crate::emulation::HEAP_SIZE {
                        return Err(invalid("input operation exceeds 16 MiB").into());
                    }
                    let count = (args[2] as usize)
                        .min(self.stdin.len().saturating_sub(self.input_position));
                    if count > self.options.step_limit.saturating_sub(self.steps) {
                        return Err(invalid("step budget in input hook").into());
                    }
                    let mut bytes = Vec::new();
                    for _ in 0..count {
                        if let Some(byte) = io::next_input(&self.stdin, &mut self.input_position) {
                            bytes.push(byte);
                        }
                    }
                    self.write_memory(binary, args[1], &bytes)?;
                    self.steps += count;
                    Term::constant(count as u64)
                }
                _ => return Err(invalid(format!("unsupported symbolic import: {name}")).into()),
            };
            for &register in convention.clobbered() {
                self.registers.remove(&register);
            }
            self.registers.insert(crate::arch::RETURN, result);
            let mut values = Vec::new();
            for output in outputs {
                values.push((output.dest, self.registers.get(&output.register).cloned()));
            }
            for (dest, value) in values {
                match value {
                    Some(value) => {
                        self.registers
                            .insert(dest.index, self.low(&value, u32::from(dest.width))?);
                    }
                    None => {
                        self.registers.remove(&dest.index);
                    }
                }
            }
            return Ok(());
        }
        let blocks = lift(image, target)?;
        let sp = crate::arch::stack_pointer(image.isa);
        let old_sp = self.resolve(self.read_register(sp)?)?;
        let pushed = convention.pushed_by_call() as u64;
        let Some(stack) = old_sp.checked_sub(pushed) else {
            return Err(invalid("call stack underflows").into());
        };
        if pushed != 0 {
            let instruction =
                super::emulation::x86_instruction_at(image, self.address).map_err(invalid)?;
            self.store(
                image,
                stack,
                &Term::constant(instruction.next_ip()),
                pushed as u8,
            )?;
        }
        let mut temporaries = BTreeMap::new();
        for (&index, value) in &self.registers {
            if index >= crate::ir::TEMP_BASE && index != crate::lift::execution::DIRECTION {
                temporaries.insert(index, value.clone());
            }
        }
        self.registers.retain(|index, _| {
            *index < crate::ir::TEMP_BASE || *index == crate::lift::execution::DIRECTION
        });
        self.returns.push(ReturnFrame {
            cursor: self.cursor.clone(),
            temporaries,
            outputs: outputs.to_vec(),
            pushed,
            return_address: if pushed != 0 {
                super::emulation::x86_instruction_at(image, self.address)
                    .map_err(invalid)?
                    .next_ip()
            } else {
                self.address
                    .checked_add(4)
                    .ok_or_else(|| invalid("return address overflows"))?
            },
        });
        self.cursor = Cursor {
            blocks: Rc::from(blocks),
            block: 0,
            statement: 0,
        };
        self.registers.insert(sp, Term::constant(stack));
        Ok(())
    }
}

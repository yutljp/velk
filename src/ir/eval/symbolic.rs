//! Symbolic evaluation of lifted expressions using the shared SMT translation.

mod cxx;
mod files;
mod libc;
mod memory;
mod runtime;
mod syscalls;

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
    defined: u64,
    bits: u32,
    session: Option<Rc<RefCell<Solver>>>,
}

impl State {
    fn output_descriptor(descriptor: u32) -> bool {
        matches!(descriptor, 1 | 2)
    }

    fn write_output(&mut self, descriptor: u32, bytes: Vec<Term>) {
        if descriptor == 1 {
            self.stdout.extend(bytes);
        }
    }
}

impl Term {
    /// Creates a concrete 64-bit term.
    #[must_use]
    pub fn constant(value: u64) -> Self {
        Self {
            text: smt::constant(value),
            concrete: Some(value),
            bits: 64 - value.leading_zeros(),
            defined: u64::MAX,
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

#[derive(Clone)]
pub(super) struct ScannedInteger {
    pub(super) start: usize,
    pub(super) length: usize,
    pub(super) whitespace: usize,
    pub(super) sign: Option<u8>,
    pub(super) digits: usize,
    pub(super) unsigned: bool,
    pub(super) canonical: bool,
    pub(super) value: Term,
}

#[derive(Default)]
struct BranchObservations {
    sides: BTreeMap<u64, [bool; 2]>,
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
    files: super::stdio::Files<Term>,
    input_files: BTreeMap<String, Vec<Term>>,
    stdin: Vec<Term>,
    scanned_integers: Vec<ScannedInteger>,
    input_position: usize,
    stdout: Vec<Term>,
    stdin_stream: u64,
    standard_streams: [u64; 3],
    heap_next: u64,
    signal_handlers: BTreeMap<u32, Term>,
    alarm: Term,
    random: runtime::Random,
    cxx_locale: Option<super::cxx::Locale>,
    argv: Vec<Vec<Term>>,
    arguments: BTreeMap<usize, Term>,
    input_memory: BTreeMap<u64, Term>,
    input_registers: BTreeMap<u16, Term>,
    returns: Vec<ReturnFrame>,
    stop: Option<String>,
    model_diagnostics: Vec<String>,
    model_call_kind: CallKind,
    branch_observations: Option<Rc<RefCell<BranchObservations>>>,
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
        let total = options
            .files
            .values()
            .fold(total, |n, bytes| n.saturating_add(bytes.len()));
        if total.saturating_add(options.argv.len()) > 65536 {
            return Err(invalid("symbolic byte inputs exceed 65536"));
        }
        let image = binary.image();
        if !matches!(image.isa, Isa::I386 | Isa::X86_64 | Isa::AArch64)
            || image.byte_order() == Some(object::Endianness::Big)
        {
            return Err(invalid(
                "symbolic execution supports little-endian i386, x86-64 and AArch64",
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
            files: super::stdio::Files::new(BTreeMap::new()).map_err(invalid)?,
            input_files: BTreeMap::new(),
            stdin: Vec::new(),
            scanned_integers: Vec::new(),
            input_position: 0,
            stdout: Vec::new(),
            stdin_stream: 0,
            standard_streams: [0; 3],
            heap_next: 0,
            signal_handlers: BTreeMap::new(),
            alarm: Term::constant(0),
            random: runtime::Random::default(),
            cxx_locale: None,
            argv: Vec::new(),
            arguments: BTreeMap::new(),
            input_memory: BTreeMap::new(),
            input_registers: BTreeMap::new(),
            returns: Vec::new(),
            stop: None,
            model_diagnostics: Vec::new(),
            model_call_kind: CallKind::Invoke,
            branch_observations: None,
        };
        let memory = state.mapped_memory(image)?;
        let initial = match crate::emulation::tls::initial(image, &memory, options.canary.as_ref())
        {
            Ok(initial) => initial,
            Err(error) => return Err(invalid(error)),
        };
        for (address, byte) in initial {
            state
                .memory
                .insert(address, Term::constant(u64::from(byte)));
        }
        let physical = super::emulation::physical_registers(image.isa);
        for &register in &physical {
            state.registers.insert(register, Term::constant(0));
        }
        if let Some(register) = crate::emulation::tls::register(image.isa) {
            state
                .registers
                .insert(register, Term::constant(memory.tls_base));
        }
        let stack = super::stack_top(image.isa)
            - match image.isa {
                Isa::X86_64 => 8,
                Isa::I386 => 4,
                _ => 0,
            };
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
            let term = Term::constant(value.value()?);
            state.arguments.insert(index, term.clone());
            state.initialize_argument(binary, index, term, stack)?;
        }
        for &index in &options.arguments {
            let term = state.symbolic()?;
            state.arguments.insert(index, term.clone());
            state.initialize_argument(binary, index, term, stack)?;
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
        for (path, bytes) in &options.files {
            let mut terms = Vec::new();
            for _ in bytes {
                terms.push(state.symbolic_byte()?);
            }
            state.input_files.insert(path.clone(), terms);
        }
        state.files = super::stdio::Files::new(state.input_files.clone()).map_err(invalid)?;
        for _ in 0..options.stdin {
            let byte = state.symbolic_byte()?;
            state.stdin.push(byte);
        }
        if !options.argv.is_empty() {
            if !options.arguments.is_empty() || !options.argument_values.is_empty() {
                return Err(invalid("argv and scalar arguments are mutually exclusive"));
            }
            let memory = state.mapped_memory(image)?;
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
            let width = crate::arch::pointer_bytes(image.isa);
            let strings = options
                .argv
                .iter()
                .copied()
                .fold(options.argv.len(), usize::saturating_add);
            let required = (options.argv.len() + 1)
                .saturating_mul(width as usize)
                .saturating_add(strings);
            if base
                .checked_add(required as u64)
                .is_none_or(|end| end > heap_end)
            {
                return Err(invalid("argv exceeds heap capacity"));
            }
            let mut address = base
                .checked_add((options.argv.len() as u64 + 1).saturating_mul(u64::from(width)))
                .ok_or_else(|| invalid("argv table overflows"))?;
            for (index, &length) in options.argv.iter().enumerate() {
                state.store(
                    image,
                    base + index as u64 * u64::from(width),
                    &Term::constant(address),
                    width,
                )?;
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
                base + options.argv.len() as u64 * u64::from(width),
                &Term::constant(0),
                width,
            )?;
            state.initialize_argument(
                binary,
                0,
                Term::constant(options.argv.len() as u64),
                stack,
            )?;
            state.initialize_argument(binary, 1, Term::constant(base), stack)?;
        }
        state.initialize_streams(binary)?;
        if let Err(failure) = state.initialize_cxx(binary) {
            return match failure {
                Failure::Error(error) => Err(error),
                _ => Err(invalid("C++ stream setup requires concrete addresses")),
            };
        }
        Ok(state)
    }

    /// Creates an unconstrained 64-bit value in this state's solver session.
    pub fn symbolic(&self) -> Result<Term> {
        let text = self.solver.borrow_mut().define(None)?;
        Ok(Term {
            text,
            concrete: None,
            bits: 64,
            defined: u64::MAX,
            session: Some(Rc::clone(&self.solver)),
        })
    }

    fn symbolic_byte(&self) -> Result<Term> {
        let term = self.symbolic()?;
        self.low(&term, 8)
    }

    fn bind(&self, expression: String) -> Result<Term> {
        let text = self.solver.borrow_mut().define(Some(&expression))?;
        Ok(Term {
            text,
            concrete: None,
            bits: 64,
            defined: u64::MAX,
            session: Some(Rc::clone(&self.solver)),
        })
    }

    fn predicate(&self, condition: &str) -> Result<Term> {
        let mut term = match self.bind(format!(
            "(ite {condition} {} {})",
            smt::constant(1),
            smt::constant(0)
        )) {
            Ok(term) => term,
            Err(error) => return Err(error),
        };
        term.bits = 1;
        Ok(term)
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

    pub(super) fn mapped_memory<'image>(&self, image: &'image Image) -> Result<Memory<'image>> {
        let base = match &self.options.tls_base {
            Some(word) => match word.value() {
                Ok(value) => Some(value),
                Err(error) => return Err(error),
            },
            None => None,
        };
        match Memory::with_tls(image, base) {
            Ok(memory) => Ok(memory),
            Err(error) => Err(invalid(error)),
        }
    }

    /// Reads byte terms from concrete addresses using emulation's memory mapping.
    pub fn read_memory(&self, binary: &Binary, address: u64, size: usize) -> Result<Vec<Term>> {
        self.check_binary(binary)?;
        let memory = self.mapped_memory(binary.image())?;
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
        let memory = self.mapped_memory(binary.image())?;
        if !memory.check(address, bytes.len() as u64, /* write */ true) {
            return Err(memory_failure(&memory));
        }
        for (offset, byte) in bytes.iter().enumerate() {
            let byte = self.low(byte, 8)?;
            self.require_defined(&byte, 8)?;
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
        self.require_defined(lhs, bits)?;
        self.require_defined(rhs, bits)?;
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
        self.require_defined(term, 64)?;
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
        if let Err(error) = self.require_defined(term, 64) {
            return Err(error);
        }
        let model = match self
            .solver
            .borrow_mut()
            .query(constraints, Some(&term.text))
        {
            Ok(Some(value)) => value,
            Ok(None) => return Ok(None),
            Err(error) => return Err(error),
        };
        if let Some(value) = term.concrete {
            return Ok(Some(value));
        }
        let mut low = if maximum { model } else { 0 };
        let mut high = if maximum {
            semantics::mask(term.bits)
        } else {
            model
        };
        while low < high {
            let middle = low + (high - low) / 2;
            let mut trial = constraints.to_vec();
            trial.push(format!(
                "({} {} {})",
                if maximum { "bvugt" } else { "bvule" },
                term.text,
                smt::constant(middle)
            ));
            let sat = match self.solver.borrow_mut().query(&trial, None) {
                Ok(value) => value.is_some(),
                Err(error) => return Err(error),
            };
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
        let mask = semantics::mask(bits);
        match value.concrete {
            Some(value) => Ok(Term::constant(value & mask)),
            None => {
                let mut result = self.bind(smt::low(&value.text, bits))?;
                result.defined = value.defined | !mask;
                result.bits = value.bits.min(bits);
                Ok(result)
            }
        }
    }

    fn require_defined(&self, value: &Term, bits: u32) -> Result<()> {
        let mask = semantics::mask(bits);
        if value.defined & mask != mask {
            return Err(invalid("value depends on an undefined register"));
        }
        Ok(())
    }

    fn resolve(&self, term: Term) -> Evaluation<u64> {
        self.require_defined(&term, 64)?;
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
        self.require_defined(term, u32::from(width) * 8)?;
        let memory = self.mapped_memory(image)?;
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
                let address = match self.resolve(self.eval(binary, addr)?) {
                    Ok(address) => address,
                    Err(Failure::Address(term, values, limited)) => {
                        if let Some(value) =
                            self.table_load(binary, &term, &values, *width, *signed)?
                        {
                            return Ok(value);
                        }
                        return Err(Failure::Address(term, values, limited));
                    }
                    Err(error) => return Err(error),
                };
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
                self.require_defined(&a, bits)?;
                self.require_defined(&b, bits)?;
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
                let test = self.predicate(&test)?;
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
        if let Expr::Apply { op, args } = expression
            && (args.len() != op.arity()
                || !matches!(
                    op,
                    crate::ir::Operation::Narrow(16 | 32 | 64)
                        | crate::ir::Operation::Pack {
                            from: 16 | 32 | 64,
                            ..
                        }
                        | crate::ir::Operation::CountLeadingZeros(8 | 16 | 32 | 64)
                        | crate::ir::Operation::InterleaveLow(8 | 16 | 32)
                        | crate::ir::Operation::InterleaveHigh(8 | 16 | 32)
                        | crate::ir::Operation::Widen {
                            bits: 8 | 16 | 32,
                            ..
                        }
                        | crate::ir::Operation::SumLanes(8 | 16 | 32 | 64)
                        | crate::ir::Operation::Lanes(
                            crate::ir::LaneOp::Add | crate::ir::LaneOp::ShiftRight,
                            8 | 16 | 32 | 64
                        )
                ))
        {
            return Err(invalid(format!("unsupported symbolic operation: {op:?}")).into());
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
        let mut result = self.bind(translated.term)?;
        if operands.iter().any(|(_, term)| term.defined != u64::MAX) {
            result.defined = match expression {
                Expr::Bin { op, .. } => {
                    let a = &operands[0].1;
                    let b = &operands[1].1;
                    defined_binary(*op, a, b)
                }
                _ => 0,
            };
        }
        Ok(result)
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
        if let Some(block) = self
            .cursor
            .blocks
            .iter()
            .position(|block| block.start == target)
        {
            self.cursor.block = block;
            self.cursor.statement = 0;
            return Ok(());
        }
        let blocks = if binary.image().functions.contains_key(&target)
            || binary.image().imports.contains_key(&target)
        {
            vec![Block {
                start: target,
                stmts: vec![Stmt::Call {
                    kind: CallKind::Tail,
                    target: Some(target),
                    through: None,
                    convention: binary.image().convention_of(target),
                    args: None,
                    floats_named: false,
                    abi: None,
                    outputs: Vec::new(),
                    clobbers: None,
                    via: None,
                }],
            }]
        } else {
            match lift(binary.image(), target) {
                Ok(blocks) => blocks,
                Err(error) => return Err(error),
            }
        };
        self.cursor = Cursor {
            blocks: Rc::from(blocks),
            block: 0,
            statement: 0,
        };
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
            match self.statement(binary, &statement, until) {
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

    fn statement(
        &mut self,
        binary: &Binary,
        statement: &Stmt,
        until: &[u64],
    ) -> Evaluation<Option<Step>> {
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
                let bits = semantics::operand_width(lhs, rhs);
                self.require_defined(&a, bits)?;
                self.require_defined(&b, bits)?;
                let test = smt::condition(*cond, &a.text, &b.text, bits);
                let mut taken = self.clone();
                taken.constraints.push(test.clone());
                if let Err(error) = taken.jump(binary, *target) {
                    taken.stop = Some(error.to_string());
                }
                let mut fallthrough = self.clone();
                fallthrough.constraints.push(format!("(not {test})"));
                let mut successors = Vec::new();
                if let Some(observations) = &self.branch_observations {
                    observations
                        .borrow_mut()
                        .sides
                        .entry(self.address)
                        .or_default();
                }
                for (index, state) in [taken, fallthrough].into_iter().enumerate() {
                    let feasible = state.satisfiable()?;
                    if let Some(observations) = &self.branch_observations {
                        observations
                            .borrow_mut()
                            .sides
                            .entry(self.address)
                            .or_default()[index] |= feasible;
                    }
                    if feasible {
                        successors.push(state);
                    }
                }
                return Ok(Some(Step::Branch(successors)));
            }
            Stmt::Switch {
                index,
                cases,
                default,
            } => {
                let index = self.eval(binary, index)?;
                let mut states = Vec::new();
                let mut otherwise = self.clone();
                for &(value, target) in cases {
                    let test = format!("(= {} {})", index.text, smt::constant(value as u64));
                    otherwise.constraints.push(format!("(not {test})"));
                    let mut state = self.clone();
                    state.constraints.push(test);
                    if state.satisfiable()? {
                        if let Err(error) = state.jump(binary, target) {
                            state.stop = Some(error.to_string());
                        }
                        states.push(state);
                    }
                }
                if otherwise.satisfiable()? {
                    match default {
                        Some(target) => {
                            if let Err(error) = otherwise.jump(binary, *target) {
                                otherwise.stop = Some(error.to_string());
                            }
                        }
                        None => otherwise.stop = Some("unsupported switch without default".into()),
                    }
                    states.push(otherwise);
                }
                return Ok(Some(Step::Branch(states)));
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
                if *kind == CallKind::Syscall {
                    return match self.syscall(binary, *convention, outputs) {
                        Ok(true) => Ok(Some(Step::Stopped("exit".into()))),
                        Ok(false) => Ok(None),
                        Err(error) => Err(error),
                    };
                }
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
                self.call(binary, target, *convention, *kind, outputs, until)?;
            }
            Stmt::Ret { value } => {
                let value = self.eval(binary, value)?;
                self.registers.insert(crate::arch::RETURN, value);
                return self.return_from_call(binary, /* machine_return */ true);
            }
            Stmt::Machine {
                instruction:
                    crate::ir::MachineInstruction::ArmSystem {
                        register: 0x5e82,
                        write,
                    },
                inputs,
                outputs,
            } if self.isa == Isa::AArch64 => {
                let register = crate::arch::aarch64::TPIDR_EL0;
                if *write {
                    let value = self.eval(binary, &inputs[0])?;
                    self.registers.insert(register, value);
                } else {
                    let value = self.read_register(register)?;
                    self.registers.insert(outputs[0].index, value);
                }
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
        let mut scanned_values = Vec::new();
        for scanned in &self.scanned_integers {
            let value = match state
                .solver
                .borrow_mut()
                .query(&state.constraints, Some(&scanned.value.text))
            {
                Ok(Some(value)) => value,
                Ok(None) => return Err(invalid("reached state is unsatisfiable")),
                Err(error) => return Err(error),
            };
            state.constraints.push(format!(
                "(= {} {})",
                scanned.value.text,
                smt::constant(value)
            ));
            scanned_values.push(value);
        }
        let mut choose = |term: &Term| -> Result<u64> {
            let Some(value) = state.extreme(term, &state.constraints, /* maximum */ false)? else {
                return Err(invalid("reached state is unsatisfiable"));
            };
            state
                .constraints
                .push(format!("(= {} {})", term.text, smt::constant(value)));
            Ok(value)
        };
        for (path, terms) in &self.input_files {
            let mut bytes = Vec::new();
            for term in terms {
                bytes.push(choose(term)? as u8);
            }
            result.files.insert(path.clone(), bytes);
        }
        let mut scanned_bytes = vec![false; self.stdin.len()];
        for scanned in &self.scanned_integers {
            let Some(end) = scanned.start.checked_add(scanned.length) else {
                return Err(invalid("scanf input range overflows"));
            };
            let Some(bytes) = scanned_bytes.get_mut(scanned.start..end) else {
                return Err(invalid("scanf input range is unavailable"));
            };
            bytes.fill(true);
        }
        for (index, byte) in self.stdin.iter().enumerate() {
            result.stdin.push(if scanned_bytes[index] {
                0
            } else {
                choose(byte)? as u8
            });
        }
        for (scanned, value) in self.scanned_integers.iter().zip(scanned_values) {
            let (sign, magnitude) = if scanned.canonical {
                if scanned.unsigned {
                    (Some(b'+'), u64::from(value as u32))
                } else {
                    let signed = value as i64;
                    (
                        Some(if signed < 0 { b'-' } else { b'+' }),
                        signed.unsigned_abs(),
                    )
                }
            } else if scanned.unsigned {
                if scanned.sign == Some(b'-') {
                    (scanned.sign, u64::from(0u32.wrapping_sub(value as u32)))
                } else {
                    (scanned.sign, u64::from(value as u32))
                }
            } else {
                let signed = value as i64;
                if (scanned.sign == Some(b'-') && signed > 0)
                    || (scanned.sign != Some(b'-') && signed < 0)
                {
                    return Err(invalid("scanf model does not match its sign"));
                }
                (scanned.sign, signed.unsigned_abs())
            };
            let digits = format!("{:0>width$}", magnitude, width = scanned.digits);
            let mut replacement = vec![b' '; scanned.whitespace];
            if let Some(sign) = sign {
                replacement.push(sign);
            }
            replacement.extend_from_slice(digits.as_bytes());
            if replacement.len() != scanned.length {
                return Err(invalid("scanf model changes the input token length"));
            }
            let Some(end) = scanned.start.checked_add(scanned.length) else {
                return Err(invalid("scanf input range overflows"));
            };
            let Some(bytes) = result.stdin.get_mut(scanned.start..end) else {
                return Err(invalid("scanf input range is unavailable"));
            };
            bytes.copy_from_slice(&replacement);
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
        for byte in &self.stdout {
            result.stdout.push(choose(byte)? as u8);
        }
        for (path, terms) in &self.files.committed {
            let mut bytes = Vec::new();
            for term in terms {
                bytes.push(choose(term)? as u8);
            }
            result.file_outputs.insert(path.clone(), bytes);
        }
        Ok(result)
    }

    /// Explores successors from this state in deterministic depth-first order.
    pub fn explore(self, binary: &Binary, options: &Options) -> Result<Report> {
        if options.returns.is_some() && !options.find.is_empty() {
            return Err(invalid(
                "find addresses and return conditions are mutually exclusive",
            ));
        }
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
        if find.is_empty() && options.returns.is_none() {
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
            let step = state.step(binary, &until)?;
            for diagnostic in &state.model_diagnostics {
                if !report.diagnostics.contains(diagnostic) {
                    report.diagnostics.push(diagnostic.clone());
                }
            }
            match step {
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
                Step::Stopped(reason) if reason == "return" && options.returns.is_some() => {
                    let Some(condition) = &options.returns else {
                        continue;
                    };
                    let (cond, value) = condition.comparison()?;
                    let returned = state.read_register(crate::arch::RETURN)?;
                    state.constrain(cond, &returned, &Term::constant(value), 64)?;
                    if state.satisfiable()? {
                        report.found = true;
                        report.reason = "found".into();
                        report.inputs = Some(state.inputs()?);
                        report.path = state.path;
                        return Ok(report);
                    }
                }
                Step::Stopped(reason) => report.diagnostics.push(reason),
            }
        }
        let failures: Vec<&String> = report
            .diagnostics
            .iter()
            .filter(|reason| {
                !reason.starts_with("libc model at ") && !reason.starts_with("import model at ")
            })
            .collect();
        if report.reason == "paths exhausted" && !failures.is_empty() {
            if failures.iter().all(|reason| reason.as_str() == "avoided") {
                report.reason = "all paths avoided".to_owned();
            } else if failures
                .iter()
                .any(|reason| reason.contains("address enumeration bound"))
            {
                report.reason = "address enumeration bound reached".to_owned();
            } else if failures.iter().any(|reason| reason.contains("budget")) {
                report.reason = "step budget".to_owned();
            } else if let Some(reason) = failures
                .into_iter()
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
        until: &[u64],
    ) -> Evaluation<()> {
        if kind == CallKind::Syscall {
            return Err(invalid("unsupported symbolic system call").into());
        }
        let image = binary.image();
        let name = image
            .imports
            .get(&target)
            .map(String::as_str)
            .or_else(|| self.cxx_locale.and_then(|locale| locale.method(target)))
            .or_else(|| super::cxx::local_name(image, target))
            .or_else(|| {
                image
                    .functions
                    .get(&target)
                    .filter(|function| function.sources.contains(&crate::loader::NameSource::Plt))
                    .and_then(|function| function.name.as_deref())
            });
        let identification = if name.is_none() && !until.contains(&target) {
            binary.symbolic_identifications()?.get(&target)
        } else {
            None
        };
        let candidate = identification.and_then(|evidence| {
            let Some(first) = evidence.candidates.first() else {
                return None;
            };
            (evidence.certainty == crate::sigs::Certainty::Exact
                && evidence
                    .candidates
                    .iter()
                    .all(|candidate| candidate.name == first.name)
                && super::emulation::hooks::find(&first.name).is_some())
            .then_some(first)
        });
        let name = name.map(|display| super::cxx::imported_name(image, display).unwrap_or(display));
        let name = name.or_else(|| candidate.map(|candidate| candidate.name.as_str()));
        if let Some(name) = name {
            if let Some(candidate) = candidate {
                let diagnostic = format!(
                    "libc model at 0x{target:x}: {} (exact signature from {})",
                    candidate.name, candidate.set
                );
                if !self.model_diagnostics.contains(&diagnostic) {
                    self.model_diagnostics.push(diagnostic);
                }
            }
            if candidate.is_none() {
                let diagnostic = format!("import model at 0x{target:x}: {name} (import symbol)");
                if !self.model_diagnostics.contains(&diagnostic) {
                    self.model_diagnostics.push(diagnostic);
                }
            }
            self.model_call_kind = kind;
            let result = if let Some(call) = super::cxx::find(name) {
                match self.cxx(binary, call, convention) {
                    Ok(value) => value,
                    Err(Failure::Error(error)) => {
                        return Err(invalid(format!("{error}: {name}")).into());
                    }
                    Err(failure) => return Err(failure),
                }
            } else {
                self.libc(binary, name, convention)?
            };
            if self.stop.is_some() {
                return Ok(());
            }
            let result = if self.isa == Isa::I386 {
                self.low(&result, 32)?
            } else {
                result
            };
            for &register in convention.clobbered() {
                if kind == CallKind::Tail && self.isa == Isa::AArch64 && register == 30 {
                    continue;
                }
                let mut unknown = self.symbolic()?;
                unknown.defined = 0;
                self.registers.insert(register, unknown);
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
            if kind == CallKind::Tail
                && let Some(Step::Stopped(reason)) =
                    self.return_from_call(binary, /* machine_return */ false)?
            {
                self.stop = Some(reason);
            }
            return Ok(());
        }
        let blocks = lift(image, target)?;
        if let Some(observations) = &self.branch_observations {
            record_branches(observations, &blocks);
        }
        if kind == CallKind::Tail {
            self.registers.retain(|index, _| {
                *index < crate::ir::TEMP_BASE || *index == crate::lift::execution::DIRECTION
            });
            self.cursor = Cursor {
                blocks: Rc::from(blocks),
                block: 0,
                statement: 0,
            };
            return Ok(());
        }
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

impl State {
    fn return_from_call(
        &mut self,
        binary: &Binary,
        machine_return: bool,
    ) -> Evaluation<Option<Step>> {
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
                    width: frame.pushed as u8,
                    signed: false,
                },
            )?;
            if self.resolve(target)? != frame.return_address {
                return Err(invalid("unsupported changed return address").into());
            }
            let instruction = super::emulation::x86_instruction_at(binary.image(), self.address)
                .map_err(invalid)?;
            let cleanup = if machine_return
                && instruction.mnemonic() == iced_x86::Mnemonic::Ret
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
            if machine_return && word & 0xffff_fc1f != 0xd65f_0000 {
                return Err(invalid("unsupported authenticated return").into());
            }
            let register = if machine_return {
                ((word >> 5) & 31) as u16
            } else {
                30
            };
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
        Ok(None)
    }

    fn initialize_argument(
        &mut self,
        binary: &Binary,
        index: usize,
        term: Term,
        stack: u64,
    ) -> Result<()> {
        if let Some(&register) = self.convention.arguments().get(index) {
            self.registers.insert(register, term);
            return Ok(());
        }
        if !matches!(
            self.convention,
            crate::ir::Convention::SysV
                | crate::ir::Convention::Aapcs64
                | crate::ir::Convention::Cdecl
                | crate::ir::Convention::Stdcall
                | crate::ir::Convention::Fastcall
                | crate::ir::Convention::Thiscall
        ) {
            return Err(invalid("unsupported stack argument convention"));
        }
        let base = stack.checked_add_signed(
            self.convention
                .stack_arguments()
                .expect("supported convention"),
        );
        let address = super::emulation::stack_argument_address(
            base,
            (index - self.convention.arguments().len()) as u64,
            crate::arch::pointer_bytes(self.isa),
        );
        let Some(address) = address else {
            return Err(invalid("stack argument address overflows"));
        };
        self.store(
            binary.image(),
            address,
            &term,
            crate::arch::pointer_bytes(self.isa),
        )
    }
    /// Explores reachable branch contexts before classifying an infeasible side.
    pub fn branch_feasibility(
        mut self,
        binary: &Binary,
        options: &Options,
    ) -> Result<crate::symbolic::FeasibilityReport> {
        if !options.find.is_empty() || !options.avoid.is_empty() || options.returns.is_some() {
            return Err(invalid(
                "branch feasibility does not accept find, avoid, or returns",
            ));
        }
        let observations = Rc::new(RefCell::new(BranchObservations::default()));
        record_branches(&observations, &self.cursor.blocks);
        self.branch_observations = Some(Rc::clone(&observations));
        let mut pending = vec![self];
        let mut report = crate::symbolic::FeasibilityReport {
            branches: Vec::new(),
            complete: true,
            paths: 0,
            diagnostics: Vec::new(),
        };
        while let Some(mut state) = pending.pop() {
            if report.paths >= options.path_limit {
                report.complete = false;
                report.diagnostics.push("path budget".into());
                break;
            }
            report.paths += 1;
            let step = state.step(binary, &[]);
            for diagnostic in &state.model_diagnostics {
                if !report.diagnostics.contains(diagnostic) {
                    report.diagnostics.push(diagnostic.clone());
                }
            }
            match step {
                Ok(Step::Branch(states)) => pending.extend(states.into_iter().rev()),
                Ok(Step::Stopped(reason)) if reason == "return" || reason == "trap" => {}
                result => {
                    report.complete = false;
                    report.diagnostics.push(match result {
                        Err(error) => error.to_string(),
                        Ok(Step::Stopped(reason)) => reason,
                        _ => "unexpected address stop".into(),
                    });
                }
            }
        }
        report.diagnostics.sort();
        report.diagnostics.dedup();
        for (&address, sides) in observations.borrow().sides.iter() {
            for (index, &feasible) in sides.iter().enumerate() {
                if !feasible {
                    report.branches.push(crate::symbolic::BranchProof {
                        address: crate::addr::format(address),
                        taken: index == 0,
                        status: if report.complete { "unsat" } else { "unknown" }.into(),
                        reason: if report.complete && !sides[0] && !sides[1] {
                            Some("branch instruction is unreachable under the assumptions".into())
                        } else if report.complete {
                            None
                        } else {
                            Some(report.diagnostics.join("; "))
                        },
                    });
                }
            }
        }
        Ok(report)
    }
}

fn defined_binary(op: crate::ir::BinOp, a: &Term, b: &Term) -> u64 {
    match op {
        crate::ir::BinOp::And => {
            (a.defined & b.defined) | a.concrete.map_or(0, |v| !v) | b.concrete.map_or(0, |v| !v)
        }
        crate::ir::BinOp::Or => {
            (a.defined & b.defined) | a.concrete.unwrap_or(0) | b.concrete.unwrap_or(0)
        }
        crate::ir::BinOp::Xor => a.defined & b.defined,
        crate::ir::BinOp::Shl if b.defined == u64::MAX && b.concrete.is_some() => {
            let count = b.concrete.unwrap_or(0) as u32 & 63;
            (a.defined << count) | !((u64::MAX) << count)
        }
        crate::ir::BinOp::Shr if b.defined == u64::MAX && b.concrete.is_some() => {
            let count = b.concrete.unwrap_or(0) as u32 & 63;
            (a.defined >> count) | !((u64::MAX) >> count)
        }
        _ => 0,
    }
}

fn record_branches(observations: &Rc<RefCell<BranchObservations>>, blocks: &[Block]) {
    for block in blocks {
        let mut address = block.start;
        for statement in &block.stmts {
            match statement {
                Stmt::Assign {
                    dest,
                    value: Expr::Const(value),
                } if dest.index == crate::lift::execution::ADDRESS => address = *value,
                Stmt::Brif { .. } | Stmt::BrifFlags { .. } => {
                    observations.borrow_mut().sides.entry(address).or_default();
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_widths_preserve_unsigned_bounds() {
        if !smt::Proofs::available() {
            return;
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/alt.o");
        let binary = Binary::open(&path).expect("bounds fixture");
        let address = *binary
            .image()
            .functions
            .keys()
            .next()
            .expect("fixture function");
        let state = State::new(&binary, &crate::addr::format(address), &Options::default())
            .expect("bounds state");
        let value = state.symbolic().expect("symbolic integer");
        let mut proofs = smt::Proofs::default();
        for bits in [0, 1, 8, 16, 32, 64] {
            let narrowed = state.low(&value, bits).expect("narrow value");
            let maximum = semantics::mask(bits);
            assert_eq!(
                state.bounds(&narrowed).expect("unsigned bounds"),
                Some((0, maximum))
            );
            let mut fork = state.clone();
            fork.constrain(Cond::Eq, &narrowed, &Term::constant(maximum), 64)
                .expect("maximum constraint");
            assert_eq!(
                fork.evaluate(&narrowed, 2).expect("maximum value"),
                [maximum]
            );
            proofs.predicate(
                format!("zero upper bits bound {bits}"),
                &format!(
                    "(bvule {} {})",
                    smt::low("r0", bits),
                    smt::constant(maximum)
                ),
                "true",
            );
        }
        let predicate = state
            .predicate(&format!("(= {} {})", value.text, smt::constant(42)))
            .expect("predicate");
        assert_eq!(
            state.evaluate(&predicate, 3).expect("boolean values"),
            [0, 1]
        );
        proofs.predicate(
            "predicate bound",
            &format!(
                "(bvule (ite (= r0 {}) {} {}) {})",
                smt::constant(42),
                smt::constant(1),
                smt::constant(0),
                smt::constant(1)
            ),
            "true",
        );
        proofs.counterexample(
            "byte bound cannot omit bit 7",
            &format!("(bvule {} {})", smt::low("r0", 8), smt::constant(127)),
            "true",
        );
        proofs.check();
    }

    #[test]
    fn an_invalid_switch_target_does_not_discard_other_cases() {
        if !smt::Proofs::available() {
            return;
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/alt.o");
        let binary = Binary::open(&path).expect("switch test image");
        let address = *binary
            .image()
            .functions
            .keys()
            .next()
            .expect("fixture function");
        let options = Options {
            arguments: vec![0],
            ..Options::default()
        };
        let mut state =
            State::new(&binary, &crate::addr::format(address), &options).expect("switch state");
        let register = state.convention.arguments()[0];
        state.cursor = Cursor {
            blocks: Rc::from(vec![
                Block {
                    start: 0,
                    stmts: vec![Stmt::Switch {
                        index: Expr::reg(register, 64),
                        cases: vec![(0, u64::MAX), (1, 1)],
                        default: Some(2),
                    }],
                },
                Block {
                    start: 1,
                    stmts: vec![Stmt::Ret {
                        value: Expr::Const(1),
                    }],
                },
                Block {
                    start: 2,
                    stmts: vec![Stmt::Ret {
                        value: Expr::Const(0),
                    }],
                },
            ]),
            block: 0,
            statement: 0,
        };
        let Step::Branch(states) = state.step(&binary, &[]).expect("switch successors") else {
            panic!("symbolic switch must fork");
        };
        assert_eq!(states.len(), 3);
        let mut returned = Vec::new();
        let mut invalid = 0;
        for mut state in states {
            match state.step(&binary, &[]).expect("case step") {
                Step::Stopped(reason) if reason == "return" => {
                    let term = state
                        .read_register(crate::arch::RETURN)
                        .expect("case return");
                    returned.extend(state.evaluate(&term, 1).expect("case value"));
                }
                Step::Stopped(reason) if reason.contains("unmapped executable address") => {
                    invalid += 1
                }
                _ => panic!("unexpected switch case outcome"),
            }
        }
        returned.sort_unstable();
        assert_eq!(returned, [0, 1]);
        assert_eq!(invalid, 1);
    }

    #[test]
    fn smt_defined_bits_survive_partial_writes() {
        use crate::ir::BinOp;
        use crate::ir::smt::Proofs;
        if !Proofs::available() {
            return;
        }
        let mut proofs = Proofs::default();
        for op in [BinOp::And, BinOp::Or, BinOp::Xor, BinOp::Shl, BinOp::Shr] {
            for mask in [0, 0xff, 0xffff, 0xffff_0000, u64::MAX] {
                for constant in [
                    None,
                    Some(0),
                    Some(1),
                    Some(8),
                    Some(0xff),
                    Some(!0xff),
                    Some(64),
                ] {
                    let mut a = Term::constant(0);
                    a.concrete = None;
                    a.defined = mask;
                    let mut b = Term::constant(constant.unwrap_or(0));
                    if constant.is_none() {
                        b.concrete = None;
                        b.defined = mask;
                    }
                    let defined = smt::constant(defined_binary(op, &a, &b));
                    let operation = match op {
                        BinOp::And => "bvand",
                        BinOp::Or => "bvor",
                        BinOp::Xor => "bvxor",
                        BinOp::Shl => "bvshl",
                        BinOp::Shr => "bvlshr",
                        _ => unreachable!(),
                    };
                    let left = constant.map_or_else(|| "r1".into(), smt::constant);
                    let right = constant.map_or_else(|| "r3".into(), smt::constant);
                    let left = if matches!(op, BinOp::Shl | BinOp::Shr) {
                        format!("(bvand {left} {})", smt::constant(63))
                    } else {
                        left
                    };
                    let right = if matches!(op, BinOp::Shl | BinOp::Shr) {
                        format!("(bvand {right} {})", smt::constant(63))
                    } else {
                        right
                    };
                    let assumption = format!(
                        "(and (= (bvand r0 {0}) (bvand r2 {0})) (= (bvand r1 {0}) (bvand r3 {0})))",
                        smt::constant(mask)
                    );
                    proofs.predicate(format!("{op:?} {mask:x} {constant:?}"), &format!("(=> {assumption} (= (bvand ({operation} r0 {left}) {defined}) (bvand ({operation} r2 {right}) {defined})))"), "true");
                }
            }
        }
        proofs.counterexample(
            "undefined high byte",
            "(bvand r0 #xffffffffffffffff)",
            "(bvand r0 #x00000000000000ff)",
        );
        proofs.check();
    }
}

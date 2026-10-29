//! Symbolic adapters for standard C++ stream calls.

use super::{Evaluation, Failure, State, Term};
use crate::ir::eval::cxx::{self, Call, Direction, Layout, Machine};
use crate::ir::smt;
use crate::ir::{Convention, Expr};
use crate::service::Binary;
use crate::symbolic::invalid;

struct Adapter<'state, 'binary> {
    state: &'state mut State,
    binary: &'binary Binary,
    convention: Convention,
}

impl State {
    pub(super) fn initialize_cxx(&mut self, binary: &Binary) -> Evaluation<()> {
        self.cxx_locale = match cxx::initialize(
            &mut Adapter {
                state: self,
                binary,
                convention: Convention::SysV,
            },
            binary.image(),
        ) {
            Ok(locale) => locale,
            Err(failure) => return Err(failure),
        };
        Ok(())
    }

    pub(super) fn cxx(
        &mut self,
        binary: &Binary,
        call: Call,
        convention: Convention,
    ) -> Evaluation<Term> {
        if crate::arch::pointer_bytes(self.isa) != 8
            || !matches!(
                binary.image().format,
                crate::loader::Format::Elf | crate::loader::Format::MachO
            )
        {
            return Err(invalid("unsupported C++ ABI: requires 64-bit ELF or Mach-O").into());
        }
        match cxx::execute(
            &mut Adapter {
                state: self,
                binary,
                convention,
            },
            call,
        ) {
            Ok(value) => Ok(value),
            Err(error) => Err(error),
        }
    }
}

// Each failed argument, memory operation or solver query aborts the call.
impl Machine for Adapter<'_, '_> {
    type Byte = Term;
    type Value = Term;
    fn result(&self, value: u64) -> Term {
        Term::constant(value)
    }
    type Error = Failure;
    fn bound(&self) -> usize {
        self.state.model_bound()
    }
    fn error(&self, message: &str) -> Failure {
        invalid(message).into()
    }
    fn constant(&self, value: u8) -> Term {
        Term::constant(u64::from(value))
    }
    fn argument(&mut self, index: usize) -> Evaluation<u64> {
        self.state.number(self.binary, self.convention, index)
    }
    fn indirect_result(&mut self) -> Evaluation<u64> {
        if self.state.isa == crate::loader::Isa::AArch64 {
            let value = match self.state.read_register(8) {
                Ok(value) => value,
                Err(error) => return Err(error.into()),
            };
            self.state.resolve(value)
        } else {
            self.argument(0)
        }
    }
    fn locale(&self) -> Option<cxx::Locale> {
        self.state.cxx_locale
    }
    fn character_result(&self, byte: Term) -> Evaluation<Term> {
        if self.state.isa == crate::loader::Isa::AArch64
            && self.binary.image().format == crate::loader::Format::MachO
        {
            if let Some(value) = byte.concrete {
                return Ok(Term::constant(u64::from(i32::from(value as i8) as u32)));
            }
            return match self.state.bind(smt::low(&smt::signed(&byte.text, 8), 32)) {
                Ok(value) => Ok(value),
                Err(error) => Err(error.into()),
            };
        }
        Ok(byte)
    }
    fn read(&mut self, address: u64, length: usize) -> Evaluation<Vec<Term>> {
        let mut bytes = Vec::new();
        for offset in 0..length {
            bytes.push(self.state.byte(self.binary, address, offset)?);
        }
        Ok(bytes)
    }
    fn write(&mut self, address: u64, bytes: &[Term]) -> Evaluation<()> {
        self.state.write_memory(self.binary, address, bytes)?;
        Ok(())
    }
    fn alternate_string_layout(&self) -> bool {
        self.binary.image().format == crate::loader::Format::MachO
    }
    fn character(&mut self, index: usize) -> Evaluation<Term> {
        let value = self.state.argument(self.binary, self.convention, index)?;
        self.state.require_defined(&value, 8)?;
        Ok(self.state.low(&value, 8)?)
    }
    fn ascii(&mut self, byte: &Term) -> Evaluation<bool> {
        self.state
            .test(format!("(bvult {} {})", byte.text, smt::constant(128)))
    }
    fn byte_value(&mut self, byte: Term) -> Evaluation<u8> {
        Ok(self.state.resolve(byte)? as u8)
    }
    fn word(&mut self, address: u64) -> Evaluation<u64> {
        let term = self.state.eval(
            self.binary,
            &Expr::Load {
                addr: Box::new(Expr::Const(address)),
                width: 8,
                signed: false,
            },
        )?;
        self.state.resolve(term)
    }
    fn relocate(&mut self, address: u64, value: u64) -> Evaluation<()> {
        if !self
            .state
            .mapped_memory(self.binary.image())?
            .check(address, 8, false)
        {
            return Err(self.error("invalid C++ stream relocation"));
        }
        for (offset, byte) in value.to_le_bytes().into_iter().enumerate() {
            self.state
                .memory
                .insert(address + offset as u64, Term::constant(u64::from(byte)));
        }
        Ok(())
    }
    fn store_word(&mut self, address: u64, value: u64) -> Evaluation<()> {
        self.state
            .store(self.binary.image(), address, &Term::constant(value), 8)?;
        Ok(())
    }
    fn allocate(&mut self, length: usize) -> Evaluation<u64> {
        let Some(start) = self
            .state
            .heap_next
            .checked_add(15)
            .map(|value| value & !15)
        else {
            return Err(self.error("C++ allocation address overflows"));
        };
        let Some(end) = start.checked_add(length as u64) else {
            return Err(self.error("C++ allocation address overflows"));
        };
        let memory = self.state.mapped_memory(self.binary.image())?;
        if end > memory.heap_base.saturating_add(crate::emulation::HEAP_SIZE) {
            return Err(self.error("C++ allocation exceeds heap"));
        }
        self.state.heap_next = end;
        Ok(start)
    }
    fn equal(&mut self, byte: &Term, value: u8) -> Evaluation<bool> {
        self.state.test(format!(
            "(= {} {})",
            byte.text,
            smt::constant(u64::from(value))
        ))
    }
    fn whitespace(&mut self, byte: &Term) -> Evaluation<bool> {
        self.state.whitespace(byte)
    }
    fn input(&mut self, consume: bool) -> Evaluation<Option<Term>> {
        self.state.tick()?;
        let byte = self.state.stdin.get(self.state.input_position).cloned();
        if consume && byte.is_some() {
            self.state.input_position += 1;
        }
        Ok(byte)
    }
    fn output(&mut self, bytes: Vec<Term>) -> Evaluation<()> {
        if self.state.stdout.len().saturating_add(bytes.len())
            > crate::emulation::HEAP_SIZE as usize
        {
            return Err(self.error("captured output exceeds 16 MiB"));
        }
        self.state.stdout.extend(bytes);
        Ok(())
    }
    fn integer(&mut self, signed: bool, bits: u8, direction: Direction) -> Evaluation<()> {
        if matches!(direction, Direction::Input) {
            let destination = self.argument(1)?;
            while let Some(byte) = self.input(false)? {
                if !self.whitespace(&byte)? {
                    break;
                }
                self.input(true)?;
            }
            let mut negative = false;
            if let Some(byte) = self.input(false)? {
                negative = self.equal(&byte, b'-')?;
                if negative || self.equal(&byte, b'+')? {
                    self.input(true)?;
                }
            }
            let limit = if signed {
                (1u64 << (bits - 1)) - u64::from(!negative)
            } else {
                u64::MAX >> (64 - bits)
            };
            let mut value = Term::constant(0);
            let mut count = 0;
            while let Some(byte) = self.input(false)? {
                if !self.state.test(format!(
                    "(and (bvuge {0} {1}) (bvule {0} {2}))",
                    byte.text,
                    smt::constant(48),
                    smt::constant(57)
                ))? {
                    break;
                }
                let digit = format!("(bvsub {} {})", byte.text, smt::constant(48));
                if self.state.test(super::libc::integer_overflow(
                    &value.text,
                    &digit,
                    10,
                    limit,
                ))? {
                    return Err(self.error("unsupported C++ integer input overflow"));
                }
                value = self.state.bind(format!(
                    "(bvadd (bvmul {} {}) {digit})",
                    value.text,
                    smt::constant(10)
                ))?;
                self.input(true)?;
                count += 1;
            }
            if count == 0 {
                return Err(self.error("unsupported C++ integer input failure"));
            }
            if negative {
                value = self.state.bind(format!("(bvneg {})", value.text))?;
            }
            self.state
                .store(self.binary.image(), destination, &value, bits / 8)?;
            return Ok(());
        }
        let argument = self.state.argument(self.binary, self.convention, 1)?;
        self.state.require_defined(&argument, bits.into())?;
        let mut value = self.state.low(&argument, bits.into())?;
        if signed
            && self.state.test(format!(
                "(bvuge {} {})",
                value.text,
                smt::constant(1u64 << (bits - 1))
            ))?
        {
            self.output(vec![Term::constant(45)])?;
            value = self
                .state
                .bind(smt::low(&format!("(bvneg {})", value.text), bits.into()))?;
        }
        let mut digits = Vec::new();
        loop {
            self.state.tick()?;
            digits.push(self.state.bind(format!(
                "(bvadd (bvurem {} {}) {})",
                value.text,
                smt::constant(10),
                smt::constant(48)
            ))?);
            value = self
                .state
                .bind(format!("(bvudiv {} {})", value.text, smt::constant(10)))?;
            if self.equal(&value, 0)? {
                break;
            }
        }
        digits.reverse();
        self.output(digits)
    }
    fn compare(&mut self, left: &[Term], right: &[Term], layout: Layout) -> Evaluation<Term> {
        for (left, right) in left.iter().zip(right) {
            if self
                .state
                .test(format!("(not (= {} {}))", left.text, right.text))?
            {
                let difference = self.state.bind(smt::low(
                    &format!("(bvsub {} {})", left.text, right.text),
                    32,
                ))?;
                return Ok(difference);
            }
        }
        let difference = left.len() as i32 - right.len() as i32;
        Ok(Term::constant(u64::from(
            if matches!(layout, Layout::Gnu) {
                difference as u32
            } else {
                difference.signum() as u32
            },
        )))
    }
    fn stream(&mut self, address: u64, input: bool) -> Evaluation<()> {
        if let Some(layout) = cxx::stream_object(self.binary.image(), address, input) {
            return cxx::validate_stream(self, address, input, layout);
        }
        for (&slot, symbol) in &self.binary.image().imports {
            if cxx::stream_symbol(symbol) == Some(input) && self.word(slot)? == address {
                let layout = if cxx::name(symbol).starts_with("_ZSt") {
                    Layout::Gnu
                } else {
                    Layout::Llvm
                };
                return cxx::validate_stream(self, address, input, layout);
            }
        }
        Err(self.error("unsupported C++ stream: expected std::cin or std::cout"))
    }
    fn end_input(&mut self, address: u64) -> Evaluation<()> {
        cxx::eof(self, address)
    }
    fn manipulator(&mut self, address: u64) -> Evaluation<Call> {
        let image = self.binary.image();
        let call = image
            .imports
            .get(&address)
            .and_then(|name| cxx::find(name))
            .or_else(|| {
                image
                    .functions
                    .get(&address)
                    .and_then(|function| function.name.as_deref())
                    .and_then(|name| cxx::imported_name(image, name))
                    .and_then(cxx::find)
            });
        let call = call.or_else(|| cxx::local_name(image, address).and_then(cxx::find));
        match call {
            Some(call @ (Call::Endl | Call::Flush)) => Ok(call),
            _ => Err(self.error("unsupported C++ stream manipulator")),
        }
    }
}

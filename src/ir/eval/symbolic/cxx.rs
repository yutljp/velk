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
    fn indirect_result_argument_offset(&self) -> usize {
        if self.state.isa == crate::loader::Isa::AArch64 {
            0
        } else {
            1
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
    fn character_int_result(&self, byte: Term) -> Evaluation<Term> {
        match self.state.low(&byte, 32) {
            Ok(value) => Ok(value),
            Err(error) => Err(error.into()),
        }
    }
    fn read(&mut self, address: u64, length: usize) -> Evaluation<Vec<Term>> {
        let mut bytes = Vec::new();
        for offset in 0..length {
            let byte = match self.state.byte(self.binary, address, offset) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            bytes.push(byte);
        }
        Ok(bytes)
    }
    fn write(&mut self, address: u64, bytes: &[Term]) -> Evaluation<()> {
        if let Err(error) = self.state.write_memory(self.binary, address, bytes) {
            return Err(error.into());
        }
        Ok(())
    }
    fn alternate_string_layout(&self) -> bool {
        self.binary.image().format == crate::loader::Format::MachO
    }
    fn character(&mut self, index: usize) -> Evaluation<Term> {
        let value = match self.state.argument(self.binary, self.convention, index) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        if let Err(error) = self.state.require_defined(&value, 8) {
            return Err(error.into());
        }
        let low_byte = match self.state.low(&value, 8) {
            Ok(value) => value,
            Err(error) => return Err(error.into()),
        };
        Ok(low_byte)
    }
    fn ascii(&mut self, byte: &Term) -> Evaluation<bool> {
        self.state
            .test(format!("(bvult {} {})", byte.text, smt::constant(128)))
    }
    fn byte_value(&mut self, byte: Term) -> Evaluation<u8> {
        let concrete = match self.state.resolve(byte) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        Ok(concrete as u8)
    }
    fn word(&mut self, address: u64) -> Evaluation<u64> {
        let term = match self.state.eval(
            self.binary,
            &Expr::Load {
                addr: Box::new(Expr::Const(address)),
                width: 8,
                signed: false,
            },
        ) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        self.state.resolve(term)
    }
    fn relocate(&mut self, address: u64, value: u64) -> Evaluation<()> {
        let memory = match self.state.mapped_memory(self.binary.image()) {
            Ok(value) => value,
            Err(error) => return Err(error.into()),
        };
        if !memory.check(address, 8, false) {
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
        if let Err(error) =
            self.state
                .store(self.binary.image(), address, &Term::constant(value), 8)
        {
            return Err(error.into());
        }
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
        let memory = match self.state.mapped_memory(self.binary.image()) {
            Ok(value) => value,
            Err(error) => return Err(error.into()),
        };
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
    fn same_byte(&mut self, left: &Term, right: &Term) -> Evaluation<bool> {
        self.state.test(format!("(= {} {})", left.text, right.text))
    }
    fn whitespace(&mut self, byte: &Term) -> Evaluation<bool> {
        self.state.whitespace(byte)
    }
    fn input(&mut self, consume: bool) -> Evaluation<Option<Term>> {
        if let Err(error) = self.state.tick() {
            return Err(error);
        }
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
            let stream = match self.argument(0) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let destination = match self.argument(1) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            loop {
                let byte = match self.input(false) {
                    Ok(Some(byte)) => byte,
                    Ok(None) => break,
                    Err(error) => return Err(error),
                };

                let is_whitespace = match self.whitespace(&byte) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if !is_whitespace {
                    break;
                }
                if let Err(error) = self.input(true) {
                    return Err(error);
                }
            }
            let next_byte = match self.input(false) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let Some(first) = next_byte else {
                if let Err(error) = self.set_stream_state(stream, true, 4) {
                    return Err(error);
                }
                return Ok(());
            };
            let negative = match self.equal(&first, b'-') {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let has_sign = if negative {
                true
            } else {
                match self.equal(&first, b'+') {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                }
            };
            if has_sign && let Err(error) = self.input(true) {
                return Err(error);
            }
            let limit = if signed {
                (1u64 << (bits - 1)) - u64::from(!negative)
            } else {
                u64::MAX >> (64 - bits)
            };
            let mut value = Term::constant(0);
            let mut count = 0;
            let mut overflow = false;
            loop {
                let byte = match self.input(false) {
                    Ok(Some(byte)) => byte,
                    Ok(None) => break,
                    Err(error) => return Err(error),
                };

                let is_digit = match self.state.test(format!(
                    "(and (bvuge {0} {1}) (bvule {0} {2}))",
                    byte.text,
                    smt::constant(48),
                    smt::constant(57)
                )) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if !is_digit {
                    break;
                }
                let digit = format!("(bvsub {} {})", byte.text, smt::constant(48));
                let overflows = if overflow {
                    false
                } else {
                    match self.state.test(super::libc::integer_overflow(
                        &value.text,
                        &digit,
                        10,
                        limit,
                    )) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    }
                };
                if overflows {
                    value = Term::constant(limit);
                    overflow = true;
                } else if !overflow {
                    value = match self.state.bind(format!(
                        "(bvadd (bvmul {} {}) {digit})",
                        value.text,
                        smt::constant(10)
                    )) {
                        Ok(value) => value,
                        Err(error) => return Err(error.into()),
                    };
                }
                if let Err(error) = self.input(true) {
                    return Err(error);
                }
                count += 1;
            }
            if count == 0 {
                if let Err(error) = self.set_stream_state(stream, true, 4) {
                    return Err(error);
                }
                if let Err(error) =
                    self.state
                        .store(self.binary.image(), destination, &value, bits / 8)
                {
                    return Err(error.into());
                }
                return Ok(());
            }
            if overflow && let Err(error) = self.set_stream_state(stream, true, 4) {
                return Err(error);
            }
            if negative {
                if overflow && !signed {
                    value = Term::constant(limit);
                } else {
                    value = match self.state.bind(format!("(bvneg {})", value.text)) {
                        Ok(value) => value,
                        Err(error) => return Err(error.into()),
                    };
                }
            }
            if let Err(error) = self
                .state
                .store(self.binary.image(), destination, &value, bits / 8)
            {
                return Err(error.into());
            }
            return Ok(());
        }
        let argument = match self.state.argument(self.binary, self.convention, 1) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        if let Err(error) = self.state.require_defined(&argument, bits.into()) {
            return Err(error.into());
        }
        let mut value = match self.state.low(&argument, bits.into()) {
            Ok(value) => value,
            Err(error) => return Err(error.into()),
        };
        let negative_output = if signed {
            match self.state.test(format!(
                "(bvuge {} {})",
                value.text,
                smt::constant(1u64 << (bits - 1))
            )) {
                Ok(value) => value,
                Err(error) => return Err(error),
            }
        } else {
            false
        };
        if negative_output {
            if let Err(error) = self.output(vec![Term::constant(45)]) {
                return Err(error);
            }
            value = match self
                .state
                .bind(smt::low(&format!("(bvneg {})", value.text), bits.into()))
            {
                Ok(value) => value,
                Err(error) => return Err(error.into()),
            };
        }
        let mut digits = Vec::new();
        loop {
            if let Err(error) = self.state.tick() {
                return Err(error);
            }
            let digit = match self.state.bind(format!(
                "(bvadd (bvurem {} {}) {})",
                value.text,
                smt::constant(10),
                smt::constant(48)
            )) {
                Ok(value) => value,
                Err(error) => return Err(error.into()),
            };
            digits.push(digit);
            value = match self
                .state
                .bind(format!("(bvudiv {} {})", value.text, smt::constant(10)))
            {
                Ok(value) => value,
                Err(error) => return Err(error.into()),
            };
            let is_zero = match self.equal(&value, 0) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            if is_zero {
                break;
            }
        }
        digits.reverse();
        self.output(digits)
    }
    fn compare(&mut self, left: &[Term], right: &[Term], layout: Layout) -> Evaluation<Term> {
        for (left, right) in left.iter().zip(right) {
            let differs = match self
                .state
                .test(format!("(not (= {} {}))", left.text, right.text))
            {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            if differs {
                let difference = match self.state.bind(smt::low(
                    &format!("(bvsub {} {})", left.text, right.text),
                    32,
                )) {
                    Ok(value) => value,
                    Err(error) => return Err(error.into()),
                };
                return Ok(difference);
            }
        }
        let difference = left.len() as i32 - right.len() as i32;
        Ok(Term::constant(u64::from(
            if matches!(layout, Layout::Gnu | Layout::GnuCow) {
                difference as u32
            } else {
                difference.signum() as u32
            },
        )))
    }
    fn string_equal(&mut self, left: &[Term], right: &[Term]) -> Evaluation<Term> {
        if left.len() != right.len() {
            return Ok(Term::constant(0));
        }
        let condition = if left.is_empty() {
            "true".to_owned()
        } else {
            let terms = left
                .iter()
                .zip(right)
                .map(|(left, right)| format!("(= {} {})", left.text, right.text))
                .collect::<Vec<String>>();
            format!("(and {})", terms.join(" "))
        };
        match self.state.bind(format!(
            "(ite {condition} {} {})",
            smt::constant(1),
            smt::constant(0)
        )) {
            Ok(value) => Ok(value),
            Err(error) => Err(error.into()),
        }
    }
    fn stream(&mut self, address: u64, input: bool) -> Evaluation<()> {
        if let Some(layout) = cxx::stream_object(self.binary.image(), address, input) {
            return cxx::validate_stream(self, address, input, layout);
        }
        for (&slot, symbol) in &self.binary.image().imports {
            if cxx::stream_symbol(symbol) == Some(input) {
                let word = match self.word(slot) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if word == address {
                    let layout = if cxx::name(symbol).starts_with("_ZSt") {
                        Layout::Gnu
                    } else {
                        Layout::Llvm
                    };
                    return cxx::validate_stream(self, address, input, layout);
                }
            }
        }
        Err(self.error("unsupported C++ stream: expected std::cin or std::cout"))
    }
    fn stream_failed(&mut self, address: u64, input: bool) -> Evaluation<bool> {
        let offset = if input { 48 } else { 40 };
        let Some(location) = address.checked_add(offset) else {
            return Err(self.error("C++ stream state address overflows"));
        };
        let flags = match self.word(location) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        if flags & 2 != 0
            && let Err(error) = self.set_stream_state(address, input, 4)
        {
            return Err(error);
        }
        Ok(flags != 0)
    }
    fn set_stream_state(&mut self, address: u64, input: bool, flags: u64) -> Evaluation<()> {
        let offset = if input { 48 } else { 40 };
        let Some(location) = address.checked_add(offset) else {
            return Err(self.error("C++ stream state address overflows"));
        };
        let current = match self.word(location) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        self.store_word(location, current | flags)
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

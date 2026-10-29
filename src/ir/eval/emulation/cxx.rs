//! Concrete adapters for standard C++ stream calls.

use super::{Runner, Stop};
use crate::ir::eval::cxx::{self, Call, Direction, Layout, Machine};
use crate::ir::{CallKind, Convention};

struct Adapter<'runner, 'image> {
    runner: &'runner mut Runner<'image>,
    convention: Convention,
    kind: CallKind,
}

impl Runner<'_> {
    pub(super) fn initialize_cxx(&mut self) -> Result<(), Stop> {
        let image = self.image;
        self.cxx_locale = match cxx::initialize(
            &mut Adapter {
                runner: self,
                convention: Convention::SysV,
                kind: CallKind::Invoke,
            },
            image,
        ) {
            Ok(locale) => locale,
            Err(stop) => return Err(stop),
        };
        Ok(())
    }

    pub(super) fn cxx(
        &mut self,
        call: Call,
        convention: Convention,
        kind: CallKind,
    ) -> Result<u64, Stop> {
        if crate::arch::pointer_bytes(self.image.isa) != 8
            || !matches!(
                self.image.format,
                crate::loader::Format::Elf | crate::loader::Format::MachO
            )
        {
            return Err(Stop::Error(
                "unsupported C++ ABI: requires 64-bit ELF or Mach-O".into(),
            ));
        }
        cxx::execute(
            &mut Adapter {
                runner: self,
                convention,
                kind,
            },
            call,
        )
    }
}

// Every argument and memory failure aborts the call.
impl Machine for Adapter<'_, '_> {
    type Byte = u8;
    type Value = u64;
    fn result(&self, value: u64) -> u64 {
        value
    }
    type Error = Stop;
    fn bound(&self) -> usize {
        crate::emulation::HEAP_SIZE as usize
    }
    fn error(&self, message: &str) -> Stop {
        Stop::Error(message.into())
    }
    fn constant(&self, value: u8) -> u8 {
        value
    }
    fn argument(&mut self, index: usize) -> Result<u64, Stop> {
        self.runner.argument(index, self.convention, self.kind)
    }
    fn indirect_result(&mut self) -> Result<u64, Stop> {
        if self.runner.image.isa == crate::loader::Isa::AArch64 {
            self.runner.eval(&crate::ir::Expr::reg(8, 64))
        } else {
            self.argument(0)
        }
    }
    fn locale(&self) -> Option<cxx::Locale> {
        self.runner.cxx_locale
    }
    fn character_result(&self, byte: u8) -> Result<u64, Stop> {
        // Darwin's arm64 ABI extends signed char results to 32 bits.
        if self.runner.image.isa == crate::loader::Isa::AArch64
            && self.runner.image.format == crate::loader::Format::MachO
        {
            Ok(u64::from(i32::from(byte as i8) as u32))
        } else {
            Ok(u64::from(byte))
        }
    }
    fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, Stop> {
        self.runner
            .check_memory_range(address, length as u64, /* write */ false)?;
        let mut bytes = Vec::new();
        for offset in 0..length {
            bytes.push(self.runner.read_byte(address + offset as u64)?);
        }
        Ok(bytes)
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), Stop> {
        self.runner
            .check_memory_range(address, bytes.len() as u64, /* write */ true)?;
        for (offset, &byte) in bytes.iter().enumerate() {
            self.runner.write_byte(address + offset as u64, byte)?;
        }
        Ok(())
    }
    fn alternate_string_layout(&self) -> bool {
        self.runner.image.format == crate::loader::Format::MachO
    }
    fn character(&mut self, index: usize) -> Result<u8, Stop> {
        Ok(self.argument(index)? as u8)
    }
    fn ascii(&mut self, byte: &u8) -> Result<bool, Stop> {
        Ok(byte.is_ascii())
    }
    fn byte_value(&mut self, byte: u8) -> Result<u8, Stop> {
        Ok(byte)
    }
    fn word(&mut self, address: u64) -> Result<u64, Stop> {
        let bytes = self.read(address, 8)?;
        Ok(u64::from_le_bytes(
            bytes.try_into().expect("eight-byte read"),
        ))
    }
    fn relocate(&mut self, address: u64, value: u64) -> Result<(), Stop> {
        self.runner
            .check_memory_range(address, 8, /* write */ false)?;
        for (offset, byte) in value.to_le_bytes().into_iter().enumerate() {
            self.runner
                .machine
                .memory
                .insert(address + offset as u64, byte);
        }
        Ok(())
    }
    fn store_word(&mut self, address: u64, value: u64) -> Result<(), Stop> {
        self.write(address, &value.to_le_bytes())
    }
    fn allocate(&mut self, length: usize) -> Result<u64, Stop> {
        let pointer = self.runner.allocate(length as u64);
        if pointer == 0 {
            return Err(self.error("C++ string allocation exceeds heap"));
        }
        Ok(pointer)
    }
    fn equal(&mut self, byte: &u8, value: u8) -> Result<bool, Stop> {
        Ok(*byte == value)
    }
    fn whitespace(&mut self, byte: &u8) -> Result<bool, Stop> {
        Ok(byte.is_ascii_whitespace())
    }
    fn input(&mut self, consume: bool) -> Result<Option<u8>, Stop> {
        self.runner.tick()?;
        let byte = self.runner.input.get(self.runner.input_position).copied();
        if consume && byte.is_some() {
            self.runner.input_position += 1;
        }
        Ok(byte)
    }
    fn output(&mut self, bytes: Vec<u8>) -> Result<(), Stop> {
        self.runner.emit(1, &bytes)
    }
    fn integer(&mut self, signed: bool, bits: u8, direction: Direction) -> Result<(), Stop> {
        if matches!(direction, Direction::Output) {
            let value = self.argument(1)?;
            let shift = 64 - bits;
            let text = if signed {
                ((value.wrapping_shl(shift.into()) as i64) >> shift).to_string()
            } else {
                (value & (u64::MAX >> shift)).to_string()
            };
            return self.output(text.into_bytes());
        }
        let destination = self.argument(1)?;
        while self
            .input(false)?
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            self.input(true)?;
        }
        let negative = self.input(false)? == Some(b'-');
        if negative || self.input(false)? == Some(b'+') {
            self.input(true)?;
        }
        let limit = if signed {
            (1u64 << (bits - 1)) - u64::from(!negative)
        } else {
            u64::MAX >> (64 - bits)
        };
        let mut value = 0u64;
        let mut count = 0;
        while let Some(byte @ b'0'..=b'9') = self.input(false)? {
            let digit = u64::from(byte - b'0');
            if value > (limit - digit.min(limit)) / 10 || digit > limit {
                return Err(self.error("unsupported C++ integer input overflow"));
            }
            value = value * 10 + digit;
            count += 1;
            self.input(true)?;
        }
        if count == 0 {
            return Err(self.error("unsupported C++ integer input failure"));
        }
        if negative {
            value = value.wrapping_neg();
        }
        self.write(destination, &value.to_le_bytes()[..usize::from(bits / 8)])
    }
    fn compare(&mut self, left: &[u8], right: &[u8], layout: Layout) -> Result<u64, Stop> {
        for (&left, &right) in left.iter().zip(right) {
            if left != right {
                return Ok(u64::from((i32::from(left) - i32::from(right)) as u32));
            }
        }
        let difference = left.len() as i32 - right.len() as i32;
        Ok(u64::from(if matches!(layout, Layout::Gnu) {
            difference as u32
        } else {
            difference.signum() as u32
        }))
    }
    fn stream(&mut self, address: u64, input: bool) -> Result<(), Stop> {
        if let Some(layout) = cxx::stream_object(self.runner.image, address, input) {
            return cxx::validate_stream(self, address, input, layout);
        }
        for (&slot, symbol) in &self.runner.image.imports {
            if cxx::stream_symbol(symbol) == Some(input) && self.word(slot)? == address {
                self.runner.memory_error()?;
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
    fn end_input(&mut self, address: u64) -> Result<(), Stop> {
        cxx::eof(self, address)
    }
    fn manipulator(&mut self, address: u64) -> Result<Call, Stop> {
        let call = self
            .runner
            .image
            .imports
            .get(&address)
            .and_then(|name| cxx::find(name))
            .or_else(|| {
                self.runner
                    .image
                    .functions
                    .get(&address)
                    .and_then(|function| function.name.as_deref())
                    .and_then(|name| cxx::imported_name(self.runner.image, name))
                    .and_then(cxx::find)
            });
        let call = call.or_else(|| cxx::local_name(self.runner.image, address).and_then(cxx::find));
        match call {
            Some(call @ (Call::Endl | Call::Flush)) => Ok(call),
            _ => Err(self.error("unsupported C++ stream manipulator")),
        }
    }
}

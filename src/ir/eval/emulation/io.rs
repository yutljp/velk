//! Bounded standard stream input and output.

mod arguments;
mod formatting;
mod scanning;

use arguments::Arguments;

use crate::ir::{CallKind, Convention};
use crate::loader::Isa;

use super::{HEAP_SIZE, Runner, Stop};

#[derive(Clone, Copy)]
pub(super) enum Operation {
    Printf,
    Fprintf,
    Sprintf,
    Snprintf,
    Puts,
    Putchar,
    Fputs,
    Fwrite,
    Write,
    Read,
    Fread,
    Fgets,
    Gets,
    Getchar,
    Scanf,
    Fscanf,
    Sscanf,
    Vprintf,
    Vfprintf,
    Vsprintf,
    Vsnprintf,
    Vscanf,
    Vfscanf,
    Vsscanf,
}

fn error(message: impl Into<String>) -> Stop {
    Stop::Error(message.into())
}

fn address(base: u64, offset: usize) -> Result<u64, Stop> {
    base.checked_add(offset as u64)
        .ok_or_else(|| error("I/O memory address overflows"))
}

impl Runner<'_> {
    // Setup failures invalidate the entire run.
    pub(super) fn initialize_io(&mut self, start: u64, stack: u64) -> Result<(), String> {
        if self.recovery.is_some() {
            return Ok(());
        }
        if let Some(argv) = &self.options.argv {
            if !self.options.arguments.is_empty() || self.image.go {
                return Err("argv requires a C main with no explicit arguments".into());
            }
            let pointer = crate::arch::pointer_bytes(self.image.isa);
            let size = argv
                .len()
                .checked_add(1)
                .and_then(|count| count.checked_mul(pointer as usize));
            let Some(size) = size.filter(|size| *size as u64 <= HEAP_SIZE) else {
                return Err("argv exceeds heap capacity".into());
            };
            let table = self.allocate(size as u64);
            if table == 0 {
                return Err("argv allocation failed".into());
            }
            for (index, text) in argv.iter().enumerate() {
                if text.contains('\0') {
                    return Err("argv contains a NUL byte".into());
                }
                let Some(size) = text.len().checked_add(1) else {
                    return Err("argv string size overflows".into());
                };
                let location = self.allocate(size as u64);
                if location == 0 {
                    return Err("argv strings exceed heap capacity".into());
                }
                for (offset, byte) in text.bytes().chain([0]).enumerate() {
                    self.machine
                        .store(location + offset as u64, u64::from(byte), 1);
                }
                self.machine
                    .store(table + (index * pointer as usize) as u64, location, pointer);
            }
            self.machine
                .store(table + (argv.len() * pointer as usize) as u64, 0, pointer);
            let options = crate::emulation::Options {
                arguments: vec![
                    crate::emulation::Word::Text(argv.len().to_string()),
                    crate::emulation::Word::Text(table.to_string()),
                ],
                ..Default::default()
            };
            if let Err(cause) = super::initialize_arguments(
                &mut self.machine,
                self.image,
                start,
                &options,
                stack,
                pointer,
            ) {
                return Err(cause.to_string());
            }
        }
        // Stream objects are opaque tokens; only the standard streams are modeled.
        let pointer = crate::arch::pointer_bytes(self.image.isa);
        for (index, name) in ["stdin", "stdout", "stderr"].iter().enumerate() {
            let imports: Vec<u64> = self
                .image
                .imports
                .iter()
                .filter(|(_, symbol)| {
                    symbol.trim_start_matches('_').split('@').next() == Some(name)
                })
                .map(|(&slot, _)| slot)
                .collect();
            let objects: Vec<u64> = self
                .image
                .data_symbols
                .iter()
                .filter(|(_, symbol)| symbol.trim_start_matches('_') == *name)
                .map(|(&slot, _)| slot)
                .collect();
            if imports.is_empty() && objects.is_empty() {
                continue;
            }
            let token = self.allocate(1);
            if token == 0 {
                return Err("standard stream allocation failed".into());
            }
            if !imports.is_empty() {
                let object = self.allocate(u64::from(pointer));
                if object == 0 {
                    return Err("standard stream allocation failed".into());
                }
                self.machine.store(object, token, pointer);
                for slot in imports {
                    // Import relocation initializes read-only slots before execution.
                    if let Err(stop) = self.range(slot, u64::from(pointer), /* write */ false) {
                        return Err(format!("standard stream import: {stop:?}"));
                    }
                    for (offset, byte) in
                        object.to_le_bytes()[..pointer as usize].iter().enumerate()
                    {
                        self.machine.memory.insert(slot + offset as u64, *byte);
                    }
                }
            }
            for slot in objects {
                self.machine.store(slot, token, pointer);
            }
            if let Err(stop) = self.memory_error() {
                return Err(format!("standard stream setup: {stop:?}"));
            }
            self.streams[index] = token;
        }
        Ok(())
    }

    fn stream(&self, value: u64, input: bool) -> Result<usize, Stop> {
        if input && value != 0 && value == self.streams[0] {
            return Ok(0);
        }
        if !input {
            for index in 1..=2 {
                if value != 0 && value == self.streams[index] {
                    return Ok(index);
                }
            }
        }
        Err(error(format!(
            "unsupported standard stream pointer 0x{value:x}"
        )))
    }

    fn emit(&mut self, stream: usize, bytes: &[u8]) -> Result<(), Stop> {
        let output = if stream == 1 {
            &mut self.stdout
        } else {
            &mut self.stderr
        };
        if output.len().saturating_add(bytes.len()) > HEAP_SIZE as usize {
            return Err(error("captured output exceeds 16 MiB"));
        }
        output.extend_from_slice(bytes);
        Ok(())
    }

    fn bytes_at(&mut self, base: u64, length: Option<usize>) -> Result<Vec<u8>, Stop> {
        if length.is_some_and(|length| length > HEAP_SIZE as usize) {
            return Err(error("memory read exceeds 16 MiB"));
        }
        let mut bytes = Vec::new();
        for offset in 0..length.unwrap_or(HEAP_SIZE as usize) {
            // Invalid memory aborts this whole operation.
            let location = address(base, offset)?;
            let byte = self.read_byte(location)?;
            if length.is_none() && byte == 0 {
                return Ok(bytes);
            }
            bytes.push(byte);
        }
        if length.is_none() {
            return Err(error("string has no terminating NUL within 16 MiB"));
        }
        Ok(bytes)
    }

    fn store_bytes(&mut self, base: u64, bytes: &[u8]) -> Result<(), Stop> {
        // A failed range check or write aborts the whole hook.
        self.range(base, bytes.len() as u64, /* write */ true)?;
        for (offset, &byte) in bytes.iter().enumerate() {
            self.write_byte(address(base, offset)?, byte)?;
        }
        Ok(())
    }

    // Each failed argument, format or memory operation stops the whole hook.
    pub(super) fn io_hook(
        &mut self,
        operation: Operation,
        convention: Convention,
        kind: CallKind,
    ) -> Result<u64, Stop> {
        use Operation::*;
        if self.recovery.is_some() {
            return Err(error("I/O calls require explicit emulation"));
        }
        let (operation, variadic) = match operation {
            Vprintf => (Printf, true),
            Vfprintf => (Fprintf, true),
            Vsprintf => (Sprintf, true),
            Vsnprintf => (Snprintf, true),
            Vscanf => (Scanf, true),
            Vfscanf => (Fscanf, true),
            Vsscanf => (Sscanf, true),
            operation => (operation, false),
        };
        let mut args = Arguments::new(convention, kind);
        if !variadic
            && self.image.isa == Isa::AArch64
            && self.image.format == crate::loader::Format::MachO
            && matches!(
                operation,
                Printf | Fprintf | Sprintf | Snprintf | Scanf | Fscanf | Sscanf
            )
        {
            return Err(error(
                "variadic I/O hooks require the ELF AArch64 calling convention",
            ));
        }
        let pointer = crate::arch::pointer_bytes(self.image.isa);
        if matches!(operation, Getchar) {
            if let Some(&byte) = self.input.get(self.input_position) {
                self.input_position += 1;
                return Ok(u64::from(byte));
            }
            return Ok(u64::from(u32::MAX));
        }
        let first = args.next(self, pointer)?;
        match operation {
            Printf | Fprintf | Sprintf | Snprintf => {
                let mut capacity = None;
                let mut stream = 1;
                let format = match operation {
                    Printf => first,
                    Fprintf => {
                        stream = self.stream(first, /* input */ false)?;
                        args.next(self, pointer)?
                    }
                    Sprintf => args.next(self, pointer)?,
                    Snprintf => {
                        capacity = Some(args.next(self, pointer)?);
                        args.next(self, pointer)?
                    }
                    _ => unreachable!(),
                };
                if variadic {
                    let list = args.next(self, pointer)?;
                    args.set_list(self, list)?;
                }
                let format = self.bytes_at(format, None)?;
                let bytes = self.format_output(&format, &mut args)?;
                if matches!(operation, Sprintf | Snprintf) {
                    let size = capacity.unwrap_or(bytes.len() as u64 + 1);
                    if size != 0 {
                        let count = bytes.len().min((size - 1).min(HEAP_SIZE) as usize);
                        self.store_bytes(first, &bytes[..count])?;
                        self.store_bytes(address(first, count)?, &[0])?;
                    }
                } else {
                    self.emit(stream, &bytes)?;
                }
                Ok(bytes.len() as u64)
            }
            Puts | Fputs | Putchar => {
                let mut bytes = if matches!(operation, Putchar) {
                    vec![first as u8]
                } else {
                    self.bytes_at(first, None)?
                };
                let stream = if matches!(operation, Fputs) {
                    self.stream(args.next(self, pointer)?, /* input */ false)?
                } else {
                    1
                };
                if matches!(operation, Puts) {
                    bytes.push(b'\n');
                }
                self.emit(stream, &bytes)?;
                Ok(if matches!(operation, Putchar) {
                    u64::from(first as u8)
                } else {
                    0
                })
            }
            Write | Fwrite => {
                let (base, count, result, stream) = if matches!(operation, Write) {
                    let fd = first as u32 as i32;
                    if !matches!(fd, 1 | 2) {
                        return Err(error(format!("unsupported write fd {fd}")));
                    }
                    let base = args.next(self, pointer)?;
                    let count = args.next(self, pointer)?;
                    (base, count, count, fd as usize)
                } else {
                    let size = args.next(self, pointer)?;
                    let count = args.next(self, pointer)?;
                    let stream = self.stream(args.next(self, pointer)?, /* input */ false)?;
                    let Some(total) = size.checked_mul(count) else {
                        return Err(error("fwrite size overflows"));
                    };
                    (first, total, if size == 0 { 0 } else { count }, stream)
                };
                self.range(base, count, /* write */ false)?;
                let bytes = self.bytes_at(base, Some(count as usize))?;
                self.emit(stream, &bytes)?;
                Ok(result)
            }
            Read | Fread | Fgets | Gets => {
                let (base, limit, size) = match operation {
                    Read => {
                        let fd = first as u32 as i32;
                        if fd != 0 {
                            return Err(error(format!("unsupported read fd {fd}")));
                        }
                        (args.next(self, pointer)?, args.next(self, pointer)?, 1)
                    }
                    Fread => {
                        let size = args.next(self, pointer)?;
                        let count = args.next(self, pointer)?;
                        self.stream(args.next(self, pointer)?, /* input */ true)?;
                        let Some(total) = size.checked_mul(count) else {
                            return Err(error("fread size overflows"));
                        };
                        (first, total, size)
                    }
                    Fgets => {
                        let limit = args.next(self, 4)? as u32 as i32;
                        self.stream(args.next(self, pointer)?, /* input */ true)?;
                        if limit <= 0 {
                            return Ok(0);
                        }
                        if limit == 1 {
                            self.store_bytes(first, &[0])?;
                            return Ok(first);
                        }
                        (first, (limit - 1) as u64, 1)
                    }
                    Gets => (first, HEAP_SIZE, 1),
                    _ => unreachable!(),
                };
                if limit > HEAP_SIZE {
                    return Err(error("input operation exceeds 16 MiB"));
                }
                if limit == 0 {
                    return Ok(0);
                }
                let line = matches!(operation, Fgets | Gets);
                let input_start = self.input_position;
                let mut bytes = Vec::new();
                while bytes.len() < limit as usize {
                    let Some(&byte) = self.input.get(self.input_position) else {
                        break;
                    };
                    self.tick()?;
                    self.input_position += 1;
                    if byte == b'\n' && matches!(operation, Gets) {
                        break;
                    }
                    bytes.push(byte);
                    if line && byte == b'\n' {
                        break;
                    }
                }
                if line && bytes.is_empty() && self.input_position == input_start {
                    return Ok(0);
                }
                let count = bytes.len();
                if line {
                    bytes.push(0);
                }
                self.store_bytes(base, &bytes)?;
                Ok(if line {
                    base
                } else {
                    (count as u64).checked_div(size).unwrap_or(0)
                })
            }
            Scanf | Fscanf | Sscanf => {
                let format = if matches!(operation, Scanf) {
                    first
                } else {
                    args.next(self, pointer)?
                };
                if matches!(operation, Fscanf) {
                    self.stream(first, /* input */ true)?;
                }
                if variadic {
                    let list = args.next(self, pointer)?;
                    args.set_list(self, list)?;
                }
                let format = self.bytes_at(format, None)?;
                let input = if matches!(operation, Sscanf) {
                    self.bytes_at(first, None)?
                } else {
                    self.input[self.input_position..].to_vec()
                };
                let (result, consumed) = self.scan_input(&format, &input, &mut args)?;
                if !matches!(operation, Sscanf) {
                    self.input_position += consumed;
                }
                Ok(result)
            }
            Getchar | Vprintf | Vfprintf | Vsprintf | Vsnprintf | Vscanf | Vfscanf | Vsscanf => {
                unreachable!()
            }
        }
    }
}

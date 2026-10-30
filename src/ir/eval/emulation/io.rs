//! Bounded standard stream input and output.

mod arguments;
mod files;
mod formatting;
mod scanning;
mod ucrt;

use arguments::Arguments;

use crate::ir::{CallKind, Convention};
use crate::loader::Isa;

use super::{HEAP_SIZE, Runner, Stop};

#[derive(Clone, Copy)]
pub(crate) enum Operation {
    Open,
    Close,
    Fopen,
    Fclose,
    Fflush,
    Setvbuf,
    Setbuf,
    Fileno,
    Feof,
    Ferror,
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

pub(crate) fn next_input<T: Clone>(input: &[T], position: &mut usize) -> Option<T> {
    let byte = input.get(*position).cloned();
    if byte.is_some() {
        *position += 1;
    }
    byte
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
                let terminated_bytes = text.bytes().chain([0]).enumerate();
                for (offset, byte) in terminated_bytes {
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
        if let Err(stop) = self.initialize_cxx() {
            return Err(format!("C++ stream setup: {stop:?}"));
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
                .filter(|(_, symbol)| {
                    symbol.trim_start_matches('_').split('@').next() == Some(name)
                })
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
                    if let Err(stop) =
                        self.check_memory_range(slot, u64::from(pointer), /* write */ false)
                    {
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

    pub(super) fn emit(&mut self, stream: usize, bytes: &[u8]) -> Result<(), Stop> {
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

    pub(super) fn bytes_at(&mut self, base: u64, length: Option<usize>) -> Result<Vec<u8>, Stop> {
        if length.is_some_and(|length| length > HEAP_SIZE as usize) {
            return Err(error("memory read exceeds 16 MiB"));
        }
        let mut bytes = Vec::new();
        for offset in 0..length.unwrap_or(HEAP_SIZE as usize) {
            // Invalid memory aborts this whole operation.
            let location = match address(base, offset) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            let byte = match self.read_byte(location) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
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

    pub(super) fn store_bytes(&mut self, base: u64, bytes: &[u8]) -> Result<(), Stop> {
        // A failed range check or write aborts the whole hook.
        if let Err(error) = self.check_memory_range(base, bytes.len() as u64, /* write */ true) {
            return Err(error);
        }
        for (offset, &byte) in bytes.iter().enumerate() {
            let field_address = match address(base, offset) {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            if let Err(error) = self.write_byte(field_address, byte) {
                return Err(error);
            }
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
        let handled = match self.file_hook(operation, convention, kind) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        if let Some(result) = handled {
            return Ok(result);
        }
        let (operation, uses_va_list) = match operation {
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
        if kind == CallKind::Syscall {
            args.index = 1;
        }
        if !uses_va_list
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
        let pointer_bytes = crate::arch::pointer_bytes(self.image.isa);
        if matches!(operation, Getchar) {
            if let Some(byte) = next_input(&self.input, &mut self.input_position) {
                return Ok(u64::from(byte));
            }
            return Ok(u64::from(u32::MAX));
        }
        let first = match args.next(self, pointer_bytes) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        match operation {
            Printf | Fprintf | Sprintf | Snprintf => {
                let mut capacity = None;
                let mut stream = 1;
                let format = match operation {
                    Printf => first,
                    Fprintf => {
                        stream = match self.stream(first, /* input */ false) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        };
                        match args.next(self, pointer_bytes) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        }
                    }
                    Sprintf => match args.next(self, pointer_bytes) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    },
                    Snprintf => {
                        let value = match args.next(self, pointer_bytes) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        };
                        capacity = Some(value);
                        match args.next(self, pointer_bytes) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        }
                    }
                    _ => unreachable!(),
                };
                if uses_va_list {
                    let list = match args.next(self, pointer_bytes) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    if let Err(error) = args.set_list(self, list) {
                        return Err(error);
                    }
                }
                let format = match self.bytes_at(format, None) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let bytes = match self.format_output(&format, &mut args) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if matches!(operation, Sprintf | Snprintf) {
                    let size = capacity.unwrap_or(bytes.len() as u64 + 1);
                    if size != 0 {
                        let count = bytes.len().min((size - 1).min(HEAP_SIZE) as usize);
                        if let Err(error) = self.store_bytes(first, &bytes[..count]) {
                            return Err(error);
                        }
                        let end_address = match address(first, count) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        };
                        if let Err(error) = self.store_bytes(end_address, &[0]) {
                            return Err(error);
                        }
                    }
                } else {
                    if let Err(error) = self.windows_crt_write(stream, &bytes) {
                        return Err(error);
                    }
                }
                Ok(bytes.len() as u64)
            }
            Puts | Fputs | Putchar => {
                let mut bytes = if matches!(operation, Putchar) {
                    vec![first as u8]
                } else {
                    match self.bytes_at(first, None) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    }
                };
                let stream = if matches!(operation, Fputs) {
                    let argument = match args.next(self, pointer_bytes) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    match self.stream(argument, /* input */ false) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    }
                } else {
                    1
                };
                if matches!(operation, Puts) {
                    bytes.push(b'\n');
                }
                if let Err(error) = self.windows_crt_write(stream, &bytes) {
                    return Err(error);
                }
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
                    let base = match args.next(self, pointer_bytes) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    let count = match args.next(self, pointer_bytes) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    (base, count, count, fd as usize)
                } else {
                    let size = match args.next(self, pointer_bytes) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    let count = match args.next(self, pointer_bytes) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    let argument = match args.next(self, pointer_bytes) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    let stream = match self.stream(argument, /* input */ false) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    let Some(total) = size.checked_mul(count) else {
                        return Err(error("fwrite size overflows"));
                    };
                    (first, total, if size == 0 { 0 } else { count }, stream)
                };
                if let Err(error) = self.check_memory_range(base, count, /* write */ false) {
                    return Err(error);
                }
                let bytes = match self.bytes_at(base, Some(count as usize)) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if matches!(operation, Fwrite) {
                    if let Err(error) = self.windows_crt_write(stream, &bytes) {
                        return Err(error);
                    }
                } else {
                    if let Err(error) = self.emit(stream, &bytes) {
                        return Err(error);
                    }
                }
                Ok(result)
            }
            Read | Fread | Fgets | Gets => {
                let (base, limit, size) = match operation {
                    Read => {
                        let fd = first as u32 as i32;
                        if fd != 0 && !self.options.stdin_descriptors.contains(&(fd as u32)) {
                            return Err(error(format!("unsupported read fd {fd}")));
                        }
                        let argument = match args.next(self, pointer_bytes) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        };
                        let pointer_bytes_argument = match args.next(self, pointer_bytes) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        };
                        (argument, pointer_bytes_argument, 1)
                    }
                    Fread => {
                        let size = match args.next(self, pointer_bytes) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        };
                        let count = match args.next(self, pointer_bytes) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        };
                        let argument = match args.next(self, pointer_bytes) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        };
                        if let Err(error) = self.stream(argument, /* input */ true) {
                            return Err(error);
                        }
                        let Some(total) = size.checked_mul(count) else {
                            return Err(error("fread size overflows"));
                        };
                        (first, total, size)
                    }
                    Fgets => {
                        let argument = match args.next(self, 4) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        };
                        let limit = argument as u32 as i32;
                        let argument = match args.next(self, pointer_bytes) {
                            Ok(value) => value,
                            Err(error) => return Err(error),
                        };
                        if let Err(error) = self.stream(argument, /* input */ true) {
                            return Err(error);
                        }
                        if limit <= 0 {
                            return Ok(0);
                        }
                        if limit == 1 {
                            if let Err(error) = self.store_bytes(first, &[0]) {
                                return Err(error);
                            }
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
                    if let Err(error) = self.tick() {
                        return Err(error);
                    }
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
                if let Err(error) = self.store_bytes(base, &bytes) {
                    return Err(error);
                }
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
                    match args.next(self, pointer_bytes) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    }
                };
                if matches!(operation, Fscanf)
                    && let Err(error) = self.stream(first, /* input */ true)
                {
                    return Err(error);
                }
                if uses_va_list {
                    let list = match args.next(self, pointer_bytes) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    };
                    if let Err(error) = args.set_list(self, list) {
                        return Err(error);
                    }
                }
                let format = match self.bytes_at(format, None) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let input = if matches!(operation, Sscanf) {
                    match self.bytes_at(first, None) {
                        Ok(value) => value,
                        Err(error) => return Err(error),
                    }
                } else {
                    self.input[self.input_position..].to_vec()
                };
                let (result, consumed) = match self.scan_input(&format, &input, &mut args) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                if !matches!(operation, Sscanf) {
                    self.input_position += consumed;
                }
                Ok(result)
            }
            Open | Close | Fopen | Fclose | Fflush | Setvbuf | Setbuf | Fileno | Feof | Ferror => {
                unreachable!()
            }
            Getchar | Vprintf | Vfprintf | Vsprintf | Vsnprintf | Vscanf | Vfscanf | Vsscanf => {
                unreachable!()
            }
        }
    }
}

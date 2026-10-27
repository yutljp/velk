//! Common C library calls, selected by imported symbol name.

use super::{CallKind, Convention, HEAP_SIZE, Runner, Stop};

#[derive(Clone, Copy)]
pub(super) enum Hook {
    Copy,
    Move,
    Set,
    Length,
    Compare,
    CompareN,
    StringCopy,
    Allocate,
    AllocateZero,
    Free,
    Io(super::io::Operation),
}

const HOOKS: &[(&str, Hook)] = &[
    ("printf", Hook::Io(super::io::Operation::Printf)),
    ("fprintf", Hook::Io(super::io::Operation::Fprintf)),
    ("sprintf", Hook::Io(super::io::Operation::Sprintf)),
    ("snprintf", Hook::Io(super::io::Operation::Snprintf)),
    ("puts", Hook::Io(super::io::Operation::Puts)),
    ("putchar", Hook::Io(super::io::Operation::Putchar)),
    ("fputs", Hook::Io(super::io::Operation::Fputs)),
    ("fwrite", Hook::Io(super::io::Operation::Fwrite)),
    ("write", Hook::Io(super::io::Operation::Write)),
    ("read", Hook::Io(super::io::Operation::Read)),
    ("fread", Hook::Io(super::io::Operation::Fread)),
    ("fgets", Hook::Io(super::io::Operation::Fgets)),
    ("gets", Hook::Io(super::io::Operation::Gets)),
    ("getchar", Hook::Io(super::io::Operation::Getchar)),
    ("scanf", Hook::Io(super::io::Operation::Scanf)),
    ("fscanf", Hook::Io(super::io::Operation::Fscanf)),
    ("sscanf", Hook::Io(super::io::Operation::Sscanf)),
    ("__isoc99_scanf", Hook::Io(super::io::Operation::Scanf)),
    ("__isoc99_fscanf", Hook::Io(super::io::Operation::Fscanf)),
    ("__isoc99_sscanf", Hook::Io(super::io::Operation::Sscanf)),
    ("vprintf", Hook::Io(super::io::Operation::Vprintf)),
    ("vfprintf", Hook::Io(super::io::Operation::Vfprintf)),
    ("vsprintf", Hook::Io(super::io::Operation::Vsprintf)),
    ("vsnprintf", Hook::Io(super::io::Operation::Vsnprintf)),
    ("vscanf", Hook::Io(super::io::Operation::Vscanf)),
    ("vfscanf", Hook::Io(super::io::Operation::Vfscanf)),
    ("vsscanf", Hook::Io(super::io::Operation::Vsscanf)),
    ("__isoc99_vscanf", Hook::Io(super::io::Operation::Vscanf)),
    ("__isoc99_vfscanf", Hook::Io(super::io::Operation::Vfscanf)),
    ("__isoc99_vsscanf", Hook::Io(super::io::Operation::Vsscanf)),
    ("memcpy", Hook::Copy),
    ("memmove", Hook::Move),
    ("memset", Hook::Set),
    ("strlen", Hook::Length),
    ("strcmp", Hook::Compare),
    ("strncmp", Hook::CompareN),
    ("strcpy", Hook::StringCopy),
    ("malloc", Hook::Allocate),
    ("calloc", Hook::AllocateZero),
    ("free", Hook::Free),
];

pub(super) fn find(name: &str) -> Option<Hook> {
    let name = if name.starts_with("__isoc99_") {
        name
    } else {
        name.strip_prefix('_').unwrap_or(name)
    };
    let name = name.split('@').next().unwrap_or(name);
    HOOKS
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, hook)| *hook)
}

impl Runner<'_> {
    pub(super) fn argument(
        &self,
        index: usize,
        convention: Convention,
        kind: CallKind,
    ) -> std::result::Result<u64, Stop> {
        if let Some(&register) = convention.arguments().get(index) {
            return self.eval(&crate::ir::Expr::reg(
                register,
                crate::arch::pointer_bytes(self.image.isa) * 8,
            ));
        }
        let Some(base) = convention.stack_arguments() else {
            return Err(Stop::Error(
                "hook convention has no stack arguments".to_owned(),
            ));
        };
        let Some(offset) = kind.stack_offset(self.image.isa, convention, base) else {
            return Err(Stop::Error(
                "hook stack argument offset is invalid".to_owned(),
            ));
        };
        let sp = match self.eval(&crate::ir::Expr::reg(
            crate::arch::stack_pointer(self.image.isa),
            crate::arch::pointer_bytes(self.image.isa) * 8,
        )) {
            Ok(value) => value,
            Err(stop) => return Err(stop),
        };
        let width = crate::arch::pointer_bytes(self.image.isa);
        let position = (index - convention.arguments().len()) as u64;
        let address = super::stack_argument_address(sp.checked_add_signed(offset), position, width);
        let Some(address) = address else {
            return Err(Stop::Error("hook argument address overflows".to_owned()));
        };
        if self.recovery.is_some() {
            return match self.recovery_load(address, width, false) {
                Ok(fact) => fact
                    .singleton()
                    .ok_or_else(|| Stop::Error("undefined stack argument".to_owned())),
                Err(stop) => Err(stop),
            };
        }
        let value = self.machine.load(address, width);
        match self.memory_error() {
            Ok(()) => Ok(value),
            Err(stop) => Err(stop),
        }
    }

    pub(super) fn read_byte(&mut self, address: u64) -> std::result::Result<u8, Stop> {
        if let Err(stop) = self.tick() {
            return Err(stop);
        }
        if self.recovery.is_some() {
            return match self.recovery_load(address, 1, false) {
                Ok(fact) => fact
                    .singleton()
                    .map(|v| v as u8)
                    .ok_or_else(|| Stop::Error("undefined input byte".to_owned())),
                Err(stop) => Err(stop),
            };
        }
        let value = self.machine.load(address, 1) as u8;
        match self.memory_error() {
            Ok(()) => Ok(value),
            Err(stop) => Err(stop),
        }
    }

    pub(super) fn write_byte(&mut self, address: u64, value: u8) -> std::result::Result<(), Stop> {
        if let Err(stop) = self.tick() {
            return Err(stop);
        }
        if self.recovery.is_some() {
            return self.recovery_store(
                address,
                1,
                crate::ssa::ranges::Fact::constant(u64::from(value)),
                0,
            );
        }
        self.machine.store(address, u64::from(value), 1);
        self.memory_error()
    }

    pub(super) fn range(
        &self,
        address: u64,
        size: u64,
        write: bool,
    ) -> std::result::Result<(), Stop> {
        if size > HEAP_SIZE {
            return Err(Stop::Error(format!(
                "hook memory operation at 0x{address:x} exceeds 16 MiB"
            )));
        }
        self.machine
            .strict
            .as_ref()
            .expect("strict memory")
            .check(address, size, write);
        self.memory_error()
    }

    pub(super) fn allocate(&mut self, size: u64) -> u64 {
        let Some(start) = self.heap_next.checked_add(15).map(|value| value & !15) else {
            return 0;
        };
        let Some(end) = start.checked_add(size.max(1)) else {
            return 0;
        };
        if end > self.heap_base + HEAP_SIZE {
            return 0;
        }
        self.heap_next = end;
        self.allocations.insert(start);
        start
    }

    fn copy_memory(
        &mut self,
        hook: Hook,
        first: u64,
        source: u64,
        size: u64,
    ) -> std::result::Result<u64, Stop> {
        match self.range(source, size, /* write */ false) {
            Ok(value) => value,
            Err(stop) => return Err(stop),
        };
        match self.range(first, size, /* write */ true) {
            Ok(value) => value,
            Err(stop) => return Err(stop),
        };
        if matches!(hook, Hook::Copy) && size != 0 && first < source + size && source < first + size
        {
            return Err(Stop::Error(format!(
                "memcpy ranges overlap at destination 0x{first:x} and source 0x{source:x}; use memmove"
            )));
        }
        let mut bytes = Vec::new();
        for offset in 0..size {
            bytes.push(match self.read_byte(source + offset) {
                Ok(value) => value,
                Err(stop) => return Err(stop),
            });
        }
        for (offset, byte) in bytes.into_iter().enumerate() {
            match self.write_byte(first + offset as u64, byte) {
                Ok(value) => value,
                Err(stop) => return Err(stop),
            };
        }
        Ok(first)
    }

    pub(super) fn hook(
        &mut self,
        hook: Hook,
        convention: Convention,
        kind: CallKind,
    ) -> std::result::Result<u64, Stop> {
        if let Hook::Io(operation) = hook {
            return self.io_hook(operation, convention, kind);
        }
        // An invalid argument or memory access aborts the hook and the run.
        let first = match self.argument(0, convention, kind) {
            Ok(value) => value,
            Err(stop) => return Err(stop),
        };
        let value = match hook {
            Hook::Io(_) => unreachable!("I/O hooks return above"),
            Hook::Allocate => self.allocate(first),
            Hook::AllocateZero => {
                let count = match self.argument(1, convention, kind) {
                    Ok(value) => value,
                    Err(stop) => return Err(stop),
                };
                let Some(size) = first.checked_mul(count) else {
                    return Ok(0);
                };
                let address = self.allocate(size);
                if address != 0 {
                    for offset in 0..size {
                        if let Err(stop) = self.write_byte(address + offset, 0) {
                            return Err(stop);
                        }
                    }
                }
                address
            }
            Hook::Free => {
                if first != 0 && !self.allocations.remove(&first) {
                    return Err(Stop::Error(format!(
                        "free of unallocated pointer 0x{first:x}"
                    )));
                }
                0
            }
            Hook::Set => {
                let byte = match self.argument(1, convention, kind) {
                    Ok(value) => value,
                    Err(stop) => return Err(stop),
                } as u8;
                let size = match self.argument(2, convention, kind) {
                    Ok(value) => value,
                    Err(stop) => return Err(stop),
                };
                match self.range(first, size, /* write */ true) {
                    Ok(value) => value,
                    Err(stop) => return Err(stop),
                };
                for offset in 0..size {
                    match self.write_byte(first + offset, byte) {
                        Ok(value) => value,
                        Err(stop) => return Err(stop),
                    };
                }
                first
            }
            Hook::Copy | Hook::Move => {
                let source = match self.argument(1, convention, kind) {
                    Ok(value) => value,
                    Err(stop) => return Err(stop),
                };
                let size = match self.argument(2, convention, kind) {
                    Ok(value) => value,
                    Err(stop) => return Err(stop),
                };
                match self.copy_memory(hook, first, source, size) {
                    Ok(value) => value,
                    Err(stop) => return Err(stop),
                }
            }
            Hook::Length | Hook::StringCopy => {
                let source = if matches!(hook, Hook::StringCopy) {
                    match self.argument(1, convention, kind) {
                        Ok(value) => value,
                        Err(stop) => return Err(stop),
                    }
                } else {
                    first
                };
                let mut size = 0u64;
                loop {
                    let Some(address) = source.checked_add(size) else {
                        return Err(Stop::Error("string address overflows".to_owned()));
                    };
                    let byte = match self.read_byte(address) {
                        Ok(value) => value,
                        Err(stop) => return Err(stop),
                    };
                    if matches!(hook, Hook::StringCopy) {
                        let Some(address) = first.checked_add(size) else {
                            return Err(Stop::Error("string destination overflows".to_owned()));
                        };
                        match self.write_byte(address, byte) {
                            Ok(value) => value,
                            Err(stop) => return Err(stop),
                        };
                    }
                    if byte == 0 {
                        break;
                    }
                    size = size.saturating_add(1);
                }
                if matches!(hook, Hook::StringCopy) {
                    first
                } else {
                    size
                }
            }
            Hook::Compare | Hook::CompareN => {
                let second = match self.argument(1, convention, kind) {
                    Ok(value) => value,
                    Err(stop) => return Err(stop),
                };
                let limit = if matches!(hook, Hook::CompareN) {
                    match self.argument(2, convention, kind) {
                        Ok(value) => value,
                        Err(stop) => return Err(stop),
                    }
                } else {
                    u64::MAX
                };
                let mut result = 0;
                for offset in 0..limit {
                    let (Some(left), Some(right)) =
                        (first.checked_add(offset), second.checked_add(offset))
                    else {
                        return Err(Stop::Error("string address overflows".to_owned()));
                    };
                    let left = match self.read_byte(left) {
                        Ok(value) => value,
                        Err(stop) => return Err(stop),
                    };
                    let right = match self.read_byte(right) {
                        Ok(value) => value,
                        Err(stop) => return Err(stop),
                    };
                    if left != right {
                        result = u64::from((i32::from(left) - i32::from(right)) as u32);
                        break;
                    }
                    if left == 0 {
                        break;
                    }
                }
                result
            }
        };
        let value = if crate::arch::pointer_bytes(self.image.isa) == 4 {
            value & 0xffff_ffff
        } else {
            value
        };
        self.machine.registers.insert(crate::arch::RETURN, value);
        Ok(value)
    }
}

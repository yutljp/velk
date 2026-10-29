//! Common C library calls, selected by imported symbol name.

use super::{CallKind, Convention, HEAP_SIZE, Runner, Stop};

#[derive(Clone, Copy)]
pub(crate) enum Hook {
    Unsupported(&'static str),
    Random,
    Seed,
    Time,
    ClockGettime,
    Gettimeofday,
    ParentProcess,
    Debugger,
    RemoteDebugger,
    Ptrace,
    GetTickCount,
    GetTickCount64,
    QueryPerformanceCounter,
    Dumpable,
    GetEnv,
    SystemCall,
    Signal,
    Alarm,
    Exit,
    StackCheckFail,
    Copy,
    Move,
    Set,
    Length,
    LengthN,
    Getline,
    MemoryCompare,
    StringCopyN,
    Character,
    Integer,
    IntegerEnd,
    Upper,
    Lower,
    Compare,
    CompareN,
    StringCopy,
    Allocate,
    AllocateZero,
    Free,
    Io(super::io::Operation),
}

const HOOKS: &[(&str, Hook)] = &[
    (
        "socket",
        Hook::Unsupported(
            "socket: network connections are not modeled; provide callReturns and stdinDescriptors for an explicit input descriptor",
        ),
    ),
    ("prctl", Hook::Dumpable),
    ("open", Hook::Io(super::io::Operation::Open)),
    ("close", Hook::Io(super::io::Operation::Close)),
    ("rand", Hook::Random),
    ("srand", Hook::Seed),
    ("time", Hook::Time),
    ("clock_gettime", Hook::ClockGettime),
    ("gettimeofday", Hook::Gettimeofday),
    ("getppid", Hook::ParentProcess),
    ("IsDebuggerPresent", Hook::Debugger),
    ("CheckRemoteDebuggerPresent", Hook::RemoteDebugger),
    ("ptrace", Hook::Ptrace),
    ("GetTickCount", Hook::GetTickCount),
    ("GetTickCount64", Hook::GetTickCount64),
    ("QueryPerformanceCounter", Hook::QueryPerformanceCounter),
    ("getenv", Hook::GetEnv),
    ("syscall", Hook::SystemCall),
    ("signal", Hook::Signal),
    ("__sysv_signal", Hook::Signal),
    ("alarm", Hook::Alarm),
    ("exit", Hook::Exit),
    ("setbuf", Hook::Io(super::io::Operation::Setbuf)),
    ("fopen", Hook::Io(super::io::Operation::Fopen)),
    ("fclose", Hook::Io(super::io::Operation::Fclose)),
    ("fflush", Hook::Io(super::io::Operation::Fflush)),
    ("setvbuf", Hook::Io(super::io::Operation::Setvbuf)),
    ("fileno", Hook::Io(super::io::Operation::Fileno)),
    ("feof", Hook::Io(super::io::Operation::Feof)),
    ("ferror", Hook::Io(super::io::Operation::Ferror)),
    ("__stack_chk_fail", Hook::StackCheckFail),
    ("__stack_chk_fail_local", Hook::StackCheckFail),
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
    ("strnlen", Hook::LengthN),
    ("getline", Hook::Getline),
    ("memcmp", Hook::MemoryCompare),
    ("strncpy", Hook::StringCopyN),
    ("strchr", Hook::Character),
    ("atoi", Hook::Integer),
    ("strtol", Hook::IntegerEnd),
    ("toupper", Hook::Upper),
    ("tolower", Hook::Lower),
    ("strcmp", Hook::Compare),
    ("strncmp", Hook::CompareN),
    ("strcpy", Hook::StringCopy),
    ("malloc", Hook::Allocate),
    ("calloc", Hook::AllocateZero),
    ("free", Hook::Free),
];

pub(crate) fn find(name: &str) -> Option<Hook> {
    if name.split('@').next() == Some("_exit") {
        return None;
    }
    let name = if name.starts_with("__isoc99_")
        || name.starts_with("__stack_chk_")
        || name.starts_with("__sysv_")
    {
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

pub(crate) fn has_exit_handlers(image: &crate::loader::Image) -> bool {
    let registration = |name: &str| {
        let name = name
            .split('@')
            .next()
            .unwrap_or(name)
            .trim_start_matches('_');
        matches!(
            name,
            "atexit" | "cxa_atexit" | "cxa_thread_atexit_impl" | "on_exit"
        )
    };
    image.imports.values().any(|name| registration(name))
        || image.functions.values().any(|function| {
            function.name.as_deref().is_some_and(registration)
                || function.aliases.iter().any(|name| registration(name))
        })
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

    pub(super) fn check_memory_range(
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
            .strict_memory
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
        match self.check_memory_range(source, size, /* write */ false) {
            Ok(value) => value,
            Err(stop) => return Err(stop),
        };
        match self.check_memory_range(first, size, /* write */ true) {
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
        if let Hook::Unsupported(message) = hook {
            return Err(Stop::Error(message.to_owned()));
        }
        if self.recovery.is_some()
            && matches!(
                hook,
                Hook::Random | Hook::Seed | Hook::Time | Hook::Signal | Hook::Alarm | Hook::Exit
            )
        {
            return Err(Stop::Error(
                "runtime state requires explicit emulation".to_owned(),
            ));
        }
        if let Hook::StackCheckFail = hook {
            return Err(Stop::StackCheckFail);
        }
        if let Hook::Io(operation) = hook {
            return self.io_hook(operation, convention, kind);
        }
        if matches!(hook, Hook::Exit) {
            if has_exit_handlers(self.image) {
                return Err(Stop::Error("exit handlers are unsupported".to_owned()));
            }
            if let Err(error) = self.files.flush(0) {
                return Err(Stop::Error(error));
            }
            return Err(Stop::Exit);
        }
        if matches!(hook, Hook::Random) {
            return Ok(u64::from(self.random.next()));
        }
        // An invalid argument or memory access aborts the hook and the run.
        let first = match self.argument(0, convention, kind) {
            Ok(value) => value,
            Err(stop) => return Err(stop),
        };
        let value = match hook {
            Hook::Unsupported(_)
            | Hook::StackCheckFail
            | Hook::Io(_)
            | Hook::Random
            | Hook::Exit => {
                unreachable!("these hooks return before the library call match")
            }
            Hook::Signal => {
                if self.image.format != crate::loader::Format::Elf {
                    return Err(Stop::Error("signal model requires Linux ELF".to_owned()));
                }
                let signal = first as u32;
                if !(1..=64).contains(&signal) || matches!(signal, 9 | 19 | 32 | 33) {
                    return Err(Stop::Error(format!("unsupported signal number {signal}")));
                }
                let handler = match self.argument(1, convention, kind) {
                    Ok(handler) => handler,
                    Err(stop) => return Err(stop),
                };
                let mask = crate::ir::semantics::mask(
                    u32::from(crate::arch::pointer_bytes(self.image.isa)) * 8,
                );
                if handler & mask == mask {
                    return Err(Stop::Error("unsupported SIG_ERR handler".to_owned()));
                }
                self.signal_handlers.insert(signal, handler).unwrap_or(0)
            }
            Hook::Alarm => {
                let previous = self.alarm;
                self.alarm = u64::from(first as u32);
                previous
            }
            Hook::Seed => {
                self.random = super::super::random::Random::seeded(first as u32);
                0
            }
            Hook::Time => {
                let value = match &self.options.time {
                    Some(word) => match word.value() {
                        Ok(value) => value,
                        Err(error) => return Err(Stop::Error(error.to_string())),
                    },
                    None => 0,
                };
                let width = crate::arch::pointer_bytes(self.image.isa);
                if first != 0 {
                    if let Err(stop) = self.check_memory_range(first, u64::from(width), true) {
                        return Err(stop);
                    }
                    for (offset, byte) in
                        value.to_le_bytes().iter().take(width as usize).enumerate()
                    {
                        if let Err(stop) = self.write_byte(first + offset as u64, *byte) {
                            return Err(stop);
                        }
                    }
                }
                value & crate::ir::semantics::mask(u32::from(width) * 8)
            }
            Hook::ClockGettime | Hook::Gettimeofday => {
                let pointer_index = if matches!(hook, Hook::ClockGettime) {
                    1
                } else {
                    0
                };
                let pointer = match self.argument(pointer_index, convention, kind) {
                    Ok(pointer) => pointer,
                    Err(stop) => return Err(stop),
                };
                let seconds = match &self.options.time {
                    Some(word) => match word.value() {
                        Ok(value) => value,
                        Err(error) => return Err(Stop::Error(error.to_string())),
                    },
                    None => 0,
                };
                let elapsed = self
                    .instructions
                    .saturating_mul(self.options.anti_analysis.clock_ticks_per_instruction);
                let nanos = elapsed % 1_000_000_000;
                let seconds = seconds.saturating_add(elapsed / 1_000_000_000);
                let width = crate::arch::pointer_bytes(self.image.isa);
                let subsecond = if matches!(hook, Hook::Gettimeofday) {
                    nanos / 1_000
                } else {
                    nanos
                };
                let Some(second_address) = pointer.checked_add(u64::from(width)) else {
                    return Err(Stop::Error("clock output address overflows".to_owned()));
                };
                for (address, value) in [(pointer, seconds), (second_address, subsecond)] {
                    if let Err(stop) = self.check_memory_range(address, u64::from(width), true) {
                        return Err(stop);
                    }
                    for (offset, byte) in
                        value.to_le_bytes().iter().take(width as usize).enumerate()
                    {
                        if let Err(stop) = self.write_byte(address + offset as u64, *byte) {
                            return Err(stop);
                        }
                    }
                }
                self.anti_analysis
                    .push(if matches!(hook, Hook::ClockGettime) {
                        "clock_gettime".to_owned()
                    } else {
                        "gettimeofday".to_owned()
                    });
                0
            }
            Hook::ParentProcess => {
                self.anti_analysis.push("getppid".to_owned());
                u64::from(self.options.anti_analysis.parent_process_id)
            }
            Hook::Debugger => {
                self.anti_analysis.push("debugger presence".to_owned());
                u64::from(self.options.anti_analysis.debugger_present)
            }
            Hook::RemoteDebugger => {
                let pointer = match self.argument(1, convention, kind) {
                    Ok(pointer) => pointer,
                    Err(stop) => return Err(stop),
                };
                let value = u32::from(self.options.anti_analysis.debugger_present);
                for (offset, byte) in value.to_le_bytes().iter().enumerate() {
                    let Some(address) = pointer.checked_add(offset as u64) else {
                        return Err(Stop::Error("debugger result address overflows".to_owned()));
                    };
                    if let Err(stop) = self.write_byte(address, *byte) {
                        return Err(stop);
                    }
                }
                self.anti_analysis
                    .push("CheckRemoteDebuggerPresent".to_owned());
                1
            }
            Hook::GetTickCount => {
                self.anti_analysis.push("GetTickCount".to_owned());
                (self
                    .instructions
                    .saturating_mul(self.options.anti_analysis.clock_ticks_per_instruction)
                    / 1_000_000) as u32 as u64
            }
            Hook::GetTickCount64 => {
                self.anti_analysis.push("GetTickCount64".to_owned());
                self.instructions
                    .saturating_mul(self.options.anti_analysis.clock_ticks_per_instruction)
                    / 1_000_000
            }
            Hook::QueryPerformanceCounter => {
                let pointer = first;
                let value = self
                    .instructions
                    .saturating_mul(self.options.anti_analysis.clock_ticks_per_instruction);
                if let Err(stop) = self.check_memory_range(pointer, 8, true) {
                    return Err(stop);
                }
                for (offset, byte) in value.to_le_bytes().iter().enumerate() {
                    let Some(address) = pointer.checked_add(offset as u64) else {
                        return Err(Stop::Error(
                            "performance counter address overflows".to_owned(),
                        ));
                    };
                    if let Err(stop) = self.write_byte(address, *byte) {
                        return Err(stop);
                    }
                }
                self.anti_analysis
                    .push("QueryPerformanceCounter".to_owned());
                1
            }
            Hook::Ptrace => {
                if first != 0 {
                    return Err(Stop::Error(format!("unsupported ptrace request {first}")));
                }
                self.anti_analysis.push("ptrace(PTRACE_TRACEME)".to_owned());
                if self.ptrace_traceme_count == 0
                    && self.options.anti_analysis.ptrace_traceme_succeeds
                {
                    self.ptrace_traceme_count = 1;
                    0
                } else {
                    u64::MAX
                }
            }
            Hook::Dumpable => {
                let operation = first as u32;
                if operation == 4 {
                    self.anti_analysis.push("prctl(PR_SET_DUMPABLE)".to_owned());
                    if self.options.anti_analysis.dumpable {
                        0
                    } else {
                        u64::MAX
                    }
                } else if self.options.skip_calls {
                    0
                } else {
                    return Err(Stop::Error(format!(
                        "unsupported prctl operation {operation}"
                    )));
                }
            }
            Hook::GetEnv => {
                let name = match self.bytes_at(first, None) {
                    Ok(bytes) => bytes,
                    Err(stop) => return Err(stop),
                };
                if name != b"LD_PRELOAD" {
                    return Ok(0);
                }
                self.anti_analysis.push("getenv(LD_PRELOAD)".to_owned());
                let Some(value) = self.options.anti_analysis.preload.as_deref() else {
                    return Ok(0);
                };
                let pointer = self.allocate(value.len() as u64 + 1);
                if pointer == 0 {
                    return Err(Stop::Error(
                        "environment value allocation failed".to_owned(),
                    ));
                }
                let mut bytes = value.as_bytes().to_vec();
                bytes.push(0);
                match self.store_bytes(pointer, &bytes) {
                    Ok(()) => pointer,
                    Err(stop) => return Err(stop),
                }
            }
            Hook::SystemCall => {
                let number = first;
                let (ptrace_number, parent_number, prctl_number) = match self.image.isa {
                    crate::loader::Isa::X86_64 => (101, 110, 157),
                    crate::loader::Isa::I386 => (26, 64, 172),
                    crate::loader::Isa::AArch64 => (117, 173, 167),
                    _ => return Err(Stop::Error("unsupported syscall architecture".to_owned())),
                };
                if number == ptrace_number {
                    let request = match self.argument(1, convention, kind) {
                        Ok(request) => request,
                        Err(stop) => return Err(stop),
                    };
                    if request != 0 {
                        return Err(Stop::Error(format!("unsupported ptrace request {request}")));
                    }
                    self.anti_analysis.push("ptrace(PTRACE_TRACEME)".to_owned());
                    if self.ptrace_traceme_count == 0
                        && self.options.anti_analysis.ptrace_traceme_succeeds
                    {
                        self.ptrace_traceme_count = 1;
                        0
                    } else {
                        u64::MAX
                    }
                } else if number == parent_number {
                    self.anti_analysis.push("getppid".to_owned());
                    u64::from(self.options.anti_analysis.parent_process_id)
                } else if number == prctl_number {
                    let operation = match self.argument(1, convention, kind) {
                        Ok(operation) => operation as u32,
                        Err(stop) => return Err(stop),
                    };
                    if operation != 4 {
                        return Err(Stop::Error(format!(
                            "unsupported prctl operation {operation}"
                        )));
                    }
                    self.anti_analysis.push("prctl(PR_SET_DUMPABLE)".to_owned());
                    if self.options.anti_analysis.dumpable {
                        0
                    } else {
                        u64::MAX
                    }
                } else {
                    return Err(Stop::Error(format!("unsupported Linux syscall {number}")));
                }
            }
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
                match self.check_memory_range(first, size, /* write */ true) {
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
            Hook::Getline => return self.getline_hook(first, convention, kind),
            Hook::Upper | Hook::Lower => {
                let value = first as u32;
                if matches!(hook, Hook::Upper) && (97..=122).contains(&value) {
                    u64::from(value - 32)
                } else if matches!(hook, Hook::Lower) && (65..=90).contains(&value) {
                    u64::from(value + 32)
                } else {
                    u64::from(value)
                }
            }
            Hook::LengthN
            | Hook::StringCopyN
            | Hook::Character
            | Hook::Integer
            | Hook::IntegerEnd => {
                return self.scalar_string_hook(hook, first, convention, kind);
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
            Hook::Compare | Hook::CompareN | Hook::MemoryCompare => {
                let second = match self.argument(1, convention, kind) {
                    Ok(value) => value,
                    Err(stop) => return Err(stop),
                };
                let limit = if !matches!(hook, Hook::Compare) {
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
                    if left == 0 && !matches!(hook, Hook::MemoryCompare) {
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

impl Runner<'_> {
    // Argument and memory failures abort the call rather than guessing a result.
    fn scalar_string_hook(
        &mut self,
        hook: Hook,
        first: u64,
        convention: Convention,
        kind: CallKind,
    ) -> Result<u64, Stop> {
        if matches!(hook, Hook::IntegerEnd)
            && matches!(
                self.image.format,
                crate::loader::Format::Pe | crate::loader::Format::Coff
            )
        {
            return Err(Stop::Error("unsupported strtol data model".into()));
        }
        let second = if matches!(hook, Hook::Integer) {
            0
        } else {
            self.argument(1, convention, kind)?
        };
        if matches!(hook, Hook::Integer | Hook::IntegerEnd) {
            let base = if matches!(hook, Hook::IntegerEnd) {
                self.argument(2, convention, kind)?
            } else {
                10
            };
            if !matches!(base, 10 | 16) {
                return Err(Stop::Error("unsupported strtol base".into()));
            }
            let mut offset = 0u64;
            let mut bytes = Vec::new();
            loop {
                let Some(address) = first.checked_add(offset) else {
                    return Err(Stop::Error("integer string address overflows".into()));
                };
                let byte = self.read_byte(address)?;
                if byte == 0 {
                    break;
                }
                bytes.push(byte);
                offset = offset.saturating_add(1);
            }
            let mut position = 0;
            while bytes.get(position).is_some_and(u8::is_ascii_whitespace) {
                position += 1;
            }
            let negative = bytes.get(position) == Some(&b'-');
            if negative || bytes.get(position) == Some(&b'+') {
                position += 1;
            }
            if base == 16
                && bytes.get(position) == Some(&b'0')
                && matches!(bytes.get(position + 1), Some(b'x' | b'X'))
                && bytes.get(position + 2).is_some_and(u8::is_ascii_hexdigit)
            {
                position += 2;
            }
            let start = position;
            let mut value = 0u64;
            let sign = 1u64 << (u32::from(crate::arch::pointer_bytes(self.image.isa)) * 8 - 1);
            let limit = if negative { sign } else { sign - 1 };
            while let Some(&byte) = bytes.get(position) {
                let digit = match byte {
                    b'0'..=b'9' => u64::from(byte - b'0'),
                    b'a'..=b'f' if base == 16 => u64::from(byte - b'a' + 10),
                    b'A'..=b'F' if base == 16 => u64::from(byte - b'A' + 10),
                    _ => break,
                };
                value = value.saturating_mul(base).saturating_add(digit).min(limit);
                position += 1;
            }
            if matches!(hook, Hook::IntegerEnd) && second != 0 {
                let Some(address) =
                    first.checked_add(if position > start { position as u64 } else { 0 })
                else {
                    return Err(Stop::Error("strtol end address overflows".into()));
                };
                self.machine
                    .store(second, address, crate::arch::pointer_bytes(self.image.isa));
                self.memory_error()?;
            }
            let result = if negative {
                value.wrapping_neg()
            } else {
                value
            };
            return Ok(if matches!(hook, Hook::Integer) {
                u64::from(result as u32)
            } else {
                result
            });
        }
        let source = if matches!(hook, Hook::StringCopyN) {
            second
        } else {
            first
        };
        let maximum = if matches!(hook, Hook::StringCopyN) {
            self.argument(2, convention, kind)?
        } else if matches!(hook, Hook::LengthN) {
            second
        } else {
            HEAP_SIZE
        };
        if maximum > HEAP_SIZE {
            return Err(Stop::Error("string operation exceeds 16 MiB".into()));
        }
        let mut ended = false;
        for offset in 0..maximum {
            let Some(address) = source.checked_add(offset) else {
                return Err(Stop::Error("string address overflows".into()));
            };
            let byte = if ended { 0 } else { self.read_byte(address)? };
            if matches!(hook, Hook::Character) && byte == second as u8 {
                return Ok(address);
            }
            if matches!(hook, Hook::StringCopyN) {
                let Some(destination) = first.checked_add(offset) else {
                    return Err(Stop::Error("string destination overflows".into()));
                };
                self.write_byte(destination, byte)?;
            }
            if byte == 0 {
                if matches!(hook, Hook::LengthN) {
                    return Ok(offset);
                }
                if matches!(hook, Hook::Character) {
                    return Ok(0);
                }
                ended = true;
            }
        }
        Ok(if matches!(hook, Hook::StringCopyN) {
            first
        } else if matches!(hook, Hook::Character) {
            0
        } else {
            maximum
        })
    }
}

impl Runner<'_> {
    // A failed pointer, stream or memory operation aborts this input call.
    fn getline_hook(
        &mut self,
        pointer: u64,
        convention: Convention,
        kind: CallKind,
    ) -> Result<u64, Stop> {
        let width = crate::arch::pointer_bytes(self.image.isa);
        let capacity_pointer = match self.argument(1, convention, kind) {
            Ok(value) => value,
            Err(stop) => return Err(stop),
        };
        let stream = self.argument(2, convention, kind)?;
        if stream == 0 || stream != self.streams[0] {
            return Err(Stop::Error("unsupported getline stream".into()));
        }
        let mut bytes = Vec::new();
        while let Some(byte) = super::io::next_input(&self.input, &mut self.input_position) {
            self.tick()?;
            bytes.push(byte);
            if byte == 10 {
                break;
            }
        }
        if bytes.is_empty() {
            return Ok(u64::MAX);
        }
        let length = bytes.len();
        bytes.push(0);
        let mut destination = self.machine.load(pointer, width);
        let capacity = self.machine.load(capacity_pointer, width);
        self.memory_error()?;
        if destination == 0 || capacity < bytes.len() as u64 {
            destination = self.allocate(bytes.len() as u64);
            if destination == 0 {
                return Ok(u64::MAX);
            }
            self.machine.store(pointer, destination, width);
            self.machine
                .store(capacity_pointer, bytes.len() as u64, width);
            self.memory_error()?;
        }
        for (offset, byte) in bytes.into_iter().enumerate() {
            let Some(address) = destination.checked_add(offset as u64) else {
                return Err(Stop::Error("getline destination overflows".into()));
            };
            self.write_byte(address, byte)?;
        }
        Ok(length as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::{Image, Isa};

    #[test]
    fn exit_does_not_ignore_registered_handlers_or_immediate_exit() {
        let mut image = Image::from_code(Isa::X86_64, 0, vec![0xc3]);
        assert!(!has_exit_handlers(&image));
        assert!(matches!(find("exit"), Some(Hook::Exit)));
        assert!(find("_exit").is_none());
        for name in [
            "atexit",
            "__cxa_atexit@GLIBC_2.2.5",
            "__cxa_thread_atexit_impl",
            "on_exit",
        ] {
            image.imports.insert(0, name.to_owned());
            assert!(has_exit_handlers(&image), "{name}");
        }
    }
}

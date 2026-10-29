//! Common C library calls, selected by imported symbol name.

use super::{CallKind, Convention, HEAP_SIZE, Runner, Stop};

#[derive(Clone, Copy)]
pub(crate) enum Hook {
    Random,
    Seed,
    Time,
    ClockGettime,
    Gettimeofday,
    Sleep,
    MicroSleep,
    NanoSleep,
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
    MemoryProtect,
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
    MemorySearch,
    MemoryCompare,
    StringCopyN,
    Character,
    ComplementSpan,
    ReverseCharacter,
    FindByteReverse,
    FindSubstring,
    Duplicate,
    DuplicateN,
    Integer,
    LongInteger,
    IntegerEnd,
    LongLongIntegerEnd,
    UnsignedIntegerEnd,
    UnsignedLongLongIntegerEnd,
    Upper,
    Lower,
    Compare,
    CompareN,
    CompareCase,
    CompareCaseN,
    StringCopy,
    Allocate,
    AllocateZero,
    Reallocate,
    Free,
    ErrnoLocation,
    SetLocale,
    GetResourceLimit,
    SetResourceLimit,
    Socket,
    Connect,
    Bind,
    Listen,
    Accept,
    Send,
    Receive,
    Sort,
    BinarySearch,
    Io(super::io::Operation),
}

const HOOKS: &[(&str, Hook)] = &[
    ("socket", Hook::Socket),
    ("connect", Hook::Connect),
    ("bind", Hook::Bind),
    ("listen", Hook::Listen),
    ("accept", Hook::Accept),
    ("send", Hook::Send),
    ("recv", Hook::Receive),
    ("qsort", Hook::Sort),
    ("bsearch", Hook::BinarySearch),
    ("sleep", Hook::Sleep),
    ("usleep", Hook::MicroSleep),
    ("nanosleep", Hook::NanoSleep),
    ("getrlimit", Hook::GetResourceLimit),
    ("setrlimit", Hook::SetResourceLimit),
    ("setlocale", Hook::SetLocale),
    ("__errno_location", Hook::ErrnoLocation),
    ("___error", Hook::ErrnoLocation),
    ("errno", Hook::ErrnoLocation),
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
    ("mprotect", Hook::MemoryProtect),
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
    ("memchr", Hook::MemorySearch),
    ("memcmp", Hook::MemoryCompare),
    ("bcmp", Hook::MemoryCompare),
    ("strncpy", Hook::StringCopyN),
    ("strchr", Hook::Character),
    ("strcspn", Hook::ComplementSpan),
    ("strrchr", Hook::ReverseCharacter),
    ("memrchr", Hook::FindByteReverse),
    ("strstr", Hook::FindSubstring),
    ("strdup", Hook::Duplicate),
    ("strndup", Hook::DuplicateN),
    ("atoi", Hook::Integer),
    ("atol", Hook::LongInteger),
    ("strtol", Hook::IntegerEnd),
    ("strtoll", Hook::LongLongIntegerEnd),
    ("strtoul", Hook::UnsignedIntegerEnd),
    ("strtoull", Hook::UnsignedLongLongIntegerEnd),
    ("toupper", Hook::Upper),
    ("tolower", Hook::Lower),
    ("strcmp", Hook::Compare),
    ("strncmp", Hook::CompareN),
    ("strcasecmp", Hook::CompareCase),
    ("strncasecmp", Hook::CompareCaseN),
    ("strcpy", Hook::StringCopy),
    ("malloc", Hook::Allocate),
    ("calloc", Hook::AllocateZero),
    ("realloc", Hook::Reallocate),
    ("free", Hook::Free),
];

pub(crate) fn find(name: &str) -> Option<Hook> {
    if name.split('@').next() == Some("_exit") {
        return None;
    }
    let name = if name.starts_with("__isoc99_")
        || name.starts_with("__stack_chk_")
        || name.starts_with("__sysv_")
        || name.starts_with("__errno_location")
        || name.starts_with("___error")
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
    fn extended_hook(
        &mut self,
        hook: Hook,
        first: u64,
        convention: Convention,
        kind: CallKind,
        depth: usize,
    ) -> Result<u64, Stop> {
        match hook {
            Hook::Sleep => {
                let ticks = (first as u32 as u64)
                    .checked_mul(1_000_000_000)
                    .ok_or_else(|| Stop::Error("sleep duration overflows".to_owned()))?;
                if !self.advance_clock(ticks) {
                    return Err(Stop::Error("emulated clock overflows".to_owned()));
                }
                Ok(0)
            }
            Hook::MicroSleep => {
                let microseconds = first as u32 as u64;
                if microseconds >= 1_000_000 {
                    return self.error_result(22);
                }
                let ticks = microseconds
                    .checked_mul(1_000)
                    .ok_or_else(|| Stop::Error("usleep duration overflows".to_owned()))?;
                if !self.advance_clock(ticks) {
                    return Err(Stop::Error("emulated clock overflows".to_owned()));
                }
                Ok(0)
            }
            Hook::NanoSleep => {
                let width = crate::arch::pointer_bytes(self.image.isa);
                let Some(nanoseconds_address) = first.checked_add(u64::from(width)) else {
                    return Err(Stop::Error(
                        "nanosleep request address overflows".to_owned(),
                    ));
                };
                let seconds = self.read_integer(first, width)?;
                let nanoseconds = self.read_integer(nanoseconds_address, width)?;
                let seconds = if width == 4 {
                    seconds as u32 as i32 as i64
                } else {
                    seconds as i64
                };
                if seconds < 0 || nanoseconds >= 1_000_000_000 {
                    return self.error_result(22);
                }
                let Some(ticks) = (seconds as u64)
                    .checked_mul(1_000_000_000)
                    .and_then(|ticks| ticks.checked_add(nanoseconds))
                else {
                    return self.error_result(22);
                };
                if !self.advance_clock(ticks) {
                    return Err(Stop::Error("emulated clock overflows".to_owned()));
                }
                Ok(0)
            }
            Hook::SetLocale => self.set_locale(first, convention, kind),
            Hook::GetResourceLimit => self.resource_limit(first, convention, kind, false),
            Hook::SetResourceLimit => self.resource_limit(first, convention, kind, true),
            Hook::Socket => {
                let descriptor = self.next_socket_descriptor()?;
                self.sockets.insert(
                    descriptor,
                    super::SocketState {
                        listening: false,
                        connected: false,
                        bound: false,
                    },
                );
                Ok(descriptor)
            }
            Hook::Connect | Hook::Bind => {
                let descriptor = first;
                if !self.sockets.contains_key(&descriptor) {
                    return self.error_result(9);
                }
                let address = self.argument(1, convention, kind)?;
                let length = self.argument(2, convention, kind)?;
                if address != 0 && length != 0 {
                    if length > 128 {
                        return self.error_result(22);
                    }
                    self.check_memory_range(address, length, false)?;
                }
                let Some(socket) = self.sockets.get_mut(&descriptor) else {
                    return self.error_result(9);
                };
                if matches!(hook, Hook::Connect) {
                    if socket.connected || socket.listening {
                        return self.error_result(106);
                    }
                    socket.connected = true;
                } else {
                    if socket.bound || socket.connected {
                        return self.error_result(22);
                    }
                    socket.bound = true;
                }
                Ok(0)
            }
            Hook::Listen => {
                let Some(socket) = self.sockets.get_mut(&first) else {
                    return self.error_result(9);
                };
                if socket.connected {
                    return self.error_result(22);
                }
                socket.bound = true;
                socket.listening = true;
                Ok(0)
            }
            Hook::Accept => {
                let Some(socket) = self.sockets.get(&first).copied() else {
                    return self.error_result(9);
                };
                if !socket.listening {
                    return self.error_result(22);
                }
                let address = self.argument(1, convention, kind)?;
                let length_pointer = self.argument(2, convention, kind)?;
                if address != 0 {
                    if length_pointer == 0 {
                        return self.error_result(14);
                    }
                    let length = self.read_integer(length_pointer, 4)?;
                    let written = length.min(16);
                    self.check_memory_range(address, written, true)?;
                    for offset in 0..written {
                        let Some(at) = address.checked_add(offset) else {
                            return Err(Stop::Error(
                                "accepted socket address overflows".to_owned(),
                            ));
                        };
                        self.write_byte(at, 0)?;
                    }
                    if written >= 2 {
                        self.write_byte(address, 2)?;
                    }
                    self.write_integer(length_pointer, 4, 16)?;
                }
                let descriptor = self.next_socket_descriptor()?;
                self.sockets.insert(
                    descriptor,
                    super::SocketState {
                        listening: false,
                        connected: true,
                        bound: false,
                    },
                );
                Ok(descriptor)
            }
            Hook::Send | Hook::Receive => self.socket_data(hook, first, convention, kind),
            Hook::Sort => self.sort(first, convention, kind, depth),
            Hook::BinarySearch => self.binary_search(first, convention, kind, depth),
            Hook::ErrnoLocation => Ok(self.errno_location()),
            _ => Err(Stop::Error("invalid extended library hook".to_owned())),
        }
    }

    fn error_result(&mut self, error: u32) -> Result<u64, Stop> {
        self.set_errno(error)?;
        Ok(u64::from(u32::MAX))
    }

    fn read_integer(&mut self, address: u64, width: u8) -> Result<u64, Stop> {
        self.check_memory_range(address, u64::from(width), false)?;
        let value = self.machine.load(address, width);
        self.memory_error()?;
        Ok(value)
    }

    fn write_integer(&mut self, address: u64, width: u8, value: u64) -> Result<(), Stop> {
        self.check_memory_range(address, u64::from(width), true)?;
        self.machine.store(address, value, width);
        self.memory_error()
    }

    fn set_locale(
        &mut self,
        category: u64,
        convention: Convention,
        kind: CallKind,
    ) -> Result<u64, Stop> {
        let locale = self.argument(1, convention, kind)?;
        let max_category = if self.image.format == crate::loader::Format::MachO {
            5
        } else {
            6
        };
        if category > max_category {
            return Ok(0);
        }
        if locale != 0 {
            let name = self.bytes_at(locale, None)?;
            if name != b"C" && name != b"POSIX" {
                return Ok(0);
            }
        }
        if let Some(address) = self.locale {
            return Ok(address);
        }
        let address = self.allocate(2);
        if address == 0 {
            return Err(Stop::Error("locale string allocation failed".to_owned()));
        }
        self.write_byte(address, b'C')?;
        self.write_byte(address + 1, 0)?;
        self.locale = Some(address);
        Ok(address)
    }

    fn resource_limit(
        &mut self,
        resource: u64,
        convention: Convention,
        kind: CallKind,
        update: bool,
    ) -> Result<u64, Stop> {
        let pointer = self.argument(1, convention, kind)?;
        let resource = resource as u32;
        let valid = if self.image.format == crate::loader::Format::MachO {
            matches!(resource, 0..=5 | 7..=8)
        } else {
            resource <= 15
        };
        if !valid {
            return self.error_result(22);
        }
        let width = crate::arch::pointer_bytes(self.image.isa);
        let Some(hard_address) = pointer.checked_add(u64::from(width)) else {
            return Err(Stop::Error("resource limit address overflows".to_owned()));
        };
        if update {
            let current = self.read_integer(pointer, width)?;
            let maximum = self.read_integer(hard_address, width)?;
            if current > maximum {
                return self.error_result(22);
            }
            let previous = self
                .resource_limits
                .get(&resource)
                .copied()
                .unwrap_or((u64::MAX, u64::MAX));
            if maximum > previous.1 {
                return self.error_result(1);
            }
            self.resource_limits.insert(resource, (current, maximum));
        } else {
            let limit = self
                .resource_limits
                .get(&resource)
                .copied()
                .unwrap_or((u64::MAX, u64::MAX));
            self.write_integer(pointer, width, limit.0)?;
            self.write_integer(hard_address, width, limit.1)?;
        }
        Ok(0)
    }

    fn next_socket_descriptor(&mut self) -> Result<u64, Stop> {
        loop {
            let descriptor = self.files.reserve_descriptor().map_err(Stop::Error)?;
            if !self.options.stdin_descriptors.contains(&descriptor) {
                return Ok(u64::from(descriptor));
            }
        }
    }

    fn socket_data(
        &mut self,
        hook: Hook,
        descriptor: u64,
        convention: Convention,
        kind: CallKind,
    ) -> Result<u64, Stop> {
        let Some(socket) = self.sockets.get(&descriptor).copied() else {
            return self.error_result(9);
        };
        if !socket.connected {
            return self.error_result(107);
        }
        let buffer = self.argument(1, convention, kind)?;
        let count = self.argument(2, convention, kind)?;
        let flags = self.argument(3, convention, kind)? as u32;
        if count > HEAP_SIZE {
            return self.error_result(90);
        }
        if matches!(hook, Hook::Send) {
            self.check_memory_range(buffer, count, false)?;
            for offset in 0..count {
                let Some(address) = buffer.checked_add(offset) else {
                    return Err(Stop::Error("socket send address overflows".to_owned()));
                };
                let _ = self.read_byte(address)?;
            }
            return Ok(count);
        }
        let remaining = self.socket_peer.len().saturating_sub(self.socket_position);
        let length = (count as usize).min(remaining);
        self.check_memory_range(buffer, length as u64, true)?;
        for offset in 0..length {
            let Some(address) = buffer.checked_add(offset as u64) else {
                return Err(Stop::Error("socket receive address overflows".to_owned()));
            };
            let byte = self.socket_peer[self.socket_position + offset];
            self.write_byte(address, byte)?;
        }
        if flags & 2 == 0 {
            self.socket_position = self.socket_position.saturating_add(length);
        }
        Ok(length as u64)
    }

    fn element_address(&self, base: u64, index: u64, size: u64) -> Result<u64, Stop> {
        let Some(offset) = index.checked_mul(size) else {
            return Err(Stop::Error("array element offset overflows".to_owned()));
        };
        base.checked_add(offset)
            .ok_or_else(|| Stop::Error("array element address overflows".to_owned()))
    }

    fn compare_elements(
        &mut self,
        comparator: u64,
        left: u64,
        right: u64,
        depth: usize,
    ) -> Result<i32, Stop> {
        let result = self.call_callback(comparator, &[left, right], depth)?;
        Ok(result as u32 as i32)
    }

    fn swap_elements(&mut self, left: u64, right: u64, size: u64) -> Result<(), Stop> {
        if left == right {
            return Ok(());
        }
        for offset in 0..size {
            let Some(left_address) = left.checked_add(offset) else {
                return Err(Stop::Error("array element address overflows".to_owned()));
            };
            let Some(right_address) = right.checked_add(offset) else {
                return Err(Stop::Error("array element address overflows".to_owned()));
            };
            let left_byte = self.read_byte(left_address)?;
            let right_byte = self.read_byte(right_address)?;
            self.write_byte(left_address, right_byte)?;
            self.write_byte(right_address, left_byte)?;
        }
        Ok(())
    }

    fn sort(
        &mut self,
        base: u64,
        convention: Convention,
        kind: CallKind,
        depth: usize,
    ) -> Result<u64, Stop> {
        let count = self.argument(1, convention, kind)?;
        let size = self.argument(2, convention, kind)?;
        let comparator = self.argument(3, convention, kind)?;
        let Some(total) = count.checked_mul(size) else {
            return Err(Stop::Error("qsort array size overflows".to_owned()));
        };
        if total > HEAP_SIZE {
            return Err(Stop::Error("qsort array exceeds 16 MiB".to_owned()));
        }
        if count < 2 || size == 0 {
            return Ok(0);
        }
        self.check_memory_range(base, total, true)?;
        let mut root = count / 2;
        while root != 0 {
            root -= 1;
            self.sift_down(base, root, count, size, comparator, depth)?;
        }
        let mut end = count;
        while end > 1 {
            self.swap_elements(base, self.element_address(base, end - 1, size)?, size)?;
            end -= 1;
            self.sift_down(base, 0, end, size, comparator, depth)?;
        }
        Ok(0)
    }

    fn sift_down(
        &mut self,
        base: u64,
        mut root: u64,
        end: u64,
        size: u64,
        comparator: u64,
        depth: usize,
    ) -> Result<(), Stop> {
        loop {
            let Some(child) = root.checked_mul(2).and_then(|value| value.checked_add(1)) else {
                return Err(Stop::Error("qsort index overflows".to_owned()));
            };
            if child >= end {
                return Ok(());
            }
            let right = child + 1;
            let child = if right < end {
                let left_address = self.element_address(base, child, size)?;
                let right_address = self.element_address(base, right, size)?;
                if self.compare_elements(comparator, left_address, right_address, depth)? < 0 {
                    right
                } else {
                    child
                }
            } else {
                child
            };
            let root_address = self.element_address(base, root, size)?;
            let child_address = self.element_address(base, child, size)?;
            if self.compare_elements(comparator, root_address, child_address, depth)? >= 0 {
                return Ok(());
            }
            self.swap_elements(root_address, child_address, size)?;
            root = child;
        }
    }

    fn binary_search(
        &mut self,
        key: u64,
        convention: Convention,
        kind: CallKind,
        depth: usize,
    ) -> Result<u64, Stop> {
        let base = self.argument(1, convention, kind)?;
        let count = self.argument(2, convention, kind)?;
        let size = self.argument(3, convention, kind)?;
        let comparator = self.argument(4, convention, kind)?;
        let Some(total) = count.checked_mul(size) else {
            return Err(Stop::Error("bsearch array size overflows".to_owned()));
        };
        if total > HEAP_SIZE {
            return Err(Stop::Error("bsearch array exceeds 16 MiB".to_owned()));
        }
        if size == 0 {
            return Ok(0);
        }
        self.check_memory_range(base, total, false)?;
        let mut lower = 0;
        let mut upper = count;
        while lower < upper {
            let middle = lower + (upper - lower) / 2;
            let element = self.element_address(base, middle, size)?;
            match self.compare_elements(comparator, key, element, depth)? {
                0 => return Ok(element),
                value if value < 0 => upper = middle,
                _ => lower = middle + 1,
            }
        }
        Ok(0)
    }
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
        self.allocations.insert(start, size.max(1));
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
        depth: usize,
    ) -> std::result::Result<u64, Stop> {
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
        if let Hook::Io(super::io::Operation::Close) = hook {
            let descriptor = self.argument(0, convention, kind)?;
            if self.sockets.remove(&descriptor).is_some() {
                return Ok(0);
            }
            return self.io_hook(super::io::Operation::Close, convention, kind);
        }
        if let Hook::Io(operation) = hook {
            return self.io_hook(operation, convention, kind);
        }
        if matches!(hook, Hook::ErrnoLocation) {
            return Ok(self.errno_location());
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
            Hook::StackCheckFail | Hook::Io(_) | Hook::Random | Hook::Exit => {
                unreachable!("these hooks return before the library call match")
            }
            Hook::Sleep
            | Hook::MicroSleep
            | Hook::NanoSleep
            | Hook::SetLocale
            | Hook::GetResourceLimit
            | Hook::SetResourceLimit
            | Hook::Socket
            | Hook::Connect
            | Hook::Bind
            | Hook::Listen
            | Hook::Accept
            | Hook::Send
            | Hook::Receive
            | Hook::Sort
            | Hook::BinarySearch
            | Hook::ErrnoLocation => {
                return self.extended_hook(hook, first, convention, kind, depth);
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
                let elapsed = self.clock_ticks();
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
                (self.clock_ticks() / 1_000_000) as u32 as u64
            }
            Hook::GetTickCount64 => {
                self.anti_analysis.push("GetTickCount64".to_owned());
                self.clock_ticks() / 1_000_000
            }
            Hook::QueryPerformanceCounter => {
                let pointer = first;
                let value = self.clock_ticks();
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
                let (ptrace_number, parent_number, prctl_number, protect_number) = match self
                    .image
                    .isa
                {
                    crate::loader::Isa::X86_64 => (101, 110, 157, 10),
                    crate::loader::Isa::I386 => (26, 64, 172, 125),
                    crate::loader::Isa::AArch64 => (117, 173, 167, 226),
                    _ => return Err(Stop::Error("unsupported syscall architecture".to_owned())),
                };
                if number == protect_number {
                    if !self.stop_on_write && self.stop_address.is_none() {
                        return Err(Stop::Error(format!("unsupported Linux syscall {number}")));
                    }
                    let length = match self.argument(1, convention, kind) {
                        Ok(length) => length,
                        Err(stop) => return Err(stop),
                    };
                    if let Err(stop) = self.check_memory_range(first, length, false) {
                        return Err(stop);
                    }
                    let _protection = match self.argument(2, convention, kind) {
                        Ok(protection) => protection,
                        Err(stop) => return Err(stop),
                    };
                    0
                } else if number == ptrace_number {
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
            Hook::MemoryProtect => {
                if !self.stop_on_write && self.stop_address.is_none() {
                    return Err(Stop::Error("mprotect requires unpacking".to_owned()));
                }
                let length = match self.argument(1, convention, kind) {
                    Ok(length) => length,
                    Err(stop) => return Err(stop),
                };
                if let Err(stop) = self.check_memory_range(first, length, false) {
                    return Err(stop);
                }
                let _protection = match self.argument(2, convention, kind) {
                    Ok(protection) => protection,
                    Err(stop) => return Err(stop),
                };
                0
            }
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
            Hook::Reallocate => {
                let size = match self.argument(1, convention, kind) {
                    Ok(value) => value,
                    Err(stop) => return Err(stop),
                };
                if first == 0 {
                    self.allocate(size)
                } else if size == 0 {
                    if self.allocations.remove(&first).is_none() {
                        return Err(Stop::Error(format!(
                            "realloc of unallocated pointer 0x{first:x}"
                        )));
                    }
                    0
                } else {
                    let Some(old_size) = self.allocations.get(&first).copied() else {
                        return Err(Stop::Error(format!(
                            "realloc of unallocated pointer 0x{first:x}"
                        )));
                    };
                    let address = self.allocate(size);
                    if address == 0 {
                        0
                    } else {
                        let count = old_size.min(size);
                        if let Err(stop) = self.copy_memory(Hook::Move, address, first, count) {
                            return Err(stop);
                        }
                        self.allocations.remove(&first);
                        address
                    }
                }
            }
            Hook::Free => {
                if first != 0 && self.allocations.remove(&first).is_none() {
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
            Hook::MemorySearch => {
                let target = match self.argument(1, convention, kind) {
                    Ok(value) => value as u8,
                    Err(stop) => return Err(stop),
                };
                let count = match self.argument(2, convention, kind) {
                    Ok(value) => value,
                    Err(stop) => return Err(stop),
                };
                if count > HEAP_SIZE {
                    return Err(Stop::Error("memory search exceeds model bound".to_owned()));
                }
                let mut found = 0;
                for offset in 0..count {
                    let Some(location) = first.checked_add(offset) else {
                        return Err(Stop::Error("memory search address overflows".to_owned()));
                    };
                    let byte = match self.read_byte(location) {
                        Ok(value) => value,
                        Err(stop) => return Err(stop),
                    };
                    if byte == target {
                        found = location;
                        break;
                    }
                }
                found
            }
            Hook::Getline => return self.getline_hook(first, convention, kind),
            Hook::ComplementSpan => {
                let reject = match self.argument(1, convention, kind) {
                    Ok(value) => value,
                    Err(stop) => return Err(stop),
                };
                let mut rejected = [false; 256];
                let mut terminated = false;
                for offset in 0..HEAP_SIZE {
                    let Some(address) = reject.checked_add(offset) else {
                        return Err(Stop::Error("string address overflows".into()));
                    };
                    let byte = match self.read_byte(address) {
                        Ok(value) => value,
                        Err(stop) => return Err(stop),
                    };
                    if byte == 0 {
                        terminated = true;
                        break;
                    }
                    rejected[usize::from(byte)] = true;
                }
                if !terminated {
                    return Err(Stop::Error("string operation exceeds 16 MiB".into()));
                }
                let mut length = None;
                for offset in 0..HEAP_SIZE {
                    let Some(address) = first.checked_add(offset) else {
                        return Err(Stop::Error("string address overflows".into()));
                    };
                    let byte = match self.read_byte(address) {
                        Ok(value) => value,
                        Err(stop) => return Err(stop),
                    };
                    if byte == 0 || rejected[usize::from(byte)] {
                        length = Some(offset);
                        break;
                    }
                }
                match length {
                    Some(length) => length,
                    None => return Err(Stop::Error("string operation exceeds 16 MiB".into())),
                }
            }
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
            | Hook::ReverseCharacter
            | Hook::FindByteReverse
            | Hook::FindSubstring
            | Hook::Duplicate
            | Hook::DuplicateN
            | Hook::Integer
            | Hook::LongInteger
            | Hook::IntegerEnd
            | Hook::LongLongIntegerEnd
            | Hook::UnsignedIntegerEnd
            | Hook::UnsignedLongLongIntegerEnd => {
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
            Hook::Compare
            | Hook::CompareN
            | Hook::MemoryCompare
            | Hook::CompareCase
            | Hook::CompareCaseN => {
                let second = match self.argument(1, convention, kind) {
                    Ok(value) => value,
                    Err(stop) => return Err(stop),
                };
                let limit = if !matches!(hook, Hook::Compare | Hook::CompareCase) {
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
                    let left = if matches!(hook, Hook::CompareCase | Hook::CompareCaseN) {
                        left.to_ascii_lowercase()
                    } else {
                        left
                    };
                    let right = if matches!(hook, Hook::CompareCase | Hook::CompareCaseN) {
                        right.to_ascii_lowercase()
                    } else {
                        right
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
        let returns_64_bits = matches!(
            hook,
            Hook::LongLongIntegerEnd | Hook::UnsignedLongLongIntegerEnd
        );
        let value = if crate::arch::pointer_bytes(self.image.isa) == 4 && !returns_64_bits {
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
        if matches!(
            hook,
            Hook::FindByteReverse | Hook::FindSubstring | Hook::Duplicate | Hook::DuplicateN
        ) {
            return self.extended_string_hook(hook, first, convention, kind);
        }
        if matches!(
            hook,
            Hook::Integer
                | Hook::LongInteger
                | Hook::IntegerEnd
                | Hook::LongLongIntegerEnd
                | Hook::UnsignedIntegerEnd
                | Hook::UnsignedLongLongIntegerEnd
        ) {
            return self.integer_string_hook(hook, first, convention, kind);
        }
        let second = if matches!(hook, Hook::Integer) {
            0
        } else {
            self.argument(1, convention, kind)?
        };
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
        let mut found_character = None;
        for offset in 0..maximum {
            let Some(address) = source.checked_add(offset) else {
                return Err(Stop::Error("string address overflows".into()));
            };
            let byte = if ended { 0 } else { self.read_byte(address)? };
            if matches!(hook, Hook::Character | Hook::ReverseCharacter) && byte == second as u8 {
                if matches!(hook, Hook::Character) {
                    return Ok(address);
                }
                found_character = Some(address);
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
                if matches!(hook, Hook::Character | Hook::ReverseCharacter) {
                    return Ok(found_character.unwrap_or(0));
                }
                ended = true;
            }
        }
        if matches!(hook, Hook::Character | Hook::ReverseCharacter) && !ended {
            return Err(Stop::Error("string exceeds 16 MiB".into()));
        }
        Ok(if matches!(hook, Hook::StringCopyN) {
            first
        } else if matches!(hook, Hook::Character | Hook::ReverseCharacter) {
            found_character.unwrap_or(0)
        } else {
            maximum
        })
    }

    fn extended_string_hook(
        &mut self,
        hook: Hook,
        first: u64,
        convention: Convention,
        kind: CallKind,
    ) -> Result<u64, Stop> {
        if matches!(hook, Hook::FindByteReverse) {
            let character = self.argument(1, convention, kind)? as u8;
            let count = self.argument(2, convention, kind)?;
            if count > HEAP_SIZE {
                return Err(Stop::Error("memory search exceeds 16 MiB".into()));
            }
            let mut found = None;
            for offset in 0..count {
                let Some(address) = first.checked_add(offset) else {
                    return Err(Stop::Error("memory search address overflows".into()));
                };
                if self.read_byte(address)? == character {
                    found = Some(address);
                }
            }
            return Ok(found.unwrap_or(0));
        }
        if matches!(hook, Hook::FindSubstring) {
            let needle = self.argument(1, convention, kind)?;
            let mut needle_bytes = Vec::new();
            let mut needle_ended = false;
            for offset in 0..HEAP_SIZE {
                let Some(address) = needle.checked_add(offset) else {
                    return Err(Stop::Error("substring address overflows".into()));
                };
                let byte = self.read_byte(address)?;
                if byte == 0 {
                    needle_ended = true;
                    break;
                }
                needle_bytes.push(byte);
            }
            if !needle_ended {
                return Err(Stop::Error("substring needle exceeds 16 MiB".into()));
            }
            if needle_bytes.is_empty() {
                return Ok(first);
            }
            for offset in 0..HEAP_SIZE {
                let Some(address) = first.checked_add(offset) else {
                    return Err(Stop::Error("substring address overflows".into()));
                };
                let byte = self.read_byte(address)?;
                if byte == 0 {
                    return Ok(0);
                }
                if byte == needle_bytes[0] {
                    let mut matched = true;
                    for (index, expected) in needle_bytes.iter().enumerate().skip(1) {
                        let Some(candidate) = address.checked_add(index as u64) else {
                            return Err(Stop::Error("substring address overflows".into()));
                        };
                        let candidate_byte = self.read_byte(candidate)?;
                        if candidate_byte == 0 || candidate_byte != *expected {
                            matched = false;
                            break;
                        }
                    }
                    if matched {
                        return Ok(address);
                    }
                }
            }
            return Err(Stop::Error("string exceeds 16 MiB".into()));
        }
        let requested_limit = if matches!(hook, Hook::DuplicateN) {
            self.argument(1, convention, kind)?
        } else {
            HEAP_SIZE
        };
        let limit = requested_limit.min(HEAP_SIZE);
        let mut bytes = Vec::new();
        let mut string_ended = false;
        for offset in 0..limit {
            let Some(address) = first.checked_add(offset) else {
                return Err(Stop::Error("string address overflows".into()));
            };
            let byte = self.read_byte(address)?;
            if byte == 0 {
                string_ended = true;
                break;
            }
            bytes.push(byte);
        }
        if !string_ended && (matches!(hook, Hook::Duplicate) || requested_limit > HEAP_SIZE) {
            return Err(Stop::Error("string exceeds 16 MiB".into()));
        }
        let address = self.allocate(bytes.len() as u64 + 1);
        if address == 0 {
            return Ok(0);
        }
        for (offset, byte) in bytes.iter().copied().chain([0]).enumerate() {
            let Some(destination) = address.checked_add(offset as u64) else {
                return Err(Stop::Error("string destination overflows".into()));
            };
            self.write_byte(destination, byte)?;
        }
        Ok(address)
    }

    fn integer_string_hook(
        &mut self,
        hook: Hook,
        first: u64,
        convention: Convention,
        kind: CallKind,
    ) -> Result<u64, Stop> {
        let end_pointer = matches!(
            hook,
            Hook::IntegerEnd
                | Hook::LongLongIntegerEnd
                | Hook::UnsignedIntegerEnd
                | Hook::UnsignedLongLongIntegerEnd
        );
        let end_address = if end_pointer {
            self.argument(1, convention, kind)?
        } else {
            0
        };
        let requested_base = if end_pointer {
            self.argument(2, convention, kind)?
        } else {
            10
        };
        if requested_base != 0 && !(2..=36).contains(&requested_base) {
            return Err(Stop::Error(format!(
                "integer conversion base {requested_base} is outside 0..=36 or 2..=36"
            )));
        }
        let mut bytes = Vec::new();
        let mut ended = false;
        for offset in 0..HEAP_SIZE {
            let Some(address) = first.checked_add(offset) else {
                return Err(Stop::Error("integer string address overflows".into()));
            };
            let byte = self.read_byte(address)?;
            if byte == 0 {
                ended = true;
                break;
            }
            bytes.push(byte);
        }
        if !ended {
            return Err(Stop::Error("integer string exceeds 16 MiB".into()));
        }
        let mut position = 0;
        while bytes.get(position).is_some_and(u8::is_ascii_whitespace) {
            position += 1;
        }
        let negative = bytes.get(position) == Some(&b'-');
        if negative || bytes.get(position) == Some(&b'+') {
            position += 1;
        }
        let mut base = requested_base;
        let has_hex_prefix = bytes.get(position) == Some(&b'0')
            && matches!(bytes.get(position + 1), Some(b'x' | b'X'))
            && bytes
                .get(position + 2)
                .and_then(|byte| digit_value(*byte))
                .is_some_and(|digit| digit < 16);
        if base == 0 {
            if has_hex_prefix {
                base = 16;
            } else if bytes.get(position) == Some(&b'0') {
                base = 8;
            } else {
                base = 10;
            }
        }
        if base == 16 && has_hex_prefix {
            position += 2;
        }
        let digit_start = position;
        let unsigned = matches!(
            hook,
            Hook::UnsignedIntegerEnd | Hook::UnsignedLongLongIntegerEnd
        );
        let bits = match hook {
            Hook::Integer => 32,
            Hook::LongInteger | Hook::IntegerEnd | Hook::UnsignedIntegerEnd
                if matches!(
                    self.image.format,
                    crate::loader::Format::Pe | crate::loader::Format::Coff
                ) =>
            {
                32
            }
            Hook::LongInteger | Hook::IntegerEnd | Hook::UnsignedIntegerEnd => {
                u32::from(crate::arch::pointer_bytes(self.image.isa)) * 8
            }
            Hook::LongLongIntegerEnd | Hook::UnsignedLongLongIntegerEnd => 64,
            _ => 64,
        };
        let sign_bit = 1u64 << (bits - 1);
        let limit = if unsigned {
            if bits == 64 {
                u64::MAX
            } else {
                (1u64 << bits) - 1
            }
        } else if negative {
            sign_bit
        } else {
            sign_bit - 1
        };
        let mut value = 0u64;
        let mut overflow = false;
        while let Some(&byte) = bytes.get(position) {
            let Some(digit) = digit_value(byte) else {
                break;
            };
            if digit >= base {
                break;
            }
            let next = u128::from(value) * u128::from(base) + u128::from(digit);
            if next > u128::from(limit) {
                overflow = true;
                value = limit;
            } else {
                value = next as u64;
            }
            position += 1;
        }
        if end_pointer && end_address != 0 {
            let consumed = if position > digit_start { position } else { 0 };
            let Some(address) = first.checked_add(consumed as u64) else {
                return Err(Stop::Error("integer end address overflows".into()));
            };
            self.machine.store(
                end_address,
                address,
                crate::arch::pointer_bytes(self.image.isa),
            );
            self.memory_error()?;
        }
        if position == digit_start {
            return Ok(0);
        }
        if overflow && end_pointer {
            self.set_errno(34)?;
        }
        if overflow {
            return Ok(limit);
        }
        let result = if unsigned {
            if negative {
                value.wrapping_neg() & limit
            } else {
                value
            }
        } else if negative {
            value.wrapping_neg()
        } else {
            value
        };
        Ok(if bits < 64 {
            result & ((1u64 << bits) - 1)
        } else {
            result
        })
    }
}

fn digit_value(byte: u8) -> Option<u64> {
    match byte {
        b'0'..=b'9' => Some(u64::from(byte - b'0')),
        b'a'..=b'z' => Some(u64::from(byte - b'a' + 10)),
        b'A'..=b'Z' => Some(u64::from(byte - b'A' + 10)),
        _ => None,
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

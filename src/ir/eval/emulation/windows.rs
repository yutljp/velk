//! Deterministic Windows process state and user-mode API calls.

mod crt;
mod io;
mod loader;
mod memory;
mod registry;
pub(super) mod seh;
mod strings;
mod threads;

use std::collections::{BTreeMap, BTreeSet};

use crate::emulation::ApiCall;
use crate::ir::{CallKind, Convention, Expr, RegRef};
use crate::loader::Isa;
use crate::ssa::ranges::Fact;

use super::{Runner, Stop};

pub(super) struct Process {
    modules: Vec<Module>,
    exports: BTreeMap<u64, Export>,
    callbacks: Vec<u64>,
    detaching: bool,
    crt_closed: bool,
    crt_exiting: bool,
    exit_handlers: Vec<u64>,
    exception_active: bool,
    instruction_state: Option<seh::State>,
    tls_directory: (u64, u64),
    threads: BTreeMap<u64, threads::Thread>,
    active_thread: Option<u64>,
    teb: u64,
    next_thread_id: u32,
    command_line: [u64; 2],
    environment_bytes: Vec<u8>,
    environment_blocks: BTreeSet<u64>,
    elapsed: u64,
    tls_used: [bool; 64],
    heap: u64,
    heap_blocks: BTreeMap<u64, memory::HeapBlock>,
    virtual_allocations: BTreeMap<u64, memory::Allocation>,
    file_handles: BTreeMap<u64, u32>,
    standard_handles: [bool; 3],
    crt_output: [Vec<u8>; 2],
    crt_buffering: [Option<u32>; 2],
    registry: BTreeMap<String, BTreeMap<String, crate::emulation::RegistryValue>>,
    registry_handles: BTreeMap<u64, registry::Key>,
}

struct Module {
    name: String,
    path: String,
    base: u64,
    size: u64,
    exports: BTreeMap<String, (u64, u32)>,
}

#[derive(Clone)]
struct Export {
    dll: String,
    name: String,
}

pub(super) enum TlsReason {
    ProcessAttach,
    ProcessDetach,
    ThreadAttach,
    ThreadDetach,
}

// These counts are also the sizes popped by the i386 stdcall entry points.
const APIS: &[(&str, usize)] = &[
    ("GetModuleHandleA", 1),
    ("GetModuleHandleW", 1),
    ("LoadLibraryA", 1),
    ("LoadLibraryW", 1),
    ("GetProcAddress", 2),
    ("GetCurrentProcessId", 0),
    ("GetCurrentThreadId", 0),
    ("GetCurrentProcess", 0),
    ("GetCurrentThread", 0),
    ("ExitProcess", 1),
    ("CreateThread", 6),
    ("ExitThread", 1),
    ("WaitForSingleObject", 2),
    ("GetExitCodeThread", 2),
    ("GetLastError", 0),
    ("SetLastError", 1),
    ("Sleep", 1),
    ("GetTickCount", 0),
    ("GetTickCount64", 0),
    ("QueryPerformanceCounter", 1),
    ("QueryPerformanceFrequency", 1),
    ("GetSystemTimeAsFileTime", 1),
    ("IsDebuggerPresent", 0),
    ("CheckRemoteDebuggerPresent", 2),
    ("GetCommandLineA", 0),
    ("GetCommandLineW", 0),
    ("GetEnvironmentStringsW", 0),
    ("FreeEnvironmentStringsW", 1),
    ("TlsAlloc", 0),
    ("TlsFree", 1),
    ("TlsGetValue", 1),
    ("TlsSetValue", 2),
    ("GetProcessHeap", 0),
    ("HeapAlloc", 3),
    ("HeapReAlloc", 4),
    ("HeapFree", 3),
    ("VirtualAlloc", 4),
    ("VirtualProtect", 4),
    ("VirtualFree", 3),
    ("lstrlenA", 1),
    ("lstrlenW", 1),
    ("MultiByteToWideChar", 6),
    ("WideCharToMultiByte", 8),
    ("GetStdHandle", 1),
    ("WriteFile", 5),
    ("ReadFile", 5),
    ("WriteConsoleA", 5),
    ("WriteConsoleW", 5),
    ("CreateFileA", 7),
    ("CreateFileW", 7),
    ("CloseHandle", 1),
];

const CRT_APIS: &[(&str, usize)] = &[
    ("atexit", 1),
    ("_onexit", 1),
    ("exit", 1),
    ("printf", 1),
    ("fprintf", 2),
    ("sprintf", 2),
    ("snprintf", 3),
    ("puts", 1),
    ("putchar", 1),
    ("malloc", 1),
    ("calloc", 2),
    ("free", 1),
    ("memcpy", 3),
    ("memmove", 3),
    ("memset", 3),
    ("memcmp", 3),
    ("strlen", 1),
    ("strnlen", 2),
    ("strcmp", 2),
    ("strncmp", 3),
    ("strcpy", 2),
    ("strncpy", 3),
    ("strchr", 2),
    ("memchr", 3),
    ("strcspn", 2),
    ("atoi", 1),
    ("strtol", 3),
    ("toupper", 1),
    ("tolower", 1),
    ("vprintf", 2),
    ("vfprintf", 3),
    ("vsprintf", 3),
    ("vsnprintf", 4),
    ("scanf", 1),
    ("fscanf", 2),
    ("sscanf", 2),
    ("vscanf", 2),
    ("vfscanf", 3),
    ("vsscanf", 3),
    ("fopen", 2),
    ("fclose", 1),
    ("fflush", 1),
    ("setbuf", 2),
    ("setvbuf", 4),
    ("fputs", 2),
    ("fwrite", 4),
    ("fread", 4),
    ("fgets", 3),
    ("getchar", 0),
    ("feof", 1),
    ("ferror", 1),
];

const UCRT_APIS: &[(&str, usize)] = &[
    ("_crt_atexit", 1),
    ("exit", 1),
    ("__acrt_iob_func", 1),
    ("__stdio_common_vfprintf", 5),
    ("__stdio_common_vsprintf", 6),
    ("__stdio_common_vsscanf", 6),
    ("puts", 1),
    ("putchar", 1),
    ("malloc", 1),
    ("calloc", 2),
    ("free", 1),
    ("memcpy", 3),
    ("memmove", 3),
    ("memset", 3),
    ("memcmp", 3),
    ("strlen", 1),
    ("strnlen", 2),
    ("strcmp", 2),
    ("strncmp", 3),
    ("strcpy", 2),
    ("strncpy", 3),
    ("strchr", 2),
    ("memchr", 3),
    ("strcspn", 2),
    ("atoi", 1),
    ("strtol", 3),
    ("toupper", 1),
    ("tolower", 1),
    ("fopen", 2),
    ("fclose", 1),
    ("fflush", 1),
    ("setbuf", 2),
    ("setvbuf", 4),
    ("fputs", 2),
    ("fwrite", 4),
    ("fread", 4),
    ("fgets", 3),
    ("getchar", 0),
    ("feof", 1),
    ("ferror", 1),
];

const REGISTRY_APIS: &[(&str, usize)] = &[
    ("RegOpenKeyExA", 5),
    ("RegOpenKeyExW", 5),
    ("RegQueryValueExA", 6),
    ("RegQueryValueExW", 6),
    ("RegCloseKey", 1),
];

fn kernel(dll: &str) -> bool {
    matches!(dll, "kernel32.dll" | "kernelbase.dll")
}

fn crt(dll: &str) -> bool {
    matches!(dll, "msvcrt.dll" | "ucrtbase.dll") || dll.starts_with("api-ms-win-crt-")
}

fn apis(dll: &str) -> &'static [(&'static str, usize)] {
    if kernel(dll) {
        APIS
    } else if dll == "msvcrt.dll" {
        CRT_APIS
    } else if crt(dll) {
        UCRT_APIS
    } else if dll == "advapi32.dll" {
        REGISTRY_APIS
    } else {
        &[]
    }
}

fn signature(export: &Export) -> Option<usize> {
    apis(&export.dll)
        .iter()
        .find(|(name, _)| *name == export.name)
        .map(|(_, count)| *count)
}

fn module_name(name: &str) -> String {
    let name = name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(name)
        .to_lowercase();
    if name.contains('.') {
        name
    } else {
        format!("{name}.dll")
    }
}

impl Runner<'_> {
    pub(super) fn windows_exports(&self) -> BTreeMap<u64, String> {
        let Some(process) = &self.windows else {
            return BTreeMap::new();
        };
        process
            .exports
            .iter()
            .map(|(&address, export)| (address, format!("{}!{}", export.dll, export.name)))
            .collect()
    }

    fn windows_state(&self) -> &Process {
        self.windows
            .as_ref()
            .expect("Windows setup precedes API calls")
    }

    fn windows_state_mut(&mut self) -> &mut Process {
        self.windows
            .as_mut()
            .expect("Windows setup precedes API calls")
    }

    fn last_error_address(&self) -> u64 {
        self.windows_teb()
            + if self.image.isa == Isa::X86_64 {
                0x68
            } else {
                0x34
            }
    }

    fn set_last_error(&mut self, value: u32) {
        self.machine
            .store(self.last_error_address(), u64::from(value), 4);
    }

    fn windows_failure(&mut self, error: u32) -> Result<u64, Stop> {
        self.set_last_error(error);
        Ok(0)
    }

    fn wide_string(&mut self, address: u64) -> Result<String, Stop> {
        let units = match self.wide_units(address, -1) {
            Ok(units) => units,
            Err(stop) => return Err(stop),
        };
        match String::from_utf16(&units[..units.len() - 1]) {
            Ok(text) => Ok(text),
            Err(_) => Err(Stop::Error("invalid UTF-16 string".to_owned())),
        }
    }

    fn windows_string(&mut self, pointer: u64, wide: bool) -> Result<String, Stop> {
        if wide {
            return self.wide_string(pointer);
        }
        let bytes = match self.bytes_at(pointer, None) {
            Ok(bytes) => bytes,
            Err(stop) => return Err(stop),
        };
        if !bytes.is_ascii() {
            return Err(Stop::Error("Windows ANSI names require ASCII".to_owned()));
        }
        Ok(String::from_utf8(bytes).expect("ASCII is UTF-8"))
    }

    fn windows_clock(&self) -> u64 {
        self.instructions
            .saturating_mul(self.options.anti_analysis.clock_ticks_per_instruction)
            .saturating_add(self.windows_state().elapsed)
    }

    pub(super) fn windows_call(
        &mut self,
        target: u64,
        original: Option<u64>,
        through: Option<&Expr>,
        kind: CallKind,
        depth: usize,
    ) -> Option<Result<(), Stop>> {
        let Some(export) = self
            .windows
            .as_ref()
            .and_then(|state| state.exports.get(&target))
            .cloned()
        else {
            return None;
        };
        self.return_cleanup = 0;
        let convention = if self.image.isa == Isa::X86_64 {
            Convention::Win64
        } else if crt(&export.dll) {
            Convention::Cdecl
        } else {
            Convention::Stdcall
        };
        let mut arguments = Vec::new();
        if let Some(count) = signature(&export) {
            let wide_options =
                self.image.isa == Isa::I386 && export.name.starts_with("__stdio_common_");
            let count = count + usize::from(wide_options);
            for index in 0..count {
                match self.argument(index, convention, kind) {
                    Ok(value) => arguments.push(value),
                    Err(stop) => return Some(Err(stop)),
                }
            }
            if wide_options {
                arguments[0] = arguments[0] as u32 as u64 | (arguments.remove(1) << 32);
            }
        }
        let qualified = format!("{}!{}", export.dll, export.name);
        self.api_calls.push(ApiCall {
            name: qualified.clone(),
            arguments: arguments
                .iter()
                .map(|&value| crate::addr::format(value))
                .collect(),
        });
        let override_value = self
            .options
            .call_returns
            .get(&qualified)
            .or_else(|| self.options.call_returns.get(&export.name))
            .or_else(|| self.options.call_returns.get(&crate::addr::format(target)))
            .or_else(|| {
                let slot = match through {
                    Some(Expr::Load { addr, .. }) => match addr.as_ref() {
                        Expr::Const(slot) => Some(*slot),
                        _ => None,
                    },
                    _ => original,
                };
                slot.and_then(|slot| self.options.call_returns.get(&crate::addr::format(slot)))
            });
        let overridden = override_value.is_some();
        if !overridden
            && signature(&export).is_some()
            && let Err(stop) = self.windows_check_teb()
        {
            return Some(Err(stop));
        }
        let result = if let Some(word) = override_value {
            match word.value() {
                Ok(value) => Ok(value),
                Err(error) => Err(Stop::Error(error.to_string())),
            }
        } else if kernel(&export.dll) && signature(&export).is_some() {
            self.windows_api(&export.name, &arguments)
        } else if export.dll == "advapi32.dll" && signature(&export).is_some() {
            self.windows_registry_api(&export.name, &arguments)
        } else if crt(&export.dll) && signature(&export).is_some() {
            if let Some(result) = self.windows_crt_lifecycle(&export.name, &arguments) {
                result
            } else if export.name.starts_with("__stdio_common_") {
                self.windows_ucrt_io(&export.name, &arguments)
            } else if export.name == "__acrt_iob_func" {
                let index = arguments[0] as u32 as usize;
                if index >= self.streams.len() {
                    Err(Stop::Error("__acrt_iob_func index exceeds 2".to_owned()))
                } else if self.streams[index] != 0 {
                    Ok(self.streams[index])
                } else {
                    let stream = self.allocate(1);
                    if stream == 0 {
                        Err(Stop::Error("CRT stream allocation failed".to_owned()))
                    } else {
                        self.streams[index] = stream;
                        Ok(stream)
                    }
                }
            } else if export.name == "fopen" {
                let path = match self.windows_string(arguments[0], /* wide */ false) {
                    Ok(path) => io::path_key(&path),
                    Err(stop) => return Some(Err(stop)),
                };
                for &handle in self.windows_state().file_handles.keys() {
                    if io::path_key(&self.files.streams[&handle].path) == path {
                        return Some(Err(Stop::Error(
                            "simultaneous CRT and Windows file handles are unsupported".to_owned(),
                        )));
                    }
                }
                let mode = match self.bytes_at(arguments[1], None) {
                    Ok(mode) => mode,
                    Err(stop) => return Some(Err(stop)),
                };
                if !mode.contains(&b'b') {
                    Err(Stop::Error(
                        "Windows CRT file streams require binary mode".to_owned(),
                    ))
                } else {
                    self.hook(
                        super::hooks::Hook::Io(super::io::Operation::Fopen),
                        convention,
                        kind,
                        depth,
                    )
                }
            } else {
                match super::hooks::find(&export.name) {
                    Some(hook) => self.hook(hook, convention, kind, depth),
                    None if self.options.skip_calls => Ok(0),
                    None => Err(Stop::Error(format!("unhandled Windows API {qualified}"))),
                }
            }
        } else if self.options.skip_calls {
            Ok(0)
        } else {
            Err(Stop::Error(format!("unhandled Windows API {qualified}")))
        };
        let value = match result {
            Ok(value) => value,
            Err(Stop::Exception(exception)) => {
                return Some(Err(Stop::Error(format!(
                    "Windows API {qualified}: {}",
                    exception.message
                ))));
            }
            Err(stop) => return Some(Err(stop)),
        };
        self.external_result(
            convention,
            if !overridden
                && ((crt(&export.dll) && export.name == "free")
                    || (kernel(&export.dll)
                        && matches!(
                            export.name.as_str(),
                            "SetLastError" | "Sleep" | "GetSystemTimeAsFileTime"
                        )))
            {
                None
            } else {
                Some(if self.image.isa == Isa::I386 {
                    u64::from(value as u32)
                } else {
                    value
                })
            },
        );
        if self.image.isa == Isa::I386 {
            if export.name == "GetTickCount64" && kernel(&export.dll) {
                self.assign_fact(
                    RegRef {
                        index: 2,
                        width: 32,
                    },
                    crate::ssa::ranges::Fact::constant(value >> 32),
                );
            }
            if convention == Convention::Stdcall {
                let cleanup = arguments.len() as u64 * 4;
                self.return_cleanup = cleanup;
                // Known imported calls already have a stack adjustment in their lifted IR.
                let lifted_cleanup = original
                    .and_then(|address| self.image.callee_cleanup(address))
                    .or_else(|| match through {
                        Some(Expr::Load { addr, .. }) => match addr.as_ref() {
                            Expr::Const(slot) => self
                                .image
                                .imports
                                .get(slot)
                                .and_then(|name| {
                                    crate::analysis::prototypes::i386_import(self.image, name)
                                })
                                .map(|(_, bytes)| bytes),
                            _ => None,
                        },
                        _ => None,
                    })
                    .unwrap_or(0);
                if kind == CallKind::Invoke && lifted_cleanup == 0 && cleanup != 0 {
                    let sp = crate::arch::stack_pointer(self.image.isa);
                    let stack = self.machine.register(sp);
                    let Some(stack) = stack
                        .checked_add(cleanup)
                        .filter(|stack| *stack < 1u64 << 32)
                    else {
                        return Some(Err(Stop::Error("Windows call stack overflows".to_owned())));
                    };
                    self.machine.assign(
                        RegRef {
                            index: sp,
                            width: 32,
                        },
                        stack,
                    );
                }
            }
        }
        Some(Ok(()))
    }

    fn windows_api(&mut self, name: &str, args: &[u64]) -> Result<u64, Stop> {
        let width = crate::arch::pointer_bytes(self.image.isa);
        let mask = crate::ir::semantics::mask(u32::from(width) * 8);
        match name {
            "GetStdHandle" | "WriteFile" | "ReadFile" | "WriteConsoleA" | "WriteConsoleW"
            | "CreateFileA" | "CreateFileW" | "CloseHandle" => self.windows_io(name, args),
            "lstrlenA" | "lstrlenW" | "MultiByteToWideChar" | "WideCharToMultiByte" => {
                self.windows_string_api(name, args)
            }
            "GetProcessHeap" => Ok(self.windows_state().heap),
            "HeapAlloc" | "HeapReAlloc" | "HeapFree" => self.windows_heap(name, args),
            "VirtualAlloc" | "VirtualProtect" | "VirtualFree" => {
                self.windows_virtual_memory(name, args)
            }
            "GetModuleHandleA" | "GetModuleHandleW" | "LoadLibraryA" | "LoadLibraryW" => {
                if args[0] == 0 {
                    return if name.starts_with("GetModule") {
                        Ok(self.windows_state().modules[0].base)
                    } else {
                        self.windows_failure(87)
                    };
                }
                let text = match self.windows_string(args[0], name.ends_with('W')) {
                    Ok(text) => text,
                    Err(stop) => return Err(stop),
                };
                let name = module_name(&text);
                let path = text.replace('/', "\\");
                match self.windows_state().modules.iter().find(|module| {
                    module.name == name
                        && (!path.contains('\\') || module.path.eq_ignore_ascii_case(&path))
                }) {
                    Some(module) => Ok(module.base),
                    None => self.windows_failure(126),
                }
            }
            "GetProcAddress" => {
                let Some(index) = self
                    .windows_state()
                    .modules
                    .iter()
                    .position(|module| module.base == args[0])
                else {
                    return self.windows_failure(6);
                };
                let address = if args[1] <= 0xffff {
                    self.windows_state().modules[index]
                        .exports
                        .values()
                        .find(|(_, ordinal)| u64::from(*ordinal) == args[1])
                        .map(|(address, _)| *address)
                } else {
                    let text = match self.windows_string(args[1], false) {
                        Ok(text) => text,
                        Err(stop) => return Err(stop),
                    };
                    self.windows_state().modules[index]
                        .exports
                        .get(&text)
                        .map(|(address, _)| *address)
                };
                match address {
                    Some(address) => Ok(address),
                    None => self.windows_failure(127),
                }
            }
            "GetCurrentProcessId" => Ok(1000),
            "GetCurrentThreadId" => Ok(self
                .machine
                .load(self.windows_teb() + u64::from(width) * 9, width)),
            "GetCurrentProcess" => Ok(mask),
            "GetCurrentThread" => Ok(mask - 1),
            "ExitProcess" => self.windows_terminate(args[0] as u32),
            "CreateThread" | "ExitThread" | "WaitForSingleObject" | "GetExitCodeThread" => {
                self.windows_thread_api(name, args)
            }
            "GetLastError" => {
                let value = self.machine.load(self.last_error_address(), 4);
                match self.memory_error() {
                    Ok(()) => Ok(value),
                    Err(stop) => Err(stop),
                }
            }
            "SetLastError" => {
                self.set_last_error(args[0] as u32);
                Ok(0)
            }
            "Sleep" => {
                let millis = args[0] as u32;
                if millis == u32::MAX {
                    return Err(Stop::Error("Sleep(INFINITE) does not return".to_owned()));
                }
                let elapsed = self
                    .windows_state()
                    .elapsed
                    .saturating_add(u64::from(millis) * 1_000_000);
                self.windows_state_mut().elapsed = elapsed;
                Ok(0)
            }
            "GetTickCount" | "GetTickCount64" => {
                self.anti_analysis.push(name.to_owned());
                let ticks = self.windows_clock() / 1_000_000;
                Ok(if name == "GetTickCount" {
                    u64::from(ticks as u32)
                } else {
                    ticks
                })
            }
            "QueryPerformanceCounter" | "QueryPerformanceFrequency" | "GetSystemTimeAsFileTime" => {
                let value = match name {
                    "QueryPerformanceFrequency" => 1_000_000_000,
                    "QueryPerformanceCounter" => self.windows_clock(),
                    _ => {
                        let seconds = match &self.options.time {
                            Some(word) => match word.value() {
                                Ok(value) => value,
                                Err(error) => return Err(Stop::Error(error.to_string())),
                            },
                            None => 0,
                        };
                        let value = seconds
                            .checked_add(11_644_473_600)
                            .and_then(|seconds| seconds.checked_mul(10_000_000))
                            .and_then(|ticks| ticks.checked_add(self.windows_clock() / 100));
                        let Some(value) = value else {
                            return Err(Stop::Error("Windows FILETIME overflows".to_owned()));
                        };
                        value
                    }
                };
                if let Err(stop) = self.store_bytes(args[0], &value.to_le_bytes()) {
                    return Err(stop);
                }
                self.anti_analysis.push(name.to_owned());
                Ok(1)
            }
            "IsDebuggerPresent" => {
                self.anti_analysis.push(name.to_owned());
                let register = crate::emulation::tls::register(self.image)
                    .expect("Windows x86 thread register");
                let teb = self.machine.register(register);
                let Some(address) = teb.checked_add(u64::from(width) * 12) else {
                    return Err(Stop::Error("TEB address overflows".to_owned()));
                };
                let peb = self.machine.load(address, width);
                if let Err(stop) = self.memory_error() {
                    return Err(stop);
                }
                let Some(address) = peb.checked_add(2) else {
                    return Err(Stop::Error("PEB address overflows".to_owned()));
                };
                let value = self.machine.load(address, 1);
                match self.memory_error() {
                    Ok(()) => Ok(value),
                    Err(stop) => Err(stop),
                }
            }
            "CheckRemoteDebuggerPresent" => {
                if args[0] != mask {
                    return self.windows_failure(6);
                }
                if args[1] == 0 {
                    return self.windows_failure(87);
                }
                let value = u32::from(self.options.anti_analysis.debugger_present);
                if let Err(stop) = self.store_bytes(args[1], &value.to_le_bytes()) {
                    return Err(stop);
                }
                self.anti_analysis.push(name.to_owned());
                Ok(1)
            }
            "GetCommandLineA" => {
                let pointer = self.windows_state().command_line[0];
                if pointer == 0 {
                    return Err(Stop::Error(
                        "GetCommandLineA requires an ASCII command line".to_owned(),
                    ));
                }
                Ok(pointer)
            }
            "GetCommandLineW" => Ok(self.windows_state().command_line[1]),
            "GetEnvironmentStringsW" => {
                let bytes = self.windows_state().environment_bytes.clone();
                let pointer = self.allocate(bytes.len() as u64);
                if pointer == 0 {
                    return self.windows_failure(8);
                }
                if let Err(stop) = self.store_bytes(pointer, &bytes) {
                    return Err(stop);
                }
                self.windows_state_mut().environment_blocks.insert(pointer);
                Ok(pointer)
            }
            "FreeEnvironmentStringsW" => {
                if !self.windows_state_mut().environment_blocks.remove(&args[0]) {
                    return self.windows_failure(87);
                }
                Ok(1)
            }
            "TlsAlloc" => {
                let Some(index) = self.windows_state().tls_used.iter().position(|used| !used)
                else {
                    self.set_last_error(8);
                    return Ok(u64::from(u32::MAX));
                };
                self.windows_state_mut().tls_used[index] = true;
                let address = self.tls_slot(index);
                self.machine.store(address, 0, width);
                let main_teb = self
                    .machine
                    .strict_memory
                    .as_ref()
                    .expect("strict memory")
                    .tls_base;
                if main_teb != self.windows_teb() {
                    self.machine.store(
                        main_teb
                            + if width == 8 { 0x1480 } else { 0xe10 }
                            + index as u64 * u64::from(width),
                        0,
                        width,
                    );
                }
                Ok(index as u64)
            }
            "TlsFree" | "TlsSetValue" | "TlsGetValue" => {
                let index = args[0] as u32 as usize;
                if index >= 64 || (name == "TlsFree" && !self.windows_state().tls_used[index]) {
                    return self.windows_failure(87);
                }
                let address = self.tls_slot(index);
                if name == "TlsGetValue" {
                    self.set_last_error(0);
                    return Ok(self.machine.load(address, width));
                }
                if name == "TlsFree" {
                    self.windows_state_mut().tls_used[index] = false;
                }
                self.machine.store(
                    address,
                    if name == "TlsSetValue" { args[1] } else { 0 },
                    width,
                );
                Ok(1)
            }
            _ => Err(Stop::Error(format!("unhandled Windows API {name}"))),
        }
    }

    fn tls_slot(&self, index: usize) -> u64 {
        self.windows_teb()
            + if self.image.isa == Isa::X86_64 {
                0x1480
            } else {
                0xe10
            }
            + index as u64 * u64::from(crate::arch::pointer_bytes(self.image.isa))
    }

    fn windows_teb(&self) -> u64 {
        self.machine.register(if self.image.isa == Isa::X86_64 {
            crate::arch::x86::GS_BASE
        } else {
            crate::arch::x86::FS_BASE
        })
    }

    fn windows_check_teb(&self) -> Result<(), Stop> {
        let teb = self.windows_teb();
        if teb != self.windows_state().teb {
            return Err(Stop::Error(format!("invalid Windows TEB at 0x{teb:x}")));
        }
        match self.check_memory_range(teb, 0x2000, /* write */ false) {
            Ok(()) => Ok(()),
            Err(stop) => Err(Stop::Error(format!(
                "invalid Windows TEB at 0x{teb:x}: {stop:?}"
            ))),
        }
    }

    pub(super) fn windows_invoke(
        &mut self,
        callback: u64,
        arguments: &[u64],
        convention: Convention,
    ) -> Result<u64, Stop> {
        let convention = if self.image.isa == Isa::X86_64 {
            Convention::Win64
        } else {
            convention
        };
        let registers = self.machine.registers.clone();
        let facts = self.facts.clone();
        let address = self.address;
        let cleanup = self.return_cleanup;
        let width = crate::arch::pointer_bytes(self.image.isa);
        let sp = crate::arch::stack_pointer(self.image.isa);
        let Some(stack) = self.machine.register(sp).checked_sub(0x100) else {
            return Err(Stop::Error("Windows callback stack underflows".to_owned()));
        };
        let stack = stack & !15;
        self.assign_fact(
            RegRef {
                index: sp,
                width: width * 8,
            },
            Fact::constant(stack),
        );
        for (index, &value) in arguments.iter().enumerate() {
            if let Some(&register) = convention.arguments().get(index) {
                self.assign_fact(
                    RegRef {
                        index: register,
                        width: width * 8,
                    },
                    Fact::constant(value),
                );
            } else {
                let offset = if width == 8 {
                    32 + (index - 4) * 8
                } else {
                    index * 4
                };
                self.machine.store(stack + offset as u64, value, width);
            }
        }
        if let Err(stop) = self.call(callback, convention, CallKind::Invoke, 0) {
            return Err(stop);
        }
        let value = self.machine.register(crate::arch::RETURN);
        self.machine.registers = registers;
        self.facts = facts;
        self.address = address;
        self.return_cleanup = cleanup;
        Ok(value)
    }

    pub(super) fn windows_callbacks(&mut self, reason: TlsReason) -> Result<(), Stop> {
        let Some(state) = &self.windows else {
            return Ok(());
        };
        let callbacks = state.callbacks.clone();
        let base = state.modules[0].base;
        let (reason, reserved) = match reason {
            TlsReason::ProcessAttach => (1, 0),
            TlsReason::ProcessDetach => (0, 1),
            TlsReason::ThreadAttach => (2, 0),
            TlsReason::ThreadDetach => (3, 0),
        };
        for callback in callbacks {
            if let Err(stop) =
                self.windows_invoke(callback, &[base, reason, reserved], Convention::Stdcall)
            {
                return Err(stop);
            }
        }
        Ok(())
    }
}

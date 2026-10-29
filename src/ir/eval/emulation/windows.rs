//! Deterministic Windows process state and user-mode API calls.

mod loader;
mod memory;

use std::collections::{BTreeMap, BTreeSet};

use crate::emulation::ApiCall;
use crate::ir::{CallKind, Convention, Expr, RegRef};
use crate::loader::Isa;

use super::{Runner, Stop};

pub(super) struct Process {
    modules: Vec<Module>,
    exports: BTreeMap<u64, Export>,
    callbacks: Vec<u64>,
    command_line: [u64; 2],
    environment_bytes: Vec<u8>,
    environment_blocks: BTreeSet<u64>,
    elapsed: u64,
    tls_used: [bool; 64],
    heap: u64,
    heap_blocks: BTreeMap<u64, memory::HeapBlock>,
    virtual_allocations: BTreeMap<u64, memory::Allocation>,
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
];

const CRT_APIS: &[(&str, usize)] = &[
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
];

fn kernel(dll: &str) -> bool {
    matches!(dll, "kernel32.dll" | "kernelbase.dll")
}

fn crt(dll: &str) -> bool {
    matches!(dll, "msvcrt.dll" | "ucrtbase.dll") || dll.starts_with("api-ms-win-crt-")
}

fn signature(export: &Export) -> Option<usize> {
    let table = if kernel(&export.dll) {
        APIS
    } else if crt(&export.dll) {
        CRT_APIS
    } else {
        return None;
    };
    table
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
        self.machine
            .strict_memory
            .as_ref()
            .expect("strict memory")
            .tls_base
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
        let mut units = Vec::new();
        for offset in (0..super::HEAP_SIZE).step_by(2) {
            let Some(at) = address.checked_add(offset) else {
                return Err(Stop::Error("UTF-16 string address overflows".to_owned()));
            };
            let low = match self.read_byte(at) {
                Ok(byte) => byte,
                Err(stop) => return Err(stop),
            };
            let Some(high_address) = at.checked_add(1) else {
                return Err(Stop::Error("UTF-16 string address overflows".to_owned()));
            };
            let high = match self.read_byte(high_address) {
                Ok(byte) => byte,
                Err(stop) => return Err(stop),
            };
            let unit = u16::from_le_bytes([low, high]);
            if unit == 0 {
                return match String::from_utf16(&units) {
                    Ok(text) => Ok(text),
                    Err(_) => Err(Stop::Error("invalid UTF-16 string".to_owned())),
                };
            }
            units.push(unit);
        }
        Err(Stop::Error("UTF-16 string exceeds 16 MiB".to_owned()))
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
            for index in 0..count {
                match self.argument(index, convention, kind) {
                    Ok(value) => arguments.push(value),
                    Err(stop) => return Some(Err(stop)),
                }
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
        let result = if let Some(word) = override_value {
            match word.value() {
                Ok(value) => Ok(value),
                Err(error) => Err(Stop::Error(error.to_string())),
            }
        } else if kernel(&export.dll) && signature(&export).is_some() {
            self.windows_api(&export.name, &arguments)
        } else if crt(&export.dll) {
            match super::hooks::find(&export.name) {
                Some(hook) => self.hook(hook, convention, kind, depth),
                None if self.options.skip_calls => Ok(0),
                None => Err(Stop::Error(format!("unhandled Windows API {qualified}"))),
            }
        } else if self.options.skip_calls {
            Ok(0)
        } else {
            Err(Stop::Error(format!("unhandled Windows API {qualified}")))
        };
        let value = match result {
            Ok(value) => value,
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
            "GetCurrentThreadId" => Ok(1001),
            "GetCurrentProcess" => Ok(mask),
            "GetCurrentThread" => Ok(mask - 1),
            "ExitProcess" => {
                self.assign_fact(
                    RegRef {
                        index: crate::arch::RETURN,
                        width: 32,
                    },
                    crate::ssa::ranges::Fact::constant(u64::from(args[0] as u32)),
                );
                Err(Stop::Exit)
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
        self.machine
            .strict_memory
            .as_ref()
            .expect("strict memory")
            .tls_base
            + if self.image.isa == Isa::X86_64 {
                0x1480
            } else {
                0xe10
            }
            + index as u64 * u64::from(crate::arch::pointer_bytes(self.image.isa))
    }

    pub(super) fn windows_callbacks(&mut self) -> Result<(), Stop> {
        let Some(state) = &self.windows else {
            return Ok(());
        };
        let callbacks = state.callbacks.clone();
        let base = state.modules[0].base;
        let registers = self.machine.registers.clone();
        let facts = self.facts.clone();
        let address = self.address;
        let width = crate::arch::pointer_bytes(self.image.isa);
        let sp = crate::arch::stack_pointer(self.image.isa);
        let stack = self.machine.register(sp).saturating_sub(0x100) & !15;
        for callback in callbacks {
            self.machine.registers = registers.clone();
            self.facts = facts.clone();
            self.machine.registers.insert(sp, stack);
            let convention = if width == 8 {
                Convention::Win64
            } else {
                Convention::Stdcall
            };
            for (index, value) in [base, 1, 0].into_iter().enumerate() {
                if let Some(&register) = convention.arguments().get(index) {
                    self.machine.assign(
                        RegRef {
                            index: register,
                            width: width * 8,
                        },
                        value,
                    );
                } else {
                    self.machine.store(stack + index as u64 * 4, value, 4);
                }
            }
            if let Err(stop) = self.call(callback, convention, CallKind::Invoke, 0) {
                return Err(stop);
            }
        }
        self.machine.registers = registers;
        self.facts = facts;
        self.address = address;
        Ok(())
    }
}

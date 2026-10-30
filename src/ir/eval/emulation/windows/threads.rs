//! Deterministic execution of a Windows thread when its handle is waited on.

use crate::ir::{Convention, RegRef};
use crate::ssa::ranges::Fact;

use super::{Runner, Stop, TlsReason};

pub(super) struct Thread {
    start: u64,
    parameter: u64,
    id: u32,
    exit: Option<u32>,
}

impl Thread {
    pub(super) fn finished(&self) -> bool {
        self.exit.is_some()
    }
}

impl Runner<'_> {
    pub(super) fn windows_thread_api(&mut self, name: &str, args: &[u64]) -> Result<u64, Stop> {
        match name {
            "CreateThread" => {
                if args[0] != 0 || args[1] != 0 || args[4] != 0 {
                    return Err(Stop::Error(
                        "CreateThread security attributes, stack sizes and flags are unsupported"
                            .to_owned(),
                    ));
                }
                if !self
                    .image
                    .section_at(args[2])
                    .is_some_and(|section| section.executable)
                {
                    return Err(Stop::Error(format!(
                        "CreateThread entry at 0x{:x} is not executable",
                        args[2]
                    )));
                }
                if self.windows_state().threads.len() >= 128 {
                    return Err(Stop::Error(
                        "Windows thread handles exceed 128 entries".to_owned(),
                    ));
                }
                if args[5] != 0
                    && let Err(stop) = self.check_memory_range(args[5], 4, /* write */ true)
                {
                    return Err(stop);
                }
                let handle = self.allocate(1);
                let id = self.windows_state().next_thread_id;
                let Some(next) = id.checked_add(1) else {
                    return self.windows_failure(8);
                };
                if handle == 0 {
                    return self.windows_failure(8);
                }
                self.windows_state_mut().next_thread_id = next;
                self.windows_state_mut().threads.insert(
                    handle,
                    Thread {
                        start: args[2],
                        parameter: args[3],
                        id,
                        exit: None,
                    },
                );
                if args[5] != 0 {
                    self.machine.store(args[5], u64::from(id), 4);
                }
                Ok(handle)
            }
            "ExitThread" => {
                if self.windows_state().active_thread.is_none() {
                    return Err(Stop::Error(
                        "ExitThread on the initial thread is unsupported".to_owned(),
                    ));
                }
                Err(Stop::ThreadExit(args[0] as u32))
            }
            "GetExitCodeThread" => {
                let mask = crate::ir::semantics::mask(
                    u32::from(crate::arch::pointer_bytes(self.image.isa)) * 8,
                );
                if args[0] == mask - 1 {
                    return match self.store_bytes(args[1], &259u32.to_le_bytes()) {
                        Ok(()) => Ok(1),
                        Err(stop) => Err(stop),
                    };
                }
                let handle = self.thread_handle(args[0]);
                let Some(thread) = self.windows_state().threads.get(&handle) else {
                    return self.windows_failure(6);
                };
                let exit = thread.exit.unwrap_or(259);
                match self.store_bytes(args[1], &exit.to_le_bytes()) {
                    Ok(()) => Ok(1),
                    Err(stop) => Err(stop),
                }
            }
            "WaitForSingleObject" => {
                let mask = crate::ir::semantics::mask(
                    u32::from(crate::arch::pointer_bytes(self.image.isa)) * 8,
                );
                if args[0] == mask - 1 {
                    if args[1] as u32 == 0 {
                        return Ok(258);
                    }
                    return Err(Stop::Error(
                        "a Windows thread cannot wait for its own termination".to_owned(),
                    ));
                }
                let handle = self.thread_handle(args[0]);
                let Some(thread) = self.windows_state().threads.get(&handle) else {
                    self.set_last_error(6);
                    return Ok(u64::from(u32::MAX));
                };
                if thread.exit.is_some() {
                    return Ok(0);
                }
                if self.windows_state().active_thread == Some(handle) {
                    if args[1] as u32 == 0 {
                        return Ok(258);
                    }
                    return Err(Stop::Error(
                        "a Windows thread cannot wait for its own termination".to_owned(),
                    ));
                }
                if args[1] as u32 == 0 {
                    return Ok(258);
                }
                if args[1] as u32 != u32::MAX {
                    return Err(Stop::Error(
                        "Windows thread waits require zero or INFINITE timeout".to_owned(),
                    ));
                }
                match self.windows_run_thread(handle) {
                    Ok(()) => Ok(0),
                    Err(stop) => Err(stop),
                }
            }
            _ => unreachable!("thread API dispatch"),
        }
    }

    fn thread_handle(&self, handle: u64) -> u64 {
        let mask =
            crate::ir::semantics::mask(u32::from(crate::arch::pointer_bytes(self.image.isa)) * 8);
        if handle == mask - 1 {
            self.windows_state().active_thread.unwrap_or(handle)
        } else {
            handle
        }
    }

    fn windows_run_thread(&mut self, handle: u64) -> Result<(), Stop> {
        if self.windows_state().active_thread.is_some() {
            return Err(Stop::Error(
                "nested Windows thread waits are unsupported".to_owned(),
            ));
        }
        let thread = &self.windows_state().threads[&handle];
        let (start, parameter, id) = (thread.start, thread.parameter, thread.id);
        let width = crate::arch::pointer_bytes(self.image.isa);
        let parent_teb = self.windows_teb();
        let peb = self.machine.load(parent_teb + u64::from(width) * 12, width);
        let memory = self.machine.strict_memory.as_mut().expect("strict memory");
        let teb = match memory.map_zeroed(0x2000, /* read_only */ false) {
            Ok(teb) => teb,
            Err(error) => return Err(Stop::Error(error)),
        };
        let stack = match memory.map_zeroed(1 << 20, /* read_only */ false) {
            Ok(stack) => stack,
            Err(error) => return Err(Stop::Error(error)),
        };
        let saved_registers = self.machine.registers.clone();
        let saved_facts = self.facts.clone();
        let saved_address = self.address;
        let saved_cleanup = self.return_cleanup;
        self.machine.registers.clear();
        self.facts.clear();
        for register in super::super::physical_registers(self.image.isa) {
            self.machine.registers.insert(register, 0);
        }
        self.machine
            .registers
            .insert(crate::lift::execution::DIRECTION, 0);
        let tls_register =
            crate::emulation::tls::register(self.image).expect("Windows TLS register");
        self.machine.registers.insert(tls_register, teb);
        let stack_end = stack + (1 << 20);
        for (offset, value) in [
            (0, if width == 4 { u64::from(u32::MAX) } else { 0 }),
            (u64::from(width), stack_end),
            (u64::from(width) * 2, stack),
            (u64::from(width) * 6, teb),
            (u64::from(width) * 8, 1000),
            (u64::from(width) * 9, u64::from(id)),
            (u64::from(width) * 12, peb),
        ] {
            self.machine.store(teb + offset, value, width);
        }
        self.assign_fact(
            RegRef {
                index: crate::arch::stack_pointer(self.image.isa),
                width: width * 8,
            },
            Fact::constant(stack_end - 0x100),
        );
        let tls = self.windows_state().tls_directory;
        if let Err(error) = self.setup_static_tls(tls, teb) {
            return Err(Stop::Error(error));
        }
        self.windows_state_mut().active_thread = Some(handle);
        self.windows_state_mut().teb = teb;
        if let Err(stop) = self.windows_callbacks(TlsReason::ThreadAttach) {
            return Err(stop);
        }
        let exit = match self.windows_invoke(start, &[parameter], Convention::Stdcall) {
            Ok(value) => value as u32,
            Err(Stop::ThreadExit(code)) => code,
            Err(stop) => return Err(stop),
        };
        if let Err(stop) = self.windows_callbacks(TlsReason::ThreadDetach) {
            return Err(stop);
        }
        if let Some(thread) = self.windows_state_mut().threads.get_mut(&handle) {
            thread.exit = Some(exit);
        }
        self.windows_state_mut().active_thread = None;
        self.windows_state_mut().teb = parent_teb;
        self.machine.registers = saved_registers;
        self.facts = saved_facts;
        self.address = saved_address;
        self.return_cleanup = saved_cleanup;
        let memory = self.machine.strict_memory.as_mut().expect("strict memory");
        memory.unmap(teb);
        memory.unmap(stack);
        self.machine.memory.retain(|&address, _| {
            !(teb..teb + 0x2000).contains(&address) && !(stack..stack_end).contains(&address)
        });
        Ok(())
    }
}

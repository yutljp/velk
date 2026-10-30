//! Dispatches hardware exceptions to registered Windows handlers.

mod unwind;

use std::collections::{HashMap, HashSet};

use crate::ir::{Convention, RegRef};
use crate::loader::Isa;
use crate::ssa::ranges::Fact;

use super::{Runner, Stop};

#[derive(Debug)]
pub(in crate::ir::eval::emulation) struct Exception {
    pub(in crate::ir::eval::emulation) code: u32,
    pub(in crate::ir::eval::emulation) access: Option<(u64, bool)>,
    pub(in crate::ir::eval::emulation) message: String,
}

pub(super) struct State {
    registers: HashMap<u16, u64>,
    facts: HashMap<u16, Fact>,
}

struct Context {
    address: u64,
    bytes: Vec<u8>,
    supported: Vec<bool>,
}

fn register_offset(index: u16, width: u8) -> usize {
    if width == 8 {
        120 + usize::from(index) * 8
    } else {
        [176, 172, 168, 164, 196, 180, 160, 156][usize::from(index)]
    }
}

fn put(bytes: &mut [u8], offset: usize, value: u64, width: u8) {
    bytes[offset..offset + usize::from(width)]
        .copy_from_slice(&value.to_le_bytes()[..usize::from(width)]);
}

fn context_word(memory: &HashMap<u64, u8>, address: u64, width: u8) -> u64 {
    let mut bytes = [0; 8];
    for offset in 0..width {
        bytes[usize::from(offset)] = *memory
            .get(&(address + u64::from(offset)))
            .expect("context bytes are initialized before dispatch");
    }
    u64::from_le_bytes(bytes)
}

impl Runner<'_> {
    fn restore_context_register(&mut self, index: u16, width: u8, value: u64) {
        let fact = match self.facts.get(&index) {
            Some(fact) => {
                let known = fact.zeros | fact.ones;
                Fact::bits(!value & known, value & known)
                    .expect("clear and set context bits are disjoint")
            }
            None => Fact::constant(value),
        };
        self.assign_fact(RegRef { index, width }, fact);
    }

    pub(in crate::ir::eval::emulation) fn windows_instruction_state(&mut self) {
        if let Some(state) = &mut self.windows {
            state.instruction_state = Some(State {
                registers: self.machine.registers.clone(),
                facts: self.facts.clone(),
            });
        }
    }

    pub(in crate::ir::eval::emulation) fn windows_divide_fault(&self) -> Stop {
        Stop::Exception(Exception {
            code: 0xc0000094,
            access: None,
            message: "division by zero".to_owned(),
        })
    }

    fn exception_context(&mut self) -> Result<Context, Stop> {
        let width = crate::arch::pointer_bytes(self.image.isa);
        let mut bytes = vec![0; if width == 8 { 1232 } else { 716 }];
        let mut supported = vec![false; bytes.len()];
        let flags_offset = if width == 8 { 48 } else { 0 };
        put(
            &mut bytes,
            flags_offset,
            if width == 8 { 0x10000b } else { 0x10023 },
            4,
        );
        supported[flags_offset..flags_offset + 4].fill(true);
        for index in 0..if width == 8 { 16 } else { 8 } {
            let offset = register_offset(index, width);
            let value = self.machine.register(index);
            put(&mut bytes, offset, value, width);
            supported[offset..offset + usize::from(width)].fill(true);
        }
        let ip = if width == 8 { 248 } else { 184 };
        put(&mut bytes, ip, self.address, width);
        supported[ip..ip + usize::from(width)].fill(true);
        let vectors = if width == 8 { 416 } else { 364 };
        for index in 0..if width == 8 { 32 } else { 16 } {
            let value = self.machine.register(crate::arch::x86::XMM0 + index);
            put(&mut bytes, vectors + usize::from(index) * 8, value, 8);
        }
        supported[vectors..vectors + if width == 8 { 256 } else { 128 }].fill(true);
        let context = self.allocate(bytes.len() as u64);
        if context == 0 {
            return Err(Stop::Error("SEH context allocation failed".to_owned()));
        }
        if let Err(stop) = self.store_bytes(context, &bytes) {
            return Err(stop);
        }
        let memory = self.machine.strict_memory.as_mut().expect("strict memory");
        memory.restrict_write(context + flags_offset as u64, 4);
        for (&index, fact) in &self.facts {
            if fact.singleton().is_some() {
                continue;
            }
            if index < if width == 8 { 16 } else { 8 } {
                memory.restrict_read(
                    context + register_offset(index, width) as u64,
                    u64::from(width),
                );
            } else if (crate::arch::x86::XMM0
                ..crate::arch::x86::XMM0 + if width == 8 { 32 } else { 16 })
                .contains(&index)
            {
                memory.restrict_read(
                    context + vectors as u64 + u64::from(index - crate::arch::x86::XMM0) * 8,
                    8,
                );
            }
        }
        let mut start = 0;
        while start < supported.len() {
            if supported[start] {
                start += 1;
                continue;
            }
            let mut end = start + 1;
            while end < supported.len() && !supported[end] {
                end += 1;
            }
            memory.restrict_read(context + start as u64, (end - start) as u64);
            memory.restrict_write(context + start as u64, (end - start) as u64);
            start = end;
        }
        Ok(Context {
            address: context,
            bytes,
            supported,
        })
    }

    fn resume_exception(
        &mut self,
        context: u64,
        bytes: &[u8],
        supported: &[bool],
    ) -> Result<u64, Stop> {
        for (offset, &byte) in bytes.iter().enumerate() {
            if !supported[offset]
                && self.machine.memory.get(&(context + offset as u64)) != Some(&byte)
            {
                return Err(Stop::Error(
                    "SEH handler modified an unsupported CONTEXT field".to_owned(),
                ));
            }
        }
        let width = crate::arch::pointer_bytes(self.image.isa);
        for index in 0..if width == 8 { 16 } else { 8 } {
            let value = context_word(
                &self.machine.memory,
                context + register_offset(index, width) as u64,
                width,
            );
            self.restore_context_register(index, width * 8, value);
        }
        let vectors = if width == 8 { 416 } else { 364 };
        for index in 0..if width == 8 { 32 } else { 16 } {
            let value = context_word(
                &self.machine.memory,
                context + vectors + u64::from(index) * 8,
                8,
            );
            let register = crate::arch::x86::XMM0 + index;
            self.restore_context_register(register, 64, value);
        }
        let target = context_word(
            &self.machine.memory,
            context + if width == 8 { 248 } else { 184 },
            width,
        );
        if let Err(stop) = self.memory_error() {
            return Err(stop);
        }
        if !self
            .image
            .section_at(target)
            .is_some_and(|section| section.executable)
        {
            return Err(Stop::Error(format!(
                "SEH continuation at 0x{target:x} is not executable"
            )));
        }
        Ok(target)
    }

    pub(in crate::ir::eval::emulation) fn windows_exception(
        &mut self,
        exception: Exception,
    ) -> Result<u64, Stop> {
        if let Err(stop) = self.windows_check_teb() {
            return Err(stop);
        }
        if self.x86_instruction().is_ok_and(|instruction| {
            instruction.has_rep_prefix()
                || instruction.has_repne_prefix()
                || (self.image.isa == Isa::X86_64
                    && matches!(
                        instruction.mnemonic(),
                        iced_x86::Mnemonic::Ret | iced_x86::Mnemonic::Pop
                    ))
        }) {
            return Err(Stop::Error(
                "SEH for repeated instructions and x64 epilogues is unsupported".to_owned(),
            ));
        }
        if self.windows_state().exception_active {
            return Err(Stop::Error(format!(
                "nested Windows exception 0x{:08x} is unsupported: {}",
                exception.code, exception.message
            )));
        }
        self.windows_state_mut().exception_active = true;
        if let Some(state) = self.windows_state_mut().instruction_state.take() {
            self.machine.registers = state.registers;
            self.facts = state.facts;
        }
        let context = match self.exception_context() {
            Ok(context) => context,
            Err(stop) => return Err(stop),
        };
        let width = crate::arch::pointer_bytes(self.image.isa);
        let mut record_bytes = vec![0; if width == 8 { 152 } else { 80 }];
        put(&mut record_bytes, 0, u64::from(exception.code), 4);
        put(
            &mut record_bytes,
            if width == 8 { 16 } else { 12 },
            self.address,
            width,
        );
        if let Some((address, write)) = exception.access {
            put(&mut record_bytes, if width == 8 { 24 } else { 16 }, 2, 4);
            put(
                &mut record_bytes,
                if width == 8 { 32 } else { 20 },
                u64::from(write),
                width,
            );
            put(
                &mut record_bytes,
                if width == 8 { 40 } else { 24 },
                address,
                width,
            );
        }
        let record = self.allocate(record_bytes.len() as u64);
        if record == 0 {
            return Err(Stop::Error("SEH record allocation failed".to_owned()));
        }
        if let Err(stop) = self.store_bytes(record, &record_bytes) {
            return Err(stop);
        }
        let handled = if self.image.isa == Isa::I386 {
            self.windows_exception_chain(record, context.address)
        } else {
            self.windows_exception_table(record, context.address)
        };
        self.windows_state_mut().exception_active = false;
        match handled {
            Ok(true) => self.resume_exception(context.address, &context.bytes, &context.supported),
            Ok(false) => Err(Stop::Error(format!(
                "unhandled Windows exception 0x{:08x}: {}",
                exception.code, exception.message
            ))),
            Err(Stop::Exception(exception)) => Err(Stop::Error(format!(
                "SEH dispatch failed: {}",
                exception.message
            ))),
            Err(stop) => Err(stop),
        }
    }

    fn windows_exception_chain(&mut self, record: u64, context: u64) -> Result<bool, Stop> {
        let teb = self.machine.register(crate::arch::x86::FS_BASE);
        let mut frame = self.machine.load(teb, 4);
        if let Err(stop) = self.memory_error() {
            return Err(stop);
        }
        let mut visited = HashSet::new();
        let stack_end = self.machine.load(teb + 4, 4);
        let stack_start = self.machine.load(teb + 8, 4);
        while frame != u64::from(u32::MAX) {
            if frame < stack_start
                || frame.checked_add(8).is_none_or(|end| end > stack_end)
                || frame & 3 != 0
                || !visited.insert(frame)
                || visited.len() > 128
            {
                return Err(Stop::Error(format!(
                    "invalid SEH registration chain at 0x{frame:x}"
                )));
            }
            if let Err(stop) = self.check_memory_range(frame, 8, /* write */ false) {
                return Err(stop);
            }
            let handler = self.machine.load(frame + 4, 4);
            let result =
                match self.windows_invoke(handler, &[record, frame, context, 0], Convention::Cdecl)
                {
                    Ok(result) => result,
                    Err(stop) => return Err(stop),
                };
            match result as u32 {
                0 => return Ok(true),
                1 => {
                    frame = self.machine.load(frame, 4);
                    if let Err(stop) = self.memory_error() {
                        return Err(stop);
                    }
                }
                value => return Err(Stop::Error(format!("unsupported SEH disposition {value}"))),
            }
        }
        Ok(false)
    }
}

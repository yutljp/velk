//! Searches x64 exception tables using version-one unwind codes.

use crate::ir::Convention;
use crate::loader::{Image, image_reads};

use super::{Runner, Stop};

struct Frame {
    base: u64,
    entry: u64,
    begin: u64,
    end: u64,
    unwind: u64,
}

fn invalid(message: &str, address: u64) -> Stop {
    Stop::Error(format!("{message} at 0x{address:x}"))
}

fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from(u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("bounded PE field"),
    ))
}

fn epilogue(image: &Image, frame: &Frame, frame_register: usize, mut pc: u64) -> bool {
    use iced_x86::{Mnemonic, OpKind, Register};

    for index in 0..32 {
        let Ok(instruction) = crate::ir::eval::emulation::x86_instruction_at(image, pc) else {
            return false;
        };
        let Some(bytes) = image_reads::bounded_bytes(image, pc, instruction.len() as u64) else {
            return false;
        };
        let opcode = if bytes[0] & 0xf0 == 0x40 {
            bytes.get(1).copied()
        } else {
            Some(bytes[0])
        };
        if !matches!(
            opcode,
            Some(0x58..=0x5f | 0x81 | 0x83 | 0x8d | 0xc2 | 0xc3 | 0xe9 | 0xeb)
        ) && bytes != [0xf3, 0xc3]
        {
            return false;
        }
        match instruction.mnemonic() {
            Mnemonic::Add
                if index == 0
                    && instruction.op0_register() == Register::RSP
                    && matches!(
                        instruction.op1_kind(),
                        OpKind::Immediate8to64 | OpKind::Immediate32to64
                    ) => {}
            Mnemonic::Lea
                if index == 0
                    && instruction.op0_register() == Register::RSP
                    && frame_register != 0
                    && instruction.memory_base().is_gpr64()
                    && instruction.memory_base().number() == frame_register
                    && instruction.memory_index() == Register::None => {}
            Mnemonic::Pop
                if instruction.op0_kind() == OpKind::Register
                    && instruction.op0_register().is_gpr64() => {}
            Mnemonic::Ret => return true,
            Mnemonic::Jmp
                if instruction.op0_kind() == OpKind::NearBranch64
                    && (instruction.near_branch_target() < frame.begin
                        || instruction.near_branch_target() >= frame.end) =>
            {
                return true;
            }
            _ => return false,
        }
        pc = instruction.next_ip();
        if pc >= frame.end {
            return false;
        }
    }
    false
}

impl Runner<'_> {
    fn exception_frame(&self, pc: u64) -> Result<Option<Frame>, Stop> {
        let Some((base, entries)) = crate::loader::seh::exception_directory(self.image) else {
            return Ok(None);
        };
        if !entries.len().is_multiple_of(12) || entries.len() / 12 > 65536 {
            return Err(invalid("invalid PE exception directory", pc));
        }
        for row in entries.as_chunks::<12>().0 {
            let (Some(begin), Some(end), Some(unwind)) = (
                base.checked_add(word(row, 0)),
                base.checked_add(word(row, 4)),
                base.checked_add(word(row, 8)),
            ) else {
                return Err(invalid("PE exception entry overflows", pc));
            };
            if begin >= end {
                return Err(invalid("invalid PE exception entry", pc));
            }
            if begin <= pc && pc < end {
                if begin >= end || word(row, 8) & 3 != 0 {
                    return Err(invalid("invalid PE exception entry", pc));
                }
                // The dispatcher receives the mapped RUNTIME_FUNCTION entry.
                let Some(image_start) = self.image.read(self.image.slice_offset, 0) else {
                    return Err(invalid("missing PE image", pc));
                };
                let Some(offset) =
                    (row.as_ptr() as usize).checked_sub(image_start.as_ptr() as usize)
                else {
                    return Err(invalid("unmapped PE exception entry", pc));
                };
                let mut entry = None;
                for section in &self.image.sections {
                    let Some(start) = section.file_offset else {
                        continue;
                    };
                    let Some(displacement) = (offset as u64)
                        .checked_add(self.image.slice_offset)
                        .and_then(|offset| offset.checked_sub(start))
                    else {
                        continue;
                    };
                    if section.loaded && displacement < self.image.section_file_size(section) {
                        entry = section.vaddr.checked_add(displacement);
                        break;
                    }
                }
                let Some(entry) = entry else {
                    return Err(invalid("unmapped PE exception entry", pc));
                };
                return Ok(Some(Frame {
                    base,
                    entry,
                    begin,
                    end,
                    unwind,
                }));
            }
        }
        Ok(None)
    }

    fn unwind_word(&self, address: u64, width: u8) -> Result<u64, Stop> {
        let value = self.machine.load(address, width);
        match self.memory_error() {
            Ok(()) => Ok(value),
            Err(stop) => Err(stop),
        }
    }

    pub(super) fn windows_exception_table(
        &mut self,
        record: u64,
        context: u64,
    ) -> Result<bool, Stop> {
        let mut registers = [0; 16];
        for (index, value) in registers.iter_mut().enumerate() {
            *value = self.machine.register(index as u16);
        }
        let mut pc = self.address;
        let teb = self.windows_teb();
        let stack_end = self.machine.load(teb + 8, 8);
        let stack_start = self.machine.load(teb + 16, 8);
        for _ in 0..128 {
            if pc == 0 {
                return Ok(false);
            }
            if registers[4] < stack_start
                || registers[4]
                    .checked_add(8)
                    .is_none_or(|end| end > stack_end)
            {
                return Err(invalid("invalid SEH stack", registers[4]));
            }
            let frame = match self.exception_frame(pc) {
                Ok(frame) => frame,
                Err(stop) => return Err(stop),
            };
            let Some(frame) = frame else {
                pc = match self.unwind_word(registers[4], 8) {
                    Ok(value) => value,
                    Err(stop) => return Err(stop),
                };
                let Some(stack) = registers[4].checked_add(8) else {
                    return Err(invalid("SEH stack overflows", registers[4]));
                };
                registers[4] = stack;
                continue;
            };
            let Some(header) = image_reads::bounded_bytes(self.image, frame.unwind, 4) else {
                return Err(invalid("missing UNWIND_INFO", frame.unwind));
            };
            let flags = header[0] >> 3;
            if header[0] & 7 != 1 || flags & !3 != 0 {
                return Err(invalid(
                    "unsupported UNWIND_INFO version or flags",
                    frame.unwind,
                ));
            }
            let count = usize::from(header[2]);
            let Some(codes_address) = frame.unwind.checked_add(4) else {
                return Err(invalid("unwind codes overflow", frame.unwind));
            };
            let Some(codes) =
                image_reads::bounded_bytes(self.image, codes_address, count as u64 * 2)
            else {
                return Err(invalid("truncated unwind codes", frame.unwind));
            };
            let offset = pc - frame.begin;
            let frame_register = usize::from(header[3] & 15);
            let frame_offset = u64::from(header[3] >> 4) * 16;
            if offset < u64::from(header[1]) {
                return Err(invalid("SEH in an x64 prologue is unsupported", pc));
            }
            let in_epilogue = count != 0 && epilogue(self.image, &frame, frame_register, pc);
            if in_epilogue && pc == self.address {
                return Err(invalid("SEH in an x64 epilogue is unsupported", pc));
            }
            let establisher = if frame_register == 0 {
                registers[4]
            } else {
                let Some(value) = registers[frame_register].checked_sub(frame_offset) else {
                    return Err(invalid("SEH frame underflows", pc));
                };
                value
            };
            let mut index = 0;
            while index < count {
                let operation = codes[index * 2 + 1] & 15;
                let info = codes[index * 2 + 1] >> 4;
                let slots = match operation {
                    0 | 2 | 3 => 1,
                    1 if info == 0 => 2,
                    4 => 2,
                    _ => return Err(invalid("unsupported unwind operation", frame.unwind)),
                };
                if index + slots > count {
                    return Err(invalid("truncated unwind operation", frame.unwind));
                }
                let operand = if slots > 1 {
                    u64::from(u16::from_le_bytes([
                        codes[(index + 1) * 2],
                        codes[(index + 1) * 2 + 1],
                    ]))
                } else {
                    0
                };
                if codes[index * 2] > header[1]
                    || (matches!(operation, 0 | 4) && !matches!(info, 3 | 5 | 6 | 7 | 12..=15))
                    || (operation == 3 && (info != 0 || frame_register == 0))
                {
                    return Err(invalid("invalid unwind operation", frame.unwind));
                }
                match operation {
                    0 => {
                        registers[usize::from(info)] = match self.unwind_word(registers[4], 8) {
                            Ok(value) => value,
                            Err(stop) => return Err(stop),
                        };
                        let Some(stack) = registers[4].checked_add(8) else {
                            return Err(invalid("SEH stack overflows", pc));
                        };
                        registers[4] = stack;
                    }
                    1 | 2 => {
                        let size = if operation == 2 {
                            u64::from(info) * 8 + 8
                        } else {
                            operand * 8
                        };
                        let Some(stack) = registers[4].checked_add(size) else {
                            return Err(invalid("SEH stack overflows", pc));
                        };
                        registers[4] = stack;
                    }
                    3 => registers[4] = establisher,
                    4 => {
                        let offset = operand * 8;
                        let Some(address) = establisher.checked_add(offset) else {
                            return Err(invalid("SEH saved register overflows", pc));
                        };
                        registers[usize::from(info)] = match self.unwind_word(address, 8) {
                            Ok(value) => value,
                            Err(stop) => return Err(stop),
                        };
                    }
                    _ => unreachable!("unwind operation was validated"),
                }
                index += slots;
            }
            if flags & 1 != 0 && !in_epilogue {
                let Some(handler_field) = codes_address.checked_add((count as u64).div_ceil(2) * 4)
                else {
                    return Err(invalid("SEH handler field overflows", frame.unwind));
                };
                let Some(handler_rva) = image_reads::word(self.image, handler_field, 4) else {
                    return Err(invalid("missing unwind handler field", handler_field));
                };
                let Some(handler) = frame.base.checked_add(handler_rva) else {
                    return Err(invalid("SEH handler overflows", handler_field));
                };
                let dispatcher = self.allocate(80);
                if dispatcher == 0 {
                    return Err(invalid("SEH dispatcher allocation failed", pc));
                }
                for (index, value) in [
                    pc,
                    frame.base,
                    frame.entry,
                    establisher,
                    0,
                    context,
                    handler,
                    handler_field + 4,
                    0,
                    0,
                ]
                .into_iter()
                .enumerate()
                {
                    self.machine.store(dispatcher + index as u64 * 8, value, 8);
                }
                if let Err(stop) = self.memory_error() {
                    return Err(stop);
                }
                self.machine
                    .strict_memory
                    .as_mut()
                    .expect("strict memory")
                    .restrict_read(dispatcher + 40, 8);
                let result = match self.windows_invoke(
                    handler,
                    &[record, establisher, context, dispatcher],
                    Convention::Win64,
                ) {
                    Ok(result) => result,
                    Err(stop) => return Err(stop),
                };
                match result as u32 {
                    0 => return Ok(true),
                    1 => {}
                    value => {
                        return Err(Stop::Error(format!("unsupported SEH disposition {value}")));
                    }
                }
            }
            pc = match self.unwind_word(registers[4], 8) {
                Ok(value) => value,
                Err(stop) => return Err(stop),
            };
            let Some(stack) = registers[4].checked_add(8) else {
                return Err(invalid("SEH stack overflows", pc));
            };
            registers[4] = stack;
        }
        Err(invalid("SEH search exceeds 128 frames", pc))
    }
}

//! Symbolic C file streams with replayable initial byte inputs.

use super::{Evaluation, State, Term};
use crate::ir::Convention;
use crate::ir::eval::emulation::io::Operation;
use crate::ir::smt;
use crate::service::Binary;
use crate::symbolic::invalid;

impl State {
    fn descriptor_hook(
        &mut self,
        binary: &Binary,
        convention: Convention,
        operation: Operation,
    ) -> Evaluation<Option<Term>> {
        use Operation::*;
        if self.model_call_kind == crate::ir::CallKind::Syscall {
            return Ok(None);
        }
        let first = match self.number(binary, convention, 0) {
            Ok(first) => first,
            Err(error) => return Err(error),
        };
        let token = self.files.descriptor(first as u32);
        if matches!(operation, Read) && token.is_none() {
            return Ok(None);
        }
        if matches!(operation, Open) {
            let flags = match self.number(binary, convention, 1) {
                Ok(flags) => flags as u32,
                Err(error) => return Err(error),
            };
            if binary.image().format != crate::loader::Format::Elf
                || !crate::ir::eval::stdio::read_only_open_flags(self.isa, flags)
            {
                return Err(invalid(format!(
                    "open: unsupported flags 0x{flags:x}; only Linux read-only files are modeled"
                ))
                .into());
            }
            let bytes = match self.concrete_format(binary, first) {
                Ok(bytes) => bytes,
                Err(error) => return Err(error),
            };
            let Ok(path) = String::from_utf8(bytes) else {
                return Err(invalid("open path is not UTF-8").into());
            };
            let memory = match self.mapped_memory(binary.image()) {
                Ok(memory) => memory,
                Err(error) => return Err(error.into()),
            };
            let token = self.heap_next;
            let Some(next) = token
                .checked_add(1)
                .filter(|end| *end <= memory.heap_base.saturating_add(crate::emulation::HEAP_SIZE))
            else {
                return Err(invalid("file descriptor allocation exceeds heap").into());
            };
            return match self.files.open_descriptor(token, path) {
                Ok(value) => {
                    self.heap_next = next;
                    Ok(Some(Term::constant(value)))
                }
                Err(cause) => Err(invalid(cause).into()),
            };
        }
        let Some(token) = token else {
            return Err(invalid(format!("close: unsupported descriptor {}", first as u32)).into());
        };
        if matches!(operation, Close) {
            return match self.files.close_descriptor(token) {
                Ok(value) => Ok(Some(Term::constant(value))),
                Err(cause) => Err(invalid(cause).into()),
            };
        }
        let base = match self.number(binary, convention, 1) {
            Ok(base) => base,
            Err(error) => return Err(error),
        };
        let count = match self.number(binary, convention, 2) {
            Ok(count) if count <= self.model_bound() as u64 => count,
            Ok(_) => return Err(invalid("file read exceeds symbolic model bound").into()),
            Err(error) => return Err(error),
        };
        let mut count_read = 0;
        for offset in 0..count {
            let byte = match self.files.read_descriptor(token) {
                Ok(Some(byte)) => byte,
                Ok(None) => break,
                Err(cause) => return Err(invalid(cause).into()),
            };
            let Some(address) = base.checked_add(offset) else {
                return Err(invalid("file read address overflows").into());
            };
            if let Err(error) = self.store(binary.image(), address, &byte, 1) {
                return Err(error.into());
            }
            count_read += 1;
        }
        Ok(Some(Term::constant(count_read)))
    }

    // Every failed argument or memory operation stops the current call.
    pub(super) fn file_hook(
        &mut self,
        binary: &Binary,
        convention: Convention,
        operation: Operation,
    ) -> Evaluation<Option<Term>> {
        use Operation::*;
        if matches!(operation, Open | Close | Read) {
            let result = self.descriptor_hook(binary, convention, operation);
            match result {
                Ok(Some(value)) => return Ok(Some(value)),
                Ok(None) => {}
                Err(error) => return Err(error),
            }
        }
        let Some(stream_index) = crate::ir::eval::stdio::stream_index(operation) else {
            return Ok(None);
        };
        let mut values = Vec::new();
        for index in 0..=stream_index {
            values.push(self.number(binary, convention, index)?);
        }
        let token = values[stream_index];
        let standard = token != 0 && self.standard_streams.contains(&token);
        if standard && matches!(operation, Fgets | Fread | Fwrite | Fputs) {
            if matches!(operation, Fgets) {
                return Ok(None);
            }
            // Existing symbolic standard stream models do not cover these calls.
            if !matches!(operation, Fread) {
                return Err(invalid(format!(
                    "unsupported symbolic standard stream operation at FILE 0x{token:x}"
                ))
                .into());
            }
        }
        let result = match operation {
            Fopen => {
                let path = self.concrete_format(binary, values[0])?;
                let Ok(path) = String::from_utf8(path) else {
                    return Err(invalid("fopen path is not UTF-8").into());
                };
                let mode_address = self.number(binary, convention, 1)?;
                let mode = self.concrete_format(binary, mode_address)?;
                let token = self.heap_next;
                let memory = self.mapped_memory(binary.image())?;
                let Some(next) = token.checked_add(1).filter(|end| {
                    *end <= memory.heap_base.saturating_add(crate::emulation::HEAP_SIZE)
                }) else {
                    return Err(invalid("FILE allocation exceeds heap").into());
                };
                self.files
                    .open(token, path, &mode)
                    .map_err(|error| super::Failure::Error(invalid(error)))?;
                self.heap_next = next;
                token
            }
            Fflush => {
                if !standard {
                    self.files
                        .flush(token)
                        .map_err(|error| super::Failure::Error(invalid(error)))?;
                }
                0
            }
            Setbuf => {
                let buffer = self.number(binary, convention, 1)?;
                if buffer != 0 {
                    return Err(invalid("setbuf with a caller-owned buffer is unsupported").into());
                }
                let mode = if matches!(
                    binary.image().format,
                    crate::loader::Format::Pe | crate::loader::Format::Coff
                ) {
                    4
                } else {
                    2
                };
                self.files
                    .set_buffering(token, standard, mode, binary.image().format)
                    .map_err(|error| super::Failure::Error(invalid(error)))?;
                0
            }
            Setvbuf => {
                let _buffer = self.number(binary, convention, 1)?;
                let mode = self.number(binary, convention, 2)? as u32;
                let _size = self.number(binary, convention, 3)?;
                self.files
                    .set_buffering(token, standard, mode, binary.image().format)
                    .map_err(|error| super::Failure::Error(invalid(error)))?
            }
            Fclose | Fileno | Feof | Ferror => {
                if standard {
                    return match operation {
                        Fileno => Ok(Some(Term::constant(
                            self.standard_streams
                                .iter()
                                .position(|&value| value == token)
                                .expect("standard stream") as u64,
                        ))),
                        _ => Err(invalid(format!(
                            "unsupported operation on standard FILE pointer 0x{token:x}"
                        ))
                        .into()),
                    };
                }
                self.files
                    .indicator(token, operation)
                    .map_err(|error| super::Failure::Error(invalid(error)))?
            }
            Fputs | Fwrite => {
                self.files
                    .stream(token)
                    .map_err(|error| super::Failure::Error(invalid(error)))?;
                let (bytes, count) = if matches!(operation, Fputs) {
                    (self.string(binary, values[0], self.model_bound())?, 0)
                } else {
                    let Some(total) = values[1]
                        .checked_mul(values[2])
                        .filter(|total| *total <= 65536)
                    else {
                        return Err(invalid("fwrite exceeds symbolic model bound").into());
                    };
                    if total == 0 {
                        return Ok(Some(Term::constant(0)));
                    }
                    (
                        self.read_memory(binary, values[0], total as usize)?,
                        values[2],
                    )
                };
                for _ in &bytes {
                    self.tick()?;
                }
                let written = self
                    .files
                    .write(token, &bytes, Term::constant(0))
                    .map_err(|error| super::Failure::Error(invalid(error)))?;
                if written {
                    count
                } else if matches!(operation, Fputs) {
                    u64::from(u32::MAX)
                } else {
                    0
                }
            }
            Fgets | Fread => {
                if !standard {
                    self.files
                        .stream(token)
                        .map_err(|error| super::Failure::Error(invalid(error)))?;
                }
                let line = matches!(operation, Fgets);
                let (limit, size) = if line {
                    let count = values[1] as u32 as i32;
                    if count <= 0 {
                        return Ok(Some(Term::constant(0)));
                    }
                    ((count - 1) as u64, 1)
                } else {
                    let Some(total) = values[1].checked_mul(values[2]) else {
                        return Err(invalid("fread size overflows").into());
                    };
                    (total, values[1])
                };
                if limit > 65536 {
                    return Err(invalid("file read exceeds symbolic model bound").into());
                }
                if !line && limit == 0 {
                    return Ok(Some(Term::constant(0)));
                }
                let mut bytes = Vec::new();
                while bytes.len() < limit as usize {
                    self.tick()?;
                    let byte = if standard {
                        crate::ir::eval::emulation::io::next_input(
                            &self.stdin,
                            &mut self.input_position,
                        )
                    } else {
                        self.files
                            .read(token)
                            .map_err(|error| super::Failure::Error(invalid(error)))?
                    };
                    let Some(byte) = byte else {
                        break;
                    };
                    let newline =
                        line && self.test(format!("(= {} {})", byte.text, smt::constant(10)))?;
                    bytes.push(byte);
                    if newline {
                        break;
                    }
                }
                if line && bytes.is_empty() && limit != 0 {
                    return Ok(Some(Term::constant(0)));
                }
                let count = bytes.len() as u64;
                if line {
                    bytes.push(Term::constant(0));
                }
                self.write_memory(binary, values[0], &bytes)?;
                if line {
                    values[0]
                } else {
                    crate::ir::eval::stdio::complete_elements(count, size)
                }
            }
            _ => unreachable!(),
        };
        Ok(Some(Term::constant(result)))
    }
}

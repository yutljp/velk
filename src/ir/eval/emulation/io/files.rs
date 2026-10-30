//! C file stream operations over explicitly supplied in-memory files.

use super::{Arguments, Operation, error};
use crate::ir::eval::emulation::{HEAP_SIZE, Runner, Stop};
use crate::ir::{CallKind, Convention};

impl Runner<'_> {
    fn descriptor_hook(
        &mut self,
        operation: Operation,
        convention: Convention,
        kind: CallKind,
    ) -> Option<Result<u64, Stop>> {
        use Operation::*;
        if kind == CallKind::Syscall || !matches!(operation, Open | Close | Read) {
            return None;
        }
        let first = match self.argument(0, convention, kind) {
            Ok(first) => first,
            Err(stop) => return Some(Err(stop)),
        };
        let token = self.files.descriptor(first as u32);
        if matches!(operation, Read) && token.is_none() {
            return None;
        }
        if self.recovery.is_some() {
            return Some(Err(error("file descriptors require explicit emulation")));
        }
        if matches!(operation, Open) {
            let flags = match self.argument(1, convention, kind) {
                Ok(flags) => flags as u32,
                Err(stop) => return Some(Err(stop)),
            };
            if self.image.format != crate::loader::Format::Elf
                || !crate::ir::eval::stdio::read_only_open_flags(self.image.isa, flags)
            {
                return Some(Err(error(format!(
                    "open: unsupported flags 0x{flags:x}; only Linux read-only files are modeled"
                ))));
            }
            let path = match self.bytes_at(first, None) {
                Ok(bytes) => match String::from_utf8(bytes) {
                    Ok(path) => path,
                    Err(_) => return Some(Err(error("open path is not UTF-8"))),
                },
                Err(stop) => return Some(Err(stop)),
            };
            if path == "/proc/self/status" {
                self.anti_analysis.push("/proc/self/status".to_owned());
            } else if path == "/proc/self/maps" {
                self.anti_analysis.push("/proc/self/maps".to_owned());
            }
            let token = self.allocate(1);
            if token == 0 {
                return Some(Err(error("file descriptor allocation failed")));
            }
            return Some(self.files.open_descriptor(token, path).map_err(error));
        }
        let Some(token) = token else {
            return Some(Err(error(format!(
                "close: unsupported descriptor {}",
                first as u32
            ))));
        };
        if matches!(operation, Close) {
            return Some(self.files.close_descriptor(token).map_err(error));
        }
        let base = match self.argument(1, convention, kind) {
            Ok(base) => base,
            Err(stop) => return Some(Err(stop)),
        };
        let count = match self.argument(2, convention, kind) {
            Ok(count) if count <= HEAP_SIZE => count,
            Ok(_) => return Some(Err(error("file read exceeds 16 MiB"))),
            Err(stop) => return Some(Err(stop)),
        };
        let mut bytes = Vec::new();
        for _ in 0..count {
            if let Err(stop) = self.tick() {
                return Some(Err(stop));
            }
            match self.files.read_descriptor(token) {
                Ok(Some(byte)) => bytes.push(byte),
                Ok(None) => break,
                Err(cause) => return Some(Err(error(cause))),
            }
        }
        let count = bytes.len() as u64;
        Some(self.store_bytes(base, &bytes).map(|()| count))
    }

    // Argument and memory failures abort the entire libc call.
    pub(super) fn file_hook(
        &mut self,
        operation: Operation,
        convention: Convention,
        kind: CallKind,
    ) -> Result<Option<u64>, Stop> {
        use Operation::*;
        if let Some(value) = self.descriptor_hook(operation, convention, kind) {
            return value.map(Some);
        }
        let Some(stream_index) = crate::ir::eval::stdio::stream_index(operation) else {
            return Ok(None);
        };
        let width = crate::arch::pointer_bytes(self.image.isa);
        let mut args = Arguments::new(convention, kind);
        let mut values = Vec::new();
        for _ in 0..=stream_index {
            values.push(args.next(self, width)?);
        }
        let token = values[stream_index];
        let standard = token != 0 && self.streams.contains(&token);
        if standard && matches!(operation, Fgets | Fread | Fwrite | Fputs) {
            return Ok(None);
        }
        if self.recovery.is_some() {
            return Err(error("file calls require explicit emulation"));
        }
        match operation {
            Fopen => {
                let path = self.bytes_at(values[0], None)?;
                let Ok(path) = String::from_utf8(path) else {
                    return Err(error("fopen path is not UTF-8"));
                };
                let mode = self.bytes_at(args.next(self, width)?, None)?;
                let token = self.allocate(1);
                if token == 0 {
                    return Err(error("FILE allocation failed"));
                }
                self.files.open(token, path, &mode).map_err(error)?;
                Ok(Some(token))
            }
            Fflush => {
                if self.windows.is_some() {
                    self.windows_flush_crt(token)?;
                }
                if !standard {
                    self.files.flush(token).map_err(error)?;
                }
                Ok(Some(0))
            }
            Setbuf => {
                let buffer = args.next(self, width)?;
                if buffer != 0 {
                    return Err(error("setbuf with a caller-owned buffer is unsupported"));
                }
                let mode = crate::ir::eval::stdio::default_buffering_mode(self.image.format);
                if standard && self.windows.is_some() {
                    let Some(true) = self.windows_set_crt_buffering(token, mode) else {
                        return Ok(Some(u64::from(u32::MAX)));
                    };
                }
                self.files
                    .set_buffering(token, standard, mode, self.image.format)
                    .map_err(error)?;
                Ok(Some(0))
            }
            Setvbuf => {
                let _buffer = args.next(self, width)?;
                let mode = args.next(self, 4)? as u32;
                let _size = args.next(self, width)?;
                if standard && self.windows.is_some() {
                    let Some(true) = self.windows_set_crt_buffering(token, mode) else {
                        return Ok(Some(u64::from(u32::MAX)));
                    };
                }
                self.files
                    .set_buffering(token, standard, mode, self.image.format)
                    .map(Some)
                    .map_err(error)
            }
            Fclose | Fileno | Feof | Ferror => {
                if standard {
                    return match operation {
                        Fileno => Ok(Some(
                            self.streams
                                .iter()
                                .position(|&value| value == token)
                                .expect("standard stream") as u64,
                        )),
                        _ => Err(error(format!(
                            "unsupported operation on standard FILE pointer 0x{token:x}"
                        ))),
                    };
                }
                self.files
                    .indicator(token, operation)
                    .map(Some)
                    .map_err(error)
            }
            Fputs | Fwrite => {
                self.files.stream(token).map_err(error)?;
                let (bytes, count) = if matches!(operation, Fputs) {
                    (self.bytes_at(values[0], None)?, 0)
                } else {
                    let Some(total) = values[1]
                        .checked_mul(values[2])
                        .filter(|total| *total <= HEAP_SIZE)
                    else {
                        return Err(error("fwrite size exceeds 16 MiB"));
                    };
                    if total == 0 {
                        return Ok(Some(0));
                    }
                    (self.bytes_at(values[0], Some(total as usize))?, values[2])
                };
                let written = self.files.write(token, &bytes, 0).map_err(error)?;
                Ok(Some(crate::ir::eval::stdio::file_write_result(
                    operation, written, count,
                )))
            }
            Fgets | Fread => {
                self.files.stream(token).map_err(error)?;
                let line = matches!(operation, Fgets);
                let (limit, size) = if line {
                    let Some(limit) = crate::ir::eval::stdio::line_buffer_size(values[1]) else {
                        return Ok(Some(0));
                    };
                    (limit, 1)
                } else {
                    let Some(total) = values[1].checked_mul(values[2]) else {
                        return Err(error("fread size overflows"));
                    };
                    (total, values[1])
                };
                if limit > HEAP_SIZE {
                    return Err(error("file read exceeds 16 MiB"));
                }
                if !line && limit == 0 {
                    return Ok(Some(0));
                }
                let mut bytes = Vec::new();
                while bytes.len() < limit as usize {
                    self.tick()?;
                    let Some(byte) = self.files.read(token).map_err(error)? else {
                        break;
                    };
                    bytes.push(byte);
                    if line && byte == b'\n' {
                        break;
                    }
                }
                if line && bytes.is_empty() && limit != 0 {
                    return Ok(Some(0));
                }
                let count = bytes.len() as u64;
                if line {
                    bytes.push(0);
                }
                self.store_bytes(values[0], &bytes)?;
                Ok(Some(if line {
                    values[0]
                } else {
                    crate::ir::eval::stdio::complete_elements(count, size)
                }))
            }
            _ => unreachable!(),
        }
    }
}

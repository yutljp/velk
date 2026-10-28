//! C file stream operations over explicitly supplied in-memory files.

use super::{Arguments, Operation, error};
use crate::ir::eval::emulation::{HEAP_SIZE, Runner, Stop};
use crate::ir::{CallKind, Convention};

impl Runner<'_> {
    // Argument and memory failures abort the entire libc call.
    pub(super) fn file_hook(
        &mut self,
        operation: Operation,
        convention: Convention,
        kind: CallKind,
    ) -> Result<Option<u64>, Stop> {
        use Operation::*;
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
                if !standard {
                    self.files.flush(token).map_err(error)?;
                }
                Ok(Some(0))
            }
            Setvbuf => {
                let _buffer = args.next(self, width)?;
                let mode = args.next(self, 4)? as u32;
                let _size = args.next(self, width)?;
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
                Ok(Some(if written {
                    count
                } else if matches!(operation, Fputs) {
                    u64::from(u32::MAX)
                } else {
                    0
                }))
            }
            Fgets | Fread => {
                self.files.stream(token).map_err(error)?;
                let line = matches!(operation, Fgets);
                let (limit, size) = if line {
                    let count = values[1] as u32 as i32;
                    if count <= 0 {
                        return Ok(Some(0));
                    }
                    ((count - 1) as u64, 1)
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

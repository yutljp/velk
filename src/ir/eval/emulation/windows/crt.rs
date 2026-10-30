//! CRT exit handlers and stream shutdown before process detach.

use crate::ir::{Convention, RegRef};
use crate::ssa::ranges::Fact;

use super::{Runner, Stop, TlsReason};

impl Runner<'_> {
    pub(in crate::ir::eval::emulation) fn windows_crt_write(
        &mut self,
        stream: usize,
        bytes: &[u8],
    ) -> Result<(), Stop> {
        if self.windows.is_none() || !matches!(stream, 1 | 2) {
            return self.emit(stream, bytes);
        }
        let index = stream - 1;
        let mode = self.windows_state().crt_buffering[index].unwrap_or_else(|| {
            if stream == 1 {
                crate::ir::eval::stdio::default_buffering_mode(self.image.format)
            } else {
                0
            }
        });
        if mode == 0 {
            return self.emit(stream, bytes);
        }
        if self.windows_state().crt_output[index]
            .len()
            .checked_add(bytes.len())
            .is_none_or(|length| length > crate::emulation::HEAP_SIZE as usize)
        {
            return Err(Stop::Error("captured output exceeds 16 MiB".to_owned()));
        }
        self.windows_state_mut().crt_output[index].reserve(bytes.len());
        self.windows_state_mut().crt_output[index].extend_from_slice(bytes);
        loop {
            let flush_length = crate::ir::eval::stdio::buffering_flush_length(
                mode,
                &self.windows_state().crt_output[index],
                crate::ir::eval::stdio::CRT_BUFFER_SIZE,
            );
            if flush_length == 0 {
                break;
            }
            let pending: Vec<u8> = self.windows_state_mut().crt_output[index]
                .drain(..flush_length)
                .collect();
            self.emit(stream, &pending)?;
        }
        Ok(())
    }

    pub(in crate::ir::eval::emulation) fn windows_flush_crt(
        &mut self,
        token: u64,
    ) -> Result<(), Stop> {
        let indices: Vec<usize> = if token == 0 {
            vec![1, 2]
        } else {
            match self.streams.iter().position(|&stream| stream == token) {
                Some(index @ 1..=2) => vec![index],
                _ => return Ok(()),
            }
        };
        for stream in indices {
            let pending = std::mem::take(&mut self.windows_state_mut().crt_output[stream - 1]);
            self.emit(stream, &pending)?;
        }
        Ok(())
    }

    pub(in crate::ir::eval::emulation) fn windows_set_crt_buffering(
        &mut self,
        token: u64,
        mode: u32,
    ) -> Option<bool> {
        let index = self
            .streams
            .iter()
            .position(|&stream| stream != 0 && stream == token)?;
        if !matches!(index, 1 | 2) {
            return Some(false);
        }
        if !crate::ir::eval::stdio::valid_buffering_mode(mode, self.image.format) {
            return Some(false);
        }
        self.windows_state_mut().crt_buffering[index - 1] = Some(mode);
        Some(true)
    }

    pub(super) fn windows_crt_lifecycle(
        &mut self,
        name: &str,
        args: &[u64],
    ) -> Option<Result<u64, Stop>> {
        if matches!(name, "atexit" | "_onexit" | "_crt_atexit") {
            let callback = args[0];
            if callback == 0 || self.windows_state().crt_closed {
                return Some(Ok(if name == "_onexit" {
                    0
                } else {
                    u64::from(u32::MAX)
                }));
            }
            if !self
                .image
                .section_at(callback)
                .is_some_and(|section| section.executable)
            {
                return Some(Err(Stop::Error(format!(
                    "{name} callback at 0x{callback:x} is not executable"
                ))));
            }
            if self.windows_state().exit_handlers.len() >= 4096 {
                return Some(Err(Stop::Error(
                    "CRT exit handlers exceed 4096 entries".to_owned(),
                )));
            }
            self.windows_state_mut().exit_handlers.push(callback);
            return Some(Ok(if name == "_onexit" { callback } else { 0 }));
        }
        if name == "exit" {
            if self.windows_state().crt_exiting || self.windows_state().detaching {
                return Some(Err(Stop::Error(
                    "recursive CRT termination is unsupported".to_owned(),
                )));
            }
            self.windows_state_mut().crt_exiting = true;
            while let Some(callback) = self.windows_state_mut().exit_handlers.pop() {
                if let Err(stop) = self.windows_invoke(callback, &[], Convention::Cdecl) {
                    return Some(Err(stop));
                }
            }
            if let Err(stop) = self.windows_close_crt() {
                return Some(Err(stop));
            }
            return Some(self.windows_terminate(args[0] as u32));
        }
        if !self.windows_state().crt_closed {
            return None;
        }
        let result = match name {
            "printf"
            | "fprintf"
            | "vprintf"
            | "vfprintf"
            | "__stdio_common_vfprintf"
            | "puts"
            | "putchar"
            | "fputs"
            | "getchar"
            | "scanf"
            | "fscanf"
            | "vscanf"
            | "vfscanf"
            | "fclose"
            | "fflush" => u64::from(u32::MAX),
            "fwrite" | "fread" | "fgets" | "fopen" => 0,
            _ => return None,
        };
        Some(Ok(result))
    }

    fn windows_close_crt(&mut self) -> Result<(), Stop> {
        if self.windows_state().crt_closed
            || !self
                .windows_state()
                .modules
                .iter()
                .any(|module| super::crt(&module.name))
        {
            return Ok(());
        }
        self.windows_flush_crt(0)?;
        let tokens: Vec<u64> = self.files.streams.keys().copied().collect();
        for token in tokens {
            if self.windows_state().file_handles.contains_key(&token) {
                continue;
            }
            if let Err(error) = self.files.flush(token) {
                return Err(Stop::Error(format!("CRT exit flush: {error}")));
            }
            if let Err(error) = self.files.close_descriptor(token) {
                return Err(Stop::Error(format!("CRT exit close: {error}")));
            }
        }
        self.windows_state_mut().crt_closed = true;
        self.windows_state_mut().standard_handles = [false; 3];
        Ok(())
    }

    pub(super) fn windows_terminate(&mut self, code: u32) -> Result<u64, Stop> {
        if self.windows_state().detaching {
            return Err(Stop::Error(
                "ExitProcess from a TLS detach callback is unsupported".to_owned(),
            ));
        }
        self.windows_state_mut().detaching = true;
        if let Err(stop) = self.windows_close_crt() {
            return Err(stop);
        }
        if let Err(stop) = self.windows_callbacks(TlsReason::ProcessDetach) {
            return Err(stop);
        }
        self.assign_fact(
            RegRef {
                index: crate::arch::RETURN,
                width: 32,
            },
            Fact::constant(u64::from(code)),
        );
        Err(Stop::Exit)
    }
}

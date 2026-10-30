//! Synchronous Windows handles backed by the shared in-memory files.

use super::{Runner, Stop};

pub(super) const STANDARD: [u64; 3] = [0x10, 0x14, 0x18];

pub(super) fn path_key(path: &str) -> String {
    path.replace('/', "\\").to_ascii_lowercase()
}

impl Runner<'_> {
    fn invalid_file(&mut self, error: u32) -> Result<u64, Stop> {
        self.set_last_error(error);
        Ok(crate::ir::semantics::mask(
            u32::from(crate::arch::pointer_bytes(self.image.isa)) * 8,
        ))
    }

    fn windows_open_file(&mut self, name: &str, args: &[u64]) -> Result<u64, Stop> {
        let path = match self.windows_string(args[0], name.ends_with('W')) {
            Ok(path) => path,
            Err(stop) => return Err(stop),
        };
        if path.is_empty() {
            return self.invalid_file(3);
        }
        if !path.is_ascii() {
            return Err(Stop::Error(format!("{name} paths require ASCII")));
        }
        if args[1] as u32 & !0xc000_0000 != 0
            || args[2] as u32 & !3 != 0
            || args[3] != 0
            || !matches!(args[5] as u32, 0 | 0x80)
            || args[6] != 0
            || path
                .split(['/', '\\'])
                .any(|part| matches!(part, "." | ".."))
        {
            return Err(Stop::Error(format!(
                "unsupported {name} access, sharing, attributes or path"
            )));
        }
        let disposition = args[4] as u32;
        if !(1..=5).contains(&disposition) {
            return self.invalid_file(87);
        }
        let readable = args[1] as u32 & 0x8000_0000 != 0;
        let writable = args[1] as u32 & 0x4000_0000 != 0;
        if !writable && matches!(disposition, 1 | 2 | 5) {
            return Err(Stop::Error(format!(
                "{name} creation/truncation requires GENERIC_WRITE"
            )));
        }
        let key = path_key(&path);
        let mut existing = None;
        for path in self.files.contents.keys() {
            if path_key(path) == key && existing.replace(path.clone()).is_some() {
                return Err(Stop::Error(format!("ambiguous Windows file path {path}")));
            }
        }
        let exists = existing.is_some();
        if exists && disposition == 1 {
            return self.invalid_file(80);
        }
        if !exists && matches!(disposition, 3 | 5) {
            return self.invalid_file(2);
        }
        let path = existing.unwrap_or(path);
        for (&handle, stream) in &self.files.streams {
            if path_key(&stream.path) == key
                && !self.windows_state().file_handles.contains_key(&handle)
            {
                return Err(Stop::Error(
                    "simultaneous CRT and Windows file handles are unsupported".to_owned(),
                ));
            }
        }
        for (&handle, &share) in &self.windows_state().file_handles {
            let stream = &self.files.streams[&handle];
            if stream.path == path
                && ((readable && share & 1 == 0)
                    || (writable && share & 2 == 0)
                    || (stream.readable && args[2] & 1 == 0)
                    || (stream.writable && args[2] & 2 == 0))
            {
                return self.invalid_file(32);
            }
        }
        let handle = self.allocate(1);
        if handle == 0 {
            return self.invalid_file(8);
        }
        if !exists {
            self.files.contents.insert(path.clone(), Vec::new());
            self.files.committed.insert(path.clone(), Vec::new());
        }
        let mode: &[u8] = if matches!(disposition, 2 | 5) {
            b"wb"
        } else {
            b"rb"
        };
        if let Err(error) = self.files.open(handle, path, mode) {
            return Err(Stop::Error(error));
        }
        let stream = self.files.streams.get_mut(&handle).expect("opened file");
        stream.readable = readable;
        stream.writable = writable;
        self.windows_state_mut()
            .file_handles
            .insert(handle, args[2] as u32);
        if matches!(disposition, 2 | 4) {
            self.set_last_error(if exists { 183 } else { 0 });
        }
        Ok(handle)
    }

    pub(super) fn windows_io(&mut self, name: &str, args: &[u64]) -> Result<u64, Stop> {
        if name.starts_with("CreateFile") {
            return self.windows_open_file(name, args);
        }
        if name == "GetStdHandle" {
            let index = match args[0] as i32 {
                -10 => 0,
                -11 => 1,
                -12 => 2,
                _ => return self.invalid_file(87),
            };
            return Ok(STANDARD[index]);
        }
        let standard = STANDARD.iter().position(|handle| *handle == args[0]);
        let standard = standard.filter(|&index| self.windows_state().standard_handles[index]);
        let file = self.windows_state().file_handles.contains_key(&args[0]);
        if name == "CloseHandle" {
            if self
                .windows_state()
                .threads
                .get(&args[0])
                .is_some_and(|thread| !thread.finished())
            {
                return Err(Stop::Error(
                    "closing a pending Windows thread handle is unsupported".to_owned(),
                ));
            }
            if self.windows_state_mut().threads.remove(&args[0]).is_some() {
                return Ok(1);
            }
            if let Some(index) = standard {
                self.windows_state_mut().standard_handles[index] = false;
                return Ok(1);
            }
            if !file {
                return self.windows_failure(6);
            }
            if let Err(error) = self.files.flush(args[0]) {
                return Err(Stop::Error(error));
            }
            if let Err(error) = self.files.close_descriptor(args[0]) {
                return Err(Stop::Error(error));
            }
            self.windows_state_mut().file_handles.remove(&args[0]);
            return Ok(1);
        }
        if args[3] != 0
            && let Err(stop) = self.store_bytes(args[3], &0u32.to_le_bytes())
        {
            return Err(stop);
        }
        if standard.is_none() && !file {
            return self.windows_failure(6);
        }
        let console = name.starts_with("WriteConsole");
        if console && standard.is_none() {
            return self.windows_failure(6);
        }
        if args[4] != 0 {
            return Err(Stop::Error(format!(
                "{name} overlapped/reserved argument is unsupported"
            )));
        }
        if args[3] == 0 {
            return Err(Stop::Error(format!(
                "{name} requires a count output pointer"
            )));
        }
        let length = u64::from(args[2] as u32);
        if length > super::super::HEAP_SIZE {
            return Err(Stop::Error(format!("{name} exceeds 16 MiB")));
        }
        let reading = name == "ReadFile";
        if file {
            let stream = &self.files.streams[&args[0]];
            if (reading && !stream.readable) || (!reading && !stream.writable) {
                return self.windows_failure(5);
            }
        } else if (reading && standard != Some(0)) || (!reading && standard == Some(0)) {
            return self.windows_failure(5);
        }
        let count;
        if reading {
            if let Err(stop) = self.check_memory_range(args[1], length, /* write */ true) {
                return Err(stop);
            }
            let mut bytes = Vec::new();
            for _ in 0..length {
                if let Err(stop) = self.tick() {
                    return Err(stop);
                }
                let byte = if file {
                    match self.files.read_descriptor(args[0]) {
                        Ok(byte) => byte,
                        Err(error) => return Err(Stop::Error(error)),
                    }
                } else {
                    super::super::io::next_input(&self.input, &mut self.input_position)
                };
                let Some(byte) = byte else { break };
                bytes.push(byte);
            }
            count = bytes.len() as u32;
            if let Err(stop) = self.store_bytes(args[1], &bytes) {
                return Err(stop);
            }
        } else {
            let bytes = if name == "WriteConsoleW" {
                let units = match self.wide_units(args[1], length as i32) {
                    Ok(units) => units,
                    Err(stop) => return Err(stop),
                };
                match String::from_utf16(&units) {
                    Ok(text) => text.into_bytes(),
                    Err(_) => {
                        return Err(Stop::Error(
                            "WriteConsoleW requires valid UTF-16".to_owned(),
                        ));
                    }
                }
            } else {
                match self.bytes_at(args[1], Some(length as usize)) {
                    Ok(bytes) => bytes,
                    Err(stop) => return Err(stop),
                }
            };
            if name == "WriteConsoleA" && !bytes.is_ascii() {
                return Err(Stop::Error("WriteConsoleA requires ASCII".to_owned()));
            }
            if file {
                if let Err(error) = self.files.write(args[0], &bytes, 0) {
                    return Err(Stop::Error(error));
                }
                if let Err(error) = self.files.flush(args[0]) {
                    return Err(Stop::Error(error));
                }
            } else if let Err(stop) = self.emit(standard.expect("standard output handle"), &bytes) {
                return Err(stop);
            }
            count = length as u32;
        }
        match self.store_bytes(args[3], &count.to_le_bytes()) {
            Ok(()) => Ok(1),
            Err(stop) => Err(stop),
        }
    }
}

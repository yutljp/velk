//! In-memory files and opaque C stream handles shared by execution engines.

use std::collections::BTreeMap;

use super::emulation::io::Operation;

pub(super) fn stream_index(operation: Operation) -> Option<usize> {
    use Operation::*;
    match operation {
        Fopen | Fclose | Fflush | Setvbuf | Setbuf | Fileno | Feof | Ferror => Some(0),
        Fgets => Some(2),
        Fread | Fwrite => Some(3),
        Fputs => Some(1),
        _ => None,
    }
}

pub(super) fn valid_buffering_mode(mode: u32, format: crate::loader::Format) -> bool {
    if matches!(
        format,
        crate::loader::Format::Pe | crate::loader::Format::Coff
    ) {
        matches!(mode, 0 | 4 | 64)
    } else {
        mode <= 2
    }
}

pub(super) fn complete_elements(bytes: u64, size: u64) -> u64 {
    bytes.checked_div(size).unwrap_or(0)
}

const LIMIT: usize = crate::emulation::HEAP_SIZE as usize;

pub(super) fn read_only_open_flags(isa: crate::loader::Isa, flags: u32) -> bool {
    let large_file = if isa == crate::loader::Isa::Arm32 {
        1 << 17
    } else {
        1 << 15
    };
    flags & !(large_file | (1 << 19)) == 0
}

#[derive(Clone, Debug)]
pub(super) struct Stream {
    pub path: String,
    pub position: usize,
    pub readable: bool,
    pub writable: bool,
    pub append: bool,
    pub eof: bool,
    pub error: bool,
    pub buffering: u32,
    pub descriptor: u32,
}

#[derive(Clone)]
pub(super) struct Files<T> {
    pub contents: BTreeMap<String, Vec<T>>,
    pub committed: BTreeMap<String, Vec<T>>,
    pub streams: BTreeMap<u64, Stream>,
    descriptors: BTreeMap<u32, u64>,
    next_descriptor: u32,
}

impl<T: Clone> Files<T> {
    pub fn new(contents: BTreeMap<String, Vec<T>>) -> Result<Self, String> {
        let total = contents
            .values()
            .fold(0usize, |n, bytes| n.saturating_add(bytes.len()));
        if total > LIMIT {
            return Err("file inputs exceed 16 MiB".into());
        }
        Ok(Self {
            committed: contents.clone(),
            contents,
            streams: BTreeMap::new(),
            descriptors: BTreeMap::new(),
            next_descriptor: 3,
        })
    }

    pub fn open(&mut self, token: u64, path: String, mode: &[u8]) -> Result<(), String> {
        let (readable, writable, append, truncate) = match mode {
            b"r" | b"rb" => (true, false, false, false),
            b"r+" | b"rb+" | b"r+b" => (true, true, false, false),
            b"w" | b"wb" => (false, true, false, true),
            b"a" | b"ab" => (false, true, true, false),
            _ => {
                return Err(format!(
                    "unsupported fopen mode {:?} for {path}",
                    String::from_utf8_lossy(mode)
                ));
            }
        };
        let Some(bytes) = self.contents.get_mut(&path) else {
            return Err(format!("unknown file path {path}"));
        };
        if truncate {
            bytes.clear();
            self.committed.insert(path.clone(), Vec::new());
        }
        let position = if append { bytes.len() } else { 0 };
        let descriptor = self.next_descriptor;
        let Some(next) = descriptor.checked_add(1) else {
            return Err("file descriptors exhausted".into());
        };
        self.next_descriptor = next;
        self.streams.insert(
            token,
            Stream {
                path,
                position,
                readable,
                writable,
                append,
                eof: false,
                error: false,
                buffering: 0,
                descriptor,
            },
        );
        Ok(())
    }

    pub fn stream(&self, token: u64) -> Result<&Stream, String> {
        match self.streams.get(&token) {
            Some(stream) => Ok(stream),
            None => Err(format!("invalid FILE pointer 0x{token:x}")),
        }
    }

    pub fn descriptor(&self, descriptor: u32) -> Option<u64> {
        self.descriptors.get(&descriptor).copied()
    }

    pub fn open_descriptor(&mut self, token: u64, path: String) -> Result<u64, String> {
        if let Err(error) = self.open(token, path, b"rb") {
            return Err(error);
        }
        let descriptor = self.streams[&token].descriptor;
        self.descriptors.insert(descriptor, token);
        Ok(u64::from(descriptor))
    }

    pub fn read_descriptor(&mut self, token: u64) -> Result<Option<T>, String> {
        let Some(stream) = self.streams.get_mut(&token) else {
            return Err("invalid file descriptor".to_owned());
        };
        let byte = self.contents[&stream.path].get(stream.position).cloned();
        if byte.is_some() {
            stream.position += 1;
        }
        Ok(byte)
    }

    pub fn close_descriptor(&mut self, token: u64) -> Result<u64, String> {
        let Some(stream) = self.streams.remove(&token) else {
            return Err("invalid file descriptor".to_owned());
        };
        self.descriptors.remove(&stream.descriptor);
        Ok(0)
    }

    pub fn set_buffering(
        &mut self,
        token: u64,
        standard: bool,
        mode: u32,
        format: crate::loader::Format,
    ) -> Result<u64, String> {
        if !standard && let Err(error) = self.stream(token) {
            return Err(error);
        }
        if !valid_buffering_mode(mode, format) {
            return Ok(u64::from(u32::MAX));
        }
        if let Some(stream) = self.streams.get_mut(&token) {
            stream.buffering = mode;
        }
        Ok(0)
    }

    pub fn indicator(&mut self, token: u64, operation: Operation) -> Result<u64, String> {
        let stream = match self.stream(token) {
            Ok(stream) => stream,
            Err(error) => return Err(error),
        };
        let result = match operation {
            Operation::Fileno => u64::from(stream.descriptor),
            Operation::Feof => u64::from(stream.eof),
            Operation::Ferror => u64::from(stream.error),
            _ => 0,
        };
        if matches!(operation, Operation::Fclose) {
            let descriptor = stream.descriptor;
            if let Err(error) = self.flush(token) {
                return Err(error);
            }
            self.streams.remove(&token);
            self.descriptors.remove(&descriptor);
        }
        Ok(result)
    }

    pub fn read(&mut self, token: u64) -> Result<Option<T>, String> {
        let Some(stream) = self.streams.get_mut(&token) else {
            return Err(format!("invalid FILE pointer 0x{token:x}"));
        };
        if !stream.readable {
            stream.error = true;
            return Ok(None);
        }
        if stream.eof {
            return Ok(None);
        }
        let byte = self.contents[&stream.path].get(stream.position).cloned();
        if byte.is_some() {
            stream.position += 1;
        } else {
            stream.eof = true;
        }
        Ok(byte)
    }

    pub fn write(&mut self, token: u64, bytes: &[T], zero: T) -> Result<bool, String> {
        let Some(stream) = self.streams.get_mut(&token) else {
            return Err(format!("invalid FILE pointer 0x{token:x}"));
        };
        if !stream.writable {
            stream.error = true;
            return Ok(false);
        }
        let total = self
            .contents
            .values()
            .fold(0usize, |n, bytes| n.saturating_add(bytes.len()));
        let file = self
            .contents
            .get_mut(&stream.path)
            .expect("open streams have files");
        let position = if stream.append {
            file.len()
        } else {
            stream.position
        };
        let Some(end) = position
            .checked_add(bytes.len())
            .filter(|end| total.saturating_add(end.saturating_sub(file.len())) <= LIMIT)
        else {
            return Err(format!("file output exceeds 16 MiB: {}", stream.path));
        };
        if bytes.is_empty() {
            return Ok(true);
        }
        if position > file.len() {
            file.resize(position, zero);
        }
        for (offset, byte) in bytes.iter().enumerate() {
            let at = position + offset;
            if at < file.len() {
                file[at] = byte.clone();
            } else {
                file.push(byte.clone());
            }
        }
        stream.position = end;
        Ok(true)
    }

    pub fn flush(&mut self, token: u64) -> Result<(), String> {
        if token == 0 {
            self.committed.clone_from(&self.contents);
            return Ok(());
        }
        let path = match self.stream(token) {
            Ok(stream) => stream.path.clone(),
            Err(error) => return Err(error),
        };
        self.committed
            .insert(path.clone(), self.contents[&path].clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_and_indicators() {
        for mode in [b"r".as_slice(), b"rb", b"r+", b"r+b", b"rb+"] {
            let mut files =
                Files::new(BTreeMap::from([("input".into(), vec![0, 255])])).expect("file model");
            files.open(1, "input".into(), mode).expect("open");
            assert_eq!(files.read(1), Ok(Some(0)));
            assert_eq!(files.read(1), Ok(Some(255)));
            assert!(!files.stream(1).expect("stream").eof);
            assert_eq!(files.read(1), Ok(None));
            assert!(files.stream(1).expect("stream").eof);
            let writable = mode.contains(&b'+');
            assert_eq!(files.write(1, &[42], 0), Ok(writable));
            assert_eq!(files.stream(1).expect("stream").error, !writable);
            assert_eq!(files.read(1), Ok(None), "EOF remains set after appending");
        }
        for mode in [b"w".as_slice(), b"wb", b"a", b"ab"] {
            let mut files =
                Files::new(BTreeMap::from([("output".into(), vec![1])])).expect("file model");
            files.open(1, "output".into(), mode).expect("open");
            assert_eq!(files.read(1), Ok(None));
            assert!(files.stream(1).expect("stream").error);
            assert!(!files.stream(1).expect("stream").eof);
            assert_eq!(files.write(1, &[2], 0), Ok(true));
            files.flush(1).expect("flush");
            assert_eq!(
                files.committed["output"],
                if mode[0] == b'w' { vec![2] } else { vec![1, 2] }
            );
        }
    }

    #[test]
    fn truncation_across_handles_preserves_positions_and_zero_fills() {
        let mut files =
            Files::new(BTreeMap::from([("file".into(), vec![1, 2, 3])])).expect("file model");
        files.open(1, "file".into(), b"r+").expect("update");
        assert_eq!(files.read(1), Ok(Some(1)));
        assert_eq!(files.read(1), Ok(Some(2)));
        files.open(2, "file".into(), b"w").expect("truncate");
        assert_eq!(files.write(1, &[9], 0), Ok(true));
        assert_eq!(files.contents["file"], [0, 0, 9]);
        assert!(files.committed["file"].is_empty());
        files.flush(0).expect("flush all");
        assert_eq!(files.committed["file"], [0, 0, 9]);
        assert!(
            files
                .stream(0)
                .expect_err("invalid pointer")
                .contains("0x0")
        );
    }
    #[test]
    fn buffering_modes_follow_target_constants() {
        use crate::loader::Format;
        for format in [Format::Elf, Format::MachO] {
            for mode in 0..=2 {
                assert!(valid_buffering_mode(mode, format));
            }
            assert!(!valid_buffering_mode(64, format));
        }
        for format in [Format::Pe, Format::Coff] {
            for mode in [0, 4, 64] {
                assert!(valid_buffering_mode(mode, format));
            }
            assert!(!valid_buffering_mode(2, format));
        }
    }

    #[test]
    fn smt_complete_elements() {
        use crate::ir::smt;
        if !smt::Proofs::available() {
            return;
        }
        let mut proofs = smt::Proofs::default();
        let elements = smt::low("r0", 20);
        for size in [1, 2, 4, 8] {
            let partial = format!("(bvurem r1 {})", smt::constant(size));
            let bytes = format!(
                "(bvadd (bvmul {elements} {}) {partial})",
                smt::constant(size)
            );
            proofs.predicate(
                format!("complete elements of size {size}"),
                &format!("(bvudiv {bytes} {})", smt::constant(size)),
                &elements,
            );
        }
        proofs.counterexample(
            "partial element is not complete",
            "(bvudiv r0 (_ bv2 64))",
            "(bvudiv (bvadd r0 (_ bv1 64)) (_ bv2 64))",
        );
        proofs.check();
        assert_eq!(complete_elements(10, 3), 3);
        assert_eq!(complete_elements(10, 0), 0);
    }
}

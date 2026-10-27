//! Immutable file snapshots with owned storage for relocated bytes.

use std::fs;
use std::ops::Deref;
#[cfg(target_os = "linux")]
use std::ops::Range;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::sync::Arc;

#[cfg(target_os = "linux")]
use memmap2::Mmap;

use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub(super) enum Bytes {
    #[cfg(target_os = "linux")]
    Mapped {
        map: Arc<Mmap>,
        range: Range<usize>,
    },
    Owned(Vec<u8>),
}

impl Bytes {
    pub(super) fn read(path: &Path) -> Result<Self> {
        #[cfg(target_os = "linux")]
        if let Ok(map) = snapshot(path) {
            let range = 0..map.len();
            return Ok(Self::Mapped {
                map: Arc::new(map),
                range,
            });
        }
        match fs::read(path) {
            Ok(bytes) => Ok(Self::Owned(bytes)),
            Err(source) => Err(Error::Io {
                path: path.to_owned(),
                source,
            }),
        }
    }

    pub(super) fn slice(&self, offset: u64, len: usize) -> Option<Self> {
        let Ok(start) = usize::try_from(offset) else {
            return None;
        };
        let Some(end) = start.checked_add(len) else {
            return None;
        };
        let Some(bytes) = self.get(start..end) else {
            return None;
        };
        match self {
            #[cfg(target_os = "linux")]
            Self::Mapped { map, range } => {
                let Some(start) = range.start.checked_add(start) else {
                    return None;
                };
                let Some(end) = start.checked_add(len) else {
                    return None;
                };
                Some(Self::Mapped {
                    map: Arc::clone(map),
                    range: start..end,
                })
            }
            Self::Owned(_) => Some(Self::Owned(bytes.to_vec())),
        }
    }

    pub(super) fn digest(&self) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(self.as_slice()).into()
    }

    pub(super) fn as_slice(&self) -> &[u8] {
        self
    }

    #[cfg(test)]
    pub(super) fn extend(&mut self, bytes: Vec<u8>) {
        self.to_mut().extend(bytes);
    }

    #[cfg(test)]
    fn to_mut(&mut self) -> &mut Vec<u8> {
        #[cfg(target_os = "linux")]
        if let Self::Mapped { .. } = self {
            *self = Self::Owned(self.to_vec());
        }
        match self {
            Self::Owned(bytes) => bytes,
            #[cfg(target_os = "linux")]
            Self::Mapped { .. } => unreachable!("converted to owned bytes"),
        }
    }
}

impl Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            #[cfg(target_os = "linux")]
            Self::Mapped { map, range } => &map[range.clone()],
            Self::Owned(bytes) => bytes,
        }
    }
}

#[cfg(test)]
impl std::ops::DerefMut for Bytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.to_mut()
    }
}

#[cfg(target_os = "linux")]
fn snapshot(path: &Path) -> std::io::Result<Mmap> {
    use rustix::fs::{self, MemfdFlags, SealFlags};
    use std::fs::File;
    use std::io;

    let mut input = match File::open(path) {
        Ok(input) => input,
        Err(error) => return Err(error),
    };
    let descriptor = match fs::memfd_create(
        "velk-input",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    ) {
        Ok(descriptor) => descriptor,
        Err(error) => return Err(error.into()),
    };
    let mut snapshot = File::from(descriptor);
    match io::copy(&mut input, &mut snapshot) {
        Ok(0) => return Err(io::Error::new(io::ErrorKind::Unsupported, "empty input")),
        Ok(_) => {}
        Err(error) => return Err(error),
    }
    if let Err(error) = fs::fcntl_add_seals(
        &snapshot,
        SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
    ) {
        return Err(error.into());
    }
    // SAFETY: The sealed snapshot cannot be written or resized, including through
    // another descriptor. A safe file API cannot provide a borrowed mapped slice.
    unsafe { memmap2::MmapOptions::new().map(&snapshot) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn mapped_snapshot_survives_input_truncation() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/mapped-input-test");
        fs::write(&path, b"original bytes").unwrap();
        let bytes = Bytes::read(&path).unwrap();
        assert!(matches!(bytes, Bytes::Mapped { .. }));
        fs::write(&path, b"changed").unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(&*bytes, b"original bytes");
        assert_eq!(&*bytes.slice(2, 6).unwrap(), b"iginal");
    }

    #[test]
    fn empty_file_falls_back_to_owned_storage() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/empty-input-test");
        fs::write(&path, []).unwrap();
        let bytes = Bytes::read(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert!(matches!(bytes, Bytes::Owned(_)));
        assert!(bytes.is_empty());
    }
}

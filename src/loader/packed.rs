//! Recognition and bounded decoding of UPX executables.

use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use object::{Object, ObjectSection};
use serde::Serialize;

use crate::error::{Error, Result};

const MAX_FILE_SIZE: u64 = 128 << 20;
const TIME_LIMIT: Duration = Duration::from_secs(10);
static NEXT: AtomicU64 = AtomicU64::new(0);

/// Packer identification and the decoder selected for recovery.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    /// Packer identified from the input.
    pub packer: String,
    /// Version string stored in the input's UPX identification, when present.
    pub version: Option<String>,
    /// Decoder selected to reconstruct the complete executable file.
    pub method: String,
}

/// Recognizes UPX headers in ELF and UPX section names in PE images.
/// A match is only a detection candidate until decoding succeeds.
#[must_use]
pub fn detect(bytes: &[u8]) -> Option<Report> {
    let prefix = &bytes[..bytes.len().min(4096)];
    let magic = prefix.windows(4).any(|window| window == b"UPX!");
    let elf = bytes.starts_with(b"\x7fELF");
    let pe = bytes.starts_with(b"MZ");
    let mut version = None;
    if pe {
        for offset in memchr::memmem::find_iter(prefix, b"UPX!") {
            let Some(start) = offset.checked_sub(5) else {
                continue;
            };
            let text = &prefix[start..offset];
            if text[0].is_ascii_digit()
                && text[1] == b'.'
                && text[2].is_ascii_digit()
                && text[3].is_ascii_digit()
                && text[4] == 0
            {
                version = Some(String::from_utf8_lossy(&text[..4]).into_owned());
                break;
            }
        }
    }
    let sections = if pe {
        match object::File::parse(bytes) {
            Ok(file) => file
                .sections()
                .any(|section| matches!(section.name(), Ok("UPX0" | "UPX1" | "UPX2"))),
            Err(_) => false,
        }
    } else {
        false
    };
    let sectionless_elf = elf
        && magic
        && match object::File::parse(bytes) {
            Ok(file) => file.sections().next().is_none(),
            Err(_) => true,
        };
    if !(sectionless_elf || sections || version.is_some()) {
        return None;
    }
    // The banner contains the release string; the numeric pack header version
    // describes the format and is not a release number.
    for offset in memchr::memmem::find_iter(bytes, b"$Id: UPX ") {
        let rest = &bytes[offset + 9..];
        let length = rest
            .iter()
            .take(32)
            .take_while(|byte| byte.is_ascii_digit() || **byte == b'.')
            .count();
        if length != 0 && rest[0].is_ascii_digit() {
            version = Some(String::from_utf8_lossy(&rest[..length]).into_owned());
            break;
        }
    }
    Some(Report {
        packer: "UPX".to_owned(),
        version,
        method: "upx -d (direct decoder)".to_owned(),
    })
}

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scratch() -> Result<Scratch> {
    for _ in 0..32 {
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("velk-unpack-{}-{sequence}", std::process::id()));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&path) {
            Ok(()) => return Ok(Scratch(path)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(Error::Packed(format!(
                    "cannot create temporary directory: {error}"
                )));
            }
        }
    }
    Err(Error::Packed(
        "cannot create a unique temporary directory".to_owned(),
    ))
}

struct Decoder(Child);

impl Drop for Decoder {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(unix)]
fn limit_decoder(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: The child callback only calls async-signal-safe setrlimit and
    // constructs an OS error on failure. Resource limits require an OS API.
    unsafe {
        command.pre_exec(|| {
            for (resource, maximum) in [
                (libc::RLIMIT_CPU, 5),
                #[cfg(target_os = "linux")]
                (libc::RLIMIT_AS, 512 << 20),
                (libc::RLIMIT_FSIZE, MAX_FILE_SIZE),
                (libc::RLIMIT_CORE, 0),
            ] {
                let limit = libc::rlimit {
                    rlim_cur: maximum,
                    rlim_max: maximum,
                };
                if libc::setrlimit(resource, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

#[cfg(target_os = "macos")]
fn decoder_memory(child: &Child) -> Result<u64> {
    let mut information = std::mem::MaybeUninit::<libc::proc_taskinfo>::uninit();
    let size = std::mem::size_of::<libc::proc_taskinfo>() as i32;
    // SAFETY: The buffer is valid for exactly `size` bytes. The OS initializes
    // the structure on a successful full-size return; no safe std API exposes it.
    let read = unsafe {
        libc::proc_pidinfo(
            child.id() as i32,
            libc::PROC_PIDTASKINFO,
            0,
            information.as_mut_ptr().cast(),
            size,
        )
    };
    if read != size {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(0);
        }
        return Err(Error::Packed(format!(
            "cannot measure UPX decoder memory: {error}"
        )));
    }
    // SAFETY: A full-size successful proc_pidinfo call initialized every field.
    Ok(unsafe { information.assume_init() }.pti_resident_size)
}

fn wait_decoder(child: &mut Decoder, time_limit: Duration) -> Result<()> {
    let start = Instant::now();
    loop {
        if start.elapsed() >= time_limit {
            return Err(Error::Packed(format!(
                "UPX decoder exceeded the {}-millisecond time limit; no recovered image",
                time_limit.as_millis()
            )));
        }
        match child.0.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                return Err(Error::Packed(format!(
                    "UPX decoding failed ({status}); damaged, unsupported, or resource limit exceeded; no recovered image"
                )));
            }
            Ok(None) => {}
            Err(error) => {
                return Err(Error::Packed(format!(
                    "cannot wait for UPX decoder: {error}"
                )));
            }
        }
        #[cfg(target_os = "macos")]
        match decoder_memory(&child.0) {
            Ok(memory) if memory > 512 << 20 => {
                return Err(Error::Packed(
                    "UPX decoder exceeded 512 MiB resident memory; no recovered image".to_owned(),
                ));
            }
            Ok(_) => {}
            Err(error) => {
                // The process may have exited between try_wait and proc_pidinfo.
                if let Ok(Some(status)) = child.0.try_wait() {
                    if status.success() {
                        return Ok(());
                    }
                    return Err(Error::Packed(format!(
                        "UPX decoding failed ({status}); no recovered image"
                    )));
                }
                return Err(error);
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

pub(super) fn unpack(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() as u64 > MAX_FILE_SIZE {
        return Err(Error::Packed("UPX input exceeds 128 MiB".to_owned()));
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return Err(Error::Packed(
        "bounded UPX decoding is currently supported on Linux and macOS only".to_owned(),
    ));
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let scratch = match scratch() {
            Ok(scratch) => scratch,
            Err(error) => return Err(error),
        };
        let input = scratch.0.join("input");
        let output = scratch.0.join("output");
        if let Err(error) = fs::write(&input, bytes) {
            return Err(Error::Packed(format!(
                "cannot write decoder input: {error}"
            )));
        }
        let mut command = Command::new("upx");
        command.env_remove("UPX");
        command
            .args(["-qq", "-d", "-o"])
            .arg(&output)
            .arg(&input)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        limit_decoder(&mut command);
        let child = match command.spawn() {
            Ok(child) => child,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::Packed(
                    "UPX detected; install upx on PATH to recover the executable".to_owned(),
                ));
            }
            Err(error) => {
                return Err(Error::Packed(format!(
                    "UPX detected; cannot start bounded decoder: {error}"
                )));
            }
        };
        let mut child = Decoder(child);
        if let Err(error) = wait_decoder(&mut child, TIME_LIMIT) {
            return Err(error);
        }
        let metadata = match fs::symlink_metadata(&output) {
            Ok(metadata) => metadata,
            Err(error) => {
                return Err(Error::Packed(format!(
                    "UPX produced no recovered file: {error}"
                )));
            }
        };
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_FILE_SIZE {
            return Err(Error::Packed(
                "UPX output is empty or exceeds 128 MiB".to_owned(),
            ));
        }
        let recovered = match fs::read(&output) {
            Ok(bytes) => bytes,
            Err(error) => return Err(Error::Packed(format!("cannot read UPX output: {error}"))),
        };
        let original = match object::FileKind::parse(bytes) {
            Ok(kind) => kind,
            Err(error) => {
                return Err(Error::Packed(format!(
                    "invalid packed file header: {error}"
                )));
            }
        };
        let file = match object::File::parse(recovered.as_slice()) {
            Ok(file) => file,
            Err(error) => {
                return Err(Error::Packed(format!(
                    "UPX output is not a complete executable: {error}"
                )));
            }
        };
        if object::FileKind::parse(recovered.as_slice()).ok() != Some(original)
            || file.entry() == 0
            || detect(&recovered).is_some()
        {
            return Err(Error::Packed(
                "UPX output has no entry, changed format, or remains packed; no recovered image"
                    .to_owned(),
            ));
        }
        Ok(recovered)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn version_strings_are_read_without_inventing_a_release_number() {
        let mut bytes = b"MZ\0\0".to_vec();
        bytes.extend_from_slice(b"5.21\0UPX!");
        assert_eq!(detect(&bytes).unwrap().version.as_deref(), Some("5.21"));
        let mut elf = b"\x7fELFUPX!".to_vec();
        elf.extend_from_slice(b"$Id: UPX 5.21 Copyright");
        assert_eq!(detect(&elf).unwrap().version.as_deref(), Some("5.21"));
        for length in 0..bytes.len() {
            let _ = detect(&bytes[..length]);
        }
        assert!(detect(b"\x7fELFUPX!").unwrap().version.is_none());
    }

    #[test]
    fn a_decoder_that_never_finishes_is_stopped_and_reaped() {
        let mut command = Command::new("sh");
        command.args(["-c", "while :; do :; done"]);
        limit_decoder(&mut command);
        let mut child = Decoder(command.spawn().unwrap());
        let start = Instant::now();
        let error = wait_decoder(&mut child, Duration::from_millis(20)).unwrap_err();
        assert!(error.to_string().contains("time limit"), "{error}");
        let pid = child.0.id();
        drop(child);
        assert!(start.elapsed() < Duration::from_secs(2));
        // SAFETY: kill with signal zero only queries the child's existence.
        assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
    }
}

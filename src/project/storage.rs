//! Atomic annotation persistence.
use std::fs;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::Sha256;

use super::{Project, error, io};
use crate::error::Result;

static NEXT: AtomicU64 = AtomicU64::new(0);

/// Returns the default sidecar path for the supplied binary path.
#[must_use]
pub fn path(binary: &Path) -> PathBuf {
    let mut name = binary.as_os_str().to_owned();
    name.push(".velk.json");
    PathBuf::from(name)
}

fn hash(binary: &Path) -> Result<String> {
    use sha2::Digest;
    let bytes = match fs::read(binary) {
        Ok(bytes) => bytes,
        Err(cause) => return Err(io(binary, cause)),
    };
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

fn initialize_digest(binary: &Path, digest: &mut Option<String>) -> Result<()> {
    if digest.is_none() {
        *digest = Some(match hash(binary) {
            Ok(value) => value,
            Err(cause) => return Err(cause),
        });
    }
    Ok(())
}

/// A missing sidecar is an empty project. An existing, invalid sidecar is an error.
pub fn load(binary: &Path) -> Result<Option<Project>> {
    let binary = match fs::canonicalize(binary) {
        Ok(binary) => binary,
        Err(cause) => return Err(io(binary, cause)),
    };
    load_at(&binary, &path(&binary), &mut None)
}

pub(crate) fn load_at(
    binary: &Path,
    project_path: &Path,
    digest: &mut Option<String>,
) -> Result<Option<Project>> {
    match fs::symlink_metadata(project_path) {
        Ok(_) => {}
        Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(cause) => return Err(io(project_path, cause)),
    }
    let bytes = match fs::read(project_path) {
        Ok(bytes) => bytes,
        Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(cause) => return Err(io(project_path, cause)),
    };
    let project: Project = match serde_json::from_slice(&bytes) {
        Ok(project) => project,
        Err(cause) => return Err(error("project_json", cause.to_string())),
    };
    if let Err(cause) = project.validate() {
        return Err(cause);
    }
    if let Err(cause) = initialize_digest(binary, digest) {
        return Err(cause);
    }
    if Some(&project.binary_sha256) != digest.as_ref() {
        return Err(error(
            "binary_mismatch",
            "project SHA-256 does not match the binary",
        ));
    }
    Ok(Some(project))
}

/// All cooperating writers lock the binary's stable inode, then read, modify, and rename.
/// Readers see either complete version; no lock file is needed beside the single sidecar.
pub fn update<T>(binary: &Path, change: impl FnOnce(&mut Project) -> Result<T>) -> Result<T> {
    let binary = match fs::canonicalize(binary) {
        Ok(binary) => binary,
        Err(cause) => return Err(io(binary, cause)),
    };
    update_at(&binary, &path(&binary), change)
}

pub(crate) fn update_at<T>(
    binary: &Path,
    destination: &Path,
    change: impl FnOnce(&mut Project) -> Result<T>,
) -> Result<T> {
    update_cached(binary, destination, &mut None, change)
}

pub(crate) fn update_cached<T>(
    binary: &Path,
    destination: &Path,
    digest: &mut Option<String>,
    change: impl FnOnce(&mut Project) -> Result<T>,
) -> Result<T> {
    let binary = match fs::canonicalize(binary) {
        Ok(path) => path,
        Err(cause) => return Err(io(binary, cause)),
    };
    let lock = match File::open(&binary) {
        Ok(file) => file,
        Err(cause) => return Err(io(&binary, cause)),
    };
    if let Err(cause) = lock.lock() {
        return Err(io(&binary, cause));
    }
    let mut project = match load_at(&binary, destination, digest) {
        Ok(Some(project)) => project,
        Ok(None) => Project {
            raw: None,
            version: 1,
            binary_sha256: {
                if let Err(cause) = initialize_digest(&binary, digest) {
                    return Err(cause);
                }
                digest.clone().expect("the binary hash was initialized")
            },
            annotations: Vec::new(),
        },
        Err(cause) => return Err(cause),
    };
    let digest = project.binary_sha256.clone();
    let value = match change(&mut project) {
        Ok(value) => value,
        Err(cause) => return Err(cause),
    };
    if project.binary_sha256 != digest {
        return Err(error(
            "binary_mismatch",
            "imported project belongs to another binary",
        ));
    }
    if let Err(cause) = project.validate() {
        return Err(cause);
    }
    let bytes = match serde_json::to_vec_pretty(&project) {
        Ok(bytes) => bytes,
        Err(cause) => return Err(error("project_json", cause.to_string())),
    };
    let mut temporary = destination.as_os_str().to_owned();
    temporary.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let temporary = PathBuf::from(temporary);
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
    {
        Ok(file) => file,
        Err(cause) => return Err(io(&temporary, cause)),
    };
    use std::io::Write;
    let result = file
        .write_all(&bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&temporary, destination));
    if let Err(cause) = result {
        let _ = fs::remove_file(&temporary);
        return Err(io(destination, cause));
    }
    if let Some(parent) = destination.parent() {
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        match File::open(parent).and_then(|directory| directory.sync_all()) {
            Ok(()) => {}
            Err(cause) => return Err(io(parent, cause)),
        }
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_project_does_not_open_the_binary() {
        let directory =
            PathBuf::from("target").join(format!("absent-project-{}", std::process::id()));
        let binary = directory.join("missing-binary");
        let mut digest = None;
        assert_eq!(load_at(&binary, &path(&binary), &mut digest).unwrap(), None);
        assert_eq!(digest, None);
    }

    #[test]
    fn session_reuses_the_binary_hash_for_reads_and_writes() {
        let directory = PathBuf::from("target").join(format!("hash-cache-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let binary = directory.join("binary");
        let destination = directory.join("annotations.json");
        fs::write(&binary, b"binary bytes").unwrap();
        let mut digest = None;
        update_cached(&binary, &destination, &mut digest, |_| Ok(())).unwrap();
        let first = load_at(&binary, &destination, &mut digest).unwrap();
        // Cached reads need no binary handle once its immutable session identity is known.
        fs::remove_file(&binary).unwrap();
        assert_eq!(load_at(&binary, &destination, &mut digest).unwrap(), first);
        fs::write(&binary, b"binary bytes").unwrap();
        update_cached(&binary, &destination, &mut digest, |_| Ok(())).unwrap();
        fs::remove_dir_all(directory).unwrap();
    }
}

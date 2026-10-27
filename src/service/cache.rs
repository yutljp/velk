//! Disposable whole-image analysis results, validated before use.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::loader::{ArmMode, Function, Image, OpenOptions, Summary};

const FORMAT: u32 = 3;
const MAX_SIZE: u64 = 256 << 20;
static NEXT: AtomicU64 = AtomicU64::new(0);

/// Persistent cache selection. Omission uses `VELK_CACHE` or the binary sidecar.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Location {
    /// Whether to use the default sidecar; false disables reads and writes.
    Enabled(bool),
    /// An explicit cache file path.
    Path(PathBuf),
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    format: u32,
    version: String,
    build: String,
    key: String,
    checksum: String,
    payload: String,
    navigation: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Saved {
    needs_defaults: bool,
    entry: Option<u64>,
    classes: Option<Vec<crate::loader::classes::Class>>,
    vtables: Option<BTreeSet<u64>>,
    functions: BTreeMap<u64, Function>,
    arm_modes: BTreeMap<u64, ArmMode>,
    fragments: BTreeMap<u64, u64>,
    objc_selectors: BTreeMap<u64, String>,
    imports: BTreeMap<u64, String>,
    import_addends: BTreeMap<u64, i64>,
    qualified_imports: BTreeMap<u64, String>,
    landing_pads: BTreeMap<u64, Vec<(u64, u64)>>,
    exception_regions: Vec<crate::loader::unwind::Region>,
    exception_handlers: Vec<crate::loader::seh::Handler>,
    go: bool,
    summaries: BTreeMap<u64, Summary>,
    result_reads: BTreeMap<u64, bool>,
    branches_to: Option<BTreeMap<u64, Vec<u64>>>,
    addressed: Option<BTreeSet<u64>>,
    go_abi0: Option<BTreeSet<u64>>,
}

impl Saved {
    fn capture(image: &Image, needs_defaults: bool) -> Self {
        Self {
            needs_defaults,
            entry: image.entry,
            classes: image.classes.get().cloned(),
            vtables: image.vtables.get().cloned(),
            functions: image.functions.clone(),
            arm_modes: image.arm_modes.clone(),
            fragments: image.fragments.clone(),
            objc_selectors: image.objc_selectors.clone(),
            imports: image.imports.clone(),
            import_addends: image.import_addends.clone(),
            qualified_imports: image
                .qualified_imports
                .iter()
                .map(|(key, value)| (*key, value.clone()))
                .collect(),
            landing_pads: image.landing_pads.clone(),
            exception_regions: image.exception_regions.clone(),
            exception_handlers: image.exception_handlers.clone(),
            go: image.go,
            summaries: image
                .summaries
                .read()
                .expect("summaries lock")
                .iter()
                .map(|(key, value)| (*key, *value))
                .collect(),
            result_reads: image
                .result_reads
                .lock()
                .expect("result reads lock")
                .iter()
                .map(|(key, value)| (*key, *value))
                .collect(),
            branches_to: image.branches_to.get().map(|branches| {
                branches
                    .iter()
                    .map(|(key, value)| (*key, value.clone()))
                    .collect()
            }),
            addressed: image
                .addressed
                .get()
                .map(|set| set.iter().copied().collect()),
            go_abi0: image.go_abi0.get().map(|set| set.iter().copied().collect()),
        }
    }

    pub(crate) fn restore(self, image: &mut Image) {
        image.entry = self.entry;
        if let Some(classes) = self.classes {
            let _ = image.classes.set(classes);
        }
        if let Some(vtables) = self.vtables {
            let _ = image.vtables.set(vtables);
        }
        image.functions = self.functions;
        image.arm_modes = self.arm_modes;
        image.fragments = self.fragments;
        image.objc_selectors = self.objc_selectors;
        image.imports = self.imports;
        image.import_addends = self.import_addends;
        image.qualified_imports = self.qualified_imports.into_iter().collect();
        image.landing_pads = self.landing_pads;
        image.exception_regions = self.exception_regions;
        image.exception_handlers = self.exception_handlers;
        image.go = self.go;
        image.summaries = std::sync::RwLock::new(self.summaries.into_iter().collect());
        image.result_reads = std::sync::Mutex::new(self.result_reads.into_iter().collect());
        if let Some(branches) = self.branches_to {
            let _ = image.branches_to.set(branches.into_iter().collect());
        }
        if let Some(addressed) = self.addressed {
            let _ = image.addressed.set(addressed.into_iter().collect());
        }
        if let Some(abi0) = self.go_abi0 {
            let _ = image.go_abi0.set(abi0.into_iter().collect());
        }
    }
}

#[derive(PartialEq)]
struct Checksums {
    analysis: String,
    navigation: Option<String>,
}

pub(super) struct Cache {
    pub(super) needs_defaults: bool,
    path: PathBuf,
    key: String,
    warned: bool,
    navigation: Option<String>,
    navigation_offset: u64,
    written: Option<Checksums>,
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hash_file(hash: &mut Sha256, path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut file) = fs::File::open(path) else {
        return false;
    };
    let mut buffer = [0; 65536];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => return true,
            Ok(size) => hash.update(&buffer[..size]),
            Err(_) => return false,
        }
    }
}

impl Cache {
    pub(super) fn new(
        binary: &Path,
        project_path: &Path,
        debug_path: Option<&Path>,
        source_digest: Option<&str>,
        options: &OpenOptions,
        signatures: &super::SignatureOptions,
        project: Option<&crate::project::Project>,
    ) -> Option<Self> {
        let Some(source_digest) = source_digest else {
            return None;
        };
        let selection = options.cache.clone().or_else(|| {
            std::env::var_os("VELK_CACHE").map(|value| {
                if value == "off" {
                    Location::Enabled(false)
                } else {
                    Location::Path(value.into())
                }
            })
        });
        let path = match selection {
            Some(Location::Enabled(false)) => return None,
            Some(Location::Path(path)) => path,
            _ => {
                let mut name = binary.as_os_str().to_owned();
                name.push(".velk-cache");
                name.into()
            }
        };
        // A cache must never replace an input, project, or signature database.
        let destination = resolved(&path);
        if destination == resolved(project_path)
            || destination == binary
            || signatures
                .files
                .iter()
                .any(|file| resolved(file) == destination)
        {
            eprintln!("analysis cache: destination is an input file; saving disabled");
            return None;
        }
        if debug_path.is_some_and(|dependency| resolved(dependency) == destination) {
            eprintln!("analysis cache: destination is a debug file; saving disabled");
            return None;
        }
        let mut hash = Sha256::new();
        let settings = (
            &options.arch,
            &options.raw,
            signatures,
            project,
            std::env::consts::ARCH,
            std::env::consts::OS,
        );
        let Ok(settings) = serde_json::to_vec(&settings) else {
            return None;
        };
        hash.update(settings);
        hash.update(source_digest.as_bytes());
        Some(Self {
            path,
            key: format!("{:x}", hash.finalize()),
            warned: false,
            navigation: None,
            navigation_offset: 0,
            needs_defaults: false,
            written: None,
        })
    }

    pub(super) fn read(&mut self) -> Option<Saved> {
        let Ok(metadata) = fs::metadata(&self.path) else {
            return None;
        };
        if metadata.len() > MAX_SIZE {
            return None;
        }
        let Ok(file) = fs::File::open(&self.path) else {
            return None;
        };
        let mut bytes = Vec::new();
        if BufReader::new(file.take(MAX_SIZE + 1))
            .read_until(b'\n', &mut bytes)
            .is_err()
            || bytes.len() as u64 > MAX_SIZE
        {
            return None;
        }
        let Ok(envelope) = serde_json::from_slice::<Envelope>(&bytes) else {
            return None;
        };
        if envelope.format != FORMAT
            || envelope.version != env!("CARGO_PKG_VERSION")
            || envelope.build != env!("VELK_ANALYSIS_BUILD")
            || envelope.key != self.key
            || digest(envelope.payload.as_bytes()) != envelope.checksum
        {
            return None;
        }
        let Ok(saved) = serde_json::from_str::<Saved>(&envelope.payload) else {
            return None;
        };
        self.needs_defaults = saved.needs_defaults;
        self.navigation_offset = bytes.len() as u64;
        self.navigation = envelope.navigation.clone();
        self.written = Some(Checksums {
            analysis: envelope.checksum,
            navigation: envelope.navigation,
        });
        Some(saved)
    }

    fn navigation_bytes(&self) -> Option<Vec<u8>> {
        let Some(checksum) = &self.navigation else {
            return None;
        };
        let Ok(mut file) = fs::File::open(&self.path) else {
            return None;
        };
        if file.seek(SeekFrom::Start(self.navigation_offset)).is_err() {
            return None;
        }
        let mut bytes = Vec::new();
        if file.take(MAX_SIZE + 1).read_to_end(&mut bytes).is_err()
            || bytes.len() as u64 > MAX_SIZE
            || digest(&bytes) != *checksum
        {
            return None;
        }
        Some(bytes)
    }

    pub(super) fn read_navigation(&mut self) -> Option<crate::xrefs::Index> {
        let result = self
            .navigation_bytes()
            .and_then(|bytes| serde_json::from_slice::<crate::xrefs::SavedIndex>(&bytes).ok());
        if result.is_none() {
            self.navigation = None;
        }
        result.map(crate::xrefs::SavedIndex::restore)
    }

    pub(super) fn write(&mut self, image: &Image, navigation: Option<&crate::xrefs::Index>) {
        if self.warned {
            return;
        }
        let saved = Saved::capture(image, self.needs_defaults);
        let Ok(payload) = serde_json::to_string(&saved) else {
            return;
        };
        let checksum = digest(payload.as_bytes());
        let navigation_bytes = match navigation {
            Some(index) => match serde_json::to_vec(&crate::xrefs::SavedIndex::capture(index)) {
                Ok(bytes) => Some(bytes),
                Err(_) => return,
            },
            None if self.written.as_ref()
                == Some(&Checksums {
                    analysis: checksum.clone(),
                    navigation: self.navigation.clone(),
                }) =>
            {
                return;
            }
            None => self.navigation_bytes(),
        };
        let navigation_checksum = navigation_bytes.as_ref().map(|bytes| digest(bytes));
        if self.written.as_ref()
            == Some(&Checksums {
                analysis: checksum.clone(),
                navigation: navigation_checksum.clone(),
            })
        {
            return;
        }
        let envelope = Envelope {
            format: FORMAT,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            build: env!("VELK_ANALYSIS_BUILD").to_owned(),
            key: self.key.clone(),
            checksum: checksum.clone(),
            payload,
            navigation: navigation_checksum.clone(),
        };
        let Ok(mut bytes) = serde_json::to_vec(&envelope) else {
            return;
        };
        bytes.push(b'\n');
        let navigation_offset = bytes.len() as u64;
        if let Some(navigation) = navigation_bytes {
            bytes.extend(navigation);
        }
        if bytes.len() as u64 > MAX_SIZE {
            return;
        }
        let mut name = self.path.as_os_str().to_owned();
        name.push(format!(
            ".{}.{}.tmp",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let temporary = PathBuf::from(name);
        let (result, created) = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(mut file) => (
                file.write_all(&bytes)
                    .and_then(|()| fs::rename(&temporary, &self.path)),
                true,
            ),
            Err(error) => (Err(error), false),
        };
        if let Err(error) = result {
            if created {
                let _ = fs::remove_file(&temporary);
            }
            eprintln!(
                "analysis cache: cannot save {}: {error}",
                self.path.display()
            );
            self.warned = true;
        } else {
            self.written = Some(Checksums {
                analysis: checksum,
                navigation: navigation_checksum.clone(),
            });
            self.navigation = navigation_checksum;
            self.navigation_offset = navigation_offset;
        }
    }
}

pub(super) fn source_digest(binary: &Path, signatures: &super::SignatureOptions) -> Option<String> {
    let Ok(bytes) = fs::read(binary) else {
        return None;
    };
    let input_digest: [u8; 32] = Sha256::digest(&bytes).into();
    dependency_digest(
        input_digest,
        debug_path(binary, &bytes).as_deref(),
        signatures,
    )
}

pub(super) fn image_source_digest(
    image: &Image,
    signatures: &super::SignatureOptions,
) -> Option<String> {
    dependency_digest(image.input_digest, image.debug_path.as_deref(), signatures)
}

fn dependency_digest(
    input_digest: [u8; 32],
    debug_path: Option<&Path>,
    signatures: &super::SignatureOptions,
) -> Option<String> {
    let mut hash = Sha256::new();
    hash.update(input_digest);
    if let Some(dependency) = debug_path {
        if dependency.is_file() {
            let mut content = Sha256::new();
            if !hash_file(&mut content, dependency) {
                return None;
            }
            hash.update(content.finalize());
        } else {
            hash.update(b"missing debug file");
        }
    }
    for file in &signatures.files {
        let mut content = Sha256::new();
        if !hash_file(&mut content, file) {
            return None;
        }
        hash.update(content.finalize());
    }
    Some(format!("{:x}", hash.finalize()))
}

fn resolved(path: &Path) -> PathBuf {
    if let Ok(path) = fs::canonicalize(path) {
        return path;
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    match (fs::canonicalize(parent), path.file_name()) {
        (Ok(parent), Some(name)) => parent.join(name),
        _ => path.to_owned(),
    }
}

pub(crate) fn debug_path(binary: &Path, bytes: &[u8]) -> Option<PathBuf> {
    use object::Object;
    let Ok(file) = object::File::parse(bytes) else {
        return None;
    };
    let Ok(Some(info)) = file.pdb_info() else {
        return None;
    };
    let filename = info
        .path()
        .rsplit(|byte| matches!(byte, b'/' | b'\\'))
        .next()
        .unwrap_or_default();
    let Ok(filename) = std::str::from_utf8(filename) else {
        return None;
    };
    if matches!(filename, "" | "." | "..") {
        return None;
    }
    Some(binary.with_file_name(filename))
}

#[cfg(test)]
mod tests;

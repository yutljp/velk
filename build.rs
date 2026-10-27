use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

fn hash_sources(path: &Path, hash: &mut Sha256) {
    if path.is_dir() {
        let mut paths: Vec<_> = fs::read_dir(path)
            .expect("source directory")
            .map(|entry| entry.expect("source entry").path())
            .collect();
        paths.sort();
        for path in paths {
            hash_sources(&path, hash);
        }
    } else {
        println!("cargo::rerun-if-changed={}", path.display());
        hash.update(path.to_string_lossy().as_bytes());
        let bytes = fs::read(path).expect("build input");
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
}

fn main() {
    let mut hash = Sha256::new();
    for path in ["src", "signatures", "Cargo.toml", "Cargo.lock", "build.rs"] {
        hash_sources(Path::new(path), &mut hash);
    }
    println!("cargo::rustc-env=VELK_ANALYSIS_BUILD={:x}", hash.finalize());
}

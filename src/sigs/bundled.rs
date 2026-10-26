//! Embedded, compressed instruction databases shared by opened binaries.

use std::io::{Cursor, Read};
use std::sync::OnceLock;

use flate2::read::GzDecoder;

use super::{Database, Entry};
use crate::loader::Isa;

/// Returns all built-in library sets, including each entry's source set name.
///
/// # Panics
///
/// Panics if a database embedded at build time is invalid.
#[must_use]
pub fn bundled() -> &'static Database {
    static DATABASE: OnceLock<Database> = OnceLock::new();
    DATABASE.get_or_init(|| {
        let mut database = Database::new(Vec::new());
        for isa in [Isa::X86_64, Isa::AArch64, Isa::I386, Isa::Arm32] {
            let part = for_isa(isa);
            database.entries.extend_from_slice(&part.entries);
            database.sources.extend_from_slice(&part.sources);
        }
        database
    })
}

pub(crate) fn for_isa(isa: Isa) -> &'static Database {
    static X86_64: OnceLock<Database> = OnceLock::new();
    static AARCH64: OnceLock<Database> = OnceLock::new();
    static I386: OnceLock<Database> = OnceLock::new();
    static ARM32: OnceLock<Database> = OnceLock::new();
    static EMPTY: OnceLock<Database> = OnceLock::new();
    let (slot, data): (&OnceLock<Database>, &[u8]) = match isa {
        Isa::X86_64 => (&X86_64, include_bytes!("../../signatures/x86_64.bin.gz")),
        Isa::AArch64 => (&AARCH64, include_bytes!("../../signatures/aarch64.bin.gz")),
        Isa::I386 => (&I386, include_bytes!("../../signatures/i386.bin.gz")),
        Isa::Arm32 => (&ARM32, include_bytes!("../../signatures/arm32.bin.gz")),
        Isa::Unsupported => return EMPTY.get_or_init(|| Database::new(Vec::new())),
    };
    slot.get_or_init(|| decode(data, isa))
}

fn count(reader: &mut Cursor<Vec<u8>>) -> u32 {
    let mut bytes = [0; 4];
    reader
        .read_exact(&mut bytes)
        .expect("embedded count is complete");
    u32::from_le_bytes(bytes)
}

fn bytes(reader: &mut Cursor<Vec<u8>>) -> Vec<u8> {
    let size = count(reader) as usize;
    let start = reader.position() as usize;
    let end = start
        .checked_add(size)
        .expect("embedded length fits in memory");
    let result = reader
        .get_ref()
        .get(start..end)
        .expect("embedded bytes are complete")
        .to_vec();
    reader.set_position(end as u64);
    result
}

fn string(reader: &mut Cursor<Vec<u8>>) -> String {
    String::from_utf8(bytes(reader)).expect("embedded names are UTF-8")
}

fn decode(data: &[u8], isa: Isa) -> Database {
    let mut decoded = Vec::new();
    GzDecoder::new(data)
        .read_to_end(&mut decoded)
        .expect("embedded database is valid gzip");
    let mut reader = Cursor::new(decoded);
    let mut magic = [0; 8];
    reader
        .read_exact(&mut magic)
        .expect("embedded header is complete");
    assert_eq!(
        &magic, b"VELKSIG1",
        "embedded database has the expected format"
    );
    let mut sources = Vec::new();
    for _ in 0..count(&mut reader) {
        sources.push(string(&mut reader));
    }
    let mut entries = Vec::new();
    for _ in 0..count(&mut reader) {
        let name = string(&mut reader);
        let set = Some(string(&mut reader));
        let body = bytes(&mut reader);
        let mut calls = Vec::new();
        for _ in 0..count(&mut reader) {
            calls.push(string(&mut reader));
        }
        let mut constants = Vec::new();
        for _ in 0..count(&mut reader) {
            constants.push(bytes(&mut reader));
        }
        entries.push(Entry {
            name,
            isa,
            size: body.len() as u64,
            bytes: body,
            calls,
            set,
            constants,
            hash: String::new(),
            tokens: Vec::new(),
        });
    }
    assert_eq!(
        reader.position(),
        reader.get_ref().len() as u64,
        "embedded database has no trailing data"
    );
    let mut database = Database::new(entries);
    database.sources = sources;
    database
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebuilt_json_matches_compact_entries_when_available() {
        let path = std::path::Path::new("target/library-signatures/defaults.json.gz");
        if !path.is_file() {
            return;
        }
        let expected: Database = Database::load(path).unwrap();
        let entries = |database: &Database| {
            let mut entries: Vec<String> = database
                .entries
                .iter()
                .map(|entry| serde_json::to_string(entry).unwrap())
                .collect();
            entries.sort();
            entries
        };
        assert_eq!(entries(bundled()), entries(&expected));
    }

    #[test]
    fn compact_sets_match_manifest_and_stay_within_budget() {
        let manifest: serde_json::Value =
            serde_json::from_str(include_str!("../../signatures/sets.json")).unwrap();
        for isa in [Isa::X86_64, Isa::AArch64, Isa::I386, Isa::Arm32] {
            let database = for_isa(isa);
            let arch = match isa {
                Isa::X86_64 => "x86_64",
                Isa::AArch64 => "aarch64",
                Isa::I386 => "i386",
                Isa::Arm32 => "arm32",
                Isa::Unsupported => unreachable!(),
            };
            assert_eq!(
                database.entries.len() as u64,
                manifest["embedded"][arch]["entries"]
            );
            assert!(!database.entries.is_empty());
            assert!(database.entries.iter().all(|entry| entry.isa == isa));
            if matches!(isa, Isa::X86_64 | Isa::AArch64) {
                for library in ["musl.", "mbedtls.", "libsodium.", "openssl.", "rust."] {
                    assert!(
                        database
                            .sources
                            .iter()
                            .any(|source| source.starts_with(library)),
                        "{arch} must include {library} signatures"
                    );
                }
            }
        }
        assert!(for_isa(Isa::Unsupported).entries.is_empty());
        assert!(
            include_bytes!("../../signatures/x86_64.bin.gz").len()
                + include_bytes!("../../signatures/aarch64.bin.gz").len()
                + include_bytes!("../../signatures/i386.bin.gz").len()
                + include_bytes!("../../signatures/arm32.bin.gz").len()
                <= 2 * 1024 * 1024
        );
    }
}

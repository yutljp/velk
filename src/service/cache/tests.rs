//! Cache validity includes every source of whole-image analysis.

use super::*;
use crate::loader::{RawArchitecture, RawOptions};
use crate::service::{Binary, Session, SignatureOptions};

fn directory(name: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/cache-validity")
        .join(format!("{name}-{}", std::process::id()));
    fs::create_dir_all(&path).unwrap();
    path
}

fn context(
    binary: &Path,
    options: &OpenOptions,
    signatures: &SignatureOptions,
    project: Option<&crate::project::Project>,
) -> Cache {
    Cache::new(
        binary,
        &crate::project::path(binary),
        None,
        source_digest(binary, signatures).as_deref(),
        options,
        signatures,
        project,
    )
    .unwrap()
}

#[test]
fn keys_cover_mapping_signatures_annotations_version_and_format() {
    let directory = directory("keys");
    let binary = directory.join("code.bin");
    fs::write(&binary, [0x8d, 0x04, 0x37, 0xc3]).unwrap();
    let mut options = OpenOptions {
        raw: Some(RawOptions {
            arch: RawArchitecture::X86_64,
            base: 0x7000,
            entries: Vec::new(),
            byte_order: crate::loader::ByteOrder::Little,
        }),
        cache: Some(Location::Path(directory.join("analysis.json"))),
        ..OpenOptions::default()
    };
    let mut signatures = SignatureOptions {
        defaults: false,
        files: Vec::new(),
    };
    drop(Binary::open_input_with_signatures(&binary, None, &options, &signatures).unwrap());
    assert!(
        context(&binary, &options, &signatures, None)
            .read()
            .is_some()
    );
    let key = context(&binary, &options, &signatures, None).key;
    for raw in [
        RawOptions {
            base: 0x8000,
            ..options.raw.clone().unwrap()
        },
        RawOptions {
            entries: vec![0x7001],
            ..options.raw.clone().unwrap()
        },
        RawOptions {
            arch: RawArchitecture::I386,
            ..options.raw.clone().unwrap()
        },
        RawOptions {
            byte_order: crate::loader::ByteOrder::Big,
            ..options.raw.clone().unwrap()
        },
    ] {
        let changed = OpenOptions {
            raw: Some(raw),
            ..options.clone()
        };
        assert!(
            context(&binary, &changed, &signatures, None)
                .read()
                .is_none()
        );
    }
    options.arch = Some(crate::loader::Architecture::Arm64);
    assert!(
        context(&binary, &options, &signatures, None)
            .read()
            .is_none()
    );
    options.arch = None;
    signatures.defaults = true;
    assert!(
        context(&binary, &options, &signatures, None)
            .read()
            .is_none()
    );
    signatures.defaults = false;
    let signature_file = directory.join("signatures.json");
    fs::write(&signature_file, b"first").unwrap();
    signatures.files.push(signature_file.clone());
    let first = context(&binary, &options, &signatures, None).key;
    fs::write(&signature_file, b"other").unwrap();
    assert_ne!(context(&binary, &options, &signatures, None).key, first);
    signatures.files.clear();
    let project: crate::project::Project = serde_json::from_value(serde_json::json!({
        "version":1,"binary_sha256":digest(&fs::read(&binary).unwrap()),"annotations":[]
    }))
    .unwrap();
    let mut changed = project.clone();
    changed.annotations.push(serde_json::from_value(serde_json::json!({"target":{"kind":"classification","address":"0x7000"},"text":"data"})).unwrap());
    assert_ne!(
        context(&binary, &options, &signatures, Some(&project)).key,
        context(&binary, &options, &signatures, Some(&changed)).key
    );
    let cache_path = directory.join("analysis.json");
    let original = fs::read(&cache_path).unwrap();
    for change in 0..3 {
        let mut envelope: Envelope = serde_json::from_slice(&original).unwrap();
        match change {
            0 => envelope.format = FORMAT + 1,
            1 => envelope.version = "different release".to_owned(),
            _ => envelope.build = "different build".to_owned(),
        }
        fs::write(&cache_path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert!(
            context(&binary, &options, &signatures, None)
                .read()
                .is_none()
        );
    }
    let mut envelope: Envelope = serde_json::from_slice(&original).unwrap();
    // A different build, release, or format produces a different key.
    envelope.key = digest(format!("{key}-different-format-version-build").as_bytes());
    fs::write(&cache_path, serde_json::to_vec(&envelope).unwrap()).unwrap();
    assert!(
        context(&binary, &options, &signatures, None)
            .read()
            .is_none()
    );
    fs::write(&cache_path, &original).unwrap();
    envelope = serde_json::from_slice(&original).unwrap();
    envelope.payload.push(' ');
    fs::write(&cache_path, serde_json::to_vec(&envelope).unwrap()).unwrap();
    assert!(
        context(&binary, &options, &signatures, None)
            .read()
            .is_none()
    );
    envelope.payload = "{}".to_owned();
    envelope.checksum = digest(envelope.payload.as_bytes());
    fs::write(&cache_path, serde_json::to_vec(&envelope).unwrap()).unwrap();
    assert!(
        context(&binary, &options, &signatures, None)
            .read()
            .is_none()
    );
    fs::write(&cache_path, &original).unwrap();
    fs::write(&binary, [0x90, 0x90, 0x90, 0xc3]).unwrap();
    assert!(
        context(&binary, &options, &signatures, None)
            .read()
            .is_none()
    );
}

#[test]
fn sessions_notice_content_changes_with_unchanged_timestamps() {
    let directory = directory("session");
    let binary = directory.join("input.o");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tail_calls.o"),
        &binary,
    )
    .unwrap();
    let options = OpenOptions {
        cache: Some(Location::Enabled(false)),
        ..OpenOptions::default()
    };
    let mut session = Session::default();
    let first = session
        .open_input(&binary, None, &options)
        .unwrap()
        .source_digest
        .clone();
    let modified = fs::metadata(&binary).unwrap().modified().unwrap();
    let mut bytes = fs::read(&binary).unwrap();
    bytes.push(0);
    fs::write(&binary, bytes).unwrap();
    fs::File::options()
        .write(true)
        .open(&binary)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(modified))
        .unwrap();
    let second = session
        .open_input(&binary, None, &options)
        .unwrap()
        .source_digest
        .clone();
    assert_ne!(first, second);
}

#[test]
fn external_debug_file_changes_invalidate_the_cache() {
    let directory = directory("debug");
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/codeview");
    let binary = directory.join("loops.O2.dll");
    let pdb = directory.join("loops.O2.pdb");
    fs::copy(fixtures.join("loops.O2.dll"), &binary).unwrap();
    fs::copy(fixtures.join("loops.O2.pdb"), &pdb).unwrap();
    let options = OpenOptions {
        cache: Some(Location::Path(directory.join("cache.json"))),
        ..OpenOptions::default()
    };
    let signatures = SignatureOptions::default();
    drop(Binary::open_input(&binary, None, &options).unwrap());
    assert!(
        context(&binary, &options, &signatures, None)
            .read()
            .is_some()
    );
    fs::write(&pdb, b"damaged").unwrap();
    assert!(
        context(&binary, &options, &signatures, None)
            .read()
            .is_none()
    );
    fs::remove_file(&pdb).unwrap();
    assert!(
        context(&binary, &options, &signatures, None)
            .read()
            .is_none()
    );
}

#[test]
fn cache_destinations_cannot_replace_analysis_inputs() {
    let directory = directory("destinations");
    let binary = directory.join("input.o");
    fs::write(&binary, b"input").unwrap();
    let binary = fs::canonicalize(binary).unwrap();
    let project = crate::project::path(&binary);
    let signature = directory.join("signature.json");
    fs::write(&signature, b"signature").unwrap();
    let signatures = SignatureOptions {
        defaults: false,
        files: vec![signature.clone()],
    };
    for path in [&binary, &project, &signature] {
        let options = OpenOptions {
            cache: Some(Location::Path(path.to_owned())),
            ..OpenOptions::default()
        };
        assert!(
            Cache::new(
                &binary,
                &project,
                None,
                Some("digest"),
                &options,
                &signatures,
                None
            )
            .is_none()
        );
    }
    assert_eq!(fs::read(&binary).unwrap(), b"input");
    assert_eq!(fs::read(&signature).unwrap(), b"signature");
    assert!(!project.exists());
}

#[test]
fn summaries_round_trip_full_register_masks_and_lazy_navigation() {
    let directory = directory("summaries");
    let binary_path = directory.join("input.o");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tail_calls.o"),
        &binary_path,
    )
    .unwrap();
    let options = OpenOptions {
        cache: Some(Location::Path(directory.join("cache.json"))),
        ..OpenOptions::default()
    };
    let signatures = SignatureOptions::default();
    let mut binary = Binary::open_input(&binary_path, None, &options).unwrap();
    let navigation = serde_json::to_value(binary.navigation(None).unwrap()).unwrap();
    let address = binary.find("tail_one").unwrap().addr;
    binary.image.summaries.write().unwrap().insert(
        address,
        Summary {
            inputs: Some(crate::ir::Registers(u128::MAX)),
            clobbers: Some(crate::ir::Registers(u128::MAX)),
            ..Summary::default()
        },
    );
    drop(binary);
    let mut cache = context(&binary_path, &options, &signatures, None);
    let saved = cache.read().expect("saved analysis is accepted");
    assert_eq!(
        saved.summaries[&address].inputs,
        Some(crate::ir::Registers(u128::MAX))
    );
    assert!(cache.navigation.is_some());
    assert_eq!(
        serde_json::to_value(cache.read_navigation().unwrap()).unwrap(),
        navigation
    );
    // Corruption of the separate index never reaches a query.
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&cache.path)
        .unwrap();
    file.write_all(b"damaged").unwrap();
    assert!(cache.read_navigation().is_none());
}

#[test]
fn cached_default_signature_decision_matches_initial_load() {
    let directory = directory("signature-decision");
    for (fixture, expected) in [("pe64.exe", false), ("cpp_virtual_x64_stripped.elf", true)] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(fixture);
        let options = OpenOptions {
            cache: Some(Location::Path(directory.join(format!("{fixture}.json")))),
            ..OpenOptions::default()
        };
        let _ = fs::remove_file(match &options.cache {
            Some(Location::Path(path)) => path,
            _ => unreachable!(),
        });
        for _ in 0..2 {
            let binary = Binary::open_input(&path, None, &options).unwrap();
            assert_eq!(
                !binary.signature_database.entries.is_empty(),
                expected,
                "{fixture}"
            );
        }
    }
}

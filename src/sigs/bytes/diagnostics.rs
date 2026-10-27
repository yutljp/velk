//! Reproducible samples of missed library names, using generated ground truth.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use serde_json::json;

use super::*;
use crate::sigs::Certainty;

fn fixture(name: &str) -> PathBuf {
    let data = fs::read(format!("target/library-signatures/fixtures/{name}.gz")).unwrap();
    let mut bytes = Vec::new();
    GzDecoder::new(data.as_slice())
        .read_to_end(&mut bytes)
        .unwrap();
    let directory = Path::new("target/signature-diagnostics");
    fs::create_dir_all(directory).unwrap();
    let path = directory.join(name);
    fs::write(&path, bytes).unwrap();
    path
}

#[test]
#[ignore = "Regenerates the diagnostic report from all 100 library fixtures."]
fn classify_missed_names() {
    let path = std::env::var("SIGNATURE_ANALYSIS_DATABASE")
        .unwrap_or_else(|_| "target/library-signatures/libraries.json.gz".to_owned());
    let decoder = GzDecoder::new(fs::File::open(path).unwrap());
    let database: Database = serde_json::from_reader(decoder).unwrap();
    let mut samples = Vec::new();
    let mut counts = BTreeMap::<String, BTreeMap<String, usize>>::new();
    for library in ["musl", "mbedtls", "libsodium", "openssl", "rust"] {
        for arch in ["x86_64", "aarch64", "i386", "arm32"] {
            for level in ["O0", "O1", "O2", "O3", "Os"] {
                let stem = format!("{library}.{arch}.{level}");
                let path = fixture(&format!("{stem}.stripped.elf"));
                let mut image = crate::loader::load(&path).unwrap();
                crate::analysis::absorb_jump_table_cases(&mut image);
                discover::arm32(&mut image, &database, None).unwrap();
                let truth: BTreeMap<u64, Vec<String>> = serde_json::from_slice(
                    &fs::read(fixture(&format!("{stem}.truth.json"))).unwrap(),
                )
                .unwrap();
                let found: BTreeMap<_, _> =
                    matching::identify(&image, &database, None, matching::MatchScope::All)
                        .unwrap()
                        .into_iter()
                        .collect();
                let misses: Vec<_> = truth
                    .iter()
                    .filter(|(addr, _)| {
                        found
                            .get(addr)
                            .is_none_or(|e| e.certainty != Certainty::Exact)
                    })
                    .collect();
                assert!(misses.len() >= 5, "{stem} has too few misses to sample");
                for index in 0..5 {
                    let (addr, raw_names) = misses[index * misses.len() / 5];
                    let names: Vec<_> = raw_names
                        .iter()
                        .map(|name| crate::loader::demangle_name(name))
                        .collect();
                    let reason = classify(&image, *addr, &names, &database, found.get(addr));
                    *counts
                        .entry(library.to_owned())
                        .or_default()
                        .entry(reason.to_owned())
                        .or_default() += 1;
                    samples.push(json!({"fixture":stem, "address":format!("0x{addr:x}"),
                        "names":names, "reason":reason}));
                }
            }
        }
    }
    let report = json!({"method":"Five evenly spaced misses by address in each architecture and optimization variant; first failing check wins.",
        "counts":counts, "samples":samples});
    let path = std::env::var("SIGNATURE_ANALYSIS_OUTPUT")
        .unwrap_or_else(|_| "target/library-signatures/miss-analysis.json".to_owned());
    fs::write(
        path,
        format!("{}\n", serde_json::to_string_pretty(&report).unwrap()),
    )
    .unwrap();
}

fn classify(
    image: &Image,
    address: u64,
    names: &[String],
    database: &Database,
    evidence: Option<&crate::sigs::Evidence>,
) -> &'static str {
    let Some(function) = image.functions.get(&address) else {
        return "function start not discovered";
    };
    let Some(size) = function.size else {
        return "function size unavailable";
    };
    let Some(bytes) = image.read_vaddr(address, size) else {
        return "function bytes unavailable";
    };
    let body = match normalize::checked(image.isa, bytes, address, &HashSet::new()) {
        Ok(body) => body,
        Err(reason) => return reason,
    };
    if !body.name_eligible {
        return "function too short or insufficient non-address bytes";
    }
    let Some(constants) = constants::image(image, &body) else {
        return "constant is writable, executable or unavailable";
    };
    if let Some(evidence) = evidence {
        return match evidence.certainty {
            Certainty::Ambiguous => "multiple names have the same body",
            _ => "callee confirmation or duplicate address rejected",
        };
    }
    let entries: Vec<_> = database
        .entries
        .iter()
        .filter(|entry| entry.isa == image.isa && names.contains(&entry.name))
        .collect();
    if entries.is_empty() {
        if names
            .iter()
            .any(|name| name.contains("{closure") || name.contains('<'))
        {
            return "generic, trait or closure name excluded from the baseline Rust sets";
        }
        if matches!(image.isa, Isa::X86_64 | Isa::I386) {
            let mut decoder = iced_x86::Decoder::new(
                if image.isa == Isa::I386 { 32 } else { 64 },
                bytes,
                iced_x86::DecoderOptions::NONE,
            );
            while decoder.can_decode() {
                if matches!(
                    decoder.decode().flow_control(),
                    iced_x86::FlowControl::IndirectCall | iced_x86::FlowControl::IndirectBranch
                ) {
                    return "indirect control flow omitted from the baseline sets";
                }
            }
        }
        return "no eligible signature for this symbol";
    }
    if entries.iter().any(|entry| entry.bytes == body.bytes) {
        return "referenced constant differs";
    }
    if database.entries.iter().any(|entry| {
        entry.isa == image.isa && entry.bytes == body.bytes && entry.constants == constants
    }) {
        return "callee confirmation or duplicate address rejected";
    }
    "normalized body differs; cause undetermined"
}

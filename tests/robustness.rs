//! Damaged files: truncated or with flipped bytes, every fixture either loads or
//! fails with an error, and every function it lists analyzes without a panic.

mod common;

use velk::service::Binary;

fn mix(seed: u64, key: u64) -> u64 {
    let mut value = seed ^ key.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

/// Variants of `bytes`: cut at several lengths, and with a few bytes overwritten.
fn damaged(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut variants = Vec::new();
    for fraction in [1, 2, 3, 5, 8] {
        variants.push(bytes[..bytes.len() * fraction / 10].to_vec());
    }
    for seed in 0..6 {
        let mut copy = bytes.to_vec();
        for flip in 0..16 {
            let position = (mix(seed, flip) % bytes.len() as u64) as usize;
            copy[position] = mix(seed, flip + 100) as u8;
        }
        variants.push(copy);
    }
    variants
}

#[test]
fn damaged_fixtures_never_panic() {
    let scratch = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("damaged");
    std::fs::create_dir_all(&scratch).expect("creating the scratch directory");
    let fixtures: Vec<_> = common::fixtures()
        .into_iter()
        .filter(|fixture| !fixture.starts_with("metrics"))
        .collect();
    common::in_parallel(&fixtures, |fixture| {
        let bytes = std::fs::read(common::fixtures_dir().join(fixture)).expect("reading a fixture");
        let name = fixture.to_string_lossy().replace('/', "_");
        for (index, variant) in damaged(&bytes).into_iter().enumerate() {
            let path = scratch.join(format!("{name}.{index}"));
            std::fs::write(&path, &variant).expect("writing a damaged copy");
            let Ok(mut binary) = Binary::open(&path) else {
                continue;
            };
            let addrs: Vec<u64> = binary.image().functions.keys().copied().take(200).collect();
            for addr in addrs {
                let _ = binary.decompile(addr, None);
                let _ = binary.card(addr, 240, None);
            }
        }
    });
}

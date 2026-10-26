use super::*;
use crate::loader::Isa;

#[test]
fn complete_signatures_match_in_both_orders_and_reject_corruption() {
    for pattern in patterns() {
        let mut image = Image::from_code(Isa::X86_64, 0x1000, pattern.bytes.clone());
        image.sections[0].executable = false;
        let matches = data(&image, None).unwrap();
        assert!(
            matches.iter().any(|found| found.name == pattern.name
                && found.address == 0x1000
                && found.order == pattern.order),
            "{} {}",
            pattern.name,
            pattern.order
        );
        for offset in [0, pattern.bytes.len() / 2, pattern.bytes.len() - 1] {
            let mut corrupted = pattern.bytes.clone();
            corrupted[offset] ^= 0x80;
            let mut image = Image::from_code(Isa::X86_64, 0x1000, corrupted);
            image.sections[0].executable = false;
            assert!(
                !data(&image, None)
                    .unwrap()
                    .iter()
                    .any(|found| found.name == pattern.name),
                "{} {offset}",
                pattern.name
            );
        }
    }
}

#[test]
fn standard_values_have_independent_known_entries() {
    let word = |name: &str, index: usize| {
        patterns()
            .iter()
            .find(|pattern| pattern.name == name)
            .unwrap()
            .words[index]
    };
    assert_eq!(word("aes_sbox", 0), 0x63);
    assert_eq!(word("aes_sbox", 255), 0x16);
    assert_eq!(word("aes_inverse_sbox", 0x63), 0);
    assert_eq!(word("md5_round_constants", 0), 0xd76aa478);
    assert_eq!(word("md5_round_constants", 63), 0xeb86d391);
    assert_eq!(word("sha256_round_constants", 63), 0xc67178f2);
    assert_eq!(word("sha512_round_constants", 79), 0x6c44198c4a475817);
    assert_eq!(word("sha224_initial_values", 0), 0xc1059ed8);
    assert_eq!(word("crc32_table", 1), 0x77073096);
    assert_eq!(word("crc64_ecma_table", 1), 0x42f0e1eba9ea3693);
}

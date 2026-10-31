//! Reverse branch-address transforms after decompression.

use super::DecodeError;

pub(super) fn decode(bytes: &mut [u8], filter: u8, target: u8) -> Result<(), DecodeError> {
    match filter {
        0 => return Ok(()),
        0x52 => {
            let end = bytes.len().saturating_sub(1);
            let (words, _) = bytes[..end].as_chunks_mut::<4>();
            for (index, word) in words.iter_mut().enumerate() {
                let instruction = u32::from_le_bytes(*word);
                if instruction & 0x7c000000 == 0x14000000 {
                    let relative = instruction.wrapping_sub(index as u32) & 0x03ffffff;
                    word.copy_from_slice(&((instruction & 0xfc000000) | relative).to_le_bytes());
                }
            }
            return Ok(());
        }
        0x50 => {
            let end = bytes.len().saturating_sub(1);
            let (words, _) = bytes[..end].as_chunks_mut::<4>();
            for (index, word) in words.iter_mut().enumerate() {
                if word[3] == 0xeb {
                    let instruction = u32::from_le_bytes(*word);
                    let relative = instruction.wrapping_sub(index as u32) & 0x00ffffff;
                    word[..3].copy_from_slice(&relative.to_le_bytes()[..3]);
                }
            }
            return Ok(());
        }
        0x26 | 0x46 | 0x49 => {}
        _ => {
            return Err(DecodeError::Unsupported(format!(
                "branch filter 0x{filter:02x}"
            )));
        }
    }
    if bytes.len() > 1 << 24 {
        return Err(DecodeError::Unsupported(
            "x86 branch filter span exceeds 24 bits".to_owned(),
        ));
    }
    let mut offset = 0;
    while offset + 5 < bytes.len() {
        if bytes[offset] & 0xfe == 0xe8 && bytes[offset + 1] == target {
            let address = u32::from_be_bytes(
                bytes[offset + 1..offset + 5]
                    .try_into()
                    .expect("four-byte branch address"),
            ) & 0x00ffffff;
            let relative = address.wrapping_sub((offset + 1) as u32);
            bytes[offset + 1..offset + 5].copy_from_slice(&relative.to_le_bytes());
            offset += 5;
        } else {
            offset += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::ir::smt::Proofs;

    #[test]
    fn smt_modular_branch_targets_round_trip() {
        if !Proofs::available() {
            return;
        }
        let mut proofs = Proofs::default();
        for bits in [24, 26] {
            let mask = (1u64 << bits) - 1;
            let field = format!("(bvand r0 (_ bv{mask} 64))");
            let encoded = format!("(bvand (bvadd {field} r1) (_ bv{mask} 64))");
            let decoded = format!("(bvand (bvsub {encoded} r1) (_ bv{mask} 64))");
            let wrong = format!("(bvand (bvadd {encoded} r1) (_ bv{mask} 64))");
            proofs.predicate(
                format!("{bits}-bit branch target inverse"),
                &field,
                &decoded,
            );
            proofs.counterexample(format!("{bits}-bit wrong branch direction"), &field, &wrong);
        }
        let target = "(bvand r0 (_ bv16777215 64))";
        let position = "(bvand r1 (_ bv16777215 64))";
        let relative = format!("(bvand (bvsub {target} {position}) (_ bv4294967295 64))");
        let encoded = format!("(bvand (bvadd {relative} {position}) (_ bv16777215 64))");
        let decoded = format!("(bvand (bvsub {encoded} {position}) (_ bv4294967295 64))");
        let wrong = format!("(bvand (bvadd {encoded} {position}) (_ bv4294967295 64))");
        proofs.predicate(
            "x86 24-bit target to 32-bit displacement",
            &relative,
            &decoded,
        );
        proofs.counterexample("x86 wrong branch direction", &relative, &wrong);
        proofs.check();
    }
}

#[cfg(kani)]
mod proofs {
    fn decode_length<const N: usize>(filter: u8) {
        let mut bytes: [u8; N] = kani::any();
        let original = bytes;
        assert!(super::decode(&mut bytes, filter, kani::any()).is_ok());
        // x86 needs one call and its four address bytes before the last byte; the
        // word filters leave the first word alone, since its distance is zero.
        let shortest = if matches!(filter, 0x50 | 0x52) { 9 } else { 6 };
        if N >= shortest {
            kani::cover!(bytes != original, "a branch is rewritten");
        }
    }

    // Every length up to twelve bytes, including those shorter than one rewritten branch.
    fn decode_every_length(filter: u8) {
        decode_length::<0>(filter);
        decode_length::<1>(filter);
        decode_length::<2>(filter);
        decode_length::<3>(filter);
        decode_length::<4>(filter);
        decode_length::<5>(filter);
        decode_length::<6>(filter);
        decode_length::<7>(filter);
        decode_length::<8>(filter);
        decode_length::<9>(filter);
        decode_length::<10>(filter);
        decode_length::<11>(filter);
        decode_length::<12>(filter);
    }

    /// The packer's direction, written from the instruction formats rather
    /// than from `decode`: the branch field of word `index` gains `index`
    /// (the word distance from the buffer start). The last byte of the buffer
    /// never starts a filtered word.
    fn encode_words(bytes: &mut [u8], arm: bool) {
        let words = bytes.len().saturating_sub(1) / 4;
        for index in 0..words {
            let at = index * 4;
            let word = u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
            let encoded = if arm {
                if bytes[at + 3] != 0xeb {
                    continue;
                }
                (word & 0xff00_0000) | (word.wrapping_add(index as u32) & 0x00ff_ffff)
            } else {
                if word & 0x7c00_0000 != 0x1400_0000 {
                    continue;
                }
                (word & 0xfc00_0000) | (word.wrapping_add(index as u32) & 0x03ff_ffff)
            };
            bytes[at..at + 4].copy_from_slice(&encoded.to_le_bytes());
        }
    }

    /// Decoding undoes the packer's transform on every input of length `N`,
    /// and some input has a rewritten branch after the first word.
    fn round_trip<const N: usize>(filter: u8) {
        let original: [u8; N] = kani::any();
        let mut bytes = original;
        encode_words(&mut bytes, filter == 0x50);
        let encoded = bytes;
        assert!(super::decode(&mut bytes, filter, 0).is_ok());
        assert_eq!(bytes, original);
        if N >= 9 {
            kani::cover!(
                encoded != original,
                "a later word's branch field is encoded"
            );
        }
    }

    fn round_trip_every_length(filter: u8) {
        round_trip::<0>(filter);
        round_trip::<4>(filter);
        round_trip::<5>(filter);
        round_trip::<8>(filter);
        round_trip::<9>(filter);
        round_trip::<12>(filter);
        round_trip::<13>(filter);
    }

    #[kani::proof]
    #[kani::unwind(14)]
    fn x86_branch_filters() {
        decode_every_length(0x26);
        decode_every_length(0x46);
        decode_every_length(0x49);
    }

    #[kani::proof]
    #[kani::unwind(14)]
    fn arm_branch_filter() {
        decode_every_length(0x50);
        round_trip_every_length(0x50);
    }

    #[kani::proof]
    #[kani::unwind(14)]
    fn aarch64_branch_filter() {
        decode_every_length(0x52);
        round_trip_every_length(0x52);
    }
}

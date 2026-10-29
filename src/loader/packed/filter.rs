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

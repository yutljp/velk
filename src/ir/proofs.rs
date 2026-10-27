//! Width-dependent scalar helper properties.

#[kani::proof]
fn bit_fields() {
    let value: u64 = kani::any();
    let bits: u32 = kani::any();
    kani::assume((1..=64).contains(&bits));
    let mask = super::semantics::mask(bits);
    let signed = super::semantics::sign_extend(value, bits);
    assert_eq!(signed as u64 & mask, value & mask);
    let shift = 64 - bits;
    assert_eq!(signed, ((value << shift) as i64) >> shift);
    kani::cover!(
        bits == 1 && signed == -1,
        "one-bit negative extension is reachable"
    );
    kani::cover!(
        bits == 64 && value == 1u64 << 63,
        "the signed minimum is reachable"
    );
    if bits < 64 {
        let limit = 1i64 << (bits - 1);
        assert!(signed >= -limit && signed < limit);
        assert_eq!(mask.count_ones(), bits);
    } else {
        assert_eq!(mask, u64::MAX);
        assert_eq!(signed as u64, value);
    }
}

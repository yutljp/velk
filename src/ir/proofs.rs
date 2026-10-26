//! Width-dependent scalar helper properties.

#[kani::proof]
fn bit_fields() {
    let value: u64 = kani::any();
    let bits: u32 = kani::any();
    kani::assume((1..=64).contains(&bits));
    let mask = super::semantics::mask(bits);
    let signed = super::semantics::sign_extend(value, bits);
    assert_eq!(signed as u64 & mask, value & mask);
    if bits < 64 {
        let limit = 1i64 << (bits - 1);
        assert!(signed >= -limit && signed < limit);
        assert_eq!(mask.count_ones(), bits);
    } else {
        assert_eq!(mask, u64::MAX);
        assert_eq!(signed as u64, value);
    }
}

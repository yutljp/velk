/// True when `magic` is a multiplier that divides by `divisor` at some shift,
/// so a remainder that multiplies the quotient back by `divisor` is exact.
/// A zero-extended 32-bit value can sit in a 64-bit register, so a wider
/// dividend also accepts a 32-bit magic.
pub(crate) fn magic_matches(magic: u64, divisor: u64, domain_bits: u64, signed: bool) -> bool {
    [domain_bits, domain_bits.min(32)].into_iter().any(|bits| {
        let at_some_shift = (0..=127).any(|shift| {
            let found = if signed {
                magic_divisor_signed64(magic, shift, bits)
            } else {
                magic_divisor(magic, shift, bits)
            };
            found == Some(divisor)
        });
        at_some_shift || (signed && magic_divisor_signed(magic, bits) == Some(divisor))
    })
}

/// Divisor for the signed `(x * M) >> S` (ARM64 `smulh` or x86-64 `imul`),
/// exact over all `x` in `[-2^(n-1), 2^(n-1))`.
pub(crate) fn magic_divisor_signed64(
    magic: u64,
    total_shift: u64,
    domain_bits: u64,
) -> Option<u64> {
    // The quotient may be the multiply's high half alone, so the shift can
    // equal the domain width.
    if magic == 0 || total_shift < domain_bits || total_shift > 127 || domain_bits > 64 {
        return None;
    }
    let modulus: u128 = 1u128 << total_shift;
    let magic_ = u128::from(magic);
    let domain: u128 = 1u128 << domain_bits;
    let base = modulus / magic_;
    for offset in 0..=2u128 {
        let divisor = base + offset;
        if divisor == 0 || divisor >= domain {
            continue;
        }
        let product = divisor * magic_;
        if product < modulus {
            continue;
        }
        let slip = product - modulus;
        let inputs = (domain / 2 - 1) / divisor;
        if inputs * slip <= modulus && inputs * slip < magic_ {
            return u64::try_from(divisor).ok();
        }
    }
    None
}

/// Divisor for the unsigned `(x * M) >> S`, exact over all `x` in
/// `[0, 2^domain_bits)`.
pub(crate) fn magic_divisor(magic: u64, total_shift: u64, domain_bits: u64) -> Option<u64> {
    if magic == 0 || total_shift < domain_bits + 1 || total_shift > 127 || domain_bits > 64 {
        return None;
    }
    let modulus: u128 = 1u128 << total_shift;
    let magic_ = u128::from(magic);
    let domain: u128 = 1u128 << domain_bits;
    let base = modulus / magic_;
    for offset in 0..=2u128 {
        let divisor = base + offset;
        if divisor == 0 || divisor >= domain {
            continue;
        }
        let product = divisor * magic_;
        if product < modulus {
            continue;
        }
        let slip = product - modulus;
        let inputs = (domain - 1) / divisor;
        if inputs * slip < magic_ {
            return u64::try_from(divisor).ok();
        }
    }
    None
}

/// Divisor for the signed `hi + sign` chain, where `hi` is the high 32 bits of
/// the widening product (a fixed shift of 32).
pub(crate) fn magic_divisor_signed(magic: u64, domain_bits: u64) -> Option<u64> {
    const TOTAL_SHIFT: u64 = 32;
    if magic == 0 || magic > 0xffff_ffff || domain_bits != 32 {
        return None;
    }
    let modulus: u128 = 1u128 << TOTAL_SHIFT;
    let magic_ = u128::from(magic);
    let domain: u128 = 1u128 << domain_bits;
    let base = modulus / magic_;
    for offset in 0..=2u128 {
        let divisor = base + offset;
        if divisor == 0 || divisor >= domain {
            continue;
        }
        let product = divisor * magic_;
        if product < modulus {
            continue;
        }
        let slip = product - modulus;
        let inputs = (domain / 2 - 1) / divisor;
        if inputs * slip <= modulus && inputs * slip < magic_ {
            return u64::try_from(divisor).ok();
        }
    }
    None
}

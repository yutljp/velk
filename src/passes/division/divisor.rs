/// Finds a candidate divisor at any shift. The complete quotient expression
/// must still pass the exact shift, sign correction, and width checks.
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
    if magic == 0
        || !(1..=64).contains(&domain_bits)
        || total_shift < domain_bits
        || total_shift > 127
    {
        return None;
    }
    let modulus: u128 = 1u128 << total_shift;
    let magic_ = u128::from(magic);
    let domain: u128 = 1u128 << domain_bits;
    let base = modulus / magic_;
    for offset in 0..=2u128 {
        let divisor = base + offset;
        if divisor == 0 || divisor >= domain / 2 {
            continue;
        }
        let product = divisor * magic_;
        if product < modulus {
            continue;
        }
        let slip = product - modulus;
        if slip == 0 {
            continue;
        }
        let half = domain / 2;
        let positive = max_error(half - 1, divisor, magic_, slip);
        let negative = max_error(half, divisor, magic_, slip);
        if positive < modulus && negative <= modulus {
            return u64::try_from(divisor).ok();
        }
    }
    None
}

/// Divisor for the unsigned `(x * M) >> S`, exact over all `x` in
/// `[0, 2^domain_bits)`.
pub(crate) fn magic_divisor(magic: u64, total_shift: u64, domain_bits: u64) -> Option<u64> {
    if magic == 0
        || !(1..=64).contains(&domain_bits)
        || total_shift < domain_bits + 1
        || total_shift > 127
    {
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
        if max_error(domain - 1, divisor, magic_, slip) < modulus {
            return u64::try_from(divisor).ok();
        }
    }
    None
}

/// Divisor for the signed `hi + sign` chain, where `hi` is the high 32 bits of
/// the widening product (a fixed shift of 32).
pub(crate) fn magic_divisor_signed(magic: u64, domain_bits: u64) -> Option<u64> {
    if magic == 0 || magic > 0xffff_ffff || domain_bits != 32 {
        return None;
    }
    magic_divisor_signed64(magic, 32, domain_bits)
}

// In each quotient interval x = q*d + r, the error is q*slip + r*magic.
// Its maximum occurs at the last input or at the preceding full interval.
fn max_error(last: u128, divisor: u128, magic: u128, slip: u128) -> u128 {
    let quotient = last / divisor;
    let tail = quotient * slip + (last % divisor) * magic;
    if quotient == 0 {
        tail
    } else {
        tail.max((quotient - 1) * slip + (divisor - 1) * magic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reciprocal_certificates_hold_over_small_domains() {
        for bits in 2..=8 {
            for shift in bits..=12 {
                for magic in 1..=255 {
                    if let Some(divisor) = magic_divisor(magic, shift, bits) {
                        for x in 0..1u128 << bits {
                            assert_eq!((x * u128::from(magic)) >> shift, x / u128::from(divisor));
                        }
                    }
                    if let Some(divisor) = magic_divisor_signed64(magic, shift, bits) {
                        let half = 1i128 << (bits - 1);
                        for x in -half..half {
                            assert_eq!(
                                ((x * i128::from(magic)) >> shift) + i128::from(x < 0),
                                x / i128::from(divisor),
                                "bits={bits} shift={shift} magic={magic} x={x}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn signed_exact_reciprocals_do_not_allow_an_added_sign_bit() {
        assert_eq!(magic_divisor_signed(0x8000_0000, 32), None);
        assert_eq!(magic_divisor_signed64(1u64 << 62, 64, 64), None);
    }

    #[test]
    fn unsigned_high_product_checks_the_last_partial_interval() {
        assert_eq!(magic_divisor(0x8000_0000_8000_0001, 65, 32), None);
        let x = u128::from(u32::MAX);
        assert_eq!((x * 0x8000_0000_8000_0001u128) >> 65, x / 4 + 1);
    }

    #[test]
    fn invalid_domains_and_shifts_are_refused() {
        for bits in [0, 65, u64::MAX] {
            assert_eq!(magic_divisor(1, 64, bits), None);
            assert_eq!(magic_divisor_signed64(1, 64, bits), None);
        }
        assert_eq!(magic_divisor(1, u64::MAX, 64), None);
        assert_eq!(magic_divisor_signed64(1, u64::MAX, 64), None);
    }
}

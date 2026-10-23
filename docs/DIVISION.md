# Constant division and remainder

The recognizers in `src/passes/division` propose replacements. Before changing
an expression or its types, `proof::equivalent` checks its complete reaching
expression, including register reads, assignment truncation, sign extension,
shift direction, and comparison width. Each read follows the definition that
reaches that point. Unsupported operations or an expansion exceeding 512
expression nodes refuse the replacement. When a multiply overwrites an input
copy, its unmodified source or a narrower view may be proposed; that expression
must pass the same complete proof.
Signed replacements cannot use an interpretation wider than their assignment.
Intermediate assignments remain available until dead-code elimination.

## Reciprocal conditions

Let `n` be the proven dividend width (32 or 64), `M` a positive multiplier,
`S` the total product shift (at most 127), `T = 2^S`, `d` the proposed positive
divisor, and `e = d*M - T`. The product must not overflow before the shift: ordinary
multiplication is accepted only for a 32-bit dividend and `M <= 2^32 - 1`.
A high-half multiplication contributes 64 to `S` and must have the required
signedness. A signed multiplier must fit a positive `int64_t`.

Define `E(L)` as below. Unsigned division requires `S >= n+1`, `e >= 0`, and
`E(2^n - 1) < T`. It proves `floor(x*M/T) = floor(x/d)` throughout the
unsigned domain, including the last partial quotient interval.

For signed division with an added sign bit, define

```
q = floor(L/d)
E(L) = max(q*e + (L % d)*M, (q-1)*e + (d-1)*M)
```

The second term is omitted when `q = 0`. This is the maximum of
`floor(y/d)*e + (y % d)*M` for `0 <= y <= L`: in each quotient
interval it increases with the remainder, and successive complete interval
maxima increase with the quotient. With `H = 2^(n-1)`, the certificate is
`S >= n`, `1 < d < H`, `e > 0`, `E(H-1) < T`, and `E(H) <= T`. It proves
`floor(x*M/T) + [x < 0] = trunc(x/d)`, including `x = -H`.
An exact reciprocal (`e = 0`) fails this particular formula at negative
multiples of `d`: adding the sign bit would increase an already exact quotient.
All bounds are evaluated with `u128`.

## Accepted arithmetic forms

- Unsigned ordinary product: `((uint64_t)(uint32_t)x * M) >> S`, with the
  unsigned certificate over 32 bits. A 64-bit low product cannot establish
  a 32-bit domain by using a smaller multiplier.
- Unsigned high product: `umulh(x, M) >> k`, with `S = 64 + k` and the
  unsigned certificate over the actual input domain. Copies must preserve
  the bits subsequently read. An arbitrary mask is not a copy.
- Signed ordinary product: a sign-extended 32-bit dividend times `M`, shifted
  arithmetically by `S`, plus a logical sign bit. A logical main shift is
  also valid when `S >= 32` and a 32-bit result discards the upper sign bits.
- Signed high product: `smulh(x, M)` shifted arithmetically by `k`, plus a
  logical sign bit, with `S = 64 + k`. The sign bit may come from the
  product, the dividend, or a main term whose width preserves its sign.
  An arithmetic sign shift produces `-1`, not the required `1`.
- Named widened shifts and a sign bit from the truncated high half use the
  same signed certificate and width checks as the preceding two forms.
  The exact main term that is shifted must be the one added at the end.
- Signed power of two: `(x >= 0 ? x : x + (d-1)) >> k`, with `d = 2^k`,
  `0 < k < n-1`, arithmetic shift and comparison at width `n`. Reversed
  `x < 0` branches are equivalent. The predicate, plain arm, adjusted arm,
  and replacement must read the same dividend value. The bias is used
  only for negative inputs, where it cannot overflow.
- Signed masked power of two: `x - ((x >= 0 ? x : x + (d-1)) & -d)`,
  with the same predicate, bias, domain and width conditions.
- Signed conditional negation: choose `x & (d-1)` when `-x` has its sign
  bit set, otherwise `-((-x) & (d-1))`, reversing branches for the
  complementary condition. All terms use the same width and dividend.
  For the minimum signed input, negation wraps, but both masked terms
  are zero because `d` divides that input.
- Multiply-back remainder: `x - q*d` modulo the result width, where `q`
  is proved to divide that exact value of `x` by that exact `d`. Shifts,
  additions and multiplies used to form `q*d` must retain the same quotient
  expression and multiply to `d`; tracking a cumulative factor alone is
  insufficient. A quotient already proved at an earlier statement is
  also accepted. Copies or intervening divisor loads cannot change any
  operand the subtract reads.

Add-back algorithms and negative multipliers are not certified by these forms.
They keep their original arithmetic.

## Regression coverage

`tests/recompile/division.rs` checks valid forms and mutations of the bias,
predicate, shift, sign fix-up, product signedness, product width, mask, sum
operand and reaching dividend. It checks the printed operators and compares
compiled C with the original IR on boundary and pseudorandom inputs at both
compiler optimization levels. The arithmetic certificate also has small-domain
exhaustive tests in `division::divisor`.

For example, with an unsigned 32-bit input, `M = 0x8000000080000001`
and `S = 65`, multiplying the high half and shifting it once gives
`0x40000000` at `x = 0xffffffff`; `x / 4` gives `0x3fffffff`.
Checking only `floor((2^n - 1)/d)*e < M` would accept this mismatched pair.

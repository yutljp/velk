# Mixed bitwise and arithmetic expressions

The default analysis simplifies expressions such as `(x ^ y) + 2 * (x & y)`
to `x + y`, `x + y - 2 * (x & y)` to `x ^ y`, and
`(x | y) + (x & y) - y` to `x`. Constant cancellation, constant scaling,
and products of these sums use the same normalization.

The normalizer expresses each bitwise function as an integer sum of AND terms,
then combines polynomial coefficients with 64-bit wrapping arithmetic. It
compares the complete coefficient maps before accepting a shorter expression.
The candidates include the expanded polynomial, individual registers, complements,
and binary arithmetic and bitwise operations on pairs of registers. This is a
bounded search, not a guarantee of the shortest possible expression.

The supported trees contain at most three distinct register reads, with widths
8, 16, 32 or 64, integer constants, addition, subtraction, multiplication,
and constant left shifts. Bitwise AND, OR and XOR terms may contain register
reads and the constants zero and all ones. Arbitrary bit masks inside these
terms, memory reads, division, right shifts and machine operations are excluded.
The search stops at 192 nodes, depth 32, 32 polynomial terms or degree four.
Unsupported trees remain eligible for simplification of supported subexpressions.
Widths are preserved inside expressions and comparisons, where signed operations
can depend on them. Arithmetic containing only bitwise complements is reduced
only to a constant or a register, preserving scaled array indexes such as
`base + (~index) * size + offset`. No solver runs during normal analysis.

CLI cards (`velk --card app mba_add`), JavaScript cards and function summaries,
and scripts run through MCP expose `simplification.mbaExpressionsSimplified`.
This counts accepted expression replacements during analysis; it does not count
source functions or identities already removed by the compiler. `simplified`
is true when any expression, predicate or dispatcher was simplified.

```javascript
const f = velk.open("app").getFunction("mba_add");
[f.card().simplification, f.summary().simplification]
```

The fixture source is `tests/cases/mba/expressions.c`.
`sh tests/make_mba_fixtures.sh` builds x86-64 and AArch64 objects with Clang
at `-O0` and `-O2`. `cargo test --release --test mba -- --test-threads 3`
compiles printed C at both optimization levels and compares it with native source
and independent unsigned formulas, including boundary inputs. The same test checks
the CLI, JavaScript and MCP data. The [SMT inventory](smt-rules.md) records the
normalizer's symbolic checks and their limits.

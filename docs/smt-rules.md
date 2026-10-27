# Expression equivalence tests

The normal Rust unit suite includes test-only Z3 checks. Run them with
`cargo test --release --lib smt -- --test-threads 3 --nocapture`.
Integer predicate and dominating-guard checks also run with
`cargo test --release --lib passes::deobfuscation -- --test-threads 3`.
Z3 must be on PATH. The tests print a clear skip message when it is absent.
The rendered-C tests also need Clang and uv. Python runs through
`uv run --no-project tests/smt_c.py` and uses only the standard library.
velk has no additional runtime dependencies.

Automatic string recovery checks known-bit extraction into stored bytes against
symbolic inputs for each byte position. Memory mapping and decoder control flow
are covered by execution tests, not by that bit-vector check.

The [inventory](../tests/smt_inventory.tsv) records grouped rewrite
families, source locations, side conditions, applicable widths and current
coverage. Rows distinguish symbolic template or instance checks, open or
partial coverage, and nondeterministic refinement rather than equality.
These counts describe inventory rows, not individual match arms or universal
proofs of every rule. The inventory is not a completeness certificate for every
expression transformation in the repository.

ARM32 checks cover carry arithmetic's zero, sign, carry and overflow flags,
rotate-through-carry values and flags, immediate shifted carry extraction,
and long multiplication with accumulation.
Word joining and nested frame offsets have symbolic checks. Frame alias
subtraction is checked through the real settling pass. Calls, ABI placement,
image-backed literal reads, frame alignment and general control flow remain open.
Offsets in recovered frame objects have symbolic address checks for i386,
x86-64, AArch64 and ARM32. Compiled array loops check that the printed function
uses one object and returns the same values as the C source. C object provenance
is outside the SMT model.

## Coverage priorities and added obligations

The following order ranks the inventory's open and partial families and the
ARM32 families checked below. Families in a row have equal priority; this is a
correctness review order, not a measured defect frequency. The inventory retains
the remaining scope.

| Priority and reason | Inventory families |
| --- | --- |
| 1. Arithmetic, comparisons and flags: a wrong value or branch changes the result. | Integer and vector constant folding; Recover overwritten comparison operand; Carry arithmetic and flags; Remove conditions fixed by dominating guards |
| 2. Casts, extensions and demanded widths: signed interpretation and discarded bits affect C results. | Remove redundant low32 view; Specialize variables to32 and drop masks; Remove masks/extensions and replace singletons; Narrow to demanded low bits; Division/remainder casts; Omit integer/float conversion casts; Fit return/argument type; Narrow assignment spelling; Narrow printed locals |
| 3. Shifts: carry supplies a result bit and the outgoing carry. | Rotate through carry |
| 4. Division idioms: composition must connect the recognized chain to its certificate. | Unsigned reciprocal multiply/shift; Signed high-product quotient; Unsigned high-product quotient; Signed widening quotient; Named widening-product quotient; Multiply-back remainder chain; Following multiply/subtract remainder; Accept quotient equivalence; Accept remainder equivalence |
| 5. Address folding and memory: address arithmetic needs object, alias and frame facts. | Remove unsigned-load mask; Store-to-load forwarding; Fuse load/op/store; Forward spilled variables; Replace frame pointer; Scale pointer arithmetic and spell negative offsets; Select common type/casts; Fold byte pointer arithmetic; Replace raw load by named access; Promote saved parameters; Stack addresses to array offsets; ABI object access to local object; Fold structure scales/indexes; Read immutable literal bytes; Normalize word frame addresses and aliases; Known-bit extraction into stored bytes |
| 6. Other effects, control flow and floating expressions: finite scalar templates do not establish these contexts. | Identical-operand sub/xor/and/or; Recursive expression substitution; Remove single-use definition; Inline local copy; Inline into only reader; Share repeated expression; Fold SSA assignments and branches; Remove floating mask; Drop update masks; Substitute returned copy; Inline values into structured nodes; Pair calls and results; Runtime division remainder; Find redundant copies across blocks; Replace redundant structured copies; Drop unused argument-register result bindings; Permute x86 scratch registers for signature matching |

The added checks call the real lowering, simplifier and remainder matchers:

- ARM32 ADC/SBC/RSC compares the zero-extended 32-bit result in the
  64-bit IR register with the modular sum or difference. Overflow compares the
  signed 64-bit exact sum or difference (including the incoming carry or borrow)
  against the 32-bit signed limits.
  All 32-bit operands and both incoming carry values are symbolic. Negative controls
  omit the incoming carry/borrow, omit result truncation or invert each NZCV flag.
- ARM32 RRX compares its 32-bit result with the concatenation of the incoming
  carry and source bits 31 through 1. The stored NZCV flags are independently
  symbolic. It checks zero upper bits in the 64-bit IR destination,
  NZC updates and V preservation,
  and preservation of all four flags without S. Missing carry and inverted
  flags are negative controls. Unknown incoming carry must refuse lowering.
- Remainder scans use 32/64-bit signed and unsigned dividends, divisors
  2/8/128/2^30, quotient copies and multiply-back steps. Following remainders
  include inline and named multiplier constants. The production equivalence
  guard must accept each replacement; symbolic execution compares return values
  and definedness. Wrong divisors and negated remainders are negative controls.
  These templates start with a quotient; reciprocal integration and scaled-add
  scans remain open.
- Full 32-bit unsigned dividends use multiplier 2^31 and shifts
  32/33/40/61/63 in a 64-bit product. The actual simplifier must emit division
  by 2^(shift-31), and both expressions are proved equal. Halving the divisor
  is a negative control. Non-power-of-two full-width composition remains open.

The ARM32 templates assign a destination distinct from every register read by
the input and flag expressions. They do not check captures when the destination
aliases an input.

`Proofs::counterexample` requires SAT for each deliberately wrong equality;
UNSAT or an exhausted solver limit fails the test. Equality checks require
UNSAT. Identical queries share work only when their expected results also match.
The negative controls accompany the added checks; older checks do not all have
negative controls.
COM vtable load substitution checks the real renderer preparation on both Windows
fixtures with symbolic input registers and byte-array memory. The check observes
the indirect target before the call. Method ABI matching is covered by the
compiled execution tests rather than this equivalence check.

## Connection to the implementation

Tests build raw input expression trees without invoking the simplifying
constructor, then invoke the real Rust constructor or pass. Both trees are
translated to SMT. Register inputs remain symbolic. Comparisons and signed
operations are also checked as enclosing expressions, through the actual
pass, because inferred operand widths affect their meaning.
When a rewrite preserves both value and inferred width, scalar contexts
preserve equality by congruence; only width-changing cases need those extra
context checks. Zero arithmetic shifts additionally use assembled symbolic
fields spanning every possible 64-bit value at each inferred width.

Straight-line tests execute assignments symbolically, including destination
truncation, before and after eight real optimization passes. A second executor
models acyclic branches, switches, traps and byte stores. It compares return
values, definedness and final memory. Private-frame tests observe the return
value and definedness, allowing writes to unescaped frame slots to disappear. Flag tests
compare the real recovered predicates with independent flag formulas.
Rotation and byte reversal tests compare the real lowered expressions with
bit-vector rotation and byte extraction. Variable rotation counts are partitioned
by every possible residue modulo the width (8/16/32/64). Each query binds the low
count bits after lowering and leaves the upper bits symbolic, covering every
64-bit count without changing the variable-count lowering. This avoids exhausting
the solver's resource limit on a single symbolic rotation query with Z3 4.13.3.
Constant-count and byte-reversal checks remain separate obligations.
Reciprocal tests obtain accepted divisors from Rust and prove their
quotient-interval inequalities for every
dividend in the corresponding domain, using integer arithmetic. They test
a finite corpus of multipliers, shifts and candidate divisors.

For scalar C, the real renderer generates functions. Clang parses the emitted
C and supplies a typed AST, including implicit integer promotions and casts.
The test script symbolically executes scalar declarations, assignments and
conditionals, and translates that AST to bit vectors and validity conditions
for signed overflow, shifts and division. A result must agree with the IR,
and the C must be defined whenever the modeled IR is defined. Leading/trailing
zero counts are checked at 8/16/32/64 bits, including zero inputs and input
truncation. A separate Clang/UBSan regression compiles and executes a masked
sum, negation and negative pointer indexes.

The inventory's `site` line numbers and [source digests](../tests/smt_sources.sha256)
are generated by the normal inventory test with `VELK_BLESS=1`. It finds each
`anchor` in its source file and requires exactly one literal occurrence.
The test parses Rust syntax and selects the smallest enclosing function or
match arm containing the entire anchor. A function includes its attributes,
signature and body; an arm includes its attributes, pattern, guard, body and
trailing comma when present. The SHA-256 covers the exact source bytes from
the first token through the last token of that span, including internal
whitespace and comments. Leading indentation and trailing whitespace outside
the span are excluded. Anchors outside these constructs are rejected.
The digest list is sorted by source path and anchor, with one entry for each
distinct pair; rows sharing an anchor share a digest. Line numbers are excluded
from digest keys. Moving an unchanged span only requires blessing locations;
edits outside it do not invalidate its review.
Git's union merge driver retains both sides of changes to the inventory and
digest files. After a merge or rebase, regenerate their sorted rows and remove
duplicates by running:

```sh
VELK_BLESS=1 cargo test --release --lib inventory -- --test-threads 3
```

Keep both sides' rewrite families and reviewed coverage when merging. Each row's
`rewrite`, `side_conditions`, `widths`, `coverage`, `anchor` and
`reviewed_sha256` fields are maintained by hand; blessing never changes them.
If duplicate keys have different reviewed digests, blessing keeps matching
reviews when the current source matches one. If none matches, it retains the
rows and fails so they can be reviewed. Conflicting rows with the same matching
digest also require manual resolution. Run the test without blessing to detect
duplicate, unsorted or stale rows.
For a source change, inspect the rewrite and its tests, update the coverage
and conditions as needed, then manually copy the reviewed source's SHA-256
from the generated digest list entry for that path and anchor into the affected
rows' `reviewed_sha256`.
The test fails on a reviewed-digest mismatch even in bless mode, after writing
the generated metadata. Repeated blessing cannot approve a source change.
Run the test again without blessing to check both metadata and review fields.
This check covers only the selected span, not called helpers, imports or other
dependencies outside it. Changes to those dependencies still require review.
The inventory holds the current coverage; this document does not duplicate
its counts.

Covered outputs are regenerated by calling the implementation on each run;
there are no saved replacement expressions that can silently remain unchanged
when a rewrite changes.

## Model and limits

Repeated-byte fill intervals have symbolic byte-array checks for store widths
1, 2, 4 and 8 bytes, each overlap offset and both store orders in the test
corpus. The tests call the real interval helper, then compare the original
stores with stores covering its returned range. Initial memory, base address
and fill byte are symbolic. Exhaustive small-range checks and compiled rendered
C complement these queries. This does not prove arbitrary address expressions,
volatile accesses, faults or C object provenance.

IR arithmetic uses 64-bit modular values. Narrow registers are zero-extended
reads. Signed shifts, division, remainder and comparisons use the real
operand-width calculation. Shift counts use their low six bits. Selects
evaluate only the selected alternative. Division-by-zero validity is
preserved, including when a rewrite would discard its evaluation.

Memory reads use a total little-endian byte array. This models loaded values,
not page faults, volatile accesses, lifetime or C pointer provenance. Calls,
atomics, arbitrary control-flow graphs and ABI object transformations
are not modeled by these checks. IEEE single/double constant folding uses SMT floating-point operations with
round-to-nearest-even arithmetic and explicit conversion rounding modes.
Integer conversions include invalid and saturating results. Comparison flags
are checked for arbitrary IEEE bit patterns, including NaNs. Integer/vector
constant instances cover lane arithmetic, comparisons, shifts, saturation,
counts, interleaving, widening and narrowing; packing, cryptographic operations
and wide division remain open. Saturating and high-product lane models refuse
widths above 32 bits rather than silently approximate them. Signed power-of-two chain tests compare the real pass before and after
rewriting. Reciprocal matcher tests check the emitted quotient and the integer
certificate separately; the connection between a high product and that
certificate remains a compositional proof gap. The normalizer has independent
symbolic tests for truncation, sign extension and modular operands.

Byte-count summation is checked compositionally. A byte count is abstracted
by an arbitrary four-bit function shared by both sides; actual byte counts
fit that range. One half is checked symbolically. The two-half Rust output
is checked structurally and its widening addition is proved separately.
This avoids a slow bit-level associativity proof.

Template constants and expression shapes form a finite corpus. Each accepted
SMT obligation proves all symbolic register values, not every possible
constant parameter, tree shape, surrounding program or renderer context.
An unsupported operation or AST node fails instead of being skipped. A SAT
result or exhausted solver work limit fails and saves an SMT query under `target/`.
Each query has a deterministic limit of 10,000,000 Z3 resource units rather
than a wall-clock timeout, so CPU contention does not reduce its proof budget. These tests
do not establish the requested repository-wide, all-rule verification goal.

## Regression counterexamples

| Transformation | Counterexample | Required correction |
| --- | --- | --- |
| Arithmetic shift by zero | An 8-bit `x = 0x80`; `(x + x) sar 0` is zero, not `0x100`. | Retain the arithmetic shift's truncation. |
| Merge masks under signed arithmetic | `((x & 0xff) & 0xffff) sar 1`, with `x = 0x80`, is `0x40`, not `0xc0`. | Preserve the signed operation's operand width. |
| Propagate an assigned constant | Assign all ones at 8 bits, then read 64 bits: the value is `0xff`. | Record the truncated assigned constant. |
| Print masked signed addition | Signed 32-bit `0x40000000 + 0x40000001` overflows even under `& 0xff`. | Use unsigned arithmetic when signed overflow is not excluded. |
| Print unary negation | Negating `INT64_MIN` wraps to itself in the IR but overflows signed C. | Negate without a sign, then restore a signed 64-bit result where needed. |
| Discard a 64-bit extension's high merge | Extend `((1 << 32) & ~0xffffffff) | 1` from eight bytes: it remains `0x100000001`. | Use the full source-width mask. |
| Cancel equal faulting expressions | `(42 / 0) - (42 / 0)` cannot become zero. | Retain potentially faulting evaluations. |

## Additional regressions and remaining gaps

| Transformation | Counterexample | Required correction |
| --- | --- | --- |
| AArch64 unsigned full-width extension | `UXTX(0x100000000)` is `0x100000000`, not zero. | Preserve all 64 input bits. |
| Print signed division/remainder | `INT32_MIN / -1` and `INT64_MIN % -1` must have the IR's wrapping results; signed C overflows. | Compute at a wider signed type and narrow the result. |
| Extend a narrow quotient | Sign-extending the eight-bit result of `-128 / -1` gives `-128`, not `128`. | Restore the narrow signed result after integer promotions. |
| Print zero counts | At eight bits, `clz(254)` is zero, not 24; `clz(0)` and `ctz(0)` return the width. | Truncate to the unsigned source type and use a builtin with an explicit zero result. |

All these cases failed against the implementation before correction. Rendered
C checks include signed division contexts; a compiled UBSan regression also
executes variable-divisor quotient and remainder functions.

The following inventory rows remain entirely open. They are modeling gaps,
not claims that the transformations are unprovable:

- Compound update masks: scalar assignments split into separate locals and
  do not exercise the compound-update helper.
- Frame-pointer replacement: the balanced-frame tests do not exercise saved
  frame-pointer setup and restoration.
- Floating-mask removal and implicit integer/float conversions in the
  renderer: the C AST translator currently supports integer C, not floating
  expressions or union bit reinterpretations.
- Byte-pointer folding, named memory access, saved-parameter promotion,
  stack-array offsets and ABI object access: require a C object, bounds,
  aliasing and ABI model beyond the total byte array.
- Structure scale/index folding: requires independently checked layout facts.

Partial rows retain their specific missing scope in the inventory: arbitrary
loops, calls, atomics, volatile/faulting memory, ABI captures, caller safety,
general range/demand facts and structured control flow are not established
by the finite acyclic templates. FP exception flags, dynamic rounding modes
and processor-specific NaN payload selection are not modeled. Floating
arithmetic folds that produce NaNs remain deliberately unfurled.

New proof entry points are `rewrite_tests` and `program` under `ir::smt`,
`division::smt_tests`, `division::proof::smt_tests`, the architecture lowering
SMT tests, and `compiled_assignments_and_return_conversions_are_equivalent`.
Every solver test must submit at least one nontrivial obligation. Zero-count
printing uses Clang generic `__builtin_clzg` / `__builtin_ctzg`, whose
second argument supplies the zero result. The rendered C corpus and UBSan
execution check both zero inputs and narrow operands with high input bits.

Mixed bitwise/arithmetic checks exercise the actual normalizer and accepted
replacement search at 8, 16, 32 and 64 bits. They check all 256 Boolean
functions of three inputs compositionally: each Boolean assignment uses an
arbitrary shared bit mask, and linearity combines the bit positions.
Direct symbolic checks cover linear sum/XOR/OR identities,
constant cancellation and scaling. The quadratic template composes the proved
sum identity with a symbolic polynomial ring check. Coefficient and shift
instances cover wrapping boundaries. Negative controls use changed coefficients,
faulting inputs, unsupported masks and search limits. These are bounded templates,
not a proof for every polynomial tree accepted by the implementation.

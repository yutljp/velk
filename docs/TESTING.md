# Testing and validation

velk checks instruction lifting, IR transformations, and generated pseudo-C
at separate boundaries. Tests use checked-in binary fixtures and finite
input sets; a passing test is evidence for those cases, not a proof that
every recovered function is correct or valid C.

## Running the checks

From the repository root:

```bash
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 cargo test --release
cargo fmt -- --check
CARGO_BUILD_JOBS=2 cargo clippy --release --all-targets -- -D warnings
BIN=target/release/velk ./tests/smoke.sh
BIN=target/release/velk ./tests/ladder.sh
```

The smoke script exercises the CLI and MCP and runs the local performance
check; it does not run the unit tests again. Both scripts check the binary
given in `BIN`, or build and check the debug binary when `BIN` is not set. The ladder checks expected behavior at
several difficulty levels; `known_*` entries are explicitly unfinished
targets. Run test functions serially: one recompilation test already
compiles the two optimization levels in parallel.

Rust/Cargo and a C compiler are needed for the build. Generated-C checks
use `clang`, hardware checks need the host support described below, and
the benchmark script uses `uv run python`. Fixture regeneration requires
Docker and the toolchains in the reference image; it is not required for
an ordinary checkout test run. These development tools are separate from
running an already built velk binary.

## Test layers

Private spills and the private stack area refer to the function's own stack
save area below the stack pointer at entry.

| Test | What it checks | Reference |
|---|---|---|
| `src/lift/hardware/` | Lifted instructions, registers, conditions, and memory | Processor execution on supported hosts |
| `src/analysis/semantics_tests.rs` | Optimization and structure lowering preserve behavior | Pre-transformation IR interpreter results |
| `src/ir/abi.rs`, `src/analysis/abi.rs` units | Aggregate classification, register banks, stack alignment, indirect results | Structured type layouts and expected ABI locations |
| `src/analysis/signature.rs`, `summary.rs` units | Incoming physical stack slots, definite writes, normal and exceptional predecessors | Explicit frame offsets, byte dependencies, and CFG expectations |
| `src/analysis/typing.rs` units | Exact pointer-return types, live output widths, entry bits used before later writes | SSA definitions, expected types, retained output controls |
| `src/analysis/indirect.rs` units | Constant-return propagation through read-only callees | Fixed instruction bytes and independently specified targets |
| `src/ssa/mod.rs` units | Entry-bit requirements, private spills, complete result dependencies | Explicit masks, frames, and observable memory effects |
| `src/render/structure/compare_chain.rs` units | Sparse equality dispatch, entry preservation, disjoint rewrites | Full original/transformed/lowered IR outcomes |
| `src/passes/copies.rs`, `read_once.rs` units | Assignment/read truncation and signed-operation/comparison widths | Full before/after interpreter outcomes |
| `src/render/` units | Pointer/integer distinctions, real member access, truth values, floating mask preconditions, segment-base bindings, saved-parameter overlap and load/store order | Expected typed pseudo-C and recognition controls |
| `tests/loader.rs` | Section allocation, relocation, nested DWARF member type/width/ownership | Input metadata and declared layout |
| `tests/recompile.rs` | Generated C results and memory effects | IR outcomes and independent scalar/byte expectations |
| `tests/invariants.rs` | Missing destinations, undefined register reads, omitted statements | Recorded structural properties |
| `tests/metrics.rs` | Function discovery and inferred parameter/return information | Debug information |
| `tests/golden.rs` | Function lists, pseudo-C, IR, signatures, summaries, output metrics | Recorded golden files |
| `tests/api.rs` | Script methods and returned fields match declarations | `src/script/api/*.d.ts` |
| `tests/robustness.rs` and related units | Damaged inputs do not panic | Runtime checks |
| `tests/smoke.sh` | CLI, MCP, selected output, and local performance | Output checks and benchmark thresholds |
| `tests/ladder.sh` | Behavior by difficulty, including known unfinished targets | `tests/expect/ladder.tsv` |

`tests/golden/casts.txt` records output lines and five disjoint cast counts
over every function in each fixture, including runtime functions. It uses
the type recognition of the readability cast metric. Pointer casts
immediately following `*` are memory-pointer casts; remaining `uint8_t *`
casts are byte-pointer casts; other pointer casts form the third class.
`uintptr_t` and `intptr_t` casts form the address-integer class, and the
remaining recognized casts form the scalar class. These are syntactic
counts rather than a classification of an expression's purpose.

The typed-pointer tests in `src/analysis/structures/tests/typed.rs` check
printed field offsets, structure-array strides, signed loads, call results,
and scalar pointers through copies. They compile and run generated C at
`-O0` and `-O2`, and check fallback for conflicting widths, partial copies,
unaligned fields, and invalid offsets.

### CLI and terminal output

Parser tests in `src/main.rs` check short/long flag equivalence, the
requirement for one mutually exclusive operation, and the scope of operands
and options. They also check rejection of bare subcommand names.
Terminal tests in `src/terminal.rs` check color suppression for a nonempty
`NO_COLOR`, `TERM=dumb`, or output that is not a terminal. They verify that
stripping ANSI styling preserves the text, including whitespace.
`tests/smoke.sh` checks selected CLI output and CLI/MCP behavior, including
JSON, script results, tool discovery, and script timeouts. Individual command
syntax and examples belong in `--help`.

### Hardware and IR

Instruction checks compare processor execution with lifted IR using the
same starting state. They include scalar floating-point and supported
vector operations, registers, flags, and memory. Undefined instruction
encodings and processor-undefined flags are excluded. AArch64 hardware
checks are compiled for arm64 macOS. The x86-64 executor is enabled on
x86-64 Unix and arm64 macOS, where it uses the system's x86-64 execution
support; availability still depends on a suitable compiler/runtime.

The focused AArch64 `SQDMULH` test compares the integer bits of the four
ordinary 16/32-bit vector forms, including saturation, register aliasing
and upper-half clearing. It requires every selected processor case to
execute and compares integer lanes without NaN equivalence. The current
IR does not model FPSR.QC; direct FPSR reads/writes remain unsupported,
with refusal checked before and after optimization. Scalar and indexed
forms remain unsupported. These checks concern register results, not
complete floating-status behavior or arbitrary external FPSR observers.

The AArch64 half-precision immediate check covers `FMOV Hd, #imm` only.
Decoder and IR checks cover every encoded immediate and all 32 destinations
against independently specified bit patterns, including clearing the other
112 destination bits. On supported hardware, a separate capability probe
precedes processor comparisons using v0–v7, which also check unchanged FPCR,
FPSR and NZCV. An unavailable probe is not a passing comparison. These checks
do not cover half-precision arithmetic or conversions, NaN payloads, or general
floating-environment behavior.

Fixture semantics checks attempt the discovered functions on finite trial
inputs, comparing return values, calls, and memory. Structured output is
also lowered to blocks for comparison. Unknown or unsupported executions
are not completed equivalence results. Keep the return type and width in
mind: a void or narrow return can hide a difference in discarded bits.

### Recompiled C

The fixture suites compile eligible call-free generated functions with
the system clang at `-O0` and `-O1`. Integer arguments are canonicalized to
their declared types before both executions. Results are compared at the
recovered return width. The memory suite also compares a checksum of its
fixed region. Initial bytes match the interpreter's seed-based values.

The common C contract includes `-fwrapv` and `-fno-strict-aliasing`.
Functions with unsupported input types or operations are outside the
generic eligibility rules. Unfinished interpreter runs, dependence on
unsupplied registers, and memory addresses the driver cannot map are
classified separately. Function-address values may be compiled/linked
without execution comparison because relocation changes their addresses.
Compilation failures and skipped comparisons are not successful executions.

Synthetic suites require every candidate to compile and compare, with no
skipped/unknown trials or differing results. They test fixed-address global
views, declared members, signed loads, overlapping accesses, raw float
bits, pointers, shifts, and whole-region checksums. The shift suite adds
strict shift sanitization and disables the common wrapping option so
invalid C shifts are observable.

A focused physical-call test uses a real host C callee to observe zero-extended
argument bits, call count and the full-width returned value. It covers narrow
and wide parameter storage at both optimization levels; it does not rely on
the interpreter's synthetic call results as the callee oracle.

Physical SIMD storage checks compare full return bits from the original IR and
unedited generated C across 16/32/64-bit accesses, upper-half clearing, finite
single/double computations, and reads before and after parameter overwrite.
Read-only FP checks distinguish unchanged formal names from the raw capture
needed by mixed FP/integer reads. Explicit writes, call clobbers, different
precisions, and volatile or atomic qualifiers remain outside that name reuse.
Generated-C comparisons include read-only sums and values saved before overwrite.

Nested FP controls check multiplication/addition grouping, right operands of
subtraction and division, negation, and precision conversions. Separate unary
minus controls compare full bits for parameters and negative literals, including
`+0.0` and `-0.0`; enclosing the operand preserves nested signs without forming
a decrement token. These finite and signed-zero cases do not establish arbitrary
NaN-payload or floating-environment equivalence. A physical `uint64_t` parameter
used to preserve otherwise unrepresented entry bits does not establish the
original floating-argument ABI.

Sparse equality-dispatch tests compare complete IR outcomes before recovery,
after recovery and after structured lowering. Generated-C cases check case and
default selection, low-bit normalization, high constants and a once-only head
effect. An independent byte reference checks interpreter memory; host C is
compared through return values and the region checksum. These checks
do not execute original target instructions.

Segment-base comparisons require explicit target FS/GS values and memory
contents shared by the interpreter and C adapter. These are test inputs,
not host TLS values. Dependency records identify each selected provider
by its FS or GS kind; function-address prototypes remain separate.
Memory initialization must apply the hashed region first, then fixture
contents, then per-trial state. Fixture bytes outside the fixed region are
applied only after an accessed page is first mapped and hash-filled;
unreferenced pages are not touched. A boundary regression covers clipped,
overlapping fixture words and reads on both sides of the region boundary.
A successful comparison of a void function
does not establish that a compiler retained unused memory reads. Returning
loads and observed stores are needed to exercise those accesses. These
checks do not validate a target-native TLS adapter or concurrent threads.

The floating mask suite uses explicit finite inputs and signed zeros,
passed as integer bits through memory. It exercises masks preserving every
bit of a floating result read at the same precision. An unmasked outer
floating operation keeps raw result storage on the bit-extraction
path. Returned raw bits and the entire region checksum compare at both
optimization levels, including known fused-operation discriminators.

That suite uses `-ffp-contract=off`, `-fno-builtin-fma`,
`-fno-builtin-fmaf`, and `-lm`: separate multiply/add must stay separate,
while explicit FMA uses the math library before a subsequent negation.
This preserves the signed-zero test contract on the tested compiler.
Passing under these options does not establish equivalent output with
arbitrary default FMA builtin lowering. This suite does not validate
NaN payloads, exception state, partial masks, precision-mismatch
reinterpretation, or the original floating-argument ABI.

### Aggregate arguments and results

Focused recompilation tests construct declared C objects from explicit
bytes and call the generated function with those objects. The interpreter
receives the corresponding register pieces, stack arguments, or indirect
copies described by `DeclaredSignature`. The generic scalar fixture suites
continue to exclude by-value aggregate parameters and results, including
functions whose declared ABI cannot be classified.

```bash
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 cargo test --release --test recompile aggregate
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 cargo test --release --test recompile scalar_stack
```

The focused suites cover integer objects, narrow register overwrites,
mixed integer/floating pieces, homogeneous floating aggregates, register
exhaustion, indirect arguments and results, and known signed/unsigned
128-bit C integer results in functions with aggregate arguments. The
128-bit checks observe both integer-register pieces; they do not establish
general support for standalone wide-integer functions. Selected integer
fixtures also use independent arithmetic expectations. Each logical input is tried
with different non-object register bits. Accepting a partial entry capture
requires those bits to be unobserved; object size alone does not establish
that condition. Padding and unnamed bit-fields are excluded from the
defined result masks.

Every defined result piece is compared at `-O0` and `-O1`. For a result
spread across registers, the test projects one piece at a time while still
evaluating every return operand. A fault or unsupported read in another
piece must not disappear. Indirect result comparisons read each defined
part of the returned object. Indirect input copies occupy the interpreter's
private stack area, while stores through a separate external pointer remain
in the observed memory region and its checksum.

Classifier and allocator units distinguish System V x86-64, base AAPCS64,
and Windows x64 rules. Missing source alignment remains unknown. The
classifier considers every power-of-two divisor of the type's size and
bounded combinations of nested alignment candidates. Typed output requires
classification, argument placement, and the allocation state for later
arguments to agree across candidates. Differences or exhausted analysis
limits require fallback. The alignment retained in `ValueAbi` describes
the representative generated C layout, not necessarily the source type's
exact alignment.

Object-relative accesses use `__builtin_memcpy` for widths of one, two,
four, or eight bytes. Tests include unaligned loads/stores, an under-aligned
byte-array object, signed and floating reads, and overlapping source and
destination bytes. The source of a store must be evaluated once before
the copy. Other access widths are rejected by the object proof, and a
diamond-shaped control-flow test requires output initialization on both
paths.

Entry captures copy exactly each piece's byte count into zero-initialized
integer storage. Result assembly copies the same bounded lengths after
evaluating every return operand. These byte/integer conversions assume a
little-endian execution environment for the generated C.

A host C call validates the generated logical C signature and body on that
host; it does not independently validate the
target machine's calling convention. Keep target instruction execution,
layout classification, IR execution, and generated-C execution as separate
boundaries.

Negative controls reject observed non-object bits, incompatible generated
definitions, address escapes, out-of-bounds accesses, and padding reads
through stack or indirect arguments. An indirect result must be written on
every return path before its defined bits are returned, with no reads of
unwritten storage. Unknown layouts, unsupported ABI variants or languages,
variadic signatures, and functions containing calls use the
physical argument form instead of the declared aggregate signature.
That fallback is not a C equivalence
guarantee: multiple results can still be shown as a first return value with
additional values in a comment.

### Incoming physical stack inputs

```bash
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 cargo test --release --lib analysis::signature::tests
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 cargo test --release --lib render::stack_bytes::tests
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 cargo test --release --test recompile stack
```

Recovery units check AAPCS64 stack inputs with unused argument registers,
full and partial prior writes, load/store order, frame-pointer origins,
call clobbers, and the incoming range and width limits. Normal, unknown,
and exception predecessors must all contribute to frame and initialized-byte
facts. Exception checks use the call-point state rather than a later block
exit, including a store after a call that must not initialize an earlier
exception path. Initial-entry controls retain required reads when unknown
backedges erase the joined frame, preserve prior-write suppression, and
keep that observation separate from joined CFG facts and result writes.
Summary/lifting units check shared exception boundaries and cache inputs.

Single-scalar stack views require each complete access to fit both the
argument slot and its declared C storage. Whole-width names and partial
byte views both require every occurrence of an address expression to have
the same known incoming offset and compatible width/storage. Dynamic or
differing origins prevent global names for affected slots and partial
views; this does not reconstruct an arbitrary dynamic SP. Controls retain
stable whole/partial views and reject unsupported widths or accesses past
actual scalar storage. A crossing access uses
a separate bounded byte array only if the renderer can redirect all
accesses to the same storage and prove every read initialized. Controls
include unsupported widths or storage, incomplete writes at joins, escaped
frame addresses, and implicit call reads through physical or SSA registers.
Saved-register folding tests distinguish access ranges overlapping known
incoming storage from immediately adjacent private spills, and retain
values read before a later store. Non-crossing cases also check normalization
of held frame addresses to entry-SP offsets, without a byte array, only
when each incoming access lies in a known complete eight-byte scalar slot
and the same origin, call, initialization, and escape checks hold.

Generated-C tests pass recovered physical words to the host as independent
scalar parameters and provide the same words at explicit interpreter
register/stack locations. They do not attach a source declaration to the
stripped function or assume that C parameter objects are adjacent.
Generic admission retains its convention, scalar-storage, ordered-slot,
and call/operation restrictions. A recovered physical signature
is not a claim of compatibility with the original source ABI.

Real stripped AAPCS64 and System V inputs use independent wrapping
arithmetic expectations, including accesses through held frame addresses.
Synthetic cases use independent little-endian byte arrays for partial and
cross-slot reads/writes, unchanged neighboring bytes, signed and floating
views, and accesses at different frame heights. The native checks compare
results and region checksums at `-O0` and `-O1`, with
alignment sanitization for the synthetic byte cases. Focused assertions
require every candidate and input to compile and compare, no skipped or
unknown rows, and no differing outcomes. Compilation failures and generic
exclusions remain separate from successful comparisons. These checks
execute generated host C and IR; they do not execute original target
instructions or establish arbitrary pointer aliasing and callee effects.

### Short-circuit conditions

Structured condition tests compare lowered nodes before and after cleanup,
including a separately written CFG reference. They check return/trap
outcomes, ordered calls, and visible memory, while structural assertions
check predicate identity, order, and occurrence count. Guarded division and
loads below the test driver's recovery threshold distinguish lazy
evaluation from an eager second test.
Negative cases retain intervening effects, labels, different terminals,
meaningful alternative branches, and nonterminal bodies that can run twice.
The checks cover loop/switch scopes and a bound of four tests per condition.

The focused recompilation cases compare C and IR return values and region
checksums. Independent scalar and forward-copy expectations also check the
IR results, including every observed byte in fixtures with overlapping buffers.
Native cases use memory counters to observe body effects; ordered calls
are checked only in the node tests. Floating comparison cases include
unordered inputs, without validating NaN payloads or floating exception
state. These checks execute host C rather than original target instructions,
and the interpreter has no volatile-load event trace.

## Fixture metrics

The following table records the selected C metrics fixtures, not a general
accuracy rate for arbitrary binaries. The dataset contains 162 source
functions across AArch64/x86-64 and O0/O2 configurations, including 11
aggregate ABI functions.

Analysis uses stripped binaries; DWARF in the paired debug binaries supplies
the reference only. These scores do not measure aggregate rendering with
DWARF declarations, which the focused tests above cover. Each metric has
its own eligible denominator. The recorded source is
[`tests/golden/metrics.txt`](../tests/golden/metrics.txt).

| Metric | AArch64 O0 | AArch64 O2 | x86-64 O0 | x86-64 O2 |
|---|---|---|---|---|
| Functions found | 162/162 | 162/162 | 162/162 | 162/162 |
| Extra functions | 0/162 | 0/162 | 0/162 | 0/162 |
| Parameter count | 151/161 | 151/161 | 151/161 | 151/161 |
| Pointer parameters | 187/189 | 186/189 | 187/189 | 186/189 |
| Parameter width | 151/157 | 151/157 | 152/157 | 152/157 |
| Parameter signedness | 139/151 | 139/151 | 140/152 | 140/152 |
| Return presence | 156/162 | 156/162 | 155/162 | 157/162 |
| Return width | 122/126 | 121/126 | 122/126 | 122/126 |
| Floating-point type | 11/15 | 11/12 | 11/15 | 11/14 |

Performance checks in `tests/bench.sh` time selected commands, with warmup
and machine-dependent thresholds. They do not establish a general
per-function latency guarantee. `tests/golden/readability.txt` records
output counts; fewer lines or casts are not themselves correctness checks.

Whole-binary throughput can be measured in one script session per fixture:

```bash
uv run python tests/throughput.py target/release/velk tests/fixtures/go_probe
uv run python tests/throughput.py target/release/velk tests/fixtures/rust_probe
```

The script reports discovered functions, decompilation failures, wall time,
peak child-process RSS in bytes, and a SHA-256 digest of the complete output.
Run each command in a fresh process without concurrent builds. Compare the
digests as well as timings when checking an optimization.

For timing inside the service and renderer, build with `--features timing`
and set `VELK_TIMING=1`. Stderr records tab-separated `timing`, scope name,
and elapsed nanoseconds. Scope times include nested calls; do not add them
together. Normal builds compile these hooks out.

## Golden changes

Golden files retain observed output and classified findings. Updating a
golden is not a substitute for investigating a difference. Review a change
before accepting it as intended behavior:

```bash
VELK_BLESS=1 CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 cargo test --release
VELK_BLESS=0 CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 cargo test --release
```

Inspect the golden diff and investigate new mismatches, compile failures,
or exclusions. Keep unsupported/unknown cases distinct from compared cases.
A passing blessed invariant test means the findings match the recorded file;
it does not mean there are no invariant findings. Inspect that file separately
and investigate newly recorded violations before accepting the update.

## Regenerating fixtures

Sources live in `tests/cases/`. Checked-in fixtures let ordinary tests run
without rebuilding each source language and target configuration. The
reference container pins its toolchains in `compose.yml` and
`docker/Dockerfile`; generated toolchain metadata is checked in with the
fixtures.

```bash
docker compose run --rm fixtures
docker compose run --rm check
```

Regenerate deliberately and review changed bytes and toolchain metadata.
The Linux reference environment is `linux/amd64`; performance thresholds
are disabled under its emulation, so benchmark locally instead. The
container uses its own target volume rather than the host build output.

## Additional review

```bash
uv run tests/review.py [REVISION]
```

This prepares changed pseudo-C alongside source and previous output in
`tests/out/review.md` (`--all` includes every function). Review verdicts in
`tests/review/verdicts.tsv` are additional investigation evidence, not a
pass/fail gate.

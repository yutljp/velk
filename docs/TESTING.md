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
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 ./tests/smoke.sh
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 ./tests/ladder.sh
```

The smoke script also builds and runs debug tests, exercises CLI/MCP, and
runs the local performance check. The ladder checks expected behavior at
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

| Test | What it checks | Reference |
|---|---|---|
| `src/lift/hardware/` | Lifted instructions, registers, conditions, and memory | Processor execution on supported hosts |
| `src/analysis/semantics_tests.rs` | Optimization and structure lowering preserve behavior | Pre-transformation IR interpreter results |
| `src/passes/copies.rs`, `read_once.rs` units | Assignment/read truncation and signed-operation/comparison widths | Full before/after interpreter outcomes |
| `src/render/` units | Pointer/integer distinctions, real member access, truth values, floating mask preconditions | Expected typed pseudo-C and recognition controls |
| `tests/loader.rs` | Section allocation, relocation, nested DWARF member type/width/ownership | Input metadata and declared layout |
| `tests/recompile.rs` | Generated C results and memory effects | Optimized IR interpreter outcomes |
| `tests/invariants.rs` | Missing destinations, undefined register reads, omitted statements | Recorded structural properties |
| `tests/metrics.rs` | Function discovery and inferred parameter/return information | Debug information |
| `tests/golden.rs` | Function lists, pseudo-C, IR, signatures, summaries, output metrics | Recorded golden files |
| `tests/api.rs` | Script methods and returned fields match declarations | `src/script/api/*.d.ts` |
| `tests/robustness.rs` and related units | Damaged inputs do not panic | Runtime checks |
| `tests/smoke.sh` | CLI, MCP, selected output, and local performance | Output checks and benchmark thresholds |
| `tests/ladder.sh` | Behavior by difficulty, including known unfinished targets | `tests/expect/ladder.tsv` |

### Hardware and IR

Instruction checks compare processor execution with lifted IR using the
same starting state. They include scalar floating-point and supported
vector operations, registers, flags, and memory. Undefined instruction
encodings and processor-undefined flags are excluded. AArch64 hardware
checks are compiled for arm64 macOS. The x86-64 executor is enabled on
x86-64 Unix and arm64 macOS, where it uses the system's x86-64 execution
support; availability still depends on a suitable compiler/runtime.

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

The floating mask suite uses explicit finite inputs and signed zeros,
passed as integer bits through memory. It exercises masks preserving every
bit of a floating result read at the same precision. An unmasked outer
floating operation keeps raw result storage on the existing bit-extraction
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

## Fixture metrics

The following table records the selected C metrics fixtures, not a general
accuracy rate for arbitrary binaries. The fixtures contain 151 source
functions across AArch64/x86-64 and O0/O2 configurations. Analysis uses
stripped binaries and debug information supplies the reference. Each
metric has its own eligible denominator. The recorded source is
[`tests/golden/metrics.txt`](../tests/golden/metrics.txt).

| Metric | AArch64 O0 | AArch64 O2 | x86-64 O0 | x86-64 O2 |
|---|---|---|---|---|
| Functions found | 151/151 | 151/151 | 151/151 | 151/151 |
| Extra functions | 0 | 0 | 0 | 0 |
| Parameter count | 150/150 | 150/150 | 150/150 | 150/150 |
| Pointer parameters | 187/189 | 186/189 | 187/189 | 186/189 |
| Parameter width | 151/157 | 151/157 | 152/157 | 152/157 |
| Parameter signedness | 139/151 | 139/151 | 140/152 | 140/152 |
| Return presence | 145/151 | 145/151 | 144/151 | 147/151 |
| Return width | 118/122 | 117/122 | 118/122 | 118/122 |
| Floating-point type | 10/10 | 10/10 | 10/10 | 10/10 |

Performance checks in `tests/bench.sh` time selected commands, with warmup
and machine-dependent thresholds. They do not establish a general
per-function latency guarantee. `tests/golden/readability.txt` records
output counts; fewer lines or casts are not themselves correctness checks.

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

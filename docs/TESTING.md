# Testing

English | [日本語](TESTING.ja.md)

velk changes its output only when every check below passes. This document lists the checks, how to run them, and
how to regenerate the test binaries.

## Requirements

- Rust (stable) and a C compiler.
- `clang` for the checks that compile the printed C.
- [uv](https://docs.astral.sh/uv/) for the Python helper scripts.
- Docker for regenerating the test binaries and for running the tests in the reference Linux environment.

## Running the checks

From the repository root:

```bash
export UV_CACHE_DIR=target/uv-cache
cargo build --release
cargo test --release -- --test-threads 3
cargo fmt -- --check
cargo clippy --release --all-targets -- -D warnings
BIN=target/release/velk bash tests/smoke.sh
BIN=target/release/velk bash tests/ladder.sh
```

- `tests/smoke.sh` runs the command line and the MCP server end to end.
- `tests/ladder.sh` checks expected results on functions of increasing difficulty. Entries marked `known_*` are
  known gaps.

## What the tests check

- **Instruction semantics.** Each lifted instruction is run on the CPU and through the IR interpreter with many
  inputs; the results must match. These tests need a host of the same architecture (or Rosetta for x86-64 on Apple
  silicon). ARM32 and x86-32 integer checks use Docker `linux/arm/v7` and `linux/386`, clang with the
  corresponding targets and `ld.lld`; they print a skip message when the Docker platform is unavailable.
- **Optimization passes.** Every function in the test binaries is interpreted before and after optimization; the
  results must match (`tests/golden/semantics.txt` must be empty).
- **Recompilation.** The printed C of each test function is compiled and run, and its results are compared with
  the IR interpreter, both for register results and for memory effects. Every `differ` count in
  `tests/golden/recompile.txt` and `tests/golden/recompile_memory.txt` must be 0.
- **Compiling every function.** An exhaustive check compiles the printed C of every function in every test binary
  together with the standard headers. It is marked `#[ignore]` because it is slow; run it with
  `cargo test --release --test recompile every_fixture_function_compiles -- --ignored --test-threads 3`. A fast subset runs in the
  normal suite.
- **Golden output.** `tests/golden/` holds the expected output for each test binary and readability metrics
  (lines, variables, casts, gotos). Review every change to these files.

The compiler used by the C checks can be chosen with `VELK_TEST_CC` (default `clang`). When a newer clang is
installed, a subset of the checks also runs with it, because newer compilers reject some conversions older ones
accept.

Recompilation checks compile functions in batches and use up to three workers.
Compilation and execution results and expected IR results are cached in `target/recompile-cache/`
and reused when their inputs are unchanged.

## Updating golden files

When an output change is intended, regenerate the golden files and review the diff:

```bash
VELK_BLESS=1 cargo test --release -- --test-threads 3
git diff tests/golden
```

## Differential testing

Outside the test suite, velk is also tested with randomly generated C programs: each program is compiled, one
function at a time is replaced by velk's output, and the program must still print the same result. This runs on
arm64 and x86-64 and has found many correctness bugs.

## Regenerating test binaries

The sources are in `tests/cases/`. The binaries are checked in so that ordinary test runs do not need every
compiler and target. To rebuild them:

```bash
docker compose run --rm fixtures
```

To run the test suite in the same pinned Linux environment, use `docker compose run --rm check`.

Regenerate the C API type library with `UV_CACHE_DIR=target/uv-cache uv run tests/generate_type_library.py`
and its Mach-O fixtures with `sh tests/make_type_library_fixtures.sh`.

Generate the Windows and Linux datasets and fixtures in the reference environment:

```sh
docker compose build fixtures
docker compose run --rm fixtures uv run tests/generate_type_library.py --platform windows
docker compose run --rm fixtures uv run tests/generate_type_library.py --platform linux
docker compose run --rm fixtures sh tests/make_type_library_fixtures.sh linux
```

The Windows dataset and lifters support x86-64 and x86-32.
Linux data and fixtures cover x86-64 and AArch64. Each target's signatures and
padded structure sizes, alignments, and field offsets are checked by its compiler.

Some groups have their own scripts: `tests/make_pe_fixtures.sh` (Windows PE), `tests/make_codeview.sh`
(CodeView / PDB), `tests/make_seh_fixtures.sh` (Windows SEH), `tests/make_objc_fixtures.sh` (Objective-C) and
`tests/make_arm64_lang_fixtures.sh` (AArch64 Rust and Go). Rebuild deliberately and review the changed bytes and
the recorded toolchain versions.

Regenerate ARM32 A32/T32 fixtures with `sh tests/make_arm32_fixtures.sh` (requires clang with ARM targets
and `ld.lld`) and x86-32 ELF/PE fixtures with `bash tests/make_i386_fixtures.sh`, both at `-O0` and `-O2`.

## Performance

Single-function decompilation should stay fast. To compare whole-binary throughput:

```bash
uv run tests/throughput.py target/release/velk tests/fixtures/go_probe
```

## Optional bounded verification, fuzzing and Miri

These checks are separate from the default suite. Use Kani, nightly Rust with Miri,
`cargo-fuzz`, and uv. The fuzz package downloads `libfuzzer-sys` on its first build.
All commands below use this checkout's `target/`; do not share it between checkouts.

```sh
sh tests/verify.sh kani
sh tests/verify.sh fuzz
sh tests/verify.sh miri
# Run all three, retaining failures from each:
sh tests/verify.sh all
```

On Linux, the script waits while the one-minute load exceeds twice the number of processors.
Its defaults are five build jobs and five test threads; set `CARGO_BUILD_JOBS=2` on
smaller machines. Each harness has a 120-second CBMC timeout; compilation and
preparation take additional time. A timeout is a failure, not a proof. Select a harness with
`cargo kani --lib --harness instruction_word`.

Every harness is behind `cfg(kani)`. Kani checks panics, arithmetic overflow and
memory access, including loop-unwinding assertions. A successful run establishes
only the bounds and preconditions below; it does not establish safety for arbitrary
binary sizes or the whole decompilation pipeline.

| Harness | Input domain and additional assertions |
| --- | --- |
| `elf_tables` | Arbitrary 0–128 bytes, 32/64-bit headers, section names/data and relocation iterators through the same `object` readers as loading. |
| `pe_tables` | Arbitrary 0–512 bytes, PE32/PE32+ headers, sections and relocations. |
| `macho_tables` | Arbitrary 0–128 bytes, 32/64-bit headers, sections and relocations. |
| `instruction_word` | 0–8 bytes, every `usize` offset; succeeds exactly when four bytes fit and returns their little-endian value. |
| `image_ranges` | 0–16 bytes, every `u64` offset and length; success and returned length match the available range. |
| `relocation_words` | 0–16 bytes, every `usize` offset and 32/64-bit value; valid writes read back, invalid writes leave the buffer unchanged; 64-bit writes preserve surrounding bytes. |
| `aarch64_relocation` | Any 32-bit instruction and relocation number, any 64-bit PC and target; CALL26 preserves the opcode and encodes the modular displacement. |
| `leb_readers` | 0–10 arbitrary bytes; signed/unsigned LEB readers stay within the buffer and consume 1–10 bytes on success. |
| `leb_round_trip` | Every `u64`, encoded in at most ten bytes, decodes exactly and consumes the encoding. |
| `encoded_pointers` | 0–16 arbitrary bytes, every 64-bit base and 8-bit encoding; the exception pointer reader stays within its section. |
| `codeview_records` | 0–16 arbitrary bytes and every `usize` requested length; bounded numeric/record reads and exact success condition for a slice. |
| `dwarf_units` | 0–32 arbitrary bytes of little-endian unit headers; declared units fit the input. This does not cover DIE traversal. |
| `unwind_entries` | 0–32 arbitrary bytes of little-endian `.eh_frame`, including referenced CIE parsing. This does not cover executing unwind instructions. |
| `bit_fields` | Every 64-bit value and valid width 1–64; masks, preserved low bits and signed value ranges. |
| `vector_window` | Every pair of 64-bit constants, offsets 0–63, with/without a following half; agrees with a 128-bit shift. |

Header bounds limit which table shapes can be reached. In particular, these proofs
do not cover arbitrarily many sections, compressed debug data, complete function
discovery, or applying every format's relocations. The relocation-word checks cover
the loader's writes separately. There is no Mach-O chained-fixup decoder in the
loader; the harnesses make no claim about those encodings.

### Fuzz targets and reproducible seeds

`fuzz/` has separate `elf`, `pe`, and `macho` opening targets, plus `functions`,
`decompile`, `script_request`, and `mcp_request`. Opening targets use the real loader;
the listing and decompilation targets use `service::Binary`. Decompilation selects
one function with a 100-ms analysis deadline. The request targets exercise the real
serde script-request type and MCP dispatch. MCP replaces supplied JavaScript with
an empty script and removes paths before dispatch; it does not fuzz JavaScript
syntax or execute supplied operations.

```sh
UV_CACHE_DIR=target/uv-cache uv run --no-project tests/fuzz.py --seed-only
UV_CACHE_DIR=target/uv-cache uv run --no-project tests/fuzz_runner_test.py
# Select one target, or omit its name for all seven:
sh tests/verify.sh fuzz elf --seconds 60 --quiet 120 --rounds 20
cargo +nightly fuzz build --target-dir target/fuzz
```

Seeds are regenerated from ELF, PE and Mach-O fixtures no larger than 65536 bytes,
plus JSON request examples. Larger fixtures are omitted. The generated corpora are
ignored by git. Each target runs in 60-second rounds, with a 10-second input timeout,
2048-MiB RSS limit, AddressSanitizer, debug assertions and overflow checks. The
runner records each round's duration, edge coverage (`cov`) and features (`ft`) under
`target/verification/fuzz/`. It requires 120 seconds of consecutive rounds with
unchanged counters, then minimizes the corpus with `cargo fuzz cmin`. Exhausting
20 rounds without that plateau fails the run. This stopping rule does not establish
that all paths were covered. Inputs that crash or time out remain in
`fuzz/artifacts/`; replay them with `cargo +nightly fuzz run TARGET ARTIFACT` and
add a normal regression test before fixing the cause.

### Unsafe blocks and Miri limits

The following is the complete list of explicit unsafe blocks in `src/` (declarations
of foreign functions are not blocks):

| Location | Related test; Miri limitation |
| --- | --- |
| `src/main.rs:478` | `tests::closed_pipe_signal`, compiled only for Miri; the `signal` foreign function is unsupported. |
| `src/lift/hardware/aarch64.rs:137` | Signal callback installed by the `Page` tests; requires a kernel signal context. Native callback coverage was not checked. |
| `src/lift/hardware/aarch64.rs:179`, `:183`, `:213`, `:231` | `lifted_instructions_match_the_processor` and the other tests using `Page`; signal setup, executable mapping, generated code and Darwin FFI. |
| `src/lift/hardware/aarch64.rs:466`, `:473` | `sqdmulh_vector_results_match_the_processor`; inline assembly reads/restores FPSR. |
| `src/lift/hardware/aarch64.rs:832`, `:842`, `:868`, `:890`, `:901` | `scalar_half_immediates_match_the_processor_without_status_changes`; inline assembly reads/writes FPCR/FPSR. |

The AArch64 hardware module is compiled only on macOS AArch64; Linux cannot run
those tests. Miri cannot interpret the generated native code or that inline
assembly. The runner attempts the Unix signal test and reports the interpreter's
unsupported-operation result explicitly; it does not suppress other failures.
It also runs the instruction-word, LEB128-overflow and CodeView-record unit tests
under Miri. Passing these safe-Rust parser tests does not verify the hardware
unsafe blocks or foreign code in dependencies.

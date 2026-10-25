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
cargo build --release
cargo test --release
cargo fmt -- --check
cargo clippy --release --all-targets -- -D warnings
BIN=target/release/velk sh tests/smoke.sh
BIN=target/release/velk sh tests/ladder.sh
```

- `tests/smoke.sh` runs the command line and the MCP server end to end.
- `tests/ladder.sh` checks expected results on functions of increasing difficulty. Entries marked `known_*` are
  known gaps.

## What the tests check

- **Instruction semantics.** Each lifted instruction is run on the CPU and through the IR interpreter with many
  inputs; the results must match. These tests need a host of the same architecture (or Rosetta for x86-64 on Apple
  silicon).
- **Optimization passes.** Every function in the test binaries is interpreted before and after optimization; the
  results must match (`tests/golden/semantics.txt` must be empty).
- **Recompilation.** The printed C of each test function is compiled and run, and its results are compared with
  the IR interpreter, both for register results and for memory effects. Every `differ` count in
  `tests/golden/recompile.txt` and `tests/golden/recompile_memory.txt` must be 0.
- **Compiling every function.** An exhaustive check compiles the printed C of every function in every test binary
  together with the standard headers. It is marked `#[ignore]` because it is slow; run it with
  `cargo test --release --test recompile every_fixture_function_compiles -- --ignored`. A fast subset runs in the
  normal suite.
- **Golden output.** `tests/golden/` holds the expected output for each test binary and readability metrics
  (lines, variables, casts, gotos). Review every change to these files.

The compiler used by the C checks can be chosen with `VELK_TEST_CC` (default `clang`). When a newer clang is
installed, a subset of the checks also runs with it, because newer compilers reject some conversions older ones
accept.

## Updating golden files

When an output change is intended, regenerate the golden files and review the diff:

```bash
VELK_BLESS=1 cargo test --release
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

Some groups have their own scripts: `tests/make_pe_fixtures.sh` (Windows PE), `tests/make_codeview.sh`
(CodeView / PDB), `tests/make_seh_fixtures.sh` (Windows SEH), `tests/make_objc_fixtures.sh` (Objective-C) and
`tests/make_arm64_lang_fixtures.sh` (AArch64 Rust and Go). Rebuild deliberately and review the changed bytes and
the recorded toolchain versions.

## Performance

Single-function decompilation should stay fast. To compare whole-binary throughput:

```bash
uv run tests/throughput.py target/release/velk tests/fixtures/go_probe
```

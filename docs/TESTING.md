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
BIN=target/release/velk bash tests/scripts/smoke.sh
BIN=target/release/velk bash tests/scripts/ladder.sh
```

- `tests/scripts/smoke.sh` runs the command line and the MCP server end to end.
- `tests/scripts/ladder.sh` checks expected results on functions of increasing difficulty. Entries marked `known_*` are
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

Regenerate the C API type library with `UV_CACHE_DIR=target/uv-cache uv run tests/scripts/generate_type_library.py`
and its Mach-O fixtures with `sh tests/scripts/make_type_library_fixtures.sh`.

Generate the Windows and Linux datasets and fixtures in the reference environment:

```sh
docker compose build fixtures
docker compose run --rm fixtures uv run tests/scripts/generate_type_library.py --platform windows
docker compose run --rm fixtures uv run tests/scripts/test_generate_type_library.py
docker compose run --rm fixtures uv run tests/scripts/generate_type_library.py --platform linux
docker compose run --rm fixtures sh tests/scripts/make_type_library_fixtures.sh linux
```

The Windows dataset and lifters support x86-64 and x86-32.
Linux data and fixtures cover x86-64 and AArch64. Each target's signatures and
padded structure sizes, alignments, and field offsets are checked by its compiler.
Function pointer fields are also checked for type compatibility, including their calling
conventions. The Rust tests compile their printed declarations for both Windows targets.
Fields whose types or alignment cannot be represented remain padding.
The header license notices are in [windows.LICENSE](../src/analysis/prototypes/windows.LICENSE).

The script API returns these layouts as data, including method parameters, result types,
and calling conventions. This example also runs through the CLI's `-r` operation and MCP's
`velk_run_script` tool:

```js
const b = velk.open("tests/fixtures/type_library_windows.win64.exe");
b.libraryType("struct IUnknownVtbl");
```

Some groups have their own scripts: `tests/scripts/make_pe_fixtures.sh` (Windows PE), `tests/scripts/make_codeview.sh`
(CodeView / PDB), `tests/scripts/make_seh_fixtures.sh` (Windows SEH), `tests/scripts/make_objc_fixtures.sh` (Objective-C) and
`tests/scripts/make_arm64_lang_fixtures.sh` (AArch64 Rust and Go). Rebuild deliberately and review the changed bytes and
the recorded toolchain versions.

Regenerate ARM32 A32/T32 fixtures with `sh tests/scripts/make_arm32_fixtures.sh` (requires clang with ARM targets
and `ld.lld`) and x86-32 ELF/PE fixtures with `bash tests/scripts/make_i386_fixtures.sh`, both at `-O0` and `-O2`.

## Performance

Single-function decompilation should stay fast. To compare whole-binary throughput:

```bash
uv run tests/scripts/throughput.py target/release/velk tests/fixtures/go_probe
```

## Optional bounded verification, fuzzing and Miri

These checks are separate from the default suite. Use Kani, nightly Rust with Miri,
`cargo-fuzz`, and uv. The fuzz package downloads `libfuzzer-sys` on its first build.
All commands below use this checkout's `target/`; do not share it between checkouts.

```sh
sh tests/scripts/verify.sh kani
sh tests/scripts/verify.sh fuzz
sh tests/scripts/verify.sh miri
# Run all three, retaining failures from each:
sh tests/scripts/verify.sh all
```

On Linux, the script waits while the one-minute load exceeds twice the number of processors.
Its defaults are five build jobs and five test threads; set `CARGO_BUILD_JOBS=2` on
smaller machines. Each harness has a 300-second CBMC timeout; compilation and
preparation take additional time. A timeout is a failure, not a proof. Select a harness with
`cargo kani --lib --harness instruction_word`. The script runs up to
`CARGO_BUILD_JOBS` harnesses concurrently.

Every harness is behind `cfg(kani)`. Kani checks panics, arithmetic overflow and
memory access, including loop-unwinding assertions. A successful run establishes
only the bounds and preconditions below; it does not establish safety for arbitrary
binary sizes or the whole decompilation pipeline.

The object-reader checks use fixed little-endian header layouts with arbitrary
remaining fields. They check raw section data and REL/RELA arrays for ELF, and
section data and relocation access for PE. Coverage goals confirm section traversal, nonempty section data,
nonempty ELF REL/RELA arrays and nonempty raw COFF/Mach-O relocation arrays.
The generic PE section relocation iterator is empty, so the PE checks call the
section header's raw COFF reader. They do not call section-name lookup, whose
CPU feature detection reaches unsupported assembly on the verification host.
ELF checks do not construct symbol tables or relocation maps.
Mach-O checks use the raw header, segment, section-offset, data and relocation
readers, without constructing the higher-level file or classifying section names.
The exception-value and image-range checks call the same pure functions as loading,
without constructing an image and its randomized maps.

The seconds below record CBMC verification on 2026-10-27 UTC, on x86-64 Linux
with Kani 0.68.0 and CBMC 6.11.0. The results combine a full run with five
workers and targeted runs with one to three workers. Times exclude compilation
and preparation. The script saves per-harness results to
`target/verification/kani.json`.

| Harness | Input domain and additional assertions | Verification seconds | Result |
| --- | --- | ---: | --- |
| `elf32_tables` | 136 bytes; fixed ELF32 header, null section and one arbitrary section; 0–24 data bytes, arbitrary data offset and remaining metadata; no program headers. | 61.49 | pass |
| `elf64_tables` | 200 bytes; the same ELF64 layout and bounds. | 58.25 | pass |
| `pe32_tables` | 352 bytes; fixed PE32 layout, one section, 0–1 COFF relocations; arbitrary section offsets/sizes; no symbols or data directories. | 51.41 | pass |
| `pe64_tables` | 368 bytes; the same PE32+ layout and bounds. | 33.27 | pass |
| `macho32_tables` | 152 bytes; one 32-bit segment command and section, 0–1 relocations; arbitrary offsets, addresses and sizes. | 88.87 | pass |
| `macho64_tables` | 184 bytes; the same 64-bit layout and bounds. | 64.42 | pass |
| `instruction_word` | 0–8 bytes, every `usize` offset; succeeds exactly when four bytes fit and returns their little-endian value. | 1.70 | pass |
| `image_ranges` | 0–16 bytes, every `u64` slice base, offset and size; exact range success, returned length and bytes. | 7.22 | pass |
| `relocation_words` | 0–16 bytes, every `usize` offset and 32/64-bit value; valid writes read back, invalid writes preserve bytes; both write widths preserve surrounding bytes. | 19.20 | pass |
| `aarch64_relocation` | Any instruction, relocation number, PC and target; CALL26 preserves opcode and encodes modular displacement. | 3.10 | pass |
| `leb_readers` | 0–10 arbitrary bytes; exact signed/unsigned LEB values and consumption when a terminator exists, using 128-bit decoding; bounded consumption otherwise; overflow and truncation rejection. | 47.46 | pass |
| `leb_round_trip` | Every `u64`, encoded in at most ten bytes; exact decode and consumption. | 19.47 | pass |
| `encoded_pointers` | 0–16 arbitrary bytes, every 64-bit base and 8-bit encoding, 4/8-byte pointer widths; scalar exception decoding consumes only available bytes; exact fixed-width values, sign extension, PC-relative addition and overflow rejection. | 30.94 | pass |
| `codeview_records` | 0–16 arbitrary bytes and every requested `usize` length; exact slice success, bytes and reader position; bounded numeric reads and record count; exact 64-bit numeric leaves and consumption; covers multiple records. | 153.62 | pass |
| `dwarf_units` | Prefixes of a 12-byte DWARF32 version-4 unit; arbitrary abbreviation offset and payload, 4/8-byte addresses; success exactly for the complete unit; exact version, address size, abbreviation offset, size and termination. | 118.45 | pass |
| `unwind_entries` | One 16-byte version-1 CIE with an empty augmentation; one-byte code/data alignment factors, arbitrary return register and instruction bytes; exact code/data alignment and return register; parses and terminates. | 31.52 | pass |
| `unwind_fde32` | A fixed CIE and one 32-bit FDE, 32 bytes total; every initial address and range; referenced CIE parses, initial address and range match and iteration terminates. | 74.44 | pass |
| `unwind_fde64` | The same property for 64-bit addresses, 40 bytes total. | 77.08 | pass |
| `bit_fields` | Every 64-bit value and width 1–64; masks, low-bit preservation, signed ranges and exact sign extension by shifts. | 2.43 | pass |
| `vector_window` | Every pair of 64-bit constants, offsets 0–63, with/without a following half; agrees with a 128-bit shift. Unwinding bound 1 suffices for these constant expressions. | 198.84 | pass |
| `chained_pointer_arm64e` | Format 1; one eight-byte pointer with arbitrary payload bits and 64-bit base; next link field zero or one; rebase value, authentication flag, bind ordinal/addend, termination and rejection of nonzero links outside the input. | 183.15 | pass |
| `chained_pointer_64` | The same property for format 2. | 107.16 | pass |
| `chained_pointer_64_offset` | The same property for format 6. | 108.87 | pass |
| `chained_pointer_arm64e_kernel` | The same property for format 7. | 168.91 | pass |
| `chained_pointer_arm64e_userland` | The same property for format 9. | 213.31 | pass |
| `chained_pointer_arm64e_firmware` | The same property for format 10. | 223.81 | pass |
| `chained_pointer_arm64e_userland24` | The same property for format 12, including all 24 ordinal bits. | 148.52 | pass |
| `chained_pointer_links` | All seven supported formats; sixteen bytes, zero payloads, base zero; first link points to offset eight using the format stride; exact offsets, rebase targets, authentication absence and termination. | 121.75 | pass |
| `export_trie_limit` | Every export value and `usize` requested index from an unending iterator; the shared production entry limit yields values exactly below `MAX_EXPORTS`, then terminates. | 0.37 | pass |

`go_table_walk` calls the production slice walk with at most two function
entries, 0–16 function-data bytes, 0–8 name bytes and every 64-bit text base.
It checks bounded output, nonwrapping code addresses and name lengths. Coverage
goals include two accepted entries and an invalid first entry followed by an
accepted second entry.
`go_table_offsets` uses one entry, an eight-byte function header and a fixed terminated name;
it checks exact acceptance and output for every 32-bit entry offset, signed
function/name offset and 64-bit text base. Virtual table mapping and executable
section membership are covered by normal regression tests, not these harnesses.

The Go harnesses were verified on 2026-10-27 UTC with Kani 0.68.0 and CBMC
6.11.0 on x86-64 Linux. These times exclude compilation and preparation.

| Harness | Verification seconds | Result |
| --- | ---: | --- |
| `go_table_walk` | 189.26 | pass |
| `go_table_offsets` | 16.66 | pass |

The chained-pointer checks parse a fixed 60-byte starts table through the dependency
and use the loader's rebase normalization. The format harnesses reject nonzero
unit links outside their eight-byte input. A separate harness with zero payloads checks
traversal through two pointers and termination for both format strides. They do not prove
whole-file fixup application, import-name lookup, arbitrary chain lengths and
payloads together, arbitrary link values with arbitrary payloads, overlapping
pointers or page geometry. Normal tests
in `src/loader/macho/fixups/tests.rs` exercise these paths. The export-limit check
bounds yielded entries, including errors; it does not bound work inside an
iterator's `next` call or prove export-trie decoding. Cyclic export files are also
covered by `cyclic_export_tries_finish_loading` in the normal robustness suite.

All 31 harnesses passed across these runs, and all 98 reachability goals were
satisfied. The userland24 format was verified separately with one worker.
The pointer-format unwind bounds are 3/4/5/6/7 according to the format's position
in the production table. Unwinding assertions remain enabled.

Each harness has reachability goals for the modeled boundaries or successful
nontrivial inputs. These include ten-byte LEB extrema, truncated encodings,
negative and overflowing PC-relative pointers, complete and truncated DWARF
units, negative unwind alignment, two Go functions, nonzero chain links and
nonzero binding ordinals. Authentication and rebase-overflow goals are emitted
only for pointer formats that support them. An unreachable goal is not evidence
that the corresponding case was checked.

These bounds do not cover arbitrary section counts, big-endian objects, compressed
debug data, DIE traversal, executing unwind instructions, complete function
discovery or applying every format's relocations. No whole-pipeline safety claim
follows from these proofs.

### UPX decoding and Windows page ranges

These harnesses cover the built-in UPX decoder in `src/loader/packed/` and the page
rounding used by the Windows virtual-memory calls. They were verified on 2026-10-31 UTC
with Kani 0.68.0 and CBMC 6.11.0 on x86-64 Linux, three workers at a time except
`x86_branch_filters`, which ran alone. Times exclude compilation and preparation.

| Harness | Input domain and additional assertions | Verification seconds | Result |
| --- | --- | ---: | --- |
| `field_reads` | 8 arbitrary bytes, every `usize` offset and length; a field is returned exactly when it lies inside the input; numeric fields of at most 8 bytes equal their little-endian value. | 5.04 | pass |
| `checksum_chunk_cannot_overflow` | One byte added at any position inside a 5552-byte checksum chunk, from any state within the bound for that position; the next state stays within the bound, so no addition overflows before the sums are reduced. | 8.09 | pass |
| `image_writes` | 8-byte image, every `usize` offset and value, widths 0–8; a write succeeds exactly inside the image, stores the little-endian value and leaves other bytes unchanged; a rejected write changes nothing. | 2.15 | pass |
| `image_copies` | 8-byte image, 0–4 source bytes, every `usize` offset; the same properties for copies. | 2.63 | pass |
| `image_strings_and_offsets` | 8 arbitrary bytes, every `usize` offset; a returned string ends at its first zero byte and matches the input; a string is rejected only when no zero byte follows the offset. Every address and base; an image offset is returned exactly when the address is not below the base. | 11.81 | pass |
| `headers_from_arbitrary_bytes` | 312 arbitrary bytes, PE header offsets 0–8; an accepted header has its section table inside the input and its data directories before the end of the table. | 80.27 | pass |
| `bit_reads` | One NRV bit read and one integer extension from any reader state over 4 input bytes, with 1- or 4-byte words; bits are 0 or 1, the position stays inside the input and an extended integer never exceeds its limit. | 4.04 | pass |
| `match_copies` | A 0–4 byte block, every match distance and length, block sizes 0–6 not smaller than the block; an accepted match fits the size and copies each byte from the given distance back; a rejected match leaves the block unchanged. | 135.38 | pass |
| `x86_branch_filters` | Filters 0x26, 0x46 and 0x49 on every length 0–7 with arbitrary bytes and branch target byte; decoding succeeds without a panic. | 25.26 | pass |
| `arm_branch_filter` | Filter 0x50 on the same inputs. | 3.98 | pass |
| `aarch64_branch_filter` | Filter 0x52 on the same inputs. | 3.15 | pass |
| `page_ranges_cover_the_request` | Every 64-bit address and size; a returned range is page aligned, covers the request and has no extra page at either end; only empty or overflowing requests are rejected. | 0.18 | pass |

The NRV harnesses check single steps of the decoder, not whole streams, and the filter
harnesses do not check that the rewritten branch addresses are correct; the SMT test
`smt_modular_branch_targets_round_trip` checks that arithmetic separately. The ELF header
reader has no Kani harness: with a fixed program-header layout and a single arbitrary byte,
CBMC still did not finish within 300 seconds. LZMA decoding and whole-file reconstruction
are covered by the UPX regression tests, not by these harnesses.

### Fuzz targets and reproducible seeds

`fuzz/` has separate `elf`, `pe`, and `macho` opening targets, plus `functions`,
`decompile`, `script_request`, and `mcp_request`. Opening targets use the real loader;
the listing and decompilation targets use `service::Binary`. Decompilation selects
one function with a 100-ms analysis deadline. The request targets exercise the real
serde script-request type and MCP dispatch. MCP replaces supplied JavaScript with
an empty script and removes paths before dispatch; it does not fuzz JavaScript
syntax or execute supplied operations.

```sh
UV_CACHE_DIR=target/uv-cache uv run --no-project tests/scripts/fuzz.py --seed-only
UV_CACHE_DIR=target/uv-cache uv run --no-project tests/scripts/fuzz_runner_test.py
# Select one target, or omit its name for all seven:
sh tests/scripts/verify.sh fuzz elf --seconds 60 --quiet 120 --rounds 20
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
| `src/main.rs`, `exit_on_closed_pipe` | `tests::closed_pipe_signal`, compiled only for Miri; the `signal` foreign function is unsupported. |
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

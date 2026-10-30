# Changelog

This changelog follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Execution

- Function execution through the IR interpreter (`--emulate`, `b.emulate`, `velk_emulate`),
  with arguments, memory, standard input, `argv`, captured output and step, time and memory limits.
- Emulation models for C library calls, C file streams, file descriptors, sockets, callbacks,
  `rand`, `time` and `alarm`, C++ standard streams and strings for both libstdc++ ABIs,
  thread-local storage, stack canaries and raw Linux system calls.
- Debugger and environment checks in emulation and symbolic execution are answered as for a
  process that is not being debugged, and each answer is listed in the report.
- Windows PE emulation with a minimal process environment: strings, files, the registry,
  C runtime shutdown, SEH and threads.
- Symbolic execution with a reach search and a state API (`--explore`, `b.explore`, `b.symbolic`,
  `velk_explore`), return conditions (`--solve`, `b.solve`) and branch feasibility (`--opaque`,
  `b.branchFeasibility`), using an external Z3 or Bitwuzla process.

#### Input

- Raw byte images with an explicit instruction set, load address and entries (`--raw-arch`,
  `--load-address`).
- A built-in UPX decoder for ELF and PE, with `upx -d` as a fallback for unsupported
  variants, and `--save-unpacked`.
- Unpacking of self-modifying Linux ELF programs by emulation (`--unpack`, `--unpack-at`).
- Discovery of startup entries and stripped `main`, and ELF segment mapping.

#### Recovery

- Decoded strings from decoder calls with known inputs and from strings built on the stack,
  including AArch64 vector loads; `decodedStrings` in `--strings`; `--no-string-decoding`.
- API-name candidates for export-name hash routines, including seeded, UTF-16, inlined,
  PEB-walking and dynamic-table forms (`apiHashes` in function summaries).
- Indicator extraction from static and recovered strings (`--iocs`, `binary.iocs()`).
- Library function names in stripped binaries from embedded signatures, applied by default,
  and Go runtime signatures with exact arity and returns.
- Structure layouts in stripped code, shared through field loads, stores and copies.
- COM interface types and IID and CLSID names.
- Mach-O chained fixups and 32-bit C++ classes.
- Call-site declarations matched against standard headers.

#### Output and simplification

- Proven opaque predicates are folded and flattened control flow is rebuilt.
- Mixed boolean-arithmetic expressions are simplified.
- Inlined memory fills, copies and string functions are printed as standard calls.
- Instruction addresses in decompiled output (`--addresses`, and a line-to-address map with `--json`).
- Disassembly comments for strings, names and data.
- Function similarity search across binaries (`--similar`, `f.similar`).

#### Interfaces

- Saved analysis next to the input (`<binary>.velk-cache`, `--cache`, `VELK_CACHE`).
- `velk --serve` for newline-delimited JSON requests, keeping one script context per process.
- `velk --api-docs` prints the embedded API topics.

### Changed

- Test and fixture scripts moved from `tests/` and `tools/` to `tests/scripts/`.

## [0.1.0] - 2026-10-26

### Added

#### Input formats

- ELF, PE/COFF and Mach-O binary loading, including ELF32 and PE32.
- Relocatable object files (`.o`, `.obj`) with section layout and relocation handling.
- Universal Mach-O slice selection for the host or an explicit `--arch` value.
- Function discovery from symbols, exports, debug information, Go function tables,
  unwind tables and code analysis.

#### Architectures

- x86-64 and AArch64 instruction lifting, including supported SIMD and atomic operations.
- x86-32 ELF and PE lifting with cdecl, stdcall, fastcall and thiscall integer arguments.
- ARM32 A32/T32 lifting for little-endian ELF32, with conditional execution and AAPCS
  register and stack arguments; floating-point, SIMD, system instructions and declared
  64-bit or aggregate arguments and results remain unsupported.
- arm64e pointer-authentication instruction lifting under the assumption that
  authentication succeeds.

#### Analysis and output

- Function argument, return-value and non-returning-call analysis over the call graph.
- Cross references, call graphs, string and constant searches, and function summaries.
- Jump-table recovery and structured C output with conditionals, loops and switches.
- C++ class recovery from RTTI (Itanium and MSVC, 64-bit): class names, bases at their offsets,
  virtual tables and adjustment thunks, used in virtual calls (`--classes`); try regions and catch
  types printed as comments.
- Byte-pattern, text and integer search, typed memory reads, and detection of well-known constant
  tables (AES, hash initial values, CRC, base64 and others) that names the matching globals.
- Comparison of two binaries (`--compare`): function matching by name, shape, call-graph
  neighbours and referenced data, a diff of the printed C, and copying annotations to the newer
  binary (`--carry-annotations`).
- Constant folding, copy propagation, common subexpression elimination and dead code elimination.
- Stack-frame recovery and promotion of non-escaping stack slots to local variables.
- Integer width, signedness, pointer and structure recovery, with stack arrays and unions.
- Variable naming from debug information and value roles, and separate variables for
  unrelated register values.
- C helper definitions and declarations emitted once per output file, with `unsupported`
  markers for instructions that cannot be translated.

#### Type information and signatures

- DWARF and CodeView/PDB names and types for functions, parameters, locals and structure fields.
- Rust and C++ symbol demangling, Go type descriptors and Objective-C class and method metadata.
- Compiler-checked C API type libraries for macOS SDKs, Windows APIs and the C runtime,
  and Linux glibc, with target-specific layouts.
- Callee prototypes from debug information and known library functions, with recovered
  variadic argument access rendered as `va_start` and `va_arg`.
- Byte signatures for identifying stripped library functions.

#### Interfaces

- CLI function listing and single-function or whole-binary C output through
  `--functions` and `--decompile`.
- CLI disassembly, IR, cross-reference, string and summary output through `--disasm`,
  `--ir`, `--xrefs`, `--strings` and `--summary`.
- JavaScript analysis API available from scripts through `--run`.
- Stdio MCP server through `--mcp`, with `velk_read_api` documentation and
  `velk_run_script` for JavaScript queries.
- Size-limited MCP replies and script execution timeouts.

#### Project files

- Binary-bound JSON project files for persistent names, types and comments, with
  type annotations requiring a 64-bit target layout.
- Project selection and annotation editing through `--project`, `--annotate` and
  the JavaScript API.
- Project import and export, with saved annotations applied to analysis and C output.

#### Verification

- SMT-solver checks of expression rewrite rules against the real rewrites, run in the test suite
  when the solver is installed.
- Instruction tests comparing CPU execution with the IR interpreter, with Docker-based
  ARM32 and x86-32 integer checks when the required platforms are available.
- Before-and-after optimization checks using the IR interpreter.
- Printed C compilation and execution checks for return values and memory effects.
- Golden output and readability metrics, plus an optional exhaustive fixture compilation check.
- CLI and MCP smoke tests, function-level regression checks and checked-in binary fixtures
  with regeneration scripts.

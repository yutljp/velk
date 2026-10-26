# Changelog

This changelog follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

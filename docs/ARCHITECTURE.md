# Architecture

English | [日本語](ARCHITECTURE.ja.md)

This document describes how velk turns a binary into C, stage by stage, and which module is responsible for each
stage.

```
binary
  │  loader    parse the file format, map sections, apply relocations, find functions and names
  ▼
Image          sections, functions, symbols, imports, debug information
  │  lift      decode instructions into IR statements, split into basic blocks
  ▼
FunctionIr     basic blocks of statements and expressions
  │  analysis  arguments and return values, jump tables, calling conventions
  │  passes    simplification, copy propagation, dead code elimination, stack frame recovery
  │  ssa       SSA form, constant propagation, splitting variables
  │  typing    integer widths and signedness, structures, debug-information types
  ▼
optimized FunctionIr
  │  render    structuring (if / loops / switch), naming, types, C output
  ▼
C · disassembly · IR · function summary (JSON)
```

## Loader (`src/loader/`)

The loader reads ELF (including ELF32), PE / COFF (including PE32) and Mach-O files and builds
an `Image`: the sections, the functions with their names and sizes, data symbols, and imports.

- Relocatable object files (`.o`, `.obj`) are laid out the way a linker would and their relocations are applied,
  so calls and data references point at real addresses.
- Functions are found from several sources: the symbol table and exports, debug information
  (DWARF, CodeView / PDB), the Go function table, unwind tables (which also give exact function sizes), and finally
  the calls and code patterns found while lifting.
- Language metadata gives better names: Rust and C++ symbol demangling, Go type descriptors, Objective-C class
  and method lists, and Windows exception (SEH) tables.
- Debug information also provides the names and types of parameters, local variables and structure fields, which
  later stages use when printing.

## Lifting (`src/lift/`)

The lifters for x86-32, x86-64, AArch64 and ARM32 decode each instruction and translate it into IR statements. Supported
instructions are translated exactly, including flags, partial register writes, vector (SIMD) operations and atomic
operations. Instructions that read machine state C cannot express (for example `cpuid` or `rdtsc`) are printed as
compiler intrinsics such as `__rdtsc()`. An instruction velk cannot translate yet is printed as `unsupported`.

The x86-32 lifter handles ELF and PE, four-byte stack slots, and cdecl, stdcall, fastcall and thiscall integer arguments; calls with unknown argument counts are rejected.

The ARM32 lifter handles A32 and T32, conditional execution, and AAPCS register and stack arguments.
Function address bits, `bx` / `blx`, and `$a` / `$t` / `$d` mapping symbols select code modes and data.
ARM32 floating-point, SIMD and system instructions and declared 64-bit or aggregate arguments and results
remain unsupported.

The instruction semantics are checked against the real CPU (`src/lift/hardware/`): the same instruction runs on
the processor and through the IR interpreter with many inputs, and the results must match.

ARM32 and x86-32 integer instruction results are also compared with Linux execution through Docker
(`linux/arm/v7` and `linux/386`); each check prints a skip message when its platform is unavailable.

## Intermediate representation (`src/ir/`)

A function is a list of basic blocks. A block holds statements (assignments, loads, stores, calls, branches,
returns) over expressions (registers, constants, arithmetic, comparisons, loads, conversions). Calls record the
calling convention and, when known, the callee's declared parameters.

`src/ir/eval.rs` interprets the IR. Tests use it to check that every transformation keeps the behaviour of the
function, and that the printed C computes the same results.

## Analysis (`src/analysis/`)

- **Function summaries**: which registers and stack slots a function reads as arguments, what it returns, and
  whether it returns at all. Summaries are computed over the call graph so that callers see accurate callees.
- **Jump tables**: indirect jumps through a table become `switch` statements.
- **Indirect calls**: recovered C++ vtable information narrows the targets of virtual calls.
- **Typing**: integer widths and signedness, pointers, recovered structures and the types from debug information.

The C API type library lazily loads compiler-checked declarations and layouts from macOS SDK headers
for Mach-O, mingw-w64 and C runtime headers for PE/COFF (using DLL-qualified imports), and glibc headers for ELF,
with separate target layouts.

## Optimization passes (`src/passes/`, `src/ssa/`)

The passes simplify the IR without changing what it computes:

- constant folding and algebraic simplification, common subexpression elimination, copy propagation and dead code
  elimination;
- recovering divisions and remainders that compilers turned into multiplications by a constant (only when the
  replacement is exact for every input);
- removing the stack frame setup, and turning stack slots whose address never escapes into ordinary variables;
- SSA construction for constant propagation and for splitting a register into separate variables.

Memory accesses are only reordered or removed when the analysis proves no other access can observe the
difference; atomic operations keep their ordering.

## Rendering C (`src/render/`)

Rendering turns the optimized IR into C:

- **Structuring**: the control-flow graph becomes `if`, `while`, `do`/`while`, `for` and `switch` statements, with
  `break`, `continue` and early `return`. `goto` is used only where the graph cannot be structured.
- **Variables**: each value gets a name and the C type its uses need. Names come from debug information when
  present, otherwise from the role of the value (`i` for a loop counter, `result` for the returned value) or
  `vN`.
- **Memory**: stack objects are declared as structures, unions or arrays; pointers get element types so accesses
  print as `p->field` or `p[i]`. Array bounds are only assumed when they are proven.
- **Calls**: callee prototypes come from debug information or a built-in table of common library functions; variadic functions use
  `va_start` / `va_arg`.
- **Output**: helper definitions and declarations the code needs are printed once, at the top of the file, so the
  output compiles on its own.

## Outer layers

- `src/service.rs` opens binaries and caches the analysis of each function. The CLI, the scripting API and the MCP
  server all go through it.
- `src/main.rs` is the command line; `src/script/` runs JavaScript against the scripting API; `src/mcp.rs` is the MCP server that
  exposes that API to agents.
- `src/xrefs.rs` indexes cross references and the call graph, and provides string and constant queries and function summaries.
- `src/sigs/bytes.rs` matches byte signatures to identify stripped library functions.
- `src/project/` persists binary-bound names, types and comments as JSON and applies them to analysis and output.

## How correctness is checked

See [TESTING.md](TESTING.md). In short: instruction semantics are compared with the CPU, every pass is checked with
the IR interpreter, and the printed C is compiled and run against the IR. Every function of every test binary must
compile.

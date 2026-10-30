# Control-flow simplification

The default analysis removes conditional branches only when it proves their outcome.
It recognizes the even low bit of `x * (x + odd)` and `x * (x - odd)`, unsigned
remainder by two of those products, subtraction or exclusive-or of an integer with
itself, and an integer combined with its bitwise complement. These rules use the
IR's integer widths and wrapping arithmetic. Expressions that read memory or may
fault are excluded from these identities. Existing constant propagation and range
analysis also prove conditions using tracked values, including private frame slots
whose stored values the memory analysis can safely forward.

Dispatcher recovery accepts comparison chains and switches that only test one
state variable. Each incoming edge must have a constant state or a conditional
choice between two constants. The pass follows the tests for those constants and
replaces the incoming edges with direct branches. It removes the decision blocks
only after proving that they are unreachable. Unknown state assignments, unresolved
edges and exception handlers prevent recovery. Headers that perform other work
remain unchanged.

Function cards and `Function.summary()` in JavaScript, including scripts run through
MCP, return a `simplification` object:

- `simplified`: whether an expression, predicate or dispatcher was simplified.
- `predicatesRemoved`: the number of conditional branches proved constant.
- `dispatcherStatesRemoved`: the number of distinct incoming constant states whose
  dispatcher tests were bypassed.
- `mbaExpressionsSimplified`: the number of mixed bitwise/arithmetic expression
  replacements. See [expression simplification](MBA.md).

The fixtures in `tests/cases/control_flow/` contain flattened and original
straight-line, branching and looping functions, integer predicates, and a variable
transition that must keep its dispatcher. `tests/scripts/make_control_flow_fixtures.sh`
builds freestanding x86-64 and AArch64 objects at `-O0` and `-O2` with Clang.
The control-flow integration test compiles the printed C and compares its return
values with independent unsigned formulas. Unit tests use Z3 only to verify the
integer identity families; runtime analysis does not invoke a solver.

## Checks removed from existing Go and Rust functions

The changed computations in the Go and Rust fixtures are limited to these checks:

- `runtime.mapaccess2` on x86-64: inside `v24 != 0`, the nested `v24 == 0`
  branch cannot run. There is no assignment or call between the tests. The
  preceding call may return any value; the proof does not constrain its result.
- `rustc_demangle::demangle` on x86-64: all incoming paths to the check at
  `0x46695` retain an unsigned length of at least two. The enclosing test admits
  lengths at most two, so the length equals the assigned constant two. The
  branch to `0x466bf` is therefore impossible. No call or assignment changes the
  length between these tests. Removing the branch also changes the printed
  nesting of the following code.
- `gimli::read::rnglists::RngListIter::next` on AArch64, instantiated with a
  little-endian `EndianSlice`: under `v11 <= 1` and `v11 != 1`, the unsigned byte
  `v11` is zero. Its nested `v11 != 0` branch cannot run. No assignment or call
  separates these tests.

`reduced_existing_checks_preserve_calls_and_memory` compiles reduced C versions
of these three checks at `-O0` and `-O2` with undefined-behavior checking. It
compares results, call counts and modified memory for 131,072 inputs per check,
including every byte value and unsigned 64-bit boundary values. These are reduced
checks, not executions of the complete Go runtime or Rust library functions.

The changed function instances are:

| Fixture | Function | Address |
|---|---|---|
| `go_probe`, `go_stripped` | `runtime.mapaccess2` | `0x45c120` |
| `rust_demo`, `rust_probe`, `rust_probe_stripped` | `rustc_demangle::demangle` | `0x46024` |
| `rust_demo_arm64`, `rust_probe_arm64`, `rust_probe_arm64_stripped` | `gimli::read::rnglists::RngListIter::next` | `0x100014670` |

For the demangler, every incoming path to `0x463fa` has a length of at least two.
The two-byte prefix path assigns two, the three-byte prefix paths retain at least
three, and the four-byte prefix paths retain at least four. All paths to
`0x46675` come from this region without changing the length. The bound of at most
two on the edge to `0x46695` therefore fixes its length to two.
`existing_dominating_checks_exclude_the_removed_paths` proves the three guard
combinations unsatisfiable with Z3 at 8, 16, 32 and 64 bits.

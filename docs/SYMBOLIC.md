# Symbolic execution

Symbolic execution represents selected inputs as bit vectors and searches for values that reach an instruction address. It uses the execution lifter and the existing IR-to-SMT expression translation. Concrete scalar expressions use the IR evaluator. An external SMT solver is required: install `z3` or `bitwuzla` on PATH, or set `VELK_SOLVER` to a command line such as `z3 -in`. Arguments may be quoted; no shell is invoked. Other operations do not start a solver.

List functions and disassemble the function to choose virtual addresses. Then run:

```sh
velk --explore check --find 0x401100 --avoid 0x401120 --stdin 8 app.elf
velk --explore check --find 0x401100 --stdin 8 --json app.elf
velk --api-docs symbolic
```

The target is checked before its instruction executes. An avoid address wins if it is also a find address. A successful report contains concrete stdin bytes, argv byte arrays, scalar arguments, memory bytes and registers, together with visited instruction addresses. A failed bounded search does not prove unreachability. Diagnostics identify unsupported operations and incomplete address enumeration.

The JavaScript API supports `b.explore(start, options)` and `b.symbolic(start, options)`. Read `velk --api-docs symbolic` for the complete option and state interfaces. For example:

```js
const b = velk.open("app.elf");
const s = b.symbolic("check", {arguments: [0]});
const x = s.readRegister(7); // rdi, the first x86-64 System V argument
s.constrain(x, "eq", s.constant(42));
s.evaluate(x); // ["0x2a"]
```

A `Symbolic` state can read and write register and memory terms, add comparisons, check satisfiability, enumerate unsigned values, compute unsigned minimum and maximum, clone with `fork()`, and step to a branch or address. `step()` returns independently constrained successor states at a branch. Terms belong to their solver session; forks share that session. Dispose of JavaScript states with `dispose()` when finished. Rust exposes `velk::symbolic::{State, Term, Step, Options, explore}`. MCP provides `velk_explore` with `path`, `start` and `options` arguments.

Initial physical registers are zero except the stack pointer, following concrete emulation. `arguments` selects scalar register argument indices; `argumentValues` sets other arguments. `argv` supplies symbolic string lengths, including argv[0]; their bytes cannot be zero, and terminators are concrete. `memory` selects writable mapped byte ranges. Register inputs use physical register indices. Memory addresses can be strings to retain all 64 bits.

Limits are deterministic: `stepLimit` defaults to 100000 IR statements per path, `pathLimit` to 256 visited states, and `addressLimit` to eight possible values per symbolic address. Address values are enumerated in increasing unsigned order. Each value gets a constrained successor; an extra diagnostic reports when more values exist. Branches are searched in depth-first order, taken side first. Concrete inputs use successive unsigned minima under the complete path constraints, so the assignment is consistent across inputs. There is no execution wall-time budget. A solver that does not respond can block the calling operation.

This implementation supports little-endian x86-64 and AArch64, scalar arithmetic, memory, conditional branches and internal calls. Symbolic stdin is consumed by `getchar` and `read` on descriptor zero. Other imports, `Apply` operations with symbolic operands, machine operations, flag-only branches, switch statements and tail calls report unsupported operations. Stack arguments are not supported. Stops at imported addresses are rejected; use the call-site instruction address. Code ranges are limited to 64 KiB and symbolic byte inputs to 65536. Arithmetic that may divide by zero stops the path. These limits also apply to loops and recursion through the per-path step budget.

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

A `Symbolic` state can read and write register and memory terms, add comparisons, check satisfiability, enumerate unsigned values, compute unsigned minimum and maximum, clone with `fork()`, and step to a branch or address. `step()` returns independently constrained successor states at a branch. Terms belong to their solver session; forks share that session. Dispose of JavaScript states with `dispose()` when finished. Rust exposes `velk::symbolic::{State, Term, Step, Options, explore}`. MCP provides `velk_explore`, `velk_solve`, and `velk_branch_feasibility` with `path`, `start` and `options` arguments.

Initial physical registers are zero except the stack pointer, following concrete emulation. `arguments` selects scalar argument indices; `argumentValues` sets other arguments. `argv` supplies symbolic string lengths, including argv[0]; their bytes cannot be zero, and terminators are concrete. `memory` selects writable mapped byte ranges. Register inputs use physical register indices. Memory addresses can be strings to retain all 64 bits.

Limits are deterministic: `stepLimit` defaults to 100000 IR statements per path, `pathLimit` to 256 visited states, and `addressLimit` to eight possible values per symbolic address. Address values are enumerated in increasing unsigned order. Each value gets a constrained successor; an extra diagnostic reports when more values exist. Branches are searched in depth-first order, taken side first. Concrete inputs use successive unsigned minima under the complete path constraints, so the assignment is consistent across inputs. There is no execution wall-time budget. A solver that does not respond can block the calling operation.

This implementation supports little-endian x86-64 and AArch64, scalar arithmetic, memory, conditional branches, internal calls, stack scalar arguments for System V x86-64 and AAPCS64, and bounded indirect jump-table indexes. Switch IR forks on case equality and the default constraint. Indirect addresses retain the `addressLimit` bound.

`b.solve("check", {arguments: [0], returns: {eq: 1}})` searches for a satisfying outermost return. Conditions are `eq`, `ne`, `lt`, and `gt` against a number or 64-bit string. Ordered comparisons use signed 64-bit values; equality compares all return-register bits. A 32-bit negative C return may be zero-extended in the machine return register. The CLI accepts `velk --solve check --returns eq:1 --stdin 8 app.elf`. Use `--symbolic-options '{"arguments":[0]}'` for scalar inputs and other limits. The Rust entry point is `symbolic::solve`.

`b.branchFeasibility("check", {arguments: [0]})`, `symbolic::branch_feasibility`, and `velk --opaque check --symbolic-options '{"arguments":[0]}' app.elf` explore reachable contexts. A branch side is reported as `unsat` only if no context admits it and exploration finishes. Limits, solver failures, or unsupported operations make the analysis incomplete; unwitnessed sides have `unknown` status and a reason. Ordinary branches with witnesses on both sides are omitted. An unvisited conditional instruction has both sides reported as unreachable after exhaustive exploration; incomplete exploration marks unwitnessed sides unknown. The analysis rejects find, avoid, and return conditions. To add assumptions, use concrete argument values, bounded symbolic memory, or Rust state constraints before `branch_feasibility`.

Libc models share the emulator's import table and input-consumption helper. Supported input calls are `getchar`, `read`, `fgets`, `gets`, `getline`, and `scanf`/`fscanf`/`sscanf`. Scanning supports `%d`, `%u`, `%x`, `%s`, `%c`, decimal widths, and assignment suppression. Stream input accepts only stdin; `read` also accepts descriptors explicitly bound through `stdinDescriptors`. String and memory models cover `strlen`, `strnlen`, `strcmp`, `strncmp`, `memcmp`, `memcpy`, `memmove`, `memset`, `strcpy`, `strncpy`, and `strchr`. Integer models cover `atoi` and `strtol` with base 10 or 16; case conversion uses ASCII. `puts` and `printf` record output, with concrete or symbolic `%d`, `%u`, `%x`, `%s`, and `%c` arguments and `%%`. Output bytes are in `inputs.stdout`, evaluated consistently with the returned inputs. A model's nonzero comparison result uses the byte difference; libc guarantees its sign. Allocation capacities and successful puts return values are model choices, rather than host libc implementation details.

Variadic AArch64 I/O requires ELF; `strtol` rejects the Windows data model. Models charge the statement budget. Memory operations have a 65536-byte bound. String scans use a finite bound derived from symbolic input sizes, at least 4096 and at most 65536 bytes; exceeding it stops the path. Unmodelled imports, unsupported formats, `Apply` operations with symbolic operands, machine operations, flag-only branches and tail calls report diagnostics. Stops at imported addresses are rejected; use the call-site instruction address. Code ranges are limited to 64 KiB and symbolic byte inputs to 65536. Arithmetic that may divide by zero stops the path. Loops and recursion also consume the per-path step budget.

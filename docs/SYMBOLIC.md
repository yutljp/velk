# Symbolic execution

Symbolic execution represents selected inputs as bit vectors and searches for values that reach an instruction address. It uses the execution lifter and the existing IR-to-SMT expression translation. Concrete scalar expressions use the IR evaluator. An external SMT solver is required: install `z3` or `bitwuzla` on PATH, or set `VELK_SOLVER` to a command line such as `z3 -in`. Arguments may be quoted; no shell is invoked. Other operations do not start a solver.

List functions and disassemble the function to choose virtual addresses. Then run:

```sh
velk --explore check --find 0x401100 --avoid 0x401120 --stdin 8 app.elf
velk --explore check --find 0x401100 --stdin 8 --json app.elf
velk --api-docs symbolic
```

The target is checked before its instruction executes. An avoid address wins if it is also a find address. A successful report contains concrete stdin bytes, argv byte arrays, scalar arguments, memory bytes and registers, together with visited instruction addresses. A failed bounded search does not prove unreachability. Diagnostics identify unsupported operations and incomplete address enumeration. Text reports show stdin, argv, and contiguous memory inputs as escaped strings and hexadecimal bytes. The path summary gives its length and first and last addresses; `--json` retains the complete address list and byte arrays.

The JavaScript API supports `b.explore(start, options)` and `b.symbolic(start, options)`. Read `velk --api-docs symbolic` for the complete option and state interfaces. For example:

```js
const b = velk.open("app.elf");
const s = b.symbolic("check", {arguments: [0]});
const x = s.readRegister(7); // rdi, the first x86-64 System V argument
s.constrain(x, "eq", s.constant(42));
s.evaluate(x); // ["0x2a"]
```

A `Symbolic` state can read and write register and memory terms, add comparisons, check satisfiability, enumerate unsigned values, compute unsigned minimum and maximum, clone with `fork()`, and step to a branch or address. `step()` returns independently constrained successor states at a branch. Terms belong to their solver session; forks share that session. Dispose of JavaScript states with `dispose()` when finished. Rust exposes `velk::symbolic::{State, Term, Step, Options, explore}`. MCP provides `velk_explore`, `velk_solve`, and `velk_branch_feasibility` with `path`, `start` and `options` arguments.

Each execution starts with a separate 4 KiB thread-local mapping. `tlsBase`
overrides its automatically selected base; overlapping or overflowing ranges are
rejected. The x86-64 FS base, i386 GS base, and AArch64 `tpidr_el0` point there.
The fixed stack guard is `0x6a09e667bb67ae00` (low 32 bits on i386); `canary`
overrides it. Guards occupy FS + `0x28`, GS + `0x14`, and TP + `0x28` for
AArch64 sysreg builds using that offset. AArch64 glibc uses the global guard;
defined `__stack_chk_guard` data symbols are initialized too. Other TLS contents
are zero except x86 self pointers. This supplies stack protection state, not a
runtime TLS loader. Explicit register and memory inputs take precedence.
Calls to `__stack_chk_fail` or `__stack_chk_fail_local` stop with
`stack check failed`; symbolic searches include that reason in diagnostics.

Initial physical registers are zero except the stack and thread pointers, following concrete emulation. `arguments` selects scalar argument indices; `argumentValues` sets other arguments. `argv` supplies symbolic string lengths, including argv[0]; their bytes cannot be zero, and terminators are concrete. `memory` selects writable mapped byte ranges. Register inputs use physical register indices. Memory addresses can be strings to retain all 64 bits.

Limits are deterministic: `stepLimit` defaults to 100000 IR statements per path, `pathLimit` to 256 visited states, and `addressLimit` to eight possible values per symbolic address. Address values are enumerated in increasing unsigned order. Each value gets a constrained successor; an extra diagnostic reports when more values exist. Branches are searched in depth-first order, taken side first. Concrete inputs use successive unsigned minima under the complete path constraints, so the assignment is consistent across inputs. There is no execution wall-time budget. A solver that does not respond can block the calling operation.

This implementation supports little-endian i386, x86-64 and AArch64, scalar arithmetic, memory, conditional branches, internal calls and tail calls to function entries, stack scalar arguments for i386 cdecl, System V x86-64 and AAPCS64, and bounded indirect jump-table indexes. Switch IR forks on case equality and the default constraint. Indirect addresses retain the `addressLimit` bound.

`b.solve("check", {arguments: [0], returns: {eq: 1}})` searches for a satisfying outermost return. Conditions are `eq`, `ne`, `lt`, and `gt` against a number or 64-bit string. Ordered comparisons use signed 64-bit values; equality compares all return-register bits. A 32-bit negative C return may be zero-extended in the machine return register. The CLI accepts `velk --solve check --returns eq:1 --stdin 8 app.elf`. Use `--symbolic-options '{"arguments":[0]}'` for scalar inputs and other limits. The Rust entry point is `symbolic::solve`.

`b.branchFeasibility("check", {arguments: [0]})`, `symbolic::branch_feasibility`, and `velk --opaque check --symbolic-options '{"arguments":[0]}' app.elf` explore reachable contexts. A branch side is reported as `unsat` only if no context admits it and exploration finishes. Limits, solver failures, or unsupported operations make the analysis incomplete; unwitnessed sides have `unknown` status and a reason. Ordinary branches with witnesses on both sides are omitted. An unvisited conditional instruction has both sides reported as unreachable after exhaustive exploration; incomplete exploration marks unwitnessed sides unknown. The analysis rejects find, avoid, and return conditions. To add assumptions, use concrete argument values, bounded symbolic memory, or Rust state constraints before `branch_feasibility`.

C++ streams use the same mangled-name dispatch and string layouts as
[emulation](EMULATION.md). Word and line input preserve symbolic bytes, decimal
integer input uses bounded symbolic accumulation, and output is recorded in
`inputs.stdout`. Unsupported imports, input failure, integer overflow, and stream formatting changes stop the affected path with a diagnostic.

Libc models share the emulator's import table and input-consumption helper. Static functions can also use a model when instruction signature matching identifies exactly one library function name with confirmed destinations. Ambiguous and unconfirmed matches execute lifted code. Diagnostics state the address, function name, and signature set used by each static model, or identify the import symbol used by an imported model. Supported input calls are `getchar`, `read`, `fgets`, `gets`, `getline`, and `scanf`/`fscanf`/`sscanf`. Scanning supports `%d`, `%u`, `%x`, `%s`, `%c`, decimal widths, and assignment suppression. Scanning and getline accept only stdin; `read` also accepts descriptors explicitly bound through `stdinDescriptors`. String and memory models cover `strlen`, `strnlen`, `strcmp`, `strncmp`, `memcmp`, `memcpy`, `memmove`, `memset`, `strcpy`, `strncpy`, and `strchr`. Integer models cover `atoi` and `strtol` with base 10 or 16; case conversion uses ASCII. `puts` and `printf` record output, with concrete or symbolic `%d`, `%u`, `%x`, `%s`, and `%c` arguments and `%%`. Output bytes are in `inputs.stdout`, evaluated consistently with the returned inputs. A model's nonzero comparison result uses the byte difference; libc guarantees its sign. Allocation capacities and successful puts return values are model choices, rather than host libc implementation details.

Variadic AArch64 I/O requires ELF; `strtol` rejects the Windows data model. Models charge the statement budget. Memory operations have a 65536-byte bound. String scans use a finite bound derived from symbolic input sizes, at least 4096 and at most 65536 bytes; exceeding it stops the path. Unmodelled imports, unsupported formats, unmodelled `Apply` operations with symbolic operands, machine operations, flag-only branches report diagnostics. Stops at imported addresses are rejected; use the call-site instruction address. Code ranges are limited to 64 KiB and symbolic byte inputs to 65536. Arithmetic that may divide by zero stops the path. Loops and recursion also consume the per-path step budget.

Constant-table loads retain one path when the complete unsigned address range spans at most 256 byte addresses inside one read-only section. Widths of one through eight bytes preserve little-endian packing and sign extension. Writable memory, larger ranges, and loads crossing a section boundary retain bounded address enumeration. Symbolic SIMD operations cover low/high interleaving and widening at 8/16/32 bits, plus lane sums, lane addition, and logical lane right shifts at 8/16/32/64 bits. Narrowing and signed or unsigned saturating packing accept 16/32/64-bit source lanes; leading-zero counts accept 8/16/32/64-bit values; other operations still stop with a diagnostic.

The 22 C programs in `tests/data/crackmes/` exercise input handling, comparisons, transforms, table lookups, a VM, state transitions, checksums, and internal calls. Build and evaluate them from the repository root:

```sh
bash tests/make_crackme_fixtures.sh target/crackmes
uv run --no-project tests/crackmes.py --cases table sum --variants elf > target/crackmes.jsonl
```

Omit `--cases` and `--variants` to evaluate all programs and built variants. The builder uses freestanding ELF imports for both architectures at `-O0` and `-O2`, with stack protection and sibling-call optimization disabled, matching the symbolic fixture build. On Linux it also builds dynamic and static libc executables when the corresponding compiler is available. Evaluation records CLI exploration and return searches separately, including elapsed seconds, diagnostics, concrete inputs, and native replay results. The default external evaluation timeout is 60 seconds per search; it is separate from symbolic execution's deterministic limits. Cross-architecture replay uses QEMU when available; otherwise the report identifies execution of the same C program on the host architecture. A missing replay binary produces `unverified`, and a rejected input produces `wrong`. Successful replay requires exit status zero and exactly `success` followed by a newline. Freestanding input stubs are never used for native validation.

The builder also creates stack-protected byte-sum and table examples at both optimization levels, plus an i386 byte-sum example. AArch64 variants cover global and TP + `0x28` guards. Regression tests replay solved inputs against host executables built with stack protection.

Linux ELF `read`, `write`, `exit` and `exit_group` syscalls use symbolic stdin and captured stdout. Unknown syscall numbers stop with a diagnostic. i386 supports the library models and symbolic argv with 4-byte cdecl stack arguments and pointers. The argv count is concrete, its pointer table ends with null, and zero-length strings have a concrete zero terminator.

## Symbolic file inputs

`files` accepts the same virtual paths and byte arrays as emulation. Each supplied
byte becomes an independent symbolic byte: the array fixes the length, not its
values. The initial bytes are shared across reopenings; stream reads consume them
in position order, and writes replace the corresponding terms. File inputs count
toward the 65536-byte total input limit. Stream operations have the same bounds
and mode semantics described in [Running loaded code](EMULATION.md), except that
individual symbolic transfers are limited to 65536 bytes.

For a function that checks five bytes read from `input`:

```sh
velk --solve solve_file --returns eq:1 app.elf --symbolic-options '{"files":{"input":[0,0,0,0,0]}}' --json
```

JavaScript uses `b.solve("solve_file", {files: {input: [0,0,0,0,0]}, returns: {eq: 1}})`;
MCP uses `velk_solve` with the same `options`. `explore` and the state API also
accept `files`. File terms participate in the existing path constraints and the
same consistent input assignment as stdin, arguments and memory. `inputs.files`
contains concrete initial bytes keyed by path; pass that map as emulation's
`files` to replay. `inputs.fileOutputs` contains committed file contents evaluated
under that assignment. `fgets` branches on symbolic newline bytes, so line
boundaries remain part of the solved path.

`rand` and `srand` use the default glibc sequence, initially seeded with 1.
Each execution has its own generator state. `time` returns a fixed Unix time
(default 0); the `time` option overrides it and a non-null argument receives
the same value at the target pointer width. `signal` records Linux signal
handlers and returns the previous handler. `alarm` replaces a pending timer
and returns its previous duration; the model clock does not advance or deliver
signals. `setbuf` accepts a null buffer for a standard or virtual file stream; caller-owned buffers are unsupported.
A concrete or uniquely constrained random seed uses concrete generator state; other symbolic seeds use bit-vector state copied on path forks. Assertions are reset between solver queries while term definitions remain available, so constraints from other paths do not restrict the query.
Unsigned bounds queries use known widths for zero-extended values, Boolean predicates, and bounded digit accumulations; arithmetic without a proven bound retains 64-bit searches.

`exit` flushes virtual file streams and stops execution. If the image names or imports an exit-handler registration function, the call stops with a diagnostic. `_exit` is not modeled as a libc call.

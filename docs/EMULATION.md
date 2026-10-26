# Running loaded code

English | [日本語](EMULATION.ja.md)

`--emulate` runs lifted instructions through the IR interpreter. It supports x86-64,
AArch64, x86-32 and little-endian ARM32 (A32/T32). The binary's code never executes
on the host. Every run starts from a fresh image; it does not edit the file or the
cached analysis.

For a routine `decode(unsigned char *buffer, unsigned count, unsigned key)` that
XORs each byte with the key, place an encoded buffer in the heap and pass its
virtual address as the first argument.

This example assumes `app.elf` contains that routine and the heap starts at
`0x10000000`. Check `heapBase` as described below if the image occupies that range:

```sh
velk --emulate app.elf decode --emulation-options '{"arguments":["0x10000000",6,93],"memory":[{"address":"0x10000000","bytes":[53,56,49,49,50,93]}],"stepLimit":100000,"timeLimitMs":1000}'
```

The result is JSON. `memory` lists contiguous changed regions, each with an
`address`, final `bytes`, and a `hex` dump. The decoded buffer in this example is
`68 65 6c 6c 6f 00` ("hello"). Initial writes are the comparison baseline: only
changes made by execution appear in the result. Unchanged bytes are omitted.

The JavaScript API accepts the same options. Use strings for addresses or values
above JavaScript's exact integer range (2^53 - 1):

```js
const b = velk.open("app.elf");
const r = b.emulate("decode", {
  arguments: ["0x10000000", 6, 93],
  memory: [{address: "0x10000000", bytes: [53, 56, 49, 49, 50, 93]}],
  trace: true
});
if (r.reason !== "return") throw new Error(r.error ?? r.reason);
const bytes = r.memory.find(region => region.address === "0x10000000").bytes;
String.fromCharCode(...bytes.slice(0, bytes.indexOf(0)));
```

`b.getFunction("decode").emulate(options)` runs a selected function. An arbitrary
instruction address can replace the name in `b.emulate()`. Supply `end: ["0x401020",
"0x401040"]` to stop before either address executes. For an address range without
a discovered function, the largest end address bounds lifting. End addresses must
be instruction boundaries. Starting in the middle of a function requires the
registers and memory that its preceding instructions would have established.

MCP clients can call `velk_emulate` with `{path, start, options, arch?}`. It returns
the complete JSON report as text. Use `velk_run_script` to select fields or slice
large dumps. `velk_read_api` with `topic: "emulation"` describes every option and
result field.

## State and limits

- `registers` maps full register names to unsigned values, for example `rax`,
  `eax` on x86-32, `x0`, `sp`, or `r0`. Registers start at zero, except the stack
  pointer; the x86 direction flag starts clear. Partial names such as `al` are
  rejected. Vector registers use the interpreter's 64-bit half names.
- `arguments` passes machine-word integer or pointer values in the function's
  recovered calling convention, including stack arguments. Set registers before
  arguments; arguments take precedence. Floating values, aggregates, multiword
  arguments and Go arguments require explicit register/memory setup.
  Initial memory writes run last, so they can replace stack argument bytes.
- Loaded sections retain their virtual addresses and write protection. Sections
  without file data read as zero. Executable sections cannot be modified. No
  dynamic linker, TLS setup or operating-system state is supplied.
- The writable stack is 1 MiB around the initial stack pointer. The writable heap
  occupies 16 MiB, starting at `0x10000000` when that range is free. If the image
  overlaps it, a free range is selected. Both areas start at zero. The report gives
  `heapBase`, `heapSize` and the initial `stackPointer`. Stop at the entry address
  with `end` to discover the heap address before preparing inputs. Images that
  overlap the stack, or leave no heap range, are rejected.
- `memory` entries contain either `bytes`, or `value` and `width` (1, 2, 4 or 8
  bytes, little endian). Writes require mapped writable memory. Initial writes
  are limited to 16 MiB. Heap bytes supplied by the caller precede allocations.
- `stepLimit` defaults to 100000 IR statements plus hook work units, including
  per-byte work. `timeLimitMs` defaults to 1000 milliseconds. Time is checked
  during execution and after lifting, rather than a hard wall-clock cutoff.
  Each lifted code range is limited to 64 KiB; call depth is limited to 128.
  Individual hook memory operations are limited to 16 MiB.
- `trace: true` includes visited instruction addresses. Repeated string operations
  can repeat the same instruction address.

## Calls and stopping

The hook table implements `memcpy`, `memmove`, `memset`, `strlen`, `strcmp`,
`strncmp`, `strcpy`, `malloc`, `calloc` and `free`. Memory hooks check mapping and
permissions; overlapping `memcpy` is rejected. String comparison returns the
unsigned-byte difference as a C `int`. Allocation uses aligned heap space;
exhaustion returns zero. `free` validates the pointer but does not reuse space.

Internal calls execute lifted code. Writes to an import slot redirect its calls
to the supplied address. Other imported calls stop with an error.
`callReturns: {"external_name": 7}` or an address key supplies an explicit result;
an explicit result takes precedence over a library hook and skips its effects.
`skipCalls: true` returns zero for unhandled calls. These options model only the
integer result and do not supply a call's other effects. Registers the convention
allows a modeled call to overwrite are reported as `"unknown"`, except its defined
result. Partial writes preserve known bits; using unknown bits stops the run.
A void result, such as `free`, leaves the integer result unknown. Hooks still run
when `skipCalls` is set.
System calls always stop.

The report includes final `registers`, the integer `returnValue`, changed memory,
`steps`, the stopping `address`, `reason`, `error`, and an optional `trace`. Stop
reasons are `return`, `end address`, `trap`, `step limit`, `time limit`, and `error`.
The CLI succeeds only for return or end address. MCP marks other stops as errors,
while preserving the report. Invalid setup produces an input error.

Unmapped reads, writes to protected memory, unavailable flags, unsupported
instructions, and operations requiring external machine state stop explicitly.
The error names the instruction; memory errors also name the accessed address.
No missing memory value or call result is guessed.

## Tests

`cargo test --release --test emulation -- --test-threads 3` builds C fixtures
with `tests/make_emulation_fixtures.sh`. The routine matrix uses `-O0` and `-O2`
with automatic vectorization disabled, on x86-64, AArch64, x86-32, ARM32 and Thumb.
It compares return values and buffers with compiled C, and compares complete
reports across the library, CLI, both JavaScript entry points and MCP. On macOS,
the arm64 and x86-64 reference executables are also emulated. The suite executes
the CLI and JavaScript examples in this document and the emulation commands in
the README files.

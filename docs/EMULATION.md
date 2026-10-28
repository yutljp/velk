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
velk --emulate app.elf decode --emulation-options '{"arguments":["0x10000000",6,93],"memory":[{"address":"0x10000000","bytes":[53,56,49,49,50,93]}],"reads":[{"address":"0x10000000"}],"stepLimit":100000,"timeLimitMs":1000}'
```

The CLI prints a short text report by default. Add `--json` for the complete JSON report. `memory` lists contiguous changed regions, each with an
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
  reads: [{address: "0x10000000"}],
  trace: true
});
if (r.reason !== "return") throw new Error(r.error ?? r.reason);
r.reads[0].value;
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

## Input, output and memory reads

For a function that reads a line from stdin and prints its verdict:

```sh
velk --emulate app.elf check_flag --emulation-options '{"stdin":{"text":"flag{input}\n"}}'
velk --emulate app.elf main --emulation-options '{"argv":["app","candidate"]}'
velk --emulate app.elf decode_buffer --emulation-options '{"reads":[{"symbol":"decoded"}]}'
```

`stdin` accepts exactly one of `text` (UTF-8), `hex` (byte pairs with optional
whitespace), or `file` (a host file read before execution). Input is limited to
16 MiB. Missing input means EOF. `argv` includes the program name at index zero;
it prepares argc and a pointer array terminated by a null pointer. It cannot be
combined with `arguments` or used for Go functions.

`stdout` and `stderr` contain captured text, decoded as UTF-8 with replacement
for invalid sequences. Each stream is limited to 16 MiB. `printf`, `fprintf`,
`sprintf`, and `snprintf` support `%d %i %u %x %X %o %c %s %p %%`, integer lengths
`hh`, `h`, `l`, `ll`, `j`, `z`, `t`, flags `- + # 0`, field widths and precision,
including `*`. Strings support byte precision. `%p` uses hexadecimal with `0x`
and `(nil)` for zero. Wide characters, floating conversions, positional arguments,
`%n` stop with an error. The v-prefixed printf and scanf entry points accept
target va_list objects. Direct variadic I/O on AArch64 Mach-O stops because its argument placement
is not implemented. The architecture fixture matrix uses ELF. `sprintf` writes a terminating
NUL; `snprintf` returns the full length and writes at most capacity minus one bytes.

The input hooks are `read` on fd 0, `fread`, `fgets`, `gets`, `getchar`, `scanf`,
`fscanf`, and `sscanf` (including their v-prefixed forms and `__isoc99_` names). Scanning supports integer
conversions `d i u x X o`, `s`, `c`, widths and assignment suppression. Other
conversions stop with the unsupported specifier in the error. Standard FILE
pointers are supplied for imported or defined `stdin`, `stdout`, and `stderr`.
Other streams stop with an error. Stream objects and argv reserve heap space
before malloc runs. `puts`, `putchar`, `fputs`, `fwrite`, and `write`
on fd 1 or 2 append to the captured streams.

Linux ELF `read`, `write`, `exit` and `exit_group` system calls use the same stream models on x86-64 (`syscall`), i386 (`int 0x80`) and AArch64 (`svc 0`). Unknown syscall numbers stop with a diagnostic. Other file operations and system calls are not modeled.

`reads` requests memory after execution, including after an execution error or
limit. Each entry selects exactly one of `address`, a defined data `symbol`, or
a full `register` name containing the final pointer. Supply a byte `length` or
omit it to read up to a terminating NUL. The total read budget is 16 MiB.
`format` is `string` (default), `bytes`, `hex` (space-separated byte pairs), or
`integers`. Integer reads require `width` 1, 2, 4 or 8 and a byte length divisible
by that width; values are unsigned little-endian decimal strings. Results appear
in `reads`, each with `address`, exact `bytes`, and formatted `value`. Unmapped
memory, undefined registers, missing symbols and unterminated strings produce
an error report. The read budget is independent of the execution step limit.

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
result. A later variadic function can stop when its prologue spills unused
registers left unknown by an earlier hook. Partial writes preserve known bits; using unknown bits stops the run.
A void result, such as `free`, leaves the integer result unknown. Hooks still run
when `skipCalls` is set.
Unsupported system calls stop.

The report includes final `registers`, the integer `returnValue`, changed memory,
`steps`, the stopping `address`, `reason`, `error`, and an optional `trace`. Stop
reasons are `return`, `exit`, `end address`, `trap`, `stack check failed`, `step limit`, `time limit`, and `error`.
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

Automatic string recovery does not supply stdin or execute I/O hooks. Input-dependent decoders require explicit emulation.

The Windows ARM64 width fixture checks printing and scanning a 32-bit `long` with 64-bit pointers. It invokes hooks with explicit import targets; unresolved PE import thunks remain unsupported.

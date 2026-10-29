# Running loaded code

English | [日本語](EMULATION.ja.md)

`--emulate` runs lifted instructions through the IR interpreter. It supports x86-64,
AArch64, x86-32 and little-endian ARM32 (A32/T32). The binary's code never executes
on the host. Every run starts from a fresh image; it does not edit the file or the
cached analysis.

## Unpacking Linux ELF files

Add `--unpack` to an analysis operation to emulate a Linux ELF from its entry point
and analyze the recovered image directly:

```sh
velk --unpack -D packed.elf main
velk --unpack --iocs packed.elf
velk --unpack --strings packed.elf
velk --unpack --save-unpacked recovered.elf --sections packed.elf
velk --unpack --unpack-at 0x401200 -D packed.elf main
```

Without `--unpack-at`, emulation stops before executing an address written during
the run. A requested stop address must be inside a mapped region and also stops
before its instruction executes. The report gives the entry, stop address, step
count, stop reason, mapped regions, written regions, and mapped regions reached by
execution. `newEntry` is set when execution reaches written code or a requested
address. The CLI prints this report to standard error; `--save-unpacked` writes the
rebuilt ELF to a path that does not already exist.

The JSON report is available as `b.unpacking` from JavaScript, MCP, and `--serve`.

`stopAddress` is an optional virtual address. Defaults are 1,000,000 IR statements,
64 MiB for the distinct-write and saved-image limits, and 5,000 milliseconds.
The memory limit applies to distinct written bytes and mapped bytes in the saved image.
Limits may be lowered;
the maximums are 10,000,000 statements, 256 MiB, and 60,000 milliseconds. A run that
reaches a bound without written code or the requested address reports
`no unpacking observed`. ELF rebuilding preserves the input's mapped load regions
and applies the writes made by emulation. Written heap pages are added as executable
load regions; stack and TLS data are not included in the saved ELF. During unpacking,
writes to mapped image memory are allowed and `mprotect` is modeled without changing
host memory protection. The image is interpreted; its instructions are never run on the host.
This path currently supports Linux ELF files for x86-64, i386, and AArch64.

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

Pass bounds through the `unpack` option to `velk.open`:

```js
const b = velk.open("packed.elf", {
  cache: false,
  unpack: {stepLimit: 1000000, memoryLimit: 67108864, timeLimitMs: 5000}
});
JSON.stringify(b.unpacking, null, 2);
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

ELF and Mach-O execution starts with a separate 4 KiB thread-local mapping. `tlsBase`
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
`socketPeer` accepts the same input forms and supplies bytes to `recv` on the
deterministic in-memory peer. Each socket call uses that same
byte stream; sends succeed and `close` releases the emulated descriptor.

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
Other streams require explicit file inputs. Stream objects and argv reserve heap space
before malloc runs. `puts`, `putchar`, `fputs`, `fwrite`, and `write`
on fd 1 or 2 append to the captured streams.

C++ stream models recognize mangled libstdc++ and libc++ imports in 64-bit
ELF and Mach-O files. They capture C strings, `std::string`, characters, decimal integers,
`endl`, and `flush` on `std::cout`, and read words, lines, and decimal integers
from `std::cin`. String storage covers libstdc++ small/heap strings and libc++
short/long strings, with the alternate layout selected for Mach-O. String
operations use the existing 16 MiB memory and output bounds, and allocations use
the existing heap. Symbolic strings use the existing 4,096–65,536-byte model bound.
String construction/destruction, `std::ios_base::Init`, and `__cxa_atexit`
registration are modeled. Stream formatting changes, input failure, integer
overflow, and unrecognized C++ calls stop with a diagnostic. These models cover
default stream formatting; custom locales and general string operations are not
modeled. String allocation capacities are model choices.

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
  without file data read as zero. Executable sections cannot be modified.
  Windows process setup is described below. Other images receive stack guards
  and the library models documented here, without a runtime loader.
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

The hook table implements `memcpy`, `memmove`, `memset`, `memchr`, `memrchr`,
`strlen`, `strnlen`, `strcmp`, `strncmp`, `strcasecmp`, `strncasecmp`, `strchr`,
`strrchr`, `strstr`, `memcmp`, `strcpy`, `strncpy`, `strdup`, `strndup`, `atoi`,
`atol`, `strtol`, `strtoll`, `strtoul`, `strtoull`, `malloc`, `calloc`, `realloc`
and `free`. Conversion functions support bases 0 through 36, write the end
pointer when requested and set `errno` to `ERANGE` on overflow. Other conversion
results leave `errno` unchanged. `qsort` and `bsearch` invoke their comparator in
emulated code. Memory hooks check mapping and permissions; overlapping `memcpy`
is rejected. String comparisons return a byte difference whose sign matches
libc. Allocation uses aligned heap space; exhaustion returns zero. `realloc`
copies the smaller of the old and requested sizes. `free` validates the pointer
but does not reuse space.

`sleep`, `usleep` and `nanosleep` advance the deterministic clock by the requested
duration. `getrlimit` starts each resource at `RLIM_INFINITY`, and `setrlimit`
updates that per-run state. `setlocale` accepts the `C` and `POSIX` locales.
`socket`, `connect`, `bind`, `listen`, `accept`, `send`, `recv` and `close` use
the in-memory peer configured by `socketPeer`; they do not open host sockets.

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

The Windows ARM64 width fixture checks printing and scanning a 32-bit `long` with 64-bit pointers. It invokes hooks with explicit import targets; automatic Windows process setup is limited to x86-64 and i386.

## Windows process setup

x86-64 and i386 PE runs initialize an 8 KiB TEB at `tlsBase`, using GS and FS
respectively. The PEB contains the main image base, process parameters, and loader
lists with the main module, ntdll, kernel32, kernelbase, and imported DLLs. Modeled
DLLs have read-only PE headers and export directories. Named IAT entries, export
walks, `GetProcAddress` (name or modeled ordinal), `GetModuleHandleA/W`, and
`LoadLibraryA/W` use the same addresses. Library loading resolves modeled modules
only; it never opens a DLL on the host. Unknown APIs stop with a DLL-qualified name
unless `callReturns` or `skipCalls` explicitly overrides the call.
Main-module export forwarders and ordinal-only imports are unsupported.

The main image's static TLS template and zero-fill are initialized before its TLS
callbacks run with `DLL_PROCESS_ATTACH`. The callbacks run once per emulation,
before the selected function, and their memory writes appear in the report.
`TlsAlloc`, `TlsFree`, `TlsGetValue`, and `TlsSetValue` model 64 TEB slots.
Additional threads and DLL initialization routines are unsupported.
Thread and process-detach TLS callbacks are not invoked.

`GetCurrentProcessId` and `GetCurrentThreadId` return 1000 and 1001. Process and
thread pseudo-handles, `ExitProcess`, and the TEB's last-error value are modeled.
`Sleep` adds milliseconds to the clock without waiting; `Sleep(INFINITE)` stops.
`GetTickCount`, `GetTickCount64`, `QueryPerformanceCounter/Frequency`, and
`GetSystemTimeAsFileTime` share the instruction clock. The performance frequency
is 1 GHz; the `time` option sets the Unix-time origin for FILETIME.
PEB `BeingDebugged` and `CheckRemoteDebuggerPresent` use
`antiAnalysis.debuggerPresent`, default false. `IsDebuggerPresent` reads the current
PEB byte, including guest writes. `NtGlobalFlag` starts at zero.
PEB debugger-field reads and debugger/time API calls appear in `antiAnalysis`.

Supply process parameters in `windows: {commandLine, imagePath, environment}`.
Defaults are `program.exe`, `C:\\program.exe`, and an empty environment. Strings
use UTF-16; ANSI module names and `GetCommandLineA` require ASCII. Environment
names are case-insensitive; duplicate names and embedded NULs are rejected.
Process metadata reserves heap space before guest allocations. Reserve explicit
heap buffers with initial `memory` writes before passing their addresses.
`GetCommandLineA/W`, `GetEnvironmentStringsW`, and `FreeEnvironmentStringsW`
provide access to these parameters. The options are shared by the CLI,
JavaScript, MCP, and `--serve`. For the fixtures built by
`sh tools/make_windows_emulation_fixtures.sh`:

```sh
velk --emulate target/windows-emulation-fixtures/x86_64.O0.exe process_parameters --emulation-options '{"windows":{"commandLine":"program.exe sample","environment":{"NAME":"value"}}}' --json
```

`apiCalls` lists DLL-qualified names and hexadecimal scalar arguments in execution
order. For variadic CRT functions, only fixed arguments are listed; unknown
signatures have an empty argument list. Imported msvcrt/ucrt functions use the
existing C library hooks and their documented limits.

`GetProcessHeap` returns the process-heap handle recorded in the PEB. `HeapAlloc`,
`HeapReAlloc`, and `HeapFree` track block sizes; zero-size allocations are supported.
Reallocation preserves the retained bytes, `HEAP_ZERO_MEMORY` zeros the added
bytes, and `HEAP_REALLOC_IN_PLACE_ONLY` refuses moves. Allocation failure preserves
the old block and last error. Heap space is bounded to the existing 16 MiB area
and is not recycled after freeing. Invalid heap handles, invalid block pointers
and unsupported heap flags stop with an error. Heap exceptions are unsupported.

`VirtualAlloc` supports `MEM_RESERVE`, `MEM_COMMIT`, and their combination, using
4 KiB pages and 64 KiB reservation alignment. Virtual reservations have a separate
16 MiB total limit. `VirtualFree` supports decommit and whole-reservation release
at the original allocation address; other release addresses stop as unsupported.
Recommitted pages are zero-filled. `VirtualProtect` changes committed pages in a
single virtual reservation and returns the first page's previous protection.
Read and write permissions are enforced for `PAGE_NOACCESS`, `PAGE_READONLY`,
`PAGE_READWRITE` and their execute variants. Executing virtual-memory code,
changing image/heap protections, output pointers within the changed region, guard
pages and other allocation/protection flags are unsupported. Unsupported modes
stop; they do not report a successful operation. See the contracts for
[HeapReAlloc](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heaprealloc)
and [VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc).
String conversion, console/file, registry, and SEH APIs are not modeled.
The Windows tests compile both architectures at `-O0` and `-O2`, check process
state and export calls, heap contents, virtual-memory transitions and rejected
accesses, and compare reports across the execution interfaces. Page alignment has
SMT checks and concrete overflow cases. The ignored `windows_matches_wine` test
compares process and memory fixtures' stdout (including memory checksums) and exit
codes with Wine. It initializes a prefix and runtime directory under `target/`;
Wine must also be able to create its server sockets.

## File streams

Supply `files: {"input": [79, 75, 10], "output": []}` in execution options to
make virtual paths available. Paths match exactly. Every opened path, including
an output file, needs an entry; no host directory or file is read implicitly.
Use `--emulation-options` on the CLI, the options argument in JavaScript, or
`options` in `velk_emulate`. For a function that opens `input`:

```sh
velk --emulate app.elf read_file --emulation-options '{"files":{"input":[79,75,10]}}' --json
```

`fopen`, `fclose`, `fread`, `fwrite`, `fgets`, `fputs`, `fflush`, `setvbuf`,
`fileno`, `feof`, and `ferror` support these virtual files. Modes are `r`, `w`,
`a`, `r+`, `rb`, `wb`, `ab`, `r+b`, and `rb+`. Text and binary modes both preserve
bytes, including NUL, CR, LF and non-UTF-8 bytes, without newline translation.
Paths must be UTF-8. `w` truncates; `a` writes at the current end; `r+` reads and
writes at one position. An attempted read past the end sets EOF; reaching the
end exactly does not. Reading a write-only stream or writing a read-only stream
sets its error indicator and returns failure. Zero-size transfers return zero.
`fread` returns complete elements, consuming any partial final element too.
`fgets` includes a newline and adds NUL; size one writes NUL without reading.
Successful `fputs` returns zero, a permitted nonnegative result.

`setvbuf` records the buffering mode without changing transfer behavior.
`fflush(file)`, `fflush(NULL)` and `fclose` commit captured file contents to the
report's `files` map. An outer function return does not implicitly close files.
Pending writes are visible to other virtual streams but absent from that map
until committed. No host writes occur. File contents total at most 16 MiB.
Descriptors start at three and are not reused. Linux ELF `open` supports read-only
files, optionally with `O_CLOEXEC` and `O_LARGEFILE`; `read` and `close` accept
these descriptors. Other flags, descriptor-based `write`, formatted I/O, seeking,
clearing indicators, and `getline` on virtual files are unsupported. Unknown paths, unsupported open modes, and invalid or closed
`FILE *` values stop with diagnostics naming the path or value.

`rand` and `srand` use the default glibc sequence, initially seeded with 1.
Each execution has its own generator state. `time` returns a fixed Unix time
(default 0); the `time` option overrides it and a non-null argument receives
the same value at the target pointer width. `signal` records Linux signal
handlers and returns the previous handler. `alarm` replaces a pending timer
and returns its previous duration. `setbuf` accepts a null buffer for a standard or virtual file stream; caller-owned buffers are unsupported.

Anti-analysis answers can be set under `antiAnalysis` in the emulation options.
By default, `ptrace(PTRACE_TRACEME)` succeeds once, then fails; `getppid` returns
1; `prctl(PR_SET_DUMPABLE)` succeeds; `getenv("LD_PRELOAD")` reports the variable
unset; and `/proc/self/status` and `/proc/self/maps` return virtual contents.
The debugger APIs return false by default. `rdtsc`, `rdtscp`, `cntvct_el0`,
`clock_gettime`, `gettimeofday`, `GetTickCount`, and `QueryPerformanceCounter`
advance from the number of executed instructions using
`clockTicksPerInstruction` (default 1). The report's `antiAnalysis` array lists
checks handled during the run. For example,
`{"antiAnalysis":{"debuggerPresent":true,"parentProcessId":42,"preload":"/lib/example.so"}}`
changes those answers. Supported fields are `debuggerPresent`,
`ptraceTracemeSucceeds`, `parentProcessId`, `tracerProcessId`, `dumpable`,
`preload`, and `clockTicksPerInstruction`.
On x86-64 ELF, `int3` invokes a handler registered for `SIGTRAP` and resumes
after the breakpoint. Symbolic execution also uses the configured parent ID,
debugger answer, dumpability result, and first `PTRACE_TRACEME` result.

`exit` flushes virtual file streams and stops execution. If the image names or imports an exit-handler registration function, the call stops with a diagnostic. `_exit` is not modeled as a libc call.

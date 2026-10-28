<div align="center">

<img width="160" height="160" alt="velk" src="https://github.com/user-attachments/assets/31a1c0c1-3ca4-4d9f-8d88-917cc43bd49e" />

# velk

Turn machine code back into C that compiles.

English | [日本語](README.ja.md)

</div>

velk is a decompiler for ELF, PE and Mach-O binaries (x86-64 and AArch64), ELF32 and PE32 binaries
(x86-32), and little-endian ELF32 binaries (ARM32: A32/T32). It prints C code that computes the same
results as the original binary. You can use it from the command line, or from an LLM agent through
its scripting API and MCP server.

```c
int sum_until_zero(int *p, int n) {
    int64_t i;
    int32_t v3;
    int32_t v4;

    if (n <= 0) {
        return 0;
    }
    v3 = 0;
    for (i = 0; i < (uint32_t)n; i++) {
        v4 = p[i];
        if (v4 == 0) {
            break;
        }
        v3 += (v4 <= 0 ? 0 : v4);
    }
    return v3;
}
```

## Features

- Cross references, call graphs, string and constant searches, and function summaries.
- [Recovered structure layouts](docs/STRUCTURES.md), shared access views and strides, with unknown source declarations kept explicit in function cards.
- Automatic [library names](docs/LIBRARY_SIGNATURES.md) from embedded signatures, with a separate full database for musl, mbedTLS, libsodium, OpenSSL libcrypto, common Rust standard library code, zlib checksums and xxHash.
- Generated C API type libraries for macOS, Windows (Win32 and the C runtime), and Linux (glibc).
  Windows COM vtable fields retain function prototypes and calling conventions, including
  `IUnknown`, `IDispatch`, and `IStream`. Scripts can inspect target layouts with
  `b.libraryType("struct IUnknownVtbl")`, also through CLI scripts and MCP.
  Calls with supported interface types print as `object->lpVtbl->Method(object, ...)`.
  Referenced IIDs and CLSIDs are named from header GUID values. See [Windows COM](docs/WINDOWS_COM.md).
- [Saved analysis](docs/ANALYSIS_CACHE.md) in `<binary>.velk-cache`; move it with `--cache PATH` or `VELK_CACHE`, or disable it with `--cache off` (`VELK_CACHE=off`).
- Persistent names, types and comments in project files (`--project`, `--annotate`).
- [Compare program versions](docs/COMPARISON.md), review C and block differences, and copy annotations to matching functions (`--compare`, `--carry-annotations`).
- C++ RTTI class names, inheritance and virtual tables (`--classes`), and typed exception comments.

## Usage

To build a stable release, check out the latest release tag (`git checkout v0.1.0`) before building.

```bash
cargo build --release --locked

velk --functions path/to/binary          # list functions
velk --classes   path/to/binary          # list C++ classes as JSON
velk --decompile path/to/binary main     # decompile one function
velk --decompile path/to/binary          # decompile all functions
velk --disasm    path/to/binary 0x1000   # disassemble
velk --emulate path/to/binary sum3 --emulation-options '{"arguments":[1,2,3]}' # execute with arguments
velk --xrefs     path/to/binary main     # references to main
velk --strings   path/to/binary          # strings with references
```

Run `velk --help` for all options.

Whole-binary work uses the available CPU cores. Set `VELK_THREADS=1` to run with one worker,
or another positive integer to limit workers. Results remain in function order.
On Linux, the binary loader uses a read-only mapped snapshot; if mapping fails, it reads the file.

Universal Mach-O files open the slice for this machine; pick another with `--arch x86_64` (or `arm64`, `arm64e`).

## Raw and packed input

Headerless code accepts an explicit instruction set, load address, and entries:
`velk -D --raw-arch x86_64 --load-address 0x7000 code.bin 0x7000`.
The same mapping is available in scripts and MCP. UPX ELF and PE inputs use the
installed UPX decoder; `--save-unpacked FILE` saves a successful recovery.
See [input formats and limits](docs/INPUT.md).

## Running loaded code

Programs can use `velk --serve` for newline-delimited JSON. Each request contains
`id`, `code`, and optionally `timeout_ms`; each reply contains the same `id`, a
JSON `result` or an `error` with `message` and `stack`, and a `log` array. Results
are not truncated. JavaScript globals, opened binaries, and symbolic states persist
for the life of the process. Each log contains only that request's output; an error
or timeout does not end the session. Dispose symbolic states when no longer needed:

```sh
printf '%s\n' '{"id":1,"code":"console.log(\"hello\"); ({answer:42})"}' | velk --serve
```

Run `velk --api-docs` to list the embedded API topics, or `velk --api-docs emulation` to
read the execution options and results in the terminal.

Run a function by name or virtual address with initial arguments and memory:

```sh
velk --emulate app.elf decode --emulation-options '{"arguments":["0x10000000",6,93],"memory":[{"address":"0x10000000","bytes":[53,56,49,49,50,93]}],"reads":[{"address":"0x10000000"}]}'
```

The result includes registers, the integer return value, changed bytes and the
stop reason. The CLI defaults to a text report; add `--json` for JSON.
Use `stdin: {text: "candidate\n"}` for program input, `argv` for main arguments,
and `reads` to inspect a symbol, address or final register pointer. Captured output
is returned in `stdout` and `stderr`. Scripts use `b.emulate(start, options)` or
`b.getFunction(name).emulate(options)`; MCP clients use `velk_emulate`.
See [Running loaded code](docs/EMULATION.md) for the decoding example, supported
library hooks, errors and execution limits.

velk also recovers strings automatically from decoder calls with known buffers,
lengths and keys, and from inline stack construction. Recovered text appears only
in comments; `--strings` includes a `decodedStrings` array with buffer, call-site
and decoder addresses. Use `--no-string-decoding` to disable recovery.
See [Automatic string recovery](docs/STRING_DECODING.md) for examples and limits.

Function summaries include `apiHashes`: export-name candidates found by evaluating
hash routines used in name-table walks. The C includes comments with matching names.
These are candidates, since a hash does not identify the loaded library.
See [API hashes](docs/API_HASHES.md) for the supported data flow and limits.

## Using velk from an agent

velk does not register itself anywhere. Build it with `cargo build --release`, then register the executable
with your agent yourself, giving the full path to the executable:

```sh
# Claude Code
claude mcp add --transport stdio velk -- /path/to/velk --mcp

# Codex CLI
codex mcp add velk -- /path/to/velk --mcp
```

For clients configured with an `mcpServers` JSON file:

```json
{
  "mcpServers": {
    "velk": { "command": "/path/to/velk", "args": ["--mcp"] }
  }
}
```

The agent calls `velk_read_api` for the overview and worked examples, then writes short JavaScript snippets
for `velk_run_script` that query the binary and return only what it needs:

```js
const b = velk.open("/path/to/binary");
b.functions({ named: true }).slice(0, 5).map(f => ({ addr: f.addr, name: f.name }));
```

Replies are limited in size (see the overview for paging and timeouts). The same API is available from the
command line with `velk --run script.js`.

The script method `b.classes()` and MCP tool `velk_classes` list the same RTTI metadata as
`--classes`. See [C++ classes and exception tables](docs/CPP_CLASSES.md) for fields and limits.

Byte patterns, typed memory and standard constants are also available as JSON:

```sh
velk --search app '48 8b ?? 24' --section .text
velk --search app 'hello' --encoding ascii
velk --read-memory app 0x1000 --type u32 --count 4
velk --detect-constants app
```

The JavaScript API and MCP provide `b.search(pattern, options)`,
`b.readMemory(address, type, {count})` and `b.detectConstants()`.
See [memory queries](docs/MEMORY.md) for encodings, bounds, types and exact
constant signatures.

Copy, fill and scalar string effects can print as standard function builtins,
including `strlen`, normalized comparisons, `strchr` and literal `strcpy`.
`velk --summary app function` and JavaScript/MCP `f.summary().inlineFunctions`
list the recovered calls and constant byte counts. See
[recognition limits](docs/MEMORY.md#inlined-memory-functions).

Function summaries include `signature.callingConvention`, `signature.parameterCount`
and `signature.variadic`, plus a `calls` array with recovered targets and argument
counts. JavaScript `f.signature()` returns the same signature fields; MCP exposes
them through `velk_run_script`. See [function signatures](docs/CALLS.md) for limits.

Library signatures apply automatically when a binary is opened. `velk -f app`
shows the recovered names, source sets and certainty; `velk -D app XXH32` prints
a matched function. `--identify app` also lists unresolved candidates.
Use `--no-default-signatures` to disable the embedded sets and repeat
`--signatures custom.json` to add user sets. Build the full database with the
documented rebuild script, then load it with
`--signatures target/library-signatures/libraries.json.gz`. Gzip-compressed JSON
uses the same option. JavaScript and MCP accept
`velk.open("app", {defaultSignatures: false, signatures: ["custom.json"]})`.
See [library signatures](docs/LIBRARY_SIGNATURES.md) for coverage, licenses,
rebuilding and measurements.

Constant control-flow predicates are removed only when integer identities or tracked
constant values prove their result for every input. Dispatch loops whose incoming
states are all constants can be replaced with direct branches. Unknown transitions
keep the dispatcher. Function cards and JavaScript/MCP function summaries include
`simplification`, with `simplified`, `predicatesRemoved`, and
`dispatcherStatesRemoved`. See [control-flow simplification](docs/CONTROL_FLOW.md).

Mixed bitwise and arithmetic expressions can simplify to sums, bitwise operations,
constants and shorter polynomials. Function cards and summaries also report
`simplification.mbaExpressionsSimplified`, the number of accepted expression
replacements. See [expression simplification](docs/MBA.md) for supported forms
and limits.

Find functions with similar analyzed structure and references:

```sh
velk --similar pair_sum tests/fixtures/arm64.o --in tests/fixtures/arm64_macho.o --limit 5 --json
```

JavaScript and MCP expose the same search as `f.similar({in: other, limit: 5})`.
Omit `in` to search the same binary, excluding `f`. Scores measure feature overlap,
not the probability of a match or equivalent behavior. See [function similarity](docs/SIMILARITY.md)
for the weights, evidence, cache behavior and limitations.

## Documentation

- [Scripting API](src/script/api/index.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Testing](docs/TESTING.md)
- [Running loaded code](docs/EMULATION.md): CLI, JavaScript and MCP execution with explicit state and limits.

## License

MIT. See [LICENSE](LICENSE).

Symbolic execution searches for inputs that reach a virtual address:
`velk --explore check --find 0x401100 --stdin 8 app.elf` (`--json` returns JSON).
It requires an external Z3 or Bitwuzla process. Rust, JavaScript (`b.explore` and
`b.symbolic`) and MCP (`velk_explore`) expose the same search. See
[Symbolic execution](docs/SYMBOLIC.md) and `velk --api-docs symbolic` for inputs,
state operations and deterministic limits.

Return conditions (`b.solve`, `--solve check --returns eq:1`) and branch feasibility (`b.branchFeasibility`, `--opaque check`) use the same bounded executor and libc models.

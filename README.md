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
- Byte signatures to identify stripped library functions.
- Generated C API type libraries for macOS, Windows (Win32 and the C runtime), and Linux (glibc).
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
velk --decompile path/to/binary '*'      # decompile all functions
velk --disasm    path/to/binary 0x1000   # disassemble
velk --emulate path/to/binary sum3 --emulation-options '{"arguments":[1,2,3]}' # execute with arguments
velk --xrefs     path/to/binary main     # references to main
velk --strings   path/to/binary          # strings with references
```

Run `velk --help` for all options.

Universal Mach-O files open the slice for this machine; pick another with `--arch x86_64` (or `arm64`, `arm64e`).

## Running loaded code

Run a function by name or virtual address with initial arguments and memory:

```sh
velk --emulate app.elf decode --emulation-options '{"arguments":["0x10000000",6,93],"memory":[{"address":"0x10000000","bytes":[53,56,49,49,50,93]}]}'
```

The JSON result includes registers, the integer return value, changed bytes and the
stop reason. Scripts use `b.emulate(start, options)` or
`b.getFunction(name).emulate(options)`; MCP clients use `velk_emulate`.
See [Running loaded code](docs/EMULATION.md) for the decoding example, supported
library hooks, errors and execution limits.

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

## Documentation

- [Scripting API](src/script/api/index.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Testing](docs/TESTING.md)
- [Running loaded code](docs/EMULATION.md): CLI, JavaScript and MCP execution with explicit state and limits.

## License

MIT. See [LICENSE](LICENSE).

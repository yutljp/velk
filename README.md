<div align="center">

<img width="160" height="160" alt="velk" src="https://github.com/user-attachments/assets/31a1c0c1-3ca4-4d9f-8d88-917cc43bd49e" />

# velk

Turn machine code back into C that compiles.

English | [日本語](README.ja.md)

</div>

velk is a decompiler for ELF, PE and Mach-O binaries (x86-64 and AArch64), ELF and PE binaries
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

## Usage

```bash
cargo build --release --locked

velk --functions path/to/binary          # list functions
velk --decompile path/to/binary main     # decompile one function
velk --decompile path/to/binary '*'      # decompile all functions
velk --disasm    path/to/binary 0x1000   # disassemble
```

Run `velk --help` for all options.

## Using velk from an agent

Register velk with your MCP client using the `--mcp` flag.

```json
{
  "mcpServers": {
    "velk": { "command": "/absolute/path/to/velk", "args": ["--mcp"] }
  }
}
```

The agent writes short JavaScript snippets that query the binary and return only what it needs. The same API is
available from the command line with `velk --run script.js`.

```js
const b = velk.open("/absolute/path/to/binary");
b.functions({ named: true }).slice(0, 5).map(f => ({ addr: f.addr, name: f.name }));
```

## Documentation

- [Scripting API](src/script/api/index.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Testing](docs/TESTING.md)

## License

Not decided yet.

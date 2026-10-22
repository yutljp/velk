# velk script API

Scripts are plain synchronous JavaScript: no `await`, no imports, no file system.
The output is everything passed to `console.log`, followed by the value of the last expression.
Opened binaries and per-function analysis stay cached between runs.

MCP script responses default to 4,000 Unicode characters, including errors and any truncation notice.
Set `max_output_chars` on `velk_run_script` to request 256–20,000 characters.
A truncation notice means the text is incomplete: filter, map selected fields, or slice a smaller range in the script before returning it.
This display limit does not change the arrays the script works with or limit its analysis work.
For a function summary use `card({budget})`; for selected instructions use `disasm({limit})`.

Topics (read one with `velk_read_api({ topic })`):

- `binary`: `velk.open(path)` and `Binary`: `sections()`, `functions(filter)`, `getFunction(nameOrAddr)`, `buildSignatures()`, `identify(signatures)`
- `func`: `Func`: `card({budget})`, `decompile()`, `disasm({limit})`, `ir()`, `signature()`, `references()`, `strings()`, `shapeHash()`
- `types`: `Addr`, `Section`, `Card`, `Reference`, `Signature`, `SignatureDb`, `Match`, `Failure`

Addresses are hex strings such as `"0x1e0"`; inputs also accept numbers.

```js
const b = velk.open("/path/to/binary");
b.functions({ named: false, minSize: 200 }).slice(0, 5)
  .map((f) => ({ addr: f.addr, name: f.name, size: f.size }));
```

Return a later slice to inspect another range, or retrieve one selected body with `b.getFunction("main").decompile()`.

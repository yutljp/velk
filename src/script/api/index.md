# velk script API

Scripts are plain synchronous JavaScript: no `await`, no imports, no file system.
The output is everything passed to `console.log`, followed by the value of the last expression.
Opened binaries and per-function analysis stay cached between runs.

Topics (read one with `velk_read_api({ topic })`):

- `binary`: `velk.open(path)` and `Binary`: `sections()`, `functions(filter)`, `getFunction(nameOrAddr)`, `buildSignatures()`, `identify(signatures)`
- `func`: `Func`: `card({budget})`, `decompile()`, `disasm({limit})`, `ir()`, `signature()`, `references()`, `strings()`, `shapeHash()`
- `types`: `Addr`, `Section`, `Card`, `Reference`, `Signature`, `SignatureDb`, `Match`, `Failure`

Addresses are hex strings such as `"0x1e0"`; inputs also accept numbers.

```js
const b = velk.open("/path/to/binary");
const big = b.functions({ named: false, minSize: 200 });
for (const f of big.slice(0, 5)) console.log(f.addr, f.strings());
b.getFunction("main").decompile();
```

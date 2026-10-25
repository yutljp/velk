# velk script API

Scripts are plain synchronous JavaScript: no `await`, no imports, no file system.
The output is everything passed to `console.log`, followed by the value of the last expression.
When several decompiled functions are logged as C text, their support definitions and declarations are collected into one marked prelude at the top of the output. Each `decompile()` result includes its own prelude for standalone use.
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

## Navigation queries

Navigation commands print JSON:

```sh
velk --xrefs BIN TARGET [--from]
velk --callers BIN TARGET [--depth N]
velk --callees BIN TARGET [--depth N]
velk --path BIN FROM TO [--depth N]
velk --strings BIN [--contains TEXT]
velk --constants BIN VALUE
velk --summary BIN FUNCTION
```

Targets accept function names, import names, data symbols or addresses. Constants
accept decimal or hexadecimal values. Callers and callees default to depth 1;
paths default to 32 and include both endpoints. Depth 0 returns no neighbors.
An unreachable path is an empty array.

Scripts use `b.xrefs(target, {from})`, `b.callers(target, {depth})`,
`b.callees(target, {depth})`, `b.callPath(from, to, {depth})`,
`b.strings({contains})` and `b.constants(value)`. A `Func` also provides
`xrefs({from})`, `callers({depth})`, `callees({depth})` and `summary()`.
The navigation index is built once per opened binary and cached in the session.
Summaries include the inferred signature, size, callees, imports, referenced
strings and incoming/outgoing reference counts.

A reference's `function` and `block` are virtual addresses; `statement` is a
zero-based lifted IR statement ordinal, not an instruction address. Constant
matches instead report the decoded instruction address and operand index.
`candidateCall` references are possible indirect targets, excluded from call
graph traversal. The `failures` field lists functions that could not be lifted;
results can be incomplete even when a query succeeds. An interrupted index build
is not cached and can be retried.

String detection scans loaded non-executable sections for printable ASCII, UTF-8
and UTF-16LE runs of at least four characters, including both UTF-16 alignments.
These are heuristic candidates, not proof that the program uses text; string
references come from the lifted IR. Scalar constants equal to mapped addresses
can appear as address references. Constant search scans decoded immediates in
executable sections, excludes branch displacements, and does not reconstruct
values assembled by multiple instructions.

## Library signatures

Build a JSON database from a named binary, object file, static `.a` archive, or
Rust `.rlib`, then apply it to a binary of the same instruction set:

```sh
velk --build-signatures library.a --output signatures.json
velk --identify stripped.bin --signatures signatures.json
velk --decompile stripped.bin 0x1000 --signatures signatures.json
velk --card stripped.bin 0x1000 --signatures signatures.json
```

Scripts can build a database without opening the archive as a binary:

```js
const database = velk.buildSignatures("library.a").database;
const binary = velk.open("stripped.bin");
const result = binary.identify(database);
result.matches.map(match => binary.getFunction(match.addr).decompile());
```

`binary.buildSignatures()` builds from the opened binary. `identify` accepts a
database object or its JSON file path, returns `matches` and `failures`, and names
unnamed functions. Existing names are preserved; subsequent function listings,
lookups, and decompilation use the inferred names. CLI `--signatures` applies
matches before card or decompilation analysis. Without a database, those operations
do no signature scanning. Source file and archive member names are recorded in
`database.sources`.

A match requires identical normalized instruction bytes, a unique candidate name,
and agreement of direct call destinations with independently matched functions.
Only encoded direct call and external jump destinations are normalized. Bodies
must contain at least 32 bytes after trailing alignment padding is removed and
24 non-padding instruction bytes outside encoded destinations. Short, ambiguous,
unsupported, or unresolved functions are skipped. Indirect control flow,
PC-relative data references, unsupported relocations, and external conditional
branches prevent matching. A skipped callee can also prevent its callers from
matching. Matches identify compiler output, not semantic equivalence; different
compiler versions or options can reduce coverage. `shapeHash()` is informational
and is not used for library identification.

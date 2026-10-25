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

## Persistent annotations

The default project file is `<binary>.velk.json` beside the canonical binary.
Use `--project PATH` or `velk.open(path, {project: "analysis.json"})` to store it
in a writable directory. Ordinary analysis creates no project and reads no binary
bytes for project hashing unless the project exists. A session hashes once.
The UTF-8 JSON document contains `version: 1`, `binary_sha256` (lowercase SHA-256),
and `annotations`. Unknown versions, fields, duplicate targets and hash mismatches fail.

```sh
velk --annotate BIN '{"target":{"kind":"function","address":"0x401000"},"name":"calculate"}'
velk --annotation BIN '{"kind":"function","address":"0x401000"}'
velk --annotations BIN
velk --unannotate BIN '{"kind":"function","address":"0x401000"}'
velk --export-project BIN
velk --import-project BIN FILE
velk --origins BIN FUNCTION
```

Commands emit JSON; errors include `code` and `message`. Set replaces one annotation;
import replaces the document. Export creates an empty project if absent.
`Binary` methods are `projectSet(annotation)`, `projectGet(target)`, `projectList()`,
`projectRemove(target)`, `projectExport()` and `projectImport(document)`.
`Func.origins()` returns stable storage selectors; use these instead of printed locals.
Changes persist immediately and sessions invalidate analysis when projects change.
A session selects one project per binary; reopening with a different explicit
project switches subsequent requests for that binary to that file.

Annotations have `target` and optional `name`, `c_type`, `text`. Targets are
`function`/`global`/`comment`/`classification` with `address`, `parameter`/`local`
with `function` and `storage`, `signature` with `function`, or `declaration` with
`name`. Addresses accept hexadecimal strings or unsigned integers. Storage is
`{kind:"register",register:N}`, `{kind:"stack",offset:N}`, or
`{kind:"definition",register:N,block:ADDR,statement:N}`. Origins are stable across
annotation edits and restarts with the same analysis version, not across upgrades.
Function names use `name`; parameters, locals and globals use `name`/`c_type`;
other kinds use `text`. Classification accepts `code` or `data` and adds/removes
only the entry at that address; it does not rewrite instructions.

Cooperating writers exclusively lock the binary inode, reread, validate, sync a
temporary file beside the project, atomically rename it and sync the directory.
Readers see complete JSON and concurrent edits are preserved. Keep the binary
unchanged during a session. Direct editors must follow the same locking protocol.
An interrupted write can leave a temporary file.

Type annotations and declarations currently require a 64-bit target layout; ARM32
projects support names, comments and classification. Types support fixed-width integers, signed/unsigned char, short, int and long long,
void, pointers (up to 16 levels), naturally aligned structs, enums and typedefs. Arrays,
bit-fields, qualifiers, floating types and arbitrary expressions are rejected.
Declarations are processed in order; structure pointers may refer forward.
Signature text uses a return type and parameter list, e.g. `int32_t (int32_t value)`.
Signatures require the existing nonvariadic scalar argument count and known
storage; parameter edits propagate to direct callers. Stack types must fit an
existing object exactly. Ambiguous storage and name collisions fail during rendering.
Names and comments preserve computation. **Declared types can change computation**
through width, signedness, pointer arithmetic, layouts and return conversions;
they are user assertions. Classification changes available entries. Comments
appear above their owning function with unsafe delimiters escaped.

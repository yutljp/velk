# velk script API

Scripts are plain synchronous JavaScript: no `await`, no imports, no file system.
The output is everything passed to `console.log`, followed by the value of the last expression.
When several decompiled functions are logged as C text, their support definitions and declarations are collected into one marked prelude at the top of the output. Each `decompile()` result includes its own prelude for standalone use.
Opened binaries and per-function analysis stay cached between runs.
JavaScript variables do not: each call evaluates in a fresh context. Reopen the
same path at the start of every script. `velk.open()` discovers functions without
decompiling all of them; `card()`, `decompile()` and other function operations
analyze the selected function and a bounded neighborhood when needed.

Open single-architecture ELF, PE/COFF or Mach-O files. Universal Mach-O files
must first be extracted, for example with `lipo -thin arm64e input -output thin`.
Use an absolute binary path when the MCP client's working directory is unknown.

MCP script responses default to 4,000 Unicode characters, including errors and any truncation notice.
Set `max_output_chars` on `velk_run_script` to request 256–20,000 characters.
A truncation notice means the text is incomplete: filter, map selected fields, or slice a smaller range in the script before returning it.
This display limit does not change the arrays the script works with or limit its analysis work.
For a function summary use `card({budget})`; for selected instructions use `disasm({limit})`.
The script time budget is `timeout_ms` (default 10,000, maximum 120,000), checked
at JavaScript interrupts and analysis boundaries rather than a hard wall-clock
cutoff. The first navigation query builds a whole-binary index; on large files,
start with function listings or cards and increase the navigation timeout.
Interrupted index builds restart on retry. Errors have `isError: true` in the MCP
tool result, with a short message and no runtime stack trace.

Topics (read one with `velk_read_api({ topic })`):

- `binary`: opening, function discovery, navigation, string/constant queries, persistent annotations and library signatures.
- `func`: cards, C, disassembly, IR, signatures, origins, references, summaries and call graph queries.
- `types`: addresses, cards, signatures and all navigation result fields. Annotation types are in `binary`.

Addresses are hex strings such as `"0x1e0"`; inputs also accept numbers within
JavaScript's safe integer range. They are virtual addresses, not file offsets.

```js
const b = velk.open("/path/to/binary");
b.functions({ named: false, minSize: 200 }).slice(0, 5)
  .map((f) => ({ addr: f.addr, name: f.name, size: f.size }));
```

Return a later slice to inspect another range, or retrieve one selected body with `b.getFunction("main").decompile()`.
`getFunction()` accepts an exact name or function start address; it also tries a
unique case-insensitive substring (and names without Mach-O's leading `_`).
It throws on missing or ambiguous matches. `"*"` is not a function selector.
For stripped binaries inspect `b.functions().slice(0, 10)` and `b.entry`; an entry
point need not be a source-level `main`.

To page long C without omitting lines, run these as separate calls, adjusting
the line range and reducing it if the response still reports truncation:

```js
const b = velk.open("/path/to/binary");
b.getFunction("main").decompile().split("\n").slice(0, 40).join("\n");
```

```js
const b = velk.open("/path/to/binary");
b.getFunction("main").decompile().split("\n").slice(40, 80).join("\n");
```

For several functions select a small batch first; mapping `decompile()` over an
entire function list still does all that work before the display limit applies.
Truncated C is incomplete and cannot be compiled as is.

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
These methods return objects containing arrays, not arrays directly. Keep pages
small, select fields and retain a failure count:

```js
const b = velk.open("/path/to/binary");
const result = b.callees("main", {depth: 1});
({functions: result.functions.slice(0, 10), failures: result.failures.length});
```

```js
const b = velk.open("/path/to/binary");
const result = b.strings({contains: "usage"});
({total: result.strings.length,
  strings: result.strings.slice(0, 5).map(s => ({addr:s.addr, text:s.text})),
  failures: result.failures.length});
```

Use `b.callers("main").functions`, `b.xrefs("main").xrefs`, and
`b.constants("0x100").matches` similarly. Change the slice to retrieve the next
page; rerunning queries reuses the index. `xrefs()` defaults to incoming
references; `{from:true}` selects references made by the containing function.

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
For example, name one function and use it in a later script with the same binary
and project path:

```js
const b = velk.open("/path/to/binary", {project: "analysis.json"});
const f = b.getFunction(b.entry ?? b.functions()[0].addr);
b.projectSet({target:{kind:"function", address:f.addr}, name:"analyzed_entry"});
b.getFunction("analyzed_entry").decompile();
```

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

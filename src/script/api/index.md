# velk script API

Scripts are plain synchronous JavaScript: no `await`, no imports, no file system.
The output is everything passed to `console.log`, followed by the value of the last expression.
When several decompiled functions are logged as C text, their support definitions and declarations are collected into one marked prelude at the top of the output. Each `decompile()` result includes its own prelude for standalone use.
Opened binaries and per-function analysis stay cached between runs.
JavaScript variables do not: each call evaluates in a fresh context. Reopen the
same path at the start of every script. `velk.open()` discovers functions without
decompiling all of them; `card()`, `decompile()` and other function operations
analyze the selected function and a bounded neighborhood when needed.

Headerless code uses `velk.open("code.bin", {raw: {arch: "x86_64", base: "0x7000"}})`.
RawOptions in the binary topic lists all instruction sets and entry options.
UPX ELF/PE recovery requires UPX on PATH. `b.packing` reports successful direct
decoding and `b.saveUnpacked("recovered.exe")` saves its complete output.
See [input formats and limits](../../../docs/INPUT.md).

`card().structureLayouts` contains inferred structure tags, hexadecimal field
offsets, C access types, access widths, minimum observed sizes and known array
strides. `elementSize` is null when the stride is unknown.
`sourceFields` and `sourceSize` remain null for inferred layouts: an access
width, C storage type or stride alone does not prove a source declaration. Overlapping entries
describe access views and do not establish a source union. `structures` retains
the generated C declarations. See `docs/STRUCTURES.md` for measurement scope.

Open ELF, PE/COFF or Mach-O files. A universal Mach-O file opens the slice for this
machine; pass `{arch: "x86_64"}` (or `"arm64"`, `"arm64e"`) to `velk.open` for another.
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
- `emulation`: initial registers, arguments, memory, limits, hooks and final execution state.
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

For parallel decompilation, use `b.decompile(selectedFunctions)` or `b.decompile()`
for every function. Results are `{addr, code, error}` objects in the selected order;
each has either C text or an error. Log each successful `code` to combine its C
prelude with other logged functions. Individual `f.decompile()` calls in a loop
remain sequential. `VELK_THREADS` limits workers across analysis and navigation;
the default is the available CPU count.

```js
const b = velk.open("/path/to/binary");
for (const result of b.decompile(b.functions().slice(0, 5))) {
  if (result.error !== null) throw new Error(result.error);
  console.log(result.code);
}
```

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
`signature()` and `summary().signature` include `callingConvention`,
`parameterCount` (including stack parameters) and `variadic`.
`summary().calls` lists analyzed calls with their block and statement index,
target, indirect status, calling convention, argument count and candidates.
Unknown targets and argument counts are null; an empty candidate list means
no candidates were recovered.
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

Opening a binary applies embedded zlib checksum and xxHash instruction sets.
`b.functions()` and `Func.library` expose candidate names, source sets and
`exact`, `ambiguous` or `unconfirmed` certainty. Only exact matches supply names.
Set `defaultSignatures: false` to disable the embedded sets. Add user databases
with `signatures: ["first.json", "second.json"]`; all enabled sets are matched
together. Handles with different options use separate cached binaries.

```sh
velk --functions stripped.bin --json
velk --identify stripped.bin
velk --functions stripped.bin --no-default-signatures
velk --build-signatures library.a --output signatures.json
velk --decompile stripped.bin 0x1000 --signatures signatures.json
```

```js
const binary = velk.open("stripped.bin", {signatures: ["extra.json"]});
binary.functions().filter(f => f.library).map(f => ({
  addr: f.addr, name: f.name, evidence: f.library
}));
const database = velk.buildSignatures("library.a").database;
const result = binary.identify(database);
result.candidates.map(candidate => candidate.evidence);
```

`buildSignatures` accepts a named binary, object, static `.a` archive or Rust
`.rlib`. `binary.buildSignatures()` uses the opened binary. `identify` accepts a
database or JSON file path and adds it to the enabled databases. It returns
`matches`, unresolved `candidates` and `failures`, and refreshes inferred names
and analysis caches. An added alias can withdraw a previously recovered name.
Existing symbol names are preserved. Input files and archive members appear in
`database.sources`; each embedded entry also has a `set` identifier.

Matching requires complete normalized instruction bodies, immediate constants,
internal branch structure and confirmed direct-call destinations. Fixed-width
x86-64 PC-relative constant reads also require identical bytes in read-only data.
Unsupported address references, relocations, indirect control flow and ambiguous
names remain unnamed. Bodies need at least 32 bytes after alignment padding is
removed and 24 non-padding bytes outside encoded destinations. Different
compilers or flags can prevent matches; exact means agreement within the enabled
sets, not a proof of source-code origin. `shapeHash()` remains informational.
See `docs/LIBRARY_SIGNATURES.md` for licenses, coverage and measurements.

## Comparing program versions

`first.compare(second)` compares binaries opened with `velk.open` and returns
`changed`, `identical`, `onlyFirst`, `onlySecond`, `failures` and `transfer`.
Matches carry a rule (`name`, `shape` or `references`), similarity, and C and
optimized-block differences. Ambiguous matches remain unmatched. Identical
requires equal machine bytes and printed C. Scores describe matching evidence,
not equivalent behavior.

`first.compare(second, { carryAnnotations: true })` copies names, types and
comments into unannotated targets in the second project's file. Existing targets
are preserved and every copied or skipped entry has a reason. Signatures and
variable annotations require compatible inferred storage and types on the same
architecture; locals also require identical bytes. Globals
require unique agreeing reference locations in matched functions. Review types
when data layouts change. Use `open`'s `project` option to select either file.
Comparison analyzes all functions; MCP callers should allow a suitable timeout
and return only the relevant slice of the report.

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


## Bytes and typed memory

`b.search("48 8b ?? 24")` searches loaded sections. Options select
`encoding` (`hex`, `ascii`, `utf16`, `integer`), integer `width` in bytes (negative integers use two’s complement),
`byteOrder` (`native`, `little`, `big`), `start`, `end` and `section`.
The default is hex in image byte order; start is inclusive and end exclusive.
Results contain `matches` with `addr`, `section` and the containing `function`
address or null. Matches may overlap but never cross section boundaries.

`b.readMemory("0x1000", "u32", {count: 4})` reads four values. Types include
`u8/u16/u32/u64`, `i8/i16/i32/i64`, `f32/f64`, `pointer`, `cstring`, `utf16`,
`TYPE[N]` and debug structures such as `struct sample`. Reads use image byte
order and pointer width. Unmapped and cross-section reads fail. Zero-initialized sections read as zero.
Unsigned 64-bit integers and pointers are hex strings; signed 64-bit integers
are decimal strings. C strings require UTF-8; UTF-16 strings reject invalid
surrogates. Infinity and NaN are strings. Limits are 65536 values (including
nested fields/elements), 16 nesting levels and 16 MiB per read.
Debug structure reads require available, unambiguous layouts; unsupported
layouts fail. Debug types on big-endian images are not currently loaded.

`b.detectConstants()` returns `matches` and navigation `failures`. Matches name
full exact data signatures, in either byte order, and complete groups of decoded
instruction immediates within one function. Each match gives `name`, `addr`,
`size`, `kind`, `section`, `byteOrder` and referencing `functions` from xrefs.
For immediates, the address is the first matched instruction, section and byte
order are null, and functions contains the function with the group. Big-endian instruction immediates are not decoded. Instructions
that construct a larger constant from pieces are not combined. The presence of
constants does not establish which algorithm a function implements.
Exact data matches supply global names in printed C. A longer matching signature
wins when signatures share the same starting address.

CLI equivalents:

```sh
velk --search BIN '48 8b ?? 24' --section .text
velk --search BIN 'hello' --encoding ascii
velk --search BIN 'hello' --encoding utf16 --byte-order little
velk --search BIN 0x12345678 --encoding integer --width 4 --byte-order big
velk --read-memory BIN 0x1000 --type u32 --count 4
velk --detect-constants BIN
```

The same JavaScript methods are available through MCP's `velk_run_script`.
Slice `matches` or `values` before returning large results.
Function summaries include `apiHashes`: name candidates from emulated export hash
comparisons connected to indirect calls. Entries include block/statement positions,
resolver and routine addresses, the constant hash, all candidates and a completion
flag. Names do not prove which module is loaded. See `docs/API_HASHES.md` for limits.

Run code with `b.emulate(nameOrAddress, options)` or `b.getFunction(name).emulate(options)`.
The dedicated `velk_emulate` MCP tool takes `{path, start, options, arch?}` and returns
an execution report. Read the `emulation` topic for its options; see
[Running loaded code](../../../docs/EMULATION.md) for a string-decoding example.

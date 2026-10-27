# API hashes

An indirect call can use an address returned by a function that walks a table of
names and compares their hashes with a constant. velk follows the call result and
comparison operands through the IR. It evaluates the recovered hash routine on a
small bundled list of Windows and C library export names. It does not identify
hash routines by instruction bytes or substitute a built-in hash formula.

Results appear in `apiHashes` in function summaries: CLI `--summary`, JavaScript
`f.summary()`, and MCP `velk_run_script`. Each entry contains the call's
`block` and `statement`, the `resolver` and hash `routine` addresses, the constant
`hash`, all matching `candidates`, and `complete`. Statement numbers refer to the
optimized IR, not instruction addresses. An empty candidate list means no name
matched. Several candidates mean a collision. `complete: false` means at least
one evaluation failed or the time budget expired; missing results are possible.
`indirectCall` distinguishes an indirect invocation from an i386 function that
returns the resolver result without invoking it.

Matching names also appear in C comments. The indirect call remains unchanged.
A match does not establish which module is loaded, whether an export is forwarded,
or whether the table actually contains that export. velk does not replace the
call with a direct API call or infer a prototype from the hash.

The current analysis requires a direct resolver call with a constant argument,
a loop with an equality comparison between that argument and a direct hash call,
and an indirect call through the resolver's result, or a returned lookup result
on i386. The hash routine must take
one pointer to a zero-terminated byte string. Stack slots and register copies are
handled through the existing memory and SSA analyses. Inlined hashes, combined
module/name hashes, wide strings, hash seeds passed as additional arguments,
and results merged through different definitions can remain unrecognized.
The analysis does not verify a PEB or link-map structure from offsets.
The supported architectures are x86-64, i386 and AArch64. Go images are skipped.
i386 indirect calls with unknown argument counts still
fail decompilation; the i386 fixtures return the lookup result instead.

Each scan allows 1,000 milliseconds. Each export-name evaluation allows 10,000 IR
statements and 100 milliseconds, within the caller's deadline. No host API or
system call executes. The bundled list is in `src/api_hashes/exports.txt`.

Build the source fixtures before running these examples:

```sh
sh tests/make_api_hash_fixtures.sh
velk --summary target/api-hash-fixtures/x86_64.O2.elf case_ror13
velk -D target/api-hash-fixtures/x86_64.O2.elf case_ror13
```

```js
const b = velk.open("target/api-hash-fixtures/x86_64.O2.elf");
b.getFunction("case_ror13").summary().apiHashes;
```

For MCP, pass that JavaScript as `code` to `velk_run_script`. Its text result contains
the same JSON array. The fixtures include ROR13, djb2, FNV-1a, CRC32, a custom
hash, collisions, unknown hashes, PE export directories and ELF dynamic symbols.
They are compiled as position-independent code for x86-64, i386 and AArch64.

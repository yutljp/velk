# API hashes

An indirect call can use an address returned by a function that walks a table of
names and compares their hashes with a constant. velk follows the call result and
comparison operands through the IR. It evaluates the recovered hash routine on a
small bundled list of Windows and C library export names. It does not identify
hash routines by instruction bytes or substitute a built-in hash formula.

Results appear in `apiHashes` in function summaries: CLI `--summary`, JavaScript
`f.summary()`, MCP `velk_run_script`, and scripts sent to `--serve`. Each entry
contains the call's `block` and `statement`, the `resolver` and hash `routine`
addresses, the constant `hash`, matching `candidates`, and `complete`. Statement
numbers refer to the optimized IR, not instruction addresses. `routine` is the
hash function for a separate hash call, or the resolver itself when velk emulates
the whole lookup. An empty candidate list means no name matched. Several
candidates mean a collision. `complete: false` means the result may omit other
matching names or a budget prevented full evaluation. Whole-resolver emulation
reports the name returned by the resolver and does not enumerate collisions.
`indirectCall` distinguishes an indirect invocation from an i386 function that
returns the resolver result without invoking it.

Matching names also appear in C comments. The indirect call remains unchanged.
A match does not establish which module is loaded, whether an export is forwarded,
or whether the table actually contains that export. velk does not replace the
call with a direct API call or infer a prototype from the hash.

The analysis requires a direct resolver call with constant arguments and an
indirect call through its result, or a returned lookup result on i386. For a
separate hash function, velk evaluates the function on names in its bundled
export list. This handles a zero-terminated byte string, constant integer
arguments, and UTF-16 strings when the routine reads 16-bit characters.

When the hash calculation is inlined, velk can emulate the whole resolver and
read the name associated with its returned address. This also handles a resolver
that walks an ELF dynamic symbol table. For 32-bit and 64-bit Windows images, the
emulator provides a synthetic PEB loader list and module export tables, so a
resolver can walk those structures and return a named export. Emulation uses the
image and synthetic process state; it does not inspect a live process. These
results identify the export selected in that state and do not establish which
modules a real process has loaded. Stack arguments are recovered from the call
site when they are constant. The supported architectures are x86-64, i386 and
AArch64 for ELF; Windows resolver emulation supports x86-64 and i386. Go images
are skipped. i386 indirect calls with unknown argument counts still fail
decompilation; the i386 fixtures return the lookup result instead.

Each scan allows 2,000,000 IR statements and name evaluations in total. A
whole-resolver evaluation allows at most 200,000 IR steps and 100 ms, within the
caller's deadline. Separate hash-name evaluations allow 10,000 IR statements
each. No host API or system call executes. The bundled list for separate hash
functions is in `src/api_hashes/exports.txt`.

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
the same JSON array. The fixtures include ROR13, djb2, FNV-1a, seeded and UTF-16
FNV-1a, CRC32, a custom hash, collisions, unknown hashes, PE export directories,
PEB resolver walks, inlined hashes, and ELF dynamic symbols.
They are compiled as position-independent code for x86-64, i386 and AArch64.

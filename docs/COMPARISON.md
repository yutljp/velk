# Comparing program versions

English | [日本語](COMPARISON.ja.md)

Compare two binaries of the same program:

```sh
velk --compare first.elf second.elf
velk --compare first.elf second.elf --carry-annotations
velk --compare first.elf second.elf --project first.json --other-project second.json
```

The result is JSON. `changed` comes first, followed by `identical`, `onlyFirst`,
`onlySecond`, `failures` and `transfer`. Each matched pair contains the function
addresses and names, the matching `rule`, a `similarity` score between zero and
one, and `cDiff` and `blockDiff` strings. The differences use one replacement hunk
with removed lines prefixed by `-` and added lines by `+`. Blocks are the optimized
IR, with their addresses and statements. Empty differences mean equal text.
`identical` requires equal machine bytes and equal printed C on the same
architecture. Relocations or names can therefore put a function in `changed`.
This is a review aid, not a proof of equivalent behavior. Analysis failures are
reported with the binary side and function address; they never imply equality.

Matching tries these rules in order:

1. `name`: an exact name or alias, including demangled symbol and debug names,
   identifies exactly one unmatched function on each side. Project renames do
   not supply matching evidence.
2. `shape`: on the same architecture, the existing function shape hash agrees,
   as do numeric constants, referenced strings and the number of callees.
   The candidate must be unique on both sides. Equal shape hashes alone are
   insufficient because the hash ignores immediate values.
3. `references`: referenced strings, numeric constants greater than 16 and
   already matched callers and callees provide shared evidence. At least two
   features must agree, including a string or two graph neighbours. Their set overlap
   must be at least 0.55, and alternatives on either side must score at least
   0.15 lower. Newly matched neighbours can establish further matches.

For `name` and `shape`, similarity is 1 for the matching evidence; it does not
mean the function bodies are identical. For `references`, it is the number of
shared features divided by the number of distinct features. Ambiguous functions
remain unmatched. An inlined or removed function can appear only in the first
binary; an added function can appear only in the second. Shared names are the
only matching rule used across architectures.

`--carry-annotations` reads the first project and atomically updates the second.
It copies function names and function-entry comments to matching functions.
Signatures and variable annotations require the same architecture and equal
inferred calling conventions, parameter storage and types. Local annotations
also require identical function bytes. Variable targets must exist on both sides. Definition origins are mapped by
block position. Instruction comments are copied by byte offset only for identical
function bytes on the same architecture. Code/data classifications are skipped.
Declarations are copied by declaration name. Conflicting destination
declarations prevent copying types that could acquire a different meaning.

Globals are matched by their read, write and address-reference locations in
matched functions with equal shapes and constants. The complete sets of
function, block, statement and reference-kind positions must agree uniquely
in both directions. These are heuristic matches: review global types when the
program's data layout changes. Every existing destination annotation target is
preserved, even if it contains only a name and the source also has a type.
Names already used at the destination are skipped.
`transfer.copied` and `transfer.skipped` list source and destination targets and
reasons. Repeating a transfer copies nothing already present. Transferring to
the same binary or project file is rejected.

The JavaScript API and MCP use the same comparison and transfer code:

```js
const first = velk.open("first.elf", { project: "first.json" });
const second = velk.open("second.elf", { project: "second.json" });
const result = first.compare(second, { carryAnnotations: true });
result.changed.map(pair => ({ name: pair.first.name, rule: pair.rule, diff: pair.cDiff }));
```

Pass that script to `velk_run_script` over MCP. Comparison analyzes every
discovered function; allow a suitable `timeout_ms` and return a slice of the
result to stay within `max_output_chars`. Deadlines are checked during analysis
and before the project update is written. A filesystem write already in progress
finishes atomically even if the script's time budget expires.

The fixtures in `tests/comparison/fixtures` contain two C versions, built for
x86-64 and AArch64 with debug information and with all symbols stripped.
`sh tests/comparison/fixtures/build.sh` rebuilds them with Clang, LLD and
`llvm-strip`. `cargo test --release --test comparison -- --test-threads 3 --nocapture`
checks each returned match against the debug names and prints precision and
recall. It also checks changed C, block differences, ambiguous functions,
inlining, additions, removals and annotation transfer through Rust, CLI,
JavaScript and MCP.

These fixtures have ten expected function pairs per comparison. Both debug
comparisons find 10/10 pairs; both stripped comparisons find 7/10, with no wrong
matches in any of the four cases (34/34 precision, 34/40 recall overall).
`renamed_before` matches `renamed_after` by shape, and the edited
`route_before` matches `route_after` by references. In stripped binaries,
`edited` and the two indistinguishable `ambiguous_*` functions stay unmatched.

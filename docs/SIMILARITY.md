# Function similarity

```sh
velk --similar pair_sum tests/fixtures/arm64.o --in tests/fixtures/arm64_macho.o --limit 5 --json
velk --similar pair_sum tests/fixtures/arm64.o --limit 3
```

```js
const b = velk.open("tests/fixtures/arm64.o", {cache: false});
const other = velk.open("tests/fixtures/arm64_macho.o", {cache: false});
b.getFunction("pair_sum").similar({in: other, limit: 5});
```

MCP's `velk_run_script` accepts the same JavaScript. Omit `in` / `--in` to
search the source binary, excluding the query's address. Explicitly supplying
the source binary includes that address. The default limit is 10; zero returns
no candidates. JSON and JavaScript return `{matches, failures}`. Each match
contains the candidate `function`, `score`, and six `evidence` entries. Text
output prints the same feature scores and shared tokens. Addresses are strings
in JSON, preserving all 64 bits.

## Score

For each feature, compute multiset Jaccard overlap: sum of the minimum token
counts divided by sum of the maximum counts. Two empty bags contribute zero.
The score is the sum of these overlaps multiplied by fixed weights:

| Feature | Weight | Tokens |
| --- | ---: | --- |
| CFG | 0.15 | Block count, edge count, natural loop header count, histogram of incoming/outgoing degree pairs |
| Calls | 0.20 | Set of resolved, demangled call target names |
| Constants | 0.25 | Set of IR constants that are outside loaded sections |
| Strings | 0.20 | Set of referenced string text from the navigation index |
| Operations | 0.15 | Multiset of IR statement kinds, binary operators, applied operations, loads, extensions and selects |
| Prototype | 0.05 | One token containing the recovered return type, ordered parameter types and variadic status |

CFG edges include exception edges. A natural loop header is a target of an
edge that dominates its source. Block addresses and register identifiers do
not appear in the CFG or operation tokens. Prototype parameter names and
calling conventions are omitted. Function names are not a matching feature;
names of called functions are. The prototype comes from analysis, without
project type overrides. String decoding during decompilation does not add
features to this index.

The range is [0, 1]. Missing calls or strings do not earn agreement or increase
the other weights, so even identical leaf functions may score below 1.
Evidence gives each weight, overlap and up to sixteen shared tokens in lexical
order. All tokens still contribute to the score. Results sort by descending
score, then ascending candidate address. There is no minimum score cutoff.

These are search suggestions, not proofs of equivalent behavior, source
identity, or security properties. Small unrelated functions can share a shape
and prototype. Optimization, inlining, vectorization, unresolved calls,
stripped names and imperfect type inference can change the ranking. A low
score does not prove different behavior. Compare the C and instructions before
using a result to guide an edit.

## Index and library

`Binary::similar(addr, limit, deadline)` searches locally.
`similar::search(&mut source, addr, &mut destination, limit, deadline)` searches
another binary. For repeated queries, obtain `Binary::similarity_index`, copy
a query with `Index::features`, and call `Index::search`.

The first request builds a feature index once per open binary, reusing the
service's analysis cache and navigation index. Later searches perform no
lifting. Feature indexes stay in the session; they are not persisted in the
sidecar cache. Project changes and signature changes invalidate them. Interrupted
builds are discarded. Functions that fail analysis are omitted and reported
with their addresses; failure to analyze the source function is an error.
Indexing large binaries can exceed the default MCP time budget; raise
`timeout_ms` when necessary. Search deadlines are also checked on cached indexes.

## Checks

`tests/similar.rs` measures hit rates at ranks one and five over all directed
pairs of variants for each C source in `tests/fixtures/metrics` and
`tests/fixtures/arm32`, using function symbols as ground truth and excluding
stripped duplicate files. This includes optimization, architecture and format
changes. Only names present and successfully analyzed on both sides count as
queries. The test prints the pair count and the numerator and denominator of
each hit rate. It also compiles the loop source with `clang` and `cc`, at `-O0`
and `-O2`, and evaluates all directed variant pairs. Compiler version lines
are printed: `cc` may name the same compiler as `clang` on some systems.

Tests check deterministic ordering, bounds, unrelated operations, address
normalization, a 5,000-candidate index and agreement between the library, CLI,
JavaScript and MCP. Fixture commands and scripts above run in the documentation
tests. No rewrite of computed C is involved, so no SMT rewrite rule is added.

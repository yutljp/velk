# Recovered structures

[日本語](STRUCTURES.ja.md)

Without debug information, fixed offsets and access widths can describe memory access views.
Indexed accesses and pointer steps can establish an access stride. A stride does not prove the original array element size. Direct
pointer copies, calls, returns and shared static addresses connect layouts across
functions. Two connected functions can contribute different fields, including
single indexed fields. Conflicting widths, overlaps, alignments or strides prevent
sharing. Unknown indirect calls do not connect layouts.

Recovered fields describe memory accesses, not necessarily the source's declared
fields or signedness. Overlapping accesses can be printed as union views when they
fit one aligned cell; this does not establish that the source declared a union.
Unused fields, nested source types and unobserved trailing bytes are not inferred.
Generated members use unsigned integer storage unless a load explicitly extends
the sign. This is an access type, not a claim about the source declaration.
Interior loop pointers are expressed relative to the start of the generated
element, so matching loads and stores can use field syntax. Partial register
reads or writes, or a local value read before its definition, prevent this transformation.
Generated fields use their hexadecimal byte offset as a short name, such as `f_c`.
Generated structure tags describe the complete access layout and stride, rather
than a guessed source class name. Identical declarations are shared in the C
prelude; different partial layouts keep distinct tags.
The existing recovery of pointer layouts uses 64-bit register values.

The CLI's `--card` output and JavaScript's `f.card()` include `structureLayouts`
when an inferred structure exists. MCP exposes the same data through
`velk_run_script`. Each layout contains:

- `name`: the generated C structure tag.
- `elementSize`: the observed array stride in bytes, or `null` when unknown.
- `minimumSize`: the end of the last observed field in bytes, without trailing padding.
- `fields`: access views with hexadecimal byte `offset`, C `type` and byte `size`.
- `sourceFields`: original declared members, currently `null` for inferred layouts.
- `sourceSize`: original declared size, currently `null` for inferred layouts.

`structures` continues to contain C declarations. Debug-information declarations
are separate from these inferred layouts.

```sh
velk --card tests/fixtures/metrics/struct_arrays.x86_64.O2.stripped.elf 0x201180
```

```js
const b = velk.open("tests/fixtures/metrics/struct_arrays.x86_64.O2.stripped.elf");
JSON.stringify(b.getFunction("0x201180").card().structureLayouts)
```

`tests/metrics.rs` compares stripped structure fixtures with their paired DWARF
fixtures. `tests/golden/structure_accuracy.txt` records correct, wrong and missed
field offsets, widths, types and element sizes for each configuration. It measures
direct non-bit-field members of structure pointer parameters; nested aggregates
are not flattened, and source unions and by-value aggregates are not scored.
A missing layout or unknown stride counts as missed. An extra inferred field
counts as wrong. Signedness differences count as wrong types even when the access
width is correct. These access comparisons are retained, including every
disagreement by function and offset; changing the generated storage type does
not prove a source type. Separate source metrics measure only `sourceFields`
and `sourceSize`: unknown declarations count as missed, not correct.

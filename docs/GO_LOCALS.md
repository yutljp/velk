# Go local storage

`tests/scripts/local_usage.py` classifies declarations in complete CLI output. The table
below covers `go_probe`, `go_stripped`, `go_probe_arm64`, and
`go_stripped_arm64`: 5,112 functions, including their runtimes. The screen finds
57,444 declarations. Its syntactic counts include register bindings and anonymous
result storage, so they differ from the named-variable readability counters.
These categories describe printed definitions, not recovered Go source variables.

| Definition or storage | Count | Example in `go_probe` |
| --- | ---: | --- |
| Multiple definitions or no recognized definition | 14,206 | `internal/abi.Name.IsBlank`: `v1` |
| Other computed value | 13,941 | `internal/abi.Kind.String`: `v1` |
| Memory read | 11,236 | `internal/abi.Kind.String`: `v4` |
| Stack slot or object | 9,578 | `internal/abi.(*Kind).String`: `local_0` |
| Call expression | 4,992 | `type:.eq.internal/abi.RegArgs`: `v1` |
| Array, aggregate, or operand following `&` | 1,276 | `internal/cpu.doinit`: `call_values` |
| Same-type register copy | 946 | `internal/cpu.processOptions`: `v56` |
| Constant | 863 | `runtime.printpanicval`: `v5` |
| Repeated copy from the same local | 308 | `runtime.chansend`: `v51` |
| Known string, slice, or interface header | 98 | `runtime.typeBitsBulkBarrier`: `string` |

The `&` category is conservative and can include bitwise operands. A copy's
source may change before a later read; the syntactic copy counts are not counts
of removable variables. Stack slots can hold spills, results, loop state, or
objects whose addresses escape. The screen does not distinguish those histories.

To reproduce the classification after a release build:

```sh
for fixture in go_probe go_stripped go_probe_arm64 go_stripped_arm64; do
    target/release/velk -D "tests/fixtures/$fixture" '*' > "target/$fixture.c"
done
uv run python tests/scripts/local_usage.py target/go_probe.c target/go_stripped.c \
    target/go_probe_arm64.c target/go_stripped_arm64.c
```

Saved parameters use their original C parameter when every alias holds that
entry value. An unused result binding in an argument register does not prevent
this substitution. Liveness retains any result that a successor can read;
declared result bindings and unmodeled control flow retain their bindings.
For example, `runtime.convT` passes `a1` to `runtime_typedmemmove` without a
separate stack copy.

Structured copies disappear only when every definition copies the same source
and that source is unchanged at every read, with matching printed types.
Read widths remain unchanged. A copy whose source is another removable copy is
retained, so simultaneous substitutions cannot extend that source's lifetime.
Call argument bindings retain their copies.
The renderer accepts a candidate only when casts, lines, and gotos do not increase.

The execution regressions in `tests/recompile/go_locals.rs` compile the printed C
and check snapshots, pointer parameters, source overwrites, and dependent copy chains. Unit tests also
check read widths and copy availability through branches and loops. Control-flow
and ABI rules remain outside the symbolic equivalence model, as recorded in
`tests/smt_inventory.tsv`.

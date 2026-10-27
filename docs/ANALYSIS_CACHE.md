# Saved analysis

English | [日本語](ANALYSIS_CACHE.ja.md)

Opening a binary saves discovered functions and boundaries, library signature
matches, exception information, and completed call summaries. A completed
navigation index is saved after its first query. These results are reused by a
later process; function C is still rendered on request. The navigation index is
read only when a query needs it.

The default file is `<binary>.velk-cache`, beside the canonical binary,
separate from the `<binary>.velk.json` annotation project. You can delete the
cache at any time. Annotations stay in the project file.

Choose a different file or disable both reading and writing:

```sh
velk --functions app.elf --cache analysis.json
velk --functions app.elf --cache off
VELK_CACHE=analysis.json velk --functions app.elf
VELK_CACHE=off velk --functions app.elf
```

The CLI option takes precedence over `VELK_CACHE`. JavaScript and MCP scripts
use the same open option, which also takes precedence over that variable:

```js
const b = velk.open("app.elf", {cache: "analysis.json"});
b.getFunction("main").decompile();
const uncached = velk.open("app.elf", {cache: false});
uncached.getFunction("main").decompile();
```

Omitting `cache` uses the environment variable or default location. `cache: true`
selects the default location. MCP's `velk_run_script` accepts these scripts.

A cache is reused only when the binary contents, velk version and build, cache
format, architecture and raw mapping, signature options and database contents,
external PDB contents, and project annotations match. All project changes
invalidate the cache, including comments. A damaged, incomplete, or mismatched
cache is ignored and rebuilt without a diagnostic. Cache reads are limited to
256 MiB. Writes use a separate file and an atomic rename, so simultaneous
processes see complete files. A failed write reports one diagnostic per opened
binary and leaves analysis available. Cache paths cannot replace the binary,
project, or selected signature databases.

Queries can add summaries and a navigation index to the saved results when the
binary handle is released. Explicit signature identification through a handle
stops further cache writes for that handle, since it changes its analysis options.

To measure opening and the first C and cross-reference queries in two separate
processes, run `uv run tools/measure_analysis_cache.py --library LIBRARY` after
`cargo build --release`. The script prints elapsed times and cache sizes. It uses
the two largest Rust fixtures and the largest Go fixture, plus the supplied
system library. Use `--binary` to select another velk executable.

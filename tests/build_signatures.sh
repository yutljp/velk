#!/bin/sh
# Build databases from Rust rlibs, optional static archives, and Go runtime fixtures.
set -eu
cd "$(dirname "$0")/.."
BIN=${BIN:-target/release/velk}
OUT=tests/out/signatures
mkdir -p "$OUT"
rustc -Vv > "$OUT/toolchain.txt"
for library in "$(rustc --print target-libdir)"/lib*.rlib; do
    [ -f "$library" ] || continue
    name=$(basename "$library")
    "$BIN" --build-signatures "$library" --output "$OUT/$name.json"
    (cd "$(dirname "$library")" && shasum -a 256 "$name") >> "$OUT/toolchain.txt"
done
for library in "$@"; do
    name=$(basename "$library")
    "$BIN" --build-signatures "$library" --output "$OUT/$name.json"
    (cd "$(dirname "$library")" && shasum -a 256 "$name") >> "$OUT/toolchain.txt"
done
for fixture in go_probe go_probe_arm64; do
    "$BIN" --build-signatures "tests/fixtures/$fixture" --output "$OUT/$fixture.json"
    shasum -a 256 "tests/fixtures/$fixture" >> "$OUT/toolchain.txt"
done
uv run --no-project python - "$OUT" <<'PY'
import json
from pathlib import Path
import sys
out = Path(sys.argv[1])
databases = [json.loads(path.read_text()) for path in sorted(list(out.glob("*.rlib.json")) + list(out.glob("*.a.json")))]
combined = {
    "version": 3,
    "entries": [entry for db in databases for entry in db["entries"]],
    "sources": [source for db in databases for source in db["sources"]],
}
(out / "libraries.json").write_text(json.dumps(combined, separators=(",", ":")) + "\n")
PY
"$BIN" -r tests/signature_sources.js > "$OUT/matches.json"

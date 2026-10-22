#!/usr/bin/env bash
# Performance regression: time the main commands and fail if an average exceeds its limit
set -euo pipefail
cd "$(dirname "$0")/.."
FIX=tests/fixtures
BIG=tests/out/arm64_big.o

# A 20 MB input for the loader: a real object followed by zero padding.
mkdir -p tests/out
if [ ! -f "$BIG" ] || [ "$FIX/arm64.o" -nt "$BIG" ]; then
  { cat "$FIX/arm64.o"; head -c 20971520 /dev/zero; } > "$BIG"
fi
cargo build --release --quiet

ITER=${ITER:-50}

uv run python - "${CARGO_TARGET_DIR:-$PWD/target}/release/velk" "$ITER" "$PWD/$FIX" "$PWD/$BIG" <<'PY'
import subprocess
import sys
import time

binary = sys.argv[1]
iterations = int(sys.argv[2])
fix = sys.argv[3]
big = sys.argv[4]

cases = [
    ("functions (small)", [binary, "--functions", f"{fix}/pe64.exe"], 120.0),
    ("ir (aarch64)", [binary, "--ir", f"{fix}/arm64.o", "helper"], 120.0),
    ("decompile (aarch64)", [binary, "--decompile", f"{fix}/arm64.o", "helper"], 120.0),
    ("functions (20 MB)", [binary, "--functions", big], 300.0),
    ("build-signatures (aarch64)", [binary, "--build-signatures", f"{fix}/arm64.o", "--output", "tests/out/bench-sigs.json"], 120.0),
]

failed = False
for name, command, limit in cases:
    # The first run of a fresh binary pays one-time costs, so it is not timed.
    subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    started = time.perf_counter()
    for _ in range(iterations):
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    average = (time.perf_counter() - started) / iterations * 1000.0
    status = "ok" if average <= limit else "SLOW"
    if average > limit:
        failed = True
    print(f"{status}: {name}: {average:.2f} ms avg (limit {limit:.0f} ms)")

sys.exit(1 if failed else 0)
PY

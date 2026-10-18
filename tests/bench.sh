#!/usr/bin/env bash
# 性能回帰: 主要コマンドの平均実行時間を計測し、しきい値を超えたら失敗する
set -euo pipefail
cd "$(dirname "$0")/.."

./tests/make_fixtures.sh >/dev/null
cargo build --release --quiet

ITER=${ITER:-50}

python3 - "$PWD/target/release/velk" "$ITER" <<'PY'
import subprocess
import sys
import time

binary = sys.argv[1]
iterations = int(sys.argv[2])

cases = [
    ("inspect (small)", [binary, "inspect", "tests/out/pe64.exe"], 120.0),
    ("lift (aarch64)", [binary, "lift", "tests/out/arm64.o", "--name", "helper"], 120.0),
    ("decompile (aarch64)", [binary, "decompile", "tests/out/arm64.o", "--name", "helper"], 120.0),
    ("inspect (20 MB)", [binary, "inspect", "tests/out/arm64_big.o"], 300.0),
    ("siggen (aarch64)", [binary, "siggen", "tests/out/arm64.o", "--output", "/tmp/velk-bench-sigs.json"], 120.0),
]

failed = False
for name, command, limit in cases:
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

"""Regenerate fixture seeds and run coverage-guided fuzzing until a quiet interval."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
TARGETS = ("elf", "pe", "macho", "functions", "decompile", "script_request", "mcp_request")
MAGICS = {
    b"\x7fELF": "elf",
    b"MZ": "pe",
    b"\xcf\xfa\xed\xfe": "macho",
    b"\xce\xfa\xed\xfe": "macho",
    b"\xfe\xed\xfa\xcf": "macho",
    b"\xfe\xed\xfa\xce": "macho",
    b"\xca\xfe\xba\xbe": "macho",
}


def seed():
    for target in TARGETS:
        (ROOT / "fuzz/corpus" / target).mkdir(parents=True, exist_ok=True)
    count = 0
    for path in sorted((ROOT / "tests/fixtures").rglob("*")):
        if not path.is_file() or path.stat().st_size > 65536:
            continue
        data = path.read_bytes()
        kind = next((kind for magic, kind in MAGICS.items() if data.startswith(magic)), None)
        if kind is None:
            continue
        digest = hashlib.sha256(data).hexdigest()
        for target in (kind, "functions", "decompile"):
            (ROOT / "fuzz/corpus" / target / digest).write_bytes(data)
        count += 1
    # Each variant enters the real serde request decoder; no supplied script is executed.
    requests = {
        "script_request": [
            b'{"op":"open","path":"binary","arch":"arm64e"}',
            b'{"op":"functions","bin":"binary"}',
            b'{"op":"decompile","bin":{"path":"binary","arch":"x86_64"},"addr":"0x0"}',
            b'{"op":"navigate","bin":"binary","query":{}}',
        ],
        "mcp_request": [
            b'{"id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}',
            b'{"id":1,"method":"tools/list"}',
            b'{"id":1,"method":"tools/call","params":{"name":"velk_read_api","arguments":{"topic":"binary"}}}',
            b'{"id":1,"method":"tools/call","params":{"name":"velk_run_script","arguments":{"code":"","timeout_ms":1,"max_output_chars":256}}}',
            b'{"id":1,"method":"tools/call","params":{"name":"velk_classes","arguments":{}}}',
        ],
    }
    for target, values in requests.items():
        for data in values:
            (ROOT / "fuzz/corpus" / target / hashlib.sha256(data).hexdigest()).write_bytes(data)
    print(f"Seeded {count} binary fixtures (at most 65536 bytes each).", flush=True)


def run(target, args):
    directory = ROOT / "target/verification/fuzz" / target
    directory.mkdir(parents=True, exist_ok=True)
    previous = None
    stable_seconds = 0.0
    for number in range(args.rounds):
        log = directory / f"{number}.log"
        command = [
            "cargo", "+nightly", "fuzz", "run", "--target-dir", "target/fuzz", target,
            "--", f"-max_total_time={args.seconds}", "-max_len=65536", "-timeout=10",
            "-rss_limit_mb=2048", "-print_final_stats=1",
        ]
        started = time.monotonic()
        with log.open("w") as output:
            result = subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, check=False)
        elapsed = time.monotonic() - started
        output = log.read_text(errors="replace")
        if result.returncode:
            print(f"{target}: failed ({result.returncode}); {log.relative_to(ROOT)}", flush=True)
            return False
        coverage = re.findall(r"cov: (\d+) ft: (\d+)", output)
        if not coverage:
            print(f"{target}: no coverage counters; {log.relative_to(ROOT)}", flush=True)
            return False
        duration = re.search(r"Done \d+ runs in (\d+) second", output)
        if duration is None:
            print(f"{target}: no execution duration; {log.relative_to(ROOT)}", flush=True)
            return False
        fuzz_seconds = int(duration[1])
        current = tuple(map(int, coverage[-1]))
        stable_seconds = stable_seconds + fuzz_seconds if current == previous else 0.0
        print(f"{target}: round={number + 1} wall_seconds={elapsed:.1f} fuzz_seconds={fuzz_seconds} cov={current[0]} ft={current[1]} quiet={stable_seconds:.1f}", flush=True)
        if stable_seconds >= args.quiet:
            result = subprocess.run([
                "cargo", "+nightly", "fuzz", "cmin", "--target-dir", "target/fuzz", target,
            ], cwd=ROOT, check=False)
            return result.returncode == 0
        previous = current
    print(f"{target}: no plateau within {args.rounds} rounds", flush=True)
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("targets", choices=TARGETS, nargs="*")
    parser.add_argument("--seed-only", action="store_true")
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--quiet", type=int, default=120)
    parser.add_argument("--rounds", type=int, default=20)
    args = parser.parse_args()
    if min(args.seconds, args.quiet, args.rounds) <= 0:
        parser.error("time limits and round counts must be positive")
    os.environ.setdefault("CARGO_BUILD_JOBS", "5")
    os.environ.setdefault("CARGO_PROFILE_RELEASE_INCREMENTAL", "true")
    seed()
    if args.seed_only:
        return 0
    directory = ROOT / "target/verification/fuzz"
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / "build.log").open("w") as output:
        result = subprocess.run([
            "cargo", "+nightly", "fuzz", "build", "--target-dir", "target/fuzz",
        ], cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, check=False)
    if result.returncode:
        print("Fuzz build failed; see target/verification/fuzz/build.log", flush=True)
        return 1
    success = True
    for target in args.targets or TARGETS:
        success = run(target, args) and success
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Measure whole-binary CLI wall time, CPU time and peak RSS on macOS or Linux."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time


CASES = ["go_probe", "go_probe_arm64", "rust_probe", "com_x86_64.dll"]


def measure(binary, fixture):
    # wait4 reports resource use for this child, rather than a cumulative peak.
    with tempfile.TemporaryFile(dir="target") as output:
        started = time.perf_counter()
        child = subprocess.Popen(
            [binary, "--decompile", "--cache", "off", str(fixture), "*"], stdout=output
        )
        _, status, usage = os.wait4(child.pid, 0)
        wall = time.perf_counter() - started
        child.returncode = os.waitstatus_to_exitcode(status)
        if child.returncode:
            raise RuntimeError(f"{binary}: {fixture}: exit {child.returncode}")
        output.seek(0)
        digest = hashlib.file_digest(output, "sha256").hexdigest()
    return {
        "wall_seconds": wall,
        "cpu_seconds": usage.ru_utime + usage.ru_stime,
        "peak_bytes": usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024),
        "sha256": digest,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binaries", nargs="+", type=Path)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    binaries = [str(binary.resolve()) for binary in args.binaries]
    results = {}
    for name in CASES:
        samples = [[] for _ in binaries]
        digest = None
        for run in range(args.runs):
            for offset in range(len(binaries)):
                index = (run + offset) % len(binaries)
                while os.getloadavg()[0] > 2 * (os.cpu_count() or 1):
                    time.sleep(15)
                row = measure(binaries[index], Path("tests/fixtures") / name)
                if digest is not None and row["sha256"] != digest:
                    raise RuntimeError(f"Output differs: {name}: {binaries[index]}")
                digest = row["sha256"]
                samples[index].append(row)
        results[name] = [
            {
                "binary": binary,
                "runs": rows,
                "median": {
                    key: statistics.median(row[key] for row in rows)
                    for key in ["wall_seconds", "cpu_seconds", "peak_bytes"]
                },
            }
            for binary, rows in zip(binaries, samples)
        ]
        args.output.write_text(json.dumps(results, indent=2) + "\n")
        print(name + ": " + ", ".join(
            f"{Path(row['binary']).name}: {row['median']}" for row in results[name]
        ), flush=True)


if __name__ == "__main__":
    main()

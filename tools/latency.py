#!/usr/bin/env python3
"""Measure alternating single-function CLI runs on a machine with load below four."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import time


CASES = [
    ("rust", "rust_probe", "rust_probe::main"),
    ("go", "go_probe", "main.main"),
    ("c", "l2_loop_x64.o", "sum_while"),
    ("aarch64-rust", "rust_probe_arm64", "rust_probe::main"),
    ("pe", "pe64.exe", "reg_div"),
]


def wait_for_load():
    load = os.getloadavg()[0]
    while load >= 4:
        print(f"Waiting for load below 4: {load:.2f}", flush=True)
        time.sleep(15)
        load = os.getloadavg()[0]
    return load


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binaries", nargs="+", type=Path)
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--equal", nargs=2, type=int, metavar=("LEFT", "RIGHT"),
                        help="require identical output from two zero-based binary indices")
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    if args.equal and any(index < 0 or index >= len(args.binaries) for index in args.equal):
        parser.error("--equal indices must refer to supplied binaries")
    binaries = [str(binary.resolve()) for binary in args.binaries]
    binary_hashes = [hashlib.sha256(Path(binary).read_bytes()).hexdigest() for binary in binaries]
    results = {}
    for name, fixture, function in CASES:
        samples = [[] for _ in binaries]
        loads = [[] for _ in binaries]
        hashes = [None for _ in binaries]
        command = ["-D", str(Path("tests/fixtures") / fixture), function]
        for binary in binaries:
            wait_for_load()
            subprocess.run([binary, *command], check=True, stdout=subprocess.DEVNULL)
        for run in range(args.runs):
            # Rotate the first binary between rounds.
            for offset in range(len(binaries)):
                index = (run + offset) % len(binaries)
                load = wait_for_load()
                started = time.perf_counter_ns()
                result = subprocess.run([binaries[index], *command], check=True,
                                        stdout=subprocess.PIPE)
                samples[index].append((time.perf_counter_ns() - started) / 1e6)
                loads[index].append(load)
                digest = hashlib.sha256(result.stdout).hexdigest()
                if hashes[index] is not None and hashes[index] != digest:
                    raise RuntimeError(f"Unstable output: {name}, {binaries[index]}")
                hashes[index] = digest
            if args.equal and hashes[args.equal[0]] != hashes[args.equal[1]]:
                raise RuntimeError(f"Output differs: {name}")
        results[name] = [
            {"binary": binary, "binary_sha256": binary_hash, "milliseconds": values,
             "load_averages": load,
             "mean": statistics.mean(values),
             "median": statistics.median(values), "sha256": digest}
            for binary, binary_hash, values, load, digest in
            zip(binaries, binary_hashes, samples, loads, hashes)
        ]
        args.output.write_text(json.dumps(results, indent=2) + "\n")
        print(name + ": " + ", ".join(
            f"{Path(row['binary']).name}={row['median']:.3f} ms" for row in results[name]
        ), flush=True)


if __name__ == "__main__":
    main()

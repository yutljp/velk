#!/usr/bin/env python3
"""Measure two process opens and their first C and reference queries."""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import time


def measure(binary, library):
    fixtures = Path("tests/fixtures").resolve()
    cases = [
        (fixtures / "rust_probe", "rust_probe::main"),
        (fixtures / "rust_demo", "rust_demo::main"),
        (fixtures / "go_probe_arm64", "main.main"),
        (library.resolve(), "strlen"),
    ]
    output_directory = Path("target/cache-measurements")
    output_directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output_directory) as directory:
        directory = Path(directory)
        for index, (path, function) in enumerate(cases):
            cache = directory / f"{index}.json"
            script = directory / "query.js"
            script.write_text(
                f"const start = Date.now(); const b = velk.open({json.dumps(str(path))}, "
                f"{{cache:{json.dumps(str(cache))}}}); const opened = Date.now(); "
                f"const f = b.getFunction({json.dumps(function)}); f.decompile(); "
                "const decompiled = Date.now(); f.xrefs(); const indexed = Date.now(); "
                "({open_ms:opened-start, decompile_ms:decompiled-opened, "
                "xref_ms:indexed-decompiled});\n"
            )
            for attempt in [1, 2]:
                start = time.perf_counter()
                result = subprocess.run(
                    [str(binary), "--run", str(script)],
                    check=True, capture_output=True, text=True,
                )
                elapsed = time.perf_counter() - start
                measurements = json.loads(result.stdout)
                print(json.dumps({
                    "input": path.name, "open": attempt, **measurements,
                    "process_ms": round(elapsed * 1000, 1),
                    "input_bytes": path.stat().st_size,
                    "cache_bytes": cache.stat().st_size,
                }), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/release/velk"))
    parser.add_argument("--library", type=Path, required=True)
    arguments = parser.parse_args()
    measure(arguments.binary, arguments.library)

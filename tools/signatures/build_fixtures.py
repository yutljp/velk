#!/usr/bin/env -S uv run --no-project python
"""Rebuild embedded sets and stripped, statically linked measurement fixtures."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True

import gzip_output

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "target" / "library-signatures"
SOURCES = OUT / "sources"
TARGETS = {
    "x86_64": ["--target=x86_64-linux-gnu"],
    "aarch64": ["--target=aarch64-linux-gnu"],
    "i386": ["--target=i386-linux-gnu"],
    "arm32": ["--target=armv7-linux-gnueabihf", "-marm"],
}


def run(*args):
    subprocess.run(args, cwd=ROOT, check=True)


def main():
    import fetch_sources
    fetch_sources.main()
    OUT.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((ROOT / "tools" / "signatures" / "sources.json").read_text())
    for name, expected in manifest["sha256"].items():
        actual = hashlib.sha256((SOURCES / name).read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(f"source checksum mismatch: {name}")
    version = subprocess.check_output(["clang", "--version"], text=True).splitlines()[0]
    if version != manifest["compiler"]:
        raise SystemExit(f"requires {manifest['compiler']}; found {version}")
    for tool, expected in manifest["tools"].items():
        actual = subprocess.check_output([tool, "--version"], text=True).strip()
        if actual != expected:
            raise SystemExit(f"requires {tool}: {expected}; found {actual}")
    database = {"version": 3, "entries": [], "sources": []}
    for arch, target in TARGETS.items():
        for level in ("O0", "O1", "O2", "O3", "Os"):
            common = ["clang", *target, f"-{level}", "-fno-stack-protector",
                      "-fno-pic", "-fno-pie", "-ffreestanding", "-funwind-tables",
                      "-I", str(ROOT / "tools/signatures/include")]
            for library, source, defines in (
                ("zlib", "adler32.c", ["-DZ_SOLO"] + (["-DNO_DIVIDE"] if arch in ("i386", "arm32") else [])),
                ("xxhash", "xxhash.c", ["-DXXH_NO_STREAM", "-DXXH_NO_XXH3"]),
            ):
                stem = f"{library}.{arch}.{level}"
                obj = OUT / f"{stem}.o"
                run(*common, *defines, "-c", str(SOURCES / library / source), "-o", str(obj))
                path = OUT / f"{stem}.json"
                run("target/release/velk", "--build-signatures", str(obj), "--output", str(path))
                built = json.loads(path.read_text())
                for entry in built["entries"]:
                    entry["set"] = f"{library}-{manifest['versions'][library]}-{arch}-{level}-clang21"
                database["entries"].extend(built["entries"])
                database["sources"].append(stem)
                wrapper = OUT / f"{stem}.c"
                if library == "zlib":
                    declarations = '#define Z_SOLO\n#include "zlib.h"\nuLong adler32_combine64(uLong, uLong, z_off64_t);\n'
                    expression = "adler32_z(1, data, 64) + adler32(1, data, 64) + adler32_combine(1, 2, 32) + adler32_combine64(1, 2, 32)"
                else:
                    declarations = '#define XXH_NO_STREAM\n#define XXH_NO_XXH3\n#include "xxhash.h"\n'
                    expression = "XXH32(data, 64, 3) + XXH64(data, 64, 5)"
                entry_attribute = "__attribute__((force_align_arg_pointer)) " if arch in ("x86_64", "i386") else ""
                wrapper.write_text(declarations + "unsigned char data[64];\nvolatile unsigned long result;\n"
                    "void *memcpy(void *d, const void *s, __SIZE_TYPE__ n) { unsigned char *a=d; const unsigned char *b=s; for (__SIZE_TYPE__ i=0;i<n;i++) a[i]=b[i]; return d; }\n"
                    + entry_attribute + "void _start(void) { result = " + expression + "; for (;;) {} }\n")
                executable = OUT / f"{stem}.elf"
                run(*common, "-I", str(SOURCES / library), "-nostdlib", "-static",
                    "-fuse-ld=lld", "-Wl,-e,_start", "-Wl,--build-id=none",
                    str(wrapper), str(obj), "-o", str(executable))
                run("llvm-strip", "--strip-all", str(executable), "-o", str(OUT / f"{stem}.stripped.elf"))
    fixture_dir = OUT / "fixtures"
    fixture_dir.mkdir(parents=True, exist_ok=True)
    for path in sorted(OUT.glob("*.elf")):
        (fixture_dir / (path.name + ".gz")).write_bytes(gzip_output.compress(path.read_bytes()))
    # Keep each variant's set provenance.
    database["entries"].sort(key=lambda entry: (entry["set"], entry["name"]))
    encoded = json.dumps(database, separators=(",", ":"), sort_keys=True).encode()
    (OUT / "base.json.gz").write_bytes(gzip_output.compress(encoded))
    print(f"{len(database['entries'])} entries, {len(encoded)} JSON bytes")
    import build_libraries
    build_libraries.main()


if __name__ == "__main__":
    main()

"""Prepare decompiled functions for a semantic review by an LLM.

For each function whose pseudo-C changed in tests/golden/fixtures since a git
revision (or every function with --all), write its C source next to the old and
new pseudo-C into tests/out/review.md. Functions already judged with the same
source and output, per tests/review/verdicts.tsv, are left out.

usage: uv run tests/review.py [REVISION] [--all]
"""

import hashlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GOLDEN = ROOT / "tests/golden/fixtures"
CASES = ROOT / "tests/cases"
VERDICTS = ROOT / "tests/review/verdicts.tsv"
OUTPUT = ROOT / "tests/out/review.md"


def decompiled(text):
    """Pseudo-C per function name in a golden file."""
    functions = {}
    for block in text.split("\n== ")[1:]:
        header, _, body = block.partition("\n")
        name = header.split(" ", 1)[1] if " " in header else header
        match = re.search(r"-- decompile\n(.*?)(?=\n-- |\Z)", body, re.S)
        if match and name != "-":
            functions[name] = match.group(1).rstrip("\n")
    return functions


# The source each fixture is built from (see tests/make_fixtures.sh); Go and
# Rust executables are left out, since their functions are mostly the runtime.
FIXTURE_SOURCES = {
    "pe64.exe": "c/pe64.c",
    "pe64.obj": "c/pe64.c",
    "arm64.o": "c/arith_mixed.c",
    "arm64_macho.o": "c/arith_mixed.c",
    "arm64_debug.o": "c/arith_mixed.c",
    "arm64_debug.elf": "c/arith_mixed.c",
    "arm64_debug_stripped.elf": "c/arith_mixed.c",
    "arm64_div.o": "c/divmod_a64.c",
    "alt.o": "c/alt_names.c",
    "x64_div.o": "c/divmod_x64.c",
    "x64_div_macho.o": "c/divmod_x64.c",
    "arm64_loops.o": "c/loops.c",
    "arm64_loops0.o": "c/loops.c",
    "x64_loops.o": "c/loops.c",
    "arm64_loops_stripped.o": "c/loops.c",
    "x64_loops_stripped.o": "c/loops.c",
    "strings.o": "c/strings.c",
    "arm64_linked.elf": "c/strings.c",
    "switch_value_table.o": "c/switch_value_table.c",
    "arm64_switch.elf": "c/switch_value_table.c",
    "switch_jumptable.o": "c/switch_jumptable.c",
    "switch_jumptable_x64.o": "c/switch_jumptable.c",
    "arm64_jumptable.elf": "c/switch_jumptable.c",
    "l5_switch.o": "c/l5_switch.c",
    "l5_switch.elf": "c/l5_switch.c",
    "cpp_demo.o": "cpp/namespace.cpp",
    "cpp_classes_a64.o": "cpp/classes.cpp",
    "cpp_classes_x64.o": "cpp/classes.cpp",
    "calls_a64.o": "c/calls.c",
    "calls_a64.elf": "c/calls.c",
}


def source_of(fixture):
    """The case source a fixture is built from, or None."""
    if fixture in FIXTURE_SOURCES:
        return CASES / FIXTURE_SOURCES[fixture]
    name = fixture.split("/")[-1]
    if fixture.startswith("metrics/"):
        return CASES / "c" / (name.split(".")[0] + ".c")
    for suffix in ("_stripped.o", "_a64.o", "_x64.o", ".o"):
        if name.endswith(suffix):
            path = CASES / "c" / (name[: -len(suffix)] + ".c")
            return path if path.exists() else None
    return None


def definitions(path):
    """Function definitions in one C or C++ file, by plain name."""
    found = {}
    definition = re.compile(r"^[A-Za-z_][\w \t\*&<>:,]*?\b([A-Za-z_]\w*)\s*\([^;{)]*\)[^;{]*\{", re.M)
    text = path.read_text()
    for match in definition.finditer(text):
        depth, end = 0, None
        for position in range(match.end() - 1, len(text)):
            depth += {"{": 1, "}": -1}.get(text[position], 0)
            if depth == 0:
                end = position + 1
                break
        if end is not None:
            found.setdefault(match.group(1), text[match.start():end])
    return found


def plain_name(name):
    name = name.split("(", 1)[0].split("::")[-1]
    return name.lstrip("_") if name.startswith("_") and name.lstrip("_") else name


def judged():
    if not VERDICTS.exists():
        return set()
    return {line.split("\t", 1)[0] for line in VERDICTS.read_text().splitlines() if line and not line.startswith("#")}


def main():
    arguments = [a for a in sys.argv[1:] if not a.startswith("--")]
    review_all = "--all" in sys.argv
    revision = arguments[0] if arguments else "HEAD"
    done = judged()
    missing = set()
    entries = []
    for path in sorted(GOLDEN.rglob("*.txt")):
        relative = path.relative_to(ROOT)
        new = decompiled(path.read_text())
        old_text = subprocess.run(
            ["git", "show", f"{revision}:{relative}"], cwd=ROOT, capture_output=True, text=True
        ).stdout
        old = decompiled(old_text)
        fixture = str(path.relative_to(GOLDEN))[: -len(".txt")]
        source_path = source_of(fixture)
        if source_path is None:
            if not fixture.startswith(("go_", "rust_")):
                missing.add(fixture)
            continue
        code = definitions(source_path)
        for name, text in new.items():
            if not review_all and old.get(name) == text:
                continue
            source = code.get(plain_name(name))
            if source is None:
                continue
            key = hashlib.sha256(f"{source}\n{text}".encode()).hexdigest()[:16]
            if key in done:
                continue
            entries.append((key, fixture, name, source_path.relative_to(ROOT), source, old.get(name), text))

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w") as out:
        out.write(
            "# Decompiler review\n\n"
            "For each entry, decide whether the pseudo-C means the same as the source, for every input\n"
            "the source defines. Ignore names, casts and formatting; report wrong conditions, operands,\n"
            "widths, signedness, missing or extra effects, and wrong control flow. Answer with one line\n"
            "per entry in tests/review/verdicts.tsv:\n\n"
            "    <key>\\t<fixture>\\t<function>\\t<same|different|unsure>\\t<reason>\n\n"
        )
        for key, fixture, name, source_path, source, old, new in entries:
            out.write(f"## {key} {fixture} {name}\n\nSource ({source_path}):\n\n```c\n{source}\n```\n\n")
            if old is not None and old != new:
                out.write(f"Previous pseudo-C:\n\n```c\n{old}\n```\n\n")
            out.write(f"Pseudo-C:\n\n```c\n{new}\n```\n\n")
    for fixture in sorted(missing):
        print(f"warning: no source known for {fixture}; add it to FIXTURE_SOURCES", file=sys.stderr)
    print(f"{len(entries)} functions to review in {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()

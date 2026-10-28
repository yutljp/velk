"""Dump and rank printed casts: uv run tools/classify_casts.py OUTPUT [--bin BIN].

The output directory contains C, diagnostics, one JSON record per cast, and counts.
Clang supplies source types when it can parse the expression; unresolved types
are explicitly recorded. Inputs are the fixtures listed in the cast golden.
"""

import argparse
import collections
import concurrent.futures
import json
import pathlib
import random
import re
import subprocess


TYPE = re.compile(
    r"\(\s*((?:(?:const|volatile)\s+)*(?:[A-Za-z_][A-Za-z_0-9]*_t|"
    r"struct\s+[A-Za-z_][A-Za-z_0-9]*|unsigned\s+(?:long long|long|int|short)|"
    r"long long|float|double|bool|char|int|long|short|FILE|void)\s*\**)\s*\)"
)


def measure(fixture, binary, output):
    result = subprocess.run(
        [binary, "--cache", "off", "-D", str(pathlib.Path("tests/fixtures") / fixture), "*"],
        capture_output=True, text=True, check=True,
    )
    source = output / (fixture + ".c")
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(result.stdout)
    ast = subprocess.run(
        ["clang", "-x", "c", "-fsyntax-only", "-ferror-limit=0", "-Xclang",
         "-ast-dump=json", str(source)], capture_output=True, text=True,
    )
    source.with_suffix(".diagnostics.txt").write_text(ast.stderr)
    types = {}

    def visit(node):
        if node.get("kind") == "CStyleCastExpr":
            offset = node.get("range", {}).get("begin", {}).get("offset")
            children = node.get("inner", [])
            if children:
                ty = children[0].get("type", {})
                types[offset] = ty.get("qualType", "unresolved")
        for child in node.get("inner", []):
            visit(child)

    if ast.stdout:
        visit(json.loads(ast.stdout))
    records = []
    for match in TYPE.finditer(result.stdout):
        target = match[1].strip()
        if target == "void":
            continue
        start = result.stdout.rfind("\n", 0, match.start()) + 1
        end = result.stdout.find("\n", match.end())
        line = result.stdout[start:end if end >= 0 else None].strip()
        following = result.stdout[match.end():].lstrip()
        preceding = result.stdout[start:match.start()].rstrip()
        if target.endswith("*"):
            group = "memory pointer" if preceding.endswith("*") else "other pointer"
            if target in ("char *", "uint8_t *", "const char *", "const uint8_t *"):
                group = "byte pointer"
        elif target in ("uintptr_t", "intptr_t"):
            group = "address integer"
        elif TYPE.match(following):
            group = "nested scalar"
        elif line.startswith("return "):
            group = "scalar in return"
        elif " = " in preceding:
            group = "scalar in assignment"
        elif line.startswith(("if (", "while (", "for (")):
            group = "scalar in condition"
        else:
            group = "other scalar"
        records.append(dict(fixture=fixture, line=result.stdout.count("\n", 0, match.start()) + 1,
                            source=types.get(match.start(), "unresolved"), target=target,
                            group=group, context=line))
    return records, result.stdout.count("\n"), ast.returncode


def sample_memory(output, count=240):
    """Screen a deterministic corpus sample by visible address and definition syntax.

    Categories describe evidence in the printed C, not a proof of why inference
    refused a layout. The saved definitions allow checking those distinctions.
    """
    records = [json.loads(line) for line in (output / "casts.jsonl").read_text().splitlines()]
    occurrences = collections.Counter()
    for record in records:
        key = (record["fixture"], record["line"])
        record["cast_index"] = occurrences[key]
        occurrences[key] += 1
    records = [record for record in records if record["group"] == "memory pointer"]
    sample = random.Random(0).sample(records, min(count, len(records)))
    sources = {}
    counts = collections.Counter()
    for record in sample:
        fixture = record["fixture"]
        if fixture not in sources:
            sources[fixture] = (output / (fixture + ".c")).read_text().splitlines()
        lines = sources[fixture]
        at = record["line"] - 1
        start = at
        while start > 0 and not re.match(r"^\S.*\) \{$", lines[start]):
            start -= 1
        end = at
        while end < len(lines) and lines[end] != "}":
            end += 1
        function = lines[start:end]
        matches = [match for match in TYPE.finditer(lines[at]) if match[1].strip() != "void"]
        cast_index = record["cast_index"]
        address = (lines[at][matches[cast_index].end():].lstrip()
                   if cast_index < len(matches) else "")
        if address.startswith("("):
            depth = 0
            for stop, char in enumerate(address):
                depth += (char == "(") - (char == ")")
                if depth == 0:
                    address = address[1:stop]
                    break
        else:
            address = re.split(r"[;,=]", address, maxsplit=1)[0]
        base = re.search(r"\b(?:v[0-9]+|a[0-9]+|result|dst|src|g|sp|rsp|rbp)\b", address)
        definitions = []
        if base:
            name = base[0]
            definitions = [line.strip() for line in function
                           if re.match(r"(?:[A-Za-z_][A-Za-z_0-9 ]*\s+\**)?" + name + r" = ", line.strip())]
        record["definitions"] = definitions
        if re.search(r"\b(?:sp|rsp|rbp)\b|&local_", address) or any(
                re.search(r" = (?!\*\().*\b(?:sp|rsp|rbp)\b", line) for line in definitions):
            reason = "stack or frame address"
        elif any(re.search(r" = .* [+-] ", line) and "*(" not in line
                 for line in definitions) or len(definitions) > 1:
            reason = "adjusted or reassigned base"
        elif "*(" in address or "->" in address:
            reason = "indirect base or field value"
        elif re.search(r"\b(?:g_[0-9a-f]+|_RN\w*)\b", address):
            reason = "global address"
        elif re.search(r"\b(?:v[0-9]+|a[0-9]+)\b.*[+*].*\b(?:v[0-9]+|a[0-9]+)\b", address):
            reason = "variable index"
        else:
            reason = "other fixed or unresolved base"
        record["reason"] = reason
        counts[reason] += 1
    (output / "memory-sample.json").write_text(json.dumps(sample, indent=2) + "\n")
    return counts.most_common()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--bin", default="target/release/velk")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    fixtures = [line.split(": ", 1)[0] for line in pathlib.Path("tests/golden/casts.txt").read_text().splitlines()
                if not line.startswith("#")]
    counts = collections.Counter()
    patterns = collections.Counter()
    lines = failures = total = unresolved = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        results = executor.map(lambda fixture: measure(fixture, args.bin, args.output), fixtures)
        with (args.output / "casts.jsonl").open("w") as dump:
            for records, line_count, status in results:
                lines += line_count
                failures += status != 0
                for record in records:
                    dump.write(json.dumps(record) + "\n")
                    counts[record["group"]] += 1
                    patterns[(record["group"], record["source"], record["target"])] += 1
                    total += 1
                    unresolved += record["source"] == "unresolved"
    summary = dict(memory_sample=sample_memory(args.output),
                   casts=total, lines=lines, unresolved=unresolved,
                   clang_failures=failures, groups=counts.most_common(),
                   patterns=[[*key, count] for key, count in patterns.most_common()])
    (args.output / "counts.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({key: value for key, value in summary.items() if key != "patterns"}, indent=2))


if __name__ == "__main__":
    main()

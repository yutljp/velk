"""Conservative syntactic screen of locals in complete velk CLI output.

Usage: uv run python tests/scripts/local_usage.py OUTPUT.c [OUTPUT.c ...]
CSV definitions and uses go to stdout; class and origin totals go to stderr.

Counts direct assignments and component writes as definitions, and read-modify
writes as both a definition and use. The single-use, copy and merge classes describe syntax; they do not prove
that IR widths, bindings and live ranges permit eliminating a variable.
Everything outside this limited screen remains separate_or_unproven.
Writes through pointers are memory accesses rather than local definitions.
Stack object members count as component definitions.
Origins describe the printed initializer or repeated definitions, not recovered
source-language variables. Stack storage takes precedence over its initializer.
"""

import collections
import csv
from pathlib import Path
import re
import sys

TOKEN = re.compile(
    r"0x[0-9a-fA-F]+|[0-9]+|[A-Za-z_][A-Za-z_0-9]*|>>=|<<=|->|\+\+|--|[+*/%&|^-]=|==|!=|<=|>=|<<|>>|&&|\|\||[^\s]"
)
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")
ASSIGNMENT_OPERATORS = {
    "=",
    "+=",
    "-=",
    "*=",
    "/=",
    "%=",
    "&=",
    "|=",
    "^=",
    ">>=",
    "<<=",
    "++",
    "--",
}


def declaration(line):
    text = line.strip()
    if text.startswith("for ("):
        text = text[5:].split(";")[0] + ";"
    if not text.endswith(";"):
        return None
    text = re.sub(r"^_Alignas\([^)]*\)\s*", "", text)
    left = text.split("=", 1)[0].rstrip("; ").strip()
    pointer = re.search(r"\(\*([A-Za-z_][A-Za-z_0-9]*)\)\s*\(", left)
    if pointer:
        name = pointer.group(1)
        local_type = left[: pointer.start()] + "(*)" + left[pointer.end() - 1 :]
        return name, local_type, line.find(left) + pointer.start(1)
    if "}" in left:
        left = left.rsplit("}", 1)[1].strip()
        aggregate = True
    else:
        aggregate = False
    match = re.search(r"([A-Za-z_][A-Za-z_0-9]*)(?:\[[^]]*\])?$", left)
    if not match:
        return None
    prefix = left[: match.start()].strip()
    if not aggregate and (
        not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9 *]*", prefix)
        or prefix.split()[0] in {"return", "goto", "case", "break", "continue"}
    ):
        return None
    name = match.group(1)
    if "[" in left[match.end(1) :]:
        prefix += left[match.end(1) :]
    stop = line.find("=") if "=" in line else len(line)
    return name, "aggregate" if aggregate else prefix, line.rfind(name, 0, stop)


def analyze(path):
    summary = collections.Counter()
    rows = []
    for part in Path(path).read_text().split("/* velk pseudo-C: ")[1:]:
        label = part.split(" */", 1)[0]
        text = re.sub(r'/\*.*?\*/|"(?:\\.|[^"\\])*"', "", part, flags=re.S)
        lines = text.splitlines()
        start = next(
            (
                i
                for i, line in enumerate(lines)
                if not line.startswith(" ") and line.endswith(") {")
            ),
            None,
        )
        if start is None:
            continue
        end = next((i for i in range(start + 1, len(lines)) if lines[i] == "}"), len(lines))
        lines = lines[start + 1 : end]
        scopes = [{}]
        locals_found = []

        def resolve(name):
            return next((scope[name] for scope in reversed(scopes) if name in scope), None)

        for i, line in enumerate(lines):
            declared = declaration(line)
            tokens = list(TOKEN.finditer(line))
            for j, token in enumerate(tokens):
                name = token.group()
                if name == "{":
                    scopes.append({})
                    continue
                if name == "}":
                    if len(scopes) > 1:
                        scopes.pop()
                    continue
                previous = tokens[j - 1].group() if j else ""
                following = tokens[j + 1].group() if j + 1 < len(tokens) else ""
                if previous in {".", "->"}:
                    continue
                is_declaration = declared and name == declared[0] and token.start() == declared[2]
                if is_declaration:
                    value = dict(
                        name=name,
                        local_type=declared[1],
                        line=i,
                        definitions=[],
                        uses=[],
                        addressed=False,
                    )
                    scopes[-1][name] = value
                    locals_found.append(value)
                else:
                    value = resolve(name)
                if value is None:
                    continue
                if previous == "&":
                    value["addressed"] = True
                direct = following in ASSIGNMENT_OPERATORS or previous in {"++", "--"}
                suffix = [t.group() for t in tokens[j + 1 :]]
                operation = next((t for t in suffix if t in ASSIGNMENT_OPERATORS), None)
                component = operation is not None and (
                    following == "." or following == "[" and "[" in value["local_type"]
                )
                if direct or component:
                    rhs = [t.group() for t in tokens[j + 2 : -1]] if following == "=" else []
                    copied = resolve(rhs[0]) if len(rhs) == 1 else None
                    types = {}
                    for operand in rhs:
                        source = resolve(operand)
                        if source is not None:
                            types[operand] = source["local_type"]
                    value["definitions"].append((i, rhs, copied, types))
                if not is_declaration and (
                    component
                    and operation != "="
                    or not component
                    and (not direct or following != "=")
                ):
                    value["uses"].append(i)
        for value in locals_found:
            definitions, uses, local_type = value["definitions"], value["uses"], value["local_type"]
            kind = "separate_or_unproven"
            copies = [
                copied
                for _, _, copied, _ in definitions
                if copied is not None and copied is not value and copied["local_type"] == local_type
            ]
            if not value["addressed"] and definitions and len(copies) == len(definitions):
                if len(definitions) == 1:
                    kind = "plain_copy"
                elif all(copied is copies[0] for copied in copies):
                    kind = "same_source_merge"
            elif (
                not value["addressed"]
                and len(definitions) == len(uses) == 1
                and uses[0] == definitions[0][0] + 1
                and local_type in {"uint32_t", "uint64_t"}
            ):
                rhs = definitions[0][1]
                inputs = [t for t in rhs if IDENTIFIER.fullmatch(t)]
                local_types = definitions[0][3]
                safe = rhs and not any(
                    t
                    in {
                        "/",
                        "%",
                        "?",
                        "[",
                        "]",
                        "*",
                        "&",
                        "++",
                        "--",
                        "(",
                        ")",
                        "==",
                        "!=",
                        "<",
                        ">",
                        "<=",
                        ">=",
                        "&&",
                        "||",
                        "!",
                    }
                    for t in rhs
                )
                safe = (
                    safe and bool(inputs) and all(local_types.get(t) == local_type for t in inputs)
                )
                consumer = lines[uses[0]].strip()
                if (
                    safe
                    and consumer.endswith(";")
                    and not consumer.startswith(("for ", "while ", "do ", "goto "))
                ):
                    kind = "single_use_candidate"
            if (
                kind == "separate_or_unproven"
                and not value["addressed"]
                and len(definitions) == len(uses) == 1
                and uses[0] == definitions[0][0] + 1
            ):
                rhs = definitions[0][1]
                load = (
                    len(rhs) >= 6 and rhs[:2] == ["*", "("] and rhs[2:5] == [local_type, "*", ")"]
                )
                consumer = lines[uses[0]].strip()
                assignment = re.fullmatch(r"(.+) = " + re.escape(value["name"]) + r";", consumer)
                if load and assignment:
                    lhs = assignment.group(1)
                    slot = re.fullmatch(r"local_\d+(?:\.[A-Za-z_][A-Za-z_0-9]*)*", lhs)
                    address = re.fullmatch(r"\*\((?:u?int\d+_t) \*\)\([A-Za-z_0-9+() -]+\)", lhs)
                    if slot or address:
                        kind = "single_use_candidate"
            summary[kind] += 1
            origin = "computed_value"
            if value["name"].startswith("local_"):
                origin = "stack_storage"
            elif local_type in {"struct go_string", "struct go_slice", "struct go_iface"}:
                origin = "typed_header"
            elif value["addressed"] or "[" in local_type or local_type == "aggregate":
                origin = "addressable_storage"
            elif kind in {"plain_copy", "same_source_merge"}:
                origin = "register_copy" if kind == "plain_copy" else "merge_copy"
            elif len(definitions) != 1:
                origin = "multiple_or_missing_definitions"
            else:
                rhs = definitions[0][1]
                if any(
                    IDENTIFIER.fullmatch(token)
                    and rhs[index + 1 : index + 2] == ["("]
                    and not re.fullmatch(r"(?:u?int\d+_t|uintptr_t|intptr_t)", token)
                    for index, token in enumerate(rhs)
                ):
                    origin = "call_result"
                elif rhs[:1] == ["*"] or any(token in {"->", "["} for token in rhs):
                    origin = "memory_read"
                elif rhs and all(
                    re.fullmatch(r"(?:0x[0-9a-fA-F]+|[0-9]+)", token) or token == "-"
                    for token in rhs
                ):
                    origin = "constant"
            rows.append(
                [
                    Path(path).name,
                    label,
                    value["name"],
                    value["line"] + 1,
                    local_type,
                    len(definitions),
                    len(uses),
                    kind,
                    origin,
                ]
            )
    return summary, rows


def main():
    writer = csv.writer(sys.stdout)
    writer.writerow(
        ["file", "function", "local", "body_line", "type", "definitions", "uses", "class", "origin"]
    )
    for path in sys.argv[1:]:
        summary, rows = analyze(path)
        writer.writerows(rows)
        print(path, dict(summary), "total", sum(summary.values()), file=sys.stderr)
        print("origins", dict(collections.Counter(row[-1] for row in rows)), file=sys.stderr)


if __name__ == "__main__":
    main()

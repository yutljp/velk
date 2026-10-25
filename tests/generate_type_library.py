"""Generate the macOS C API library from the selected SDK's headers.

Run with UV_CACHE_DIR=target/uv-cache uv run tests/generate_type_library.py.
Clang supplies declarations and record layouts; no binary database is read.
Only signatures identical on arm64 and x86_64 are admitted. Aggregate values,
long doubles, vectors, blocks, mixed integer/floating signatures, stack
arguments, and new variadic APIs are excluded.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

HEADERS = """assert.h ctype.h dirent.h dlfcn.h errno.h fcntl.h fnmatch.h glob.h
grp.h iconv.h inttypes.h langinfo.h libgen.h locale.h math.h netdb.h poll.h
pthread.h pwd.h regex.h sched.h semaphore.h setjmp.h signal.h spawn.h stdio.h
stdlib.h string.h strings.h sys/event.h sys/file.h sys/ioctl.h sys/mman.h
sys/resource.h sys/select.h sys/socket.h sys/stat.h sys/statvfs.h sys/time.h
sys/times.h sys/uio.h sys/utsname.h sys/wait.h sys/xattr.h syslog.h termios.h
time.h unistd.h utime.h wchar.h wctype.h arpa/inet.h net/if.h netinet/in.h""".split()
SCALARS = {"void": 0, "_Bool": 1, "char": 1, "signed char": 1,
           "unsigned char": 1, "short": 2, "unsigned short": 2, "int": 4,
           "unsigned int": 4, "long": 8, "unsigned long": 8, "long long": 8,
           "unsigned long long": 8, "float": 4, "double": 8}
KEEP = {"size_t", "ssize_t", "intptr_t", "uintptr_t", "ptrdiff_t"}
KEEP.update(f"{s}int{b}_t" for s in ("", "u") for b in (8, 16, 32, 64))
SCALARS.update({name: 8 for name in ("size_t", "ssize_t", "intptr_t", "uintptr_t", "ptrdiff_t")})
SCALARS.update({f"{s}int{b}_t": b // 8 for s in ("", "u") for b in (8, 16, 32, 64)})
STANDARD_HEADERS = ["inttypes.h", "stdbool.h", "stddef.h", "stdint.h", "stdlib.h"]


def run(args):
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stderr)
    return result.stdout


def extract(clang, sdk, target, source):
    args = [clang, "-target", target, "-isysroot", str(sdk), "-Wno-deprecated-declarations", "-fno-builtin",
            "-fsyntax-only", str(source)]
    nodes = json.loads(run(args + ["-Xclang", "-ast-dump=json"]))["inner"]
    standard = source.parent / "standard.c"
    standard.write_text("".join(f"#include <{h}>\n" for h in STANDARD_HEADERS))
    standard_args = [arg if arg != str(source) else str(standard) for arg in args]
    standard_nodes = json.loads(run(standard_args + ["-Xclang", "-ast-dump=json"]))["inner"]
    predefined = {"struct " + n["name"] for n in standard_nodes
                  if n["kind"] == "RecordDecl" and n.get("name")
                  and n.get("tagUsed") == "struct" and n.get("completeDefinition")}
    typedefs = {n["name"]: n["type"].get("desugaredQualType", n["type"]["qualType"])
                for n in nodes if n["kind"] == "TypedefDecl"}
    enum_nodes = [n for n in nodes if n["kind"] == "EnumDecl"]
    enum_names = {n["id"]: "enum " + n["name"] for n in enum_nodes if n.get("name")}
    enum_spellings = {}
    for n in nodes:
        if n["kind"] != "TypedefDecl":
            continue
        pending = list(n.get("inner", []))
        while pending:
            inner = pending.pop()
            if inner["kind"] == "EnumType":
                ident = inner["decl"]["id"]
                enum_names.setdefault(ident, n["name"])
                enum_spellings[inner["type"]["qualType"]] = ident
            pending.extend(inner.get("inner", []))
    # Query compatible integer types without executing target code.
    probe = source.parent / "enum_types.c"
    candidates = ["int", "unsigned int", "long", "unsigned long", "long long", "unsigned long long", "short", "unsigned short"]
    lines = [source.read_text()]
    queries = {}
    for i, (ident, name) in enumerate(sorted(enum_names.items(), key=lambda item: item[1])):
        for j, scalar in enumerate(candidates):
            var = f"velk_enum_{i}_{j}"
            lines.append(f"char {var}[__builtin_types_compatible_p({name}, {scalar}) ? 1 : 2];")
            queries[var] = (ident, scalar)
    probe.write_text("\n".join(lines))
    probe_args = [arg if arg != str(source) else str(probe) for arg in args]
    enum_types = {}
    for n in json.loads(run(probe_args + ["-Xclang", "-ast-dump=json"]))["inner"]:
        if n.get("name") in queries and n["type"]["qualType"] == "char[1]":
            ident, scalar = queries[n["name"]]
            enum_types[ident] = scalar
    for ident, name in enum_names.items():
        if name.startswith("enum "):
            enum_spellings[name] = ident
    tags = {"struct " + n["name"] for n in nodes
            if n["kind"] == "RecordDecl" and n.get("name") and n.get("tagUsed") == "struct"}
    used_typedefs = set()

    def normalize(text, depth=0):
        if depth > 24:
            return None
        text = re.sub(r"\b(?:restrict|__restrict|_Nonnull|_Nullable|_Null_unspecified|volatile)\b", "", text)
        text = " ".join(text.split())
        if text.endswith(" const"):
            text = text[:-6].strip()
        if text.endswith("*"):
            inner = normalize(text[:-1], depth + 1)
            return inner + " *" if inner else None
        if text.startswith("const "):
            inner = normalize(text[6:], depth + 1)
            if inner and "*" in inner:
                return None
            return "const " + inner if inner else None
        if text in typedefs and text not in KEEP:
            used_typedefs.add(text)
            return normalize(typedefs[text], depth + 1)
        if text in SCALARS or text in KEEP or text in tags:
            return text
        if text in enum_spellings:
            return enum_types.get(enum_spellings[text])
        return None

    layouts = {}
    dump = run(args + ["-Xclang", "-fdump-record-layouts-complete"])
    for block in dump.split("*** Dumping AST Record Layout")[1:]:
        lines = block.strip().splitlines()
        head = re.fullmatch(r"\s*0 \| (struct \w+)", lines[0])
        size = re.search(r"\[sizeof=(\d+), align=(\d+)\]", block)
        if not head or not size:
            continue
        offsets = []
        for line in lines[1:]:
            field = re.fullmatch(r"\s*(\d+) \|   \S.*", line)
            if field:
                offsets.append(int(field[1]))
        layouts[head[1]] = (int(size[1]), int(size[2]), offsets)

    records = {}
    for n in nodes:
        if n["kind"] != "RecordDecl" or not n.get("completeDefinition") or n.get("tagUsed") != "struct":
            continue
        name = "struct " + n.get("name", "")
        layout = layouts.get(name)
        fields = [f for f in n.get("inner", []) if f["kind"] == "FieldDecl"]
        if not layout or len(fields) != len(layout[2]) or any(f.get("isBitfield") for f in fields):
            continue
        size, align, offsets = layout
        members = []
        for f, offset in zip(fields, offsets):
            ty = normalize(f["type"]["qualType"])
            base = (ty or "").removeprefix("const ")
            width = 8 if ty and ty.endswith("*") else SCALARS.get(base, 0)
            # Unknown and array fields retain their bytes as padding.
            if width and f.get("name"):
                members.append([offset, f["name"], ty, width])
        if size and align and all(o + w <= size and o % w == 0 and align >= w
                                  for o, _, _, w in members):
            records[name] = {"size": size, "align": align,
                             "opaque": name in predefined or name.startswith("struct _"),
                             "fields": members}

    functions = {}
    rejected = 0
    for n in nodes:
        if n["kind"] != "FunctionDecl" or n.get("storageClass") == "static" or n.get("isImplicit"):
            continue
        name = n["name"]
        if any(c["kind"] == "UnavailableAttr" or
               (c["kind"] == "AvailabilityAttr" and c.get("platform") == "macos" and c.get("unavailable"))
               for c in n.get("inner", [])):
            continue
        if n.get("variadic") or any(c["kind"] == "CompoundStmt" for c in n.get("inner", [])):
            rejected += 1
            continue
        ret = normalize(n["type"]["qualType"].split(" (", 1)[0])
        params = [normalize(p["type"]["qualType"]) for p in n.get("inner", []) if p["kind"] == "ParmVarDecl"]
        types = [ret] + params
        if any(t is None or (not t.endswith("*") and t.removeprefix("const ") not in SCALARS) for t in types):
            rejected += 1
            continue
        floating = [t in ("float", "double") for t in params]
        if any(floating) and not all(floating):
            # Calls currently list integer arguments before floating ones.
            rejected += 1
            continue
        if len(params) > (8 if any(floating) else 6) or " ()" in n["type"]["qualType"]:
            # Import summaries do not describe arguments on the stack.
            rejected += 1
            continue
        functions[name] = ret + " " + name + "(" + (", ".join(params) or "void") + ")"
    # Typedef and enum spelling is retained for provenance, even where the
    # runtime deliberately uses a scalar type or declines the signature.
    aliases = {name: typedefs[name] for name in sorted(used_typedefs)
               if not any(c in typedefs[name] for c in ("/", "\\"))}
    constants = {}
    for n in enum_nodes:
        if n["id"] not in enum_names or n["id"] not in enum_types:
            continue
        values = {}
        current = -1
        for c in n.get("inner", []):
            if c["kind"] != "EnumConstantDecl":
                continue
            pending = list(c.get("inner", []))
            value = None
            while pending:
                expr = pending.pop()
                if "value" in expr and expr["kind"] == "ConstantExpr":
                    value = int(expr["value"])
                    break
                pending.extend(expr.get("inner", []))
            current = current + 1 if value is None else value
            values[c["name"]] = current
        constants[enum_names[n["id"]]] = {"type": enum_types[n["id"]], "values": values}
    return {"functions": functions, "records": records, "typedefs": aliases, "enums": constants}, rejected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--output", type=Path, default=Path("src/analysis/prototypes/macos.json"))
    args = parser.parse_args()
    sdk = args.sdk or Path(run(["xcrun", "--show-sdk-path"]).strip())
    settings = json.loads((sdk / "SDKSettings.json").read_text())
    with tempfile.TemporaryDirectory() as temp:
        source = Path(temp) / "headers.c"
        source.write_text("".join(f"#include <{h}>\n" for h in HEADERS))
        arm, arm_rejected = extract(args.clang, sdk, "arm64-apple-macos", source)
        x64, x64_rejected = extract(args.clang, sdk, "x86_64-apple-macos", source)
    resource = Path(run([args.clang, "-print-resource-dir"]).strip()) / "include"
    header_hashes = {}
    for header in sorted(set(HEADERS + STANDARD_HEADERS)):
        path = sdk / "usr/include" / header
        if path.is_file():
            header_hashes[header] = hashlib.sha256(path.read_bytes()).hexdigest()
        path = resource / header
        if header in STANDARD_HEADERS and path.is_file():
            header_hashes["clang/" + header] = hashlib.sha256(path.read_bytes()).hexdigest()
    data = {"version": 1, "source": {"sdk": settings["CanonicalName"],
            "compiler": run([args.clang, "--version"]).splitlines()[0],
            "headers": header_hashes,
            "standard_headers": STANDARD_HEADERS,
            "targets": ["arm64-apple-macos", "x86_64-apple-macos"],
            "rejected_signatures": [arm_rejected, x64_rejected]}}
    for kind in arm:
        data[kind] = {k: v for k, v in sorted(arm[kind].items()) if x64[kind].get(k) == v}
    # Check every normalized function type against its header declaration.
    with tempfile.TemporaryDirectory() as temp:
        check = Path(temp) / "signatures.c"
        lines = [f"#include <{h}>" for h in HEADERS]
        for i, (name, declaration) in enumerate(data["functions"].items()):
            alias = f"velk_api_{i}"
            pointer = declaration.replace(name + "(", "(*" + alias + ")(", 1)
            lines.append(f"typedef {pointer};")
            lines.append(f'_Static_assert(__builtin_types_compatible_p(__typeof__(&{name}), {alias}), "{name}");')
        check.write_text("\n".join(lines))
        for target in data["source"]["targets"]:
            run([args.clang, "-target", target, "-isysroot", str(sdk), "-fno-builtin",
                 "-Wno-deprecated-declarations", "-fsyntax-only", str(check)])
        # Compile the exact padded record representation used by the printer.
        lines = ["#include <stddef.h>", "#include <stdint.h>", "#include <sys/types.h>"]
        rename = lambda text: re.sub(r"\bstruct (\w+)", r"struct velk_header_\1", text)
        tags = set(data["records"])
        for record in data["records"].values():
            for _, _, text, _ in record["fields"]:
                tags.update(re.findall(r"struct \w+", text))
        lines.extend(rename(tag) + ";" for tag in sorted(tags))
        for name, record in data["records"].items():
            members, offset = [], 0
            for at, field, text, width in record["fields"]:
                if at > offset:
                    members.append(f"uint8_t gap_0x{offset:x}[0x{at-offset:x}];")
                members.append(f"{rename(text)} {field};")
                offset = at + width
            if offset < record["size"]:
                members.append(f'uint8_t gap_0x{offset:x}[0x{record["size"]-offset:x}];')
            members[0] = f'_Alignas({record["align"]}) ' + members[0]
            tag = rename(name)
            lines.append(tag + " {" + "".join(members) + "};")
            lines.append(f'_Static_assert(sizeof({tag}) == {record["size"]}, "{name} size");')
            lines.append(f'_Static_assert(_Alignof({tag}) == {record["align"]}, "{name} alignment");')
            for at, field, _, _ in record["fields"]:
                lines.append(f'_Static_assert(offsetof({tag}, {field}) == {at}, "{name}.{field}");')
        check.write_text("\n".join(lines))
        for target in data["source"]["targets"]:
            run([args.clang, "-target", target, "-isysroot", str(sdk), "-std=c11", "-fsyntax-only", str(check)])
    # One entry per line keeps generated diffs reviewable.
    text = '{\n"version":1,\n"source":' + json.dumps(data["source"], separators=(",", ":"))
    for kind in arm:
        entries = [json.dumps(k) + ":" + json.dumps(v, separators=(",", ":")) for k, v in data[kind].items()]
        text += ',\n"' + kind + '":{\n' + ",\n".join(entries) + "\n}"
    args.output.write_text(text + "\n}\n")
    print({kind: len(data[kind]) for kind in arm})


if __name__ == "__main__":
    main()

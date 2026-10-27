"""Generate C API libraries from target compiler headers.

Run with UV_CACHE_DIR=target/uv-cache uv run tests/generate_type_library.py.
Clang supplies declarations and record layouts; no binary database is read.
macOS shares signatures identical on arm64 and x86_64; Windows and Linux keep
separate target declarations and layouts. Aggregate values,
long doubles, vectors, blocks, mixed integer/floating signatures, and new variadic
APIs are excluded. Active lifters use register-argument signatures.
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
KEEP = {"FILE", "size_t", "ssize_t", "intptr_t", "uintptr_t", "ptrdiff_t"}
KEEP.update(f"{s}int{b}_t" for s in ("", "u") for b in (8, 16, 32, 64))
SCALARS.update({name: 8 for name in ("size_t", "ssize_t", "intptr_t", "uintptr_t", "ptrdiff_t")})
SCALARS.update({f"{s}int{b}_t": b // 8 for s in ("", "u") for b in (8, 16, 32, 64)})
STANDARD_HEADERS = ["inttypes.h", "stdbool.h", "stddef.h", "stdint.h", "stdlib.h"]


def run(args):
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stderr)
    return result.stdout


def compiler_args(clang, sdk, target):
    args = [clang, "-target", target, "-Wno-deprecated-declarations", "-fno-builtin"]
    if sdk:
        args.extend(["-isysroot", str(sdk)])
    if "mingw" in target:
        prefix = "i686" if target.startswith("i686") else "x86_64"
        args.extend(["--sysroot=/usr/" + prefix + "-w64-mingw32", "-D_WIN32_WINNT=0x0602"])
    elif target.startswith("aarch64-linux"):
        args.append("--sysroot=/usr/aarch64-linux-gnu")
    if "linux" in target:
        args.append("-D_GNU_SOURCE")
    return args


def undefinitions(names):
    return [f"#undef {name}" for name in sorted(set(names)) if re.fullmatch(r"[A-Za-z_]\w*", name)]


def split_parameters(text):
    pieces, start, depth = [], 0, 0
    for at, char in enumerate(text + ","):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            pieces.append(text[start:at].strip())
            start = at + 1
    return pieces


def field_declaration(text, name):
    if re.search(r"\(\*+\)", text):
        return re.sub(r"\((\*+)\)", lambda match: f"({match[1]}{name})", text, count=1)
    return f"{text} {name}"


def guid_constants(nodes):
    def unwrap(node):
        while node.get("kind") in ("ImplicitCastExpr", "CStyleCastExpr", "ConstantExpr", "ParenExpr") and len(node.get("inner", [])) == 1:
            node = node["inner"][0]
        return node

    values = {}
    for node in nodes:
        name = node.get("name", "")
        if node.get("kind") != "VarDecl" or not name.startswith(("IID_", "CLSID_")):
            continue
        initializers = [unwrap(inner) for inner in node.get("inner", [])]
        initializers = [inner for inner in initializers if inner.get("kind") == "InitListExpr"]
        if len(initializers) != 1:
            continue
        fields = [unwrap(inner) for inner in initializers[0].get("inner", [])]
        if len(fields) != 4 or fields[3].get("kind") != "InitListExpr":
            continue
        octets = [unwrap(inner) for inner in fields[3].get("inner", [])]
        fields = fields[:3] + octets
        if len(octets) != 8 or any(field.get("kind") != "IntegerLiteral" for field in fields):
            continue
        data = bytearray()
        for field, width in zip(fields, [4, 2, 2] + [1] * 8):
            value = int(field["value"]) & ((1 << (width * 8)) - 1)
            data.extend(value.to_bytes(width, "little"))
        values[name] = list(data)
    return values


def extract(clang, sdk, target, source):
    args = compiler_args(clang, sdk, target) + ["-fsyntax-only", str(source)]
    nodes = json.loads(run(args + ["-Xclang", "-ast-dump=json"]))["inner"]
    standard = source.parent / "standard.c"
    standard.write_text("".join(f"#include <{h}>\n" for h in STANDARD_HEADERS))
    standard_args = [arg if arg != str(source) else str(standard) for arg in args]
    standard_nodes = json.loads(run(standard_args + ["-Xclang", "-ast-dump=json"]))["inner"]
    predefined = {"struct " + n["name"] for n in standard_nodes
                  if n.get("kind") == "RecordDecl" and n.get("name")
                  and n.get("tagUsed") == "struct" and n.get("completeDefinition")}
    typedefs = {n["name"]: n["type"].get("desugaredQualType", n["type"]["qualType"])
                for n in nodes if n.get("kind") == "TypedefDecl"}
    enum_nodes = [n for n in nodes if n.get("kind") == "EnumDecl"]
    enum_names = {n["id"]: "enum " + n["name"] for n in enum_nodes if n.get("name")}
    enum_spellings = {}
    for n in nodes:
        if n.get("kind") != "TypedefDecl":
            continue
        pending = list(n.get("inner", []))
        while pending:
            inner = pending.pop()
            if inner.get("kind") == "EnumType":
                ident = inner["decl"]["id"]
                enum_names.setdefault(ident, n["name"])
                enum_spellings[inner["type"]["qualType"]] = ident
            pending.extend(inner.get("inner", []))
    # Query compatible integer types without executing target code.
    probe = source.parent / "enum_types.c"
    candidates = ["int", "unsigned int", "long", "unsigned long", "long long", "unsigned long long", "short", "unsigned short"]
    names = [n["name"] for n in nodes if n.get("name")]
    for n in nodes:
        names.extend(f["name"] for f in n.get("inner", [])
                     if f.get("kind") == "FieldDecl" and f.get("name"))
    lines = [source.read_text(), "#include <stddef.h>"] + undefinitions(names)
    queries = {}
    for i, (ident, name) in enumerate(sorted(enum_names.items(), key=lambda item: item[1])):
        for j, scalar in enumerate(candidates):
            var = f"velk_enum_{i}_{j}"
            lines.append(f"char {var}[__builtin_types_compatible_p({name}, {scalar}) ? 1 : 2];")
            queries[var] = (ident, scalar)
    record_queries = {}
    layouts = {}
    for i, n in enumerate(nodes):
        if (n.get("kind") != "RecordDecl" or not n.get("completeDefinition")
                or n.get("tagUsed") != "struct" or not n.get("name")):
            continue
        fields = [f for f in n.get("inner", []) if f.get("kind") == "FieldDecl"]
        if any(f.get("isBitfield") or not f.get("name") for f in fields):
            continue
        name = "struct " + n["name"]
        layouts[name] = [0, 0, [0] * len(fields)]
        for kind, expression in [(0, f"sizeof({name})"), (1, f"_Alignof({name})")]:
            var = f"velk_record_{i}_{kind}"
            lines.append(f"char {var}[{expression}];")
            record_queries[var] = (name, kind, None)
        for j, field in enumerate(fields):
            var = f"velk_offset_{i}_{j}"
            lines.append(f'char {var}[offsetof({name}, {field["name"]}) + 1];')
            record_queries[var] = (name, 2, j)
    probe.write_text("\n".join(lines))
    probe_args = [arg if arg != str(source) else str(probe) for arg in args]
    enum_types = {}
    for n in json.loads(run(probe_args + ["-Xclang", "-ast-dump=json"]))["inner"]:
        if n.get("name") in queries and n["type"]["qualType"] == "char[1]":
            ident, scalar = queries[n["name"]]
            enum_types[ident] = scalar
        if n.get("name") in record_queries:
            name, kind, index = record_queries[n["name"]]
            count = int(re.fullmatch(r"char\[(\d+)\]", n["type"]["qualType"])[1])
            if kind == 2:
                layouts[name][2][index] = count - 1
            else:
                layouts[name][kind] = count
    for ident, name in enum_names.items():
        if name.startswith("enum "):
            enum_spellings[name] = ident
    tags = {n["tagUsed"] + " " + n["name"] for n in nodes
            if n.get("kind") == "RecordDecl" and n.get("name") and n.get("tagUsed") in ("struct", "union")}
    used_typedefs = set()

    def normalize(text, depth=0):
        if depth > 24:
            return None
        text = re.sub(r"\b(?:restrict|__restrict|_Nonnull|_Nullable|_Null_unspecified)\b", "", text)
        text = " ".join(text.split())
        if text.endswith(" const"):
            text = text[:-6].strip()
        attribute = re.search(r"\s+__attribute__\(\((\w+)\)\)$", text)
        function_text = text[:attribute.start()] if attribute else text
        function = re.fullmatch(r"(.+?)\(\s*(\*+)\s*\)\s*\((.*)\)", function_text)
        if function:
            result, stars, arguments = function.groups()
            convention = attribute[1] if attribute else None
            if convention not in (None, "cdecl", "stdcall", "fastcall", "thiscall", "ms_abi"):
                return None
            result = normalize(result, depth + 1)
            arguments = split_parameters(arguments)
            if not arguments or arguments == [""]:
                # A declaration without a prototype has unknown parameters.
                return None
            normalized = [arg if arg == "..." else normalize(re.sub(r"(?<!\w)const$", "", arg).strip(), depth + 1)
                          for arg in arguments]
            if result is None or any(arg is None for arg in normalized):
                return None
            attribute = convention
            if "mingw" in target and not target.startswith("i686"):
                attribute = "ms_abi"
            attribute = f" __attribute__(({attribute}))" if attribute and attribute != "cdecl" else ""
            return f'{result}{attribute} ({stars})({", ".join(normalized)})'
        if text.endswith("*"):
            inner = normalize(text[:-1], depth + 1)
            if inner and re.search(r"\(\*+\)", inner):
                return re.sub(r"\((\*+)\)", r"(*\1)", inner, count=1)
            return inner + " *" if inner else None
        if text.startswith("volatile "):
            inner = normalize(text[9:], depth + 1)
            return "volatile " + inner if inner else None
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

    records = {}
    for n in nodes:
        if n.get("kind") != "RecordDecl" or not n.get("completeDefinition") or n.get("tagUsed") != "struct":
            continue
        name = "struct " + n.get("name", "")
        layout = layouts.get(name)
        fields = [f for f in n.get("inner", []) if f.get("kind") == "FieldDecl"]
        if not layout or len(fields) != len(layout[2]) or any(f.get("isBitfield") for f in fields):
            continue
        size, align, offsets = layout
        members = []
        for f, offset in zip(fields, offsets):
            ty = normalize(f["type"]["qualType"])
            base = (ty or "").removeprefix("const ")
            width = SCALARS["uintptr_t"] if ty and (ty.endswith("*") or re.search(r"\(\*+\)", ty)) else SCALARS.get(base, 0)
            if ty and re.search(r"\(\*+\)", ty) and (offset % width or align < width):
                # A naturally aligned declaration cannot describe a packed callback.
                continue
            # Unknown and array fields retain their bytes as padding.
            if width and f.get("name"):
                members.append([offset, f["name"], ty, width])
        if size and align and all(o + w <= size and o % w == 0 and align >= w
                                  for o, _, _, w in members):
            records[name] = {"size": size, "align": align,
                             "opaque": name in predefined or ("mingw" not in target and name.startswith("struct _"))
                             or ("mingw" in target and name.endswith("__")),
                             "fields": members}

    functions = {}
    conventions = {}
    rejected = 0
    for n in nodes:
        if n.get("kind") != "FunctionDecl" or n.get("storageClass") == "static" or n.get("isImplicit"):
            continue
        name = n["name"]
        if any(c.get("kind") == "UnavailableAttr" or
               (c.get("kind") == "AvailabilityAttr" and c.get("platform") == "macos" and c.get("unavailable"))
               for c in n.get("inner", [])):
            continue
        if n.get("variadic") or any(c.get("kind") == "CompoundStmt" for c in n.get("inner", [])):
            rejected += 1
            continue
        function_type = n["type"]["qualType"]
        result, _, parameters = function_type.partition("(")
        if parameters.lstrip().startswith("*"):
            rejected += 1
            continue
        ret = normalize(result.strip())
        params = [normalize(p["type"]["qualType"]) for p in n.get("inner", []) if p.get("kind") == "ParmVarDecl"]
        types = [ret] + params
        if any(t is None or "(" in t or "union " in t or (not t.endswith("*") and t.removeprefix("const ") not in SCALARS) for t in types):
            rejected += 1
            continue
        floating = [t in ("float", "double") for t in params]
        if any(floating) and not all(floating):
            # Calls currently list integer arguments before floating ones.
            rejected += 1
            continue
        if len(params) > (4 if "mingw" in target else 8 if any(floating) else 6) or " ()" in n["type"]["qualType"]:
            # Import summaries do not describe arguments on the stack.
            rejected += 1
            continue
        conventions[name] = "stdcall" if "stdcall" in n["type"]["qualType"] else "c"
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
            if c.get("kind") != "EnumConstantDecl":
                continue
            pending = list(c.get("inner", []))
            value = None
            while pending:
                expr = pending.pop()
                if "value" in expr and expr.get("kind") == "ConstantExpr":
                    value = int(expr["value"])
                    break
                pending.extend(expr.get("inner", []))
            current = current + 1 if value is None else value
            values[c["name"]] = current
        constants[enum_names[n["id"]]] = {"type": enum_types[n["id"]], "values": values}
    return {"functions": functions, "records": records, "typedefs": aliases, "enums": constants, "conventions": conventions, "guids": guid_constants(nodes)}, rejected


def header_variables(clang, sdk, target, headers):
    variables = {}
    include_depths = {}
    pointer_size = 4 if target.startswith("i686") else 8
    scalar_sizes = dict(SCALARS)
    if "mingw" in target:
        scalar_sizes["long"] = scalar_sizes["unsigned long"] = 4
    for name in ["size_t", "ssize_t", "intptr_t", "uintptr_t", "ptrdiff_t"]:
        scalar_sizes[name] = pointer_size
    with tempfile.TemporaryDirectory() as temp:
        source = Path(temp) / "variables.c"
        for header in sorted(headers, key=lambda h: (len(h), h)):
            prefix = "#include <winsock2.h>\n#include <windows.h>\n" if "mingw" in target else ""
            source.write_text(prefix + f"#include <{header}>\n")
            args = compiler_args(clang, sdk, target)
            result = subprocess.run(args + ["-fsyntax-only", str(source), "-H",
                                            "-Xclang", "-ast-dump=json"],
                                    capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(result.stderr)
            nodes = json.loads(result.stdout)["inner"]
            depths = {str(source): 0}
            for line in result.stderr.splitlines():
                match = re.fullmatch(r"(\.+) (.+)", line)
                if match:
                    depths[match[2]] = len(match[1])
            checks = []
            for node in nodes:
                location = node.get("loc", {})
                if node.get("kind") != "VarDecl" or node.get("storageClass") != "extern":
                    continue
                name = node.get("name")
                ty = node["type"]["qualType"]
                scalar = re.sub(r"\b(const|volatile)\b", "", ty).strip()
                size = pointer_size if ty.endswith("*") else scalar_sizes.get(scalar)
                if name and size and "(" not in ty and "[" not in ty:
                    # Prefer the public header with the shortest include chain.
                    parent = location.get("includedFrom", {}).get("file", "")
                    depth = depths.get(parent, len(nodes))
                    if name not in variables or depth < include_depths[name]:
                        variables[name] = {"type": ty, "size": size, "header": header}
                        include_depths[name] = depth
                    checks.append(f'_Static_assert(sizeof({name}) == {size}, "{name}");')
            source.write_text(source.read_text() + "\n".join(checks) + "\n")
            run(args + ["-fsyntax-only", str(source)])
    return variables


def header_guids(clang, target, headers):
    with tempfile.TemporaryDirectory() as temp:
        source = Path(temp) / "guids.c"
        source.write_text("#include <initguid.h>\n" + "".join(f"#include <{h}>\n" for h in headers))
        args = compiler_args(clang, None, target)
        nodes = json.loads(run(args + ["-fsyntax-only", str(source), "-Xclang", "-ast-dump=json"]))["inner"]
        dependencies = run(args + ["-M", "-MT", "guids", str(source)])
        return guid_constants(nodes), dependencies


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=["macos", "windows", "linux"], default="macos")
    parser.add_argument("--sdk", type=Path)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--output", type=Path, default=Path("src/analysis/prototypes/macos.json"))
    args = parser.parse_args()
    if args.platform != "macos":
        generate_platform(args)
        return
    sdk = args.sdk or Path(run(["xcrun", "--show-sdk-path"]).strip())
    settings = json.loads((sdk / "SDKSettings.json").read_text())
    with tempfile.TemporaryDirectory() as temp:
        source = Path(temp) / "headers.c"
        source.write_text("".join(f"#include <{h}>\n" for h in HEADERS))
        arm, arm_rejected = extract(args.clang, sdk, "arm64-apple-macos", source)
        x64, x64_rejected = extract(args.clang, sdk, "x86_64-apple-macos", source)
        arm.pop("conventions")
        x64.pop("conventions")
    for target, declarations in zip(["arm64-apple-macos", "x86_64-apple-macos"], [arm, x64]):
        declarations["variables"] = header_variables(args.clang, sdk, target, HEADERS)
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
    for target in data["source"]["targets"]:
        verify_target(args.clang, target, HEADERS, data, sdk)
    # One entry per line keeps generated diffs reviewable.
    text = '{\n"version":1,\n"source":' + json.dumps(data["source"], separators=(",", ":"))
    for kind in arm:
        entries = [json.dumps(k) + ":" + json.dumps(v, separators=(",", ":")) for k, v in data[kind].items()]
        text += ',\n"' + kind + '":{\n' + ",\n".join(entries) + "\n}"
    args.output.write_text(text + "\n}\n")
    print({kind: len(data[kind]) for kind in arm})


LINUX_HEADERS = [h for h in HEADERS if h != "sys/event.h"] + [
    "sys/epoll.h", "sys/eventfd.h", "sys/inotify.h", "sys/prctl.h", "sys/sendfile.h",
    "sys/sysinfo.h", "sys/vfs.h", "sys/random.h"]
WINDOWS_HEADERS = """winsock2.h windows.h ws2tcpip.h wininet.h winhttp.h winternl.h
shellapi.h shlobj.h objbase.h wincrypt.h bcrypt.h psapi.h tlhelp32.h iphlpapi.h""".split()
CRT_HEADERS = "stdio.h stdlib.h string.h wchar.h math.h time.h process.h io.h errno.h locale.h ctype.h".split()
WINDOWS_DLLS = "msvcrt ucrtbase kernel32 user32 advapi32 ws2_32 wininet winhttp ntdll shell32 ole32 crypt32 bcrypt psapi iphlpapi".split()


def printed_type(text, target):
    if "mingw" not in target:
        return text
    if target.startswith("i686"):
        text = re.sub(r"\b(size_t|uintptr_t)\b", "uint32_t", text)
        text = re.sub(r"\b(ssize_t|intptr_t|ptrdiff_t)\b", "int32_t", text)
    text = re.sub(r"\bunsigned long\b(?! long)", "uint32_t", text)
    return re.sub(r"(?<!long )\blong\b(?! long)", "int32_t", text)


def verify_target(clang, target, headers, data, sdk=None):
    with tempfile.TemporaryDirectory() as temp:
        check = Path(temp) / "check.c"
        lines = [f"#include <{h}>" for h in headers]
        names = list(data["functions"])
        for text in data["functions"].values():
            names.extend(re.findall(r"struct (\w+)", text))
        for name, record in data["records"].items():
            names.append(name[7:])
            for _, field, text, _ in record["fields"]:
                names.append(field)
                names.extend(re.findall(r"struct (\w+)", text))
        lines.extend(undefinitions(names))
        for i, (name, declaration) in enumerate(data["functions"].items()):
            alias = f"velk_api_{i}"
            pointer = declaration.replace(name + "(", "(*" + alias + ")(", 1)
            if target.startswith("i686") and data["conventions"].get(name) == "stdcall":
                pointer = pointer.replace("(*", "(__attribute__((stdcall)) *", 1)
            lines.extend([f"typedef {pointer};",
                          f'_Static_assert(__builtin_types_compatible_p(__typeof__(&{name}), {alias}), "{name}");'])
        # Compare both the original layout and the exact padded representation
        # against the compiler for this target.
        lines.extend(["#include <stddef.h>", "#include <stdint.h>"])
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
                    members.append(f"uint8_t gap_0x{offset:x}[{at-offset}];")
                members.append(field_declaration(rename(printed_type(text, target)), field) + ";")
                if re.search(r"\(\*+\)", text):
                    alias = f"velk_field_{len(lines)}"
                    lines.extend([f"typedef {field_declaration(text, alias)};",
                                  f'_Static_assert(__builtin_types_compatible_p(__typeof__((({name} *)0)->{field}), {alias}), "{field}");'])
                offset = at + width
            if offset < record["size"]:
                members.append(f'uint8_t gap_0x{offset:x}[{record["size"]-offset}];')
            members[0] = f'_Alignas({record["align"]}) ' + members[0]
            tag = rename(name)
            lines.append(tag + " {" + "".join(members) + "};")
            for spelling in [name, tag]:
                lines.extend([f'_Static_assert(sizeof({spelling}) == {record["size"]}, "size");',
                              f'_Static_assert(_Alignof({spelling}) == {record["align"]}, "alignment");'])
                for at, field, _, _ in record["fields"]:
                    lines.append(f'_Static_assert(offsetof({spelling}, {field}) == {at}, "offset");')
        check.write_text("\n".join(lines))
        run(compiler_args(clang, sdk, target) + ["-std=gnu11", "-fsyntax-only", str(check)])


def write_targets(output, result):
    encode = lambda value: json.dumps(value, separators=(",", ":"), sort_keys=True)
    text = '{\n"version":2,\n"source":' + encode(result["source"]) + ',\n"targets":{\n'
    targets = []
    for target, data in sorted(result["targets"].items()):
        sections = []
        for kind, value in sorted(data.items()):
            if isinstance(value, dict):
                entries = [encode(k) + ":" + encode(v) for k, v in sorted(value.items())]
                value_text = "{\n" + ",\n".join(entries) + "\n}"
            else:
                value_text = encode(value)
            sections.append(encode(kind) + ":" + value_text)
        targets.append(encode(target) + ":{\n" + ",\n".join(sections) + "\n}")
    output.write_text(text + ",\n".join(targets) + "\n}\n}\n")


def generate_platform(args):
    windows = args.platform == "windows"
    headers = WINDOWS_HEADERS + CRT_HEADERS if windows else LINUX_HEADERS
    targets = (["x86_64-w64-mingw32", "i686-w64-mingw32"] if windows else
               ["x86_64-linux-gnu", "aarch64-linux-gnu"])
    datasets = {}
    header_hashes = {}
    groups = ([h for h in WINDOWS_HEADERS if h != "winhttp.h"],
              ["winsock2.h", "windows.h", "winhttp.h"], CRT_HEADERS) if windows else [headers]
    for target in targets:
        # The renderer's long is LP64. Use exact-width scalars for LLP64.
        bits = 32 if target.startswith("i686") else 64
        SCALARS["long"] = SCALARS["unsigned long"] = 4 if windows else 8
        for name in ["size_t", "ssize_t", "intptr_t", "uintptr_t", "ptrdiff_t"]:
            SCALARS[name] = bits // 8
        exports = {}
        if windows:
            prefix = "i686" if bits == 32 else "x86_64"
            for dll in WINDOWS_DLLS:
                archive = Path(f"/usr/{prefix}-w64-mingw32/lib/lib{dll}.a")
                symbols = run(["llvm-nm", "--defined-only", str(archive)])
                for symbol in re.findall(r"\b__imp_([^\s]+)", symbols):
                    if bits == 32:
                        symbol = symbol.removeprefix("_")
                    symbol = symbol.split("@")[0]
                    exports.setdefault(symbol, []).append(dll + ".dll")
        if windows:
            archive = Path(f"/usr/{prefix}-w64-mingw32/lib/libucrt.a")
            symbols = run(["llvm-nm", "-A", "--defined-only", str(archive)])
            for dll, symbol in re.findall(r":lib(api-ms-win-crt-[^:]+-l1-1-0)s\d+\.o:.*\b__imp_([^\s]+)", symbols):
                if bits == 32:
                    symbol = symbol.removeprefix("_")
                symbol = symbol.split("@")[0]
                exports.setdefault(symbol, []).append(dll + ".dll")
        data = {kind: {} for kind in ["functions", "records", "typedefs", "enums", "conventions", "guids"]}
        conflicts = {kind: set() for kind in data}
        hashes = {}
        rejected = 0
        for group in groups:
            with tempfile.TemporaryDirectory() as temp:
                source = Path(temp) / "headers.c"
                source.write_text("".join(f"#include <{h}>\n" for h in group))
                extracted, count = extract(args.clang, None, target, source)
                rejected += count
                if windows:
                    extracted["functions"] = {k: v for k, v in extracted["functions"].items() if k in exports}
                verify_target(args.clang, target, group, extracted)
                dependencies = run(compiler_args(args.clang, None, target) + ["-M", "-MT", "headers", str(source)])
                if windows:
                    extracted["guids"], guid_dependencies = header_guids(args.clang, target, group)
                    dependencies += " " + guid_dependencies
                for dependency in dependencies.replace("\\\n", " ").split()[1:]:
                    path = Path(dependency)
                    if path.is_file() and dependency.startswith("/usr/"):
                        hashes[str(path.relative_to("/usr"))] = hashlib.sha256(path.read_bytes()).hexdigest()
                for kind, entries in extracted.items():
                    for name, value in entries.items():
                        if name in conflicts[kind]:
                            continue
                        if name in data[kind] and data[kind][name] != value:
                            data[kind].pop(name)
                            conflicts[kind].add(name)
                        else:
                            data[kind][name] = value
        header_hashes[target] = hashes
        data["functions"] = {k: v for k, v in data["functions"].items() if k in data["conventions"]}
        if windows:
            # Import archives associate declarations with their exporting DLL.
            data["imports"] = {dll + "!" + name: name for name in data["functions"]
                               for dll in exports[name]}
            for kind in ["functions", "records"]:
                data[kind] = json.loads(printed_type(json.dumps(data[kind]), target))
        data["conventions"] = {name: data["conventions"][name] for name in data["functions"]}
        data["rejected_signatures"] = rejected
        data["calling_convention"] = "stdcall" if bits == 32 else "win64" if windows else "c"
        data["variables"] = header_variables(args.clang, None, target, headers)
        datasets[target] = data
        print(target, {kind: len(data[kind]) for kind in ["functions", "records", "typedefs"]})
    result = {"version": 2, "source": {"compiler": run([args.clang, "--version"]).splitlines()[0],
              "headers": headers, "guid_header": "initguid.h" if windows else None, "header_sha256": header_hashes}, "targets": datasets}
    output = args.output if args.output != Path("src/analysis/prototypes/macos.json") else Path(f"src/analysis/prototypes/{args.platform}.json")
    write_targets(output, result)


if __name__ == "__main__":
    main()

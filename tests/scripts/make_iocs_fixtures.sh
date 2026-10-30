#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
out=${1:-target/iocs-fixtures}
mkdir -p "$out"
UV_CACHE_DIR="$out/uv-cache" uv run python tests/iocs/generate.py "$out/iocs.c"
clang --target=x86_64-linux-gnu -O0 -fno-builtin -fno-stack-protector -fno-pie \
    -nostdlib -static -fuse-ld=lld -Wl,-e,main -Wl,--build-id=none \
    "$out/iocs.c" -o "$out/iocs.elf"
clang --target=x86_64-pc-windows-msvc -O0 -fno-builtin -fno-stack-protector -c \
    "$out/iocs.c" -o "$out/iocs.obj"
lld-link /nologo /entry:main /subsystem:console /nodefaultlib /out:"$out/iocs.exe" \
    "$out/iocs.obj"
clang --target=x86_64-apple-darwin -O0 -fno-builtin -fno-stack-protector -c \
    "$out/iocs.c" -o "$out/iocs.macho.o"
if command -v ld64.lld >/dev/null 2>&1; then
    ld64.lld -arch x86_64 -platform_version macos 11.0 11.0 -e _main \
        -o "$out/iocs.macho" "$out/iocs.macho.o"
else
    clang --target=x86_64-apple-darwin -nostdlib -Wl,-e,_main \
        "$out/iocs.macho.o" -o "$out/iocs.macho"
fi

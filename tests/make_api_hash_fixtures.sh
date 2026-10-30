#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
out=${1:-target/api-hash-fixtures}
mkdir -p "$out"
for architecture in x86_64 i386 aarch64; do
    case "$architecture" in
        x86_64) triple=x86_64-linux-gnu ;;
        i386) triple=i386-linux-gnu ;;
        aarch64) triple=aarch64-linux-gnu ;;
    esac
    for optimization in O0 O2; do
        clang --target="$triple" "-$optimization" -fPIC -shared -nostdlib \
            -fno-stack-protector -fno-optimize-sibling-calls -fno-builtin \
            -fuse-ld=lld -Wl,-Bsymbolic -Wl,--build-id=none \
            tests/api_hashes/fixtures.c -o "$out/$architecture.$optimization.elf"
        clang --target="$triple" "-$optimization" -nostdlib -fno-pie -no-pie \
            -fno-stack-protector -fno-optimize-sibling-calls -fno-builtin \
            -fuse-ld=lld -Wl,--export-dynamic -Wl,--hash-style=sysv \
            -Wl,--build-id=none -Wl,-e,case_inline \
            tests/api_hashes/resolvers.c -o "$out/resolvers.$architecture.$optimization.elf"
    done
done
for architecture in win64 win32; do
    case "$architecture" in
        win64) triple=x86_64-w64-windows-gnu; machine=x64; export=case_pe ;;
        win32) triple=i686-w64-windows-gnu; machine=x86; export=case_pe ;;
    esac
    clang --target="$triple" -O0 -fno-stack-protector -c \
        tests/api_hashes/windows.c -o "$out/windows.$architecture.obj"
    lld-link /dll /noentry /nodefaultlib "/machine:$machine" "/export:$export" \
        "/out:$out/windows.$architecture.dll" "$out/windows.$architecture.obj"
done
clang -O2 -DNATIVE tests/api_hashes/fixtures.c -o "$out/reference"
clang -O2 -DNATIVE -fno-builtin tests/api_hashes/resolvers.c -o "$out/resolvers-reference"

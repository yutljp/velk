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
    done
done
clang -O2 -DNATIVE tests/api_hashes/fixtures.c -o "$out/reference"

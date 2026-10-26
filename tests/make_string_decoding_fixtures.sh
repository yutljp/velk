#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
out=${1:-target/string-decoding-fixtures}
mkdir -p "$out"
for architecture in x86_64 aarch64 i386 arm32 thumb32; do
    case "$architecture" in
        x86_64) target=x86_64-linux-gnu; mode= ;;
        aarch64) target=aarch64-linux-gnu; mode= ;;
        i386) target=i386-linux-gnu; mode= ;;
        arm32) target=armv7-linux-gnueabihf; mode='-marm -march=armv7ve' ;;
        thumb32) target=armv7-linux-gnueabihf; mode='-mthumb -march=armv7ve' ;;
    esac
    for optimization in O0 O2; do
        clang --target="$target" $mode "-$optimization" -fno-vectorize -fno-slp-vectorize \
            -fno-builtin -fno-stack-protector -fno-pie -fno-optimize-sibling-calls \
            -nostdlib -static -fuse-ld=lld -Wl,-e,case_xor -Wl,--build-id=none \
            tests/string_decoding/fixtures.c -o "$out/$architecture.$optimization.elf"
        clang --target="$target" $mode "-$optimization" -fno-vectorize -fno-slp-vectorize \
            -fno-builtin -fno-stack-protector -fno-optimize-sibling-calls \
            -fPIC -shared -nostdlib -fuse-ld=lld -Wl,-Bsymbolic tests/string_decoding/unknown.c \
            -o "$out/$architecture.$optimization.shared.elf"
    done
done
clang -O0 -fno-builtin -DNATIVE tests/string_decoding/fixtures.c -o "$out/reference"

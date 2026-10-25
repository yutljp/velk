#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT="$ROOT/tests/fixtures/arm32"
mkdir -p "$OUT"
for source in "$ROOT"/tests/cases/c/*.c; do
    name=$(basename "$source" .c)
    case "$name" in pe64 | shared_pointers) continue ;; esac
    for mode in arm thumb; do
        target=armv7a-linux-gnueabihf
        [ "$mode" = arm ] || target=thumbv7m-none-eabi
        for opt in O0 O2; do
            base="$OUT/$name.$mode.$opt"
            clang "--target=$target" "-$opt" -g -fno-inline "-ffile-prefix-map=$ROOT=." -c "$source" -o "$base.o"
            ld.lld -m armelf --entry=0 --unresolved-symbols=ignore-all -o "$base.elf" "$base.o"
            rm "$base.o"
        done
    done
done
clang --version | head -1 > "$OUT/toolchain.txt"
ld.lld --version | head -1 >> "$OUT/toolchain.txt"

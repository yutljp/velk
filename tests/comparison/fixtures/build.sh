#!/bin/sh
set -eu
cd "$(dirname "$0")"
for arch in x86_64 aarch64; do
    for version in first second; do
        clang --target="$arch-linux-gnu" -fuse-ld=lld -nostdlib -static \
            -O1 -g -fdebug-prefix-map="$PWD"=. -ffile-prefix-map="$PWD"=. \
            -fno-pie -Wl,-e,entry -Wl,--build-id=none \
            "$version.c" -o "$version.$arch.debug.elf"
        llvm-strip --strip-all "$version.$arch.debug.elf" \
            -o "$version.$arch.stripped.elf"
    done
done

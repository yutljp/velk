#!/usr/bin/env bash
set -euo pipefail
out=${1:?output directory required}
source_dir=$(cd "$(dirname "$0")/data/crackmes" && pwd)
mkdir -p "$out"
for arch in x86_64 aarch64; do
    clang --target="$arch-unknown-linux-gnu" -O2 -fPIC -ffreestanding -c \
        "$source_dir/../symbolic_streams.c" -o "$out/$arch-imports.o"
    ld.lld -shared "$out/$arch-imports.o" -o "$out/lib$arch-input.so"
    for opt in 0 2; do
        for source in "$source_dir"/*.c; do
            name=$(basename "$source" .c)
            base="$out/$arch-O$opt-$name"
            clang --target="$arch-unknown-linux-gnu" -O"$opt" -g -ffreestanding \
                -fno-stack-protector -fno-optimize-sibling-calls \
                -c "$source" -o "$base.o"
            ld.lld -e main "$base.o" -L"$out" -l"$arch-input" -o "$base.elf"
            if [ "$(uname -s)" = Linux ]; then
                host_arch=$(uname -m)
                if [ "$host_arch" = arm64 ]; then host_arch=aarch64; fi
                compiler="$arch-linux-gnu-gcc"
                if [ "$arch" = "$host_arch" ]; then compiler=clang; fi
                if command -v "$compiler" >/dev/null; then
                    for linkage in dynamic static; do
                        flags=(-no-pie)
                        if [ "$linkage" = static ]; then flags=(-static); fi
                        "$compiler" -O"$opt" -g -fno-builtin -fno-stack-protector \
                            -fno-optimize-sibling-calls "${flags[@]}" \
                            "$source" -o "$base-$linkage"
                    done
                fi
            fi
        done
    done
done

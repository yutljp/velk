#!/usr/bin/env bash
set -euo pipefail
out=${1:?output directory required}
mkdir -p "$out"
source_dir=$(cd "$(dirname "$0")/../tests/data" && pwd)
for arch in x86_64 aarch64; do
    clang --target="$arch-unknown-linux-gnu" -O2 -fPIC -ffreestanding -c \
        "$source_dir/symbolic_streams.c" -o "$out/$arch-streams.o"
    ld.lld -shared -soname "lib$arch-input.so" "$out/$arch-streams.o" -o "$out/lib$arch-input.so"
    for opt in 0 2; do
        clang --target="$arch-unknown-linux-gnu" -O"$opt" -g -ffreestanding \
            -fno-stack-protector -fno-optimize-sibling-calls \
            -c "$source_dir/symbolic.c" -o "$out/$arch-O$opt.o"
        clang --target="$arch-unknown-linux-gnu" -O"$opt" -g -ffreestanding \
            -fno-stack-protector -fno-optimize-sibling-calls \
            -c "$source_dir/symbolic_io.c" -o "$out/$arch-io-O$opt.o"
        clang --target="$arch-unknown-linux-gnu" -O"$opt" -g -ffreestanding \
            -fno-stack-protector -fno-optimize-sibling-calls \
            -c "$source_dir/symbolic_libc.c" -o "$out/$arch-libc-O$opt.o"
        ld.lld -e password "$out/$arch-O$opt.o" "$out/$arch-io-O$opt.o" "$out/$arch-libc-O$opt.o" \
            -L"$out" -l"$arch-input" -o "$out/$arch-O$opt.elf"
    done
done
if [ "$(uname -s)" = Linux ]; then
    clang -O2 -ffreestanding "$source_dir/symbolic_libc.c" \
        "$source_dir/symbolic_native.c" -o "$out/native-libc"
fi

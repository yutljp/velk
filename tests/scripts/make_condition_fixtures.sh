#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
out=${1:?output directory required}
mkdir -p "$out"
clang --target=armv7a-linux-gnueabihf -c "$root/tests/data/condition_select/arm32.S" -o "$out/arm32.o"
ld.lld -m armelf -e pc_load_arm "$out/arm32.o" -o "$out/arm32.elf"
clang --target=aarch64-linux-gnu -c "$root/tests/data/condition_select/aarch64.S" -o "$out/aarch64.o"
ld.lld -m aarch64elf -e select_eq "$out/aarch64.o" -o "$out/aarch64.elf"
clang --target=x86_64-linux-gnu -c "$root/tests/data/condition_select/x86_64.S" -o "$out/x86_64.o"
ld.lld -m elf_x86_64 -e select_eq "$out/x86_64.o" -o "$out/x86_64.elf"
clang --target=i386-linux-gnu -c "$root/tests/data/condition_select/x86_64.S" -o "$out/i386.o"
ld.lld -m elf_i386 -e select_eq "$out/i386.o" -o "$out/i386.elf"

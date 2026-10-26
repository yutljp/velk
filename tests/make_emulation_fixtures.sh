#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
out=${1:-target/emulation-fixtures}
mkdir -p "$out"
for architecture in x86_64 i386 aarch64 arm32 thumb32; do
    case "$architecture" in
        x86_64) target=x86_64-linux-gnu; mode= ;;
        i386) target=i386-linux-gnu; mode= ;;
        aarch64) target=aarch64-linux-gnu; mode= ;;
        arm32) target=armv7-linux-gnueabihf; mode='-marm -march=armv7ve' ;;
        thumb32) target=armv7-linux-gnueabihf; mode='-mthumb -march=armv7ve' ;;
    esac
    for optimization in O0 O2; do
        clang --target="$target" $mode "-$optimization" -fno-vectorize -fno-slp-vectorize \
            -fno-builtin -fno-stack-protector -fno-pie -fno-optimize-sibling-calls \
            -nostdlib -static -fuse-ld=lld -Wl,-e,xor_key -Wl,--build-id=none \
            tests/emulation/routines.c -o "$out/$architecture.$optimization.elf"
        clang --target="$target" $mode "-$optimization" -fno-builtin -fno-stack-protector \
            -fno-vectorize -fno-slp-vectorize \
            -fPIC -shared -nostdlib -fuse-ld=lld tests/emulation/hooks.c \
            -o "$out/$architecture.$optimization.hooks.elf"
    done
done
for mode in arm thumb; do
    clang --target=armv7-linux-gnueabihf -m"$mode" -march=armv7ve -nostdlib -static \
        -fuse-ld=lld -Wl,-e,extend_byte -Wl,--build-id=none tests/emulation/extensions.S \
        -o "$out/$mode.extensions.elf"
done
if [ "$(uname -s)" = Darwin ]; then
    for architecture in arm64 x86_64; do
        for optimization in O0 O2; do
            clang -arch "$architecture" "-$optimization" -fno-builtin \
                -fno-vectorize -fno-slp-vectorize -fno-stack-protector -fno-optimize-sibling-calls \
                tests/emulation/reference.c -o "$out/$architecture.$optimization.native"
            clang -arch "$architecture" "-$optimization" -fno-builtin -DNATIVE \
                tests/emulation/hooks.c -o "$out/$architecture.$optimization.hooks.native"
        done
    done
else
    for optimization in O0 O2; do
        clang "-$optimization" -fno-builtin tests/emulation/reference.c -o "$out/host.$optimization.native"
        clang "-$optimization" -fno-builtin -DNATIVE tests/emulation/hooks.c -o "$out/host.$optimization.hooks.native"
    done
fi
clang --version > "$out/toolchain.txt"
ld.lld --version >> "$out/toolchain.txt"

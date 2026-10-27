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
        clang --target="$target" $mode "-$optimization" -fno-builtin -fno-stack-protector \
            -fno-vectorize -fno-slp-vectorize -fPIC -shared -nostdlib -fuse-ld=lld \
            tests/emulation/io.c -o "$out/$architecture.$optimization.io.elf"
    done
done
clang -O2 -DNATIVE -fno-builtin tests/emulation/io.c -o "$out/host.io.native"
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

cat > "$out/imports.def" <<'IMPORTS'
LIBRARY msvcrt.dll
EXPORTS
printf
sscanf
IMPORTS
clang --target=aarch64-windows-msvc -O1 -fno-builtin -c tests/emulation/windows_io.c -o "$out/arm64.obj"
lld-link /lib /def:"$out/imports.def" /machine:arm64 /out:"$out/arm64.lib"
lld-link /dll /noentry /nodefaultlib /out:"$out/arm64.dll" "$out/arm64.obj" "$out/arm64.lib"

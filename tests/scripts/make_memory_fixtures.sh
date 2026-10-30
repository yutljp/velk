#!/bin/sh
set -eu
# Keep fixture debug paths relative and compile without system headers.
mkdir -p tests/data/byte_search
for arch in x86_64 i386 aarch64 arm thumb aarch64_be; do
    case "$arch" in
        x86_64) triple=x86_64-linux-gnu; emulation=elf_x86_64 ;;
        i386) triple=i686-linux-gnu; emulation=elf_i386 ;;
        aarch64) triple=aarch64-linux-gnu; emulation=aarch64elf ;;
        arm) triple=armv7a-linux-gnueabihf; emulation=armelf ;;
        thumb) triple=thumbv7m-none-eabi; emulation=armelf ;;
        aarch64_be) triple=aarch64_be-linux-gnu; emulation=aarch64elfb ;;
    esac
    clang --target="$triple" -O1 -gdwarf-4 -fno-inline -fno-builtin -fno-pic -fno-pie \
        -ffile-prefix-map="$PWD"=. -fdebug-compilation-dir=. \
        -c tests/cases/memory/values.c -o "target/memory-$arch.o"
    ld.lld -m "$emulation" --entry=table_byte -o "tests/data/byte_search/$arch.elf" "target/memory-$arch.o"
done
clang --version | head -1 > tests/data/byte_search/toolchain.txt
ld.lld --version | head -1 >> tests/data/byte_search/toolchain.txt
clang --target=x86_64-pc-windows-msvc -O1 -c tests/cases/memory/section_tail.c -o target/memory-tail.obj
lld-link /Brepro /dll /noentry /nodefaultlib /export:read_tail /out:tests/data/byte_search/section_tail.dll \
    /implib:target/memory-tail.lib target/memory-tail.obj

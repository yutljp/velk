#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
for arch in x86_64 i686; do
    "$arch-w64-mingw32-gcc" -O1 -g -femit-struct-debug-baseonly -nostdlib -shared \
        -Wl,-e,0 -Wl,--no-insert-timestamp "-ffile-prefix-map=$PWD=." \
        tests/cases/com/interfaces.c tests/cases/com/identifiers.c -lole32 -o "tests/fixtures/com_$arch.dll"
done
{
    x86_64-w64-mingw32-gcc --version | head -1
    i686-w64-mingw32-gcc --version | head -1
} > tests/fixtures/com_toolchain.txt

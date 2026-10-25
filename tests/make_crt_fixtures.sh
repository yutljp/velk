#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p target
for arch in x86_64 i686; do
    "$arch-w64-mingw32-gcc" -O1 -fno-builtin -D__USE_MINGW_ANSI_STDIO=0 \
        -c tests/cases/c/crt_windows.c -o "target/crt-$arch.o"
    lld-link /lldmingw /entry:fixture_entry /subsystem:console /timestamp:0 \
        "/out:tests/fixtures/crt_windows.$arch.exe" "target/crt-$arch.o" \
        "/usr/$arch-w64-mingw32/lib/libmsvcrt.a"
done

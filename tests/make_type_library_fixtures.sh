#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ "${1:-macos}" = linux ]; then
    clang -O1 tests/cases/c/type_library_linux.c -pthread -o tests/fixtures/type_library_linux_x86_64
    clang --target=aarch64-linux-gnu --gcc-toolchain=/usr -O1 \
        tests/cases/c/type_library_linux.c -pthread -o tests/fixtures/type_library_linux_arm64
    x86_64-w64-mingw32-gcc -O1 -nostdlib -Wl,--no-insert-timestamp -Wl,-e,fixture_entry \
        tests/cases/c/type_library_windows.c -lkernel32 -ladvapi32 -lws2_32 \
        -o tests/fixtures/type_library_windows.win64.exe
    exit
fi
sdk=$(xcrun --sdk macosx --show-sdk-path)
for arch in arm64 x86_64; do
    clang -target "$arch-apple-macos11" -isysroot "$sdk" -O1 \
        tests/cases/c/type_library.c -o "tests/fixtures/type_library_${arch}"
done
